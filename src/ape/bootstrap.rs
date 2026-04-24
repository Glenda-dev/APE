use crate::ApeManager;
use crate::ape::process::{FileHandle, FileType, NormalFileHandle, NormalHandleBackend};
use crate::config::ApeConfig;
use crate::drivers::tty::TtyDevice;
use crate::layout::{
    DEFAULT_INIT_PROCESS_NAME, DEFAULT_VIEW_ROOT, DEFAULT_VT_NAME, FIRST_USER_FD, ROOTFS_SLOT,
    STDIO_SLOT,
};
use crate::task as task_subsystem;
use crate::vfs::worker::{VfsWorkerConfig, VfsWorkerKind, spawn_worker};
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapPtr, CapType, Endpoint, Page};
use glenda::client::TerminalClient;
use glenda::error::Error;
use glenda::interface::{
    CSpaceService, FileSystemService, InitService, ProcessService, ResourceService, ThreadService,
    VSpaceService, VirtualFileSystemService, VirtualTerminalService, VolumeService,
};
use glenda::ipc::Badge;
use glenda::mem::Perms;
use glenda::protocol;
use glenda::protocol::fs::OpenFlags;
use linux_raw_sys::general::*;

const VFS_WORKER_STACK_SIZE: usize = 64 * 1024;
const VFS_WORKER_STACK_PAGES: usize = VFS_WORKER_STACK_SIZE / PGSIZE;
const DEVTMPFS_WORKER_STACK_BASE: usize = 0x5700_0000;
const TMPFS_WORKER_STACK_BASE: usize = DEVTMPFS_WORKER_STACK_BASE + 0x20_000;
const PIPEFS_WORKER_STACK_BASE: usize = TMPFS_WORKER_STACK_BASE + 0x20_000;

impl<'a> ApeManager<'a> {
    pub fn bootstrap(&mut self) -> Result<(), Error> {
        self.init_client.report_service(Badge::null(), protocol::init::ServiceState::Starting)?;

        self.load_ape_config();
        self.mount_rootfs()?;
        self.setup_view()?;
        self.start_vfs_workers()?;
        self.start_async_runtime()?;
        self.mount_devtmpfs()?;
        self.init_stdio()?;
        self.load_init()?;

        Ok(())
    }

    fn load_ape_config(&mut self) {
        match ApeConfig::load(self.res_client, self.cspace_mgr, self.vspace_mgr) {
            Ok(config) => {
                log!(
                    "bootstrap: loaded ape config (init_path={}, root_partition={}, stdio_vt={}, seat_id={}, devices={})",
                    config.init_path,
                    config.root_partition,
                    config.stdio.vt_name,
                    config.stdio.seat_id,
                    config.stdio.devices.len()
                );
                self.set_config(config);
            }
            Err(e) => {
                warn!("bootstrap: load ape config failed: {:?}, using defaults", e);
                self.set_config(ApeConfig::default());
            }
        }
    }

    fn mount_rootfs(&mut self) -> Result<(), Error> {
        let root_partition = self.config().root_partition.clone();
        log!("bootstrap: mounting rootfs partition {} -> {}", root_partition, DEFAULT_VIEW_ROOT);
        let target_ep =
            self.vol_client.mount_partition(Badge::null(), &root_partition, ROOTFS_SLOT)?;
        self.fs_client.mount(Badge::null(), DEFAULT_VIEW_ROOT, target_ep)?;
        log!("bootstrap: mounted rootfs successfully");
        Ok(())
    }

    fn setup_view(&mut self) -> Result<(), Error> {
        let view_id = self.fs_client.create_view(Badge::null(), DEFAULT_VIEW_ROOT)?;
        self.fs_client.set_view(Badge::null(), view_id)?;
        log!("bootstrap: switched to view {} with root {}", view_id, DEFAULT_VIEW_ROOT);
        Ok(())
    }

    fn mount_devtmpfs(&mut self) -> Result<(), Error> {
        let dev_path = "/linux/dev";
        match self.fs_client.mkdir(Badge::null(), dev_path, 0o755) {
            Ok(()) | Err(Error::AlreadyExists) => {}
            Err(e) => return Err(e),
        }

        let dev_ep = self.dev_vfs_endpoint.ok_or(Error::NotInitialized)?;
        self.fs_client.mount(Badge::null(), dev_path, dev_ep)?;
        log!("bootstrap: mounted ape devtmpfs backend at {}", dev_path);
        Ok(())
    }

    fn alloc_worker_endpoint_and_windows(
        &mut self,
    ) -> Result<(Endpoint, CapPtr, CapPtr, Endpoint), Error> {
        let endpoint_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        self.res_client.alloc(Badge::null(), CapType::Endpoint, 0, endpoint_slot)?;

        let reply_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        let recv_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;

        let park_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        self.res_client.alloc(Badge::null(), CapType::Endpoint, 0, park_slot)?;

        Ok((Endpoint::from(endpoint_slot), reply_slot, recv_slot, Endpoint::from(park_slot)))
    }

    fn alloc_worker_stack(&mut self, stack_base: usize) -> Result<usize, Error> {
        let frame_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        let page_level =
            CapType::page_pages_to_level(VFS_WORKER_STACK_PAGES).ok_or(Error::InvalidArgs)?;
        self.res_client.alloc(Badge::null(), CapType::Page, page_level, frame_slot)?;

        self.vspace_mgr.map_page(
            Page::from(frame_slot),
            stack_base,
            Perms::READ | Perms::WRITE,
            VFS_WORKER_STACK_PAGES,
            &mut *self.res_client,
            &mut *self.cspace_mgr,
        )?;

        Ok(stack_base + VFS_WORKER_STACK_SIZE)
    }

    fn start_vfs_workers(&mut self) -> Result<(), Error> {
        let (dev_ep, dev_reply, dev_recv, dev_park) = self.alloc_worker_endpoint_and_windows()?;
        let (tmp_ep, tmp_reply, tmp_recv, tmp_park) = self.alloc_worker_endpoint_and_windows()?;
        let (pipe_ep, pipe_reply, pipe_recv, pipe_park) =
            self.alloc_worker_endpoint_and_windows()?;

        let dev_cfg = VfsWorkerConfig {
            endpoint: dev_ep,
            reply_slot: dev_reply,
            recv_slot: dev_recv,
            park_endpoint: dev_park,
            kind: VfsWorkerKind::DevTmpFs,
        };
        let tmp_cfg = VfsWorkerConfig {
            endpoint: tmp_ep,
            reply_slot: tmp_reply,
            recv_slot: tmp_recv,
            park_endpoint: tmp_park,
            kind: VfsWorkerKind::TmpFs,
        };
        let pipe_cfg = VfsWorkerConfig {
            endpoint: pipe_ep,
            reply_slot: pipe_reply,
            recv_slot: pipe_recv,
            park_endpoint: pipe_park,
            kind: VfsWorkerKind::PipeFs,
        };

        let dev_stack_top = self.alloc_worker_stack(DEVTMPFS_WORKER_STACK_BASE)?;
        let tmp_stack_top = self.alloc_worker_stack(TMPFS_WORKER_STACK_BASE)?;
        let pipe_stack_top = self.alloc_worker_stack(PIPEFS_WORKER_STACK_BASE)?;

        let _dev_tid = spawn_worker(self.proc_client, dev_cfg, dev_stack_top)?;
        let _tmp_tid = spawn_worker(self.proc_client, tmp_cfg, tmp_stack_top)?;
        let _pipe_tid = spawn_worker(self.proc_client, pipe_cfg, pipe_stack_top)?;

        self.dev_vfs_endpoint = Some(dev_ep);
        self.tmp_vfs_endpoint = Some(tmp_ep);
        self.pipe_vfs_endpoint = Some(pipe_ep);

        log!("bootstrap: started vfs workers (devtmpfs + tmpfs + pipefs)");
        Ok(())
    }

    fn init_stdio(&mut self) -> Result<(), Error> {
        let cfg = self.config().clone();
        let vt_name =
            if cfg.stdio.vt_name.is_empty() { DEFAULT_VT_NAME } else { cfg.stdio.vt_name.as_str() };
        let seat_id = cfg.stdio.seat_id;
        let devices_to_bind = cfg.stdio.devices;

        let (vt_id, vt_ep) = self.vt_client.create_vt(Badge::null(), vt_name, STDIO_SLOT)?;

        // 将 stdio VT 绑定到指定 seat 并切换为前台活动 VT。
        self.vt_client.bind_seat(Badge::null(), seat_id, vt_id)?;
        self.vt_client.switch_vt(Badge::null(), seat_id, vt_id)?;

        for dev in devices_to_bind {
            self.vt_client.assign_device_to_seat(Badge::null(), seat_id, dev.as_str())?;
            log!("bootstrap: bound device {} to seat {}", dev, seat_id);
        }

        // 2. 创建 TerminalClient
        let term_client = TerminalClient::new(vt_ep);
        self.set_stdio_term(Some(term_client));

        Ok(())
    }

    fn load_init(&mut self) -> Result<(), Error> {
        // 1. Create process
        log!("load_init: creating init process via Warren");
        let host_pid = self.proc_client.create(Badge::null(), DEFAULT_INIT_PROCESS_NAME)?;
        log!("load_init: created host init pid={}", host_pid);

        // 2. Fetch CNode
        let cnode_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        log!("load_init: requesting child cnode at slot {:?}", cnode_slot);
        let cnode = self.proc_client.get_cnode(Badge::null(), host_pid, cnode_slot)?;
        log!("load_init: received child cnode cap={:?}", cnode.cap());

        // 3. Register
        let pid = self.register_process(0, host_pid, cnode);
        log!("load_init: registered local init pid={}", pid);

        // 4. 为 init 进程初始化 stdio fds
        if let Some(term) = self.stdio_term() {
            TtyDevice::global().set_foreground_pgrp(pid as i32);
            let tty_path = self.resolve_path_for_process(pid, "/dev/tty")?;
            let tty = self.open_normal_handle(&tty_path, OpenFlags::O_RDWR)?;

            let proc = self.get_process_mut(pid).unwrap();
            proc.controlling_tty = Some(term.endpoint().cap().bits());
            proc.fds.insert(STDIN_FILENO, FileHandle { file_type: FileType::Normal(tty) });
            proc.fds.insert(STDOUT_FILENO, FileHandle { file_type: FileType::Normal(tty) });
            proc.fds.insert(STDERR_FILENO, FileHandle { file_type: FileType::Normal(tty) });
            proc.fd_paths.insert(STDIN_FILENO, "/dev/tty".into());
            proc.fd_paths.insert(STDOUT_FILENO, "/dev/tty".into());
            proc.fd_paths.insert(STDERR_FILENO, "/dev/tty".into());
            proc.next_fd = FIRST_USER_FD;
        }

        let init_path = self.config().init_path.clone();
        log!("load_init: execve init path={}", init_path);
        task_subsystem::do_execve(self, pid, &init_path, &[], &[])?;
        log!("load_init: execve completed");
        let tcb_cap = self.get_process(pid).ok_or(Error::NotFound)?.tcb();
        tcb_cap.resume()?;
        log!("load_init: resumed init tcb");
        Ok(())
    }

    fn open_normal_handle(
        &mut self,
        path: &str,
        flags: OpenFlags,
    ) -> Result<NormalFileHandle, Error> {
        let fs_ep_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        let mut fs_open_client = glenda::client::FsClient::new(self.fs_client.endpoint());
        if let Err(e) = fs_open_client.open(Badge::null(), path, flags, 0, fs_ep_slot) {
            let _ = glenda::cap::CSPACE_CAP.delete(fs_ep_slot);
            self.cspace_mgr.free(fs_ep_slot);
            return Err(e);
        }

        Ok(NormalFileHandle {
            backend: NormalHandleBackend::Fs,
            fs_client: glenda::client::FsClient::new(glenda::cap::Endpoint::from(fs_ep_slot)),
            fs_ep_slot,
            offset: 0,
            async_io: None,
        })
    }
}
