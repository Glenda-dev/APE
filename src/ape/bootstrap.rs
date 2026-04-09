use crate::ApeManager;
use crate::ape::process::{FileHandle, FileType};
use crate::config::ApeConfig;
use crate::layout::DEFAULT_PROCESS_ROOT;
use crate::layout::{DEFAULT_INIT_PROCESS_NAME, DEFAULT_VT_NAME};
use ape::sys::constants::FIRST_USER_FD;
use glenda::cap::Endpoint;
use glenda::error::Error;
use glenda::interface::{
    CSpaceService, FileSystemService, InitService, ProcessService, ThreadService,
    VirtualFileSystemService, VirtualTerminalService,
};
use glenda::ipc::{Badge, MsgFlags, MsgTag, UTCB};
use glenda::protocol;
use glenda::protocol::volume;
use linux_raw_sys::general::*;

impl<'a> ApeManager<'a> {
    pub fn bootstrap(&mut self) -> Result<(), Error> {
        self.init_client.report_service(Badge::null(), protocol::init::ServiceState::Starting)?;

        self.load_ape_config();
        self.mount_rootfs()?;
        self.init_stdio()?;
        self.load_init()?;

        log!("bootstrap: bootstrap complete");
        Ok(())
    }

    fn load_ape_config(&mut self) {
        match ApeConfig::load(self.res_client, self.cspace_mgr, self.vspace_mgr) {
            Ok(config) => {
                self.config = config;
                log!(
                    "bootstrap: loaded ape config (init_path={}, root_partition={})",
                    self.config.init_path,
                    self.config.root_partition
                );
            }
            Err(e) => {
                warn!("bootstrap: load ape config failed: {:?}, using defaults", e);
                self.config = ApeConfig::default();
            }
        }
    }

    fn mount_rootfs(&mut self) -> Result<(), Error> {
        log!(
            "bootstrap: mounting rootfs partition {} -> {}",
            self.config.root_partition,
            DEFAULT_PROCESS_ROOT
        );

        match self.fs_client.mkdir(Badge::null(), DEFAULT_PROCESS_ROOT, 0o755) {
            Ok(()) => {}
            Err(Error::AlreadyExists) => {}
            Err(e) => return Err(e),
        }

        let mut utcb = unsafe { UTCB::new() };
        let target_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        utcb.clear();
        {
            let mut writer = unsafe { utcb.get_buffer_writer() };
            writer.write_str(&self.config.root_partition)?;
        }
        utcb.set_msg_tag(MsgTag::new(
            protocol::VOLUME_PROTO,
            volume::MOUNT_PARTITION,
            MsgFlags::HAS_BUFFER,
        ));
        utcb.set_recv_window(target_slot);
        self.volume_ep.call(&mut utcb)?;

        if !utcb.get_msg_tag().flags().contains(MsgFlags::HAS_CAP) {
            return Err(Error::Generic);
        }

        self.fs_client.mount(Badge::null(), DEFAULT_PROCESS_ROOT, Endpoint::from(target_slot))?;

        Ok(())
    }

    fn init_stdio(&mut self) -> Result<(), Error> {
        log!("bootstrap: initializing stdio...");
        // 1. 获取 vt0
        let vt_recv = self.cspace_mgr.alloc(&mut *self.res_client)?;
        let (_vt_id, vt_ep) = self.vt_client.create_vt(Badge::null(), DEFAULT_VT_NAME, vt_recv)?;

        // 2. 创建 TerminalClient
        let term_client = glenda::client::TerminalClient::new(vt_ep);
        self.stdio_term = Some(term_client);

        Ok(())
    }

    fn load_init(&mut self) -> Result<(), Error> {
        log!("bootstrap: loading init process via execve...");

        // 1. Create process
        let host_pid = self.proc_client.create(Badge::null(), DEFAULT_INIT_PROCESS_NAME)?;
        debug!("bootstrap: Process created: host_pid={}", host_pid);

        // 2. Fetch CNode
        let cnode_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        let cnode = self.proc_client.get_cnode(Badge::null(), host_pid, cnode_slot)?;
        debug!("bootstrap: Fetched process CNode into slot: {:?}", cnode_slot);

        // 3. Register
        let pid = self.register_process(0, host_pid, cnode);
        debug!("bootstrap: Process registered in APE (pid={}, host_pid={})", pid, host_pid);

        // 4. 为 init 进程初始化 stdio fds
        if let Some(term) = self.stdio_term {
            let proc = self.get_process_mut(pid).unwrap();
            proc.fds.insert(STDIN_FILENO, FileHandle { file_type: FileType::Terminal(term) });
            proc.fds.insert(STDOUT_FILENO, FileHandle { file_type: FileType::Terminal(term) });
            proc.fds.insert(STDERR_FILENO, FileHandle { file_type: FileType::Terminal(term) });
            proc.next_fd = FIRST_USER_FD;
        }

        let init_path = self.config.init_path.clone();
        self.execve_path(pid, &init_path, &[], &[])?;

        log!("bootstrap: init process loaded, pid: {}", pid);
        let tcb_cap = self.get_process(pid).ok_or(Error::NotFound)?.tcb();
        tcb_cap.resume()?;
        Ok(())
    }
}
