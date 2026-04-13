use crate::ApeManager;
use crate::ape::process::{FileHandle, FileType};
use crate::config::ApeConfig;
use crate::layout::{
    DEFAULT_INIT_PROCESS_NAME, DEFAULT_VIEW_ROOT, DEFAULT_VT_NAME, ROOTFS_SLOT, STDIO_SLOT,
};
use ape::sys::constants::FIRST_USER_FD;
use glenda::cap::CSPACE_CAP;
use glenda::client::TerminalClient;
use glenda::error::Error;
use glenda::interface::{
    CSpaceService, InitService, ProcessService, ResourceService, ThreadService,
    VirtualFileSystemService, VirtualTerminalService, VolumeService,
};
use glenda::ipc::{Badge, MsgFlags, MsgTag, UTCB};
use glenda::protocol;
use linux_raw_sys::general::*;

fn set_terminal_foreground_pgrp(term: TerminalClient, pgrp: i32) -> Result<(), Error> {
    let mut utcb = unsafe { UTCB::new() };
    utcb.clear();
    utcb.set_msg_tag(MsgTag::new(
        protocol::TERMINAL_PROTO,
        protocol::terminal::TERM_SET_PGRP,
        MsgFlags::NONE,
    ));
    utcb.set_mr(0, pgrp as usize);
    term.endpoint().call(utcb)
}

impl<'a> ApeManager<'a> {
    pub fn bootstrap(&mut self) -> Result<(), Error> {
        self.init_client.report_service(Badge::null(), protocol::init::ServiceState::Starting)?;

        self.load_ape_config();
        self.mount_rootfs()?;
        self.setup_view()?;
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
                self.config = config;
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
            DEFAULT_VIEW_ROOT
        );
        let target_ep = self.vol_client.mount_partition(
            Badge::null(),
            &self.config.root_partition,
            ROOTFS_SLOT,
        )?;
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

    fn init_stdio(&mut self) -> Result<(), Error> {
        let vt_name = if self.config.stdio.vt_name.is_empty() {
            DEFAULT_VT_NAME
        } else {
            self.config.stdio.vt_name.as_str()
        };
        let seat_id = self.config.stdio.seat_id;
        let devices_to_bind = self.config.stdio.devices.clone();

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
        self.stdio_term = Some(term_client);

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
        if let Some(term) = self.stdio_term {
            set_terminal_foreground_pgrp(term, pid as i32)?;

            let proc = self.get_process_mut(pid).unwrap();
            proc.fds.insert(STDIN_FILENO, FileHandle { file_type: FileType::Terminal(term) });
            proc.fds.insert(STDOUT_FILENO, FileHandle { file_type: FileType::Terminal(term) });
            proc.fds.insert(STDERR_FILENO, FileHandle { file_type: FileType::Terminal(term) });
            proc.next_fd = FIRST_USER_FD;
        }

        let init_path = self.config.init_path.clone();
        log!("load_init: execve init path={}", init_path);
        self.execve_path(pid, &init_path, &[], &[])?;
        log!("load_init: execve completed");
        let tcb_cap = self.get_process(pid).ok_or(Error::NotFound)?.tcb();
        tcb_cap.resume()?;
        log!("load_init: resumed init tcb");
        Ok(())
    }
}
