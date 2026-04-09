use crate::ApeManager;
use crate::ape::process::{FileHandle, FileType};
use crate::layout::{DEFAULT_INIT_PROCESS_NAME, DEFAULT_INIT_PROGRAM, DEFAULT_VT_NAME};
use ape::sys::constants::FIRST_USER_FD;
use glenda::error::Error;
use glenda::interface::{
    CSpaceService, InitService, ProcessService, ThreadService, VirtualTerminalService,
};
use glenda::ipc::Badge;
use glenda::protocol;
use linux_raw_sys::general::*;

impl<'a> ApeManager<'a> {
    pub fn bootstrap(&mut self) -> Result<(), Error> {
        self.init_client.report_service(Badge::null(), protocol::init::ServiceState::Starting)?;

        self.mount_rootfs()?;
        self.init_stdio()?;
        self.load_init()?;

        log!("bootstrap: bootstrap complete");
        Ok(())
    }

    fn mount_rootfs(&mut self) -> Result<(), Error> {
        log!("bootstrap: mounting rootfs...");
        // TODO: 从 fs 服务获取 rootfs 并在内部 VFS 挂载
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

        self.execve_path(pid, DEFAULT_INIT_PROGRAM, &[], &[])?;

        log!("bootstrap: init process loaded, pid: {}", pid);
        let tcb_cap = self.get_process(pid).ok_or(Error::NotFound)?.tcb();
        tcb_cap.resume()?;
        Ok(())
    }
}
