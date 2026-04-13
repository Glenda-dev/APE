use crate::ApeManager;
use glenda::cap::CSPACE_CAP;
use glenda::error::Error;
use glenda::interface::{CSpaceService, ProcessService};
use glenda::ipc::Badge;

impl<'a> ApeManager<'a> {
    fn clear_reply_cap_for_exit(&mut self) {
        if let Err(e) = CSPACE_CAP.delete(self.ipc.reply.cap())
            && e != Error::InvalidCapability
            && e != Error::InvalidSlot
        {
            warn!("exit: failed to clear ape reply slot {:?}: {:?}", self.ipc.reply.cap(), e);
        }
    }

    fn release_process_cnode_cap(&mut self, pid: usize) {
        if let Some(slot) = self.get_process(pid).map(|p| p.cnode_cap.cap()) {
            let _ = CSPACE_CAP.revoke(slot);
            if let Err(e) = CSPACE_CAP.delete(slot)
                && e != Error::InvalidCapability
                && e != Error::InvalidSlot
            {
                warn!("exit: failed to delete child cnode slot {:?}: {:?}", slot, e);
            } else {
                self.cspace_mgr.free(slot);
            }
        }
    }

    fn kill_host_process_by_local_pid(&mut self, pid: usize) {
        let host_pid = self
            .host_pid_map
            .iter()
            .find_map(|(host_pid, local_pid)| (*local_pid == pid).then_some(*host_pid));

        if let Some(host_pid) = host_pid {
            let _ = self.proc_client.kill(Badge::null(), host_pid);
            self.host_pid_map.remove(&host_pid);
        }
    }

    fn terminate_process_impl(
        &mut self,
        pid: usize,
        exit_code: usize,
        panic_if_init: bool,
        clear_reply: bool,
    ) -> Result<(), Error> {
        if clear_reply {
            self.clear_reply_cap_for_exit();
        }
        self.release_process_cnode_cap(pid);
        self.kill_host_process_by_local_pid(pid);

        let _ = self.release_process_intermediate_page_tables(pid);
        self.processes.remove(&pid);

        if panic_if_init && pid == 1 {
            panic!(
                "Init process faulted with exit code {:#x}, shutting down Ape service",
                exit_code
            );
        }

        Ok(())
    }

    pub(crate) fn terminate_process(
        &mut self,
        pid: usize,
        exit_code: usize,
        panic_if_init: bool,
    ) -> Result<(), Error> {
        self.terminate_process_impl(pid, exit_code, panic_if_init, true)
    }

    pub(crate) fn terminate_process_preserve_reply(
        &mut self,
        pid: usize,
        exit_code: usize,
        panic_if_init: bool,
    ) -> Result<(), Error> {
        self.terminate_process_impl(pid, exit_code, panic_if_init, false)
    }
}
