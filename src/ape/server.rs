use crate::ApeManager;
use glenda::cap::{CSPACE_CAP, CapPtr, Endpoint, Reply};
use glenda::error::Error;
use glenda::interface::FaultService;
use glenda::interface::{
    CSpaceService, InitService, ResourceService, SystemService, VSpaceService,
};
use glenda::ipc::{Badge, UTCB};
use glenda::protocol;

impl<'a> SystemService for ApeManager<'a> {
    fn init(&mut self) -> Result<(), Error> {
        self.bootstrap()
    }
    fn listen(&mut self, ep: Endpoint, reply: CapPtr, recv: CapPtr) -> Result<(), Error> {
        self.ipc.endpoint = ep;
        self.ipc.reply = Reply::from(reply);
        self.ipc.recv = recv;
        Ok(())
    }
    fn run(&mut self) -> Result<(), Error> {
        if self.ipc.endpoint.cap().is_null() || self.ipc.reply.cap().is_null() {
            return Err(Error::NotInitialized);
        }
        self.init_client.report_service(Badge::null(), protocol::init::ServiceState::Running)?;
        self.ipc.running = true;
        while self.ipc.running {
            let mut utcb = unsafe { UTCB::new() };
            utcb.set_reply_window(self.ipc.reply.cap());
            utcb.set_recv_window(self.ipc.recv);
            if let Err(e) = self.ipc.endpoint.recv(&mut utcb) {
                error!("Recv error: {:?}", e);
                continue;
            }
            self.set_active_caller_pid(utcb.get_badge().bits());
            match self.dispatch(&mut utcb) {
                Ok(()) => {}
                Err(Error::Success) => {
                    continue;
                }
                Err(e) => {
                    error!("Dispatch error: {:?}", e);
                    continue;
                }
            }
            self.clear_active_caller_pid();

            for pid in self.take_deferred_host_kills() {
                self.kill_host_process_by_local_pid(pid);
            }
            if let Err(e) = self.reply(&mut utcb) {
                error!("Reply error: {:?}", e);
            }
        }
        Ok(())
    }
    fn dispatch(&mut self, utcb: &mut UTCB) -> Result<(), Error> {
        let badge = utcb.get_badge();
        let msg_tag = utcb.get_msg_tag();
        let proto = msg_tag.proto();
        let label = msg_tag.label();
        glenda::ipc_dispatch! {
            self, utcb,
            (protocol::KERNEL_PROTO, protocol::kernel::SYSCALL) => |s: &mut ApeManager, utcb: &mut UTCB| {
                let mut args = [0usize; 8];
                for i in 0..8 {
                    args[i] = utcb.get_mr(i);
                }
                s.handle_syscall(badge.bits(), args)
            },
            (protocol::KERNEL_PROTO, protocol::kernel::PAGE_FAULT) => |s: &mut ApeManager, utcb: &mut UTCB| s.page_fault(badge, utcb.get_mr(0), utcb.get_mr(1), utcb.get_mr(2)),
            (protocol::KERNEL_PROTO, protocol::kernel::ILLEGAL_INSTRUCTION) => |s: &mut ApeManager, utcb: &mut UTCB| s.illegal_instruction(badge, utcb.get_mr(0), utcb.get_mr(1)),
            (protocol::KERNEL_PROTO, protocol::kernel::BREAKPOINT) => |s: &mut ApeManager, utcb: &mut UTCB| s.breakpoint(badge, utcb.get_mr(0)),
            (protocol::KERNEL_PROTO, protocol::kernel::ACCESS_FAULT) => |s: &mut ApeManager, utcb: &mut UTCB| s.access_fault(badge, utcb.get_mr(0), utcb.get_mr(1)),
            (protocol::KERNEL_PROTO, protocol::kernel::VIRT_EXIT) => |s: &mut ApeManager, utcb: &mut UTCB| s.virt_exit(badge, utcb.get_mr(0), utcb.get_mr(1), utcb.get_mr(2), utcb.get_mr(3)),
            (protocol::KERNEL_PROTO, protocol::kernel::UNKNOWN_FAULT) => |s: &mut ApeManager, utcb: &mut UTCB| s.unknown_fault(badge, utcb.get_mr(0), utcb.get_mr(1), utcb.get_mr(2)),
            (_, _) => |_: &mut ApeManager, _: &mut UTCB| Err(Error::InvalidProtocol),
        }
    }
    fn reply(&mut self, utcb: &mut UTCB) -> Result<(), Error> {
        self.ipc.reply.reply(utcb)
    }
    fn stop(&mut self) {
        self.ipc.running = false;
        log!("Shutting down...");
        let _ =
            self.init_client.report_service(Badge::null(), protocol::init::ServiceState::Stopped);
    }
}
