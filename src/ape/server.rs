use crate::ApeManager;
use glenda::cap::{CapPtr, Endpoint, Reply};
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
        self.endpoint = ep;
        self.reply = Reply::from(reply);
        self.recv = recv;
        Ok(())
    }
    fn run(&mut self) -> Result<(), Error> {
        if self.endpoint.cap().is_null() || self.reply.cap().is_null() {
            return Err(Error::NotInitialized);
        }
        self.init_client.report_service(Badge::null(), protocol::init::ServiceState::Running)?;
        self.running = true;
        while self.running {
            let mut utcb = unsafe { UTCB::new() };
            utcb.set_reply_window(self.reply.cap());
            utcb.set_recv_window(self.recv);
            if let Err(e) = self.endpoint.recv(&mut utcb) {
                error!("Recv error: {:?}", e);
                continue;
            }

            match self.dispatch(&mut utcb) {
                Ok(()) => {}
                Err(e) => {
                    error!("Dispatch error: {:?}", e);
                }
            }
            self.reply(&mut utcb)?;
        }
        Ok(())
    }
    fn dispatch(&mut self, utcb: &mut UTCB) -> Result<(), Error> {
        let badge = utcb.get_badge();
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
            (protocol::KERNEL_PROTO, protocol::kernel::UNKNOWN_FAULT) => |s: &mut ApeManager, utcb: &mut UTCB| s.unknown_fault(badge, utcb.get_mr(0), utcb.get_mr(1), utcb.get_mr(2)),
            (_, _) => |_: &mut ApeManager, _: &mut UTCB| Err(Error::InvalidProtocol),
        }
    }
    fn reply(&mut self, utcb: &mut UTCB) -> Result<(), Error> {
        self.reply.reply(utcb)
    }
    fn stop(&mut self) {
        self.running = false;
        log!("Shutting down...");
        let _ =
            self.init_client.report_service(Badge::null(), protocol::init::ServiceState::Stopped);
    }
}
