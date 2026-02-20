use crate::ApeManager;
use glenda::cap::{CapPtr, Endpoint, Reply};
use glenda::error::Error;
use glenda::interface::SystemService;
use glenda::ipc::UTCB;
use glenda::protocol;

impl SystemService for ApeManager {
    fn init(&mut self) -> Result<(), Error> {
        log!("Mounting root filesystem with UUID: {}", self.rootfs_uuid);
        // Logic to mount FS would go here (interacting with VFS service)

        log!("Loading init...");
        // Logic to spawn 'init' process would go here
        // For now, we manually register PID 1 representing 'init'
        // In a real flow, we would load the ELF, create thread/vspace, and then register.
        self.register_process(0, 0, 0);

        Ok(())
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
        self.running = true;
        while self.running {
            let mut utcb = unsafe { UTCB::new() };
            utcb.set_reply_window(self.reply.cap());
            utcb.set_recv_window(self.recv);
            match self.endpoint.recv(&mut utcb) {
                Ok(_) => {}
                Err(e) => {
                    log!("Recv error: {:?}", e);
                    continue;
                }
            };

            match self.dispatch(&mut utcb) {
                Ok(()) => {}
                Err(e) => {
                    log!("Dispatch error: {:?}", e);
                }
            }
            self.reply(&mut utcb)?;
        }
        Ok(())
    }
    fn dispatch(&mut self, utcb: &mut UTCB) -> Result<(), Error> {
        let tag = utcb.get_msg_tag();
        let badge = utcb.get_badge();
        let label = tag.label();
        let proto = tag.proto();
        let flags = tag.flags();
        let args = utcb.get_mrs();

        glenda::ipc_dispatch! {
            self, utcb,
            (protocol::KERNEL_PROTO, _) => |_, _| Err(Error::NotImplemented),
            (_, _) => |_, _| Err(Error::InvalidProtocol),
        }
    }
    fn reply(&mut self, utcb: &mut UTCB) -> Result<(), Error> {
        self.reply.reply(utcb)
    }
    fn stop(&mut self) {
        self.running = false;
        log!("Shutting down...");
        // Shutdown /init
        log!("Unmounting root filesystem with UUID: {}", self.rootfs_uuid);
    }
}
