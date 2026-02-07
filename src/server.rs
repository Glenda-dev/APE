use crate::ApeManager;
use crate::log;
use glenda::cap::{CapPtr, Endpoint, Reply};
use glenda::error::Error;
use glenda::interface::SystemService;
use glenda::ipc::{Badge, MsgTag, UTCB};
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
    fn listen(&mut self, ep: Endpoint, reply: CapPtr) -> Result<(), Error> {
        self.endpoint = ep;
        self.reply = Reply::from(reply);
        Ok(())
    }
    fn run(&mut self) -> Result<(), Error> {
        if self.endpoint.cap().is_null() || self.reply.cap().is_null() {
            return Err(Error::NotInitialized);
        }
        self.running = true;
        while self.running {
            match self.endpoint.recv(self.reply.cap()) {
                Ok(b) => b,
                Err(e) => {
                    log!("Recv error: {:?}", e);
                    continue;
                }
            };
            let utcb = unsafe { UTCB::get() };
            let msg_info = utcb.msg_tag;
            let badge = utcb.badge;

            let res = self.dispatch(badge, msg_info);
            match res {
                Ok(()) => {}
                Err(e) => {
                    log!("Dispatch error: {:?}", e);
                }
            }
        }
        Ok(())
    }
    fn dispatch(&mut self, badge: Badge, info: MsgTag) -> Result<(), Error> {
        let label = info.label();
        let proto = info.proto();
        let flags = info.flags();
        let args = unsafe { UTCB::get() }.mrs_regs;
        log!(
            "Received message: badge={}, label={}, proto={}, flags={}, args={:?}",
            badge,
            label,
            proto,
            flags,
            args
        );
        if proto != protocol::KERNEL_PROTO {
            return Err(Error::InvalidProtocol);
        }
        Err(Error::NotImplemented)
    }
    fn reply(&mut self, info: MsgTag) -> Result<(), Error> {
        self.reply.reply(info)
    }
    fn stop(&mut self) {
        self.running = false;
        log!("Shutting down...");
        // Shutdown /init
        log!("Unmounting root filesystem with UUID: {}", self.rootfs_uuid);
    }
}
