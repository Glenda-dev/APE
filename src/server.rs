use crate::ApeService;
use crate::log;
use glenda::cap::{CapPtr, Endpoint, Reply};
use glenda::error::Error;
use glenda::interface::SystemService;
use glenda::ipc::{Badge, MsgArgs, MsgFlags, MsgTag, UTCB};
use glenda::protocol;

impl SystemService for ApeService {
    fn init(&mut self) -> Result<(), Error> {
        log!("Mounting root filesystem with UUID: {}", self.rootfs_uuid);
        log!("Loading init...");
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
            let label = msg_info.label();
            let proto = msg_info.proto();
            let flags = msg_info.flags();
            let args = utcb.mrs_regs;

            let res = self.dispatch(badge, label, proto, flags, args);
            match res {
                Ok(ret) => self.reply(
                    protocol::GENERIC_PROTO,
                    protocol::generic::REPLY,
                    MsgFlags::OK,
                    ret,
                )?,
                Err(e) => match e {
                    Error::Success => {
                        continue;
                    }
                    _ => self.reply(
                        protocol::GENERIC_PROTO,
                        protocol::generic::REPLY,
                        MsgFlags::ERROR,
                        [e as usize, 0, 0, 0, 0, 0, 0, 0],
                    )?,
                },
            }
        }
        Ok(())
    }
    fn dispatch(
        &mut self,
        badge: Badge,
        label: usize,
        proto: usize,
        flags: MsgFlags,
        msg: MsgArgs,
    ) -> Result<MsgArgs, Error> {
        log!(
            "Received message: badge={}, label={}, proto={}, flags={}, msg={:?}",
            badge,
            label,
            proto,
            flags,
            msg
        );
        if proto != protocol::KERNEL_PROTO {
            return Err(Error::InvalidProtocol);
        }
        Err(Error::NotImplemented)
    }
    fn reply(
        &mut self,
        label: usize,
        proto: usize,
        flags: MsgFlags,
        msg: MsgArgs,
    ) -> Result<(), Error> {
        let tag = MsgTag::new(proto, label, flags);
        self.reply.reply(tag, msg)
    }
    fn stop(&mut self) {
        self.running = false;
        log!("Shutting down...");
        // Shutdown /init
        log!("Unmounting root filesystem with UUID: {}", self.rootfs_uuid);
    }
}
