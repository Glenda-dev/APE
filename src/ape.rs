use alloc::string::String;
use glenda::cap::{CapPtr, Endpoint, Reply};

pub struct ApeService {
    pub running: bool,
    pub rootfs_uuid: String,
    pub endpoint: Endpoint,
    pub reply: Reply,
}

impl ApeService {
    pub fn new(rootfs_uuid: String) -> Self {
        Self {
            running: false,
            rootfs_uuid,
            endpoint: Endpoint::from(CapPtr::null()),
            reply: Reply::from(CapPtr::null()),
        }
    }
}
