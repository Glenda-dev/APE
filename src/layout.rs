pub use glenda::cap::{CapPtr, Endpoint};
pub const INIT_SLOT: CapPtr = CapPtr::from(9);
pub const INIT_CAP: Endpoint = Endpoint::from(INIT_SLOT);
pub const VT_SLOT: CapPtr = CapPtr::from(10);
pub const VT_CAP: Endpoint = Endpoint::from(VT_SLOT);
pub const FS_SLOT: CapPtr = CapPtr::from(11);
pub const FS_CAP: Endpoint = Endpoint::from(FS_SLOT);
