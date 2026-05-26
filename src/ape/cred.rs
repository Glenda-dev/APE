use glenda::protocol::auth::IdentityInfo;
use glenda::sync::rwlock::RwLock;

pub struct CredStruct {
    pub identity: RwLock<IdentityInfo>,
}

impl CredStruct {
    pub fn new() -> Self {
        Self { identity: RwLock::new(IdentityInfo::default()) }
    }
}
