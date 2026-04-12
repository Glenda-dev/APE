use alloc::string::String;
use glenda::arch::mem::PGSIZE;
use glenda::client::ResourceClient;
use glenda::error::Error;
use glenda::interface::{CSpaceService, ResourceService, VSpaceService};
use glenda::ipc::Badge;
use glenda::mem::Perms;
use glenda::utils::align::align_up;
use glenda::utils::manager::{CSpaceManager, VSpaceManager};
use serde::{Deserialize, Serialize};

pub const APE_CONFIG_PATH: &str = "ape.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApeConfig {
    pub init_path: String,
    pub root_partition: String,
}

impl Default for ApeConfig {
    fn default() -> Self {
        Self { init_path: String::from("/bin/sh"), root_partition: String::from("disk0p0") }
    }
}

impl ApeConfig {
    pub fn load(
        res_client: &mut ResourceClient,
        cspace: &mut CSpaceManager,
        vspace: &mut VSpaceManager,
    ) -> Result<Self, Error> {
        let config_slot = cspace.alloc(res_client)?;
        let (frame, size) = res_client.get_config(Badge::null(), APE_CONFIG_PATH, config_slot)?;
        if size == 0 {
            return Err(Error::InvalidConfig);
        }

        let pages = align_up(size, PGSIZE) / PGSIZE;
        let map_addr = vspace.map_scratch(frame, Perms::READ, pages, res_client, cspace)?;

        let parse_result = {
            let raw = unsafe { core::slice::from_raw_parts(map_addr as *const u8, size) };
            let data = match raw.iter().position(|b| *b == 0) {
                Some(end) => &raw[..end],
                None => raw,
            };
            serde_json::from_slice::<Self>(data).map_err(|_| Error::InvalidConfig)
        };

        let unmap_result = vspace.unmap(map_addr, pages);
        match (parse_result, unmap_result) {
            (Err(e), _) => Err(e),
            (Ok(_), Err(e)) => Err(e),
            (Ok(config), Ok(())) => Ok(config),
        }
    }
}
