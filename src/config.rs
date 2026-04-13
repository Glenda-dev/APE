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

fn default_init_path() -> String {
    String::from("/bin/sh")
}

fn default_root_partition() -> String {
    String::from("disk0p0")
}

fn default_stdio_vt_name() -> String {
    String::from("vt0")
}

fn default_stdio_seat_id() -> usize {
    0
}

fn default_stdio_devices() -> alloc::vec::Vec<String> {
    alloc::vec![String::from("uart0")]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ApeStdioConfig {
    #[serde(default = "default_stdio_vt_name")]
    pub vt_name: String,
    #[serde(default = "default_stdio_seat_id")]
    pub seat_id: usize,
    #[serde(default = "default_stdio_devices")]
    pub devices: alloc::vec::Vec<String>,
}

impl Default for ApeStdioConfig {
    fn default() -> Self {
        Self {
            vt_name: default_stdio_vt_name(),
            seat_id: default_stdio_seat_id(),
            devices: default_stdio_devices(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ApeConfig {
    #[serde(default = "default_init_path")]
    pub init_path: String,
    #[serde(default = "default_root_partition")]
    pub root_partition: String,
    #[serde(default)]
    pub stdio: ApeStdioConfig,
}

impl Default for ApeConfig {
    fn default() -> Self {
        Self {
            init_path: default_init_path(),
            root_partition: default_root_partition(),
            stdio: ApeStdioConfig::default(),
        }
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
