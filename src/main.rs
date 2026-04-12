#![no_std]
#![no_main]
#![allow(unused)]

#[macro_use]
extern crate glenda;
extern crate alloc;
mod ape;
mod arch;
mod config;
mod elf;
mod fs;
mod init;
mod io;
mod layout;
mod mm;
mod net;
mod proc;
mod syscall;

pub use ape::ApeManager;

use glenda::cap::{
    CSPACE_CAP, CapPtr, CapType, ENDPOINT_CAP, ENDPOINT_SLOT, MONITOR_CAP, RECV_SLOT, REPLY_SLOT,
    VSPACE_CAP,
};
use glenda::client::{
    FsClient, InitClient, ProcessClient, ResourceClient, VirtualTerminalClient, VolumeClient,
};
use glenda::interface::{ResourceService, SystemService};
use glenda::ipc::Badge;
use glenda::protocol::resource::{
    APE_ENDPOINT, FS_ENDPOINT, INIT_ENDPOINT, ResourceType, VOLUME_ENDPOINT, VT_ENDPOINT,
};
use glenda::utils::manager::{CSpaceManager, VSpaceManager};
use layout::*;

#[unsafe(no_mangle)]
fn main() -> usize {
    glenda::console::init_logging("APE");
    log!("Starting ANSI/POSIX Environment...");

    let mut cspace_mgr = CSpaceManager::new(CSPACE_CAP, 16);
    let mut vspace_mgr = VSpaceManager::new(VSPACE_CAP, VSPACE_SCRATCH_START, VSPACE_SCRATCH_END);
    let mut res_client = ResourceClient::new(MONITOR_CAP);
    let mut proc_client = ProcessClient::new(MONITOR_CAP);

    let stat = res_client.status(Badge::null()).expect("Failed to get system status");
    let mem = stat.memory;
    log!(
        "System status: memory: {}/{} MB",
        mem.available_bytes / 1024 / 1024,
        mem.total_bytes / 1024 / 1024
    );

    res_client
        .get_cap(Badge::null(), ResourceType::Endpoint, INIT_ENDPOINT, INIT_SLOT)
        .expect("Failed to get init endpoint");
    let mut init_client = InitClient::new(INIT_CAP);

    res_client
        .get_cap(Badge::null(), ResourceType::Endpoint, FS_ENDPOINT, FS_SLOT)
        .expect("Failed to get fs endpoint");
    let mut fs_client = FsClient::new(FS_CAP);

    res_client
        .get_cap(Badge::null(), ResourceType::Endpoint, VOLUME_ENDPOINT, VOLUME_SLOT)
        .expect("Failed to get volume endpoint");
    let mut vol_client = VolumeClient::new_simple(VOLUME_CAP, &res_client);

    res_client
        .get_cap(Badge::null(), ResourceType::Endpoint, VT_ENDPOINT, VT_SLOT)
        .expect("Failed to get vt endpoint");
    let mut vt_client = VirtualTerminalClient::new(VT_CAP);

    res_client
        .alloc(Badge::null(), CapType::Endpoint, 0, ENDPOINT_SLOT)
        .expect("Failed to alloc endpoint");
    // Register APE endpoint to monitor
    res_client
        .register_cap(Badge::null(), ResourceType::Endpoint, APE_ENDPOINT, ENDPOINT_SLOT)
        .expect("Failed to register APE endpoint");

    let mut ape_mgr = ApeManager::new(
        &mut init_client,
        &mut proc_client,
        &mut res_client,
        &mut vt_client,
        &mut vol_client,
        &mut fs_client,
        &mut cspace_mgr,
        &mut vspace_mgr,
    );

    ape_mgr.listen(ENDPOINT_CAP, RECV_SLOT, REPLY_SLOT).expect("Failed to listen");
    ape_mgr.init().expect("Failed to init");
    ape_mgr.run().expect("Failed to run");
    0
}
