#![no_std]
#![no_main]
#![allow(unused)]

#[macro_use]
extern crate glenda;
extern crate alloc;
mod ape;
mod arch;
mod config;
mod drivers;
mod elf;
mod fs;
mod io;
mod layout;
mod mm;
mod net;
mod syscall;
mod system;
mod task;
mod vfs;

pub use ape::ApeManager;

use glenda::cap::{
    CSPACE_CAP, CapPtr, CapType, ENDPOINT_CAP, ENDPOINT_SLOT, MONITOR_CAP, RECV_SLOT, REPLY_SLOT,
    VSPACE_CAP,
};
use glenda::client::{
    AuthClient, FsClient, InitClient, ProcessClient, ResourceClient, TimeClient,
    VirtualTerminalClient, VolumeClient,
};
use glenda::interface::{CSpaceService, ResourceService, SystemService};
use glenda::ipc::Badge;
use glenda::protocol::resource::{
    APE_ENDPOINT, FACTOTUM_ENDPOINT, FS_ENDPOINT, INIT_ENDPOINT, ResourceType, TIME_ENDPOINT,
    VOLUME_ENDPOINT, VT_ENDPOINT,
};
use glenda::runtime::{RuntimeThreadConfig, init_current_thread};
use glenda::utils::manager::{CSpaceManager, VSpaceManager};
use layout::*;

#[unsafe(no_mangle)]
fn main() -> usize {
    glenda::console::init_logging("APE");
    log!("Starting ANSI/POSIX Environment...");

    let mut cspace_mgr = CSpaceManager::new(CSPACE_CAP, CSPACE_DYNAMIC_L1_START_SLOT);
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
        .get_cap(Badge::null(), ResourceType::Endpoint, TIME_ENDPOINT, TIME_SLOT)
        .expect("Failed to get time endpoint");
    let mut time_client = TimeClient::new(TIME_CAP);

    res_client
        .get_cap(Badge::null(), ResourceType::Endpoint, FACTOTUM_ENDPOINT, AUTH_SLOT)
        .expect("Failed to get factotum endpoint");
    let mut auth_client = AuthClient::new(AUTH_CAP);

    res_client
        .alloc(Badge::null(), CapType::Endpoint, 0, ENDPOINT_SLOT)
        .expect("Failed to alloc endpoint");

    let main_park_slot =
        cspace_mgr.alloc(&mut res_client).expect("Failed to alloc APE main park slot");
    res_client
        .alloc(Badge::null(), CapType::Endpoint, 0, main_park_slot)
        .expect("Failed to alloc APE main park endpoint");
    init_current_thread(RuntimeThreadConfig::new(
        glenda::cap::Endpoint::from(main_park_slot),
        CapPtr::null(),
        CapPtr::null(),
    ))
    .expect("Failed to init APE main thread runtime");

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
        &mut time_client,
        &mut auth_client,
        &mut cspace_mgr,
        &mut vspace_mgr,
    );

    ape_mgr.listen(ENDPOINT_CAP, REPLY_SLOT, RECV_SLOT).expect("Failed to listen");
    ape_mgr.init().expect("Failed to init");
    ape_mgr.run().expect("Failed to run");
    0
}
