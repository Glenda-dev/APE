use crate::ApeManager;
use crate::layout::{
    APE_ASYNC_NOTIFY_BADGE_BITS, APE_DISPATCHER_STACK_PAGES, APE_DISPATCHER_STACK_SIZE,
    APE_DISPATCHER_STACK_SPAN, APE_DISPATCHER_STACK0_BASE,
};
use alloc::sync::Arc;
use glenda::cap::{CSPACE_CAP, CapPtr, Endpoint, Reply};
use glenda::client::ProcessClient;
use glenda::error::Error;
use glenda::interface::FaultService;
use glenda::interface::{
    CSpaceService, InitService, ResourceService, SystemService, ThreadService, VSpaceService,
};
use glenda::ipc::{Badge, UTCB};
use glenda::mem::Perms;
use glenda::protocol;
use glenda::runtime::{RuntimeThreadConfig, RuntimeWorker, spawn_worker};
use glenda::sync::mutex::Mutex;
use libape::policy::decode_ape_syscall;

impl<'a> SystemService for ApeManager<'a> {
    fn init(&mut self) -> Result<(), Error> {
        self.bootstrap()
    }

    fn listen(&mut self, ep: Endpoint, reply: CapPtr, recv: CapPtr) -> Result<(), Error> {
        self.service_state.ipc.endpoint = ep;
        self.service_state.ipc.reply = Reply::from(reply);
        self.service_state.ipc.recv = recv;
        Ok(())
    }
    fn run(&mut self) -> Result<(), Error> {
        if self.service_state.ipc.endpoint.cap().is_null()
            || self.service_state.ipc.reply.cap().is_null()
        {
            return Err(Error::NotInitialized);
        }
        self.init_client.report_service(Badge::null(), protocol::init::ServiceState::Running)?;
        self.service_state.ipc.running = true;
        while self.service_state.ipc.running {
            if let Err(e) = self.drain_async_events() {
                warn!("async runtime drain failed before recv: {:?}", e);
            }
            let mut utcb = unsafe { UTCB::new() };
            utcb.clear();
            utcb.set_reply_window(self.service_state.ipc.reply.cap());
            utcb.set_recv_window(self.service_state.ipc.recv);
            if let Err(e) = self.service_state.ipc.endpoint.recv(&mut utcb) {
                error!("Recv error: {:?}", e);
                continue;
            }
            if utcb.get_badge().bits() == APE_ASYNC_NOTIFY_BADGE_BITS {
                if let Err(e) = self.drain_async_events() {
                    warn!("async runtime drain failed after notify: {:?}", e);
                }
                continue;
            }
            self.set_active_caller_pid(utcb.get_badge().bits());
            let should_reply = match self.dispatch(&mut utcb) {
                Ok(()) => true,
                Err(Error::Success) => false,
                Err(e) => {
                    error!("Dispatch error: {:?}", e);
                    false
                }
            };
            self.clear_active_caller_pid();

            if should_reply && let Err(e) = self.reply(&mut utcb) {
                error!("Reply error: {:?}", e);
            }
        }
        Ok(())
    }
    fn dispatch(&mut self, utcb: &mut UTCB) -> Result<(), Error> {
        let badge = utcb.get_badge();
        let msg_tag = utcb.get_msg_tag();
        let proto = msg_tag.proto();
        let label = msg_tag.label();

        glenda::ipc_dispatch! {
            self, utcb,
            (protocol::KERNEL_PROTO, protocol::kernel::SYSCALL) => |s: &mut ApeManager, utcb: &mut UTCB| {
                let mut args = [0usize; 8];
                for i in 0..8 {
                    args[i] = utcb.get_mr(i);
                }
                s.handle_syscall(badge.bits(), args)
            },
            (protocol::KERNEL_PROTO, protocol::kernel::PAGE_FAULT) => |s: &mut ApeManager, utcb: &mut UTCB| s.page_fault(badge, utcb.get_mr(0), utcb.get_mr(1), utcb.get_mr(2)),
            (protocol::KERNEL_PROTO, protocol::kernel::ILLEGAL_INSTRUCTION) => |s: &mut ApeManager, utcb: &mut UTCB| s.illegal_instruction(badge, utcb.get_mr(0), utcb.get_mr(1)),
            (protocol::KERNEL_PROTO, protocol::kernel::BREAKPOINT) => |s: &mut ApeManager, utcb: &mut UTCB| s.breakpoint(badge, utcb.get_mr(0)),
            (protocol::KERNEL_PROTO, protocol::kernel::ACCESS_FAULT) => |s: &mut ApeManager, utcb: &mut UTCB| s.access_fault(badge, utcb.get_mr(0), utcb.get_mr(1)),
            (protocol::KERNEL_PROTO, protocol::kernel::VIRT_EXIT) => |s: &mut ApeManager, utcb: &mut UTCB| s.virt_exit(badge, utcb.get_mr(0), utcb.get_mr(1), utcb.get_mr(2), utcb.get_mr(3)),
            (protocol::KERNEL_PROTO, protocol::kernel::UNKNOWN_FAULT) => |s: &mut ApeManager, utcb: &mut UTCB| s.unknown_fault(badge, utcb.get_mr(0), utcb.get_mr(1), utcb.get_mr(2)),
            (protocol::KERNEL_PROTO, protocol::kernel::NOTIFY) => |s: &mut ApeManager, utcb: &mut UTCB| {
                if let Err(e) = s.drain_async_events() {
                    warn!("async runtime drain failed in notify: {:?}", e);
                }
                Err(Error::Success)
            },
            (_, _) => |_: &mut ApeManager, _: &mut UTCB| Err(Error::InvalidProtocol),
        }
    }
    fn reply(&mut self, utcb: &mut UTCB) -> Result<(), Error> {
        self.service_state.ipc.reply.reply(utcb)
    }
    fn stop(&mut self) {
        self.service_state.ipc.running = false;
        log!("Shutting down...");
        let _ =
            self.init_client.report_service(Badge::null(), protocol::init::ServiceState::Stopped);
    }
}

#[derive(Clone)]
pub struct ApeSharedManager(pub Arc<Mutex<ApeManager<'static>>>);

struct ApeDispatchWorkerConfig {
    shared: ApeSharedManager,
    endpoint: Endpoint,
    reply_slot: CapPtr,
    recv_slot: CapPtr,
}

#[derive(Debug, Clone, Copy)]
pub struct ApeDispatchThreadSpec {
    pub stack_top: usize,
    pub reply_slot: CapPtr,
    pub recv_slot: CapPtr,
    pub thread: RuntimeThreadConfig,
}

struct ApeDispatchWorker;

impl RuntimeWorker for ApeDispatchWorker {
    type Config = ApeDispatchWorkerConfig;

    fn run(config: Self::Config) -> ! {
        run_dispatch_loop(config.shared, config.endpoint, config.reply_slot, config.recv_slot)
    }
}

fn run_dispatch_loop(
    shared: ApeSharedManager,
    endpoint: Endpoint,
    reply_slot: CapPtr,
    recv_slot: CapPtr,
) -> ! {
    loop {
        {
            let mgr = shared.0.lock();
            if !mgr.service_state.ipc.running {
                glenda::sys::exit(0);
            }
        }

        let utcb = unsafe { UTCB::new() };
        utcb.clear();
        utcb.set_reply_window(reply_slot);
        utcb.set_recv_window(recv_slot);

        if let Err(e) = endpoint.recv(utcb) {
            error!("Recv error: {:?}", e);
            continue;
        }

        if utcb.get_badge().bits() == APE_ASYNC_NOTIFY_BADGE_BITS {
            let mut mgr = shared.0.lock();
            if let Err(e) = mgr.drain_async_events() {
                warn!("async runtime drain failed after notify: {:?}", e);
            }
            continue;
        }

        let caller_pid = utcb.get_badge().bits();
        let should_reply = {
            let mut mgr = shared.0.lock();
            mgr.service_state.ipc.endpoint = endpoint;
            mgr.service_state.ipc.reply = Reply::from(reply_slot);
            mgr.service_state.ipc.recv = recv_slot;
            mgr.set_active_caller_pid(caller_pid);
            let should_reply = match mgr.dispatch(utcb) {
                Ok(()) => true,
                Err(Error::Success) => false,
                Err(e) => {
                    error!("Dispatch error: {:?}", e);
                    false
                }
            };
            mgr.clear_active_caller_pid();
            should_reply
        };

        if should_reply && let Err(e) = Reply::from(reply_slot).reply(utcb) {
            error!("Reply error: {:?}", e);
        }
    }
}

pub fn run_multithreaded(shared: ApeSharedManager) -> ! {
    let (endpoint, worker_specs) = {
        let mut mgr = shared.0.lock();
        if mgr.service_state.ipc.endpoint.cap().is_null()
            || mgr.service_state.ipc.reply.cap().is_null()
        {
            panic!("APE not initialized before multithreaded run");
        }
        mgr.init_client
            .report_service(Badge::null(), protocol::init::ServiceState::Running)
            .expect("Failed to report APE running");
        mgr.service_state.ipc.running = true;

        let endpoint = mgr.service_state.ipc.endpoint;
        let mut specs = alloc::vec::Vec::new();
        for worker_id in 1..crate::layout::APE_DISPATCHER_COUNT {
            specs.push(mgr.alloc_dispatch_thread_spec(worker_id).expect("alloc dispatch worker"));
        }
        (endpoint, specs)
    };

    {
        let mut proc_client = ProcessClient::new(glenda::cap::MONITOR_CAP);
        for spec in worker_specs {
            let config = ApeDispatchWorkerConfig {
                shared: shared.clone(),
                endpoint,
                reply_slot: spec.reply_slot,
                recv_slot: spec.recv_slot,
            };
            spawn_worker::<ApeDispatchWorker>(
                &mut proc_client,
                spec.thread,
                config,
                spec.stack_top,
            )
            .expect("spawn APE dispatch worker");
        }
    }

    run_dispatch_loop(shared, endpoint, glenda::cap::REPLY_SLOT, glenda::cap::RECV_SLOT)
}

impl ApeManager<'_> {
    fn alloc_dispatch_stack(&mut self, stack_base: usize) -> Result<usize, Error> {
        let frame_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        let page_level = glenda::cap::CapType::page_pages_to_level(APE_DISPATCHER_STACK_PAGES)
            .ok_or(Error::InvalidArgs)?;
        self.res_client.alloc(Badge::null(), glenda::cap::CapType::Page, page_level, frame_slot)?;

        self.vspace_mgr.map_page(
            glenda::cap::Page::from(frame_slot),
            stack_base,
            Perms::READ | Perms::WRITE,
            APE_DISPATCHER_STACK_PAGES,
            &mut *self.res_client,
            &mut *self.cspace_mgr,
        )?;

        Ok(stack_base + APE_DISPATCHER_STACK_SIZE)
    }

    pub fn alloc_dispatch_thread_spec(
        &mut self,
        worker_id: usize,
    ) -> Result<ApeDispatchThreadSpec, Error> {
        let reply_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        let recv_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        let park_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        self.res_client.alloc(Badge::null(), glenda::cap::CapType::Endpoint, 0, park_slot)?;
        let stack_base = APE_DISPATCHER_STACK0_BASE + (worker_id - 1) * APE_DISPATCHER_STACK_SPAN;
        let stack_top = self.alloc_dispatch_stack(stack_base)?;

        Ok(ApeDispatchThreadSpec {
            stack_top,
            reply_slot,
            recv_slot,
            thread: RuntimeThreadConfig::new(Endpoint::from(park_slot), recv_slot, reply_slot)
                .with_worker_id(worker_id),
        })
    }
}
