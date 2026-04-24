use crate::ApeManager;
use crate::layout::{
    APE_ASYNC_NOTIFY_BADGE_BITS, APE_ASYNC_WORKER_COUNT, APE_ASYNC_WORKER_STACK_PAGES,
    APE_ASYNC_WORKER_STACK_SIZE, APE_ASYNC_WORKER_STACK0_BASE, TIME_CAP,
};
use crate::syscall::map_error_to_errno;
use alloc::vec::Vec;
use core::cmp::max;
use glenda::cap::{CSPACE_CAP, CapPtr, CapType, ENDPOINT_CAP, Endpoint, Page, Reply};
use glenda::client::TimeClient;
use glenda::error::Error;
use glenda::interface::{CSpaceService, ResourceService, TimeService, VSpaceService};
use glenda::ipc::{Badge, UTCB};
use glenda::mem::Perms;
use glenda::runtime::{RuntimeThreadConfig, ThreadPoolBuilder, WorkerThreadSpec};
use glenda::sync::channel::bounded;
use linux_raw_sys::errno::EINTR;
use linux_raw_sys::general::__kernel_timespec;

use super::{ApeAsyncRuntime, PendingSleepReply, SleepCompletion};

const APE_ASYNC_SLEEP_QUEUE_CAPACITY: usize = 64;
const APE_ASYNC_WORKER_STACK_SPAN: usize = 0x20_000;
const NSEC_PER_SEC: u64 = 1_000_000_000;

#[inline]
fn ns_to_timespec(ns: u64) -> __kernel_timespec {
    __kernel_timespec {
        tv_sec: i64::try_from(ns / NSEC_PER_SEC).unwrap_or(i64::MAX),
        tv_nsec: i64::try_from(ns % NSEC_PER_SEC).unwrap_or(0),
    }
}

impl<'a> ApeManager<'a> {
    fn alloc_async_worker_stack(&mut self, stack_base: usize) -> Result<usize, Error> {
        let frame_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        let page_level =
            CapType::page_pages_to_level(APE_ASYNC_WORKER_STACK_PAGES).ok_or(Error::InvalidArgs)?;
        self.res_client.alloc(Badge::null(), CapType::Page, page_level, frame_slot)?;

        self.vspace_mgr.map_page(
            Page::from(frame_slot),
            stack_base,
            Perms::READ | Perms::WRITE,
            APE_ASYNC_WORKER_STACK_PAGES,
            &mut *self.res_client,
            &mut *self.cspace_mgr,
        )?;

        Ok(stack_base + APE_ASYNC_WORKER_STACK_SIZE)
    }

    fn alloc_async_worker_spec(&mut self, worker_id: usize) -> Result<WorkerThreadSpec, Error> {
        let park_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        self.res_client.alloc(Badge::null(), CapType::Endpoint, 0, park_slot)?;
        let park_ep = Endpoint::from(park_slot);
        let stack_base = APE_ASYNC_WORKER_STACK0_BASE + worker_id * APE_ASYNC_WORKER_STACK_SPAN;
        let stack_top = self.alloc_async_worker_stack(stack_base)?;

        Ok(WorkerThreadSpec {
            stack_top,
            thread: RuntimeThreadConfig::new(park_ep, CapPtr::null(), CapPtr::null())
                .with_worker_id(worker_id),
        })
    }

    pub(crate) fn start_async_runtime(&mut self) -> Result<(), Error> {
        if self.async_runtime.is_some() {
            return Ok(());
        }

        let (sleep_done_tx, sleep_done_rx) = bounded(APE_ASYNC_SLEEP_QUEUE_CAPACITY);
        let mut specs = Vec::with_capacity(APE_ASYNC_WORKER_COUNT);
        for worker_id in 0..APE_ASYNC_WORKER_COUNT {
            specs.push(self.alloc_async_worker_spec(worker_id)?);
        }

        let sleep_pool = ThreadPoolBuilder::new()
            .with_queue_capacity(APE_ASYNC_SLEEP_QUEUE_CAPACITY)
            .build(self.proc_client, &specs)?;

        self.async_runtime = Some(ApeAsyncRuntime {
            sleep_pool,
            sleep_done_tx,
            sleep_done_rx,
            next_sleep_request_id: 1,
            pending_sleep_replies: Default::default(),
        });
        log!("Async runtime started with {} worker threads", APE_ASYNC_WORKER_COUNT);
        Ok(())
    }

    fn alloc_pending_reply_slot(&mut self) -> Result<CapPtr, Error> {
        let src_reply = self.ipc.reply.cap();
        if src_reply.is_null() {
            return Err(Error::InvalidCapability);
        }

        let mut retry = 0usize;
        let reply_slot = loop {
            let slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
            if slot == src_reply {
                self.cspace_mgr.free(slot);
                retry = retry.saturating_add(1);
                if retry > 64 {
                    return Err(Error::OutOfMemory);
                }
                continue;
            }
            break slot;
        };

        if let Err(e) = CSPACE_CAP.transfer_self(src_reply, reply_slot) {
            self.cspace_mgr.free(reply_slot);
            return Err(e);
        }
        Ok(reply_slot)
    }

    pub(crate) fn schedule_nanosleep_async(
        &mut self,
        pid: usize,
        req_ns: u64,
        rem_ptr: usize,
    ) -> Result<(), Error> {
        let deadline_ns = self.time_client.mono_now(Badge::null())?.saturating_add(req_ns);
        let reply_slot = self.alloc_pending_reply_slot()?;
        let sleep_ms = usize::try_from(req_ns.div_ceil(1_000_000)).unwrap_or(usize::MAX);

        let (request_id, sleep_done_tx) = {
            let runtime = self.async_runtime.as_mut().ok_or(Error::NotInitialized)?;
            let request_id = runtime.next_sleep_request_id;
            runtime.next_sleep_request_id = runtime.next_sleep_request_id.saturating_add(1);
            runtime
                .pending_sleep_replies
                .insert(pid, PendingSleepReply { reply_slot, rem_ptr, deadline_ns, request_id });
            (request_id, runtime.sleep_done_tx.clone())
        };

        let runtime = self.async_runtime.as_ref().ok_or(Error::NotInitialized)?;
        let _ = runtime.sleep_pool.spawn_blocking(move || {
            let mut time_client = TimeClient::new(TIME_CAP);
            let _ = time_client.sleep(Badge::null(), max(1, sleep_ms));
            sleep_done_tx.send(SleepCompletion { pid, request_id });
            let _ = ENDPOINT_CAP.notify(Badge::new(APE_ASYNC_NOTIFY_BADGE_BITS));
        });
        Ok(())
    }

    fn take_pending_sleep_reply(&mut self, pid: usize) -> Option<PendingSleepReply> {
        self.async_runtime.as_mut().and_then(|runtime| runtime.pending_sleep_replies.remove(&pid))
    }

    pub(crate) fn drop_pending_sleep_reply(&mut self, pid: usize) {
        if let Some(pending) = self.take_pending_sleep_reply(pid) {
            let _ = CSPACE_CAP.delete(pending.reply_slot);
            self.cspace_mgr.free(pending.reply_slot);
        }
    }

    fn reply_pending_sleep(
        &mut self,
        pid: usize,
        pending: PendingSleepReply,
        ret: isize,
        remain_ns: Option<u64>,
    ) -> Result<(), Error> {
        let mut final_ret = ret;
        if pending.rem_ptr != 0 {
            let ts = ns_to_timespec(remain_ns.unwrap_or(0));
            if let Err(e) = self.write_obj_to_user(pid, pending.rem_ptr, &ts) {
                final_ret = map_error_to_errno(e);
            }
        }

        let mut utcb = unsafe { UTCB::new() };
        utcb.clear();
        utcb.set_mr(0, final_ret as usize);
        let reply_result = Reply::from(pending.reply_slot).reply(&mut utcb);
        let _ = CSPACE_CAP.delete(pending.reply_slot);
        self.cspace_mgr.free(pending.reply_slot);
        reply_result
    }

    pub(crate) fn interrupt_pending_sleep_reply(&mut self, pid: usize) -> bool {
        let Some(pending) = self.take_pending_sleep_reply(pid) else {
            return false;
        };

        let now = self.time_client.mono_now(Badge::null()).unwrap_or(0);
        let remain_ns = pending.deadline_ns.saturating_sub(now);
        if let Err(e) = self.reply_pending_sleep(pid, pending, -(EINTR as isize), Some(remain_ns)) {
            warn!("nanosleep: failed to reply EINTR for pid={}: {:?}", pid, e);
        }
        true
    }

    fn complete_sleep_reply(&mut self, completion: SleepCompletion) -> Result<(), Error> {
        let pending = {
            let Some(runtime) = self.async_runtime.as_mut() else {
                return Ok(());
            };
            let Some(current) = runtime.pending_sleep_replies.get(&completion.pid).copied() else {
                return Ok(());
            };
            if current.request_id != completion.request_id {
                return Ok(());
            }
            runtime.pending_sleep_replies.remove(&completion.pid).unwrap()
        };

        self.reply_pending_sleep(completion.pid, pending, 0, Some(0))
    }

    pub(crate) fn drain_async_events(&mut self) -> Result<(), Error> {
        loop {
            let completion = {
                let Some(runtime) = self.async_runtime.as_ref() else {
                    return Ok(());
                };
                runtime.sleep_done_rx.try_recv()
            };
            let Some(completion) = completion else {
                break;
            };
            self.complete_sleep_reply(completion)?;
        }
        Ok(())
    }
}
