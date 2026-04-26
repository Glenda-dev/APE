use crate::ApeManager;
use crate::task as task_subsystem;
use glenda::error::Error;
use glenda::interface::{SystemService, ThreadService};
use linux_raw_sys::general::{
    LINUX_REBOOT_CMD_CAD_OFF, LINUX_REBOOT_CMD_CAD_ON, LINUX_REBOOT_CMD_HALT,
    LINUX_REBOOT_CMD_POWER_OFF, LINUX_REBOOT_CMD_RESTART, LINUX_REBOOT_CMD_RESTART2,
    LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_MAGIC2A, LINUX_REBOOT_MAGIC2B,
    LINUX_REBOOT_MAGIC2C,
};

#[inline]
fn valid_reboot_magic2(v: usize) -> bool {
    matches!(
        v as u32,
        LINUX_REBOOT_MAGIC2 | LINUX_REBOOT_MAGIC2A | LINUX_REBOOT_MAGIC2B | LINUX_REBOOT_MAGIC2C
    )
}

#[inline]
fn reboot_cmd_name(cmd: usize) -> &'static str {
    match cmd as u32 {
        LINUX_REBOOT_CMD_RESTART => "RESTART",
        LINUX_REBOOT_CMD_RESTART2 => "RESTART2",
        LINUX_REBOOT_CMD_POWER_OFF => "POWER_OFF",
        LINUX_REBOOT_CMD_HALT => "HALT",
        LINUX_REBOOT_CMD_CAD_ON => "CAD_ON",
        LINUX_REBOOT_CMD_CAD_OFF => "CAD_OFF",
        _ => "UNKNOWN",
    }
}

fn do_reboot_runtime(mgr: &mut ApeManager<'_>, caller_pid: usize) -> Result<(), Error> {
    let init_pid = if mgr.get_process(1).is_some() { 1 } else { caller_pid };
    let pids = mgr.local_pids();
    for victim in pids {
        if victim == init_pid {
            continue;
        }
        if let Err(e) = mgr.terminate_process(victim, 0) {
            warn!("sys_reboot: failed to terminate pid {} during APE reboot: {:?}", victim, e);
        }
    }

    let init_path = mgr.config().init_path.clone();
    log!("sys_reboot: rebooting APE runtime by exec init pid={}, path={}", init_pid, init_path);
    task_subsystem::do_execve(mgr, init_pid, &init_path, &[], &[])?;

    if init_pid != caller_pid
        && let Some(proc) = mgr.get_process(init_pid)
        && let Err(e) = proc.tcb().resume()
    {
        warn!("sys_reboot: resume init pid {} failed: {:?}", init_pid, e);
    }

    Ok(())
}

pub(crate) fn do_reboot(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    magic: usize,
    magic2: usize,
    cmd: usize,
    _arg: usize,
) -> Result<isize, Error> {
    log!(
        "sys_reboot: pid={}, magic={:#x}, magic2={:#x}, cmd={:#x}({})",
        pid,
        magic,
        magic2,
        cmd,
        reboot_cmd_name(cmd)
    );

    if magic != LINUX_REBOOT_MAGIC1 as usize || !valid_reboot_magic2(magic2) {
        warn!("sys_reboot: invalid magic");
        return Err(Error::InvalidArgs);
    }

    match cmd as u32 {
        LINUX_REBOOT_CMD_CAD_ON | LINUX_REBOOT_CMD_CAD_OFF => {
            log!("sys_reboot: CAD command accepted as no-op");
            // TODO(ape): 实现 CAD 行为配置（Ctrl-Alt-Del 触发动作）并持久化策略。
            Ok(0)
        }
        LINUX_REBOOT_CMD_RESTART | LINUX_REBOOT_CMD_RESTART2 => {
            do_reboot_runtime(mgr, pid)?;
            Ok(0)
        }
        LINUX_REBOOT_CMD_POWER_OFF | LINUX_REBOOT_CMD_HALT => {
            log!("sys_reboot: shutting down APE service (no system reset)");
            mgr.stop();
            Ok(0)
        }
        _ => {
            warn!("sys_reboot: unsupported cmd {:#x}", cmd);
            Err(Error::InvalidArgs)
        }
    }
}
