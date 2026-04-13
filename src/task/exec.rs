use crate::ApeManager;
use glenda::error::Error;

pub(crate) fn do_execve(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    filename_ptr: usize,
    argv_ptr: usize,
    envp_ptr: usize,
) -> Result<(), Error> {
    let exec_input = mgr.parse_execve_user_input(pid, filename_ptr, argv_ptr, envp_ptr)?;

    // 保持行为与 Linux 接近：允许 filename 与 argv[0] 不同。
    mgr.do_execve_path(pid, &exec_input.filename, &exec_input.argv, &exec_input.envp)
}
