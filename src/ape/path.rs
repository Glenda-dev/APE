use crate::layout::DEFAULT_PROCESS_ROOT;
use alloc::string::String;

pub fn resolve_path(raw_path: &str, root_dir: &str, cwd: &str) -> String {
    libape::path::resolve_path(raw_path, root_dir, cwd, DEFAULT_PROCESS_ROOT)
}

pub fn path_inside_root(abs_path: &str, root_dir: &str) -> Option<String> {
    libape::path::path_inside_root(abs_path, root_dir, DEFAULT_PROCESS_ROOT)
}
