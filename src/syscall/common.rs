use glenda::error::Error;

pub(crate) fn map_error_to_errno(err: Error) -> isize {
    libape::compat::map_error_to_errno(err)
}
