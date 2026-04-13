use glenda::error::Error;
use linux_raw_sys::errno::*;

pub(crate) fn map_error_to_errno(err: Error) -> isize {
    match err {
        Error::OutOfMemory | Error::CNodeFull => -(ENOMEM as isize),
        Error::InvalidArgs | Error::InvalidConfig => -(EINVAL as isize),
        Error::InvalidCapability | Error::InvalidMethod => -(EINVAL as isize),
        Error::InvalidType => -(ENOTTY as isize),
        Error::InvalidAddress => -(EFAULT as isize),
        Error::MessageTooLong => -(ENAMETOOLONG as isize),
        Error::InvalidSlot => -(EBADF as isize),
        Error::SlotNotEmpty => -(EEXIST as isize),
        Error::NotFound => -(ENOENT as isize),
        Error::AlreadyExists => -(EEXIST as isize),
        Error::ResourceBusy => -(EBUSY as isize),
        Error::WouldBlock => -(EAGAIN as isize),
        Error::Interrupted => -(EINTR as isize),
        Error::Timeout => -(ETIMEDOUT as isize),
        Error::PermissionDenied => -(EPERM as isize),
        Error::NotSupported | Error::NotImplemented => -(ENOSYS as isize),
        Error::IoError | Error::DeviceError | Error::InternalError | Error::Generic => {
            -(EIO as isize)
        }
        _ => -(ENOSYS as isize),
    }
}
