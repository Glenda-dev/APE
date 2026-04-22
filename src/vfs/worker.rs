use glenda::client::ProcessClient;
use glenda::error::Error;
use glenda::vfs::{FsRpcWorker, VfsWorkerFactory, VfsWorkerServer, spawn_vfs_worker};

use super::server::{DevTmpFsNamespace, PipeFsNamespace, TmpFsNamespace};

#[derive(Clone, Copy)]
pub enum VfsWorkerKind {
    DevTmpFs,
    TmpFs,
    PipeFs,
}

pub struct ApeVfsWorkerFactory;

impl VfsWorkerFactory for ApeVfsWorkerFactory {
    type Kind = VfsWorkerKind;

    fn create_server(kind: Self::Kind) -> alloc::boxed::Box<dyn VfsWorkerServer> {
        match kind {
            VfsWorkerKind::DevTmpFs => {
                alloc::boxed::Box::new(FsRpcWorker::new(DevTmpFsNamespace::new()))
            }
            VfsWorkerKind::TmpFs => alloc::boxed::Box::new(FsRpcWorker::new(TmpFsNamespace::new())),
            VfsWorkerKind::PipeFs => {
                alloc::boxed::Box::new(FsRpcWorker::new(PipeFsNamespace::new()))
            }
        }
    }
}

pub type VfsWorkerConfig = glenda::vfs::VfsWorkerConfig<ApeVfsWorkerFactory>;

pub fn spawn_worker(
    proc_client: &mut ProcessClient,
    cfg: VfsWorkerConfig,
    stack_top: usize,
) -> Result<usize, Error> {
    spawn_vfs_worker::<ApeVfsWorkerFactory>(proc_client, cfg, stack_top)
}
