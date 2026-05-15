use std::time::Duration;

use crate::net::mpc_engine::{MpcEngineError, MpcSessionTopologyError};
use crate::storage::preproc::PreprocStoreError;
use crate::VirtualMachineError;

pub type MpcRunnerResult<T> = Result<T, MpcRunnerError>;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MpcRunnerError {
    #[error("MPC runner VM is already executing")]
    VmAlreadyExecuting,
    #[error("MPC runner VM guard no longer owns the VM")]
    VmGuardEmpty,
    #[error("MPC runner VM slot was occupied during restore")]
    VmSlotOccupiedDuringRestore,
    #[error("Execution timed out after {timeout:?}")]
    ExecutionTimedOut { timeout: Duration },
    #[error("Join error: {source:?}")]
    Join {
        #[source]
        source: tokio::task::JoinError,
    },
    #[error("MPC {operation} failed: {reason}")]
    MpcBackendOperationFailed {
        operation: &'static str,
        reason: String,
    },
    #[error(transparent)]
    MpcSessionTopology(#[from] MpcSessionTopologyError),
    #[error(transparent)]
    PreprocStore(#[from] PreprocStoreError),
    #[error(transparent)]
    VirtualMachine(#[from] VirtualMachineError),
}

impl From<MpcRunnerError> for String {
    fn from(error: MpcRunnerError) -> Self {
        error.to_string()
    }
}

pub(super) trait MpcRunnerBackendResultExt<T> {
    fn map_mpc_runner_backend_err(self, operation: &'static str) -> MpcRunnerResult<T>;
}

impl<T> MpcRunnerBackendResultExt<T> for Result<T, String> {
    fn map_mpc_runner_backend_err(self, operation: &'static str) -> MpcRunnerResult<T> {
        self.map_err(|reason| MpcRunnerError::MpcBackendOperationFailed { operation, reason })
    }
}

impl<T> MpcRunnerBackendResultExt<T> for Result<T, MpcEngineError> {
    fn map_mpc_runner_backend_err(self, operation: &'static str) -> MpcRunnerResult<T> {
        self.map_err(|error| MpcRunnerError::MpcBackendOperationFailed {
            operation,
            reason: error.into_backend_reason(operation),
        })
    }
}
