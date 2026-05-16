use crate::foreign_functions::ForeignFunctionError;
use crate::mpc_values::MpcValueError;
use crate::net::client_store::{ClientInputStoreError, ClientShareIndex};
use crate::net::mpc_engine::{MpcEngineError, MpcEngineIdentity};
use crate::net::reveal_batcher::RevealBatchError;
use crate::net::share_algebra::ShareAlgebraError;
use crate::runtime_hooks::HookError;
use crate::runtime_value_ops::ValueOpError;
use std::error::Error;
use std::fmt;
use stoffel_vm_types::activations::ActivationError;
use stoffel_vm_types::core_types::{ForeignObjectError, TableMemoryError};
use stoffel_vm_types::functions::FunctionError;

pub(crate) type VmResult<T> = Result<T, VmError>;

pub(crate) trait MpcBackendResultExt<T> {
    fn map_mpc_backend_err(self, operation: &'static str) -> VmResult<T>;
}

impl<T> MpcBackendResultExt<T> for Result<T, String> {
    fn map_mpc_backend_err(self, operation: &'static str) -> VmResult<T> {
        self.map_err(|reason| VmError::MpcBackendOperationFailed { operation, reason })
    }
}

impl<T> MpcBackendResultExt<T> for Result<T, MpcEngineError> {
    fn map_mpc_backend_err(self, operation: &'static str) -> VmResult<T> {
        self.map_err(|error| VmError::MpcBackendOperationFailed {
            operation,
            reason: error.into_backend_reason(operation),
        })
    }
}

impl<T> MpcBackendResultExt<T> for Result<T, ShareAlgebraError> {
    fn map_mpc_backend_err(self, operation: &'static str) -> VmResult<T> {
        self.map_err(|error| VmError::MpcBackendOperationFailed {
            operation,
            reason: error.to_string(),
        })
    }
}

/// Public VM error type.
///
/// The runtime keeps detailed internal error variants for VM execution,
/// memory, hook, and MPC subsystems. This wrapper exposes an idiomatic
/// `std::error::Error` surface without forcing public callers to depend on
/// every internal implementation detail.
#[derive(Debug)]
pub struct VirtualMachineError {
    inner: Box<VmError>,
}

pub type VirtualMachineResult<T> = Result<T, VirtualMachineError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VirtualMachineErrorKind {
    Activation,
    ClientInput,
    ForeignFunction,
    ForeignObject,
    Function,
    Hook,
    Message,
    Mpc,
    Registration,
    Runtime,
    TableMemory,
    Value,
}

impl VirtualMachineError {
    pub(crate) fn new(inner: VmError) -> Self {
        Self {
            inner: Box::new(inner),
        }
    }

    pub fn kind(&self) -> VirtualMachineErrorKind {
        self.inner.kind()
    }
}

impl VmError {
    pub(crate) fn kind(&self) -> VirtualMachineErrorKind {
        match self {
            VmError::Activation(_) => VirtualMachineErrorKind::Activation,
            VmError::ClientInputStore(_) => VirtualMachineErrorKind::ClientInput,
            VmError::ForeignFunction(_) => VirtualMachineErrorKind::ForeignFunction,
            VmError::ForeignObject(_) => VirtualMachineErrorKind::ForeignObject,
            VmError::Function(_) => VirtualMachineErrorKind::Function,
            VmError::Hook(_) => VirtualMachineErrorKind::Hook,
            VmError::Message(_) => VirtualMachineErrorKind::Message,
            VmError::MpcValue(_)
            | VmError::RevealBatch(_)
            | VmError::MpcEngineNotConfigured
            | VmError::MpcEngineNotReady
            | VmError::MpcBackendOperationFailed { .. }
            | VmError::AsyncMpcEngineMismatch { .. }
            | VmError::MpcOutputEngineNotConfigured
            | VmError::MpcOutputEngineNotReady
            | VmError::ShareDataFormatMismatch { .. }
            | VmError::ShareDataBatchFormatMismatch { .. }
            | VmError::ClientShareNotFound { .. }
            | VmError::ClientShareTypeMismatch { .. }
            | VmError::InvalidShareRevealValue => VirtualMachineErrorKind::Mpc,
            VmError::FunctionAlreadyRegistered { .. }
            | VmError::RegistrationDuplicateFunction { .. }
            | VmError::RegistrationFunctionAlreadyRegistered { .. } => {
                VirtualMachineErrorKind::Registration
            }
            #[cfg(test)]
            VmError::NoActivationRecordToExecute => VirtualMachineErrorKind::Runtime,
            VmError::NoActiveActivationRecord
            | VmError::UnexpectedEndOfExecution
            | VmError::StackLengthOverflow
            | VmError::StackAddressOverflow { .. }
            | VmError::StackAddressOutOfBounds { .. }
            | VmError::RegisterOutOfBounds { .. }
            | VmError::PendingRevealWithoutQueuedBatch { .. }
            | VmError::ClearValueInSecretRegister { .. }
            | VmError::FunctionArityMismatch { .. }
            | VmError::EntryFunctionRequiresUpvalues { .. }
            | VmError::UpvalueNotFound { .. }
            | VmError::ClosureUpvalueNotFound { .. }
            | VmError::UpvalueReadNotFound { .. }
            | VmError::UpvalueWriteNotFound { .. }
            | VmError::ExpectedClosure { .. }
            | VmError::ForeignFunctionAsClosure { .. }
            | VmError::QuotedFunctionNotFound { .. }
            | VmError::FunctionNotFound { .. }
            | VmError::CannotExecuteForeignFunction { .. }
            | VmError::MissingResolvedInstructions { .. }
            | VmError::RuntimeInstructionMetadataMismatch { .. }
            | VmError::JumpTargetOutOfBounds { .. }
            | VmError::ConstantOutOfBounds { .. }
            | VmError::InvalidFunctionNameConstant { .. } => VirtualMachineErrorKind::Runtime,
            #[cfg(test)]
            VmError::InstructionOutOfBounds { .. } => VirtualMachineErrorKind::Runtime,
            VmError::TableMemory(_) => VirtualMachineErrorKind::TableMemory,
            VmError::ValueOp(error) => error
                .runtime_error()
                .map_or(VirtualMachineErrorKind::Value, VmError::kind),
        }
    }
}

impl fmt::Display for VirtualMachineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl Error for VirtualMachineError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.inner.source()
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum VmError {
    #[error("{0}")]
    Message(String),
    #[error("No active activation record")]
    NoActiveActivationRecord,
    #[error("No activation record to execute")]
    #[cfg(test)]
    NoActivationRecordToExecute,
    #[error("Unexpected end of execution")]
    UnexpectedEndOfExecution,
    #[error("Stack length exceeds VM address range")]
    StackLengthOverflow,
    #[error("Stack address [sp+{offset}] overflows VM address range")]
    StackAddressOverflow { offset: i32 },
    #[error("Stack address [sp+{offset}] out of bounds")]
    StackAddressOutOfBounds { offset: i32 },
    #[error("Register r{register} out of bounds for frame with {register_count} registers")]
    RegisterOutOfBounds {
        register: usize,
        register_count: usize,
    },
    #[error("Register r{register} is pending a reveal, but no queued reveal can resolve it")]
    PendingRevealWithoutQueuedBatch { register: usize },
    #[error(
        "Cannot write clear {value_type} value directly to secret register r{register}: {reason}"
    )]
    ClearValueInSecretRegister {
        value_type: &'static str,
        register: usize,
        reason: String,
    },
    #[error("Invalid share type for conversion to clear value")]
    InvalidShareRevealValue,
    #[error("Function {function} expects {expected} arguments but got {actual}")]
    FunctionArityMismatch {
        function: String,
        expected: usize,
        actual: usize,
    },
    #[error(
        "Cannot execute function {function} as an entry point because it requires captured upvalues: {upvalues:?}"
    )]
    EntryFunctionRequiresUpvalues {
        function: String,
        upvalues: Vec<String>,
    },
    #[error("Could not find upvalue {name} when calling function")]
    UpvalueNotFound { name: String },
    #[error("Could not find upvalue {name} when creating closure")]
    ClosureUpvalueNotFound { name: String },
    #[error("Upvalue '{name}' not found")]
    UpvalueReadNotFound { name: String },
    #[error("Upvalue '{name}' not found for writing")]
    UpvalueWriteNotFound { name: String },
    #[error("First argument must be a closure, but got {actual}")]
    ExpectedClosure { actual: &'static str },
    #[error("Cannot execute foreign function as closure: {function}")]
    ForeignFunctionAsClosure { function: String },
    #[error("Function '{function}' is already registered")]
    FunctionAlreadyRegistered { function: String },
    #[error("{group} registration contains duplicate function '{function}'")]
    RegistrationDuplicateFunction { group: String, function: String },
    #[error("{group} cannot register function '{function}' because it is already registered")]
    RegistrationFunctionAlreadyRegistered { group: String, function: String },
    #[error("Function '{function}' not found")]
    QuotedFunctionNotFound { function: String },
    #[error("Function {function} not found")]
    FunctionNotFound { function: String },
    #[error("Cannot execute foreign function {function}")]
    CannotExecuteForeignFunction { function: String },
    #[error("MPC engine not configured")]
    MpcEngineNotConfigured,
    #[error("MPC engine configured but not ready")]
    MpcEngineNotReady,
    #[error("MPC {operation} failed: {reason}")]
    MpcBackendOperationFailed {
        operation: &'static str,
        reason: String,
    },
    #[error("Async MPC engine {runtime} does not match VM engine {configured}")]
    AsyncMpcEngineMismatch {
        runtime: MpcEngineIdentity,
        configured: MpcEngineIdentity,
    },
    #[error("No MPC engine configured for output protocol")]
    MpcOutputEngineNotConfigured,
    #[error("MPC engine is not ready")]
    MpcOutputEngineNotReady,
    #[error("Share data format mismatch in {operation}: left is {left}, right is {right}")]
    ShareDataFormatMismatch {
        operation: &'static str,
        left: &'static str,
        right: &'static str,
    },
    #[error(
        "Share data format mismatch in {operation} at index {index}: expected {expected}, got {actual}"
    )]
    ShareDataBatchFormatMismatch {
        operation: &'static str,
        expected: &'static str,
        actual: &'static str,
        index: usize,
    },
    #[error("No share found for client {client_id} at index {index}")]
    ClientShareNotFound {
        client_id: usize,
        index: ClientShareIndex,
    },
    #[error("Client {client_id} share {index} has type {stored_type:?}, but {requested_type:?} was requested")]
    ClientShareTypeMismatch {
        client_id: usize,
        index: ClientShareIndex,
        stored_type: stoffel_vm_types::core_types::ShareType,
        requested_type: stoffel_vm_types::core_types::ShareType,
    },
    #[error("Function {function} has no resolved instructions")]
    MissingResolvedInstructions { function: String },
    #[error(
        "Function {function} has {resolved_instruction_count} resolved instructions but {source_instruction_count} source instructions"
    )]
    RuntimeInstructionMetadataMismatch {
        function: String,
        resolved_instruction_count: usize,
        source_instruction_count: usize,
    },
    #[cfg(test)]
    #[error("Instruction index {index} out of bounds")]
    InstructionOutOfBounds { index: usize },
    #[error("Jump target {target} out of bounds for instruction stream with {instruction_count} instructions")]
    JumpTargetOutOfBounds {
        target: usize,
        instruction_count: usize,
    },
    #[error("Constant index {index} out of bounds")]
    ConstantOutOfBounds { index: usize },
    #[error("Expected string constant for function name at index {index}")]
    InvalidFunctionNameConstant { index: usize },
    #[error(transparent)]
    ClientInputStore(#[from] ClientInputStoreError),
    #[error(transparent)]
    Activation(#[from] ActivationError),
    #[error(transparent)]
    Function(#[from] FunctionError),
    #[error(transparent)]
    ForeignFunction(#[from] ForeignFunctionError),
    #[error(transparent)]
    ForeignObject(#[from] ForeignObjectError),
    #[error(transparent)]
    Hook(#[from] HookError),
    #[error(transparent)]
    MpcValue(#[from] MpcValueError),
    #[error(transparent)]
    RevealBatch(#[from] RevealBatchError),
    #[error(transparent)]
    TableMemory(#[from] TableMemoryError),
    #[error(transparent)]
    ValueOp(#[from] ValueOpError),
}

impl From<VmError> for VirtualMachineError {
    fn from(error: VmError) -> Self {
        VirtualMachineError::new(error)
    }
}

impl From<String> for VirtualMachineError {
    fn from(error: String) -> Self {
        VmError::from(error).into()
    }
}

impl From<&str> for VirtualMachineError {
    fn from(error: &str) -> Self {
        VmError::from(error).into()
    }
}

impl From<String> for VmError {
    fn from(error: String) -> Self {
        VmError::Message(error)
    }
}

impl From<&str> for VmError {
    fn from(error: &str) -> Self {
        VmError::Message(error.to_owned())
    }
}

impl From<VmError> for String {
    fn from(error: VmError) -> Self {
        error.to_string()
    }
}

impl From<VirtualMachineError> for String {
    fn from(error: VirtualMachineError) -> Self {
        error.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn public_vm_error_boxes_internal_error() {
        assert_eq!(size_of::<VirtualMachineError>(), size_of::<usize>());
        assert!(size_of::<VirtualMachineError>() < size_of::<VmError>());
    }
}
