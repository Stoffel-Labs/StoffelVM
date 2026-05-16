use crate::error::VmError;
use crate::mpc_values::MpcValueError;
use crate::output::VmOutputError;
use crate::value_conversions::ValueConversionError;
use crate::{VirtualMachineError, VirtualMachineErrorKind};
use stoffel_vm_types::core_types::{ForeignObjectError, ShareTypeError, TableMemoryError, Value};

pub type ForeignFunctionResult<T> = Result<T, ForeignFunctionError>;
pub type ForeignFunctionCallbackResult<T = Value> = Result<T, ForeignFunctionCallbackError>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ForeignFunctionCallbackError {
    #[error("{0}")]
    Message(String),
    #[error("{message}")]
    Runtime {
        kind: VirtualMachineErrorKind,
        message: String,
    },
    #[error(transparent)]
    ForeignObject(#[from] ForeignObjectError),
    #[error(transparent)]
    TableMemory(#[from] TableMemoryError),
    #[error(transparent)]
    Output(#[from] VmOutputError),
}

impl ForeignFunctionCallbackError {
    /// VM error kind preserved when a callback failed while delegating back into
    /// VM runtime services.
    pub fn runtime_kind(&self) -> Option<VirtualMachineErrorKind> {
        match self {
            ForeignFunctionCallbackError::Runtime { kind, .. } => Some(*kind),
            _ => None,
        }
    }
}

impl From<String> for ForeignFunctionCallbackError {
    fn from(message: String) -> Self {
        Self::Message(message)
    }
}

impl From<&str> for ForeignFunctionCallbackError {
    fn from(message: &str) -> Self {
        Self::Message(message.to_owned())
    }
}

impl From<VmError> for ForeignFunctionCallbackError {
    fn from(error: VmError) -> Self {
        let error = VirtualMachineError::from(error);
        Self::Runtime {
            kind: error.kind(),
            message: error.to_string(),
        }
    }
}

impl From<ValueConversionError> for ForeignFunctionCallbackError {
    fn from(error: ValueConversionError) -> Self {
        Self::Runtime {
            kind: VirtualMachineErrorKind::Value,
            message: error.to_string(),
        }
    }
}

impl From<MpcValueError> for ForeignFunctionCallbackError {
    fn from(error: MpcValueError) -> Self {
        VmError::from(error).into()
    }
}

impl From<ShareTypeError> for ForeignFunctionCallbackError {
    fn from(error: ShareTypeError) -> Self {
        MpcValueError::from(error).into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ForeignFunctionError {
    #[error("Foreign function {function} failed: {source}")]
    CallbackFailed {
        function: String,
        #[source]
        source: ForeignFunctionCallbackError,
    },
}

impl From<ForeignFunctionError> for String {
    fn from(error: ForeignFunctionError) -> Self {
        error.to_string()
    }
}
