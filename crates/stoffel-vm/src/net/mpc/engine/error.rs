use super::MpcCapability;
use std::fmt;

pub type MpcEngineResult<T> = Result<T, MpcEngineError>;

#[cfg(any(feature = "honeybadger", feature = "avss"))]
pub(crate) trait MpcEngineOperationResultExt<T> {
    fn map_mpc_engine_operation(self, operation: &'static str) -> MpcEngineResult<T>;
}

#[cfg(any(feature = "honeybadger", feature = "avss"))]
impl<T> MpcEngineOperationResultExt<T> for Result<T, String> {
    fn map_mpc_engine_operation(self, operation: &'static str) -> MpcEngineResult<T> {
        self.map_err(|reason| MpcEngineError::operation_failed(operation, reason))
    }
}

#[cfg(any(feature = "honeybadger", feature = "avss"))]
impl<T> MpcEngineOperationResultExt<T> for Result<T, crate::net::BlockOnError> {
    fn map_mpc_engine_operation(self, operation: &'static str) -> MpcEngineResult<T> {
        self.map_err(|error| MpcEngineError::operation_failed(operation, error.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MpcEngineError {
    CapabilityUnavailable {
        protocol_name: String,
        capability: MpcCapability,
        advertised: bool,
    },
    OperationFailed {
        operation: &'static str,
        reason: String,
    },
}

impl MpcEngineError {
    pub(crate) fn capability_unavailable(
        protocol_name: &str,
        capability: MpcCapability,
        advertised: bool,
    ) -> Self {
        Self::CapabilityUnavailable {
            protocol_name: protocol_name.to_owned(),
            capability,
            advertised,
        }
    }

    pub fn operation_failed(operation: &'static str, reason: impl Into<String>) -> Self {
        Self::OperationFailed {
            operation,
            reason: reason.into(),
        }
    }

    pub(crate) fn into_backend_reason(self, operation: &'static str) -> String {
        match self {
            Self::OperationFailed {
                operation: engine_operation,
                reason,
            } if engine_operation == operation => reason,
            error => error.to_string(),
        }
    }
}

impl fmt::Display for MpcEngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MpcEngineError::CapabilityUnavailable {
                protocol_name,
                capability,
                advertised,
            } => write!(f, "{}", capability.error_for(protocol_name, *advertised)),
            MpcEngineError::OperationFailed { operation, reason } => {
                write!(f, "MPC engine operation '{operation}' failed: {reason}")
            }
        }
    }
}

impl std::error::Error for MpcEngineError {}

impl From<MpcEngineError> for String {
    fn from(error: MpcEngineError) -> Self {
        error.to_string()
    }
}
