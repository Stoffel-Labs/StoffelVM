use crate::error::VmError;
use crate::net::share_runtime::MpcShareRuntime;
use crate::value_conversions::ValueConversionError;

pub(crate) type ShareRuntimeProvider<'a> = &'a dyn Fn() -> ValueOpResult<MpcShareRuntime<'a>>;
pub(crate) type ValueOpResult<T> = Result<T, ValueOpError>;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ValueOpError {
    #[error("Type error in {operation} operation")]
    TypeError { operation: &'static str },
    #[error("Share type mismatch in {operation} operation")]
    ShareTypeMismatch { operation: &'static str },
    #[error("Integer overflow in {operation} operation")]
    IntegerOverflow { operation: &'static str },
    #[error("Division by zero")]
    DivisionByZero,
    #[error("Modulo by zero")]
    ModuloByZero,
    #[error("Invalid shift amount {amount} in {operation} operation")]
    InvalidShiftAmount {
        operation: &'static str,
        amount: i64,
    },
    #[error("Shift amount {amount} out of range in {operation} operation")]
    ShiftOutOfRange {
        operation: &'static str,
        amount: u32,
    },
    #[error("{message}")]
    Unsupported { message: &'static str },
    #[error("Cannot compare {left} and {right}")]
    CannotCompare { left: String, right: String },
    #[error(transparent)]
    ValueConversion(#[from] ValueConversionError),
    #[error(transparent)]
    Runtime(#[from] Box<VmError>),
}

impl From<VmError> for ValueOpError {
    fn from(error: VmError) -> Self {
        ValueOpError::Runtime(Box::new(error))
    }
}

impl ValueOpError {
    pub(crate) fn runtime_error(&self) -> Option<&VmError> {
        match self {
            ValueOpError::Runtime(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

pub(super) fn checked_integer_result<T>(
    operation: &'static str,
    result: Option<T>,
) -> ValueOpResult<T> {
    result.ok_or(ValueOpError::IntegerOverflow { operation })
}

pub(super) fn type_error<T>(operation: &'static str) -> ValueOpResult<T> {
    Err(ValueOpError::TypeError { operation })
}

pub(super) fn unsupported<T>(message: &'static str) -> ValueOpResult<T> {
    Err(ValueOpError::Unsupported { message })
}
