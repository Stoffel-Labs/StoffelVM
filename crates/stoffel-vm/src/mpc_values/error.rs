use crate::value_conversions::ValueConversionError;
use stoffel_vm_types::core_types::{ShareType, ShareTypeError, TableMemoryError, Value};

pub type MpcValueResult<T> = Result<T, MpcValueError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MpcValueError {
    TableMemory(TableMemoryError),
    TableMemoryContext {
        context: String,
        source: TableMemoryError,
    },
    ValueConversion(String),
    ShareType(ShareTypeError),
    UnsupportedClearShareValue {
        value: Value,
    },
    UnsupportedClearShareConversion {
        share_type: ShareType,
        value: Value,
    },
    ShareTypeMismatch {
        context: String,
        left: ShareType,
        right: ShareType,
    },
    MissingField {
        context: String,
        field: &'static str,
    },
    MissingArrayElement {
        context: String,
        index: usize,
    },
    UnexpectedValue {
        context: String,
        expected: String,
        actual: Value,
    },
    IndexOutOfBounds {
        context: String,
        index: usize,
        len: usize,
    },
    Message(String),
}

impl MpcValueError {
    pub fn table_memory_context(context: impl Into<String>, source: TableMemoryError) -> Self {
        Self::TableMemoryContext {
            context: context.into(),
            source,
        }
    }

    pub fn message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }

    pub fn missing_field(context: impl Into<String>, field: &'static str) -> Self {
        Self::MissingField {
            context: context.into(),
            field,
        }
    }

    pub fn missing_array_element(context: impl Into<String>, index: usize) -> Self {
        Self::MissingArrayElement {
            context: context.into(),
            index,
        }
    }

    pub fn unexpected_value(
        context: impl Into<String>,
        expected: impl Into<String>,
        actual: Value,
    ) -> Self {
        Self::UnexpectedValue {
            context: context.into(),
            expected: expected.into(),
            actual,
        }
    }

    pub fn index_out_of_bounds(context: impl Into<String>, index: usize, len: usize) -> Self {
        Self::IndexOutOfBounds {
            context: context.into(),
            index,
            len,
        }
    }
}

impl std::fmt::Display for MpcValueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MpcValueError::TableMemory(source) => write!(f, "{source}"),
            MpcValueError::TableMemoryContext { context, source } => {
                write!(f, "{context}: {source}")
            }
            MpcValueError::ValueConversion(message) | MpcValueError::Message(message) => {
                write!(f, "{message}")
            }
            MpcValueError::ShareType(source) => write!(f, "{source}"),
            MpcValueError::UnsupportedClearShareValue { value } => {
                write!(f, "Cannot create share from value type: {value:?}")
            }
            MpcValueError::UnsupportedClearShareConversion { share_type, value } => {
                write!(f, "Cannot create {share_type:?} share from {value:?}")
            }
            MpcValueError::ShareTypeMismatch {
                context,
                left,
                right,
            } => write!(f, "{context}: share type mismatch: {left:?} vs {right:?}"),
            MpcValueError::MissingField { context, field } => {
                write!(f, "{context} missing {field} field")
            }
            MpcValueError::MissingArrayElement { context, index } => {
                write!(f, "{context} missing element at index {index}")
            }
            MpcValueError::UnexpectedValue {
                context,
                expected,
                actual,
            } => write!(f, "{context}: expected {expected}, got {actual:?}"),
            MpcValueError::IndexOutOfBounds {
                context,
                index,
                len,
            } => write!(f, "{context} index {index} out of bounds (len: {len})"),
        }
    }
}

impl std::error::Error for MpcValueError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MpcValueError::TableMemory(source)
            | MpcValueError::TableMemoryContext { source, .. } => Some(source),
            MpcValueError::ShareType(source) => Some(source),
            MpcValueError::ValueConversion(_)
            | MpcValueError::UnsupportedClearShareValue { .. }
            | MpcValueError::UnsupportedClearShareConversion { .. }
            | MpcValueError::ShareTypeMismatch { .. }
            | MpcValueError::MissingField { .. }
            | MpcValueError::MissingArrayElement { .. }
            | MpcValueError::UnexpectedValue { .. }
            | MpcValueError::IndexOutOfBounds { .. }
            | MpcValueError::Message(_) => None,
        }
    }
}

impl From<TableMemoryError> for MpcValueError {
    fn from(error: TableMemoryError) -> Self {
        MpcValueError::TableMemory(error)
    }
}

impl From<ValueConversionError> for MpcValueError {
    fn from(error: ValueConversionError) -> Self {
        MpcValueError::ValueConversion(error.to_string())
    }
}

impl From<ShareTypeError> for MpcValueError {
    fn from(error: ShareTypeError) -> Self {
        MpcValueError::ShareType(error)
    }
}

impl From<MpcValueError> for String {
    fn from(error: MpcValueError) -> Self {
        error.to_string()
    }
}
