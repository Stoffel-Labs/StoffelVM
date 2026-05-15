use crate::net::curve::MpcCurveError;
use std::fmt;

pub type ShareAlgebraResult<T> = Result<T, ShareAlgebraError>;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ShareAlgebraError {
    Decode {
        type_name: &'static str,
        source: String,
    },
    DecodeTrailingBytes {
        type_name: &'static str,
    },
    DecodeShareBytes {
        feldman_error: Box<ShareAlgebraError>,
        robust_error: Box<ShareAlgebraError>,
    },
    DecodeShareAt {
        index: usize,
        source: Box<ShareAlgebraError>,
    },
    EncodeShareBytes {
        source: String,
    },
    EncodeFeldmanCommitment {
        source: String,
    },
    FeldmanOperation {
        operation: &'static str,
        source: String,
    },
    FieldElementDecode {
        source: String,
    },
    ShareMetadataMismatch,
    ShareFormatMismatch {
        left: &'static str,
        right: &'static str,
    },
    InterpolationFormatMismatch,
    InterpolationEmpty,
    RecoverSecret {
        source: String,
    },
    DivisionByZero,
    ScalarHasNoInverse,
    FixedPointScaleOverflow,
    FixedPointScalarOverflow,
    FixedPointScalarOutOfRange,
    ExpectedFixedPointShareType,
    CurveConversion(MpcCurveError),
}

impl ShareAlgebraError {
    pub(crate) fn feldman_operation(operation: &'static str, source: impl fmt::Debug) -> Self {
        Self::FeldmanOperation {
            operation,
            source: format!("{source:?}"),
        }
    }
}

impl fmt::Display for ShareAlgebraError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShareAlgebraError::Decode { type_name, source } => {
                write!(f, "Failed to decode {type_name}: {source}")
            }
            ShareAlgebraError::DecodeTrailingBytes { type_name } => {
                write!(f, "Failed to decode {type_name}: trailing bytes in payload")
            }
            ShareAlgebraError::DecodeShareBytes {
                feldman_error,
                robust_error,
            } => {
                write!(
                    f,
                    "Failed to decode share bytes: {feldman_error}; {robust_error}"
                )
            }
            ShareAlgebraError::DecodeShareAt { index, source } => {
                write!(f, "Failed to decode share at index {index}: {source}")
            }
            ShareAlgebraError::EncodeShareBytes { source } => {
                write!(f, "Failed to encode share bytes: {source}")
            }
            ShareAlgebraError::EncodeFeldmanCommitment { source } => {
                write!(f, "Failed to encode Feldman commitment: {source}")
            }
            ShareAlgebraError::FeldmanOperation { operation, source } => {
                write!(f, "Failed to {operation}: {source}")
            }
            ShareAlgebraError::FieldElementDecode { source } => {
                write!(f, "Failed to deserialize field element: {source}")
            }
            ShareAlgebraError::ShareMetadataMismatch => {
                write!(f, "Share metadata mismatch (id/degree)")
            }
            ShareAlgebraError::ShareFormatMismatch { left, right } => {
                write!(f, "Share format mismatch: left is {left}, right is {right}")
            }
            ShareAlgebraError::InterpolationFormatMismatch => {
                write!(f, "Share format mismatch in interpolation input")
            }
            ShareAlgebraError::InterpolationEmpty => {
                write!(f, "Cannot interpolate from empty shares array")
            }
            ShareAlgebraError::RecoverSecret { source } => {
                write!(f, "Failed to recover secret: {source}")
            }
            ShareAlgebraError::DivisionByZero => write!(f, "Division by zero"),
            ShareAlgebraError::ScalarHasNoInverse => write!(f, "Scalar has no inverse in field"),
            ShareAlgebraError::FixedPointScaleOverflow => write!(f, "Fixed-point scale overflow"),
            ShareAlgebraError::FixedPointScalarOverflow => write!(f, "Fixed-point scalar overflow"),
            ShareAlgebraError::FixedPointScalarOutOfRange => {
                write!(f, "Fixed-point scalar exceeds i64 range")
            }
            ShareAlgebraError::ExpectedFixedPointShareType => {
                write!(f, "Expected fixed-point share type")
            }
            ShareAlgebraError::CurveConversion(source) => write!(f, "{source}"),
        }
    }
}

impl std::error::Error for ShareAlgebraError {}

impl From<ShareAlgebraError> for String {
    fn from(error: ShareAlgebraError) -> Self {
        error.to_string()
    }
}

impl From<MpcCurveError> for ShareAlgebraError {
    fn from(error: MpcCurveError) -> Self {
        ShareAlgebraError::CurveConversion(error)
    }
}
