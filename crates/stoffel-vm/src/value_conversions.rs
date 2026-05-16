use stoffel_vm_types::core_types::Value;

pub(crate) type ValueConversionResult<T> = Result<T, ValueConversionError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValueConversionError {
    ExpectedNonNegativeInteger { name: String },
    ExpectedInteger { name: String },
    TooLargeForPlatform { name: String },
    TooLargeForU64 { name: String },
    ExceedsI64Range { name: String },
    ExceedsVmIntegerRange { name: String, value: u128 },
}

impl ValueConversionError {
    fn expected_non_negative_integer(name: &str) -> Self {
        Self::ExpectedNonNegativeInteger {
            name: name.to_owned(),
        }
    }

    fn expected_integer(name: &str) -> Self {
        Self::ExpectedInteger {
            name: name.to_owned(),
        }
    }

    fn too_large_for_platform(name: &str) -> Self {
        Self::TooLargeForPlatform {
            name: name.to_owned(),
        }
    }

    fn too_large_for_u64(name: &str) -> Self {
        Self::TooLargeForU64 {
            name: name.to_owned(),
        }
    }

    fn exceeds_i64_range(name: &str) -> Self {
        Self::ExceedsI64Range {
            name: name.to_owned(),
        }
    }

    fn exceeds_vm_integer_range(name: &str, value: impl Into<u128>) -> Self {
        Self::ExceedsVmIntegerRange {
            name: name.to_owned(),
            value: value.into(),
        }
    }
}

impl std::fmt::Display for ValueConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValueConversionError::ExpectedNonNegativeInteger { name } => {
                write!(f, "{name} must be a non-negative integer")
            }
            ValueConversionError::ExpectedInteger { name } => {
                write!(f, "{name} must be an integer")
            }
            ValueConversionError::TooLargeForPlatform { name } => {
                write!(f, "{name} is too large for this platform")
            }
            ValueConversionError::TooLargeForU64 { name } => {
                write!(f, "{name} is too large for u64")
            }
            ValueConversionError::ExceedsI64Range { name } => {
                write!(f, "{name} exceeds i64 range")
            }
            ValueConversionError::ExceedsVmIntegerRange { name, value } => {
                write!(f, "{name} {value} exceeds VM integer range")
            }
        }
    }
}

impl std::error::Error for ValueConversionError {}

impl From<ValueConversionError> for String {
    fn from(error: ValueConversionError) -> Self {
        error.to_string()
    }
}

pub(crate) fn value_to_usize(value: &Value, name: &str) -> ValueConversionResult<usize> {
    match value {
        Value::I64(v) if *v >= 0 => {
            usize::try_from(*v).map_err(|_| ValueConversionError::too_large_for_platform(name))
        }
        Value::I32(v) if *v >= 0 => {
            usize::try_from(*v).map_err(|_| ValueConversionError::too_large_for_platform(name))
        }
        Value::I16(v) if *v >= 0 => {
            usize::try_from(*v).map_err(|_| ValueConversionError::too_large_for_platform(name))
        }
        Value::I8(v) if *v >= 0 => {
            usize::try_from(*v).map_err(|_| ValueConversionError::too_large_for_platform(name))
        }
        Value::U64(v) => {
            usize::try_from(*v).map_err(|_| ValueConversionError::too_large_for_platform(name))
        }
        Value::U32(v) => {
            usize::try_from(*v).map_err(|_| ValueConversionError::too_large_for_platform(name))
        }
        Value::U16(v) => Ok((*v).into()),
        Value::U8(v) => Ok((*v).into()),
        _ => Err(ValueConversionError::expected_non_negative_integer(name)),
    }
}

pub(crate) fn value_to_u64(value: &Value, name: &str) -> ValueConversionResult<u64> {
    match value {
        Value::I64(v) if *v >= 0 => {
            u64::try_from(*v).map_err(|_| ValueConversionError::too_large_for_u64(name))
        }
        Value::I32(v) if *v >= 0 => {
            u64::try_from(*v).map_err(|_| ValueConversionError::too_large_for_u64(name))
        }
        Value::I16(v) if *v >= 0 => {
            u64::try_from(*v).map_err(|_| ValueConversionError::too_large_for_u64(name))
        }
        Value::I8(v) if *v >= 0 => {
            u64::try_from(*v).map_err(|_| ValueConversionError::too_large_for_u64(name))
        }
        Value::U64(v) => Ok(*v),
        Value::U32(v) => Ok((*v).into()),
        Value::U16(v) => Ok((*v).into()),
        Value::U8(v) => Ok((*v).into()),
        _ => Err(ValueConversionError::expected_non_negative_integer(name)),
    }
}

pub(crate) fn value_to_i64(value: &Value, name: &str) -> ValueConversionResult<i64> {
    match value {
        Value::I64(v) => Ok(*v),
        Value::I32(v) => Ok((*v).into()),
        Value::I16(v) => Ok((*v).into()),
        Value::I8(v) => Ok((*v).into()),
        Value::U64(v) => {
            i64::try_from(*v).map_err(|_| ValueConversionError::exceeds_i64_range(name))
        }
        Value::U32(v) => Ok((*v).into()),
        Value::U16(v) => Ok((*v).into()),
        Value::U8(v) => Ok((*v).into()),
        _ => Err(ValueConversionError::expected_integer(name)),
    }
}

pub(crate) fn usize_to_vm_i64(value: usize, name: &str) -> ValueConversionResult<i64> {
    i64::try_from(value)
        .map_err(|_| ValueConversionError::exceeds_vm_integer_range(name, value as u128))
}

pub(crate) fn u64_to_vm_i64(value: u64, name: &str) -> ValueConversionResult<i64> {
    i64::try_from(value)
        .map_err(|_| ValueConversionError::exceeds_vm_integer_range(name, u128::from(value)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stoffel_vm_types::core_types::F64;

    #[test]
    fn integer_conversions_accept_vm_integer_widths() {
        assert_eq!(value_to_usize(&Value::U8(7), "count"), Ok(7));
        assert_eq!(value_to_u64(&Value::U32(9), "timeout_ms"), Ok(9));
        assert_eq!(value_to_i64(&Value::I16(-3), "scalar"), Ok(-3));
    }

    #[test]
    fn integer_conversions_report_typed_argument_errors() {
        assert_eq!(
            value_to_usize(&Value::I64(-1), "index"),
            Err(ValueConversionError::ExpectedNonNegativeInteger {
                name: "index".to_string()
            })
        );
        assert_eq!(
            value_to_i64(&Value::Float(F64::new(1.5)), "scalar"),
            Err(ValueConversionError::ExpectedInteger {
                name: "scalar".to_string()
            })
        );
    }

    #[test]
    fn integer_conversions_report_range_errors_without_losing_context() {
        assert_eq!(
            value_to_i64(&Value::U64(i64::MAX as u64 + 1), "scalar"),
            Err(ValueConversionError::ExceedsI64Range {
                name: "scalar".to_string()
            })
        );
        assert_eq!(
            u64_to_vm_i64(i64::MAX as u64 + 1, "session_id"),
            Err(ValueConversionError::ExceedsVmIntegerRange {
                name: "session_id".to_string(),
                value: i64::MAX as u128 + 1
            })
        );
    }

    #[test]
    fn conversion_errors_preserve_existing_display_messages() {
        let error = value_to_usize(&Value::String("x".to_string()), "index").unwrap_err();
        assert_eq!(error.to_string(), "index must be a non-negative integer");

        let error = usize_to_vm_i64(usize::MAX, "array length").unwrap_err();
        if usize::MAX > i64::MAX as usize {
            assert_eq!(
                error.to_string(),
                format!("array length {} exceeds VM integer range", usize::MAX)
            );
        }
    }
}
