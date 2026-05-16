use super::{MpcValueError, MpcValueResult};
use crate::value_conversions::value_to_i64;
use stoffel_vm_types::core_types::{ClearShareInput, ClearShareValue, ShareType, Value, F64};

pub(crate) fn clear_share_input(
    clear_value: &Value,
    explicit_type: Option<ShareType>,
) -> MpcValueResult<ClearShareInput> {
    let share_type = match explicit_type {
        Some(share_type) => share_type,
        None => infer_clear_share_type(clear_value)?,
    };
    let value = canonical_clear_share_value(share_type, clear_value)?;

    Ok(ClearShareInput::new(share_type, value))
}

fn infer_clear_share_type(clear_value: &Value) -> MpcValueResult<ShareType> {
    match clear_value {
        Value::I64(_)
        | Value::I32(_)
        | Value::I16(_)
        | Value::I8(_)
        | Value::U64(_)
        | Value::U32(_)
        | Value::U16(_)
        | Value::U8(_) => Ok(ShareType::default_secret_int()),
        Value::Float(_) => Ok(ShareType::default_secret_fixed_point()),
        Value::Bool(_) => Ok(ShareType::boolean()),
        value => Err(MpcValueError::UnsupportedClearShareValue {
            value: value.clone(),
        }),
    }
}

fn canonical_clear_share_value(
    share_type: ShareType,
    clear_value: &Value,
) -> MpcValueResult<ClearShareValue> {
    match (share_type, clear_value) {
        (ShareType::SecretInt { .. }, Value::I64(value)) => Ok(ClearShareValue::Integer(*value)),
        (ShareType::SecretInt { bit_length }, Value::Bool(value))
            if bit_length == stoffel_vm_types::core_types::BOOLEAN_SECRET_INT_BITS =>
        {
            Ok(ClearShareValue::Boolean(*value))
        }
        (ShareType::SecretInt { .. }, value) if is_integer_value(value) => Ok(
            ClearShareValue::Integer(value_to_i64(value, "clear integer")?),
        ),
        (ShareType::SecretFixedPoint { .. }, Value::Float(value)) => {
            Ok(ClearShareValue::FixedPoint(*value))
        }
        (ShareType::SecretFixedPoint { .. }, value) if is_integer_value(value) => Ok(
            ClearShareValue::FixedPoint(F64(value_to_i64(value, "clear integer")? as f64)),
        ),
        (share_type, value) => Err(MpcValueError::UnsupportedClearShareConversion {
            share_type,
            value: value.clone(),
        }),
    }
}

fn is_integer_value(value: &Value) -> bool {
    matches!(
        value,
        Value::I64(_)
            | Value::I32(_)
            | Value::I16(_)
            | Value::I8(_)
            | Value::U64(_)
            | Value::U32(_)
            | Value::U16(_)
            | Value::U8(_)
    )
}
