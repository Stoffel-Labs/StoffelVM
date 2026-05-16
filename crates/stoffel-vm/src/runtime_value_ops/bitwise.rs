use super::error::{type_error, unsupported, ValueOpError, ValueOpResult};
use super::share_operands::contains_share_operand;
use stoffel_vm_types::core_types::Value;

pub(crate) fn bit_and(left: &Value, right: &Value) -> ValueOpResult<Value> {
    if let Some(result) = try_clear_bit_and(left, right) {
        return result;
    }

    if contains_share_operand(left, right) {
        unsupported("Bitwise AND is not supported on secret shares")
    } else {
        type_error("AND")
    }
}

pub(crate) fn bit_or(left: &Value, right: &Value) -> ValueOpResult<Value> {
    if let Some(result) = try_clear_bit_or(left, right) {
        return result;
    }

    if contains_share_operand(left, right) {
        unsupported("Bitwise OR is not supported on secret shares")
    } else {
        type_error("OR")
    }
}

pub(crate) fn bit_xor(left: &Value, right: &Value) -> ValueOpResult<Value> {
    if let Some(result) = try_clear_bit_xor(left, right) {
        return result;
    }

    if contains_share_operand(left, right) {
        unsupported("Bitwise XOR is not supported on secret shares")
    } else {
        type_error("XOR")
    }
}

pub(crate) fn bit_not(value: &Value) -> ValueOpResult<Value> {
    if let Some(result) = try_clear_bit_not(value) {
        return result;
    }

    if matches!(value, Value::Share(_, _)) {
        unsupported("Bitwise NOT is not supported on secret shares")
    } else {
        type_error("NOT")
    }
}

pub(crate) fn shl(left: &Value, right: &Value) -> ValueOpResult<Value> {
    if let Some(result) = try_clear_shl(left, right) {
        return result;
    }

    if contains_share_operand(left, right) {
        unsupported("Left shift is not supported on secret shares")
    } else {
        type_error("SHL")
    }
}

pub(crate) fn shr(left: &Value, right: &Value) -> ValueOpResult<Value> {
    if let Some(result) = try_clear_shr(left, right) {
        return result;
    }

    if contains_share_operand(left, right) {
        unsupported("Right shift is not supported on secret shares")
    } else {
        type_error("SHR")
    }
}

pub(crate) fn try_clear_bit_and(left: &Value, right: &Value) -> Option<ValueOpResult<Value>> {
    Some(match (left, right) {
        (Value::I64(a), Value::I64(b)) => Ok(Value::I64(a & b)),
        (Value::Bool(a), Value::Bool(b)) => Ok(Value::Bool(*a && *b)),
        _ => return None,
    })
}

pub(crate) fn try_clear_bit_or(left: &Value, right: &Value) -> Option<ValueOpResult<Value>> {
    Some(match (left, right) {
        (Value::I64(a), Value::I64(b)) => Ok(Value::I64(a | b)),
        (Value::Bool(a), Value::Bool(b)) => Ok(Value::Bool(*a || *b)),
        _ => return None,
    })
}

pub(crate) fn try_clear_bit_xor(left: &Value, right: &Value) -> Option<ValueOpResult<Value>> {
    Some(match (left, right) {
        (Value::I64(a), Value::I64(b)) => Ok(Value::I64(a ^ b)),
        (Value::Bool(a), Value::Bool(b)) => Ok(Value::Bool(a ^ b)),
        _ => return None,
    })
}

pub(crate) fn try_clear_bit_not(value: &Value) -> Option<ValueOpResult<Value>> {
    Some(match value {
        Value::I64(value) => Ok(Value::I64(!*value)),
        Value::Bool(value) => Ok(Value::Bool(!*value)),
        _ => return None,
    })
}

pub(crate) fn try_clear_shl(left: &Value, right: &Value) -> Option<ValueOpResult<Value>> {
    Some(match (left, right) {
        (Value::I64(a), Value::I64(b)) => checked_i64_shl(*a, *b).map(Value::I64),
        _ => return None,
    })
}

pub(crate) fn try_clear_shr(left: &Value, right: &Value) -> Option<ValueOpResult<Value>> {
    Some(match (left, right) {
        (Value::I64(a), Value::I64(b)) => checked_i64_shr(*a, *b).map(Value::I64),
        _ => return None,
    })
}

fn checked_shift_amount(operation: &'static str, amount: i64) -> ValueOpResult<u32> {
    u32::try_from(amount).map_err(|_| ValueOpError::InvalidShiftAmount { operation, amount })
}

fn checked_i64_shl(value: i64, amount: i64) -> ValueOpResult<i64> {
    let amount = checked_shift_amount("SHL", amount)?;
    value
        .checked_shl(amount)
        .ok_or(ValueOpError::ShiftOutOfRange {
            operation: "SHL",
            amount,
        })
}

fn checked_i64_shr(value: i64, amount: i64) -> ValueOpResult<i64> {
    let amount = checked_shift_amount("SHR", amount)?;
    value
        .checked_shr(amount)
        .ok_or(ValueOpError::ShiftOutOfRange {
            operation: "SHR",
            amount,
        })
}
