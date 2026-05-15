use super::error::{type_error, unsupported, ValueOpError, ValueOpResult};
use super::share_operands::contains_share_operand;
use stoffel_vm_types::core_types::Value;

pub(crate) fn bit_and(left: &Value, right: &Value) -> ValueOpResult<Value> {
    match (left, right) {
        (Value::I64(a), Value::I64(b)) => Ok(Value::I64(a & b)),
        (Value::Bool(a), Value::Bool(b)) => Ok(Value::Bool(*a && *b)),
        _ if contains_share_operand(left, right) => {
            unsupported("Bitwise AND is not supported on secret shares")
        }
        _ => type_error("AND"),
    }
}

pub(crate) fn bit_or(left: &Value, right: &Value) -> ValueOpResult<Value> {
    match (left, right) {
        (Value::I64(a), Value::I64(b)) => Ok(Value::I64(a | b)),
        (Value::Bool(a), Value::Bool(b)) => Ok(Value::Bool(*a || *b)),
        _ if contains_share_operand(left, right) => {
            unsupported("Bitwise OR is not supported on secret shares")
        }
        _ => type_error("OR"),
    }
}

pub(crate) fn bit_xor(left: &Value, right: &Value) -> ValueOpResult<Value> {
    match (left, right) {
        (Value::I64(a), Value::I64(b)) => Ok(Value::I64(a ^ b)),
        (Value::Bool(a), Value::Bool(b)) => Ok(Value::Bool(a ^ b)),
        _ if contains_share_operand(left, right) => {
            unsupported("Bitwise XOR is not supported on secret shares")
        }
        _ => type_error("XOR"),
    }
}

pub(crate) fn bit_not(value: &Value) -> ValueOpResult<Value> {
    match value {
        Value::I64(a) => Ok(Value::I64(!a)),
        Value::Bool(a) => Ok(Value::Bool(!a)),
        Value::Share(_, _) => unsupported("Bitwise NOT is not supported on secret shares"),
        _ => type_error("NOT"),
    }
}

pub(crate) fn shl(left: &Value, right: &Value) -> ValueOpResult<Value> {
    match (left, right) {
        (Value::I64(a), Value::I64(b)) => Ok(Value::I64(checked_i64_shl(*a, *b)?)),
        _ if contains_share_operand(left, right) => {
            unsupported("Left shift is not supported on secret shares")
        }
        _ => type_error("SHL"),
    }
}

pub(crate) fn shr(left: &Value, right: &Value) -> ValueOpResult<Value> {
    match (left, right) {
        (Value::I64(a), Value::I64(b)) => Ok(Value::I64(checked_i64_shr(*a, *b)?)),
        _ if contains_share_operand(left, right) => {
            unsupported("Right shift is not supported on secret shares")
        }
        _ => type_error("SHR"),
    }
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
