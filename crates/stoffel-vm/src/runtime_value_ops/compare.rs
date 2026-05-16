use super::error::{unsupported, ValueOpError, ValueOpResult};
use std::cmp::Ordering;
use stoffel_vm_types::core_types::Value;

#[inline]
pub(crate) fn compare(left: &Value, right: &Value) -> ValueOpResult<Ordering> {
    if let Some(ordering) = try_clear_compare(left, right) {
        return Ok(ordering);
    }

    match (left, right) {
        (Value::Share(_, _), _) | (_, Value::Share(_, _)) => {
            unsupported("CMP on secret shares is not supported without an MPC comparison protocol")
        }
        _ => Err(ValueOpError::CannotCompare {
            left: format!("{left:?}"),
            right: format!("{right:?}"),
        }),
    }
}

#[inline]
pub(crate) fn try_clear_compare(left: &Value, right: &Value) -> Option<Ordering> {
    Some(match (left, right) {
        (Value::I64(a), Value::I64(b)) => compare_ordered(a, b),
        (Value::I32(a), Value::I32(b)) => compare_ordered(a, b),
        (Value::I16(a), Value::I16(b)) => compare_ordered(a, b),
        (Value::I8(a), Value::I8(b)) => compare_ordered(a, b),
        (Value::U8(a), Value::U8(b)) => compare_ordered(a, b),
        (Value::U16(a), Value::U16(b)) => compare_ordered(a, b),
        (Value::U32(a), Value::U32(b)) => compare_ordered(a, b),
        (Value::U64(a), Value::U64(b)) => compare_ordered(a, b),
        (Value::String(a), Value::String(b)) => compare_ordered(a, b),
        (Value::Bool(a), Value::Bool(b)) => compare_ordered(a, b),
        _ => return None,
    })
}

#[inline]
fn compare_ordered<T: Ord>(left: &T, right: &T) -> Ordering {
    left.cmp(right)
}
