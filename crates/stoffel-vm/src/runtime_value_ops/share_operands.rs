use super::error::{ValueOpError, ValueOpResult};
use crate::value_conversions::value_to_i64;
use stoffel_vm_types::core_types::{ShareData, ShareType, Value};

pub(crate) struct BorrowedSharePair<'a> {
    pub(crate) share_type: ShareType,
    pub(crate) left_data: &'a ShareData,
    pub(crate) right_data: &'a ShareData,
}

pub(crate) fn matching_share_pair<'a>(
    operation: &'static str,
    left: &'a Value,
    right: &'a Value,
) -> ValueOpResult<Option<BorrowedSharePair<'a>>> {
    let Some((left_type, left_data)) = share_operand(left) else {
        return Ok(None);
    };
    let Some((right_type, right_data)) = share_operand(right) else {
        return Ok(None);
    };

    ensure_same_share_type(operation, &left_type, &right_type)?;
    Ok(Some(BorrowedSharePair {
        share_type: left_type,
        left_data,
        right_data,
    }))
}

pub(super) fn share_scalar_operands<'a>(
    share_value: &'a Value,
    scalar_value: &Value,
) -> ValueOpResult<Option<(ShareType, &'a ShareData, i64)>> {
    let Some((share_type, share_data)) = share_operand(share_value) else {
        return Ok(None);
    };
    let Some(scalar) = integer_scalar(scalar_value)? else {
        return Ok(None);
    };

    Ok(Some((share_type, share_data, scalar)))
}

pub(super) fn contains_share_operand(left: &Value, right: &Value) -> bool {
    share_operand(left).is_some() || share_operand(right).is_some()
}

fn share_operand(value: &Value) -> Option<(ShareType, &ShareData)> {
    match value {
        Value::Share(share_type, data) => Some((*share_type, data)),
        _ => None,
    }
}

fn integer_scalar(value: &Value) -> ValueOpResult<Option<i64>> {
    if matches!(
        value,
        Value::I64(_)
            | Value::I32(_)
            | Value::I16(_)
            | Value::I8(_)
            | Value::U8(_)
            | Value::U16(_)
            | Value::U32(_)
            | Value::U64(_)
    ) {
        value_to_i64(value, "share scalar")
            .map(Some)
            .map_err(Into::into)
    } else {
        Ok(None)
    }
}

fn ensure_same_share_type(
    operation: &'static str,
    left: &ShareType,
    right: &ShareType,
) -> ValueOpResult<()> {
    if left == right {
        Ok(())
    } else {
        Err(ValueOpError::ShareTypeMismatch { operation })
    }
}
