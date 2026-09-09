use super::error::{
    checked_integer_result, type_error, unsupported, ShareRuntimeProvider, ValueOpError,
    ValueOpResult,
};
use super::share_operands::{matching_share_pair, share_scalar_operands};
use stoffel_vm_types::core_types::{
    ClearShareInput, ClearShareValue, FixedPointPrecision, ShareType, Value,
    DEFAULT_FIXED_POINT_FRACTIONAL_BITS, DEFAULT_FIXED_POINT_TOTAL_BITS, F64,
};

pub(crate) fn add(
    left: &Value,
    right: &Value,
    share_runtime: ShareRuntimeProvider<'_>,
) -> ValueOpResult<Value> {
    if let Some(result) = try_clear_add(left, right) {
        return result;
    }

    if let Some(pair) = matching_share_pair("ADD", left, right)? {
        let data = share_runtime()?.add_data(pair.share_type, pair.left_data, pair.right_data)?;
        return Ok(Value::Share(pair.share_type, data));
    }

    if let Some((share_type, share_data, scalar)) = share_scalar_operands(left, right)? {
        let data = share_runtime()?.add_scalar_data(share_type, share_data, scalar)?;
        return Ok(Value::Share(share_type, data));
    }

    if let Some((share_type, share_data, scalar)) = share_scalar_operands(right, left)? {
        let data = share_runtime()?.add_scalar_data(share_type, share_data, scalar)?;
        return Ok(Value::Share(share_type, data));
    }

    type_error("ADD")
}

pub(crate) fn sub(
    left: &Value,
    right: &Value,
    share_runtime: ShareRuntimeProvider<'_>,
) -> ValueOpResult<Value> {
    if let Some(result) = try_clear_sub(left, right) {
        return result;
    }

    if let Some(pair) = matching_share_pair("SUB", left, right)? {
        let data = share_runtime()?.sub_data(pair.share_type, pair.left_data, pair.right_data)?;
        return Ok(Value::Share(pair.share_type, data));
    }

    if let Some((share_type, share_data, scalar)) = share_scalar_operands(left, right)? {
        let data = share_runtime()?.sub_scalar_data(share_type, share_data, scalar)?;
        return Ok(Value::Share(share_type, data));
    }

    if let Some((share_type, share_data, scalar)) = share_scalar_operands(right, left)? {
        let data = share_runtime()?.scalar_sub_data(share_type, scalar, share_data)?;
        return Ok(Value::Share(share_type, data));
    }

    type_error("SUB")
}

pub(crate) fn mul(
    left: &Value,
    right: &Value,
    share_runtime: ShareRuntimeProvider<'_>,
) -> ValueOpResult<Value> {
    if let Some(result) = try_clear_mul(left, right) {
        return result;
    }

    if let Some(pair) = matching_share_pair("MUL", left, right)? {
        let data = share_runtime()?.multiply_share_data(
            pair.share_type,
            pair.left_data,
            pair.right_data,
        )?;
        return Ok(Value::Share(pair.share_type, data));
    }

    // Secret share x fixed-point (non-integer) scalar, in either operand order.
    // Produces a fixed-point result; see `mul_share_by_fixed_scalar`.
    if let Some(result) = mul_share_by_fixed_scalar(left, right, share_runtime)? {
        return Ok(result);
    }
    if let Some(result) = mul_share_by_fixed_scalar(right, left, share_runtime)? {
        return Ok(result);
    }

    if let Some((share_type, share_data, scalar)) = share_scalar_operands(left, right)? {
        let data = share_runtime()?.mul_scalar_data(share_type, share_data, scalar)?;
        return Ok(Value::Share(share_type, data));
    }

    if let Some((share_type, share_data, scalar)) = share_scalar_operands(right, left)? {
        let data = share_runtime()?.mul_scalar_data(share_type, share_data, scalar)?;
        return Ok(Value::Share(share_type, data));
    }

    type_error("MUL")
}

pub(crate) fn div(
    left: &Value,
    right: &Value,
    share_runtime: ShareRuntimeProvider<'_>,
) -> ValueOpResult<Value> {
    if let Some(result) = try_clear_div(left, right) {
        return result;
    }

    if matching_share_pair("DIV", left, right)?.is_some() {
        return unsupported("Share/Share division is not supported on secret shares");
    }

    // Secret fixed-point share divided by a public constant: run the
    // interactive fixed-point division protocol (reciprocal + truncation) so
    // the quotient stays secret-shared with correct fixed-point semantics.
    if let Value::Share(share_type @ ShareType::SecretFixedPoint { .. }, share_data) = left {
        if let Some(divisor_scaled) = fixed_point_divisor_scaled(*share_type, right) {
            let data = share_runtime()?.div_fixed_by_const_data(
                *share_type,
                share_data,
                divisor_scaled,
            )?;
            return Ok(Value::Share(*share_type, data));
        }
    }

    if let Some((share_type, share_data, scalar)) = share_scalar_operands(left, right)? {
        let data = share_runtime()?.div_scalar_data(share_type, share_data, scalar)?;
        return Ok(Value::Share(share_type, data));
    }

    type_error("DIV")
}

/// Multiply a secret share by a public fixed-point (non-integer) scalar, in a
/// type-generic way. Returns `Ok(None)` when this isn't a `share x float` pair
/// (so the caller can fall through to the integer-scalar path).
///
/// Result is always fixed-point. Fractional bits add under multiplication, so:
/// - integer share x fixed scalar -> the integer contributes 0 fractional bits,
///   so the product already has exactly `f` bits: scale the scalar by `2^f`,
///   multiply locally, and reinterpret the result as fixed-point. No truncation.
/// - fixed share x fixed scalar -> the product would carry `2f` fractional bits,
///   so it must be truncated back to `f`. Secret-share the public scalar locally
///   and run the secret*secret fixed-point multiply, which truncates.
fn mul_share_by_fixed_scalar(
    share_value: &Value,
    scalar_value: &Value,
    share_runtime: ShareRuntimeProvider<'_>,
) -> ValueOpResult<Option<Value>> {
    let Value::Share(share_type, share_data) = share_value else {
        return Ok(None);
    };
    let Value::Float(F64(scalar)) = scalar_value else {
        return Ok(None);
    };
    if *share_type == ShareType::SecretField {
        return unsupported("SecretField requires an integer scalar or field arithmetic");
    }
    let scalar = *scalar;

    // The product keeps the share's precision when the share is already
    // fixed-point; otherwise it adopts the default fixed-point precision.
    let (total_bits, target_f) = match share_type {
        ShareType::SecretFixedPoint { precision } => {
            (precision.total_bits(), precision.fractional_bits())
        }
        _ => (
            DEFAULT_FIXED_POINT_TOTAL_BITS,
            DEFAULT_FIXED_POINT_FRACTIONAL_BITS,
        ),
    };
    let result_type = ShareType::SecretFixedPoint {
        precision: FixedPointPrecision::new(total_bits, target_f),
    };

    let share_is_fixed = matches!(share_type, ShareType::SecretFixedPoint { .. });
    if share_is_fixed {
        // Fixed x fixed: needs the truncating secret*secret multiply.
        let scalar_input =
            ClearShareInput::new(result_type, ClearShareValue::FixedPoint(F64(scalar)));
        let scalar_share = share_runtime()?.input_share(scalar_input)?;
        let data = share_runtime()?.multiply_share_data(result_type, share_data, &scalar_share)?;
        Ok(Some(Value::Share(result_type, data)))
    } else {
        // Integer x fixed: exact and local.
        let Some(scaled) = scale_to_fixed(scalar, target_f) else {
            return Ok(None);
        };
        let data = share_runtime()?.mul_scalar_data(*share_type, share_data, scaled)?;
        Ok(Some(Value::Share(result_type, data)))
    }
}

/// `round(value * 2^fractional_bits)` as `i64`, or `None` on overflow/non-finite.
fn scale_to_fixed(value: f64, fractional_bits: usize) -> Option<i64> {
    let scale = 2f64.powi(i32::try_from(fractional_bits).ok()?);
    let scaled = (value * scale).round();
    if !scaled.is_finite() || scaled < i64::MIN as f64 || scaled >= 9.223_372_036_854_776e18 {
        return None;
    }
    Some(scaled as i64)
}

/// Scale a public divisor into the share's fixed-point representation
/// (`round(divisor * 2^f)`), for a `secret fix64 / <constant>` division.
/// Accepts a clear fixed-point (`Value::Float`) or integer divisor; returns
/// `None` for anything else.
fn fixed_point_divisor_scaled(share_type: ShareType, divisor: &Value) -> Option<i64> {
    let ShareType::SecretFixedPoint { precision } = share_type else {
        return None;
    };
    let divisor_f64 = match divisor {
        Value::Float(value) => value.0,
        Value::I64(v) => *v as f64,
        Value::I32(v) => f64::from(*v),
        Value::I16(v) => f64::from(*v),
        Value::I8(v) => f64::from(*v),
        Value::U8(v) => f64::from(*v),
        Value::U16(v) => f64::from(*v),
        Value::U32(v) => f64::from(*v),
        Value::U64(v) => *v as f64,
        _ => return None,
    };
    let scale = 2f64.powi(i32::try_from(precision.fractional_bits()).ok()?);
    let scaled = (divisor_f64 * scale).round();
    if !scaled.is_finite() || scaled < i64::MIN as f64 || scaled >= 9.223_372_036_854_776e18 {
        return None;
    }
    Some(scaled as i64)
}

pub(crate) fn modulo(left: &Value, right: &Value) -> ValueOpResult<Value> {
    if let Some(result) = try_clear_modulo(left, right) {
        return result;
    }

    if matching_share_pair("MOD", left, right)?.is_some() {
        return unsupported("Share/Share modulo is not supported on secret shares");
    }

    type_error("MOD")
}

pub(crate) fn try_clear_add(left: &Value, right: &Value) -> Option<ValueOpResult<Value>> {
    Some(match (left, right) {
        (Value::I64(a), Value::I64(b)) => checked_value("ADD", a.checked_add(*b), Value::I64),
        (Value::I32(a), Value::I32(b)) => checked_value("ADD", a.checked_add(*b), Value::I32),
        (Value::I16(a), Value::I16(b)) => checked_value("ADD", a.checked_add(*b), Value::I16),
        (Value::I8(a), Value::I8(b)) => checked_value("ADD", a.checked_add(*b), Value::I8),
        (Value::U8(a), Value::U8(b)) => checked_value("ADD", a.checked_add(*b), Value::U8),
        (Value::U16(a), Value::U16(b)) => checked_value("ADD", a.checked_add(*b), Value::U16),
        (Value::U32(a), Value::U32(b)) => checked_value("ADD", a.checked_add(*b), Value::U32),
        (Value::U64(a), Value::U64(b)) => checked_value("ADD", a.checked_add(*b), Value::U64),
        (Value::Float(a), Value::I64(b)) => Ok(Value::Float(F64(a.0 + *b as f64))),
        (Value::I64(a), Value::Float(b)) => Ok(Value::Float(F64(*a as f64 + b.0))),
        (Value::Float(a), Value::Float(b)) => Ok(Value::Float(F64(a.0 + b.0))),
        (Value::String(a), Value::String(b)) => Ok(Value::String(format!("{a}{b}"))),
        _ => return None,
    })
}

pub(crate) fn try_clear_sub(left: &Value, right: &Value) -> Option<ValueOpResult<Value>> {
    Some(match (left, right) {
        (Value::I64(a), Value::I64(b)) => checked_value("SUB", a.checked_sub(*b), Value::I64),
        (Value::I32(a), Value::I32(b)) => checked_value("SUB", a.checked_sub(*b), Value::I32),
        (Value::I16(a), Value::I16(b)) => checked_value("SUB", a.checked_sub(*b), Value::I16),
        (Value::I8(a), Value::I8(b)) => checked_value("SUB", a.checked_sub(*b), Value::I8),
        (Value::U8(a), Value::U8(b)) => checked_value("SUB", a.checked_sub(*b), Value::U8),
        (Value::U16(a), Value::U16(b)) => checked_value("SUB", a.checked_sub(*b), Value::U16),
        (Value::U32(a), Value::U32(b)) => checked_value("SUB", a.checked_sub(*b), Value::U32),
        (Value::U64(a), Value::U64(b)) => checked_value("SUB", a.checked_sub(*b), Value::U64),
        (Value::Float(a), Value::I64(b)) => Ok(Value::Float(F64(a.0 - *b as f64))),
        (Value::I64(a), Value::Float(b)) => Ok(Value::Float(F64(*a as f64 - b.0))),
        (Value::Float(a), Value::Float(b)) => Ok(Value::Float(F64(a.0 - b.0))),
        _ => return None,
    })
}

pub(crate) fn try_clear_mul(left: &Value, right: &Value) -> Option<ValueOpResult<Value>> {
    Some(match (left, right) {
        (Value::I64(a), Value::I64(b)) => checked_value("MUL", a.checked_mul(*b), Value::I64),
        (Value::I32(a), Value::I32(b)) => checked_value("MUL", a.checked_mul(*b), Value::I32),
        (Value::I16(a), Value::I16(b)) => checked_value("MUL", a.checked_mul(*b), Value::I16),
        (Value::I8(a), Value::I8(b)) => checked_value("MUL", a.checked_mul(*b), Value::I8),
        (Value::U8(a), Value::U8(b)) => checked_value("MUL", a.checked_mul(*b), Value::U8),
        (Value::U16(a), Value::U16(b)) => checked_value("MUL", a.checked_mul(*b), Value::U16),
        (Value::U32(a), Value::U32(b)) => checked_value("MUL", a.checked_mul(*b), Value::U32),
        (Value::U64(a), Value::U64(b)) => checked_value("MUL", a.checked_mul(*b), Value::U64),
        (Value::Float(a), Value::I64(b)) => Ok(Value::Float(F64(a.0 * *b as f64))),
        (Value::I64(a), Value::Float(b)) => Ok(Value::Float(F64(*a as f64 * b.0))),
        (Value::Float(a), Value::Float(b)) => Ok(Value::Float(F64(a.0 * b.0))),
        _ => return None,
    })
}

pub(crate) fn try_clear_div(left: &Value, right: &Value) -> Option<ValueOpResult<Value>> {
    Some(match (left, right) {
        (Value::I64(a), Value::I64(b)) => checked_div_i64(*a, *b).map(Value::I64),
        (Value::I32(a), Value::I32(b)) => checked_div_i32(*a, *b).map(Value::I32),
        (Value::I16(a), Value::I16(b)) => checked_div_i16(*a, *b).map(Value::I16),
        (Value::I8(a), Value::I8(b)) => checked_div_i8(*a, *b).map(Value::I8),
        (Value::U8(a), Value::U8(b)) => checked_div_u8(*a, *b).map(Value::U8),
        (Value::U16(a), Value::U16(b)) => checked_div_u16(*a, *b).map(Value::U16),
        (Value::U32(a), Value::U32(b)) => checked_div_u32(*a, *b).map(Value::U32),
        (Value::U64(a), Value::U64(b)) => checked_div_u64(*a, *b).map(Value::U64),
        (Value::Float(a), Value::I64(b)) => {
            ensure_nonzero_i64(*b, "Division").map(|()| Value::Float(F64(a.0 / *b as f64)))
        }
        (Value::I64(a), Value::Float(b)) => {
            ensure_nonzero_f64(b.0, "Division").map(|()| Value::Float(F64(*a as f64 / b.0)))
        }
        (Value::Float(a), Value::Float(b)) => {
            ensure_nonzero_f64(b.0, "Division").map(|()| Value::Float(F64(a.0 / b.0)))
        }
        _ => return None,
    })
}

pub(crate) fn try_clear_modulo(left: &Value, right: &Value) -> Option<ValueOpResult<Value>> {
    Some(match (left, right) {
        (Value::I64(a), Value::I64(b)) => checked_rem_i64(*a, *b).map(Value::I64),
        (Value::I32(a), Value::I32(b)) => checked_rem_i32(*a, *b).map(Value::I32),
        (Value::I16(a), Value::I16(b)) => checked_rem_i16(*a, *b).map(Value::I16),
        (Value::I8(a), Value::I8(b)) => checked_rem_i8(*a, *b).map(Value::I8),
        (Value::U8(a), Value::U8(b)) => checked_rem_u8(*a, *b).map(Value::U8),
        (Value::U16(a), Value::U16(b)) => checked_rem_u16(*a, *b).map(Value::U16),
        (Value::U32(a), Value::U32(b)) => checked_rem_u32(*a, *b).map(Value::U32),
        (Value::U64(a), Value::U64(b)) => checked_rem_u64(*a, *b).map(Value::U64),
        (Value::Float(a), Value::I64(b)) => {
            ensure_nonzero_i64(*b, "Modulo").map(|()| Value::Float(F64(a.0 % *b as f64)))
        }
        (Value::I64(a), Value::Float(b)) => {
            ensure_nonzero_f64(b.0, "Modulo").map(|()| Value::Float(F64(*a as f64 % b.0)))
        }
        (Value::Float(a), Value::Float(b)) => {
            ensure_nonzero_f64(b.0, "Modulo").map(|()| Value::Float(F64(a.0 % b.0)))
        }
        _ => return None,
    })
}

fn checked_value<T>(
    operation: &'static str,
    result: Option<T>,
    wrap: impl FnOnce(T) -> Value,
) -> ValueOpResult<Value> {
    checked_integer_result(operation, result).map(wrap)
}

fn ensure_nonzero_i64(value: i64, operation: &'static str) -> ValueOpResult<()> {
    if value == 0 {
        zero_division_error(operation)
    } else {
        Ok(())
    }
}

fn ensure_nonzero_f64(value: f64, operation: &'static str) -> ValueOpResult<()> {
    if value == 0.0 {
        zero_division_error(operation)
    } else {
        Ok(())
    }
}

fn zero_division_error<T>(operation: &'static str) -> ValueOpResult<T> {
    match operation {
        "Modulo" => Err(ValueOpError::ModuloByZero),
        _ => Err(ValueOpError::DivisionByZero),
    }
}

macro_rules! checked_div {
    ($name:ident, $ty:ty) => {
        fn $name(left: $ty, right: $ty) -> ValueOpResult<$ty> {
            if right == 0 {
                return Err(ValueOpError::DivisionByZero);
            }
            checked_integer_result("DIV", left.checked_div(right))
        }
    };
}

macro_rules! checked_rem {
    ($name:ident, $ty:ty) => {
        fn $name(left: $ty, right: $ty) -> ValueOpResult<$ty> {
            if right == 0 {
                return Err(ValueOpError::ModuloByZero);
            }
            checked_integer_result("MOD", left.checked_rem(right))
        }
    };
}

checked_div!(checked_div_i64, i64);
checked_div!(checked_div_i32, i32);
checked_div!(checked_div_i16, i16);
checked_div!(checked_div_i8, i8);
checked_div!(checked_div_u8, u8);
checked_div!(checked_div_u16, u16);
checked_div!(checked_div_u32, u32);
checked_div!(checked_div_u64, u64);

checked_rem!(checked_rem_i64, i64);
checked_rem!(checked_rem_i32, i32);
checked_rem!(checked_rem_i16, i16);
checked_rem!(checked_rem_i8, i8);
checked_rem!(checked_rem_u8, u8);
checked_rem!(checked_rem_u16, u16);
checked_rem!(checked_rem_u32, u32);
checked_rem!(checked_rem_u64, u64);
