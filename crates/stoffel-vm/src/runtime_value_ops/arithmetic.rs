use super::error::{
    checked_integer_result, type_error, unsupported, ShareRuntimeProvider, ValueOpError,
    ValueOpResult,
};
use super::share_operands::{matching_share_pair, share_scalar_operands};
use stoffel_vm_types::core_types::{Value, F64};

pub(crate) fn add(
    left: &Value,
    right: &Value,
    share_runtime: ShareRuntimeProvider<'_>,
) -> ValueOpResult<Value> {
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

    match (left, right) {
        (Value::I64(a), Value::I64(b)) => Ok(Value::I64(checked_integer_result(
            "ADD",
            a.checked_add(*b),
        )?)),
        (Value::I32(a), Value::I32(b)) => Ok(Value::I32(checked_integer_result(
            "ADD",
            a.checked_add(*b),
        )?)),
        (Value::I16(a), Value::I16(b)) => Ok(Value::I16(checked_integer_result(
            "ADD",
            a.checked_add(*b),
        )?)),
        (Value::I8(a), Value::I8(b)) => {
            Ok(Value::I8(checked_integer_result("ADD", a.checked_add(*b))?))
        }
        (Value::U8(a), Value::U8(b)) => {
            Ok(Value::U8(checked_integer_result("ADD", a.checked_add(*b))?))
        }
        (Value::U16(a), Value::U16(b)) => Ok(Value::U16(checked_integer_result(
            "ADD",
            a.checked_add(*b),
        )?)),
        (Value::U32(a), Value::U32(b)) => Ok(Value::U32(checked_integer_result(
            "ADD",
            a.checked_add(*b),
        )?)),
        (Value::U64(a), Value::U64(b)) => Ok(Value::U64(checked_integer_result(
            "ADD",
            a.checked_add(*b),
        )?)),
        _ => type_error("ADD"),
    }
}

pub(crate) fn sub(
    left: &Value,
    right: &Value,
    share_runtime: ShareRuntimeProvider<'_>,
) -> ValueOpResult<Value> {
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

    match (left, right) {
        (Value::I64(a), Value::I64(b)) => Ok(Value::I64(checked_integer_result(
            "SUB",
            a.checked_sub(*b),
        )?)),
        (Value::I32(a), Value::I32(b)) => Ok(Value::I32(checked_integer_result(
            "SUB",
            a.checked_sub(*b),
        )?)),
        (Value::I16(a), Value::I16(b)) => Ok(Value::I16(checked_integer_result(
            "SUB",
            a.checked_sub(*b),
        )?)),
        (Value::I8(a), Value::I8(b)) => {
            Ok(Value::I8(checked_integer_result("SUB", a.checked_sub(*b))?))
        }
        (Value::U8(a), Value::U8(b)) => {
            Ok(Value::U8(checked_integer_result("SUB", a.checked_sub(*b))?))
        }
        (Value::U16(a), Value::U16(b)) => Ok(Value::U16(checked_integer_result(
            "SUB",
            a.checked_sub(*b),
        )?)),
        (Value::U32(a), Value::U32(b)) => Ok(Value::U32(checked_integer_result(
            "SUB",
            a.checked_sub(*b),
        )?)),
        (Value::U64(a), Value::U64(b)) => Ok(Value::U64(checked_integer_result(
            "SUB",
            a.checked_sub(*b),
        )?)),
        _ => type_error("SUB"),
    }
}

pub(crate) fn mul(
    left: &Value,
    right: &Value,
    share_runtime: ShareRuntimeProvider<'_>,
) -> ValueOpResult<Value> {
    if let Some(pair) = matching_share_pair("MUL", left, right)? {
        let data = share_runtime()?.multiply_share_data(
            pair.share_type,
            pair.left_data,
            pair.right_data,
        )?;
        return Ok(Value::Share(pair.share_type, data));
    }

    if let Some((share_type, share_data, scalar)) = share_scalar_operands(left, right)? {
        let data = share_runtime()?.mul_scalar_data(share_type, share_data, scalar)?;
        return Ok(Value::Share(share_type, data));
    }

    if let Some((share_type, share_data, scalar)) = share_scalar_operands(right, left)? {
        let data = share_runtime()?.mul_scalar_data(share_type, share_data, scalar)?;
        return Ok(Value::Share(share_type, data));
    }

    match (left, right) {
        (Value::I64(a), Value::I64(b)) => Ok(Value::I64(checked_integer_result(
            "MUL",
            a.checked_mul(*b),
        )?)),
        (Value::I32(a), Value::I32(b)) => Ok(Value::I32(checked_integer_result(
            "MUL",
            a.checked_mul(*b),
        )?)),
        (Value::I16(a), Value::I16(b)) => Ok(Value::I16(checked_integer_result(
            "MUL",
            a.checked_mul(*b),
        )?)),
        (Value::I8(a), Value::I8(b)) => {
            Ok(Value::I8(checked_integer_result("MUL", a.checked_mul(*b))?))
        }
        (Value::U8(a), Value::U8(b)) => {
            Ok(Value::U8(checked_integer_result("MUL", a.checked_mul(*b))?))
        }
        (Value::U16(a), Value::U16(b)) => Ok(Value::U16(checked_integer_result(
            "MUL",
            a.checked_mul(*b),
        )?)),
        (Value::U32(a), Value::U32(b)) => Ok(Value::U32(checked_integer_result(
            "MUL",
            a.checked_mul(*b),
        )?)),
        (Value::U64(a), Value::U64(b)) => Ok(Value::U64(checked_integer_result(
            "MUL",
            a.checked_mul(*b),
        )?)),
        _ => type_error("MUL"),
    }
}

pub(crate) fn div(
    left: &Value,
    right: &Value,
    share_runtime: ShareRuntimeProvider<'_>,
) -> ValueOpResult<Value> {
    if matching_share_pair("DIV", left, right)?.is_some() {
        return unsupported("Share/Share division is not supported on secret shares");
    }

    if let Some((share_type, share_data, scalar)) = share_scalar_operands(left, right)? {
        let data = share_runtime()?.div_scalar_data(share_type, share_data, scalar)?;
        return Ok(Value::Share(share_type, data));
    }

    match (left, right) {
        (Value::I64(a), Value::I64(b)) => checked_div_i64(*a, *b).map(Value::I64),
        (Value::I32(a), Value::I32(b)) => checked_div_i32(*a, *b).map(Value::I32),
        (Value::I16(a), Value::I16(b)) => checked_div_i16(*a, *b).map(Value::I16),
        (Value::I8(a), Value::I8(b)) => checked_div_i8(*a, *b).map(Value::I8),
        (Value::U8(a), Value::U8(b)) => checked_div_u8(*a, *b).map(Value::U8),
        (Value::U16(a), Value::U16(b)) => checked_div_u16(*a, *b).map(Value::U16),
        (Value::U32(a), Value::U32(b)) => checked_div_u32(*a, *b).map(Value::U32),
        (Value::U64(a), Value::U64(b)) => checked_div_u64(*a, *b).map(Value::U64),
        (Value::Float(a), Value::I64(b)) => {
            ensure_nonzero_i64(*b, "Division")?;
            Ok(Value::Float(F64(a.0 / *b as f64)))
        }
        (Value::I64(a), Value::Float(b)) => {
            ensure_nonzero_f64(b.0, "Division")?;
            Ok(Value::Float(F64(*a as f64 / b.0)))
        }
        (Value::Float(a), Value::Float(b)) => {
            ensure_nonzero_f64(b.0, "Division")?;
            Ok(Value::Float(F64(a.0 / b.0)))
        }
        _ => type_error("DIV"),
    }
}

pub(crate) fn modulo(left: &Value, right: &Value) -> ValueOpResult<Value> {
    if matching_share_pair("MOD", left, right)?.is_some() {
        return unsupported("Share/Share modulo is not supported on secret shares");
    }

    match (left, right) {
        (Value::I64(a), Value::I64(b)) => checked_rem_i64(*a, *b).map(Value::I64),
        (Value::I32(a), Value::I32(b)) => checked_rem_i32(*a, *b).map(Value::I32),
        (Value::I16(a), Value::I16(b)) => checked_rem_i16(*a, *b).map(Value::I16),
        (Value::I8(a), Value::I8(b)) => checked_rem_i8(*a, *b).map(Value::I8),
        (Value::U8(a), Value::U8(b)) => checked_rem_u8(*a, *b).map(Value::U8),
        (Value::U16(a), Value::U16(b)) => checked_rem_u16(*a, *b).map(Value::U16),
        (Value::U32(a), Value::U32(b)) => checked_rem_u32(*a, *b).map(Value::U32),
        (Value::U64(a), Value::U64(b)) => checked_rem_u64(*a, *b).map(Value::U64),
        _ => type_error("MOD"),
    }
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
