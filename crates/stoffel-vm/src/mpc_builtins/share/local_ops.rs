use super::result::create_result_share_value;
use crate::core_vm::VirtualMachine;
use crate::foreign_functions::{
    ForeignFunctionCallbackError, ForeignFunctionCallbackResult, ForeignFunctionContext,
};
use crate::value_conversions::value_to_i64;
use crate::VirtualMachineResult;
use stoffel_vm_types::core_types::{
    ClearShareInput, ClearShareValue, FixedPointPrecision, ShareType, Value,
    DEFAULT_FIXED_POINT_FRACTIONAL_BITS, DEFAULT_FIXED_POINT_TOTAL_BITS, F64,
};

pub(super) fn register(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    vm.try_register_typed_foreign_method("Share", "add", "Share.add", share_add)?;
    vm.try_register_typed_foreign_method("Share", "sub", "Share.sub", share_sub)?;
    vm.try_register_typed_foreign_method("Share", "neg", "Share.neg", share_neg)?;
    vm.try_register_typed_foreign_method(
        "Share",
        "add_constant",
        "Share.add_constant",
        share_add_constant,
    )?;
    // Deprecated alias for `add_constant`; kept so bytecode compiled before the
    // rename (which still calls `Share.add_scalar`) resolves to the same handler.
    vm.try_register_typed_foreign_method(
        "Share",
        "add_scalar",
        "Share.add_scalar",
        share_add_constant,
    )?;
    vm.try_register_typed_foreign_method(
        "Share",
        "mul_scalar",
        "Share.mul_scalar",
        share_mul_scalar,
    )?;
    vm.try_register_typed_foreign_method("Share", "mul_field", "Share.mul_field", share_mul_field)?;
    vm.try_register_typed_foreign_method("Share", "add_field", "Share.add_field", share_add_field)?;
    vm.try_register_typed_foreign_method("Share", "retag", "Share.retag", share_retag)?;
    vm.try_register_typed_foreign_function("Share.interpolate_local", share_interpolate_local)?;
    Ok(())
}

/// Reinterpret an integer share's declared bit-length — a local type-tag change
/// only, with NO interactive reduction of the underlying secret. The caller is
/// responsible for ensuring the value already fits the new width (e.g. tagging a
/// share known to hold 0/1 as a 1-bit `secret bool`). This is a reinterpret, not
/// a cast: narrowing a value that does not fit will leave it out of range.
/// Use `bit_length = 1` for booleans.
fn share_retag(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let (share_value, bit_length) = {
        let args = ctx.named_args("Share.retag");
        args.require_exact(2, "2 arguments: share, bit_length")?;
        (
            args.cloned(0)?,
            value_to_i64(&args.cloned(1)?, "bit_length")?,
        )
    };
    let bit_length = usize::try_from(bit_length).map_err(|_| {
        ForeignFunctionCallbackError::Message("bit_length must be non-negative".to_string())
    })?;

    let (ty, data) = ctx.extract_share_data(&share_value)?;
    if !matches!(
        ty,
        ShareType::SecretInt { .. } | ShareType::SecretUInt { .. }
    ) {
        return Err("Share.retag requires an integer share".into());
    }

    create_result_share_value(ShareType::try_secret_int(bit_length)?, data)
}

fn share_add(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let (share_type, left_data, right_data) = {
        let (left, right) = {
            let args = ctx.named_args("Share.add");
            args.require_min(2, "2 arguments: share1, share2")?;
            (args.cloned(0)?, args.cloned(1)?)
        };

        ctx.extract_matching_share_pair(&left, &right, "Share.add")?
    };
    let result_data = ctx.secret_share_add_data(share_type, &left_data, &right_data)?;
    create_result_share_value(share_type, result_data)
}

fn share_sub(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let (share_type, left_data, right_data) = {
        let (left, right) = {
            let args = ctx.named_args("Share.sub");
            args.require_min(2, "2 arguments: share1, share2")?;
            (args.cloned(0)?, args.cloned(1)?)
        };

        ctx.extract_matching_share_pair(&left, &right, "Share.sub")?
    };
    let result_data = ctx.secret_share_sub_data(share_type, &left_data, &right_data)?;
    create_result_share_value(share_type, result_data)
}

fn share_neg(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let (ty, data) = {
        let share_value = {
            let args = ctx.named_args("Share.neg");
            args.require_exact(1, "1 argument: share")?;
            args.cloned(0)?
        };

        ctx.extract_share_data(&share_value)?
    };

    let result_data = ctx.secret_share_neg_data(ty, &data)?;
    create_result_share_value(ty, result_data)
}

fn share_add_constant(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let (share_value, constant_value) = {
        let args = ctx.named_args("Share.add_constant");
        args.require_min(2, "2 arguments: share, constant")?;
        (args.cloned(0)?, args.cloned(1)?)
    };
    let (ty, data) = ctx.extract_share_data(&share_value)?;

    // A fixed-point (non-integer) constant promotes the result to fixed-point.
    // Addition does not change the number of fractional bits, so both operands
    // are represented in the same `f`-bit fixed-point domain and added locally
    // (share + share, no communication):
    // - fixed share + fixed constant: operands already share precision `f`, so
    //   locally share the constant and add it directly.
    // - integer share + fixed constant: scale the integer share into the
    //   fixed-point domain (multiply its value by `2^f`) before adding.
    if let Value::Float(F64(constant)) = constant_value {
        if ty == ShareType::SecretField {
            return Err("SecretField requires an integer scalar or field arithmetic".into());
        }
        let (total_bits, target_f) = match ty {
            ShareType::SecretFixedPoint { precision } => {
                (precision.total_bits(), precision.fractional_bits())
            }
            _ => (
                DEFAULT_FIXED_POINT_TOTAL_BITS,
                DEFAULT_FIXED_POINT_FRACTIONAL_BITS,
            ),
        };
        let result_ty = ShareType::SecretFixedPoint {
            precision: FixedPointPrecision::new(total_bits, target_f),
        };
        let constant_share = ctx.input_share_data(ClearShareInput::new(
            result_ty,
            ClearShareValue::FixedPoint(F64(constant)),
        ))?;
        let result_data = if matches!(ty, ShareType::SecretFixedPoint { .. }) {
            ctx.secret_share_add_data(result_ty, &data, &constant_share)?
        } else {
            let scale = scale_fixed_scalar(1.0, target_f)?;
            let promoted = ctx.secret_share_mul_scalar_data(ty, &data, scale)?;
            ctx.secret_share_add_data(result_ty, &promoted, &constant_share)?
        };
        return create_result_share_value(result_ty, result_data);
    }

    let constant = value_to_i64(&constant_value, "constant")?;
    let result_data = ctx.secret_share_add_scalar_data(ty, &data, constant)?;
    create_result_share_value(ty, result_data)
}

fn share_mul_scalar(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let (share_value, scalar_value) = {
        let args = ctx.named_args("Share.mul_scalar");
        args.require_min(2, "2 arguments: share, scalar")?;
        (args.cloned(0)?, args.cloned(1)?)
    };
    let (ty, data) = ctx.extract_share_data(&share_value)?;

    // A fixed-point (non-integer) scalar promotes the result to fixed-point and
    // is handled generically for any share type. Fractional bits add under
    // multiplication, so the result keeps `f` fractional bits:
    // - integer share x fixed scalar: exact and local (the integer contributes
    //   0 fractional bits), so multiply by round(scalar * 2^f) and reinterpret
    //   the product as fixed-point.
    // - fixed share x fixed scalar: the product would carry 2f fractional bits,
    //   so secret-share the public scalar and run the truncating secret*secret
    //   fixed-point multiply.
    if let Value::Float(F64(scalar)) = scalar_value {
        if ty == ShareType::SecretField {
            return Err("SecretField requires an integer scalar or field arithmetic".into());
        }
        let (total_bits, target_f) = match ty {
            ShareType::SecretFixedPoint { precision } => {
                (precision.total_bits(), precision.fractional_bits())
            }
            _ => (
                DEFAULT_FIXED_POINT_TOTAL_BITS,
                DEFAULT_FIXED_POINT_FRACTIONAL_BITS,
            ),
        };
        let result_ty = ShareType::SecretFixedPoint {
            precision: FixedPointPrecision::new(total_bits, target_f),
        };
        let result_data = if matches!(ty, ShareType::SecretFixedPoint { .. }) {
            let scalar_share = ctx.input_share_data(ClearShareInput::new(
                result_ty,
                ClearShareValue::FixedPoint(F64(scalar)),
            ))?;
            ctx.secret_share_mul_data(result_ty, &data, &scalar_share)?
        } else {
            let scaled = scale_fixed_scalar(scalar, target_f)?;
            ctx.secret_share_mul_scalar_data(ty, &data, scaled)?
        };
        return create_result_share_value(result_ty, result_data);
    }

    let scalar = value_to_i64(&scalar_value, "scalar")?;
    let result_data = ctx.secret_share_mul_scalar_data(ty, &data, scalar)?;
    create_result_share_value(ty, result_data)
}

/// `round(value * 2^fractional_bits)` as `i64`, erroring on overflow/non-finite.
fn scale_fixed_scalar(
    value: f64,
    fractional_bits: usize,
) -> Result<i64, ForeignFunctionCallbackError> {
    let exp = i32::try_from(fractional_bits).map_err(|_| {
        ForeignFunctionCallbackError::Message("fixed-point precision too large".to_string())
    })?;
    let scaled = (value * 2f64.powi(exp)).round();
    if !scaled.is_finite() || scaled < i64::MIN as f64 || scaled >= 9.223_372_036_854_776e18 {
        return Err(ForeignFunctionCallbackError::Message(format!(
            "fixed-point scalar {value} out of range"
        )));
    }
    Ok(scaled as i64)
}

fn share_mul_field(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let (ty, data, field_bytes) = {
        let (share_value, field_value) = {
            let args = ctx.named_args("Share.mul_field");
            args.require_min(2, "2 arguments: share, field_bytes")?;
            (args.cloned(0)?, args.cloned(1)?)
        };

        let (ty, data) = ctx.extract_share_data(&share_value)?;
        if matches!(ty, ShareType::SecretFixedPoint { .. }) {
            return Err("Field arithmetic requires an integer or field share; use scalar arithmetic for fixed-point shares".into());
        }
        let field_bytes = ctx.read_byte_array(&field_value)?;
        (ty, data, field_bytes)
    };

    let result_data = ctx.secret_share_mul_field_data(ty, &data, &field_bytes)?;
    create_result_share_value(ShareType::SecretField, result_data)
}

fn share_add_field(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let (ty, data, field_bytes) = {
        let (share_value, field_value) = {
            let args = ctx.named_args("Share.add_field");
            args.require_min(2, "2 arguments: share, field_bytes")?;
            (args.cloned(0)?, args.cloned(1)?)
        };

        let (ty, data) = ctx.extract_share_data(&share_value)?;
        if matches!(ty, ShareType::SecretFixedPoint { .. }) {
            return Err("Field arithmetic requires an integer or field share; use scalar arithmetic for fixed-point shares".into());
        }
        let field_bytes = ctx.read_byte_array(&field_value)?;
        (ty, data, field_bytes)
    };

    let result_data = ctx.secret_share_add_field_data(ty, &data, &field_bytes)?;
    create_result_share_value(ShareType::SecretField, result_data)
}

fn share_interpolate_local(
    mut ctx: ForeignFunctionContext,
) -> ForeignFunctionCallbackResult<Value> {
    let shares_arg = {
        let args = ctx.named_args("Share.interpolate_local");
        args.require_exact(1, "1 argument: shares_array")?;
        args.cloned(0)?
    };

    let Some((ty, share_data)) =
        ctx.extract_homogeneous_share_array(&shares_arg, "Share.interpolate_local shares_array")?
    else {
        return Err("Cannot interpolate from empty array".into());
    };

    let threshold = ctx.require_mpc_runtime_info()?.threshold_param().value();
    let required = 2 * threshold + 1;
    if share_data.len() < required {
        return Err(format!(
            "Need at least {} shares for interpolation, got {}",
            required,
            share_data.len()
        )
        .into());
    }

    Ok(ctx.secret_share_interpolate_local(ty, &share_data)?)
}
