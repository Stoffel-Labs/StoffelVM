use super::result::create_result_share_object;
use crate::core_vm::VirtualMachine;
use crate::foreign_functions::{ForeignFunctionCallbackResult, ForeignFunctionContext};
use crate::value_conversions::value_to_i64;
use crate::VirtualMachineResult;
use stoffel_vm_types::core_types::Value;

pub(super) fn register(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    vm.try_register_typed_foreign_function("Share.add", share_add)?;
    vm.try_register_typed_foreign_function("Share.sub", share_sub)?;
    vm.try_register_typed_foreign_function("Share.neg", share_neg)?;
    vm.try_register_typed_foreign_function("Share.add_scalar", share_add_scalar)?;
    vm.try_register_typed_foreign_function("Share.mul_scalar", share_mul_scalar)?;
    vm.try_register_typed_foreign_function("Share.mul_field", share_mul_field)?;
    vm.try_register_typed_foreign_function("Share.interpolate_local", share_interpolate_local)?;
    Ok(())
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
    create_result_share_object(&mut ctx, share_type, result_data)
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
    create_result_share_object(&mut ctx, share_type, result_data)
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
    create_result_share_object(&mut ctx, ty, result_data)
}

fn share_add_scalar(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let (ty, data, scalar) = {
        let (share_value, scalar_value) = {
            let args = ctx.named_args("Share.add_scalar");
            args.require_min(2, "2 arguments: share, scalar")?;
            (args.cloned(0)?, args.cloned(1)?)
        };

        let (ty, data) = ctx.extract_share_data(&share_value)?;
        let scalar = value_to_i64(&scalar_value, "scalar")?;
        (ty, data, scalar)
    };

    let result_data = ctx.secret_share_add_scalar_data(ty, &data, scalar)?;
    create_result_share_object(&mut ctx, ty, result_data)
}

fn share_mul_scalar(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let (ty, data, scalar) = {
        let (share_value, scalar_value) = {
            let args = ctx.named_args("Share.mul_scalar");
            args.require_min(2, "2 arguments: share, scalar")?;
            (args.cloned(0)?, args.cloned(1)?)
        };

        let (ty, data) = ctx.extract_share_data(&share_value)?;
        let scalar = value_to_i64(&scalar_value, "scalar")?;
        (ty, data, scalar)
    };

    let result_data = ctx.secret_share_mul_scalar_data(ty, &data, scalar)?;
    create_result_share_object(&mut ctx, ty, result_data)
}

fn share_mul_field(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let (ty, data, field_bytes) = {
        let (share_value, field_value) = {
            let args = ctx.named_args("Share.mul_field");
            args.require_min(2, "2 arguments: share, field_bytes")?;
            (args.cloned(0)?, args.cloned(1)?)
        };

        let (ty, data) = ctx.extract_share_data(&share_value)?;
        let field_bytes = ctx.read_byte_array(&field_value)?;
        (ty, data, field_bytes)
    };

    let result_data = ctx.secret_share_mul_field_data(ty, &data, &field_bytes)?;
    create_result_share_object(&mut ctx, ty, result_data)
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
