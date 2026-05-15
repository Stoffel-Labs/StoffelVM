use super::result::create_result_share_object;
use crate::core_vm::VirtualMachine;
use crate::foreign_functions::{
    ForeignFunctionCallbackResult, ForeignFunctionContext, MpcOnlineBuiltin,
};
use crate::net::client_store::ClientOutputShareCount;
use crate::net::mpc_engine::MpcExponentGenerator;
use crate::value_conversions::value_to_usize;
use crate::VirtualMachineResult;
use stoffel_vm_types::core_types::{ShareType, Value};

pub(super) fn register(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    vm.try_register_mpc_online_foreign_function(MpcOnlineBuiltin::Mul, share_mul)?;
    vm.try_register_mpc_online_foreign_function(MpcOnlineBuiltin::Open, share_open)?;
    vm.try_register_mpc_online_foreign_function(MpcOnlineBuiltin::BatchOpen, share_batch_open)?;
    vm.try_register_mpc_online_foreign_function(
        MpcOnlineBuiltin::SendToClient,
        share_send_to_client,
    )?;
    vm.try_register_mpc_online_foreign_function(MpcOnlineBuiltin::OpenExp, share_open_exp)?;
    vm.try_register_mpc_online_foreign_function(MpcOnlineBuiltin::Random, share_random)?;
    vm.try_register_mpc_online_foreign_function(MpcOnlineBuiltin::OpenField, share_open_field)?;
    vm.try_register_mpc_online_foreign_function(
        MpcOnlineBuiltin::OpenExpCustom,
        share_open_exp_custom,
    )?;
    Ok(())
}

fn share_mul(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let (share_type, left_data, right_data) = {
        let (left, right) = {
            let args = ctx.named_args("Share.mul");
            args.require_min(2, "2 arguments: share1, share2")?;
            (args.cloned(0)?, args.cloned(1)?)
        };

        ctx.extract_matching_share_pair(&left, &right, "Share.mul")?
    };

    let result_data = ctx.secret_share_mul_data(share_type, &left_data, &right_data)?;
    create_result_share_object(&mut ctx, share_type, result_data)
}

fn share_open(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let (ty, data) = {
        let share_value = {
            let args = ctx.named_args("Share.open");
            args.require_exact(1, "1 argument: share")?;
            args.cloned(0)?
        };

        ctx.extract_share_data(&share_value)?
    };

    let revealed = ctx.open_share_data(ty, &data)?;
    Ok(revealed.into_vm_value())
}

fn share_batch_open(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let shares_arg = {
        let args = ctx.named_args("Share.batch_open");
        args.require_exact(1, "1 argument: shares_array")?;
        args.cloned(0)?
    };

    let Some((share_type, share_data)) =
        ctx.extract_homogeneous_share_array(&shares_arg, "Share.batch_open shares_array")?
    else {
        return ctx.create_array(0);
    };

    let revealed: Vec<Value> = ctx
        .batch_open_share_data(share_type, &share_data)?
        .into_iter()
        .map(|value| value.into_vm_value())
        .collect();

    let result_ref = ctx.create_array_ref(revealed.len())?;
    ctx.push_array_ref_values(result_ref, &revealed)?;

    Ok(Value::from(result_ref))
}

fn share_send_to_client(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let (data, client_id) = {
        let (share_value, client_id_value) = {
            let args = ctx.named_args("Share.send_to_client");
            args.require_min(2, "2 arguments: share, client_id")?;
            (args.cloned(0)?, args.cloned(1)?)
        };

        let (_ty, data) = ctx.extract_share_data(&share_value)?;
        let client_id = value_to_usize(&client_id_value, "client_id")?;
        (data, client_id)
    };

    ctx.send_output_to_client(client_id, data.as_bytes(), ClientOutputShareCount::one())?;
    Ok(Value::Bool(true))
}

fn share_open_exp(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let (ty, data, curve_name) = {
        let (share_value, curve_value) = {
            let args = ctx.named_args("Share.open_exp");
            args.require_min(2, "2 arguments: share, curve_name")?;
            (args.cloned(0)?, args.cloned(1)?)
        };

        let (ty, data) = ctx.extract_share_data(&share_value)?;
        let curve_name = match curve_value {
            Value::String(s) => s,
            _ => return Err("curve_name must be a string".into()),
        };

        (ty, data, curve_name)
    };

    let generator = MpcExponentGenerator::from_curve_name(&curve_name).map_err(String::from)?;
    let result_bytes =
        ctx.open_share_in_exp_group_data(generator.group(), ty, &data, generator.bytes())?;

    ctx.create_byte_array(&result_bytes)
}

fn share_random(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let share_type = ShareType::default_secret_int();
    let share_data = ctx.random_share_data(share_type)?;
    create_result_share_object(&mut ctx, share_type, share_data)
}

fn share_open_field(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let (ty, data) = {
        let share_value = {
            let args = ctx.named_args("Share.open_field");
            args.require_exact(1, "1 argument: share")?;
            args.cloned(0)?
        };

        ctx.extract_share_data(&share_value)?
    };

    let result_bytes = ctx.open_share_as_field_data(ty, &data)?;
    ctx.create_byte_array(&result_bytes)
}

fn share_open_exp_custom(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let (ty, data, gen_bytes) = {
        let (share_value, generator_value) = {
            let args = ctx.named_args("Share.open_exp_custom");
            args.require_min(2, "2 arguments: share, generator_bytes")?;
            (args.cloned(0)?, args.cloned(1)?)
        };

        let (ty, data) = ctx.extract_share_data(&share_value)?;
        let gen_bytes = ctx.read_byte_array(&generator_value)?;
        (ty, data, gen_bytes)
    };

    let result_bytes = ctx.open_share_in_exp_data(ty, &data, &gen_bytes)?;
    ctx.create_byte_array(&result_bytes)
}
