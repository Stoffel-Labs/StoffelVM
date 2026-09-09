use super::result::{create_result_share_object, create_result_share_value};
use crate::core_vm::VirtualMachine;
use crate::foreign_functions::{
    ForeignFunctionCallbackResult, ForeignFunctionContext, MpcOnlineBuiltin,
};
use crate::net::client_store::ClientOutputShareCount;
use crate::net::curve::clear_share_value_to_vm_value;
use crate::net::mpc_engine::MpcExponentGenerator;
use crate::value_conversions::value_to_usize;
use crate::VirtualMachineResult;
use stoffel_vm_types::core_types::{ShareType, Value};

pub(super) fn register(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    vm.try_register_mpc_online_foreign_method("Share", "mul", MpcOnlineBuiltin::Mul, share_mul)?;
    vm.try_register_mpc_online_foreign_function(MpcOnlineBuiltin::BatchMul, share_batch_mul)?;
    vm.try_register_mpc_online_foreign_method("Share", "open", MpcOnlineBuiltin::Open, share_open)?;
    vm.try_register_mpc_online_foreign_method(
        "Share",
        "open_fixed",
        MpcOnlineBuiltin::Open,
        share_open,
    )?;
    vm.try_register_mpc_online_foreign_function(MpcOnlineBuiltin::BatchOpen, share_batch_open)?;
    vm.try_register_typed_foreign_function("Share.batch_open_field", share_batch_open_field)?;
    vm.try_register_typed_foreign_function("Share.batch_open_exp", share_batch_open_exp)?;
    vm.try_register_typed_foreign_function(
        "Share.batch_open_exp_custom",
        share_batch_open_exp_custom,
    )?;
    vm.try_register_mpc_online_foreign_method(
        "Share",
        "send_to_client",
        MpcOnlineBuiltin::SendToClient,
        share_send_to_client,
    )?;
    vm.try_register_mpc_online_foreign_method(
        "Share",
        "open_exp",
        MpcOnlineBuiltin::OpenExp,
        share_open_exp,
    )?;
    vm.try_register_mpc_online_foreign_function(MpcOnlineBuiltin::Random, share_random)?;
    vm.try_register_mpc_online_foreign_function(MpcOnlineBuiltin::RandomField, share_random)?;
    vm.try_register_mpc_online_foreign_function(MpcOnlineBuiltin::RandomInt, share_random_int)?;
    vm.try_register_mpc_online_foreign_method(
        "Share",
        "open_field",
        MpcOnlineBuiltin::OpenField,
        share_open_field,
    )?;
    vm.try_register_mpc_online_foreign_method(
        "Share",
        "open_exp_custom",
        MpcOnlineBuiltin::OpenExpCustom,
        share_open_exp_custom,
    )?;
    Ok(())
}

fn share_batch_open_field(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let shares_arg = {
        let args = ctx.named_args("Share.batch_open_field");
        args.require_exact(1, "1 argument: shares_array")?;
        args.cloned(0)?
    };
    let Some((share_type, share_data)) =
        ctx.extract_homogeneous_share_array(&shares_arg, "Share.batch_open_field shares_array")?
    else {
        return ctx.create_array(0);
    };
    let fields = ctx.batch_open_shares_as_field_data(share_type, &share_data)?;
    let mut values = Vec::with_capacity(fields.len());
    for field in fields {
        values.push(ctx.create_byte_array(&field)?);
    }
    let result_ref = ctx.create_array_ref(values.len())?;
    ctx.push_array_ref_values(result_ref, &values)?;
    Ok(Value::from(result_ref))
}

fn share_batch_open_exp(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let (shares_arg, curve_name) = {
        let args = ctx.named_args("Share.batch_open_exp");
        args.require_exact(2, "2 arguments: shares_array, curve_name")?;
        let curve_name = match args.cloned(1)? {
            Value::String(value) => value,
            _ => return Err("curve_name must be a string".into()),
        };
        (args.cloned(0)?, curve_name)
    };
    let Some((share_type, share_data)) =
        ctx.extract_homogeneous_share_array(&shares_arg, "Share.batch_open_exp shares_array")?
    else {
        return ctx.create_array(0);
    };
    let generator = MpcExponentGenerator::from_curve_name(&curve_name).map_err(String::from)?;
    let points = ctx.batch_open_shares_in_exp_group_data(
        generator.group(),
        share_type,
        &share_data,
        generator.bytes(),
    )?;
    let mut values = Vec::with_capacity(points.len());
    for point in points {
        values.push(ctx.create_byte_array(&point)?);
    }
    let result_ref = ctx.create_array_ref(values.len())?;
    ctx.push_array_ref_values(result_ref, &values)?;
    Ok(Value::from(result_ref))
}

fn share_batch_open_exp_custom(
    mut ctx: ForeignFunctionContext,
) -> ForeignFunctionCallbackResult<Value> {
    let (shares_arg, generators_arg, curve_name) = {
        let args = ctx.named_args("Share.batch_open_exp_custom");
        args.require_exact(3, "3 arguments: shares_array, generators_array, curve_name")?;
        let curve_name = match args.cloned(2)? {
            Value::String(value) => value,
            _ => return Err("curve_name must be a string".into()),
        };
        (args.cloned(0)?, args.cloned(1)?, curve_name)
    };
    let Some((share_type, share_data)) = ctx
        .extract_homogeneous_share_array(&shares_arg, "Share.batch_open_exp_custom shares_array")?
    else {
        return ctx.create_array(0);
    };
    let Value::Array(generators_ref) = generators_arg else {
        return Err("generators_array must be a list[bytes]".into());
    };
    let generator_count = ctx.read_array_ref_len(generators_ref)?;
    if generator_count != share_data.len() {
        return Err(format!(
            "Share.batch_open_exp_custom requires the same number of shares and generators ({} != {})",
            share_data.len(),
            generator_count
        )
        .into());
    }
    let mut generators = Vec::with_capacity(generator_count);
    for index in 0..generator_count {
        let index_i64 = i64::try_from(index)
            .map_err(|_| "generator index exceeds the VM integer range".to_string())?;
        let value = ctx
            .read_table_field(generators_ref.into(), &Value::I64(index_i64))?
            .ok_or_else(|| format!("missing generator at index {index}"))?;
        generators.push(ctx.read_byte_array(&value)?);
    }
    let generator = MpcExponentGenerator::from_curve_name(&curve_name).map_err(String::from)?;
    let points = ctx.batch_open_shares_in_exp_group_custom_data(
        generator.group(),
        share_type,
        &share_data,
        &generators,
    )?;
    let mut values = Vec::with_capacity(points.len());
    for point in points {
        values.push(ctx.create_byte_array(&point)?);
    }
    let result_ref = ctx.create_array_ref(values.len())?;
    ctx.push_array_ref_values(result_ref, &values)?;
    Ok(Value::from(result_ref))
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
    create_result_share_value(share_type, result_data)
}

fn share_batch_mul(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let (lefts_arg, rights_arg) = {
        let args = ctx.named_args("Share.batch_mul");
        args.require_exact(2, "2 arguments: lefts_array, rights_array")?;
        (args.cloned(0)?, args.cloned(1)?)
    };

    let Some((share_type, left_data)) =
        ctx.extract_homogeneous_share_array(&lefts_arg, "Share.batch_mul lefts_array")?
    else {
        return ctx.create_array(0);
    };
    let Some((right_share_type, right_data)) =
        ctx.extract_homogeneous_share_array(&rights_arg, "Share.batch_mul rights_array")?
    else {
        return ctx.create_array(0);
    };

    if share_type != right_share_type {
        return Err(
            crate::foreign_functions::ForeignFunctionCallbackError::Message(
                "Share.batch_mul requires arrays with matching share types".to_string(),
            ),
        );
    }
    if left_data.len() != right_data.len() {
        return Err(
            crate::foreign_functions::ForeignFunctionCallbackError::Message(
                "Share.batch_mul requires arrays with the same length".to_string(),
            ),
        );
    }

    let results = ctx
        .secret_share_batch_mul_data(share_type, &left_data, &right_data)?
        .into_iter()
        .map(|data| Value::Share(share_type, data))
        .collect::<Vec<_>>();

    let result_ref = ctx.create_array_ref(results.len())?;
    ctx.push_array_ref_values(result_ref, &results)?;
    Ok(Value::from(result_ref))
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
    Ok(clear_share_value_to_vm_value(ty, revealed))
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
        .map(|value| clear_share_value_to_vm_value(share_type, value))
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

fn share_random_int(ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let bit_length = {
        let args = ctx.named_args("Share.random_int");
        args.require_exact(1, "1 argument: bit_length")?;
        value_to_usize(&args.cloned(0)?, "bit_length")?
    };
    let share_type = ShareType::secret_int(bit_length);
    let share_data = ctx.random_integer_share_data(share_type)?;
    Ok(Value::Share(share_type, share_data))
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
