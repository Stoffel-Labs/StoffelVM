use crate::core_vm::VirtualMachine;
use crate::net::mpc_engine::MpcCapability;
use crate::value_conversions::{u64_to_vm_i64, usize_to_vm_i64};
use crate::VirtualMachineResult;
use stoffel_vm_types::core_types::Value;

pub(crate) fn register(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    register_engine_info(vm)?;
    register_local_randomness(vm)?;
    Ok(())
}

fn register_engine_info(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    vm.try_register_typed_foreign_function("Mpc.party_id", |ctx| {
        let info = ctx.require_mpc_runtime_info()?;
        Ok(Value::I64(usize_to_vm_i64(info.party().id(), "party_id")?))
    })?;

    vm.try_register_typed_foreign_function("Mpc.n_parties", |ctx| {
        let info = ctx.require_mpc_runtime_info()?;
        Ok(Value::I64(usize_to_vm_i64(
            info.party_count().count(),
            "n_parties",
        )?))
    })?;

    vm.try_register_typed_foreign_function("Mpc.threshold", |ctx| {
        let info = ctx.require_mpc_runtime_info()?;
        Ok(Value::I64(usize_to_vm_i64(
            info.threshold_param().value(),
            "threshold",
        )?))
    })?;

    vm.try_register_typed_foreign_function("Mpc.is_ready", |ctx| {
        let ready = ctx
            .mpc_runtime_info()
            .map(|info| info.is_ready())
            .unwrap_or(false);
        Ok(Value::Bool(ready))
    })?;

    vm.try_register_typed_foreign_function("Mpc.instance_id", |ctx| {
        let info = ctx.require_mpc_runtime_info()?;
        Ok(Value::I64(u64_to_vm_i64(
            info.instance().id(),
            "instance_id",
        )?))
    })?;

    vm.try_register_typed_foreign_function("Mpc.protocol_name", |ctx| {
        let info = ctx.require_mpc_runtime_info()?;
        Ok(Value::String(info.protocol_name().to_owned()))
    })?;

    vm.try_register_typed_foreign_function("Mpc.curve", |ctx| {
        let info = ctx.require_mpc_runtime_info()?;
        Ok(Value::String(info.curve_config().name().to_owned()))
    })?;

    vm.try_register_typed_foreign_function("Mpc.field", |ctx| {
        let info = ctx.require_mpc_runtime_info()?;
        Ok(Value::String(info.field_kind().name().to_owned()))
    })?;

    vm.try_register_typed_foreign_function("Mpc.has_capability", |ctx| {
        let args = ctx.named_args("Mpc.has_capability");
        args.require_exact(1, "1 argument: capability")?;
        let capability =
            MpcCapability::parse_name(args.string(0, "capability")?).map_err(String::from)?;
        let info = ctx.require_mpc_runtime_info()?;
        Ok(Value::Bool(info.has_capability(capability)))
    })?;

    vm.try_register_typed_foreign_function("Mpc.capabilities", |mut ctx| {
        let info = ctx.require_mpc_runtime_info()?;
        let values = info
            .capabilities()
            .iter_supported()
            .map(|capability| Value::String(capability.as_str().to_owned()))
            .collect::<Vec<_>>();
        let array_ref = ctx.create_array_ref(values.len())?;
        ctx.push_array_ref_values(array_ref, &values)?;
        Ok(Value::from(array_ref))
    })?;

    Ok(())
}

fn register_local_randomness(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    vm.try_register_typed_foreign_function("Mpc.rand", |mut ctx| {
        use rand::RngCore;
        let mut bytes = vec![0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        ctx.create_byte_array(&bytes)
    })?;

    vm.try_register_typed_foreign_function("Mpc.rand_int", |ctx| {
        use rand::Rng;
        let args = ctx.named_args("Mpc.rand_int");
        args.require_exact(1, "1 argument: bit_length (8, 16, 32, or 64)")?;

        let bit_length = args.usize(0, "bit_length")?;
        if bit_length == 0 {
            return Err("bit_length must be a positive integer".into());
        }

        let mut rng = rand::rng();
        match bit_length {
            8 => Ok(Value::U8(rng.random())),
            16 => Ok(Value::U16(rng.random())),
            32 => Ok(Value::U32(rng.random())),
            64 => Ok(Value::U64(rng.random())),
            _ => Err(format!(
                "Unsupported bit_length {}. Must be 8, 16, 32, or 64",
                bit_length
            )
            .into()),
        }
    })?;

    Ok(())
}
