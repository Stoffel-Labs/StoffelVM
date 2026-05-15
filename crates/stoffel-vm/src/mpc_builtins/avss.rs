use crate::core_vm::VirtualMachine;
use crate::value_conversions::usize_to_vm_i64;
use crate::VirtualMachineResult;
use stoffel_vm_types::core_types::Value;

pub(crate) fn register(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    register_get_commitment(vm)?;
    register_get_key_name(vm)?;
    register_commitment_count(vm)?;
    register_is_avss_share(vm)?;
    Ok(())
}

fn register_get_commitment(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    vm.try_register_typed_foreign_function("Avss.get_commitment", |mut ctx| {
        let (share, index) = {
            let args = ctx.named_args("Avss.get_commitment");
            args.require_min(2, "2 arguments: avss_share, index")?;
            (args.cloned(0)?, args.usize(1, "index")?)
        };

        if !ctx.is_avss_share_object(&share) {
            return Err("First argument must be an AVSS share object".into());
        }

        let commitment_bytes = ctx.avss_commitment(&share, index)?;

        ctx.create_byte_array(&commitment_bytes)
    })?;

    Ok(())
}

fn register_get_key_name(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    vm.try_register_typed_foreign_function("Avss.get_key_name", |mut ctx| {
        let share = {
            let args = ctx.named_args("Avss.get_key_name");
            args.require_exact(1, "1 argument: avss_share")?;
            args.cloned(0)?
        };

        if !ctx.is_avss_share_object(&share) {
            return Err("Argument must be an AVSS share object".into());
        }

        let key_name = ctx.avss_key_name(&share)?;
        Ok(Value::String(key_name))
    })?;

    Ok(())
}

fn register_commitment_count(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    vm.try_register_typed_foreign_function("Avss.commitment_count", |mut ctx| {
        let share = {
            let args = ctx.named_args("Avss.commitment_count");
            args.require_exact(1, "1 argument: avss_share")?;
            args.cloned(0)?
        };

        if !ctx.is_avss_share_object(&share) {
            return Err("Argument must be an AVSS share object".into());
        }

        let count = ctx.avss_commitment_count(&share)?;
        Ok(Value::I64(usize_to_vm_i64(count, "commitment count")?))
    })?;

    Ok(())
}

fn register_is_avss_share(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    vm.try_register_typed_foreign_function("Avss.is_avss_share", |mut ctx| {
        let value = {
            let args = ctx.named_args("Avss.is_avss_share");
            args.require_exact(1, "1 argument: value")?;
            args.cloned(0)?
        };

        let is_avss = ctx.is_avss_share_object(&value);
        Ok(Value::Bool(is_avss))
    })?;

    Ok(())
}
