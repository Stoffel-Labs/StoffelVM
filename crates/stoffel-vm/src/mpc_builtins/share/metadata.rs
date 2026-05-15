use crate::core_vm::VirtualMachine;
use crate::foreign_functions::{ForeignFunctionCallbackResult, ForeignFunctionContext};
use crate::value_conversions::{usize_to_vm_i64, value_to_usize};
use crate::VirtualMachineResult;
use stoffel_vm_types::core_types::{ObjectRef, ShareType, Value};

pub(super) fn register(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    vm.try_register_typed_foreign_function("Share.get_type", share_get_type)?;
    vm.try_register_typed_foreign_function("Share.get_party_id", share_get_party_id)?;
    vm.try_register_typed_foreign_function("Share.get_commitment", share_get_commitment)?;
    vm.try_register_typed_foreign_function("Share.commitment_count", share_commitment_count)?;
    vm.try_register_typed_foreign_function("Share.has_commitments", share_has_commitments)?;
    Ok(())
}

fn share_get_type(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let share_value = {
        let args = ctx.named_args("Share.get_type");
        args.require_exact(1, "1 argument: share")?;
        args.cloned(0)?
    };

    let ty = ctx.get_share_type(&share_value)?;
    let type_str = match ty {
        ShareType::SecretInt { .. } => "SecretInt",
        ShareType::SecretFixedPoint { .. } => "SecretFixedPoint",
    };

    Ok(Value::String(type_str.to_string()))
}

fn share_get_party_id(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let share_value = {
        let args = ctx.named_args("Share.get_party_id");
        args.require_exact(1, "1 argument: share")?;
        args.cloned(0)?
    };

    match &share_value {
        value if ObjectRef::from_value(value).is_some() => {
            let Some(party_id) = ctx.get_share_party_id(&share_value)? else {
                return Err("Share object missing __party_id metadata".into());
            };
            Ok(Value::I64(usize_to_vm_i64(party_id, "party_id")?))
        }
        Value::Share(_, _) => {
            let party_id = ctx.require_mpc_runtime_info()?.party().id();
            Ok(Value::I64(usize_to_vm_i64(party_id, "party_id")?))
        }
        _ => Err("Expected Share object".into()),
    }
}

fn share_get_commitment(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let (share_data, index) = {
        let (share_value, index_value) = {
            let args = ctx.named_args("Share.get_commitment");
            args.require_min(2, "2 arguments: share, index")?;
            (args.cloned(0)?, args.cloned(1)?)
        };
        let (_, share_data) = ctx.extract_share_data(&share_value)?;
        let index = value_to_usize(&index_value, "index")?;
        (share_data, index)
    };
    let commitments = share_data
        .commitments()
        .ok_or("Share does not have Feldman commitments (requires AVSS backend)")?;
    let commitment = commitments.get(index).ok_or_else(|| {
        format!(
            "Commitment index {} out of bounds (have {})",
            index,
            commitments.len()
        )
    })?;
    ctx.create_byte_array(commitment)
}

fn share_commitment_count(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let share_value = {
        let args = ctx.named_args("Share.commitment_count");
        args.require_exact(1, "1 argument: share")?;
        args.cloned(0)?
    };
    let (_, share_data) = ctx.extract_share_data(&share_value)?;
    match share_data.commitments() {
        Some(commitments) => Ok(Value::I64(usize_to_vm_i64(
            commitments.len(),
            "commitment count",
        )?)),
        None => Ok(Value::I64(0)),
    }
}

fn share_has_commitments(mut ctx: ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> {
    let share_value = {
        let args = ctx.named_args("Share.has_commitments");
        args.require_exact(1, "1 argument: share")?;
        args.cloned(0)?
    };
    let (_, share_data) = ctx.extract_share_data(&share_value)?;
    Ok(Value::Bool(share_data.has_commitments()))
}
