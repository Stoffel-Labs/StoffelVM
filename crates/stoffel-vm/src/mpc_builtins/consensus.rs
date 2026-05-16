use crate::core_vm::VirtualMachine;
use crate::foreign_functions::MpcOnlineBuiltin;
use crate::net::mpc_engine::{AbaSessionId, MpcPartyId};
use crate::value_conversions::{u64_to_vm_i64, usize_to_vm_i64};
use crate::VirtualMachineResult;
use stoffel_vm_types::core_types::Value;

pub(crate) fn register_rbc(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    vm.try_register_mpc_online_foreign_function(MpcOnlineBuiltin::RbcBroadcast, |ctx| {
        let args = ctx.named_args("Rbc.broadcast");
        args.require_exact(1, "1 argument: message")?;
        let message_bytes = args.string(0, "Message")?.as_bytes().to_vec();

        let session_id = ctx.rbc_broadcast(&message_bytes)?;
        Ok(Value::I64(u64_to_vm_i64(session_id.id(), "session_id")?))
    })?;

    vm.try_register_mpc_online_foreign_function(MpcOnlineBuiltin::RbcReceive, |ctx| {
        let args = ctx.named_args("Rbc.receive");
        args.require_min(2, "2 arguments: from_party, timeout_ms")?;

        let from_party = args.usize(0, "from_party")?;
        let timeout_ms = args.u64(1, "timeout_ms")?;

        let message = ctx.rbc_receive_from(MpcPartyId::new(from_party), timeout_ms)?;
        Ok(Value::String(
            String::from_utf8(message).unwrap_or_else(|_| "<binary data>".to_string()),
        ))
    })?;

    vm.try_register_mpc_online_foreign_function(MpcOnlineBuiltin::RbcReceiveAny, |mut ctx| {
        let timeout_ms = {
            let args = ctx.named_args("Rbc.receive_any");
            args.require_exact(1, "1 argument: timeout_ms")?;
            args.u64(0, "timeout_ms")?
        };

        let (party_id, message) = ctx.rbc_receive_any(timeout_ms)?;

        ctx.create_object_with_fields([
            (
                Value::String("party_id".to_string()),
                Value::I64(usize_to_vm_i64(party_id.id(), "party_id")?),
            ),
            (
                Value::String("message".to_string()),
                Value::String(
                    String::from_utf8(message).unwrap_or_else(|_| "<binary>".to_string()),
                ),
            ),
        ])
    })?;

    Ok(())
}

pub(crate) fn register_aba(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    vm.try_register_mpc_online_foreign_function(MpcOnlineBuiltin::AbaPropose, |ctx| {
        let args = ctx.named_args("Aba.propose");
        args.require_exact(1, "1 argument: value (bool)")?;
        let value = args.bool(0, "value")?;

        let session_id = ctx.aba_propose(value)?;
        Ok(Value::I64(u64_to_vm_i64(session_id.id(), "session_id")?))
    })?;

    vm.try_register_mpc_online_foreign_function(MpcOnlineBuiltin::AbaResult, |ctx| {
        let args = ctx.named_args("Aba.result");
        args.require_min(2, "2 arguments: session_id, timeout_ms")?;

        let session_id = args.u64(0, "session_id")?;
        let timeout_ms = args.u64(1, "timeout_ms")?;

        let result = ctx.aba_result(AbaSessionId::new(session_id), timeout_ms)?;
        Ok(Value::Bool(result))
    })?;

    vm.try_register_mpc_online_foreign_function(MpcOnlineBuiltin::AbaProposeAndWait, |ctx| {
        let args = ctx.named_args("Aba.propose_and_wait");
        args.require_min(2, "2 arguments: value (bool), timeout_ms")?;

        let value = args.bool(0, "value")?;
        let timeout_ms = args.u64(1, "timeout_ms")?;

        let result = ctx.aba_propose_and_wait(value, timeout_ms)?;
        Ok(Value::Bool(result))
    })?;

    Ok(())
}
