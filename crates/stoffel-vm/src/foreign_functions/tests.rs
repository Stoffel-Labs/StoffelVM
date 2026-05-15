use super::*;
use crate::net::curve::MpcFieldKind;
use crate::net::mpc_engine::{
    AbaSessionId, MpcCapabilities, MpcEngine, MpcEngineConsensus, MpcEngineResult, MpcPartyId,
    MpcSessionTopology, RbcSessionId,
};
use crate::vm_state::VMState;
use std::sync::Arc;
use stoffel_vm_types::core_types::{
    ArrayRef, ClearShareInput, ClearShareValue, ObjectRef, ShareData, ShareType, TableMemoryError,
    TableRef, Value,
};

struct NotReadyEngine;

impl MpcEngine for NotReadyEngine {
    fn protocol_name(&self) -> &'static str {
        "not-ready"
    }

    fn topology(&self) -> MpcSessionTopology {
        MpcSessionTopology::try_new(0, 0, 3, 1).expect("test topology should be valid")
    }

    fn is_ready(&self) -> bool {
        false
    }

    fn start(&self) -> crate::net::mpc_engine::MpcEngineResult<()> {
        Ok(())
    }

    fn input_share(
        &self,
        _clear: ClearShareInput,
    ) -> crate::net::mpc_engine::MpcEngineResult<ShareData> {
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "test_mpc_engine",
            "not implemented",
        ))
    }

    fn open_share(
        &self,
        _ty: ShareType,
        _share_bytes: &[u8],
    ) -> crate::net::mpc_engine::MpcEngineResult<ClearShareValue> {
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "test_mpc_engine",
            "not implemented",
        ))
    }

    fn field_kind(&self) -> MpcFieldKind {
        MpcFieldKind::Bls12_381Fr
    }
}

struct ReadyConsensusEngine;

impl MpcEngine for ReadyConsensusEngine {
    fn protocol_name(&self) -> &'static str {
        "ready-consensus"
    }

    fn topology(&self) -> MpcSessionTopology {
        MpcSessionTopology::try_new(7, 1, 4, 1).expect("test topology should be valid")
    }

    fn is_ready(&self) -> bool {
        true
    }

    fn start(&self) -> crate::net::mpc_engine::MpcEngineResult<()> {
        Ok(())
    }

    fn input_share(
        &self,
        _clear: ClearShareInput,
    ) -> crate::net::mpc_engine::MpcEngineResult<ShareData> {
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "test_mpc_engine",
            "not implemented",
        ))
    }

    fn open_share(
        &self,
        _ty: ShareType,
        _share_bytes: &[u8],
    ) -> crate::net::mpc_engine::MpcEngineResult<ClearShareValue> {
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "test_mpc_engine",
            "not implemented",
        ))
    }

    fn field_kind(&self) -> MpcFieldKind {
        MpcFieldKind::Bls12_381Fr
    }

    fn capabilities(&self) -> MpcCapabilities {
        MpcCapabilities::CONSENSUS
    }

    fn as_consensus(&self) -> Option<&dyn MpcEngineConsensus> {
        Some(self)
    }
}

impl MpcEngineConsensus for ReadyConsensusEngine {
    fn rbc_broadcast(&self, message: &[u8]) -> MpcEngineResult<RbcSessionId> {
        Ok(RbcSessionId::new(message.len() as u64))
    }

    fn rbc_receive(&self, from_party: MpcPartyId, timeout_ms: u64) -> MpcEngineResult<Vec<u8>> {
        Ok(format!("{from_party}:{timeout_ms}").into_bytes())
    }

    fn rbc_receive_any(&self, timeout_ms: u64) -> MpcEngineResult<(MpcPartyId, Vec<u8>)> {
        Ok((self.party(), timeout_ms.to_be_bytes().to_vec()))
    }

    fn aba_propose(&self, value: bool) -> MpcEngineResult<AbaSessionId> {
        Ok(AbaSessionId::new(if value { 11 } else { 22 }))
    }

    fn aba_result(&self, session_id: AbaSessionId, timeout_ms: u64) -> MpcEngineResult<bool> {
        Ok(session_id.id() + timeout_ms == 33)
    }
}

#[test]
fn foreign_function_call_errors_include_function_name() {
    let function = ForeignFunction::new(
        "native.fail",
        Arc::new(|_| Err(ForeignFunctionCallbackError::from("argument mismatch"))),
    );
    let mut vm_state = VMState::new();
    let args = [];
    let context = ForeignFunctionContext::new(&args, &mut vm_state);

    let err = function.call(context).unwrap_err();

    assert_eq!(
        err,
        ForeignFunctionError::CallbackFailed {
            function: "native.fail".to_string(),
            source: ForeignFunctionCallbackError::from("argument mismatch"),
        }
    );
    assert_eq!(
        err.to_string(),
        "Foreign function native.fail failed: argument mismatch"
    );
}

#[test]
fn foreign_context_reports_typed_mpc_configuration_errors() {
    let mut vm_state = VMState::new();
    let args = [];
    let context = ForeignFunctionContext::new(&args, &mut vm_state);

    let err = match context.require_mpc_runtime_info() {
        Err(err) => err,
        Ok(_) => panic!("MPC engine should be missing"),
    };
    assert!(matches!(err, crate::error::VmError::MpcEngineNotConfigured));

    vm_state.set_mpc_engine(Arc::new(NotReadyEngine));
    let context = ForeignFunctionContext::new(&args, &mut vm_state);

    let err = match context.rbc_broadcast(b"not ready") {
        Err(err) => err,
        Ok(_) => panic!("MPC engine should not be ready"),
    };
    assert!(matches!(err, crate::error::VmError::MpcEngineNotReady));
}

#[test]
fn foreign_context_centralizes_consensus_operations() {
    let mut vm_state = VMState::new();
    vm_state.set_mpc_engine(Arc::new(ReadyConsensusEngine));
    let args = [];
    let context = ForeignFunctionContext::new(&args, &mut vm_state);

    assert_eq!(
        context.rbc_broadcast(b"vm").expect("broadcast"),
        RbcSessionId::new(2)
    );
    assert_eq!(
        context
            .rbc_receive_from(MpcPartyId::new(3), 40)
            .expect("receive"),
        b"3:40".to_vec()
    );
    assert_eq!(
        context.rbc_receive_any(19).expect("receive any"),
        (MpcPartyId::new(1), 19u64.to_be_bytes().to_vec())
    );
    assert_eq!(
        context.aba_propose(true).expect("propose"),
        AbaSessionId::new(11)
    );
    assert!(context
        .aba_result(AbaSessionId::new(11), 22)
        .expect("result"));
    assert!(!context
        .aba_propose_and_wait(false, 10)
        .expect("propose and wait"));
}

#[test]
fn foreign_context_table_reads_use_callback_error_surface() {
    let mut vm_state = VMState::new();
    let args = [];
    let mut context = ForeignFunctionContext::new(&args, &mut vm_state);

    let err = context
        .read_table_field(TableRef::object(999), &Value::I64(0))
        .expect_err("missing object should report table memory error");

    assert_eq!(
        err,
        ForeignFunctionCallbackError::TableMemory(TableMemoryError::ObjectNotFound { id: 999 })
    );
}

#[test]
fn foreign_arguments_centralize_arity_and_type_checks() {
    let mut vm_state = VMState::new();
    let values = [
        Value::String("alice".to_string()),
        Value::I64(7),
        Value::from(ArrayRef::new(3)),
        Value::from(ObjectRef::new(4)),
    ];
    let context = ForeignFunctionContext::new(&values, &mut vm_state);
    let args = context.named_args("Example.call");

    args.require_exact(4, "4 arguments: name, index, array, object")
        .expect("arity");
    assert_eq!(args.string(0, "name").expect("string"), "alice");
    assert_eq!(args.cloned_string(0, "name").expect("cloned"), "alice");
    assert_eq!(args.usize(1, "index").expect("usize"), 7);
    assert_eq!(args.u64(1, "index").expect("u64"), 7);
    assert_eq!(args.array_ref(2, "array").expect("array").id(), 3);
    assert_eq!(args.array_id(2, "array").expect("array id"), 3);
    assert_eq!(args.object_ref(3, "object").expect("object").id(), 4);

    let err = args
        .require_min(5, "at least 5 arguments")
        .expect_err("arity error");
    assert_eq!(err.to_string(), "Example.call expects at least 5 arguments");

    let err = args.string(1, "name").expect_err("type error");
    assert_eq!(err.to_string(), "name must be a string");
}
