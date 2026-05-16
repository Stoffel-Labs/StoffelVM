use super::*;
use crate::core_vm::VirtualMachine;
use crate::error::VirtualMachineErrorKind;
use crate::error::VmError;
use crate::foreign_functions::{ForeignFunction, ForeignFunctionCallbackError, Function};
use crate::net::client_store::{ClientOutputShareCount, ClientShare, ClientShareIndex};
use crate::net::curve::{MpcCurveConfig, MpcFieldKind};
use crate::net::mpc_engine::{
    AsyncMpcEngine, MpcCapabilities, MpcEngine, MpcEngineClientOutput, MpcEngineResult,
    MpcSessionTopology,
};
use crate::net::reveal_batcher::RevealBatcher;
use crate::reveal_destination::{FrameDepth, RevealDestination};
use crate::runtime_hooks::{HookCallTarget, HookEvent, RegisterWritePreviousValue};
use crate::runtime_instruction::{
    RuntimeBinaryOp, RuntimeInstruction, RuntimeRegister, StackOffset,
};
use crate::vm_state::mpc_operation::PendingMpcOperation;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::sync::{Arc, Mutex};
use stoffel_vm_types::activations::CompareFlag;
use stoffel_vm_types::core_types::{
    ClearShareInput, ClearShareValue, Closure, ShareData, ShareType, Value, F64,
};
use stoffel_vm_types::functions::VMFunction;
use stoffel_vm_types::instructions::Instruction;
use stoffel_vm_types::registers::{RegisterFile, RegisterIndex, RegisterMoveKind};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelnet::network_utils::ClientId;

struct DummyFieldEngine;

fn frame_depth(depth: usize) -> FrameDepth {
    FrameDepth::new(depth)
}

const fn r(index: usize) -> RegisterIndex {
    RegisterIndex::new(index)
}

fn test_topology(instance_id: u64) -> MpcSessionTopology {
    MpcSessionTopology::try_new(instance_id, 0, 3, 1).expect("test topology should be valid")
}

fn runtime_reg(index: usize, register_count: usize) -> RuntimeRegister {
    RuntimeRegister::try_new(index, register_count).expect("test register should fit frame")
}

fn reveal_destination(depth: usize, register: usize) -> RevealDestination {
    RevealDestination::new(frame_depth(depth), runtime_reg(register, register + 1))
}

#[test]
fn call_stack_checkpoint_keeps_typed_frame_depth_boundary() {
    let checkpoint = CallStackCheckpoint::new(2);

    assert_eq!(checkpoint.frame_depth_floor(), FrameDepth::new(2));
    assert!(!checkpoint.has_active_frame(2));
    assert!(checkpoint.has_active_frame(3));
    assert!(checkpoint.is_current_depth(2));
    assert!(checkpoint.is_returning_from_entry_frame(3));
    assert!(!checkpoint.is_returning_from_entry_frame(4));
}

#[test]
fn function_registration_clears_vm_local_call_target_cache() {
    let mut vm = VMState::new();
    vm.try_insert_function(Function::foreign(ForeignFunction::new(
        "cached",
        Arc::new(|_| Ok(Value::Unit)),
    )))
    .expect("register cached function");

    let _ = vm.call_target("cached").expect("resolve call target");
    assert!(vm.last_call_target.is_some());

    vm.try_insert_function(Function::foreign(ForeignFunction::new(
        "new_function",
        Arc::new(|_| Ok(Value::Unit)),
    )))
    .expect("register new function");
    assert!(vm.last_call_target.is_none());
}

impl MpcEngine for DummyFieldEngine {
    fn protocol_name(&self) -> &'static str {
        "dummy"
    }
    fn topology(&self) -> MpcSessionTopology {
        test_topology(0)
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
    fn shutdown(&self) {}
    fn field_kind(&self) -> MpcFieldKind {
        MpcFieldKind::Bls12_381Fr
    }
}

#[derive(Default)]
struct MockBatchEngine {
    calls: Mutex<Vec<(ShareType, usize)>>,
    share_batches: Mutex<Vec<(ShareType, Vec<Vec<u8>>)>>,
}

impl MpcEngine for MockBatchEngine {
    fn protocol_name(&self) -> &'static str {
        "mock-batch"
    }
    fn topology(&self) -> MpcSessionTopology {
        test_topology(0)
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
    fn batch_open_shares(
        &self,
        ty: ShareType,
        shares: &[Vec<u8>],
    ) -> crate::net::mpc_engine::MpcEngineResult<Vec<ClearShareValue>> {
        self.calls.lock().unwrap().push((ty, shares.len()));
        self.share_batches
            .lock()
            .unwrap()
            .push((ty, shares.to_vec()));
        let values = shares
            .iter()
            .map(|bytes| match ty {
                ShareType::SecretInt { .. } => {
                    ClearShareValue::Integer(bytes.first().copied().unwrap_or(0) as i64)
                }
                ShareType::SecretFixedPoint { .. } => {
                    ClearShareValue::FixedPoint(F64(
                        bytes.first().copied().unwrap_or(0) as f64 + 0.5
                    ))
                }
            })
            .collect();
        Ok(values)
    }
    fn shutdown(&self) {}
    fn field_kind(&self) -> MpcFieldKind {
        MpcFieldKind::Bls12_381Fr
    }
}

struct ShortBatchEngine;

impl MpcEngine for ShortBatchEngine {
    fn protocol_name(&self) -> &'static str {
        "short-batch"
    }
    fn topology(&self) -> MpcSessionTopology {
        test_topology(0)
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
    fn batch_open_shares(
        &self,
        _ty: ShareType,
        _shares: &[Vec<u8>],
    ) -> crate::net::mpc_engine::MpcEngineResult<Vec<ClearShareValue>> {
        Ok(vec![])
    }
    fn field_kind(&self) -> MpcFieldKind {
        MpcFieldKind::Bls12_381Fr
    }
}

struct FailingBatchEngine;

impl MpcEngine for FailingBatchEngine {
    fn protocol_name(&self) -> &'static str {
        "failing-batch"
    }
    fn topology(&self) -> MpcSessionTopology {
        test_topology(0)
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
    fn batch_open_shares(
        &self,
        _ty: ShareType,
        _shares: &[Vec<u8>],
    ) -> crate::net::mpc_engine::MpcEngineResult<Vec<ClearShareValue>> {
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "batch_open_shares",
            "backend unavailable",
        ))
    }
    fn field_kind(&self) -> MpcFieldKind {
        MpcFieldKind::Bls12_381Fr
    }
}

#[derive(Default)]
struct MockConversionEngine {
    input_calls: Mutex<Vec<(ShareType, Value)>>,
}

impl MpcEngine for MockConversionEngine {
    fn protocol_name(&self) -> &'static str {
        "mock-conversion"
    }
    fn topology(&self) -> MpcSessionTopology {
        test_topology(0)
    }
    fn is_ready(&self) -> bool {
        true
    }
    fn start(&self) -> crate::net::mpc_engine::MpcEngineResult<()> {
        Ok(())
    }
    fn input_share(
        &self,
        clear: ClearShareInput,
    ) -> crate::net::mpc_engine::MpcEngineResult<ShareData> {
        self.input_calls
            .lock()
            .unwrap()
            .push((clear.share_type(), clear.into_vm_value()));
        Ok(ShareData::Opaque(vec![42]))
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
    fn shutdown(&self) {}
}

struct AsyncOpenEngine {
    instance_id: u64,
    curve_config: MpcCurveConfig,
    field_kind: MpcFieldKind,
    input_calls: Mutex<Vec<(ShareType, Value)>>,
    open_calls: Mutex<Vec<(ShareType, Vec<u8>)>>,
}

impl AsyncOpenEngine {
    fn new(instance_id: u64) -> Self {
        Self::with_field_kind(instance_id, MpcFieldKind::Bls12_381Fr)
    }

    fn with_field_kind(instance_id: u64, field_kind: MpcFieldKind) -> Self {
        let curve_config = match field_kind {
            MpcFieldKind::Bls12_381Fr => MpcCurveConfig::Bls12_381,
            MpcFieldKind::Bn254Fr => MpcCurveConfig::Bn254,
            MpcFieldKind::Curve25519Fr => MpcCurveConfig::Curve25519,
        };
        Self::with_curve_config_and_field_kind(instance_id, curve_config, field_kind)
    }

    fn with_curve_config(instance_id: u64, curve_config: MpcCurveConfig) -> Self {
        Self::with_curve_config_and_field_kind(instance_id, curve_config, curve_config.field_kind())
    }

    fn with_curve_config_and_field_kind(
        instance_id: u64,
        curve_config: MpcCurveConfig,
        field_kind: MpcFieldKind,
    ) -> Self {
        Self {
            instance_id,
            curve_config,
            field_kind,
            input_calls: Mutex::new(Vec::new()),
            open_calls: Mutex::new(Vec::new()),
        }
    }
}

impl Default for AsyncOpenEngine {
    fn default() -> Self {
        Self::new(0)
    }
}

impl MpcEngine for AsyncOpenEngine {
    fn protocol_name(&self) -> &'static str {
        "async-open"
    }
    fn topology(&self) -> MpcSessionTopology {
        test_topology(self.instance_id)
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
            "input_share",
            "sync input_share should not be used by async execution",
        ))
    }
    fn open_share(
        &self,
        _ty: ShareType,
        _share_bytes: &[u8],
    ) -> crate::net::mpc_engine::MpcEngineResult<ClearShareValue> {
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "open_share",
            "sync open_share should not be used by async execution",
        ))
    }
    fn shutdown(&self) {}
    fn curve_config(&self) -> MpcCurveConfig {
        self.curve_config
    }
    fn field_kind(&self) -> MpcFieldKind {
        self.field_kind
    }
}

#[async_trait::async_trait]
impl AsyncMpcEngine for AsyncOpenEngine {
    async fn input_share_async(
        &self,
        clear: ClearShareInput,
    ) -> crate::net::mpc_engine::MpcEngineResult<ShareData> {
        self.input_calls
            .lock()
            .unwrap()
            .push((clear.share_type(), clear.into_vm_value()));
        Ok(ShareData::Opaque(vec![42]))
    }

    async fn open_share_async(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
    ) -> crate::net::mpc_engine::MpcEngineResult<ClearShareValue> {
        self.open_calls
            .lock()
            .unwrap()
            .push((ty, share_bytes.to_vec()));
        Ok(ClearShareValue::Integer(99))
    }
}

#[derive(Default)]
struct OutputRecordingEngine {
    calls: Mutex<Vec<(ClientId, Vec<u8>, ClientOutputShareCount)>>,
}

impl MpcEngine for OutputRecordingEngine {
    fn protocol_name(&self) -> &'static str {
        "output-recording"
    }
    fn topology(&self) -> MpcSessionTopology {
        test_topology(0)
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
        MpcCapabilities::CLIENT_OUTPUT
    }
    fn as_client_output(&self) -> Option<&dyn MpcEngineClientOutput> {
        Some(self)
    }
}

impl MpcEngineClientOutput for OutputRecordingEngine {
    fn send_output_to_client(
        &self,
        client_id: ClientId,
        shares: &[u8],
        output_share_count: ClientOutputShareCount,
    ) -> MpcEngineResult<()> {
        self.calls
            .lock()
            .unwrap()
            .push((client_id, shares.to_vec(), output_share_count));
        Ok(())
    }
}

fn encode_test_share_bls(value: i64, id: usize, degree: usize) -> Vec<u8> {
    let share = RobustShare::new(ark_bls12_381::Fr::from(value as u64), id, degree);
    let mut out = Vec::new();
    share
        .serialize_compressed(&mut out)
        .expect("serialize test share");
    out
}

fn vm_with_registers(registers: Vec<Value>) -> VMState {
    let mut vm = VMState::new();
    vm.push_activation_record(ActivationRecord::with_registers(
        "test",
        RegisterFile::from(registers),
        vec![],
        None,
    ));
    vm
}

#[test]
fn create_closure_reports_typed_missing_upvalue_error() {
    let mut vm = vm_with_registers(vec![Value::Unit]);
    let upvalues = vec!["missing".to_string()];

    let err = vm
        .create_closure_value("closure_target".to_string(), &upvalues)
        .expect_err("missing closure upvalue should be typed");

    match err {
        crate::error::VmError::ClosureUpvalueNotFound { name } => {
            assert_eq!(name, "missing");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn get_upvalue_reports_typed_missing_upvalue_error() {
    let vm = vm_with_registers(vec![Value::Unit]);

    let err = vm
        .get_upvalue_value("missing")
        .expect_err("missing upvalue read should be typed");

    match err {
        crate::error::VmError::UpvalueReadNotFound { name } => {
            assert_eq!(name, "missing");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn set_upvalue_reports_typed_missing_upvalue_error() {
    let mut vm = vm_with_registers(vec![Value::Unit]);

    let err = vm
        .set_upvalue_value("missing", Value::I64(1))
        .expect_err("missing upvalue write should be typed");

    match err {
        crate::error::VmError::UpvalueWriteNotFound { name } => {
            assert_eq!(name, "missing");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn secret_share_add_without_engine_returns_error_not_panic() {
    let vm = VMState::new();
    let lhs = encode_test_share_bls(3, 1, 1);
    let rhs = encode_test_share_bls(5, 1, 1);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        vm.secret_share_add(ShareType::secret_int(64), &lhs, &rhs)
    }));

    let call = result.expect("secret_share_add should not panic without MPC engine");
    assert!(call.is_err());
}

#[test]
fn fixed_point_scalar_ops_use_scaled_domain_units() {
    let mut vm = VMState::new();
    vm.set_mpc_engine(Arc::new(DummyFieldEngine));

    let ty = ShareType::default_secret_fixed_point();
    let precision = match ty {
        ShareType::SecretFixedPoint { precision } => precision,
        _ => unreachable!(),
    };

    let base = encode_test_share_bls(0, 1, 1);
    let added = vm
        .secret_share_add_scalar(ty, &base, 1)
        .expect("fixed-point add scalar");
    let added_share = RobustShare::<ark_bls12_381::Fr>::deserialize_compressed(added.as_slice())
        .expect("deserialize added share");

    let scaled_one =
        crate::net::share_algebra::scale_fixed_point_scalar(precision.f(), 1).expect("scaled one");
    assert_eq!(
        added_share.share[0],
        ark_bls12_381::Fr::from(scaled_one as u64),
        "fixed-point add must add one full fixed-point unit, not one LSB"
    );

    let subtracted = vm
        .secret_share_sub_scalar(ty, &added, 1)
        .expect("fixed-point sub scalar");
    let subtracted_share =
        RobustShare::<ark_bls12_381::Fr>::deserialize_compressed(subtracted.as_slice())
            .expect("deserialize subtracted share");
    assert_eq!(
        subtracted_share.share[0],
        ark_bls12_381::Fr::from(0u64),
        "subtracting the same scalar should round-trip to original value"
    );

    let scalar_minus = vm
        .scalar_sub_secret_share(ty, 1, &base)
        .expect("scalar minus fixed-point share");
    let scalar_minus_share =
        RobustShare::<ark_bls12_381::Fr>::deserialize_compressed(scalar_minus.as_slice())
            .expect("deserialize scalar-minus share");
    assert_eq!(
        scalar_minus_share.share[0],
        ark_bls12_381::Fr::from(scaled_one as u64),
        "scalar-share subtraction must use fixed-point scaled scalar"
    );
}

#[test]
fn reveal_batcher_flush_groups_mixed_share_types() {
    let mut batcher = RevealBatcher::new();
    let engine = MockBatchEngine::default();
    let fixed_ty = ShareType::default_secret_fixed_point();

    batcher.queue(
        reveal_destination(0, 1),
        ShareType::secret_int(64),
        ShareData::Opaque(vec![10]),
    );
    batcher.queue(
        reveal_destination(0, 2),
        fixed_ty,
        ShareData::Opaque(vec![7]),
    );
    batcher.queue(
        reveal_destination(0, 3),
        ShareType::secret_int(64),
        ShareData::Opaque(vec![11]),
    );

    let results = batcher
        .flush(frame_depth(0), &engine)
        .expect("mixed flush should succeed");
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].destination(), reveal_destination(0, 1));
    assert_eq!(results[0].value(), &Value::I64(10));
    assert_eq!(results[1].destination(), reveal_destination(0, 2));
    assert_eq!(results[1].value(), &Value::Float(F64(7.5)));
    assert_eq!(results[2].destination(), reveal_destination(0, 3));
    assert_eq!(results[2].value(), &Value::I64(11));

    let calls = engine.calls.lock().unwrap().clone();
    assert_eq!(
        calls.len(),
        2,
        "mixed reveals should be split into two batches"
    );
    assert_eq!(calls[0], (ShareType::secret_int(64), 2));
    assert_eq!(calls[1], (fixed_ty, 1));
}

#[test]
fn reveal_batcher_keeps_structured_share_data_until_backend_flush() {
    let mut batcher = RevealBatcher::new();
    let engine = MockBatchEngine::default();
    let ty = ShareType::secret_int(64);

    batcher.queue(
        reveal_destination(0, 4),
        ty,
        ShareData::Feldman {
            data: vec![21],
            commitments: vec![vec![1, 2, 3]],
        },
    );

    let results = batcher
        .flush(frame_depth(0), &engine)
        .expect("flush should succeed");

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].destination(), reveal_destination(0, 4));
    assert_eq!(results[0].value(), &Value::I64(21));
    assert_eq!(
        engine.share_batches.lock().unwrap().as_slice(),
        &[(ty, vec![vec![21]])]
    );
}

#[test]
fn reveal_batcher_splits_same_type_mixed_share_data_formats() {
    let mut batcher = RevealBatcher::new();
    let engine = MockBatchEngine::default();
    let ty = ShareType::secret_int(64);

    batcher.queue(reveal_destination(0, 1), ty, ShareData::Opaque(vec![10]));
    batcher.queue(
        reveal_destination(0, 2),
        ty,
        ShareData::Feldman {
            data: vec![11],
            commitments: vec![vec![1, 2, 3]],
        },
    );

    let results = batcher
        .flush(frame_depth(0), &engine)
        .expect("flush should succeed");

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].register_index(), 1);
    assert_eq!(results[0].value(), &Value::I64(10));
    assert_eq!(results[1].register_index(), 2);
    assert_eq!(results[1].value(), &Value::I64(11));
    assert_eq!(
        engine.share_batches.lock().unwrap().as_slice(),
        &[(ty, vec![vec![10]]), (ty, vec![vec![11]])]
    );
}

#[test]
fn reveal_batcher_scopes_pending_registers_by_frame_depth() {
    let mut batcher = RevealBatcher::new();
    let engine = MockBatchEngine::default();
    let ty = ShareType::secret_int(64);

    batcher.queue(reveal_destination(0, 1), ty, ShareData::Opaque(vec![10]));
    batcher.queue(reveal_destination(1, 1), ty, ShareData::Opaque(vec![11]));

    assert!(batcher.has_pending_destination(reveal_destination(0, 1)));
    assert!(batcher.has_pending_destination(reveal_destination(1, 1)));

    let callee_results = batcher
        .flush(frame_depth(1), &engine)
        .expect("callee frame flush should succeed");

    assert_eq!(callee_results.len(), 1);
    assert_eq!(callee_results[0].destination(), reveal_destination(1, 1));
    assert_eq!(callee_results[0].value(), &Value::I64(11));
    assert!(batcher.has_pending_destination(reveal_destination(0, 1)));
    assert!(!batcher.has_pending_destination(reveal_destination(1, 1)));

    let caller_results = batcher
        .flush(frame_depth(0), &engine)
        .expect("caller frame flush should succeed");

    assert_eq!(caller_results.len(), 1);
    assert_eq!(caller_results[0].destination(), reveal_destination(0, 1));
    assert_eq!(caller_results[0].value(), &Value::I64(10));
}

#[test]
fn reveal_batcher_queue_replaces_existing_destination() {
    let mut batcher = RevealBatcher::new();
    let engine = MockBatchEngine::default();
    let ty = ShareType::secret_int(64);

    batcher.queue(reveal_destination(0, 1), ty, ShareData::Opaque(vec![10]));
    batcher.queue(reveal_destination(0, 1), ty, ShareData::Opaque(vec![12]));

    let results = batcher
        .flush(frame_depth(0), &engine)
        .expect("flush should succeed");

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].destination(), reveal_destination(0, 1));
    assert_eq!(results[0].value(), &Value::I64(12));
    assert_eq!(engine.calls.lock().unwrap().as_slice(), &[(ty, 1)]);
}

#[test]
fn reveal_batcher_reports_typed_count_mismatch() {
    let mut batcher = RevealBatcher::new();
    batcher.queue(
        reveal_destination(0, 1),
        ShareType::secret_int(64),
        ShareData::Opaque(vec![10]),
    );

    let err = batcher
        .flush(frame_depth(0), &ShortBatchEngine)
        .expect_err("short backend result must be rejected");

    assert_eq!(
        err.to_string(),
        "Batch reveal count mismatch for SecretInt { bit_length: 64 }: got 0, expected 1"
    );
}

#[test]
fn reveal_batcher_wraps_backend_errors_with_share_type_context() {
    let mut batcher = RevealBatcher::new();
    batcher.queue(
        reveal_destination(0, 1),
        ShareType::secret_int(64),
        ShareData::Opaque(vec![10]),
    );

    let err = batcher
        .flush(frame_depth(0), &FailingBatchEngine)
        .expect_err("backend failure should include reveal context");
    let message = err.to_string();

    assert!(
        message.contains("Batch reveal for SecretInt { bit_length: 64 } failed"),
        "unexpected error: {err}"
    );
    assert!(
        message.contains("backend unavailable"),
        "unexpected error: {err}"
    );
}

#[test]
fn replacing_mpc_engine_clears_engine_scoped_runtime_state() {
    let mut vm = VMState::new();
    let ty = ShareType::secret_int(64);

    vm.set_mpc_engine(Arc::new(MockBatchEngine::default()));
    vm.store_client_shares(42, vec![ClientShare::typed(ty, ShareData::Opaque(vec![7]))]);
    vm.mpc_runtime
        .queue_reveal(reveal_destination(0, 1), ty, ShareData::Opaque(vec![9]));

    assert_eq!(vm.client_store_len(), 1);
    assert!(vm
        .mpc_runtime
        .has_pending_reveal_destination(reveal_destination(0, 1)));

    vm.set_mpc_engine(Arc::new(MockBatchEngine::default()));

    assert_eq!(vm.client_store_len(), 0);
    assert!(!vm
        .mpc_runtime
        .has_pending_reveal_destination(reveal_destination(0, 1)));
}

#[test]
fn sync_secret_to_clear_mov_resolves_pending_reveal_on_return() {
    let engine = Arc::new(MockBatchEngine::default());
    let ty = ShareType::secret_int(64);
    let mut vm = VirtualMachine::builder()
        .with_register_layout(RegisterLayout::new(8))
        .with_mpc_engine(engine.clone())
        .build();
    let function = VMFunction::new(
        "sync_reveal_return".to_string(),
        vec![],
        Vec::new(),
        None,
        9,
        vec![
            Instruction::LDI(8, Value::Share(ty, ShareData::Opaque(vec![42]))),
            Instruction::MOV(0, 8),
            Instruction::RET(0),
        ],
        std::collections::HashMap::new(),
    );
    vm.register_function(function);

    let result = vm
        .execute("sync_reveal_return")
        .expect("sync reveal should resolve before return");

    assert_eq!(result, Value::I64(42));
    assert_eq!(engine.calls.lock().unwrap().as_slice(), &[(ty, 1)]);
}

#[test]
fn overwritten_pending_reveal_does_not_clobber_register() {
    let engine = Arc::new(MockBatchEngine::default());
    let ty = ShareType::secret_int(64);
    let mut vm = VirtualMachine::builder()
        .with_register_layout(RegisterLayout::new(8))
        .with_mpc_engine(engine.clone())
        .build();
    let function = VMFunction::new(
        "overwrite_pending_reveal".to_string(),
        vec![],
        Vec::new(),
        None,
        9,
        vec![
            Instruction::LDI(8, Value::Share(ty, ShareData::Opaque(vec![7]))),
            Instruction::MOV(0, 8),
            Instruction::LDI(0, Value::I64(5)),
            Instruction::RET(0),
        ],
        std::collections::HashMap::new(),
    );
    vm.register_function(function);

    let result = vm
        .execute("overwrite_pending_reveal")
        .expect("overwritten reveal should not clobber destination");

    assert_eq!(result, Value::I64(5));
    assert!(
        engine.calls.lock().unwrap().is_empty(),
        "stale pending reveal should be cancelled before it reaches the backend"
    );
}

#[test]
fn binary_instruction_resolves_pending_reveal_before_reading_operand() {
    let engine = Arc::new(MockBatchEngine::default());
    let ty = ShareType::secret_int(64);
    let mut vm = VirtualMachine::builder()
        .with_register_layout(RegisterLayout::new(8))
        .with_mpc_engine(engine.clone())
        .build();
    let function = VMFunction::new(
        "binary_flushes_pending_reveal".to_string(),
        vec![],
        Vec::new(),
        None,
        9,
        vec![
            Instruction::LDI(8, Value::Share(ty, ShareData::Opaque(vec![42]))),
            Instruction::MOV(0, 8),
            Instruction::LDI(1, Value::I64(8)),
            Instruction::ADD(2, 0, 1),
            Instruction::RET(2),
        ],
        std::collections::HashMap::new(),
    );
    vm.register_function(function);

    let result = vm
        .execute("binary_flushes_pending_reveal")
        .expect("binary instruction should resolve queued reveal");

    assert_eq!(result, Value::I64(50));
    assert_eq!(engine.calls.lock().unwrap().as_slice(), &[(ty, 1)]);
}

#[test]
fn mpc_planner_resolves_pending_reveal_before_reading_multiply_operands() {
    let engine = Arc::new(MockBatchEngine::default());
    let ty = ShareType::secret_int(64);
    let mut vm = VMState::new();
    vm.set_mpc_engine(engine.clone());
    vm.push_activation_record(ActivationRecord::with_registers(
        "test",
        RegisterFile::with_default_layout(3),
        vec![],
        None,
    ));
    vm.assign_current_register(runtime_reg(1, 3), Value::I64(2))
        .expect("write scalar operand");
    vm.queue_reveal_to_register(
        &Value::Share(ty, ShareData::Opaque(vec![42])),
        runtime_reg(0, 3),
    )
    .expect("queue pending reveal");

    let operation = vm
        .plan_async_mpc_operation(
            &RuntimeInstruction::Binary {
                op: RuntimeBinaryOp::Multiply,
                dest: runtime_reg(2, 3),
                lhs: runtime_reg(0, 3),
                rhs: runtime_reg(1, 3),
            },
            false,
        )
        .expect("planner should resolve pending operands");

    assert!(
        operation.is_none(),
        "clear multiply after reveal should not require async MPC work"
    );
    assert_eq!(engine.calls.lock().unwrap().as_slice(), &[(ty, 1)]);
    assert_eq!(
        vm.current_activation_record()
            .expect("current frame")
            .register(r(0)),
        Some(&Value::I64(42))
    );
}

#[test]
fn vm_call_preserves_caller_pending_reveals_across_frame_switch() {
    let engine = Arc::new(MockBatchEngine::default());
    let ty = ShareType::secret_int(64);
    let mut vm = VirtualMachine::builder()
        .with_register_layout(RegisterLayout::new(8))
        .with_mpc_engine(engine.clone())
        .build();
    let main = VMFunction::new(
        "flush_before_call".to_string(),
        vec![],
        Vec::new(),
        None,
        9,
        vec![
            Instruction::LDI(8, Value::Share(ty, ShareData::Opaque(vec![42]))),
            Instruction::MOV(1, 8),
            Instruction::CALL("callee_writes_same_register".to_string()),
            Instruction::RET(1),
        ],
        std::collections::HashMap::new(),
    );
    let callee = VMFunction::new(
        "callee_writes_same_register".to_string(),
        vec![],
        Vec::new(),
        None,
        2,
        vec![Instruction::LDI(1, Value::I64(99)), Instruction::RET(0)],
        std::collections::HashMap::new(),
    );
    vm.register_function(main);
    vm.register_function(callee);

    let result = vm
        .execute("flush_before_call")
        .expect("caller reveal should survive callee frame switch");

    assert_eq!(result, Value::I64(42));
    assert_eq!(engine.calls.lock().unwrap().as_slice(), &[(ty, 1)]);
}

#[test]
fn closure_call_preserves_caller_pending_reveals_across_frame_switch() {
    let engine = Arc::new(MockBatchEngine::default());
    let ty = ShareType::secret_int(64);
    let mut vm = VMState::new();
    vm.set_register_layout(RegisterLayout::new(8));
    vm.set_mpc_engine(engine.clone());
    let callee = VMFunction::new(
        "closure_callee_writes_same_register".to_string(),
        vec![],
        Vec::new(),
        None,
        2,
        vec![Instruction::LDI(1, Value::I64(99)), Instruction::RET(0)],
        std::collections::HashMap::new(),
    );
    vm.try_insert_function(Function::vm(callee))
        .expect("register callee");

    let mut registers = RegisterFile::new(RegisterLayout::new(8), 9);
    *registers.get_mut(r(8)).expect("secret register r8") =
        Value::Share(ty, ShareData::Opaque(vec![42]));
    vm.push_activation_record(ActivationRecord::with_registers(
        "caller",
        registers,
        vec![],
        None,
    ));
    vm.execute_mov(runtime_reg(1, 9), runtime_reg(8, 9), false)
        .expect("queue caller reveal");
    let closure = Value::Closure(Arc::new(Closure::new(
        "closure_callee_writes_same_register".to_string(),
        Vec::new(),
    )));

    vm.call_closure_value(&closure, &[], false)
        .expect("closure call should preserve caller reveal before pushing callee");
    vm.execute_until_return_to_depth(CallStackCheckpoint::new(1))
        .expect("callee should return to caller");
    vm.resolve_register(runtime_reg(1, 9))
        .expect("observing caller register should flush reveal");

    assert_eq!(
        vm.current_activation_record()
            .expect("caller frame")
            .register(r(1)),
        Some(&Value::I64(42))
    );
    assert_eq!(engine.calls.lock().unwrap().as_slice(), &[(ty, 1)]);
}

#[test]
fn foreign_call_does_not_eagerly_open_caller_pending_reveal() {
    let engine = Arc::new(MockBatchEngine::default());
    let ty = ShareType::secret_int(64);
    let mut vm = VirtualMachine::builder()
        .with_register_layout(RegisterLayout::new(8))
        .with_mpc_engine(engine.clone())
        .build();
    let engine_for_foreign = Arc::clone(&engine);
    vm.register_foreign_function("assert_no_open_yet", move |_ctx| {
        if !engine_for_foreign.calls.lock().unwrap().is_empty() {
            return Err("caller reveal opened before foreign call".to_string());
        }
        Ok(Value::Unit)
    });
    let function = VMFunction::new(
        "preserve_pending_reveal_across_foreign_call".to_string(),
        vec![],
        Vec::new(),
        None,
        9,
        vec![
            Instruction::LDI(8, Value::Share(ty, ShareData::Opaque(vec![42]))),
            Instruction::MOV(1, 8),
            Instruction::CALL("assert_no_open_yet".to_string()),
            Instruction::RET(1),
        ],
        std::collections::HashMap::new(),
    );
    vm.register_function(function);

    let result = vm
        .execute("preserve_pending_reveal_across_foreign_call")
        .expect("pending caller reveal should survive foreign call");

    assert_eq!(result, Value::I64(42));
    assert_eq!(engine.calls.lock().unwrap().as_slice(), &[(ty, 1)]);
}

#[test]
fn return_discards_unused_pending_reveals_without_opening_them() {
    let engine = Arc::new(MockBatchEngine::default());
    let ty = ShareType::secret_int(64);
    let mut vm = VirtualMachine::builder()
        .with_register_layout(RegisterLayout::new(8))
        .with_mpc_engine(engine.clone())
        .build();
    let function = VMFunction::new(
        "discard_unused_pending_reveal".to_string(),
        vec![],
        Vec::new(),
        None,
        9,
        vec![
            Instruction::LDI(0, Value::I64(5)),
            Instruction::LDI(8, Value::Share(ty, ShareData::Opaque(vec![7]))),
            Instruction::MOV(1, 8),
            Instruction::RET(0),
        ],
        std::collections::HashMap::new(),
    );
    vm.register_function(function);

    let result = vm
        .execute("discard_unused_pending_reveal")
        .expect("unused queued reveal should not affect return");

    assert_eq!(result, Value::I64(5));
    assert!(
        engine.calls.lock().unwrap().is_empty(),
        "unused pending reveal should be discarded without opening a secret"
    );
}

#[test]
fn missing_call_target_does_not_drain_argument_stack() {
    let mut vm = VMState::new();
    vm.push_activation_record(ActivationRecord::with_registers(
        "caller",
        RegisterFile::from(vec![Value::Unit]),
        vec![],
        None,
    ));
    vm.current_frame_mut()
        .expect("caller frame")
        .push_stack(Value::I64(1));
    vm.current_frame_mut()
        .expect("caller frame")
        .push_stack(Value::I64(2));

    let err = vm
        .execute_call("missing", false)
        .expect_err("missing call target should fail");

    assert_eq!(err.to_string(), "Function 'missing' not found");
    assert_eq!(
        vm.current_activation_record()
            .expect("caller frame")
            .stack(),
        &[Value::I64(1), Value::I64(2)]
    );
}

#[test]
fn vm_call_arity_mismatch_does_not_drain_argument_stack() {
    let mut vm = VMState::new();
    let callee = VMFunction::new(
        "callee".to_string(),
        vec!["left".to_string(), "right".to_string()],
        Vec::new(),
        None,
        2,
        vec![Instruction::RET(0)],
        std::collections::HashMap::new(),
    );
    vm.try_insert_function(Function::vm(callee))
        .expect("register callee");
    vm.push_activation_record(ActivationRecord::with_registers(
        "caller",
        RegisterFile::from(vec![Value::Unit]),
        vec![],
        None,
    ));
    vm.current_frame_mut()
        .expect("caller frame")
        .push_stack(Value::I64(1));

    let err = vm
        .execute_call("callee", false)
        .expect_err("arity mismatch should fail");

    assert_eq!(
        err.to_string(),
        "Function callee expects 2 arguments but got 1"
    );
    assert_eq!(
        vm.current_activation_record()
            .expect("caller frame")
            .stack(),
        &[Value::I64(1)]
    );
}

#[test]
fn vm_call_argument_conversion_failure_does_not_drain_stack_or_emit_call_hook() {
    let mut vm = VMState::new();
    vm.set_register_layout(RegisterLayout::new(0));
    let callee = VMFunction::new(
        "callee".to_string(),
        vec!["secret_arg".to_string()],
        Vec::new(),
        None,
        1,
        vec![Instruction::RET(0)],
        std::collections::HashMap::new(),
    );
    vm.try_insert_function(Function::vm(callee))
        .expect("register callee");
    vm.push_activation_record(ActivationRecord::with_registers(
        "caller",
        RegisterFile::new(RegisterLayout::new(0), 1),
        vec![],
        None,
    ));
    vm.current_frame_mut()
        .expect("caller frame")
        .push_stack(Value::I64(5));
    let events = Arc::new(Mutex::new(0usize));
    let events_for_hook = Arc::clone(&events);
    vm.try_register_hook_boxed(
        Box::new(|event| {
            matches!(
                event,
                HookEvent::BeforeFunctionCall(_, _) | HookEvent::StackPop(_)
            )
        }),
        Box::new(move |_, _| {
            *events_for_hook.lock().unwrap() += 1;
            Ok(())
        }),
        0,
    )
    .expect("register hook");

    let err = vm
        .execute_call("callee", true)
        .expect_err("secret argument conversion should fail without an MPC engine");

    assert!(
        err.to_string().contains("MPC engine not configured"),
        "unexpected error: {err}"
    );
    assert_eq!(*events.lock().unwrap(), 0);
    assert_eq!(
        vm.current_activation_record()
            .expect("caller frame")
            .stack(),
        &[Value::I64(5)]
    );
    assert_eq!(vm.call_stack_depth(), 1);
}

#[test]
fn stack_pop_hook_error_restores_argument_stack_before_call() {
    let mut vm = VMState::new();
    let callee = VMFunction::new(
        "callee".to_string(),
        vec!["arg".to_string()],
        Vec::new(),
        None,
        1,
        vec![Instruction::RET(0)],
        std::collections::HashMap::new(),
    );
    vm.try_insert_function(Function::vm(callee))
        .expect("register callee");
    vm.push_activation_record(ActivationRecord::with_registers(
        "caller",
        RegisterFile::from(vec![Value::Unit]),
        vec![],
        None,
    ));
    vm.current_frame_mut()
        .expect("caller frame")
        .push_stack(Value::I64(5));
    vm.try_register_hook_boxed(
        Box::new(|event| matches!(event, HookEvent::StackPop(_))),
        Box::new(|_, _| Err("stack pop blocked".into())),
        0,
    )
    .expect("register hook");

    let err = vm
        .execute_call("callee", true)
        .expect_err("stack pop hook failure should abort the call");

    assert!(
        err.to_string().contains("stack pop blocked"),
        "unexpected error: {err}"
    );
    assert_eq!(
        vm.current_activation_record()
            .expect("caller frame")
            .stack(),
        &[Value::I64(5)]
    );
    assert_eq!(vm.call_stack_depth(), 1);
}

#[test]
fn vm_before_call_hook_error_restores_argument_stack() {
    let mut vm = VMState::new();
    let callee = VMFunction::new(
        "callee".to_string(),
        vec!["arg".to_string()],
        Vec::new(),
        None,
        1,
        vec![Instruction::RET(0)],
        std::collections::HashMap::new(),
    );
    vm.try_insert_function(Function::vm(callee))
        .expect("register callee");
    vm.push_activation_record(ActivationRecord::with_registers(
        "caller",
        RegisterFile::from(vec![Value::Unit]),
        vec![],
        None,
    ));
    vm.current_frame_mut()
        .expect("caller frame")
        .push_stack(Value::I64(5));
    vm.try_register_hook_boxed(
        Box::new(|event| matches!(event, HookEvent::BeforeFunctionCall(_, _))),
        Box::new(|_, _| Err("call blocked".into())),
        0,
    )
    .expect("register hook");

    let err = vm
        .execute_call("callee", true)
        .expect_err("before-call hook failure should abort the call");

    assert!(
        err.to_string().contains("call blocked"),
        "unexpected error: {err}"
    );
    assert_eq!(
        vm.current_activation_record()
            .expect("caller frame")
            .stack(),
        &[Value::I64(5)]
    );
    assert_eq!(vm.call_stack_depth(), 1);
}

#[test]
fn foreign_callback_error_restores_argument_stack() {
    let mut vm = VMState::new();
    vm.try_insert_function(Function::foreign(ForeignFunction::new(
        "native",
        Arc::new(|_| Err(ForeignFunctionCallbackError::from("callback failed"))),
    )))
    .expect("register foreign function");
    vm.push_activation_record(ActivationRecord::with_registers(
        "caller",
        RegisterFile::from(vec![Value::Unit]),
        vec![],
        None,
    ));
    vm.current_frame_mut()
        .expect("caller frame")
        .push_stack(Value::I64(1));
    vm.current_frame_mut()
        .expect("caller frame")
        .push_stack(Value::I64(2));

    let err = vm
        .execute_call("native", false)
        .expect_err("foreign callback failure should propagate");

    assert!(
        err.to_string().contains("callback failed"),
        "unexpected error: {err}"
    );
    let frame = vm.current_activation_record().expect("caller frame");
    assert_eq!(frame.stack(), &[Value::I64(1), Value::I64(2)]);
    assert_eq!(frame.register(r(0)), Some(&Value::Unit));
    assert_eq!(vm.call_stack_depth(), 1);
}

#[test]
fn foreign_before_call_hook_error_restores_argument_stack() {
    let mut vm = VMState::new();
    vm.try_insert_function(Function::foreign(ForeignFunction::new(
        "native",
        Arc::new(|_| Ok(Value::I64(99))),
    )))
    .expect("register foreign function");
    vm.push_activation_record(ActivationRecord::with_registers(
        "caller",
        RegisterFile::from(vec![Value::Unit]),
        vec![],
        None,
    ));
    vm.current_frame_mut()
        .expect("caller frame")
        .push_stack(Value::I64(1));
    vm.current_frame_mut()
        .expect("caller frame")
        .push_stack(Value::I64(2));
    vm.try_register_hook_boxed(
        Box::new(|event| matches!(event, HookEvent::BeforeFunctionCall(_, _))),
        Box::new(|_, _| Err("foreign call blocked".into())),
        0,
    )
    .expect("register hook");

    let err = vm
        .execute_call("native", true)
        .expect_err("before-call hook failure should abort the foreign call");

    assert!(
        err.to_string().contains("foreign call blocked"),
        "unexpected error: {err}"
    );
    let frame = vm.current_activation_record().expect("caller frame");
    assert_eq!(frame.stack(), &[Value::I64(1), Value::I64(2)]);
    assert_eq!(frame.register(r(0)), Some(&Value::Unit));
    assert_eq!(vm.call_stack_depth(), 1);
}

#[test]
fn closure_call_arity_mismatch_does_not_emit_call_hook_or_push_frame() {
    let mut vm = VMState::new();
    let callee = VMFunction::new(
        "callee".to_string(),
        vec!["left".to_string(), "right".to_string()],
        Vec::new(),
        None,
        2,
        vec![Instruction::RET(0)],
        std::collections::HashMap::new(),
    );
    vm.try_insert_function(Function::vm(callee))
        .expect("register callee");
    vm.push_activation_record(ActivationRecord::with_registers(
        "caller",
        RegisterFile::from(vec![Value::Unit]),
        vec![],
        None,
    ));
    let call_events = Arc::new(Mutex::new(0usize));
    let call_events_for_hook = Arc::clone(&call_events);
    vm.try_register_hook_boxed(
        Box::new(|event| matches!(event, HookEvent::BeforeFunctionCall(_, _))),
        Box::new(move |_, _| {
            *call_events_for_hook.lock().unwrap() += 1;
            Ok(())
        }),
        0,
    )
    .expect("register hook");
    let closure = Value::Closure(Arc::new(Closure::new("callee".to_string(), Vec::new())));

    let err = vm
        .call_closure_value(&closure, &[Value::I64(1)], true)
        .expect_err("arity mismatch should fail");

    assert_eq!(
        err.to_string(),
        "Function callee expects 2 arguments but got 1"
    );
    assert_eq!(*call_events.lock().unwrap(), 0);
    assert_eq!(vm.call_stack_depth(), 1);
}

#[test]
fn closure_call_argument_conversion_failure_does_not_emit_call_hook_or_push_frame() {
    let mut vm = VMState::new();
    vm.set_register_layout(RegisterLayout::new(0));
    let callee = VMFunction::new(
        "callee".to_string(),
        vec!["secret_arg".to_string()],
        Vec::new(),
        None,
        1,
        vec![Instruction::RET(0)],
        std::collections::HashMap::new(),
    );
    vm.try_insert_function(Function::vm(callee))
        .expect("register callee");
    vm.push_activation_record(ActivationRecord::with_registers(
        "caller",
        RegisterFile::new(RegisterLayout::new(0), 1),
        vec![],
        None,
    ));
    let call_events = Arc::new(Mutex::new(0usize));
    let call_events_for_hook = Arc::clone(&call_events);
    vm.try_register_hook_boxed(
        Box::new(|event| matches!(event, HookEvent::BeforeFunctionCall(_, _))),
        Box::new(move |_, _| {
            *call_events_for_hook.lock().unwrap() += 1;
            Ok(())
        }),
        0,
    )
    .expect("register hook");
    let closure = Value::Closure(Arc::new(Closure::new("callee".to_string(), Vec::new())));

    let err = vm
        .call_closure_value(&closure, &[Value::I64(5)], true)
        .expect_err("secret argument conversion should fail without an MPC engine");

    assert!(
        err.to_string().contains("MPC engine not configured"),
        "unexpected error: {err}"
    );
    assert_eq!(*call_events.lock().unwrap(), 0);
    assert_eq!(vm.call_stack_depth(), 1);
}

#[test]
fn execute_until_return_to_depth_unwinds_frames_on_instruction_error() {
    let mut vm = VMState::new();
    let function = VMFunction::new(
        "bad_write".to_string(),
        vec![],
        Vec::new(),
        None,
        3,
        vec![Instruction::LDI(2, Value::I64(7))],
        std::collections::HashMap::new(),
    );
    vm.try_insert_function(Function::vm(function))
        .expect("register function");
    vm.push_activation_record(ActivationRecord::with_registers(
        "bad_write",
        RegisterFile::from(vec![Value::Unit]),
        vec![],
        None,
    ));

    let err = vm
        .execute_until_return_to_depth(CallStackCheckpoint::new(0))
        .expect_err("out-of-bounds register write should fail");

    assert!(
        err.to_string()
            .contains("Register r2 out of bounds for frame with 1 registers"),
        "unexpected error: {err}"
    );
    assert_eq!(vm.call_stack_depth(), 0);
}

#[test]
fn run_until_effect_or_budget_yields_after_local_instruction_budget() {
    let mut vm = VMState::new();
    let function = VMFunction::new(
        "budgeted".to_string(),
        vec![],
        Vec::new(),
        None,
        2,
        vec![
            Instruction::LDI(0, Value::I64(1)),
            Instruction::LDI(1, Value::I64(2)),
            Instruction::RET(1),
        ],
        std::collections::HashMap::new(),
    );
    vm.try_insert_function(Function::vm(function))
        .expect("register function");
    let checkpoint = vm
        .push_entry_frame("budgeted", &[], |function| {
            VmError::CannotExecuteForeignFunction {
                function: function.to_owned(),
            }
        })
        .expect("push entry frame");

    assert!(matches!(
        vm.run_until_effect_or_budget_to_depth(checkpoint, VmExecutionBudget::max_instructions(1))
            .expect("first local slice should run"),
        VmRunSlice::BudgetExhausted
    ));
    assert_eq!(
        vm.current_activation_record().unwrap().register(r(0)),
        Some(&Value::I64(1))
    );

    assert!(matches!(
        vm.run_until_effect_or_budget_to_depth(checkpoint, VmExecutionBudget::max_instructions(1))
            .expect("second local slice should run"),
        VmRunSlice::BudgetExhausted
    ));
    assert_eq!(
        vm.current_activation_record().unwrap().register(r(1)),
        Some(&Value::I64(2))
    );

    match vm
        .run_until_effect_or_budget_to_depth(checkpoint, VmExecutionBudget::max_instructions(1))
        .expect("return slice should complete")
    {
        VmRunSlice::Complete(value) => assert_eq!(value, Value::I64(2)),
        other => panic!("expected completion, got {other:?}"),
    }
    assert_eq!(vm.call_stack_depth(), 0);
}

#[test]
fn run_until_effect_or_budget_yields_online_operation_without_awaiting() {
    let ty = ShareType::secret_int(64);
    let share_data = ShareData::Opaque(vec![1, 2, 3]);
    let mut vm = VMState::new();
    vm.set_register_layout(RegisterLayout::new(1));
    let function = VMFunction::new(
        "online_reveal".to_string(),
        vec![],
        Vec::new(),
        None,
        2,
        vec![
            Instruction::LDI(1, Value::Share(ty, share_data)),
            Instruction::MOV(0, 1),
            Instruction::RET(0),
        ],
        std::collections::HashMap::new(),
    );
    vm.try_insert_function(Function::vm(function))
        .expect("register function");
    let checkpoint = vm
        .push_entry_frame("online_reveal", &[], |function| {
            VmError::CannotExecuteForeignFunction {
                function: function.to_owned(),
            }
        })
        .expect("push entry frame");

    match vm
        .run_until_effect_or_budget_to_depth(checkpoint, VmExecutionBudget::max_instructions(8))
        .expect("slice should yield on online operation")
    {
        VmRunSlice::Yield(_) => {}
        other => panic!("expected online yield, got {other:?}"),
    }

    assert_eq!(
        vm.current_activation_record().unwrap().register(r(0)),
        Some(&Value::Unit),
        "destination register must not be written before the async effect completes"
    );
}

#[test]
fn run_until_effect_or_budget_yields_clear_to_secret_input_without_awaiting() {
    let mut vm = VMState::new();
    vm.set_register_layout(RegisterLayout::new(1));
    let function = VMFunction::new(
        "online_input".to_string(),
        vec![],
        Vec::new(),
        None,
        2,
        vec![Instruction::LDI(1, Value::I64(7)), Instruction::RET(1)],
        std::collections::HashMap::new(),
    );
    vm.try_insert_function(Function::vm(function))
        .expect("register function");
    let checkpoint = vm
        .push_entry_frame("online_input", &[], |function| {
            VmError::CannotExecuteForeignFunction {
                function: function.to_owned(),
            }
        })
        .expect("push entry frame");

    match vm
        .run_until_effect_or_budget_to_depth(checkpoint, VmExecutionBudget::max_instructions(8))
        .expect("slice should yield on async input sharing")
    {
        VmRunSlice::Yield(_) => {}
        other => panic!("expected input-sharing yield, got {other:?}"),
    }

    assert_eq!(
        vm.current_activation_record().unwrap().register(r(1)),
        Some(&Value::Unit),
        "secret register must not be written before async input sharing completes"
    );
}

#[test]
fn implicit_function_end_uses_shared_frame_return_path() {
    let mut vm = VMState::new();
    let callee = VMFunction::new(
        "callee".to_string(),
        vec![],
        Vec::new(),
        None,
        1,
        vec![Instruction::LDI(0, Value::I64(7))],
        std::collections::HashMap::new(),
    );
    let caller = VMFunction::new(
        "caller".to_string(),
        vec![],
        Vec::new(),
        None,
        1,
        vec![Instruction::CALL("callee".to_string()), Instruction::RET(0)],
        std::collections::HashMap::new(),
    );
    vm.try_insert_function(Function::vm(callee))
        .expect("register callee");
    vm.try_insert_function(Function::vm(caller))
        .expect("register caller");
    vm.push_activation_record(ActivationRecord::for_function(
        "caller",
        RegisterLayout::default(),
        1,
        Vec::new(),
        None,
    ));

    let events = Arc::new(Mutex::new(Vec::new()));
    let events_for_hook = Arc::clone(&events);
    vm.try_register_hook_boxed(
        Box::new(|event| {
            matches!(event, HookEvent::RegisterWrite(reg, _, _) if reg.index() == 0)
                || matches!(event, HookEvent::AfterFunctionCall(_, _))
        }),
        Box::new(move |event, context| {
            let cursor = context.current_instruction_cursor().map(|cursor| {
                (
                    cursor.function_name().to_owned(),
                    cursor.instruction_index(),
                )
            });
            match event {
                HookEvent::RegisterWrite(
                    reg,
                    RegisterWritePreviousValue::Ready(Value::Unit),
                    Value::I64(7),
                ) if reg.index() == 0 && context.current_function_name() == Some("caller") => {
                    events_for_hook
                        .lock()
                        .unwrap()
                        .push(("caller-write".to_owned(), cursor));
                }
                HookEvent::AfterFunctionCall(target, Value::I64(7))
                    if target == &HookCallTarget::vm_function("callee") =>
                {
                    events_for_hook
                        .lock()
                        .unwrap()
                        .push(("callee-after".to_owned(), cursor));
                }
                _ => {}
            }
            Ok(())
        }),
        0,
    )
    .expect("register hook");

    let result = vm
        .execute_until_return_to_depth(CallStackCheckpoint::new(0))
        .expect("caller should return");

    assert_eq!(result, Value::I64(7));
    assert_eq!(
        events.lock().unwrap().as_slice(),
        &[
            ("caller-write".to_owned(), Some(("caller".to_owned(), 0))),
            ("callee-after".to_owned(), Some(("caller".to_owned(), 0)))
        ]
    );
    assert_eq!(vm.call_stack_depth(), 0);
}

#[test]
fn register_layout_controls_clear_to_secret_mov_boundary() {
    let mut vm = VMState::new();
    vm.set_register_layout(RegisterLayout::new(8));
    let engine = Arc::new(MockConversionEngine::default());
    vm.set_mpc_engine(engine.clone());

    let mut registers = RegisterFile::new(RegisterLayout::new(8), 9);
    *registers.get_mut(r(0)).expect("clear register r0") = Value::I64(5);
    vm.push_activation_record(ActivationRecord::with_registers(
        "test",
        registers,
        vec![],
        None,
    ));

    vm.execute_mov(runtime_reg(8, 9), runtime_reg(0, 9), false)
        .unwrap();

    let record = vm.current_activation_record().unwrap();
    assert!(matches!(
        record.register(r(8)),
        Some(Value::Share(ShareType::SecretInt { bit_length: 64 }, _))
    ));
    assert_eq!(
        engine.input_calls.lock().unwrap().as_slice(),
        &[(ShareType::secret_int(64), Value::I64(5))]
    );
}

#[test]
fn active_frame_layout_controls_secret_to_clear_mov_boundary() {
    let mut vm = VMState::new();
    let engine = Arc::new(MockBatchEngine::default());
    vm.set_mpc_engine(engine.clone());
    let ty = ShareType::secret_int(64);

    let mut registers = RegisterFile::new(RegisterLayout::new(1), 2);
    *registers.get_mut(r(1)).expect("secret register r1") =
        Value::Share(ty, ShareData::Opaque(vec![7]));
    vm.push_activation_record(ActivationRecord::with_registers(
        "test",
        registers,
        vec![],
        None,
    ));

    vm.execute_mov(runtime_reg(0, 2), runtime_reg(1, 2), false)
        .expect("frame layout should classify r1 to r0 as secret-to-clear");

    let frame = vm.current_activation_record().expect("frame");
    assert!(
        frame.register(r(0)).is_none(),
        "pending reveal should not masquerade as a VM Unit value"
    );
    assert!(frame
        .register_slot(r(0))
        .is_some_and(|slot| slot.is_pending_reveal()));

    vm.resolve_register(runtime_reg(0, 2))
        .expect("observing destination should flush reveal");

    assert_eq!(
        vm.current_activation_record()
            .expect("frame")
            .register(r(0)),
        Some(&Value::I64(7))
    );
    assert_eq!(engine.calls.lock().unwrap().as_slice(), &[(ty, 1)]);
}

#[test]
fn unresolved_pending_reveal_reports_typed_runtime_error() {
    let mut vm = VMState::new();
    let mut registers = RegisterFile::new(RegisterLayout::default(), 1);
    registers
        .set_pending_reveal(r(0))
        .expect("clear register r0 exists");
    vm.push_activation_record(ActivationRecord::with_registers(
        "test",
        registers,
        vec![],
        None,
    ));

    let err = vm
        .current_register_value(runtime_reg(0, 1))
        .expect_err("pending reveal without queued batch must not read as Unit");

    assert!(matches!(
        err,
        VmError::PendingRevealWithoutQueuedBatch { register: 0 }
    ));
}

#[test]
fn register_write_hook_reports_pending_reveal_previous_state() {
    let mut vm = VMState::new();
    let mut registers = RegisterFile::new(RegisterLayout::default(), 1);
    registers
        .set_pending_reveal(r(0))
        .expect("clear register r0 exists");
    vm.push_activation_record(ActivationRecord::with_registers(
        "test",
        registers,
        vec![],
        None,
    ));

    let events = Arc::new(Mutex::new(Vec::new()));
    let events_for_hook = Arc::clone(&events);
    vm.try_register_hook_boxed(
        Box::new(|event| matches!(event, HookEvent::RegisterWrite(_, _, _))),
        Box::new(move |event, _ctx| {
            events_for_hook.lock().unwrap().push(event.clone());
            Ok(())
        }),
        0,
    )
    .expect("register hook");

    vm.write_current_register(runtime_reg(0, 1), Value::I64(7), true)
        .expect("write pending register");

    let events = events.lock().unwrap();
    assert!(matches!(
        events.as_slice(),
        [HookEvent::RegisterWrite(
            reg,
            RegisterWritePreviousValue::PendingReveal,
            Value::I64(7)
        )] if reg.index() == 0 && reg.is_clear()
    ));
}

#[test]
fn mov_hooks_read_source_before_overwriting_same_register() {
    let mut vm = VMState::new();
    let events = Arc::new(Mutex::new(Vec::new()));
    let events_for_hook = Arc::clone(&events);
    vm.try_register_hook_boxed(
        Box::new(|event| {
            matches!(
                event,
                HookEvent::RegisterRead(_, _) | HookEvent::RegisterWrite(_, _, _)
            )
        }),
        Box::new(move |event, _ctx| {
            events_for_hook.lock().unwrap().push(event.clone());
            Ok(())
        }),
        0,
    )
    .expect("register hook");
    vm.push_activation_record(ActivationRecord::with_registers(
        "test",
        RegisterFile::from(vec![Value::I64(5)]),
        vec![],
        None,
    ));

    vm.write_mov_result(runtime_reg(0, 1), runtime_reg(0, 1), Value::I64(7), true)
        .expect("write mov result");

    let events = events.lock().unwrap();
    assert!(matches!(
        events.as_slice(),
        [
            HookEvent::RegisterRead(read_reg, Value::I64(5)),
            HookEvent::RegisterWrite(
                write_reg,
                RegisterWritePreviousValue::Ready(Value::I64(5)),
                Value::I64(7),
            )
        ] if read_reg.index() == 0 && read_reg.is_clear()
            && write_reg.index() == 0 && write_reg.is_clear()
    ));
}

#[test]
fn ldi_to_secret_register_uses_mpc_conversion() {
    let mut vm = VMState::new();
    vm.set_register_layout(RegisterLayout::new(1));
    let engine = Arc::new(MockConversionEngine::default());
    vm.set_mpc_engine(engine.clone());

    let registers = RegisterFile::new(RegisterLayout::new(1), 2);
    vm.push_activation_record(ActivationRecord::with_registers(
        "test",
        registers,
        vec![],
        None,
    ));

    vm.execute_ldi(runtime_reg(1, 2), Value::I64(5), false)
        .unwrap();

    let record = vm.current_activation_record().unwrap();
    assert!(matches!(
        record.register(r(1)),
        Some(Value::Share(ShareType::SecretInt { bit_length: 64 }, _))
    ));
    assert_eq!(
        engine.input_calls.lock().unwrap().as_slice(),
        &[(ShareType::secret_int(64), Value::I64(5))]
    );
}

#[test]
fn ldi_to_secret_register_canonicalizes_vm_integer_widths() {
    let mut vm = VMState::new();
    vm.set_register_layout(RegisterLayout::new(1));
    let engine = Arc::new(MockConversionEngine::default());
    vm.set_mpc_engine(engine.clone());

    let registers = RegisterFile::new(RegisterLayout::new(1), 2);
    vm.push_activation_record(ActivationRecord::with_registers(
        "test",
        registers,
        vec![],
        None,
    ));

    vm.execute_ldi(runtime_reg(1, 2), Value::U8(5), false)
        .unwrap();

    let record = vm.current_activation_record().unwrap();
    assert!(matches!(
        record.register(r(1)),
        Some(Value::Share(ShareType::SecretInt { bit_length: 64 }, _))
    ));
    assert_eq!(
        engine.input_calls.lock().unwrap().as_slice(),
        &[(ShareType::secret_int(64), Value::I64(5))]
    );
}

#[test]
fn ldi_to_secret_register_rejects_unsigned_values_outside_i64_before_backend_dispatch() {
    let mut vm = VMState::new();
    vm.set_register_layout(RegisterLayout::new(1));
    let engine = Arc::new(MockConversionEngine::default());
    vm.set_mpc_engine(engine.clone());

    let registers = RegisterFile::new(RegisterLayout::new(1), 2);
    vm.push_activation_record(ActivationRecord::with_registers(
        "test",
        registers,
        vec![],
        None,
    ));

    let err = vm
        .execute_ldi(runtime_reg(1, 2), Value::U64(i64::MAX as u64 + 1), false)
        .expect_err("oversized unsigned value must not be sent to the MPC backend");

    let message = err.to_string();
    assert!(
        message.contains("clear integer") && message.contains("exceeds i64 range"),
        "unexpected error: {message}"
    );
    assert!(engine.input_calls.lock().unwrap().is_empty());
    let record = vm.current_activation_record().unwrap();
    assert_eq!(record.register(r(1)), Some(&Value::Unit));
}

#[test]
fn secret_register_write_rejects_clear_value_without_mpc_engine() {
    let mut vm = VMState::new();
    vm.set_register_layout(RegisterLayout::new(1));

    let registers = RegisterFile::new(RegisterLayout::new(1), 2);
    vm.push_activation_record(ActivationRecord::with_registers(
        "test",
        registers,
        vec![],
        None,
    ));

    let err = vm
        .execute_ldi(runtime_reg(1, 2), Value::I64(5), false)
        .unwrap_err();

    assert!(
        err.to_string().contains("secret register r1"),
        "unexpected error: {err}"
    );
    assert!(
        err.to_string().contains("MPC engine not configured"),
        "unexpected error: {err}"
    );
    let record = vm.current_activation_record().unwrap();
    assert_eq!(record.register(r(1)), Some(&Value::Unit));
}

#[test]
fn entry_argument_to_secret_register_uses_mpc_conversion() {
    let engine = Arc::new(MockConversionEngine::default());
    let mut vm = VirtualMachine::builder()
        .with_register_layout(RegisterLayout::new(0))
        .with_mpc_engine(engine.clone())
        .build();
    let function = VMFunction::new(
        "secret_arg".to_string(),
        vec!["x".to_string()],
        Vec::new(),
        None,
        1,
        vec![Instruction::RET(0)],
        std::collections::HashMap::new(),
    );
    vm.register_function(function);

    let result = vm
        .execute_with_args("secret_arg", &[Value::I64(5)])
        .expect("secret-register argument should be converted through MPC");

    assert!(matches!(
        result,
        Value::Share(ShareType::SecretInt { bit_length: 64 }, _)
    ));
    assert_eq!(
        engine.input_calls.lock().unwrap().as_slice(),
        &[(ShareType::secret_int(64), Value::I64(5))]
    );
}

#[test]
fn foreign_return_to_secret_register_uses_mpc_conversion() {
    let engine = Arc::new(MockConversionEngine::default());
    let mut vm = VirtualMachine::builder()
        .with_register_layout(RegisterLayout::new(0))
        .with_mpc_engine(engine.clone())
        .build();
    vm.register_foreign_function("native_secret", |_ctx| Ok(Value::I64(7)));
    let function = VMFunction::new(
        "call_native_secret".to_string(),
        vec![],
        Vec::new(),
        None,
        1,
        vec![
            Instruction::CALL("native_secret".to_string()),
            Instruction::RET(0),
        ],
        std::collections::HashMap::new(),
    );
    vm.register_function(function);

    let result = vm
        .execute("call_native_secret")
        .expect("foreign return should be converted through MPC");

    assert!(matches!(
        result,
        Value::Share(ShareType::SecretInt { bit_length: 64 }, _)
    ));
    assert_eq!(
        engine.input_calls.lock().unwrap().as_slice(),
        &[(ShareType::secret_int(64), Value::I64(7))]
    );
}

#[test]
fn register_move_kind_uses_layout_boundaries() {
    let mut vm = VMState::new();
    vm.set_register_layout(RegisterLayout::new(2));
    let layout = vm.register_layout();

    assert_eq!(layout.move_kind(r(0), r(1)), RegisterMoveKind::Copy);
    assert_eq!(
        layout.move_kind(r(2), r(0)),
        RegisterMoveKind::ClearToSecret
    );
    assert_eq!(
        layout.move_kind(r(0), r(2)),
        RegisterMoveKind::SecretToClear
    );
    assert_eq!(layout.move_kind(r(2), r(3)), RegisterMoveKind::Copy);
}

#[test]
fn secret_to_clear_mov_requires_share_value() {
    let mut vm = VMState::new();
    vm.set_register_layout(RegisterLayout::new(1));
    vm.set_mpc_engine(Arc::new(MockConversionEngine::default()));
    let mut registers = RegisterFile::new(RegisterLayout::new(1), 2);
    *registers.get_mut(r(1)).expect("secret register r1") = Value::I64(5);
    vm.push_activation_record(ActivationRecord::with_registers(
        "test",
        registers,
        vec![],
        None,
    ));

    let err = vm
        .execute_mov(runtime_reg(0, 2), runtime_reg(1, 2), false)
        .unwrap_err();

    assert!(
        err.to_string()
            .contains("Invalid share type for conversion to clear value"),
        "unexpected error: {err}"
    );
}

#[test]
fn execution_without_activation_frame_returns_error() {
    let mut vm = VMState::new();

    let err = vm.execute_until_return().unwrap_err();

    assert!(
        err.to_string().contains("No activation record to execute"),
        "unexpected error: {err}"
    );
    assert!(vm.current_activation_record().is_none());
}

#[test]
fn register_access_out_of_bounds_returns_error() {
    let mut vm = VMState::new();
    vm.push_activation_record(ActivationRecord::with_registers(
        "test",
        RegisterFile::from(vec![Value::I64(1)]),
        vec![],
        None,
    ));

    let stale_register = runtime_reg(2, 3);

    let write_err = vm
        .assign_current_register(stale_register, Value::I64(5))
        .unwrap_err();
    assert!(
        write_err.to_string().contains("Register r2 out of bounds"),
        "unexpected error: {write_err}"
    );

    let read_err = vm.current_register_value(stale_register).unwrap_err();
    assert!(
        read_err.to_string().contains("Register r2 out of bounds"),
        "unexpected error: {read_err}"
    );
}

#[test]
fn ld_uses_checked_stack_addressing() {
    let mut record = ActivationRecord::with_registers(
        "test",
        RegisterFile::from(vec![Value::Unit]),
        vec![],
        None,
    );
    record.push_stack(Value::I64(10));
    record.push_stack(Value::I64(20));

    let mut vm = VMState::new();
    vm.push_activation_record(record);

    vm.execute_ld(runtime_reg(0, 1), StackOffset::new(0), false)
        .unwrap();
    assert_eq!(
        vm.current_activation_record().unwrap().register(r(0)),
        Some(&Value::I64(20))
    );

    vm.execute_ld(runtime_reg(0, 1), StackOffset::new(-1), false)
        .unwrap();
    assert_eq!(
        vm.current_activation_record().unwrap().register(r(0)),
        Some(&Value::I64(10))
    );

    let err = vm
        .execute_ld(runtime_reg(0, 1), StackOffset::new(-3), false)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("Stack address [sp+-3] out of bounds"),
        "unexpected error: {err}"
    );
}

#[test]
fn integer_add_overflow_returns_vm_error() {
    let mut vm = vm_with_registers(vec![Value::I64(i64::MAX), Value::I64(1), Value::Unit]);

    let err = vm
        .execute_add(
            runtime_reg(2, 3),
            runtime_reg(0, 3),
            runtime_reg(1, 3),
            false,
        )
        .unwrap_err();

    assert!(
        err.to_string()
            .contains("Integer overflow in ADD operation"),
        "unexpected error: {err}"
    );
    let record = vm.current_activation_record().unwrap();
    assert_eq!(record.register(r(2)), Some(&Value::Unit));
}

#[test]
fn unsigned_sub_underflow_returns_vm_error() {
    let mut vm = vm_with_registers(vec![Value::U8(0), Value::U8(1), Value::Unit]);

    let err = vm
        .execute_sub(
            runtime_reg(2, 3),
            runtime_reg(0, 3),
            runtime_reg(1, 3),
            false,
        )
        .unwrap_err();

    assert!(
        err.to_string()
            .contains("Integer overflow in SUB operation"),
        "unexpected error: {err}"
    );
    let record = vm.current_activation_record().unwrap();
    assert_eq!(record.register(r(2)), Some(&Value::Unit));
}

#[test]
fn signed_division_overflow_returns_vm_error() {
    let mut vm = vm_with_registers(vec![Value::I64(i64::MIN), Value::I64(-1), Value::Unit]);

    let err = vm
        .execute_div(
            runtime_reg(2, 3),
            runtime_reg(0, 3),
            runtime_reg(1, 3),
            false,
        )
        .unwrap_err();

    assert!(
        err.to_string()
            .contains("Integer overflow in DIV operation"),
        "unexpected error: {err}"
    );
    let record = vm.current_activation_record().unwrap();
    assert_eq!(record.register(r(2)), Some(&Value::Unit));
}

#[test]
fn shift_amount_out_of_range_returns_vm_error() {
    let mut vm = vm_with_registers(vec![Value::I64(1), Value::I64(64), Value::Unit]);

    let err = vm
        .execute_shl(
            runtime_reg(2, 3),
            runtime_reg(0, 3),
            runtime_reg(1, 3),
            false,
        )
        .unwrap_err();

    assert!(
        err.to_string().contains("out of range in SHL operation"),
        "unexpected error: {err}"
    );
    let record = vm.current_activation_record().unwrap();
    assert_eq!(record.register(r(2)), Some(&Value::Unit));
}

#[test]
fn client_share_load_uses_stored_type_and_share_data() {
    let vm = VMState::new();
    let share_type = ShareType::default_secret_fixed_point();
    let share_data = ShareData::Feldman {
        data: vec![1, 2, 3],
        commitments: vec![vec![4, 5, 6]],
    };
    vm.store_client_shares(42, vec![ClientShare::typed(share_type, share_data.clone())]);

    let loaded = vm
        .load_client_share_as(
            42,
            ClientShareIndex::new(0),
            ShareType::default_secret_fixed_point(),
        )
        .expect("typed fixed-point share should load");

    assert_eq!(loaded, Value::Share(share_type, share_data));
}

#[test]
fn client_share_load_accepts_explicit_share_type_request() {
    let vm = VMState::new();
    let requested_type = ShareType::secret_fixed_point_from_bits(32, 8);
    let share_data = ShareData::Opaque(vec![1, 2, 3]);
    vm.store_client_shares(42, vec![ClientShare::untyped(share_data.clone())]);

    let loaded = vm
        .load_client_share_as(42, ClientShareIndex::new(0), requested_type)
        .expect("explicit share type request should load untyped input");

    assert_eq!(loaded, Value::Share(requested_type, share_data));
}

#[test]
fn client_share_load_rejects_mismatched_stored_type() {
    let vm = VMState::new();
    vm.store_client_shares(
        42,
        vec![ClientShare::typed(
            ShareType::default_secret_fixed_point(),
            ShareData::Opaque(vec![1, 2, 3]),
        )],
    );

    let err = vm
        .load_client_share(42, ClientShareIndex::new(0))
        .unwrap_err();

    assert!(
        err.to_string().contains("has type"),
        "unexpected mismatch error: {err}"
    );
}

#[test]
fn hydrate_client_inputs_requires_client_input_capability() {
    let mut vm = VMState::new();
    vm.set_mpc_engine(Arc::new(MockConversionEngine::default()));

    let err = vm.hydrate_from_mpc_engine().unwrap_err();

    match err {
        crate::error::VmError::MpcBackendOperationFailed { operation, reason } => {
            assert_eq!(operation, "client_ops");
            assert!(
                reason.contains("does not support client input hydration"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn send_output_to_client_requires_output_capability() {
    let mut vm = VMState::new();
    vm.set_mpc_engine(Arc::new(MockConversionEngine::default()));

    let err = vm
        .send_output_to_client(7, &[1, 2, 3], ClientOutputShareCount::one())
        .unwrap_err();

    assert!(
        err.to_string()
            .contains("does not support client output delivery"),
        "unexpected error: {err}"
    );
}

#[test]
fn send_output_to_client_uses_output_capability_trait() {
    let mut vm = VMState::new();
    let engine = Arc::new(OutputRecordingEngine::default());
    vm.set_mpc_engine(engine.clone());
    let output_share_count = ClientOutputShareCount::try_new(2).unwrap();

    vm.send_output_to_client(7, &[1, 2, 3], output_share_count)
        .expect("client output should be routed through output ops");

    assert_eq!(
        engine.calls.lock().unwrap().as_slice(),
        &[(7, vec![1, 2, 3], output_share_count)]
    );
}

#[test]
fn cmp_updates_compare_flag_for_ready_clear_registers() {
    let mut vm = VMState::new();
    vm.push_activation_record(ActivationRecord::with_registers(
        "test",
        RegisterFile::from(vec![Value::I64(1), Value::I64(2)]),
        vec![],
        None,
    ));

    vm.execute_cmp(runtime_reg(0, 2), runtime_reg(1, 2))
        .expect("ready clear registers should compare");

    assert_eq!(
        vm.current_frame().unwrap().compare_flag(),
        CompareFlag::Less
    );
}

#[test]
fn cmp_rejects_secret_shares_without_decoding_share_bytes() {
    let mut vm = VMState::new();
    let ty = ShareType::secret_int(64);
    vm.push_activation_record(ActivationRecord::with_registers(
        "test",
        RegisterFile::from(vec![
            Value::Share(ty, ShareData::Opaque(vec![1])),
            Value::Share(ty, ShareData::Opaque(vec![2])),
        ]),
        vec![],
        None,
    ));

    let err = vm
        .execute_cmp(runtime_reg(0, 2), runtime_reg(1, 2))
        .unwrap_err();

    assert!(
        err.to_string()
            .contains("CMP on secret shares is not supported"),
        "unexpected error: {err}"
    );
}

#[test]
fn pending_async_open_preserves_share_data_shape_until_backend_dispatch() {
    let ty = ShareType::secret_int(64);
    let share_data = ShareData::Feldman {
        data: vec![1, 2, 3],
        commitments: vec![vec![4, 5, 6]],
    };
    let mut vm = VMState::new();
    vm.set_register_layout(RegisterLayout::new(1));
    vm.push_activation_record(ActivationRecord::with_registers(
        "test",
        RegisterFile::new(RegisterLayout::new(1), 2),
        vec![],
        None,
    ));
    vm.assign_current_register(runtime_reg(1, 2), Value::Share(ty, share_data.clone()))
        .expect("write secret register");

    let operation = vm
        .plan_async_mpc_operation(
            &RuntimeInstruction::Move {
                dest: runtime_reg(0, 2),
                src: runtime_reg(1, 2),
            },
            false,
        )
        .expect("plan async operation")
        .expect("secret-to-clear move should need MPC");

    match operation {
        PendingMpcOperation::Open {
            share_type,
            share_data: planned_share_data,
            src,
            dest,
        } => {
            assert_eq!(share_type, ty);
            assert_eq!(planned_share_data, share_data);
            assert_eq!(src.index(), 1);
            assert_eq!(dest.index(), 0);
        }
        other => panic!("expected open operation, got {other:?}"),
    }
}

#[test]
fn pending_async_multiply_preserves_share_data_shape_until_backend_dispatch() {
    let ty = ShareType::secret_int(64);
    let left_data = ShareData::Feldman {
        data: vec![1, 2, 3],
        commitments: vec![vec![4, 5, 6]],
    };
    let right_data = ShareData::Feldman {
        data: vec![7, 8, 9],
        commitments: vec![vec![10, 11, 12]],
    };
    let mut vm = VMState::new();
    vm.push_activation_record(ActivationRecord::with_registers(
        "test",
        RegisterFile::from(vec![
            Value::Share(ty, left_data.clone()),
            Value::Share(ty, right_data.clone()),
            Value::Unit,
        ]),
        vec![],
        None,
    ));

    let operation = vm
        .plan_async_mpc_operation(
            &RuntimeInstruction::Binary {
                op: RuntimeBinaryOp::Multiply,
                dest: runtime_reg(2, 3),
                lhs: runtime_reg(0, 3),
                rhs: runtime_reg(1, 3),
            },
            false,
        )
        .expect("plan async operation")
        .expect("share multiplication should need MPC");

    match operation {
        PendingMpcOperation::Multiply {
            share_type,
            left_data: planned_left_data,
            right_data: planned_right_data,
            dest,
        } => {
            assert_eq!(share_type, ty);
            assert_eq!(planned_left_data, left_data);
            assert_eq!(planned_right_data, right_data);
            assert_eq!(dest.index(), 2);
        }
        other => panic!("expected multiply operation, got {other:?}"),
    }
}

#[test]
fn pending_async_multiply_rejects_mixed_share_data_formats_before_backend_dispatch() {
    let ty = ShareType::secret_int(64);
    let mut vm = VMState::new();
    vm.push_activation_record(ActivationRecord::with_registers(
        "test",
        RegisterFile::from(vec![
            Value::Share(ty, ShareData::Opaque(vec![1])),
            Value::Share(
                ty,
                ShareData::Feldman {
                    data: vec![2],
                    commitments: vec![vec![3]],
                },
            ),
            Value::Unit,
        ]),
        vec![],
        None,
    ));

    let err = vm
        .plan_async_mpc_operation(
            &RuntimeInstruction::Binary {
                op: RuntimeBinaryOp::Multiply,
                dest: runtime_reg(2, 3),
                lhs: runtime_reg(0, 3),
                rhs: runtime_reg(1, 3),
            },
            false,
        )
        .expect_err("mixed share data formats should be rejected before async dispatch");

    assert_eq!(
        err.to_string(),
        "Share data format mismatch in async_multiply_share: left is opaque, right is feldman"
    );
}

#[test]
fn share_multiply_rejects_engine_without_multiplication_capability() {
    let mut vm = VMState::new();
    vm.set_mpc_engine(Arc::new(MockConversionEngine::default()));
    let ty = ShareType::secret_int(64);
    vm.push_activation_record(ActivationRecord::with_registers(
        "test",
        RegisterFile::from(vec![
            Value::Share(ty, ShareData::Opaque(vec![1])),
            Value::Share(ty, ShareData::Opaque(vec![2])),
            Value::Unit,
        ]),
        vec![],
        None,
    ));

    let err = vm
        .execute_mul(
            runtime_reg(2, 3),
            runtime_reg(0, 3),
            runtime_reg(1, 3),
            false,
        )
        .unwrap_err();

    assert!(
        err.to_string().contains("does not support multiplication"),
        "unexpected error: {err}"
    );
}

#[test]
fn share_multiply_rejects_mismatched_share_types_before_engine_dispatch() {
    let mut vm = VMState::new();
    vm.push_activation_record(ActivationRecord::with_registers(
        "test",
        RegisterFile::from(vec![
            Value::Share(ShareType::secret_int(64), ShareData::Opaque(vec![1])),
            Value::Share(ShareType::secret_int(32), ShareData::Opaque(vec![2])),
            Value::Unit,
        ]),
        vec![],
        None,
    ));

    let err = vm
        .execute_mul(
            runtime_reg(2, 3),
            runtime_reg(0, 3),
            runtime_reg(1, 3),
            false,
        )
        .unwrap_err();

    assert_eq!(err.to_string(), "Share type mismatch in MUL operation");
}

#[tokio::test]
async fn async_clear_to_secret_ldi_uses_async_input_share() {
    let engine = Arc::new(AsyncOpenEngine::default());
    let mut vm = VirtualMachine::builder()
        .with_register_layout(RegisterLayout::new(1))
        .with_mpc_engine(engine.clone())
        .build();
    let function = VMFunction::new(
        "async_input".to_string(),
        vec![],
        Vec::new(),
        None,
        2,
        vec![Instruction::LDI(1, Value::I64(7)), Instruction::RET(1)],
        std::collections::HashMap::new(),
    );
    vm.register_function(function);

    let result = vm
        .execute_async("async_input", engine.as_ref())
        .await
        .expect("async input sharing should execute");

    assert_eq!(
        result,
        Value::Share(ShareType::secret_int(64), ShareData::Opaque(vec![42]))
    );
    assert_eq!(
        engine.input_calls.lock().unwrap().as_slice(),
        &[(ShareType::secret_int(64), Value::I64(7))]
    );
}

#[tokio::test]
async fn async_secret_to_clear_mov_uses_async_open() {
    let engine = Arc::new(AsyncOpenEngine::default());
    let ty = ShareType::secret_int(64);
    let share_bytes = vec![9, 8, 7];
    let mut vm = VirtualMachine::builder()
        .with_register_layout(RegisterLayout::new(1))
        .with_mpc_engine(engine.clone())
        .build();
    let function = VMFunction::new(
        "async_reveal".to_string(),
        vec![],
        Vec::new(),
        None,
        2,
        vec![
            Instruction::LDI(1, Value::Share(ty, ShareData::Opaque(share_bytes.clone()))),
            Instruction::MOV(0, 1),
            Instruction::RET(0),
        ],
        std::collections::HashMap::new(),
    );
    vm.register_function(function);

    let result = vm
        .execute_async("async_reveal", engine.as_ref())
        .await
        .expect("async reveal should execute");

    assert_eq!(result, Value::I64(99));
    assert_eq!(
        engine.open_calls.lock().unwrap().as_slice(),
        &[(ty, share_bytes)]
    );
}

#[tokio::test]
async fn async_execution_accepts_async_engine_trait_object() {
    let engine = Arc::new(AsyncOpenEngine::default());
    let async_engine: &dyn AsyncMpcEngine = engine.as_ref();
    let ty = ShareType::secret_int(64);
    let share_bytes = vec![7, 8, 9];
    let mut vm = VirtualMachine::builder()
        .with_register_layout(RegisterLayout::new(1))
        .with_mpc_engine(engine.clone())
        .build();
    let function = VMFunction::new(
        "async_reveal_dyn".to_string(),
        vec![],
        Vec::new(),
        None,
        2,
        vec![
            Instruction::LDI(1, Value::Share(ty, ShareData::Opaque(share_bytes.clone()))),
            Instruction::MOV(0, 1),
            Instruction::RET(0),
        ],
        std::collections::HashMap::new(),
    );
    vm.register_function(function);

    let result = vm
        .execute_async("async_reveal_dyn", async_engine)
        .await
        .expect("async trait-object engine should execute");

    assert_eq!(result, Value::I64(99));
    assert_eq!(
        engine.open_calls.lock().unwrap().as_slice(),
        &[(ty, share_bytes)]
    );
}

#[tokio::test]
async fn async_secret_to_clear_mov_completes_hook_lifecycle() {
    let engine = Arc::new(AsyncOpenEngine::default());
    let ty = ShareType::secret_int(64);
    let share_bytes = vec![9, 8, 7];
    let hook_events = Arc::new(Mutex::new(Vec::<&'static str>::new()));
    let hook_events_for_callback = Arc::clone(&hook_events);

    let mut vm = VirtualMachine::builder()
        .with_register_layout(RegisterLayout::new(1))
        .with_mpc_engine(engine.clone())
        .build();
    vm.register_hook(
        |_| true,
        move |event, _ctx| {
            let tag = match event {
                HookEvent::BeforeInstructionExecute(Instruction::MOV(0, 1)) => Some("before-mov"),
                HookEvent::RegisterRead(reg, Value::Share(_, _))
                    if reg.index() == 1 && reg.is_secret() && reg.bank_index() == 0 =>
                {
                    Some("read-src")
                }
                HookEvent::RegisterWrite(
                    reg,
                    RegisterWritePreviousValue::Ready(Value::Unit),
                    Value::I64(99),
                ) if reg.index() == 0 && reg.is_clear() && reg.bank_index() == 0 => {
                    Some("write-dest")
                }
                HookEvent::AfterInstructionExecute(Instruction::MOV(0, 1)) => Some("after-mov"),
                _ => None,
            };
            if let Some(tag) = tag {
                hook_events_for_callback.lock().unwrap().push(tag);
            }
            Ok(())
        },
        100,
    );
    let function = VMFunction::new(
        "async_reveal_hooks".to_string(),
        vec![],
        Vec::new(),
        None,
        2,
        vec![
            Instruction::LDI(1, Value::Share(ty, ShareData::Opaque(share_bytes))),
            Instruction::MOV(0, 1),
            Instruction::RET(0),
        ],
        std::collections::HashMap::new(),
    );
    vm.register_function(function);

    let result = vm
        .execute_async("async_reveal_hooks", engine.as_ref())
        .await
        .expect("async reveal should execute");

    assert_eq!(result, Value::I64(99));
    assert_eq!(
        hook_events.lock().unwrap().as_slice(),
        &["before-mov", "read-src", "write-dest", "after-mov"]
    );
}

#[tokio::test]
async fn async_mpc_operation_rejects_mismatched_state_engine() {
    let configured_engine = Arc::new(AsyncOpenEngine::new(1));
    let execution_engine = Arc::new(AsyncOpenEngine::new(2));
    let ty = ShareType::secret_int(64);
    let mut vm = VirtualMachine::builder()
        .with_register_layout(RegisterLayout::new(1))
        .with_mpc_engine(configured_engine)
        .build();
    let function = VMFunction::new(
        "async_reveal_mismatch".to_string(),
        vec![],
        Vec::new(),
        None,
        2,
        vec![
            Instruction::LDI(1, Value::Share(ty, ShareData::Opaque(vec![1, 2, 3]))),
            Instruction::MOV(0, 1),
            Instruction::RET(0),
        ],
        std::collections::HashMap::new(),
    );
    vm.register_function(function);

    let err = vm
        .execute_async("async_reveal_mismatch", execution_engine.as_ref())
        .await
        .expect_err("async execution should reject a mismatched MPC engine");

    assert!(
        err.to_string().contains("does not match VM engine"),
        "unexpected error: {err}"
    );
    assert!(execution_engine.open_calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn async_mpc_operation_rejects_mismatched_field_engine() {
    let configured_engine = Arc::new(AsyncOpenEngine::with_field_kind(
        1,
        MpcFieldKind::Bls12_381Fr,
    ));
    let execution_engine = Arc::new(AsyncOpenEngine::with_field_kind(1, MpcFieldKind::Bn254Fr));
    let ty = ShareType::secret_int(64);
    let mut vm = VirtualMachine::builder()
        .with_register_layout(RegisterLayout::new(1))
        .with_mpc_engine(configured_engine)
        .build();
    let function = VMFunction::new(
        "async_reveal_field_mismatch".to_string(),
        vec![],
        Vec::new(),
        None,
        2,
        vec![
            Instruction::LDI(1, Value::Share(ty, ShareData::Opaque(vec![1, 2, 3]))),
            Instruction::MOV(0, 1),
            Instruction::RET(0),
        ],
        std::collections::HashMap::new(),
    );
    vm.register_function(function);

    let err = vm
        .execute_async("async_reveal_field_mismatch", execution_engine.as_ref())
        .await
        .expect_err("async execution should reject a mismatched MPC field");
    let message = err.to_string();

    assert!(
        message.contains("field bn254-fr"),
        "unexpected error: {err}"
    );
    assert!(
        message.contains("field bls12-381-fr"),
        "unexpected error: {err}"
    );
    assert!(execution_engine.open_calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn async_mpc_operation_rejects_mismatched_curve_engine_with_same_field() {
    let configured_engine = Arc::new(AsyncOpenEngine::with_curve_config(
        1,
        MpcCurveConfig::Curve25519,
    ));
    let execution_engine = Arc::new(AsyncOpenEngine::with_curve_config(
        1,
        MpcCurveConfig::Ed25519,
    ));
    assert_eq!(
        configured_engine.field_kind(),
        execution_engine.field_kind()
    );

    let ty = ShareType::secret_int(64);
    let mut vm = VirtualMachine::builder()
        .with_register_layout(RegisterLayout::new(1))
        .with_mpc_engine(configured_engine)
        .build();
    let function = VMFunction::new(
        "async_reveal_curve_mismatch".to_string(),
        vec![],
        Vec::new(),
        None,
        2,
        vec![
            Instruction::LDI(1, Value::Share(ty, ShareData::Opaque(vec![1, 2, 3]))),
            Instruction::MOV(0, 1),
            Instruction::RET(0),
        ],
        std::collections::HashMap::new(),
    );
    vm.register_function(function);

    let err = vm
        .execute_async("async_reveal_curve_mismatch", execution_engine.as_ref())
        .await
        .expect_err("async execution should reject a mismatched MPC curve");
    let message = err.to_string();

    assert!(message.contains("curve ed25519"), "unexpected error: {err}");
    assert!(
        message.contains("curve curve25519"),
        "unexpected error: {err}"
    );
    assert!(execution_engine.open_calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn async_share_multiply_reports_missing_capability_as_mpc_backend_error() {
    let engine = Arc::new(AsyncOpenEngine::default());
    let ty = ShareType::secret_int(64);
    let mut vm = VirtualMachine::builder()
        .with_mpc_engine(engine.clone())
        .build();
    let function = VMFunction::new(
        "async_mul_missing_capability".to_string(),
        vec![],
        Vec::new(),
        None,
        3,
        vec![
            Instruction::LDI(0, Value::Share(ty, ShareData::Opaque(vec![1]))),
            Instruction::LDI(1, Value::Share(ty, ShareData::Opaque(vec![2]))),
            Instruction::MUL(2, 0, 1),
            Instruction::RET(2),
        ],
        std::collections::HashMap::new(),
    );
    vm.register_function(function);

    let err = vm
        .execute_async("async_mul_missing_capability", engine.as_ref())
        .await
        .expect_err("async share multiplication should require multiplication capability");

    assert_eq!(err.kind(), VirtualMachineErrorKind::Mpc);
    assert!(
        err.to_string().contains("MPC multiplication_ops failed"),
        "unexpected error: {err}"
    );
}

#[test]
fn secret_share_add_supports_feldman_encoded_shares() {
    use ark_bls12_381::G1Projective;
    use ark_ec::{CurveGroup, PrimeGroup};
    use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;

    fn encode_test_feldman_share_bls(value: i64, id: usize, degree: usize) -> Vec<u8> {
        let value_fr = ark_bls12_381::Fr::from(value as u64);
        let commitment = G1Projective::generator() * value_fr;
        let share = FeldmanShamirShare::new(value_fr, id, degree, vec![commitment])
            .expect("create Feldman share");
        let mut out = Vec::new();
        share
            .serialize_compressed(&mut out)
            .expect("serialize Feldman share");
        out
    }

    let mut vm = VMState::new();
    vm.set_mpc_engine(Arc::new(DummyFieldEngine));

    let lhs = encode_test_feldman_share_bls(3, 1, 0);
    let rhs = encode_test_feldman_share_bls(5, 1, 0);

    let result = vm
        .secret_share_add(ShareType::secret_int(64), &lhs, &rhs)
        .expect("Feldman-encoded shares should support local share add");
    let decoded = FeldmanShamirShare::<ark_bls12_381::Fr, G1Projective>::deserialize_compressed(
        result.as_slice(),
    )
    .expect("result must preserve Feldman share wire format");
    assert_eq!(decoded.feldmanshare.share[0], ark_bls12_381::Fr::from(8u64));
    assert_eq!(
        decoded.commitments[0],
        G1Projective::generator() * ark_bls12_381::Fr::from(8u64)
    );

    let lhs_data = ShareData::Feldman {
        data: lhs,
        commitments: Vec::new(),
    };
    let rhs_data = ShareData::Feldman {
        data: rhs,
        commitments: Vec::new(),
    };
    let result_data = vm
        .secret_share_add_data(ShareType::secret_int(64), &lhs_data, &rhs_data)
        .expect("Feldman share data should remain Feldman after local add");
    let result_commitments = result_data
        .commitments()
        .expect("local add should preserve Feldman commitments");
    let mut expected_commitment = Vec::new();
    (G1Projective::generator() * ark_bls12_381::Fr::from(8u64))
        .into_affine()
        .serialize_compressed(&mut expected_commitment)
        .expect("serialize expected commitment");
    assert_eq!(result_commitments[0], expected_commitment);
}

#[test]
fn secret_share_interpolate_local_supports_feldman_encoded_shares() {
    use ark_bls12_381::G1Projective;
    use ark_ec::PrimeGroup;
    use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;

    fn encode(share: FeldmanShamirShare<ark_bls12_381::Fr, G1Projective>) -> Vec<u8> {
        let mut out = Vec::new();
        share
            .serialize_compressed(&mut out)
            .expect("serialize Feldman share");
        out
    }

    let mut vm = VMState::new();
    vm.set_mpc_engine(Arc::new(DummyFieldEngine));

    let commitments = vec![
        G1Projective::generator() * ark_bls12_381::Fr::from(5u64),
        G1Projective::generator() * ark_bls12_381::Fr::from(2u64),
    ];
    let share_1 = FeldmanShamirShare::new(ark_bls12_381::Fr::from(7u64), 1, 1, commitments.clone())
        .expect("create share 1");
    let share_2 = FeldmanShamirShare::new(ark_bls12_381::Fr::from(9u64), 2, 1, commitments)
        .expect("create share 2");

    let opened = vm
        .secret_share_interpolate_local(
            ShareType::secret_int(64),
            &[
                ShareData::Feldman {
                    data: encode(share_1),
                    commitments: Vec::new(),
                },
                ShareData::Feldman {
                    data: encode(share_2),
                    commitments: Vec::new(),
                },
            ],
        )
        .expect("interpolate Feldman shares");
    assert_eq!(opened, Value::I64(5));
}
