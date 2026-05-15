use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use stoffel_vm_types::core_types::{ClearShareInput, ClearShareValue, ShareData, ShareType, Value};
use stoffel_vm_types::functions::VMFunction;
use stoffel_vm_types::instructions::Instruction;

use crate::core_vm::VirtualMachine;
use crate::net::client_store::{
    ClientInputHydrationCount, ClientInputStore, ClientShare, ClientShareIndex,
};
use crate::net::curve::MpcFieldKind;
use crate::net::mpc_engine::{
    AsyncMpcEngine, AsyncMpcEngineClientOps, MpcCapabilities, MpcEngine, MpcEngineResult,
    MpcSessionTopology, MpcSessionTopologyError,
};
use crate::VirtualMachineErrorKind;

use super::guard::RunnerVmGuard;
use super::*;

struct SyncOnlyEngine;

impl MpcEngine for SyncOnlyEngine {
    fn protocol_name(&self) -> &'static str {
        "sync-only"
    }

    fn topology(&self) -> MpcSessionTopology {
        MpcSessionTopology::try_new(7, 2, 3, 1).expect("test topology should be valid")
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

#[async_trait::async_trait]
impl AsyncMpcEngine for SyncOnlyEngine {
    async fn open_share_async(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
    ) -> crate::net::mpc_engine::MpcEngineResult<ClearShareValue> {
        self.open_share(ty, share_bytes)
    }
}

struct AsyncHydratingEngine {
    hydrate_calls: AtomicUsize,
}

impl Default for AsyncHydratingEngine {
    fn default() -> Self {
        Self {
            hydrate_calls: AtomicUsize::new(0),
        }
    }
}

impl MpcEngine for AsyncHydratingEngine {
    fn protocol_name(&self) -> &'static str {
        "async-hydrating"
    }

    fn topology(&self) -> MpcSessionTopology {
        MpcSessionTopology::try_new(8, 2, 3, 1).expect("test topology should be valid")
    }

    fn is_ready(&self) -> bool {
        true
    }

    fn start(&self) -> MpcEngineResult<()> {
        Ok(())
    }

    fn input_share(&self, _clear: ClearShareInput) -> MpcEngineResult<ShareData> {
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "input_share",
            "not used",
        ))
    }

    fn open_share(&self, _ty: ShareType, _share_bytes: &[u8]) -> MpcEngineResult<ClearShareValue> {
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "open_share",
            "not used",
        ))
    }

    fn capabilities(&self) -> MpcCapabilities {
        MpcCapabilities::CLIENT_INPUT
    }

    fn field_kind(&self) -> MpcFieldKind {
        MpcFieldKind::Bls12_381Fr
    }
}

#[async_trait::async_trait]
impl AsyncMpcEngine for AsyncHydratingEngine {
    fn as_async_client_ops(&self) -> Option<&dyn AsyncMpcEngineClientOps> {
        Some(self)
    }

    async fn open_share_async(
        &self,
        _ty: ShareType,
        _share_bytes: &[u8],
    ) -> MpcEngineResult<ClearShareValue> {
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "async_open_share",
            "not used",
        ))
    }
}

#[async_trait::async_trait]
impl AsyncMpcEngineClientOps for AsyncHydratingEngine {
    async fn get_client_ids_async(&self) -> Vec<stoffelnet::network_utils::ClientId> {
        vec![7]
    }

    async fn hydrate_client_inputs_async(
        &self,
        store: &ClientInputStore,
    ) -> MpcEngineResult<ClientInputHydrationCount> {
        self.hydrate_calls.fetch_add(1, Ordering::SeqCst);
        store.store_client_shares(
            7,
            vec![ClientShare::typed(
                ShareType::default_secret_int(),
                ShareData::Opaque(vec![9]),
            )],
        );
        Ok(ClientInputHydrationCount::new(1))
    }

    async fn hydrate_client_inputs_for_async(
        &self,
        store: &ClientInputStore,
        client_ids: &[stoffelnet::network_utils::ClientId],
    ) -> MpcEngineResult<ClientInputHydrationCount> {
        let mut hydrated = 0;
        for &client_id in client_ids {
            store.store_client_shares(
                client_id,
                vec![ClientShare::typed(
                    ShareType::default_secret_int(),
                    ShareData::Opaque(vec![9]),
                )],
            );
            hydrated += 1;
        }
        Ok(ClientInputHydrationCount::new(hydrated))
    }
}

#[test]
fn test_config_defaults() {
    let config = MpcRunnerConfig::default();
    assert_eq!(config.execution_timeout, std::time::Duration::from_secs(30));
    assert!(config.auto_hydrate);
}

#[test]
fn test_builder_methods() {
    let builder = MpcRunnerBuilder::try_new(123, 0, 5, 1)
        .expect("test topology should be valid")
        .execution_timeout(std::time::Duration::from_secs(60))
        .disable_auto_hydrate();

    assert_eq!(
        builder.topology(),
        MpcSessionTopology::try_new(123, 0, 5, 1).unwrap()
    );
    assert_eq!(
        builder.config.execution_timeout,
        std::time::Duration::from_secs(60)
    );
    assert!(!builder.config.auto_hydrate);
}

#[test]
fn builder_accepts_validated_topology_and_rejects_invalid_raw_topology() {
    let topology = MpcSessionTopology::try_new(123, 1, 5, 2).expect("valid topology");
    let builder = MpcRunnerBuilder::from_topology(topology);

    assert_eq!(builder.topology(), topology);
    assert!(matches!(
        MpcRunnerBuilder::try_new(123, 5, 5, 1),
        Err(MpcSessionTopologyError::PartyOutOfRange {
            party_id: 5,
            n_parties: 5
        })
    ));
}

#[test]
fn runner_accepts_sync_only_engine_for_blocking_orchestration() {
    let config = MpcRunnerConfig {
        execution_timeout: std::time::Duration::from_secs(1),
        auto_hydrate: false,
    };

    let runner = MpcRunner::with_config(
        VirtualMachine::without_builtins(),
        Arc::new(SyncOnlyEngine),
        config,
    );

    assert!(runner.is_ready());
    assert_eq!(
        runner.topology(),
        MpcSessionTopology::try_new(7, 2, 3, 1).unwrap()
    );
    assert_eq!(runner.instance().id(), 7);
    assert_eq!(runner.party().id(), 2);
    assert_eq!(runner.party_count().count(), 3);
    assert_eq!(runner.threshold_param().value(), 1);
    assert_eq!(runner.mpc_engine().protocol_name(), "sync-only");
}

#[test]
fn runner_vm_guard_restores_vm_slot_on_drop() {
    let slot = Arc::new(Mutex::new(Some(VirtualMachine::without_builtins())));

    {
        let _guard = RunnerVmGuard::take(&slot).expect("take runner VM");
        assert!(slot.lock().is_none());
    }

    assert!(slot.lock().is_some());
}

fn returning_function(name: &str, value: i64) -> VMFunction {
    VMFunction::new(
        name.to_string(),
        Vec::new(),
        Vec::new(),
        None,
        1,
        vec![Instruction::LDI(0, Value::I64(value)), Instruction::RET(0)],
        HashMap::new(),
    )
}

#[test]
fn runner_reports_typed_busy_vm_slot_errors() {
    let runner = MpcRunner::with_config(
        VirtualMachine::without_builtins(),
        Arc::new(SyncOnlyEngine),
        MpcRunnerConfig::default(),
    );
    #[allow(deprecated)]
    let _guard = RunnerVmGuard::take(runner.vm()).expect("take runner VM");

    let err = runner
        .hydrate_client_inputs()
        .expect_err("busy VM slot should be a typed runner error");

    assert!(matches!(err, MpcRunnerError::VmAlreadyExecuting));
    assert_eq!(err.to_string(), "MPC runner VM is already executing");
}

#[test]
fn runner_vm_accessors_report_busy_vm_slot_without_exposing_option_state() {
    let runner = MpcRunner::with_config(
        VirtualMachine::without_builtins(),
        Arc::new(SyncOnlyEngine),
        MpcRunnerConfig::default(),
    );
    #[allow(deprecated)]
    let _guard = RunnerVmGuard::take(runner.vm()).expect("take runner VM");

    let inspect_err = runner
        .try_with_vm(|_| ())
        .expect_err("busy VM slot should reject inspection");
    let inspect_result_err = runner
        .try_with_vm_result(|_| Ok(()))
        .expect_err("busy VM slot should reject fallible inspection");
    let mutate_err = runner
        .try_with_vm_mut(|_| ())
        .expect_err("busy VM slot should reject mutation");
    let mutate_result_err = runner
        .try_with_vm_mut_result(|_| Ok(()))
        .expect_err("busy VM slot should reject fallible mutation");

    assert!(matches!(inspect_err, MpcRunnerError::VmAlreadyExecuting));
    assert!(matches!(
        inspect_result_err,
        MpcRunnerError::VmAlreadyExecuting
    ));
    assert!(matches!(mutate_err, MpcRunnerError::VmAlreadyExecuting));
    assert!(matches!(
        mutate_result_err,
        MpcRunnerError::VmAlreadyExecuting
    ));
}

#[test]
fn runner_preserves_vm_error_kind_for_registration_failures() {
    let runner = MpcRunner::with_config(
        VirtualMachine::without_builtins(),
        Arc::new(SyncOnlyEngine),
        MpcRunnerConfig::default(),
    );
    runner
        .try_register_function(returning_function("main", 1))
        .expect("first registration");

    let err = runner
        .try_register_function(returning_function("main", 2))
        .expect_err("duplicate registration should remain typed");

    let MpcRunnerError::VirtualMachine(error) = err else {
        panic!("expected VM error from duplicate registration");
    };
    assert_eq!(error.kind(), VirtualMachineErrorKind::Registration);
}

#[test]
fn runner_registers_foreign_items_without_exposing_vm_slot() {
    let runner = MpcRunner::with_config(
        VirtualMachine::without_builtins(),
        Arc::new(SyncOnlyEngine),
        MpcRunnerConfig::default(),
    );

    let object_ref = runner
        .try_register_foreign_object(String::from("payload"))
        .expect("register foreign object");

    runner
        .try_register_foreign_function("native", move |ctx| {
            let object = ctx
                .get_foreign_object::<String>(object_ref)
                .ok_or_else(|| "missing object".to_owned())?;
            let payload = object.lock().clone();
            Ok(Value::String(payload))
        })
        .expect("register foreign function");

    assert!(runner
        .try_with_vm(|vm| vm.has_function("native"))
        .expect("inspect VM"));
}

#[tokio::test]
async fn async_execute_function_restores_runner_vm_slot() {
    let config = MpcRunnerConfig {
        execution_timeout: std::time::Duration::from_secs(1),
        auto_hydrate: false,
    };
    let runner = MpcRunner::with_config(
        VirtualMachine::without_builtins(),
        Arc::new(SyncOnlyEngine),
        config,
    );
    runner
        .try_register_function(returning_function("main", 42))
        .expect("register function");

    let result = runner
        .execute_function("main")
        .await
        .expect("async execution");

    assert_eq!(result.value, Value::I64(42));
    assert_eq!(result.clients_hydrated, ClientInputHydrationCount::zero());
    assert!(runner
        .try_with_vm(|vm| vm.has_function("main"))
        .expect("VM should be restored after async execution"));
}

#[tokio::test]
async fn async_execute_function_uses_async_client_input_hydration() {
    let config = MpcRunnerConfig {
        execution_timeout: std::time::Duration::from_secs(1),
        auto_hydrate: true,
    };
    let engine = Arc::new(AsyncHydratingEngine::default());
    let runner = MpcRunner::with_config(VirtualMachine::without_builtins(), engine.clone(), config);
    runner
        .try_register_function(returning_function("main", 42))
        .expect("register function");

    let result = runner
        .execute_function("main")
        .await
        .expect("async execution with client hydration");

    assert_eq!(result.value, Value::I64(42));
    assert_eq!(result.clients_hydrated, ClientInputHydrationCount::new(1));
    assert_eq!(engine.hydrate_calls.load(Ordering::SeqCst), 1);
    let hydrated_share = runner
        .try_with_vm(|vm| vm.client_share_data(7, ClientShareIndex::new(0)))
        .expect("inspect hydrated VM input")
        .expect("client input should be hydrated");
    assert_eq!(hydrated_share.data(), &ShareData::Opaque(vec![9]));
}
