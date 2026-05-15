use std::sync::Arc;

use parking_lot::Mutex;
use stoffel_vm_types::core_types::{ForeignObjectRef, Value};
use stoffel_vm_types::functions::VMFunction;
use tokio::task::JoinHandle;

use crate::core_vm::{VirtualMachine, VmEntryInvocation};
use crate::foreign_functions::{ForeignFunctionCallbackResult, ForeignFunctionContext};
use crate::net::client_store::ClientInputHydrationCount;
use crate::net::hb_engine::HoneyBadgerMpcEngine;
use crate::net::mpc_engine::{
    AsyncMpcEngine, MpcEngine, MpcInstanceId, MpcPartyCount, MpcPartyId, MpcSessionTopology,
    MpcThreshold,
};
use crate::storage::preproc::{LmdbPreprocStore, PreprocStore};
use crate::VirtualMachineResult;

use super::config::{MpcExecutionResult, MpcRunnerConfig};
use super::error::{MpcRunnerBackendResultExt, MpcRunnerError, MpcRunnerResult};
use super::guard::RunnerVmGuard;

/// MpcRunner orchestrates running a VM with MPC background tasks.
///
/// This helper manages the lifecycle of:
/// - MPC message processing background task
/// - VM execution in blocking context
/// - Client input hydration from MPC to VM
pub struct MpcRunner<E = HoneyBadgerMpcEngine<ark_bls12_381::Fr, ark_bls12_381::G1Projective>> {
    /// The VM wrapped in a mutex for thread-safe access.
    vm: Arc<Mutex<Option<VirtualMachine>>>,
    /// The MPC engine attached to the VM.
    mpc_engine: Arc<E>,
    /// Background task handle for message processing.
    message_processor: Option<JoinHandle<()>>,
    /// Runner behavior.
    config: MpcRunnerConfig,
}

impl<E> MpcRunner<E>
where
    E: MpcEngine + 'static,
{
    /// Create a new MpcRunner with an existing VM and MPC engine.
    ///
    /// The runner attaches the engine to the VM so blocking VM execution and
    /// async MPC-aware execution use the same backend.
    pub fn new(vm: VirtualMachine, mpc_engine: Arc<E>) -> Self {
        Self::with_config(vm, mpc_engine, MpcRunnerConfig::default())
    }

    /// Create a new MpcRunner with custom configuration.
    pub fn with_config(
        mut vm: VirtualMachine,
        mpc_engine: Arc<E>,
        config: MpcRunnerConfig,
    ) -> Self {
        vm.set_mpc_engine(mpc_engine.clone());
        Self {
            vm: Arc::new(Mutex::new(Some(vm))),
            mpc_engine,
            message_processor: None,
            config,
        }
    }

    /// Attach an externally-spawned message processor task.
    ///
    /// The caller is responsible for spawning the message processing task.
    /// The runner stores the handle so it can abort it on shutdown.
    pub fn attach_message_processor(&mut self, handle: JoinHandle<()>) {
        self.message_processor = Some(handle);
    }

    /// Hydrate VM client store from MPC engine's client inputs.
    ///
    /// Returns the number of clients hydrated.
    pub fn hydrate_client_inputs(&self) -> MpcRunnerResult<ClientInputHydrationCount> {
        self.try_with_vm_result(|vm| vm.hydrate_from_mpc_engine())
    }

    /// Inspect the managed VM without exposing the runner's internal VM slot.
    ///
    /// Returns [`MpcRunnerError::VmAlreadyExecuting`] when the VM is temporarily
    /// moved out for execution.
    pub fn try_with_vm<R, F>(&self, inspect: F) -> MpcRunnerResult<R>
    where
        F: FnOnce(&VirtualMachine) -> R,
    {
        let vm = self.vm.lock();
        let vm = vm.as_ref().ok_or(MpcRunnerError::VmAlreadyExecuting)?;
        Ok(inspect(vm))
    }

    /// Inspect the managed VM with a VM-fallible callback.
    pub fn try_with_vm_result<R, F>(&self, inspect: F) -> MpcRunnerResult<R>
    where
        F: FnOnce(&VirtualMachine) -> VirtualMachineResult<R>,
    {
        let vm = self.vm.lock();
        let vm = vm.as_ref().ok_or(MpcRunnerError::VmAlreadyExecuting)?;
        inspect(vm).map_err(MpcRunnerError::from)
    }

    /// Mutate the managed VM without exposing the runner's internal VM slot.
    ///
    /// Returns [`MpcRunnerError::VmAlreadyExecuting`] when the VM is temporarily
    /// moved out for execution.
    pub fn try_with_vm_mut<R, F>(&self, mutate: F) -> MpcRunnerResult<R>
    where
        F: FnOnce(&mut VirtualMachine) -> R,
    {
        let mut vm = self.vm.lock();
        let vm = vm.as_mut().ok_or(MpcRunnerError::VmAlreadyExecuting)?;
        Ok(mutate(vm))
    }

    /// Mutate the managed VM with a VM-fallible callback.
    pub fn try_with_vm_mut_result<R, F>(&self, mutate: F) -> MpcRunnerResult<R>
    where
        F: FnOnce(&mut VirtualMachine) -> VirtualMachineResult<R>,
    {
        let mut vm = self.vm.lock();
        let vm = vm.as_mut().ok_or(MpcRunnerError::VmAlreadyExecuting)?;
        mutate(vm).map_err(MpcRunnerError::from)
    }

    /// Execute a VM function with MPC support using blocking orchestration.
    pub async fn execute_function_blocking(
        &self,
        function_name: &str,
    ) -> MpcRunnerResult<MpcExecutionResult<Value>> {
        let clients_hydrated = if self.config.auto_hydrate {
            self.hydrate_client_inputs()?
        } else {
            ClientInputHydrationCount::zero()
        };

        let vm_arc = self.vm.clone();
        let fn_name = function_name.to_string();
        let timeout = self.config.execution_timeout;

        let result = tokio::time::timeout(timeout, async {
            tokio::task::spawn_blocking(move || {
                let mut vm_guard = RunnerVmGuard::take(&vm_arc)?;
                let execution = vm_guard
                    .vm_mut()?
                    .execute(&fn_name)
                    .map_err(MpcRunnerError::from);
                vm_guard.restore()?;
                execution
            })
            .await
            .map_err(|source| MpcRunnerError::Join { source })?
        })
        .await
        .map_err(|_| MpcRunnerError::ExecutionTimedOut { timeout })??;

        Ok(MpcExecutionResult {
            value: result,
            clients_hydrated,
        })
    }

    /// Get access to the VM slot for advanced registration or inspection.
    ///
    /// The slot is `None` while execution has temporarily moved the VM out of
    /// the mutex so no synchronous mutex guard is held across protocol awaits.
    ///
    /// Prefer [`MpcRunner::try_with_vm`], [`MpcRunner::try_with_vm_result`],
    /// [`MpcRunner::try_with_vm_mut`], [`MpcRunner::try_with_vm_mut_result`],
    /// or the typed registration helpers. This method remains as a compatibility
    /// escape hatch for callers that need to integrate with the slot-level
    /// execution model directly.
    #[deprecated(
        since = "0.1.0",
        note = "prefer try_with_vm, try_with_vm_result, try_with_vm_mut, try_with_vm_mut_result, or typed registration helpers"
    )]
    pub fn vm(&self) -> &Arc<Mutex<Option<VirtualMachine>>> {
        &self.vm
    }

    /// Get access to the MPC engine.
    pub fn mpc_engine(&self) -> &Arc<E> {
        &self.mpc_engine
    }

    /// Register a function on the VM.
    pub fn try_register_function(&self, function: VMFunction) -> MpcRunnerResult<()> {
        self.try_with_vm_mut_result(|vm| vm.try_register_function(function))
    }

    /// Register a foreign function on the VM.
    pub fn try_register_foreign_function<F>(&self, name: &str, func: F) -> MpcRunnerResult<()>
    where
        F: Fn(ForeignFunctionContext) -> Result<Value, String> + 'static + Send + Sync,
    {
        self.try_with_vm_mut_result(|vm| vm.try_register_foreign_function(name, func))
    }

    /// Register a typed foreign function on the VM.
    pub fn try_register_typed_foreign_function<F>(&self, name: &str, func: F) -> MpcRunnerResult<()>
    where
        F: Fn(ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value>
            + 'static
            + Send
            + Sync,
    {
        self.try_with_vm_mut_result(|vm| vm.try_register_typed_foreign_function(name, func))
    }

    /// Register a foreign object on the VM.
    pub fn try_register_foreign_object<T: 'static + Send + Sync>(
        &self,
        object: T,
    ) -> MpcRunnerResult<ForeignObjectRef> {
        self.try_with_vm_mut_result(|vm| vm.try_register_foreign_object(object))
    }

    /// Register a foreign object on the VM.
    pub fn try_register_foreign_object_ref<T: 'static + Send + Sync>(
        &self,
        object: T,
    ) -> MpcRunnerResult<ForeignObjectRef> {
        self.try_register_foreign_object(object)
    }

    /// Register a foreign object on the VM and return it as a VM value.
    pub fn try_register_foreign_object_value<T: 'static + Send + Sync>(
        &self,
        object: T,
    ) -> MpcRunnerResult<Value> {
        self.try_register_foreign_object(object).map(Value::from)
    }

    #[track_caller]
    pub fn register_function(&self, function: VMFunction) {
        self.try_register_function(function)
            .expect("invalid VM function registration");
    }

    /// Stop the message processor and clean up.
    pub async fn shutdown(mut self) {
        if let Some(handle) = self.message_processor.take() {
            handle.abort();
            let _ = handle.await;
        }
        self.mpc_engine.shutdown();
    }

    /// Check if the MPC engine is ready.
    pub fn is_ready(&self) -> bool {
        self.mpc_engine.is_ready()
    }

    /// Get the validated MPC session topology.
    pub fn topology(&self) -> MpcSessionTopology {
        self.mpc_engine.topology()
    }

    /// Get the typed MPC instance ID.
    pub fn instance(&self) -> MpcInstanceId {
        self.topology().instance()
    }

    /// Get the party ID.
    pub fn party(&self) -> MpcPartyId {
        self.topology().party()
    }

    /// Get the typed MPC party count.
    pub fn party_count(&self) -> MpcPartyCount {
        self.topology().party_count()
    }

    /// Get the typed MPC threshold parameter.
    pub fn threshold_param(&self) -> MpcThreshold {
        self.topology().threshold_param()
    }

    /// Attach a persistent preprocessing store to the MPC engine.
    ///
    /// Must be called before `preprocess()` / `start()`. The engine will
    /// attempt to load existing material from the store before running the MPC
    /// preprocessing protocol, and persist newly generated material for future
    /// runs.
    pub fn set_preproc_store(
        &self,
        store: Arc<dyn PreprocStore>,
        program_hash: [u8; 32],
    ) -> MpcRunnerResult<()> {
        self.mpc_engine
            .preproc_persistence_ops()
            .map_mpc_runner_backend_err("preproc_persistence_ops")?
            .set_preproc_store(store, program_hash)
            .map_mpc_runner_backend_err("set_preproc_store")
    }

    /// Convenience: open the default LMDB store and attach it.
    pub fn enable_preproc_persistence(&self, program_hash: [u8; 32]) -> MpcRunnerResult<()> {
        let store = Arc::new(LmdbPreprocStore::open(LmdbPreprocStore::default_path())?);
        self.set_preproc_store(store, program_hash)
    }
}

impl<E> MpcRunner<E>
where
    E: MpcEngine + AsyncMpcEngine + 'static,
{
    async fn hydrate_client_inputs_for_async_execution(
        &self,
    ) -> MpcRunnerResult<ClientInputHydrationCount> {
        let store = self.try_with_vm_result(|vm| {
            vm.client_input_store_for_async_engine(self.mpc_engine.as_ref())
        })?;
        let client_ops = self
            .mpc_engine
            .async_client_ops()
            .map_mpc_runner_backend_err("async_client_ops")?;
        client_ops
            .hydrate_client_inputs_async(&store)
            .await
            .map_mpc_runner_backend_err("hydrate_client_inputs_async")
    }

    /// Execute a VM function with MPC support using async-native VM execution.
    ///
    /// This only awaits when MPC operations are needed, keeping the async
    /// runtime unblocked for non-MPC instructions.
    pub async fn execute_function(
        &self,
        function_name: &str,
    ) -> MpcRunnerResult<MpcExecutionResult<Value>> {
        let clients_hydrated = if self.config.auto_hydrate {
            self.hydrate_client_inputs_for_async_execution().await?
        } else {
            ClientInputHydrationCount::zero()
        };

        let timeout = self.config.execution_timeout;
        let mut vm_guard = RunnerVmGuard::take(&self.vm)?;
        let execution = tokio::time::timeout(
            timeout,
            vm_guard
                .vm_mut()?
                .execute_async(function_name, self.mpc_engine.as_ref()),
        )
        .await;
        vm_guard.restore()?;
        let result = execution.map_err(|_| MpcRunnerError::ExecutionTimedOut { timeout })??;

        Ok(MpcExecutionResult {
            value: result,
            clients_hydrated,
        })
    }

    /// Execute multiple VM entry-point invocations concurrently.
    ///
    /// The managed VM is used as a template. Each invocation receives an
    /// independent runtime clone, so the runner does not hold the VM slot or a
    /// mutex guard while awaiting online MPC operations.
    pub async fn execute_functions<I>(
        &self,
        invocations: I,
    ) -> MpcRunnerResult<MpcExecutionResult<Vec<Value>>>
    where
        I: IntoIterator<Item = VmEntryInvocation>,
    {
        let clients_hydrated = if self.config.auto_hydrate {
            self.hydrate_client_inputs_for_async_execution().await?
        } else {
            ClientInputHydrationCount::zero()
        };

        let timeout = self.config.execution_timeout;
        let vm_template = self.try_with_vm_result(|vm| vm.try_clone_with_independent_state())?;
        let execution = tokio::time::timeout(
            timeout,
            vm_template.execute_many_async_with_args(invocations, self.mpc_engine.as_ref()),
        )
        .await;
        let result = execution.map_err(|_| MpcRunnerError::ExecutionTimedOut { timeout })??;

        Ok(MpcExecutionResult {
            value: result,
            clients_hydrated,
        })
    }
}
