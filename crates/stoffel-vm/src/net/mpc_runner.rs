//! MpcRunner - Helper for running VM with MPC background tasks
//!
//! This module provides a convenient way to run a VM alongside the async
//! HoneyBadger MPC background tasks (message processing, preprocessing, etc.).
//!
//! The runner encapsulates the pattern of:
//! 1. Running MPC message processing in a background task
//! 2. Running VM execution in a blocking context
//! 3. Coordinating between async MPC operations and sync VM operations
//!
//! # Example
//!
//! ```rust,ignore
//! use stoffel_vm::net::mpc_runner::MpcRunner;
//!
//! let runner = MpcRunner::new(vm, mpc_engine);
//! runner.register_function(my_function);
//! let result = runner.execute_function("my_function").await?;
//! ```

use crate::core_vm::VirtualMachine;
use crate::net::hb_engine::HoneyBadgerMpcEngine;
use crate::net::mpc_engine::{MpcEngine, MpcEngineClientOps};
use ark_bls12_381::Fr;
use parking_lot::Mutex;
use std::sync::Arc;
use stoffelmpc_mpc::common::rbc::rbc::Avid as RBCImpl;
use stoffelmpc_mpc::honeybadger::HoneyBadgerMPCNode;
use stoffelnet::transports::quic::QuicNetworkManager;
use tokio::task::JoinHandle;

/// Configuration for MPC runner behavior
#[derive(Clone, Debug)]
pub struct MpcRunnerConfig {
    /// Timeout for VM execution
    pub execution_timeout: std::time::Duration,
    /// Whether to automatically hydrate client inputs from MPC before execution
    pub auto_hydrate: bool,
}

impl Default for MpcRunnerConfig {
    fn default() -> Self {
        Self {
            execution_timeout: std::time::Duration::from_secs(30),
            auto_hydrate: true,
        }
    }
}

/// Result of MPC-enabled VM execution
pub struct MpcExecutionResult<T> {
    /// The return value from VM execution
    pub value: T,
    /// Number of client inputs hydrated (if auto_hydrate was enabled)
    pub clients_hydrated: usize,
}

/// MpcRunner orchestrates running a VM with MPC background tasks
///
/// This helper manages the lifecycle of:
/// - MPC message processing background task
/// - VM execution in blocking context
/// - Client input hydration from MPC to VM
pub struct MpcRunner {
    /// The VM wrapped in a mutex for thread-safe access
    vm: Arc<Mutex<VirtualMachine>>,
    /// The MPC engine attached to the VM
    mpc_engine: Arc<HoneyBadgerMpcEngine>,
    /// Background task handle for message processing
    message_processor: Option<JoinHandle<()>>,
    /// Configuration
    config: MpcRunnerConfig,
}

impl MpcRunner {
    /// Create a new MpcRunner with an existing VM and MPC engine
    ///
    /// The VM should already have the MPC engine attached via `vm.state.mpc_engine`.
    /// If you need to create both from scratch, use `MpcRunner::from_node` instead.
    pub fn new(vm: VirtualMachine, mpc_engine: Arc<HoneyBadgerMpcEngine>) -> Self {
        Self {
            vm: Arc::new(Mutex::new(vm)),
            mpc_engine,
            message_processor: None,
            config: MpcRunnerConfig::default(),
        }
    }

    /// Create a new MpcRunner with custom configuration
    pub fn with_config(
        vm: VirtualMachine,
        mpc_engine: Arc<HoneyBadgerMpcEngine>,
        config: MpcRunnerConfig,
    ) -> Self {
        Self {
            vm: Arc::new(Mutex::new(vm)),
            mpc_engine,
            message_processor: None,
            config,
        }
    }

    /// Create an MpcRunner from raw MPC components
    ///
    /// This creates a VM, attaches the MPC engine, and sets up the message processor.
    ///
    /// # Arguments
    /// * `instance_id` - Unique ID for this MPC session
    /// * `party_id` - This party's ID in the MPC network
    /// * `n_parties` - Total number of parties
    /// * `threshold` - Threshold parameter for secret sharing
    /// * `network` - The QUIC network manager
    /// * `node` - The HoneyBadger MPC node
    pub fn from_node(
        instance_id: u64,
        party_id: usize,
        n_parties: usize,
        threshold: usize,
        network: Arc<QuicNetworkManager>,
        node: HoneyBadgerMPCNode<Fr, RBCImpl>,
    ) -> Self {
        let mut vm = VirtualMachine::new();
        let mpc_engine = HoneyBadgerMpcEngine::from_existing_node(
            instance_id,
            party_id,
            n_parties,
            threshold,
            network,
            node,
        );

        vm.state.mpc_engine = Some(mpc_engine.clone());

        Self {
            vm: Arc::new(Mutex::new(vm)),
            mpc_engine,
            message_processor: None,
            config: MpcRunnerConfig::default(),
        }
    }

    /// Attach an externally-spawned message processor task
    ///
    /// The caller is responsible for spawning the message processing task
    /// (which handles MPC protocol messages). This method stores the handle
    /// so the runner can abort it on shutdown.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let handle = tokio::spawn(async move {
    ///     while let Some(raw_msg) = receiver.recv().await {
    ///         node.process(raw_msg, network.clone()).await.ok();
    ///     }
    /// });
    /// runner.attach_message_processor(handle);
    /// ```
    pub fn attach_message_processor(&mut self, handle: JoinHandle<()>) {
        self.message_processor = Some(handle);
    }

    /// Hydrate VM client store from MPC engine's client inputs
    ///
    /// This copies client input shares from the HoneyBadger node to the VM's
    /// ClientInputStore, making them accessible via ClientStore.take_share().
    ///
    /// Returns the number of clients hydrated.
    pub fn hydrate_client_inputs(&self) -> Result<usize, String> {
        let vm = self.vm.lock();
        let store = vm.state.client_store();
        self.mpc_engine.hydrate_client_inputs_sync(&store)
    }

    /// Execute a VM function with MPC support (async-native)
    ///
    /// If `auto_hydrate` is enabled in config, this will first hydrate client
    /// inputs from the MPC engine before execution.
    ///
    /// This method uses the async-native VM execution which only awaits when
    /// MPC operations are needed, keeping the async runtime unblocked for
    /// non-MPC instructions.
    pub async fn execute_function(
        &self,
        function_name: &str,
    ) -> Result<MpcExecutionResult<stoffel_vm_types::core_types::Value>, String> {
        // Hydrate client inputs if configured
        let clients_hydrated = if self.config.auto_hydrate {
            self.hydrate_client_inputs()?
        } else {
            0
        };

        let timeout = self.config.execution_timeout;

        let result = tokio::time::timeout(timeout, async {
            // Execute using async MPC-aware execution
            let mut vm = self.vm.lock();
            vm.execute_async(function_name, self.mpc_engine.as_ref())
                .await
        })
        .await
        .map_err(|_| format!("Execution timed out after {:?}", timeout))??;

        Ok(MpcExecutionResult {
            value: result,
            clients_hydrated,
        })
    }

    /// Execute a VM function with MPC support (blocking mode)
    ///
    /// This is the blocking version that uses spawn_blocking for environments
    /// where async MPC isn't available or desired. It uses block_in_place
    /// internally for MPC operations.
    pub async fn execute_function_blocking(
        &self,
        function_name: &str,
    ) -> Result<MpcExecutionResult<stoffel_vm_types::core_types::Value>, String> {
        // Hydrate client inputs if configured
        let clients_hydrated = if self.config.auto_hydrate {
            self.hydrate_client_inputs()?
        } else {
            0
        };

        // Execute VM in blocking context
        let vm_arc = self.vm.clone();
        let fn_name = function_name.to_string();
        let timeout = self.config.execution_timeout;

        let result = tokio::time::timeout(timeout, async {
            tokio::task::spawn_blocking(move || {
                let mut vm = vm_arc.lock();
                vm.execute(&fn_name)
            })
            .await
            .map_err(|e| format!("Join error: {:?}", e))?
        })
        .await
        .map_err(|_| format!("Execution timed out after {:?}", timeout))??;

        Ok(MpcExecutionResult {
            value: result,
            clients_hydrated,
        })
    }

    /// Get access to the VM for registration of functions, etc.
    pub fn vm(&self) -> &Arc<Mutex<VirtualMachine>> {
        &self.vm
    }

    /// Get access to the MPC engine
    pub fn mpc_engine(&self) -> &Arc<HoneyBadgerMpcEngine> {
        &self.mpc_engine
    }

    /// Register a function on the VM
    pub fn register_function(&self, function: stoffel_vm_types::functions::VMFunction) {
        let mut vm = self.vm.lock();
        vm.register_function(function);
    }

    /// Stop the message processor and clean up
    pub async fn shutdown(mut self) {
        if let Some(handle) = self.message_processor.take() {
            handle.abort();
            let _ = handle.await;
        }
        self.mpc_engine.shutdown();
    }

    /// Check if the MPC engine is ready
    pub fn is_ready(&self) -> bool {
        self.mpc_engine.is_ready()
    }

    /// Get the party ID
    pub fn party_id(&self) -> usize {
        self.mpc_engine.party_id()
    }
}

/// Builder for creating MpcRunner with customizable options
pub struct MpcRunnerBuilder {
    instance_id: u64,
    party_id: usize,
    n_parties: usize,
    threshold: usize,
    config: MpcRunnerConfig,
}

impl MpcRunnerBuilder {
    /// Create a new builder with required MPC parameters
    pub fn new(instance_id: u64, party_id: usize, n_parties: usize, threshold: usize) -> Self {
        Self {
            instance_id,
            party_id,
            n_parties,
            threshold,
            config: MpcRunnerConfig::default(),
        }
    }

    /// Set the execution timeout
    pub fn execution_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.config.execution_timeout = timeout;
        self
    }

    /// Disable auto-hydration of client inputs
    pub fn disable_auto_hydrate(mut self) -> Self {
        self.config.auto_hydrate = false;
        self
    }

    /// Build the MpcRunner with an existing MPC node and network
    pub fn build(
        self,
        network: Arc<QuicNetworkManager>,
        node: HoneyBadgerMPCNode<Fr, RBCImpl>,
    ) -> MpcRunner {
        let mut vm = VirtualMachine::new();
        let mpc_engine = HoneyBadgerMpcEngine::from_existing_node(
            self.instance_id,
            self.party_id,
            self.n_parties,
            self.threshold,
            network,
            node,
        );

        vm.state.mpc_engine = Some(mpc_engine.clone());

        MpcRunner {
            vm: Arc::new(Mutex::new(vm)),
            mpc_engine,
            message_processor: None,
            config: self.config,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = MpcRunnerConfig::default();
        assert_eq!(config.execution_timeout, std::time::Duration::from_secs(30));
        assert!(config.auto_hydrate);
    }

    #[test]
    fn test_builder_methods() {
        let builder = MpcRunnerBuilder::new(123, 0, 5, 1)
            .execution_timeout(std::time::Duration::from_secs(60))
            .disable_auto_hydrate();

        assert_eq!(builder.instance_id, 123);
        assert_eq!(builder.party_id, 0);
        assert_eq!(builder.n_parties, 5);
        assert_eq!(builder.threshold, 1);
        assert_eq!(
            builder.config.execution_timeout,
            std::time::Duration::from_secs(60)
        );
        assert!(!builder.config.auto_hydrate);
    }
}
