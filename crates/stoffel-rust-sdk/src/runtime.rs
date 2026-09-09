//! Built runtime for a compiled or loaded Stoffel program.
//!
//! A runtime owns program metadata, validated MPC/network settings, and local
//! execution inputs. It can construct participant builders or execute supported
//! local development paths.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::client::{ClientBuilder, OffChainClientConfigBuilder};
use crate::config::{
    MpcConfig, MpcConfigSummary, NetworkConfig, NetworkConfigSummary, NetworkDeployment,
};
use crate::error::{Error, Result};
use crate::program::{BytecodeSummary, Program, ProgramSummary};
use crate::server::ServerBuilder;
use crate::types::{ProgramArgs, Value};
use crate::vm;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuntimeSummary {
    pub program: ProgramSummary,
    pub mpc: Option<MpcConfigSummary>,
    pub network: Option<NetworkConfigSummary>,
    pub named_input_count: usize,
    pub client_input_count: usize,
    pub expected_clients: Option<usize>,
    pub local_runner_configured: bool,
}

#[derive(Debug, Clone)]
pub struct StoffelRuntime {
    program: Program,
    mpc_config: Option<MpcConfig>,
    network_config: Option<NetworkConfig>,
    local_runner_path: Option<PathBuf>,
    inputs: Vec<(String, Value)>,
    client_inputs: Vec<(u64, Vec<Value>)>,
    expected_clients: Option<usize>,
    /// Developer-supplied per-client output counts, used by the local runner as
    /// a fallback only when the program does not statically declare outputs for
    /// a client (otherwise the manifest count wins).
    client_output_counts: std::collections::HashMap<u64, u64>,
}

impl StoffelRuntime {
    pub(crate) fn new(
        program: Program,
        mpc_config: Option<MpcConfig>,
        network_config: Option<NetworkConfig>,
        local_runner_path: Option<PathBuf>,
        inputs: Vec<(String, Value)>,
        client_inputs: Vec<(u64, Vec<Value>)>,
        expected_clients: Option<usize>,
    ) -> Self {
        Self {
            program,
            mpc_config,
            network_config,
            local_runner_path,
            inputs,
            client_inputs,
            expected_clients,
            client_output_counts: std::collections::HashMap::new(),
        }
    }

    /// Set developer-supplied per-client output counts (CLI / Stoffel.toml).
    pub(crate) fn set_client_output_counts(&mut self, counts: std::collections::HashMap<u64, u64>) {
        self.client_output_counts = counts;
    }

    /// Developer-supplied per-client output counts (local-runner fallback).
    pub(crate) fn client_output_counts(&self) -> &std::collections::HashMap<u64, u64> {
        &self.client_output_counts
    }

    pub fn program(&self) -> &Program {
        &self.program
    }

    pub(crate) fn with_program_and_client_inputs(
        mut self,
        program: Program,
        client_inputs: Vec<(u64, Vec<Value>)>,
    ) -> Self {
        self.program = program;
        self.inputs.clear();
        self.client_inputs = client_inputs;
        self
    }

    /// Serialize the compiled program as CLI-compatible Stoffel bytecode.
    pub fn to_bytecode(&self) -> Result<Vec<u8>> {
        self.program.to_bytecode()
    }

    /// Save the compiled program as CLI-compatible Stoffel bytecode.
    pub fn save_bytecode(&self, path: impl AsRef<Path>) -> Result<()> {
        self.program.save_bytecode(path)
    }

    /// Summarize the CLI-compatible bytecode artifact without changing it.
    pub fn bytecode_summary(&self) -> Result<BytecodeSummary> {
        self.program.bytecode_summary()
    }

    pub fn client(&self) -> ClientBuilder {
        let builder = ClientBuilder::new().with_program(self.program.clone());
        match &self.network_config {
            Some(config) => match config.server_addresses() {
                Ok(addresses) => builder.servers(addresses),
                Err(error) => builder.configuration_error(error.to_string()),
            },
            None => builder,
        }
    }

    /// Create a client builder with this runtime's program and all deployment servers.
    pub fn client_for_deployment(&self, deployment: &NetworkDeployment) -> ClientBuilder {
        ClientBuilder::new()
            .with_program(self.program.clone())
            .network_deployment(deployment)
    }

    /// Create an off-chain client IO config builder from this runtime's typed program metadata.
    ///
    /// The runtime supplies the MPC backend, topology, and output count for
    /// `client_slot`. Callers still provide coordinator/node endpoints,
    /// execution ID, timestamp, and client identity explicitly. The execution
    /// ID must match the coordinator and every MPC node for that invocation.
    pub fn offchain_client_config(&self, client_slot: u64) -> Result<OffChainClientConfigBuilder> {
        let client = self.program.client(client_slot).ok_or_else(|| {
            Error::Configuration(format!(
                "program does not declare ClientStore metadata for client slot {client_slot}"
            ))
        })?;
        let input_start_index = self
            .program
            .clients()
            .take_while(|schema| schema.client_slot() != client_slot)
            .map(|schema| schema.input_count() as u64)
            .sum();
        let mpc_config = self
            .mpc_config
            .as_ref()
            .ok_or_else(|| Error::Configuration("MPC configuration is required".to_owned()))?;
        Ok(OffChainClientConfigBuilder::default()
            .client_slot(client_slot)
            .input_start_index(input_start_index)
            .parties(mpc_config.parties)
            .threshold(mpc_config.threshold)
            .backend(mpc_config.backend)
            .input_types(client.inputs().iter().copied())
            .output_types(client.outputs().iter().copied()))
    }

    pub fn server(&self, party_id: usize) -> ServerBuilder {
        let mut builder = ServerBuilder::new(party_id).with_program(self.program.clone());
        if let Some(config) = &self.mpc_config {
            builder = builder.mpc_config(config);
        }
        match &self.network_config {
            Some(config) if config.network.party_id == party_id => builder.network_config(config),
            Some(config) => builder.configuration_error(format!(
                "network config party_id {} does not match requested server party_id {party_id}",
                config.network.party_id
            )),
            None => builder,
        }
    }

    /// Create a server builder for one party config while carrying this program.
    pub fn server_for_config(&self, config: &NetworkConfig) -> ServerBuilder {
        let mut builder = ServerBuilder::new(config.party_id()).with_program(self.program.clone());
        if let Some(mpc_config) = &self.mpc_config {
            builder = builder.mpc_config(mpc_config);
        }
        builder.network_config(config)
    }

    /// Create one server builder per party in a validated deployment plan.
    ///
    /// Each builder carries this runtime's compiled program metadata and uses
    /// the corresponding party's network config.
    pub fn servers_for_deployment(&self, deployment: &NetworkDeployment) -> Vec<ServerBuilder> {
        deployment
            .configs()
            .iter()
            .map(|config| self.server_for_config(config))
            .collect()
    }

    pub fn mpc_config(&self) -> Option<&MpcConfig> {
        self.mpc_config.as_ref()
    }

    pub fn network_config(&self) -> Option<&NetworkConfig> {
        self.network_config.as_ref()
    }

    pub fn mpc_summary(&self) -> Result<Option<MpcConfigSummary>> {
        self.mpc_config.as_ref().map(MpcConfig::summary).transpose()
    }

    pub fn network_summary(&self) -> Result<Option<NetworkConfigSummary>> {
        self.network_config
            .as_ref()
            .map(NetworkConfig::summary)
            .transpose()
    }

    pub fn summary(&self) -> Result<RuntimeSummary> {
        Ok(RuntimeSummary {
            program: self.program.summary(),
            mpc: self.mpc_summary()?,
            network: self.network_summary()?,
            named_input_count: self.inputs.len(),
            client_input_count: self.client_inputs.len(),
            expected_clients: self.expected_clients,
            local_runner_configured: self.local_runner_path.is_some(),
        })
    }

    pub fn local_runner_binary_path(&self) -> Option<&Path> {
        self.local_runner_path.as_deref()
    }

    pub fn inputs(&self) -> &[(String, Value)] {
        &self.inputs
    }

    pub fn client_inputs(&self) -> &[(u64, Vec<Value>)] {
        &self.client_inputs
    }

    pub fn configured_expected_clients(&self) -> Option<usize> {
        self.expected_clients
    }

    pub fn validate_client_inputs(&self) -> Result<()> {
        if let Some(expected_clients) = self.expected_clients {
            if expected_clients == 0 {
                return Err(Error::Configuration(
                    "expected_clients must be greater than 0".to_owned(),
                ));
            }
            self.program.validate_expected_clients(expected_clients)?;
        }
        self.program
            .validate_owned_client_inputs(&self.client_inputs)
    }

    /// Replace named function inputs for clear execution.
    pub fn with_inputs<V>(mut self, inputs: &[(&str, V)]) -> Self
    where
        V: Clone + Into<Value>,
    {
        self.inputs = inputs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone().into()))
            .collect();
        self
    }

    /// Add one named function input for clear execution.
    pub fn with_input<V>(mut self, name: impl Into<String>, value: V) -> Self
    where
        V: Into<Value>,
    {
        self.inputs.push((name.into(), value.into()));
        self
    }

    /// Replace named function inputs with values loaded from a `.json`, `.csv`, or `.txt` file.
    pub fn with_input_file(mut self, path: impl AsRef<Path>) -> Result<Self> {
        self.inputs = crate::input_file::load_named_inputs_file(path)?;
        Ok(self)
    }

    /// Add one semantic coordinator client input set for local networked execution.
    /// Fixed-point positions declared by the program manifest are scaled
    /// automatically before secret sharing.
    pub fn with_client_input<V>(mut self, client_slot: u64, values: &[V]) -> Self
    where
        V: Clone + Into<Value>,
    {
        self.client_inputs.push((
            client_slot,
            values.iter().cloned().map(Into::into).collect(),
        ));
        self
    }

    /// Replace local ClientStore inputs with values loaded from a `.json`, `.csv`, or `.txt` file.
    pub fn with_client_input_file(mut self, path: impl AsRef<Path>) -> Result<Self> {
        self.client_inputs = crate::input_file::load_client_inputs_file(path)?;
        Ok(self)
    }

    /// Replace all coordinator client input sets for local networked execution.
    pub fn with_client_inputs<V>(mut self, inputs: &[(u64, &[V])]) -> Self
    where
        V: Clone + Into<Value>,
    {
        self.client_inputs = inputs
            .iter()
            .map(|(client_slot, values)| {
                (
                    *client_slot,
                    values.iter().cloned().map(Into::into).collect(),
                )
            })
            .collect();
        self
    }

    /// Declare output-capable client slots `0..n-1` for local execution.
    pub fn expected_output_clients(mut self, n: usize) -> Self {
        self.expected_clients = Some(n);
        self
    }

    /// Set the `stoffel-run` binary path used by local coordinator execution.
    pub fn local_runner_path(mut self, path: impl AsRef<Path>) -> Self {
        self.local_runner_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Configure a real localhost coordinator-backed MPC run.
    ///
    /// This builder exposes local development controls without replacing the
    /// networking, coordinator, or protocol implementations owned by the lower
    /// crates.
    pub fn local_network(&self) -> LocalNetworkBuilder<'_> {
        LocalNetworkBuilder::new(self)
    }

    pub(crate) fn input_values_for_function(&self, function_name: &str) -> Result<Vec<Value>> {
        let function = self
            .program
            .function(function_name)
            .ok_or_else(|| Error::FunctionNotFound(function_name.to_owned()))?;
        function.validate_inputs(&self.inputs)?;
        let parameters = function.parameters();
        let mut values = Vec::with_capacity(parameters.len());

        for parameter in parameters {
            let value = self
                .inputs
                .iter()
                .find(|(name, _)| name == parameter)
                .map(|(_, value)| value)
                .expect("function input validation should guarantee one value per parameter");
            values.push(value.clone());
        }

        Ok(values)
    }

    pub fn execute_clear(&self) -> Result<Vec<Value>> {
        self.execute_clear_function("main")
    }

    pub fn execute_clear_function(&self, name: &str) -> Result<Vec<Value>> {
        vm::execute_clear(self, name)
    }

    /// Execute a named function with positional SDK values.
    ///
    /// This is the direct, local cleartext execution path for a loaded or
    /// compiled program. Arguments are validated against the function metadata
    /// stored in the binary before the VM is invoked.
    pub fn execute<A>(&self, name: &str, args: A) -> Result<Vec<Value>>
    where
        A: ProgramArgs,
    {
        let args = args.into_values();
        vm::execute_clear_with_sdk_args(self, name, &args)
    }

    /// Execute `main` with positional SDK values.
    pub fn execute_main<A>(&self, args: A) -> Result<Vec<Value>>
    where
        A: ProgramArgs,
    {
        self.execute("main", args)
    }

    /// Execute the runtime's `main` entrypoint using the local coordinator runner.
    ///
    /// This uses the same real localhost party mesh as [`crate::Stoffel::execute_local`].
    /// It is intended for runtimes that were built from no-argument
    /// `ClientStore` entrypoints with client input supplied through the builder.
    pub async fn execute_local(&self) -> Result<Vec<Value>> {
        self.execute_local_function("main").await
    }

    /// Execute a named runtime entrypoint using the local coordinator runner.
    pub async fn execute_local_function(&self, name: &str) -> Result<Vec<Value>> {
        vm::execute_local(self, name).await
    }

    /// Execute `main` when its VM return must remain secret-shared.
    pub async fn execute_local_returning_party_shares(
        &self,
    ) -> Result<vm::LocalShareExecutionOutput> {
        self.execute_local_function_returning_party_shares("main")
            .await
    }

    /// Execute a named entrypoint that returns exactly one secret share per
    /// party. Use [`Self::execute_local_function`] for public VM returns.
    pub async fn execute_local_function_returning_party_shares(
        &self,
        name: &str,
    ) -> Result<vm::LocalShareExecutionOutput> {
        vm::execute_local_returning_party_shares(self, name).await
    }
}

#[derive(Debug, Clone)]
pub struct LocalNetworkBuilder<'a> {
    runtime: &'a StoffelRuntime,
    entry: String,
    runner_path: Option<PathBuf>,
    timeout: Option<Duration>,
}

impl<'a> LocalNetworkBuilder<'a> {
    fn new(runtime: &'a StoffelRuntime) -> Self {
        Self {
            runtime,
            entry: "main".to_owned(),
            runner_path: None,
            timeout: None,
        }
    }

    /// Select the runtime entrypoint to execute. Default is `main`.
    pub fn entry(mut self, entry: impl Into<String>) -> Self {
        self.entry = entry.into();
        self
    }

    /// Override the `stoffel-run` binary path for this local run.
    pub fn runner_path(mut self, path: impl AsRef<Path>) -> Self {
        self.runner_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set the timeout applied to the local coordinator and party processes.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn configured_entry(&self) -> &str {
        &self.entry
    }

    pub fn configured_runner_path(&self) -> Option<&Path> {
        self.runner_path.as_deref()
    }

    pub fn configured_timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Execute the configured local coordinator-backed MPC run.
    pub async fn run(self) -> Result<Vec<Value>> {
        if matches!(self.timeout, Some(timeout) if timeout.is_zero()) {
            return Err(Error::Configuration(
                "local network timeout must be greater than zero".to_owned(),
            ));
        }
        vm::execute_local_with_options(
            self.runtime,
            &self.entry,
            vm::LocalExecutionOptions {
                runner_path: self.runner_path,
                timeout: self.timeout,
            },
        )
        .await
    }

    /// Execute the configured local MPC run when its VM return must remain
    /// secret-shared. This requires exactly one return share per party.
    pub async fn run_returning_party_shares(self) -> Result<vm::LocalShareExecutionOutput> {
        if matches!(self.timeout, Some(timeout) if timeout.is_zero()) {
            return Err(Error::Configuration(
                "local network timeout must be greater than zero".to_owned(),
            ));
        }
        vm::execute_local_returning_party_shares_options(
            self.runtime,
            &self.entry,
            vm::LocalExecutionOptions {
                runner_path: self.runner_path,
                timeout: self.timeout,
            },
        )
        .await
    }
}
