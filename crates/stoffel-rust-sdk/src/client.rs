//! Client-side builders and computation handles.
//!
//! The SDK validates client configuration and program input arity here. Live
//! submission and ordering verification remain delegated to `stoffel-networking`
//! and the MPC runtime instead of being simulated in the SDK.

use std::collections::BTreeSet;
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};
use stoffel_mpc_coordinator_off_chain::{
    node_rpc::NodeRPCClient as OffChainNodeRPCClient, OffChainCoordinatorClient,
};
use stoffel_mpc_coordinator_shared::{Coordinator as _, ExecutionId};
use stoffel_vm_types::core_types::ShareType;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelnet::network_utils::Network as _;
use stoffelnet::transports::quic::QuicNetworkManager;

use crate::client_value_codec::{decode_fixed_point_value, encode_fixed_point_value};
use crate::config::{validate_socket_address, Curve, MpcBackend, NetworkConfig, NetworkDeployment};
use crate::consensus::VerifiedOrdering;
use crate::error::{Error, Result};
use crate::program::Program;
use crate::types::{
    ClientId, ClientValueType, GeneratedProgramManifest, TypedClientInputs, TypedClientOutputs,
    Value,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientState {
    Disconnected,
    Connected,
}

impl fmt::Display for ClientState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ClientState::Disconnected => "disconnected",
            ClientState::Connected => "connected",
        })
    }
}

impl FromStr for ClientState {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim() {
            "disconnected" => Ok(ClientState::Disconnected),
            "connected" => Ok(ClientState::Connected),
            state => Err(Error::Configuration(format!(
                "unsupported client state '{state}'; expected 'disconnected' or 'connected'"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputationStatus {
    Pending,
    Completed,
    Cancelled,
}

impl fmt::Display for ComputationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ComputationStatus::Pending => "pending",
            ComputationStatus::Completed => "completed",
            ComputationStatus::Cancelled => "cancelled",
        })
    }
}

impl FromStr for ComputationStatus {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim() {
            "pending" => Ok(ComputationStatus::Pending),
            "completed" => Ok(ComputationStatus::Completed),
            "cancelled" => Ok(ComputationStatus::Cancelled),
            status => Err(Error::Configuration(format!(
                "unsupported computation status '{status}'; expected 'pending', 'completed', or 'cancelled'"
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientBuilder {
    servers: Vec<String>,
    program: Option<Program>,
    client_id: ClientId,
    verified_ordering: Option<VerifiedOrdering>,
    connection_timeout: Duration,
    offchain_io: Option<OffChainClientConfig>,
    config_error: Option<String>,
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self {
            servers: Vec::new(),
            program: None,
            client_id: 0,
            verified_ordering: None,
            connection_timeout: Duration::from_secs(10),
            offchain_io: None,
            config_error: None,
        }
    }

    pub fn servers<I, S>(mut self, servers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.servers = servers.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_servers(self, servers: &[&str]) -> Self {
        self.servers(servers.iter().copied())
    }

    pub fn server(mut self, server: impl Into<String>) -> Self {
        self.servers.push(server.into());
        self
    }

    pub fn client_id(mut self, client_id: ClientId) -> Self {
        self.client_id = client_id;
        self
    }

    pub fn with_program(mut self, program: Program) -> Self {
        self.program = Some(program);
        self
    }

    pub fn with_verified_ordering(mut self, ordering: VerifiedOrdering) -> Self {
        self.verified_ordering = Some(ordering);
        self
    }

    pub fn connection_timeout(mut self, timeout: Duration) -> Self {
        self.connection_timeout = timeout;
        self
    }

    pub fn offchain_io(mut self, config: OffChainClientConfig) -> Self {
        self.offchain_io = Some(config);
        self
    }

    pub fn configured_servers(&self) -> &[String] {
        &self.servers
    }

    pub fn configured_client_id(&self) -> ClientId {
        self.client_id
    }

    pub fn configured_program(&self) -> Option<&Program> {
        self.program.as_ref()
    }

    pub fn has_configured_program(&self) -> bool {
        self.program.is_some()
    }

    pub fn configured_verified_ordering(&self) -> Option<&VerifiedOrdering> {
        self.verified_ordering.as_ref()
    }

    pub fn has_configured_verified_ordering(&self) -> bool {
        self.verified_ordering.is_some()
    }

    pub fn configured_connection_timeout(&self) -> Duration {
        self.connection_timeout
    }

    pub fn configured_offchain_io(&self) -> Option<&OffChainClientConfig> {
        self.offchain_io.as_ref()
    }

    pub fn has_configured_offchain_io(&self) -> bool {
        self.offchain_io.is_some()
    }

    pub fn network_config(mut self, config: &NetworkConfig) -> Self {
        match config.server_addresses() {
            Ok(addresses) => {
                self.servers = addresses;
            }
            Err(error) => {
                self.config_error = Some(error.to_string());
            }
        }
        self
    }

    /// Use all server addresses from a validated deployment plan.
    ///
    /// This only configures the client builder; live connection and submission
    /// still belong to `stoffel-networking` integration.
    pub fn network_deployment(mut self, deployment: &NetworkDeployment) -> Self {
        self.servers = deployment.server_addresses();
        self
    }

    pub fn network_config_file(mut self, path: impl AsRef<Path>) -> Self {
        match NetworkConfig::from_toml_file(path) {
            Ok(config) => self.network_config(&config),
            Err(error) => {
                self.config_error = Some(error.to_string());
                self
            }
        }
    }

    pub(crate) fn configuration_error(mut self, error: impl Into<String>) -> Self {
        self.config_error = Some(error.into());
        self
    }

    pub fn build(self) -> Result<StoffelClient> {
        if let Some(error) = self.config_error {
            return Err(Error::Configuration(error));
        }
        if self.connection_timeout.is_zero() {
            return Err(Error::Configuration(
                "client connection timeout must be greater than zero".to_owned(),
            ));
        }
        if let Some(config) = &self.offchain_io {
            config.validate()?;
        }
        if self.servers.is_empty() {
            return Err(Error::Configuration(
                "client requires at least one server address".to_owned(),
            ));
        }
        if let Some(index) = self
            .servers
            .iter()
            .position(|server| server.trim().is_empty())
        {
            return Err(Error::Configuration(format!(
                "client server address at index {index} must not be empty"
            )));
        }
        for (index, server) in self.servers.iter().enumerate() {
            validate_socket_address(&format!("client server address at index {index}"), server)?;
        }
        let mut server_addresses = BTreeSet::new();
        for server in &self.servers {
            if !server_addresses.insert(server.as_str()) {
                return Err(Error::Configuration(format!(
                    "duplicate client server address '{server}'"
                )));
            }
        }
        Ok(StoffelClient {
            servers: self.servers,
            program: self.program,
            client_id: self.client_id,
            transport_client_id: None,
            verified_ordering: self.verified_ordering,
            network: None,
            offchain_io: self.offchain_io,
            state: ClientState::Disconnected,
        })
    }

    #[tracing::instrument(skip_all, fields(server_count = self.servers.len()))]
    pub async fn connect(self) -> Result<StoffelClient> {
        let connection_timeout = self.connection_timeout;
        let mut client = self.build()?;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut network = QuicNetworkManager::new();

        for server in &client.servers {
            let address = server.parse::<SocketAddr>().map_err(|error| {
                Error::Configuration(format!("invalid client server address '{server}': {error}"))
            })?;
            match tokio::time::timeout(connection_timeout, network.connect_as_client(address)).await
            {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    return Err(Error::NetworkConnection(format!(
                        "failed to connect to server '{server}': {error}"
                    )));
                }
                Err(_) => {
                    return Err(Error::NetworkConnection(format!(
                        "timed out after {:?} connecting to server '{server}'",
                        connection_timeout
                    )));
                }
            }
        }

        client.transport_client_id = Some(network.local_derived_id());
        client.network = Some(network);
        client.state = ClientState::Connected;
        Ok(client)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffChainClientConfig {
    /// Execution namespace shared by the coordinator, MPC nodes, and clients.
    pub execution_id: ExecutionId,
    pub coordinator_host: String,
    pub coordinator_port: u16,
    pub timestamp: u64,
    #[serde(default)]
    pub client_slot: u64,
    #[serde(default)]
    pub input_start_index: u64,
    pub parties: usize,
    pub threshold: usize,
    pub backend: MpcBackend,
    pub node_rpc_addresses: Vec<String>,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub output_count: u64,
    pub input_types: Vec<ShareType>,
    pub output_types: Vec<ShareType>,
    #[serde(with = "duration_millis")]
    pub timeout: Duration,
}

impl OffChainClientConfig {
    pub fn builder() -> OffChainClientConfigBuilder {
        OffChainClientConfigBuilder::default()
    }

    pub fn validate(&self) -> Result<()> {
        if self.execution_id.is_zero() {
            return Err(Error::Configuration(
                "off-chain execution ID must be nonzero".to_owned(),
            ));
        }
        if self.coordinator_host.trim().is_empty() {
            return Err(Error::Configuration(
                "off-chain coordinator host must not be empty".to_owned(),
            ));
        }
        if self.timestamp == 0 {
            return Err(Error::Configuration(
                "off-chain coordinator timestamp must be greater than zero".to_owned(),
            ));
        }
        if self.threshold == 0 {
            return Err(Error::Configuration(
                "off-chain client threshold must be greater than zero".to_owned(),
            ));
        }
        if self.parties < 5 {
            return Err(Error::Configuration(
                "off-chain client parties must be at least 5".to_owned(),
            ));
        }
        if self.parties < 4 * self.threshold + 1 {
            return Err(Error::Unsupported(
                "off-chain client IO requires parties >= 4 * threshold + 1".to_owned(),
            ));
        }
        if self.node_rpc_addresses.is_empty() {
            return Err(Error::Configuration(
                "off-chain client IO requires at least one node RPC address".to_owned(),
            ));
        }
        for (index, address) in self.node_rpc_addresses.iter().enumerate() {
            validate_socket_address(&format!("node RPC address at index {index}"), address)?;
        }
        if self.cert_der.is_empty() {
            return Err(Error::Configuration(
                "off-chain client IO requires a client certificate DER".to_owned(),
            ));
        }
        if self.key_der.is_empty() {
            return Err(Error::Configuration(
                "off-chain client IO requires a client key DER".to_owned(),
            ));
        }
        if self.timeout.is_zero() {
            return Err(Error::Configuration(
                "off-chain client IO timeout must be greater than zero".to_owned(),
            ));
        }
        if !self.output_types.is_empty() && self.output_count != self.output_types.len() as u64 {
            return Err(Error::Configuration(format!(
                "off-chain client output_count {} does not match {} configured output type(s)",
                self.output_count,
                self.output_types.len()
            )));
        }
        Ok(())
    }

    fn node_rpc_endpoints(&self) -> Result<Vec<(String, u16)>> {
        self.node_rpc_addresses
            .iter()
            .map(|address| {
                let parsed = address.parse::<SocketAddr>().map_err(|error| {
                    Error::Configuration(format!("invalid node RPC address '{address}': {error}"))
                })?;
                Ok((parsed.ip().to_string(), parsed.port()))
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct OffChainClientConfigBuilder {
    execution_id: Option<ExecutionId>,
    coordinator_host: String,
    coordinator_port: Option<u16>,
    timestamp: Option<u64>,
    client_slot: u64,
    input_start_index: u64,
    parties: usize,
    threshold: usize,
    backend: MpcBackend,
    node_rpc_addresses: Vec<String>,
    cert_der: Option<Vec<u8>>,
    key_der: Option<Vec<u8>>,
    output_count: u64,
    input_types: Vec<ShareType>,
    output_types: Vec<ShareType>,
    timeout: Duration,
    config_error: Option<String>,
}

impl OffChainClientConfigBuilder {
    /// Select the execution namespace used by every coordinator and node RPC.
    pub fn execution_id(mut self, execution_id: ExecutionId) -> Self {
        self.execution_id = Some(execution_id);
        self
    }

    pub fn coordinator(mut self, host: impl Into<String>, port: u16) -> Self {
        self.coordinator_host = host.into();
        self.coordinator_port = Some(port);
        self
    }

    pub fn timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    pub fn client_slot(mut self, client_slot: u64) -> Self {
        self.client_slot = client_slot;
        self
    }

    pub fn input_start_index(mut self, input_start_index: u64) -> Self {
        self.input_start_index = input_start_index;
        self
    }

    pub fn parties(mut self, parties: usize) -> Self {
        self.parties = parties;
        self
    }

    pub fn threshold(mut self, threshold: usize) -> Self {
        self.threshold = threshold;
        self
    }

    pub fn backend(mut self, backend: MpcBackend) -> Self {
        self.backend = backend;
        self
    }

    pub fn manifest<M: GeneratedProgramManifest>(self) -> Self {
        self.backend(M::BACKEND)
    }

    pub fn honeybadger(mut self) -> Self {
        self.backend = MpcBackend::HoneyBadger;
        self
    }

    pub fn avss(mut self, curve: Curve) -> Self {
        self.backend = MpcBackend::Avss { curve };
        self
    }

    pub fn node_rpc_addresses<I, S>(mut self, addresses: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.node_rpc_addresses = addresses.into_iter().map(Into::into).collect();
        self
    }

    pub fn node_rpc_address(mut self, address: impl Into<String>) -> Self {
        self.node_rpc_addresses.push(address.into());
        self
    }

    pub fn identity_der(mut self, cert_der: Vec<u8>, key_der: Vec<u8>) -> Self {
        self.cert_der = Some(cert_der);
        self.key_der = Some(key_der);
        self
    }

    pub fn identity_files(
        mut self,
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Self {
        match std::fs::read(cert_path)
            .and_then(|cert| std::fs::read(key_path).map(|key| (cert, key)))
        {
            Ok((cert, key)) => {
                self.cert_der = Some(cert);
                self.key_der = Some(key);
            }
            Err(error) => {
                self.config_error = Some(error.to_string());
            }
        }
        self
    }

    pub fn output_count(mut self, output_count: u64) -> Self {
        self.output_count = output_count;
        self
    }

    pub fn input_types<I>(mut self, input_types: I) -> Self
    where
        I: IntoIterator<Item = ShareType>,
    {
        self.input_types = input_types.into_iter().collect();
        self
    }

    pub fn output_types<I>(mut self, output_types: I) -> Self
    where
        I: IntoIterator<Item = ShareType>,
    {
        self.output_types = output_types.into_iter().collect();
        self.output_count = self.output_types.len() as u64;
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn build(self) -> Result<OffChainClientConfig> {
        if let Some(error) = self.config_error {
            return Err(Error::Io(std::io::Error::other(error)));
        }
        let config = OffChainClientConfig {
            execution_id: self.execution_id.ok_or_else(|| {
                Error::Configuration("off-chain execution ID is required".to_owned())
            })?,
            coordinator_host: self.coordinator_host,
            coordinator_port: self.coordinator_port.ok_or_else(|| {
                Error::Configuration("off-chain coordinator port is required".to_owned())
            })?,
            timestamp: self.timestamp.ok_or_else(|| {
                Error::Configuration("off-chain coordinator timestamp is required".to_owned())
            })?,
            client_slot: self.client_slot,
            input_start_index: self.input_start_index,
            parties: self.parties,
            threshold: self.threshold,
            backend: self.backend,
            node_rpc_addresses: self.node_rpc_addresses,
            cert_der: self.cert_der.ok_or_else(|| {
                Error::Configuration("off-chain client certificate DER is required".to_owned())
            })?,
            key_der: self.key_der.ok_or_else(|| {
                Error::Configuration("off-chain client key DER is required".to_owned())
            })?,
            output_count: self.output_count,
            input_types: self.input_types,
            output_types: self.output_types,
            timeout: self.timeout,
        };
        config.validate()?;
        Ok(config)
    }
}

impl Default for OffChainClientConfigBuilder {
    fn default() -> Self {
        Self {
            execution_id: None,
            coordinator_host: "127.0.0.1".to_owned(),
            coordinator_port: None,
            timestamp: None,
            client_slot: 0,
            input_start_index: 0,
            parties: 5,
            threshold: 1,
            backend: MpcBackend::HoneyBadger,
            node_rpc_addresses: Vec::new(),
            cert_der: None,
            key_der: None,
            output_count: 0,
            input_types: Vec::new(),
            output_types: Vec::new(),
            timeout: Duration::from_secs(30),
            config_error: None,
        }
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct StoffelClient {
    servers: Vec<String>,
    program: Option<Program>,
    client_id: ClientId,
    transport_client_id: Option<ClientId>,
    verified_ordering: Option<VerifiedOrdering>,
    network: Option<QuicNetworkManager>,
    offchain_io: Option<OffChainClientConfig>,
    state: ClientState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSummary {
    pub client_id: ClientId,
    pub transport_client_id: Option<ClientId>,
    pub server_count: usize,
    pub has_program: bool,
    pub has_verified_ordering: bool,
    pub has_offchain_io: bool,
    pub connected: bool,
    pub state: ClientState,
}

impl StoffelClient {
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    #[tracing::instrument(skip_all, fields(server_count = servers.len()))]
    pub async fn connect(servers: &[&str]) -> Result<Self> {
        ClientBuilder::new()
            .servers(servers.iter().copied())
            .connect()
            .await
    }

    #[tracing::instrument(skip_all, fields(client_id = self.client_id))]
    pub async fn disconnect(self) -> Result<()> {
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(client_id = self.client_id, input_count = inputs.len()))]
    pub async fn run<V>(&self, inputs: &[V]) -> Result<Vec<Value>>
    where
        V: Clone + Into<Value>,
    {
        self.run_function("main", inputs).await
    }

    #[tracing::instrument(skip_all, fields(client_id = self.client_id, function = name, input_count = inputs.len()))]
    pub async fn run_function<V>(&self, name: &str, inputs: &[V]) -> Result<Vec<Value>>
    where
        V: Clone + Into<Value>,
    {
        let inputs = inputs
            .iter()
            .map(|value| value.clone().into())
            .collect::<Vec<Value>>();
        self.validate_submission_inputs(name, inputs.len())?;
        self.run_offchain_inputs(&inputs).await
    }

    #[tracing::instrument(skip_all, fields(client_id = self.client_id))]
    pub async fn run_typed<I, O>(&self, inputs: I) -> Result<O>
    where
        I: TypedClientInputs,
        O: TypedClientOutputs,
    {
        self.run_function_typed("main", inputs).await
    }

    #[tracing::instrument(skip_all, fields(client_id = self.client_id))]
    pub async fn run_typed_with_manifest<M, I, O>(&self, inputs: I) -> Result<O>
    where
        M: GeneratedProgramManifest,
        I: TypedClientInputs,
        O: TypedClientOutputs,
    {
        self.run_function_typed_with_manifest::<M, I, O>("main", inputs)
            .await
    }

    #[tracing::instrument(skip_all, fields(client_id = self.client_id, function = name))]
    pub async fn run_function_typed<I, O>(&self, name: &str, inputs: I) -> Result<O>
    where
        I: TypedClientInputs,
        O: TypedClientOutputs,
    {
        self.validate_typed_submission(name, &I::value_types(), &O::value_types())?;
        let outputs = self.run_offchain_inputs(&inputs.into_values()).await?;
        O::from_values(outputs)
    }

    #[tracing::instrument(skip_all, fields(client_id = self.client_id, function = name))]
    pub async fn run_function_typed_with_manifest<M, I, O>(
        &self,
        name: &str,
        inputs: I,
    ) -> Result<O>
    where
        M: GeneratedProgramManifest,
        I: TypedClientInputs,
        O: TypedClientOutputs,
    {
        self.validate_generated_typed_submission::<M>(name, &I::value_types(), &O::value_types())?;
        let outputs = self.run_offchain_inputs(&inputs.into_values()).await?;
        O::from_values(outputs)
    }

    #[tracing::instrument(skip_all, fields(client_id = self.client_id, input_count = inputs.len()))]
    pub async fn submit<V>(&self, inputs: &[V]) -> Result<ComputationHandle>
    where
        V: Clone + Into<Value>,
    {
        self.submit_function("main", inputs).await
    }

    #[tracing::instrument(skip_all, fields(client_id = self.client_id, function = name, input_count = inputs.len()))]
    pub async fn submit_function<V>(&self, name: &str, inputs: &[V]) -> Result<ComputationHandle>
    where
        V: Clone + Into<Value>,
    {
        let inputs = inputs
            .iter()
            .map(|value| value.clone().into())
            .collect::<Vec<Value>>();
        self.validate_submission_inputs(name, inputs.len())?;
        let config = self.offchain_io.as_ref().cloned().ok_or_else(|| {
            Error::Configuration(
                "client run/submit requires off-chain client IO configuration".to_owned(),
            )
        })?;
        let handle = ComputationHandle::submitted();
        let task_handle = handle.clone();
        tokio::spawn(async move {
            let result = run_offchain_inputs_with_config(&config, &inputs).await;
            task_handle.complete(result);
        });
        Ok(handle)
    }

    #[tracing::instrument(skip_all, fields(client_id = self.client_id))]
    pub async fn submit_typed<I>(&self, inputs: I) -> Result<ComputationHandle>
    where
        I: TypedClientInputs,
    {
        self.submit_function_typed("main", inputs).await
    }

    #[tracing::instrument(skip_all, fields(client_id = self.client_id))]
    pub async fn submit_typed_with_manifest<M, I>(&self, inputs: I) -> Result<ComputationHandle>
    where
        M: GeneratedProgramManifest,
        I: TypedClientInputs,
    {
        self.submit_function_typed_with_manifest::<M, I>("main", inputs)
            .await
    }

    #[tracing::instrument(skip_all, fields(client_id = self.client_id, function = name))]
    pub async fn submit_function_typed<I>(&self, name: &str, inputs: I) -> Result<ComputationHandle>
    where
        I: TypedClientInputs,
    {
        self.validate_typed_inputs(name, &I::value_types())?;
        let inputs = inputs.into_values();
        let config = self.offchain_io.as_ref().cloned().ok_or_else(|| {
            Error::Configuration(
                "client run/submit requires off-chain client IO configuration".to_owned(),
            )
        })?;
        let handle = ComputationHandle::submitted();
        let task_handle = handle.clone();
        tokio::spawn(async move {
            let result = run_offchain_inputs_with_config(&config, &inputs).await;
            task_handle.complete(result);
        });
        Ok(handle)
    }

    #[tracing::instrument(skip_all, fields(client_id = self.client_id, function = name))]
    pub async fn submit_function_typed_with_manifest<M, I>(
        &self,
        name: &str,
        inputs: I,
    ) -> Result<ComputationHandle>
    where
        M: GeneratedProgramManifest,
        I: TypedClientInputs,
    {
        self.validate_generated_typed_inputs::<M>(name, &I::value_types())?;
        let inputs = inputs.into_values();
        let config = self.offchain_io.as_ref().cloned().ok_or_else(|| {
            Error::Configuration(
                "client run/submit requires off-chain client IO configuration".to_owned(),
            )
        })?;
        let handle = ComputationHandle::submitted();
        let task_handle = handle.clone();
        tokio::spawn(async move {
            let result = run_offchain_inputs_with_config(&config, &inputs).await;
            task_handle.complete(result);
        });
        Ok(handle)
    }

    #[tracing::instrument(skip_all, fields(client_id = self.client_id))]
    pub async fn verify_ordering(&self) -> Result<VerifiedOrdering> {
        if let Some(ordering) = &self.verified_ordering {
            return Ok(ordering.clone());
        }
        if let Some(ordering) = self
            .network
            .as_ref()
            .and_then(|network| network.verified_ordering())
        {
            return Ok(ordering);
        }
        Err(Error::Unsupported(
            "ordering verification is performed by stoffel-networking over live QUIC connections"
                .to_owned(),
        ))
    }

    pub fn state(&self) -> ClientState {
        self.state
    }

    pub fn summary(&self) -> ClientSummary {
        ClientSummary {
            client_id: self.client_id,
            transport_client_id: self.transport_client_id,
            server_count: self.servers.len(),
            has_program: self.has_program(),
            has_verified_ordering: self.verified_ordering.is_some(),
            has_offchain_io: self.offchain_io.is_some(),
            connected: self.is_connected(),
            state: self.state,
        }
    }

    pub fn client_id(&self) -> ClientId {
        self.client_id
    }

    pub fn transport_client_id(&self) -> Option<ClientId> {
        self.transport_client_id
    }

    pub fn servers(&self) -> &[String] {
        &self.servers
    }

    pub fn program(&self) -> Option<&Program> {
        self.program.as_ref()
    }

    pub fn verified_ordering(&self) -> Option<&VerifiedOrdering> {
        self.verified_ordering.as_ref()
    }

    pub fn network_manager(&self) -> Option<&QuicNetworkManager> {
        self.network.as_ref()
    }

    pub fn offchain_io(&self) -> Option<&OffChainClientConfig> {
        self.offchain_io.as_ref()
    }

    pub fn is_connected(&self) -> bool {
        self.state == ClientState::Connected && self.network.is_some()
    }

    pub fn has_program(&self) -> bool {
        self.program.is_some()
    }

    async fn run_offchain_inputs(&self, inputs: &[Value]) -> Result<Vec<Value>> {
        let config = self.offchain_io.as_ref().ok_or_else(|| {
            Error::Configuration(
                "client run/submit requires off-chain client IO configuration".to_owned(),
            )
        })?;
        run_offchain_inputs_with_config(config, inputs).await
    }

    fn validate_submission_inputs(&self, name: &str, input_count: usize) -> Result<()> {
        if let Some(program) = &self.program {
            if program.has_client_io() {
                let client_slot = u64::try_from(self.client_id).map_err(|_| {
                    Error::InvalidInput(format!(
                        "client id {} cannot be represented as a ClientStore slot",
                        self.client_id
                    ))
                })?;
                let client = program.client(client_slot).ok_or_else(|| {
                    Error::InvalidInput(format!(
                        "program does not declare ClientStore metadata for client slot {client_slot}"
                    ))
                })?;
                if client.input_count() != input_count {
                    return Err(Error::InvalidInput(format!(
                        "client slot {client_slot} expects {} inputs, got {input_count}",
                        client.input_count()
                    )));
                }
                return Ok(());
            }
        }
        self.validate_function_inputs(name, input_count)
    }

    fn validate_typed_inputs(&self, name: &str, input_types: &[ClientValueType]) -> Result<()> {
        if let Some(program) = &self.program {
            if program.has_client_io() {
                let client_slot = self.client_slot()?;
                let client = program.client(client_slot).ok_or_else(|| {
                    Error::InvalidInput(format!(
                        "program does not declare ClientStore metadata for client slot {client_slot}"
                    ))
                })?;
                validate_client_value_types("input", client_slot, client.inputs(), input_types)?;
                return Ok(());
            }
        }
        self.validate_function_inputs(name, input_types.len())
    }

    fn validate_typed_submission(
        &self,
        name: &str,
        input_types: &[ClientValueType],
        output_types: &[ClientValueType],
    ) -> Result<()> {
        if let Some(program) = &self.program {
            if program.has_client_io() {
                let client_slot = self.client_slot()?;
                let client = program.client(client_slot).ok_or_else(|| {
                    Error::InvalidInput(format!(
                        "program does not declare ClientStore metadata for client slot {client_slot}"
                    ))
                })?;
                validate_client_value_types("input", client_slot, client.inputs(), input_types)?;
                validate_client_value_types("output", client_slot, client.outputs(), output_types)?;
                return Ok(());
            }
        }
        self.validate_function_inputs(name, input_types.len())
    }

    fn validate_generated_typed_inputs<M: GeneratedProgramManifest>(
        &self,
        name: &str,
        input_types: &[ClientValueType],
    ) -> Result<()> {
        let client_slot = self.client_slot()?;
        let expected_inputs = M::client_input_types(client_slot).ok_or_else(|| {
            Error::InvalidInput(format!(
                "generated manifest does not declare client slot {client_slot}"
            ))
        })?;
        validate_client_value_types_from_values(
            "input",
            client_slot,
            expected_inputs,
            input_types,
        )?;
        self.validate_generated_backend::<M>()?;
        self.validate_typed_inputs(name, input_types)
    }

    fn validate_generated_typed_submission<M: GeneratedProgramManifest>(
        &self,
        name: &str,
        input_types: &[ClientValueType],
        output_types: &[ClientValueType],
    ) -> Result<()> {
        let client_slot = self.client_slot()?;
        let expected_inputs = M::client_input_types(client_slot).ok_or_else(|| {
            Error::InvalidInput(format!(
                "generated manifest does not declare client slot {client_slot}"
            ))
        })?;
        let expected_outputs = M::client_output_types(client_slot).ok_or_else(|| {
            Error::InvalidInput(format!(
                "generated manifest does not declare client slot {client_slot}"
            ))
        })?;
        validate_client_value_types_from_values(
            "input",
            client_slot,
            expected_inputs,
            input_types,
        )?;
        validate_client_value_types_from_values(
            "output",
            client_slot,
            expected_outputs,
            output_types,
        )?;
        self.validate_generated_backend::<M>()?;
        self.validate_typed_submission(name, input_types, output_types)
    }

    fn validate_generated_backend<M: GeneratedProgramManifest>(&self) -> Result<()> {
        if let Some(program) = &self.program {
            let program_backend = sdk_backend_from_program(program);
            if program_backend != M::BACKEND {
                return Err(Error::InvalidInput(format!(
                    "generated manifest backend {} does not match loaded program backend {}",
                    M::BACKEND,
                    program_backend
                )));
            }
        }
        Ok(())
    }

    fn client_slot(&self) -> Result<u64> {
        u64::try_from(self.client_id).map_err(|_| {
            Error::InvalidInput(format!(
                "client id {} cannot be represented as a ClientStore slot",
                self.client_id
            ))
        })
    }

    fn validate_function_inputs(&self, name: &str, input_count: usize) -> Result<()> {
        if let Some(program) = &self.program {
            let function = program
                .function(name)
                .ok_or_else(|| Error::FunctionNotFound(name.to_owned()))?;
            if function.arg_count() != input_count {
                return Err(Error::InvalidInput(format!(
                    "function '{name}' expects {} inputs, got {input_count}",
                    function.arg_count()
                )));
            }
        }
        Ok(())
    }
}

fn validate_client_value_types(
    direction: &str,
    client_slot: u64,
    share_types: &[ShareType],
    value_types: &[ClientValueType],
) -> Result<()> {
    if share_types.len() != value_types.len() {
        return Err(Error::InvalidInput(format!(
            "client slot {client_slot} expects {} typed {direction}s, got {}",
            share_types.len(),
            value_types.len()
        )));
    }
    for (ordinal, (share_type, value_type)) in share_types.iter().zip(value_types).enumerate() {
        if !value_type.is_compatible_with_share_type(*share_type) {
            return Err(Error::InvalidInput(format!(
                "client slot {client_slot} {direction} {ordinal} expects {share_type:?}, got {value_type:?}"
            )));
        }
    }
    Ok(())
}

fn validate_client_value_types_from_values(
    direction: &str,
    client_slot: u64,
    expected: &[ClientValueType],
    actual: &[ClientValueType],
) -> Result<()> {
    if expected.len() != actual.len() {
        return Err(Error::InvalidInput(format!(
            "generated manifest client slot {client_slot} expects {} typed {direction}s, got {}",
            expected.len(),
            actual.len()
        )));
    }
    for (ordinal, (expected_type, actual_type)) in expected.iter().zip(actual).enumerate() {
        if expected_type != actual_type {
            return Err(Error::InvalidInput(format!(
                "generated manifest client slot {client_slot} {direction} {ordinal} expects {expected_type:?}, got {actual_type:?}"
            )));
        }
    }
    Ok(())
}

fn sdk_backend_from_program(program: &Program) -> MpcBackend {
    match program.bytecode_backend() {
        stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger => MpcBackend::HoneyBadger,
        stoffel_vm_types::compiled_binary::MpcBackend::Avss => MpcBackend::Avss {
            curve: match program.bytecode_curve() {
                stoffel_vm_types::compiled_binary::MpcCurve::Bls12_381 => Curve::Bls12_381,
                stoffel_vm_types::compiled_binary::MpcCurve::Bn254 => Curve::Bn254,
                stoffel_vm_types::compiled_binary::MpcCurve::Curve25519 => Curve::Curve25519,
                stoffel_vm_types::compiled_binary::MpcCurve::Ed25519 => Curve::Ed25519,
                stoffel_vm_types::compiled_binary::MpcCurve::Secp256k1 => Curve::Secp256k1,
                stoffel_vm_types::compiled_binary::MpcCurve::Secp256r1 => Curve::Secp256r1,
            },
        },
    }
}

async fn run_offchain_inputs_with_config(
    config: &OffChainClientConfig,
    inputs: &[Value],
) -> Result<Vec<Value>> {
    match config.backend {
        MpcBackend::HoneyBadger => {
            run_offchain_with_share::<Fr, RobustShare<Fr>>(config, inputs).await
        }
        MpcBackend::Avss { curve } => match curve {
            Curve::Bls12_381 => {
                run_offchain_with_share::<
                    ark_bls12_381::Fr,
                    FeldmanShamirShare<ark_bls12_381::Fr, ark_bls12_381::G1Projective>,
                >(config, inputs)
                .await
            }
            Curve::Bn254 => {
                run_offchain_with_share::<
                    ark_bn254::Fr,
                    FeldmanShamirShare<ark_bn254::Fr, ark_bn254::G1Projective>,
                >(config, inputs)
                .await
            }
            Curve::Curve25519 => {
                run_offchain_with_share::<
                    ark_curve25519::Fr,
                    FeldmanShamirShare<ark_curve25519::Fr, ark_curve25519::EdwardsProjective>,
                >(config, inputs)
                .await
            }
            Curve::Ed25519 => {
                run_offchain_with_share::<
                    ark_ed25519::Fr,
                    FeldmanShamirShare<ark_ed25519::Fr, ark_ed25519::EdwardsProjective>,
                >(config, inputs)
                .await
            }
            Curve::Secp256k1 => {
                run_offchain_with_share::<
                    ark_secp256k1::Fr,
                    FeldmanShamirShare<ark_secp256k1::Fr, ark_secp256k1::Projective>,
                >(config, inputs)
                .await
            }
            Curve::Secp256r1 => {
                run_offchain_with_share::<
                    ark_secp256r1::Fr,
                    FeldmanShamirShare<ark_secp256r1::Fr, ark_secp256r1::Projective>,
                >(config, inputs)
                .await
            }
        },
    }
}

async fn run_offchain_with_share<F, S>(
    config: &OffChainClientConfig,
    inputs: &[Value],
) -> Result<Vec<Value>>
where
    F: stoffel_vm::net::curve::SupportedMpcField,
    S: stoffel_mpc_coordinator_shared::ShareBound<F, ValueType = F>,
{
    tokio::time::timeout(config.timeout, async {
        let coord = OffChainCoordinatorClient::<F, S>::start_rpc_client_for_execution(
            &config.coordinator_host,
            config.coordinator_port,
            config.threshold as u64,
            config.parties as u64,
            config.output_count,
            config.execution_id,
            config.cert_der.clone(),
            config.key_der.clone(),
        )
        .await?;
        if config.input_types.len() != inputs.len() {
            return Err(Error::InvalidInput(format!(
                "off-chain client config for slot {} has {} input type(s), got {} input value(s)",
                config.client_slot,
                config.input_types.len(),
                inputs.len()
            )));
        }
        let mut coord = coord;
        let reserved_indices = (0..inputs.len())
            .map(|ordinal| config.input_start_index + ordinal as u64)
            .collect::<Vec<_>>();
        if !reserved_indices.is_empty() {
            coord.reserve_mask_indices(&reserved_indices).await?;
        }
        let node_rpc = OffChainNodeRPCClient::<F, S>::start_rpc_client_for_execution(
            config.parties,
            config.threshold,
            config.node_rpc_endpoints()?,
            config.execution_id,
            config.cert_der.clone(),
            config.key_der.clone(),
        )
        .await?;
        let masks = node_rpc
            .receive_assigned_masks(config.input_start_index, inputs.len() as u64)
            .await?;
        let curve = config.backend.curve().unwrap_or(Curve::Bls12_381);
        let masked_inputs = inputs
            .iter()
            .zip(config.input_types.iter())
            .enumerate()
            .map(|(ordinal, (input, share_type))| {
                let reserved_index = config.input_start_index + ordinal as u64;
                let mask = masks.get(ordinal).ok_or_else(|| {
                    Error::Coordinator(stoffel_mpc_coordinator_shared::CoordinatorError::JSONError(
                        format!("missing assigned mask for input ordinal {ordinal}"),
                    ))
                })?;
                let field_input = value_to_field::<F>(input, *share_type, curve)?;
                Ok((reserved_index, field_input + mask))
            })
            .collect::<Result<Vec<_>>>()?;
        coord.send_masked_inputs(&masked_inputs).await?;
        outputs_to_values(coord.obtain_outputs().await?, &config.output_types)
    })
    .await
    .map_err(|_| {
        Error::NetworkConnection(format!(
            "off-chain client IO timed out after {:?}",
            config.timeout
        ))
    })?
}

fn value_to_field<F: PrimeField>(value: &Value, share_type: ShareType, curve: Curve) -> Result<F> {
    match (share_type, value) {
        (ShareType::SecretInt { bit_length: 1 }, Value::Bool(value)) => Ok(F::from(*value as u64)),
        (ShareType::SecretInt { bit_length: 1 }, Value::I64(value)) => {
            Ok(F::from((*value != 0) as u64))
        }
        (ShareType::SecretInt { .. }, Value::I64(value)) => Ok(i64_to_field::<F>(*value)),
        (ShareType::SecretInt { .. }, Value::U64(value)) => {
            let value = i64::try_from(*value).map_err(|_| {
                Error::InvalidInput("u64 secret integer input exceeds i64 range".to_owned())
            })?;
            Ok(i64_to_field::<F>(value))
        }
        // `Value::Bytes` is the full-width field input path used by protocols
        // such as blinded OPRFs. Integer SDK values remain intentionally
        // bounded, while canonical field scalars can use the entire Fr domain.
        (ShareType::SecretInt { bit_length }, Value::Bytes(value)) if bit_length > 1 => {
            canonical_field_from_be_bytes::<F>(value, curve)
        }
        (ShareType::SecretUInt { .. }, Value::Bytes(value)) => {
            canonical_field_from_be_bytes::<F>(value, curve)
        }
        (ShareType::SecretUInt { bit_length }, Value::U64(value)) => {
            validate_secret_uint_range(*value, bit_length)?;
            Ok(F::from(*value))
        }
        (ShareType::SecretUInt { bit_length }, Value::I64(value)) => {
            let value = u64::try_from(*value).map_err(|_| {
                Error::InvalidInput(
                    "signed input for secret unsigned integer must be non-negative".to_owned(),
                )
            })?;
            validate_secret_uint_range(value, bit_length)?;
            Ok(F::from(value))
        }
        (ShareType::SecretFixedPoint { precision }, value) => Ok(i64_to_field::<F>(
            encode_fixed_point_value(value, precision)?,
        )),
        _ => Err(Error::InvalidInput(format!(
            "value kind '{}' is not compatible with share type {share_type:?}",
            value.kind()
        ))),
    }
}

fn canonical_field_from_be_bytes<F: PrimeField>(bytes: &[u8], curve: Curve) -> Result<F> {
    use ark_ff::BigInteger;

    let field_bytes = F::MODULUS_BIT_SIZE.div_ceil(8) as usize;
    if bytes.len() != field_bytes {
        return Err(Error::InvalidInput(format!(
            "{curve} field input must be exactly {field_bytes} canonical big-endian bytes, got {}",
            bytes.len()
        )));
    }

    let value = F::from_be_bytes_mod_order(bytes);
    let encoded = value.into_bigint().to_bytes_be();
    let mut canonical = vec![0u8; field_bytes];
    let start = field_bytes
        .checked_sub(encoded.len())
        .ok_or_else(|| Error::InvalidInput(format!("{curve} field input is not canonical")))?;
    canonical[start..].copy_from_slice(&encoded);
    if canonical.as_slice() != bytes {
        return Err(Error::InvalidInput(format!(
            "{curve} field input must be less than the scalar-field modulus"
        )));
    }
    Ok(value)
}

fn validate_secret_uint_range(value: u64, bit_length: usize) -> Result<()> {
    if bit_length >= 64 {
        return Ok(());
    }
    let max = (1u64 << bit_length) - 1;
    if value <= max {
        Ok(())
    } else {
        Err(Error::InvalidInput(format!(
            "secret unsigned integer input {value} does not fit in {bit_length} bit(s)"
        )))
    }
}

fn i64_to_field<F: PrimeField>(value: i64) -> F {
    stoffel_vm::net::curve::field_from_i64(value)
}

fn field_to_i64<F: PrimeField>(value: F) -> Result<i64> {
    let positive = value.into_bigint();
    if positive.as_ref()[1..].iter().all(|limb| *limb == 0)
        && positive.as_ref()[0] <= i64::MAX as u64
    {
        return Ok(positive.as_ref()[0] as i64);
    }

    let negative = (-value).into_bigint();
    if negative.as_ref()[1..].iter().all(|limb| *limb == 0)
        && negative.as_ref()[0] <= i64::MAX as u64 + 1
    {
        let magnitude = negative.as_ref()[0];
        return if magnitude == (i64::MAX as u64 + 1) {
            Ok(i64::MIN)
        } else {
            Ok(-(magnitude as i64))
        };
    }

    Err(Error::InvalidInput(
        "field output cannot be represented as i64".to_owned(),
    ))
}

fn field_to_u64<F: PrimeField>(value: F, bit_length: usize) -> Result<u64> {
    let positive = value.into_bigint();
    if positive.as_ref()[1..].iter().all(|limb| *limb == 0) {
        let value = positive.as_ref()[0];
        validate_secret_uint_range(value, bit_length)?;
        return Ok(value);
    }

    Err(Error::InvalidInput(
        "field output cannot be represented as u64".to_owned(),
    ))
}

fn field_to_value<F: PrimeField>(value: F, share_type: ShareType) -> Result<Value> {
    match share_type {
        ShareType::SecretInt { bit_length: 1 } => Ok(Value::Bool(!value.is_zero())),
        ShareType::SecretInt { .. } => Ok(Value::I64(field_to_i64(value)?)),
        ShareType::SecretUInt { bit_length } => Ok(Value::U64(field_to_u64(value, bit_length)?)),
        ShareType::SecretFixedPoint { precision } => {
            let scaled = field_to_i64(value)?;
            Ok(Value::Float(decode_fixed_point_value(scaled, precision)?))
        }
    }
}

fn outputs_to_values<F: PrimeField>(
    outputs: Vec<F>,
    output_types: &[ShareType],
) -> Result<Vec<Value>> {
    if outputs.len() != output_types.len() {
        return Err(Error::InvalidInput(format!(
            "expected {} outputs, got {}",
            output_types.len(),
            outputs.len()
        )));
    }
    outputs
        .into_iter()
        .zip(output_types.iter().copied())
        .map(|(output, share_type)| field_to_value(output, share_type))
        .collect()
}

#[allow(dead_code)]
fn bound_outputs_to_values<F: PrimeField>(
    outputs: Vec<(u64, F)>,
    output_types: &[ShareType],
) -> Result<Vec<Value>> {
    if outputs.len() != output_types.len() {
        return Err(Error::InvalidInput(format!(
            "expected {} assigned outputs, got {}",
            output_types.len(),
            outputs.len()
        )));
    }
    let mut values = outputs
        .into_iter()
        .map(|(output_ordinal, share)| {
            let share_type = output_types
                .get(output_ordinal as usize)
                .copied()
                .ok_or_else(|| {
                    Error::InvalidInput(format!(
                        "assigned output ordinal {} is out of range",
                        output_ordinal
                    ))
                })?;
            let value = field_to_value(share, share_type)?;
            Ok((output_ordinal, value))
        })
        .collect::<Result<Vec<_>>>()?;
    values.sort_by_key(|(ordinal, _)| *ordinal);
    Ok(values.into_iter().map(|(_, value)| value).collect())
}

mod duration_millis {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(duration: &Duration, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(
            duration
                .as_millis()
                .try_into()
                .map_err(|_| serde::ser::Error::custom("duration milliseconds exceed u64 range"))?,
        )
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}

#[derive(Debug, Clone)]
pub struct ComputationHandle {
    state: Arc<Mutex<ComputationState>>,
    notify: Arc<tokio::sync::Notify>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputationSummary {
    pub status: ComputationStatus,
    pub has_result: bool,
    pub result_count: usize,
}

#[derive(Debug)]
struct ComputationState {
    status: ComputationStatus,
    result: Option<Result<Vec<Value>>>,
    awaitable: bool,
}

impl ComputationHandle {
    pub fn pending() -> Self {
        Self {
            state: Arc::new(Mutex::new(ComputationState {
                status: ComputationStatus::Pending,
                result: None,
                awaitable: false,
            })),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    fn submitted() -> Self {
        Self {
            state: Arc::new(Mutex::new(ComputationState {
                status: ComputationStatus::Pending,
                result: None,
                awaitable: true,
            })),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    pub fn completed(result: Vec<Value>) -> Self {
        Self {
            state: Arc::new(Mutex::new(ComputationState {
                status: ComputationStatus::Completed,
                result: Some(Ok(result)),
                awaitable: true,
            })),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    #[tracing::instrument(skip_all)]
    pub async fn await_result(self) -> Result<Vec<Value>> {
        loop {
            let result = {
                let state = self.state.lock().map_err(|_| {
                    Error::Computation("computation handle state lock was poisoned".to_owned())
                })?;
                match (state.status, state.result.as_ref()) {
                    (ComputationStatus::Cancelled, _) => Some(Err(Error::Computation(
                        "computation was cancelled".to_owned(),
                    ))),
                    (_, Some(Ok(result))) => Some(Ok(result.clone())),
                    (_, Some(Err(error))) => Some(Err(clone_error_for_handle(error))),
                    (ComputationStatus::Pending, None) if !state.awaitable => {
                        Some(Err(Error::Unsupported(
                            "computation has not been submitted to a live network".to_owned(),
                        )))
                    }
                    _ => None,
                }
            };
            if let Some(result) = result {
                return result;
            }
            self.notify.notified().await;
        }
    }

    pub fn cancel(&self) {
        if let Ok(mut state) = self.state.lock() {
            if state.status == ComputationStatus::Pending {
                state.status = ComputationStatus::Cancelled;
                state.result = None;
                self.notify.notify_waiters();
            }
        }
    }

    pub(crate) fn complete(&self, result: Result<Vec<Value>>) {
        if let Ok(mut state) = self.state.lock() {
            if state.status == ComputationStatus::Pending {
                state.status = ComputationStatus::Completed;
                state.result = Some(result);
                self.notify.notify_waiters();
            }
        }
    }

    pub fn status(&self) -> ComputationStatus {
        self.state
            .lock()
            .map(|state| state.status)
            .unwrap_or(ComputationStatus::Cancelled)
    }

    pub fn summary(&self) -> ComputationSummary {
        self.state
            .lock()
            .map(|state| ComputationSummary {
                status: state.status,
                has_result: state.result.as_ref().is_some_and(|result| result.is_ok()),
                result_count: state
                    .result
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .map_or(0, Vec::len),
            })
            .unwrap_or(ComputationSummary {
                status: ComputationStatus::Cancelled,
                has_result: false,
                result_count: 0,
            })
    }

    pub fn is_pending(&self) -> bool {
        self.status() == ComputationStatus::Pending
    }

    pub fn is_completed(&self) -> bool {
        self.status() == ComputationStatus::Completed
    }

    pub fn is_cancelled(&self) -> bool {
        self.status() == ComputationStatus::Cancelled
    }
}

fn clone_error_for_handle(error: &Error) -> Error {
    match error {
        Error::Compilation(message) => Error::Compilation(message.clone()),
        Error::Configuration(message) => Error::Configuration(message.clone()),
        Error::Network(error) => Error::NetworkConnection(error.to_string()),
        Error::NetworkConnection(message) => Error::NetworkConnection(message.clone()),
        Error::Consensus(error) => Error::Computation(error.to_string()),
        Error::Coordinator(error) => Error::Coordinator(error.clone()),
        Error::Preprocessing(message) => Error::Preprocessing(message.clone()),
        Error::Computation(message) => Error::Computation(message.clone()),
        Error::FunctionNotFound(name) => Error::FunctionNotFound(name.clone()),
        Error::InvalidInput(message) => Error::InvalidInput(message.clone()),
        Error::Unsupported(message) => Error::Unsupported(message.clone()),
        Error::Io(error) => Error::Io(std::io::Error::new(error.kind(), error.to_string())),
        Error::Bytecode(message) => Error::Bytecode(message.clone()),
        Error::ConfigParse(error) => Error::Configuration(error.to_string()),
        Error::ConfigSerialize(error) => Error::Configuration(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offchain_client_builder_carries_the_execution_namespace() {
        let execution_id = ExecutionId::from_bytes([0x5a; 32]);
        let builder = OffChainClientConfigBuilder::default().execution_id(execution_id);

        assert_eq!(builder.execution_id, Some(execution_id));
    }

    #[test]
    fn secret_uint_values_encode_and_decode_as_unsigned() -> Result<()> {
        let share_type = ShareType::secret_uint(8);
        let field = value_to_field::<Fr>(&Value::U64(255), share_type, Curve::Bls12_381)?;
        assert_eq!(field_to_value(field, share_type)?, Value::U64(255));
        Ok(())
    }

    #[test]
    fn secret_uint_encoding_rejects_negative_or_out_of_range_values() {
        let share_type = ShareType::secret_uint(8);

        assert!(value_to_field::<Fr>(&Value::I64(-1), share_type, Curve::Bls12_381).is_err());
        assert!(value_to_field::<Fr>(&Value::U64(256), share_type, Curve::Bls12_381).is_err());
    }

    #[test]
    fn fixed_point_values_use_semantic_manifest_encoding() -> Result<()> {
        let share_type = ShareType::default_secret_fixed_point();

        let integer = value_to_field::<Fr>(&Value::I64(1), share_type, Curve::Bls12_381)?;
        let fractional = value_to_field::<Fr>(&Value::Float(1.5), share_type, Curve::Bls12_381)?;

        assert_eq!(integer, Fr::from(65_536u64));
        assert_eq!(fractional, Fr::from(98_304u64));
        assert_eq!(field_to_value(fractional, share_type)?, Value::Float(1.5));
        Ok(())
    }

    #[test]
    fn full_width_field_bytes_are_accepted_for_integer_shares() -> Result<()> {
        use ark_ff::{BigInteger, PrimeField};

        let expected = Fr::from(42u64);
        let encoded = expected.into_bigint().to_bytes_be();
        let mut canonical = vec![0u8; 32];
        canonical[32 - encoded.len()..].copy_from_slice(&encoded);

        assert_eq!(
            value_to_field::<Fr>(
                &Value::Bytes(canonical),
                ShareType::default_secret_int(),
                Curve::Bls12_381,
            )?,
            expected
        );
        Ok(())
    }

    #[test]
    fn full_width_field_bytes_must_be_canonical() {
        use ark_ff::{BigInteger, PrimeField};

        let modulus = Fr::MODULUS.to_bytes_be();
        let mut encoded = vec![0u8; 32];
        encoded[32 - modulus.len()..].copy_from_slice(&modulus);

        assert!(value_to_field::<Fr>(
            &Value::Bytes(encoded),
            ShareType::default_secret_int(),
            Curve::Bls12_381,
        )
        .is_err());
    }

    #[test]
    fn full_width_field_bytes_are_curve_generic() -> Result<()> {
        fn check<F: PrimeField>(curve: Curve) -> Result<()> {
            use ark_ff::BigInteger;

            let expected = F::from(42u64);
            let encoded = expected.into_bigint().to_bytes_be();
            let field_bytes = F::MODULUS_BIT_SIZE.div_ceil(8) as usize;
            let mut canonical = vec![0u8; field_bytes];
            canonical[field_bytes - encoded.len()..].copy_from_slice(&encoded);
            assert_eq!(
                value_to_field::<F>(
                    &Value::Bytes(canonical),
                    ShareType::default_secret_int(),
                    curve,
                )?,
                expected
            );
            Ok(())
        }

        check::<ark_bls12_381::Fr>(Curve::Bls12_381)?;
        check::<ark_bn254::Fr>(Curve::Bn254)?;
        check::<ark_curve25519::Fr>(Curve::Curve25519)?;
        check::<ark_ed25519::Fr>(Curve::Ed25519)?;
        check::<ark_secp256k1::Fr>(Curve::Secp256k1)?;
        check::<ark_secp256r1::Fr>(Curve::Secp256r1)?;
        Ok(())
    }
}
