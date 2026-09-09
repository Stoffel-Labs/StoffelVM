//! Reference Rust SDK for building Stoffel MPC applications.
//!
//! The SDK provides a small public entry point, [`Stoffel`], for compiling
//! Stoffel-Lang programs, loading bytecode, configuring MPC runtime settings,
//! executing local development programs, and constructing client/server
//! participants.
//!
//! ```
//! use stoffel::prelude::*;
//!
//! # fn main() -> stoffel::Result<()> {
//! let result = Stoffel::compile(
//!     "def main(a: int64, b: int64) -> int64:\n  return a + b",
//! )?
//! .with_inputs(&[("a", 42_i64), ("b", 58_i64)])
//! .execute_clear()?;
//!
//! assert_eq!(result[0].as_i64(), Some(100));
//! # Ok(())
//! # }
//! ```
//!
//! Local MPC development uses the same builder, but delegates to
//! `stoffel-vm`'s real localhost coordinator runner and a built `stoffel-run`
//! binary instead of simulating the protocol in the SDK:
//!
//! ```no_run
//! use stoffel::prelude::*;
//!
//! # async fn example() -> stoffel::Result<()> {
//! let result = Stoffel::compile(
//!     "def main() -> int64:\n  var share = ClientStore.take_share(0, 0)\n  return share.open()",
//! )?
//! .parties(5)
//! .threshold(1)
//! .with_client_input(0, &[42_i64])
//! .execute_local()
//! .await?;
//!
//! assert_eq!(result[0].as_i64(), Some(42));
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

pub mod backend;
pub mod client;
mod client_value_codec;
pub mod compiler;
pub mod config;
pub mod consensus;
pub mod coordinator;
pub mod error;
pub mod input_file;
pub mod networking;
pub mod observability;
pub mod prelude;
pub mod program;
pub mod runtime;
pub mod server;
pub mod types;
pub mod vm;

use std::path::{Path, PathBuf};
use std::time::Duration;

pub use backend::{
    avss::{AvssBackend, AvssEngine},
    honeybadger::HoneyBadgerBackend,
    Backend, MpcBackend,
};
pub use client::{
    ClientBuilder, ClientState, ClientSummary, ComputationHandle, ComputationStatus,
    ComputationSummary, OffChainClientConfig, OffChainClientConfigBuilder, StoffelClient,
};
pub use compiler::CompilationOptions;
pub use config::{
    Curve, MpcConfig, MpcConfigBuilder, MpcConfigSummary, MpcSection, NetworkConfig,
    NetworkConfigBuilder, NetworkConfigSummary, NetworkDeployment, NetworkDeploymentBuilder,
    NetworkSection, PreprocessingConfig,
};
pub use consensus::{ConsensusGate, NodePublicKey, VerifiedOrdering};
pub use coordinator::{
    Coordinator, ExecutionId, OffChainCoordinator, OffChainCoordinatorClient,
    OffChainCoordinatorServer, ShareBound,
};
pub use error::{ConsensusError, CoordinatorError, Error, ErrorCategory, NetworkError, Result};
pub use input_file::{load_client_inputs_file, load_named_inputs_file};
pub use networking::{NetworkManager, QuicNetworkConfig, QuicNetworkManager};
pub use observability::{
    init_tracing, HealthStatus, OpenTelemetryGuard, ServerMetrics, ServerMetricsSnapshot,
    TracingConfig, TracingConfigBuilder, TracingConfigSummary,
};
pub use program::{
    BytecodeSummary, ClientMetadata, ClientMetadataSummary, FunctionMetadata, FunctionSummary,
    Program, ProgramSummary,
};
pub use runtime::{LocalNetworkBuilder, RuntimeSummary, StoffelRuntime};
pub use server::{
    OffChainServerConfig, OffChainServerConfigBuilder, ServerBuilder, ServerState, ServerSummary,
    StoffelServer,
};
pub use stoffel_vm_types::compiled_binary::FunctionType;
pub use stoffel_vm_types::core_types::{ShareDataFormat, ShareType};
pub use types::{
    ClientId, ClientInputValue, ClientOutputValue, ClientValueType, FieldElement,
    GeneratedProgramManifest, GroupElement, MaskIndex, PartyId, ProgramArgs, PublicKey, Round,
    Share, TypedClientInputs, TypedClientOutputs, Value, ValueSummary,
};
pub use vm::{LocalClientOutput, LocalPartyShareOutput, LocalShareExecutionOutput, OpaqueShare};

#[derive(Debug, Clone)]
enum ProgramSource {
    Source { source: String, filename: String },
    File { path: std::path::PathBuf },
    Bytecode(Vec<u8>),
    Program(Program),
}

/// Inputs accepted by [`Stoffel::load_program`].
pub trait LoadableProgram {
    fn load_program(self) -> Result<Program>;
}

impl LoadableProgram for Program {
    fn load_program(self) -> Result<Program> {
        Ok(self)
    }
}

impl LoadableProgram for &Program {
    fn load_program(self) -> Result<Program> {
        Ok(self.clone())
    }
}

impl LoadableProgram for &[u8] {
    fn load_program(self) -> Result<Program> {
        Program::from_bytecode(self)
    }
}

impl LoadableProgram for Vec<u8> {
    fn load_program(self) -> Result<Program> {
        Program::from_bytecode(&self)
    }
}

impl LoadableProgram for &Path {
    fn load_program(self) -> Result<Program> {
        Program::from_bytecode_file(self)
    }
}

impl LoadableProgram for PathBuf {
    fn load_program(self) -> Result<Program> {
        Program::from_bytecode_file(self)
    }
}

impl LoadableProgram for &PathBuf {
    fn load_program(self) -> Result<Program> {
        Program::from_bytecode_file(self)
    }
}

/// SDK entry point and builder.
#[derive(Debug, Clone)]
pub struct Stoffel {
    source: Option<ProgramSource>,
    mpc_config: MpcConfig,
    backend_explicit: bool,
    network_config: Option<NetworkConfig>,
    local_runner_path: Option<PathBuf>,
    config_error: Option<String>,
    inputs: Vec<(String, Value)>,
    client_inputs: Vec<(u64, Vec<Value>)>,
    expected_clients: Option<usize>,
    client_output_counts: std::collections::HashMap<u64, u64>,
    compiler_options: CompilationOptions,
}

impl Stoffel {
    /// Compile a Stoffel-Lang source string.
    pub fn compile(source: &str) -> Result<Self> {
        Ok(Self::from_source(ProgramSource::Source {
            source: source.to_owned(),
            filename: "<sdk>".to_owned(),
        }))
    }

    /// Compile a Stoffel-Lang file.
    pub fn compile_file(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self::from_source(ProgramSource::File {
            path: path.as_ref().to_path_buf(),
        }))
    }

    /// Load serialized Stoffel bytecode.
    pub fn load(bytecode: &[u8]) -> Result<Self> {
        Ok(Self::from_source(ProgramSource::Bytecode(
            bytecode.to_vec(),
        )))
    }

    /// Load serialized Stoffel bytecode from a file.
    pub fn load_file(path: impl AsRef<Path>) -> Result<Self> {
        let bytecode = std::fs::read(path)?;
        Self::load(&bytecode)
    }

    /// Load an executable program directly from bytecode, a bytecode path, or
    /// an already constructed [`Program`].
    ///
    /// ```
    /// use stoffel::prelude::*;
    ///
    /// # fn main() -> stoffel::Result<()> {
    /// let bytecode = Stoffel::compile(
    ///     "def main(a: int64, b: int64) -> int64:\n  return a + b",
    /// )?
    /// .build()?
    /// .to_bytecode()?;
    ///
    /// let program = Stoffel::load_program(bytecode)?;
    /// let result = program.execute("main", (40_i64, 2_i64))?;
    ///
    /// assert_eq!(result[0].as_i64(), Some(42));
    /// # Ok(())
    /// # }
    /// ```
    pub fn load_program(program: impl LoadableProgram) -> Result<StoffelRuntime> {
        Self::from_source(ProgramSource::Program(program.load_program()?)).build()
    }

    /// Set the number of MPC parties. Default is 5.
    pub fn parties(mut self, n: usize) -> Self {
        self.mpc_config.parties = n;
        self
    }

    /// Set the Byzantine threshold. Default is 1.
    pub fn threshold(mut self, t: usize) -> Self {
        self.mpc_config.threshold = t;
        self
    }

    /// Set the MPC instance identifier. Default is generated from process-local time.
    pub fn instance_id(mut self, id: u64) -> Self {
        self.mpc_config.instance_id = id;
        self
    }

    /// Select an MPC backend. Default is HoneyBadger.
    pub fn backend(mut self, backend: MpcBackend) -> Self {
        self.mpc_config.backend = backend;
        self.backend_explicit = true;
        self
    }

    /// Select the backend and curve declared by generated program bindings.
    pub fn manifest<M: GeneratedProgramManifest>(self) -> Self {
        self.backend(M::BACKEND)
    }

    /// Select the HoneyBadger backend.
    pub fn honeybadger(mut self) -> Self {
        self.mpc_config.backend = MpcBackend::HoneyBadger;
        self.backend_explicit = true;
        self
    }

    /// Select the AVSS backend with the given curve.
    pub fn avss(mut self, curve: Curve) -> Self {
        self.mpc_config.backend = MpcBackend::Avss { curve };
        self.backend_explicit = true;
        self
    }

    /// Select the AVSS curve. This also selects the AVSS backend.
    pub fn curve(mut self, curve: Curve) -> Self {
        self.mpc_config.backend = MpcBackend::Avss { curve };
        self.backend_explicit = true;
        self
    }

    /// Enable or disable compiler optimizations.
    pub fn optimize(mut self, enabled: bool) -> Self {
        self.compiler_options.optimize = enabled;
        self
    }

    /// Set the compiler optimization level (0-3).
    pub fn optimization_level(mut self, level: u8) -> Self {
        self.compiler_options.optimization_level = level;
        if level > 0 {
            self.compiler_options.optimize = true;
        }
        self
    }

    /// Print compiler intermediate representations while compiling.
    pub fn print_ir(mut self, enabled: bool) -> Self {
        self.compiler_options.print_ir = enabled;
        self
    }

    /// Replace all Stoffel-Lang compiler options carried by this builder.
    pub fn compiler_options(mut self, options: CompilationOptions) -> Self {
        self.compiler_options = options;
        self
    }

    /// Preserve additional named functions as executable entrypoints when
    /// compiling source. This is useful for programs that expose more than
    /// `main` through generated bindings.
    pub fn entry_points<I, S>(mut self, entry_points: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.compiler_options.entry_points = entry_points.into_iter().map(Into::into).collect();
        self
    }

    /// Attach named inputs for local execution.
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

    /// Attach one named input for local execution.
    pub fn with_input<V>(mut self, name: impl Into<String>, value: V) -> Self
    where
        V: Into<Value>,
    {
        self.inputs.push((name.into(), value.into()));
        self
    }

    /// Replace named inputs with values loaded from a `.json`, `.csv`, or `.txt` file.
    pub fn with_input_file(mut self, path: impl AsRef<Path>) -> Result<Self> {
        self.inputs = input_file::load_named_inputs_file(path)?;
        Ok(self)
    }

    /// Attach one coordinator client input set for local networked execution.
    ///
    /// This is distinct from named function parameters. It feeds programs that
    /// read secret client values through `ClientStore`. Values are semantic:
    /// fixed-point positions declared by the program manifest are scaled
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
        self.client_inputs = input_file::load_client_inputs_file(path)?;
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

    /// Provide the number of output values a client receives via
    /// `send_to_client`, for the local simulator. This is a **fallback**: when
    /// the program statically declares the client's outputs (recorded in the
    /// client-IO manifest), that count is used instead. Needed only when the
    /// program sends to a slot the compiler cannot resolve statically.
    pub fn client_output_count(mut self, client_slot: u64, count: u64) -> Self {
        self.client_output_counts.insert(client_slot, count);
        self
    }

    /// Attach explicit network configuration.
    pub fn network_config(mut self, config: NetworkConfig) -> Self {
        self.network_config = Some(config);
        self
    }

    /// Load network configuration from a TOML file.
    pub fn network_config_file(mut self, path: impl AsRef<Path>) -> Self {
        match NetworkConfig::from_toml_file(path) {
            Ok(config) => self.network_config = Some(config),
            Err(error) => self.config_error = Some(error.to_string()),
        }
        self
    }

    /// Set the `stoffel-run` binary path used by local coordinator execution.
    pub fn local_runner_path(mut self, path: impl AsRef<Path>) -> Self {
        self.local_runner_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Build a runtime from the configured program and MPC settings.
    pub fn build(self) -> Result<StoffelRuntime> {
        if let Some(error) = self.config_error {
            return Err(Error::Configuration(error));
        }
        let mut mpc_config = self.mpc_config;
        let mut backend_explicit = self.backend_explicit;
        if let Some(config) = &self.network_config {
            mpc_config = config.to_mpc_config(mpc_config.instance_id)?;
            backend_explicit = true;
        }
        mpc_config.validate()?;

        let source = self
            .source
            .ok_or_else(|| Error::Configuration("no program source configured".to_owned()))?;
        let program = match source {
            ProgramSource::Source { source, filename } => compiler::compile_source_with_options(
                &source,
                &filename,
                mpc_config.backend,
                self.compiler_options,
            )?,
            ProgramSource::File { path } => compiler::compile_file_with_options(
                &path,
                mpc_config.backend,
                self.compiler_options,
            )?,
            ProgramSource::Bytecode(bytecode) => {
                let program = Program::from_bytecode(&bytecode)?;
                let bytecode_backend =
                    backend_from_bytecode(program.bytecode_backend(), program.bytecode_curve())?;
                if backend_explicit {
                    validate_bytecode_backend(&program, mpc_config.backend)?;
                } else {
                    mpc_config.backend = bytecode_backend;
                }
                program
            }
            ProgramSource::Program(program) => {
                let bytecode_backend =
                    backend_from_bytecode(program.bytecode_backend(), program.bytecode_curve())?;
                if backend_explicit {
                    validate_bytecode_backend(&program, mpc_config.backend)?;
                } else {
                    mpc_config.backend = bytecode_backend;
                }
                program
            }
        };
        validate_bytecode_backend(&program, mpc_config.backend)?;
        if program.is_empty() {
            return Err(Error::Configuration(
                "program must contain at least one function".to_owned(),
            ));
        }
        if let Some(expected_clients) = self.expected_clients {
            if expected_clients == 0 {
                return Err(Error::Configuration(
                    "expected_clients must be greater than 0".to_owned(),
                ));
            }
            program.validate_expected_clients(expected_clients)?;
        }
        if let Some(config) = &self.network_config {
            validate_program_network_config(&program, config)?;
        }
        let mut runtime = StoffelRuntime::new(
            program,
            Some(mpc_config),
            self.network_config,
            self.local_runner_path,
            self.inputs,
            self.client_inputs,
            self.expected_clients,
        );
        runtime.set_client_output_counts(self.client_output_counts);
        Ok(runtime)
    }

    /// Validate attached coordinator client inputs against compiled program metadata.
    pub fn validate_client_inputs(self) -> Result<()> {
        let runtime = self.build()?;
        runtime.validate_client_inputs()
    }

    /// Execute locally using real MPC nodes.
    ///
    /// This delegates to `stoffel-vm`'s local coordinator runner, which starts a
    /// real localhost party mesh via `stoffel-run`. HoneyBadger supports
    /// no-argument `ClientStore` entrypoints and named [`Self::with_inputs`]
    /// values, which are adapted into local coordinator client input by a
    /// generated bytecode wrapper. AVSS local execution supports no-input
    /// programs and BLS12-381 local client input through the same lower runner.
    #[tracing::instrument(skip_all)]
    pub async fn execute_local(self) -> Result<Vec<Value>> {
        self.execute_local_function("main").await
    }

    /// Execute a named function locally using real MPC nodes.
    #[tracing::instrument(skip_all, fields(function = name))]
    pub async fn execute_local_function(self, name: &str) -> Result<Vec<Value>> {
        let (runtime, entry) = self.build_for_local_execution(name)?;
        vm::execute_local(&runtime, &entry).await
    }

    /// Execute `main` locally when its VM return must remain secret-shared.
    ///
    /// Unlike [`Self::execute_local`], this method requires exactly one secret
    /// VM return share per party. It never compares or reconstructs payload
    /// bytes. Each share and that party's printed output are paired in a
    /// [`LocalPartyShareOutput`].
    pub async fn execute_local_returning_party_shares(self) -> Result<LocalShareExecutionOutput> {
        self.execute_local_function_returning_party_shares("main")
            .await
    }

    /// Named-function variant of [`Self::execute_local_returning_party_shares`].
    #[tracing::instrument(skip_all, fields(function = name))]
    pub async fn execute_local_function_returning_party_shares(
        self,
        name: &str,
    ) -> Result<LocalShareExecutionOutput> {
        let (runtime, entry) = self.build_for_local_execution(name)?;
        vm::execute_local_returning_party_shares(&runtime, &entry).await
    }

    /// Execute `main` locally and also return the program's printed output.
    ///
    /// Useful when the result a client cares about is emitted with `print`
    /// (e.g. a 16-byte cipher block) rather than returned as a scalar — a
    /// returned aggregate such as a `list` only comes back as an opaque handle.
    pub async fn execute_local_capturing_output(self) -> Result<(Vec<Value>, String)> {
        self.execute_local_function_capturing_output("main").await
    }

    /// Execute a named function locally and also return its printed output.
    #[tracing::instrument(skip_all, fields(function = name))]
    pub async fn execute_local_function_capturing_output(
        self,
        name: &str,
    ) -> Result<(Vec<Value>, String)> {
        let (runtime, entry) = self.build_for_local_execution(name)?;
        let (values, program_output, _client_outputs) =
            vm::execute_local_capturing_with_options(&runtime, &entry, Default::default()).await?;
        Ok((values, program_output))
    }

    /// Execute `main` locally and return the **client outputs** delivered via
    /// `send_to_client`, reconstructed by the off-chain client (alongside the
    /// VM return values). This is the value a client actually receives — not a
    /// public reveal to the compute nodes.
    pub async fn execute_local_capturing_client_outputs(
        self,
    ) -> Result<(Vec<Value>, Vec<vm::LocalClientOutput>)> {
        self.execute_local_function_capturing_client_outputs("main")
            .await
    }

    /// Named-function variant of [`Self::execute_local_capturing_client_outputs`].
    #[tracing::instrument(skip_all, fields(function = name))]
    pub async fn execute_local_function_capturing_client_outputs(
        self,
        name: &str,
    ) -> Result<(Vec<Value>, Vec<vm::LocalClientOutput>)> {
        let (runtime, entry) = self.build_for_local_execution(name)?;
        let (values, _program_output, client_outputs) =
            vm::execute_local_capturing_with_options(&runtime, &entry, Default::default()).await?;
        Ok((values, client_outputs))
    }

    /// Execute `main` locally with an explicit timeout and return reconstructed
    /// client outputs delivered via `send_to_client`.
    pub async fn execute_local_capturing_client_outputs_with_timeout(
        self,
        timeout: Duration,
    ) -> Result<(Vec<Value>, Vec<vm::LocalClientOutput>)> {
        self.execute_local_function_capturing_client_outputs_with_timeout("main", timeout)
            .await
    }

    /// Named-function variant of
    /// [`Self::execute_local_capturing_client_outputs_with_timeout`].
    #[tracing::instrument(skip_all, fields(function = name))]
    pub async fn execute_local_function_capturing_client_outputs_with_timeout(
        self,
        name: &str,
        timeout: Duration,
    ) -> Result<(Vec<Value>, Vec<vm::LocalClientOutput>)> {
        if timeout.is_zero() {
            return Err(Error::Configuration(
                "local network timeout must be greater than zero".to_owned(),
            ));
        }
        let (runtime, entry) = self.build_for_local_execution(name)?;
        let (values, _program_output, client_outputs) = vm::execute_local_capturing_with_options(
            &runtime,
            &entry,
            vm::LocalExecutionOptions {
                runner_path: None,
                timeout: Some(timeout),
            },
        )
        .await?;
        Ok((values, client_outputs))
    }

    /// Execute locally using real MPC nodes with an explicit coordinator timeout.
    #[tracing::instrument(skip_all)]
    pub async fn execute_local_with_timeout(self, timeout: Duration) -> Result<Vec<Value>> {
        self.execute_local_function_with_timeout("main", timeout)
            .await
    }

    /// Execute a named function locally using real MPC nodes with an explicit
    /// coordinator timeout.
    #[tracing::instrument(skip_all, fields(function = name))]
    pub async fn execute_local_function_with_timeout(
        self,
        name: &str,
        timeout: Duration,
    ) -> Result<Vec<Value>> {
        if timeout.is_zero() {
            return Err(Error::Configuration(
                "local network timeout must be greater than zero".to_owned(),
            ));
        }
        let (runtime, entry) = self.build_for_local_execution(name)?;
        vm::execute_local_with_options(
            &runtime,
            &entry,
            vm::LocalExecutionOptions {
                runner_path: None,
                timeout: Some(timeout),
            },
        )
        .await
    }

    /// Execute a cleartext Stoffel program with the embedded VM.
    ///
    /// This is intended for local development of non-secret logic. Secret MPC
    /// programs should use [`Self::execute_local`], which is reserved for the
    /// PRD's full multi-node localhost execution model.
    pub fn execute_clear(self) -> Result<Vec<Value>> {
        self.execute_clear_function("main")
    }

    /// Execute a named cleartext function with the embedded VM.
    pub fn execute_clear_function(self, name: &str) -> Result<Vec<Value>> {
        let runtime = self.build()?;
        vm::execute_clear(&runtime, name)
    }

    /// Create a server builder without compiling a program.
    pub fn server(party_id: usize) -> ServerBuilder {
        ServerBuilder::new(party_id)
    }

    /// Create a client builder.
    pub fn client() -> ClientBuilder {
        ClientBuilder::new()
    }

    fn from_source(source: ProgramSource) -> Self {
        Self {
            source: Some(source),
            mpc_config: MpcConfig::default(),
            backend_explicit: false,
            network_config: None,
            local_runner_path: None,
            config_error: None,
            inputs: Vec::new(),
            client_inputs: Vec::new(),
            expected_clients: None,
            client_output_counts: std::collections::HashMap::new(),
            compiler_options: CompilationOptions::default(),
        }
    }

    fn build_for_local_execution(self, name: &str) -> Result<(StoffelRuntime, String)> {
        if self.inputs.is_empty() {
            return Ok((self.build()?, name.to_owned()));
        }
        if !self.client_inputs.is_empty() {
            return Err(Error::Configuration(
                "`with_inputs` and `with_client_input` cannot be combined for local execution"
                    .to_owned(),
            ));
        }
        let source_parameter_types = local_source_parameter_types(&self.source, name)?;
        let mut probe = self.clone();
        probe.inputs.clear();
        let probe_runtime = probe.build()?;
        if probe_runtime.program().has_client_input_metadata() {
            return Err(Error::Unsupported(
                "SDK local named-input adapter does not support programs that already declare ClientStore input metadata"
                    .to_owned(),
            ));
        }

        let function = probe_runtime
            .program()
            .function(name)
            .ok_or_else(|| Error::FunctionNotFound(name.to_owned()))?;
        let ordered_inputs =
            ordered_inputs_for_parameters(&self.inputs, name, function.parameters())?;
        let entry = unique_local_entry_name(probe_runtime.program(), "__stoffel_sdk_local_entry");
        let input_shapes = ordered_inputs
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let source_marks_secret = source_parameter_types
                    .as_ref()
                    .and_then(|types| types.get(index))
                    .map(|ty| local_parameter_type_is_secret(ty));
                let bytecode_marks_secret = function
                    .parameter_types()
                    .get(index)
                    .map(function_type_is_secret);
                if source_marks_secret
                    .or(bytecode_marks_secret)
                    .unwrap_or(true)
                {
                    crate::program::LocalInputShape::secret_from_value(value)
                } else {
                    crate::program::LocalInputShape::clear_from_value(value)
                }
            })
            .collect::<Vec<_>>();
        let client_inputs = flatten_local_named_inputs(&ordered_inputs, &input_shapes)?;
        let wrapped_program =
            probe_runtime
                .program()
                .with_local_client_input_wrapper(name, &entry, &input_shapes)?;
        let local_client_inputs = if client_inputs.is_empty() {
            Vec::new()
        } else {
            vec![(0, client_inputs)]
        };
        Ok((
            probe_runtime.with_program_and_client_inputs(wrapped_program, local_client_inputs),
            entry,
        ))
    }
}

fn flatten_local_named_inputs(
    values: &[Value],
    shapes: &[crate::program::LocalInputShape],
) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for (value, shape) in values.iter().zip(shapes) {
        flatten_local_named_input(value, shape, &mut out)?;
    }
    Ok(out)
}

fn flatten_local_named_input(
    value: &Value,
    shape: &crate::program::LocalInputShape,
    out: &mut Vec<Value>,
) -> Result<()> {
    match (value, shape) {
        (_, crate::program::LocalInputShape::Clear(_)) => Ok(()),
        (Value::List(values), crate::program::LocalInputShape::List(shapes)) => {
            for (value, shape) in values.iter().zip(shapes) {
                flatten_local_named_input(value, shape, out)?;
            }
            Ok(())
        }
        (Value::Object(fields), crate::program::LocalInputShape::Object(shapes)) => {
            for (name, shape) in shapes {
                if let Some(value) = fields.get(name) {
                    flatten_local_named_input(value, shape, out)?;
                }
            }
            Ok(())
        }
        (_, crate::program::LocalInputShape::Share(_)) => {
            out.push(value.clone());
            Ok(())
        }
        _ => Err(Error::InvalidInput(
            "local named-input wrapper shape does not match input value".to_owned(),
        )),
    }
}

fn local_source_parameter_types(
    source: &Option<ProgramSource>,
    function_name: &str,
) -> Result<Option<Vec<String>>> {
    let Some(source) = source else {
        return Ok(None);
    };
    let source = match source {
        ProgramSource::Source { source, .. } => source.clone(),
        ProgramSource::File { path } => std::fs::read_to_string(path)?,
        ProgramSource::Bytecode(_) | ProgramSource::Program(_) => return Ok(None),
    };
    Ok(parse_function_parameter_types(&source, function_name))
}

fn parse_function_parameter_types(source: &str, function_name: &str) -> Option<Vec<String>> {
    let prefix = format!("def {function_name}(");
    let start = source.find(&prefix)? + prefix.len();
    let mut depth = 1usize;
    let mut end = start;
    for (offset, character) in source[start..].char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    end = start + offset;
                    break;
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return None;
    }

    let params = &source[start..end];
    let mut types = Vec::new();
    for param in split_parameter_list(params) {
        let (_, ty) = param.split_once(':')?;
        types.push(ty.trim().to_owned());
    }
    Some(types)
}

fn split_parameter_list(params: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut depth = 0usize;
    for (index, character) in params.char_indices() {
        match character {
            '[' | '(' => depth += 1,
            ']' | ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                let part = params[start..index].trim();
                if !part.is_empty() {
                    parts.push(part);
                }
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    let part = params[start..].trim();
    if !part.is_empty() {
        parts.push(part);
    }
    parts
}

fn local_parameter_type_is_secret(ty: &str) -> bool {
    ty.split(|character: char| {
        !(character.is_ascii_alphanumeric()
            || character == '_'
            || character == '['
            || character == ']')
    })
    .any(|token| token == "secret" || token == "Share" || token.contains("secret"))
}

fn function_type_is_secret(ty: &stoffel_vm_types::compiled_binary::FunctionType) -> bool {
    use stoffel_vm_types::compiled_binary::FunctionType;

    match ty {
        FunctionType::Secret(_) => true,
        FunctionType::List(element) => function_type_is_secret(element),
        FunctionType::Dict(key, value) => {
            function_type_is_secret(key) || function_type_is_secret(value)
        }
        FunctionType::Generic(_, arguments) => arguments.iter().any(function_type_is_secret),
        _ => false,
    }
}

fn ordered_inputs_for_parameters(
    inputs: &[(String, Value)],
    function_name: &str,
    parameters: &[String],
) -> Result<Vec<Value>> {
    for (name, _) in inputs {
        if !parameters.iter().any(|parameter| parameter == name) {
            return Err(Error::InvalidInput(format!(
                "unexpected input '{name}' for function '{function_name}'"
            )));
        }
    }

    let mut values = Vec::with_capacity(parameters.len());
    for parameter in parameters {
        let mut matches = inputs
            .iter()
            .filter(|(name, _)| name == parameter)
            .map(|(_, value)| value);
        let Some(value) = matches.next() else {
            return Err(Error::InvalidInput(format!(
                "missing input '{parameter}' for function '{function_name}'"
            )));
        };
        if matches.next().is_some() {
            return Err(Error::InvalidInput(format!(
                "duplicate input '{parameter}' for function '{function_name}'"
            )));
        }
        values.push(value.clone());
    }
    Ok(values)
}

fn unique_local_entry_name(program: &Program, base: &str) -> String {
    if program.function(base).is_none() {
        return base.to_owned();
    }
    for suffix in 1.. {
        let candidate = format!("{base}_{suffix}");
        if program.function(&candidate).is_none() {
            return candidate;
        }
    }
    unreachable!("unbounded suffix search should always find a unique function name")
}

fn backend_from_bytecode(
    backend: stoffel_vm_types::compiled_binary::MpcBackend,
    curve: stoffel_vm_types::compiled_binary::MpcCurve,
) -> Result<MpcBackend> {
    match backend {
        stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger => Ok(MpcBackend::HoneyBadger),
        stoffel_vm_types::compiled_binary::MpcBackend::Avss => Ok(MpcBackend::Avss {
            curve: curve_from_bytecode(curve),
        }),
    }
}

fn curve_from_bytecode(curve: stoffel_vm_types::compiled_binary::MpcCurve) -> Curve {
    match curve {
        stoffel_vm_types::compiled_binary::MpcCurve::Bls12_381 => Curve::Bls12_381,
        stoffel_vm_types::compiled_binary::MpcCurve::Bn254 => Curve::Bn254,
        stoffel_vm_types::compiled_binary::MpcCurve::Curve25519 => Curve::Curve25519,
        stoffel_vm_types::compiled_binary::MpcCurve::Ed25519 => Curve::Ed25519,
        stoffel_vm_types::compiled_binary::MpcCurve::Secp256k1 => Curve::Secp256k1,
        stoffel_vm_types::compiled_binary::MpcCurve::Secp256r1 => Curve::Secp256r1,
    }
}

fn validate_bytecode_backend(program: &Program, expected: MpcBackend) -> Result<()> {
    let actual = program.bytecode_backend();
    if actual != expected.compiler_backend() {
        return Err(Error::Configuration(format!(
            "bytecode MPC backend ({actual:?}) does not match runtime backend ({expected})"
        )));
    }
    let Some(expected_curve) = expected.curve() else {
        return Ok(());
    };
    let actual_curve = curve_from_bytecode(program.bytecode_curve());
    if actual_curve != expected_curve {
        return Err(Error::Configuration(format!(
            "bytecode AVSS curve ({actual_curve}) does not match runtime backend ({expected})"
        )));
    }
    Ok(())
}

fn validate_program_network_config(program: &Program, config: &NetworkConfig) -> Result<()> {
    config.validate_server_addresses()?;
    program.validate_expected_clients(config.network.expected_clients)
}
