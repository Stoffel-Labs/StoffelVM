use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ark_bls12_381::Fr;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use stoffel_mpc_coordinator_off_chain::tests::fake_coord::{
    HoneyBadgerCoordinatorConnection, HoneyBadgerCoordinatorRPCServerSharedBase,
};
use stoffel_mpc_coordinator_off_chain::{
    node_rpc::NodeRPCClient as OffChainNodeRPCClient, InputAssignment, OffChainCoordinatorClient,
    OffChainCoordinatorServer,
};
use stoffel_mpc_coordinator_shared::self_signed_certs;
use stoffel_mpc_coordinator_shared::{Coordinator, ExecutionId as CoordinatorExecutionId};
use stoffel_vm_types::compiled_binary::{utils::save_to_file, CompiledBinary};
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use x509_parser::prelude::{FromDer, X509Certificate};

use stoffel_vm::net::curve::SupportedMpcField;
use stoffel_vm::net::program_id_from_bytes;
use stoffel_vm::net::session::ExecutionId;
use stoffel_vm::net::{MpcBackendKind, MpcCurveConfig};

use crate::returned_share::{ReturnedShare, ReturnedShareParseError, RETURNED_SHARE_PREFIX_V1};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(180);
const DEFAULT_AUTH_TOKEN: &str = "stoffel-local-coordinator-runner";
const READINESS_POLL_INTERVAL: Duration = Duration::from_millis(20);
const PROCESS_EXIT_GRACE: Duration = Duration::from_secs(2);
const LOG_DRAIN_GRACE: Duration = Duration::from_secs(1);
const CHILD_KILL_GRACE: Duration = Duration::from_secs(1);
const CLEANUP_GRACE: Duration = Duration::from_secs(5);
const MAX_LOG_BYTES: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum LocalCoordinatorRunnerError {
    #[error("{source}\n\nParticipant cleanup diagnostics:\n{diagnostics}")]
    Cleanup {
        #[source]
        source: Box<LocalCoordinatorRunnerError>,
        diagnostics: String,
    },
    #[error("invalid local coordinator runner configuration: {0}")]
    Configuration(String),
    #[error("local coordinator runner IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("local coordinator error: {0}")]
    Coordinator(#[from] stoffel_mpc_coordinator_shared::CoordinatorError),
    #[error("local coordinator runner timed out during {phase} after {timeout:?}")]
    PhaseTimeout { phase: String, timeout: Duration },
    #[error(
        "local party {name} timed out after {timeout:?} (last completed phase: {phase}): {output}"
    )]
    PartyTimeout {
        name: String,
        phase: &'static str,
        timeout: Duration,
        output: String,
    },
    #[error("local party {name} exited with {status} (last completed phase: {phase}): {output}")]
    PartyExit {
        name: String,
        phase: &'static str,
        status: std::process::ExitStatus,
        output: String,
    },
    #[error(
        "local party {name} acknowledged completion but did not exit within {grace:?}: {output}"
    )]
    PartyShutdown {
        name: String,
        grace: Duration,
        output: String,
    },
    #[error("local party {name} exited successfully without acknowledging coordinated completion: {output}")]
    MissingCompletion { name: String, output: String },
    #[error("local {participant} failed during {phase}: {error}")]
    ParticipantFailure {
        participant: String,
        phase: &'static str,
        error: String,
    },
    #[error("invalid mask assignment for local client {client_slot}: {message}")]
    MaskAssignment { client_slot: u64, message: String },
    #[error("one or more local coordinator processes failed: {0}")]
    ProcessFailures(String),
    #[error("bytecode serialization failed: {0:?}")]
    Bytecode(stoffel_vm_types::compiled_binary::BinaryError),
}

pub type LocalCoordinatorRunnerResult<T> = Result<T, LocalCoordinatorRunnerError>;

#[derive(Debug, Clone)]
pub struct LocalCoordinatorRunner {
    runner_path: PathBuf,
    binary: CompiledBinary,
    entry: String,
    parties: usize,
    threshold: usize,
    backend: MpcBackendKind,
    curve_config: MpcCurveConfig,
    timeout: Duration,
    auth_token: String,
    client_inputs: Vec<LocalClientInput>,
    expected_clients: Option<usize>,
    /// Per-client number of output values to receive via `send_to_client`.
    client_output_counts: std::collections::HashMap<u64, u64>,
}

impl LocalCoordinatorRunner {
    pub fn builder(
        runner_path: impl Into<PathBuf>,
        binary: CompiledBinary,
    ) -> LocalCoordinatorRunnerBuilder {
        let curve_config = MpcCurveConfig::from(binary.client_io_manifest.mpc_curve);
        LocalCoordinatorRunnerBuilder {
            runner: Self {
                runner_path: runner_path.into(),
                backend: MpcBackendKind::from(binary.client_io_manifest.mpc_backend),
                binary,
                entry: "main".to_owned(),
                parties: 5,
                threshold: 1,
                curve_config,
                timeout: DEFAULT_TIMEOUT,
                auth_token: DEFAULT_AUTH_TOKEN.to_owned(),
                client_inputs: Vec::new(),
                expected_clients: None,
                client_output_counts: std::collections::HashMap::new(),
            },
        }
    }

    pub async fn run(self) -> LocalCoordinatorRunnerResult<LocalCoordinatorRunOutput> {
        self.validate()?;
        let cancellation = CancellationToken::new();
        // Dropping the caller's future requests cleanup without aborting the
        // owner of the processes. That owner retains the temp directory and
        // coordinator until every child has been killed and reaped.
        let _cancel_on_drop = cancellation.clone().drop_guard();
        tokio::spawn(self.run_owned(cancellation))
            .await
            .map_err(|error| {
                LocalCoordinatorRunnerError::ProcessFailures(format!("local supervisor: {error}"))
            })?
    }

    async fn run_owned(
        self,
        cancellation: CancellationToken,
    ) -> LocalCoordinatorRunnerResult<LocalCoordinatorRunOutput> {
        let timeout = self.timeout;
        let deadline = Instant::now() + timeout;
        let _local_run_guard = tokio::select! {
            guard = local_run_lock().lock() => guard,
            _ = cancellation.cancelled() => return Err(cancelled_run()),
            _ = tokio::time::sleep_until(deadline) => return Err(phase_timeout("local run admission", timeout)),
        };
        let _ = rustls::crypto::ring::default_provider().install_default();

        let temp = TempRunDir::new()?;
        let program_path = temp.path().join("program.stflb");
        save_to_file(&self.binary, &program_path).map_err(LocalCoordinatorRunnerError::Bytecode)?;
        let program_bytes = self.binary_bytes()?;
        let program_id = program_id_from_bytes(&program_bytes);
        let execution_id = ExecutionId::new();

        let node_identities = write_node_identities(temp.path(), self.parties)?;
        let node_public_keys = node_identities
            .iter()
            .map(|identity| public_key_from_cert(&identity.cert_der))
            .collect::<LocalCoordinatorRunnerResult<Vec<_>>>()?;
        let known_client_inputs = self.known_client_inputs();
        let mut local_clients = write_client_identities(temp.path(), &known_client_inputs)?;
        for client in local_clients.iter_mut() {
            client.output_count = self.output_count_for_slot(client.client_slot);
        }
        let client_bindings = local_clients
            .iter()
            .map(|client| Ok((client.client_slot, public_key_from_cert(&client.cert_der)?)))
            .collect::<LocalCoordinatorRunnerResult<Vec<_>>>()?;

        let coord_reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let coord_port = coord_reservation.local_addr()?.port();
        let coord_cert = self_signed_certs::server_cert();
        let (n_inputs, output_clients) = self.coordinator_client_io_binding(&client_bindings)?;
        let coord_state = HoneyBadgerCoordinatorRPCServerSharedBase::new_for_execution(
            CoordinatorExecutionId::from_bytes(*execution_id.as_bytes()),
            program_id,
            self.parties as u64,
            self.threshold as u64,
            node_public_keys,
            n_inputs,
            output_clients,
            InputAssignment::default(),
        )?;
        let coord = match tokio::time::timeout_at(deadline, async {
            drop(coord_reservation);
            OffChainCoordinatorServer::<HoneyBadgerCoordinatorConnection>::start_coord(
                coord_state,
                "127.0.0.1",
                coord_port,
                self.threshold as u64,
                coord_cert.cert.der().to_vec(),
                coord_cert.signing_key.serialize_der(),
            )
            .await
        })
        .await
        {
            Ok(Ok(coordinator)) => coordinator,
            Ok(Err(error)) => {
                return Err(LocalCoordinatorRunnerError::ParticipantFailure {
                    participant: "coordinator".to_owned(),
                    phase: "listener readiness",
                    error: error.to_string(),
                });
            }
            Err(_) => return Err(phase_timeout("coordinator listener readiness", timeout)),
        };

        let result = async {
        if cancellation.is_cancelled() {
            return Err(cancelled_run());
        }
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut all_markers = Vec::with_capacity(self.parties);
        let mut network_addrs = Vec::with_capacity(self.parties);
        let mut node_rpc_addrs = Vec::with_capacity(self.parties);
        for party in 0..self.parties {
            let name = if party == 0 { "leader".to_owned() } else { format!("party{party}") };
            let markers = PartyMarkers::new(temp.path(), &name, party == 0);
            let (network, rpc) = markers.reserve_ports(party == 0)?;
            network_addrs.push(network);
            node_rpc_addrs.push(rpc);
            all_markers.push((name, markers));
        }
        let bootnode = network_addrs[0];
        let mut party_tasks = JoinSet::new();
        let mut party_outputs = Vec::with_capacity(self.parties);
        let leader_markers = all_markers[0].1.clone();
        let (leader_name, leader_child) = self.spawn_party(
            "leader",
            SpawnPartyContext {
                program_path: &program_path,
                identity: &node_identities[0],
                rpc_addr: node_rpc_addrs[0],
                local_store_path: temp.path().join("local-node0.redb"),
                execution_id,
                role: PartyRole::Leader { bootnode },
                clients: &local_clients,
                coord_port,
                timestamp,
                markers: &leader_markers,
            },
        )?;
        spawn_party_monitor(
            &mut party_tasks,
            leader_name,
            leader_child,
            leader_markers.clone(),
            deadline,
            timeout,
            cancellation.clone(),
        );
        if let Err(error) = wait_for_readiness(
            "leader bootnode readiness",
            &[(
                "leader",
                leader_markers.bootnode.as_ref().expect("leader marker"),
            )],
            deadline,
            timeout,
            &mut party_tasks,
            &mut party_outputs,
        )
        .await
        {
            return Err(cleanup_after_failure(error, &cancellation, &mut party_tasks).await);
        }

        for (party_id, identity) in node_identities.iter().enumerate().skip(1) {
            let (name, markers) = &all_markers[party_id];
            let bind = network_addrs[party_id];
            let spawned = self.spawn_party(
                name,
                SpawnPartyContext {
                    program_path: &program_path,
                    identity,
                    rpc_addr: node_rpc_addrs[party_id],
                    local_store_path: temp.path().join(format!("local-node{party_id}.redb")),
                    execution_id,
                    role: PartyRole::Follower {
                        party_id,
                        bootnode,
                        bind,
                    },
                    clients: &local_clients,
                    coord_port,
                    timestamp,
                    markers,
                },
            );
            let (name, child) = match spawned {
                Ok(spawned) => spawned,
                Err(error) => {
                    return Err(cleanup_after_failure(error, &cancellation, &mut party_tasks).await);
                }
            };
            spawn_party_monitor(
                &mut party_tasks,
                name.clone(),
                child,
                markers.clone(),
                deadline,
                timeout,
                cancellation.clone(),
            );
        }

        let rpc_markers = all_markers
            .iter()
            .map(|(name, markers)| (name.as_str(), &markers.rpc))
            .collect::<Vec<_>>();
        if let Err(error) = wait_for_readiness(
            "party RPC listener readiness",
            &rpc_markers,
            deadline,
            timeout,
            &mut party_tasks,
            &mut party_outputs,
        )
        .await
        {
            return Err(cleanup_after_failure(error, &cancellation, &mut party_tasks).await);
        }

        let threshold = self.threshold;
        let mut client_tasks = JoinSet::new();
        let client_context = LocalClientRunContext {
            execution_id,
            node_rpc_addrs,
            coord_port,
            parties: self.parties,
            threshold,
            deadline,
            timeout,
        };
        for client in local_clients
            .iter()
            .filter(|client| client.input.has_input() || client.output_count > 0)
            .cloned()
        {
            let slot = client.client_slot;
            let backend = self.backend;
            let curve_config = self.curve_config;
            let context = client_context.clone();
            client_tasks.spawn(async move {
                let result = match backend {
                    MpcBackendKind::HoneyBadger => {
                        run_honeybadger_offchain_client(client, context).await
                    }
                    MpcBackendKind::Avss => {
                        run_avss_offchain_client_for_curve(curve_config, client, context).await
                    }
                };
                (slot, result)
            });
        }

        let mut client_outputs = Vec::new();
        while !party_tasks.is_empty() || !client_tasks.is_empty() {
            let event = tokio::select! {
                _ = cancellation.cancelled() => RunEvent::Cancelled,
                party = party_tasks.join_next(), if !party_tasks.is_empty() => RunEvent::Party(party),
                client = client_tasks.join_next(), if !client_tasks.is_empty() => RunEvent::Client(client),
            };

            let failure = match event {
                RunEvent::Cancelled => Some(cancelled_run()),
                RunEvent::Party(Some(Ok(Ok(output)))) => {
                    party_outputs.push(output);
                    None
                }
                RunEvent::Party(Some(Ok(Err(error)))) => Some(error),
                RunEvent::Party(Some(Err(error))) => {
                    Some(LocalCoordinatorRunnerError::ParticipantFailure {
                        participant: "party monitor".to_owned(),
                        phase: "process supervision",
                        error: error.to_string(),
                    })
                }
                RunEvent::Client(Some(Ok((_, Ok(Some(output)))))) => {
                    client_outputs.push(output);
                    None
                }
                RunEvent::Client(Some(Ok((_, Ok(None))))) => None,
                RunEvent::Client(Some(Ok((_, Err(error))))) => Some(error),
                RunEvent::Client(Some(Err(error))) => {
                    Some(LocalCoordinatorRunnerError::ParticipantFailure {
                        participant: "client task".to_owned(),
                        phase: "task supervision",
                        error: error.to_string(),
                    })
                }
                RunEvent::Party(None) | RunEvent::Client(None) => None,
            };

            if let Some(error) = failure {
                client_tasks.abort_all();
                while client_tasks.join_next().await.is_some() {}
                return Err(cleanup_after_failure(error, &cancellation, &mut party_tasks).await);
            }
        }

        party_outputs.sort_by_key(|output| party_sort_key(&output.name));
        client_outputs.sort_by_key(|output| output.client_slot);
        let combined_output = party_outputs
            .iter()
            .map(|output| output.combined.as_str())
            .collect::<String>();

        Ok(LocalCoordinatorRunOutput {
            combined_output,
            party_outputs,
            client_outputs,
        })
        }.await;
        // shutdown awaits the listener and its accepted connections; Drop alone
        // only schedules cancellation and can leave the port live at return.
        let shutdown = tokio::time::timeout(CLEANUP_GRACE, coord.shutdown()).await;
        if shutdown.is_err() {
            let shutdown_error = phase_timeout("coordinator shutdown", CLEANUP_GRACE);
            return Err(match result {
                Ok(_) => shutdown_error,
                Err(source) => LocalCoordinatorRunnerError::Cleanup {
                    source: Box::new(source),
                    diagnostics: shutdown_error.to_string(),
                },
            });
        }
        result
    }

    fn validate(&self) -> LocalCoordinatorRunnerResult<()> {
        if !self.runner_path.exists() {
            return Err(LocalCoordinatorRunnerError::Configuration(format!(
                "stoffel-run binary does not exist at {}",
                self.runner_path.display()
            )));
        }
        if self.binary.functions.is_empty() {
            return Err(LocalCoordinatorRunnerError::Configuration(
                "program must contain at least one function".to_owned(),
            ));
        }
        self.backend
            .validate_party_count(self.parties)
            .map_err(|error| LocalCoordinatorRunnerError::Configuration(error.to_string()))?;
        if matches!(self.backend, MpcBackendKind::HoneyBadger)
            && self.parties < self.threshold.saturating_mul(4).saturating_add(1)
        {
            return Err(LocalCoordinatorRunnerError::Configuration(format!(
                "HoneyBadger parties ({}) must be >= 4 * threshold ({}) + 1",
                self.parties, self.threshold
            )));
        }
        self.curve_config
            .validate_for_backend(self.backend)
            .map_err(|error| LocalCoordinatorRunnerError::Configuration(error.to_string()))?;
        if self.timeout.is_zero() {
            return Err(LocalCoordinatorRunnerError::Configuration(
                "timeout must be greater than zero".to_owned(),
            ));
        }
        self.validate_expected_clients()?;
        self.validate_client_inputs()?;
        Ok(())
    }

    fn validate_expected_clients(&self) -> LocalCoordinatorRunnerResult<()> {
        let Some(expected_clients) = self.expected_clients else {
            return Ok(());
        };
        if expected_clients == 0 {
            return Err(LocalCoordinatorRunnerError::Configuration(
                "--expected-output-clients must be greater than 0".to_owned(),
            ));
        }
        let minimum = self
            .binary
            .client_io_manifest
            .clients
            .iter()
            .map(|schema| usize::try_from(schema.client_slot).unwrap_or(usize::MAX))
            .map(|slot| slot.saturating_add(1))
            .max()
            .unwrap_or(0);
        if minimum > expected_clients {
            return Err(LocalCoordinatorRunnerError::Configuration(format!(
                "program declares ClientStore slot(s) requiring expected_clients >= {minimum}, but expected_clients is {expected_clients}"
            )));
        }
        Ok(())
    }

    fn validate_client_inputs(&self) -> LocalCoordinatorRunnerResult<()> {
        if self.binary.client_io_manifest.clients.is_empty() && self.client_inputs.is_empty() {
            return Ok(());
        }
        // Each client owns a contiguous range sized to its actual input count;
        // asymmetric clients do not require padding.
        if !self.binary.client_io_manifest.clients.is_empty()
            && self.client_inputs.is_empty()
            && self
                .binary
                .client_io_manifest
                .clients
                .iter()
                .any(|schema| !schema.inputs.is_empty())
        {
            return Err(LocalCoordinatorRunnerError::Configuration(
                "program declares ClientStore input metadata; provide local client inputs"
                    .to_owned(),
            ));
        }
        if self.binary.client_io_manifest.clients.is_empty() {
            let mut seen_slots = HashSet::with_capacity(self.client_inputs.len());
            for client in &self.client_inputs {
                if !seen_slots.insert(client.client_slot) {
                    return Err(LocalCoordinatorRunnerError::Configuration(format!(
                        "client slot {} was provided more than once",
                        client.client_slot
                    )));
                }
            }
            return Ok(());
        }
        let mut seen_slots = HashSet::with_capacity(self.client_inputs.len());
        for client in &self.client_inputs {
            if !seen_slots.insert(client.client_slot) {
                return Err(LocalCoordinatorRunnerError::Configuration(format!(
                    "client slot {} was provided more than once",
                    client.client_slot
                )));
            }
            let Some(schema) = self
                .binary
                .client_io_manifest
                .clients
                .iter()
                .find(|schema| schema.client_slot == client.client_slot)
            else {
                return Err(LocalCoordinatorRunnerError::Configuration(format!(
                    "client slot {} is not declared in the program client IO manifest",
                    client.client_slot
                )));
            };
            if schema.inputs.len() != client.values.len() {
                return Err(LocalCoordinatorRunnerError::Configuration(format!(
                    "client slot {} expects {} inputs, got {}",
                    client.client_slot,
                    schema.inputs.len(),
                    client.values.len()
                )));
            }
        }
        for schema in &self.binary.client_io_manifest.clients {
            if !schema.inputs.is_empty() && !seen_slots.contains(&schema.client_slot) {
                return Err(LocalCoordinatorRunnerError::Configuration(format!(
                    "client slot {} is declared in the program client IO manifest but no input was provided",
                    schema.client_slot
                )));
            }
        }
        Ok(())
    }

    /// Number of output values a client receives via `send_to_client`: an
    /// explicit override if provided, else the statically recorded count from
    /// the program's client-IO manifest.
    fn output_count_for_slot(&self, client_slot: u64) -> u64 {
        // Prefer the statically recorded output count from the client-IO
        // manifest. Only when the program does not statically declare outputs
        // for this client (e.g. it sends to a parameterized slot) do we fall
        // back to a developer-provided count (SDK builder / `stoffel run
        // --outputs` / Stoffel.toml), threaded in via `client_output_counts`.
        let manifest_count = self
            .binary
            .client_io_manifest
            .clients
            .iter()
            .find(|schema| schema.client_slot == client_slot)
            .map(|schema| schema.outputs.len() as u64)
            .unwrap_or(0);
        if manifest_count > 0 {
            return manifest_count;
        }
        self.client_output_counts
            .get(&client_slot)
            .copied()
            .unwrap_or(0)
    }

    fn known_client_inputs(&self) -> Vec<LocalClientInput> {
        let mut slots = BTreeSet::new();
        for client in &self.client_inputs {
            slots.insert(client.client_slot);
        }
        for schema in &self.binary.client_io_manifest.clients {
            slots.insert(schema.client_slot);
        }
        if let Some(expected_clients) = self.expected_clients {
            for client_slot in 0..expected_clients {
                slots.insert(client_slot as u64);
            }
        }

        slots
            .into_iter()
            .map(|client_slot| {
                self.client_inputs
                    .iter()
                    .find(|input| input.client_slot == client_slot)
                    .cloned()
                    .unwrap_or_else(|| LocalClientInput::raw(client_slot, Vec::<String>::new()))
            })
            .collect()
    }

    fn binary_bytes(&self) -> LocalCoordinatorRunnerResult<Vec<u8>> {
        let mut bytes = Vec::new();
        self.binary
            .serialize(&mut std::io::Cursor::new(&mut bytes))
            .map_err(LocalCoordinatorRunnerError::Bytecode)?;
        Ok(bytes)
    }

    fn coordinator_client_io_binding(
        &self,
        client_bindings: &[(u64, Vec<u8>)],
    ) -> LocalCoordinatorRunnerResult<(u64, Vec<Vec<u8>>)> {
        let mut n_inputs = 0_u64;
        let output_clients = client_bindings
            .iter()
            .map(|(_slot, identity)| identity.clone())
            .collect::<Vec<_>>();
        if self.binary.client_io_manifest.clients.is_empty() {
            for input in &self.client_inputs {
                client_bindings
                    .iter()
                    .find(|(slot, _identity)| *slot == input.client_slot)
                    .ok_or_else(|| {
                        LocalCoordinatorRunnerError::Configuration(format!(
                            "client slot {} does not have a local client identity",
                            input.client_slot
                        ))
                    })?;
                n_inputs += input.values.len() as u64;
            }
            return Ok((n_inputs, output_clients));
        }

        for schema in &self.binary.client_io_manifest.clients {
            client_bindings
                .iter()
                .find(|(slot, _identity)| *slot == schema.client_slot)
                .ok_or_else(|| {
                    LocalCoordinatorRunnerError::Configuration(format!(
                        "client slot {} does not have a local client identity",
                        schema.client_slot
                    ))
                })?;
            n_inputs += schema.inputs.len() as u64;
        }
        Ok((n_inputs, output_clients))
    }

    fn spawn_party(
        &self,
        name: &str,
        context: SpawnPartyContext<'_>,
    ) -> LocalCoordinatorRunnerResult<(String, Child)> {
        let mut command = Command::new(&self.runner_path);
        command
            .arg(context.program_path)
            .arg(&self.entry)
            .arg("--n-parties")
            .arg(self.parties.to_string())
            .arg("--threshold")
            .arg(self.threshold.to_string())
            .arg("--mpc-backend")
            .arg(self.backend.name())
            .arg("--curve")
            .arg(self.curve_config.name())
            .arg("--off-chain-coord")
            .arg(format!("127.0.0.1:{}", context.coord_port))
            .arg("--rpc-bind")
            .arg(context.rpc_addr.to_string())
            .arg("--cert")
            .arg(&context.identity.cert_path)
            .arg("--key")
            .arg(&context.identity.key_path)
            .arg("--timestamp")
            .arg(context.timestamp.to_string())
            .arg("--local-store")
            .arg(&context.local_store_path)
            .arg("--execution-id")
            .arg(context.execution_id.to_string())
            .env("STOFFEL_AUTH_TOKEN", &self.auth_token)
            .env("STOFFEL_LOCAL_RPC_READY_FILE", &context.markers.rpc)
            .env("STOFFEL_LOCAL_COMPLETION_FILE", &context.markers.completion)
            .env(
                "STOFFEL_LOCAL_NETWORK_HANDOFF",
                &context.markers.network_handoff,
            )
            .env("STOFFEL_LOCAL_RPC_HANDOFF", &context.markers.rpc_handoff)
            // Tie each spawned party to this runner's lifetime: `kill_on_drop`
            // handles a graceful drop, and the parent-death watchdog (keyed off
            // this env var) covers the case where the runner is force-killed
            // (SIGKILL) and cannot run drop cleanup, preventing orphaned parties.
            .env("STOFFEL_DIE_WITH_PARENT", "1")
            .kill_on_drop(true)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if !context.clients.is_empty() {
            command
                .arg("--expected-clients")
                .arg(
                    context
                        .clients
                        .iter()
                        .map(|client| client.cert_path.display().to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                )
                .arg("--client-input-count")
                .arg(self.max_client_input_count().to_string())
                .arg("--client-input-total")
                .arg(self.total_client_input_count().to_string());
            command.arg("--client-roster").arg(
                context
                    .clients
                    .iter()
                    .map(|client| client.client_slot.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            );
            let input_slots = context
                .clients
                .iter()
                .filter(|client| client.input.has_input())
                .map(|client| client.client_slot.to_string())
                .collect::<Vec<_>>();
            if !input_slots.is_empty() {
                command
                    .arg("--client-input-slots")
                    .arg(input_slots.join(","));
            }
        }

        match context.role {
            PartyRole::Leader { bootnode } => {
                command
                    .env(
                        "STOFFEL_LOCAL_BOOTNODE_READY_FILE",
                        context
                            .markers
                            .bootnode
                            .as_ref()
                            .expect("leader has a bootnode readiness marker"),
                    )
                    .arg("--leader")
                    .arg("--bind")
                    .arg(bootnode.to_string());
            }
            PartyRole::Follower {
                party_id,
                bootnode,
                bind,
            } => {
                command
                    .arg("--party-id")
                    .arg(party_id.to_string())
                    .arg("--bootstrap")
                    .arg(bootnode.to_string())
                    .arg("--bind")
                    .arg(bind.to_string());
            }
        }

        let child = command.spawn()?;
        // Profiler attachment hooks. External `sample`/`ps` can't reliably discover
        // these short-lived child processes (PID races; TEE-buffered markers arrive
        // after the fast online window), so the runner attaches from spawn instead.
        if let Some(pid) = child.id() {
            if std::env::var("STOFFEL_PRINT_PARTY_PIDS").is_ok() {
                eprintln!("[local-runner] party '{name}' pid={pid}");
            }
            // Attach macOS `sample` to this child for STOFFEL_SAMPLE_CHILDREN seconds,
            // writing to /tmp/stoffel_child_sample_<name>_<pid>.txt. Detached — runs
            // independently of the runner, sampling the party across all its phases.
            if let Ok(dur) = std::env::var("STOFFEL_SAMPLE_CHILDREN") {
                let path = format!("/tmp/stoffel_child_sample_{name}_{pid}.txt");
                match std::process::Command::new("sample")
                    .arg(pid.to_string())
                    .arg(&dur)
                    .arg("-mayDie")
                    .arg("-file")
                    .arg(&path)
                    .spawn()
                {
                    Ok(_) => {
                        eprintln!(
                            "[local-runner] sampling party '{name}' (pid={pid}) for {dur}s -> {path}"
                        );
                    }
                    Err(error) => {
                        eprintln!("[local-runner] failed to attach sample to pid={pid}: {error}")
                    }
                }
            }
        }
        Ok((name.to_owned(), child))
    }

    fn max_client_input_count(&self) -> usize {
        self.client_inputs
            .iter()
            .filter(|client| !client.values.is_empty())
            .map(|client| client.values.len())
            .max()
            .unwrap_or(0)
    }

    /// Total number of input values across all clients (sum of per-client
    /// counts). Clients may supply different numbers of inputs, so the input
    /// mask reservation/wait must use this actual total, not `num_clients * max`.
    fn total_client_input_count(&self) -> usize {
        self.client_inputs
            .iter()
            .map(|client| client.values.len())
            .sum()
    }
}

#[derive(Debug, Clone)]
pub struct LocalCoordinatorRunnerBuilder {
    runner: LocalCoordinatorRunner,
}

impl LocalCoordinatorRunnerBuilder {
    pub fn entry(mut self, entry: impl Into<String>) -> Self {
        self.runner.entry = entry.into();
        self
    }

    pub fn parties(mut self, parties: usize) -> Self {
        self.runner.parties = parties;
        self
    }

    pub fn threshold(mut self, threshold: usize) -> Self {
        self.runner.threshold = threshold;
        self
    }

    pub fn backend(mut self, backend: MpcBackendKind) -> Self {
        self.runner.backend = backend;
        self
    }

    pub fn curve(mut self, curve_config: MpcCurveConfig) -> Self {
        self.runner.curve_config = curve_config;
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.runner.timeout = timeout;
        self
    }

    pub fn auth_token(mut self, auth_token: impl Into<String>) -> Self {
        self.runner.auth_token = auth_token.into();
        self
    }

    pub fn client_input(mut self, client_slot: u64, values: impl IntoIterator<Item = i64>) -> Self {
        self.runner
            .client_inputs
            .push(LocalClientInput::new(client_slot, values));
        self
    }

    pub fn client_inputs(mut self, inputs: impl IntoIterator<Item = LocalClientInput>) -> Self {
        self.runner.client_inputs.extend(inputs);
        self
    }

    pub fn expected_output_clients(mut self, expected_clients: usize) -> Self {
        self.runner.expected_clients = Some(expected_clients);
        self
    }

    /// Override the number of output values a client receives via
    /// `send_to_client`. When unset, the count is taken from the program's
    /// client-IO manifest (the statically recorded output schema).
    pub fn client_output_count(mut self, client_slot: u64, count: u64) -> Self {
        self.runner.client_output_counts.insert(client_slot, count);
        self
    }

    pub fn build(self) -> LocalCoordinatorRunnerResult<LocalCoordinatorRunner> {
        self.runner.validate()?;
        Ok(self.runner)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalClientInput {
    pub client_slot: u64,
    pub values: Vec<String>,
}

impl LocalClientInput {
    pub fn new(client_slot: u64, values: impl IntoIterator<Item = i64>) -> Self {
        Self {
            client_slot,
            values: values.into_iter().map(|value| value.to_string()).collect(),
        }
    }

    pub fn raw(client_slot: u64, values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            client_slot,
            values: values.into_iter().map(Into::into).collect(),
        }
    }

    fn has_input(&self) -> bool {
        !self.values.is_empty()
    }
}

/// A client's reconstructed output values, received via `send_to_client` and
/// reconstructed by the off-chain client (not a public reveal to the nodes).
#[derive(Debug, Clone)]
pub struct ClientOutputRecord {
    pub client_slot: u64,
    pub values: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct LocalCoordinatorRunOutput {
    pub combined_output: String,
    pub party_outputs: Vec<LocalPartyOutput>,
    pub client_outputs: Vec<ClientOutputRecord>,
}

impl LocalCoordinatorRunOutput {
    pub fn returned_values(&self) -> Vec<&str> {
        returned_values_from(&self.combined_output)
    }

    /// Decode every party-local secret share returned by the run.
    ///
    /// Unlike [`Self::consistent_returned_values`], this intentionally does
    /// not compare payloads: distinct parties normally hold distinct bytes for
    /// the same logical secret.
    pub fn returned_shares(&self) -> Result<Vec<ReturnedShare>, ReturnedShareParseError> {
        returned_shares_from(&self.combined_output)
    }

    pub fn consistent_returned_values(&self) -> Result<Vec<String>, String> {
        let mut parties = self.party_outputs.iter();
        let Some(first_party) = parties.next() else {
            return Err("local coordinator run did not produce any party output".to_owned());
        };
        let first_values = first_party
            .returned_values()
            .into_iter()
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        if first_values.is_empty() {
            return Err(format!(
                "local party {} did not report a VM return value",
                first_party.name
            ));
        }
        if first_values
            .iter()
            .any(|value| value.starts_with(RETURNED_SHARE_PREFIX_V1))
        {
            return Err(
                "secret VM returns are party-local and must be read with returned_shares()"
                    .to_owned(),
            );
        }

        for party in parties {
            let values = party
                .returned_values()
                .into_iter()
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
            if values != first_values {
                return Err(format!(
                    "local party {} returned {:?}, expected {:?} from party {}",
                    party.name, values, first_values, first_party.name
                ));
            }
        }

        Ok(first_values)
    }
}

fn returned_values_from(output: &str) -> Vec<&str> {
    output
        .lines()
        .filter_map(|line| line.trim().strip_prefix("Program returned: "))
        .collect()
}

fn returned_shares_from(output: &str) -> Result<Vec<ReturnedShare>, ReturnedShareParseError> {
    returned_values_from(output)
        .into_iter()
        .filter(|value| value.starts_with(RETURNED_SHARE_PREFIX_V1))
        .map(str::parse)
        .collect()
}

#[derive(Debug, Clone)]
pub struct LocalPartyOutput {
    pub name: String,
    pub stdout: String,
    pub stderr: String,
    pub combined: String,
}

impl LocalPartyOutput {
    pub fn returned_values(&self) -> Vec<&str> {
        returned_values_from(&self.combined)
    }

    /// Decode this party's unrevealed VM return shares.
    ///
    /// The returned bytes are the local backend serialization and can be fed
    /// directly into a party-local hashing or sealing operation.
    pub fn returned_shares(&self) -> Result<Vec<ReturnedShare>, ReturnedShareParseError> {
        returned_shares_from(&self.combined)
    }
}

#[derive(Clone)]
struct NodeIdentity {
    cert_path: PathBuf,
    key_path: PathBuf,
    cert_der: Vec<u8>,
}

#[derive(Clone)]
struct LocalClientIdentity {
    input: LocalClientInput,
    cert_path: PathBuf,
    key_path: PathBuf,
    cert_der: Vec<u8>,
    reserved_index_start: u64,
    client_slot: u64,
    /// Number of output values this client receives via `send_to_client`.
    output_count: u64,
}

#[derive(Clone)]
struct LocalClientRunContext {
    execution_id: ExecutionId,
    node_rpc_addrs: Vec<SocketAddr>,
    coord_port: u16,
    parties: usize,
    threshold: usize,
    deadline: Instant,
    timeout: Duration,
}

async fn run_honeybadger_offchain_client(
    client: LocalClientIdentity,
    context: LocalClientRunContext,
) -> LocalCoordinatorRunnerResult<Option<ClientOutputRecord>> {
    let LocalClientRunContext {
        execution_id,
        node_rpc_addrs,
        coord_port,
        parties,
        threshold,
        deadline,
        timeout,
    } = context;
    let client_slot = client.client_slot;
    let mut phase = "input validation";
    let result = tokio::time::timeout_at(deadline, async {
        eprintln!(
            "[local-client {}] starting off-chain coordinator input submission",
            client.client_slot
        );
        let input_values = client
            .input
            .values
            .iter()
            .map(|value| parse_input_as_field::<Fr>(value))
            .collect::<LocalCoordinatorRunnerResult<Vec<_>>>()?;
        eprintln!(
            "[local-client {}] connecting coordinator",
            client.client_slot
        );
        phase = "coordinator connection";
        let mut coord: OffChainCoordinatorClient<Fr, RobustShare<Fr>> =
            OffChainCoordinatorClient::start_rpc_client_for_execution(
                "127.0.0.1",
                coord_port,
                threshold as u64,
                parties as u64,
                client.output_count,
                CoordinatorExecutionId::from_bytes(*execution_id.as_bytes()),
                client.cert_der.clone(),
                std::fs::read(&client.key_path)?,
            )
            .await?;

        let reserved_indices = (0..input_values.len())
            .map(|offset| client.reserved_index_start + offset as u64)
            .collect::<Vec<_>>();
        for index in &reserved_indices {
            eprintln!(
                "[local-client {}] reserving mask index {}",
                client.client_slot, *index
            );
        }
        phase = "mask reservation";
        if !reserved_indices.is_empty() {
            reserve_mask_indices_when_ready(&mut coord, &reserved_indices, deadline, timeout)
                .await?;
        }

        // Output-only clients need only the coordinator. Parties may already
        // have finished and closed their RPC listeners by the time we run.
        let received_masks = if reserved_indices.is_empty() {
            Vec::new()
        } else {
            phase = "node RPC connection";
            eprintln!("[local-client {}] connecting node RPC", client.client_slot);
            let rpc_addrs = node_rpc_addrs
                .iter()
                .map(|addr| (addr.ip().to_string(), addr.port()))
                .collect::<Vec<_>>();
            let node_rpc: OffChainNodeRPCClient<Fr, RobustShare<Fr>> =
                OffChainNodeRPCClient::start_rpc_client_for_execution(
                    parties,
                    threshold,
                    rpc_addrs,
                    CoordinatorExecutionId::from_bytes(*execution_id.as_bytes()),
                    client.cert_der,
                    std::fs::read(&client.key_path)?,
                )
                .await?;

            eprintln!(
                "[local-client {}] receiving assigned masks",
                client.client_slot
            );
            phase = "assigned mask delivery";
            node_rpc
                .receive_assigned_masks(client.reserved_index_start, input_values.len() as u64)
                .await?
        };
        let mut masks = assigned_mask_map(client.client_slot, &reserved_indices, received_masks)?;

        let masked_inputs = input_values
            .into_iter()
            .enumerate()
            .map(|(offset, input)| {
                let index = client.reserved_index_start + offset as u64;
                let mask = masks
                    .remove(&index)
                    .expect("validated mask assignment covers every reserved index");
                (index, input + mask)
            })
            .collect::<Vec<_>>();
        eprintln!(
            "[local-client {}] submitting {} masked inputs",
            client.client_slot,
            masked_inputs.len()
        );
        phase = "masked input submission";
        if !masked_inputs.is_empty() {
            send_masked_inputs_when_ready(&coord, &masked_inputs, deadline, timeout).await?;
        }
        eprintln!(
            "[local-client {}] input submission complete",
            client.client_slot
        );

        if client.output_count == 0 {
            return Ok(None);
        }

        eprintln!(
            "[local-client {}] obtaining {} client output value(s)",
            client.client_slot, client.output_count
        );
        phase = "client output reconstruction";
        let output_values: Vec<Fr> = coord.obtain_outputs().await?;
        eprintln!(
            "[local-client {}] received {} client output value(s)",
            client.client_slot,
            output_values.len()
        );
        let values = output_values.iter().map(field_to_u64).collect::<Vec<_>>();
        Ok(Some(ClientOutputRecord {
            client_slot: client.client_slot,
            values,
        }))
    })
    .await
    .map_err(|_| phase_timeout(format!("client {client_slot}: {phase}"), timeout))?;
    result.map_err(|error: LocalCoordinatorRunnerError| {
        LocalCoordinatorRunnerError::ParticipantFailure {
            participant: format!("client {client_slot}"),
            phase,
            error: error.to_string(),
        }
    })
}

/// Preserve small signed field values in a `u64` wire slot.
///
/// Positive values retain their ordinary `u64` representation. Negative field
/// values use the corresponding two's-complement `i64` bits so the manifest-
/// aware SDK can decode signed integer and fixed-point client outputs without
/// losing the sign at this lower-level runner boundary.
fn field_to_u64<F: PrimeField>(value: &F) -> u64 {
    let positive = value.into_bigint();
    if positive.as_ref()[1..].iter().all(|limb| *limb == 0) {
        return positive.as_ref()[0];
    }

    let negative = (-*value).into_bigint();
    if negative.as_ref()[1..].iter().all(|limb| *limb == 0)
        && negative.as_ref()[0] <= i64::MAX as u64 + 1
    {
        let magnitude = negative.as_ref()[0];
        let signed = if magnitude == i64::MAX as u64 + 1 {
            i64::MIN
        } else {
            -(magnitude as i64)
        };
        return signed as u64;
    }

    positive.as_ref()[0]
}

async fn run_avss_offchain_client<F, G>(
    client: LocalClientIdentity,
    context: LocalClientRunContext,
) -> LocalCoordinatorRunnerResult<Option<ClientOutputRecord>>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    let LocalClientRunContext {
        execution_id,
        node_rpc_addrs,
        coord_port,
        parties,
        threshold,
        deadline,
        timeout,
    } = context;
    let client_slot = client.client_slot;
    let mut phase = "input validation";
    let result = tokio::time::timeout_at(deadline, async {
        eprintln!(
            "[local-client {}] starting AVSS off-chain coordinator input submission",
            client.client_slot
        );
        let input_values = client
            .input
            .values
            .iter()
            .map(|value| parse_input_as_field::<F>(value))
            .collect::<LocalCoordinatorRunnerResult<Vec<_>>>()?;
        phase = "coordinator connection";
        let mut coord: OffChainCoordinatorClient<F, FeldmanShamirShare<F, G>> =
            OffChainCoordinatorClient::start_rpc_client_for_execution(
                "127.0.0.1",
                coord_port,
                threshold as u64,
                parties as u64,
                client.output_count,
                CoordinatorExecutionId::from_bytes(*execution_id.as_bytes()),
                client.cert_der.clone(),
                std::fs::read(&client.key_path)?,
            )
            .await?;

        let reserved_indices = (0..input_values.len())
            .map(|offset| client.reserved_index_start + offset as u64)
            .collect::<Vec<_>>();
        for index in &reserved_indices {
            eprintln!(
                "[local-client {}] reserving AVSS mask index {}",
                client.client_slot, *index
            );
        }
        phase = "mask reservation";
        if !reserved_indices.is_empty() {
            reserve_avss_mask_indices_when_ready(&mut coord, &reserved_indices, deadline, timeout)
                .await?;
        }

        let received_masks = if reserved_indices.is_empty() {
            Vec::new()
        } else {
            phase = "node RPC connection";
            let rpc_addrs = node_rpc_addrs
                .iter()
                .map(|addr| (addr.ip().to_string(), addr.port()))
                .collect::<Vec<_>>();
            let node_rpc: OffChainNodeRPCClient<F, FeldmanShamirShare<F, G>> =
                OffChainNodeRPCClient::start_rpc_client_for_execution(
                    parties,
                    threshold,
                    rpc_addrs,
                    CoordinatorExecutionId::from_bytes(*execution_id.as_bytes()),
                    client.cert_der,
                    std::fs::read(&client.key_path)?,
                )
                .await?;

            eprintln!(
                "[local-client {}] receiving assigned AVSS masks",
                client.client_slot
            );
            phase = "assigned mask delivery";
            node_rpc
                .receive_assigned_masks(client.reserved_index_start, input_values.len() as u64)
                .await?
        };
        let mut masks = assigned_mask_map(client.client_slot, &reserved_indices, received_masks)?;

        let masked_inputs = input_values
            .into_iter()
            .enumerate()
            .map(|(offset, input)| {
                let index = client.reserved_index_start + offset as u64;
                let mask = masks
                    .remove(&index)
                    .expect("validated mask assignment covers every reserved index");
                (index, input + mask)
            })
            .collect::<Vec<_>>();
        eprintln!(
            "[local-client {}] submitting {} AVSS masked inputs",
            client.client_slot,
            masked_inputs.len()
        );
        phase = "masked input submission";
        if !masked_inputs.is_empty() {
            send_avss_masked_inputs_when_ready(&coord, &masked_inputs, deadline, timeout).await?;
        }
        eprintln!(
            "[local-client {}] AVSS input submission complete",
            client.client_slot
        );
        if client.output_count == 0 {
            return Ok(None);
        }
        phase = "client output reconstruction";
        let output_values: Vec<F> = coord.obtain_outputs().await?;
        Ok(Some(ClientOutputRecord {
            client_slot,
            values: output_values.iter().map(field_to_u64).collect(),
        }))
    })
    .await
    .map_err(|_| phase_timeout(format!("client {client_slot}: {phase}"), timeout))?;
    result.map_err(|error: LocalCoordinatorRunnerError| {
        LocalCoordinatorRunnerError::ParticipantFailure {
            participant: format!("client {client_slot}"),
            phase,
            error: error.to_string(),
        }
    })
}

async fn run_avss_offchain_client_for_curve(
    curve_config: MpcCurveConfig,
    client: LocalClientIdentity,
    context: LocalClientRunContext,
) -> LocalCoordinatorRunnerResult<Option<ClientOutputRecord>> {
    macro_rules! run {
        ($field:ty, $group:ty) => {
            run_avss_offchain_client::<$field, $group>(client, context).await
        };
    }

    match curve_config {
        MpcCurveConfig::Bls12_381 => run!(ark_bls12_381::Fr, ark_bls12_381::G1Projective),
        MpcCurveConfig::Bn254 => run!(ark_bn254::Fr, ark_bn254::G1Projective),
        MpcCurveConfig::Curve25519 => {
            run!(ark_curve25519::Fr, ark_curve25519::EdwardsProjective)
        }
        MpcCurveConfig::Ed25519 => run!(ark_ed25519::Fr, ark_ed25519::EdwardsProjective),
        MpcCurveConfig::Secp256k1 => run!(ark_secp256k1::Fr, ark_secp256k1::Projective),
        MpcCurveConfig::Secp256r1 => run!(ark_secp256r1::Fr, ark_secp256r1::Projective),
    }
}

fn assigned_mask_map<T>(
    client_slot: u64,
    expected_indices: &[u64],
    masks: Vec<T>,
) -> LocalCoordinatorRunnerResult<BTreeMap<u64, T>> {
    // receive_assigned_masks validates each node's explicit reserved indices
    // (including duplicates and omissions), then reconstructs in ascending
    // reserved-index order. Check cardinality before zipping this API's result.
    if masks.len() != expected_indices.len() {
        return Err(LocalCoordinatorRunnerError::MaskAssignment {
            client_slot,
            message: format!(
                "expected {} assigned masks, received {}",
                expected_indices.len(),
                masks.len()
            ),
        });
    }
    exact_mask_assignment(
        client_slot,
        expected_indices,
        expected_indices.iter().copied().zip(masks).collect(),
    )
}

fn exact_mask_assignment<T>(
    client_slot: u64,
    expected_indices: &[u64],
    indexed_masks: Vec<(u64, T)>,
) -> LocalCoordinatorRunnerResult<BTreeMap<u64, T>> {
    let expected = expected_indices.iter().copied().collect::<BTreeSet<_>>();
    let mut masks = BTreeMap::new();
    for (index, mask) in indexed_masks {
        if !expected.contains(&index) {
            return Err(LocalCoordinatorRunnerError::MaskAssignment {
                client_slot,
                message: format!("received unexpected reserved index {index}"),
            });
        }
        if masks.insert(index, mask).is_some() {
            return Err(LocalCoordinatorRunnerError::MaskAssignment {
                client_slot,
                message: format!("received duplicate reserved index {index}"),
            });
        }
    }

    let missing = expected
        .difference(&masks.keys().copied().collect())
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(LocalCoordinatorRunnerError::MaskAssignment {
            client_slot,
            message: format!("missing reserved indices {missing:?}"),
        });
    }
    Ok(masks)
}

async fn reserve_mask_indices_when_ready(
    coord: &mut OffChainCoordinatorClient<Fr, RobustShare<Fr>>,
    indices: &[u64],
    deadline: Instant,
    timeout: Duration,
) -> LocalCoordinatorRunnerResult<()> {
    loop {
        match coord.reserve_mask_indices(indices).await {
            Ok(()) => return Ok(()),
            Err(error) if coordinator_wrong_round(&error) => {
                if Instant::now() >= deadline {
                    return Err(phase_timeout("HoneyBadger mask reservation", timeout));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

async fn reserve_avss_mask_indices_when_ready<F, G>(
    coord: &mut OffChainCoordinatorClient<F, FeldmanShamirShare<F, G>>,
    indices: &[u64],
    deadline: Instant,
    timeout: Duration,
) -> LocalCoordinatorRunnerResult<()>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    loop {
        match coord.reserve_mask_indices(indices).await {
            Ok(()) => return Ok(()),
            Err(error) if coordinator_wrong_round(&error) => {
                if Instant::now() >= deadline {
                    return Err(phase_timeout("AVSS mask reservation", timeout));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

async fn send_masked_inputs_when_ready(
    coord: &OffChainCoordinatorClient<Fr, RobustShare<Fr>>,
    masked_inputs: &[(u64, Fr)],
    deadline: Instant,
    timeout: Duration,
) -> LocalCoordinatorRunnerResult<()> {
    loop {
        match coord.send_masked_inputs(masked_inputs).await {
            Ok(()) => return Ok(()),
            Err(error) if coordinator_wrong_round(&error) => {
                if Instant::now() >= deadline {
                    return Err(phase_timeout(
                        "HoneyBadger masked input submission",
                        timeout,
                    ));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

async fn send_avss_masked_inputs_when_ready<F, G>(
    coord: &OffChainCoordinatorClient<F, FeldmanShamirShare<F, G>>,
    masked_inputs: &[(u64, F)],
    deadline: Instant,
    timeout: Duration,
) -> LocalCoordinatorRunnerResult<()>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    loop {
        match coord.send_masked_inputs(masked_inputs).await {
            Ok(()) => return Ok(()),
            Err(error) if coordinator_wrong_round(&error) => {
                if Instant::now() >= deadline {
                    return Err(phase_timeout("AVSS masked input submission", timeout));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn coordinator_wrong_round(error: &stoffel_mpc_coordinator_shared::CoordinatorError) -> bool {
    let message = error.to_string();
    message.contains("WrongRound")
        || message.contains("Need round")
        || message.contains("current round is")
}

fn parse_input_as_field<F: PrimeField>(value: &str) -> LocalCoordinatorRunnerResult<F> {
    let value = value.trim();
    // Booleans are advertised by the CLI as valid client inputs; share them
    // as the field bits 1/0 so secret-bool gates work on them.
    if value.eq_ignore_ascii_case("true") {
        return Ok(F::from(1u64));
    }
    if value.eq_ignore_ascii_case("false") {
        return Ok(F::from(0u64));
    }
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        let mut hex = hex.to_owned();
        if hex.len() % 2 == 1 {
            hex.insert(0, '0');
        }
        let bytes = hex::decode(&hex).map_err(|error| {
            LocalCoordinatorRunnerError::Configuration(format!(
                "invalid hex client input '{value}': {error}"
            ))
        })?;
        return Ok(F::from_be_bytes_mod_order(&bytes));
    }
    let value = value.parse::<i64>().map_err(|error| {
        LocalCoordinatorRunnerError::Configuration(format!(
            "invalid integer client input '{value}': {error}"
        ))
    })?;
    Ok(stoffel_vm::net::field_from_i64::<F>(value))
}

enum PartyRole {
    Leader {
        bootnode: SocketAddr,
    },
    Follower {
        party_id: usize,
        bootnode: SocketAddr,
        bind: SocketAddr,
    },
}

struct SpawnPartyContext<'a> {
    program_path: &'a Path,
    identity: &'a NodeIdentity,
    rpc_addr: SocketAddr,
    local_store_path: PathBuf,
    execution_id: ExecutionId,
    role: PartyRole,
    clients: &'a [LocalClientIdentity],
    coord_port: u16,
    timestamp: u64,
    markers: &'a PartyMarkers,
}

#[derive(Clone)]
struct PartyMarkers {
    bootnode: Option<PathBuf>,
    rpc: PathBuf,
    completion: PathBuf,
    network_handoff: PathBuf,
    rpc_handoff: PathBuf,
    reservations: Arc<Mutex<PortReservations>>,
}

#[derive(Default)]
struct PortReservations {
    network: Vec<UdpSocket>,
    rpc: Option<TcpListener>,
}

impl PartyMarkers {
    fn new(directory: &Path, name: &str, has_bootnode: bool) -> Self {
        Self {
            bootnode: has_bootnode.then(|| directory.join(format!("{name}.bootnode-ready"))),
            rpc: directory.join(format!("{name}.rpc-ready")),
            completion: directory.join(format!("{name}.complete")),
            network_handoff: directory.join(format!("{name}.network-handoff")),
            rpc_handoff: directory.join(format!("{name}.rpc-handoff")),
            reservations: Arc::new(Mutex::new(PortReservations::default())),
        }
    }

    fn reserve_ports(&self, leader: bool) -> std::io::Result<(SocketAddr, SocketAddr)> {
        let network = if leader {
            reserve_udp_port_pair()?
        } else {
            vec![UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?]
        };
        let network_addr = network[0].local_addr()?;
        let rpc = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let rpc_addr = rpc.local_addr()?;
        *self
            .reservations
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = PortReservations {
            network,
            rpc: Some(rpc),
        };
        Ok((network_addr, rpc_addr))
    }

    fn service_bind_handoffs(&self) -> std::io::Result<()> {
        let mut reservations = self
            .reservations
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        for (path, is_rpc) in [(&self.network_handoff, false), (&self.rpc_handoff, true)] {
            let grant = PathBuf::from(format!("{}.granted", path.display()));
            if path.exists() && !grant.exists() {
                if is_rpc {
                    reservations.rpc.take();
                } else {
                    reservations.network.clear();
                }
                std::fs::write(grant, b"bind")?;
            }
        }
        Ok(())
    }

    fn last_completed_phase(&self) -> &'static str {
        if self.completion.exists() {
            "coordinated execution completion"
        } else if self.rpc.exists() {
            "party RPC listener readiness"
        } else if self.bootnode.as_ref().is_some_and(|marker| marker.exists()) {
            "leader bootnode readiness"
        } else {
            "process spawn"
        }
    }
}

type PartyJoinResult =
    Option<Result<LocalCoordinatorRunnerResult<LocalPartyOutput>, tokio::task::JoinError>>;
type ClientTaskResult = (
    u64,
    LocalCoordinatorRunnerResult<Option<ClientOutputRecord>>,
);
type ClientJoinResult = Option<Result<ClientTaskResult, tokio::task::JoinError>>;

enum RunEvent {
    Cancelled,
    Party(PartyJoinResult),
    Client(ClientJoinResult),
}

struct TempRunDir {
    path: PathBuf,
}

impl TempRunDir {
    fn new() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!("stoffel-local-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempRunDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn write_node_identities(
    path: &Path,
    count: usize,
) -> LocalCoordinatorRunnerResult<Vec<NodeIdentity>> {
    (0..count)
        .map(|index| {
            let cert = self_signed_certs::client_cert();
            let cert_der = cert.cert.der().to_vec();
            let key_der = cert.signing_key.serialize_der();
            let cert_path = path.join(format!("node{index}.cert.der"));
            let key_path = path.join(format!("node{index}.key.der"));
            std::fs::write(&cert_path, &cert_der)?;
            std::fs::write(&key_path, key_der)?;
            Ok(NodeIdentity {
                cert_path,
                key_path,
                cert_der,
            })
        })
        .collect()
}

fn write_client_identities(
    path: &Path,
    inputs: &[LocalClientInput],
) -> LocalCoordinatorRunnerResult<Vec<LocalClientIdentity>> {
    let mut sorted_inputs = inputs.to_vec();
    sorted_inputs.sort_by_key(|input| input.client_slot);
    // Reserve a contiguous block per client in slot order (clients may supply
    // different numbers of inputs). The VM groups the returned shares per client
    // (see `store_reserved_client_inputs`), so no uniform padding is required.
    let mut next_reserved_index = 0_u64;
    sorted_inputs
        .into_iter()
        .map(|input| {
            let cert = self_signed_certs::client_cert();
            let cert_der = cert.cert.der().to_vec();
            let key_der = cert.signing_key.serialize_der();
            let cert_path = path.join(format!("client{}.cert.der", input.client_slot));
            let key_path = path.join(format!("client{}.key.der", input.client_slot));
            std::fs::write(&cert_path, &cert_der)?;
            std::fs::write(&key_path, key_der)?;
            let reserved_index_start = next_reserved_index;
            next_reserved_index += input.values.len() as u64;
            Ok(LocalClientIdentity {
                client_slot: input.client_slot,
                input,
                cert_path,
                key_path,
                cert_der,
                reserved_index_start,
                output_count: 0,
            })
        })
        .collect()
}

fn public_key_from_cert(cert_der: &[u8]) -> LocalCoordinatorRunnerResult<Vec<u8>> {
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|error| {
        LocalCoordinatorRunnerError::Configuration(format!("parse node certificate: {error:?}"))
    })?;
    Ok(cert.public_key().subject_public_key.data.as_ref().to_vec())
}

async fn wait_for_child(
    name: String,
    mut child: Child,
    markers: PartyMarkers,
    deadline: Instant,
    timeout: Duration,
    cancellation: CancellationToken,
) -> LocalCoordinatorRunnerResult<LocalPartyOutput> {
    let (Some(stdout_pipe), Some(stderr_pipe)) = (child.stdout.take(), child.stderr.take()) else {
        terminate_child(&mut child).await;
        return Err(LocalCoordinatorRunnerError::Configuration(
            "child stdout and stderr must be piped".to_owned(),
        ));
    };
    let tee_output = std::env::var("STOFFEL_LOCAL_RUNNER_TEE")
        .is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"));
    let stdout_task = LogReader::start(name.clone(), "stdout", stdout_pipe, tee_output);
    let stderr_task = LogReader::start(name.clone(), "stderr", stderr_pipe, tee_output);

    let mut completion_seen = None;
    let status = loop {
        if markers.completion.exists() && completion_seen.is_none() {
            completion_seen = Some(Instant::now());
        }
        match markers
            .service_bind_handoffs()
            .and_then(|()| child.try_wait())
        {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                terminate_child(&mut child).await;
                let (_, _, combined) = finish_child_output(&name, stdout_task, stderr_task).await;
                return Err(LocalCoordinatorRunnerError::ParticipantFailure {
                    participant: name,
                    phase: "process supervision",
                    error: format!(
                        "{error} (last completed phase: {})\n{combined}",
                        markers.last_completed_phase()
                    ),
                });
            }
        }
        if cancellation.is_cancelled() {
            terminate_child(&mut child).await;
            let (_stdout, _stderr, combined) =
                finish_child_output(&name, stdout_task, stderr_task).await;
            return Err(LocalCoordinatorRunnerError::ProcessFailures(format!(
                "local party {name} cancelled during cleanup (last completed phase: {})\n{combined}",
                markers.last_completed_phase()
            )));
        }
        if completion_seen.is_some_and(|seen| seen.elapsed() >= PROCESS_EXIT_GRACE) {
            terminate_child(&mut child).await;
            let (_stdout, _stderr, combined) =
                finish_child_output(&name, stdout_task, stderr_task).await;
            return Err(LocalCoordinatorRunnerError::PartyShutdown {
                name,
                grace: PROCESS_EXIT_GRACE,
                output: combined,
            });
        }
        if completion_seen.is_none() && Instant::now() >= deadline {
            let phase = markers.last_completed_phase();
            terminate_child(&mut child).await;
            let (_stdout, _stderr, combined) =
                finish_child_output(&name, stdout_task, stderr_task).await;
            return Err(LocalCoordinatorRunnerError::PartyTimeout {
                name,
                phase,
                timeout,
                output: combined,
            });
        }
        tokio::select! {
            _ = cancellation.cancelled() => {}
            _ = tokio::time::sleep(READINESS_POLL_INTERVAL) => {}
        }
    };

    let (stdout, stderr, combined) = finish_child_output(&name, stdout_task, stderr_task).await;
    if !status.success() {
        return Err(LocalCoordinatorRunnerError::PartyExit {
            name,
            phase: markers.last_completed_phase(),
            status,
            output: combined,
        });
    }
    if !markers.completion.exists() {
        return Err(LocalCoordinatorRunnerError::MissingCompletion {
            name,
            output: combined,
        });
    }

    Ok(LocalPartyOutput {
        name,
        stdout,
        stderr,
        combined,
    })
}

fn spawn_party_monitor(
    tasks: &mut JoinSet<LocalCoordinatorRunnerResult<LocalPartyOutput>>,
    name: String,
    child: Child,
    markers: PartyMarkers,
    deadline: Instant,
    timeout: Duration,
    cancellation: CancellationToken,
) {
    tasks.spawn(wait_for_child(
        name,
        child,
        markers,
        deadline,
        timeout,
        cancellation,
    ));
}

async fn wait_for_readiness(
    phase: &'static str,
    markers: &[(&str, &PathBuf)],
    deadline: Instant,
    timeout: Duration,
    party_tasks: &mut JoinSet<LocalCoordinatorRunnerResult<LocalPartyOutput>>,
    completed: &mut Vec<LocalPartyOutput>,
) -> LocalCoordinatorRunnerResult<()> {
    loop {
        let missing = markers
            .iter()
            .filter(|(_, path)| !path.exists())
            .map(|(name, _)| *name)
            .collect::<Vec<_>>();
        if missing.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(phase_timeout(
                format!("{phase} (missing: {})", missing.join(", ")),
                timeout,
            ));
        }
        tokio::select! {
            result = party_tasks.join_next(), if !party_tasks.is_empty() => {
                // A no-input party may finish between our marker snapshot and
                // this select. Keep its result and recheck readiness instead of
                // treating successful early completion as a startup failure.
                if let Some(Ok(Ok(output))) = result {
                    if markers.iter().any(|(name, path)| *name == output.name && !path.exists()) {
                        return Err(LocalCoordinatorRunnerError::ParticipantFailure {
                            participant: output.name,
                            phase,
                            error: format!("completed without its readiness acknowledgement\n{}", output.combined),
                        });
                    }
                    completed.push(output);
                    continue;
                }
                return match result {
                    Some(Ok(Err(error))) => Err(LocalCoordinatorRunnerError::ParticipantFailure {
                        participant: format!("startup (missing: {})", missing.join(", ")),
                        phase,
                        error: error.to_string(),
                    }),
                    Some(Err(error)) => Err(LocalCoordinatorRunnerError::ParticipantFailure {
                        participant: "party monitor".to_owned(),
                        phase: "startup supervision",
                        error: error.to_string(),
                    }),
                    None => Err(LocalCoordinatorRunnerError::ProcessFailures(
                        format!("all local parties stopped before {phase}")
                    )),
                    Some(Ok(Ok(_))) => unreachable!("handled successful completion above"),
                };
            }
            _ = tokio::time::sleep(READINESS_POLL_INTERVAL) => {}
        }
    }
}

async fn cancel_and_reap_parties(
    cancellation: &CancellationToken,
    tasks: &mut JoinSet<LocalCoordinatorRunnerResult<LocalPartyOutput>>,
) -> Vec<String> {
    cancellation.cancel();
    let mut diagnostics = Vec::new();
    let cleanup_deadline = Instant::now() + CLEANUP_GRACE;
    while !tasks.is_empty() {
        match tokio::time::timeout_at(cleanup_deadline, tasks.join_next()).await {
            Ok(Some(Ok(Ok(output)))) => diagnostics.push(output.combined),
            Ok(Some(Ok(Err(error)))) => diagnostics.push(error.to_string()),
            Ok(Some(Err(error))) => diagnostics.push(error.to_string()),
            Ok(None) => break,
            Err(_) => {
                diagnostics.push("participant cleanup exceeded its deadline".to_owned());
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                break;
            }
        }
    }
    diagnostics
}

async fn cleanup_after_failure(
    error: LocalCoordinatorRunnerError,
    cancellation: &CancellationToken,
    tasks: &mut JoinSet<LocalCoordinatorRunnerResult<LocalPartyOutput>>,
) -> LocalCoordinatorRunnerError {
    let diagnostics = cancel_and_reap_parties(cancellation, tasks)
        .await
        .join("\n");
    if diagnostics.is_empty() {
        error
    } else {
        LocalCoordinatorRunnerError::Cleanup {
            source: Box::new(error),
            diagnostics,
        }
    }
}

async fn terminate_child(child: &mut Child) {
    if child.try_wait().ok().flatten().is_some() {
        return;
    }
    if !matches!(
        tokio::time::timeout(CHILD_KILL_GRACE, child.kill()).await,
        Ok(Ok(()))
    ) {
        let _ = child.start_kill();
        let _ = tokio::time::timeout(CHILD_KILL_GRACE, child.wait()).await;
    }
}

async fn finish_child_output(
    name: &str,
    stdout_task: LogReader,
    stderr_task: LogReader,
) -> (String, String, String) {
    let (stdout, stderr) = tokio::join!(
        finish_log_reader(stdout_task, "stdout"),
        finish_log_reader(stderr_task, "stderr")
    );
    let combined = format!("== {name} stdout ==\n{stdout}\n== {name} stderr ==\n{stderr}\n");
    (stdout, stderr, combined)
}

async fn finish_log_reader(mut reader: LogReader, stream: &'static str) -> String {
    let suffix = match tokio::time::timeout(LOG_DRAIN_GRACE, &mut reader.task).await {
        Ok(Ok(Ok(()))) => String::new(),
        Ok(Ok(Err(error))) => format!("\n<{stream} read failed: {error}>"),
        Ok(Err(error)) => format!("\n<{stream} reader task failed: {error}>"),
        Err(_) => {
            reader.task.abort();
            let _ = (&mut reader.task).await;
            format!("\n<{stream} log drain timed out after {LOG_DRAIN_GRACE:?}>")
        }
    };
    let log = reader
        .output
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    format!("{}{suffix}", String::from_utf8_lossy(&log))
}

fn phase_timeout(phase: impl Into<String>, timeout: Duration) -> LocalCoordinatorRunnerError {
    LocalCoordinatorRunnerError::PhaseTimeout {
        phase: phase.into(),
        timeout,
    }
}

fn cancelled_run() -> LocalCoordinatorRunnerError {
    LocalCoordinatorRunnerError::ProcessFailures("local run cancelled".to_owned())
}

fn party_sort_key(name: &str) -> usize {
    if name == "leader" {
        0
    } else {
        name.strip_prefix("party")
            .and_then(|suffix| suffix.parse().ok())
            .unwrap_or(usize::MAX)
    }
}

struct LogReader {
    task: JoinHandle<std::io::Result<()>>,
    output: Arc<Mutex<Vec<u8>>>,
}

impl LogReader {
    fn start<R: AsyncRead + Unpin + Send + 'static>(
        name: String,
        stream: &'static str,
        mut pipe: R,
        tee: bool,
    ) -> Self {
        let output = Arc::new(Mutex::new(Vec::new()));
        let tail = output.clone();
        let task = tokio::spawn(async move {
            let mut chunk = [0; 8192];
            loop {
                let count = pipe.read(&mut chunk).await?;
                if count == 0 {
                    return Ok(());
                }
                if tee {
                    eprint!(
                        "[{name} {stream}] {}",
                        String::from_utf8_lossy(&chunk[..count])
                    );
                }
                let mut log = tail.lock().unwrap_or_else(|error| error.into_inner());
                let excess = (log.len() + count).saturating_sub(MAX_LOG_BYTES);
                log.drain(..excess);
                log.extend_from_slice(&chunk[..count]);
            }
        });
        Self { task, output }
    }
}

impl Drop for LogReader {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn local_run_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn reserve_udp_port_pair() -> std::io::Result<Vec<UdpSocket>> {
    // Mix the wall-clock nanos with the process id and a per-call counter so
    // that runner processes launched concurrently (e.g. parallel CLI tests)
    // and successive calls within one process begin their scan from different
    // base ports. Retain both UDP sockets until the child requests its bind
    // handoff, including the leader's required +1000 party socket.
    static CALL_COUNTER: AtomicU16 = AtomicU16::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos() as u16)
        .unwrap_or(0);
    let pid = std::process::id() as u16;
    let call = CALL_COUNTER.fetch_add(1, Ordering::Relaxed);
    let seed = nanos
        .wrapping_add(pid.wrapping_mul(7))
        .wrapping_add(call.wrapping_mul(1009));
    for offset in 0..30_000u16 {
        let port = 20_000 + ((seed.wrapping_add(offset)) % 30_000);
        if let Ok(bootnode) = UdpSocket::bind((Ipv4Addr::LOCALHOST, port)) {
            if let Ok(party) = UdpSocket::bind((Ipv4Addr::LOCALHOST, port + 1000)) {
                return Ok(vec![bootnode, party]);
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrNotAvailable,
        "could not reserve a localhost bootnode port with a free +1000 party port in 20000..50999",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use stoffel_vm_types::compiled_binary::{ClientIoSchema, CompiledFunction, FunctionType};
    use stoffel_vm_types::core_types::ShareType;

    fn test_runner(mut binary: CompiledBinary) -> LocalCoordinatorRunnerBuilder {
        binary.functions.push(CompiledFunction {
            name: "main".to_owned(),
            register_count: 0,
            parameters: Vec::new(),
            parameter_types: Vec::new(),
            return_type: FunctionType::Unknown,
            upvalues: Vec::new(),
            parent: None,
            labels: HashMap::new(),
            instructions: Vec::new(),
        });
        LocalCoordinatorRunner::builder("/bin/sh", binary)
    }

    #[test]
    fn client_output_wire_value_preserves_small_signed_field_values() {
        type Fr = ark_bls12_381::Fr;

        assert_eq!(field_to_u64(&Fr::from(98_304u64)), 98_304);
        assert_eq!(field_to_u64(&-Fr::from(32_768u64)) as i64, -32_768);
    }

    #[test]
    fn indexed_mask_assignment_is_keyed_by_reserved_index() {
        let masks = exact_mask_assignment(3, &[40, 41, 42], vec![(42, 12), (40, 10), (41, 11)])
            .expect("reordered indexed masks should be accepted");

        assert_eq!(
            masks.into_iter().collect::<Vec<_>>(),
            vec![(40, 10), (41, 11), (42, 12)]
        );
    }

    #[test]
    fn indexed_mask_assignment_rejects_missing_duplicate_and_unexpected_indices() {
        let missing = exact_mask_assignment(7, &[4, 5], vec![(4, 10)]).unwrap_err();
        assert!(missing.to_string().contains("missing reserved indices [5]"));

        let duplicate = exact_mask_assignment(7, &[4, 5], vec![(4, 10), (4, 11)]).unwrap_err();
        assert!(duplicate.to_string().contains("duplicate reserved index 4"));

        let unexpected = exact_mask_assignment(7, &[4, 5], vec![(4, 10), (6, 11)]).unwrap_err();
        assert!(unexpected
            .to_string()
            .contains("unexpected reserved index 6"));
    }

    #[test]
    fn assigned_mask_batch_rejects_truncation_before_pairing_inputs() {
        assert!(assigned_mask_map(0, &[10, 11], vec![1]).is_err());
        assert!(assigned_mask_map(0, &[10], vec![1, 2]).is_err());
        assert_eq!(assigned_mask_map(0, &[10, 11], vec![3, 4]).unwrap()[&11], 4);
    }

    #[test]
    fn reservations_are_released_only_for_the_requested_bind_phase() {
        let temp = TempRunDir::new().unwrap();
        let markers = PartyMarkers::new(temp.path(), "leader", true);
        let (network, rpc) = markers.reserve_ports(true).unwrap();
        assert!(UdpSocket::bind(network).is_err());
        assert!(UdpSocket::bind((network.ip(), network.port() + 1000)).is_err());
        assert!(TcpListener::bind(rpc).is_err());
        std::fs::write(&markers.network_handoff, b"ready").unwrap();
        markers.service_bind_handoffs().unwrap();
        assert!(markers.reservations.lock().unwrap().network.is_empty());
        assert!(PathBuf::from(format!("{}.granted", markers.network_handoff.display())).exists());
        assert!(TcpListener::bind(rpc).is_err());
        std::fs::write(&markers.rpc_handoff, b"ready").unwrap();
        markers.service_bind_handoffs().unwrap();
        // Once released, another process may legitimately acquire the port.
        // Assert that we dropped ownership and granted the handoff, not that
        // the entire machine leaves this now-unreserved port unused.
        assert!(markers.reservations.lock().unwrap().rpc.is_none());
        assert!(PathBuf::from(format!("{}.granted", markers.rpc_handoff.display())).exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dropping_run_reaps_children_and_releases_coordinator() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let script = temp.path().join("party.sh");
        let pid_path = temp.path().join("pid");
        let args_path = temp.path().join("args");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nprintf '%s' $$ > '{}'\nexec sleep 30\n",
                args_path.display(),
                pid_path.display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut runner = test_runner(CompiledBinary::new()).build().unwrap();
        runner.runner_path = script;
        let run = tokio::spawn(runner.run());
        tokio::time::timeout(Duration::from_secs(5), async {
            while !pid_path.exists() {
                tokio::time::sleep(READINESS_POLL_INTERVAL).await;
            }
        })
        .await
        .unwrap();
        let pid: i32 = std::fs::read_to_string(&pid_path).unwrap().parse().unwrap();
        let args = std::fs::read_to_string(&args_path).unwrap();
        let coordinator = args
            .lines()
            .collect::<Vec<_>>()
            .windows(2)
            .find(|pair| pair[0] == "--off-chain-coord")
            .unwrap()[1]
            .to_owned();
        run.abort();
        let _ = run.await;
        tokio::time::timeout(CLEANUP_GRACE, async {
            loop {
                let exited = unsafe { libc::kill(pid, 0) } == -1;
                let closed = tokio::net::TcpStream::connect(&coordinator).await.is_err();
                if exited && closed {
                    break;
                }
                tokio::time::sleep(READINESS_POLL_INTERVAL).await;
            }
        })
        .await
        .expect("cancelled run must reap the child and close its coordinator");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn first_client_failure_cancels_parties_and_preserves_diagnostics() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let script = temp.path().join("party.sh");
        std::fs::write(
            &script,
            format!(
                r#"#!/bin/sh
printf '%s' $$ > '{dir}/pid.'$$
if [ -n "$STOFFEL_LOCAL_BOOTNODE_READY_FILE" ]; then
  printf ready > "$STOFFEL_LOCAL_BOOTNODE_READY_FILE"
fi
printf ready > "$STOFFEL_LOCAL_RPC_READY_FILE"
printf 'injected party diagnostic\n' >&2
exec sleep 30
"#,
                dir = temp.path().display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut runner = test_runner(CompiledBinary::new())
            .client_inputs([LocalClientInput::raw(0, ["invalid-field"])])
            .build()
            .unwrap();
        runner.runner_path = script;
        let error = tokio::time::timeout(Duration::from_secs(10), runner.run())
            .await
            .expect("client error must not wait for the protocol timeout")
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("client 0"), "{message}");
        assert!(message.contains("invalid-field"), "{message}");
        assert!(message.contains("injected party diagnostic"), "{message}");
        let mut parties = 0;
        for entry in std::fs::read_dir(temp.path()).unwrap() {
            let path = entry.unwrap().path();
            if path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("pid.")
            {
                let pid: i32 = std::fs::read_to_string(path).unwrap().parse().unwrap();
                assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
                parties += 1;
            }
        }
        assert_eq!(parties, 5);
    }

    #[tokio::test]
    async fn log_drain_is_bounded_and_keeps_the_tail_without_newlines() {
        let (mut writer, reader) = tokio::io::duplex(16384);
        let log = LogReader::start("party".to_owned(), "stderr", reader, false);
        use tokio::io::AsyncWriteExt;
        let writing = tokio::spawn(async move {
            writer
                .write_all(&vec![b'x'; MAX_LOG_BYTES + 8192])
                .await
                .unwrap();
            writer.write_all(b"final diagnostic").await.unwrap();
            writer
        });
        let _open_pipe = writing.await.unwrap();
        let output = finish_log_reader(log, "stderr").await;
        assert!(output.contains("final diagnostic"));
        assert!(output.contains("log drain timed out"));
        assert!(output.len() < MAX_LOG_BYTES + 200);
    }

    #[tokio::test]
    async fn readiness_timeout_names_the_missing_participant_and_phase() {
        let temp = TempRunDir::new().unwrap();
        let missing = temp.path().join("party2.rpc-ready");
        let mut party_tasks = JoinSet::new();
        let error = wait_for_readiness(
            "party RPC listener readiness",
            &[("party2", &missing)],
            Instant::now() + Duration::from_millis(30),
            Duration::from_millis(30),
            &mut party_tasks,
            &mut Vec::new(),
        )
        .await
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("party RPC listener readiness (missing: party2)"));
    }

    #[tokio::test]
    async fn readiness_preserves_a_party_that_finishes_during_the_wait() {
        let temp = TempRunDir::new().unwrap();
        let marker = temp.path().join("party1.rpc-ready");
        let ready_marker = marker.clone();
        let mut party_tasks = JoinSet::new();
        party_tasks.spawn(async move {
            std::fs::write(ready_marker, b"ready").unwrap();
            Ok(LocalPartyOutput {
                name: "party1".to_owned(),
                stdout: "result".to_owned(),
                stderr: String::new(),
                combined: "result".to_owned(),
            })
        });
        let mut completed = Vec::new();
        wait_for_readiness(
            "party RPC listener readiness",
            &[("party1", &marker)],
            Instant::now() + Duration::from_secs(1),
            Duration::from_secs(1),
            &mut party_tasks,
            &mut completed,
        )
        .await
        .unwrap();
        // Either the completion branch or the readiness poll can win under
        // load; both must leave the successful output available to the owner.
        while let Some(result) = party_tasks.join_next().await {
            completed.push(result.unwrap().unwrap());
        }
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].stdout, "result");
    }

    #[tokio::test]
    async fn readiness_wait_accepts_a_delayed_acknowledgement() {
        let temp = TempRunDir::new().unwrap();
        let marker = temp.path().join("party1.rpc-ready");
        let delayed_marker = marker.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            std::fs::write(delayed_marker, b"ready").unwrap();
        });
        let mut party_tasks = JoinSet::new();

        wait_for_readiness(
            "party RPC listener readiness",
            &[("party1", &marker)],
            Instant::now() + Duration::from_secs(1),
            Duration::from_secs(1),
            &mut party_tasks,
            &mut Vec::new(),
        )
        .await
        .expect("delayed readiness should recover before the shared deadline");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn completed_child_that_stalls_is_reaped_as_shutdown_failure() {
        let temp = TempRunDir::new().unwrap();
        let markers = PartyMarkers::new(temp.path(), "leader", true);
        std::fs::write(&markers.completion, b"complete").unwrap();

        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "echo 'online VM execution complete' >&2; exec sleep 30",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let child = command.spawn().unwrap();
        let pid = child.id().unwrap() as i32;
        let started = Instant::now();
        let error = wait_for_child(
            "leader".to_owned(),
            child,
            markers,
            Instant::now() + Duration::from_secs(10),
            Duration::from_secs(10),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();

        assert!(matches!(
            error,
            LocalCoordinatorRunnerError::PartyShutdown { .. }
        ));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1, "child must be reaped");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancellation_kills_and_reaps_every_party_child() {
        let temp = TempRunDir::new().unwrap();
        let cancellation = CancellationToken::new();
        let mut tasks = JoinSet::new();
        let mut pids = Vec::new();
        for name in ["leader", "party1"] {
            let markers = PartyMarkers::new(temp.path(), name, name == "leader");
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", "exec sleep 30"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            let child = command.spawn().unwrap();
            pids.push(child.id().unwrap() as i32);
            spawn_party_monitor(
                &mut tasks,
                name.to_owned(),
                child,
                markers,
                Instant::now() + Duration::from_secs(30),
                Duration::from_secs(30),
                cancellation.clone(),
            );
        }

        cancel_and_reap_parties(&cancellation, &mut tasks).await;

        assert!(tasks.is_empty());
        for pid in pids {
            assert_eq!(unsafe { libc::kill(pid, 0) }, -1, "child must be reaped");
        }
    }

    #[test]
    fn expected_clients_create_output_identities_for_dynamic_outputs() {
        let runner = test_runner(CompiledBinary::new())
            .expected_output_clients(2)
            .build()
            .expect("runner");

        let known_clients = runner.known_client_inputs();
        assert_eq!(
            known_clients
                .iter()
                .map(|client| client.client_slot)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert!(known_clients.iter().all(|client| client.values.is_empty()));

        let (n_inputs, output_clients) = runner
            .coordinator_client_io_binding(&[(0, vec![10]), (1, vec![11])])
            .expect("binding");
        assert_eq!(n_inputs, 0);
        assert_eq!(output_clients, vec![vec![10], vec![11]]);
    }

    #[test]
    fn enforces_backend_specific_minimum_party_counts() {
        let avss_error = match test_runner(CompiledBinary::new())
            .backend(MpcBackendKind::Avss)
            .parties(3)
            .build()
        {
            Ok(_) => panic!("AVSS must reject fewer than four parties"),
            Err(error) => error,
        };
        assert!(avss_error
            .to_string()
            .contains("AVSS requires at least 4 parties"));

        test_runner(CompiledBinary::new())
            .backend(MpcBackendKind::Avss)
            .parties(4)
            .build()
            .expect("AVSS should accept four parties");

        let hb_error = match test_runner(CompiledBinary::new())
            .backend(MpcBackendKind::HoneyBadger)
            .parties(4)
            .build()
        {
            Ok(_) => panic!("HoneyBadger must reject fewer than five parties"),
            Err(error) => error,
        };
        assert!(hb_error
            .to_string()
            .contains("HoneyBadger requires at least 5 parties"));

        test_runner(CompiledBinary::new())
            .backend(MpcBackendKind::HoneyBadger)
            .parties(5)
            .build()
            .expect("HoneyBadger should accept five parties");
    }

    #[test]
    fn avss_client_inputs_accept_every_supported_curve() {
        let curves = [
            MpcCurveConfig::Bls12_381,
            MpcCurveConfig::Bn254,
            MpcCurveConfig::Curve25519,
            MpcCurveConfig::Ed25519,
            MpcCurveConfig::Secp256k1,
            MpcCurveConfig::Secp256r1,
        ];

        for curve in curves {
            let mut binary = CompiledBinary::new();
            binary.client_io_manifest.clients = vec![ClientIoSchema {
                client_slot: 0,
                inputs: vec![ShareType::default_secret_int()],
                outputs: Vec::new(),
            }];
            test_runner(binary)
                .backend(MpcBackendKind::Avss)
                .curve(curve)
                .client_input(0, [42])
                .build()
                .unwrap_or_else(|error| panic!("{curve:?} must accept AVSS client input: {error}"));
        }
    }

    #[test]
    fn expected_clients_union_keeps_manifest_inputs_and_output_only_slots() {
        let mut binary = CompiledBinary::new();
        binary.client_io_manifest.clients = vec![ClientIoSchema {
            client_slot: 0,
            inputs: vec![ShareType::default_secret_int()],
            outputs: Vec::new(),
        }];

        let runner = test_runner(binary)
            .expected_output_clients(2)
            .client_input(0, [42])
            .build()
            .expect("runner");

        let known_clients = runner.known_client_inputs();
        assert_eq!(
            known_clients
                .iter()
                .map(|client| client.client_slot)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert_eq!(known_clients[0].values, vec!["42".to_owned()]);
        assert!(known_clients[1].values.is_empty());

        let (n_inputs, output_clients) = runner
            .coordinator_client_io_binding(&[(0, vec![10]), (1, vec![11])])
            .expect("binding");
        assert_eq!(n_inputs, 1);
        assert_eq!(output_clients, vec![vec![10], vec![11]]);
    }
}
