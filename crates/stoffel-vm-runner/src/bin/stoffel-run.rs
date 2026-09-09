use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, FftField, PrimeField};
use ark_std::rand::{rngs::OsRng, RngCore};
use futures::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use stoffel_mpc_coordinator_off_chain::node_rpc::{
    NodeRPCClient as OffChainNodeRPCClient, NodeRPCServer as OffChainNodeRPCServer,
};
use stoffel_mpc_coordinator_off_chain::{
    AssignedMaskReservation, ExecutionRegistration, InputAssignment, InputClientRange,
    OffChainCoordinatorClient,
};
use stoffel_mpc_coordinator_shared::{
    Coordinator, CoordinatorError, ExecutionId as CoordinatorExecutionId, NodeRPCError, Round,
    ShareBound,
};
use stoffel_vm::core_vm::{VirtualMachine, VmCooperativeExecutionMetrics};
use stoffel_vm::net::curve::{
    field_from_i64, field_to_clear_share_value, field_to_i64, SupportedMpcField,
};
use stoffel_vm::net::engine_config::DeploymentMode;
use stoffel_vm::net::hb_engine::{HoneyBadgerMpcEngine, StandingPreprocAction};
use stoffel_vm::net::mpc_engine::{
    AsyncMpcEngine, DurableIdentityDigest, MpcEngine, MpcSessionTopology,
};
use stoffel_vm::net::session::ExecutionId;
use stoffel_vm::net::{
    avss_protocol_instance_id, honeybadger_node_opts_with_truncation,
    honeybadger_protocol_instance_id, honeybadger_protocol_timeout, ExecutionConnectionScanner,
    ExecutionInboundMessage, ExecutionInbox, ExecutionMessageKind, ExecutionScopedNetwork,
    ExecutionTransportMux, ExecutionTransportSource, NodeExecutionContext, NodeSupervisor,
    PreparedNodeExecution, EXECUTION_CLIENT_ROUTE_HELLO_V1 as EXECUTION_CLIENT_HELLO_V1,
};
use stoffel_vm::net::{
    program_id_from_bytes, register_and_wait_for_session, run_bootnode_with_config,
    run_bootnode_with_config_ready, SessionRegistrationConfig,
};
use stoffel_vm::net::{MpcBackendKind, MpcCurveConfig};
use stoffel_vm::runtime_hooks::{HookContext, HookEvent};
use stoffel_vm::storage::preproc::{
    standing_preproc_snapshot, LmdbPreprocStore, OwnedPreprocBundle, PoolAvailability,
    PreprocKeyScope, PreprocStore, StandingPreprocSnapshot,
};
use stoffel_vm::storage::{LocalStorage, RedbLocalStorage};
use stoffel_vm_runner::{
    ResolvedStandingExecutionAdmissionV1, ReturnedShare, StandingClientCatalog,
    StandingExecutionHandler, StandingNodeControl, StandingProgram, StandingProgramCatalog,
};
use stoffel_vm_types::compiled_binary::{
    BinaryError, ClientIoManifest, ClientIoSchema, CompiledBinary,
};
use stoffel_vm_types::core_types::{ClearShareValue, ShareType, TableRef, Value};
use stoffel_vm_types::fixed_point_codec::{encode_fixed_point_float, encode_fixed_point_integer};
use stoffelmpc_mpc::avss_mpc::input::AvssInputError;
#[cfg(feature = "statistics")]
use stoffelmpc_mpc::avss_mpc::statistics::NodeStatisticsCounters as AvssNodeStatisticsCounters;
use stoffelmpc_mpc::avss_mpc::{AvssMPCClient, AvssSessionId};
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::common::MPCProtocol;
use stoffelmpc_mpc::honeybadger::input::InputError;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
#[cfg(feature = "statistics")]
use stoffelmpc_mpc::honeybadger::statistics::NodeStatisticsCounters;
use stoffelmpc_mpc::honeybadger::SessionId as HbSessionId;
use stoffelmpc_mpc::honeybadger::{HoneyBadgerMPCClient, HoneyBadgerMPCNode};
use stoffelnet::network_utils::Network;
use stoffelnet::network_utils::{ClientId, NetworkError, NodePublicKey};
use stoffelnet::transports::quic::{NetworkManager, PeerConnection, QuicNetworkManager};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use x509_parser::prelude::*;
type HbCoordinatorShare<F> = RobustShare<F>;

// Each submission can contain a large encrypted output vector. Keep the default pipeline shallow:
// it overlaps one coordinator round trip without allowing every client payload to queue at once.
const DEFAULT_OUTPUT_SHARE_SUBMISSION_CONCURRENCY: usize = 2;

fn output_share_submission_concurrency() -> usize {
    env::var("STOFFEL_OUTPUT_SHARE_SUBMISSION_CONCURRENCY")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|concurrency| *concurrency > 0)
        .unwrap_or(DEFAULT_OUTPUT_SHARE_SUBMISSION_CONCURRENCY)
}

async fn collect_bounded<I, F, Fut, T>(items: I, concurrency: usize, operation: F) -> Vec<T>
where
    I: IntoIterator,
    F: FnMut(I::Item) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    assert!(concurrency > 0, "bounded concurrency must be non-zero");
    stream::iter(items)
        .map(operation)
        .buffer_unordered(concurrency)
        .collect()
        .await
}

async fn send_output_shares_bounded<F, S>(
    coordinator: &OffChainCoordinatorClient<F, S>,
    submissions: Vec<(Vec<u8>, Vec<S>)>,
) -> Vec<(Vec<u8>, Result<(), CoordinatorError>)>
where
    F: FftField,
    S: ShareBound<F>,
{
    collect_bounded(
        submissions,
        output_share_submission_concurrency(),
        |(client_key, shares)| async move {
            let client_id = client_key.clone();
            let result = coordinator
                .send_output_shares(client_key.clone(), client_key, shares)
                .await;
            (client_id, result)
        },
    )
    .await
}

fn group_output_shares_by_client<T>(
    records: impl IntoIterator<Item = (ClientId, Vec<T>)>,
) -> BTreeMap<ClientId, Vec<T>> {
    let mut grouped = BTreeMap::new();
    for (client_id, mut shares) in records {
        grouped
            .entry(client_id)
            .or_insert_with(Vec::new)
            .append(&mut shares);
    }
    grouped
}

fn read_trimmed_u64(path: &str) -> Option<u64> {
    fs::read_to_string(path)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
}

/// Publish a process-local lifecycle acknowledgement for
/// `LocalCoordinatorRunner`. The marker is written through a sibling temporary
/// file and renamed so the supervisor never observes a partial acknowledgement.
fn write_local_runner_marker_or_exit(variable: &str, phase: &str) {
    let Ok(path) = std::env::var(variable) else {
        return;
    };
    let path = PathBuf::from(path);
    let temporary = path.with_extension("tmp");
    if let Err(error) =
        fs::write(&temporary, phase.as_bytes()).and_then(|()| fs::rename(&temporary, &path))
    {
        eprintln!(
            "Failed to acknowledge {phase} to the local runner at '{}': {error}",
            path.display()
        );
        exit(13);
    }
    eprintln!("[party] local runner acknowledged {phase}");
}

async fn local_bind_handoff(variable: &str) {
    let Ok(path) = std::env::var(variable) else {
        return;
    };
    let grant = PathBuf::from(format!("{path}.granted"));
    if let Err(error) = fs::write(&path, b"ready to bind") {
        eprintln!("Local listener handoff failed: {error}");
        exit(13);
    }
    // The parent retains the actual TCP/UDP sockets until this request. The
    // dependency APIs bind their own sockets, so release immediately before
    // that bind; inheriting sockets would require changing those APIs.
    let wait = async {
        while !grant.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    if tokio::time::timeout(session_registration_timeout(), wait)
        .await
        .is_err()
    {
        eprintln!("Local listener handoff timed out: {variable}");
        exit(13);
    }
}

fn coordinator_execution_already_retired(error: &str) -> bool {
    error.contains(" is not registered")
}

async fn finish_hb_execution<F: PrimeField>(
    coordinator: &HbOffChainCoordinator<F>,
) -> Result<(), String> {
    if let Err(error) = coordinator.finalize().await {
        let error = error.to_string();
        if coordinator_execution_already_retired(&error) {
            return Ok(());
        }
        return Err(error);
    }
    if let Err(error) = coordinator.wait_for_round(Round::ProgramFinished).await {
        let error = error.to_string();
        if coordinator_execution_already_retired(&error) {
            return Ok(());
        }
        return Err(error);
    }
    Ok(())
}

async fn finish_avss_execution<F, G>(
    coordinator: &AvssOffChainCoordinator<F, G>,
) -> Result<(), String>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    if let Err(error) = coordinator.finalize().await {
        let error = error.to_string();
        if coordinator_execution_already_retired(&error) {
            return Ok(());
        }
        return Err(error);
    }
    if let Err(error) = coordinator.wait_for_round(Round::ProgramFinished).await {
        let error = error.to_string();
        if coordinator_execution_already_retired(&error) {
            return Ok(());
        }
        return Err(error);
    }
    Ok(())
}

fn current_cgroup_memory_bytes() -> Option<u64> {
    read_trimmed_u64("/sys/fs/cgroup/memory.current")
        .or_else(|| read_trimmed_u64("/sys/fs/cgroup/memory/memory.usage_in_bytes"))
}

/// Stable eBPF boundary identifiers for the HoneyBadger client-input path.
///
/// Keep the numeric values synchronized with `scripts/stoffel-input-path.bt`.
/// Each marker denotes entry into the named phase; `Complete` closes the final
/// interval.
#[repr(u64)]
#[derive(Clone, Copy)]
enum InputPathPhase {
    ReservationRegistryInit = 1,
    MaskPoolPrepare = 2,
    ReservationProposeRpc = 3,
    ReservationRoundWait = 4,
    ReservedIndicesWait = 5,
    ReservationMirror = 6,
    MaskSharesMaterialize = 7,
    ReservedIndicesPublish = 8,
    MaskShareBatchBuild = 9,
    MaskSharesPublish = 10,
    InputCollectionProposeRpc = 11,
    InputCollectionRoundWait = 12,
    MaskedInputsWaitReconstruct = 13,
    MaskRetire = 14,
    VmInputHydration = 15,
    Complete = 16,
}

/// No-op uprobe target used by the eBPF input-path profiler.
///
/// Exporting one stable C symbol avoids relying on unstable Rust async symbol
/// names. With no tracer attached, this is only one non-inlined function call
/// at each coarse phase boundary and does not perform timing or logging.
#[no_mangle]
#[inline(never)]
pub extern "C" fn stoffel_input_path_probe(phase: u64, clients: u64, inputs: u64) {
    std::hint::black_box((phase, clients, inputs));
}

fn mark_input_path_phase(phase: InputPathPhase, clients: usize, inputs: usize) {
    stoffel_input_path_probe(
        phase as u64,
        u64::try_from(clients).unwrap_or(u64::MAX),
        u64::try_from(inputs).unwrap_or(u64::MAX),
    );
}

/// Owns the detached routing work for one standing execution.
///
/// Tasks spawned through this group observe the execution's cancellation token.
/// Cleanup additionally aborts and joins every task, which makes dropping the
/// receivers (and any retained ingress leases in their queues/current futures)
/// deterministic before the execution ID can be reused.
struct ExecutionTaskGroup {
    cancellation: CancellationToken,
    tasks: TaskTracker,
}

impl ExecutionTaskGroup {
    fn child_of(parent: &CancellationToken) -> Self {
        Self {
            cancellation: parent.child_token(),
            tasks: TaskTracker::new(),
        }
    }

    fn spawn<F>(&self, task: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let cancellation = self.cancellation.clone();
        self.tasks.spawn(async move {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => {}
                _ = task => {}
            }
        });
    }

    fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    async fn shutdown(&self) {
        self.cancellation.cancel();
        self.tasks.close();
        self.tasks.wait().await;
    }

    #[cfg(test)]
    fn task_count(&self) -> usize {
        self.tasks.len()
    }
}

impl Drop for ExecutionTaskGroup {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.tasks.close();
    }
}

fn spawn_execution_task<F>(tasks: Option<&ExecutionTaskGroup>, task: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    if let Some(tasks) = tasks {
        tasks.spawn(task);
    } else {
        // One-shot runners terminate after their sole execution. Standing
        // executions always provide an owner tied to prepared cleanup.
        tokio::spawn(task);
    }
}

fn manifest_client_input_types(
    manifest: &ClientIoManifest,
    runtime_client_count: Option<usize>,
) -> std::collections::BTreeMap<usize, Vec<ShareType>> {
    let mut input_types = manifest
        .clients
        .iter()
        .filter_map(|schema| {
            usize::try_from(schema.client_slot)
                .ok()
                .map(|slot| (slot, schema.inputs.clone()))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    if let Some(runtime_client_count) = runtime_client_count {
        for client_slot in 0..runtime_client_count {
            if let Some(resolved) = manifest.input_types_for_client_slot(client_slot as u64) {
                input_types.insert(client_slot, resolved.to_vec());
            }
        }
    }
    input_types
}

fn manifest_client_input_slots(
    client_input_types: &std::collections::BTreeMap<usize, Vec<ShareType>>,
) -> Vec<usize> {
    client_input_types
        .iter()
        .filter_map(|(slot, inputs)| (!inputs.is_empty()).then_some(*slot))
        .collect()
}

fn checked_client_input_total(counts: impl IntoIterator<Item = usize>) -> Result<usize, String> {
    counts.into_iter().try_fold(0usize, |total, count| {
        total
            .checked_add(count)
            .ok_or_else(|| "standing client-input demand overflows usize".to_owned())
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MaskReservationRun {
    start: u64,
    count: u64,
    client_id: ClientId,
}

/// Validate the coordinator's canonical mask order and coalesce adjacent
/// indices owned by the same client. Standing engines can then remove one
/// correlated share batch per client run instead of one share per RPC index.
fn canonical_mask_reservation_runs(
    reserved_masks: &[(u64, Option<ClientId>)],
) -> Result<impl Iterator<Item = MaskReservationRun> + '_, String> {
    for (position, (index, client_id)) in reserved_masks.iter().copied().enumerate() {
        let expected = u64::try_from(position)
            .map_err(|_| "coordinator mask index exceeds u64 range".to_owned())?;
        if index != expected {
            return Err(format!(
                "coordinator returned non-canonical mask index {index}; expected {expected}"
            ));
        }
        client_id.ok_or_else(|| {
            format!("coordinator reserved mask index {index} for an unadmitted client identity")
        })?;
    }
    Ok(reserved_masks
        .chunk_by(|left, right| left.1 == right.1)
        .map(|run| MaskReservationRun {
            start: run[0].0,
            count: u64::try_from(run.len()).expect("validated mask run length fits u64"),
            client_id: run[0].1.expect("validated mask run has a client identity"),
        }))
}

/// Planned preprocessing material counts for one program run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PlannedPreprocessing {
    n_triples: usize,
    n_random: usize,
    n_prandbit: usize,
    n_prandint: usize,
}

impl PlannedPreprocessing {
    fn availability(self) -> Result<PoolAvailability, String> {
        Ok(PoolAvailability {
            beaver: u32::try_from(self.n_triples)
                .map_err(|_| "triple target exceeds LMDB metadata domain".to_owned())?,
            random: u32::try_from(self.n_random)
                .map_err(|_| "random-share target exceeds LMDB metadata domain".to_owned())?,
            prand_bit: u32::try_from(self.n_prandbit)
                .map_err(|_| "random-bit target exceeds LMDB metadata domain".to_owned())?,
            prand_int: u32::try_from(self.n_prandint)
                .map_err(|_| "random-integer target exceeds LMDB metadata domain".to_owned())?,
        })
    }
}

impl PlannedPreprocessing {
    fn checked_scale(self, capacity: usize) -> Result<Self, String> {
        let capacity = capacity.max(1);
        let scale = |value: usize, label: &str| {
            value.checked_mul(capacity).ok_or_else(|| {
                format!("{label} reservoir target overflows usize: {value} * {capacity}")
            })
        };
        Ok(Self {
            n_triples: scale(self.n_triples, "triple")?,
            n_random: scale(self.n_random, "random-share")?,
            n_prandbit: scale(self.n_prandbit, "random-bit")?,
            n_prandint: scale(self.n_prandint, "random-integer")?,
        })
    }
}

/// Round a demand up to a coarse band for privacy: the observable preprocessing
/// volume reveals only which band the program's demand falls in, not its exact
/// operation count. We band to **eighths of an octave** (the next multiple of
/// 1/8 of the demand's power-of-two floor) rather than to the next full power of
/// two. Full-octave banding can nearly *double* the demand, which both wastes
/// preprocessing and — critically — can push a program that comfortably fits the
/// MPC backend's per-session generation capacity over that ceiling (e.g. a
/// 166k-triple program banded to 262k exceeds HoneyBadger's ~196k triple limit,
/// failing with a spurious `LimitError`). Eighth-octave banding over-provisions
/// by at most ~12.5% while still hiding the exact count to within a size band.
fn band_pow2(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    // Largest power of two <= n (the octave floor).
    let floor_pow2 = if n.is_power_of_two() {
        n
    } else {
        n.next_power_of_two() >> 1
    };
    // Round up to the next multiple of an eighth of that octave.
    let granularity = (floor_pow2 >> 3).max(1);
    n.div_ceil(granularity).saturating_mul(granularity)
}

/// Turn the compiler's static preprocessing-demand estimate into concrete
/// material counts to generate up front. Each count is rounded up to a power of
/// two for privacy (see `band_pow2`); `dynamic` programs (data-dependent loops,
/// recursion, runtime-sized batches) get three extra octaves of headroom because
/// the static estimate may only cover one dynamically-sized iteration. The
/// triple count absorbs the dependency
/// that prandbit generation itself consumes a triple per bit. The random count
/// only covers program-visible random material; HoneyBadger generates the
/// random shares needed to build triples inside `run_preprocessing`.
/// `STOFFEL_PREPROCESSING_TRIPLES` / `STOFFEL_PREPROCESSING_PRANDBITS` override
/// the estimate for unusually loop-heavy programs.
fn plan_preprocessing(
    demand: &stoffel_vm_types::compiled_binary::PreprocessingDemand,
    threshold: usize,
    n_client_random: usize,
) -> PlannedPreprocessing {
    let env_u64 = |name: &str| {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
    };

    // Dynamic programs may undercount, so give them three extra octaves before
    // banding. Standing mode only accepts such manifests when explicitly run
    // with `--allow-dynamic-preprocessing`; the larger safety margin keeps that
    // opt-in path from exhausting its fixed per-execution allocation.
    let with_headroom = |n: u64| -> u64 {
        if demand.dynamic {
            n.saturating_mul(8)
        } else {
            n
        }
    };

    let prandbits = env_u64("STOFFEL_PREPROCESSING_PRANDBITS")
        .map(band_pow2)
        .unwrap_or_else(|| band_pow2(with_headroom(demand.prandbits)));
    let prandints = band_pow2(with_headroom(demand.prandints));
    let direct_randoms = band_pow2(with_headroom(demand.randoms));

    let direct_triples = env_u64("STOFFEL_PREPROCESSING_TRIPLES")
        .map(band_pow2)
        .unwrap_or_else(|| band_pow2(with_headroom(demand.triples)));

    // prandbit generation consumes one triple + one random per bit.
    let mut triple_target = direct_triples.saturating_add(prandbits);
    if triple_target > 0 {
        // Floor to the protocol's minimum triple batch so tiny programs still run.
        triple_target = triple_target.max(2 * threshold as u64 + 1);
    }
    let n_triples = band_pow2(triple_target);
    // HoneyBadger adds and consumes two random shares per triple internally.
    // `n_random` is the pool left for direct program use and prandbit generation
    // after triples have been built; adding `2 * n_triples` here makes the
    // backend generate an extra full random pool.
    let n_random = band_pow2(
        2u64.saturating_add(direct_randoms)
            .saturating_add(prandbits)
            .saturating_add(n_client_random as u64),
    );

    PlannedPreprocessing {
        n_triples: n_triples as usize,
        n_random: n_random as usize,
        n_prandbit: prandbits as usize,
        n_prandint: prandints as usize,
    }
}

type HbOffChainCoordinator<F> = OffChainCoordinatorClient<F, HbCoordinatorShare<F>>;
type HbOffChainNodeRpcClient<F> = OffChainNodeRPCClient<F, HbCoordinatorShare<F>>;
type AvssCoordinatorShare<F, G> = FeldmanShamirShare<F, G>;
type AvssOffChainCoordinator<F, G> = OffChainCoordinatorClient<F, AvssCoordinatorShare<F, G>>;
type AvssOffChainNodeRpcClient<F, G> = OffChainNodeRPCClient<F, AvssCoordinatorShare<F, G>>;

macro_rules! dispatch_avss_curve {
    ($curve:expr, $call:ident) => {
        match $curve {
            MpcCurveConfig::Bls12_381 => {
                $call!(ark_bls12_381::Fr, ark_bls12_381::G1Projective)
            }
            MpcCurveConfig::Bn254 => $call!(ark_bn254::Fr, ark_bn254::G1Projective),
            MpcCurveConfig::Curve25519 => {
                $call!(ark_curve25519::Fr, ark_curve25519::EdwardsProjective)
            }
            MpcCurveConfig::Ed25519 => {
                $call!(ark_ed25519::Fr, ark_ed25519::EdwardsProjective)
            }
            MpcCurveConfig::Secp256k1 => {
                $call!(ark_secp256k1::Fr, ark_secp256k1::Projective)
            }
            MpcCurveConfig::Secp256r1 => {
                $call!(ark_secp256r1::Fr, ark_secp256r1::Projective)
            }
        }
    };
}

macro_rules! dispatch_hb_curve {
    ($curve:expr, $call:ident, $unsupported:expr) => {
        match $curve {
            MpcCurveConfig::Bls12_381 => {
                $call!(ark_bls12_381::Fr, ark_bls12_381::G1Projective)
            }
            MpcCurveConfig::Bn254 => $call!(ark_bn254::Fr, ark_bn254::G1Projective),
            MpcCurveConfig::Curve25519 => {
                $call!(ark_curve25519::Fr, ark_curve25519::EdwardsProjective)
            }
            MpcCurveConfig::Ed25519 => {
                $call!(ark_ed25519::Fr, ark_ed25519::EdwardsProjective)
            }
            MpcCurveConfig::Secp256k1 | MpcCurveConfig::Secp256r1 => $unsupported,
        }
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
enum PreprocessingExchangePhase {
    AvssEcdh,
    HoneyBadgerInventory,
    HoneyBadgerReady,
    AvssInventory,
    AvssReady,
    ReservoirAllocationSnapshot,
    ReservoirAllocationCommit,
    HoneyBadgerTransportReady,
    AvssTransportReady,
}

impl PreprocessingExchangePhase {
    fn domain(self) -> &'static [u8] {
        match self {
            Self::AvssEcdh => b"stoffel-avss-ecdh-transcript-v2",
            Self::HoneyBadgerTransportReady => b"stoffel-hb-transport-ready-v1",
            Self::AvssTransportReady => b"stoffel-avss-transport-ready-v1",
            Self::HoneyBadgerInventory => b"stoffel-hb-preprocessing-inventory-v2",
            Self::HoneyBadgerReady => b"stoffel-hb-preprocessing-ready-v2",
            Self::AvssInventory => b"stoffel-avss-preprocessing-inventory-v2",
            Self::AvssReady => b"stoffel-avss-preprocessing-ready-v2",
            Self::ReservoirAllocationSnapshot => b"stoffel-reservoir-allocation-snapshot-v3",
            Self::ReservoirAllocationCommit => b"stoffel-reservoir-allocation-commit-v2",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum PreprocessingExchangeMessage {
    Value(Vec<u8>),
    Ack([u8; 32]),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PreprocessingExchangeFrame {
    phase: PreprocessingExchangePhase,
    message: PreprocessingExchangeMessage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StandingPreprocessingProposal<T> {
    snapshot: T,
    targets: PoolAvailability,
    nonce: [u8; 32],
}

fn fresh_preprocessing_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut nonce);
    nonce
}

fn validate_preprocessing_proposals<T>(
    proposals: Vec<StandingPreprocessingProposal<T>>,
    expected_targets: PoolAvailability,
    label: &str,
) -> Result<Vec<T>, String> {
    proposals
        .into_iter()
        .enumerate()
        .map(|(party_id, proposal)| {
            if proposal.targets != expected_targets {
                return Err(format!(
                    "party {party_id} proposed divergent {label} preprocessing targets: local={expected_targets:?}, remote={:?}",
                    proposal.targets
                ));
            }
            Ok(proposal.snapshot)
        })
        .collect()
}

fn encode_preprocessing_exchange(frame: &PreprocessingExchangeFrame) -> Result<Vec<u8>, String> {
    bincode::serialize(frame).map_err(|error| format!("serialize preprocessing exchange: {error}"))
}

fn decode_preprocessing_exchange(payload: &[u8]) -> Result<PreprocessingExchangeFrame, String> {
    bincode::deserialize(payload)
        .map_err(|error| format!("deserialize preprocessing exchange: {error}"))
}

fn preprocessing_transcript_digest(
    phase: PreprocessingExchangePhase,
    execution_id: ExecutionId,
    values: &[Option<Vec<u8>>],
) -> Result<[u8; 32], String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"stoffel-standing-preprocessing-transcript-v2");
    hasher.update(&(phase.domain().len() as u64).to_le_bytes());
    hasher.update(phase.domain());
    hasher.update(execution_id.as_bytes());
    hasher.update(&(values.len() as u64).to_le_bytes());
    for (sender_id, value) in values.iter().enumerate() {
        let value = value
            .as_ref()
            .ok_or_else(|| format!("preprocessing transcript is missing party {sender_id}"))?;
        hasher.update(&(sender_id as u64).to_le_bytes());
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn record_preprocessing_exchange_value<T: PartialEq>(
    slots: &mut [Option<T>],
    sender_id: usize,
    value: T,
    label: &str,
) -> Result<(), String> {
    match slots
        .get_mut(sender_id)
        .ok_or_else(|| format!("{label} sender {sender_id} is outside the party set"))?
    {
        slot @ None => {
            *slot = Some(value);
            Ok(())
        }
        Some(existing) if existing == &value => Ok(()),
        Some(_) => Err(format!(
            "authenticated party {sender_id} equivocated during {label}"
        )),
    }
}

struct CompletedPreprocessingTranscript {
    digest: [u8; 32],
    acknowledgement: Vec<u8>,
}

fn preprocessing_transcript_ack_if_complete(
    phase: PreprocessingExchangePhase,
    execution_id: ExecutionId,
    values: &[Option<Vec<u8>>],
    local_digest: Option<[u8; 32]>,
) -> Result<Option<CompletedPreprocessingTranscript>, String> {
    if local_digest.is_some() || values.iter().any(Option::is_none) {
        return Ok(None);
    }

    let digest = preprocessing_transcript_digest(phase, execution_id, values)?;
    let acknowledgement = encode_preprocessing_exchange(&PreprocessingExchangeFrame {
        phase,
        message: PreprocessingExchangeMessage::Ack(digest),
    })?;
    Ok(Some(CompletedPreprocessingTranscript {
        digest,
        acknowledgement,
    }))
}

async fn advertise_preprocessing_ack(
    network: &ExecutionScopedNetwork,
    party_id: usize,
    acknowledgement: &[u8],
    advertised: &mut [bool],
) {
    for (peer_id, peer_advertised) in advertised.iter_mut().enumerate() {
        if peer_id == party_id || *peer_advertised {
            continue;
        }
        match network.send(peer_id, acknowledgement).await {
            Ok(_) => *peer_advertised = true,
            Err(error) => eprintln!(
                "party {} failed to acknowledge preprocessing transcript to party {peer_id}: {error}",
                party_id
            ),
        }
    }
}

/// Route preprocessing coordination without creating a second inbox reader.
#[allow(clippy::too_many_arguments)]
async fn preprocessing_transcript_exchange<T>(
    network: &ExecutionScopedNetwork,
    receiver: &mut mpsc::Receiver<ExecutionInboundMessage>,
    execution_id: ExecutionId,
    party_id: usize,
    parties: usize,
    cancellation: &CancellationToken,
    timeout: Duration,
    phase: PreprocessingExchangePhase,
    local_value: &T,
) -> Result<(Vec<T>, [u8; 32]), String>
where
    T: Serialize + serde::de::DeserializeOwned,
{
    if parties == 0 || party_id >= parties {
        return Err(format!(
            "invalid preprocessing exchange topology: party {} of {}",
            party_id, parties
        ));
    }
    let local_value = bincode::serialize(local_value)
        .map_err(|error| format!("serialize local preprocessing value: {error}"))?;
    let value_frame = encode_preprocessing_exchange(&PreprocessingExchangeFrame {
        phase,
        message: PreprocessingExchangeMessage::Value(local_value.clone()),
    })?;
    let mut values = vec![None; parties];
    values[party_id] = Some(local_value);
    let mut acknowledgements = vec![None; parties];
    let mut ack_advertised = vec![false; parties];
    ack_advertised[party_id] = true;

    let exchange = async {
        let mut retry = tokio::time::interval(STANDING_PREPROC_CONTROL_RETRY_INTERVAL);
        retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut local_digest = None;
        let mut acknowledgement = None;
        while local_digest.is_none()
            || acknowledgements.iter().any(Option::is_none)
            || ack_advertised.iter().any(|advertised| !advertised)
        {
            if let Some(completed) = preprocessing_transcript_ack_if_complete(
                phase,
                execution_id,
                &values,
                local_digest,
            )? {
                local_digest = Some(completed.digest);
                acknowledgements[party_id] = Some(completed.digest);
                // This is the latency-sensitive first advertisement. The interval below is only
                // for retrying failed sends; a healthy exchange must not wait for its next tick.
                advertise_preprocessing_ack(
                    network,
                    party_id,
                    &completed.acknowledgement,
                    &mut ack_advertised,
                )
                .await;
                acknowledgement = Some(completed.acknowledgement);
            }

            tokio::select! {
                _ = cancellation.cancelled() => {
                    return Err("preprocessing transcript exchange cancelled".to_owned());
                }
                _ = retry.tick() => {
                    for peer_id in 0..parties {
                        if peer_id != party_id {
                            if let Err(error) = network.send(peer_id, &value_frame).await {
                                eprintln!("party {} failed to advertise preprocessing value to party {peer_id}: {error}", party_id);
                            }
                        }
                    }
                    if let Some(ack) = acknowledgement.as_deref() {
                        advertise_preprocessing_ack(
                            network,
                            party_id,
                            ack,
                            &mut ack_advertised,
                        )
                        .await;
                    }
                }
                inbound = receiver.recv() => {
                    let inbound = inbound.ok_or_else(|| {
                        "preprocessing exchange channel closed before agreement".to_owned()
                    })?;
                    let sender_id = match inbound.source {
                        ExecutionTransportSource::Party(sender_id) => sender_id,
                        ExecutionTransportSource::Client(_) => continue,
                    };
                    let frame = match decode_preprocessing_exchange(&inbound.payload) {
                        Ok(frame) => frame,
                        Err(error) => {
                            eprintln!("ignoring malformed party exchange: {error}");
                            continue;
                        }
                    };
                    if frame.phase != phase {
                        continue;
                    }
                    if sender_id >= parties {
                        return Err(format!(
                            "preprocessing exchange sender {} is outside party set {}",
                            sender_id, parties
                        ));
                    }
                    match frame.message {
                        PreprocessingExchangeMessage::Value(value) => {
                            record_preprocessing_exchange_value(
                                &mut values,
                                sender_id,
                                value,
                                "preprocessing transcript value",
                            )?;
                        }
                        PreprocessingExchangeMessage::Ack(digest) => {
                            record_preprocessing_exchange_value(
                                &mut acknowledgements,
                                sender_id,
                                digest,
                                "preprocessing transcript acknowledgement",
                            )?;
                        }
                    }
                }
            }

            if let Some(expected) = local_digest {
                for (party_id, received) in acknowledgements.iter().enumerate() {
                    let Some(received) = received else { continue };
                    if received != &expected {
                        return Err(format!(
                            "party {party_id} acknowledged a divergent preprocessing transcript"
                        ));
                    }
                }
            }
        }
        local_digest.ok_or_else(|| {
            "preprocessing exchange completed without a transcript digest".to_owned()
        })
    };

    let digest = tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| format!("timed out during {:?} preprocessing exchange", phase))??;
    let values = values
        .into_iter()
        .enumerate()
        .map(|(sender_id, value)| {
            let value =
                value.ok_or_else(|| format!("preprocessing exchange missing party {sender_id}"))?;
            bincode::deserialize(&value).map_err(|error| {
                format!("decode preprocessing value from party {sender_id}: {error}")
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((values, digest))
}

/// Wait until the local protocol inbox processor is running, then prove that
/// every party has reached the same point over the execution-scoped transport.
/// Receiving the complete transcript also proves that each peer's physical
/// receive loop and execution inbox are routing control frames bidirectionally.
#[allow(clippy::too_many_arguments)]
async fn synchronize_preprocessing_transport(
    network: &ExecutionScopedNetwork,
    receiver: &mut mpsc::Receiver<ExecutionInboundMessage>,
    execution_id: ExecutionId,
    party_id: usize,
    parties: usize,
    instance_id: u64,
    cancellation: &CancellationToken,
    timeout: Duration,
    phase: PreprocessingExchangePhase,
    backend: &str,
    processor_ready: oneshot::Receiver<()>,
) -> Result<(), String> {
    tokio::time::timeout(timeout, async {
        tokio::select! {
            result = processor_ready => result.map_err(|_| {
                format!("{backend} execution inbox processor stopped before signaling readiness")
            }),
            _ = cancellation.cancelled() => {
                Err(format!("{backend} execution inbox readiness was cancelled"))
            }
        }
    })
    .await
    .map_err(|_| {
        format!("timed out waiting for the local {backend} execution inbox processor")
    })??;

    if parties > 1 {
        let (ready_instances, _) = preprocessing_transcript_exchange(
            network,
            receiver,
            execution_id,
            party_id,
            parties,
            cancellation,
            timeout,
            phase,
            &instance_id,
        )
        .await?;
        if ready_instances.iter().any(|ready| *ready != instance_id) {
            return Err(format!(
                "parties reported divergent {backend} protocol instances during transport readiness"
            ));
        }
    }

    eprintln!("[party {party_id}] {backend} execution transport ready for preprocessing");
    Ok(())
}

const STANDING_PREPROC_CONTROL_RETRY_INTERVAL: Duration = Duration::from_millis(250);
/// Unregisters an execution inbox on every return path. Full execution IDs are
/// globally non-reusable in standing mode.
struct ExecutionInboxRegistrationGuard {
    mux: ExecutionTransportMux,
    execution_id: ExecutionId,
}

impl ExecutionInboxRegistrationGuard {
    fn new(mux: ExecutionTransportMux, execution_id: ExecutionId) -> Self {
        Self { mux, execution_id }
    }
}

impl Drop for ExecutionInboxRegistrationGuard {
    fn drop(&mut self) {
        self.mux.unregister(self.execution_id);
    }
}

fn start_party_execution_transport(
    network: &QuicNetworkManager,
    execution_id: ExecutionId,
) -> Result<
    (
        ExecutionTransportMux,
        ExecutionInbox,
        ExecutionInboxRegistrationGuard,
        ExecutionConnectionScanner,
    ),
    String,
> {
    let mux = ExecutionTransportMux::new(4096).map_err(|error| error.to_string())?;
    let inbox = mux
        .register(execution_id)
        .map_err(|error| error.to_string())?;
    let registration = ExecutionInboxRegistrationGuard::new(mux.clone(), execution_id);
    let scanner = ExecutionConnectionScanner::spawn(network.clone(), mux.clone())
        .map_err(|error| error.to_string())?;
    Ok((mux, inbox, registration, scanner))
}

fn require_network_execution_id(execution_id: Option<ExecutionId>) -> ExecutionId {
    execution_id.unwrap_or_else(|| {
        eprintln!("Error: --execution-id <64-hex-chars> is required for MPC party sessions");
        exit(2);
    })
}

fn coordinator_execution_id(execution_id: ExecutionId) -> CoordinatorExecutionId {
    CoordinatorExecutionId::from_bytes(*execution_id.as_bytes())
}

fn session_registration_timeout() -> Duration {
    let seconds = env::var("STOFFEL_SESSION_REGISTRATION_TIMEOUT_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(120);
    Duration::from_secs(seconds)
}

/// Bound execution-control exchanges that intentionally require every party
/// (client-roster agreement, AVSS key agreement, and standing-reservoir
/// allocation). These are fail-closed barriers rather than threshold opens:
/// proceeding without an identical transcript can make parties consume
/// different correlated preprocessing material.
fn execution_coordination_timeout() -> Duration {
    let seconds = env::var("STOFFEL_EXECUTION_COORDINATION_TIMEOUT_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(120);
    Duration::from_secs(seconds)
}

fn extract_pubkey_from_cert(cert_der: &[u8]) -> Vec<u8> {
    let (_, parsed) = X509Certificate::from_der(cert_der).expect("parse X.509 cert");
    parsed
        .public_key()
        .subject_public_key
        .data
        .as_ref()
        .to_vec()
}

fn durable_identity_from_cert(cert_der: &[u8]) -> DurableIdentityDigest {
    DurableIdentityDigest::from_cert_der(cert_der).unwrap_or_else(|error| {
        eprintln!("Error: failed to derive durable identity from certificate: {error}");
        exit(2);
    })
}

fn required_storage_identity(
    cert_der: &Option<Vec<u8>>,
    key_der: &Option<Vec<u8>>,
    storage_enabled: bool,
) -> Option<DurableIdentityDigest> {
    if !storage_enabled {
        return None;
    }
    let cert = cert_der.as_ref().unwrap_or_else(|| {
        eprintln!("Error: --cert is required when persistent VM/preprocessing storage is enabled");
        exit(2);
    });
    let _key = key_der.as_ref().unwrap_or_else(|| {
        eprintln!("Error: --key is required when persistent VM/preprocessing storage is enabled");
        exit(2);
    });
    Some(durable_identity_from_cert(cert))
}

/// One physical accept loop owns the process-lifetime QUIC listener. Execution
/// handlers only consume their envelope-demultiplexed inboxes; starting an
/// accept loop per execution makes concurrent jobs race for new clients.
fn spawn_connection_accept_loop(
    mut network: QuicNetworkManager,
    party_id: usize,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match network.accept().await {
                Ok(connection) => {
                    // `accept` handles both external clients and authenticated
                    // party reconnects. Recompute the stable certificate-sorted
                    // party IDs after a peer replaces a dead physical QUIC
                    // connection so the shared execution scanner sees the
                    // canonical sender identity.
                    let assigned = network.assign_party_ids();
                    eprintln!(
                        "[party {party_id}] Accepted {:?} connection from {} (assigned_party_connections={assigned})",
                        connection.get_connection_role(),
                        connection.remote_address(),
                    );
                }
                Err(error) => {
                    eprintln!("[party {party_id}] Connection accept error: {error}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    })
}

/// Keep the fixed-membership standing mesh connected for the lifetime of the
/// process. The higher certificate-derived ID dials each pair, matching the
/// transport's duplicate-connection tie-breaker while allowing a transient
/// partition or closed stream to heal without restarting the deployment.
fn spawn_standing_mesh_reconnect_loop(
    mut network: QuicNetworkManager,
    peers: Vec<(NodePublicKey, SocketAddr)>,
    party_id: usize,
    cancellation: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let local_transport_id = network.local_derived_id();
    tokio::spawn(async move {
        let mut retry = tokio::time::interval(Duration::from_millis(500));
        retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = cancellation.cancelled() => return,
                _ = retry.tick() => {}
            }

            network.cleanup_dead_connections().await;
            for (peer_public_key, address) in &peers {
                let peer_transport_id = peer_public_key.derive_id();
                if peer_transport_id == local_transport_id
                    || local_transport_id < peer_transport_id
                    || network.is_party_connected(peer_transport_id).await
                {
                    continue;
                }

                eprintln!(
                    "[party {party_id}] standing mesh reconnecting to transport peer {peer_transport_id} at {address}"
                );
                match tokio::time::timeout(
                    Duration::from_secs(3),
                    network.connect_as_server_with_expected_public_key(*address, peer_public_key),
                )
                .await
                {
                    Ok(Ok(_)) => {
                        let assigned = network.assign_party_ids();
                        eprintln!(
                            "[party {party_id}] standing mesh reconnected to transport peer {peer_transport_id} (assigned_party_connections={assigned})"
                        );
                    }
                    Ok(Err(error)) => eprintln!(
                        "[party {party_id}] standing mesh reconnect to transport peer {peer_transport_id} failed: {error}"
                    ),
                    Err(_) => eprintln!(
                        "[party {party_id}] standing mesh reconnect to transport peer {peer_transport_id} timed out"
                    ),
                }
            }
        }
    })
}
#[derive(Debug, Clone)]
enum CoordinatorOutputFormat {
    FieldInteger,
    FixedPoint { fractional_bits: usize },
    Manifest(Vec<ShareType>),
}

#[derive(Debug, Clone)]
struct ClientManifestSemantics {
    client_slot: u64,
    inputs: Vec<ShareType>,
    outputs: Vec<ShareType>,
}

fn load_client_manifest_semantics(
    program_path: &Path,
    requested_slot: Option<u64>,
    reserved_input_index: Option<u64>,
    input_count: usize,
    requested_output_count: Option<usize>,
) -> Result<ClientManifestSemantics, String> {
    let file = File::open(program_path).map_err(|error| {
        format!(
            "failed to open client program '{}': {error}",
            program_path.display()
        )
    })?;
    let binary = CompiledBinary::deserialize(&mut BufReader::new(file)).map_err(|error| {
        format!(
            "failed to load client program manifest '{}': {error:?}",
            program_path.display()
        )
    })?;
    let manifest = &binary.client_io_manifest;
    let clients = &manifest.clients;
    if clients.is_empty() && manifest.dynamic_client_inputs.is_empty() {
        return Err(format!(
            "program '{}' has no client-I/O manifest",
            program_path.display()
        ));
    }

    let (client_slot, inputs, outputs) = match requested_slot {
        Some(slot) => client_manifest_semantics_for_slot(manifest, slot).ok_or_else(|| {
            let available = manifest_client_slots(manifest);
            format!(
                "client slot {slot} is absent from program '{}'; available slots: {available}",
                program_path.display()
            )
        })?,
        None if reserved_input_index.is_some() && input_count > 0 => {
            let reserved_input_index = reserved_input_index.expect("checked above");
            let slot = client_slot_for_reserved_index(manifest, reserved_input_index).ok_or_else(
                || {
                    format!(
                        "coordinator input index {reserved_input_index} is not the start of a client input range in '{}'; pass --client-slot <slot>",
                        program_path.display()
                    )
                },
            )?;
            client_manifest_semantics_for_slot(manifest, slot)
                .expect("reserved input slot came from this manifest")
        }
        None => {
            let mut candidates = clients
                .iter()
                .filter(|schema| {
                    schema.inputs.len() == input_count
                        && requested_output_count.is_none_or(|count| schema.outputs.len() == count)
                })
                .map(|schema| {
                    (
                        schema.client_slot,
                        schema.inputs.as_slice(),
                        schema.outputs.as_slice(),
                    )
                })
                .collect::<Vec<_>>();
            candidates.extend(
                manifest
                    .dynamic_client_inputs
                    .iter()
                    .filter(|schema| {
                        schema.inputs.len() == input_count
                            && requested_output_count.is_none_or(|count| count == 0)
                    })
                    .map(|schema| {
                        (
                            schema.first_client_slot,
                            schema.inputs.as_slice(),
                            &[] as &[ShareType],
                        )
                    }),
            );
            candidates.dedup_by(|left, right| left.1 == right.1 && left.2 == right.2);
            match candidates.as_slice() {
                [schema] => *schema,
                [] if clients.len() == 1 => {
                    let schema = &clients[0];
                    (
                        schema.client_slot,
                        schema.inputs.as_slice(),
                        schema.outputs.as_slice(),
                    )
                }
                [] => {
                    return Err(format!(
                        "no client schema in '{}' matches {input_count} input(s){}; pass --client-slot <slot>",
                        program_path.display(),
                        requested_output_count
                            .map(|count| format!(" and {count} output(s)"))
                            .unwrap_or_default()
                    ));
                }
                _ => {
                    let slots = candidates
                        .iter()
                        .map(|(slot, _, _)| slot.to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    return Err(format!(
                        "client schema is ambiguous in '{}'; matching slots are {slots}. Pass --client-slot <slot>",
                        program_path.display()
                    ));
                }
            }
        }
    };

    if inputs.len() != input_count {
        return Err(format!(
            "client slot {} expects {} input value(s) from the program manifest, got {input_count}",
            client_slot,
            inputs.len()
        ));
    }
    if let Some(output_count) = requested_output_count {
        if outputs.len() != output_count {
            return Err(format!(
                "client slot {} expects {} output value(s) from the program manifest, but --outputs requested {output_count}",
                client_slot,
                outputs.len()
            ));
        }
    }

    Ok(ClientManifestSemantics {
        client_slot,
        inputs: inputs.to_vec(),
        outputs: outputs.to_vec(),
    })
}

fn client_manifest_semantics_for_slot(
    manifest: &ClientIoManifest,
    client_slot: u64,
) -> Option<(u64, &[ShareType], &[ShareType])> {
    let concrete = manifest
        .clients
        .iter()
        .find(|schema| schema.client_slot == client_slot);
    let inputs = manifest.input_types_for_client_slot(client_slot)?;
    let outputs = concrete
        .map(|schema| schema.outputs.as_slice())
        .unwrap_or(&[]);
    Some((client_slot, inputs, outputs))
}

fn client_schema_for_reserved_index(
    clients: &[ClientIoSchema],
    reserved_input_index: u64,
) -> Option<&ClientIoSchema> {
    let mut ordered = clients.iter().collect::<Vec<_>>();
    ordered.sort_unstable_by_key(|schema| schema.client_slot);
    let mut next_index = 0_u64;
    for schema in ordered {
        if !schema.inputs.is_empty() && next_index == reserved_input_index {
            return Some(schema);
        }
        next_index = next_index.checked_add(u64::try_from(schema.inputs.len()).ok()?)?;
    }
    None
}

fn client_slot_for_reserved_index(
    manifest: &ClientIoManifest,
    reserved_input_index: u64,
) -> Option<u64> {
    if manifest.dynamic_client_inputs.is_empty() {
        return client_schema_for_reserved_index(&manifest.clients, reserved_input_index)
            .map(|schema| schema.client_slot);
    }

    let max_static_slot = manifest
        .clients
        .iter()
        .map(|schema| schema.client_slot)
        .max()
        .unwrap_or(0);
    let max_slot = max_static_slot.max(u64::from(u8::MAX));
    let mut next_index = 0_u64;
    for client_slot in 0..=max_slot {
        let inputs = manifest
            .input_types_for_client_slot(client_slot)
            .unwrap_or(&[]);
        if !inputs.is_empty() && next_index == reserved_input_index {
            return Some(client_slot);
        }
        next_index = next_index.checked_add(u64::try_from(inputs.len()).ok()?)?;
        if next_index > reserved_input_index {
            return None;
        }
    }
    None
}

fn manifest_client_slots(manifest: &ClientIoManifest) -> String {
    let mut slots = manifest
        .clients
        .iter()
        .map(|schema| schema.client_slot.to_string())
        .collect::<Vec<_>>();
    slots.extend(
        manifest
            .dynamic_client_inputs
            .iter()
            .map(|schema| format!("{}+ (runtime)", schema.first_client_slot)),
    );
    slots.join(", ")
}

fn semantic_client_input_count(inputs: Option<&str>) -> usize {
    inputs
        .filter(|inputs| !inputs.trim().is_empty())
        .map(|inputs| inputs.split(',').count())
        .unwrap_or(0)
}

fn encode_manifest_client_inputs(
    inputs: Option<&str>,
    share_types: &[ShareType],
) -> Result<Option<String>, String> {
    let values = inputs
        .filter(|inputs| !inputs.trim().is_empty())
        .map(|inputs| inputs.split(',').map(str::trim).collect::<Vec<_>>())
        .unwrap_or_default();
    if values.len() != share_types.len() {
        return Err(format!(
            "program manifest expects {} client input value(s), got {}",
            share_types.len(),
            values.len()
        ));
    }
    if values.is_empty() {
        return Ok(None);
    }

    values
        .into_iter()
        .zip(share_types)
        .enumerate()
        .map(|(index, (value, share_type))| {
            encode_manifest_client_input(value, *share_type)
                .map_err(|error| format!("client input {index}: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|values| Some(values.join(",")))
}

fn encode_manifest_client_input(value: &str, share_type: ShareType) -> Result<String, String> {
    match share_type {
        ShareType::SecretField => Err("field inputs require --raw-client-io".to_owned()),
        ShareType::SecretFixedPoint { precision } => {
            if value.starts_with("0x") || value.starts_with("0X") {
                return Err(
                    "fixed-point inputs must be ordinary integers or decimals; use --raw-client-io for an encoded field value"
                        .to_owned(),
                );
            }
            let encoded = match value.parse::<i128>() {
                Ok(integer) => encode_fixed_point_integer(integer, precision),
                Err(_) => {
                    let value = value
                        .parse::<f64>()
                        .map_err(|_| format!("invalid fixed-point value '{value}'"))?;
                    encode_fixed_point_float(value, precision)
                }
            };
            encoded
                .map_err(|error| error.to_string())
                .map(|encoded| encoded.to_string())
        }
        ShareType::SecretInt { bit_length: 1 } => match value {
            "true" => Ok("1".to_owned()),
            "false" => Ok("0".to_owned()),
            value => value
                .parse::<i64>()
                .map(|value| i64::from(value != 0).to_string())
                .map_err(|_| format!("invalid boolean value '{value}'")),
        },
        ShareType::SecretInt { .. } => {
            if value.starts_with("0x") || value.starts_with("0X") {
                return Ok(value.to_owned());
            }
            value
                .parse::<i64>()
                .map(|value| value.to_string())
                .map_err(|_| format!("invalid signed integer value '{value}'"))
        }
        ShareType::SecretUInt { bit_length } => {
            if value.starts_with("0x") || value.starts_with("0X") {
                return Ok(value.to_owned());
            }
            let value = value
                .parse::<u64>()
                .map_err(|_| format!("invalid unsigned integer value '{value}'"))?;
            if bit_length < u64::BITS as usize && value >= (1_u64 << bit_length) {
                return Err(format!(
                    "unsigned value {value} does not fit the declared {bit_length}-bit range"
                ));
            }
            Ok(value.to_string())
        }
    }
}
fn render_fixed_point_i64(scaled: i64, fractional_bits: usize) -> Option<String> {
    let scale = 1_i128.checked_shl(u32::try_from(fractional_bits).ok()?)?;
    if scale == 0 {
        return None;
    }

    let scaled = i128::from(scaled);
    let negative = scaled < 0;
    let magnitude = scaled.abs();
    let whole = magnitude / scale;
    let mut remainder = magnitude % scale;

    if remainder == 0 {
        return Some(if negative {
            format!("-{whole}")
        } else {
            whole.to_string()
        });
    }

    let mut fractional = String::new();
    while remainder != 0 {
        remainder *= 10;
        let digit = remainder / scale;
        fractional.push(char::from(b'0' + u8::try_from(digit).ok()?));
        remainder %= scale;
    }

    Some(if negative {
        format!("-{whole}.{fractional}")
    } else {
        format!("{whole}.{fractional}")
    })
}
fn format_coordinator_outputs<F>(outputs: &[F], output_format: &CoordinatorOutputFormat) -> String
where
    F: PrimeField + Copy + PartialEq + std::fmt::Debug,
{
    let rendered = outputs
        .iter()
        .copied()
        .enumerate()
        .map(
            |(index, output)| match (field_to_i64(output), output_format) {
                (Ok(signed), CoordinatorOutputFormat::FieldInteger)
                    if field_from_i64::<F>(signed) == output =>
                {
                    signed.to_string()
                }
                (Ok(signed), CoordinatorOutputFormat::FixedPoint { fractional_bits })
                    if field_from_i64::<F>(signed) == output =>
                {
                    render_fixed_point_i64(signed, *fractional_bits)
                        .unwrap_or_else(|| format!("{output:?}"))
                }
                (_, CoordinatorOutputFormat::Manifest(output_types)) => output_types
                    .get(index)
                    .and_then(|share_type| format_manifest_client_output(output, *share_type))
                    .unwrap_or_else(|| format!("{output:?}")),
                _ => format!("{output:?}"),
            },
        )
        .collect::<Vec<_>>()
        .join(", ");

    format!("[{}]", rendered)
}

fn format_manifest_client_output<F>(output: F, share_type: ShareType) -> Option<String>
where
    F: PrimeField + Copy,
{
    match field_to_clear_share_value(share_type, output).ok()? {
        ClearShareValue::Integer(value) => Some(value.to_string()),
        ClearShareValue::UnsignedInteger(value) => Some(value.to_string()),
        ClearShareValue::Boolean(value) => Some(value.to_string()),
        ClearShareValue::FixedPoint(_) => {
            let precision = share_type.precision()?;
            render_fixed_point_i64(field_to_i64(output).ok()?, precision.fractional_bits())
        }
    }
}
trait ReservedMaskIndices {
    fn into_reserved_indices(self) -> Vec<u64>;
}
impl ReservedMaskIndices for u64 {
    fn into_reserved_indices(self) -> Vec<u64> {
        vec![self]
    }
}
impl ReservedMaskIndices for Vec<u64> {
    fn into_reserved_indices(self) -> Vec<u64> {
        self
    }
}
fn normalize_client_to_indices<I, V>(
    client_to_indices: std::collections::HashMap<I, V>,
) -> std::collections::HashMap<I, Vec<u64>>
where
    I: Eq + std::hash::Hash,
    V: ReservedMaskIndices,
{
    client_to_indices
        .into_iter()
        .map(|(client_id, indices)| (client_id, indices.into_reserved_indices()))
        .collect()
}

fn sorted_assigned_mask_reservations(
    client_to_indices: &std::collections::HashMap<Vec<u8>, Vec<u64>>,
) -> Vec<AssignedMaskReservation> {
    let reservation_count = client_to_indices.values().map(Vec::len).sum();
    let mut reservations = Vec::with_capacity(reservation_count);
    for (client, indices) in client_to_indices {
        reservations.extend(indices.iter().map(|index| AssignedMaskReservation {
            client: client.clone(),
            reserved_index: *index,
            input_ordinal: *index,
        }));
    }
    reservations.sort_unstable_by_key(|reservation| reservation.reserved_index);
    reservations
}

fn store_reserved_client_inputs<F, I>(
    vm: &mut VirtualMachine,
    client_to_indices: &std::collections::HashMap<I, Vec<u64>>,
    client_inputs: std::collections::HashMap<I, Vec<RobustShare<F>>>,
    client_input_count: usize,
    client_input_slots: &std::collections::HashMap<I, usize>,
    client_input_types: &std::collections::BTreeMap<usize, Vec<ShareType>>,
) where
    F: ark_ff::FftField,
    I: Eq + std::hash::Hash + std::fmt::Debug,
{
    if client_input_count == 0 {
        eprintln!("--client-input-count must be greater than 0");
        exit(13);
    }

    let mut seen_reserved_indices = std::collections::HashSet::new();
    // Group each client's shares independently — clients may provide DIFFERENT
    // numbers of inputs. Reservation indices are assigned in request-arrival
    // order, so they cannot be used to infer a manifest slot. Bind the
    // coordinator's authenticated client identity directly to its admitted
    // manifest slot instead.
    let mut per_client: Vec<(usize, Vec<RobustShare<F>>)> = Vec::new();

    for (client_id, shares) in client_inputs {
        if shares.is_empty() {
            eprintln!(
                "Coordinator returned zero input shares for client {:?}",
                client_id
            );
            exit(13);
        }
        let reserved_indices = match client_to_indices.get(&client_id) {
            Some(indices) => indices,
            None => {
                eprintln!(
                    "Coordinator returned input for client {:?} without a reserved index",
                    client_id
                );
                exit(13);
            }
        };
        if reserved_indices.len() != shares.len() {
            eprintln!(
                "Coordinator returned {} input shares for client {:?}, but {} reserved indices were recorded",
                shares.len(),
                client_id,
                reserved_indices.len()
            );
            exit(13);
        }

        let mut indexed_shares: Vec<(u64, RobustShare<F>)> =
            reserved_indices.iter().copied().zip(shares).collect();
        indexed_shares.sort_by_key(|(reserved_index, _)| *reserved_index);

        let client_slot = match client_input_slots.get(&client_id) {
            Some(slot) => *slot,
            None => {
                eprintln!(
                    "Coordinator returned input for client {:?} without an admitted manifest slot",
                    client_id
                );
                exit(13);
            }
        };
        let mut ordered_shares = Vec::with_capacity(indexed_shares.len());
        for (reserved_index, share) in indexed_shares {
            if reserved_index > usize::MAX as u64 {
                eprintln!(
                    "Coordinator reserved index {} exceeds local usize range",
                    reserved_index
                );
                exit(13);
            }
            if !seen_reserved_indices.insert(reserved_index as usize) {
                eprintln!(
                    "Coordinator assigned duplicate reserved index {} while collecting inputs",
                    reserved_index
                );
                exit(13);
            }
            ordered_shares.push(share);
        }
        per_client.push((client_slot, ordered_shares));
    }

    per_client.sort_by_key(|(client_slot, _)| *client_slot);

    let inputs = per_client.into_iter().map(|(client_slot, shares)| {
        let share_types = client_input_types.get(&client_slot).cloned();
        (client_slot, shares, share_types)
    });
    if let Err(error) = vm.try_replace_client_inputs_with_types(inputs) {
        eprintln!(
            "Failed to atomically hydrate client input shares: {}",
            error
        );
        exit(13);
    }
}
fn store_reserved_client_inputs_feldman<F, G, I>(
    vm: &mut VirtualMachine,
    client_to_indices: &std::collections::HashMap<I, Vec<u64>>,
    client_inputs: std::collections::HashMap<I, Vec<FeldmanShamirShare<F, G>>>,
    client_input_count: usize,
    client_input_slots: &std::collections::HashMap<I, usize>,
    client_input_types: &std::collections::BTreeMap<usize, Vec<ShareType>>,
) where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F>,
    I: Eq + std::hash::Hash + std::fmt::Debug,
{
    if client_input_count == 0 {
        eprintln!("--client-input-count must be greater than 0");
        exit(13);
    }

    let mut seen_reserved_indices = std::collections::HashSet::new();
    // As in the HoneyBadger path, reservation order is nondeterministic under
    // concurrent clients. Use the authenticated identity-to-slot admission map.
    let mut per_client: Vec<(usize, Vec<FeldmanShamirShare<F, G>>)> = Vec::new();

    for (client_id, shares) in client_inputs {
        if shares.is_empty() {
            eprintln!(
                "Coordinator returned zero AVSS input shares for client {:?}",
                client_id
            );
            exit(13);
        }
        let reserved_indices = match client_to_indices.get(&client_id) {
            Some(indices) => indices,
            None => {
                eprintln!(
                    "Coordinator returned input for client {:?} without a reserved index",
                    client_id
                );
                exit(13);
            }
        };
        if reserved_indices.len() != shares.len() {
            eprintln!(
                "Coordinator returned {} AVSS input shares for client {:?}, but {} reserved indices were recorded",
                shares.len(),
                client_id,
                reserved_indices.len()
            );
            exit(13);
        }

        let mut indexed_shares: Vec<(u64, FeldmanShamirShare<F, G>)> =
            reserved_indices.iter().copied().zip(shares).collect();
        indexed_shares.sort_by_key(|(reserved_index, _)| *reserved_index);

        let client_slot = match client_input_slots.get(&client_id) {
            Some(slot) => *slot,
            None => {
                eprintln!(
                    "Coordinator returned AVSS input for client {:?} without an admitted manifest slot",
                    client_id
                );
                exit(13);
            }
        };
        let mut ordered_shares = Vec::with_capacity(indexed_shares.len());
        for (reserved_index, share) in indexed_shares {
            if reserved_index > usize::MAX as u64 {
                eprintln!(
                    "Coordinator reserved index {} exceeds local usize range",
                    reserved_index
                );
                exit(13);
            }
            if !seen_reserved_indices.insert(reserved_index as usize) {
                eprintln!(
                    "Coordinator assigned duplicate reserved index {} while collecting inputs",
                    reserved_index
                );
                exit(13);
            }
            ordered_shares.push(share);
        }
        per_client.push((client_slot, ordered_shares));
    }

    per_client.sort_by_key(|(client_slot, _)| *client_slot);

    for (client_slot, shares) in per_client {
        let result = if let Some(share_types) = client_input_types.get(&client_slot) {
            vm.try_store_client_input_feldman_with_types(client_slot, shares, share_types)
        } else {
            vm.try_store_client_input_feldman(client_slot, shares)
        };
        if let Err(error) = result {
            eprintln!(
                "Failed to store AVSS input shares for client slot {}: {}",
                client_slot, error
            );
            exit(13);
        }
    }
}
fn configure_preproc_store(
    engine: &dyn MpcEngine,
    program_hash: [u8; 32],
    preproc_store: Option<Arc<dyn PreprocStore>>,
) -> Result<(), String> {
    let Some(store) = preproc_store else {
        return Ok(());
    };
    engine
        .preproc_persistence_ops()?
        .set_preproc_store(store, program_hash)?;
    Ok(())
}
async fn load_reserved_mask_shares<F, G>(
    engine: &Arc<HoneyBadgerMpcEngine<F, G>>,
    capacity: usize,
    reserved_indices: impl IntoIterator<Item = u64>,
) -> Result<Vec<RobustShare<F>>, String>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    if capacity == 0 {
        return Ok(Vec::new());
    }

    let mut slots: Vec<Option<RobustShare<F>>> = vec![None; capacity];
    let mut reserved_indices: Vec<u64> = reserved_indices.into_iter().collect();
    reserved_indices.sort_unstable();
    if reserved_indices.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("duplicate reserved mask share request".to_owned());
    }
    let reservation = engine.reservation_ops()?;
    let share_bytes = reservation.get_mask_shares(&reserved_indices).await?;
    if share_bytes.len() != reserved_indices.len() {
        return Err(format!(
            "mask share batch returned {} shares for {} requested indices",
            share_bytes.len(),
            reserved_indices.len()
        ));
    }
    for (reserved_index, share_bytes) in reserved_indices.into_iter().zip(share_bytes) {
        let slot = usize::try_from(reserved_index)
            .map_err(|_| format!("reserved index {reserved_index} exceeds usize range"))?;
        if slot >= capacity {
            return Err(format!(
                "reserved index {reserved_index} exceeds expected input capacity {capacity}"
            ));
        }
        let share =
            ark_serialize::CanonicalDeserialize::deserialize_compressed(share_bytes.as_slice())
                .map_err(|e| format!("deserialize reserved mask share {reserved_index}: {e:?}"))?;
        slots[slot] = Some(share);
    }

    slots
        .into_iter()
        .enumerate()
        .map(|(slot, share)| {
            share.ok_or_else(|| format!("missing reserved mask share for slot {slot}"))
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
async fn collect_hb_coordinator_inputs<F, G>(
    vm: &mut VirtualMachine,
    engine: &Arc<HoneyBadgerMpcEngine<F, G>>,
    coord: &mut HbOffChainCoordinator<F>,
    node_rpc: &OffChainNodeRPCServer,
    execution_id: CoordinatorExecutionId,
    input_ids: &[Vec<u8>],
    client_input_slots_by_id: &std::collections::HashMap<Vec<u8>, usize>,
    client_input_total: Option<usize>,
    client_input_count: usize,
    client_input_types: &std::collections::BTreeMap<usize, Vec<ShareType>>,
    program_id: [u8; 32],
    run_id: u64,
    my_id: usize,
) -> Result<(), String>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    if input_ids.is_empty() {
        return Ok(());
    }

    let total_input_count =
        client_input_total.unwrap_or_else(|| input_ids.len().saturating_mul(client_input_count));
    if total_input_count == 0 {
        return Ok(());
    }
    let profile_clients = input_ids.len();
    mark_input_path_phase(
        InputPathPhase::ReservationRegistryInit,
        profile_clients,
        total_input_count,
    );

    if engine.is_standing() {
        engine
            .reservation_ops()
            .map_err(|e| e.to_string())?
            .init_reservations_for_run(
                program_id,
                total_input_count as u64,
                run_id,
                PoolAvailability::default(),
            )
            .await
            .map_err(|e| e.to_string())?;
    }
    mark_input_path_phase(
        InputPathPhase::MaskPoolPrepare,
        profile_clients,
        total_input_count,
    );

    let precomputed_mask_shares = if engine.is_standing() {
        None
    } else {
        Some(
            engine
                .node_handle()
                .lock()
                .await
                .preprocessing_material
                .lock()
                .await
                .take_random_shares(total_input_count)
                .map_err(|e| format!("take_random_shares: {e}"))?,
        )
    };
    mark_input_path_phase(
        InputPathPhase::ReservationProposeRpc,
        profile_clients,
        total_input_count,
    );

    eprintln!("[party {my_id}] proposing InputMaskReservation");
    coord
        .reserve_input_masks()
        .await
        .map_err(|e| e.to_string())?;
    mark_input_path_phase(
        InputPathPhase::ReservationRoundWait,
        profile_clients,
        total_input_count,
    );
    coord
        .wait_for_round(Round::InputMaskReservation)
        .await
        .map_err(|e| e.to_string())?;
    mark_input_path_phase(
        InputPathPhase::ReservedIndicesWait,
        profile_clients,
        total_input_count,
    );

    eprintln!("[party {my_id}] waiting for reserved input indices");
    let client_to_indices = normalize_client_to_indices(
        coord
            .wait_for_indices(total_input_count as u64)
            .await
            .map_err(|e| e.to_string())?,
    );
    eprintln!("[party {my_id}] reserved input indices received");
    mark_input_path_phase(
        InputPathPhase::ReservationMirror,
        profile_clients,
        total_input_count,
    );

    // Mirror the coordinator's logical allocation in deterministic index order.
    // Standing engines destructively remove each corresponding mask from LMDB
    // here and retain it only in process memory until input reconstruction has
    // completed. This prevents a later program/execution from reusing it.
    let mut reserved_masks = client_to_indices
        .iter()
        .flat_map(|(client, indices)| {
            let client_id = input_ids.iter().position(|expected| expected == client);
            indices.iter().copied().map(move |index| (index, client_id))
        })
        .collect::<Vec<_>>();
    reserved_masks.sort_unstable_by_key(|(index, _)| *index);
    let reserved_mask_indices = reserved_masks
        .iter()
        .map(|(index, _)| *index)
        .collect::<Vec<_>>();
    if engine.is_standing() {
        let reservations = engine.reservation_ops().map_err(|e| e.to_string())?;
        // Reserve in maximal same-client contiguous runs instead of one index at a time: each
        // `reserve_masks` call round-trips through the reservation registry (and, for standing
        // engines, the mask-share cache lock), so issuing one call per index serializes that
        // cost across every reserved index instead of every client.
        for run in canonical_mask_reservation_runs(&reserved_masks)? {
            let run_end = run
                .start
                .checked_add(run.count)
                .ok_or_else(|| "standing mask reservation run overflows u64".to_owned())?;
            let grant = reservations
                .reserve_masks(run.client_id, run.count)
                .await
                .map_err(|e| e.to_string())?;
            if grant.start != run.start || grant.count != run.count {
                return Err(format!(
                    "node reservation diverged from coordinator run {}..{}: start={}, count={}",
                    run.start, run_end, grant.start, grant.count,
                ));
            }
        }
    }
    mark_input_path_phase(
        InputPathPhase::MaskSharesMaterialize,
        profile_clients,
        total_input_count,
    );

    let mask_shares = if let Some(mask_shares) = precomputed_mask_shares {
        mask_shares
    } else {
        let mask_shares = load_reserved_mask_shares(
            engine,
            total_input_count,
            client_to_indices.values().flatten().copied(),
        )
        .await?;

        mask_shares
    };
    mark_input_path_phase(
        InputPathPhase::ReservedIndicesPublish,
        profile_clients,
        total_input_count,
    );

    let mut assigned_reservations = Vec::with_capacity(reserved_mask_indices.len());
    for (index, client_position) in &reserved_masks {
        let client_position = (*client_position).ok_or_else(|| {
            format!("reserved index {index} belongs to an unexpected client identity")
        })?;
        let client = input_ids.get(client_position).ok_or_else(|| {
            format!("reserved index {index} references missing client slot {client_position}")
        })?;
        assigned_reservations.push(AssignedMaskReservation {
            client: client.clone(),
            reserved_index: *index,
            input_ordinal: *index,
        });
    }
    node_rpc
        .add_assigned_reserved_indices_for_execution(execution_id, assigned_reservations)
        .await
        .or_else(|error| match error {
            NodeRPCError::JSONError => {
                eprintln!(
                    "[party {my_id}] reserved-index batch observed a stale client sink; continuing"
                );
                Ok(())
            }
            other => Err(format!("add reserved-index batch: {other:?}")),
        })?;
    mark_input_path_phase(
        InputPathPhase::MaskShareBatchBuild,
        profile_clients,
        total_input_count,
    );
    let mask_share_pairs = reserved_mask_indices
        .iter()
        .map(|index| {
            let slot = usize::try_from(*index)
                .map_err(|_| format!("reserved index {index} exceeds usize range"))?;
            let share = mask_shares
                .get(slot)
                .ok_or_else(|| format!("reserved index {index} exceeds mask share slots"))?;
            Ok((*index, share))
        })
        .collect::<Result<Vec<_>, String>>()?;
    mark_input_path_phase(
        InputPathPhase::MaskSharesPublish,
        profile_clients,
        total_input_count,
    );
    node_rpc
        .add_mask_shares_for_execution(execution_id, &mask_share_pairs)
        .await
        .map_err(|error| format!("add mask shares: {error:?}"))?;
    mark_input_path_phase(
        InputPathPhase::InputCollectionProposeRpc,
        profile_clients,
        total_input_count,
    );

    eprintln!("[party {my_id}] proposing InputCollection");
    coord.collect_inputs().await.map_err(|e| e.to_string())?;
    mark_input_path_phase(
        InputPathPhase::InputCollectionRoundWait,
        profile_clients,
        total_input_count,
    );
    coord
        .wait_for_round(Round::InputCollection)
        .await
        .map_err(|e| e.to_string())?;
    mark_input_path_phase(
        InputPathPhase::MaskedInputsWaitReconstruct,
        profile_clients,
        total_input_count,
    );

    eprintln!("[party {my_id}] waiting for masked client inputs");
    let client_inputs = coord
        .wait_for_inputs(total_input_count as u64, mask_shares)
        .await
        .map_err(|e| e.to_string())?;
    eprintln!("[party {my_id}] masked client inputs received");
    mark_input_path_phase(
        InputPathPhase::MaskRetire,
        profile_clients,
        total_input_count,
    );
    if engine.is_standing() {
        engine
            .reservation_ops()
            .map_err(|e| e.to_string())?
            .retire_masks(&reserved_mask_indices)
            .await
            .map_err(|e| e.to_string())?;
    }
    mark_input_path_phase(
        InputPathPhase::VmInputHydration,
        profile_clients,
        total_input_count,
    );
    store_reserved_client_inputs(
        vm,
        &client_to_indices,
        client_inputs,
        client_input_count,
        client_input_slots_by_id,
        client_input_types,
    );
    mark_input_path_phase(InputPathPhase::Complete, profile_clients, total_input_count);

    Ok(())
}

fn client_transport_recipient(
    recipient: stoffelnet::network_utils::PartyId,
    local_position: usize,
) -> Option<stoffelnet::network_utils::PartyId> {
    if recipient >= local_position {
        recipient.checked_add(1)
    } else {
        Some(recipient)
    }
}

/// Execution-scoped adapter used by MPC clients. Its sends use
/// the client route, so a persistent party's shared transport mux delivers
/// them only to the matching execution's client inbox.
struct ScopedClientNetworkAdapter {
    inner: ExecutionScopedNetwork,
    local_position: usize,
}

#[async_trait::async_trait]
impl Network for ScopedClientNetworkAdapter {
    type NodeType = <ExecutionScopedNetwork as Network>::NodeType;
    type NetworkConfig = <ExecutionScopedNetwork as Network>::NetworkConfig;

    async fn send(
        &self,
        recipient: stoffelnet::network_utils::PartyId,
        message: &[u8],
    ) -> Result<usize, stoffelnet::network_utils::NetworkError> {
        let mapped = client_transport_recipient(recipient, self.local_position).ok_or(
            stoffelnet::network_utils::NetworkError::PartyNotFound(recipient),
        )?;
        self.inner.send(mapped, message).await
    }

    async fn broadcast(
        &self,
        message: &[u8],
    ) -> Result<usize, stoffelnet::network_utils::NetworkError> {
        let n = self.party_count();
        let mut total = 0usize;
        for party_id in 0..n {
            total = total.saturating_add(self.send(party_id, message).await?);
        }
        Ok(total)
    }

    fn parties(&self) -> Vec<&Self::NodeType> {
        self.inner.parties()
    }

    fn parties_mut(&mut self) -> Vec<&mut Self::NodeType> {
        self.inner.parties_mut()
    }

    fn config(&self) -> &Self::NetworkConfig {
        self.inner.config()
    }

    fn node(&self, id: stoffelnet::network_utils::PartyId) -> Option<&Self::NodeType> {
        self.inner.node(id)
    }

    fn node_mut(&mut self, id: stoffelnet::network_utils::PartyId) -> Option<&mut Self::NodeType> {
        self.inner.node_mut(id)
    }

    async fn send_to_client(
        &self,
        client: ClientId,
        message: &[u8],
    ) -> Result<usize, stoffelnet::network_utils::NetworkError> {
        self.inner.send_to_client(client, message).await
    }

    fn clients(&self) -> Vec<ClientId> {
        self.inner.clients()
    }

    fn is_client_connected(&self, client: ClientId) -> bool {
        self.inner.is_client_connected(client)
    }

    fn local_party_id(&self) -> stoffelnet::network_utils::PartyId {
        self.inner.local_party_id()
    }

    fn party_count(&self) -> usize {
        self.inner.party_count().saturating_sub(1)
    }

    fn verified_ordering(&self) -> Option<stoffelnet::network_utils::VerifiedOrdering> {
        self.inner.verified_ordering()
    }
}

async fn send_execution_client_hellos(
    network: &ScopedClientNetworkAdapter,
    parties: usize,
) -> Result<(), String> {
    for party_id in 0..parties {
        network
            .send(party_id, EXECUTION_CLIENT_HELLO_V1)
            .await
            .map_err(|error| {
                format!("failed to send execution hello to party {party_id}: {error}")
            })?;
    }
    Ok(())
}

/// Network adapter for MPC servers that remaps sequential client indices
/// (0, 1, ...) back to transport client IDs for send_to_client().
/// The MPC protocol uses small indices (because session_id only has 8 bits),
/// and the network layer exposes clients in canonical sorted transport order.
struct ServerClientAdapter {
    inner: ExecutionScopedNetwork,
    /// Maps sequential index to transport client ID.
    client_id_map: Vec<ClientId>,
}
#[async_trait::async_trait]
impl Network for ServerClientAdapter {
    type NodeType = <ExecutionScopedNetwork as Network>::NodeType;
    type NetworkConfig = <ExecutionScopedNetwork as Network>::NetworkConfig;

    async fn send(
        &self,
        recipient: stoffelnet::network_utils::PartyId,
        message: &[u8],
    ) -> Result<usize, stoffelnet::network_utils::NetworkError> {
        self.inner.send(recipient, message).await
    }

    async fn broadcast(
        &self,
        message: &[u8],
    ) -> Result<usize, stoffelnet::network_utils::NetworkError> {
        self.inner.broadcast(message).await
    }

    fn parties(&self) -> Vec<&Self::NodeType> {
        self.inner.parties()
    }

    fn parties_mut(&mut self) -> Vec<&mut Self::NodeType> {
        self.inner.parties_mut()
    }

    fn config(&self) -> &Self::NetworkConfig {
        self.inner.config()
    }

    fn node(&self, id: stoffelnet::network_utils::PartyId) -> Option<&Self::NodeType> {
        self.inner.node(id)
    }

    fn node_mut(&mut self, id: stoffelnet::network_utils::PartyId) -> Option<&mut Self::NodeType> {
        self.inner.node_mut(id)
    }

    async fn send_to_client(
        &self,
        client: ClientId,
        message: &[u8],
    ) -> Result<usize, stoffelnet::network_utils::NetworkError> {
        // Remap sequential index to the canonical transport client ID.
        let transport_id = self.client_id_map.get(client).copied().unwrap_or(client);
        self.inner.send_to_client(transport_id, message).await
    }

    fn clients(&self) -> Vec<ClientId> {
        self.inner.clients()
    }

    fn is_client_connected(&self, client: ClientId) -> bool {
        let transport_id = self.client_id_map.get(client).copied().unwrap_or(client);
        self.inner.is_client_connected(transport_id)
    }

    fn local_party_id(&self) -> stoffelnet::network_utils::PartyId {
        self.inner.local_party_id()
    }

    fn party_count(&self) -> usize {
        self.inner.party_count()
    }

    fn verified_ordering(&self) -> Option<stoffelnet::network_utils::VerifiedOrdering> {
        self.inner.verified_ordering()
    }
}

fn is_flag_present(raw_args: &[String], flag: &str) -> bool {
    raw_args
        .iter()
        .any(|arg| arg == flag || arg.starts_with(&format!("{flag}=")))
}

fn cli_option_takes_value(argument: &str) -> bool {
    matches!(
        argument,
        "--advertise"
            | "--bind"
            | "--bootstrap"
            | "--cert"
            | "--client-index"
            | "--client-input-count"
            | "--client-input-slots"
            | "--client-input-total"
            | "--client-roster"
            | "--client-slot"
            | "--client-transport-servers"
            | "--eth-node"
            | "--execution-id"
            | "--expected-clients"
            | "--inputs"
            | "--key"
            | "--local-store"
            | "--mpc-backend"
            | "--mpc-curve"
            | "--n-parties"
            | "--off-chain-coord"
            | "--on-chain-coord"
            | "--output-fixed-point-fractional-bits"
            | "--outputs"
            | "--party-id"
            | "--preproc-store"
            | "--print-program-id"
            | "--print-program-manifest"
            | "--program"
            | "--rpc-bind"
            | "--servers"
            | "--stun-servers"
            | "--threshold"
            | "--timestamp"
            | "--wait-for-clients"
            | "--wallet-sk"
    )
}

fn validate_cli_option_values(raw_args: &[String]) -> Result<(), String> {
    let mut index = 0;
    while let Some(argument) = raw_args.get(index) {
        if let Some((option, value)) = argument.split_once('=') {
            if cli_option_takes_value(option) && value.is_empty() {
                return Err(format!("{option} requires a value"));
            }
            index += 1;
            continue;
        }

        if cli_option_takes_value(argument) {
            let value = raw_args
                .get(index + 1)
                .filter(|value| !value.starts_with("--"))
                .ok_or_else(|| format!("{argument} requires a value"))?;
            if value.is_empty() {
                return Err(format!("{argument} requires a value"));
            }
            index += 2;
            continue;
        }

        index += 1;
    }
    Ok(())
}

fn normalized_cli_arguments(raw_args: &[String]) -> Vec<String> {
    let mut normalized = Vec::with_capacity(raw_args.len());
    for argument in raw_args {
        if let Some((option, value)) = argument.split_once('=') {
            if cli_option_takes_value(option) {
                normalized.push(option.to_owned());
                normalized.push(value.to_owned());
                continue;
            }
        }
        normalized.push(argument.clone());
    }
    normalized
}

fn cli_positional_arguments(raw_args: &[String]) -> Vec<String> {
    let mut positional = Vec::new();
    let mut index = 0;
    while let Some(argument) = raw_args.get(index) {
        if argument
            .split_once('=')
            .is_some_and(|(option, _)| cli_option_takes_value(option))
        {
            index += 1;
            continue;
        }
        if cli_option_takes_value(argument) {
            index += 2;
            continue;
        }
        if !argument.starts_with('-') {
            positional.push(argument.clone());
        }
        index += 1;
    }
    positional
}

fn validate_required_cli_parameters(
    mode: &str,
    requirements: &[(&str, bool)],
) -> Result<(), String> {
    let missing = requirements
        .iter()
        .filter_map(|(parameter, present)| (!present).then_some(*parameter))
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("{mode} requires {}", missing.join(", ")))
    }
}

fn validate_forbidden_cli_parameters(
    mode: &str,
    parameters: &[(&str, bool)],
) -> Result<(), String> {
    let present = parameters
        .iter()
        .filter_map(|(parameter, present)| (*present).then_some(*parameter))
        .collect::<Vec<_>>();
    if present.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{mode} does not accept mode-specific parameter(s): {}",
            present.join(", ")
        ))
    }
}

fn validate_cli_mode_flags(
    as_client: bool,
    as_bootnode: bool,
    as_leader: bool,
    has_party_id: bool,
    has_bootstrap: bool,
) -> Result<(), String> {
    let has_party_marker = has_party_id || has_bootstrap;
    if as_client && (as_bootnode || as_leader || has_party_marker) {
        return Err(
            "--client cannot be combined with --bootnode, --leader, --party-id, or --bootstrap"
                .to_owned(),
        );
    }
    if as_bootnode && (as_leader || has_party_marker) {
        return Err(
            "--bootnode cannot be combined with --leader, --party-id, or --bootstrap".to_owned(),
        );
    }
    if as_leader && has_party_marker {
        return Err("--leader cannot be combined with --party-id or --bootstrap".to_owned());
    }
    if has_party_id != has_bootstrap {
        return Err("party mode requires both --party-id and --bootstrap".to_owned());
    }
    Ok(())
}

fn validate_client_server_count(n_parties: usize, server_count: usize) -> Result<(), String> {
    if server_count == n_parties {
        Ok(())
    } else {
        Err(format!(
            "client mode requires exactly one --servers address per party (got {server_count}, expected {n_parties})"
        ))
    }
}

fn exit_on_cli_configuration_error(result: Result<(), String>) {
    if let Err(error) = result {
        eprintln!("Error: {error}");
        exit(2);
    }
}

/// Resolve the compiled artifact used for semantic client I/O.
///
/// Client mode historically accepted options before the positional program
/// path (`stoffel-run --client program.stflb ...`), but semantic I/O only
/// inspected argv[1]. Walk the arguments with their arity so option values are
/// not mistaken for the program. An explicit `--program` remains authoritative.
fn client_program_from_arguments(raw_args: &[String]) -> Option<PathBuf> {
    let positional_program = cli_positional_arguments(raw_args)
        .into_iter()
        .next()
        .map(PathBuf::from);
    let mut explicit_program = None;
    let mut index = 0;

    while let Some(argument) = raw_args.get(index) {
        if argument == "--program" {
            explicit_program = raw_args.get(index + 1).map(PathBuf::from);
            index += 2;
            continue;
        }
        if let Some(program) = argument.strip_prefix("--program=") {
            if !program.is_empty() {
                explicit_program = Some(PathBuf::from(program));
            }
            index += 1;
            continue;
        }
        if cli_option_takes_value(argument) {
            index += 2;
            continue;
        }
        index += 1;
    }

    explicit_program.or(positional_program)
}

fn print_vm_result(vm: &mut VirtualMachine, result: Value) {
    println!("Program returned: {}", format_vm_result(vm, &result));
}

fn format_vm_result(vm: &mut VirtualMachine, result: &Value) -> String {
    let returned_share = ReturnedShare::from_vm_value(result).or_else(|| {
        matches!(result, Value::Object(_))
            .then(|| vm.read_share_object(result).ok())
            .flatten()
            .map(|(share_type, share_data)| ReturnedShare::from_share_data(share_type, &share_data))
    });
    if let Some(share) = returned_share {
        return share.to_string();
    }

    match result {
        Value::Array(arr_ref) => {
            if let Some(bytes) = vm
                .read_byte_array(&Value::from(*arr_ref))
                .ok()
                .filter(|bytes| !bytes.is_empty())
            {
                let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                format!("byte[{}] 0x{}", bytes.len(), hex)
            } else {
                format_vm_value(vm, result, 4)
            }
        }
        _ => format_vm_value(vm, result, 4),
    }
}

fn format_vm_value(vm: &mut VirtualMachine, value: &Value, max_depth: usize) -> String {
    let mut active_tables = HashSet::new();
    format_vm_value_inner(vm, value, max_depth, &mut active_tables)
}

fn format_vm_value_inner(
    vm: &mut VirtualMachine,
    value: &Value,
    max_depth: usize,
    active_tables: &mut HashSet<TableRef>,
) -> String {
    match value {
        Value::I64(i) => i.to_string(),
        Value::I32(i) => i.to_string(),
        Value::I16(i) => i.to_string(),
        Value::I8(i) => i.to_string(),
        Value::U64(i) => i.to_string(),
        Value::U32(i) => i.to_string(),
        Value::U16(i) => i.to_string(),
        Value::U8(i) => i.to_string(),
        Value::Float(fp) => fp.0.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::String(s) => format!("\"{}\"", s),
        Value::Unit => "()".to_string(),
        Value::Closure(c) => format!("Function({})", c.function_id()),
        Value::Foreign(foreign_ref) => format!("Foreign({})", foreign_ref.id()),
        Value::Share(share_type, _) => format!("Share({:?})", share_type),
        Value::Array(array_ref) => {
            let table_ref = TableRef::from(*array_ref);
            if !active_tables.insert(table_ref) {
                return format!("Array({}) <cycle>", array_ref.id());
            }
            let formatted = format_vm_array(vm, *array_ref, max_depth, active_tables);
            active_tables.remove(&table_ref);
            formatted
        }
        Value::Object(object_ref) => {
            let table_ref = TableRef::from(*object_ref);
            if !active_tables.insert(table_ref) {
                return format!("Object({}) <cycle>", object_ref.id());
            }
            let formatted = format_vm_object(vm, *object_ref, max_depth, active_tables);
            active_tables.remove(&table_ref);
            formatted
        }
    }
}

fn format_vm_array(
    vm: &mut VirtualMachine,
    array_ref: stoffel_vm_types::core_types::ArrayRef,
    max_depth: usize,
    active_tables: &mut HashSet<TableRef>,
) -> String {
    let len = match vm.read_array_len(array_ref) {
        Ok(len) => len,
        Err(error) => return format!("Array({}) <error: {}>", array_ref.id(), error),
    };
    if max_depth == 0 {
        return format!("[...{} elements]", len);
    }

    let display_count = len.min(64);
    let mut parts = Vec::with_capacity(display_count);
    for index in 0..display_count {
        let key = Value::I64(index as i64);
        let value = match vm.read_table_field(TableRef::from(array_ref), &key) {
            Ok(Some(value)) => value,
            Ok(None) => Value::Unit,
            Err(error) => {
                parts.push(format!("<error: {}>", error));
                continue;
            }
        };
        parts.push(format_vm_value_inner(
            vm,
            &value,
            max_depth - 1,
            active_tables,
        ));
    }

    if len > display_count {
        format!("[{}, ...({} more)]", parts.join(", "), len - display_count)
    } else {
        format!("[{}]", parts.join(", "))
    }
}

fn format_vm_object(
    vm: &mut VirtualMachine,
    object_ref: stoffel_vm_types::core_types::ObjectRef,
    max_depth: usize,
    active_tables: &mut HashSet<TableRef>,
) -> String {
    let entries = match vm.read_object_entries(object_ref, 64) {
        Ok(entries) => entries,
        Err(error) => return format!("Object({}) <error: {}>", object_ref.id(), error),
    };
    if max_depth == 0 {
        return format!("{{...{} fields}}", entries.len());
    }

    let mut parts = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        let key = format_vm_value_inner(vm, &key, max_depth - 1, active_tables);
        let value = format_vm_value_inner(vm, &value, max_depth - 1, active_tables);
        parts.push(format!("{}: {}", key, value));
    }
    format!("{{{}}}", parts.join(", "))
}
fn coordinator_output_share_bytes(vm: &mut VirtualMachine, result: &Value) -> Option<Vec<u8>> {
    vm.read_share_object(result)
        .ok()
        .map(|(_ty, share_data)| share_data.as_bytes().to_vec())
}
fn parse_inputs_as_field<F: PrimeField>(inputs_str: &str) -> Vec<F> {
    // An output-only client has no inputs.
    if inputs_str.trim().is_empty() {
        return Vec::new();
    }
    inputs_str
        .split(',')
        .map(|s| {
            let s = s.trim();
            if let Some(hex_value) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                let mut hex_value = hex_value.to_owned();
                if hex_value.len() % 2 == 1 {
                    hex_value.insert(0, '0');
                }
                let bytes = hex::decode(&hex_value).unwrap_or_else(|error| {
                    eprintln!("Invalid hex input value '{}': {}", s, error);
                    exit(2);
                });
                return F::from_be_bytes_mod_order(&bytes);
            }

            let val: i64 = s.parse().unwrap_or_else(|_| {
                eprintln!("Invalid input value: {}", s);
                exit(2);
            });
            stoffel_vm::net::field_from_i64::<F>(val)
        })
        .collect()
}
fn field_outputs_to_hex<F: PrimeField>(outputs: &[F], curve_config: MpcCurveConfig) -> String {
    let mut bytes = Vec::new();
    for output in outputs {
        if matches!(
            curve_config,
            MpcCurveConfig::Secp256k1 | MpcCurveConfig::Secp256r1
        ) {
            bytes.extend_from_slice(&fixed_width_be_bytes(
                &output.into_bigint().to_bytes_be(),
                32,
            ));
        } else {
            ark_serialize::CanonicalSerialize::serialize_compressed(output, &mut bytes)
                .expect("field serialization to Vec cannot fail");
        }
    }
    hex::encode(bytes)
}
fn fixed_width_be_bytes(bytes: &[u8], width: usize) -> Vec<u8> {
    let significant = bytes
        .iter()
        .position(|byte| *byte != 0)
        .map(|idx| &bytes[idx..])
        .unwrap_or(&[]);
    if significant.len() >= width {
        significant[significant.len() - width..].to_vec()
    } else {
        let mut out = vec![0u8; width - significant.len()];
        out.extend_from_slice(significant);
        out
    }
}

/// Connect to all MPC servers with retry logic. Inbound ownership is handed
/// exclusively to the execution connection scanner after this returns.
async fn connect_to_all_servers(
    network: &Arc<tokio::sync::Mutex<QuicNetworkManager>>,
    server_addrs: &[SocketAddr],
) -> Vec<Arc<dyn PeerConnection>> {
    let max_retries = 10;
    let retry_delay = Duration::from_millis(500);
    let mut connected_servers = Vec::with_capacity(server_addrs.len());

    for (server_idx, &addr) in server_addrs.iter().enumerate() {
        let mut retry_count = 0;

        loop {
            eprintln!(
                "[client] Connecting to server {} at {} (attempt {}/{})",
                server_idx,
                addr,
                retry_count + 1,
                max_retries
            );

            let connection_result = {
                let mut net = network.lock().await;
                net.connect_as_client(addr).await
            };

            match connection_result {
                Ok(connection) => {
                    eprintln!("[client] Connected to server {} at {}", server_idx, addr);
                    connected_servers.push((addr, connection));
                    break;
                }
                Err(e) => {
                    retry_count += 1;
                    if retry_count >= max_retries {
                        eprintln!(
                            "[client] Failed to connect to server {} at {} after {} attempts: {}",
                            server_idx, addr, retry_count, e
                        );
                        exit(21);
                    }
                    eprintln!(
                        "[client] Connection attempt {} failed: {}, retrying...",
                        retry_count, e
                    );
                    tokio::time::sleep(retry_delay).await;
                }
            }
        }
    }

    let (assigned_party_ids, local_party_id) = {
        let net = network.lock().await;
        let assigned = net.assign_party_ids();
        let local = net.compute_local_party_id();
        (assigned, local)
    };
    eprintln!(
        "[client] Assigned authenticated party IDs for {} connections",
        assigned_party_ids
    );

    let mut seen_peers = HashSet::new();
    for (addr, connection) in &connected_servers {
        let authenticated_peer = connection.remote_party_id().unwrap_or_else(|| {
            eprintln!(
                "[client] Connected server {} has no authenticated party identity",
                addr
            );
            exit(24);
        });
        let peer = local_party_id.map_or(authenticated_peer, |local_id| {
            if authenticated_peer == local_id {
                eprintln!(
                    "[client] Connected server {} resolved to local authenticated identity {}",
                    addr, authenticated_peer
                );
                exit(24);
            }
            if authenticated_peer > local_id {
                authenticated_peer - 1
            } else {
                authenticated_peer
            }
        });

        if !seen_peers.insert(peer) {
            eprintln!(
                "[client] Duplicate authenticated party identity {} detected for server {}",
                peer, addr
            );
            exit(24);
        }

        let _ = connection;
    }
    connected_servers
        .into_iter()
        .map(|(_, connection)| connection)
        .collect()
}

async fn establish_coordinator_output_client_routes(
    execution_id: ExecutionId,
    server_addrs: &[SocketAddr],
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> Arc<tokio::sync::Mutex<QuicNetworkManager>> {
    let mut client_network = QuicNetworkManager::new();
    client_network
        .set_local_certificate_der(cert_der, key_der)
        .unwrap_or_else(|error| {
            eprintln!("Error: failed to configure coordinator-client certificate: {error}");
            exit(2);
        });
    let network = Arc::new(tokio::sync::Mutex::new(client_network));
    for (party_id, &address) in server_addrs.iter().enumerate() {
        network
            .lock()
            .await
            .add_node_with_party_id(party_id, address);
    }
    let hello_frame = stoffel_vm::net::encode_execution_frame(
        execution_id,
        ExecutionMessageKind::Control,
        EXECUTION_CLIENT_HELLO_V1,
    )
    .unwrap_or_else(|error| {
        eprintln!("[client] Failed to encode coordinator execution route: {error}");
        exit(24);
    });
    let mut last_error = None;
    for attempt in 1..=10 {
        let connections = connect_to_all_servers(&network, server_addrs).await;
        let mut send_result = Ok(());
        for (party_id, connection) in connections.iter().enumerate() {
            if let Err(error) = connection.send(&hello_frame).await {
                send_result = Err(format!(
                    "failed to send execution hello to party {party_id}: {error}"
                ));
                break;
            }
        }
        match send_result {
            Ok(()) => {
                for _ in 0..2 {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    for connection in &connections {
                        let _ = connection.send(&hello_frame).await;
                    }
                }
                return network;
            }
            Err(error) => {
                eprintln!(
                    "[client] Coordinator execution route attempt {attempt}/10 failed: {error}"
                );
                last_error = Some(error);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
    eprintln!(
        "[client] Failed to establish coordinator execution route: {}",
        last_error.as_deref().unwrap_or("unknown transport failure")
    );
    exit(24)
}
fn normalize_client_ids(mut ids: Vec<ClientId>) -> Vec<ClientId> {
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// Binds one authenticated client connection to both its compact protocol
/// index and the VM-visible slot compiled into the program manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClientProtocolBinding {
    protocol_index: usize,
    route_id: ClientId,
    manifest_slot: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClientInputSetup {
    protocol_index: usize,
    input_count: usize,
}

struct PartyClients {
    bindings: Vec<ClientProtocolBinding>,
    input_setup: Vec<ClientInputSetup>,
    route_ids: Vec<ClientId>,
    manifest_driven: bool,
}

#[cfg(test)]
fn bind_admitted_client_slots(
    route_ids: &[ClientId],
    manifest_slots: &[usize],
) -> Vec<ClientProtocolBinding> {
    debug_assert_eq!(route_ids.len(), manifest_slots.len());
    route_ids
        .iter()
        .copied()
        .zip(manifest_slots.iter().copied())
        .enumerate()
        .map(
            |(protocol_index, (route_id, manifest_slot))| ClientProtocolBinding {
                protocol_index,
                route_id,
                manifest_slot,
            },
        )
        .collect()
}

fn client_binding_route_ids(bindings: &[ClientProtocolBinding]) -> HashSet<ClientId> {
    let ids = bindings
        .iter()
        .map(|binding| binding.route_id)
        .collect::<HashSet<_>>();
    debug_assert_eq!(ids.len(), bindings.len());
    ids
}

fn resolve_client_protocol_bindings(
    expected: Option<&[ClientProtocolBinding]>,
    observed: HashSet<ClientId>,
) -> Result<Vec<ClientProtocolBinding>, String> {
    if let Some(expected) = expected {
        let expected_ids = client_binding_route_ids(expected);
        if observed != expected_ids {
            let mut missing = expected_ids
                .difference(&observed)
                .copied()
                .collect::<Vec<_>>();
            let mut unexpected = observed
                .difference(&expected_ids)
                .copied()
                .collect::<Vec<_>>();
            missing.sort_unstable();
            unexpected.sort_unstable();
            return Err(format!(
                "execution client set does not match admission: missing={missing:?}, unexpected={unexpected:?}"
            ));
        }
        return Ok(expected.to_vec());
    }

    let client_ids = normalize_client_ids(observed.into_iter().collect());
    if client_ids.len() > usize::from(u8::MAX) + 1 {
        return Err(format!(
            "{} clients exceed the one-byte MPC client index domain",
            client_ids.len()
        ));
    }
    Ok(client_ids
        .into_iter()
        .enumerate()
        .map(|(protocol_index, route_id)| ClientProtocolBinding {
            protocol_index,
            route_id,
            manifest_slot: protocol_index,
        })
        .collect())
}

fn client_input_setup_plan(
    bindings: &[ClientProtocolBinding],
    client_input_types: &BTreeMap<usize, Vec<ShareType>>,
    one_shot_input_count: usize,
    use_manifest_input_counts: bool,
) -> Vec<ClientInputSetup> {
    bindings
        .iter()
        .filter_map(|binding| {
            let input_count = if use_manifest_input_counts {
                client_input_types
                    .get(&binding.manifest_slot)
                    .map(Vec::len)
                    .unwrap_or(0)
            } else {
                one_shot_input_count
            };
            (input_count > 0).then_some(ClientInputSetup {
                protocol_index: binding.protocol_index,
                input_count,
            })
        })
        .collect()
}

async fn prepare_party_clients(
    client_inbox: &mut mpsc::Receiver<ExecutionInboundMessage>,
    expected_count: Option<usize>,
    expected_bindings: Option<&[ClientProtocolBinding]>,
    input_types: &BTreeMap<usize, Vec<ShareType>>,
    fallback_input_count: usize,
) -> Result<PartyClients, String> {
    let bindings = admit_execution_clients(client_inbox, expected_count, expected_bindings).await?;
    let manifest_driven = expected_bindings.is_some();
    Ok(PartyClients {
        input_setup: client_input_setup_plan(
            &bindings,
            input_types,
            fallback_input_count,
            manifest_driven,
        ),
        route_ids: bindings.iter().map(|binding| binding.route_id).collect(),
        bindings,
        manifest_driven,
    })
}

fn client_preprocessing_count(
    clients: &PartyClients,
    deployment_mode: DeploymentMode,
    input_types: &BTreeMap<usize, Vec<ShareType>>,
    client_count_hint: usize,
    fallback_input_count: usize,
) -> Result<usize, String> {
    if deployment_mode == DeploymentMode::Standing {
        checked_client_input_total(input_types.values().map(Vec::len))
    } else if clients.manifest_driven {
        checked_client_input_total(clients.input_setup.iter().map(|setup| setup.input_count))
    } else {
        clients
            .route_ids
            .len()
            .max(client_count_hint)
            .checked_mul(fallback_input_count)
            .ok_or_else(|| "client input preprocessing demand exceeds usize".to_owned())
    }
}

async fn send_client_instances(
    network: &ExecutionScopedNetwork,
    party_id: usize,
    instance_id: u64,
    clients: &[ClientProtocolBinding],
) -> Result<(), String> {
    for client in clients {
        let protocol_index = u8::try_from(client.protocol_index).map_err(|_| {
            format!(
                "client protocol index {} exceeds INST domain",
                client.protocol_index
            )
        })?;
        let mut message = Vec::with_capacity(13);
        message.extend_from_slice(b"INST");
        message.extend_from_slice(&instance_id.to_le_bytes());
        message.push(protocol_index);
        if let Err(error) = network.send_to_client(client.route_id, &message).await {
            eprintln!(
                "[party {party_id}] Failed to send INST to client {}: {error:?}",
                client.route_id
            );
        }
    }
    Ok(())
}

/// Protocol identities installed in the backend `InputServer`.
///
/// Admission and output routing intentionally retain every client binding, but
/// the input barrier must contain only clients that declared at least one
/// input. An output-only client has no masked-input transcript to complete and
/// therefore must never be represented by an `Empty` InputServer entry.
fn mpc_input_protocol_ids(input_setup_plan: &[ClientInputSetup]) -> Vec<ClientId> {
    input_setup_plan
        .iter()
        .map(|setup| setup.protocol_index)
        .collect()
}

fn client_output_slot_map(bindings: &[ClientProtocolBinding]) -> BTreeMap<ClientId, ClientId> {
    bindings
        .iter()
        .map(|binding| (binding.manifest_slot, binding.route_id))
        .collect()
}

fn standing_client_key(
    admission: &ResolvedStandingExecutionAdmissionV1,
    manifest_slot: ClientId,
) -> Option<&Vec<u8>> {
    admission
        .clients
        .iter()
        .zip(&admission.expected_client_public_keys)
        .find_map(|(client, key)| (client.manifest_slot == manifest_slot).then_some(key))
}

fn input_client_bindings_from_output_ids(
    output_ids: &[Vec<u8>],
    client_roster: &[usize],
    client_input_slots: &[usize],
    client_input_count: usize,
) -> Vec<(Vec<u8>, usize)> {
    if client_input_count == 0 {
        return Vec::new();
    }
    if client_input_slots.is_empty() {
        return output_ids
            .iter()
            .enumerate()
            .map(|(ordinal, client_id)| {
                (
                    client_id.clone(),
                    client_roster.get(ordinal).copied().unwrap_or(ordinal),
                )
            })
            .collect();
    }

    let input_slots = client_input_slots.iter().copied().collect::<HashSet<_>>();
    output_ids
        .iter()
        .enumerate()
        .filter_map(|(ordinal, client_id)| {
            let slot = client_roster.get(ordinal).copied().unwrap_or(ordinal);
            input_slots
                .contains(&slot)
                .then(|| (client_id.clone(), slot))
        })
        .collect()
}

fn input_client_ids_from_output_ids(
    output_ids: &[Vec<u8>],
    client_roster: &[usize],
    client_input_slots: &[usize],
    client_input_count: usize,
) -> Vec<Vec<u8>> {
    input_client_bindings_from_output_ids(
        output_ids,
        client_roster,
        client_input_slots,
        client_input_count,
    )
    .into_iter()
    .map(|(client_id, _)| client_id)
    .collect()
}

fn input_client_slot_map_from_output_ids(
    output_ids: &[Vec<u8>],
    client_roster: &[usize],
    client_input_slots: &[usize],
    client_input_count: usize,
) -> Result<std::collections::HashMap<Vec<u8>, usize>, String> {
    let bindings = input_client_bindings_from_output_ids(
        output_ids,
        client_roster,
        client_input_slots,
        client_input_count,
    );
    let mut slots = std::collections::HashMap::with_capacity(bindings.len());
    let mut seen_slots = HashSet::with_capacity(bindings.len());
    for (client_id, slot) in bindings {
        if slots.insert(client_id, slot).is_some() {
            return Err("duplicate authenticated client identity in input admission".to_owned());
        }
        if !seen_slots.insert(slot) {
            return Err(format!(
                "multiple authenticated input clients were assigned manifest slot {slot}"
            ));
        }
    }
    Ok(slots)
}

struct ClientProtocolConfig {
    execution_id: ExecutionId,
    n: usize,
    t: usize,
    /// Number of input values this client contributes (0 for an output-only client).
    input_len: usize,
    /// Number of output values this client receives via `send_to_client` (0 for
    /// an input-only client).
    output_len: usize,
    instance_id: u64,
    client_index: u8,
    local_position: usize,
    curve_config: MpcCurveConfig,
    output_format: CoordinatorOutputFormat,
}
/// Number of distinct, successfully processed mask-share senders that proves
/// an input client has initiated its masked-input broadcast.
///
/// HoneyBadger reconstructs its robust mask after `2t + 1` shares. AVSS can
/// reconstruct after `t + 1` consistent shares; among `2t + 1` authenticated
/// senders at most `t` can be Byzantine, so the same quorum guarantees at
/// least `t + 1` honest shares with the common commitment. Waiting for all
/// `n` servers is incorrect: a server that receives the masked-input RBC
/// before it initializes its local input state consumes that input directly
/// and intentionally never sends its now-unnecessary mask share to the client.
fn client_input_completion_quorum(n: usize, t: usize) -> Result<usize, String> {
    let minimum_parties = t
        .checked_mul(3)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| format!("client input topology overflow for threshold {t}"))?;
    if n < minimum_parties {
        return Err(format!(
            "invalid client input topology: n={n}, t={t}; requires n >= 3t + 1"
        ));
    }

    t.checked_mul(2)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| format!("client input quorum overflow for threshold {t}"))
}

fn hb_input_only_completion_proven(
    input_broadcast_started: bool,
    distinct_successful_senders: usize,
    quorum: usize,
) -> bool {
    // HoneyBadgerMPCClient::process intentionally ignores authenticated
    // messages for unrelated subprotocols and returns Ok. Therefore sender
    // count alone is only diagnostic; rbc_done is the exact public protocol
    // state proving that 2t+1 actual mask shares were reconstructed and the
    // masked-input AVID broadcast was initiated.
    input_broadcast_started && distinct_successful_senders >= quorum
}

/// A direct-client message retains the mux's ingress lease until protocol
/// processing finishes with it, including while it waits in a downstream
/// channel or the pre-INST replay buffer.
struct DirectClientInboundMessage {
    sender_id: usize,
    message: ExecutionInboundMessage,
}

fn direct_client_inbound_message(
    local_position: usize,
    message: ExecutionInboundMessage,
) -> DirectClientInboundMessage {
    let sender_id = match message.source {
        ExecutionTransportSource::Party(authenticated_id) => {
            if authenticated_id > local_position {
                authenticated_id - 1
            } else {
                authenticated_id
            }
        }
        ExecutionTransportSource::Client(client_id) => client_id,
    };
    DirectClientInboundMessage { sender_id, message }
}

async fn run_hb_client_protocol_for_curve<F: PrimeField>(
    config: ClientProtocolConfig,
    inputs_str: &str,
    network_for_process: Arc<tokio::sync::Mutex<QuicNetworkManager>>,
    mut msg_rx: mpsc::Receiver<DirectClientInboundMessage>,
) -> Result<(), String> {
    let instance_id = honeybadger_protocol_instance_id(config.instance_id);
    // Use the sequential client_index (0, 1, ...) as the MPC identity,
    // not the transport-derived cid, because the session_id only has
    // 8 bits for the client_id field.
    let mpc_cid = config.client_index as usize;
    // Input and output cardinalities are independent. In particular, a client
    // may submit one value and remain connected for several output values.
    let expects_output = config.output_len > 0;
    let input_only_quorum = (!expects_output && config.input_len > 0)
        .then(|| client_input_completion_quorum(config.n, config.t))
        .transpose()?;
    let mut mpc_client = HoneyBadgerMPCClient::<F, Avid<HbSessionId>>::new(
        mpc_cid,
        config.n,
        config.t,
        instance_id,
        parse_inputs_as_field::<F>(inputs_str),
        config.output_len,
    )
    .map_err(|e| format!("Failed to create MPC client: {:?}", e))?;

    let scoped_network = {
        let guard = network_for_process.lock().await;
        ExecutionScopedNetwork::for_client((*guard).clone(), config.execution_id)
            .map_err(|error| format!("invalid HoneyBadger client execution transport: {error}"))?
    };

    let mut messages_processed = 0usize;
    let mut successful_input_senders = HashSet::new();
    while let Some(mut inbound) = msg_rx.recv().await {
        let sender_id = inbound.sender_id;
        let data = std::mem::take(&mut inbound.message.payload);
        // Skip INST messages from other servers (already consumed the first one)
        if data.len() == 13 && data.starts_with(b"INST") {
            eprintln!(
                "[client {}] Skipping extra INST from sender {}",
                mpc_cid, sender_id
            );
            continue;
        }
        eprintln!(
            "[client {}] Received {} bytes from sender {} (raw)",
            mpc_cid,
            data.len(),
            sender_id
        );

        let adapter = ScopedClientNetworkAdapter {
            inner: scoped_network.clone(),
            local_position: config.local_position,
        };

        match mpc_client.process(sender_id, data, Arc::new(adapter)).await {
            Ok(()) => {
                messages_processed += 1;
                if input_only_quorum.is_some() {
                    if sender_id >= config.n {
                        return Err(format!(
                            "HB input response has out-of-range authenticated sender {sender_id} for n={}",
                            config.n
                        ));
                    }
                    successful_input_senders.insert(sender_id);
                }
                eprintln!(
                    "[client {}] Successfully processed message #{} from server {}",
                    mpc_cid, messages_processed, sender_id
                );
                if expects_output {
                    if let Some(outputs) = mpc_client.output.get_output() {
                        let output_hex = field_outputs_to_hex(&outputs, config.curve_config);
                        if matches!(&config.output_format, CoordinatorOutputFormat::Manifest(_)) {
                            eprintln!(
                                "[client {mpc_cid}] raw output: field[{}] 0x{}",
                                outputs.len(),
                                output_hex
                            );
                        } else {
                            println!("Client output: field[{}] 0x{}", outputs.len(), output_hex);
                        }
                        println!(
                            "outputs: {}",
                            format_coordinator_outputs(&outputs, &config.output_format,)
                        );
                        eprintln!(
                            "[client {}] Reconstructed {} output value(s)",
                            mpc_cid,
                            outputs.len()
                        );
                        return Ok(());
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "[client {}] Failed to process message from {}: {:?}",
                    mpc_cid, sender_id, e
                );
            }
        }

        let hb_input_broadcast_started = if input_only_quorum.is_some() {
            mpc_client.input.client_data.lock().await.rbc_done
        } else {
            false
        };
        if input_only_quorum.is_some_and(|quorum| {
            hb_input_only_completion_proven(
                hb_input_broadcast_started,
                successful_input_senders.len(),
                quorum,
            )
        }) {
            eprintln!(
                "[client {mpc_cid}] Input-only protocol complete after {} distinct mask-share senders",
                successful_input_senders.len()
            );
            return Ok(());
        }
    }

    if expects_output {
        return Err(format!(
            "HB client receiver closed before {} output value(s) reconstructed (processed {messages_processed} messages)",
            config.output_len,
        ));
    }

    if let Some(quorum) = input_only_quorum {
        let input_broadcast_started = mpc_client.input.client_data.lock().await.rbc_done;
        return Err(format!(
            "HB client receiver closed before input broadcast completion: broadcast_started={input_broadcast_started}, received {}/{} distinct successful protocol senders (processed {messages_processed} messages)",
            successful_input_senders.len(),
            quorum
        ));
    }

    eprintln!("[client {mpc_cid}] Message processing done ({messages_processed} messages)");
    Ok(())
}
async fn run_avss_client_protocol_for_curve<F, G>(
    config: ClientProtocolConfig,
    inputs_str: &str,
    network_for_process: Arc<tokio::sync::Mutex<QuicNetworkManager>>,
    mut msg_rx: mpsc::Receiver<DirectClientInboundMessage>,
) -> Result<(), String>
where
    F: PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    let mpc_cid = config.client_index as usize;
    let instance_id = avss_protocol_instance_id(config.instance_id);
    let mut mpc_client = AvssMPCClient::<F, Avid<AvssSessionId>, G>::new(
        mpc_cid,
        config.n,
        config.t,
        instance_id,
        parse_inputs_as_field::<F>(inputs_str),
        config.output_len,
    )
    .map_err(|e| format!("Failed to create AVSS MPC client: {:?}", e))?;

    let scoped_network = {
        let guard = network_for_process.lock().await;
        ExecutionScopedNetwork::for_client((*guard).clone(), config.execution_id)
            .map_err(|error| format!("invalid AVSS client execution transport: {error}"))?
    };

    let expects_output = config.output_len > 0;
    let input_only_quorum = (!expects_output && config.input_len > 0)
        .then(|| client_input_completion_quorum(config.n, config.t))
        .transpose()?;
    let mut messages_processed = 0usize;
    let mut successful_input_senders = HashSet::new();
    while let Some(mut inbound) = msg_rx.recv().await {
        let sender_id = inbound.sender_id;
        let data = std::mem::take(&mut inbound.message.payload);
        eprintln!(
            "[client {}] Received {} AVSS bytes from sender {}",
            mpc_cid,
            data.len(),
            sender_id
        );
        if data.len() == 13 && data.starts_with(b"INST") {
            eprintln!(
                "[client {}] Skipping extra INST from sender {}",
                mpc_cid, sender_id
            );
            continue;
        }

        let adapter = ScopedClientNetworkAdapter {
            inner: scoped_network.clone(),
            local_position: config.local_position,
        };

        match mpc_client.process(sender_id, data, Arc::new(adapter)).await {
            Ok(()) => {
                messages_processed += 1;
                if input_only_quorum.is_some() {
                    if sender_id >= config.n {
                        return Err(format!(
                            "AVSS input response has out-of-range authenticated sender {sender_id} for n={}",
                            config.n
                        ));
                    }
                    successful_input_senders.insert(sender_id);
                }
                if expects_output {
                    if let Some(outputs) = mpc_client.output.get_output() {
                        let output_hex = field_outputs_to_hex(&outputs, config.curve_config);
                        if matches!(&config.output_format, CoordinatorOutputFormat::Manifest(_)) {
                            eprintln!(
                                "[client {mpc_cid}] raw output: field[{}] 0x{}",
                                outputs.len(),
                                output_hex
                            );
                        } else {
                            println!("Client output: field[{}] 0x{}", outputs.len(), output_hex);
                        }
                        println!(
                            "outputs: {}",
                            format_coordinator_outputs(&outputs, &config.output_format,)
                        );
                        return Ok(());
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "[client {}] Failed to process AVSS message from {}: {:?}",
                    mpc_cid, sender_id, e
                );
            }
        }
        if input_only_quorum.is_some_and(|quorum| successful_input_senders.len() >= quorum) {
            eprintln!(
                "[client {mpc_cid}] AVSS input-only protocol complete after {} distinct mask-share senders",
                successful_input_senders.len()
            );
            return Ok(());
        }
    }

    if expects_output {
        Err(format!(
            "AVSS client receiver closed before {} output value(s) reconstructed (processed {} messages)",
            config.output_len, messages_processed
        ))
    } else if let Some(quorum) = input_only_quorum {
        Err(format!(
            "AVSS client receiver closed before input broadcast quorum: received {}/{} distinct successful mask-share senders (processed {messages_processed} messages)",
            successful_input_senders.len(),
            quorum
        ))
    } else {
        Ok(())
    }
}
async fn run_avss_client_for_curve(
    curve_config: MpcCurveConfig,
    config: ClientProtocolConfig,
    inputs_str: &str,
    network_for_process: Arc<tokio::sync::Mutex<QuicNetworkManager>>,
    msg_rx: mpsc::Receiver<DirectClientInboundMessage>,
) -> Result<(), String> {
    macro_rules! run {
        ($F:ty, $G:ty) => {
            run_avss_client_protocol_for_curve::<$F, $G>(
                config,
                inputs_str,
                network_for_process,
                msg_rx,
            )
            .await
        };
    }
    dispatch_avss_curve!(curve_config, run)
}
async fn run_hb_client_for_curve(
    curve_config: MpcCurveConfig,
    config: ClientProtocolConfig,
    inputs_str: &str,
    network_for_process: Arc<tokio::sync::Mutex<QuicNetworkManager>>,
    msg_rx: mpsc::Receiver<DirectClientInboundMessage>,
) -> Result<(), String> {
    macro_rules! run {
        ($F:ty, $G:ty) => {
            run_hb_client_protocol_for_curve::<$F>(config, inputs_str, network_for_process, msg_rx)
                .await
        };
    }
    dispatch_hb_curve!(
        curve_config,
        run,
        Err(format!(
            "client mode with honeybadger backend does not support curve {}",
            curve_config.name()
        ))
    )
}

#[allow(clippy::too_many_arguments)]
async fn run_as_client(
    execution_id: ExecutionId,
    n_parties: Option<usize>,
    threshold: Option<usize>,
    mpc_backend: Option<&str>,
    mpc_curve: Option<&str>,
    client_inputs: Option<String>,
    client_outputs: Option<usize>,
    output_format: CoordinatorOutputFormat,
    server_addrs: Vec<SocketAddr>,
    cert_der: Option<Vec<u8>>,
    key_der: Option<Vec<u8>>,
) {
    let n = n_parties.unwrap_or_else(|| {
        eprintln!("Error: --n-parties is required in client mode");
        exit(2);
    });
    let t = threshold.unwrap_or(1);

    let backend_kind = if let Some(backend_name) = mpc_backend {
        MpcBackendKind::from_str(backend_name).unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            exit(2);
        })
    } else {
        MpcBackendKind::default()
    };
    if let Err(error) = backend_kind.validate_party_count(n) {
        eprintln!("Error: {error}");
        exit(2);
    }

    // A client may be an input client (provides `--inputs`), an output-only
    // client (provides `--outputs` and no inputs, e.g. a result recipient), or
    // both. `--inputs` is therefore optional.
    let inputs_str = client_inputs.unwrap_or_default();
    let input_len = if inputs_str.trim().is_empty() {
        0
    } else {
        inputs_str.split(',').count()
    };
    let output_len = client_outputs.unwrap_or(input_len);
    if input_len == 0 && output_len == 0 {
        eprintln!(
            "Error: a client must either provide --inputs (comma-separated values) or receive \
             outputs via --outputs <N> in client mode"
        );
        exit(2);
    }

    if server_addrs.is_empty() {
        eprintln!("Error: --servers is required in client mode (comma-separated addresses)");
        eprintln!(
            "Example: --servers 172.18.0.2:9000,172.18.0.3:9000,172.18.0.4:9000,172.18.0.5:9000,172.18.0.6:9000"
        );
        exit(2);
    }

    if server_addrs.len() != n {
        eprintln!(
            "Error: number of servers ({}) doesn't match n_parties ({})",
            server_addrs.len(),
            n
        );
        exit(2);
    }

    let curve_config = if let Some(name) = mpc_curve {
        MpcCurveConfig::from_str(name).unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            exit(2);
        })
    } else {
        MpcCurveConfig::default()
    };

    if let Err(e) = curve_config.validate_for_backend(backend_kind) {
        eprintln!("Error: {}", e);
        exit(2);
    }
    eprintln!(
        "[client] Client mode (backend={}, curve={}, n={}, t={}, {} inputs, {} outputs, {} servers)",
        backend_kind.name(),
        curve_config.name(),
        n,
        t,
        input_len,
        output_len,
        server_addrs.len()
    );

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls crypto");

    let mut client_network = QuicNetworkManager::new();
    match (cert_der, key_der) {
        (Some(cert_der), Some(key_der)) => client_network
            .set_local_certificate_der(cert_der, key_der)
            .unwrap_or_else(|error| {
                eprintln!("Error: failed to configure direct-client certificate: {error}");
                exit(2);
            }),
        (None, None) => {}
        _ => {
            eprintln!("Error: direct client requires both --cert and --key when either is set");
            exit(2);
        }
    }
    let network = Arc::new(tokio::sync::Mutex::new(client_network));

    for (party_id, &addr) in server_addrs.iter().enumerate() {
        network.lock().await.add_node_with_party_id(party_id, addr);
        eprintln!("[client] Added server party {} at {}", party_id, addr);
    }

    let (msg_tx, mut msg_rx) = mpsc::channel::<DirectClientInboundMessage>(1000);

    eprintln!("[client] Connecting to {} servers...", server_addrs.len());
    connect_to_all_servers(&network, &server_addrs).await;

    // Get the client's position in the (n+1)-key sorted list so inbound and
    // outbound authenticated IDs can both skip the client's own slot.
    let local_position = {
        let net = network.lock().await;
        net.compute_local_party_id().unwrap_or(0)
    };

    // MPC backends own no raw connection reader here. The shared scanner is
    // the sole physical reader and feeds this execution's registered inbox.
    let (_execution_registration, _execution_scanner) = {
        let mux = ExecutionTransportMux::new_client(4096)
            .expect("MPC execution inbox capacity is nonzero");
        let mut inbox = mux.register(execution_id).unwrap_or_else(|error| {
            eprintln!("[client] Failed to register execution transport: {error}");
            exit(24);
        });
        let registration = ExecutionInboxRegistrationGuard::new(mux.clone(), execution_id);
        let scanner_network = {
            let net = network.lock().await;
            (*net).clone()
        };
        let scanner =
            ExecutionConnectionScanner::spawn(scanner_network, mux).unwrap_or_else(|error| {
                eprintln!("[client] Failed to start execution transport: {error}");
                exit(24);
            });
        let routed_tx = msg_tx.clone();
        tokio::spawn(async move {
            loop {
                let message = tokio::select! {
                    message = inbox.party.recv() => message,
                    message = inbox.client.recv() => message,
                };
                let Some(message) = message else { break };
                let inbound = direct_client_inbound_message(local_position, message);
                if routed_tx.send(inbound).await.is_err() {
                    break;
                }
            }
        });
        (registration, scanner)
    };

    let hello_network = {
        let control_network = {
            let net = network.lock().await;
            ExecutionScopedNetwork::for_client((*net).clone(), execution_id)
                .map(|network| network.with_message_kind(ExecutionMessageKind::Control))
                .unwrap_or_else(|error| {
                    eprintln!("[client] Failed to create execution hello transport: {error}");
                    exit(24);
                })
        };
        let hello_network = ScopedClientNetworkAdapter {
            inner: control_network,
            local_position,
        };
        send_execution_client_hellos(&hello_network, n)
            .await
            .unwrap_or_else(|error| {
                eprintln!("[client] {error}");
                exit(24);
            });
        hello_network
    };

    let cid = {
        let net = network.lock().await;
        net.local_derived_id()
    };
    eprintln!("[client {}] Derived transport client ID", cid);

    // Read INST message from servers: [b"INST" | instance_id:u64 | client_index:u8]
    let (instance_id, client_index, pending_messages) = {
        let timeout_dur = honeybadger_protocol_timeout();
        let mut result: Option<(u64, u8)> = None;
        let mut pending_messages = Vec::new();
        let deadline = tokio::time::Instant::now() + timeout_dur;
        let mut hello_retry = tokio::time::interval(Duration::from_secs(1));
        hello_retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Consume the immediate first tick; the initial hello was sent above.
        hello_retry.tick().await;
        while result.is_none() {
            tokio::select! {
                message = msg_rx.recv() => match message {
                Some(inbound) => {
                    let data = &inbound.message.payload;
                    if data.len() == 13 && &data[0..4] == b"INST" {
                        let id_bytes: [u8; 8] = data[4..12].try_into().unwrap();
                        let inst_id = u64::from_le_bytes(id_bytes);
                        let idx = data[12];
                        result = Some((inst_id, idx));
                    } else {
                        pending_messages.push(inbound);
                    }
                }
                None => {
                    eprintln!("[client {}] Channel closed before receiving INST", cid);
                    exit(25);
                }
                },
                _ = hello_retry.tick() => {
                    if let Err(error) = send_execution_client_hellos(&hello_network, n).await {
                        eprintln!("[client {cid}] execution hello retry failed: {error}");
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    eprintln!("[client {}] Timeout waiting for INST from server", cid);
                    exit(25);
                }
            }
        }
        // The first INST proves only one server admitted this physical route.
        // Keep advertising briefly so an honest scanner that is still
        // discovering its connection does not miss the only useful hello. This
        // is deliberately bounded rather than an all-party acknowledgement
        // barrier: the client must still progress when a Byzantine party omits.
        for _ in 0..2 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if let Err(error) = send_execution_client_hellos(&hello_network, n).await {
                eprintln!("[client {cid}] execution hello grace retry failed: {error}");
            }
        }
        let (id, idx) = result.unwrap();
        eprintln!(
            "[client {}] Received INST: instance_id={}, client_index={}",
            cid, id, idx
        );
        (id, idx, pending_messages)
    };

    eprintln!(
        "[client {}] Connected to all servers, starting input protocol...",
        cid
    );

    eprintln!(
        "[client {}] Local position in sorted key list: {}",
        cid, local_position
    );

    let msg_rx = if pending_messages.is_empty() {
        msg_rx
    } else {
        eprintln!(
            "[client {}] Replaying {} protocol messages received before INST",
            cid,
            pending_messages.len()
        );
        let (replay_tx, replay_rx) = mpsc::channel::<DirectClientInboundMessage>(1000);
        tokio::spawn(async move {
            for message in pending_messages {
                if replay_tx.send(message).await.is_err() {
                    return;
                }
            }
            while let Some(message) = msg_rx.recv().await {
                if replay_tx.send(message).await.is_err() {
                    return;
                }
            }
        });
        replay_rx
    };

    let network_for_process = network.clone();
    let inputs_for_task = inputs_str.clone();
    let process_handle = match backend_kind {
        MpcBackendKind::HoneyBadger => {
            let protocol_config = ClientProtocolConfig {
                execution_id,
                n,
                t,
                input_len,
                output_len,
                instance_id,
                client_index,
                local_position,
                curve_config,
                output_format: output_format.clone(),
            };
            tokio::spawn(async move {
                run_hb_client_for_curve(
                    curve_config,
                    protocol_config,
                    &inputs_for_task,
                    network_for_process,
                    msg_rx,
                )
                .await
            })
        }
        MpcBackendKind::Avss => {
            let protocol_config = ClientProtocolConfig {
                execution_id,
                n,
                t,
                input_len,
                output_len,
                instance_id,
                client_index,
                local_position,
                curve_config,
                output_format,
            };
            tokio::spawn(async move {
                run_avss_client_for_curve(
                    curve_config,
                    protocol_config,
                    &inputs_for_task,
                    network_for_process,
                    msg_rx,
                )
                .await
            })
        }
    };

    let timeout_duration = honeybadger_protocol_timeout();
    match tokio::time::timeout(timeout_duration, process_handle).await {
        Ok(Ok(Ok(()))) => {
            eprintln!("[client {}] Direct MPC client protocol completed", cid);
        }
        Ok(Ok(Err(e))) => {
            eprintln!("[client {}] Input protocol failed: {}", cid, e);
            exit(22);
        }
        Ok(Err(e)) => {
            eprintln!("[client {}] Input task error: {:?}", cid, e);
            exit(22);
        }
        Err(_) => {
            eprintln!(
                "[client {}] Timeout waiting for input protocol to complete",
                cid
            );
            exit(23);
        }
    }
}
struct AvssOffchainCoordinatorClientArgs {
    execution_id: ExecutionId,
    curve_config: MpcCurveConfig,
    client_inputs: Option<String>,
    client_outputs: Option<usize>,
    output_format: CoordinatorOutputFormat,
    server_addrs: Vec<SocketAddr>,
    client_transport_addrs: Vec<SocketAddr>,
    coord_addr: (String, u16),
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    threshold: Option<usize>,
    coordinator_client_index: Option<u64>,
}
async fn run_avss_offchain_coordinator_client_for_curve<F, G>(
    args: AvssOffchainCoordinatorClientArgs,
) where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    let AvssOffchainCoordinatorClientArgs {
        execution_id,
        curve_config: _,
        client_inputs,
        client_outputs,
        output_format,
        server_addrs,
        client_transport_addrs,
        coord_addr,
        cert_der,
        key_der,
        threshold,
        coordinator_client_index,
    } = args;

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls crypto");

    let t = threshold.unwrap_or(1);
    let input_values = client_inputs
        .as_deref()
        .map(parse_inputs_as_field::<F>)
        .unwrap_or_default();
    let output_len = client_outputs.unwrap_or(input_values.len());
    let reserved_index = coordinator_client_index.unwrap_or_else(|| {
        if input_values.is_empty() {
            return 0;
        }
        eprintln!(
            "Error: coordinator client mode requires --client-index to claim a reserved input slot"
        );
        exit(2);
    });

    let mut coord: AvssOffChainCoordinator<F, G> =
        AvssOffChainCoordinator::<F, G>::start_rpc_client_for_execution(
            &coord_addr.0,
            coord_addr.1,
            t as u64,
            server_addrs.len() as u64,
            output_len as u64,
            coordinator_execution_id(execution_id),
            cert_der.clone(),
            key_der.clone(),
        )
        .await
        .unwrap_or_else(|error| {
            eprintln!("Failed to connect to AVSS off-chain coordinator: {error}");
            exit(13);
        });
    // jsonrpsee multiplexes requests on one WebSocket. Starting a long-lived
    // subscription concurrently with the input RPC on that same connection
    // can make subscription acceptance wait behind the submission response
    // while holding the coordinator's execution lock. Give eager output
    // subscription its own authenticated connection.
    let eager_output_coord = if !input_values.is_empty() && output_len > 0 {
        Some(
            AvssOffChainCoordinator::<F, G>::start_rpc_client_for_execution(
                &coord_addr.0,
                coord_addr.1,
                t as u64,
                server_addrs.len() as u64,
                output_len as u64,
                coordinator_execution_id(execution_id),
                cert_der.clone(),
                key_der.clone(),
            )
            .await
            .unwrap_or_else(|error| {
                eprintln!("Failed to connect AVSS output subscription: {error}");
                exit(13);
            }),
        )
    } else {
        None
    };
    if input_values.is_empty() && output_len > 0 {
        if client_transport_addrs.len() != server_addrs.len() {
            eprintln!(
                "Error: output-only coordinator clients require one --client-transport-servers address per RPC server (got {} transport addresses for {} servers)",
                client_transport_addrs.len(),
                server_addrs.len()
            );
            exit(2);
        }
        // Subscribe for the result before releasing the parties' authenticated
        // client-transport barrier. Fast programs can otherwise finish and be
        // retired between the route handshake and the first output RPC.
        let output_wait = async {
            coord.wait_for_round(Round::Preprocessing).await.unwrap();
            coord.obtain_outputs().await.unwrap()
        };
        let route_wait = establish_coordinator_output_client_routes(
            execution_id,
            &client_transport_addrs,
            cert_der.clone(),
            key_der.clone(),
        );
        let (outputs, _output_client_routes) = tokio::join!(output_wait, route_wait);
        println!(
            "outputs: {}",
            format_coordinator_outputs(&outputs, &output_format)
        );
        return;
    }

    coord.wait_for_round(Round::Preprocessing).await.unwrap();
    let mut eager_outputs = None;
    if !input_values.is_empty() {
        coord
            .wait_for_round(Round::InputMaskReservation)
            .await
            .unwrap();
        let reserve_indices: Vec<u64> = (0..input_values.len() as u64)
            .map(|offset| reserved_index + offset)
            .collect();
        eprintln!(
            "[client slot {reserved_index}] reserving {} input mask(s)",
            reserve_indices.len()
        );
        coord.reserve_mask_indices(&reserve_indices).await.unwrap();

        let rpc_addrs: Vec<(String, u16)> = server_addrs
            .iter()
            .map(|addr| (addr.ip().to_string(), addr.port()))
            .collect();
        let node_rpc_client = if input_values.is_empty() {
            None
        } else {
            Some(
                AvssOffChainNodeRpcClient::<F, G>::start_rpc_client_for_execution(
                    rpc_addrs.len(),
                    t,
                    rpc_addrs,
                    coordinator_execution_id(execution_id),
                    cert_der,
                    key_der,
                )
                .await
                .unwrap_or_else(|error| {
                    eprintln!("Failed to connect to AVSS node RPC servers: {error}");
                    exit(13);
                }),
            )
        };
        eprintln!("[client slot {reserved_index}] waiting for assigned mask shares");
        let masks = node_rpc_client
            .as_ref()
            .expect("input clients create a node RPC client")
            .receive_assigned_masks(
                reserved_index,
                u64::try_from(input_values.len()).expect("client input count exceeds u64"),
            )
            .await
            .unwrap();

        coord.wait_for_round(Round::InputCollection).await.unwrap();
        let masked_inputs: Vec<(u64, F)> = input_values
            .iter()
            .zip(masks)
            .enumerate()
            .map(|(offset, (input_value, mask))| {
                (reserved_index + offset as u64, mask + *input_value)
            })
            .collect();
        eprintln!(
            "[client slot {reserved_index}] submitting {} masked input(s)",
            masked_inputs.len()
        );
        if output_len == 0 {
            coord.send_masked_inputs(&masked_inputs).await.unwrap();
        } else {
            // Let the input RPC fully release the coordinator execution lock
            // before installing the long-lived output subscription. The
            // coordinator retains shares and snapshots them for late waiters.
            coord.send_masked_inputs(&masked_inputs).await.unwrap();
            eager_outputs = Some(
                eager_output_coord
                    .as_ref()
                    .expect("input/output clients create an output coordinator")
                    .obtain_outputs()
                    .await
                    .unwrap(),
            );
        }
    }
    if output_len == 0 {
        eprintln!("[client slot {reserved_index}] input submission complete; no outputs requested");
        return;
    }

    let outputs = match eager_outputs {
        Some(outputs) => outputs,
        None => {
            coord.wait_for_round(Round::MPCExecution).await.unwrap();
            coord
                .wait_for_round(Round::OutputDistribution)
                .await
                .unwrap();
            coord.obtain_outputs().await.unwrap()
        }
    };
    println!(
        "outputs: {}",
        format_coordinator_outputs(&outputs, &output_format)
    );
}
async fn run_avss_offchain_coordinator_client(args: AvssOffchainCoordinatorClientArgs) {
    macro_rules! run {
        ($F:ty, $G:ty) => {
            run_avss_offchain_coordinator_client_for_curve::<$F, $G>(args).await
        };
    }
    dispatch_avss_curve!(args.curve_config, run)
}
#[allow(clippy::too_many_arguments)]
async fn run_hb_coordinator_client_for_field<F>(
    execution_id: ExecutionId,
    client_inputs: Option<String>,
    client_outputs: Option<usize>,
    output_format: CoordinatorOutputFormat,
    server_addrs: Vec<SocketAddr>,
    client_transport_addrs: Vec<SocketAddr>,
    coord_addr: Option<(String, u16)>,
    contract_addr: Option<String>,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    threshold: Option<usize>,
    coordinator_client_index: Option<u64>,
    eth_node_addr: Option<String>,
    wallet_sk_str: Option<String>,
) where
    F: SupportedMpcField,
{
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls crypto");

    let t = threshold.unwrap_or(1);
    let input_values = client_inputs
        .as_deref()
        .map(parse_inputs_as_field::<F>)
        .unwrap_or_default();
    let output_len = client_outputs.unwrap_or(input_values.len());
    let reserved_index = coordinator_client_index.unwrap_or_else(|| {
        if input_values.is_empty() {
            return 0;
        }
        eprintln!(
            "Error: coordinator client mode requires --client-index to claim a reserved input slot"
        );
        exit(2);
    });

    if contract_addr.is_some() {
        let _ = (eth_node_addr, wallet_sk_str);
        eprintln!(
            "Error: on-chain coordinator mode is temporarily unavailable in the crates.io-ready build"
        );
        exit(2);
    }

    // Off-chain client mode
    let ca = coord_addr.expect("--off-chain-coord required in off-chain client mode");
    let mut coord: HbOffChainCoordinator<F> =
        HbOffChainCoordinator::<F>::start_rpc_client_for_execution(
            &ca.0,
            ca.1,
            t as u64,
            server_addrs.len() as u64,
            output_len as u64,
            coordinator_execution_id(execution_id),
            cert_der.clone(),
            key_der.clone(),
        )
        .await
        .unwrap_or_else(|error| {
            eprintln!("Failed to connect to off-chain coordinator: {error}");
            exit(13);
        });
    // Keep the long-lived output subscription off the WebSocket carrying the
    // input submission. Otherwise subscription acceptance can hold the
    // coordinator execution lock while its handshake waits behind the input
    // RPC response on the same connection.
    let eager_output_coord = if !input_values.is_empty() && output_len > 0 {
        Some(
            HbOffChainCoordinator::<F>::start_rpc_client_for_execution(
                &ca.0,
                ca.1,
                t as u64,
                server_addrs.len() as u64,
                output_len as u64,
                coordinator_execution_id(execution_id),
                cert_der.clone(),
                key_der.clone(),
            )
            .await
            .unwrap_or_else(|error| {
                eprintln!("Failed to connect output subscription: {error}");
                exit(13);
            }),
        )
    } else {
        None
    };
    if input_values.is_empty() && output_len > 0 {
        if client_transport_addrs.len() != server_addrs.len() {
            eprintln!(
                "Error: output-only coordinator clients require one --client-transport-servers address per RPC server (got {} transport addresses for {} servers)",
                client_transport_addrs.len(),
                server_addrs.len()
            );
            exit(2);
        }
        // Subscribe for the result before releasing the parties' authenticated
        // client-transport barrier. Fast programs can otherwise finish and be
        // retired between the route handshake and the first output RPC.
        let output_wait = async {
            coord.wait_for_round(Round::Preprocessing).await.unwrap();
            coord.obtain_outputs().await.unwrap()
        };
        let route_wait = establish_coordinator_output_client_routes(
            execution_id,
            &client_transport_addrs,
            cert_der.clone(),
            key_der.clone(),
        );
        let (outputs, _output_client_routes) = tokio::join!(output_wait, route_wait);
        println!(
            "outputs: {}",
            format_coordinator_outputs(&outputs, &output_format)
        );
        return;
    }

    coord.wait_for_round(Round::Preprocessing).await.unwrap();
    let mut eager_outputs = None;
    if !input_values.is_empty() {
        coord
            .wait_for_round(Round::InputMaskReservation)
            .await
            .unwrap();
        let reserve_indices: Vec<u64> = (0..input_values.len() as u64)
            .map(|offset| reserved_index + offset)
            .collect();
        eprintln!(
            "[client slot {reserved_index}] reserving {} input mask(s)",
            reserve_indices.len()
        );
        coord.reserve_mask_indices(&reserve_indices).await.unwrap();

        let rpc_addrs: Vec<(String, u16)> = server_addrs
            .iter()
            .map(|a| (a.ip().to_string(), a.port()))
            .collect();
        let node_rpc_client = if input_values.is_empty() {
            None
        } else {
            Some(
                HbOffChainNodeRpcClient::<F>::start_rpc_client_for_execution(
                    rpc_addrs.len(),
                    t,
                    rpc_addrs,
                    coordinator_execution_id(execution_id),
                    cert_der,
                    key_der,
                )
                .await
                .unwrap_or_else(|error| {
                    eprintln!("Failed to connect to node RPC servers: {error}");
                    exit(13);
                }),
            )
        };
        eprintln!("[client slot {reserved_index}] waiting for assigned mask shares");
        let masks = node_rpc_client
            .as_ref()
            .expect("input clients create a node RPC client")
            .receive_assigned_masks(
                reserved_index,
                u64::try_from(input_values.len()).expect("client input count exceeds u64"),
            )
            .await
            .unwrap();

        coord.wait_for_round(Round::InputCollection).await.unwrap();
        let masked_inputs: Vec<(u64, F)> = input_values
            .iter()
            .zip(masks)
            .enumerate()
            .map(|(offset, (input_value, mask))| {
                (reserved_index + offset as u64, mask + *input_value)
            })
            .collect();
        eprintln!(
            "[client slot {reserved_index}] submitting {} masked input(s)",
            masked_inputs.len()
        );
        if output_len == 0 {
            coord.send_masked_inputs(&masked_inputs).await.unwrap();
        } else {
            // Let the input RPC fully release the coordinator execution lock
            // before installing the long-lived output subscription. The
            // coordinator retains shares and snapshots them for late waiters.
            coord.send_masked_inputs(&masked_inputs).await.unwrap();
            eager_outputs = Some(
                eager_output_coord
                    .as_ref()
                    .expect("input/output clients create an output coordinator")
                    .obtain_outputs()
                    .await
                    .unwrap(),
            );
        }
    }
    if output_len == 0 {
        eprintln!("[client slot {reserved_index}] input submission complete; no outputs requested");
        return;
    }

    let outputs = match eager_outputs {
        Some(outputs) => outputs,
        None => {
            coord.wait_for_round(Round::MPCExecution).await.unwrap();
            eprintln!("[client slot {reserved_index}] waiting for output distribution");
            coord
                .wait_for_round(Round::OutputDistribution)
                .await
                .unwrap();
            coord.obtain_outputs().await.unwrap()
        }
    };
    println!(
        "outputs: {}",
        format_coordinator_outputs(&outputs, &output_format)
    );
}
#[allow(clippy::too_many_arguments)]
async fn run_hb_coordinator_client(
    curve_config: MpcCurveConfig,
    execution_id: ExecutionId,
    client_inputs: Option<String>,
    client_outputs: Option<usize>,
    output_format: CoordinatorOutputFormat,
    server_addrs: Vec<SocketAddr>,
    client_transport_addrs: Vec<SocketAddr>,
    coord_addr: Option<(String, u16)>,
    contract_addr: Option<String>,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    threshold: Option<usize>,
    coordinator_client_index: Option<u64>,
    eth_node_addr: Option<String>,
    wallet_sk_str: Option<String>,
) {
    macro_rules! run {
        ($F:ty, $G:ty) => {
            run_hb_coordinator_client_for_field::<$F>(
                execution_id,
                client_inputs,
                client_outputs,
                output_format,
                server_addrs,
                client_transport_addrs,
                coord_addr,
                contract_addr,
                cert_der,
                key_der,
                threshold,
                coordinator_client_index,
                eth_node_addr,
                wallet_sk_str,
            )
            .await
        };
    }
    dispatch_hb_curve!(curve_config, run, {
        eprintln!(
            "Error: curve {} is not supported by honeybadger backend",
            curve_config.name()
        );
        exit(2);
    })
}
async fn admit_execution_clients(
    client_inbox: &mut mpsc::Receiver<ExecutionInboundMessage>,
    expected_client_count: Option<usize>,
    expected_client_bindings: Option<&[ClientProtocolBinding]>,
) -> Result<Vec<ClientProtocolBinding>, String> {
    let expected_client_ids = expected_client_bindings.map(client_binding_route_ids);
    let roster_count = expected_client_bindings.map(<[_]>::len);
    if let (Some(expected), Some(roster)) = (expected_client_count, roster_count) {
        if expected != roster {
            return Err(format!(
                "wait-for-clients count {expected} does not match the {roster} admitted client bindings"
            ));
        }
    }
    let wait_for = roster_count
        .filter(|count| *count > 0)
        .or(expected_client_count);
    if wait_for == Some(0) {
        return Err("--wait-for-clients count must be greater than 0".to_owned());
    }
    let mut bindings = Vec::new();
    if let Some(expected) = wait_for {
        let deadline = tokio::time::Instant::now() + honeybadger_protocol_timeout();
        let mut clients = HashSet::with_capacity(expected);
        while clients.len() < expected {
            let inbound = tokio::time::timeout_at(deadline, client_inbox.recv())
                .await
                .map_err(|_| {
                    format!(
                        "timeout waiting for execution client hellos ({}/{expected})",
                        clients.len()
                    )
                })?
                .ok_or_else(|| {
                    "execution client inbox closed while waiting for client hellos".to_owned()
                })?;
            match inbound.source {
                ExecutionTransportSource::Client(client_id)
                    if inbound.kind == ExecutionMessageKind::Control
                        && inbound.payload == EXECUTION_CLIENT_HELLO_V1
                        && expected_client_ids
                            .as_ref()
                            .is_none_or(|allowed| allowed.contains(&client_id)) =>
                {
                    clients.insert(client_id);
                }
                // Valid clients wait for INST before sending MPC payloads.
                // Premature or unrelated traffic is not replayed into the
                // execution after admission.
                _ => {}
            }
        }
        bindings = resolve_client_protocol_bindings(expected_client_bindings, clients)?;
    } else if expected_client_bindings.is_some() {
        bindings = resolve_client_protocol_bindings(expected_client_bindings, HashSet::new())?;
    }

    Ok(bindings)
}

enum PartyPreprocessing {
    OneShot,
    Reservoir { burst_capacity: usize },
    Execution(OwnedPreprocBundle),
}

impl PartyPreprocessing {
    fn into_parts(self) -> (DeploymentMode, usize, bool, Option<OwnedPreprocBundle>) {
        match self {
            Self::OneShot => (DeploymentMode::OneShot, 1, false, None),
            Self::Reservoir { burst_capacity } => {
                (DeploymentMode::Standing, burst_capacity, true, None)
            }
            Self::Execution(bundle) => (DeploymentMode::Standing, 1, false, Some(bundle)),
        }
    }
}

struct PartySetup<'a> {
    net: Arc<QuicNetworkManager>,
    reply_mux: ExecutionTransportMux,
    execution_id: ExecutionId,
    execution_inbox: ExecutionInbox,
    my_id: usize,
    identity: DurableIdentityDigest,
    n: usize,
    t: usize,
    instance_id: u64,
    expected_client_count: Option<usize>,
    expected_client_bindings: Option<Arc<Vec<ClientProtocolBinding>>>,
    expected_client_reservation_identities: Option<Arc<BTreeMap<ClientId, DurableIdentityDigest>>>,
    client_count_hint: usize,
    client_input_count: usize,
    client_input_types: &'a std::collections::BTreeMap<usize, Vec<ShareType>>,
    preprocessing_demand: stoffel_vm_types::compiled_binary::PreprocessingDemand,
    program_hash: [u8; 32],
    preproc_store: Option<Arc<dyn PreprocStore>>,
    preprocessing: PartyPreprocessing,
    execution_tasks: Option<&'a ExecutionTaskGroup>,
}

async fn setup_hb_party_for_curve<F, G>(
    vm: &mut VirtualMachine,
    setup: PartySetup<'_>,
) -> Result<Arc<HoneyBadgerMpcEngine<F, G>>, String>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    let PartySetup {
        net,
        reply_mux,
        execution_id,
        mut execution_inbox,
        my_id,
        identity,
        n,
        t,
        instance_id,
        expected_client_count,
        expected_client_bindings,
        expected_client_reservation_identities,
        client_count_hint,
        client_input_count,
        client_input_types,
        preprocessing_demand,
        program_hash,
        preproc_store,
        preprocessing,
        execution_tasks,
    } = setup;
    let (
        deployment_mode,
        preprocessing_burst_capacity,
        use_program_preproc_reservoir,
        preallocated_bundle,
    ) = preprocessing.into_parts();

    let protocol_network = ExecutionScopedNetwork::for_party((*net).clone(), execution_id)
        .map_err(|error| format!("invalid HoneyBadger execution transport: {error}"))?
        .with_reply_mux(reply_mux);
    let control_network = protocol_network
        .clone()
        .with_message_kind(ExecutionMessageKind::Control);

    let clients = prepare_party_clients(
        &mut execution_inbox.client,
        expected_client_count,
        expected_client_bindings.as_deref().map(Vec::as_slice),
        client_input_types,
        client_input_count,
    )
    .await?;
    let client_bindings = &clients.bindings;
    let input_ids = &clients.route_ids;
    let input_setup_plan = &clients.input_setup;

    // ---- Phase 2: Setup MPC node and preprocess ----
    //
    // CRITICAL: We use exactly TWO clones of the MPC node to avoid the
    // double-processing bug where init_ransha() is called multiple times:
    //   - Clone 1 (`processing_node`): handles incoming messages via process()
    //   - Clone 2 (inside `engine`): initiates preprocessing via run_preprocessing()
    // Both share the same Arc<Mutex> stores, but only ONE processes each message.
    // Plan the preprocessing material from the compiler's static demand
    // estimate, rounding each count up to a power of 2 so the generated volume
    // reveals only the program's size octave (privacy), not its exact operation
    // counts. The plan folds in the dependency that prandbit generation consumes
    // a triple + random per bit, and a baseline so light programs still run.
    let n_client_random = client_preprocessing_count(
        &clients,
        deployment_mode,
        client_input_types,
        client_count_hint,
        client_input_count,
    )?;
    let plan = plan_preprocessing(&preprocessing_demand, t, n_client_random)
        .checked_scale(preprocessing_burst_capacity)?;
    let n_triples = plan.n_triples;
    let n_random = plan.n_random;
    let n_prandbit = plan.n_prandbit;
    let n_prandint = plan.n_prandint;
    let protocol_timeout = honeybadger_protocol_timeout();
    eprintln!(
        "[party {}] Creating MPC node opts (n_triples={}, n_random={}, n_prandbit={}, n_prandint={}, dynamic={}, timeout={}s)",
        my_id,
        n_triples,
        n_random,
        n_prandbit,
        n_prandint,
        preprocessing_demand.dynamic,
        protocol_timeout.as_secs()
    );
    let mpc_opts = honeybadger_node_opts_with_truncation(
        n,
        t,
        n_triples,
        n_random,
        n_prandbit,
        n_prandint,
        instance_id,
    )
    .unwrap_or_else(|e| {
        eprintln!("Failed to create MPC node options: {}", e);
        std::process::exit(2);
    });

    // Use sequential indices (0..n_clients) as client IDs for the MPC protocol
    // because the session_id only has 8 bits for the client_id field.
    // The backend's InputServer treats every configured ID as a required
    // participant in `wait_for_all_inputs`. Keep output-only clients in
    // `client_bindings` for INST and output routing, but exclude them from the
    // input protocol instead of requiring a synthetic completion message.
    let mpc_input_ids = mpc_input_protocol_ids(input_setup_plan);
    let mpc_node = <HoneyBadgerMPCNode<F, Avid<HbSessionId>> as MPCProtocol<
        F,
        RobustShare<F>,
        QuicNetworkManager,
    >>::setup(my_id, mpc_opts, mpc_input_ids)
    .map_err(|e| format!("Failed to create MPC node: {:?}", e))?;
    eprintln!("[party {}] MPC node setup complete", my_id);

    // Wire a send hook into the shared QuicNetworkManager so that ALL outbound
    // sends - both reactive sends from process() and proactive sends from the
    // engine during preprocessing/operations - are counted.
    #[cfg(feature = "statistics")]
    {
        let counters = mpc_node.statistics_counters.clone();
        net.set_send_hook(std::sync::Arc::new(move |data: &[u8], n: usize| {
            counters.record_outbound(data, n as u64);
        }));
    }

    // Created via from_existing_node which wraps the protocol node in Arc<Mutex>.
    let open_message_router = Arc::new(stoffel_vm::net::OpenMessageRouter::new());
    let topology = MpcSessionTopology::try_new(instance_id, my_id, n, t)
        .map_err(|error| format!("Invalid HoneyBadger MPC topology: {error}"))?;
    let engine = HoneyBadgerMpcEngine::<F, G>::try_from_existing_node_for_execution(
        open_message_router.clone(),
        topology,
        identity,
        net.clone(),
        protocol_network.clone(),
        mpc_node, // moved, not cloned
        deployment_mode,
    )?;
    if let Some(identities) = expected_client_reservation_identities {
        engine
            .install_standing_client_identities(identities.as_ref().clone())
            .await?;
    }

    let has_preproc_store = preproc_store.is_some();
    configure_preproc_store(engine.as_ref(), program_hash, preproc_store)?;
    if has_preproc_store {
        engine.set_preproc_store_identity(identity);
    }
    if use_program_preproc_reservoir {
        engine.use_program_preproc_reservoir();
    }
    if clients.manifest_driven {
        engine
            .set_client_output_slot_map(client_output_slot_map(client_bindings))
            .await;
    } else {
        engine.set_client_output_id_map(input_ids.clone()).await;
    }
    vm.set_mpc_engine(engine.clone());

    eprintln!("[party {}] Starting execution inbox pump...", my_id);
    let mut server_rx = execution_inbox.party;
    let mut preprocessing_exchange_rx = execution_inbox.control;
    let mut client_rx = execution_inbox.client;

    // Map canonical client transport IDs to MPC protocol indices.
    let client_id_to_index: std::collections::HashMap<ClientId, usize> = client_bindings
        .iter()
        .map(|binding| (binding.route_id, binding.protocol_index))
        .collect();

    // Single processing loop using tokio::select! for both server and client messages.
    // Only this task calls process(); fetch the node handle per message so reset swaps are visible.
    let processing_net = Arc::new(protocol_network);
    let processing_engine = engine.clone();
    let process_party_id = my_id;
    let processing_router = open_message_router;
    let preprocessing_cancellation = execution_tasks
        .map(ExecutionTaskGroup::cancellation_token)
        .unwrap_or_default();
    let (processor_ready_tx, processor_ready_rx) = oneshot::channel();
    spawn_execution_task(execution_tasks, async move {
        let _ = processor_ready_tx.send(());
        loop {
            tokio::select! {
                Some(message) = server_rx.recv() => {
                    let sender_id = match message.source {
                        ExecutionTransportSource::Party(sender_id) => sender_id,
                        ExecutionTransportSource::Client(client_id) => {
                            eprintln!("[party {}] Ignoring client source {} on party route", process_party_id, client_id);
                            continue;
                        }
                    };
                    let raw_msg = message.payload;
                    match processing_router.try_handle_wire_message(sender_id, &raw_msg) {
                        Ok(true) => continue,
                        Err(error) => {
                            eprintln!("[party {}] Failed to route open message from {}: {}", process_party_id, sender_id, error);
                            continue;
                        }
                        Ok(false) => {}
                    }
                    match processing_router.try_handle_hb_open_exp_wire_message(sender_id, &raw_msg) {
                        Ok(true) => continue,
                        Err(error) => {
                            eprintln!("[party {}] Failed to route open-exp message from {}: {}", process_party_id, sender_id, error);
                            continue;
                        }
                        Ok(false) => {}
                    }
                    let node_handle = processing_engine.node_handle().clone();
                    let process_result = {
                        let mut node = node_handle.lock().await;
                        node.process(sender_id, raw_msg, processing_net.clone()).await
                    };
                    if let Err(e) = process_result {
                        eprintln!(
                            "[party {}] Failed to process message from {}: {:?}",
                            process_party_id, sender_id, e
                        );
                    }
                }
                Some(message) = client_rx.recv() => {
                    let client_id = match message.source {
                        ExecutionTransportSource::Client(client_id) => client_id,
                        ExecutionTransportSource::Party(party_id) => {
                            eprintln!("[party {}] Ignoring party source {} on client route", process_party_id, party_id);
                            continue;
                        }
                    };
                    if message.kind != ExecutionMessageKind::Mpc {
                        eprintln!("[party {}] Ignoring client control message from {}", process_party_id, client_id);
                        continue;
                    }
                    let raw_msg = message.payload;
                    // Remap transport client ID → sequential index
                    let Some(mpc_sender_id) = client_id_to_index.get(&client_id).copied() else {
                        eprintln!(
                            "[party {}] Ignoring MPC payload from unauthorized client {}",
                            process_party_id, client_id
                        );
                        continue;
                    };
                    let node_handle = processing_engine.node_handle().clone();
                    let process_result = {
                        let mut node = node_handle.lock().await;
                        node.process(mpc_sender_id, raw_msg, processing_net.clone()).await
                    };
                    if let Err(e) = process_result {
                        eprintln!(
                            "[party {}] Failed to process client message from {} (idx {}): {:?}",
                            process_party_id, client_id, mpc_sender_id, e
                        );
                    }
                }
                else => break,
            }
        }
    });

    if preallocated_bundle.is_none() {
        synchronize_preprocessing_transport(
            &control_network,
            &mut preprocessing_exchange_rx,
            execution_id,
            my_id,
            n,
            instance_id,
            &preprocessing_cancellation,
            honeybadger_protocol_timeout(),
            PreprocessingExchangePhase::HoneyBadgerTransportReady,
            "HoneyBadger",
            processor_ready_rx,
        )
        .await?;
    }
    let mut standing_preprocessing_action = None;
    if engine.is_standing() && n > 1 && preallocated_bundle.is_none() {
        let local_snapshot = engine.standing_preproc_snapshot().await?;
        let local_targets = engine.standing_preproc_targets().await?;
        let local_proposal = StandingPreprocessingProposal {
            snapshot: local_snapshot,
            targets: local_targets,
            nonce: fresh_preprocessing_nonce(),
        };
        let (proposals, fresh_generation_id) = preprocessing_transcript_exchange(
            &control_network,
            &mut preprocessing_exchange_rx,
            execution_id,
            my_id,
            n,
            &preprocessing_cancellation,
            honeybadger_protocol_timeout(),
            PreprocessingExchangePhase::HoneyBadgerInventory,
            &local_proposal,
        )
        .await?;
        let snapshots = validate_preprocessing_proposals(proposals, local_targets, "HoneyBadger")?;
        let agreed_plan = engine
            .install_standing_preproc_plan(snapshots, fresh_generation_id)
            .await?;
        standing_preprocessing_action = Some(agreed_plan.action);
        eprintln!(
            "[party {}] HB standing preprocessing agreement: action={:?} generation={} targets={:?}",
            my_id,
            agreed_plan.action,
            hex::encode(&agreed_plan.generation_id[..4]),
            local_targets,
        );
    }

    let preprocessing_started_at = std::time::Instant::now();
    if let Some(bundle) = preallocated_bundle {
        engine.activate_preallocated_standing(bundle).await?;
        standing_preprocessing_action = Some(StandingPreprocAction::Reuse);
        eprintln!(
            "[party {}][execution {}] Activated preallocated HB reservoir bundle; preprocessing_wait_ms=0",
            my_id, execution_id
        );
    } else {
        eprintln!("[party {}] Starting MPC preprocessing...", my_id);
        engine
            .preprocess()
            .await
            .map_err(|e| format!("MPC preprocessing failed: {}", e))?;
        eprintln!(
            "[party {}] MPC preprocessing complete! PP_SECS: {:.3}",
            my_id,
            preprocessing_started_at.elapsed().as_secs_f64()
        );
        match current_cgroup_memory_bytes() {
            Some(bytes) => eprintln!(
                "[party {}] POST_PREPROCESSING_CGROUP_MEM_BYTES: {}",
                my_id, bytes
            ),
            None => eprintln!(
                "[party {}] POST_PREPROCESSING_CGROUP_MEM_BYTES: unavailable",
                my_id
            ),
        }
    }
    if n > 1 && standing_preprocessing_action != Some(StandingPreprocAction::Reuse) {
        eprintln!(
            "[party {}] Waiting for all parties to finish MPC preprocessing...",
            my_id
        );
        let (ready_instances, _) = preprocessing_transcript_exchange(
            &control_network,
            &mut preprocessing_exchange_rx,
            execution_id,
            my_id,
            n,
            &preprocessing_cancellation,
            honeybadger_protocol_timeout(),
            PreprocessingExchangePhase::HoneyBadgerReady,
            &instance_id,
        )
        .await?;
        if ready_instances.iter().any(|ready| *ready != instance_id) {
            return Err("parties reported divergent HoneyBadger protocol instances".to_owned());
        }
        eprintln!(
            "[party {}] All parties completed MPC preprocessing; continuing",
            my_id
        );
    }

    if !client_bindings.is_empty() {
        // Create a server-side network adapter that remaps sequential client
        // indices to transport client IDs for send_to_client().
        let server_adapter = Arc::new(ServerClientAdapter {
            inner: engine.protocol_network().as_ref().clone(),
            client_id_map: client_bindings
                .iter()
                .map(|binding| binding.route_id)
                .collect(),
        });

        if !input_setup_plan.is_empty() {
            eprintln!(
                "[party {}] Initializing InputServer for {} input clients...",
                my_id,
                input_setup_plan.len()
            );
            let (server_id, mut input_server) = {
                let node = engine.node_handle().lock().await;
                (node.id, node.preprocess.input.clone())
            };
            for setup in input_setup_plan {
                let local_shares = engine
                    .reserve_client_input_masks(setup.input_count)
                    .await
                    .map_err(|e| {
                        format!(
                            "Not enough random shares for client protocol index {}: {e}",
                            setup.protocol_index
                        )
                    })?;

                eprintln!(
                    "[party {}] Sending {} random shares to client protocol index {} (server_id={})",
                    my_id, setup.input_count, setup.protocol_index, server_id
                );
                let init_result = input_server
                    .init(
                        setup.protocol_index,
                        local_shares,
                        setup.input_count,
                        server_adapter.clone(),
                    )
                    .await;
                match init_result {
                    Ok(()) => {}
                    Err(InputError::NetworkError(
                        NetworkError::ClientNotFound(_) | NetworkError::SendError,
                    )) => {
                        eprintln!(
                            "[party {my_id}] HB client {} disconnected after admission; continuing with stored input state",
                            setup.protocol_index
                        );
                    }
                    Err(error) => {
                        return Err(format!(
                            "Failed to init InputServer for client protocol index {}: {error:?}",
                            setup.protocol_index
                        ));
                    }
                }
            }
        }

        // Every admitted client receives its compact protocol index, including
        // output-only clients for which no InputServer state was initialized.
        eprintln!(
            "[party {my_id}] Sending INST to {} clients...",
            client_bindings.len()
        );
        send_client_instances(&control_network, my_id, instance_id, client_bindings).await?;

        if !input_setup_plan.is_empty() {
            eprintln!(
                "[party {}] Waiting for all client inputs (timeout={}s)...",
                my_id,
                honeybadger_protocol_timeout().as_secs()
            );
            // The inbox processor acquires the node mutex to feed masked-input
            // frames into InputServer. Clone its shared handle before waiting so
            // this task does not hold that mutex and deadlock the producer.
            let mut input_server = {
                let node = engine.node_handle().lock().await;
                node.preprocess.input.clone()
            };
            let client_inputs = input_server
                .wait_for_all_inputs(honeybadger_protocol_timeout())
                .await
                .map_err(|e| format!("Failed to receive client inputs: {e:?}"))?;

            for (protocol_index, shares) in client_inputs {
                let binding = client_bindings
                    .iter()
                    .find(|binding| binding.protocol_index == protocol_index)
                    .ok_or_else(|| {
                        format!(
                            "InputServer returned unknown client protocol index {protocol_index}"
                        )
                    })?;
                if binding.protocol_index != protocol_index
                    || !input_setup_plan
                        .iter()
                        .any(|setup| setup.protocol_index == protocol_index)
                {
                    return Err(format!(
                        "InputServer returned uninitialized client protocol index {protocol_index}"
                    ));
                }
                if let Some(share_types) = client_input_types.get(&binding.manifest_slot) {
                    vm.try_store_client_input_with_types(
                        binding.manifest_slot,
                        shares,
                        share_types,
                    )?;
                } else {
                    vm.try_store_client_input(binding.manifest_slot, shares)?;
                }
                eprintln!(
                    "[party {}] Stored inputs for protocol index {} in manifest slot {} (client {})",
                    my_id, protocol_index, binding.manifest_slot, binding.route_id
                );
            }
        }
    }

    Ok(engine)
}
async fn setup_avss_party_for_curve<F, G>(
    vm: &mut VirtualMachine,
    setup: PartySetup<'_>,
) -> Result<Arc<stoffel_vm::net::avss_engine::AvssMpcEngine<F, G>>, String>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    let PartySetup {
        net,
        execution_id,
        reply_mux,
        mut execution_inbox,
        my_id,
        identity,
        n,
        t,
        instance_id,
        expected_client_count,
        expected_client_bindings,
        expected_client_reservation_identities: _,
        client_count_hint,
        client_input_count,
        client_input_types,
        preprocessing_demand,
        program_hash,
        preproc_store,
        preprocessing,
        execution_tasks,
    } = setup;
    let (
        deployment_mode,
        preprocessing_burst_capacity,
        use_program_preproc_reservoir,
        preallocated_bundle,
    ) = preprocessing.into_parts();

    let protocol_network = ExecutionScopedNetwork::for_party((*net).clone(), execution_id)
        .map_err(|error| format!("invalid AVSS execution transport: {error}"))?
        .with_reply_mux(reply_mux);
    let control_network = protocol_network
        .clone()
        .with_message_kind(ExecutionMessageKind::Control);

    let clients = prepare_party_clients(
        &mut execution_inbox.client,
        expected_client_count,
        expected_client_bindings.as_deref().map(Vec::as_slice),
        client_input_types,
        client_input_count,
    )
    .await?;
    let client_bindings = &clients.bindings;
    let input_ids = &clients.route_ids;
    let input_setup_plan = &clients.input_setup;

    // ---- Phase 2: ECDH key exchange over existing network ----
    // AVSS has the same InputServer barrier semantics as HoneyBadger: only
    // clients with declared inputs belong in the required input set.
    let mpc_input_ids = mpc_input_protocol_ids(input_setup_plan);

    // Generate ECDH key pair for AVSS payload confidentiality
    let mut rng = OsRng;
    let sk_i = F::rand(&mut rng);
    let pk_i: G = G::generator() * sk_i;

    // Reuse the same authenticated, retrying transcript exchange used by
    // preprocessing coordination. The sender position comes from the TLS-bound
    // party route, so the exchanged value only needs the common instance and
    // canonical public-key bytes.
    let mut pk_bytes = Vec::new();
    pk_i.serialize_compressed(&mut pk_bytes)
        .map_err(|error| format!("failed to serialize AVSS ECDH public key: {error:?}"))?;
    let preprocessing_cancellation = execution_tasks
        .map(ExecutionTaskGroup::cancellation_token)
        .unwrap_or_default();
    let mut party_rx = execution_inbox.party;
    let mut preprocessing_exchange_rx = execution_inbox.control;
    eprintln!("[party {my_id}] Exchanging ECDH public keys...");
    let (public_keys, _) = preprocessing_transcript_exchange(
        &control_network,
        &mut preprocessing_exchange_rx,
        execution_id,
        my_id,
        n,
        &preprocessing_cancellation,
        execution_coordination_timeout(),
        PreprocessingExchangePhase::AvssEcdh,
        &(instance_id, pk_bytes),
    )
    .await?;
    let mut pk_map = Vec::with_capacity(n);
    for (peer_id, (peer_instance, serialized_key)) in public_keys.into_iter().enumerate() {
        if peer_instance != instance_id {
            return Err(format!(
                "party {peer_id} proposed AVSS ECDH instance {peer_instance}, expected {instance_id}"
            ));
        }
        let key = G::deserialize_compressed(serialized_key.as_slice()).map_err(|error| {
            format!("failed to deserialize AVSS ECDH public key from party {peer_id}: {error:?}")
        })?;
        let mut canonical = Vec::new();
        key.serialize_compressed(&mut canonical).map_err(|error| {
            format!("failed to canonicalize AVSS ECDH public key from party {peer_id}: {error:?}")
        })?;
        if canonical != serialized_key {
            return Err(format!(
                "party {peer_id} sent a non-canonical AVSS ECDH public key"
            ));
        }
        pk_map.push(key);
    }
    eprintln!(
        "[party {my_id}] PK exchange complete ({} keys)",
        pk_map.len()
    );
    let pk_map = Arc::new(pk_map);

    // ---- Phase 3: Create engine directly with existing network ----
    use stoffel_vm::net::avss_engine::{AvssEngineConfig, AvssMpcEngine};
    let session = stoffel_vm::net::MpcSessionConfig::try_new(instance_id, my_id, n, t, net.clone())
        .map_err(|error| format!("Invalid AVSS MPC topology: {error}"))?
        .try_with_execution_id(execution_id)
        .map_err(|error| format!("Invalid AVSS execution identity: {error}"))?
        .with_local_identity(identity)
        .with_input_ids(mpc_input_ids);
    let n_client_random = client_preprocessing_count(
        &clients,
        deployment_mode,
        client_input_types,
        client_count_hint,
        client_input_count,
    )?;
    let planned = plan_preprocessing(&preprocessing_demand, t, n_client_random)
        .checked_scale(preprocessing_burst_capacity)?;
    let engine = AvssMpcEngine::<F, G>::from_config(
        AvssEngineConfig::new(session, sk_i, pk_map)
            .with_deployment_mode(deployment_mode)
            .with_protocol_network(protocol_network.clone())
            .with_preprocessing_counts(planned.n_random, planned.n_triples),
    )
    .await
    .map_err(|e| format!("Failed to create AVSS engine: {}", e))?;
    configure_preproc_store(engine.as_ref(), program_hash, preproc_store)?;
    if use_program_preproc_reservoir {
        engine.use_program_preproc_reservoir();
    }
    if clients.manifest_driven {
        engine
            .set_client_output_slot_map(client_output_slot_map(client_bindings))
            .await;
    } else {
        engine.set_client_output_id_map(input_ids.clone()).await;
    }

    #[cfg(feature = "statistics")]
    {
        let counters = engine
            .node_handle()
            .lock()
            .await
            .statistics_counters
            .clone();
        net.set_send_hook(std::sync::Arc::new(move |data: &[u8], n: usize| {
            counters.record_outbound(data, n as u64);
        }));
    }

    engine
        .start_async()
        .await
        .map_err(|e| format!("Failed to start AVSS engine: {}", e))?;
    vm.set_mpc_engine(engine.clone());

    // ---- Phase 4: Route backend traffic from the mux's MPC inbox.
    let mut client_rx = execution_inbox.client;

    let client_id_to_index: std::collections::HashMap<ClientId, usize> = client_bindings
        .iter()
        .map(|binding| (binding.route_id, binding.protocol_index))
        .collect();
    let processing_engine = engine.clone();
    let open_message_router = engine.open_message_router();
    let (processor_ready_tx, processor_ready_rx) = oneshot::channel();
    spawn_execution_task(execution_tasks, async move {
        let _ = processor_ready_tx.send(());
        loop {
            tokio::select! {
                Some(message) = party_rx.recv() => {
                    let sender_id = match message.source {
                        ExecutionTransportSource::Party(sender_id) => sender_id,
                        ExecutionTransportSource::Client(client_id) => {
                            eprintln!("[AVSS] Ignoring client {client_id} on the party route");
                            continue;
                        }
                    };
                    let data = message.payload;
                    if open_message_router.try_handle_wire_message(sender_id, &data).unwrap_or(false)
                        || open_message_router
                            .try_handle_avss_open_exp_wire_message(sender_id, &data)
                            .unwrap_or(false)
                        || open_message_router
                            .try_handle_avss_g2_exp_wire_message(sender_id, &data)
                            .unwrap_or(false)
                    {
                        continue;
                    }
                    if let Err(error) = processing_engine
                        .process_wrapped_message(sender_id, &data)
                        .await
                    {
                        eprintln!(
                            "[AVSS] Party failed to process message from {sender_id}: {error}"
                        );
                    }
                }
                Some(message) = client_rx.recv() => {
                    let client_id = match message.source {
                        ExecutionTransportSource::Client(client_id) => client_id,
                        ExecutionTransportSource::Party(party_id) => {
                            eprintln!("[AVSS] Ignoring party {party_id} on the client route");
                            continue;
                        }
                    };
                    if message.kind != ExecutionMessageKind::Mpc {
                        continue;
                    }
                    let Some(mpc_sender_id) = client_id_to_index.get(&client_id).copied() else {
                        eprintln!("[AVSS] Ignoring MPC payload from unauthorized client {client_id}");
                        continue;
                    };
                    if let Err(error) = processing_engine
                        .process_wrapped_message(mpc_sender_id, &message.payload)
                        .await
                    {
                        eprintln!(
                            "[party {}] Failed to process client message from {} (idx {}): {}",
                            processing_engine.party().id(),
                            client_id,
                            mpc_sender_id,
                            error
                        );
                    }
                }
                else => break,
            }
        }
    });

    // ---- Phase 5: Preprocessing ----
    if preallocated_bundle.is_none() {
        synchronize_preprocessing_transport(
            &control_network,
            &mut preprocessing_exchange_rx,
            execution_id,
            my_id,
            n,
            instance_id,
            &preprocessing_cancellation,
            execution_coordination_timeout(),
            PreprocessingExchangePhase::AvssTransportReady,
            "AVSS",
            processor_ready_rx,
        )
        .await?;
    }
    let mut standing_preprocessing_action = None;
    if engine.is_standing() && n > 1 && preallocated_bundle.is_none() {
        let local_snapshot = engine.standing_preproc_snapshot().await?;
        let local_targets = engine.standing_preproc_targets().await?;
        let local_proposal = StandingPreprocessingProposal {
            snapshot: local_snapshot,
            targets: local_targets,
            nonce: fresh_preprocessing_nonce(),
        };
        let (proposals, fresh_generation_id) = preprocessing_transcript_exchange(
            &control_network,
            &mut preprocessing_exchange_rx,
            execution_id,
            my_id,
            n,
            &preprocessing_cancellation,
            execution_coordination_timeout(),
            PreprocessingExchangePhase::AvssInventory,
            &local_proposal,
        )
        .await?;
        let snapshots = validate_preprocessing_proposals(proposals, local_targets, "AVSS")?;
        let agreed_plan = engine
            .install_standing_preproc_plan(snapshots, fresh_generation_id)
            .await?;
        standing_preprocessing_action = Some(agreed_plan.action);
        eprintln!(
            "[party {}] AVSS standing preprocessing agreement: action={:?} generation={} targets={:?}",
            my_id,
            agreed_plan.action,
            hex::encode(&agreed_plan.generation_id[..4]),
            local_targets,
        );
    }
    if let Some(bundle) = preallocated_bundle {
        engine.activate_preallocated_standing(bundle).await?;
        standing_preprocessing_action = Some(StandingPreprocAction::Reuse);
        eprintln!(
            "[party {}][execution {}] Activated preallocated AVSS reservoir bundle; preprocessing_wait_ms=0",
            my_id, execution_id
        );
    } else {
        eprintln!("[party {}] Starting AVSS preprocessing...", my_id);
        let preprocessing_started_at = std::time::Instant::now();
        engine.preprocess().await?;
        eprintln!(
            "[party {}] AVSS preprocessing complete! PP_SECS: {:.3}",
            my_id,
            preprocessing_started_at.elapsed().as_secs_f64()
        );
    }

    if n > 1 && standing_preprocessing_action != Some(StandingPreprocAction::Reuse) {
        eprintln!(
            "[party {}] Waiting for all parties to finish AVSS preprocessing...",
            my_id
        );
        let (ready_instances, _) = preprocessing_transcript_exchange(
            &control_network,
            &mut preprocessing_exchange_rx,
            execution_id,
            my_id,
            n,
            &preprocessing_cancellation,
            execution_coordination_timeout(),
            PreprocessingExchangePhase::AvssReady,
            &instance_id,
        )
        .await?;
        if ready_instances.iter().any(|ready| *ready != instance_id) {
            return Err("parties reported divergent AVSS protocol instances".to_owned());
        }
        eprintln!(
            "[party {}] All parties completed AVSS preprocessing; continuing",
            my_id
        );
    }

    // ---- Phase 6: Client input initialization ----
    if !client_bindings.is_empty() {
        let server_adapter = Arc::new(ServerClientAdapter {
            inner: protocol_network.clone(),
            client_id_map: client_bindings
                .iter()
                .map(|binding| binding.route_id)
                .collect(),
        });

        if !input_setup_plan.is_empty() {
            eprintln!(
                "[party {}] Initializing AVSS InputServer for {} input clients...",
                my_id,
                input_setup_plan.len()
            );
            let mut input_server = {
                let node = engine.node_handle().lock().await;
                node.input_server.clone()
            };
            for setup in input_setup_plan {
                let local_shares = engine
                    .reserve_client_input_masks(setup.input_count)
                    .await
                    .map_err(|e| {
                        format!(
                            "Not enough AVSS random shares for client protocol index {}: {e}",
                            setup.protocol_index
                        )
                    })?;
                let init_result = input_server
                    .init(
                        setup.protocol_index,
                        local_shares,
                        setup.input_count,
                        server_adapter.clone(),
                    )
                    .await;
                match init_result {
                    Ok(()) => {}
                    Err(AvssInputError::NetworkError(
                        NetworkError::ClientNotFound(_) | NetworkError::SendError,
                    )) => {
                        // init stores the local masks before attempting this
                        // send. A threshold-fast client may already have
                        // broadcast its masked input and disconnected; keep
                        // waiting for that authenticated broadcast.
                        eprintln!(
                            "[party {my_id}] AVSS client {} disconnected after admission; continuing with stored input state",
                            setup.protocol_index
                        );
                    }
                    Err(error) => {
                        return Err(format!(
                            "Failed to init AVSS InputServer for client protocol index {}: {error:?}",
                            setup.protocol_index
                        ));
                    }
                }
            }
        }

        // Every admitted client receives INST, including output-only clients.
        eprintln!(
            "[party {my_id}] Sending INST to {} clients...",
            client_bindings.len()
        );
        send_client_instances(&control_network, my_id, instance_id, client_bindings).await?;

        if !input_setup_plan.is_empty() {
            eprintln!(
                "[party {}] Waiting for all AVSS client inputs (timeout={}s)...",
                my_id,
                honeybadger_protocol_timeout().as_secs()
            );
            // Processing masked-input frames also needs the engine node mutex.
            // AvssInputServer clones share their watch/RBC state, so wait on a
            // clone after releasing the node guard.
            let mut input_server = {
                let node = engine.node_handle().lock().await;
                node.input_server.clone()
            };
            let client_inputs = input_server
                .wait_for_all_inputs(honeybadger_protocol_timeout())
                .await
                .map_err(|e| format!("Failed to receive AVSS client inputs: {e:?}"))?;

            for (protocol_index, shares) in client_inputs {
                let binding = client_bindings
                    .iter()
                    .find(|binding| binding.protocol_index == protocol_index)
                    .ok_or_else(|| {
                        format!(
                            "AVSS InputServer returned unknown client protocol index {protocol_index}"
                        )
                    })?;
                if binding.protocol_index != protocol_index
                    || !input_setup_plan
                        .iter()
                        .any(|setup| setup.protocol_index == protocol_index)
                {
                    return Err(format!(
                        "AVSS InputServer returned uninitialized client protocol index {protocol_index}"
                    ));
                }
                if let Some(share_types) = client_input_types.get(&binding.manifest_slot) {
                    vm.try_store_client_input_feldman_with_types(
                        binding.manifest_slot,
                        shares,
                        share_types,
                    )?;
                } else {
                    vm.try_store_client_input_feldman(binding.manifest_slot, shares)?;
                }
                eprintln!(
                    "[party {}] Stored AVSS inputs for protocol index {} in manifest slot {} (client {})",
                    my_id, protocol_index, binding.manifest_slot, binding.route_id
                );
            }
        }
    }

    Ok(engine)
}
#[allow(clippy::too_many_arguments)]
async fn run_avss_coordinated_party_for_curve<F, G>(
    vm: &mut VirtualMachine,
    net: Arc<QuicNetworkManager>,
    my_id: usize,
    n: usize,
    t: usize,
    instance_id: u64,
    execution_id: ExecutionId,
    coord_addr: (String, u16),
    rpc_addr: (String, u16),
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    expected_clients: &[String],
    client_input_total: Option<usize>,
    client_input_count: usize,
    client_roster: &[usize],
    client_input_slots: &[usize],
    client_input_types: &std::collections::BTreeMap<usize, Vec<ShareType>>,
    preprocessing_demand: stoffel_vm_types::compiled_binary::PreprocessingDemand,
    program_hash: [u8; 32],
    preproc_store: Option<Arc<dyn PreprocStore>>,
    as_leader: bool,
    one_off: bool,
    agreed_entry: &str,
) -> Result<(), String>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    let coordinator_execution_id = coordinator_execution_id(execution_id);
    let input_ids: Vec<Vec<u8>> = expected_clients
        .iter()
        .map(|path| extract_pubkey_from_cert(&fs::read(path).expect("read client cert")))
        .collect();
    let client_input_slots_by_id = input_client_slot_map_from_output_ids(
        &input_ids,
        client_roster,
        client_input_slots,
        client_input_count,
    )?;
    let client_input_total =
        client_input_total.unwrap_or_else(|| input_ids.len().saturating_mul(client_input_count));
    let (mux, execution_inbox, _execution_registration, _execution_scanner) =
        start_party_execution_transport(&net, execution_id)
            .map_err(|error| format!("Failed to start AVSS execution transport: {error}"))?;
    let coord: AvssOffChainCoordinator<F, G> =
        AvssOffChainCoordinator::<F, G>::start_rpc_client_for_execution(
            &coord_addr.0,
            coord_addr.1,
            t as u64,
            n as u64,
            2,
            coordinator_execution_id,
            cert_der.clone(),
            key_der.clone(),
        )
        .await
        .map_err(|error| format!("Failed to connect to AVSS off-chain coordinator: {error}"))?;

    local_bind_handoff("STOFFEL_LOCAL_RPC_HANDOFF").await;
    let node_rpc: OffChainNodeRPCServer = OffChainNodeRPCServer::start_for_execution(
        &rpc_addr.0,
        rpc_addr.1,
        coordinator_execution_id,
        cert_der.clone(),
        key_der.clone(),
    )
    .await
    .map_err(|error| format!("Failed to start AVSS node RPC server: {error}"))?;
    write_local_runner_marker_or_exit(
        "STOFFEL_LOCAL_RPC_READY_FILE",
        "party RPC listener readiness",
    );

    eprintln!("[party {my_id}] proposing Preprocessing");
    coord
        .start_preprocessing()
        .await
        .map_err(|e| e.to_string())?;

    let engine = setup_avss_party_for_curve::<F, G>(
        vm,
        PartySetup {
            net,
            reply_mux: mux,
            execution_id,
            execution_inbox,
            my_id,
            identity: durable_identity_from_cert(&cert_der),
            n,
            t,
            instance_id,
            expected_client_count: None,
            expected_client_bindings: None,
            expected_client_reservation_identities: None,
            client_count_hint: input_ids.len(),
            client_input_count,
            client_input_types,
            preprocessing_demand,
            program_hash,
            preproc_store,
            preprocessing: PartyPreprocessing::OneShot,
            execution_tasks: None,
        },
    )
    .await?;
    engine.enable_client_output_capture().await;

    // expected_clients includes output-only identities. Use the declared
    // input bindings, not the output roster, to decide whether to collect masks.
    if client_input_total == 0 {
        if !client_input_slots_by_id.is_empty() {
            return Err("AVSS coordinator has input clients but no declared inputs".to_string());
        }
        eprintln!(
            "[party {}] AVSS coordinator mode has no client inputs; preprocessing complete, skipping input collection",
            my_id
        );
    } else {
        if client_input_slots_by_id.is_empty() {
            return Err(format!(
                "AVSS coordinator declared {client_input_total} inputs without any input client identities"
            ));
        }
        let mask_shares = {
            let node = engine.node_handle().lock().await;
            let local_shares = node
                .preprocessing_material
                .lock()
                .await
                .take_v_random_shares(client_input_total)
                .map_err(|e| {
                    format!(
                        "Not enough AVSS random shares for {client_input_total} client inputs: {e:?}"
                    )
                })?;
            local_shares
        };
        let mask_share_pairs: Vec<(u64, &_)> = mask_shares
            .iter()
            .enumerate()
            .map(|(idx, share)| (idx as u64, share))
            .collect();
        node_rpc
            .add_mask_shares_for_execution(coordinator_execution_id, &mask_share_pairs)
            .await
            .map_err(|e| format!("add_mask_shares: {:?}", e))?;

        eprintln!("[party {my_id}] proposing InputMaskReservation");
        coord
            .reserve_input_masks()
            .await
            .map_err(|e| e.to_string())?;
        coord
            .wait_for_round(Round::InputMaskReservation)
            .await
            .map_err(|e| e.to_string())?;

        let client_to_indices = normalize_client_to_indices(
            coord
                .wait_for_indices(client_input_total as u64)
                .await
                .map_err(|e| e.to_string())?,
        );

        node_rpc
            .add_assigned_reserved_indices_for_execution(
                coordinator_execution_id,
                sorted_assigned_mask_reservations(&client_to_indices),
            )
            .await
            .or_else(|error| match error {
                NodeRPCError::JSONError => {
                    eprintln!(
                        "[party {my_id}] AVSS reserved-index batch observed a stale client sink; continuing"
                    );
                    Ok(())
                }
                other => Err(format!("add AVSS reserved-index batch: {other:?}")),
            })?;

        eprintln!("[party {my_id}] proposing InputCollection");
        coord.collect_inputs().await.map_err(|e| e.to_string())?;
        coord
            .wait_for_round(Round::InputCollection)
            .await
            .map_err(|e| e.to_string())?;

        let client_inputs = coord
            .wait_for_inputs(client_input_total as u64, mask_shares)
            .await
            .map_err(|e| e.to_string())?;
        store_reserved_client_inputs_feldman::<F, G, _>(
            vm,
            &client_to_indices,
            client_inputs,
            client_input_count,
            &client_input_slots_by_id,
            client_input_types,
        );
    }

    eprintln!("[party {my_id}] proposing MPCExecution");
    coord.start_mpc().await.map_err(|e| e.to_string())?;
    coord
        .wait_for_round(Round::MPCExecution)
        .await
        .map_err(|e| e.to_string())?;

    eprintln!("Starting VM execution of '{}'...", agreed_entry);
    let (result, cooperative_metrics) = vm
        .execute_async_with_metrics(agreed_entry, engine.as_ref())
        .await
        .map_err(|err| format!("Execution error in '{}': {}", agreed_entry, err))?;
    eprintln!(
        "[party {my_id}] cooperative VM execution: instruction_budget_yields={} online_effect_yields={}",
        cooperative_metrics.instruction_budget_yields, cooperative_metrics.online_effect_yields,
    );

    let captured_outputs = engine.drain_client_output_records().await;
    if !captured_outputs.is_empty() {
        eprintln!("[party {my_id}] proposing OutputDistribution");
        coord.send_output().await.map_err(|e| e.to_string())?;
        coord
            .wait_for_round(Round::OutputDistribution)
            .await
            .map_err(|e| e.to_string())?;

        let outputs_by_client = group_output_shares_by_client(
            captured_outputs
                .into_iter()
                .map(|record| (record.client_id, record.shares)),
        );
        let mut submissions = Vec::with_capacity(outputs_by_client.len());
        for (client_id, shares) in outputs_by_client {
            let client_key = input_ids.get(client_id).ok_or_else(|| {
                format!(
                    "AVSS output client index {} has no matching coordinator client identity",
                    client_id
                )
            })?;
            submissions.push((client_key.clone(), shares));
        }
        for (_, result) in send_output_shares_bounded(&coord, submissions).await {
            result.map_err(|e| format!("send_output_shares: {e}"))?;
        }
    }

    eprintln!("[party {my_id}] proposing ProgramFinished");
    eprintln!("[party {my_id}] finalizing coordinated execution");
    finish_avss_execution(&coord).await?;

    // Arm one-off shutdown before this party retires. The coordinator keeps serving terminal
    // round replays until every party retires, then exits immediately; a bounded server-side grace
    // period still guarantees shutdown if a faulty party never acknowledges.
    if as_leader && one_off {
        if let Err(e) = coord.request_shutdown().await {
            eprintln!(
                "Warning: failed to request off-chain coordinator shutdown: {}",
                e
            );
        }
    }
    if one_off {
        coord
            .retire_execution()
            .await
            .map_err(|e| format!("retire AVSS coordinator execution: {e}"))?;
    }

    #[cfg(feature = "statistics")]
    {
        let node = engine.node_handle().lock().await;
        eprintln!("AVSS statistics:\n{}", node.statistics_snapshot());
    }

    print_vm_result(vm, result);
    write_local_runner_marker_or_exit(
        "STOFFEL_LOCAL_COMPLETION_FILE",
        "coordinated execution completion",
    );
    Ok(())
}
#[allow(clippy::too_many_arguments)]
async fn run_avss_coordinated_party(
    curve_config: MpcCurveConfig,
    vm: &mut VirtualMachine,
    net: Arc<QuicNetworkManager>,
    my_id: usize,
    n: usize,
    t: usize,
    instance_id: u64,
    execution_id: ExecutionId,
    coord_addr: (String, u16),
    rpc_addr: (String, u16),
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    expected_clients: &[String],
    client_input_total: Option<usize>,
    client_input_count: usize,
    client_roster: &[usize],
    client_input_slots: &[usize],
    client_input_types: &std::collections::BTreeMap<usize, Vec<ShareType>>,
    preprocessing_demand: stoffel_vm_types::compiled_binary::PreprocessingDemand,
    program_hash: [u8; 32],
    preproc_store: Option<Arc<dyn PreprocStore>>,
    as_leader: bool,
    one_off: bool,
    agreed_entry: &str,
) -> Result<(), String> {
    macro_rules! run {
        ($F:ty, $G:ty) => {
            run_avss_coordinated_party_for_curve::<$F, $G>(
                vm,
                net,
                my_id,
                n,
                t,
                instance_id,
                execution_id,
                coord_addr,
                rpc_addr,
                cert_der,
                key_der,
                expected_clients,
                client_input_total,
                client_input_count,
                client_roster,
                client_input_slots,
                client_input_types,
                preprocessing_demand,
                program_hash,
                preproc_store,
                as_leader,
                one_off,
                agreed_entry,
            )
            .await
        };
    }
    dispatch_avss_curve!(curve_config, run)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReservoirAllocationSnapshot {
    /// Commits the complete frozen standing admission, including the ordered
    /// certificate identity/manifest-slot roster, before any material moves.
    admission_config_digest: [u8; 32],
    requested: PoolAvailability,
    inventory: StandingPreprocSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct ReservoirAllocationCommit {
    allocation_digest: [u8; 32],
    allocated: PoolAvailability,
    remaining: PoolAvailability,
}

fn validate_reservoir_allocation_admission(
    local: &ReservoirAllocationSnapshot,
    snapshots: &[ReservoirAllocationSnapshot],
) -> Result<(), String> {
    if let Some((party_id, peer)) = snapshots
        .iter()
        .enumerate()
        .find(|(_, peer)| peer.admission_config_digest != local.admission_config_digest)
    {
        return Err(format!(
            "party {party_id} has divergent frozen standing admission: local config digest={}, remote config digest={}",
            hex::encode(local.admission_config_digest),
            hex::encode(peer.admission_config_digest),
        ));
    }
    Ok(())
}

struct StandingReservoirState {
    program: Arc<StandingProgram>,
    per_execution: PoolAvailability,
    material_capacity: usize,
    lane: Arc<tokio::sync::Mutex<()>>,
}

fn standing_execution_id(
    domain: &[u8],
    pool_id: ExecutionId,
    program_id: [u8; 32],
    trigger: &[u8],
) -> ExecutionId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(pool_id.as_bytes());
    hasher.update(&program_id);
    hasher.update(trigger);
    let mut bytes = *hasher.finalize().as_bytes();
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[0] = 1;
    }
    ExecutionId::from_bytes(bytes)
}

fn standing_reservoir_warm_execution_id(pool_id: ExecutionId, program_id: [u8; 32]) -> ExecutionId {
    standing_execution_id(
        b"stoffel-standing-reservoir-warm-v2",
        pool_id,
        program_id,
        &[],
    )
}

/// LMDB reservoir namespace. Pool IDs must be globally unique among live
/// deployments; a preprocessing volume must never be cloned into another live
/// pool because both would otherwise own copies of the same correlated data.
fn standing_preproc_pool_program_id(pool_id: ExecutionId, real_program_id: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"stoffel-standing-preproc-pool-v1");
    hasher.update(pool_id.as_bytes());
    hasher.update(&real_program_id);
    *hasher.finalize().as_bytes()
}

fn standing_reservoir_refill_execution_id(
    pool_id: ExecutionId,
    program_id: [u8; 32],
    trigger_execution_id: ExecutionId,
) -> ExecutionId {
    standing_execution_id(
        b"stoffel-standing-reservoir-refill-v3",
        pool_id,
        program_id,
        trigger_execution_id.as_bytes(),
    )
}

fn standing_reservoir_plan(
    manifest: &ClientIoManifest,
    threshold: usize,
    burst_capacity: usize,
) -> Result<(PlannedPreprocessing, PlannedPreprocessing, usize), String> {
    let client_input_total =
        checked_client_input_total(manifest.clients.iter().map(|client| client.inputs.len()))?;
    let per_execution = plan_preprocessing(
        &manifest.preprocessing_demand,
        threshold,
        client_input_total,
    );
    let material_capacity = burst_capacity
        .checked_add(1)
        .ok_or_else(|| "standing reservoir burst capacity overflows usize".to_owned())?;
    let high = per_execution.checked_scale(material_capacity)?;
    Ok((per_execution, high, material_capacity))
}

fn availability_reached_refill_threshold(
    actual: PoolAvailability,
    per_execution: PoolAvailability,
) -> bool {
    (per_execution.beaver > 0 && actual.beaver <= per_execution.beaver)
        || (per_execution.random > 0 && actual.random <= per_execution.random)
        || (per_execution.prand_bit > 0 && actual.prand_bit <= per_execution.prand_bit)
        || (per_execution.prand_int > 0 && actual.prand_int <= per_execution.prand_int)
}

struct StandingRunnerExecutionHandler {
    network: Arc<QuicNetworkManager>,
    mux: ExecutionTransportMux,
    local_store: Option<RedbLocalStorage>,
    preproc_store: Arc<dyn PreprocStore>,
    persistent_identity: DurableIdentityDigest,
    party_id: usize,
    parties: usize,
    threshold: usize,
    pool_id: ExecutionId,
    coordinator_addr: (String, u16),
    coordinator_cert_der: Vec<u8>,
    coordinator_key_der: Vec<u8>,
    node_rpc: Arc<OffChainNodeRPCServer>,
    reservoirs: BTreeMap<[u8; 32], Arc<StandingReservoirState>>,
    reservoir_cancellation: CancellationToken,
}

struct StandingPreparedExecution {
    handler: Arc<StandingRunnerExecutionHandler>,
    admission: Arc<ResolvedStandingExecutionAdmissionV1>,
    reservoir: Arc<StandingReservoirState>,
    context: NodeExecutionContext,
    execution_inbox: Option<ExecutionInbox>,
    execution_registration: Option<ExecutionInboxRegistrationGuard>,
    execution_tasks: ExecutionTaskGroup,
    preprocessing_bundle: Option<OwnedPreprocBundle>,
}

#[async_trait::async_trait]
impl PreparedNodeExecution for StandingPreparedExecution {
    async fn execute(&mut self) -> Result<VmCooperativeExecutionMetrics, String> {
        eprintln!(
            "[party {}][execution {}] starting online execution",
            self.handler.party_id, self.context.spec.execution_id,
        );
        let execution_inbox = self.execution_inbox.take().ok_or_else(|| {
            format!(
                "online execution inbox for {} was already consumed",
                self.context.spec.execution_id
            )
        })?;
        let preprocessing_bundle = self.preprocessing_bundle.take().ok_or_else(|| {
            format!(
                "owned preprocessing bundle for {} was already consumed",
                self.context.spec.execution_id
            )
        })?;
        tokio::select! {
            biased;
            _ = self.context.cancellation.cancelled() => Err("execution cancelled".to_owned()),
            result = self.handler.execute_inner(
                &self.admission,
                &self.reservoir.program,
                &self.context,
                execution_inbox,
                &self.execution_tasks,
                preprocessing_bundle,
            ) => result,
        }
    }

    async fn cleanup(&mut self) -> Result<(), String> {
        // Close ingress before retiring the execution's persistent scopes.
        self.execution_inbox.take();
        self.execution_registration.take();
        // Dropping this single-owner value burns already-destructively-allocated
        // correlated material if execution was cancelled before activation.
        self.preprocessing_bundle.take();
        self.execution_tasks.shutdown().await;
        self.handler
            .cleanup_execution_resources(&self.context)
            .await
    }
}

impl StandingRunnerExecutionHandler {
    fn coordinator_registration(
        &self,
        admission: &ResolvedStandingExecutionAdmissionV1,
        program: &StandingProgram,
    ) -> Result<ExecutionRegistration, String> {
        let schemas = program
            .client_io_manifest
            .clients
            .iter()
            .map(|schema| (schema.client_slot, schema))
            .collect::<BTreeMap<_, _>>();
        let mut input_clients = Vec::new();
        let mut input_ranges = Vec::new();
        let mut n_inputs: u64 = 0;
        let mut output_clients = Vec::new();
        for (client, public_key) in admission
            .clients
            .iter()
            .zip(&admission.expected_client_public_keys)
        {
            let manifest_slot = u64::try_from(client.manifest_slot)
                .map_err(|_| "standing client manifest slot exceeds u64".to_owned())?;
            let schema = schemas.get(&manifest_slot).ok_or_else(|| {
                format!(
                    "standing client slot {} is absent from the program manifest",
                    client.manifest_slot
                )
            })?;
            if !schema.outputs.is_empty() {
                output_clients.push(public_key.clone());
            }
            if schema.inputs.is_empty() {
                continue;
            }
            let count = u64::try_from(schema.inputs.len())
                .map_err(|_| "client input count exceeds u64".to_owned())?;
            n_inputs = n_inputs
                .checked_add(count)
                .ok_or_else(|| "coordinator input count exceeds u64".to_owned())?;
            let client_index = u32::try_from(input_clients.len())
                .map_err(|_| "coordinator input client count exceeds u32".to_owned())?;
            input_clients.push(public_key.clone());
            input_ranges.push(InputClientRange {
                client_index,
                count,
            });
        }
        let min_output_shares = match program.backend {
            MpcBackendKind::HoneyBadger => self
                .threshold
                .checked_mul(2)
                .and_then(|threshold| threshold.checked_add(1)),
            MpcBackendKind::Avss => self.threshold.checked_add(1),
        }
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| "coordinator output quorum overflows u64".to_owned())?;
        Ok(ExecutionRegistration {
            execution_id: coordinator_execution_id(admission.execution_id),
            program_hash: admission.program_id,
            n_inputs,
            output_clients,
            input_assignment: InputAssignment {
                clients: input_clients,
                ranges: input_ranges,
            },
            min_output_shares,
        })
    }

    async fn register_coordinator_execution(
        &self,
        admission: &ResolvedStandingExecutionAdmissionV1,
        program: &StandingProgram,
    ) -> Result<(), String> {
        let execution_id = coordinator_execution_id(admission.execution_id);
        let registration = self.coordinator_registration(admission, program)?;
        self.node_rpc
            .register_execution(execution_id)
            .await
            .map_err(|error| format!("register standing node RPC execution: {error}"))?;
        let coord =
            match HbOffChainCoordinator::<ark_bls12_381::Fr>::start_rpc_client_for_execution(
                &self.coordinator_addr.0,
                self.coordinator_addr.1,
                self.threshold as u64,
                self.parties as u64,
                0,
                execution_id,
                self.coordinator_cert_der.clone(),
                self.coordinator_key_der.clone(),
            )
            .await
            {
                Ok(coord) => coord,
                Err(error) => {
                    self.node_rpc.retire_execution(execution_id).await;
                    return Err(format!("connect to standing coordinator: {error}"));
                }
            };
        let result = coord
            .register_execution(registration)
            .await
            .map_err(|error| format!("register standing coordinator execution: {error}"));
        if result.is_err() {
            let _ = coord.retire_execution().await;
            self.node_rpc.retire_execution(execution_id).await;
        }
        result
    }

    fn expected_client_identities(
        &self,
        admission: &ResolvedStandingExecutionAdmissionV1,
    ) -> Arc<BTreeMap<ClientId, DurableIdentityDigest>> {
        Arc::new(
            admission
                .expected_client_certificate_identities
                .iter()
                .enumerate()
                .map(|(client_id, identity)| {
                    (
                        client_id,
                        DurableIdentityDigest::from_certificate_identity(*identity),
                    )
                })
                .collect(),
        )
    }

    fn expected_client_bindings(
        &self,
        admission: &ResolvedStandingExecutionAdmissionV1,
        program: &StandingProgram,
    ) -> Arc<Vec<ClientProtocolBinding>> {
        let output_only_slots = program
            .client_io_manifest
            .clients
            .iter()
            .filter_map(|schema| {
                if schema.inputs.is_empty() && !schema.outputs.is_empty() {
                    usize::try_from(schema.client_slot).ok()
                } else {
                    None
                }
            })
            .collect::<HashSet<_>>();
        Arc::new(
            admission
                .clients
                .iter()
                .enumerate()
                .filter(|(_, client)| output_only_slots.contains(&client.manifest_slot))
                .map(|(client_id, client)| ClientProtocolBinding {
                    protocol_index: client_id,
                    route_id: client_id,
                    manifest_slot: client.manifest_slot,
                })
                .collect(),
        )
    }

    async fn warm_reservoirs(
        &mut self,
        programs: impl IntoIterator<Item = Arc<StandingProgram>>,
        burst_capacity: usize,
    ) -> Result<(), String> {
        let mut programs = programs.into_iter().peekable();
        if programs.peek().is_none() {
            return Err(
                "standing node program catalog is empty; no preprocessing reservoirs can be warmed"
                    .to_owned(),
            );
        }
        for program in programs {
            let preproc_program_id =
                standing_preproc_pool_program_id(self.pool_id, program.program_id);
            let (per_execution_plan, high_plan, material_capacity) = standing_reservoir_plan(
                &program.client_io_manifest,
                self.threshold,
                burst_capacity,
            )?;
            let warm_execution_id =
                standing_reservoir_warm_execution_id(self.pool_id, program.program_id);
            let generation_id = self
                .warm_reservoir_program(&program, warm_execution_id, material_capacity)
                .await?;
            let source_scope = PreprocKeyScope::new(
                preproc_program_id,
                program.curve.field_kind(),
                self.parties,
                self.threshold,
                self.persistent_identity,
            );
            let availability = self
                .preproc_store
                .scope_availability(&source_scope)
                .await
                .map_err(String::from)?;
            let high_watermark = high_plan.availability()?;
            let per_execution = per_execution_plan.availability()?;
            if !availability.covers(high_watermark) {
                return Err(format!(
                    "standing reservoir {} did not reach high watermark: actual={availability:?}, required={high_watermark:?}",
                    hex::encode(program.program_id)
                ));
            }
            eprintln!(
                "[party {}] standing reservoir ready: program={} backend={} curve={} generation={} availability={:?} low={:?} high={:?}",
                self.party_id,
                hex::encode(program.program_id),
                program.backend.name(),
                program.curve.name(),
                hex::encode(generation_id),
                availability,
                per_execution,
                high_watermark,
            );
            self.reservoirs.insert(
                program.program_id,
                Arc::new(StandingReservoirState {
                    program,
                    per_execution,
                    material_capacity,
                    lane: Arc::new(tokio::sync::Mutex::new(())),
                }),
            );
        }
        Ok(())
    }

    fn spawn_synchronized_reservoir_refill(
        self: &Arc<Self>,
        state: Arc<StandingReservoirState>,
        lane: tokio::sync::OwnedMutexGuard<()>,
        trigger_execution_id: ExecutionId,
    ) {
        let refill_execution_id = standing_reservoir_refill_execution_id(
            self.pool_id,
            state.program.program_id,
            trigger_execution_id,
        );
        // Keep the program lane locked while the existing preprocessing engine
        // performs its all-party inventory agreement and top-up/rebuild. This
        // is the only refill protocol: there is no staging lane, promotion
        // transaction, retry journal, or second commit barrier. A failed refill
        // remains fail-closed; the next allocation observes the divergent
        // inventory and asks the engine to rebuild it.
        let handler = Arc::clone(self);
        tokio::spawn(async move {
            eprintln!(
                "[party {}] RESERVOIR_REFILL_STARTED program={}",
                handler.party_id,
                hex::encode(state.program.program_id),
            );
            let result = tokio::select! {
                _ = handler.reservoir_cancellation.cancelled() => {
                    Err("standing reservoir refill cancelled".to_owned())
                }
                result = handler.warm_reservoir_program(
                    &state.program,
                    refill_execution_id,
                    state.material_capacity,
                ) => result,
            };
            match result {
                Ok(generation_id) => {
                    eprintln!(
                        "[party {}] RESERVOIR_REFILL_COMPLETED program={} generation={}",
                        handler.party_id,
                        hex::encode(state.program.program_id),
                        hex::encode(&generation_id[..4]),
                    );
                }
                Err(error) => {
                    eprintln!(
                        "[party {}] RESERVOIR_REFILL_FAILED program={}: {error}",
                        handler.party_id,
                        hex::encode(state.program.program_id),
                    );
                }
            }
            drop(lane);
        });
    }
    async fn reserve_reservoir_bundle(
        self: &Arc<Self>,
        admission: &ResolvedStandingExecutionAdmissionV1,
        state: Arc<StandingReservoirState>,
        cancellation: &CancellationToken,
        exchange_rx: &mut mpsc::Receiver<ExecutionInboundMessage>,
    ) -> Result<OwnedPreprocBundle, String> {
        // Serializes allocation and refill decisions for this program. Every
        // party processes the immutable Prepare stream in the same order and
        // confirms the exact source snapshot before moving bytes.
        let lane = tokio::select! {
            _ = cancellation.cancelled() => {
                return Err("reservoir allocation cancelled before entering the program lane".to_owned());
            }
            lane = Arc::clone(&state.lane).lock_owned() => lane,
        };
        let preproc_program_id =
            standing_preproc_pool_program_id(self.pool_id, admission.program_id);
        let source = PreprocKeyScope::new(
            preproc_program_id,
            state.program.curve.field_kind(),
            self.parties,
            self.threshold,
            self.persistent_identity,
        );
        let snapshot = ReservoirAllocationSnapshot {
            admission_config_digest: admission.config_digest,
            requested: state.per_execution,
            inventory: standing_preproc_snapshot(self.preproc_store.as_ref(), source)
                .await
                .map_err(String::from)?,
        };
        let control_network =
            ExecutionScopedNetwork::for_party((*self.network).clone(), admission.execution_id)
                .map_err(|error| format!("create reservoir allocation transport: {error}"))?
                .with_reply_mux(self.mux.clone())
                .with_message_kind(ExecutionMessageKind::Control);
        // This marker is also the synchronization point used by the
        // production-shaped fault-injection harness. Emit it only after this
        // program's allocation lane and transport inbox are live, but before
        // waiting for any peer's snapshot.
        eprintln!(
            "[party {}] RESERVOIR_ALLOCATION_STARTED execution={}",
            self.party_id, admission.execution_id,
        );
        let (snapshots, allocation_digest) = preprocessing_transcript_exchange(
            &control_network,
            exchange_rx,
            admission.execution_id,
            self.party_id,
            self.parties,
            cancellation,
            execution_coordination_timeout(),
            PreprocessingExchangePhase::ReservoirAllocationSnapshot,
            &snapshot,
        )
        .await?;
        if let Err(error) = validate_reservoir_allocation_admission(&snapshot, &snapshots) {
            // A divergent admission is not an inventory failure. Fail closed
            // before allocate_from_reservoir and do not start the refill path,
            // which would otherwise mutate valid material in response to a
            // certificate-roster/configuration disagreement.
            return Err(format!(
                "standing admission diverged before reservoir allocation for program {} execution {}: {error}",
                hex::encode(admission.program_id),
                admission.execution_id,
            ));
        }
        if snapshots.iter().any(|peer| peer != &snapshot) {
            let error = format!(
                "standing reservoir diverged before allocation for program {} execution {}: local={snapshot:?}, parties={snapshots:?}",
                hex::encode(admission.program_id),
                admission.execution_id
            );
            self.spawn_synchronized_reservoir_refill(
                Arc::clone(&state),
                lane,
                admission.execution_id,
            );
            return Err(error);
        }
        let local_allocation = match self
            .preproc_store
            .take_bundle_from_reservoir(&source, state.per_execution)
            .await
        {
            Ok(bundle) if bundle.availability() == state.per_execution => Ok(bundle),
            Ok(bundle) => Err(format!(
                "reservoir allocation returned {:?}, expected {:?}",
                bundle.availability(),
                state.per_execution
            )),
            Err(error) => Err(error.to_string()),
        };
        if let Err(error) = &local_allocation {
            eprintln!(
                "[party {}][execution {}] local reservoir allocation failed before commit: {error}",
                self.party_id, admission.execution_id,
            );
        }
        // The remaining inventory is returned by the same LMDB transaction
        // that removed the bundle, so the commit needs no second store read.
        let remaining = local_allocation
            .as_ref()
            .map(|bundle| bundle.remaining)
            .unwrap_or_default();
        let commit = ReservoirAllocationCommit {
            allocation_digest,
            allocated: local_allocation
                .as_ref()
                .map(|bundle| bundle.availability())
                .unwrap_or_default(),
            remaining,
        };
        let commits = preprocessing_transcript_exchange(
            &control_network,
            exchange_rx,
            admission.execution_id,
            self.party_id,
            self.parties,
            cancellation,
            execution_coordination_timeout(),
            PreprocessingExchangePhase::ReservoirAllocationCommit,
            &commit,
        )
        .await
        .map(|(commits, _)| commits);
        let commit_failure = match &commits {
            Ok(commits) => commits.iter().any(|peer| {
                peer.allocation_digest != allocation_digest
                    || peer.allocated != state.per_execution
                    || peer.remaining != remaining
            }),
            Err(_) => true,
        };
        if commit_failure {
            let exchange_error = commits.err();
            self.spawn_synchronized_reservoir_refill(
                Arc::clone(&state),
                lane,
                admission.execution_id,
            );
            let error = exchange_error.unwrap_or_else(|| {
                format!(
                    "standing reservoir allocation commit failed on at least one party for execution {}",
                    admission.execution_id
                )
            });
            return Err(error);
        }
        let allocated = commit.allocated;
        let generation_id = snapshot
            .inventory
            .generation_id
            .expect("warmed reservoir has a generation marker");
        eprintln!(
            "[party {}][execution {}] reservoir allocation ready: program={} generation={} digest={} allocated={:?} remaining={:?} low={:?}",
            self.party_id,
            admission.execution_id,
            hex::encode(admission.program_id),
            hex::encode(&generation_id[..4]),
            hex::encode(allocation_digest),
            allocated,
            remaining,
            state.per_execution,
        );
        if availability_reached_refill_threshold(remaining, state.per_execution) {
            self.spawn_synchronized_reservoir_refill(
                Arc::clone(&state),
                lane,
                admission.execution_id,
            );
        }
        local_allocation
    }

    async fn warm_reservoir_program(
        &self,
        program: &StandingProgram,
        execution_id: ExecutionId,
        burst_capacity: usize,
    ) -> Result<[u8; 32], String> {
        let preproc_program_id = standing_preproc_pool_program_id(self.pool_id, program.program_id);
        let instance_id = stoffel_vm::net::session::derive_instance_id_for_execution(&execution_id);
        let execution_inbox = self
            .mux
            .register_with_client_identities(execution_id, Vec::new())
            .map_err(|error| format!("register reservoir transport: {error}"))?;
        let registration = ExecutionInboxRegistrationGuard::new(self.mux.clone(), execution_id);
        let mut vm = VirtualMachine::builder().build();
        let client_input_types = manifest_client_input_types(&program.client_io_manifest, None);
        let execution_tasks = ExecutionTaskGroup::child_of(&self.reservoir_cancellation);
        let mut setup = Some(PartySetup {
            net: Arc::clone(&self.network),
            reply_mux: self.mux.clone(),
            execution_id,
            execution_inbox,
            my_id: self.party_id,
            identity: self.persistent_identity,
            n: self.parties,
            t: self.threshold,
            instance_id,
            expected_client_count: None,
            expected_client_bindings: None,
            expected_client_reservation_identities: None,
            client_count_hint: 0,
            client_input_count: 0,
            client_input_types: &client_input_types,
            preprocessing_demand: program.client_io_manifest.preprocessing_demand,
            program_hash: preproc_program_id,
            preproc_store: Some(Arc::clone(&self.preproc_store)),
            preprocessing: PartyPreprocessing::Reservoir { burst_capacity },
            execution_tasks: Some(&execution_tasks),
        });

        let result = async {
            match program.backend {
                MpcBackendKind::HoneyBadger => {
                    macro_rules! warm_hb {
                        ($F:ty, $G:ty) => {{
                            let engine = setup_hb_party_for_curve::<$F, $G>(
                                &mut vm,
                                setup.take().expect("reservoir setup is consumed once"),
                            )
                            .await?;
                            let snapshot = engine.standing_preproc_snapshot().await?;
                            let generation = snapshot.generation_id.ok_or_else(|| {
                                "HB reservoir completed without a generation marker".to_owned()
                            })?;
                            Ok::<[u8; 32], String>(generation)
                        }};
                    }
                    dispatch_hb_curve!(
                        program.curve,
                        warm_hb,
                        Err(format!(
                            "curve {} is not supported by HoneyBadger reservoir",
                            program.curve.name()
                        ))
                    )
                }
                MpcBackendKind::Avss => {
                    macro_rules! warm_avss {
                        ($F:ty, $G:ty) => {{
                            let engine = setup_avss_party_for_curve::<$F, $G>(
                                &mut vm,
                                setup.take().expect("reservoir setup is consumed once"),
                            )
                            .await?;
                            let snapshot = engine.standing_preproc_snapshot().await?;
                            let generation = snapshot.generation_id.ok_or_else(|| {
                                "AVSS reservoir completed without a generation marker".to_owned()
                            })?;
                            Ok::<[u8; 32], String>(generation)
                        }};
                    }
                    dispatch_avss_curve!(program.curve, warm_avss)
                }
            }
        }
        .await;
        drop(registration);
        execution_tasks.shutdown().await;
        result
    }

    async fn cleanup_execution_resources(
        &self,
        context: &NodeExecutionContext,
    ) -> Result<(), String> {
        let execution_id = coordinator_execution_id(context.spec.execution_id);
        self.node_rpc.retire_execution(execution_id).await;
        let coordinator_cleanup =
            match HbOffChainCoordinator::<ark_bls12_381::Fr>::start_rpc_client_for_execution(
                &self.coordinator_addr.0,
                self.coordinator_addr.1,
                self.threshold as u64,
                self.parties as u64,
                0,
                execution_id,
                self.coordinator_cert_der.clone(),
                self.coordinator_key_der.clone(),
            )
            .await
            {
                Ok(coordinator) => coordinator
                    .retire_execution()
                    .await
                    .map_err(|error| error.to_string())
                    .or_else(|error| {
                        coordinator_execution_already_retired(&error)
                            .then_some(())
                            .ok_or_else(|| format!("retire coordinator execution: {error}"))
                    }),
                Err(error) => Err(format!("connect for coordinator cleanup: {error}")),
            };

        // Preprocessing was already removed from LMDB into the execution's
        // owned in-memory bundle. Cleanup only retires local VM state; dropping
        // the bundle burns any unused correlated material.
        let Some(storage) = self.local_store.as_ref() else {
            return coordinator_cleanup;
        };
        let storage = storage.clone();
        let local_execution_id = context.spec.execution_id;
        tokio::task::spawn_blocking(move || {
            let mut namespace = storage.with_namespace(*local_execution_id.as_bytes());
            namespace.clear().map_err(String::from)
        })
        .await
        .map_err(|error| format!("Redb cleanup worker failed: {error}"))??;
        coordinator_cleanup
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_hb_standing<F, G>(
        &self,
        vm: &mut VirtualMachine,
        engine: Arc<HoneyBadgerMpcEngine<F, G>>,
        admission: &ResolvedStandingExecutionAdmissionV1,
        program: &StandingProgram,
        client_input_types: &BTreeMap<usize, Vec<ShareType>>,
        client_input_count: usize,
    ) -> Result<VmCooperativeExecutionMetrics, String>
    where
        F: SupportedMpcField,
        G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
    {
        // Installing the MPC engine clears engine-scoped VM state, including
        // ClientStore. Restore the admitted roster only after setup so
        // output-only clients remain visible to the Stoffel program.
        if !admission.clients.is_empty() {
            vm.set_client_roster(admission.clients.iter().map(|client| client.manifest_slot));
        }
        let execution_id = coordinator_execution_id(admission.execution_id);
        let mut coord = HbOffChainCoordinator::<F>::start_rpc_client_for_execution(
            &self.coordinator_addr.0,
            self.coordinator_addr.1,
            self.threshold as u64,
            self.parties as u64,
            0,
            execution_id,
            self.coordinator_cert_der.clone(),
            self.coordinator_key_der.clone(),
        )
        .await
        .map_err(|error| format!("connect to standing coordinator: {error}"))?;
        // Input collection uses long-lived subscriptions. Keep the subsequent
        // phase-control RPCs and subscriptions on a clean WebSocket so dropping
        // the input stream cannot head-of-line block the MPC transition.
        let lifecycle_coord = HbOffChainCoordinator::<F>::start_rpc_client_for_execution(
            &self.coordinator_addr.0,
            self.coordinator_addr.1,
            self.threshold as u64,
            self.parties as u64,
            0,
            execution_id,
            self.coordinator_cert_der.clone(),
            self.coordinator_key_der.clone(),
        )
        .await
        .map_err(|error| format!("connect to standing lifecycle coordinator: {error}"))?;
        eprintln!("[party {}] proposing Preprocessing", self.party_id);
        coord
            .start_preprocessing()
            .await
            .map_err(|error| error.to_string())?;
        coord
            .wait_for_round(Round::Preprocessing)
            .await
            .map_err(|error| error.to_string())?;

        engine.enable_client_output_capture().await;
        let input_total = self.coordinator_registration(admission, program)?.n_inputs as usize;
        let client_roster = admission
            .clients
            .iter()
            .map(|client| client.manifest_slot)
            .collect::<Vec<_>>();
        let client_input_slots = manifest_client_input_slots(client_input_types);
        let input_client_ids = input_client_ids_from_output_ids(
            &admission.expected_client_public_keys,
            &client_roster,
            &client_input_slots,
            client_input_count,
        );
        let client_input_slots_by_id = input_client_slot_map_from_output_ids(
            &admission.expected_client_public_keys,
            &client_roster,
            &client_input_slots,
            client_input_count,
        )?;
        collect_hb_coordinator_inputs(
            vm,
            &engine,
            &mut coord,
            self.node_rpc.as_ref(),
            execution_id,
            &input_client_ids,
            &client_input_slots_by_id,
            Some(input_total),
            client_input_count,
            client_input_types,
            standing_preproc_pool_program_id(self.pool_id, admission.program_id),
            0,
            self.party_id,
        )
        .await?;

        eprintln!("[party {}] proposing MPCExecution", self.party_id);
        lifecycle_coord
            .start_mpc()
            .await
            .map_err(|error| error.to_string())?;
        lifecycle_coord
            .wait_for_round(Round::MPCExecution)
            .await
            .map_err(|error| error.to_string())?;
        let (result, metrics) = vm
            .execute_async_with_metrics(&admission.entry, engine.as_ref())
            .await
            .map_err(|error| format!("VM execution failed: {error}"))?;

        let outputs_by_client = group_output_shares_by_client(
            engine
                .drain_client_output_records()
                .await
                .into_iter()
                .map(|record| (record.client_id, record.shares)),
        );
        if !outputs_by_client.is_empty() {
            eprintln!("[party {}] proposing OutputDistribution", self.party_id);
            lifecycle_coord
                .send_output()
                .await
                .map_err(|error| error.to_string())?;
            lifecycle_coord
                .wait_for_round(Round::OutputDistribution)
                .await
                .map_err(|error| error.to_string())?;
        }
        let mut submissions = Vec::with_capacity(outputs_by_client.len());
        for (client_id, shares) in outputs_by_client {
            let client_key = standing_client_key(admission, client_id).ok_or_else(|| {
                format!(
                    "HoneyBadger output client slot {} is absent from the admission",
                    client_id
                )
            })?;
            submissions.push((client_key.clone(), shares));
        }
        for (_, result) in send_output_shares_bounded(&lifecycle_coord, submissions).await {
            result.map_err(|error| format!("send HoneyBadger output shares: {error}"))?;
        }
        eprintln!("[party {}] proposing ProgramFinished", self.party_id);
        finish_hb_execution(&lifecycle_coord).await?;
        print_vm_result(vm, result);
        Ok(metrics)
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_avss_standing<F, G>(
        &self,
        vm: &mut VirtualMachine,
        engine: Arc<stoffel_vm::net::avss_engine::AvssMpcEngine<F, G>>,
        admission: &ResolvedStandingExecutionAdmissionV1,
        program: &StandingProgram,
        client_input_types: &BTreeMap<usize, Vec<ShareType>>,
        client_input_count: usize,
    ) -> Result<VmCooperativeExecutionMetrics, String>
    where
        F: SupportedMpcField,
        G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
    {
        // Installing the MPC engine clears engine-scoped VM state, including
        // ClientStore. Restore the admitted roster only after setup so
        // output-only clients remain visible to the Stoffel program.
        if !admission.clients.is_empty() {
            vm.set_client_roster(admission.clients.iter().map(|client| client.manifest_slot));
        }
        let execution_id = coordinator_execution_id(admission.execution_id);
        let coord = AvssOffChainCoordinator::<F, G>::start_rpc_client_for_execution(
            &self.coordinator_addr.0,
            self.coordinator_addr.1,
            self.threshold as u64,
            self.parties as u64,
            0,
            execution_id,
            self.coordinator_cert_der.clone(),
            self.coordinator_key_der.clone(),
        )
        .await
        .map_err(|error| format!("connect to standing coordinator: {error}"))?;
        // Input collection uses long-lived subscriptions. Keep the subsequent
        // phase-control RPCs and subscriptions on a clean WebSocket so dropping
        // the input stream cannot head-of-line block the MPC transition.
        let lifecycle_coord = AvssOffChainCoordinator::<F, G>::start_rpc_client_for_execution(
            &self.coordinator_addr.0,
            self.coordinator_addr.1,
            self.threshold as u64,
            self.parties as u64,
            0,
            execution_id,
            self.coordinator_cert_der.clone(),
            self.coordinator_key_der.clone(),
        )
        .await
        .map_err(|error| format!("connect to standing lifecycle coordinator: {error}"))?;
        eprintln!("[party {}] proposing Preprocessing", self.party_id);
        coord
            .start_preprocessing()
            .await
            .map_err(|error| error.to_string())?;
        coord
            .wait_for_round(Round::Preprocessing)
            .await
            .map_err(|error| error.to_string())?;

        engine.enable_client_output_capture().await;
        let input_total = self.coordinator_registration(admission, program)?.n_inputs as usize;
        let client_input_slots = manifest_client_input_slots(client_input_types);
        let client_roster = admission
            .clients
            .iter()
            .map(|client| client.manifest_slot)
            .collect::<Vec<_>>();
        let client_input_slots_by_id = input_client_slot_map_from_output_ids(
            &admission.expected_client_public_keys,
            &client_roster,
            &client_input_slots,
            client_input_count,
        )?;
        if input_total > 0 {
            let mask_shares = {
                let node = engine.node_handle().lock().await;
                let shares = node
                    .preprocessing_material
                    .lock()
                    .await
                    .take_v_random_shares(input_total)
                    .map_err(|error| {
                        format!(
                            "not enough AVSS random shares for {input_total} client inputs: {error:?}"
                        )
                    })?;
                shares
            };
            eprintln!("[party {}] proposing InputMaskReservation", self.party_id);
            coord
                .reserve_input_masks()
                .await
                .map_err(|error| error.to_string())?;
            coord
                .wait_for_round(Round::InputMaskReservation)
                .await
                .map_err(|error| error.to_string())?;
            let client_to_indices = normalize_client_to_indices(
                coord
                    .wait_for_indices(input_total as u64)
                    .await
                    .map_err(|error| error.to_string())?,
            );
            self.node_rpc
                .add_assigned_reserved_indices_for_execution(
                    execution_id,
                    sorted_assigned_mask_reservations(&client_to_indices),
                )
                .await
                .map_err(|error| format!("add AVSS reserved-index batch: {error:?}"))?;
            let mask_share_pairs: Vec<(u64, &_)> = mask_shares
                .iter()
                .enumerate()
                .map(|(index, share)| (index as u64, share))
                .collect();
            self.node_rpc
                .add_mask_shares_for_execution(execution_id, &mask_share_pairs)
                .await
                .map_err(|error| format!("add AVSS mask shares: {error:?}"))?;
            eprintln!("[party {}] proposing InputCollection", self.party_id);
            coord
                .collect_inputs()
                .await
                .map_err(|error| error.to_string())?;
            coord
                .wait_for_round(Round::InputCollection)
                .await
                .map_err(|error| error.to_string())?;
            let client_inputs = coord
                .wait_for_inputs(input_total as u64, mask_shares)
                .await
                .map_err(|error| error.to_string())?;
            store_reserved_client_inputs_feldman::<F, G, _>(
                vm,
                &client_to_indices,
                client_inputs,
                client_input_count,
                &client_input_slots_by_id,
                client_input_types,
            );
        }

        eprintln!("[party {}] proposing MPCExecution", self.party_id);
        lifecycle_coord
            .start_mpc()
            .await
            .map_err(|error| error.to_string())?;
        lifecycle_coord
            .wait_for_round(Round::MPCExecution)
            .await
            .map_err(|error| error.to_string())?;
        let (result, metrics) = vm
            .execute_async_with_metrics(&admission.entry, engine.as_ref())
            .await
            .map_err(|error| format!("VM execution failed: {error}"))?;
        let outputs_by_client = group_output_shares_by_client(
            engine
                .drain_client_output_records()
                .await
                .into_iter()
                .map(|record| (record.client_id, record.shares)),
        );
        if !outputs_by_client.is_empty() {
            eprintln!("[party {}] proposing OutputDistribution", self.party_id);
            lifecycle_coord
                .send_output()
                .await
                .map_err(|error| error.to_string())?;
            lifecycle_coord
                .wait_for_round(Round::OutputDistribution)
                .await
                .map_err(|error| error.to_string())?;
        }
        let mut submissions = Vec::with_capacity(outputs_by_client.len());
        for (client_id, shares) in outputs_by_client {
            let client_key = standing_client_key(admission, client_id).ok_or_else(|| {
                format!(
                    "AVSS output client slot {} is absent from the admission",
                    client_id
                )
            })?;
            submissions.push((client_key.clone(), shares));
        }
        for (_, result) in send_output_shares_bounded(&lifecycle_coord, submissions).await {
            result.map_err(|error| format!("send AVSS output shares: {error}"))?;
        }
        eprintln!("[party {}] proposing ProgramFinished", self.party_id);
        finish_avss_execution(&lifecycle_coord).await?;
        print_vm_result(vm, result);
        Ok(metrics)
    }

    async fn execute_inner(
        &self,
        admission: &ResolvedStandingExecutionAdmissionV1,
        program: &StandingProgram,
        context: &NodeExecutionContext,
        execution_inbox: ExecutionInbox,
        execution_tasks: &ExecutionTaskGroup,
        preprocessing_bundle: OwnedPreprocBundle,
    ) -> Result<VmCooperativeExecutionMetrics, String> {
        let mut vm = load_standing_vm(
            &program.bytes,
            self.local_store
                .as_ref()
                .map(|storage| storage.with_namespace(*context.spec.execution_id.as_bytes())),
        )?;
        let client_input_types =
            manifest_client_input_types(&program.client_io_manifest, Some(admission.clients.len()));
        let manifest_client_input_count =
            client_input_types.values().map(Vec::len).max().unwrap_or(0);
        let execution_id = context.spec.execution_id;
        let instance_id =
            stoffel_vm::net::derive_instance_id_for_execution(&context.spec.execution_id);
        let preproc_program_id =
            standing_preproc_pool_program_id(self.pool_id, admission.program_id);
        let expected_client_bindings = self.expected_client_bindings(admission, program);
        let mut setup = Some(PartySetup {
            net: Arc::clone(&self.network),
            reply_mux: self.mux.clone(),
            execution_id,
            execution_inbox,
            my_id: self.party_id,
            identity: self.persistent_identity,
            n: self.parties,
            t: self.threshold,
            instance_id,
            expected_client_count: None,
            expected_client_bindings: Some(expected_client_bindings),
            expected_client_reservation_identities: Some(
                self.expected_client_identities(admission),
            ),
            client_count_hint: admission.clients.len(),
            client_input_count: manifest_client_input_count,
            client_input_types: &client_input_types,
            preprocessing_demand: program.client_io_manifest.preprocessing_demand,
            program_hash: preproc_program_id,
            preproc_store: Some(Arc::clone(&self.preproc_store)),
            preprocessing: PartyPreprocessing::Execution(preprocessing_bundle),
            execution_tasks: Some(execution_tasks),
        });
        let metrics = match program.backend {
            MpcBackendKind::HoneyBadger => {
                macro_rules! setup_hb_standing {
                    ($F:ty, $G:ty) => {{
                        let engine = setup_hb_party_for_curve::<$F, $G>(
                            &mut vm,
                            setup.take().expect("execution setup is consumed once"),
                        )
                        .await?;
                        self.execute_hb_standing(
                            &mut vm,
                            engine,
                            admission,
                            program,
                            &client_input_types,
                            manifest_client_input_count,
                        )
                        .await?
                    }};
                }
                dispatch_hb_curve!(program.curve, setup_hb_standing, {
                    return Err(format!(
                        "curve {} is not supported by HoneyBadger",
                        program.curve.name()
                    ));
                })
            }
            MpcBackendKind::Avss => {
                macro_rules! setup_avss_standing {
                    ($F:ty, $G:ty) => {{
                        let engine = setup_avss_party_for_curve::<$F, $G>(
                            &mut vm,
                            setup.take().expect("execution setup is consumed once"),
                        )
                        .await?;
                        self.execute_avss_standing(
                            &mut vm,
                            engine,
                            admission,
                            program,
                            &client_input_types,
                            manifest_client_input_count,
                        )
                        .await?
                    }};
                }
                dispatch_avss_curve!(program.curve, setup_avss_standing)
            }
        };
        eprintln!(
            "[party {}][execution {}] cooperative VM execution: instruction_budget_yields={} online_effect_yields={}",
            self.party_id,
            execution_id,
            metrics.instruction_budget_yields,
            metrics.online_effect_yields,
        );

        Ok(metrics)
    }
}

#[async_trait::async_trait]
impl StandingExecutionHandler for StandingRunnerExecutionHandler {
    async fn prepare(
        self: Arc<Self>,
        admission: ResolvedStandingExecutionAdmissionV1,
        context: NodeExecutionContext,
    ) -> Result<Box<dyn PreparedNodeExecution>, String> {
        let admission = Arc::new(admission);
        let reservoir = self
            .reservoirs
            .get(&admission.program_id)
            .cloned()
            .ok_or_else(|| {
                format!(
                    "program {} has no ready standing preprocessing reservoir",
                    hex::encode(admission.program_id)
                )
            })?;
        // Establish every fallible online resource before destructively moving
        // preprocessing material into the execution scope.
        let execution_inbox = self
            .mux
            .register_with_client_identities(
                context.spec.execution_id,
                admission.expected_client_certificate_identities.clone(),
            )
            .map_err(|error| format!("register prepared execution transport: {error}"))?;
        let execution_registration =
            ExecutionInboxRegistrationGuard::new(self.mux.clone(), context.spec.execution_id);
        let execution_tasks = ExecutionTaskGroup::child_of(&context.cancellation);
        let mut execution_inbox = execution_inbox;
        let preprocessing_bundle = self
            .reserve_reservoir_bundle(
                &admission,
                Arc::clone(&reservoir),
                &context.cancellation,
                &mut execution_inbox.control,
            )
            .await?;
        self.register_coordinator_execution(&admission, &reservoir.program)
            .await?;
        // Once allocation succeeds, always return an owned prepared value.
        // If cancellation raced with allocation, the supervisor takes its
        // cleanup path and burns the execution scope instead of leaking it.
        Ok(Box::new(StandingPreparedExecution {
            handler: self,
            admission,
            reservoir,
            context,
            execution_inbox: Some(execution_inbox),
            execution_registration: Some(execution_registration),
            execution_tasks,
            preprocessing_bundle: Some(preprocessing_bundle),
        }))
    }
}

fn load_standing_vm(
    program: &[u8],
    local_storage: Option<RedbLocalStorage>,
) -> Result<VirtualMachine, String> {
    let mut builder = VirtualMachine::builder();
    if let Some(storage) = local_storage {
        builder = builder.with_local_storage(storage);
    }
    let mut vm = builder.build();
    let (function_count, _, _) = CompiledBinary::try_for_each_resolved_vm_function_from_reader(
        &mut BufReader::new(program),
        |header, stream| {
            let mut stream_error = None;
            let result = vm.try_register_resolved_function_without_source(header, || match stream
                .next_instruction()
            {
                Ok(instruction) => instruction,
                Err(error) => {
                    stream_error = Some(error);
                    None
                }
            });
            if let Some(error) = stream_error {
                return Err(error);
            }
            result.map_err(|error| {
                BinaryError::InvalidData(format!("invalid VM function: {error}"))
            })?;
            Ok(())
        },
    )
    .map_err(|error| format!("invalid compiled program: {error:?}"))?;
    if function_count == 0 {
        return Err("compiled program contains no functions".to_owned());
    }
    vm.discard_vm_source_instructions();
    Ok(vm)
}

fn standing_flag_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

fn standing_required_flag(args: &[String], name: &str) -> Result<String, String> {
    standing_flag_value(args, name).ok_or_else(|| format!("{name} is required in standing mode"))
}

fn standing_host_port(args: &[String], name: &str) -> Result<(String, u16), String> {
    let value = standing_required_flag(args, name)?;
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| format!("{name} must be formatted as <host>:<port>"))?;
    if host.is_empty() {
        return Err(format!("{name} host must not be empty"));
    }
    let port = port
        .parse::<u16>()
        .map_err(|error| format!("invalid {name} port: {error}"))?;
    Ok((host.to_owned(), port))
}

fn load_standing_party_public_keys(
    directory: &Path,
    parties: usize,
) -> Result<Vec<(usize, NodePublicKey)>, String> {
    (0..parties)
        .map(|party_id| {
            let path = directory.join(format!("cert{party_id}.crt"));
            let cert_der = fs::read(&path).map_err(|error| {
                format!(
                    "read standing party certificate {}: {error}",
                    path.display()
                )
            })?;
            let public_key = QuicNetworkManager::public_key_from_certificate_der(&cert_der)
                .map_err(|error| {
                    format!(
                        "parse standing party certificate {}: {error}",
                        path.display()
                    )
                })?;
            Ok((party_id, public_key))
        })
        .collect()
}

async fn run_standing_node(raw_args: &[String]) -> Result<(), String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let party_id = standing_required_flag(raw_args, "--party-id")?
        .parse::<usize>()
        .map_err(|error| format!("invalid --party-id: {error}"))?;
    let parties = standing_required_flag(raw_args, "--n-parties")?
        .parse::<usize>()
        .map_err(|error| format!("invalid --n-parties: {error}"))?;
    let threshold = standing_flag_value(raw_args, "--threshold")
        .unwrap_or_else(|| "1".to_owned())
        .parse::<usize>()
        .map_err(|error| format!("invalid --threshold: {error}"))?;
    let pool_id = standing_required_flag(raw_args, "--pool-id")?
        .parse::<ExecutionId>()
        .map_err(|error| format!("invalid --pool-id: {error}"))?;
    if pool_id.is_zero() {
        return Err("--pool-id must be nonzero".to_owned());
    }
    MpcSessionTopology::try_new(
        stoffel_vm::net::derive_instance_id_for_execution(&pool_id),
        party_id,
        parties,
        threshold,
    )
    .map_err(|error| format!("invalid standing MPC topology: {error}"))?;
    let control_dir = PathBuf::from(standing_required_flag(raw_args, "--control-dir")?);
    let programs_dir = PathBuf::from(standing_required_flag(raw_args, "--program-dir")?);
    let client_cert_dir = PathBuf::from(standing_required_flag(raw_args, "--client-cert-dir")?);
    let party_cert_dir = PathBuf::from(standing_required_flag(raw_args, "--party-cert-dir")?);
    let program_catalog = Arc::new(
        if is_flag_present(raw_args, "--allow-dynamic-preprocessing") {
            StandingProgramCatalog::load_with_dynamic_preprocessing(&programs_dir)
        } else {
            StandingProgramCatalog::load(&programs_dir)
        }
        .map_err(|error| error.to_string())?,
    );
    let client_catalog =
        Arc::new(StandingClientCatalog::load(&client_cert_dir).map_err(|error| error.to_string())?);
    let bind = standing_required_flag(raw_args, "--bind")?
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid --bind: {error}"))?;
    let advertise = standing_flag_value(raw_args, "--advertise")
        .map(|value| value.parse::<SocketAddr>())
        .transpose()
        .map_err(|error| format!("invalid --advertise: {error}"))?;
    let cert_path = standing_required_flag(raw_args, "--cert")?;
    let key_path = standing_required_flag(raw_args, "--key")?;
    let cert_der = fs::read(&cert_path).map_err(|error| format!("read --cert: {error}"))?;
    let key_der = fs::read(&key_path).map_err(|error| format!("read --key: {error}"))?;
    let coordinator_addr = standing_host_port(raw_args, "--off-chain-coord")?;
    let node_rpc_bind = standing_required_flag(raw_args, "--rpc-bind")?
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid --rpc-bind: {error}"))?;
    let node_rpc = Arc::new(
        OffChainNodeRPCServer::start(
            &node_rpc_bind.ip().to_string(),
            node_rpc_bind.port(),
            cert_der.clone(),
            key_der.clone(),
        )
        .await
        .map_err(|error| format!("start standing node RPC listener: {error}"))?,
    );
    let party_public_keys = load_standing_party_public_keys(&party_cert_dir, parties)?;
    let local_public_key = QuicNetworkManager::public_key_from_certificate_der(&cert_der)
        .map_err(|error| format!("parse --cert: {error}"))?;
    if party_public_keys.get(party_id).map(|(_, key)| key) != Some(&local_public_key) {
        return Err(format!(
            "--cert does not match {}/cert{}.crt for logical party {}",
            party_cert_dir.display(),
            party_id,
            party_id
        ));
    }
    let persistent_identity = durable_identity_from_cert(&cert_der);
    let preproc_store: Arc<dyn PreprocStore> = Arc::new(
        LmdbPreprocStore::open(standing_required_flag(raw_args, "--preproc-store")?)
            .map_err(String::from)?,
    );
    let local_store = standing_flag_value(raw_args, "--local-store")
        .map(|path| {
            match fs::remove_file(&path) {
                Ok(()) => {
                    eprintln!("[party {party_id}] standing startup removed orphaned local VM state")
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("remove stale --local-store: {error}")),
            }
            RedbLocalStorage::new(path).map_err(|error| format!("open --local-store: {error}"))
        })
        .transpose()?;
    let reservoir_burst_capacity = standing_flag_value(raw_args, "--reservoir-burst-capacity")
        .unwrap_or_else(|| "9".to_owned())
        .parse::<usize>()
        .map_err(|error| format!("invalid --reservoir-burst-capacity: {error}"))?;
    if reservoir_burst_capacity == 0 {
        return Err("--reservoir-burst-capacity must be greater than zero".to_owned());
    }
    let as_leader = is_flag_present(raw_args, "--leader");

    let (bootnode, party_bind) = if as_leader {
        let bootnode = bind;
        tokio::spawn(async move {
            if let Err(error) = run_bootnode_with_config(bootnode, parties).await {
                eprintln!("standing bootnode failed: {error}");
            }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let party_bind = SocketAddr::new(bind.ip(), bind.port().saturating_add(1000));
        let connect = if bind.ip().is_unspecified() {
            SocketAddr::new("127.0.0.1".parse().unwrap(), bind.port())
        } else {
            bind
        };
        (connect, party_bind)
    } else {
        let bootnode = standing_required_flag(raw_args, "--bootstrap")?
            .parse::<SocketAddr>()
            .map_err(|error| format!("invalid --bootstrap: {error}"))?;
        (bootnode, bind)
    };

    let mut network = QuicNetworkManager::with_node_id(party_id);
    network
        .set_local_certificate_der(cert_der.clone(), key_der.clone())
        .map_err(|error| format!("configure node certificate: {error}"))?;
    network
        .install_expected_server_public_keys(
            party_public_keys
                .iter()
                .map(|(_, public_key)| public_key.clone()),
        )
        .map_err(|error| format!("configure standing party certificate roster: {error}"))?;
    network
        .listen(party_bind)
        .await
        .map_err(|error| format!("listen on {party_bind}: {error}"))?;
    let pool_program_id = program_id_from_bytes(b"stoffel-standing-physical-mesh-v1");
    let standing_session = register_and_wait_for_session(
        &mut network,
        SessionRegistrationConfig {
            execution_id: pool_id,
            bootnode,
            my_party_id: party_id,
            my_listen: advertise.unwrap_or(party_bind),
            program_id: pool_program_id,
            entry: "__standing_node_pool_v1".to_owned(),
            n_parties: parties,
            threshold,
            timeout: session_registration_timeout(),
            expected_party_public_keys: Some(party_public_keys.clone()),
        },
    )
    .await
    .map_err(|error| format!("standing mesh registration failed: {error}"))?;
    // Freeze and verify the party roster first; client identities extend the
    // process-wide TLS allowlist only after mesh consensus is complete.
    for client_public_key in client_catalog.transport_public_keys() {
        network.add_allowed_certificate_public_key(client_public_key);
    }
    let party_public_key_map = party_public_keys.into_iter().collect::<BTreeMap<_, _>>();
    let reconnect_peers = standing_session
        .parties
        .iter()
        .filter(|(registered_party_id, _)| *registered_party_id != party_id)
        .map(|(registered_party_id, address)| {
            party_public_key_map
                .get(registered_party_id)
                .cloned()
                .map(|public_key| (public_key, *address))
                .ok_or_else(|| {
                    format!(
                        "configured standing roster omitted TLS identity for party {registered_party_id}"
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let protocol_party_id = network.local_party_id();
    let mux = ExecutionTransportMux::new(4096)
        .map_err(|error| format!("create standing execution mux: {error}"))?;
    let scanner = ExecutionConnectionScanner::spawn(network.clone(), mux.clone())
        .map_err(|error| format!("start standing execution scanner: {error}"))?;
    let reservoir_cancellation = CancellationToken::new();
    let _connection_accept_loop = spawn_connection_accept_loop(network.clone(), protocol_party_id);
    let _mesh_reconnect_loop = spawn_standing_mesh_reconnect_loop(
        network.clone(),
        reconnect_peers,
        protocol_party_id,
        reservoir_cancellation.clone(),
    );
    let mut handler = StandingRunnerExecutionHandler {
        network: Arc::new(network),
        mux,
        local_store,
        preproc_store,
        persistent_identity,
        party_id: protocol_party_id,
        parties,
        threshold,
        pool_id,
        coordinator_addr,
        coordinator_cert_der: cert_der,
        coordinator_key_der: key_der,
        node_rpc,
        reservoirs: BTreeMap::new(),
        reservoir_cancellation: reservoir_cancellation.clone(),
    };
    handler
        .warm_reservoirs(program_catalog.programs(), reservoir_burst_capacity)
        .await?;
    let handler = Arc::new(handler);
    let (supervisor, events) = NodeSupervisor::new();
    let mut control = StandingNodeControl::new(
        party_id,
        control_dir,
        program_catalog,
        client_catalog,
        Arc::clone(&supervisor),
        events,
        handler,
    )
    .map_err(|error| error.to_string())?;
    let cancellation = CancellationToken::new();
    eprintln!(
        "[party {protocol_party_id}] standing node ready: reservoir_burst_capacity={reservoir_burst_capacity}"
    );
    let mut control_task = {
        let cancellation = cancellation.clone();
        tokio::spawn(async move { control.run(cancellation).await })
    };
    let result = tokio::select! {
        result = &mut control_task => {
            reservoir_cancellation.cancel();
            cancellation.cancel();
            supervisor.shutdown();
            result
                .map_err(|error| format!("standing control task failed: {error}"))?
                .map_err(|error| error.to_string())
        }
        signal = stoffel_vm::net::wait_for_shutdown_signal() => {
            signal.map_err(|error| error.to_string())?;
            reservoir_cancellation.cancel();
            supervisor.shutdown();
            cancellation.cancel();
            control_task
                .await
                .map_err(|error| format!("standing control task failed: {error}"))?
                .map_err(|error| error.to_string())?;
            Ok(())
        }
    };
    scanner.shutdown().await;
    result
}

// Use a Tokio runtime for async operations
#[tokio::main]
async fn main() {
    // The MPC protocol code (honeybadger/avss engines, preprocessing, etc.) emits
    // `tracing` events, but nothing consumes them unless a subscriber is installed.
    // RUST_LOG controls the level/target filter (e.g. `RUST_LOG=stoffel_vm=debug`);
    // it defaults to "info" so protocol-round messages show up out of the box.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    // When spawned by the local coordinator runner, tie this process's lifetime
    // to its parent: if the parent (the test/CLI/SDK process) dies — including a
    // SIGKILL, where the parent's `kill_on_drop` cleanup cannot run — this party
    // would otherwise be re-parented to init/launchd and leak as an orphaned MPC
    // process. Poll the parent PID and exit promptly once it changes.
    if std::env::var_os("STOFFEL_DIE_WITH_PARENT").is_some() {
        // SAFETY: `getppid` is always safe to call and takes no arguments.
        let original_parent = unsafe { libc::getppid() };
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                // SAFETY: see above.
                let current = unsafe { libc::getppid() };
                if current != original_parent || current <= 1 {
                    eprintln!(
                        "[watchdog] parent process exited (ppid {original_parent} -> {current}); shutting down"
                    );
                    std::process::exit(0);
                }
            }
        });
    }

    let raw_args = env::args().skip(1).collect::<Vec<_>>();
    exit_on_cli_configuration_error(validate_cli_option_values(&raw_args));
    let positional_client_program = client_program_from_arguments(&raw_args);

    if let Some(index) = raw_args.iter().position(|arg| arg == "--print-program-id") {
        let path = raw_args.get(index + 1).unwrap_or_else(|| {
            eprintln!("Error: --print-program-id requires an artifact path");
            exit(2);
        });
        let bytes = fs::read(path).unwrap_or_else(|error| {
            eprintln!("Error: failed to read program artifact '{path}': {error}");
            exit(2);
        });
        println!("{}", hex::encode(program_id_from_bytes(&bytes)));
        return;
    }

    if let Some(index) = raw_args
        .iter()
        .position(|arg| arg == "--print-program-manifest")
    {
        #[derive(Serialize)]
        struct ProgramManifestReport {
            program_id: String,
            bytecode_version: u16,
            entries: Vec<String>,
            manifest: ClientIoManifest,
        }

        let path = raw_args.get(index + 1).unwrap_or_else(|| {
            eprintln!("Error: --print-program-manifest requires an artifact path");
            exit(2);
        });
        let bytes = fs::read(path).unwrap_or_else(|error| {
            eprintln!("Error: failed to read program artifact '{path}': {error}");
            exit(2);
        });
        let mut entries = Vec::new();
        let (_, bytecode_version, manifest) = CompiledBinary::try_for_each_vm_function_from_reader(
            &mut BufReader::new(bytes.as_slice()),
            |function| {
                entries.push(function.name().to_owned());
                Ok(())
            },
        )
        .unwrap_or_else(|error| {
            eprintln!("Error: failed to deserialize program artifact '{path}': {error:?}");
            exit(2);
        });
        entries.sort();
        let report = ProgramManifestReport {
            program_id: hex::encode(program_id_from_bytes(&bytes)),
            bytecode_version,
            entries,
            manifest,
        };
        println!(
            "{}",
            serde_json::to_string(&report).expect("program manifest report is serializable")
        );
        return;
    }

    if is_flag_present(&raw_args, "--standing-node") {
        if let Err(error) = run_standing_node(&raw_args).await {
            eprintln!("Standing node failed: {error}");
            exit(13);
        }
        return;
    }

    if raw_args.is_empty() {
        // Allow bootnode-only mode without program path
        print_usage_and_exit();
    }

    let mut entry: String = "main".to_string();

    let mut trace_instr = false;
    let mut trace_regs = false;
    let mut trace_stack = false;
    let mut as_bootnode = false;
    let mut as_leader = false;
    let mut as_client = false;
    let mut one_off = false;
    let mut bind_addr: Option<SocketAddr> = None;
    let mut party_id: Option<usize> = None;
    let mut bootstrap_addr: Option<SocketAddr> = None;
    let mut n_parties: Option<usize> = None;
    let mut threshold: Option<usize> = None;
    let mut client_inputs: Option<String> = None;
    let mut client_outputs: Option<usize> = None;
    let mut client_program = positional_client_program;
    let mut client_manifest_slot: Option<u64> = None;
    let mut raw_client_io = false;
    let mut output_fixed_point_fractional_bits: Option<usize> = None;
    let mut expected_client_count: Option<usize> = None;
    let mut client_input_count: usize = 1;
    // Actual TOTAL number of client input values across all clients (sum of each
    // client's count). 0 = unset, in which case we fall back to the uniform
    // `num_clients * client_input_count`. Lets clients provide different counts.
    let mut client_input_total: Option<usize> = None;
    let mut _enable_nat: bool = false;
    let mut _stun_servers: Vec<SocketAddr> = Vec::new();
    let mut server_addrs: Vec<SocketAddr> = Vec::new();
    let mut client_transport_addrs: Vec<SocketAddr> = Vec::new();
    let mut mpc_backend: Option<String> = None;
    let mut mpc_curve: Option<String> = None;
    let mut rpc_addr: Option<(String, u16)> = None;
    let mut coord_addr: Option<(String, u16)> = None;
    let mut key_der: Option<Vec<u8>> = None;
    let mut cert_der: Option<Vec<u8>> = None;
    let mut expected_clients: Vec<String> = Vec::new();
    let mut client_roster: Vec<usize> = Vec::new();
    let mut client_input_slots: Vec<usize> = Vec::new();
    let mut eth_node_addr: Option<String> = None;
    let mut wallet_sk_str: Option<String> = None;
    let mut contract_addr: Option<String> = None;
    let mut coordinator_client_index: Option<u64> = None;
    let mut preproc_store_path: Option<String> = None;
    let mut local_store_path: Option<String> = None;
    let mut advertise_addr: Option<SocketAddr> = None;
    let mut execution_id: Option<ExecutionId> = None;

    for arg in &raw_args {
        if arg == "-h" || arg == "--help" {
            print_usage_and_exit();
        } else if arg == "--trace-instr" {
            trace_instr = true;
        } else if arg == "--trace-regs" {
            trace_regs = true;
        } else if arg == "--trace-stack" {
            trace_stack = true;
        } else if arg == "--bootnode" {
            as_bootnode = true;
        } else if arg == "--leader" {
            as_leader = true;
        } else if arg == "--client" {
            as_client = true;
        } else if arg == "--raw-client-io" {
            raw_client_io = true;
        } else if arg == "--one-off" {
            one_off = true;
        } else if arg == "--nat" {
            _enable_nat = true;
        } else if let Some(_rest) = arg.strip_prefix("--bind") {
            // support "--bind" and "--bind=.."
            // actual value parsed later from positional with key
        } else if let Some(_rest) = arg.strip_prefix("--party-id") {
        } else if let Some(_rest) = arg.strip_prefix("--bootstrap") {
        } else if let Some(_rest) = arg.strip_prefix("--n-parties") {
        } else if let Some(_rest) = arg.strip_prefix("--threshold") {
        } else if let Some(_rest) = arg.strip_prefix("--inputs") {
        } else if let Some(_rest) = arg.strip_prefix("--outputs") {
        } else if let Some(_rest) = arg.strip_prefix("--program") {
        } else if let Some(_rest) = arg.strip_prefix("--client-slot") {
        } else if let Some(_rest) = arg.strip_prefix("--output-fixed-point-fractional-bits") {
        } else if let Some(_rest) = arg.strip_prefix("--wait-for-clients") {
        } else if let Some(_rest) = arg.strip_prefix("--client-input-count") {
        } else if let Some(_rest) = arg.strip_prefix("--client-input-total") {
        } else if let Some(_rest) = arg.strip_prefix("--stun-servers") {
        } else if let Some(_rest) = arg.strip_prefix("--servers") {
        } else if let Some(_rest) = arg.strip_prefix("--client-transport-servers") {
        } else if let Some(_rest) = arg.strip_prefix("--mpc-backend") {
        } else if let Some(_rest) = arg.strip_prefix("--mpc-curve") {
        } else if let Some(_rest) = arg.strip_prefix("--rpc-bind") {
        } else if let Some(_rest) = arg.strip_prefix("--off-chain-coord") {
        } else if let Some(_rest) = arg.strip_prefix("--on-chain-coord") {
        } else if let Some(_rest) = arg.strip_prefix("--eth-node") {
        } else if let Some(_rest) = arg.strip_prefix("--wallet-sk") {
        } else if let Some(_rest) = arg.strip_prefix("--key") {
        } else if let Some(_rest) = arg.strip_prefix("--cert") {
        } else if let Some(_rest) = arg.strip_prefix("--expected-clients") {
        } else if let Some(_rest) = arg.strip_prefix("--client-roster") {
        } else if let Some(_rest) = arg.strip_prefix("--client-input-slots") {
        } else if let Some(_rest) = arg.strip_prefix("--client-index") {
        } else if let Some(_rest) = arg.strip_prefix("--preproc-store") {
        } else if let Some(_rest) = arg.strip_prefix("--local-store") {
        } else if let Some(_rest) = arg.strip_prefix("--advertise") {
        } else if let Some(_rest) = arg.strip_prefix("--execution-id") {
        }
    }

    let has_party_id = is_flag_present(&raw_args, "--party-id");
    let has_bootstrap = is_flag_present(&raw_args, "--bootstrap");
    let has_offchain_coordinator = is_flag_present(&raw_args, "--off-chain-coord");
    let has_onchain_coordinator = is_flag_present(&raw_args, "--on-chain-coord");
    let has_coordinator = has_offchain_coordinator || has_onchain_coordinator;
    let party_mode_requested = has_party_id || has_bootstrap;

    exit_on_cli_configuration_error(validate_cli_mode_flags(
        as_client,
        as_bootnode,
        as_leader,
        has_party_id,
        has_bootstrap,
    ));

    if as_client {
        exit_on_cli_configuration_error(validate_required_cli_parameters(
            "client mode",
            &[
                (
                    "a positional program or --program (or explicit --raw-client-io)",
                    client_program.is_some() || raw_client_io,
                ),
                ("--n-parties", is_flag_present(&raw_args, "--n-parties")),
                ("--servers", is_flag_present(&raw_args, "--servers")),
                (
                    "--execution-id",
                    is_flag_present(&raw_args, "--execution-id"),
                ),
            ],
        ));
        if has_coordinator {
            exit_on_cli_configuration_error(validate_required_cli_parameters(
                "coordinator client mode",
                &[
                    ("--cert", is_flag_present(&raw_args, "--cert")),
                    ("--key", is_flag_present(&raw_args, "--key")),
                ],
            ));
        } else if is_flag_present(&raw_args, "--cert") != is_flag_present(&raw_args, "--key") {
            exit_on_cli_configuration_error(Err(
                "direct client mode requires --cert and --key to be provided together".to_owned(),
            ));
        } else {
            exit_on_cli_configuration_error(validate_forbidden_cli_parameters(
                "direct client mode",
                &[
                    (
                        "--client-index",
                        is_flag_present(&raw_args, "--client-index"),
                    ),
                    (
                        "--client-transport-servers",
                        is_flag_present(&raw_args, "--client-transport-servers"),
                    ),
                ],
            ));
        }
        exit_on_cli_configuration_error(validate_forbidden_cli_parameters(
            "client mode",
            &[
                ("--bind", is_flag_present(&raw_args, "--bind")),
                ("--advertise", is_flag_present(&raw_args, "--advertise")),
                ("--rpc-bind", is_flag_present(&raw_args, "--rpc-bind")),
                (
                    "--expected-clients",
                    is_flag_present(&raw_args, "--expected-clients"),
                ),
                (
                    "--wait-for-clients",
                    is_flag_present(&raw_args, "--wait-for-clients"),
                ),
            ],
        ));
    } else if as_bootnode {
        exit_on_cli_configuration_error(validate_required_cli_parameters(
            "bootnode mode",
            &[
                ("--bind", is_flag_present(&raw_args, "--bind")),
                ("--n-parties", is_flag_present(&raw_args, "--n-parties")),
            ],
        ));
    } else if as_leader || party_mode_requested {
        let mode = if as_leader {
            "leader mode"
        } else {
            "party mode"
        };
        exit_on_cli_configuration_error(validate_required_cli_parameters(
            mode,
            &[
                ("a positional program", client_program.is_some()),
                ("--bind", is_flag_present(&raw_args, "--bind")),
                ("--n-parties", is_flag_present(&raw_args, "--n-parties")),
                (
                    "--execution-id",
                    is_flag_present(&raw_args, "--execution-id"),
                ),
            ],
        ));
        if has_coordinator {
            exit_on_cli_configuration_error(validate_required_cli_parameters(
                "coordinator server mode",
                &[
                    ("--rpc-bind", is_flag_present(&raw_args, "--rpc-bind")),
                    ("--cert", is_flag_present(&raw_args, "--cert")),
                    ("--key", is_flag_present(&raw_args, "--key")),
                ],
            ));
        } else {
            exit_on_cli_configuration_error(validate_forbidden_cli_parameters(
                mode,
                &[("--rpc-bind", is_flag_present(&raw_args, "--rpc-bind"))],
            ));
            if is_flag_present(&raw_args, "--cert") != is_flag_present(&raw_args, "--key") {
                exit_on_cli_configuration_error(Err(format!(
                    "{mode} requires --cert and --key to be provided together"
                )));
            }
        }
    } else {
        exit_on_cli_configuration_error(validate_forbidden_cli_parameters(
            "local mode",
            &[
                ("--bind", is_flag_present(&raw_args, "--bind")),
                ("--n-parties", is_flag_present(&raw_args, "--n-parties")),
                ("--threshold", is_flag_present(&raw_args, "--threshold")),
                ("--advertise", is_flag_present(&raw_args, "--advertise")),
                (
                    "--execution-id",
                    is_flag_present(&raw_args, "--execution-id"),
                ),
                ("--servers", is_flag_present(&raw_args, "--servers")),
                ("--rpc-bind", is_flag_present(&raw_args, "--rpc-bind")),
                ("--off-chain-coord", has_offchain_coordinator),
                ("--on-chain-coord", has_onchain_coordinator),
                (
                    "--expected-clients",
                    is_flag_present(&raw_args, "--expected-clients"),
                ),
                ("--one-off", one_off),
                ("--inputs", is_flag_present(&raw_args, "--inputs")),
                ("--outputs", is_flag_present(&raw_args, "--outputs")),
                ("--program", is_flag_present(&raw_args, "--program")),
                ("--client-slot", is_flag_present(&raw_args, "--client-slot")),
                ("--raw-client-io", raw_client_io),
                (
                    "--client-index",
                    is_flag_present(&raw_args, "--client-index"),
                ),
                (
                    "--client-transport-servers",
                    is_flag_present(&raw_args, "--client-transport-servers"),
                ),
            ],
        ));
    }

    let mut positional = cli_positional_arguments(&raw_args);

    if positional.is_empty() {
        // Bootnode and client modes do not require a positional program. Client
        // mode accepts --program, and raw mode intentionally has no artifact.
        if !as_bootnode && !as_client {
            print_usage_and_exit();
        }
    }

    // Parse key-value style flags
    let normalized_args = normalized_cli_arguments(&raw_args);
    let mut args_iter = normalized_args.into_iter().peekable();
    while let Some(a) = args_iter.next() {
        match a.as_str() {
            "--bind" => {
                if let Some(v) = args_iter.next() {
                    bind_addr = Some(v.parse().expect("Invalid --bind addr"));
                }
            }
            "--party-id" => {
                if let Some(v) = args_iter.next() {
                    party_id = Some(v.parse().expect("Invalid --party-id"));
                }
            }
            "--bootstrap" => {
                if let Some(v) = args_iter.next() {
                    bootstrap_addr = Some(v.parse().expect("Invalid --bootstrap addr"));
                }
            }
            "--n-parties" => {
                if let Some(v) = args_iter.next() {
                    n_parties = Some(v.parse().expect("Invalid --n-parties"));
                }
            }
            "--threshold" => {
                if let Some(v) = args_iter.next() {
                    threshold = Some(v.parse().expect("Invalid --threshold"));
                }
            }
            "--inputs" => {
                if let Some(v) = args_iter.next() {
                    client_inputs = Some(v);
                }
            }
            "--outputs" => {
                if let Some(v) = args_iter.next() {
                    client_outputs = Some(v.parse().expect("Invalid --outputs"));
                }
            }
            "--program" => {
                if let Some(v) = args_iter.next() {
                    client_program = Some(PathBuf::from(v));
                }
            }
            "--client-slot" => {
                if let Some(v) = args_iter.next() {
                    client_manifest_slot = Some(v.parse().expect("Invalid --client-slot"));
                }
            }
            "--output-fixed-point-fractional-bits" => {
                if let Some(v) = args_iter.next() {
                    output_fixed_point_fractional_bits = Some(
                        v.parse()
                            .expect("Invalid --output-fixed-point-fractional-bits"),
                    );
                }
            }
            "--wait-for-clients" => {
                if let Some(v) = args_iter.next() {
                    expected_client_count = Some(v.parse().expect("Invalid --wait-for-clients"));
                }
            }
            "--client-input-count" => {
                if let Some(v) = args_iter.next() {
                    client_input_count = v.parse().expect("Invalid --client-input-count");
                }
            }
            "--client-input-total" => {
                if let Some(v) = args_iter.next() {
                    client_input_total = Some(v.parse().expect("Invalid --client-input-total"));
                }
            }
            "--stun-servers" => {
                if let Some(v) = args_iter.next() {
                    _stun_servers = v
                        .split(',')
                        .filter_map(|s| {
                            let s = s.trim();
                            s.parse::<SocketAddr>().ok().or_else(|| {
                                eprintln!("Warning: Invalid STUN server address '{}', skipping", s);
                                None
                            })
                        })
                        .collect();
                }
            }
            "--servers" => {
                if let Some(v) = args_iter.next() {
                    server_addrs = v
                        .split(',')
                        .filter_map(|s| {
                            let s = s.trim();
                            s.parse::<SocketAddr>().ok().or_else(|| {
                                eprintln!("Warning: Invalid server address '{}', skipping", s);
                                None
                            })
                        })
                        .collect();
                }
            }
            "--client-transport-servers" => {
                if let Some(v) = args_iter.next() {
                    client_transport_addrs = v
                        .split(',')
                        .filter_map(|s| {
                            let s = s.trim();
                            s.parse::<SocketAddr>().ok().or_else(|| {
                                eprintln!(
                                    "Warning: Invalid client transport address '{}', skipping",
                                    s
                                );
                                None
                            })
                        })
                        .collect();
                }
            }
            "--mpc-backend" => {
                if let Some(v) = args_iter.next() {
                    mpc_backend = Some(v);
                }
            }
            "--mpc-curve" => {
                if let Some(v) = args_iter.next() {
                    mpc_curve = Some(v);
                }
            }
            "--rpc-bind" => {
                if let Some(v) = args_iter.next() {
                    let parts: Vec<&str> = v.rsplitn(2, ':').collect();
                    let port: u16 = parts[0].parse().expect("Invalid --rpc-bind port");
                    let host = parts[1].to_string();
                    rpc_addr = Some((host, port));
                }
            }
            "--off-chain-coord" => {
                if let Some(v) = args_iter.next() {
                    let parts: Vec<&str> = v.rsplitn(2, ':').collect();
                    let port: u16 = parts[0].parse().expect("Invalid --off-chain-coord port");
                    let host = parts[1].to_string();
                    coord_addr = Some((host, port));
                }
            }
            "--on-chain-coord" => {
                if let Some(v) = args_iter.next() {
                    contract_addr = Some(v);
                }
            }
            "--eth-node" => {
                if let Some(v) = args_iter.next() {
                    eth_node_addr = Some(v);
                }
            }
            "--wallet-sk" => {
                if let Some(v) = args_iter.next() {
                    wallet_sk_str = Some(v);
                }
            }
            "--key" => {
                if let Some(v) = args_iter.next() {
                    key_der = Some(std::fs::read(&v).expect("Failed to read --key file"));
                }
            }
            "--cert" => {
                if let Some(v) = args_iter.next() {
                    cert_der = Some(std::fs::read(&v).expect("Failed to read --cert file"));
                }
            }
            "--client-index" => {
                if let Some(v) = args_iter.next() {
                    coordinator_client_index = Some(v.parse().expect("Invalid --client-index"));
                }
            }
            "--preproc-store" => {
                if let Some(v) = args_iter.next() {
                    preproc_store_path = Some(v);
                }
            }
            "--local-store" => {
                if let Some(v) = args_iter.next() {
                    local_store_path = Some(v);
                }
            }
            "--expected-clients" => {
                if let Some(v) = args_iter.next() {
                    expected_clients = v.split(',').map(|s| s.trim().to_string()).collect();
                }
            }
            "--client-roster" => {
                if let Some(v) = args_iter.next() {
                    client_roster = v
                        .split(',')
                        .filter(|s| !s.trim().is_empty())
                        .map(|s| s.trim().parse().expect("Invalid --client-roster slot"))
                        .collect();
                }
            }
            "--client-input-slots" => {
                if let Some(v) = args_iter.next() {
                    client_input_slots = v
                        .split(',')
                        .filter(|s| !s.trim().is_empty())
                        .map(|s| s.trim().parse().expect("Invalid --client-input-slots slot"))
                        .collect();
                }
            }
            "--advertise" => {
                if let Some(v) = args_iter.next() {
                    advertise_addr = Some(v.parse().expect("Invalid --advertise addr"));
                }
            }
            "--execution-id" => {
                if let Some(v) = args_iter.next() {
                    let parsed = v.parse::<ExecutionId>().unwrap_or_else(|error| {
                        eprintln!("Error: invalid --execution-id: {error}");
                        exit(2);
                    });
                    if parsed.is_zero() {
                        eprintln!("Error: --execution-id must be nonzero");
                        exit(2);
                    }
                    execution_id = Some(parsed);
                }
            }
            _ => {}
        }
    }

    if as_client {
        exit_on_cli_configuration_error(validate_required_cli_parameters(
            "client mode",
            &[
                (
                    "a positional program or --program (or explicit --raw-client-io)",
                    client_program.is_some() || raw_client_io,
                ),
                ("--n-parties", n_parties.is_some()),
                ("--servers", !server_addrs.is_empty()),
                ("--execution-id", execution_id.is_some()),
            ],
        ));
        exit_on_cli_configuration_error(validate_client_server_count(
            n_parties.expect("client requirements checked above"),
            server_addrs.len(),
        ));
        if raw_client_io && client_manifest_slot.is_some() {
            exit_on_cli_configuration_error(Err(
                "--client-slot cannot be combined with --raw-client-io".to_owned(),
            ));
        }
    } else if as_bootnode {
        exit_on_cli_configuration_error(validate_required_cli_parameters(
            "bootnode mode",
            &[
                ("--bind", bind_addr.is_some()),
                ("--n-parties", n_parties.is_some()),
            ],
        ));
    } else if as_leader || party_mode_requested {
        let mode = if as_leader {
            "leader mode"
        } else {
            "party mode"
        };
        exit_on_cli_configuration_error(validate_required_cli_parameters(
            mode,
            &[
                ("a positional program", client_program.is_some()),
                ("--bind", bind_addr.is_some()),
                ("--n-parties", n_parties.is_some()),
                ("--execution-id", execution_id.is_some()),
            ],
        ));
        if has_coordinator {
            exit_on_cli_configuration_error(validate_required_cli_parameters(
                "coordinator server mode",
                &[
                    ("--rpc-bind", rpc_addr.is_some()),
                    ("--cert", cert_der.is_some()),
                    ("--key", key_der.is_some()),
                ],
            ));
        }
    }

    let mut coordinator_output_format = match output_fixed_point_fractional_bits {
        Some(bits) => {
            if bits > 62 {
                eprintln!("Error: --output-fixed-point-fractional-bits must be <= 62");
                exit(2);
            }
            CoordinatorOutputFormat::FixedPoint {
                fractional_bits: bits,
            }
        }
        None => CoordinatorOutputFormat::FieldInteger,
    };
    let storage_identity = required_storage_identity(
        &cert_der,
        &key_der,
        local_store_path.is_some() || preproc_store_path.is_some(),
    );
    let preproc_store: Option<Arc<dyn PreprocStore>> = preproc_store_path
        .as_deref()
        .map(LmdbPreprocStore::open)
        .transpose()
        .unwrap_or_else(|error| {
            eprintln!("Error: failed to open preprocessing store: {error}");
            exit(2);
        })
        .map(|store| Arc::new(store) as Arc<dyn PreprocStore>);
    if contract_addr.is_some() {
        let _ = (eth_node_addr.as_ref(), wallet_sk_str.as_ref());
        eprintln!(
            "Error: on-chain coordinator mode is temporarily unavailable in the crates.io-ready build"
        );
        exit(2);
    }

    // Bootnode-only mode (no program execution)
    if as_bootnode && !as_leader {
        let n = n_parties.unwrap_or_else(|| {
            eprintln!("Error: --n-parties is required for bootnode mode");
            exit(2);
        });
        let backend = mpc_backend
            .as_deref()
            .map(MpcBackendKind::from_str)
            .transpose()
            .unwrap_or_else(|error| {
                eprintln!("Error: {error}");
                exit(2);
            })
            .unwrap_or_default();
        if let Err(error) = backend.validate_party_count(n) {
            eprintln!("Error: {error}");
            exit(2);
        }
        let bind = bind_addr.expect("bootnode CLI requirements validated");
        eprintln!("Starting bootnode on {}", bind);
        // Install crypto provider for quinn/rustls
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("install rustls crypto");
        if let Err(e) = run_bootnode_with_config(bind, n).await {
            eprintln!("Bootnode error: {}", e);
            exit(10);
        }
        return;
    }

    // Client mode: connect to MPC servers and provide inputs
    if as_client {
        if client_manifest_slot.is_some() && client_program.is_none() {
            eprintln!(
                "Error: --client-slot requires a positional program or --program <compiled.stflb>"
            );
            exit(2);
        }
        if let Some(program_path) = client_program.as_deref().filter(|_| !raw_client_io) {
            let semantics = load_client_manifest_semantics(
                program_path,
                client_manifest_slot,
                coordinator_client_index,
                semantic_client_input_count(client_inputs.as_deref()),
                client_outputs,
            )
            .unwrap_or_else(|error| {
                eprintln!("Error: {error}");
                exit(2);
            });
            client_inputs =
                encode_manifest_client_inputs(client_inputs.as_deref(), &semantics.inputs)
                    .unwrap_or_else(|error| {
                        eprintln!("Error: {error}");
                        exit(2);
                    });
            client_outputs = Some(semantics.outputs.len());
            coordinator_output_format = CoordinatorOutputFormat::Manifest(semantics.outputs);
            eprintln!(
                "[client] using semantic client I/O from {} for manifest slot {}",
                program_path.display(),
                semantics.client_slot
            );
        }

        let input_count = semantic_client_input_count(client_inputs.as_deref());
        let output_count = client_outputs.unwrap_or(input_count);
        if input_count == 0 && output_count == 0 {
            exit_on_cli_configuration_error(Err(
                "client mode requires at least one input or requested output".to_owned(),
            ));
        }
        if has_coordinator && input_count > 0 {
            exit_on_cli_configuration_error(validate_required_cli_parameters(
                "coordinator input client mode",
                &[("--client-index", coordinator_client_index.is_some())],
            ));
        }
        if has_coordinator && input_count == 0 && output_count > 0 {
            exit_on_cli_configuration_error(validate_required_cli_parameters(
                "coordinator output-only client mode",
                &[(
                    "--client-transport-servers",
                    !client_transport_addrs.is_empty(),
                )],
            ));
            if client_transport_addrs.len() != server_addrs.len() {
                exit_on_cli_configuration_error(Err(format!(
                    "coordinator output-only client mode requires exactly one --client-transport-servers address per --servers address (got {}, expected {})",
                    client_transport_addrs.len(),
                    server_addrs.len()
                )));
            }
        }

        if coord_addr.is_some()
            && contract_addr.is_none()
            && mpc_backend.as_deref().is_some_and(|backend| {
                backend.eq_ignore_ascii_case("avss") || backend.eq_ignore_ascii_case("adkg")
            })
        {
            let party_count = n_parties.unwrap_or(server_addrs.len());
            if let Err(error) = MpcBackendKind::Avss.validate_party_count(party_count) {
                eprintln!("Error: {error}");
                exit(2);
            }
            let curve_config = if let Some(ref name) = mpc_curve {
                match MpcCurveConfig::from_str(name) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        exit(2);
                    }
                }
            } else {
                MpcCurveConfig::default()
            };
            if let Err(e) = curve_config.validate_for_backend(MpcBackendKind::Avss) {
                eprintln!("Error: {}", e);
                exit(2);
            }
            run_avss_offchain_coordinator_client(AvssOffchainCoordinatorClientArgs {
                execution_id: require_network_execution_id(execution_id),
                curve_config,
                client_inputs,
                client_outputs,
                output_format: coordinator_output_format,
                server_addrs,
                client_transport_addrs,
                coord_addr: coord_addr.clone().unwrap(),
                cert_der: cert_der.clone().expect("--cert required in client mode"),
                key_der: key_der.clone().expect("--key required in client mode"),
                threshold,
                coordinator_client_index,
            })
            .await;
            return;
        }

        // Coordinator-based client mode
        if contract_addr.is_some() || coord_addr.is_some() {
            {
                let party_count = n_parties.unwrap_or(server_addrs.len());
                if let Err(error) = MpcBackendKind::HoneyBadger.validate_party_count(party_count) {
                    eprintln!("Error: {error}");
                    exit(2);
                }
                let curve_config = if let Some(ref name) = mpc_curve {
                    match MpcCurveConfig::from_str(name) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            exit(2);
                        }
                    }
                } else {
                    MpcCurveConfig::default()
                };
                if let Err(e) = curve_config.validate_for_backend(MpcBackendKind::HoneyBadger) {
                    eprintln!("Error: {}", e);
                    exit(2);
                }
                run_hb_coordinator_client(
                    curve_config,
                    require_network_execution_id(execution_id),
                    client_inputs,
                    client_outputs,
                    coordinator_output_format,
                    server_addrs,
                    client_transport_addrs,
                    coord_addr,
                    None,
                    cert_der.expect("--cert required in client mode"),
                    key_der.expect("--key required in client mode"),
                    threshold,
                    coordinator_client_index,
                    None,
                    None,
                )
                .await;
                return;
            }
        }

        // Direct client mode (no coordinator)
        {
            run_as_client(
                require_network_execution_id(execution_id),
                n_parties,
                threshold,
                mpc_backend.as_deref(),
                mpc_curve.as_deref(),
                client_inputs,
                client_outputs,
                coordinator_output_format,
                server_addrs,
                cert_der,
                key_der,
            )
            .await;
            return;
        }
    }

    let path_opt = if !positional.is_empty() {
        Some(positional.remove(0))
    } else {
        None
    };
    entry = if !positional.is_empty() {
        positional.remove(0)
    } else {
        entry
    };

    let manifest_config = path_opt.as_ref().map(|path| {
        let file = File::open(path).unwrap_or_else(|error| {
            eprintln!(
                "Error: failed to open compiled program '{}': {}",
                path, error
            );
            exit(2);
        });
        let (_, _, client_io_manifest) =
            CompiledBinary::try_for_each_vm_function_from_reader(&mut BufReader::new(file), |_| {
                Ok(())
            })
            .unwrap_or_else(|error| {
                eprintln!(
                    "Error: failed to deserialize compiled program '{}': {:?}",
                    path, error
                );
                exit(2);
            });
        (
            MpcBackendKind::from(client_io_manifest.mpc_backend),
            MpcCurveConfig::from(client_io_manifest.mpc_curve),
        )
    });
    let manifest_backend = manifest_config.map(|(backend, _)| backend);
    let manifest_curve = manifest_config.map(|(_, curve)| curve);

    // Program manifests are authoritative; --mpc-backend also serves client mode.
    let backend_kind = if let Some(ref name) = mpc_backend {
        let cli_backend = match MpcBackendKind::from_str(name) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Error: {}", e);
                exit(2);
            }
        };
        if let Some(manifest_backend) = manifest_backend {
            if cli_backend != manifest_backend {
                eprintln!(
                    "Error: --mpc-backend '{}' does not match program manifest backend '{}'",
                    cli_backend.name(),
                    manifest_backend.name()
                );
                exit(2);
            }
        }
        cli_backend
    } else {
        manifest_backend.unwrap_or_default()
    };

    let curve_config = if let Some(ref name) = mpc_curve {
        let cli_curve = match MpcCurveConfig::from_str(name) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error: {}", e);
                exit(2);
            }
        };
        if let Some(manifest_curve) = manifest_curve {
            if cli_curve != manifest_curve {
                eprintln!(
                    "Error: --mpc-curve '{}' does not match program manifest curve '{}'",
                    cli_curve.name(),
                    manifest_curve.name()
                );
                exit(2);
            }
        }
        cli_curve
    } else {
        manifest_curve.unwrap_or_default()
    };

    if let Err(e) = curve_config.validate_for_backend(backend_kind) {
        eprintln!("Error: {}", e);
        exit(2);
    }
    if let Some(n) = n_parties {
        if let Err(error) = backend_kind.validate_party_count(n) {
            eprintln!("Error: {error}");
            exit(2);
        }
    }

    // Optional: bring up networking in party mode if bootstrap provided or if leader
    let mut net_opt: Option<Arc<QuicNetworkManager>> = None;
    let program_id: [u8; 32];
    let mut agreed_entry = entry.clone();
    let mut session_instance_id: Option<u64> = None;
    let mut session_n_parties: Option<usize> = None;
    let mut session_threshold: Option<usize> = None;

    // Leader mode: this party also runs the bootnode
    if as_leader {
        let bind = bind_addr.expect("leader CLI requirements validated");
        let my_id = 0usize;

        // Install crypto provider for quinn/rustls
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("install rustls crypto");

        // Must have program path
        if path_opt.is_none() {
            eprintln!("Error: leader mode requires a program path");
            exit(2);
        }
        let program_path = path_opt.as_ref().unwrap();
        let bytes = std::fs::read(program_path).expect("read program");
        program_id = program_id_from_bytes(&bytes);

        // Get MPC parameters (required for session)
        let n = n_parties.unwrap_or_else(|| {
            eprintln!("Error: --n-parties is required for leader mode");
            exit(2);
        });
        let t = threshold.unwrap_or(1);

        eprintln!(
            "[leader/party {}] Starting bootnode on {} and participating in session (n={}, t={})",
            my_id, bind, n, t
        );

        // Spawn bootnode in background
        local_bind_handoff("STOFFEL_LOCAL_NETWORK_HANDOFF").await;
        let bootnode_bind = bind;
        let bootnode_n = n;
        let (bootnode_ready_tx, bootnode_ready_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Err(e) =
                run_bootnode_with_config_ready(bootnode_bind, bootnode_n, Some(bootnode_ready_tx))
                    .await
            {
                eprintln!("Bootnode error: {}", e);
            }
        });
        if bootnode_ready_rx.await.is_err() {
            eprintln!("Bootnode stopped before its listener became ready");
            exit(11);
        }
        write_local_runner_marker_or_exit(
            "STOFFEL_LOCAL_BOOTNODE_READY_FILE",
            "bootnode listener readiness",
        );

        // Now connect to ourselves as the bootnode
        let mut mgr = QuicNetworkManager::with_node_id(my_id);
        if let (Some(cert), Some(key)) = (cert_der.as_ref(), key_der.as_ref()) {
            if let Err(e) = mgr.set_local_certificate_der(cert.clone(), key.clone()) {
                eprintln!("Failed to configure local node certificate: {}", e);
                exit(11);
            }
        }
        // Listen on a different port for peer connections
        let party_bind: SocketAddr = format!("{}:{}", bind.ip(), bind.port() + 1000)
            .parse()
            .unwrap();
        if let Err(e) = mgr.listen(party_bind).await {
            eprintln!("Failed to listen on {}: {}", party_bind, e);
            exit(11);
        }

        // When the bind address is 0.0.0.0 (e.g. ECS/Fargate), connecting TO 0.0.0.0
        // fails on Linux because it is not a valid destination. Use 127.0.0.1 to reach
        // our own bootnode instead.
        let bootnode_connect: SocketAddr = if bind.ip().is_unspecified() {
            format!("127.0.0.1:{}", bind.port()).parse().unwrap()
        } else {
            bind
        };

        eprintln!(
            "[leader/party {}] Party listening on {}, registering with bootnode {} (connect via {})",
            my_id, party_bind, bind, bootnode_connect
        );

        // Register with our own bootnode and wait for the physical party mesh.
        // Every party already validated its local content-addressed artifact.
        let session_info = match register_and_wait_for_session(
            &mut mgr,
            SessionRegistrationConfig {
                execution_id: require_network_execution_id(execution_id),
                bootnode: bootnode_connect,
                my_party_id: my_id,
                my_listen: advertise_addr.unwrap_or(party_bind),
                program_id,
                entry: entry.clone(),
                n_parties: n,
                threshold: t,
                timeout: session_registration_timeout(),
                expected_party_public_keys: None,
            },
        )
        .await
        {
            Ok(info) => info,
            Err(e) => {
                eprintln!("Session registration failed: {}", e);
                exit(12);
            }
        };

        // Use session parameters
        agreed_entry = session_info.entry.clone();
        session_instance_id = Some(session_info.instance_id);
        session_n_parties = Some(session_info.n_parties);
        session_threshold = Some(session_info.threshold);

        eprintln!(
            "[leader/party {}] Session started: instance_id={}, n={}, t={}, entry={}",
            my_id,
            session_info.instance_id,
            session_info.n_parties,
            session_info.threshold,
            agreed_entry
        );

        let net = Arc::new(mgr);
        net_opt = Some(net.clone());
    } else if let Some(bootnode) = bootstrap_addr {
        // Regular party mode: connect to external bootnode
        let bind = bind_addr.expect("party CLI requirements validated");
        let my_id = party_id.expect("party CLI requirements validated");
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("install rustls crypto");

        // Must have program path in party mode
        if path_opt.is_none() {
            eprintln!("Error: party mode requires a program path");
            exit(2);
        }
        let program_path = path_opt.as_ref().unwrap();
        let bytes = std::fs::read(program_path).expect("read program");
        program_id = program_id_from_bytes(&bytes);

        // Get MPC parameters (required for session)
        let n = n_parties.unwrap_or_else(|| {
            eprintln!("Error: --n-parties is required for party mode");
            exit(2);
        });
        let t = threshold.unwrap_or(1);

        // Prepare QUIC manager
        let mut mgr = QuicNetworkManager::with_node_id(my_id);
        if let (Some(cert), Some(key)) = (cert_der.as_ref(), key_der.as_ref()) {
            if let Err(e) = mgr.set_local_certificate_der(cert.clone(), key.clone()) {
                eprintln!("Failed to configure local node certificate: {}", e);
                exit(11);
            }
        }
        // Listen so peers can connect back directly
        local_bind_handoff("STOFFEL_LOCAL_NETWORK_HANDOFF").await;
        if let Err(e) = mgr.listen(bind).await {
            eprintln!("Failed to listen on {}: {}", bind, e);
            exit(11);
        }

        // Note: if using port 0, the OS assigns a port. For now we use the bind address.
        // In a real deployment, you should use specific ports, not port 0.
        let actual_listen = bind;
        eprintln!(
            "[party {}] Listening on {}, connecting to bootnode {}",
            my_id, actual_listen, bootnode
        );

        // Register with bootnode and wait until the physical party mesh is complete.
        let session_info = match register_and_wait_for_session(
            &mut mgr,
            SessionRegistrationConfig {
                execution_id: require_network_execution_id(execution_id),
                bootnode,
                my_party_id: my_id,
                my_listen: advertise_addr.unwrap_or(actual_listen),
                program_id,
                entry: entry.clone(),
                n_parties: n,
                threshold: t,
                timeout: session_registration_timeout(),
                expected_party_public_keys: None,
            },
        )
        .await
        {
            Ok(info) => info,
            Err(e) => {
                eprintln!("Session registration failed: {}", e);
                exit(12);
            }
        };

        // Use session parameters
        agreed_entry = session_info.entry.clone();
        session_instance_id = Some(session_info.instance_id);
        session_n_parties = Some(session_info.n_parties);
        session_threshold = Some(session_info.threshold);

        eprintln!(
            "[party {}] Session started: instance_id={}, n={}, t={}, entry={}",
            my_id,
            session_info.instance_id,
            session_info.n_parties,
            session_info.threshold,
            agreed_entry
        );

        let net = Arc::new(mgr);
        net_opt = Some(net.clone());
    } else {
        // local run: must have path
        if let Some(p) = &path_opt {
            let bytes = std::fs::read(p).expect("read program");
            program_id = program_id_from_bytes(&bytes);
        } else {
            eprintln!("Error: local run requires a program path unless --bootnode or --leader");
            exit(2);
        }
    }

    if let Some(n) = session_n_parties {
        if let Err(error) = backend_kind.validate_party_count(n) {
            eprintln!("Error: {error}");
            exit(2);
        }
    }

    // Load compiled binary from a file path
    let load_path: String = if let Some(p) = path_opt.clone() {
        p
    } else {
        // Use cached program path if we fetched it from bootnode
        let p = stoffel_vm::net::program_sync::program_path(&program_id);
        p.to_string_lossy().to_string()
    };
    // Initialize VM
    let mut vm_builder = VirtualMachine::builder();
    if let Some(path) = &local_store_path {
        let storage = match RedbLocalStorage::new(path) {
            Ok(storage) => storage,
            Err(err) => {
                eprintln!("Error: failed to open local storage: {}", err);
                exit(3);
            }
        };
        vm_builder = vm_builder.with_local_storage(storage);
    }
    let mut vm = vm_builder.build();

    let (function_count, _bytecode_version, client_io_manifest) = if trace_instr {
        // Instruction tracing hooks need the source Instruction stream for each
        // program counter. Use the source-preserving loader only in traced mode;
        // normal execution keeps the low-peak streaming path below.
        let mut f = File::open(&load_path).expect("open binary file");
        let compiled = match CompiledBinary::deserialize(&mut f) {
            Ok(compiled) => compiled,
            Err(err) => {
                eprintln!("Error: invalid compiled program: {:?}", err);
                exit(3);
            }
        };
        let bytecode_version = compiled.version;
        let client_io_manifest = compiled.client_io_manifest.clone();
        let functions = match compiled.try_to_vm_functions() {
            Ok(functions) => functions,
            Err(err) => {
                eprintln!("Error: invalid compiled program: {:?}", err);
                exit(3);
            }
        };
        let function_count = functions.len();
        for function in functions {
            if let Err(err) = vm.try_register_function(function) {
                eprintln!("Error: invalid VM function: {}", err);
                exit(3);
            }
        }
        (function_count, bytecode_version, client_io_manifest)
    } else {
        // Register all functions as they are read and lowered to avoid retaining
        // the compiled or resolved function table beside the runtime program.
        let f = File::open(&load_path).expect("open binary file");
        match CompiledBinary::try_for_each_resolved_vm_function_from_reader(
            &mut BufReader::new(f),
            |header, stream| {
                let mut stream_error = None;
                let result = vm.try_register_resolved_function_without_source(header, || {
                    match stream.next_instruction() {
                        Ok(instruction) => instruction,
                        Err(err) => {
                            stream_error = Some(err);
                            None
                        }
                    }
                });
                if let Some(err) = stream_error {
                    return Err(err);
                }
                result.map_err(|err| {
                    BinaryError::InvalidData(format!("invalid VM function: {err}"))
                })?;
                Ok(())
            },
        ) {
            Ok(result) => result,
            Err(err) => {
                eprintln!("Error: invalid compiled program: {:?}", err);
                exit(3);
            }
        }
    };
    let runtime_client_count = if expected_clients.is_empty() {
        expected_client_count
    } else {
        Some(expected_clients.len())
    };
    let client_input_types = manifest_client_input_types(&client_io_manifest, runtime_client_count);
    let preprocessing_demand = client_io_manifest.preprocessing_demand;
    if function_count == 0 {
        eprintln!("Error: compiled program contains no functions");
        exit(3);
    }

    // Register debugging hooks based on flags
    if trace_instr {
        vm.register_hook(
            |event| {
                matches!(
                    event,
                    HookEvent::BeforeInstructionExecute(_) | HookEvent::AfterInstructionExecute(_)
                )
            },
            |event, ctx: &HookContext| match event {
                HookEvent::BeforeInstructionExecute(instr) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    let pc = ctx.get_current_instruction();
                    eprintln!(
                        "[instr][depth {}][{}][pc {}] BEFORE {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        pc,
                        instr
                    );
                    Ok(())
                }
                HookEvent::AfterInstructionExecute(instr) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    let pc = ctx.get_current_instruction();
                    eprintln!(
                        "[instr][depth {}][{}][pc {}] AFTER  {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        pc,
                        instr
                    );
                    Ok(())
                }
                _ => Ok(()),
            },
            0,
        );
    }

    if trace_regs {
        vm.register_hook(
            |event| {
                matches!(
                    event,
                    HookEvent::RegisterRead(_, _) | HookEvent::RegisterWrite(_, _, _)
                )
            },
            |event, ctx: &HookContext| match event {
                HookEvent::RegisterRead(idx, val) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    let bank = if idx.is_secret() { "secret" } else { "clear" };
                    eprintln!(
                        "[regs][depth {}][{}] R{} ({}[{}]) -> {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        idx.index(),
                        bank,
                        idx.bank_index(),
                        val
                    );
                    Ok(())
                }
                HookEvent::RegisterWrite(idx, old, new) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    let bank = if idx.is_secret() { "secret" } else { "clear" };
                    eprintln!(
                        "[regs][depth {}][{}] R{} ({}[{}]): {:?} -> {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        idx.index(),
                        bank,
                        idx.bank_index(),
                        old,
                        new
                    );
                    Ok(())
                }
                _ => Ok(()),
            },
            0,
        );
    }

    if trace_stack {
        vm.register_hook(
            |event| {
                matches!(
                    event,
                    HookEvent::BeforeFunctionCall(_, _)
                        | HookEvent::AfterFunctionCall(_, _)
                        | HookEvent::StackPush(_)
                        | HookEvent::StackPop(_)
                )
            },
            |event, ctx: &HookContext| match event {
                HookEvent::BeforeFunctionCall(func, args) => {
                    eprintln!(
                        "[stack][depth {}] CALL {} with {:?}",
                        ctx.get_call_depth(),
                        func,
                        args
                    );
                    Ok(())
                }
                HookEvent::AfterFunctionCall(func, ret) => {
                    eprintln!(
                        "[stack][depth {}] RET  {} => {:?}",
                        ctx.get_call_depth(),
                        func,
                        ret
                    );
                    Ok(())
                }
                HookEvent::StackPush(v) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    eprintln!(
                        "[stack][depth {}][{}] PUSH {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        v
                    );
                    Ok(())
                }
                HookEvent::StackPop(v) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    eprintln!(
                        "[stack][depth {}][{}] POP  {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        v
                    );
                    Ok(())
                }
                _ => Ok(()),
            },
            0,
        );
    }

    if !trace_instr {
        vm.discard_vm_source_instructions();
    }

    // =====================================================================
    // COORDINATOR (or no coordinator)
    // =====================================================================

    // Coordinator initialization (both leader and party modes)
    let mut coord_opt: Option<HbOffChainCoordinator<ark_bls12_381::Fr>> = None;
    let mut node_rpc_opt: Option<OffChainNodeRPCServer> = None;
    let mut input_ids: Vec<Vec<u8>> = Vec::new();
    let mut client_input_slots_by_id = std::collections::HashMap::new();
    let mut output_ids: Vec<Vec<u8>> = Vec::new();
    let mut hb_bls12381_coord_engine: Option<
        Arc<HoneyBadgerMpcEngine<ark_bls12_381::Fr, ark_bls12_381::G1Projective>>,
    > = None;
    // Retain every concrete backend/curve engine behind the async trait. VM
    // online execution must always use the cooperative scheduler; limiting this
    // to the BLS12-381 coordinator path makes concurrent jobs block one another.
    let mut cooperative_engine: Option<Arc<dyn AsyncMpcEngine>> = None;
    #[cfg(feature = "statistics")]
    let mut hb_node_counters: Option<Arc<NodeStatisticsCounters>> = None;
    #[cfg(feature = "statistics")]
    let mut avss_node_counters: Option<Arc<AvssNodeStatisticsCounters>> = None;

    if matches!(backend_kind, MpcBackendKind::HoneyBadger) {
        if let Some(ref ca) = coord_addr {
            let execution_id = require_network_execution_id(execution_id);
            let coord = HbOffChainCoordinator::<ark_bls12_381::Fr>::start_rpc_client_for_execution(
                &ca.0,
                ca.1,
                session_threshold.unwrap_or(1) as u64,
                session_n_parties.unwrap_or_else(|| n_parties.unwrap_or(5)) as u64,
                1,
                coordinator_execution_id(execution_id),
                cert_der.clone().expect("--cert required"),
                key_der.clone().expect("--key required"),
            )
            .await
            .unwrap_or_else(|error| {
                eprintln!("Failed to connect to off-chain coordinator: {error}");
                exit(13);
            });
            coord_opt = Some(coord);

            output_ids = expected_clients
                .iter()
                .filter(|path| !path.trim().is_empty())
                .map(|path| extract_pubkey_from_cert(&fs::read(path).expect("read client cert")))
                .collect();
            input_ids = input_client_ids_from_output_ids(
                &output_ids,
                &client_roster,
                &client_input_slots,
                client_input_count,
            );
            client_input_slots_by_id = input_client_slot_map_from_output_ids(
                &output_ids,
                &client_roster,
                &client_input_slots,
                client_input_count,
            )
            .unwrap_or_else(|error| {
                eprintln!("Invalid coordinator client input admission: {error}");
                exit(13);
            });

            if let Some(ref rpc) = rpc_addr {
                let node_cert_der = cert_der.clone().unwrap();
                local_bind_handoff("STOFFEL_LOCAL_RPC_HANDOFF").await;
                let node_rpc = OffChainNodeRPCServer::start_for_execution(
                    &rpc.0,
                    rpc.1,
                    coordinator_execution_id(execution_id),
                    node_cert_der,
                    key_der.clone().unwrap(),
                )
                .await
                .unwrap_or_else(|error| {
                    eprintln!("Failed to start node RPC server: {error}");
                    exit(13);
                });
                node_rpc_opt = Some(node_rpc);
                write_local_runner_marker_or_exit(
                    "STOFFEL_LOCAL_RPC_READY_FILE",
                    "party RPC listener readiness",
                );
            }
        }
    }

    // Keep the scanner guard alive through VM execution. Dropping it cancels
    // the sole physical receive owner and would strand the execution inbox.
    let mut _execution_scanner: Option<ExecutionConnectionScanner> = None;
    let mut _execution_registration: Option<ExecutionInboxRegistrationGuard> = None;

    // If in party mode, configure MPC engine based on selected backend
    if let Some(net) = net_opt.clone() {
        // Use the network-derived party ID (sorted public key index), not the
        // bootnode-assigned one, because send() routes via sorted public keys.
        let my_id = net.local_party_id();
        // Use session parameters (already agreed upon with bootnode)
        let n = session_n_parties.unwrap_or_else(|| net.parties().len());
        let t = session_threshold.unwrap_or(1);
        // Use the session instance_id (agreed with all parties via bootnode)
        let instance_id =
            session_instance_id.expect("session instance_id should be set in party mode");
        let _client_accept_loop = spawn_connection_accept_loop((*net).clone(), my_id);

        eprintln!(
            "[party {}] Creating MPC engine (backend={}): instance_id={}, n={}, t={}",
            my_id,
            backend_kind.name(),
            instance_id,
            n,
            t
        );

        match backend_kind {
            MpcBackendKind::HoneyBadger => {
                let execution_id = require_network_execution_id(execution_id);
                let (mux, inbox, registration, scanner) =
                    start_party_execution_transport(&net, execution_id).unwrap_or_else(|error| {
                        eprintln!("[party {my_id}] Failed to start execution transport: {error}");
                        exit(13);
                    });
                let mut execution_inbox = Some(inbox);
                _execution_registration = Some(registration);
                _execution_scanner = Some(scanner);
                // Phase 1: Coordinator preprocessing trigger
                if let Some(ref mut coord) = coord_opt {
                    eprintln!("[party {my_id}] proposing Preprocessing");
                    coord.start_preprocessing().await.unwrap();
                }
                // Phase 2: Create MPC engine + preprocessing + coordinator input phases
                macro_rules! setup_hb {
                    ($F:ty, $G:ty) => {{
                        match setup_hb_party_for_curve::<$F, $G>(
                            &mut vm,
                            PartySetup {
                                net: net.clone(),
                                reply_mux: mux.clone(),
                                execution_id,
                                execution_inbox: execution_inbox
                                    .take()
                                    .expect("HoneyBadger execution inbox is consumed once"),
                                my_id,
                                identity: storage_identity.unwrap_or_else(|| {
                                    DurableIdentityDigest::from_legacy_party_id(my_id)
                                }),
                                n,
                                t,
                                instance_id,
                                expected_client_count,
                                expected_client_bindings: None,
                                expected_client_reservation_identities: None,
                                client_count_hint: 0,
                                client_input_count,
                                client_input_types: &client_input_types,
                                preprocessing_demand,
                                program_hash: program_id,
                                preproc_store: preproc_store.clone(),
                                preprocessing: PartyPreprocessing::OneShot,
                                execution_tasks: None,
                            },
                        )
                        .await
                        {
                            Ok(engine) => {
                                #[cfg(feature = "statistics")]
                                {
                                    hb_node_counters = engine
                                        .node_handle()
                                        .try_lock()
                                        .ok()
                                        .map(|guard| Arc::clone(&guard.statistics_counters));
                                }
                                cooperative_engine = Some(engine);
                            }
                            Err(e) => {
                                eprintln!("[party {}] HoneyBadger setup failed: {}", my_id, e);
                                exit(13);
                            }
                        };
                    }};
                }

                // Bls12_381 path with coordinator support
                if coord_opt.is_some() && matches!(curve_config, MpcCurveConfig::Bls12_381) {
                    let runtime = match setup_hb_party_for_curve::<
                        ark_bls12_381::Fr,
                        ark_bls12_381::G1Projective,
                    >(
                        &mut vm,
                        PartySetup {
                            net: net.clone(),
                            reply_mux: mux.clone(),
                            execution_id,
                            execution_inbox: execution_inbox
                                .take()
                                .expect("HoneyBadger execution inbox is consumed once"),
                            my_id,
                            identity: storage_identity.unwrap_or_else(|| {
                                DurableIdentityDigest::from_legacy_party_id(my_id)
                            }),
                            n,
                            t,
                            instance_id,
                            expected_client_count: None, // coordinator handles clients
                            expected_client_bindings: None,
                            expected_client_reservation_identities: None,
                            client_count_hint: output_ids.len(),
                            client_input_count,
                            client_input_types: &client_input_types,
                            preprocessing_demand,
                            program_hash: program_id,
                            preproc_store: preproc_store.clone(),
                            preprocessing: PartyPreprocessing::OneShot,
                            execution_tasks: None,
                        },
                    )
                    .await
                    {
                        Ok(engine) => engine,
                        Err(e) => {
                            eprintln!("[party {}] HoneyBadger setup failed: {}", my_id, e);
                            exit(13);
                        }
                    };
                    let engine = runtime;
                    cooperative_engine = Some(engine.clone());
                    if coord_opt.is_some() {
                        engine.enable_client_output_capture().await;
                        hb_bls12381_coord_engine = Some(engine.clone());
                    }

                    // Coordinator mask distribution + input collection
                    if let Some(ref mut coord) = coord_opt {
                        let node_rpc = node_rpc_opt
                            .as_ref()
                            .expect("--rpc-bind required with coordinator");

                        if let Err(e) = collect_hb_coordinator_inputs(
                            &mut vm,
                            &engine,
                            coord,
                            node_rpc,
                            coordinator_execution_id(execution_id),
                            &input_ids,
                            &client_input_slots_by_id,
                            client_input_total,
                            client_input_count,
                            &client_input_types,
                            program_id,
                            0,
                            my_id,
                        )
                        .await
                        {
                            eprintln!(
                                "[party {}] coordinator input collection failed: {}",
                                my_id, e
                            );
                            exit(13);
                        }
                    }
                } else {
                    // No coordinator or non-Bls12_381 curves
                    dispatch_hb_curve!(curve_config, setup_hb, {
                        eprintln!(
                            "Error: curve {} is not supported by honeybadger backend",
                            curve_config.name()
                        );
                        exit(2);
                    })
                }

                eprintln!(
                    "[party {}] HoneyBadger MPC engine set, starting VM execution...",
                    my_id
                );
            }
            MpcBackendKind::Avss => {
                let execution_id = require_network_execution_id(execution_id);
                eprintln!(
                    "[party {}] Setting up AVSS backend (curve: {})...",
                    my_id,
                    curve_config.name()
                );

                if let Some(coord) = coord_addr.clone() {
                    let rpc = rpc_addr.clone().unwrap_or_else(|| {
                        eprintln!("Error: --rpc-bind is required with AVSS coordinator mode");
                        exit(2);
                    });
                    let cert = cert_der.clone().unwrap_or_else(|| {
                        eprintln!("Error: --cert is required with AVSS coordinator mode");
                        exit(2);
                    });
                    let key = key_der.clone().unwrap_or_else(|| {
                        eprintln!("Error: --key is required with AVSS coordinator mode");
                        exit(2);
                    });
                    if let Err(e) = run_avss_coordinated_party(
                        curve_config,
                        &mut vm,
                        net.clone(),
                        my_id,
                        n,
                        t,
                        instance_id,
                        execution_id,
                        coord,
                        rpc,
                        cert,
                        key,
                        &expected_clients,
                        client_input_total,
                        client_input_count,
                        &client_roster,
                        &client_input_slots,
                        &client_input_types,
                        preprocessing_demand,
                        program_id,
                        preproc_store.clone(),
                        as_leader,
                        one_off,
                        &agreed_entry,
                    )
                    .await
                    {
                        eprintln!("[party {}] AVSS coordinator execution failed: {}", my_id, e);
                        exit(13);
                    }
                    return;
                }

                let (mux, inbox, registration, scanner) =
                    start_party_execution_transport(&net, execution_id).unwrap_or_else(|error| {
                        eprintln!(
                            "[party {my_id}] Failed to start AVSS execution transport: {error}"
                        );
                        exit(13);
                    });
                let mut execution_inbox = Some(inbox);
                _execution_registration = Some(registration);
                _execution_scanner = Some(scanner);

                macro_rules! setup_avss {
                    ($F:ty, $G:ty) => {{
                        match setup_avss_party_for_curve::<$F, $G>(
                            &mut vm,
                            PartySetup {
                                net: net.clone(),
                                reply_mux: mux.clone(),
                                execution_id,
                                execution_inbox: execution_inbox
                                    .take()
                                    .expect("AVSS execution inbox is consumed once"),
                                my_id,
                                identity: storage_identity.unwrap_or_else(|| {
                                    DurableIdentityDigest::from_legacy_party_id(my_id)
                                }),
                                n,
                                t,
                                instance_id,
                                expected_client_count,
                                expected_client_bindings: None,
                                expected_client_reservation_identities: None,
                                client_count_hint: expected_client_count.unwrap_or(0),
                                client_input_count,
                                client_input_types: &client_input_types,
                                preprocessing_demand,
                                program_hash: program_id,
                                preproc_store: preproc_store.clone(),
                                preprocessing: PartyPreprocessing::OneShot,
                                execution_tasks: None,
                            },
                        )
                        .await
                        {
                            Ok(engine) => {
                                #[cfg(feature = "statistics")]
                                {
                                    avss_node_counters = engine
                                        .node_handle()
                                        .try_lock()
                                        .ok()
                                        .map(|guard| Arc::clone(&guard.statistics_counters));
                                }
                                cooperative_engine = Some(engine);
                            }
                            Err(e) => {
                                eprintln!("[party {}] AVSS setup failed: {}", my_id, e);
                                exit(13);
                            }
                        }
                    }};
                }

                dispatch_avss_curve!(curve_config, setup_avss);

                eprintln!(
                    "[party {}] AVSS engine set, starting VM execution...",
                    my_id
                );
            }
        }
    }

    // Coordinator: signal MPC execution phase
    if let Some(ref mut coord) = coord_opt {
        eprintln!("[party] proposing MPCExecution");
        if let Err(error) = coord.start_mpc().await {
            eprintln!("Failed to propose coordinator MPCExecution round: {error}");
            exit(13);
        }
        if let Err(error) = coord.wait_for_round(Round::MPCExecution).await {
            eprintln!("Failed waiting for coordinator MPCExecution round: {error}");
            exit(13);
        }
    }

    eprintln!("Starting VM execution of '{}'...", agreed_entry);
    if !client_roster.is_empty() {
        vm.set_client_roster(client_roster.clone());
    }

    // Execute entry function. Prefer the async MPC scheduler when an async-capable
    // engine was installed so secret-share operations yield instead of blocking
    // inside the synchronous VM instruction path.
    //
    // This call is the online phase (preprocessing is already done), so timing it
    // isolates online MPC cost from preprocessing for benchmarking.
    let online_started_at = std::time::Instant::now();
    let (execution_result, cooperative_metrics) = if let Some(engine) = cooperative_engine.as_ref()
    {
        match vm
            .execute_async_with_metrics(&agreed_entry, engine.as_ref())
            .await
        {
            Ok((value, metrics)) => (Ok(value), Some(metrics)),
            Err(error) => (Err(error), None),
        }
    } else {
        (vm.execute(&agreed_entry), None)
    };
    if let Some(metrics) = cooperative_metrics {
        eprintln!(
            "cooperative VM execution: instruction_budget_yields={} online_effect_yields={}",
            metrics.instruction_budget_yields, metrics.online_effect_yields,
        );
    }
    eprintln!(
        "online VM execution complete! EXEC_SECS: {:.3}",
        online_started_at.elapsed().as_secs_f64()
    );

    match execution_result {
        Ok(result) => {
            {
                let mut handled_by_coordinator = false;

                if let Some(ref mut coord) = coord_opt {
                    handled_by_coordinator = true;
                    // Coordinator output delivery
                    let output_share = if output_ids.is_empty() {
                        None
                    } else {
                        coordinator_output_share_bytes(&mut vm, &result)
                    };
                    let captured_outputs = if let Some(engine) = hb_bls12381_coord_engine.as_ref() {
                        engine.drain_client_output_records().await
                    } else {
                        Vec::new()
                    };

                    if output_share.is_some() || !captured_outputs.is_empty() {
                        eprintln!("[party] proposing OutputDistribution");
                        if let Err(error) = coord.send_output().await {
                            eprintln!(
                                "Failed to propose coordinator OutputDistribution round: {error}"
                            );
                            exit(13);
                        }
                        if let Err(error) = coord.wait_for_round(Round::OutputDistribution).await {
                            eprintln!(
                                "Failed waiting for coordinator OutputDistribution round: {error}"
                            );
                            exit(13);
                        }

                        let mut output_shares_by_client: Vec<
                            Vec<HbCoordinatorShare<ark_bls12_381::Fr>>,
                        > = vec![Vec::new(); output_ids.len()];

                        if let Some(output_share) = output_share {
                            let share: HbCoordinatorShare<ark_bls12_381::Fr> =
                                ark_serialize::CanonicalDeserialize::deserialize_compressed(
                                    output_share.as_slice(),
                                )
                                .expect("deserialize output share");
                            for shares in output_shares_by_client.iter_mut() {
                                shares.push(share.clone());
                            }
                        }

                        for record in captured_outputs {
                            let Some(shares) = output_shares_by_client.get_mut(record.client_id)
                            else {
                                eprintln!(
                                    "Execution error in '{}': HoneyBadger output client index {} has no matching coordinator client identity",
                                    agreed_entry, record.client_id
                                );
                                exit(4);
                            };
                            shares.extend(record.shares);
                        }

                        let mut submissions = Vec::with_capacity(output_ids.len());
                        for (cid, output_shares) in
                            output_ids.iter().zip(output_shares_by_client.into_iter())
                        {
                            if output_shares.is_empty() {
                                continue;
                            }
                            submissions.push((cid.clone(), output_shares));
                        }
                        for (cid, result) in send_output_shares_bounded(coord, submissions).await {
                            if let Err(e) = result {
                                eprintln!(
                                    "Failed to submit output shares for client {:?}: {}",
                                    cid, e
                                );
                                exit(13);
                            }
                        }
                    }

                    eprintln!("[party] proposing ProgramFinished");
                    eprintln!("[party] finalizing coordinated execution");
                    if let Err(error) = finish_hb_execution(coord).await {
                        eprintln!("Failed to finalize coordinated execution: {error}");
                        exit(13);
                    }

                    // Request first so the designated party cannot be the final acknowledgement
                    // before the one-off coordinator has armed its graceful drain.
                    if as_leader && one_off {
                        if let Err(e) = coord.request_shutdown().await {
                            eprintln!(
                                "Warning: failed to request off-chain coordinator shutdown: {}",
                                e
                            );
                        }
                    }
                    if one_off {
                        if let Err(error) = coord.retire_execution().await {
                            eprintln!(
                                "Warning: failed to retire completed coordinator execution: {error}"
                            );
                        }
                    }

                    print_vm_result(&mut vm, result.clone());
                }

                if !handled_by_coordinator {
                    print_vm_result(&mut vm, result);
                }
            }
            write_local_runner_marker_or_exit(
                "STOFFEL_LOCAL_COMPLETION_FILE",
                "coordinated execution completion",
            );
        }
        Err(err) => {
            eprintln!("Execution error in '{}': {}", agreed_entry, err);
            exit(4);
        }
    }

    #[cfg(feature = "statistics")]
    if let Some(engine) = hb_bls12381_coord_engine.as_ref() {
        let node = engine.node_handle().lock().await;
        eprintln!(
            "HoneyBadger MPC statistics:\n{}",
            node.statistics_snapshot()
        );
    } else if let Some(counters) = hb_node_counters.as_ref() {
        eprintln!("HoneyBadger MPC statistics:\n{}", counters.snapshot());
    } else if let Some(counters) = avss_node_counters.as_ref() {
        eprintln!("AVSS statistics:\n{}", counters.snapshot());
    }
}

fn print_usage_and_exit() -> ! {
    eprintln!(
        r#"Stoffel VM Runner

Usage:
  stoffel-run <path-to-compiled-binary> [entry_function] [flags]

Flags:
  --standing-node         Run a long-lived concurrent execution host
  --control-dir <path>    Mounted standing-node command/event directory
  --program-dir <path>    Content-addressed standing-node program artifacts
  --client-cert-dir <path>
                          Coordinator client certificates named by standing admissions
  --pool-id <64-hex>      Nonzero identity for the process-lifetime party mesh
  --reservoir-burst-capacity <n>
                          Per-program preprocessing burst capacity warmed before
                          standing readiness (default: 9)
  --allow-dynamic-preprocessing
                          Admit dynamic demand floors (bounded test/example use only)
  --print-program-id <path>
                          Print the domain-separated content ID and exit
  --print-program-manifest <path>
                          Print content ID, entries, and client/preprocessing metadata as JSON
  --trace-instr           Trace instructions before/after execution
  --trace-regs            Trace register reads/writes
  --trace-stack           Trace function calls and stack push/pop
  --bootnode              Run as bootnode only (coordinates party discovery)
  --leader                Run as leader: bootnode + party 0 in one process
  --client                Run as client (provide inputs to MPC network)
  --one-off               After confirming the off-chain coordinator's ProgramFinished
                          round, tell it to shut down (leader only; coordinator must
                          have been started with --one-off itself)
  --bind <addr:port>      Bind address (required in bootnode/leader/party mode)
  --party-id <usize>      Party id (party mode, 0-indexed)
  --bootstrap <addr:port> Bootnode address (required in party mode)
  --n-parties <usize>     Number of parties for MPC (required in every network mode)
  --threshold <usize>     Threshold t (default: 1)
  --mpc-backend <name>    MPC backend: honeybadger (default) or avss
  --mpc-curve <name>      MPC curve: bls12-381 (default), bn254, curve25519, ed25519;
                          AVSS also supports secp256k1 and p-256
  --inputs <values>       Comma-separated input values (client mode)
  --program <path>        Compiled program used to translate client inputs and outputs
                          according to its client-I/O manifest (client mode).
                          The first positional program path has the same semantics.
                          Required in client mode unless --raw-client-io is explicit.
  --client-slot <u64>     Manifest client slot. Usually inferred from --client-index
                          and the manifest's per-client input ranges
  --raw-client-io         Treat --inputs and reconstructed outputs as raw field values,
                          bypassing --program semantics
  --outputs <n>           Number of output field elements to reconstruct (client mode)
  --output-fixed-point-fractional-bits <n>
                          Decode coordinator client outputs as fixed-point values
                          with n fractional bits instead of raw field integers
  --servers <addrs>       Exactly one comma-separated server address per MPC party
  --client-transport-servers <addrs>
                          Coordinator-mode QUIC addresses used to authenticate
                          output-only clients with each standing execution
  --wait-for-clients <n>
                          Number of client inputs to collect before starting computation
                          (HoneyBadger only; ALPN handles routing, this controls coordination)
  --client-input-count <n>
                          Number of input shares each direct host-mode client submits
                          (default: 1; use with --wait-for-clients)
  --off-chain-coord <addr:port>
                          Off-chain coordinator address (required in standing mode)
  --on-chain-coord <address>
                          Temporarily unavailable in the crates.io-ready build
  --eth-node <url>        Reserved for future on-chain coordinator support
  --wallet-sk <hex>       Reserved for future on-chain coordinator support
  --rpc-bind <addr:port>  Node mask-RPC bind address (required with a coordinator)
  --cert <path>           Path to DER-encoded X.509 certificate
  --key <path>            Path to DER-encoded private key
  --client-index <u64>    Reserved coordinator input index (coordinator client mode)
  --preproc-store <path>  Persistent MPC preprocessing store directory
  --local-store <path>    Persistent VM local storage database
  --execution-id <hex>    Nonzero 256-bit execution ID (required in client/leader/party mode)
  --expected-clients <cert-paths>
                          Comma-separated client cert paths for off-chain coordinator mode
  -h, --help              Show this help

Required environment:
  STOFFEL_AUTH_TOKEN      Shared secret required by bootnode and all parties for
                          authenticated discovery registration

Mode contracts:
  Client:    --client, program (or --raw-client-io), --servers, --n-parties,
             and --execution-id. Coordinator clients additionally require --cert/--key;
             input clients require --client-index.
  Party:     program, --party-id, --bootstrap, --bind, --n-parties, and --execution-id.
  Leader:    program, --leader, --bind, --n-parties, and --execution-id.
  Bootnode:  --bootnode, --bind, and --n-parties.
  Coordinator parties additionally require --off-chain-coord, --rpc-bind, --cert, and --key.

Multi-Party Execution:
  In party mode, all parties register with the bootnode and wait until
  all n-parties have joined. The bootnode then broadcasts a session with
  a shared instance_id to all parties, ensuring they all use the same
  MPC configuration.

  Use --leader on one party to have it also run the bootnode. This reduces
  the number of processes needed by one.

Examples:
  # Local execution (no MPC)
  stoffel-run program.stfbin
  stoffel-run program.stfbin main --trace-instr

  # Multi-party execution (5 parties, threshold 1) - Leader mode (recommended)
  # Terminal 1: Leader (bootnode + party 0)
  STOFFEL_AUTH_TOKEN=replace-with-random-secret \
  stoffel-run program.stfbin main --leader --bind 127.0.0.1:9000 --n-parties 5 --threshold 1

  # Terminals 2-5: Other parties
  STOFFEL_AUTH_TOKEN=replace-with-random-secret \
  stoffel-run program.stfbin main --party-id 1 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9002 --n-parties 5 --threshold 1
  STOFFEL_AUTH_TOKEN=replace-with-random-secret \
  stoffel-run program.stfbin main --party-id 2 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9003 --n-parties 5 --threshold 1
  STOFFEL_AUTH_TOKEN=replace-with-random-secret \
  stoffel-run program.stfbin main --party-id 3 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9004 --n-parties 5 --threshold 1
  STOFFEL_AUTH_TOKEN=replace-with-random-secret \
  stoffel-run program.stfbin main --party-id 4 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9005 --n-parties 5 --threshold 1

  # Alternative: Separate bootnode (6 processes total)
  # Terminal 1: Bootnode only
  STOFFEL_AUTH_TOKEN=replace-with-random-secret \
  stoffel-run --bootnode --bind 127.0.0.1:9000 --n-parties 5

  # Terminals 2-6: All parties
  STOFFEL_AUTH_TOKEN=replace-with-random-secret \
  stoffel-run program.stfbin main --party-id 0 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9001 --n-parties 5 --threshold 1
  STOFFEL_AUTH_TOKEN=replace-with-random-secret \
  stoffel-run program.stfbin main --party-id 1 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9002 --n-parties 5 --threshold 1
  # ... etc

  # Multi-party execution with client inputs (canonical sorted client IDs)
  # Terminal 1: Leader with expected client count
  stoffel-run program.stfbin main --leader --bind 127.0.0.1:9000 --n-parties 5 --threshold 1 --wait-for-clients 2

  # Terminals 2-5: Other parties (same expected-client-count)
  stoffel-run program.stfbin main --party-id 1 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9002 --n-parties 5 --wait-for-clients 2
  # ... etc

  # Client mode: provide inputs to the MPC network
  # Note: clients connect directly to party servers, not the bootnode
  stoffel-run --client --program program.stflb --client-slot 0 --inputs 10,20 --servers 127.0.0.1:10000,127.0.0.1:9002,127.0.0.1:9003,127.0.0.1:9004,127.0.0.1:9005 --n-parties 5
  stoffel-run --client --program program.stflb --client-slot 1 --inputs 30,40 --servers 127.0.0.1:10000,127.0.0.1:9002,127.0.0.1:9003,127.0.0.1:9004,127.0.0.1:9005 --n-parties 5

  # Docker example with client inputs:
  # Start parties with expected-client-count:
  # docker run ... -e STOFFEL_EXPECTED_CLIENT_COUNT=2 stoffelvm:latest
  # Then run clients connecting to the party servers:
  stoffel-run --client --program /app/programs/program.stflb --client-slot 0 --inputs 42 --servers 172.18.0.2:9000,172.18.0.3:9000,172.18.0.4:9000,172.18.0.5:9000,172.18.0.6:9000 --n-parties 5
"#
    );
    exit(1);
}

#[cfg(test)]
mod tests {
    use super::{
        band_pow2, bind_admitted_client_slots, canonical_mask_reservation_runs,
        checked_client_input_total, cli_positional_arguments, client_input_completion_quorum,
        client_input_setup_plan, client_output_slot_map, client_program_from_arguments,
        client_schema_for_reserved_index, client_transport_recipient, collect_bounded,
        coordinator_execution_already_retired, decode_preprocessing_exchange,
        direct_client_inbound_message, encode_manifest_client_inputs,
        encode_preprocessing_exchange, field_outputs_to_hex, format_coordinator_outputs,
        format_vm_result, group_output_shares_by_client, hb_input_only_completion_proven,
        input_client_ids_from_output_ids, input_client_slot_map_from_output_ids,
        load_client_manifest_semantics, manifest_client_input_slots, manifest_client_input_types,
        mpc_input_protocol_ids, plan_preprocessing, preprocessing_transcript_ack_if_complete,
        preprocessing_transcript_digest, record_preprocessing_exchange_value,
        render_fixed_point_i64, resolve_client_protocol_bindings, standing_preproc_pool_program_id,
        standing_reservoir_plan, standing_reservoir_refill_execution_id, validate_cli_mode_flags,
        validate_cli_option_values, validate_client_server_count, validate_preprocessing_proposals,
        validate_required_cli_parameters, validate_reservoir_allocation_admission,
        CoordinatorOutputFormat, ExecutionTaskGroup, PreprocessingExchangeFrame,
        PreprocessingExchangeMessage, PreprocessingExchangePhase, ReservoirAllocationSnapshot,
        StandingPreprocessingProposal,
    };
    use std::collections::{BTreeMap, HashSet};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use stoffel_vm::core_vm::VirtualMachine;
    use stoffel_vm::net::mpc_engine::{
        MpcEngine, MpcEngineError, MpcEngineResult, MpcSessionTopology,
    };
    use stoffel_vm::net::session::ExecutionId;
    use stoffel_vm::net::MpcCurveConfig;
    use stoffel_vm::storage::preproc::PreprocMeta;
    use stoffel_vm::storage::preproc::{PoolAvailability, StandingPreprocSnapshot};
    use stoffel_vm_types::compiled_binary::{
        ClientIoManifest, ClientIoSchema, CompiledBinary, DynamicClientInputSchema,
        PreprocessingDemand,
    };
    use stoffel_vm_types::core_types::{
        ClearShareInput, ClearShareValue, ShareData, ShareType, Value,
    };

    #[test]
    fn resolves_positional_client_program_independent_of_option_order() {
        let arguments = |values: &[&str]| {
            values
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
        };

        for values in [
            vec!["program.stflb", "main", "--client"],
            vec!["--client", "program.stflb", "main"],
            vec!["--client", "--client-slot", "3", "program.stflb", "main"],
        ] {
            assert_eq!(
                client_program_from_arguments(&arguments(&values)),
                Some(std::path::PathBuf::from("program.stflb"))
            );
        }

        assert_eq!(
            client_program_from_arguments(&arguments(&[
                "positional.stflb",
                "--program",
                "explicit.stflb",
            ])),
            Some(std::path::PathBuf::from("explicit.stflb"))
        );
        assert_eq!(
            client_program_from_arguments(&arguments(&[
                "--client",
                "--program=explicit.stflb",
                "main",
            ])),
            Some(std::path::PathBuf::from("explicit.stflb"))
        );
        assert_eq!(
            client_program_from_arguments(&arguments(&[
                "--client",
                "--inputs",
                "1,2",
                "--servers",
                "127.0.0.1:9000",
            ])),
            None
        );
    }

    #[test]
    fn cli_positionals_exclude_option_values() {
        let arguments = [
            "--leader",
            "--bind",
            "127.0.0.1:9000",
            "program.stflb",
            "main",
            "--n-parties=5",
            "--execution-id",
            "01",
        ]
        .map(str::to_owned);

        assert_eq!(
            cli_positional_arguments(&arguments),
            vec!["program.stflb".to_owned(), "main".to_owned()]
        );
    }

    #[test]
    fn cli_value_options_reject_missing_values() {
        let missing = ["--client".to_owned(), "--servers".to_owned()];
        assert_eq!(
            validate_cli_option_values(&missing),
            Err("--servers requires a value".to_owned())
        );

        let empty = ["--n-parties=".to_owned()];
        assert_eq!(
            validate_cli_option_values(&empty),
            Err("--n-parties requires a value".to_owned())
        );
    }

    #[test]
    fn cli_modes_reject_ambiguous_or_partial_server_roles() {
        assert!(validate_cli_mode_flags(true, false, true, false, false).is_err());
        assert_eq!(
            validate_cli_mode_flags(false, false, false, true, false),
            Err("party mode requires both --party-id and --bootstrap".to_owned())
        );
        assert!(validate_cli_mode_flags(false, false, false, true, true).is_ok());
    }

    #[test]
    fn cli_required_parameters_report_every_missing_value() {
        assert_eq!(
            validate_required_cli_parameters(
                "party mode",
                &[
                    ("--bind", false),
                    ("--n-parties", true),
                    ("--execution-id", false)
                ],
            ),
            Err("party mode requires --bind, --execution-id".to_owned())
        );
    }

    #[test]
    fn client_server_roster_must_match_party_count() {
        assert!(validate_client_server_count(5, 5).is_ok());
        assert_eq!(
            validate_client_server_count(5, 4),
            Err(
                "client mode requires exactly one --servers address per party (got 4, expected 5)"
                    .to_owned()
            )
        );
    }

    struct OpenCountingEngine {
        opens: Arc<AtomicUsize>,
    }

    impl MpcEngine for OpenCountingEngine {
        fn protocol_name(&self) -> &'static str {
            "open-counting-test"
        }

        fn topology(&self) -> MpcSessionTopology {
            MpcSessionTopology::try_new(7, 0, 3, 1).expect("test topology")
        }

        fn is_ready(&self) -> bool {
            true
        }

        fn start(&self) -> MpcEngineResult<()> {
            Ok(())
        }

        fn input_share(&self, _clear: ClearShareInput) -> MpcEngineResult<ShareData> {
            Err(MpcEngineError::operation_failed(
                "input_share",
                "not used by returned-share formatting test",
            ))
        }

        fn open_share(
            &self,
            _share_type: ShareType,
            _share_bytes: &[u8],
        ) -> MpcEngineResult<ClearShareValue> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            Ok(ClearShareValue::Integer(0))
        }
    }

    #[test]
    fn vm_result_preserves_returned_share_bytes_without_a_runtime_open() {
        let opens = Arc::new(AtomicUsize::new(0));
        let mut vm = VirtualMachine::builder()
            .with_mpc_engine(Arc::new(OpenCountingEngine {
                opens: Arc::clone(&opens),
            }))
            .build();
        let returned = Value::Share(
            ShareType::secret_int(64),
            ShareData::Opaque(vec![0x00, 0x01, 0xfe, 0xff].into()),
        );
        let returned_object = vm
            .create_share_object(
                ShareType::secret_int(64),
                ShareData::Opaque(vec![0x00, 0x01, 0xfe, 0xff].into()),
                2,
            )
            .expect("share object");

        assert_eq!(
            format_vm_result(&mut vm, &returned),
            "share:v1[secret-int:64;opaque;4] 0x0001feff"
        );
        assert_eq!(
            format_vm_result(&mut vm, &returned_object),
            "share:v1[secret-int:64;opaque;4] 0x0001feff"
        );
        assert_eq!(
            opens.load(Ordering::SeqCst),
            0,
            "formatting a return value must never call the MPC open protocol"
        );
    }

    #[test]
    fn vm_result_keeps_clear_returns_unchanged() {
        let mut vm = VirtualMachine::try_new().expect("VM");
        assert_eq!(format_vm_result(&mut vm, &Value::I64(42)), "42");
    }

    #[test]
    fn captured_output_shares_are_batched_once_per_client_in_call_order() {
        let grouped =
            group_output_shares_by_client([(1, vec![10]), (0, vec![20, 21]), (1, vec![11, 12])]);
        assert_eq!(grouped.get(&0), Some(&vec![20, 21]));
        assert_eq!(grouped.get(&1), Some(&vec![10, 11, 12]));
    }

    #[tokio::test]
    async fn bounded_collection_pipelines_work_without_exceeding_its_limit() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut completed = collect_bounded(0..32, 4, |item| {
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            async move {
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(current, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                active.fetch_sub(1, Ordering::SeqCst);
                item
            }
        })
        .await;

        completed.sort_unstable();
        assert_eq!(completed, (0..32).collect::<Vec<_>>());
        assert_eq!(peak.load(Ordering::SeqCst), 4);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn execution_task_group_cancels_drops_and_joins_every_child() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tokio_util::sync::CancellationToken;

        struct ActiveTask {
            active: Arc<AtomicUsize>,
            dropped: Arc<AtomicUsize>,
        }

        impl Drop for ActiveTask {
            fn drop(&mut self) {
                self.active.fetch_sub(1, Ordering::SeqCst);
                self.dropped.fetch_add(1, Ordering::SeqCst);
            }
        }

        let parent = CancellationToken::new();
        let tasks = ExecutionTaskGroup::child_of(&parent);
        let active = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(tokio::sync::Notify::new());

        for _ in 0..3 {
            let active = Arc::clone(&active);
            let dropped = Arc::clone(&dropped);
            let started = Arc::clone(&started);
            tasks.spawn(async move {
                active.fetch_add(1, Ordering::SeqCst);
                let _active = ActiveTask { active, dropped };
                started.notify_one();
                std::future::pending::<()>().await;
            });
        }

        while active.load(Ordering::SeqCst) != 3 {
            started.notified().await;
        }
        assert_eq!(tasks.task_count(), 3);

        // A prepared execution's token cancellation stops each child even
        // before cleanup gets its deterministic abort-and-join pass.
        parent.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while active.load(Ordering::SeqCst) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("execution children must observe parent cancellation");

        tasks.shutdown().await;
        assert_eq!(tasks.task_count(), 0);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(dropped.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn direct_client_downstream_queue_retains_ingress_capacity_lease() {
        use stoffel_vm::net::session::ExecutionId;
        use stoffel_vm::net::{
            encode_execution_frame, ExecutionIngressLimits, ExecutionMessageKind,
            ExecutionTransportMux,
        };

        let execution_id = ExecutionId::from_bytes([0x73; 32]);
        let mux = ExecutionTransportMux::new_client_with_limits(ExecutionIngressLimits {
            inbox_capacity: 2,
            execution_byte_capacity: 3,
            global_byte_capacity: 3,
        })
        .expect("valid client mux");
        let mut inbox = mux.register(execution_id).unwrap();
        let frame =
            encode_execution_frame(execution_id, ExecutionMessageKind::Mpc, &[1, 2, 3]).unwrap();

        mux.route_party_frame(5, &frame).unwrap();
        let routed = direct_client_inbound_message(3, inbox.client.recv().await.unwrap());
        assert_eq!(routed.sender_id, 4);
        let (downstream_tx, mut downstream_rx) = tokio::sync::mpsc::channel(1);
        downstream_tx.send(routed).await.unwrap();

        assert!(
            mux.route_party_frame(5, &frame).is_err(),
            "moving into the protocol queue must not release ingress capacity"
        );
        drop(downstream_rx.recv().await.unwrap());
        mux.route_party_frame(5, &frame)
            .expect("dropping the queued direct-client message releases its lease");
    }

    fn demand(triples: u64, prandbits: u64, prandints: u64, dynamic: bool) -> PreprocessingDemand {
        PreprocessingDemand {
            triples,
            randoms: 0,
            prandbits,
            prandints,
            dynamic,
        }
    }

    #[test]
    fn band_pow2_rounds_up_to_eighth_octave_and_keeps_zero() {
        assert_eq!(band_pow2(0), 0);
        assert_eq!(band_pow2(1), 1);
        // Powers of two and their eighth-octave multiples are exact.
        assert_eq!(band_pow2(16), 16);
        assert_eq!(band_pow2(131072), 131072);
        // 50 → octave floor 32, eighth = 4, round up to 52.
        assert_eq!(band_pow2(50), 52);
        // The banded value never exceeds the demand by more than one eighth of
        // its octave, so a demand that fits the backend capacity stays fitting:
        // 165_696 bands to 180_224 (< the old 262_144 that tripped LimitError).
        assert_eq!(band_pow2(165_696), 180_224);
        for n in [1u64, 7, 9, 100, 1000, 60_000, 134_528, 165_696, 200_000] {
            let b = band_pow2(n);
            assert!(b >= n, "band must not under-provision");
            assert!(
                b <= n + (n / 8) + 8,
                "band over-provisions by at most ~1/8 octave"
            );
        }
    }

    #[test]
    fn standing_preprocessing_storage_is_scoped_by_pool_and_program() {
        let first_pool = ExecutionId::from_bytes([0x11; 32]);
        let second_pool = ExecutionId::from_bytes([0x22; 32]);
        let first_program = [0x33; 32];
        let second_program = [0x44; 32];
        let derived = standing_preproc_pool_program_id(first_pool, first_program);

        assert_eq!(
            derived,
            standing_preproc_pool_program_id(first_pool, first_program)
        );
        assert_ne!(derived, first_program);
        assert_ne!(
            derived,
            standing_preproc_pool_program_id(second_pool, first_program)
        );
        assert_ne!(
            derived,
            standing_preproc_pool_program_id(first_pool, second_program)
        );
    }

    #[test]
    fn standing_reservoir_plan_keeps_one_spare_and_refills_at_one_bundle() {
        let input = ShareType::secret_int(64);
        let manifest = ClientIoManifest {
            clients: vec![
                ClientIoSchema {
                    client_slot: 0,
                    inputs: vec![input],
                    outputs: Vec::new(),
                },
                ClientIoSchema {
                    client_slot: 1,
                    inputs: vec![input, input, input],
                    outputs: Vec::new(),
                },
                ClientIoSchema {
                    client_slot: 2,
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                },
            ],
            ..ClientIoManifest::default()
        };

        let (per_execution, high, material_capacity) =
            standing_reservoir_plan(&manifest, 1, 9).unwrap();
        assert_eq!(material_capacity, 10);
        assert_eq!(
            per_execution.n_random, 6,
            "one baseline pair plus four inputs"
        );
        assert_eq!(high, per_execution.checked_scale(10).unwrap());

        let per_execution = per_execution.availability().unwrap();
        assert!(super::availability_reached_refill_threshold(
            per_execution,
            per_execution,
        ));
        assert!(!super::availability_reached_refill_threshold(
            PoolAvailability {
                beaver: per_execution.beaver.saturating_mul(2),
                random: per_execution.random.saturating_mul(2),
                prand_bit: per_execution.prand_bit.saturating_mul(2),
                prand_int: per_execution.prand_int.saturating_mul(2),
            },
            per_execution,
        ));
    }

    #[test]
    fn standing_client_input_total_is_checked() {
        assert_eq!(checked_client_input_total([1, 3, 0]).unwrap(), 4);
        assert!(checked_client_input_total([usize::MAX, 1])
            .unwrap_err()
            .contains("overflows usize"));
    }

    #[test]
    fn standing_mask_reservations_are_grouped_by_contiguous_client_run() {
        let reservations = [
            (0, Some(4)),
            (1, Some(4)),
            (2, Some(9)),
            (3, Some(9)),
            (4, Some(9)),
            (5, Some(4)),
        ];
        let runs = canonical_mask_reservation_runs(&reservations)
            .unwrap()
            .collect::<Vec<_>>();
        assert_eq!(runs.len(), 3);
        assert_eq!((runs[0].start, runs[0].count, runs[0].client_id), (0, 2, 4));
        assert_eq!((runs[1].start, runs[1].count, runs[1].client_id), (2, 3, 9));
        assert_eq!((runs[2].start, runs[2].count, runs[2].client_id), (5, 1, 4));

        assert!(canonical_mask_reservation_runs(&[(1, Some(4))]).is_err());
        assert!(canonical_mask_reservation_runs(&[(0, None)]).is_err());
    }

    #[test]
    fn reservoir_admission_mismatch_is_separate_from_inventory_repair() {
        use stoffel_vm::storage::preproc::PoolAvailability;

        let local = ReservoirAllocationSnapshot {
            admission_config_digest: [0x93; 32],
            requested: PoolAvailability {
                beaver: 2,
                random: 1,
                prand_bit: 0,
                prand_int: 0,
            },
            inventory: StandingPreprocSnapshot {
                generation_id: Some([0x94; 32]),
                beaver: PreprocMeta {
                    count: 8,
                    consumed: 0,
                    item_size: 96,
                },
                random: PreprocMeta {
                    count: 4,
                    consumed: 0,
                    item_size: 32,
                },
                prand_bit: PreprocMeta::default(),
                prand_int: PreprocMeta::default(),
            },
        };

        let mut divergent_admission = local.clone();
        divergent_admission.admission_config_digest = [0x95; 32];
        let error =
            validate_reservoir_allocation_admission(&local, &[local.clone(), divergent_admission])
                .unwrap_err();
        assert!(error.contains("divergent frozen standing admission"));

        let mut divergent_inventory = local.clone();
        divergent_inventory.inventory.beaver.count -= 1;
        validate_reservoir_allocation_admission(
            &local,
            &[local.clone(), divergent_inventory.clone()],
        )
        .expect("matching admissions leave actual inventory divergence to the refill path");
        assert_ne!(local, divergent_inventory);
    }

    #[test]
    fn preprocessing_inventory_generation_binds_order_backend_and_execution() {
        let execution_id = ExecutionId::from_bytes([0x71; 32]);
        let encode = |value| Some(bincode::serialize(&value).unwrap());
        let inventory = vec![encode(3u64), encode(5u64), encode(8u64)];
        let hb = preprocessing_transcript_digest(
            PreprocessingExchangePhase::HoneyBadgerInventory,
            execution_id,
            &inventory,
        )
        .unwrap();
        assert_eq!(
            hb,
            preprocessing_transcript_digest(
                PreprocessingExchangePhase::HoneyBadgerInventory,
                execution_id,
                &inventory,
            )
            .unwrap()
        );

        let reordered = vec![encode(5u64), encode(3u64), encode(8u64)];
        assert_ne!(
            hb,
            preprocessing_transcript_digest(
                PreprocessingExchangePhase::HoneyBadgerInventory,
                execution_id,
                &reordered,
            )
            .unwrap()
        );
        assert_ne!(
            hb,
            preprocessing_transcript_digest(
                PreprocessingExchangePhase::AvssInventory,
                execution_id,
                &inventory,
            )
            .unwrap()
        );
        assert_ne!(
            hb,
            preprocessing_transcript_digest(
                PreprocessingExchangePhase::HoneyBadgerInventory,
                ExecutionId::from_bytes([0x72; 32]),
                &inventory,
            )
            .unwrap()
        );
        assert!(preprocessing_transcript_digest(
            PreprocessingExchangePhase::HoneyBadgerInventory,
            execution_id,
            &[encode(3u64), None, encode(8u64)],
        )
        .unwrap_err()
        .contains("missing party 1"));
    }

    #[test]
    fn preprocessing_exchange_retries_are_idempotent_and_equivocation_fails() {
        let mut values = vec![None, None];
        record_preprocessing_exchange_value(&mut values, 1, vec![7], "preprocessing value")
            .unwrap();
        record_preprocessing_exchange_value(&mut values, 1, vec![7], "preprocessing value")
            .unwrap();
        let error =
            record_preprocessing_exchange_value(&mut values, 1, vec![8], "preprocessing value")
                .unwrap_err();
        assert!(error.contains("equivocated"));
        assert_eq!(values[1], Some(vec![7]));
    }

    #[test]
    fn preprocessing_ack_is_ready_when_the_last_value_arrives() {
        let execution_id = ExecutionId::from_bytes([0x74; 32]);
        let phase = PreprocessingExchangePhase::HoneyBadgerReady;
        let mut values = vec![Some(vec![1]), None];

        assert!(
            preprocessing_transcript_ack_if_complete(phase, execution_id, &values, None)
                .unwrap()
                .is_none(),
            "an incomplete transcript must not be acknowledged"
        );

        values[1] = Some(vec![2]);
        let completed =
            preprocessing_transcript_ack_if_complete(phase, execution_id, &values, None)
                .unwrap()
                .expect("the final value makes the acknowledgement immediately available");
        assert_eq!(
            decode_preprocessing_exchange(&completed.acknowledgement).unwrap(),
            PreprocessingExchangeFrame {
                phase,
                message: PreprocessingExchangeMessage::Ack(completed.digest),
            }
        );
        assert!(
            preprocessing_transcript_ack_if_complete(
                phase,
                execution_id,
                &values,
                Some(completed.digest),
            )
            .unwrap()
            .is_none(),
            "the same transcript must not trigger another first advertisement"
        );
    }

    #[test]
    fn fresh_preprocessing_generation_binds_every_party_nonce() {
        let execution_id = ExecutionId::from_bytes([0x91; 32]);
        let targets = PoolAvailability {
            beaver: 3,
            random: 5,
            prand_bit: 7,
            prand_int: 11,
        };
        let proposal = |nonce| StandingPreprocessingProposal {
            snapshot: 13u64,
            targets,
            nonce,
        };
        let encode = |value| Some(bincode::serialize(&value).unwrap());
        let first = vec![encode(proposal([0x21; 32])), encode(proposal([0x22; 32]))];
        let second = vec![encode(proposal([0x21; 32])), encode(proposal([0x23; 32]))];

        assert_ne!(
            preprocessing_transcript_digest(
                PreprocessingExchangePhase::HoneyBadgerInventory,
                execution_id,
                &first,
            )
            .unwrap(),
            preprocessing_transcript_digest(
                PreprocessingExchangePhase::HoneyBadgerInventory,
                execution_id,
                &second,
            )
            .unwrap(),
        );
    }

    #[test]
    fn preprocessing_target_mismatch_is_rejected_before_protocol_start() {
        let expected = PoolAvailability {
            beaver: 2,
            random: 4,
            prand_bit: 6,
            prand_int: 8,
        };
        let mut divergent = expected;
        divergent.random += 1;
        let error = validate_preprocessing_proposals(
            vec![
                StandingPreprocessingProposal {
                    snapshot: 1u64,
                    targets: expected,
                    nonce: [0x31; 32],
                },
                StandingPreprocessingProposal {
                    snapshot: 2u64,
                    targets: divergent,
                    nonce: [0x32; 32],
                },
            ],
            expected,
            "test",
        )
        .unwrap_err();
        assert!(error.contains("party 1 proposed divergent"));
    }

    #[test]
    fn identical_preprocessing_proposal_retry_is_idempotent() {
        let proposal = StandingPreprocessingProposal {
            snapshot: 17u64,
            targets: PoolAvailability {
                beaver: 1,
                random: 2,
                prand_bit: 3,
                prand_int: 4,
            },
            nonce: [0x41; 32],
        };
        let mut proposals = vec![None, None];
        record_preprocessing_exchange_value(&mut proposals, 1, proposal, "proposal").unwrap();
        record_preprocessing_exchange_value(&mut proposals, 1, proposal, "proposal").unwrap();

        let mut equivocation = proposal;
        equivocation.nonce[0] ^= 1;
        assert!(
            record_preprocessing_exchange_value(&mut proposals, 1, equivocation, "proposal",)
                .unwrap_err()
                .contains("equivocated")
        );
        assert_eq!(proposals[1], Some(proposal));
    }

    #[test]
    fn preprocessing_exchange_wire_carries_phase() {
        let frame = PreprocessingExchangeFrame {
            phase: PreprocessingExchangePhase::AvssReady,
            message: PreprocessingExchangeMessage::Ack([0x5a; 32]),
        };
        let encoded = encode_preprocessing_exchange(&frame).unwrap();
        assert_eq!(decode_preprocessing_exchange(&encoded).unwrap(), frame);
    }

    #[test]
    fn refill_route_is_bound_to_the_common_trigger() {
        let pool_id = ExecutionId::from_bytes([0x81; 32]);
        let program_id = [0x82; 32];
        let trigger = ExecutionId::from_bytes([0x83; 32]);
        let route = standing_reservoir_refill_execution_id(pool_id, program_id, trigger);
        assert_eq!(
            route,
            standing_reservoir_refill_execution_id(pool_id, program_id, trigger)
        );
        assert_ne!(
            route,
            standing_reservoir_refill_execution_id(
                pool_id,
                program_id,
                ExecutionId::from_bytes([0x84; 32]),
            )
        );
    }

    #[test]
    fn client_transport_routing_keeps_lower_recipient_unchanged() {
        assert_eq!(client_transport_recipient(1, 3), Some(1));
    }

    #[test]
    fn client_transport_routing_shifts_past_local_position_without_leaking() {
        assert_eq!(client_transport_recipient(3, 3), Some(4));
        assert_eq!(client_transport_recipient(4, 3), Some(5));
    }

    #[test]
    fn client_transport_routing_rejects_shift_overflow() {
        assert_eq!(client_transport_recipient(usize::MAX, 0), None);
    }

    #[test]
    fn plan_for_single_division_folds_prandbit_cost_into_triples_and_randoms() {
        // 16 prandbits + 1 prandint (one secure fix64 / constant). prandbit
        // generation consumes a triple + random per bit, so the planned triple
        // and random pools must cover the banded prandbit count. HoneyBadger
        // generates the random shares needed to build triples internally, so the
        // visible random pool is only the baseline plus prandbits.
        let plan = plan_preprocessing(&demand(0, 16, 1, false), 1, 0);
        assert_eq!(plan.n_prandbit, 16);
        assert_eq!(plan.n_prandint, 1);
        assert_eq!(plan.n_triples, 16);
        assert_eq!(plan.n_random, 18);
    }

    #[test]
    fn plan_for_clear_program_still_provisions_minimal_random_pool() {
        let plan = plan_preprocessing(&demand(0, 0, 0, false), 1, 0);
        assert_eq!(plan.n_prandbit, 0);
        assert_eq!(plan.n_prandint, 0);
        assert_eq!(plan.n_triples, 0);
        assert_eq!(plan.n_random, 2);
    }

    #[test]
    fn plan_for_secret_multiplication_floors_to_protocol_triple_batch() {
        // One triple demanded, but the protocol's minimum batch is 2t+1 = 3.
        // Eighth-octave banding leaves 3 as-is (its octave floor is 2, so the
        // granularity is 1). The requested random pool stays at the baseline
        // because HoneyBadger generates the random shares used to build triples
        // inside preprocessing.
        let plan = plan_preprocessing(&demand(1, 0, 0, false), 1, 0);
        assert_eq!(plan.n_prandbit, 0);
        assert_eq!(plan.n_triples, 3);
        assert_eq!(plan.n_random, 2);
    }

    #[test]
    fn plan_gives_dynamic_programs_three_extra_octaves_of_headroom() {
        let stat = plan_preprocessing(&demand(0, 16, 1, false), 1, 0);
        let dyn_ = plan_preprocessing(&demand(0, 16, 1, true), 1, 0);
        // The dynamic flag multiplies the estimate by eight before banding, so
        // the prandbit pool is three octaves larger than the static plan's.
        assert_eq!(stat.n_prandbit, 16);
        assert_eq!(dyn_.n_prandbit, 128);
        assert!(dyn_.n_triples >= stat.n_triples);
    }

    #[test]
    fn formats_negative_field_outputs_as_signed_i64s() {
        let outputs = vec![-ark_bls12_381::Fr::from(10u64)];
        assert_eq!(
            format_coordinator_outputs(&outputs, &CoordinatorOutputFormat::FieldInteger),
            "[-10]"
        );
    }

    #[test]
    fn output_only_clients_do_not_become_input_clients() {
        let output_ids = vec![vec![10], vec![11], vec![12]];

        let input_ids = input_client_ids_from_output_ids(&output_ids, &[0, 1, 2], &[], 0);

        assert!(input_ids.is_empty());
    }

    #[test]
    fn manifest_input_slots_exclude_output_only_clients() {
        let input_types = BTreeMap::from([
            (0, Vec::new()),
            (2, vec![ShareType::default_secret_int()]),
            (5, Vec::new()),
        ]);

        assert_eq!(manifest_client_input_slots(&input_types), vec![2]);
    }

    #[test]
    fn input_only_client_completion_uses_protocol_quorum_not_all_parties() {
        // Regression for split client I/O with n=5,t=1: after parties 0, 2,
        // and 3 supplied mask shares, the client broadcast its masked input.
        // Parties 1 and 4 consumed that RBC before initializing their local
        // InputServer and therefore correctly never sent redundant shares.
        assert_eq!(client_input_completion_quorum(5, 1).unwrap(), 3);
        assert_eq!(client_input_completion_quorum(4, 1).unwrap(), 3);
        assert_eq!(client_input_completion_quorum(1, 0).unwrap(), 1);
    }

    #[test]
    fn input_only_client_completion_rejects_invalid_or_overflowing_topology() {
        let too_few = client_input_completion_quorum(3, 1).unwrap_err();
        assert!(too_few.contains("requires n >= 3t + 1"));

        let empty = client_input_completion_quorum(0, 0).unwrap_err();
        assert!(empty.contains("requires n >= 3t + 1"));

        let overflow = client_input_completion_quorum(usize::MAX, usize::MAX).unwrap_err();
        assert!(overflow.contains("topology overflow"));
    }

    #[test]
    fn honeybadger_input_only_completion_rejects_ok_noop_sender_quorum() {
        // HoneyBadgerMPCClient::process returns Ok for authenticated wrapped
        // messages belonging to another subprotocol. Even a full diagnostic
        // sender quorum must not complete an input-only client until the
        // InputClient's public rbc_done state proves its masked-input
        // broadcast actually started.
        assert!(!hb_input_only_completion_proven(false, 3, 3));
        assert!(!hb_input_only_completion_proven(true, 2, 3));
        assert!(hb_input_only_completion_proven(true, 3, 3));
    }

    #[test]
    fn admitted_client_order_binds_permuted_sparse_manifest_slots() {
        let bindings = bind_admitted_client_slots(&[900, 100, 700], &[9, 2, 41]);
        assert_eq!(bindings[0].protocol_index, 0);
        assert_eq!(bindings[0].route_id, 900);
        assert_eq!(bindings[0].manifest_slot, 9);
        assert_eq!(bindings[1].protocol_index, 1);
        assert_eq!(bindings[1].route_id, 100);
        assert_eq!(bindings[1].manifest_slot, 2);

        // Arrival order cannot change protocol indices; the immutable
        // admission order is retained after observing exactly the admitted set.
        let observed = HashSet::from([700, 900, 100]);
        let resolved = resolve_client_protocol_bindings(Some(&bindings), observed).unwrap();
        assert_eq!(resolved, bindings);
        assert_eq!(
            client_output_slot_map(&resolved),
            BTreeMap::from([(2, 100), (9, 900), (41, 700)])
        );

        let input_types = BTreeMap::from([
            (2, vec![ShareType::default_secret_int(); 2]),
            (9, Vec::new()),
            (41, vec![ShareType::default_secret_int()]),
        ]);
        let plan = client_input_setup_plan(&resolved, &input_types, 99, true);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].protocol_index, 1);
        assert_eq!(plan[0].input_count, 2);
        assert_eq!(plan[1].protocol_index, 2);
        assert_eq!(plan[1].input_count, 1);
    }

    #[test]
    fn admitted_client_resolution_rejects_unknown_or_missing_cert_identity() {
        let bindings = bind_admitted_client_slots(&[10, 20], &[7, 3]);
        let error = resolve_client_protocol_bindings(Some(&bindings), HashSet::from([10, 999]))
            .unwrap_err();

        assert!(error.contains("missing=[20]"));
        assert!(error.contains("unexpected=[999]"));
    }

    #[test]
    fn output_only_setup_skips_input_server_plan_but_retains_inst_and_output_targets() {
        let bindings = bind_admitted_client_slots(&[51, 52], &[8, 27]);
        let input_types = BTreeMap::from([(8, Vec::new()), (27, Vec::new())]);

        let plan = client_input_setup_plan(&bindings, &input_types, 0, true);
        assert!(
            plan.is_empty(),
            "no InputServer state should be initialized"
        );
        assert_eq!(bindings.len(), 2, "both clients still receive INST");
        assert_eq!(
            client_output_slot_map(&bindings),
            BTreeMap::from([(8, 51), (27, 52)])
        );
    }

    #[test]
    fn split_authenticated_input_and_output_clients_gate_only_on_the_input_client() {
        // These route IDs represent two distinct authenticated certificate
        // principals. Slot 4 submits one input and receives no output; slot 9
        // submits no input and remains connected to receive one output.
        let admitted = bind_admitted_client_slots(&[0x51, 0xa2], &[4, 9]);
        let bindings =
            resolve_client_protocol_bindings(Some(&admitted), HashSet::from([0xa2, 0x51])).unwrap();
        let input_types =
            BTreeMap::from([(4, vec![ShareType::default_secret_int()]), (9, Vec::new())]);

        let input_plan = client_input_setup_plan(&bindings, &input_types, 0, true);
        assert_eq!(input_plan.len(), 1);
        assert_eq!(
            mpc_input_protocol_ids(&input_plan),
            vec![0],
            "the output-only authenticated client must not hold the InputServer barrier open"
        );

        // Admission, INST delivery, and output routing still retain both exact
        // authenticated routes; excluding a route from InputServer does not
        // weaken or merge execution-scoped client admission.
        assert_eq!(bindings.len(), 2);
        assert_eq!(
            client_output_slot_map(&bindings),
            BTreeMap::from([(4, 0x51), (9, 0xa2)])
        );
    }

    #[test]
    fn output_only_client_before_input_client_preserves_sparse_protocol_identity() {
        // Protocol indices are admission-order identities. Filtering the input
        // set must not renumber an input client across parties or collide it
        // with the output-only client's authenticated route.
        let admitted = bind_admitted_client_slots(&[0xa2, 0x51], &[9, 4]);
        let bindings =
            resolve_client_protocol_bindings(Some(&admitted), HashSet::from([0x51, 0xa2])).unwrap();
        let input_types =
            BTreeMap::from([(4, vec![ShareType::default_secret_int()]), (9, Vec::new())]);
        let input_plan = client_input_setup_plan(&bindings, &input_types, 0, true);

        assert_eq!(mpc_input_protocol_ids(&input_plan), vec![1]);
        assert_eq!(client_output_slot_map(&bindings).get(&9), Some(&0xa2));
    }

    #[test]
    fn one_shot_client_binding_remains_sorted_ordinal_and_allows_zero_inputs() {
        let bindings = resolve_client_protocol_bindings(None, HashSet::from([91, 17])).unwrap();
        assert_eq!(bindings[0].route_id, 17);
        assert_eq!(bindings[0].manifest_slot, 0);
        assert_eq!(bindings[1].route_id, 91);
        assert_eq!(bindings[1].manifest_slot, 1);
        assert!(client_input_setup_plan(&bindings, &BTreeMap::new(), 0, false).is_empty());
    }

    #[test]
    fn client_input_slots_select_sparse_input_clients_from_output_roster() {
        let output_ids = vec![vec![20], vec![21], vec![22]];

        let input_ids = input_client_ids_from_output_ids(&output_ids, &[0, 2, 5], &[2], 1);

        assert_eq!(input_ids, vec![vec![21]]);
    }

    #[test]
    fn coordinator_input_identity_preserves_permuted_manifest_slots() {
        let output_ids = vec![vec![41], vec![40]];

        let slots =
            input_client_slot_map_from_output_ids(&output_ids, &[1, 0], &[0, 1], 2).unwrap();

        assert_eq!(slots.get(&vec![41]), Some(&1));
        assert_eq!(slots.get(&vec![40]), Some(&0));
    }

    #[test]
    fn terminal_cleanup_recognizes_only_an_already_retired_execution() {
        assert!(coordinator_execution_already_retired(
            "Execution abc is not registered"
        ));
        assert!(!coordinator_execution_already_retired(
            "coordinator transport disconnected"
        ));
    }

    #[test]
    fn missing_client_input_slots_treats_all_one_shot_clients_as_inputs() {
        let output_ids = vec![vec![30], vec![31]];

        let input_ids = input_client_ids_from_output_ids(&output_ids, &[], &[], 1);

        assert_eq!(input_ids, output_ids);
    }

    #[test]
    fn formats_positive_field_outputs_as_signed_i64s() {
        let outputs = vec![ark_bls12_381::Fr::from(10u64)];
        assert_eq!(
            format_coordinator_outputs(&outputs, &CoordinatorOutputFormat::FieldInteger),
            "[10]"
        );
    }

    #[test]
    fn formats_fixed_point_outputs_without_raw_scale() {
        let outputs = vec![
            ark_bls12_381::Fr::from(524_288u64),
            ark_bls12_381::Fr::from(163_840u64),
        ];

        assert_eq!(
            format_coordinator_outputs(
                &outputs,
                &CoordinatorOutputFormat::FixedPoint {
                    fractional_bits: 16
                }
            ),
            "[8, 2.5]"
        );
    }

    #[test]
    fn manifest_client_inputs_are_encoded_from_semantic_values() {
        let inputs = encode_manifest_client_inputs(
            Some("0,1.5,true,255"),
            &[
                ShareType::default_secret_fixed_point(),
                ShareType::default_secret_fixed_point(),
                ShareType::boolean(),
                ShareType::secret_uint(8),
            ],
        )
        .unwrap();

        assert_eq!(inputs.as_deref(), Some("0,98304,1,255"));
    }

    #[test]
    fn coordinator_reserved_ranges_identify_manifest_client_slots() {
        let clients = vec![
            ClientIoSchema {
                client_slot: 0,
                inputs: vec![ShareType::default_secret_int(); 2],
                outputs: Vec::new(),
            },
            ClientIoSchema {
                client_slot: 7,
                inputs: vec![ShareType::default_secret_fixed_point(); 3],
                outputs: Vec::new(),
            },
        ];

        assert_eq!(
            client_schema_for_reserved_index(&clients, 0).map(|schema| schema.client_slot),
            Some(0)
        );
        assert_eq!(
            client_schema_for_reserved_index(&clients, 2).map(|schema| schema.client_slot),
            Some(7)
        );
        assert!(client_schema_for_reserved_index(&clients, 1).is_none());
    }

    #[test]
    fn compiled_manifest_maps_large_reserved_client_ranges() {
        let mut binary = CompiledBinary::new();
        binary.client_io_manifest.clients = vec![
            ClientIoSchema {
                client_slot: 0,
                inputs: vec![ShareType::default_secret_fixed_point(); 4_096],
                outputs: vec![ShareType::default_secret_fixed_point(); 2],
            },
            ClientIoSchema {
                client_slot: 1,
                inputs: vec![ShareType::default_secret_fixed_point(); 4_096],
                outputs: vec![ShareType::default_secret_fixed_point(); 2],
            },
        ];
        let mut artifact = tempfile::NamedTempFile::new().unwrap();
        binary.serialize(artifact.as_file_mut()).unwrap();

        let semantics =
            load_client_manifest_semantics(artifact.path(), None, Some(4_096), 4_096, Some(2))
                .unwrap();

        assert_eq!(semantics.client_slot, 1);
        assert_eq!(semantics.inputs.len(), 4_096);
        assert_eq!(semantics.outputs.len(), 2);
    }

    #[test]
    fn dynamic_manifest_maps_the_hundredth_client_range() {
        let mut binary = CompiledBinary::new();
        binary.client_io_manifest.clients = vec![ClientIoSchema {
            client_slot: 0,
            inputs: vec![ShareType::default_secret_fixed_point(); 4_096],
            outputs: Vec::new(),
        }];
        binary.client_io_manifest.dynamic_client_inputs = vec![DynamicClientInputSchema {
            first_client_slot: 1,
            inputs: vec![ShareType::default_secret_fixed_point(); 4_096],
        }];
        let mut artifact = tempfile::NamedTempFile::new().unwrap();
        binary.serialize(artifact.as_file_mut()).unwrap();

        let semantics =
            load_client_manifest_semantics(artifact.path(), None, Some(99 * 4_096), 4_096, None)
                .unwrap();

        assert_eq!(semantics.client_slot, 99);
        assert_eq!(semantics.inputs.len(), 4_096);
        assert!(semantics
            .inputs
            .iter()
            .all(|share_type| *share_type == ShareType::default_secret_fixed_point()));

        let expanded = manifest_client_input_types(&binary.client_io_manifest, Some(100));
        assert_eq!(expanded.len(), 100);
        assert_eq!(expanded[&99].len(), 4_096);
    }

    #[test]
    fn manifest_client_outputs_are_decoded_by_position() {
        let outputs = vec![
            ark_bls12_381::Fr::from(98_304u64),
            -ark_bls12_381::Fr::from(32_768u64),
            ark_bls12_381::Fr::from(1u64),
            ark_bls12_381::Fr::from(255u64),
        ];
        let format = CoordinatorOutputFormat::Manifest(vec![
            ShareType::default_secret_fixed_point(),
            ShareType::default_secret_fixed_point(),
            ShareType::boolean(),
            ShareType::secret_uint(8),
        ]);

        assert_eq!(
            format_coordinator_outputs(&outputs, &format),
            "[1.5, -0.5, true, 255]"
        );
    }

    #[test]
    fn formats_negative_fixed_point_outputs_without_raw_scale() {
        assert_eq!(
            render_fixed_point_i64(-163_840, 16).as_deref(),
            Some("-2.5")
        );
    }

    #[test]
    fn avss_client_output_hex_concatenates_fixed_width_ecdsa_scalars() {
        let outputs = vec![ark_secp256k1::Fr::from(1u64), ark_secp256k1::Fr::from(2u64)];
        let output_hex = field_outputs_to_hex(&outputs, MpcCurveConfig::Secp256k1);

        assert_eq!(output_hex.len(), 128);
        assert_eq!(
            output_hex,
            format!("{}{}", "0".repeat(63) + "1", "0".repeat(63) + "2")
        );
    }
}
