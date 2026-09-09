// AVSS MPC Engine - Asynchronously Verifiable Secret Sharing
//
// This engine provides AVSS functionality using the AVSS (Asynchronously Verifiable Secret Sharing)
// protocol from mpc-protocols. Each party gets a Feldman-verifiable share where:
// - The share itself is a Shamir share of the secret key
// - commitment[0] = g^secret = the public key
//
// The AVSS protocol produces secret keys for threshold cryptography where no single party
// knows the full secret, but any t+1 parties can collaborate to use it.
//
// Transport identity and authentication are handled by QUIC/TLS (ALPN + certificates).
// AVSS ECDH keys are used separately for protocol payload confidentiality.
//
// The engine is generic over a (field, curve) pair `(F, G)` where `G: CurveGroup<ScalarField = F>`.
// Only tested pairs from `MpcCurveConfig` should be used; arbitrary pairs are not guaranteed
// to work correctly with the AVSS protocol.

use crate::net::engine_config::{DeploymentMode, MpcSessionConfig};
use crate::net::execution_transport::ExecutionScopedNetwork;
use crate::net::mpc_engine::{DurableIdentityDigest, MpcPartyId, MpcSessionTopology};
use ark_ec::CurveGroup;
use ark_ff::{FftField, PrimeField};
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Arc, RwLock as StdRwLock,
};
use std::time::Duration;
use stoffelmpc_mpc::avss_mpc::{
    AvssMPCNode as AvssMpcNode, AvssMPCNodeOpts as AvssMpcNodeOpts, AvssSessionId,
};
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::common::MPCProtocol;
use stoffelnet::network_utils::ClientId;
use stoffelnet::transports::quic::QuicNetworkManager;
use tokio::sync::{Mutex, RwLock};

mod capabilities;
mod client_io;
mod config;
mod engine;
mod operations;
mod preprocessing;
mod session_ids;
mod shares;
#[cfg(test)]
mod tests;
pub use config::AvssEngineConfig;
pub use operations::AvssOperations;
pub use preprocessing::{
    agree_standing_preproc_plan, StandingPreprocAction, StandingPreprocPlan,
    StandingPreprocSnapshot,
};
/// Network type used by the AVSS protocol internals. It is execution-scoped
/// for both one-shot and standing executions.
pub type AvssExecutionNetwork = ExecutionScopedNetwork<QuicNetworkManager>;
pub type Bls12381AvssField = ark_bls12_381::Fr;
pub type Bls12381AvssGroup = ark_bls12_381::G1Projective;
pub type Bls12381AvssShare = FeldmanShamirShare<Bls12381AvssField, Bls12381AvssGroup>;
use session_ids::{field_from_usize, protocol_instance_id_u32, usize_seed, AvssSessionIds};
const DEFAULT_RESET_DRAIN_TIMEOUT_MS: u64 = 30_000;

/// Decode a canonical AVSS scalar, falling back to reducing arbitrary
/// big-endian bytes into the selected scalar field.
pub fn decode_avss_field<F>(bytes: &[u8]) -> Result<F, String>
where
    F: ark_ff::PrimeField + ark_serialize::CanonicalDeserialize,
{
    match F::deserialize_compressed(bytes) {
        Ok(value) => Ok(value),
        Err(_) => Ok(F::from_be_bytes_mod_order(bytes)),
    }
}

pub fn decode_bls12381_avss_field(bytes: &[u8]) -> Result<Bls12381AvssField, String> {
    decode_avss_field(bytes)
}

// ============================================================================

/// Default number of random double-sharing pairs to pre-generate.
const DEFAULT_N_RANDOM_SHARES: usize = 16;
/// Default number of Beaver multiplication triples to pre-generate.
const DEFAULT_N_TRIPLES: usize = 8;

// ============================================================================
// Error types
// ============================================================================

/// Error types for AVSS operations
#[derive(Debug, Clone)]
pub enum AvssError {
    NotReady,
    InvalidShare,
    SessionNotFound(u64),
    Serialization(String),
    Protocol(String),
    InvalidCommitmentIndex(usize),
}

impl std::fmt::Display for AvssError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AvssError::NotReady => write!(f, "AVSS engine not ready"),
            AvssError::InvalidShare => write!(f, "Invalid Feldman share"),
            AvssError::SessionNotFound(id) => write!(f, "Session {} not found", id),
            AvssError::Serialization(msg) => write!(f, "Serialization error: {}", msg),
            AvssError::Protocol(msg) => write!(f, "Protocol error: {}", msg),
            AvssError::InvalidCommitmentIndex(idx) => {
                write!(f, "Invalid commitment index: {}", idx)
            }
        }
    }
}

impl std::error::Error for AvssError {}

// ============================================================================
// AvssMpcEngine<F, G> - Generic AVSS engine
// ============================================================================

/// AVSS MPC Engine that uses AVSS for distributed key generation.
///
/// Generic over field `F` and curve group `G`. The compile-time constraint
/// `G: CurveGroup<ScalarField = F>` ensures that the field and curve are
/// correctly paired, which is required for Feldman commitments in AVSS.
///
/// # Warning
///
/// Only use (F, G) pairs from `MpcCurveConfig`. Using untested pairs may
/// produce incorrect results with the AVSS protocol.
pub struct AvssMpcEngine<F, G>
where
    F: FftField + PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    topology: MpcSessionTopology,
    current_instance_id: AtomicU64,
    local_identity: DurableIdentityDigest,
    /// Physical manager retained for connection admission and status. AVSS
    /// protocol traffic uses `protocol_net`.
    net: Arc<QuicNetworkManager>,
    protocol_net: Arc<AvssExecutionNetwork>,
    input_ids: Vec<ClientId>,
    /// Full AVSS MPC node (share gen, multiplication, preprocessing, message routing)
    avss_node: Arc<Mutex<AvssMpcNode<F, Avid<AvssSessionId>, G>>>,
    in_flight: Arc<AtomicUsize>,
    /// Generated Feldman shares indexed by user-defined key name
    stored_shares: Arc<Mutex<BTreeMap<String, FeldmanShamirShare<F, G>>>>,
    /// Allocates AVSS protocol session IDs in the engine's instance namespace.
    session_ids: AvssSessionIds,
    ready: AtomicBool,
    /// Signaled after `process_wrapped_message` completes, waking `wait_for_share`
    /// and `await_received_share` without polling.
    share_notify: Arc<tokio::sync::Notify>,
    /// This party's AVSS ECDH key used for payload confidentiality.
    /// Transport identity/authentication is handled separately by TLS.
    /// Retained for potential node re-creation; read by the inner `AvssMpcNode`.
    #[allow(dead_code)]
    sk_i: F,
    public_keys: Arc<Vec<G>>,
    _marker: PhantomData<G>,
    /// Persistent preprocessing store.
    preproc_store: tokio::sync::RwLock<Option<Arc<dyn crate::storage::preproc::PreprocStore>>>,
    /// Program hash and field kind for keying stored material.
    preproc_config: tokio::sync::RwLock<Option<([u8; 32], crate::net::curve::MpcFieldKind)>>,
    /// Background reservoir engines persist into the stable program lane while
    /// keeping protocol traffic isolated by their full execution envelope.
    use_program_preproc_reservoir: AtomicBool,
    /// Party-agreed gate for correlated standing AVSS top-up/rebuild.
    standing_preproc_plan: Mutex<Option<preprocessing::StandingPreprocPlan>>,
    /// Maps VM-visible manifest slots to transport-derived client IDs.
    /// One-shot sessions install the equivalent ordinal map (0, 1, ...).
    client_output_id_map: RwLock<BTreeMap<ClientId, ClientId>>,
    /// Manifest-driven maps reject unknown slots; direct one-shot sessions use
    /// transport IDs.
    strict_client_output_id_map: AtomicBool,
    /// Optional in-process capture used by coordinator-backed output delivery.
    client_output_capture: Mutex<Option<Vec<AvssClientOutputRecord<F, G>>>>,
    /// Router that owns open-message accumulation for this AVSS runtime.
    open_message_router: Arc<crate::net::open_registry::OpenMessageRouter>,
    /// Per-instance open share accumulation registry.
    open_registry: StdRwLock<Arc<crate::net::open_registry::InstanceRegistry>>,
    /// Deployment lifetime semantics for one-shot and standing execution.
    deployment_mode: DeploymentMode,
}

pub(super) struct AvssNodeLease<F, G>
where
    F: FftField + PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    node: AvssMpcNode<F, Avid<AvssSessionId>, G>,
    in_flight: Arc<AtomicUsize>,
}

impl<F, G> Deref for AvssNodeLease<F, G>
where
    F: FftField + PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    type Target = AvssMpcNode<F, Avid<AvssSessionId>, G>;

    fn deref(&self) -> &Self::Target {
        &self.node
    }
}

impl<F, G> DerefMut for AvssNodeLease<F, G>
where
    F: FftField + PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.node
    }
}

impl<F, G> Drop for AvssNodeLease<F, G>
where
    F: FftField + PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Clone)]
pub struct AvssClientOutputRecord<F, G>
where
    F: FftField + PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    pub client_id: ClientId,
    pub shares: Vec<FeldmanShamirShare<F, G>>,
}

impl<F, G> AvssMpcEngine<F, G>
where
    F: FftField + PrimeField + Send + Sync + 'static,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    pub(super) async fn clone_avss_node(&self) -> AvssNodeLease<F, G> {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        let node = self.avss_node.lock().await.clone();
        AvssNodeLease {
            node,
            in_flight: self.in_flight.clone(),
        }
    }

    fn reset_drain_timeout() -> Duration {
        let millis = std::env::var("STOFFEL_DRAIN_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_RESET_DRAIN_TIMEOUT_MS);
        Duration::from_millis(millis)
    }

    async fn await_inflight_drained(&self) -> Result<(), String> {
        let timeout = Self::reset_drain_timeout();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.in_flight.load(Ordering::SeqCst) == 0 {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "timed out after {:?} waiting for AVSS in-flight operations to drain",
                    timeout
                ));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn build_node_for_instance(
        &self,
        new_instance_id: u64,
    ) -> Result<AvssMpcNode<F, Avid<AvssSessionId>, G>, String> {
        let (n_random_shares, n_triples) = {
            let node = self.avss_node.lock().await;
            (node.params.n_v_random_shares, node.params.n_triples)
        };
        let opts = AvssMpcNodeOpts::new(
            self.topology.n_parties(),
            self.topology.threshold(),
            n_random_shares,
            n_triples,
            self.sk_i,
            self.public_keys.clone(),
            protocol_instance_id_u32(new_instance_id),
            std::time::Duration::from_secs(60),
        )
        .map_err(|e| format!("Failed to recreate AvssMpcNodeOpts: {:?}", e))?;
        <AvssMpcNode<F, Avid<AvssSessionId>, G> as MPCProtocol<
            F,
            FeldmanShamirShare<F, G>,
            AvssExecutionNetwork,
        >>::setup(self.topology.party_id(), opts, self.input_ids.clone())
        .map_err(|e| format!("Failed to recreate AvssMpcNode: {:?}", e))
    }

    pub(crate) async fn reset_state_for_next_run(
        &self,
        new_instance_id: u64,
    ) -> Result<(), String> {
        let was_ready = self.ready.swap(false, Ordering::SeqCst);
        self.await_inflight_drained().await?;

        let new_node = self.build_node_for_instance(new_instance_id).await?;
        {
            let mut node = self.avss_node.lock().await;
            *node = new_node;
        }
        self.session_ids.reset(new_instance_id);

        let new_registry = self.open_message_router.register_instance(new_instance_id);
        let old_registry = {
            let mut slot = self
                .open_registry
                .write()
                .expect("open registry lock poisoned");
            std::mem::replace(&mut *slot, new_registry)
        };
        let old_ref_count = Arc::strong_count(&old_registry);
        if old_ref_count > 1 {
            tracing::warn!(
                instance_id = old_registry.instance_id(),
                strong_count = old_ref_count,
                "old AVSS open registry still has external references after reset"
            );
        }
        drop(old_registry);

        self.current_instance_id
            .store(new_instance_id, Ordering::SeqCst);
        *self.standing_preproc_plan.lock().await = None;
        self.client_output_id_map.write().await.clear();
        self.strict_client_output_id_map
            .store(false, Ordering::SeqCst);
        {
            let mut capture = self.client_output_capture.lock().await;
            if capture.is_some() {
                *capture = Some(Vec::new());
            }
        }
        self.ready.store(was_ready, Ordering::SeqCst);
        Ok(())
    }

    /// Create a new AVSS engine from a named backend configuration.
    pub async fn from_config(config: AvssEngineConfig<F, G>) -> Result<Arc<Self>, String> {
        let AvssEngineConfig {
            session,
            secret_key,
            public_keys,
            deployment_mode,
            protocol_network,
            n_random_shares,
            n_triples,
        } = config;
        let execution_id = session.execution_id();
        let (topology, local_identity, network, input_ids, open_message_router) =
            session.into_parts();
        let instance_id = topology.instance_id();
        let party_id = topology.party_id();
        let n_parties = topology.n_parties();
        let threshold = topology.threshold();
        crate::net::MpcBackendKind::Avss
            .validate_party_count(n_parties)
            .map_err(|error| error.to_string())?;

        // Create the AvssMpcNode via MPCProtocol::setup
        let instance_id_u32 = protocol_instance_id_u32(instance_id);
        let opts = AvssMpcNodeOpts::new(
            n_parties,
            threshold,
            n_random_shares,
            n_triples,
            secret_key,
            public_keys.clone(),
            instance_id_u32,
            std::time::Duration::from_secs(60),
        )
        .map_err(|e| format!("Failed to create AvssMpcNodeOpts: {:?}", e))?;
        let avss_node = <AvssMpcNode<F, Avid<AvssSessionId>, G> as MPCProtocol<
            F,
            FeldmanShamirShare<F, G>,
            AvssExecutionNetwork,
        >>::setup(party_id, opts, input_ids.clone())
        .map_err(|e| format!("Failed to create AvssMpcNode: {:?}", e))?;

        let protocol_net = match protocol_network {
            Some(network) => network,
            None => ExecutionScopedNetwork::for_party(network.as_ref().clone(), execution_id)
                .map_err(|error| format!("invalid AVSS execution transport: {error}"))?,
        };

        Ok(Arc::new(Self {
            topology,
            current_instance_id: AtomicU64::new(instance_id),
            local_identity,
            net: network,
            protocol_net: Arc::new(protocol_net),
            input_ids: input_ids.clone(),
            avss_node: Arc::new(Mutex::new(avss_node)),
            in_flight: Arc::new(AtomicUsize::new(0)),
            stored_shares: Arc::new(Mutex::new(BTreeMap::new())),
            session_ids: AvssSessionIds::new(instance_id, party_id, n_parties),
            ready: AtomicBool::new(false),
            share_notify: Arc::new(tokio::sync::Notify::new()),
            sk_i: secret_key,
            public_keys,
            _marker: PhantomData,
            preproc_store: tokio::sync::RwLock::new(None),
            preproc_config: tokio::sync::RwLock::new(None),
            use_program_preproc_reservoir: AtomicBool::new(false),
            standing_preproc_plan: Mutex::new(None),
            client_output_id_map: RwLock::new(BTreeMap::new()),
            strict_client_output_id_map: AtomicBool::new(false),
            client_output_capture: Mutex::new(None),
            open_message_router: open_message_router.clone(),
            open_registry: StdRwLock::new(open_message_router.register_instance(instance_id)),
            deployment_mode,
        }))
    }

    pub async fn set_client_output_id_map(&self, client_ids: Vec<ClientId>) {
        *self.client_output_id_map.write().await = client_ids.into_iter().enumerate().collect();
        self.strict_client_output_id_map
            .store(false, Ordering::SeqCst);
    }

    /// Install an explicit VM manifest-slot to authenticated transport mapping.
    /// Standing admissions use this when roster slots are sparse or permuted.
    pub async fn set_client_output_slot_map(&self, client_ids: BTreeMap<ClientId, ClientId>) {
        *self.client_output_id_map.write().await = client_ids;
        self.strict_client_output_id_map
            .store(true, Ordering::SeqCst);
    }

    pub(crate) async fn client_output_transport_id(
        &self,
        client_id: ClientId,
    ) -> Result<ClientId, String> {
        if let Some(transport_id) = self
            .client_output_id_map
            .read()
            .await
            .get(&client_id)
            .copied()
        {
            return Ok(transport_id);
        }
        if self.strict_client_output_id_map.load(Ordering::SeqCst) {
            return Err(format!(
                "VM output references client slot {client_id}, which is not present in the standing admission"
            ));
        }
        Ok(client_id)
    }

    pub async fn enable_client_output_capture(&self) {
        *self.client_output_capture.lock().await = Some(Vec::new());
    }

    pub async fn drain_client_output_records(&self) -> Vec<AvssClientOutputRecord<F, G>> {
        self.client_output_capture
            .lock()
            .await
            .as_mut()
            .map(std::mem::take)
            .unwrap_or_default()
    }

    /// Create a new AVSS engine.
    ///
    /// Prefer [`AvssMpcEngine::from_config`] for new code.
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        instance_id: u64,
        party_id: usize,
        n: usize,
        t: usize,
        net: Arc<QuicNetworkManager>,
        sk_i: F,
        pk_map: Arc<Vec<G>>,
        input_ids: Vec<ClientId>,
    ) -> Result<Arc<Self>, String> {
        let session = MpcSessionConfig::try_new(instance_id, party_id, n, t, net)
            .map_err(|error| error.to_string())?
            .with_input_ids(input_ids);
        Self::from_config(AvssEngineConfig::new(session, sk_i, pk_map)).await
    }

    /// Create a new AVSS engine using a caller-owned open-message router.
    ///
    /// Prefer [`AvssMpcEngine::from_config`] with
    /// [`MpcSessionConfig::with_open_message_router`] for new code.
    #[allow(clippy::too_many_arguments)]
    pub async fn new_with_router(
        open_message_router: Arc<crate::net::open_registry::OpenMessageRouter>,
        instance_id: u64,
        party_id: usize,
        n: usize,
        t: usize,
        net: Arc<QuicNetworkManager>,
        sk_i: F,
        pk_map: Arc<Vec<G>>,
        input_ids: Vec<ClientId>,
    ) -> Result<Arc<Self>, String> {
        let session = MpcSessionConfig::try_new(instance_id, party_id, n, t, net)
            .map_err(|error| error.to_string())?
            .with_input_ids(input_ids)
            .with_open_message_router(open_message_router);
        Self::from_config(AvssEngineConfig::new(session, sk_i, pk_map)).await
    }

    pub fn open_message_router(&self) -> Arc<crate::net::open_registry::OpenMessageRouter> {
        self.open_message_router.clone()
    }

    pub(crate) fn open_registry(&self) -> Arc<crate::net::open_registry::InstanceRegistry> {
        self.open_registry
            .read()
            .expect("open registry lock poisoned")
            .clone()
    }

    pub fn deployment_mode(&self) -> DeploymentMode {
        self.deployment_mode
    }

    pub fn is_standing(&self) -> bool {
        self.deployment_mode == DeploymentMode::Standing
    }

    /// Route persistent preprocessing storage to this program's stable
    /// reservoir lane. Configure this before snapshot agreement/preprocessing.
    pub fn use_program_preproc_reservoir(&self) {
        self.use_program_preproc_reservoir
            .store(true, Ordering::SeqCst);
    }

    /// Returns a handle to the inner MPC node for direct access (e.g., InputServer init).
    pub fn node_handle(&self) -> &Arc<Mutex<AvssMpcNode<F, Avid<AvssSessionId>, G>>> {
        &self.avss_node
    }

    /// Get the validated MPC session topology.
    pub fn topology(&self) -> MpcSessionTopology {
        self.topology
            .with_instance(self.current_instance_id.load(Ordering::SeqCst))
    }

    pub fn current_instance_id(&self) -> u64 {
        self.current_instance_id.load(Ordering::SeqCst)
    }

    /// Get the typed party identity.
    pub fn party(&self) -> MpcPartyId {
        self.topology.party()
    }

    /// Get network manager
    pub fn net(&self) -> Arc<QuicNetworkManager> {
        self.net.clone()
    }

    /// Execution-scoped network used for every AVSS protocol response.
    pub fn protocol_net(&self) -> Arc<AvssExecutionNetwork> {
        self.protocol_net.clone()
    }

    /// Full standing-execution identity carried by the protocol transport.
    pub fn execution_id(&self) -> crate::net::session::ExecutionId {
        self.protocol_net.execution_id()
    }
}

/// Type alias for BLS12-381 AVSS engine
pub type Bls12381AvssMpcEngine = AvssMpcEngine<ark_bls12_381::Fr, ark_bls12_381::G1Projective>;
/// Type alias for BN254 AVSS engine
pub type Bn254AvssMpcEngine = AvssMpcEngine<ark_bn254::Fr, ark_bn254::G1Projective>;
/// Type alias for Curve25519 AVSS engine
pub type Curve25519AvssMpcEngine =
    AvssMpcEngine<ark_curve25519::Fr, ark_curve25519::EdwardsProjective>;
/// Type alias for Ed25519 AVSS engine.
///
/// Note: `ark_ed25519::Fr` is a re-export of `ark_curve25519::Fr`, so
/// field-only metadata is shared with Curve25519. The group type
/// (`EdwardsProjective`) preserves the configured curve identity.
pub type Ed25519AvssMpcEngine = AvssMpcEngine<ark_ed25519::Fr, ark_ed25519::EdwardsProjective>;
/// Type alias for secp256k1 AVSS engine.
pub type Secp256k1AvssMpcEngine = AvssMpcEngine<ark_secp256k1::Fr, ark_secp256k1::Projective>;
/// Type alias for NIST P-256 (secp256r1) AVSS engine.
pub type P256AvssMpcEngine = AvssMpcEngine<ark_secp256r1::Fr, ark_secp256r1::Projective>;
