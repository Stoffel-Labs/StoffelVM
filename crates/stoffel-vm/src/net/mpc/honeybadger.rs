use crate::net::curve::SupportedMpcField;
use crate::net::execution_transport::ExecutionScopedNetwork;
use crate::net::mpc::{honeybadger_node_opts, honeybadger_node_opts_with_truncation};
use crate::net::mpc_engine::{DurableIdentityDigest, MpcPartyId, MpcSessionTopology};
use crate::net::reservation::ReservationRegistry;
use crate::net::session::ExecutionId;
use crate::storage::preproc::PreprocStore;
use ark_ec::{CurveGroup, PrimeGroup};
use std::collections::{BTreeMap, VecDeque};
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;
use stoffelmpc_mpc::common::MPCProtocol;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::HoneyBadgerMPCNode;
use stoffelnet::network_utils::ClientId;
use stoffelnet::transports::quic::QuicNetworkManager;
use tokio::sync::{Mutex, RwLock};

mod capabilities;
mod client_io;
mod config;
mod consensus;
mod engine;
mod operations;
mod preprocessing;
mod reservation;
#[cfg(test)]
mod tests;
pub use config::{HoneyBadgerEngineConfig, HoneyBadgerPreprocessingConfig};
pub use preprocessing::{
    agree_standing_preproc_plan, StandingPreprocAction, StandingPreprocPlan,
    StandingPreprocSnapshot,
};

// RBC/SSS type aliases used by HB implementation
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::honeybadger::SessionId as HbSessionId;
type RBCImpl = Avid<HbSessionId>;
const DEFAULT_RESET_DRAIN_TIMEOUT_MS: u64 = 30_000;

use crate::net::engine_config::{DeploymentMode, MpcSessionConfig};

/// HoneyBadger-backed MPC engine that integrates with the VM.
/// This wraps a real HoneyBadgerMPCNode and provides MPC operations
/// (input sharing, multiplication, output reconstruction) to the VM.
pub struct HoneyBadgerMpcEngine<F = ark_bls12_381::Fr, G = ark_bls12_381::G1Projective>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    topology: MpcSessionTopology,
    current_instance_id: AtomicU64,
    local_identity: DurableIdentityDigest,
    /// Physical manager retained for topology and connection inspection.
    /// MPC protocol sends use `protocol_net`.
    net: Arc<QuicNetworkManager>,
    /// Outbound adapter that envelopes every message with the execution ID.
    protocol_net: Arc<ExecutionScopedNetwork>,
    input_ids: Vec<ClientId>,
    node: Arc<Mutex<HoneyBadgerMPCNode<F, RBCImpl>>>,
    in_flight: Arc<AtomicUsize>,
    ready: AtomicBool,
    group_marker: PhantomData<G>,
    /// Persistent preprocessing store.
    preproc_store: tokio::sync::RwLock<Option<Arc<dyn PreprocStore>>>,
    /// Background reservoir engines persist into the stable program lane while
    /// keeping protocol traffic isolated by their full execution envelope.
    use_program_preproc_reservoir: AtomicBool,
    /// One-shot, party-agreed gate for correlated standing top-up.
    standing_preproc_plan: Mutex<Option<StandingPreprocPlan>>,
    /// Program hash for keying stored material.
    program_hash: tokio::sync::RwLock<Option<[u8; 32]>>,
    /// Durable node identity used for persistent store keys.
    persistent_identity: StdRwLock<DurableIdentityDigest>,
    /// Reservation registry for masked-input protocol.
    reservation: tokio::sync::RwLock<Option<ReservationRegistry>>,
    /// Destructively allocated standing mask shares keyed by the logical
    /// reservation index. Material is removed from LMDB before insertion here
    /// and erased after the masked-input exchange completes.
    reserved_mask_shares: Mutex<BTreeMap<u64, Vec<u8>>>,
    /// Execution-local random shares in consumption order.
    ///
    /// The upstream preprocessing container is a `Vec` whose
    /// `take_random_shares(1)` implementation drains from the front, shifting
    /// every remaining element. Pulling the upstream pool into this deque once
    /// keeps repeated `Share.random_field()` calls linear overall while
    /// preserving the party-aligned share order.
    random_share_cache: Mutex<VecDeque<RobustShare<F>>>,
    /// Optional in-process capture used by coordinator-backed output delivery.
    client_output_capture: Mutex<Option<Vec<HoneyBadgerClientOutputRecord<F>>>>,
    /// Maps VM-visible manifest slots to transport-derived client IDs.
    /// One-shot sessions install the equivalent ordinal map (0, 1, ...).
    client_output_id_map: RwLock<BTreeMap<ClientId, ClientId>>,
    /// Manifest-driven maps reject unknown slots; direct one-shot sessions use
    /// transport IDs.
    strict_client_output_id_map: AtomicBool,
    /// Frozen execution ordinal to certificate-exact durable client identity.
    /// `None` means no standing admission roster was installed; an empty map
    /// is a valid deny-all roster.
    client_reservation_identities: RwLock<Option<BTreeMap<ClientId, DurableIdentityDigest>>>,
    /// Session-local router for open-share/open-exp payloads.
    open_message_router: Arc<crate::net::open_registry::OpenMessageRouter>,
    /// Per-instance open share accumulation registry.
    open_registry: StdRwLock<Arc<crate::net::open_registry::InstanceRegistry>>,
    /// Deployment lifetime semantics for one-shot and standing execution.
    deployment_mode: DeploymentMode,
}

pub(super) struct HoneyBadgerNodeLease<F>
where
    F: SupportedMpcField,
{
    node: HoneyBadgerMPCNode<F, RBCImpl>,
    in_flight: Arc<AtomicUsize>,
}

impl<F> Deref for HoneyBadgerNodeLease<F>
where
    F: SupportedMpcField,
{
    type Target = HoneyBadgerMPCNode<F, RBCImpl>;

    fn deref(&self) -> &Self::Target {
        &self.node
    }
}

impl<F> DerefMut for HoneyBadgerNodeLease<F>
where
    F: SupportedMpcField,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.node
    }
}

impl<F> Drop for HoneyBadgerNodeLease<F>
where
    F: SupportedMpcField,
{
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Clone)]
pub struct HoneyBadgerClientOutputRecord<F>
where
    F: SupportedMpcField,
{
    pub client_id: ClientId,
    pub shares: Vec<RobustShare<F>>,
}

pub type Bls12381HoneyBadgerMpcEngine =
    HoneyBadgerMpcEngine<ark_bls12_381::Fr, ark_bls12_381::G1Projective>;
pub type Bn254HoneyBadgerMpcEngine = HoneyBadgerMpcEngine<ark_bn254::Fr, ark_bn254::G1Projective>;
pub type Curve25519HoneyBadgerMpcEngine =
    HoneyBadgerMpcEngine<ark_curve25519::Fr, ark_curve25519::EdwardsProjective>;
pub type Ed25519HoneyBadgerMpcEngine =
    HoneyBadgerMpcEngine<ark_ed25519::Fr, ark_ed25519::EdwardsProjective>;
pub type Secp256k1HoneyBadgerMpcEngine =
    HoneyBadgerMpcEngine<ark_secp256k1::Fr, ark_secp256k1::Projective>;
pub type P256HoneyBadgerMpcEngine =
    HoneyBadgerMpcEngine<ark_secp256r1::Fr, ark_secp256r1::Projective>;

impl<F, G> HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    pub(super) const fn robust_open_required_contributions(threshold: usize) -> usize {
        3 * threshold + 1
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

    pub fn net(&self) -> Arc<QuicNetworkManager> {
        self.net.clone()
    }

    pub fn execution_id(&self) -> ExecutionId {
        self.protocol_net.execution_id()
    }

    pub fn protocol_network(&self) -> Arc<ExecutionScopedNetwork> {
        Arc::clone(&self.protocol_net)
    }

    pub fn topology(&self) -> MpcSessionTopology {
        self.topology
            .with_instance(self.current_instance_id.load(Ordering::SeqCst))
    }

    pub fn current_instance_id(&self) -> u64 {
        self.current_instance_id.load(Ordering::SeqCst)
    }

    pub(super) async fn clone_node(&self) -> HoneyBadgerNodeLease<F> {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        let node = self.node.lock().await.clone();
        HoneyBadgerNodeLease {
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
                    "timed out after {:?} waiting for HoneyBadger in-flight operations to drain",
                    timeout
                ));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn build_node_for_instance(
        &self,
        new_instance_id: u64,
    ) -> Result<HoneyBadgerMPCNode<F, RBCImpl>, String> {
        let (n_triples, n_random_shares, n_prandbit, n_prandint) = {
            let node = self.node.lock().await;
            (
                node.params.n_triples,
                node.params.n_random_shares,
                node.params.n_prandbit,
                node.params.n_prandint,
            )
        };
        let mpc_opts = honeybadger_node_opts_with_truncation(
            self.topology.n_parties(),
            self.topology.threshold(),
            n_triples,
            n_random_shares,
            n_prandbit,
            n_prandint,
            new_instance_id,
        )?;
        <HoneyBadgerMPCNode<F, RBCImpl> as MPCProtocol<
            F,
            RobustShare<F>,
            QuicNetworkManager,
        >>::setup(self.topology.party_id(), mpc_opts, self.input_ids.clone())
        .map_err(|e| format!("Failed to recreate HoneyBadger MPC node: {:?}", e))
    }

    pub(crate) async fn reset_state_for_next_run(
        &self,
        new_instance_id: u64,
    ) -> Result<(), String> {
        let was_ready = self.ready.swap(false, Ordering::SeqCst);
        self.await_inflight_drained().await?;

        let new_node = self.build_node_for_instance(new_instance_id).await?;
        {
            let mut node = self.node.lock().await;
            *node = new_node;
        }

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
                "old HoneyBadger open registry still has external references after reset"
            );
        }
        drop(old_registry);

        self.current_instance_id
            .store(new_instance_id, Ordering::SeqCst);
        *self.reservation.write().await = None;
        self.reserved_mask_shares.lock().await.clear();
        self.random_share_cache.lock().await.clear();
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

    pub fn deployment_mode(&self) -> DeploymentMode {
        self.deployment_mode
    }

    pub fn is_standing(&self) -> bool {
        self.deployment_mode == DeploymentMode::Standing
    }

    pub fn party(&self) -> MpcPartyId {
        self.topology.party()
    }

    pub(crate) fn persistent_identity(&self) -> DurableIdentityDigest {
        *self
            .persistent_identity
            .read()
            .expect("persistent identity lock poisoned")
    }

    pub fn set_preproc_store_identity(&self, identity: DurableIdentityDigest) {
        *self
            .persistent_identity
            .write()
            .expect("persistent identity lock poisoned") = identity;
    }

    /// Route persistent preprocessing storage to this program's stable
    /// reservoir lane. Configure this before snapshot agreement/preprocessing.
    pub fn use_program_preproc_reservoir(&self) {
        self.use_program_preproc_reservoir
            .store(true, Ordering::SeqCst);
    }

    pub fn from_config(config: HoneyBadgerEngineConfig) -> Result<Arc<Self>, String> {
        let HoneyBadgerEngineConfig {
            session,
            preprocessing,
            deployment_mode,
        } = config;
        let execution_id = session.execution_id();
        let (topology, local_identity, network, input_ids, open_message_router) =
            session.into_parts();
        let protocol_net = ExecutionScopedNetwork::for_party((*network).clone(), execution_id)
            .map_err(|error| format!("invalid HoneyBadger execution transport: {error}"))?;
        let instance_id = topology.instance_id();
        let party_id = topology.party_id();
        let n_parties = topology.n_parties();
        let threshold = topology.threshold();

        // Create the MPC node options
        let mpc_opts = honeybadger_node_opts(
            n_parties,
            threshold,
            preprocessing.triples,
            preprocessing.random_shares,
            instance_id,
        )?;

        // Create the MPC node
        let node = <HoneyBadgerMPCNode<F, RBCImpl> as MPCProtocol<
            F,
            RobustShare<F>,
            QuicNetworkManager,
        >>::setup(party_id, mpc_opts, input_ids.clone())
        .map_err(|e| format!("Failed to create MPC node: {:?}", e))?;

        Ok(Arc::new(Self {
            topology,
            current_instance_id: AtomicU64::new(instance_id),
            local_identity,
            net: network,
            protocol_net: Arc::new(protocol_net),
            input_ids: input_ids.clone(),
            node: Arc::new(Mutex::new(node)),
            in_flight: Arc::new(AtomicUsize::new(0)),
            ready: AtomicBool::new(false),
            group_marker: PhantomData,
            preproc_store: tokio::sync::RwLock::new(None),
            use_program_preproc_reservoir: AtomicBool::new(false),
            standing_preproc_plan: Mutex::new(None),
            program_hash: tokio::sync::RwLock::new(None),
            persistent_identity: StdRwLock::new(local_identity),
            reservation: tokio::sync::RwLock::new(None),
            reserved_mask_shares: Mutex::new(BTreeMap::new()),
            random_share_cache: Mutex::new(VecDeque::new()),
            client_output_capture: Mutex::new(None),
            client_output_id_map: RwLock::new(BTreeMap::new()),
            strict_client_output_id_map: AtomicBool::new(false),
            client_reservation_identities: RwLock::new(None),
            open_registry: StdRwLock::new(open_message_router.register_instance(instance_id)),
            open_message_router,
            deployment_mode,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        instance_id: u64,
        party_id: usize,
        n: usize,
        t: usize,
        n_triples: usize,
        n_random: usize,
        net: Arc<QuicNetworkManager>,
        input_ids: Vec<ClientId>,
    ) -> Result<Arc<Self>, String> {
        let session = MpcSessionConfig::try_new(instance_id, party_id, n, t, net)
            .map_err(|error| error.to_string())?
            .with_input_ids(input_ids);
        let preprocessing = HoneyBadgerPreprocessingConfig::new(n_triples, n_random);
        Self::from_config(HoneyBadgerEngineConfig::new(session, preprocessing))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_router(
        open_message_router: Arc<crate::net::open_registry::OpenMessageRouter>,
        instance_id: u64,
        party_id: usize,
        n: usize,
        t: usize,
        n_triples: usize,
        n_random: usize,
        net: Arc<QuicNetworkManager>,
        input_ids: Vec<ClientId>,
    ) -> Result<Arc<Self>, String> {
        let session = MpcSessionConfig::try_new(instance_id, party_id, n, t, net)
            .map_err(|error| error.to_string())?
            .with_input_ids(input_ids)
            .with_open_message_router(open_message_router);
        let preprocessing = HoneyBadgerPreprocessingConfig::new(n_triples, n_random);
        Self::from_config(HoneyBadgerEngineConfig::new(session, preprocessing))
    }

    /// Construct an engine from an existing, network-driven HoneyBadgerMPCNode.
    /// This avoids creating a separate node that isn't wired into the message loop.
    pub fn try_from_existing_node(
        instance_id: u64,
        party_id: usize,
        n: usize,
        t: usize,
        net: Arc<QuicNetworkManager>,
        node: HoneyBadgerMPCNode<F, RBCImpl>,
    ) -> Result<Arc<Self>, crate::net::mpc_engine::MpcSessionTopologyError> {
        Self::try_from_existing_node_with_router(
            Arc::new(crate::net::open_registry::OpenMessageRouter::new()),
            instance_id,
            party_id,
            n,
            t,
            net,
            node,
        )
    }

    pub fn try_from_existing_node_with_router(
        open_message_router: Arc<crate::net::open_registry::OpenMessageRouter>,
        instance_id: u64,
        party_id: usize,
        n: usize,
        t: usize,
        net: Arc<QuicNetworkManager>,
        node: HoneyBadgerMPCNode<F, RBCImpl>,
    ) -> Result<Arc<Self>, crate::net::mpc_engine::MpcSessionTopologyError> {
        let topology = MpcSessionTopology::try_new(instance_id, party_id, n, t)?;
        Ok(Self::from_existing_node_with_router_and_topology(
            open_message_router,
            topology,
            DurableIdentityDigest::from_legacy_party_id(party_id),
            net,
            node,
        ))
    }

    pub fn from_existing_node_with_topology(
        topology: MpcSessionTopology,
        net: Arc<QuicNetworkManager>,
        node: HoneyBadgerMPCNode<F, RBCImpl>,
    ) -> Arc<Self> {
        Self::from_existing_node_with_router_and_topology(
            Arc::new(crate::net::open_registry::OpenMessageRouter::new()),
            topology,
            DurableIdentityDigest::from_legacy_party_id(topology.party_id()),
            net,
            node,
        )
    }

    pub fn from_existing_node_with_router_and_topology(
        open_message_router: Arc<crate::net::open_registry::OpenMessageRouter>,
        topology: MpcSessionTopology,
        local_identity: DurableIdentityDigest,
        net: Arc<QuicNetworkManager>,
        node: HoneyBadgerMPCNode<F, RBCImpl>,
    ) -> Arc<Self> {
        Self::from_existing_node_with_router_topology_and_mode(
            open_message_router,
            topology,
            local_identity,
            net,
            node,
            DeploymentMode::OneShot,
        )
    }

    pub fn from_existing_node_with_router_topology_and_mode(
        open_message_router: Arc<crate::net::open_registry::OpenMessageRouter>,
        topology: MpcSessionTopology,
        local_identity: DurableIdentityDigest,
        net: Arc<QuicNetworkManager>,
        node: HoneyBadgerMPCNode<F, RBCImpl>,
        deployment_mode: DeploymentMode,
    ) -> Arc<Self> {
        let execution_id =
            crate::net::session::derive_execution_id_for_instance(topology.instance_id());
        let protocol_net = Arc::new(
            ExecutionScopedNetwork::for_party((*net).clone(), execution_id)
                .expect("derived one-shot execution IDs are nonzero"),
        );
        Self::from_existing_node_with_transport(
            open_message_router,
            topology,
            local_identity,
            net,
            protocol_net,
            node,
            deployment_mode,
        )
    }

    /// Wrap an already network-driven node with an execution-scoped transport.
    /// This is the runner/supervisor constructor for concurrent executions.
    #[allow(clippy::too_many_arguments)]
    pub fn try_from_existing_node_for_execution(
        open_message_router: Arc<crate::net::open_registry::OpenMessageRouter>,
        topology: MpcSessionTopology,
        local_identity: DurableIdentityDigest,
        net: Arc<QuicNetworkManager>,
        protocol_net: ExecutionScopedNetwork,
        node: HoneyBadgerMPCNode<F, RBCImpl>,
        deployment_mode: DeploymentMode,
    ) -> Result<Arc<Self>, String> {
        Ok(Self::from_existing_node_with_transport(
            open_message_router,
            topology,
            local_identity,
            net,
            Arc::new(protocol_net),
            node,
            deployment_mode,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn from_existing_node_with_transport(
        open_message_router: Arc<crate::net::open_registry::OpenMessageRouter>,
        topology: MpcSessionTopology,
        local_identity: DurableIdentityDigest,
        net: Arc<QuicNetworkManager>,
        protocol_net: Arc<ExecutionScopedNetwork>,
        node: HoneyBadgerMPCNode<F, RBCImpl>,
        deployment_mode: DeploymentMode,
    ) -> Arc<Self> {
        let instance_id = topology.instance_id();
        let node = Arc::new(Mutex::new(node));
        Arc::new(Self {
            topology,
            current_instance_id: AtomicU64::new(instance_id),
            local_identity,
            net,
            protocol_net,
            input_ids: Vec::new(),
            node,
            in_flight: Arc::new(AtomicUsize::new(0)),
            ready: AtomicBool::new(true),
            group_marker: PhantomData,
            preproc_store: tokio::sync::RwLock::new(None),
            use_program_preproc_reservoir: AtomicBool::new(false),
            standing_preproc_plan: Mutex::new(None),
            program_hash: tokio::sync::RwLock::new(None),
            persistent_identity: StdRwLock::new(local_identity),
            reservation: tokio::sync::RwLock::new(None),
            reserved_mask_shares: Mutex::new(BTreeMap::new()),
            random_share_cache: Mutex::new(VecDeque::new()),
            client_output_capture: Mutex::new(None),
            client_output_id_map: RwLock::new(BTreeMap::new()),
            strict_client_output_id_map: AtomicBool::new(false),
            client_reservation_identities: RwLock::new(None),
            open_registry: StdRwLock::new(open_message_router.register_instance(instance_id)),
            open_message_router,
            deployment_mode,
        })
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

    /// Install the immutable client principal roster for a standing execution.
    /// Identical retries are harmless; changing an installed ordinal is not.
    pub async fn install_standing_client_identities(
        &self,
        identities: BTreeMap<ClientId, DurableIdentityDigest>,
    ) -> Result<(), String> {
        if !self.is_standing() {
            return Err("standing client identities require a standing engine".to_owned());
        }
        let mut installed = self.client_reservation_identities.write().await;
        match installed.as_ref() {
            Some(existing) if existing == &identities => Ok(()),
            Some(_) => Err("standing client identity roster is immutable".to_owned()),
            None => {
                *installed = Some(identities);
                Ok(())
            }
        }
    }

    pub(crate) async fn client_identity(
        &self,
        client_id: ClientId,
    ) -> Result<DurableIdentityDigest, String> {
        if self.is_standing() {
            return self
                .client_reservation_identities
                .read()
                .await
                .as_ref()
                .ok_or_else(|| {
                    "standing client identity roster was not installed for this execution"
                        .to_owned()
                })?
                .get(&client_id)
                .copied()
                .ok_or_else(|| {
                    format!(
                        "client protocol ordinal {client_id} is not admitted for this execution"
                    )
                });
        }

        Ok(self
            .net
            .client_public_key_bytes_by_transport_id(client_id)
            .or_else(|| self.net.client_public_key_bytes(client_id))
            .map(|key| DurableIdentityDigest::from_public_key_bytes(&key))
            .unwrap_or_else(|| DurableIdentityDigest::from_legacy_party_id(client_id)))
    }

    pub async fn enable_client_output_capture(&self) {
        *self.client_output_capture.lock().await = Some(Vec::new());
    }

    pub async fn drain_client_output_records(&self) -> Vec<HoneyBadgerClientOutputRecord<F>> {
        self.client_output_capture
            .lock()
            .await
            .as_mut()
            .map(std::mem::take)
            .unwrap_or_default()
    }

    /// Returns a handle to the inner MPC node for direct access (e.g., InputServer init).
    pub fn node_handle(&self) -> &Arc<Mutex<HoneyBadgerMPCNode<F, RBCImpl>>> {
        &self.node
    }
}
