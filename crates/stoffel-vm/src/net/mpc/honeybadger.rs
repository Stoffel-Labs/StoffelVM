use crate::net::curve::SupportedMpcField;
use crate::net::mpc::honeybadger_node_opts;
use crate::net::mpc_engine::{MpcPartyId, MpcSessionTopology};
use crate::net::reservation::ReservationRegistry;
use crate::storage::preproc::PreprocStore;
use ark_ec::{CurveGroup, PrimeGroup};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::Arc;
use stoffelmpc_mpc::common::MPCProtocol;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::HoneyBadgerMPCNode;
use stoffelnet::network_utils::ClientId;
use stoffelnet::transports::quic::QuicNetworkManager;
use tokio::sync::Mutex;

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

// RBC/SSS type aliases used by HB implementation
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::honeybadger::SessionId as HbSessionId;
type RBCImpl = Avid<HbSessionId>;

use crate::net::engine_config::MpcSessionConfig;

/// HoneyBadger-backed MPC engine that integrates with the VM.
/// This wraps a real HoneyBadgerMPCNode and provides MPC operations
/// (input sharing, multiplication, output reconstruction) to the VM.
pub struct HoneyBadgerMpcEngine<F = ark_bls12_381::Fr, G = ark_bls12_381::G1Projective>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    topology: MpcSessionTopology,
    net: Arc<QuicNetworkManager>,
    node: Arc<Mutex<HoneyBadgerMPCNode<F, RBCImpl>>>,
    ready: AtomicBool,
    group_marker: PhantomData<G>,
    /// Persistent preprocessing store.
    preproc_store: tokio::sync::RwLock<Option<Arc<dyn PreprocStore>>>,
    /// Program hash for keying stored material.
    program_hash: tokio::sync::RwLock<Option<[u8; 32]>>,
    /// Stable operator-assigned party slot used for persistent store keys.
    persistent_party_id: AtomicUsize,
    /// Reservation registry for masked-input protocol.
    reservation: tokio::sync::RwLock<Option<ReservationRegistry>>,
    /// Session-local router for open-share/open-exp payloads.
    open_message_router: Arc<crate::net::open_registry::OpenMessageRouter>,
    /// Per-instance open share accumulation registry.
    open_registry: Arc<crate::net::open_registry::InstanceRegistry>,
}

pub type Bls12381HoneyBadgerMpcEngine =
    HoneyBadgerMpcEngine<ark_bls12_381::Fr, ark_bls12_381::G1Projective>;
pub type Bn254HoneyBadgerMpcEngine = HoneyBadgerMpcEngine<ark_bn254::Fr, ark_bn254::G1Projective>;
pub type Curve25519HoneyBadgerMpcEngine =
    HoneyBadgerMpcEngine<ark_curve25519::Fr, ark_curve25519::EdwardsProjective>;
pub type Ed25519HoneyBadgerMpcEngine =
    HoneyBadgerMpcEngine<ark_ed25519::Fr, ark_ed25519::EdwardsProjective>;

impl<F, G> HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    pub fn open_message_router(&self) -> Arc<crate::net::open_registry::OpenMessageRouter> {
        self.open_message_router.clone()
    }

    pub fn net(&self) -> Arc<QuicNetworkManager> {
        self.net.clone()
    }

    pub fn topology(&self) -> MpcSessionTopology {
        self.topology
    }

    pub(super) async fn clone_node(&self) -> HoneyBadgerMPCNode<F, RBCImpl> {
        self.node.lock().await.clone()
    }

    pub fn party(&self) -> MpcPartyId {
        self.topology.party()
    }

    pub fn from_config(config: HoneyBadgerEngineConfig) -> Result<Arc<Self>, String> {
        let HoneyBadgerEngineConfig {
            session,
            preprocessing,
        } = config;
        let (topology, network, input_ids, open_message_router) = session.into_parts();
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
        >>::setup(party_id, mpc_opts, input_ids)
        .map_err(|e| format!("Failed to create MPC node: {:?}", e))?;

        Ok(Arc::new(Self {
            topology,
            net: network,
            node: Arc::new(Mutex::new(node)),
            ready: AtomicBool::new(false),
            group_marker: PhantomData,
            preproc_store: tokio::sync::RwLock::new(None),
            program_hash: tokio::sync::RwLock::new(None),
            persistent_party_id: AtomicUsize::new(party_id),
            reservation: tokio::sync::RwLock::new(None),
            open_registry: open_message_router.register_instance(instance_id),
            open_message_router,
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
            net,
            node,
        )
    }

    pub fn from_existing_node_with_router_and_topology(
        open_message_router: Arc<crate::net::open_registry::OpenMessageRouter>,
        topology: MpcSessionTopology,
        net: Arc<QuicNetworkManager>,
        node: HoneyBadgerMPCNode<F, RBCImpl>,
    ) -> Arc<Self> {
        let instance_id = topology.instance_id();
        let party_id = topology.party_id();
        let node = Arc::new(Mutex::new(node));
        Arc::new(Self {
            topology,
            net,
            node,
            ready: AtomicBool::new(true),
            group_marker: PhantomData,
            preproc_store: tokio::sync::RwLock::new(None),
            program_hash: tokio::sync::RwLock::new(None),
            persistent_party_id: AtomicUsize::new(party_id),
            reservation: tokio::sync::RwLock::new(None),
            open_registry: open_message_router.register_instance(instance_id),
            open_message_router,
        })
    }

    /// Returns a handle to the inner MPC node for direct access (e.g., InputServer init).
    pub fn node_handle(&self) -> &Arc<Mutex<HoneyBadgerMPCNode<F, RBCImpl>>> {
        &self.node
    }
}
