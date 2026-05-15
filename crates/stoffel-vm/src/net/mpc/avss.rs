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

use crate::net::engine_config::MpcSessionConfig;
use crate::net::mpc_engine::{MpcPartyId, MpcSessionTopology};
use ark_ec::CurveGroup;
use ark_ff::{FftField, PrimeField};
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::{atomic::AtomicBool, Arc};
use stoffelmpc_mpc::avss_mpc::{
    AvssMPCNode as AvssMpcNode, AvssMPCNodeOpts as AvssMpcNodeOpts, AvssSessionId,
};
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::common::MPCProtocol;
use stoffelnet::network_utils::ClientId;
use stoffelnet::transports::quic::QuicNetworkManager;
use tokio::sync::Mutex;

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
use session_ids::{field_from_usize, protocol_instance_id_u32, usize_seed, AvssSessionIds};

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
    net: Arc<QuicNetworkManager>,
    /// Full AVSS MPC node (share gen, multiplication, preprocessing, message routing)
    avss_node: Arc<Mutex<AvssMpcNode<F, Avid<AvssSessionId>, G>>>,
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
    _marker: PhantomData<G>,
    /// Persistent preprocessing store.
    preproc_store: tokio::sync::RwLock<Option<Arc<dyn crate::storage::preproc::PreprocStore>>>,
    /// Program hash and field kind for keying stored material.
    preproc_config: tokio::sync::RwLock<Option<([u8; 32], crate::net::curve::MpcFieldKind)>>,
    /// Router that owns open-message accumulation for this AVSS runtime.
    open_message_router: Arc<crate::net::open_registry::OpenMessageRouter>,
    /// Per-instance open share accumulation registry.
    open_registry: Arc<crate::net::open_registry::InstanceRegistry>,
}

impl<F, G> AvssMpcEngine<F, G>
where
    F: FftField + PrimeField + Send + Sync + 'static,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    pub(super) async fn clone_avss_node(&self) -> AvssMpcNode<F, Avid<AvssSessionId>, G> {
        self.avss_node.lock().await.clone()
    }

    /// Create a new AVSS engine from a named backend configuration.
    pub async fn from_config(config: AvssEngineConfig<F, G>) -> Result<Arc<Self>, String> {
        let AvssEngineConfig {
            session,
            secret_key,
            public_keys,
        } = config;
        let (topology, network, input_ids, open_message_router) = session.into_parts();
        let instance_id = topology.instance_id();
        let party_id = topology.party_id();
        let n_parties = topology.n_parties();
        let threshold = topology.threshold();

        // Create the AvssMpcNode via MPCProtocol::setup
        let instance_id_u32 = protocol_instance_id_u32(instance_id)?;
        let opts = AvssMpcNodeOpts::new(
            n_parties,
            threshold,
            DEFAULT_N_RANDOM_SHARES,
            DEFAULT_N_TRIPLES,
            secret_key,
            public_keys,
            instance_id_u32,
            std::time::Duration::from_secs(60),
        )
        .map_err(|e| format!("Failed to create AvssMpcNodeOpts: {:?}", e))?;
        let avss_node = <AvssMpcNode<F, Avid<AvssSessionId>, G> as MPCProtocol<
            F,
            FeldmanShamirShare<F, G>,
            QuicNetworkManager,
        >>::setup(party_id, opts, input_ids)
        .map_err(|e| format!("Failed to create AvssMpcNode: {:?}", e))?;

        Ok(Arc::new(Self {
            topology,
            net: network,
            avss_node: Arc::new(Mutex::new(avss_node)),
            stored_shares: Arc::new(Mutex::new(BTreeMap::new())),
            session_ids: AvssSessionIds::new(instance_id, party_id, n_parties),
            ready: AtomicBool::new(false),
            share_notify: Arc::new(tokio::sync::Notify::new()),
            sk_i: secret_key,
            _marker: PhantomData,
            preproc_store: tokio::sync::RwLock::new(None),
            preproc_config: tokio::sync::RwLock::new(None),
            open_message_router: open_message_router.clone(),
            open_registry: open_message_router.register_instance(instance_id),
        }))
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

    /// Returns a handle to the inner MPC node for direct access (e.g., InputServer init).
    pub fn node_handle(&self) -> &Arc<Mutex<AvssMpcNode<F, Avid<AvssSessionId>, G>>> {
        &self.avss_node
    }

    /// Get the validated MPC session topology.
    pub fn topology(&self) -> MpcSessionTopology {
        self.topology
    }

    /// Get the typed party identity.
    pub fn party(&self) -> MpcPartyId {
        self.topology.party()
    }

    /// Get network manager
    pub fn net(&self) -> Arc<QuicNetworkManager> {
        self.net.clone()
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
/// `curve_config()` will report `MpcCurveConfig::Curve25519`. The group
/// type (`EdwardsProjective`) is distinct.
pub type Ed25519AvssMpcEngine = AvssMpcEngine<ark_ed25519::Fr, ark_ed25519::EdwardsProjective>;
