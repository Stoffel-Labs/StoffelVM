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

use crate::net::curve::{MpcCurveConfig, SupportedMpcField};
use crate::net::mpc_engine::MpcEngine;
use ark_ec::CurveGroup;
use ark_ff::{FftField, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::marker::PhantomData;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;
use stoffel_vm_types::core_types::{ShareType, Value, BOOLEAN_SECRET_INT_BITS};
use stoffelmpc_mpc::avss_mpc::{
    AdkgNode as AvssMpcNode, AdkgNodeOpts as AvssMpcNodeOpts, AvssSessionId,
    ProtocolType as AvssProtocolType,
};
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::common::{MPCProtocol, ProtocolSessionId, SecretSharingScheme};
use stoffelnet::network_utils::Network;
use stoffelnet::transports::quic::QuicNetworkManager;
use tokio::sync::Mutex;
use tracing::info;

// ============================================================================
// Open-in-exp registry for AVSS
// ============================================================================

/// Wire prefix that identifies an AVSS open-in-exp contribution message.
const AVSS_EXP_WIRE_PREFIX: &[u8; 4] = b"AXOP";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AvssExpOpenWireMessage {
    instance_id: u64,
    sender_party_id: usize,
    share_id: usize,
    partial_point: Vec<u8>,
}

#[derive(Default, Clone)]
struct AvssExpOpenAccumulator {
    /// (share_id, serialized compressed affine point)
    partial_points: Vec<(usize, Vec<u8>)>,
    party_ids: Vec<usize>,
    result: Option<Vec<u8>>,
    result_cached_at: Option<std::time::Instant>,
}

const AVSS_EXP_EVICTION_AGE: Duration = Duration::from_secs(60);

static AVSS_EXP_REGISTRY: once_cell::sync::Lazy<
    parking_lot::Mutex<HashMap<(u64, usize), AvssExpOpenAccumulator>>,
> = once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(HashMap::new()));

static AVSS_EXP_NOTIFY: once_cell::sync::Lazy<tokio::sync::Notify> =
    once_cell::sync::Lazy::new(tokio::sync::Notify::new);

fn insert_remote_avss_exp_partial(
    instance_id: u64,
    sender_party_id: usize,
    share_id: usize,
    partial_point: Vec<u8>,
) {
    let mut reg = AVSS_EXP_REGISTRY.lock();
    let now = std::time::Instant::now();
    reg.retain(|_, acc| {
        acc.result_cached_at
            .is_none_or(|t| now.duration_since(t) < AVSS_EXP_EVICTION_AGE)
    });
    let mut seq = 0usize;
    loop {
        let key = (instance_id, seq);
        let entry = reg.entry(key).or_default();
        if !entry.party_ids.contains(&sender_party_id) {
            entry.partial_points.push((share_id, partial_point));
            entry.party_ids.push(sender_party_id);
            break;
        }
        seq += 1;
    }
    drop(reg);
    AVSS_EXP_NOTIFY.notify_waiters();
}

/// Inspect an incoming message and, if it carries an AVSS open-in-exp contribution
/// (`AXOP` prefix), insert it into the accumulator registry and return `Ok(true)`.
/// Returns `Ok(false)` for unrelated messages.
pub(crate) fn try_handle_avss_open_exp_wire_message(
    authenticated_sender_id: usize,
    payload: &[u8],
) -> Result<bool, String> {
    if payload.len() < AVSS_EXP_WIRE_PREFIX.len()
        || &payload[..AVSS_EXP_WIRE_PREFIX.len()] != AVSS_EXP_WIRE_PREFIX
    {
        return Ok(false);
    }

    let message: AvssExpOpenWireMessage =
        bincode::deserialize(&payload[AVSS_EXP_WIRE_PREFIX.len()..])
            .map_err(|e| format!("deserialize avss open-exp payload: {}", e))?;

    if authenticated_sender_id == crate::net::open_registry::UNKNOWN_SENDER_ID {
        tracing::warn!(
            sender_party_id = message.sender_party_id,
            "Rejecting AVSS open-exp wire message from unauthenticated connection"
        );
        return Err(
            "avss open-exp wire rejected: sender identity not authenticated".to_string(),
        );
    }
    if message.sender_party_id != authenticated_sender_id {
        return Err(format!(
            "avss open-exp sender mismatch: transport={} payload={}",
            authenticated_sender_id, message.sender_party_id
        ));
    }
    // In AVSS the share_id equals party_id + 1 (evaluation points are 1-indexed).
    if message.share_id != message.sender_party_id + 1 {
        return Err(format!(
            "avss open-exp share_id mismatch: sender_party_id={} share_id={}",
            message.sender_party_id, message.share_id
        ));
    }

    insert_remote_avss_exp_partial(
        message.instance_id,
        message.sender_party_id,
        message.share_id,
        message.partial_point,
    );
    Ok(true)
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
    instance_id: u64,
    party_id: usize,
    n: usize,
    t: usize,
    net: Arc<QuicNetworkManager>,
    /// Full AVSS MPC node (share gen, multiplication, preprocessing, message routing)
    avss_node: Arc<Mutex<AvssMpcNode<F, Avid<AvssSessionId>, G>>>,
    /// Generated Feldman shares indexed by user-defined key name
    stored_shares: Arc<Mutex<BTreeMap<String, FeldmanShamirShare<F, G>>>>,
    /// Session counter for generating unique session IDs
    session_counter: Arc<Mutex<u64>>,
    /// Counter used to deterministically coordinate local clear->share conversion.
    input_share_counter: AtomicU64,
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
}

impl<F, G> AvssMpcEngine<F, G>
where
    F: FftField + PrimeField + Send + Sync + 'static,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    /// Create a new AVSS engine
    ///
    /// # Arguments
    /// * `instance_id` - Unique identifier for this AVSS instance
    /// * `party_id` - This party's ID (0 to n-1)
    /// * `n` - Number of parties
    /// * `t` - Threshold (tolerates up to t malicious parties)
    /// * `net` - Network manager for communication
    /// * `sk_i` - This party's AVSS ECDH secret key for share encryption
    /// * `pk_map` - AVSS ECDH public keys from all parties
    pub async fn new(
        instance_id: u64,
        party_id: usize,
        n: usize,
        t: usize,
        net: Arc<QuicNetworkManager>,
        sk_i: F,
        pk_map: Arc<Vec<G>>,
    ) -> Result<Arc<Self>, String> {
        // Create the AvssMpcNode via MPCProtocol::setup
        let instance_id_u32 = u32::try_from(instance_id)
            .map_err(|_| format!("instance_id {} exceeds u32", instance_id))?;
        let opts = AvssMpcNodeOpts::new(
            n,
            t,
            DEFAULT_N_RANDOM_SHARES,
            DEFAULT_N_TRIPLES,
            sk_i,
            pk_map,
            instance_id_u32,
            std::time::Duration::from_secs(60),
        )
        .map_err(|e| format!("Failed to create AvssMpcNodeOpts: {:?}", e))?;
        let avss_node = <AvssMpcNode<F, Avid<AvssSessionId>, G> as MPCProtocol<
            F,
            FeldmanShamirShare<F, G>,
            QuicNetworkManager,
        >>::setup(party_id, opts, vec![])
        .map_err(|e| format!("Failed to create AvssMpcNode: {:?}", e))?;

        Ok(Arc::new(Self {
            instance_id,
            party_id,
            n,
            t,
            net,
            avss_node: Arc::new(Mutex::new(avss_node)),
            stored_shares: Arc::new(Mutex::new(BTreeMap::new())),
            session_counter: Arc::new(Mutex::new(0)),
            input_share_counter: AtomicU64::new(0),
            ready: AtomicBool::new(false),
            share_notify: Arc::new(tokio::sync::Notify::new()),
            sk_i,
            _marker: PhantomData,
        }))
    }

    #[inline]
    fn mix64(mut x: u64) -> u64 {
        x ^= x >> 33;
        x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
        x ^= x >> 33;
        x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
        x ^= x >> 33;
        x
    }

    #[inline]
    fn derive_session_slot24(instance_id: u64, party_id: usize) -> u32 {
        let seed = instance_id ^ ((party_id as u64).rotate_left(17));
        (Self::mix64(seed) as u32) & 0x00ff_ffff
    }

    #[inline]
    fn derive_input_share_slot24(instance_id: u64, dealer_id: usize) -> u32 {
        // Keep input-share sessions in a dedicated slot namespace to avoid collisions
        // with other AVSS rounds that use derive_session_slot24().
        let seed = instance_id ^ ((dealer_id as u64).rotate_left(29)) ^ 0x4953_4841_5245_5f53; // "ISHARE_S"
        (Self::mix64(seed) as u32) & 0x00ff_ffff
    }

    fn allocate_input_share_session(&self) -> Result<(usize, AvssSessionId), String> {
        let round = self.input_share_counter.fetch_add(1, Ordering::SeqCst);
        let dealer_id = (round as usize) % self.n.max(1);
        let round_u32 = u32::try_from(round)
            .map_err(|_| "AVSS input_share counter overflowed u32".to_string())?;
        let slot24 = Self::derive_input_share_slot24(self.instance_id, dealer_id);
        Ok((
            dealer_id,
            AvssSessionId::new(AvssProtocolType::Avss, slot24, round_u32),
        ))
    }

    async fn run_input_share_round(
        &self,
        dealer_id: usize,
        session_id: AvssSessionId,
        secret: F,
    ) -> Result<FeldmanShamirShare<F, G>, String> {
        if self.party_id == dealer_id {
            let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
            let mut node = self.avss_node.lock().await;
            node.share_gen_avss
                .avss
                .init(vec![secret], session_id, &mut rng, self.net.clone())
                .await
                .map_err(|e| format!("AVSS input_share init failed: {:?}", e))?;
        }

        self.wait_for_share(session_id).await
    }

    async fn run_multiply_round(
        avss_node: Arc<Mutex<AvssMpcNode<F, Avid<AvssSessionId>, G>>>,
        net: Arc<QuicNetworkManager>,
        left_share_bytes: Vec<u8>,
        right_share_bytes: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let left_share = Self::decode_feldman_share(&left_share_bytes)?;
        let right_share = Self::decode_feldman_share(&right_share_bytes)?;

        let result = {
            let mut node = avss_node.lock().await;
            node.mul(vec![left_share], vec![right_share], net)
                .await
                .map_err(|e| format!("Multiplication failed: {:?}", e))?
        };

        let product = result
            .into_iter()
            .next()
            .ok_or_else(|| "Multiplication returned no result".to_string())?;
        Self::encode_feldman_share(&product)
    }

    async fn broadcast_open_registry_payload(&self, payload: Vec<u8>) -> Result<(), String> {
        for peer_id in 0..self.n {
            if peer_id == self.party_id {
                continue;
            }
            self.net
                .send(peer_id, &payload)
                .await
                .map_err(|e| format!("Failed to send open payload to party {}: {}", peer_id, e))?;
        }
        Ok(())
    }

    fn broadcast_open_registry_payload_sync(&self, payload: Vec<u8>) -> Result<(), String> {
        crate::net::block_on_current(self.broadcast_open_registry_payload(payload))
    }

    fn encode_avss_open_exp_wire_message(
        instance_id: u64,
        sender_party_id: usize,
        share_id: usize,
        partial_point: &[u8],
    ) -> Result<Vec<u8>, String> {
        let payload = AvssExpOpenWireMessage {
            instance_id,
            sender_party_id,
            share_id,
            partial_point: partial_point.to_vec(),
        };
        let encoded = bincode::serialize(&payload)
            .map_err(|e| format!("serialize avss open-exp payload: {}", e))?;
        let mut out = Vec::with_capacity(AVSS_EXP_WIRE_PREFIX.len() + encoded.len());
        out.extend_from_slice(AVSS_EXP_WIRE_PREFIX);
        out.extend_from_slice(&encoded);
        Ok(out)
    }

    async fn broadcast_open_avss_exp_payload(&self, payload: Vec<u8>) -> Result<(), String> {
        for peer_id in 0..self.n {
            if peer_id == self.party_id {
                continue;
            }
            self.net.send(peer_id, &payload).await.map_err(|e| {
                format!("broadcast avss open-exp to {}: {}", peer_id, e)
            })?;
        }
        Ok(())
    }

    fn broadcast_open_avss_exp_payload_sync(&self, payload: Vec<u8>) -> Result<(), String> {
        crate::net::block_on_current(self.broadcast_open_avss_exp_payload(payload))
    }

    /// Reveal an AVSS share in the exponent: reconstructs `[secret] * generator`
    /// via Lagrange interpolation in the group using integer evaluation points (1, 2, …).
    ///
    /// Each party computes `share_value * generator`, broadcasts its partial point,
    /// and waits until `t+1` contributions are available.
    pub fn open_share_in_exp_impl(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
        generator_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        let share = Self::decode_feldman_share(share_bytes)?;
        let generator = G::deserialize_compressed(&generator_bytes[..])
            .map_err(|e| format!("deserialize generator: {}", e))?;

        let share_value = share.feldmanshare.share[0];
        let share_id = share.feldmanshare.id;

        let partial_point = generator * share_value;
        let mut partial_bytes = Vec::new();
        partial_point
            .into_affine()
            .serialize_compressed(&mut partial_bytes)
            .map_err(|e| format!("serialize partial point: {}", e))?;

        let wire_message = Self::encode_avss_open_exp_wire_message(
            self.instance_id,
            self.party_id,
            share_id,
            &partial_bytes,
        )?;
        self.broadcast_open_avss_exp_payload_sync(wire_message)?;

        let required = self.t + 1;
        let instance_id = self.instance_id;
        let party_id = self.party_id;

        let try_check = |my_sequence: &mut Option<usize>,
                         partial_bytes: &[u8],
                         share_id: usize|
         -> Result<Option<Vec<u8>>, String> {
            let mut reg = AVSS_EXP_REGISTRY.lock();

            if my_sequence.is_none() {
                let mut seq = 0;
                loop {
                    let key = (instance_id, seq);
                    let entry = reg.entry(key).or_insert_with(AvssExpOpenAccumulator::default);
                    if !entry.party_ids.contains(&party_id) {
                        entry.partial_points.push((share_id, partial_bytes.to_vec()));
                        entry.party_ids.push(party_id);
                        *my_sequence = Some(seq);
                        break;
                    }
                    seq += 1;
                }
            }

            let seq = my_sequence.expect("sequence must be set after insertion");
            let key = (instance_id, seq);
            let entry = reg
                .get_mut(&key)
                .expect("avss exp registry entry must exist after insertion");

            if let Some(result) = entry.result.clone() {
                return Ok(Some(result));
            }

            if entry.partial_points.len() >= required {
                let collected: Vec<(usize, Vec<u8>)> = entry
                    .partial_points
                    .iter()
                    .take(required)
                    .cloned()
                    .collect();

                let mut points: Vec<(usize, G)> = Vec::with_capacity(collected.len());
                for (sid, bytes) in &collected {
                    let pt = <G as CurveGroup>::Affine::deserialize_compressed(&bytes[..])
                        .map_err(|e| format!("deserialize partial point: {}", e))?;
                    points.push((*sid, pt.into()));
                }

                // AVSS evaluation points are 1-indexed integers.
                let eval_points: Vec<(usize, F)> = points
                    .iter()
                    .map(|(id, _)| (*id, F::from(*id as u64)))
                    .collect();

                let mut result = G::zero();
                for (i, (_id_i, pt_i)) in points.iter().enumerate() {
                    let x_i = eval_points[i].1;
                    let mut lambda = F::from(1u64);
                    for (j, _) in points.iter().enumerate() {
                        if i == j {
                            continue;
                        }
                        let x_j = eval_points[j].1;
                        let num = -x_j;
                        let den = x_i - x_j;
                        lambda *= num
                            * den
                                .inverse()
                                .ok_or_else(|| "zero denominator in AVSS Lagrange".to_string())?;
                    }
                    result += *pt_i * lambda;
                }

                let mut result_bytes = Vec::new();
                result
                    .into_affine()
                    .serialize_compressed(&mut result_bytes)
                    .map_err(|e| format!("serialize result: {}", e))?;

                entry.result = Some(result_bytes.clone());
                entry.result_cached_at = Some(std::time::Instant::now());
                return Ok(Some(result_bytes));
            }

            Ok(None)
        };

        // Use async Notify when a multi-thread tokio runtime is available.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
                return tokio::task::block_in_place(|| {
                    handle.block_on(async {
                        let deadline =
                            tokio::time::Instant::now() + tokio::time::Duration::from_secs(30);
                        let mut my_sequence: Option<usize> = None;

                        loop {
                            let notified = AVSS_EXP_NOTIFY.notified();

                            if let Some(result) =
                                try_check(&mut my_sequence, &partial_bytes, share_id)?
                            {
                                return Ok(result);
                            }

                            if tokio::time::Instant::now() >= deadline {
                                return Err(
                                    "Timeout waiting for AVSS open_share_in_exp contributions"
                                        .to_string(),
                                );
                            }

                            tokio::select! {
                                _ = notified => {}
                                _ = tokio::time::sleep_until(deadline) => {}
                            }
                        }
                    })
                });
            }
        }

        // Polling fallback.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let mut my_sequence: Option<usize> = None;
        loop {
            if let Some(result) = try_check(&mut my_sequence, &partial_bytes, share_id)? {
                return Ok(result);
            }
            if std::time::Instant::now() >= deadline {
                return Err(
                    "Timeout waiting for AVSS open_share_in_exp contributions".to_string(),
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Start the engine and mark it ready
    pub async fn start_async(&self) -> Result<(), String> {
        self.ready.store(true, Ordering::SeqCst);
        info!(
            "AVSS engine started: instance={}, party={}, n={}, t={}",
            self.instance_id, self.party_id, self.n, self.t
        );
        Ok(())
    }

    /// Generate a new random AVSS share and store it under the given key name.
    ///
    /// The `key_name` must be the same across all parties so they can
    /// coordinate retrieval later. This party initiates the AVSS protocol
    /// with a randomly generated secret.
    pub async fn generate_random_share(
        &self,
        key_name: &str,
    ) -> Result<FeldmanShamirShare<F, G>, String> {
        self.generate_random_share_with_network(key_name, self.net.clone())
            .await
    }

    /// Like `generate_random_share`, but uses a custom `Network` implementation.
    ///
    /// This is useful when the network's `send(party_id, msg)` routing differs
    /// from party-id-based indexing (e.g. stoffelnet's sender_id system).
    pub async fn generate_random_share_with_network<
        N: stoffelnet::network_utils::Network + Send + Sync + 'static,
    >(
        &self,
        key_name: &str,
        net: Arc<N>,
    ) -> Result<FeldmanShamirShare<F, G>, String> {
        if !self.ready.load(Ordering::SeqCst) {
            return Err("AVSS engine not ready".into());
        }

        let share = {
            let mut node = self.avss_node.lock().await;
            node.rand(net)
                .await
                .map_err(|e| format!("AVSS rand failed: {:?}", e))?
        };

        // Store the share under the user-defined key name
        {
            let mut shares = self.stored_shares.lock().await;
            shares.insert(key_name.to_string(), share.clone());
        }

        info!(
            "AVSS share generation completed: party={}, key='{}'",
            self.party_id, key_name
        );

        Ok(share)
    }

    /// Generate an AVSS share for a specific secret and store under the given key name.
    pub async fn generate_share_with_secret(
        &self,
        key_name: &str,
        secret: F,
    ) -> Result<FeldmanShamirShare<F, G>, String> {
        self.generate_share_with_secret_and_network(key_name, secret, self.net.clone())
            .await
    }

    /// Like `generate_share_with_secret`, but uses a custom `Network` implementation.
    pub async fn generate_share_with_secret_and_network<
        N: stoffelnet::network_utils::Network + Send + Sync + 'static,
    >(
        &self,
        key_name: &str,
        secret: F,
        net: Arc<N>,
    ) -> Result<FeldmanShamirShare<F, G>, String> {
        if !self.ready.load(Ordering::SeqCst) {
            return Err("AVSS engine not ready".into());
        }

        // Generate session ID
        let session_id = {
            let mut counter = self.session_counter.lock().await;
            let id = *counter;
            *counter += 1;
            let id = u32::try_from(id).map_err(|_| {
                "AVSS session counter overflowed u32; cannot allocate new session".to_string()
            })?;
            let slot24 = Self::derive_session_slot24(self.instance_id, self.party_id);
            AvssSessionId::new(AvssProtocolType::Avss, slot24, id)
        };

        // Run AVSS init through the inner share_gen_avss node
        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        {
            let mut node = self.avss_node.lock().await;
            node.share_gen_avss
                .avss
                .init(vec![secret], session_id, &mut rng, net)
                .await
                .map_err(|e| format!("AVSS init failed: {:?}", e))?;
        }

        info!(
            "AVSS share generation initiated: party={}, key='{}', session={}",
            self.party_id,
            key_name,
            session_id.as_u64()
        );

        // Wait for our own share to be processed
        let share = self.wait_for_share(session_id).await?;

        // Store the share under the user-defined key name
        {
            let mut shares = self.stored_shares.lock().await;
            shares.insert(key_name.to_string(), share.clone());
        }

        Ok(share)
    }

    /// Wait for a share from a specific session.
    ///
    /// Uses `share_notify` to wake immediately when `process_wrapped_message`
    /// delivers new data, instead of polling with a fixed sleep interval.
    async fn wait_for_share(
        &self,
        session_id: AvssSessionId,
    ) -> Result<FeldmanShamirShare<F, G>, String> {
        let deadline =
            tokio::time::Instant::now() + tokio::time::Duration::from_secs(30);

        loop {
            let notified = self.share_notify.notified();

            {
                let node = self.avss_node.lock().await;
                let shares = node.share_gen_avss.avss.shares.lock().await;
                if let Some(Some(share_vec)) = shares.get(&session_id) {
                    if let Some(share) = share_vec.first() {
                        return Ok(share.clone());
                    }
                }
            }

            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(format!(
                        "Timeout waiting for AVSS share: session={}",
                        session_id.as_u64()
                    ));
                }
            }
        }
    }

    /// Wait for a received share (non-dealer path) and store it under the given key name.
    ///
    /// Non-dealer parties receive shares via `process_wrapped_message`, which stores them
    /// in the inner AVSS shares store. This method waits (via `share_notify`) for any
    /// completed share not yet stored in `stored_shares`, stores it under `key_name`,
    /// and returns it.
    pub async fn await_received_share(
        &self,
        key_name: &str,
    ) -> Result<FeldmanShamirShare<F, G>, String> {
        let deadline =
            tokio::time::Instant::now() + tokio::time::Duration::from_secs(30);

        loop {
            let notified = self.share_notify.notified();

            {
                let node = self.avss_node.lock().await;
                let shares = node.share_gen_avss.avss.shares.lock().await;
                let stored = self.stored_shares.lock().await;

                for (_session_id, maybe_shares) in shares.iter() {
                    if let Some(share_vec) = maybe_shares {
                        if let Some(share) = share_vec.first() {
                            let already_stored = stored
                                .values()
                                .any(|s| s.feldmanshare.share == share.feldmanshare.share);
                            if !already_stored {
                                let share = share.clone();
                                drop(stored);
                                drop(shares);
                                drop(node);
                                let mut stored = self.stored_shares.lock().await;
                                stored.insert(key_name.to_string(), share.clone());
                                return Ok(share);
                            }
                        }
                    }
                }
            }

            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(format!(
                        "Timeout waiting for received share for key '{}'",
                        key_name
                    ));
                }
            }
        }
    }

    /// Retrieve a stored Feldman share by key name.
    pub async fn get_share(&self, key_name: &str) -> Option<FeldmanShamirShare<F, G>> {
        let shares = self.stored_shares.lock().await;
        shares.get(key_name).cloned()
    }

    /// Get the public key (commitment[0]) for a stored share.
    pub async fn get_public_key(&self, key_name: &str) -> Option<G> {
        self.get_share(key_name).await.map(|s| s.commitments[0])
    }

    /// Get public key bytes for a stored share.
    pub async fn get_public_key_bytes(&self, key_name: &str) -> Result<Vec<u8>, String> {
        let share = self
            .get_share(key_name)
            .await
            .ok_or_else(|| format!("Key '{}' not found", key_name))?;
        Self::encode_group_element(&share.commitments[0])
    }

    /// Process an incoming wire-format message via the AVSS protocol node.
    ///
    /// The node handles all message routing internally (RBC, AVSS, multiplication).
    /// Callers should pass the raw bytes received from the network to this method.
    pub async fn process_wrapped_message(
        &self,
        sender_id: usize,
        data: &[u8],
    ) -> Result<(), String> {
        self.process_wrapped_message_with_network(sender_id, data, self.net.clone())
            .await
    }

    /// Like `process_wrapped_message`, but uses a custom `Network` implementation
    /// for protocol responses.
    pub async fn process_wrapped_message_with_network<
        N: stoffelnet::network_utils::Network + Send + Sync + 'static,
    >(
        &self,
        sender_id: usize,
        data: &[u8],
        net: Arc<N>,
    ) -> Result<(), String> {
        let mut node = self.avss_node.lock().await;
        let result = node
            .process(sender_id, data.to_vec(), net)
            .await
            .map_err(|e| format!("AVSS process failed: {:?}", e));
        self.share_notify.notify_waiters();
        result
    }

    /// Helper: encode a group element to bytes
    pub fn encode_group_element(g: &G) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        g.serialize_compressed(&mut bytes)
            .map_err(|e| format!("Serialization failed: {:?}", e))?;
        Ok(bytes)
    }

    /// Helper: decode a group element from bytes
    pub fn decode_group_element(bytes: &[u8]) -> Result<G, String> {
        G::deserialize_compressed(bytes).map_err(|e| format!("Deserialization failed: {:?}", e))
    }

    /// Get party ID
    pub fn party_id(&self) -> usize {
        self.party_id
    }

    /// Get network manager
    pub fn net(&self) -> Arc<QuicNetworkManager> {
        self.net.clone()
    }

    /// Encode a FeldmanShamirShare to bytes using CanonicalSerialize
    pub fn encode_feldman_share(share: &FeldmanShamirShare<F, G>) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        share
            .serialize_compressed(&mut out)
            .map_err(|e| format!("serialize FeldmanShamirShare: {}", e))?;
        Ok(out)
    }

    /// Decode a FeldmanShamirShare from bytes using CanonicalDeserialize
    pub fn decode_feldman_share(bytes: &[u8]) -> Result<FeldmanShamirShare<F, G>, String> {
        FeldmanShamirShare::<F, G>::deserialize_compressed(bytes)
            .map_err(|e| format!("deserialize FeldmanShamirShare: {}", e))
    }

    /// Create AVSS shares for a secret value (generates Feldman-verifiable shares for all parties).
    ///
    /// Returns this party's share.
    #[allow(dead_code)]
    fn create_avss_share_with_rng<R: Rng>(
        &self,
        secret: F,
        rng: &mut R,
    ) -> Result<FeldmanShamirShare<F, G>, String> {
        use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};

        // Generate random polynomial with p(0) = secret
        let mut poly = DensePolynomial::<F>::rand(self.t, rng);
        poly[0] = secret;

        // Compute Feldman commitments: C_j = g * c_j
        let generator = G::generator();
        let commitments: Vec<G> = poly.coeffs.iter().map(|c| generator * c).collect();

        // Evaluate at this party's point (1-indexed)
        let x = F::from((self.party_id + 1) as u64);
        let share_value = poly.evaluate(&x);

        FeldmanShamirShare::new(share_value, self.party_id + 1, self.t, commitments)
            .map_err(|e| format!("Failed to create FeldmanShamirShare: {:?}", e))
    }

    /// Reconstruct the secret from a set of Feldman shares using Lagrange interpolation.
    fn reconstruct_secret(
        shares: &[FeldmanShamirShare<F, G>],
        n: usize,
        t: usize,
    ) -> Result<F, String> {
        let (_, secret) = FeldmanShamirShare::<F, G>::recover_secret(shares, n, t)
            .map_err(|e| format!("Failed to recover secret: {:?}", e))?;
        Ok(secret)
    }

    #[inline]
    fn field_from_i64(value: i64) -> F {
        crate::net::curve::field_from_i64(value)
    }

    fn field_to_value(ty: ShareType, secret: F) -> Result<Value, String> {
        Ok(crate::net::curve::field_to_value(ty, secret))
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

// ============================================================================
// MpcEngine Implementation
// ============================================================================
//
// The AVSS engine implements MpcEngine using the full AVSS MPC protocol.
// It supports input sharing, opening, multiplication (Beaver triples), random
// share generation, and preprocessing via FeldmanShamirShare.
// AVSS-specific operations (key generation, commitment access) are available via
// AvssOperations trait through as_any() downcasting.

impl<F, G> MpcEngine for AvssMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    fn protocol_name(&self) -> &'static str {
        "avss"
    }

    fn instance_id(&self) -> u64 {
        self.instance_id
    }

    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    fn start(&self) -> Result<(), String> {
        self.ready.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn input_share(&self, ty: ShareType, clear: &Value) -> Result<Vec<u8>, String> {
        let secret = match (ty, clear) {
            (ShareType::SecretInt { .. }, Value::I64(v)) => Self::field_from_i64(*v),
            (
                ShareType::SecretInt {
                    bit_length: BOOLEAN_SECRET_INT_BITS,
                },
                Value::Bool(b),
            ) => {
                if *b {
                    F::from(1u64)
                } else {
                    F::from(0u64)
                }
            }
            (ShareType::SecretFixedPoint { precision }, Value::Float(fp)) => {
                let f = precision.f();
                let scale = (1u64 << f) as f64;
                let scaled_value = (fp.0 * scale) as i64;
                Self::field_from_i64(scaled_value)
            }
            _ => return Err("Unsupported type for input_share".to_string()),
        };

        let (dealer_id, session_id) = self.allocate_input_share_session()?;
        let share = crate::net::block_on_current(
            self.run_input_share_round(dealer_id, session_id, secret),
        )?;
        Self::encode_feldman_share(&share)
    }

    fn multiply_share(&self, _ty: ShareType, left: &[u8], right: &[u8]) -> Result<Vec<u8>, String> {
        let avss_node = self.avss_node.clone();
        let net = self.net.clone();
        let left_bytes = left.to_vec();
        let right_bytes = right.to_vec();

        let fut = Self::run_multiply_round(avss_node, net, left_bytes, right_bytes);

        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                #[allow(deprecated)]
                match handle.runtime_flavor() {
                    tokio::runtime::RuntimeFlavor::MultiThread => {
                        tokio::task::block_in_place(|| handle.block_on(fut))
                    }
                    tokio::runtime::RuntimeFlavor::CurrentThread => {
                        std::thread::spawn(move || {
                            let rt = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()
                                .map_err(|e| format!("failed to create Tokio runtime: {e}"))?;
                            rt.block_on(fut)
                        })
                        .join()
                        .map_err(|_| "AVSS multiply worker thread panicked".to_string())?
                    }
                    _ => Err("operation requires a multi-thread Tokio runtime".to_string()),
                }
            }
            Err(_) => {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("failed to create Tokio runtime: {e}"))?;
                rt.block_on(fut)
            }
        }
    }

    fn open_share(&self, ty: ShareType, share_bytes: &[u8]) -> Result<Value, String> {
        let type_key = match ty {
            ShareType::SecretInt { bit_length } => format!("avss-int-{bit_length}"),
            ShareType::SecretFixedPoint { precision } => {
                format!("avss-fixed-{}-{}", precision.k(), precision.f())
            }
        };

        let wire_message = crate::net::open_registry::encode_single_share_wire_message(
            self.instance_id,
            &type_key,
            self.party_id,
            share_bytes,
        )?;
        self.broadcast_open_registry_payload_sync(wire_message)?;

        let required = self.t + 1;
        let n = self.n;
        let t = self.t;

        crate::net::open_registry::open_share_via_registry(
            self.instance_id,
            self.party_id,
            &type_key,
            share_bytes,
            required,
            |collected| {
                let mut shares: Vec<FeldmanShamirShare<F, G>> = Vec::with_capacity(collected.len());
                for bytes in collected {
                    shares.push(Self::decode_feldman_share(bytes)?);
                }
                let secret = Self::reconstruct_secret(&shares, n, t)?;
                Self::field_to_value(ty, secret)
            },
        )
    }

    fn batch_open_shares(&self, ty: ShareType, shares: &[Vec<u8>]) -> Result<Vec<Value>, String> {
        let type_key = match ty {
            ShareType::SecretInt { bit_length } => format!("avss-batch-int-{bit_length}"),
            ShareType::SecretFixedPoint { precision } => {
                format!("avss-batch-fixed-{}-{}", precision.k(), precision.f())
            }
        };

        let wire_message = crate::net::open_registry::encode_batch_share_wire_message(
            self.instance_id,
            &type_key,
            self.party_id,
            shares,
        )?;
        self.broadcast_open_registry_payload_sync(wire_message)?;

        let required = self.t + 1;
        let n = self.n;
        let t = self.t;

        crate::net::open_registry::batch_open_via_registry(
            self.instance_id,
            self.party_id,
            &type_key,
            shares,
            required,
            |collected, pos| {
                let mut decoded_shares: Vec<FeldmanShamirShare<F, G>> =
                    Vec::with_capacity(collected.len());
                for bytes in collected {
                    decoded_shares.push(Self::decode_feldman_share(bytes)?);
                }
                let secret = Self::reconstruct_secret(&decoded_shares, n, t)
                    .map_err(|e| format!("batch reconstruct_secret pos {}: {}", pos, e))?;
                Self::field_to_value(ty, secret)
            },
        )
    }

    fn shutdown(&self) {
        self.ready.store(false, Ordering::SeqCst);
    }

    fn party_id(&self) -> usize {
        self.party_id
    }

    fn n_parties(&self) -> usize {
        self.n
    }

    fn threshold(&self) -> usize {
        self.t
    }

    fn curve_config(&self) -> MpcCurveConfig {
        F::CURVE_CONFIG
    }

    fn capabilities(&self) -> crate::net::mpc_engine::MpcCapabilities {
        use crate::net::mpc_engine::MpcCapabilities;
        MpcCapabilities::MULTIPLICATION | MpcCapabilities::OPEN_IN_EXP | MpcCapabilities::ELLIPTIC_CURVES
    }

    fn random_share(&self, _ty: ShareType) -> Result<Vec<u8>, String> {
        let share =
            crate::net::block_on_current(self.generate_random_share("__random_share__"))?;
        Self::encode_feldman_share(&share)
    }

    fn open_share_in_exp(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        generator_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.open_share_in_exp_impl(ty, share_bytes, generator_bytes)
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
}

// ============================================================================
// Additional Trait Implementations for AVSS-specific Operations
// ============================================================================

/// AVSS-specific operations trait.
///
/// This trait is object-safe and uses `Vec<u8>` for share data so it can be
/// used through `dyn AvssOperations` without knowing the concrete `(F, G)`.
pub trait AvssOperations {
    /// Generate a new random share and store it under `key_name` (async).
    /// Returns the serialized FeldmanShamirShare.
    fn avss_generate_share(
        &self,
        key_name: String,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send + '_>>;

    /// Get commitment at index for a stored share (synchronous).
    /// Index 0 is the public key.
    fn avss_get_commitment(&self, key_name: &str, index: usize) -> Result<Vec<u8>, String>;
}

impl<F, G> AvssOperations for AvssMpcEngine<F, G>
where
    F: FftField + PrimeField + Send + Sync + 'static,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    fn avss_generate_share(
        &self,
        key_name: String,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send + '_>>
    {
        Box::pin(async move {
            let share = self.generate_random_share(&key_name).await?;
            Self::encode_feldman_share(&share)
        })
    }

    fn avss_get_commitment(&self, key_name: &str, index: usize) -> Result<Vec<u8>, String> {
        let key_name = key_name.to_string();
        crate::net::block_on_current(async {
            let share = self
                .get_share(&key_name)
                .await
                .ok_or_else(|| format!("Key '{}' not found", key_name))?;
            let commitment = share
                .commitments
                .get(index)
                .ok_or_else(|| format!("Commitment index {} out of bounds", index))?;
            Self::encode_group_element(commitment)
        })
    }

}

// ============================================================================
// Registry for coordinating AVSS sessions across parties
// ============================================================================

/// Global registry for AVSS share coordination (for in-process multi-party testing).
///
/// Only compiled for tests and integration test feature gates; not used in production.
#[cfg(any(test, feature = "avss_itest"))]
#[derive(Default)]
struct AvssRegistry {
    /// Maps (instance_id, session_id, party_id) to serialized share
    shares: std::collections::HashMap<(u64, u64, usize), Vec<u8>>,
    /// Maps (instance_id, session_id) to aggregated public key once agreed
    public_keys: std::collections::HashMap<(u64, u64), Vec<u8>>,
}

#[cfg(any(test, feature = "avss_itest"))]
static AVSS_REGISTRY: once_cell::sync::Lazy<parking_lot::Mutex<AvssRegistry>> =
    once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(AvssRegistry::default()));

/// Store a share in the global registry (for testing)
#[cfg(any(test, feature = "avss_itest"))]
pub fn registry_store_share(
    instance_id: u64,
    session_id: u64,
    party_id: usize,
    share_bytes: Vec<u8>,
) {
    let mut registry = AVSS_REGISTRY.lock();
    registry
        .shares
        .insert((instance_id, session_id, party_id), share_bytes);
}

/// Get all shares for a session from the registry (for testing)
#[cfg(any(test, feature = "avss_itest"))]
pub fn registry_get_shares(instance_id: u64, session_id: u64) -> Vec<(usize, Vec<u8>)> {
    let registry = AVSS_REGISTRY.lock();
    registry
        .shares
        .iter()
        .filter_map(|((inst, sess, party), bytes)| {
            if *inst == instance_id && *sess == session_id {
                Some((*party, bytes.clone()))
            } else {
                None
            }
        })
        .collect()
}

/// Store agreed public key in registry
#[cfg(any(test, feature = "avss_itest"))]
pub fn registry_store_public_key(instance_id: u64, session_id: u64, pk_bytes: Vec<u8>) {
    let mut registry = AVSS_REGISTRY.lock();
    registry
        .public_keys
        .insert((instance_id, session_id), pk_bytes);
}

/// Get public key from registry
#[cfg(any(test, feature = "avss_itest"))]
pub fn registry_get_public_key(instance_id: u64, session_id: u64) -> Option<Vec<u8>> {
    let registry = AVSS_REGISTRY.lock();
    registry
        .public_keys
        .get(&(instance_id, session_id))
        .cloned()
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Projective as G1};
    use ark_ec::PrimeGroup;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    use std::sync::Arc;
    use stoffelmpc_mpc::common::share::avss::verify_feldman;
    use stoffelnet::transports::quic::QuicNetworkManager;

    #[test]
    fn test_feldman_share_serialization() {
        let mut rng = test_rng();

        // Create a Feldman share manually for testing
        let share_value = Fr::rand(&mut rng);
        let degree = 2;
        let commitments: Vec<G1> = (0..=degree)
            .map(|_| G1::generator() * Fr::rand(&mut rng))
            .collect();

        let share = FeldmanShamirShare::new(share_value, 1, degree, commitments.clone())
            .expect("Failed to create FeldmanShamirShare");

        // Test serialization roundtrip
        let bytes =
            Bls12381AvssMpcEngine::encode_feldman_share(&share).expect("Serialization failed");
        assert!(!bytes.is_empty());

        let restored =
            Bls12381AvssMpcEngine::decode_feldman_share(&bytes).expect("Deserialization failed");
        assert_eq!(restored.commitments.len(), share.commitments.len());
        assert_eq!(restored.feldmanshare.id, share.feldmanshare.id);
        assert_eq!(restored.feldmanshare.share, share.feldmanshare.share);
    }

    #[test]
    fn test_bn254_feldman_share_serialization() {
        use ark_bn254::{Fr as BnFr, G1Projective as BnG1};

        let mut rng = test_rng();
        let share_value = BnFr::rand(&mut rng);
        let degree = 2;
        let commitments: Vec<BnG1> = (0..=degree)
            .map(|_| <BnG1 as PrimeGroup>::generator() * BnFr::rand(&mut rng))
            .collect();

        let share = FeldmanShamirShare::new(share_value, 1, degree, commitments.clone())
            .expect("Failed to create FeldmanShamirShare");

        let bytes = Bn254AvssMpcEngine::encode_feldman_share(&share).expect("Serialization failed");
        assert!(!bytes.is_empty());

        let restored =
            Bn254AvssMpcEngine::decode_feldman_share(&bytes).expect("Deserialization failed");
        assert_eq!(restored.commitments.len(), share.commitments.len());
        assert_eq!(restored.feldmanshare.id, share.feldmanshare.id);
        assert_eq!(restored.feldmanshare.share, share.feldmanshare.share);
    }

    #[test]
    fn test_public_key_extraction() {
        let mut rng = test_rng();

        // The secret
        let secret = Fr::rand(&mut rng);

        // commitment[0] = g^secret = the public key
        let public_key = G1::generator() * secret;

        // Create Feldman share with this commitment
        let share_value = Fr::rand(&mut rng);
        let degree = 2;
        let mut commitments = vec![public_key]; // commitment[0] = g^secret
        for _ in 1..=degree {
            commitments.push(G1::generator() * Fr::rand(&mut rng));
        }

        let share = FeldmanShamirShare::new(share_value, 1, degree, commitments)
            .expect("Failed to create FeldmanShamirShare");

        // Verify public key extraction from commitment[0]
        assert_eq!(share.commitments[0], public_key);
    }

    #[test]
    fn test_feldman_verification() {
        let mut rng = test_rng();
        let n = 4;
        let t = 1;
        let secret = Fr::from(12345u64);

        use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
        let mut poly = DensePolynomial::rand(t, &mut rng);
        poly[0] = secret;

        let commitments: Vec<G1> = poly.coeffs.iter().map(|c| G1::generator() * c).collect();

        for i in 1..=n {
            let x = Fr::from(i as u64);
            let y = poly.evaluate(&x);

            let share = FeldmanShamirShare::new(y, i, t, commitments.clone())
                .expect("Failed to create share");

            assert!(
                verify_feldman(share.clone()),
                "Feldman verification failed for party {}",
                i
            );
        }

        assert_eq!(commitments[0], G1::generator() * secret);
    }

    #[test]
    fn test_registry_operations() {
        let instance_id = 100;
        let session_id = 1;

        registry_store_share(instance_id, session_id, 0, vec![1, 2, 3]);
        registry_store_share(instance_id, session_id, 1, vec![4, 5, 6]);
        registry_store_share(instance_id, session_id, 2, vec![7, 8, 9]);

        let shares = registry_get_shares(instance_id, session_id);
        assert_eq!(shares.len(), 3);

        let pk = vec![10, 11, 12];
        registry_store_public_key(instance_id, session_id, pk.clone());
        assert_eq!(registry_get_public_key(instance_id, session_id), Some(pk));
    }

    #[test]
    fn test_session_slot24_uses_full_instance_party_domains() {
        let base = Bls12381AvssMpcEngine::derive_session_slot24(1, 2);
        let high_bits_changed = Bls12381AvssMpcEngine::derive_session_slot24(257, 258);
        let very_high_bits_changed = Bls12381AvssMpcEngine::derive_session_slot24(1u64 << 40, 2);

        assert_ne!(
            base, high_bits_changed,
            "slot24 must not collapse instance/party IDs that differ outside low 8 bits"
        );
        assert_ne!(
            base, very_high_bits_changed,
            "slot24 must include high instance-id bits in domain separation"
        );
    }

    /// Helper to generate Feldman shares for testing
    fn generate_feldman_shares(secret: Fr, n: usize, t: usize) -> Vec<FeldmanShamirShare<Fr, G1>> {
        use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
        let mut rng = test_rng();
        let mut poly = DensePolynomial::<Fr>::rand(t, &mut rng);
        poly[0] = secret;
        let generator = G1::generator();
        let commitments: Vec<G1> = poly.coeffs.iter().map(|c| generator * c).collect();

        (1..=n)
            .map(|i| {
                let x = Fr::from(i as u64);
                let share_value = poly.evaluate(&x);
                FeldmanShamirShare::new(share_value, i, t, commitments.clone()).unwrap()
            })
            .collect()
    }

    #[test]
    fn test_feldman_share_serialization_roundtrip() {
        let n = 4;
        let t = 1;
        let secret = Fr::from(42u64);

        let shares = generate_feldman_shares(secret, n, t);

        for share in &shares {
            let bytes = Bls12381AvssMpcEngine::encode_feldman_share(share).expect("encode failed");
            let decoded =
                Bls12381AvssMpcEngine::decode_feldman_share(&bytes).expect("decode failed");
            assert_eq!(share.feldmanshare.id, decoded.feldmanshare.id);
            assert_eq!(share.feldmanshare.degree, decoded.feldmanshare.degree);
            assert_eq!(share.feldmanshare.share, decoded.feldmanshare.share);
        }

        // Verify reconstruction works after round-tripping through bytes
        let required = t + 1;
        let subset: Vec<_> = shares.iter().take(required).cloned().collect();
        let recovered = Bls12381AvssMpcEngine::reconstruct_secret(&subset, n, t)
            .expect("reconstruct_secret failed");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_bn254_feldman_share_roundtrip() {
        use ark_bn254::{Fr as BnFr, G1Projective as BnG1};
        use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};

        let mut rng = test_rng();
        let n = 4;
        let t = 1;
        let secret = BnFr::from(42u64);

        let mut poly = DensePolynomial::<BnFr>::rand(t, &mut rng);
        poly[0] = secret;
        let generator = <BnG1 as PrimeGroup>::generator();
        let commitments: Vec<BnG1> = poly.coeffs.iter().map(|c| generator * c).collect();

        let shares: Vec<_> = (1..=n)
            .map(|i| {
                let x = BnFr::from(i as u64);
                let y = poly.evaluate(&x);
                FeldmanShamirShare::<BnFr, BnG1>::new(y, i, t, commitments.clone()).unwrap()
            })
            .collect();

        for share in &shares {
            let bytes = Bn254AvssMpcEngine::encode_feldman_share(share).expect("encode failed");
            let decoded = Bn254AvssMpcEngine::decode_feldman_share(&bytes).expect("decode failed");
            assert_eq!(share.feldmanshare.id, decoded.feldmanshare.id);
            assert_eq!(share.feldmanshare.degree, decoded.feldmanshare.degree);
            assert_eq!(share.feldmanshare.share, decoded.feldmanshare.share);
        }

        let required = t + 1;
        let subset: Vec<_> = shares.iter().take(required).cloned().collect();
        let recovered =
            Bn254AvssMpcEngine::reconstruct_secret(&subset, n, t).expect("reconstruct_secret failed");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_avss_input_share_i64() {
        let n = 4;
        let t = 1;
        let party_id = 0;
        let secret = Fr::from(42u64);

        let shares = generate_feldman_shares(secret, n, t);
        let bytes =
            Bls12381AvssMpcEngine::encode_feldman_share(&shares[party_id]).expect("encode failed");
        assert!(!bytes.is_empty());

        let decoded = Bls12381AvssMpcEngine::decode_feldman_share(&bytes).expect("decode failed");
        assert_eq!(decoded.feldmanshare.id, shares[party_id].feldmanshare.id);
        assert_eq!(
            decoded.feldmanshare.share,
            shares[party_id].feldmanshare.share
        );
    }

    #[test]
    fn test_avss_input_share_bool() {
        let n = 4;
        let t = 1;
        let party_id = 1;
        let secret = Fr::from(1u64); // true

        let shares = generate_feldman_shares(secret, n, t);
        let bytes =
            Bls12381AvssMpcEngine::encode_feldman_share(&shares[party_id]).expect("encode failed");
        let decoded = Bls12381AvssMpcEngine::decode_feldman_share(&bytes).expect("decode failed");
        assert_eq!(decoded.feldmanshare.id, shares[party_id].feldmanshare.id);
    }

    #[test]
    fn test_avss_input_share_float() {
        let n = 4;
        let t = 1;
        let party_id = 2;

        let f = 16u32;
        let scale = (1u64 << f) as f64;
        let scaled_value = (3.14 * scale) as i64;
        let secret = Fr::from(scaled_value as u64);

        let shares = generate_feldman_shares(secret, n, t);
        let bytes =
            Bls12381AvssMpcEngine::encode_feldman_share(&shares[party_id]).expect("encode failed");
        let decoded = Bls12381AvssMpcEngine::decode_feldman_share(&bytes).expect("decode failed");
        assert_eq!(decoded.feldmanshare.id, shares[party_id].feldmanshare.id);
    }

    #[test]
    fn test_avss_fixed_point_negative_encoding_roundtrip() {
        let ty = ShareType::default_secret_fixed_point();
        let precision = match ty {
            ShareType::SecretFixedPoint { precision } => precision,
            _ => unreachable!(),
        };
        let f = precision.f();
        let scale = (1u64 << f) as f64;

        // Choose a power-of-two denominator so this is exactly representable.
        let clear = -3.25f64;
        let scaled = (clear * scale) as i64;
        let encoded = Bls12381AvssMpcEngine::field_from_i64(scaled);
        let decoded = Bls12381AvssMpcEngine::field_to_value(ty, encoded).expect("decode value");

        match decoded {
            Value::Float(v) => assert!(
                (v.0 - clear).abs() < 1e-12,
                "expected {}, got {}",
                clear,
                v.0
            ),
            other => panic!("expected Value::Float, got {:?}", other),
        }
    }

    /// Verify that negative fixed-point values survive the full
    /// encode → share → reconstruct → decode pipeline.
    /// Regression test for the mismatch demonstrated in PR #31.
    #[test]
    fn test_avss_negative_fixed_point_share_reconstruct_roundtrip() {
        let n = 4;
        let t = 1;
        let ty = ShareType::default_secret_fixed_point();
        let precision = match ty {
            ShareType::SecretFixedPoint { precision } => precision,
            _ => unreachable!(),
        };

        let clear_value = -3.25_f64;
        let scale = (1u64 << precision.f()) as f64;
        let scaled_value = (clear_value * scale) as i64;

        // Encode using the AVSS engine's field_from_i64 (now delegates to curve::field_from_i64).
        let secret = Bls12381AvssMpcEngine::field_from_i64(scaled_value);

        // Share and reconstruct
        let shares = generate_feldman_shares(secret, n, t);
        let subset: Vec<_> = shares.iter().take(t + 1).cloned().collect();
        let recovered = Bls12381AvssMpcEngine::reconstruct_secret(&subset, n, t)
            .expect("reconstruct_secret failed");

        // Decode using field_to_value (now delegates to curve::field_to_i64).
        let decoded = Bls12381AvssMpcEngine::field_to_value(ty, recovered).expect("decode value");

        match decoded {
            Value::Float(v) => assert!(
                (v.0 - clear_value).abs() < 1e-12,
                "negative fixed-point round-trip failed: expected {}, got {}",
                clear_value,
                v.0
            ),
            other => panic!("expected Value::Float, got {:?}", other),
        }
    }

    #[test]
    fn test_avss_input_share_reconstruction() {
        let n = 4;
        let t = 1;
        let secret_val = 12345u64;
        let secret = Fr::from(secret_val);

        let shares = generate_feldman_shares(secret, n, t);

        let mut decoded_shares = Vec::new();
        for share in &shares {
            let bytes = Bls12381AvssMpcEngine::encode_feldman_share(share).expect("encode failed");
            let decoded =
                Bls12381AvssMpcEngine::decode_feldman_share(&bytes).expect("decode failed");
            decoded_shares.push(decoded);
        }

        let required = t + 1;
        let subset: Vec<_> = decoded_shares.iter().take(required).cloned().collect();
        let recovered = Bls12381AvssMpcEngine::reconstruct_secret(&subset, n, t)
            .expect("reconstruct_secret failed");
        assert_eq!(
            recovered, secret,
            "Reconstructed secret should match original"
        );
    }

    #[test]
    fn test_bn254_input_share_reconstruction() {
        use ark_bn254::{Fr as BnFr, G1Projective as BnG1};
        use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};

        let mut rng = test_rng();
        let n = 4;
        let t = 1;
        let secret_val = 12345u64;
        let secret = BnFr::from(secret_val);

        let mut poly = DensePolynomial::<BnFr>::rand(t, &mut rng);
        poly[0] = secret;
        let generator = <BnG1 as PrimeGroup>::generator();
        let commitments: Vec<BnG1> = poly.coeffs.iter().map(|c| generator * c).collect();

        let shares: Vec<_> = (1..=n)
            .map(|i| {
                let x = BnFr::from(i as u64);
                let y = poly.evaluate(&x);
                FeldmanShamirShare::<BnFr, BnG1>::new(y, i, t, commitments.clone()).unwrap()
            })
            .collect();

        let mut decoded_shares = Vec::new();
        for share in &shares {
            let bytes = Bn254AvssMpcEngine::encode_feldman_share(share).expect("encode failed");
            let decoded = Bn254AvssMpcEngine::decode_feldman_share(&bytes).expect("decode failed");
            decoded_shares.push(decoded);
        }

        let required = t + 1;
        let subset: Vec<_> = decoded_shares.iter().take(required).cloned().collect();
        let recovered =
            Bn254AvssMpcEngine::reconstruct_secret(&subset, n, t).expect("reconstruct_secret failed");
        assert_eq!(
            recovered, secret,
            "Reconstructed secret should match original"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_avss_input_share_session_allocation_is_consistent_across_parties() {
        let n = 4usize;
        let t = 1usize;
        let instance_id = 77u64;

        let net = Arc::new(QuicNetworkManager::new());
        let pk_map = Arc::new(vec![G1::generator(); n]);

        let e0 = AvssMpcEngine::<Fr, G1>::new(
            instance_id,
            0,
            n,
            t,
            net.clone(),
            Fr::from(11u64),
            pk_map.clone(),
        )
        .await
        .expect("engine0");
        let e1 = AvssMpcEngine::<Fr, G1>::new(instance_id, 1, n, t, net, Fr::from(13u64), pk_map)
            .await
            .expect("engine1");

        let (dealer0, sid0) = e0.allocate_input_share_session().expect("session0");
        let (dealer1, sid1) = e1.allocate_input_share_session().expect("session1");
        assert_eq!(dealer0, dealer1, "dealer selection must be deterministic");
        assert_eq!(
            sid0.as_u64(),
            sid1.as_u64(),
            "session ids must match across parties for the same input_share round"
        );

        let (dealer0_next, sid0_next) = e0.allocate_input_share_session().expect("session0-next");
        let (dealer1_next, sid1_next) = e1.allocate_input_share_session().expect("session1-next");
        assert_eq!(
            dealer0_next, dealer1_next,
            "dealer selection must stay aligned across rounds"
        );
        assert_eq!(
            sid0_next.as_u64(),
            sid1_next.as_u64(),
            "session ids must stay aligned across rounds"
        );
    }
}
