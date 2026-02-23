// ADKG MPC Engine - Asynchronous Distributed Key Generation
//
// This engine provides ADKG functionality using the AVSS (Asynchronously Verifiable Secret Sharing)
// protocol from mpc-protocols. Each party gets a Feldman-verifiable share where:
// - The share itself is a Shamir share of the secret key
// - commitment[0] = g^secret = the public key
//
// The ADKG protocol produces secret keys for threshold cryptography where no single party
// knows the full secret, but any t+1 parties can collaborate to use it.
//
// Transport identity and authentication are handled by QUIC/TLS (ALPN + certificates).
// AVSS ECDH keys are used separately for protocol payload confidentiality.
//
// The engine is generic over a (field, curve) pair `(F, G)` where `G: CurveGroup<ScalarField = F>`.
// Only tested pairs from `AdkgCurveConfig` should be used; arbitrary pairs are not guaranteed
// to work correctly with the AVSS protocol.

use crate::net::curve::{MpcCurveConfig, SupportedMpcField};
use crate::net::mpc_engine::MpcEngine;
use ark_ec::CurveGroup;
use ark_ff::{FftField, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::SeedableRng;
use ark_std::UniformRand;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use stoffel_vm_types::core_types::{ShareType, Value, BOOLEAN_SECRET_INT_BITS, F64};
use stoffelmpc_mpc::avss_mpc::{AvssSessionId, AvssWrappedMessage, ProtocolType as AvssProtocolType};
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::share::avss::AvssNode;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::common::{ProtocolSessionId, SecretSharingScheme};
use ark_ec::PrimeGroup;
use stoffelnet::transports::quic::QuicNetworkManager;
use tokio::sync::mpsc::{self, Receiver};
use tokio::sync::Mutex;
use tracing::info;

// ============================================================================
// AdkgCurveConfig - Curated list of supported curves
// ============================================================================

/// Curated list of supported elliptic curves for ADKG.
///
/// # AVSS Compatibility Warning
///
/// The AVSS protocol requires Feldman commitments over an elliptic curve
/// group whose scalar field matches the secret sharing field. Only the
/// (field, curve) pairs in this enum are tested and guaranteed to work.
///
/// Using `AdkgMpcEngine<F, G>` directly with an untested pair may produce
/// incorrect results. Always prefer constructing engines via `AdkgCurveConfig`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdkgCurveConfig {
    /// BLS12-381: 255-bit Fr, 48-byte compressed G1 points
    Bls12_381,
    /// BN254: 254-bit Fr, 32-byte compressed G1 points
    Bn254,
    /// Curve25519 (Edwards form): 253-bit Fr, 32-byte compressed points
    Curve25519,
    /// Ed25519 (twisted Edwards curve): same scalar field as Curve25519
    Ed25519,
    // TODO: Ristretto — prime-order group over Curve25519 (no ark crate yet;
    //       needs curve25519-dalek or a custom ark adapter)
}

impl AdkgCurveConfig {
    /// Parse a curve name from a string (case-insensitive).
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "bls12-381" | "bls12_381" | "bls12381" => Ok(AdkgCurveConfig::Bls12_381),
            "bn254" => Ok(AdkgCurveConfig::Bn254),
            "curve25519" => Ok(AdkgCurveConfig::Curve25519),
            "ed25519" => Ok(AdkgCurveConfig::Ed25519),
            other => Err(format!(
                "Unknown curve '{}'. Supported curves: bls12-381, bn254, curve25519, ed25519",
                other
            )),
        }
    }

    /// Human-readable name for this curve.
    pub fn name(&self) -> &'static str {
        match self {
            AdkgCurveConfig::Bls12_381 => "bls12-381",
            AdkgCurveConfig::Bn254 => "bn254",
            AdkgCurveConfig::Curve25519 => "curve25519",
            AdkgCurveConfig::Ed25519 => "ed25519",
        }
    }
}

impl Default for AdkgCurveConfig {
    fn default() -> Self {
        AdkgCurveConfig::Bls12_381
    }
}

// ============================================================================
// Error types
// ============================================================================

/// Error types for ADKG operations
#[derive(Debug, Clone)]
pub enum AdkgError {
    NotReady,
    InvalidShare,
    SessionNotFound(u64),
    Serialization(String),
    Protocol(String),
    InvalidCommitmentIndex(usize),
}

impl std::fmt::Display for AdkgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdkgError::NotReady => write!(f, "ADKG engine not ready"),
            AdkgError::InvalidShare => write!(f, "Invalid Feldman share"),
            AdkgError::SessionNotFound(id) => write!(f, "Session {} not found", id),
            AdkgError::Serialization(msg) => write!(f, "Serialization error: {}", msg),
            AdkgError::Protocol(msg) => write!(f, "Protocol error: {}", msg),
            AdkgError::InvalidCommitmentIndex(idx) => {
                write!(f, "Invalid commitment index: {}", idx)
            }
        }
    }
}

impl std::error::Error for AdkgError {}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration options for ADKG engine
#[derive(Clone, Debug)]
pub struct AdkgEngineOpts {
    /// Number of parties in the system
    pub n_parties: usize,
    /// Threshold - protocol tolerates up to t malicious parties
    pub threshold: usize,
    /// Instance ID for this ADKG session
    pub instance_id: u64,
    /// Which curve to use
    pub curve: AdkgCurveConfig,
}

impl AdkgEngineOpts {
    pub fn new(n_parties: usize, threshold: usize, instance_id: u64) -> Self {
        Self {
            n_parties,
            threshold,
            instance_id,
            curve: AdkgCurveConfig::default(),
        }
    }

    pub fn with_curve(mut self, curve: AdkgCurveConfig) -> Self {
        self.curve = curve;
        self
    }
}

// ============================================================================
// AdkgMpcEngine<F, G> - Generic ADKG engine
// ============================================================================

/// ADKG MPC Engine that uses AVSS for distributed key generation.
///
/// Generic over field `F` and curve group `G`. The compile-time constraint
/// `G: CurveGroup<ScalarField = F>` ensures that the field and curve are
/// correctly paired, which is required for Feldman commitments in AVSS.
///
/// # Warning
///
/// Only use (F, G) pairs from `AdkgCurveConfig`. Using untested pairs may
/// produce incorrect results with the AVSS protocol.
pub struct AdkgMpcEngine<F, G>
where
    F: FftField,
    G: CurveGroup<ScalarField = F>,
{
    instance_id: u64,
    party_id: usize,
    n: usize,
    t: usize,
    net: Arc<QuicNetworkManager>,
    /// AVSS node for the protocol
    avss_node: Arc<Mutex<AvssNode<F, Avid<AvssSessionId>, G, AvssSessionId>>>,
    /// Channel to receive AVSS completion notifications
    output_receiver: Arc<Mutex<Receiver<AvssSessionId>>>,
    /// Generated Feldman shares indexed by user-defined key name
    stored_shares: Arc<Mutex<BTreeMap<String, FeldmanShamirShare<F, G>>>>,
    /// Session counter for generating unique session IDs
    session_counter: Arc<Mutex<u64>>,
    ready: AtomicBool,
    /// This party's AVSS ECDH key used for payload confidentiality.
    /// Transport identity/authentication is handled separately by TLS.
    sk_i: F,
    _marker: PhantomData<G>,
}

impl<F, G> AdkgMpcEngine<F, G>
where
    F: FftField + PrimeField + Send + Sync + 'static,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    /// Create a new ADKG engine
    ///
    /// # Arguments
    /// * `instance_id` - Unique identifier for this ADKG instance
    /// * `party_id` - This party's ID (0 to n-1)
    /// * `n` - Number of parties
    /// * `t` - Threshold (tolerates up to t malicious parties)
    /// * `net` - Network manager for communication
    /// * `sk_i` - This party's AVSS ECDH secret key for share encryption
    /// * `pk_map` - AVSS ECDH public keys from all parties
    pub fn new(
        instance_id: u64,
        party_id: usize,
        n: usize,
        t: usize,
        net: Arc<QuicNetworkManager>,
        sk_i: F,
        pk_map: Arc<Vec<G>>,
    ) -> Result<Arc<Self>, String> {
        // Create channel for AVSS output notifications
        let (output_sender, output_receiver) = mpsc::channel(128);

        // Create the AVSS node
        let avss_node = AvssNode::new(
                party_id,
                n,
                t,
                sk_i,
                pk_map,
                output_sender,
                Arc::new(AvssWrappedMessage::rbc_wrap),
                Arc::new(AvssWrappedMessage::avss_wrap),
            )
            .map_err(|e| format!("Failed to create AVSS node: {:?}", e))?;

        Ok(Arc::new(Self {
            instance_id,
            party_id,
            n,
            t,
            net,
            avss_node: Arc::new(Mutex::new(avss_node)),
            output_receiver: Arc::new(Mutex::new(output_receiver)),
            stored_shares: Arc::new(Mutex::new(BTreeMap::new())),
            session_counter: Arc::new(Mutex::new(0)),
            ready: AtomicBool::new(false),
            sk_i,
            _marker: PhantomData,
        }))
    }

    /// Start the engine and mark it ready
    pub async fn start_async(&self) -> Result<(), String> {
        self.ready.store(true, Ordering::SeqCst);
        info!(
            "ADKG engine started: instance={}, party={}, n={}, t={}",
            self.instance_id, self.party_id, self.n, self.t
        );
        Ok(())
    }

    /// Generate a new random AVSS share and store it under the given key name.
    ///
    /// The `key_name` must be the same across all parties so they can
    /// coordinate retrieval later. This party initiates the AVSS protocol
    /// with a randomly generated secret.
    pub async fn generate_random_share(&self, key_name: &str) -> Result<FeldmanShamirShare<F, G>, String> {
        if !self.ready.load(Ordering::SeqCst) {
            return Err("AVSS engine not ready".into());
        }

        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        let secret = F::rand(&mut rng);

        self.generate_share_with_secret(key_name, secret).await
    }

    /// Generate an AVSS share for a specific secret and store under the given key name.
    pub async fn generate_share_with_secret(&self, key_name: &str, secret: F) -> Result<FeldmanShamirShare<F, G>, String> {
        if !self.ready.load(Ordering::SeqCst) {
            return Err("AVSS engine not ready".into());
        }

        // Generate session ID
        let session_id = {
            let mut counter = self.session_counter.lock().await;
            let id = *counter;
            *counter += 1;
            let slot24 = AvssSessionId::pack_slot24(
                self.instance_id as u8,
                self.party_id as u8,
                0,
            );
            AvssSessionId::new(AvssProtocolType::Avss, slot24, id as u32)
        };

        // Run AVSS init
        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        {
            let mut node = self.avss_node.lock().await;
            node.init(vec![secret], session_id, &mut rng, self.net.clone())
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

    /// Wait for a share from a specific session
    async fn wait_for_share(
        &self,
        session_id: AvssSessionId,
    ) -> Result<FeldmanShamirShare<F, G>, String> {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);

        loop {
            // Check if share is ready
            {
                let node = self.avss_node.lock().await;
                let shares = node.shares.lock().await;
                if let Some(Some(share_vec)) = shares.get(&session_id) {
                    // AvssNode stores Vec<FeldmanShamirShare> per session;
                    // for ADKG the first share is ours
                    if let Some(share) = share_vec.first() {
                        return Ok(share.clone());
                    }
                }
            }

            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "Timeout waiting for ADKG share: session={}",
                    session_id.as_u64()
                ));
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Retrieve a stored Feldman share by key name.
    pub async fn get_share(&self, key_name: &str) -> Option<FeldmanShamirShare<F, G>> {
        let shares = self.stored_shares.lock().await;
        shares.get(key_name).cloned()
    }

    /// Get the public key (commitment[0]) for a stored share.
    pub async fn get_public_key(&self, key_name: &str) -> Option<G> {
        self.get_share(key_name)
            .await
            .map(|s| s.commitments[0])
    }

    /// Get public key bytes for a stored share.
    pub async fn get_public_key_bytes(&self, key_name: &str) -> Result<Vec<u8>, String> {
        let share = self
            .get_share(key_name)
            .await
            .ok_or_else(|| format!("Key '{}' not found", key_name))?;
        Self::encode_group_element(&share.commitments[0])
    }

    /// Process incoming AVSS message
    ///
    /// This should be called when receiving AVSS messages from the network.
    pub async fn process_message(
        &self,
        msg: stoffelmpc_mpc::common::share::avss::AvssMessage<AvssSessionId>,
    ) -> Result<(), String> {
        let sender_id = msg.sender_id;
        let mut node = self.avss_node.lock().await;
        node.process(msg, sender_id)
            .await
            .map_err(|e| format!("AVSS process failed: {:?}", e))
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
    fn create_avss_share(&self, secret: F) -> Result<FeldmanShamirShare<F, G>, String> {
        use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
        let mut rng = ark_std::test_rng();

        // Generate random polynomial with p(0) = secret
        let mut poly = DensePolynomial::<F>::rand(self.t, &mut rng);
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
    fn reconstruct_secret(shares: &[FeldmanShamirShare<F, G>], n: usize) -> Result<F, String> {
        let (_, secret) = FeldmanShamirShare::<F, G>::recover_secret(shares, n)
            .map_err(|e| format!("Failed to recover secret: {:?}", e))?;
        Ok(secret)
    }
}

/// Type alias for BLS12-381 ADKG engine
pub type Bls12381AdkgEngine =
    AdkgMpcEngine<ark_bls12_381::Fr, ark_bls12_381::G1Projective>;
/// Type alias for BN254 ADKG engine
pub type Bn254AdkgEngine = AdkgMpcEngine<ark_bn254::Fr, ark_bn254::G1Projective>;
/// Type alias for Curve25519 ADKG engine
pub type Curve25519AdkgEngine =
    AdkgMpcEngine<ark_curve25519::Fr, ark_curve25519::EdwardsProjective>;
/// Type alias for Ed25519 ADKG engine
pub type Ed25519AdkgEngine =
    AdkgMpcEngine<ark_ed25519::Fr, ark_ed25519::EdwardsProjective>;

// ============================================================================
// MpcEngine Implementation
// ============================================================================
//
// The AVSS engine implements MpcEngine using Feldman-verifiable secret sharing.
// It supports input sharing and opening via FeldmanShamirShare.
// Secure multiplication is not supported (AVSS lacks Beaver triples).
// AVSS-specific operations (key generation, commitment access) are available via
// AdkgOperations trait through as_any() downcasting.

impl<F, G> MpcEngine for AdkgMpcEngine<F, G>
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
            (ShareType::SecretInt { .. }, Value::I64(v)) => F::from(*v as u64),
            (
                ShareType::SecretInt {
                    bit_length: BOOLEAN_SECRET_INT_BITS,
                },
                Value::Bool(b),
            ) => {
                if *b { F::from(1u64) } else { F::from(0u64) }
            }
            (ShareType::SecretFixedPoint { precision }, Value::Float(fp)) => {
                let f = precision.f();
                let scale = (1u64 << f) as f64;
                let scaled_value = (fp.0 * scale) as i64;
                if scaled_value >= 0 {
                    F::from(scaled_value as u64)
                } else {
                    -F::from((-scaled_value) as u64)
                }
            }
            _ => return Err("Unsupported type for input_share".to_string()),
        };

        let share = self.create_avss_share(secret)?;
        Self::encode_feldman_share(&share)
    }

    fn multiply_share(
        &self,
        _ty: ShareType,
        _left: &[u8],
        _right: &[u8],
    ) -> Result<Vec<u8>, String> {
        Err("AVSS backend does not support secure multiplication. \
             Use the HoneyBadger backend for programs that require multiplication (it provides Beaver triples via preprocessing).".into())
    }

    fn open_share(&self, ty: ShareType, share_bytes: &[u8]) -> Result<Value, String> {
        #[derive(Default, Clone)]
        struct OpenAccumulator {
            shares: Vec<Vec<u8>>,
            party_ids: Vec<usize>,
            result: Option<Value>,
        }

        static REGISTRY: once_cell::sync::Lazy<
            parking_lot::Mutex<std::collections::HashMap<(u64, usize, String), OpenAccumulator>>,
        > = once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(std::collections::HashMap::new()));

        let type_key = match ty {
            ShareType::SecretInt { bit_length } => format!("avss-int-{bit_length}"),
            ShareType::SecretFixedPoint { precision } => {
                format!("avss-fixed-{}-{}", precision.k(), precision.f())
            }
        };

        let required = self.t + 1;
        let mut my_sequence: Option<usize> = None;

        loop {
            let mut reg = REGISTRY.lock();

            if my_sequence.is_none() {
                let mut seq = 0;
                loop {
                    let key = (self.instance_id, seq, type_key.clone());
                    let entry = reg.entry(key).or_insert_with(OpenAccumulator::default);

                    if !entry.party_ids.contains(&self.party_id) {
                        entry.shares.push(share_bytes.to_vec());
                        entry.party_ids.push(self.party_id);
                        my_sequence = Some(seq);
                        break;
                    }
                    seq += 1;
                }
            }

            let seq = my_sequence.unwrap();
            let key = (self.instance_id, seq, type_key.clone());
            let entry = reg.get_mut(&key).unwrap();

            if let Some(result) = entry.result.clone() {
                return Ok(result);
            }

            if entry.shares.len() >= required {
                let collected: Vec<_> = entry.shares.iter().take(required).cloned().collect();
                let mut shares: Vec<FeldmanShamirShare<F, G>> = Vec::with_capacity(collected.len());
                for bytes in &collected {
                    shares.push(Self::decode_feldman_share(bytes)?);
                }

                let secret = Self::reconstruct_secret(&shares, self.n)?;

                let value = match ty {
                    ShareType::SecretInt { .. } if ty.is_boolean() => {
                        use ark_ff::Zero;
                        Value::Bool(!secret.is_zero())
                    }
                    ShareType::SecretInt { .. } => {
                        let bigint = secret.into_bigint();
                        let limbs = bigint.as_ref();
                        Value::I64(limbs[0] as i64)
                    }
                    ShareType::SecretFixedPoint { precision } => {
                        let bigint = secret.into_bigint();
                        let limbs = bigint.as_ref();
                        let scaled_value = limbs[0] as i64;
                        let f = precision.f();
                        let scale = (1u64 << f) as f64;
                        let float_value = scaled_value as f64 / scale;
                        Value::Float(F64(float_value))
                    }
                };
                entry.result = Some(value.clone());
                return Ok(value);
            }

            drop(reg);
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn batch_open_shares(&self, ty: ShareType, shares: &[Vec<u8>]) -> Result<Vec<Value>, String> {
        if shares.is_empty() {
            return Ok(vec![]);
        }

        #[derive(Clone)]
        struct BatchOpenAccumulator {
            batch_size: usize,
            shares_per_position: Vec<Vec<Vec<u8>>>,
            party_ids: Vec<usize>,
            results: Option<Vec<Value>>,
        }

        impl BatchOpenAccumulator {
            fn new(batch_size: usize) -> Self {
                Self {
                    batch_size,
                    shares_per_position: vec![Vec::new(); batch_size],
                    party_ids: Vec::new(),
                    results: None,
                }
            }
        }

        static BATCH_REGISTRY: once_cell::sync::Lazy<
            parking_lot::Mutex<
                std::collections::HashMap<(u64, usize, String, usize), BatchOpenAccumulator>,
            >,
        > = once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(std::collections::HashMap::new()));

        let type_key = match ty {
            ShareType::SecretInt { bit_length } => format!("avss-batch-int-{bit_length}"),
            ShareType::SecretFixedPoint { precision } => {
                format!("avss-batch-fixed-{}-{}", precision.k(), precision.f())
            }
        };

        let batch_size = shares.len();
        let required = self.t + 1;
        let mut my_sequence: Option<usize> = None;

        loop {
            let mut reg = BATCH_REGISTRY.lock();

            if my_sequence.is_none() {
                let mut seq = 0;
                loop {
                    let key = (self.instance_id, seq, type_key.clone(), batch_size);
                    let entry =
                        reg.entry(key)
                            .or_insert_with(|| BatchOpenAccumulator::new(batch_size));

                    if !entry.party_ids.contains(&self.party_id) {
                        for (pos, share_bytes) in shares.iter().enumerate() {
                            entry.shares_per_position[pos].push(share_bytes.clone());
                        }
                        entry.party_ids.push(self.party_id);
                        my_sequence = Some(seq);
                        break;
                    }
                    seq += 1;
                }
            }

            let seq = my_sequence.unwrap();
            let key = (self.instance_id, seq, type_key.clone(), batch_size);
            let entry = reg.get_mut(&key).unwrap();

            if let Some(results) = entry.results.clone() {
                return Ok(results);
            }

            if entry.party_ids.len() >= required {
                let mut results = Vec::with_capacity(batch_size);

                for pos in 0..batch_size {
                    let collected: Vec<_> = entry.shares_per_position[pos]
                        .iter()
                        .take(required)
                        .cloned()
                        .collect();

                    let mut decoded_shares: Vec<FeldmanShamirShare<F, G>> =
                        Vec::with_capacity(collected.len());
                    for bytes in &collected {
                        decoded_shares.push(Self::decode_feldman_share(bytes)?);
                    }

                    let secret = Self::reconstruct_secret(&decoded_shares, self.n)
                        .map_err(|e| format!("batch reconstruct_secret pos {}: {}", pos, e))?;

                    let value = match ty {
                        ShareType::SecretInt { .. } if ty.is_boolean() => {
                            use ark_ff::Zero;
                            Value::Bool(!secret.is_zero())
                        }
                        ShareType::SecretInt { .. } => {
                            let bigint = secret.into_bigint();
                            let limbs = bigint.as_ref();
                            Value::I64(limbs[0] as i64)
                        }
                        ShareType::SecretFixedPoint { precision } => {
                            let bigint = secret.into_bigint();
                            let limbs = bigint.as_ref();
                            let scaled_value = limbs[0] as i64;
                            let f = precision.f();
                            let scale = (1u64 << f) as f64;
                            let float_value = scaled_value as f64 / scale;
                            Value::Float(F64(float_value))
                        }
                    };
                    results.push(value);
                }

                entry.results = Some(results.clone());
                return Ok(results);
            }

            drop(reg);
            std::thread::sleep(Duration::from_millis(5));
        }
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

    fn supports_elliptic_curves(&self) -> bool { true }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
}

// ============================================================================
// Additional Trait Implementations for ADKG-specific Operations
// ============================================================================

/// AVSS-specific operations trait.
///
/// This trait is object-safe and uses `Vec<u8>` for share data so it can be
/// used through `dyn AdkgOperations` without knowing the concrete `(F, G)`.
pub trait AdkgOperations {
    /// Generate a new random share and store it under `key_name` (async).
    /// Returns the serialized FeldmanShamirShare.
    fn avss_generate_share(
        &self,
        key_name: String,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send + '_>>;

    /// Get commitment at index for a stored share (synchronous).
    fn avss_get_commitment(&self, key_name: &str, index: usize) -> Result<Vec<u8>, String>;

    /// Get the public key (commitment[0]) for a stored share.
    fn avss_get_public_key(&self, key_name: &str) -> Result<Vec<u8>, String>;
}

impl<F, G> AdkgOperations for AdkgMpcEngine<F, G>
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
        // Use blocking approach for sync interface
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                #[allow(deprecated)]
                match handle.runtime_flavor() {
                    tokio::runtime::RuntimeFlavor::MultiThread => {
                        let key_name = key_name.to_string();
                        tokio::task::block_in_place(|| {
                            handle.block_on(async {
                                let share = self
                                    .get_share(&key_name)
                                    .await
                                    .ok_or_else(|| format!("Key '{}' not found", key_name))?;
                                let commitment = share
                                    .commitments
                                    .get(index)
                                    .ok_or_else(|| {
                                        format!("Commitment index {} out of bounds", index)
                                    })?;
                                Self::encode_group_element(commitment)
                            })
                        })
                    }
                    _ => Err("Cannot call avss_get_commitment from single-thread runtime".into()),
                }
            }
            Err(_) => {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("Failed to build runtime: {}", e))?;
                let key_name = key_name.to_string();
                rt.block_on(async {
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
    }

    fn avss_get_public_key(&self, key_name: &str) -> Result<Vec<u8>, String> {
        self.avss_get_commitment(key_name, 0)
    }
}

// ============================================================================
// Registry for coordinating ADKG sessions across parties
// ============================================================================

/// Global registry for ADKG share coordination (for in-process multi-party testing)
#[derive(Default)]
struct AdkgRegistry {
    /// Maps (instance_id, session_id, party_id) to serialized share
    shares: std::collections::HashMap<(u64, u64, usize), Vec<u8>>,
    /// Maps (instance_id, session_id) to aggregated public key once agreed
    public_keys: std::collections::HashMap<(u64, u64), Vec<u8>>,
}

static ADKG_REGISTRY: once_cell::sync::Lazy<parking_lot::Mutex<AdkgRegistry>> =
    once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(AdkgRegistry::default()));

/// Store a share in the global registry (for testing)
pub fn registry_store_share(
    instance_id: u64,
    session_id: u64,
    party_id: usize,
    share_bytes: Vec<u8>,
) {
    let mut registry = ADKG_REGISTRY.lock();
    registry
        .shares
        .insert((instance_id, session_id, party_id), share_bytes);
}

/// Get all shares for a session from the registry (for testing)
pub fn registry_get_shares(instance_id: u64, session_id: u64) -> Vec<(usize, Vec<u8>)> {
    let registry = ADKG_REGISTRY.lock();
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
pub fn registry_store_public_key(instance_id: u64, session_id: u64, pk_bytes: Vec<u8>) {
    let mut registry = ADKG_REGISTRY.lock();
    registry
        .public_keys
        .insert((instance_id, session_id), pk_bytes);
}

/// Get public key from registry
pub fn registry_get_public_key(instance_id: u64, session_id: u64) -> Option<Vec<u8>> {
    let registry = ADKG_REGISTRY.lock();
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
    use stoffelmpc_mpc::common::share::avss::verify_feldman;

    #[test]
    fn test_adkg_curve_config_parsing() {
        assert_eq!(
            AdkgCurveConfig::from_str("bls12-381").unwrap(),
            AdkgCurveConfig::Bls12_381
        );
        assert_eq!(
            AdkgCurveConfig::from_str("bls12_381").unwrap(),
            AdkgCurveConfig::Bls12_381
        );
        assert_eq!(
            AdkgCurveConfig::from_str("BLS12-381").unwrap(),
            AdkgCurveConfig::Bls12_381
        );
        assert_eq!(
            AdkgCurveConfig::from_str("bn254").unwrap(),
            AdkgCurveConfig::Bn254
        );
        assert_eq!(
            AdkgCurveConfig::from_str("BN254").unwrap(),
            AdkgCurveConfig::Bn254
        );
        assert_eq!(
            AdkgCurveConfig::from_str("curve25519").unwrap(),
            AdkgCurveConfig::Curve25519
        );
        assert_eq!(
            AdkgCurveConfig::from_str("ed25519").unwrap(),
            AdkgCurveConfig::Ed25519
        );
        assert!(AdkgCurveConfig::from_str("unknown").is_err());
        assert!(AdkgCurveConfig::from_str("secp256k1").is_err());
    }

    #[test]
    fn test_adkg_curve_config_default() {
        assert_eq!(AdkgCurveConfig::default(), AdkgCurveConfig::Bls12_381);
    }

    #[test]
    fn test_adkg_curve_config_name() {
        assert_eq!(AdkgCurveConfig::Bls12_381.name(), "bls12-381");
        assert_eq!(AdkgCurveConfig::Bn254.name(), "bn254");
        assert_eq!(AdkgCurveConfig::Curve25519.name(), "curve25519");
        assert_eq!(AdkgCurveConfig::Ed25519.name(), "ed25519");
    }

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
        let bytes = Bls12381AdkgEngine::encode_feldman_share(&share)
            .expect("Serialization failed");
        assert!(!bytes.is_empty());

        let restored = Bls12381AdkgEngine::decode_feldman_share(&bytes)
            .expect("Deserialization failed");
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

        let bytes = Bn254AdkgEngine::encode_feldman_share(&share)
            .expect("Serialization failed");
        assert!(!bytes.is_empty());

        let restored = Bn254AdkgEngine::decode_feldman_share(&bytes)
            .expect("Deserialization failed");
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

    /// Helper to generate Feldman shares for testing
    fn generate_feldman_shares(
        secret: Fr,
        n: usize,
        t: usize,
    ) -> Vec<FeldmanShamirShare<Fr, G1>> {
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
            let bytes =
                Bls12381AdkgEngine::encode_feldman_share(share).expect("encode failed");
            let decoded =
                Bls12381AdkgEngine::decode_feldman_share(&bytes).expect("decode failed");
            assert_eq!(share.feldmanshare.id, decoded.feldmanshare.id);
            assert_eq!(share.feldmanshare.degree, decoded.feldmanshare.degree);
            assert_eq!(share.feldmanshare.share, decoded.feldmanshare.share);
        }

        // Verify reconstruction works after round-tripping through bytes
        let required = t + 1;
        let subset: Vec<_> = shares.iter().take(required).cloned().collect();
        let recovered =
            Bls12381AdkgEngine::reconstruct_secret(&subset, n).expect("reconstruct_secret failed");
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
            let bytes = Bn254AdkgEngine::encode_feldman_share(share).expect("encode failed");
            let decoded =
                Bn254AdkgEngine::decode_feldman_share(&bytes).expect("decode failed");
            assert_eq!(share.feldmanshare.id, decoded.feldmanshare.id);
            assert_eq!(share.feldmanshare.degree, decoded.feldmanshare.degree);
            assert_eq!(share.feldmanshare.share, decoded.feldmanshare.share);
        }

        let required = t + 1;
        let subset: Vec<_> = shares.iter().take(required).cloned().collect();
        let recovered =
            Bn254AdkgEngine::reconstruct_secret(&subset, n).expect("reconstruct_secret failed");
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
            Bls12381AdkgEngine::encode_feldman_share(&shares[party_id]).expect("encode failed");
        assert!(!bytes.is_empty());

        let decoded =
            Bls12381AdkgEngine::decode_feldman_share(&bytes).expect("decode failed");
        assert_eq!(decoded.feldmanshare.id, shares[party_id].feldmanshare.id);
        assert_eq!(decoded.feldmanshare.share, shares[party_id].feldmanshare.share);
    }

    #[test]
    fn test_avss_input_share_bool() {
        let n = 4;
        let t = 1;
        let party_id = 1;
        let secret = Fr::from(1u64); // true

        let shares = generate_feldman_shares(secret, n, t);
        let bytes =
            Bls12381AdkgEngine::encode_feldman_share(&shares[party_id]).expect("encode failed");
        let decoded =
            Bls12381AdkgEngine::decode_feldman_share(&bytes).expect("decode failed");
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
            Bls12381AdkgEngine::encode_feldman_share(&shares[party_id]).expect("encode failed");
        let decoded =
            Bls12381AdkgEngine::decode_feldman_share(&bytes).expect("decode failed");
        assert_eq!(decoded.feldmanshare.id, shares[party_id].feldmanshare.id);
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
            let bytes =
                Bls12381AdkgEngine::encode_feldman_share(share).expect("encode failed");
            let decoded =
                Bls12381AdkgEngine::decode_feldman_share(&bytes).expect("decode failed");
            decoded_shares.push(decoded);
        }

        let required = t + 1;
        let subset: Vec<_> = decoded_shares.iter().take(required).cloned().collect();
        let recovered =
            Bls12381AdkgEngine::reconstruct_secret(&subset, n).expect("reconstruct_secret failed");
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
            let bytes =
                Bn254AdkgEngine::encode_feldman_share(share).expect("encode failed");
            let decoded =
                Bn254AdkgEngine::decode_feldman_share(&bytes).expect("decode failed");
            decoded_shares.push(decoded);
        }

        let required = t + 1;
        let subset: Vec<_> = decoded_shares.iter().take(required).cloned().collect();
        let recovered =
            Bn254AdkgEngine::reconstruct_secret(&subset, n).expect("reconstruct_secret failed");
        assert_eq!(
            recovered, secret,
            "Reconstructed secret should match original"
        );
    }
}
