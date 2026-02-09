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
// The engine is generic over a (field, curve) pair `(F, G)` where `G: CurveGroup<ScalarField = F>`.
// Only tested pairs from `AdkgCurveConfig` should be used; arbitrary pairs are not guaranteed
// to work correctly with the AVSS protocol.

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
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
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
}

impl AdkgCurveConfig {
    /// Parse a curve name from a string (case-insensitive).
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "bls12-381" | "bls12_381" | "bls12381" => Ok(AdkgCurveConfig::Bls12_381),
            "bn254" => Ok(AdkgCurveConfig::Bn254),
            other => Err(format!(
                "Unknown ADKG curve '{}'. Supported curves: bls12-381, bn254",
                other
            )),
        }
    }

    /// Human-readable name for this curve.
    pub fn name(&self) -> &'static str {
        match self {
            AdkgCurveConfig::Bls12_381 => "bls12-381",
            AdkgCurveConfig::Bn254 => "bn254",
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
// AdkgSecretKey<F, G> - Generic secret key
// ============================================================================

/// Stored ADKG secret key with its Feldman commitments.
///
/// Generic over field `F` and curve group `G` where `G: CurveGroup<ScalarField = F>`.
#[derive(Clone, Debug)]
pub struct AdkgSecretKey<F: FftField, G: CurveGroup<ScalarField = F>> {
    /// The session ID this key belongs to
    pub session_id: u64,
    /// The Feldman-verifiable share
    pub share: FeldmanShamirShare<F, G>,
}

impl<F, G> AdkgSecretKey<F, G>
where
    F: FftField,
    G: CurveGroup<ScalarField = F>,
{
    /// Get the public key (commitment[0] = g^secret)
    pub fn public_key(&self) -> G {
        self.share.commitments[0]
    }

    /// Get commitment at a specific index
    pub fn commitment(&self, index: usize) -> Option<G> {
        self.share.commitments.get(index).cloned()
    }

    /// Get all commitments
    pub fn commitments(&self) -> &[G] {
        &self.share.commitments
    }

    /// Serialize the public key to bytes
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        self.share.commitments[0]
            .serialize_compressed(&mut bytes)
            .map_err(|e| format!("Failed to serialize public key: {:?}", e))?;
        Ok(bytes)
    }

    /// Serialize the entire secret key (share + commitments) to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        self.share
            .serialize_compressed(&mut bytes)
            .map_err(|e| format!("Failed to serialize secret key: {:?}", e))?;
        Ok(bytes)
    }

    /// Deserialize from bytes
    pub fn from_bytes(session_id: u64, bytes: &[u8]) -> Result<Self, String> {
        let share = FeldmanShamirShare::<F, G>::deserialize_compressed(bytes)
            .map_err(|e| format!("Failed to deserialize secret key: {:?}", e))?;
        Ok(Self { session_id, share })
    }
}

/// Type alias for BLS12-381 secret key
pub type Bls12381AdkgSecretKey =
    AdkgSecretKey<ark_bls12_381::Fr, ark_bls12_381::G1Projective>;
/// Type alias for BN254 secret key
pub type Bn254AdkgSecretKey = AdkgSecretKey<ark_bn254::Fr, ark_bn254::G1Projective>;

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
    /// Generated secret keys indexed by session ID
    secret_keys: Arc<Mutex<BTreeMap<u64, AdkgSecretKey<F, G>>>>,
    /// Session counter for generating unique session IDs
    session_counter: Arc<Mutex<u64>>,
    ready: AtomicBool,
    /// This party's secret key for ECDH in AVSS
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
    /// * `sk_i` - This party's secret key for ECDH
    /// * `pk_map` - Public keys of all parties for ECDH
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
            secret_keys: Arc::new(Mutex::new(BTreeMap::new())),
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

    /// Run ADKG as the dealer to generate a new distributed key
    ///
    /// This party initiates the AVSS protocol with a randomly generated secret.
    /// All parties will receive Feldman-verifiable shares.
    pub async fn generate_key(&self) -> Result<AdkgSecretKey<F, G>, String> {
        if !self.is_ready() {
            return Err("ADKG engine not ready".into());
        }

        // Generate a random secret
        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        let secret = F::rand(&mut rng);

        self.generate_key_with_secret(secret).await
    }

    /// Run ADKG as the dealer with a specific secret
    ///
    /// This allows testing with known secrets.
    pub async fn generate_key_with_secret(&self, secret: F) -> Result<AdkgSecretKey<F, G>, String> {
        if !self.is_ready() {
            return Err("ADKG engine not ready".into());
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
            "ADKG key generation initiated: party={}, session={}",
            self.party_id,
            session_id.as_u64()
        );

        // Wait for our own share to be processed
        let share = self.wait_for_share(session_id).await?;

        // Store the key
        let key = AdkgSecretKey {
            session_id: session_id.as_u64(),
            share,
        };
        {
            let mut keys = self.secret_keys.lock().await;
            keys.insert(session_id.as_u64(), key.clone());
        }

        Ok(key)
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

    /// Get a secret key by session ID
    pub async fn get_secret_key(&self, session_id: u64) -> Option<AdkgSecretKey<F, G>> {
        let keys = self.secret_keys.lock().await;
        keys.get(&session_id).cloned()
    }

    /// Get the public key for a session
    pub async fn get_public_key(&self, session_id: u64) -> Option<G> {
        self.get_secret_key(session_id)
            .await
            .map(|k| k.public_key())
    }

    /// Get public key bytes for a session
    pub async fn get_public_key_bytes(&self, session_id: u64) -> Result<Vec<u8>, String> {
        let key = self
            .get_secret_key(session_id)
            .await
            .ok_or_else(|| format!("Session {} not found", session_id))?;
        key.public_key_bytes()
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

    /// Encode a RobustShare to bytes using CanonicalSerialize
    fn encode_robustshare(share: &RobustShare<F>) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        share
            .serialize_compressed(&mut out)
            .map_err(|e| format!("serialize RobustShare: {}", e))?;
        Ok(out)
    }

    /// Decode a RobustShare from bytes using CanonicalDeserialize
    fn decode_robustshare(bytes: &[u8]) -> Result<RobustShare<F>, String> {
        RobustShare::<F>::deserialize_compressed(bytes)
            .map_err(|e| format!("deserialize RobustShare: {}", e))
    }
}

/// Type alias for BLS12-381 ADKG engine
pub type Bls12381AdkgEngine =
    AdkgMpcEngine<ark_bls12_381::Fr, ark_bls12_381::G1Projective>;
/// Type alias for BN254 ADKG engine
pub type Bn254AdkgEngine = AdkgMpcEngine<ark_bn254::Fr, ark_bn254::G1Projective>;

// ============================================================================
// MpcEngine Implementation
// ============================================================================
//
// The ADKG engine implements MpcEngine as a proper AVSS-based MPC protocol.
// It supports input sharing and opening via RobustShare, identical to HoneyBadger.
// Secure multiplication is not supported (AVSS lacks Beaver triples).
// ADKG-specific operations (key generation, commitment access) are available via
// AdkgOperations trait through as_any() downcasting.

impl<F, G> MpcEngine for AdkgMpcEngine<F, G>
where
    F: FftField + PrimeField + Send + Sync + 'static,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    fn protocol_name(&self) -> &'static str {
        "adkg"
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
        match (ty, clear) {
            (ShareType::SecretInt { .. }, Value::I64(v)) => {
                let secret = F::from(*v as u64);
                let mut rng = ark_std::test_rng();
                let shares = RobustShare::compute_shares(secret, self.n, self.t, None, &mut rng)
                    .map_err(|e| format!("compute_shares: {:?}", e))?;
                let my = &shares[self.party_id];
                Self::encode_robustshare(my)
            }
            (
                ShareType::SecretInt {
                    bit_length: BOOLEAN_SECRET_INT_BITS,
                },
                Value::Bool(b),
            ) => {
                let secret = if *b { F::from(1u64) } else { F::from(0u64) };
                let mut rng = ark_std::test_rng();
                let shares = RobustShare::compute_shares(secret, self.n, self.t, None, &mut rng)
                    .map_err(|e| format!("compute_shares: {:?}", e))?;
                let my = &shares[self.party_id];
                Self::encode_robustshare(my)
            }
            (ShareType::SecretFixedPoint { precision }, Value::Float(fp)) => {
                let f = precision.f();
                let scale = (1u64 << f) as f64;
                let scaled_value = (fp.0 * scale) as i64;
                let secret = if scaled_value >= 0 {
                    F::from(scaled_value as u64)
                } else {
                    -F::from((-scaled_value) as u64)
                };
                let mut rng = ark_std::test_rng();
                let shares = RobustShare::compute_shares(secret, self.n, self.t, None, &mut rng)
                    .map_err(|e| format!("compute_shares: {:?}", e))?;
                let my = &shares[self.party_id];
                Self::encode_robustshare(my)
            }
            _ => Err("Unsupported type for input_share".to_string()),
        }
    }

    fn multiply_share(
        &self,
        _ty: ShareType,
        _left: &[u8],
        _right: &[u8],
    ) -> Result<Vec<u8>, String> {
        Err("AVSS protocol does not support secure multiplication (requires Beaver triples)".into())
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
            ShareType::SecretInt { bit_length } => format!("adkg-int-{bit_length}"),
            ShareType::SecretFixedPoint { precision } => {
                format!("adkg-fixed-{}-{}", precision.k(), precision.f())
            }
        };

        let required = 2 * self.t + 1;
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
                let mut shares: Vec<RobustShare<F>> = Vec::with_capacity(collected.len());
                for bytes in &collected {
                    shares.push(Self::decode_robustshare(bytes)?);
                }

                let (_deg, secret) = RobustShare::recover_secret(&shares, self.n)
                    .map_err(|e| format!("recover_secret: {:?}", e))?;

                let value = match ty {
                    ShareType::SecretInt { .. } if ty.is_boolean() => {
                        use ark_ff::Zero;
                        Value::Bool(!secret.is_zero())
                    }
                    ShareType::SecretInt { .. } => {
                        let bigint = secret.into_bigint();
                        let limbs = bigint.as_ref(); // &[u64] — works for any field size
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
            ShareType::SecretInt { bit_length } => format!("adkg-batch-int-{bit_length}"),
            ShareType::SecretFixedPoint { precision } => {
                format!("adkg-batch-fixed-{}-{}", precision.k(), precision.f())
            }
        };

        let batch_size = shares.len();
        let required = 2 * self.t + 1;
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

                    let mut decoded_shares: Vec<RobustShare<F>> =
                        Vec::with_capacity(collected.len());
                    for bytes in &collected {
                        decoded_shares.push(Self::decode_robustshare(bytes)?);
                    }

                    let (_deg, secret) = RobustShare::recover_secret(&decoded_shares, self.n)
                        .map_err(|e| format!("batch recover_secret pos {}: {:?}", pos, e))?;

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

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
}

// ============================================================================
// Additional Trait Implementations for ADKG-specific Operations
// ============================================================================

/// ADKG-specific operations trait.
///
/// This trait is object-safe and uses `Vec<u8>` for key data so it can be
/// used through `dyn AdkgOperations` without knowing the concrete `(F, G)`.
pub trait AdkgOperations {
    /// Generate a new distributed key (async)
    fn adkg_generate_key_bytes(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(u64, Vec<u8>), String>> + Send + '_>>;

    /// Get commitment at index (synchronous)
    fn adkg_get_commitment(&self, session_id: u64, index: usize) -> Result<Vec<u8>, String>;

    /// Get the public key (commitment[0]) for a session
    fn adkg_get_public_key(&self, session_id: u64) -> Result<Vec<u8>, String>;
}

impl<F, G> AdkgOperations for AdkgMpcEngine<F, G>
where
    F: FftField + PrimeField + Send + Sync + 'static,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    fn adkg_generate_key_bytes(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(u64, Vec<u8>), String>> + Send + '_>>
    {
        Box::pin(async move {
            let key = self.generate_key().await?;
            let bytes = key.to_bytes()?;
            Ok((key.session_id, bytes))
        })
    }

    fn adkg_get_commitment(&self, session_id: u64, index: usize) -> Result<Vec<u8>, String> {
        // Use blocking approach for sync interface
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                #[allow(deprecated)]
                match handle.runtime_flavor() {
                    tokio::runtime::RuntimeFlavor::MultiThread => {
                        tokio::task::block_in_place(|| {
                            handle.block_on(async {
                                let key = self
                                    .get_secret_key(session_id)
                                    .await
                                    .ok_or_else(|| format!("Session {} not found", session_id))?;
                                let commitment = key
                                    .commitment(index)
                                    .ok_or_else(|| {
                                        format!("Commitment index {} out of bounds", index)
                                    })?;
                                Self::encode_group_element(&commitment)
                            })
                        })
                    }
                    _ => Err("Cannot call adkg_get_commitment from single-thread runtime".into()),
                }
            }
            Err(_) => {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("Failed to build runtime: {}", e))?;
                rt.block_on(async {
                    let key = self
                        .get_secret_key(session_id)
                        .await
                        .ok_or_else(|| format!("Session {} not found", session_id))?;
                    let commitment = key
                        .commitment(index)
                        .ok_or_else(|| format!("Commitment index {} out of bounds", index))?;
                    Self::encode_group_element(&commitment)
                })
            }
        }
    }

    fn adkg_get_public_key(&self, session_id: u64) -> Result<Vec<u8>, String> {
        self.adkg_get_commitment(session_id, 0)
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
    }

    #[test]
    fn test_adkg_secret_key_serialization() {
        let mut rng = test_rng();

        // Create a Feldman share manually for testing
        let share_value = Fr::rand(&mut rng);
        let degree = 2;
        let commitments: Vec<G1> = (0..=degree)
            .map(|_| G1::generator() * Fr::rand(&mut rng))
            .collect();

        let feldman_share = FeldmanShamirShare::new(share_value, 1, degree, commitments.clone())
            .expect("Failed to create FeldmanShamirShare");

        let key = Bls12381AdkgSecretKey {
            session_id: 42,
            share: feldman_share,
        };

        // Test serialization
        let bytes = key.to_bytes().expect("Serialization failed");
        assert!(!bytes.is_empty());

        // Test deserialization
        let restored =
            Bls12381AdkgSecretKey::from_bytes(42, &bytes).expect("Deserialization failed");
        assert_eq!(restored.session_id, key.session_id);
        assert_eq!(
            restored.share.commitments.len(),
            key.share.commitments.len()
        );
    }

    #[test]
    fn test_bn254_secret_key_serialization() {
        use ark_bn254::{Fr as BnFr, G1Projective as BnG1};

        let mut rng = test_rng();
        let share_value = BnFr::rand(&mut rng);
        let degree = 2;
        let commitments: Vec<BnG1> = (0..=degree)
            .map(|_| <BnG1 as PrimeGroup>::generator() * BnFr::rand(&mut rng))
            .collect();

        let feldman_share =
            FeldmanShamirShare::new(share_value, 1, degree, commitments.clone())
                .expect("Failed to create FeldmanShamirShare");

        let key = Bn254AdkgSecretKey {
            session_id: 42,
            share: feldman_share,
        };

        let bytes = key.to_bytes().expect("Serialization failed");
        assert!(!bytes.is_empty());

        let restored =
            Bn254AdkgSecretKey::from_bytes(42, &bytes).expect("Deserialization failed");
        assert_eq!(restored.session_id, key.session_id);
        assert_eq!(
            restored.share.commitments.len(),
            key.share.commitments.len()
        );
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

        let feldman_share = FeldmanShamirShare::new(share_value, 1, degree, commitments)
            .expect("Failed to create FeldmanShamirShare");

        let key = Bls12381AdkgSecretKey {
            session_id: 1,
            share: feldman_share,
        };

        // Verify public key extraction
        assert_eq!(key.public_key(), public_key);
        assert_eq!(key.commitment(0), Some(public_key));
    }

    #[test]
    fn test_feldman_verification() {
        let mut rng = test_rng();
        let n = 4;
        let t = 1;
        let secret = Fr::from(12345u64);

        // Generate polynomial
        use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
        let mut poly = DensePolynomial::rand(t, &mut rng);
        poly[0] = secret;

        // Generate commitments
        let commitments: Vec<G1> = poly.coeffs.iter().map(|c| G1::generator() * c).collect();

        // Generate shares and verify
        for i in 1..=n {
            let x = Fr::from(i as u64);
            let y = poly.evaluate(&x);

            let share = FeldmanShamirShare::new(y, i, t, commitments.clone())
                .expect("Failed to create share");

            // Verify the share
            assert!(
                verify_feldman(share.clone()),
                "Feldman verification failed for party {}",
                i
            );
        }

        // Verify that commitment[0] = g^secret
        assert_eq!(commitments[0], G1::generator() * secret);
    }

    #[test]
    fn test_registry_operations() {
        let instance_id = 100;
        let session_id = 1;

        // Store shares
        registry_store_share(instance_id, session_id, 0, vec![1, 2, 3]);
        registry_store_share(instance_id, session_id, 1, vec![4, 5, 6]);
        registry_store_share(instance_id, session_id, 2, vec![7, 8, 9]);

        // Get shares
        let shares = registry_get_shares(instance_id, session_id);
        assert_eq!(shares.len(), 3);

        // Store and get public key
        let pk = vec![10, 11, 12];
        registry_store_public_key(instance_id, session_id, pk.clone());
        assert_eq!(registry_get_public_key(instance_id, session_id), Some(pk));
    }

    #[test]
    fn test_robustshare_serialization_roundtrip() {
        let mut rng = test_rng();
        let n = 4;
        let t = 1;
        let secret = Fr::from(42u64);

        let shares = RobustShare::compute_shares(secret, n, t, None, &mut rng)
            .expect("compute_shares failed");

        for share in &shares {
            let bytes =
                Bls12381AdkgEngine::encode_robustshare(share).expect("encode failed");
            let decoded =
                Bls12381AdkgEngine::decode_robustshare(&bytes).expect("decode failed");
            assert_eq!(share.id, decoded.id);
            assert_eq!(share.degree, decoded.degree);
            assert_eq!(share.share, decoded.share);
        }

        // Verify reconstruction works after round-tripping through bytes
        let required = 2 * t + 1;
        let subset: Vec<_> = shares.iter().take(required).cloned().collect();
        let (_deg, recovered) =
            RobustShare::recover_secret(&subset, n).expect("recover_secret failed");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_bn254_robustshare_roundtrip() {
        use ark_bn254::Fr as BnFr;

        let mut rng = test_rng();
        let n = 4;
        let t = 1;
        let secret = BnFr::from(42u64);

        let shares = RobustShare::compute_shares(secret, n, t, None, &mut rng)
            .expect("compute_shares failed");

        for share in &shares {
            let bytes = Bn254AdkgEngine::encode_robustshare(share).expect("encode failed");
            let decoded =
                Bn254AdkgEngine::decode_robustshare(&bytes).expect("decode failed");
            assert_eq!(share.id, decoded.id);
            assert_eq!(share.degree, decoded.degree);
            assert_eq!(share.share, decoded.share);
        }

        let required = 2 * t + 1;
        let subset: Vec<_> = shares.iter().take(required).cloned().collect();
        let (_deg, recovered) =
            RobustShare::recover_secret(&subset, n).expect("recover_secret failed");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_adkg_input_share_i64() {
        let n = 4;
        let t = 1;
        let party_id = 0;
        let secret = Fr::from(42u64);
        let mut rng = ark_std::test_rng();

        let shares = RobustShare::compute_shares(secret, n, t, None, &mut rng)
            .expect("compute_shares failed");
        let bytes =
            Bls12381AdkgEngine::encode_robustshare(&shares[party_id]).expect("encode failed");
        assert!(!bytes.is_empty());

        let decoded =
            Bls12381AdkgEngine::decode_robustshare(&bytes).expect("decode failed");
        assert_eq!(decoded.id, shares[party_id].id);
        assert_eq!(decoded.share, shares[party_id].share);
    }

    #[test]
    fn test_adkg_input_share_bool() {
        let n = 4;
        let t = 1;
        let party_id = 1;
        let secret = Fr::from(1u64); // true
        let mut rng = ark_std::test_rng();

        let shares = RobustShare::compute_shares(secret, n, t, None, &mut rng)
            .expect("compute_shares failed");
        let bytes =
            Bls12381AdkgEngine::encode_robustshare(&shares[party_id]).expect("encode failed");
        let decoded =
            Bls12381AdkgEngine::decode_robustshare(&bytes).expect("decode failed");
        assert_eq!(decoded.id, shares[party_id].id);
    }

    #[test]
    fn test_adkg_input_share_float() {
        let n = 4;
        let t = 1;
        let party_id = 2;

        let f = 16u32;
        let scale = (1u64 << f) as f64;
        let scaled_value = (3.14 * scale) as i64;
        let secret = Fr::from(scaled_value as u64);
        let mut rng = ark_std::test_rng();

        let shares = RobustShare::compute_shares(secret, n, t, None, &mut rng)
            .expect("compute_shares failed");
        let bytes =
            Bls12381AdkgEngine::encode_robustshare(&shares[party_id]).expect("encode failed");
        let decoded =
            Bls12381AdkgEngine::decode_robustshare(&bytes).expect("decode failed");
        assert_eq!(decoded.id, shares[party_id].id);
    }

    #[test]
    fn test_adkg_input_share_reconstruction() {
        let n = 4;
        let t = 1;
        let secret_val = 12345u64;
        let secret = Fr::from(secret_val);
        let mut rng = ark_std::test_rng();

        let shares = RobustShare::compute_shares(secret, n, t, None, &mut rng)
            .expect("compute_shares failed");

        let mut decoded_shares = Vec::new();
        for share in &shares {
            let bytes =
                Bls12381AdkgEngine::encode_robustshare(share).expect("encode failed");
            let decoded =
                Bls12381AdkgEngine::decode_robustshare(&bytes).expect("decode failed");
            decoded_shares.push(decoded);
        }

        let required = 2 * t + 1;
        let subset: Vec<_> = decoded_shares.iter().take(required).cloned().collect();
        let (_deg, recovered) =
            RobustShare::recover_secret(&subset, n).expect("recover_secret failed");
        assert_eq!(
            recovered, secret,
            "Reconstructed secret should match original"
        );
    }

    #[test]
    fn test_bn254_input_share_reconstruction() {
        use ark_bn254::Fr as BnFr;

        let n = 4;
        let t = 1;
        let secret_val = 12345u64;
        let secret = BnFr::from(secret_val);
        let mut rng = ark_std::test_rng();

        let shares = RobustShare::compute_shares(secret, n, t, None, &mut rng)
            .expect("compute_shares failed");

        let mut decoded_shares = Vec::new();
        for share in &shares {
            let bytes =
                Bn254AdkgEngine::encode_robustshare(share).expect("encode failed");
            let decoded =
                Bn254AdkgEngine::decode_robustshare(&bytes).expect("decode failed");
            decoded_shares.push(decoded);
        }

        let required = 2 * t + 1;
        let subset: Vec<_> = decoded_shares.iter().take(required).cloned().collect();
        let (_deg, recovered) =
            RobustShare::recover_secret(&subset, n).expect("recover_secret failed");
        assert_eq!(
            recovered, secret,
            "Reconstructed secret should match original"
        );
    }
}
