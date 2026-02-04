// ADKG MPC Engine - Asynchronous Distributed Key Generation
//
// This engine provides ADKG functionality using the AVSS (Asynchronously Verifiable Secret Sharing)
// protocol from mpc-protocols. Each party gets a Feldman-verifiable share where:
// - The share itself is a Shamir share of the secret key
// - commitment[0] = g^secret = the public key
//
// The ADKG protocol produces secret keys for threshold cryptography where no single party
// knows the full secret, but any t+1 parties can collaborate to use it.

use crate::net::mpc_engine::MpcEngine;
use ark_bls12_381::{Fr, G1Projective as G1};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::SeedableRng;
use ark_std::UniformRand;
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use stoffel_vm_types::core_types::{ShareType, Value};
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::share::avss::{AvssNode, FeldmanShamirShare};
use stoffelmpc_mpc::honeybadger::{ProtocolType, SessionId};
use stoffelnet::transports::quic::QuicNetworkManager;
use tokio::sync::mpsc::{self, Receiver};
use tokio::sync::Mutex;
use tracing::info;

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

/// Configuration options for ADKG engine
#[derive(Clone, Debug)]
pub struct AdkgEngineOpts {
    /// Number of parties in the system
    pub n_parties: usize,
    /// Threshold - protocol tolerates up to t malicious parties
    pub threshold: usize,
    /// Instance ID for this ADKG session
    pub instance_id: u64,
}

impl AdkgEngineOpts {
    pub fn new(n_parties: usize, threshold: usize, instance_id: u64) -> Self {
        Self {
            n_parties,
            threshold,
            instance_id,
        }
    }
}

/// Stored ADKG secret key with its Feldman commitments
#[derive(Clone, Debug)]
pub struct AdkgSecretKey {
    /// The session ID this key belongs to
    pub session_id: u64,
    /// The Feldman-verifiable share
    pub share: FeldmanShamirShare<Fr, G1>,
}

impl AdkgSecretKey {
    /// Get the public key (commitment[0] = g^secret)
    pub fn public_key(&self) -> G1 {
        self.share.commitments[0]
    }

    /// Get commitment at a specific index
    pub fn commitment(&self, index: usize) -> Option<G1> {
        self.share.commitments.get(index).cloned()
    }

    /// Get all commitments
    pub fn commitments(&self) -> &[G1] {
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
        let share = FeldmanShamirShare::<Fr, G1>::deserialize_compressed(bytes)
            .map_err(|e| format!("Failed to deserialize secret key: {:?}", e))?;
        Ok(Self { session_id, share })
    }
}

/// ADKG MPC Engine that uses AVSS for distributed key generation
///
/// This engine provides:
/// 1. Key generation - run ADKG protocol to produce threshold-shared keys
/// 2. Public key extraction - get commitment[0] as the distributed public key
/// 3. Integration with VM - implement MpcEngine trait for VM compatibility
pub struct AdkgMpcEngine {
    instance_id: u64,
    party_id: usize,
    n: usize,
    t: usize,
    net: Arc<QuicNetworkManager>,
    /// AVSS node for the protocol
    avss_node: Arc<Mutex<AvssNode<Fr, Avid, G1>>>,
    /// Channel to receive AVSS completion notifications
    output_receiver: Arc<Mutex<Receiver<SessionId>>>,
    /// Generated secret keys indexed by session ID
    secret_keys: Arc<Mutex<BTreeMap<u64, AdkgSecretKey>>>,
    /// Session counter for generating unique session IDs
    session_counter: Arc<Mutex<u64>>,
    ready: AtomicBool,
    /// This party's secret key for ECDH in AVSS
    sk_i: Fr,
}

impl AdkgMpcEngine {
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
        sk_i: Fr,
        pk_map: Arc<Vec<G1>>,
    ) -> Result<Arc<Self>, String> {
        // Create channel for AVSS output notifications
        let (output_sender, output_receiver) = mpsc::channel(128);

        // Create the AVSS node
        let avss_node = AvssNode::new(party_id, n, t, sk_i, pk_map, output_sender)
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
    pub async fn generate_key(&self) -> Result<AdkgSecretKey, String> {
        if !self.is_ready() {
            return Err("ADKG engine not ready".into());
        }

        // Generate a random secret
        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        let secret = Fr::rand(&mut rng);

        self.generate_key_with_secret(secret).await
    }

    /// Run ADKG as the dealer with a specific secret
    ///
    /// This allows testing with known secrets.
    pub async fn generate_key_with_secret(&self, secret: Fr) -> Result<AdkgSecretKey, String> {
        if !self.is_ready() {
            return Err("ADKG engine not ready".into());
        }

        // Generate session ID
        let session_id = {
            let mut counter = self.session_counter.lock().await;
            let id = *counter;
            *counter += 1;
            SessionId::new(ProtocolType::Avss, self.instance_id as u8, self.party_id as u8, 0, id as u32)
        };

        // Run AVSS init
        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        {
            let mut node = self.avss_node.lock().await;
            node.init(secret, session_id, &mut rng, self.net.clone())
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
        session_id: SessionId,
    ) -> Result<FeldmanShamirShare<Fr, G1>, String> {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);

        loop {
            // Check if share is ready
            {
                let node = self.avss_node.lock().await;
                let shares = node.shares.lock().await;
                if let Some(Some(share)) = shares.get(&session_id) {
                    return Ok(share.clone());
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
    pub async fn get_secret_key(&self, session_id: u64) -> Option<AdkgSecretKey> {
        let keys = self.secret_keys.lock().await;
        keys.get(&session_id).cloned()
    }

    /// Get the public key for a session
    pub async fn get_public_key(&self, session_id: u64) -> Option<G1> {
        self.get_secret_key(session_id).await.map(|k| k.public_key())
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
    pub async fn process_message(&self, msg: stoffelmpc_mpc::common::share::avss::AvssMessage) -> Result<(), String> {
        let mut node = self.avss_node.lock().await;
        node.process(msg)
            .await
            .map_err(|e| format!("AVSS process failed: {:?}", e))
    }

    /// Helper: encode a group element to bytes
    pub fn encode_group_element(g: &G1) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        g.serialize_compressed(&mut bytes)
            .map_err(|e| format!("Serialization failed: {:?}", e))?;
        Ok(bytes)
    }

    /// Helper: decode a group element from bytes
    pub fn decode_group_element(bytes: &[u8]) -> Result<G1, String> {
        G1::deserialize_compressed(bytes).map_err(|e| format!("Deserialization failed: {:?}", e))
    }

    /// Get party ID
    pub fn party_id(&self) -> usize {
        self.party_id
    }

    /// Get network manager
    pub fn net(&self) -> Arc<QuicNetworkManager> {
        self.net.clone()
    }
}

// ============================================================================
// MpcEngine Implementation
// ============================================================================
//
// The ADKG engine implements MpcEngine primarily for compatibility with the VM,
// but its main purpose is key generation rather than general MPC computation.
// The standard MPC operations (multiply, open) are implemented minimally.

impl MpcEngine for AdkgMpcEngine {
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

    fn input_share(&self, _ty: ShareType, _clear: &Value) -> Result<Vec<u8>, String> {
        // ADKG doesn't support standard input sharing - use generate_key instead
        Err("ADKG engine doesn't support input_share - use generate_key for key generation".into())
    }

    fn multiply_share(
        &self,
        _ty: ShareType,
        _left: &[u8],
        _right: &[u8],
    ) -> Result<Vec<u8>, String> {
        // ADKG is for key generation, not general MPC multiplication
        Err("ADKG engine doesn't support multiply_share - use HoneyBadger engine for MPC".into())
    }

    fn open_share(&self, _ty: ShareType, _share_bytes: &[u8]) -> Result<Value, String> {
        // ADKG is for key generation, not secret reconstruction
        Err("ADKG engine doesn't support open_share - use get_public_key for public key access".into())
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

/// ADKG-specific operations trait
pub trait AdkgOperations {
    /// Generate a new distributed key (async)
    fn adkg_generate_key(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<AdkgSecretKey, String>> + Send + '_>>;

    /// Get commitment at index (synchronous)
    fn adkg_get_commitment(&self, session_id: u64, index: usize) -> Result<Vec<u8>, String>;

    /// Get the public key (commitment[0]) for a session
    fn adkg_get_public_key(&self, session_id: u64) -> Result<Vec<u8>, String>;
}

impl AdkgOperations for AdkgMpcEngine {
    fn adkg_generate_key(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<AdkgSecretKey, String>> + Send + '_>>
    {
        Box::pin(self.generate_key())
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
                                    .ok_or_else(|| format!("Commitment index {} out of bounds", index))?;
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
pub fn registry_store_share(instance_id: u64, session_id: u64, party_id: usize, share_bytes: Vec<u8>) {
    let mut registry = ADKG_REGISTRY.lock();
    registry.shares.insert((instance_id, session_id, party_id), share_bytes);
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
    registry.public_keys.insert((instance_id, session_id), pk_bytes);
}

/// Get public key from registry
pub fn registry_get_public_key(instance_id: u64, session_id: u64) -> Option<Vec<u8>> {
    let registry = ADKG_REGISTRY.lock();
    registry.public_keys.get(&(instance_id, session_id)).cloned()
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::PrimeGroup;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    use stoffelmpc_mpc::common::share::avss::verify_feldman;

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

        let key = AdkgSecretKey {
            session_id: 42,
            share: feldman_share,
        };

        // Test serialization
        let bytes = key.to_bytes().expect("Serialization failed");
        assert!(!bytes.is_empty());

        // Test deserialization
        let restored = AdkgSecretKey::from_bytes(42, &bytes).expect("Deserialization failed");
        assert_eq!(restored.session_id, key.session_id);
        assert_eq!(restored.share.commitments.len(), key.share.commitments.len());
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

        let key = AdkgSecretKey {
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
            assert!(verify_feldman(share.clone()), "Feldman verification failed for party {}", i);
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
}
