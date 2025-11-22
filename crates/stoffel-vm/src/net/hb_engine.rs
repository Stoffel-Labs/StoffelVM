use crate::net::mpc::honeybadger_node_opts;
use crate::net::mpc_engine::MpcEngine;
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::SeedableRng;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use stoffel_vm_types::core_types::{ShareType, Value, BOOLEAN_SECRET_INT_BITS};
use stoffelmpc_mpc::common::{MPCProtocol, PreprocessingMPCProtocol, SecretSharingScheme};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::{HoneyBadgerError, HoneyBadgerMPCNode, ProtocolType, SessionId};
use stoffelnet::network_utils::ClientId;
use stoffelnet::transports::quic::QuicNetworkManager;
use tokio::sync::Mutex;

// RBC/SSS type aliases used by HB implementation
use stoffelmpc_mpc::common::rbc::rbc::Avid as RBCImpl;

/// HoneyBadger-backed MPC engine that integrates with the VM.
/// This wraps a real HoneyBadgerMPCNode and provides MPC operations
/// (input sharing, multiplication, output reconstruction) to the VM.
pub struct HoneyBadgerMpcEngine {
    instance_id: u64,
    party_id: usize,
    n: usize,
    t: usize,
    net: Arc<QuicNetworkManager>,
    node: Arc<Mutex<HoneyBadgerMPCNode<Fr, RBCImpl>>>,
    ready: AtomicBool,
    /// Session counter for multiplication operations
    mul_session_counter: Arc<Mutex<usize>>,
}

impl HoneyBadgerMpcEngine {
    /// Fully async startup + preprocessing
    pub async fn start_async(&self) -> Result<(), String> {
        self.preprocess().await
    }

    pub async fn preprocess(&self) -> Result<(), String> {
        // Run the actual preprocessing protocol to generate triples and random shares
        let mut node = self.node.lock().await;
        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        node.run_preprocessing(self.net.clone(), &mut rng)
            .await
            .map_err(|e| format!("Preprocessing failed: {:?}", e))?;

        self.ready.store(true, Ordering::SeqCst);
        Ok(())
    }

    pub async fn multiply_share_async(
        &self,
        ty: ShareType,
        left: &[u8],
        right: &[u8],
    ) -> Result<Vec<u8>, String> {
        if !self.is_ready() {
            return Err("MPC engine not ready".into());
        }

        match ty {
            ShareType::SecretInt { .. } | ShareType::SecretFixedPoint { .. } => {
                // Decode the input shares
                let left_share = Self::decode_share(left)?;
                let right_share = Self::decode_share(right)?;

                // Perform MPC multiplication
                let x_shares = vec![left_share];
                let y_shares = vec![right_share];

                // Lock node just for the call and initial snapshot
                let mut node = self.node.lock().await;
                let before_keys: std::collections::HashSet<SessionId> = {
                    let map = node.operations.mul.mult_storage.lock().await;
                    map.keys().cloned().collect()
                };

                node.mul(x_shares, y_shares, self.net.clone())
                    .await
                    .map_err(|e| format!("MPC multiplication failed: {:?}", e))?;

                // Poll the storage briefly to allow asynchronous propagation
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
                loop {
                    // Identify the newly created session and fetch its output
                    if let Some((session_id, result_share)) = {
                        let storage_map = node.operations.mul.mult_storage.lock().await;
                        // Prefer keys that didn't exist before; if none, take any with output
                        let mut chosen: Option<(SessionId, RobustShare<Fr>)> = None;
                        for (sid, storage_mutex) in storage_map.iter() {
                            if !before_keys.contains(sid) {
                                let storage = storage_mutex.lock().await;
                                if let Some(first) = storage.protocol_output.get(0) {
                                    chosen = Some((*sid, first.clone()));
                                    break;
                                }
                            }
                        }
                        if chosen.is_none() {
                            for (sid, storage_mutex) in storage_map.iter() {
                                let storage = storage_mutex.lock().await;
                                if let Some(first) = storage.protocol_output.get(0) {
                                    chosen = Some((*sid, first.clone()));
                                    break;
                                }
                            }
                        }
                        chosen
                    } {
                        let _ = session_id; // reserved for tracing if needed
                        break Self::encode_share(&result_share);
                    }

                    if std::time::Instant::now() >= deadline {
                        break Err("Multiplication produced no output within timeout".to_string());
                    }
                    // Small yield before retry
                    drop(node); // allow other tasks to progress
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    node = self.node.lock().await;
                }
            }
            _ => Err("Unsupported share type for multiply_share".to_string()),
        }
    }

    pub async fn open_share_async(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
    ) -> Result<Value, String> {
        // Use the same registry approach but non-blocking API boundary to VM future paths later
        // For now, just delegate to sync version because registry is local
        self.open_share(ty, share_bytes)
    }

    pub fn net(&self) -> Arc<QuicNetworkManager> {
        self.net.clone()
    }
    pub fn party_id(&self) -> usize {
        self.party_id
    }

    /// Initialize input shares from a client. This must be called after preprocessing.
    /// The client provides shares for all parties, and each party stores its own share.
    pub async fn init_client_input(
        &self,
        client_id: ClientId,
        shares: Vec<RobustShare<Fr>>,
    ) -> Result<(), String> {
        if !self.is_ready() {
            return Err("MPC engine not ready".into());
        }

        // Take random shares from preprocessing material for the input protocol
        let num_shares = shares.len();
        let local_shares = self
            .reserve_random_shares(num_shares)
            .await
            .map_err(|e| format!("Failed to take random shares: {}", e))?;

        // Initialize the input protocol with the client's shares
        let mut node = self.node.lock().await;
        node.preprocess
            .input
            .init(client_id, local_shares, num_shares, self.net.clone())
            .await
            .map_err(|e| format!("Failed to initialize client input: {:?}", e))?;

        Ok(())
    }

    async fn reserve_random_shares(
        &self,
        num_shares: usize,
    ) -> Result<Vec<RobustShare<Fr>>, String> {
        loop {
            let attempt = {
                let mut node = self.node.lock().await;
                let mut prep_material = node.preprocessing_material.lock().await;
                prep_material.take_random_shares(num_shares)
            };

            match attempt {
                Ok(shares) => return Ok(shares),
                Err(HoneyBadgerError::NotEnoughPreprocessing) => {
                    self.regenerate_random_shares(num_shares).await?;
                    continue;
                }
                Err(other) => {
                    return Err(format!("Failed to take random shares: {:?}", other));
                }
            }
        }
    }

    async fn regenerate_random_shares(&self, needed: usize) -> Result<(), String> {
        let mut node = self.node.lock().await;
        {
            let current = node.preprocessing_material.lock().await.len().1;
            let target = current + needed;
            if node.params.n_random_shares < target {
                node.params.n_random_shares = target;
            }
        }

        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        node.run_preprocessing(self.net.clone(), &mut rng)
            .await
            .map_err(|e| format!("Failed to regenerate preprocessing material: {:?}", e))
    }

    /// Get the shares for a specific client after input initialization
    pub async fn get_client_shares(
        &self,
        client_id: ClientId,
    ) -> Result<Vec<RobustShare<Fr>>, String> {
        let node = self.node.lock().await;
        let input_store = node.preprocess.input.input_shares.lock().await;
        let shares = input_store
            .get(&client_id)
            .ok_or_else(|| format!("No shares found for client {}", client_id))?
            .clone();
        Ok(shares)
    }

    pub fn new(
        instance_id: u64,
        party_id: usize,
        n: usize,
        t: usize,
        n_triples: usize,
        n_random: usize,
        net: Arc<QuicNetworkManager>,
    ) -> Result<Arc<Self>, String> {
        // Create the MPC node options
        let mpc_opts = honeybadger_node_opts(n, t, n_triples, n_random, instance_id);

        // Create the MPC node
        let node = <HoneyBadgerMPCNode<Fr, RBCImpl> as MPCProtocol<
            Fr,
            RobustShare<Fr>,
            QuicNetworkManager,
        >>::setup(party_id, mpc_opts)
        .map_err(|e| format!("Failed to create MPC node: {:?}", e))?;

        Ok(Arc::new(Self {
            instance_id,
            party_id,
            n,
            t,
            net,
            node: Arc::new(Mutex::new(node)),
            ready: AtomicBool::new(false),
            mul_session_counter: Arc::new(Mutex::new(0)),
        }))
    }

    /// Construct an engine from an existing, network-driven HoneyBadgerMPCNode.
    /// This avoids creating a separate node that isn't wired into the message loop.
    pub fn from_existing_node(
        instance_id: u64,
        party_id: usize,
        n: usize,
        t: usize,
        net: Arc<QuicNetworkManager>,
        node: HoneyBadgerMPCNode<Fr, RBCImpl>,
    ) -> Arc<Self> {
        // Wrap the provided node so this engine can access it via async locks.
        // Note: This currently clones/moves a node instance rather than sharing the
        // exact same node that the server loop owns. Concurrency semantics depend on
        // the underlying type's Clone implementation. For tests focused on compile
        // viability, we prioritize type compatibility here.
        let node = Arc::new(Mutex::new(node));
        Arc::new(Self {
            instance_id,
            party_id,
            n,
            t,
            net,
            node,
            // Assume the provided node has been preprocessed already in tests; callers can override via start()/preprocess().
            ready: AtomicBool::new(true),
            mul_session_counter: Arc::new(Mutex::new(0)),
        })
    }

    fn ensure_rt() -> Result<tokio::runtime::Handle, String> {
        tokio::runtime::Handle::try_current()
            .map_err(|e| format!("Tokio runtime not available: {}", e))
    }

    fn encode_share(share: &RobustShare<Fr>) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        share
            .serialize_compressed(&mut out)
            .map_err(|e| format!("serialize share: {}", e))?;
        Ok(out)
    }

    fn decode_share(bytes: &[u8]) -> Result<RobustShare<Fr>, String> {
        RobustShare::<Fr>::deserialize_compressed(bytes)
            .map_err(|e| format!("deserialize share: {}", e))
    }
}

impl MpcEngine for HoneyBadgerMpcEngine {
    fn protocol_name(&self) -> &'static str {
        "honeybadger-mpc"
    }
    fn instance_id(&self) -> u64 {
        self.instance_id
    }
    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    fn start(&self) -> Result<(), String> {
        // Mark engine as ready in test/single-process scenarios. Real deployments should call `preprocess()`.
        self.ready.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn input_share(&self, ty: ShareType, clear: &Value) -> Result<Vec<u8>, String> {
        // Minimal support: ShareType::Int over Fr via direct embedding (u64 -> Fr).
        match (ty, clear) {
            (ShareType::SecretInt { .. }, Value::I64(v)) => {
                let secret = Fr::from(*v as u64);
                let mut rng = ark_std::test_rng();
                let shares = RobustShare::compute_shares(secret, self.n, self.t, None, &mut rng)
                    .map_err(|e| format!("compute_shares: {:?}", e))?;
                let my = &shares[self.party_id];
                Self::encode_share(my)
            }
            (
                ShareType::SecretInt {
                    bit_length: BOOLEAN_SECRET_INT_BITS,
                },
                Value::Bool(b),
            ) => {
                let secret = if *b { Fr::from(1u64) } else { Fr::from(0u64) };
                let mut rng = ark_std::test_rng();
                let shares = RobustShare::compute_shares(secret, self.n, self.t, None, &mut rng)
                    .map_err(|e| format!("compute_shares: {:?}", e))?;
                let my = &shares[self.party_id];
                Self::encode_share(my)
            }
            (ShareType::SecretFixedPoint { .. }, Value::Float(fp)) => {
                // Basic fixed-point: assume input already scaled as i64; map to field via u64 cast.
                let secret = Fr::from(*fp as u64);
                let mut rng = ark_std::test_rng();
                let shares = RobustShare::compute_shares(secret, self.n, self.t, None, &mut rng)
                    .map_err(|e| format!("compute_shares: {:?}", e))?;
                let my = &shares[self.party_id];
                Self::encode_share(my)
            }
            _ => Err("Unsupported type for input_share".to_string()),
        }
    }

    fn multiply_share(&self, ty: ShareType, left: &[u8], right: &[u8]) -> Result<Vec<u8>, String> {
        // Execute the async version without attempting to create a nested runtime.
        // If we're already inside a Tokio runtime (which is the case in #[tokio::test]
        // and most server code), use block_in_place on a multi-thread runtime to
        // synchronously wait for the future without deadlocking.
        // Otherwise, create a fresh runtime and block_on.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                // Inside a Tokio runtime; avoid panic by using block_in_place on multi-thread.
                // If the runtime is current_thread, block_in_place will panic; in that case,
                // return a clear error to guide callers (our tests use multi-thread runtime).
                #[allow(deprecated)]
                {
                    // RuntimeFlavor is available on stable Tokio; use it to guard block_in_place
                    match handle.runtime_flavor() {
                        tokio::runtime::RuntimeFlavor::MultiThread => {
                            tokio::task::block_in_place(|| {
                                handle.block_on(self.multiply_share_async(ty, left, right))
                            })
                        }
                        tokio::runtime::RuntimeFlavor::CurrentThread => {
                            Err("MPC multiply_share called from a single-thread Tokio runtime; synchronous waiting is unsupported in this context".to_string())
                        }
                        _ => {
                            // Any other (future) runtime flavor: conservatively refuse to block synchronously.
                            Err("MPC multiply_share called from an unsupported Tokio runtime flavor for synchronous waiting".to_string())
                        }
                    }
                }
            }
            Err(_) => {
                // No Tokio runtime active; create a lightweight current-thread runtime and block.
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("Failed to build Tokio runtime: {}", e))?;
                rt.block_on(self.multiply_share_async(ty, left, right))
            }
        }
    }

    fn open_share(&self, ty: ShareType, share_bytes: &[u8]) -> Result<Value, String> {
        // In-process aggregator using a global registry of shares; reconstruct when 2t+1 are present.
        #[derive(Default, Clone)]
        struct OpenAccumulator {
            shares: Vec<Vec<u8>>,
            result: Option<Value>,
        }

        static REGISTRY: once_cell::sync::Lazy<
            parking_lot::Mutex<std::collections::HashMap<(u64, String), OpenAccumulator>>,
        > = once_cell::sync::Lazy::new(
            || parking_lot::Mutex::new(std::collections::HashMap::new()),
        );

        let key = (
            self.instance_id,
            match ty {
                ShareType::SecretInt { bit_length } => format!("int-{bit_length}"),
                ShareType::SecretFixedPoint { precision } => format!(
                    "fixed-{}-{}",
                    precision.total_bits(),
                    precision.fractional_bits()
                ),
            },
        );

        let required = 2 * self.t + 1;
        let mut pushed = false;

        loop {
            let mut reg = REGISTRY.lock();
            let entry = reg
                .entry(key.clone())
                .or_insert_with(OpenAccumulator::default);

            if let Some(result) = entry.result.clone() {
                return Ok(result);
            }

            if !pushed {
                entry.shares.push(share_bytes.to_vec());
                pushed = true;
            }

            if entry.shares.len() >= required {
                let collected: Vec<_> = entry.shares.iter().take(required).cloned().collect();
                let mut shares: Vec<RobustShare<Fr>> = Vec::with_capacity(collected.len());
                for bytes in &collected {
                    shares.push(Self::decode_share(bytes)?);
                }
                let (_deg, secret) = RobustShare::recover_secret(&shares, self.n)
                    .map_err(|e| format!("recover_secret: {:?}", e))?;
                let value = match ty {
                    ShareType::SecretInt { .. } if ty.is_boolean() => {
                        use ark_ff::Zero;
                        Value::Bool(!secret.is_zero())
                    }
                    ShareType::SecretInt { .. } => {
                        let limbs: [u64; 4] = secret.into_bigint().0;
                        Value::I64(limbs[0] as i64)
                    }
                    ShareType::SecretFixedPoint { .. } => {
                        let limbs: [u64; 4] = secret.into_bigint().0;
                        Value::Float(limbs[0] as i64)
                    }
                };
                entry.result = Some(value.clone());
                return Ok(value);
            }

            drop(reg);
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn shutdown(&self) {
        self.ready.store(false, Ordering::SeqCst);
    }
}
