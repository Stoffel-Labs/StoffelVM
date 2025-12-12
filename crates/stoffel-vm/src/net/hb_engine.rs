use crate::net::client_store::ClientInputStore;
use crate::net::mpc::honeybadger_node_opts;
use crate::net::mpc_engine::{AsyncMpcEngineConsensus, MpcEngine, MpcEngineClientOps, MpcEngineConsensus};
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::SeedableRng;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use stoffel_vm_types::core_types::{BOOLEAN_SECRET_INT_BITS, F64, ShareType, Value};
use stoffelmpc_mpc::common::{MPCProtocol, PreprocessingMPCProtocol, SecretSharingScheme};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::{HoneyBadgerError, HoneyBadgerMPCNode};
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

                // Lock node and perform multiplication
                // node.mul() returns the result directly (via internal wait_for_result)
                let mut node = self.node.lock().await;
                let result_shares = node.mul(x_shares, y_shares, self.net.clone())
                    .await
                    .map_err(|e| format!("MPC multiplication failed: {:?}", e))?;

                // Get the first result share
                let result_share = result_shares.into_iter().next()
                    .ok_or_else(|| "Multiplication returned no shares".to_string())?;

                Self::encode_share(&result_share)
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
    ///
    /// Note: This method waits for all inputs to be received before returning.
    /// The wait timeout is configurable via DEFAULT_INPUT_WAIT_TIMEOUT.
    pub async fn get_client_shares(
        &self,
        client_id: ClientId,
    ) -> Result<Vec<RobustShare<Fr>>, String> {
        let all_inputs = self.wait_for_inputs().await?;
        all_inputs
            .get(&client_id)
            .cloned()
            .ok_or_else(|| format!("No shares found for client {}", client_id))
    }

    /// Get all client IDs that have submitted inputs to this HB node
    ///
    /// Note: This method waits for all inputs to be received before returning.
    pub async fn get_client_ids(&self) -> Vec<ClientId> {
        match self.wait_for_inputs().await {
            Ok(inputs) => inputs.keys().copied().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Get all client inputs from the HB node's input store
    /// Returns a map of client_id -> shares
    ///
    /// Note: This method waits for all inputs to be received before returning.
    pub async fn get_all_client_inputs(
        &self,
    ) -> Result<Vec<(ClientId, Vec<RobustShare<Fr>>)>, String> {
        let all_inputs = self.wait_for_inputs().await?;
        Ok(all_inputs
            .into_iter()
            .map(|(client_id, shares)| (client_id, shares))
            .collect())
    }

    /// Wait for all client inputs to be received
    ///
    /// Uses the InputServer's wait_for_all_inputs method with a default timeout.
    async fn wait_for_inputs(&self) -> Result<std::collections::HashMap<ClientId, Vec<RobustShare<Fr>>>, String> {
        let mut node = self.node.lock().await;
        node.preprocess
            .input
            .wait_for_all_inputs(Duration::from_secs(30))
            .await
            .map_err(|e| format!("Failed to wait for inputs: {:?}", e))
    }

    /// Hydrate a ClientInputStore with all client inputs from the HB node
    ///
    /// This copies all client input shares from the HoneyBadger node's internal
    /// input store to the provided ClientInputStore, making them available
    /// to the VM for execution.
    ///
    /// # Arguments
    /// * `store` - The ClientInputStore to populate with client inputs
    ///
    /// # Returns
    /// The number of clients whose inputs were hydrated
    pub async fn hydrate_client_inputs(&self, store: &ClientInputStore) -> Result<usize, String> {
        let all_inputs = self.get_all_client_inputs().await?;
        let count = all_inputs.len();

        for (client_id, shares) in all_inputs {
            store.store_client_input(client_id, shares);
        }

        Ok(count)
    }

    /// Hydrate a ClientInputStore with inputs from specific clients
    ///
    /// # Arguments
    /// * `store` - The ClientInputStore to populate
    /// * `client_ids` - The client IDs to hydrate inputs for
    ///
    /// # Returns
    /// The number of clients successfully hydrated
    pub async fn hydrate_client_inputs_for(
        &self,
        store: &ClientInputStore,
        client_ids: &[ClientId],
    ) -> Result<usize, String> {
        let mut count = 0;
        for &client_id in client_ids {
            match self.get_client_shares(client_id).await {
                Ok(shares) => {
                    store.store_client_input(client_id, shares);
                    count += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to get shares for client {}: {}",
                        client_id,
                        e
                    );
                }
            }
        }
        Ok(count)
    }

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
        // Create the MPC node options
        let mpc_opts = honeybadger_node_opts(n, t, n_triples, n_random, instance_id);

        // Create the MPC node
        let node = <HoneyBadgerMPCNode<Fr, RBCImpl> as MPCProtocol<
            Fr,
            RobustShare<Fr>,
            QuicNetworkManager,
        >>::setup(party_id, mpc_opts, input_ids)
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

    /// Send output share(s) to a specific client using the OutputServer protocol
    ///
    /// This is used for private output where only the designated client can
    /// reconstruct the result by collecting shares from all parties.
    pub async fn send_output_to_client_async_impl(
        &self,
        client_id: ClientId,
        shares_bytes: &[u8],
        input_len: usize,
    ) -> Result<(), String> {
        // Deserialize shares from bytes
        // If input_len == 1, try to deserialize as a single RobustShare first
        // (Value::Share stores a single share's bytes)
        let shares: Vec<RobustShare<Fr>> = if input_len == 1 {
            // Try to deserialize as a single share
            let single_share: RobustShare<Fr> =
                CanonicalDeserialize::deserialize_compressed(shares_bytes)
                    .map_err(|e| format!("Failed to deserialize single share: {:?}", e))?;
            vec![single_share]
        } else {
            // Multiple shares - deserialize as Vec
            CanonicalDeserialize::deserialize_compressed(shares_bytes)
                .map_err(|e| format!("Failed to deserialize shares: {:?}", e))?
        };

        if shares.len() != input_len {
            return Err(format!(
                "Share count mismatch: got {}, expected {}",
                shares.len(),
                input_len
            ));
        }

        // Use the OutputServer from the node to send shares to the client
        let node = self.node.lock().await;
        node.output
            .init(client_id as usize, shares, input_len, self.net.clone())
            .await
            .map_err(|e| format!("OutputServer.init failed: {:?}", e))
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
            (ShareType::SecretFixedPoint { precision }, Value::Float(fp)) => {
                // Convert f64 to fixed-point scaled integer
                // Scale factor = 2^f (fractional bits)
                let f = precision.f();
                let scale = (1u64 << f) as f64;
                let scaled_value = (fp.0 * scale) as i64;
                // Map to field (handle negative values by wrapping)
                let secret = if scaled_value >= 0 {
                    Fr::from(scaled_value as u64)
                } else {
                    // For negative values, use field modular arithmetic
                    -Fr::from((-scaled_value) as u64)
                };
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
        // Each open operation gets a unique session ID to prevent different values being mixed together.
        //
        // CRITICAL: All parties must agree on which accumulator to use for each open operation.
        // We achieve this by having each party find the first accumulator (by sequence number)
        // that they haven't contributed to yet. Since all parties execute the same bytecode
        // in the same order, they will all converge on the same accumulator for each open.
        #[derive(Default, Clone)]
        struct OpenAccumulator {
            shares: Vec<Vec<u8>>,
            party_ids: Vec<usize>, // Track which parties have contributed
            result: Option<Value>,
        }

        // Registry: maps (instance_id, sequence, type_string) to accumulator
        static REGISTRY: once_cell::sync::Lazy<
            parking_lot::Mutex<std::collections::HashMap<(u64, usize, String), OpenAccumulator>>,
        > = once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(std::collections::HashMap::new()));

        let type_key = match ty {
            ShareType::SecretInt { bit_length } => format!("int-{bit_length}"),
            ShareType::SecretFixedPoint { precision } => {
                format!("fixed-{}-{}", precision.k(), precision.f())
            }
        };

        let required = 2 * self.t + 1;
        let mut my_sequence: Option<usize> = None;

        loop {
            let mut reg = REGISTRY.lock();

            // If we haven't contributed yet, find the right accumulator
            if my_sequence.is_none() {
                // Find the first sequence number where this party hasn't contributed
                let mut seq = 0;
                loop {
                    let key = (self.instance_id, seq, type_key.clone());
                    let entry = reg.entry(key).or_insert_with(OpenAccumulator::default);

                    if !entry.party_ids.contains(&self.party_id) {
                        // This party hasn't contributed here yet - use this accumulator
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

            // Check if result is ready
            if let Some(result) = entry.result.clone() {
                return Ok(result);
            }

            // Check if we have enough shares to reconstruct
            if entry.shares.len() >= required {
                let collected: Vec<_> = entry.shares.iter().take(required).cloned().collect();
                let mut shares: Vec<RobustShare<Fr>> = Vec::with_capacity(collected.len());
                for bytes in &collected {
                    shares.push(Self::decode_share(bytes)?);
                }

                // Debug: log share IDs, degrees, and values being used for reconstruction
                tracing::info!(
                    "open_share reconstruction: n={}, t={}, required={}, shares.len()={}",
                    self.n, self.t, required, shares.len()
                );

                // Sort shares by ID for interpolation debugging
                let mut sorted_shares = shares.clone();
                sorted_shares.sort_by_key(|s| s.id);

                for (i, share) in sorted_shares.iter().enumerate() {
                    tracing::info!(
                        "  sorted_share[{}]: id={}, degree={}, value={:?}",
                        i, share.id, share.degree,
                        share.share[0].into_bigint().0 // All limbs of the share value
                    );
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
                    ShareType::SecretFixedPoint { precision } => {
                        let limbs: [u64; 4] = secret.into_bigint().0;
                        let scaled_value = limbs[0] as i64;
                        // Convert from fixed-point scaled integer back to f64
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

    fn send_output_to_client(
        &self,
        client_id: ClientId,
        shares: &[u8],
        input_len: usize,
    ) -> Result<(), String> {
        // Execute the async version, handling runtime context appropriately
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                #[allow(deprecated)]
                match handle.runtime_flavor() {
                    tokio::runtime::RuntimeFlavor::MultiThread => {
                        tokio::task::block_in_place(|| {
                            handle.block_on(self.send_output_to_client_async_impl(
                                client_id, shares, input_len,
                            ))
                        })
                    }
                    tokio::runtime::RuntimeFlavor::CurrentThread => {
                        Err("send_output_to_client called from a single-thread Tokio runtime; synchronous waiting is unsupported".to_string())
                    }
                    _ => {
                        Err("send_output_to_client called from an unsupported Tokio runtime flavor".to_string())
                    }
                }
            }
            Err(_) => {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("Failed to build Tokio runtime: {}", e))?;
                rt.block_on(self.send_output_to_client_async_impl(client_id, shares, input_len))
            }
        }
    }
}

use crate::net::mpc_engine::AsyncMpcEngine;

#[async_trait::async_trait]
impl AsyncMpcEngine for HoneyBadgerMpcEngine {
    async fn multiply_share_async(
        &self,
        ty: ShareType,
        left: &[u8],
        right: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.multiply_share_async(ty, left, right).await
    }

    async fn open_share_async(&self, ty: ShareType, share_bytes: &[u8]) -> Result<Value, String> {
        self.open_share_async(ty, share_bytes).await
    }

    async fn send_output_to_client_async(
        &self,
        client_id: ClientId,
        shares: &[u8],
        input_len: usize,
    ) -> Result<(), String> {
        self.send_output_to_client_async_impl(client_id, shares, input_len)
            .await
    }
}

impl MpcEngineClientOps for HoneyBadgerMpcEngine {
    fn get_client_ids_sync(&self) -> Vec<ClientId> {
        // Use the async/sync bridging pattern
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                #[allow(deprecated)]
                match handle.runtime_flavor() {
                    tokio::runtime::RuntimeFlavor::MultiThread => {
                        tokio::task::block_in_place(|| handle.block_on(self.get_client_ids()))
                    }
                    _ => Vec::new(), // Cannot block on single-thread runtime
                }
            }
            Err(_) => {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .ok();
                rt.map(|rt| rt.block_on(self.get_client_ids()))
                    .unwrap_or_default()
            }
        }
    }

    fn hydrate_client_inputs_sync(&self, store: &ClientInputStore) -> Result<usize, String> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                #[allow(deprecated)]
                match handle.runtime_flavor() {
                    tokio::runtime::RuntimeFlavor::MultiThread => {
                        tokio::task::block_in_place(|| {
                            handle.block_on(self.hydrate_client_inputs(store))
                        })
                    }
                    tokio::runtime::RuntimeFlavor::CurrentThread => {
                        Err("Cannot hydrate client inputs from single-thread Tokio runtime".to_string())
                    }
                    _ => Err("Unsupported Tokio runtime flavor".to_string()),
                }
            }
            Err(_) => {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("Failed to build Tokio runtime: {}", e))?;
                rt.block_on(self.hydrate_client_inputs(store))
            }
        }
    }

    fn hydrate_client_inputs_for_sync(
        &self,
        store: &ClientInputStore,
        client_ids: &[ClientId],
    ) -> Result<usize, String> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                #[allow(deprecated)]
                match handle.runtime_flavor() {
                    tokio::runtime::RuntimeFlavor::MultiThread => {
                        tokio::task::block_in_place(|| {
                            handle.block_on(self.hydrate_client_inputs_for(store, client_ids))
                        })
                    }
                    tokio::runtime::RuntimeFlavor::CurrentThread => {
                        Err("Cannot hydrate client inputs from single-thread Tokio runtime".to_string())
                    }
                    _ => Err("Unsupported Tokio runtime flavor".to_string()),
                }
            }
            Err(_) => {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("Failed to build Tokio runtime: {}", e))?;
                rt.block_on(self.hydrate_client_inputs_for(store, client_ids))
            }
        }
    }
}

// ============================================================================
// MpcEngineConsensus Implementation (RBC and ABA)
// ============================================================================
//
// RBC and ABA use in-process registries for coordination between parties.
// This mirrors the open_share approach where all parties in the same process
// coordinate through shared state.
//
// For multi-process deployments, these protocols would need to use the
// actual network-based Avid/ABA implementations from mpc-protocols.

/// Registry for RBC broadcasts - maps (instance_id, session_id) to broadcast data
#[derive(Default)]
struct RbcRegistry {
    /// Maps (instance_id, session_id, from_party) to message bytes
    messages: std::collections::HashMap<(u64, u64, usize), Vec<u8>>,
    /// Session counter for generating unique session IDs
    session_counter: u64,
}

/// Registry for ABA sessions - maps (instance_id, session_id) to agreement state
#[derive(Default)]
struct AbaRegistry {
    /// Maps (instance_id, session_id, party_id) to proposed value
    proposals: std::collections::HashMap<(u64, u64, usize), bool>,
    /// Maps (instance_id, session_id) to agreed result once consensus is reached
    results: std::collections::HashMap<(u64, u64), bool>,
    /// Session counter for generating unique session IDs
    session_counter: u64,
}

static RBC_REGISTRY: once_cell::sync::Lazy<parking_lot::Mutex<RbcRegistry>> =
    once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(RbcRegistry::default()));

static ABA_REGISTRY: once_cell::sync::Lazy<parking_lot::Mutex<AbaRegistry>> =
    once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(AbaRegistry::default()));

impl MpcEngineConsensus for HoneyBadgerMpcEngine {
    fn rbc_broadcast(&self, message: &[u8]) -> Result<u64, String> {
        let mut registry = RBC_REGISTRY.lock();

        // Generate a unique session ID
        let session_id = registry.session_counter;
        registry.session_counter += 1;

        // Store the message for this party's broadcast
        let key = (self.instance_id, session_id, self.party_id);
        registry.messages.insert(key, message.to_vec());

        tracing::info!(
            instance_id = self.instance_id,
            session_id = session_id,
            party_id = self.party_id,
            message_len = message.len(),
            "RBC broadcast initiated"
        );

        Ok(session_id)
    }

    fn rbc_receive(&self, from_party: usize, timeout_ms: u64) -> Result<Vec<u8>, String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);

        loop {
            {
                let registry = RBC_REGISTRY.lock();

                // Look for a message from the specified party
                // We need to find the session where from_party broadcast
                for ((inst_id, _session_id, party), message) in registry.messages.iter() {
                    if *inst_id == self.instance_id && *party == from_party {
                        tracing::info!(
                            instance_id = self.instance_id,
                            from_party = from_party,
                            message_len = message.len(),
                            "RBC receive found message"
                        );
                        return Ok(message.clone());
                    }
                }
            }

            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "RBC receive timeout waiting for message from party {}",
                    from_party
                ));
            }

            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    fn rbc_receive_any(&self, timeout_ms: u64) -> Result<(usize, Vec<u8>), String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);

        // Track which parties we've already received from
        let mut received_from = std::collections::HashSet::new();

        loop {
            {
                let registry = RBC_REGISTRY.lock();

                // Look for any message we haven't received yet
                for ((inst_id, _session_id, party), message) in registry.messages.iter() {
                    if *inst_id == self.instance_id
                        && *party != self.party_id
                        && !received_from.contains(party)
                    {
                        received_from.insert(*party);
                        tracing::info!(
                            instance_id = self.instance_id,
                            from_party = *party,
                            message_len = message.len(),
                            "RBC receive_any found message"
                        );
                        return Ok((*party, message.clone()));
                    }
                }
            }

            if std::time::Instant::now() >= deadline {
                return Err("RBC receive_any timeout waiting for message from any party".to_string());
            }

            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    fn aba_propose(&self, value: bool) -> Result<u64, String> {
        let mut registry = ABA_REGISTRY.lock();

        // Generate a unique session ID
        let session_id = registry.session_counter;
        registry.session_counter += 1;

        // Store this party's proposal
        let key = (self.instance_id, session_id, self.party_id);
        registry.proposals.insert(key, value);

        tracing::info!(
            instance_id = self.instance_id,
            session_id = session_id,
            party_id = self.party_id,
            value = value,
            "ABA propose initiated"
        );

        Ok(session_id)
    }

    fn aba_result(&self, session_id: u64, timeout_ms: u64) -> Result<bool, String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        let required = 2 * self.t + 1; // Need 2t+1 proposals for agreement

        loop {
            {
                let mut registry = ABA_REGISTRY.lock();

                // Check if result is already computed
                if let Some(&result) = registry.results.get(&(self.instance_id, session_id)) {
                    return Ok(result);
                }

                // Count proposals for this session
                let mut true_count = 0usize;
                let mut false_count = 0usize;

                for ((inst_id, sess_id, _party), &proposal) in registry.proposals.iter() {
                    if *inst_id == self.instance_id && *sess_id == session_id {
                        if proposal {
                            true_count += 1;
                        } else {
                            false_count += 1;
                        }
                    }
                }

                // ABA agreement rule: if 2t+1 parties agree on a value, that's the result
                if true_count >= required {
                    registry.results.insert((self.instance_id, session_id), true);
                    tracing::info!(
                        instance_id = self.instance_id,
                        session_id = session_id,
                        result = true,
                        true_count = true_count,
                        "ABA agreement reached"
                    );
                    return Ok(true);
                }

                if false_count >= required {
                    registry.results.insert((self.instance_id, session_id), false);
                    tracing::info!(
                        instance_id = self.instance_id,
                        session_id = session_id,
                        result = false,
                        false_count = false_count,
                        "ABA agreement reached"
                    );
                    return Ok(false);
                }
            }

            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "ABA result timeout waiting for agreement on session {}",
                    session_id
                ));
            }

            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
}

#[async_trait::async_trait]
impl AsyncMpcEngineConsensus for HoneyBadgerMpcEngine {
    async fn rbc_broadcast_async(&self, message: &[u8]) -> Result<u64, String> {
        // Use sync version since registry operations are quick
        self.rbc_broadcast(message)
    }

    async fn rbc_receive_async(
        &self,
        from_party: usize,
        timeout_ms: u64,
    ) -> Result<Vec<u8>, String> {
        // For async, we could use tokio::time::sleep but for now delegate to sync
        self.rbc_receive(from_party, timeout_ms)
    }

    async fn rbc_receive_any_async(&self, timeout_ms: u64) -> Result<(usize, Vec<u8>), String> {
        self.rbc_receive_any(timeout_ms)
    }

    async fn aba_propose_async(&self, value: bool) -> Result<u64, String> {
        self.aba_propose(value)
    }

    async fn aba_result_async(&self, session_id: u64, timeout_ms: u64) -> Result<bool, String> {
        self.aba_result(session_id, timeout_ms)
    }
}
