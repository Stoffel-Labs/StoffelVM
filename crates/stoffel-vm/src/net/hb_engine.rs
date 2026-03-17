use crate::net::client_store::ClientInputStore;
use crate::net::curve::{MpcCurveConfig, SupportedMpcField};
use crate::net::mpc::honeybadger_node_opts;
use crate::net::mpc_engine::{
    AsyncMpcEngineConsensus, MpcEngine, MpcEngineClientOps, MpcEngineConsensus,
};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::any::TypeId;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use stoffel_vm_types::core_types::{ShareType, Value, BOOLEAN_SECRET_INT_BITS, F64};
use stoffelmpc_mpc::common::{MPCProtocol, PreprocessingMPCProtocol, SecretSharingScheme};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::{HoneyBadgerError, HoneyBadgerMPCNode};
use stoffelnet::network_utils::{ClientId, Network};
use stoffelnet::transports::quic::QuicNetworkManager;
use tokio::sync::Mutex;

// RBC/SSS type aliases used by HB implementation
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::honeybadger::SessionId as HbSessionId;
type RBCImpl = Avid<HbSessionId>;

const EXP_OPEN_WIRE_PREFIX: &[u8; 4] = b"XOP1";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExpOpenWireMessage {
    instance_id: u64,
    sender_party_id: usize,
    share_id: usize,
    partial_point: Vec<u8>,
}

#[derive(Default, Clone)]
struct ExpOpenAccumulator {
    partial_points: Vec<(usize, Vec<u8>)>, // (share_id, serialized affine point)
    party_ids: Vec<usize>,
    result: Option<Vec<u8>>,
    /// Set when `result` is first cached; used for eviction.
    result_cached_at: Option<std::time::Instant>,
}

/// Completed entries older than this are evicted on the next insertion.
const EXP_EVICTION_AGE: Duration = Duration::from_secs(60);

static EXP_REGISTRY: once_cell::sync::Lazy<
    parking_lot::Mutex<HashMap<(u64, usize), ExpOpenAccumulator>>,
> = once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(HashMap::new()));

/// Notified after every insertion into [`EXP_REGISTRY`].
static EXP_NOTIFY: once_cell::sync::Lazy<tokio::sync::Notify> =
    once_cell::sync::Lazy::new(tokio::sync::Notify::new);

/// Clear the exponentiation-domain open registry. Useful between test cases.
pub(crate) fn clear_exp_registry() {
    EXP_REGISTRY.lock().clear();
}

fn insert_remote_exp_partial(
    instance_id: u64,
    sender_party_id: usize,
    share_id: usize,
    partial_point: Vec<u8>,
) {
    let mut reg = EXP_REGISTRY.lock();
    // Evict completed entries older than EXP_EVICTION_AGE.
    let now = std::time::Instant::now();
    reg.retain(|_, acc| {
        acc.result_cached_at
            .is_none_or(|t| now.duration_since(t) < EXP_EVICTION_AGE)
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
    EXP_NOTIFY.notify_waiters();
}

pub(crate) fn try_handle_open_exp_wire_message(
    authenticated_sender_id: usize,
    payload: &[u8],
) -> Result<bool, String> {
    if payload.len() < EXP_OPEN_WIRE_PREFIX.len()
        || &payload[..EXP_OPEN_WIRE_PREFIX.len()] != EXP_OPEN_WIRE_PREFIX
    {
        return Ok(false);
    }

    let message: ExpOpenWireMessage = bincode::deserialize(&payload[EXP_OPEN_WIRE_PREFIX.len()..])
        .map_err(|e| format!("deserialize open-exp payload: {}", e))?;

    if authenticated_sender_id == crate::net::open_registry::UNKNOWN_SENDER_ID {
        tracing::warn!(
            sender_party_id = message.sender_party_id,
            "Rejecting open-exp wire message from unauthenticated connection"
        );
        return Err("open-exp wire rejected: sender identity not authenticated".to_string());
    }
    if message.sender_party_id != authenticated_sender_id {
        return Err(format!(
            "open-exp sender mismatch: transport={} payload={}",
            authenticated_sender_id, message.sender_party_id
        ));
    }

    if message.share_id != message.sender_party_id {
        return Err(format!(
            "open-exp share_id mismatch: sender_party_id={} share_id={}",
            message.sender_party_id, message.share_id
        ));
    }

    insert_remote_exp_partial(
        message.instance_id,
        message.sender_party_id,
        message.share_id,
        message.partial_point,
    );
    Ok(true)
}

/// HoneyBadger-backed MPC engine that integrates with the VM.
/// This wraps a real HoneyBadgerMPCNode and provides MPC operations
/// (input sharing, multiplication, output reconstruction) to the VM.
pub struct HoneyBadgerMpcEngine<F = ark_bls12_381::Fr, G = ark_bls12_381::G1Projective>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    instance_id: u64,
    party_id: usize,
    n: usize,
    t: usize,
    net: Arc<QuicNetworkManager>,
    node: Arc<Mutex<HoneyBadgerMPCNode<F, RBCImpl>>>,
    ready: AtomicBool,
    /// Session counter for multiplication operations
    mul_session_counter: Arc<Mutex<usize>>,
    group_marker: PhantomData<G>,
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
                let result_shares = node
                    .mul(x_shares, y_shares, self.net.clone())
                    .await
                    .map_err(|e| format!("MPC multiplication failed: {:?}", e))?;

                // Get the first result share
                let result_share = result_shares
                    .into_iter()
                    .next()
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
        shares: Vec<RobustShare<F>>,
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
    ) -> Result<Vec<RobustShare<F>>, String> {
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
    ) -> Result<Vec<RobustShare<F>>, String> {
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
    ) -> Result<Vec<(ClientId, Vec<RobustShare<F>>)>, String> {
        let all_inputs = self.wait_for_inputs().await?;
        Ok(all_inputs
            .into_iter()
            .map(|(client_id, shares)| (client_id, shares))
            .collect())
    }

    /// Wait for all client inputs to be received
    ///
    /// Uses the InputServer's wait_for_all_inputs method with a default timeout.
    async fn wait_for_inputs(
        &self,
    ) -> Result<std::collections::HashMap<ClientId, Vec<RobustShare<F>>>, String> {
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
                    tracing::warn!("Failed to get shares for client {}: {}", client_id, e);
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
        let node = <HoneyBadgerMPCNode<F, RBCImpl> as MPCProtocol<
            F,
            RobustShare<F>,
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
            group_marker: PhantomData,
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
        node: HoneyBadgerMPCNode<F, RBCImpl>,
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
            group_marker: PhantomData,
        })
    }

    /// Pull one pre-generated random share from the preprocessing pool.
    /// If the pool is empty, `reserve_random_shares` auto-regenerates via
    /// the RanSha protocol over the network.
    pub async fn random_share_async_impl(&self, _ty: ShareType) -> Result<Vec<u8>, String> {
        let shares = self.reserve_random_shares(1).await?;
        Self::encode_share(&shares[0])
    }

    fn encode_open_exp_wire_message(
        instance_id: u64,
        sender_party_id: usize,
        share_id: usize,
        partial_point: &[u8],
    ) -> Result<Vec<u8>, String> {
        let payload = ExpOpenWireMessage {
            instance_id,
            sender_party_id,
            share_id,
            partial_point: partial_point.to_vec(),
        };
        let encoded = bincode::serialize(&payload)
            .map_err(|e| format!("serialize open-exp payload: {}", e))?;
        let mut out = Vec::with_capacity(EXP_OPEN_WIRE_PREFIX.len() + encoded.len());
        out.extend_from_slice(EXP_OPEN_WIRE_PREFIX);
        out.extend_from_slice(&encoded);
        Ok(out)
    }

    async fn broadcast_open_exp_payload(&self, payload: Vec<u8>) -> Result<(), String> {
        for peer_id in 0..self.n {
            if peer_id == self.party_id {
                continue;
            }
            self.net.send(peer_id, &payload).await.map_err(|e| {
                format!(
                    "Failed to send open-exp payload to party {}: {}",
                    peer_id, e
                )
            })?;
        }
        Ok(())
    }

    fn broadcast_open_exp_payload_sync(&self, payload: Vec<u8>) -> Result<(), String> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                #[allow(deprecated)]
                {
                    match handle.runtime_flavor() {
                        tokio::runtime::RuntimeFlavor::MultiThread => tokio::task::block_in_place(
                            || handle.block_on(self.broadcast_open_exp_payload(payload)),
                        ),
                        tokio::runtime::RuntimeFlavor::CurrentThread => Err(
                            "open_share_in_exp called from a single-thread Tokio runtime; synchronous waiting is unsupported in this context".to_string(),
                        ),
                        _ => Err(
                            "open_share_in_exp called from an unsupported Tokio runtime flavor"
                                .to_string(),
                        ),
                    }
                }
            }
            Err(_) => {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("Failed to build Tokio runtime: {}", e))?;
                rt.block_on(self.broadcast_open_exp_payload(payload))
            }
        }
    }

    /// Reveal a share in the exponent using transport-backed contribution exchange.
    ///
    /// Each party computes `share_value * generator`, broadcasts its partial point,
    /// and reconstructs `[secret] * generator` once `2t+1` contributions are available.
    pub fn open_share_in_exp_impl(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
        generator_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        // Decode the share
        let share = Self::decode_share(share_bytes)?;

        // Decode the generator point
        let generator = G::deserialize_compressed(&generator_bytes[..])
            .map_err(|e| format!("deserialize generator: {}", e))?;

        // Compute partial point: share_value * generator
        let partial_point = generator * share.share[0];

        // Serialize the partial point
        let mut partial_bytes = Vec::new();
        partial_point
            .into_affine()
            .serialize_compressed(&mut partial_bytes)
            .map_err(|e| format!("serialize partial point: {}", e))?;

        let wire_message = Self::encode_open_exp_wire_message(
            self.instance_id,
            self.party_id,
            share.id,
            &partial_bytes,
        )?;
        self.broadcast_open_exp_payload_sync(wire_message)?;

        let required = 2 * self.t + 1;
        let instance_id = self.instance_id;
        let party_id = self.party_id;
        let n = self.n;

        // Closure that checks the registry and returns the result or reconstructs.
        // Returns Ok(Some(bytes)) when done, Ok(None) when more contributions needed.
        let try_check = |my_sequence: &mut Option<usize>,
                         partial_bytes: &[u8],
                         share_id: usize|
         -> Result<Option<Vec<u8>>, String> {
            let mut reg = EXP_REGISTRY.lock();

            if my_sequence.is_none() {
                let mut seq = 0;
                loop {
                    let key = (instance_id, seq);
                    let entry = reg.entry(key).or_insert_with(ExpOpenAccumulator::default);

                    if !entry.party_ids.contains(&party_id) {
                        entry
                            .partial_points
                            .push((share_id, partial_bytes.to_vec()));
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
                .expect("exp registry entry must exist after insertion");

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

                let domain = GeneralEvaluationDomain::<F>::new(n)
                    .ok_or_else(|| "No suitable FFT domain".to_string())?;
                let eval_points: Vec<(usize, F)> = points
                    .iter()
                    .map(|(id, _)| (*id, domain.element(*id)))
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
                                .ok_or_else(|| "zero denominator in Lagrange".to_string())?;
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
                            let notified = EXP_NOTIFY.notified();

                            if let Some(result) =
                                try_check(&mut my_sequence, &partial_bytes, share.id)?
                            {
                                return Ok(result);
                            }

                            if tokio::time::Instant::now() >= deadline {
                                return Err(format!(
                                    "Timeout waiting for open_share_in_exp contributions"
                                ));
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
            if let Some(result) = try_check(&mut my_sequence, &partial_bytes, share.id)? {
                return Ok(result);
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "Timeout waiting for open_share_in_exp contributions"
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn ensure_rt() -> Result<tokio::runtime::Handle, String> {
        tokio::runtime::Handle::try_current()
            .map_err(|e| format!("Tokio runtime not available: {}", e))
    }

    /// Convert a reconstructed field element to the appropriate [`Value`] for a given share type.
    fn field_to_value(ty: ShareType, secret: F) -> Value {
        match ty {
            ShareType::SecretInt { .. } if ty.is_boolean() => Value::Bool(!secret.is_zero()),
            ShareType::SecretInt { .. } => Value::I64(crate::net::curve::field_to_i64(secret)),
            ShareType::SecretFixedPoint { precision } => {
                let scaled_value = crate::net::curve::field_to_i64(secret);
                let f = precision.f();
                let scale = (1u64 << f) as f64;
                let float_value = scaled_value as f64 / scale;
                Value::Float(F64(float_value))
            }
        }
    }

    fn encode_share(share: &RobustShare<F>) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        share
            .serialize_compressed(&mut out)
            .map_err(|e| format!("serialize share: {}", e))?;
        Ok(out)
    }

    fn decode_share(bytes: &[u8]) -> Result<RobustShare<F>, String> {
        RobustShare::<F>::deserialize_compressed(bytes)
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
        let shares: Vec<RobustShare<F>> = if input_len == 1 {
            // Try to deserialize as a single share
            let single_share: RobustShare<F> =
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

impl<F, G> MpcEngine for HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
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
                let secret = crate::net::curve::field_from_i64::<F>(*v);
                let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
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
                let secret = if *b { F::from(1u64) } else { F::from(0u64) };
                let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
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
                let secret = crate::net::curve::field_from_i64(scaled_value);
                let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
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
        let type_key = match ty {
            ShareType::SecretInt { bit_length } => format!("hb-int-{bit_length}"),
            ShareType::SecretFixedPoint { precision } => {
                format!("hb-fixed-{}-{}", precision.k(), precision.f())
            }
        };

        let required = 2 * self.t + 1;
        let n = self.n;

        crate::net::open_registry::open_share_via_registry(
            self.instance_id,
            self.party_id,
            &type_key,
            share_bytes,
            required,
            |collected| {
                let mut shares: Vec<RobustShare<F>> = Vec::with_capacity(collected.len());
                for bytes in collected {
                    shares.push(Self::decode_share(bytes)?);
                }

                tracing::debug!(
                    "open_share reconstruction: n={}, required={}, shares.len()={}",
                    n,
                    required,
                    shares.len()
                );

                let (_deg, secret) = RobustShare::recover_secret(&shares, n)
                    .map_err(|e| format!("recover_secret: {:?}", e))?;
                Ok(Self::field_to_value(ty, secret))
            },
        )
    }

    fn batch_open_shares(&self, ty: ShareType, shares: &[Vec<u8>]) -> Result<Vec<Value>, String> {
        let type_key = match ty {
            ShareType::SecretInt { bit_length } => format!("hb-batch-int-{bit_length}"),
            ShareType::SecretFixedPoint { precision } => {
                format!("hb-batch-fixed-{}-{}", precision.k(), precision.f())
            }
        };

        let required = 2 * self.t + 1;
        let n = self.n;

        crate::net::open_registry::batch_open_via_registry(
            self.instance_id,
            self.party_id,
            &type_key,
            shares,
            required,
            |collected, pos| {
                let mut decoded_shares: Vec<RobustShare<F>> = Vec::with_capacity(collected.len());
                for bytes in collected {
                    decoded_shares.push(Self::decode_share(bytes)?);
                }

                let (_deg, secret) = RobustShare::recover_secret(&decoded_shares, n)
                    .map_err(|e| format!("batch recover_secret pos {}: {:?}", pos, e))?;
                Ok(Self::field_to_value(ty, secret))
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
        if TypeId::of::<G>() == TypeId::of::<ark_bls12_381::G1Projective>() {
            MpcCurveConfig::Bls12_381
        } else if TypeId::of::<G>() == TypeId::of::<ark_bn254::G1Projective>() {
            MpcCurveConfig::Bn254
        } else if TypeId::of::<G>() == TypeId::of::<ark_curve25519::EdwardsProjective>() {
            MpcCurveConfig::Curve25519
        } else if TypeId::of::<G>() == TypeId::of::<ark_ed25519::EdwardsProjective>() {
            MpcCurveConfig::Ed25519
        } else {
            F::CURVE_CONFIG
        }
    }

    fn capabilities(&self) -> crate::net::mpc_engine::MpcCapabilities {
        use crate::net::mpc_engine::MpcCapabilities;
        MpcCapabilities::MULTIPLICATION
            | MpcCapabilities::OPEN_IN_EXP
            | MpcCapabilities::CLIENT_INPUT
            | MpcCapabilities::CONSENSUS
    }

    fn as_consensus(&self) -> Option<&dyn MpcEngineConsensus> {
        Some(self)
    }
    fn as_client_ops(&self) -> Option<&dyn MpcEngineClientOps> {
        Some(self)
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }

    fn random_share(&self, ty: ShareType) -> Result<Vec<u8>, String> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) =>
            {
                #[allow(deprecated)]
                match handle.runtime_flavor() {
                    tokio::runtime::RuntimeFlavor::MultiThread => {
                        tokio::task::block_in_place(|| {
                            handle.block_on(self.random_share_async_impl(ty))
                        })
                    }
                    _ => Err("random_share requires multi-thread Tokio runtime".to_string()),
                }
            }
            Err(_) => {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("Failed to build Tokio runtime: {}", e))?;
                rt.block_on(self.random_share_async_impl(ty))
            }
        }
    }

    fn open_share_in_exp(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        generator_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.open_share_in_exp_impl(ty, share_bytes, generator_bytes)
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
impl<F, G> AsyncMpcEngine for HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
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

    async fn batch_open_shares_async(
        &self,
        ty: ShareType,
        shares: &[Vec<u8>],
    ) -> Result<Vec<Value>, String> {
        // Delegate to sync version - the registry operations are quick
        self.batch_open_shares(ty, shares)
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

    async fn random_share_async(&self, ty: ShareType) -> Result<Vec<u8>, String> {
        self.random_share_async_impl(ty).await
    }

    async fn open_share_in_exp_async(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        generator_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.open_share_in_exp_impl(ty, share_bytes, generator_bytes)
    }
}

impl<F, G> MpcEngineClientOps for HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
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
            Ok(handle) =>
            {
                #[allow(deprecated)]
                match handle.runtime_flavor() {
                    tokio::runtime::RuntimeFlavor::MultiThread => {
                        tokio::task::block_in_place(|| {
                            handle.block_on(self.hydrate_client_inputs(store))
                        })
                    }
                    tokio::runtime::RuntimeFlavor::CurrentThread => Err(
                        "Cannot hydrate client inputs from single-thread Tokio runtime".to_string(),
                    ),
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
            Ok(handle) =>
            {
                #[allow(deprecated)]
                match handle.runtime_flavor() {
                    tokio::runtime::RuntimeFlavor::MultiThread => {
                        tokio::task::block_in_place(|| {
                            handle.block_on(self.hydrate_client_inputs_for(store, client_ids))
                        })
                    }
                    tokio::runtime::RuntimeFlavor::CurrentThread => Err(
                        "Cannot hydrate client inputs from single-thread Tokio runtime".to_string(),
                    ),
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
    /// Tracks deliveries to receivers: (instance_id, receiver_party, from_party, session_id).
    delivered: std::collections::HashSet<(u64, usize, usize, u64)>,
}

/// Registry for ABA sessions - maps (instance_id, session_id) to agreement state
#[derive(Default)]
struct AbaRegistry {
    /// Maps (instance_id, session_id, party_id) to proposed value
    proposals: std::collections::HashMap<(u64, u64, usize), bool>,
    /// Maps (instance_id, session_id) to agreed result once consensus is reached
    results: std::collections::HashMap<(u64, u64), bool>,
}

static RBC_REGISTRY: once_cell::sync::Lazy<parking_lot::Mutex<RbcRegistry>> =
    once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(RbcRegistry::default()));

/// Notified after every insertion into [`RBC_REGISTRY`].
static RBC_NOTIFY: once_cell::sync::Lazy<tokio::sync::Notify> =
    once_cell::sync::Lazy::new(tokio::sync::Notify::new);

static ABA_REGISTRY: once_cell::sync::Lazy<parking_lot::Mutex<AbaRegistry>> =
    once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(AbaRegistry::default()));

/// Notified after every insertion into [`ABA_REGISTRY`].
static ABA_NOTIFY: once_cell::sync::Lazy<tokio::sync::Notify> =
    once_cell::sync::Lazy::new(tokio::sync::Notify::new);

impl<F, G> MpcEngineConsensus for HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    fn rbc_broadcast(&self, message: &[u8]) -> Result<u64, String> {
        let mut registry = RBC_REGISTRY.lock();

        // Assign the earliest session index this party has not used yet for this instance.
        let mut session_id = 0u64;
        while registry
            .messages
            .contains_key(&(self.instance_id, session_id, self.party_id))
        {
            session_id = session_id
                .checked_add(1)
                .ok_or_else(|| "RBC session id overflow".to_string())?;
        }

        // Store the message for this party's broadcast
        let key = (self.instance_id, session_id, self.party_id);
        registry.messages.insert(key, message.to_vec());
        drop(registry);

        RBC_NOTIFY.notify_waiters();

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
        let instance_id = self.instance_id;
        let party_id = self.party_id;

        let try_deliver = || -> Option<Vec<u8>> {
            let mut registry = RBC_REGISTRY.lock();
            let mut next: Option<(u64, Vec<u8>)> = None;
            for ((inst_id, session_id, party), message) in registry.messages.iter() {
                if *inst_id != instance_id || *party != from_party {
                    continue;
                }
                let delivery_key = (instance_id, party_id, from_party, *session_id);
                if registry.delivered.contains(&delivery_key) {
                    continue;
                }
                match next {
                    Some((best_session, _)) if *session_id >= best_session => {}
                    _ => next = Some((*session_id, message.clone())),
                }
            }
            if let Some((session_id, message)) = next {
                registry
                    .delivered
                    .insert((instance_id, party_id, from_party, session_id));
                tracing::info!(
                    instance_id = instance_id,
                    session_id = session_id,
                    from_party = from_party,
                    message_len = message.len(),
                    "RBC receive delivered message"
                );
                return Some(message);
            }
            None
        };

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
                return tokio::task::block_in_place(|| {
                    handle.block_on(async {
                        let deadline = tokio::time::Instant::now()
                            + tokio::time::Duration::from_millis(timeout_ms);
                        loop {
                            let notified = RBC_NOTIFY.notified();
                            if let Some(msg) = try_deliver() {
                                return Ok(msg);
                            }
                            if tokio::time::Instant::now() >= deadline {
                                return Err(format!(
                                    "RBC receive timeout waiting for message from party {}",
                                    from_party
                                ));
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

        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        loop {
            if let Some(msg) = try_deliver() {
                return Ok(msg);
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "RBC receive timeout waiting for message from party {}",
                    from_party
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    fn rbc_receive_any(&self, timeout_ms: u64) -> Result<(usize, Vec<u8>), String> {
        let instance_id = self.instance_id;
        let party_id = self.party_id;

        let try_deliver = || -> Option<(usize, Vec<u8>)> {
            let mut registry = RBC_REGISTRY.lock();
            let mut next: Option<(u64, usize, Vec<u8>)> = None;
            for ((inst_id, session_id, party), message) in registry.messages.iter() {
                if *inst_id != instance_id || *party == party_id {
                    continue;
                }
                let delivery_key = (instance_id, party_id, *party, *session_id);
                if registry.delivered.contains(&delivery_key) {
                    continue;
                }
                match next {
                    Some((best_session, best_party, _))
                        if (*session_id, *party) >= (best_session, best_party) => {}
                    _ => next = Some((*session_id, *party, message.clone())),
                }
            }
            if let Some((session_id, party, message)) = next {
                registry
                    .delivered
                    .insert((instance_id, party_id, party, session_id));
                tracing::info!(
                    instance_id = instance_id,
                    session_id = session_id,
                    from_party = party,
                    message_len = message.len(),
                    "RBC receive_any delivered message"
                );
                return Some((party, message));
            }
            None
        };

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
                return tokio::task::block_in_place(|| {
                    handle.block_on(async {
                        let deadline = tokio::time::Instant::now()
                            + tokio::time::Duration::from_millis(timeout_ms);
                        loop {
                            let notified = RBC_NOTIFY.notified();
                            if let Some(result) = try_deliver() {
                                return Ok(result);
                            }
                            if tokio::time::Instant::now() >= deadline {
                                return Err(
                                    "RBC receive_any timeout waiting for message from any party"
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

        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        loop {
            if let Some(result) = try_deliver() {
                return Ok(result);
            }
            if std::time::Instant::now() >= deadline {
                return Err(
                    "RBC receive_any timeout waiting for message from any party".to_string()
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    fn aba_propose(&self, value: bool) -> Result<u64, String> {
        let mut registry = ABA_REGISTRY.lock();

        // Assign the earliest session index this party has not proposed in yet.
        // This keeps round indices aligned across parties despite asynchronous ordering.
        let mut session_id = 0u64;
        while registry
            .proposals
            .contains_key(&(self.instance_id, session_id, self.party_id))
        {
            session_id = session_id
                .checked_add(1)
                .ok_or_else(|| "ABA session id overflow".to_string())?;
        }

        // Store this party's proposal
        let key = (self.instance_id, session_id, self.party_id);
        registry.proposals.insert(key, value);
        drop(registry);

        ABA_NOTIFY.notify_waiters();

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
        let instance_id = self.instance_id;
        let required = 2 * self.t + 1;

        let try_check = || -> Option<bool> {
            let mut registry = ABA_REGISTRY.lock();

            if let Some(&result) = registry.results.get(&(instance_id, session_id)) {
                return Some(result);
            }

            let mut true_count = 0usize;
            let mut false_count = 0usize;

            for ((inst_id, sess_id, _party), &proposal) in registry.proposals.iter() {
                if *inst_id == instance_id && *sess_id == session_id {
                    if proposal {
                        true_count += 1;
                    } else {
                        false_count += 1;
                    }
                }
            }

            if true_count >= required {
                registry.results.insert((instance_id, session_id), true);
                tracing::info!(
                    instance_id = instance_id,
                    session_id = session_id,
                    result = true,
                    true_count = true_count,
                    "ABA agreement reached"
                );
                return Some(true);
            }

            if false_count >= required {
                registry.results.insert((instance_id, session_id), false);
                tracing::info!(
                    instance_id = instance_id,
                    session_id = session_id,
                    result = false,
                    false_count = false_count,
                    "ABA agreement reached"
                );
                return Some(false);
            }

            None
        };

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
                return tokio::task::block_in_place(|| {
                    handle.block_on(async {
                        let deadline = tokio::time::Instant::now()
                            + tokio::time::Duration::from_millis(timeout_ms);
                        loop {
                            let notified = ABA_NOTIFY.notified();
                            if let Some(result) = try_check() {
                                return Ok(result);
                            }
                            if tokio::time::Instant::now() >= deadline {
                                return Err(format!(
                                    "ABA result timeout waiting for agreement on session {}",
                                    session_id
                                ));
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

        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        loop {
            if let Some(result) = try_check() {
                return Ok(result);
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "ABA result timeout waiting for agreement on session {}",
                    session_id
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

#[async_trait::async_trait]
impl<F, G> AsyncMpcEngineConsensus for HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn next_instance_id() -> u64 {
        static NEXT_INSTANCE_ID: AtomicU64 = AtomicU64::new(1_000_000);
        NEXT_INSTANCE_ID.fetch_add(1, Ordering::Relaxed)
    }

    fn test_engine(
        instance_id: u64,
        party_id: usize,
        n: usize,
        t: usize,
    ) -> Arc<HoneyBadgerMpcEngine<ark_bls12_381::Fr, ark_bls12_381::G1Projective>> {
        HoneyBadgerMpcEngine::<ark_bls12_381::Fr, ark_bls12_381::G1Projective>::new(
            instance_id,
            party_id,
            n,
            t,
            1,
            1,
            Arc::new(QuicNetworkManager::new()),
            Vec::new(),
        )
        .expect("engine construction should succeed")
    }

    fn open_exp_test_payload(
        instance_id: u64,
        sender_party_id: usize,
        share_id: usize,
        partial_point: Vec<u8>,
    ) -> Vec<u8> {
        let payload = ExpOpenWireMessage {
            instance_id,
            sender_party_id,
            share_id,
            partial_point,
        };
        let encoded = bincode::serialize(&payload).expect("serialize test payload");
        let mut wire = Vec::with_capacity(EXP_OPEN_WIRE_PREFIX.len() + encoded.len());
        wire.extend_from_slice(EXP_OPEN_WIRE_PREFIX);
        wire.extend_from_slice(&encoded);
        wire
    }

    #[test]
    fn aba_same_round_uses_shared_session_and_converges() {
        let instance_id = next_instance_id();
        let n = 4;
        let t = 1;
        let e0 = test_engine(instance_id, 0, n, t);
        let e1 = test_engine(instance_id, 1, n, t);
        let e2 = test_engine(instance_id, 2, n, t);
        let e3 = test_engine(instance_id, 3, n, t);

        let s0 = e0.aba_propose(true).expect("party 0 propose");
        let s1 = e1.aba_propose(true).expect("party 1 propose");
        let s2 = e2.aba_propose(true).expect("party 2 propose");
        let s3 = e3.aba_propose(true).expect("party 3 propose");

        assert_eq!(s0, s1, "same ABA round must share one session id");
        assert_eq!(s1, s2, "same ABA round must share one session id");
        assert_eq!(s2, s3, "same ABA round must share one session id");

        let r0 = e0.aba_result(s0, 50).expect("party 0 agreement");
        let r1 = e1.aba_result(s1, 50).expect("party 1 agreement");
        let r2 = e2.aba_result(s2, 50).expect("party 2 agreement");
        let r3 = e3.aba_result(s3, 50).expect("party 3 agreement");

        assert!(r0 && r1 && r2 && r3, "all parties should decide true");
    }

    #[test]
    fn rbc_receive_delivers_new_broadcast_each_call_in_order() {
        let instance_id = next_instance_id();
        let n = 4;
        let t = 1;
        let sender = test_engine(instance_id, 0, n, t);
        let receiver = test_engine(instance_id, 1, n, t);

        sender.rbc_broadcast(b"first").expect("broadcast first");
        sender.rbc_broadcast(b"second").expect("broadcast second");

        let first = receiver.rbc_receive(0, 50).expect("receive first");
        let second = receiver.rbc_receive(0, 50).expect("receive second");

        assert_eq!(
            first, b"first",
            "first receive should return first broadcast"
        );
        assert_eq!(
            second, b"second",
            "second receive should return second broadcast"
        );
    }

    #[test]
    fn open_exp_wire_rejects_mismatched_share_id() {
        clear_exp_registry();
        let instance_id = next_instance_id();
        let payload = open_exp_test_payload(instance_id, 1, 0, vec![1, 2, 3, 4]);

        let err = try_handle_open_exp_wire_message(1, &payload)
            .expect_err("mismatched share_id must be rejected");
        assert!(
            err.contains("open-exp share_id mismatch"),
            "unexpected error: {}",
            err
        );
        assert!(
            !EXP_REGISTRY.lock().contains_key(&(instance_id, 0)),
            "rejected payload must not be inserted into the registry"
        );
    }

    #[test]
    fn open_exp_wire_accepts_matching_share_id() {
        clear_exp_registry();
        let instance_id = next_instance_id();
        let payload = open_exp_test_payload(instance_id, 1, 1, vec![9, 8, 7, 6]);

        let handled =
            try_handle_open_exp_wire_message(1, &payload).expect("matching sender/share is valid");
        assert!(handled, "open-exp prefix payload must be handled");

        let reg = EXP_REGISTRY.lock();
        let entry = reg
            .get(&(instance_id, 0))
            .expect("entry should be inserted for valid payload");
        assert_eq!(entry.party_ids, vec![1]);
        assert_eq!(entry.partial_points, vec![(1, vec![9, 8, 7, 6])]);
    }
}
