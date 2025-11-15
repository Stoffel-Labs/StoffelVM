use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::SeedableRng;
use tokio::sync::Mutex;
use stoffelmpc_mpc::common::{SecretSharingScheme, MPCProtocol, PreprocessingMPCProtocol};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::{HoneyBadgerMPCNode, HoneyBadgerMPCNodeOpts, SessionId, ProtocolType};
use stoffelnet::network_utils::ClientId;
use stoffelnet::transports::quic::QuicNetworkManager;
use crate::net::mpc_engine::MpcEngine;
use stoffel_vm_types::core_types::{ShareType, Value};

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
        if !self.is_ready() { return Err("MPC engine not ready".into()); }

        match ty {
            ShareType::Int(_) | ShareType::Bool(_) | ShareType::Float(_) => {
                // Decode the input shares
                let left_share = Self::decode_share(left)?;
                let right_share = Self::decode_share(right)?;

                // Get next session ID for this multiplication
                let session_idx = {
                    let mut counter = self.mul_session_counter.lock().await;
                    let idx = *counter;
                    *counter += 1;
                    idx
                };

                let session_id = SessionId::new(ProtocolType::Mul, session_idx as u8, 0, self.instance_id);

                // Perform MPC multiplication
                let mut node = self.node.lock().await;
                let x_shares = vec![left_share];
                let y_shares = vec![right_share];

                node.mul(x_shares, y_shares, self.net.clone())
                    .await
                    .map_err(|e| format!("MPC multiplication failed: {:?}", e))?;

                // Retrieve the result from the multiplication storage
                let storage_map = node.operations.mul.mult_storage.lock().await;
                let storage_mutex = storage_map.get(&session_id)
                    .ok_or_else(|| format!("No result for session {:?}", session_id))?;
                let storage = storage_mutex.lock().await;

                if storage.protocol_output.is_empty() {
                    return Err("Multiplication produced no output".to_string());
                }

                let result_share = &storage.protocol_output[0];
                Self::encode_share(result_share)
            }
            _ => Err("Unsupported share type for multiply_share".to_string()),
        }
    }

    pub async fn open_share_async(&self, ty: ShareType, share_bytes: &[u8]) -> Result<Value, String> {
        // Use the same registry approach but non-blocking API boundary to VM future paths later
        // For now, just delegate to sync version because registry is local
        self.open_share(ty, share_bytes)
    }

    pub fn net(&self) -> Arc<QuicNetworkManager> { self.net.clone() }
    pub fn party_id(&self) -> usize { self.party_id }

    /// Initialize input shares from a client. This must be called after preprocessing.
    /// The client provides shares for all parties, and each party stores its own share.
    pub async fn init_client_input(&self, client_id: ClientId, shares: Vec<RobustShare<Fr>>) -> Result<(), String> {
        if !self.is_ready() {
            return Err("MPC engine not ready".into());
        }

        // Take random shares from preprocessing material for the input protocol
        let num_shares = shares.len();
        let local_shares = {
            let node = self.node.lock().await;
            let mut prep_material = node.preprocessing_material.lock().await;
            prep_material
                .take_random_shares(num_shares)
                .map_err(|e| format!("Failed to take random shares: {:?}", e))?
        };

        // Initialize the input protocol with the client's shares
        let mut node = self.node.lock().await;
        node.preprocess
            .input
            .init(client_id, local_shares, num_shares, self.net.clone())
            .await
            .map_err(|e| format!("Failed to initialize client input: {:?}", e))?;

        Ok(())
    }

    /// Get the shares for a specific client after input initialization
    pub async fn get_client_shares(&self, client_id: ClientId) -> Result<Vec<RobustShare<Fr>>, String> {
        let node = self.node.lock().await;
        let input_store = node.preprocess.input.input_shares.lock().await;
        let shares = input_store
            .get(&client_id)
            .ok_or_else(|| format!("No shares found for client {}", client_id))?
            .clone();
        Ok(shares)
    }

    pub fn new(instance_id: u64, party_id: usize, n: usize, t: usize, n_triples: usize, n_random: usize, net: Arc<QuicNetworkManager>) -> Result<Arc<Self>, String> {
        // Create the MPC node options
        let mpc_opts = HoneyBadgerMPCNodeOpts::new(
            n,
            t,
            n_triples,
            n_random,
            instance_id,
        );

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

    fn ensure_rt() -> Result<tokio::runtime::Handle, String> {
        tokio::runtime::Handle::try_current().map_err(|e| format!("Tokio runtime not available: {}", e))
    }

    fn encode_share(share: &RobustShare<Fr>) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        share.serialize_compressed(&mut out).map_err(|e| format!("serialize share: {}", e))?;
        Ok(out)
    }

    fn decode_share(bytes: &[u8]) -> Result<RobustShare<Fr>, String> {
        RobustShare::<Fr>::deserialize_compressed(bytes).map_err(|e| format!("deserialize share: {}", e))
    }
}

impl MpcEngine for HoneyBadgerMpcEngine {
    fn protocol_name(&self) -> &'static str { "honeybadger-mpc" }
    fn instance_id(&self) -> u64 { self.instance_id }
    fn is_ready(&self) -> bool { self.ready.load(Ordering::SeqCst) }

    fn start(&self) -> Result<(), String> {
        // Mark engine as ready in test/single-process scenarios. Real deployments should call `preprocess()`.
        self.ready.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn input_share(&self, ty: ShareType, clear: &Value) -> Result<Vec<u8>, String> {
        // Minimal support: ShareType::Int over Fr via direct embedding (u64 -> Fr).
        match (ty, clear) {
            (ShareType::Int(_), Value::I64(v)) => {
                let secret = Fr::from(*v as u64);
                let mut rng = ark_std::test_rng();
                let shares = RobustShare::compute_shares(secret, self.n, self.t, None, &mut rng)
                    .map_err(|e| format!("compute_shares: {:?}", e))?;
                let my = &shares[self.party_id];
                Self::encode_share(my)
            }
            (ShareType::Bool(_), Value::Bool(b)) => {
                let secret = if *b { Fr::from(1u64) } else { Fr::from(0u64) };
                let mut rng = ark_std::test_rng();
                let shares = RobustShare::compute_shares(secret, self.n, self.t, None, &mut rng)
                    .map_err(|e| format!("compute_shares: {:?}", e))?;
                let my = &shares[self.party_id];
                Self::encode_share(my)
            }
            (ShareType::Float(_), Value::Float(fp)) => {
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

    fn multiply_share(
        &self,
        ty: ShareType,
        left: &[u8],
        right: &[u8],
    ) -> Result<Vec<u8>, String> {
        // Block on the async version using the current runtime
        let rt = Self::ensure_rt()?;
        rt.block_on(self.multiply_share_async(ty, left, right))
    }

    fn open_share(&self, ty: ShareType, share_bytes: &[u8]) -> Result<Value, String> {
        // In-process aggregator using a global registry of shares; reconstruct when 2t+1 are present.
        static REGISTRY: once_cell::sync::Lazy<parking_lot::Mutex<std::collections::HashMap<(u64, &'static str), Vec<Vec<u8>>>>>
            = once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(std::collections::HashMap::new()));
        let key = (self.instance_id, match ty { ShareType::Int(_) => "int", ShareType::Float(_) => "float", ShareType::Bool(_) => "bool", _ => "other" });
        {
            let mut reg = REGISTRY.lock();
            let entry = reg.entry(key).or_default();
            entry.push(share_bytes.to_vec());
            if entry.len() < (2 * self.t + 1) {
                return Err(format!("open_share needs {} shares, currently have {}", 2 * self.t + 1, entry.len()));
            }
            // collect exactly 2t+1
            let collected: Vec<Vec<u8>> = entry.iter().take(2 * self.t + 1).cloned().collect();
            drop(reg);
            // decode to RobustShare
            let mut shares: Vec<RobustShare<Fr>> = Vec::with_capacity(collected.len());
            for b in collected.iter() {
                shares.push(Self::decode_share(b)?);
            }
            let (_deg, secret) = RobustShare::recover_secret(&shares, self.n)
                .map_err(|e| format!("recover_secret: {:?}", e))?;
            // map back to Value
            return match ty {
                ShareType::Int(_) => {
                    let limbs: [u64; 4] = secret.into_bigint().0;
                    Ok(Value::I64(limbs[0] as i64))
                }
                ShareType::Bool(_) => {
                    use ark_ff::Zero;
                    let is_one = !secret.is_zero();
                    Ok(Value::Bool(is_one))
                }
                ShareType::Float(_) => {
                    let limbs: [u64; 4] = secret.into_bigint().0;
                    Ok(Value::Float(limbs[0] as i64))
                }
                _ => Err("Unsupported type for open_share".to_string()),
            };
        }
    }

    fn shutdown(&self) { self.ready.store(false, Ordering::SeqCst); }
}
