
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use tokio::runtime::Handle;
use tokio::sync::Mutex;
use stoffelmpc_mpc::common::{MPCProtocol, SecretSharingScheme};
use stoffelmpc_mpc::honeybadger::{HoneyBadgerMPCNode, HoneyBadgerMPCNodeOpts};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelnet::transports::quic::QuicNetworkManager;
use crate::net::mpc_engine::MpcEngine;
use stoffel_vm_types::core_types::{ShareType, Value};

// RBC/SSS type aliases used by HB implementation
use stoffelmpc_mpc::common::rbc::rbc::Avid as RBCImpl;

/// Minimal HoneyBadger-backed engine. Single-party-local wrapper that can
/// perform share input (local robust-shamir splitting) and online multiplication
/// via the underlying HoneyBadgerMPCNode. Network topology is expected to be
/// prepared outside with QUIC; for this minimal engine, we create the node and
/// rely on external network manager usage inside the protocol calls.
pub struct HoneyBadgerMpcEngine {
    instance_id: u64,
    party_id: usize,
    n: usize,
    t: usize,
    node: Arc<Mutex<HoneyBadgerMPCNode<Fr, RBCImpl>>>,
    net: Arc<QuicNetworkManager>,
    ready: AtomicBool,
}

impl HoneyBadgerMpcEngine {
    pub fn new(instance_id: u64, party_id: usize, n: usize, t: usize, n_triples: usize, n_random: usize, net: Arc<QuicNetworkManager>) -> Arc<Self> {
        // For now, construct a single node for this local party.
        let opts = HoneyBadgerMPCNodeOpts::new(n, t, n_triples, n_random, instance_id);
        let node = <HoneyBadgerMPCNode<Fr, RBCImpl> as MPCProtocol<Fr, RobustShare<Fr>, QuicNetworkManager>>::setup(party_id, opts)
            .expect("Failed to setup HoneyBadgerMPCNode");
        Arc::new(Self {
            instance_id,
            party_id,
            n,
            t,
            node: Arc::new(Mutex::new(node)),
            net,
            ready: AtomicBool::new(false),
        })
    }

    fn ensure_rt() -> Result<Handle, String> {
        Handle::try_current().map_err(|e| format!("Tokio runtime not available: {}", e))
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
        // Run preprocessing once before allowing online ops.
        let rt = Self::ensure_rt()?;
        let node = self.node.clone();
        let net = self.net.clone();
        rt.block_on(async move {
            use ark_std::rand::{rngs::StdRng, SeedableRng};
            let mut rng: StdRng = StdRng::from_seed([42u8; 32]);
            // Best-effort preprocessing; if protocol requires, handle errors.
            use stoffelmpc_mpc::common::PreprocessingMPCProtocol;
            if let Err(e) = node.lock().await.run_preprocessing(net.clone(), &mut rng).await {
                return Err(format!("preprocessing failed: {:?}", e));
            }
            Ok::<(), String>(())
        })?;
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
        if !self.is_ready() { return Err("MPC engine not ready".into()); }
        match ty {
            ShareType::Int(_) | ShareType::Bool(_) | ShareType::Float(_) => {
                let l = Self::decode_share(left)?;
                let r = Self::decode_share(right)?;
                let rt = Self::ensure_rt()?;
                let node = self.node.clone();
                let net = self.net.clone();
                let fut = async move {
                    let mut n = node.lock().await;
                    let res = n.mul(vec![l], vec![r], net.clone()).await
                        .map_err(|e| format!("mul error: {:?}", e))?;
                    if res.is_empty() { return Err("mul returned empty".to_string()); }
                    Ok::<RobustShare<Fr>, String>(res[0].clone())
                };
                let share = rt.block_on(fut)?;
                Self::encode_share(&share)
            }
            _ => Err("Unsupported share type for multiply_share".to_string()),
        }
    }

    fn open_share(&self, ty: ShareType, share_bytes: &[u8]) -> Result<Value, String> {
        // In-process aggregator using QUIC broadcast and collect is non-trivial.
        // As a minimal viable path for single-process multi-party tests, we reconstruct
        // only if we can get 2t+1 shares via a global registry. Otherwise, return error.
        static REGISTRY: once_cell::sync::Lazy<parking_lot::Mutex<std::collections::HashMap<(u64, &'static str), Vec<Vec<u8>>>>> = once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(std::collections::HashMap::new()));
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
                    // interpret field element as u64 (mod p) truncated
                    let limbs: [u64; 4] = secret.into_bigint().0;
                    Ok(Value::I64(limbs[0] as i64))
                }
                ShareType::Bool(_) => {
                    use ark_ff::Zero;
                                        let is_one = !secret.is_zero();
                    Ok(Value::Bool(is_one))
                }
                ShareType::Float(_) => {
                    // naive mapping: interpret as u64, cast to f64
                    let limbs: [u64; 4] = secret.into_bigint().0;
                    Ok(Value::Float(limbs[0] as i64))
                }
                _ => Err("Unsupported type for open_share".to_string()),
            };
        }
    }

    fn shutdown(&self) { self.ready.store(false, Ordering::SeqCst); }
}
