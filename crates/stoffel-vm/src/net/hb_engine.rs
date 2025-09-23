use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use tokio::sync::Mutex;
use stoffelmpc_mpc::common::SecretSharingScheme;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use crate::net::p2p::QuicNetworkManager;
// Note: tests pass Arc<Mutex<QuicNetworkManager>> where required; HoneyBadger APIs accept Arc<N>.
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
    net: Arc<QuicNetworkManager>,
    ready: AtomicBool,
}

impl HoneyBadgerMpcEngine {
    /// Fully async startup + preprocessing
    pub async fn start_async(&self) -> Result<(), String> {
        self.preprocess().await
    }

    pub async fn preprocess(&self) -> Result<(), String> {
        // Minimal stub: mark ready without network preprocessing to avoid cross-crate trait conflicts
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
                let l = Self::decode_share(left)?;
                let r = Self::decode_share(right)?;
                // Local multiply of the decoded shares (placeholder for real MPC)
                let mut prod = l.clone();
                prod.share[0] = l.share[0] * r.share[0];
                prod.degree = 2 * self.t;
                Self::encode_share(&prod)
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

    pub fn new(instance_id: u64, party_id: usize, n: usize, t: usize, _n_triples: usize, _n_random: usize, net: Arc<QuicNetworkManager>) -> Arc<Self> {
        // Minimal constructor: we do not initialize a HoneyBadger node here to avoid cross-crate trait constraints.
        Arc::new(Self {
            instance_id,
            party_id,
            n,
            t,
            net,
            ready: AtomicBool::new(false),
        })
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
        if !self.is_ready() { return Err("MPC engine not ready".into()); }
        match ty {
            ShareType::Int(_) | ShareType::Bool(_) | ShareType::Float(_) => {
                let _l = Self::decode_share(left)?;
                let _r = Self::decode_share(right)?;
                // Avoid blocking in async contexts
                return Err("multiply_share called inside async runtime; use multiply_share_async".to_string());
            }
            _ => Err("Unsupported share type for multiply_share".to_string()),
        }
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
