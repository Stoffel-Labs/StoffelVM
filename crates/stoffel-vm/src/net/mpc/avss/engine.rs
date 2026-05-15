use super::AvssMpcEngine;
use crate::net::curve::{MpcCurveConfig, SupportedMpcField};
use crate::net::mpc_engine::{
    MpcCapabilities, MpcEngine, MpcEngineClientOps, MpcEngineClientOutput, MpcEngineFieldOpen,
    MpcEngineMultiplication, MpcEngineOpenInExponent, MpcEngineOperationResultExt,
    MpcEnginePreprocPersistence, MpcEngineRandomness, MpcSessionTopology,
};
use ark_ec::CurveGroup;
use ark_std::rand::SeedableRng;
use std::sync::{atomic::Ordering, Arc};
use stoffel_vm_types::core_types::{
    ClearShareInput, ClearShareValue, ShareData, ShareType, BOOLEAN_SECRET_INT_BITS,
};
use stoffelmpc_mpc::avss_mpc::{AvssMPCNode as AvssMpcNode, AvssSessionId};
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::common::MPCProtocol;
use stoffelnet::transports::quic::QuicNetworkManager;
use tokio::sync::Mutex;
use tracing::info;

impl<F, G> AvssMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    pub(super) fn allocate_input_share_session(&self) -> Result<(usize, AvssSessionId), String> {
        self.session_ids.next_input_share_session()
    }

    pub(super) fn clear_input_to_field(clear: ClearShareInput) -> Result<F, String> {
        match clear.into_parts() {
            (ShareType::SecretInt { .. }, ClearShareValue::Integer(v)) => {
                Ok(Self::field_from_i64(v))
            }
            (
                ShareType::SecretInt {
                    bit_length: BOOLEAN_SECRET_INT_BITS,
                },
                ClearShareValue::Boolean(b),
            ) => {
                if b {
                    Ok(F::from(1u64))
                } else {
                    Ok(F::from(0u64))
                }
            }
            (ShareType::SecretFixedPoint { precision }, ClearShareValue::FixedPoint(fp)) => {
                let scaled_value = crate::net::curve::fixed_point_float_to_i64(precision, fp)?;
                Ok(Self::field_from_i64(scaled_value))
            }
            _ => Err("Unsupported type for input_share".to_string()),
        }
    }

    pub(super) async fn run_input_share_round(
        &self,
        dealer_id: usize,
        session_id: AvssSessionId,
        secret: F,
    ) -> Result<FeldmanShamirShare<F, G>, String> {
        if self.topology.party_id() == dealer_id {
            let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
            let mut node = self.clone_avss_node().await;
            node.share_gen_avss
                .avss
                .init(vec![secret], session_id, &mut rng, self.net.clone())
                .await
                .map_err(|e| format!("AVSS input_share init failed: {:?}", e))?;
        }

        self.wait_for_share(session_id).await
    }

    pub(super) async fn run_multiply_round(
        avss_node: Arc<Mutex<AvssMpcNode<F, Avid<AvssSessionId>, G>>>,
        net: Arc<QuicNetworkManager>,
        left_share_bytes: Vec<u8>,
        right_share_bytes: Vec<u8>,
    ) -> Result<ShareData, String> {
        let left_share = Self::decode_feldman_share(&left_share_bytes)?;
        let right_share = Self::decode_feldman_share(&right_share_bytes)?;

        let mut node = {
            let node = avss_node.lock().await;
            node.clone()
        };
        let result = node
            .mul(vec![left_share], vec![right_share], net)
            .await
            .map_err(|e| format!("Multiplication failed: {:?}", e))?;

        let product = result
            .into_iter()
            .next()
            .ok_or_else(|| "Multiplication returned no result".to_string())?;
        Self::share_to_share_data(&product)
    }

    pub(super) async fn broadcast_open_registry_payload(
        &self,
        payload: Vec<u8>,
    ) -> Result<(), String> {
        crate::net::broadcast::broadcast_to_other_parties(
            self.net.as_ref(),
            self.topology.n_parties(),
            self.topology.party_id(),
            &payload,
            "Failed to send open payload to party",
        )
        .await
    }

    pub(super) fn broadcast_open_registry_payload_sync(
        &self,
        payload: Vec<u8>,
    ) -> Result<(), String> {
        crate::net::block_on_current(self.broadcast_open_registry_payload(payload))
    }

    /// Start the engine and mark it ready.
    pub async fn start_async(&self) -> Result<(), String> {
        self.ready.store(true, Ordering::SeqCst);
        info!(
            "AVSS engine started: instance={}, party={}, n={}, t={}",
            self.topology.instance_id(),
            self.topology.party_id(),
            self.topology.n_parties(),
            self.topology.threshold()
        );
        Ok(())
    }
}

impl<F, G> MpcEngine for AvssMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    fn protocol_name(&self) -> &'static str {
        "avss"
    }

    fn topology(&self) -> MpcSessionTopology {
        self.topology
    }

    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    fn start(&self) -> crate::net::mpc_engine::MpcEngineResult<()> {
        self.ready.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn input_share(
        &self,
        clear: ClearShareInput,
    ) -> crate::net::mpc_engine::MpcEngineResult<ShareData> {
        (|| -> Result<ShareData, String> {
            let secret = Self::clear_input_to_field(clear)?;
            let (dealer_id, session_id) = self.allocate_input_share_session()?;
            let share = crate::net::block_on_current(
                self.run_input_share_round(dealer_id, session_id, secret),
            )?;
            Self::share_to_share_data(&share)
        })()
        .map_mpc_engine_operation("input_share")
    }

    fn open_share(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
    ) -> crate::net::mpc_engine::MpcEngineResult<ClearShareValue> {
        (|| -> Result<ClearShareValue, String> {
            let type_key = match ty {
                ShareType::SecretInt { bit_length } => format!("avss-int-{bit_length}"),
                ShareType::SecretFixedPoint { precision } => {
                    format!("avss-fixed-{}-{}", precision.k(), precision.f())
                }
            };

            let wire_message = crate::net::open_registry::encode_single_share_wire_message(
                self.topology.instance_id(),
                &type_key,
                self.topology.party_id(),
                share_bytes,
            )?;
            self.broadcast_open_registry_payload_sync(wire_message)?;

            let required = self.topology.threshold() + 1;
            let n = self.topology.n_parties();
            let t = self.topology.threshold();

            self.open_registry.open_share_wait(
                self.topology.party_id(),
                &type_key,
                share_bytes,
                required,
                |collected| {
                    let mut shares: Vec<FeldmanShamirShare<F, G>> =
                        Vec::with_capacity(collected.len());
                    for bytes in collected {
                        shares.push(Self::decode_feldman_share(bytes)?);
                    }
                    let secret = Self::reconstruct_secret(&shares, n, t)?;
                    Self::field_to_clear_share_value(ty, secret)
                },
            )
        })()
        .map_mpc_engine_operation("open_share")
    }

    fn batch_open_shares(
        &self,
        ty: ShareType,
        shares: &[Vec<u8>],
    ) -> crate::net::mpc_engine::MpcEngineResult<Vec<ClearShareValue>> {
        (|| -> Result<Vec<ClearShareValue>, String> {
            let type_key = match ty {
                ShareType::SecretInt { bit_length } => format!("avss-batch-int-{bit_length}"),
                ShareType::SecretFixedPoint { precision } => {
                    format!("avss-batch-fixed-{}-{}", precision.k(), precision.f())
                }
            };

            let wire_message = crate::net::open_registry::encode_batch_share_wire_message(
                self.topology.instance_id(),
                &type_key,
                self.topology.party_id(),
                shares,
            )?;
            self.broadcast_open_registry_payload_sync(wire_message)?;

            let required = self.topology.threshold() + 1;
            let n = self.topology.n_parties();
            let t = self.topology.threshold();

            self.open_registry.batch_open_wait(
                self.topology.party_id(),
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
                    Self::field_to_clear_share_value(ty, secret)
                },
            )
        })()
        .map_mpc_engine_operation("batch_open_shares")
    }

    fn shutdown(&self) {
        self.ready.store(false, Ordering::SeqCst);
    }

    fn curve_config(&self) -> MpcCurveConfig {
        F::CURVE_CONFIG
    }

    fn capabilities(&self) -> MpcCapabilities {
        MpcCapabilities::MULTIPLICATION
            | MpcCapabilities::OPEN_IN_EXP
            | MpcCapabilities::ELLIPTIC_CURVES
            | MpcCapabilities::CLIENT_INPUT
            | MpcCapabilities::CLIENT_OUTPUT
            | MpcCapabilities::RANDOMNESS
            | MpcCapabilities::FIELD_OPEN
            | MpcCapabilities::PREPROC_PERSISTENCE
    }

    fn as_client_ops(&self) -> Option<&dyn MpcEngineClientOps> {
        Some(self)
    }

    fn as_multiplication(&self) -> Option<&dyn MpcEngineMultiplication> {
        Some(self)
    }

    fn as_client_output(&self) -> Option<&dyn MpcEngineClientOutput> {
        Some(self)
    }

    fn as_open_in_exp(&self) -> Option<&dyn MpcEngineOpenInExponent> {
        Some(self)
    }

    fn as_randomness(&self) -> Option<&dyn MpcEngineRandomness> {
        Some(self)
    }

    fn as_field_open(&self) -> Option<&dyn MpcEngineFieldOpen> {
        Some(self)
    }

    fn as_preproc_persistence(&self) -> Option<&dyn MpcEnginePreprocPersistence> {
        Some(self)
    }
}
