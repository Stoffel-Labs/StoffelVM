use super::HoneyBadgerMpcEngine;
use crate::net::curve::{MpcCurveConfig, SupportedMpcField};
use crate::net::mpc_engine::{
    MpcCapabilities, MpcEngine, MpcEngineClientOps, MpcEngineClientOutput, MpcEngineConsensus,
    MpcEngineMultiplication, MpcEngineOpenInExponent, MpcEngineOperationResultExt,
    MpcEnginePreprocPersistence, MpcEngineRandomness, MpcEngineReservation, MpcSessionTopology,
};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_std::rand::SeedableRng;
use std::any::TypeId;
use std::sync::atomic::Ordering;
use stoffel_vm_types::core_types::{
    ClearShareInput, ClearShareValue, ShareData, ShareType, BOOLEAN_SECRET_INT_BITS,
};
use stoffelmpc_mpc::common::SecretSharingScheme;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

impl<F, G> MpcEngine for HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    fn protocol_name(&self) -> &'static str {
        "honeybadger-mpc"
    }

    fn topology(&self) -> MpcSessionTopology {
        self.topology
    }

    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    fn start(&self) -> crate::net::mpc_engine::MpcEngineResult<()> {
        // Mark engine as ready in test/single-process scenarios. Real deployments should call `preprocess()`.
        self.ready.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn input_share(
        &self,
        clear: ClearShareInput,
    ) -> crate::net::mpc_engine::MpcEngineResult<ShareData> {
        (|| -> Result<ShareData, String> {
            match clear.into_parts() {
                (ShareType::SecretInt { .. }, ClearShareValue::Integer(v)) => {
                    let secret = crate::net::curve::field_from_i64::<F>(v);
                    let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
                    let shares = RobustShare::compute_shares(
                        secret,
                        self.topology.n_parties(),
                        self.topology.threshold(),
                        None,
                        &mut rng,
                    )
                    .map_err(|e| format!("compute_shares: {:?}", e))?;
                    let my = &shares[self.topology.party_id()];
                    Self::encode_share(my).map(ShareData::Opaque)
                }
                (
                    ShareType::SecretInt {
                        bit_length: BOOLEAN_SECRET_INT_BITS,
                    },
                    ClearShareValue::Boolean(b),
                ) => {
                    let secret = if b { F::from(1u64) } else { F::from(0u64) };
                    let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
                    let shares = RobustShare::compute_shares(
                        secret,
                        self.topology.n_parties(),
                        self.topology.threshold(),
                        None,
                        &mut rng,
                    )
                    .map_err(|e| format!("compute_shares: {:?}", e))?;
                    let my = &shares[self.topology.party_id()];
                    Self::encode_share(my).map(ShareData::Opaque)
                }
                (ShareType::SecretFixedPoint { precision }, ClearShareValue::FixedPoint(fp)) => {
                    let scaled_value = crate::net::curve::fixed_point_float_to_i64(precision, fp)?;
                    let secret = crate::net::curve::field_from_i64(scaled_value);
                    let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
                    let shares = RobustShare::compute_shares(
                        secret,
                        self.topology.n_parties(),
                        self.topology.threshold(),
                        None,
                        &mut rng,
                    )
                    .map_err(|e| format!("compute_shares: {:?}", e))?;
                    let my = &shares[self.topology.party_id()];
                    Self::encode_share(my).map(ShareData::Opaque)
                }
                _ => Err("Unsupported type for input_share".to_string()),
            }
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
                ShareType::SecretInt { bit_length } => format!("hb-int-{bit_length}"),
                ShareType::SecretFixedPoint { precision } => {
                    format!("hb-fixed-{}-{}", precision.k(), precision.f())
                }
            };

            let wire_message = crate::net::open_registry::encode_single_share_wire_message(
                self.topology.instance_id(),
                &type_key,
                self.topology.party_id(),
                share_bytes,
            )?;
            self.broadcast_open_registry_payload_sync(wire_message)?;

            let required = 2 * self.topology.threshold() + 1;
            let n = self.topology.n_parties();
            let t = self.topology.threshold();

            self.open_registry.open_share_wait(
                self.topology.party_id(),
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

                    let (_deg, secret) = RobustShare::recover_secret(&shares, n, t)
                        .map_err(|e| format!("recover_secret: {:?}", e))?;
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
                ShareType::SecretInt { bit_length } => format!("hb-batch-int-{bit_length}"),
                ShareType::SecretFixedPoint { precision } => {
                    format!("hb-batch-fixed-{}-{}", precision.k(), precision.f())
                }
            };

            let wire_message = crate::net::open_registry::encode_batch_share_wire_message(
                self.topology.instance_id(),
                &type_key,
                self.topology.party_id(),
                shares,
            )?;
            self.broadcast_open_registry_payload_sync(wire_message)?;

            let required = 2 * self.topology.threshold() + 1;
            let n = self.topology.n_parties();
            let t = self.topology.threshold();

            self.open_registry.batch_open_wait(
                self.topology.party_id(),
                &type_key,
                shares,
                required,
                |collected, pos| {
                    let mut decoded_shares: Vec<RobustShare<F>> =
                        Vec::with_capacity(collected.len());
                    for bytes in collected {
                        decoded_shares.push(Self::decode_share(bytes)?);
                    }

                    let (_deg, secret) = RobustShare::recover_secret(&decoded_shares, n, t)
                        .map_err(|e| format!("batch recover_secret pos {}: {:?}", pos, e))?;
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

    fn capabilities(&self) -> MpcCapabilities {
        MpcCapabilities::MULTIPLICATION
            | MpcCapabilities::OPEN_IN_EXP
            | MpcCapabilities::CLIENT_INPUT
            | MpcCapabilities::CLIENT_OUTPUT
            | MpcCapabilities::CONSENSUS
            | MpcCapabilities::RESERVATION
            | MpcCapabilities::RANDOMNESS
            | MpcCapabilities::PREPROC_PERSISTENCE
    }

    fn as_consensus(&self) -> Option<&dyn MpcEngineConsensus> {
        Some(self)
    }

    fn as_multiplication(&self) -> Option<&dyn MpcEngineMultiplication> {
        Some(self)
    }

    fn as_client_ops(&self) -> Option<&dyn MpcEngineClientOps> {
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

    fn as_reservation(&self) -> Option<&dyn MpcEngineReservation> {
        Some(self)
    }

    fn as_preproc_persistence(&self) -> Option<&dyn MpcEnginePreprocPersistence> {
        Some(self)
    }
}
