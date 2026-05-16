use super::HoneyBadgerMpcEngine;
use crate::net::curve::SupportedMpcField;
use crate::net::mpc_engine::MpcEngine;
use crate::net::open_registry::{ExpOpenRegistryKind, ExpOpenRequest};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use stoffel_vm_types::core_types::{ClearShareValue, ShareData, ShareType};
use stoffelmpc_mpc::common::{MPCProtocol, SecretSharingScheme};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

impl<F, G> HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    pub async fn multiply_share_async(
        &self,
        ty: ShareType,
        left: &[u8],
        right: &[u8],
    ) -> Result<ShareData, String> {
        if !self.is_ready() {
            return Err("MPC engine not ready".into());
        }

        match ty {
            ShareType::SecretInt { .. } | ShareType::SecretFixedPoint { .. } => {
                let left_share = Self::decode_share(left)?;
                let right_share = Self::decode_share(right)?;

                let mut node = self.clone_node().await;
                let result_shares = node
                    .mul(vec![left_share], vec![right_share], self.net.clone())
                    .await
                    .map_err(|e| format!("MPC multiplication failed: {:?}", e))?;

                let result_share = result_shares
                    .into_iter()
                    .next()
                    .ok_or_else(|| "Multiplication returned no shares".to_string())?;

                Self::encode_share(&result_share).map(ShareData::Opaque)
            }
        }
    }

    pub async fn open_share_async_impl(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
    ) -> Result<ClearShareValue, String> {
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
        self.broadcast_open_registry_payload(wire_message).await?;

        let required = 2 * self.topology.threshold() + 1;
        let n = self.topology.n_parties();
        let t = self.topology.threshold();

        self.open_registry
            .open_share_async(
                self.topology.party_id(),
                type_key,
                share_bytes.to_vec(),
                required,
                |collected| {
                    let mut shares: Vec<RobustShare<F>> = Vec::with_capacity(collected.len());
                    for bytes in collected {
                        shares.push(Self::decode_share(bytes)?);
                    }

                    let (_deg, secret) = RobustShare::recover_secret(&shares, n, t)
                        .map_err(|e| format!("recover_secret: {:?}", e))?;
                    Self::field_to_clear_share_value(ty, secret)
                },
            )
            .await
    }

    pub async fn batch_open_shares_async_impl(
        &self,
        ty: ShareType,
        shares: &[Vec<u8>],
    ) -> Result<Vec<ClearShareValue>, String> {
        if shares.is_empty() {
            return Ok(Vec::new());
        }

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
        self.broadcast_open_registry_payload(wire_message).await?;

        let required = 2 * self.topology.threshold() + 1;
        let n = self.topology.n_parties();
        let t = self.topology.threshold();

        self.open_registry
            .batch_open_async(
                self.topology.party_id(),
                type_key,
                shares.to_vec(),
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
            .await
    }

    async fn broadcast_open_exp_payload(&self, payload: Vec<u8>) -> Result<(), String> {
        crate::net::broadcast::broadcast_to_other_parties(
            self.net.as_ref(),
            self.topology.n_parties(),
            self.topology.party_id(),
            &payload,
            "Failed to send open-exp payload to party",
        )
        .await
    }

    fn broadcast_open_exp_payload_sync(&self, payload: Vec<u8>) -> Result<(), String> {
        crate::net::block_on_current(self.broadcast_open_exp_payload(payload))
    }

    async fn broadcast_open_registry_payload(&self, payload: Vec<u8>) -> Result<(), String> {
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
        let share = Self::decode_share(share_bytes)?;
        let generator = G::deserialize_compressed(generator_bytes)
            .map_err(|e| format!("deserialize generator: {}", e))?;
        let partial_point = generator * share.share[0];

        let mut partial_bytes = Vec::new();
        partial_point
            .into_affine()
            .serialize_compressed(&mut partial_bytes)
            .map_err(|e| format!("serialize partial point: {}", e))?;

        let wire_message = crate::net::open_registry::encode_hb_open_exp_wire_message(
            self.topology.instance_id(),
            self.topology.party_id(),
            share.id,
            &partial_bytes,
        )?;
        self.broadcast_open_exp_payload_sync(wire_message)?;

        let required = 2 * self.topology.threshold() + 1;
        let n = self.topology.n_parties();
        let domain = GeneralEvaluationDomain::<F>::new(n)
            .ok_or_else(|| "No suitable FFT domain".to_string())?;

        self.open_registry.exp_open_wait(
            ExpOpenRequest {
                kind: ExpOpenRegistryKind::G1,
                party_id: self.topology.party_id(),
                share_id: share.id,
                partial_point: &partial_bytes,
                required,
                timeout_message: "Timeout waiting for open_share_in_exp contributions",
            },
            |partial_points| {
                crate::net::group_interpolation::interpolate_compressed_group_points::<F, G, _>(
                    partial_points,
                    |id| Ok(domain.element(id)),
                    "deserialize partial point",
                    "zero denominator in Lagrange",
                    "serialize result",
                )
            },
        )
    }

    pub async fn open_share_in_exp_async_impl(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
        generator_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        let share = Self::decode_share(share_bytes)?;
        let generator = G::deserialize_compressed(generator_bytes)
            .map_err(|e| format!("deserialize generator: {}", e))?;
        let partial_point = generator * share.share[0];

        let mut partial_bytes = Vec::new();
        partial_point
            .into_affine()
            .serialize_compressed(&mut partial_bytes)
            .map_err(|e| format!("serialize partial point: {}", e))?;

        let wire_message = crate::net::open_registry::encode_hb_open_exp_wire_message(
            self.topology.instance_id(),
            self.topology.party_id(),
            share.id,
            &partial_bytes,
        )?;
        self.broadcast_open_exp_payload(wire_message).await?;

        let required = 2 * self.topology.threshold() + 1;
        let n = self.topology.n_parties();
        let domain = GeneralEvaluationDomain::<F>::new(n)
            .ok_or_else(|| "No suitable FFT domain".to_string())?;

        self.open_registry
            .exp_open_async(
                ExpOpenRequest {
                    kind: ExpOpenRegistryKind::G1,
                    party_id: self.topology.party_id(),
                    share_id: share.id,
                    partial_point: &partial_bytes,
                    required,
                    timeout_message: "Timeout waiting for open_share_in_exp contributions",
                },
                |partial_points| {
                    crate::net::group_interpolation::interpolate_compressed_group_points::<F, G, _>(
                        partial_points,
                        |id| Ok(domain.element(id)),
                        "deserialize partial point",
                        "zero denominator in Lagrange",
                        "serialize result",
                    )
                },
            )
            .await
    }

    pub(super) fn field_to_clear_share_value(
        ty: ShareType,
        secret: F,
    ) -> Result<ClearShareValue, String> {
        crate::net::curve::field_to_clear_share_value(ty, secret).map_err(Into::into)
    }

    pub(super) fn encode_share(share: &RobustShare<F>) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        share
            .serialize_compressed(&mut out)
            .map_err(|e| format!("serialize share: {}", e))?;
        Ok(out)
    }

    pub(super) fn decode_share(bytes: &[u8]) -> Result<RobustShare<F>, String> {
        RobustShare::<F>::deserialize_compressed(bytes)
            .map_err(|e| format!("deserialize share: {}", e))
    }
}
