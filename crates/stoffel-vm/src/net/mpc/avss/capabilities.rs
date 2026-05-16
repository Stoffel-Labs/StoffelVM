use super::{field_from_usize, usize_seed, AvssMpcEngine};
use crate::net::client_store::{
    ClientInputHydrationCount, ClientInputStore, ClientOutputShareCount,
};
use crate::net::curve::{MpcCurveConfig, SupportedMpcField};
use crate::net::mpc_engine::{
    AsyncMpcEngine, AsyncMpcEngineClientOps, MpcEngine, MpcEngineClientOps, MpcEngineClientOutput,
    MpcEngineError, MpcEngineFieldOpen, MpcEngineMultiplication, MpcEngineOpenInExponent,
    MpcEngineOperationResultExt, MpcEnginePreprocPersistence, MpcEngineRandomness, MpcEngineResult,
    MpcExponentGroup,
};
use crate::net::open_registry::{ExpOpenRegistryKind, ExpOpenRequest};
use crate::storage::preproc::PreprocStore;
use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
use std::any::TypeId;
use std::sync::Arc;
use stoffel_vm_types::core_types::{ClearShareInput, ClearShareValue, ShareData, ShareType};
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::common::MPCProtocol;
use stoffelnet::network_utils::ClientId;
use stoffelnet::transports::quic::QuicNetworkManager;

impl<F, G> AvssMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    async fn broadcast_open_avss_exp_payload(&self, payload: Vec<u8>) -> Result<(), String> {
        crate::net::broadcast::broadcast_to_other_parties(
            self.net.as_ref(),
            self.topology.n_parties(),
            self.topology.party_id(),
            &payload,
            "broadcast avss open-exp to",
        )
        .await
    }

    fn broadcast_open_avss_exp_payload_sync(&self, payload: Vec<u8>) -> Result<(), String> {
        crate::net::block_on_current(self.broadcast_open_avss_exp_payload(payload))
    }

    /// Reveal an AVSS share in the exponent: reconstructs `[secret] * generator`
    /// via Lagrange interpolation in the group using integer evaluation points (1, 2, ...).
    ///
    /// Each party computes `share_value * generator`, broadcasts its partial point,
    /// and waits until `t+1` contributions are available.
    fn open_share_in_exp_impl(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
        generator_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        let share = Self::decode_feldman_share(share_bytes)?;
        let generator = G::deserialize_compressed(generator_bytes)
            .map_err(|e| format!("deserialize generator: {}", e))?;

        let share_value = share.feldmanshare.share[0];
        let share_id = share.feldmanshare.id;

        let partial_point = generator * share_value;
        let mut partial_bytes = Vec::new();
        partial_point
            .into_affine()
            .serialize_compressed(&mut partial_bytes)
            .map_err(|e| format!("serialize partial point: {}", e))?;

        let wire_message = crate::net::open_registry::encode_avss_open_exp_wire_message(
            self.topology.instance_id(),
            self.topology.party_id(),
            share_id,
            &partial_bytes,
        )?;
        self.broadcast_open_avss_exp_payload_sync(wire_message)?;

        let required = self.topology.threshold() + 1;
        self.open_registry.exp_open_wait(
            ExpOpenRequest {
                kind: ExpOpenRegistryKind::G1,
                party_id: self.topology.party_id(),
                share_id,
                partial_point: &partial_bytes,
                required,
                timeout_message: "Timeout waiting for AVSS open_share_in_exp contributions",
            },
            |partial_points| {
                crate::net::group_interpolation::interpolate_compressed_group_points::<F, G, _>(
                    partial_points,
                    |id| field_from_usize::<F>(id, "AVSS evaluation point"),
                    "deserialize partial point",
                    "zero denominator in AVSS Lagrange",
                    "serialize result",
                )
            },
        )
    }

    async fn open_share_in_exp_async_impl(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
        generator_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        let share = Self::decode_feldman_share(share_bytes)?;
        let generator = G::deserialize_compressed(generator_bytes)
            .map_err(|e| format!("deserialize generator: {}", e))?;

        let share_value = share.feldmanshare.share[0];
        let share_id = share.feldmanshare.id;

        let partial_point = generator * share_value;
        let mut partial_bytes = Vec::new();
        partial_point
            .into_affine()
            .serialize_compressed(&mut partial_bytes)
            .map_err(|e| format!("serialize partial point: {}", e))?;

        let wire_message = crate::net::open_registry::encode_avss_open_exp_wire_message(
            self.topology.instance_id(),
            self.topology.party_id(),
            share_id,
            &partial_bytes,
        )?;
        self.broadcast_open_avss_exp_payload(wire_message).await?;

        let required = self.topology.threshold() + 1;
        self.open_registry
            .exp_open_async(
                ExpOpenRequest {
                    kind: ExpOpenRegistryKind::G1,
                    party_id: self.topology.party_id(),
                    share_id,
                    partial_point: &partial_bytes,
                    required,
                    timeout_message: "Timeout waiting for AVSS open_share_in_exp contributions",
                },
                |partial_points| {
                    crate::net::group_interpolation::interpolate_compressed_group_points::<F, G, _>(
                        partial_points,
                        |id| field_from_usize::<F>(id, "AVSS evaluation point"),
                        "deserialize partial point",
                        "zero denominator in AVSS Lagrange",
                        "serialize result",
                    )
                },
            )
            .await
    }

    fn open_share_in_exp_bls12381_g2(
        &self,
        share_bytes: &[u8],
        generator_g2_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        use ark_bls12_381::{Fr, G2Projective};
        use ark_ec::CurveGroup as _;
        use ark_serialize::{CanonicalDeserialize as _, CanonicalSerialize as _};

        if F::CURVE_CONFIG != MpcCurveConfig::Bls12_381 {
            return Err(format!(
                "MPC backend '{}' uses {:?}, which cannot open shares in bls12-381-g2",
                self.protocol_name(),
                F::CURVE_CONFIG
            ));
        }

        let share = Self::decode_feldman_share(share_bytes)?;
        let generator_g2 = G2Projective::deserialize_compressed(generator_g2_bytes)
            .map_err(|e| format!("deserialize G2 generator: {}", e))?;

        let mut share_value_bytes = Vec::new();
        share.feldmanshare.share[0]
            .serialize_compressed(&mut share_value_bytes)
            .map_err(|e| format!("serialize BLS12-381 scalar share: {}", e))?;
        let share_value = Fr::deserialize_compressed(&share_value_bytes[..])
            .map_err(|e| format!("deserialize BLS12-381 scalar share: {}", e))?;
        let share_id: usize = share.feldmanshare.id;

        let partial_point: G2Projective = generator_g2 * share_value;
        let mut partial_bytes = Vec::new();
        partial_point
            .into_affine()
            .serialize_compressed(&mut partial_bytes)
            .map_err(|e| format!("serialize G2 partial point: {}", e))?;

        let wire_payload = crate::net::open_registry::encode_avss_g2_open_exp_wire_message(
            self.topology.instance_id(),
            self.topology.party_id(),
            share_id,
            &partial_bytes,
        )?;

        crate::net::block_on_current(crate::net::broadcast::broadcast_to_other_parties(
            self.net.as_ref(),
            self.topology.n_parties(),
            self.topology.party_id(),
            &wire_payload,
            "broadcast avss g2 open-exp to",
        ))?;

        let required = self.topology.threshold() + 1;
        self.open_registry.exp_open_wait(
            ExpOpenRequest {
                kind: ExpOpenRegistryKind::G2,
                party_id: self.topology.party_id(),
                share_id,
                partial_point: &partial_bytes,
                required,
                timeout_message: "Timeout waiting for AVSS G2 open_share_in_exp contributions",
            },
            |partial_points| {
                crate::net::group_interpolation::interpolate_compressed_group_points::<
                    Fr,
                    G2Projective,
                    _,
                >(
                    partial_points,
                    |id| usize_seed(id, "AVSS G2 evaluation point").map(Fr::from),
                    "deserialize G2 partial point",
                    "zero denominator in AVSS G2 Lagrange",
                    "serialize G2 result",
                )
            },
        )
    }

    async fn open_share_in_exp_bls12381_g2_async(
        &self,
        share_bytes: &[u8],
        generator_g2_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        use ark_bls12_381::{Fr, G2Projective};
        use ark_ec::CurveGroup as _;
        use ark_serialize::{CanonicalDeserialize as _, CanonicalSerialize as _};

        if F::CURVE_CONFIG != MpcCurveConfig::Bls12_381 {
            return Err(format!(
                "MPC backend '{}' uses {:?}, which cannot open shares in bls12-381-g2",
                self.protocol_name(),
                F::CURVE_CONFIG
            ));
        }

        let share = Self::decode_feldman_share(share_bytes)?;
        let generator_g2 = G2Projective::deserialize_compressed(generator_g2_bytes)
            .map_err(|e| format!("deserialize G2 generator: {}", e))?;

        let mut share_value_bytes = Vec::new();
        share.feldmanshare.share[0]
            .serialize_compressed(&mut share_value_bytes)
            .map_err(|e| format!("serialize BLS12-381 scalar share: {}", e))?;
        let share_value = Fr::deserialize_compressed(&share_value_bytes[..])
            .map_err(|e| format!("deserialize BLS12-381 scalar share: {}", e))?;
        let share_id: usize = share.feldmanshare.id;

        let partial_point: G2Projective = generator_g2 * share_value;
        let mut partial_bytes = Vec::new();
        partial_point
            .into_affine()
            .serialize_compressed(&mut partial_bytes)
            .map_err(|e| format!("serialize G2 partial point: {}", e))?;

        let wire_payload = crate::net::open_registry::encode_avss_g2_open_exp_wire_message(
            self.topology.instance_id(),
            self.topology.party_id(),
            share_id,
            &partial_bytes,
        )?;

        crate::net::broadcast::broadcast_to_other_parties(
            self.net.as_ref(),
            self.topology.n_parties(),
            self.topology.party_id(),
            &wire_payload,
            "broadcast avss g2 open-exp to",
        )
        .await?;

        let required = self.topology.threshold() + 1;
        self.open_registry
            .exp_open_async(
                ExpOpenRequest {
                    kind: ExpOpenRegistryKind::G2,
                    party_id: self.topology.party_id(),
                    share_id,
                    partial_point: &partial_bytes,
                    required,
                    timeout_message: "Timeout waiting for AVSS G2 open_share_in_exp contributions",
                },
                |partial_points| {
                    crate::net::group_interpolation::interpolate_compressed_group_points::<
                        Fr,
                        G2Projective,
                        _,
                    >(
                        partial_points,
                        |id| usize_seed(id, "AVSS G2 evaluation point").map(Fr::from),
                        "deserialize G2 partial point",
                        "zero denominator in AVSS G2 Lagrange",
                        "serialize G2 result",
                    )
                },
            )
            .await
    }
}

impl<F, G> MpcEngineMultiplication for AvssMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    fn multiply_share(
        &self,
        _ty: ShareType,
        left: &[u8],
        right: &[u8],
    ) -> MpcEngineResult<ShareData> {
        (|| -> Result<ShareData, String> {
            let avss_node = self.avss_node.clone();
            let net = self.net.clone();
            let left_bytes = left.to_vec();
            let right_bytes = right.to_vec();

            let fut = Self::run_multiply_round(avss_node, net, left_bytes, right_bytes);

            match tokio::runtime::Handle::try_current() {
                Ok(handle) => {
                    #[allow(deprecated)]
                    let runtime_flavor = handle.runtime_flavor();
                    match runtime_flavor {
                        tokio::runtime::RuntimeFlavor::MultiThread => {
                            tokio::task::block_in_place(|| handle.block_on(fut))
                        }
                        tokio::runtime::RuntimeFlavor::CurrentThread => {
                            std::thread::spawn(move || {
                                let rt = tokio::runtime::Builder::new_current_thread()
                                    .enable_all()
                                    .build()
                                    .map_err(|e| format!("failed to create Tokio runtime: {e}"))?;
                                rt.block_on(fut)
                            })
                            .join()
                            .map_err(|_| "AVSS multiply worker thread panicked".to_string())?
                        }
                        _ => Err("operation requires a multi-thread Tokio runtime".to_string()),
                    }
                }
                Err(_) => {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| format!("failed to create Tokio runtime: {e}"))?;
                    rt.block_on(fut)
                }
            }
        })()
        .map_mpc_engine_operation("multiply_share")
    }
}

impl<F, G> MpcEnginePreprocPersistence for AvssMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    fn set_preproc_store(
        &self,
        store: Arc<dyn PreprocStore>,
        program_hash: [u8; 32],
    ) -> MpcEngineResult<()> {
        let field_kind = self.curve_config().field_kind();
        crate::net::try_block_on_current(async {
            *self.preproc_store.write().await = Some(store);
            *self.preproc_config.write().await = Some((program_hash, field_kind));
            Ok(())
        })
        .map_mpc_engine_operation("set_preproc_store")
    }
}

impl<F, G> MpcEngineFieldOpen for AvssMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    fn open_share_as_field(&self, ty: ShareType, share_bytes: &[u8]) -> MpcEngineResult<Vec<u8>> {
        (|| -> Result<Vec<u8>, String> {
            let type_key = match ty {
                ShareType::SecretInt { bit_length } => format!("avss-field-int-{bit_length}"),
                ShareType::SecretFixedPoint { precision } => {
                    format!("avss-field-fixed-{}-{}", precision.k(), precision.f())
                }
            };

            let wire_message = crate::net::open_registry::encode_single_share_wire_message(
                self.topology.instance_id(),
                &type_key,
                self.topology.party_id(),
                share_bytes,
            )?;
            self.broadcast_open_registry_payload_sync(wire_message)?;

            let n = self.topology.n_parties();
            let t = self.topology.threshold();
            let required = Self::byzantine_open_contribution_count(n, t)?;

            self.open_registry.open_bytes_wait(
                self.topology.party_id(),
                &type_key,
                share_bytes,
                required,
                |collected| {
                    let secret = Self::reconstruct_verified_secret(
                        share_bytes,
                        collected,
                        n,
                        t,
                        "AVSS open_share_as_field",
                    )?;
                    let mut out = Vec::new();
                    secret
                        .serialize_compressed(&mut out)
                        .map_err(|e| format!("serialize field element: {}", e))?;
                    Ok(out)
                },
            )
        })()
        .map_mpc_engine_operation("open_share_as_field")
    }
}

impl<F, G> MpcEngineRandomness for AvssMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    fn random_share(&self, _ty: ShareType) -> MpcEngineResult<ShareData> {
        (|| -> Result<ShareData, String> {
            let share = crate::net::block_on_current(async {
                let mut node_clone = self.clone_avss_node().await;
                MPCProtocol::<F, FeldmanShamirShare<F, G>, QuicNetworkManager>::rand(
                    &mut node_clone,
                    self.net.clone(),
                )
                .await
                .map_err(|e| format!("random_share (multi-dealer RanSha) failed: {:?}", e))
            })?;
            Self::share_to_share_data(&share)
        })()
        .map_mpc_engine_operation("random_share")
    }
}

impl<F, G> MpcEngineOpenInExponent for AvssMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    fn open_share_in_exp(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        generator_bytes: &[u8],
    ) -> MpcEngineResult<Vec<u8>> {
        self.open_share_in_exp_impl(ty, share_bytes, generator_bytes)
            .map_mpc_engine_operation("open_share_in_exp")
    }

    fn native_exponent_group(&self) -> MpcExponentGroup {
        if TypeId::of::<G>() == TypeId::of::<ark_bls12_381::G1Projective>() {
            MpcExponentGroup::Bls12381G1
        } else if TypeId::of::<G>() == TypeId::of::<ark_bn254::G1Projective>() {
            MpcExponentGroup::Bn254G1
        } else if TypeId::of::<G>() == TypeId::of::<ark_curve25519::EdwardsProjective>() {
            MpcExponentGroup::Curve25519Edwards
        } else if TypeId::of::<G>() == TypeId::of::<ark_ed25519::EdwardsProjective>() {
            MpcExponentGroup::Ed25519Edwards
        } else {
            MpcExponentGroup::native_for_curve(self.curve_config())
        }
    }

    fn supports_exponent_group(&self, group: MpcExponentGroup) -> bool {
        match group {
            MpcExponentGroup::Bls12381G2 => TypeId::of::<F>() == TypeId::of::<ark_bls12_381::Fr>(),
            _ => self.native_exponent_group() == group,
        }
    }

    fn open_share_in_exp_group(
        &self,
        group: MpcExponentGroup,
        ty: ShareType,
        share_bytes: &[u8],
        generator_bytes: &[u8],
    ) -> MpcEngineResult<Vec<u8>> {
        if !self.supports_exponent_group(group) {
            return Err(MpcEngineError::operation_failed(
                "open_share_in_exp_group",
                group.unsupported_error(self.protocol_name()),
            ));
        }

        let result = match group {
            MpcExponentGroup::Bls12381G2 => {
                self.open_share_in_exp_bls12381_g2(share_bytes, generator_bytes)
            }
            _ => self.open_share_in_exp_impl(ty, share_bytes, generator_bytes),
        };

        result.map_mpc_engine_operation("open_share_in_exp_group")
    }
}

impl<F, G> MpcEngineClientOutput for AvssMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    fn send_output_to_client(
        &self,
        client_id: ClientId,
        shares: &[u8],
        output_share_count: ClientOutputShareCount,
    ) -> MpcEngineResult<()> {
        crate::net::try_block_on_current(self.send_output_to_client_async_impl(
            client_id,
            shares,
            output_share_count,
        ))
        .map_mpc_engine_operation("send_output_to_client")
    }
}

impl<F, G> MpcEngineClientOps for AvssMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    fn get_client_ids_sync(&self) -> Vec<ClientId> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                #[allow(deprecated)]
                let runtime_flavor = handle.runtime_flavor();
                match runtime_flavor {
                    tokio::runtime::RuntimeFlavor::MultiThread => {
                        tokio::task::block_in_place(|| handle.block_on(self.get_client_ids()))
                    }
                    _ => Vec::new(),
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

    fn hydrate_client_inputs_sync(
        &self,
        store: &ClientInputStore,
    ) -> MpcEngineResult<ClientInputHydrationCount> {
        crate::net::try_block_on_current(self.hydrate_client_inputs(store))
            .map_mpc_engine_operation("hydrate_client_inputs_sync")
    }

    fn hydrate_client_inputs_for_sync(
        &self,
        store: &ClientInputStore,
        client_ids: &[ClientId],
    ) -> MpcEngineResult<ClientInputHydrationCount> {
        crate::net::try_block_on_current(self.hydrate_client_inputs_for(store, client_ids))
            .map_mpc_engine_operation("hydrate_client_inputs_for_sync")
    }
}

#[async_trait::async_trait]
impl<F, G> AsyncMpcEngineClientOps for AvssMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    async fn get_client_ids_async(&self) -> Vec<ClientId> {
        self.get_client_ids().await
    }

    async fn hydrate_client_inputs_async(
        &self,
        store: &ClientInputStore,
    ) -> MpcEngineResult<ClientInputHydrationCount> {
        self.hydrate_client_inputs(store)
            .await
            .map_mpc_engine_operation("hydrate_client_inputs_async")
    }

    async fn hydrate_client_inputs_for_async(
        &self,
        store: &ClientInputStore,
        client_ids: &[ClientId],
    ) -> MpcEngineResult<ClientInputHydrationCount> {
        self.hydrate_client_inputs_for(store, client_ids)
            .await
            .map_mpc_engine_operation("hydrate_client_inputs_for_async")
    }
}

#[async_trait::async_trait]
impl<F, G> AsyncMpcEngine for AvssMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    fn as_async_client_ops(&self) -> Option<&dyn AsyncMpcEngineClientOps> {
        Some(self)
    }

    async fn input_share_async(&self, clear: ClearShareInput) -> MpcEngineResult<ShareData> {
        async {
            let secret = Self::clear_input_to_field(clear)?;
            let (dealer_id, session_id) = self.allocate_input_share_session()?;
            let share = self
                .run_input_share_round(dealer_id, session_id, secret)
                .await?;
            Self::share_to_share_data(&share)
        }
        .await
        .map_mpc_engine_operation("async_input_share")
    }

    async fn multiply_share_async(
        &self,
        _ty: ShareType,
        left: &[u8],
        right: &[u8],
    ) -> MpcEngineResult<ShareData> {
        Self::run_multiply_round(
            self.avss_node.clone(),
            self.net.clone(),
            left.to_vec(),
            right.to_vec(),
        )
        .await
        .map_mpc_engine_operation("async_multiply_share")
    }

    async fn open_share_async(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
    ) -> MpcEngineResult<ClearShareValue> {
        async {
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
            self.broadcast_open_registry_payload(wire_message).await?;

            let n = self.topology.n_parties();
            let t = self.topology.threshold();
            let required = Self::byzantine_open_contribution_count(n, t)?;

            self.open_registry
                .open_share_async(
                    self.topology.party_id(),
                    type_key,
                    share_bytes.to_vec(),
                    required,
                    |collected| {
                        let secret = Self::reconstruct_verified_secret(
                            share_bytes,
                            collected,
                            n,
                            t,
                            "AVSS async_open_share",
                        )?;
                        Self::field_to_clear_share_value(ty, secret)
                    },
                )
                .await
        }
        .await
        .map_mpc_engine_operation("async_open_share")
    }

    async fn batch_open_shares_async(
        &self,
        ty: ShareType,
        shares: &[Vec<u8>],
    ) -> MpcEngineResult<Vec<ClearShareValue>> {
        async {
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
            self.broadcast_open_registry_payload(wire_message).await?;

            let n = self.topology.n_parties();
            let t = self.topology.threshold();
            let required = Self::byzantine_open_contribution_count(n, t)?;

            self.open_registry
                .batch_open_async(
                    self.topology.party_id(),
                    type_key,
                    shares.to_vec(),
                    required,
                    |collected, pos| {
                        let expected_share = shares.get(pos).ok_or_else(|| {
                            format!(
                                "AVSS async_batch_open_shares missing local share at position {pos}"
                            )
                        })?;
                        let secret = Self::reconstruct_verified_secret(
                            expected_share,
                            collected,
                            n,
                            t,
                            &format!("AVSS async_batch_open_shares pos {pos}"),
                        )?;
                        Self::field_to_clear_share_value(ty, secret)
                    },
                )
                .await
        }
        .await
        .map_mpc_engine_operation("async_batch_open_shares")
    }

    async fn random_share_async(&self, _ty: ShareType) -> MpcEngineResult<ShareData> {
        async {
            let mut node_clone = self.clone_avss_node().await;
            let share = MPCProtocol::<F, FeldmanShamirShare<F, G>, QuicNetworkManager>::rand(
                &mut node_clone,
                self.net.clone(),
            )
            .await
            .map_err(|e| format!("random_share (multi-dealer RanSha) failed: {:?}", e))?;
            Self::share_to_share_data(&share)
        }
        .await
        .map_mpc_engine_operation("async_random_share")
    }

    async fn open_share_as_field_async(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
    ) -> MpcEngineResult<Vec<u8>> {
        async {
            let type_key = match ty {
                ShareType::SecretInt { bit_length } => format!("avss-field-int-{bit_length}"),
                ShareType::SecretFixedPoint { precision } => {
                    format!("avss-field-fixed-{}-{}", precision.k(), precision.f())
                }
            };

            let wire_message = crate::net::open_registry::encode_single_share_wire_message(
                self.topology.instance_id(),
                &type_key,
                self.topology.party_id(),
                share_bytes,
            )?;
            self.broadcast_open_registry_payload(wire_message).await?;

            let n = self.topology.n_parties();
            let t = self.topology.threshold();
            let required = Self::byzantine_open_contribution_count(n, t)?;

            self.open_registry
                .open_bytes_async(
                    self.topology.party_id(),
                    type_key,
                    share_bytes.to_vec(),
                    required,
                    |collected| {
                        let secret = Self::reconstruct_verified_secret(
                            share_bytes,
                            collected,
                            n,
                            t,
                            "AVSS async_open_share_as_field",
                        )?;
                        let mut out = Vec::new();
                        secret
                            .serialize_compressed(&mut out)
                            .map_err(|e| format!("serialize field element: {}", e))?;
                        Ok(out)
                    },
                )
                .await
        }
        .await
        .map_mpc_engine_operation("async_open_share_as_field")
    }

    async fn open_share_in_exp_async(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        generator_bytes: &[u8],
    ) -> MpcEngineResult<Vec<u8>> {
        self.open_share_in_exp_async_impl(ty, share_bytes, generator_bytes)
            .await
            .map_mpc_engine_operation("async_open_share_in_exp")
    }

    async fn open_share_in_exp_group_async(
        &self,
        group: MpcExponentGroup,
        ty: ShareType,
        share_bytes: &[u8],
        generator_bytes: &[u8],
    ) -> MpcEngineResult<Vec<u8>> {
        if !self.supports_exponent_group(group) {
            return Err(MpcEngineError::operation_failed(
                "async_open_share_in_exp_group",
                group.unsupported_error(self.protocol_name()),
            ));
        }

        let result = match group {
            MpcExponentGroup::Bls12381G2 => {
                self.open_share_in_exp_bls12381_g2_async(share_bytes, generator_bytes)
                    .await
            }
            _ => {
                self.open_share_in_exp_async_impl(ty, share_bytes, generator_bytes)
                    .await
            }
        };

        result.map_mpc_engine_operation("async_open_share_in_exp_group")
    }

    async fn send_output_to_client_async(
        &self,
        client_id: ClientId,
        shares: &[u8],
        output_share_count: ClientOutputShareCount,
    ) -> MpcEngineResult<()> {
        self.send_output_to_client_async_impl(client_id, shares, output_share_count)
            .await
            .map_mpc_engine_operation("async_send_output_to_client")
    }
}
