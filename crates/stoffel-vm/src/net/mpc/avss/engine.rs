use super::{AvssExecutionNetwork, AvssMpcEngine};
use crate::net::curve::{MpcCurveConfig, SupportedMpcField};
use crate::net::mpc_engine::{
    DurableIdentityDigest, MpcCapabilities, MpcEngine, MpcEngineClientOps, MpcEngineClientOutput,
    MpcEngineFieldOpen, MpcEngineMultiplication, MpcEngineOpenInExponent,
    MpcEngineOperationResultExt, MpcEnginePreprocPersistence, MpcEngineRandomness,
    MpcSessionTopology,
};
use ark_ec::CurveGroup;
use std::any::TypeId;
use std::sync::{atomic::Ordering, Arc};
use stoffel_vm_types::core_types::{
    ClearShareInput, ClearShareValue, ShareData, ShareType, BOOLEAN_SECRET_INT_BITS,
};
use stoffelmpc_mpc::avss_mpc::triple_gen::BeaverTriple;
use stoffelmpc_mpc::avss_mpc::{AvssMPCNode as AvssMpcNode, AvssSessionId};
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::common::MPCProtocol;
use tokio::sync::Mutex;
use tracing::info;

impl<F, G> AvssMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    #[cfg(all(test, feature = "avss_itest"))]
    pub(crate) async fn active_multiplication_session_count(&self) -> usize {
        let node = self.avss_node.lock().await;
        let count = node.mul_node.mult_storage.lock().await.len();
        count
    }

    pub(super) fn clear_input_to_field(clear: ClearShareInput) -> Result<F, String> {
        match clear.into_parts() {
            (ShareType::SecretInt { .. }, ClearShareValue::Integer(v)) => {
                Ok(Self::field_from_i64(v))
            }
            (ShareType::SecretUInt { .. }, ClearShareValue::UnsignedInteger(v)) => {
                Ok(crate::net::curve::field_from_u64::<F>(v))
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

    /// Build the local share of a PUBLIC constant, with no network round.
    ///
    /// A clear input has no secret to protect, so it needs no AVSS dealing:
    /// the constant polynomial `f(x) = value` written as a degree-`t` sharing
    /// (all non-constant coefficients zero) gives every party the share `value`
    /// at its own evaluation point, with Feldman commitments
    /// `[value*G, 0, .., 0]`. This verifies under `verify_feldman`, adds and
    /// Beaver-multiplies like any degree-`t` sharing, and reconstructs to
    /// `value` — mirroring the HoneyBadger engine's local `input_share`.
    ///
    /// Do NOT replace this with a runtime AVSS dealing: preprocessing already
    /// consumes the low `(ProtocolType::Avss, dealer, exec/round)` session
    /// slots, so a runtime dealing allocated from a fresh counter collides
    /// with an ended preprocessing session and the RBC layer silently drops it
    /// (the original from_clear timeout).
    pub(super) async fn local_constant_share(
        &self,
        value: F,
    ) -> Result<FeldmanShamirShare<F, G>, String> {
        let node = self.clone_avss_node().await;
        let avss = &node.share_gen_avss.avss;
        let share_id = *avss
            .ids
            .get(avss.id)
            .ok_or_else(|| format!("AVSS party index {} missing from share ids", avss.id))?;
        let threshold = self.topology.threshold();
        let mut commitments = vec![G::zero(); threshold + 1];
        commitments[0] = G::generator().mul(value);
        FeldmanShamirShare::new(value, share_id, threshold, commitments)
            .map_err(|e| format!("constant share construction failed: {:?}", e))
    }

    pub(super) async fn run_multiply_round(
        avss_node: Arc<Mutex<AvssMpcNode<F, Avid<AvssSessionId>, G>>>,
        net: Arc<AvssExecutionNetwork>,
        left_share_bytes: Vec<u8>,
        right_share_bytes: Vec<u8>,
    ) -> Result<ShareData, String> {
        let left_share = Self::decode_feldman_share(&left_share_bytes)?;
        let right_share = Self::decode_feldman_share(&right_share_bytes)?;

        let mut node = {
            let node = avss_node.lock().await;
            node.clone()
        };
        Self::ensure_multiply_preprocessing_ids(&mut node, net.clone()).await?;
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

    pub(super) async fn run_batch_multiply_round(
        avss_node: Arc<Mutex<AvssMpcNode<F, Avid<AvssSessionId>, G>>>,
        net: Arc<AvssExecutionNetwork>,
        pairs: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<Vec<ShareData>, String> {
        if pairs.is_empty() {
            return Ok(Vec::new());
        }
        let mut left_shares = Vec::with_capacity(pairs.len());
        let mut right_shares = Vec::with_capacity(pairs.len());
        for (left, right) in pairs {
            left_shares.push(Self::decode_feldman_share(&left)?);
            right_shares.push(Self::decode_feldman_share(&right)?);
        }

        let mut node = {
            let node = avss_node.lock().await;
            node.clone()
        };
        Self::ensure_multiply_preprocessing_ids(&mut node, net.clone()).await?;
        node.mul(left_shares, right_shares, net)
            .await
            .map_err(|e| format!("Batch multiplication failed: {:?}", e))?
            .iter()
            .map(Self::share_to_share_data)
            .collect()
    }

    /// Execute one native vectorized AVSS multiplication session for all
    /// supplied pairs. This is the async implementation shared by the async
    /// engine capability and its synchronous compatibility adapter.
    pub(crate) async fn batch_multiply_share_async(
        &self,
        pairs: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<Vec<ShareData>, String> {
        let pairs = pairs.to_vec();
        if self.is_standing() {
            self.run_standing_batch_multiply_round(pairs).await
        } else {
            Self::run_batch_multiply_round(self.avss_node.clone(), self.protocol_net.clone(), pairs)
                .await
        }
    }

    pub(super) async fn run_standing_multiply_round(
        &self,
        left_share_bytes: Vec<u8>,
        right_share_bytes: Vec<u8>,
    ) -> Result<ShareData, String> {
        let left_share = Self::decode_feldman_share(&left_share_bytes)?;
        let right_share = Self::decode_feldman_share(&right_share_bytes)?;
        let mut node = self.clone_avss_node().await;
        let available = node.preprocessing_material.lock().await.len().0;
        if available < 1 {
            return Err("not enough AVSS Beaver triples: need 1, available 0".to_owned());
        }
        let result = node
            .mul(
                vec![left_share],
                vec![right_share],
                self.protocol_net.clone(),
            )
            .await
            .map_err(|e| format!("Multiplication failed: {:?}", e))?;

        let product = result
            .into_iter()
            .next()
            .ok_or_else(|| "Multiplication returned no result".to_string())?;
        Self::share_to_share_data(&product)
    }

    pub(super) async fn run_standing_batch_multiply_round(
        &self,
        pairs: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<Vec<ShareData>, String> {
        if pairs.is_empty() {
            return Ok(Vec::new());
        }
        let mut left_shares = Vec::with_capacity(pairs.len());
        let mut right_shares = Vec::with_capacity(pairs.len());
        for (left, right) in pairs {
            left_shares.push(Self::decode_feldman_share(&left)?);
            right_shares.push(Self::decode_feldman_share(&right)?);
        }
        let mut node = self.clone_avss_node().await;
        let required = left_shares.len();
        let available = node.preprocessing_material.lock().await.len().0;
        if available < required {
            return Err(format!(
                "not enough AVSS Beaver triples: need {required}, available {available}"
            ));
        }
        node.mul(left_shares, right_shares, self.protocol_net.clone())
            .await
            .map_err(|e| format!("Batch multiplication failed: {:?}", e))?
            .iter()
            .map(Self::share_to_share_data)
            .collect()
    }

    async fn ensure_multiply_preprocessing_ids(
        node: &mut AvssMpcNode<F, Avid<AvssSessionId>, G>,
        net: Arc<AvssExecutionNetwork>,
    ) -> Result<(), String> {
        let mut triple_count = {
            let store = node.preprocessing_material.lock().await;
            store.len().0
        };

        if triple_count == 0 {
            MPCProtocol::<F, FeldmanShamirShare<F, G>, AvssExecutionNetwork>::rand(node, net)
                .await
                .map_err(|e| format!("preprocess multiplication material failed: {:?}", e))?;
            triple_count = {
                let store = node.preprocessing_material.lock().await;
                store.len().0
            };
        }

        if triple_count == 0 {
            return Ok(());
        }

        let mut triples = {
            let mut store = node.preprocessing_material.lock().await;
            store
                .take_triples(triple_count)
                .map_err(|e| format!("take multiplication triples: {:?}", e))?
        };

        Self::normalize_multiply_triples(&mut triples);

        let mut store = node.preprocessing_material.lock().await;
        store.add(Some(triples), None);
        Ok(())
    }

    pub(super) fn normalize_multiply_triples(triples: &mut [BeaverTriple<F, G>]) {
        for triple in triples {
            // mpc-protocols builds the triple c-share with a 0-based party id,
            // while AVSS/Feldman shares are evaluated at 1-based ids.
            let share_id = triple.a.feldmanshare.id;
            triple.c.feldmanshare.id = share_id;
        }
    }

    pub(super) async fn broadcast_open_registry_payload(
        &self,
        payload: Vec<u8>,
    ) -> Result<(), String> {
        crate::net::broadcast::broadcast_to_other_parties(
            self.protocol_net.as_ref(),
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
            self.current_instance_id(),
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
        AvssMpcEngine::topology(self)
    }

    fn local_identity(&self) -> DurableIdentityDigest {
        self.local_identity
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
            let share = crate::net::block_on_current(self.local_constant_share(secret))?;
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
                ShareType::SecretUInt { bit_length } => format!("avss-uint-{bit_length}"),
                ShareType::SecretFixedPoint { precision } => {
                    format!("avss-fixed-{}-{}", precision.k(), precision.f())
                }
            };

            let seq = self.open_registry().insert_single_next(
                &type_key,
                self.topology.party_id(),
                share_bytes.to_vec(),
            )?;
            let wire_message = crate::net::open_registry::encode_single_share_wire_message(
                self.current_instance_id(),
                seq,
                &type_key,
                self.topology.party_id(),
                share_bytes,
            )?;
            self.broadcast_open_registry_payload_sync(wire_message)?;

            let n = self.topology.n_parties();
            let t = self.topology.threshold();
            let required = Self::byzantine_open_contribution_count(n, t)?;

            self.open_registry().open_share_at_wait(
                self.topology.party_id(),
                &type_key,
                seq,
                share_bytes,
                required,
                |collected| {
                    let secret = Self::reconstruct_verified_secret(
                        share_bytes,
                        collected,
                        n,
                        t,
                        "AVSS open_share",
                    )?;
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
                ShareType::SecretUInt { bit_length } => format!("avss-batch-uint-{bit_length}"),
                ShareType::SecretFixedPoint { precision } => {
                    format!("avss-batch-fixed-{}-{}", precision.k(), precision.f())
                }
            };

            let seq = self.open_registry().insert_batch_next(
                &type_key,
                self.topology.party_id(),
                shares.to_vec(),
            )?;
            let wire_message = crate::net::open_registry::encode_batch_share_wire_message(
                self.current_instance_id(),
                seq,
                &type_key,
                self.topology.party_id(),
                shares,
            )?;
            self.broadcast_open_registry_payload_sync(wire_message)?;

            let n = self.topology.n_parties();
            let t = self.topology.threshold();
            let required = Self::byzantine_open_contribution_count(n, t)?;

            self.open_registry().batch_open_at_wait(
                self.topology.party_id(),
                &type_key,
                seq,
                shares,
                required,
                |collected, pos| {
                    let expected_share = shares.get(pos).ok_or_else(|| {
                        format!("AVSS batch_open_shares missing local share at position {pos}")
                    })?;
                    let secret = Self::reconstruct_verified_secret(
                        expected_share,
                        collected,
                        n,
                        t,
                        &format!("AVSS batch_open_shares pos {pos}"),
                    )?;
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
        } else if TypeId::of::<G>() == TypeId::of::<ark_secp256k1::Projective>() {
            MpcCurveConfig::Secp256k1
        } else if TypeId::of::<G>() == TypeId::of::<ark_secp256r1::Projective>() {
            MpcCurveConfig::Secp256r1
        } else {
            F::CURVE_CONFIG
        }
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
