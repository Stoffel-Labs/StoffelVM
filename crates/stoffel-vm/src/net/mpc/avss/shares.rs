use super::{field_from_usize, usize_seed, AvssMpcEngine};
use ark_ec::CurveGroup;
use ark_ff::{FftField, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use stoffel_vm_types::core_types::{ClearShareValue, ShareData, ShareType};
use stoffelmpc_mpc::avss_mpc::AvssSessionId;
use stoffelmpc_mpc::common::share::avss::verify_feldman;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::common::{MPCProtocol, ProtocolSessionId, SecretSharingScheme};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct AvssExpDleqProof {
    base_nonce: Vec<u8>,
    generator_nonce: Vec<u8>,
    response: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct AvssExpContribution {
    pub(super) partial_point: Vec<u8>,
    pub(super) dleq_proof: AvssExpDleqProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct AvssG2ExpContribution {
    pub(super) partial_point: Vec<u8>,
}

/// Verify a Feldman share against its own embedded evaluation id.
///
/// `stoffelcrypto` 0.1.1 added an `expected_id` argument to
/// [`verify_feldman`] so protocol code can bind a share to the party that
/// is supposed to hold it. The helpers in this module operate on shares whose
/// origin is already fixed by the caller (the local share, or peer shares whose
/// commitments must match the local ones), so we bind to the id carried in the
/// share itself, preserving the pre-0.1.1 semantics.
pub(super) fn verify_feldman_self<F: FftField, G: CurveGroup<ScalarField = F>>(
    share: &FeldmanShamirShare<F, G>,
) -> bool {
    let expected_id = share.feldmanshare.id;
    verify_feldman(share.clone(), expected_id)
}

impl<F, G> AvssMpcEngine<F, G>
where
    F: FftField + PrimeField + UniformRand + Send + Sync + 'static,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    /// Generate a new random AVSS share and store it under the given key name.
    ///
    /// The `key_name` must be the same across all parties so they can
    /// coordinate retrieval later. This party initiates the AVSS protocol
    /// with a randomly generated secret.
    pub async fn generate_random_share(
        &self,
        key_name: &str,
    ) -> Result<FeldmanShamirShare<F, G>, String> {
        self.generate_random_share_with_network(key_name, self.net.clone())
            .await
    }

    /// Like `generate_random_share`, but uses a custom `Network` implementation.
    ///
    /// This is useful when the network's `send(party_id, msg)` routing differs
    /// from party-id-based indexing (e.g. stoffelnet's sender_id system).
    pub async fn generate_random_share_with_network<
        N: stoffelnet::network_utils::Network + Send + Sync + 'static,
    >(
        &self,
        key_name: &str,
        net: Arc<N>,
    ) -> Result<FeldmanShamirShare<F, G>, String> {
        if !self.ready.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("AVSS engine not ready".into());
        }

        // The public engine API is dealer-driven: one caller generates a fresh
        // secret and distributes Feldman-verifiable shares to the other parties.
        // The inner `rand()` path is cooperative preprocessing and requires every
        // party to start the round locally, which is not how this API is used.
        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        let secret = F::rand(&mut rng);
        self.generate_share_with_secret_and_network(key_name, secret, net)
            .await
    }

    /// Generate an AVSS share for a specific secret and store under the given key name.
    pub async fn generate_share_with_secret(
        &self,
        key_name: &str,
        secret: F,
    ) -> Result<FeldmanShamirShare<F, G>, String> {
        self.generate_share_with_secret_and_network(key_name, secret, self.net.clone())
            .await
    }

    /// Like `generate_share_with_secret`, but uses a custom `Network` implementation.
    pub async fn generate_share_with_secret_and_network<
        N: stoffelnet::network_utils::Network + Send + Sync + 'static,
    >(
        &self,
        key_name: &str,
        secret: F,
        net: Arc<N>,
    ) -> Result<FeldmanShamirShare<F, G>, String> {
        if !self.ready.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("AVSS engine not ready".into());
        }

        let session_id = self.session_ids.next_dealer_session()?;

        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        let mut node = self.clone_avss_node().await;
        node.share_gen_avss
            .avss
            .init(vec![secret], session_id, &mut rng, net)
            .await
            .map_err(|e| format!("AVSS init failed: {:?}", e))?;

        info!(
            "AVSS share generation initiated: party={}, key='{}', session={}",
            self.topology.party_id(),
            key_name,
            session_id.as_u128()
        );

        let share = self.wait_for_share(session_id).await?;

        {
            let mut shares = self.stored_shares.lock().await;
            shares.insert(key_name.to_string(), share.clone());
        }

        Ok(share)
    }

    /// Wait for a share from a specific session.
    ///
    /// Uses `share_notify` to wake immediately when `process_wrapped_message`
    /// delivers new data, instead of polling with a fixed sleep interval.
    pub(super) async fn wait_for_share(
        &self,
        session_id: AvssSessionId,
    ) -> Result<FeldmanShamirShare<F, G>, String> {
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(30);

        loop {
            let notified = self.share_notify.notified();

            {
                let mut node = self.clone_avss_node().await;
                // Drain any pending RBC completions before checking: the AVID
                // completion send races the per-message drain in
                // `AvssMPCNode::process`, and once the last message of a round
                // has been processed no further traffic would ever drain it —
                // a waiter must pump the queue itself or hang until timeout.
                if let Err(e) = node.share_gen_avss.avss.drain_rbc_output().await {
                    tracing::warn!("wait_for_share: drain_rbc_output failed: {e:?}");
                }
                let shares = node.share_gen_avss.avss.shares.lock().await;
                if let Some((_, Some(share_vec))) = shares.get(&session_id) {
                    if let Some(share) = share_vec.first() {
                        return Ok(share.clone());
                    }
                }
            }

            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(format!(
                        "Timeout waiting for AVSS share: session={}",
                        session_id.as_u128()
                    ));
                }
            }
        }
    }

    /// Wait for a received share (non-dealer path) and store it under the given key name.
    ///
    /// Non-dealer parties receive shares via `process_wrapped_message`, which stores them
    /// in the inner AVSS shares store. This method waits (via `share_notify`) for any
    /// completed share not yet stored in `stored_shares`, stores it under `key_name`,
    /// and returns it.
    pub async fn await_received_share(
        &self,
        key_name: &str,
    ) -> Result<FeldmanShamirShare<F, G>, String> {
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(30);

        loop {
            let notified = self.share_notify.notified();

            {
                let node = self.clone_avss_node().await;
                let shares = node.share_gen_avss.avss.shares.lock().await;
                let stored = self.stored_shares.lock().await;

                for share_vec in shares.values().filter_map(|(_, v)| v.as_ref()) {
                    if let Some(share) = share_vec.first() {
                        let already_stored = stored
                            .values()
                            .any(|s| s.feldmanshare.share == share.feldmanshare.share);
                        if !already_stored {
                            let share = share.clone();
                            drop(stored);
                            drop(shares);
                            drop(node);
                            let mut stored = self.stored_shares.lock().await;
                            stored.insert(key_name.to_string(), share.clone());
                            return Ok(share);
                        }
                    }
                }
            }

            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(format!(
                        "Timeout waiting for received share for key '{}'",
                        key_name
                    ));
                }
            }
        }
    }

    /// Retrieve a stored Feldman share by key name.
    pub async fn get_share(&self, key_name: &str) -> Option<FeldmanShamirShare<F, G>> {
        let shares = self.stored_shares.lock().await;
        shares.get(key_name).cloned()
    }

    /// Get the public key (commitment[0]) for a stored share.
    pub async fn get_public_key(&self, key_name: &str) -> Option<G> {
        self.get_share(key_name).await.map(|s| s.commitments[0])
    }

    /// Get public key bytes for a stored share.
    pub async fn get_public_key_bytes(&self, key_name: &str) -> Result<Vec<u8>, String> {
        let share = self
            .get_share(key_name)
            .await
            .ok_or_else(|| format!("Key '{}' not found", key_name))?;
        Self::encode_group_element(&share.commitments[0])
    }

    /// Process an incoming wire-format message via the AVSS protocol node.
    ///
    /// The node handles all message routing internally (RBC, AVSS, multiplication).
    /// Callers should pass the raw bytes received from the network to this method.
    pub async fn process_wrapped_message(
        &self,
        sender_id: usize,
        data: &[u8],
    ) -> Result<(), String> {
        self.process_wrapped_message_with_network(sender_id, data, self.net.clone())
            .await
    }

    /// Like `process_wrapped_message`, but uses a custom `Network` implementation
    /// for protocol responses.
    pub async fn process_wrapped_message_with_network<
        N: stoffelnet::network_utils::Network + Send + Sync + 'static,
    >(
        &self,
        sender_id: usize,
        data: &[u8],
        net: Arc<N>,
    ) -> Result<(), String> {
        let mut node = self.clone_avss_node().await;
        let result = node
            .process(sender_id, data.to_vec(), net)
            .await
            .map_err(|e| format!("AVSS process failed: {:?}", e));
        self.share_notify.notify_waiters();
        result
    }

    /// Helper: encode a group element to bytes.
    pub fn encode_group_element(g: &G) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        g.serialize_compressed(&mut bytes)
            .map_err(|e| format!("Serialization failed: {:?}", e))?;
        Ok(bytes)
    }

    /// Helper: decode a group element from bytes.
    pub fn decode_group_element(bytes: &[u8]) -> Result<G, String> {
        G::deserialize_compressed(bytes).map_err(|e| format!("Deserialization failed: {:?}", e))
    }

    /// Encode a FeldmanShamirShare to bytes using CanonicalSerialize.
    pub fn encode_feldman_share(share: &FeldmanShamirShare<F, G>) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        share
            .serialize_compressed(&mut out)
            .map_err(|e| format!("serialize FeldmanShamirShare: {}", e))?;
        Ok(out)
    }

    /// Decode a FeldmanShamirShare from bytes using CanonicalDeserialize.
    pub fn decode_feldman_share(bytes: &[u8]) -> Result<FeldmanShamirShare<F, G>, String> {
        FeldmanShamirShare::<F, G>::deserialize_compressed(bytes)
            .map_err(|e| format!("deserialize FeldmanShamirShare: {}", e))
    }

    fn serialize_group_point(point: G, context: &str) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        point
            .into_affine()
            .serialize_compressed(&mut bytes)
            .map_err(|e| format!("{context}: {e}"))?;
        Ok(bytes)
    }

    fn serialize_scalar(value: &F, context: &str) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        value
            .serialize_compressed(&mut bytes)
            .map_err(|e| format!("{context}: {e}"))?;
        Ok(bytes)
    }

    fn deserialize_scalar(bytes: &[u8], context: &str) -> Result<F, String> {
        F::deserialize_compressed(bytes).map_err(|e| format!("{context}: {e}"))
    }

    fn feldman_commitment_at(
        commitments: &[G],
        share_id: usize,
        context: &str,
    ) -> Result<G, String> {
        if commitments.is_empty() {
            return Err(format!("{context}: Feldman commitments are empty"));
        }

        let x = field_from_usize::<F>(share_id, "AVSS Feldman commitment evaluation point")?;
        let mut power = F::from(1u64);
        let mut expected = G::zero();
        for commitment in commitments {
            expected += *commitment * power;
            power *= x;
        }
        Ok(expected)
    }

    fn exp_dleq_challenge(
        share_id: usize,
        feldman_commitment: G,
        generator: G,
        partial_point: G,
        base_nonce: G,
        generator_nonce: G,
    ) -> Result<F, String> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"stoffel-avss-open-exp-dleq-v1");
        hasher.update(
            &usize_seed(share_id, "AVSS open-in-exponent DLEQ transcript share id")?.to_be_bytes(),
        );
        for (context, point) in [
            ("feldman commitment", feldman_commitment),
            ("opening generator", generator),
            ("partial point", partial_point),
            ("base nonce", base_nonce),
            ("generator nonce", generator_nonce),
        ] {
            let bytes = Self::serialize_group_point(point, context)?;
            hasher.update(&(bytes.len() as u64).to_be_bytes());
            hasher.update(&bytes);
        }
        Ok(F::from_be_bytes_mod_order(hasher.finalize().as_bytes()))
    }

    pub(super) fn encode_verified_exp_contribution(
        share: &FeldmanShamirShare<F, G>,
        generator: G,
        partial_point: G,
    ) -> Result<Vec<u8>, String> {
        if !verify_feldman_self(share) {
            return Err(
                "AVSS open-in-exponent local Feldman share failed commitment verification"
                    .to_string(),
            );
        }

        let feldman_commitment = Self::feldman_commitment_at(
            &share.commitments,
            share.feldmanshare.id,
            "AVSS local Feldman commitment evaluation",
        )?;
        if feldman_commitment != G::generator() * share.feldmanshare.share[0] {
            return Err(
                "AVSS open-in-exponent local share does not match Feldman commitments".to_string(),
            );
        }
        if partial_point != generator * share.feldmanshare.share[0] {
            return Err(
                "AVSS open-in-exponent local partial point does not match share value".to_string(),
            );
        }

        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        let nonce = F::rand(&mut rng);
        let base_nonce = G::generator() * nonce;
        let generator_nonce = generator * nonce;
        let challenge = Self::exp_dleq_challenge(
            share.feldmanshare.id,
            feldman_commitment,
            generator,
            partial_point,
            base_nonce,
            generator_nonce,
        )?;
        let response = nonce + challenge * share.feldmanshare.share[0];

        let contribution = AvssExpContribution {
            partial_point: Self::serialize_group_point(partial_point, "serialize partial point")?,
            dleq_proof: AvssExpDleqProof {
                base_nonce: Self::serialize_group_point(base_nonce, "serialize DLEQ base nonce")?,
                generator_nonce: Self::serialize_group_point(
                    generator_nonce,
                    "serialize DLEQ generator nonce",
                )?,
                response: Self::serialize_scalar(&response, "serialize DLEQ response")?,
            },
        };

        bincode::serialize(&contribution)
            .map_err(|e| format!("serialize AVSS open-in-exponent contribution: {e}"))
    }

    fn verify_exp_contribution(
        commitments: &[G],
        generator: G,
        share_id: usize,
        contribution_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        let contribution: AvssExpContribution = bincode::deserialize(contribution_bytes)
            .map_err(|e| format!("deserialize AVSS open-in-exponent contribution: {e}"))?;
        let partial_point = G::deserialize_compressed(&contribution.partial_point[..])
            .map_err(|e| format!("deserialize AVSS open-in-exponent partial point: {e}"))?;
        let base_nonce = G::deserialize_compressed(&contribution.dleq_proof.base_nonce[..])
            .map_err(|e| format!("deserialize AVSS open-in-exponent base nonce: {e}"))?;
        let generator_nonce =
            G::deserialize_compressed(&contribution.dleq_proof.generator_nonce[..])
                .map_err(|e| format!("deserialize AVSS open-in-exponent generator nonce: {e}"))?;
        let response = Self::deserialize_scalar(
            &contribution.dleq_proof.response,
            "deserialize AVSS open-in-exponent DLEQ response",
        )?;
        let feldman_commitment = Self::feldman_commitment_at(
            commitments,
            share_id,
            "AVSS received Feldman commitment evaluation",
        )?;
        let challenge = Self::exp_dleq_challenge(
            share_id,
            feldman_commitment,
            generator,
            partial_point,
            base_nonce,
            generator_nonce,
        )?;

        let base_check = G::generator() * response == base_nonce + feldman_commitment * challenge;
        let generator_check = generator * response == generator_nonce + partial_point * challenge;
        if !base_check || !generator_check {
            return Err("AVSS open-in-exponent DLEQ proof verification failed".to_string());
        }

        Ok(contribution.partial_point)
    }

    pub(super) fn filter_verified_exp_points(
        expected_share_bytes: &[u8],
        generator: G,
        collected: &[(usize, Vec<u8>)],
        required_valid: usize,
        context: &str,
    ) -> Result<Vec<(usize, Vec<u8>)>, String> {
        let expected_share = Self::decode_feldman_share(expected_share_bytes)?;
        if !verify_feldman_self(&expected_share) {
            return Err(format!(
                "{context}: local Feldman share failed commitment verification"
            ));
        }

        let mut verified = Vec::with_capacity(required_valid);
        for (share_id, contribution) in collected {
            let Ok(partial_point) = Self::verify_exp_contribution(
                &expected_share.commitments,
                generator,
                *share_id,
                contribution,
            ) else {
                continue;
            };
            verified.push((*share_id, partial_point));
            if verified.len() == required_valid {
                break;
            }
        }

        if verified.len() < required_valid {
            return Err(format!(
                "{context}: collected {} contributions but only {} valid open-in-exponent proofs matched the local commitments; need {}",
                collected.len(),
                verified.len(),
                required_valid
            ));
        }

        Ok(verified)
    }

    pub(super) fn encode_verified_g2_exp_contribution(
        partial_point: ark_bls12_381::G2Projective,
    ) -> Result<Vec<u8>, String> {
        let contribution = AvssG2ExpContribution {
            partial_point: {
                let mut bytes = Vec::new();
                partial_point
                    .into_affine()
                    .serialize_compressed(&mut bytes)
                    .map_err(|e| format!("serialize AVSS G2 partial point: {e}"))?;
                bytes
            },
        };

        bincode::serialize(&contribution)
            .map_err(|e| format!("serialize AVSS G2 open-in-exponent contribution: {e}"))
    }

    fn bls12381_g1_feldman_commitment_at(
        commitments: &[G],
        share_id: usize,
        context: &str,
    ) -> Result<ark_bls12_381::G1Projective, String> {
        use ark_bls12_381::{Fr, G1Projective};
        use ark_ff::Zero;

        if commitments.is_empty() {
            return Err(format!("{context}: Feldman commitments are empty"));
        }

        let x = Fr::from(usize_seed(
            share_id,
            "AVSS G2 Feldman commitment evaluation point",
        )?);
        let mut power = Fr::from(1u64);
        let mut expected = G1Projective::zero();
        for commitment in commitments {
            let commitment_bytes =
                Self::serialize_group_point(*commitment, "serialize BLS12-381 G1 commitment")?;
            let commitment_g1 = G1Projective::deserialize_compressed(&commitment_bytes[..])
                .map_err(|e| format!("{context}: deserialize BLS12-381 G1 commitment: {e}"))?;
            expected += commitment_g1 * power;
            power *= x;
        }
        Ok(expected)
    }

    pub(super) fn filter_verified_bls12381_g2_exp_points(
        expected_share_bytes: &[u8],
        generator_g2: ark_bls12_381::G2Projective,
        collected: &[(usize, Vec<u8>)],
        required_valid: usize,
        context: &str,
    ) -> Result<Vec<(usize, Vec<u8>)>, String> {
        use ark_bls12_381::{Bls12_381, G1Projective, G2Projective};
        use ark_ec::{pairing::Pairing, PrimeGroup};

        let expected_share = Self::decode_feldman_share(expected_share_bytes)?;
        if !verify_feldman_self(&expected_share) {
            return Err(format!(
                "{context}: local Feldman share failed commitment verification"
            ));
        }

        let mut verified = Vec::with_capacity(required_valid);
        for (share_id, contribution_bytes) in collected {
            let Ok(contribution) =
                bincode::deserialize::<AvssG2ExpContribution>(contribution_bytes)
            else {
                continue;
            };
            let Ok(partial_point) =
                G2Projective::deserialize_compressed(&contribution.partial_point[..])
            else {
                continue;
            };
            let Ok(feldman_commitment) = Self::bls12381_g1_feldman_commitment_at(
                &expected_share.commitments,
                *share_id,
                context,
            ) else {
                continue;
            };

            let left =
                Bls12_381::pairing(feldman_commitment.into_affine(), generator_g2.into_affine());
            let right = Bls12_381::pairing(
                G1Projective::generator().into_affine(),
                partial_point.into_affine(),
            );
            if left != right {
                continue;
            }

            verified.push((*share_id, contribution.partial_point));
            if verified.len() == required_valid {
                break;
            }
        }

        if verified.len() < required_valid {
            return Err(format!(
                "{context}: collected {} contributions but only {} valid BLS12-381 G2 partial points matched the local commitments; need {}",
                collected.len(),
                verified.len(),
                required_valid
            ));
        }

        Ok(verified)
    }

    /// Convert a FeldmanShamirShare into a `ShareData::Feldman` with extracted commitments.
    pub fn share_to_share_data(share: &FeldmanShamirShare<F, G>) -> Result<ShareData, String> {
        let data = Self::encode_feldman_share(share)?;

        let commitments = share
            .commitments
            .iter()
            .map(|c| {
                let mut buf = Vec::new();
                c.into_affine()
                    .serialize_compressed(&mut buf)
                    .map_err(|e| format!("serialize commitment: {}", e))?;
                Ok(buf)
            })
            .collect::<Result<Vec<Vec<u8>>, String>>()?;

        Ok(ShareData::Feldman {
            data: data.into(),
            commitments: commitments.into(),
        })
    }

    /// Create AVSS shares for a secret value (generates Feldman-verifiable shares for all parties).
    ///
    /// Returns this party's share.
    #[allow(dead_code)]
    pub(super) fn create_avss_share_with_rng<R: Rng>(
        &self,
        secret: F,
        rng: &mut R,
    ) -> Result<FeldmanShamirShare<F, G>, String> {
        use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};

        let mut poly = DensePolynomial::<F>::rand(self.topology.threshold(), rng);
        poly[0] = secret;

        let generator = G::generator();
        let commitments: Vec<G> = poly.coeffs.iter().map(|c| generator * c).collect();

        let x = field_from_usize::<F>(self.topology.party_id() + 1, "AVSS party evaluation point")?;
        let share_value = poly.evaluate(&x);

        FeldmanShamirShare::new(
            share_value,
            self.topology.party_id() + 1,
            self.topology.threshold(),
            commitments,
        )
        .map_err(|e| format!("Failed to create FeldmanShamirShare: {:?}", e))
    }

    /// Reconstruct the secret from a set of Feldman shares using Lagrange interpolation.
    pub(super) fn reconstruct_secret(
        shares: &[FeldmanShamirShare<F, G>],
        n: usize,
        t: usize,
    ) -> Result<F, String> {
        let (_, secret) = FeldmanShamirShare::<F, G>::recover_secret(shares, n, t)
            .map_err(|e| format!("Failed to recover secret: {:?}", e))?;
        Ok(secret)
    }

    pub(super) fn byzantine_open_contribution_count(n: usize, t: usize) -> Result<usize, String> {
        let required_valid = t
            .checked_add(1)
            .ok_or_else(|| "AVSS open valid contribution count overflowed".to_string())?;
        let required_collected = n
            .checked_sub(t)
            .ok_or_else(|| "AVSS open topology has threshold above party count".to_string())?;

        if required_collected < required_valid {
            return Err(format!(
                "AVSS open requires n - t >= t + 1, got n={n}, t={t}"
            ));
        }

        Ok(required_collected)
    }

    pub(super) fn reconstruct_verified_secret(
        expected_share_bytes: &[u8],
        collected: &[Vec<u8>],
        n: usize,
        t: usize,
        context: &str,
    ) -> Result<F, String> {
        let expected_share = Self::decode_feldman_share(expected_share_bytes)?;
        let required_valid = t
            .checked_add(1)
            .ok_or_else(|| format!("{context}: valid contribution count overflowed"))?;

        if !verify_feldman_self(&expected_share) {
            return Err(format!(
                "{context}: local Feldman share failed commitment verification"
            ));
        }

        let mut verified = Vec::with_capacity(required_valid);
        for share_bytes in collected {
            let Ok(share) = Self::decode_feldman_share(share_bytes) else {
                continue;
            };

            if share.commitments != expected_share.commitments {
                continue;
            }

            if verify_feldman_self(&share) {
                verified.push(share);
                if verified.len() == required_valid {
                    break;
                }
            }
        }

        if verified.len() < required_valid {
            return Err(format!(
                "{context}: collected {} contributions but only {} valid Feldman shares matched the local commitments; need {}",
                collected.len(),
                verified.len(),
                required_valid
            ));
        }

        Self::reconstruct_secret(&verified, n, t)
    }

    #[inline]
    pub(super) fn field_from_i64(value: i64) -> F {
        crate::net::curve::field_from_i64(value)
    }

    pub(super) fn field_to_clear_share_value(
        ty: ShareType,
        secret: F,
    ) -> Result<ClearShareValue, String> {
        crate::net::curve::field_to_clear_share_value(ty, secret).map_err(Into::into)
    }
}
