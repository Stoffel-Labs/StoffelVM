use super::{field_from_usize, AvssMpcEngine};
use ark_ec::CurveGroup;
use ark_ff::{FftField, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{Rng, SeedableRng};
use std::sync::Arc;
use stoffel_vm_types::core_types::{ClearShareValue, ShareData, ShareType};
use stoffelmpc_mpc::avss_mpc::AvssSessionId;
use stoffelmpc_mpc::common::share::avss::verify_feldman;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::common::{MPCProtocol, ProtocolSessionId, SecretSharingScheme};
use tracing::info;

impl<F, G> AvssMpcEngine<F, G>
where
    F: FftField + PrimeField + Send + Sync + 'static,
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
            session_id.as_u64()
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
                let node = self.clone_avss_node().await;
                let shares = node.share_gen_avss.avss.shares.lock().await;
                if let Some(Some(share_vec)) = shares.get(&session_id) {
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
                        session_id.as_u64()
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

                for (_session_id, maybe_shares) in shares.iter() {
                    if let Some(share_vec) = maybe_shares {
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

    /// Convert a FeldmanShamirShare into a `ShareData::Feldman` with extracted commitments.
    pub(super) fn share_to_share_data(
        share: &FeldmanShamirShare<F, G>,
    ) -> Result<ShareData, String> {
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

        Ok(ShareData::Feldman { data, commitments })
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

        if !verify_feldman(expected_share.clone()) {
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

            if verify_feldman(share.clone()) {
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
