use super::HoneyBadgerMpcEngine;
use crate::net::curve::SupportedMpcField;
use crate::net::mpc_engine::{MpcEngine, MpcExponentGroup};
use crate::net::open_registry::{ExpOpenRegistryKind, ExpOpenRequest};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::any::TypeId;
use std::time::Instant;
use stoffel_vm_types::core_types::{ClearShareValue, ShareData, ShareType};
use stoffelmpc_mpc::common::types::fixed::{
    ClearFixedPoint, FixedPointPrecision, SecretFixedPoint,
};
use stoffelmpc_mpc::common::{MPCProtocol, MPCTypeOps, SecretSharingScheme};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

/// Env var overriding how many secret-pair multiply operands are fed to a
/// single HoneyBadger `mul()` session. See [`max_honeybadger_mul_pairs_per_session`].
const STOFFEL_HB_MUL_MAX_PAIRS_PER_SESSION_ENV: &str = "STOFFEL_HB_MUL_MAX_PAIRS_PER_SESSION";

/// Default multiplier on `(threshold + 1)` for the pairs fed to one `mul()`
/// session. Matches `mpc-protocols`' own per-session deserialization bound
/// (`128 * (t+1)`), so the default stays within what the protocol already
/// supports without a change. See [`max_honeybadger_mul_pairs_per_session`].
const DEFAULT_MAX_HONEYBADGER_MUL_BATCH_RECON_CHUNKS: usize = 128;

/// Maximum secret-pair multiply operands fed to a single HoneyBadger `mul()`
/// session.
///
/// `batch_multiply_share_async` calls `node.mul()` once per chunk of this size
/// and *awaits each call before starting the next*, so each chunk is a
/// sequential communication round. Raising this packs more same-depth
/// multiplications into one round and directly cuts the round count for wide
/// depth-levels (e.g. a layer with 144 independent muls is 1 round at the
/// default `256` but 3 rounds at a cap of `64`).
///
/// The protocol itself imposes no fixed width here: `batch_recon` packs any
/// number of `(t+1)`-groups into a single send + broadcast, and `mpc-protocols`'s
/// own `node.mul` further chunks into independent sessions whose rounds overlap.
/// The only hard ceiling is the deserialization bound on one opened-values
/// message, `128 * (t+1)` in `mpc-protocols::honeybadger::max_mul_pairs_per_session`.
/// The default matches that bound, so it is the highest value that needs no
/// protocol change; going beyond `128*(t+1)` requires raising that mpc-protocols
/// cap (and the matching `deser_bounded_vec` bound). Measured on the AES-128
/// circuit (t=1): raising the cap `64 -> 256` cut online rounds 702 -> 426
/// (−39%) and online time ~1.11s -> ~0.96s with identical NIST output.
///
/// The `(t+1)` factor only keeps the count a clean multiple so there is no RBC
/// remainder; an explicit override (below) is used as-is.
pub(crate) fn max_honeybadger_mul_pairs_per_session(threshold: usize) -> usize {
    let from_env = std::env::var(STOFFEL_HB_MUL_MAX_PAIRS_PER_SESSION_ENV)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok().map(|v| v.max(1)));
    from_env.unwrap_or_else(|| max_honeybadger_mul_pairs_per_session_with(threshold, None))
}

/// Pure (env-free) core of [`max_honeybadger_mul_pairs_per_session`], factored
/// out so the default formula is unit-testable without touching process-global
/// environment state. `override_pairs = Some(n)` forces the result to `n`.
pub(crate) fn max_honeybadger_mul_pairs_per_session_with(
    threshold: usize,
    override_pairs: Option<usize>,
) -> usize {
    if let Some(value) = override_pairs {
        return value.max(1);
    }
    DEFAULT_MAX_HONEYBADGER_MUL_BATCH_RECON_CHUNKS.saturating_mul(threshold.saturating_add(1))
}

impl<F, G> HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    fn trace_multiply_enabled() -> bool {
        std::env::var("STOFFEL_HB_MULTIPLY_TRACE")
            .is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
    }

    pub async fn multiply_share_async(
        &self,
        ty: ShareType,
        left: &[u8],
        right: &[u8],
    ) -> Result<ShareData, String> {
        if !self.is_ready() {
            return Err("MPC engine not ready".into());
        }

        // Secret fixed-point multiplication needs the truncating fixed-point
        // multiply (the raw integer multiply would leave the product with 2f
        // fractional bits) plus the same probabilistic-truncation preprocessing
        // the fixed-point division path provisions. Route it through `mul_fixed`
        // and provision a pool of prandbit/prandint (and the triples/randoms
        // their generation consumes) so it is self-sufficient without a protocol
        // change, mirroring `divide_fixed_by_constant_async`.
        if let ShareType::SecretFixedPoint { precision } = ty {
            let left_share = Self::decode_share(left)?;
            let right_share = Self::decode_share(right)?;
            let proto_precision =
                FixedPointPrecision::new(precision.total_bits(), precision.fractional_bits());
            let x = SecretFixedPoint::new_with_precision(left_share, proto_precision);
            let y = SecretFixedPoint::new_with_precision(right_share, proto_precision);

            let mut node = self.clone_node().await;
            let f = precision.fractional_bits();
            if self.is_standing() {
                let triples = self.reserve_beaver_triples(1).await?;
                let prandbits = self.reserve_prandbit_shares(f).await?;
                let prandints = self.reserve_prandint_shares(1, ty).await?;
                node.preprocessing_material.lock().await.add(
                    Some(triples),
                    None,
                    None,
                    None,
                    Some(prandbits),
                    Some(prandints),
                );
            } else {
                const PRANDBIT_POOL_MULS: usize = 16;
                let pool = f.saturating_mul(PRANDBIT_POOL_MULS);
                node.params.n_prandbit = node.params.n_prandbit.max(pool);
                node.params.n_prandint = node.params.n_prandint.max(PRANDBIT_POOL_MULS);
                node.params.n_triples = node.params.n_triples.saturating_add(pool);
                node.params.n_random_shares = node.params.n_random_shares.saturating_add(pool);
            }

            let result = node
                .mul_fixed(x, y, self.protocol_net.clone())
                .await
                .map_err(|e| format!("MPC fixed-point multiply failed: {:?}", e))?;
            return Self::encode_share(result.value()).map(|v| ShareData::Opaque(v.into()));
        }

        match ty {
            ShareType::SecretInt { .. }
            | ShareType::SecretUInt { .. }
            | ShareType::SecretFixedPoint { .. } => {
                let left_share = Self::decode_share(left)?;
                let right_share = Self::decode_share(right)?;

                let mut node = self.clone_node().await;
                // Provision a triple pool so a secret*secret multiply is
                // self-sufficient even when the program's static preprocessing
                // estimate was 0 (e.g. operands produced by `Share.from_clear*`,
                // whose opaque type the demand analysis doesn't count). node.mul
                // regenerates from params on demand; `.max` never shrinks an
                // already-sized estimate (e.g. AES/CBC). Triple generation pulls
                // 2 randoms each, which run_preprocessing adds automatically.
                if self.is_standing() {
                    let triples = self.reserve_beaver_triples(1).await?;
                    node.preprocessing_material.lock().await.add(
                        Some(triples),
                        None,
                        None,
                        None,
                        None,
                        None,
                    );
                } else {
                    const TRIPLE_POOL_MULS: usize = 64;
                    node.params.n_triples = node.params.n_triples.max(TRIPLE_POOL_MULS);
                }
                let trace = Self::trace_multiply_enabled();
                let started_at = Instant::now();
                if trace {
                    let _m = node.preprocessing_material.lock().await.length();
                    let (triples, randoms, bits, exp_points) =
                        (_m.beaver_triples, _m.random_shr, _m.prandbit, _m.prandint);
                    eprintln!(
                        "[hb multiply start] party={} items=1 ty={:?} material=triples:{} randoms:{} bits:{} exp_points:{}",
                        self.topology.party_id(),
                        ty,
                        triples,
                        randoms,
                        bits,
                        exp_points
                    );
                }
                let result_shares = node
                    .mul(
                        vec![left_share],
                        vec![right_share],
                        self.protocol_net.clone(),
                    )
                    .await
                    .map_err(|e| format!("MPC multiplication failed: {:?}", e))?;
                if trace {
                    let _m = node.preprocessing_material.lock().await.length();
                    let (triples, randoms, bits, exp_points) =
                        (_m.beaver_triples, _m.random_shr, _m.prandbit, _m.prandint);
                    eprintln!(
                        "[hb multiply done] party={} items=1 elapsed_ms={} material=triples:{} randoms:{} bits:{} exp_points:{}",
                        self.topology.party_id(),
                        started_at.elapsed().as_millis(),
                        triples,
                        randoms,
                        bits,
                        exp_points
                    );
                }

                let result_share = result_shares
                    .into_iter()
                    .next()
                    .ok_or_else(|| "Multiplication returned no shares".to_string())?;

                Self::encode_share(&result_share).map(|v| ShareData::Opaque(v.into()))
            }
        }
    }

    /// Divide a secret fixed-point share by a public positive constant using the
    /// HoneyBadger fixed-point division protocol (reciprocal + probabilistic
    /// truncation). `divisor_scaled` is `round(divisor * 2^f)`, i.e. the divisor
    /// in the same fixed-point scale as the share. The protocol node pulls (and,
    /// if depleted, regenerates) the truncation randomness it needs internally.
    pub async fn divide_fixed_by_constant_async(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        divisor_scaled: i64,
    ) -> Result<ShareData, String> {
        if !self.is_ready() {
            return Err("MPC engine not ready".into());
        }

        let precision = match ty {
            ShareType::SecretFixedPoint { precision } => precision,
            _ => {
                return Err(
                    "fixed-point division requires a secret fix64 (SecretFixedPoint) share".into(),
                );
            }
        };
        if divisor_scaled <= 0 {
            return Err("fixed-point division by a non-positive constant is not supported".into());
        }

        let dividend = Self::decode_share(share_bytes)?;
        let proto_precision =
            FixedPointPrecision::new(precision.total_bits(), precision.fractional_bits());
        let x = SecretFixedPoint::new_with_precision(dividend, proto_precision);
        let divisor_field = crate::net::curve::field_from_i64::<F>(divisor_scaled);
        let y = ClearFixedPoint::new_with_precision(divisor_field, proto_precision);

        let mut node = self.clone_node().await;
        let f = precision.fractional_bits();
        if self.is_standing() {
            let prandbits = self.reserve_prandbit_shares(f).await?;
            let prandints = self.reserve_prandint_shares(1, ty).await?;
            node.preprocessing_material.lock().await.add(
                None,
                None,
                None,
                None,
                Some(prandbits),
                Some(prandints),
            );
        } else {
            // Each division's truncation consumes `f` random bits and one random
            // integer. One-shot mode preserves the legacy behavior of
            // provisioning a local pool and letting the protocol regenerate it.
            const PRANDBIT_POOL_DIVS: usize = 16;
            let pool = f.saturating_mul(PRANDBIT_POOL_DIVS);
            node.params.n_prandbit = node.params.n_prandbit.max(pool);
            node.params.n_prandint = node.params.n_prandint.max(PRANDBIT_POOL_DIVS);
            node.params.n_triples = node.params.n_triples.saturating_add(pool);
            node.params.n_random_shares = node.params.n_random_shares.saturating_add(pool);
        }
        let result = node
            .div_with_const_fixed(x, y, self.protocol_net.clone())
            .await
            .map_err(|e| format!("MPC fixed-point division failed: {:?}", e))?;

        Self::encode_share(result.value()).map(|v| ShareData::Opaque(v.into()))
    }

    pub async fn batch_multiply_share_async(
        &self,
        ty: ShareType,
        pairs: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<Vec<ShareData>, String> {
        if !self.is_ready() {
            return Err("MPC engine not ready".into());
        }

        if pairs.is_empty() {
            return Ok(Vec::new());
        }

        match ty {
            ShareType::SecretInt { .. }
            | ShareType::SecretUInt { .. }
            | ShareType::SecretFixedPoint { .. } => {
                let max_pairs_per_session =
                    max_honeybadger_mul_pairs_per_session(self.topology.threshold()).max(1);
                let trace = Self::trace_multiply_enabled();
                let started_at = Instant::now();
                if trace {
                    eprintln!(
                        "[hb batch_multiply start] party={} items={} ty={:?}",
                        self.topology.party_id(),
                        pairs.len(),
                        ty
                    );
                }

                let mut encoded_results = Vec::with_capacity(pairs.len());
                let mut node = self.clone_node().await;
                if !self.is_standing() {
                    node.params.n_triples = node.params.n_triples.max(max_pairs_per_session);
                }
                for (chunk_index, chunk) in pairs.chunks(max_pairs_per_session).enumerate() {
                    let mut left_shares = Vec::with_capacity(chunk.len());
                    let mut right_shares = Vec::with_capacity(chunk.len());

                    for (left, right) in chunk {
                        left_shares.push(Self::decode_share(left)?);
                        right_shares.push(Self::decode_share(right)?);
                    }

                    if self.is_standing() {
                        let triples = self.reserve_beaver_triples(chunk.len()).await?;
                        node.preprocessing_material.lock().await.add(
                            Some(triples),
                            None,
                            None,
                            None,
                            None,
                            None,
                        );
                    }

                    let chunk_started_at = Instant::now();
                    if trace {
                        let _m = node.preprocessing_material.lock().await.length();
                        let (triples, randoms, bits, exp_points) =
                            (_m.beaver_triples, _m.random_shr, _m.prandbit, _m.prandint);
                        eprintln!(
                            "[hb batch_multiply chunk start] party={} chunk={} items={} material=triples:{} randoms:{} bits:{} exp_points:{}",
                            self.topology.party_id(),
                            chunk_index,
                            chunk.len(),
                            triples,
                            randoms,
                            bits,
                            exp_points
                        );
                    }

                    let result_shares = node
                        .mul(left_shares, right_shares, self.protocol_net.clone())
                        .await
                        .map_err(|e| format!("MPC batch multiplication failed: {:?}", e))?;
                    if trace {
                        let _m = node.preprocessing_material.lock().await.length();
                        let (triples, randoms, bits, exp_points) =
                            (_m.beaver_triples, _m.random_shr, _m.prandbit, _m.prandint);
                        eprintln!(
                            "[hb batch_multiply chunk done] party={} chunk={} items={} elapsed_ms={} material=triples:{} randoms:{} bits:{} exp_points:{}",
                            self.topology.party_id(),
                            chunk_index,
                            chunk.len(),
                            chunk_started_at.elapsed().as_millis(),
                            triples,
                            randoms,
                            bits,
                            exp_points
                        );
                    }

                    if result_shares.len() != chunk.len() {
                        return Err(format!(
                            "Batch multiplication returned {} shares for {} inputs",
                            result_shares.len(),
                            chunk.len()
                        ));
                    }

                    for share in result_shares {
                        encoded_results
                            .push(Self::encode_share(&share).map(|v| ShareData::Opaque(v.into()))?);
                    }
                }
                if trace {
                    eprintln!(
                        "[hb batch_multiply done] party={} items={} chunks={} elapsed_ms={}",
                        self.topology.party_id(),
                        pairs.len(),
                        pairs.len().div_ceil(max_pairs_per_session),
                        started_at.elapsed().as_millis()
                    );
                }

                Ok(encoded_results)
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
            ShareType::SecretUInt { bit_length } => format!("hb-uint-{bit_length}"),
            ShareType::SecretFixedPoint { precision } => {
                format!("hb-fixed-{}-{}", precision.k(), precision.f())
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
        self.broadcast_open_registry_payload(wire_message).await?;

        let required = Self::robust_open_required_contributions(self.topology.threshold());
        let n = self.topology.n_parties();
        let t = self.topology.threshold();

        self.open_registry()
            .open_share_at_async(
                self.topology.party_id(),
                type_key,
                seq,
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

    /// Reveal a share as its raw field element (rather than decoding it back to
    /// an integer/fixed-point clear value). Backs `Share.open_field`, which lets
    /// StoffelLang programs do public field arithmetic on opened values (e.g.
    /// the joint random-bit protocol opens `r^2` and takes its field sqrt).
    ///
    /// Reconstruction is identical to `open_share` — collect `3t+1` robust
    /// shares and recover the secret — but the result is the canonically
    /// serialized field element. A distinct `hb-field-*` type key keeps this
    /// opening's broadcast namespace separate from the integer `open` path.
    pub async fn open_share_as_field_async_impl(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        let type_key = match ty {
            ShareType::SecretInt { bit_length } => format!("hb-field-int-{bit_length}"),
            ShareType::SecretUInt { bit_length } => format!("hb-field-uint-{bit_length}"),
            ShareType::SecretFixedPoint { precision } => {
                format!("hb-field-fixed-{}-{}", precision.k(), precision.f())
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
        self.broadcast_open_registry_payload(wire_message).await?;

        let required = Self::robust_open_required_contributions(self.topology.threshold());
        let n = self.topology.n_parties();
        let t = self.topology.threshold();

        self.open_registry()
            .open_bytes_at_async(
                self.topology.party_id(),
                type_key,
                seq,
                share_bytes.to_vec(),
                required,
                |collected| {
                    let mut shares: Vec<RobustShare<F>> = Vec::with_capacity(collected.len());
                    for bytes in collected {
                        shares.push(Self::decode_share(bytes)?);
                    }

                    let (_deg, secret) = RobustShare::recover_secret(&shares, n, t)
                        .map_err(|e| format!("recover_secret: {:?}", e))?;
                    let mut out = Vec::new();
                    secret
                        .serialize_compressed(&mut out)
                        .map_err(|e| format!("serialize field element: {}", e))?;
                    Ok(out)
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
            ShareType::SecretUInt { bit_length } => format!("hb-batch-uint-{bit_length}"),
            ShareType::SecretFixedPoint { precision } => {
                format!("hb-batch-fixed-{}-{}", precision.k(), precision.f())
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
        self.broadcast_open_registry_payload(wire_message).await?;

        let required = Self::robust_open_required_contributions(self.topology.threshold());
        let n = self.topology.n_parties();
        let t = self.topology.threshold();

        self.open_registry()
            .batch_open_at_async(
                self.topology.party_id(),
                type_key,
                Some(seq),
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
            .await
    }

    pub async fn batch_open_shares_as_fields_async_impl(
        &self,
        ty: ShareType,
        shares: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, String> {
        if shares.is_empty() {
            return Ok(Vec::new());
        }

        let type_key = match ty {
            ShareType::SecretInt { bit_length } => format!("hb-batch-field-int-{bit_length}"),
            ShareType::SecretUInt { bit_length } => format!("hb-batch-field-uint-{bit_length}"),
            ShareType::SecretFixedPoint { precision } => {
                format!("hb-batch-field-fixed-{}-{}", precision.k(), precision.f())
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
        self.broadcast_open_registry_payload(wire_message).await?;

        let required = Self::robust_open_required_contributions(self.topology.threshold());
        let (_party_ids, collected) = self
            .open_registry()
            .batch_collect_at_async(
                self.topology.party_id(),
                type_key,
                seq,
                shares.to_vec(),
                required,
            )
            .await?;
        let n = self.topology.n_parties();
        let t = self.topology.threshold();
        collected
            .iter()
            .enumerate()
            .map(|(position, contributions)| {
                let decoded = contributions
                    .iter()
                    .map(|bytes| Self::decode_share(bytes))
                    .collect::<Result<Vec<RobustShare<F>>, _>>()?;
                let (_degree, secret) =
                    RobustShare::recover_secret(&decoded, n, t).map_err(|error| {
                        format!("batch field recover_secret pos {position}: {error:?}")
                    })?;
                let mut encoded = Vec::new();
                secret
                    .serialize_compressed(&mut encoded)
                    .map_err(|error| format!("serialize batch field pos {position}: {error}"))?;
                Ok(encoded)
            })
            .collect()
    }

    pub async fn batch_open_shares_in_exp_group_custom_async_impl(
        &self,
        group: MpcExponentGroup,
        ty: ShareType,
        shares: &[Vec<u8>],
        generators: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, String> {
        if shares.len() != generators.len() {
            return Err(format!(
                "batch exponent share/generator length mismatch: {} != {}",
                shares.len(),
                generators.len()
            ));
        }
        if shares.is_empty() {
            return Ok(Vec::new());
        }
        self.require_verifiable_exponent_open()?;
        if group != MpcExponentGroup::native_for_curve(self.curve_config()) {
            return Err(group.unsupported_error(self.protocol_name()));
        }

        let mut partial_points = Vec::with_capacity(shares.len());
        for (position, (share_bytes, generator_bytes)) in shares.iter().zip(generators).enumerate()
        {
            let share = Self::decode_share(share_bytes)?;
            if share.id != self.topology.party_id() {
                return Err(format!(
                    "batch exponent share {position} has party id {}, expected {}",
                    share.id,
                    self.topology.party_id()
                ));
            }
            let generator =
                G::deserialize_compressed(generator_bytes.as_slice()).map_err(|error| {
                    format!("deserialize batch exponent generator {position}: {error}")
                })?;
            let mut encoded = Vec::new();
            (generator * share.share[0])
                .into_affine()
                .serialize_compressed(&mut encoded)
                .map_err(|error| {
                    format!("serialize batch exponent partial point {position}: {error}")
                })?;
            partial_points.push(encoded);
        }

        let share_type = match ty {
            ShareType::SecretInt { bit_length } => format!("int-{bit_length}"),
            ShareType::SecretUInt { bit_length } => format!("uint-{bit_length}"),
            ShareType::SecretFixedPoint { precision } => {
                format!("fixed-{}-{}", precision.k(), precision.f())
            }
        };
        let type_key = format!("hb-batch-exp-{}-{share_type}", group.as_str());
        let seq = self.open_registry().insert_batch_next(
            &type_key,
            self.topology.party_id(),
            partial_points.clone(),
        )?;
        let wire_message = crate::net::open_registry::encode_batch_share_wire_message(
            self.current_instance_id(),
            seq,
            &type_key,
            self.topology.party_id(),
            &partial_points,
        )?;
        self.broadcast_open_registry_payload(wire_message).await?;

        let required = 2 * self.topology.threshold() + 1;
        let (party_ids, collected) = self
            .open_registry()
            .batch_collect_at_async(
                self.topology.party_id(),
                type_key,
                seq,
                partial_points,
                required,
            )
            .await?;
        let domain = GeneralEvaluationDomain::<F>::new(self.topology.n_parties())
            .ok_or_else(|| "No suitable FFT domain".to_string())?;
        collected
            .into_iter()
            .enumerate()
            .map(|(position, contributions)| {
                let partials = party_ids
                    .iter()
                    .copied()
                    .zip(contributions)
                    .collect::<Vec<_>>();
                crate::net::group_interpolation::interpolate_compressed_group_points::<F, G, _>(
                    &partials,
                    |id| Ok(domain.element(id)),
                    &format!("deserialize batch exponent partial point {position}"),
                    &format!("zero denominator in batch exponent position {position}"),
                    &format!("serialize batch exponent result {position}"),
                )
            })
            .collect()
    }

    async fn broadcast_open_exp_payload(&self, payload: Vec<u8>) -> Result<(), String> {
        crate::net::broadcast::broadcast_to_other_parties(
            self.protocol_net.as_ref(),
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
        self.require_verifiable_exponent_open()?;
        let share = Self::decode_share(share_bytes)?;
        let generator = G::deserialize_compressed(generator_bytes)
            .map_err(|e| format!("deserialize generator: {}", e))?;
        let partial_point = generator * share.share[0];

        let mut partial_bytes = Vec::new();
        partial_point
            .into_affine()
            .serialize_compressed(&mut partial_bytes)
            .map_err(|e| format!("serialize partial point: {}", e))?;

        let seq = self.open_registry().insert_exp_next(
            ExpOpenRegistryKind::G1,
            self.topology.party_id(),
            share.id,
            partial_bytes.clone(),
        )?;
        let wire_message = crate::net::open_registry::encode_hb_open_exp_wire_message(
            self.current_instance_id(),
            seq,
            self.topology.party_id(),
            share.id,
            &partial_bytes,
        )?;
        self.broadcast_open_exp_payload_sync(wire_message)?;

        let required = 2 * self.topology.threshold() + 1;
        let n = self.topology.n_parties();
        let domain = GeneralEvaluationDomain::<F>::new(n)
            .ok_or_else(|| "No suitable FFT domain".to_string())?;

        self.open_registry().exp_open_wait(
            ExpOpenRequest {
                kind: ExpOpenRegistryKind::G1,
                sequence: Some(seq),
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
        self.require_verifiable_exponent_open()?;
        let share = Self::decode_share(share_bytes)?;
        let generator = G::deserialize_compressed(generator_bytes)
            .map_err(|e| format!("deserialize generator: {}", e))?;
        let partial_point = generator * share.share[0];

        let mut partial_bytes = Vec::new();
        partial_point
            .into_affine()
            .serialize_compressed(&mut partial_bytes)
            .map_err(|e| format!("serialize partial point: {}", e))?;

        let seq = self.open_registry().insert_exp_next(
            ExpOpenRegistryKind::G1,
            self.topology.party_id(),
            share.id,
            partial_bytes.clone(),
        )?;
        let wire_message = crate::net::open_registry::encode_hb_open_exp_wire_message(
            self.current_instance_id(),
            seq,
            self.topology.party_id(),
            share.id,
            &partial_bytes,
        )?;
        self.broadcast_open_exp_payload(wire_message).await?;

        let required = 2 * self.topology.threshold() + 1;
        let n = self.topology.n_parties();
        let domain = GeneralEvaluationDomain::<F>::new(n)
            .ok_or_else(|| "No suitable FFT domain".to_string())?;

        self.open_registry()
            .exp_open_async(
                ExpOpenRequest {
                    kind: ExpOpenRegistryKind::G1,
                    sequence: Some(seq),
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

    pub fn open_share_in_exp_bls12381_g2_impl(
        &self,
        share_bytes: &[u8],
        generator_g2_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.require_verifiable_exponent_open()?;
        use ark_bls12_381::{Fr, G2Projective};

        if TypeId::of::<F>() != TypeId::of::<Fr>() {
            return Err(format!(
                "MPC backend '{}' uses {:?}, which cannot open shares in bls12-381-g2",
                self.protocol_name(),
                F::CURVE_CONFIG
            ));
        }

        let share = Self::decode_share(share_bytes)?;
        let generator = G2Projective::deserialize_compressed(generator_g2_bytes)
            .map_err(|e| format!("deserialize G2 generator: {}", e))?;

        let mut share_value_bytes = Vec::new();
        share.share[0]
            .serialize_compressed(&mut share_value_bytes)
            .map_err(|e| format!("serialize BLS12-381 scalar share: {}", e))?;
        let share_value = Fr::deserialize_compressed(&share_value_bytes[..])
            .map_err(|e| format!("deserialize BLS12-381 scalar share: {}", e))?;

        let partial_point = generator * share_value;
        let mut partial_bytes = Vec::new();
        partial_point
            .into_affine()
            .serialize_compressed(&mut partial_bytes)
            .map_err(|e| format!("serialize G2 partial point: {}", e))?;

        let seq = self.open_registry().insert_exp_next(
            ExpOpenRegistryKind::G1,
            self.topology.party_id(),
            share.id,
            partial_bytes.clone(),
        )?;
        let wire_message = crate::net::open_registry::encode_hb_open_exp_wire_message(
            self.current_instance_id(),
            seq,
            self.topology.party_id(),
            share.id,
            &partial_bytes,
        )?;
        self.broadcast_open_exp_payload_sync(wire_message)?;

        let required = 2 * self.topology.threshold() + 1;
        let n = self.topology.n_parties();
        let domain = GeneralEvaluationDomain::<Fr>::new(n)
            .ok_or_else(|| "No suitable FFT domain".to_string())?;

        self.open_registry().exp_open_wait(
            ExpOpenRequest {
                kind: ExpOpenRegistryKind::G1,
                sequence: Some(seq),
                party_id: self.topology.party_id(),
                share_id: share.id,
                partial_point: &partial_bytes,
                required,
                timeout_message: "Timeout waiting for BLS12-381 G2 open_share_in_exp contributions",
            },
            |partial_points| {
                crate::net::group_interpolation::interpolate_compressed_group_points::<
                    Fr,
                    G2Projective,
                    _,
                >(
                    partial_points,
                    |id| Ok(domain.element(id)),
                    "deserialize G2 partial point",
                    "zero denominator in BLS12-381 G2 Lagrange",
                    "serialize G2 result",
                )
            },
        )
    }

    pub async fn open_share_in_exp_bls12381_g2_async_impl(
        &self,
        share_bytes: &[u8],
        generator_g2_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.require_verifiable_exponent_open()?;
        use ark_bls12_381::{Fr, G2Projective};

        if TypeId::of::<F>() != TypeId::of::<Fr>() {
            return Err(format!(
                "MPC backend '{}' uses {:?}, which cannot open shares in bls12-381-g2",
                self.protocol_name(),
                F::CURVE_CONFIG
            ));
        }

        let share = Self::decode_share(share_bytes)?;
        let generator = G2Projective::deserialize_compressed(generator_g2_bytes)
            .map_err(|e| format!("deserialize G2 generator: {}", e))?;

        let mut share_value_bytes = Vec::new();
        share.share[0]
            .serialize_compressed(&mut share_value_bytes)
            .map_err(|e| format!("serialize BLS12-381 scalar share: {}", e))?;
        let share_value = Fr::deserialize_compressed(&share_value_bytes[..])
            .map_err(|e| format!("deserialize BLS12-381 scalar share: {}", e))?;

        let partial_point = generator * share_value;
        let mut partial_bytes = Vec::new();
        partial_point
            .into_affine()
            .serialize_compressed(&mut partial_bytes)
            .map_err(|e| format!("serialize G2 partial point: {}", e))?;

        let seq = self.open_registry().insert_exp_next(
            ExpOpenRegistryKind::G1,
            self.topology.party_id(),
            share.id,
            partial_bytes.clone(),
        )?;
        let wire_message = crate::net::open_registry::encode_hb_open_exp_wire_message(
            self.current_instance_id(),
            seq,
            self.topology.party_id(),
            share.id,
            &partial_bytes,
        )?;
        self.broadcast_open_exp_payload(wire_message).await?;

        let required = 2 * self.topology.threshold() + 1;
        let n = self.topology.n_parties();
        let domain = GeneralEvaluationDomain::<Fr>::new(n)
            .ok_or_else(|| "No suitable FFT domain".to_string())?;

        self.open_registry()
            .exp_open_async(
                ExpOpenRequest {
                    kind: ExpOpenRegistryKind::G1,
                    sequence: Some(seq),
                    party_id: self.topology.party_id(),
                    share_id: share.id,
                    partial_point: &partial_bytes,
                    required,
                    timeout_message:
                        "Timeout waiting for BLS12-381 G2 open_share_in_exp contributions",
                },
                |partial_points| {
                    crate::net::group_interpolation::interpolate_compressed_group_points::<
                        Fr,
                        G2Projective,
                        _,
                    >(
                        partial_points,
                        |id| Ok(domain.element(id)),
                        "deserialize G2 partial point",
                        "zero denominator in BLS12-381 G2 Lagrange",
                        "serialize G2 result",
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

    fn require_verifiable_exponent_open(&self) -> Result<(), String> {
        if self.topology.threshold() > 0 {
            return Err(
                "HoneyBadger open-in-exponent is disabled for Byzantine-threshold sessions: \
                 RobustShare carries no authenticated polynomial commitment, so peer partial \
                 points cannot be verified without revealing the scalar; use the AVSS backend \
                 for verifiable exponent openings"
                    .to_string(),
            );
        }
        Ok(())
    }

    pub(super) fn encode_share(share: &RobustShare<F>) -> Result<Vec<u8>, String> {
        let mut out = Vec::with_capacity(share.compressed_size());
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

#[cfg(test)]
mod tests {
    use super::max_honeybadger_mul_pairs_per_session_with;

    #[test]
    fn default_max_mul_pairs_per_session_matches_protocol_deserialization_bound() {
        // Default (no override): 128 * (t+1), matching mpc-protocols' own
        // per-session deserialization bound — one `mul()` session opens all its
        // (t+1)-groups through a single batch_recon, so the width is bounded by
        // that deser limit, not by child-session id space.
        assert_eq!(max_honeybadger_mul_pairs_per_session_with(0, None), 128);
        assert_eq!(max_honeybadger_mul_pairs_per_session_with(1, None), 256);
        assert_eq!(max_honeybadger_mul_pairs_per_session_with(3, None), 512);
    }

    #[test]
    fn override_forces_pairs_per_session_directly() {
        // An explicit override is used as-is (not forced to a multiple of t+1).
        assert_eq!(
            max_honeybadger_mul_pairs_per_session_with(1, Some(256)),
            256
        );
        // A floor of 1 keeps an accidental 0 from starving every multiply.
        assert_eq!(max_honeybadger_mul_pairs_per_session_with(1, Some(0)), 1);
    }
}
