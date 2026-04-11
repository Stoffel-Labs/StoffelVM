//! Shared MPC curve and field configuration.
//!
//! This module centralizes curve parsing/validation across backends.

use crate::net::backend::MpcBackendKind;

/// Curated set of MPC curves supported by the VM.
///
/// Ed25519 and Curve25519 share the same scalar field (`ark_curve25519::Fr`).
/// At the type level `ark_ed25519::Fr` is a re-export of `ark_curve25519::Fr`,
/// so `SupportedMpcField` is implemented once and covers both curves.
/// `curve_config()` on an Ed25519 engine will report `Curve25519` because the
/// field is identical; use the server / CLI `--mpc-curve` flag to distinguish
/// intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpcCurveConfig {
    Bls12_381,
    Bn254,
    Curve25519,
    /// Ed25519 uses the same scalar field as Curve25519.
    /// See enum-level docs for details.
    Ed25519,
}

impl std::str::FromStr for MpcCurveConfig {
    type Err = String;

    /// Parse a curve name (case-insensitive with common aliases).
    fn from_str(input: &str) -> Result<Self, String> {
        match input.trim().to_ascii_lowercase().as_str() {
            "bls12-381" | "bls12_381" | "bls12381" => Ok(Self::Bls12_381),
            "bn254" => Ok(Self::Bn254),
            "curve25519" | "curve-25519" => Ok(Self::Curve25519),
            "ed25519" | "ed-25519" => Ok(Self::Ed25519),
            other => Err(format!(
                "Unknown MPC curve '{other}'. Supported curves: bls12-381, bn254, curve25519, ed25519"
            )),
        }
    }
}

impl MpcCurveConfig {
    pub fn name(self) -> &'static str {
        match self {
            Self::Bls12_381 => "bls12-381",
            Self::Bn254 => "bn254",
            Self::Curve25519 => "curve25519",
            Self::Ed25519 => "ed25519",
        }
    }

    pub fn field_kind(self) -> MpcFieldKind {
        match self {
            Self::Bls12_381 => MpcFieldKind::Bls12_381Fr,
            Self::Bn254 => MpcFieldKind::Bn254Fr,
            Self::Curve25519 => MpcFieldKind::Curve25519Fr,
            // Ed25519 uses the same scalar field as curve25519.
            Self::Ed25519 => MpcFieldKind::Curve25519Fr,
        }
    }

    /// Validate that this curve is compatible with the given backend.
    ///
    /// Currently all curves are supported by all backends. This is an extension
    /// point for future backend-specific restrictions.
    pub fn validate_for_backend(self, _backend: MpcBackendKind) -> Result<(), String> {
        Ok(())
    }
}

impl Default for MpcCurveConfig {
    fn default() -> Self {
        Self::Bls12_381
    }
}

/// Field-dispatch metadata for VM-local share math.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpcFieldKind {
    Bls12_381Fr,
    Bn254Fr,
    Curve25519Fr,
}

impl MpcFieldKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Bls12_381Fr => "bls12-381-fr",
            Self::Bn254Fr => "bn254-fr",
            Self::Curve25519Fr => "curve25519-fr",
        }
    }
}

/// Implemented by supported MPC scalar fields so engines can expose
/// compile-time field metadata at runtime.
pub trait SupportedMpcField: ark_ff::FftField + ark_ff::PrimeField + Send + Sync + 'static {
    const CURVE_CONFIG: MpcCurveConfig;

    fn field_kind() -> MpcFieldKind {
        Self::CURVE_CONFIG.field_kind()
    }
}

impl SupportedMpcField for ark_bls12_381::Fr {
    const CURVE_CONFIG: MpcCurveConfig = MpcCurveConfig::Bls12_381;
}

impl SupportedMpcField for ark_bn254::Fr {
    const CURVE_CONFIG: MpcCurveConfig = MpcCurveConfig::Bn254;
}

impl SupportedMpcField for ark_curve25519::Fr {
    const CURVE_CONFIG: MpcCurveConfig = MpcCurveConfig::Curve25519;
}

/// Convert an `i64` to a field element.
///
/// Positive values map to `F::from(value as u64)`.
/// Negative values map to `-F::from((-value) as u64)`, i.e. the field-additive
/// inverse, which is correct for fields whose modulus exceeds `2^63`.
#[inline]
pub fn field_from_i64<F: ark_ff::PrimeField>(value: i64) -> F {
    if value >= 0 {
        F::from(value as u64)
    } else {
        -F::from((-value) as u64)
    }
}

/// Convert a field element back to `i64`.
///
/// This is the inverse of [`field_from_i64`]. Elements in the lower half of the
/// field (i.e. `bigint < (p-1)/2`) are returned as non-negative `i64`; elements
/// in the upper half are interpreted as negative values.
///
/// Only correct when the original value was in `i64` range and the field modulus
/// is much larger than `2^64`.
#[inline]
pub fn field_to_i64<F: ark_ff::PrimeField>(value: F) -> i64 {
    let bigint = value.into_bigint();
    let limbs = bigint.as_ref();
    let raw = limbs.first().copied().unwrap_or(0);

    // Check if the element is in the upper half of the field (i.e. represents a negative value).
    // We do this by comparing with (p-1)/2.  For a negative value -x, the field
    // representation is p - x, which is > (p-1)/2 when x > 0.
    let neg = (-value).into_bigint();
    let neg_raw = neg.as_ref().first().copied().unwrap_or(0);

    // If the negation is smaller (fits in fewer limbs / smaller lowest limb),
    // the original element was in the upper half → negative.
    // We compare full bigints to be safe.
    if !value.is_zero() && neg < bigint {
        -(neg_raw as i64)
    } else {
        raw as i64
    }
}

/// Convert a reconstructed field element to the appropriate [`Value`] for a
/// given [`ShareType`].
///
/// Used by both the HoneyBadger and AVSS engines after secret reconstruction.
pub fn field_to_value<F: ark_ff::PrimeField>(
    ty: stoffel_vm_types::core_types::ShareType,
    secret: F,
) -> stoffel_vm_types::core_types::Value {
    use stoffel_vm_types::core_types::{Value, BOOLEAN_SECRET_INT_BITS, F64};

    match ty {
        stoffel_vm_types::core_types::ShareType::SecretInt { bit_length }
            if bit_length == BOOLEAN_SECRET_INT_BITS =>
        {
            Value::Bool(!secret.is_zero())
        }
        stoffel_vm_types::core_types::ShareType::SecretInt { .. } => {
            Value::I64(field_to_i64(secret))
        }
        stoffel_vm_types::core_types::ShareType::SecretFixedPoint { precision } => {
            let scaled = field_to_i64(secret);
            let scale = (1u64 << precision.f()) as f64;
            Value::Float(F64(scaled as f64 / scale))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn parse_curve_names() {
        assert_eq!(
            MpcCurveConfig::from_str("bls12-381").unwrap(),
            MpcCurveConfig::Bls12_381
        );
        assert_eq!(
            MpcCurveConfig::from_str("bn254").unwrap(),
            MpcCurveConfig::Bn254
        );
        assert_eq!(
            MpcCurveConfig::from_str("curve25519").unwrap(),
            MpcCurveConfig::Curve25519
        );
        assert_eq!(
            MpcCurveConfig::from_str("ed25519").unwrap(),
            MpcCurveConfig::Ed25519
        );
        // Also works via str::parse()
        assert_eq!(
            "bn254".parse::<MpcCurveConfig>().unwrap(),
            MpcCurveConfig::Bn254
        );
    }

    #[test]
    fn reject_unknown_curve() {
        assert!(MpcCurveConfig::from_str("ristretto").is_err());
    }

    #[test]
    fn field_from_i64_positive() {
        type Fr = ark_bls12_381::Fr;
        assert_eq!(field_from_i64::<Fr>(0), Fr::from(0u64));
        assert_eq!(field_from_i64::<Fr>(1), Fr::from(1u64));
        assert_eq!(field_from_i64::<Fr>(42), Fr::from(42u64));
        assert_eq!(field_from_i64::<Fr>(i64::MAX), Fr::from(i64::MAX as u64));
    }

    #[test]
    fn field_from_i64_negative() {
        type Fr = ark_bls12_381::Fr;
        // -1 in the field should equal the additive inverse of 1
        assert_eq!(field_from_i64::<Fr>(-1), -Fr::from(1u64));
        assert_eq!(field_from_i64::<Fr>(-42), -Fr::from(42u64));
    }

    #[test]
    fn field_roundtrip_positive() {
        type Fr = ark_bls12_381::Fr;
        for v in [0i64, 1, 42, 1000, i64::MAX] {
            assert_eq!(
                field_to_i64(field_from_i64::<Fr>(v)),
                v,
                "roundtrip failed for {v}"
            );
        }
    }

    #[test]
    fn field_roundtrip_negative() {
        type Fr = ark_bls12_381::Fr;
        for v in [-1i64, -42, -1000, i64::MIN + 1] {
            assert_eq!(
                field_to_i64(field_from_i64::<Fr>(v)),
                v,
                "roundtrip failed for {v}"
            );
        }
    }

    #[test]
    #[cfg(feature = "avss")]
    fn avss_curve_compatibility() {
        assert!(MpcCurveConfig::Bls12_381
            .validate_for_backend(MpcBackendKind::Avss)
            .is_ok());
        assert!(MpcCurveConfig::Bn254
            .validate_for_backend(MpcBackendKind::Avss)
            .is_ok());
        assert!(MpcCurveConfig::Curve25519
            .validate_for_backend(MpcBackendKind::Avss)
            .is_ok());
    }
}
