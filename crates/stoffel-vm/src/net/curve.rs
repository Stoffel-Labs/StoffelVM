//! Shared MPC curve and field configuration.
//!
//! This module centralizes curve parsing/validation across backends.

use crate::net::backend::MpcBackendKind;
use std::fmt;
use stoffel_vm_types::core_types::{
    ClearShareValue, FixedPointPrecision, ShareType, Value, BOOLEAN_SECRET_INT_BITS, F64,
};

pub type MpcCurveResult<T> = Result<T, MpcCurveError>;

/// Typed error surface for MPC curve and field conversion boundaries.
///
/// These helpers sit between backend field elements and VM values. Keeping the
/// failures structured lets engines and builtins preserve operational context
/// without parsing display strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MpcCurveError {
    UnknownCurve {
        name: String,
    },
    BackendCurveUnsupported {
        curve: MpcCurveConfig,
        backend: MpcBackendKind,
    },
    FieldElementBelowI64Min,
    FieldElementExceedsI64Max,
    FixedPointFractionalBitsTooLarge {
        fractional_bits: usize,
    },
    FixedPointScaleNotFinite {
        fractional_bits: usize,
    },
    FixedPointInputNotFinite {
        value: F64,
    },
    FixedPointScaledInputNotFinite {
        value: F64,
        precision: FixedPointPrecision,
    },
    FixedPointScaledInputOutOfI64Range {
        value: F64,
        precision: FixedPointPrecision,
    },
    RevealedValueShareTypeMismatch {
        share_type: ShareType,
        value: Value,
    },
}

impl fmt::Display for MpcCurveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MpcCurveError::UnknownCurve { name } => write!(
                f,
                "Unknown MPC curve '{name}'. Supported curves: bls12-381, bn254, curve25519, ed25519"
            ),
            MpcCurveError::BackendCurveUnsupported { curve, backend } => write!(
                f,
                "MPC curve '{}' is not supported by {} backend",
                curve.name(),
                backend.name()
            ),
            MpcCurveError::FieldElementBelowI64Min => {
                write!(f, "Field element is below i64::MIN")
            }
            MpcCurveError::FieldElementExceedsI64Max => {
                write!(f, "Field element exceeds i64::MAX")
            }
            MpcCurveError::FixedPointFractionalBitsTooLarge { .. } => {
                write!(f, "Fixed-point fractional bit count is too large")
            }
            MpcCurveError::FixedPointScaleNotFinite { .. } => {
                write!(f, "Fixed-point scale is not finite")
            }
            MpcCurveError::FixedPointInputNotFinite { .. } => {
                write!(f, "Fixed-point input must be finite")
            }
            MpcCurveError::FixedPointScaledInputNotFinite { .. } => {
                write!(f, "Fixed-point scaled input is not finite")
            }
            MpcCurveError::FixedPointScaledInputOutOfI64Range { .. } => {
                write!(f, "Fixed-point scaled input exceeds i64 range")
            }
            MpcCurveError::RevealedValueShareTypeMismatch { share_type, value } => {
                write!(
                    f,
                    "Revealed value {value:?} is not valid for share type {share_type:?}"
                )
            }
        }
    }
}

impl std::error::Error for MpcCurveError {}

impl From<MpcCurveError> for String {
    fn from(error: MpcCurveError) -> Self {
        error.to_string()
    }
}

/// Curated set of MPC curves supported by the VM.
///
/// Ed25519 and Curve25519 share the same scalar field (`ark_curve25519::Fr`).
/// At the type level `ark_ed25519::Fr` is a re-export of `ark_curve25519::Fr`,
/// so `SupportedMpcField` is implemented once and covers both curves.
/// `curve_config()` on an Ed25519 engine will report `Curve25519` because the
/// field is identical; use the server / CLI `--mpc-curve` flag to distinguish
/// intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum MpcCurveConfig {
    #[default]
    Bls12_381,
    Bn254,
    Curve25519,
    /// Ed25519 uses the same scalar field as Curve25519.
    /// See enum-level docs for details.
    Ed25519,
}

impl std::str::FromStr for MpcCurveConfig {
    type Err = MpcCurveError;

    /// Parse a curve name (case-insensitive with common aliases).
    fn from_str(input: &str) -> MpcCurveResult<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "bls12-381" | "bls12_381" | "bls12381" => Ok(Self::Bls12_381),
            "bn254" => Ok(Self::Bn254),
            "curve25519" | "curve-25519" => Ok(Self::Curve25519),
            "ed25519" | "ed-25519" => Ok(Self::Ed25519),
            other => Err(MpcCurveError::UnknownCurve {
                name: other.to_string(),
            }),
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
    pub fn validate_for_backend(self, _backend: MpcBackendKind) -> MpcCurveResult<()> {
        Ok(())
    }
}

/// Field-dispatch metadata for VM-local share math.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
        -F::from(value.unsigned_abs())
    }
}

fn bigint_to_single_limb_u64<B: AsRef<[u64]>>(value: &B) -> Option<u64> {
    let limbs = value.as_ref();
    if limbs.iter().skip(1).any(|limb| *limb != 0) {
        return None;
    }

    Some(limbs.first().copied().unwrap_or(0))
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
pub fn field_to_i64<F: ark_ff::PrimeField>(value: F) -> MpcCurveResult<i64> {
    let bigint = value.into_bigint();

    // Check if the element is in the upper half of the field (i.e. represents a negative value).
    // We do this by comparing with (p-1)/2.  For a negative value -x, the field
    // representation is p - x, which is > (p-1)/2 when x > 0.
    let neg = (-value).into_bigint();

    // If the negation is smaller (fits in fewer limbs / smaller lowest limb),
    // the original element was in the upper half → negative.
    // We compare full bigints to be safe.
    if !value.is_zero() && neg < bigint {
        let magnitude =
            bigint_to_single_limb_u64(&neg).ok_or(MpcCurveError::FieldElementBelowI64Min)?;
        if magnitude == (1u64 << 63) {
            Ok(i64::MIN)
        } else {
            let magnitude =
                i64::try_from(magnitude).map_err(|_| MpcCurveError::FieldElementBelowI64Min)?;
            Ok(-magnitude)
        }
    } else {
        let raw =
            bigint_to_single_limb_u64(&bigint).ok_or(MpcCurveError::FieldElementExceedsI64Max)?;
        i64::try_from(raw).map_err(|_| MpcCurveError::FieldElementExceedsI64Max)
    }
}

pub fn fixed_point_scale_as_f64(fractional_bits: usize) -> MpcCurveResult<f64> {
    let exponent = i32::try_from(fractional_bits)
        .map_err(|_| MpcCurveError::FixedPointFractionalBitsTooLarge { fractional_bits })?;
    let scale = 2f64.powi(exponent);
    if !scale.is_finite() {
        return Err(MpcCurveError::FixedPointScaleNotFinite { fractional_bits });
    }

    Ok(scale)
}

pub fn fixed_point_float_to_i64(precision: FixedPointPrecision, value: F64) -> MpcCurveResult<i64> {
    if !value.0.is_finite() {
        return Err(MpcCurveError::FixedPointInputNotFinite { value });
    }

    let scale = fixed_point_scale_as_f64(precision.f())?;
    let scaled = value.0 * scale;
    if !scaled.is_finite() {
        return Err(MpcCurveError::FixedPointScaledInputNotFinite { value, precision });
    }

    let truncated = scaled.trunc();
    const I64_MAX_EXCLUSIVE_AS_F64: f64 = 9_223_372_036_854_775_808.0;
    if truncated < i64::MIN as f64 || truncated >= I64_MAX_EXCLUSIVE_AS_F64 {
        return Err(MpcCurveError::FixedPointScaledInputOutOfI64Range { value, precision });
    }

    Ok(truncated as i64)
}

/// Convert a reconstructed field element to the canonical clear value for a
/// given [`ShareType`].
///
/// Used by both the HoneyBadger and AVSS engines after secret reconstruction.
pub fn field_to_clear_share_value<F: ark_ff::PrimeField>(
    ty: ShareType,
    secret: F,
) -> MpcCurveResult<ClearShareValue> {
    match ty {
        ShareType::SecretInt { bit_length } if bit_length == BOOLEAN_SECRET_INT_BITS => {
            Ok(ClearShareValue::Boolean(!secret.is_zero()))
        }
        ShareType::SecretInt { .. } => Ok(ClearShareValue::Integer(field_to_i64(secret)?)),
        ShareType::SecretFixedPoint { precision } => {
            let scaled = field_to_i64(secret)?;
            let scale = fixed_point_scale_as_f64(precision.f())?;
            Ok(ClearShareValue::FixedPoint(F64(scaled as f64 / scale)))
        }
    }
}

/// Convert a reconstructed field element to the appropriate [`Value`] for a
/// given [`ShareType`].
pub fn field_to_value<F: ark_ff::PrimeField>(ty: ShareType, secret: F) -> MpcCurveResult<Value> {
    field_to_clear_share_value(ty, secret).map(ClearShareValue::into_vm_value)
}

pub fn revealed_value_to_clear_share_value(
    ty: ShareType,
    value: Value,
) -> MpcCurveResult<ClearShareValue> {
    match (ty, value) {
        (ShareType::SecretInt { bit_length }, Value::Bool(value))
            if bit_length == BOOLEAN_SECRET_INT_BITS =>
        {
            Ok(ClearShareValue::Boolean(value))
        }
        (ShareType::SecretInt { bit_length }, Value::I64(value))
            if bit_length != BOOLEAN_SECRET_INT_BITS =>
        {
            Ok(ClearShareValue::Integer(value))
        }
        (ShareType::SecretFixedPoint { .. }, Value::Float(value)) => {
            Ok(ClearShareValue::FixedPoint(value))
        }
        (share_type, value) => {
            Err(MpcCurveError::RevealedValueShareTypeMismatch { share_type, value })
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
        assert_eq!(
            MpcCurveConfig::from_str("ristretto").unwrap_err(),
            MpcCurveError::UnknownCurve {
                name: "ristretto".to_string()
            }
        );
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
                field_to_i64(field_from_i64::<Fr>(v)).expect("decode field value"),
                v,
                "roundtrip failed for {v}"
            );
        }
    }

    #[test]
    fn field_roundtrip_negative() {
        type Fr = ark_bls12_381::Fr;
        for v in [-1i64, -42, -1000, i64::MIN + 1, i64::MIN] {
            assert_eq!(
                field_to_i64(field_from_i64::<Fr>(v)).expect("decode field value"),
                v,
                "roundtrip failed for {v}"
            );
        }
    }

    #[test]
    fn field_to_i64_rejects_unrepresentable_positive_value() {
        type Fr = ark_bls12_381::Fr;
        let value = Fr::from(1u64 << 63);

        assert_eq!(
            field_to_i64(value).unwrap_err(),
            MpcCurveError::FieldElementExceedsI64Max
        );
    }

    #[test]
    fn fixed_point_float_to_i64_rejects_non_finite_values() {
        let precision = FixedPointPrecision::new(64, 16);

        assert_eq!(
            fixed_point_float_to_i64(precision, F64(f64::NAN)).unwrap_err(),
            MpcCurveError::FixedPointInputNotFinite {
                value: F64(f64::NAN)
            }
        );
        assert_eq!(
            fixed_point_float_to_i64(precision, F64(f64::INFINITY)).unwrap_err(),
            MpcCurveError::FixedPointInputNotFinite {
                value: F64(f64::INFINITY)
            }
        );
        assert_eq!(
            fixed_point_float_to_i64(precision, F64(f64::NEG_INFINITY)).unwrap_err(),
            MpcCurveError::FixedPointInputNotFinite {
                value: F64(f64::NEG_INFINITY)
            }
        );
    }

    #[test]
    fn fixed_point_float_to_i64_rejects_values_outside_i64_range() {
        let precision = FixedPointPrecision::new(64, 0);

        assert_eq!(
            fixed_point_float_to_i64(precision, F64(i64::MAX as f64)).unwrap_err(),
            MpcCurveError::FixedPointScaledInputOutOfI64Range {
                value: F64(i64::MAX as f64),
                precision,
            }
        );
        assert_eq!(
            fixed_point_float_to_i64(precision, F64((i64::MIN as f64) - 2048.0)).unwrap_err(),
            MpcCurveError::FixedPointScaledInputOutOfI64Range {
                value: F64((i64::MIN as f64) - 2048.0),
                precision,
            }
        );
    }

    #[test]
    fn field_to_value_rejects_unrepresentable_fixed_point_scale() {
        type Fr = ark_bls12_381::Fr;
        let ty = ShareType::secret_fixed_point_from_bits(2049, 2048);

        assert_eq!(
            field_to_value::<Fr>(ty, Fr::from(1u64)).unwrap_err(),
            MpcCurveError::FixedPointScaleNotFinite {
                fractional_bits: 2048
            }
        );
    }

    #[test]
    fn revealed_value_to_clear_share_value_enforces_share_type() {
        let boolean_ty = ShareType::SecretInt {
            bit_length: BOOLEAN_SECRET_INT_BITS,
        };
        let integer_ty = ShareType::SecretInt { bit_length: 64 };
        let fixed_ty = ShareType::secret_fixed_point_from_bits(64, 16);

        assert_eq!(
            revealed_value_to_clear_share_value(boolean_ty, Value::Bool(true)).unwrap(),
            ClearShareValue::Boolean(true)
        );
        assert_eq!(
            revealed_value_to_clear_share_value(integer_ty, Value::I64(-17)).unwrap(),
            ClearShareValue::Integer(-17)
        );
        assert_eq!(
            revealed_value_to_clear_share_value(fixed_ty, Value::Float(F64(3.25))).unwrap(),
            ClearShareValue::FixedPoint(F64(3.25))
        );

        assert_eq!(
            revealed_value_to_clear_share_value(boolean_ty, Value::I64(1)).unwrap_err(),
            MpcCurveError::RevealedValueShareTypeMismatch {
                share_type: boolean_ty,
                value: Value::I64(1),
            }
        );
        assert_eq!(
            revealed_value_to_clear_share_value(integer_ty, Value::Bool(true)).unwrap_err(),
            MpcCurveError::RevealedValueShareTypeMismatch {
                share_type: integer_ty,
                value: Value::Bool(true),
            }
        );
        assert_eq!(
            revealed_value_to_clear_share_value(fixed_ty, Value::I64(3)).unwrap_err(),
            MpcCurveError::RevealedValueShareTypeMismatch {
                share_type: fixed_ty,
                value: Value::I64(3),
            }
        );
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
