//! Checked conversion between semantic numeric values and VM fixed-point units.
//!
//! This module is intentionally field-agnostic. Client boundaries use it before
//! mapping the resulting signed integer into the selected MPC field.

use std::fmt;

use crate::core_types::FixedPointPrecision;

#[derive(Debug, Clone, PartialEq)]
pub enum FixedPointCodecError {
    FractionalBitsTooLarge { fractional_bits: usize },
    ScaleNotFinite { fractional_bits: usize },
    InputNotFinite,
    ScalingOverflow,
    SignedEncodingOutOfRange,
    DeclaredPrecisionOutOfRange { encoded: i128, total_bits: usize },
}

impl fmt::Display for FixedPointCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FractionalBitsTooLarge { fractional_bits } => write!(
                formatter,
                "fixed-point fractional-bit count {fractional_bits} is too large"
            ),
            Self::ScaleNotFinite { fractional_bits } => write!(
                formatter,
                "fixed-point scale for {fractional_bits} fractional bits is not finite"
            ),
            Self::InputNotFinite => write!(formatter, "fixed-point client input must be finite"),
            Self::ScalingOverflow => {
                write!(
                    formatter,
                    "fixed-point client input overflows during scaling"
                )
            }
            Self::SignedEncodingOutOfRange => write!(
                formatter,
                "fixed-point client input is outside the VM's signed 64-bit encoded range"
            ),
            Self::DeclaredPrecisionOutOfRange {
                encoded,
                total_bits,
            } => write!(
                formatter,
                "fixed-point client input encodes to {encoded}, outside the signed {total_bits}-bit range"
            ),
        }
    }
}

impl std::error::Error for FixedPointCodecError {}

pub fn encode_fixed_point_integer(
    value: i128,
    precision: FixedPointPrecision,
) -> Result<i64, FixedPointCodecError> {
    let shift = u32::try_from(precision.fractional_bits()).map_err(|_| {
        FixedPointCodecError::FractionalBitsTooLarge {
            fractional_bits: precision.fractional_bits(),
        }
    })?;
    let scale = 1_i128.checked_shl(shift).filter(|scale| *scale > 0).ok_or(
        FixedPointCodecError::FractionalBitsTooLarge {
            fractional_bits: precision.fractional_bits(),
        },
    )?;
    let encoded = value
        .checked_mul(scale)
        .ok_or(FixedPointCodecError::ScalingOverflow)?;
    checked_fixed_point_encoding(encoded, precision)
}

pub fn encode_fixed_point_float(
    value: f64,
    precision: FixedPointPrecision,
) -> Result<i64, FixedPointCodecError> {
    if !value.is_finite() {
        return Err(FixedPointCodecError::InputNotFinite);
    }

    let scaled = value * fixed_point_scale(precision)?;
    if !scaled.is_finite() {
        return Err(FixedPointCodecError::ScalingOverflow);
    }

    let rounded = scaled.round();
    const I64_MIN_AS_F64: f64 = -9_223_372_036_854_775_808.0;
    const I64_MAX_EXCLUSIVE_AS_F64: f64 = 9_223_372_036_854_775_808.0;
    if rounded < I64_MIN_AS_F64 || rounded >= I64_MAX_EXCLUSIVE_AS_F64 {
        return Err(FixedPointCodecError::SignedEncodingOutOfRange);
    }
    checked_fixed_point_encoding(i128::from(rounded as i64), precision)
}

pub fn decode_fixed_point_float(
    encoded: i64,
    precision: FixedPointPrecision,
) -> Result<f64, FixedPointCodecError> {
    Ok(encoded as f64 / fixed_point_scale(precision)?)
}

fn checked_fixed_point_encoding(
    encoded: i128,
    precision: FixedPointPrecision,
) -> Result<i64, FixedPointCodecError> {
    let total_bits = precision.total_bits();
    if total_bits < i128::BITS as usize {
        let magnitude_bits = u32::try_from(total_bits - 1)
            .map_err(|_| FixedPointCodecError::SignedEncodingOutOfRange)?;
        let magnitude = 1_i128
            .checked_shl(magnitude_bits)
            .ok_or(FixedPointCodecError::SignedEncodingOutOfRange)?;
        if encoded < -magnitude || encoded > magnitude - 1 {
            return Err(FixedPointCodecError::DeclaredPrecisionOutOfRange {
                encoded,
                total_bits,
            });
        }
    }
    i64::try_from(encoded).map_err(|_| FixedPointCodecError::SignedEncodingOutOfRange)
}

fn fixed_point_scale(precision: FixedPointPrecision) -> Result<f64, FixedPointCodecError> {
    let exponent = i32::try_from(precision.fractional_bits()).map_err(|_| {
        FixedPointCodecError::FractionalBitsTooLarge {
            fractional_bits: precision.fractional_bits(),
        }
    })?;
    let scale = 2f64.powi(exponent);
    if !scale.is_finite() {
        return Err(FixedPointCodecError::ScaleNotFinite {
            fractional_bits: precision.fractional_bits(),
        });
    }
    Ok(scale)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_values_use_declared_precision() {
        let precision = FixedPointPrecision::new(64, 16);

        assert_eq!(encode_fixed_point_integer(1, precision).unwrap(), 65_536);
        assert_eq!(encode_fixed_point_float(1.5, precision).unwrap(), 98_304);
        assert_eq!(encode_fixed_point_integer(-2, precision).unwrap(), -131_072);
        assert_eq!(decode_fixed_point_float(-32_768, precision).unwrap(), -0.5);
    }

    #[test]
    fn invalid_values_and_declared_overflow_are_rejected() {
        let precision = FixedPointPrecision::new(32, 16);

        assert!(encode_fixed_point_float(f64::NAN, precision).is_err());
        assert!(encode_fixed_point_integer(32_768, precision).is_err());
    }
}
