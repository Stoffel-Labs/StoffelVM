//! Backend-oriented local arithmetic over serialized secret shares.
//!
//! These operations are local transformations on a party's share bytes. Keeping
//! them behind the MPC engine layer prevents the VM executor from knowing about
//! concrete share encodings.

macro_rules! dispatch_share_curve_config {
    ($curve_config:expr, $function:ident ( $($arg:expr),* $(,)? )) => {
        match $curve_config {
            crate::net::curve::MpcCurveConfig::Bls12_381 => {
                $function::<ark_bls12_381::Fr, ark_bls12_381::G1Projective>($($arg),*)
            }
            crate::net::curve::MpcCurveConfig::Bn254 => {
                $function::<ark_bn254::Fr, ark_bn254::G1Projective>($($arg),*)
            }
            crate::net::curve::MpcCurveConfig::Curve25519 => {
                $function::<ark_curve25519::Fr, ark_curve25519::EdwardsProjective>($($arg),*)
            }
            crate::net::curve::MpcCurveConfig::Ed25519 => {
                $function::<ark_ed25519::Fr, ark_ed25519::EdwardsProjective>($($arg),*)
            }
        }
    };
}

mod codec;
mod error;
mod interpolation;
mod ops;
mod scalar;

pub(crate) use codec::preserve_share_data_format_for_curve;
pub use error::{ShareAlgebraError, ShareAlgebraResult};
pub(crate) use interpolation::interpolate_local_for_curve;
pub(crate) use ops::{
    add_share_for_curve, mul_share_field_for_curve, neg_share_for_curve, sub_share_for_curve,
};
pub(crate) use scalar::{
    add_share_scalar_for_curve, div_share_scalar_for_curve, mul_share_scalar_for_curve,
    scalar_sub_share_for_curve, sub_share_scalar_for_curve,
};

#[cfg(test)]
pub(crate) use scalar::scale_fixed_point_scalar;

#[cfg(test)]
mod tests;
