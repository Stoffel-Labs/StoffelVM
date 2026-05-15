//! Backend-oriented local arithmetic over serialized secret shares.
//!
//! These operations are local transformations on a party's share bytes. Keeping
//! them behind the MPC engine layer prevents the VM executor from knowing about
//! concrete share encodings.

macro_rules! dispatch_share_curve {
    ($field_kind:expr, $function:ident ( $($arg:expr),* $(,)? )) => {
        match $field_kind {
            crate::net::curve::MpcFieldKind::Bls12_381Fr => {
                $function::<ark_bls12_381::Fr, ark_bls12_381::G1Projective>($($arg),*)
            }
            crate::net::curve::MpcFieldKind::Bn254Fr => {
                $function::<ark_bn254::Fr, ark_bn254::G1Projective>($($arg),*)
            }
            crate::net::curve::MpcFieldKind::Curve25519Fr => {
                $function::<ark_curve25519::Fr, ark_curve25519::EdwardsProjective>($($arg),*)
            }
        }
    };
}

mod codec;
mod error;
mod interpolation;
mod ops;
mod scalar;

pub(crate) use codec::preserve_share_data_format;
pub use error::{ShareAlgebraError, ShareAlgebraResult};
pub(crate) use interpolation::interpolate_local;
pub(crate) use ops::{add_share, mul_share_field, neg_share, sub_share};
pub(crate) use scalar::{
    add_share_scalar, div_share_scalar, mul_share_scalar, scalar_sub_share, sub_share_scalar,
};

#[cfg(test)]
pub(crate) use scalar::scale_fixed_point_scalar;

#[cfg(test)]
mod tests;
