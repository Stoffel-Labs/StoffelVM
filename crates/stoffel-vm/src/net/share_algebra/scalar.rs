use super::ops::{
    scalar_sub_share_typed, share_div_scalar_typed, share_scalar_op_typed, ShareScalarOp,
};
use super::{ShareAlgebraError, ShareAlgebraResult};
use crate::net::curve::MpcCurveConfig;
use stoffel_vm_types::core_types::ShareType;

#[inline]
pub(crate) fn scale_fixed_point_scalar(
    fractional_bits: usize,
    scalar: i64,
) -> ShareAlgebraResult<i64> {
    let shift =
        u32::try_from(fractional_bits).map_err(|_| ShareAlgebraError::FixedPointScaleOverflow)?;
    let scale = 1i128
        .checked_shl(shift)
        .ok_or(ShareAlgebraError::FixedPointScaleOverflow)?;
    let scaled = (scalar as i128)
        .checked_mul(scale)
        .ok_or(ShareAlgebraError::FixedPointScalarOverflow)?;
    i64::try_from(scaled).map_err(|_| ShareAlgebraError::FixedPointScalarOutOfRange)
}

pub(crate) fn add_share_scalar_for_curve(
    curve_config: MpcCurveConfig,
    ty: ShareType,
    share_bytes: &[u8],
    scalar: i64,
) -> ShareAlgebraResult<Vec<u8>> {
    match ty {
        ShareType::SecretInt { .. } => dispatch_share_curve_config!(
            curve_config,
            share_scalar_op_typed(share_bytes, scalar, ShareScalarOp::Add)
        ),
        ShareType::SecretFixedPoint { precision } => {
            let scaled_scalar = scale_fixed_point_scalar(precision.f(), scalar)?;
            dispatch_share_curve_config!(
                curve_config,
                share_scalar_op_typed(share_bytes, scaled_scalar, ShareScalarOp::Add)
            )
        }
    }
}

pub(crate) fn sub_share_scalar_for_curve(
    curve_config: MpcCurveConfig,
    ty: ShareType,
    share_bytes: &[u8],
    scalar: i64,
) -> ShareAlgebraResult<Vec<u8>> {
    match ty {
        ShareType::SecretInt { .. } => dispatch_share_curve_config!(
            curve_config,
            share_scalar_op_typed(share_bytes, scalar, ShareScalarOp::Sub)
        ),
        ShareType::SecretFixedPoint { precision } => {
            let scaled_scalar = scale_fixed_point_scalar(precision.f(), scalar)?;
            dispatch_share_curve_config!(
                curve_config,
                share_scalar_op_typed(share_bytes, scaled_scalar, ShareScalarOp::Sub)
            )
        }
    }
}

pub(crate) fn scalar_sub_share_for_curve(
    curve_config: MpcCurveConfig,
    ty: ShareType,
    scalar: i64,
    share_bytes: &[u8],
) -> ShareAlgebraResult<Vec<u8>> {
    match ty {
        ShareType::SecretInt { .. } => {
            dispatch_share_curve_config!(curve_config, scalar_sub_share_typed(scalar, share_bytes))
        }
        ShareType::SecretFixedPoint { precision } => {
            let scaled_scalar = scale_fixed_point_scalar(precision.f(), scalar)?;
            dispatch_share_curve_config!(
                curve_config,
                scalar_sub_share_typed(scaled_scalar, share_bytes)
            )
        }
    }
}

pub(crate) fn mul_share_scalar_for_curve(
    curve_config: MpcCurveConfig,
    ty: ShareType,
    share_bytes: &[u8],
    scalar: i64,
) -> ShareAlgebraResult<Vec<u8>> {
    match ty {
        ShareType::SecretInt { .. } | ShareType::SecretFixedPoint { .. } => {
            dispatch_share_curve_config!(
                curve_config,
                share_scalar_op_typed(share_bytes, scalar, ShareScalarOp::Mul)
            )
        }
    }
}

pub(crate) fn div_share_scalar_for_curve(
    curve_config: MpcCurveConfig,
    ty: ShareType,
    share_bytes: &[u8],
    scalar: i64,
) -> ShareAlgebraResult<Vec<u8>> {
    match ty {
        ShareType::SecretInt { .. } | ShareType::SecretFixedPoint { .. } => {
            dispatch_share_curve_config!(curve_config, share_div_scalar_typed(share_bytes, scalar))
        }
    }
}
