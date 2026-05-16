use super::ops::{
    scalar_sub_share_typed, share_div_scalar_typed, share_scalar_op_typed, ShareScalarOp,
};
use super::{ShareAlgebraError, ShareAlgebraResult};
use crate::net::curve::MpcFieldKind;
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

pub(crate) fn add_share_scalar(
    field_kind: MpcFieldKind,
    ty: ShareType,
    share_bytes: &[u8],
    scalar: i64,
) -> ShareAlgebraResult<Vec<u8>> {
    match ty {
        ShareType::SecretInt { .. } => secret_int_add_scalar(field_kind, share_bytes, scalar),
        ShareType::SecretFixedPoint { .. } => {
            secret_fixed_point_add_scalar(field_kind, ty, share_bytes, scalar)
        }
    }
}

pub(crate) fn sub_share_scalar(
    field_kind: MpcFieldKind,
    ty: ShareType,
    share_bytes: &[u8],
    scalar: i64,
) -> ShareAlgebraResult<Vec<u8>> {
    match ty {
        ShareType::SecretInt { .. } => secret_int_sub_scalar(field_kind, share_bytes, scalar),
        ShareType::SecretFixedPoint { .. } => {
            secret_fixed_point_sub_scalar(field_kind, ty, share_bytes, scalar)
        }
    }
}

pub(crate) fn scalar_sub_share(
    field_kind: MpcFieldKind,
    ty: ShareType,
    scalar: i64,
    share_bytes: &[u8],
) -> ShareAlgebraResult<Vec<u8>> {
    match ty {
        ShareType::SecretInt { .. } => scalar_sub_secret_int(field_kind, scalar, share_bytes),
        ShareType::SecretFixedPoint { .. } => {
            scalar_sub_secret_fixed_point(field_kind, ty, scalar, share_bytes)
        }
    }
}

pub(crate) fn mul_share_scalar(
    field_kind: MpcFieldKind,
    ty: ShareType,
    share_bytes: &[u8],
    scalar: i64,
) -> ShareAlgebraResult<Vec<u8>> {
    match ty {
        ShareType::SecretInt { .. } => secret_int_mul_scalar(field_kind, share_bytes, scalar),
        ShareType::SecretFixedPoint { .. } => {
            secret_fixed_point_mul_scalar(field_kind, share_bytes, scalar)
        }
    }
}

pub(crate) fn div_share_scalar(
    field_kind: MpcFieldKind,
    ty: ShareType,
    share_bytes: &[u8],
    scalar: i64,
) -> ShareAlgebraResult<Vec<u8>> {
    match ty {
        ShareType::SecretInt { .. } => secret_int_div_scalar(field_kind, share_bytes, scalar),
        ShareType::SecretFixedPoint { .. } => {
            secret_fixed_point_div_scalar(field_kind, share_bytes, scalar)
        }
    }
}

fn secret_int_add_scalar(
    field_kind: MpcFieldKind,
    share_bytes: &[u8],
    scalar: i64,
) -> ShareAlgebraResult<Vec<u8>> {
    dispatch_share_curve!(
        field_kind,
        share_scalar_op_typed(share_bytes, scalar, ShareScalarOp::Add)
    )
}

fn secret_int_sub_scalar(
    field_kind: MpcFieldKind,
    share_bytes: &[u8],
    scalar: i64,
) -> ShareAlgebraResult<Vec<u8>> {
    dispatch_share_curve!(
        field_kind,
        share_scalar_op_typed(share_bytes, scalar, ShareScalarOp::Sub)
    )
}

fn scalar_sub_secret_int(
    field_kind: MpcFieldKind,
    scalar: i64,
    share_bytes: &[u8],
) -> ShareAlgebraResult<Vec<u8>> {
    dispatch_share_curve!(field_kind, scalar_sub_share_typed(scalar, share_bytes))
}

fn secret_int_mul_scalar(
    field_kind: MpcFieldKind,
    share_bytes: &[u8],
    scalar: i64,
) -> ShareAlgebraResult<Vec<u8>> {
    dispatch_share_curve!(
        field_kind,
        share_scalar_op_typed(share_bytes, scalar, ShareScalarOp::Mul)
    )
}

fn secret_int_div_scalar(
    field_kind: MpcFieldKind,
    share_bytes: &[u8],
    scalar: i64,
) -> ShareAlgebraResult<Vec<u8>> {
    dispatch_share_curve!(field_kind, share_div_scalar_typed(share_bytes, scalar))
}

fn secret_fixed_point_add_scalar(
    field_kind: MpcFieldKind,
    ty: ShareType,
    share_bytes: &[u8],
    scalar: i64,
) -> ShareAlgebraResult<Vec<u8>> {
    let precision = match ty {
        ShareType::SecretFixedPoint { precision } => precision,
        _ => return Err(ShareAlgebraError::ExpectedFixedPointShareType),
    };
    let scaled_scalar = scale_fixed_point_scalar(precision.f(), scalar)?;
    dispatch_share_curve!(
        field_kind,
        share_scalar_op_typed(share_bytes, scaled_scalar, ShareScalarOp::Add)
    )
}

fn secret_fixed_point_sub_scalar(
    field_kind: MpcFieldKind,
    ty: ShareType,
    share_bytes: &[u8],
    scalar: i64,
) -> ShareAlgebraResult<Vec<u8>> {
    let precision = match ty {
        ShareType::SecretFixedPoint { precision } => precision,
        _ => return Err(ShareAlgebraError::ExpectedFixedPointShareType),
    };
    let scaled_scalar = scale_fixed_point_scalar(precision.f(), scalar)?;
    dispatch_share_curve!(
        field_kind,
        share_scalar_op_typed(share_bytes, scaled_scalar, ShareScalarOp::Sub)
    )
}

fn scalar_sub_secret_fixed_point(
    field_kind: MpcFieldKind,
    ty: ShareType,
    scalar: i64,
    share_bytes: &[u8],
) -> ShareAlgebraResult<Vec<u8>> {
    let precision = match ty {
        ShareType::SecretFixedPoint { precision } => precision,
        _ => return Err(ShareAlgebraError::ExpectedFixedPointShareType),
    };
    let scaled_scalar = scale_fixed_point_scalar(precision.f(), scalar)?;
    dispatch_share_curve!(
        field_kind,
        scalar_sub_share_typed(scaled_scalar, share_bytes)
    )
}

fn secret_fixed_point_mul_scalar(
    field_kind: MpcFieldKind,
    share_bytes: &[u8],
    scalar: i64,
) -> ShareAlgebraResult<Vec<u8>> {
    dispatch_share_curve!(
        field_kind,
        share_scalar_op_typed(share_bytes, scalar, ShareScalarOp::Mul)
    )
}

fn secret_fixed_point_div_scalar(
    field_kind: MpcFieldKind,
    share_bytes: &[u8],
    scalar: i64,
) -> ShareAlgebraResult<Vec<u8>> {
    dispatch_share_curve!(field_kind, share_div_scalar_typed(share_bytes, scalar))
}
