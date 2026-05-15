use super::codec::{
    decode_share_bytes_typed, encode_share_bytes_typed, format_name, DecodedShare, LocalShareFormat,
};
use super::{ShareAlgebraError, ShareAlgebraResult};
use ark_ec::CurveGroup;
use ark_ff::{FftField, PrimeField};
use stoffel_vm_types::core_types::ShareType;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

use crate::net::curve::{field_from_i64, MpcFieldKind};

#[derive(Debug, Clone, Copy)]
enum ShareBinaryOp {
    Add,
    Sub,
}

#[derive(Debug, Clone, Copy)]
enum ShareUnaryOp {
    Neg,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum ShareScalarOp {
    Add,
    Sub,
    Mul,
}

pub(crate) fn add_share(
    field_kind: MpcFieldKind,
    _ty: ShareType,
    lhs_bytes: &[u8],
    rhs_bytes: &[u8],
) -> ShareAlgebraResult<Vec<u8>> {
    dispatch_share_curve!(
        field_kind,
        share_binary_op_typed(lhs_bytes, rhs_bytes, ShareBinaryOp::Add)
    )
}

pub(crate) fn sub_share(
    field_kind: MpcFieldKind,
    _ty: ShareType,
    lhs_bytes: &[u8],
    rhs_bytes: &[u8],
) -> ShareAlgebraResult<Vec<u8>> {
    dispatch_share_curve!(
        field_kind,
        share_binary_op_typed(lhs_bytes, rhs_bytes, ShareBinaryOp::Sub)
    )
}

pub(crate) fn neg_share(
    field_kind: MpcFieldKind,
    _ty: ShareType,
    share_bytes: &[u8],
) -> ShareAlgebraResult<Vec<u8>> {
    dispatch_share_curve!(
        field_kind,
        share_unary_op_typed(share_bytes, ShareUnaryOp::Neg)
    )
}

pub(crate) fn mul_share_field(
    field_kind: MpcFieldKind,
    _ty: ShareType,
    share_bytes: &[u8],
    scalar_bytes: &[u8],
) -> ShareAlgebraResult<Vec<u8>> {
    dispatch_share_curve!(field_kind, share_field_mul_typed(share_bytes, scalar_bytes))
}

pub(super) fn share_scalar_op_typed<F, G>(
    share_bytes: &[u8],
    scalar: i64,
    op: ShareScalarOp,
) -> ShareAlgebraResult<Vec<u8>>
where
    F: FftField + PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    let share = decode_share_bytes_typed::<F, G>(share_bytes)?;
    let scalar_f = field_from_i64::<F>(scalar);
    match share {
        DecodedShare::Robust(share) => {
            let value = match op {
                ShareScalarOp::Add => share.share[0] + scalar_f,
                ShareScalarOp::Sub => share.share[0] - scalar_f,
                ShareScalarOp::Mul => share.share[0] * scalar_f,
            };
            let new_share = RobustShare::new(value, share.id, share.degree);
            encode_share_bytes_typed(&new_share)
        }
        DecodedShare::Feldman(share) => {
            let new_share = match op {
                ShareScalarOp::Add => (share + scalar_f).map_err(|e| {
                    ShareAlgebraError::feldman_operation("add scalar to Feldman share", e)
                })?,
                ShareScalarOp::Sub => (share - scalar_f).map_err(|e| {
                    ShareAlgebraError::feldman_operation("subtract scalar from Feldman share", e)
                })?,
                ShareScalarOp::Mul => (share * scalar_f).map_err(|e| {
                    ShareAlgebraError::feldman_operation("multiply Feldman share by scalar", e)
                })?,
            };
            encode_share_bytes_typed(&new_share)
        }
    }
}

pub(super) fn scalar_sub_share_typed<F, G>(
    scalar: i64,
    share_bytes: &[u8],
) -> ShareAlgebraResult<Vec<u8>>
where
    F: FftField + PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    let share = decode_share_bytes_typed::<F, G>(share_bytes)?;
    let scalar_f = field_from_i64::<F>(scalar);
    match share {
        DecodedShare::Robust(share) => {
            let new_share = RobustShare::new(scalar_f - share.share[0], share.id, share.degree);
            encode_share_bytes_typed(&new_share)
        }
        DecodedShare::Feldman(share) => {
            let negated = (share * -F::from(1u64))
                .map_err(|e| ShareAlgebraError::feldman_operation("negate Feldman share", e))?;
            let new_share = (negated + scalar_f).map_err(|e| {
                ShareAlgebraError::feldman_operation("subtract Feldman share from scalar", e)
            })?;
            encode_share_bytes_typed(&new_share)
        }
    }
}

pub(super) fn share_div_scalar_typed<F, G>(
    share_bytes: &[u8],
    scalar: i64,
) -> ShareAlgebraResult<Vec<u8>>
where
    F: FftField + PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    if scalar == 0 {
        return Err(ShareAlgebraError::DivisionByZero);
    }

    let share = decode_share_bytes_typed::<F, G>(share_bytes)?;
    let scalar_f = field_from_i64::<F>(scalar);
    let scalar_inv = scalar_f
        .inverse()
        .ok_or(ShareAlgebraError::ScalarHasNoInverse)?;
    match share {
        DecodedShare::Robust(share) => {
            let new_share = RobustShare::new(share.share[0] * scalar_inv, share.id, share.degree);
            encode_share_bytes_typed(&new_share)
        }
        DecodedShare::Feldman(share) => {
            let new_share = (share * scalar_inv).map_err(|e| {
                ShareAlgebraError::feldman_operation("divide Feldman share by scalar", e)
            })?;
            encode_share_bytes_typed(&new_share)
        }
    }
}

fn share_binary_op_typed<F, G>(
    lhs_bytes: &[u8],
    rhs_bytes: &[u8],
    op: ShareBinaryOp,
) -> ShareAlgebraResult<Vec<u8>>
where
    F: FftField + PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    let lhs = decode_share_bytes_typed::<F, G>(lhs_bytes)?;
    let rhs = decode_share_bytes_typed::<F, G>(rhs_bytes)?;

    match (lhs, rhs) {
        (DecodedShare::Robust(lhs), DecodedShare::Robust(rhs)) => {
            if lhs.id != rhs.id || lhs.degree != rhs.degree {
                return Err(ShareAlgebraError::ShareMetadataMismatch);
            }

            let value = match op {
                ShareBinaryOp::Add => lhs.share[0] + rhs.share[0],
                ShareBinaryOp::Sub => lhs.share[0] - rhs.share[0],
            };
            let new_share = RobustShare::new(value, lhs.id, lhs.degree);
            encode_share_bytes_typed(&new_share)
        }
        (DecodedShare::Feldman(lhs), DecodedShare::Feldman(rhs)) => {
            let new_share = match op {
                ShareBinaryOp::Add => (lhs + rhs)
                    .map_err(|e| ShareAlgebraError::feldman_operation("add Feldman shares", e))?,
                ShareBinaryOp::Sub => (lhs - rhs).map_err(|e| {
                    ShareAlgebraError::feldman_operation("subtract Feldman shares", e)
                })?,
            };
            encode_share_bytes_typed(&new_share)
        }
        (DecodedShare::Robust(_), DecodedShare::Feldman(_)) => {
            Err(ShareAlgebraError::ShareFormatMismatch {
                left: format_name(LocalShareFormat::Robust),
                right: format_name(LocalShareFormat::Feldman),
            })
        }
        (DecodedShare::Feldman(_), DecodedShare::Robust(_)) => {
            Err(ShareAlgebraError::ShareFormatMismatch {
                left: format_name(LocalShareFormat::Feldman),
                right: format_name(LocalShareFormat::Robust),
            })
        }
    }
}

fn share_unary_op_typed<F, G>(share_bytes: &[u8], op: ShareUnaryOp) -> ShareAlgebraResult<Vec<u8>>
where
    F: FftField + PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    let share = decode_share_bytes_typed::<F, G>(share_bytes)?;
    match share {
        DecodedShare::Robust(share) => {
            let value = match op {
                ShareUnaryOp::Neg => -share.share[0],
            };
            let new_share = RobustShare::new(value, share.id, share.degree);
            encode_share_bytes_typed(&new_share)
        }
        DecodedShare::Feldman(share) => {
            let scalar = match op {
                ShareUnaryOp::Neg => -F::from(1u64),
            };
            let new_share = (share * scalar)
                .map_err(|e| ShareAlgebraError::feldman_operation("negate Feldman share", e))?;
            encode_share_bytes_typed(&new_share)
        }
    }
}

fn share_field_mul_typed<F, G>(
    share_bytes: &[u8],
    scalar_bytes: &[u8],
) -> ShareAlgebraResult<Vec<u8>>
where
    F: FftField + PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    let share = decode_share_bytes_typed::<F, G>(share_bytes)?;
    let scalar_f = F::deserialize_compressed(scalar_bytes).map_err(|e| {
        ShareAlgebraError::FieldElementDecode {
            source: e.to_string(),
        }
    })?;
    match share {
        DecodedShare::Robust(share) => {
            let new_share = RobustShare::new(share.share[0] * scalar_f, share.id, share.degree);
            encode_share_bytes_typed(&new_share)
        }
        DecodedShare::Feldman(share) => {
            let new_share = (share * scalar_f).map_err(|e| {
                ShareAlgebraError::feldman_operation("multiply Feldman share by field element", e)
            })?;
            encode_share_bytes_typed(&new_share)
        }
    }
}
