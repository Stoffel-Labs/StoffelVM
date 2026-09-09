use super::codec::{decode_share_bytes_typed, DecodedShare, LocalShareFormat};
use super::{ShareAlgebraError, ShareAlgebraResult};
use ark_ec::CurveGroup;
use ark_ff::{FftField, PrimeField};
use stoffel_vm_types::core_types::{ShareType, Value, F64};
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::common::SecretSharingScheme;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

use crate::net::curve::{
    clear_share_value_to_vm_value, field_to_i64, field_to_wrapping_secret_int,
    field_to_wrapping_secret_uint, fixed_point_scale_as_f64, MpcCurveConfig,
};
use stoffel_vm_types::core_types::ClearShareValue;

pub(crate) fn interpolate_local_for_curve(
    curve_config: MpcCurveConfig,
    ty: ShareType,
    shares: &[Vec<u8>],
    n_parties: usize,
    threshold: usize,
) -> ShareAlgebraResult<Value> {
    if shares.is_empty() {
        return Err(ShareAlgebraError::InterpolationEmpty);
    }

    dispatch_share_curve_config!(
        curve_config,
        share_interpolate_local_typed(ty, shares, n_parties, threshold)
    )
}

fn share_interpolate_local_typed<F, G>(
    ty: ShareType,
    shares: &[Vec<u8>],
    n_parties: usize,
    threshold: usize,
) -> ShareAlgebraResult<Value>
where
    F: FftField + PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    let mut robust_shares: Vec<RobustShare<F>> = Vec::with_capacity(shares.len());
    let mut feldman_shares: Vec<FeldmanShamirShare<F, G>> = Vec::with_capacity(shares.len());
    let mut format = None;
    for (i, share_bytes) in shares.iter().enumerate() {
        let share = decode_share_bytes_typed::<F, G>(share_bytes).map_err(|e| {
            ShareAlgebraError::DecodeShareAt {
                index: i,
                source: Box::new(e),
            }
        })?;
        match share {
            DecodedShare::Robust(share) => {
                if format == Some(LocalShareFormat::Feldman) {
                    return Err(ShareAlgebraError::InterpolationFormatMismatch);
                }
                format = Some(LocalShareFormat::Robust);
                robust_shares.push(share);
            }
            DecodedShare::Feldman(share) => {
                if format == Some(LocalShareFormat::Robust) {
                    return Err(ShareAlgebraError::InterpolationFormatMismatch);
                }
                format = Some(LocalShareFormat::Feldman);
                feldman_shares.push(share);
            }
        }
    }

    let secret = match format {
        Some(LocalShareFormat::Robust) => {
            let (_degree, secret) =
                RobustShare::recover_secret(&robust_shares, n_parties, threshold).map_err(|e| {
                    ShareAlgebraError::RecoverSecret {
                        source: format!("{e:?}"),
                    }
                })?;
            secret
        }
        Some(LocalShareFormat::Feldman) => {
            let (_degree, secret) =
                FeldmanShamirShare::recover_secret(&feldman_shares, n_parties, threshold).map_err(
                    |e| ShareAlgebraError::RecoverSecret {
                        source: format!("{e:?}"),
                    },
                )?;
            secret
        }
        None => return Err(ShareAlgebraError::InterpolationEmpty),
    };

    match ty {
        ShareType::SecretField => {
            Err(crate::net::curve::MpcCurveError::FieldRequiresRawOpening.into())
        }
        ShareType::SecretInt { bit_length: 1 } => Ok(Value::Bool(!secret.is_zero())),
        ty @ ShareType::SecretInt { bit_length } => Ok(clear_share_value_to_vm_value(
            ty,
            ClearShareValue::Integer(field_to_wrapping_secret_int(secret, bit_length)?),
        )),
        ty @ ShareType::SecretUInt { bit_length } => Ok(clear_share_value_to_vm_value(
            ty,
            ClearShareValue::UnsignedInteger(field_to_wrapping_secret_uint(secret, bit_length)?),
        )),
        ShareType::SecretFixedPoint { precision } => {
            let scaled_value = field_to_i64(secret)?;
            let scale = fixed_point_scale_as_f64(precision.f())?;
            Ok(Value::Float(F64(scaled_value as f64 / scale)))
        }
    }
}
