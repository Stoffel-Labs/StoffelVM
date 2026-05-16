use super::codec::{decode_share_bytes_typed, DecodedShare, LocalShareFormat};
use super::{ShareAlgebraError, ShareAlgebraResult};
use ark_ec::CurveGroup;
use ark_ff::{FftField, PrimeField};
use stoffel_vm_types::core_types::{ShareType, Value, F64};
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::common::SecretSharingScheme;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

use crate::net::curve::{field_to_i64, fixed_point_scale_as_f64, MpcFieldKind};

pub(crate) fn interpolate_local(
    field_kind: MpcFieldKind,
    ty: ShareType,
    shares: &[Vec<u8>],
    n_parties: usize,
    threshold: usize,
) -> ShareAlgebraResult<Value> {
    if shares.is_empty() {
        return Err(ShareAlgebraError::InterpolationEmpty);
    }

    dispatch_share_curve!(
        field_kind,
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
        ShareType::SecretInt { bit_length: 1 } => Ok(Value::Bool(!secret.is_zero())),
        ShareType::SecretInt { .. } => Ok(Value::I64(field_to_i64(secret)?)),
        ShareType::SecretFixedPoint { precision } => {
            let scaled_value = field_to_i64(secret)?;
            let scale = fixed_point_scale_as_f64(precision.f())?;
            Ok(Value::Float(F64(scaled_value as f64 / scale)))
        }
    }
}
