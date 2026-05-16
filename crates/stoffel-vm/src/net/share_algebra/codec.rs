use super::{ShareAlgebraError, ShareAlgebraResult};
use ark_ec::CurveGroup;
use ark_ff::{FftField, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::io::Cursor;
use stoffel_vm_types::core_types::ShareData;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

use crate::net::curve::MpcCurveConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LocalShareFormat {
    Robust,
    Feldman,
}

pub(super) enum DecodedShare<F, G>
where
    F: FftField + PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    Robust(RobustShare<F>),
    Feldman(FeldmanShamirShare<F, G>),
}

pub(super) fn decode_exact_typed<T: CanonicalDeserialize>(
    bytes: &[u8],
    type_name: &'static str,
) -> ShareAlgebraResult<T> {
    let mut cursor = Cursor::new(bytes);
    let decoded =
        T::deserialize_compressed(&mut cursor).map_err(|e| ShareAlgebraError::Decode {
            type_name,
            source: e.to_string(),
        })?;
    if cursor.position() != bytes.len() as u64 {
        return Err(ShareAlgebraError::DecodeTrailingBytes { type_name });
    }
    Ok(decoded)
}

pub(super) fn encode_share_bytes_typed<T: CanonicalSerialize>(
    share: &T,
) -> ShareAlgebraResult<Vec<u8>> {
    let mut encoded = Vec::new();
    share
        .serialize_compressed(&mut encoded)
        .map_err(|e| ShareAlgebraError::EncodeShareBytes {
            source: e.to_string(),
        })?;
    Ok(encoded)
}

pub(crate) fn preserve_share_data_format_for_curve(
    curve_config: MpcCurveConfig,
    template: &ShareData,
    result_bytes: Vec<u8>,
) -> ShareAlgebraResult<ShareData> {
    match template {
        ShareData::Opaque(_) => Ok(ShareData::Opaque(result_bytes)),
        ShareData::Feldman { .. } => {
            dispatch_share_curve_config!(
                curve_config,
                feldman_share_data_from_bytes_typed(result_bytes)
            )
        }
    }
}

pub(super) fn format_name(format: LocalShareFormat) -> &'static str {
    match format {
        LocalShareFormat::Robust => "RobustShare",
        LocalShareFormat::Feldman => "FeldmanShamirShare",
    }
}

pub(super) fn decode_share_bytes_typed<F, G>(bytes: &[u8]) -> ShareAlgebraResult<DecodedShare<F, G>>
where
    F: FftField + PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    let feldman_err =
        match decode_exact_typed::<FeldmanShamirShare<F, G>>(bytes, "FeldmanShamirShare") {
            Ok(share) => return Ok(DecodedShare::Feldman(share)),
            Err(err) => err,
        };

    let robust_err = match decode_exact_typed::<RobustShare<F>>(bytes, "RobustShare") {
        Ok(share) => return Ok(DecodedShare::Robust(share)),
        Err(err) => err,
    };

    Err(ShareAlgebraError::DecodeShareBytes {
        feldman_error: Box::new(feldman_err),
        robust_error: Box::new(robust_err),
    })
}

fn encode_feldman_commitments_typed<G>(commitments: &[G]) -> ShareAlgebraResult<Vec<Vec<u8>>>
where
    G: CurveGroup,
{
    commitments
        .iter()
        .map(|commitment| {
            let mut encoded = Vec::new();
            commitment
                .into_affine()
                .serialize_compressed(&mut encoded)
                .map_err(|e| ShareAlgebraError::EncodeFeldmanCommitment {
                    source: e.to_string(),
                })?;
            Ok(encoded)
        })
        .collect()
}

fn feldman_share_data_from_bytes_typed<F, G>(bytes: Vec<u8>) -> ShareAlgebraResult<ShareData>
where
    F: FftField + PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    let share = decode_exact_typed::<FeldmanShamirShare<F, G>>(&bytes, "FeldmanShamirShare")?;
    let commitments = encode_feldman_commitments_typed(&share.commitments)?;
    Ok(ShareData::Feldman {
        data: bytes,
        commitments,
    })
}
