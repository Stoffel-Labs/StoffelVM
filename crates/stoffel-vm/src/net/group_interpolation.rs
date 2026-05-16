use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Interpolate compressed group-valued Shamir evaluations at zero.
pub(crate) fn interpolate_compressed_group_points<F, G, E>(
    partial_points: &[(usize, Vec<u8>)],
    evaluation_point: E,
    deserialize_context: &str,
    zero_denominator_context: &str,
    serialize_context: &str,
) -> Result<Vec<u8>, String>
where
    F: Field,
    G: CurveGroup<ScalarField = F>,
    <G as CurveGroup>::Affine: CanonicalDeserialize + CanonicalSerialize,
    E: Fn(usize) -> Result<F, String>,
{
    if partial_points.is_empty() {
        return Err("cannot interpolate empty group point set".to_string());
    }

    let mut points: Vec<(usize, G)> = Vec::with_capacity(partial_points.len());
    for (id, bytes) in partial_points {
        let point = <G as CurveGroup>::Affine::deserialize_compressed(&bytes[..])
            .map_err(|error| format!("{deserialize_context}: {error}"))?;
        points.push((*id, point.into()));
    }

    let eval_points: Vec<(usize, F)> = points
        .iter()
        .map(|(id, _)| evaluation_point(*id).map(|point| (*id, point)))
        .collect::<Result<_, _>>()?;

    let mut result = G::zero();
    for (i, (_id_i, point_i)) in points.iter().enumerate() {
        let x_i = eval_points[i].1;
        let mut lambda = F::from(1u64);
        for (j, _) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            let x_j = eval_points[j].1;
            let denominator = x_i - x_j;
            lambda *= -x_j
                * denominator
                    .inverse()
                    .ok_or_else(|| zero_denominator_context.to_string())?;
        }
        result += *point_i * lambda;
    }

    let mut result_bytes = Vec::new();
    result
        .into_affine()
        .serialize_compressed(&mut result_bytes)
        .map_err(|error| format!("{serialize_context}: {error}"))?;
    Ok(result_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine, G1Projective};
    use ark_ec::{CurveGroup, PrimeGroup};
    use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};

    fn compressed(point: G1Projective) -> Vec<u8> {
        let mut bytes = Vec::new();
        point
            .into_affine()
            .serialize_compressed(&mut bytes)
            .expect("serialize group point");
        bytes
    }

    fn decoded(bytes: &[u8]) -> G1Projective {
        G1Affine::deserialize_compressed(bytes)
            .expect("deserialize group point")
            .into()
    }

    #[test]
    fn interpolates_integer_evaluation_points_at_zero() {
        let generator = G1Projective::generator();
        let secret = Fr::from(17u64);
        let slope = Fr::from(5u64);
        let points = [1usize, 2, 3].map(|id| {
            let x = Fr::from(id as u64);
            (id, compressed(generator * (secret + slope * x)))
        });

        let reconstructed = interpolate_compressed_group_points::<Fr, G1Projective, _>(
            &points,
            |id| Ok(Fr::from(id as u64)),
            "deserialize partial point",
            "zero denominator",
            "serialize result",
        )
        .expect("interpolate");

        assert_eq!(decoded(&reconstructed), generator * secret);
    }

    #[test]
    fn interpolates_fft_domain_evaluation_points_at_zero() {
        let domain = GeneralEvaluationDomain::<Fr>::new(4).expect("domain");
        let generator = G1Projective::generator();
        let secret = Fr::from(23u64);
        let slope = Fr::from(11u64);
        let points = [0usize, 1, 2].map(|id| {
            let x = domain.element(id);
            (id, compressed(generator * (secret + slope * x)))
        });

        let reconstructed = interpolate_compressed_group_points::<Fr, G1Projective, _>(
            &points,
            |id| Ok(domain.element(id)),
            "deserialize partial point",
            "zero denominator",
            "serialize result",
        )
        .expect("interpolate");

        assert_eq!(decoded(&reconstructed), generator * secret);
    }
}
