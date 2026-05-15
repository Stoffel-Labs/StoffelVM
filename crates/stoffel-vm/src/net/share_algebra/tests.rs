use super::{scale_fixed_point_scalar, ShareAlgebraError};

#[test]
fn scale_fixed_point_scalar_rejects_unrepresentable_shift() {
    let err = scale_fixed_point_scalar(usize::MAX, 1).unwrap_err();

    assert_eq!(err, ShareAlgebraError::FixedPointScaleOverflow);
    assert_eq!(err.to_string(), "Fixed-point scale overflow");
}

#[test]
fn scale_fixed_point_scalar_rejects_i64_overflow() {
    let range_err = scale_fixed_point_scalar(63, 1).unwrap_err();
    let overflow_err = scale_fixed_point_scalar(126, 3).unwrap_err();

    assert_eq!(range_err, ShareAlgebraError::FixedPointScalarOutOfRange);
    assert_eq!(overflow_err, ShareAlgebraError::FixedPointScalarOverflow);
    assert_eq!(
        range_err.to_string(),
        "Fixed-point scalar exceeds i64 range"
    );
    assert_eq!(overflow_err.to_string(), "Fixed-point scalar overflow");
}
