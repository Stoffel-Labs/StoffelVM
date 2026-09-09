use crate::error::{Error, Result};
use crate::types::Value;
use stoffel_vm_types::core_types::FixedPointPrecision;
use stoffel_vm_types::fixed_point_codec::{
    decode_fixed_point_float, encode_fixed_point_float, encode_fixed_point_integer,
};

pub(crate) fn encode_fixed_point_value(
    value: &Value,
    precision: FixedPointPrecision,
) -> Result<i64> {
    match value {
        Value::I64(value) => encode_fixed_point_integer(i128::from(*value), precision),
        Value::U64(value) => encode_fixed_point_integer(i128::from(*value), precision),
        Value::Float(value) => encode_fixed_point_float(*value, precision),
        value => {
            return Err(Error::InvalidInput(format!(
                "fixed-point client input must be an integer or float, got {}",
                value.kind()
            )))
        }
    }
    .map_err(|error| Error::InvalidInput(error.to_string()))
}

pub(crate) fn decode_fixed_point_value(
    encoded: i64,
    precision: FixedPointPrecision,
) -> Result<f64> {
    decode_fixed_point_float(encoded, precision)
        .map_err(|error| Error::InvalidInput(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_fixed_point_values_encode_with_manifest_precision() {
        let precision = FixedPointPrecision::new(64, 16);

        assert_eq!(
            encode_fixed_point_value(&Value::I64(1), precision).unwrap(),
            65_536
        );
        assert_eq!(
            encode_fixed_point_value(&Value::Float(1.5), precision).unwrap(),
            98_304
        );
        assert_eq!(
            encode_fixed_point_value(&Value::I64(-2), precision).unwrap(),
            -131_072
        );
    }

    #[test]
    fn fixed_point_codec_rejects_invalid_values_and_precision_overflow() {
        let precision = FixedPointPrecision::new(32, 16);

        assert!(encode_fixed_point_value(&Value::Float(f64::NAN), precision).is_err());
        assert!(encode_fixed_point_value(&Value::I64(32_768), precision).is_err());
        assert!(encode_fixed_point_value(&Value::Bool(true), precision).is_err());
    }

    #[test]
    fn fixed_point_values_decode_with_manifest_precision() {
        let precision = FixedPointPrecision::new(64, 16);

        assert_eq!(decode_fixed_point_value(98_304, precision).unwrap(), 1.5);
        assert_eq!(decode_fixed_point_value(-32_768, precision).unwrap(), -0.5);
    }
}
