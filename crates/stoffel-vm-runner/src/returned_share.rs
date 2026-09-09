//! Stable runner representation for a VM return value that remains secret-shared.
//!
//! The bytes in [`ReturnedShare`] are the exact backend serialization held by
//! the local party. They can be hashed, encrypted, or otherwise sealed without
//! running an MPC open/reconstruction protocol.

use std::fmt;
use std::str::FromStr;

use stoffel_vm_types::core_types::{ShareData, ShareDataFormat, ShareType, Value};

/// Versioned prefix used by `stoffel-run` for an unrevealed share return.
pub const RETURNED_SHARE_PREFIX_V1: &str = "share:v1[";

/// One party's opaque VM return share.
///
/// `data` is deliberately not interpreted by the runner. It is the exact byte
/// string returned by [`ShareData::as_bytes`], suitable for hashing or sealing
/// by a party-local consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnedShare {
    pub share_type: ShareType,
    pub format: ShareDataFormat,
    pub data: Vec<u8>,
}

impl ReturnedShare {
    pub fn new(share_type: ShareType, format: ShareDataFormat, data: Vec<u8>) -> Self {
        Self {
            share_type,
            format,
            data,
        }
    }

    pub fn from_share_data(share_type: ShareType, data: &ShareData) -> Self {
        Self::new(share_type, data.format(), data.as_bytes().to_vec())
    }

    pub fn from_vm_value(value: &Value) -> Option<Self> {
        match value {
            Value::Share(share_type, data) => Some(Self::from_share_data(*share_type, data)),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }
}

impl fmt::Display for ReturnedShare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{RETURNED_SHARE_PREFIX_V1}{};{};{}] 0x{}",
            DisplayShareType(self.share_type),
            self.format.as_str(),
            self.data.len(),
            hex::encode(&self.data)
        )
    }
}

impl FromStr for ReturnedShare {
    type Err = ReturnedShareParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let encoded = value
            .trim()
            .strip_prefix(RETURNED_SHARE_PREFIX_V1)
            .ok_or(ReturnedShareParseError::MissingEnvelope)?;
        let (metadata, data_hex) = encoded
            .split_once("] 0x")
            .ok_or(ReturnedShareParseError::MissingEnvelope)?;

        let mut fields = metadata.split(';');
        let share_type = parse_share_type(
            fields
                .next()
                .ok_or(ReturnedShareParseError::InvalidMetadata)?,
        )?;
        let format = match fields
            .next()
            .ok_or(ReturnedShareParseError::InvalidMetadata)?
        {
            "opaque" => ShareDataFormat::Opaque,
            "feldman" => ShareDataFormat::Feldman,
            other => return Err(ReturnedShareParseError::InvalidFormat(other.to_owned())),
        };
        let declared_len = fields
            .next()
            .ok_or(ReturnedShareParseError::InvalidMetadata)?
            .parse::<usize>()
            .map_err(|_| ReturnedShareParseError::InvalidLength)?;
        if fields.next().is_some() {
            return Err(ReturnedShareParseError::InvalidMetadata);
        }

        let data = hex::decode(data_hex).map_err(ReturnedShareParseError::InvalidHex)?;
        if data.len() != declared_len {
            return Err(ReturnedShareParseError::LengthMismatch {
                declared: declared_len,
                actual: data.len(),
            });
        }

        Ok(Self::new(share_type, format, data))
    }
}

struct DisplayShareType(ShareType);

impl fmt::Display for DisplayShareType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            ShareType::SecretInt { bit_length } => write!(formatter, "secret-int:{bit_length}"),
            ShareType::SecretUInt { bit_length } => write!(formatter, "secret-uint:{bit_length}"),
            ShareType::SecretFixedPoint { precision } => write!(
                formatter,
                "secret-fixed-point:{}:{}",
                precision.total_bits(),
                precision.fractional_bits()
            ),
        }
    }
}

fn parse_share_type(value: &str) -> Result<ShareType, ReturnedShareParseError> {
    let mut parts = value.split(':');
    let kind = parts
        .next()
        .ok_or_else(|| ReturnedShareParseError::InvalidType(value.to_owned()))?;
    let first = parse_type_width(parts.next(), value)?;
    let share_type = match kind {
        "secret-int" if parts.next().is_none() => ShareType::try_secret_int(first),
        "secret-uint" if parts.next().is_none() => ShareType::try_secret_uint(first),
        "secret-fixed-point" => {
            let fractional = parse_type_width(parts.next(), value)?;
            if parts.next().is_some() {
                return Err(ReturnedShareParseError::InvalidType(value.to_owned()));
            }
            ShareType::try_secret_fixed_point_from_bits(first, fractional)
        }
        _ => return Err(ReturnedShareParseError::InvalidType(value.to_owned())),
    };
    share_type.map_err(|_| ReturnedShareParseError::InvalidType(value.to_owned()))
}

fn parse_type_width(
    value: Option<&str>,
    full_type: &str,
) -> Result<usize, ReturnedShareParseError> {
    value
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or_else(|| ReturnedShareParseError::InvalidType(full_type.to_owned()))
}

#[derive(Debug, thiserror::Error)]
pub enum ReturnedShareParseError {
    #[error("returned share does not use the supported share:v1 envelope")]
    MissingEnvelope,
    #[error("returned share metadata must contain type, format, and byte length")]
    InvalidMetadata,
    #[error("invalid returned share type '{0}'")]
    InvalidType(String),
    #[error("invalid returned share data format '{0}'")]
    InvalidFormat(String),
    #[error("invalid returned share byte length")]
    InvalidLength,
    #[error("invalid returned share hex data: {0}")]
    InvalidHex(hex::FromHexError),
    #[error("returned share declared {declared} byte(s), encoded {actual}")]
    LengthMismatch { declared: usize, actual: usize },
}

#[cfg(test)]
mod tests {
    use super::{ReturnedShare, ReturnedShareParseError};
    use stoffel_vm_types::core_types::{ShareData, ShareDataFormat, ShareType, Value};

    #[test]
    fn returned_share_round_trips_exact_opaque_bytes() {
        let returned = ReturnedShare::new(
            ShareType::secret_int(64),
            ShareDataFormat::Opaque,
            vec![0x00, 0x01, 0xfe, 0xff],
        );

        let encoded = returned.to_string();
        assert_eq!(encoded, "share:v1[secret-int:64;opaque;4] 0x0001feff");
        assert_eq!(encoded.parse::<ReturnedShare>().unwrap(), returned);
    }

    #[test]
    fn returned_share_round_trips_fixed_point_metadata() {
        let returned = ReturnedShare::new(
            ShareType::secret_fixed_point_from_bits(48, 12),
            ShareDataFormat::Feldman,
            vec![0xab, 0xcd],
        );

        let encoded = returned.to_string();
        assert_eq!(
            encoded,
            "share:v1[secret-fixed-point:48:12;feldman;2] 0xabcd"
        );
        assert_eq!(encoded.parse::<ReturnedShare>().unwrap(), returned);
    }

    #[test]
    fn returned_share_extracts_the_vm_share_without_opening_it() {
        let value = Value::Share(
            ShareType::secret_uint(32),
            ShareData::Opaque(vec![3, 1, 4, 1, 5].into()),
        );

        let returned = ReturnedShare::from_vm_value(&value).unwrap();
        assert_eq!(returned.share_type, ShareType::secret_uint(32));
        assert_eq!(returned.format, ShareDataFormat::Opaque);
        assert_eq!(returned.as_bytes(), &[3, 1, 4, 1, 5]);
    }

    #[test]
    fn returned_share_rejects_a_length_mismatch() {
        let error = "share:v1[secret-int:64;opaque;3] 0x0001"
            .parse::<ReturnedShare>()
            .unwrap_err();
        assert!(matches!(
            error,
            ReturnedShareParseError::LengthMismatch {
                declared: 3,
                actual: 2
            }
        ));
    }
}
