use crate::net::curve::MpcCurveConfig;
use std::fmt;

pub type MpcExponentResult<T> = Result<T, MpcExponentError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MpcExponentError {
    UnsupportedGroupName {
        name: String,
    },
    SerializeDefaultGenerator {
        description: &'static str,
        source: String,
    },
}

impl fmt::Display for MpcExponentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MpcExponentError::UnsupportedGroupName { name } => {
                write!(f, "Unsupported curve: {name}")
            }
            MpcExponentError::SerializeDefaultGenerator {
                description,
                source,
            } => write!(f, "serialize {description}: {source}"),
        }
    }
}

impl std::error::Error for MpcExponentError {}

impl From<MpcExponentError> for String {
    fn from(error: MpcExponentError) -> Self {
        error.to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MpcExponentGroup {
    Bls12381G1,
    Bls12381G2,
    Bn254G1,
    Curve25519Edwards,
    Ed25519Edwards,
}

impl MpcExponentGroup {
    pub const fn as_str(self) -> &'static str {
        match self {
            MpcExponentGroup::Bls12381G1 => "bls12-381-g1",
            MpcExponentGroup::Bls12381G2 => "bls12-381-g2",
            MpcExponentGroup::Bn254G1 => "bn254-g1",
            MpcExponentGroup::Curve25519Edwards => "curve25519-edwards",
            MpcExponentGroup::Ed25519Edwards => "ed25519-edwards",
        }
    }

    pub fn parse_name(input: &str) -> MpcExponentResult<Self> {
        input.parse()
    }

    pub const fn native_for_curve(curve: MpcCurveConfig) -> Self {
        match curve {
            MpcCurveConfig::Bls12_381 => MpcExponentGroup::Bls12381G1,
            MpcCurveConfig::Bn254 => MpcExponentGroup::Bn254G1,
            MpcCurveConfig::Curve25519 => MpcExponentGroup::Curve25519Edwards,
            MpcCurveConfig::Ed25519 => MpcExponentGroup::Ed25519Edwards,
        }
    }

    pub fn unsupported_error(self, protocol_name: &str) -> String {
        format!(
            "MPC backend '{}' does not support Share.open_exp for {}",
            protocol_name,
            self.as_str()
        )
    }

    pub fn default_generator_bytes(self) -> MpcExponentResult<Vec<u8>> {
        match self {
            MpcExponentGroup::Bls12381G1 => {
                serialize_prime_group_generator::<ark_bls12_381::G1Projective>("generator")
            }
            MpcExponentGroup::Bls12381G2 => {
                serialize_prime_group_generator::<ark_bls12_381::G2Projective>("G2 generator")
            }
            MpcExponentGroup::Bn254G1 => {
                serialize_prime_group_generator::<ark_bn254::G1Projective>("generator")
            }
            MpcExponentGroup::Curve25519Edwards => {
                serialize_prime_group_generator::<ark_curve25519::EdwardsProjective>("generator")
            }
            MpcExponentGroup::Ed25519Edwards => {
                serialize_prime_group_generator::<ark_ed25519::EdwardsProjective>("generator")
            }
        }
    }
}

impl std::str::FromStr for MpcExponentGroup {
    type Err = MpcExponentError;

    fn from_str(input: &str) -> MpcExponentResult<Self> {
        let trimmed = input.trim();
        match trimmed.to_ascii_lowercase().as_str() {
            "bls12-381-g1" => Ok(MpcExponentGroup::Bls12381G1),
            "bls12-381-g2" => Ok(MpcExponentGroup::Bls12381G2),
            "bn254-g1" => Ok(MpcExponentGroup::Bn254G1),
            "curve25519-edwards" => Ok(MpcExponentGroup::Curve25519Edwards),
            "ed25519-edwards" => Ok(MpcExponentGroup::Ed25519Edwards),
            _ => Err(MpcExponentError::UnsupportedGroupName {
                name: trimmed.to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpcExponentGenerator {
    group: MpcExponentGroup,
    bytes: Vec<u8>,
}

impl MpcExponentGenerator {
    pub fn from_curve_name(curve_name: &str) -> MpcExponentResult<Self> {
        let group = MpcExponentGroup::parse_name(curve_name)?;
        Self::for_group(group)
    }

    pub fn for_group(group: MpcExponentGroup) -> MpcExponentResult<Self> {
        let bytes = group.default_generator_bytes()?;
        Ok(Self { group, bytes })
    }

    pub const fn group(&self) -> MpcExponentGroup {
        self.group
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_parts(self) -> (MpcExponentGroup, Vec<u8>) {
        (self.group, self.bytes)
    }
}

fn serialize_prime_group_generator<G>(description: &'static str) -> MpcExponentResult<Vec<u8>>
where
    G: ark_ec::CurveGroup + ark_ec::PrimeGroup,
{
    use ark_serialize::CanonicalSerialize;

    let generator = G::generator();
    let mut bytes = Vec::new();
    generator
        .into_affine()
        .serialize_compressed(&mut bytes)
        .map_err(|err| MpcExponentError::SerializeDefaultGenerator {
            description,
            source: err.to_string(),
        })?;
    Ok(bytes)
}
