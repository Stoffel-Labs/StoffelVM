//! Shared MPC curve and field configuration.
//!
//! This module centralizes curve parsing/validation across backends.

use crate::net::backend::MpcBackendKind;

/// Curated set of MPC curves supported by the VM.
///
/// Ed25519 and Curve25519 share the same scalar field (`ark_curve25519::Fr`).
/// At the type level `ark_ed25519::Fr` is a re-export of `ark_curve25519::Fr`,
/// so `SupportedMpcField` is implemented once and covers both curves.
/// `curve_config()` on an Ed25519 engine will report `Curve25519` because the
/// field is identical; use the server / CLI `--mpc-curve` flag to distinguish
/// intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpcCurveConfig {
    Bls12_381,
    Bn254,
    Curve25519,
    /// Ed25519 uses the same scalar field as Curve25519.
    /// See enum-level docs for details.
    Ed25519,
}

impl std::str::FromStr for MpcCurveConfig {
    type Err = String;

    /// Parse a curve name (case-insensitive with common aliases).
    fn from_str(input: &str) -> Result<Self, String> {
        match input.trim().to_ascii_lowercase().as_str() {
            "bls12-381" | "bls12_381" | "bls12381" => Ok(Self::Bls12_381),
            "bn254" => Ok(Self::Bn254),
            "curve25519" | "curve-25519" => Ok(Self::Curve25519),
            "ed25519" | "ed-25519" => Ok(Self::Ed25519),
            other => Err(format!(
                "Unknown MPC curve '{other}'. Supported curves: bls12-381, bn254, curve25519, ed25519"
            )),
        }
    }
}

impl MpcCurveConfig {
    pub fn name(self) -> &'static str {
        match self {
            Self::Bls12_381 => "bls12-381",
            Self::Bn254 => "bn254",
            Self::Curve25519 => "curve25519",
            Self::Ed25519 => "ed25519",
        }
    }

    pub fn field_kind(self) -> MpcFieldKind {
        match self {
            Self::Bls12_381 => MpcFieldKind::Bls12_381Fr,
            Self::Bn254 => MpcFieldKind::Bn254Fr,
            Self::Curve25519 => MpcFieldKind::Curve25519Fr,
            // Ed25519 uses the same scalar field as curve25519.
            Self::Ed25519 => MpcFieldKind::Curve25519Fr,
        }
    }

    pub fn supports_backend(self, backend: MpcBackendKind) -> bool {
        match backend {
            #[cfg(feature = "honeybadger")]
            MpcBackendKind::HoneyBadger => true,
            #[cfg(feature = "avss")]
            MpcBackendKind::Avss => true,
        }
    }

    pub fn validate_for_backend(self, backend: MpcBackendKind) -> Result<(), String> {
        if self.supports_backend(backend) {
            return Ok(());
        }

        let backend_name = backend.name();
        Err(format!(
            "MPC curve '{}' is not supported by backend '{}'",
            self.name(),
            backend_name
        ))
    }
}

impl Default for MpcCurveConfig {
    fn default() -> Self {
        Self::Bls12_381
    }
}

/// Field-dispatch metadata for VM-local share math.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpcFieldKind {
    Bls12_381Fr,
    Bn254Fr,
    Curve25519Fr,
}

impl MpcFieldKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Bls12_381Fr => "bls12-381-fr",
            Self::Bn254Fr => "bn254-fr",
            Self::Curve25519Fr => "curve25519-fr",
        }
    }
}

/// Implemented by supported MPC scalar fields so engines can expose
/// compile-time field metadata at runtime.
pub trait SupportedMpcField: ark_ff::FftField + ark_ff::PrimeField + Send + Sync + 'static {
    const CURVE_CONFIG: MpcCurveConfig;

    fn field_kind() -> MpcFieldKind {
        Self::CURVE_CONFIG.field_kind()
    }
}

impl SupportedMpcField for ark_bls12_381::Fr {
    const CURVE_CONFIG: MpcCurveConfig = MpcCurveConfig::Bls12_381;
}

impl SupportedMpcField for ark_bn254::Fr {
    const CURVE_CONFIG: MpcCurveConfig = MpcCurveConfig::Bn254;
}

impl SupportedMpcField for ark_curve25519::Fr {
    const CURVE_CONFIG: MpcCurveConfig = MpcCurveConfig::Curve25519;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn parse_curve_names() {
        assert_eq!(
            MpcCurveConfig::from_str("bls12-381").unwrap(),
            MpcCurveConfig::Bls12_381
        );
        assert_eq!(
            MpcCurveConfig::from_str("bn254").unwrap(),
            MpcCurveConfig::Bn254
        );
        assert_eq!(
            MpcCurveConfig::from_str("curve25519").unwrap(),
            MpcCurveConfig::Curve25519
        );
        assert_eq!(
            MpcCurveConfig::from_str("ed25519").unwrap(),
            MpcCurveConfig::Ed25519
        );
        // Also works via str::parse()
        assert_eq!(
            "bn254".parse::<MpcCurveConfig>().unwrap(),
            MpcCurveConfig::Bn254
        );
    }

    #[test]
    fn reject_unknown_curve() {
        assert!(MpcCurveConfig::from_str("ristretto").is_err());
    }

    #[test]
    #[cfg(feature = "avss")]
    fn avss_curve_compatibility() {
        assert!(MpcCurveConfig::Bls12_381
            .validate_for_backend(MpcBackendKind::Avss)
            .is_ok());
        assert!(MpcCurveConfig::Bn254
            .validate_for_backend(MpcBackendKind::Avss)
            .is_ok());
        assert!(MpcCurveConfig::Curve25519
            .validate_for_backend(MpcBackendKind::Avss)
            .is_ok());
    }
}
