//! MPC backend selection.
//!
//! Provides an enum for choosing between HoneyBadger and ADKG backends at runtime.

/// Available MPC backend implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpcBackendKind {
    #[cfg(feature = "honeybadger")]
    HoneyBadger,
    #[cfg(feature = "adkg")]
    Adkg,
}

impl MpcBackendKind {
    /// Parse a backend name from a string.
    ///
    /// Accepted values:
    /// - `"honeybadger"` or `"hb"` -> `HoneyBadger`
    /// - `"adkg"` -> `Adkg`
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            #[cfg(feature = "honeybadger")]
            "honeybadger" | "hb" => Ok(MpcBackendKind::HoneyBadger),
            #[cfg(feature = "adkg")]
            "adkg" => Ok(MpcBackendKind::Adkg),
            other => {
                let mut available = Vec::new();
                #[cfg(feature = "honeybadger")]
                available.push("honeybadger");
                #[cfg(feature = "adkg")]
                available.push("adkg");
                Err(format!(
                    "Unknown MPC backend '{}'. Available: {}",
                    other,
                    available.join(", ")
                ))
            }
        }
    }

    /// Returns the default backend.
    ///
    /// Prefers HoneyBadger when available, falls back to ADKG.
    pub fn default_backend() -> Self {
        #[cfg(feature = "honeybadger")]
        {
            MpcBackendKind::HoneyBadger
        }
        #[cfg(not(feature = "honeybadger"))]
        {
            #[cfg(feature = "adkg")]
            {
                MpcBackendKind::Adkg
            }
            #[cfg(not(feature = "adkg"))]
            {
                compile_error!("At least one MPC backend feature must be enabled");
            }
        }
    }

    /// Whether this backend supports general MPC operations (input sharing, opening).
    pub fn supports_general_mpc(&self) -> bool {
        match self {
            #[cfg(feature = "honeybadger")]
            MpcBackendKind::HoneyBadger => true,
            #[cfg(feature = "adkg")]
            MpcBackendKind::Adkg => true,
        }
    }

    /// Whether this backend supports secure multiplication (requires Beaver triples).
    pub fn supports_multiplication(&self) -> bool {
        match self {
            #[cfg(feature = "honeybadger")]
            MpcBackendKind::HoneyBadger => true,
            #[cfg(feature = "adkg")]
            MpcBackendKind::Adkg => false,
        }
    }

    /// Whether this backend supports distributed key generation.
    pub fn supports_dkg(&self) -> bool {
        match self {
            #[cfg(feature = "honeybadger")]
            MpcBackendKind::HoneyBadger => false,
            #[cfg(feature = "adkg")]
            MpcBackendKind::Adkg => true,
        }
    }

    /// Whether this backend supports client inputs.
    pub fn supports_client_input(&self) -> bool {
        match self {
            #[cfg(feature = "honeybadger")]
            MpcBackendKind::HoneyBadger => true,
            #[cfg(feature = "adkg")]
            MpcBackendKind::Adkg => false,
        }
    }

    /// Human-readable name for this backend.
    pub fn name(&self) -> &'static str {
        match self {
            #[cfg(feature = "honeybadger")]
            MpcBackendKind::HoneyBadger => "honeybadger",
            #[cfg(feature = "adkg")]
            MpcBackendKind::Adkg => "adkg",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "honeybadger")]
    fn test_parse_honeybadger() {
        assert_eq!(
            MpcBackendKind::from_str("honeybadger").unwrap(),
            MpcBackendKind::HoneyBadger
        );
        assert_eq!(
            MpcBackendKind::from_str("hb").unwrap(),
            MpcBackendKind::HoneyBadger
        );
        assert_eq!(
            MpcBackendKind::from_str("HoneyBadger").unwrap(),
            MpcBackendKind::HoneyBadger
        );
    }

    #[test]
    #[cfg(feature = "adkg")]
    fn test_parse_adkg() {
        assert_eq!(
            MpcBackendKind::from_str("adkg").unwrap(),
            MpcBackendKind::Adkg
        );
        assert_eq!(
            MpcBackendKind::from_str("ADKG").unwrap(),
            MpcBackendKind::Adkg
        );
    }

    #[test]
    fn test_parse_unknown() {
        assert!(MpcBackendKind::from_str("unknown").is_err());
    }

    #[test]
    #[cfg(feature = "honeybadger")]
    fn test_default_is_honeybadger() {
        assert_eq!(MpcBackendKind::default_backend(), MpcBackendKind::HoneyBadger);
    }

    #[test]
    #[cfg(feature = "honeybadger")]
    fn test_honeybadger_capabilities() {
        let hb = MpcBackendKind::HoneyBadger;
        assert!(hb.supports_general_mpc());
        assert!(!hb.supports_dkg());
        assert!(hb.supports_client_input());
    }

    #[test]
    #[cfg(feature = "adkg")]
    fn test_adkg_capabilities() {
        let adkg = MpcBackendKind::Adkg;
        assert!(adkg.supports_general_mpc());
        assert!(!adkg.supports_multiplication());
        assert!(adkg.supports_dkg());
        assert!(!adkg.supports_client_input());
    }

    #[test]
    #[cfg(feature = "honeybadger")]
    fn test_honeybadger_supports_multiplication() {
        let hb = MpcBackendKind::HoneyBadger;
        assert!(hb.supports_multiplication());
    }
}
