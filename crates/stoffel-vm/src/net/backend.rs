//! MPC backend selection.
//!
//! Provides an enum for choosing between HoneyBadger and AVSS backends at runtime.

/// Available MPC backend implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpcBackendKind {
    #[cfg(feature = "honeybadger")]
    HoneyBadger,
    #[cfg(feature = "adkg")]
    Avss,
}

impl std::str::FromStr for MpcBackendKind {
    type Err = String;

    /// Parse a backend name from a string.
    ///
    /// Accepted values:
    /// - `"honeybadger"` or `"hb"` -> `HoneyBadger`
    /// - `"adkg"` -> `Adkg`
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            #[cfg(feature = "honeybadger")]
            "honeybadger" | "hb" => Ok(MpcBackendKind::HoneyBadger),
            #[cfg(feature = "adkg")]
            "avss" | "adkg" => Ok(MpcBackendKind::Avss),
            other => {
                let mut available = Vec::new();
                #[cfg(feature = "honeybadger")]
                available.push("honeybadger");
                #[cfg(feature = "adkg")]
                available.push("avss");
                Err(format!(
                    "Unknown MPC backend '{}'. Available: {}",
                    other,
                    available.join(", ")
                ))
            }
        }
    }
}

impl MpcBackendKind {
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
                MpcBackendKind::Avss
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
            MpcBackendKind::Avss => true,
        }
    }

    /// Whether this backend supports secure multiplication (requires Beaver triples).
    pub fn supports_multiplication(&self) -> bool {
        match self {
            #[cfg(feature = "honeybadger")]
            MpcBackendKind::HoneyBadger => true,
            #[cfg(feature = "adkg")]
            MpcBackendKind::Avss => false,
        }
    }

    /// Whether this backend supports elliptic curve operations.
    pub fn supports_elliptic_curves(&self) -> bool {
        match self {
            #[cfg(feature = "honeybadger")]
            MpcBackendKind::HoneyBadger => false,
            #[cfg(feature = "adkg")]
            MpcBackendKind::Avss => true,
        }
    }

    /// Whether this backend supports client inputs.
    ///
    /// Both backends support client inputs; in ADKG the client and server roles
    /// are unified (every party is also a client).
    pub fn supports_client_input(&self) -> bool {
        match self {
            #[cfg(feature = "honeybadger")]
            MpcBackendKind::HoneyBadger => true,
            #[cfg(feature = "adkg")]
            MpcBackendKind::Avss => true,
        }
    }

    /// Human-readable name for this backend.
    pub fn name(&self) -> &'static str {
        match self {
            #[cfg(feature = "honeybadger")]
            MpcBackendKind::HoneyBadger => "honeybadger",
            #[cfg(feature = "adkg")]
            MpcBackendKind::Avss => "avss",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

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
    fn test_parse_avss() {
        assert_eq!(
            MpcBackendKind::from_str("avss").unwrap(),
            MpcBackendKind::Avss
        );
        assert_eq!(
            MpcBackendKind::from_str("AVSS").unwrap(),
            MpcBackendKind::Avss
        );
        // "adkg" is kept as a backward-compatible alias
        assert_eq!(
            MpcBackendKind::from_str("adkg").unwrap(),
            MpcBackendKind::Avss
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
        assert!(!hb.supports_elliptic_curves());
        assert!(hb.supports_client_input());
    }

    #[test]
    #[cfg(feature = "adkg")]
    fn test_avss_capabilities() {
        let avss = MpcBackendKind::Avss;
        assert!(avss.supports_general_mpc());
        assert!(!avss.supports_multiplication());
        assert!(avss.supports_elliptic_curves());
        assert!(avss.supports_client_input());
    }

    #[test]
    #[cfg(feature = "honeybadger")]
    fn test_honeybadger_supports_multiplication() {
        let hb = MpcBackendKind::HoneyBadger;
        assert!(hb.supports_multiplication());
    }
}
