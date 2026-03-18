//! MPC backend selection.
//!
//! Provides an enum for choosing between HoneyBadger and AVSS backends at runtime.

/// Available MPC backend implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpcBackendKind {
    #[cfg(feature = "honeybadger")]
    HoneyBadger,
    #[cfg(feature = "avss")]
    Avss,
}

impl std::str::FromStr for MpcBackendKind {
    type Err = String;

    /// Parse a backend name from a string.
    ///
    /// Accepted values:
    /// - `"honeybadger"` or `"hb"` -> `HoneyBadger`
    /// - `"avss"` or `"adkg"` -> `Avss`
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            #[cfg(feature = "honeybadger")]
            "honeybadger" | "hb" => Ok(MpcBackendKind::HoneyBadger),
            #[cfg(feature = "avss")]
            "avss" | "adkg" => Ok(MpcBackendKind::Avss),
            other => {
                let mut available = Vec::new();
                #[cfg(feature = "honeybadger")]
                available.push("honeybadger");
                #[cfg(feature = "avss")]
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
    /// Prefers HoneyBadger when available, falls back to AVSS.
    pub fn default_backend() -> Self {
        #[cfg(feature = "honeybadger")]
        {
            MpcBackendKind::HoneyBadger
        }
        #[cfg(not(feature = "honeybadger"))]
        {
            #[cfg(feature = "avss")]
            {
                MpcBackendKind::Avss
            }
            #[cfg(not(feature = "avss"))]
            {
                compile_error!("At least one MPC backend feature must be enabled");
            }
        }
    }

    /// Whether this backend supports secure multiplication (requires Beaver triples).
    pub fn supports_multiplication(&self) -> bool {
        match self {
            #[cfg(feature = "honeybadger")]
            MpcBackendKind::HoneyBadger => true,
            #[cfg(feature = "avss")]
            MpcBackendKind::Avss => true,
        }
    }

    /// Whether this backend supports and is safe for elliptic curve operations.
    ///
    /// AVSS uses `FeldmanShamirShare<F, G>` whose commitments are EC points (`G`),
    /// enabling operations like `open_share_in_exp` and threshold signatures.
    /// HoneyBadger uses `RobustShare<F>` with field-only commitments and is not
    /// suitable for direct EC operations.
    pub fn supports_elliptic_curves(&self) -> bool {
        match self {
            #[cfg(feature = "honeybadger")]
            MpcBackendKind::HoneyBadger => false,
            #[cfg(feature = "avss")]
            MpcBackendKind::Avss => true,
        }
    }

    /// Whether this backend supports standalone client input mode.
    ///
    /// HoneyBadger supports a separate client role (`stoffel-run --client`) where
    /// external clients submit secret inputs to the MPC parties.
    ///
    /// AVSS does not yet support this: the underlying `AdkgNode` protocol ignores
    /// `input_ids` during setup and has no `InputServer`/`OutputServer` equivalent.
    /// In the current AVSS design, each party provides its own inputs directly.
    pub fn supports_client_input(&self) -> bool {
        match self {
            #[cfg(feature = "honeybadger")]
            MpcBackendKind::HoneyBadger => true,
            #[cfg(feature = "avss")]
            MpcBackendKind::Avss => false,
        }
    }

    /// Human-readable name for this backend.
    pub fn name(&self) -> &'static str {
        match self {
            #[cfg(feature = "honeybadger")]
            MpcBackendKind::HoneyBadger => "honeybadger",
            #[cfg(feature = "avss")]
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
    #[cfg(feature = "avss")]
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
        assert_eq!(
            MpcBackendKind::default_backend(),
            MpcBackendKind::HoneyBadger
        );
    }

    #[test]
    #[cfg(feature = "honeybadger")]
    fn test_honeybadger_capabilities() {
        let hb = MpcBackendKind::HoneyBadger;
        assert!(!hb.supports_elliptic_curves());
        assert!(hb.supports_client_input());
    }

    #[test]
    #[cfg(feature = "avss")]
    fn test_avss_capabilities() {
        let avss = MpcBackendKind::Avss;
        assert!(avss.supports_multiplication());
        assert!(avss.supports_elliptic_curves());
        assert!(!avss.supports_client_input());
    }

    #[test]
    #[cfg(feature = "honeybadger")]
    fn test_honeybadger_supports_multiplication() {
        let hb = MpcBackendKind::HoneyBadger;
        assert!(hb.supports_multiplication());
    }
}
