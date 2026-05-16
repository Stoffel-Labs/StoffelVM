use std::fmt;

bitflags::bitflags! {
    /// Capability flags advertised by an [`MpcEngine`](super::MpcEngine) implementation.
    ///
    /// Engines return these from [`MpcEngine::capabilities()`](super::MpcEngine::capabilities).
    /// The individual `supports_*()` convenience methods delegate to this bitfield.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MpcCapabilities: u32 {
        const MULTIPLICATION   = 0b0000_0001;
        const ELLIPTIC_CURVES  = 0b0000_0010;
        const CLIENT_INPUT     = 0b0000_0100;
        const CONSENSUS        = 0b0000_1000;
        const OPEN_IN_EXP      = 0b0001_0000;
        const RESERVATION      = 0b0010_0000;
        const CLIENT_OUTPUT    = 0b0100_0000;
        const RANDOMNESS       = 0b1000_0000;
        const FIELD_OPEN       = 0b0001_0000_0000;
        const PREPROC_PERSISTENCE = 0b0010_0000_0000;
    }
}

pub type MpcCapabilityResult<T> = Result<T, MpcCapabilityError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MpcCapabilityError {
    UnsupportedCapability { name: String },
}

impl fmt::Display for MpcCapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MpcCapabilityError::UnsupportedCapability { name } => {
                write!(f, "Unsupported MPC capability: {name}")
            }
        }
    }
}

impl std::error::Error for MpcCapabilityError {}

impl From<MpcCapabilityError> for String {
    fn from(error: MpcCapabilityError) -> Self {
        error.to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MpcCapability {
    Multiplication,
    EllipticCurves,
    ClientInput,
    Consensus,
    OpenInExponent,
    Reservation,
    ClientOutput,
    Randomness,
    FieldOpen,
    PreprocPersistence,
}

impl MpcCapability {
    pub const ALL: [Self; 10] = [
        Self::Multiplication,
        Self::EllipticCurves,
        Self::ClientInput,
        Self::Consensus,
        Self::OpenInExponent,
        Self::Reservation,
        Self::ClientOutput,
        Self::Randomness,
        Self::FieldOpen,
        Self::PreprocPersistence,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            MpcCapability::Multiplication => "multiplication",
            MpcCapability::EllipticCurves => "elliptic-curves",
            MpcCapability::ClientInput => "client-input",
            MpcCapability::Consensus => "consensus",
            MpcCapability::OpenInExponent => "open-in-exponent",
            MpcCapability::Reservation => "reservation",
            MpcCapability::ClientOutput => "client-output",
            MpcCapability::Randomness => "randomness",
            MpcCapability::FieldOpen => "field-open",
            MpcCapability::PreprocPersistence => "preprocessing-persistence",
        }
    }

    pub fn parse_name(input: &str) -> MpcCapabilityResult<Self> {
        let normalized = input.trim().to_ascii_lowercase().replace('_', "-");
        match normalized.as_str() {
            "multiplication" | "multiply" | "mul" => Ok(MpcCapability::Multiplication),
            "elliptic-curves" | "elliptic-curve" | "curves" => Ok(MpcCapability::EllipticCurves),
            "client-input" | "client-inputs" => Ok(MpcCapability::ClientInput),
            "consensus" | "rbc-aba" | "rbc" | "aba" => Ok(MpcCapability::Consensus),
            "open-in-exponent" | "open-in-exp" | "open-exp" => Ok(MpcCapability::OpenInExponent),
            "reservation" | "preprocessing-reservation" | "preproc-reservation" => {
                Ok(MpcCapability::Reservation)
            }
            "client-output" | "client-outputs" => Ok(MpcCapability::ClientOutput),
            "randomness" | "random" => Ok(MpcCapability::Randomness),
            "field-open" | "field-opening" | "open-field" => Ok(MpcCapability::FieldOpen),
            "preprocessing-persistence" | "preproc-persistence" | "preproc-store" => {
                Ok(MpcCapability::PreprocPersistence)
            }
            _ => Err(MpcCapabilityError::UnsupportedCapability {
                name: input.trim().to_string(),
            }),
        }
    }

    pub const fn flag(self) -> MpcCapabilities {
        match self {
            MpcCapability::Multiplication => MpcCapabilities::MULTIPLICATION,
            MpcCapability::EllipticCurves => MpcCapabilities::ELLIPTIC_CURVES,
            MpcCapability::ClientInput => MpcCapabilities::CLIENT_INPUT,
            MpcCapability::Consensus => MpcCapabilities::CONSENSUS,
            MpcCapability::OpenInExponent => MpcCapabilities::OPEN_IN_EXP,
            MpcCapability::Reservation => MpcCapabilities::RESERVATION,
            MpcCapability::ClientOutput => MpcCapabilities::CLIENT_OUTPUT,
            MpcCapability::Randomness => MpcCapabilities::RANDOMNESS,
            MpcCapability::FieldOpen => MpcCapabilities::FIELD_OPEN,
            MpcCapability::PreprocPersistence => MpcCapabilities::PREPROC_PERSISTENCE,
        }
    }

    const fn advertised_label(self) -> &'static str {
        match self {
            MpcCapability::Multiplication => "multiplication",
            MpcCapability::EllipticCurves => "elliptic curves",
            MpcCapability::ClientInput => "client input",
            MpcCapability::Consensus => "consensus",
            MpcCapability::OpenInExponent => "open-in-exponent",
            MpcCapability::Reservation => "reservation",
            MpcCapability::ClientOutput => "client output",
            MpcCapability::Randomness => "randomness",
            MpcCapability::FieldOpen => "field opening",
            MpcCapability::PreprocPersistence => "preprocessing persistence",
        }
    }

    const fn trait_name(self) -> Option<&'static str> {
        match self {
            MpcCapability::Multiplication => Some("MpcEngineMultiplication"),
            MpcCapability::ClientInput => Some("MpcEngineClientOps"),
            MpcCapability::Consensus => Some("MpcEngineConsensus"),
            MpcCapability::OpenInExponent => Some("MpcEngineOpenInExponent"),
            MpcCapability::Reservation => Some("MpcEngineReservation"),
            MpcCapability::ClientOutput => Some("MpcEngineClientOutput"),
            MpcCapability::Randomness => Some("MpcEngineRandomness"),
            MpcCapability::FieldOpen => Some("MpcEngineFieldOpen"),
            MpcCapability::PreprocPersistence => Some("MpcEnginePreprocPersistence"),
            MpcCapability::EllipticCurves => None,
        }
    }

    const fn unsupported_message(self) -> &'static str {
        match self {
            MpcCapability::Multiplication => "does not support multiplication",
            MpcCapability::EllipticCurves => "does not support elliptic curve operations",
            MpcCapability::ClientInput => "does not support client input hydration",
            MpcCapability::Consensus => "does not support consensus (RBC/ABA)",
            MpcCapability::OpenInExponent => "does not support Share.open_exp",
            MpcCapability::Reservation => "does not support preprocessing reservation",
            MpcCapability::ClientOutput => "does not support client output delivery",
            MpcCapability::Randomness => "does not support jointly-random share generation",
            MpcCapability::FieldOpen => "does not support Share.open_field",
            MpcCapability::PreprocPersistence => "does not support preprocessing persistence",
        }
    }

    pub(crate) fn error_for(self, protocol_name: &str, advertised: bool) -> String {
        if advertised {
            if let Some(trait_name) = self.trait_name() {
                format!(
                    "MPC backend '{}' advertises {} but does not expose {}",
                    protocol_name,
                    self.advertised_label(),
                    trait_name
                )
            } else {
                format!(
                    "MPC backend '{}' {}",
                    protocol_name,
                    self.unsupported_message()
                )
            }
        } else {
            format!(
                "MPC backend '{}' {}",
                protocol_name,
                self.unsupported_message()
            )
        }
    }
}

impl MpcCapabilities {
    pub fn supports(self, capability: MpcCapability) -> bool {
        self.contains(capability.flag())
    }

    pub fn iter_supported(self) -> impl Iterator<Item = MpcCapability> {
        MpcCapability::ALL
            .into_iter()
            .filter(move |capability| self.supports(*capability))
    }
}
