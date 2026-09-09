use std::collections::{HashMap, HashSet};

use stoffel_vm_types::core_types::ClearShareValue;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum OpenResult {
    ClearShare(ClearShareValue),
    Bytes(Vec<u8>),
}

#[derive(Clone, Default)]
pub(super) struct OpenAccumulator {
    pub(super) shares: Vec<Vec<u8>>,
    pub(super) party_ids: Vec<usize>,
    pub(super) result: Option<OpenResult>,
}

/// Key: (sequence, type_key)
pub(super) type SingleKey = (usize, String);

#[derive(Clone)]
pub(super) struct BatchOpenAccumulator {
    pub(super) shares_per_position: Vec<Vec<Vec<u8>>>,
    pub(super) party_ids: Vec<usize>,
    pub(super) results: Option<Vec<ClearShareValue>>,
}

impl BatchOpenAccumulator {
    pub(super) fn new(batch_size: usize) -> Self {
        Self {
            shares_per_position: vec![Vec::new(); batch_size],
            party_ids: Vec::new(),
            results: None,
        }
    }
}

/// Key: (sequence, type_key, batch_size)
pub(super) type BatchKey = (usize, String, usize);

// ---------------------------------------------------------------------------
// EXP accumulator (shared by HB and AVSS open-in-exponent)
// ---------------------------------------------------------------------------

/// Key: sequence number (no instance_id needed — scoped per instance)
pub(super) type ExpKey = usize;

#[derive(Default, Clone)]
pub struct ExpOpenAccumulator {
    pub partial_points: Vec<(usize, Vec<u8>)>, // (share_id, serialized affine point)
    pub party_ids: Vec<usize>,
    pub result: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpOpenRegistryKind {
    G1,
    G2,
}

#[derive(Debug, Clone, Copy)]
pub struct ExpOpenRequest<'a> {
    pub kind: ExpOpenRegistryKind,
    pub sequence: Option<usize>,
    pub party_id: usize,
    pub share_id: usize,
    pub partial_point: &'a [u8],
    pub required: usize,
    pub timeout_message: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpOpenProgress {
    Pending {
        sequence: usize,
        current_count: usize,
    },
    Ready(Vec<u8>),
    Collected {
        sequence: usize,
        partial_points: Vec<(usize, Vec<u8>)>,
    },
}

// ---------------------------------------------------------------------------
// RBC state (HB consensus)
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct RbcState {
    /// Monotonic local session allocator per broadcaster.
    pub next_sessions: HashMap<usize, u64>,
    /// Maps broadcaster VAL sessions to the digest already accepted for that session.
    pub messages: HashMap<(u64, usize), [u8; 32]>,
    /// Candidate payloads learned from VAL or ECHO, keyed by their digest.
    pub candidates: HashMap<(u64, usize, [u8; 32]), Vec<u8>>,
    /// Authenticated peer whose quota was charged when each candidate was first retained.
    pub candidate_sources: HashMap<(u64, usize, [u8; 32]), usize>,
    /// Tracks deliveries: (receiver_party, from_party, session_id)
    pub delivered: HashSet<(usize, usize, u64)>,
    /// Local receiver identities that share this registry (normally exactly one in production).
    pub receivers: HashSet<usize>,
    /// Authenticated ECHO relays keyed by (session, broadcaster, digest).
    pub echoes: HashMap<(u64, usize, [u8; 32]), HashSet<usize>>,
    /// Authenticated READY relays keyed by (session, broadcaster, digest).
    pub readies: HashMap<(u64, usize, [u8; 32]), HashSet<usize>>,
    /// Per-local-party protocol messages already emitted.
    pub sent_echoes: HashSet<(usize, usize, u64)>,
    pub sent_readies: HashSet<(usize, usize, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RbcRelayPhase {
    Echo,
    Ready,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RbcRelay {
    pub phase: RbcRelayPhase,
    pub session_id: u64,
    pub broadcaster_party_id: usize,
    pub digest: [u8; 32],
    pub message: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RbcProgress {
    pub relays: Vec<RbcRelay>,
    pub delivery: Option<(usize, Vec<u8>)>,
}
