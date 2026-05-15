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
// RBC / ABA state (HB consensus)
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct RbcState {
    /// Maps (session_id, from_party) → message bytes
    pub messages: HashMap<(u64, usize), Vec<u8>>,
    /// Tracks deliveries: (receiver_party, from_party, session_id)
    pub delivered: HashSet<(usize, usize, u64)>,
}

#[derive(Default)]
pub struct AbaState {
    /// Maps (session_id, party_id) → proposed value
    pub proposals: HashMap<(u64, usize), bool>,
    /// Maps session_id → agreed result once consensus is reached
    pub results: HashMap<u64, bool>,
}
