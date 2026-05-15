use serde::{Deserialize, Serialize};

/// Maximum wire message payload size accepted from the network (1 MB).
pub(super) const MAX_WIRE_MESSAGE_LEN: usize = 1_048_576;

pub(super) const OPEN_REGISTRY_WIRE_PREFIX: &[u8; 4] = b"OPN1";

/// Sentinel value indicating the sender's party identity is unknown.
pub const UNKNOWN_SENDER_ID: usize = usize::MAX;

/// HoneyBadger open-in-exp wire prefix.
pub(super) const HB_EXP_OPEN_WIRE_PREFIX: &[u8; 4] = b"XOP1";
/// AVSS open-in-exp wire prefix.
pub(super) const AVSS_EXP_WIRE_PREFIX: &[u8; 4] = b"AXOP";
/// AVSS G2 open-in-exp wire prefix.
pub(super) const AVSS_G2_EXP_WIRE_PREFIX: &[u8; 4] = b"AXG2";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ExpOpenWireMessage {
    pub(super) instance_id: u64,
    pub(super) sender_party_id: usize,
    pub(super) share_id: usize,
    pub(super) partial_point: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) enum OpenRegistryWireMessage {
    Single {
        instance_id: u64,
        type_key: String,
        sender_party_id: usize,
        share: Vec<u8>,
    },
    Batch {
        instance_id: u64,
        type_key: String,
        sender_party_id: usize,
        shares: Vec<Vec<u8>>,
    },
}

pub fn encode_single_share_wire_message(
    instance_id: u64,
    type_key: &str,
    sender_party_id: usize,
    share_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let payload = OpenRegistryWireMessage::Single {
        instance_id,
        type_key: type_key.to_string(),
        sender_party_id,
        share: share_bytes.to_vec(),
    };
    let encoded =
        bincode::serialize(&payload).map_err(|e| format!("serialize open wire payload: {}", e))?;
    let mut out = Vec::with_capacity(OPEN_REGISTRY_WIRE_PREFIX.len() + encoded.len());
    out.extend_from_slice(OPEN_REGISTRY_WIRE_PREFIX);
    out.extend_from_slice(&encoded);
    Ok(out)
}

pub fn encode_batch_share_wire_message(
    instance_id: u64,
    type_key: &str,
    sender_party_id: usize,
    shares: &[Vec<u8>],
) -> Result<Vec<u8>, String> {
    let payload = OpenRegistryWireMessage::Batch {
        instance_id,
        type_key: type_key.to_string(),
        sender_party_id,
        shares: shares.to_vec(),
    };
    let encoded =
        bincode::serialize(&payload).map_err(|e| format!("serialize open wire payload: {}", e))?;
    let mut out = Vec::with_capacity(OPEN_REGISTRY_WIRE_PREFIX.len() + encoded.len());
    out.extend_from_slice(OPEN_REGISTRY_WIRE_PREFIX);
    out.extend_from_slice(&encoded);
    Ok(out)
}

fn encode_exp_open_wire_message(
    prefix: &[u8; 4],
    serialize_context: &str,
    instance_id: u64,
    sender_party_id: usize,
    share_id: usize,
    partial_point: &[u8],
) -> Result<Vec<u8>, String> {
    let payload = ExpOpenWireMessage {
        instance_id,
        sender_party_id,
        share_id,
        partial_point: partial_point.to_vec(),
    };
    let encoded = bincode::serialize(&payload).map_err(|e| format!("{serialize_context}: {e}"))?;
    let mut out = Vec::with_capacity(prefix.len() + encoded.len());
    out.extend_from_slice(prefix);
    out.extend_from_slice(&encoded);
    Ok(out)
}

pub fn encode_hb_open_exp_wire_message(
    instance_id: u64,
    sender_party_id: usize,
    share_id: usize,
    partial_point: &[u8],
) -> Result<Vec<u8>, String> {
    encode_exp_open_wire_message(
        HB_EXP_OPEN_WIRE_PREFIX,
        "serialize open-exp payload",
        instance_id,
        sender_party_id,
        share_id,
        partial_point,
    )
}

pub fn encode_avss_open_exp_wire_message(
    instance_id: u64,
    sender_party_id: usize,
    share_id: usize,
    partial_point: &[u8],
) -> Result<Vec<u8>, String> {
    encode_exp_open_wire_message(
        AVSS_EXP_WIRE_PREFIX,
        "serialize avss open-exp payload",
        instance_id,
        sender_party_id,
        share_id,
        partial_point,
    )
}

pub fn encode_avss_g2_open_exp_wire_message(
    instance_id: u64,
    sender_party_id: usize,
    share_id: usize,
    partial_point: &[u8],
) -> Result<Vec<u8>, String> {
    encode_exp_open_wire_message(
        AVSS_G2_EXP_WIRE_PREFIX,
        "serialize avss g2 open-exp payload",
        instance_id,
        sender_party_id,
        share_id,
        partial_point,
    )
}
