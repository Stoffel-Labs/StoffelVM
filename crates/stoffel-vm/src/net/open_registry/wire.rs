use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

/// Maximum wire message payload size accepted from the network (1 MB).
pub(super) const MAX_WIRE_MESSAGE_LEN: usize = 1_048_576;
/// Maximum number of independently allocated positions in one batch frame.
pub(super) const MAX_BATCH_ELEMENTS: usize = 4_096;
/// Maximum UTF-8 bytes accepted for a registry type discriminator.
pub(super) const MAX_TYPE_KEY_LEN: usize = 256;

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
    pub(super) seq: u64,
    pub(super) sender_party_id: usize,
    pub(super) share_id: usize,
    pub(super) partial_point: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) enum OpenRegistryWireMessage {
    Single {
        instance_id: u64,
        seq: u64,
        type_key: String,
        sender_party_id: usize,
        share: Vec<u8>,
    },
    Batch {
        instance_id: u64,
        seq: u64,
        type_key: String,
        sender_party_id: usize,
        #[serde(deserialize_with = "deserialize_bounded_batch")]
        shares: Vec<Vec<u8>>,
    },
    Rbc {
        instance_id: u64,
        session_id: u64,
        sender_party_id: usize,
        message: Vec<u8>,
    },
    RbcEcho {
        instance_id: u64,
        session_id: u64,
        broadcaster_party_id: usize,
        sender_party_id: usize,
        digest: [u8; 32],
        message: Vec<u8>,
    },
    RbcReady {
        instance_id: u64,
        session_id: u64,
        broadcaster_party_id: usize,
        sender_party_id: usize,
        digest: [u8; 32],
    },
}

fn deserialize_bounded_batch<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedBatchVisitor;

    impl<'de> Visitor<'de> for BoundedBatchVisitor {
        type Value = Vec<Vec<u8>>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "a batch with at most {MAX_BATCH_ELEMENTS} elements"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence
                .size_hint()
                .is_some_and(|length| length > MAX_BATCH_ELEMENTS)
            {
                return Err(A::Error::custom(format!(
                    "batch element count exceeds maximum of {MAX_BATCH_ELEMENTS}"
                )));
            }
            let mut shares = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
            while let Some(share) = sequence.next_element()? {
                if shares.len() == MAX_BATCH_ELEMENTS {
                    return Err(A::Error::custom(format!(
                        "batch element count exceeds maximum of {MAX_BATCH_ELEMENTS}"
                    )));
                }
                shares.push(share);
            }
            Ok(shares)
        }
    }

    deserializer.deserialize_seq(BoundedBatchVisitor)
}

/// Serialization-only borrowed mirror of `OpenRegistryWireMessage`.
///
/// Variant order and fields intentionally match the owned wire enum, so bincode
/// produces the same payload without cloning an entire batch first.
#[derive(Serialize)]
enum BorrowedOpenRegistryWireMessage<'a> {
    Single {
        instance_id: u64,
        seq: u64,
        type_key: &'a str,
        sender_party_id: usize,
        share: &'a [u8],
    },
    Batch {
        instance_id: u64,
        seq: u64,
        type_key: &'a str,
        sender_party_id: usize,
        shares: &'a [Vec<u8>],
    },
    Rbc {
        instance_id: u64,
        session_id: u64,
        sender_party_id: usize,
        message: &'a [u8],
    },
    RbcEcho {
        instance_id: u64,
        session_id: u64,
        broadcaster_party_id: usize,
        sender_party_id: usize,
        digest: [u8; 32],
        message: &'a [u8],
    },
    RbcReady {
        instance_id: u64,
        session_id: u64,
        broadcaster_party_id: usize,
        sender_party_id: usize,
        digest: [u8; 32],
    },
}

pub fn encode_single_share_wire_message(
    instance_id: u64,
    seq: usize,
    type_key: &str,
    sender_party_id: usize,
    share_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let payload = BorrowedOpenRegistryWireMessage::Single {
        instance_id,
        seq: seq as u64,
        type_key,
        sender_party_id,
        share: share_bytes,
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
    seq: usize,
    type_key: &str,
    sender_party_id: usize,
    shares: &[Vec<u8>],
) -> Result<Vec<u8>, String> {
    let payload = BorrowedOpenRegistryWireMessage::Batch {
        instance_id,
        seq: seq as u64,
        type_key,
        sender_party_id,
        shares,
    };
    let encoded =
        bincode::serialize(&payload).map_err(|e| format!("serialize open wire payload: {}", e))?;
    let mut out = Vec::with_capacity(OPEN_REGISTRY_WIRE_PREFIX.len() + encoded.len());
    out.extend_from_slice(OPEN_REGISTRY_WIRE_PREFIX);
    out.extend_from_slice(&encoded);
    Ok(out)
}

pub fn encode_rbc_wire_message(
    instance_id: u64,
    session_id: u64,
    sender_party_id: usize,
    message: &[u8],
) -> Result<Vec<u8>, String> {
    let payload = BorrowedOpenRegistryWireMessage::Rbc {
        instance_id,
        session_id,
        sender_party_id,
        message,
    };
    let encoded =
        bincode::serialize(&payload).map_err(|e| format!("serialize RBC payload: {}", e))?;
    let mut out = Vec::with_capacity(OPEN_REGISTRY_WIRE_PREFIX.len() + encoded.len());
    out.extend_from_slice(OPEN_REGISTRY_WIRE_PREFIX);
    out.extend_from_slice(&encoded);
    Ok(out)
}

pub fn encode_rbc_relay_wire_message(
    instance_id: u64,
    session_id: u64,
    broadcaster_party_id: usize,
    sender_party_id: usize,
    digest: [u8; 32],
    message: Option<&[u8]>,
    ready: bool,
) -> Result<Vec<u8>, String> {
    let payload = if ready {
        BorrowedOpenRegistryWireMessage::RbcReady {
            instance_id,
            session_id,
            broadcaster_party_id,
            sender_party_id,
            digest,
        }
    } else {
        let message = message.ok_or_else(|| "RBC ECHO relay is missing its payload".to_string())?;
        BorrowedOpenRegistryWireMessage::RbcEcho {
            instance_id,
            session_id,
            broadcaster_party_id,
            sender_party_id,
            digest,
            message,
        }
    };
    let encoded =
        bincode::serialize(&payload).map_err(|e| format!("serialize RBC relay payload: {e}"))?;
    let mut out = Vec::with_capacity(OPEN_REGISTRY_WIRE_PREFIX.len() + encoded.len());
    out.extend_from_slice(OPEN_REGISTRY_WIRE_PREFIX);
    out.extend_from_slice(&encoded);
    Ok(out)
}

fn encode_exp_open_wire_message(
    prefix: &[u8; 4],
    serialize_context: &str,
    instance_id: u64,
    seq: usize,
    sender_party_id: usize,
    share_id: usize,
    partial_point: &[u8],
) -> Result<Vec<u8>, String> {
    let payload = ExpOpenWireMessage {
        instance_id,
        seq: seq as u64,
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
    seq: usize,
    sender_party_id: usize,
    share_id: usize,
    partial_point: &[u8],
) -> Result<Vec<u8>, String> {
    encode_exp_open_wire_message(
        HB_EXP_OPEN_WIRE_PREFIX,
        "serialize open-exp payload",
        instance_id,
        seq,
        sender_party_id,
        share_id,
        partial_point,
    )
}

pub fn encode_avss_open_exp_wire_message(
    instance_id: u64,
    seq: usize,
    sender_party_id: usize,
    share_id: usize,
    partial_point: &[u8],
) -> Result<Vec<u8>, String> {
    encode_exp_open_wire_message(
        AVSS_EXP_WIRE_PREFIX,
        "serialize avss open-exp payload",
        instance_id,
        seq,
        sender_party_id,
        share_id,
        partial_point,
    )
}

pub fn encode_avss_g2_open_exp_wire_message(
    instance_id: u64,
    seq: usize,
    sender_party_id: usize,
    share_id: usize,
    partial_point: &[u8],
) -> Result<Vec<u8>, String> {
    encode_exp_open_wire_message(
        AVSS_G2_EXP_WIRE_PREFIX,
        "serialize avss g2 open-exp payload",
        instance_id,
        seq,
        sender_party_id,
        share_id,
        partial_point,
    )
}
