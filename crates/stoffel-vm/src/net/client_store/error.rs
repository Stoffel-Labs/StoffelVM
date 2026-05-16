#[cfg(any(feature = "honeybadger", feature = "avss"))]
use super::ClientShareIndex;
#[cfg(any(feature = "honeybadger", feature = "avss"))]
use stoffelnet::network_utils::ClientId;

#[derive(Debug, thiserror::Error)]
pub enum ClientInputStoreError {
    #[error(
        "failed to serialize robust share for client {client_id} at index {share_index}: {reason}"
    )]
    #[cfg(feature = "honeybadger")]
    RobustShareSerialization {
        client_id: ClientId,
        share_index: ClientShareIndex,
        reason: String,
    },
    #[cfg(feature = "avss")]
    #[error(
        "failed to serialize Feldman share for client {client_id} at index {share_index}: {reason}"
    )]
    FeldmanShareSerialization {
        client_id: ClientId,
        share_index: ClientShareIndex,
        reason: String,
    },
    #[cfg(feature = "avss")]
    #[error("failed to serialize Feldman commitments for client {client_id} at index {share_index}: {reason}")]
    FeldmanCommitmentSerialization {
        client_id: ClientId,
        share_index: ClientShareIndex,
        reason: String,
    },
}
