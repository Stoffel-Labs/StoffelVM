use stoffelnet::network_utils::Network;

/// Broadcast an already-encoded payload to every party except the sender.
pub(crate) async fn broadcast_to_other_parties<N>(
    network: &N,
    party_count: usize,
    own_party_id: usize,
    payload: &[u8],
    peer_error_context: &str,
) -> Result<(), String>
where
    N: Network + Sync,
{
    for peer_id in 0..party_count {
        if peer_id == own_party_id {
            continue;
        }
        network
            .send(peer_id, payload)
            .await
            .map_err(|error| format!("{peer_error_context} {peer_id}: {error}"))?;
    }
    Ok(())
}
