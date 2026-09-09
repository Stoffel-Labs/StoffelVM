use super::HoneyBadgerMpcEngine;
use crate::net::curve::SupportedMpcField;
use crate::net::mpc_engine::{
    AsyncMpcEngineConsensus, MpcEngineConsensus, MpcEngineOperationResultExt, MpcEngineResult,
    MpcPartyId, RbcSessionId,
};
use ark_ec::{CurveGroup, PrimeGroup};
use stoffelnet::network_utils::Network;

impl<F, G> HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    async fn rbc_receive_with_quorum(
        &self,
        from_party: Option<usize>,
        timeout_ms: u64,
    ) -> Result<(usize, Vec<u8>), String> {
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_millis(timeout_ms);
        loop {
            let registry = self.open_registry();
            let notified = registry.rbc_notify.notified();
            let progress = registry.rbc_progress(
                self.topology.party_id(),
                from_party,
                self.topology.n_parties(),
                self.topology.threshold(),
            )?;

            // ECHO/READY contributions are recorded in the shared registry by
            // rbc_progress. Wake peer receivers that may now have a quorum.
            if !progress.relays.is_empty() {
                registry.rbc_notify.notify_waiters();
            }

            for relay in progress.relays {
                let wire_message = crate::net::open_registry::encode_rbc_relay_wire_message(
                    self.current_instance_id(),
                    relay.session_id,
                    relay.broadcaster_party_id,
                    self.topology.party_id(),
                    relay.digest,
                    relay.message.as_deref(),
                    matches!(relay.phase, crate::net::open_registry::RbcRelayPhase::Ready),
                )?;
                if self.net.party_count() > 1 {
                    self.broadcast_open_registry_payload(wire_message).await?;
                }
            }

            if let Some(delivery) = progress.delivery {
                return Ok(delivery);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(match from_party {
                    Some(party) => {
                        format!("RBC receive timeout waiting for message from party {party}")
                    }
                    None => {
                        "RBC receive_any timeout waiting for message from any party".to_string()
                    }
                });
            }
            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep_until(deadline) => {}
            }
        }
    }
}

// RBC uses the engine's session-local open registry for in-process coordination
// between parties. Multi-process deployments should route through the
// protocol/network implementations behind this adapter.
impl<F, G> MpcEngineConsensus for HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    fn rbc_broadcast(&self, message: &[u8]) -> MpcEngineResult<RbcSessionId> {
        let session_id = self
            .open_registry()
            .rbc_broadcast(self.topology.party_id(), message)
            .map_mpc_engine_operation("rbc_broadcast")?;
        let wire_message = crate::net::open_registry::encode_rbc_wire_message(
            self.current_instance_id(),
            session_id,
            self.topology.party_id(),
            message,
        )
        .map_mpc_engine_operation("rbc_broadcast")?;
        let digest = *blake3::hash(message).as_bytes();
        self.open_registry()
            .insert_rbc_relay(
                false,
                session_id,
                self.topology.party_id(),
                self.topology.party_id(),
                digest,
                Some(message.to_vec()),
            )
            .map_mpc_engine_operation("rbc_broadcast")?;
        let echo_message = crate::net::open_registry::encode_rbc_relay_wire_message(
            self.current_instance_id(),
            session_id,
            self.topology.party_id(),
            self.topology.party_id(),
            digest,
            Some(message),
            false,
        )
        .map_mpc_engine_operation("rbc_broadcast")?;
        if self.net.party_count() > 1 {
            self.broadcast_open_registry_payload_sync(wire_message)
                .map_mpc_engine_operation("rbc_broadcast")?;
            self.broadcast_open_registry_payload_sync(echo_message)
                .map_mpc_engine_operation("rbc_broadcast")?;
        }
        Ok(RbcSessionId::new(session_id))
    }

    fn rbc_receive(&self, from_party: MpcPartyId, timeout_ms: u64) -> MpcEngineResult<Vec<u8>> {
        crate::net::block_on_current(
            self.rbc_receive_with_quorum(Some(from_party.id()), timeout_ms),
        )
        .map(|(_, message)| message)
        .map_mpc_engine_operation("rbc_receive")
    }

    fn rbc_receive_any(&self, timeout_ms: u64) -> MpcEngineResult<(MpcPartyId, Vec<u8>)> {
        crate::net::block_on_current(self.rbc_receive_with_quorum(None, timeout_ms))
            .map(|(party_id, message)| (MpcPartyId::new(party_id), message))
            .map_mpc_engine_operation("rbc_receive_any")
    }
}

#[async_trait::async_trait]
impl<F, G> AsyncMpcEngineConsensus for HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    async fn rbc_broadcast_async(&self, message: &[u8]) -> MpcEngineResult<RbcSessionId> {
        let session_id = self
            .open_registry()
            .rbc_broadcast_async(self.topology.party_id(), message)
            .await
            .map_mpc_engine_operation("async_rbc_broadcast")?;
        let wire_message = crate::net::open_registry::encode_rbc_wire_message(
            self.current_instance_id(),
            session_id,
            self.topology.party_id(),
            message,
        )
        .map_mpc_engine_operation("async_rbc_broadcast")?;
        let digest = *blake3::hash(message).as_bytes();
        self.open_registry()
            .insert_rbc_relay(
                false,
                session_id,
                self.topology.party_id(),
                self.topology.party_id(),
                digest,
                Some(message.to_vec()),
            )
            .map_mpc_engine_operation("async_rbc_broadcast")?;
        let echo_message = crate::net::open_registry::encode_rbc_relay_wire_message(
            self.current_instance_id(),
            session_id,
            self.topology.party_id(),
            self.topology.party_id(),
            digest,
            Some(message),
            false,
        )
        .map_mpc_engine_operation("async_rbc_broadcast")?;
        if self.net.party_count() > 1 {
            self.broadcast_open_registry_payload(wire_message)
                .await
                .map_mpc_engine_operation("async_rbc_broadcast")?;
            self.broadcast_open_registry_payload(echo_message)
                .await
                .map_mpc_engine_operation("async_rbc_broadcast")?;
        }
        Ok(RbcSessionId::new(session_id))
    }

    async fn rbc_receive_async(
        &self,
        from_party: MpcPartyId,
        timeout_ms: u64,
    ) -> MpcEngineResult<Vec<u8>> {
        self.rbc_receive_with_quorum(Some(from_party.id()), timeout_ms)
            .await
            .map(|(_, message)| message)
            .map_mpc_engine_operation("async_rbc_receive")
    }

    async fn rbc_receive_any_async(
        &self,
        timeout_ms: u64,
    ) -> MpcEngineResult<(MpcPartyId, Vec<u8>)> {
        self.rbc_receive_with_quorum(None, timeout_ms)
            .await
            .map(|(party_id, message)| (MpcPartyId::new(party_id), message))
            .map_mpc_engine_operation("async_rbc_receive_any")
    }
}
