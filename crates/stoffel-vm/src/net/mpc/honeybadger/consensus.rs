use super::HoneyBadgerMpcEngine;
use crate::net::curve::SupportedMpcField;
use crate::net::mpc_engine::{
    AbaSessionId, AsyncMpcEngineConsensus, MpcEngineConsensus, MpcEngineOperationResultExt,
    MpcEngineResult, MpcPartyId, RbcSessionId,
};
use ark_ec::{CurveGroup, PrimeGroup};

// RBC and ABA use the engine's session-local open registry for in-process
// coordination between parties. Multi-process deployments should route through
// the protocol/network implementations behind this adapter.
impl<F, G> MpcEngineConsensus for HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    fn rbc_broadcast(&self, message: &[u8]) -> MpcEngineResult<RbcSessionId> {
        self.open_registry
            .rbc_broadcast(self.topology.party_id(), message)
            .map(RbcSessionId::new)
            .map_mpc_engine_operation("rbc_broadcast")
    }

    fn rbc_receive(&self, from_party: MpcPartyId, timeout_ms: u64) -> MpcEngineResult<Vec<u8>> {
        self.open_registry
            .rbc_receive(self.topology.party_id(), from_party.id(), timeout_ms)
            .map_mpc_engine_operation("rbc_receive")
    }

    fn rbc_receive_any(&self, timeout_ms: u64) -> MpcEngineResult<(MpcPartyId, Vec<u8>)> {
        self.open_registry
            .rbc_receive_any(self.topology.party_id(), timeout_ms)
            .map(|(party_id, message)| (MpcPartyId::new(party_id), message))
            .map_mpc_engine_operation("rbc_receive_any")
    }

    fn aba_propose(&self, value: bool) -> MpcEngineResult<AbaSessionId> {
        self.open_registry
            .aba_propose(self.topology.party_id(), value)
            .map(AbaSessionId::new)
            .map_mpc_engine_operation("aba_propose")
    }

    fn aba_result(&self, session_id: AbaSessionId, timeout_ms: u64) -> MpcEngineResult<bool> {
        let required = 2 * self.topology.threshold() + 1;
        self.open_registry
            .aba_result(required, session_id.id(), timeout_ms)
            .map_mpc_engine_operation("aba_result")
    }
}

#[async_trait::async_trait]
impl<F, G> AsyncMpcEngineConsensus for HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    async fn rbc_broadcast_async(&self, message: &[u8]) -> MpcEngineResult<RbcSessionId> {
        self.open_registry
            .rbc_broadcast_async(self.topology.party_id(), message)
            .await
            .map(RbcSessionId::new)
            .map_mpc_engine_operation("async_rbc_broadcast")
    }

    async fn rbc_receive_async(
        &self,
        from_party: MpcPartyId,
        timeout_ms: u64,
    ) -> MpcEngineResult<Vec<u8>> {
        self.open_registry
            .rbc_receive_async(self.topology.party_id(), from_party.id(), timeout_ms)
            .await
            .map_mpc_engine_operation("async_rbc_receive")
    }

    async fn rbc_receive_any_async(
        &self,
        timeout_ms: u64,
    ) -> MpcEngineResult<(MpcPartyId, Vec<u8>)> {
        self.open_registry
            .rbc_receive_any_async(self.topology.party_id(), timeout_ms)
            .await
            .map(|(party_id, message)| (MpcPartyId::new(party_id), message))
            .map_mpc_engine_operation("async_rbc_receive_any")
    }

    async fn aba_propose_async(&self, value: bool) -> MpcEngineResult<AbaSessionId> {
        self.open_registry
            .aba_propose_async(self.topology.party_id(), value)
            .await
            .map(AbaSessionId::new)
            .map_mpc_engine_operation("async_aba_propose")
    }

    async fn aba_result_async(
        &self,
        session_id: AbaSessionId,
        timeout_ms: u64,
    ) -> MpcEngineResult<bool> {
        let required = 2 * self.topology.threshold() + 1;
        self.open_registry
            .aba_result_async(required, session_id.id(), timeout_ms)
            .await
            .map_mpc_engine_operation("async_aba_result")
    }
}
