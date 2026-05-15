use super::super::{AbaSessionId, MpcEngineResult, MpcPartyId, RbcSessionId};
use super::core::MpcEngine;

/// Extended MPC engine trait for consensus protocols (RBC and ABA).
///
/// RBC (Reliable Broadcast) ensures that:
/// - If the broadcaster is honest, all honest parties deliver the same message
/// - If any honest party delivers a message, all honest parties eventually
///   deliver it
///
/// ABA (Asynchronous Binary Agreement) ensures that:
/// - All honest parties eventually decide on the same binary value
/// - If all honest parties propose the same value, that value is decided
pub trait MpcEngineConsensus: MpcEngine {
    /// Broadcast a message reliably to all parties using RBC.
    fn rbc_broadcast(&self, message: &[u8]) -> MpcEngineResult<RbcSessionId>;

    /// Receive a reliable broadcast from a specific party.
    fn rbc_receive(&self, from_party: MpcPartyId, timeout_ms: u64) -> MpcEngineResult<Vec<u8>>;

    /// Receive a reliable broadcast from any party.
    fn rbc_receive_any(&self, timeout_ms: u64) -> MpcEngineResult<(MpcPartyId, Vec<u8>)>;

    /// Propose a binary value for Asynchronous Binary Agreement.
    fn aba_propose(&self, value: bool) -> MpcEngineResult<AbaSessionId>;

    /// Get the agreed-upon result for an ABA session.
    fn aba_result(&self, session_id: AbaSessionId, timeout_ms: u64) -> MpcEngineResult<bool>;

    /// Propose a value and wait for agreement.
    fn aba_propose_and_wait(&self, value: bool, timeout_ms: u64) -> MpcEngineResult<bool> {
        let session_id = self.aba_propose(value)?;
        self.aba_result(session_id, timeout_ms)
    }
}

/// Async version of `MpcEngineConsensus`.
#[async_trait::async_trait]
pub trait AsyncMpcEngineConsensus: MpcEngineConsensus {
    /// Broadcast a message reliably to all parties asynchronously.
    async fn rbc_broadcast_async(&self, message: &[u8]) -> MpcEngineResult<RbcSessionId>;

    /// Receive a reliable broadcast from a specific party asynchronously.
    async fn rbc_receive_async(
        &self,
        from_party: MpcPartyId,
        timeout_ms: u64,
    ) -> MpcEngineResult<Vec<u8>>;

    /// Receive a reliable broadcast from any party asynchronously.
    async fn rbc_receive_any_async(
        &self,
        timeout_ms: u64,
    ) -> MpcEngineResult<(MpcPartyId, Vec<u8>)>;

    /// Propose a binary value for ABA asynchronously.
    async fn aba_propose_async(&self, value: bool) -> MpcEngineResult<AbaSessionId>;

    /// Get the agreed-upon result for an ABA session asynchronously.
    async fn aba_result_async(
        &self,
        session_id: AbaSessionId,
        timeout_ms: u64,
    ) -> MpcEngineResult<bool>;

    /// Propose and wait for agreement asynchronously.
    async fn aba_propose_and_wait_async(
        &self,
        value: bool,
        timeout_ms: u64,
    ) -> MpcEngineResult<bool> {
        let session_id = self.aba_propose_async(value).await?;
        self.aba_result_async(session_id, timeout_ms).await
    }
}
