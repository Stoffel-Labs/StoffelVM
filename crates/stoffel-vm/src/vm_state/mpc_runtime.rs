use crate::error::{MpcBackendResultExt, VmError, VmResult};
use crate::net::client_store::{
    ClientInputHydrationCount, ClientInputIndex, ClientInputStore, ClientOutputShareCount,
    ClientShare, ClientShareIndex,
};
use crate::net::mpc_engine::{
    AbaSessionId, MpcEngine, MpcEngineConsensus, MpcPartyId, MpcRuntimeInfo, RbcSessionId,
};
use crate::net::reveal_batcher::{RevealBatcher, RevealedRegister};
use crate::net::share_runtime::MpcShareRuntime;
use crate::reveal_destination::{FrameDepth, RevealDestination};
use std::sync::Arc;
use stoffel_vm_types::core_types::{ShareData, ShareType, Value};
#[cfg(feature = "honeybadger")]
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelnet::network_utils::ClientId;

pub(super) struct MpcRuntimeState {
    engine: Option<Arc<dyn MpcEngine>>,
    client_store: Arc<ClientInputStore>,
    reveal_batcher: RevealBatcher,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ClientShareRequest {
    requested_type: ShareType,
}

impl ClientShareRequest {
    pub(super) const fn new(requested_type: ShareType) -> Self {
        Self { requested_type }
    }

    pub(super) fn default_secret_int() -> Self {
        Self::new(ShareType::default_secret_int())
    }

    const fn requested_type(self) -> ShareType {
        self.requested_type
    }
}

impl Default for MpcRuntimeState {
    fn default() -> Self {
        Self::new()
    }
}

impl MpcRuntimeState {
    pub(super) fn new() -> Self {
        Self {
            engine: None,
            client_store: Arc::new(ClientInputStore::new()),
            reveal_batcher: RevealBatcher::new(),
        }
    }

    pub(super) fn set_engine(&mut self, engine: Arc<dyn MpcEngine>) {
        self.clear_engine_scoped_state();
        self.engine = Some(engine);
    }

    fn clear_engine_scoped_state(&mut self) {
        self.client_store.clear();
        self.reveal_batcher.clear_all();
    }

    pub(super) fn engine(&self) -> Option<Arc<dyn MpcEngine>> {
        self.engine.as_ref().map(Arc::clone)
    }

    pub(super) fn clone_independent(&self) -> Self {
        let mut cloned = Self::new();
        if let Some(engine) = self.engine() {
            cloned.set_engine(engine);
        }
        cloned
            .client_store
            .replace_client_shares(self.client_store.snapshot_client_shares());
        cloned
    }

    pub(super) fn runtime_info(&self) -> Option<MpcRuntimeInfo> {
        self.engine.as_deref().map(MpcRuntimeInfo::from_engine)
    }

    pub(super) fn configured_engine(&self) -> VmResult<&dyn MpcEngine> {
        self.engine
            .as_deref()
            .ok_or(VmError::MpcEngineNotConfigured)
    }

    pub(super) fn ensure_ready(&self) -> VmResult<()> {
        match &self.engine {
            Some(engine) if engine.is_ready() => Ok(()),
            Some(_) => Err(VmError::MpcEngineNotReady),
            None => Err(VmError::MpcEngineNotConfigured),
        }
    }

    fn ready_engine(&self) -> VmResult<&dyn MpcEngine> {
        let engine = self.configured_engine()?;
        if engine.is_ready() {
            Ok(engine)
        } else {
            Err(VmError::MpcEngineNotReady)
        }
    }

    pub(super) fn share_runtime(&self) -> VmResult<MpcShareRuntime<'_>> {
        MpcShareRuntime::from_configured(self.engine.as_deref())
    }

    fn consensus_ops(&self) -> VmResult<&dyn MpcEngineConsensus> {
        self.ready_engine()?
            .consensus_ops()
            .map_mpc_backend_err("consensus_ops")
    }

    pub(super) fn rbc_broadcast(&self, message: &[u8]) -> VmResult<RbcSessionId> {
        self.consensus_ops()?
            .rbc_broadcast(message)
            .map_mpc_backend_err("rbc_broadcast")
    }

    pub(super) fn rbc_receive(&self, from_party: MpcPartyId, timeout_ms: u64) -> VmResult<Vec<u8>> {
        self.consensus_ops()?
            .rbc_receive(from_party, timeout_ms)
            .map_mpc_backend_err("rbc_receive")
    }

    pub(super) fn rbc_receive_any(&self, timeout_ms: u64) -> VmResult<(MpcPartyId, Vec<u8>)> {
        self.consensus_ops()?
            .rbc_receive_any(timeout_ms)
            .map_mpc_backend_err("rbc_receive_any")
    }

    pub(super) fn aba_propose(&self, value: bool) -> VmResult<AbaSessionId> {
        self.consensus_ops()?
            .aba_propose(value)
            .map_mpc_backend_err("aba_propose")
    }

    pub(super) fn aba_result(&self, session_id: AbaSessionId, timeout_ms: u64) -> VmResult<bool> {
        self.consensus_ops()?
            .aba_result(session_id, timeout_ms)
            .map_mpc_backend_err("aba_result")
    }

    pub(super) fn aba_propose_and_wait(&self, value: bool, timeout_ms: u64) -> VmResult<bool> {
        self.consensus_ops()?
            .aba_propose_and_wait(value, timeout_ms)
            .map_mpc_backend_err("aba_propose_and_wait")
    }

    pub(super) fn hydrate_client_inputs(&self) -> VmResult<ClientInputHydrationCount> {
        let engine = self.ready_engine()?;

        engine
            .client_ops()
            .map_mpc_backend_err("client_ops")?
            .hydrate_client_inputs_sync(&self.client_store)
            .map_mpc_backend_err("hydrate_client_inputs_sync")
    }

    pub(super) fn refresh_client_inputs(&self) -> VmResult<ClientInputHydrationCount> {
        self.client_store.clear();
        self.hydrate_client_inputs()
    }

    pub(super) fn client_store_len(&self) -> usize {
        self.client_store.len()
    }

    #[cfg(feature = "honeybadger")]
    pub(super) fn client_store(&self) -> Arc<ClientInputStore> {
        Arc::clone(&self.client_store)
    }

    pub(super) fn client_id_at_index(&self, index: ClientInputIndex) -> Option<ClientId> {
        self.client_store.client_id_at(index)
    }

    pub(super) fn clear_client_inputs(&self) {
        self.client_store.clear();
    }

    pub(super) fn client_share_data(
        &self,
        client_id: ClientId,
        index: ClientShareIndex,
    ) -> Option<ClientShare> {
        self.client_store.get_client_share_data(client_id, index)
    }

    pub(super) fn store_client_shares(&self, client_id: ClientId, shares: Vec<ClientShare>) {
        self.client_store.store_client_shares(client_id, shares);
    }

    pub(super) fn replace_client_shares<I>(&self, inputs: I) -> usize
    where
        I: IntoIterator<Item = (ClientId, Vec<ClientShare>)>,
    {
        self.client_store.replace_client_shares(inputs)
    }

    #[cfg(feature = "honeybadger")]
    pub(super) fn try_store_client_input<F>(
        &self,
        client_id: ClientId,
        shares: Vec<RobustShare<F>>,
    ) -> VmResult<usize>
    where
        F: ark_ff::FftField,
    {
        Ok(self
            .client_store
            .try_store_client_input(client_id, shares)?)
    }

    #[cfg(feature = "avss")]
    pub(super) fn try_store_client_input_feldman<F, G>(
        &self,
        client_id: ClientId,
        shares: Vec<stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare<F, G>>,
    ) -> VmResult<usize>
    where
        F: ark_ff::FftField + ark_ff::PrimeField,
        G: ark_ec::CurveGroup<ScalarField = F>,
    {
        Ok(self
            .client_store
            .try_store_client_input_feldman(client_id, shares)?)
    }

    #[cfg(feature = "honeybadger")]
    pub(super) fn try_replace_client_input<F, I>(&self, inputs: I) -> VmResult<usize>
    where
        F: ark_ff::FftField,
        I: IntoIterator<Item = (ClientId, Vec<RobustShare<F>>)>,
    {
        Ok(self.client_store.try_replace_client_input(inputs)?)
    }

    #[cfg(feature = "honeybadger")]
    pub(super) fn client_share<F>(
        &self,
        client_id: ClientId,
        index: ClientShareIndex,
    ) -> Option<RobustShare<F>>
    where
        F: ark_ff::FftField,
    {
        self.client_store.get_client_share(client_id, index)
    }

    pub(super) fn client_share_as(
        &self,
        client_id: ClientId,
        index: ClientShareIndex,
        request: ClientShareRequest,
    ) -> VmResult<Value> {
        let requested_type = request.requested_type();
        let share = self
            .client_store
            .get_client_share_data(client_id, index)
            .ok_or(VmError::ClientShareNotFound { client_id, index })?;

        let share_type = match share.share_type() {
            Some(stored_type) if stored_type != requested_type => {
                return Err(VmError::ClientShareTypeMismatch {
                    client_id,
                    index,
                    stored_type,
                    requested_type,
                });
            }
            Some(stored_type) => stored_type,
            None => requested_type,
        };

        Ok(Value::Share(share_type, share.into_data()))
    }

    pub(super) fn send_output_to_client(
        &self,
        client_id: ClientId,
        share_bytes: &[u8],
        output_share_count: ClientOutputShareCount,
    ) -> VmResult<()> {
        let engine = self
            .engine
            .as_ref()
            .ok_or(VmError::MpcOutputEngineNotConfigured)?;

        if !engine.is_ready() {
            return Err(VmError::MpcOutputEngineNotReady);
        }

        engine
            .client_output_ops()
            .map_mpc_backend_err("client_output_ops")?
            .send_output_to_client(client_id, share_bytes, output_share_count)
            .map_mpc_backend_err("send_output_to_client")
    }

    pub(super) fn cancel_reveal_destination(&mut self, destination: RevealDestination) {
        self.reveal_batcher.cancel_destination(destination);
    }

    pub(super) fn clear_frame_reveals(&mut self, frame_depth: FrameDepth) {
        self.reveal_batcher.clear_frame(frame_depth);
    }

    pub(super) fn clear_reveals_at_or_above(&mut self, depth: FrameDepth) {
        self.reveal_batcher.clear_frames_at_or_above(depth);
    }

    pub(super) fn is_reveal_batching_enabled(&self) -> bool {
        self.reveal_batcher.is_enabled()
    }

    pub(super) fn has_pending_reveals(&self, frame_depth: FrameDepth) -> bool {
        self.reveal_batcher.has_pending_frame(frame_depth)
    }

    pub(super) fn has_any_pending_reveals(&self) -> bool {
        self.reveal_batcher.has_pending()
    }

    pub(super) fn has_pending_reveal_destination(&self, destination: RevealDestination) -> bool {
        self.reveal_batcher.has_pending_destination(destination)
    }

    pub(super) fn queue_reveal(
        &mut self,
        destination: RevealDestination,
        ty: ShareType,
        data: ShareData,
    ) {
        self.reveal_batcher.queue(destination, ty, data);
    }

    pub(super) fn should_auto_flush_reveals(&self, frame_depth: FrameDepth) -> bool {
        self.reveal_batcher.should_auto_flush(frame_depth)
    }

    pub(super) fn flush_reveals(
        &mut self,
        frame_depth: FrameDepth,
    ) -> VmResult<Vec<RevealedRegister>> {
        if !self.reveal_batcher.has_pending_frame(frame_depth) {
            return Ok(Vec::new());
        }

        let engine = self.engine().ok_or(VmError::MpcEngineNotConfigured)?;
        Ok(self.reveal_batcher.flush(frame_depth, engine.as_ref())?)
    }
}
