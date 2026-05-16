use super::mpc_runtime::ClientShareRequest;
use super::VMState;
use crate::error::VmResult;
use crate::net::client_store::{
    ClientInputHydrationCount, ClientInputIndex, ClientOutputShareCount, ClientShare,
    ClientShareIndex,
};
use crate::net::mpc_engine::{
    AbaSessionId, MpcEngine, MpcExponentGroup, MpcPartyId, MpcRuntimeInfo, RbcSessionId,
};
use std::sync::Arc;
use stoffel_vm_types::core_types::{ClearShareInput, ClearShareValue, ShareData, ShareType, Value};
#[cfg(feature = "honeybadger")]
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelnet::network_utils::ClientId;

impl VMState {
    /// Attach an MPC engine to the VM state.
    pub(crate) fn set_mpc_engine(&mut self, engine: Arc<dyn MpcEngine>) {
        self.mpc_runtime.set_engine(engine);
    }

    /// Snapshot VM-facing MPC runtime metadata without exposing backend ops.
    pub(crate) fn mpc_runtime_info(&self) -> Option<MpcRuntimeInfo> {
        self.mpc_runtime.runtime_info()
    }

    /// Ensure an MPC engine is configured and ready.
    pub(crate) fn ensure_mpc_ready(&self) -> VmResult<()> {
        self.mpc_runtime.ensure_ready()
    }

    /// Open a VM share value through the configured MPC backend.
    pub(crate) fn open_share_value(&self, value: &Value) -> VmResult<Value> {
        self.mpc_runtime.share_runtime()?.open_share_value(value)
    }

    /// Hydrate the VM's client input store from the MPC engine's input store.
    pub(crate) fn hydrate_from_mpc_engine(&self) -> VmResult<ClientInputHydrationCount> {
        self.mpc_runtime.hydrate_client_inputs()
    }

    /// Clear the client input store and re-hydrate from the MPC engine.
    pub(crate) fn refresh_client_inputs(&self) -> VmResult<ClientInputHydrationCount> {
        self.mpc_runtime.refresh_client_inputs()
    }

    pub(crate) fn rbc_broadcast(&self, message: &[u8]) -> VmResult<RbcSessionId> {
        self.mpc_runtime.rbc_broadcast(message)
    }

    pub(crate) fn rbc_receive(&self, from_party: MpcPartyId, timeout_ms: u64) -> VmResult<Vec<u8>> {
        self.mpc_runtime.rbc_receive(from_party, timeout_ms)
    }

    pub(crate) fn rbc_receive_any(&self, timeout_ms: u64) -> VmResult<(MpcPartyId, Vec<u8>)> {
        self.mpc_runtime.rbc_receive_any(timeout_ms)
    }

    pub(crate) fn aba_propose(&self, value: bool) -> VmResult<AbaSessionId> {
        self.mpc_runtime.aba_propose(value)
    }

    pub(crate) fn aba_result(&self, session_id: AbaSessionId, timeout_ms: u64) -> VmResult<bool> {
        self.mpc_runtime.aba_result(session_id, timeout_ms)
    }

    pub(crate) fn aba_propose_and_wait(&self, value: bool, timeout_ms: u64) -> VmResult<bool> {
        self.mpc_runtime.aba_propose_and_wait(value, timeout_ms)
    }

    /// Get the number of clients that have provided inputs.
    #[inline]
    pub(crate) fn client_store_len(&self) -> usize {
        self.mpc_runtime.client_store_len()
    }

    #[cfg(feature = "honeybadger")]
    pub(crate) fn client_input_store(&self) -> Arc<crate::net::client_store::ClientInputStore> {
        self.mpc_runtime.client_store()
    }

    /// Get a client ID by index in sorted order.
    pub(crate) fn client_id_at_index(&self, index: ClientInputIndex) -> Option<ClientId> {
        self.mpc_runtime.client_id_at_index(index)
    }

    /// Clear all VM client inputs.
    pub(crate) fn clear_client_inputs(&self) {
        self.mpc_runtime.clear_client_inputs();
    }

    /// Retrieve a backend-neutral VM client share payload.
    pub(crate) fn client_share_data(
        &self,
        client_id: ClientId,
        index: ClientShareIndex,
    ) -> Option<ClientShare> {
        self.mpc_runtime.client_share_data(client_id, index)
    }

    /// Store VM share payloads through the runtime boundary.
    pub(crate) fn store_client_shares(&self, client_id: ClientId, shares: Vec<ClientShare>) {
        self.mpc_runtime.store_client_shares(client_id, shares);
    }

    /// Replace all VM client inputs with backend-neutral VM share payloads.
    pub(crate) fn replace_client_shares<I>(&self, inputs: I) -> usize
    where
        I: IntoIterator<Item = (ClientId, Vec<ClientShare>)>,
    {
        self.mpc_runtime.replace_client_shares(inputs)
    }

    /// Store HoneyBadger client shares through the runtime boundary.
    #[cfg(feature = "honeybadger")]
    pub(crate) fn try_store_client_input<F>(
        &self,
        client_id: ClientId,
        shares: Vec<RobustShare<F>>,
    ) -> VmResult<usize>
    where
        F: ark_ff::FftField,
    {
        self.mpc_runtime.try_store_client_input(client_id, shares)
    }

    /// Store AVSS Feldman client shares through the runtime boundary.
    #[cfg(feature = "avss")]
    pub(crate) fn try_store_client_input_feldman<F, G>(
        &self,
        client_id: ClientId,
        shares: Vec<stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare<F, G>>,
    ) -> VmResult<usize>
    where
        F: ark_ff::FftField + ark_ff::PrimeField,
        G: ark_ec::CurveGroup<ScalarField = F>,
    {
        self.mpc_runtime
            .try_store_client_input_feldman(client_id, shares)
    }

    /// Replace all VM client inputs with robust shares.
    #[cfg(feature = "honeybadger")]
    pub(crate) fn try_replace_client_input<F, I>(&self, inputs: I) -> VmResult<usize>
    where
        F: ark_ff::FftField,
        I: IntoIterator<Item = (ClientId, Vec<RobustShare<F>>)>,
    {
        self.mpc_runtime.try_replace_client_input(inputs)
    }

    /// Retrieve a robust share for a client input.
    #[cfg(feature = "honeybadger")]
    pub(crate) fn client_share<F>(
        &self,
        client_id: ClientId,
        index: ClientShareIndex,
    ) -> Option<RobustShare<F>>
    where
        F: ark_ff::FftField,
    {
        self.mpc_runtime.client_share(client_id, index)
    }

    /// Load a client's input share from the VM client store.
    pub(crate) fn load_client_share(
        &self,
        client_id: ClientId,
        index: ClientShareIndex,
    ) -> VmResult<Value> {
        self.mpc_runtime
            .client_share_as(client_id, index, ClientShareRequest::default_secret_int())
    }

    /// Load a client's input share with an explicit VM share type.
    pub(crate) fn load_client_share_as(
        &self,
        client_id: ClientId,
        index: ClientShareIndex,
        share_type: ShareType,
    ) -> VmResult<Value> {
        self.mpc_runtime
            .client_share_as(client_id, index, ClientShareRequest::new(share_type))
    }

    /// Send output share(s) to a specific client for private reconstruction.
    pub(crate) fn send_output_to_client(
        &self,
        client_id: ClientId,
        share_bytes: &[u8],
        output_share_count: ClientOutputShareCount,
    ) -> VmResult<()> {
        self.mpc_runtime
            .send_output_to_client(client_id, share_bytes, output_share_count)
    }
}

impl VMState {
    pub(crate) fn input_share_data(&self, clear: ClearShareInput) -> VmResult<ShareData> {
        self.share_runtime()?.input_share(clear)
    }

    pub(crate) fn open_share_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
    ) -> VmResult<ClearShareValue> {
        self.share_runtime()?.open_share_data(ty, share_data)
    }

    pub(crate) fn batch_open_share_data(
        &self,
        ty: ShareType,
        shares: &[ShareData],
    ) -> VmResult<Vec<ClearShareValue>> {
        self.share_runtime()?.batch_open_share_data(ty, shares)
    }

    pub(crate) fn random_share_data(&self, ty: ShareType) -> VmResult<ShareData> {
        self.share_runtime()?.random_share_data(ty)
    }

    pub(crate) fn open_share_as_field_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
    ) -> VmResult<Vec<u8>> {
        self.share_runtime()?
            .open_share_as_field_data(ty, share_data)
    }

    pub(crate) fn open_share_in_exp_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        generator_bytes: &[u8],
    ) -> VmResult<Vec<u8>> {
        self.share_runtime()?
            .open_share_in_exp_data(ty, share_data, generator_bytes)
    }

    pub(crate) fn open_share_in_exp_group_data(
        &self,
        group: MpcExponentGroup,
        ty: ShareType,
        share_data: &ShareData,
        generator_bytes: &[u8],
    ) -> VmResult<Vec<u8>> {
        self.share_runtime()?
            .open_share_in_exp_group_data(group, ty, share_data, generator_bytes)
    }

    #[cfg(test)]
    pub(super) fn secret_share_sub_scalar(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> VmResult<Vec<u8>> {
        self.share_runtime()?
            .sub_scalar_bytes(ty, share_bytes, scalar)
    }

    #[cfg(test)]
    pub(super) fn scalar_sub_secret_share(
        &self,
        ty: ShareType,
        scalar: i64,
        share_bytes: &[u8],
    ) -> VmResult<Vec<u8>> {
        self.share_runtime()?
            .scalar_sub_bytes(ty, scalar, share_bytes)
    }

    pub(crate) fn secret_share_add_data(
        &self,
        ty: ShareType,
        lhs_data: &ShareData,
        rhs_data: &ShareData,
    ) -> VmResult<ShareData> {
        self.share_runtime()?.add_data(ty, lhs_data, rhs_data)
    }

    pub(crate) fn secret_share_sub_data(
        &self,
        ty: ShareType,
        lhs_data: &ShareData,
        rhs_data: &ShareData,
    ) -> VmResult<ShareData> {
        self.share_runtime()?.sub_data(ty, lhs_data, rhs_data)
    }

    pub(crate) fn secret_share_mul_data(
        &self,
        ty: ShareType,
        lhs_data: &ShareData,
        rhs_data: &ShareData,
    ) -> VmResult<ShareData> {
        self.share_runtime()?
            .multiply_share_data(ty, lhs_data, rhs_data)
    }

    pub(crate) fn secret_share_neg_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
    ) -> VmResult<ShareData> {
        self.share_runtime()?.neg_data(ty, share_data)
    }

    pub(crate) fn secret_share_add_scalar_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        scalar: i64,
    ) -> VmResult<ShareData> {
        self.share_runtime()?
            .add_scalar_data(ty, share_data, scalar)
    }

    pub(crate) fn secret_share_mul_scalar_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        scalar: i64,
    ) -> VmResult<ShareData> {
        self.share_runtime()?
            .mul_scalar_data(ty, share_data, scalar)
    }

    pub(crate) fn secret_share_mul_field_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        scalar_bytes: &[u8],
    ) -> VmResult<ShareData> {
        self.share_runtime()?
            .mul_field_data(ty, share_data, scalar_bytes)
    }

    #[cfg(test)]
    pub(crate) fn secret_share_add(
        &self,
        ty: ShareType,
        lhs_bytes: &[u8],
        rhs_bytes: &[u8],
    ) -> VmResult<Vec<u8>> {
        self.share_runtime()?.add_bytes(ty, lhs_bytes, rhs_bytes)
    }

    #[cfg(test)]
    pub(crate) fn secret_share_add_scalar(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> VmResult<Vec<u8>> {
        self.share_runtime()?
            .add_scalar_bytes(ty, share_bytes, scalar)
    }

    pub(crate) fn secret_share_interpolate_local(
        &self,
        ty: ShareType,
        shares: &[ShareData],
    ) -> VmResult<Value> {
        self.share_runtime()?
            .interpolate_share_data_local(ty, shares)
    }
}
