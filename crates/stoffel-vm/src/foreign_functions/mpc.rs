use super::ForeignFunctionContext;
use crate::error::{VmError, VmResult};
use crate::net::client_store::{ClientInputIndex, ClientOutputShareCount, ClientShareIndex};
use crate::net::mpc_engine::{
    AbaSessionId, MpcExponentGroup, MpcPartyId, MpcRuntimeInfo, RbcSessionId,
};
use stoffel_vm_types::core_types::{ClearShareInput, ClearShareValue, ShareData, ShareType, Value};
use stoffelnet::network_utils::ClientId;

impl<'a> ForeignFunctionContext<'a> {
    pub(crate) fn client_store_len(&self) -> usize {
        self.services.client_store_len()
    }

    pub(crate) fn client_id_at_index(&self, index: ClientInputIndex) -> Option<ClientId> {
        self.services.client_id_at_index(index)
    }

    pub(crate) fn load_client_share(
        &self,
        client_id: ClientId,
        share_index: ClientShareIndex,
    ) -> VmResult<Value> {
        self.services.load_client_share(client_id, share_index)
    }

    pub(crate) fn load_client_share_as(
        &self,
        client_id: ClientId,
        share_index: ClientShareIndex,
        share_type: ShareType,
    ) -> VmResult<Value> {
        self.services
            .load_client_share_as(client_id, share_index, share_type)
    }

    pub(crate) fn send_output_to_client(
        &self,
        client_id: ClientId,
        share_bytes: &[u8],
        output_share_count: ClientOutputShareCount,
    ) -> VmResult<()> {
        self.services
            .send_output_to_client(client_id, share_bytes, output_share_count)
    }

    pub(crate) fn mpc_runtime_info(&self) -> Option<MpcRuntimeInfo> {
        self.services.mpc_runtime_info()
    }

    pub(crate) fn require_mpc_runtime_info(&self) -> VmResult<MpcRuntimeInfo> {
        self.mpc_runtime_info()
            .ok_or(VmError::MpcEngineNotConfigured)
    }

    pub(crate) fn rbc_broadcast(&self, message: &[u8]) -> VmResult<RbcSessionId> {
        self.services.rbc_broadcast(message)
    }

    pub(crate) fn rbc_receive_from(
        &self,
        from_party: MpcPartyId,
        timeout_ms: u64,
    ) -> VmResult<Vec<u8>> {
        self.services.rbc_receive_from(from_party, timeout_ms)
    }

    pub(crate) fn rbc_receive_any(&self, timeout_ms: u64) -> VmResult<(MpcPartyId, Vec<u8>)> {
        self.services.rbc_receive_any(timeout_ms)
    }

    pub(crate) fn aba_propose(&self, value: bool) -> VmResult<AbaSessionId> {
        self.services.aba_propose(value)
    }

    pub(crate) fn aba_result(&self, session_id: AbaSessionId, timeout_ms: u64) -> VmResult<bool> {
        self.services.aba_result(session_id, timeout_ms)
    }

    pub(crate) fn aba_propose_and_wait(&self, value: bool, timeout_ms: u64) -> VmResult<bool> {
        self.services.aba_propose_and_wait(value, timeout_ms)
    }

    pub(crate) fn input_share_data(&self, clear: ClearShareInput) -> VmResult<ShareData> {
        self.services.input_share_data(clear)
    }

    pub(crate) fn open_share_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
    ) -> VmResult<ClearShareValue> {
        self.services.open_share_data(ty, share_data)
    }

    pub(crate) fn batch_open_share_data(
        &self,
        ty: ShareType,
        shares: &[ShareData],
    ) -> VmResult<Vec<ClearShareValue>> {
        self.services.batch_open_share_data(ty, shares)
    }

    pub(crate) fn random_share_data(&self, ty: ShareType) -> VmResult<ShareData> {
        self.services.random_share_data(ty)
    }

    pub(crate) fn open_share_as_field_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
    ) -> VmResult<Vec<u8>> {
        self.services.open_share_as_field_data(ty, share_data)
    }

    pub(crate) fn open_share_in_exp_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        generator_bytes: &[u8],
    ) -> VmResult<Vec<u8>> {
        self.services
            .open_share_in_exp_data(ty, share_data, generator_bytes)
    }

    pub(crate) fn open_share_in_exp_group_data(
        &self,
        group: MpcExponentGroup,
        ty: ShareType,
        share_data: &ShareData,
        generator_bytes: &[u8],
    ) -> VmResult<Vec<u8>> {
        self.services
            .open_share_in_exp_group_data(group, ty, share_data, generator_bytes)
    }

    pub(crate) fn secret_share_add_data(
        &self,
        ty: ShareType,
        lhs_data: &ShareData,
        rhs_data: &ShareData,
    ) -> VmResult<ShareData> {
        self.services.secret_share_add_data(ty, lhs_data, rhs_data)
    }

    pub(crate) fn secret_share_sub_data(
        &self,
        ty: ShareType,
        lhs_data: &ShareData,
        rhs_data: &ShareData,
    ) -> VmResult<ShareData> {
        self.services.secret_share_sub_data(ty, lhs_data, rhs_data)
    }

    pub(crate) fn secret_share_mul_data(
        &self,
        ty: ShareType,
        lhs_data: &ShareData,
        rhs_data: &ShareData,
    ) -> VmResult<ShareData> {
        self.services.secret_share_mul_data(ty, lhs_data, rhs_data)
    }

    pub(crate) fn secret_share_neg_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
    ) -> VmResult<ShareData> {
        self.services.secret_share_neg_data(ty, share_data)
    }

    pub(crate) fn secret_share_add_scalar_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        scalar: i64,
    ) -> VmResult<ShareData> {
        self.services
            .secret_share_add_scalar_data(ty, share_data, scalar)
    }

    pub(crate) fn secret_share_mul_scalar_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        scalar: i64,
    ) -> VmResult<ShareData> {
        self.services
            .secret_share_mul_scalar_data(ty, share_data, scalar)
    }

    pub(crate) fn secret_share_mul_field_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        scalar_bytes: &[u8],
    ) -> VmResult<ShareData> {
        self.services
            .secret_share_mul_field_data(ty, share_data, scalar_bytes)
    }

    pub(crate) fn secret_share_interpolate_local(
        &self,
        ty: ShareType,
        shares: &[ShareData],
    ) -> VmResult<Value> {
        self.services.secret_share_interpolate_local(ty, shares)
    }
}
