use crate::error::VmResult;
use crate::net::client_store::{ClientInputIndex, ClientOutputShareCount, ClientShareIndex};
use crate::net::mpc_engine::{
    AbaSessionId, MpcExponentGroup, MpcPartyId, MpcRuntimeInfo, RbcSessionId,
};
use crate::output::VmOutputResult;
use crate::runtime_hooks::HookEvent;
use crate::vm_state::VMState;
use std::any::Any;
use std::sync::Arc;
use stoffel_vm_types::core_types::{
    ArrayRef, ClearShareInput, ClearShareValue, ForeignObjectRef, ObjectRef, ShareData, ShareType,
    TableMemoryResult, TableRef, Value,
};
use stoffelnet::network_utils::ClientId;

pub(crate) trait ForeignFunctionVmServices:
    ForeignObjectServices
    + ForeignOutputServices
    + ForeignHookServices
    + ForeignClosureServices
    + ForeignTableMemoryServices
    + ForeignMpcServices
    + ForeignShareObjectServices
{
}

impl<T> ForeignFunctionVmServices for T where
    T: ForeignObjectServices
        + ForeignOutputServices
        + ForeignHookServices
        + ForeignClosureServices
        + ForeignTableMemoryServices
        + ForeignMpcServices
        + ForeignShareObjectServices
        + ?Sized
{
}

pub(crate) trait ForeignObjectServices {
    fn get_foreign_object_any_ref(
        &self,
        object_ref: ForeignObjectRef,
    ) -> Option<Arc<dyn Any + Send + Sync>>;
}

impl ForeignObjectServices for VMState {
    fn get_foreign_object_any_ref(
        &self,
        object_ref: ForeignObjectRef,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        VMState::get_foreign_object_any_ref(self, object_ref)
    }
}

pub(crate) trait ForeignOutputServices {
    fn write_output_line(&self, line: &str) -> VmOutputResult<()>;
}

impl ForeignOutputServices for VMState {
    fn write_output_line(&self, line: &str) -> VmOutputResult<()> {
        VMState::write_output_line(self, line)
    }
}

pub(crate) trait ForeignHookServices {
    fn hooks_enabled(&self) -> bool;

    fn trigger_hook_with_snapshot(&self, event: &HookEvent) -> VmResult<()>;
}

impl ForeignHookServices for VMState {
    fn hooks_enabled(&self) -> bool {
        VMState::hooks_enabled(self)
    }

    fn trigger_hook_with_snapshot(&self, event: &HookEvent) -> VmResult<()> {
        VMState::trigger_hook_with_snapshot(self, event)
    }
}

pub(crate) trait ForeignClosureServices {
    fn create_closure_value(
        &mut self,
        function_name: String,
        upvalue_names: &[String],
    ) -> VmResult<Value>;

    fn call_closure_value(&mut self, closure_value: &Value, args: &[Value]) -> VmResult<()>;

    fn get_upvalue_value(&self, name: &str) -> VmResult<Value>;

    fn set_upvalue_value(&mut self, name: &str, new_value: Value) -> VmResult<()>;
}

impl ForeignClosureServices for VMState {
    fn create_closure_value(
        &mut self,
        function_name: String,
        upvalue_names: &[String],
    ) -> VmResult<Value> {
        VMState::create_closure_value(self, function_name, upvalue_names)
    }

    fn call_closure_value(&mut self, closure_value: &Value, args: &[Value]) -> VmResult<()> {
        VMState::call_closure_value(self, closure_value, args, true)
    }

    fn get_upvalue_value(&self, name: &str) -> VmResult<Value> {
        VMState::get_upvalue_value(self, name)
    }

    fn set_upvalue_value(&mut self, name: &str, new_value: Value) -> VmResult<()> {
        VMState::set_upvalue_value(self, name, new_value)
    }
}

pub(crate) trait ForeignTableMemoryServices {
    fn try_read_table_field(
        &mut self,
        table_ref: TableRef,
        key: &Value,
    ) -> TableMemoryResult<Option<Value>>;

    fn try_read_array_ref_len(&mut self, array_ref: ArrayRef) -> TableMemoryResult<usize>;

    fn try_read_object_ref_len(&mut self, object_ref: ObjectRef) -> TableMemoryResult<usize>;

    fn try_read_object_ref_entries(
        &mut self,
        object_ref: ObjectRef,
        limit: usize,
    ) -> TableMemoryResult<Vec<(Value, Value)>>;

    fn read_byte_array(&mut self, value: &Value) -> VmResult<Vec<u8>>;

    fn create_byte_array(&mut self, bytes: &[u8]) -> VmResult<Value>;

    fn create_object_ref(&mut self) -> VmResult<ObjectRef>;

    fn create_array_ref(&mut self, capacity: usize) -> VmResult<ArrayRef>;

    fn set_table_field(&mut self, table_ref: TableRef, key: Value, value: Value) -> VmResult<()>;

    fn push_array_ref_values(&mut self, array_ref: ArrayRef, values: &[Value]) -> VmResult<usize>;
}

impl ForeignTableMemoryServices for VMState {
    fn try_read_table_field(
        &mut self,
        table_ref: TableRef,
        key: &Value,
    ) -> TableMemoryResult<Option<Value>> {
        VMState::try_read_table_field(self, table_ref, key)
    }

    fn try_read_array_ref_len(&mut self, array_ref: ArrayRef) -> TableMemoryResult<usize> {
        VMState::try_read_array_ref_len(self, array_ref)
    }

    fn try_read_object_ref_len(&mut self, object_ref: ObjectRef) -> TableMemoryResult<usize> {
        VMState::try_read_object_ref_len(self, object_ref)
    }

    fn try_read_object_ref_entries(
        &mut self,
        object_ref: ObjectRef,
        limit: usize,
    ) -> TableMemoryResult<Vec<(Value, Value)>> {
        VMState::try_read_object_ref_entries(self, object_ref, limit)
    }

    fn read_byte_array(&mut self, value: &Value) -> VmResult<Vec<u8>> {
        VMState::read_byte_array(self, value)
    }

    fn create_byte_array(&mut self, bytes: &[u8]) -> VmResult<Value> {
        VMState::create_byte_array(self, bytes)
    }

    fn create_object_ref(&mut self) -> VmResult<ObjectRef> {
        VMState::create_object_ref(self)
    }

    fn create_array_ref(&mut self, capacity: usize) -> VmResult<ArrayRef> {
        VMState::create_array_ref(self, capacity)
    }

    fn set_table_field(&mut self, table_ref: TableRef, key: Value, value: Value) -> VmResult<()> {
        VMState::set_table_field(self, table_ref, key, value)
    }

    fn push_array_ref_values(&mut self, array_ref: ArrayRef, values: &[Value]) -> VmResult<usize> {
        VMState::push_array_ref_values(self, array_ref, values)
    }
}

pub(crate) trait ForeignMpcServices {
    fn client_store_len(&self) -> usize;

    fn client_id_at_index(&self, index: ClientInputIndex) -> Option<ClientId>;

    fn load_client_share(
        &self,
        client_id: ClientId,
        share_index: ClientShareIndex,
    ) -> VmResult<Value>;

    fn load_client_share_as(
        &self,
        client_id: ClientId,
        share_index: ClientShareIndex,
        share_type: ShareType,
    ) -> VmResult<Value>;

    fn send_output_to_client(
        &self,
        client_id: ClientId,
        share_bytes: &[u8],
        output_share_count: ClientOutputShareCount,
    ) -> VmResult<()>;

    fn mpc_runtime_info(&self) -> Option<MpcRuntimeInfo>;

    fn rbc_broadcast(&self, message: &[u8]) -> VmResult<RbcSessionId>;

    fn rbc_receive_from(&self, from_party: MpcPartyId, timeout_ms: u64) -> VmResult<Vec<u8>>;

    fn rbc_receive_any(&self, timeout_ms: u64) -> VmResult<(MpcPartyId, Vec<u8>)>;

    fn aba_propose(&self, value: bool) -> VmResult<AbaSessionId>;

    fn aba_result(&self, session_id: AbaSessionId, timeout_ms: u64) -> VmResult<bool>;

    fn aba_propose_and_wait(&self, value: bool, timeout_ms: u64) -> VmResult<bool>;

    fn input_share_data(&self, clear: ClearShareInput) -> VmResult<ShareData>;

    fn open_share_data(&self, ty: ShareType, share_data: &ShareData) -> VmResult<ClearShareValue>;

    fn batch_open_share_data(
        &self,
        ty: ShareType,
        shares: &[ShareData],
    ) -> VmResult<Vec<ClearShareValue>>;

    fn random_share_data(&self, ty: ShareType) -> VmResult<ShareData>;

    fn open_share_as_field_data(&self, ty: ShareType, share_data: &ShareData) -> VmResult<Vec<u8>>;

    fn open_share_in_exp_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        generator_bytes: &[u8],
    ) -> VmResult<Vec<u8>>;

    fn open_share_in_exp_group_data(
        &self,
        group: MpcExponentGroup,
        ty: ShareType,
        share_data: &ShareData,
        generator_bytes: &[u8],
    ) -> VmResult<Vec<u8>>;

    fn secret_share_add_data(
        &self,
        ty: ShareType,
        lhs_data: &ShareData,
        rhs_data: &ShareData,
    ) -> VmResult<ShareData>;

    fn secret_share_sub_data(
        &self,
        ty: ShareType,
        lhs_data: &ShareData,
        rhs_data: &ShareData,
    ) -> VmResult<ShareData>;

    fn secret_share_mul_data(
        &self,
        ty: ShareType,
        lhs_data: &ShareData,
        rhs_data: &ShareData,
    ) -> VmResult<ShareData>;

    fn secret_share_neg_data(&self, ty: ShareType, share_data: &ShareData) -> VmResult<ShareData>;

    fn secret_share_add_scalar_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        scalar: i64,
    ) -> VmResult<ShareData>;

    fn secret_share_mul_scalar_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        scalar: i64,
    ) -> VmResult<ShareData>;

    fn secret_share_mul_field_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        scalar_bytes: &[u8],
    ) -> VmResult<ShareData>;

    fn secret_share_interpolate_local(
        &self,
        ty: ShareType,
        shares: &[ShareData],
    ) -> VmResult<Value>;
}

impl ForeignMpcServices for VMState {
    fn client_store_len(&self) -> usize {
        VMState::client_store_len(self)
    }

    fn client_id_at_index(&self, index: ClientInputIndex) -> Option<ClientId> {
        VMState::client_id_at_index(self, index)
    }

    fn load_client_share(
        &self,
        client_id: ClientId,
        share_index: ClientShareIndex,
    ) -> VmResult<Value> {
        VMState::load_client_share(self, client_id, share_index)
    }

    fn load_client_share_as(
        &self,
        client_id: ClientId,
        share_index: ClientShareIndex,
        share_type: ShareType,
    ) -> VmResult<Value> {
        VMState::load_client_share_as(self, client_id, share_index, share_type)
    }

    fn send_output_to_client(
        &self,
        client_id: ClientId,
        share_bytes: &[u8],
        output_share_count: ClientOutputShareCount,
    ) -> VmResult<()> {
        VMState::send_output_to_client(self, client_id, share_bytes, output_share_count)
    }

    fn mpc_runtime_info(&self) -> Option<MpcRuntimeInfo> {
        VMState::mpc_runtime_info(self)
    }

    fn rbc_broadcast(&self, message: &[u8]) -> VmResult<RbcSessionId> {
        VMState::rbc_broadcast(self, message)
    }

    fn rbc_receive_from(&self, from_party: MpcPartyId, timeout_ms: u64) -> VmResult<Vec<u8>> {
        VMState::rbc_receive(self, from_party, timeout_ms)
    }

    fn rbc_receive_any(&self, timeout_ms: u64) -> VmResult<(MpcPartyId, Vec<u8>)> {
        VMState::rbc_receive_any(self, timeout_ms)
    }

    fn aba_propose(&self, value: bool) -> VmResult<AbaSessionId> {
        VMState::aba_propose(self, value)
    }

    fn aba_result(&self, session_id: AbaSessionId, timeout_ms: u64) -> VmResult<bool> {
        VMState::aba_result(self, session_id, timeout_ms)
    }

    fn aba_propose_and_wait(&self, value: bool, timeout_ms: u64) -> VmResult<bool> {
        VMState::aba_propose_and_wait(self, value, timeout_ms)
    }

    fn input_share_data(&self, clear: ClearShareInput) -> VmResult<ShareData> {
        VMState::input_share_data(self, clear)
    }

    fn open_share_data(&self, ty: ShareType, share_data: &ShareData) -> VmResult<ClearShareValue> {
        VMState::open_share_data(self, ty, share_data)
    }

    fn batch_open_share_data(
        &self,
        ty: ShareType,
        shares: &[ShareData],
    ) -> VmResult<Vec<ClearShareValue>> {
        VMState::batch_open_share_data(self, ty, shares)
    }

    fn random_share_data(&self, ty: ShareType) -> VmResult<ShareData> {
        VMState::random_share_data(self, ty)
    }

    fn open_share_as_field_data(&self, ty: ShareType, share_data: &ShareData) -> VmResult<Vec<u8>> {
        VMState::open_share_as_field_data(self, ty, share_data)
    }

    fn open_share_in_exp_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        generator_bytes: &[u8],
    ) -> VmResult<Vec<u8>> {
        VMState::open_share_in_exp_data(self, ty, share_data, generator_bytes)
    }

    fn open_share_in_exp_group_data(
        &self,
        group: MpcExponentGroup,
        ty: ShareType,
        share_data: &ShareData,
        generator_bytes: &[u8],
    ) -> VmResult<Vec<u8>> {
        VMState::open_share_in_exp_group_data(self, group, ty, share_data, generator_bytes)
    }

    fn secret_share_add_data(
        &self,
        ty: ShareType,
        lhs_data: &ShareData,
        rhs_data: &ShareData,
    ) -> VmResult<ShareData> {
        VMState::secret_share_add_data(self, ty, lhs_data, rhs_data)
    }

    fn secret_share_sub_data(
        &self,
        ty: ShareType,
        lhs_data: &ShareData,
        rhs_data: &ShareData,
    ) -> VmResult<ShareData> {
        VMState::secret_share_sub_data(self, ty, lhs_data, rhs_data)
    }

    fn secret_share_mul_data(
        &self,
        ty: ShareType,
        lhs_data: &ShareData,
        rhs_data: &ShareData,
    ) -> VmResult<ShareData> {
        VMState::secret_share_mul_data(self, ty, lhs_data, rhs_data)
    }

    fn secret_share_neg_data(&self, ty: ShareType, share_data: &ShareData) -> VmResult<ShareData> {
        VMState::secret_share_neg_data(self, ty, share_data)
    }

    fn secret_share_add_scalar_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        scalar: i64,
    ) -> VmResult<ShareData> {
        VMState::secret_share_add_scalar_data(self, ty, share_data, scalar)
    }

    fn secret_share_mul_scalar_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        scalar: i64,
    ) -> VmResult<ShareData> {
        VMState::secret_share_mul_scalar_data(self, ty, share_data, scalar)
    }

    fn secret_share_mul_field_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        scalar_bytes: &[u8],
    ) -> VmResult<ShareData> {
        VMState::secret_share_mul_field_data(self, ty, share_data, scalar_bytes)
    }

    fn secret_share_interpolate_local(
        &self,
        ty: ShareType,
        shares: &[ShareData],
    ) -> VmResult<Value> {
        VMState::secret_share_interpolate_local(self, ty, shares)
    }
}

pub(crate) trait ForeignShareObjectServices {
    fn extract_share_data(&mut self, value: &Value) -> VmResult<(ShareType, ShareData)>;

    fn extract_matching_share_pair(
        &mut self,
        left: &Value,
        right: &Value,
        context: &'static str,
    ) -> VmResult<(ShareType, ShareData, ShareData)>;

    fn extract_homogeneous_share_array(
        &mut self,
        value: &Value,
        context: &'static str,
    ) -> VmResult<Option<(ShareType, Vec<ShareData>)>>;

    fn share_type(&mut self, value: &Value) -> VmResult<ShareType>;

    fn share_party_id(&mut self, value: &Value) -> VmResult<Option<usize>>;

    fn create_share_object_value(
        &mut self,
        share_type: ShareType,
        share_data: ShareData,
        party_id: usize,
    ) -> VmResult<Value>;

    #[cfg(feature = "avss")]
    fn is_avss_share_object(&mut self, value: &Value) -> bool;

    #[cfg(feature = "avss")]
    fn avss_commitment(&mut self, value: &Value, index: usize) -> VmResult<Vec<u8>>;

    #[cfg(feature = "avss")]
    fn avss_key_name(&mut self, value: &Value) -> VmResult<String>;

    #[cfg(feature = "avss")]
    fn avss_commitment_count(&mut self, value: &Value) -> VmResult<usize>;
}

impl ForeignShareObjectServices for VMState {
    fn extract_share_data(&mut self, value: &Value) -> VmResult<(ShareType, ShareData)> {
        VMState::extract_share_data(self, value)
    }

    fn extract_matching_share_pair(
        &mut self,
        left: &Value,
        right: &Value,
        context: &'static str,
    ) -> VmResult<(ShareType, ShareData, ShareData)> {
        VMState::extract_matching_share_pair(self, left, right, context)
    }

    fn extract_homogeneous_share_array(
        &mut self,
        value: &Value,
        context: &'static str,
    ) -> VmResult<Option<(ShareType, Vec<ShareData>)>> {
        VMState::extract_homogeneous_share_array(self, value, context)
    }

    fn share_type(&mut self, value: &Value) -> VmResult<ShareType> {
        VMState::share_type(self, value)
    }

    fn share_party_id(&mut self, value: &Value) -> VmResult<Option<usize>> {
        VMState::share_party_id(self, value)
    }

    fn create_share_object_value(
        &mut self,
        share_type: ShareType,
        share_data: ShareData,
        party_id: usize,
    ) -> VmResult<Value> {
        VMState::create_share_object_value(self, share_type, share_data, party_id)
    }

    #[cfg(feature = "avss")]
    fn is_avss_share_object(&mut self, value: &Value) -> bool {
        VMState::is_avss_share_object(self, value)
    }

    #[cfg(feature = "avss")]
    fn avss_commitment(&mut self, value: &Value, index: usize) -> VmResult<Vec<u8>> {
        VMState::avss_commitment(self, value, index)
    }

    #[cfg(feature = "avss")]
    fn avss_key_name(&mut self, value: &Value) -> VmResult<String> {
        VMState::avss_key_name(self, value)
    }

    #[cfg(feature = "avss")]
    fn avss_commitment_count(&mut self, value: &Value) -> VmResult<usize> {
        VMState::avss_commitment_count(self, value)
    }
}
