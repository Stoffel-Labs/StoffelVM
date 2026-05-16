use super::VMState;
use crate::error::VmResult;
#[cfg(feature = "avss")]
use crate::mpc_values::avss_object;
use crate::mpc_values::share_object;
use stoffel_vm_types::core_types::{ShareData, ShareType, Value};

impl VMState {
    pub(crate) fn extract_share_data(&mut self, value: &Value) -> VmResult<(ShareType, ShareData)> {
        Ok(share_object::extract_share_data(
            self.table_memory.as_mut(),
            value,
        )?)
    }

    pub(crate) fn extract_matching_share_pair(
        &mut self,
        left: &Value,
        right: &Value,
        context: &'static str,
    ) -> VmResult<(ShareType, ShareData, ShareData)> {
        let pair = share_object::extract_matching_share_pair(
            self.table_memory.as_mut(),
            left,
            right,
            context,
        )?;

        Ok((pair.share_type, pair.left_data, pair.right_data))
    }

    pub(crate) fn extract_homogeneous_share_array(
        &mut self,
        value: &Value,
        context: &'static str,
    ) -> VmResult<Option<(ShareType, Vec<ShareData>)>> {
        Ok(share_object::extract_homogeneous_share_array(
            self.table_memory.as_mut(),
            value,
            context,
        )?)
    }

    pub(crate) fn share_type(&mut self, value: &Value) -> VmResult<ShareType> {
        Ok(share_object::get_share_type(
            self.table_memory.as_mut(),
            value,
        )?)
    }

    pub(crate) fn share_party_id(&mut self, value: &Value) -> VmResult<Option<usize>> {
        Ok(share_object::get_party_id(
            self.table_memory.as_mut(),
            value,
        )?)
    }

    pub(crate) fn create_share_object_value(
        &mut self,
        share_type: ShareType,
        share_data: ShareData,
        party_id: usize,
    ) -> VmResult<Value> {
        let object_ref = share_object::create_share_object_ref(
            self.table_memory.as_mut(),
            share_type,
            share_data,
            party_id,
        )?;
        Ok(Value::from(object_ref))
    }

    #[cfg(feature = "avss")]
    pub(crate) fn create_avss_share_object_value(
        &mut self,
        key_name: &str,
        share_data: Vec<u8>,
        commitment_bytes: Vec<Vec<u8>>,
        party_id: usize,
    ) -> VmResult<Value> {
        let object_ref = avss_object::create_avss_share_object_ref(
            self.table_memory.as_mut(),
            key_name,
            share_data,
            commitment_bytes,
            party_id,
        )?;
        Ok(Value::from(object_ref))
    }

    #[cfg(feature = "avss")]
    pub(crate) fn is_avss_share_object(&mut self, value: &Value) -> bool {
        avss_object::is_avss_share_object(self.table_memory.as_mut(), value)
    }

    #[cfg(feature = "avss")]
    pub(crate) fn avss_commitment(&mut self, value: &Value, index: usize) -> VmResult<Vec<u8>> {
        Ok(avss_object::get_commitment(
            self.table_memory.as_mut(),
            value,
            index,
        )?)
    }

    #[cfg(feature = "avss")]
    pub(crate) fn avss_key_name(&mut self, value: &Value) -> VmResult<String> {
        Ok(avss_object::get_key_name(
            self.table_memory.as_mut(),
            value,
        )?)
    }

    #[cfg(feature = "avss")]
    pub(crate) fn avss_commitment_count(&mut self, value: &Value) -> VmResult<usize> {
        Ok(avss_object::get_commitment_count(
            self.table_memory.as_mut(),
            value,
        )?)
    }
}
