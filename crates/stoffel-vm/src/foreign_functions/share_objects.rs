use super::{ForeignFunctionCallbackResult, ForeignFunctionContext};
use stoffel_vm_types::core_types::{ShareData, ShareType, Value};

impl<'a> ForeignFunctionContext<'a> {
    pub(crate) fn extract_share_data(
        &mut self,
        value: &Value,
    ) -> ForeignFunctionCallbackResult<(ShareType, ShareData)> {
        Ok(self.services.extract_share_data(value)?)
    }

    pub(crate) fn extract_matching_share_pair(
        &mut self,
        left: &Value,
        right: &Value,
        context: &'static str,
    ) -> ForeignFunctionCallbackResult<(ShareType, ShareData, ShareData)> {
        Ok(self
            .services
            .extract_matching_share_pair(left, right, context)?)
    }

    pub(crate) fn extract_homogeneous_share_array(
        &mut self,
        value: &Value,
        context: &'static str,
    ) -> ForeignFunctionCallbackResult<Option<(ShareType, Vec<ShareData>)>> {
        Ok(self
            .services
            .extract_homogeneous_share_array(value, context)?)
    }

    pub(crate) fn get_share_type(
        &mut self,
        value: &Value,
    ) -> ForeignFunctionCallbackResult<ShareType> {
        Ok(self.services.share_type(value)?)
    }

    pub(crate) fn get_share_party_id(
        &mut self,
        value: &Value,
    ) -> ForeignFunctionCallbackResult<Option<usize>> {
        Ok(self.services.share_party_id(value)?)
    }

    pub(crate) fn create_share_object(
        &mut self,
        share_type: ShareType,
        share_data: ShareData,
    ) -> ForeignFunctionCallbackResult<Value> {
        let party_id = self.require_mpc_runtime_info()?.party().id();
        Ok(self
            .services
            .create_share_object_value(share_type, share_data, party_id)?)
    }

    #[cfg(feature = "avss")]
    pub(crate) fn is_avss_share_object(&mut self, value: &Value) -> bool {
        self.services.is_avss_share_object(value)
    }

    #[cfg(feature = "avss")]
    pub(crate) fn avss_commitment(
        &mut self,
        value: &Value,
        index: usize,
    ) -> ForeignFunctionCallbackResult<Vec<u8>> {
        Ok(self.services.avss_commitment(value, index)?)
    }

    #[cfg(feature = "avss")]
    pub(crate) fn avss_key_name(&mut self, value: &Value) -> ForeignFunctionCallbackResult<String> {
        Ok(self.services.avss_key_name(value)?)
    }

    #[cfg(feature = "avss")]
    pub(crate) fn avss_commitment_count(
        &mut self,
        value: &Value,
    ) -> ForeignFunctionCallbackResult<usize> {
        Ok(self.services.avss_commitment_count(value)?)
    }
}
