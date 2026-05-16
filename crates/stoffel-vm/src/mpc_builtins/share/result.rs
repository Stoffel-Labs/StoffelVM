use crate::foreign_functions::{ForeignFunctionCallbackResult, ForeignFunctionContext};
use stoffel_vm_types::core_types::{ShareData, ShareType, Value};

pub(super) fn create_result_share_object(
    ctx: &mut ForeignFunctionContext<'_>,
    share_type: ShareType,
    share_data: ShareData,
) -> ForeignFunctionCallbackResult<Value> {
    ctx.create_share_object(share_type, share_data)
}
