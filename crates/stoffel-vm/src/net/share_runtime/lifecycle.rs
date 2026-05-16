use super::{MpcEngine, MpcShareRuntime};
use crate::error::{MpcBackendResultExt, VmError, VmResult};
use crate::mpc_values::clear_share_input;
use stoffel_vm_types::core_types::{ClearShareInput, ShareData, Value};

impl<'engine> MpcShareRuntime<'engine> {
    pub(crate) fn from_configured(
        engine: Option<&'engine dyn MpcEngine>,
    ) -> VmResult<MpcShareRuntime<'engine>> {
        let engine = engine.ok_or(VmError::MpcEngineNotConfigured)?;
        Ok(MpcShareRuntime { engine })
    }

    pub(crate) fn ensure_ready(&self) -> VmResult<()> {
        if self.engine.is_ready() {
            Ok(())
        } else {
            Err(VmError::MpcEngineNotReady)
        }
    }

    pub(crate) fn share_clear_value(&self, value: &Value) -> VmResult<Value> {
        let input = clear_share_input(value, None)?;
        let share_type = input.share_type();
        let share_data = self.input_share(input)?;
        Ok(Value::Share(share_type, share_data))
    }

    pub(crate) fn input_share(&self, clear: ClearShareInput) -> VmResult<ShareData> {
        self.ensure_ready()?;
        self.engine
            .input_share(clear)
            .map_mpc_backend_err("input_share")
    }
}
