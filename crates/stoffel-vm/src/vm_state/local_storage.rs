use super::VMState;
use crate::error::{VmError, VmResult};
use crate::storage::{LocalStorageValues, PersistentValueContext};
use std::sync::Arc;
use stoffel_vm_types::core_types::Value;

impl VMState {
    pub(crate) fn local_storage_store_value(&mut self, key: &[u8], value: &Value) -> VmResult<()> {
        let storage = Arc::clone(
            self.local_storage
                .as_ref()
                .ok_or(VmError::LocalStorageNotConfigured)?,
        );
        let mut storage = storage.lock();
        let context = self.local_storage_value_context(key);
        storage
            .as_mut()
            .store_value_with_context(key, value, self.table_memory.as_mut(), context.as_ref())
            .map_err(local_storage_error("store value"))
    }

    pub(crate) fn local_storage_load_value(&mut self, key: &[u8]) -> VmResult<Option<Value>> {
        let storage = Arc::clone(
            self.local_storage
                .as_ref()
                .ok_or(VmError::LocalStorageNotConfigured)?,
        );
        let storage = storage.lock();
        let context = self.local_storage_value_context(key);
        storage
            .as_ref()
            .retrieve_value_with_context(key, self.table_memory.as_mut(), context.as_ref())
            .map_err(local_storage_error("load value"))
    }

    pub(crate) fn local_storage_delete(&mut self, key: &[u8]) -> VmResult<bool> {
        let storage = Arc::clone(
            self.local_storage
                .as_ref()
                .ok_or(VmError::LocalStorageNotConfigured)?,
        );
        let mut storage = storage.lock();
        storage
            .as_mut()
            .delete(key)
            .map_err(local_storage_error("delete"))
    }

    pub(crate) fn local_storage_exists(&mut self, key: &[u8]) -> VmResult<bool> {
        let storage = Arc::clone(
            self.local_storage
                .as_ref()
                .ok_or(VmError::LocalStorageNotConfigured)?,
        );
        let storage = storage.lock();
        storage
            .as_ref()
            .exists(key)
            .map_err(local_storage_error("exists"))
    }

    pub(crate) fn clear_local_storage(&mut self) -> VmResult<()> {
        let Some(storage) = &self.local_storage else {
            return Ok(());
        };
        let storage = Arc::clone(storage);
        let mut storage = storage.lock();
        storage
            .as_mut()
            .clear()
            .map_err(local_storage_error("clear"))?;
        Ok(())
    }
}

impl VMState {
    fn local_storage_value_context(&self, key: &[u8]) -> Option<PersistentValueContext> {
        self.mpc_runtime_info()
            .map(|info| PersistentValueContext::from_mpc_runtime(info, key))
    }
}

fn local_storage_error<E: ToString>(operation: &'static str) -> impl FnOnce(E) -> VmError {
    move |error| VmError::LocalStorageOperationFailed {
        operation,
        reason: error.to_string(),
    }
}
