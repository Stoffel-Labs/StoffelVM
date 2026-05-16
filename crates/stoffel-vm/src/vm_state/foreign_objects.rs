use super::VMState;
use crate::error::{VmError, VmResult};
use parking_lot::Mutex;
use std::any::Any;
use std::sync::Arc;
use stoffel_vm_types::core_types::ForeignObjectRef;

impl VMState {
    pub(crate) fn try_register_foreign_object_ref<T: 'static + Send + Sync>(
        &mut self,
        object: T,
    ) -> VmResult<ForeignObjectRef> {
        self.foreign_objects
            .try_register_object_ref(object)
            .map_err(VmError::from)
    }

    pub(crate) fn get_foreign_object_ref<T: 'static + Send + Sync>(
        &self,
        object_ref: ForeignObjectRef,
    ) -> Option<Arc<Mutex<T>>> {
        self.foreign_objects.get_object_ref(object_ref)
    }

    pub(crate) fn get_foreign_object_any_ref(
        &self,
        object_ref: ForeignObjectRef,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        self.foreign_objects.get_object_any_ref(object_ref)
    }
}
