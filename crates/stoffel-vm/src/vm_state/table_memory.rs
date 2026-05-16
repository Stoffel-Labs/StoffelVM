use super::VMState;
use crate::error::VmResult;
use crate::mpc_values::byte_arrays;
use stoffel_vm_types::core_types::{
    ArrayRef, ObjectRef, TableMemoryResult, TableMemoryView, TableRef, Value,
};

impl VMState {
    pub(crate) fn table_memory_view(&self) -> Option<&dyn TableMemoryView> {
        self.table_memory.as_table_memory_view()
    }

    pub(crate) fn read_table_field(
        &mut self,
        table_ref: TableRef,
        key: &Value,
    ) -> VmResult<Option<Value>> {
        Ok(self.try_read_table_field(table_ref, key)?)
    }

    pub(crate) fn try_read_table_field(
        &mut self,
        table_ref: TableRef,
        key: &Value,
    ) -> TableMemoryResult<Option<Value>> {
        self.table_memory.read_table_field(table_ref, key)
    }

    pub(crate) fn read_array_ref_len(&mut self, array_ref: ArrayRef) -> VmResult<usize> {
        Ok(self.try_read_array_ref_len(array_ref)?)
    }

    pub(crate) fn try_read_array_ref_len(
        &mut self,
        array_ref: ArrayRef,
    ) -> TableMemoryResult<usize> {
        self.table_memory.read_array_ref_len(array_ref)
    }

    pub(crate) fn read_object_ref_len(&mut self, object_ref: ObjectRef) -> VmResult<usize> {
        Ok(self.try_read_object_ref_len(object_ref)?)
    }

    pub(crate) fn try_read_object_ref_len(
        &mut self,
        object_ref: ObjectRef,
    ) -> TableMemoryResult<usize> {
        self.table_memory.read_object_ref_len(object_ref)
    }

    pub(crate) fn read_object_ref_entries(
        &mut self,
        object_ref: ObjectRef,
        limit: usize,
    ) -> VmResult<Vec<(Value, Value)>> {
        Ok(self.try_read_object_ref_entries(object_ref, limit)?)
    }

    pub(crate) fn try_read_object_ref_entries(
        &mut self,
        object_ref: ObjectRef,
        limit: usize,
    ) -> TableMemoryResult<Vec<(Value, Value)>> {
        self.table_memory.read_object_ref_entries(object_ref, limit)
    }

    pub(crate) fn read_byte_array(&mut self, value: &Value) -> VmResult<Vec<u8>> {
        Ok(byte_arrays::extract_byte_array(
            self.table_memory.as_mut(),
            value,
        )?)
    }

    pub(crate) fn create_byte_array(&mut self, bytes: &[u8]) -> VmResult<Value> {
        Ok(Value::from(byte_arrays::create_byte_array_ref(
            self.table_memory.as_mut(),
            bytes,
        )?))
    }

    pub(crate) fn create_object_ref(&mut self) -> VmResult<ObjectRef> {
        Ok(self.table_memory.create_object_ref()?)
    }

    pub(crate) fn create_array_ref(&mut self, capacity: usize) -> VmResult<ArrayRef> {
        if capacity == 0 {
            Ok(self.table_memory.create_array_ref()?)
        } else {
            Ok(self.table_memory.create_array_ref_with_capacity(capacity)?)
        }
    }

    pub(crate) fn set_table_field(
        &mut self,
        table_ref: TableRef,
        key: Value,
        value: Value,
    ) -> VmResult<()> {
        Ok(self.table_memory.set_table_field(table_ref, key, value)?)
    }

    pub(crate) fn push_array_ref_values(
        &mut self,
        array_ref: ArrayRef,
        values: &[Value],
    ) -> VmResult<usize> {
        Ok(self.table_memory.push_array_ref_values(array_ref, values)?)
    }
}
