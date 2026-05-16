use super::VirtualMachine;
use crate::VirtualMachineResult;
use stoffel_vm_types::core_types::{ArrayRef, ObjectRef, TableMemoryView, TableRef, Value};

impl VirtualMachine {
    /// Inspect the VM's configured table memory when the backend supports
    /// truly immutable observation.
    ///
    /// Backends with access side effects, such as ORAM-style memory, can return
    /// `None` and still satisfy the VM execution contract through the mutating
    /// `read_*` helpers.
    pub fn table_memory_view(&self) -> Option<&dyn TableMemoryView> {
        self.state.table_memory_view()
    }

    /// Semantically read a table field through the configured memory backend.
    pub fn read_table_field(
        &mut self,
        table_ref: TableRef,
        key: &Value,
    ) -> VirtualMachineResult<Option<Value>> {
        Ok(self.state.read_table_field(table_ref, key)?)
    }

    /// Semantically read an array length through the configured memory backend.
    pub fn read_array_ref_len(&mut self, array_ref: ArrayRef) -> VirtualMachineResult<usize> {
        self.read_array_len(array_ref)
    }

    /// Semantically read an array length through the configured memory backend.
    pub fn read_array_len(&mut self, array_ref: ArrayRef) -> VirtualMachineResult<usize> {
        Ok(self.state.read_array_ref_len(array_ref)?)
    }

    /// Semantically read an object length through the configured memory backend.
    pub fn read_object_ref_len(&mut self, object_ref: ObjectRef) -> VirtualMachineResult<usize> {
        self.read_object_len(object_ref)
    }

    /// Semantically read an object length through the configured memory backend.
    pub fn read_object_len(&mut self, object_ref: ObjectRef) -> VirtualMachineResult<usize> {
        Ok(self.state.read_object_ref_len(object_ref)?)
    }

    /// Semantically read object entries through the configured memory backend.
    pub fn read_object_ref_entries(
        &mut self,
        object_ref: ObjectRef,
        limit: usize,
    ) -> VirtualMachineResult<Vec<(Value, Value)>> {
        self.read_object_entries(object_ref, limit)
    }

    /// Semantically read object entries through the configured memory backend.
    pub fn read_object_entries(
        &mut self,
        object_ref: ObjectRef,
        limit: usize,
    ) -> VirtualMachineResult<Vec<(Value, Value)>> {
        Ok(self.state.read_object_ref_entries(object_ref, limit)?)
    }

    /// Semantically read a VM byte array (`Value::Array` of `Value::U8`).
    pub fn read_byte_array(&mut self, value: &Value) -> VirtualMachineResult<Vec<u8>> {
        Ok(self.state.read_byte_array(value)?)
    }

    /// Create a VM byte array (`Value::Array` of `Value::U8`) from raw bytes.
    pub fn create_byte_array(&mut self, bytes: &[u8]) -> VirtualMachineResult<Value> {
        Ok(self.state.create_byte_array(bytes)?)
    }

    /// Create a VM table object and return its typed handle.
    pub fn create_object_ref(&mut self) -> VirtualMachineResult<ObjectRef> {
        Ok(self.state.create_object_ref()?)
    }

    /// Create a VM table array and return its typed handle.
    pub fn create_array_ref(&mut self, capacity: usize) -> VirtualMachineResult<ArrayRef> {
        Ok(self.state.create_array_ref(capacity)?)
    }

    /// Create a VM table object through the configured memory backend.
    pub fn create_object(&mut self) -> VirtualMachineResult<Value> {
        Ok(Value::from(self.create_object_ref()?))
    }

    /// Create a VM table array through the configured memory backend.
    pub fn create_array(&mut self, capacity: usize) -> VirtualMachineResult<Value> {
        Ok(Value::from(self.create_array_ref(capacity)?))
    }

    /// Set a field on a VM table through the configured memory backend.
    pub fn set_table_field(
        &mut self,
        table_ref: TableRef,
        key: Value,
        value: Value,
    ) -> VirtualMachineResult<()> {
        Ok(self.state.set_table_field(table_ref, key, value)?)
    }

    /// Append values to a VM array through the configured memory backend.
    pub fn push_array_ref_values(
        &mut self,
        array_ref: ArrayRef,
        values: &[Value],
    ) -> VirtualMachineResult<usize> {
        self.push_array_values(array_ref, values)
    }

    /// Append values to a VM array through the configured memory backend.
    pub fn push_array_values(
        &mut self,
        array_ref: ArrayRef,
        values: &[Value],
    ) -> VirtualMachineResult<usize> {
        Ok(self.state.push_array_ref_values(array_ref, values)?)
    }

    /// Create a VM object and populate it with fields through the VM table boundary.
    pub fn create_object_with_fields<I>(&mut self, fields: I) -> VirtualMachineResult<Value>
    where
        I: IntoIterator<Item = (Value, Value)>,
    {
        let object_ref = self.create_object_ref()?;
        let table_ref = TableRef::from(object_ref);
        for (key, value) in fields {
            self.set_table_field(table_ref, key, value)?;
        }
        Ok(Value::from(object_ref))
    }
}
