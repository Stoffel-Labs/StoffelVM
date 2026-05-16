use super::{ForeignFunctionCallbackResult, ForeignFunctionContext};
use stoffel_vm_types::core_types::{ArrayRef, ObjectRef, TableRef, Value};

impl<'a> ForeignFunctionContext<'a> {
    /// Semantically read a table field through the configured memory backend.
    ///
    /// This uses a mutable memory borrow so ORAM-style backends can update
    /// their internal state during logical reads.
    pub fn read_table_field(
        &mut self,
        table_ref: TableRef,
        key: &Value,
    ) -> ForeignFunctionCallbackResult<Option<Value>> {
        Ok(self.services.try_read_table_field(table_ref, key)?)
    }

    /// Semantically read an array length through the configured memory backend.
    ///
    /// This uses a mutable memory borrow so ORAM-style backends can update
    /// their internal state during logical length reads.
    pub fn read_array_ref_len(
        &mut self,
        array_ref: ArrayRef,
    ) -> ForeignFunctionCallbackResult<usize> {
        self.read_array_len(array_ref)
    }

    /// Semantically read an array length through the configured memory backend.
    ///
    /// This uses a mutable memory borrow so ORAM-style backends can update
    /// their internal state during logical length reads.
    pub fn read_array_len(&mut self, array_ref: ArrayRef) -> ForeignFunctionCallbackResult<usize> {
        Ok(self.services.try_read_array_ref_len(array_ref)?)
    }

    /// Semantically read an object length through the configured memory backend.
    ///
    /// This uses a mutable memory borrow so ORAM-style backends can update
    /// their internal state during logical object-shape reads.
    pub fn read_object_ref_len(
        &mut self,
        object_ref: ObjectRef,
    ) -> ForeignFunctionCallbackResult<usize> {
        self.read_object_len(object_ref)
    }

    /// Semantically read an object length through the configured memory backend.
    ///
    /// This uses a mutable memory borrow so ORAM-style backends can update
    /// their internal state during logical object-shape reads.
    pub fn read_object_len(
        &mut self,
        object_ref: ObjectRef,
    ) -> ForeignFunctionCallbackResult<usize> {
        Ok(self.services.try_read_object_ref_len(object_ref)?)
    }

    /// Semantically read object entries through the configured memory backend.
    ///
    /// This uses a mutable memory borrow so ORAM-style backends can update
    /// their internal state during logical object reads.
    pub fn read_object_ref_entries(
        &mut self,
        object_ref: ObjectRef,
        limit: usize,
    ) -> ForeignFunctionCallbackResult<Vec<(Value, Value)>> {
        self.read_object_entries(object_ref, limit)
    }

    /// Semantically read object entries through the configured memory backend.
    ///
    /// This uses a mutable memory borrow so ORAM-style backends can update
    /// their internal state during logical object reads.
    pub fn read_object_entries(
        &mut self,
        object_ref: ObjectRef,
        limit: usize,
    ) -> ForeignFunctionCallbackResult<Vec<(Value, Value)>> {
        Ok(self
            .services
            .try_read_object_ref_entries(object_ref, limit)?)
    }

    /// Semantically read a VM byte array (`Value::Array` of `Value::U8`).
    pub fn read_byte_array(&mut self, value: &Value) -> ForeignFunctionCallbackResult<Vec<u8>> {
        Ok(self.services.read_byte_array(value)?)
    }

    /// Create a VM byte array (`Value::Array` of `Value::U8`) from raw bytes.
    pub fn create_byte_array(&mut self, bytes: &[u8]) -> ForeignFunctionCallbackResult<Value> {
        Ok(self.services.create_byte_array(bytes)?)
    }

    /// Create a VM table object and return its typed handle.
    pub fn create_object_ref(&mut self) -> ForeignFunctionCallbackResult<ObjectRef> {
        Ok(self.services.create_object_ref()?)
    }

    /// Create a VM table array and return its typed handle.
    pub fn create_array_ref(&mut self, capacity: usize) -> ForeignFunctionCallbackResult<ArrayRef> {
        Ok(self.services.create_array_ref(capacity)?)
    }

    /// Create a VM table object through the configured memory backend.
    pub fn create_object(&mut self) -> ForeignFunctionCallbackResult<Value> {
        Ok(Value::from(self.create_object_ref()?))
    }

    /// Create a VM table array through the configured memory backend.
    pub fn create_array(&mut self, capacity: usize) -> ForeignFunctionCallbackResult<Value> {
        Ok(Value::from(self.create_array_ref(capacity)?))
    }

    /// Set a field on a VM table through the configured memory backend.
    pub fn set_table_field(
        &mut self,
        table_ref: TableRef,
        key: Value,
        value: Value,
    ) -> ForeignFunctionCallbackResult<()> {
        Ok(self.services.set_table_field(table_ref, key, value)?)
    }

    /// Append values to a VM array through the configured memory backend.
    pub fn push_array_ref_values(
        &mut self,
        array_ref: ArrayRef,
        values: &[Value],
    ) -> ForeignFunctionCallbackResult<usize> {
        self.push_array_values(array_ref, values)
    }

    /// Append values to a VM array through the configured memory backend.
    pub fn push_array_values(
        &mut self,
        array_ref: ArrayRef,
        values: &[Value],
    ) -> ForeignFunctionCallbackResult<usize> {
        Ok(self.services.push_array_ref_values(array_ref, values)?)
    }

    /// Append this call's argument tail directly to a VM array.
    pub fn push_array_args_from(
        &mut self,
        array_ref: ArrayRef,
        start: usize,
        function: &'static str,
    ) -> ForeignFunctionCallbackResult<usize> {
        let values = self
            .args
            .get(start..)
            .ok_or_else(|| format!("{function} missing arguments starting at {start}"))?;
        Ok(self.services.push_array_ref_values(array_ref, values)?)
    }

    /// Create a VM object and populate it with fields.
    pub fn create_object_with_fields<I>(
        &mut self,
        fields: I,
    ) -> ForeignFunctionCallbackResult<Value>
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
