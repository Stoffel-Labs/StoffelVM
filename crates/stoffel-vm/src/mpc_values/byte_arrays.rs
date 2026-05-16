use super::{MpcValueError, MpcValueResult};
use crate::value_conversions::usize_to_vm_i64;
use stoffel_vm_types::core_types::{ArrayRef, TableMemory, TableRef, Value};

/// Extract a `Vec<u8>` from a VM byte array (`Value::Array` of `Value::U8`).
pub(crate) fn extract_byte_array<M: TableMemory + ?Sized>(
    store: &mut M,
    value: &Value,
) -> MpcValueResult<Vec<u8>> {
    let Some(array_ref) = ArrayRef::from_value(value) else {
        return Err(MpcValueError::message("Expected byte array"));
    };

    extract_byte_array_ref(store, array_ref)
}

/// Extract a `Vec<u8>` from a typed VM byte-array handle.
pub(crate) fn extract_byte_array_ref<M: TableMemory + ?Sized>(
    store: &mut M,
    array_ref: ArrayRef,
) -> MpcValueResult<Vec<u8>> {
    let len = store.read_array_ref_len(array_ref)?;
    let array = TableRef::from(array_ref);
    let mut bytes = Vec::with_capacity(len);
    for i in 0..len {
        match store.read_table_field(array, &Value::I64(usize_to_vm_i64(i, "array index")?)) {
            Ok(Some(Value::U8(b))) => bytes.push(b),
            Err(e) => {
                return Err(MpcValueError::table_memory_context(
                    format!("Failed to read byte at index {i}"),
                    e,
                ));
            }
            _ => return Err(MpcValueError::message(format!("Expected U8 at index {i}"))),
        }
    }

    Ok(bytes)
}

/// Create a VM byte array handle (`Value::Array` of `Value::U8`) from raw bytes.
pub(crate) fn create_byte_array_ref<M: TableMemory + ?Sized>(
    store: &mut M,
    bytes: &[u8],
) -> MpcValueResult<ArrayRef> {
    let array_ref = store.create_array_ref_with_capacity(bytes.len())?;
    let values: Vec<Value> = bytes.iter().copied().map(Value::U8).collect();
    store.push_array_ref_values(array_ref, &values)?;
    Ok(array_ref)
}

/// Create a VM byte array (`Value::Array` of `Value::U8`) from raw bytes.
#[cfg(test)]
pub(crate) fn create_byte_array<M: TableMemory + ?Sized>(
    store: &mut M,
    bytes: &[u8],
) -> MpcValueResult<usize> {
    Ok(create_byte_array_ref(store, bytes)?.id())
}
