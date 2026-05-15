use super::byte_arrays::{create_byte_array_ref, extract_byte_array_ref};
use super::{avss_fields, MpcValueError, MpcValueResult};
use crate::value_conversions::usize_to_vm_i64;
use stoffel_vm_types::core_types::{ArrayRef, ObjectRef, TableMemory, TableRef, Value};

fn field(name: &str) -> Value {
    Value::String(name.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AvssShareObjectRef(ObjectRef);

impl AvssShareObjectRef {
    pub const fn new_unchecked(object_ref: ObjectRef) -> Self {
        Self(object_ref)
    }

    pub fn validate<M: TableMemory + ?Sized>(
        store: &mut M,
        object_ref: ObjectRef,
    ) -> MpcValueResult<Self> {
        let avss_ref = Self::new_unchecked(object_ref);
        avss_ref.require_type_tag(store)?;
        Ok(avss_ref)
    }

    pub const fn object_ref(self) -> ObjectRef {
        self.0
    }

    pub const fn table_ref(self) -> TableRef {
        TableRef::Object(self.0)
    }

    pub const fn into_value(self) -> Value {
        self.0.into_value()
    }

    pub fn is_avss_share_object<M: TableMemory + ?Sized>(self, store: &mut M) -> bool {
        matches!(
            store.read_table_field(self.table_ref(), &field(avss_fields::TYPE)),
            Ok(Some(Value::String(s))) if s == avss_fields::TYPE_VALUE
        )
    }

    pub fn key_name<M: TableMemory + ?Sized>(self, store: &mut M) -> MpcValueResult<String> {
        self.require_type_tag(store)?;
        let key_name_field = store
            .read_table_field(self.table_ref(), &field(avss_fields::KEY_NAME))
            .map_err(|e| {
                MpcValueError::table_memory_context("failed to read AVSS __key_name field", e)
            })?
            .ok_or_else(|| {
                MpcValueError::missing_field("AVSS share object", avss_fields::KEY_NAME)
            })?;

        match key_name_field {
            Value::String(s) => Ok(s),
            actual => Err(MpcValueError::unexpected_value(
                "AVSS __key_name field",
                "String",
                actual,
            )),
        }
    }

    pub fn commitment<M: TableMemory + ?Sized>(
        self,
        store: &mut M,
        index: usize,
    ) -> MpcValueResult<Vec<u8>> {
        let commitments_array_ref = self.commitments_array_ref(store)?;
        let commitments_array = TableRef::from(commitments_array_ref);
        let commitment_count = store
            .read_array_ref_len(commitments_array_ref)
            .map_err(|e| {
                MpcValueError::table_memory_context("failed to read AVSS commitment count", e)
            })?;
        if index >= commitment_count {
            return Err(MpcValueError::index_out_of_bounds(
                "AVSS commitments",
                index,
                commitment_count,
            ));
        }

        let commitment = store
            .read_table_field(
                commitments_array,
                &Value::I64(usize_to_vm_i64(index, "commitment index")?),
            )
            .map_err(|e| {
                MpcValueError::table_memory_context(
                    format!("failed to read commitment at index {index}"),
                    e,
                )
            })?
            .ok_or_else(|| {
                MpcValueError::message(format!("Commitment at index {index} not found"))
            })?;

        let commitment_array_ref = match ArrayRef::from_value(&commitment) {
            Some(array_ref) => array_ref,
            None => {
                return Err(MpcValueError::unexpected_value(
                    format!("AVSS commitment at index {index}"),
                    "Array",
                    commitment,
                ));
            }
        };

        extract_byte_array_ref(store, commitment_array_ref)
    }

    pub fn commitment_count<M: TableMemory + ?Sized>(self, store: &mut M) -> MpcValueResult<usize> {
        let commitments_array_ref = self.commitments_array_ref(store)?;
        store
            .read_array_ref_len(commitments_array_ref)
            .map_err(|e| {
                MpcValueError::table_memory_context("failed to read AVSS commitment count", e)
            })
    }

    fn require_type_tag<M: TableMemory + ?Sized>(self, store: &mut M) -> MpcValueResult<()> {
        let type_field = store
            .read_table_field(self.table_ref(), &field(avss_fields::TYPE))
            .map_err(|e| {
                MpcValueError::table_memory_context("failed to read AVSS __type field", e)
            })?
            .ok_or_else(|| {
                MpcValueError::message("Object is not an AVSS share: missing __type field")
            })?;

        if type_field != Value::String(avss_fields::TYPE_VALUE.to_string()) {
            return Err(MpcValueError::message(format!(
                "Object is not an AVSS share: __type is {:?}, expected {:?}",
                type_field,
                avss_fields::TYPE_VALUE
            )));
        }

        Ok(())
    }

    fn commitments_array_ref<M: TableMemory + ?Sized>(
        self,
        store: &mut M,
    ) -> MpcValueResult<ArrayRef> {
        self.require_type_tag(store)?;
        let commitments_field = store
            .read_table_field(self.table_ref(), &field(avss_fields::COMMITMENTS))
            .map_err(|e| {
                MpcValueError::table_memory_context("failed to read AVSS __commitments field", e)
            })?
            .ok_or_else(|| {
                MpcValueError::missing_field("AVSS share object", avss_fields::COMMITMENTS)
            })?;

        match ArrayRef::from_value(&commitments_field) {
            Some(array_ref) => Ok(array_ref),
            None => Err(MpcValueError::unexpected_value(
                "AVSS __commitments field",
                "Array",
                commitments_field,
            )),
        }
    }
}

impl From<AvssShareObjectRef> for ObjectRef {
    fn from(avss_ref: AvssShareObjectRef) -> Self {
        avss_ref.object_ref()
    }
}

impl From<AvssShareObjectRef> for TableRef {
    fn from(avss_ref: AvssShareObjectRef) -> Self {
        avss_ref.table_ref()
    }
}

impl From<AvssShareObjectRef> for Value {
    fn from(avss_ref: AvssShareObjectRef) -> Self {
        avss_ref.into_value()
    }
}

/// Create a new AVSS share object in the object store.
pub fn create_avss_share_object_ref<M: TableMemory + ?Sized>(
    store: &mut M,
    key_name: &str,
    share_data: Vec<u8>,
    commitment_bytes: Vec<Vec<u8>>,
    party_id: usize,
) -> MpcValueResult<AvssShareObjectRef> {
    let object_ref = store.create_object_ref().map_err(|e| {
        MpcValueError::table_memory_context("failed to create AVSS share object", e)
    })?;
    let obj = TableRef::from(object_ref);

    store
        .set_table_field(
            obj,
            field(avss_fields::TYPE),
            Value::String(avss_fields::TYPE_VALUE.to_string()),
        )
        .map_err(|e| MpcValueError::table_memory_context("failed to set AVSS type tag", e))?;

    store
        .set_table_field(
            obj,
            field(avss_fields::KEY_NAME),
            Value::String(key_name.to_string()),
        )
        .map_err(|e| MpcValueError::table_memory_context("failed to set AVSS key name", e))?;

    let share_array_ref = create_byte_array_ref(store, &share_data)?;
    store
        .set_table_field(
            obj,
            field(avss_fields::SHARE_DATA),
            Value::from(share_array_ref),
        )
        .map_err(|e| MpcValueError::table_memory_context("failed to set AVSS share data", e))?;

    let commitment_array_refs: Vec<ArrayRef> = commitment_bytes
        .into_iter()
        .map(|commitment| create_byte_array_ref(store, &commitment))
        .collect::<MpcValueResult<Vec<_>>>()?;

    let commitments_array_ref = store
        .create_array_ref_with_capacity(commitment_array_refs.len())
        .map_err(|e| {
            MpcValueError::table_memory_context("failed to create AVSS commitments array", e)
        })?;
    let commitment_values: Vec<Value> =
        commitment_array_refs.into_iter().map(Value::from).collect();
    store
        .push_array_ref_values(commitments_array_ref, &commitment_values)
        .map_err(|e| {
            MpcValueError::table_memory_context("failed to populate AVSS commitments array", e)
        })?;
    store
        .set_table_field(
            obj,
            field(avss_fields::COMMITMENTS),
            Value::from(commitments_array_ref),
        )
        .map_err(|e| MpcValueError::table_memory_context("failed to set AVSS commitments", e))?;

    store
        .set_table_field(
            obj,
            field(avss_fields::PARTY_ID),
            Value::I64(usize_to_vm_i64(party_id, "party_id")?),
        )
        .map_err(|e| MpcValueError::table_memory_context("failed to set AVSS party ID", e))?;

    Ok(AvssShareObjectRef::new_unchecked(object_ref))
}

/// Check if a value is an AVSS share object.
pub fn is_avss_share_object<M: TableMemory + ?Sized>(store: &mut M, value: &Value) -> bool {
    let Some(object_ref) = ObjectRef::from_value(value) else {
        return false;
    };

    is_avss_share_object_ref(store, AvssShareObjectRef::new_unchecked(object_ref))
}

/// Check if a typed object handle references an AVSS share object.
pub fn is_avss_share_object_ref<M: TableMemory + ?Sized>(
    store: &mut M,
    avss_ref: AvssShareObjectRef,
) -> bool {
    avss_ref.is_avss_share_object(store)
}

/// Extract key name from an AVSS share object.
pub fn get_key_name<M: TableMemory + ?Sized>(
    store: &mut M,
    value: &Value,
) -> MpcValueResult<String> {
    let object_ref = ObjectRef::try_from(value)?;
    get_key_name_ref(store, AvssShareObjectRef::new_unchecked(object_ref))
}

/// Extract key name from a typed AVSS share object handle.
pub fn get_key_name_ref<M: TableMemory + ?Sized>(
    store: &mut M,
    avss_ref: AvssShareObjectRef,
) -> MpcValueResult<String> {
    avss_ref.key_name(store)
}

/// Extract commitment bytes at a specific index from an AVSS share object.
pub fn get_commitment<M: TableMemory + ?Sized>(
    store: &mut M,
    value: &Value,
    index: usize,
) -> MpcValueResult<Vec<u8>> {
    let object_ref = ObjectRef::try_from(value)?;
    get_commitment_ref(store, AvssShareObjectRef::new_unchecked(object_ref), index)
}

/// Extract commitment bytes from a typed AVSS share object handle.
pub fn get_commitment_ref<M: TableMemory + ?Sized>(
    store: &mut M,
    avss_ref: AvssShareObjectRef,
    index: usize,
) -> MpcValueResult<Vec<u8>> {
    avss_ref.commitment(store, index)
}

/// Get the number of commitments in an AVSS share object.
pub fn get_commitment_count<M: TableMemory + ?Sized>(
    store: &mut M,
    value: &Value,
) -> MpcValueResult<usize> {
    let object_ref = ObjectRef::try_from(value)?;
    get_commitment_count_ref(store, AvssShareObjectRef::new_unchecked(object_ref))
}

/// Get the number of commitments from a typed AVSS share object handle.
pub fn get_commitment_count_ref<M: TableMemory + ?Sized>(
    store: &mut M,
    avss_ref: AvssShareObjectRef,
) -> MpcValueResult<usize> {
    avss_ref.commitment_count(store)
}
