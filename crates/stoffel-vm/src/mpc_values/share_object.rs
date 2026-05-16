use super::{share_fields, MpcValueError, MpcValueResult};
use crate::value_conversions::{usize_to_vm_i64, value_to_usize};
use stoffel_vm_types::core_types::{
    ArrayRef, ObjectRef, ShareData, ShareType, TableMemory, TableRef, Value,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchingSharePair {
    pub share_type: ShareType,
    pub left_data: ShareData,
    pub right_data: ShareData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ShareObjectRef(ObjectRef);

impl ShareObjectRef {
    pub const fn new_unchecked(object_ref: ObjectRef) -> Self {
        Self(object_ref)
    }

    pub fn validate<M: TableMemory + ?Sized>(
        store: &mut M,
        object_ref: ObjectRef,
    ) -> MpcValueResult<Self> {
        let share_ref = Self::new_unchecked(object_ref);
        share_ref.require_type_tag(store)?;
        Ok(share_ref)
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

    pub fn is_share_object<M: TableMemory + ?Sized>(self, store: &mut M) -> bool {
        matches!(
            store.read_table_field(self.table_ref(), &field(share_fields::TYPE)),
            Ok(Some(Value::String(s))) if s == share_fields::TYPE_VALUE
        )
    }

    pub fn share_data<M: TableMemory + ?Sized>(
        self,
        store: &mut M,
    ) -> MpcValueResult<(ShareType, ShareData)> {
        self.require_type_tag(store)?;
        let metadata_type = self.decode_metadata_share_type(store)?;

        let data_field = store
            .read_table_field(self.table_ref(), &field(share_fields::DATA))
            .map_err(|e| {
                MpcValueError::table_memory_context("failed to read Share __data field", e)
            })?
            .ok_or_else(|| MpcValueError::message("Share object missing __data field"))?;

        match data_field {
            Value::Share(ty, data) if ty == metadata_type => Ok((ty, data)),
            Value::Share(ty, _) => Err(MpcValueError::message(format!(
                "Share metadata type {:?} does not match __data type {:?}",
                metadata_type, ty
            ))),
            _ => Err(MpcValueError::message(
                "Share __data field is not a Share value",
            )),
        }
    }

    pub fn share_type<M: TableMemory + ?Sized>(self, store: &mut M) -> MpcValueResult<ShareType> {
        self.share_data(store).map(|(ty, _)| ty)
    }

    pub fn party_id<M: TableMemory + ?Sized>(self, store: &mut M) -> MpcValueResult<usize> {
        self.require_type_tag(store)?;
        let party_id = store
            .read_table_field(self.table_ref(), &field(share_fields::PARTY_ID))
            .map_err(|e| {
                MpcValueError::table_memory_context("failed to read Share __party_id field", e)
            })?
            .ok_or_else(|| MpcValueError::missing_field("Share object", share_fields::PARTY_ID))?;

        Ok(value_to_usize(&party_id, "party_id")?)
    }

    fn require_type_tag<M: TableMemory + ?Sized>(self, store: &mut M) -> MpcValueResult<()> {
        let type_field = store
            .read_table_field(self.table_ref(), &field(share_fields::TYPE))
            .map_err(|e| {
                MpcValueError::table_memory_context("failed to read Share __type field", e)
            })?
            .ok_or_else(|| MpcValueError::message("Object is not a Share: missing __type field"))?;

        if type_field != Value::String(share_fields::TYPE_VALUE.to_string()) {
            return Err(MpcValueError::message(format!(
                "Object is not a Share: __type is {:?}, expected {:?}",
                type_field,
                share_fields::TYPE_VALUE
            )));
        }

        Ok(())
    }

    fn decode_metadata_share_type<M: TableMemory + ?Sized>(
        self,
        store: &mut M,
    ) -> MpcValueResult<ShareType> {
        let share_type_field = store
            .read_table_field(self.table_ref(), &field(share_fields::SHARE_TYPE))
            .map_err(|e| {
                MpcValueError::table_memory_context("failed to read Share __share_type field", e)
            })?
            .ok_or_else(|| MpcValueError::message("Share object missing __share_type field"))?;

        match share_type_field {
            Value::String(s) if s == share_fields::SECRET_INT => {
                let bit_length = match store
                    .read_table_field(self.table_ref(), &field(share_fields::BIT_LENGTH))
                    .map_err(|e| {
                        MpcValueError::table_memory_context("failed to read Share bit length", e)
                    })? {
                    Some(value) => value_to_usize(&value, "bit_length")?,
                    _ => 64,
                };
                Ok(ShareType::try_secret_int(bit_length)?)
            }
            Value::String(s) if s == share_fields::SECRET_FIXED_POINT => {
                let k = match store
                    .read_table_field(self.table_ref(), &field(share_fields::PRECISION_K))
                    .map_err(|e| {
                        MpcValueError::table_memory_context("failed to read Share precision k", e)
                    })? {
                    Some(value) => value_to_usize(&value, "precision k")?,
                    _ => 64,
                };
                let f = match store
                    .read_table_field(self.table_ref(), &field(share_fields::PRECISION_F))
                    .map_err(|e| {
                        MpcValueError::table_memory_context("failed to read Share precision f", e)
                    })? {
                    Some(value) => value_to_usize(&value, "precision f")?,
                    _ => 16,
                };
                Ok(ShareType::try_secret_fixed_point_from_bits(k, f)?)
            }
            _ => Err(MpcValueError::message(format!(
                "Unknown share type: {:?}",
                share_type_field
            ))),
        }
    }
}

impl From<ShareObjectRef> for ObjectRef {
    fn from(share_ref: ShareObjectRef) -> Self {
        share_ref.object_ref()
    }
}

impl From<ShareObjectRef> for TableRef {
    fn from(share_ref: ShareObjectRef) -> Self {
        share_ref.table_ref()
    }
}

impl From<ShareObjectRef> for Value {
    fn from(share_ref: ShareObjectRef) -> Self {
        share_ref.into_value()
    }
}

fn field(name: &str) -> Value {
    Value::String(name.to_string())
}

/// Create a new Share object in the object store.
pub fn create_share_object_ref<M: TableMemory + ?Sized>(
    store: &mut M,
    share_type: ShareType,
    data: ShareData,
    party_id: usize,
) -> MpcValueResult<ShareObjectRef> {
    let object_ref = store.create_object_ref()?;
    let obj = TableRef::from(object_ref);

    store
        .set_table_field(
            obj,
            field(share_fields::TYPE),
            Value::String(share_fields::TYPE_VALUE.to_string()),
        )
        .map_err(|e| MpcValueError::table_memory_context("failed to set Share type tag", e))?;

    match share_type {
        ShareType::SecretInt { bit_length } => {
            store
                .set_table_field(
                    obj,
                    field(share_fields::SHARE_TYPE),
                    Value::String(share_fields::SECRET_INT.to_string()),
                )
                .map_err(|e| MpcValueError::table_memory_context("failed to set Share type", e))?;
            store
                .set_table_field(
                    obj,
                    field(share_fields::BIT_LENGTH),
                    Value::I64(usize_to_vm_i64(bit_length, "bit_length")?),
                )
                .map_err(|e| {
                    MpcValueError::table_memory_context("failed to set Share bit length", e)
                })?;
        }
        ShareType::SecretFixedPoint { precision } => {
            store
                .set_table_field(
                    obj,
                    field(share_fields::SHARE_TYPE),
                    Value::String(share_fields::SECRET_FIXED_POINT.to_string()),
                )
                .map_err(|e| MpcValueError::table_memory_context("failed to set Share type", e))?;
            store
                .set_table_field(
                    obj,
                    field(share_fields::PRECISION_K),
                    Value::I64(usize_to_vm_i64(precision.k(), "precision k")?),
                )
                .map_err(|e| {
                    MpcValueError::table_memory_context("failed to set Share precision k", e)
                })?;
            store
                .set_table_field(
                    obj,
                    field(share_fields::PRECISION_F),
                    Value::I64(usize_to_vm_i64(precision.f(), "precision f")?),
                )
                .map_err(|e| {
                    MpcValueError::table_memory_context("failed to set Share precision f", e)
                })?;
        }
    }

    store
        .set_table_field(
            obj,
            field(share_fields::DATA),
            Value::Share(share_type, data),
        )
        .map_err(|e| MpcValueError::table_memory_context("failed to set Share data", e))?;

    store
        .set_table_field(
            obj,
            field(share_fields::PARTY_ID),
            Value::I64(usize_to_vm_i64(party_id, "party_id")?),
        )
        .map_err(|e| MpcValueError::table_memory_context("failed to set Share party ID", e))?;

    Ok(ShareObjectRef::new_unchecked(object_ref))
}

/// Extract share data from a Share object or raw `Value::Share`.
pub fn extract_share_data<M: TableMemory + ?Sized>(
    store: &mut M,
    value: &Value,
) -> MpcValueResult<(ShareType, ShareData)> {
    if let Value::Share(ty, data) = value {
        return Ok((*ty, data.clone()));
    }

    let Some(object_ref) = ObjectRef::from_value(value) else {
        return Err(MpcValueError::message(format!(
            "Expected Share object or Share value, got {:?}",
            value
        )));
    };

    extract_share_data_ref(store, ShareObjectRef::new_unchecked(object_ref))
}

/// Extract share data from a typed Share object handle.
pub fn extract_share_data_ref<M: TableMemory + ?Sized>(
    store: &mut M,
    share_ref: ShareObjectRef,
) -> MpcValueResult<(ShareType, ShareData)> {
    share_ref.share_data(store)
}

pub fn extract_matching_share_pair<M: TableMemory + ?Sized>(
    store: &mut M,
    left: &Value,
    right: &Value,
    context: impl Into<String>,
) -> MpcValueResult<MatchingSharePair> {
    let (left_type, left_data) = extract_share_data(store, left)?;
    let (right_type, right_data) = extract_share_data(store, right)?;

    if left_type != right_type {
        return Err(MpcValueError::ShareTypeMismatch {
            context: context.into(),
            left: left_type,
            right: right_type,
        });
    }

    Ok(MatchingSharePair {
        share_type: left_type,
        left_data,
        right_data,
    })
}

/// Extract Share values from a VM array.
pub fn extract_share_array<M: TableMemory + ?Sized>(
    store: &mut M,
    value: &Value,
    context: &str,
) -> MpcValueResult<Vec<(ShareType, ShareData)>> {
    let array_ref = match ArrayRef::from_value(value) {
        Some(array_ref) => array_ref,
        None => {
            return Err(MpcValueError::unexpected_value(
                context,
                "array of Share values",
                value.clone(),
            ));
        }
    };

    extract_share_array_ref(store, array_ref, context)
}

/// Extract Share values from a typed VM array handle.
pub fn extract_share_array_ref<M: TableMemory + ?Sized>(
    store: &mut M,
    array_ref: ArrayRef,
    context: &str,
) -> MpcValueResult<Vec<(ShareType, ShareData)>> {
    let array = TableRef::from(array_ref);
    let len = store.read_array_ref_len(array_ref).map_err(|e| {
        MpcValueError::table_memory_context(format!("failed to read {context} length"), e)
    })?;
    let mut shares = Vec::with_capacity(len);

    for i in 0..len {
        let idx = Value::I64(usize_to_vm_i64(i, "array index")?);
        let element = store
            .read_table_field(array, &idx)
            .map_err(|e| {
                MpcValueError::table_memory_context(
                    format!("failed to read {context} element {i}"),
                    e,
                )
            })?
            .ok_or_else(|| MpcValueError::missing_array_element(context, i))?;
        if element == Value::Unit {
            return Err(MpcValueError::missing_array_element(context, i));
        }

        shares.push(extract_share_data(store, &element)?);
    }

    Ok(shares)
}

/// Extract Share values from a VM array and require one common share type.
pub fn extract_homogeneous_share_array<M: TableMemory + ?Sized>(
    store: &mut M,
    value: &Value,
    context: &str,
) -> MpcValueResult<Option<(ShareType, Vec<ShareData>)>> {
    let array_ref = match ArrayRef::from_value(value) {
        Some(array_ref) => array_ref,
        None => {
            return Err(MpcValueError::unexpected_value(
                context,
                "array of Share values",
                value.clone(),
            ));
        }
    };

    extract_homogeneous_share_array_ref(store, array_ref, context)
}

/// Extract Share values from a typed VM array handle and require one common share type.
pub fn extract_homogeneous_share_array_ref<M: TableMemory + ?Sized>(
    store: &mut M,
    array_ref: ArrayRef,
    context: &str,
) -> MpcValueResult<Option<(ShareType, Vec<ShareData>)>> {
    let shares = extract_share_array_ref(store, array_ref, context)?;
    let Some((first_ty, _)) = shares.first() else {
        return Ok(None);
    };
    let first_ty = *first_ty;
    let mut data = Vec::with_capacity(shares.len());

    for (i, (ty, share_data)) in shares.into_iter().enumerate() {
        if ty != first_ty {
            return Err(MpcValueError::message(format!(
                "All shares must have the same type. Element 0 has {:?} but element {} has {:?}",
                first_ty, i, ty
            )));
        }

        data.push(share_data);
    }

    Ok(Some((first_ty, data)))
}

/// Check if a value is a Share object or raw `Value::Share`.
pub fn is_share_object<M: TableMemory + ?Sized>(store: &mut M, value: &Value) -> bool {
    if matches!(value, Value::Share(_, _)) {
        return true;
    }

    let Some(object_ref) = ObjectRef::from_value(value) else {
        return false;
    };

    is_share_object_ref(store, ShareObjectRef::new_unchecked(object_ref))
}

/// Check if a typed object handle references a Share object.
pub fn is_share_object_ref<M: TableMemory + ?Sized>(
    store: &mut M,
    share_ref: ShareObjectRef,
) -> bool {
    share_ref.is_share_object(store)
}

/// Get the `ShareType` from a Share object or raw `Value::Share`.
pub fn get_share_type<M: TableMemory + ?Sized>(
    store: &mut M,
    value: &Value,
) -> MpcValueResult<ShareType> {
    if let Value::Share(ty, _) = value {
        return Ok(*ty);
    }

    let Some(object_ref) = ObjectRef::from_value(value) else {
        return Err(MpcValueError::message(format!(
            "Not a Share object: {:?}",
            value
        )));
    };

    get_share_type_ref(store, ShareObjectRef::new_unchecked(object_ref))
}

/// Get the `ShareType` from a typed Share object handle.
pub fn get_share_type_ref<M: TableMemory + ?Sized>(
    store: &mut M,
    share_ref: ShareObjectRef,
) -> MpcValueResult<ShareType> {
    share_ref.share_type(store)
}

/// Get the creator party ID from a Share object.
///
/// Raw `Value::Share` values do not carry object metadata, so callers that
/// still accept raw shares can substitute the current backend party ID.
pub fn get_party_id<M: TableMemory + ?Sized>(
    store: &mut M,
    value: &Value,
) -> MpcValueResult<Option<usize>> {
    if matches!(value, Value::Share(_, _)) {
        return Ok(None);
    }

    let Some(object_ref) = ObjectRef::from_value(value) else {
        return Err(MpcValueError::message(format!(
            "Not a Share object: {:?}",
            value
        )));
    };

    get_party_id_ref(store, ShareObjectRef::new_unchecked(object_ref)).map(Some)
}

/// Get the creator party ID from a typed Share object handle.
pub fn get_party_id_ref<M: TableMemory + ?Sized>(
    store: &mut M,
    share_ref: ShareObjectRef,
) -> MpcValueResult<usize> {
    share_ref.party_id(store)
}
