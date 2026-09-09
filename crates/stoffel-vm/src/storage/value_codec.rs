//! Binary persistence codec for VM values.
//!
//! The codec is intentionally local to the VM runtime. It avoids requiring
//! `stoffel-vm-types::Value` to commit to a public serialization format while
//! still allowing local storage backends to persist structured VM values.

use crate::net::mpc_engine::{DurableIdentityDigest, MpcRuntimeInfo};
use std::collections::HashSet;
use stoffel_vm_types::core_types::{
    ShareData, ShareType, TableMemory, TableMemoryError, TableRef, Value, F64,
};

pub type PersistentValueResult<T> = Result<T, PersistentValueError>;

const MAGIC: &[u8; 8] = b"STFLVAL1";
// v4 distinguishes field shares from integer shares. Previous envelopes cannot
// identify field values that were persisted with integer tags.
const SHARE_ENVELOPE_VERSION: u8 = 4;
pub const MAX_PERSISTENT_VALUE_BYTES: usize = 16 * 1024 * 1024;
const MAX_PERSISTENT_BLOB_BYTES: usize = MAX_PERSISTENT_VALUE_BYTES;
const MAX_PERSISTENT_TABLE_ENTRIES: usize = 65_536;
const MAX_PERSISTENT_COMMITMENTS: usize = 4_096;

const TAG_UNIT: u8 = 0;
const TAG_I64: u8 = 1;
const TAG_I32: u8 = 2;
const TAG_I16: u8 = 3;
const TAG_I8: u8 = 4;
const TAG_U8: u8 = 5;
const TAG_U16: u8 = 6;
const TAG_U32: u8 = 7;
const TAG_U64: u8 = 8;
const TAG_FLOAT: u8 = 9;
const TAG_BOOL: u8 = 10;
const TAG_STRING: u8 = 11;
const TAG_SHARE: u8 = 12;
const TAG_OBJECT: u8 = 13;
const TAG_ARRAY: u8 = 14;

const SHARE_TYPE_SECRET_FIELD: u8 = 3;
const SHARE_TYPE_SECRET_INT: u8 = 0;
const SHARE_TYPE_SECRET_FIXED_POINT: u8 = 1;
const SHARE_TYPE_SECRET_UINT: u8 = 2;

const SHARE_DATA_OPAQUE: u8 = 0;
const SHARE_DATA_FELDMAN: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentValueContext {
    share: Option<PersistentShareContext>,
}

impl PersistentValueContext {
    pub fn with_share_context(share: PersistentShareContext) -> Self {
        Self { share: Some(share) }
    }

    pub fn from_mpc_runtime(info: MpcRuntimeInfo, key_id: &[u8]) -> Self {
        Self {
            share: Some(PersistentShareContext::from_mpc_runtime(info, key_id)),
        }
    }

    pub fn from_mpc_runtime_with_party_id(
        info: MpcRuntimeInfo,
        key_id: &[u8],
        _party_id: usize,
    ) -> Self {
        Self {
            share: Some(PersistentShareContext::from_mpc_runtime(info, key_id)),
        }
    }

    fn share_context(&self) -> Option<&PersistentShareContext> {
        self.share.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentShareContext {
    protocol_name: String,
    curve: String,
    field: String,
    node_identity: DurableIdentityDigest,
    n_parties: usize,
    threshold: usize,
    key_id_digest: [u8; 32],
}

impl PersistentShareContext {
    pub fn new(
        protocol_name: impl Into<String>,
        curve: impl Into<String>,
        field: impl Into<String>,
        node_identity: DurableIdentityDigest,
        n_parties: usize,
        threshold: usize,
        key_id: &[u8],
    ) -> Self {
        Self {
            protocol_name: protocol_name.into(),
            curve: curve.into(),
            field: field.into(),
            node_identity,
            n_parties,
            threshold,
            key_id_digest: digest_bytes(key_id),
        }
    }

    fn from_mpc_runtime(info: MpcRuntimeInfo, key_id: &[u8]) -> Self {
        Self::new(
            info.protocol_name(),
            info.curve_config().name(),
            info.field_kind().name(),
            info.local_identity(),
            info.party_count().count(),
            info.threshold_param().value(),
            key_id,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PersistentValueError {
    #[error("cannot persist {type_name} values")]
    UnsupportedValue { type_name: &'static str },
    #[error("cannot persist or load share values without MPC persistence context")]
    MissingShareContext,
    #[error("persistent share metadata mismatch for {field}: expected {expected}, got {actual}")]
    ShareContextMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    #[error("persistent share digest mismatch for {field}")]
    ShareDigestMismatch { field: &'static str },
    #[error("cannot persist cyclic {type_name} value with id {id}")]
    CyclicValue { type_name: &'static str, id: usize },
    #[error("{label} count {count} exceeds supported limit {limit}")]
    LimitExceeded {
        label: &'static str,
        count: usize,
        limit: usize,
    },
    #[error("{label} length {len} exceeds supported range")]
    LengthOverflow { label: &'static str, len: u64 },
    #[error("invalid persistent value data: {reason}")]
    InvalidData { reason: String },
    #[error("table memory {operation} failed: {reason}")]
    TableMemory {
        operation: &'static str,
        reason: String,
    },
    #[error("persistent value contains trailing bytes")]
    TrailingBytes,
}

impl From<PersistentValueError> for String {
    fn from(error: PersistentValueError) -> Self {
        error.to_string()
    }
}

pub fn encode_value(value: &Value, memory: &mut dyn TableMemory) -> PersistentValueResult<Vec<u8>> {
    encode_value_with_context(value, memory, None)
}

pub fn encode_value_with_context(
    value: &Value,
    memory: &mut dyn TableMemory,
    context: Option<&PersistentValueContext>,
) -> PersistentValueResult<Vec<u8>> {
    let mut encoder = Encoder {
        memory,
        output: Vec::from(MAGIC.as_slice()),
        active_tables: HashSet::new(),
        share_context: context.and_then(PersistentValueContext::share_context),
    };
    encoder.write_value(value)?;
    Ok(encoder.output)
}

pub fn decode_value(bytes: &[u8], memory: &mut dyn TableMemory) -> PersistentValueResult<Value> {
    decode_value_with_context(bytes, memory, None)
}

pub fn decode_value_with_context(
    bytes: &[u8],
    memory: &mut dyn TableMemory,
    context: Option<&PersistentValueContext>,
) -> PersistentValueResult<Value> {
    if bytes.len() > MAX_PERSISTENT_VALUE_BYTES {
        return Err(PersistentValueError::LimitExceeded {
            label: "persistent value byte",
            count: bytes.len(),
            limit: MAX_PERSISTENT_VALUE_BYTES,
        });
    }
    let mut reader = Reader { bytes, cursor: 0 };
    reader.read_magic()?;
    let value = reader.read_value(
        memory,
        context.and_then(PersistentValueContext::share_context),
    )?;
    if !reader.is_empty() {
        return Err(PersistentValueError::TrailingBytes);
    }
    Ok(value)
}

struct Encoder<'a> {
    memory: &'a mut dyn TableMemory,
    output: Vec<u8>,
    active_tables: HashSet<TableRef>,
    share_context: Option<&'a PersistentShareContext>,
}

impl Encoder<'_> {
    fn write_value(&mut self, value: &Value) -> PersistentValueResult<()> {
        match value {
            Value::Unit => self.write_u8(TAG_UNIT),
            Value::I64(value) => {
                self.write_u8(TAG_I64);
                self.write_i64(*value);
            }
            Value::I32(value) => {
                self.write_u8(TAG_I32);
                self.write_i32(*value);
            }
            Value::I16(value) => {
                self.write_u8(TAG_I16);
                self.write_i16(*value);
            }
            Value::I8(value) => {
                self.write_u8(TAG_I8);
                self.write_u8(*value as u8);
            }
            Value::U8(value) => {
                self.write_u8(TAG_U8);
                self.write_u8(*value);
            }
            Value::U16(value) => {
                self.write_u8(TAG_U16);
                self.write_u16(*value);
            }
            Value::U32(value) => {
                self.write_u8(TAG_U32);
                self.write_u32(*value);
            }
            Value::U64(value) => {
                self.write_u8(TAG_U64);
                self.write_u64(*value);
            }
            Value::Float(value) => {
                self.write_u8(TAG_FLOAT);
                self.write_u64(value.value().to_bits());
            }
            Value::Bool(value) => {
                self.write_u8(TAG_BOOL);
                self.write_u8(u8::from(*value));
            }
            Value::String(value) => {
                self.write_u8(TAG_STRING);
                self.write_string(value)?;
            }
            Value::Share(share_type, share_data) => {
                self.write_u8(TAG_SHARE);
                self.write_share_envelope(share_data)?;
                self.write_share_type(*share_type)?;
                self.write_share_data(share_data)?;
            }
            Value::Object(object_ref) => {
                self.write_u8(TAG_OBJECT);
                self.write_table(TableRef::from(*object_ref), "object", |encoder| {
                    let entries = encoder
                        .memory
                        .read_object_ref_entries(*object_ref, usize::MAX)
                        .map_err(table_memory_error("read object entries"))?;
                    encoder.write_len(entries.len(), "object entry")?;
                    for (key, value) in entries {
                        encoder.write_value(&key)?;
                        encoder.write_value(&value)?;
                    }
                    Ok(())
                })?;
            }
            Value::Array(array_ref) => {
                self.write_u8(TAG_ARRAY);
                self.write_table(TableRef::from(*array_ref), "array", |encoder| {
                    let len = encoder
                        .memory
                        .read_array_ref_len(*array_ref)
                        .map_err(table_memory_error("read array length"))?;
                    let entries = encoder
                        .memory
                        .read_array_ref_entries(*array_ref, usize::MAX)
                        .map_err(table_memory_error("read array entries"))?;
                    encoder.write_len(len, "array")?;
                    encoder.write_len(entries.len(), "array entry")?;
                    for (key, value) in entries {
                        encoder.write_value(&key)?;
                        encoder.write_value(&value)?;
                    }
                    Ok(())
                })?;
            }
            Value::Foreign(_) => {
                return Err(PersistentValueError::UnsupportedValue {
                    type_name: value.type_name(),
                });
            }
            Value::Closure(_) => {
                return Err(PersistentValueError::UnsupportedValue {
                    type_name: value.type_name(),
                });
            }
        }
        Ok(())
    }

    fn write_table<F>(
        &mut self,
        table_ref: TableRef,
        type_name: &'static str,
        write: F,
    ) -> PersistentValueResult<()>
    where
        F: FnOnce(&mut Self) -> PersistentValueResult<()>,
    {
        if !self.active_tables.insert(table_ref) {
            return Err(PersistentValueError::CyclicValue {
                type_name,
                id: table_ref.id(),
            });
        }
        let result = write(self);
        self.active_tables.remove(&table_ref);
        result
    }

    fn write_share_type(&mut self, share_type: ShareType) -> PersistentValueResult<()> {
        match share_type {
            ShareType::SecretField => self.write_u8(SHARE_TYPE_SECRET_FIELD),
            ShareType::SecretInt { bit_length } => {
                self.write_u8(SHARE_TYPE_SECRET_INT);
                self.write_len(bit_length, "secret integer bit")?;
            }
            ShareType::SecretUInt { bit_length } => {
                self.write_u8(SHARE_TYPE_SECRET_UINT);
                self.write_len(bit_length, "secret unsigned integer bit")?;
            }
            ShareType::SecretFixedPoint { precision } => {
                self.write_u8(SHARE_TYPE_SECRET_FIXED_POINT);
                self.write_len(precision.total_bits(), "fixed-point total bit")?;
                self.write_len(precision.fractional_bits(), "fixed-point fractional bit")?;
            }
        }
        Ok(())
    }

    fn write_share_envelope(&mut self, share_data: &ShareData) -> PersistentValueResult<()> {
        let context = self
            .share_context
            .ok_or(PersistentValueError::MissingShareContext)?;
        self.write_u8(SHARE_ENVELOPE_VERSION);
        self.write_string(&context.protocol_name)?;
        self.write_string(&context.curve)?;
        self.write_string(&context.field)?;
        self.write_digest(&context.node_identity.as_bytes());
        self.write_len(context.n_parties, "party count")?;
        self.write_len(context.threshold, "threshold")?;
        self.write_digest(&context.key_id_digest);
        self.write_digest(&digest_bytes(share_data.as_bytes()));
        let commitment_digest = share_commitment_digest(share_data)?;
        self.write_optional_digest(commitment_digest.as_ref());
        Ok(())
    }

    fn write_share_data(&mut self, share_data: &ShareData) -> PersistentValueResult<()> {
        match share_data {
            ShareData::Opaque(bytes) => {
                self.write_u8(SHARE_DATA_OPAQUE);
                self.write_bytes(bytes)?;
            }
            ShareData::Feldman { data, commitments } => {
                self.write_u8(SHARE_DATA_FELDMAN);
                self.write_bytes(data)?;
                self.write_len(commitments.len(), "Feldman commitment")?;
                for commitment in commitments.iter() {
                    self.write_bytes(commitment)?;
                }
            }
        }
        Ok(())
    }

    fn write_string(&mut self, value: &str) -> PersistentValueResult<()> {
        self.write_bytes(value.as_bytes())
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> PersistentValueResult<()> {
        self.write_len(bytes.len(), "byte")?;
        self.output.extend_from_slice(bytes);
        Ok(())
    }

    fn write_len(&mut self, len: usize, label: &'static str) -> PersistentValueResult<()> {
        let len = u64::try_from(len).map_err(|_| PersistentValueError::LengthOverflow {
            label,
            len: u64::MAX,
        })?;
        self.write_u64(len);
        Ok(())
    }

    fn write_u8(&mut self, value: u8) {
        self.output.push(value);
    }

    fn write_i16(&mut self, value: i16) {
        self.output.extend_from_slice(&value.to_le_bytes());
    }

    fn write_i32(&mut self, value: i32) {
        self.output.extend_from_slice(&value.to_le_bytes());
    }

    fn write_i64(&mut self, value: i64) {
        self.output.extend_from_slice(&value.to_le_bytes());
    }

    fn write_u16(&mut self, value: u16) {
        self.output.extend_from_slice(&value.to_le_bytes());
    }

    fn write_u32(&mut self, value: u32) {
        self.output.extend_from_slice(&value.to_le_bytes());
    }

    fn write_u64(&mut self, value: u64) {
        self.output.extend_from_slice(&value.to_le_bytes());
    }

    fn write_digest(&mut self, digest: &[u8; 32]) {
        self.output.extend_from_slice(digest);
    }

    fn write_optional_digest(&mut self, digest: Option<&[u8; 32]>) {
        match digest {
            Some(digest) => {
                self.write_u8(1);
                self.write_digest(digest);
            }
            None => self.write_u8(0),
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl Reader<'_> {
    fn read_magic(&mut self) -> PersistentValueResult<()> {
        let magic = self.read_exact(MAGIC.len())?;
        if magic != MAGIC {
            return Err(invalid_data("unknown persistent value format"));
        }
        Ok(())
    }

    fn read_value(
        &mut self,
        memory: &mut dyn TableMemory,
        share_context: Option<&PersistentShareContext>,
    ) -> PersistentValueResult<Value> {
        match self.read_u8()? {
            TAG_UNIT => Ok(Value::Unit),
            TAG_I64 => Ok(Value::I64(self.read_i64()?)),
            TAG_I32 => Ok(Value::I32(self.read_i32()?)),
            TAG_I16 => Ok(Value::I16(self.read_i16()?)),
            TAG_I8 => Ok(Value::I8(self.read_u8()? as i8)),
            TAG_U8 => Ok(Value::U8(self.read_u8()?)),
            TAG_U16 => Ok(Value::U16(self.read_u16()?)),
            TAG_U32 => Ok(Value::U32(self.read_u32()?)),
            TAG_U64 => Ok(Value::U64(self.read_u64()?)),
            TAG_FLOAT => Ok(Value::Float(F64::new(f64::from_bits(self.read_u64()?)))),
            TAG_BOOL => match self.read_u8()? {
                0 => Ok(Value::Bool(false)),
                1 => Ok(Value::Bool(true)),
                value => Err(invalid_data(format!("invalid boolean byte {value}"))),
            },
            TAG_STRING => Ok(Value::String(self.read_string()?)),
            TAG_SHARE => {
                let envelope = self.read_share_envelope()?;
                let share_type = self.read_share_type()?;
                let share_data = self.read_share_data()?;
                envelope.validate(share_context, &share_data)?;
                Ok(Value::Share(share_type, share_data))
            }
            TAG_OBJECT => self.read_object(memory, share_context),
            TAG_ARRAY => self.read_array(memory, share_context),
            tag => Err(invalid_data(format!("unknown value tag {tag}"))),
        }
    }

    fn read_object(
        &mut self,
        memory: &mut dyn TableMemory,
        share_context: Option<&PersistentShareContext>,
    ) -> PersistentValueResult<Value> {
        let object_ref = memory
            .create_object_ref()
            .map_err(table_memory_error("create object"))?;
        let entry_count = self.read_len_bounded("object entry", MAX_PERSISTENT_TABLE_ENTRIES)?;
        for _ in 0..entry_count {
            let key = self.read_value(memory, share_context)?;
            let value = self.read_value(memory, share_context)?;
            memory
                .set_table_field(TableRef::from(object_ref), key, value)
                .map_err(table_memory_error("set object field"))?;
        }
        Ok(Value::from(object_ref))
    }

    fn read_array(
        &mut self,
        memory: &mut dyn TableMemory,
        share_context: Option<&PersistentShareContext>,
    ) -> PersistentValueResult<Value> {
        let capacity = self.read_len_bounded("array", MAX_PERSISTENT_TABLE_ENTRIES)?;
        let array_ref = memory
            .create_array_ref_with_capacity(capacity)
            .map_err(table_memory_error("create array"))?;
        let entry_count = self.read_len_bounded("array entry", MAX_PERSISTENT_TABLE_ENTRIES)?;
        for _ in 0..entry_count {
            let key = self.read_value(memory, share_context)?;
            let value = self.read_value(memory, share_context)?;
            memory
                .set_table_field(TableRef::from(array_ref), key, value)
                .map_err(table_memory_error("set array field"))?;
        }
        Ok(Value::from(array_ref))
    }

    fn read_share_envelope(&mut self) -> PersistentValueResult<ShareEnvelope> {
        let version = self.read_u8()?;
        if version != SHARE_ENVELOPE_VERSION {
            return Err(invalid_data(format!(
                "unsupported persistent share envelope version {version}"
            )));
        }

        let protocol_name = self.read_string()?;
        let curve = self.read_string()?;
        let field = self.read_string()?;

        Ok(ShareEnvelope {
            protocol_name,
            curve,
            field,
            node_identity: DurableIdentityDigest::from_bytes(self.read_digest()?),
            n_parties: self.read_len("party count")?,
            threshold: self.read_len("threshold")?,
            key_id_digest: self.read_digest()?,
            payload_digest: self.read_digest()?,
            commitment_digest: self.read_optional_digest()?,
        })
    }

    fn read_share_type(&mut self) -> PersistentValueResult<ShareType> {
        match self.read_u8()? {
            SHARE_TYPE_SECRET_FIELD => Ok(ShareType::SecretField),
            SHARE_TYPE_SECRET_INT => {
                let bit_length = self.read_len("secret integer bit")?;
                ShareType::try_secret_int(bit_length)
                    .map_err(|error| invalid_data(error.to_string()))
            }
            SHARE_TYPE_SECRET_UINT => {
                let bit_length = self.read_len("secret unsigned integer bit")?;
                ShareType::try_secret_uint(bit_length)
                    .map_err(|error| invalid_data(error.to_string()))
            }
            SHARE_TYPE_SECRET_FIXED_POINT => {
                let total_bits = self.read_len("fixed-point total bit")?;
                let fractional_bits = self.read_len("fixed-point fractional bit")?;
                ShareType::try_secret_fixed_point_from_bits(total_bits, fractional_bits)
                    .map_err(|error| invalid_data(error.to_string()))
            }
            tag => Err(invalid_data(format!("unknown share type tag {tag}"))),
        }
    }

    fn read_share_data(&mut self) -> PersistentValueResult<ShareData> {
        match self.read_u8()? {
            SHARE_DATA_OPAQUE => Ok(ShareData::Opaque(self.read_bytes()?.to_vec().into())),
            SHARE_DATA_FELDMAN => {
                let data = self.read_bytes()?.to_vec();
                let commitment_count =
                    self.read_len_bounded("Feldman commitment", MAX_PERSISTENT_COMMITMENTS)?;
                let mut commitments = Vec::with_capacity(commitment_count);
                for _ in 0..commitment_count {
                    commitments.push(self.read_bytes()?.to_vec());
                }
                Ok(ShareData::Feldman {
                    data: data.into(),
                    commitments: commitments.into(),
                })
            }
            tag => Err(invalid_data(format!("unknown share data tag {tag}"))),
        }
    }

    fn read_string(&mut self) -> PersistentValueResult<String> {
        let bytes = self.read_bytes()?;
        String::from_utf8(bytes.to_vec()).map_err(|error| invalid_data(error.to_string()))
    }

    fn read_bytes(&mut self) -> PersistentValueResult<&[u8]> {
        let len = self.read_len_bounded("byte", MAX_PERSISTENT_BLOB_BYTES)?;
        self.read_exact(len)
    }

    fn read_len(&mut self, label: &'static str) -> PersistentValueResult<usize> {
        let len = self.read_u64()?;
        usize::try_from(len).map_err(|_| PersistentValueError::LengthOverflow { label, len })
    }

    fn read_len_bounded(
        &mut self,
        label: &'static str,
        limit: usize,
    ) -> PersistentValueResult<usize> {
        let len = self.read_len(label)?;
        if len > limit {
            return Err(PersistentValueError::LimitExceeded {
                label,
                count: len,
                limit,
            });
        }
        Ok(len)
    }

    fn read_i16(&mut self) -> PersistentValueResult<i16> {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(self.read_exact(2)?);
        Ok(i16::from_le_bytes(bytes))
    }

    fn read_i32(&mut self) -> PersistentValueResult<i32> {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(self.read_exact(4)?);
        Ok(i32::from_le_bytes(bytes))
    }

    fn read_i64(&mut self) -> PersistentValueResult<i64> {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(self.read_exact(8)?);
        Ok(i64::from_le_bytes(bytes))
    }

    fn read_u8(&mut self) -> PersistentValueResult<u8> {
        let bytes = self.read_exact(1)?;
        Ok(bytes[0])
    }

    fn read_u16(&mut self) -> PersistentValueResult<u16> {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(self.read_exact(2)?);
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_u32(&mut self) -> PersistentValueResult<u32> {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(self.read_exact(4)?);
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u64(&mut self) -> PersistentValueResult<u64> {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(self.read_exact(8)?);
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_digest(&mut self) -> PersistentValueResult<[u8; 32]> {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(self.read_exact(32)?);
        Ok(digest)
    }

    fn read_optional_digest(&mut self) -> PersistentValueResult<Option<[u8; 32]>> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.read_digest()?)),
            value => Err(invalid_data(format!(
                "invalid optional digest marker {value}"
            ))),
        }
    }

    fn read_exact(&mut self, len: usize) -> PersistentValueResult<&[u8]> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or_else(|| invalid_data(format!("read of {len} bytes overflows input cursor")))?;
        let bytes = self.bytes.get(self.cursor..end).ok_or_else(|| {
            invalid_data(format!(
                "expected {len} bytes at offset {}, but input ended",
                self.cursor
            ))
        })?;
        self.cursor = end;
        Ok(bytes)
    }

    fn is_empty(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

struct ShareEnvelope {
    protocol_name: String,
    curve: String,
    field: String,
    node_identity: DurableIdentityDigest,
    n_parties: usize,
    threshold: usize,
    key_id_digest: [u8; 32],
    payload_digest: [u8; 32],
    commitment_digest: Option<[u8; 32]>,
}

impl ShareEnvelope {
    fn validate(
        self,
        context: Option<&PersistentShareContext>,
        share_data: &ShareData,
    ) -> PersistentValueResult<()> {
        let context = context.ok_or(PersistentValueError::MissingShareContext)?;
        self.require_str("backend", &context.protocol_name, &self.protocol_name)?;
        self.require_str("curve", &context.curve, &self.curve)?;
        self.require_str("field", &context.field, &self.field)?;
        self.require_identity("node_identity", context.node_identity, self.node_identity)?;
        self.require_usize("n_parties", context.n_parties, self.n_parties)?;
        self.require_usize("threshold", context.threshold, self.threshold)?;
        if self.key_id_digest != context.key_id_digest {
            return Err(PersistentValueError::ShareDigestMismatch { field: "key_id" });
        }
        if self.payload_digest != digest_bytes(share_data.as_bytes()) {
            return Err(PersistentValueError::ShareDigestMismatch {
                field: "share_payload",
            });
        }
        if self.commitment_digest != share_commitment_digest(share_data)? {
            return Err(PersistentValueError::ShareDigestMismatch {
                field: "commitment",
            });
        }
        Ok(())
    }

    fn require_str(
        &self,
        field: &'static str,
        expected: &str,
        actual: &str,
    ) -> PersistentValueResult<()> {
        if expected == actual {
            return Ok(());
        }
        Err(PersistentValueError::ShareContextMismatch {
            field,
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        })
    }

    fn require_usize(
        &self,
        field: &'static str,
        expected: usize,
        actual: usize,
    ) -> PersistentValueResult<()> {
        if expected == actual {
            return Ok(());
        }
        Err(PersistentValueError::ShareContextMismatch {
            field,
            expected: expected.to_string(),
            actual: actual.to_string(),
        })
    }

    fn require_identity(
        &self,
        field: &'static str,
        expected: DurableIdentityDigest,
        actual: DurableIdentityDigest,
    ) -> PersistentValueResult<()> {
        if expected == actual {
            return Ok(());
        }
        Err(PersistentValueError::ShareContextMismatch {
            field,
            expected: expected.to_string(),
            actual: actual.to_string(),
        })
    }
}

fn table_memory_error(
    operation: &'static str,
) -> impl FnOnce(TableMemoryError) -> PersistentValueError {
    move |error| PersistentValueError::TableMemory {
        operation,
        reason: error.to_string(),
    }
}

fn invalid_data(reason: impl Into<String>) -> PersistentValueError {
    PersistentValueError::InvalidData {
        reason: reason.into(),
    }
}

fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn share_commitment_digest(share_data: &ShareData) -> PersistentValueResult<Option<[u8; 32]>> {
    match share_data {
        ShareData::Opaque(_) => Ok(None),
        ShareData::Feldman { commitments, .. } => {
            let commitment = commitments
                .first()
                .ok_or_else(|| invalid_data("Feldman share is missing commitment[0]"))?;
            Ok(Some(digest_bytes(commitment)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_value, decode_value_with_context, encode_value, encode_value_with_context,
        PersistentShareContext, PersistentValueContext, PersistentValueError, MAGIC,
        MAX_PERSISTENT_COMMITMENTS, MAX_PERSISTENT_TABLE_ENTRIES, SHARE_DATA_FELDMAN,
        SHARE_ENVELOPE_VERSION, SHARE_TYPE_SECRET_INT, TAG_ARRAY, TAG_SHARE,
    };
    use crate::net::mpc_engine::DurableIdentityDigest;
    use std::sync::Arc;
    use stoffel_vm_types::core_types::{
        Closure, ObjectRef, ObjectStore, ShareData, ShareType, TableMemory, TableRef, Upvalue,
        Value, F64,
    };

    fn test_context(key: &[u8]) -> PersistentValueContext {
        PersistentValueContext::with_share_context(PersistentShareContext::new(
            "avss-mpc",
            "bls12-381",
            "bls12-381-fr",
            DurableIdentityDigest::from_public_key_bytes(b"test node"),
            5,
            1,
            key,
        ))
    }

    #[test]
    fn primitive_and_share_values_round_trip() {
        let mut memory = ObjectStore::new();
        let context = test_context(b"value");
        let values = [
            Value::Share(
                ShareType::SecretField,
                ShareData::Opaque(vec![1, 2, 3].into()),
            ),
            Value::Unit,
            Value::I64(-42),
            Value::I32(-32),
            Value::I16(-16),
            Value::I8(-8),
            Value::U8(8),
            Value::U16(16),
            Value::U32(32),
            Value::U64(42),
            Value::Float(F64::new(1.25)),
            Value::Bool(true),
            Value::String("stored".to_owned()),
            Value::Share(
                ShareType::secret_fixed_point_from_bits(64, 16),
                ShareData::Feldman {
                    data: vec![1, 2, 3].into(),
                    commitments: vec![vec![4, 5], vec![6]].into(),
                },
            ),
        ];

        for value in values {
            let encoded = encode_value_with_context(&value, &mut memory, Some(&context))
                .expect("encode value");
            let decoded = decode_value_with_context(&encoded, &mut memory, Some(&context))
                .expect("decode value");
            assert_eq!(decoded, value);
        }
    }

    #[test]
    fn closures_are_rejected() {
        let mut memory = ObjectStore::new();
        let closure = Value::Closure(Arc::new(Closure::new(
            "inner",
            vec![Upvalue::new("x", Value::I64(7))],
        )));

        assert_eq!(
            encode_value(&closure, &mut memory).expect_err("closure rejected"),
            PersistentValueError::UnsupportedValue {
                type_name: "function"
            }
        );
    }

    #[test]
    fn object_and_array_values_round_trip_through_table_memory() {
        let mut memory = ObjectStore::new();
        let context = test_context(b"object");
        let array_ref = memory.create_array_ref().expect("array");
        memory
            .set_table_field(TableRef::from(array_ref), Value::I64(0), Value::U8(10))
            .expect("array index 0");
        memory
            .set_table_field(
                TableRef::from(array_ref),
                Value::String("kind".to_owned()),
                Value::String("bytes".to_owned()),
            )
            .expect("array extra field");

        let object_ref = memory.create_object_ref().expect("object");
        memory
            .set_table_field(
                TableRef::from(object_ref),
                Value::String("payload".to_owned()),
                Value::from(array_ref),
            )
            .expect("object payload");
        memory
            .set_table_field(
                TableRef::from(object_ref),
                Value::String("share".to_owned()),
                Value::Share(
                    ShareType::secret_int(64),
                    ShareData::Opaque(vec![9, 8, 7].into()),
                ),
            )
            .expect("object share");

        let encoded =
            encode_value_with_context(&Value::from(object_ref), &mut memory, Some(&context))
                .expect("encode object");
        let decoded = decode_value_with_context(&encoded, &mut memory, Some(&context))
            .expect("decode object");
        let decoded_object = ObjectRef::from_value(&decoded).expect("decoded object");
        assert_eq!(
            memory
                .read_table_field(
                    TableRef::from(decoded_object),
                    &Value::String("share".to_owned())
                )
                .expect("read share"),
            Some(Value::Share(
                ShareType::secret_int(64),
                ShareData::Opaque(vec![9, 8, 7].into())
            ))
        );

        let decoded_array = match memory
            .read_table_field(
                TableRef::from(decoded_object),
                &Value::String("payload".to_owned()),
            )
            .expect("read payload")
        {
            Some(Value::Array(array_ref)) => array_ref,
            other => panic!("expected decoded array, got {other:?}"),
        };

        assert_eq!(
            memory
                .read_table_field(TableRef::from(decoded_array), &Value::I64(0))
                .expect("read array index"),
            Some(Value::U8(10))
        );
        assert_eq!(
            memory
                .read_table_field(
                    TableRef::from(decoded_array),
                    &Value::String("kind".to_owned())
                )
                .expect("read array extra field"),
            Some(Value::String("bytes".to_owned()))
        );
    }

    #[test]
    fn shares_require_matching_persistence_context() {
        let mut memory = ObjectStore::new();
        let share = Value::Share(
            ShareType::secret_int(64),
            ShareData::Feldman {
                data: vec![1, 2, 3].into(),
                commitments: vec![vec![4, 5, 6]].into(),
            },
        );
        let context = test_context(b"share-key");

        assert_eq!(
            encode_value(&share, &mut memory).expect_err("missing context"),
            PersistentValueError::MissingShareContext
        );

        let encoded = encode_value_with_context(&share, &mut memory, Some(&context))
            .expect("encode with context");
        let wrong_key = test_context(b"other-key");
        assert_eq!(
            decode_value_with_context(&encoded, &mut memory, Some(&wrong_key))
                .expect_err("key mismatch"),
            PersistentValueError::ShareDigestMismatch { field: "key_id" }
        );
    }

    #[test]
    fn noncurrent_share_envelopes_are_rejected_before_decoding_payload() {
        let mut memory = ObjectStore::new();
        let context = test_context(b"share-key");
        for version in (0..SHARE_ENVELOPE_VERSION).chain([SHARE_ENVELOPE_VERSION + 1, u8::MAX]) {
            let mut bytes = Vec::from(MAGIC.as_slice());
            bytes.extend_from_slice(&[TAG_SHARE, version]);
            assert_eq!(
                decode_value_with_context(&bytes, &mut memory, Some(&context)),
                Err(PersistentValueError::InvalidData {
                    reason: format!("unsupported persistent share envelope version {version}")
                })
            );
        }
    }

    #[test]
    fn decode_rejects_large_array_capacity() {
        let mut memory = ObjectStore::new();
        let mut bytes = Vec::from(MAGIC.as_slice());
        bytes.push(TAG_ARRAY);
        bytes.extend_from_slice(&((MAX_PERSISTENT_TABLE_ENTRIES as u64) + 1).to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());

        assert_eq!(
            decode_value(&bytes, &mut memory).expect_err("large array rejected"),
            PersistentValueError::LimitExceeded {
                label: "array",
                count: MAX_PERSISTENT_TABLE_ENTRIES + 1,
                limit: MAX_PERSISTENT_TABLE_ENTRIES,
            }
        );
    }

    #[test]
    fn decode_rejects_large_commitment_count() {
        let mut memory = ObjectStore::new();
        let context = test_context(b"share-key");
        let mut bytes = Vec::from(MAGIC.as_slice());
        bytes.push(TAG_SHARE);
        bytes.push(SHARE_ENVELOPE_VERSION);
        write_test_string(&mut bytes, "avss-mpc");
        write_test_string(&mut bytes, "bls12-381");
        write_test_string(&mut bytes, "bls12-381-fr");
        bytes.extend_from_slice(
            &DurableIdentityDigest::from_public_key_bytes(b"test node").as_bytes(),
        );
        bytes.extend_from_slice(&5u64.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(blake3::hash(b"share-key").as_bytes());
        bytes.extend_from_slice(blake3::hash(&[]).as_bytes());
        bytes.push(0);
        bytes.push(SHARE_TYPE_SECRET_INT);
        bytes.extend_from_slice(&64u64.to_le_bytes());
        bytes.push(SHARE_DATA_FELDMAN);
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&((MAX_PERSISTENT_COMMITMENTS as u64) + 1).to_le_bytes());

        assert_eq!(
            decode_value_with_context(&bytes, &mut memory, Some(&context))
                .expect_err("large commitment count rejected"),
            PersistentValueError::LimitExceeded {
                label: "Feldman commitment",
                count: MAX_PERSISTENT_COMMITMENTS + 1,
                limit: MAX_PERSISTENT_COMMITMENTS,
            }
        );
    }

    fn write_test_string(bytes: &mut Vec<u8>, value: &str) {
        bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }

    #[test]
    fn cyclic_tables_are_rejected() {
        let mut memory = ObjectStore::new();
        let object_ref = memory.create_object_ref().expect("object");
        memory
            .set_table_field(
                TableRef::from(object_ref),
                Value::String("self".to_owned()),
                Value::from(object_ref),
            )
            .expect("cycle");

        let error =
            encode_value(&Value::from(object_ref), &mut memory).expect_err("cycle rejected");
        assert_eq!(
            error,
            PersistentValueError::CyclicValue {
                type_name: "object",
                id: object_ref.id()
            }
        );
    }
}
