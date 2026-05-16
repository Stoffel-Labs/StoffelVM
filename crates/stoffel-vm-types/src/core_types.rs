//! # Core Types for StoffelVM
//!
//! This module defines the fundamental types used throughout the StoffelVM.
//! It includes the value system, object model, and storage mechanisms that
//! form the foundation of the VM's runtime environment.
//!
//! The VM supports various value types:
//! - Primitive types: Int, Float, Bool, String, Unit
//! - Complex types: Object, Array, Closure
//! - Foreign types: References to Rust objects exposed to the VM
//!
//! The module also provides storage systems for objects, arrays, and foreign objects,
//! as well as the upvalue system for closures.

use parking_lot::Mutex;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use std::any::Any;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

const ARRAY_DENSE_INLINE_CAPACITY: usize = 16;
const ARRAY_DENSE_INDEX_LIMIT: usize = 32;
const TABLE_DISPLAY_ENTRY_LIMIT: usize = 10;

pub type TableMemoryResult<T> = Result<T, TableMemoryError>;

/// Typed error surface for VM table memory implementations.
///
/// The in-memory [`ObjectStore`] is only one implementation of this contract.
/// Keeping allocation, lookup, and index failures structured makes it easier
/// for future backends such as Path-ORAM to preserve operational detail without
/// forcing the VM to parse error strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableMemoryError {
    Backend(String),
    ObjectNotFound { id: usize },
    ArrayNotFound { id: usize },
    ExpectedTableValue,
    ExpectedObjectValue,
    ExpectedArrayValue,
    AllocatorOverflow { allocator: &'static str },
    ArrayIndexDoesNotFitHost { index: i64 },
    ArrayLengthOverflow { index: i64 },
    VmIntegerRangeExceeded { label: &'static str, value: usize },
    ArrayPushLengthOverflow,
}

impl TableMemoryError {
    pub fn backend(message: impl Into<String>) -> Self {
        Self::Backend(message.into())
    }
}

impl fmt::Display for TableMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TableMemoryError::Backend(message) => write!(f, "{message}"),
            TableMemoryError::ObjectNotFound { id } => {
                write!(f, "Object with ID {id} not found")
            }
            TableMemoryError::ArrayNotFound { id } => write!(f, "Array with ID {id} not found"),
            TableMemoryError::ExpectedTableValue => write!(f, "Expected object or array"),
            TableMemoryError::ExpectedObjectValue => write!(f, "Expected object"),
            TableMemoryError::ExpectedArrayValue => write!(f, "Expected array"),
            TableMemoryError::AllocatorOverflow { allocator } => {
                write!(f, "{allocator} ID allocator overflowed")
            }
            TableMemoryError::ArrayIndexDoesNotFitHost { index } => {
                write!(f, "Array index {index} does not fit host usize")
            }
            TableMemoryError::ArrayLengthOverflow { index } => {
                write!(f, "Array index {index} overflows array length")
            }
            TableMemoryError::VmIntegerRangeExceeded { label, value } => {
                write!(f, "{label} {value} exceeds VM integer range")
            }
            TableMemoryError::ArrayPushLengthOverflow => {
                write!(f, "Array length overflow while pushing values")
            }
        }
    }
}

impl std::error::Error for TableMemoryError {}

impl From<String> for TableMemoryError {
    fn from(message: String) -> Self {
        TableMemoryError::backend(message)
    }
}

impl From<&str> for TableMemoryError {
    fn from(message: &str) -> Self {
        TableMemoryError::backend(message)
    }
}

impl From<TableMemoryError> for String {
    fn from(error: TableMemoryError) -> Self {
        error.to_string()
    }
}

/// A wrapper around f64 that implements Eq and Hash using bit representation.
/// This allows f64 values to be used in contexts requiring these traits.
/// NaN values are handled by treating all NaNs as equal.
#[derive(Clone, Copy, Default)]
pub struct F64(pub f64);

impl F64 {
    /// Create a new F64 wrapper
    pub fn new(value: f64) -> Self {
        F64(value)
    }

    /// Get the inner f64 value
    pub fn value(&self) -> f64 {
        self.0
    }

    /// Convert to bits for comparison, normalizing NaN values
    fn to_bits_normalized(self) -> u64 {
        if self.0.is_nan() {
            // All NaN values map to the same bit pattern
            f64::NAN.to_bits()
        } else if self.0 == 0.0 {
            // Treat -0.0 and 0.0 as equal
            0u64
        } else {
            self.0.to_bits()
        }
    }
}

impl PartialEq for F64 {
    fn eq(&self, other: &Self) -> bool {
        self.to_bits_normalized() == other.to_bits_normalized()
    }
}

impl Eq for F64 {}

impl Hash for F64 {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_bits_normalized().hash(state);
    }
}

impl fmt::Debug for F64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for F64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<f64> for F64 {
    fn from(value: f64) -> Self {
        F64(value)
    }
}

impl From<F64> for f64 {
    fn from(value: F64) -> Self {
        value.0
    }
}

impl std::ops::Add for F64 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        F64(self.0 + rhs.0)
    }
}

impl std::ops::Sub for F64 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        F64(self.0 - rhs.0)
    }
}

impl std::ops::Mul for F64 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        F64(self.0 * rhs.0)
    }
}

impl std::ops::Div for F64 {
    type Output = Self;
    fn div(self, rhs: Self) -> Self::Output {
        F64(self.0 / rhs.0)
    }
}

impl std::ops::Neg for F64 {
    type Output = Self;
    fn neg(self) -> Self::Output {
        F64(-self.0)
    }
}

impl PartialOrd for F64 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

/// Represents an array in the VM
///
/// Arrays in StoffelVM are 0-indexed and support both numeric indices
/// and arbitrary keys (similar to JavaScript arrays or Lua tables).
/// The implementation uses a hybrid approach:
/// - Small arrays use a contiguous SmallVec for efficient access
/// - Larger indices and non-numeric keys use a hash map
/// - A length hint is maintained for O(1) length queries (stores len = last_index + 1)
#[derive(Debug, Clone)]
pub struct Array {
    /// Contiguous storage for small numeric array indices.
    elements: SmallVec<[Value; ARRAY_DENSE_INLINE_CAPACITY]>,
    /// Storage for large indices and non-numeric keys
    extra_fields: FxHashMap<Value, Value>,
    /// Cached length for O(1) access
    length_hint: usize,
}

impl Array {
    pub fn new() -> Self {
        Array {
            elements: SmallVec::new(),
            extra_fields: FxHashMap::default(),
            length_hint: 0,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Array {
            // This is a VM-visible hint, not permission to reserve arbitrary
            // host memory. Grow the dense part on real writes instead.
            elements: SmallVec::with_capacity(capacity.min(ARRAY_DENSE_INLINE_CAPACITY)),
            extra_fields: FxHashMap::default(),
            length_hint: 0,
        }
    }

    pub fn get(&self, key: &Value) -> Option<&Value> {
        match key {
            // 0-indexed arrays: Valid numeric keys are 0..<length
            Value::I64(idx) if *idx >= 0 => {
                let Ok(idx_usize) = usize::try_from(*idx) else {
                    return self.extra_fields.get(key);
                };
                if idx_usize < self.length_hint {
                    // Check if in dense part or sparse part (extra_fields).
                    if idx_usize < self.elements.len() {
                        Some(&self.elements[idx_usize])
                    } else {
                        self.extra_fields.get(key)
                    }
                } else {
                    self.extra_fields.get(key)
                }
            }
            _ => self.extra_fields.get(key),
        }
    }

    pub fn try_set(&mut self, key: Value, value: Value) -> TableMemoryResult<()> {
        match key {
            // 0-indexed arrays: only indices >= 0 are valid for the dense part
            Value::I64(idx) if idx >= 0 => {
                let idx_usize = usize::try_from(idx)
                    .map_err(|_| TableMemoryError::ArrayIndexDoesNotFitHost { index: idx })?;
                let new_len = idx_usize
                    .checked_add(1)
                    .ok_or(TableMemoryError::ArrayLengthOverflow { index: idx })?;
                i64::try_from(new_len).map_err(|_| TableMemoryError::VmIntegerRangeExceeded {
                    label: "Array length",
                    value: new_len,
                })?;

                // Update length_hint to the highest occupied numeric index + 1
                self.length_hint = self.length_hint.max(new_len);
                if idx_usize < ARRAY_DENSE_INDEX_LIMIT {
                    if idx_usize >= self.elements.len() {
                        self.elements.resize(idx_usize + 1, Value::Unit);
                    }
                    self.elements[idx_usize] = value;
                } else {
                    self.extra_fields.insert(Value::I64(idx), value);
                }
            }
            _ => {
                self.extra_fields.insert(key, value);
            }
        }
        Ok(())
    }

    pub fn try_push_values(&mut self, values: &[Value]) -> TableMemoryResult<usize> {
        let start = self.length_hint;
        for (offset, value) in values.iter().enumerate() {
            let idx = start
                .checked_add(offset)
                .ok_or(TableMemoryError::ArrayPushLengthOverflow)?;
            let idx_i64 =
                i64::try_from(idx).map_err(|_| TableMemoryError::VmIntegerRangeExceeded {
                    label: "Array index",
                    value: idx,
                })?;
            let new_len = idx
                .checked_add(1)
                .ok_or(TableMemoryError::ArrayLengthOverflow { index: idx_i64 })?;
            i64::try_from(new_len).map_err(|_| TableMemoryError::VmIntegerRangeExceeded {
                label: "Array length",
                value: new_len,
            })?;

            self.length_hint = self.length_hint.max(new_len);
            if idx < ARRAY_DENSE_INDEX_LIMIT {
                if idx >= self.elements.len() {
                    self.elements.resize(idx + 1, Value::Unit);
                }
                self.elements[idx] = value.clone();
            } else {
                self.extra_fields.insert(Value::I64(idx_i64), value.clone());
            }
        }

        Ok(self.length_hint)
    }

    pub fn length(&self) -> usize {
        self.length_hint
    }

    /// Format the array contents for display with a depth limit to prevent infinite recursion.
    /// Returns a string like `[1, 2, 3]` for simple arrays.
    pub fn format_contents(&self, memory: &dyn TableMemoryView, max_depth: usize) -> String {
        if max_depth == 0 {
            return format!("[...{} elements]", self.length_hint);
        }

        let mut parts = Vec::with_capacity(self.length_hint.min(TABLE_DISPLAY_ENTRY_LIMIT));
        let truncated = self.length_hint > TABLE_DISPLAY_ENTRY_LIMIT;
        let display_count = self.length_hint.min(TABLE_DISPLAY_ENTRY_LIMIT);

        for i in 0..display_count {
            if let Some(val) = self.get(&Value::I64(i as i64)) {
                parts.push(val.format_with_memory(memory, max_depth - 1));
            } else {
                parts.push("()".to_string());
            }
        }

        if truncated {
            format!(
                "[{}, ...({} more)]",
                parts.join(", "),
                self.length_hint - TABLE_DISPLAY_ENTRY_LIMIT
            )
        } else {
            format!("[{}]", parts.join(", "))
        }
    }
}

impl Default for Array {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents an upvalue - a variable captured from an outer scope
///
/// Upvalues are the mechanism that enables closures to capture and maintain
/// references to variables from their enclosing scopes, even after those
/// scopes have exited. This is essential for implementing true lexical scoping.
///
/// When a function references a variable from an outer scope, that variable
/// is tracked as an upvalue, ensuring it remains accessible throughout the
/// lifetime of any closures that reference it.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Upvalue {
    /// Name of the captured variable
    name: String,
    /// Value of the captured variable
    value: Value,
}

impl Upvalue {
    pub fn new(name: impl Into<String>, value: Value) -> Self {
        Self {
            name: name.into(),
            value,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn value_mut(&mut self) -> &mut Value {
        &mut self.value
    }

    pub fn set_value(&mut self, value: Value) {
        self.value = value;
    }
}

/// Represents a closure - a function with its captured environment
///
/// Closures combine a function with the variables it captures from its
/// surrounding lexical environment. This allows functions to maintain access
/// to variables from their defining scope, even after that scope has exited.
///
/// The VM implements true lexical scoping through this upvalue system, where
/// multiple closures can share references to the same captured variables.
#[derive(Clone)]
pub struct Closure {
    /// Reference to the base function (by name)
    function_id: String,
    /// Variables captured from outer scopes
    upvalues: Vec<Upvalue>,
}

impl Closure {
    pub fn new(function_id: impl Into<String>, upvalues: Vec<Upvalue>) -> Self {
        Self {
            function_id: function_id.into(),
            upvalues,
        }
    }

    pub fn function_id(&self) -> &str {
        &self.function_id
    }

    pub fn upvalues(&self) -> &[Upvalue] {
        &self.upvalues
    }

    pub fn upvalues_mut(&mut self) -> &mut [Upvalue] {
        &mut self.upvalues
    }

    pub fn replace_upvalues(&mut self, upvalues: Vec<Upvalue>) {
        self.upvalues = upvalues;
    }
}

impl PartialEq for Closure {
    fn eq(&self, other: &Self) -> bool {
        self.function_id == other.function_id && self.upvalues == other.upvalues
    }
}

impl Eq for Closure {}

impl std::hash::Hash for Closure {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.function_id.hash(state);
        self.upvalues.hash(state);
    }
}

/// Default bit-length used when creating secret integers in the VM.
pub const DEFAULT_SECRET_INT_BITS: usize = 64;
/// Bit-length reserved for boolean secrets (0 or 1).
pub const BOOLEAN_SECRET_INT_BITS: usize = 1;
/// Default total bits for fixed-point representations.
pub const DEFAULT_FIXED_POINT_TOTAL_BITS: usize = 64;
/// Default fractional bits for fixed-point representations.
pub const DEFAULT_FIXED_POINT_FRACTIONAL_BITS: usize = 16;

/// VM-level fixed-point precision metadata.
///
/// This deliberately lives in `stoffel-vm-types` instead of an MPC backend crate
/// so bytecode/value metadata remains independent from the protocol selected at
/// runtime. Backends can map this shape onto their own fixed-point encodings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FixedPointPrecision {
    total_bits: usize,
    fractional_bits: usize,
}

impl FixedPointPrecision {
    pub fn new(total_bits: usize, fractional_bits: usize) -> Self {
        Self::try_new(total_bits, fractional_bits).expect(
            "fixed-point precision requires total_bits > 0 and fractional_bits < total_bits",
        )
    }

    const fn from_validated(total_bits: usize, fractional_bits: usize) -> Self {
        Self {
            total_bits,
            fractional_bits,
        }
    }

    pub const fn total_bits(self) -> usize {
        self.total_bits
    }

    pub const fn fractional_bits(self) -> usize {
        self.fractional_bits
    }

    /// Compatibility accessor for MPC fixed-point terminology.
    pub const fn k(self) -> usize {
        self.total_bits()
    }

    /// Compatibility accessor for MPC fixed-point terminology.
    pub const fn f(self) -> usize {
        self.fractional_bits()
    }
}

fn default_fixed_point_precision() -> FixedPointPrecision {
    FixedPointPrecision::new(
        DEFAULT_FIXED_POINT_TOTAL_BITS,
        DEFAULT_FIXED_POINT_FRACTIONAL_BITS,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareTypeError {
    SecretIntBitLengthZero,
    FixedPointTotalBitsZero,
    FixedPointFractionalBitsOutOfRange {
        total_bits: usize,
        fractional_bits: usize,
    },
}

pub type ShareTypeResult<T> = Result<T, ShareTypeError>;

impl fmt::Display for ShareTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShareTypeError::SecretIntBitLengthZero => {
                write!(f, "bit_length must be a positive integer")
            }
            ShareTypeError::FixedPointTotalBitsZero => {
                write!(f, "total_bits must be a positive integer")
            }
            ShareTypeError::FixedPointFractionalBitsOutOfRange { .. } => {
                write!(f, "frac_bits must be less than total_bits")
            }
        }
    }
}

impl std::error::Error for ShareTypeError {}

impl From<ShareTypeError> for String {
    fn from(error: ShareTypeError) -> Self {
        error.to_string()
    }
}

impl FixedPointPrecision {
    pub fn try_new(total_bits: usize, fractional_bits: usize) -> ShareTypeResult<Self> {
        if total_bits == 0 {
            return Err(ShareTypeError::FixedPointTotalBitsZero);
        }
        if fractional_bits >= total_bits {
            return Err(ShareTypeError::FixedPointFractionalBitsOutOfRange {
                total_bits,
                fractional_bits,
            });
        }
        Ok(Self::from_validated(total_bits, fractional_bits))
    }
}

/// Enum to represent the underlying type of a secret share
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ShareType {
    /// Secure integer shares (mirrors `SecretInt` in mpc-protocols)
    SecretInt { bit_length: usize },
    /// Secure fixed-point shares (mirrors `SecretFixedPoint` in mpc-protocols)
    SecretFixedPoint { precision: FixedPointPrecision },
}

impl ShareType {
    pub fn try_secret_int(bit_length: usize) -> ShareTypeResult<Self> {
        if bit_length == 0 {
            return Err(ShareTypeError::SecretIntBitLengthZero);
        }
        Ok(ShareType::SecretInt { bit_length })
    }

    pub fn secret_int(bit_length: usize) -> Self {
        Self::try_secret_int(bit_length).expect("secret integers require a positive bit length")
    }

    pub fn boolean() -> Self {
        ShareType::SecretInt {
            bit_length: BOOLEAN_SECRET_INT_BITS,
        }
    }

    pub fn default_secret_int() -> Self {
        ShareType::SecretInt {
            bit_length: DEFAULT_SECRET_INT_BITS,
        }
    }

    pub fn try_secret_fixed_point_from_bits(
        total_bits: usize,
        fractional_bits: usize,
    ) -> ShareTypeResult<Self> {
        Ok(ShareType::SecretFixedPoint {
            precision: FixedPointPrecision::try_new(total_bits, fractional_bits)?,
        })
    }

    pub fn secret_fixed_point_from_bits(total_bits: usize, fractional_bits: usize) -> Self {
        Self::try_secret_fixed_point_from_bits(total_bits, fractional_bits)
            .expect("fixed-point shares require total_bits > 0 and fractional_bits < total_bits")
    }

    pub fn default_secret_fixed_point() -> Self {
        ShareType::SecretFixedPoint {
            precision: default_fixed_point_precision(),
        }
    }

    pub fn bit_length(&self) -> Option<usize> {
        match self {
            ShareType::SecretInt { bit_length } => Some(*bit_length),
            _ => None,
        }
    }

    pub fn precision(&self) -> Option<FixedPointPrecision> {
        match self {
            ShareType::SecretFixedPoint { precision } => Some(*precision),
            _ => None,
        }
    }

    pub fn is_boolean(&self) -> bool {
        matches!(
            self,
            ShareType::SecretInt {
                bit_length: BOOLEAN_SECRET_INT_BITS
            }
        )
    }
}

impl Eq for ShareType {}

impl Hash for ShareType {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            ShareType::SecretInt { bit_length } => {
                0u8.hash(state);
                bit_length.hash(state);
            }
            ShareType::SecretFixedPoint { precision } => {
                1u8.hash(state);
                precision.k().hash(state);
                precision.f().hash(state);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClearShareValue {
    Integer(i64),
    FixedPoint(F64),
    Boolean(bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClearShareInput {
    share_type: ShareType,
    value: ClearShareValue,
}

impl ClearShareInput {
    pub const fn new(share_type: ShareType, value: ClearShareValue) -> Self {
        Self { share_type, value }
    }

    pub const fn share_type(self) -> ShareType {
        self.share_type
    }

    pub const fn value(self) -> ClearShareValue {
        self.value
    }

    pub const fn into_parts(self) -> (ShareType, ClearShareValue) {
        (self.share_type, self.value)
    }
}

/// Backing data for a secret share, distinguishing opaque bytes from Feldman
/// shares that carry extractable commitments.
///
/// When the AVSS backend produces a `FeldmanShamirShare`, the commitments
/// (where `commitment[0] = g^secret` is the public key) are stored alongside
/// the serialized share bytes. This allows bytecode programs to access
/// commitments via `Share.get_commitment(share, index)`.
///
/// The HoneyBadger backend produces `Opaque` shares (no commitments).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShareDataFormat {
    Opaque,
    Feldman,
}

impl ShareDataFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            ShareDataFormat::Opaque => "opaque",
            ShareDataFormat::Feldman => "feldman",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum ShareData {
    /// Opaque share bytes (e.g., HoneyBadger RobustShare)
    Opaque(Vec<u8>),
    /// Feldman share with extractable commitments (AVSS)
    Feldman {
        /// Full serialized FeldmanShamirShare (used by engine for MPC ops)
        data: Vec<u8>,
        /// Extracted Feldman commitments — commitment\[0\] is the public key
        commitments: Vec<Vec<u8>>,
    },
}

impl ShareData {
    /// Share bytes for MPC engine operations (multiply, open, etc.)
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            ShareData::Opaque(b) => b,
            ShareData::Feldman { data, .. } => data,
        }
    }

    /// Consume and return the share bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            ShareData::Opaque(b) => b,
            ShareData::Feldman { data, .. } => data,
        }
    }

    /// Feldman commitments, if available.
    pub fn commitments(&self) -> Option<&[Vec<u8>]> {
        match self {
            ShareData::Opaque(_) => None,
            ShareData::Feldman { commitments, .. } => Some(commitments),
        }
    }

    /// Representation format carried by this share payload.
    pub fn format(&self) -> ShareDataFormat {
        match self {
            ShareData::Opaque(_) => ShareDataFormat::Opaque,
            ShareData::Feldman { .. } => ShareDataFormat::Feldman,
        }
    }

    /// Whether this share carries Feldman commitments.
    pub fn has_commitments(&self) -> bool {
        self.format() == ShareDataFormat::Feldman
    }
}

/// Value types supported by the VM
///
/// This enum represents all possible values that can be manipulated by the VM.
/// It includes both primitive types (Int, Float, Bool, String) and complex types
/// (Object, Array, Closure), as well as references to foreign objects.
///
/// The VM uses a dual-type system:
/// - Clear values: Publicly visible values used for control flow and general computation
/// - Secret values: Privately shared values used in secure multiparty computation
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Value {
    /// 64-bit signed integer
    I64(i64),
    /// 32-bit signed integer
    I32(i32),
    /// 16-bit signed integer
    I16(i16),
    /// 8-bit signed integer
    I8(i8),
    /// 8-bit unsigned integer
    U8(u8),
    /// 16-bit unsigned integer
    U16(u16),
    /// 32-bit unsigned integer
    U32(u32),
    /// 64-bit unsigned integer
    U64(u64),
    /// 64-bit floating point number (uses F64 wrapper for Eq/Hash)
    Float(F64),
    /// Boolean value
    Bool(bool),
    /// String value
    String(String),
    /// Reference to an object (key-value map)
    Object(ObjectRef),
    /// Reference to an array
    Array(ArrayRef),
    /// Reference to a foreign object (Rust object exposed to VM)
    Foreign(ForeignObjectRef),
    /// Function closure (function with captured environment)
    Closure(Arc<Closure>),
    /// Unit/void/nil value
    Unit,
    /// Secret shared value (for SMPC)
    Share(ShareType, ShareData),
}

/// Typed reference to a VM object allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectRef(usize);

impl ObjectRef {
    pub const fn new(id: usize) -> Self {
        Self(id)
    }

    pub const fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::Object(object_ref) => Some(*object_ref),
            _ => None,
        }
    }

    pub const fn id(self) -> usize {
        self.0
    }

    pub const fn into_value(self) -> Value {
        Value::Object(self)
    }
}

impl fmt::Display for ObjectRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.id().fmt(f)
    }
}

impl TryFrom<&Value> for ObjectRef {
    type Error = TableMemoryError;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        Self::from_value(value).ok_or(TableMemoryError::ExpectedObjectValue)
    }
}

impl From<ObjectRef> for Value {
    fn from(object_ref: ObjectRef) -> Self {
        object_ref.into_value()
    }
}

/// Typed reference to a VM array allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArrayRef(usize);

impl ArrayRef {
    pub const fn new(id: usize) -> Self {
        Self(id)
    }

    pub const fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::Array(array_ref) => Some(*array_ref),
            _ => None,
        }
    }

    pub const fn id(self) -> usize {
        self.0
    }

    pub const fn into_value(self) -> Value {
        Value::Array(self)
    }
}

impl fmt::Display for ArrayRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.id().fmt(f)
    }
}

impl TryFrom<&Value> for ArrayRef {
    type Error = TableMemoryError;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        Self::from_value(value).ok_or(TableMemoryError::ExpectedArrayValue)
    }
}

impl From<ArrayRef> for Value {
    fn from(array_ref: ArrayRef) -> Self {
        array_ref.into_value()
    }
}

/// Typed reference to a Rust object stored behind the VM foreign-object table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ForeignObjectRef(usize);

impl ForeignObjectRef {
    pub const fn new(id: usize) -> Self {
        Self(id)
    }

    pub const fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::Foreign(foreign_ref) => Some(*foreign_ref),
            _ => None,
        }
    }

    pub const fn id(self) -> usize {
        self.0
    }

    pub const fn into_value(self) -> Value {
        Value::Foreign(self)
    }
}

impl fmt::Display for ForeignObjectRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.id().fmt(f)
    }
}

impl TryFrom<&Value> for ForeignObjectRef {
    type Error = ForeignObjectError;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        Self::from_value(value).ok_or(ForeignObjectError::ExpectedForeignValue)
    }
}

impl From<ForeignObjectRef> for Value {
    fn from(foreign_ref: ForeignObjectRef) -> Self {
        foreign_ref.into_value()
    }
}

/// Typed reference to any VM table allocation.
///
/// Table memory backends should operate on this handle instead of accepting an
/// arbitrary VM value. The VM presentation layer can still convert to and from
/// `Value::Object` / `Value::Array` at API boundaries. Use [`ObjectRef`] and
/// [`ArrayRef`] when an operation only accepts one table kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TableRef {
    Object(ObjectRef),
    Array(ArrayRef),
}

impl TableRef {
    pub const fn object(id: usize) -> Self {
        Self::Object(ObjectRef::new(id))
    }

    pub const fn array(id: usize) -> Self {
        Self::Array(ArrayRef::new(id))
    }

    pub const fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::Object(object_ref) => Some(Self::Object(*object_ref)),
            Value::Array(array_ref) => Some(Self::Array(*array_ref)),
            _ => None,
        }
    }

    pub const fn id(self) -> usize {
        match self {
            Self::Object(object_ref) => object_ref.id(),
            Self::Array(array_ref) => array_ref.id(),
        }
    }

    pub const fn object_ref(self) -> Option<ObjectRef> {
        match self {
            Self::Object(object_ref) => Some(object_ref),
            Self::Array(_) => None,
        }
    }

    pub const fn array_ref(self) -> Option<ArrayRef> {
        match self {
            Self::Array(array_ref) => Some(array_ref),
            Self::Object(_) => None,
        }
    }

    pub const fn into_value(self) -> Value {
        match self {
            Self::Object(object_ref) => object_ref.into_value(),
            Self::Array(array_ref) => array_ref.into_value(),
        }
    }
}

impl From<ObjectRef> for TableRef {
    fn from(object_ref: ObjectRef) -> Self {
        Self::Object(object_ref)
    }
}

impl From<ArrayRef> for TableRef {
    fn from(array_ref: ArrayRef) -> Self {
        Self::Array(array_ref)
    }
}

impl TryFrom<&Value> for TableRef {
    type Error = TableMemoryError;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        Self::from_value(value).ok_or(TableMemoryError::ExpectedTableValue)
    }
}

impl From<TableRef> for Value {
    fn from(table_ref: TableRef) -> Self {
        table_ref.into_value()
    }
}

impl ClearShareValue {
    pub fn into_vm_value(self) -> Value {
        match self {
            ClearShareValue::Integer(value) => Value::I64(value),
            ClearShareValue::FixedPoint(value) => Value::Float(value),
            ClearShareValue::Boolean(value) => Value::Bool(value),
        }
    }
}

impl ClearShareInput {
    pub fn into_vm_value(self) -> Value {
        self.value.into_vm_value()
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::I64(i) => write!(f, "{}", i),
            Value::I32(i) => write!(f, "{}i32", i),
            Value::I16(i) => write!(f, "{}i16", i),
            Value::I8(i) => write!(f, "{}i8", i),
            Value::U8(i) => write!(f, "{}u8", i),
            Value::U16(i) => write!(f, "{}u16", i),
            Value::U32(i) => write!(f, "{}u32", i),
            Value::U64(i) => write!(f, "{}u64", i),
            Value::Float(fp) => {
                write!(f, "{}f64", fp.0)
            }
            Value::Bool(b) => write!(f, "{}", b),
            Value::String(s) => write!(f, "\"{}\"", s),
            Value::Object(object_ref) => write!(f, "Object({})", object_ref.id()),
            Value::Array(array_ref) => write!(f, "Array({})", array_ref.id()),
            Value::Foreign(foreign_ref) => write!(f, "Foreign({})", foreign_ref.id()),
            Value::Closure(c) => write!(f, "Function({})", c.function_id()),
            Value::Unit => write!(f, "()"),
            Value::Share(share_type, _) => write!(f, "Share({:?})", share_type),
        }
    }
}

impl Value {
    /// Stable VM-visible type name for this value.
    ///
    /// Keeping this match on `Value` avoids scattering duplicate variant
    /// classification across builtins and runtime error paths.
    pub const fn type_name(&self) -> &'static str {
        match self {
            Value::I64(_) => "int64",
            Value::Float(_) => "float",
            Value::Bool(_) => "boolean",
            Value::String(_) => "string",
            Value::Object(_) => "object",
            Value::Array(_) => "array",
            Value::Foreign(_) => "cffi_function",
            Value::Closure(_) => "function",
            Value::Unit => "nil",
            Value::I32(_) => "int32",
            Value::I16(_) => "int16",
            Value::I8(_) => "int8",
            Value::U8(_) => "uint8",
            Value::U16(_) => "uint16",
            Value::U32(_) => "uint32",
            Value::U64(_) => "uint64",
            Value::Share(_, _) => "share",
        }
    }

    /// Format the value with rich information using table memory to resolve references.
    ///
    /// This method displays the actual contents of arrays and objects rather than just
    /// their IDs. The `max_depth` parameter controls how deeply nested structures are
    /// expanded to prevent infinite recursion and overly verbose output.
    ///
    /// This immutable variant is intended for non-mutating memory backends and
    /// compatibility with existing callers. VM-visible formatting against
    /// backends with access side effects, such as ORAM-style memory, should use
    /// [`Value::format_with_memory_mut`] instead.
    ///
    /// # Arguments
    /// * `memory` - Table memory containing array and object data
    /// * `max_depth` - Maximum depth for nested structure expansion (0 = no expansion)
    ///
    /// # Examples
    /// ```text
    /// Value::I64(42).format_with_memory(&memory, 2)       // "42"
    /// Value::from(ArrayRef::new(1)).format_with_memory(&memory, 2)     // "[1, 2, 3]"
    /// Value::from(ObjectRef::new(1)).format_with_memory(&memory, 2)    // "{name: \"test\", count: 5}"
    /// ```
    pub fn format_with_memory<M: TableMemoryView + ?Sized>(
        &self,
        memory: &M,
        max_depth: usize,
    ) -> String {
        match self {
            Value::I64(i) => format!("{}", i),
            Value::I32(i) => format!("{}i32", i),
            Value::I16(i) => format!("{}i16", i),
            Value::I8(i) => format!("{}i8", i),
            Value::U8(i) => format!("{}u8", i),
            Value::U16(i) => format!("{}u16", i),
            Value::U32(i) => format!("{}u32", i),
            Value::U64(i) => format!("{}u64", i),
            Value::Float(fp) => format!("{}f64", fp.0),
            Value::Bool(b) => format!("{}", b),
            Value::String(s) => format!("\"{}\"", s),
            Value::Unit => "()".to_string(),
            Value::Closure(c) => format!("Function({})", c.function_id()),
            Value::Foreign(foreign_ref) => format!("Foreign({})", foreign_ref.id()),
            Value::Share(share_type, _) => format!("Share({:?})", share_type),
            Value::Array(array_ref) => Self::format_array_reference(memory, *array_ref, max_depth),
            Value::Object(object_ref) => {
                Self::format_object_reference(memory, *object_ref, max_depth)
            }
        }
    }

    /// Format the value with rich information using semantic table-memory
    /// reads. ORAM-style backends should use this variant because formatting
    /// may observe array/object contents and therefore may mutate backend
    /// access metadata.
    pub fn format_with_memory_mut<M: TableMemory + ?Sized>(
        &self,
        memory: &mut M,
        max_depth: usize,
    ) -> String {
        self.format_with_memory_mut_inner(memory, max_depth)
    }

    fn format_with_memory_mut_inner<M: TableMemory + ?Sized>(
        &self,
        memory: &mut M,
        max_depth: usize,
    ) -> String {
        match self {
            Value::I64(i) => format!("{}", i),
            Value::I32(i) => format!("{}i32", i),
            Value::I16(i) => format!("{}i16", i),
            Value::I8(i) => format!("{}i8", i),
            Value::U8(i) => format!("{}u8", i),
            Value::U16(i) => format!("{}u16", i),
            Value::U32(i) => format!("{}u32", i),
            Value::U64(i) => format!("{}u64", i),
            Value::Float(fp) => format!("{}f64", fp.0),
            Value::Bool(b) => format!("{}", b),
            Value::String(s) => format!("\"{}\"", s),
            Value::Unit => "()".to_string(),
            Value::Closure(c) => format!("Function({})", c.function_id()),
            Value::Foreign(foreign_ref) => format!("Foreign({})", foreign_ref.id()),
            Value::Share(share_type, _) => format!("Share({:?})", share_type),
            Value::Array(array_ref) => {
                Self::format_array_reference_mut(memory, *array_ref, max_depth)
            }
            Value::Object(object_ref) => {
                Self::format_object_reference_mut(memory, *object_ref, max_depth)
            }
        }
    }

    /// Backwards-compatible helper for callers that explicitly hold the default
    /// in-memory table store.
    pub fn format_with_store(&self, store: &ObjectStore, max_depth: usize) -> String {
        self.format_with_memory(store, max_depth)
    }

    /// Format the value with rich information, using a default depth of 3.
    /// Convenience method for typical logging use cases.
    pub fn format_rich_with_memory<M: TableMemoryView + ?Sized>(&self, memory: &M) -> String {
        self.format_with_memory(memory, 3)
    }

    /// Format the value with rich information, using semantic table-memory
    /// reads and a default depth of 3.
    pub fn format_rich_with_memory_mut<M: TableMemory + ?Sized>(&self, memory: &mut M) -> String {
        self.format_with_memory_mut(memory, 3)
    }

    /// Format the value with rich information, using a default depth of 3.
    /// Convenience method for typical logging use cases.
    pub fn format_rich(&self, store: &ObjectStore) -> String {
        self.format_rich_with_memory(store)
    }

    fn format_array_reference<M: TableMemoryView + ?Sized>(
        memory: &M,
        array_ref: ArrayRef,
        max_depth: usize,
    ) -> String {
        let len = match memory.array_ref_len(array_ref) {
            Ok(len) => len,
            Err(_) => return format!("Array({}) <not found>", array_ref.id()),
        };

        if max_depth == 0 {
            return format!("[...{} elements]", len);
        }

        let mut parts = Vec::with_capacity(len.min(TABLE_DISPLAY_ENTRY_LIMIT));
        let truncated = len > TABLE_DISPLAY_ENTRY_LIMIT;
        let display_count = len.min(TABLE_DISPLAY_ENTRY_LIMIT);

        for i in 0..display_count {
            match memory.get_table_field(TableRef::from(array_ref), &Value::I64(i as i64)) {
                Ok(Some(val)) => parts.push(val.format_with_memory(memory, max_depth - 1)),
                Ok(None) => parts.push("()".to_string()),
                Err(err) => parts.push(format!("<error: {}>", err)),
            }
        }

        if truncated {
            format!(
                "[{}, ...({} more)]",
                parts.join(", "),
                len - TABLE_DISPLAY_ENTRY_LIMIT
            )
        } else {
            format!("[{}]", parts.join(", "))
        }
    }

    fn format_array_reference_mut<M: TableMemory + ?Sized>(
        memory: &mut M,
        array_ref: ArrayRef,
        max_depth: usize,
    ) -> String {
        let len = match memory.read_array_ref_len(array_ref) {
            Ok(len) => len,
            Err(_) => return format!("Array({}) <not found>", array_ref.id()),
        };

        if max_depth == 0 {
            return format!("[...{} elements]", len);
        }

        let mut parts = Vec::with_capacity(len.min(TABLE_DISPLAY_ENTRY_LIMIT));
        let truncated = len > TABLE_DISPLAY_ENTRY_LIMIT;
        let display_count = len.min(TABLE_DISPLAY_ENTRY_LIMIT);

        for i in 0..display_count {
            match memory.read_table_field(TableRef::from(array_ref), &Value::I64(i as i64)) {
                Ok(Some(val)) => {
                    parts.push(val.format_with_memory_mut_inner(memory, max_depth - 1))
                }
                Ok(None) => parts.push("()".to_string()),
                Err(err) => parts.push(format!("<error: {}>", err)),
            }
        }

        if truncated {
            format!(
                "[{}, ...({} more)]",
                parts.join(", "),
                len - TABLE_DISPLAY_ENTRY_LIMIT
            )
        } else {
            format!("[{}]", parts.join(", "))
        }
    }

    fn format_object_reference<M: TableMemoryView + ?Sized>(
        memory: &M,
        object_ref: ObjectRef,
        max_depth: usize,
    ) -> String {
        let len = match memory.object_ref_len(object_ref) {
            Ok(len) => len,
            Err(_) => return format!("Object({}) <not found>", object_ref.id()),
        };

        if max_depth == 0 {
            return format!("{{...{} fields}}", len);
        }

        let entries = match memory.object_ref_entries(object_ref, TABLE_DISPLAY_ENTRY_LIMIT) {
            Ok(entries) => entries,
            Err(_) => return format!("Object({}) <not found>", object_ref.id()),
        };
        let truncated = len > entries.len();
        let mut parts = Vec::with_capacity(entries.len());

        for (key, value) in entries {
            let key_str = key.format_with_memory(memory, 0);
            let val_str = value.format_with_memory(memory, max_depth - 1);
            parts.push(format!("{}: {}", key_str, val_str));
        }

        if truncated {
            format!("{{{}, ...({} more)}}", parts.join(", "), len - parts.len())
        } else {
            format!("{{{}}}", parts.join(", "))
        }
    }

    fn format_object_reference_mut<M: TableMemory + ?Sized>(
        memory: &mut M,
        object_ref: ObjectRef,
        max_depth: usize,
    ) -> String {
        let len = match memory.read_object_ref_len(object_ref) {
            Ok(len) => len,
            Err(_) => return format!("Object({}) <not found>", object_ref.id()),
        };

        if max_depth == 0 {
            return format!("{{...{} fields}}", len);
        }

        let entries = match memory.read_object_ref_entries(object_ref, TABLE_DISPLAY_ENTRY_LIMIT) {
            Ok(entries) => entries,
            Err(_) => return format!("Object({}) <not found>", object_ref.id()),
        };
        let truncated = len > entries.len();
        let mut parts = Vec::with_capacity(entries.len());

        for (key, value) in entries {
            let key_str = key.format_with_memory_mut_inner(memory, 0);
            let val_str = value.format_with_memory_mut_inner(memory, max_depth - 1);
            parts.push(format!("{}: {}", key_str, val_str));
        }

        if truncated {
            format!("{{{}, ...({} more)}}", parts.join(", "), len - parts.len())
        } else {
            format!("{{{}}}", parts.join(", "))
        }
    }
}

/// Object structure for key-value storage
///
/// Objects in StoffelVM are similar to JavaScript objects or Lua tables -
/// they store key-value pairs where both keys and values can be any valid VM value.
/// This provides a flexible foundation for implementing various data structures
/// and programming patterns.
#[derive(Debug, Clone)]
pub struct Object {
    /// Map of field names to values
    fields: FxHashMap<Value, Value>,
}

impl Object {
    pub fn new() -> Self {
        Self {
            fields: FxHashMap::default(),
        }
    }

    pub fn get(&self, key: &Value) -> Option<&Value> {
        self.fields.get(key)
    }

    pub fn set(&mut self, key: Value, value: Value) -> Option<Value> {
        self.fields.insert(key, value)
    }

    pub fn len(&self) -> usize {
        self.fields.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Format the object contents for display with a depth limit to prevent infinite recursion.
    /// Returns a string like `{a: 1, b: 2}` for simple objects.
    pub fn format_contents(&self, memory: &dyn TableMemoryView, max_depth: usize) -> String {
        if max_depth == 0 {
            return format!("{{...{} fields}}", self.fields.len());
        }

        let mut parts: Vec<String> =
            Vec::with_capacity(self.fields.len().min(TABLE_DISPLAY_ENTRY_LIMIT));
        let truncated = self.fields.len() > TABLE_DISPLAY_ENTRY_LIMIT;

        for (key, val) in self.fields.iter().take(TABLE_DISPLAY_ENTRY_LIMIT) {
            let key_str = key.format_with_memory(memory, 0); // Keys formatted without depth
            let val_str = val.format_with_memory(memory, max_depth - 1);
            parts.push(format!("{}: {}", key_str, val_str));
        }

        if truncated {
            format!(
                "{{{}, ...({} more)}}",
                parts.join(", "),
                self.fields.len() - TABLE_DISPLAY_ENTRY_LIMIT
            )
        } else {
            format!("{{{}}}", parts.join(", "))
        }
    }
}

impl Default for Object {
    fn default() -> Self {
        Self::new()
    }
}

/// Immutable view of object/array table memory.
///
/// This is intended for diagnostics, formatting, and tests over backends where
/// observation is truly non-mutating. VM execution should use [`TableMemory`],
/// whose read methods take `&mut self` so access-tracking backends such as
/// ORAM can update internal state during logical reads.
pub trait TableMemoryView {
    /// Read a table field without mutating backend state.
    ///
    /// Implementations should return `Ok(None)` for a missing field on an
    /// existing table and `Err` for a table reference that cannot be resolved.
    fn get_table_field(&self, table_ref: TableRef, key: &Value)
    -> TableMemoryResult<Option<Value>>;
    fn array_ref_len(&self, array_ref: ArrayRef) -> TableMemoryResult<usize>;
    fn object_ref_len(&self, object_ref: ObjectRef) -> TableMemoryResult<usize>;
    fn object_ref_entries(
        &self,
        object_ref: ObjectRef,
        limit: usize,
    ) -> TableMemoryResult<Vec<(Value, Value)>>;
}

/// Object/array table memory operations used by the VM execution path.
///
/// The default implementation is [`ObjectStore`], a Lua-like in-memory table
/// store. Reads are part of this mutable trait because future backends such as
/// Path-ORAM may need to update access metadata when the VM observes table
/// contents.
pub trait TableMemory: Send + Sync {
    fn try_clone_empty(&self) -> TableMemoryResult<Box<dyn TableMemory>>;
    fn as_table_memory_view(&self) -> Option<&dyn TableMemoryView> {
        None
    }
    fn create_object_ref(&mut self) -> TableMemoryResult<ObjectRef>;
    fn create_array_ref(&mut self) -> TableMemoryResult<ArrayRef>;
    /// Create an array with an optional capacity hint.
    ///
    /// This hint is not a semantic length and implementations may cap or ignore
    /// it to avoid eager host allocation.
    fn create_array_ref_with_capacity(&mut self, _capacity: usize) -> TableMemoryResult<ArrayRef> {
        self.create_array_ref()
    }
    fn create_object_table_ref(&mut self) -> TableMemoryResult<TableRef> {
        self.create_object_ref().map(TableRef::from)
    }
    fn create_array_table_ref(&mut self) -> TableMemoryResult<TableRef> {
        self.create_array_ref().map(TableRef::from)
    }
    fn create_array_table_ref_with_capacity(
        &mut self,
        capacity: usize,
    ) -> TableMemoryResult<TableRef> {
        self.create_array_ref_with_capacity(capacity)
            .map(TableRef::from)
    }
    /// Semantically read a table field through the VM execution path.
    fn read_table_field(
        &mut self,
        table_ref: TableRef,
        key: &Value,
    ) -> TableMemoryResult<Option<Value>>;
    fn set_table_field(
        &mut self,
        table_ref: TableRef,
        key: Value,
        field_value: Value,
    ) -> TableMemoryResult<()>;
    /// Semantically read an array length through the VM execution path.
    fn read_array_ref_len(&mut self, array_ref: ArrayRef) -> TableMemoryResult<usize>;
    fn push_array_ref_values(
        &mut self,
        array_ref: ArrayRef,
        values: &[Value],
    ) -> TableMemoryResult<usize>;
    /// Semantically read an object length through the VM-visible memory path.
    fn read_object_ref_len(&mut self, object_ref: ObjectRef) -> TableMemoryResult<usize>;
    /// Semantically read object entries through the VM-visible memory path.
    ///
    /// The returned entries are owned so callers can release the memory backend
    /// borrow before recursively formatting nested values.
    fn read_object_ref_entries(
        &mut self,
        object_ref: ObjectRef,
        limit: usize,
    ) -> TableMemoryResult<Vec<(Value, Value)>>;
}

/// Combined storage system for objects and arrays
///
/// This centralized store manages all objects and arrays in the VM.
/// It provides a reference-based system where objects and arrays are
/// identified by typed handles.
///
/// The store handles creation, access, and modification of objects and arrays,
/// as well as field access operations that work across both types.
#[derive(Default)]
pub struct ObjectStore {
    /// Storage for objects, indexed by typed object handle.
    objects: FxHashMap<ObjectRef, Object>,
    /// Storage for arrays, indexed by typed array handle.
    arrays: FxHashMap<ArrayRef, Array>,
    /// Next available ID for object/array allocation
    next_id: usize,
}

impl ObjectStore {
    pub fn new() -> Self {
        ObjectStore {
            objects: FxHashMap::default(),
            arrays: FxHashMap::default(),
            next_id: 1,
        }
    }

    fn allocate_id(&mut self) -> TableMemoryResult<usize> {
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(TableMemoryError::AllocatorOverflow {
                allocator: "ObjectStore",
            })?;
        Ok(id)
    }

    fn object_not_found(object_ref: ObjectRef) -> TableMemoryError {
        TableMemoryError::ObjectNotFound {
            id: object_ref.id(),
        }
    }

    fn array_not_found(array_ref: ArrayRef) -> TableMemoryError {
        TableMemoryError::ArrayNotFound { id: array_ref.id() }
    }

    pub fn create_object_ref(&mut self) -> TableMemoryResult<ObjectRef> {
        let object_ref = ObjectRef::new(self.allocate_id()?);
        self.objects.insert(object_ref, Object::new());
        Ok(object_ref)
    }

    pub fn create_array_ref(&mut self) -> TableMemoryResult<ArrayRef> {
        let array_ref = ArrayRef::new(self.allocate_id()?);
        self.arrays.insert(array_ref, Array::new());
        Ok(array_ref)
    }

    pub fn create_array_ref_with_capacity(
        &mut self,
        capacity: usize,
    ) -> TableMemoryResult<ArrayRef> {
        let array_ref = ArrayRef::new(self.allocate_id()?);
        self.arrays
            .insert(array_ref, Array::with_capacity(capacity));
        Ok(array_ref)
    }

    pub fn get_object_ref(&self, object_ref: ObjectRef) -> Option<&Object> {
        self.objects.get(&object_ref)
    }

    pub fn get_object_ref_mut(&mut self, object_ref: ObjectRef) -> Option<&mut Object> {
        self.objects.get_mut(&object_ref)
    }

    pub fn get_array_ref(&self, array_ref: ArrayRef) -> Option<&Array> {
        self.arrays.get(&array_ref)
    }

    pub fn get_array_ref_mut(&mut self, array_ref: ArrayRef) -> Option<&mut Array> {
        self.arrays.get_mut(&array_ref)
    }

    pub fn try_get_table_field(
        &self,
        table_ref: TableRef,
        key: &Value,
    ) -> TableMemoryResult<Option<Value>> {
        match table_ref {
            TableRef::Object(object_ref) => self
                .get_object_ref(object_ref)
                .ok_or_else(|| Self::object_not_found(object_ref))
                .map(|obj| obj.get(key).cloned()),
            TableRef::Array(array_ref) => self
                .get_array_ref(array_ref)
                .ok_or_else(|| Self::array_not_found(array_ref))
                .map(|arr| arr.get(key).cloned()),
        }
    }

    pub fn set_table_field(
        &mut self,
        table_ref: TableRef,
        key: Value,
        field_value: Value,
    ) -> TableMemoryResult<()> {
        match table_ref {
            TableRef::Object(object_ref) => {
                if let Some(obj) = self.get_object_ref_mut(object_ref) {
                    obj.set(key, field_value);
                    Ok(())
                } else {
                    Err(Self::object_not_found(object_ref))
                }
            }
            TableRef::Array(array_ref) => {
                if let Some(arr) = self.get_array_ref_mut(array_ref) {
                    arr.try_set(key, field_value)
                } else {
                    Err(Self::array_not_found(array_ref))
                }
            }
        }
    }

    pub fn array_ref_len(&self, array_ref: ArrayRef) -> TableMemoryResult<usize> {
        self.get_array_ref(array_ref)
            .map(Array::length)
            .ok_or_else(|| Self::array_not_found(array_ref))
    }

    pub fn object_ref_len(&self, object_ref: ObjectRef) -> TableMemoryResult<usize> {
        self.get_object_ref(object_ref)
            .map(Object::len)
            .ok_or_else(|| Self::object_not_found(object_ref))
    }

    pub fn object_ref_entries(
        &self,
        object_ref: ObjectRef,
        limit: usize,
    ) -> TableMemoryResult<Vec<(Value, Value)>> {
        let object = self
            .get_object_ref(object_ref)
            .ok_or_else(|| Self::object_not_found(object_ref))?;
        Ok(object
            .fields
            .iter()
            .take(limit)
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }

    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    pub fn array_count(&self) -> usize {
        self.arrays.len()
    }

    pub fn contains_object_ref(&self, object_ref: ObjectRef) -> bool {
        self.objects.contains_key(&object_ref)
    }

    pub fn contains_array_ref(&self, array_ref: ArrayRef) -> bool {
        self.arrays.contains_key(&array_ref)
    }
}

impl TableMemoryView for ObjectStore {
    fn get_table_field(
        &self,
        table_ref: TableRef,
        key: &Value,
    ) -> TableMemoryResult<Option<Value>> {
        ObjectStore::try_get_table_field(self, table_ref, key)
    }

    fn array_ref_len(&self, array_ref: ArrayRef) -> TableMemoryResult<usize> {
        ObjectStore::array_ref_len(self, array_ref)
    }

    fn object_ref_len(&self, object_ref: ObjectRef) -> TableMemoryResult<usize> {
        ObjectStore::object_ref_len(self, object_ref)
    }

    fn object_ref_entries(
        &self,
        object_ref: ObjectRef,
        limit: usize,
    ) -> TableMemoryResult<Vec<(Value, Value)>> {
        ObjectStore::object_ref_entries(self, object_ref, limit)
    }
}

impl TableMemory for ObjectStore {
    fn try_clone_empty(&self) -> TableMemoryResult<Box<dyn TableMemory>> {
        Ok(Box::new(ObjectStore::new()))
    }

    fn as_table_memory_view(&self) -> Option<&dyn TableMemoryView> {
        Some(self)
    }

    fn create_object_ref(&mut self) -> TableMemoryResult<ObjectRef> {
        ObjectStore::create_object_ref(self)
    }

    fn create_array_ref(&mut self) -> TableMemoryResult<ArrayRef> {
        ObjectStore::create_array_ref(self)
    }

    fn create_array_ref_with_capacity(&mut self, capacity: usize) -> TableMemoryResult<ArrayRef> {
        ObjectStore::create_array_ref_with_capacity(self, capacity)
    }

    fn read_table_field(
        &mut self,
        table_ref: TableRef,
        key: &Value,
    ) -> TableMemoryResult<Option<Value>> {
        ObjectStore::try_get_table_field(self, table_ref, key)
    }

    fn set_table_field(
        &mut self,
        table_ref: TableRef,
        key: Value,
        field_value: Value,
    ) -> TableMemoryResult<()> {
        ObjectStore::set_table_field(self, table_ref, key, field_value)
    }

    fn read_array_ref_len(&mut self, array_ref: ArrayRef) -> TableMemoryResult<usize> {
        ObjectStore::array_ref_len(self, array_ref)
    }

    fn push_array_ref_values(
        &mut self,
        array_ref: ArrayRef,
        values: &[Value],
    ) -> TableMemoryResult<usize> {
        let array = self
            .get_array_ref_mut(array_ref)
            .ok_or_else(|| ObjectStore::array_not_found(array_ref))?;
        array.try_push_values(values)
    }

    fn read_object_ref_len(&mut self, object_ref: ObjectRef) -> TableMemoryResult<usize> {
        ObjectStore::object_ref_len(self, object_ref)
    }

    fn read_object_ref_entries(
        &mut self,
        object_ref: ObjectRef,
        limit: usize,
    ) -> TableMemoryResult<Vec<(Value, Value)>> {
        ObjectStore::object_ref_entries(self, object_ref, limit)
    }
}

pub type ForeignObjectResult<T> = Result<T, ForeignObjectError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForeignObjectError {
    AllocatorOverflow,
    ExpectedForeignValue,
}

impl fmt::Display for ForeignObjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ForeignObjectError::AllocatorOverflow => {
                write!(f, "Foreign object ID allocator overflowed")
            }
            ForeignObjectError::ExpectedForeignValue => write!(f, "Expected foreign object"),
        }
    }
}

impl std::error::Error for ForeignObjectError {}

impl From<ForeignObjectError> for String {
    fn from(error: ForeignObjectError) -> Self {
        error.to_string()
    }
}

/// Storage system for foreign (Rust) objects.
///
/// Objects are stored as type-erased `Arc<Mutex<T>>` values and recovered with
/// `Arc::downcast`, so callers keep a typed shared handle without a custom
/// object-erasure trait.
pub struct ForeignObjectStorage {
    /// Storage for foreign objects, indexed by typed handle.
    objects: FxHashMap<ForeignObjectRef, Arc<dyn Any + Send + Sync>>,
    /// Next available ID for foreign object allocation
    next_id: usize,
}

impl Default for ForeignObjectStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl ForeignObjectStorage {
    pub fn new() -> Self {
        ForeignObjectStorage {
            objects: FxHashMap::default(),
            next_id: 1,
        }
    }

    fn allocate_ref(&mut self) -> ForeignObjectResult<ForeignObjectRef> {
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(ForeignObjectError::AllocatorOverflow)?;
        Ok(ForeignObjectRef::new(id))
    }

    pub fn register_object_ref<T: 'static + Send + Sync>(
        &mut self,
        object: T,
    ) -> ForeignObjectResult<ForeignObjectRef> {
        let object_ref = self.allocate_ref()?;

        let object = Arc::new(Mutex::new(object));
        self.objects.insert(object_ref, object);

        Ok(object_ref)
    }

    pub fn try_register_object_ref<T: 'static + Send + Sync>(
        &mut self,
        object: T,
    ) -> ForeignObjectResult<ForeignObjectRef> {
        self.register_object_ref(object)
    }

    pub fn get_object_ref<T: 'static + Send + Sync>(
        &self,
        object_ref: ForeignObjectRef,
    ) -> Option<Arc<Mutex<T>>> {
        self.objects
            .get(&object_ref)
            .and_then(|object| Arc::clone(object).downcast::<Mutex<T>>().ok())
    }

    pub fn get_object_any_ref(
        &self,
        object_ref: ForeignObjectRef,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        self.objects.get(&object_ref).map(Arc::clone)
    }

    pub fn remove_object_ref(&mut self, object_ref: ForeignObjectRef) -> bool {
        self.objects.remove(&object_ref).is_some()
    }

    pub fn contains_object_ref(&self, object_ref: ForeignObjectRef) -> bool {
        self.objects.contains_key(&object_ref)
    }

    pub fn len(&self) -> usize {
        self.objects.len()
    }

    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MutatingFormatMemory {
        inner: ObjectStore,
        reads: Arc<AtomicUsize>,
    }

    impl MutatingFormatMemory {
        fn new(reads: Arc<AtomicUsize>) -> Self {
            Self {
                inner: ObjectStore::new(),
                reads,
            }
        }
    }

    impl TableMemory for MutatingFormatMemory {
        fn try_clone_empty(&self) -> TableMemoryResult<Box<dyn TableMemory>> {
            Ok(Box::new(Self::new(Arc::clone(&self.reads))))
        }

        fn create_object_ref(&mut self) -> TableMemoryResult<ObjectRef> {
            self.inner.create_object_ref()
        }

        fn create_array_ref(&mut self) -> TableMemoryResult<ArrayRef> {
            self.inner.create_array_ref()
        }

        fn create_array_ref_with_capacity(
            &mut self,
            capacity: usize,
        ) -> TableMemoryResult<ArrayRef> {
            self.inner.create_array_ref_with_capacity(capacity)
        }

        fn read_table_field(
            &mut self,
            table_ref: TableRef,
            key: &Value,
        ) -> TableMemoryResult<Option<Value>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.read_table_field(table_ref, key)
        }

        fn set_table_field(
            &mut self,
            table_ref: TableRef,
            key: Value,
            field_value: Value,
        ) -> TableMemoryResult<()> {
            self.inner.set_table_field(table_ref, key, field_value)
        }

        fn read_array_ref_len(&mut self, array_ref: ArrayRef) -> TableMemoryResult<usize> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.read_array_ref_len(array_ref)
        }

        fn push_array_ref_values(
            &mut self,
            array_ref: ArrayRef,
            values: &[Value],
        ) -> TableMemoryResult<usize> {
            self.inner.push_array_ref_values(array_ref, values)
        }

        fn read_object_ref_len(&mut self, object_ref: ObjectRef) -> TableMemoryResult<usize> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.read_object_ref_len(object_ref)
        }

        fn read_object_ref_entries(
            &mut self,
            object_ref: ObjectRef,
            limit: usize,
        ) -> TableMemoryResult<Vec<(Value, Value)>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.read_object_ref_entries(object_ref, limit)
        }
    }

    #[test]
    fn share_type_rejects_zero_secret_int_bit_length() {
        let err = ShareType::try_secret_int(0).unwrap_err();

        assert_eq!(err, ShareTypeError::SecretIntBitLengthZero);
        assert_eq!(err.to_string(), "bit_length must be a positive integer");
    }

    #[test]
    fn share_type_accepts_positive_secret_int_bit_length() {
        assert_eq!(
            ShareType::try_secret_int(64),
            Ok(ShareType::SecretInt { bit_length: 64 })
        );
    }

    #[test]
    fn share_type_rejects_zero_fixed_point_total_bits() {
        let err = ShareType::try_secret_fixed_point_from_bits(0, 0).unwrap_err();

        assert_eq!(err, ShareTypeError::FixedPointTotalBitsZero);
        assert_eq!(err.to_string(), "total_bits must be a positive integer");
    }

    #[test]
    fn share_type_rejects_fixed_point_fractional_bits_out_of_range() {
        let err = ShareType::try_secret_fixed_point_from_bits(64, 64).unwrap_err();

        assert_eq!(
            err,
            ShareTypeError::FixedPointFractionalBitsOutOfRange {
                total_bits: 64,
                fractional_bits: 64
            }
        );
        assert_eq!(err.to_string(), "frac_bits must be less than total_bits");
    }

    #[test]
    fn fixed_point_precision_is_vm_local_metadata() {
        let precision = FixedPointPrecision::new(128, 32);

        assert_eq!(precision.total_bits(), 128);
        assert_eq!(precision.fractional_bits(), 32);
        assert_eq!(precision.k(), 128);
        assert_eq!(precision.f(), 32);
    }

    #[test]
    fn fixed_point_precision_try_new_rejects_invalid_metadata() {
        assert_eq!(
            FixedPointPrecision::try_new(0, 0),
            Err(ShareTypeError::FixedPointTotalBitsZero)
        );
        assert_eq!(
            FixedPointPrecision::try_new(64, 64),
            Err(ShareTypeError::FixedPointFractionalBitsOutOfRange {
                total_bits: 64,
                fractional_bits: 64
            })
        );
    }

    #[test]
    fn share_type_accepts_valid_fixed_point_precision() {
        let share_type = ShareType::try_secret_fixed_point_from_bits(64, 16)
            .expect("valid fixed-point share type");

        assert!(matches!(
            share_type,
            ShareType::SecretFixedPoint { precision }
                if precision.k() == 64 && precision.f() == 16
        ));
    }

    #[test]
    fn share_data_exposes_representation_format() {
        let opaque = ShareData::Opaque(vec![1, 2, 3]);
        let feldman = ShareData::Feldman {
            data: vec![4, 5, 6],
            commitments: vec![vec![7, 8, 9]],
        };

        assert_eq!(opaque.format(), ShareDataFormat::Opaque);
        assert_eq!(opaque.format().as_str(), "opaque");
        assert!(!opaque.has_commitments());
        assert_eq!(feldman.format(), ShareDataFormat::Feldman);
        assert_eq!(feldman.format().as_str(), "feldman");
        assert!(feldman.has_commitments());
    }

    #[test]
    fn table_memory_trait_covers_object_and_array_access() {
        let mut memory: Box<dyn TableMemory> = Box::new(ObjectStore::new());

        let object_ref = memory.create_object_ref().expect("create object");
        let object_table_ref = TableRef::from(object_ref);
        memory
            .set_table_field(
                object_table_ref,
                Value::String("name".to_string()),
                Value::I64(7),
            )
            .expect("set object field");
        assert_eq!(
            memory.read_table_field(object_table_ref, &Value::String("name".to_string())),
            Ok(Some(Value::I64(7)))
        );

        let array_ref = memory.create_array_ref().expect("create array");
        memory
            .push_array_ref_values(array_ref, &[Value::I64(1), Value::I64(2)])
            .expect("push array values");
        assert_eq!(memory.read_array_ref_len(array_ref), Ok(2));
        assert_eq!(
            memory.read_table_field(TableRef::from(array_ref), &Value::I64(1)),
            Ok(Some(Value::I64(2)))
        );

        let object_entries = memory
            .read_object_ref_entries(object_ref, 8)
            .expect("object entries");
        assert_eq!(memory.read_object_ref_len(object_ref), Ok(1));
        assert_eq!(
            memory
                .read_object_ref_entries(object_ref, 8)
                .expect("typed object entries")
                .len(),
            1
        );
        assert_eq!(object_entries.len(), 1);
    }

    #[test]
    fn object_store_lookup_helpers_preserve_table_kinds() {
        let mut store = ObjectStore::new();

        let object_ref = store.create_object_ref().expect("create object");
        let array_ref = store.create_array_ref().expect("create array");

        assert!(store.contains_object_ref(object_ref));
        assert!(!store.contains_array_ref(ArrayRef::new(object_ref.id())));
        assert!(store.contains_array_ref(array_ref));
        assert!(!store.contains_object_ref(ObjectRef::new(array_ref.id())));
        assert!(store.get_object_ref(object_ref).is_some());
        assert!(
            store
                .get_array_ref(ArrayRef::new(object_ref.id()))
                .is_none()
        );
        assert!(store.get_array_ref(array_ref).is_some());
        assert!(
            store
                .get_object_ref(ObjectRef::new(array_ref.id()))
                .is_none()
        );
    }

    #[test]
    fn table_memory_capacity_hint_is_optional_for_backends() {
        struct CapacityAgnosticMemory {
            inner: ObjectStore,
        }

        impl TableMemory for CapacityAgnosticMemory {
            fn try_clone_empty(&self) -> TableMemoryResult<Box<dyn TableMemory>> {
                Ok(Box::new(Self {
                    inner: ObjectStore::new(),
                }))
            }

            fn create_object_ref(&mut self) -> TableMemoryResult<ObjectRef> {
                self.inner.create_object_ref()
            }

            fn create_array_ref(&mut self) -> TableMemoryResult<ArrayRef> {
                self.inner.create_array_ref()
            }

            fn read_table_field(
                &mut self,
                table_ref: TableRef,
                key: &Value,
            ) -> TableMemoryResult<Option<Value>> {
                self.inner.read_table_field(table_ref, key)
            }

            fn set_table_field(
                &mut self,
                table_ref: TableRef,
                key: Value,
                field_value: Value,
            ) -> TableMemoryResult<()> {
                self.inner.set_table_field(table_ref, key, field_value)
            }

            fn push_array_ref_values(
                &mut self,
                array_ref: ArrayRef,
                values: &[Value],
            ) -> TableMemoryResult<usize> {
                self.inner.push_array_ref_values(array_ref, values)
            }

            fn read_array_ref_len(&mut self, array_ref: ArrayRef) -> TableMemoryResult<usize> {
                self.inner.read_array_ref_len(array_ref)
            }

            fn read_object_ref_len(&mut self, object_ref: ObjectRef) -> TableMemoryResult<usize> {
                self.inner.read_object_ref_len(object_ref)
            }

            fn read_object_ref_entries(
                &mut self,
                object_ref: ObjectRef,
                limit: usize,
            ) -> TableMemoryResult<Vec<(Value, Value)>> {
                self.inner.read_object_ref_entries(object_ref, limit)
            }
        }

        let mut memory: Box<dyn TableMemory> = Box::new(CapacityAgnosticMemory {
            inner: ObjectStore::new(),
        });

        let array_ref = memory
            .create_array_ref_with_capacity(usize::MAX)
            .expect("capacity-agnostic memory can ignore capacity hints");

        assert_eq!(memory.read_array_ref_len(array_ref), Ok(0));
        assert!(
            memory.as_table_memory_view().is_none(),
            "immutable table inspection is an opt-in backend capability"
        );
    }

    #[test]
    fn object_store_exposes_optional_table_memory_view() {
        let mut memory: Box<dyn TableMemory> = Box::new(ObjectStore::new());
        let object_ref = memory.create_object_ref().expect("create object");
        memory
            .set_table_field(
                TableRef::from(object_ref),
                Value::String("answer".to_string()),
                Value::I64(42),
            )
            .expect("set field");

        let view = memory
            .as_table_memory_view()
            .expect("ObjectStore supports immutable inspection");
        assert_eq!(
            view.get_table_field(
                TableRef::from(object_ref),
                &Value::String("answer".to_string())
            ),
            Ok(Some(Value::I64(42)))
        );
    }

    #[test]
    fn table_ref_converts_only_object_and_array_values() {
        let object_ref = ObjectRef::new(7);
        let array_ref = ArrayRef::new(9);
        let foreign_ref = ForeignObjectRef::new(11);

        assert_eq!(
            ObjectRef::from_value(&Value::from(object_ref)),
            Some(object_ref)
        );
        assert_eq!(ObjectRef::from_value(&Value::from(array_ref)), None);
        assert_eq!(
            ArrayRef::from_value(&Value::from(array_ref)),
            Some(array_ref)
        );
        assert_eq!(ArrayRef::from_value(&Value::from(object_ref)), None);
        assert_eq!(
            ForeignObjectRef::from_value(&Value::from(foreign_ref)),
            Some(foreign_ref)
        );
        assert_eq!(ForeignObjectRef::from_value(&Value::from(object_ref)), None);
        assert_eq!(
            TableRef::from_value(&Value::from(object_ref)),
            Some(TableRef::Object(object_ref))
        );
        assert_eq!(
            TableRef::from_value(&Value::from(array_ref)),
            Some(TableRef::Array(array_ref))
        );
        assert_eq!(TableRef::from(object_ref), TableRef::Object(object_ref));
        assert_eq!(TableRef::from(array_ref), TableRef::Array(array_ref));
        assert_eq!(TableRef::object(7).object_ref(), Some(object_ref));
        assert_eq!(TableRef::object(7).array_ref(), None);
        assert_eq!(TableRef::array(9).array_ref(), Some(array_ref));
        assert_eq!(TableRef::array(9).object_ref(), None);
        assert_eq!(TableRef::from_value(&Value::I64(1)), None);
        assert_eq!(Value::from(object_ref), Value::Object(object_ref));
        assert_eq!(Value::from(array_ref), Value::Array(array_ref));
        assert_eq!(Value::from(foreign_ref), Value::Foreign(foreign_ref));
        assert_eq!(Value::from(TableRef::object(7)), Value::Object(object_ref));
        assert_eq!(
            TableRef::try_from(&Value::String("not-table".to_string())),
            Err(TableMemoryError::ExpectedTableValue)
        );
        assert_eq!(
            ObjectRef::try_from(&Value::String("not-object".to_string())),
            Err(TableMemoryError::ExpectedObjectValue)
        );
        assert_eq!(
            ArrayRef::try_from(&Value::String("not-array".to_string())),
            Err(TableMemoryError::ExpectedArrayValue)
        );
        assert_eq!(
            ForeignObjectRef::try_from(&Value::String("not-foreign".to_string())),
            Err(ForeignObjectError::ExpectedForeignValue)
        );
    }

    #[test]
    fn value_formatting_uses_table_memory_view_trait_object() {
        let mut memory = ObjectStore::new();

        let array_ref = memory.create_array_ref().expect("create array");
        memory
            .push_array_ref_values(array_ref, &[Value::I64(10), Value::I64(11)])
            .expect("push array values");

        let object_ref = memory.create_object_ref().expect("create object");
        let object = Value::from(object_ref);
        memory
            .set_table_field(
                TableRef::from(object_ref),
                Value::String("values".to_string()),
                Value::from(array_ref),
            )
            .expect("set array field");
        memory
            .set_table_field(
                TableRef::from(object_ref),
                Value::String("answer".to_string()),
                Value::I64(42),
            )
            .expect("set number field");

        let view: &dyn TableMemoryView = &memory;
        let formatted = object.format_rich_with_memory(view);
        assert!(formatted.contains("\"answer\": 42"));
        assert!(formatted.contains("\"values\": [10, 11]"));
    }

    #[test]
    fn value_formatting_can_use_mutating_table_memory_reads() {
        let reads = Arc::new(AtomicUsize::new(0));
        let mut memory = MutatingFormatMemory::new(Arc::clone(&reads));

        let array_ref = memory.create_array_ref().expect("create array");
        memory
            .push_array_ref_values(array_ref, &[Value::I64(10), Value::I64(11)])
            .expect("push array values");

        let object_ref = memory.create_object_ref().expect("create object");
        let object = Value::from(object_ref);
        memory
            .set_table_field(
                TableRef::from(object_ref),
                Value::String("values".to_string()),
                Value::from(array_ref),
            )
            .expect("set array field");
        memory
            .set_table_field(
                TableRef::from(object_ref),
                Value::String("answer".to_string()),
                Value::I64(42),
            )
            .expect("set number field");

        let formatted = object.format_rich_with_memory_mut(&mut memory);

        assert!(formatted.contains("\"answer\": 42"));
        assert!(formatted.contains("\"values\": [10, 11]"));
        assert!(
            reads.load(Ordering::SeqCst) >= 5,
            "semantic formatting should use mutating reads"
        );
    }

    #[test]
    fn value_type_name_covers_vm_value_variants() {
        let closure = Value::Closure(Arc::new(Closure::new("callee", Vec::new())));
        let share = Value::Share(ShareType::boolean(), ShareData::Opaque(Vec::new()));

        let cases = [
            (Value::I64(1), "int64"),
            (Value::I32(1), "int32"),
            (Value::I16(1), "int16"),
            (Value::I8(1), "int8"),
            (Value::U64(1), "uint64"),
            (Value::U32(1), "uint32"),
            (Value::U16(1), "uint16"),
            (Value::U8(1), "uint8"),
            (Value::Float(F64(1.25)), "float"),
            (Value::Bool(true), "boolean"),
            (Value::String("x".to_string()), "string"),
            (Value::from(ObjectRef::new(1)), "object"),
            (Value::from(ArrayRef::new(2)), "array"),
            (Value::from(ForeignObjectRef::new(3)), "cffi_function"),
            (closure, "function"),
            (Value::Unit, "nil"),
            (share, "share"),
        ];

        for (value, expected) in cases {
            assert_eq!(value.type_name(), expected);
        }
    }

    #[test]
    fn object_store_trait_allocation_reports_id_overflow() {
        fn saturated_store() -> ObjectStore {
            ObjectStore {
                objects: FxHashMap::default(),
                arrays: FxHashMap::default(),
                next_id: usize::MAX,
            }
        }

        let mut object_store = saturated_store();
        let err = <ObjectStore as TableMemory>::create_object_ref(&mut object_store).unwrap_err();
        assert_eq!(
            err,
            TableMemoryError::AllocatorOverflow {
                allocator: "ObjectStore"
            }
        );
        assert_eq!(object_store.object_count(), 0);

        let mut array_store = saturated_store();
        let err = <ObjectStore as TableMemory>::create_array_ref(&mut array_store).unwrap_err();
        assert_eq!(
            err,
            TableMemoryError::AllocatorOverflow {
                allocator: "ObjectStore"
            }
        );
        assert_eq!(array_store.array_count(), 0);

        let mut array_store = saturated_store();
        let err = <ObjectStore as TableMemory>::create_array_ref_with_capacity(&mut array_store, 4)
            .unwrap_err();
        assert_eq!(
            err,
            TableMemoryError::AllocatorOverflow {
                allocator: "ObjectStore"
            }
        );
        assert_eq!(array_store.array_count(), 0);
    }

    #[test]
    fn object_store_direct_ref_allocation_methods_are_fallible() {
        fn saturated_store() -> ObjectStore {
            ObjectStore {
                objects: FxHashMap::default(),
                arrays: FxHashMap::default(),
                next_id: usize::MAX,
            }
        }

        let mut object_store = saturated_store();
        let err = object_store.create_object_ref().unwrap_err();
        assert_eq!(
            err,
            TableMemoryError::AllocatorOverflow {
                allocator: "ObjectStore"
            }
        );
        assert_eq!(object_store.object_count(), 0);

        let mut array_store = saturated_store();
        let err = array_store.create_array_ref().unwrap_err();
        assert_eq!(
            err,
            TableMemoryError::AllocatorOverflow {
                allocator: "ObjectStore"
            }
        );
        assert_eq!(array_store.array_count(), 0);

        let mut array_store = saturated_store();
        let err = array_store.create_array_ref_with_capacity(4).unwrap_err();
        assert_eq!(
            err,
            TableMemoryError::AllocatorOverflow {
                allocator: "ObjectStore"
            }
        );
        assert_eq!(array_store.array_count(), 0);
    }

    #[test]
    fn object_store_trait_table_field_distinguishes_missing_field_from_invalid_handle() {
        let mut store = ObjectStore::new();
        let object_ref = store.create_object_ref().expect("create object");
        let array_ref = store.create_array_ref().expect("create array");
        let missing_key = Value::String("missing".to_string());

        assert_eq!(
            <ObjectStore as TableMemoryView>::get_table_field(
                &store,
                TableRef::from(object_ref),
                &missing_key
            ),
            Ok(None)
        );
        assert_eq!(
            <ObjectStore as TableMemoryView>::get_table_field(
                &store,
                TableRef::from(array_ref),
                &Value::I64(0)
            ),
            Ok(None)
        );

        let object_err = <ObjectStore as TableMemoryView>::get_table_field(
            &store,
            TableRef::object(usize::MAX),
            &missing_key,
        )
        .unwrap_err();
        assert_eq!(
            object_err,
            TableMemoryError::ObjectNotFound { id: usize::MAX }
        );

        let array_err = <ObjectStore as TableMemoryView>::get_table_field(
            &store,
            TableRef::array(usize::MAX),
            &Value::I64(0),
        )
        .unwrap_err();
        assert_eq!(
            array_err,
            TableMemoryError::ArrayNotFound { id: usize::MAX }
        );
    }

    #[test]
    fn array_rejects_indices_that_exceed_representable_vm_length() {
        let mut array = Array::new();

        let err = array
            .try_set(Value::I64(i64::MAX), Value::I64(1))
            .unwrap_err();

        assert!(matches!(
            err,
            TableMemoryError::VmIntegerRangeExceeded {
                label: "Array length",
                ..
            } | TableMemoryError::ArrayIndexDoesNotFitHost { .. }
        ));
        assert_eq!(array.length(), 0);
    }

    #[test]
    fn array_capacity_hint_does_not_force_large_dense_allocation() {
        let array = Array::with_capacity(usize::MAX);

        assert_eq!(array.length(), 0);
        assert!(array.elements.capacity() <= ARRAY_DENSE_INLINE_CAPACITY);
    }

    #[test]
    fn object_store_capacity_hint_does_not_force_large_dense_allocation() {
        let mut store = ObjectStore::new();

        let array_ref =
            <ObjectStore as TableMemory>::create_array_ref_with_capacity(&mut store, usize::MAX)
                .expect("capacity hint should not be an eager allocation request");
        let array = store.get_array_ref(array_ref).expect("created array");

        assert_eq!(array.length(), 0);
        assert!(array.elements.capacity() <= ARRAY_DENSE_INLINE_CAPACITY);
    }

    #[test]
    fn object_store_push_array_values_checks_index_conversion() {
        let array_ref = ArrayRef::new(1);
        let mut array = Array::new();
        array.length_hint = usize::try_from(i64::MAX).unwrap_or(usize::MAX);

        let mut store = ObjectStore {
            objects: FxHashMap::default(),
            arrays: FxHashMap::default(),
            next_id: 2,
        };
        store.arrays.insert(array_ref, array);

        let err = <ObjectStore as TableMemory>::push_array_ref_values(
            &mut store,
            array_ref,
            &[Value::I64(1)],
        )
        .unwrap_err();

        assert!(matches!(
            err,
            TableMemoryError::VmIntegerRangeExceeded {
                label: "Array length" | "Array index",
                ..
            } | TableMemoryError::ArrayLengthOverflow { .. }
                | TableMemoryError::ArrayPushLengthOverflow
        ));
    }

    #[test]
    fn array_push_appends_without_redecoding_numeric_keys() {
        let mut array = Array::new();

        let len = array
            .try_push_values(&[Value::I64(10), Value::I64(11)])
            .expect("append values");

        assert_eq!(len, 2);
        assert_eq!(array.length(), 2);
        assert_eq!(array.get(&Value::I64(0)), Some(&Value::I64(10)));
        assert_eq!(array.get(&Value::I64(1)), Some(&Value::I64(11)));
    }

    #[test]
    fn foreign_object_storage_encapsulates_typed_objects() {
        let mut storage = ForeignObjectStorage::new();

        let object_ref = storage
            .try_register_object_ref(String::from("stored"))
            .expect("foreign object registration");

        assert_eq!(storage.len(), 1);
        assert!(storage.contains_object_ref(object_ref));
        assert_eq!(
            storage
                .get_object_ref::<String>(object_ref)
                .unwrap()
                .lock()
                .as_str(),
            "stored"
        );
        assert!(storage.get_object_ref::<u64>(object_ref).is_none());
        assert!(storage.remove_object_ref(object_ref));
        assert!(storage.is_empty());
        assert!(storage.get_object_ref::<String>(object_ref).is_none());
    }

    #[test]
    fn foreign_object_registration_is_fallible() {
        let mut storage = ForeignObjectStorage {
            objects: FxHashMap::default(),
            next_id: usize::MAX,
        };

        let err = storage
            .try_register_object_ref(String::from("stored"))
            .unwrap_err();

        assert_eq!(err, ForeignObjectError::AllocatorOverflow);
        assert_eq!(err.to_string(), "Foreign object ID allocator overflowed");
        assert!(storage.is_empty());
    }

    #[test]
    fn closure_and_upvalue_accessors_preserve_captured_state() {
        let mut upvalue = Upvalue::new("counter", Value::I64(1));
        assert_eq!(upvalue.name(), "counter");
        assert_eq!(upvalue.value(), &Value::I64(1));

        upvalue.set_value(Value::I64(2));
        assert_eq!(upvalue.value(), &Value::I64(2));

        let mut closure = Closure::new("increment", vec![upvalue]);
        assert_eq!(closure.function_id(), "increment");
        assert_eq!(closure.upvalues()[0].name(), "counter");
        assert_eq!(closure.upvalues()[0].value(), &Value::I64(2));

        closure.replace_upvalues(vec![Upvalue::new("counter", Value::I64(3))]);
        assert_eq!(closure.upvalues()[0].value(), &Value::I64(3));
    }
}
