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
use stoffelmpc_mpc::common::types::fixed::FixedPointPrecision;

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
    fn to_bits_normalized(&self) -> u64 {
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
/// - Small arrays (indices < 32) use a contiguous SmallVec for efficient access
/// - Larger indices and non-numeric keys use a hash map
/// - A length hint is maintained for O(1) length queries (stores len = last_index + 1)
#[derive(Debug, Clone)]
pub struct Array {
    /// Contiguous storage for small arrays (optimized for indices < 32)
    elements: SmallVec<[Value; 16]>, // Optimize for small arrays
    /// Storage for large indices and non-numeric keys
    extra_fields: FxHashMap<Value, Value>, // Already using FxHashMap
    /// Cached length for O(1) access
    length_hint: usize, // Cache length for O(1) access
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
            elements: SmallVec::with_capacity(capacity),
            extra_fields: FxHashMap::default(),
            length_hint: 0,
        }
    }

    pub fn get(&self, key: &Value) -> Option<&Value> {
        match key {
            // 0-indexed arrays: Valid numeric keys are 0..<length
            Value::I64(idx) if *idx >= 0 && (*idx as usize) < self.length_hint => {
                Some(&self.elements[*idx as usize])
            }
            _ => self.extra_fields.get(key),
        }
    }

    pub fn set(&mut self, key: Value, value: Value) {
        match key {
            // 0-indexed arrays: only indices >= 0 are valid for the dense part
            Value::I64(idx) if idx >= 0 => {
                let idx_usize = idx as usize; // 0-based
                // Update length_hint to the highest occupied numeric index + 1
                self.length_hint = self.length_hint.max(idx_usize + 1);
                if idx_usize < 32 {
                    // Small array optimization
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
    }

    pub fn length(&self) -> usize {
        self.length_hint
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
    pub name: String,
    /// Value of the captured variable
    pub value: Value,
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
    pub function_id: String,
    /// Variables captured from outer scopes
    pub upvalues: Vec<Upvalue>,
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

fn default_fixed_point_precision() -> FixedPointPrecision {
    FixedPointPrecision::new(
        DEFAULT_FIXED_POINT_TOTAL_BITS,
        DEFAULT_FIXED_POINT_FRACTIONAL_BITS,
    )
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
    pub fn secret_int(bit_length: usize) -> Self {
        assert!(
            bit_length > 0,
            "secret integers require a positive bit length"
        );
        ShareType::SecretInt { bit_length }
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

    pub fn secret_fixed_point_from_bits(total_bits: usize, fractional_bits: usize) -> Self {
        ShareType::SecretFixedPoint {
            precision: FixedPointPrecision::new(total_bits, fractional_bits),
        }
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
    Object(usize),
    /// Reference to an array
    Array(usize),
    /// Reference to a foreign object (Rust object exposed to VM)
    Foreign(usize),
    /// Function closure (function with captured environment)
    Closure(Arc<Closure>),
    /// Unit/void/nil value
    Unit,
    /// Secret shared value (for SMPC) TODO: Change
    Share(ShareType, Vec<u8>),
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
            Value::Object(id) => write!(f, "Object({})", id),
            Value::Array(id) => write!(f, "Array({})", id),
            Value::Foreign(id) => write!(f, "Foreign({})", id),
            Value::Closure(c) => write!(f, "Function({})", c.function_id),
            Value::Unit => write!(f, "()"),
            Value::Share(share_type, _) => write!(f, "Share({:?})", share_type),
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
    pub fields: FxHashMap<Value, Value>,
}

/// Combined storage system for objects and arrays
///
/// This centralized store manages all objects and arrays in the VM.
/// It provides a reference-based system where objects and arrays are
/// identified by numeric IDs, similar to a simple garbage collection system.
///
/// The store handles creation, access, and modification of objects and arrays,
/// as well as field access operations that work across both types.
#[derive(Default)]
pub struct ObjectStore {
    /// Storage for objects, indexed by ID
    pub objects: FxHashMap<usize, Object>,
    /// Storage for arrays, indexed by ID
    pub arrays: FxHashMap<usize, Array>,
    /// Next available ID for object/array allocation
    pub next_id: usize,
}

impl ObjectStore {
    pub fn new() -> Self {
        ObjectStore {
            objects: FxHashMap::default(),
            arrays: FxHashMap::default(),
            next_id: 1,
        }
    }

    pub fn create_object(&mut self) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.objects.insert(
            id,
            Object {
                fields: FxHashMap::default(),
            },
        );
        id
    }

    pub fn create_array(&mut self) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.arrays.insert(id, Array::new());
        id
    }

    pub fn create_array_with_capacity(&mut self, capacity: usize) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.arrays.insert(id, Array::with_capacity(capacity));
        id
    }

    pub fn get_object(&self, id: usize) -> Option<&Object> {
        self.objects.get(&id)
    }

    pub fn get_object_mut(&mut self, id: usize) -> Option<&mut Object> {
        self.objects.get_mut(&id)
    }

    pub fn get_array(&self, id: usize) -> Option<&Array> {
        self.arrays.get(&id)
    }

    pub fn get_array_mut(&mut self, id: usize) -> Option<&mut Array> {
        self.arrays.get_mut(&id)
    }

    pub fn get_field(&self, value: &Value, key: &Value) -> Option<Value> {
        match value {
            Value::Object(id) => self
                .get_object(*id)
                .and_then(|obj| obj.fields.get(key).cloned()),
            Value::Array(id) => self.get_array(*id).and_then(|arr| arr.get(key).cloned()),
            _ => None,
        }
    }

    pub fn set_field(
        &mut self,
        value: &Value,
        key: Value,
        field_value: Value,
    ) -> Result<(), String> {
        match value {
            Value::Object(id) => {
                if let Some(obj) = self.get_object_mut(*id) {
                    obj.fields.insert(key, field_value);
                    Ok(())
                } else {
                    Err(format!("Object with ID {} not found", id))
                }
            }
            Value::Array(id) => {
                if let Some(arr) = self.get_array_mut(*id) {
                    arr.set(key, field_value);
                    Ok(())
                } else {
                    Err(format!("Array with ID {} not found", id))
                }
            }
            _ => Err("Expected object or array".to_string()),
        }
    }
}

/// Trait for type-erased foreign objects
///
/// This trait enables the VM to store and retrieve arbitrary Rust types
/// in a type-safe manner. It provides the foundation for the Foreign Function
/// Interface (FFI) system, allowing Rust objects to be exposed to the VM.
pub trait AnyObject: Send + Sync {
    /// Get a reference to the object as a type-erased Any
    fn as_any(&self) -> &dyn Any;
    /// Get a mutable reference to the object as a type-erased Any
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Type-specific container for foreign objects
///
/// This generic wrapper preserves the exact type of a foreign object
/// while implementing the AnyObject trait. It uses Arc<Mutex<T>> to
/// provide thread-safe shared access to the wrapped object.
pub struct TypedObject<T: 'static + Send + Sync> {
    /// Thread-safe reference to the wrapped object
    pub value: Arc<Mutex<T>>,
}

impl<T: 'static + Send + Sync> AnyObject for TypedObject<T> {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Storage system for foreign (Rust) objects
///
/// This system manages all foreign objects exposed to the VM.
/// It provides a way to register Rust objects with the VM and
/// retrieve them later in a type-safe manner.
///
/// Foreign objects are identified by numeric IDs, similar to
/// the ObjectStore system for VM-native objects and arrays.
pub struct ForeignObjectStorage {
    /// Storage for foreign objects, indexed by ID
    pub objects: FxHashMap<usize, Box<dyn AnyObject + Send + Sync>>,
    /// Next available ID for foreign object allocation
    pub next_id: usize,
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

    pub fn register_object<T: 'static + Send + Sync>(&mut self, object: T) -> usize {
        let id = self.next_id;
        self.next_id += 1;

        // Store a TypedObject wrapper that preserves the exact type
        let typed_obj = TypedObject {
            value: Arc::new(Mutex::new(object)),
        };
        self.objects.insert(id, Box::new(typed_obj));

        id
    }

    pub fn get_object<T: 'static + Send + Sync>(&self, id: usize) -> Option<Arc<Mutex<T>>> {
        self.objects.get(&id).and_then(|obj| {
            // Using safe downcast
            if let Some(typed) = obj.as_any().downcast_ref::<TypedObject<T>>() {
                Some(Arc::clone(&typed.value))
            } else {
                None
            }
        })
    }
}
