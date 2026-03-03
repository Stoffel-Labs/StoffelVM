//! C Foreign Function Interface (CFFI) for StoffelVM
//!
//! This module provides a C-compatible API for interacting with StoffelVM from languages
//! like C, Go, Nim, JavaScript, Python, etc. It allows external code to:
//!
//! - Create and manage VM instances
//! - Register foreign functions with the VM
//! - Execute VM functions and retrieve results
//! - Convert between VM and C-compatible types
//!
//! # Safety
//!
//! This module contains unsafe code due to the nature of FFI. Care must be taken when
//! using these functions from other languages to ensure memory safety and proper resource
//! management.
//!
//! # Example (C)
//!
//! ```c
//! #include "stoffel_vm.h"
//! #include <stdio.h>
//!
//! // Example C callback function
//! int double_value(StoffelValue* args, int arg_count, StoffelValue* result) {
//!     if (arg_count != 1 || args[0].value_type != STOFFEL_VALUE_INT) {
//!         return -1; // Error
//!     }
//!     
//!     result->value_type = STOFFEL_VALUE_INT;
//!     result->data.int_val = args[0].data.int_val * 2;
//!     return 0; // Success
//! }
//!
//! int main() {
//!     // Create a VM instance
//!     VMHandle vm = stoffel_create_vm();
//!     
//!     // Register a foreign function
//!     stoffel_register_foreign_function(vm, "double", double_value);
//!     
//!     // Execute a VM function
//!     StoffelValue result;
//!     int status = stoffel_execute(vm, "test_double", &result);
//!     
//!     // Clean up
//!     stoffel_destroy_vm(vm);
//!     return 0;
//! }
//! ```

use std::ffi::{c_char, CStr, CString};
use std::io::Cursor;
use std::marker::PhantomPinned;
use std::os::raw::{c_int, c_void};
use std::sync::{Arc, Mutex};

use crate::core_vm::VirtualMachine;
use crate::foreign_functions::ForeignFunctionContext;
#[cfg(feature = "honeybadger")]
use crate::net::hb_engine::HoneyBadgerMpcEngine;
#[cfg(feature = "honeybadger")]
use crate::net::mpc_engine::MpcEngine;
use stoffel_vm_types::compiled_binary::CompiledBinary;
use stoffel_vm_types::core_types::{ShareType, Value, F64};
#[cfg(feature = "honeybadger")]
use stoffelnet::transports::quic::QuicNetworkManager;

/// Maximum share buffer size accepted from FFI callers (1 MB).
/// Prevents accidental or malicious oversized allocations from C/SDK code.
const MAX_FFI_SHARE_LEN: usize = 1_048_576;

/// Write a `Vec<u8>` result through FFI out-pointers using the boxed-slice pattern.
///
/// The Vec is shrunk to exact length via `into_boxed_slice()`, then leaked as a raw
/// pointer. The caller must free with the corresponding `*_free_bytes` function which
/// reconstructs the `Box<[u8]>`.
///
/// # Safety
/// `result_ptr` and `result_len_ptr` must be valid, non-null, aligned pointers.
unsafe fn write_ffi_result_bytes(
    bytes: Vec<u8>,
    result_ptr: *mut *mut u8,
    result_len_ptr: *mut usize,
) {
    let boxed = bytes.into_boxed_slice();
    let len = boxed.len();
    let ptr = Box::into_raw(boxed) as *mut u8;
    *result_ptr = ptr;
    *result_len_ptr = len;
}

/// Free bytes previously allocated via [`write_ffi_result_bytes`].
///
/// Reconstructs the `Box<[u8]>` and drops it.
///
/// # Safety
/// `ptr` must have been produced by `write_ffi_result_bytes` with the matching `len`,
/// and must not have been freed already.
unsafe fn free_ffi_result_bytes(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len));
    }
}

/// Opaque pointer type for the VM
pub type VMHandle = *mut c_void;

/// Value types in StoffelVM exposed to C
#[repr(C)]
pub enum StoffelValueType {
    /// Unit/void value
    Unit = 0,
    /// Integer value
    Int = 1,
    /// Float value
    Float = 2,
    /// Boolean value
    Bool = 3,
    /// String value
    String = 4,
    /// Object reference
    Object = 5,
    /// Array reference
    Array = 6,
    /// Foreign object reference
    Foreign = 7,
    /// Function closure
    Closure = 8,
}

/// Union to hold the actual value data
#[repr(C)]
pub union StoffelValueData {
    /// Integer value
    pub int_val: i64,
    /// Float value
    pub float_val: f64,
    /// Boolean value
    pub bool_val: bool,
    /// String value (C string)
    pub string_val: *const c_char,
    /// Object ID
    pub object_id: usize,
    /// Array ID
    pub array_id: usize,
    /// Foreign object ID
    pub foreign_id: usize,
    /// Closure ID (for future use)
    pub closure_id: usize,
}

/// C-compatible representation of a StoffelVM value
#[repr(C)]
pub struct StoffelValue {
    /// Type of the value
    pub value_type: StoffelValueType,
    /// Actual value data
    pub data: StoffelValueData,
}

/// Type for C callback functions
pub type CForeignFunction =
    extern "C" fn(args: *const StoffelValue, arg_count: c_int, result: *mut StoffelValue) -> c_int;

// ============================================================================
// HoneyBadgerMpcEngine FFI Types
// ============================================================================

#[cfg(feature = "honeybadger")]
/// Opaque pointer type for HoneyBadgerMpcEngine
///
/// This type is used to pass engine handles across the FFI boundary.
/// The actual `Arc<HoneyBadgerMpcEngine>` is stored inside a Box for stable pointer.
#[repr(C)]
pub struct HBEngineOpaque {
    _data: (),
    _marker: core::marker::PhantomData<(*mut u8, PhantomPinned)>,
}

#[cfg(feature = "honeybadger")]
/// Opaque pointer type for QuicNetworkManager
///
/// This type is used to pass network handles across the FFI boundary.
#[repr(C)]
pub struct HBNetworkOpaque {
    _data: (),
    _marker: core::marker::PhantomData<(*mut u8, PhantomPinned)>,
}

#[cfg(feature = "honeybadger")]
/// Error codes for HoneyBadgerMpcEngine FFI operations
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HBEngineErrorCode {
    /// Operation succeeded
    HBEngineSuccess = 0,
    /// Null pointer provided
    HBEngineNullPointer = 1,
    /// Engine not ready (preprocessing not complete)
    HBEngineNotReady = 2,
    /// Network error during MPC operation
    HBEngineNetworkError = 3,
    /// Preprocessing failed
    HBEnginePreprocessingFailed = 4,
    /// Multiplication operation failed
    HBEngineMultiplyFailed = 5,
    /// Share opening/reconstruction failed
    HBEngineOpenShareFailed = 6,
    /// Serialization/deserialization error
    HBEngineSerializationError = 7,
    /// Invalid share type provided
    HBEngineInvalidShareType = 8,
    /// Client input initialization failed
    HBEngineClientInputFailed = 9,
    /// Client shares retrieval failed
    HBEngineGetClientSharesFailed = 10,
    /// Tokio runtime creation failed
    HBEngineRuntimeError = 11,
    /// Invalid configuration parameters
    HBEngineInvalidConfig = 12,
}

/// C-compatible representation of ShareType
///
/// The `kind` field indicates the type:
/// - 0 = Int (width is the value)
/// - 1 = Bool (width is 1 for true, 0 for false)
/// - 2 = Float (width is the value)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CShareType {
    /// Type kind: 0=Int, 1=Bool, 2=Float
    pub kind: u8,
    /// Width/value depending on kind
    pub width: i64,
}

impl From<CShareType> for ShareType {
    fn from(c: CShareType) -> Self {
        match c.kind {
            // kind 0 = SecretInt with bit_length
            0 => ShareType::secret_int(c.width as usize),
            // kind 1 = Boolean (1-bit SecretInt)
            1 => ShareType::boolean(),
            // kind 2 = SecretFixedPoint (width encodes total_bits, fractional_bits assumed default)
            2 => ShareType::default_secret_fixed_point(),
            // Default to 64-bit secret int
            _ => ShareType::default_secret_int(),
        }
    }
}

impl From<ShareType> for CShareType {
    fn from(st: ShareType) -> Self {
        match st {
            ShareType::SecretInt { bit_length } => CShareType {
                kind: 0,
                width: bit_length as i64,
            },
            ShareType::SecretFixedPoint { precision } => CShareType {
                kind: 2,
                width: precision.k() as i64,
            },
        }
    }
}

/// Creates a new VM instance
///
/// # Returns
///
/// A handle to the VM instance, or NULL if creation failed
///
/// # Safety
///
/// The returned handle must be freed with `stoffel_destroy_vm` to avoid memory leaks.
#[no_mangle]
pub extern "C" fn stoffel_create_vm() -> VMHandle {
    let vm = Box::new(VirtualMachine::new());
    Box::into_raw(vm) as VMHandle
}

/// Destroys a VM instance
///
/// # Arguments
///
/// * `handle` - Handle to the VM instance
///
/// # Safety
///
/// The handle must not be used after this function is called.
#[no_mangle]
pub extern "C" fn stoffel_destroy_vm(handle: VMHandle) {
    if !handle.is_null() {
        unsafe {
            let _ = Box::from_raw(handle as *mut VirtualMachine);
        }
    }
}

/// Executes a VM function and returns the result
///
/// # Arguments
///
/// * `handle` - Handle to the VM instance
/// * `function_name` - Name of the function to execute
/// * `result` - Pointer to a StoffelValue to store the result
///
/// # Returns
///
/// 0 on success, non-zero on error
///
/// # Safety
///
/// The function_name must be a valid null-terminated C string.
/// The result pointer must be valid and point to enough memory to store a StoffelValue.
#[no_mangle]
pub extern "C" fn stoffel_execute(
    handle: VMHandle,
    function_name: *const c_char,
    result: *mut StoffelValue,
) -> c_int {
    if handle.is_null() || function_name.is_null() || result.is_null() {
        return -1;
    }

    let vm = unsafe { &mut *(handle as *mut VirtualMachine) };
    let c_str = unsafe { CStr::from_ptr(function_name) };
    let function_name = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    match vm.execute(function_name) {
        Ok(value) => match value_to_stoffel_value(&value) {
            Ok(converted) => {
                unsafe {
                    *result = converted;
                }
                0
            }
            Err(_) => -4,
        },
        Err(_) => -3,
    }
}

/// Executes a VM function with arguments and returns the result
///
/// # Arguments
///
/// * `handle` - Handle to the VM instance
/// * `function_name` - Name of the function to execute
/// * `args` - Array of StoffelValue arguments
/// * `arg_count` - Number of arguments
/// * `result` - Pointer to a StoffelValue to store the result
///
/// # Returns
///
/// 0 on success, non-zero on error
///
/// # Safety
///
/// The function_name must be a valid null-terminated C string.
/// The args pointer must be valid and point to at least arg_count StoffelValue structs.
/// The result pointer must be valid and point to enough memory to store a StoffelValue.
#[no_mangle]
pub extern "C" fn stoffel_execute_with_args(
    handle: VMHandle,
    function_name: *const c_char,
    args: *const StoffelValue,
    arg_count: c_int,
    result: *mut StoffelValue,
) -> c_int {
    if handle.is_null()
        || function_name.is_null()
        || (arg_count > 0 && args.is_null())
        || result.is_null()
    {
        return -1;
    }

    let vm = unsafe { &mut *(handle as *mut VirtualMachine) };
    let c_str = unsafe { CStr::from_ptr(function_name) };
    let function_name = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    // Guard against unreasonable arg counts from C callers
    if arg_count < 0 || arg_count > 1024 {
        return -1;
    }

    // Convert C args to Rust Values
    let mut rust_args = Vec::with_capacity(arg_count as usize);
    for i in 0..arg_count {
        let arg = unsafe { &*args.offset(i as isize) };
        match stoffel_value_to_value(arg) {
            Ok(value) => rust_args.push(value),
            Err(_) => return -3,
        }
    }

    match vm.execute_with_args(function_name, &rust_args) {
        Ok(value) => match value_to_stoffel_value(&value) {
            Ok(converted) => {
                unsafe {
                    *result = converted;
                }
                0
            }
            Err(_) => -5,
        },
        Err(_) => -4,
    }
}

/// Wrapper for C foreign functions to be called from Rust
struct CForeignFunctionWrapper {
    func: CForeignFunction,
}

impl CForeignFunctionWrapper {
    fn call(&self, ctx: ForeignFunctionContext) -> Result<Value, String> {
        // Convert Rust args to C args
        let c_args: Vec<StoffelValue> = ctx
            .args
            .iter()
            .map(value_to_stoffel_value)
            .collect::<Result<Vec<_>, _>>()?;

        let mut result = StoffelValue {
            value_type: StoffelValueType::Unit,
            data: StoffelValueData { int_val: 0 },
        };

        // Call the C function
        let status = (self.func)(c_args.as_ptr(), c_args.len() as c_int, &mut result);

        if status != 0 {
            return Err(format!("Foreign function returned error code: {}", status));
        }

        // Convert C result back to Rust
        stoffel_value_to_value(&result)
    }
}

/// Registers a C function with the VM
///
/// # Arguments
///
/// * `handle` - Handle to the VM instance
/// * `name` - Name of the function to register
/// * `func` - Pointer to the C function
///
/// # Returns
///
/// 0 on success, non-zero on error
///
/// # Safety
///
/// The name must be a valid null-terminated C string.
/// The func pointer must be valid and point to a function with the correct signature.
#[no_mangle]
pub extern "C" fn stoffel_register_foreign_function(
    handle: VMHandle,
    name: *const c_char,
    func: CForeignFunction,
) -> c_int {
    if handle.is_null() || name.is_null() {
        return -1;
    }

    let vm = unsafe { &mut *(handle as *mut VirtualMachine) };
    let c_str = unsafe { CStr::from_ptr(name) };
    let name = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let wrapper = CForeignFunctionWrapper { func };

    vm.register_foreign_function(name, move |ctx| wrapper.call(ctx));

    0
}

/// Thread-safe wrapper for C pointers
///
/// This struct wraps a raw pointer in a way that makes it safe to share
/// between threads. The actual safety is the responsibility of the C code
/// that manages the pointer.
///
/// # Safety
///
/// The user must ensure that the pointer remains valid for the lifetime of this wrapper
/// and that any operations on the pointer are thread-safe.
struct CForeignObject {
    /// The raw pointer, wrapped in Arc<Mutex<>> for thread safety
    ptr: Arc<Mutex<*mut c_void>>,
}

// Implement Send and Sync for CForeignObject
// This is safe because we're using Arc<Mutex<>> for synchronization
unsafe impl Send for CForeignObject {}
unsafe impl Sync for CForeignObject {}

impl CForeignObject {
    /// Creates a new CForeignObject from a raw pointer
    ///
    /// # Safety
    ///
    /// The pointer must be valid and must remain valid for the lifetime of the wrapper.
    fn new(ptr: *mut c_void) -> Self {
        CForeignObject {
            ptr: Arc::new(Mutex::new(ptr)),
        }
    }

    /// Gets the raw pointer
    ///
    /// # Safety
    ///
    /// The caller must ensure that any operations on the pointer are thread-safe.
    fn get_ptr(&self) -> *mut c_void {
        *self.ptr.lock().unwrap()
    }
}

/// Registers a foreign object with the VM
///
/// # Arguments
///
/// * `handle` - Handle to the VM instance
/// * `object` - Pointer to the object
/// * `result` - Pointer to a StoffelValue to store the result
///
/// # Returns
///
/// 0 on success, non-zero on error
///
/// # Safety
///
/// The object pointer must be valid and must remain valid for the lifetime of the VM.
/// The result pointer must be valid and point to enough memory to store a StoffelValue.
///
/// # Notes
///
/// This function wraps the raw pointer in a thread-safe wrapper that implements
/// Send and Sync. The actual safety of the pointer is the responsibility of the
/// C code that manages it.
#[no_mangle]
pub extern "C" fn stoffel_register_foreign_object(
    handle: VMHandle,
    object: *mut c_void,
    result: *mut StoffelValue,
) -> c_int {
    if handle.is_null() || object.is_null() || result.is_null() {
        return -1;
    }

    let vm = unsafe { &mut *(handle as *mut VirtualMachine) };

    // Create a thread-safe wrapper around the raw pointer
    let foreign_object = CForeignObject::new(object);

    // Register the wrapped object with the VM
    let value = vm.register_foreign_object(foreign_object);

    // Convert the result to a StoffelValue
    let converted = match value_to_stoffel_value(&value) {
        Ok(converted) => converted,
        Err(_) => return -2,
    };
    unsafe {
        *result = converted;
    }

    0
}

/// Creates a new string in the VM
///
/// # Arguments
///
/// * `handle` - Handle to the VM instance
/// * `str` - Pointer to a null-terminated C string
/// * `result` - Pointer to a StoffelValue to store the result
///
/// # Returns
///
/// 0 on success, non-zero on error
///
/// # Safety
///
/// The str pointer must be a valid null-terminated C string.
/// The result pointer must be valid and point to enough memory to store a StoffelValue.
#[no_mangle]
pub extern "C" fn stoffel_create_string(
    handle: VMHandle,
    str: *const c_char,
    result: *mut StoffelValue,
) -> c_int {
    if handle.is_null() || str.is_null() || result.is_null() {
        return -1;
    }

    let c_str = unsafe { CStr::from_ptr(str) };
    let rust_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let value = Value::String(rust_str.to_string());

    let converted = match value_to_stoffel_value(&value) {
        Ok(converted) => converted,
        Err(_) => return -3,
    };
    unsafe {
        *result = converted;
    }

    0
}

/// Converts a Rust Value to a C-compatible StoffelValue
///
/// # Arguments
///
/// * `value` - Reference to a Rust Value
///
/// # Returns
///
/// A C-compatible StoffelValue or an error if no safe ABI conversion exists
fn value_to_stoffel_value(value: &Value) -> Result<StoffelValue, String> {
    match value {
        Value::Unit => Ok(StoffelValue {
            value_type: StoffelValueType::Unit,
            data: StoffelValueData { int_val: 0 },
        }),
        Value::I64(n) => Ok(StoffelValue {
            value_type: StoffelValueType::Int,
            data: StoffelValueData { int_val: *n },
        }),
        Value::I32(n) => Ok(StoffelValue {
            value_type: StoffelValueType::Int,
            data: StoffelValueData {
                int_val: i64::from(*n),
            },
        }),
        Value::I16(n) => Ok(StoffelValue {
            value_type: StoffelValueType::Int,
            data: StoffelValueData {
                int_val: i64::from(*n),
            },
        }),
        Value::I8(n) => Ok(StoffelValue {
            value_type: StoffelValueType::Int,
            data: StoffelValueData {
                int_val: i64::from(*n),
            },
        }),
        Value::U8(n) => Ok(StoffelValue {
            value_type: StoffelValueType::Int,
            data: StoffelValueData {
                int_val: i64::from(*n),
            },
        }),
        Value::U16(n) => Ok(StoffelValue {
            value_type: StoffelValueType::Int,
            data: StoffelValueData {
                int_val: i64::from(*n),
            },
        }),
        Value::U32(n) => Ok(StoffelValue {
            value_type: StoffelValueType::Int,
            data: StoffelValueData {
                int_val: i64::from(*n),
            },
        }),
        Value::U64(n) => {
            let int_val =
                i64::try_from(*n).map_err(|_| format!("u64 value {n} exceeds C ABI int range"))?;
            Ok(StoffelValue {
                value_type: StoffelValueType::Int,
                data: StoffelValueData { int_val },
            })
        }
        Value::Float(f) => Ok(StoffelValue {
            value_type: StoffelValueType::Float,
            data: StoffelValueData { float_val: f.0 },
        }),
        Value::Bool(b) => Ok(StoffelValue {
            value_type: StoffelValueType::Bool,
            data: StoffelValueData { bool_val: *b },
        }),
        Value::String(s) => {
            // Note: This creates a memory leak as we're not freeing the CString
            // In a real implementation, you would need to handle this properly
            let c_string = CString::new(s.as_str())
                .map_err(|_| "String contains interior null byte".to_string())?;
            let ptr = c_string.into_raw();
            Ok(StoffelValue {
                value_type: StoffelValueType::String,
                data: StoffelValueData { string_val: ptr },
            })
        }
        Value::Object(id) => Ok(StoffelValue {
            value_type: StoffelValueType::Object,
            data: StoffelValueData { object_id: *id },
        }),
        Value::Array(id) => Ok(StoffelValue {
            value_type: StoffelValueType::Array,
            data: StoffelValueData { array_id: *id },
        }),
        Value::Foreign(id) => Ok(StoffelValue {
            value_type: StoffelValueType::Foreign,
            data: StoffelValueData { foreign_id: *id },
        }),
        Value::Closure(_) => Ok(StoffelValue {
            value_type: StoffelValueType::Closure,
            data: StoffelValueData { closure_id: 0 }, // Simplified
        }),
        Value::Share(_, _) => Err("Cannot convert secret share value to C ABI".to_string()),
        Value::PendingReveal(_) => Err("Cannot convert pending reveal marker to C ABI".to_string()),
    }
}

/// Converts a C-compatible StoffelValue to a Rust Value
///
/// # Arguments
///
/// * `value` - Reference to a C-compatible StoffelValue
///
/// # Returns
///
/// A Result containing either the converted Rust Value or an error message
fn stoffel_value_to_value(value: &StoffelValue) -> Result<Value, String> {
    match value.value_type {
        StoffelValueType::Unit => Ok(Value::Unit),
        StoffelValueType::Int => unsafe { Ok(Value::I64(value.data.int_val)) },
        StoffelValueType::Float => unsafe { Ok(Value::Float(F64(value.data.float_val))) },
        StoffelValueType::Bool => unsafe { Ok(Value::Bool(value.data.bool_val)) },
        StoffelValueType::String => unsafe {
            if value.data.string_val.is_null() {
                return Err("Null string pointer".to_string());
            }
            let c_str = CStr::from_ptr(value.data.string_val);
            match c_str.to_str() {
                Ok(s) => Ok(Value::String(s.to_string())),
                Err(_) => Err("Invalid UTF-8 in string".to_string()),
            }
        },
        StoffelValueType::Object => unsafe { Ok(Value::Object(value.data.object_id)) },
        StoffelValueType::Array => unsafe { Ok(Value::Array(value.data.array_id)) },
        StoffelValueType::Foreign => unsafe { Ok(Value::Foreign(value.data.foreign_id)) },
        StoffelValueType::Closure => Err("Closure conversion not implemented".to_string()),
    }
}

/// Frees a string created by the VM
///
/// # Arguments
///
/// * `str` - Pointer to a C string created by the VM
///
/// # Safety
///
/// The str pointer must have been created by stoffel_create_string or similar functions.
/// After this function is called, the pointer must not be used.
#[no_mangle]
pub extern "C" fn stoffel_free_string(str: *mut c_char) {
    if !str.is_null() {
        unsafe {
            let _ = CString::from_raw(str);
        }
    }
}

/// Loads bytecode into the VM
///
/// # Arguments
///
/// * `handle` - Handle to the VM instance
/// * `bytecode` - Pointer to bytecode data
/// * `bytecode_len` - Length of bytecode data in bytes
///
/// # Returns
///
/// 0 on success, non-zero on error:
/// - -1: Null handle or bytecode pointer
/// - -2: Bytecode deserialization failed
/// - -3: Function registration failed
///
/// # Safety
///
/// The bytecode pointer must be valid and point to at least `bytecode_len` bytes.
#[no_mangle]
pub extern "C" fn stoffel_load_bytecode(
    handle: VMHandle,
    bytecode: *const u8,
    bytecode_len: usize,
) -> c_int {
    if handle.is_null() || bytecode.is_null() {
        return -1;
    }

    let vm = unsafe { &mut *(handle as *mut VirtualMachine) };

    // Create a byte slice from the raw pointer
    let bytes = unsafe { std::slice::from_raw_parts(bytecode, bytecode_len) };

    // Deserialize the compiled binary
    let mut cursor = Cursor::new(bytes);
    let compiled_binary = match CompiledBinary::deserialize(&mut cursor) {
        Ok(binary) => binary,
        Err(_) => return -2,
    };

    // Convert to VM functions and register them
    let vm_functions = compiled_binary.to_vm_functions();

    for function in vm_functions {
        vm.register_function(function);
    }

    0
}

// ============================================================================
// HoneyBadgerMpcEngine FFI Functions
// ============================================================================

#[cfg(feature = "honeybadger")]
/// Creates a new HoneyBadgerMpcEngine
///
/// # Arguments
///
/// * `instance_id` - Unique identifier for this MPC instance
/// * `party_id` - This party's ID (0 to n-1)
/// * `n` - Total number of parties
/// * `t` - Threshold (corruption tolerance)
/// * `n_triples` - Number of Beaver triples to generate
/// * `n_random` - Number of random shares to generate
/// * `network_ptr` - Pointer to HBNetworkOpaque (QuicNetworkManager)
///
/// # Returns
///
/// Pointer to opaque engine handle, or null on failure
///
/// # Safety
///
/// The network_ptr must be a valid pointer to an HBNetworkOpaque created by this FFI.
#[no_mangle]
pub extern "C" fn hb_engine_new(
    instance_id: u64,
    party_id: usize,
    n: usize,
    t: usize,
    n_triples: usize,
    n_random: usize,
    network_ptr: *mut HBNetworkOpaque,
) -> *mut HBEngineOpaque {
    if network_ptr.is_null() {
        return std::ptr::null_mut();
    }

    // Extract Arc<QuicNetworkManager> from the opaque pointer
    let net: Arc<QuicNetworkManager> = unsafe {
        let boxed = &*(network_ptr as *const Arc<QuicNetworkManager>);
        Arc::clone(boxed)
    };

    match HoneyBadgerMpcEngine::<ark_bls12_381::Fr, ark_bls12_381::G1Projective>::new(
        instance_id,
        party_id,
        n,
        t,
        n_triples,
        n_random,
        net,
        Vec::new(),
    ) {
        Ok(engine) => {
            // engine is Arc<HoneyBadgerMpcEngine>, box it for stable FFI pointer
            Box::into_raw(Box::new(engine)) as *mut HBEngineOpaque
        }
        Err(_) => std::ptr::null_mut(),
    }
}

#[cfg(feature = "honeybadger")]
/// Frees a HoneyBadgerMpcEngine instance
///
/// # Safety
///
/// The pointer must have been created by hb_engine_new and not already freed.
#[no_mangle]
pub extern "C" fn hb_engine_free(engine_ptr: *mut HBEngineOpaque) {
    if !engine_ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(engine_ptr as *mut Arc<HoneyBadgerMpcEngine>);
        }
    }
}

#[cfg(feature = "honeybadger")]
/// Runs preprocessing (generates Beaver triples and random shares)
///
/// This is a blocking call that runs the async preprocessing protocol.
/// Must be called before any computation operations.
///
/// # Returns
///
/// * HBEngineSuccess on success
/// * Error code on failure
#[no_mangle]
pub extern "C" fn hb_engine_start_async(engine_ptr: *mut HBEngineOpaque) -> HBEngineErrorCode {
    if engine_ptr.is_null() {
        return HBEngineErrorCode::HBEngineNullPointer;
    }

    let engine = unsafe { &*(engine_ptr as *const Arc<HoneyBadgerMpcEngine>) };

    // Create tokio runtime for blocking on async
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return HBEngineErrorCode::HBEngineRuntimeError,
    };

    match rt.block_on(engine.start_async()) {
        Ok(()) => HBEngineErrorCode::HBEngineSuccess,
        Err(_) => HBEngineErrorCode::HBEnginePreprocessingFailed,
    }
}

#[cfg(feature = "honeybadger")]
/// Checks if the engine is ready (preprocessing complete)
///
/// # Returns
///
/// 1 if ready, 0 if not ready or null pointer
#[no_mangle]
pub extern "C" fn hb_engine_is_ready(engine_ptr: *mut HBEngineOpaque) -> c_int {
    if engine_ptr.is_null() {
        return 0;
    }

    let engine = unsafe { &*(engine_ptr as *const Arc<HoneyBadgerMpcEngine>) };
    if engine.is_ready() {
        1
    } else {
        0
    }
}

#[cfg(feature = "honeybadger")]
/// Performs secure multiplication of two shares
///
/// # Arguments
///
/// * `engine_ptr` - Engine handle
/// * `share_type` - Type information for the shares
/// * `left_ptr` - Pointer to left share bytes
/// * `left_len` - Length of left share
/// * `right_ptr` - Pointer to right share bytes
/// * `right_len` - Length of right share
/// * `result_ptr` - Output: pointer to result bytes (caller must free with hb_free_bytes)
/// * `result_len_ptr` - Output: length of result bytes
///
/// # Returns
///
/// * HBEngineSuccess on success, error code on failure
#[no_mangle]
pub extern "C" fn hb_engine_multiply_share_async(
    engine_ptr: *mut HBEngineOpaque,
    share_type: CShareType,
    left_ptr: *const u8,
    left_len: usize,
    right_ptr: *const u8,
    right_len: usize,
    result_ptr: *mut *mut u8,
    result_len_ptr: *mut usize,
) -> HBEngineErrorCode {
    if engine_ptr.is_null()
        || left_ptr.is_null()
        || right_ptr.is_null()
        || result_ptr.is_null()
        || result_len_ptr.is_null()
    {
        return HBEngineErrorCode::HBEngineNullPointer;
    }

    if left_len > MAX_FFI_SHARE_LEN || right_len > MAX_FFI_SHARE_LEN {
        return HBEngineErrorCode::HBEngineInvalidShareType;
    }
    let engine = unsafe { &*(engine_ptr as *const Arc<HoneyBadgerMpcEngine>) };
    let left = unsafe { std::slice::from_raw_parts(left_ptr, left_len) };
    let right = unsafe { std::slice::from_raw_parts(right_ptr, right_len) };
    let ty: ShareType = share_type.into();

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return HBEngineErrorCode::HBEngineRuntimeError,
    };

    match rt.block_on(engine.multiply_share_async(ty, left, right)) {
        Ok(result) => {
            unsafe {
                write_ffi_result_bytes(result, result_ptr, result_len_ptr);
            }
            HBEngineErrorCode::HBEngineSuccess
        }
        Err(_) => HBEngineErrorCode::HBEngineMultiplyFailed,
    }
}

#[cfg(feature = "honeybadger")]
/// Opens (reconstructs) a shared value
///
/// # Arguments
///
/// * `engine_ptr` - Engine handle
/// * `share_type` - Type information for the share
/// * `share_ptr` - Pointer to share bytes
/// * `share_len` - Length of share bytes
/// * `result_ptr` - Output: StoffelValue containing the reconstructed value
///
/// # Returns
///
/// * HBEngineSuccess on success, error code on failure
#[no_mangle]
pub extern "C" fn hb_engine_open_share(
    engine_ptr: *mut HBEngineOpaque,
    share_type: CShareType,
    share_ptr: *const u8,
    share_len: usize,
    result_ptr: *mut StoffelValue,
) -> HBEngineErrorCode {
    if engine_ptr.is_null() || share_ptr.is_null() || result_ptr.is_null() {
        return HBEngineErrorCode::HBEngineNullPointer;
    }

    if share_len > MAX_FFI_SHARE_LEN {
        return HBEngineErrorCode::HBEngineInvalidShareType;
    }
    let engine = unsafe { &*(engine_ptr as *const Arc<HoneyBadgerMpcEngine>) };
    let share_bytes = unsafe { std::slice::from_raw_parts(share_ptr, share_len) };
    let ty: ShareType = share_type.into();

    // open_share is sync in the current implementation (uses global registry)
    match engine.open_share(ty, share_bytes) {
        Ok(value) => {
            let converted = match value_to_stoffel_value(&value) {
                Ok(converted) => converted,
                Err(_) => return HBEngineErrorCode::HBEngineOpenShareFailed,
            };
            unsafe {
                *result_ptr = converted;
            }
            HBEngineErrorCode::HBEngineSuccess
        }
        Err(_) => HBEngineErrorCode::HBEngineOpenShareFailed,
    }
}

#[cfg(feature = "honeybadger")]
/// Initialize input shares from a client
///
/// # Arguments
///
/// * `engine_ptr` - Engine handle
/// * `client_id` - Client identifier
/// * `shares_data` - Serialized shares data (ark_serialize compressed format)
/// * `shares_len` - Length of shares data
///
/// # Returns
///
/// * HBEngineSuccess on success, error code on failure
///
/// # Note
///
/// The shares_data must be serialized using ark_serialize compressed format.
/// Format: [num_shares: u32][share1_bytes][share2_bytes]...
#[no_mangle]
pub extern "C" fn hb_engine_init_client_input(
    engine_ptr: *mut HBEngineOpaque,
    client_id: u64,
    shares_data: *const u8,
    shares_len: usize,
) -> HBEngineErrorCode {
    use ark_bls12_381::Fr;
    use ark_serialize::CanonicalDeserialize;
    use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

    if engine_ptr.is_null() || shares_data.is_null() {
        return HBEngineErrorCode::HBEngineNullPointer;
    }

    let engine = unsafe { &*(engine_ptr as *const Arc<HoneyBadgerMpcEngine>) };
    let shares_bytes = unsafe { std::slice::from_raw_parts(shares_data, shares_len) };

    // Deserialize shares from bytes using ark_serialize
    // Format: [num_shares: u32][share1_bytes][share2_bytes]...
    if shares_len < 4 {
        return HBEngineErrorCode::HBEngineSerializationError;
    }
    let num_shares = u32::from_le_bytes([
        shares_bytes[0],
        shares_bytes[1],
        shares_bytes[2],
        shares_bytes[3],
    ]) as usize;
    let mut cursor = &shares_bytes[4..];
    let mut shares: Vec<RobustShare<Fr>> = Vec::with_capacity(num_shares);

    for _ in 0..num_shares {
        match RobustShare::<Fr>::deserialize_compressed(&mut cursor) {
            Ok(share) => shares.push(share),
            Err(_) => return HBEngineErrorCode::HBEngineSerializationError,
        }
    }

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return HBEngineErrorCode::HBEngineRuntimeError,
    };

    match rt.block_on(engine.init_client_input(client_id as usize, shares)) {
        Ok(()) => HBEngineErrorCode::HBEngineSuccess,
        Err(_) => HBEngineErrorCode::HBEngineClientInputFailed,
    }
}

#[cfg(feature = "honeybadger")]
/// Get shares for a specific client
///
/// # Arguments
///
/// * `engine_ptr` - Engine handle
/// * `client_id` - Client identifier
/// * `result_ptr` - Output: pointer to serialized shares (ark_serialize compressed format)
/// * `result_len_ptr` - Output: length of result
///
/// # Returns
///
/// * HBEngineSuccess on success, error code on failure
///
/// # Note
///
/// Caller must free the result bytes with hb_free_bytes.
/// Format: [num_shares: u32][share1_bytes][share2_bytes]...
#[no_mangle]
pub extern "C" fn hb_engine_get_client_shares(
    engine_ptr: *mut HBEngineOpaque,
    client_id: u64,
    result_ptr: *mut *mut u8,
    result_len_ptr: *mut usize,
) -> HBEngineErrorCode {
    use ark_serialize::CanonicalSerialize;

    if engine_ptr.is_null() || result_ptr.is_null() || result_len_ptr.is_null() {
        return HBEngineErrorCode::HBEngineNullPointer;
    }

    let engine = unsafe { &*(engine_ptr as *const Arc<HoneyBadgerMpcEngine>) };

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return HBEngineErrorCode::HBEngineRuntimeError,
    };

    match rt.block_on(engine.get_client_shares(client_id as usize)) {
        Ok(shares) => {
            // Serialize shares using ark_serialize
            // Format: [num_shares: u32][share1_bytes][share2_bytes]...
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&(shares.len() as u32).to_le_bytes());
            for share in &shares {
                if share.serialize_compressed(&mut bytes).is_err() {
                    return HBEngineErrorCode::HBEngineSerializationError;
                }
            }
            unsafe {
                write_ffi_result_bytes(bytes, result_ptr, result_len_ptr);
            }
            HBEngineErrorCode::HBEngineSuccess
        }
        Err(_) => HBEngineErrorCode::HBEngineGetClientSharesFailed,
    }
}

#[cfg(feature = "honeybadger")]
/// Get the party ID of the engine
#[no_mangle]
pub extern "C" fn hb_engine_party_id(engine_ptr: *mut HBEngineOpaque) -> usize {
    if engine_ptr.is_null() {
        return 0;
    }
    let engine = unsafe { &*(engine_ptr as *const Arc<HoneyBadgerMpcEngine>) };
    engine.party_id()
}

#[cfg(feature = "honeybadger")]
/// Get the instance ID of the engine
#[no_mangle]
pub extern "C" fn hb_engine_instance_id(engine_ptr: *mut HBEngineOpaque) -> u64 {
    if engine_ptr.is_null() {
        return 0;
    }
    let engine = unsafe { &*(engine_ptr as *const Arc<HoneyBadgerMpcEngine>) };
    engine.instance_id()
}

#[cfg(feature = "honeybadger")]
/// Get the protocol name (returns static string, do not free)
#[no_mangle]
pub extern "C" fn hb_engine_protocol_name(engine_ptr: *mut HBEngineOpaque) -> *const c_char {
    static PROTOCOL_NAME: &[u8] = b"honeybadger-mpc\0";
    if engine_ptr.is_null() {
        return std::ptr::null();
    }
    PROTOCOL_NAME.as_ptr() as *const c_char
}

#[cfg(feature = "honeybadger")]
/// Get the network handle from the engine
///
/// Returns a cloned network pointer. Caller must free with hb_network_free.
#[no_mangle]
pub extern "C" fn hb_engine_get_network(engine_ptr: *mut HBEngineOpaque) -> *mut HBNetworkOpaque {
    if engine_ptr.is_null() {
        return std::ptr::null_mut();
    }

    let engine = unsafe { &*(engine_ptr as *const Arc<HoneyBadgerMpcEngine>) };
    let net = engine.net();

    // Box the Arc for stable FFI pointer
    Box::into_raw(Box::new(net)) as *mut HBNetworkOpaque
}

#[cfg(feature = "honeybadger")]
/// Free a network handle obtained from hb_engine_get_network
#[no_mangle]
pub extern "C" fn hb_network_free(network_ptr: *mut HBNetworkOpaque) {
    if !network_ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(network_ptr as *mut Arc<QuicNetworkManager>);
        }
    }
}

#[cfg(feature = "honeybadger")]
/// Free bytes allocated by engine functions (e.g., multiply_share_async result)
#[no_mangle]
pub extern "C" fn hb_free_bytes(ptr: *mut u8, len: usize) {
    unsafe {
        free_ffi_result_bytes(ptr, len);
    }
}

// ============================================================================
// HoneyBadgerMpcEngine FFI - Unit Tests
// ============================================================================

#[cfg(all(test, feature = "honeybadger"))]
mod hb_engine_tests {
    use super::*;

    #[test]
    fn test_share_type_conversion_int() {
        let c_int = CShareType { kind: 0, width: 64 };
        let st: ShareType = c_int.into();
        assert!(matches!(st, ShareType::SecretInt { bit_length: 64 }));
    }

    #[test]
    fn test_share_type_conversion_bool() {
        // Both width values should result in boolean (1-bit SecretInt)
        let c_bool_true = CShareType { kind: 1, width: 1 };
        let st: ShareType = c_bool_true.into();
        assert!(matches!(st, ShareType::SecretInt { bit_length: 1 }));

        let c_bool_false = CShareType { kind: 1, width: 0 };
        let st: ShareType = c_bool_false.into();
        assert!(matches!(st, ShareType::SecretInt { bit_length: 1 }));
    }

    #[test]
    fn test_share_type_conversion_float() {
        let c_float = CShareType { kind: 2, width: 42 };
        let st: ShareType = c_float.into();
        assert!(matches!(st, ShareType::SecretFixedPoint { .. }));
    }

    #[test]
    fn test_null_pointer_handling() {
        assert_eq!(
            hb_engine_start_async(std::ptr::null_mut()),
            HBEngineErrorCode::HBEngineNullPointer
        );

        assert_eq!(hb_engine_is_ready(std::ptr::null_mut()), 0);
        assert!(hb_engine_get_network(std::ptr::null_mut()).is_null());
        assert_eq!(hb_engine_party_id(std::ptr::null_mut()), 0);
        assert_eq!(hb_engine_instance_id(std::ptr::null_mut()), 0);
        assert!(hb_engine_protocol_name(std::ptr::null_mut()).is_null());
    }

    #[test]
    fn test_hb_engine_new_null_network() {
        let engine = hb_engine_new(1, 0, 5, 1, 8, 16, std::ptr::null_mut());
        assert!(engine.is_null());
    }

    #[test]
    fn test_hb_engine_free_null() {
        // Should not crash
        hb_engine_free(std::ptr::null_mut());
    }

    #[test]
    fn test_hb_network_free_null() {
        // Should not crash
        hb_network_free(std::ptr::null_mut());
    }

    #[test]
    fn test_hb_free_bytes_null() {
        // Should not crash
        hb_free_bytes(std::ptr::null_mut(), 0);
        hb_free_bytes(std::ptr::null_mut(), 10);
    }
}

// ============================================================================
// AVSS Engine FFI Types and Functions
//
// FFI function and type names use the `adkg_` / `Adkg` prefix for ABI
// compatibility with existing C/SDK consumers. Internally, this is the AVSS
// (Asynchronously Verifiable Secret Sharing) engine.
// ============================================================================

#[cfg(feature = "avss")]
mod avss_ffi {
    use super::*;
    use crate::net::avss_engine::{AvssMpcEngine, AvssOperations};
    use crate::net::mpc_engine::MpcEngine;
    use ark_serialize::CanonicalDeserialize;
    use ark_std::rand::SeedableRng;
    use std::future::Future;
    use std::sync::Arc;
    use stoffelnet::transports::quic::QuicNetworkManager;

    fn block_on_avss<Fut, T>(fut: Fut) -> Result<T, String>
    where
        Fut: Future<Output = Result<T, String>> + Send + 'static,
        T: Send + 'static,
    {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) =>
            {
                #[allow(deprecated)]
                match handle.runtime_flavor() {
                    tokio::runtime::RuntimeFlavor::MultiThread => {
                        tokio::task::block_in_place(|| handle.block_on(fut))
                    }
                    tokio::runtime::RuntimeFlavor::CurrentThread => std::thread::spawn(move || {
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .map_err(|e| format!("failed to build tokio runtime: {}", e))?;
                        rt.block_on(fut)
                    })
                    .join()
                    .map_err(|_| "thread panicked in block_on_avss".to_string())?,
                    _ => Err("unsupported tokio runtime flavor".to_string()),
                }
            }
            Err(_) => {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("failed to build tokio runtime: {}", e))?;
                rt.block_on(fut)
            }
        }
    }

    /// C-compatible curve configuration for AVSS.
    /// Variants are constructed by C/SDK callers via integer discriminants.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[allow(dead_code)]
    pub enum CAdkgCurveConfig {
        Bls12_381 = 0,
        Bn254 = 1,
        Curve25519 = 2,
        Ed25519 = 3,
    }

    impl CAdkgCurveConfig {
        fn from_ffi(value: u32) -> Option<Self> {
            match value {
                0 => Some(CAdkgCurveConfig::Bls12_381),
                1 => Some(CAdkgCurveConfig::Bn254),
                2 => Some(CAdkgCurveConfig::Curve25519),
                3 => Some(CAdkgCurveConfig::Ed25519),
                _ => None,
            }
        }
    }

    /// Internal wrapper that erases the generic (F, G) types behind trait objects.
    /// The opaque pointer stores a `Box<AvssFfiWrapper>`.
    struct AvssFfiWrapper {
        engine: Arc<dyn MpcEngine>,
        avss_ops: Arc<dyn AvssOperations + Send + Sync>,
    }

    /// Opaque pointer type for AvssMpcEngine
    #[repr(C)]
    pub struct AdkgEngineOpaque {
        _data: (),
        _marker: core::marker::PhantomData<(*mut u8, PhantomPinned)>,
    }

    /// Error codes for AVSS engine FFI operations.
    /// Variants are matched by C/SDK callers via integer discriminants.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[allow(dead_code)]
    pub enum AdkgEngineErrorCode {
        /// Operation succeeded
        Success = 0,
        /// Null pointer provided
        NullPointer = 1,
        /// Engine not ready
        NotReady = 2,
        /// Key generation failed
        KeyGenFailed = 3,
        /// Serialization error
        SerializationError = 4,
        /// Session not found
        SessionNotFound = 5,
        /// Invalid commitment index
        InvalidCommitmentIndex = 6,
        /// Tokio runtime creation failed
        RuntimeError = 7,
        /// Invalid curve configuration
        InvalidCurveConfig = 8,
    }

    /// Generic helper: deserialize keys, create an `AvssMpcEngine<F, G>`, and wrap it.
    fn create_engine_inner<F, G>(
        instance_id: u64,
        party_id: usize,
        n: usize,
        t: usize,
        net: Arc<QuicNetworkManager>,
        sk_bytes: &[u8],
        pk_bytes: &[u8],
    ) -> Result<AvssFfiWrapper, String>
    where
        F: crate::net::curve::SupportedMpcField + ark_std::UniformRand,
        G: ark_ec::CurveGroup<ScalarField = F> + Send + Sync + 'static,
    {
        let sk_i: F = if sk_bytes.is_empty() {
            let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
            F::rand(&mut rng)
        } else {
            CanonicalDeserialize::deserialize_compressed(sk_bytes)
                .map_err(|e| format!("failed to deserialize secret key: {}", e))?
        };

        let pk_map: Vec<G> = Vec::<G>::deserialize_compressed(pk_bytes)
            .map_err(|e| format!("failed to deserialize public key map: {}", e))?;
        if pk_map.len() != n {
            return Err(format!(
                "public key map length {} does not match n={}",
                pk_map.len(),
                n
            ));
        }

        let engine = block_on_avss(AvssMpcEngine::<F, G>::new(
            instance_id,
            party_id,
            n,
            t,
            net,
            sk_i,
            Arc::new(pk_map),
        ))?;

        let engine_arc: Arc<AvssMpcEngine<F, G>> = engine;
        Ok(AvssFfiWrapper {
            engine: engine_arc.clone() as Arc<dyn MpcEngine>,
            avss_ops: engine_arc as Arc<dyn AvssOperations + Send + Sync>,
        })
    }

    fn create_bls12381_engine(
        instance_id: u64,
        party_id: usize,
        n: usize,
        t: usize,
        net: Arc<QuicNetworkManager>,
        sk_bytes: &[u8],
        pk_bytes: &[u8],
    ) -> Result<AvssFfiWrapper, String> {
        create_engine_inner::<ark_bls12_381::Fr, ark_bls12_381::G1Projective>(
            instance_id,
            party_id,
            n,
            t,
            net,
            sk_bytes,
            pk_bytes,
        )
    }

    fn create_bn254_engine(
        instance_id: u64,
        party_id: usize,
        n: usize,
        t: usize,
        net: Arc<QuicNetworkManager>,
        sk_bytes: &[u8],
        pk_bytes: &[u8],
    ) -> Result<AvssFfiWrapper, String> {
        create_engine_inner::<ark_bn254::Fr, ark_bn254::G1Projective>(
            instance_id,
            party_id,
            n,
            t,
            net,
            sk_bytes,
            pk_bytes,
        )
    }

    fn create_curve25519_engine(
        instance_id: u64,
        party_id: usize,
        n: usize,
        t: usize,
        net: Arc<QuicNetworkManager>,
        sk_bytes: &[u8],
        pk_bytes: &[u8],
    ) -> Result<AvssFfiWrapper, String> {
        create_engine_inner::<ark_curve25519::Fr, ark_curve25519::EdwardsProjective>(
            instance_id,
            party_id,
            n,
            t,
            net,
            sk_bytes,
            pk_bytes,
        )
    }

    fn create_ed25519_engine(
        instance_id: u64,
        party_id: usize,
        n: usize,
        t: usize,
        net: Arc<QuicNetworkManager>,
        sk_bytes: &[u8],
        pk_bytes: &[u8],
    ) -> Result<AvssFfiWrapper, String> {
        create_engine_inner::<ark_ed25519::Fr, ark_ed25519::EdwardsProjective>(
            instance_id,
            party_id,
            n,
            t,
            net,
            sk_bytes,
            pk_bytes,
        )
    }

    /// Creates a new AVSS engine
    ///
    /// # Arguments
    /// * `instance_id` - Unique instance identifier
    /// * `party_id` - This party's ID (0 to n-1)
    /// * `n` - Total number of parties
    /// * `t` - Threshold
    /// * `network_ptr` - Pointer to a QuicNetworkManager (same opaque type as HB)
    /// * `curve_config` - Curve configuration (0 = BLS12-381, 1 = BN254, 2 = Curve25519, 3 = Ed25519)
    /// * `sk_bytes` - Secret key bytes (serialized Fr element), or null for random key
    /// * `sk_len` - Length of secret key bytes
    /// * `pk_map_ptr` - Pointer to serialized public key map (required, must not be null)
    /// * `pk_map_len` - Length of public key map bytes (must be > 0)
    ///
    /// # Returns
    /// Pointer to opaque engine handle, or null on failure
    #[no_mangle]
    pub extern "C" fn adkg_engine_new(
        instance_id: u64,
        party_id: usize,
        n: usize,
        t: usize,
        network_ptr: *mut c_void,
        curve_config: u32,
        sk_bytes: *const u8,
        sk_len: usize,
        pk_map_ptr: *const u8,
        pk_map_len: usize,
    ) -> *mut AdkgEngineOpaque {
        if network_ptr.is_null() {
            return std::ptr::null_mut();
        }
        if pk_map_ptr.is_null() || pk_map_len == 0 {
            return std::ptr::null_mut();
        }

        // Extract network from opaque pointer
        let net: Arc<QuicNetworkManager> = unsafe {
            let boxed = &*(network_ptr as *const Arc<QuicNetworkManager>);
            Arc::clone(boxed)
        };

        let sk_slice = if sk_bytes.is_null() || sk_len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(sk_bytes, sk_len) }
        };

        let pk_slice = unsafe { std::slice::from_raw_parts(pk_map_ptr, pk_map_len) };

        let curve_config = match CAdkgCurveConfig::from_ffi(curve_config) {
            Some(config) => config,
            None => return std::ptr::null_mut(),
        };

        let wrapper = match curve_config {
            CAdkgCurveConfig::Bls12_381 => {
                create_bls12381_engine(instance_id, party_id, n, t, net, sk_slice, pk_slice)
            }
            CAdkgCurveConfig::Bn254 => {
                create_bn254_engine(instance_id, party_id, n, t, net, sk_slice, pk_slice)
            }
            CAdkgCurveConfig::Curve25519 => {
                create_curve25519_engine(instance_id, party_id, n, t, net, sk_slice, pk_slice)
            }
            CAdkgCurveConfig::Ed25519 => {
                create_ed25519_engine(instance_id, party_id, n, t, net, sk_slice, pk_slice)
            }
        };

        match wrapper {
            Ok(w) => {
                if let Err(e) = w.engine.start() {
                    eprintln!("adkg_engine_new: engine start failed: {}", e);
                    return std::ptr::null_mut();
                }
                Box::into_raw(Box::new(w)) as *mut AdkgEngineOpaque
            }
            Err(e) => {
                eprintln!("adkg_engine_new: {}", e);
                std::ptr::null_mut()
            }
        }
    }

    /// Frees an AVSS engine instance
    #[no_mangle]
    pub extern "C" fn adkg_engine_free(engine_ptr: *mut AdkgEngineOpaque) {
        if !engine_ptr.is_null() {
            unsafe {
                let _ = Box::from_raw(engine_ptr as *mut AvssFfiWrapper);
            }
        }
    }

    /// Helper to get the wrapper from an opaque pointer
    unsafe fn get_wrapper<'a>(ptr: *mut AdkgEngineOpaque) -> &'a AvssFfiWrapper {
        &*(ptr as *const AvssFfiWrapper)
    }

    unsafe fn write_boxed_result_bytes(
        bytes: Vec<u8>,
        result_ptr: *mut *mut u8,
        result_len_ptr: *mut usize,
    ) {
        // Delegate to the shared helper at module scope.
        write_ffi_result_bytes(bytes, result_ptr, result_len_ptr);
    }

    /// Generates a new distributed share under the given key name
    ///
    /// Returns serialized share bytes via out parameters on success.
    /// Caller must free result bytes with adkg_free_bytes.
    #[no_mangle]
    pub extern "C" fn adkg_engine_generate_share(
        engine_ptr: *mut AdkgEngineOpaque,
        key_name: *const c_char,
        result_ptr: *mut *mut u8,
        result_len_ptr: *mut usize,
    ) -> AdkgEngineErrorCode {
        if engine_ptr.is_null()
            || key_name.is_null()
            || result_ptr.is_null()
            || result_len_ptr.is_null()
        {
            return AdkgEngineErrorCode::NullPointer;
        }

        let wrapper = unsafe { get_wrapper(engine_ptr) };

        let c_str = unsafe { CStr::from_ptr(key_name) };
        let key_name_str = match c_str.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return AdkgEngineErrorCode::SerializationError,
        };

        let avss_ops = Arc::clone(&wrapper.avss_ops);
        match block_on_avss(async move { avss_ops.avss_generate_share(key_name_str).await }) {
            Ok(share_bytes) => {
                unsafe {
                    write_boxed_result_bytes(share_bytes, result_ptr, result_len_ptr);
                }
                AdkgEngineErrorCode::Success
            }
            Err(_) => AdkgEngineErrorCode::KeyGenFailed,
        }
    }

    /// Get the public key for a stored share by key name
    ///
    /// Caller must free result bytes with adkg_free_bytes.
    #[no_mangle]
    pub extern "C" fn adkg_engine_get_public_key(
        engine_ptr: *mut AdkgEngineOpaque,
        key_name: *const c_char,
        result_ptr: *mut *mut u8,
        result_len_ptr: *mut usize,
    ) -> AdkgEngineErrorCode {
        if engine_ptr.is_null()
            || key_name.is_null()
            || result_ptr.is_null()
            || result_len_ptr.is_null()
        {
            return AdkgEngineErrorCode::NullPointer;
        }

        let wrapper = unsafe { get_wrapper(engine_ptr) };

        let c_str = unsafe { CStr::from_ptr(key_name) };
        let key_name_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => return AdkgEngineErrorCode::SerializationError,
        };

        match wrapper.avss_ops.avss_get_public_key(key_name_str) {
            Ok(bytes) => {
                unsafe {
                    write_boxed_result_bytes(bytes, result_ptr, result_len_ptr);
                }
                AdkgEngineErrorCode::Success
            }
            Err(_) => AdkgEngineErrorCode::SessionNotFound,
        }
    }

    /// Get a commitment at a specific index for a stored share by key name
    ///
    /// Caller must free result bytes with adkg_free_bytes.
    #[no_mangle]
    pub extern "C" fn adkg_engine_get_commitment(
        engine_ptr: *mut AdkgEngineOpaque,
        key_name: *const c_char,
        index: usize,
        result_ptr: *mut *mut u8,
        result_len_ptr: *mut usize,
    ) -> AdkgEngineErrorCode {
        if engine_ptr.is_null()
            || key_name.is_null()
            || result_ptr.is_null()
            || result_len_ptr.is_null()
        {
            return AdkgEngineErrorCode::NullPointer;
        }

        let wrapper = unsafe { get_wrapper(engine_ptr) };

        let c_str = unsafe { CStr::from_ptr(key_name) };
        let key_name_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => return AdkgEngineErrorCode::SerializationError,
        };

        match wrapper.avss_ops.avss_get_commitment(key_name_str, index) {
            Ok(bytes) => {
                unsafe {
                    write_boxed_result_bytes(bytes, result_ptr, result_len_ptr);
                }
                AdkgEngineErrorCode::Success
            }
            Err(_) => AdkgEngineErrorCode::InvalidCommitmentIndex,
        }
    }

    /// Check if the engine is ready
    #[no_mangle]
    pub extern "C" fn adkg_engine_is_ready(engine_ptr: *mut AdkgEngineOpaque) -> c_int {
        if engine_ptr.is_null() {
            return 0;
        }
        let wrapper = unsafe { get_wrapper(engine_ptr) };
        if wrapper.engine.is_ready() {
            1
        } else {
            0
        }
    }

    /// Get the party ID
    #[no_mangle]
    pub extern "C" fn adkg_engine_party_id(engine_ptr: *mut AdkgEngineOpaque) -> usize {
        if engine_ptr.is_null() {
            return 0;
        }
        let wrapper = unsafe { get_wrapper(engine_ptr) };
        wrapper.engine.party_id()
    }

    /// Get the protocol name (returns static string, do not free)
    #[no_mangle]
    pub extern "C" fn adkg_engine_protocol_name(
        engine_ptr: *mut AdkgEngineOpaque,
    ) -> *const c_char {
        static PROTOCOL_NAME: &[u8] = b"avss\0";
        if engine_ptr.is_null() {
            return std::ptr::null();
        }
        PROTOCOL_NAME.as_ptr() as *const c_char
    }

    /// Free bytes allocated by AVSS engine functions
    #[no_mangle]
    pub extern "C" fn adkg_free_bytes(ptr: *mut u8, len: usize) {
        unsafe {
            free_ffi_result_bytes(ptr, len);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ark_bls12_381::G1Projective;
        use ark_ec::PrimeGroup;
        use ark_serialize::CanonicalSerialize;
        use std::sync::Arc;
        use stoffelnet::transports::quic::QuicNetworkManager;

        #[test]
        fn test_adkg_engine_new_null_network() {
            let engine = adkg_engine_new(
                1,
                0,
                5,
                1,
                std::ptr::null_mut(),
                CAdkgCurveConfig::Bls12_381 as u32,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
            );
            assert!(engine.is_null());
        }

        #[test]
        fn test_adkg_engine_new_invalid_curve_config_rejected() {
            let n = 4usize;
            let net = Arc::new(QuicNetworkManager::new());
            let mut pk_map_bytes = Vec::new();
            vec![G1Projective::generator(); n]
                .serialize_compressed(&mut pk_map_bytes)
                .expect("serialize pk map");
            let net_ptr = &net as *const Arc<QuicNetworkManager> as *mut c_void;

            let engine = adkg_engine_new(
                1,
                0,
                n,
                1,
                net_ptr,
                99,
                std::ptr::null(),
                0,
                pk_map_bytes.as_ptr(),
                pk_map_bytes.len(),
            );
            assert!(engine.is_null(), "invalid curve config must be rejected");
        }

        #[test]
        fn test_adkg_engine_new_null_pk_map_rejected() {
            let net = Arc::new(QuicNetworkManager::new());
            let net_ptr = &net as *const Arc<QuicNetworkManager> as *mut c_void;

            let engine = adkg_engine_new(
                1,
                0,
                4,
                1,
                net_ptr,
                CAdkgCurveConfig::Bls12_381 as u32,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
            );
            assert!(
                engine.is_null(),
                "constructor must reject null/empty public key map"
            );
        }

        #[test]
        fn test_adkg_engine_new_without_tokio_runtime() {
            let n = 4usize;
            let net = Arc::new(QuicNetworkManager::new());
            let mut pk_map_bytes = Vec::new();
            vec![G1Projective::generator(); n]
                .serialize_compressed(&mut pk_map_bytes)
                .expect("serialize pk map");
            let net_ptr = &net as *const Arc<QuicNetworkManager> as *mut c_void;

            let engine = adkg_engine_new(
                1,
                0,
                n,
                1,
                net_ptr,
                CAdkgCurveConfig::Bls12_381 as u32,
                std::ptr::null(),
                0,
                pk_map_bytes.as_ptr(),
                pk_map_bytes.len(),
            );
            assert!(
                !engine.is_null(),
                "constructor should succeed without an ambient Tokio runtime"
            );
            adkg_engine_free(engine);
        }

        #[test]
        fn test_adkg_engine_free_null() {
            adkg_engine_free(std::ptr::null_mut());
        }

        #[test]
        fn test_adkg_engine_is_ready_null() {
            assert_eq!(adkg_engine_is_ready(std::ptr::null_mut()), 0);
        }

        #[test]
        fn test_adkg_engine_party_id_null() {
            assert_eq!(adkg_engine_party_id(std::ptr::null_mut()), 0);
        }

        #[test]
        fn test_adkg_engine_protocol_name_null() {
            assert!(adkg_engine_protocol_name(std::ptr::null_mut()).is_null());
        }

        #[test]
        fn test_adkg_free_bytes_null() {
            adkg_free_bytes(std::ptr::null_mut(), 0);
            adkg_free_bytes(std::ptr::null_mut(), 10);
        }
    }
}
