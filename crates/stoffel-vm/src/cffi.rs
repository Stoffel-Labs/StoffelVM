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
use std::mem::ManuallyDrop;
use std::os::raw::{c_int, c_void};
use std::sync::{Arc, Mutex};

use stoffel_vm_types::compiled_binary::CompiledBinary;
use stoffel_vm_types::core_types::{ShareType, Value};
use crate::core_vm::VirtualMachine;
use crate::foreign_functions::ForeignFunctionContext;
use crate::net::hb_engine::HoneyBadgerMpcEngine;
use crate::net::mpc_engine::MpcEngine;
use stoffelnet::transports::quic::QuicNetworkManager;

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
pub type CForeignFunction = extern "C" fn(
    args: *const StoffelValue,
    arg_count: c_int,
    result: *mut StoffelValue,
) -> c_int;

// ============================================================================
// HoneyBadgerMpcEngine FFI Types
// ============================================================================

/// Opaque pointer type for HoneyBadgerMpcEngine
///
/// This type is used to pass engine handles across the FFI boundary.
/// The actual `Arc<HoneyBadgerMpcEngine>` is stored inside a Box for stable pointer.
#[repr(C)]
pub struct HBEngineOpaque {
    _data: (),
    _marker: core::marker::PhantomData<(*mut u8, PhantomPinned)>,
}

/// Opaque pointer type for QuicNetworkManager
///
/// This type is used to pass network handles across the FFI boundary.
#[repr(C)]
pub struct HBNetworkOpaque {
    _data: (),
    _marker: core::marker::PhantomData<(*mut u8, PhantomPinned)>,
}

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
            0 => ShareType::Int(c.width),
            1 => ShareType::Bool(c.width != 0),
            2 => ShareType::Float(c.width),
            _ => ShareType::Int(c.width), // Default fallback
        }
    }
}

impl From<ShareType> for CShareType {
    fn from(st: ShareType) -> Self {
        match st {
            ShareType::Int(w) => CShareType { kind: 0, width: w },
            ShareType::Bool(b) => CShareType { kind: 1, width: if b { 1 } else { 0 } },
            ShareType::Float(w) => CShareType { kind: 2, width: w },
            ShareType::I32(v) => CShareType { kind: 0, width: v as i64 },
            ShareType::I16(v) => CShareType { kind: 0, width: v as i64 },
            ShareType::I8(v) => CShareType { kind: 0, width: v as i64 },
            ShareType::U8(v) => CShareType { kind: 0, width: v as i64 },
            ShareType::U16(v) => CShareType { kind: 0, width: v as i64 },
            ShareType::U32(v) => CShareType { kind: 0, width: v as i64 },
            ShareType::U64(v) => CShareType { kind: 0, width: v as i64 },
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
        Ok(value) => {
            unsafe {
                *result = value_to_stoffel_value(&value);
            }
            0
        }
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
    if handle.is_null() || function_name.is_null() || (arg_count > 0 && args.is_null()) || result.is_null() {
        return -1;
    }

    let vm = unsafe { &mut *(handle as *mut VirtualMachine) };
    let c_str = unsafe { CStr::from_ptr(function_name) };
    let function_name = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

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
        Ok(value) => {
            unsafe {
                *result = value_to_stoffel_value(&value);
            }
            0
        }
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
            .map(|arg| value_to_stoffel_value(arg))
            .collect();

        let mut result = StoffelValue {
            value_type: StoffelValueType::Unit,
            data: StoffelValueData { int_val: 0 },
        };

        // Call the C function
        let status = (self.func)(
            c_args.as_ptr(),
            c_args.len() as c_int,
            &mut result,
        );

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

    vm.register_foreign_function(name, move |ctx| {
        wrapper.call(ctx)
    });

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
    unsafe {
        *result = value_to_stoffel_value(&value);
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

    unsafe {
        *result = value_to_stoffel_value(&value);
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
/// A C-compatible StoffelValue
fn value_to_stoffel_value(value: &Value) -> StoffelValue {
    match value {
        Value::Unit => StoffelValue {
            value_type: StoffelValueType::Unit,
            data: StoffelValueData { int_val: 0 },
        },
        Value::I64(n) => StoffelValue {
            value_type: StoffelValueType::Int,
            data: StoffelValueData { int_val: *n },
        },
        Value::Float(f) => StoffelValue {
            value_type: StoffelValueType::Float,
            data: StoffelValueData { float_val: *f as f64 },
        },
        Value::Bool(b) => StoffelValue {
            value_type: StoffelValueType::Bool,
            data: StoffelValueData { bool_val: *b },
        },
        Value::String(s) => {
            // Note: This creates a memory leak as we're not freeing the CString
            // In a real implementation, you would need to handle this properly
            let c_string = CString::new(s.clone()).unwrap_or_default();
            let ptr = c_string.into_raw();
            StoffelValue {
                value_type: StoffelValueType::String,
                data: StoffelValueData { string_val: ptr },
            }
        },
        Value::Object(id) => StoffelValue {
            value_type: StoffelValueType::Object,
            data: StoffelValueData { object_id: *id },
        },
        Value::Array(id) => StoffelValue {
            value_type: StoffelValueType::Array,
            data: StoffelValueData { array_id: *id },
        },
        Value::Foreign(id) => StoffelValue {
            value_type: StoffelValueType::Foreign,
            data: StoffelValueData { foreign_id: *id },
        },
        Value::Closure(_) => StoffelValue {
            value_type: StoffelValueType::Closure,
            data: StoffelValueData { closure_id: 0 }, // Simplified
        },
        _ => panic!("Invalid value type"),
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
        StoffelValueType::Float => unsafe { Ok(Value::Float(value.data.float_val as i64)) },
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

    match HoneyBadgerMpcEngine::new(instance_id, party_id, n, t, n_triples, n_random, net) {
        Ok(engine) => {
            // engine is Arc<HoneyBadgerMpcEngine>, box it for stable FFI pointer
            Box::into_raw(Box::new(engine)) as *mut HBEngineOpaque
        }
        Err(_) => std::ptr::null_mut(),
    }
}

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
    if engine.is_ready() { 1 } else { 0 }
}

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
    if engine_ptr.is_null() || left_ptr.is_null() || right_ptr.is_null()
       || result_ptr.is_null() || result_len_ptr.is_null() {
        return HBEngineErrorCode::HBEngineNullPointer;
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
            let mut result = ManuallyDrop::new(result);
            unsafe {
                *result_ptr = result.as_mut_ptr();
                *result_len_ptr = result.len();
            }
            HBEngineErrorCode::HBEngineSuccess
        }
        Err(_) => HBEngineErrorCode::HBEngineMultiplyFailed,
    }
}

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

    let engine = unsafe { &*(engine_ptr as *const Arc<HoneyBadgerMpcEngine>) };
    let share_bytes = unsafe { std::slice::from_raw_parts(share_ptr, share_len) };
    let ty: ShareType = share_type.into();

    // open_share is sync in the current implementation (uses global registry)
    match engine.open_share(ty, share_bytes) {
        Ok(value) => {
            unsafe {
                *result_ptr = value_to_stoffel_value(&value);
            }
            HBEngineErrorCode::HBEngineSuccess
        }
        Err(_) => HBEngineErrorCode::HBEngineOpenShareFailed,
    }
}

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
    use ark_serialize::CanonicalDeserialize;
    use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
    use ark_bls12_381::Fr;

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
    let num_shares = u32::from_le_bytes([shares_bytes[0], shares_bytes[1], shares_bytes[2], shares_bytes[3]]) as usize;
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
            let mut bytes = ManuallyDrop::new(bytes);
            unsafe {
                *result_ptr = bytes.as_mut_ptr();
                *result_len_ptr = bytes.len();
            }
            HBEngineErrorCode::HBEngineSuccess
        }
        Err(_) => HBEngineErrorCode::HBEngineGetClientSharesFailed,
    }
}

/// Get the party ID of the engine
#[no_mangle]
pub extern "C" fn hb_engine_party_id(engine_ptr: *mut HBEngineOpaque) -> usize {
    if engine_ptr.is_null() {
        return 0;
    }
    let engine = unsafe { &*(engine_ptr as *const Arc<HoneyBadgerMpcEngine>) };
    engine.party_id()
}

/// Get the instance ID of the engine
#[no_mangle]
pub extern "C" fn hb_engine_instance_id(engine_ptr: *mut HBEngineOpaque) -> u64 {
    if engine_ptr.is_null() {
        return 0;
    }
    let engine = unsafe { &*(engine_ptr as *const Arc<HoneyBadgerMpcEngine>) };
    engine.instance_id()
}

/// Get the protocol name (returns static string, do not free)
#[no_mangle]
pub extern "C" fn hb_engine_protocol_name(engine_ptr: *mut HBEngineOpaque) -> *const c_char {
    static PROTOCOL_NAME: &[u8] = b"honeybadger-mpc\0";
    if engine_ptr.is_null() {
        return std::ptr::null();
    }
    PROTOCOL_NAME.as_ptr() as *const c_char
}

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

/// Free a network handle obtained from hb_engine_get_network
#[no_mangle]
pub extern "C" fn hb_network_free(network_ptr: *mut HBNetworkOpaque) {
    if !network_ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(network_ptr as *mut Arc<QuicNetworkManager>);
        }
    }
}

/// Free bytes allocated by engine functions (e.g., multiply_share_async result)
#[no_mangle]
pub extern "C" fn hb_free_bytes(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        unsafe {
            let _ = Vec::from_raw_parts(ptr, len, len);
        }
    }
}

// ============================================================================
// HoneyBadgerMpcEngine FFI - Unit Tests
// ============================================================================

#[cfg(test)]
mod hb_engine_tests {
    use super::*;

    #[test]
    fn test_share_type_conversion_int() {
        let c_int = CShareType { kind: 0, width: 64 };
        let st: ShareType = c_int.into();
        assert!(matches!(st, ShareType::Int(64)));
    }

    #[test]
    fn test_share_type_conversion_bool() {
        let c_bool_true = CShareType { kind: 1, width: 1 };
        let st: ShareType = c_bool_true.into();
        assert!(matches!(st, ShareType::Bool(true)));

        let c_bool_false = CShareType { kind: 1, width: 0 };
        let st: ShareType = c_bool_false.into();
        assert!(matches!(st, ShareType::Bool(false)));
    }

    #[test]
    fn test_share_type_conversion_float() {
        let c_float = CShareType { kind: 2, width: 42 };
        let st: ShareType = c_float.into();
        assert!(matches!(st, ShareType::Float(42)));
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
