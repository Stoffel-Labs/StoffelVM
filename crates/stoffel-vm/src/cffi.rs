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
use std::os::raw::{c_int, c_void};
use std::sync::{Arc, Mutex};

use stoffel_vm_types::core_types::Value;
use crate::core_vm::VirtualMachine;
use crate::foreign_functions::ForeignFunctionContext;

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
