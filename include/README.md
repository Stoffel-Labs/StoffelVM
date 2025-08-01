# StoffelVM C Foreign Function Interface (CFFI)

This directory contains the C API for StoffelVM, allowing you to use the VM from C, C++, and other languages that support C FFI.

## Overview

The StoffelVM CFFI layer provides a bridge between the Rust implementation of StoffelVM and other programming languages. It allows you to:

- Create and manage VM instances
- Register foreign functions with the VM
- Execute VM functions and retrieve results
- Convert between VM and C-compatible types

## Getting Started

### Building the Library

To build the StoffelVM library with CFFI support:

```bash
# Clone the repository
git clone https://github.com/your-org/stoffelvm.git
cd stoffelvm

# Build the library (including the C API)
cargo build --release
```

This will generate a dynamic library (`libstoffel_vm.so` on Linux, `libstoffel_vm.dylib` on macOS, or `stoffel_vm.dll` on Windows) in the `target/release` directory.

### Using the Library from C

1. Include the header file in your C code:

```c
#include "stoffel_vm.h"
```

2. Compile your C code with the StoffelVM library:

```bash
gcc -o my_program my_program.c -L/path/to/stoffel_vm/target/release -lstoffel_vm
```

3. Make sure the library is in your library path when running your program:

```bash
# Linux
export LD_LIBRARY_PATH=/path/to/stoffel_vm/target/release:$LD_LIBRARY_PATH

# macOS
export DYLD_LIBRARY_PATH=/path/to/stoffel_vm/target/release:$DYLD_LIBRARY_PATH

# Windows
# Add the directory to your PATH environment variable
```

## API Reference

See the `stoffel_vm.h` header file for the complete API reference. Here's a summary of the main functions:

- `VMHandle stoffel_create_vm(void)`: Creates a new VM instance
- `void stoffel_destroy_vm(VMHandle handle)`: Destroys a VM instance
- `int stoffel_execute(VMHandle handle, const char* function_name, StoffelValue* result)`: Executes a VM function
- `int stoffel_execute_with_args(VMHandle handle, const char* function_name, const StoffelValue* args, int arg_count, StoffelValue* result)`: Executes a VM function with arguments
- `int stoffel_register_foreign_function(VMHandle handle, const char* name, CForeignFunction func)`: Registers a C function with the VM
- `int stoffel_register_foreign_object(VMHandle handle, void* object, StoffelValue* result)`: Registers a foreign object with the VM
- `int stoffel_create_string(VMHandle handle, const char* str, StoffelValue* result)`: Creates a new string in the VM
- `void stoffel_free_string(char* str)`: Frees a string created by the VM

## Example

See the `examples/c_ffi_example.c` file for a complete example of using the StoffelVM CFFI layer from C.

Here's a simple example of creating a VM, registering a function, and executing it:

```c
#include <stdio.h>
#include "stoffel_vm.h"

// Example C callback function
int double_value(const StoffelValue* args, int arg_count, StoffelValue* result) {
    if (arg_count != 1 || args[0].value_type != STOFFEL_VALUE_INT) {
        return -1; // Error
    }
    
    result->value_type = STOFFEL_VALUE_INT;
    result->data.int_val = args[0].data.int_val * 2;
    return 0; // Success
}

int main() {
    // Create a VM instance
    VMHandle vm = stoffel_create_vm();
    
    // Register a foreign function
    stoffel_register_foreign_function(vm, "double", double_value);
    
    // Execute a VM function
    StoffelValue arg;
    arg.value_type = STOFFEL_VALUE_INT;
    arg.data.int_val = 21;
    
    StoffelValue result;
    int status = stoffel_execute_with_args(vm, "double", &arg, 1, &result);
    
    if (status == 0 && result.value_type == STOFFEL_VALUE_INT) {
        printf("Result: %lld\n", (long long)result.data.int_val);
    }
    
    // Clean up
    stoffel_destroy_vm(vm);
    
    return 0;
}
```

## Using from Other Languages

### Python (using ctypes)

```python
import ctypes
from ctypes import c_void_p, c_char_p, c_int, c_int64, Structure, Union, POINTER

# Load the library
lib = ctypes.cdll.LoadLibrary("libstoffel_vm.so")  # Adjust path as needed

# Define the types
class StoffelValueType(ctypes.c_int):
    UNIT = 0
    INT = 1
    FLOAT = 2
    BOOL = 3
    STRING = 4
    OBJECT = 5
    ARRAY = 6
    FOREIGN = 7
    CLOSURE = 8

class StoffelValueData(Union):
    _fields_ = [
        ("int_val", c_int64),
        ("float_val", ctypes.c_double),
        ("bool_val", ctypes.c_int),
        ("string_val", c_char_p),
        ("object_id", ctypes.c_size_t),
        ("array_id", ctypes.c_size_t),
        ("foreign_id", ctypes.c_size_t),
        ("closure_id", ctypes.c_size_t),
    ]

class StoffelValue(Structure):
    _fields_ = [
        ("value_type", StoffelValueType),
        ("data", StoffelValueData),
    ]

# Set up function signatures
lib.stoffel_create_vm.restype = c_void_p
lib.stoffel_destroy_vm.argtypes = [c_void_p]
lib.stoffel_execute.argtypes = [c_void_p, c_char_p, POINTER(StoffelValue)]
lib.stoffel_execute.restype = c_int

# Use the VM
vm = lib.stoffel_create_vm()
# ... use the VM ...
lib.stoffel_destroy_vm(vm)
```

### Go (using cgo)

```go
package main

/*
#cgo LDFLAGS: -L/path/to/stoffel_vm/target/release -lstoffel_vm
#include "stoffel_vm.h"
*/
import "C"
import (
    "fmt"
    "unsafe"
)

func main() {
    // Create a VM instance
    vm := C.stoffel_create_vm()
    defer C.stoffel_destroy_vm(vm)
    
    // ... use the VM ...
}
```

## Memory Management

When using the StoffelVM CFFI layer, it's important to understand how memory is managed:

- The VM owns all values created within it
- Strings returned by the VM must be freed with `stoffel_free_string`
- The VM handle must be freed with `stoffel_destroy_vm`
- Foreign objects registered with the VM are owned by the VM

## Thread Safety

The StoffelVM CFFI layer is not thread-safe by default. If you need to use the VM from multiple threads, you should use appropriate synchronization mechanisms.

## Error Handling

Most functions in the CFFI layer return an integer status code:

- `0`: Success
- Non-zero: Error

When an error occurs, you should check the status code and handle the error appropriately.