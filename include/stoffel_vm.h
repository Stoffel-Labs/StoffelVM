/**
 * @file stoffel_vm.h
 * @brief C API for StoffelVM
 *
 * This header file defines the C API for interacting with StoffelVM from C, C++,
 * and other languages that support C FFI. It provides functions for creating and
 * managing VM instances, registering foreign functions, executing VM functions,
 * and working with VM values.
 */

#ifndef STOFFEL_VM_H
#define STOFFEL_VM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opaque handle to a VM instance
 */
typedef void* VMHandle;

/**
 * Value types in StoffelVM
 */
typedef enum {
    STOFFEL_VALUE_UNIT = 0,    /**< Unit/void value */
    STOFFEL_VALUE_INT = 1,     /**< Integer value */
    STOFFEL_VALUE_FLOAT = 2,   /**< Float value */
    STOFFEL_VALUE_BOOL = 3,    /**< Boolean value */
    STOFFEL_VALUE_STRING = 4,  /**< String value */
    STOFFEL_VALUE_OBJECT = 5,  /**< Object reference */
    STOFFEL_VALUE_ARRAY = 6,   /**< Array reference */
    STOFFEL_VALUE_FOREIGN = 7, /**< Foreign object reference */
    STOFFEL_VALUE_CLOSURE = 8  /**< Function closure */
} StoffelValueType;

/**
 * Union to hold the actual value data
 */
typedef union {
    int64_t int_val;           /**< Integer value */
    double float_val;          /**< Float value */
    int bool_val;              /**< Boolean value (0 = false, non-zero = true) */
    const char* string_val;    /**< String value (C string) */
    size_t object_id;          /**< Object ID */
    size_t array_id;           /**< Array ID */
    size_t foreign_id;         /**< Foreign object ID */
    size_t closure_id;         /**< Closure ID (for future use) */
} StoffelValueData;

/**
 * C-compatible representation of a StoffelVM value
 */
typedef struct {
    StoffelValueType value_type; /**< Type of the value */
    StoffelValueData data;       /**< Actual value data */
} StoffelValue;

/**
 * Type for C callback functions
 *
 * @param args Array of arguments passed to the function
 * @param arg_count Number of arguments
 * @param result Pointer to store the result
 * @return 0 on success, non-zero on error
 */
typedef int (*CForeignFunction)(
    const StoffelValue* args,
    int arg_count,
    StoffelValue* result
);

/**
 * Creates a new VM instance
 *
 * @return A handle to the VM instance, or NULL if creation failed
 */
VMHandle stoffel_create_vm(void);

/**
 * Destroys a VM instance
 *
 * @param handle Handle to the VM instance
 */
void stoffel_destroy_vm(VMHandle handle);

/**
 * Executes a VM function and returns the result
 *
 * @param handle Handle to the VM instance
 * @param function_name Name of the function to execute
 * @param result Pointer to a StoffelValue to store the result
 * @return 0 on success, non-zero on error
 */
int stoffel_execute(
    VMHandle handle,
    const char* function_name,
    StoffelValue* result
);

/**
 * Executes a VM function with arguments and returns the result
 *
 * @param handle Handle to the VM instance
 * @param function_name Name of the function to execute
 * @param args Array of StoffelValue arguments
 * @param arg_count Number of arguments
 * @param result Pointer to a StoffelValue to store the result
 * @return 0 on success, non-zero on error
 */
int stoffel_execute_with_args(
    VMHandle handle,
    const char* function_name,
    const StoffelValue* args,
    int arg_count,
    StoffelValue* result
);

/**
 * Registers a C function with the VM
 *
 * @param handle Handle to the VM instance
 * @param name Name of the function to register
 * @param func Pointer to the C function
 * @return 0 on success, non-zero on error
 */
int stoffel_register_foreign_function(
    VMHandle handle,
    const char* name,
    CForeignFunction func
);

/**
 * Registers a foreign object with the VM
 *
 * @param handle Handle to the VM instance
 * @param object Pointer to the object
 * @param result Pointer to a StoffelValue to store the result
 * @return 0 on success, non-zero on error
 */
int stoffel_register_foreign_object(
    VMHandle handle,
    void* object,
    StoffelValue* result
);

/**
 * Creates a new string in the VM
 *
 * @param handle Handle to the VM instance
 * @param str Pointer to a null-terminated C string
 * @param result Pointer to a StoffelValue to store the result
 * @return 0 on success, non-zero on error
 */
int stoffel_create_string(
    VMHandle handle,
    const char* str,
    StoffelValue* result
);

/**
 * Frees a string created by the VM
 *
 * @param str Pointer to a C string created by the VM
 */
void stoffel_free_string(char* str);

#ifdef __cplusplus
}
#endif

#endif /* STOFFEL_VM_H */