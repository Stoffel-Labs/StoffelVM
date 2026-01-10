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

/**
 * Loads bytecode into the VM
 *
 * @param handle Handle to the VM instance
 * @param bytecode Pointer to bytecode data
 * @param bytecode_len Length of bytecode data in bytes
 * @return 0 on success, non-zero on error
 */
int stoffel_load_bytecode(
    VMHandle handle,
    const uint8_t* bytecode,
    size_t bytecode_len
);

/* ============================================================================
 * HoneyBadgerMpcEngine FFI
 * ============================================================================ */

/**
 * Opaque handle to a HoneyBadgerMpcEngine instance
 */
typedef struct HBEngineOpaque HBEngineOpaque;

/**
 * Opaque handle to a QuicNetworkManager instance
 */
typedef struct HBNetworkOpaque HBNetworkOpaque;

/**
 * Error codes for HoneyBadgerMpcEngine operations
 */
typedef enum {
    HBEngineSuccess = 0,             /**< Operation succeeded */
    HBEngineNullPointer = 1,         /**< Null pointer provided */
    HBEngineNotReady = 2,            /**< Engine not ready (preprocessing not complete) */
    HBEngineNetworkError = 3,        /**< Network error during MPC operation */
    HBEnginePreprocessingFailed = 4, /**< Preprocessing failed */
    HBEngineMultiplyFailed = 5,      /**< Multiplication operation failed */
    HBEngineOpenShareFailed = 6,     /**< Share opening/reconstruction failed */
    HBEngineSerializationError = 7,  /**< Serialization/deserialization error */
    HBEngineInvalidShareType = 8,    /**< Invalid share type provided */
    HBEngineClientInputFailed = 9,   /**< Client input initialization failed */
    HBEngineGetClientSharesFailed = 10, /**< Client shares retrieval failed */
    HBEngineRuntimeError = 11,       /**< Tokio runtime creation failed */
    HBEngineInvalidConfig = 12       /**< Invalid configuration parameters */
} HBEngineErrorCode;

/**
 * C-compatible representation of ShareType
 *
 * kind: 0=Int, 1=Bool, 2=Float
 * width: value/width depending on kind
 */
typedef struct {
    uint8_t kind;   /**< Type kind: 0=Int, 1=Bool, 2=Float */
    int64_t width;  /**< Width/value depending on kind */
} CShareType;

/**
 * Creates a new HoneyBadgerMpcEngine
 *
 * @param instance_id Unique identifier for this MPC instance
 * @param party_id This party's ID (0 to n-1)
 * @param n Total number of parties
 * @param t Threshold (corruption tolerance)
 * @param n_triples Number of Beaver triples to generate
 * @param n_random Number of random shares to generate
 * @param network_ptr Pointer to HBNetworkOpaque
 * @return Pointer to engine handle, or NULL on failure
 */
HBEngineOpaque* hb_engine_new(
    uint64_t instance_id,
    size_t party_id,
    size_t n,
    size_t t,
    size_t n_triples,
    size_t n_random,
    HBNetworkOpaque* network_ptr
);

/**
 * Frees a HoneyBadgerMpcEngine instance
 *
 * @param engine_ptr Engine handle to free
 */
void hb_engine_free(HBEngineOpaque* engine_ptr);

/**
 * Runs preprocessing (generates Beaver triples and random shares)
 *
 * This is a blocking call that runs the async preprocessing protocol.
 * Must be called before any computation operations.
 *
 * @param engine_ptr Engine handle
 * @return HBEngineSuccess on success, error code on failure
 */
HBEngineErrorCode hb_engine_start_async(HBEngineOpaque* engine_ptr);

/**
 * Checks if the engine is ready (preprocessing complete)
 *
 * @param engine_ptr Engine handle
 * @return 1 if ready, 0 if not ready or null pointer
 */
int hb_engine_is_ready(HBEngineOpaque* engine_ptr);

/**
 * Performs secure multiplication of two shares
 *
 * @param engine_ptr Engine handle
 * @param share_type Type information for the shares
 * @param left_ptr Pointer to left share bytes
 * @param left_len Length of left share
 * @param right_ptr Pointer to right share bytes
 * @param right_len Length of right share
 * @param result_ptr Output: pointer to result bytes (caller must free with hb_free_bytes)
 * @param result_len_ptr Output: length of result bytes
 * @return HBEngineSuccess on success, error code on failure
 */
HBEngineErrorCode hb_engine_multiply_share_async(
    HBEngineOpaque* engine_ptr,
    CShareType share_type,
    const uint8_t* left_ptr,
    size_t left_len,
    const uint8_t* right_ptr,
    size_t right_len,
    uint8_t** result_ptr,
    size_t* result_len_ptr
);

/**
 * Opens (reconstructs) a shared value
 *
 * @param engine_ptr Engine handle
 * @param share_type Type information for the share
 * @param share_ptr Pointer to share bytes
 * @param share_len Length of share bytes
 * @param result_ptr Output: StoffelValue containing the reconstructed value
 * @return HBEngineSuccess on success, error code on failure
 */
HBEngineErrorCode hb_engine_open_share(
    HBEngineOpaque* engine_ptr,
    CShareType share_type,
    const uint8_t* share_ptr,
    size_t share_len,
    StoffelValue* result_ptr
);

/**
 * Initialize input shares from a client
 *
 * @param engine_ptr Engine handle
 * @param client_id Client identifier
 * @param shares_data Serialized shares data (bincode format)
 * @param shares_len Length of shares data
 * @return HBEngineSuccess on success, error code on failure
 */
HBEngineErrorCode hb_engine_init_client_input(
    HBEngineOpaque* engine_ptr,
    uint64_t client_id,
    const uint8_t* shares_data,
    size_t shares_len
);

/**
 * Get shares for a specific client
 *
 * Caller must free the result bytes with hb_free_bytes
 *
 * @param engine_ptr Engine handle
 * @param client_id Client identifier
 * @param result_ptr Output: pointer to serialized shares (bincode format)
 * @param result_len_ptr Output: length of result
 * @return HBEngineSuccess on success, error code on failure
 */
HBEngineErrorCode hb_engine_get_client_shares(
    HBEngineOpaque* engine_ptr,
    uint64_t client_id,
    uint8_t** result_ptr,
    size_t* result_len_ptr
);

/**
 * Get the party ID of the engine
 *
 * @param engine_ptr Engine handle
 * @return Party ID, or 0 if null pointer
 */
size_t hb_engine_party_id(HBEngineOpaque* engine_ptr);

/**
 * Get the instance ID of the engine
 *
 * @param engine_ptr Engine handle
 * @return Instance ID, or 0 if null pointer
 */
uint64_t hb_engine_instance_id(HBEngineOpaque* engine_ptr);

/**
 * Get the protocol name (returns static string, do not free)
 *
 * @param engine_ptr Engine handle
 * @return Protocol name string, or NULL if null pointer
 */
const char* hb_engine_protocol_name(HBEngineOpaque* engine_ptr);

/**
 * Get the network handle from the engine
 *
 * Returns a cloned network pointer. Caller must free with hb_network_free.
 *
 * @param engine_ptr Engine handle
 * @return Network handle, or NULL if null pointer
 */
HBNetworkOpaque* hb_engine_get_network(HBEngineOpaque* engine_ptr);

/**
 * Free a network handle obtained from hb_engine_get_network
 *
 * @param network_ptr Network handle to free
 */
void hb_network_free(HBNetworkOpaque* network_ptr);

/**
 * Free bytes allocated by engine functions
 *
 * @param ptr Pointer to bytes to free
 * @param len Length of the byte array
 */
void hb_free_bytes(uint8_t* ptr, size_t len);

/**
 * Hydrate VM's ClientInputStore from engine's input store
 *
 * After calling hb_engine_init_client_input() to store client shares in the engine,
 * call this function to copy those shares to the VM's ClientInputStore where the
 * ClientStore.take_share instruction can access them during execution.
 *
 * @param engine_ptr Engine handle
 * @param vm_handle VM handle
 * @return HBEngineSuccess on success, error code on failure
 */
HBEngineErrorCode hb_engine_hydrate_to_vm(
    HBEngineOpaque* engine_ptr,
    VMHandle vm_handle
);

#ifdef __cplusplus
}
#endif

#endif /* STOFFEL_VM_H */