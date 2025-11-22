// Abstraction for MPC engines used by the VM.
// Minimal trait needed by VMState and current HoneyBadger engine.

use stoffel_vm_types::core_types::{ShareType, Value};

pub trait MpcEngine: Send + Sync {
    fn protocol_name(&self) -> &'static str;
    fn instance_id(&self) -> u64;
    fn is_ready(&self) -> bool;

    // Synchronous wrappers used by non-async VM entrypoints
    fn start(&self) -> Result<(), String>;
    fn input_share(&self, ty: ShareType, clear: &Value) -> Result<Vec<u8>, String>;
    fn multiply_share(&self, ty: ShareType, left: &[u8], right: &[u8]) -> Result<Vec<u8>, String>;
    fn open_share(&self, ty: ShareType, share_bytes: &[u8]) -> Result<Value, String>;
    fn shutdown(&self) -> () {
        ()
    }
}
