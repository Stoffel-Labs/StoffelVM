//! Abstract MPC engine interface for the VM.
//!
//! This trait provides an integration point between the VM runtime and any
//! concrete MPC protocol backend (e.g., HoneyBadger over QUIC). Keeping this
//! as a thin, object-safe abstraction improves maintainability and allows
//! swapping implementations without touching core VM logic.
//!
//! Note: This module is compiled only when the `mpc` Cargo feature is enabled.

use std::sync::Arc;

/// Object-safe MPC engine abstraction expected by the VM.
pub trait MpcEngine: Send + Sync {
    /// Human-readable protocol/implementation name (for logging/telemetry).
    fn protocol_name(&self) -> &'static str;

    /// Unique instance/session identifier for this engine.
    fn instance_id(&self) -> u64;

    /// Whether the engine has been initialized and its message pumps are running.
    fn is_ready(&self) -> bool;

    /// Start background tasks (e.g., message pumps). Safe to call multiple times.
    fn start(&self) -> Result<(), String>;

    /// Convert a clear value into a secret share byte representation for the given type.
    fn input_share(
        &self,
        ty: stoffel_vm_types::core_types::ShareType,
        clear: &stoffel_vm_types::core_types::Value,
    ) -> Result<Vec<u8>, String>;

    /// Multiply two secret shares (opaque byte formats) of the given type.
    /// Returns the resulting share bytes on success.
    fn multiply_share(
        &self,
        ty: stoffel_vm_types::core_types::ShareType,
        left: &[u8],
        right: &[u8],
    ) -> Result<Vec<u8>, String>;

    /// Open (reveal) a secret share as a clear VM value of the same type.
    fn open_share(
        &self,
        ty: stoffel_vm_types::core_types::ShareType,
        share_bytes: &[u8],
    ) -> Result<stoffel_vm_types::core_types::Value, String>;

    /// Graceful shutdown of background tasks and network resources.
    fn shutdown(&self);
}

/// A no-op engine useful for tests or when wiring is incomplete.
/// Operations will report not-ready and no background work is performed.
pub struct NoopMpcEngine {
    instance_id: u64,
}

impl NoopMpcEngine {
    pub fn new(instance_id: u64) -> Arc<Self> {
        Arc::new(Self { instance_id })
    }
}

impl MpcEngine for NoopMpcEngine {
    fn protocol_name(&self) -> &'static str { "noop-mpc" }
    fn instance_id(&self) -> u64 { self.instance_id }
    fn is_ready(&self) -> bool { false }
    fn start(&self) -> Result<(), String> { Ok(()) }
    fn input_share(
        &self,
        ty: stoffel_vm_types::core_types::ShareType,
        _clear: &stoffel_vm_types::core_types::Value,
    ) -> Result<Vec<u8>, String> {
        Err(format!(
            "NoopMpcEngine does not support input_share for {:?}. Attach a real MPC engine.",
            ty
        ))
    }
    fn multiply_share(
        &self,
        ty: stoffel_vm_types::core_types::ShareType,
        _left: &[u8],
        _right: &[u8],
    ) -> Result<Vec<u8>, String> {
        Err(format!(
            "NoopMpcEngine does not support multiply_share for {:?}. Attach a real MPC engine.",
            ty
        ))
    }
    fn open_share(
        &self,
        ty: stoffel_vm_types::core_types::ShareType,
        _share_bytes: &[u8],
    ) -> Result<stoffel_vm_types::core_types::Value, String> {
        Err(format!(
            "NoopMpcEngine does not support open_share for {:?}. Attach a real MPC engine.",
            ty
        ))
    }
    fn shutdown(&self) {}
}
