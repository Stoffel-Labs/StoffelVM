//! MPC Builtin Functions for StoffelVM
//!
//! This module provides object-oriented MPC operations as foreign functions.
//! It exposes secret sharing, RBC (Reliable Broadcast), and ABA (Asynchronous
//! Binary Agreement) primitives as builtins.
//!
//! # API Pattern
//!
//! Functions use a module-prefixed pattern with object-as-first-argument:
//! ```text
//! let share = Share.from_clear(42)
//! let result = Share.multiply(share1, share2)
//! let value = Share.open(share)
//! ```
//!
//! # Share Object Structure
//!
//! Share objects are regular VM tables stored through the configured
//! [`stoffel_vm_types::core_types::TableMemory`] backend. Builtins use
//! semantic table reads so memory implementations such as Path-ORAM can update
//! access metadata during logical reads.
//!
//! Share tables use the following fields:
//! - `__type`: "Share"
//! - `__share_type`: "SecretInt" or "SecretFixedPoint"
//! - `__data`: Value::Share(ty, bytes) containing the raw share data
//! - `__party_id`: Party ID that created this share
//! - `__bit_length`: For SecretInt, the bit length
//! - `__precision_k`: For SecretFixedPoint, total bits
//! - `__precision_f`: For SecretFixedPoint, fractional bits

use crate::core_vm::VirtualMachine;
use crate::VirtualMachineResult;

#[cfg(feature = "avss")]
mod avss;
mod bytes;
mod consensus;
mod crypto;
mod info;
mod share;

pub use crate::mpc_values::{
    aba_fields, rbc_fields, share_fields, share_object, MpcValueError, MpcValueResult,
};
#[cfg(feature = "avss")]
pub use crate::mpc_values::{avss_fields, avss_object};

const MPC_BUILTIN_FUNCTIONS: &[&str] = &[
    "Share.from_clear",
    "Share.from_clear_int",
    "Share.from_clear_fixed",
    "Share.add",
    "Share.sub",
    "Share.neg",
    "Share.add_scalar",
    "Share.mul_scalar",
    "Share.mul",
    "Share.open",
    "Share.batch_open",
    "Share.send_to_client",
    "Share.interpolate_local",
    "Share.get_type",
    "Share.get_party_id",
    "Share.open_exp",
    "Share.random",
    "Share.get_commitment",
    "Share.commitment_count",
    "Share.has_commitments",
    "Share.mul_field",
    "Share.open_field",
    "Share.open_exp_custom",
    "Bytes.concat",
    "Bytes.from_string",
    "Crypto.sha256",
    "Crypto.sha512",
    "Crypto.hash_to_field",
    "Crypto.hash_to_g1",
    "Mpc.party_id",
    "Mpc.n_parties",
    "Mpc.threshold",
    "Mpc.is_ready",
    "Mpc.instance_id",
    "Mpc.protocol_name",
    "Mpc.curve",
    "Mpc.field",
    "Mpc.has_capability",
    "Mpc.capabilities",
    "Mpc.rand",
    "Mpc.rand_int",
    "Rbc.broadcast",
    "Rbc.receive",
    "Rbc.receive_any",
    "Aba.propose",
    "Aba.result",
    "Aba.propose_and_wait",
];

#[cfg(feature = "avss")]
const AVSS_BUILTIN_FUNCTIONS: &[&str] = &[
    "Avss.get_commitment",
    "Avss.get_key_name",
    "Avss.commitment_count",
    "Avss.is_avss_share",
];

/// Try to register all MPC builtin functions with the VM.
pub fn try_register_mpc_builtins(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    vm.ensure_function_names_available(MPC_BUILTIN_FUNCTIONS, "MPC builtins")?;
    #[cfg(feature = "avss")]
    vm.ensure_function_names_available(AVSS_BUILTIN_FUNCTIONS, "AVSS builtins")?;
    register_mpc_builtins_unchecked(vm)
}

/// Register all MPC builtin functions with the VM
#[track_caller]
pub fn register_mpc_builtins(vm: &mut VirtualMachine) {
    try_register_mpc_builtins(vm).expect("invalid MPC builtin registration");
}

fn register_mpc_builtins_unchecked(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    share::register(vm)?;
    info::register(vm)?;
    consensus::register_rbc(vm)?;
    consensus::register_aba(vm)?;
    crypto::register(vm)?;
    bytes::register(vm)?;
    #[cfg(feature = "avss")]
    avss::register(vm)?;
    Ok(())
}

#[cfg(test)]
mod tests;
