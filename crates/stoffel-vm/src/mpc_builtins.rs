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
//! Share objects are stored in the ObjectStore with the following fields:
//! - `__type`: "Share"
//! - `__share_type`: "SecretInt" or "SecretFixedPoint"
//! - `__data`: Value::Share(ty, bytes) containing the raw share data
//! - `__party_id`: Party ID that created this share
//! - `__bit_length`: For SecretInt, the bit length
//! - `__precision_k`: For SecretFixedPoint, total bits
//! - `__precision_f`: For SecretFixedPoint, fractional bits

use crate::core_vm::VirtualMachine;
use crate::foreign_functions::ForeignFunctionContext;
use stoffel_vm_types::core_types::{ShareType, Value};

/// Field name constants for Share objects
pub mod share_fields {
    pub const TYPE: &str = "__type";
    pub const SHARE_TYPE: &str = "__share_type";
    pub const DATA: &str = "__data";
    pub const PARTY_ID: &str = "__party_id";
    pub const BIT_LENGTH: &str = "__bit_length";
    pub const PRECISION_K: &str = "__precision_k";
    pub const PRECISION_F: &str = "__precision_f";

    pub const TYPE_VALUE: &str = "Share";
    pub const SECRET_INT: &str = "SecretInt";
    pub const SECRET_FIXED_POINT: &str = "SecretFixedPoint";
}

/// Field name constants for RBC session objects
pub mod rbc_fields {
    pub const TYPE: &str = "__type";
    pub const SESSION_ID: &str = "__session_id";
    pub const TYPE_VALUE: &str = "RbcSession";
}

/// Field name constants for ABA session objects
pub mod aba_fields {
    pub const TYPE: &str = "__type";
    pub const SESSION_ID: &str = "__session_id";
    pub const TYPE_VALUE: &str = "AbaSession";
}

/// Field name constants for SecureVoting session objects
pub mod voting_fields {
    pub const TYPE: &str = "__type";
    pub const NUM_OPTIONS: &str = "__num_options";
    pub const VOTES: &str = "__votes";
    pub const TYPE_VALUE: &str = "SecureVotingSession";
}

/// Field name constants for ConsensusValue session objects
pub mod consensus_fields {
    pub const TYPE: &str = "__type";
    pub const VALUE: &str = "__value";
    pub const SESSION_ID: &str = "__session_id";
    pub const TYPE_VALUE: &str = "ConsensusValueSession";
}

/// Helper module for Share object operations
pub mod share_object {
    use super::share_fields;
    use stoffel_vm_types::core_types::{ObjectStore, ShareType, Value};

    /// Create a new Share object in the object store
    ///
    /// # Arguments
    /// * `store` - The object store to create the share in
    /// * `share_type` - The type of share (SecretInt or SecretFixedPoint)
    /// * `data` - The raw share bytes
    /// * `party_id` - The party ID that created this share
    ///
    /// # Returns
    /// The object ID of the created share
    pub fn create_share_object(
        store: &mut ObjectStore,
        share_type: ShareType,
        data: Vec<u8>,
        party_id: usize,
    ) -> usize {
        let id = store.create_object();
        let obj = Value::Object(id);

        // Set type tag
        store
            .set_field(
                &obj,
                Value::String(share_fields::TYPE.to_string()),
                Value::String(share_fields::TYPE_VALUE.to_string()),
            )
            .unwrap();

        // Set share type and type-specific fields
        match share_type {
            ShareType::SecretInt { bit_length } => {
                store
                    .set_field(
                        &obj,
                        Value::String(share_fields::SHARE_TYPE.to_string()),
                        Value::String(share_fields::SECRET_INT.to_string()),
                    )
                    .unwrap();
                store
                    .set_field(
                        &obj,
                        Value::String(share_fields::BIT_LENGTH.to_string()),
                        Value::I64(bit_length as i64),
                    )
                    .unwrap();
            }
            ShareType::SecretFixedPoint { precision } => {
                store
                    .set_field(
                        &obj,
                        Value::String(share_fields::SHARE_TYPE.to_string()),
                        Value::String(share_fields::SECRET_FIXED_POINT.to_string()),
                    )
                    .unwrap();
                store
                    .set_field(
                        &obj,
                        Value::String(share_fields::PRECISION_K.to_string()),
                        Value::I64(precision.k() as i64),
                    )
                    .unwrap();
                store
                    .set_field(
                        &obj,
                        Value::String(share_fields::PRECISION_F.to_string()),
                        Value::I64(precision.f() as i64),
                    )
                    .unwrap();
            }
        }

        // Set share data
        store
            .set_field(
                &obj,
                Value::String(share_fields::DATA.to_string()),
                Value::Share(share_type, data),
            )
            .unwrap();

        // Set party ID
        store
            .set_field(
                &obj,
                Value::String(share_fields::PARTY_ID.to_string()),
                Value::I64(party_id as i64),
            )
            .unwrap();

        id
    }

    /// Extract share data from a Share object
    ///
    /// # Arguments
    /// * `store` - The object store containing the share
    /// * `value` - The value (should be Object or Share)
    ///
    /// # Returns
    /// A tuple of (ShareType, share_bytes) or an error
    pub fn extract_share_data(
        store: &ObjectStore,
        value: &Value,
    ) -> Result<(ShareType, Vec<u8>), String> {
        match value {
            // Direct share value (backward compatibility)
            Value::Share(ty, data) => Ok((*ty, data.clone())),

            // Share object
            Value::Object(id) => {
                // Verify type field
                let type_field = store
                    .get_field(value, &Value::String(share_fields::TYPE.to_string()))
                    .ok_or_else(|| "Object is not a Share: missing __type field".to_string())?;

                if type_field != Value::String(share_fields::TYPE_VALUE.to_string()) {
                    return Err(format!(
                        "Object is not a Share: __type is {:?}, expected \"Share\"",
                        type_field
                    ));
                }

                // Extract data field
                let data_field = store
                    .get_field(value, &Value::String(share_fields::DATA.to_string()))
                    .ok_or_else(|| "Share object missing __data field".to_string())?;

                match data_field {
                    Value::Share(ty, data) => Ok((ty, data)),
                    _ => Err("Share __data field is not a Share value".to_string()),
                }
            }

            _ => Err(format!(
                "Expected Share object or Share value, got {:?}",
                value
            )),
        }
    }

    /// Check if a value is a Share object
    pub fn is_share_object(store: &ObjectStore, value: &Value) -> bool {
        match value {
            Value::Share(_, _) => true,
            Value::Object(_) => store
                .get_field(value, &Value::String(share_fields::TYPE.to_string()))
                .map(|v| v == Value::String(share_fields::TYPE_VALUE.to_string()))
                .unwrap_or(false),
            _ => false,
        }
    }

    /// Get the ShareType from a Share object
    pub fn get_share_type(store: &ObjectStore, value: &Value) -> Result<ShareType, String> {
        match value {
            Value::Share(ty, _) => Ok(*ty),
            Value::Object(_) => {
                let share_type_field = store
                    .get_field(value, &Value::String(share_fields::SHARE_TYPE.to_string()))
                    .ok_or_else(|| "Share object missing __share_type field".to_string())?;

                match share_type_field {
                    Value::String(s) if s == share_fields::SECRET_INT => {
                        let bit_length = store
                            .get_field(value, &Value::String(share_fields::BIT_LENGTH.to_string()))
                            .and_then(|v| match v {
                                Value::I64(n) => Some(n as usize),
                                _ => None,
                            })
                            .unwrap_or(64);
                        Ok(ShareType::SecretInt { bit_length })
                    }
                    Value::String(s) if s == share_fields::SECRET_FIXED_POINT => {
                        let k = store
                            .get_field(value, &Value::String(share_fields::PRECISION_K.to_string()))
                            .and_then(|v| match v {
                                Value::I64(n) => Some(n as usize),
                                _ => None,
                            })
                            .unwrap_or(64);
                        let f = store
                            .get_field(value, &Value::String(share_fields::PRECISION_F.to_string()))
                            .and_then(|v| match v {
                                Value::I64(n) => Some(n as usize),
                                _ => None,
                            })
                            .unwrap_or(16);
                        Ok(ShareType::secret_fixed_point_from_bits(k, f))
                    }
                    _ => Err(format!("Unknown share type: {:?}", share_type_field)),
                }
            }
            _ => Err(format!("Not a Share object: {:?}", value)),
        }
    }
}

/// Register all MPC builtin functions with the VM
pub fn register_mpc_builtins(vm: &mut VirtualMachine) {
    register_share_builtins(vm);
    register_mpc_info_builtins(vm);
    register_rbc_builtins(vm);
    register_aba_builtins(vm);
    register_consensus_builtins(vm);
}

/// Register Share module builtins
fn register_share_builtins(vm: &mut VirtualMachine) {
    // Share.from_clear - Create share from clear value (auto-detect type)
    vm.register_foreign_function("Share.from_clear", |ctx| {
        share_from_clear(ctx, None)
    });

    // Share.from_clear_int - Create integer share with custom bit length
    vm.register_foreign_function("Share.from_clear_int", |ctx| {
        if ctx.args.len() < 2 {
            return Err(
                "Share.from_clear_int expects 2 arguments: value, bit_length".to_string(),
            );
        }
        let bit_length = match &ctx.args[1] {
            Value::I64(n) if *n > 0 => *n as usize,
            _ => return Err("bit_length must be a positive integer".to_string()),
        };
        share_from_clear(ctx, Some(ShareType::SecretInt { bit_length }))
    });

    // Share.from_clear_fixed - Create fixed-point share with custom precision
    vm.register_foreign_function("Share.from_clear_fixed", |ctx| {
        if ctx.args.len() < 3 {
            return Err(
                "Share.from_clear_fixed expects 3 arguments: value, total_bits, frac_bits"
                    .to_string(),
            );
        }
        let k = match &ctx.args[1] {
            Value::I64(n) if *n > 0 => *n as usize,
            _ => return Err("total_bits must be a positive integer".to_string()),
        };
        let f = match &ctx.args[2] {
            Value::I64(n) if *n >= 0 => *n as usize,
            _ => return Err("frac_bits must be a non-negative integer".to_string()),
        };
        if f >= k {
            return Err("frac_bits must be less than total_bits".to_string());
        }
        share_from_clear(ctx, Some(ShareType::secret_fixed_point_from_bits(k, f)))
    });

    // Share.add - Add two shares (local operation)
    vm.register_foreign_function("Share.add", share_add);

    // Share.sub - Subtract two shares (local operation)
    vm.register_foreign_function("Share.sub", share_sub);

    // Share.neg - Negate a share (local operation)
    vm.register_foreign_function("Share.neg", share_neg);

    // Share.add_scalar - Add scalar to share (local operation)
    vm.register_foreign_function("Share.add_scalar", share_add_scalar);

    // Share.mul_scalar - Multiply share by scalar (local operation)
    vm.register_foreign_function("Share.mul_scalar", share_mul_scalar);

    // Share.mul - Multiply two shares (network operation)
    vm.register_foreign_function("Share.mul", share_mul);

    // Share.open - Reconstruct secret (network operation)
    vm.register_foreign_function("Share.open", share_open);

    // Share.send_to_client - Send share to specific client (network operation)
    vm.register_foreign_function("Share.send_to_client", share_send_to_client);

    // Share.interpolate_local - Local reconstruction from array of shares
    vm.register_foreign_function("Share.interpolate_local", share_interpolate_local);

    // Share.get_type - Get the share type as string
    vm.register_foreign_function("Share.get_type", share_get_type);

    // Share.get_party_id - Get the party ID from share object
    vm.register_foreign_function("Share.get_party_id", share_get_party_id);
}

/// Register Mpc info builtins
fn register_mpc_info_builtins(vm: &mut VirtualMachine) {
    // Mpc.party_id - Get this party's ID
    vm.register_foreign_function("Mpc.party_id", |ctx| {
        let engine = ctx
            .vm_state
            .mpc_engine()
            .ok_or_else(|| "MPC engine not configured".to_string())?;
        Ok(Value::I64(engine.party_id() as i64))
    });

    // Mpc.n_parties - Get total number of parties
    vm.register_foreign_function("Mpc.n_parties", |ctx| {
        let engine = ctx
            .vm_state
            .mpc_engine()
            .ok_or_else(|| "MPC engine not configured".to_string())?;
        Ok(Value::I64(engine.n_parties() as i64))
    });

    // Mpc.threshold - Get corruption threshold
    vm.register_foreign_function("Mpc.threshold", |ctx| {
        let engine = ctx
            .vm_state
            .mpc_engine()
            .ok_or_else(|| "MPC engine not configured".to_string())?;
        Ok(Value::I64(engine.threshold() as i64))
    });

    // Mpc.is_ready - Check if MPC engine is ready
    vm.register_foreign_function("Mpc.is_ready", |ctx| {
        let ready = ctx
            .vm_state
            .mpc_engine()
            .map(|e| e.is_ready())
            .unwrap_or(false);
        Ok(Value::Bool(ready))
    });

    // Mpc.instance_id - Get MPC instance ID
    vm.register_foreign_function("Mpc.instance_id", |ctx| {
        let engine = ctx
            .vm_state
            .mpc_engine()
            .ok_or_else(|| "MPC engine not configured".to_string())?;
        Ok(Value::I64(engine.instance_id() as i64))
    });
}

/// Register RBC (Reliable Broadcast) builtins
fn register_rbc_builtins(vm: &mut VirtualMachine) {
    use crate::net::hb_engine::HoneyBadgerMpcEngine;
    use crate::net::mpc_engine::MpcEngineConsensus;

    // Rbc.broadcast - Broadcast a message reliably
    vm.register_foreign_function("Rbc.broadcast", |ctx| {
        let engine = ctx
            .vm_state
            .mpc_engine()
            .ok_or_else(|| "MPC engine not configured".to_string())?;

        // Try to downcast to HoneyBadgerMpcEngine which implements MpcEngineConsensus
        let any = engine
            .as_any()
            .ok_or_else(|| "MPC engine does not support downcasting".to_string())?;

        let hb_engine = any
            .downcast_ref::<HoneyBadgerMpcEngine>()
            .ok_or_else(|| "MPC engine does not support RBC".to_string())?;

        // Get message from args
        if ctx.args.is_empty() {
            return Err("Rbc.broadcast expects 1 argument: message".to_string());
        }

        let message_bytes = match &ctx.args[0] {
            Value::String(s) => s.as_bytes().to_vec(),
            _ => return Err("Message must be a string".to_string()),
        };

        let session_id = hb_engine.rbc_broadcast(&message_bytes)?;
        Ok(Value::I64(session_id as i64))
    });

    // Rbc.receive - Receive broadcast from specific party
    vm.register_foreign_function("Rbc.receive", |ctx| {
        let engine = ctx
            .vm_state
            .mpc_engine()
            .ok_or_else(|| "MPC engine not configured".to_string())?;

        let any = engine
            .as_any()
            .ok_or_else(|| "MPC engine does not support downcasting".to_string())?;

        let hb_engine = any
            .downcast_ref::<HoneyBadgerMpcEngine>()
            .ok_or_else(|| "MPC engine does not support RBC".to_string())?;

        if ctx.args.len() < 2 {
            return Err("Rbc.receive expects 2 arguments: from_party, timeout_ms".to_string());
        }

        let from_party = match &ctx.args[0] {
            Value::I64(n) if *n >= 0 => *n as usize,
            _ => return Err("from_party must be a non-negative integer".to_string()),
        };

        let timeout_ms = match &ctx.args[1] {
            Value::I64(n) if *n >= 0 => *n as u64,
            _ => return Err("timeout_ms must be a non-negative integer".to_string()),
        };

        let message = hb_engine.rbc_receive(from_party, timeout_ms)?;
        Ok(Value::String(
            String::from_utf8(message).unwrap_or_else(|_| "<binary data>".to_string()),
        ))
    });

    // Rbc.receive_any - Receive broadcast from any party
    vm.register_foreign_function("Rbc.receive_any", |ctx| {
        let engine = ctx
            .vm_state
            .mpc_engine()
            .ok_or_else(|| "MPC engine not configured".to_string())?;

        let any = engine
            .as_any()
            .ok_or_else(|| "MPC engine does not support downcasting".to_string())?;

        let hb_engine = any
            .downcast_ref::<HoneyBadgerMpcEngine>()
            .ok_or_else(|| "MPC engine does not support RBC".to_string())?;

        if ctx.args.is_empty() {
            return Err("Rbc.receive_any expects 1 argument: timeout_ms".to_string());
        }

        let timeout_ms = match &ctx.args[0] {
            Value::I64(n) if *n >= 0 => *n as u64,
            _ => return Err("timeout_ms must be a non-negative integer".to_string()),
        };

        let (party_id, message) = hb_engine.rbc_receive_any(timeout_ms)?;

        // Create result object with party_id and message
        let obj_id = ctx.vm_state.object_store.create_object();
        let obj = Value::Object(obj_id);
        ctx.vm_state.object_store.set_field(
            &obj,
            Value::String("party_id".to_string()),
            Value::I64(party_id as i64),
        )?;
        ctx.vm_state.object_store.set_field(
            &obj,
            Value::String("message".to_string()),
            Value::String(String::from_utf8(message).unwrap_or_else(|_| "<binary>".to_string())),
        )?;

        Ok(obj)
    });
}

/// Register ABA (Asynchronous Binary Agreement) builtins
fn register_aba_builtins(vm: &mut VirtualMachine) {
    use crate::net::hb_engine::HoneyBadgerMpcEngine;
    use crate::net::mpc_engine::MpcEngineConsensus;

    // Aba.propose - Propose a binary value
    vm.register_foreign_function("Aba.propose", |ctx| {
        let engine = ctx
            .vm_state
            .mpc_engine()
            .ok_or_else(|| "MPC engine not configured".to_string())?;

        let any = engine
            .as_any()
            .ok_or_else(|| "MPC engine does not support downcasting".to_string())?;

        let hb_engine = any
            .downcast_ref::<HoneyBadgerMpcEngine>()
            .ok_or_else(|| "MPC engine does not support ABA".to_string())?;

        if ctx.args.is_empty() {
            return Err("Aba.propose expects 1 argument: value (bool)".to_string());
        }

        let value = match &ctx.args[0] {
            Value::Bool(b) => *b,
            _ => return Err("value must be a boolean".to_string()),
        };

        let session_id = hb_engine.aba_propose(value)?;
        Ok(Value::I64(session_id as i64))
    });

    // Aba.result - Get agreed result
    vm.register_foreign_function("Aba.result", |ctx| {
        let engine = ctx
            .vm_state
            .mpc_engine()
            .ok_or_else(|| "MPC engine not configured".to_string())?;

        let any = engine
            .as_any()
            .ok_or_else(|| "MPC engine does not support downcasting".to_string())?;

        let hb_engine = any
            .downcast_ref::<HoneyBadgerMpcEngine>()
            .ok_or_else(|| "MPC engine does not support ABA".to_string())?;

        if ctx.args.len() < 2 {
            return Err("Aba.result expects 2 arguments: session_id, timeout_ms".to_string());
        }

        let session_id = match &ctx.args[0] {
            Value::I64(n) if *n >= 0 => *n as u64,
            _ => return Err("session_id must be a non-negative integer".to_string()),
        };

        let timeout_ms = match &ctx.args[1] {
            Value::I64(n) if *n >= 0 => *n as u64,
            _ => return Err("timeout_ms must be a non-negative integer".to_string()),
        };

        let result = hb_engine.aba_result(session_id, timeout_ms)?;
        Ok(Value::Bool(result))
    });

    // Aba.propose_and_wait - Propose and wait for result
    vm.register_foreign_function("Aba.propose_and_wait", |ctx| {
        let engine = ctx
            .vm_state
            .mpc_engine()
            .ok_or_else(|| "MPC engine not configured".to_string())?;

        let any = engine
            .as_any()
            .ok_or_else(|| "MPC engine does not support downcasting".to_string())?;

        let hb_engine = any
            .downcast_ref::<HoneyBadgerMpcEngine>()
            .ok_or_else(|| "MPC engine does not support ABA".to_string())?;

        if ctx.args.len() < 2 {
            return Err(
                "Aba.propose_and_wait expects 2 arguments: value (bool), timeout_ms".to_string(),
            );
        }

        let value = match &ctx.args[0] {
            Value::Bool(b) => *b,
            _ => return Err("value must be a boolean".to_string()),
        };

        let timeout_ms = match &ctx.args[1] {
            Value::I64(n) if *n >= 0 => *n as u64,
            _ => return Err("timeout_ms must be a non-negative integer".to_string()),
        };

        let result = hb_engine.aba_propose_and_wait(value, timeout_ms)?;
        Ok(Value::Bool(result))
    });
}

/// Register high-level consensus builtins
fn register_consensus_builtins(vm: &mut VirtualMachine) {
    use crate::net::hb_engine::HoneyBadgerMpcEngine;
    use crate::net::mpc_engine::MpcEngineConsensus;

    // SecureVoting.create - Create a voting session
    // Returns a voting session object that can be used for voting and tallying
    vm.register_foreign_function("SecureVoting.create", |ctx| {
        if ctx.args.is_empty() {
            return Err("SecureVoting.create expects 1 argument: num_options".to_string());
        }

        let num_options = match &ctx.args[0] {
            Value::I64(n) if *n > 0 => *n,
            _ => return Err("num_options must be a positive integer".to_string()),
        };

        // Create the voting session object
        let obj_id = ctx.vm_state.object_store.create_object();
        let obj = Value::Object(obj_id);

        ctx.vm_state.object_store.set_field(
            &obj,
            Value::String(voting_fields::TYPE.to_string()),
            Value::String(voting_fields::TYPE_VALUE.to_string()),
        )?;
        ctx.vm_state.object_store.set_field(
            &obj,
            Value::String(voting_fields::NUM_OPTIONS.to_string()),
            Value::I64(num_options),
        )?;

        // Initialize votes array with zeros for each option
        let votes_id = ctx.vm_state.object_store.create_object();
        let votes = Value::Object(votes_id);
        for i in 0..num_options {
            ctx.vm_state
                .object_store
                .set_field(&votes, Value::I64(i), Value::I64(0))?;
        }
        ctx.vm_state.object_store.set_field(
            &obj,
            Value::String(voting_fields::VOTES.to_string()),
            votes,
        )?;

        Ok(obj)
    });

    // SecureVoting.vote - Cast a vote in a voting session
    // TODO: Implementation incomplete - stubbed out for now
    vm.register_foreign_function("SecureVoting.vote", |_ctx| {
        Err("SecureVoting.vote is not yet implemented".to_string())
    });

    // SecureVoting.tally - Tally votes and return results
    // TODO: Implementation incomplete - stubbed out for now
    vm.register_foreign_function("SecureVoting.tally", |_ctx| {
        Err("SecureVoting.tally is not yet implemented".to_string())
    });

    // ConsensusValue.propose - Propose a value for consensus using RBC
    // TODO: Implementation incomplete - stubbed out for now
    vm.register_foreign_function("ConsensusValue.propose", |_ctx| {
        Err("ConsensusValue.propose is not yet implemented".to_string())
    });

    // ConsensusValue.get - Get the agreed consensus value
    // TODO: Implementation incomplete - stubbed out for now
    vm.register_foreign_function("ConsensusValue.get", |_ctx| {
        Err("ConsensusValue.get is not yet implemented".to_string())
    });
}

// ============================================================================
// Share builtin implementations
// ============================================================================

/// Create a share from a clear value
fn share_from_clear(
    ctx: ForeignFunctionContext,
    explicit_type: Option<ShareType>,
) -> Result<Value, String> {
    if ctx.args.is_empty() {
        return Err("Share.from_clear expects at least 1 argument: value".to_string());
    }

    let engine = ctx
        .vm_state
        .mpc_engine()
        .ok_or_else(|| "MPC engine not configured".to_string())?;

    let clear_value = &ctx.args[0];

    // Determine share type from explicit type or value type
    let share_type = match explicit_type {
        Some(ty) => ty,
        None => match clear_value {
            Value::I64(_) | Value::I32(_) | Value::I16(_) | Value::I8(_) => {
                ShareType::default_secret_int()
            }
            Value::U64(_) | Value::U32(_) | Value::U16(_) | Value::U8(_) => {
                ShareType::default_secret_int()
            }
            Value::Float(_) => ShareType::default_secret_fixed_point(),
            Value::Bool(_) => ShareType::boolean(),
            _ => return Err(format!("Cannot create share from value type: {:?}", clear_value)),
        },
    };

    // Convert value to appropriate type for input_share
    let input_value = match (share_type, clear_value) {
        (ShareType::SecretInt { .. }, Value::I64(n)) => Value::I64(*n),
        (ShareType::SecretInt { .. }, Value::I32(n)) => Value::I64(*n as i64),
        (ShareType::SecretInt { .. }, Value::I16(n)) => Value::I64(*n as i64),
        (ShareType::SecretInt { .. }, Value::I8(n)) => Value::I64(*n as i64),
        (ShareType::SecretInt { .. }, Value::U64(n)) => Value::I64(*n as i64),
        (ShareType::SecretInt { .. }, Value::U32(n)) => Value::I64(*n as i64),
        (ShareType::SecretInt { .. }, Value::U16(n)) => Value::I64(*n as i64),
        (ShareType::SecretInt { .. }, Value::U8(n)) => Value::I64(*n as i64),
        (ShareType::SecretInt { bit_length }, Value::Bool(b)) if bit_length == 1 => {
            Value::Bool(*b)
        }
        (ShareType::SecretFixedPoint { .. }, Value::Float(f)) => Value::Float(*f),
        (ShareType::SecretFixedPoint { .. }, Value::I64(n)) => {
            Value::Float(stoffel_vm_types::core_types::F64(*n as f64))
        }
        _ => {
            return Err(format!(
                "Cannot create {:?} share from {:?}",
                share_type, clear_value
            ))
        }
    };

    // Create the share
    let share_bytes = engine.input_share(share_type, &input_value)?;
    let party_id = engine.party_id();

    // Create Share object
    let obj_id = share_object::create_share_object(
        &mut ctx.vm_state.object_store,
        share_type,
        share_bytes,
        party_id,
    );

    Ok(Value::Object(obj_id))
}

/// Add two shares (local operation)
fn share_add(ctx: ForeignFunctionContext) -> Result<Value, String> {
    if ctx.args.len() < 2 {
        return Err("Share.add expects 2 arguments: share1, share2".to_string());
    }

    let (ty1, data1) = share_object::extract_share_data(&ctx.vm_state.object_store, &ctx.args[0])?;
    let (ty2, data2) = share_object::extract_share_data(&ctx.vm_state.object_store, &ctx.args[1])?;

    // Verify types match
    if ty1 != ty2 {
        return Err(format!(
            "Share type mismatch: {:?} vs {:?}",
            ty1, ty2
        ));
    }

    // Perform addition using VM's share arithmetic
    let result_data = ctx.vm_state.secret_share_add(ty1, &data1, &data2)?;

    let party_id = ctx
        .vm_state
        .mpc_engine()
        .map(|e| e.party_id())
        .unwrap_or(0);

    let obj_id = share_object::create_share_object(
        &mut ctx.vm_state.object_store,
        ty1,
        result_data,
        party_id,
    );

    Ok(Value::Object(obj_id))
}

/// Subtract two shares (local operation)
fn share_sub(ctx: ForeignFunctionContext) -> Result<Value, String> {
    if ctx.args.len() < 2 {
        return Err("Share.sub expects 2 arguments: share1, share2".to_string());
    }

    let (ty1, data1) = share_object::extract_share_data(&ctx.vm_state.object_store, &ctx.args[0])?;
    let (ty2, data2) = share_object::extract_share_data(&ctx.vm_state.object_store, &ctx.args[1])?;

    if ty1 != ty2 {
        return Err(format!(
            "Share type mismatch: {:?} vs {:?}",
            ty1, ty2
        ));
    }

    let result_data = ctx.vm_state.secret_share_sub(ty1, &data1, &data2)?;

    let party_id = ctx
        .vm_state
        .mpc_engine()
        .map(|e| e.party_id())
        .unwrap_or(0);

    let obj_id = share_object::create_share_object(
        &mut ctx.vm_state.object_store,
        ty1,
        result_data,
        party_id,
    );

    Ok(Value::Object(obj_id))
}

/// Negate a share (local operation)
fn share_neg(ctx: ForeignFunctionContext) -> Result<Value, String> {
    if ctx.args.is_empty() {
        return Err("Share.neg expects 1 argument: share".to_string());
    }

    let (ty, data) = share_object::extract_share_data(&ctx.vm_state.object_store, &ctx.args[0])?;

    let result_data = ctx.vm_state.secret_share_neg(ty, &data)?;

    let party_id = ctx
        .vm_state
        .mpc_engine()
        .map(|e| e.party_id())
        .unwrap_or(0);

    let obj_id = share_object::create_share_object(
        &mut ctx.vm_state.object_store,
        ty,
        result_data,
        party_id,
    );

    Ok(Value::Object(obj_id))
}

/// Add scalar to share (local operation)
fn share_add_scalar(ctx: ForeignFunctionContext) -> Result<Value, String> {
    if ctx.args.len() < 2 {
        return Err("Share.add_scalar expects 2 arguments: share, scalar".to_string());
    }

    let (ty, data) = share_object::extract_share_data(&ctx.vm_state.object_store, &ctx.args[0])?;
    let scalar = match &ctx.args[1] {
        Value::I64(n) => *n,
        Value::I32(n) => *n as i64,
        Value::I16(n) => *n as i64,
        Value::I8(n) => *n as i64,
        _ => return Err("Scalar must be an integer".to_string()),
    };

    let result_data = ctx.vm_state.secret_share_add_scalar(ty, &data, scalar)?;

    let party_id = ctx
        .vm_state
        .mpc_engine()
        .map(|e| e.party_id())
        .unwrap_or(0);

    let obj_id = share_object::create_share_object(
        &mut ctx.vm_state.object_store,
        ty,
        result_data,
        party_id,
    );

    Ok(Value::Object(obj_id))
}

/// Multiply share by scalar (local operation)
fn share_mul_scalar(ctx: ForeignFunctionContext) -> Result<Value, String> {
    if ctx.args.len() < 2 {
        return Err("Share.mul_scalar expects 2 arguments: share, scalar".to_string());
    }

    let (ty, data) = share_object::extract_share_data(&ctx.vm_state.object_store, &ctx.args[0])?;
    let scalar = match &ctx.args[1] {
        Value::I64(n) => *n,
        Value::I32(n) => *n as i64,
        Value::I16(n) => *n as i64,
        Value::I8(n) => *n as i64,
        _ => return Err("Scalar must be an integer".to_string()),
    };

    let result_data = ctx.vm_state.secret_share_mul_scalar(ty, &data, scalar)?;

    let party_id = ctx
        .vm_state
        .mpc_engine()
        .map(|e| e.party_id())
        .unwrap_or(0);

    let obj_id = share_object::create_share_object(
        &mut ctx.vm_state.object_store,
        ty,
        result_data,
        party_id,
    );

    Ok(Value::Object(obj_id))
}

/// Multiply two shares (network operation)
fn share_mul(ctx: ForeignFunctionContext) -> Result<Value, String> {
    if ctx.args.len() < 2 {
        return Err("Share.mul expects 2 arguments: share1, share2".to_string());
    }

    let engine = ctx
        .vm_state
        .mpc_engine()
        .ok_or_else(|| "MPC engine not configured".to_string())?;

    if !engine.is_ready() {
        return Err("MPC engine not ready".to_string());
    }

    let (ty1, data1) = share_object::extract_share_data(&ctx.vm_state.object_store, &ctx.args[0])?;
    let (ty2, data2) = share_object::extract_share_data(&ctx.vm_state.object_store, &ctx.args[1])?;

    if ty1 != ty2 {
        return Err(format!(
            "Share type mismatch: {:?} vs {:?}",
            ty1, ty2
        ));
    }

    // Perform MPC multiplication
    let result_data = engine.multiply_share(ty1, &data1, &data2)?;
    let party_id = engine.party_id();

    let obj_id = share_object::create_share_object(
        &mut ctx.vm_state.object_store,
        ty1,
        result_data,
        party_id,
    );

    Ok(Value::Object(obj_id))
}

/// Open/reveal a share (network operation)
fn share_open(ctx: ForeignFunctionContext) -> Result<Value, String> {
    if ctx.args.is_empty() {
        return Err("Share.open expects 1 argument: share".to_string());
    }

    let engine = ctx
        .vm_state
        .mpc_engine()
        .ok_or_else(|| "MPC engine not configured".to_string())?;

    if !engine.is_ready() {
        return Err("MPC engine not ready".to_string());
    }

    let (ty, data) = share_object::extract_share_data(&ctx.vm_state.object_store, &ctx.args[0])?;

    engine.open_share(ty, &data)
}

/// Send share to specific client (network operation)
fn share_send_to_client(ctx: ForeignFunctionContext) -> Result<Value, String> {
    if ctx.args.len() < 2 {
        return Err("Share.send_to_client expects 2 arguments: share, client_id".to_string());
    }

    let engine = ctx
        .vm_state
        .mpc_engine()
        .ok_or_else(|| "MPC engine not configured".to_string())?;

    if !engine.is_ready() {
        return Err("MPC engine not ready".to_string());
    }

    let (_ty, data) = share_object::extract_share_data(&ctx.vm_state.object_store, &ctx.args[0])?;
    let client_id = match &ctx.args[1] {
        Value::I64(n) if *n >= 0 => *n as usize,
        Value::U64(n) => *n as usize,
        _ => return Err("client_id must be a non-negative integer".to_string()),
    };

    engine.send_output_to_client(client_id, &data, 1)?;
    Ok(Value::Bool(true))
}

/// Local interpolation - reconstruct secret from array of shares
fn share_interpolate_local(ctx: ForeignFunctionContext) -> Result<Value, String> {
    if ctx.args.is_empty() {
        return Err("Share.interpolate_local expects 1 argument: shares_array".to_string());
    }

    let array_id = match &ctx.args[0] {
        Value::Array(id) => *id,
        _ => return Err("Argument must be an array of shares".to_string()),
    };

    let array = ctx
        .vm_state
        .object_store
        .get_array(array_id)
        .ok_or_else(|| "Array not found".to_string())?;

    let len = array.length();
    if len == 0 {
        return Err("Cannot interpolate from empty array".to_string());
    }

    // Get threshold to check we have enough shares
    let threshold = ctx
        .vm_state
        .mpc_engine()
        .map(|e| e.threshold())
        .unwrap_or(0);

    let required = 2 * threshold + 1;
    if len < required {
        return Err(format!(
            "Need at least {} shares for interpolation, got {}",
            required, len
        ));
    }

    // Collect share data
    let mut shares_data: Vec<Vec<u8>> = Vec::with_capacity(len);
    let mut share_type: Option<ShareType> = None;

    for i in 0..len {
        let idx = Value::I64(i as i64);
        let element = array.get(&idx).ok_or_else(|| format!("Missing element at index {}", i))?;

        let (ty, data) = share_object::extract_share_data(&ctx.vm_state.object_store, element)?;

        if let Some(expected_ty) = share_type {
            if ty != expected_ty {
                return Err(format!(
                    "Share type mismatch at index {}: {:?} vs {:?}",
                    i, ty, expected_ty
                ));
            }
        } else {
            share_type = Some(ty);
        }

        shares_data.push(data);
    }

    let ty = share_type.unwrap();

    // Perform local interpolation
    ctx.vm_state.secret_share_interpolate_local(ty, &shares_data)
}

/// Get share type as string
fn share_get_type(ctx: ForeignFunctionContext) -> Result<Value, String> {
    if ctx.args.is_empty() {
        return Err("Share.get_type expects 1 argument: share".to_string());
    }

    let ty = share_object::get_share_type(&ctx.vm_state.object_store, &ctx.args[0])?;
    let type_str = match ty {
        ShareType::SecretInt { .. } => "SecretInt",
        ShareType::SecretFixedPoint { .. } => "SecretFixedPoint",
    };

    Ok(Value::String(type_str.to_string()))
}

/// Get party ID from share object
fn share_get_party_id(ctx: ForeignFunctionContext) -> Result<Value, String> {
    if ctx.args.is_empty() {
        return Err("Share.get_party_id expects 1 argument: share".to_string());
    }

    match &ctx.args[0] {
        Value::Object(_) => {
            let party_id = ctx
                .vm_state
                .object_store
                .get_field(&ctx.args[0], &Value::String(share_fields::PARTY_ID.to_string()))
                .ok_or_else(|| "Share object missing __party_id field".to_string())?;
            Ok(party_id)
        }
        Value::Share(_, _) => {
            // For raw shares, return current party ID
            let party_id = ctx
                .vm_state
                .mpc_engine()
                .map(|e| e.party_id())
                .unwrap_or(0);
            Ok(Value::I64(party_id as i64))
        }
        _ => Err("Expected Share object".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_object_creation() {
        use stoffel_vm_types::core_types::ObjectStore;

        let mut store = ObjectStore::new();
        let share_type = ShareType::default_secret_int();
        let data = vec![1, 2, 3, 4];
        let party_id = 0;

        let id = share_object::create_share_object(&mut store, share_type, data.clone(), party_id);

        // Verify we can extract the share data
        let result = share_object::extract_share_data(&store, &Value::Object(id));
        assert!(result.is_ok());
        let (ty, extracted_data) = result.unwrap();
        assert_eq!(ty, share_type);
        assert_eq!(extracted_data, data);
    }

    #[test]
    fn test_is_share_object() {
        use stoffel_vm_types::core_types::ObjectStore;

        let mut store = ObjectStore::new();
        let share_type = ShareType::default_secret_int();
        let data = vec![1, 2, 3, 4];

        let share_id = share_object::create_share_object(&mut store, share_type, data, 0);
        let non_share_id = store.create_object();

        assert!(share_object::is_share_object(&store, &Value::Object(share_id)));
        assert!(!share_object::is_share_object(
            &store,
            &Value::Object(non_share_id)
        ));
        assert!(share_object::is_share_object(
            &store,
            &Value::Share(share_type, vec![])
        ));
        assert!(!share_object::is_share_object(&store, &Value::I64(42)));
    }
}
