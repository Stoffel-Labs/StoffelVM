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
use sha2::{Digest, Sha256, Sha512};
use stoffel_vm_types::core_types::{ObjectStore, ShareData, ShareType, Value};

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

/// Helper module for Share object operations
pub mod share_object {
    use super::share_fields;
    use stoffel_vm_types::core_types::{ObjectStore, ShareData, ShareType, Value};

    /// Create a new Share object in the object store
    ///
    /// # Arguments
    /// * `store` - The object store to create the share in
    /// * `share_type` - The type of share (SecretInt or SecretFixedPoint)
    /// * `data` - The share data
    /// * `party_id` - The party ID that created this share
    ///
    /// # Returns
    /// The object ID of the created share
    pub fn create_share_object(
        store: &mut ObjectStore,
        share_type: ShareType,
        data: ShareData,
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
    ) -> Result<(ShareType, ShareData), String> {
        match value {
            // Direct share value (backward compatibility)
            Value::Share(ty, data) => Ok((*ty, data.clone())),

            // Share object
            Value::Object(_id) => {
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

// ============================================================================
// Byte array helpers
// ============================================================================

/// Extract a `Vec<u8>` from a VM byte array (`Value::Array` of `Value::U8`).
fn extract_byte_array(store: &ObjectStore, value: &Value) -> Result<Vec<u8>, String> {
    match value {
        Value::Array(arr_id) => {
            let arr = store.get_array(*arr_id).ok_or("Array not found")?;
            let len = arr.length();
            let mut bytes = Vec::with_capacity(len);
            for i in 0..len {
                match arr.get(&Value::I64(i as i64)) {
                    Some(Value::U8(b)) => bytes.push(*b),
                    _ => return Err(format!("Expected U8 at index {}", i)),
                }
            }
            Ok(bytes)
        }
        _ => Err("Expected byte array".to_string()),
    }
}

/// Create a VM byte array (`Value::Array` of `Value::U8`) from raw bytes.
fn create_byte_array(store: &mut ObjectStore, bytes: &[u8]) -> usize {
    let arr_id = store.create_array_with_capacity(bytes.len());
    let arr = store.get_array_mut(arr_id).unwrap();
    for (i, &b) in bytes.iter().enumerate() {
        arr.set(Value::I64(i as i64), Value::U8(b));
    }
    arr_id
}

/// Register all MPC builtin functions with the VM
pub fn register_mpc_builtins(vm: &mut VirtualMachine) {
    register_share_builtins(vm);
    register_mpc_info_builtins(vm);
    register_rbc_builtins(vm);
    register_aba_builtins(vm);
    register_crypto_builtins(vm);
    register_bytes_builtins(vm);
    #[cfg(feature = "avss")]
    register_avss_builtins(vm);
}

/// Register Share module builtins
fn register_share_builtins(vm: &mut VirtualMachine) {
    // Share.from_clear - Create share from clear value (auto-detect type)
    vm.register_foreign_function("Share.from_clear", |ctx| share_from_clear(ctx, None));

    // Share.from_clear_int - Create integer share with custom bit length
    vm.register_foreign_function("Share.from_clear_int", |ctx| {
        if ctx.args.len() < 2 {
            return Err("Share.from_clear_int expects 2 arguments: value, bit_length".to_string());
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

    // Share.batch_open - Batch reconstruct array of secrets (network operation, more efficient)
    vm.register_foreign_function("Share.batch_open", share_batch_open);

    // Share.send_to_client - Send share to specific client (network operation)
    vm.register_foreign_function("Share.send_to_client", share_send_to_client);

    // Share.interpolate_local - Local reconstruction from array of shares
    vm.register_foreign_function("Share.interpolate_local", share_interpolate_local);

    // Share.get_type - Get the share type as string
    vm.register_foreign_function("Share.get_type", share_get_type);

    // Share.get_party_id - Get the party ID from share object
    vm.register_foreign_function("Share.get_party_id", share_get_party_id);

    // Share.open_exp - Reveal share in the exponent (returns public group element)
    vm.register_foreign_function("Share.open_exp", share_open_exp);

    // Share.random - Generate a jointly-random share (DKG)
    // No party knows the secret. In AVSS mode, the share carries Feldman
    // commitments where commitment[0] = g^secret = public key.
    vm.register_foreign_function("Share.random", |ctx| {
        let engine = ctx
            .vm_state
            .mpc_engine()
            .ok_or_else(|| "MPC engine not configured".to_string())?;
        let share_type = ShareType::default_secret_int();
        let share_data = engine.random_share(share_type)?;
        let party_id = engine.party_id();
        let obj_id = share_object::create_share_object(
            &mut ctx.vm_state.object_store,
            share_type,
            share_data,
            party_id,
        );
        Ok(Value::Object(obj_id))
    });

    // Share.get_commitment - Extract a Feldman commitment from a share
    // commitment[0] is the public key. Only available on shares from AVSS backend.
    // Returns a byte array.
    vm.register_foreign_function("Share.get_commitment", |ctx| {
        if ctx.args.len() < 2 {
            return Err(
                "Share.get_commitment expects 2 arguments: share, index".to_string(),
            );
        }
        let (_, share_data) =
            share_object::extract_share_data(&ctx.vm_state.object_store, &ctx.args[0])?;
        let index = match &ctx.args[1] {
            Value::I64(n) if *n >= 0 => *n as usize,
            _ => return Err("index must be a non-negative integer".to_string()),
        };
        let commitments = share_data
            .commitments()
            .ok_or("Share does not have Feldman commitments (requires AVSS backend)")?;
        let commitment = commitments
            .get(index)
            .ok_or_else(|| format!("Commitment index {} out of bounds (have {})", index, commitments.len()))?;
        let arr_id = ctx
            .vm_state
            .object_store
            .create_array_with_capacity(commitment.len());
        {
            let arr = ctx
                .vm_state
                .object_store
                .get_array_mut(arr_id)
                .ok_or("failed to access commitment byte array")?;
            for (i, &byte) in commitment.iter().enumerate() {
                arr.set(Value::I64(i as i64), Value::U8(byte));
            }
        }
        Ok(Value::Array(arr_id))
    });

    // Share.commitment_count - Get the number of Feldman commitments on a share
    vm.register_foreign_function("Share.commitment_count", |ctx| {
        if ctx.args.is_empty() {
            return Err("Share.commitment_count expects 1 argument: share".to_string());
        }
        let (_, share_data) =
            share_object::extract_share_data(&ctx.vm_state.object_store, &ctx.args[0])?;
        match share_data.commitments() {
            Some(c) => Ok(Value::I64(c.len() as i64)),
            None => Ok(Value::I64(0)),
        }
    });

    // Share.has_commitments - Check if a share carries Feldman commitments
    vm.register_foreign_function("Share.has_commitments", |ctx| {
        if ctx.args.is_empty() {
            return Err("Share.has_commitments expects 1 argument: share".to_string());
        }
        let (_, share_data) =
            share_object::extract_share_data(&ctx.vm_state.object_store, &ctx.args[0])?;
        Ok(Value::Bool(share_data.has_commitments()))
    });

    // Share.mul_field - Multiply share by a field element (given as byte array)
    vm.register_foreign_function("Share.mul_field", |ctx| {
        if ctx.args.len() < 2 {
            return Err(
                "Share.mul_field expects 2 arguments: share, field_bytes".to_string(),
            );
        }

        let (ty, data) =
            share_object::extract_share_data(&ctx.vm_state.object_store, &ctx.args[0])?;
        let field_bytes = extract_byte_array(&ctx.vm_state.object_store, &ctx.args[1])?;

        let result_data =
            ctx.vm_state
                .secret_share_mul_field(ty, data.as_bytes(), &field_bytes)?;

        let party_id = ctx
            .vm_state
            .mpc_engine()
            .map(|e| e.party_id())
            .unwrap_or(0);

        let obj_id = share_object::create_share_object(
            &mut ctx.vm_state.object_store,
            ty,
            ShareData::Opaque(result_data),
            party_id,
        );

        Ok(Value::Object(obj_id))
    });

    // Share.open_field - Open a share and return the raw field element bytes
    vm.register_foreign_function("Share.open_field", |ctx| {
        if ctx.args.is_empty() {
            return Err("Share.open_field expects 1 argument: share".to_string());
        }

        let engine = ctx
            .vm_state
            .mpc_engine()
            .ok_or_else(|| "MPC engine not configured".to_string())?;

        if !engine.is_ready() {
            return Err("MPC engine not ready".to_string());
        }

        let (ty, data) =
            share_object::extract_share_data(&ctx.vm_state.object_store, &ctx.args[0])?;

        let result_bytes = engine.open_share_as_field(ty, data.as_bytes())?;

        let arr_id = create_byte_array(&mut ctx.vm_state.object_store, &result_bytes);
        Ok(Value::Array(arr_id))
    });

    // Share.open_exp_custom - Reveal share in the exponent with a custom generator point
    // Same as Share.open_exp but the generator is provided directly as bytes
    vm.register_foreign_function("Share.open_exp_custom", |ctx| {
        if ctx.args.len() < 2 {
            return Err(
                "Share.open_exp_custom expects 2 arguments: share, generator_bytes".to_string(),
            );
        }

        let engine = ctx
            .vm_state
            .mpc_engine()
            .ok_or_else(|| "MPC engine not configured".to_string())?;

        if !engine.is_ready() {
            return Err("MPC engine not ready".to_string());
        }

        if !engine.supports_open_share_in_exp() {
            return Err(format!(
                "MPC backend '{}' does not support Share.open_exp_custom",
                engine.protocol_name()
            ));
        }

        let (ty, data) =
            share_object::extract_share_data(&ctx.vm_state.object_store, &ctx.args[0])?;
        let gen_bytes = extract_byte_array(&ctx.vm_state.object_store, &ctx.args[1])?;

        let result_bytes = engine.open_share_in_exp(ty, data.as_bytes(), &gen_bytes)?;

        let arr_id = create_byte_array(&mut ctx.vm_state.object_store, &result_bytes);
        Ok(Value::Array(arr_id))
    });
}

// ============================================================================
// Bytes builtins
// ============================================================================

/// Register Bytes module builtins
fn register_bytes_builtins(vm: &mut VirtualMachine) {
    // Bytes.concat - Concatenate two byte arrays
    vm.register_foreign_function("Bytes.concat", |ctx| {
        if ctx.args.len() < 2 {
            return Err("Bytes.concat expects 2 arguments: a, b".to_string());
        }

        let a = extract_byte_array(&ctx.vm_state.object_store, &ctx.args[0])?;
        let b = extract_byte_array(&ctx.vm_state.object_store, &ctx.args[1])?;

        let mut combined = Vec::with_capacity(a.len() + b.len());
        combined.extend_from_slice(&a);
        combined.extend_from_slice(&b);

        let arr_id = create_byte_array(&mut ctx.vm_state.object_store, &combined);
        Ok(Value::Array(arr_id))
    });

    // Bytes.from_string - Convert a string to a byte array
    vm.register_foreign_function("Bytes.from_string", |ctx| {
        if ctx.args.is_empty() {
            return Err("Bytes.from_string expects 1 argument: string".to_string());
        }

        let s = match &ctx.args[0] {
            Value::String(s) => s.clone(),
            _ => return Err("Argument must be a string".to_string()),
        };

        let bytes = s.as_bytes();
        let arr_id = create_byte_array(&mut ctx.vm_state.object_store, bytes);
        Ok(Value::Array(arr_id))
    });
}

// ============================================================================
// Crypto builtins
// ============================================================================

/// Register Crypto module builtins
fn register_crypto_builtins(vm: &mut VirtualMachine) {
    // Crypto.sha256 - Compute SHA-256 hash of byte array
    vm.register_foreign_function("Crypto.sha256", |ctx| {
        if ctx.args.is_empty() {
            return Err("Crypto.sha256 expects 1 argument: data (byte array)".to_string());
        }

        let bytes = extract_byte_array(&ctx.vm_state.object_store, &ctx.args[0])?;
        let hash = Sha256::digest(&bytes);

        let arr_id = create_byte_array(&mut ctx.vm_state.object_store, &hash);
        Ok(Value::Array(arr_id))
    });

    // Crypto.sha512 - Compute SHA-512 hash of byte array
    vm.register_foreign_function("Crypto.sha512", |ctx| {
        if ctx.args.is_empty() {
            return Err("Crypto.sha512 expects 1 argument: data (byte array)".to_string());
        }

        let bytes = extract_byte_array(&ctx.vm_state.object_store, &ctx.args[0])?;
        let hash = Sha512::digest(&bytes);

        let arr_id = create_byte_array(&mut ctx.vm_state.object_store, &hash);
        Ok(Value::Array(arr_id))
    });

    // Crypto.hash_to_field - Hash bytes to a field element (reduced mod field order)
    vm.register_foreign_function("Crypto.hash_to_field", |ctx| {
        if ctx.args.len() < 2 {
            return Err(
                "Crypto.hash_to_field expects 2 arguments: hash_bytes, curve_name".to_string(),
            );
        }

        let hash_bytes = extract_byte_array(&ctx.vm_state.object_store, &ctx.args[0])?;

        let curve_name = match &ctx.args[1] {
            Value::String(s) => s.clone(),
            _ => return Err("curve_name must be a string".to_string()),
        };

        use crate::net::curve::MpcCurveConfig;
        use ark_ff::PrimeField;
        use ark_serialize::CanonicalSerialize;

        let curve = curve_name
            .parse::<MpcCurveConfig>()
            .map_err(|e| format!("Invalid curve name: {}", e))?;

        let out_bytes = match curve {
            MpcCurveConfig::Bls12_381 => {
                let field_elem = ark_bls12_381::Fr::from_be_bytes_mod_order(&hash_bytes);
                let mut out = Vec::new();
                field_elem
                    .serialize_compressed(&mut out)
                    .map_err(|e| format!("serialize field element: {}", e))?;
                out
            }
            MpcCurveConfig::Bn254 => {
                let field_elem = ark_bn254::Fr::from_be_bytes_mod_order(&hash_bytes);
                let mut out = Vec::new();
                field_elem
                    .serialize_compressed(&mut out)
                    .map_err(|e| format!("serialize field element: {}", e))?;
                out
            }
            MpcCurveConfig::Curve25519 | MpcCurveConfig::Ed25519 => {
                // Ed25519/Curve25519 uses little-endian byte order per RFC 8032
                let field_elem = ark_curve25519::Fr::from_le_bytes_mod_order(&hash_bytes);
                let mut out = Vec::new();
                field_elem
                    .serialize_compressed(&mut out)
                    .map_err(|e| format!("serialize field element: {}", e))?;
                out
            }
        };

        let arr_id = create_byte_array(&mut ctx.vm_state.object_store, &out_bytes);
        Ok(Value::Array(arr_id))
    });

    // Crypto.hash_to_g1 - Hash bytes to a BLS12-381 G1 point
    //
    // Uses try-and-increment: H(msg || counter) is interpreted as a
    // candidate Fq x-coordinate. If a valid G1 point exists at that x,
    // we use it; otherwise increment counter and retry. This avoids
    // a known DLOG relation between the hash point and the generator.
    vm.register_foreign_function("Crypto.hash_to_g1", |ctx| {
        if ctx.args.is_empty() {
            return Err("Crypto.hash_to_g1 expects 1 argument: data (byte array)".to_string());
        }

        let bytes = extract_byte_array(&ctx.vm_state.object_store, &ctx.args[0])?;

        use ark_bls12_381::{Fq, G1Affine};
        use ark_ec::AffineRepr;
        use ark_ff::PrimeField;
        use ark_serialize::CanonicalSerialize;

        // Try-and-increment: hash(msg || counter) → Fq → try as x-coord
        let mut point: Option<G1Affine> = None;
        for counter in 0u32..256 {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            hasher.update(counter.to_le_bytes());
            let hash = hasher.finalize();
            let x = Fq::from_be_bytes_mod_order(&hash);
            if let Some(p) = G1Affine::get_point_from_x_unchecked(x, false) {
                if p.is_on_curve() && !p.is_zero() {
                    // Clear cofactor to ensure we're in the prime-order subgroup
                    let cleared = p.clear_cofactor();
                    if !cleared.is_zero() {
                        point = Some(cleared);
                        break;
                    }
                }
            }
        }

        let p = point.ok_or("hash_to_g1: failed to find valid point after 256 attempts")?;
        let mut out = Vec::new();
        p.serialize_compressed(&mut out)
            .map_err(|e| format!("serialize G1 point: {}", e))?;

        let arr_id = create_byte_array(&mut ctx.vm_state.object_store, &out);
        Ok(Value::Array(arr_id))
    });
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

    // Mpc.rand - Generate 32 cryptographically random bytes (local, not MPC)
    // Note: rand 0.9 ThreadRng is backed by OsRng-seeded ChaCha (CSPRNG).
    vm.register_foreign_function("Mpc.rand", |ctx| {
        use rand::RngCore;
        let mut bytes = vec![0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        let arr_id = ctx
            .vm_state
            .object_store
            .create_array_with_capacity(bytes.len());
        {
            let arr = ctx
                .vm_state
                .object_store
                .get_array_mut(arr_id)
                .ok_or_else(|| "Failed to create result array".to_string())?;
            for (i, byte) in bytes.into_iter().enumerate() {
                arr.set(Value::I64(i as i64), Value::U8(byte));
            }
        }
        Ok(Value::Array(arr_id))
    });

    // Mpc.rand_int - Generate a cryptographically random integer (local, not MPC)
    // Accepts bit_length: 8, 16, 32, or 64 — returns the corresponding unsigned int type
    // Note: rand 0.9 ThreadRng is backed by OsRng-seeded ChaCha (CSPRNG).
    vm.register_foreign_function("Mpc.rand_int", |ctx| {
        use rand::Rng;
        if ctx.args.is_empty() {
            return Err(
                "Mpc.rand_int expects 1 argument: bit_length (8, 16, 32, or 64)".to_string(),
            );
        }
        let bit_length = match &ctx.args[0] {
            Value::I64(n) if *n > 0 => *n as usize,
            _ => return Err("bit_length must be a positive integer".to_string()),
        };
        let mut rng = rand::rng();
        match bit_length {
            8 => Ok(Value::U8(rng.random())),
            16 => Ok(Value::U16(rng.random())),
            32 => Ok(Value::U32(rng.random())),
            64 => Ok(Value::U64(rng.random())),
            _ => Err(format!(
                "Unsupported bit_length {}. Must be 8, 16, 32, or 64",
                bit_length
            )),
        }
    });
}

/// Register RBC (Reliable Broadcast) builtins
fn register_rbc_builtins(vm: &mut VirtualMachine) {
    // Rbc.broadcast - Broadcast a message reliably
    vm.register_foreign_function("Rbc.broadcast", |ctx| {
        let engine = ctx
            .vm_state
            .mpc_engine()
            .ok_or_else(|| "MPC engine not configured".to_string())?;

        let consensus = engine
            .as_consensus()
            .ok_or_else(|| "MPC engine does not support consensus (RBC/ABA)".to_string())?;

        // Get message from args
        if ctx.args.is_empty() {
            return Err("Rbc.broadcast expects 1 argument: message".to_string());
        }

        let message_bytes = match &ctx.args[0] {
            Value::String(s) => s.as_bytes().to_vec(),
            _ => return Err("Message must be a string".to_string()),
        };

        let session_id = consensus.rbc_broadcast(&message_bytes)?;
        Ok(Value::I64(session_id as i64))
    });

    // Rbc.receive - Receive broadcast from specific party
    vm.register_foreign_function("Rbc.receive", |ctx| {
        let engine = ctx
            .vm_state
            .mpc_engine()
            .ok_or_else(|| "MPC engine not configured".to_string())?;

        let consensus = engine
            .as_consensus()
            .ok_or_else(|| "MPC engine does not support consensus (RBC/ABA)".to_string())?;

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

        let message = consensus.rbc_receive(from_party, timeout_ms)?;
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

        let consensus = engine
            .as_consensus()
            .ok_or_else(|| "MPC engine does not support consensus (RBC/ABA)".to_string())?;

        if ctx.args.is_empty() {
            return Err("Rbc.receive_any expects 1 argument: timeout_ms".to_string());
        }

        let timeout_ms = match &ctx.args[0] {
            Value::I64(n) if *n >= 0 => *n as u64,
            _ => return Err("timeout_ms must be a non-negative integer".to_string()),
        };

        let (party_id, message) = consensus.rbc_receive_any(timeout_ms)?;

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
    // Aba.propose - Propose a binary value
    vm.register_foreign_function("Aba.propose", |ctx| {
        let engine = ctx
            .vm_state
            .mpc_engine()
            .ok_or_else(|| "MPC engine not configured".to_string())?;

        let consensus = engine
            .as_consensus()
            .ok_or_else(|| "MPC engine does not support consensus (RBC/ABA)".to_string())?;

        if ctx.args.is_empty() {
            return Err("Aba.propose expects 1 argument: value (bool)".to_string());
        }

        let value = match &ctx.args[0] {
            Value::Bool(b) => *b,
            _ => return Err("value must be a boolean".to_string()),
        };

        let session_id = consensus.aba_propose(value)?;
        Ok(Value::I64(session_id as i64))
    });

    // Aba.result - Get agreed result
    vm.register_foreign_function("Aba.result", |ctx| {
        let engine = ctx
            .vm_state
            .mpc_engine()
            .ok_or_else(|| "MPC engine not configured".to_string())?;

        let consensus = engine
            .as_consensus()
            .ok_or_else(|| "MPC engine does not support consensus (RBC/ABA)".to_string())?;

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

        let result = consensus.aba_result(session_id, timeout_ms)?;
        Ok(Value::Bool(result))
    });

    // Aba.propose_and_wait - Propose and wait for result
    vm.register_foreign_function("Aba.propose_and_wait", |ctx| {
        let engine = ctx
            .vm_state
            .mpc_engine()
            .ok_or_else(|| "MPC engine not configured".to_string())?;

        let consensus = engine
            .as_consensus()
            .ok_or_else(|| "MPC engine does not support consensus (RBC/ABA)".to_string())?;

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

        let result = consensus.aba_propose_and_wait(value, timeout_ms)?;
        Ok(Value::Bool(result))
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
            _ => {
                return Err(format!(
                    "Cannot create share from value type: {:?}",
                    clear_value
                ))
            }
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
        (ShareType::SecretInt { bit_length }, Value::Bool(b)) if bit_length == 1 => Value::Bool(*b),
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
        return Err(format!("Share type mismatch: {:?} vs {:?}", ty1, ty2));
    }

    // Perform addition using VM's share arithmetic
    let result_data = ctx.vm_state.secret_share_add(ty1, data1.as_bytes(), data2.as_bytes())?;

    let party_id = ctx.vm_state.mpc_engine().map(|e| e.party_id()).unwrap_or(0);

    let obj_id = share_object::create_share_object(
        &mut ctx.vm_state.object_store,
        ty1,
        ShareData::Opaque(result_data),
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
        return Err(format!("Share type mismatch: {:?} vs {:?}", ty1, ty2));
    }

    let result_data = ctx.vm_state.secret_share_sub(ty1, data1.as_bytes(), data2.as_bytes())?;

    let party_id = ctx.vm_state.mpc_engine().map(|e| e.party_id()).unwrap_or(0);

    let obj_id = share_object::create_share_object(
        &mut ctx.vm_state.object_store,
        ty1,
        ShareData::Opaque(result_data),
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

    let result_data = ctx.vm_state.secret_share_neg(ty, data.as_bytes())?;

    let party_id = ctx.vm_state.mpc_engine().map(|e| e.party_id()).unwrap_or(0);

    let obj_id = share_object::create_share_object(
        &mut ctx.vm_state.object_store,
        ty,
        ShareData::Opaque(result_data),
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

    let result_data = ctx.vm_state.secret_share_add_scalar(ty, data.as_bytes(), scalar)?;

    let party_id = ctx.vm_state.mpc_engine().map(|e| e.party_id()).unwrap_or(0);

    let obj_id = share_object::create_share_object(
        &mut ctx.vm_state.object_store,
        ty,
        ShareData::Opaque(result_data),
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

    let result_data = ctx.vm_state.secret_share_mul_scalar(ty, data.as_bytes(), scalar)?;

    let party_id = ctx.vm_state.mpc_engine().map(|e| e.party_id()).unwrap_or(0);

    let obj_id = share_object::create_share_object(
        &mut ctx.vm_state.object_store,
        ty,
        ShareData::Opaque(result_data),
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
        return Err(format!("Share type mismatch: {:?} vs {:?}", ty1, ty2));
    }

    // Perform MPC multiplication
    let result_data = engine.multiply_share(ty1, data1.as_bytes(), data2.as_bytes())?;
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

    engine.open_share(ty, data.as_bytes())
}

/// Batch open/reveal an array of shares (network operation - more efficient than individual opens)
///
/// This function reveals multiple secrets at once, reducing network rounds.
/// All shares in the array must be of the same type.
///
/// # Arguments
/// * `shares_array` - Array of Share objects to reveal
///
/// # Returns
/// Array of revealed values (I64 for SecretInt, Float for SecretFixedPoint)
fn share_batch_open(ctx: ForeignFunctionContext) -> Result<Value, String> {
    if ctx.args.is_empty() {
        return Err("Share.batch_open expects 1 argument: shares_array".to_string());
    }

    let engine = ctx
        .vm_state
        .mpc_engine()
        .ok_or_else(|| "MPC engine not configured".to_string())?;

    if !engine.is_ready() {
        return Err("MPC engine not ready".to_string());
    }

    // Extract array
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
        // Return empty array
        let result_id = ctx.vm_state.object_store.create_array();
        return Ok(Value::Array(result_id));
    }

    // Extract all share data from the array
    let mut share_data: Vec<(ShareType, ShareData)> = Vec::with_capacity(len);

    for i in 0..len {
        let idx = Value::I64(i as i64);
        let value = array
            .get(&idx)
            .ok_or_else(|| format!("Missing element at index {}", i))?;

        let (ty, data) = share_object::extract_share_data(&ctx.vm_state.object_store, value)?;
        share_data.push((ty, data));
    }

    // Verify all shares have the same type
    let first_ty = share_data[0].0;
    for (i, (ty, _)) in share_data.iter().enumerate().skip(1) {
        if *ty != first_ty {
            return Err(format!(
                "All shares must have the same type. Element 0 has {:?} but element {} has {:?}",
                first_ty, i, ty
            ));
        }
    }

    // Collect share bytes for batch reveal
    let shares: Vec<Vec<u8>> = share_data.iter().map(|(_, d)| d.as_bytes().to_vec()).collect();

    // Perform batch reveal
    let revealed = engine.batch_open_shares(first_ty, &shares)?;

    // Create result array
    let result_id = ctx
        .vm_state
        .object_store
        .create_array_with_capacity(revealed.len());
    let result_array = ctx
        .vm_state
        .object_store
        .get_array_mut(result_id)
        .ok_or_else(|| "Failed to create result array".to_string())?;

    for (i, value) in revealed.into_iter().enumerate() {
        result_array.set(Value::I64(i as i64), value);
    }

    Ok(Value::Array(result_id))
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

    engine.send_output_to_client(client_id, data.as_bytes(), 1)?;
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
        let element = array
            .get(&idx)
            .ok_or_else(|| format!("Missing element at index {}", i))?;

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

        shares_data.push(data.into_bytes());
    }

    let ty = share_type.unwrap();

    // Perform local interpolation
    ctx.vm_state
        .secret_share_interpolate_local(ty, &shares_data)
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
                .get_field(
                    &ctx.args[0],
                    &Value::String(share_fields::PARTY_ID.to_string()),
                )
                .ok_or_else(|| "Share object missing __party_id field".to_string())?;
            Ok(party_id)
        }
        Value::Share(_, _) => {
            // For raw shares, return current party ID
            let party_id = ctx.vm_state.mpc_engine().map(|e| e.party_id()).unwrap_or(0);
            Ok(Value::I64(party_id as i64))
        }
        _ => Err("Expected Share object".to_string()),
    }
}

/// Open a share in the exponent — returns the public group element `[secret] * generator`
///
/// # Arguments
/// * `share` - A Share object
/// * `curve_name` - String identifying the curve + generator (e.g. "bls12-381-g1")
///
/// # Returns
/// An array of U8 values containing the serialized (compressed) group element
fn share_open_exp(ctx: ForeignFunctionContext) -> Result<Value, String> {
    if ctx.args.len() < 2 {
        return Err("Share.open_exp expects 2 arguments: share, curve_name".to_string());
    }

    let engine = ctx
        .vm_state
        .mpc_engine()
        .ok_or_else(|| "MPC engine not configured".to_string())?;

    if !engine.is_ready() {
        return Err("MPC engine not ready".to_string());
    }

    if !engine.supports_open_share_in_exp() {
        return Err(format!(
            "MPC backend '{}' does not support Share.open_exp",
            engine.protocol_name()
        ));
    }

    let (ty, data) = share_object::extract_share_data(&ctx.vm_state.object_store, &ctx.args[0])?;

    let curve_name = match &ctx.args[1] {
        Value::String(s) => s.as_str(),
        _ => return Err("curve_name must be a string".to_string()),
    };

    // Special case: G2 threshold exponentiation for BLS12-381 threshold BLS signatures.
    // This uses a separate trait (ThresholdExpG2) with its own wire protocol and registry.
    #[cfg(feature = "avss")]
    if curve_name == "bls12-381-g2" {
        use crate::net::avss_engine::{Bls12381AvssMpcEngine, ThresholdExpG2};
        use ark_bls12_381::G2Projective;
        use ark_ec::{CurveGroup, PrimeGroup};
        use ark_serialize::CanonicalSerialize;

        let g2_engine: &Bls12381AvssMpcEngine = engine
            .as_any()
            .and_then(|any| any.downcast_ref::<Bls12381AvssMpcEngine>())
            .ok_or_else(|| {
                "G2 threshold exponentiation requires the BLS12-381 AVSS backend".to_string()
            })?;

        let gen = G2Projective::generator();
        let mut gen_bytes = Vec::new();
        gen.into_affine()
            .serialize_compressed(&mut gen_bytes)
            .map_err(|e| format!("serialize G2 generator: {}", e))?;

        let result_bytes = g2_engine.open_share_in_exp_g2(data.as_bytes(), &gen_bytes)?;

        let arr_id = ctx
            .vm_state
            .object_store
            .create_array_with_capacity(result_bytes.len());
        {
            let arr = ctx
                .vm_state
                .object_store
                .get_array_mut(arr_id)
                .ok_or_else(|| "Failed to create result array".to_string())?;
            for (i, byte) in result_bytes.into_iter().enumerate() {
                arr.set(Value::I64(i as i64), Value::U8(byte));
            }
        }
        return Ok(Value::Array(arr_id));
    }
    #[cfg(not(feature = "avss"))]
    if curve_name == "bls12-381-g2" {
        return Err("G2 threshold exponentiation requires the 'avss' feature".to_string());
    }

    // Map curve name to the serialized generator point
    let generator_bytes = match curve_name {
        "bls12-381-g1" => {
            use ark_bls12_381::G1Projective;
            use ark_ec::{CurveGroup, PrimeGroup};
            use ark_serialize::CanonicalSerialize;
            let gen = G1Projective::generator();
            let mut buf = Vec::new();
            gen.into_affine()
                .serialize_compressed(&mut buf)
                .map_err(|e| format!("serialize generator: {}", e))?;
            buf
        }
        "bn254-g1" => {
            use ark_bn254::G1Projective;
            use ark_ec::{CurveGroup, PrimeGroup};
            use ark_serialize::CanonicalSerialize;
            let gen = G1Projective::generator();
            let mut buf = Vec::new();
            gen.into_affine()
                .serialize_compressed(&mut buf)
                .map_err(|e| format!("serialize generator: {}", e))?;
            buf
        }
        "curve25519-edwards" => {
            use ark_curve25519::EdwardsProjective;
            use ark_ec::{CurveGroup, PrimeGroup};
            use ark_serialize::CanonicalSerialize;
            let gen = EdwardsProjective::generator();
            let mut buf = Vec::new();
            gen.into_affine()
                .serialize_compressed(&mut buf)
                .map_err(|e| format!("serialize generator: {}", e))?;
            buf
        }
        "ed25519-edwards" => {
            use ark_ec::{CurveGroup, PrimeGroup};
            use ark_ed25519::EdwardsProjective;
            use ark_serialize::CanonicalSerialize;
            let gen = EdwardsProjective::generator();
            let mut buf = Vec::new();
            gen.into_affine()
                .serialize_compressed(&mut buf)
                .map_err(|e| format!("serialize generator: {}", e))?;
            buf
        }
        _ => return Err(format!("Unsupported curve: {}", curve_name)),
    };

    let result_bytes = engine.open_share_in_exp(ty, data.as_bytes(), &generator_bytes)?;

    // Return as byte array
    let arr_id = ctx
        .vm_state
        .object_store
        .create_array_with_capacity(result_bytes.len());
    {
        let arr = ctx
            .vm_state
            .object_store
            .get_array_mut(arr_id)
            .ok_or_else(|| "Failed to create result array".to_string())?;
        for (i, byte) in result_bytes.into_iter().enumerate() {
            arr.set(Value::I64(i as i64), Value::U8(byte));
        }
    }
    Ok(Value::Array(arr_id))
}

/// Field name constants for AVSS share objects
#[cfg(feature = "avss")]
pub mod avss_fields {
    pub const TYPE: &str = "__type";
    pub const KEY_NAME: &str = "__key_name";
    pub const SHARE_DATA: &str = "__share_data";
    pub const COMMITMENTS: &str = "__commitments";
    pub const PARTY_ID: &str = "__party_id";
    pub const TYPE_VALUE: &str = "AvssShare";
}

/// Helper module for AVSS share object operations
#[cfg(feature = "avss")]
pub mod avss_object {
    use super::avss_fields;
    use stoffel_vm_types::core_types::{ObjectStore, Value};

    /// Create a new AVSS share object in the object store
    ///
    /// # Arguments
    /// * `store` - The object store to create the object in
    /// * `key_name` - User-defined key name for this share
    /// * `share_data` - The serialized Feldman share
    /// * `commitment_bytes` - Array of serialized commitment group elements
    /// * `party_id` - The party ID
    ///
    /// # Returns
    /// The object ID of the created AVSS share
    pub fn create_avss_share_object(
        store: &mut ObjectStore,
        key_name: &str,
        share_data: Vec<u8>,
        commitment_bytes: Vec<Vec<u8>>,
        party_id: usize,
    ) -> Result<usize, String> {
        let id = store.create_object();
        let obj = Value::Object(id);

        // Set type tag
        store
            .set_field(
                &obj,
                Value::String(avss_fields::TYPE.to_string()),
                Value::String(avss_fields::TYPE_VALUE.to_string()),
            )
            .map_err(|e| format!("failed to set AVSS type tag: {}", e))?;

        // Set key name
        store
            .set_field(
                &obj,
                Value::String(avss_fields::KEY_NAME.to_string()),
                Value::String(key_name.to_string()),
            )
            .map_err(|e| format!("failed to set AVSS key name: {}", e))?;

        // Set share data as bytes (using a binary representation)
        // We'll store it as an array of U8 values
        let share_array_id = store.create_array_with_capacity(share_data.len());
        {
            let arr = store
                .get_array_mut(share_array_id)
                .ok_or_else(|| "failed to get share data array".to_string())?;
            for (i, byte) in share_data.into_iter().enumerate() {
                arr.set(Value::I64(i as i64), Value::U8(byte));
            }
        }
        store
            .set_field(
                &obj,
                Value::String(avss_fields::SHARE_DATA.to_string()),
                Value::Array(share_array_id),
            )
            .map_err(|e| format!("failed to set AVSS share data: {}", e))?;

        // Set commitments as array of byte arrays
        let commitment_arr_ids: Vec<usize> = commitment_bytes
            .into_iter()
            .enumerate()
            .map(|(idx, commitment)| {
                let commitment_arr_id = store.create_array_with_capacity(commitment.len());
                let commitment_arr = store
                    .get_array_mut(commitment_arr_id)
                    .ok_or_else(|| format!("failed to get commitment array at index {}", idx))?;
                for (j, byte) in commitment.into_iter().enumerate() {
                    commitment_arr.set(Value::I64(j as i64), Value::U8(byte));
                }
                Ok(commitment_arr_id)
            })
            .collect::<Result<Vec<_>, String>>()?;

        let commitments_array_id = store.create_array_with_capacity(commitment_arr_ids.len());
        {
            let arr = store
                .get_array_mut(commitments_array_id)
                .ok_or_else(|| "failed to get commitments array".to_string())?;
            for (i, commitment_arr_id) in commitment_arr_ids.into_iter().enumerate() {
                arr.set(Value::I64(i as i64), Value::Array(commitment_arr_id));
            }
        }
        store
            .set_field(
                &obj,
                Value::String(avss_fields::COMMITMENTS.to_string()),
                Value::Array(commitments_array_id),
            )
            .map_err(|e| format!("failed to set AVSS commitments: {}", e))?;

        // Set party ID
        store
            .set_field(
                &obj,
                Value::String(avss_fields::PARTY_ID.to_string()),
                Value::I64(party_id as i64),
            )
            .map_err(|e| format!("failed to set AVSS party ID: {}", e))?;

        Ok(id)
    }

    /// Check if a value is an AVSS share object
    pub fn is_avss_share_object(store: &ObjectStore, value: &Value) -> bool {
        match value {
            Value::Object(_) => store
                .get_field(value, &Value::String(avss_fields::TYPE.to_string()))
                .map(|v| v == Value::String(avss_fields::TYPE_VALUE.to_string()))
                .unwrap_or(false),
            _ => false,
        }
    }

    /// Extract key name from an AVSS share object
    pub fn get_key_name(store: &ObjectStore, value: &Value) -> Result<String, String> {
        let key_name_field = store
            .get_field(value, &Value::String(avss_fields::KEY_NAME.to_string()))
            .ok_or_else(|| "AVSS share object missing __key_name field".to_string())?;

        match key_name_field {
            Value::String(s) => Ok(s),
            _ => Err("Invalid key_name type".to_string()),
        }
    }

    /// Extract commitment at a specific index from an AVSS share object
    ///
    /// Returns the commitment as bytes (serialized group element)
    pub fn get_commitment(
        store: &ObjectStore,
        value: &Value,
        index: usize,
    ) -> Result<Vec<u8>, String> {
        let commitments_field = store
            .get_field(value, &Value::String(avss_fields::COMMITMENTS.to_string()))
            .ok_or_else(|| "AVSS share object missing __commitments field".to_string())?;

        let commitments_array_id = match commitments_field {
            Value::Array(id) => id,
            _ => return Err("Invalid commitments type".to_string()),
        };

        let commitments_array = store
            .get_array(commitments_array_id)
            .ok_or_else(|| "Commitments array not found".to_string())?;

        if index >= commitments_array.length() {
            return Err(format!(
                "Commitment index {} out of bounds (max: {})",
                index,
                commitments_array.length()
            ));
        }

        let commitment = commitments_array
            .get(&Value::I64(index as i64))
            .ok_or_else(|| format!("Commitment at index {} not found", index))?;

        let commitment_arr_id = match commitment {
            Value::Array(id) => *id,
            _ => return Err("Invalid commitment type".to_string()),
        };

        let commitment_arr = store
            .get_array(commitment_arr_id)
            .ok_or_else(|| "Commitment byte array not found".to_string())?;

        let mut bytes = Vec::with_capacity(commitment_arr.length());
        for i in 0..commitment_arr.length() {
            if let Some(Value::U8(b)) = commitment_arr.get(&Value::I64(i as i64)) {
                bytes.push(*b);
            } else {
                return Err("Invalid byte in commitment".to_string());
            }
        }

        Ok(bytes)
    }

    /// Get the number of commitments in an AVSS share object
    pub fn get_commitment_count(store: &ObjectStore, value: &Value) -> Result<usize, String> {
        let commitments_field = store
            .get_field(value, &Value::String(avss_fields::COMMITMENTS.to_string()))
            .ok_or_else(|| "AVSS share object missing __commitments field".to_string())?;

        let commitments_array_id = match commitments_field {
            Value::Array(id) => id,
            _ => return Err("Invalid commitments type".to_string()),
        };

        let commitments_array = store
            .get_array(commitments_array_id)
            .ok_or_else(|| "Commitments array not found".to_string())?;

        Ok(commitments_array.length())
    }
}

/// Register AVSS (Asynchronously Verifiable Secret Sharing) builtins
#[cfg(feature = "avss")]
fn register_avss_builtins(vm: &mut VirtualMachine) {
    // These builtins work on AVSS share objects stored in the VM

    // Avss.get_commitment - Get commitment at index from AVSS share
    // commitment[0] is the public key
    vm.register_foreign_function("Avss.get_commitment", |ctx| {
        if ctx.args.len() < 2 {
            return Err("Avss.get_commitment expects 2 arguments: avss_share, index".to_string());
        }

        if !avss_object::is_avss_share_object(&ctx.vm_state.object_store, &ctx.args[0]) {
            return Err("First argument must be an AVSS share object".to_string());
        }

        let index = match &ctx.args[1] {
            Value::I64(n) if *n >= 0 => *n as usize,
            Value::U64(n) => *n as usize,
            _ => return Err("index must be a non-negative integer".to_string()),
        };

        let commitment_bytes =
            avss_object::get_commitment(&ctx.vm_state.object_store, &ctx.args[0], index)?;

        let arr_id = ctx
            .vm_state
            .object_store
            .create_array_with_capacity(commitment_bytes.len());
        {
            let arr = ctx
                .vm_state
                .object_store
                .get_array_mut(arr_id)
                .ok_or("failed to access commitment byte array")?;
            for (i, byte) in commitment_bytes.into_iter().enumerate() {
                arr.set(Value::I64(i as i64), Value::U8(byte));
            }
        }
        Ok(Value::Array(arr_id))
    });

    // Avss.get_key_name - Get the key name from AVSS share
    vm.register_foreign_function("Avss.get_key_name", |ctx| {
        if ctx.args.is_empty() {
            return Err("Avss.get_key_name expects 1 argument: avss_share".to_string());
        }

        if !avss_object::is_avss_share_object(&ctx.vm_state.object_store, &ctx.args[0]) {
            return Err("Argument must be an AVSS share object".to_string());
        }

        let key_name = avss_object::get_key_name(&ctx.vm_state.object_store, &ctx.args[0])?;
        Ok(Value::String(key_name))
    });

    // Avss.commitment_count - Get the number of commitments in an AVSS share
    vm.register_foreign_function("Avss.commitment_count", |ctx| {
        if ctx.args.is_empty() {
            return Err("Avss.commitment_count expects 1 argument: avss_share".to_string());
        }

        if !avss_object::is_avss_share_object(&ctx.vm_state.object_store, &ctx.args[0]) {
            return Err("Argument must be an AVSS share object".to_string());
        }

        let count = avss_object::get_commitment_count(&ctx.vm_state.object_store, &ctx.args[0])?;
        Ok(Value::I64(count as i64))
    });

    // Avss.is_avss_share - Check if value is an AVSS share object
    vm.register_foreign_function("Avss.is_avss_share", |ctx| {
        if ctx.args.is_empty() {
            return Err("Avss.is_avss_share expects 1 argument: value".to_string());
        }

        let is_avss = avss_object::is_avss_share_object(&ctx.vm_state.object_store, &ctx.args[0]);
        Ok(Value::Bool(is_avss))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core_vm::VirtualMachine;
    use crate::net::curve::MpcFieldKind;
    use crate::net::mpc_engine::MpcEngine;
    use std::collections::HashMap;
    use std::sync::Arc;
    use stoffel_vm_types::core_types::ShareData;
    use stoffel_vm_types::functions::VMFunction;
    use stoffel_vm_types::instructions::Instruction;

    struct NoOpenExpEngine;

    impl MpcEngine for NoOpenExpEngine {
        fn protocol_name(&self) -> &'static str {
            "no-open-exp"
        }
        fn instance_id(&self) -> u64 {
            0
        }
        fn is_ready(&self) -> bool {
            true
        }
        fn start(&self) -> Result<(), String> {
            Ok(())
        }
        fn input_share(&self, _ty: ShareType, _clear: &Value) -> Result<ShareData, String> {
            Err("not implemented".to_string())
        }
        fn multiply_share(
            &self,
            _ty: ShareType,
            _left: &[u8],
            _right: &[u8],
        ) -> Result<ShareData, String> {
            Err("not implemented".to_string())
        }
        fn open_share(&self, _ty: ShareType, _share_bytes: &[u8]) -> Result<Value, String> {
            Err("not implemented".to_string())
        }
        fn shutdown(&self) {}
        fn party_id(&self) -> usize {
            0
        }
        fn n_parties(&self) -> usize {
            3
        }
        fn threshold(&self) -> usize {
            1
        }
        fn field_kind(&self) -> MpcFieldKind {
            MpcFieldKind::Bls12_381Fr
        }
    }

    #[test]
    fn test_share_object_creation() {
        use stoffel_vm_types::core_types::ObjectStore;

        let mut store = ObjectStore::new();
        let share_type = ShareType::default_secret_int();
        let data = vec![1, 2, 3, 4];
        let party_id = 0;

        let id = share_object::create_share_object(&mut store, share_type, ShareData::Opaque(data.clone()), party_id);

        // Verify we can extract the share data
        let result = share_object::extract_share_data(&store, &Value::Object(id));
        assert!(result.is_ok());
        let (ty, extracted_data) = result.unwrap();
        assert_eq!(ty, share_type);
        assert_eq!(extracted_data, ShareData::Opaque(data));
    }

    #[test]
    fn test_is_share_object() {
        use stoffel_vm_types::core_types::ObjectStore;

        let mut store = ObjectStore::new();
        let share_type = ShareType::default_secret_int();
        let data = vec![1, 2, 3, 4];

        let share_id = share_object::create_share_object(&mut store, share_type, ShareData::Opaque(data), 0);
        let non_share_id = store.create_object();

        assert!(share_object::is_share_object(
            &store,
            &Value::Object(share_id)
        ));
        assert!(!share_object::is_share_object(
            &store,
            &Value::Object(non_share_id)
        ));
        assert!(share_object::is_share_object(
            &store,
            &Value::Share(share_type, ShareData::Opaque(vec![]))
        ));
        assert!(!share_object::is_share_object(&store, &Value::I64(42)));
    }

    #[test]
    fn share_open_exp_rejects_engine_without_support() {
        let mut vm = VirtualMachine::new();
        register_mpc_builtins(&mut vm);
        vm.state.set_mpc_engine(Arc::new(NoOpenExpEngine));

        let share_id = share_object::create_share_object(
            &mut vm.state.object_store,
            ShareType::secret_int(64),
            ShareData::Opaque(vec![1, 2, 3, 4]),
            0,
        );

        let fn_call = VMFunction::new(
            "test_share_open_exp".to_string(),
            vec![],
            Vec::new(),
            None,
            4,
            vec![
                Instruction::LDI(0, Value::Object(share_id)),
                Instruction::LDI(1, Value::String("bls12-381-g1".to_string())),
                Instruction::PUSHARG(0),
                Instruction::PUSHARG(1),
                Instruction::CALL("Share.open_exp".to_string()),
                Instruction::RET(0),
            ],
            HashMap::new(),
        );
        vm.register_function(fn_call);

        let err = vm
            .execute("test_share_open_exp")
            .expect_err("Share.open_exp should fail for engines without exponent-open support");

        assert!(
            err.contains("does not support Share.open_exp"),
            "expected capability error, got: {}",
            err
        );
    }
}
