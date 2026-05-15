use crate::core_vm::VirtualMachine;
use crate::VirtualMachineResult;
use sha2::{Digest, Sha256, Sha512};
use stoffel_vm_types::core_types::Value;

pub(crate) fn register(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    register_hash_builtins(vm)?;
    register_curve_builtins(vm)?;
    Ok(())
}

fn register_hash_builtins(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    vm.try_register_typed_foreign_function("Crypto.sha256", |mut ctx| {
        let hash = {
            let data = {
                let args = ctx.named_args("Crypto.sha256");
                args.require_exact(1, "1 argument: data (byte array)")?;
                args.cloned(0)?
            };

            let bytes = ctx.read_byte_array(&data)?;
            Sha256::digest(&bytes)
        };

        ctx.create_byte_array(&hash)
    })?;

    vm.try_register_typed_foreign_function("Crypto.sha512", |mut ctx| {
        let hash = {
            let data = {
                let args = ctx.named_args("Crypto.sha512");
                args.require_exact(1, "1 argument: data (byte array)")?;
                args.cloned(0)?
            };

            let bytes = ctx.read_byte_array(&data)?;
            Sha512::digest(&bytes)
        };

        ctx.create_byte_array(&hash)
    })?;

    Ok(())
}

fn register_curve_builtins(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    vm.try_register_typed_foreign_function("Crypto.hash_to_field", |mut ctx| {
        let (hash_bytes, curve_name) = {
            let (hash_value, curve_value) = {
                let args = ctx.named_args("Crypto.hash_to_field");
                args.require_min(2, "2 arguments: hash_bytes, curve_name")?;
                (args.cloned(0)?, args.cloned(1)?)
            };

            let hash_bytes = ctx.read_byte_array(&hash_value)?;

            let curve_name = match curve_value {
                Value::String(s) => s,
                _ => return Err("curve_name must be a string".into()),
            };

            (hash_bytes, curve_name)
        };

        use crate::net::curve::MpcCurveConfig;
        use ark_ff::PrimeField;

        let curve = curve_name
            .parse::<MpcCurveConfig>()
            .map_err(|e| format!("Invalid curve name: {}", e))?;

        let out_bytes = match curve {
            MpcCurveConfig::Bls12_381 => {
                let field_elem = ark_bls12_381::Fr::from_be_bytes_mod_order(&hash_bytes);
                serialize_field_element(field_elem)?
            }
            MpcCurveConfig::Bn254 => {
                let field_elem = ark_bn254::Fr::from_be_bytes_mod_order(&hash_bytes);
                serialize_field_element(field_elem)?
            }
            MpcCurveConfig::Curve25519 | MpcCurveConfig::Ed25519 => {
                let field_elem = ark_curve25519::Fr::from_le_bytes_mod_order(&hash_bytes);
                serialize_field_element(field_elem)?
            }
        };

        ctx.create_byte_array(&out_bytes)
    })?;

    vm.try_register_typed_foreign_function("Crypto.hash_to_g1", |mut ctx| {
        let out = {
            let data = {
                let args = ctx.named_args("Crypto.hash_to_g1");
                args.require_exact(1, "1 argument: data (byte array)")?;
                args.cloned(0)?
            };

            let bytes = ctx.read_byte_array(&data)?;
            let point = hash_to_bls12381_g1(&bytes)?;

            use ark_serialize::CanonicalSerialize;
            let mut out = Vec::new();
            point
                .serialize_compressed(&mut out)
                .map_err(|e| format!("serialize G1 point: {}", e))?;
            out
        };

        ctx.create_byte_array(&out)
    })?;

    Ok(())
}

fn serialize_field_element<F>(field_elem: F) -> Result<Vec<u8>, String>
where
    F: ark_serialize::CanonicalSerialize,
{
    let mut out = Vec::new();
    field_elem
        .serialize_compressed(&mut out)
        .map_err(|e| format!("serialize field element: {}", e))?;
    Ok(out)
}

fn hash_to_bls12381_g1(bytes: &[u8]) -> Result<ark_bls12_381::G1Affine, String> {
    use ark_bls12_381::{Fq, G1Affine};
    use ark_ec::AffineRepr;
    use ark_ff::PrimeField;

    for counter in 0u32..256 {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hasher.update(counter.to_le_bytes());
        let hash = hasher.finalize();
        let x = Fq::from_be_bytes_mod_order(&hash);

        if let Some(point) = G1Affine::get_point_from_x_unchecked(x, false) {
            if point.is_on_curve() && !point.is_zero() {
                let cleared = point.clear_cofactor();
                if !cleared.is_zero() {
                    return Ok(cleared);
                }
            }
        }
    }

    Err("hash_to_g1: failed to find valid point after 256 attempts".to_string())
}
