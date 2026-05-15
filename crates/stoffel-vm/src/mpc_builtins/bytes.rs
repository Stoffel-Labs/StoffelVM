use crate::core_vm::VirtualMachine;
use crate::VirtualMachineResult;

pub(crate) fn register(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    vm.try_register_typed_foreign_function("Bytes.concat", |mut ctx| {
        let (left, right) = {
            let args = ctx.named_args("Bytes.concat");
            args.require_min(2, "2 arguments: a, b")?;
            (args.cloned(0)?, args.cloned(1)?)
        };

        let a = ctx.read_byte_array(&left)?;
        let b = ctx.read_byte_array(&right)?;

        let mut combined = Vec::with_capacity(a.len() + b.len());
        combined.extend_from_slice(&a);
        combined.extend_from_slice(&b);

        ctx.create_byte_array(&combined)
    })?;

    vm.try_register_typed_foreign_function("Bytes.from_string", |mut ctx| {
        let bytes = {
            let args = ctx.named_args("Bytes.from_string");
            args.require_exact(1, "1 argument: string")?;
            args.string(0, "Argument")?.as_bytes().to_vec()
        };

        ctx.create_byte_array(&bytes)
    })?;

    Ok(())
}
