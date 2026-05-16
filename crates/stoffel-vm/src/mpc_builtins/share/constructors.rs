use super::result::create_result_share_object;
use crate::core_vm::VirtualMachine;
use crate::foreign_functions::{
    ForeignFunctionCallbackResult, ForeignFunctionContext, MpcOnlineBuiltin,
};
use crate::mpc_values::clear_share_input;
use crate::VirtualMachineResult;
use stoffel_vm_types::core_types::{ShareType, Value};

pub(super) fn register(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    vm.try_register_mpc_online_foreign_function(MpcOnlineBuiltin::FromClear, |ctx| {
        share_from_clear(ctx, None)
    })?;

    vm.try_register_mpc_online_foreign_function(MpcOnlineBuiltin::FromClearInt, |ctx| {
        let bit_length = {
            let args = ctx.named_args("Share.from_clear_int");
            args.require_min(2, "2 arguments: value, bit_length")?;
            args.usize(1, "bit_length")?
        };
        share_from_clear(ctx, Some(ShareType::try_secret_int(bit_length)?))
    })?;

    vm.try_register_mpc_online_foreign_function(MpcOnlineBuiltin::FromClearFixed, |ctx| {
        let (k, f) = {
            let args = ctx.named_args("Share.from_clear_fixed");
            args.require_min(3, "3 arguments: value, total_bits, frac_bits")?;
            (args.usize(1, "total_bits")?, args.usize(2, "frac_bits")?)
        };
        share_from_clear(
            ctx,
            Some(ShareType::try_secret_fixed_point_from_bits(k, f)?),
        )
    })?;

    Ok(())
}

fn share_from_clear(
    mut ctx: ForeignFunctionContext,
    explicit_type: Option<ShareType>,
) -> ForeignFunctionCallbackResult<Value> {
    let clear_value = {
        let args = ctx.named_args("Share.from_clear");
        args.require_min(1, "at least 1 argument: value")?;
        args.cloned(0)?
    };

    let input = clear_share_input(&clear_value, explicit_type)?;
    let share_type = input.share_type();
    let share_bytes = ctx.input_share_data(input)?;

    create_result_share_object(&mut ctx, share_type, share_bytes)
}
