use super::{
    execution::{ExecutionContext, InstructionEffect, InstructionOutcome},
    CallStackCheckpoint, VMState,
};
use crate::error::{VmError, VmResult};
use crate::runtime_hooks::HookEvent;
use crate::runtime_instruction::{
    FetchedInstruction, JumpTarget, RuntimeInstructionTable, RuntimeJumpCondition, RuntimeOpcode,
    RuntimeRegister, StackOffset,
};
use crate::runtime_value_ops;
use stoffel_vm_types::activations::{ActivationRecord, CompareFlag, InstructionPointer};
use stoffel_vm_types::core_types::Value;
use stoffel_vm_types::instructions::Instruction;
use stoffel_vm_types::registers::{
    ClearRegisterCompareResult, ClearRegisterCopyResult, ClearRegisterOperationResult,
    FastClearBinaryOp, RegisterMoveKind, SecretRegisterCopyResult,
};

#[cfg(test)]
use super::mpc_operation::PendingMpcOperation;
#[cfg(test)]
use crate::runtime_instruction::{
    RuntimeBinaryOp, RuntimeImmediate, RuntimeInstruction, RuntimeShiftOp, RuntimeUnaryOp,
};

#[cfg(test)]
pub(super) trait InstructionRuntime {
    fn plan_async_mpc_operation(
        &mut self,
        instruction: &RuntimeInstruction,
        hooks_enabled: bool,
    ) -> VmResult<Option<PendingMpcOperation>>;
    fn execute_ld(
        &mut self,
        dest: RuntimeRegister,
        offset: StackOffset,
        hooks_enabled: bool,
    ) -> VmResult<()>;
    fn execute_ldi(
        &mut self,
        dest: RuntimeRegister,
        value: Value,
        hooks_enabled: bool,
    ) -> VmResult<()>;
    fn execute_mov(
        &mut self,
        dest: RuntimeRegister,
        src: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()>;
    fn execute_binary(
        &mut self,
        op: RuntimeBinaryOp,
        dest: RuntimeRegister,
        lhs: RuntimeRegister,
        rhs: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()>;
    fn execute_unary(
        &mut self,
        op: RuntimeUnaryOp,
        dest: RuntimeRegister,
        src: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()>;
    fn execute_shift(
        &mut self,
        op: RuntimeShiftOp,
        dest: RuntimeRegister,
        src: RuntimeRegister,
        amount: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()>;
    fn execute_jump(&mut self, condition: RuntimeJumpCondition, target: JumpTarget)
        -> VmResult<()>;
    fn execute_call(
        &mut self,
        function_name: &str,
        hooks_enabled: bool,
    ) -> VmResult<InstructionOutcome>;
    fn execute_ret(
        &mut self,
        src: RuntimeRegister,
        hook_instruction: &Instruction,
        hooks_enabled: bool,
        checkpoint: CallStackCheckpoint,
    ) -> VmResult<InstructionOutcome>;
    fn execute_pusharg(&mut self, reg: RuntimeRegister, hooks_enabled: bool) -> VmResult<()>;
    fn execute_cmp(&mut self, lhs: RuntimeRegister, rhs: RuntimeRegister) -> VmResult<()>;
    fn execute_lds(
        &mut self,
        dest: RuntimeRegister,
        slot: usize,
        hooks_enabled: bool,
    ) -> VmResult<()>;
    fn execute_sts(
        &mut self,
        slot: usize,
        src: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()>;
}

#[cfg(test)]
pub(super) struct InstructionExecutor<'state, 'instruction, R: InstructionRuntime + ?Sized> {
    state: &'state mut R,
    instruction: &'instruction RuntimeInstruction,
    hook_instruction: &'instruction Instruction,
    context: ExecutionContext,
}

#[cfg(test)]
impl<'state, 'instruction, R: InstructionRuntime + ?Sized>
    InstructionExecutor<'state, 'instruction, R>
{
    pub(super) fn new(
        state: &'state mut R,
        instruction: &'instruction RuntimeInstruction,
        hook_instruction: &'instruction Instruction,
        context: ExecutionContext,
    ) -> Self {
        Self {
            state,
            instruction,
            hook_instruction,
            context,
        }
    }

    pub(super) fn execute_effect(self) -> VmResult<InstructionEffect> {
        if let Some(operation) = self
            .state
            .plan_async_mpc_operation(self.instruction, self.context.hooks_enabled())?
        {
            return Ok(InstructionEffect::PendingMpc(operation));
        }

        self.execute_local().map(InstructionEffect::Completed)
    }

    pub(super) fn execute_local(self) -> VmResult<InstructionOutcome> {
        let hooks_enabled = self.context.hooks_enabled();

        match self.instruction {
            RuntimeInstruction::Noop => {}
            RuntimeInstruction::LoadStack { dest, offset } => {
                self.state.execute_ld(*dest, *offset, hooks_enabled)?;
            }
            RuntimeInstruction::LoadImmediate { dest, value } => {
                self.state
                    .execute_ldi(*dest, value.direct_value()?.clone(), hooks_enabled)?;
            }
            RuntimeInstruction::Move { dest, src } => {
                self.state.execute_mov(*dest, *src, hooks_enabled)?;
            }
            RuntimeInstruction::Binary { op, dest, lhs, rhs } => {
                self.state
                    .execute_binary(*op, *dest, *lhs, *rhs, hooks_enabled)?;
            }
            RuntimeInstruction::Unary { op, dest, src } => {
                self.state.execute_unary(*op, *dest, *src, hooks_enabled)?;
            }
            RuntimeInstruction::Shift {
                op,
                dest,
                src,
                amount,
            } => {
                self.state
                    .execute_shift(*op, *dest, *src, *amount, hooks_enabled)?;
            }
            RuntimeInstruction::Jump { condition, target } => {
                self.state.execute_jump(*condition, *target)?;
            }
            RuntimeInstruction::Call { function } => {
                return self
                    .state
                    .execute_call(function.direct_function_name()?, hooks_enabled);
            }
            RuntimeInstruction::Return { src } => {
                return self.state.execute_ret(
                    *src,
                    self.hook_instruction,
                    hooks_enabled,
                    self.context.checkpoint(),
                );
            }
            RuntimeInstruction::PushArg { src } => {
                self.state.execute_pusharg(*src, hooks_enabled)?;
            }
            RuntimeInstruction::Compare { lhs, rhs } => {
                self.state.execute_cmp(*lhs, *rhs)?;
            }
            RuntimeInstruction::SpillLoad { dest, slot } => {
                self.state.execute_lds(*dest, *slot, hooks_enabled)?;
            }
            RuntimeInstruction::SpillStore { slot, src } => {
                self.state.execute_sts(*slot, *src, hooks_enabled)?;
            }
        }

        Ok(InstructionOutcome::Continue)
    }
}

#[cfg(test)]
impl InstructionRuntime for VMState {
    fn plan_async_mpc_operation(
        &mut self,
        instruction: &RuntimeInstruction,
        hooks_enabled: bool,
    ) -> VmResult<Option<PendingMpcOperation>> {
        VMState::plan_async_mpc_operation(self, instruction, hooks_enabled)
    }

    fn execute_ld(
        &mut self,
        dest: RuntimeRegister,
        offset: StackOffset,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        VMState::execute_ld(self, dest, offset, hooks_enabled)
    }

    fn execute_ldi(
        &mut self,
        dest: RuntimeRegister,
        value: Value,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        VMState::execute_ldi(self, dest, value, hooks_enabled)
    }

    fn execute_mov(
        &mut self,
        dest: RuntimeRegister,
        src: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        VMState::execute_mov(self, dest, src, hooks_enabled)
    }

    fn execute_binary(
        &mut self,
        op: RuntimeBinaryOp,
        dest: RuntimeRegister,
        lhs: RuntimeRegister,
        rhs: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        VMState::execute_binary_op(self, op, dest, lhs, rhs, hooks_enabled)
    }

    fn execute_unary(
        &mut self,
        op: RuntimeUnaryOp,
        dest: RuntimeRegister,
        src: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        VMState::execute_unary_op(self, op, dest, src, hooks_enabled)
    }

    fn execute_shift(
        &mut self,
        op: RuntimeShiftOp,
        dest: RuntimeRegister,
        src: RuntimeRegister,
        amount: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        VMState::execute_shift_op(self, op, dest, src, amount, hooks_enabled)
    }

    fn execute_jump(
        &mut self,
        condition: RuntimeJumpCondition,
        target: JumpTarget,
    ) -> VmResult<()> {
        VMState::execute_jump(self, condition, target)
    }

    fn execute_call(
        &mut self,
        function_name: &str,
        hooks_enabled: bool,
    ) -> VmResult<InstructionOutcome> {
        VMState::execute_call(self, function_name, hooks_enabled)
    }

    fn execute_ret(
        &mut self,
        src: RuntimeRegister,
        hook_instruction: &Instruction,
        hooks_enabled: bool,
        checkpoint: CallStackCheckpoint,
    ) -> VmResult<InstructionOutcome> {
        VMState::execute_ret(self, src, hook_instruction, hooks_enabled, checkpoint)
    }

    fn execute_pusharg(&mut self, reg: RuntimeRegister, hooks_enabled: bool) -> VmResult<()> {
        VMState::execute_pusharg(self, reg, hooks_enabled)
    }

    fn execute_cmp(&mut self, lhs: RuntimeRegister, rhs: RuntimeRegister) -> VmResult<()> {
        VMState::execute_cmp(self, lhs, rhs)
    }

    fn execute_lds(
        &mut self,
        dest: RuntimeRegister,
        slot: usize,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        VMState::execute_lds(self, dest, slot, hooks_enabled)
    }

    fn execute_sts(
        &mut self,
        slot: usize,
        src: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        VMState::execute_sts(self, slot, src, hooks_enabled)
    }
}

impl VMState {
    #[inline(never)]
    pub(super) fn execute_clear_instruction_run_on_frame_without_hooks<
        'function,
        const BUDGETED: bool,
    >(
        frame: &mut ActivationRecord,
        first: FetchedInstruction<'function>,
        instruction_table: RuntimeInstructionTable<'function>,
        mut instruction_pointer: InstructionPointer,
        clear_fast_paths_enabled: bool,
        max_instructions: usize,
    ) -> (usize, InstructionPointer) {
        let mut fetched = first;
        let mut executed = 0;
        let first_next_instruction_pointer = instruction_pointer;
        // The caller has already advanced past `first`. Start at its index so
        // every successful instruction can use the same branch-free cursor
        // update. A fetched index cannot be usize::MAX: it indexes a live
        // allocation and the instruction table has an additional sentinel.
        instruction_pointer = InstructionPointer::new(instruction_pointer.index().wrapping_sub(1));

        loop {
            let opcode = fetched.opcode();
            let handled = match opcode {
                RuntimeOpcode::Noop => true,
                opcode @ (RuntimeOpcode::Jump
                | RuntimeOpcode::JumpEqual
                | RuntimeOpcode::JumpNotEqual
                | RuntimeOpcode::JumpLess
                | RuntimeOpcode::JumpGreater) => {
                    let condition = match opcode {
                        RuntimeOpcode::Jump => RuntimeJumpCondition::Always,
                        RuntimeOpcode::JumpEqual => RuntimeJumpCondition::Equal,
                        RuntimeOpcode::JumpNotEqual => RuntimeJumpCondition::NotEqual,
                        RuntimeOpcode::JumpLess => RuntimeJumpCondition::Less,
                        RuntimeOpcode::JumpGreater => RuntimeJumpCondition::Greater,
                        _ => unreachable!("matched jump runtime opcode"),
                    };
                    if condition.should_jump(frame.compare_flag()) {
                        // The common success update below advances this to the
                        // exact target, preserving one cursor path for every
                        // opcode in the run.
                        instruction_pointer = InstructionPointer::new(
                            fetched.jump_target_a().index().wrapping_sub(1),
                        );
                    }
                    true
                }
                _ if !clear_fast_paths_enabled => false,
                RuntimeOpcode::Add => frame.try_add_clear_primitive(
                    fetched.register_a().register_index(),
                    fetched.register_b().register_index(),
                    fetched.register_c().register_index(),
                ),
                RuntimeOpcode::LoadStack => {
                    fetched
                        .stack_offset_b()
                        .resolve_index(frame.stack_len())
                        .ok()
                        .and_then(|stack_index| {
                            frame.copy_stack_value_to_clear_register(
                                fetched.register_a().register_index(),
                                stack_index,
                            )
                        })
                        == Some(ClearRegisterCopyResult::Copied)
                }
                RuntimeOpcode::LoadImmediate => {
                    frame.write_clear_register_value_from_ref(
                        fetched.register_a().register_index(),
                        fetched.validated_load_immediate_value(),
                    ) == ClearRegisterCopyResult::Copied
                }
                RuntimeOpcode::Move => {
                    frame.copy_clear_register_value(
                        fetched.register_a().register_index(),
                        fetched.register_b().register_index(),
                    ) == ClearRegisterCopyResult::Copied
                }
                RuntimeOpcode::BitNot => frame.try_bit_not_clear_primitive(
                    fetched.register_a().register_index(),
                    fetched.register_b().register_index(),
                ),
                RuntimeOpcode::PushArg => {
                    frame.push_clear_register_value(fetched.register_a().register_index())
                        == ClearRegisterCopyResult::Copied
                }
                RuntimeOpcode::SpillLoad => frame.spill_load_into_register(
                    fetched.register_a().register_index(),
                    fetched.operand_b_usize(),
                ),
                RuntimeOpcode::SpillStore => {
                    frame.spill_store_clear_register(
                        fetched.operand_a_usize(),
                        fetched.register_b().register_index(),
                    ) == ClearRegisterCopyResult::Copied
                }
                RuntimeOpcode::Subtract
                | RuntimeOpcode::Multiply
                | RuntimeOpcode::Divide
                | RuntimeOpcode::Modulo
                | RuntimeOpcode::BitAnd
                | RuntimeOpcode::BitOr
                | RuntimeOpcode::BitXor
                | RuntimeOpcode::ShiftLeft
                | RuntimeOpcode::ShiftRight => {
                    macro_rules! apply {
                        ($op:ident) => {{
                            const OP: u8 = FastClearBinaryOp::$op as u8;
                            let dest = fetched.register_a().register_index();
                            let lhs = fetched.register_b().register_index();
                            let rhs = fetched.register_c().register_index();
                            frame.try_apply_clear_binary_primitive::<OP>(dest, lhs, rhs)
                        }};
                    }
                    match opcode {
                        RuntimeOpcode::Subtract => apply!(Subtract),
                        RuntimeOpcode::Multiply => apply!(Multiply),
                        RuntimeOpcode::Divide => apply!(Divide),
                        RuntimeOpcode::Modulo => apply!(Modulo),
                        RuntimeOpcode::BitAnd => apply!(BitAnd),
                        RuntimeOpcode::BitOr => apply!(BitOr),
                        RuntimeOpcode::BitXor => apply!(BitXor),
                        RuntimeOpcode::ShiftLeft => apply!(ShiftLeft),
                        RuntimeOpcode::ShiftRight => apply!(ShiftRight),
                        _ => unreachable!("matched clear binary runtime opcode"),
                    }
                }
                RuntimeOpcode::Compare => {
                    if let Some(ordering) = frame.try_compare_clear_primitive(
                        fetched.register_a().register_index(),
                        fetched.register_b().register_index(),
                    ) {
                        frame.set_compare_flag(CompareFlag::from_ordering(ordering));
                        true
                    } else {
                        false
                    }
                }
                _ => false,
            };

            if !handled {
                return (
                    executed,
                    if executed == 0 {
                        first_next_instruction_pointer
                    } else {
                        instruction_pointer
                    },
                );
            }

            instruction_pointer =
                InstructionPointer::new(instruction_pointer.index().wrapping_add(1));
            if BUDGETED {
                executed += 1;
                if executed >= max_instructions {
                    return (executed, instruction_pointer);
                }
            } else {
                // The unbounded executor needs only the zero/non-zero result;
                // keeping this boolean-shaped value lets LLVM remove the
                // cooperative counter and limit branch from its hot loop.
                executed = 1;
            }

            // Leave the cursor unchanged until this look-ahead instruction has
            // completed. If it is unsupported (or DIV/MOD fails), the caller
            // fetches and executes that same instruction through the generic
            // path without rewinding anything.
            // SAFETY: the table has an appended return sentinel and the cursor
            // is advanced only after a successfully executed instruction.
            fetched = unsafe { instruction_table.get_instruction_unchecked(instruction_pointer) };
        }
    }

    pub(super) fn execute_effect_fetched_instruction_without_hooks(
        &mut self,
        fetched: FetchedInstruction<'_>,
        checkpoint: CallStackCheckpoint,
    ) -> VmResult<InstructionEffect> {
        if fetched.may_yield_mpc_effect() {
            if let Some(operation) = self.plan_async_mpc_operation_for_fetched(fetched, false)? {
                return Ok(InstructionEffect::PendingMpc(operation));
            }
        }

        self.execute_local_fetched_instruction_without_hooks(fetched, checkpoint)
            .map(InstructionEffect::Completed)
    }

    pub(super) fn execute_effect_instruction(
        &mut self,
        fetched: FetchedInstruction<'_>,
        hook_instruction: &Instruction,
        context: ExecutionContext,
    ) -> VmResult<InstructionEffect> {
        if !context.hooks_enabled() {
            return self
                .execute_effect_fetched_instruction_without_hooks(fetched, context.checkpoint());
        }

        if fetched.may_yield_mpc_effect() {
            if let Some(operation) =
                self.plan_async_mpc_operation_for_fetched(fetched, context.hooks_enabled())?
            {
                return Ok(InstructionEffect::PendingMpc(operation));
            }
        }

        self.execute_local_instruction(fetched, hook_instruction, context)
            .map(InstructionEffect::Completed)
    }

    pub(super) fn execute_local_fetched_instruction_without_hooks(
        &mut self,
        fetched: FetchedInstruction<'_>,
        checkpoint: CallStackCheckpoint,
    ) -> VmResult<InstructionOutcome> {
        self.execute_local_fetched_instruction_with_hook_mode::<false>(fetched, None, checkpoint)
    }

    pub(super) fn execute_local_instruction(
        &mut self,
        fetched: FetchedInstruction<'_>,
        hook_instruction: &Instruction,
        context: ExecutionContext,
    ) -> VmResult<InstructionOutcome> {
        if !context.hooks_enabled() {
            return self
                .execute_local_fetched_instruction_without_hooks(fetched, context.checkpoint());
        }

        self.execute_local_fetched_instruction_with_hook_mode::<true>(
            fetched,
            Some(hook_instruction),
            context.checkpoint(),
        )
    }

    #[inline]
    fn execute_local_fetched_instruction_with_hook_mode<const HOOKS_ENABLED: bool>(
        &mut self,
        fetched: FetchedInstruction<'_>,
        hook_instruction: Option<&Instruction>,
        checkpoint: CallStackCheckpoint,
    ) -> VmResult<InstructionOutcome> {
        // Dispatch the packed representation directly. Runtime instructions are
        // already validated while the function is lowered, so constructing a
        // second enum and eagerly decoding all three operands on every fetch is
        // pure interpreter overhead.
        match fetched.opcode() {
            RuntimeOpcode::Noop => {}
            RuntimeOpcode::LoadStack => {
                self.execute_ld(
                    fetched.register_a(),
                    fetched.stack_offset_b(),
                    HOOKS_ENABLED,
                )?;
            }
            RuntimeOpcode::LoadImmediate => {
                self.execute_ldi(
                    fetched.register_a(),
                    fetched.direct_load_immediate_value()?.clone(),
                    HOOKS_ENABLED,
                )?;
            }
            RuntimeOpcode::Move => {
                self.execute_mov(fetched.register_a(), fetched.register_b(), HOOKS_ENABLED)?;
            }
            RuntimeOpcode::Add => {
                self.execute_add(
                    fetched.register_a(),
                    fetched.register_b(),
                    fetched.register_c(),
                    HOOKS_ENABLED,
                )?;
            }
            opcode @ (RuntimeOpcode::Subtract
            | RuntimeOpcode::Multiply
            | RuntimeOpcode::Divide
            | RuntimeOpcode::Modulo
            | RuntimeOpcode::BitAnd
            | RuntimeOpcode::BitOr
            | RuntimeOpcode::BitXor) => {
                self.execute_other_clear_binary::<HOOKS_ENABLED>(fetched, opcode)?;
            }
            RuntimeOpcode::BitNot => {
                self.execute_not(fetched.register_a(), fetched.register_b(), HOOKS_ENABLED)?;
            }
            opcode @ (RuntimeOpcode::ShiftLeft | RuntimeOpcode::ShiftRight) => {
                let dest = fetched.register_a();
                let src = fetched.register_b();
                let amount = fetched.register_c();
                match opcode {
                    RuntimeOpcode::ShiftLeft => {
                        self.execute_shl(dest, src, amount, HOOKS_ENABLED)?
                    }
                    RuntimeOpcode::ShiftRight => {
                        self.execute_shr(dest, src, amount, HOOKS_ENABLED)?
                    }
                    _ => unreachable!("matched shift runtime opcode"),
                }
            }
            opcode @ (RuntimeOpcode::Jump
            | RuntimeOpcode::JumpEqual
            | RuntimeOpcode::JumpNotEqual
            | RuntimeOpcode::JumpLess
            | RuntimeOpcode::JumpGreater) => {
                let condition = match opcode {
                    RuntimeOpcode::Jump => RuntimeJumpCondition::Always,
                    RuntimeOpcode::JumpEqual => RuntimeJumpCondition::Equal,
                    RuntimeOpcode::JumpNotEqual => RuntimeJumpCondition::NotEqual,
                    RuntimeOpcode::JumpLess => RuntimeJumpCondition::Less,
                    RuntimeOpcode::JumpGreater => RuntimeJumpCondition::Greater,
                    _ => unreachable!("matched jump runtime opcode"),
                };
                self.execute_jump(condition, fetched.jump_target_a())?;
            }
            RuntimeOpcode::Call => {
                return self.execute_call(fetched.direct_call_target_name()?, HOOKS_ENABLED);
            }
            RuntimeOpcode::Return => {
                let src = fetched.register_a();
                if HOOKS_ENABLED {
                    let instruction =
                        hook_instruction.expect("hook instruction is required when hooks run");
                    return self.execute_ret(src, instruction, true, checkpoint);
                }

                let return_value = self.resolve_register(src)?.into_value();
                return self.return_current_frame(return_value, None, false, checkpoint);
            }
            RuntimeOpcode::PushArg => {
                self.execute_pusharg(fetched.register_a(), HOOKS_ENABLED)?;
            }
            RuntimeOpcode::Compare => {
                self.execute_cmp(fetched.register_a(), fetched.register_b())?;
            }
            RuntimeOpcode::SpillLoad => {
                self.execute_lds(
                    fetched.register_a(),
                    fetched.operand_b_usize(),
                    HOOKS_ENABLED,
                )?;
            }
            RuntimeOpcode::SpillStore => {
                self.execute_sts(
                    fetched.operand_a_usize(),
                    fetched.register_b(),
                    HOOKS_ENABLED,
                )?;
            }
        }

        Ok(InstructionOutcome::Continue)
    }

    #[inline(never)]
    fn execute_other_clear_binary<const HOOKS_ENABLED: bool>(
        &mut self,
        fetched: FetchedInstruction<'_>,
        opcode: RuntimeOpcode,
    ) -> VmResult<()> {
        let dest = fetched.register_a();
        let lhs = fetched.register_b();
        let rhs = fetched.register_c();
        match opcode {
            RuntimeOpcode::Subtract => self.execute_sub(dest, lhs, rhs, HOOKS_ENABLED),
            RuntimeOpcode::Multiply => self.execute_mul(dest, lhs, rhs, HOOKS_ENABLED),
            RuntimeOpcode::Divide => self.execute_div(dest, lhs, rhs, HOOKS_ENABLED),
            RuntimeOpcode::Modulo => self.execute_mod(dest, lhs, rhs, HOOKS_ENABLED),
            RuntimeOpcode::BitAnd => self.execute_and(dest, lhs, rhs, HOOKS_ENABLED),
            RuntimeOpcode::BitOr => self.execute_or(dest, lhs, rhs, HOOKS_ENABLED),
            RuntimeOpcode::BitXor => self.execute_xor(dest, lhs, rhs, HOOKS_ENABLED),
            _ => unreachable!("matched binary runtime opcode"),
        }
    }

    #[cfg(test)]
    pub(super) fn execute_binary_op(
        &mut self,
        op: RuntimeBinaryOp,
        dest: RuntimeRegister,
        lhs: RuntimeRegister,
        rhs: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        match op {
            RuntimeBinaryOp::Add => self.execute_add(dest, lhs, rhs, hooks_enabled),
            RuntimeBinaryOp::Subtract => self.execute_sub(dest, lhs, rhs, hooks_enabled),
            RuntimeBinaryOp::Multiply => self.execute_mul(dest, lhs, rhs, hooks_enabled),
            RuntimeBinaryOp::Divide => self.execute_div(dest, lhs, rhs, hooks_enabled),
            RuntimeBinaryOp::Modulo => self.execute_mod(dest, lhs, rhs, hooks_enabled),
            RuntimeBinaryOp::BitAnd => self.execute_and(dest, lhs, rhs, hooks_enabled),
            RuntimeBinaryOp::BitOr => self.execute_or(dest, lhs, rhs, hooks_enabled),
            RuntimeBinaryOp::BitXor => self.execute_xor(dest, lhs, rhs, hooks_enabled),
        }
    }

    #[cfg(test)]
    pub(super) fn execute_unary_op(
        &mut self,
        op: RuntimeUnaryOp,
        dest: RuntimeRegister,
        src: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        match op {
            RuntimeUnaryOp::BitNot => self.execute_not(dest, src, hooks_enabled),
        }
    }

    #[cfg(test)]
    pub(super) fn execute_shift_op(
        &mut self,
        op: RuntimeShiftOp,
        dest: RuntimeRegister,
        src: RuntimeRegister,
        amount: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        match op {
            RuntimeShiftOp::Left => self.execute_shl(dest, src, amount, hooks_enabled),
            RuntimeShiftOp::Right => self.execute_shr(dest, src, amount, hooks_enabled),
        }
    }

    #[inline]
    pub(super) fn execute_ld(
        &mut self,
        dest: RuntimeRegister,
        offset: StackOffset,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        if !hooks_enabled && self.try_execute_fast_clear_ld(dest, offset)? {
            return Ok(());
        }

        let value = {
            let record = self.current_frame()?;
            let idx = offset.resolve_index(record.stack_len())?;
            record
                .stack_value(idx)
                .cloned()
                .ok_or(VmError::StackAddressOutOfBounds {
                    offset: offset.raw(),
                })?
        };

        self.write_current_register(dest, value, hooks_enabled)?;
        Ok(())
    }

    fn try_execute_fast_clear_ld(
        &mut self,
        dest: RuntimeRegister,
        offset: StackOffset,
    ) -> VmResult<bool> {
        if self.mpc_runtime.has_any_pending_reveals() {
            return Ok(false);
        }

        let dest_index = dest.register_index();
        let record = self.current_frame_mut()?;
        let idx = offset.resolve_index(record.stack_len())?;

        match record.copy_stack_value_to_clear_register(dest_index, idx) {
            Some(ClearRegisterCopyResult::Copied) => Ok(true),
            Some(ClearRegisterCopyResult::NotClearRegister) => Ok(false),
            Some(ClearRegisterCopyResult::SourcePendingReveal) => {
                unreachable!("stack values cannot be pending register reveals")
            }
            Some(ClearRegisterCopyResult::RegisterOutOfBounds) => Err(
                Self::register_out_of_bounds(dest.index(), record.register_count()),
            ),
            None => Err(VmError::StackAddressOutOfBounds {
                offset: offset.raw(),
            }),
        }
    }

    #[inline]
    pub(super) fn execute_ldi(
        &mut self,
        dest: RuntimeRegister,
        value: Value,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        self.write_current_register(dest, value, hooks_enabled)?;
        Ok(())
    }

    /// LDS: load a register from a spill slot.
    ///
    /// This is a raw, value-preserving restore: it writes the saved value straight into
    /// the destination register slot without any clear<->secret conversion. The register
    /// allocator can place an array/object handle (a clear value) in a register whose VR
    /// is "secret"-typed because its *contents* are secret; routing the restore through the
    /// normal clear/secret write path would corrupt that handle. Spilling must round-trip
    /// the exact value, so we bypass conversion (mirroring STS below).
    pub(super) fn execute_lds(
        &mut self,
        dest: RuntimeRegister,
        slot: usize,
        _hooks_enabled: bool,
    ) -> VmResult<()> {
        let value = self.current_frame()?.spill_load(slot);
        let record = self.current_frame_mut()?;
        Self::ensure_frame_contains_register(record, dest)?;
        let count = record.register_count();
        *record
            .register_mut(dest.register_index())
            .ok_or_else(|| Self::register_out_of_bounds(dest.index(), count))? = value;
        Ok(())
    }

    /// STS: store a register into a spill slot (raw, value-preserving save).
    pub(super) fn execute_sts(
        &mut self,
        slot: usize,
        src: RuntimeRegister,
        _hooks_enabled: bool,
    ) -> VmResult<()> {
        let value = self.current_register_value(src)?.into_value();
        self.current_frame_mut()?.spill_store(slot, value);
        Ok(())
    }

    pub(super) fn execute_mov(
        &mut self,
        dest: RuntimeRegister,
        src: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        if !hooks_enabled
            && dest == src
            && self.register_layout.is_clear(dest.register_index())
            && !self.mpc_runtime.has_any_pending_reveals()
        {
            return Ok(());
        }

        if !hooks_enabled && self.try_execute_fast_clear_copy_mov(dest, src)? {
            return Ok(());
        }

        if !hooks_enabled
            && self.register_layout.is_secret(dest.register_index())
            && self.register_layout.is_secret(src.register_index())
            && self.try_execute_fast_secret_copy_mov(dest, src)?
        {
            return Ok(());
        }

        let move_kind = self
            .current_register_layout()?
            .move_kind(dest.register_index(), src.register_index());
        let src_value = self.resolve_register(src)?.into_value();

        if move_kind == RegisterMoveKind::SecretToClear && !hooks_enabled {
            self.queue_reveal_to_register(&src_value, dest)?;
            return Ok(());
        }

        let result_value = match move_kind {
            RegisterMoveKind::ClearToSecret => match src_value {
                Value::Share(_, _) => src_value,
                Value::Object(_) => {
                    let (share_type, share_data) = self.extract_share_data(&src_value)?;
                    Value::Share(share_type, share_data)
                }
                _ => self.convert_to_share(&src_value)?,
            },
            RegisterMoveKind::SecretToClear => self.reveal_share_immediate(&src_value)?,
            RegisterMoveKind::Copy => src_value,
        };

        self.write_mov_result(dest, src, result_value, hooks_enabled)
    }

    #[inline]
    fn try_execute_fast_clear_copy_mov(
        &mut self,
        dest: RuntimeRegister,
        src: RuntimeRegister,
    ) -> VmResult<bool> {
        if self.mpc_runtime.has_any_pending_reveals() {
            return Ok(false);
        }

        let dest_index = dest.register_index();
        let src_index = src.register_index();
        let record = self.current_frame_mut()?;
        match record.copy_clear_register_value(dest_index, src_index) {
            ClearRegisterCopyResult::Copied => Ok(true),
            ClearRegisterCopyResult::NotClearRegister => Ok(false),
            ClearRegisterCopyResult::SourcePendingReveal => {
                Err(VmError::PendingRevealWithoutQueuedBatch {
                    register: src.index(),
                })
            }
            ClearRegisterCopyResult::RegisterOutOfBounds => {
                let register_count = record.register_count();
                let register = if dest.index() >= register_count {
                    dest.index()
                } else {
                    src.index()
                };
                Err(Self::register_out_of_bounds(register, register_count))
            }
        }
    }

    #[inline]
    fn try_execute_fast_secret_copy_mov(
        &mut self,
        dest: RuntimeRegister,
        src: RuntimeRegister,
    ) -> VmResult<bool> {
        if self.mpc_runtime.has_any_pending_reveals() {
            return Ok(false);
        }

        let dest_index = dest.register_index();
        let src_index = src.register_index();
        let record = self.current_frame_mut()?;
        match record.copy_secret_register_value(dest_index, src_index) {
            SecretRegisterCopyResult::Copied => Ok(true),
            SecretRegisterCopyResult::NotSecretRegister
            | SecretRegisterCopyResult::SourceNotSecretValue => Ok(false),
            SecretRegisterCopyResult::SourcePendingReveal => {
                Err(VmError::PendingRevealWithoutQueuedBatch {
                    register: src.index(),
                })
            }
            SecretRegisterCopyResult::RegisterOutOfBounds => {
                let register_count = record.register_count();
                let register = if dest.index() >= register_count {
                    dest.index()
                } else {
                    src.index()
                };
                Err(Self::register_out_of_bounds(register, register_count))
            }
        }
    }

    pub(super) fn write_mov_result(
        &mut self,
        dest: RuntimeRegister,
        src: RuntimeRegister,
        result_value: Value,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        if !hooks_enabled {
            return self.assign_current_register_without_previous(dest, result_value);
        }

        let src_value = (
            self.hook_register(src)?,
            self.current_register_value(src)?.into_value(),
        );
        let (old_value, result_value) = self.assign_current_register(dest, result_value)?;

        let read_event = HookEvent::RegisterRead(src_value.0, src_value.1);
        self.trigger_hook_with_snapshot(&read_event)?;

        let write_event =
            HookEvent::RegisterWrite(self.hook_register(dest)?, old_value, result_value);
        self.trigger_hook_with_snapshot(&write_event)?;
        Ok(())
    }

    pub(super) fn execute_add(
        &mut self,
        dest: RuntimeRegister,
        src1: RuntimeRegister,
        src2: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        if !hooks_enabled && self.try_execute_fast_clear_add(dest, src1, src2)? {
            return Ok(());
        }

        let (left, right) = self.with_resolved_register_pair(src1, src2, |left, right, _| {
            Ok((left.clone(), right.clone()))
        })?;
        let left = self.unwrap_share_value_for_arith(left)?;
        let right = self.unwrap_share_value_for_arith(right)?;
        let result_value =
            runtime_value_ops::add(&left, &right, &|| self.share_runtime().map_err(Into::into))?;

        self.write_current_register(dest, result_value, hooks_enabled)?;
        Ok(())
    }

    fn try_execute_fast_clear_add(
        &mut self,
        dest: RuntimeRegister,
        src1: RuntimeRegister,
        src2: RuntimeRegister,
    ) -> VmResult<bool> {
        self.try_execute_fast_clear_binary_op(dest, src1, src2, runtime_value_ops::try_clear_add)
    }

    #[inline]
    fn try_execute_fast_clear_binary_op(
        &mut self,
        dest: RuntimeRegister,
        src1: RuntimeRegister,
        src2: RuntimeRegister,
        op: impl FnOnce(&Value, &Value) -> Option<Result<Value, runtime_value_ops::ValueOpError>>,
    ) -> VmResult<bool> {
        if self.mpc_runtime.has_any_pending_reveals() {
            return Ok(false);
        }

        let outcome = self.current_frame_mut()?.apply_clear_binary(
            dest.register_index(),
            src1.register_index(),
            src2.register_index(),
            op,
        )?;
        match outcome {
            ClearRegisterOperationResult::Applied => Ok(true),
            ClearRegisterOperationResult::NotClearRegister
            | ClearRegisterOperationResult::UnsupportedOperands => Ok(false),
            ClearRegisterOperationResult::RegisterOutOfBounds(register) => {
                Err(Self::register_out_of_bounds(
                    register.index(),
                    self.current_frame()?.register_count(),
                ))
            }
            ClearRegisterOperationResult::SourcePendingReveal(register) => {
                Err(VmError::PendingRevealWithoutQueuedBatch {
                    register: register.index(),
                })
            }
        }
    }

    fn try_execute_fast_clear_not(
        &mut self,
        dest: RuntimeRegister,
        src: RuntimeRegister,
    ) -> VmResult<bool> {
        if self.mpc_runtime.has_any_pending_reveals() {
            return Ok(false);
        }

        let dest_index = dest.register_index();
        let src_index = src.register_index();
        let result_value = {
            let record = self.current_frame()?;
            Self::ensure_frame_contains_register(record, dest)?;
            Self::ensure_frame_contains_register(record, src)?;

            let layout = record.register_layout();
            if !layout.is_clear(dest_index) || !layout.is_clear(src_index) {
                return Ok(false);
            }

            let Some(value) = record.register(src_index) else {
                return Err(VmError::PendingRevealWithoutQueuedBatch {
                    register: src.index(),
                });
            };

            let Some(result_value) = runtime_value_ops::try_clear_bit_not(value) else {
                return Ok(false);
            };
            result_value?
        };

        self.write_fast_clear_register(dest, result_value)
            .map(|()| true)
    }

    #[inline]
    fn write_fast_clear_register(&mut self, dest: RuntimeRegister, value: Value) -> VmResult<()> {
        let dest_index = dest.register_index();
        let record = self.current_frame_mut()?;
        let register_count = record.register_count();
        let Some(slot) = record.register_mut(dest_index) else {
            return Err(Self::register_out_of_bounds(dest.index(), register_count));
        };
        *slot = value;
        Ok(())
    }

    pub(super) fn execute_sub(
        &mut self,
        dest: RuntimeRegister,
        src1: RuntimeRegister,
        src2: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        if !hooks_enabled
            && self.try_execute_fast_clear_binary_op(
                dest,
                src1,
                src2,
                runtime_value_ops::try_clear_sub,
            )?
        {
            return Ok(());
        }

        let (left, right) = self.with_resolved_register_pair(src1, src2, |left, right, _| {
            Ok((left.clone(), right.clone()))
        })?;
        let left = self.unwrap_share_value_for_arith(left)?;
        let right = self.unwrap_share_value_for_arith(right)?;
        let result_value =
            runtime_value_ops::sub(&left, &right, &|| self.share_runtime().map_err(Into::into))?;

        self.write_current_register(dest, result_value, hooks_enabled)?;
        Ok(())
    }

    pub(super) fn execute_mul(
        &mut self,
        dest: RuntimeRegister,
        src1: RuntimeRegister,
        src2: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        if !hooks_enabled
            && self.try_execute_fast_clear_binary_op(
                dest,
                src1,
                src2,
                runtime_value_ops::try_clear_mul,
            )?
        {
            return Ok(());
        }

        let (left, right) = self.with_resolved_register_pair(src1, src2, |left, right, _| {
            Ok((left.clone(), right.clone()))
        })?;
        let left = self.unwrap_share_value_for_arith(left)?;
        let right = self.unwrap_share_value_for_arith(right)?;
        let computed =
            runtime_value_ops::mul(&left, &right, &|| self.share_runtime().map_err(Into::into))?;

        self.write_current_register(dest, computed, hooks_enabled)?;
        Ok(())
    }

    pub(super) fn execute_div(
        &mut self,
        dest: RuntimeRegister,
        src1: RuntimeRegister,
        src2: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        if !hooks_enabled
            && self.try_execute_fast_clear_binary_op(
                dest,
                src1,
                src2,
                runtime_value_ops::try_clear_div,
            )?
        {
            return Ok(());
        }

        let (left, right) = self.with_resolved_register_pair(src1, src2, |left, right, _| {
            Ok((left.clone(), right.clone()))
        })?;
        let left = self.unwrap_share_value_for_arith(left)?;
        let right = self.unwrap_share_value_for_arith(right)?;
        let result_value =
            runtime_value_ops::div(&left, &right, &|| self.share_runtime().map_err(Into::into))?;

        self.write_current_register(dest, result_value, hooks_enabled)?;
        Ok(())
    }

    pub(super) fn execute_mod(
        &mut self,
        dest: RuntimeRegister,
        src1: RuntimeRegister,
        src2: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        if !hooks_enabled
            && self.try_execute_fast_clear_binary_op(
                dest,
                src1,
                src2,
                runtime_value_ops::try_clear_modulo,
            )?
        {
            return Ok(());
        }

        let result_value = self.with_resolved_register_pair(src1, src2, |left, right, _| {
            Ok(runtime_value_ops::modulo(left, right)?)
        })?;

        self.write_current_register(dest, result_value, hooks_enabled)?;
        Ok(())
    }

    pub(super) fn execute_and(
        &mut self,
        dest: RuntimeRegister,
        src1: RuntimeRegister,
        src2: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        if !hooks_enabled
            && self.try_execute_fast_clear_binary_op(
                dest,
                src1,
                src2,
                runtime_value_ops::try_clear_bit_and,
            )?
        {
            return Ok(());
        }

        let result_value = self.with_resolved_register_pair(src1, src2, |left, right, state| {
            Ok(runtime_value_ops::bit_and(left, right, &|| {
                state.share_runtime().map_err(Into::into)
            })?)
        })?;

        self.write_current_register(dest, result_value, hooks_enabled)?;
        Ok(())
    }

    pub(super) fn execute_or(
        &mut self,
        dest: RuntimeRegister,
        src1: RuntimeRegister,
        src2: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        if !hooks_enabled
            && self.try_execute_fast_clear_binary_op(
                dest,
                src1,
                src2,
                runtime_value_ops::try_clear_bit_or,
            )?
        {
            return Ok(());
        }

        let result_value = self.with_resolved_register_pair(src1, src2, |left, right, state| {
            Ok(runtime_value_ops::bit_or(left, right, &|| {
                state.share_runtime().map_err(Into::into)
            })?)
        })?;

        self.write_current_register(dest, result_value, hooks_enabled)?;
        Ok(())
    }

    pub(super) fn execute_xor(
        &mut self,
        dest: RuntimeRegister,
        src1: RuntimeRegister,
        src2: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        if !hooks_enabled
            && self.try_execute_fast_clear_binary_op(
                dest,
                src1,
                src2,
                runtime_value_ops::try_clear_bit_xor,
            )?
        {
            return Ok(());
        }

        let result_value = self.with_resolved_register_pair(src1, src2, |left, right, state| {
            Ok(runtime_value_ops::bit_xor(left, right, &|| {
                state.share_runtime().map_err(Into::into)
            })?)
        })?;

        self.write_current_register(dest, result_value, hooks_enabled)?;
        Ok(())
    }

    pub(super) fn execute_not(
        &mut self,
        dest: RuntimeRegister,
        src: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        if !hooks_enabled && self.try_execute_fast_clear_not(dest, src)? {
            return Ok(());
        }

        let result_value = self.with_resolved_register(src, |value, state| {
            Ok(runtime_value_ops::bit_not(value, &|| {
                state.share_runtime().map_err(Into::into)
            })?)
        })?;

        self.write_current_register(dest, result_value, hooks_enabled)?;
        Ok(())
    }

    pub(super) fn execute_shl(
        &mut self,
        dest: RuntimeRegister,
        src: RuntimeRegister,
        amount: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        if !hooks_enabled
            && self.try_execute_fast_clear_binary_op(
                dest,
                src,
                amount,
                runtime_value_ops::try_clear_shl,
            )?
        {
            return Ok(());
        }

        let result_value = self.with_resolved_register_pair(src, amount, |left, right, _| {
            Ok(runtime_value_ops::shl(left, right)?)
        })?;

        self.write_current_register(dest, result_value, hooks_enabled)?;
        Ok(())
    }

    pub(super) fn execute_shr(
        &mut self,
        dest: RuntimeRegister,
        src: RuntimeRegister,
        amount: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        if !hooks_enabled
            && self.try_execute_fast_clear_binary_op(
                dest,
                src,
                amount,
                runtime_value_ops::try_clear_shr,
            )?
        {
            return Ok(());
        }

        let result_value = self.with_resolved_register_pair(src, amount, |left, right, _| {
            Ok(runtime_value_ops::shr(left, right)?)
        })?;

        self.write_current_register(dest, result_value, hooks_enabled)?;
        Ok(())
    }

    #[inline]
    pub(super) fn execute_jump(
        &mut self,
        condition: RuntimeJumpCondition,
        target: JumpTarget,
    ) -> VmResult<()> {
        let frame = self.current_frame_mut()?;
        if condition.should_jump(frame.compare_flag()) {
            frame.set_instruction_pointer(InstructionPointer::new(target.index()));
        }
        Ok(())
    }

    #[inline]
    pub(super) fn execute_pusharg(
        &mut self,
        reg: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        let value = self.resolve_register(reg)?.into_value();
        let hook_value = hooks_enabled.then(|| value.clone());
        self.current_frame_mut()?.push_stack(value);

        if let Some(value) = hook_value {
            let event = HookEvent::StackPush(value);
            self.trigger_hook_with_snapshot(&event)?;
        }
        Ok(())
    }

    pub(super) fn execute_cmp(
        &mut self,
        lhs: RuntimeRegister,
        rhs: RuntimeRegister,
    ) -> VmResult<()> {
        if self.try_execute_fast_clear_cmp(lhs, rhs)? {
            return Ok(());
        }

        let compare_result = self.with_resolved_register_pair(lhs, rhs, |left, right, _| {
            Ok(runtime_value_ops::compare(left, right)?)
        })?;

        self.current_frame_mut()?
            .set_compare_flag(CompareFlag::from(compare_result));
        Ok(())
    }

    fn try_execute_fast_clear_cmp(
        &mut self,
        lhs: RuntimeRegister,
        rhs: RuntimeRegister,
    ) -> VmResult<bool> {
        if self.mpc_runtime.has_any_pending_reveals() {
            return Ok(false);
        }

        let record = self.current_frame_mut()?;
        match record.compare_clear(
            lhs.register_index(),
            rhs.register_index(),
            runtime_value_ops::try_clear_compare,
        ) {
            ClearRegisterCompareResult::Compared(ordering) => {
                record.set_compare_flag(CompareFlag::from_ordering(ordering));
                Ok(true)
            }
            ClearRegisterCompareResult::NotClearRegister
            | ClearRegisterCompareResult::UnsupportedOperands => Ok(false),
            ClearRegisterCompareResult::RegisterOutOfBounds(register) => Err(
                Self::register_out_of_bounds(register.index(), record.register_count()),
            ),
            ClearRegisterCompareResult::SourcePendingReveal(register) => {
                Err(VmError::PendingRevealWithoutQueuedBatch {
                    register: register.index(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stoffel_vm_types::core_types::{ShareData, ShareType};

    #[derive(Debug, PartialEq)]
    enum RuntimeCall {
        LoadImmediate {
            dest: RuntimeRegister,
            value: Value,
            hooks_enabled: bool,
        },
        Binary {
            op: RuntimeBinaryOp,
            dest: RuntimeRegister,
            lhs: RuntimeRegister,
            rhs: RuntimeRegister,
            hooks_enabled: bool,
        },
        Unary {
            op: RuntimeUnaryOp,
            dest: RuntimeRegister,
            src: RuntimeRegister,
            hooks_enabled: bool,
        },
        Shift {
            op: RuntimeShiftOp,
            dest: RuntimeRegister,
            src: RuntimeRegister,
            amount: RuntimeRegister,
            hooks_enabled: bool,
        },
    }

    #[derive(Default)]
    struct FakeInstructionRuntime {
        calls: Vec<RuntimeCall>,
        pending_operation: Option<PendingMpcOperation>,
    }

    impl FakeInstructionRuntime {
        fn unexpected<T>(operation: &'static str) -> VmResult<T> {
            panic!("unexpected instruction runtime operation: {operation}");
        }
    }

    impl InstructionRuntime for FakeInstructionRuntime {
        fn plan_async_mpc_operation(
            &mut self,
            _instruction: &RuntimeInstruction,
            _hooks_enabled: bool,
        ) -> VmResult<Option<PendingMpcOperation>> {
            Ok(self.pending_operation.take())
        }

        fn execute_ld(
            &mut self,
            _dest: RuntimeRegister,
            _offset: StackOffset,
            _hooks_enabled: bool,
        ) -> VmResult<()> {
            Self::unexpected("execute_ld")
        }

        fn execute_ldi(
            &mut self,
            dest: RuntimeRegister,
            value: Value,
            hooks_enabled: bool,
        ) -> VmResult<()> {
            self.calls.push(RuntimeCall::LoadImmediate {
                dest,
                value,
                hooks_enabled,
            });
            Ok(())
        }

        fn execute_mov(
            &mut self,
            _dest: RuntimeRegister,
            _src: RuntimeRegister,
            _hooks_enabled: bool,
        ) -> VmResult<()> {
            Self::unexpected("execute_mov")
        }

        fn execute_binary(
            &mut self,
            op: RuntimeBinaryOp,
            dest: RuntimeRegister,
            lhs: RuntimeRegister,
            rhs: RuntimeRegister,
            hooks_enabled: bool,
        ) -> VmResult<()> {
            self.calls.push(RuntimeCall::Binary {
                op,
                dest,
                lhs,
                rhs,
                hooks_enabled,
            });
            Ok(())
        }

        fn execute_unary(
            &mut self,
            op: RuntimeUnaryOp,
            dest: RuntimeRegister,
            src: RuntimeRegister,
            hooks_enabled: bool,
        ) -> VmResult<()> {
            self.calls.push(RuntimeCall::Unary {
                op,
                dest,
                src,
                hooks_enabled,
            });
            Ok(())
        }

        fn execute_shift(
            &mut self,
            op: RuntimeShiftOp,
            dest: RuntimeRegister,
            src: RuntimeRegister,
            amount: RuntimeRegister,
            hooks_enabled: bool,
        ) -> VmResult<()> {
            self.calls.push(RuntimeCall::Shift {
                op,
                dest,
                src,
                amount,
                hooks_enabled,
            });
            Ok(())
        }

        fn execute_jump(
            &mut self,
            _condition: RuntimeJumpCondition,
            _target: JumpTarget,
        ) -> VmResult<()> {
            Self::unexpected("execute_jump")
        }

        fn execute_call(
            &mut self,
            _function_name: &str,
            _hooks_enabled: bool,
        ) -> VmResult<InstructionOutcome> {
            Self::unexpected("execute_call")
        }

        fn execute_ret(
            &mut self,
            _src: RuntimeRegister,
            _hook_instruction: &Instruction,
            _hooks_enabled: bool,
            _checkpoint: CallStackCheckpoint,
        ) -> VmResult<InstructionOutcome> {
            Self::unexpected("execute_ret")
        }

        fn execute_pusharg(&mut self, _reg: RuntimeRegister, _hooks_enabled: bool) -> VmResult<()> {
            Self::unexpected("execute_pusharg")
        }

        fn execute_cmp(&mut self, _lhs: RuntimeRegister, _rhs: RuntimeRegister) -> VmResult<()> {
            Self::unexpected("execute_cmp")
        }

        fn execute_lds(
            &mut self,
            _dest: RuntimeRegister,
            _slot: usize,
            _hooks_enabled: bool,
        ) -> VmResult<()> {
            Self::unexpected("execute_lds")
        }

        fn execute_sts(
            &mut self,
            _slot: usize,
            _src: RuntimeRegister,
            _hooks_enabled: bool,
        ) -> VmResult<()> {
            Self::unexpected("execute_sts")
        }
    }

    fn runtime_reg(index: usize) -> RuntimeRegister {
        RuntimeRegister::try_new(index, 4).expect("test register should fit")
    }

    fn context(hooks_enabled: bool) -> ExecutionContext {
        ExecutionContext::new(CallStackCheckpoint::new(0), hooks_enabled)
    }

    #[test]
    fn instruction_executor_dispatches_through_runtime_trait() {
        let mut runtime = FakeInstructionRuntime::default();
        let instruction = RuntimeInstruction::Binary {
            op: RuntimeBinaryOp::Add,
            dest: runtime_reg(0),
            lhs: runtime_reg(1),
            rhs: runtime_reg(2),
        };
        let hook_instruction = Instruction::ADD(0, 1, 2);

        let outcome =
            InstructionExecutor::new(&mut runtime, &instruction, &hook_instruction, context(true))
                .execute_local()
                .expect("dispatch should succeed");

        assert!(matches!(outcome, InstructionOutcome::Continue));
        assert_eq!(
            runtime.calls,
            vec![RuntimeCall::Binary {
                op: RuntimeBinaryOp::Add,
                dest: runtime_reg(0),
                lhs: runtime_reg(1),
                rhs: runtime_reg(2),
                hooks_enabled: true,
            }]
        );
    }

    #[test]
    fn instruction_executor_dispatches_unary_and_shift_operation_families() {
        let mut runtime = FakeInstructionRuntime::default();
        let unary = RuntimeInstruction::Unary {
            op: RuntimeUnaryOp::BitNot,
            dest: runtime_reg(0),
            src: runtime_reg(1),
        };
        let shift = RuntimeInstruction::Shift {
            op: RuntimeShiftOp::Left,
            dest: runtime_reg(2),
            src: runtime_reg(0),
            amount: runtime_reg(3),
        };

        InstructionExecutor::new(
            &mut runtime,
            &unary,
            &Instruction::NOT(0, 1),
            context(false),
        )
        .execute_local()
        .expect("unary dispatch should succeed");

        InstructionExecutor::new(
            &mut runtime,
            &shift,
            &Instruction::SHL(2, 0, 3),
            context(true),
        )
        .execute_local()
        .expect("shift dispatch should succeed");

        assert_eq!(
            runtime.calls,
            vec![
                RuntimeCall::Unary {
                    op: RuntimeUnaryOp::BitNot,
                    dest: runtime_reg(0),
                    src: runtime_reg(1),
                    hooks_enabled: false,
                },
                RuntimeCall::Shift {
                    op: RuntimeShiftOp::Left,
                    dest: runtime_reg(2),
                    src: runtime_reg(0),
                    amount: runtime_reg(3),
                    hooks_enabled: true,
                },
            ]
        );
    }

    #[test]
    fn instruction_executor_reports_pending_mpc_without_local_dispatch() {
        let mut runtime = FakeInstructionRuntime {
            pending_operation: Some(PendingMpcOperation::Multiply {
                share_type: ShareType::secret_int(64),
                left_data: ShareData::Opaque(vec![1].into()),
                right_data: ShareData::Opaque(vec![2].into()),
                dest: runtime_reg(0),
            }),
            ..Default::default()
        };
        let instruction = RuntimeInstruction::LoadImmediate {
            dest: runtime_reg(0),
            value: RuntimeImmediate::inline(Value::I64(7)),
        };
        let hook_instruction = Instruction::LDI(0, Value::I64(7));

        let effect = InstructionExecutor::new(
            &mut runtime,
            &instruction,
            &hook_instruction,
            context(false),
        )
        .execute_effect()
        .expect("pending MPC planning should succeed");

        assert!(runtime.calls.is_empty());
        assert!(matches!(
            effect,
            InstructionEffect::PendingMpc(PendingMpcOperation::Multiply { .. })
        ));
    }
}
