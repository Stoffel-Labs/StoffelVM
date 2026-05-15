use super::{
    execution::{ExecutionContext, InstructionEffect, InstructionOutcome},
    mpc_operation::PendingMpcOperation,
    CallStackCheckpoint, VMState,
};
use crate::error::{VmError, VmResult};
use crate::runtime_hooks::HookEvent;
use crate::runtime_instruction::{
    JumpTarget, RuntimeBinaryOp, RuntimeInstruction, RuntimeJumpCondition, RuntimeRegister,
    RuntimeShiftOp, RuntimeUnaryOp, StackOffset,
};
use crate::runtime_value_ops;
use stoffel_vm_types::activations::{CompareFlag, InstructionPointer};
use stoffel_vm_types::core_types::Value;
use stoffel_vm_types::instructions::Instruction;
use stoffel_vm_types::registers::RegisterMoveKind;

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
}

pub(super) struct InstructionExecutor<'state, 'instruction, R: InstructionRuntime + ?Sized> {
    state: &'state mut R,
    instruction: &'instruction RuntimeInstruction,
    hook_instruction: &'instruction Instruction,
    context: ExecutionContext,
}

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
            RuntimeInstruction::LoadStack { dest, offset } => {
                self.state.execute_ld(*dest, *offset, hooks_enabled)?;
            }
            RuntimeInstruction::LoadImmediate { dest, value } => {
                self.state
                    .execute_ldi(*dest, value.clone(), hooks_enabled)?;
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
                return self.state.execute_call(function, hooks_enabled);
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
        }

        Ok(InstructionOutcome::Continue)
    }
}

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
}

impl VMState {
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

    pub(super) fn execute_mov(
        &mut self,
        dest: RuntimeRegister,
        src: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        let move_kind = self
            .current_register_layout()?
            .move_kind(dest.register_index(), src.register_index());
        let src_value = self.resolve_register(src)?.into_value();

        if move_kind == RegisterMoveKind::SecretToClear && !hooks_enabled {
            self.queue_reveal_to_register(&src_value, dest)?;
            return Ok(());
        }

        let result_value = match move_kind {
            RegisterMoveKind::ClearToSecret if !matches!(src_value, Value::Share(_, _)) => {
                self.convert_to_share(&src_value)?
            }
            RegisterMoveKind::SecretToClear => self.reveal_share_immediate(&src_value)?,
            RegisterMoveKind::Copy | RegisterMoveKind::ClearToSecret => src_value,
        };

        self.write_mov_result(dest, src, result_value, hooks_enabled)
    }

    pub(super) fn write_mov_result(
        &mut self,
        dest: RuntimeRegister,
        src: RuntimeRegister,
        result_value: Value,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        let src_value = if hooks_enabled {
            Some((
                self.hook_register(src)?,
                self.current_register_value(src)?.into_value(),
            ))
        } else {
            None
        };
        let (old_value, result_value) = self.assign_current_register(dest, result_value)?;

        if let Some((src_reg, src_value)) = src_value {
            let read_event = HookEvent::RegisterRead(src_reg, src_value);
            self.trigger_hook_with_snapshot(&read_event)?;

            let write_event =
                HookEvent::RegisterWrite(self.hook_register(dest)?, old_value, result_value);
            self.trigger_hook_with_snapshot(&write_event)?;
        }
        Ok(())
    }

    pub(super) fn execute_add(
        &mut self,
        dest: RuntimeRegister,
        src1: RuntimeRegister,
        src2: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        let operands = self.resolve_register_pair(src1, src2)?;
        let result_value =
            runtime_value_ops::add(operands.left_value(), operands.right_value(), &|| {
                self.share_runtime().map_err(Into::into)
            })?;

        self.write_current_register(dest, result_value, hooks_enabled)?;
        Ok(())
    }

    pub(super) fn execute_sub(
        &mut self,
        dest: RuntimeRegister,
        src1: RuntimeRegister,
        src2: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        let operands = self.resolve_register_pair(src1, src2)?;
        let result_value =
            runtime_value_ops::sub(operands.left_value(), operands.right_value(), &|| {
                self.share_runtime().map_err(Into::into)
            })?;

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
        let operands = self.resolve_register_pair(src1, src2)?;
        let computed =
            runtime_value_ops::mul(operands.left_value(), operands.right_value(), &|| {
                self.share_runtime().map_err(Into::into)
            })?;

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
        let operands = self.resolve_register_pair(src1, src2)?;
        let result_value =
            runtime_value_ops::div(operands.left_value(), operands.right_value(), &|| {
                self.share_runtime().map_err(Into::into)
            })?;

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
        let operands = self.resolve_register_pair(src1, src2)?;
        let result_value =
            runtime_value_ops::modulo(operands.left_value(), operands.right_value())?;

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
        let operands = self.resolve_register_pair(src1, src2)?;
        let result_value =
            runtime_value_ops::bit_and(operands.left_value(), operands.right_value())?;

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
        let operands = self.resolve_register_pair(src1, src2)?;
        let result_value =
            runtime_value_ops::bit_or(operands.left_value(), operands.right_value())?;

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
        let operands = self.resolve_register_pair(src1, src2)?;
        let result_value =
            runtime_value_ops::bit_xor(operands.left_value(), operands.right_value())?;

        self.write_current_register(dest, result_value, hooks_enabled)?;
        Ok(())
    }

    pub(super) fn execute_not(
        &mut self,
        dest: RuntimeRegister,
        src: RuntimeRegister,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        let src = self.resolve_register(src)?;
        let result_value = runtime_value_ops::bit_not(src.value())?;

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
        let operands = self.resolve_register_pair(src, amount)?;
        let result_value = runtime_value_ops::shl(operands.left_value(), operands.right_value())?;

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
        let operands = self.resolve_register_pair(src, amount)?;
        let result_value = runtime_value_ops::shr(operands.left_value(), operands.right_value())?;

        self.write_current_register(dest, result_value, hooks_enabled)?;
        Ok(())
    }

    #[inline]
    pub(super) fn execute_jump(
        &mut self,
        condition: RuntimeJumpCondition,
        target: JumpTarget,
    ) -> VmResult<()> {
        if condition.should_jump(self.current_frame()?.compare_flag()) {
            self.current_frame_mut()?
                .set_instruction_pointer(InstructionPointer::new(target.index()));
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
        self.current_frame_mut()?.push_stack(value.clone());

        if hooks_enabled {
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
        let operands = self.resolve_register_pair(lhs, rhs)?;
        let compare_result =
            runtime_value_ops::compare(operands.left_value(), operands.right_value())?;

        self.current_frame_mut()?
            .set_compare_flag(CompareFlag::from(compare_result));
        Ok(())
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
                left_data: ShareData::Opaque(vec![1]),
                right_data: ShareData::Opaque(vec![2]),
                dest: runtime_reg(0),
            }),
            ..Default::default()
        };
        let instruction = RuntimeInstruction::LoadImmediate {
            dest: runtime_reg(0),
            value: Value::I64(7),
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
