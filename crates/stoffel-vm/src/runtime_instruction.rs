use crate::error::{VmError, VmResult};
use std::sync::Arc;
use stoffel_vm_types::activations::{CompareFlag, InstructionPointer};
use stoffel_vm_types::core_types::Value;
use stoffel_vm_types::functions::VMFunction;
use stoffel_vm_types::instructions::{Instruction, ResolvedInstruction};
use stoffel_vm_types::registers::{RegisterIndex, RETURN_REGISTER_INDEX};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeBinaryOp {
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulo,
    BitAnd,
    BitOr,
    BitXor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeUnaryOp {
    BitNot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeShiftOp {
    Left,
    Right,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeJumpCondition {
    Always,
    Equal,
    NotEqual,
    Less,
    Greater,
}

impl RuntimeJumpCondition {
    pub(crate) const fn should_jump(self, compare_flag: CompareFlag) -> bool {
        match self {
            Self::Always => true,
            Self::Equal => compare_flag.is_equal(),
            Self::NotEqual => compare_flag.is_not_equal(),
            Self::Less => compare_flag.is_less(),
            Self::Greater => compare_flag.is_greater(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RuntimeRegister(usize);

impl RuntimeRegister {
    pub(crate) fn try_new(register: usize, register_count: usize) -> VmResult<Self> {
        if register < register_count {
            Ok(Self(register))
        } else {
            Err(VmError::RegisterOutOfBounds {
                register,
                register_count,
            })
        }
    }

    pub(crate) fn return_register(register_count: usize) -> VmResult<Self> {
        Self::try_new(RETURN_REGISTER_INDEX, register_count)
    }

    pub(crate) const fn index(self) -> usize {
        self.0
    }

    pub(crate) const fn register_index(self) -> RegisterIndex {
        RegisterIndex::new(self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StackOffset(i32);

impl StackOffset {
    pub(crate) const fn new(offset: i32) -> Self {
        Self(offset)
    }

    pub(crate) const fn raw(self) -> i32 {
        self.0
    }

    pub(crate) fn resolve_index(self, stack_len: usize) -> VmResult<usize> {
        if self.0 == 0 {
            return stack_len
                .checked_sub(1)
                .ok_or(VmError::StackAddressOutOfBounds { offset: self.0 });
        }

        let stack_len = i64::try_from(stack_len).map_err(|_| VmError::StackLengthOverflow)?;
        let index = stack_len
            .checked_add(i64::from(self.0))
            .and_then(|index| index.checked_sub(1))
            .ok_or(VmError::StackAddressOverflow { offset: self.0 })?;

        if index < 0 || index >= stack_len {
            return Err(VmError::StackAddressOutOfBounds { offset: self.0 });
        }

        usize::try_from(index).map_err(|_| VmError::StackAddressOutOfBounds { offset: self.0 })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JumpTarget(usize);

impl JumpTarget {
    pub(crate) fn try_new(target: usize, instruction_count: usize) -> VmResult<Self> {
        if target <= instruction_count {
            Ok(Self(target))
        } else {
            Err(VmError::JumpTargetOutOfBounds {
                target,
                instruction_count,
            })
        }
    }

    pub(crate) const fn index(self) -> usize {
        self.0
    }
}

#[derive(Debug)]
struct RuntimeInstructionEntry {
    hook_instruction: Instruction,
    runtime_instruction: RuntimeInstruction,
}

#[derive(Debug, Clone)]
pub(crate) enum RuntimeInstruction {
    Noop,
    LoadStack {
        dest: RuntimeRegister,
        offset: StackOffset,
    },
    LoadImmediate {
        dest: RuntimeRegister,
        value: Value,
    },
    Move {
        dest: RuntimeRegister,
        src: RuntimeRegister,
    },
    Binary {
        op: RuntimeBinaryOp,
        dest: RuntimeRegister,
        lhs: RuntimeRegister,
        rhs: RuntimeRegister,
    },
    Unary {
        op: RuntimeUnaryOp,
        dest: RuntimeRegister,
        src: RuntimeRegister,
    },
    Shift {
        op: RuntimeShiftOp,
        dest: RuntimeRegister,
        src: RuntimeRegister,
        amount: RuntimeRegister,
    },
    Jump {
        condition: RuntimeJumpCondition,
        target: JumpTarget,
    },
    Call {
        function: Arc<str>,
    },
    Return {
        src: RuntimeRegister,
    },
    PushArg {
        src: RuntimeRegister,
    },
    Compare {
        lhs: RuntimeRegister,
        rhs: RuntimeRegister,
    },
}

/// VM function lowered for runtime dispatch.
///
/// `VMFunction` keeps source-oriented metadata for registration, binary
/// conversion, hook display, and call-frame setup. This type stores only the
/// execution form the VM actually dispatches, so constants and symbolic calls
/// are lowered once at registration instead of being re-decoded for every
/// instruction fetch.
#[derive(Debug)]
pub(crate) struct RuntimeFunction {
    instructions: Vec<RuntimeInstructionEntry>,
}

impl RuntimeFunction {
    pub(crate) fn from_vm_function(function: &VMFunction) -> VmResult<Self> {
        let resolved_instructions = function.resolved_instructions().ok_or_else(|| {
            VmError::MissingResolvedInstructions {
                function: function.name().to_owned(),
            }
        })?;
        let source_instructions = function.instructions();

        if resolved_instructions.len() != source_instructions.len() {
            return Err(VmError::RuntimeInstructionMetadataMismatch {
                function: function.name().to_owned(),
                resolved_instruction_count: resolved_instructions.len(),
                source_instruction_count: source_instructions.len(),
            });
        }

        let instructions = resolved_instructions
            .iter()
            .zip(source_instructions)
            .map(|(resolved, source)| {
                Ok(RuntimeInstructionEntry {
                    hook_instruction: source.clone(),
                    runtime_instruction: lower_instruction(function, resolved)?,
                })
            })
            .collect::<VmResult<Vec<_>>>()?;

        Ok(Self { instructions })
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.instructions.len()
    }

    #[inline]
    pub(crate) fn get_instruction(
        &self,
        instruction_pointer: InstructionPointer,
    ) -> Option<FetchedInstruction<'_>> {
        self.instructions
            .get(instruction_pointer.index())
            .map(|entry| FetchedInstruction { entry })
    }

    #[cfg(test)]
    fn instruction_entry(
        &self,
        instruction_pointer: InstructionPointer,
    ) -> VmResult<&RuntimeInstructionEntry> {
        let index = instruction_pointer.index();
        self.instructions
            .get(index)
            .ok_or_else(|| VmError::InstructionOutOfBounds { index })
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FetchedInstruction<'function> {
    entry: &'function RuntimeInstructionEntry,
}

impl<'function> FetchedInstruction<'function> {
    #[cfg(test)]
    pub(crate) fn fetch(
        instruction_pointer: InstructionPointer,
        function: &'function RuntimeFunction,
    ) -> VmResult<Self> {
        let entry = function.instruction_entry(instruction_pointer)?;
        Ok(FetchedInstruction { entry })
    }

    #[inline]
    pub(crate) fn hook_instruction(&self) -> &Instruction {
        &self.entry.hook_instruction
    }

    #[inline]
    pub(crate) fn runtime_instruction(&self) -> &RuntimeInstruction {
        &self.entry.runtime_instruction
    }

    #[inline]
    #[cfg(test)]
    pub(crate) fn instructions(&self) -> (&RuntimeInstruction, &Instruction) {
        (self.runtime_instruction(), self.hook_instruction())
    }
}

fn lower_instruction(
    vm_function: &VMFunction,
    resolved: &ResolvedInstruction,
) -> VmResult<RuntimeInstruction> {
    Ok(match *resolved {
        ResolvedInstruction::NOP => RuntimeInstruction::Noop,
        ResolvedInstruction::LD(dest, offset) => RuntimeInstruction::LoadStack {
            dest: reg(vm_function, dest)?,
            offset: StackOffset::new(offset),
        },
        ResolvedInstruction::LDI(dest, const_idx) => {
            let value = get_constant_value(vm_function, const_idx)?;
            RuntimeInstruction::LoadImmediate {
                dest: reg(vm_function, dest)?,
                value,
            }
        }
        ResolvedInstruction::MOV(dest, src) => RuntimeInstruction::Move {
            dest: reg(vm_function, dest)?,
            src: reg(vm_function, src)?,
        },
        ResolvedInstruction::ADD(dest, lhs, rhs) => RuntimeInstruction::Binary {
            op: RuntimeBinaryOp::Add,
            dest: reg(vm_function, dest)?,
            lhs: reg(vm_function, lhs)?,
            rhs: reg(vm_function, rhs)?,
        },
        ResolvedInstruction::SUB(dest, lhs, rhs) => RuntimeInstruction::Binary {
            op: RuntimeBinaryOp::Subtract,
            dest: reg(vm_function, dest)?,
            lhs: reg(vm_function, lhs)?,
            rhs: reg(vm_function, rhs)?,
        },
        ResolvedInstruction::MUL(dest, lhs, rhs) => RuntimeInstruction::Binary {
            op: RuntimeBinaryOp::Multiply,
            dest: reg(vm_function, dest)?,
            lhs: reg(vm_function, lhs)?,
            rhs: reg(vm_function, rhs)?,
        },
        ResolvedInstruction::DIV(dest, lhs, rhs) => RuntimeInstruction::Binary {
            op: RuntimeBinaryOp::Divide,
            dest: reg(vm_function, dest)?,
            lhs: reg(vm_function, lhs)?,
            rhs: reg(vm_function, rhs)?,
        },
        ResolvedInstruction::MOD(dest, lhs, rhs) => RuntimeInstruction::Binary {
            op: RuntimeBinaryOp::Modulo,
            dest: reg(vm_function, dest)?,
            lhs: reg(vm_function, lhs)?,
            rhs: reg(vm_function, rhs)?,
        },
        ResolvedInstruction::AND(dest, lhs, rhs) => RuntimeInstruction::Binary {
            op: RuntimeBinaryOp::BitAnd,
            dest: reg(vm_function, dest)?,
            lhs: reg(vm_function, lhs)?,
            rhs: reg(vm_function, rhs)?,
        },
        ResolvedInstruction::OR(dest, lhs, rhs) => RuntimeInstruction::Binary {
            op: RuntimeBinaryOp::BitOr,
            dest: reg(vm_function, dest)?,
            lhs: reg(vm_function, lhs)?,
            rhs: reg(vm_function, rhs)?,
        },
        ResolvedInstruction::XOR(dest, lhs, rhs) => RuntimeInstruction::Binary {
            op: RuntimeBinaryOp::BitXor,
            dest: reg(vm_function, dest)?,
            lhs: reg(vm_function, lhs)?,
            rhs: reg(vm_function, rhs)?,
        },
        ResolvedInstruction::NOT(dest, src) => RuntimeInstruction::Unary {
            op: RuntimeUnaryOp::BitNot,
            dest: reg(vm_function, dest)?,
            src: reg(vm_function, src)?,
        },
        ResolvedInstruction::SHL(dest, src, amount) => RuntimeInstruction::Shift {
            op: RuntimeShiftOp::Left,
            dest: reg(vm_function, dest)?,
            src: reg(vm_function, src)?,
            amount: reg(vm_function, amount)?,
        },
        ResolvedInstruction::SHR(dest, src, amount) => RuntimeInstruction::Shift {
            op: RuntimeShiftOp::Right,
            dest: reg(vm_function, dest)?,
            src: reg(vm_function, src)?,
            amount: reg(vm_function, amount)?,
        },
        ResolvedInstruction::JMP(target) => {
            lower_jump(vm_function, RuntimeJumpCondition::Always, target)?
        }
        ResolvedInstruction::JMPEQ(target) => {
            lower_jump(vm_function, RuntimeJumpCondition::Equal, target)?
        }
        ResolvedInstruction::JMPNEQ(target) => {
            lower_jump(vm_function, RuntimeJumpCondition::NotEqual, target)?
        }
        ResolvedInstruction::JMPLT(target) => {
            lower_jump(vm_function, RuntimeJumpCondition::Less, target)?
        }
        ResolvedInstruction::JMPGT(target) => {
            lower_jump(vm_function, RuntimeJumpCondition::Greater, target)?
        }
        ResolvedInstruction::CALL(func_idx) => {
            let func_name = get_function_name_from_constant(vm_function, func_idx)?;
            RuntimeInstruction::Call {
                function: Arc::from(func_name),
            }
        }
        ResolvedInstruction::RET(src) => RuntimeInstruction::Return {
            src: reg(vm_function, src)?,
        },
        ResolvedInstruction::PUSHARG(src) => RuntimeInstruction::PushArg {
            src: reg(vm_function, src)?,
        },
        ResolvedInstruction::CMP(lhs, rhs) => RuntimeInstruction::Compare {
            lhs: reg(vm_function, lhs)?,
            rhs: reg(vm_function, rhs)?,
        },
    })
}

fn reg(vm_function: &VMFunction, register: usize) -> VmResult<RuntimeRegister> {
    RuntimeRegister::try_new(register, vm_function.register_count())
}

fn lower_jump(
    vm_function: &VMFunction,
    condition: RuntimeJumpCondition,
    target: usize,
) -> VmResult<RuntimeInstruction> {
    Ok(RuntimeInstruction::Jump {
        condition,
        target: JumpTarget::try_new(target, vm_function.instructions().len())?,
    })
}

fn get_constant_value(vm_function: &VMFunction, const_idx: usize) -> VmResult<Value> {
    vm_function
        .constant_values()
        .and_then(|c| c.get(const_idx).cloned())
        .ok_or(VmError::ConstantOutOfBounds { index: const_idx })
}

fn get_function_name_from_constant(vm_function: &VMFunction, func_idx: usize) -> VmResult<String> {
    let value = get_constant_value(vm_function, func_idx)?;
    match value {
        Value::String(name) => Ok(name),
        _ => Err(VmError::InvalidFunctionNameConstant { index: func_idx }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn stack_offset_resolves_relative_to_top_of_stack() {
        assert_eq!(StackOffset::new(0).resolve_index(3).unwrap(), 2);
        assert_eq!(StackOffset::new(-1).resolve_index(3).unwrap(), 1);
        assert_eq!(StackOffset::new(-2).resolve_index(3).unwrap(), 0);
    }

    #[test]
    fn stack_offset_rejects_addresses_outside_stack() {
        assert!(matches!(
            StackOffset::new(0).resolve_index(0),
            Err(VmError::StackAddressOutOfBounds { offset: 0 })
        ));
        assert!(matches!(
            StackOffset::new(1).resolve_index(1),
            Err(VmError::StackAddressOutOfBounds { offset: 1 })
        ));
        assert!(matches!(
            StackOffset::new(-3).resolve_index(2),
            Err(VmError::StackAddressOutOfBounds { offset: -3 })
        ));
    }

    #[test]
    fn jump_condition_evaluates_compare_flags_in_one_place() {
        assert!(RuntimeJumpCondition::Always.should_jump(CompareFlag::Less));
        assert!(RuntimeJumpCondition::Equal.should_jump(CompareFlag::Equal));
        assert!(!RuntimeJumpCondition::Equal.should_jump(CompareFlag::Greater));
        assert!(RuntimeJumpCondition::NotEqual.should_jump(CompareFlag::Less));
        assert!(!RuntimeJumpCondition::NotEqual.should_jump(CompareFlag::Equal));
        assert!(RuntimeJumpCondition::Less.should_jump(CompareFlag::Less));
        assert!(!RuntimeJumpCondition::Less.should_jump(CompareFlag::Greater));
        assert!(RuntimeJumpCondition::Greater.should_jump(CompareFlag::Greater));
        assert!(!RuntimeJumpCondition::Greater.should_jump(CompareFlag::Less));
    }

    #[test]
    fn runtime_register_accepts_operands_inside_frame() {
        assert_eq!(RuntimeRegister::try_new(0, 3).unwrap().index(), 0);
        assert_eq!(RuntimeRegister::try_new(2, 3).unwrap().index(), 2);
    }

    #[test]
    fn runtime_register_rejects_operands_outside_frame() {
        assert!(matches!(
            RuntimeRegister::try_new(3, 3),
            Err(VmError::RegisterOutOfBounds {
                register: 3,
                register_count: 3
            })
        ));
    }

    #[test]
    fn lowering_preserves_noop_as_dispatch_only_instruction() {
        let function = VMFunction::new(
            "noop".to_owned(),
            vec![],
            vec![],
            None,
            1,
            vec![Instruction::NOP],
            HashMap::new(),
        );

        assert!(matches!(
            lower_instruction(&function, &ResolvedInstruction::NOP).unwrap(),
            RuntimeInstruction::Noop
        ));
    }

    #[test]
    fn lowering_rejects_resolved_register_outside_frame() {
        let function = VMFunction::new(
            "bad_register".to_owned(),
            vec![],
            vec![],
            None,
            1,
            vec![Instruction::RET(0)],
            HashMap::new(),
        );

        let error = lower_instruction(&function, &ResolvedInstruction::RET(1)).unwrap_err();
        assert!(matches!(
            error,
            VmError::RegisterOutOfBounds {
                register: 1,
                register_count: 1
            }
        ));
    }

    #[test]
    fn jump_target_accepts_instruction_indices_and_function_end() {
        assert_eq!(JumpTarget::try_new(0, 3).unwrap().index(), 0);
        assert_eq!(JumpTarget::try_new(2, 3).unwrap().index(), 2);
        assert_eq!(JumpTarget::try_new(3, 3).unwrap().index(), 3);
    }

    #[test]
    fn jump_target_rejects_targets_past_function_end() {
        assert!(matches!(
            JumpTarget::try_new(4, 3),
            Err(VmError::JumpTargetOutOfBounds {
                target: 4,
                instruction_count: 3
            })
        ));
    }

    #[test]
    fn lowering_rejects_resolved_jump_target_past_function_end() {
        let function = VMFunction::new(
            "bad_jump".to_owned(),
            vec![],
            vec![],
            None,
            1,
            vec![Instruction::RET(0)],
            HashMap::new(),
        );

        let error = lower_instruction(&function, &ResolvedInstruction::JMP(2)).unwrap_err();
        assert!(matches!(
            error,
            VmError::JumpTargetOutOfBounds {
                target: 2,
                instruction_count: 1
            }
        ));
    }
}
