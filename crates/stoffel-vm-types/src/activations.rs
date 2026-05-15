//! # Activation Records for StoffelVM
//!
//! This module defines the activation record system for the StoffelVM.
//! Activation records represent function call frames and contain all the state
//! needed for function execution, including:
//!
//! - Local variables and registers
//! - Upvalues (captured variables)
//! - Argument stack
//! - Instruction pointer

use crate::core_types::{Closure, Upvalue, Value};
use crate::registers::{RegisterFile, RegisterIndex, RegisterLayout, RegisterSlot};
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use std::cmp::Ordering;
use std::fmt;
use std::sync::Arc;

pub type ActivationResult<T> = Result<T, ActivationError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivationError {
    FunctionArityMismatch {
        function: String,
        expected: usize,
        actual: usize,
    },
    RegisterOutOfBounds {
        register: usize,
        register_count: usize,
    },
    InstructionPointerOverflow {
        function: String,
        instruction_pointer: usize,
    },
}

impl fmt::Display for ActivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActivationError::FunctionArityMismatch {
                function,
                expected,
                actual,
            } => write!(
                f,
                "Function {function} expects {expected} arguments but got {actual}"
            ),
            ActivationError::RegisterOutOfBounds {
                register,
                register_count,
            } => write!(
                f,
                "Register r{register} out of bounds for frame with {register_count} registers"
            ),
            ActivationError::InstructionPointerOverflow {
                function,
                instruction_pointer,
            } => write!(
                f,
                "Function {function} instruction pointer {instruction_pointer} cannot advance"
            ),
        }
    }
}

impl std::error::Error for ActivationError {}

impl From<ActivationError> for String {
    fn from(error: ActivationError) -> Self {
        error.to_string()
    }
}

/// Result of the most recent VM `CMP` instruction.
///
/// The bytecode branches on the last comparison result, but the runtime should
/// not pass that state around as magic `-1`, `0`, and `1` integers. This type
/// keeps branch semantics explicit while still exposing the legacy integer form
/// for hook/debug consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CompareFlag {
    Less,
    #[default]
    Equal,
    Greater,
}

impl CompareFlag {
    pub const fn from_ordering(ordering: Ordering) -> Self {
        match ordering {
            Ordering::Less => Self::Less,
            Ordering::Equal => Self::Equal,
            Ordering::Greater => Self::Greater,
        }
    }

    pub const fn as_ordering(self) -> Ordering {
        match self {
            Self::Less => Ordering::Less,
            Self::Equal => Ordering::Equal,
            Self::Greater => Ordering::Greater,
        }
    }

    pub const fn as_i32(self) -> i32 {
        match self {
            Self::Less => -1,
            Self::Equal => 0,
            Self::Greater => 1,
        }
    }

    pub const fn is_equal(self) -> bool {
        matches!(self, Self::Equal)
    }

    pub const fn is_not_equal(self) -> bool {
        !self.is_equal()
    }

    pub const fn is_less(self) -> bool {
        matches!(self, Self::Less)
    }

    pub const fn is_greater(self) -> bool {
        matches!(self, Self::Greater)
    }
}

impl From<Ordering> for CompareFlag {
    fn from(ordering: Ordering) -> Self {
        Self::from_ordering(ordering)
    }
}

impl From<CompareFlag> for Ordering {
    fn from(flag: CompareFlag) -> Self {
        flag.as_ordering()
    }
}

impl fmt::Display for CompareFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_i32())
    }
}

/// Instruction pointer for an activation frame.
///
/// The VM treats instruction positions as executable control-flow state, not as
/// arbitrary collection indices. Keeping this state typed at the frame boundary
/// makes jumps, fetches, and hook cursors convert explicitly when they need the
/// raw index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct InstructionPointer(usize);

impl InstructionPointer {
    pub const fn new(index: usize) -> Self {
        Self(index)
    }

    pub const fn index(self) -> usize {
        self.0
    }

    pub fn previous(self) -> Option<Self> {
        self.0.checked_sub(1).map(Self)
    }

    fn try_advance(self, function: &str) -> ActivationResult<Self> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| ActivationError::InstructionPointerOverflow {
                function: function.to_owned(),
                instruction_pointer: self.0,
            })
    }
}

impl fmt::Display for InstructionPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Stack of active VM call frames.
///
/// Keeping frame-stack operations behind this type avoids scattering raw
/// collection manipulation through the runtime. That matters for the VM because
/// call-frame depth is part of execution control, unwind cleanup, hook snapshots,
/// and foreign-function reentry.
#[derive(Clone, Default)]
pub struct ActivationStack {
    records: SmallVec<[ActivationRecord; 8]>,
}

impl ActivationStack {
    pub fn new() -> Self {
        Self {
            records: SmallVec::new(),
        }
    }

    pub fn push(&mut self, record: ActivationRecord) {
        self.records.push(record);
    }

    pub fn pop(&mut self) -> Option<ActivationRecord> {
        self.records.pop()
    }

    pub fn current(&self) -> Option<&ActivationRecord> {
        self.records.last()
    }

    pub fn current_mut(&mut self) -> Option<&mut ActivationRecord> {
        self.records.last_mut()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn truncate(&mut self, depth: usize) {
        self.records.truncate(depth);
    }

    pub fn as_slice(&self) -> &[ActivationRecord] {
        &self.records
    }

    pub fn iter(&self) -> std::slice::Iter<'_, ActivationRecord> {
        self.records.iter()
    }

    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, ActivationRecord> {
        self.records.iter_mut()
    }
}

impl AsRef<[ActivationRecord]> for ActivationStack {
    fn as_ref(&self) -> &[ActivationRecord] {
        self.as_slice()
    }
}

impl fmt::Debug for ActivationStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.records.iter()).finish()
    }
}

/// Activation record for function calls
///
/// An activation record represents a function call frame and contains all the state
/// needed for function execution. It is created when a function is called and
/// remains active until the function returns.
///
/// The VM maintains a stack of activation records, with the top record representing
/// the currently executing function. When a function calls another function, a new
/// activation record is pushed onto the stack.
#[derive(Clone)]
pub struct ActivationRecord {
    /// Name of the function being executed
    function_name: String,
    /// Local variables by name
    locals: FxHashMap<String, Value>,
    /// Register values (optimized for small functions)
    registers: RegisterFile,
    /// Captured variables from outer scopes
    upvalues: Vec<Upvalue>,
    /// Argument stack for function calls
    stack: SmallVec<[Value; 8]>,
    /// Comparison flag for conditional jumps
    compare_flag: CompareFlag,
    /// Current instruction pointer
    instruction_pointer: InstructionPointer,
    /// Original closure for upvalue updates
    closure: Option<Arc<Closure>>,
}

impl ActivationRecord {
    /// Create an empty call frame for a VM function.
    pub fn for_function(
        function_name: impl Into<String>,
        layout: RegisterLayout,
        register_count: usize,
        upvalues: Vec<Upvalue>,
        closure: Option<Arc<Closure>>,
    ) -> Self {
        ActivationRecord {
            function_name: function_name.into(),
            locals: FxHashMap::default(),
            registers: RegisterFile::new(layout, register_count),
            upvalues,
            stack: SmallVec::new(),
            compare_flag: CompareFlag::default(),
            instruction_pointer: InstructionPointer::default(),
            closure,
        }
    }

    /// Create a frame around an existing register file.
    pub fn with_registers(
        function_name: impl Into<String>,
        registers: RegisterFile,
        upvalues: Vec<Upvalue>,
        closure: Option<Arc<Closure>>,
    ) -> Self {
        ActivationRecord {
            function_name: function_name.into(),
            locals: FxHashMap::default(),
            registers,
            upvalues,
            stack: SmallVec::new(),
            compare_flag: CompareFlag::default(),
            instruction_pointer: InstructionPointer::default(),
            closure,
        }
    }

    /// Bind function parameters to ABI registers and local names.
    pub fn bind_parameters(
        &mut self,
        parameters: &[String],
        args: &[Value],
    ) -> ActivationResult<()> {
        if parameters.len() != args.len() {
            return Err(ActivationError::FunctionArityMismatch {
                function: self.function_name.clone(),
                expected: parameters.len(),
                actual: args.len(),
            });
        }

        if parameters.len() > self.registers.len() {
            return Err(ActivationError::RegisterOutOfBounds {
                register: self.registers.len(),
                register_count: self.registers.len(),
            });
        }

        for ((name, value), slot) in parameters
            .iter()
            .zip(args.iter())
            .zip(self.registers.iter_mut())
        {
            *slot = value.clone();
            self.locals.insert(name.clone(), value.clone());
        }

        Ok(())
    }

    pub fn function_name(&self) -> &str {
        &self.function_name
    }

    pub fn local(&self, name: &str) -> Option<&Value> {
        self.locals.get(name)
    }

    pub fn registers(&self) -> &RegisterFile {
        &self.registers
    }

    pub fn register_layout(&self) -> RegisterLayout {
        self.registers.layout()
    }

    pub fn register_count(&self) -> usize {
        self.registers.len()
    }

    pub fn register(&self, index: RegisterIndex) -> Option<&Value> {
        self.registers.get(index)
    }

    pub fn register_mut(&mut self, index: RegisterIndex) -> Option<&mut Value> {
        self.registers.get_mut(index)
    }

    pub fn register_slot(&self, index: RegisterIndex) -> Option<&RegisterSlot> {
        self.registers.get_slot(index)
    }

    pub fn register_exists(&self, index: RegisterIndex) -> bool {
        self.registers.contains(index)
    }

    pub fn replace_register_value(
        &mut self,
        index: RegisterIndex,
        value: Value,
    ) -> Option<RegisterSlot> {
        self.registers.replace_value(index, value)
    }

    pub fn set_register_pending_reveal(&mut self, index: RegisterIndex) -> Option<RegisterSlot> {
        self.registers.set_pending_reveal(index)
    }

    pub fn iter_registers_mut(&mut self) -> impl Iterator<Item = &mut Value> + '_ {
        self.registers.iter_mut()
    }

    pub fn upvalues(&self) -> &[Upvalue] {
        &self.upvalues
    }

    pub fn upvalue_mut(&mut self, name: &str) -> Option<&mut Upvalue> {
        self.upvalues
            .iter_mut()
            .rev()
            .find(|upvalue| upvalue.name() == name)
    }

    pub fn stack(&self) -> &[Value] {
        &self.stack
    }

    pub fn stack_len(&self) -> usize {
        self.stack.len()
    }

    pub fn stack_value(&self, index: usize) -> Option<&Value> {
        self.stack.get(index)
    }

    pub fn push_stack(&mut self, value: Value) {
        self.stack.push(value);
    }

    pub fn pop_stack(&mut self) -> Option<Value> {
        self.stack.pop()
    }

    pub fn clear_stack(&mut self) {
        self.stack.clear();
    }

    pub fn take_stack(&mut self) -> SmallVec<[Value; 8]> {
        std::mem::take(&mut self.stack)
    }

    pub fn replace_stack(&mut self, stack: SmallVec<[Value; 8]>) -> SmallVec<[Value; 8]> {
        std::mem::replace(&mut self.stack, stack)
    }

    pub fn compare_flag(&self) -> CompareFlag {
        self.compare_flag
    }

    pub fn compare_flag_i32(&self) -> i32 {
        self.compare_flag.as_i32()
    }

    pub fn set_compare_flag(&mut self, compare_flag: CompareFlag) {
        self.compare_flag = compare_flag;
    }

    pub fn instruction_pointer(&self) -> InstructionPointer {
        self.instruction_pointer
    }

    pub fn try_advance_instruction_pointer(&mut self) -> ActivationResult<()> {
        self.instruction_pointer = self.instruction_pointer.try_advance(&self.function_name)?;
        Ok(())
    }

    #[track_caller]
    pub fn advance_instruction_pointer(&mut self) {
        self.try_advance_instruction_pointer()
            .expect("instruction pointer overflow")
    }

    pub fn set_instruction_pointer(&mut self, instruction_pointer: InstructionPointer) {
        self.instruction_pointer = instruction_pointer;
    }

    pub fn closure(&self) -> Option<&Arc<Closure>> {
        self.closure.as_ref()
    }

    pub fn set_closure(&mut self, closure: Option<Arc<Closure>>) {
        self.closure = closure;
    }
}

impl fmt::Debug for ActivationRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ActivationRecord {{ function: {}, ip: {}, registers: {:?}, locals: {:?}, upvalues: {:?}, stack: {:?}, compare_flag: {} }}",
            self.function_name,
            self.instruction_pointer.index(),
            self.registers,
            self.locals,
            self.upvalues,
            self.stack,
            self.compare_flag
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn r(index: usize) -> RegisterIndex {
        RegisterIndex::new(index)
    }

    fn frame(name: &str) -> ActivationRecord {
        ActivationRecord::for_function(name, RegisterLayout::default(), 1, Vec::new(), None)
    }

    #[test]
    fn activation_stack_encapsulates_frame_lifecycle() {
        let mut stack = ActivationStack::new();
        assert!(stack.is_empty());
        assert!(stack.current().is_none());

        stack.push(frame("entry"));
        stack.push(frame("callee"));

        assert_eq!(stack.len(), 2);
        assert_eq!(stack.as_slice().len(), 2);
        assert_eq!(stack.current().unwrap().function_name(), "callee");

        stack.truncate(1);
        assert_eq!(stack.len(), 1);
        assert_eq!(stack.current().unwrap().function_name(), "entry");

        let popped = stack.pop().expect("entry frame");
        assert_eq!(popped.function_name(), "entry");
        assert!(stack.is_empty());
    }

    #[test]
    fn bind_parameters_reports_typed_arity_error() {
        let mut frame =
            ActivationRecord::for_function("main", RegisterLayout::default(), 2, Vec::new(), None);

        let err = frame
            .bind_parameters(&["x".to_string(), "y".to_string()], &[Value::I64(1)])
            .unwrap_err();

        assert_eq!(
            err,
            ActivationError::FunctionArityMismatch {
                function: "main".to_string(),
                expected: 2,
                actual: 1
            }
        );
        assert_eq!(
            err.to_string(),
            "Function main expects 2 arguments but got 1"
        );
    }

    #[test]
    fn bind_parameters_reports_typed_register_bounds_error() {
        let mut frame =
            ActivationRecord::for_function("main", RegisterLayout::default(), 1, Vec::new(), None);

        let err = frame
            .bind_parameters(
                &["x".to_string(), "y".to_string()],
                &[Value::I64(1), Value::I64(2)],
            )
            .unwrap_err();

        assert_eq!(
            err,
            ActivationError::RegisterOutOfBounds {
                register: 1,
                register_count: 1
            }
        );
        assert_eq!(
            err.to_string(),
            "Register r1 out of bounds for frame with 1 registers"
        );
    }

    #[test]
    fn bind_parameters_does_not_partially_mutate_on_bounds_error() {
        let mut frame =
            ActivationRecord::for_function("main", RegisterLayout::default(), 1, Vec::new(), None);
        *frame.register_mut(r(0)).expect("register r0") = Value::I64(99);

        let err = frame
            .bind_parameters(
                &["x".to_string(), "y".to_string()],
                &[Value::I64(1), Value::I64(2)],
            )
            .unwrap_err();

        assert_eq!(
            err,
            ActivationError::RegisterOutOfBounds {
                register: 1,
                register_count: 1
            }
        );
        assert_eq!(frame.register(r(0)), Some(&Value::I64(99)));
        assert_eq!(frame.local("x"), None);
        assert_eq!(frame.local("y"), None);
    }

    #[test]
    fn bind_parameters_writes_registers_and_locals() {
        let mut frame =
            ActivationRecord::for_function("main", RegisterLayout::default(), 2, Vec::new(), None);

        frame
            .bind_parameters(
                &["x".to_string(), "y".to_string()],
                &[Value::I64(1), Value::I64(2)],
            )
            .expect("valid parameter binding");

        assert_eq!(frame.register(r(0)), Some(&Value::I64(1)));
        assert_eq!(frame.register(r(1)), Some(&Value::I64(2)));
        assert_eq!(frame.local("x"), Some(&Value::I64(1)));
        assert_eq!(frame.local("y"), Some(&Value::I64(2)));
    }

    #[test]
    fn activation_record_tracks_closure_as_typed_handle() {
        let closure = Arc::new(Closure::new("callee", Vec::new()));
        let mut frame = ActivationRecord::for_function(
            "main",
            RegisterLayout::default(),
            1,
            Vec::new(),
            Some(Arc::clone(&closure)),
        );

        assert!(
            frame
                .closure()
                .is_some_and(|stored| Arc::ptr_eq(stored, &closure))
        );

        let replacement = Arc::new(Closure::new("replacement", Vec::new()));
        frame.set_closure(Some(Arc::clone(&replacement)));

        assert!(
            frame
                .closure()
                .is_some_and(|stored| Arc::ptr_eq(stored, &replacement))
        );
    }

    #[test]
    fn take_stack_moves_values_and_clears_frame_stack() {
        let mut frame =
            ActivationRecord::for_function("main", RegisterLayout::default(), 1, Vec::new(), None);
        frame.push_stack(Value::I64(1));
        frame.push_stack(Value::I64(2));

        let values = frame.take_stack();

        assert_eq!(values.as_slice(), &[Value::I64(1), Value::I64(2)]);
        assert!(frame.stack().is_empty());
    }

    #[test]
    fn replace_stack_swaps_frame_stack_transactionally() {
        let mut frame =
            ActivationRecord::for_function("main", RegisterLayout::default(), 1, Vec::new(), None);
        frame.push_stack(Value::I64(1));

        let previous = frame.replace_stack(SmallVec::from_vec(vec![Value::I64(2), Value::I64(3)]));

        assert_eq!(previous.as_slice(), &[Value::I64(1)]);
        assert_eq!(frame.stack(), &[Value::I64(2), Value::I64(3)]);
    }

    #[test]
    fn instruction_pointer_advancement_reports_overflow() {
        let mut frame =
            ActivationRecord::for_function("main", RegisterLayout::default(), 1, Vec::new(), None);
        frame.set_instruction_pointer(InstructionPointer::new(usize::MAX));

        let err = frame.try_advance_instruction_pointer().unwrap_err();

        assert_eq!(
            err,
            ActivationError::InstructionPointerOverflow {
                function: "main".to_string(),
                instruction_pointer: usize::MAX,
            }
        );
        assert_eq!(frame.instruction_pointer().index(), usize::MAX);
        assert_eq!(
            err.to_string(),
            format!(
                "Function main instruction pointer {} cannot advance",
                usize::MAX
            )
        );
    }

    #[test]
    fn instruction_pointer_previous_is_explicit_control_flow_state() {
        assert_eq!(InstructionPointer::new(3).previous().unwrap().index(), 2);
        assert_eq!(InstructionPointer::new(0).previous(), None);
    }

    #[test]
    fn compare_flag_preserves_branch_semantics_without_magic_numbers() {
        assert_eq!(CompareFlag::from(Ordering::Less).as_i32(), -1);
        assert_eq!(CompareFlag::from(Ordering::Equal).as_i32(), 0);
        assert_eq!(CompareFlag::from(Ordering::Greater).as_i32(), 1);

        assert!(CompareFlag::Less.is_less());
        assert!(CompareFlag::Equal.is_equal());
        assert!(CompareFlag::Greater.is_greater());
        assert!(CompareFlag::Less.is_not_equal());
    }
}
