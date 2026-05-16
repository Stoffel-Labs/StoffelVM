use crate::program::Program;
use std::{cmp::Ordering, fmt, sync::Arc};
use stoffel_vm_types::activations::{ActivationRecord, CompareFlag, InstructionPointer};
use stoffel_vm_types::core_types::{ArrayRef, ObjectRef, Upvalue, Value};
use stoffel_vm_types::instructions::Instruction;
use stoffel_vm_types::registers::{
    RegisterAddress, RegisterBank, RegisterIndex, RegisterLayout, RegisterSlot,
};

pub type HookResult<T> = Result<T, HookError>;
pub type HookCallbackResult<T = ()> = Result<T, HookCallbackError>;

/// Register identity exposed to hook callbacks.
///
/// Bytecode still addresses registers by absolute frame index, while the VM
/// stores values in clear and secret banks. This type keeps both views together
/// so hook consumers can reason about MPC register-bank boundaries without
/// reimplementing layout logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HookRegister {
    index: usize,
    address: RegisterAddress,
}

impl HookRegister {
    pub const fn new(index: usize, layout: RegisterLayout) -> Self {
        Self {
            index,
            address: layout.address(RegisterIndex::new(index)),
        }
    }

    /// Absolute bytecode register index.
    pub const fn index(self) -> usize {
        self.index
    }

    /// Absolute bytecode register index.
    pub const fn absolute_index(self) -> usize {
        self.index()
    }

    /// Bank-local register address.
    pub const fn address(self) -> RegisterAddress {
        self.address
    }

    pub const fn bank(self) -> RegisterBank {
        self.address.bank()
    }

    pub const fn bank_index(self) -> usize {
        self.address.index()
    }

    pub const fn is_clear(self) -> bool {
        matches!(self.bank(), RegisterBank::Clear)
    }

    pub const fn is_secret(self) -> bool {
        matches!(self.bank(), RegisterBank::Secret)
    }

    pub fn matches_layout(self, layout: RegisterLayout) -> bool {
        self.address == layout.address(RegisterIndex::new(self.index))
    }
}

impl fmt::Display for HookRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.index.fmt(f)
    }
}

/// Stable typed handle returned by VM hook registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HookId(usize);

impl HookId {
    pub const fn new(id: usize) -> Self {
        Self(id)
    }

    pub const fn id(self) -> usize {
        self.0
    }
}

impl fmt::Display for HookId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HookCallbackError {
    #[error("{0}")]
    Message(String),
}

impl From<String> for HookCallbackError {
    fn from(message: String) -> Self {
        Self::Message(message)
    }
}

impl From<&str> for HookCallbackError {
    fn from(message: &str) -> Self {
        Self::Message(message.to_owned())
    }
}

impl From<HookCallbackError> for String {
    fn from(error: HookCallbackError) -> Self {
        error.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HookError {
    #[error("Hook ID allocator overflowed")]
    AllocatorOverflow,
    #[error("Hook {hook_id} callback failed: {source}")]
    CallbackFailed {
        hook_id: HookId,
        #[source]
        source: HookCallbackError,
    },
}

impl From<HookError> for String {
    fn from(error: HookError) -> Self {
        error.to_string()
    }
}

/// Previous state of a register observed by a register-write hook.
///
/// Register writes can replace a queued reveal placeholder before the reveal is
/// flushed. Hook consumers need to see that state explicitly instead of having
/// the VM report it as a concrete `Unit` value.
#[derive(Clone, PartialEq)]
pub enum RegisterWritePreviousValue {
    Ready(Value),
    PendingReveal,
}

impl RegisterWritePreviousValue {
    pub fn ready(value: Value) -> Self {
        Self::Ready(value)
    }

    pub const fn pending_reveal() -> Self {
        Self::PendingReveal
    }

    pub fn as_value(&self) -> Option<&Value> {
        match self {
            Self::Ready(value) => Some(value),
            Self::PendingReveal => None,
        }
    }

    pub fn into_value(self) -> Option<Value> {
        match self {
            Self::Ready(value) => Some(value),
            Self::PendingReveal => None,
        }
    }

    pub const fn is_pending_reveal(&self) -> bool {
        matches!(self, Self::PendingReveal)
    }
}

impl From<Value> for RegisterWritePreviousValue {
    fn from(value: Value) -> Self {
        Self::Ready(value)
    }
}

impl From<RegisterSlot> for RegisterWritePreviousValue {
    fn from(slot: RegisterSlot) -> Self {
        match slot {
            RegisterSlot::Ready(value) => Self::Ready(value),
            RegisterSlot::PendingReveal => Self::PendingReveal,
        }
    }
}

impl fmt::Debug for RegisterWritePreviousValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready(value) => fmt::Debug::fmt(value, f),
            Self::PendingReveal => f.write_str("<pending reveal>"),
        }
    }
}

/// Function-like call target exposed to hook callbacks.
///
/// Calls are not VM values: bytecode functions, closures, and foreign callbacks
/// have different runtime behavior and different extension points. Keeping the
/// target typed lets debugging and tracing code distinguish those cases without
/// parsing display strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HookCallTarget {
    VmFunction { name: String },
    Closure { function: String },
    ForeignFunction { name: String },
}

impl HookCallTarget {
    pub fn vm_function(name: impl Into<String>) -> Self {
        Self::VmFunction { name: name.into() }
    }

    pub fn closure(function: impl Into<String>) -> Self {
        Self::Closure {
            function: function.into(),
        }
    }

    pub fn foreign_function(name: impl Into<String>) -> Self {
        Self::ForeignFunction { name: name.into() }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::VmFunction { name } | Self::ForeignFunction { name } => name,
            Self::Closure { function } => function,
        }
    }

    pub const fn is_vm_function(&self) -> bool {
        matches!(self, Self::VmFunction { .. })
    }

    pub const fn is_closure(&self) -> bool {
        matches!(self, Self::Closure { .. })
    }

    pub const fn is_foreign_function(&self) -> bool {
        matches!(self, Self::ForeignFunction { .. })
    }

    pub fn display_label(&self) -> String {
        match self {
            Self::VmFunction { name } | Self::Closure { function: name } => {
                format!("<function {name}>")
            }
            Self::ForeignFunction { name } => format!("<foreign function {name}>"),
        }
    }
}

impl fmt::Display for HookCallTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display_label())
    }
}

/// Hook event types
#[derive(Debug, Clone)]
pub enum HookEvent {
    BeforeInstructionExecute(Instruction),
    AfterInstructionExecute(Instruction),
    RegisterRead(HookRegister, Value),
    RegisterWrite(HookRegister, RegisterWritePreviousValue, Value),
    VariableRead(String, Value),
    VariableWrite(String, Value, Value),
    UpvalueRead(String, Value),
    UpvalueWrite(String, Value, Value),
    ObjectFieldRead(ObjectRef, Value, Value),
    ObjectFieldWrite(ObjectRef, Value, Value, Value),
    ArrayElementRead(ArrayRef, Value, Value),
    ArrayElementWrite(ArrayRef, Value, Value, Value),
    BeforeFunctionCall(HookCallTarget, Vec<Value>),
    AfterFunctionCall(HookCallTarget, Value),
    ClosureCreated(String, Vec<Upvalue>),
    StackPush(Value),
    StackPop(Value),
}

/// Instruction position associated with the hook snapshot.
///
/// Older hook APIs exposed only an instruction index, which made nested calls
/// ambiguous because the active frame and the saved instruction index could
/// refer to different functions. This cursor keeps the function and instruction
/// pointer together so hook consumers can reason about call boundaries without
/// depending on VM internals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionCursor {
    function_name: Arc<str>,
    instruction_pointer: InstructionPointer,
}

impl InstructionCursor {
    pub(crate) fn new(
        function_name: impl Into<Arc<str>>,
        instruction_pointer: InstructionPointer,
    ) -> Self {
        Self {
            function_name: function_name.into(),
            instruction_pointer,
        }
    }

    pub fn function_name(&self) -> &str {
        self.function_name.as_ref()
    }

    pub fn instruction_pointer(&self) -> InstructionPointer {
        self.instruction_pointer
    }

    pub fn instruction_index(&self) -> usize {
        self.instruction_pointer.index()
    }
}

/// Read-only view of a VM call frame exposed to hook callbacks.
///
/// Hook callbacks should depend on this stable inspection API rather than the
/// VM's concrete activation-record representation. That keeps frame storage and
/// register-bank internals free to evolve independently of the public hook API.
#[derive(Clone, Copy)]
pub struct HookFrame<'a> {
    record: &'a ActivationRecord,
}

impl<'a> HookFrame<'a> {
    fn new(record: &'a ActivationRecord) -> Self {
        Self { record }
    }

    pub fn function_name(&self) -> &'a str {
        self.record.function_name()
    }

    pub fn register_layout(&self) -> RegisterLayout {
        self.record.register_layout()
    }

    pub fn register_count(&self) -> usize {
        self.record.register_count()
    }

    pub fn hook_register(&self, reg_idx: usize) -> Option<HookRegister> {
        self.record
            .register_exists(RegisterIndex::new(reg_idx))
            .then(|| HookRegister::new(reg_idx, self.register_layout()))
    }

    pub fn contains_hook_register(&self, register: HookRegister) -> bool {
        self.record
            .register_exists(RegisterIndex::new(register.index()))
            && register.matches_layout(self.register_layout())
    }

    pub fn register_value(&self, register: HookRegister) -> Option<&'a Value> {
        self.contains_hook_register(register)
            .then(|| self.record.register(RegisterIndex::new(register.index())))
            .flatten()
    }

    pub fn register_value_for(&self, register: HookRegister) -> Option<&'a Value> {
        self.register_value(register)
    }

    pub fn get_register_value(&self, register: HookRegister) -> Option<Value> {
        self.register_value(register).cloned()
    }

    pub fn get_register_value_for(&self, register: HookRegister) -> Option<Value> {
        self.get_register_value(register)
    }

    pub fn register_slot(&self, register: HookRegister) -> Option<&'a RegisterSlot> {
        self.contains_hook_register(register)
            .then(|| {
                self.record
                    .register_slot(RegisterIndex::new(register.index()))
            })
            .flatten()
    }

    pub fn register_slot_for(&self, register: HookRegister) -> Option<&'a RegisterSlot> {
        self.register_slot(register)
    }

    pub fn get_register_slot(&self, register: HookRegister) -> Option<RegisterSlot> {
        self.register_slot(register).cloned()
    }

    pub fn get_register_slot_for(&self, register: HookRegister) -> Option<RegisterSlot> {
        self.get_register_slot(register)
    }

    pub fn local_value(&self, name: &str) -> Option<&'a Value> {
        self.record.local(name)
    }

    pub fn upvalue_value(&self, name: &str) -> Option<&'a Value> {
        self.record
            .upvalues()
            .iter()
            .rev()
            .find(|upvalue| upvalue.name() == name)
            .map(Upvalue::value)
    }

    pub fn stack_len(&self) -> usize {
        self.record.stack_len()
    }

    pub fn stack_value(&self, index: usize) -> Option<&'a Value> {
        self.record.stack_value(index)
    }

    pub fn compare_flag_i32(&self) -> i32 {
        self.record.compare_flag_i32()
    }

    pub fn compare_flag(&self) -> CompareFlag {
        self.record.compare_flag()
    }

    pub fn compare_ordering(&self) -> Ordering {
        self.compare_flag().as_ordering()
    }
}

// A simplified context that doesn't require borrowing the entire VMState
pub struct HookContext<'a> {
    activation_records: &'a [ActivationRecord],
    current_instruction: Option<InstructionCursor>,
    program: &'a Program,
}

impl<'a> HookContext<'a> {
    pub(crate) fn new(
        activation_records: &'a [ActivationRecord],
        current_instruction: Option<InstructionCursor>,
        program: &'a Program,
    ) -> Self {
        HookContext {
            activation_records,
            current_instruction,
            program,
        }
    }

    /// Current frame, if execution is inside a VM function.
    pub fn current_frame(&self) -> Option<HookFrame<'_>> {
        self.activation_records.last().map(HookFrame::new)
    }

    /// Read-only views of all active frames from oldest to newest.
    pub fn frames(
        &self,
    ) -> impl DoubleEndedIterator<Item = HookFrame<'_>> + ExactSizeIterator + '_ {
        self.activation_records.iter().map(HookFrame::new)
    }

    pub fn get_compare_flag(&self) -> Option<i32> {
        self.current_frame().map(|frame| frame.compare_flag_i32())
    }

    pub fn get_typed_compare_flag(&self) -> Option<CompareFlag> {
        self.current_frame().map(|frame| frame.compare_flag())
    }

    pub fn get_compare_ordering(&self) -> Option<Ordering> {
        self.current_frame().map(|frame| frame.compare_ordering())
    }

    pub fn hook_register(&self, reg_idx: usize) -> Option<HookRegister> {
        self.current_frame()
            .and_then(|frame| frame.hook_register(reg_idx))
    }

    pub fn contains_hook_register(&self, register: HookRegister) -> bool {
        self.current_frame()
            .is_some_and(|frame| frame.contains_hook_register(register))
    }

    pub fn register_value(&self, register: HookRegister) -> Option<&Value> {
        self.current_frame()
            .and_then(|frame| frame.register_value(register))
    }

    pub fn register_value_for(&self, register: HookRegister) -> Option<&Value> {
        self.register_value(register)
    }

    pub fn get_register_value(&self, register: HookRegister) -> Option<Value> {
        self.register_value(register).cloned()
    }

    pub fn get_register_value_for(&self, register: HookRegister) -> Option<Value> {
        self.get_register_value(register)
    }

    pub fn register_slot(&self, register: HookRegister) -> Option<&RegisterSlot> {
        self.current_frame()
            .and_then(|frame| frame.register_slot(register))
    }

    pub fn register_slot_for(&self, register: HookRegister) -> Option<&RegisterSlot> {
        self.register_slot(register)
    }

    pub fn get_register_slot(&self, register: HookRegister) -> Option<RegisterSlot> {
        self.register_slot(register).cloned()
    }

    pub fn get_register_slot_for(&self, register: HookRegister) -> Option<RegisterSlot> {
        self.get_register_slot(register)
    }

    pub fn current_instruction_cursor(&self) -> Option<&InstructionCursor> {
        self.current_instruction.as_ref()
    }

    pub fn current_instruction_pointer(&self) -> Option<InstructionPointer> {
        self.current_instruction
            .as_ref()
            .map(InstructionCursor::instruction_pointer)
    }

    pub fn current_instruction_function_name(&self) -> Option<&str> {
        self.current_instruction
            .as_ref()
            .map(InstructionCursor::function_name)
    }

    pub fn current_instruction_index_opt(&self) -> Option<usize> {
        self.current_instruction
            .as_ref()
            .map(InstructionCursor::instruction_index)
    }

    pub fn current_instruction_index(&self) -> usize {
        self.current_instruction_index_opt().unwrap_or_default()
    }

    pub fn get_current_instruction(&self) -> usize {
        self.current_instruction_index()
    }

    pub fn current_function_name(&self) -> Option<&str> {
        self.current_frame().map(|frame| frame.function_name())
    }

    pub fn get_function_name(&self) -> Option<String> {
        self.current_function_name().map(ToOwned::to_owned)
    }

    pub fn call_depth(&self) -> usize {
        self.activation_records.len()
    }

    pub fn get_call_depth(&self) -> usize {
        self.call_depth()
    }

    pub fn instruction_at_pointer(
        &self,
        function_name: &str,
        instruction_pointer: InstructionPointer,
    ) -> Option<&Instruction> {
        self.program
            .instruction_at(function_name, instruction_pointer)
    }

    pub fn get_instruction_at_pointer(
        &self,
        function_name: &str,
        instruction_pointer: InstructionPointer,
    ) -> Option<Instruction> {
        self.instruction_at_pointer(function_name, instruction_pointer)
            .cloned()
    }

    pub fn instruction_at(&self, function_name: &str, index: usize) -> Option<&Instruction> {
        self.instruction_at_pointer(function_name, InstructionPointer::new(index))
    }

    pub fn get_instruction_at(&self, function_name: &str, index: usize) -> Option<Instruction> {
        self.instruction_at(function_name, index).cloned()
    }
}

/// Hook predicate that determines if a hook should fire
pub type HookPredicate = dyn Fn(&HookEvent) -> bool + Send + Sync;

/// Hook callback that executes when a hook is triggered
pub type HookCallback = dyn Fn(&HookEvent, &HookContext) -> HookCallbackResult + Send + Sync;

/// A hook registered with the VM
pub struct Hook {
    id: HookId,
    predicate: Box<HookPredicate>,
    callback: Box<HookCallback>,
    enabled: bool,
    priority: i32,
}

/// Hook manager to handle hook registration and triggering
pub struct HookManager {
    hooks: Vec<Hook>,
    enabled_hooks: usize,
    next_hook_id: usize,
}

impl Default for HookManager {
    fn default() -> Self {
        Self::new()
    }
}

impl HookManager {
    pub fn new() -> Self {
        HookManager {
            hooks: Vec::new(),
            enabled_hooks: 0,
            next_hook_id: 1,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }

    pub fn has_enabled_hooks(&self) -> bool {
        self.enabled_hooks != 0
    }

    pub fn try_register_hook(
        &mut self,
        predicate: Box<HookPredicate>,
        callback: Box<HookCallback>,
        priority: i32,
    ) -> HookResult<HookId> {
        let id = self.next_hook_id;
        self.next_hook_id = self
            .next_hook_id
            .checked_add(1)
            .ok_or(HookError::AllocatorOverflow)?;
        let hook_id = HookId::new(id);

        self.hooks.push(Hook {
            id: hook_id,
            predicate,
            callback,
            enabled: true,
            priority,
        });
        self.enabled_hooks += 1;

        self.hooks
            .sort_by_key(|hook| std::cmp::Reverse(hook.priority));

        Ok(hook_id)
    }

    #[track_caller]
    pub fn register_hook(
        &mut self,
        predicate: Box<HookPredicate>,
        callback: Box<HookCallback>,
        priority: i32,
    ) -> HookId {
        self.try_register_hook(predicate, callback, priority)
            .expect("hook registration failed")
    }

    pub fn unregister_hook(&mut self, hook_id: HookId) -> bool {
        let Some(index) = self.hooks.iter().position(|hook| hook.id == hook_id) else {
            return false;
        };

        let hook = self.hooks.remove(index);
        if hook.enabled {
            self.enabled_hooks -= 1;
        }
        true
    }

    pub fn enable_hook(&mut self, hook_id: HookId) -> bool {
        if let Some(hook) = self.hooks.iter_mut().find(|h| h.id == hook_id) {
            if !hook.enabled {
                self.enabled_hooks += 1;
            }
            hook.enabled = true;
            return true;
        }
        false
    }

    pub fn disable_hook(&mut self, hook_id: HookId) -> bool {
        if let Some(hook) = self.hooks.iter_mut().find(|h| h.id == hook_id) {
            if hook.enabled {
                self.enabled_hooks -= 1;
            }
            hook.enabled = false;
            return true;
        }
        false
    }

    pub fn trigger_with_context(&self, event: &HookEvent, context: &HookContext) -> HookResult<()> {
        // Fast path: if no enabled hooks are registered, return immediately.
        if !self.has_enabled_hooks() {
            return Ok(());
        }

        for hook in self
            .hooks
            .iter()
            .filter(|hook| hook.enabled && (hook.predicate)(event))
        {
            (hook.callback)(event, context).map_err(|source| HookError::CallbackFailed {
                hook_id: hook.id,
                source,
            })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foreign_functions::Function;
    use crate::program::Program;
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::sync::Arc;
    use stoffel_vm_types::functions::VMFunction;
    use stoffel_vm_types::registers::RegisterFile;

    #[test]
    fn hook_context_exposes_borrowed_frame_view() {
        let records = vec![ActivationRecord::with_registers(
            "main",
            RegisterFile::from(vec![Value::I64(7)]),
            Vec::new(),
            None,
        )];
        let program = Program::new();
        let context = HookContext::new(
            &records,
            Some(InstructionCursor::new("main", InstructionPointer::new(3))),
            &program,
        );
        let current_frame = context.current_frame().expect("current hook frame");

        assert_eq!(context.frames().len(), 1);
        assert_eq!(current_frame.function_name(), "main");
        let register = current_frame.hook_register(0).expect("register handle");
        assert_eq!(current_frame.register_value(register), Some(&Value::I64(7)));
        assert_eq!(
            current_frame.get_register_value(register),
            Some(Value::I64(7))
        );
        assert!(matches!(
            current_frame.get_register_slot(register),
            Some(RegisterSlot::Ready(Value::I64(7)))
        ));
        assert_eq!(current_frame.register_count(), 1);
        assert_eq!(context.current_function_name(), Some("main"));
        assert_eq!(context.register_value(register), Some(&Value::I64(7)));
        assert!(matches!(
            context.get_register_slot(register),
            Some(RegisterSlot::Ready(Value::I64(7)))
        ));
        assert_eq!(context.current_instruction_function_name(), Some("main"));
        assert_eq!(
            context.current_instruction_pointer(),
            Some(InstructionPointer::new(3))
        );
        assert_eq!(context.current_instruction_index_opt(), Some(3));
        assert_eq!(context.current_instruction_index(), 3);
        assert_eq!(context.call_depth(), 1);

        assert_eq!(context.get_function_name(), Some("main".to_string()));
        assert_eq!(context.get_register_value(register), Some(Value::I64(7)));
        assert_eq!(context.get_current_instruction(), 3);
        assert_eq!(context.get_call_depth(), 1);
    }

    #[test]
    fn hook_context_reads_program_instructions_by_typed_pointer() {
        let mut program = Program::new();
        program
            .try_insert(Function::vm(VMFunction::new(
                "main".to_string(),
                Vec::new(),
                Vec::new(),
                None,
                1,
                vec![Instruction::LDI(0, Value::I64(7)), Instruction::RET(0)],
                HashMap::new(),
            )))
            .expect("program registration");
        let context = HookContext::new(
            &[],
            Some(InstructionCursor::new("main", InstructionPointer::new(1))),
            &program,
        );

        assert!(matches!(
            context.instruction_at_pointer("main", InstructionPointer::new(1)),
            Some(Instruction::RET(0))
        ));
        assert!(matches!(
            context.get_instruction_at_pointer("main", InstructionPointer::new(1)),
            Some(Instruction::RET(0))
        ));
        assert!(matches!(
            context.get_instruction_at("main", 1),
            Some(Instruction::RET(0))
        ));
    }

    #[test]
    fn hook_call_target_names_function_kinds_without_value_strings() {
        let vm_function = HookCallTarget::vm_function("main");
        let closure = HookCallTarget::closure("captured");
        let foreign = HookCallTarget::foreign_function("native");

        assert!(vm_function.is_vm_function());
        assert_eq!(vm_function.name(), "main");
        assert_eq!(vm_function.display_label(), "<function main>");

        assert!(closure.is_closure());
        assert_eq!(closure.name(), "captured");
        assert_eq!(closure.to_string(), "<function captured>");

        assert!(foreign.is_foreign_function());
        assert_eq!(foreign.name(), "native");
        assert_eq!(foreign.to_string(), "<foreign function native>");
    }

    #[test]
    fn hook_context_exposes_register_bank_aware_inspection() {
        let layout = RegisterLayout::new(1);
        let records = vec![ActivationRecord::with_registers(
            "main",
            RegisterFile::from_absolute_values(layout, vec![Value::I64(7), Value::I64(11)]),
            Vec::new(),
            None,
        )];
        let program = Program::new();
        let context = HookContext::new(&records, None, &program);
        let current_frame = context.current_frame().expect("current hook frame");

        let clear_register = current_frame
            .hook_register(0)
            .expect("clear register handle");
        assert!(clear_register.is_clear());
        assert_eq!(clear_register.bank_index(), 0);
        assert_eq!(
            current_frame.register_value(clear_register),
            Some(&Value::I64(7))
        );
        assert_eq!(
            current_frame.register_value_for(clear_register),
            Some(&Value::I64(7))
        );

        let secret_register = context.hook_register(1).expect("secret register handle");
        assert!(secret_register.is_secret());
        assert_eq!(secret_register.bank_index(), 0);
        assert_eq!(
            context.get_register_value(secret_register),
            Some(Value::I64(11))
        );
        assert_eq!(
            context.get_register_value_for(secret_register),
            Some(Value::I64(11))
        );
        assert!(matches!(
            context.get_register_slot(secret_register),
            Some(RegisterSlot::Ready(Value::I64(11)))
        ));

        let same_index_wrong_layout = HookRegister::new(1, RegisterLayout::new(8));
        assert!(!current_frame.contains_hook_register(same_index_wrong_layout));
        assert_eq!(
            current_frame.register_value_for(same_index_wrong_layout),
            None
        );
        assert_eq!(context.hook_register(2), None);
    }

    #[test]
    fn hook_register_exposes_absolute_and_bank_local_addresses() {
        let layout = RegisterLayout::new(2);

        let clear = HookRegister::new(1, layout);
        assert_eq!(clear.index(), 1);
        assert_eq!(clear.absolute_index(), 1);
        assert_eq!(clear.bank(), RegisterBank::Clear);
        assert_eq!(clear.bank_index(), 1);
        assert!(clear.is_clear());

        let secret = HookRegister::new(3, layout);
        assert_eq!(secret.index(), 3);
        assert_eq!(
            secret.address(),
            RegisterAddress::new(RegisterBank::Secret, 1)
        );
        assert_eq!(secret.bank(), RegisterBank::Secret);
        assert_eq!(secret.bank_index(), 1);
        assert!(secret.is_secret());
    }

    #[test]
    fn hook_registration_reports_id_overflow_without_mutating_manager() {
        let mut manager = HookManager {
            hooks: Vec::new(),
            enabled_hooks: 0,
            next_hook_id: usize::MAX,
        };

        let err = manager
            .try_register_hook(Box::new(|_| true), Box::new(|_, _| Ok(())), 0)
            .unwrap_err();

        assert_eq!(err, HookError::AllocatorOverflow);
        assert!(manager.is_empty());
    }

    #[test]
    fn hook_callback_errors_include_hook_id() {
        let mut manager = HookManager::new();
        let hook_id = manager
            .try_register_hook(
                Box::new(|_| true),
                Box::new(|_, _| Err(HookCallbackError::from("callback exploded"))),
                0,
            )
            .expect("register hook");
        let activation_records = Vec::new();
        let program = Program::new();
        let context = HookContext::new(&activation_records, None, &program);

        let err = manager
            .trigger_with_context(&HookEvent::StackPush(Value::I64(1)), &context)
            .unwrap_err();

        assert_eq!(
            err,
            HookError::CallbackFailed {
                hook_id,
                source: HookCallbackError::from("callback exploded"),
            }
        );
        assert_eq!(
            err.to_string(),
            format!("Hook {hook_id} callback failed: callback exploded")
        );
    }

    #[test]
    fn hook_dispatch_preserves_priority_order_and_skips_disabled_hooks() {
        let mut manager = HookManager::new();
        let calls = Arc::new(Mutex::new(Vec::new()));

        let low_calls = Arc::clone(&calls);
        manager
            .try_register_hook(
                Box::new(|_| true),
                Box::new(move |_, _| {
                    low_calls.lock().push(1);
                    Ok(())
                }),
                1,
            )
            .expect("register low-priority hook");

        let high_calls = Arc::clone(&calls);
        manager
            .try_register_hook(
                Box::new(|_| true),
                Box::new(move |_, _| {
                    high_calls.lock().push(2);
                    Ok(())
                }),
                10,
            )
            .expect("register high-priority hook");

        let disabled_calls = Arc::clone(&calls);
        let disabled_id = manager
            .try_register_hook(
                Box::new(|_| true),
                Box::new(move |_, _| {
                    disabled_calls.lock().push(3);
                    Ok(())
                }),
                20,
            )
            .expect("register disabled hook");
        assert!(manager.disable_hook(disabled_id));

        let activation_records = Vec::new();
        let program = Program::new();
        let context = HookContext::new(&activation_records, None, &program);
        manager
            .trigger_with_context(&HookEvent::StackPush(Value::I64(1)), &context)
            .expect("trigger hooks");

        assert_eq!(&*calls.lock(), &[2, 1]);
    }

    #[test]
    fn hook_manager_tracks_enabled_hooks_for_execution_fast_path() {
        let mut manager = HookManager::new();
        assert!(manager.is_empty());
        assert!(!manager.has_enabled_hooks());

        let first = manager
            .try_register_hook(Box::new(|_| true), Box::new(|_, _| Ok(())), 0)
            .expect("register first hook");
        let second = manager
            .try_register_hook(Box::new(|_| true), Box::new(|_, _| Ok(())), 0)
            .expect("register second hook");

        assert!(!manager.is_empty());
        assert!(manager.has_enabled_hooks());

        assert!(manager.disable_hook(first));
        assert!(manager.has_enabled_hooks());
        assert!(manager.disable_hook(second));
        assert!(!manager.has_enabled_hooks());

        assert!(manager.enable_hook(first));
        assert!(manager.has_enabled_hooks());
        assert!(manager.unregister_hook(first));
        assert!(!manager.has_enabled_hooks());
        assert!(manager.unregister_hook(second));
        assert!(manager.is_empty());
    }
}
