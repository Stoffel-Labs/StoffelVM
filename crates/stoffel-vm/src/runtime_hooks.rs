use stoffel_vm_types::activations::ActivationRecord;
use stoffel_vm_types::core_types::{Upvalue, Value};
use crate::foreign_functions::Function;
use stoffel_vm_types::instructions::Instruction;
use crate::vm_state::VMState;

/// Hook event types
#[derive(Debug, Clone)]
pub enum HookEvent {
    BeforeInstructionExecute(Instruction),
    AfterInstructionExecute(Instruction),
    RegisterRead(usize, Value),
    RegisterWrite(usize, Value, Value),
    VariableRead(String, Value),
    VariableWrite(String, Value, Value),
    UpvalueRead(String, Value),
    UpvalueWrite(String, Value, Value),
    ObjectFieldRead(usize, Value, Value),
    ObjectFieldWrite(usize, Value, Value, Value),
    ArrayElementRead(usize, Value, Value),
    ArrayElementWrite(usize, Value, Value, Value),
    BeforeFunctionCall(Value, Vec<Value>),
    AfterFunctionCall(Value, Value),
    ClosureCreated(String, Vec<Upvalue>),
    StackPush(Value),
    StackPop(Value),
}

// A simplified context that doesn't require borrowing the entire VMState
pub struct HookContext<'a> {
    pub activation_records: &'a [ActivationRecord],
    pub current_instruction: usize,
    pub functions: &'a rustc_hash::FxHashMap<String, Function>,
}

impl<'a> HookContext<'a> {
    pub fn new(
        activation_records: &'a [ActivationRecord],
        current_instruction: usize,
        functions: &'a rustc_hash::FxHashMap<String, Function>,
    ) -> Self {
        HookContext {
            activation_records,
            current_instruction,
            functions,
        }
    }

    // Safe accessor methods for VM state
    pub fn current_activation_record(&self) -> Option<&ActivationRecord> {
        self.activation_records.last()
    }

    pub fn get_compare_flag(&self) -> Option<i32> {
        self.current_activation_record().map(|r| r.compare_flag)
    }

    pub fn get_register_value(&self, reg_idx: usize) -> Option<Value> {
        self.current_activation_record()
            .and_then(|r| r.registers.get(reg_idx))
            .cloned()
    }

    pub fn get_current_instruction(&self) -> usize {
        self.current_instruction
    }

    pub fn get_function_name(&self) -> Option<String> {
        self.current_activation_record()
            .map(|r| r.function_name.clone())
    }

    pub fn get_call_depth(&self) -> usize {
        self.activation_records.len()
    }

    pub fn get_instruction_at(&self, function_name: &str, index: usize) -> Option<Instruction> {
        self.functions
            .get(function_name)
            .and_then(|func| match func {
                Function::VM(vm_func) => vm_func.instructions.get(index).cloned(),
                _ => None,
            })
    }
}

/// Hook predicate that determines if a hook should fire
pub type HookPredicate = dyn Fn(&HookEvent) -> bool + Send + Sync;

/// Hook callback that executes when a hook is triggered
pub type HookCallback = dyn Fn(&HookEvent, &HookContext) -> Result<(), String> + Send + Sync;

/// A hook registered with the VM
pub struct Hook {
    pub id: usize,
    pub predicate: Box<HookPredicate>,
    pub callback: Box<HookCallback>,
    pub enabled: bool,
    pub priority: i32,
}

/// Hook manager to handle hook registration and triggering
pub struct HookManager {
    pub hooks: Vec<Hook>,
    pub next_hook_id: usize,
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
            next_hook_id: 1,
        }
    }

    pub fn register_hook(
        &mut self,
        predicate: Box<HookPredicate>,
        callback: Box<HookCallback>,
        priority: i32,
    ) -> usize {
        let id = self.next_hook_id;
        self.next_hook_id += 1;

        self.hooks.push(Hook {
            id,
            predicate,
            callback,
            enabled: true,
            priority,
        });

        self.hooks.sort_by(|a, b| b.priority.cmp(&a.priority));

        id
    }

    pub fn unregister_hook(&mut self, hook_id: usize) -> bool {
        let len = self.hooks.len();
        self.hooks.retain(|hook| hook.id != hook_id);
        len != self.hooks.len()
    }

    pub fn enable_hook(&mut self, hook_id: usize) -> bool {
        if let Some(hook) = self.hooks.iter_mut().find(|h| h.id == hook_id) {
            hook.enabled = true;
            return true;
        }
        false
    }

    pub fn disable_hook(&mut self, hook_id: usize) -> bool {
        if let Some(hook) = self.hooks.iter_mut().find(|h| h.id == hook_id) {
            hook.enabled = false;
            return true;
        }
        false
    }

    pub fn trigger(&self, event: &HookEvent, vm_state: &VMState) -> Result<(), String> {
        let context = HookContext::new(
            &vm_state.activation_records,
            vm_state.current_instruction,
            &vm_state.functions,
        );

        self.trigger_with_context(event, &context)
    }

    pub fn trigger_with_context(
        &self,
        event: &HookEvent,
        context: &HookContext,
    ) -> Result<(), String> {
        // Fast path: if no hooks are registered, return immediately
        if self.hooks.is_empty() {
            return Ok(());
        }

        // Find matching hooks
        let matching_hooks: Vec<_> = self
            .hooks
            .iter()
            .filter(|hook| hook.enabled && (hook.predicate)(event))
            .collect();

        // Fast path: if no hooks match, return immediately
        if matching_hooks.is_empty() {
            return Ok(());
        }

        // Execute matching hooks
        for hook in matching_hooks {
            (hook.callback)(event, context)?;
        }

        Ok(())
    }
}
