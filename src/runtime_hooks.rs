use crate::activations::ActivationRecord;
use crate::functions::Function;
use crate::instructions::Instruction;
use crate::vm_state::{VMState};
use crate::core_types::{Upvalue, Value};

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

pub struct HookContext<'a> {
    pub vm_state: &'a VMState,
}

impl<'a> HookContext<'a> {
    pub fn new(vm_state: &'a VMState) -> Self {
        HookContext { vm_state }
    }

    // Safe accessor methods for VM state
    pub fn current_activation_record(&self) -> Option<&ActivationRecord> {
        self.vm_state.activation_records.last()
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
        self.vm_state.current_instruction
    }

    pub fn get_function_name(&self) -> Option<String> {
        self.current_activation_record().map(|r| r.function_name.clone())
    }

    pub fn get_call_depth(&self) -> usize {
        self.vm_state.activation_records.len()
    }

    pub fn get_instruction_at(&self, function_name: &str, index: usize) -> Option<Instruction> {
        self.vm_state.functions.get(function_name).and_then(|func| {
            match func {
                Function::VM(vm_func) => vm_func.instructions.get(index).cloned(),
                _ => None
            }
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
        let context = HookContext::new(vm_state);

        let matching_hooks: Vec<_> = self.hooks.iter()
            .filter(|hook| hook.enabled && (hook.predicate)(event))
            .collect();

        for hook in matching_hooks {
            (hook.callback)(event, &context)?;
        }

        Ok(())
    }
}