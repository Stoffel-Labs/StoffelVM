use super::VMState;
use std::sync::Arc;
use stoffel_vm_types::core_types::{Closure, Value};

impl VMState {
    pub(crate) fn replace_closure_references(
        &mut self,
        current_closure: &Arc<Closure>,
        new_closure_arc: Arc<Closure>,
    ) {
        for record in self.call_stack.iter_mut() {
            if let Some(closure_arc) = record.closure().cloned() {
                if Arc::ptr_eq(&closure_arc, current_closure) {
                    record.set_closure(Some(Arc::clone(&new_closure_arc)));
                }
            }

            for register in record.iter_registers_mut() {
                if let Value::Closure(closure_arc) = register {
                    if Arc::ptr_eq(closure_arc, current_closure) {
                        *register = Value::Closure(Arc::clone(&new_closure_arc));
                    }
                }
            }
        }
    }

    /// Find an upvalue (captured variable) by name in the activation record stack.
    pub(crate) fn find_upvalue(&self, name: &str) -> Option<Value> {
        for record in self.call_stack.iter().rev() {
            if let Some(value) = record.local(name) {
                return Some(value.clone());
            }

            for upvalue in record.upvalues() {
                if upvalue.name() == name {
                    return Some(upvalue.value().clone());
                }
            }
        }
        None
    }
}
