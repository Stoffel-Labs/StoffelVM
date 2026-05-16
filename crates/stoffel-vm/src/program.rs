use crate::error::{VmError, VmResult};
use crate::foreign_functions::{ForeignFunction, Function};
use crate::runtime_instruction::RuntimeFunction;
use rustc_hash::FxHashMap;
use std::sync::Arc;
use stoffel_vm_types::activations::{ActivationRecord, ActivationResult, InstructionPointer};
use stoffel_vm_types::core_types::{Closure, Upvalue, Value};
use stoffel_vm_types::functions::VMFunction;
use stoffel_vm_types::instructions::Instruction;
use stoffel_vm_types::registers::RegisterLayout;

/// Minimal owned metadata needed to push a VM call frame.
///
/// The executor must mutate `VMState` after lookup, so it cannot keep a borrow
/// into the program map. This type avoids cloning the whole function body and
/// resolved instruction stream for every call.
#[derive(Debug, Clone)]
pub(crate) struct VmCallTarget {
    name: Arc<str>,
    parameters: Vec<String>,
    upvalues: Vec<String>,
    frame_register_count: usize,
    runtime: Arc<RuntimeFunction>,
}

impl VmCallTarget {
    fn from_vm_function(function: &VMFunction, runtime: Arc<RuntimeFunction>) -> Self {
        Self {
            name: Arc::from(function.name()),
            parameters: function.parameters().to_vec(),
            upvalues: function.upvalues().to_vec(),
            frame_register_count: function.register_count(),
            runtime,
        }
    }

    pub(crate) fn name(&self) -> &str {
        self.name.as_ref()
    }

    pub(crate) fn parameters(&self) -> &[String] {
        &self.parameters
    }

    pub(crate) fn upvalues(&self) -> &[String] {
        &self.upvalues
    }

    pub(crate) fn runtime_function(&self) -> Arc<RuntimeFunction> {
        Arc::clone(&self.runtime)
    }

    pub(crate) fn frame_register_count(&self) -> usize {
        self.frame_register_count
    }

    pub(crate) fn instantiate_frame<I>(
        &self,
        layout: RegisterLayout,
        register_args: I,
        upvalues: Vec<Upvalue>,
        closure: Option<Arc<Closure>>,
    ) -> ActivationResult<ActivationRecord>
    where
        I: IntoIterator<Item = Value>,
        I::IntoIter: ExactSizeIterator,
    {
        let mut record = ActivationRecord::for_function_with_local_capacity(
            Arc::clone(&self.name),
            layout,
            self.frame_register_count,
            upvalues,
            closure,
            self.parameters.len(),
        );
        let register_args = register_args.into_iter();
        if !self.parameters.is_empty() || register_args.len() != 0 {
            record.bind_owned_parameters(&self.parameters, register_args)?;
        }
        Ok(record)
    }

    pub(crate) fn instantiate_empty_frame(&self, layout: RegisterLayout) -> ActivationRecord {
        debug_assert!(self.parameters.is_empty());
        debug_assert!(self.upvalues.is_empty());
        ActivationRecord::for_function(
            Arc::clone(&self.name),
            layout,
            self.frame_register_count,
            Vec::new(),
            None,
        )
    }
}

#[derive(Clone)]
pub(crate) enum CallTarget {
    Vm(Arc<VmCallTarget>),
    Foreign(Arc<ForeignFunction>),
}

#[derive(Clone)]
enum RegisteredFunction {
    Vm {
        source: Arc<VMFunction>,
        runtime: Arc<RuntimeFunction>,
        call_target: Arc<VmCallTarget>,
    },
    Foreign(Arc<ForeignFunction>),
}

/// Registered callable program for a VM instance.
///
/// VM bytecode, lowered runtime instructions, call-frame metadata, and native
/// callback handles are immutable after registration, so clones of `Program`
/// share those payloads by `Arc`. That keeps independent VM runtime clones
/// cheap while preserving an owned registry boundary instead of exposing a raw
/// map everywhere.
#[derive(Clone, Default)]
pub struct Program {
    functions: FxHashMap<String, RegisteredFunction>,
}

impl Program {
    pub fn new() -> Self {
        Self {
            functions: FxHashMap::default(),
        }
    }

    pub fn try_insert(&mut self, function: Function) -> VmResult<()> {
        let name = function.name().to_owned();
        if self.functions.contains_key(&name) {
            return Err(VmError::FunctionAlreadyRegistered { function: name });
        }

        let registered = match function {
            Function::VM(mut function) => {
                function.resolve_instructions()?;
                let runtime = Arc::new(RuntimeFunction::from_vm_function(&function)?);
                let call_target = VmCallTarget::from_vm_function(&function, Arc::clone(&runtime));
                RegisteredFunction::Vm {
                    source: Arc::from(function),
                    runtime,
                    call_target: Arc::new(call_target),
                }
            }
            Function::Foreign(function) => RegisteredFunction::Foreign(Arc::new(function)),
        };

        self.functions.insert(name, registered);
        Ok(())
    }

    pub fn contains(&self, name: &str) -> bool {
        self.functions.contains_key(name)
    }

    pub fn ensure_names_available(&self, names: &[&str], group_name: &str) -> VmResult<()> {
        for (index, name) in names.iter().enumerate() {
            if names[index + 1..].contains(name) {
                return Err(VmError::RegistrationDuplicateFunction {
                    group: group_name.to_owned(),
                    function: (*name).to_owned(),
                });
            }
            if self.contains(name) {
                return Err(VmError::RegistrationFunctionAlreadyRegistered {
                    group: group_name.to_owned(),
                    function: (*name).to_owned(),
                });
            }
        }
        Ok(())
    }

    pub(crate) fn call_target(&self, name: &str) -> VmResult<CallTarget> {
        match self.functions.get(name) {
            Some(RegisteredFunction::Vm { call_target, .. }) => {
                Ok(CallTarget::Vm(Arc::clone(call_target)))
            }
            Some(RegisteredFunction::Foreign(function)) => {
                Ok(CallTarget::Foreign(Arc::clone(function)))
            }
            None => Err(VmError::QuotedFunctionNotFound {
                function: name.to_owned(),
            }),
        }
    }

    pub fn foreign_function(&self, name: &str) -> VmResult<Option<Arc<ForeignFunction>>> {
        match self.functions.get(name) {
            Some(RegisteredFunction::Foreign(function)) => Ok(Some(Arc::clone(function))),
            Some(RegisteredFunction::Vm { .. }) => Ok(None),
            None => Err(VmError::FunctionNotFound {
                function: name.to_owned(),
            }),
        }
    }

    #[cfg(test)]
    pub fn vm_function(&self, name: &str) -> VmResult<&VMFunction> {
        self.vm_function_with_foreign_error(name, |name| VmError::CannotExecuteForeignFunction {
            function: name.to_owned(),
        })
    }

    pub(crate) fn runtime_function(&self, name: &str) -> VmResult<Arc<RuntimeFunction>> {
        match self.functions.get(name) {
            Some(RegisteredFunction::Vm { runtime, .. }) => Ok(Arc::clone(runtime)),
            Some(RegisteredFunction::Foreign(_)) | None => {
                Err(VmError::MissingResolvedInstructions {
                    function: name.to_owned(),
                })
            }
        }
    }

    pub(crate) fn instruction_at(
        &self,
        name: &str,
        instruction_pointer: InstructionPointer,
    ) -> Option<&Instruction> {
        match self.functions.get(name)? {
            RegisteredFunction::Vm { source, .. } => {
                source.instructions().get(instruction_pointer.index())
            }
            RegisteredFunction::Foreign(_) => None,
        }
    }

    pub(crate) fn vm_call_target_with_foreign_error<F>(
        &self,
        name: &str,
        foreign_error: F,
    ) -> VmResult<Arc<VmCallTarget>>
    where
        F: FnOnce(&str) -> VmError,
    {
        match self.functions.get(name) {
            Some(RegisteredFunction::Vm { call_target, .. }) => Ok(Arc::clone(call_target)),
            Some(RegisteredFunction::Foreign(_)) => Err(foreign_error(name)),
            None => Err(VmError::FunctionNotFound {
                function: name.to_owned(),
            }),
        }
    }

    #[cfg(test)]
    pub fn vm_function_with_foreign_error<F>(
        &self,
        name: &str,
        foreign_error: F,
    ) -> VmResult<&VMFunction>
    where
        F: FnOnce(&str) -> VmError,
    {
        match self.functions.get(name) {
            Some(RegisteredFunction::Vm { source, .. }) => Ok(source),
            Some(RegisteredFunction::Foreign(_)) => Err(foreign_error(name)),
            None => Err(VmError::FunctionNotFound {
                function: name.to_owned(),
            }),
        }
    }

    #[cfg(test)]
    pub fn ensure_vm_entry<F>(&self, name: &str, foreign_error: F) -> VmResult<()>
    where
        F: FnOnce(&str) -> VmError,
    {
        match self.functions.get(name) {
            Some(RegisteredFunction::Vm { .. }) => Ok(()),
            Some(RegisteredFunction::Foreign(_)) => Err(foreign_error(name)),
            None => Err(VmError::FunctionNotFound {
                function: name.to_owned(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foreign_functions::ForeignFunctionContext;
    use crate::runtime_instruction::{FetchedInstruction, RuntimeInstruction};
    use std::collections::HashMap;
    use std::mem::size_of;
    use std::sync::Arc;
    use stoffel_vm_types::core_types::{Closure, Upvalue, Value};
    use stoffel_vm_types::instructions::Instruction;
    use stoffel_vm_types::registers::RegisterIndex;
    use stoffel_vm_types::registers::RegisterLayout;

    fn vm_function(name: &str) -> VMFunction {
        VMFunction::new(
            name.to_string(),
            Vec::new(),
            Vec::new(),
            None,
            1,
            Vec::new(),
            HashMap::new(),
        )
    }

    fn foreign_function(name: &str) -> ForeignFunction {
        ForeignFunction::new(
            name,
            Arc::new(|_: ForeignFunctionContext<'_>| Ok(Value::Unit)),
        )
    }

    #[test]
    fn registered_function_uses_indirection_and_runtime_metadata_stays_compact() {
        assert!(size_of::<RegisteredFunction>() < size_of::<VMFunction>());
        assert_eq!(
            size_of::<RuntimeFunction>(),
            size_of::<Vec<RuntimeInstruction>>()
        );
    }

    #[test]
    fn cloned_program_shares_immutable_vm_payloads() {
        let mut program = Program::new();
        program
            .try_insert(Function::vm(vm_function("main")))
            .expect("program registration");

        let cloned = program.clone();
        let original_payload = program.functions.get("main").expect("original function");
        let cloned_payload = cloned.functions.get("main").expect("cloned function");

        let (
            RegisteredFunction::Vm {
                source: original_source,
                runtime: original_runtime,
                call_target: original_call_target,
            },
            RegisteredFunction::Vm {
                source: cloned_source,
                runtime: cloned_runtime,
                call_target: cloned_call_target,
            },
        ) = (original_payload, cloned_payload)
        else {
            panic!("main should be a VM function");
        };

        assert!(Arc::ptr_eq(original_source, cloned_source));
        assert!(Arc::ptr_eq(original_runtime, cloned_runtime));
        assert!(Arc::ptr_eq(original_call_target, cloned_call_target));
    }

    #[test]
    fn vm_call_target_lookup_reuses_resolved_metadata() {
        let mut program = Program::new();
        program
            .try_insert(Function::vm(vm_function("main")))
            .expect("program registration");

        let CallTarget::Vm(first) = program.call_target("main").expect("first lookup") else {
            panic!("main should be a VM call target");
        };
        let CallTarget::Vm(second) = program.call_target("main").expect("second lookup") else {
            panic!("main should be a VM call target");
        };

        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn vm_call_target_reuses_resolved_runtime_payload() {
        let mut program = Program::new();
        program
            .try_insert(Function::vm(vm_function("main")))
            .expect("program registration");

        let runtime = program.runtime_function("main").expect("runtime function");
        let CallTarget::Vm(target) = program.call_target("main").expect("call target") else {
            panic!("main should be a VM call target");
        };

        assert!(Arc::ptr_eq(&runtime, &target.runtime_function()));
    }

    #[test]
    fn vm_call_target_instantiates_activation_frame_from_resolved_metadata() {
        let mut function = VMFunction::new(
            "callee".to_string(),
            vec!["x".to_string()],
            vec!["outer".to_string()],
            None,
            3,
            Vec::new(),
            HashMap::new(),
        );
        function
            .resolve_instructions()
            .expect("function should resolve");
        let runtime = Arc::new(
            RuntimeFunction::from_vm_function(&function).expect("runtime function should lower"),
        );
        let target = VmCallTarget::from_vm_function(&function, runtime);
        let upvalues = vec![Upvalue::new("outer".to_string(), Value::I64(9))];
        let closure = Arc::new(Closure::new("callee".to_string(), Vec::new()));

        let frame = target
            .instantiate_frame(
                RegisterLayout::new(1),
                vec![Value::I64(7)],
                upvalues,
                Some(Arc::clone(&closure)),
            )
            .expect("call target should create a valid activation frame");

        assert_eq!(frame.function_name(), "callee");
        assert_eq!(frame.register_layout(), RegisterLayout::new(1));
        assert_eq!(frame.register_count(), 3);
        assert_eq!(frame.register(RegisterIndex::new(0)), Some(&Value::I64(7)));
        assert_eq!(frame.local("x"), Some(&Value::I64(7)));
        assert_eq!(frame.upvalues()[0].name(), "outer");
        assert_eq!(frame.upvalues()[0].value(), &Value::I64(9));
        assert!(frame
            .closure()
            .is_some_and(|stored| Arc::ptr_eq(stored, &closure)));
    }

    #[test]
    fn program_rejects_duplicate_function_names() {
        let mut program = Program::new();
        program
            .try_insert(Function::vm(vm_function("main")))
            .expect("first registration");

        let err = program
            .try_insert(Function::foreign(foreign_function("main")))
            .expect_err("duplicate registration must fail");

        assert!(
            err.to_string().contains("main") && err.to_string().contains("already registered"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn program_validates_registration_name_groups() {
        let mut program = Program::new();
        program
            .try_insert(Function::vm(vm_function("existing")))
            .expect("existing registration");

        let err = program
            .ensure_names_available(&["a", "a"], "builtins")
            .expect_err("duplicate builtin names must be rejected");
        assert!(err.to_string().contains("duplicate function 'a'"));

        let err = program
            .ensure_names_available(&["existing"], "builtins")
            .expect_err("registered builtin names must be rejected");
        assert!(
            err.to_string().contains("existing") && err.to_string().contains("already registered")
        );
    }

    #[test]
    fn program_exposes_typed_vm_and_foreign_lookup() {
        let mut program = Program::new();
        program
            .try_insert(Function::vm(vm_function("main")))
            .expect("vm registration");
        program
            .try_insert(Function::foreign(foreign_function("native")))
            .expect("foreign registration");

        assert_eq!(program.vm_function("main").unwrap().name(), "main");
        assert!(program.foreign_function("main").unwrap().is_none());
        assert!(program.foreign_function("native").unwrap().is_some());

        let CallTarget::Vm(target) = program.call_target("main").unwrap() else {
            panic!("main should be a VM call target");
        };
        assert_eq!(target.name(), "main");
        assert_eq!(target.frame_register_count(), 1);

        let err = program
            .ensure_vm_entry("native", |name| VmError::from(format!("{name} is foreign")))
            .expect_err("foreign entry must be rejected");
        assert_eq!(err.to_string(), "native is foreign");
    }

    #[test]
    fn foreign_function_lookup_reuses_registered_callback() {
        let mut program = Program::new();
        program
            .try_insert(Function::foreign(foreign_function("native")))
            .expect("foreign registration");

        let first = program
            .foreign_function("native")
            .expect("first lookup")
            .expect("native should be foreign");
        let second = program
            .foreign_function("native")
            .expect("second lookup")
            .expect("native should be foreign");

        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn program_resolves_vm_functions_on_insert() {
        let mut program = Program::new();
        program
            .try_insert(Function::vm(VMFunction::new(
                "secret_frame".to_string(),
                Vec::new(),
                Vec::new(),
                None,
                1,
                vec![Instruction::LDI(16, Value::I64(7)), Instruction::RET(16)],
                HashMap::new(),
            )))
            .expect("program registration should normalize VM functions");

        let function = program.vm_function("secret_frame").unwrap();
        assert!(function.is_resolved());
        assert_eq!(function.register_count(), 17);

        let CallTarget::Vm(target) = program.call_target("secret_frame").unwrap() else {
            panic!("secret_frame should be a VM call target");
        };
        assert_eq!(target.frame_register_count(), 17);
    }

    #[test]
    fn program_caches_runtime_instructions_on_insert() {
        let mut program = Program::new();
        program
            .try_insert(Function::vm(VMFunction::new(
                "main".to_string(),
                Vec::new(),
                Vec::new(),
                None,
                1,
                vec![
                    Instruction::LDI(0, Value::I64(7)),
                    Instruction::CALL("native".to_string()),
                    Instruction::RET(0),
                ],
                HashMap::new(),
            )))
            .expect("program registration should lower runtime instructions");

        let runtime = program.runtime_function("main").expect("runtime function");
        assert_eq!(runtime.len(), 3);
        assert!(runtime
            .get_instruction(InstructionPointer::new(3))
            .is_none());

        let fetched = FetchedInstruction::fetch(InstructionPointer::new(0), &runtime)
            .expect("first instruction");
        let (runtime_instruction, _) = fetched.instructions();
        assert!(matches!(
            runtime_instruction,
            RuntimeInstruction::LoadImmediate {
                value: Value::I64(7),
                dest
            } if dest.index() == 0
        ));

        let fetched = FetchedInstruction::fetch(InstructionPointer::new(1), &runtime)
            .expect("call instruction");
        let (runtime_instruction, _) = fetched.instructions();
        assert!(matches!(
            runtime_instruction,
            RuntimeInstruction::Call { function } if function.as_ref() == "native"
        ));
    }
}
