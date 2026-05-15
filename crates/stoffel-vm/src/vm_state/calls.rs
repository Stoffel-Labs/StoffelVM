use super::{execution::InstructionOutcome, CallStackCheckpoint, VMState};
use crate::error::{VmError, VmResult};
use crate::foreign_functions::{
    ForeignArguments, ForeignFunction, ForeignFunctionCallbackError, ForeignFunctionCallbackResult,
    ForeignFunctionContext, ForeignFunctionError, MpcOnlineBuiltin,
};
use crate::mpc_values::clear_share_input;
use crate::net::mpc_engine::{AbaSessionId, MpcExponentGenerator, MpcPartyId};
use crate::net::share_runtime::ensure_matching_share_data_format;
use crate::program::{CallTarget, VmCallTarget};
use crate::runtime_hooks::{HookCallTarget, HookEvent};
use crate::runtime_instruction::RuntimeRegister;
use crate::value_conversions::value_to_usize;
use crate::vm_state::mpc_operation::{
    PendingMpcBuiltinCall, PendingMpcBuiltinOperation, PendingMpcOperation,
};
use smallvec::SmallVec;
use std::sync::Arc;
use stoffel_vm_types::core_types::{Closure, ShareType, Upvalue, Value};
use stoffel_vm_types::instructions::Instruction;

struct PreparedVmFrame {
    register_args: Vec<Value>,
    upvalues: Vec<Upvalue>,
    closure: Option<Arc<Closure>>,
}

impl PreparedVmFrame {
    fn entry(register_args: Vec<Value>) -> Self {
        Self {
            register_args,
            upvalues: Vec::new(),
            closure: None,
        }
    }

    fn function(register_args: Vec<Value>, upvalues: Vec<Upvalue>) -> Self {
        Self {
            register_args,
            upvalues,
            closure: None,
        }
    }

    fn closure(register_args: Vec<Value>, upvalues: Vec<Upvalue>, closure: Arc<Closure>) -> Self {
        Self {
            register_args,
            upvalues,
            closure: Some(closure),
        }
    }
}

struct DrainedCallArgs {
    checkpoint: CallStackCheckpoint,
    values: SmallVec<[Value; 8]>,
}

impl DrainedCallArgs {
    fn new(checkpoint: CallStackCheckpoint, values: SmallVec<[Value; 8]>) -> Self {
        Self { checkpoint, values }
    }

    const fn checkpoint(&self) -> CallStackCheckpoint {
        self.checkpoint
    }

    fn as_slice(&self) -> &[Value] {
        &self.values
    }

    fn into_values(self) -> SmallVec<[Value; 8]> {
        self.values
    }
}

impl VMState {
    pub(crate) fn push_entry_frame<F>(
        &mut self,
        function_name: &str,
        args: &[Value],
        foreign_error: F,
    ) -> VmResult<CallStackCheckpoint>
    where
        F: FnOnce(&str) -> VmError,
    {
        let checkpoint = CallStackCheckpoint::new(self.call_stack_depth());
        let target = self
            .program
            .vm_call_target_with_foreign_error(function_name, foreign_error)?;
        let prepared = self.prepare_vm_entry_call(&target, args)?;
        self.push_prepared_vm_frame(&target, prepared)?;
        Ok(checkpoint)
    }

    pub(super) fn execute_call(
        &mut self,
        function_name: &str,
        hooks_enabled: bool,
    ) -> VmResult<InstructionOutcome> {
        let function = self.program.call_target(function_name)?;

        match function {
            CallTarget::Vm(target) => {
                let args = self.current_stack_args_clone()?;
                let prepared = self.prepare_vm_call(&target, &args)?;
                let drained_args = self.drain_call_args(hooks_enabled)?;
                debug_assert_eq!(drained_args.as_slice(), args.as_slice());
                if let Err(error) =
                    self.call_vm_function(&target, drained_args.as_slice(), prepared, hooks_enabled)
                {
                    self.restore_call_args_after_error(drained_args)?;
                    return Err(error);
                }
            }
            CallTarget::Foreign(foreign_func) => {
                let args = self.drain_call_args(hooks_enabled)?;
                let outcome = match self.call_foreign_function_internal(
                    function_name,
                    foreign_func.as_ref(),
                    args.as_slice(),
                    hooks_enabled,
                    args.checkpoint(),
                ) {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        self.restore_call_args_after_error(args)?;
                        return Err(error);
                    }
                };
                if let InstructionOutcome::Return(_) = outcome {
                    return Ok(outcome);
                }
            }
        }

        Ok(InstructionOutcome::Continue)
    }

    fn current_stack_args_clone(&self) -> VmResult<SmallVec<[Value; 8]>> {
        Ok(self.current_frame()?.stack().iter().cloned().collect())
    }

    fn validate_vm_call_arity(&self, target: &VmCallTarget, actual: usize) -> VmResult<()> {
        let expected = target.parameters().len();
        if expected != actual {
            return Err(VmError::FunctionArityMismatch {
                function: target.name().to_owned(),
                expected,
                actual,
            });
        }
        Ok(())
    }

    fn prepare_vm_entry_call(
        &self,
        target: &VmCallTarget,
        args: &[Value],
    ) -> VmResult<PreparedVmFrame> {
        self.validate_vm_call_arity(target, args.len())?;
        if !target.upvalues().is_empty() {
            return Err(VmError::EntryFunctionRequiresUpvalues {
                function: target.name().to_owned(),
                upvalues: target.upvalues().to_vec(),
            });
        }
        Ok(PreparedVmFrame::entry(
            self.prepare_register_arguments(args)?,
        ))
    }

    fn prepare_vm_call(&self, target: &VmCallTarget, args: &[Value]) -> VmResult<PreparedVmFrame> {
        self.validate_vm_call_arity(target, args.len())?;
        let mut upvalues = Vec::with_capacity(target.upvalues().len());
        for name in target.upvalues() {
            let value = self
                .find_upvalue(name)
                .ok_or_else(|| VmError::UpvalueNotFound { name: name.clone() })?;
            upvalues.push(Upvalue::new(name.clone(), value));
        }
        let prepared_args = self.prepare_register_arguments(args)?;
        Ok(PreparedVmFrame::function(prepared_args, upvalues))
    }

    fn drain_call_args(&mut self, hooks_enabled: bool) -> VmResult<DrainedCallArgs> {
        let checkpoint = CallStackCheckpoint::new(self.call_stack.len());
        let values = self.current_frame_mut()?.take_stack();

        if hooks_enabled {
            for value in values.iter().rev() {
                let event = HookEvent::StackPop(value.clone());
                if let Err(error) = self.trigger_hook_with_snapshot(&event) {
                    self.current_frame_mut()?.replace_stack(values);
                    return Err(error);
                }
            }
        }

        Ok(DrainedCallArgs::new(checkpoint, values))
    }

    fn restore_call_args_after_error(&mut self, args: DrainedCallArgs) -> VmResult<()> {
        if args.checkpoint().is_current_depth(self.call_stack.len()) {
            self.current_frame_mut()?.replace_stack(args.into_values());
        }

        Ok(())
    }

    pub(super) fn plan_async_mpc_builtin_call(
        &mut self,
        function_name: &str,
        hooks_enabled: bool,
    ) -> VmResult<Option<PendingMpcOperation>> {
        let CallTarget::Foreign(foreign_func) = self.program.call_target(function_name)? else {
            return Ok(None);
        };
        let Some(builtin) = foreign_func.mpc_online_builtin_kind() else {
            return Ok(None);
        };

        let args = self.drain_call_args(hooks_enabled)?;
        let planned =
            self.plan_drained_async_mpc_builtin_call(builtin, args.as_slice(), hooks_enabled);
        match planned {
            Ok(operation) => Ok(Some(PendingMpcOperation::BuiltinCall(operation))),
            Err(error) => {
                self.restore_call_args_after_error(args)?;
                Err(error)
            }
        }
    }

    fn plan_drained_async_mpc_builtin_call(
        &mut self,
        builtin: MpcOnlineBuiltin,
        args: &[Value],
        hooks_enabled: bool,
    ) -> VmResult<PendingMpcBuiltinCall> {
        let function = builtin.function_name();
        let call_target = HookCallTarget::foreign_function(function);

        if hooks_enabled {
            let event = HookEvent::BeforeFunctionCall(call_target.clone(), args.to_vec());
            self.trigger_hook_with_snapshot(&event)?;
        }

        let operation = self
            .parse_async_mpc_builtin_operation(builtin, args)
            .map_err(|source| Self::foreign_callback_failed(function, source))?;
        let return_register = self.current_return_register()?;
        Ok(PendingMpcBuiltinCall::new(
            return_register,
            call_target,
            operation,
        ))
    }

    fn foreign_callback_failed(
        function: &'static str,
        source: ForeignFunctionCallbackError,
    ) -> VmError {
        VmError::ForeignFunction(ForeignFunctionError::CallbackFailed {
            function: function.to_owned(),
            source,
        })
    }

    fn parse_async_mpc_builtin_operation(
        &mut self,
        builtin: MpcOnlineBuiltin,
        args: &[Value],
    ) -> ForeignFunctionCallbackResult<PendingMpcBuiltinOperation> {
        let function = builtin.function_name();
        let args = ForeignArguments::new(function, args);

        match builtin {
            MpcOnlineBuiltin::FromClear => {
                args.require_min(1, "at least 1 argument: value")?;
                let clear_value = args.cloned(0)?;
                let clear = clear_share_input(&clear_value, None)?;
                Ok(PendingMpcBuiltinOperation::InputShare { clear })
            }
            MpcOnlineBuiltin::FromClearInt => {
                args.require_min(2, "2 arguments: value, bit_length")?;
                let clear_value = args.cloned(0)?;
                let bit_length = args.usize(1, "bit_length")?;
                let clear =
                    clear_share_input(&clear_value, Some(ShareType::try_secret_int(bit_length)?))?;
                Ok(PendingMpcBuiltinOperation::InputShare { clear })
            }
            MpcOnlineBuiltin::FromClearFixed => {
                args.require_min(3, "3 arguments: value, total_bits, frac_bits")?;
                let clear_value = args.cloned(0)?;
                let k = args.usize(1, "total_bits")?;
                let f = args.usize(2, "frac_bits")?;
                let clear = clear_share_input(
                    &clear_value,
                    Some(ShareType::try_secret_fixed_point_from_bits(k, f)?),
                )?;
                Ok(PendingMpcBuiltinOperation::InputShare { clear })
            }
            MpcOnlineBuiltin::Mul => {
                args.require_min(2, "2 arguments: share1, share2")?;
                let left = args.cloned(0)?;
                let right = args.cloned(1)?;
                let (share_type, left_data, right_data) =
                    self.extract_matching_share_pair(&left, &right, "Share.mul")?;
                ensure_matching_share_data_format("async_multiply_share", &left_data, &right_data)?;
                Ok(PendingMpcBuiltinOperation::Mul {
                    share_type,
                    left_data,
                    right_data,
                })
            }
            MpcOnlineBuiltin::Open => {
                args.require_exact(1, "1 argument: share")?;
                let share_value = args.cloned(0)?;
                let (share_type, share_data) = self.extract_share_data(&share_value)?;
                Ok(PendingMpcBuiltinOperation::Open {
                    share_type,
                    share_data,
                })
            }
            MpcOnlineBuiltin::BatchOpen => {
                args.require_exact(1, "1 argument: shares_array")?;
                let shares_arg = args.cloned(0)?;
                let Some((share_type, share_data)) = self.extract_homogeneous_share_array(
                    &shares_arg,
                    "Share.batch_open shares_array",
                )?
                else {
                    return Ok(PendingMpcBuiltinOperation::BatchOpen {
                        share_type: ShareType::default_secret_int(),
                        share_data: Vec::new(),
                    });
                };
                Ok(PendingMpcBuiltinOperation::BatchOpen {
                    share_type,
                    share_data,
                })
            }
            MpcOnlineBuiltin::SendToClient => {
                args.require_min(2, "2 arguments: share, client_id")?;
                let share_value = args.cloned(0)?;
                let client_id_value = args.cloned(1)?;
                let (_share_type, share_data) = self.extract_share_data(&share_value)?;
                let client_id = value_to_usize(&client_id_value, "client_id")?;
                Ok(PendingMpcBuiltinOperation::SendToClient {
                    share_data,
                    client_id,
                })
            }
            MpcOnlineBuiltin::OpenExp => {
                args.require_min(2, "2 arguments: share, curve_name")?;
                let share_value = args.cloned(0)?;
                let curve_name = match args.cloned(1)? {
                    Value::String(value) => value,
                    _ => return Err("curve_name must be a string".into()),
                };
                let (share_type, share_data) = self.extract_share_data(&share_value)?;
                let generator =
                    MpcExponentGenerator::from_curve_name(&curve_name).map_err(String::from)?;
                let (group, generator_bytes) = generator.into_parts();
                Ok(PendingMpcBuiltinOperation::OpenExp {
                    group,
                    share_type,
                    share_data,
                    generator_bytes,
                })
            }
            MpcOnlineBuiltin::Random => Ok(PendingMpcBuiltinOperation::Random {
                share_type: ShareType::default_secret_int(),
            }),
            MpcOnlineBuiltin::OpenField => {
                args.require_exact(1, "1 argument: share")?;
                let share_value = args.cloned(0)?;
                let (share_type, share_data) = self.extract_share_data(&share_value)?;
                Ok(PendingMpcBuiltinOperation::OpenField {
                    share_type,
                    share_data,
                })
            }
            MpcOnlineBuiltin::OpenExpCustom => {
                args.require_min(2, "2 arguments: share, generator_bytes")?;
                let share_value = args.cloned(0)?;
                let generator_value = args.cloned(1)?;
                let (share_type, share_data) = self.extract_share_data(&share_value)?;
                let generator_bytes = self.read_byte_array(&generator_value)?;
                Ok(PendingMpcBuiltinOperation::OpenExpCustom {
                    share_type,
                    share_data,
                    generator_bytes,
                })
            }
            MpcOnlineBuiltin::RbcBroadcast => {
                args.require_exact(1, "1 argument: message")?;
                let message = args.string(0, "Message")?.as_bytes().to_vec();
                Ok(PendingMpcBuiltinOperation::RbcBroadcast { message })
            }
            MpcOnlineBuiltin::RbcReceive => {
                args.require_min(2, "2 arguments: from_party, timeout_ms")?;
                let from_party = args.usize(0, "from_party")?;
                let timeout_ms = args.u64(1, "timeout_ms")?;
                Ok(PendingMpcBuiltinOperation::RbcReceive {
                    from_party: MpcPartyId::new(from_party),
                    timeout_ms,
                })
            }
            MpcOnlineBuiltin::RbcReceiveAny => {
                args.require_exact(1, "1 argument: timeout_ms")?;
                let timeout_ms = args.u64(0, "timeout_ms")?;
                Ok(PendingMpcBuiltinOperation::RbcReceiveAny { timeout_ms })
            }
            MpcOnlineBuiltin::AbaPropose => {
                args.require_exact(1, "1 argument: value (bool)")?;
                let value = args.bool(0, "value")?;
                Ok(PendingMpcBuiltinOperation::AbaPropose { value })
            }
            MpcOnlineBuiltin::AbaResult => {
                args.require_min(2, "2 arguments: session_id, timeout_ms")?;
                let session_id = args.u64(0, "session_id")?;
                let timeout_ms = args.u64(1, "timeout_ms")?;
                Ok(PendingMpcBuiltinOperation::AbaResult {
                    session_id: AbaSessionId::new(session_id),
                    timeout_ms,
                })
            }
            MpcOnlineBuiltin::AbaProposeAndWait => {
                args.require_min(2, "2 arguments: value (bool), timeout_ms")?;
                let value = args.bool(0, "value")?;
                let timeout_ms = args.u64(1, "timeout_ms")?;
                Ok(PendingMpcBuiltinOperation::AbaProposeAndWait { value, timeout_ms })
            }
        }
    }

    fn push_prepared_vm_frame(
        &mut self,
        target: &VmCallTarget,
        prepared: PreparedVmFrame,
    ) -> VmResult<()> {
        let record = target.instantiate_frame(
            self.register_layout,
            &prepared.register_args,
            prepared.upvalues,
            prepared.closure,
        )?;
        self.call_stack.push(record);
        Ok(())
    }

    fn call_vm_function(
        &mut self,
        target: &VmCallTarget,
        args: &[Value],
        prepared: PreparedVmFrame,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        if hooks_enabled {
            let event = HookEvent::BeforeFunctionCall(
                HookCallTarget::vm_function(target.name()),
                args.to_vec(),
            );
            self.trigger_hook_with_snapshot(&event)?;
        }

        self.push_prepared_vm_frame(target, prepared)
    }

    pub(crate) fn call_closure_value(
        &mut self,
        closure_value: &Value,
        args: &[Value],
        hooks_enabled: bool,
    ) -> VmResult<()> {
        let closure = match closure_value {
            Value::Closure(closure) => closure,
            other => {
                return Err(VmError::ExpectedClosure {
                    actual: other.type_name(),
                });
            }
        };

        let function_name = closure.function_id().to_owned();
        let upvalues = closure.upvalues().to_vec();
        let target = self
            .program
            .vm_call_target_with_foreign_error(&function_name, |name| {
                VmError::ForeignFunctionAsClosure {
                    function: name.to_owned(),
                }
            })?;
        self.validate_vm_call_arity(&target, args.len())?;
        let prepared_args = self.prepare_register_arguments(args)?;

        if hooks_enabled {
            let event = HookEvent::BeforeFunctionCall(
                HookCallTarget::closure(closure.function_id()),
                args.to_vec(),
            );
            self.trigger_hook_with_snapshot(&event)?;
        }

        self.push_prepared_vm_frame(
            &target,
            PreparedVmFrame::closure(prepared_args, upvalues, Arc::clone(closure)),
        )
    }

    pub(crate) fn create_closure_value(
        &mut self,
        function_name: String,
        upvalue_names: &[String],
    ) -> VmResult<Value> {
        let mut upvalues = Vec::with_capacity(upvalue_names.len());
        for name in upvalue_names {
            let value = self
                .find_upvalue(name)
                .ok_or_else(|| VmError::ClosureUpvalueNotFound { name: name.clone() })?;

            upvalues.push(Upvalue::new(name.clone(), value));
        }

        let closure = Closure::new(function_name.clone(), upvalues.clone());
        let event = HookEvent::ClosureCreated(function_name, upvalues);
        self.trigger_hook_with_snapshot(&event)?;

        Ok(Value::Closure(Arc::new(closure)))
    }

    pub(crate) fn get_upvalue_value(&self, name: &str) -> VmResult<Value> {
        let record = self.current_frame()?;
        for upvalue in record.upvalues().iter().rev() {
            if upvalue.name() == name {
                let value = upvalue.value().clone();
                let event = HookEvent::UpvalueRead(name.to_owned(), value.clone());
                self.trigger_hook_with_snapshot(&event)?;

                return Ok(value);
            }
        }

        Err(VmError::UpvalueReadNotFound {
            name: name.to_owned(),
        })
    }

    pub(crate) fn set_upvalue_value(&mut self, name: &str, new_value: Value) -> VmResult<()> {
        let (old_value, current_closure_arc) = {
            let record = self.current_frame_mut()?;

            let upvalue =
                record
                    .upvalue_mut(name)
                    .ok_or_else(|| VmError::UpvalueWriteNotFound {
                        name: name.to_owned(),
                    })?;
            let old_value = upvalue.value().clone();
            upvalue.set_value(new_value.clone());

            let current_closure_arc = record.closure().cloned();

            (old_value, current_closure_arc)
        };

        let event = HookEvent::UpvalueWrite(name.to_owned(), old_value, new_value.clone());
        self.trigger_hook_with_snapshot(&event)?;

        if let Some(current_closure) = current_closure_arc {
            let mut new_closure = (*current_closure).clone();

            for upvalue in new_closure.upvalues_mut() {
                if upvalue.name() == name {
                    upvalue.set_value(new_value.clone());
                    break;
                }
            }

            let new_closure_arc = Arc::new(new_closure);
            self.replace_closure_references(&current_closure, new_closure_arc);
        }

        Ok(())
    }

    fn call_foreign_function_internal(
        &mut self,
        function_name: &str,
        foreign_func: &ForeignFunction,
        args: &[Value],
        hooks_enabled: bool,
        checkpoint: CallStackCheckpoint,
    ) -> VmResult<InstructionOutcome> {
        let call_target = HookCallTarget::foreign_function(function_name);

        if hooks_enabled {
            let event = HookEvent::BeforeFunctionCall(call_target.clone(), args.to_vec());
            self.trigger_hook_with_snapshot(&event)?;
        }

        let context = ForeignFunctionContext::new(args, self);
        let result = foreign_func.call(context)?;

        if checkpoint.has_active_frame(self.call_stack.len()) {
            return Ok(InstructionOutcome::Continue);
        }

        if self.call_stack.is_empty() {
            return Ok(InstructionOutcome::Return(result));
        }

        let return_register = self.current_return_register()?;
        self.complete_foreign_function_return(return_register, call_target, result, hooks_enabled)?;

        Ok(InstructionOutcome::Continue)
    }

    pub(super) fn complete_foreign_function_return(
        &mut self,
        return_register: RuntimeRegister,
        call_target: HookCallTarget,
        result: Value,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        let (old_value, result) = self.assign_current_register(return_register, result)?;
        if hooks_enabled {
            let reg_event = HookEvent::RegisterWrite(
                self.hook_register(return_register)?,
                old_value,
                result.clone(),
            );
            self.trigger_hook_with_snapshot(&reg_event)?;

            let fn_event = HookEvent::AfterFunctionCall(call_target, result);
            self.trigger_hook_with_snapshot(&fn_event)?;
        }

        Ok(())
    }

    pub(super) fn execute_ret(
        &mut self,
        reg: RuntimeRegister,
        instruction: &Instruction,
        hooks_enabled: bool,
        checkpoint: CallStackCheckpoint,
    ) -> VmResult<InstructionOutcome> {
        let return_value = self.resolve_register(reg)?.into_value();

        self.return_current_frame(return_value, Some(instruction), hooks_enabled, checkpoint)
    }

    pub(super) fn return_current_frame(
        &mut self,
        return_value: Value,
        completed_instruction: Option<&Instruction>,
        hooks_enabled: bool,
        checkpoint: CallStackCheckpoint,
    ) -> VmResult<InstructionOutcome> {
        let frame_depth = self.current_frame_depth()?;
        let returning_from = self.current_hook_call_target()?;
        self.mpc_runtime.clear_frame_reveals(frame_depth);

        self.update_closure_upvalues()?;

        if checkpoint.is_returning_from_entry_frame(self.call_stack.len()) {
            if hooks_enabled {
                if let Some(instruction) = completed_instruction {
                    let event = HookEvent::AfterInstructionExecute(instruction.clone());
                    self.trigger_hook_with_snapshot(&event)?;
                }
            }
            self.call_stack.pop();
            self.clear_current_instruction();
            return Ok(InstructionOutcome::Return(return_value));
        }

        self.call_stack.pop();
        self.sync_current_instruction_to_current_frame();

        let return_register = self.current_return_register()?;
        let (old_value, return_value) =
            self.assign_current_register(return_register, return_value)?;
        if hooks_enabled {
            let event = HookEvent::RegisterWrite(
                self.hook_register(return_register)?,
                old_value,
                return_value.clone(),
            );
            self.trigger_hook_with_snapshot(&event)?;

            let event = HookEvent::AfterFunctionCall(returning_from, return_value);
            self.trigger_hook_with_snapshot(&event)?;
        }

        Ok(InstructionOutcome::Continue)
    }

    fn current_hook_call_target(&self) -> VmResult<HookCallTarget> {
        let record = self.current_frame()?;
        if record.closure().is_some() {
            Ok(HookCallTarget::closure(record.function_name()))
        } else {
            Ok(HookCallTarget::vm_function(record.function_name()))
        }
    }

    fn update_closure_upvalues(&mut self) -> VmResult<()> {
        let record = self.current_frame_mut()?;
        if let Some(closure_arc) = record.closure().cloned() {
            let mut new_closure = (*closure_arc).clone();
            new_closure.replace_upvalues(record.upvalues().to_vec());
            record.set_closure(Some(Arc::new(new_closure)));
        }
        Ok(())
    }
}
