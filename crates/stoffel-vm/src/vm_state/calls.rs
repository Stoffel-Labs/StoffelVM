use super::{execution::InstructionOutcome, CallStackCheckpoint, VMState};
use crate::error::{VmError, VmResult};
use crate::foreign_functions::{
    ForeignArguments, ForeignFunction, ForeignFunctionCallbackError, ForeignFunctionCallbackResult,
    ForeignFunctionContext, ForeignFunctionError, MpcOnlineBuiltin,
};
use crate::mpc_values::clear_share_input;
use crate::mpc_values::share_object::{self, ShareOrScalar};
use crate::net::client_store::ClientOutputShareCount;
use crate::net::mpc_engine::{MpcExponentGenerator, MpcPartyId};
use crate::net::share_runtime::ensure_matching_share_data_format;
use crate::program::{CallTarget, VmCallTarget};
use crate::runtime_hooks::{HookCallTarget, HookEvent};
use crate::runtime_instruction::RuntimeRegister;
use crate::standard_library::encode_output_share_list;
use crate::value_conversions::value_to_usize;
use crate::vm_state::mpc_operation::{
    PendingMpcBuiltinCall, PendingMpcBuiltinOperation, PendingMpcOperation,
};
use smallvec::SmallVec;
use std::borrow::Cow;
use std::sync::Arc;
use stoffel_vm_types::core_types::{
    Closure, ObjectRef, ShareData, ShareType, TableRef, Upvalue, Value,
};
use stoffel_vm_types::instructions::Instruction;
use stoffel_vm_types::registers::RegisterIndex;

struct PreparedVmFrame {
    register_args: SmallVec<[Value; 8]>,
    upvalues: Vec<Upvalue>,
    closure: Option<Arc<Closure>>,
}

impl PreparedVmFrame {
    fn entry(register_args: SmallVec<[Value; 8]>) -> Self {
        Self {
            register_args,
            upvalues: Vec::new(),
            closure: None,
        }
    }

    fn function(register_args: SmallVec<[Value; 8]>, upvalues: Vec<Upvalue>) -> Self {
        Self {
            register_args,
            upvalues,
            closure: None,
        }
    }

    fn closure(
        register_args: SmallVec<[Value; 8]>,
        upvalues: Vec<Upvalue>,
        closure: Arc<Closure>,
    ) -> Self {
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

struct ResolvedCallTarget<'name> {
    name: Cow<'name, str>,
    target: CallTarget,
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
        let resolved = self.resolve_call_target(function_name)?;
        let function_name = resolved.name;
        let function = resolved.target;

        match function {
            CallTarget::Vm(target) => {
                let arg_count = self.current_frame()?.stack().len();
                if arg_count == 0 {
                    if !hooks_enabled
                        && target.parameters().is_empty()
                        && target.upvalues().is_empty()
                    {
                        self.push_empty_vm_frame_without_hooks(&target);
                    } else {
                        let prepared = self.prepare_vm_call_without_args(&target)?;
                        self.call_vm_function(&target, &[], prepared, hooks_enabled)?;
                    }
                } else {
                    if !hooks_enabled && self.can_move_call_args_directly(&target, arg_count) {
                        let upvalues = self.collect_vm_call_upvalues(&target)?;
                        let drained_args = self.drain_call_args(false)?;
                        let prepared =
                            PreparedVmFrame::function(drained_args.into_values(), upvalues);
                        self.push_prepared_vm_frame(&target, prepared)?;
                    } else {
                        let prepared = {
                            let args = self.current_frame()?.stack();
                            self.prepare_vm_call(&target, args)?
                        };
                        let drained_args = self.drain_call_args(hooks_enabled)?;
                        if let Err(error) = self.call_vm_function(
                            &target,
                            drained_args.as_slice(),
                            prepared,
                            hooks_enabled,
                        ) {
                            self.restore_call_args_after_error(drained_args)?;
                            return Err(error);
                        }
                    }
                }
            }
            CallTarget::Foreign(foreign_func) => {
                let arg_count = self.current_frame()?.stack().len();
                if arg_count == 0 {
                    let checkpoint = CallStackCheckpoint::new(self.call_stack.len());
                    let outcome = self.call_foreign_function_internal(
                        function_name.as_ref(),
                        foreign_func.as_ref(),
                        &[],
                        hooks_enabled,
                        checkpoint,
                    )?;
                    if let InstructionOutcome::Return(_) = outcome {
                        return Ok(outcome);
                    }
                } else {
                    let args = self.drain_call_args(hooks_enabled)?;
                    let outcome = match self.call_foreign_function_internal(
                        function_name.as_ref(),
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
        }

        Ok(InstructionOutcome::Continue)
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

    pub(super) fn call_target(&mut self, function_name: &str) -> VmResult<CallTarget> {
        if let Some((cached_name, target)) = &self.last_call_target {
            if cached_name.as_ref() == function_name {
                return Ok(target.clone());
            }
        }

        let target = self.program.call_target(function_name)?;
        self.last_call_target = Some((Arc::from(function_name), target.clone()));
        Ok(target)
    }

    fn resolve_call_target<'name>(
        &mut self,
        function_name: &'name str,
    ) -> VmResult<ResolvedCallTarget<'name>> {
        if let Some((receiver_type, method_name)) = function_name.split_once('.') {
            if self
                .program
                .method_target_name(receiver_type, method_name)
                .is_some()
            {
                let Some(receiver) = self.current_frame()?.stack().first().cloned() else {
                    return Err(VmError::MethodCallRequiresReceiver {
                        method: function_name.to_owned(),
                    });
                };
                let actual = self.runtime_type_name(&receiver)?;
                if actual != receiver_type {
                    return Err(VmError::MethodReceiverTypeMismatch {
                        method: method_name.to_owned(),
                        expected: receiver_type.to_owned(),
                        actual,
                    });
                }
            }

            return Ok(ResolvedCallTarget {
                name: Cow::Borrowed(function_name),
                target: self.call_target(function_name)?,
            });
        }

        // Program-defined functions and registered builtins take precedence:
        // a user function named `sub` must stay callable even though `sub`
        // is also a method name in the registry (UFCS: x.f(y) == f(x, y)).
        let direct_err = match self.call_target(function_name) {
            Ok(target) => {
                return Ok(ResolvedCallTarget {
                    name: Cow::Borrowed(function_name),
                    target,
                });
            }
            Err(error) => error,
        };

        if self
            .program
            .receiver_types_for_method(function_name)
            .is_some()
        {
            let Some(receiver) = self.current_frame()?.stack().first().cloned() else {
                return Err(VmError::MethodCallRequiresReceiver {
                    method: function_name.to_owned(),
                });
            };
            let actual = self.runtime_type_name(&receiver)?;

            if let Some(canonical_name) = self
                .program
                .method_target_name(&actual, function_name)
                .map(str::to_owned)
            {
                let target = self.program.call_target(&canonical_name)?;
                return Ok(ResolvedCallTarget {
                    name: Cow::Owned(canonical_name),
                    target,
                });
            }

            return Err(VmError::MethodNotFound {
                method: function_name.to_owned(),
                receiver_type: actual,
            });
        }

        Err(direct_err)
    }

    fn runtime_type_name(&mut self, value: &Value) -> VmResult<String> {
        if let Some(object_ref) = ObjectRef::from_value(value) {
            let type_field = self.table_memory.read_table_field(
                TableRef::from(object_ref),
                &Value::String("__type".to_owned()),
            )?;
            if let Some(Value::String(type_name)) = type_field {
                return Ok(type_name);
            }
            return Ok("object".to_owned());
        }

        Ok(match value {
            Value::Share(_, _) => "Share",
            other => other.type_name(),
        }
        .to_owned())
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
        let upvalues = self.collect_vm_call_upvalues(target)?;
        let prepared_args = self.prepare_register_arguments(args)?;
        Ok(PreparedVmFrame::function(prepared_args, upvalues))
    }

    fn prepare_vm_call_without_args(&self, target: &VmCallTarget) -> VmResult<PreparedVmFrame> {
        self.validate_vm_call_arity(target, 0)?;
        let upvalues = self.collect_vm_call_upvalues(target)?;

        Ok(PreparedVmFrame::function(SmallVec::new(), upvalues))
    }

    fn can_move_call_args_directly(&self, target: &VmCallTarget, arg_count: usize) -> bool {
        if target.parameters().len() != arg_count || arg_count > target.frame_register_count() {
            return false;
        }

        (0..arg_count).all(|register| self.register_layout.is_clear(RegisterIndex::new(register)))
    }

    fn collect_vm_call_upvalues(&self, target: &VmCallTarget) -> VmResult<Vec<Upvalue>> {
        let mut upvalues = Vec::with_capacity(target.upvalues().len());
        for name in target.upvalues() {
            let value = self
                .find_upvalue(name)
                .ok_or_else(|| VmError::UpvalueNotFound { name: name.clone() })?;
            upvalues.push(Upvalue::new(name.clone(), value));
        }

        Ok(upvalues)
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
        let CallTarget::Foreign(foreign_func) = self.resolve_call_target(function_name)?.target
        else {
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

    /// Clear integer operands that can scale a share locally.
    fn clear_integer_scalar(value: &Value) -> Option<i64> {
        match value {
            Value::I64(v) => Some(*v),
            Value::I32(v) => Some(i64::from(*v)),
            Value::I16(v) => Some(i64::from(*v)),
            Value::I8(v) => Some(i64::from(*v)),
            Value::U8(v) => Some(i64::from(*v)),
            Value::U16(v) => Some(i64::from(*v)),
            Value::U32(v) => Some(i64::from(*v)),
            Value::U64(v) => i64::try_from(*v).ok(),
            _ => None,
        }
    }

    /// If one operand is a share and the other a clear integer, compute the
    /// product as a local scaling (no multiplication triple needed).
    fn try_local_scalar_mul(
        &mut self,
        left: &Value,
        right: &Value,
    ) -> ForeignFunctionCallbackResult<Option<PendingMpcBuiltinOperation>> {
        let (share_value, scalar) = match (
            Self::clear_integer_scalar(left),
            Self::clear_integer_scalar(right),
        ) {
            (None, Some(scalar)) => (left, scalar),
            (Some(scalar), None) => (right, scalar),
            _ => return Ok(None),
        };
        if !share_object::is_share_object(self.table_memory.as_mut(), share_value) {
            return Ok(None);
        }
        let (share_type, share_data) = self.extract_share_data(share_value)?;
        let share_data = self
            .share_runtime()?
            .mul_scalar_data(share_type, &share_data, scalar)?;
        Ok(Some(PendingMpcBuiltinOperation::LocalShare {
            share_type,
            share_data,
        }))
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
            MpcOnlineBuiltin::FromClearUInt => {
                args.require_min(2, "2 arguments: value, bit_length")?;
                let clear_value = args.cloned(0)?;
                let bit_length = args.usize(1, "bit_length")?;
                let clear =
                    clear_share_input(&clear_value, Some(ShareType::try_secret_uint(bit_length)?))?;
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
                // A share multiplied by a clear integer is a local scaling;
                // no multiplication triple or MPC round is needed.
                if let Some(operation) = self.try_local_scalar_mul(&left, &right)? {
                    return Ok(operation);
                }
                let (share_type, left_data, right_data) =
                    self.extract_matching_share_pair(&left, &right, "Share.mul")?;
                ensure_matching_share_data_format("async_multiply_share", &left_data, &right_data)?;
                Ok(PendingMpcBuiltinOperation::Mul {
                    share_type,
                    left_data,
                    right_data,
                })
            }
            MpcOnlineBuiltin::BatchMul => {
                args.require_exact(2, "2 arguments: lefts_array, rights_array")?;
                let lefts_arg = args.cloned(0)?;
                let rights_arg = args.cloned(1)?;
                let lefts =
                    self.extract_share_or_scalar_array(&lefts_arg, "Share.batch_mul lefts_array")?;
                let rights = self
                    .extract_share_or_scalar_array(&rights_arg, "Share.batch_mul rights_array")?;

                if lefts.is_empty() && rights.is_empty() {
                    return Ok(PendingMpcBuiltinOperation::BatchMul {
                        share_type: ShareType::default_secret_int(),
                        left_data: Vec::new(),
                        right_data: Vec::new(),
                    });
                }
                if lefts.len() != rights.len() {
                    return Err("Share.batch_mul requires arrays with the same length".into());
                }

                // Pairs with a clear integer operand are local scalings and
                // are computed immediately; only share-by-share pairs go to
                // the engine.
                let mut share_type: Option<ShareType> = None;
                let mut precomputed: Vec<Option<ShareData>> = Vec::with_capacity(lefts.len());
                let mut left_data: Vec<ShareData> = Vec::new();
                let mut right_data: Vec<ShareData> = Vec::new();

                let mut require_type = |ty: ShareType| -> Result<(), ForeignFunctionCallbackError> {
                    match share_type {
                        None => {
                            share_type = Some(ty);
                            Ok(())
                        }
                        Some(existing) if existing == ty => Ok(()),
                        Some(_) => {
                            Err("Share.batch_mul requires arrays with matching share types".into())
                        }
                    }
                };

                let mut local_products: Vec<(usize, ShareType, ShareData, i64)> = Vec::new();
                for (index, (left, right)) in lefts.into_iter().zip(rights).enumerate() {
                    match (left, right) {
                        (ShareOrScalar::Share(lt, ld), ShareOrScalar::Share(rt, rd)) => {
                            require_type(lt)?;
                            require_type(rt)?;
                            ensure_matching_share_data_format(
                                "async_batch_multiply_share",
                                &ld,
                                &rd,
                            )?;
                            precomputed.push(None);
                            left_data.push(ld);
                            right_data.push(rd);
                        }
                        (ShareOrScalar::Share(ty, data), ShareOrScalar::Scalar(scalar))
                        | (ShareOrScalar::Scalar(scalar), ShareOrScalar::Share(ty, data)) => {
                            require_type(ty)?;
                            precomputed.push(None); // placeholder, filled below
                            local_products.push((index, ty, data, scalar));
                        }
                        (ShareOrScalar::Scalar(_), ShareOrScalar::Scalar(_)) => {
                            return Err(
                                "Share.batch_mul requires at least one share per pair".into()
                            );
                        }
                    }
                }

                for (index, ty, data, scalar) in local_products {
                    let scaled = self.share_runtime()?.mul_scalar_data(ty, &data, scalar)?;
                    precomputed[index] = Some(scaled);
                }

                let share_type =
                    share_type.expect("non-empty batch always sees at least one share");

                if precomputed.iter().all(Option::is_none) {
                    // Pure share-by-share batch: keep the original operation
                    // shape (and its effect accounting).
                    return Ok(PendingMpcBuiltinOperation::BatchMul {
                        share_type,
                        left_data,
                        right_data,
                    });
                }

                Ok(PendingMpcBuiltinOperation::BatchMulMixed {
                    share_type,
                    precomputed,
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
                    client_id,
                    share_bytes: share_data.as_bytes().to_vec(),
                    output_share_count: ClientOutputShareCount::one(),
                })
            }
            MpcOnlineBuiltin::OutputSendToClient => {
                args.require_exact(2, "2 arguments: client_id, share_value")?;
                let client_id = args.usize(0, "client_id")?;
                let output_value = args.cloned(1)?;

                let (share_bytes, output_share_count) = match &output_value {
                    Value::Array(_) => {
                        let Some((_share_type, share_data)) = self
                            .extract_homogeneous_share_array(
                                &output_value,
                                "MpcOutput.send_to_client share_value",
                            )?
                        else {
                            return Err(
                                "MpcOutput.send_to_client requires at least one output share"
                                    .into(),
                            );
                        };
                        let output_share_count = ClientOutputShareCount::try_new(share_data.len())
                            .map_err(|error| error.to_string())?;
                        (encode_output_share_list(&share_data)?, output_share_count)
                    }
                    _ => {
                        let (_share_type, share_data) = self.extract_share_data(&output_value)?;
                        (
                            share_data.as_bytes().to_vec(),
                            ClientOutputShareCount::one(),
                        )
                    }
                };

                Ok(PendingMpcBuiltinOperation::SendToClient {
                    client_id,
                    share_bytes,
                    output_share_count,
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
            MpcOnlineBuiltin::Random | MpcOnlineBuiltin::RandomField => {
                Ok(PendingMpcBuiltinOperation::Random {
                    share_type: ShareType::default_secret_int(),
                })
            }
            MpcOnlineBuiltin::RandomInt => {
                args.require_exact(1, "1 argument: bit_length")?;
                let bit_length = args.usize(0, "bit_length")?;
                Ok(PendingMpcBuiltinOperation::RandomInt {
                    share_type: ShareType::try_secret_int(bit_length)?,
                })
            }
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
        }
    }

    fn push_prepared_vm_frame(
        &mut self,
        target: &VmCallTarget,
        prepared: PreparedVmFrame,
    ) -> VmResult<()> {
        let record = target.instantiate_frame(
            self.register_layout,
            prepared.register_args,
            prepared.upvalues,
            prepared.closure,
        )?;
        self.push_activation_frame(record, Some(target.runtime_function()));
        Ok(())
    }

    fn push_empty_vm_frame_without_hooks(&mut self, target: &VmCallTarget) {
        let record = target.instantiate_empty_frame(self.register_layout);
        self.push_activation_frame(record, Some(target.runtime_function()));
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

        if self.hooks_enabled() {
            let closure = Closure::new(function_name.clone(), upvalues.clone());
            let event = HookEvent::ClosureCreated(function_name, upvalues);
            self.trigger_hook_with_snapshot(&event)?;
            return Ok(Value::Closure(Arc::new(closure)));
        }

        Ok(Value::Closure(Arc::new(Closure::new(
            function_name,
            upvalues,
        ))))
    }

    pub(crate) fn get_upvalue_value(&self, name: &str) -> VmResult<Value> {
        let record = self.current_frame()?;
        for upvalue in record.upvalues().iter().rev() {
            if upvalue.name() == name {
                let value = upvalue.value().clone();
                if self.hooks_enabled() {
                    let event = HookEvent::UpvalueRead(name.to_owned(), value.clone());
                    self.trigger_hook_with_snapshot(&event)?;
                }

                return Ok(value);
            }
        }

        Err(VmError::UpvalueReadNotFound {
            name: name.to_owned(),
        })
    }

    pub(crate) fn set_upvalue_value(&mut self, name: &str, new_value: Value) -> VmResult<()> {
        let hooks_enabled = self.hooks_enabled();
        let (old_value, current_closure_arc) = {
            let record = self.current_frame_mut()?;

            let upvalue =
                record
                    .upvalue_mut(name)
                    .ok_or_else(|| VmError::UpvalueWriteNotFound {
                        name: name.to_owned(),
                    })?;
            let old_value = hooks_enabled.then(|| upvalue.value().clone());
            upvalue.set_value(new_value.clone());

            let current_closure_arc = record.closure().cloned();

            (old_value, current_closure_arc)
        };

        if let Some(old_value) = old_value {
            let event = HookEvent::UpvalueWrite(name.to_owned(), old_value, new_value.clone());
            self.trigger_hook_with_snapshot(&event)?;
        }

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
        let call_target = if hooks_enabled {
            let call_target = HookCallTarget::foreign_function(function_name);
            let event = HookEvent::BeforeFunctionCall(call_target.clone(), args.to_vec());
            self.trigger_hook_with_snapshot(&event)?;
            Some(call_target)
        } else {
            None
        };

        let context = ForeignFunctionContext::new(args, self);
        let result = foreign_func.call(context)?;

        if checkpoint.has_active_frame(self.call_stack.len()) {
            return Ok(InstructionOutcome::Continue);
        }

        if self.call_stack.is_empty() {
            return Ok(InstructionOutcome::Return(result));
        }

        let return_register = self.current_return_register()?;
        if let Some(call_target) = call_target {
            self.complete_foreign_function_return(return_register, call_target, result, true)?;
        } else {
            self.assign_current_register_without_previous(return_register, result)?;
        }

        Ok(InstructionOutcome::Continue)
    }

    pub(super) fn complete_foreign_function_return(
        &mut self,
        return_register: RuntimeRegister,
        call_target: HookCallTarget,
        result: Value,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        if !hooks_enabled {
            return self.assign_current_register_without_previous(return_register, result);
        }

        let (old_value, result) = self.assign_current_register(return_register, result)?;
        let reg_event = HookEvent::RegisterWrite(
            self.hook_register(return_register)?,
            old_value,
            result.clone(),
        );
        self.trigger_hook_with_snapshot(&reg_event)?;

        let fn_event = HookEvent::AfterFunctionCall(call_target, result);
        self.trigger_hook_with_snapshot(&fn_event)?;

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
        self.mpc_runtime.clear_frame_reveals(frame_depth);

        self.update_closure_upvalues()?;

        if checkpoint.is_returning_from_entry_frame(self.call_stack.len()) {
            if hooks_enabled {
                if let Some(instruction) = completed_instruction {
                    let event = HookEvent::AfterInstructionExecute(instruction.clone());
                    self.trigger_hook_with_snapshot(&event)?;
                }
            }
            self.pop_activation_frame();
            self.clear_current_instruction();
            return Ok(InstructionOutcome::Return(return_value));
        }

        if !hooks_enabled {
            self.pop_activation_frame();
            self.sync_current_instruction_to_current_frame();

            let return_register = self.current_return_register()?;
            self.assign_current_register_without_previous(return_register, return_value)?;
            return Ok(InstructionOutcome::Continue);
        }

        let returning_from = self.current_hook_call_target()?;
        self.pop_activation_frame();
        self.sync_current_instruction_to_current_frame();

        let return_register = self.current_return_register()?;
        let (old_value, return_value) =
            self.assign_current_register(return_register, return_value)?;
        let event = HookEvent::RegisterWrite(
            self.hook_register(return_register)?,
            old_value,
            return_value.clone(),
        );
        self.trigger_hook_with_snapshot(&event)?;

        let event = HookEvent::AfterFunctionCall(returning_from, return_value);
        self.trigger_hook_with_snapshot(&event)?;

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
