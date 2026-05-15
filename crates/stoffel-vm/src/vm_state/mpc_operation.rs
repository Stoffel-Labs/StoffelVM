use super::{CompletedVmEffect, VMState};
use crate::error::{MpcBackendResultExt, VmError, VmResult};
use crate::mpc_values::clear_share_input;
use crate::net::client_store::ClientOutputShareCount;
use crate::net::mpc_engine::{
    AbaSessionId, AsyncMpcEngine, MpcEngine, MpcExponentGroup, MpcPartyId,
};
use crate::net::share_runtime::ensure_matching_share_data_format;
use crate::runtime_hooks::{HookCallTarget, HookEvent};
use crate::runtime_instruction::{RuntimeBinaryOp, RuntimeInstruction, RuntimeRegister};
use crate::runtime_value_ops::matching_share_pair;
use crate::value_conversions::{u64_to_vm_i64, usize_to_vm_i64};
use stoffel_vm_types::core_types::{
    ClearShareInput, ClearShareValue, ShareData, ShareType, TableRef, Value,
};
use stoffel_vm_types::registers::RegisterMoveKind;
use stoffelnet::network_utils::ClientId;

/// MPC protocol work that cannot be completed as a local VM step.
#[derive(Debug, Clone)]
pub(super) enum PendingMpcOperation {
    Input {
        clear: ClearShareInput,
        dest: RuntimeRegister,
    },
    Multiply {
        share_type: ShareType,
        left_data: ShareData,
        right_data: ShareData,
        dest: RuntimeRegister,
    },
    Open {
        share_type: ShareType,
        share_data: ShareData,
        src: RuntimeRegister,
        dest: RuntimeRegister,
    },
    BuiltinCall(PendingMpcBuiltinCall),
}

#[derive(Debug)]
pub(super) enum CompletedMpcOperation {
    Input {
        share_type: ShareType,
        share_data: ShareData,
        dest: RuntimeRegister,
    },
    Multiply {
        share_type: ShareType,
        share_data: ShareData,
        dest: RuntimeRegister,
    },
    Open {
        value: ClearShareValue,
        src: RuntimeRegister,
        dest: RuntimeRegister,
    },
    BuiltinCall(CompletedMpcBuiltinCall),
}

#[derive(Debug, Clone)]
pub(super) struct PendingMpcBuiltinCall {
    return_register: RuntimeRegister,
    call_target: HookCallTarget,
    operation: PendingMpcBuiltinOperation,
}

impl PendingMpcBuiltinCall {
    pub(super) fn new(
        return_register: RuntimeRegister,
        call_target: HookCallTarget,
        operation: PendingMpcBuiltinOperation,
    ) -> Self {
        Self {
            return_register,
            call_target,
            operation,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) enum PendingMpcBuiltinOperation {
    InputShare {
        clear: ClearShareInput,
    },
    Mul {
        share_type: ShareType,
        left_data: ShareData,
        right_data: ShareData,
    },
    Open {
        share_type: ShareType,
        share_data: ShareData,
    },
    BatchOpen {
        share_type: ShareType,
        share_data: Vec<ShareData>,
    },
    SendToClient {
        share_data: ShareData,
        client_id: ClientId,
    },
    OpenExp {
        group: MpcExponentGroup,
        share_type: ShareType,
        share_data: ShareData,
        generator_bytes: Vec<u8>,
    },
    Random {
        share_type: ShareType,
    },
    OpenField {
        share_type: ShareType,
        share_data: ShareData,
    },
    OpenExpCustom {
        share_type: ShareType,
        share_data: ShareData,
        generator_bytes: Vec<u8>,
    },
    RbcBroadcast {
        message: Vec<u8>,
    },
    RbcReceive {
        from_party: MpcPartyId,
        timeout_ms: u64,
    },
    RbcReceiveAny {
        timeout_ms: u64,
    },
    AbaPropose {
        value: bool,
    },
    AbaResult {
        session_id: AbaSessionId,
        timeout_ms: u64,
    },
    AbaProposeAndWait {
        value: bool,
        timeout_ms: u64,
    },
}

#[derive(Debug)]
pub(super) struct CompletedMpcBuiltinCall {
    return_register: RuntimeRegister,
    call_target: HookCallTarget,
    result: CompletedMpcBuiltinResult,
}

#[derive(Debug)]
pub(super) enum CompletedMpcBuiltinResult {
    Value(Value),
    ShareObject {
        share_type: ShareType,
        share_data: ShareData,
    },
    BatchOpen(Vec<ClearShareValue>),
    ByteArray(Vec<u8>),
    RbcReceiveAny {
        party_id: MpcPartyId,
        message: Vec<u8>,
    },
}

impl PendingMpcOperation {
    fn input_share(dest: RuntimeRegister, value: &Value) -> VmResult<Option<PendingMpcOperation>> {
        match value {
            Value::Share(_, _) | Value::Unit => Ok(None),
            clear => {
                let clear = clear_share_input(clear, None).map_err(|err| {
                    VmError::ClearValueInSecretRegister {
                        value_type: value.type_name(),
                        register: dest.index(),
                        reason: err.to_string(),
                    }
                })?;
                Ok(Some(PendingMpcOperation::Input { clear, dest }))
            }
        }
    }

    fn open_share(
        src: RuntimeRegister,
        dest: RuntimeRegister,
        value: Value,
    ) -> Option<PendingMpcOperation> {
        match value {
            Value::Share(share_type, share_data) => Some(PendingMpcOperation::Open {
                share_type,
                share_data,
                src,
                dest,
            }),
            _ => None,
        }
    }

    fn multiply_share(
        dest: RuntimeRegister,
        left: Value,
        right: Value,
    ) -> VmResult<Option<PendingMpcOperation>> {
        let Some(pair) = matching_share_pair("MUL", &left, &right)? else {
            return Ok(None);
        };

        ensure_matching_share_data_format("async_multiply_share", pair.left_data, pair.right_data)?;
        Ok(Some(PendingMpcOperation::Multiply {
            share_type: pair.share_type,
            left_data: pair.left_data.clone(),
            right_data: pair.right_data.clone(),
            dest,
        }))
    }

    pub(super) async fn execute_async<E: AsyncMpcEngine + ?Sized>(
        self,
        engine: &E,
    ) -> VmResult<CompletedMpcOperation> {
        self.ensure_engine_can_execute(engine)?;

        match self {
            PendingMpcOperation::Input { clear, dest } => {
                let share_type = clear.share_type();
                let share_data = engine
                    .input_share_async(clear)
                    .await
                    .map_mpc_backend_err("async_input_share")?;

                Ok(CompletedMpcOperation::Input {
                    share_type,
                    share_data,
                    dest,
                })
            }
            PendingMpcOperation::Multiply {
                share_type,
                left_data,
                right_data,
                dest,
            } => {
                let share_data = engine
                    .multiply_share_async(share_type, left_data.as_bytes(), right_data.as_bytes())
                    .await
                    .map_mpc_backend_err("async_multiply_share")?;

                Ok(CompletedMpcOperation::Multiply {
                    share_type,
                    share_data,
                    dest,
                })
            }
            PendingMpcOperation::Open {
                share_type,
                share_data,
                src,
                dest,
            } => {
                let value = engine
                    .open_share_async(share_type, share_data.as_bytes())
                    .await
                    .map_mpc_backend_err("async_open_share")?;

                Ok(CompletedMpcOperation::Open { value, src, dest })
            }
            PendingMpcOperation::BuiltinCall(call) => Ok(CompletedMpcOperation::BuiltinCall(
                call.execute_async(engine).await?,
            )),
        }
    }

    pub(super) fn ensure_engine_can_execute<E: AsyncMpcEngine + ?Sized>(
        &self,
        engine: &E,
    ) -> VmResult<()> {
        if !engine.is_ready() {
            return Err(VmError::MpcEngineNotReady);
        }

        match self {
            PendingMpcOperation::Input { .. } => {}
            PendingMpcOperation::Multiply { .. } => {
                engine
                    .multiplication_ops()
                    .map_mpc_backend_err("multiplication_ops")?;
            }
            PendingMpcOperation::Open { .. } => {}
            PendingMpcOperation::BuiltinCall(call) => call.ensure_engine_can_execute(engine)?,
        }

        Ok(())
    }
}

impl PendingMpcBuiltinCall {
    async fn execute_async<E: AsyncMpcEngine + ?Sized>(
        self,
        engine: &E,
    ) -> VmResult<CompletedMpcBuiltinCall> {
        let result = match self.operation {
            PendingMpcBuiltinOperation::InputShare { clear } => {
                let share_type = clear.share_type();
                let share_data = engine
                    .input_share_async(clear)
                    .await
                    .map_mpc_backend_err("async_input_share")?;
                CompletedMpcBuiltinResult::ShareObject {
                    share_type,
                    share_data,
                }
            }
            PendingMpcBuiltinOperation::Mul {
                share_type,
                left_data,
                right_data,
            } => {
                let share_data = engine
                    .multiply_share_async(share_type, left_data.as_bytes(), right_data.as_bytes())
                    .await
                    .map_mpc_backend_err("async_multiply_share")?;
                CompletedMpcBuiltinResult::ShareObject {
                    share_type,
                    share_data,
                }
            }
            PendingMpcBuiltinOperation::Open {
                share_type,
                share_data,
            } => {
                let value = engine
                    .open_share_async(share_type, share_data.as_bytes())
                    .await
                    .map_mpc_backend_err("async_open_share")?;
                CompletedMpcBuiltinResult::Value(value.into_vm_value())
            }
            PendingMpcBuiltinOperation::BatchOpen {
                share_type,
                share_data,
            } => {
                let share_bytes: Vec<Vec<u8>> = share_data
                    .iter()
                    .map(|share_data| share_data.as_bytes().to_vec())
                    .collect();
                let values = engine
                    .batch_open_shares_async(share_type, &share_bytes)
                    .await
                    .map_mpc_backend_err("async_batch_open_shares")?;
                CompletedMpcBuiltinResult::BatchOpen(values)
            }
            PendingMpcBuiltinOperation::SendToClient {
                share_data,
                client_id,
            } => {
                engine
                    .send_output_to_client_async(
                        client_id,
                        share_data.as_bytes(),
                        ClientOutputShareCount::one(),
                    )
                    .await
                    .map_mpc_backend_err("async_send_output_to_client")?;
                CompletedMpcBuiltinResult::Value(Value::Bool(true))
            }
            PendingMpcBuiltinOperation::OpenExp {
                group,
                share_type,
                share_data,
                generator_bytes,
            } => {
                let bytes = engine
                    .open_share_in_exp_group_async(
                        group,
                        share_type,
                        share_data.as_bytes(),
                        &generator_bytes,
                    )
                    .await
                    .map_mpc_backend_err("async_open_share_in_exp_group")?;
                CompletedMpcBuiltinResult::ByteArray(bytes)
            }
            PendingMpcBuiltinOperation::Random { share_type } => {
                let share_data = engine
                    .random_share_async(share_type)
                    .await
                    .map_mpc_backend_err("async_random_share")?;
                CompletedMpcBuiltinResult::ShareObject {
                    share_type,
                    share_data,
                }
            }
            PendingMpcBuiltinOperation::OpenField {
                share_type,
                share_data,
            } => {
                let bytes = engine
                    .open_share_as_field_async(share_type, share_data.as_bytes())
                    .await
                    .map_mpc_backend_err("async_open_share_as_field")?;
                CompletedMpcBuiltinResult::ByteArray(bytes)
            }
            PendingMpcBuiltinOperation::OpenExpCustom {
                share_type,
                share_data,
                generator_bytes,
            } => {
                let bytes = engine
                    .open_share_in_exp_async(share_type, share_data.as_bytes(), &generator_bytes)
                    .await
                    .map_mpc_backend_err("async_open_share_in_exp")?;
                CompletedMpcBuiltinResult::ByteArray(bytes)
            }
            PendingMpcBuiltinOperation::RbcBroadcast { message } => {
                let session_id = engine
                    .async_consensus_ops()
                    .map_mpc_backend_err("async_consensus_ops")?
                    .rbc_broadcast_async(&message)
                    .await
                    .map_mpc_backend_err("async_rbc_broadcast")?;
                CompletedMpcBuiltinResult::Value(session_id_value(session_id.id())?)
            }
            PendingMpcBuiltinOperation::RbcReceive {
                from_party,
                timeout_ms,
            } => {
                let message = engine
                    .async_consensus_ops()
                    .map_mpc_backend_err("async_consensus_ops")?
                    .rbc_receive_async(from_party, timeout_ms)
                    .await
                    .map_mpc_backend_err("async_rbc_receive")?;
                CompletedMpcBuiltinResult::Value(Value::String(consensus_message_to_string(
                    message,
                    "<binary data>",
                )))
            }
            PendingMpcBuiltinOperation::RbcReceiveAny { timeout_ms } => {
                let (party_id, message) = engine
                    .async_consensus_ops()
                    .map_mpc_backend_err("async_consensus_ops")?
                    .rbc_receive_any_async(timeout_ms)
                    .await
                    .map_mpc_backend_err("async_rbc_receive_any")?;
                CompletedMpcBuiltinResult::RbcReceiveAny { party_id, message }
            }
            PendingMpcBuiltinOperation::AbaPropose { value } => {
                let session_id = engine
                    .async_consensus_ops()
                    .map_mpc_backend_err("async_consensus_ops")?
                    .aba_propose_async(value)
                    .await
                    .map_mpc_backend_err("async_aba_propose")?;
                CompletedMpcBuiltinResult::Value(session_id_value(session_id.id())?)
            }
            PendingMpcBuiltinOperation::AbaResult {
                session_id,
                timeout_ms,
            } => {
                let result = engine
                    .async_consensus_ops()
                    .map_mpc_backend_err("async_consensus_ops")?
                    .aba_result_async(session_id, timeout_ms)
                    .await
                    .map_mpc_backend_err("async_aba_result")?;
                CompletedMpcBuiltinResult::Value(Value::Bool(result))
            }
            PendingMpcBuiltinOperation::AbaProposeAndWait { value, timeout_ms } => {
                let result = engine
                    .async_consensus_ops()
                    .map_mpc_backend_err("async_consensus_ops")?
                    .aba_propose_and_wait_async(value, timeout_ms)
                    .await
                    .map_mpc_backend_err("async_aba_propose_and_wait")?;
                CompletedMpcBuiltinResult::Value(Value::Bool(result))
            }
        };

        Ok(CompletedMpcBuiltinCall {
            return_register: self.return_register,
            call_target: self.call_target,
            result,
        })
    }

    fn ensure_engine_can_execute<E: AsyncMpcEngine + ?Sized>(&self, engine: &E) -> VmResult<()> {
        match &self.operation {
            PendingMpcBuiltinOperation::InputShare { .. } => {}
            PendingMpcBuiltinOperation::Mul { .. } => {
                engine
                    .multiplication_ops()
                    .map_mpc_backend_err("multiplication_ops")?;
            }
            PendingMpcBuiltinOperation::Open { .. }
            | PendingMpcBuiltinOperation::BatchOpen { .. } => {}
            PendingMpcBuiltinOperation::SendToClient { .. } => {
                engine
                    .client_output_ops()
                    .map_mpc_backend_err("client_output_ops")?;
            }
            PendingMpcBuiltinOperation::OpenExp { .. }
            | PendingMpcBuiltinOperation::OpenExpCustom { .. } => {
                engine
                    .open_in_exp_ops()
                    .map_mpc_backend_err("open_in_exp_ops")?;
            }
            PendingMpcBuiltinOperation::Random { .. } => {
                engine
                    .randomness_ops()
                    .map_mpc_backend_err("randomness_ops")?;
            }
            PendingMpcBuiltinOperation::OpenField { .. } => {
                engine
                    .field_open_ops()
                    .map_mpc_backend_err("field_open_ops")?;
            }
            PendingMpcBuiltinOperation::RbcBroadcast { .. }
            | PendingMpcBuiltinOperation::RbcReceive { .. }
            | PendingMpcBuiltinOperation::RbcReceiveAny { .. }
            | PendingMpcBuiltinOperation::AbaPropose { .. }
            | PendingMpcBuiltinOperation::AbaResult { .. }
            | PendingMpcBuiltinOperation::AbaProposeAndWait { .. } => {
                engine
                    .async_consensus_ops()
                    .map_mpc_backend_err("async_consensus_ops")?;
            }
        }

        Ok(())
    }
}

fn session_id_value(session_id: u64) -> VmResult<Value> {
    Ok(Value::I64(
        u64_to_vm_i64(session_id, "session_id")
            .map_err(|error| VmError::from(error.to_string()))?,
    ))
}

fn consensus_message_to_string(message: Vec<u8>, binary_fallback: &str) -> String {
    String::from_utf8(message).unwrap_or_else(|_| binary_fallback.to_string())
}

impl VMState {
    pub(super) fn plan_async_mpc_operation(
        &mut self,
        instruction: &RuntimeInstruction,
        hooks_enabled: bool,
    ) -> VmResult<Option<PendingMpcOperation>> {
        match instruction {
            RuntimeInstruction::LoadImmediate { dest, value } => {
                if !self
                    .current_register_layout()?
                    .is_secret(dest.register_index())
                {
                    return Ok(None);
                }

                PendingMpcOperation::input_share(*dest, value)
            }
            RuntimeInstruction::Move { dest, src } => {
                if self
                    .current_register_layout()?
                    .move_kind(dest.register_index(), src.register_index())
                    != RegisterMoveKind::SecretToClear
                {
                    return Ok(None);
                }

                let src_value = self.resolve_register(*src)?.into_value();
                Ok(PendingMpcOperation::open_share(*src, *dest, src_value))
            }
            RuntimeInstruction::Binary {
                op: RuntimeBinaryOp::Multiply,
                dest,
                lhs,
                rhs,
            } => {
                let (left, right) = self.resolve_register_pair(*lhs, *rhs)?.into_values();
                PendingMpcOperation::multiply_share(*dest, left, right)
            }
            RuntimeInstruction::Call { function } => {
                self.plan_async_mpc_builtin_call(function, hooks_enabled)
            }
            _ => Ok(None),
        }
    }

    pub(crate) fn ensure_async_engine_matches<E: MpcEngine + ?Sized>(
        &self,
        engine: &E,
    ) -> VmResult<()> {
        let configured = self.mpc_runtime.configured_engine()?;

        let configured_identity = configured.identity();
        let async_identity = engine.identity();

        if configured_identity != async_identity {
            return Err(VmError::AsyncMpcEngineMismatch {
                runtime: async_identity,
                configured: configured_identity,
            });
        }

        Ok(())
    }

    pub(crate) fn apply_completed_vm_effect(&mut self, effect: CompletedVmEffect) -> VmResult<()> {
        let (operation, after_instruction, hooks_enabled) = effect.into_parts();
        self.apply_completed_mpc_operation(operation, hooks_enabled)?;

        if hooks_enabled {
            let event = HookEvent::AfterInstructionExecute(after_instruction);
            self.trigger_hook_with_snapshot(&event)?;
        }

        Ok(())
    }

    pub(super) fn apply_completed_mpc_operation(
        &mut self,
        operation: CompletedMpcOperation,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        match operation {
            CompletedMpcOperation::Input {
                share_type,
                share_data,
                dest,
            } => {
                self.write_current_register(
                    dest,
                    Value::Share(share_type, share_data),
                    hooks_enabled,
                )?;
                Ok(())
            }
            CompletedMpcOperation::Multiply {
                share_type,
                share_data,
                dest,
            } => {
                self.write_current_register(
                    dest,
                    Value::Share(share_type, share_data),
                    hooks_enabled,
                )?;
                Ok(())
            }
            CompletedMpcOperation::Open { value, src, dest } => {
                self.write_mov_result(dest, src, value.into_vm_value(), hooks_enabled)?;
                Ok(())
            }
            CompletedMpcOperation::BuiltinCall(call) => {
                let result = self.materialize_mpc_builtin_result(call.result)?;
                self.complete_foreign_function_return(
                    call.return_register,
                    call.call_target,
                    result,
                    hooks_enabled,
                )
            }
        }
    }

    fn materialize_mpc_builtin_result(
        &mut self,
        result: CompletedMpcBuiltinResult,
    ) -> VmResult<Value> {
        match result {
            CompletedMpcBuiltinResult::Value(value) => Ok(value),
            CompletedMpcBuiltinResult::ShareObject {
                share_type,
                share_data,
            } => {
                let party_id = self
                    .mpc_runtime_info()
                    .ok_or(VmError::MpcEngineNotConfigured)?
                    .party()
                    .id();
                self.create_share_object_value(share_type, share_data, party_id)
            }
            CompletedMpcBuiltinResult::BatchOpen(values) => {
                let revealed: Vec<Value> = values
                    .into_iter()
                    .map(ClearShareValue::into_vm_value)
                    .collect();
                let result_ref = self.create_array_ref(revealed.len())?;
                self.push_array_ref_values(result_ref, &revealed)?;
                Ok(Value::from(result_ref))
            }
            CompletedMpcBuiltinResult::ByteArray(bytes) => self.create_byte_array(&bytes),
            CompletedMpcBuiltinResult::RbcReceiveAny { party_id, message } => {
                let object_ref = self.create_object_ref()?;
                let table_ref = TableRef::from(object_ref);
                for (key, value) in [
                    (
                        Value::String("party_id".to_string()),
                        Value::I64(
                            usize_to_vm_i64(party_id.id(), "party_id")
                                .map_err(|error| VmError::from(error.to_string()))?,
                        ),
                    ),
                    (
                        Value::String("message".to_string()),
                        Value::String(consensus_message_to_string(message, "<binary>")),
                    ),
                ] {
                    self.set_table_field(table_ref, key, value)?;
                }
                Ok(Value::from(object_ref))
            }
        }
    }
}
