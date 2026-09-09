use super::{CompletedVmEffect, VMState};
use crate::error::{MpcBackendResultExt, VmError, VmResult};
use crate::foreign_functions::ForeignFunctionError;
use crate::mpc_values::clear_share_input;
use crate::net::client_store::ClientOutputShareCount;
use crate::net::curve::clear_share_value_to_vm_value;
use crate::net::mpc_engine::{AsyncMpcEngine, MpcEngine, MpcExponentGroup, MpcPartyId};
use crate::net::share_runtime::ensure_matching_share_data_format;
use crate::runtime_hooks::{HookCallTarget, HookEvent};
#[cfg(test)]
use crate::runtime_instruction::RuntimeInstruction;
use crate::runtime_instruction::{
    FetchedInstruction, RuntimeBinaryOp, RuntimeOpcode, RuntimeRegister,
};
use crate::runtime_value_ops::{bool_or_data, bool_xor_data, matching_share_pair};
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
    BooleanBit {
        op: RuntimeBinaryOp,
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
    BooleanBit {
        op: RuntimeBinaryOp,
        share_type: ShareType,
        left_data: ShareData,
        right_data: ShareData,
        product_data: ShareData,
        dest: RuntimeRegister,
    },
    Open {
        share_type: ShareType,
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

    pub(crate) const fn operation(&self) -> &PendingMpcBuiltinOperation {
        &self.operation
    }
}

#[derive(Debug, Clone)]
pub(crate) enum PendingMpcBuiltinOperation {
    InputShare {
        clear: ClearShareInput,
    },
    Mul {
        share_type: ShareType,
        left_data: ShareData,
        right_data: ShareData,
    },
    BatchMul {
        share_type: ShareType,
        left_data: Vec<ShareData>,
        right_data: Vec<ShareData>,
    },
    /// A share already combined with a public scalar locally; completes
    /// without any MPC interaction.
    LocalShare {
        share_type: ShareType,
        share_data: ShareData,
    },
    /// Batch multiplication where some pairs were share-by-public-scalar
    /// products computed locally (`precomputed[i] == Some(data)`), and the
    /// remaining `None` slots are filled, in order, from the engine batch
    /// over `left_data`/`right_data`.
    BatchMulMixed {
        share_type: ShareType,
        precomputed: Vec<Option<ShareData>>,
        left_data: Vec<ShareData>,
        right_data: Vec<ShareData>,
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
        share_bytes: Vec<u8>,
        client_id: ClientId,
        output_share_count: ClientOutputShareCount,
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
    RandomInt {
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
    ShareValue {
        share_type: ShareType,
        share_data: ShareData,
    },
    ShareValues {
        share_type: ShareType,
        share_data: Vec<ShareData>,
    },
    BatchOpen {
        share_type: ShareType,
        values: Vec<ClearShareValue>,
    },
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

    fn boolean_bit_share(
        op: RuntimeBinaryOp,
        dest: RuntimeRegister,
        left: Value,
        right: Value,
    ) -> VmResult<Option<PendingMpcOperation>> {
        let operation = match op {
            RuntimeBinaryOp::BitAnd => "AND",
            RuntimeBinaryOp::BitOr => "OR",
            RuntimeBinaryOp::BitXor => "XOR",
            _ => return Ok(None),
        };
        let Some(pair) = matching_share_pair(operation, &left, &right)? else {
            return Ok(None);
        };

        if pair.share_type != ShareType::boolean() {
            return Ok(None);
        }

        ensure_matching_share_data_format(
            "async_boolean_bit_share",
            pair.left_data,
            pair.right_data,
        )?;
        Ok(Some(PendingMpcOperation::BooleanBit {
            op,
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
            PendingMpcOperation::BooleanBit {
                op,
                share_type,
                left_data,
                right_data,
                dest,
            } => {
                let product_data = engine
                    .multiply_share_async(share_type, left_data.as_bytes(), right_data.as_bytes())
                    .await
                    .map_mpc_backend_err("async_boolean_bit_share")?;

                Ok(CompletedMpcOperation::BooleanBit {
                    op,
                    share_type,
                    left_data,
                    right_data,
                    product_data,
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

                Ok(CompletedMpcOperation::Open {
                    share_type,
                    value,
                    src,
                    dest,
                })
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
            PendingMpcOperation::Multiply { .. } | PendingMpcOperation::BooleanBit { .. } => {
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
                CompletedMpcBuiltinResult::ShareValue {
                    share_type,
                    share_data,
                }
            }
            PendingMpcBuiltinOperation::BatchMul {
                share_type,
                left_data,
                right_data,
            } => {
                let pairs: Vec<(Vec<u8>, Vec<u8>)> = left_data
                    .iter()
                    .zip(right_data.iter())
                    .map(|(left, right)| (left.as_bytes().to_vec(), right.as_bytes().to_vec()))
                    .collect();
                let share_data = engine
                    .batch_multiply_share_async(share_type, &pairs)
                    .await
                    .map_mpc_backend_err("async_batch_multiply_share")?;
                CompletedMpcBuiltinResult::ShareValues {
                    share_type,
                    share_data,
                }
            }
            PendingMpcBuiltinOperation::LocalShare {
                share_type,
                share_data,
            } => CompletedMpcBuiltinResult::ShareObject {
                share_type,
                share_data,
            },
            PendingMpcBuiltinOperation::BatchMulMixed {
                share_type,
                precomputed,
                left_data,
                right_data,
            } => {
                let engine_results = if left_data.is_empty() {
                    Vec::new()
                } else {
                    let pairs: Vec<(Vec<u8>, Vec<u8>)> = left_data
                        .iter()
                        .zip(right_data.iter())
                        .map(|(left, right)| (left.as_bytes().to_vec(), right.as_bytes().to_vec()))
                        .collect();
                    engine
                        .batch_multiply_share_async(share_type, &pairs)
                        .await
                        .map_mpc_backend_err("async_batch_multiply_share")?
                };

                let mut engine_results = engine_results.into_iter();
                let mut share_data = Vec::with_capacity(precomputed.len());
                for slot in precomputed {
                    match slot {
                        Some(data) => share_data.push(data),
                        None => share_data.push(engine_results.next().ok_or_else(|| {
                            VmError::ForeignFunction(ForeignFunctionError::CallbackFailed {
                                function: "Share.batch_mul".to_owned(),
                                source: "engine returned fewer batch products than requested"
                                    .into(),
                            })
                        })?),
                    }
                }
                CompletedMpcBuiltinResult::ShareValues {
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
                CompletedMpcBuiltinResult::Value(clear_share_value_to_vm_value(share_type, value))
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
                CompletedMpcBuiltinResult::BatchOpen { share_type, values }
            }
            PendingMpcBuiltinOperation::SendToClient {
                client_id,
                share_bytes,
                output_share_count,
            } => {
                engine
                    .send_output_to_client_async(client_id, &share_bytes, output_share_count)
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
                let share_data = match engine.try_random_share_cached(share_type) {
                    Some(result) => result.map_mpc_backend_err("cached_random_share")?,
                    None => engine
                        .random_share_async(share_type)
                        .await
                        .map_mpc_backend_err("async_random_share")?,
                };
                CompletedMpcBuiltinResult::ShareObject {
                    share_type,
                    share_data,
                }
            }
            PendingMpcBuiltinOperation::RandomInt { share_type } => {
                let share_data = engine
                    .random_integer_share_async(share_type)
                    .await
                    .map_mpc_backend_err("async_random_integer_share")?;
                CompletedMpcBuiltinResult::ShareValue {
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
            PendingMpcBuiltinOperation::LocalShare { .. } => {}
            PendingMpcBuiltinOperation::Mul { .. }
            | PendingMpcBuiltinOperation::BatchMul { .. } => {
                engine
                    .multiplication_ops()
                    .map_mpc_backend_err("multiplication_ops")?;
            }
            PendingMpcBuiltinOperation::BatchMulMixed { left_data, .. } => {
                if !left_data.is_empty() {
                    engine
                        .multiplication_ops()
                        .map_mpc_backend_err("multiplication_ops")?;
                }
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
            PendingMpcBuiltinOperation::RandomInt { .. } => {
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
            | PendingMpcBuiltinOperation::RbcReceiveAny { .. } => {
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
    pub(super) fn plan_async_mpc_operation_for_fetched(
        &mut self,
        fetched: FetchedInstruction<'_>,
        hooks_enabled: bool,
    ) -> VmResult<Option<PendingMpcOperation>> {
        match fetched.opcode() {
            RuntimeOpcode::LoadImmediate => {
                let dest = fetched.register_a();
                if !self
                    .current_register_layout()?
                    .is_secret(dest.register_index())
                {
                    return Ok(None);
                }

                PendingMpcOperation::input_share(dest, fetched.direct_load_immediate_value()?)
            }
            RuntimeOpcode::Move => {
                let dest = fetched.register_a();
                let src = fetched.register_b();
                if self
                    .current_register_layout()?
                    .move_kind(dest.register_index(), src.register_index())
                    != RegisterMoveKind::SecretToClear
                {
                    return Ok(None);
                }

                let src_value = self.resolve_register(src)?.into_value();
                Ok(PendingMpcOperation::open_share(src, dest, src_value))
            }
            RuntimeOpcode::Multiply => {
                let dest = fetched.register_a();
                let (left, right) = self
                    .resolve_register_pair(fetched.register_b(), fetched.register_c())?
                    .into_values();
                PendingMpcOperation::multiply_share(dest, left, right)
            }
            opcode @ (RuntimeOpcode::BitAnd | RuntimeOpcode::BitOr | RuntimeOpcode::BitXor) => {
                let op = match opcode {
                    RuntimeOpcode::BitAnd => RuntimeBinaryOp::BitAnd,
                    RuntimeOpcode::BitOr => RuntimeBinaryOp::BitOr,
                    RuntimeOpcode::BitXor => RuntimeBinaryOp::BitXor,
                    _ => unreachable!("matched boolean runtime opcode"),
                };
                let dest = fetched.register_a();
                let (left, right) = self
                    .resolve_register_pair(fetched.register_b(), fetched.register_c())?
                    .into_values();
                PendingMpcOperation::boolean_bit_share(op, dest, left, right)
            }
            RuntimeOpcode::Call => {
                self.plan_async_mpc_builtin_call(fetched.direct_call_target_name()?, hooks_enabled)
            }
            _ => Ok(None),
        }
    }

    #[cfg(test)]
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

                PendingMpcOperation::input_share(*dest, value.direct_value()?)
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
            RuntimeInstruction::Binary {
                op:
                    op @ (RuntimeBinaryOp::BitAnd | RuntimeBinaryOp::BitOr | RuntimeBinaryOp::BitXor),
                dest,
                lhs,
                rhs,
            } => {
                let (left, right) = self.resolve_register_pair(*lhs, *rhs)?.into_values();
                PendingMpcOperation::boolean_bit_share(*op, *dest, left, right)
            }
            RuntimeInstruction::Call { function } => {
                self.plan_async_mpc_builtin_call(function.direct_function_name()?, hooks_enabled)
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
                runtime: Box::new(async_identity),
                configured: Box::new(configured_identity),
            });
        }

        Ok(())
    }

    pub(crate) fn apply_completed_vm_effect(&mut self, effect: CompletedVmEffect) -> VmResult<()> {
        let (operation, after_instruction, hooks_enabled) = effect.into_parts();
        self.apply_completed_mpc_operation(operation, hooks_enabled)?;

        if let Some(after_instruction) = after_instruction {
            let event = HookEvent::AfterInstructionExecute(after_instruction);
            self.trigger_hook_with_snapshot(&event)?;
        } else {
            debug_assert!(!hooks_enabled);
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
            CompletedMpcOperation::BooleanBit {
                op,
                share_type,
                left_data,
                right_data,
                product_data,
                dest,
            } => {
                let share_runtime = || self.share_runtime().map_err(Into::into);
                let share_data = match op {
                    RuntimeBinaryOp::BitAnd => product_data,
                    RuntimeBinaryOp::BitOr => bool_or_data(
                        &share_runtime,
                        share_type,
                        &left_data,
                        &right_data,
                        &product_data,
                    )?,
                    RuntimeBinaryOp::BitXor => bool_xor_data(
                        &share_runtime,
                        share_type,
                        &left_data,
                        &right_data,
                        &product_data,
                    )?,
                    _ => {
                        return Err(VmError::Message(
                            "completed boolean bit operation used a non-bitwise opcode".to_string(),
                        ));
                    }
                };
                self.write_current_register(
                    dest,
                    Value::Share(share_type, share_data),
                    hooks_enabled,
                )?;
                Ok(())
            }
            CompletedMpcOperation::Open {
                share_type,
                value,
                src,
                dest,
            } => {
                self.write_mov_result(
                    dest,
                    src,
                    clear_share_value_to_vm_value(share_type, value),
                    hooks_enabled,
                )?;
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
            CompletedMpcBuiltinResult::ShareValue {
                share_type,
                share_data,
            } => Ok(Value::Share(share_type, share_data)),
            CompletedMpcBuiltinResult::ShareValues {
                share_type,
                share_data,
            } => {
                let shares: Vec<Value> = share_data
                    .into_iter()
                    .map(|share_data| Value::Share(share_type, share_data))
                    .collect();
                let result_ref = self.create_array_ref(shares.len())?;
                self.push_array_ref_values(result_ref, &shares)?;
                Ok(Value::from(result_ref))
            }
            CompletedMpcBuiltinResult::BatchOpen { share_type, values } => {
                let revealed: Vec<Value> = values
                    .into_iter()
                    .map(|value| clear_share_value_to_vm_value(share_type, value))
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
