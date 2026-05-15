use super::*;
use crate::foreign_functions::ForeignFunctionCallbackError;
use crate::net::client_store::{ClientShare, ClientShareIndex};
use crate::net::mpc_engine::{
    AbaSessionId, AsyncMpcEngine, AsyncMpcEngineConsensus, MpcCapabilities, MpcEngine,
    MpcEngineConsensus, MpcEngineResult, MpcPartyId, MpcSessionTopology, RbcSessionId,
};
use crate::runtime_hooks::{HookCallbackError, HookEvent, HookId};
use crate::VirtualMachineError;
use crate::VirtualMachineErrorKind;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use stoffel_vm_types::core_types::{
    ArrayRef, ClearShareInput, ClearShareValue, ForeignObjectRef, ObjectRef, ObjectStore,
    ShareData, ShareType, TableMemory, TableMemoryResult, TableRef, Value,
};
use stoffel_vm_types::functions::VMFunction;
use stoffel_vm_types::instructions::Instruction;
use stoffel_vm_types::registers::RegisterLayout;

fn callback_error(error: &VirtualMachineError) -> &ForeignFunctionCallbackError {
    let mut source = error.source();
    while let Some(error) = source {
        if let Some(callback_error) = error.downcast_ref::<ForeignFunctionCallbackError>() {
            return callback_error;
        }
        if let Some(crate::foreign_functions::ForeignFunctionError::CallbackFailed {
            source, ..
        }) = error.downcast_ref::<crate::foreign_functions::ForeignFunctionError>()
        {
            return source;
        }
        source = error.source();
    }

    panic!("expected foreign function callback error source");
}

struct ClonePreservedEngine;

impl MpcEngine for ClonePreservedEngine {
    fn protocol_name(&self) -> &'static str {
        "clone-preserved"
    }

    fn topology(&self) -> MpcSessionTopology {
        MpcSessionTopology::try_new(7, 1, 3, 1).expect("test topology should be valid")
    }

    fn is_ready(&self) -> bool {
        true
    }

    fn start(&self) -> crate::net::mpc_engine::MpcEngineResult<()> {
        Ok(())
    }

    fn input_share(
        &self,
        _clear: ClearShareInput,
    ) -> crate::net::mpc_engine::MpcEngineResult<ShareData> {
        Ok(ShareData::Opaque(Vec::new()))
    }

    fn open_share(
        &self,
        _ty: ShareType,
        _share_bytes: &[u8],
    ) -> crate::net::mpc_engine::MpcEngineResult<ClearShareValue> {
        Ok(ClearShareValue::Integer(42))
    }

    fn capabilities(&self) -> MpcCapabilities {
        MpcCapabilities::CLIENT_INPUT
    }
}

#[async_trait::async_trait]
impl AsyncMpcEngine for ClonePreservedEngine {
    async fn open_share_async(
        &self,
        _ty: ShareType,
        _share_bytes: &[u8],
    ) -> crate::net::mpc_engine::MpcEngineResult<ClearShareValue> {
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "async_open_share",
            "not used",
        ))
    }
}

struct BarrierOpenEngine {
    barrier: Arc<tokio::sync::Barrier>,
    open_started: AtomicUsize,
    open_finished: AtomicUsize,
}

impl BarrierOpenEngine {
    fn new(expected_concurrent_opens: usize) -> Self {
        Self {
            barrier: Arc::new(tokio::sync::Barrier::new(expected_concurrent_opens)),
            open_started: AtomicUsize::new(0),
            open_finished: AtomicUsize::new(0),
        }
    }
}

impl MpcEngine for BarrierOpenEngine {
    fn protocol_name(&self) -> &'static str {
        "barrier-open"
    }

    fn topology(&self) -> MpcSessionTopology {
        MpcSessionTopology::try_new(9, 1, 3, 1).expect("test topology should be valid")
    }

    fn is_ready(&self) -> bool {
        true
    }

    fn start(&self) -> crate::net::mpc_engine::MpcEngineResult<()> {
        Ok(())
    }

    fn input_share(
        &self,
        _clear: ClearShareInput,
    ) -> crate::net::mpc_engine::MpcEngineResult<ShareData> {
        Ok(ShareData::Opaque(Vec::new()))
    }

    fn open_share(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
    ) -> crate::net::mpc_engine::MpcEngineResult<ClearShareValue> {
        Ok(ClearShareValue::Integer(
            share_bytes.first().copied().unwrap_or_default() as i64,
        ))
    }
}

#[async_trait::async_trait]
impl AsyncMpcEngine for BarrierOpenEngine {
    async fn open_share_async(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
    ) -> crate::net::mpc_engine::MpcEngineResult<ClearShareValue> {
        let opened_value = share_bytes.first().copied().unwrap_or_default() as i64;
        self.open_started.fetch_add(1, Ordering::SeqCst);
        self.barrier.wait().await;
        self.open_finished.fetch_add(1, Ordering::SeqCst);
        Ok(ClearShareValue::Integer(opened_value))
    }
}

struct BarrierInputEngine {
    barrier: Arc<tokio::sync::Barrier>,
    input_started: AtomicUsize,
    input_finished: AtomicUsize,
    sync_input_calls: AtomicUsize,
}

impl BarrierInputEngine {
    fn new(expected_concurrent_inputs: usize) -> Self {
        Self {
            barrier: Arc::new(tokio::sync::Barrier::new(expected_concurrent_inputs)),
            input_started: AtomicUsize::new(0),
            input_finished: AtomicUsize::new(0),
            sync_input_calls: AtomicUsize::new(0),
        }
    }
}

impl MpcEngine for BarrierInputEngine {
    fn protocol_name(&self) -> &'static str {
        "barrier-input"
    }

    fn topology(&self) -> MpcSessionTopology {
        MpcSessionTopology::try_new(12, 1, 3, 1).expect("test topology should be valid")
    }

    fn is_ready(&self) -> bool {
        true
    }

    fn start(&self) -> MpcEngineResult<()> {
        Ok(())
    }

    fn input_share(&self, _clear: ClearShareInput) -> MpcEngineResult<ShareData> {
        self.sync_input_calls.fetch_add(1, Ordering::SeqCst);
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "input_share",
            "sync input_share should not be used by async builtin calls",
        ))
    }

    fn open_share(&self, _ty: ShareType, _share_bytes: &[u8]) -> MpcEngineResult<ClearShareValue> {
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "open_share",
            "sync open_share should not be used by async builtin calls",
        ))
    }
}

#[async_trait::async_trait]
impl AsyncMpcEngine for BarrierInputEngine {
    async fn input_share_async(&self, clear: ClearShareInput) -> MpcEngineResult<ShareData> {
        let share_byte = match clear.value() {
            ClearShareValue::Integer(value) => value.to_le_bytes()[0],
            ClearShareValue::FixedPoint(value) => (value.0 as i64).to_le_bytes()[0],
            ClearShareValue::Boolean(value) => u8::from(value),
        };

        self.input_started.fetch_add(1, Ordering::SeqCst);
        self.barrier.wait().await;
        self.input_finished.fetch_add(1, Ordering::SeqCst);
        Ok(ShareData::Opaque(vec![share_byte]))
    }

    async fn open_share_async(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
    ) -> MpcEngineResult<ClearShareValue> {
        Ok(ClearShareValue::Integer(
            share_bytes.first().copied().unwrap_or_default() as i64,
        ))
    }
}

struct AsyncBatchOpenEngine {
    sync_batch_calls: AtomicUsize,
    async_batch_calls: AtomicUsize,
}

impl AsyncBatchOpenEngine {
    fn new() -> Self {
        Self {
            sync_batch_calls: AtomicUsize::new(0),
            async_batch_calls: AtomicUsize::new(0),
        }
    }
}

impl MpcEngine for AsyncBatchOpenEngine {
    fn protocol_name(&self) -> &'static str {
        "async-batch-open"
    }

    fn topology(&self) -> MpcSessionTopology {
        MpcSessionTopology::try_new(10, 1, 3, 1).expect("test topology should be valid")
    }

    fn is_ready(&self) -> bool {
        true
    }

    fn start(&self) -> crate::net::mpc_engine::MpcEngineResult<()> {
        Ok(())
    }

    fn input_share(
        &self,
        _clear: ClearShareInput,
    ) -> crate::net::mpc_engine::MpcEngineResult<ShareData> {
        Ok(ShareData::Opaque(Vec::new()))
    }

    fn open_share(
        &self,
        _ty: ShareType,
        _share_bytes: &[u8],
    ) -> crate::net::mpc_engine::MpcEngineResult<ClearShareValue> {
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "open_share",
            "sync open_share should not be used by async builtin calls",
        ))
    }

    fn batch_open_shares(
        &self,
        _ty: ShareType,
        _shares: &[Vec<u8>],
    ) -> crate::net::mpc_engine::MpcEngineResult<Vec<ClearShareValue>> {
        self.sync_batch_calls.fetch_add(1, Ordering::SeqCst);
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "batch_open_shares",
            "sync batch_open_shares should not be used by async builtin calls",
        ))
    }
}

#[async_trait::async_trait]
impl AsyncMpcEngine for AsyncBatchOpenEngine {
    async fn open_share_async(
        &self,
        _ty: ShareType,
        _share_bytes: &[u8],
    ) -> crate::net::mpc_engine::MpcEngineResult<ClearShareValue> {
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "async_open_share",
            "not used",
        ))
    }

    async fn batch_open_shares_async(
        &self,
        _ty: ShareType,
        shares: &[Vec<u8>],
    ) -> crate::net::mpc_engine::MpcEngineResult<Vec<ClearShareValue>> {
        self.async_batch_calls.fetch_add(1, Ordering::SeqCst);
        Ok(shares
            .iter()
            .map(
                |share| ClearShareValue::Integer(share.first().copied().unwrap_or_default() as i64),
            )
            .collect())
    }
}

struct BarrierConsensusEngine {
    barrier: Arc<tokio::sync::Barrier>,
    rbc_receive_started: AtomicUsize,
    rbc_receive_finished: AtomicUsize,
    aba_result_calls: AtomicUsize,
}

impl BarrierConsensusEngine {
    fn new(expected_concurrent_receives: usize) -> Self {
        Self {
            barrier: Arc::new(tokio::sync::Barrier::new(expected_concurrent_receives)),
            rbc_receive_started: AtomicUsize::new(0),
            rbc_receive_finished: AtomicUsize::new(0),
            aba_result_calls: AtomicUsize::new(0),
        }
    }
}

impl MpcEngine for BarrierConsensusEngine {
    fn protocol_name(&self) -> &'static str {
        "barrier-consensus"
    }

    fn topology(&self) -> MpcSessionTopology {
        MpcSessionTopology::try_new(11, 1, 3, 1).expect("test topology should be valid")
    }

    fn is_ready(&self) -> bool {
        true
    }

    fn start(&self) -> MpcEngineResult<()> {
        Ok(())
    }

    fn input_share(&self, _clear: ClearShareInput) -> MpcEngineResult<ShareData> {
        Ok(ShareData::Opaque(Vec::new()))
    }

    fn open_share(&self, _ty: ShareType, _share_bytes: &[u8]) -> MpcEngineResult<ClearShareValue> {
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "open_share",
            "not used",
        ))
    }

    fn capabilities(&self) -> MpcCapabilities {
        MpcCapabilities::CONSENSUS
    }

    fn as_consensus(&self) -> Option<&dyn MpcEngineConsensus> {
        Some(self)
    }
}

impl MpcEngineConsensus for BarrierConsensusEngine {
    fn rbc_broadcast(&self, _message: &[u8]) -> MpcEngineResult<RbcSessionId> {
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "rbc_broadcast",
            "sync rbc_broadcast should not be used by async builtin calls",
        ))
    }

    fn rbc_receive(&self, _from_party: MpcPartyId, _timeout_ms: u64) -> MpcEngineResult<Vec<u8>> {
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "rbc_receive",
            "sync rbc_receive should not be used by async builtin calls",
        ))
    }

    fn rbc_receive_any(&self, _timeout_ms: u64) -> MpcEngineResult<(MpcPartyId, Vec<u8>)> {
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "rbc_receive_any",
            "sync rbc_receive_any should not be used by async builtin calls",
        ))
    }

    fn aba_propose(&self, _value: bool) -> MpcEngineResult<AbaSessionId> {
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "aba_propose",
            "sync aba_propose should not be used by async builtin calls",
        ))
    }

    fn aba_result(&self, _session_id: AbaSessionId, _timeout_ms: u64) -> MpcEngineResult<bool> {
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "aba_result",
            "sync aba_result should not be used by async builtin calls",
        ))
    }
}

#[async_trait::async_trait]
impl AsyncMpcEngine for BarrierConsensusEngine {
    fn as_async_consensus_ops(&self) -> Option<&dyn AsyncMpcEngineConsensus> {
        Some(self)
    }

    async fn open_share_async(
        &self,
        _ty: ShareType,
        _share_bytes: &[u8],
    ) -> MpcEngineResult<ClearShareValue> {
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "async_open_share",
            "not used",
        ))
    }
}

#[async_trait::async_trait]
impl AsyncMpcEngineConsensus for BarrierConsensusEngine {
    async fn rbc_broadcast_async(&self, _message: &[u8]) -> MpcEngineResult<RbcSessionId> {
        Ok(RbcSessionId::new(7))
    }

    async fn rbc_receive_async(
        &self,
        from_party: MpcPartyId,
        _timeout_ms: u64,
    ) -> MpcEngineResult<Vec<u8>> {
        self.rbc_receive_started.fetch_add(1, Ordering::SeqCst);
        self.barrier.wait().await;
        self.rbc_receive_finished.fetch_add(1, Ordering::SeqCst);
        Ok(format!("from-{}", from_party.id()).into_bytes())
    }

    async fn rbc_receive_any_async(
        &self,
        _timeout_ms: u64,
    ) -> MpcEngineResult<(MpcPartyId, Vec<u8>)> {
        Ok((MpcPartyId::new(2), b"any".to_vec()))
    }

    async fn aba_propose_async(&self, _value: bool) -> MpcEngineResult<AbaSessionId> {
        Ok(AbaSessionId::new(3))
    }

    async fn aba_result_async(
        &self,
        _session_id: AbaSessionId,
        _timeout_ms: u64,
    ) -> MpcEngineResult<bool> {
        self.aba_result_calls.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }
}

struct TrackingMemory {
    inner: ObjectStore,
    created_objects: Arc<AtomicUsize>,
}

impl TrackingMemory {
    fn new(created_objects: Arc<AtomicUsize>) -> Self {
        Self {
            inner: ObjectStore::new(),
            created_objects,
        }
    }
}

impl TableMemory for TrackingMemory {
    fn try_clone_empty(&self) -> TableMemoryResult<Box<dyn TableMemory>> {
        Ok(Box::new(TrackingMemory::new(Arc::clone(
            &self.created_objects,
        ))))
    }

    fn create_object_ref(&mut self) -> TableMemoryResult<ObjectRef> {
        self.created_objects.fetch_add(1, Ordering::SeqCst);
        self.inner.create_object_ref()
    }

    fn create_array_ref(&mut self) -> TableMemoryResult<ArrayRef> {
        self.inner.create_array_ref()
    }

    fn create_array_ref_with_capacity(&mut self, capacity: usize) -> TableMemoryResult<ArrayRef> {
        self.inner.create_array_ref_with_capacity(capacity)
    }

    fn read_table_field(
        &mut self,
        table_ref: TableRef,
        key: &Value,
    ) -> TableMemoryResult<Option<Value>> {
        self.inner.read_table_field(table_ref, key)
    }

    fn set_table_field(
        &mut self,
        table_ref: TableRef,
        key: Value,
        field_value: Value,
    ) -> TableMemoryResult<()> {
        self.inner.set_table_field(table_ref, key, field_value)
    }

    fn push_array_ref_values(
        &mut self,
        array_ref: ArrayRef,
        values: &[Value],
    ) -> TableMemoryResult<usize> {
        self.inner.push_array_ref_values(array_ref, values)
    }

    fn read_array_ref_len(&mut self, array_ref: ArrayRef) -> TableMemoryResult<usize> {
        self.inner.read_array_ref_len(array_ref)
    }

    fn read_object_ref_len(&mut self, object_ref: ObjectRef) -> TableMemoryResult<usize> {
        self.inner.read_object_ref_len(object_ref)
    }

    fn read_object_ref_entries(
        &mut self,
        object_ref: ObjectRef,
        limit: usize,
    ) -> TableMemoryResult<Vec<(Value, Value)>> {
        self.inner.read_object_ref_entries(object_ref, limit)
    }
}

struct FailingReadMemory {
    inner: ObjectStore,
}

impl FailingReadMemory {
    fn new() -> Self {
        Self {
            inner: ObjectStore::new(),
        }
    }
}

impl TableMemory for FailingReadMemory {
    fn try_clone_empty(&self) -> TableMemoryResult<Box<dyn TableMemory>> {
        Ok(Box::new(FailingReadMemory::new()))
    }

    fn create_object_ref(&mut self) -> TableMemoryResult<ObjectRef> {
        self.inner.create_object_ref()
    }

    fn create_array_ref(&mut self) -> TableMemoryResult<ArrayRef> {
        self.inner.create_array_ref()
    }

    fn create_array_ref_with_capacity(&mut self, capacity: usize) -> TableMemoryResult<ArrayRef> {
        self.inner.create_array_ref_with_capacity(capacity)
    }

    fn read_table_field(
        &mut self,
        _table_ref: TableRef,
        _key: &Value,
    ) -> TableMemoryResult<Option<Value>> {
        Err("simulated table read failure".into())
    }

    fn set_table_field(
        &mut self,
        table_ref: TableRef,
        key: Value,
        field_value: Value,
    ) -> TableMemoryResult<()> {
        self.inner.set_table_field(table_ref, key, field_value)
    }

    fn push_array_ref_values(
        &mut self,
        array_ref: ArrayRef,
        values: &[Value],
    ) -> TableMemoryResult<usize> {
        self.inner.push_array_ref_values(array_ref, values)
    }

    fn read_array_ref_len(&mut self, array_ref: ArrayRef) -> TableMemoryResult<usize> {
        self.inner.read_array_ref_len(array_ref)
    }

    fn read_object_ref_len(&mut self, object_ref: ObjectRef) -> TableMemoryResult<usize> {
        self.inner.read_object_ref_len(object_ref)
    }

    fn read_object_ref_entries(
        &mut self,
        object_ref: ObjectRef,
        limit: usize,
    ) -> TableMemoryResult<Vec<(Value, Value)>> {
        self.inner.read_object_ref_entries(object_ref, limit)
    }
}

struct MutatingReadMemory {
    inner: ObjectStore,
    reads: Arc<AtomicUsize>,
}

impl MutatingReadMemory {
    fn new(reads: Arc<AtomicUsize>) -> Self {
        Self {
            inner: ObjectStore::new(),
            reads,
        }
    }
}

impl TableMemory for MutatingReadMemory {
    fn try_clone_empty(&self) -> TableMemoryResult<Box<dyn TableMemory>> {
        Ok(Box::new(MutatingReadMemory::new(Arc::clone(&self.reads))))
    }

    fn create_object_ref(&mut self) -> TableMemoryResult<ObjectRef> {
        self.inner.create_object_ref()
    }

    fn create_array_ref(&mut self) -> TableMemoryResult<ArrayRef> {
        self.inner.create_array_ref()
    }

    fn create_array_ref_with_capacity(&mut self, capacity: usize) -> TableMemoryResult<ArrayRef> {
        self.inner.create_array_ref_with_capacity(capacity)
    }

    fn read_table_field(
        &mut self,
        table_ref: TableRef,
        key: &Value,
    ) -> TableMemoryResult<Option<Value>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.try_get_table_field(table_ref, key)
    }

    fn set_table_field(
        &mut self,
        table_ref: TableRef,
        key: Value,
        field_value: Value,
    ) -> TableMemoryResult<()> {
        self.inner.set_table_field(table_ref, key, field_value)
    }

    fn read_array_ref_len(&mut self, array_ref: ArrayRef) -> TableMemoryResult<usize> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.array_ref_len(array_ref)
    }

    fn push_array_ref_values(
        &mut self,
        array_ref: ArrayRef,
        values: &[Value],
    ) -> TableMemoryResult<usize> {
        self.inner.push_array_ref_values(array_ref, values)
    }

    fn read_object_ref_len(&mut self, object_ref: ObjectRef) -> TableMemoryResult<usize> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.read_object_ref_len(object_ref)
    }

    fn read_object_ref_entries(
        &mut self,
        object_ref: ObjectRef,
        limit: usize,
    ) -> TableMemoryResult<Vec<(Value, Value)>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.read_object_ref_entries(object_ref, limit)
    }
}

struct FailingAllocMemory {
    inner: ObjectStore,
}

impl FailingAllocMemory {
    fn new() -> Self {
        Self {
            inner: ObjectStore::new(),
        }
    }
}

impl TableMemory for FailingAllocMemory {
    fn try_clone_empty(&self) -> TableMemoryResult<Box<dyn TableMemory>> {
        Ok(Box::new(FailingAllocMemory::new()))
    }

    fn create_object_ref(&mut self) -> TableMemoryResult<ObjectRef> {
        Err("simulated table allocation failure".into())
    }

    fn create_array_ref(&mut self) -> TableMemoryResult<ArrayRef> {
        Err("simulated table allocation failure".into())
    }

    fn create_array_ref_with_capacity(&mut self, _capacity: usize) -> TableMemoryResult<ArrayRef> {
        Err("simulated table allocation failure".into())
    }

    fn read_table_field(
        &mut self,
        table_ref: TableRef,
        key: &Value,
    ) -> TableMemoryResult<Option<Value>> {
        self.inner.read_table_field(table_ref, key)
    }

    fn set_table_field(
        &mut self,
        table_ref: TableRef,
        key: Value,
        field_value: Value,
    ) -> TableMemoryResult<()> {
        self.inner.set_table_field(table_ref, key, field_value)
    }

    fn push_array_ref_values(
        &mut self,
        array_ref: ArrayRef,
        values: &[Value],
    ) -> TableMemoryResult<usize> {
        self.inner.push_array_ref_values(array_ref, values)
    }

    fn read_array_ref_len(&mut self, array_ref: ArrayRef) -> TableMemoryResult<usize> {
        self.inner.read_array_ref_len(array_ref)
    }

    fn read_object_ref_len(&mut self, object_ref: ObjectRef) -> TableMemoryResult<usize> {
        self.inner.read_object_ref_len(object_ref)
    }

    fn read_object_ref_entries(
        &mut self,
        object_ref: ObjectRef,
        limit: usize,
    ) -> TableMemoryResult<Vec<(Value, Value)>> {
        self.inner.read_object_ref_entries(object_ref, limit)
    }
}

struct HugePushMemory {
    inner: ObjectStore,
}

impl HugePushMemory {
    fn new() -> Self {
        Self {
            inner: ObjectStore::new(),
        }
    }
}

impl TableMemory for HugePushMemory {
    fn try_clone_empty(&self) -> TableMemoryResult<Box<dyn TableMemory>> {
        Ok(Box::new(HugePushMemory::new()))
    }

    fn create_object_ref(&mut self) -> TableMemoryResult<ObjectRef> {
        self.inner.create_object_ref()
    }

    fn create_array_ref(&mut self) -> TableMemoryResult<ArrayRef> {
        self.inner.create_array_ref()
    }

    fn create_array_ref_with_capacity(&mut self, capacity: usize) -> TableMemoryResult<ArrayRef> {
        self.inner.create_array_ref_with_capacity(capacity)
    }

    fn read_table_field(
        &mut self,
        table_ref: TableRef,
        key: &Value,
    ) -> TableMemoryResult<Option<Value>> {
        self.inner.read_table_field(table_ref, key)
    }

    fn set_table_field(
        &mut self,
        table_ref: TableRef,
        key: Value,
        field_value: Value,
    ) -> TableMemoryResult<()> {
        self.inner.set_table_field(table_ref, key, field_value)
    }

    fn push_array_ref_values(
        &mut self,
        _array_ref: ArrayRef,
        _values: &[Value],
    ) -> TableMemoryResult<usize> {
        Ok(usize::MAX)
    }

    fn read_array_ref_len(&mut self, array_ref: ArrayRef) -> TableMemoryResult<usize> {
        self.inner.read_array_ref_len(array_ref)
    }

    fn read_object_ref_len(&mut self, object_ref: ObjectRef) -> TableMemoryResult<usize> {
        self.inner.read_object_ref_len(object_ref)
    }

    fn read_object_ref_entries(
        &mut self,
        object_ref: ObjectRef,
        limit: usize,
    ) -> TableMemoryResult<Vec<(Value, Value)>> {
        self.inner.read_object_ref_entries(object_ref, limit)
    }
}

struct FailingCloneMemory {
    inner: ObjectStore,
}

impl FailingCloneMemory {
    fn new() -> Self {
        Self {
            inner: ObjectStore::new(),
        }
    }
}

impl TableMemory for FailingCloneMemory {
    fn try_clone_empty(&self) -> TableMemoryResult<Box<dyn TableMemory>> {
        Err("simulated table clone failure".into())
    }

    fn create_object_ref(&mut self) -> TableMemoryResult<ObjectRef> {
        self.inner.create_object_ref()
    }

    fn create_array_ref(&mut self) -> TableMemoryResult<ArrayRef> {
        self.inner.create_array_ref()
    }

    fn create_array_ref_with_capacity(&mut self, capacity: usize) -> TableMemoryResult<ArrayRef> {
        self.inner.create_array_ref_with_capacity(capacity)
    }

    fn read_table_field(
        &mut self,
        table_ref: TableRef,
        key: &Value,
    ) -> TableMemoryResult<Option<Value>> {
        self.inner.read_table_field(table_ref, key)
    }

    fn set_table_field(
        &mut self,
        table_ref: TableRef,
        key: Value,
        field_value: Value,
    ) -> TableMemoryResult<()> {
        self.inner.set_table_field(table_ref, key, field_value)
    }

    fn push_array_ref_values(
        &mut self,
        array_ref: ArrayRef,
        values: &[Value],
    ) -> TableMemoryResult<usize> {
        self.inner.push_array_ref_values(array_ref, values)
    }

    fn read_array_ref_len(&mut self, array_ref: ArrayRef) -> TableMemoryResult<usize> {
        self.inner.read_array_ref_len(array_ref)
    }

    fn read_object_ref_len(&mut self, object_ref: ObjectRef) -> TableMemoryResult<usize> {
        self.inner.read_object_ref_len(object_ref)
    }

    fn read_object_ref_entries(
        &mut self,
        object_ref: ObjectRef,
        limit: usize,
    ) -> TableMemoryResult<Vec<(Value, Value)>> {
        self.inner.read_object_ref_entries(object_ref, limit)
    }
}

// Helper function to create a test VM
// Each test gets its own VM instance to allow parallel test execution
fn setup_vm() -> VirtualMachine {
    // Create a new VM with its own independent state
    // Use a static VM instance as the base for all test VMs
    static BASE_VM: once_cell::sync::Lazy<VirtualMachine> =
        once_cell::sync::Lazy::new(VirtualMachine::new);

    // Clone the base VM with its own independent state
    // This allows tests to run in parallel without locking each other
    let vm = BASE_VM
        .try_clone_with_independent_state()
        .expect("clone base VM with independent state");

    // Return the VM
    vm
}

#[test]
fn try_new_exposes_fallible_default_construction() {
    let vm = VirtualMachine::try_new().expect("default VM construction should succeed");

    assert!(vm.has_function("create_object"));
    assert!(vm.has_function("Share.from_clear"));
}

#[test]
fn try_register_mpc_builtins_rejects_duplicate_registration_from_vm_api() {
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .build();

    vm.try_register_mpc_builtins()
        .expect("first MPC builtin registration should succeed");
    let err = vm
        .try_register_mpc_builtins()
        .expect_err("second MPC builtin registration must be rejected");
    assert_eq!(err.kind(), VirtualMachineErrorKind::Registration);
    let err = err.to_string();
    assert!(
        err.contains("Share.from_clear") && err.contains("already registered"),
        "unexpected error: {err}"
    );
    assert!(vm.has_function("Share.from_clear"));
}

// Helper function to create a VMFunction with default values for new fields
fn create_test_vmfunction(
    name: String,
    parameters: Vec<String>,
    upvalues: Vec<String>,
    parent: Option<String>,
    register_count: usize,
    instructions: Vec<Instruction>,
    labels: HashMap<String, usize>,
) -> VMFunction {
    VMFunction::new(
        name,
        parameters,
        upvalues,
        parent,
        register_count,
        instructions,
        labels,
    )
}

#[test]
fn builder_accepts_custom_table_memory() {
    let created_objects = Arc::new(AtomicUsize::new(0));
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .with_table_memory(TrackingMemory::new(Arc::clone(&created_objects)))
        .build();

    let object_ref = vm.create_object_ref().expect("create object");
    let table_ref = TableRef::from(object_ref);
    vm.set_table_field(
        table_ref,
        Value::String("answer".to_string()),
        Value::I64(42),
    )
    .expect("set field in custom memory");

    assert_eq!(created_objects.load(Ordering::SeqCst), 1);
    assert_eq!(
        vm.read_table_field(table_ref, &Value::String("answer".to_string()))
            .unwrap(),
        Some(Value::I64(42))
    );

    let mut cloned = vm
        .try_clone_with_independent_state()
        .expect("clone VM with custom table memory");
    let cloned_object_ref = cloned.create_object_ref().expect("create cloned object");
    let cloned_table_ref = TableRef::from(cloned_object_ref);

    assert_eq!(created_objects.load(Ordering::SeqCst), 2);
    assert_eq!(
        cloned
            .read_table_field(cloned_table_ref, &Value::String("answer".to_string()))
            .unwrap(),
        None
    );
}

#[test]
fn builder_accepts_boxed_table_memory_backend() {
    let created_objects = Arc::new(AtomicUsize::new(0));
    let backend: Box<dyn TableMemory> = Box::new(TrackingMemory::new(Arc::clone(&created_objects)));
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .with_boxed_table_memory(backend)
        .build();

    vm.create_object_ref()
        .expect("boxed backend should be used");

    assert_eq!(created_objects.load(Ordering::SeqCst), 1);
}

#[test]
fn table_memory_view_is_an_optional_backend_capability() {
    let default_vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .build();
    assert!(
        default_vm.table_memory_view().is_some(),
        "ObjectStore supports immutable inspection"
    );

    let created_objects = Arc::new(AtomicUsize::new(0));
    let custom_vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .with_table_memory(TrackingMemory::new(created_objects))
        .build();
    assert!(
        custom_vm.table_memory_view().is_none(),
        "custom backends should opt into immutable inspection explicitly"
    );
}

#[test]
fn vm_table_construction_helpers_use_table_memory_boundary() {
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .build();

    let object = vm
        .create_object_with_fields([(Value::String("answer".to_string()), Value::I64(42))])
        .expect("create object with fields");
    let table_ref = TableRef::try_from(&object).expect("created object should be a table");
    let object_ref = table_ref.object_ref().expect("created object ref");
    assert_eq!(
        vm.read_table_field(table_ref, &Value::String("answer".to_string()))
            .expect("read object field"),
        Some(Value::I64(42))
    );
    assert_eq!(vm.read_object_len(object_ref).expect("object length"), 1);
    assert_eq!(
        vm.read_object_entries(object_ref, 8)
            .expect("object entries"),
        vec![(Value::String("answer".to_string()), Value::I64(42))]
    );

    let array_ref = vm.create_array_ref(0).expect("create array");
    assert_eq!(
        vm.push_array_values(array_ref, &[Value::I64(1), Value::I64(2)])
            .expect("push array values"),
        2
    );
    assert_eq!(vm.read_array_len(array_ref).expect("array length"), 2);
    assert_eq!(
        vm.read_table_field(TableRef::from(array_ref), &Value::I64(1))
            .expect("read array field"),
        Some(Value::I64(2))
    );
}

#[test]
fn independent_clone_propagates_table_memory_clone_errors() {
    let vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .with_table_memory(FailingCloneMemory::new())
        .build();

    let err = match vm.try_clone_with_independent_state() {
        Ok(_) => panic!("fallible table memory clone should fail"),
        Err(err) => err,
    };
    let err = err.to_string();

    assert!(
        err.contains("simulated table clone failure"),
        "unexpected error: {err}"
    );
}

#[test]
fn independent_clone_preserves_configured_mpc_runtime_info() {
    let vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .with_mpc_engine(Arc::new(ClonePreservedEngine))
        .build();

    let cloned = vm
        .try_clone_with_independent_state()
        .expect("clone VM with configured MPC engine");
    let cloned_info = cloned
        .mpc_runtime_info()
        .expect("cloned MPC runtime metadata");

    assert_eq!(cloned_info.protocol_name(), "clone-preserved");
    assert_eq!(
        cloned_info.topology(),
        MpcSessionTopology::try_new(7, 1, 3, 1).expect("test topology should be valid")
    );
    assert_eq!(cloned_info.capabilities(), MpcCapabilities::CLIENT_INPUT);
}

#[test]
fn independent_clone_preserves_client_input_snapshot_without_aliasing() {
    let vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .build();
    let share_type = ShareType::secret_int(64);

    vm.store_client_shares(
        10,
        vec![ClientShare::typed(
            share_type,
            ShareData::Opaque(vec![1, 2, 3]),
        )],
    );

    let cloned = vm
        .try_clone_with_independent_state()
        .expect("clone VM with hydrated client inputs");

    vm.replace_client_shares([(
        11,
        vec![ClientShare::typed(share_type, ShareData::Opaque(vec![4]))],
    )]);

    let cloned_share = cloned
        .client_share_data(10, ClientShareIndex::new(0))
        .expect("cloned client input snapshot");
    assert_eq!(cloned_share.share_type(), Some(share_type));
    assert_eq!(cloned_share.data(), &ShareData::Opaque(vec![1, 2, 3]));
    assert!(cloned
        .client_share_data(11, ClientShareIndex::new(0))
        .is_none());
}

#[test]
fn vm_open_share_value_uses_configured_mpc_runtime() {
    let vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .with_mpc_engine(Arc::new(ClonePreservedEngine))
        .build();

    let opened = vm
        .open_share_value(&Value::Share(
            ShareType::default_secret_int(),
            ShareData::Opaque(vec![1, 2, 3]),
        ))
        .expect("open share through VM runtime");

    assert_eq!(opened, Value::I64(42));
}

#[test]
fn mpc_runtime_info_exposes_metadata_without_backend_handle() {
    let vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .with_mpc_engine(Arc::new(ClonePreservedEngine))
        .build();

    let info = vm.mpc_runtime_info().expect("configured MPC metadata");

    assert_eq!(info.protocol_name(), "clone-preserved");
    assert_eq!(
        info.topology(),
        MpcSessionTopology::try_new(7, 1, 3, 1).expect("test topology should be valid")
    );
    assert_eq!(info.capabilities(), MpcCapabilities::CLIENT_INPUT);
    assert!(info.is_ready());
    assert!(VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .build()
        .mpc_runtime_info()
        .is_none());
}

#[test]
fn replace_client_shares_uses_backend_neutral_payloads() {
    let vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .build();
    let share_type = ShareType::secret_int(64);

    vm.store_client_shares(
        10,
        vec![ClientShare::typed(share_type, ShareData::Opaque(vec![0]))],
    );
    let replaced = vm.replace_client_shares([
        (
            2,
            vec![ClientShare::typed(share_type, ShareData::Opaque(vec![7]))],
        ),
        (
            1,
            vec![ClientShare::untyped(ShareData::Feldman {
                data: vec![8],
                commitments: vec![vec![9]],
            })],
        ),
    ]);

    assert_eq!(replaced, 2);
    assert!(vm.client_share_data(10, ClientShareIndex::new(0)).is_none());
    let typed_share = vm
        .client_share_data(2, ClientShareIndex::new(0))
        .expect("typed client share");
    assert_eq!(typed_share.share_type(), Some(share_type));
    assert_eq!(typed_share.data(), &ShareData::Opaque(vec![7]));
    let feldman_share = vm
        .client_share_data(1, ClientShareIndex::new(0))
        .expect("feldman client share");
    assert_eq!(feldman_share.share_type(), None);
    assert!(feldman_share.data().has_commitments());
}

#[test]
fn independent_clone_preserves_registered_program_entries() {
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .build();
    vm.try_register_function(VMFunction::new(
        "answer".to_string(),
        Vec::new(),
        Vec::new(),
        None,
        1,
        vec![Instruction::LDI(0, Value::I64(99)), Instruction::RET(0)],
        HashMap::new(),
    ))
    .expect("register VM function");
    vm.try_register_foreign_function("native_answer", |_| Ok(Value::I64(42)))
        .expect("register foreign function");

    let mut cloned = vm
        .try_clone_with_independent_state()
        .expect("clone VM with registered program entries");

    assert_eq!(cloned.execute("answer").unwrap(), Value::I64(99));
    assert_eq!(
        cloned.execute_with_args("native_answer", &[]).unwrap(),
        Value::I64(42)
    );
}

#[test]
fn table_memory_read_errors_propagate_through_get_field_builtin() {
    let mut vm = VirtualMachine::builder()
        .with_mpc_builtins(false)
        .with_table_memory(FailingReadMemory::new())
        .build();
    let object_id = vm.create_object_ref().expect("create object").id();

    let err = vm
        .execute_with_args(
            "get_field",
            &[
                Value::from(ObjectRef::new(object_id)),
                Value::String("answer".to_string()),
            ],
        )
        .expect_err("table read errors should not be converted to nil");
    let err = err.to_string();

    assert!(
        err.contains("simulated table read failure"),
        "unexpected error: {err}"
    );
    assert!(
        !err.contains("get_field failed: get_field failed"),
        "table memory errors should propagate without builtin-specific string wrapping: {err}"
    );
}

#[test]
fn table_memory_read_errors_propagate_through_set_field_builtin() {
    let mut vm = VirtualMachine::builder()
        .with_mpc_builtins(false)
        .with_table_memory(FailingReadMemory::new())
        .build();
    let object_id = vm.create_object_ref().expect("create object").id();

    let err = vm
        .execute_with_args(
            "set_field",
            &[
                Value::from(ObjectRef::new(object_id)),
                Value::String("answer".to_string()),
                Value::I64(42),
            ],
        )
        .expect_err("set_field old-value reads must propagate table memory failures");
    let err = err.to_string();

    assert!(
        err.contains("simulated table read failure"),
        "unexpected error: {err}"
    );
    assert!(
        !err.contains("get_field failed"),
        "table memory errors should propagate without builtin-specific string wrapping: {err}"
    );
}

#[test]
fn table_memory_builtins_use_mutating_read_boundary() {
    let reads = Arc::new(AtomicUsize::new(0));
    let mut vm = VirtualMachine::builder()
        .with_mpc_builtins(false)
        .with_table_memory(MutatingReadMemory::new(Arc::clone(&reads)))
        .build();
    let key = Value::String("answer".to_string());
    let object_id = vm.create_object_ref().expect("create object").id();
    vm.set_table_field(TableRef::object(object_id), key.clone(), Value::I64(41))
        .expect("seed field");

    let result = vm
        .execute_with_args(
            "get_field",
            &[Value::from(ObjectRef::new(object_id)), key.clone()],
        )
        .expect("get_field should use mutable table read");
    assert_eq!(result, Value::I64(41));

    vm.execute_with_args(
        "set_field",
        &[Value::from(ObjectRef::new(object_id)), key, Value::I64(42)],
    )
    .expect("set_field old-value lookup should use mutable table read");

    assert_eq!(reads.load(Ordering::SeqCst), 2);
}

#[test]
fn byte_array_builtins_use_mutating_read_boundary() {
    let reads = Arc::new(AtomicUsize::new(0));
    let mut vm = VirtualMachine::builder()
        .with_table_memory(MutatingReadMemory::new(Arc::clone(&reads)))
        .build();
    let left = vm.create_byte_array(&[1, 2]).expect("left byte array");
    let right = vm.create_byte_array(&[3, 4, 5]).expect("right byte array");

    let result = vm
        .execute_with_args("Bytes.concat", &[left, right])
        .expect("Bytes.concat should use mutable table reads");

    assert_eq!(reads.load(Ordering::SeqCst), 7);
    assert_eq!(
        vm.read_byte_array(&result)
            .expect("result should remain a byte array"),
        vec![1, 2, 3, 4, 5]
    );
}

#[test]
fn array_length_builtin_uses_mutating_read_boundary() {
    let reads = Arc::new(AtomicUsize::new(0));
    let mut vm = VirtualMachine::builder()
        .with_mpc_builtins(false)
        .with_table_memory(MutatingReadMemory::new(Arc::clone(&reads)))
        .build();
    let array_ref = vm.create_array_ref(0).expect("create array");
    vm.push_array_values(array_ref, &[Value::I64(1), Value::I64(2)])
        .expect("seed array");

    let result = vm
        .execute_with_args("array_length", &[Value::from(array_ref)])
        .expect("array_length should use mutable length read");

    assert_eq!(result, Value::I64(2));
    assert_eq!(reads.load(Ordering::SeqCst), 1);
}

#[test]
fn share_object_builtins_use_mutating_read_boundary() {
    let reads = Arc::new(AtomicUsize::new(0));
    let mut vm = VirtualMachine::builder()
        .with_table_memory(MutatingReadMemory::new(Arc::clone(&reads)))
        .build();
    let share_value = vm
        .create_share_object(
            ShareType::default_secret_int(),
            ShareData::Opaque(vec![1]),
            7,
        )
        .expect("share object creation should succeed");

    let result = vm
        .execute_with_args("Share.get_party_id", &[share_value])
        .expect("Share.get_party_id should use mutable table reads");

    assert_eq!(result, Value::I64(7));
    assert_eq!(reads.load(Ordering::SeqCst), 2);
}

#[test]
fn table_memory_allocation_errors_propagate_through_create_object_builtin() {
    let mut vm = VirtualMachine::builder()
        .with_mpc_builtins(false)
        .with_table_memory(FailingAllocMemory::new())
        .build();

    let err = vm
        .execute_with_args("create_object", &[])
        .expect_err("table allocation errors should not be hidden");
    let err = err.to_string();

    assert!(
        err.contains("simulated table allocation failure"),
        "unexpected error: {err}"
    );
}

#[test]
fn array_push_rejects_lengths_outside_vm_integer_range() {
    let mut vm = VirtualMachine::builder()
        .with_mpc_builtins(false)
        .with_table_memory(HugePushMemory::new())
        .build();

    let err = vm
        .execute_with_args(
            "array_push",
            &[Value::from(ArrayRef::new(1)), Value::I64(1)],
        )
        .expect_err("array_push must not truncate oversized table lengths");
    let err = err.to_string();

    assert!(
        err.contains("array length") && err.contains("exceeds VM integer range"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_execute_cleans_up_top_level_frame() {
    let mut vm = setup_vm();
    let test_function = VMFunction::new(
        "cleanup_test".to_string(),
        vec![],
        Vec::new(),
        None,
        1,
        vec![Instruction::LDI(0, Value::I64(7)), Instruction::RET(0)],
        HashMap::new(),
    );

    vm.try_register_function(test_function).unwrap();

    assert_eq!(vm.execute("cleanup_test").unwrap(), Value::I64(7));
    assert_eq!(vm.state.call_stack_depth(), 0);
    assert_eq!(vm.execute("cleanup_test").unwrap(), Value::I64(7));
    assert_eq!(vm.state.call_stack_depth(), 0);
}

#[test]
fn test_register_function_rejects_unknown_labels() {
    let mut vm = setup_vm();
    let test_function = VMFunction::new(
        "bad_jump".to_string(),
        vec![],
        Vec::new(),
        None,
        1,
        vec![Instruction::JMP("missing".to_string()), Instruction::RET(0)],
        HashMap::new(),
    );

    let err = vm.try_register_function(test_function).unwrap_err();
    let err = err.to_string();
    assert!(err.contains("unknown label"));
}

#[test]
fn public_vm_errors_preserve_kind_and_string_compatibility() {
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .build();
    let function = VMFunction::new(
        "needs_arg".to_string(),
        vec!["x".to_string()],
        Vec::new(),
        None,
        1,
        vec![Instruction::RET(0)],
        HashMap::new(),
    );
    vm.register_function(function);

    let err = vm
        .execute_with_args("needs_arg", &[])
        .expect_err("arity mismatch should be reported");
    assert_eq!(err.kind(), VirtualMachineErrorKind::Runtime);

    let message = err.to_string();
    let converted: String = err.into();
    assert_eq!(converted, message);
    assert!(message.contains("expects 1 arguments but got 0"));
}

#[test]
fn value_operation_runtime_errors_preserve_inner_public_kind() {
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .build();
    let share_type = ShareType::secret_int(64);
    let function = VMFunction::new(
        "secret_add_without_engine".to_string(),
        Vec::new(),
        Vec::new(),
        None,
        3,
        vec![
            Instruction::LDI(0, Value::Share(share_type, ShareData::Opaque(vec![1]))),
            Instruction::LDI(1, Value::Share(share_type, ShareData::Opaque(vec![2]))),
            Instruction::ADD(2, 0, 1),
            Instruction::RET(2),
        ],
        HashMap::new(),
    );
    vm.register_function(function);

    let err = vm
        .execute("secret_add_without_engine")
        .expect_err("secret-share addition requires an MPC engine");

    assert_eq!(err.kind(), VirtualMachineErrorKind::Mpc);
    assert!(
        err.to_string().contains("MPC engine not configured"),
        "unexpected error: {err}"
    );
}

#[test]
fn benchmark_entrypoint_accepts_arguments() {
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .build();
    let function = VMFunction::new(
        "double".to_string(),
        vec!["x".to_string()],
        Vec::new(),
        None,
        1,
        vec![Instruction::ADD(0, 0, 0), Instruction::RET(0)],
        HashMap::new(),
    );
    vm.register_function(function);

    let result = vm
        .execute_for_benchmark_with_args("double", &[Value::I64(7)])
        .expect("benchmark execution should bind arguments");

    assert_eq!(result, Value::I64(14));
}

#[tokio::test]
async fn async_entrypoint_accepts_arguments() {
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .build();
    let function = VMFunction::new(
        "double_async".to_string(),
        vec!["x".to_string()],
        Vec::new(),
        None,
        1,
        vec![Instruction::ADD(0, 0, 0), Instruction::RET(0)],
        HashMap::new(),
    );
    vm.register_function(function);

    let result = vm
        .execute_async_with_args("double_async", &[Value::I64(11)], &ClonePreservedEngine)
        .await
        .expect("async execution should bind arguments");

    assert_eq!(result, Value::I64(22));
}

fn async_open_function(name: &str, opened_value: u8) -> VMFunction {
    VMFunction::new(
        name.to_string(),
        Vec::new(),
        Vec::new(),
        None,
        2,
        vec![
            Instruction::LDI(
                1,
                Value::Share(
                    ShareType::secret_int(64),
                    ShareData::Opaque(vec![opened_value]),
                ),
            ),
            Instruction::MOV(0, 1),
            Instruction::RET(0),
        ],
        HashMap::new(),
    )
}

fn async_share_open_call_function(name: &str, opened_value: u8) -> VMFunction {
    VMFunction::new(
        name.to_string(),
        Vec::new(),
        Vec::new(),
        None,
        2,
        vec![
            Instruction::LDI(
                1,
                Value::Share(
                    ShareType::secret_int(64),
                    ShareData::Opaque(vec![opened_value]),
                ),
            ),
            Instruction::PUSHARG(1),
            Instruction::CALL("Share.open".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    )
}

fn async_share_from_clear_open_call_function(name: &str, clear_value: i64) -> VMFunction {
    VMFunction::new(
        name.to_string(),
        Vec::new(),
        Vec::new(),
        None,
        2,
        vec![
            Instruction::LDI(1, Value::I64(clear_value)),
            Instruction::PUSHARG(1),
            Instruction::CALL("Share.from_clear".to_string()),
            Instruction::PUSHARG(0),
            Instruction::CALL("Share.open".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    )
}

fn async_rbc_receive_call_function(name: &str, from_party: usize) -> VMFunction {
    VMFunction::new(
        name.to_string(),
        Vec::new(),
        Vec::new(),
        None,
        3,
        vec![
            Instruction::LDI(1, Value::I64(from_party as i64)),
            Instruction::PUSHARG(1),
            Instruction::LDI(2, Value::I64(1_000)),
            Instruction::PUSHARG(2),
            Instruction::CALL("Rbc.receive".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    )
}

#[tokio::test]
async fn execute_many_async_yields_on_share_from_clear_builtin_call() {
    let engine = Arc::new(BarrierInputEngine::new(2));
    let runtime_engine: Arc<dyn MpcEngine> = engine.clone();
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_engine(runtime_engine)
        .build();
    vm.register_function(async_share_from_clear_open_call_function(
        "from_clear_first",
        17,
    ));
    vm.register_function(async_share_from_clear_open_call_function(
        "from_clear_second",
        23,
    ));

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        vm.execute_many_async(["from_clear_first", "from_clear_second"], engine.as_ref()),
    )
    .await
    .expect("Share.from_clear calls should both reach the async input barrier")
    .expect("batched async share construction should succeed");

    assert_eq!(result, vec![Value::I64(17), Value::I64(23)]);
    assert_eq!(engine.sync_input_calls.load(Ordering::SeqCst), 0);
    assert_eq!(engine.input_started.load(Ordering::SeqCst), 2);
    assert_eq!(engine.input_finished.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn execute_many_async_runs_independent_programs_across_online_effects() {
    let engine = Arc::new(BarrierOpenEngine::new(2));
    let runtime_engine: Arc<dyn MpcEngine> = engine.clone();
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .with_register_layout(RegisterLayout::new(1))
        .build();
    vm.set_mpc_engine(runtime_engine);
    vm.register_function(async_open_function("open_first", 11));
    vm.register_function(async_open_function("open_second", 29));

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        vm.execute_many_async(["open_first", "open_second"], engine.as_ref()),
    )
    .await
    .expect("concurrent online effects should both reach the barrier")
    .expect("batched async execution should succeed");

    assert_eq!(result, vec![Value::I64(11), Value::I64(29)]);
    assert_eq!(engine.open_started.load(Ordering::SeqCst), 2);
    assert_eq!(engine.open_finished.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn execute_many_async_yields_on_rbc_receive_builtin_call() {
    let engine = Arc::new(BarrierConsensusEngine::new(2));
    let runtime_engine: Arc<dyn MpcEngine> = engine.clone();
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_engine(runtime_engine)
        .build();
    vm.register_function(async_rbc_receive_call_function("receive_first", 2));
    vm.register_function(async_rbc_receive_call_function("receive_second", 3));

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        vm.execute_many_async(["receive_first", "receive_second"], engine.as_ref()),
    )
    .await
    .expect("Rbc.receive calls should both reach the async barrier")
    .expect("batched async consensus execution should succeed");

    assert_eq!(
        result,
        vec![
            Value::String("from-2".to_string()),
            Value::String("from-3".to_string())
        ]
    );
    assert_eq!(engine.rbc_receive_started.load(Ordering::SeqCst), 2);
    assert_eq!(engine.rbc_receive_finished.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn aba_result_builtin_uses_async_consensus_ops() {
    let engine = Arc::new(BarrierConsensusEngine::new(1));
    let runtime_engine: Arc<dyn MpcEngine> = engine.clone();
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_engine(runtime_engine)
        .build();
    vm.register_function(VMFunction::new(
        "aba_result_async".to_string(),
        Vec::new(),
        Vec::new(),
        None,
        3,
        vec![
            Instruction::LDI(1, Value::I64(3)),
            Instruction::PUSHARG(1),
            Instruction::LDI(2, Value::I64(1_000)),
            Instruction::PUSHARG(2),
            Instruction::CALL("Aba.result".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    ));

    let result = vm
        .execute_async("aba_result_async", engine.as_ref())
        .await
        .expect("Aba.result should execute through async consensus ops");

    assert_eq!(result, Value::Bool(true));
    assert_eq!(engine.aba_result_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn execute_many_async_yields_on_share_open_builtin_call() {
    let engine = Arc::new(BarrierOpenEngine::new(2));
    let runtime_engine: Arc<dyn MpcEngine> = engine.clone();
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_engine(runtime_engine)
        .build();
    vm.register_function(async_share_open_call_function("builtin_open_first", 13));
    vm.register_function(async_share_open_call_function("builtin_open_second", 31));

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        vm.execute_many_async(
            ["builtin_open_first", "builtin_open_second"],
            engine.as_ref(),
        ),
    )
    .await
    .expect("Share.open calls should both reach the async barrier")
    .expect("batched async builtin execution should succeed");

    assert_eq!(result, vec![Value::I64(13), Value::I64(31)]);
    assert_eq!(engine.open_started.load(Ordering::SeqCst), 2);
    assert_eq!(engine.open_finished.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn share_batch_open_builtin_uses_async_batch_open() {
    let engine = Arc::new(AsyncBatchOpenEngine::new());
    let runtime_engine: Arc<dyn MpcEngine> = engine.clone();
    let ty = ShareType::secret_int(64);
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_engine(runtime_engine)
        .build();
    let shares = vm.create_array_ref(2).expect("create shares array");
    vm.push_array_values(
        shares,
        &[
            Value::Share(ty, ShareData::Opaque(vec![5])),
            Value::Share(ty, ShareData::Opaque(vec![8])),
        ],
    )
    .expect("seed shares array");
    vm.register_function(VMFunction::new(
        "builtin_batch_open".to_string(),
        vec!["shares".to_string()],
        Vec::new(),
        None,
        1,
        vec![
            Instruction::PUSHARG(0),
            Instruction::CALL("Share.batch_open".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    ));

    let result = vm
        .execute_async_with_args(
            "builtin_batch_open",
            &[Value::from(shares)],
            engine.as_ref(),
        )
        .await
        .expect("Share.batch_open should execute through async engine");
    let Value::Array(result_ref) = result else {
        panic!("Share.batch_open should return an array");
    };

    assert_eq!(vm.read_array_len(result_ref).expect("result length"), 2);
    assert_eq!(
        vm.read_table_field(TableRef::from(result_ref), &Value::I64(0))
            .expect("read first result"),
        Some(Value::I64(5))
    );
    assert_eq!(
        vm.read_table_field(TableRef::from(result_ref), &Value::I64(1))
            .expect("read second result"),
        Some(Value::I64(8))
    );
    assert_eq!(engine.sync_batch_calls.load(Ordering::SeqCst), 0);
    assert_eq!(engine.async_batch_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn try_register_function_rejects_duplicate_names() {
    let mut vm = setup_vm();
    let first = VMFunction::new(
        "duplicate".to_string(),
        vec![],
        Vec::new(),
        None,
        1,
        vec![Instruction::LDI(0, Value::I64(1)), Instruction::RET(0)],
        HashMap::new(),
    );
    let second = VMFunction::new(
        "duplicate".to_string(),
        vec![],
        Vec::new(),
        None,
        1,
        vec![Instruction::LDI(0, Value::I64(2)), Instruction::RET(0)],
        HashMap::new(),
    );

    vm.try_register_function(first)
        .expect("register first function");
    let err = vm
        .try_register_function(second)
        .expect_err("duplicate function names must be rejected");
    let err = err.to_string();

    assert!(
        err.contains("already registered"),
        "unexpected error: {err}"
    );
    assert_eq!(vm.execute("duplicate").unwrap(), Value::I64(1));
}

#[test]
fn try_register_foreign_function_rejects_duplicate_names() {
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .build();

    vm.try_register_foreign_function("native", |_| Ok(Value::I64(1)))
        .expect("register first foreign function");
    let err = vm
        .try_register_foreign_function("native", |_| Ok(Value::I64(2)))
        .expect_err("duplicate foreign function names must be rejected");
    let err = err.to_string();

    assert!(
        err.contains("already registered"),
        "unexpected error: {err}"
    );
    assert_eq!(vm.execute_with_args("native", &[]).unwrap(), Value::I64(1));
}

#[test]
fn vm_entry_rejects_foreign_functions_with_typed_runtime_error() {
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .build();

    vm.try_register_foreign_function("native", |_| Ok(Value::I64(1)))
        .expect("register foreign function");

    let err = vm
        .execute("native")
        .expect_err("foreign functions cannot be VM entry frames");
    assert_eq!(err.kind(), VirtualMachineErrorKind::Runtime);
    assert_eq!(err.to_string(), "Cannot execute foreign function native");

    assert_eq!(vm.execute_with_args("native", &[]).unwrap(), Value::I64(1));
}

#[test]
fn vm_entry_rejects_functions_that_require_captured_upvalues() {
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .build();

    vm.try_register_function(create_test_vmfunction(
        "needs_capture".to_string(),
        Vec::new(),
        vec!["secret_context".to_string()],
        None,
        1,
        vec![Instruction::RET(0)],
        HashMap::new(),
    ))
    .expect("register function with upvalues");

    let err = vm
        .execute("needs_capture")
        .expect_err("entry points cannot require captured upvalues");

    assert_eq!(err.kind(), VirtualMachineErrorKind::Runtime);
    assert!(err.to_string().contains("requires captured upvalues"));
    assert!(err.to_string().contains("secret_context"));
    assert!(vm.state.current_activation_record().is_none());
}

#[test]
fn typed_foreign_function_registration_accepts_structured_callback_errors() {
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .build();

    vm.try_register_typed_foreign_function("native.typed", |mut ctx| ctx.create_object())
        .expect("typed foreign function registration should succeed");
    assert!(matches!(
        vm.execute_with_args("native.typed", &[]).unwrap(),
        Value::Object(_)
    ));

    vm.try_register_typed_foreign_function("native.typed_fail", |_ctx| {
        Err(ForeignFunctionCallbackError::from("typed failure"))
    })
    .expect("typed failing foreign function registration should succeed");

    let err = vm
        .execute_with_args("native.typed_fail", &[])
        .expect_err("typed callback error should propagate through VM execution");
    assert_eq!(err.kind(), VirtualMachineErrorKind::ForeignFunction);
    assert_eq!(
        err.to_string(),
        "Foreign function native.typed_fail failed: typed failure"
    );
}

#[test]
fn typed_foreign_function_can_use_named_argument_facade() {
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .build();

    vm.try_register_typed_foreign_function("native.describe", |ctx| {
        let args = ctx.named_args("native.describe");
        args.require_exact(2, "2 arguments: label, count")?;
        let label = args.string(0, "label")?;
        let count = args.usize(1, "count")?;

        Ok(Value::String(format!("{label}:{count}")))
    })
    .expect("typed foreign function registration should succeed");

    let result = vm
        .execute_with_args(
            "native.describe",
            &[Value::String("items".to_owned()), Value::I64(3)],
        )
        .expect("typed native function should execute");
    assert_eq!(result, Value::String("items:3".to_owned()));

    let err = vm
        .execute_with_args(
            "native.describe",
            &[
                Value::String("items".to_owned()),
                Value::String("many".to_owned()),
            ],
        )
        .expect_err("typed argument facade should report conversion failure");
    assert_eq!(err.kind(), VirtualMachineErrorKind::ForeignFunction);
    assert!(err
        .to_string()
        .contains("count must be a non-negative integer"));
}

#[test]
fn try_register_standard_library_rejects_duplicate_registration() {
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .build();

    vm.try_register_standard_library()
        .expect("first standard library registration should succeed");
    let err = vm
        .try_register_standard_library()
        .expect_err("second standard library registration must be rejected");
    assert_eq!(err.kind(), VirtualMachineErrorKind::Registration);
    let err = err.to_string();

    assert!(
        err.contains("create_object") && err.contains("already registered"),
        "unexpected error: {err}"
    );
    assert!(vm.has_function("create_object"));
}

#[test]
fn test_create_array_rejects_negative_capacity() {
    let mut vm = setup_vm();
    let err = vm
        .execute_with_args("create_array", &[Value::I64(-1)])
        .expect_err("negative array capacity must be rejected");
    assert_eq!(err.kind(), VirtualMachineErrorKind::ForeignFunction);
    assert_eq!(
        callback_error(&err).runtime_kind(),
        Some(VirtualMachineErrorKind::Value)
    );
    let err = err.to_string();
    assert!(err.contains("non-negative"));
}

#[test]
fn test_create_array_accepts_vm_integer_width_capacity() {
    let mut vm = setup_vm();

    let result = vm
        .execute_with_args("create_array", &[Value::U8(4)])
        .expect("u8 array capacity should use shared integer conversion");

    assert!(matches!(result, Value::Array(_)));
}

#[test]
fn test_less_than_jump() {
    let mut vm = setup_vm();

    let mut labels = HashMap::new();
    labels.insert("less_than".to_string(), 6);
    labels.insert("end".to_string(), 7);

    // Use the new VMFunction::new method to create a function with default values for the new fields
    let test_function = VMFunction::new(
        "test_less_than_jump".to_string(),
        vec![],
        Vec::new(),
        None,
        3,
        vec![
            Instruction::LDI(0, Value::I64(5)),          // r0 = 5
            Instruction::LDI(1, Value::I64(10)),         // r1 = 10
            Instruction::CMP(0, 1),                      // Compare r0 < r1
            Instruction::JMPLT("less_than".to_string()), // Jump if less than
            Instruction::LDI(2, Value::I64(0)),          // Should be skipped
            Instruction::JMP("end".to_string()),
            // less_than:
            Instruction::LDI(2, Value::I64(1)), // Set result to 1 if jump taken
            // end:
            Instruction::RET(2),
        ],
        labels,
    );

    vm.register_function(test_function);
    let result = vm.execute("test_less_than_jump").unwrap();
    assert_eq!(result, Value::I64(1)); // Expect 1 because 5 < 10
}

#[test]
fn test_greater_than_jump() {
    let mut vm = setup_vm();

    let mut labels = HashMap::new();
    labels.insert("greater_than".to_string(), 6);
    labels.insert("end".to_string(), 7);

    let test_function = VMFunction::new(
        "test_greater_than_jump".to_string(),
        vec![],
        Vec::new(),
        None,
        3,
        vec![
            Instruction::LDI(0, Value::I64(15)),            // r0 = 15
            Instruction::LDI(1, Value::I64(10)),            // r1 = 10
            Instruction::CMP(0, 1),                         // Compare r0 > r1
            Instruction::JMPGT("greater_than".to_string()), // Jump if greater than
            Instruction::LDI(2, Value::I64(0)),             // Should be skipped
            Instruction::JMP("end".to_string()),
            // greater_than:
            Instruction::LDI(2, Value::I64(1)), // Set result to 1 if jump taken
            // end:
            Instruction::RET(2),
        ],
        labels,
    );

    vm.register_function(test_function);
    let result = vm.execute("test_greater_than_jump").unwrap();
    assert_eq!(result, Value::I64(1)); // Expect 1 because 15 > 10
}

// Example of using new jumps for <=
// Jump if NOT greater than (JMPGT to the false branch)
// Or Jump if Less Than OR Equal (JMPLT target; JMPEQ target)

#[test]
fn test_load_instructions() {
    let mut vm = setup_vm();

    let test_function = VMFunction::new(
        "test_load".to_string(),
        vec![],
        Vec::new(),
        None,
        3,
        vec![
            // Push value to stack
            Instruction::LDI(0, Value::I64(42)),
            Instruction::PUSHARG(0),
            // Load from stack to register
            Instruction::LD(1, 0),
            // Move between registers
            Instruction::MOV(2, 1),
            Instruction::RET(2),
        ],
        HashMap::new(),
    );

    vm.register_function(test_function);
    let result = vm.execute("test_load").unwrap();
    assert_eq!(result, Value::I64(42));
}

#[test]
fn test_object_operations() {
    let mut vm = setup_vm();

    let test_function = VMFunction::new(
        "test_objects".to_string(),
        vec![],
        Vec::new(),
        None,
        5,
        vec![
            // Create object
            Instruction::CALL("create_object".to_string()),
            Instruction::MOV(1, 0),
            // Set field "name" to "test"
            Instruction::PUSHARG(1),
            Instruction::LDI(2, Value::String("name".to_string())),
            Instruction::PUSHARG(2),
            Instruction::LDI(3, Value::String("test".to_string())),
            Instruction::PUSHARG(3),
            Instruction::CALL("set_field".to_string()),
            // Get field "name"
            Instruction::PUSHARG(1),
            Instruction::PUSHARG(2),
            Instruction::CALL("get_field".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(test_function);
    let result = vm.execute("test_objects").unwrap();
    assert_eq!(result, Value::String("test".to_string()));
}

#[test]
fn test_object_nested_fields() {
    let mut vm = setup_vm();

    let test_function = VMFunction::new(
        "test_nested_objects".to_string(),
        vec![],
        Vec::new(),
        None,
        5,
        vec![
            // Create parent object
            Instruction::CALL("create_object".to_string()),
            Instruction::MOV(1, 0),
            // Create child object
            Instruction::CALL("create_object".to_string()),
            Instruction::MOV(2, 0),
            // Set child.value = 42
            Instruction::PUSHARG(2),
            Instruction::LDI(3, Value::String("value".to_string())),
            Instruction::PUSHARG(3),
            Instruction::LDI(4, Value::I64(42)),
            Instruction::PUSHARG(4),
            Instruction::CALL("set_field".to_string()),
            // Set parent.child = child
            Instruction::PUSHARG(1),
            Instruction::LDI(3, Value::String("child".to_string())),
            Instruction::PUSHARG(3),
            Instruction::PUSHARG(2),
            Instruction::CALL("set_field".to_string()),
            // Get parent.child
            Instruction::PUSHARG(1),
            Instruction::PUSHARG(3),
            Instruction::CALL("get_field".to_string()),
            Instruction::MOV(2, 0),
            // Get child.value
            Instruction::PUSHARG(2),
            Instruction::LDI(3, Value::String("value".to_string())),
            Instruction::PUSHARG(3),
            Instruction::CALL("get_field".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(test_function);
    let result = vm.execute("test_nested_objects").unwrap();
    assert_eq!(result, Value::I64(42));
}

#[test]
fn test_array_operations() {
    let mut vm = setup_vm();

    let test_function = VMFunction::new(
        "test_arrays".to_string(),
        vec![],
        Vec::new(),
        None,
        5,
        vec![
            // Create array
            Instruction::LDI(0, Value::I64(5)),
            Instruction::PUSHARG(0),
            Instruction::CALL("create_array".to_string()),
            Instruction::MOV(1, 0),
            // Push elements
            Instruction::PUSHARG(1),
            Instruction::LDI(2, Value::I64(42)),
            Instruction::PUSHARG(2),
            Instruction::CALL("array_push".to_string()),
            // Get element at index 0 (0-indexed array)
            Instruction::PUSHARG(1),
            Instruction::LDI(3, Value::I64(0)),
            Instruction::PUSHARG(3),
            Instruction::CALL("get_field".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(test_function);
    let result = vm.execute("test_arrays").unwrap();
    assert_eq!(result, Value::I64(42));
}

#[test]
fn test_array_length() {
    let mut vm = setup_vm();

    let test_function = VMFunction::new(
        "test_array_length".to_string(),
        vec![],
        Vec::new(),
        None,
        5,
        vec![
            // Create array
            Instruction::CALL("create_array".to_string()),
            Instruction::MOV(1, 0),
            // Push multiple elements
            Instruction::PUSHARG(1),
            Instruction::LDI(2, Value::I64(10)),
            Instruction::PUSHARG(2),
            Instruction::CALL("array_push".to_string()),
            Instruction::PUSHARG(1),
            Instruction::LDI(2, Value::I64(20)),
            Instruction::PUSHARG(2),
            Instruction::CALL("array_push".to_string()),
            Instruction::PUSHARG(1),
            Instruction::LDI(2, Value::I64(30)),
            Instruction::PUSHARG(2),
            Instruction::CALL("array_push".to_string()),
            // Get array length
            Instruction::PUSHARG(1),
            Instruction::CALL("array_length".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(test_function);
    let result = vm.execute("test_array_length").unwrap();
    assert_eq!(result, Value::I64(3));
}

#[test]
fn test_array_non_integer_indices() {
    let mut vm = setup_vm();

    let test_function = VMFunction::new(
        "test_array_string_keys".to_string(),
        vec![],
        Vec::new(),
        None,
        5,
        vec![
            // Create array
            Instruction::CALL("create_array".to_string()),
            Instruction::MOV(1, 0),
            // Set array["key"] = "value"
            Instruction::PUSHARG(1),
            Instruction::LDI(2, Value::String("key".to_string())),
            Instruction::PUSHARG(2),
            Instruction::LDI(3, Value::String("value".to_string())),
            Instruction::PUSHARG(3),
            Instruction::CALL("set_field".to_string()),
            // Get array["key"]
            Instruction::PUSHARG(1),
            Instruction::PUSHARG(2),
            Instruction::CALL("get_field".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(test_function);
    let result = vm.execute("test_array_string_keys").unwrap();
    assert_eq!(result, Value::String("value".to_string()));
}

#[test]
fn test_closures() {
    let mut vm = setup_vm();

    // Counter creator function
    let create_counter = VMFunction::new(
        "create_counter".to_string(),
        vec!["start".to_string()],
        Vec::new(),
        None,
        5,
        vec![
            Instruction::LDI(1, Value::String("increment".to_string())),
            Instruction::PUSHARG(1),
            Instruction::LDI(2, Value::String("start".to_string())),
            Instruction::PUSHARG(2),
            Instruction::CALL("create_closure".to_string()),
            // Save the closure in another register BEFORE calling type/print
            Instruction::MOV(3, 0), // Save closure to r3
            // Now it's safe to do debug prints
            Instruction::PUSHARG(0),
            Instruction::CALL("type".to_string()),
            Instruction::PUSHARG(0),
            Instruction::CALL("print".to_string()),
            // Restore the closure to r0 before returning
            Instruction::MOV(0, 3),
            Instruction::RET(0), // Now returns the closure
        ],
        HashMap::new(),
    );

    let increment = VMFunction::new(
        "increment".to_string(),
        vec!["amount".to_string()],
        vec!["start".to_string()],
        Some("create_counter".to_string()),
        5,
        vec![
            // "amount" is in r0
            Instruction::MOV(2, 0), // Save amount to r2 before it gets overwritten
            // Get upvalue value
            Instruction::LDI(1, Value::String("start".to_string())),
            Instruction::PUSHARG(1),
            Instruction::CALL("get_upvalue".to_string()),
            // Current "start" value is now in r0

            // Add amount to start
            Instruction::ADD(3, 0, 2), // r3 = start + amount
            // Update the upvalue
            Instruction::LDI(1, Value::String("start".to_string())),
            Instruction::PUSHARG(1),
            Instruction::PUSHARG(3),
            Instruction::CALL("set_upvalue".to_string()),
            // r0 now contains unit/void

            // Return the new value
            Instruction::MOV(0, 3), // Put result back in r0 before returning
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    // Test function
    let test_function = VMFunction::new(
        "test_closures".to_string(),
        vec![],
        Vec::new(),
        None,
        8,
        vec![
            // Create counter with initial value 10
            Instruction::LDI(0, Value::I64(10)),
            Instruction::PUSHARG(0),
            Instruction::CALL("create_counter".to_string()),
            Instruction::MOV(1, 0), // Save closure in r1
            // ONLY INCLUDE SIMPLE DEBUGGING - NO CHAINED CALLS
            // This simple debugging won't cause stack issues
            Instruction::PUSHARG(1),
            Instruction::CALL("type".to_string()),
            Instruction::MOV(5, 0), // Save type result
            Instruction::PUSHARG(5),
            Instruction::CALL("print".to_string()),
            // First call to increment
            Instruction::PUSHARG(1),
            Instruction::LDI(2, Value::I64(5)),
            Instruction::PUSHARG(2),
            Instruction::CALL("call_closure".to_string()),
            Instruction::MOV(3, 0), // Save first result in r3
            // Print first result (standalone calls)
            Instruction::PUSHARG(3),
            Instruction::CALL("print".to_string()),
            // Second call to increment
            Instruction::PUSHARG(1),
            Instruction::LDI(2, Value::I64(7)),
            Instruction::PUSHARG(2),
            Instruction::CALL("call_closure".to_string()),
            Instruction::MOV(4, 0), // Save second result in r4
            // Print second result (standalone calls)
            Instruction::PUSHARG(4),
            Instruction::CALL("print".to_string()),
            // Return final result
            Instruction::RET(4),
        ],
        HashMap::new(),
    );

    vm.register_function(create_counter);
    vm.register_function(increment);
    vm.register_function(test_function);

    // Before running the test
    let upvalue_log = Arc::new(Mutex::new(Vec::new()));
    let upvalue_log_clone = Arc::clone(&upvalue_log);

    vm.register_hook(
        |event| {
            matches!(event, HookEvent::UpvalueRead(_, _))
                || matches!(event, HookEvent::UpvalueWrite(_, _, _))
        },
        move |event, _ctx| {
            // add 'move' keyword to explicitly capture upvalue_log_clone
            match event {
                HookEvent::UpvalueRead(name, value) => {
                    let mut log = upvalue_log_clone.lock();
                    log.push(format!("Read {} = {:?}", name, value));
                }
                HookEvent::UpvalueWrite(name, old, new) => {
                    let mut log = upvalue_log_clone.lock();
                    log.push(format!("Write {} {:?} -> {:?}", name, old, new));
                }
                _ => {}
            }
            Ok(())
        },
        100,
    );

    // Run the test
    let result = vm.execute("test_closures").unwrap();

    // Print the upvalue operations log
    println!("UPVALUE OPERATIONS:");
    let log = upvalue_log.lock();
    for entry in log.iter() {
        println!("{}", entry);
    }

    // Check expected value
    assert_eq!(result, Value::I64(22));
}

#[test]
fn test_multiple_closures() {
    let mut vm = setup_vm();

    // Counter creator function
    let create_counter = VMFunction::new(
        "create_counter".to_string(),
        vec!["start".to_string()],
        Vec::new(),
        None,
        5,
        vec![
            // Store start parameter as local variable to isolate it per closure
            Instruction::MOV(3, 0), // Copy start parameter to r3
            // Create the increment closure with the local start value
            Instruction::LDI(1, Value::String("increment".to_string())),
            Instruction::PUSHARG(1),
            Instruction::LDI(2, Value::String("start".to_string())),
            Instruction::PUSHARG(2),
            Instruction::CALL("create_closure".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    // Increment function
    let increment = VMFunction::new(
        "increment".to_string(),
        vec!["amount".to_string()],
        vec!["start".to_string()],
        Some("create_counter".to_string()),
        5,
        vec![
            // Get upvalue
            Instruction::LDI(1, Value::String("start".to_string())),
            Instruction::PUSHARG(1),
            Instruction::CALL("get_upvalue".to_string()),
            Instruction::MOV(1, 0),
            // Add amount
            Instruction::ADD(2, 1, 0),
            // Set upvalue
            Instruction::LDI(3, Value::String("start".to_string())),
            Instruction::PUSHARG(3),
            Instruction::PUSHARG(2),
            Instruction::CALL("set_upvalue".to_string()),
            // Return new value
            Instruction::MOV(0, 2),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    // Test function with multiple counters
    let test_function = VMFunction::new(
        "test_multiple_closures".to_string(),
        vec![],
        Vec::new(),
        None,
        5,
        vec![
            // Create counter1 with initial value 10
            Instruction::LDI(0, Value::I64(10)),
            Instruction::PUSHARG(0),
            Instruction::CALL("create_counter".to_string()),
            Instruction::MOV(1, 0),
            // Create counter2 with initial value 20
            Instruction::LDI(0, Value::I64(20)),
            Instruction::PUSHARG(0),
            Instruction::CALL("create_counter".to_string()),
            Instruction::MOV(2, 0),
            // Call counter1 with 5
            Instruction::PUSHARG(1),
            Instruction::LDI(0, Value::I64(5)),
            Instruction::PUSHARG(0),
            Instruction::CALL("call_closure".to_string()),
            Instruction::MOV(3, 0),
            // Call counter2 with 10
            Instruction::PUSHARG(2),
            Instruction::LDI(0, Value::I64(10)),
            Instruction::PUSHARG(0),
            Instruction::CALL("call_closure".to_string()),
            Instruction::MOV(4, 0),
            // Return counter2 result
            Instruction::RET(4),
        ],
        HashMap::new(),
    );

    vm.register_function(create_counter);
    vm.register_function(increment);
    vm.register_function(test_function);

    // Before running the test
    let upvalue_log = Arc::new(Mutex::new(Vec::new()));
    let upvalue_log_clone = Arc::clone(&upvalue_log);

    vm.register_hook(
        |event| matches!(event, HookEvent::ClosureCreated(_, _)),
        move |event, _ctx| {
            if let HookEvent::ClosureCreated(func_name, upvalues) = event {
                println!("CLOSURE CREATED: {} with upvalues:", func_name);
                for upval in upvalues {
                    println!("  - {}: {:?}", upval.name(), upval.value());
                }
            }
            Ok(())
        },
        100,
    );

    // 2. Hook for function calls
    vm.register_hook(
        |event| matches!(event, HookEvent::BeforeFunctionCall(_, _)),
        move |event, _ctx| {
            if let HookEvent::BeforeFunctionCall(func, args) = event {
                println!("FUNCTION CALL: {:?} with args: {:?}", func, args);
            }
            Ok(())
        },
        100,
    );

    // 3. Hook for function returns
    vm.register_hook(
        |event| matches!(event, HookEvent::AfterFunctionCall(_, _)),
        move |event, _ctx| {
            if let HookEvent::AfterFunctionCall(func, result) = event {
                println!("FUNCTION RETURN: {:?} -> {:?}", func, result);
            }
            Ok(())
        },
        100,
    );

    // 4. Hook for register operations
    vm.register_hook(
        |event| matches!(event, HookEvent::RegisterWrite(_, _, _)),
        move |event, _ctx| {
            if let HookEvent::RegisterWrite(reg, old, new) = event {
                println!("REGISTER WRITE: r{} = {:?} (was {:?})", reg, new, old);
            }
            Ok(())
        },
        100,
    );

    // 5. Hook for stack operations
    vm.register_hook(
        |event| matches!(event, HookEvent::StackPush(_)) || matches!(event, HookEvent::StackPop(_)),
        move |event, _ctx| {
            match event {
                HookEvent::StackPush(value) => println!("STACK PUSH: {:?}", value),
                HookEvent::StackPop(value) => println!("STACK POP: {:?}", value),
                _ => {}
            }
            Ok(())
        },
        100,
    );

    // 6. Hook for local variable operations
    vm.register_hook(
        |event| {
            matches!(event, HookEvent::VariableRead(_, _))
                || matches!(event, HookEvent::VariableWrite(_, _, _))
        },
        move |event, _ctx| {
            match event {
                HookEvent::VariableRead(name, value) => {
                    println!("VARIABLE READ: {} = {:?}", name, value);
                }
                HookEvent::VariableWrite(name, old, new) => {
                    println!("VARIABLE WRITE: {} = {:?} (was {:?})", name, new, old);
                }
                _ => {}
            }
            Ok(())
        },
        100,
    );

    // 7. Hook for instruction execution
    vm.register_hook(
        |event| matches!(event, HookEvent::BeforeInstructionExecute(_)),
        move |event, ctx| {
            if let HookEvent::BeforeInstructionExecute(instr) = event {
                let func_name = ctx
                    .get_function_name()
                    .unwrap_or_else(|| "unknown".to_string());
                println!(
                    "EXEC [{}:{}]: {:?}",
                    func_name,
                    ctx.get_current_instruction(),
                    instr
                );
            }
            Ok(())
        },
        100,
    );

    // 8. Hook specifically to trace activation records
    vm.register_hook(
        |_| true, // Any event
        move |event, _ctx| {
            // This runs on every hook - add these lines to the existing upvalue hook
            if matches!(event, HookEvent::UpvalueRead(_, _))
                || matches!(event, HookEvent::UpvalueWrite(_, _, _))
            {
                // Get call stack information
                println!("  Call stack depth: {}", _ctx.get_call_depth());
                println!(
                    "  Current function: {}",
                    _ctx.get_function_name().unwrap_or_default()
                );
            }
            Ok(())
        },
        90, // Lower priority so it runs after other hooks
    );

    vm.register_hook(
        |event| {
            matches!(event, HookEvent::UpvalueRead(_, _))
                || matches!(event, HookEvent::UpvalueWrite(_, _, _))
        },
        move |event, _ctx| {
            // add 'move' keyword to explicitly capture upvalue_log_clone
            match event {
                HookEvent::UpvalueRead(name, value) => {
                    let mut log = upvalue_log_clone.lock();
                    log.push(format!("Read {} = {:?}", name, value));
                }
                HookEvent::UpvalueWrite(name, old, new) => {
                    let mut log = upvalue_log_clone.lock();
                    log.push(format!("Write {} {:?} -> {:?}", name, old, new));
                }
                _ => {}
            }
            Ok(())
        },
        100,
    );

    let result = vm.execute("test_multiple_closures").unwrap();

    // Print the upvalue operations log
    println!("UPVALUE OPERATIONS:");
    let log = upvalue_log.lock();
    for entry in log.iter() {
        println!("{}", entry);
    }

    // The test should return an integer value, which is the result of calling the second counter with 10
    assert_eq!(result, Value::I64(40)); // 20 + 10 + 10 = 40
}

#[test]
fn test_nested_closures() {
    let mut vm = setup_vm();

    // Create a function that returns a function that captures both parameters
    let create_adder = create_test_vmfunction(
        "create_adder".to_string(),
        vec!["x".to_string()],
        Vec::new(),
        None,
        5,
        vec![
            Instruction::LDI(1, Value::String("add".to_string())),
            Instruction::PUSHARG(1),
            Instruction::LDI(2, Value::String("x".to_string())),
            Instruction::PUSHARG(2),
            Instruction::CALL("create_closure".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    // The inner function that adds its parameter to the captured x
    let add = create_test_vmfunction(
        "add".to_string(),
        vec!["y".to_string()],
        vec!["x".to_string()],
        Some("create_adder".to_string()),
        5,
        vec![
            // Save y in register r3 so it doesn't get overwritten
            Instruction::MOV(3, 0), // r3 = y
            // Get upvalue x
            Instruction::LDI(1, Value::String("x".to_string())),
            Instruction::PUSHARG(1),
            Instruction::CALL("get_upvalue".to_string()),
            // x is now in r0

            // Add y (in r3) to x (in r0)
            Instruction::ADD(2, 0, 3), // r2 = x + y
            // Make sure we're returning the right value
            Instruction::MOV(0, 2), // r0 = r2 (result)
            Instruction::RET(0),    // Return register 0
        ],
        HashMap::new(),
    );

    // Test function
    let test_function = create_test_vmfunction(
        "test_nested_closures".to_string(),
        vec![],
        Vec::new(),
        None,
        5,
        vec![
            // Create adder with x=10
            Instruction::LDI(0, Value::I64(10)),
            Instruction::PUSHARG(0),
            Instruction::CALL("create_adder".to_string()),
            Instruction::MOV(1, 0),
            // Call adder with y=5
            Instruction::PUSHARG(1),
            Instruction::LDI(0, Value::I64(5)),
            Instruction::PUSHARG(0),
            Instruction::CALL("call_closure".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(create_adder);
    vm.register_function(add);
    vm.register_function(test_function);

    let result = vm.execute("test_nested_closures").unwrap();
    assert_eq!(result, Value::I64(15)); // 10 + 5 = 15
}

#[test]
fn test_foreign_functions() {
    let mut vm = setup_vm();

    // Register a custom foreign function
    vm.register_foreign_function("double", |ctx| {
        let args = ctx.args();
        if args.len() != 1 {
            return Err("double expects 1 argument".to_string());
        }

        match &args[0] {
            Value::I64(n) => Ok(Value::I64(n * 2)),
            _ => Err("double expects an integer".to_string()),
        }
    });

    let test_function = VMFunction::new(
        "test_foreign".to_string(),
        vec![],
        Vec::new(),
        None,
        3,
        vec![
            Instruction::LDI(0, Value::I64(21)),
            Instruction::PUSHARG(0),
            Instruction::CALL("double".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(test_function);
    let result = vm.execute("test_foreign").unwrap();
    assert_eq!(result, Value::I64(42));
}

#[test]
fn test_foreign_function_with_multiple_args() {
    let mut vm = setup_vm();

    // Register a custom foreign function that takes multiple arguments
    vm.register_foreign_function("sum", |ctx| {
        let args = ctx.args();
        if args.len() < 2 {
            return Err("sum expects at least 2 arguments".to_string());
        }

        let mut total = 0;
        for arg in args {
            match arg {
                Value::I64(n) => total += n,
                _ => return Err("sum expects integers".to_string()),
            }
        }

        Ok(Value::I64(total))
    });

    let test_function = VMFunction::new(
        "test_foreign_multi_args".to_string(),
        vec![],
        Vec::new(),
        None,
        4,
        vec![
            Instruction::LDI(0, Value::I64(10)),
            Instruction::PUSHARG(0),
            Instruction::LDI(1, Value::I64(20)),
            Instruction::PUSHARG(1),
            Instruction::LDI(2, Value::I64(12)),
            Instruction::PUSHARG(2),
            Instruction::CALL("sum".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(test_function);
    let result = vm.execute("test_foreign_multi_args").unwrap();
    assert_eq!(result, Value::I64(42));
}

#[test]
fn test_foreign_objects() {
    let mut vm = setup_vm();

    // Create a custom struct
    #[derive(Clone)]
    struct TestObject {
        value: i32,
    }

    let obj = TestObject { value: 42 };
    let obj_ref = vm.register_foreign_object(obj);
    let obj_value = Value::from(obj_ref);
    assert!(vm.get_foreign_object::<TestObject>(obj_ref).is_some());

    // Register a function to access the object
    vm.register_foreign_function("get_test_object_value", move |ctx| {
        let args = ctx.args();
        if args.len() != 1 {
            return Err("get_test_object_value expects 1 argument".to_string());
        }

        let foreign_ref = ForeignObjectRef::from_value(&args[0])
            .ok_or_else(|| "Expected foreign object".to_string())?;
        if let Some(obj_arc) = ctx.get_foreign_object::<TestObject>(foreign_ref) {
            let locked = obj_arc.lock();
            // Return the actual value, not the pointer
            Ok(Value::I64(locked.value as i64))
        } else {
            Err("Invalid foreign object".to_string())
        }
    });

    let test_function = VMFunction::new(
        "test_foreign_object".to_string(),
        vec![],
        Vec::new(),
        None,
        2,
        vec![
            Instruction::LDI(0, obj_value),
            Instruction::PUSHARG(0),
            Instruction::CALL("get_test_object_value".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(test_function);
    let result = vm.execute("test_foreign_object").unwrap();
    assert_eq!(result, Value::I64(42));
}

#[test]
fn test_foreign_object_mutation() {
    let mut vm = setup_vm();

    // Create a custom struct
    struct Counter {
        value: i64,
    }

    let counter = Counter { value: 0 };
    let counter_ref = vm.register_foreign_object(counter);
    let counter_value = Value::from(counter_ref);

    vm.register_foreign_function("increment_counter", move |ctx| {
        let args = ctx.args();
        if args.len() != 2 {
            return Err(format!(
                "increment_counter expects 2 arguments: counter and amount, got {}",
                args.len()
            ));
        }

        let foreign_ref = ForeignObjectRef::from_value(&args[0])
            .ok_or_else(|| format!("Expected foreign object, got {:?}", args[0]))?;

        if let Some(counter_rc) = ctx.get_foreign_object::<Counter>(foreign_ref) {
            let amount = match &args[1] {
                Value::I64(n) => n,
                other => {
                    return Err(format!(
                        "Second argument must be an integer, got {:?}",
                        other
                    ));
                }
            };
            let mut counter = counter_rc.lock();
            counter.value += amount;
            let new_value = counter.value;

            Ok(Value::I64(new_value))
        } else {
            Err(format!(
                "Foreign object with ID {} not found or wrong type",
                foreign_ref.id()
            ))
        }
    });

    let test_function = VMFunction::new(
        "test_foreign_object_mutation".to_string(),
        vec![],
        Vec::new(),
        None,
        3,
        vec![
            Instruction::LDI(0, counter_value.clone()),
            Instruction::PUSHARG(0),
            Instruction::LDI(1, Value::I64(10)),
            Instruction::PUSHARG(1),
            Instruction::CALL("increment_counter".to_string()),
            Instruction::LDI(0, counter_value),
            Instruction::PUSHARG(0),
            Instruction::LDI(1, Value::I64(32)),
            Instruction::PUSHARG(1),
            Instruction::CALL("increment_counter".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(test_function);
    let result = vm.execute("test_foreign_object_mutation").unwrap();
    assert_eq!(result, Value::I64(42)); // 0 + 10 + 32 = 42
}

#[test]
fn test_hook_system() {
    let mut vm = setup_vm();

    // Use a RefCell to track hook calls
    let hook_calls = Arc::new(Mutex::new(0));
    let hook_calls_clone = Arc::clone(&hook_calls);

    // Register a hook that counts instruction executions
    vm.register_hook(
        |event| matches!(event, HookEvent::BeforeInstructionExecute(_)),
        move |_, _| {
            let mut calls = hook_calls_clone.lock();
            *calls += 1;
            Ok(())
        },
        100,
    );

    let test_function = VMFunction::new(
        "test_hooks".to_string(),
        vec![],
        Vec::new(),
        None,
        2,
        vec![
            Instruction::LDI(0, Value::I64(1)),
            Instruction::LDI(1, Value::I64(2)),
            Instruction::ADD(0, 0, 1),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(test_function);
    let result = vm.execute("test_hooks").unwrap();

    assert_eq!(result, Value::I64(3));
    let hook_calls = hook_calls.lock();
    assert_eq!(*hook_calls, 4); // 4 instructions executed
}

#[test]
fn table_hook_events_expose_typed_table_refs() {
    let mut vm = setup_vm();
    let events = Arc::new(Mutex::new(Vec::<HookEvent>::new()));
    let events_for_hook = Arc::clone(&events);

    vm.register_hook(
        |event| {
            matches!(
                event,
                HookEvent::ObjectFieldRead(_, _, _)
                    | HookEvent::ObjectFieldWrite(_, _, _, _)
                    | HookEvent::ArrayElementRead(_, _, _)
                    | HookEvent::ArrayElementWrite(_, _, _, _)
            )
        },
        move |event, _| {
            events_for_hook.lock().push(event.clone());
            Ok(())
        },
        100,
    );

    let object_ref = vm.create_object_ref().expect("create object");
    let object_key = Value::String("answer".to_string());
    vm.execute_with_args(
        "set_field",
        &[Value::from(object_ref), object_key.clone(), Value::I64(7)],
    )
    .expect("set object field");
    assert_eq!(
        vm.execute_with_args("get_field", &[Value::from(object_ref), object_key.clone()])
            .expect("read object field"),
        Value::I64(7)
    );

    let array_ref = vm.create_array_ref(0).expect("create array");
    let array_key = Value::I64(0);
    vm.execute_with_args(
        "set_field",
        &[Value::from(array_ref), array_key.clone(), Value::I64(9)],
    )
    .expect("set array element");
    assert_eq!(
        vm.execute_with_args("get_field", &[Value::from(array_ref), array_key.clone()])
            .expect("read array element"),
        Value::I64(9)
    );

    let events = events.lock();
    assert_eq!(events.len(), 4);
    assert!(matches!(
        &events[0],
        HookEvent::ObjectFieldWrite(
            event_ref,
            event_key,
            Value::Unit,
            Value::I64(7)
        ) if *event_ref == object_ref && event_key == &object_key
    ));
    assert!(matches!(
        &events[1],
        HookEvent::ObjectFieldRead(event_ref, event_key, Value::I64(7))
            if *event_ref == object_ref && event_key == &object_key
    ));
    assert!(matches!(
        &events[2],
        HookEvent::ArrayElementWrite(
            event_ref,
            event_key,
            Value::Unit,
            Value::I64(9)
        ) if *event_ref == array_ref && event_key == &array_key
    ));
    assert!(matches!(
        &events[3],
        HookEvent::ArrayElementRead(event_ref, event_key, Value::I64(9))
            if *event_ref == array_ref && event_key == &array_key
    ));
}

#[test]
fn test_register_read_write_hooks() {
    let mut vm = setup_vm();

    // Track register writes
    let register_writes = Arc::new(Mutex::new(Vec::<(usize, Value)>::new()));
    let register_writes_clone = Arc::clone(&register_writes);

    // Then fix the hook registration
    vm.register_hook(
        |event| matches!(event, HookEvent::RegisterWrite(_, _, _)),
        move |event, _ctx| {
            if let HookEvent::RegisterWrite(reg, _, new_value) = event {
                let mut log = register_writes_clone.lock();
                log.push((reg.index(), new_value.clone()));
            }
            Ok(())
        },
        100,
    );

    let test_function = VMFunction::new(
        "test_register_hooks".to_string(),
        vec![],
        Vec::new(),
        None,
        3,
        vec![
            Instruction::LDI(0, Value::I64(10)),
            Instruction::LDI(1, Value::I64(20)),
            Instruction::ADD(2, 0, 1),
            Instruction::RET(2),
        ],
        HashMap::new(),
    );

    vm.register_function(test_function);
    let result = vm.execute("test_register_hooks").unwrap();

    assert_eq!(result, Value::I64(30));

    let writes = register_writes.lock();
    assert_eq!(writes.len(), 3);
    assert_eq!(writes[0], (0, Value::I64(10)));
    assert_eq!(writes[1], (1, Value::I64(20)));
    assert_eq!(writes[2], (2, Value::I64(30)));
}

#[test]
fn test_upvalue_hooks() {
    let mut vm = setup_vm();

    // Track upvalue operations
    let upvalue_ops = Arc::new(Mutex::new(Vec::new()));
    let upvalue_ops_clone = Arc::clone(&upvalue_ops);

    // Register a hook that tracks upvalue operations
    vm.register_hook(
        |event| {
            matches!(event, HookEvent::UpvalueRead(_, _))
                || matches!(event, HookEvent::UpvalueWrite(_, _, _))
        },
        move |event, _ctx| {
            match event {
                HookEvent::UpvalueRead(name, value) => {
                    println!("UpvalueRead: {} = {:?}", name, value);
                    let mut ops = upvalue_ops_clone.lock();
                    ops.push(("read", name.clone(), value.clone()));
                }
                HookEvent::UpvalueWrite(name, old_value, new_value) => {
                    println!(
                        "UpvalueWrite: {} = {:?} -> {:?}",
                        name, old_value, new_value
                    );
                    let mut ops = upvalue_ops_clone.lock();
                    ops.push(("write", name.clone(), new_value.clone()));
                }
                _ => {}
            }
            Ok(())
        },
        100,
    );

    // Register a hook that tracks instruction execution
    vm.register_hook(
        |event| matches!(event, HookEvent::BeforeInstructionExecute(_)),
        move |event, ctx| {
            if let HookEvent::BeforeInstructionExecute(instruction) = event {
                println!("Executing instruction: {:?}", instruction);
                if let Some(frame) = ctx.current_frame() {
                    println!("  Function: {}", frame.function_name());
                    println!("  Register count: {}", frame.register_count());
                }
            }
            Ok(())
        },
        90,
    );

    // Register a hook that tracks register writes
    vm.register_hook(
        |event| matches!(event, HookEvent::RegisterWrite(_, _, _)),
        move |event, _ctx| {
            if let HookEvent::RegisterWrite(reg, old_value, new_value) = event {
                println!(
                    "RegisterWrite: r{} = {:?} -> {:?}",
                    reg, old_value, new_value
                );
            }
            Ok(())
        },
        80,
    );

    // Counter creator function
    let create_counter = create_test_vmfunction(
        "create_counter".to_string(),
        vec!["start".to_string()],
        Vec::new(),
        None,
        5,
        vec![
            Instruction::LDI(1, Value::String("increment".to_string())),
            Instruction::PUSHARG(1),
            Instruction::LDI(2, Value::String("start".to_string())),
            Instruction::PUSHARG(2),
            Instruction::CALL("create_closure".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    // Increment function
    let increment = create_test_vmfunction(
        "increment".to_string(),
        vec!["amount".to_string()],
        vec!["start".to_string()],
        Some("create_counter".to_string()),
        5,
        vec![
            // Get upvalue
            Instruction::LDI(1, Value::String("start".to_string())),
            Instruction::PUSHARG(1),
            Instruction::CALL("get_upvalue".to_string()),
            Instruction::MOV(1, 0),
            // Add amount
            Instruction::ADD(2, 1, 0),
            // Set upvalue
            Instruction::LDI(3, Value::String("start".to_string())),
            Instruction::PUSHARG(3),
            Instruction::PUSHARG(2),
            Instruction::CALL("set_upvalue".to_string()),
            // Return new value
            Instruction::MOV(0, 2),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    // Test function
    let test_function = VMFunction::new(
        "test_upvalue_hooks".to_string(),
        vec![],
        Vec::new(),
        None,
        5,
        vec![
            // Create counter with initial value 10
            Instruction::LDI(0, Value::I64(10)),
            Instruction::PUSHARG(0),
            Instruction::CALL("create_counter".to_string()),
            Instruction::MOV(1, 0),
            // Call increment with 5
            Instruction::PUSHARG(1),
            Instruction::LDI(2, Value::I64(5)),
            Instruction::PUSHARG(2),
            Instruction::CALL("call_closure".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    // Print the test function instructions
    println!("Test function instructions:");
    for (i, instruction) in test_function.instructions().iter().enumerate() {
        println!("  {}: {:?}", i, instruction);
    }

    vm.register_function(create_counter);
    vm.register_function(increment);
    vm.register_function(test_function);

    let result = vm.execute("test_upvalue_hooks").unwrap();
    println!("Result: {:?}", result);

    let ops = upvalue_ops.lock();
    println!("Upvalue operations: {:?}", ops);
    assert_eq!(ops.len(), 2);
    assert_eq!(ops[0], ("read", "start".to_string(), Value::I64(10)));
    assert_eq!(ops[1], ("write", "start".to_string(), Value::I64(20)));

    assert_eq!(result, Value::I64(20)); // The result is 20 because the upvalue is updated to 20
}

#[test]
fn test_error_handling() {
    let mut vm = setup_vm();

    // Test division by zero
    let div_zero_function = create_test_vmfunction(
        "div_zero".to_string(),
        vec![],
        Vec::new(),
        None,
        3,
        vec![
            Instruction::LDI(0, Value::I64(10)),
            Instruction::LDI(1, Value::I64(0)),
            Instruction::DIV(2, 0, 1),
            Instruction::RET(2),
        ],
        HashMap::new(),
    );

    vm.register_function(div_zero_function);
    let result = vm.execute("div_zero");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "Division by zero");

    // Test invalid function call
    let invalid_call_function = VMFunction::new(
        "invalid_call".to_string(),
        vec![],
        Vec::new(),
        None,
        1,
        vec![
            Instruction::CALL("nonexistent_function".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(invalid_call_function);
    let result = vm.execute("invalid_call");
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Function 'nonexistent_function' not found"
    );
}

#[test]
fn test_type_errors() {
    let mut vm = setup_vm();

    // Test type error in arithmetic
    let type_error_function = VMFunction::new(
        "type_error".to_string(),
        vec![],
        Vec::new(),
        None,
        3,
        vec![
            Instruction::LDI(0, Value::I64(10)),
            Instruction::LDI(1, Value::String("not a number".to_string())),
            Instruction::ADD(2, 0, 1),
            Instruction::RET(2),
        ],
        HashMap::new(),
    );

    vm.register_function(type_error_function);
    let result = vm.execute("type_error");
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Type error in ADD operation"
    );
}

#[test]
fn test_stack_operations() {
    let mut vm = setup_vm();

    // Track stack operations
    let stack_ops = Arc::new(Mutex::new(Vec::new()));
    let stack_ops_clone = Arc::clone(&stack_ops);

    // Register a hook that tracks stack operations
    vm.register_hook(
        |event| matches!(event, HookEvent::StackPush(_)) || matches!(event, HookEvent::StackPop(_)),
        move |event, _ctx| {
            match event {
                HookEvent::StackPush(value) => {
                    let mut ops = stack_ops_clone.lock();
                    ops.push(("push", value.clone()));
                }
                HookEvent::StackPop(value) => {
                    let mut ops = stack_ops_clone.lock();
                    ops.push(("pop", value.clone()));
                }
                _ => {}
            }
            Ok(())
        },
        100,
    );

    let test_function = VMFunction::new(
        "test_stack".to_string(),
        vec![],
        Vec::new(),
        None,
        3,
        vec![
            Instruction::LDI(0, Value::I64(10)),
            Instruction::PUSHARG(0),
            Instruction::LDI(1, Value::I64(20)),
            Instruction::PUSHARG(1),
            Instruction::CALL("sum".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    // Register sum function
    vm.register_foreign_function("sum", |ctx| {
        let args = ctx.args();
        if args.len() != 2 {
            return Err("sum expects 2 arguments".to_string());
        }

        match (&args[0], &args[1]) {
            (Value::I64(a), Value::I64(b)) => Ok(Value::I64(a + b)),
            _ => Err("sum expects integers".to_string()),
        }
    });

    vm.register_function(test_function);
    let result = vm.execute("test_stack").unwrap();
    assert_eq!(result, Value::I64(30));

    let ops = stack_ops.lock();
    println!("{:?}", ops);
    assert_eq!(ops.len(), 4);
    assert_eq!(ops[0], ("push", Value::I64(10)));
    assert_eq!(ops[1], ("push", Value::I64(20)));
    assert_eq!(ops[2], ("pop", Value::I64(20)));
    assert_eq!(ops[3], ("pop", Value::I64(10)));
}

#[test]
fn test_fibonacci() {
    let mut vm = setup_vm();

    // Fibonacci function
    let mut labels = HashMap::new();
    labels.insert("base_case_zero".to_string(), 7);
    labels.insert("base_case_one".to_string(), 9);
    labels.insert("recursive_case".to_string(), 11);

    let fib_function = VMFunction::new(
        "fibonacci".to_string(),
        vec!["n".to_string()],
        Vec::new(),
        None,
        5,
        vec![
            // Check if n == 0
            Instruction::LDI(1, Value::I64(0)),
            Instruction::CMP(0, 1),
            Instruction::JMPEQ("base_case_zero".to_string()),
            // Check if n == 1
            Instruction::LDI(1, Value::I64(1)),
            Instruction::CMP(0, 1),
            Instruction::JMPEQ("base_case_one".to_string()),
            // Otherwise, recursive case
            Instruction::JMP("recursive_case".to_string()),
            // base_case_zero: return 0
            Instruction::LDI(0, Value::I64(0)),
            Instruction::RET(0),
            // base_case_one: return 1
            Instruction::LDI(0, Value::I64(1)),
            Instruction::RET(0),
            // recursive_case: return fibonacci(n-1) + fibonacci(n-2)
            // Save n
            Instruction::MOV(4, 0), // Save n in r4
            // Calculate fibonacci(n-1)
            Instruction::LDI(1, Value::I64(1)),
            Instruction::SUB(2, 0, 1),
            Instruction::PUSHARG(2),
            Instruction::CALL("fibonacci".to_string()),
            Instruction::MOV(3, 0),
            // Calculate fibonacci(n-2)
            Instruction::MOV(0, 4), // Restore n from r4
            Instruction::LDI(1, Value::I64(2)),
            Instruction::SUB(2, 0, 1),
            Instruction::PUSHARG(2),
            Instruction::CALL("fibonacci".to_string()),
            // Add results
            Instruction::ADD(0, 0, 3),
            Instruction::RET(0),
        ],
        labels,
    );

    // Test function
    let test_function = VMFunction::new(
        "test_fibonacci".to_string(),
        vec![],
        Vec::new(),
        None,
        2,
        vec![
            Instruction::LDI(0, Value::I64(10)),
            Instruction::PUSHARG(0),
            Instruction::CALL("fibonacci".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(fib_function);
    vm.register_function(test_function);

    let result = vm.execute("test_fibonacci").unwrap();
    assert_eq!(result, Value::I64(55)); // fib(10) = 55
}

#[test]
fn test_factorial() {
    let mut vm = setup_vm();

    // Factorial function definition stays the same
    let mut labels = HashMap::new();
    labels.insert("base_case".to_string(), 6);
    labels.insert("recursive_case".to_string(), 8);

    let factorial_function = VMFunction::new(
        "factorial".to_string(),
        vec!["n".to_string()],
        Vec::new(),
        None,
        5,
        vec![
            // Check if n == 1
            Instruction::LDI(1, Value::I64(1)),          // r1 = 1
            Instruction::CMP(0, 1),                      // Compare n with 1
            Instruction::JMPEQ("base_case".to_string()), // If n == 1, go to base case
            // Check if n < 1 by comparing 1 with n
            Instruction::CMP(1, 0), // Compare 1 with n
            // If 1 > n, the comparison is Greater (meaning n < 1)
            // If 1 < n, the comparison is Less (meaning n > 1)
            Instruction::JMPNEQ("recursive_case".to_string()), // If not equal, go to recursive case
            // If execution reaches here, n must be < 1, so go to base case
            Instruction::JMP("base_case".to_string()),
            // base_case: (n <= 1)
            Instruction::LDI(0, Value::I64(1)), // Return 1
            Instruction::RET(0),
            // recursive_case: (n > 1)
            // Save n
            Instruction::MOV(3, 0), // r3 = n
            // Calculate n-1
            Instruction::LDI(1, Value::I64(1)), // r1 = 1
            Instruction::SUB(2, 0, 1),          // r2 = n - 1
            // Call factorial(n-1)
            Instruction::PUSHARG(2),
            Instruction::CALL("factorial".to_string()),
            // Result in r0

            // Multiply n * factorial(n-1)
            Instruction::MUL(0, 3, 0), // r0 = n * factorial(n-1)
            Instruction::RET(0),
        ],
        labels,
    );

    // Test function stays the same
    let test_function = VMFunction::new(
        "test_factorial".to_string(),
        vec![],
        Vec::new(),
        None,
        2,
        vec![
            Instruction::LDI(0, Value::I64(5)),
            Instruction::PUSHARG(0),
            Instruction::CALL("factorial".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    // Debug tracking
    let call_depth = Arc::new(Mutex::new(0));
    let call_depth_clone = Arc::clone(&call_depth);

    let compare_results = Arc::new(Mutex::new(Vec::new()));

    // Hook 1: Track instruction execution with depth
    let hook1_id = vm.register_hook(
        |event| matches!(event, HookEvent::BeforeInstructionExecute(_)),
        move |event, _ctx| {
            if let HookEvent::BeforeInstructionExecute(instruction) = event {
                let call_depth = call_depth_clone.lock();
                let depth = *call_depth;
                let indent = "  ".repeat(depth);
                println!("{}[D{}] EXEC: {:?}", indent, depth, instruction);
            }
            Ok(())
        },
        100,
    );

    let compare_results_clone = Arc::clone(&compare_results);
    let call_depth_clone = Arc::clone(&call_depth);
    // Hook 2: Track comparison operations
    let hook2_id = vm.register_hook(
        |event| {
            matches!(
                event,
                HookEvent::AfterInstructionExecute(Instruction::CMP(_, _))
            )
        },
        move |event, ctx| {
            if let HookEvent::AfterInstructionExecute(Instruction::CMP(reg1, reg2)) = event {
                if let Some(flag) = ctx.get_compare_flag() {
                    let call_depth = call_depth_clone.lock();
                    let mut compare_results = compare_results_clone.lock();
                    let depth = *call_depth;
                    let indent = "  ".repeat(depth);
                    compare_results.push((depth, *reg1, *reg2, flag));

                    let reg1_val = ctx
                        .hook_register(*reg1)
                        .and_then(|register| ctx.get_register_value(register))
                        .unwrap_or(Value::Unit);
                    let reg2_val = ctx
                        .hook_register(*reg2)
                        .and_then(|register| ctx.get_register_value(register))
                        .unwrap_or(Value::Unit);

                    let meaning = match flag {
                        -1 => "LESS THAN",
                        0 => "EQUAL",
                        1 => "GREATER THAN",
                        _ => "UNKNOWN",
                    };

                    println!(
                        "{}  CMP r{} ({:?}) r{} ({:?}) = {} ({})",
                        indent, reg1, reg1_val, reg2, reg2_val, flag, meaning
                    );
                }
            }
            Ok(())
        },
        90,
    );

    let call_depth_clone = Arc::clone(&call_depth);
    // Hook 3: Track function calls and returns
    let hook3_id = vm.register_hook(
        |event| {
            matches!(event, HookEvent::BeforeFunctionCall(_, _))
                || matches!(event, HookEvent::AfterFunctionCall(_, _))
        },
        move |event, _ctx| {
            match event {
                HookEvent::BeforeFunctionCall(_, args) => {
                    let mut call_depth = call_depth_clone.lock();
                    let depth = *call_depth;
                    let indent = "  ".repeat(depth);
                    *call_depth += 1;

                    let arg_str = if !args.is_empty() {
                        format!("{:?}", args[0])
                    } else {
                        "no args".to_string()
                    };

                    println!("{}>> CALL factorial({}) [depth={}]", indent, arg_str, depth);
                }
                HookEvent::AfterFunctionCall(_, result) => {
                    let mut call_depth = call_depth_clone.lock();
                    *call_depth -= 1;
                    let depth = *call_depth;
                    let indent = "  ".repeat(depth);
                    println!("{}<<  RETURN {:?} [depth={}]", indent, result, depth);
                }
                _ => {}
            }
            Ok(())
        },
        80,
    );

    let call_depth_clone = Arc::clone(&call_depth);
    // Hook 4: Track JMPEQ/JMPNEQ decisions
    let hook4_id = vm.register_hook(
        |event| {
            matches!(
                event,
                HookEvent::BeforeInstructionExecute(Instruction::JMPEQ(_))
            ) || matches!(
                event,
                HookEvent::BeforeInstructionExecute(Instruction::JMPNEQ(_))
            )
        },
        move |event, ctx| {
            if let HookEvent::BeforeInstructionExecute(jump_instruction) = event {
                if let Some(flag) = ctx.get_compare_flag() {
                    let call_depth = call_depth_clone.lock();
                    let depth = *call_depth;
                    let indent = "  ".repeat(depth);

                    let will_jump = match jump_instruction {
                        Instruction::JMPEQ(_) => flag == 0,
                        Instruction::JMPNEQ(_) => flag != 0,
                        _ => false,
                    };

                    let dest = match jump_instruction {
                        Instruction::JMPEQ(label) | Instruction::JMPNEQ(label) => label.as_str(),
                        _ => "unknown",
                    };

                    println!(
                        "{}  JUMP to {} will {}",
                        indent,
                        dest,
                        if will_jump { "HAPPEN" } else { "NOT HAPPEN" }
                    );
                }
            }
            Ok(())
        },
        70,
    );

    vm.register_function(factorial_function);
    vm.register_function(test_function);

    println!("\n====== EXECUTING TEST_FACTORIAL ======\n");
    let result = vm.execute("test_factorial");

    // Clean up hooks
    vm.unregister_hook(hook1_id);
    vm.unregister_hook(hook2_id);
    vm.unregister_hook(hook3_id);
    vm.unregister_hook(hook4_id);

    match result {
        Ok(value) => {
            println!("\nFinal result: {:?}", value);

            // Print a summary of comparison operations
            println!("\nComparison operations (depth, reg1, reg2, flag):");
            let compare_results = compare_results.lock();
            for (depth, reg1, reg2, flag) in compare_results.iter() {
                println!("  Depth {}: CMP r{} r{} = {}", depth, reg1, reg2, flag);
            }

            assert_eq!(value, Value::I64(120)); // 5! = 120
        }
        Err(e) => {
            println!("\nERROR: {}", e);
            panic!("Test failed: {}", e);
        }
    }
}

#[test]
fn test_performance() {
    let mut vm = setup_vm();

    // Loop function
    let mut labels = HashMap::new();
    labels.insert("loop_start".to_string(), 1);
    labels.insert("loop_end".to_string(), 7);

    let loop_function = VMFunction::new(
        "loop_test".to_string(),
        vec!["iterations".to_string()],
        Vec::new(),
        None,
        4,
        vec![
            // Initialize counter
            Instruction::LDI(1, Value::I64(0)),
            // loop_start:
            Instruction::CMP(1, 0),
            Instruction::JMPEQ("loop_end".to_string()),
            // Increment counter
            Instruction::LDI(2, Value::I64(1)),
            Instruction::ADD(1, 1, 2),
            // Do some work (arithmetic)
            Instruction::MUL(3, 1, 2),
            // Loop back
            Instruction::JMP("loop_start".to_string()),
            // loop_end:
            Instruction::RET(1),
        ],
        labels,
    );

    vm.register_function(loop_function);

    // Run with different iteration counts to measure performance
    let iterations = 10000; // Reduced for faster test runs
    let start = Instant::now();

    let result = vm
        .execute_with_args("loop_test", &[Value::I64(iterations)])
        .unwrap();
    let duration = start.elapsed();

    assert_eq!(result, Value::I64(iterations));
    println!(
        "Performance test: {} iterations in {:?}",
        iterations, duration
    );
    // We don't assert on timing as it's environment-dependent
}

#[test]
fn test_type_function() {
    let mut vm = setup_vm();

    let test_function = VMFunction::new(
        "test_type".to_string(),
        vec![],
        Vec::new(),
        None,
        5,
        vec![
            // Test integer type
            Instruction::LDI(0, Value::I64(42)),
            Instruction::PUSHARG(0),
            Instruction::CALL("type".to_string()),
            Instruction::MOV(1, 0),
            // Test string type
            Instruction::LDI(0, Value::String("hello".to_string())),
            Instruction::PUSHARG(0),
            Instruction::CALL("type".to_string()),
            Instruction::MOV(2, 0),
            // Test boolean type
            Instruction::LDI(0, Value::Bool(true)),
            Instruction::PUSHARG(0),
            Instruction::CALL("type".to_string()),
            Instruction::MOV(3, 0),
            // Test object type
            Instruction::CALL("create_object".to_string()),
            Instruction::PUSHARG(0),
            Instruction::CALL("type".to_string()),
            Instruction::MOV(4, 0),
            // Return string type result
            Instruction::RET(2),
        ],
        HashMap::new(),
    );

    vm.register_function(test_function);
    let result = vm.execute("test_type").unwrap();
    assert_eq!(result, Value::String("string".to_string()));
}

#[test]
fn typed_hook_registration_accepts_structured_callback_errors() {
    let mut vm = setup_vm();

    let test_function = VMFunction::new(
        "typed_hook_error".to_string(),
        vec![],
        Vec::new(),
        None,
        1,
        vec![Instruction::LDI(0, Value::I64(1)), Instruction::RET(0)],
        HashMap::new(),
    );
    vm.register_function(test_function);

    vm.register_typed_hook(
        |event| matches!(event, HookEvent::BeforeInstructionExecute(_)),
        |_, _| Err(HookCallbackError::from("typed hook failure")),
        100,
    );

    let err = vm
        .execute("typed_hook_error")
        .expect_err("typed hook callback errors should propagate");
    assert_eq!(err.kind(), VirtualMachineErrorKind::Hook);
    assert!(
        err.to_string()
            .contains("Hook 1 callback failed: typed hook failure"),
        "unexpected error: {err}"
    );
}

#[test]
fn hook_registration_uses_typed_handles() {
    let mut vm = setup_vm();

    let hook_id: HookId = vm.register_hook(|_| true, |_, _| Ok(()), 0);
    assert!(vm.disable_hook(hook_id));
    assert!(vm.enable_hook(hook_id));
    assert!(vm.unregister_hook(hook_id));
}

#[test]
fn test_hook_enable_disable() {
    let mut vm = setup_vm();

    // Use a RefCell to track hook calls
    let hook_calls = Arc::new(Mutex::new(0));
    let hook_calls_clone = Arc::clone(&hook_calls);

    // Register a hook that counts instruction executions
    let hook_id = vm.register_hook(
        move |event| matches!(event, HookEvent::BeforeInstructionExecute(_)),
        move |_, _| {
            let mut hook_calls_clone = hook_calls_clone.lock();
            *hook_calls_clone += 1;
            Ok(())
        },
        100,
    );

    let test_function = VMFunction::new(
        "test_hook_toggle".to_string(),
        vec![],
        Vec::new(),
        None,
        2,
        vec![
            Instruction::LDI(0, Value::I64(1)),
            Instruction::LDI(1, Value::I64(2)),
            Instruction::ADD(0, 0, 1),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(test_function);

    // First run with hook enabled
    let result = vm.execute("test_hook_toggle").unwrap();
    assert_eq!(result, Value::I64(3));
    {
        let mut hook_calls_guard = hook_calls.lock();
        assert_eq!(*hook_calls_guard, 4); // 4 instructions executed
                                          // Reset counter
        *hook_calls_guard = 0;
    } // Explicitly drop the lock

    // Disable the hook
    assert!(vm.disable_hook(hook_id));

    // Run again with hook disabled
    let result = vm.execute("test_hook_toggle").unwrap();
    assert_eq!(result, Value::I64(3));
    {
        let hook_calls_guard = hook_calls.lock();
        assert_eq!(*hook_calls_guard, 0); // No hook calls
    } // Explicitly drop the lock

    // Re-enable the hook
    assert!(vm.enable_hook(hook_id));

    // Run again with hook re-enabled
    let result = vm.execute("test_hook_toggle").unwrap();
    assert_eq!(result, Value::I64(3));
    {
        let hook_calls_guard = hook_calls.lock();
        assert_eq!(*hook_calls_guard, 4); // 4 more instructions executed
    } // Explicitly drop the lock
}

#[test]
fn test_hook_unregister() {
    let mut vm = setup_vm();

    // Use a RefCell to track hook calls
    let hook_calls = Arc::new(Mutex::new(0));
    let hook_calls_clone = Arc::clone(&hook_calls);

    // Register a hook that counts instruction executions
    let hook_id = vm.register_hook(
        |event| matches!(event, HookEvent::BeforeInstructionExecute(_)),
        move |_, _| {
            let mut hook_calls_clone = hook_calls_clone.lock();
            *hook_calls_clone += 1;
            Ok(())
        },
        100,
    );

    let test_function = VMFunction::new(
        "test_hook_unregister".to_string(),
        vec![],
        Vec::new(),
        None,
        2,
        vec![
            Instruction::LDI(0, Value::I64(1)),
            Instruction::LDI(1, Value::I64(2)),
            Instruction::ADD(0, 0, 1),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(test_function);

    // First run with hook registered
    let result = vm.execute("test_hook_unregister").unwrap();
    assert_eq!(result, Value::I64(3));
    {
        let mut hook_calls_guard = hook_calls.lock();
        assert_eq!(*hook_calls_guard, 4); // 4 instructions executed
                                          // Reset counter
        *hook_calls_guard = 0;
    } // Explicitly drop the lock

    // Unregister the hook
    assert!(vm.unregister_hook(hook_id));

    // Run again with hook unregistered
    let result = vm.execute("test_hook_unregister").unwrap();
    assert_eq!(result, Value::I64(3));
    {
        let hook_calls_guard = hook_calls.lock();
        assert_eq!(*hook_calls_guard, 0); // No hook calls
    } // Explicitly drop the lock
}

#[test]
fn test_hook_priority() {
    let mut vm = setup_vm();

    // Track hook execution order
    let hook_order = Arc::new(Mutex::new(Vec::new()));

    // Clone for each hook
    let hook_order_1 = Arc::clone(&hook_order);
    let hook_order_2 = Arc::clone(&hook_order);
    let hook_order_3 = Arc::clone(&hook_order);

    // Register hooks with different priorities
    vm.register_hook(
        |event| matches!(event, HookEvent::BeforeInstructionExecute(_)),
        move |_, _| {
            let mut hook_order_1 = hook_order_1.lock();
            hook_order_1.push(1);
            Ok(())
        },
        10, // Low priority
    );

    vm.register_hook(
        |event| matches!(event, HookEvent::BeforeInstructionExecute(_)),
        move |_, _| {
            let mut hook_order_2 = hook_order_2.lock();
            hook_order_2.push(2);
            Ok(())
        },
        100, // Medium priority
    );

    vm.register_hook(
        |event| matches!(event, HookEvent::BeforeInstructionExecute(_)),
        move |_, _| {
            let mut hook_order_3 = hook_order_3.lock();
            hook_order_3.push(3);
            Ok(())
        },
        1000, // High priority
    );

    let test_function = VMFunction::new(
        "test_hook_priority".to_string(),
        vec![],
        Vec::new(),
        None,
        1,
        vec![Instruction::LDI(0, Value::I64(42)), Instruction::RET(0)],
        HashMap::new(),
    );

    vm.register_function(test_function);
    let result = vm.execute("test_hook_priority").unwrap();
    assert_eq!(result, Value::I64(42));
    {
        let hook_order_guard = hook_order.lock();
        // Check that hooks executed in priority order (highest first)
        assert_eq!(hook_order_guard.len(), 6); // 2 instructions * 3 hooks = 6 events

        // For the first instruction, hooks should execute in priority order
        assert_eq!(hook_order_guard[0], 3); // Highest priority
        assert_eq!(hook_order_guard[1], 2); // Medium priority
        assert_eq!(hook_order_guard[2], 1); // Lowest priority
    } // Explicitly drop the lock
}

#[test]
fn test_complex_program() {
    let mut vm = setup_vm();

    // Function to calculate sum of squares from 1 to n
    let mut labels = HashMap::new();
    labels.insert("loop_start".to_string(), 2);
    labels.insert("loop_end".to_string(), 9); // Loop end is at position 9 (0-indexed)

    let sum_squares = VMFunction::new(
        "sum_squares".to_string(),
        vec!["n".to_string()],
        Vec::new(),
        None,
        5,
        vec![
            // Initialize sum = 0
            Instruction::LDI(1, Value::I64(0)),
            // Initialize i = 1
            Instruction::LDI(2, Value::I64(1)),
            // loop_start:
            // Check if i > n (we want to exit if true)
            Instruction::CMP(2, 0), // Compare i (r2) with n (r0)
            // If i > n, exit the loop
            // CMP records Greater if the first operand is greater than the second
            // We want to continue only if i <= n
            Instruction::JMPGT("loop_end".to_string()), // If i > n, exit loop
            // square = i * i
            Instruction::MUL(3, 2, 2),
            // sum += square
            Instruction::ADD(1, 1, 3),
            // i++
            Instruction::LDI(4, Value::I64(1)),
            Instruction::ADD(2, 2, 4),
            // Go back to loop start
            Instruction::JMP("loop_start".to_string()),
            // loop_end:
            // Return sum
            Instruction::MOV(0, 1),
            Instruction::RET(0),
        ],
        labels,
    );

    // Test function
    let test_function = VMFunction::new(
        "test_complex".to_string(),
        vec![],
        Vec::new(),
        None,
        2,
        vec![
            Instruction::LDI(0, Value::I64(5)),
            Instruction::PUSHARG(0),
            Instruction::CALL("sum_squares".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(sum_squares);
    vm.register_function(test_function);

    let result = vm.execute("test_complex").unwrap();
    assert_eq!(result, Value::I64(55)); // 1 + 4 + 9 + 16 + 25 = 55
}
