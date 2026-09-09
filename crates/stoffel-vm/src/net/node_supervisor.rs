//! Standing-node execution admission and lifecycle management.
//!
//! [`NodeSupervisor`] is deliberately transport-agnostic. A coordinator-facing
//! service supplies the preparation future for each admitted execution. The
//! supervisor owns only lifecycle state: bounded admission, idempotency,
//! cancellation, and process shutdown.

use crate::core_vm::VmCooperativeExecutionMetrics;
pub use crate::net::session::ExecutionId;
use async_trait::async_trait;
use futures::FutureExt;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Immutable version-one description of a single program execution.
///
/// `program_id` identifies program contents. `execution_id` identifies this
/// invocation, so simultaneous invocations of the same program remain distinct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionSpecV1 {
    pub execution_id: ExecutionId,
    pub program_id: [u8; 32],
}

impl ExecutionSpecV1 {
    pub fn new(execution_id: ExecutionId, program_id: [u8; 32]) -> Self {
        Self {
            execution_id,
            program_id,
        }
    }
}

/// Event emitted by a standing node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeEvent {
    pub execution_id: ExecutionId,
    #[serde(flatten)]
    pub kind: NodeEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum NodeEventKind {
    Preparing,
    Ready,
    CancelAccepted,
    Completed {
        metrics: VmCooperativeExecutionMetrics,
    },
    Failed {
        error: String,
    },
    Cancelled,
}

impl NodeEvent {
    fn new(execution_id: ExecutionId, kind: NodeEventKind) -> Self {
        Self { execution_id, kind }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionPhase {
    Preparing,
    Ready,
    Running,
    Cancelling,
    Terminal,
}

impl ExecutionPhase {
    const fn is_terminal(self) -> bool {
        matches!(self, Self::Terminal)
    }
}

/// Per-execution resources passed to the handler running the fresh task.
#[derive(Debug, Clone)]
pub struct NodeExecutionContext {
    pub spec: ExecutionSpecV1,
    pub cancellation: CancellationToken,
}

/// Type-erased execution that has completed its setup work.
///
/// Implementations may retain backend-specific VMs, engines, transport
/// registrations, and preprocessing leases. [`Self::execute`] contains the
/// online work and may wait for admitted clients. [`Self::cleanup`] is invoked
/// after execution or cancellation.
#[async_trait]
pub trait PreparedNodeExecution: Send + 'static {
    /// Run the online phase cooperatively. Network waits naturally return
    /// `Pending`; CPU-heavy implementations must also yield periodically. The
    /// supervisor isolates executions into separate Tokio tasks, but it cannot
    /// preempt a future that performs unbounded synchronous work in one poll.
    async fn execute(&mut self) -> Result<VmCooperativeExecutionMetrics, String>;

    async fn cleanup(&mut self) -> Result<(), String> {
        Ok(())
    }
}

async fn catch_execution_panic<T>(
    future: impl Future<Output = Result<T, String>>,
    panic_message: &'static str,
) -> Result<T, String> {
    AssertUnwindSafe(future)
        .catch_unwind()
        .await
        .map_err(|_| panic_message.to_owned())?
}

async fn cleanup_prepared(prepared: &mut dyn PreparedNodeExecution) -> Result<(), String> {
    AssertUnwindSafe(prepared.cleanup())
        .catch_unwind()
        .await
        .map_err(|_| "execution cleanup panicked".to_owned())?
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NodeSupervisorError {
    #[error("standing node is shutting down and no longer accepts execution commands")]
    ShuttingDown,
    #[error("zero execution ID cannot be admitted by a standing node")]
    ZeroExecutionId,
    #[error("execution ID {execution_id} is already active")]
    DuplicateExecutionId { execution_id: ExecutionId },
    #[error("unknown execution {execution_id}")]
    UnknownExecution { execution_id: ExecutionId },
    #[error("failed to install process signal handler: {reason}")]
    Signal { reason: String },
}

struct EntryState {
    phase: ExecutionPhase,
}

struct ExecutionEntry {
    spec: ExecutionSpecV1,
    state: Mutex<EntryState>,
    cancellation: CancellationToken,
    prepare_previous: Option<CancellationToken>,
    prepare_done: CancellationToken,
}

impl ExecutionEntry {
    fn new(
        spec: ExecutionSpecV1,
        prepare_previous: Option<CancellationToken>,
        prepare_done: CancellationToken,
    ) -> Self {
        Self {
            spec,
            state: Mutex::new(EntryState {
                phase: ExecutionPhase::Preparing,
            }),
            cancellation: CancellationToken::new(),
            prepare_previous,
            prepare_done,
        }
    }

    fn phase(&self) -> ExecutionPhase {
        self.state.lock().phase
    }
}

/// Standing-node execution supervisor.
///
/// The durable control-plane journal owns replay prevention; terminal entries
/// leave this in-memory supervisor after their event is emitted. The trusted
/// command log is the sole admission and flow-control boundary;
/// a local scheduler could choose different runnable programs on different
/// parties and split the mesh. Every Prepare launches an independent Tokio task
/// after setup, so an execution waiting on a faulty peer cannot head-of-line
/// block another admitted, runnable execution.
pub struct NodeSupervisor {
    state: Mutex<SupervisorState>,
    events: mpsc::UnboundedSender<NodeEvent>,
}

struct SupervisorState {
    accepting: bool,
    executions: HashMap<ExecutionId, Arc<ExecutionEntry>>,
    prepare_tails: HashMap<[u8; 32], (ExecutionId, CancellationToken)>,
}

impl NodeSupervisor {
    pub fn new() -> (Arc<Self>, mpsc::UnboundedReceiver<NodeEvent>) {
        let (events, receiver) = mpsc::unbounded_channel();
        let supervisor = Arc::new(Self {
            state: Mutex::new(SupervisorState {
                accepting: true,
                executions: HashMap::new(),
                prepare_tails: HashMap::new(),
            }),
            events,
        });
        (supervisor, receiver)
    }

    /// Admit one execution and return its immediate acknowledgement. Later
    /// lifecycle transitions are published to the control-plane event sink.
    pub fn prepare<F, Fut>(
        self: &Arc<Self>,
        spec: ExecutionSpecV1,
        prepare: F,
    ) -> Result<NodeEvent, NodeSupervisorError>
    where
        F: FnOnce(NodeExecutionContext) -> Fut + Send + 'static,
        Fut: Future<Output = Result<Box<dyn PreparedNodeExecution>, String>> + Send + 'static,
    {
        if spec.execution_id.is_zero() {
            return Err(NodeSupervisorError::ZeroExecutionId);
        }
        let entry = {
            let mut state = self.state.lock();
            if !state.accepting {
                return Err(NodeSupervisorError::ShuttingDown);
            }

            if let Some(existing) = state.executions.get(&spec.execution_id) {
                return Err(NodeSupervisorError::DuplicateExecutionId {
                    execution_id: existing.spec.execution_id,
                });
            }

            let execution_id = spec.execution_id;
            let tail = CancellationToken::new();
            let previous = state
                .prepare_tails
                .insert(spec.program_id, (execution_id, tail.clone()))
                .map(|(_, tail)| tail);
            let entry = Arc::new(ExecutionEntry::new(spec, previous, tail));
            state.executions.insert(execution_id, Arc::clone(&entry));
            entry
        };

        // Capture the acknowledgement before the new preparation task can
        // advance concurrently on a multi-threaded runtime.
        self.spawn_execution(Arc::clone(&entry), prepare);

        // Setup can wait on preprocessing or faulty peers, so it runs outside
        // the serial command pump and launches once its private resources are ready.
        Ok(NodeEvent::new(
            entry.spec.execution_id,
            NodeEventKind::Preparing,
        ))
    }

    fn spawn_execution<F, Fut>(self: &Arc<Self>, entry: Arc<ExecutionEntry>, prepare: F)
    where
        F: FnOnce(NodeExecutionContext) -> Fut + Send + 'static,
        Fut: Future<Output = Result<Box<dyn PreparedNodeExecution>, String>> + Send + 'static,
    {
        let context = NodeExecutionContext {
            spec: entry.spec.clone(),
            cancellation: entry.cancellation.clone(),
        };
        let supervisor = Arc::clone(self);
        tokio::spawn(async move {
            if let Some(previous) = &entry.prepare_previous {
                // Even a cancelled middle entry closes its lane only after its
                // predecessor. Otherwise a later same-program Prepare could
                // overtake the still-running predecessor on another party.
                previous.cancelled().await;
            }

            let preparation = if entry.cancellation.is_cancelled() {
                Err("preparation cancelled".to_owned())
            } else {
                catch_execution_panic(prepare(context), "preparation handler panicked").await
            };
            entry.prepare_done.cancel();
            {
                let mut state = supervisor.state.lock();
                if state
                    .prepare_tails
                    .get(&entry.spec.program_id)
                    .is_some_and(|(execution_id, _)| *execution_id == entry.spec.execution_id)
                {
                    state.prepare_tails.remove(&entry.spec.program_id);
                }
            }
            let mut prepared = match preparation {
                Ok(prepared) => prepared,
                Err(error) => {
                    let event = if entry.cancellation.is_cancelled() {
                        NodeEventKind::Cancelled
                    } else {
                        NodeEventKind::Failed { error }
                    };
                    supervisor.finish_terminal(&entry, event);
                    return;
                }
            };

            let ready = {
                let mut state = entry.state.lock();
                if state.phase == ExecutionPhase::Preparing && !entry.cancellation.is_cancelled() {
                    state.phase = ExecutionPhase::Ready;
                    true
                } else {
                    false
                }
            };

            if ready {
                supervisor.emit(NodeEvent::new(
                    entry.spec.execution_id,
                    NodeEventKind::Ready,
                ));
            } else {
                let _ = cleanup_prepared(prepared.as_mut()).await;
                supervisor.finish_terminal(&entry, NodeEventKind::Cancelled);
                return;
            }

            let execute = {
                let mut state = entry.state.lock();
                if state.phase == ExecutionPhase::Ready && !entry.cancellation.is_cancelled() {
                    state.phase = ExecutionPhase::Running;
                    true
                } else {
                    false
                }
            };
            if !execute {
                let _ = cleanup_prepared(prepared.as_mut()).await;
                supervisor.finish_terminal(&entry, NodeEventKind::Cancelled);
                return;
            }

            let execution =
                catch_execution_panic(prepared.execute(), "execution handler panicked").await;
            let cleanup = cleanup_prepared(prepared.as_mut()).await;
            supervisor.finish_execution(&entry, execution, cleanup);
        });
    }

    pub fn cancel(&self, execution_id: ExecutionId) -> Result<NodeEvent, NodeSupervisorError> {
        let entry = self
            .state
            .lock()
            .executions
            .get(&execution_id)
            .cloned()
            .ok_or(NodeSupervisorError::UnknownExecution { execution_id })?;
        Ok(self.request_cancellation(entry))
    }

    fn request_cancellation(&self, entry: Arc<ExecutionEntry>) -> NodeEvent {
        {
            let mut state = entry.state.lock();
            match state.phase {
                ExecutionPhase::Preparing | ExecutionPhase::Ready | ExecutionPhase::Running => {
                    state.phase = ExecutionPhase::Cancelling;
                    entry.cancellation.cancel();
                }
                ExecutionPhase::Cancelling => {}
                phase if phase.is_terminal() => {}
                _ => unreachable!("all execution phases handled"),
            }
        };

        NodeEvent::new(entry.spec.execution_id, NodeEventKind::CancelAccepted)
    }

    fn finish_terminal(&self, entry: &ExecutionEntry, mut event: NodeEventKind) {
        {
            let mut state = entry.state.lock();
            if state.phase.is_terminal() {
                return;
            }
            if entry.cancellation.is_cancelled() {
                event = NodeEventKind::Cancelled;
            }
            debug_assert!(matches!(
                &event,
                NodeEventKind::Completed { .. }
                    | NodeEventKind::Failed { .. }
                    | NodeEventKind::Cancelled
            ));
            state.phase = ExecutionPhase::Terminal;
        }
        self.emit_terminal(entry, event);
    }

    fn finish_execution(
        &self,
        entry: &ExecutionEntry,
        execution: Result<VmCooperativeExecutionMetrics, String>,
        cleanup: Result<(), String>,
    ) {
        let event = if let Err(error) = cleanup {
            NodeEventKind::Failed {
                error: format!("execution cleanup failed: {error}"),
            }
        } else {
            match execution {
                Ok(metrics) => NodeEventKind::Completed { metrics },
                Err(error) => NodeEventKind::Failed { error },
            }
        };
        self.finish_terminal(entry, event);
    }

    fn emit(&self, event: NodeEvent) {
        let _ = self.events.send(event);
    }

    fn emit_terminal(&self, entry: &ExecutionEntry, kind: NodeEventKind) {
        debug_assert!(entry.phase().is_terminal());
        let event = NodeEvent::new(entry.spec.execution_id, kind);
        self.state
            .lock()
            .executions
            .remove(&entry.spec.execution_id);
        self.emit(event);
    }

    /// Stop admission and cancel every active execution. The standing process
    /// exits immediately after its control and transport loops are stopped.
    pub fn shutdown(&self) {
        let active: Vec<_> = {
            let mut state = self.state.lock();
            state.accepting = false;
            state.executions.values().cloned().collect()
        };
        for entry in active {
            self.request_cancellation(entry);
        }
    }
}

/// Wait for the process shutdown signal appropriate to the current platform.
pub async fn wait_for_shutdown_signal() -> Result<(), NodeSupervisorError> {
    #[cfg(unix)]
    {
        let mut terminate = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        )
        .map_err(|error| NodeSupervisorError::Signal {
            reason: error.to_string(),
        })?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.map_err(|error| NodeSupervisorError::Signal {
                reason: error.to_string(),
            }),
            _ = terminate.recv() => Ok(()),
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|error| NodeSupervisorError::Signal {
                reason: error.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::sync::Notify;

    #[derive(Default)]
    struct GateHandler {
        prepare_calls: AtomicUsize,
        execute_calls: AtomicUsize,
        cleanup_calls: AtomicUsize,
        release: Notify,
    }

    struct Prepared(Arc<GateHandler>);

    #[derive(Default)]
    struct OrderingHandler {
        started: Mutex<Vec<u8>>,
        first_started: AtomicBool,
        other_started: AtomicBool,
        second_started: AtomicBool,
        release_first: Notify,
        changed: Notify,
    }

    struct OrderingPrepared;

    #[async_trait]
    impl PreparedNodeExecution for OrderingPrepared {
        async fn execute(&mut self) -> Result<VmCooperativeExecutionMetrics, String> {
            Ok(VmCooperativeExecutionMetrics::default())
        }
    }

    #[async_trait]
    impl PreparedNodeExecution for Prepared {
        async fn execute(&mut self) -> Result<VmCooperativeExecutionMetrics, String> {
            self.0.execute_calls.fetch_add(1, Ordering::SeqCst);
            Ok(VmCooperativeExecutionMetrics::default())
        }

        async fn cleanup(&mut self) -> Result<(), String> {
            self.0.cleanup_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    impl GateHandler {
        async fn prepare(
            self: Arc<Self>,
            context: NodeExecutionContext,
        ) -> Result<Box<dyn PreparedNodeExecution>, String> {
            self.prepare_calls.fetch_add(1, Ordering::SeqCst);
            tokio::select! {
                _ = context.cancellation.cancelled() => Err("cancelled".to_owned()),
                _ = self.release.notified() => Ok(Box::new(Prepared(self))),
            }
        }
    }

    impl OrderingHandler {
        async fn prepare(
            self: Arc<Self>,
            context: NodeExecutionContext,
        ) -> Result<Box<dyn PreparedNodeExecution>, String> {
            let marker = context.spec.execution_id.as_bytes()[0];
            self.started.lock().push(marker);
            match context.spec.program_id[0] {
                1 if marker == 1 => {
                    self.first_started.store(true, Ordering::Release);
                    self.changed.notify_waiters();
                    self.release_first.notified().await;
                }
                1 => {
                    self.second_started.store(true, Ordering::Release);
                    self.changed.notify_waiters();
                }
                _ => {
                    self.other_started.store(true, Ordering::Release);
                    self.changed.notify_waiters();
                }
            }
            Ok(Box::new(OrderingPrepared))
        }
    }

    fn spec(byte: u8) -> ExecutionSpecV1 {
        ExecutionSpecV1::new(ExecutionId::from([byte; 32]), [byte; 32])
    }

    macro_rules! preparation {
        ($handler:expr) => {{
            let handler = Arc::clone(&$handler);
            move |context| handler.prepare(context)
        }};
    }

    async fn wait_for(
        events: &mut mpsc::UnboundedReceiver<NodeEvent>,
        execution_id: ExecutionId,
        expected: impl Fn(&NodeEventKind) -> bool,
    ) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let event = events.recv().await.expect("event channel remains open");
                if event.execution_id == execution_id && expected(&event.kind) {
                    return;
                }
            }
        })
        .await
        .expect("execution reaches requested phase");
    }

    async fn wait_until(handler: &OrderingHandler, ready: impl Fn(&OrderingHandler) -> bool) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let notified = handler.changed.notified();
                if ready(handler) {
                    return;
                }
                notified.await;
            }
        })
        .await
        .expect("preparation reaches expected point");
    }

    #[tokio::test]
    async fn prepare_launch_and_cleanup_are_isolated() {
        let handler = Arc::new(GateHandler::default());
        let (supervisor, mut events) = NodeSupervisor::new();
        let first = spec(1);
        let execution_id = first.execution_id;

        let preparing = supervisor
            .prepare(first.clone(), preparation!(handler))
            .unwrap();
        assert!(matches!(
            preparing,
            NodeEvent {
                execution_id: id,
                kind: NodeEventKind::Preparing,
            } if id == execution_id
        ));
        assert!(matches!(
            supervisor.prepare(first, preparation!(handler)),
            Err(NodeSupervisorError::DuplicateExecutionId { .. })
        ));
        let conflicting = ExecutionSpecV1::new(execution_id, [2; 32]);
        assert!(matches!(
            supervisor.prepare(conflicting, preparation!(handler)),
            Err(NodeSupervisorError::DuplicateExecutionId { .. })
        ));
        while handler.prepare_calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        handler.release.notify_one();
        let ready = tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .expect("ready event is emitted")
            .expect("supervisor event channel remains open");
        assert!(matches!(
            ready,
            NodeEvent {
                execution_id: id,
                kind: NodeEventKind::Ready,
            } if id == execution_id
        ));
        wait_for(&mut events, execution_id, |kind| {
            matches!(kind, NodeEventKind::Completed { .. })
        })
        .await;
        assert_eq!(handler.prepare_calls.load(Ordering::SeqCst), 1);
        assert_eq!(handler.execute_calls.load(Ordering::SeqCst), 1);
        assert_eq!(handler.cleanup_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancellation_cleans_preparing_work() {
        let handler = Arc::new(GateHandler::default());
        let (supervisor, mut events) = NodeSupervisor::new();
        let execution_id = spec(9).execution_id;
        supervisor.prepare(spec(9), preparation!(handler)).unwrap();
        supervisor.cancel(execution_id).unwrap();
        wait_for(&mut events, execution_id, |kind| {
            matches!(kind, NodeEventKind::Cancelled)
        })
        .await;
        assert_eq!(handler.execute_calls.load(Ordering::SeqCst), 0);
    }

    struct FailingHandler;

    impl FailingHandler {
        async fn prepare(
            self: Arc<Self>,
            _context: NodeExecutionContext,
        ) -> Result<Box<dyn PreparedNodeExecution>, String> {
            Err("deliberate preparation failure".to_owned())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_preparation_emits_event_and_releases_active_state() {
        let handler = Arc::new(FailingHandler);
        let (supervisor, mut events) = NodeSupervisor::new();
        let first = spec(10);
        let preparing = supervisor
            .prepare(first.clone(), preparation!(handler))
            .unwrap();
        assert!(matches!(
            preparing,
            NodeEvent {
                execution_id: id,
                kind: NodeEventKind::Preparing,
            } if id == first.execution_id
        ));
        wait_for(&mut events, first.execution_id, |kind| {
            matches!(kind, NodeEventKind::Failed { .. })
        })
        .await;
        supervisor
            .prepare(spec(11), preparation!(handler))
            .expect("terminal execution does not retain active state");
    }

    #[tokio::test]
    async fn same_program_preparation_is_fifo_while_different_programs_overlap() {
        let handler = Arc::new(OrderingHandler::default());
        let (supervisor, _events) = NodeSupervisor::new();
        let first = spec(1);
        let second = ExecutionSpecV1::new(ExecutionId::from([2; 32]), [1; 32]);
        let other = ExecutionSpecV1::new(ExecutionId::from([3; 32]), [3; 32]);

        supervisor.prepare(first, preparation!(handler)).unwrap();
        supervisor.prepare(second, preparation!(handler)).unwrap();
        supervisor.prepare(other, preparation!(handler)).unwrap();

        wait_until(&handler, |state| {
            state.first_started.load(Ordering::Acquire)
                && state.other_started.load(Ordering::Acquire)
        })
        .await;
        let started = handler.started.lock().clone();
        assert_eq!(started.len(), 2);
        assert!(started.contains(&1));
        assert!(started.contains(&3));
        assert!(!handler.second_started.load(Ordering::Acquire));

        handler.release_first.notify_one();
        wait_until(&handler, |state| {
            state.second_started.load(Ordering::Acquire)
        })
        .await;
        let started = handler.started.lock().clone();
        assert_eq!(started.len(), 3);
        assert_eq!(started.last(), Some(&2));
    }

    #[tokio::test]
    async fn cancelled_middle_prepare_does_not_release_later_same_program_work() {
        let handler = Arc::new(OrderingHandler::default());
        let (supervisor, mut events) = NodeSupervisor::new();
        let same_program = |byte: u8| ExecutionSpecV1::new(ExecutionId::from([byte; 32]), [1; 32]);
        let first = same_program(1);
        let middle = same_program(2);
        let last = same_program(3);

        supervisor.prepare(first, preparation!(handler)).unwrap();
        supervisor
            .prepare(middle.clone(), preparation!(handler))
            .unwrap();
        supervisor.prepare(last, preparation!(handler)).unwrap();
        wait_until(&handler, |state| {
            state.first_started.load(Ordering::Acquire)
        })
        .await;

        supervisor.cancel(middle.execution_id).unwrap();
        tokio::task::yield_now().await;
        assert_eq!(*handler.started.lock(), vec![1]);

        handler.release_first.notify_one();
        wait_for(&mut events, middle.execution_id, |kind| {
            matches!(kind, NodeEventKind::Cancelled)
        })
        .await;
        wait_until(&handler, |state| {
            state.second_started.load(Ordering::Acquire)
        })
        .await;
        assert_eq!(*handler.started.lock(), vec![1, 3]);
    }
}
