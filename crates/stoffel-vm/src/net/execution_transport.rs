//! Execution-scoped framing and routing for shared node transports.
//!
//! A persistent node can execute more than one MPC program at once.  A raw MPC
//! frame therefore cannot be routed by party ID, program ID, or a shortened
//! protocol instance ID alone: every frame has to carry the full
//! [`ExecutionId`].  This module provides the common wire envelope, a
//! [`Network`] adapter for outbound frames, and the single-reader transport
//! runtime used to demultiplex inbound frames into per-execution inboxes.
//!
//! The runtime enforces at most one [`ExecutionConnectionScanner`] across a
//! cloned `QuicNetworkManager` set. An execution consumes only its
//! [`ExecutionInbox`]; it must never call `PeerConnection::receive` itself.
//! The scanner lease coordinates scanner instances, but cannot intercept an
//! arbitrary caller that already holds a raw connection and calls `receive`.

use crate::net::session::ExecutionId;
use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use stoffelnet::network_utils::{
    CertificateIdentity, ClientId, Network, NetworkError, PartyId, VerifiedOrdering,
};
use stoffelnet::transports::quic::{
    ExecutionScannerReceiveOwnerLease, PeerConnection, QuicNetworkManager,
};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Magic bytes at the beginning of every execution-scoped frame.
pub const EXECUTION_ENVELOPE_MAGIC: [u8; 4] = *b"STXE";
/// Current execution envelope version.
pub const EXECUTION_ENVELOPE_VERSION: u8 = 1;
/// Fixed byte length of an execution envelope header.
pub const EXECUTION_ENVELOPE_HEADER_LEN: usize = 38;
/// The only client frame allowed to establish an execution-to-physical-
/// connection reply route. Protocol data cannot win a route race before the
/// party's explicit admission handshake.
pub const EXECUTION_CLIENT_ROUTE_HELLO_V1: &[u8] = b"STOFFEL_EXECUTION_CLIENT_HELLO_V1";
/// Maximum payload accepted by the execution transport (10 MB).
///
/// Deployments must configure the physical transport to accept no more than
/// this payload plus [`EXECUTION_ENVELOPE_HEADER_LEN`]. The execution mux sees a
/// frame only after `PeerConnection::receive` has assembled it, so this is not
/// by itself a pre-allocation bound for a differently configured transport.
pub const MAX_EXECUTION_PAYLOAD_LEN: usize = 10_000_000;
/// Maximum queued payload bytes retained by one execution inbox by default.
///
/// The channel's item capacity alone is not a useful memory bound because MPC
/// frames vary substantially in size. Keep room for one maximum-sized frame
/// from a source plus one from the remaining quorum, while preventing one
/// stalled execution from retaining an unbounded collection of large frames.
pub const DEFAULT_EXECUTION_INBOX_BYTE_CAPACITY: usize = 2 * MAX_EXECUTION_PAYLOAD_LEN;
/// Maximum queued payload bytes retained by all execution inboxes by default.
///
/// Standing nodes intentionally multiplex hundreds of executions over one
/// physical mesh.  The former eight-frame budget could be exhausted by a
/// short cross-execution burst even though every individual inbox was healthy;
/// the demultiplexer then had to retire an arbitrary execution and its MPC
/// peers eventually timed out waiting for a contribution that had already
/// reached the physical connection.  Keep a process-wide bound, but allow 32
/// independently busy inboxes to reach their per-execution bound at once.
pub const DEFAULT_EXECUTION_MUX_BYTE_CAPACITY: usize = 32 * DEFAULT_EXECUTION_INBOX_BYTE_CAPACITY;
const CONNECTION_SCAN_INTERVAL: Duration = Duration::from_millis(50);
/// How long a physical reader may apply bounded backpressure for a busy
/// execution before concluding that its consumer has stopped draining.
///
/// A short queue-full condition is normal when hundreds of executions share
/// one transport and Tokio schedules a burst of protocol frames before their
/// VM tasks. Dropping the already-consumed frame would permanently corrupt the
/// affected transcript, so preserve ordering and let the physical stream
/// backpressure briefly. A genuinely abandoned route is isolated after a
/// bounded interval rather than blocking sibling executions forever. The
/// execution itself remains owned by its explicit registration guard.
const EXECUTION_INGRESS_BACKPRESSURE_TIMEOUT: Duration = Duration::from_secs(30);
const EXECUTION_INGRESS_RETRY_INTERVAL: Duration = Duration::from_millis(2);

/// A physical client is not useful to the standing node until it proves an
/// authorized execution route. Keep this short so certificate-valid but idle
/// connections cannot consume the shared physical-client limit indefinitely.
const CLIENT_EXECUTION_HELLO_TIMEOUT: Duration = Duration::from_secs(10);

const MAGIC_RANGE: std::ops::Range<usize> = 0..4;
const VERSION_INDEX: usize = 4;
const KIND_INDEX: usize = 5;
const EXECUTION_ID_RANGE: std::ops::Range<usize> = 6..38;

/// Purpose of an execution-scoped payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ExecutionMessageKind {
    /// An opaque frame consumed by an MPC protocol implementation.
    Mpc = 1,
    /// Execution-scoped readiness, lifecycle, or protocol control traffic.
    Control = 2,
}

impl ExecutionMessageKind {
    fn decode(value: u8) -> Result<Self, ExecutionEnvelopeError> {
        match value {
            1 => Ok(Self::Mpc),
            2 => Ok(Self::Control),
            value => Err(ExecutionEnvelopeError::UnknownMessageKind(value)),
        }
    }
}

/// Errors produced by the strict execution-envelope codec.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecutionEnvelopeError {
    #[error("execution envelope is too short: expected at least {expected} bytes, got {actual}")]
    TooShort { expected: usize, actual: usize },
    #[error("invalid execution envelope magic")]
    InvalidMagic,
    #[error("unsupported execution envelope version {0}")]
    UnsupportedVersion(u8),
    #[error("unknown execution envelope message kind {0}")]
    UnknownMessageKind(u8),
    #[error("zero execution ID is not valid for an execution-scoped frame")]
    ZeroExecutionId,
    #[error("execution payload is too large: {actual} bytes (maximum {maximum})")]
    PayloadTooLarge { actual: usize, maximum: usize },
}

/// Borrowed view of one version-one execution envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionEnvelopeV1<'a> {
    execution_id: ExecutionId,
    kind: ExecutionMessageKind,
    payload: &'a [u8],
}

impl<'a> ExecutionEnvelopeV1<'a> {
    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    pub const fn kind(&self) -> ExecutionMessageKind {
        self.kind
    }

    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Decode one complete physical frame.
    pub fn decode(frame: &'a [u8]) -> Result<Self, ExecutionEnvelopeError> {
        if frame.len() < EXECUTION_ENVELOPE_HEADER_LEN {
            return Err(ExecutionEnvelopeError::TooShort {
                expected: EXECUTION_ENVELOPE_HEADER_LEN,
                actual: frame.len(),
            });
        }
        if frame[MAGIC_RANGE] != EXECUTION_ENVELOPE_MAGIC {
            return Err(ExecutionEnvelopeError::InvalidMagic);
        }
        if frame[VERSION_INDEX] != EXECUTION_ENVELOPE_VERSION {
            return Err(ExecutionEnvelopeError::UnsupportedVersion(
                frame[VERSION_INDEX],
            ));
        }
        let kind = ExecutionMessageKind::decode(frame[KIND_INDEX])?;

        let mut execution_id_bytes = [0u8; 32];
        execution_id_bytes.copy_from_slice(&frame[EXECUTION_ID_RANGE]);
        let execution_id = ExecutionId::from_bytes(execution_id_bytes);
        if execution_id.is_zero() {
            return Err(ExecutionEnvelopeError::ZeroExecutionId);
        }

        let payload = &frame[EXECUTION_ENVELOPE_HEADER_LEN..];
        if payload.len() > MAX_EXECUTION_PAYLOAD_LEN {
            return Err(ExecutionEnvelopeError::PayloadTooLarge {
                actual: payload.len(),
                maximum: MAX_EXECUTION_PAYLOAD_LEN,
            });
        }

        Ok(Self {
            execution_id,
            kind,
            payload,
        })
    }
}

/// Encode a borrowed payload without first copying it into an owned envelope.
/// This is the hot-path codec used by [`ExecutionScopedNetwork`].
pub fn encode_execution_frame(
    execution_id: ExecutionId,
    kind: ExecutionMessageKind,
    payload: &[u8],
) -> Result<Vec<u8>, ExecutionEnvelopeError> {
    if execution_id.is_zero() {
        return Err(ExecutionEnvelopeError::ZeroExecutionId);
    }
    if payload.len() > MAX_EXECUTION_PAYLOAD_LEN {
        return Err(ExecutionEnvelopeError::PayloadTooLarge {
            actual: payload.len(),
            maximum: MAX_EXECUTION_PAYLOAD_LEN,
        });
    }

    let mut encoded = Vec::with_capacity(EXECUTION_ENVELOPE_HEADER_LEN + payload.len());
    encoded.extend_from_slice(&EXECUTION_ENVELOPE_MAGIC);
    encoded.push(EXECUTION_ENVELOPE_VERSION);
    encoded.push(kind as u8);
    encoded.extend_from_slice(execution_id.as_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

/// A cloneable [`Network`] adapter that scopes every outbound frame.
///
/// Clones share the underlying QUIC connection maps but hold their endpoint role and
/// message kind by value, so creating a control-kind clone cannot mutate MPC
/// sends already in flight.
#[derive(Clone)]
pub struct ExecutionScopedNetwork<N = QuicNetworkManager> {
    inner: N,
    execution_id: ExecutionId,
    tolerate_party_omission: bool,
    kind: ExecutionMessageKind,
    reply_mux: Option<ExecutionTransportMux>,
}

impl<N> ExecutionScopedNetwork<N> {
    pub fn for_party(inner: N, execution_id: ExecutionId) -> Result<Self, ExecutionTransportError> {
        Self::scoped(inner, execution_id, true)
    }

    /// Construct an adapter for an external client's connection manager.
    pub fn for_client(
        inner: N,
        execution_id: ExecutionId,
    ) -> Result<Self, ExecutionTransportError> {
        Self::scoped(inner, execution_id, false)
    }

    fn scoped(
        inner: N,
        execution_id: ExecutionId,
        tolerate_party_omission: bool,
    ) -> Result<Self, ExecutionTransportError> {
        if execution_id.is_zero() {
            return Err(ExecutionTransportError::ZeroExecutionId);
        }
        Ok(Self {
            inner,
            execution_id,
            tolerate_party_omission,
            kind: ExecutionMessageKind::Mpc,
            reply_mux: None,
        })
    }

    /// Route party-to-client replies through the execution registry that
    /// admitted the exact physical client connection.
    pub fn with_reply_mux(mut self, mux: ExecutionTransportMux) -> Self {
        self.reply_mux = Some(mux);
        self
    }

    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// Change this adapter value's message kind without mutating any clones.
    pub fn with_message_kind(mut self, new_kind: ExecutionMessageKind) -> Self {
        self.kind = new_kind;
        self
    }

    fn frame_for(&self, payload: &[u8]) -> Result<Vec<u8>, NetworkError> {
        encode_execution_frame(self.execution_id, self.kind, payload)
            .map_err(|_| NetworkError::SendError)
    }

    fn tolerates_omission(&self) -> bool {
        self.tolerate_party_omission && self.kind == ExecutionMessageKind::Mpc
    }
}

#[async_trait]
impl<N> Network for ExecutionScopedNetwork<N>
where
    N: Network + Send + Sync,
    N::NodeType: Send + Sync,
{
    type NodeType = N::NodeType;
    type NetworkConfig = N::NetworkConfig;

    async fn send(&self, recipient: PartyId, message: &[u8]) -> Result<usize, NetworkError> {
        let frame = self.frame_for(message)?;
        let result = self.inner.send(recipient, &frame).await;
        if self.tolerates_omission()
            && matches!(
                result,
                Err(NetworkError::PartyNotFound(_))
                    | Err(NetworkError::SendError)
                    | Err(NetworkError::Timeout)
            )
        {
            // Byzantine omission is protocol input, not a local VM failure.
            Ok(0)
        } else {
            result
        }
    }

    async fn broadcast(&self, message: &[u8]) -> Result<usize, NetworkError> {
        let frame = self.frame_for(message)?;
        self.inner.broadcast(&frame).await
    }

    fn parties(&self) -> Vec<&Self::NodeType> {
        self.inner.parties()
    }

    fn parties_mut(&mut self) -> Vec<&mut Self::NodeType> {
        self.inner.parties_mut()
    }

    fn config(&self) -> &Self::NetworkConfig {
        self.inner.config()
    }

    fn node(&self, id: PartyId) -> Option<&Self::NodeType> {
        self.inner.node(id)
    }

    fn node_mut(&mut self, id: PartyId) -> Option<&mut Self::NodeType> {
        self.inner.node_mut(id)
    }

    async fn send_to_client(
        &self,
        client: ClientId,
        message: &[u8],
    ) -> Result<usize, NetworkError> {
        let frame = self.frame_for(message)?;
        if let Some(mux) = &self.reply_mux {
            mux.send_client_reply(self.execution_id, client, &frame)
                .await
        } else {
            self.inner.send_to_client(client, &frame).await
        }
    }

    fn clients(&self) -> Vec<ClientId> {
        self.inner.clients()
    }

    fn is_client_connected(&self, client: ClientId) -> bool {
        self.inner.is_client_connected(client)
    }

    fn local_party_id(&self) -> PartyId {
        self.inner.local_party_id()
    }

    fn party_count(&self) -> usize {
        self.inner.party_count()
    }

    fn verified_ordering(&self) -> Option<VerifiedOrdering> {
        self.inner.verified_ordering()
    }
}

/// Authenticated physical source of an inbound frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionTransportSource {
    Party(PartyId),
    Client(ClientId),
}

/// One decoded message delivered to an execution-owned inbox.
#[derive(Debug)]
pub struct ExecutionInboundMessage {
    pub source: ExecutionTransportSource,
    pub kind: ExecutionMessageKind,
    pub payload: Vec<u8>,
    // The lease follows the payload through any downstream bounded channel.
    // Its final drop releases both the per-execution and global queued-byte
    // reservations, including when a handler is cancelled with messages queued.
    _ingress_lease: ExecutionIngressLease,
}

/// Retained payload bytes are bounded twice: once for the destination
/// execution and once across the whole mux. The bounded route channels provide
/// the item limit, so duplicating item counters here only creates state which
/// can drift from the channels.
#[derive(Debug)]
struct IngressAccounting {
    limits: ExecutionIngressLimits,
    global_bytes: Arc<Semaphore>,
}

impl IngressAccounting {
    fn new(limits: ExecutionIngressLimits) -> Self {
        Self {
            limits,
            global_bytes: Arc::new(Semaphore::new(limits.global_byte_capacity)),
        }
    }

    fn reserve(
        &self,
        execution_bytes: Arc<Semaphore>,
        payload_bytes: usize,
    ) -> Result<ExecutionIngressLease, ()> {
        let permits = u32::try_from(payload_bytes).map_err(|_| ())?;
        let execution = execution_bytes
            .try_acquire_many_owned(permits)
            .map_err(|_| ())?;
        let global = Arc::clone(&self.global_bytes)
            .try_acquire_many_owned(permits)
            .map_err(|_| ())?;
        Ok(ExecutionIngressLease {
            _execution: execution,
            _global: global,
        })
    }

    #[cfg(test)]
    fn queued_bytes(&self) -> usize {
        self.limits
            .global_byte_capacity
            .saturating_sub(self.global_bytes.available_permits())
    }
}

#[derive(Debug)]
struct ExecutionIngressLease {
    _execution: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
}

/// The three bounded ingress queues owned by one execution.
pub struct ExecutionInbox {
    pub party: mpsc::Receiver<ExecutionInboundMessage>,
    pub control: mpsc::Receiver<ExecutionInboundMessage>,
    pub client: mpsc::Receiver<ExecutionInboundMessage>,
}

struct ExecutionInboxSenders {
    party: mpsc::Sender<ExecutionInboundMessage>,
    control: mpsc::Sender<ExecutionInboundMessage>,
    client: mpsc::Sender<ExecutionInboundMessage>,
    disabled_routes: AtomicU8,
    expected_client_identities: Option<Vec<CertificateIdentity>>,
    client_routes: Mutex<HashMap<ClientId, Weak<dyn PeerConnection>>>,
    execution_bytes: Arc<Semaphore>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionInboxRoute {
    Party,
    Control,
    Client,
}

impl ExecutionInboxRoute {
    const fn disabled_bit(self) -> u8 {
        match self {
            Self::Party => 1 << 0,
            Self::Control => 1 << 1,
            Self::Client => 1 << 2,
        }
    }
}

impl ExecutionInboxSenders {
    fn route_is_disabled(&self, route: ExecutionInboxRoute) -> bool {
        self.disabled_routes.load(Ordering::Acquire) & route.disabled_bit() != 0
    }

    fn disable_route(&self, route: ExecutionInboxRoute) {
        self.disabled_routes
            .fetch_or(route.disabled_bit(), Ordering::AcqRel);
    }
}

/// Errors from registration, framing, or inbox routing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecutionTransportError {
    #[error(transparent)]
    Envelope(#[from] ExecutionEnvelopeError),
    #[error("zero execution ID cannot be registered or scoped")]
    ZeroExecutionId,
    #[error("execution {0} is already registered")]
    DuplicateExecution(ExecutionId),
    #[error("all execution ingress item and byte capacities must be greater than zero")]
    InvalidIngressCapacity,
    #[error("an execution connection scanner already owns this network manager")]
    ConnectionScannerAlreadyRunning,
    #[error(
        "authenticated client {client_id} attempted to bind execution {execution_id} from a \
         second live physical connection"
    )]
    ClientRouteConflict {
        client_id: ClientId,
        execution_id: ExecutionId,
    },
    #[error(
        "expected client certificate identity appears at both ordinal {first_client_id} and {duplicate_client_id}"
    )]
    DuplicateExpectedClientIdentity {
        first_client_id: ClientId,
        duplicate_client_id: ClientId,
    },
    #[error(
        "client connection did not expose a TLS-authenticated certificate for execution {execution_id}"
    )]
    ClientCertificateIdentityUnavailable { execution_id: ExecutionId },
    #[error("certificate is not authorized for execution {execution_id}")]
    UnauthorizedClientCertificate { execution_id: ExecutionId },
    #[error("an authenticated client cannot send to direct client endpoint for {execution_id}")]
    ClientSourceOnClientEndpoint { execution_id: ExecutionId },
    #[error("execution inbox is full for {execution_id}")]
    InboxFull { execution_id: ExecutionId },
    #[error("queued payload byte capacity exceeded for execution {execution_id}")]
    InboxByteCapacityExceeded { execution_id: ExecutionId },
}

/// Retained-ingress limits for a shared execution mux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionIngressLimits {
    pub inbox_capacity: usize,
    pub execution_byte_capacity: usize,
    pub global_byte_capacity: usize,
}

impl ExecutionIngressLimits {
    pub const fn production(inbox_capacity: usize) -> Self {
        Self {
            inbox_capacity,
            execution_byte_capacity: DEFAULT_EXECUTION_INBOX_BYTE_CAPACITY,
            global_byte_capacity: DEFAULT_EXECUTION_MUX_BYTE_CAPACITY,
        }
    }
}

/// Central full-ID registry and non-blocking execution demultiplexer.
#[derive(Clone)]
pub struct ExecutionTransportMux {
    direct_client: bool,
    inbox_capacity: usize,
    ingress: Arc<IngressAccounting>,
    entries: Arc<RwLock<HashMap<ExecutionId, Arc<ExecutionInboxSenders>>>>,
}

impl ExecutionTransportMux {
    pub fn new(inbox_capacity: usize) -> Result<Self, ExecutionTransportError> {
        Self::new_with_limits(ExecutionIngressLimits::production(inbox_capacity))
    }

    /// Construct a mux for a direct client receiving party output/control.
    pub fn new_client(inbox_capacity: usize) -> Result<Self, ExecutionTransportError> {
        Self::build(ExecutionIngressLimits::production(inbox_capacity), true)
    }

    pub fn new_with_limits(
        limits: ExecutionIngressLimits,
    ) -> Result<Self, ExecutionTransportError> {
        Self::build(limits, false)
    }

    pub fn new_client_with_limits(
        limits: ExecutionIngressLimits,
    ) -> Result<Self, ExecutionTransportError> {
        Self::build(limits, true)
    }

    fn build(
        limits: ExecutionIngressLimits,
        direct_client: bool,
    ) -> Result<Self, ExecutionTransportError> {
        if limits.inbox_capacity == 0
            || limits.execution_byte_capacity == 0
            || limits.global_byte_capacity == 0
            || limits.execution_byte_capacity > limits.global_byte_capacity
        {
            return Err(ExecutionTransportError::InvalidIngressCapacity);
        }
        Ok(Self {
            direct_client,
            inbox_capacity: limits.inbox_capacity,
            ingress: Arc::new(IngressAccounting::new(limits)),
            entries: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Register a globally unique wire execution ID.
    ///
    /// Callers must never reuse an ID, including after unregister. The mux
    /// intentionally does not retain an unbounded tombstone per completed run;
    /// standing control persists this invariant in its bounded durable index.
    pub fn register(
        &self,
        execution_id: ExecutionId,
    ) -> Result<ExecutionInbox, ExecutionTransportError> {
        self.register_inner(execution_id, None)
    }

    /// Atomically register an inbox and its execution-local certificate
    /// roster. An empty roster is an explicit deny-all client policy.
    pub fn register_with_client_identities(
        &self,
        execution_id: ExecutionId,
        expected_client_identities: Vec<CertificateIdentity>,
    ) -> Result<ExecutionInbox, ExecutionTransportError> {
        self.register_inner(execution_id, Some(expected_client_identities))
    }

    fn register_inner(
        &self,
        execution_id: ExecutionId,
        expected_client_identities: Option<Vec<CertificateIdentity>>,
    ) -> Result<ExecutionInbox, ExecutionTransportError> {
        if execution_id.is_zero() {
            return Err(ExecutionTransportError::ZeroExecutionId);
        }
        if let Some(identities) = &expected_client_identities {
            for duplicate_client_id in 0..identities.len() {
                if let Some(first_client_id) = identities[..duplicate_client_id]
                    .iter()
                    .position(|identity| identity == &identities[duplicate_client_id])
                {
                    return Err(ExecutionTransportError::DuplicateExpectedClientIdentity {
                        first_client_id,
                        duplicate_client_id,
                    });
                }
            }
        }
        let (party_tx, party) = mpsc::channel(self.inbox_capacity);
        let (control_tx, control) = mpsc::channel(self.inbox_capacity);
        let (client_tx, client) = mpsc::channel(self.inbox_capacity);
        let mut entries = self.entries.write();
        if entries.contains_key(&execution_id) {
            return Err(ExecutionTransportError::DuplicateExecution(execution_id));
        }
        let execution_bytes = Arc::new(Semaphore::new(self.ingress.limits.execution_byte_capacity));
        entries.insert(
            execution_id,
            Arc::new(ExecutionInboxSenders {
                party: party_tx,
                control: control_tx,
                client: client_tx,
                disabled_routes: AtomicU8::new(0),
                expected_client_identities,
                client_routes: Mutex::new(HashMap::new()),
                execution_bytes,
            }),
        );
        Ok(ExecutionInbox {
            party,
            control,
            client,
        })
    }

    /// Explicitly retire every route for an execution.
    ///
    /// Individual route closure or saturation never calls this method: the
    /// owner which created the registration is solely responsible for ending
    /// its lifetime.
    pub fn unregister(&self, execution_id: ExecutionId) -> bool {
        self.entries.write().remove(&execution_id).is_some()
    }

    /// Validate local registration and bind the authenticated physical client
    /// connection for replies from this execution.
    fn authorize_client_route_if_registered(
        &self,
        envelope: &ExecutionEnvelopeV1<'_>,
        transport_client_id: ClientId,
        connection: &Arc<dyn PeerConnection>,
    ) -> Result<Option<ClientId>, ExecutionTransportError> {
        let execution_id = envelope.execution_id();
        let entries = self.entries.read();
        let Some(entry) = entries.get(&execution_id) else {
            return Ok(None);
        };
        let client_id = if let Some(expected) = &entry.expected_client_identities {
            let public_key = connection.authenticated_peer_public_key().ok_or(
                ExecutionTransportError::ClientCertificateIdentityUnavailable { execution_id },
            )?;
            expected
                .iter()
                .position(|identity| *identity == public_key.certificate_identity())
                .ok_or(ExecutionTransportError::UnauthorizedClientCertificate { execution_id })?
        } else {
            // One-shot executions do not have a standing-node client roster.
            // Standing mode always installs an explicit certificate roster.
            transport_client_id
        };
        let is_route_hello = envelope.kind() == ExecutionMessageKind::Control
            && envelope.payload() == EXECUTION_CLIENT_ROUTE_HELLO_V1;
        let candidate = Arc::downgrade(connection);
        let mut routes = entry.client_routes.lock();
        if !is_route_hello {
            return if routes.get(&client_id).is_some_and(|existing| {
                Weak::ptr_eq(existing, &candidate) && existing.upgrade().is_some()
            }) {
                Ok(Some(client_id))
            } else {
                Err(ExecutionTransportError::ClientRouteConflict {
                    client_id,
                    execution_id,
                })
            };
        }
        if let Some(existing) = routes.get(&client_id) {
            if Weak::ptr_eq(existing, &candidate) {
                return Ok(Some(client_id));
            }
            if existing.upgrade().is_some() {
                return Err(ExecutionTransportError::ClientRouteConflict {
                    client_id,
                    execution_id,
                });
            }
        }
        routes.insert(client_id, candidate);
        Ok(Some(client_id))
    }

    async fn send_client_reply(
        &self,
        execution_id: ExecutionId,
        client_id: ClientId,
        message: &[u8],
    ) -> Result<usize, NetworkError> {
        let entry = self
            .entries
            .read()
            .get(&execution_id)
            .cloned()
            .ok_or(NetworkError::ClientNotFound(client_id))?;
        let connection = entry
            .client_routes
            .lock()
            .get(&client_id)
            .and_then(Weak::upgrade)
            .ok_or(NetworkError::ClientNotFound(client_id))?;
        if connection.send(message).await.is_ok() {
            return Ok(message.len());
        }
        let candidate = Arc::downgrade(&connection);
        let mut routes = entry.client_routes.lock();
        if routes
            .get(&client_id)
            .is_some_and(|existing| Weak::ptr_eq(existing, &candidate))
        {
            routes.remove(&client_id);
        }
        Err(NetworkError::SendError)
    }

    pub fn route_party_frame(
        &self,
        sender: PartyId,
        frame: &[u8],
    ) -> Result<(), ExecutionTransportError> {
        let envelope = ExecutionEnvelopeV1::decode(frame)?;
        self.route_envelope(
            ExecutionTransportSource::Party(sender),
            ExecutionTransportSource::Party(sender),
            envelope,
        )
    }

    fn inbox_route(
        &self,
        authenticated_source: ExecutionTransportSource,
        kind: ExecutionMessageKind,
        execution_id: ExecutionId,
    ) -> Result<ExecutionInboxRoute, ExecutionTransportError> {
        match (self.direct_client, authenticated_source, kind) {
            (false, ExecutionTransportSource::Party(_), ExecutionMessageKind::Control) => {
                Ok(ExecutionInboxRoute::Control)
            }
            (false, ExecutionTransportSource::Party(_), ExecutionMessageKind::Mpc) => {
                Ok(ExecutionInboxRoute::Party)
            }
            (false, ExecutionTransportSource::Client(_), _)
            | (true, ExecutionTransportSource::Party(_), _) => Ok(ExecutionInboxRoute::Client),
            (true, ExecutionTransportSource::Client(_), _) => {
                Err(ExecutionTransportError::ClientSourceOnClientEndpoint { execution_id })
            }
        }
    }

    fn route_envelope(
        &self,
        authenticated_source: ExecutionTransportSource,
        source: ExecutionTransportSource,
        envelope: ExecutionEnvelopeV1<'_>,
    ) -> Result<(), ExecutionTransportError> {
        let execution_id = envelope.execution_id();
        let route = self.inbox_route(authenticated_source, envelope.kind(), execution_id)?;

        // Keep the registry read lock through the non-blocking send so an
        // unregister cannot race a delivery into a completed execution.
        let entries = self.entries.read();
        let senders = entries.get(&execution_id).cloned();
        let Some(senders) = senders else {
            return Ok(());
        };
        if senders.route_is_disabled(route) {
            return Ok(());
        }

        let kind = envelope.kind();
        let payload_bytes = envelope.payload().len();
        let ingress_lease = self
            .ingress
            .reserve(Arc::clone(&senders.execution_bytes), payload_bytes)
            .map_err(|()| ExecutionTransportError::InboxByteCapacityExceeded { execution_id })?;
        let message = ExecutionInboundMessage {
            source,
            kind,
            payload: envelope.payload().to_vec(),
            _ingress_lease: ingress_lease,
        };
        let result = match route {
            ExecutionInboxRoute::Party => senders.party.try_send(message),
            ExecutionInboxRoute::Control => senders.control.try_send(message),
            ExecutionInboxRoute::Client => senders.client.try_send(message),
        };
        match result {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(message)) => {
                drop(message);
                Err(ExecutionTransportError::InboxFull { execution_id })
            }
            Err(mpsc::error::TrySendError::Closed(message)) => {
                drop(message);
                // Receivers have deliberately different lifetimes. For
                // example, preprocessing drops the control receiver while the
                // party protocol route remains active. A closed sibling route
                // must therefore never unregister the whole execution.
                senders.disable_route(route);
                Ok(())
            }
        }
    }

    async fn route_envelope_with_backpressure(
        &self,
        authenticated_source: ExecutionTransportSource,
        source: ExecutionTransportSource,
        envelope: ExecutionEnvelopeV1<'_>,
        cancel: &CancellationToken,
    ) -> Result<(), ExecutionTransportError> {
        self.route_envelope_with_backpressure_until(
            authenticated_source,
            source,
            envelope,
            cancel,
            Instant::now() + EXECUTION_INGRESS_BACKPRESSURE_TIMEOUT,
        )
        .await
    }

    async fn route_envelope_with_backpressure_until(
        &self,
        authenticated_source: ExecutionTransportSource,
        source: ExecutionTransportSource,
        envelope: ExecutionEnvelopeV1<'_>,
        cancel: &CancellationToken,
        deadline: Instant,
    ) -> Result<(), ExecutionTransportError> {
        let route = self.inbox_route(
            authenticated_source,
            envelope.kind(),
            envelope.execution_id(),
        )?;
        loop {
            match self.route_envelope(authenticated_source, source, envelope) {
                Err(error @ ExecutionTransportError::InboxFull { .. })
                | Err(error @ ExecutionTransportError::InboxByteCapacityExceeded { .. }) => {
                    if Instant::now() >= deadline {
                        if matches!(error, ExecutionTransportError::InboxFull { .. }) {
                            if let Some(senders) =
                                self.entries.read().get(&envelope.execution_id()).cloned()
                            {
                                senders.disable_route(route);
                            }
                        }
                        return Err(error);
                    }
                    tokio::select! {
                        _ = cancel.cancelled() => return Ok(()),
                        _ = tokio::time::sleep(EXECUTION_INGRESS_RETRY_INTERVAL) => {}
                    }
                }
                result => return result,
            }
        }
    }
}

struct ReceiveTask {
    cancel: CancellationToken,
    join: JoinHandle<()>,
}

/// Guard for the execution scanner which owns per-connection reader tasks.
///
/// Dropping the guard cancels the scanner and all child receive loops. Use
/// [`shutdown`](Self::shutdown) when the caller needs to await their exit. The
/// clone-shared network lease remains claimed until the scanner task and all
/// child loops have actually exited; dropping this public handle only requests
/// cancellation.
pub struct ExecutionConnectionScanner {
    cancel: CancellationToken,
    join: Option<JoinHandle<()>>,
}

impl ExecutionConnectionScanner {
    pub fn spawn(
        network: QuicNetworkManager,
        mux: ExecutionTransportMux,
    ) -> Result<Self, ExecutionTransportError> {
        let receive_owner = network
            .try_acquire_execution_scanner_receive_owner()
            .ok_or(ExecutionTransportError::ConnectionScannerAlreadyRunning)?;
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let join = tokio::spawn(async move {
            run_connection_scanner(network, mux, task_cancel, receive_owner).await;
        });
        Ok(Self {
            cancel,
            join: Some(join),
        })
    }

    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}

impl Drop for ExecutionConnectionScanner {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn connection_identity(connection: &Arc<dyn PeerConnection>) -> usize {
    Arc::as_ptr(connection) as *const () as usize
}

async fn run_connection_scanner(
    network: QuicNetworkManager,
    mux: ExecutionTransportMux,
    cancel: CancellationToken,
    receive_owner: ExecutionScannerReceiveOwnerLease,
) {
    let mut interval = tokio::time::interval(CONNECTION_SCAN_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut tasks: HashMap<usize, ReceiveTask> = HashMap::new();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = interval.tick() => {
                network.cleanup_dead_connections().await;
                let mut connections: HashMap<
                    usize,
                    (ExecutionTransportSource, Arc<dyn PeerConnection>),
                > = HashMap::new();
                for (_, connection) in network.get_all_server_connections() {
                    // Party IDs are the agreed roster positions, not compact
                    // certificate IDs. Starting a reader before assignment can
                    // permanently misattribute its first frame.
                    let Some(party_id) = connection.remote_party_id() else {
                        continue;
                    };
                    connections.entry(connection_identity(&connection))
                        .or_insert((ExecutionTransportSource::Party(party_id), connection));
                }
                for (_, connection) in network.get_all_client_connections() {
                    let Some(client_id) = connection
                        .authenticated_peer_public_key()
                        .map(|key| key.derive_id())
                    else {
                        continue;
                    };
                    connections.entry(connection_identity(&connection))
                        .or_insert((ExecutionTransportSource::Client(client_id), connection));
                }

                let obsolete: Vec<usize> = tasks.keys()
                    .filter(|identity| !connections.contains_key(identity))
                    .copied()
                    .collect();
                for identity in obsolete {
                    if let Some(task) = tasks.remove(&identity) {
                        task.cancel.cancel();
                        let _ = task.join.await;
                    }
                }

                for (identity, (source, connection)) in connections {
                    let restart = tasks.get(&identity).is_some_and(|task| task.join.is_finished());
                    if tasks.contains_key(&identity) && !restart {
                        continue;
                    }
                    if let Some(task) = tasks.remove(&identity) {
                        task.cancel.cancel();
                        let _ = task.join.await;
                    }
                    if !connection.is_connected().await {
                        continue;
                    }
                    let task_cancel = cancel.child_token();
                    let receive_cancel = task_cancel.clone();
                    let receive_mux = mux.clone();
                    // A child retains the manager-wide scanner claim even if
                    // the supervisor task unwinds. Reacquisition is impossible
                    // while any physical reader from the prior scanner lives.
                    let receive_owner = receive_owner.clone();
                    let join = tokio::spawn(async move {
                        run_connection_receive_loop_with_owner(
                            connection,
                            source,
                            receive_mux,
                            receive_cancel,
                            Some(receive_owner),
                        )
                        .await;
                    });
                    tasks.insert(identity, ReceiveTask { cancel: task_cancel, join });
                }
            }
        }
    }

    for (_, task) in tasks.drain() {
        task.cancel.cancel();
        let _ = task.join.await;
    }
}

async fn run_connection_receive_loop_with_owner(
    connection: Arc<dyn PeerConnection>,
    authenticated_source: ExecutionTransportSource,
    mux: ExecutionTransportMux,
    cancel: CancellationToken,
    receive_owner: Option<ExecutionScannerReceiveOwnerLease>,
) {
    // Never select directly over `PeerConnection::receive`: dropping a receive
    // future after it has consumed only part of a physical frame can desync a
    // stream transport. One dedicated task owns sequential reads until close.
    // The single-slot channel retains at most one completed raw frame, plus the
    // reader's one in-flight frame, both bounded by the physical frame limit.
    let (frame_tx, mut frame_rx) = mpsc::channel::<Result<Vec<u8>, String>>(1);
    let reader_connection = connection.clone();
    let reader_receive_owner = receive_owner.clone();
    let reader = tokio::spawn(async move {
        let _receive_owner = reader_receive_owner;
        loop {
            let result = reader_connection.receive().await;
            let terminal = result.is_err();
            if frame_tx.send(result).await.is_err() || terminal {
                break;
            }
        }
    });

    let mut client_admitted = !matches!(authenticated_source, ExecutionTransportSource::Client(_));
    let client_hello_deadline = Instant::now() + CLIENT_EXECUTION_HELLO_TIMEOUT;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                break;
            },
            _ = tokio::time::sleep_until(client_hello_deadline.into()), if !client_admitted => {
                let _ = connection.close().await;
                break;
            },
            result = frame_rx.recv() => match result {
                Some(Ok(frame)) => {
                    let mut logical_source = authenticated_source;
                    let envelope = match ExecutionEnvelopeV1::decode(&frame) {
                        Ok(envelope) => envelope,
                        Err(_) => {
                            // A frame codec failure leaves the peer stream
                            // untrustworthy. Close rather than allowing an
                            // attacker to retain a physical client slot.
                            let _ = connection.close().await;
                            break;
                        }
                    };
                    // A certificate identifies the logical client admission,
                    // while the explicit hello binds this execution to the
                    // exact physical process. Subsequent frames must remain on
                    // that connection; a sibling reusing the certificate can
                    // neither inject protocol input nor receive replies.
                    if let ExecutionTransportSource::Client(transport_client_id) = authenticated_source {
                        let is_route_hello = envelope.kind() == ExecutionMessageKind::Control
                            && envelope.payload() == EXECUTION_CLIENT_ROUTE_HELLO_V1;
                        match mux.authorize_client_route_if_registered(
                            &envelope,
                            transport_client_id,
                            &connection,
                        ) {
                            Ok(Some(client_id)) => {
                                logical_source = ExecutionTransportSource::Client(client_id);
                                client_admitted |= is_route_hello;
                            }
                            Ok(None) => {}
                            Err(_) => continue,
                        }
                    }

                    match mux
                        .route_envelope_with_backpressure(
                            authenticated_source,
                            logical_source,
                            envelope,
                            &cancel,
                        )
                        .await
                    {
                        Ok(_) => {}
                        Err(error @ ExecutionTransportError::InboxFull { execution_id, .. })
                        | Err(error @ ExecutionTransportError::InboxByteCapacityExceeded {
                            execution_id,
                            ..
                        }) => {
                            // A full inbox is transient under a concurrent
                            // burst. After bounded backpressure, a route-local
                            // item overflow disables only that logical route;
                            // byte-budget pressure drops only this frame. The
                            // execution's sibling routes remain registered.
                            tracing::warn!(
                                %execution_id,
                                %error,
                                "execution transport ingress remained saturated; dropping frame"
                            );
                        }
                        Err(_) => {}
                    }
                }
                Some(Err(_)) => break,
                None => {
                    break;
                },
            },
        }
    }

    // Close is the cancellation mechanism for the dedicated reader. Drop the
    // channel first so a reader waiting to publish a completed frame can exit;
    // then await it so no receive future is ever aborted mid-frame.
    drop(frame_rx);
    if cancel.is_cancelled() {
        let _ = connection.close().await;
    }
    let _ = reader.await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use stoffelnet::transports::quic::LoopbackPeerConnection;

    fn execution(byte: u8) -> ExecutionId {
        ExecutionId::from_bytes([byte; 32])
    }

    fn frame(execution_id: ExecutionId, kind: ExecutionMessageKind, payload: &[u8]) -> Vec<u8> {
        encode_execution_frame(execution_id, kind, payload).unwrap()
    }

    fn route_client_frame(
        mux: &ExecutionTransportMux,
        execution_id: ExecutionId,
        kind: ExecutionMessageKind,
        payload: &[u8],
    ) -> Result<(), ExecutionTransportError> {
        let encoded = frame(execution_id, kind, payload);
        let envelope = ExecutionEnvelopeV1::decode(&encoded).unwrap();
        mux.route_envelope(
            ExecutionTransportSource::Client(7),
            ExecutionTransportSource::Client(7),
            envelope,
        )
    }

    #[test]
    fn envelope_round_trip_preserves_full_execution_id() {
        let execution_id = ExecutionId::from_bytes([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ]);
        let encoded = frame(execution_id, ExecutionMessageKind::Control, b"ready");
        let decoded = ExecutionEnvelopeV1::decode(&encoded).unwrap();

        assert_eq!(decoded.execution_id(), execution_id);
        assert_eq!(decoded.kind(), ExecutionMessageKind::Control);
        assert_eq!(decoded.payload(), b"ready");
    }

    #[test]
    fn envelope_rejects_zero_execution_ids() {
        assert_eq!(
            encode_execution_frame(ExecutionId::from([0; 32]), ExecutionMessageKind::Mpc, &[],)
                .unwrap_err(),
            ExecutionEnvelopeError::ZeroExecutionId
        );

        let mut bad = frame(execution(1), ExecutionMessageKind::Mpc, b"abc");
        bad[EXECUTION_ID_RANGE].fill(0);
        assert_eq!(
            ExecutionEnvelopeV1::decode(&bad).unwrap_err(),
            ExecutionEnvelopeError::ZeroExecutionId
        );
    }

    #[test]
    fn expected_client_roster_is_exact_and_ordered() {
        let first_identity = CertificateIdentity::from_bytes([1; 32]);
        let second_identity = CertificateIdentity::from_bytes([2; 32]);
        let mux = ExecutionTransportMux::new(1).unwrap();
        assert!(mux
            .register_with_client_identities(execution(1), vec![first_identity, second_identity])
            .is_ok());
        assert!(mux
            .register_with_client_identities(execution(2), vec![first_identity, first_identity])
            .is_err());
    }

    #[tokio::test]
    async fn mux_isolates_inboxes_by_full_execution_id() {
        let mux = ExecutionTransportMux::new(8).unwrap();
        let mut first = mux.register(execution(1)).unwrap();
        let mut second = mux.register(execution(2)).unwrap();

        mux.route_party_frame(
            3,
            &frame(execution(2), ExecutionMessageKind::Mpc, b"second"),
        )
        .unwrap();
        mux.route_party_frame(
            3,
            &frame(execution(1), ExecutionMessageKind::Control, b"first"),
        )
        .unwrap();

        let first_message = first.control.recv().await.unwrap();
        let second_message = second.party.recv().await.unwrap();
        assert_eq!(first_message.payload, b"first");
        assert_eq!(second_message.payload, b"second");
    }

    #[tokio::test]
    async fn closing_one_inbox_route_preserves_the_execution_and_its_siblings() {
        let limits = ExecutionIngressLimits {
            inbox_capacity: 4,
            execution_byte_capacity: 300_000,
            global_byte_capacity: 1_000_000,
        };
        let mux = ExecutionTransportMux::new_with_limits(limits).unwrap();

        let control_id = execution(10);
        let mut control_closed = mux.register(control_id).unwrap();
        drop(control_closed.control);
        let late_preprocessing_value = [0_u8; 24];
        mux.route_party_frame(
            1,
            &frame(
                control_id,
                ExecutionMessageKind::Control,
                &late_preprocessing_value,
            ),
        )
        .unwrap();
        let batch_open = vec![0xAB; 229_439];
        mux.route_party_frame(
            1,
            &frame(control_id, ExecutionMessageKind::Mpc, &batch_open),
        )
        .unwrap();
        route_client_frame(
            &mux,
            control_id,
            ExecutionMessageKind::Mpc,
            b"client survives",
        )
        .unwrap();
        assert_eq!(
            control_closed.party.recv().await.unwrap().payload,
            batch_open
        );
        assert_eq!(
            control_closed.client.recv().await.unwrap().payload,
            b"client survives"
        );
        assert!(mux.entries.read().contains_key(&control_id));

        let party_id = execution(11);
        let mut party_closed = mux.register(party_id).unwrap();
        drop(party_closed.party);
        mux.route_party_frame(
            1,
            &frame(party_id, ExecutionMessageKind::Mpc, b"late party"),
        )
        .unwrap();
        mux.route_party_frame(
            1,
            &frame(party_id, ExecutionMessageKind::Control, b"control survives"),
        )
        .unwrap();
        route_client_frame(
            &mux,
            party_id,
            ExecutionMessageKind::Mpc,
            b"client survives",
        )
        .unwrap();
        assert_eq!(
            party_closed.control.recv().await.unwrap().payload,
            b"control survives"
        );
        assert_eq!(
            party_closed.client.recv().await.unwrap().payload,
            b"client survives"
        );
        assert!(mux.entries.read().contains_key(&party_id));

        let client_id = execution(12);
        let mut client_closed = mux.register(client_id).unwrap();
        drop(client_closed.client);
        route_client_frame(
            &mux,
            client_id,
            ExecutionMessageKind::Control,
            b"late client control",
        )
        .unwrap();
        mux.route_party_frame(
            1,
            &frame(client_id, ExecutionMessageKind::Mpc, b"party survives"),
        )
        .unwrap();
        mux.route_party_frame(
            1,
            &frame(
                client_id,
                ExecutionMessageKind::Control,
                b"control survives",
            ),
        )
        .unwrap();
        assert_eq!(
            client_closed.party.recv().await.unwrap().payload,
            b"party survives"
        );
        assert_eq!(
            client_closed.control.recv().await.unwrap().payload,
            b"control survives"
        );
        assert!(mux.entries.read().contains_key(&client_id));
        assert_eq!(mux.ingress.queued_bytes(), 0);
    }

    #[tokio::test]
    async fn saturated_control_route_does_not_retire_party_route() {
        let limits = ExecutionIngressLimits {
            inbox_capacity: 1,
            execution_byte_capacity: 64,
            global_byte_capacity: 128,
        };
        let mux = ExecutionTransportMux::new_with_limits(limits).unwrap();
        let execution_id = execution(13);
        let mut inbox = mux.register(execution_id).unwrap();
        mux.route_party_frame(
            1,
            &frame(execution_id, ExecutionMessageKind::Control, b"first"),
        )
        .unwrap();

        let encoded = frame(execution_id, ExecutionMessageKind::Control, b"second");
        let envelope = ExecutionEnvelopeV1::decode(&encoded).unwrap();
        let error = mux
            .route_envelope_with_backpressure_until(
                ExecutionTransportSource::Party(1),
                ExecutionTransportSource::Party(1),
                envelope,
                &CancellationToken::new(),
                Instant::now() + Duration::from_millis(20),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, ExecutionTransportError::InboxFull { .. }));

        mux.route_party_frame(
            1,
            &frame(execution_id, ExecutionMessageKind::Mpc, b"party survives"),
        )
        .unwrap();
        assert_eq!(inbox.party.recv().await.unwrap().payload, b"party survives");
        assert!(mux.entries.read().contains_key(&execution_id));
    }

    #[tokio::test]
    async fn party_send_tolerates_omission_but_client_send_does_not() {
        let party =
            ExecutionScopedNetwork::for_party(QuicNetworkManager::new(), execution(9)).unwrap();
        assert_eq!(party.send(4, b"quorum message").await, Ok(0));

        let client =
            ExecutionScopedNetwork::for_client(QuicNetworkManager::new(), execution(9)).unwrap();
        assert!(matches!(
            client.send(4, b"client message").await,
            Err(NetworkError::PartyNotFound(4))
        ));
    }

    #[tokio::test]
    async fn reply_routes_are_owned_and_isolated_by_execution() {
        let mux = ExecutionTransportMux::new(8).unwrap();
        let first_id = execution(1);
        let second_id = execution(2);
        let _first_inbox = mux.register(first_id).unwrap();
        let second_inbox = mux.register(second_id).unwrap();
        let address = "127.0.0.1:1".parse().unwrap();
        let first = Arc::new(LoopbackPeerConnection::new(address, None));
        let second = Arc::new(LoopbackPeerConnection::new(address, None));
        let first_peer = Arc::clone(&first) as Arc<dyn PeerConnection>;
        let second_peer = Arc::clone(&second) as Arc<dyn PeerConnection>;
        let first_hello_frame = frame(
            first_id,
            ExecutionMessageKind::Control,
            EXECUTION_CLIENT_ROUTE_HELLO_V1,
        );
        let second_hello_frame = frame(
            second_id,
            ExecutionMessageKind::Control,
            EXECUTION_CLIENT_ROUTE_HELLO_V1,
        );
        let first_hello = ExecutionEnvelopeV1::decode(&first_hello_frame).unwrap();
        let second_hello = ExecutionEnvelopeV1::decode(&second_hello_frame).unwrap();

        assert_eq!(
            mux.authorize_client_route_if_registered(&first_hello, 0, &first_peer),
            Ok(Some(0))
        );
        assert!(matches!(
            mux.authorize_client_route_if_registered(&first_hello, 0, &second_peer),
            Err(ExecutionTransportError::ClientRouteConflict { .. })
        ));
        assert_eq!(
            mux.authorize_client_route_if_registered(&second_hello, 0, &second_peer),
            Ok(Some(0))
        );
        let first_network = ExecutionScopedNetwork::for_party(QuicNetworkManager::new(), first_id)
            .unwrap()
            .with_reply_mux(mux.clone());
        let second_network =
            ExecutionScopedNetwork::for_party(QuicNetworkManager::new(), second_id)
                .unwrap()
                .with_reply_mux(mux.clone());
        first_network.send_to_client(0, b"first").await.unwrap();
        second_network.send_to_client(0, b"second").await.unwrap();

        assert_eq!(
            first.receive().await.unwrap(),
            frame(first_id, ExecutionMessageKind::Mpc, b"first")
        );
        assert_eq!(
            second.receive().await.unwrap(),
            frame(second_id, ExecutionMessageKind::Mpc, b"second")
        );
        assert!(mux.unregister(first_id));
        assert!(matches!(
            first_network.send_to_client(0, b"stale").await,
            Err(NetworkError::ClientNotFound(0))
        ));
        drop(second_inbox);
    }

    #[tokio::test]
    async fn authenticated_context_selects_the_only_valid_inbox() {
        let party_mux = ExecutionTransportMux::new(4).unwrap();
        let mut party_inbox = party_mux.register(execution(3)).unwrap();
        let party_frame = frame(execution(3), ExecutionMessageKind::Mpc, b"party");
        party_mux.route_party_frame(1, &party_frame).unwrap();
        assert_eq!(party_inbox.party.recv().await.unwrap().payload, b"party");

        let client_mux = ExecutionTransportMux::new_client(4).unwrap();
        let mut client_inbox = client_mux.register(execution(4)).unwrap();
        let client_frame = frame(execution(4), ExecutionMessageKind::Mpc, b"client");
        client_mux.route_party_frame(1, &client_frame).unwrap();
        assert_eq!(client_inbox.client.recv().await.unwrap().payload, b"client");

        let envelope = ExecutionEnvelopeV1::decode(&client_frame).unwrap();
        let error = client_mux
            .route_envelope(
                ExecutionTransportSource::Client(1),
                ExecutionTransportSource::Client(1),
                envelope,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            ExecutionTransportError::ClientSourceOnClientEndpoint { .. }
        ));
    }

    #[tokio::test]
    async fn ingress_lease_releases_capacity_when_message_drops() {
        let limits = ExecutionIngressLimits {
            inbox_capacity: 2,
            execution_byte_capacity: 16,
            global_byte_capacity: 32,
        };
        let mux = ExecutionTransportMux::new_with_limits(limits).unwrap();
        let mut inbox = mux.register(execution(5)).unwrap();
        let message = frame(execution(5), ExecutionMessageKind::Mpc, b"12345678");

        mux.route_party_frame(1, &message).unwrap();
        assert_eq!(mux.ingress.queued_bytes(), 8);
        mux.route_party_frame(1, &message).unwrap();
        assert_eq!(mux.ingress.queued_bytes(), 16);
        assert!(matches!(
            mux.route_party_frame(1, &message),
            Err(ExecutionTransportError::InboxByteCapacityExceeded { .. })
        ));

        drop(inbox.party.recv().await.unwrap());
        drop(inbox.party.recv().await.unwrap());
        assert_eq!(mux.ingress.queued_bytes(), 0);
        mux.route_party_frame(1, &message).unwrap();
    }

    #[test]
    fn production_ingress_budget_supports_concurrent_execution_bursts() {
        let limits = ExecutionIngressLimits::production(4096);
        assert_eq!(
            limits.execution_byte_capacity,
            2 * MAX_EXECUTION_PAYLOAD_LEN
        );
        assert!(
            limits.global_byte_capacity >= 32 * limits.execution_byte_capacity,
            "the shared standing-node mux must not retire a healthy execution during a modest cross-execution burst"
        );
    }

    #[tokio::test]
    async fn transient_ingress_pressure_backpressures_without_retiring_the_execution() {
        let limits = ExecutionIngressLimits {
            inbox_capacity: 1,
            execution_byte_capacity: 16,
            global_byte_capacity: 32,
        };
        let mux = ExecutionTransportMux::new_with_limits(limits).unwrap();
        let mut bursty = mux.register(execution(5)).unwrap();
        let mut healthy = mux.register(execution(6)).unwrap();
        mux.route_party_frame(1, &frame(execution(5), ExecutionMessageKind::Mpc, b"first"))
            .unwrap();

        let retry_mux = mux.clone();
        let cancel = CancellationToken::new();
        let retry_cancel = cancel.clone();
        let retry = tokio::spawn(async move {
            let encoded = frame(execution(5), ExecutionMessageKind::Mpc, b"second");
            let envelope = ExecutionEnvelopeV1::decode(&encoded).unwrap();
            retry_mux
                .route_envelope_with_backpressure(
                    ExecutionTransportSource::Party(1),
                    ExecutionTransportSource::Party(1),
                    envelope,
                    &retry_cancel,
                )
                .await
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!retry.is_finished());
        assert_eq!(bursty.party.recv().await.unwrap().payload, b"first");
        tokio::time::timeout(Duration::from_secs(1), retry)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(bursty.party.recv().await.unwrap().payload, b"second");
        assert!(mux.entries.read().contains_key(&execution(5)));

        mux.route_party_frame(
            1,
            &frame(execution(6), ExecutionMessageKind::Mpc, b"sibling"),
        )
        .unwrap();
        assert_eq!(healthy.party.recv().await.unwrap().payload, b"sibling");
    }

    #[test]
    fn registration_is_unique_and_unknown_frames_are_dropped() {
        let mux = ExecutionTransportMux::new(4).unwrap();
        let _inbox = mux.register(execution(6)).unwrap();
        assert!(matches!(
            mux.register(execution(6)),
            Err(ExecutionTransportError::DuplicateExecution(id)) if id == execution(6)
        ));
        mux.route_party_frame(
            1,
            &frame(execution(7), ExecutionMessageKind::Mpc, b"unknown"),
        )
        .unwrap();
        assert!(mux.unregister(execution(6)));
        assert!(!mux.entries.read().contains_key(&execution(6)));
    }
}
