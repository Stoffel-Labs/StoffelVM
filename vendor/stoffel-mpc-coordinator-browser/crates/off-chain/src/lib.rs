pub mod browser_rpc;
pub mod tests;

use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use async_trait::async_trait;
use hpke::{
    aead::AesGcm256,
    kdf::HkdfSha256,
    kem::{DhP256HkdfSha256, Kem},
    single_shot_open, single_shot_seal, Deserializable, OpModeR, OpModeS, Serializable,
};
use jsonrpsee::async_client::Client;
use jsonrpsee::server::RpcModule;
use jsonrpsee::types::{error::ErrorCode, ErrorObjectOwned};
use jsonrpsee::{
    core::{to_json_raw_value, RpcResult, SubscriptionResult},
    proc_macros::rpc,
    PendingSubscriptionSink, SubscriptionSink,
};
use p256::{pkcs8::DecodePrivateKey, SecretKey};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use stoffel_mpc_coordinator_shared::{
    round_before, round_index, rpc::RPCServerHandle, Coordinator, CoordinatorError, ExecutionId,
    Round, ShareBound,
};
use tokio::sync::{oneshot, MappedMutexGuard, Mutex, MutexGuard};
use CoordinatorRPCBaseError::*;

/// KEM, KDF, and AEAD instantiations are needed to encrypt the output shares for an MPC client
/// before sending them to the coordinator.
type KemImpl = DhP256HkdfSha256;
type KdfImpl = HkdfSha256;
type AeadImpl = AesGcm256;

/// An MPC client interacts with two types of entities: the coordinator and nodes.
/// Towards the nodes, the MPC client uses a public key (currently ECDSA).
/// Towards the coordinator, it uses either an Ethereum address (on-chain) or the same public key as for the nodes (off-chain).
///
/// In the on-chain case we make clients sign a nonce with the Ethereum address,
/// which is sent to the nodes through a TLS channel that authenticates the client as
/// the owner of the public key, so the node can deduce that the public key and the
/// owner of the Ethereum address are the same and the node can safely send its mask share to the client.
///
/// In the off-chain case, no signature is needed, since the identities towards coordinator and nodes
/// must simply be the same: if a client requests a mask share from a node for a previously reserved
/// mask index, then the node simply checks that the public keys used for both these actions are the same.
pub type ClientIdentity = Vec<u8>;

/// A deliberately small, explicit bound for the number of live executions owned by one RPC
/// listener. Finished executions must be retired before this many more are registered.
pub const DEFAULT_MAX_CONCURRENT_EXECUTIONS: usize = 1024;
const SUBSCRIPTION_SEND_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a one-off coordinator waits for parties to acknowledge the terminal round after the
/// designated party requests shutdown. Unanimous acknowledgement closes immediately; the bound
/// preserves liveness when a faulty party never acknowledges.
pub const DEFAULT_ONE_OFF_SHUTDOWN_GRACE: Duration = Duration::from_secs(30);
const ONE_OFF_RETIREMENT_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug)]
pub struct OneOffShutdownConfig {
    pub execution_id: ExecutionId,
    pub grace: Duration,
}

/// How many sealed-but-not-unanimously-acknowledged executions are remembered. A sealed
/// execution holds no protocol state, so this only has to be large enough that a slow but
/// honest party can still acknowledge its own executions after the quorum sealed them.
pub const DEFAULT_MAX_RETIRED_EXECUTIONS: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssignedMaskReservation {
    pub client: ClientIdentity,
    pub reserved_index: u64,
    pub input_ordinal: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssignedMaskedInputEvent {
    pub client: ClientIdentity,
    pub reserved_index: u64,
    pub input_ordinal: u64,
    pub masked_input: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssignedMaskShare {
    pub reserved_index: u64,
    pub share_bytes: Vec<u8>,
}

/// One global input slot, expanded from an `InputClientRange`. Not sent over the wire — see
/// `InputAssignment` for why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputSlotAssignment {
    /// Index into the owning `InputAssignment::clients`.
    pub client_index: u32,
    pub label: u64,
}

/// One client's contiguous block of global input slots. A client's own inputs are always
/// numbered `0..count` (see every `InputAssignment` producer), so the wire format only needs
/// one entry per *client* rather than one per *input*: `register_execution`'s global slot index
/// `i` falls in the range starting at the sum of every earlier range's `count`, with per-client
/// label `i - that_start`. Expanded into one `InputSlotAssignment` per slot on receipt (see
/// `CoordinatorExecutionState::new`) — that expansion only costs memory, not JSON bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputClientRange {
    /// Index into the owning `InputAssignment::clients`.
    pub client_index: u32,
    /// Number of contiguous global input slots this client owns.
    pub count: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputAssignment {
    /// Every client referenced by `ranges`, indexed by `InputClientRange::client_index`.
    pub clients: Vec<ClientIdentity>,
    /// One entry per client with at least one input, in global-slot order. Deliberately not one
    /// entry per input slot — with a wide client roster and many inputs per client (e.g. a
    /// federated-learning model vector), a flat per-slot list turns `register_execution`'s
    /// payload into `O(n_inputs)` JSON entries instead of `O(clients.len())`, which is enough on
    /// its own to blow past jsonrpsee's request-size cap even with no duplicated data.
    pub ranges: Vec<InputClientRange>,
}

/// Immutable data that binds one invocation to its program and client I/O layout.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRegistration {
    pub execution_id: ExecutionId,
    pub program_hash: [u8; 32],
    pub n_inputs: u64,
    pub output_clients: Vec<ClientIdentity>,
    pub input_assignment: InputAssignment,
    /// Number of independently encrypted node shares required before an output client is notified.
    pub min_output_shares: u64,
}

/// The node-side RPC interface.
pub mod node_rpc {
    use super::{AssignedMaskReservation, AssignedMaskShare, ClientIdentity};
    use ark_ff::FftField;
    use ark_serialize::CanonicalSerialize;
    use async_trait::async_trait;
    use jsonrpsee::{
        async_client::Client,
        core::{to_json_raw_value, JsonRawValue, SubscriptionResult},
        proc_macros::rpc,
        server::RpcModule,
        types::{error::ErrorCode, ErrorObjectOwned},
        PendingSubscriptionSink, SubscriptionSink,
    };
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::marker::PhantomData;
    use std::sync::Arc;
    use stoffel_mpc_coordinator_shared::{
        rpc::RPCServerHandle, CoordinatorError, ExecutionId, NodeRPCError, ShareBound,
    };
    use tokio::sync::Mutex;
    use tokio::task::JoinSet;

    /// Errors returned by the node-side RPC interface.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum OffChainNodeRPCServerError {
        SerializationError = 1,
        ExecutionNotFound = 2,
    }

    /// The off-chain node-side JSON-RPC interface.
    #[rpc(server, client)]
    pub trait OffChainNodeRPC {
        #[subscription(name = "sub_receive_assigned_mask_shares", unsubscribe = "unsub_receive_assigned_mask_shares", item = Vec<AssignedMaskShare>)]
        async fn receive_assigned_mask_shares(
            &self,
            execution_id: ExecutionId,
            start: u64,
            count: u64,
        ) -> SubscriptionResult;
    }

    pub struct NodeRPCServer {
        rpc_server: Arc<Mutex<NodeRPCServerInternal>>,
        addr: String,
        server_handle: RPCServerHandle,
        browser_handle: Option<jsonrpsee::server::ServerHandle>,
    }

    /// An object used by an MPC client to connect to the RPC interfaces of many nodes.
    pub struct NodeRPCClient<F: FftField, S: ShareBound<F>> {
        /// The per-node client handles for each connection to a node.
        node_rpcs: Vec<Client>,
        /// Total number of MPC nodes in the network (used for share reconstruction).
        n: usize,
        /// The threshold value.
        t: usize,
        /// The program invocation to which all RPC calls made by this handle belong.
        execution_id: ExecutionId,
        _phantom: PhantomData<(F, S)>,
    }

    impl<F: FftField, S: ShareBound<F>> NodeRPCClient<F, S> {
        pub async fn start_rpc_client_for_execution(
            n: usize,
            t: usize,
            addrs: Vec<(String, u16)>,
            execution_id: ExecutionId,
            cert_der: Vec<u8>,
            key_der: Vec<u8>,
        ) -> Result<Self, CoordinatorError> {
            let node_rpcs: Vec<Client> =
                futures_util::future::join_all(addrs.iter().map(|(addr, port)| {
                    stoffel_mpc_coordinator_shared::self_signed_certs::setup_client(
                        addr,
                        *port,
                        cert_der.clone(),
                        key_der.clone(),
                    )
                }))
                .await
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?;

            Ok(Self {
                node_rpcs,
                n,
                t,
                execution_id,
                _phantom: PhantomData,
            })
        }

        pub async fn receive_assigned_masks(
            &self,
            start: u64,
            count: u64,
        ) -> Result<Vec<S::ValueType>, CoordinatorError> {
            let end = start.checked_add(count).ok_or_else(|| {
                CoordinatorError::JSONError("Assigned mask range overflows u64".to_string())
            })?;
            if count == 0 {
                return Ok(Vec::new());
            }
            let mut share_futures = JoinSet::new();

            for rpc in self.node_rpcs.iter() {
                let mut sub = rpc
                    .receive_assigned_mask_shares(self.execution_id, start, count)
                    .await
                    .map_err(|e| CoordinatorError::SubscriptionError(e.to_string()))?;
                share_futures.spawn(async move { sub.next().await });
            }

            let mut share_sets: HashMap<u64, Vec<S>> = HashMap::new();
            let expected_indices = (start..end).collect::<Vec<_>>();

            while let Some(share_result) = share_futures.join_next().await {
                let assigned_shares_option =
                    share_result.map_err(|e| CoordinatorError::SubscriptionError(e.to_string()))?;
                let assigned_shares = match assigned_shares_option {
                    Some(res) => {
                        res.map_err(|e| CoordinatorError::SubscriptionError(e.to_string()))?
                    }
                    None => continue,
                };

                let mut indices = assigned_shares
                    .iter()
                    .map(|assigned_share| assigned_share.reserved_index)
                    .collect::<Vec<_>>();
                indices.sort_unstable();
                if expected_indices != indices {
                    return Err(CoordinatorError::JSONError(
                        "MPC node returned the wrong assigned mask share range".to_string(),
                    ));
                }

                for assigned_share in assigned_shares {
                    let share: S = ark_serialize::CanonicalDeserialize::deserialize_compressed(
                        assigned_share.share_bytes.as_slice(),
                    )
                    .map_err(|_| CoordinatorError::DeserializationError)?;

                    share_sets
                        .entry(assigned_share.reserved_index)
                        .or_default()
                        .push(share);
                }

                if expected_indices.iter().all(|reserved_index| {
                    share_sets
                        .get(reserved_index)
                        .is_some_and(|shares| shares.len() >= S::min_shares(self.t))
                }) {
                    break;
                }
            }

            let mut outputs = Vec::with_capacity(share_sets.len());
            for reserved_index in expected_indices {
                let Some(mask_shares) = share_sets.remove(&reserved_index) else {
                    return Err(CoordinatorError::MaskReconstructionFailed(0));
                };
                if mask_shares.len() < S::min_shares(self.t) {
                    return Err(CoordinatorError::MaskReconstructionFailed(
                        mask_shares.len(),
                    ));
                }
                let (_, mask) = S::recover_secret(&mask_shares, self.n, self.t)
                    .map_err(|_| CoordinatorError::MaskReconstructionFailed(mask_shares.len()))?;
                outputs.push(mask);
            }

            Ok(outputs)
        }
    }

    impl NodeRPCServer {
        pub async fn start(
            addr: &str,
            port: u16,
            cert_der: Vec<u8>,
            key_der: Vec<u8>,
        ) -> Result<Self, CoordinatorError> {
            let rpc_server_data = Arc::new(Mutex::new(NodeRPCServerInternal::new()));
            let server_handle =
                stoffel_mpc_coordinator_shared::rpc::start_coord::<NodeRPCServerImpl>(
                    addr,
                    port,
                    cert_der,
                    key_der,
                    rpc_server_data.clone(),
                )
                .await?;
            let server = Self {
                rpc_server: rpc_server_data,
                addr: String::from(addr),
                server_handle,
                browser_handle: None,
            };
            match std::env::var("STOFFEL_BROWSER_NODE_RPC_BIND") {
                Ok(bind) if !bind.trim().is_empty() => server.with_browser_rpc(&bind).await,
                _ => Ok(server),
            }
        }

        pub async fn start_for_execution(
            addr: &str,
            port: u16,
            execution_id: ExecutionId,
            cert_der: Vec<u8>,
            key_der: Vec<u8>,
        ) -> Result<Self, CoordinatorError> {
            let server = Self::start(addr, port, cert_der, key_der).await?;
            server.register_execution(execution_id).await?;
            Ok(server)
        }

        pub fn get_addr(&self) -> String {
            self.addr.clone()
        }

        pub async fn shutdown(self) {
            if let Some(handle) = self.browser_handle {
                let _ = handle.stop();
                handle.stopped().await;
            }
            self.server_handle.shutdown().await;
        }

        /// Add a signed browser JSON-RPC listener sharing this node's execution state.
        pub async fn with_browser_rpc(mut self, bind: &str) -> Result<Self, CoordinatorError> {
            self.browser_handle = Some(
                crate::browser_rpc::start_node_browser_rpc(bind, self.rpc_server.clone()).await?,
            );
            Ok(self)
        }

        /// Registers a program invocation on this long-running listener.
        pub async fn register_execution(
            &self,
            execution_id: ExecutionId,
        ) -> Result<(), CoordinatorError> {
            self.rpc_server
                .lock()
                .await
                .register_execution(execution_id)
        }

        /// Stops admitting new RPCs for an invocation and drops all of its node-side state.
        pub async fn retire_execution(&self, execution_id: ExecutionId) -> bool {
            self.rpc_server.lock().await.retire_execution(execution_id)
        }

        async fn execution_state(
            &self,
            execution_id: ExecutionId,
        ) -> Result<Arc<Mutex<NodeRPCExecutionState>>, NodeRPCError> {
            self.rpc_server
                .lock()
                .await
                .execution_state(execution_id)
                .ok_or(NodeRPCError::ExecutionNotFound)
        }

        pub async fn add_assigned_reserved_index_for_execution(
            &self,
            execution_id: ExecutionId,
            reservation: AssignedMaskReservation,
        ) -> Result<(), NodeRPCError> {
            self.add_assigned_reserved_indices_for_execution(execution_id, vec![reservation])
                .await
        }

        /// Batch form of `add_assigned_reserved_index_for_execution`: registers every
        /// reservation in `reservations` in one call, instead of the caller looping and
        /// re-acquiring this execution's state lock once per index. This is what a node process
        /// should call when it receives a batched `sub_reserved_indices`/
        /// `sub_assigned_reserved_indices` event covering several indices at once.
        pub async fn add_assigned_reserved_indices_for_execution(
            &self,
            execution_id: ExecutionId,
            reservations: Vec<AssignedMaskReservation>,
        ) -> Result<(), NodeRPCError> {
            let d = self.execution_state(execution_id).await?;
            let mut pending_sends: Vec<(SubscriptionSink, Box<JsonRawValue>)> = Vec::new();
            {
                let mut d = d.lock().await;

                for reservation in &reservations {
                    if d.index_to_client.contains_key(&reservation.reserved_index) {
                        return Err(NodeRPCError::IndexAlreadyAdded);
                    }
                }

                // Phase 1: register every reservation in the batch before checking any pending
                // range request below. A range request only completes once every index in its
                // range has both a reservation and a share, so checking it once per registration
                // in this batch (instead of once after all of them land) can only produce the
                // same answer more slowly.
                let mut touched_clients: Vec<ClientIdentity> = Vec::new();
                for reservation in &reservations {
                    let id = reservation.client.clone();
                    let i = reservation.reserved_index;

                    d.index_to_client.insert(i, id.clone());
                    d.assigned_reservations.insert(i, reservation.clone());
                    if !touched_clients.contains(&id) {
                        touched_clients.push(id);
                    }
                }

                // Phase 2: now that the batch's indices are all registered, check once per
                // affected client whether its pending range request can be satisfied.
                for id in touched_clients {
                    if let Some(request) = d.assigned_sinks.remove(&id) {
                        match d.assigned_mask_shares_for_client(
                            &id,
                            request.start,
                            request.count,
                        )? {
                            Some(assigned_shares) => {
                                let json = to_json_raw_value(&assigned_shares)
                                    .map_err(|_| NodeRPCError::SerializationError)?;
                                pending_sends.push((request.sink, json));
                            }
                            None => {
                                d.assigned_sinks.insert(id, request);
                            }
                        }
                    }
                }
            }

            for (sink, json) in pending_sends {
                let _ = sink.send(json).await;
            }

            Ok(())
        }

        pub async fn add_reserved_index_for_execution(
            &self,
            execution_id: ExecutionId,
            client: ClientIdentity,
            reserved_index: u64,
        ) -> Result<(), NodeRPCError> {
            self.add_reserved_indices_for_execution(execution_id, client, vec![reserved_index])
                .await
        }

        /// Batch form of `add_reserved_index_for_execution`: registers every index in `indices`
        /// for `client` from a single (now-vectorized) `ReservedInputEvent`, instead of the
        /// caller looping and re-acquiring this execution's state lock once per index.
        pub async fn add_reserved_indices_for_execution(
            &self,
            execution_id: ExecutionId,
            client: ClientIdentity,
            indices: Vec<u64>,
        ) -> Result<(), NodeRPCError> {
            self.add_assigned_reserved_indices_for_execution(
                execution_id,
                indices
                    .into_iter()
                    .map(|i| AssignedMaskReservation {
                        client: client.clone(),
                        reserved_index: i,
                        input_ordinal: i,
                    })
                    .collect(),
            )
            .await
        }

        pub async fn add_mask_share_for_execution<S: CanonicalSerialize>(
            &self,
            execution_id: ExecutionId,
            i: u64,
            share: &S,
        ) -> Result<(), NodeRPCError> {
            self.add_mask_shares_for_execution(execution_id, &[(i, share)])
                .await
        }

        /// Batch form of `add_mask_share_for_execution`: registers every `(index, share)` pair
        /// in `shares` while holding this execution's state lock only once, instead of the
        /// caller looping and re-acquiring the lock (and re-checking every affected client's
        /// pending range request) once per index.
        pub async fn add_mask_shares_for_execution<S: CanonicalSerialize>(
            &self,
            execution_id: ExecutionId,
            shares: &[(u64, &S)],
        ) -> Result<(), NodeRPCError> {
            let d = self.execution_state(execution_id).await?;
            let mut pending_sends: Vec<(SubscriptionSink, Box<JsonRawValue>)> = Vec::new();
            {
                let mut d = d.lock().await;

                for (i, _) in shares {
                    if d.mask_shares.contains_key(i) {
                        return Err(NodeRPCError::IndexAlreadyAdded);
                    }
                }

                // Phase 1: record every share in the batch before checking any pending range
                // request below, for the same reason `add_assigned_reserved_indices_for_execution`
                // does: a range request only completes once every index in its range has both a
                // reservation and a share, so checking it once per client touched by this batch
                // (instead of once per index) can only produce the same answer more slowly.
                let mut touched_clients: Vec<ClientIdentity> = Vec::new();
                for (i, share) in shares {
                    let mut share_bytes = Vec::new();
                    share
                        .serialize_compressed(&mut share_bytes)
                        .map_err(|_| NodeRPCError::SerializationError)?;
                    d.mask_shares.insert(*i, share_bytes);

                    if let Some(id) = d.index_to_client.get(i).cloned() {
                        if !touched_clients.contains(&id) {
                            touched_clients.push(id);
                        }
                    }
                }

                // Phase 2: now that the batch's shares are all recorded, check once per affected
                // client whether its pending range request can be satisfied.
                for id in touched_clients {
                    if let Some(request) = d.assigned_sinks.remove(&id) {
                        match d.assigned_mask_shares_for_client(
                            &id,
                            request.start,
                            request.count,
                        )? {
                            Some(assigned_shares) => {
                                let json = to_json_raw_value(&assigned_shares)
                                    .map_err(|_| NodeRPCError::SerializationError)?;
                                pending_sends.push((request.sink, json));
                            }
                            None => {
                                d.assigned_sinks.insert(id, request);
                            }
                        }
                    }
                }
            }

            for (sink, json) in pending_sends {
                let _ = sink.send(json).await;
            }

            Ok(())
        }
    }

    /// The server-side information for one client connection to the node-side RPC interface.
    pub struct NodeRPCServerImpl {
        /// A reference to the server's shared state.
        d: Arc<Mutex<NodeRPCServerInternal>>,
        /// The connected client's identity, which is the client's public key in DER format.
        id: Vec<u8>,
    }

    impl NodeRPCServerImpl {
        async fn execution_state(
            &self,
            execution_id: ExecutionId,
        ) -> Option<Arc<Mutex<NodeRPCExecutionState>>> {
            self.d.lock().await.execution_state(execution_id)
        }
    }

    impl stoffel_mpc_coordinator_shared::rpc::RPCServerConnection for NodeRPCServerImpl {
        type Internal = NodeRPCServerInternal;

        fn new(internal: Arc<Mutex<Self::Internal>>, id: Vec<u8>) -> Self {
            Self { d: internal, id }
        }

        fn into_rpc(self) -> RpcModule<Self>
        where
            Self: Sized,
        {
            crate::node_rpc::OffChainNodeRPCServer::into_rpc(self)
        }
    }

    /// The internal state of the node-side RPC server.
    pub struct NodeRPCServerInternal {
        executions: HashMap<ExecutionId, Arc<Mutex<NodeRPCExecutionState>>>,
    }

    /// State that must never be shared between two program invocations.
    pub(crate) struct NodeRPCExecutionState {
        /// Maps reserved indices to the clients that have reserved them.
        index_to_client: HashMap<u64, ClientIdentity>,
        assigned_reservations: HashMap<u64, AssignedMaskReservation>,
        assigned_sinks: HashMap<ClientIdentity, AssignedMaskRequest>,
        /// Preprocessed mask shares, indexed only within this execution.
        mask_shares: HashMap<u64, Vec<u8>>,
    }

    struct AssignedMaskRequest {
        start: u64,
        count: u64,
        sink: SubscriptionSink,
    }

    impl NodeRPCServerInternal {
        fn new() -> Self {
            Self {
                executions: HashMap::new(),
            }
        }

        fn register_execution(
            &mut self,
            execution_id: ExecutionId,
        ) -> Result<(), CoordinatorError> {
            if execution_id.is_zero() {
                return Err(CoordinatorError::JSONError(
                    "zero execution IDs are not valid for persistent RPC listeners".to_string(),
                ));
            }
            if self.executions.contains_key(&execution_id) {
                return Err(CoordinatorError::JSONError(format!(
                    "Execution {execution_id} is already registered"
                )));
            }
            if self.executions.len() >= super::DEFAULT_MAX_CONCURRENT_EXECUTIONS {
                return Err(CoordinatorError::JSONError(format!(
                    "Execution capacity {} reached",
                    super::DEFAULT_MAX_CONCURRENT_EXECUTIONS
                )));
            }
            self.executions.insert(
                execution_id,
                Arc::new(Mutex::new(NodeRPCExecutionState::new())),
            );
            Ok(())
        }

        fn retire_execution(&mut self, execution_id: ExecutionId) -> bool {
            self.executions.remove(&execution_id).is_some()
        }

        pub(crate) fn execution_state(
            &self,
            execution_id: ExecutionId,
        ) -> Option<Arc<Mutex<NodeRPCExecutionState>>> {
            self.executions.get(&execution_id).cloned()
        }
    }

    impl NodeRPCExecutionState {
        fn new() -> Self {
            Self {
                index_to_client: HashMap::new(),
                assigned_reservations: HashMap::new(),
                assigned_sinks: HashMap::new(),
                mask_shares: HashMap::new(),
            }
        }
    }

    impl NodeRPCExecutionState {
        fn assigned_mask_share(
            &self,
            reserved_index: u64,
            share_bytes: &[u8],
        ) -> Result<AssignedMaskShare, NodeRPCError> {
            self.assigned_reservations
                .get(&reserved_index)
                .ok_or(NodeRPCError::IndexNotAdded)?;
            Ok(AssignedMaskShare {
                reserved_index,
                share_bytes: share_bytes.to_vec(),
            })
        }

        pub(crate) fn assigned_mask_shares_for_client(
            &self,
            id: &ClientIdentity,
            start: u64,
            count: u64,
        ) -> Result<Option<Vec<AssignedMaskShare>>, NodeRPCError> {
            let end = start
                .checked_add(count)
                .ok_or(NodeRPCError::IndexNotAdded)?;
            let mut assigned_shares = Vec::new();
            for i in start..end {
                let Some(client) = self.index_to_client.get(&i) else {
                    return Ok(None);
                };
                if client != id {
                    return Err(NodeRPCError::AuthenticationFailed(id.clone()));
                }
                let Some(share) = self.mask_shares.get(&i) else {
                    return Ok(None);
                };
                assigned_shares.push(self.assigned_mask_share(i, share)?);
            }

            Ok(Some(assigned_shares))
        }
    }

    #[async_trait]
    impl OffChainNodeRPCServer for NodeRPCServerImpl {
        async fn receive_assigned_mask_shares(
            &self,
            pending: PendingSubscriptionSink,
            execution_id: ExecutionId,
            start: u64,
            count: u64,
        ) -> SubscriptionResult {
            use OffChainNodeRPCServerError::*;

            let Some(d) = self.execution_state(execution_id).await else {
                pending
                    .reject(ErrorObjectOwned::owned(
                        ErrorCode::ServerError(ExecutionNotFound as i32).code(),
                        format!("Execution {execution_id} is not registered"),
                        None::<()>,
                    ))
                    .await;
                return Ok(());
            };
            let mut d = d.lock().await;

            // A new subscription from the same client supersedes any previous one still
            // pending: the client only ever moves on to the next input after it has consumed
            // (or given up on) the last one, so a still-registered sink at this point is stale
            // rather than a genuine conflict (e.g. the client returned early once threshold
            // shares from other nodes arrived and abandoned this node's still-outstanding
            // subscription without waiting for the unsubscribe to be processed here first).
            d.assigned_sinks.remove(&self.id);

            let assigned_shares = match d.assigned_mask_shares_for_client(&self.id, start, count) {
                Ok(assigned_shares) => assigned_shares,
                Err(e) => {
                    pending
                        .reject(ErrorObjectOwned::owned(
                            ErrorCode::ServerError(SerializationError as i32).code(),
                            format!("Serializing assigned shares failed: {e}"),
                            None::<()>,
                        ))
                        .await;
                    return Ok(());
                }
            };

            if let Some(assigned_shares) = assigned_shares {
                let json = match to_json_raw_value(&assigned_shares) {
                    Ok(j) => j,
                    Err(e) => {
                        pending
                            .reject(ErrorObjectOwned::owned(
                                ErrorCode::ServerError(SerializationError as i32).code(),
                                format!("Converting assigned shares to JSON failed: {e}"),
                                None::<()>,
                            ))
                            .await;
                        return Ok(());
                    }
                };

                let sink = pending.accept().await?;
                sink.send(json).await?;

                return Ok(());
            }

            let sink = pending.accept().await?;
            d.assigned_sinks
                .insert(self.id.clone(), AssignedMaskRequest { start, count, sink });

            Ok(())
        }
    }
}

/// Events that mimic those used for the on-chain coordinator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    CoordinatorInitialized {
        creation_block: u64,
        designated_party: ClientIdentity,
    },
    /// Carries every (index, masked input) pair submitted by one `submit_masked_input`/
    /// `submit_masked_inputs` call, so a batch submission only needs one event on the wire
    /// instead of one per index.
    MaskedInputEvent {
        client: ClientIdentity,
        masked_inputs: Vec<(u64, Vec<u8>)>,
    },
    IndexBufferEvent {
        total_indices: u64,
        designated_party: ClientIdentity,
    },
    /// Carries every index reserved by one `reserve_mask_index`/`reserve_mask_indices` call, so a
    /// batch reservation only needs one event on the wire instead of one per index.
    ReservedInputEvent {
        client: ClientIdentity,
        reserved_indices: Vec<u64>,
    },
    PreprocessingStarted {
        designated_party: ClientIdentity,
    },
    InputCollectionStarted,
    InputMaskReservationStarted,
    MPCStarted,
    ExecutionDone,
    OutputSendingStarted,
    OutputsPublished,
    ClientInputMaskReservationEvent,
    ClientOutputCollection,
    PreprocessingRoundExecuted,
}

/// RPC interface implemented by the developer.
#[rpc(server, client)]
pub trait StoffelCoordinatorRPC {
    #[method(name = "start_preprocessing")]
    async fn start_preprocessing(&self, execution_id: ExecutionId) -> RpcResult<()>;
    #[method(name = "reserve_input_masks")]
    async fn reserve_input_masks(&self, execution_id: ExecutionId) -> RpcResult<()>;
    #[method(name = "collect_inputs")]
    async fn collect_inputs(&self, execution_id: ExecutionId) -> RpcResult<()>;
    #[method(name = "start_mpc")]
    async fn start_mpc(&self, execution_id: ExecutionId) -> RpcResult<()>;
    #[method(name = "send_output")]
    async fn send_output(&self, execution_id: ExecutionId) -> RpcResult<()>;
    #[method(name = "finalize")]
    async fn finalize(&self, execution_id: ExecutionId) -> RpcResult<()>;
}

// RPC interface already implemented by this library.
#[rpc(server, client)]
pub trait CoordinatorRPCBase {
    #[method(name = "register_execution")]
    async fn register_execution(&self, registration: ExecutionRegistration) -> RpcResult<()>;

    #[method(name = "retire_execution")]
    async fn retire_execution(&self, execution_id: ExecutionId) -> RpcResult<()>;

    /// Explicitly asks the coordinator (as a whole — this is not scoped to any one execution)
    /// to shut down. Only the designated party may call this, and only once it has itself
    /// confirmed (e.g. via `sub_round`/`wait_for_round`) that the execution it cares about
    /// reached `Round::ProgramFinished` — the coordinator does not infer this from the round
    /// transition on its own, since that would race the response to whichever call caused the
    /// transition (see `transition`). One-off coordinator invocations exit once this is called;
    /// standing coordinators reject it.
    #[method(name = "request_shutdown")]
    async fn request_shutdown(&self) -> RpcResult<()>;

    /// Wait for round `round` to be started.
    #[subscription(name = "sub_round", unsubscribe = "unsub_round", item = Event)]
    async fn sub_round(&self, execution_id: ExecutionId, round: Round) -> SubscriptionResult;

    #[subscription(name = "sub_reserved_indices", unsubscribe = "unsub_reserved_indices", item = Event)]
    async fn sub_reserved_indices(&self, execution_id: ExecutionId) -> SubscriptionResult;

    #[subscription(name = "sub_masked_inputs", unsubscribe = "unsub_masked_inputs", item = Event)]
    async fn sub_masked_inputs(&self, execution_id: ExecutionId) -> SubscriptionResult;

    /// Pushes every `AssignedMaskReservation` from one `reserve_mask_index`/`reserve_mask_indices`
    /// call as a single batch, mirroring `receive_assigned_mask_shares`'s `Vec<AssignedMaskShare>`
    /// item -- one message per reservation batch instead of one per index.
    #[subscription(name = "sub_assigned_reserved_indices", unsubscribe = "unsub_assigned_reserved_indices", item = Vec<AssignedMaskReservation>)]
    async fn sub_assigned_reserved_indices(&self, execution_id: ExecutionId) -> SubscriptionResult;

    /// Pushes every `AssignedMaskedInputEvent` from one `submit_masked_input`/
    /// `submit_masked_inputs` call as a single batch, mirroring
    /// `sub_assigned_reserved_indices`'s `Vec<AssignedMaskReservation>` item -- one message per
    /// submission batch instead of one per index.
    #[subscription(name = "sub_assigned_masked_inputs", unsubscribe = "unsub_assigned_masked_inputs", item = Vec<AssignedMaskedInputEvent>)]
    async fn sub_assigned_masked_inputs(&self, execution_id: ExecutionId) -> SubscriptionResult;

    /// Returns the number of available input masks left. TODO: this involves a race condition
    /// since querying this and reserving an index is not atomic. remove it?
    #[method(name = "available_input_masks")]
    async fn available_input_masks(&self, execution_id: ExecutionId) -> RpcResult<u64>;

    /// MPC clients can request index `i`.
    #[method(name = "reserve_mask_index")]
    async fn reserve_mask_index(&self, execution_id: ExecutionId, i: u64) -> RpcResult<()>;

    /// Batch form of `reserve_mask_index`: reserves every index in `indices` in one round trip,
    /// atomically (either all of them are reserved, or an error is returned and none are).
    /// Clients with many inputs should use this instead of calling `reserve_mask_index` in a
    /// loop -- one round trip per input is what makes large client counts blow past the RPC
    /// client's request timeout under load.
    #[method(name = "reserve_mask_indices")]
    async fn reserve_mask_indices(
        &self,
        execution_id: ExecutionId,
        indices: Vec<u64>,
    ) -> RpcResult<()>;

    /// An MPC client uses this to submit a masked input `masked_input`, for which it has
    /// previously reserved the index `reserved_index`.
    #[method(name = "submit_masked_input")]
    async fn submit_masked_input(
        &self,
        execution_id: ExecutionId,
        masked_input: Vec<u8>,
        reserved_index: u64,
    ) -> RpcResult<()>;

    /// Batch form of `submit_masked_input`: submits every (index, masked input) pair in
    /// `reserved_indices`/`masked_inputs` in one round trip, atomically (either all of them are
    /// recorded, or an error is returned and none are). Clients with many inputs should use this
    /// instead of calling `submit_masked_input` in a loop -- one round trip per input is what
    /// makes large client counts blow past the RPC client's request timeout under load.
    #[method(name = "submit_masked_inputs")]
    async fn submit_masked_inputs(
        &self,
        execution_id: ExecutionId,
        masked_inputs: Vec<Vec<u8>>,
        reserved_indices: Vec<u64>,
    ) -> RpcResult<()>;

    /// The designated party uses this to transition to the new round `next_round`.
    #[method(name = "transition")]
    async fn transition(&self, execution_id: ExecutionId, next_round: Round) -> RpcResult<()>;

    /// MPC nodes use this to send encrypted output shares `enc_shares` for a client with identity
    /// `client_id`.
    #[method(name = "send_output_shares")]
    async fn send_output_shares(
        &self,
        execution_id: ExecutionId,
        client_id: ClientIdentity,
        enc_shares: (Vec<u8>, Vec<u8>),
    ) -> RpcResult<()>;

    /// MPC clients use this to receive their output shares from the coordinator, so they can
    /// reconstruct their private output.
    #[subscription(name = "sub_obtain_output_shares", unsubscribe = "unsub_obtain_output_shares", item = Vec<(Vec<u8>, Vec<u8>)>)]
    async fn obtain_output_shares(&self, execution_id: ExecutionId) -> SubscriptionResult;
}

/// Errors returned to RPC clients by the basic coordinator RPC interface.
pub enum CoordinatorRPCBaseError {
    NotDesignatedParty = 1,
    WrongRound = 2,
    IndexOutOfBounds = 3,
    BadID = 4,
    MaskedInputAlreadySubmitted = 5,
    IndexNotReserved = 6,
    IndexAlreadyReserved = 7,
    OutputSharesAlreadySent = 8,
    OutputSharesAlreadyRequested = 9,
    NotParty = 10,
    SendingFailed = 11,
    NotOutputClient = 12,
    MismatchedBatchLengths = 13,
    ClientAlreadyReserved = 14,
    UnauthorizedClientIo = 15,
    ExecutionNotFound = 16,
    ExecutionAlreadyRegistered = 17,
    ShutdownNotAccepted = 18,
    EmptyBatch = 19,
}

/// Every round except `Idle`, in protocol order.
const ORDERED_ROUNDS: [Round; 6] = [
    Round::Preprocessing,
    Round::InputMaskReservation,
    Round::InputCollection,
    Round::MPCExecution,
    Round::OutputDistribution,
    Round::ProgramFinished,
];

fn execution_not_found(execution_id: ExecutionId) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        ErrorCode::ServerError(CoordinatorRPCBaseError::ExecutionNotFound as i32).code(),
        format!("Execution {execution_id} is not registered"),
        None::<()>,
    )
}

/// The basic server-side information for one client connection to the coordinator RPC interface.
/// Can be extended by the developer.
#[derive(Clone)]
pub struct CoordinatorRPCServerConnectionBase {
    /// A reference to the server's shared state.
    d: Arc<Mutex<CoordinatorRPCServerSharedBase>>,
    /// The connected client's identity, which is the client's public key in DER format.
    id: ClientIdentity,
}

/// The basic internal state of the coordinator RPC server.
/// Can be extended by the developer.
pub struct CoordinatorRPCServerSharedBase {
    mpc_nodes: Vec<ClientIdentity>,
    n: u64,
    t: u64,
    executions: HashMap<ExecutionId, CoordinatorExecutionState>,
    /// Set by one-off coordinator invocations via `watch_for_shutdown_request`. Fired by the
    /// `request_shutdown` RPC method; absent (and thus rejecting shutdown requests) for standing
    /// coordinators.
    shutdown_notify: Option<oneshot::Sender<()>>,
    /// The execution served by a one-off coordinator. Unlike standing executions, its round
    /// history remains live until every party acknowledges it or the one-off grace period expires.
    one_off_execution: Option<ExecutionId>,
    /// Executions that reached the retirement quorum. Their protocol state has been dropped;
    /// only the acknowledging identities are kept so that stragglers can still retire cleanly.
    retired: RetiredExecutions,
}

/// A bounded, insertion-ordered set of executions that have been sealed but not yet
/// acknowledged by every party. Bounding this (rather than waiting for acknowledgements that
/// a faulty party may never send) is what keeps a silent party from consuming memory forever.
#[derive(Default)]
struct RetiredExecutions {
    acks: HashMap<ExecutionId, HashSet<ClientIdentity>>,
    order: VecDeque<ExecutionId>,
}

impl RetiredExecutions {
    fn seal(&mut self, execution_id: ExecutionId, acks: HashSet<ClientIdentity>) {
        if self.acks.insert(execution_id, acks).is_none() {
            self.order.push_back(execution_id);
        }
        while self.order.len() > DEFAULT_MAX_RETIRED_EXECUTIONS {
            if let Some(evicted) = self.order.pop_front() {
                self.acks.remove(&evicted);
            }
        }
    }

    /// Records one more acknowledgement, forgetting the execution entirely once every party
    /// has acknowledged it. Returns false when the execution is not sealed.
    fn acknowledge(&mut self, execution_id: ExecutionId, party: &ClientIdentity, n: usize) -> bool {
        let Some(acks) = self.acks.get_mut(&execution_id) else {
            return false;
        };
        acks.insert(party.clone());
        if acks.len() >= n {
            self.acks.remove(&execution_id);
            self.order.retain(|candidate| *candidate != execution_id);
        }
        true
    }

    fn contains(&self, execution_id: ExecutionId) -> bool {
        self.acks.contains_key(&execution_id)
    }
}

/// All mutable protocol state for one program invocation.
struct CoordinatorExecutionState {
    registration: ExecutionRegistration,
    retirement_acks: HashSet<ClientIdentity>,
    /// Parties that have proposed each round transition. A round is applied once its proposer
    /// set reaches the transition quorum, which replaces the previous single designated proposer.
    transition_votes: HashMap<Round, HashSet<ClientIdentity>>,
    // Contains the sinks of clients, which subscribed to the transition to the given round.
    sinks: HashMap<Round, Vec<SubscriptionSink>>,
    trans_events: HashMap<Round, Event>,
    reserved_index_events: Vec<Event>,
    reserved_index_sinks: Vec<SubscriptionSink>,
    assigned_reserved_index_events: Vec<AssignedMaskReservation>,
    assigned_reserved_index_sinks: Vec<SubscriptionSink>,
    masked_input_events: Vec<Event>,
    masked_input_sinks: Vec<SubscriptionSink>,
    assigned_masked_input_events: Vec<AssignedMaskedInputEvent>,
    assigned_masked_input_sinks: Vec<SubscriptionSink>,
    /// Serializes client input broadcasts without holding the coordinator-wide
    /// execution-state mutex across subscription I/O.
    masked_input_delivery: Arc<Mutex<()>>,
    n_reserved: u64,
    reserved_indices: Vec<Option<ClientIdentity>>,
    masked_inputs: Vec<Option<Vec<u8>>>,
    /// The current round.
    round: Round,
    /// Stores encrypted output shares sent by MPC nodes for MPC clients. The first element of the key is the client ID,
    /// the second is the node ID.
    output_shares: HashMap<(ClientIdentity, ClientIdentity), (Vec<u8>, Vec<u8>)>,
    /// A client remains subscribed as additional parties submit output shares.
    output_sinks: HashMap<ClientIdentity, Arc<SubscriptionSink>>,
    /// The set of clients that are permitted to call `obtain_output_shares`.
    output_clients: Vec<ClientIdentity>,
    /// Optional index assignments used to prevent clients from reserving indices assigned to others.
    input_assignments: Vec<InputSlotAssignment>,
}

type TransitionDelivery = (Round, Event, Vec<SubscriptionSink>);
type OutputDelivery = (Arc<SubscriptionSink>, Vec<(Vec<u8>, Vec<u8>)>);

async fn deliver_transitions(deliveries: Vec<TransitionDelivery>) {
    for (round, event, sinks) in deliveries {
        let results = futures_util::future::join_all(sinks.iter().map(|sink| {
            let json = to_json_raw_value(&event).expect("failed convert to JSON");
            tokio::time::timeout(SUBSCRIPTION_SEND_TIMEOUT, sink.send(json))
        }))
        .await;
        if results.iter().any(|result| !matches!(result, Ok(Ok(())))) {
            eprintln!(
                "coordinator subscriber disconnected or timed out while broadcasting {:?}",
                round
            );
        }
    }
}

impl CoordinatorRPCServerConnectionBase {
    pub fn new(internal: Arc<Mutex<CoordinatorRPCServerSharedBase>>, id: ClientIdentity) -> Self {
        Self { d: internal, id }
    }

    async fn execution_state(
        &self,
        execution_id: ExecutionId,
    ) -> Result<MappedMutexGuard<'_, CoordinatorExecutionState>, ErrorObjectOwned> {
        let shared = self.d.lock().await;
        if !shared.executions.contains_key(&execution_id) {
            return Err(execution_not_found(execution_id));
        }
        Ok(MutexGuard::map(shared, |shared| {
            shared
                .executions
                .get_mut(&execution_id)
                .expect("execution presence checked before mapping")
        }))
    }
}

impl CoordinatorRPCServerSharedBase {
    pub fn new(
        n: u64,
        t: u64,
        initial_mpc_nodes: Vec<ClientIdentity>,
    ) -> Result<Self, CoordinatorError> {
        validate_topology(n, t, &initial_mpc_nodes)?;
        Ok(Self {
            mpc_nodes: initial_mpc_nodes,
            n,
            t,
            executions: HashMap::new(),
            shutdown_notify: None,
            one_off_execution: None,
            retired: RetiredExecutions::default(),
        })
    }

    /// How many distinct parties must propose a round transition before it is applied.
    ///
    /// The upper bound is the liveness bound `n - t`: requiring more than that would let `t`
    /// faulty parties halt every execution simply by staying silent, which is the failure this
    /// quorum exists to remove. Within that bound we prefer the honest-majority quorum `2t + 1`.
    /// The lower bound `t + 1` guarantees at least one honest proposer, so a colluding minority
    /// can never advance a round on its own.
    ///
    /// Note that a quorum is not what makes an early transition *safe* — a quorum containing a
    /// single honest party is still enough to advance. Safety comes from the coordinator-side
    /// preconditions checked in `blocking_precondition`; the quorum is what removes the single
    /// designated proposer as a point of failure.
    fn transition_quorum(&self) -> usize {
        let liveness_bound = (self.n - self.t) as usize;
        let honest_majority = (2 * self.t + 1) as usize;
        honest_majority
            .min(liveness_bound)
            .max((self.t + 1) as usize)
    }

    /// How many parties must acknowledge completion before an execution's protocol state is
    /// dropped. Bounded by `n - t` for the same reason as [`Self::transition_quorum`].
    fn retirement_quorum(&self) -> usize {
        (self.n - self.t) as usize
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_for_execution(
        execution_id: ExecutionId,
        prog_hash: [u8; 32],
        n: u64,
        t: u64,
        initial_mpc_nodes: Vec<ClientIdentity>,
        n_inputs: u64,
        output_clients: Vec<ClientIdentity>,
        input_assignment: InputAssignment,
    ) -> Result<Self, CoordinatorError> {
        let min_output_shares = t
            .checked_mul(2)
            .and_then(|threshold| threshold.checked_add(1))
            .ok_or_else(|| CoordinatorError::JSONError("output quorum overflow".to_owned()))?;
        let mut shared = Self::new(n, t, initial_mpc_nodes)?;
        shared.register_execution(ExecutionRegistration {
            execution_id,
            program_hash: prog_hash,
            n_inputs,
            output_clients,
            input_assignment,
            min_output_shares,
        })?;
        Ok(shared)
    }

    pub fn register_execution(
        &mut self,
        registration: ExecutionRegistration,
    ) -> Result<(), CoordinatorError> {
        if let Some(existing) = self.executions.get(&registration.execution_id) {
            if existing.registration == registration {
                return Ok(());
            }
            return Err(CoordinatorError::JSONError(format!(
                "Execution {} is already registered with different metadata",
                registration.execution_id
            )));
        }
        if self.executions.len() >= DEFAULT_MAX_CONCURRENT_EXECUTIONS {
            // Healthy stragglers need the completed round history until they have also reached
            // ProgramFinished. Keep that history during normal operation, and only compact a
            // quorum-retired execution when its slot is actually needed. This preserves bounded
            // memory without racing a live fifth party merely because the first `n - t` parties
            // finished slightly earlier.
            let retirement_quorum = self.retirement_quorum();
            let evictable = self
                .executions
                .iter()
                .find_map(|(execution_id, execution)| {
                    (self.one_off_execution != Some(*execution_id)
                        && execution.retirement_acks.len() >= retirement_quorum)
                        .then_some(*execution_id)
                });
            if let Some(execution_id) = evictable {
                let execution = self
                    .executions
                    .remove(&execution_id)
                    .expect("eviction candidate came from the execution map");
                self.retired.seal(execution_id, execution.retirement_acks);
            } else {
                return Err(CoordinatorError::JSONError(format!(
                    "Execution capacity {} reached",
                    DEFAULT_MAX_CONCURRENT_EXECUTIONS
                )));
            }
        }
        let execution = CoordinatorExecutionState::new(registration.clone(), self.n)?;
        self.executions.insert(registration.execution_id, execution);
        Ok(())
    }

    /// Returns the current round of the given execution, or `None` if it is not registered
    /// (either because it never was, or because it has already been retired).
    pub fn round(&self, execution_id: ExecutionId) -> Option<Round> {
        self.executions
            .get(&execution_id)
            .map(|execution| execution.round)
    }

    /// Returns a receiver that resolves once a party calls the `request_shutdown` RPC method.
    /// Used by one-off coordinator invocations to know when it is safe to exit, without
    /// guessing based on internal round state (see `request_shutdown`'s doc comment for why
    /// that would be racy).
    pub fn watch_for_shutdown_request(
        &mut self,
        execution_id: ExecutionId,
    ) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        self.shutdown_notify = Some(tx);
        self.one_off_execution = Some(execution_id);
        rx
    }

    /// Acknowledges that `party` has finished with `execution_id`.
    ///
    /// Retirement happens in two stages. Once `n - t` parties have acknowledged, the execution is
    /// eligible for capacity reclamation, but its complete round history stays live so a healthy
    /// straggler can still finish. Unanimity removes it immediately. If faulty parties leave the
    /// coordinator at capacity, registration compacts a quorum-retired execution into a bounded
    /// acknowledgement-only tombstone before admitting new work.
    pub fn retire_execution(
        &mut self,
        execution_id: ExecutionId,
        party: &ClientIdentity,
    ) -> Result<(), CoordinatorError> {
        // The RPC entry point already rejects non-parties, but this is a public method and the
        // acknowledgement count is a quorum: counting an identity that is not on the roster would
        // let one party's acknowledgements stand in for several.
        if !self.mpc_nodes.contains(party) {
            return Err(CoordinatorError::JSONError(
                "Only configured MPC parties can retire executions".to_owned(),
            ));
        }
        let n = self.mpc_nodes.len();
        if self.retired.acknowledge(execution_id, party, n) {
            return Ok(());
        }
        let Some(execution) = self.executions.get_mut(&execution_id) else {
            // Already retired and forgotten. Acknowledging twice is not an error: a party that
            // retries after a lost connection must not see its cleanup fail.
            return Ok(());
        };
        execution.retirement_acks.insert(party.clone());
        if execution.retirement_acks.len() >= n {
            self.executions.remove(&execution_id);
        }
        Ok(())
    }

    /// Whether `execution_id` has reached its retirement quorum but not yet been forgotten.
    pub fn is_retired(&self, execution_id: ExecutionId) -> bool {
        self.retired.contains(execution_id)
            || self.executions.get(&execution_id).is_some_and(|execution| {
                execution.retirement_acks.len() >= self.retirement_quorum()
            })
    }

    fn retirement_progress(&self, execution_id: ExecutionId) -> (usize, usize, bool) {
        let n = self.mpc_nodes.len();
        if let Some(execution) = self.executions.get(&execution_id) {
            return (execution.retirement_acks.len(), n, false);
        }
        if let Some(acks) = self.retired.acks.get(&execution_id) {
            return (acks.len(), n, false);
        }
        // The one-off execution is registered before the listener starts and can only leave both
        // maps after unanimous retirement, so absence here is its completed drain state.
        (n, n, true)
    }
}

fn validate_topology(
    n: u64,
    t: u64,
    initial_mpc_nodes: &[ClientIdentity],
) -> Result<(), CoordinatorError> {
    if initial_mpc_nodes.is_empty() {
        return Err(CoordinatorError::JSONError(
            "Coordinator requires at least one MPC node".to_string(),
        ));
    }
    let n_usize = usize::try_from(n).map_err(|_| CoordinatorError::U64ToUsizeError)?;
    if initial_mpc_nodes.len() != n_usize {
        return Err(CoordinatorError::JSONError(format!(
            "Coordinator was configured for {n} MPC nodes, but received {} node identities",
            initial_mpc_nodes.len()
        )));
    }
    if t >= n {
        return Err(CoordinatorError::JSONError(format!(
            "Threshold {t} must be less than the MPC node count {n}"
        )));
    }
    // Every secret-sharing scheme this coordinator serves needs at least `t + 1` honest parties
    // to reconstruct, and the control-plane quorums below need `n - t >= t + 1` to be both safe
    // and live. Both reduce to the same bound.
    if n < 2 * t + 1 {
        return Err(CoordinatorError::JSONError(format!(
            "MPC node count {n} must be at least 2t + 1 = {} for threshold {t}",
            2 * t + 1
        )));
    }
    if initial_mpc_nodes
        .iter()
        .enumerate()
        .any(|(index, node)| initial_mpc_nodes[..index].contains(node))
    {
        return Err(CoordinatorError::JSONError(
            "MPC node identities must be unique".to_string(),
        ));
    }
    Ok(())
}

/// Expands the wire-compact per-client `ranges` into one `InputSlotAssignment` per global input
/// slot, in range order, with each range's own labels numbered `0..count`. Purely an in-memory
/// expansion — see `InputAssignment` for why the wire format itself stays range-based.
fn expand_input_ranges(ranges: &[InputClientRange]) -> Vec<InputSlotAssignment> {
    let total = ranges.iter().map(|range| range.count).sum::<u64>();
    let mut slots = Vec::with_capacity(total.min(usize::MAX as u64) as usize);
    for range in ranges {
        for label in 0..range.count {
            slots.push(InputSlotAssignment {
                client_index: range.client_index,
                label,
            });
        }
    }
    slots
}

impl CoordinatorExecutionState {
    fn new(registration: ExecutionRegistration, n: u64) -> Result<Self, CoordinatorError> {
        if registration.execution_id.is_zero() {
            return Err(CoordinatorError::JSONError(
                "execution ID must be nonzero".to_string(),
            ));
        }
        if registration.program_hash == [0; 32] {
            return Err(CoordinatorError::JSONError(
                "program hash must be nonzero".to_string(),
            ));
        }
        let ranges_total: u64 = registration
            .input_assignment
            .ranges
            .iter()
            .map(|range| range.count)
            .sum();
        if !registration.input_assignment.ranges.is_empty() && registration.n_inputs != ranges_total
        {
            return Err(CoordinatorError::JSONError(format!(
                "Input assignment covers {ranges_total} inputs, but coordinator was configured with {} inputs",
                registration.n_inputs
            )));
        }
        let n_clients = registration.input_assignment.clients.len();
        if let Some(range) = registration
            .input_assignment
            .ranges
            .iter()
            .find(|range| range.client_index as usize >= n_clients)
        {
            return Err(CoordinatorError::JSONError(format!(
                "Input range references client_index {}, but only {n_clients} clients were provided",
                range.client_index
            )));
        }
        if registration.min_output_shares == 0 || registration.min_output_shares > n {
            return Err(CoordinatorError::JSONError(format!(
                "Output quorum {} must be between 1 and {n}",
                registration.min_output_shares
            )));
        }
        let n_inputs = usize::try_from(registration.n_inputs)
            .map_err(|_| CoordinatorError::U64ToUsizeError)?;
        Ok(Self {
            registration: registration.clone(),
            retirement_acks: HashSet::new(),
            transition_votes: HashMap::new(),
            sinks: HashMap::new(),
            trans_events: HashMap::new(),
            reserved_index_events: vec![],
            reserved_index_sinks: vec![],
            assigned_reserved_index_events: vec![],
            assigned_reserved_index_sinks: vec![],
            masked_input_events: vec![],
            masked_input_sinks: vec![],
            assigned_masked_input_events: vec![],
            assigned_masked_input_sinks: vec![],
            masked_input_delivery: Arc::new(Mutex::new(())),
            n_reserved: 0,
            reserved_indices: vec![None; n_inputs],
            masked_inputs: vec![None; n_inputs],
            round: Round::Idle,
            output_shares: HashMap::new(),
            output_sinks: HashMap::new(),
            output_clients: registration.output_clients.clone(),
            input_assignments: expand_input_ranges(&registration.input_assignment.ranges),
        })
    }

    /// Resolves an input slot's owning client identity. `client_index` is validated against
    /// `input_assignment.clients` in `new`, so this only returns `None` for a slot that isn't
    /// one of `self.input_assignments` (i.e. an out-of-range slot index, not an out-of-range
    /// `client_index`).
    fn input_slot_client(&self, slot: &InputSlotAssignment) -> Option<&ClientIdentity> {
        self.registration
            .input_assignment
            .clients
            .get(slot.client_index as usize)
    }

    async fn subscribe_reserved_indices(&mut self, sink: SubscriptionSink) -> SubscriptionResult {
        if !self.reserved_index_events.is_empty() {
            for event in &self.reserved_index_events {
                let json = to_json_raw_value(event).expect("failed convert to JSON");
                if !matches!(
                    tokio::time::timeout(SUBSCRIPTION_SEND_TIMEOUT, sink.send(json)).await,
                    Ok(Ok(()))
                ) {
                    eprintln!(
                        "coordinator reserved-index subscriber disconnected or timed out during replay"
                    );
                    return Ok(());
                }
            }
        }

        self.reserved_index_sinks.push(sink);
        Ok(())
    }

    async fn subscribe_masked_inputs(&mut self, sink: SubscriptionSink) -> SubscriptionResult {
        if !self.masked_input_events.is_empty() {
            for event in &self.masked_input_events {
                let json = to_json_raw_value(event).expect("failed convert to JSON");
                if !matches!(
                    tokio::time::timeout(SUBSCRIPTION_SEND_TIMEOUT, sink.send(json)).await,
                    Ok(Ok(()))
                ) {
                    eprintln!(
                        "coordinator masked-input subscriber disconnected or timed out during replay"
                    );
                    return Ok(());
                }
            }
        }

        self.masked_input_sinks.push(sink);
        Ok(())
    }

    async fn subscribe_assigned_reserved_indices(
        &mut self,
        sink: SubscriptionSink,
    ) -> SubscriptionResult {
        // Replay history as a single batch, matching the one-message-per-reservation-call shape
        // that live broadcasts use.
        if !self.assigned_reserved_index_events.is_empty() {
            let json = to_json_raw_value(&self.assigned_reserved_index_events)
                .expect("failed convert to JSON");
            if !matches!(
                tokio::time::timeout(SUBSCRIPTION_SEND_TIMEOUT, sink.send(json)).await,
                Ok(Ok(()))
            ) {
                eprintln!(
                    "coordinator assigned reserved-index subscriber disconnected or timed out during replay"
                );
                return Ok(());
            }
        }

        self.assigned_reserved_index_sinks.push(sink);
        Ok(())
    }

    async fn subscribe_assigned_masked_inputs(
        &mut self,
        sink: SubscriptionSink,
    ) -> SubscriptionResult {
        // Replay history as a single batch, matching the one-message-per-submission-call shape
        // that live broadcasts use.
        if !self.assigned_masked_input_events.is_empty() {
            let json = to_json_raw_value(&self.assigned_masked_input_events)
                .expect("failed convert to JSON");
            if !matches!(
                tokio::time::timeout(SUBSCRIPTION_SEND_TIMEOUT, sink.send(json)).await,
                Ok(Ok(()))
            ) {
                eprintln!(
                    "coordinator assigned masked-input subscriber disconnected or timed out during replay"
                );
                return Ok(());
            }
        }

        self.assigned_masked_input_sinks.push(sink);
        Ok(())
    }

    /// True when this execution has no client inputs at all, so the two input rounds carry no
    /// work and `Preprocessing` advances straight to `MPCExecution`.
    fn skips_empty_input_rounds(&self, next_round: Round) -> bool {
        self.round == Round::Preprocessing && next_round == Round::MPCExecution
    }

    /// True when this execution has no output clients at all, so `OutputDistribution` carries no
    /// work and `MPCExecution` advances straight to `ProgramFinished`.
    fn skips_empty_output_rounds(&self, next_round: Round) -> bool {
        self.round == Round::MPCExecution && next_round == Round::ProgramFinished
    }

    /// A reason the coordinator must not enter `next_round` yet, independent of how many parties
    /// proposed it.
    ///
    /// This is what actually protects the protocol from a malicious proposer. Round order alone
    /// is not enough: entering `MPCExecution` while input slots are still empty would run the
    /// program on a truncated input set, silently censoring the clients that had not submitted.
    /// Because every honest party proposes `MPCExecution` only after it has received all inputs,
    /// this can only ever hold back a proposal that no honest party would have made.
    fn blocking_precondition(&self, next_round: Round) -> Option<String> {
        if next_round == Round::MPCExecution && !self.skips_empty_input_rounds(next_round) {
            let missing = self
                .masked_inputs
                .iter()
                .filter(|input| input.is_none())
                .count();
            if missing > 0 {
                return Some(format!(
                    "{missing} of {} masked inputs have not been submitted",
                    self.masked_inputs.len()
                ));
            }
        }
        None
    }

    /// The next round that both follows the current one and has reached the proposer quorum.
    fn next_quorum_round(&self, quorum: usize) -> Option<Round> {
        ORDERED_ROUNDS.into_iter().find(|&candidate| {
            (round_before(candidate) == Some(self.round)
                || self.skips_empty_input_rounds(candidate)
                || self.skips_empty_output_rounds(candidate))
                && self
                    .transition_votes
                    .get(&candidate)
                    .is_some_and(|voters| voters.len() >= quorum)
        })
    }

    /// Applies every round whose proposer quorum is already satisfied.
    ///
    /// This cascades rather than applying a single round so that proposals which arrived out of
    /// order — a fast party proposing round `R + 1` before the coordinator applied `R` — are not
    /// stranded. It is also why proposals for a future round are recorded rather than rejected.
    fn try_advance(
        &mut self,
        quorum: usize,
        roster_head: &ClientIdentity,
    ) -> Vec<TransitionDelivery> {
        let mut deliveries = Vec::new();
        while let Some(next_round) = self.next_quorum_round(quorum) {
            if let Some(reason) = self.blocking_precondition(next_round) {
                eprintln!(
                    "coordinator holding {:?} for execution {}: {reason}",
                    next_round, self.registration.execution_id
                );
                return deliveries;
            }

            let event = match next_round {
                // `Idle` is never a member of ORDERED_ROUNDS, so it cannot be reached here.
                Round::Idle => return deliveries,
                Round::Preprocessing => Event::PreprocessingStarted {
                    // Informational only: retained so the off-chain event mirrors its on-chain
                    // counterpart. No party derives authority from this field any more.
                    designated_party: roster_head.clone(),
                },
                Round::InputMaskReservation => Event::InputMaskReservationStarted,
                Round::InputCollection => Event::InputCollectionStarted,
                Round::MPCExecution => Event::MPCStarted,
                Round::OutputDistribution => Event::OutputSendingStarted,
                Round::ProgramFinished => Event::ExecutionDone,
            };

            let sinks = self
                .transition(event.clone(), next_round)
                .expect("round order validated before transition");
            deliveries.push((next_round, event, sinks));

            #[cfg(feature = "benchmark")]
            {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                println!("BENCH_ROUND: {:?} ts={}", next_round, ts);
            }
        }
        deliveries
    }

    fn transition(
        &mut self,
        event: Event,
        round: Round,
    ) -> Result<Vec<SubscriptionSink>, CoordinatorError> {
        if round_before(round).is_none() {
            return Err(CoordinatorError::CannotTransitionToIdle);
        }

        let sinks = self.sinks.remove(&round).unwrap_or_default();

        // Record the round even if one of the existing subscribers has disconnected.
        // Late subscribers will replay this event from history.
        self.trans_events.insert(round, event.clone());

        self.round = round;

        Ok(sinks)
    }

    fn ready_output_snapshot(
        &mut self,
        client_id: &ClientIdentity,
        min_shares: usize,
    ) -> Option<OutputDelivery> {
        let waiter = self.output_sinks.get(client_id)?.clone();
        if waiter.is_closed() {
            self.output_sinks.remove(client_id);
            return None;
        }

        let output_shares = self
            .output_shares
            .iter()
            .filter(|((candidate, _), _)| candidate == client_id)
            .map(|(_, shares)| shares.clone())
            .collect::<Vec<_>>();
        if output_shares.len() < min_shares {
            return None;
        }

        Some((waiter, output_shares))
    }
}

async fn deliver_ready_output_waiters(
    shared: &Arc<Mutex<CoordinatorRPCServerSharedBase>>,
    execution_id: ExecutionId,
    client_id: &ClientIdentity,
    min_shares: usize,
) {
    let Some((waiter, output_shares)) = ({
        let mut shared = shared.lock().await;
        shared
            .executions
            .get_mut(&execution_id)
            .expect("output execution remains registered")
            .ready_output_snapshot(client_id, min_shares)
    }) else {
        return;
    };

    let json = to_json_raw_value(&output_shares).expect("failed convert to JSON");
    if waiter.send(json).await.is_err() {
        let mut shared = shared.lock().await;
        if let Some(execution) = shared.executions.get_mut(&execution_id) {
            if execution
                .output_sinks
                .get(client_id)
                .is_some_and(|current| Arc::ptr_eq(current, &waiter))
            {
                execution.output_sinks.remove(client_id);
            }
        }
    }
}

/// Pre-implemented RPC methods.
#[async_trait]
impl CoordinatorRPCBaseServer for CoordinatorRPCServerConnectionBase {
    async fn register_execution(&self, registration: ExecutionRegistration) -> RpcResult<()> {
        let mut shared = self.d.lock().await;
        if !shared.mpc_nodes.contains(&self.id) {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(NotParty as i32).code(),
                "Only configured MPC parties can register executions.",
                None::<()>,
            ));
        }
        shared.register_execution(registration).map_err(|error| {
            ErrorObjectOwned::owned(
                ErrorCode::ServerError(ExecutionAlreadyRegistered as i32).code(),
                error.to_string(),
                None::<()>,
            )
        })
    }

    async fn retire_execution(&self, execution_id: ExecutionId) -> RpcResult<()> {
        let mut shared = self.d.lock().await;
        if !shared.mpc_nodes.contains(&self.id) {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(NotParty as i32).code(),
                "Only configured MPC parties can retire executions.",
                None::<()>,
            ));
        }
        shared
            .retire_execution(execution_id, &self.id)
            .map_err(|error| {
                ErrorObjectOwned::owned(
                    ErrorCode::ServerError(ExecutionNotFound as i32).code(),
                    error.to_string(),
                    None::<()>,
                )
            })
    }

    async fn request_shutdown(&self) -> RpcResult<()> {
        let mut shared = self.d.lock().await;
        let designated_party = shared.mpc_nodes[0].clone();
        if self.id != designated_party {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(NotDesignatedParty as i32).code(),
                "Only the designated party can request coordinator shutdown.",
                None::<()>,
            ));
        }
        let Some(execution_id) = shared.one_off_execution else {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(ShutdownNotAccepted as i32).code(),
                "This coordinator does not accept shutdown requests.",
                None::<()>,
            ));
        };
        if shared.round(execution_id) != Some(Round::ProgramFinished) {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(WrongRound as i32).code(),
                "The one-off coordinator cannot shut down before ProgramFinished.",
                None::<()>,
            ));
        }
        match shared.shutdown_notify.take() {
            Some(tx) => {
                let _ = tx.send(());
                Ok(())
            }
            None => Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(ShutdownNotAccepted as i32).code(),
                "This coordinator does not accept shutdown requests.",
                None::<()>,
            )),
        }
    }

    async fn sub_round(
        &self,
        pending: PendingSubscriptionSink,
        execution_id: ExecutionId,
        round: Round,
    ) -> SubscriptionResult {
        if round_before(round).is_none() {
            pending
                .reject(ErrorObjectOwned::owned(
                    ErrorCode::InvalidParams.code(),
                    format!("Cannot subscribe to round {:?}", round),
                    None::<()>,
                ))
                .await;
            return Ok(());
        }

        // Accepting a JSON-RPC subscription performs WebSocket I/O. Never do
        // that while holding the coordinator-wide execution-state mutex: a
        // slow handshake for one execution must not block phase transitions or
        // client input delivery for every other execution.
        let execution_exists = {
            let shared = self.d.lock().await;
            shared.executions.contains_key(&execution_id)
        };
        if !execution_exists {
            pending.reject(execution_not_found(execution_id)).await;
            return Ok(());
        }
        let sink = pending.accept().await?;

        let replay = {
            let Ok(mut d) = self.execution_state(execution_id).await else {
                // The execution was retired while the subscription handshake
                // was in flight. Dropping the accepted sink closes it.
                return Ok(());
            };
            if let Some(event) = d.trans_events.get(&round) {
                event.clone()
            } else {
                d.sinks.entry(round).or_default().push(sink);
                return Ok(());
            }
        };

        let json = to_json_raw_value(&replay).expect("failed convert to JSON");
        if !matches!(
            tokio::time::timeout(SUBSCRIPTION_SEND_TIMEOUT, sink.send(json)).await,
            Ok(Ok(()))
        ) {
            eprintln!(
                "coordinator round subscriber disconnected or timed out while replaying {:?}",
                round
            );
        }
        Ok(())
    }

    async fn available_input_masks(&self, execution_id: ExecutionId) -> RpcResult<u64> {
        let d = self.execution_state(execution_id).await?;
        Ok(d.masked_inputs.len() as u64 - d.n_reserved)
    }

    async fn sub_assigned_reserved_indices(
        &self,
        pending: PendingSubscriptionSink,
        execution_id: ExecutionId,
    ) -> SubscriptionResult {
        let execution_exists = {
            let shared = self.d.lock().await;
            shared.executions.contains_key(&execution_id)
        };
        if !execution_exists {
            pending.reject(execution_not_found(execution_id)).await;
            return Ok(());
        }
        let sink = pending.accept().await?;
        let Ok(mut d) = self.execution_state(execution_id).await else {
            return Ok(());
        };
        d.subscribe_assigned_reserved_indices(sink).await
    }

    async fn sub_assigned_masked_inputs(
        &self,
        pending: PendingSubscriptionSink,
        execution_id: ExecutionId,
    ) -> SubscriptionResult {
        let execution_exists = {
            let shared = self.d.lock().await;
            shared.executions.contains_key(&execution_id)
        };
        if !execution_exists {
            pending.reject(execution_not_found(execution_id)).await;
            return Ok(());
        }
        let sink = pending.accept().await?;
        let Ok(mut d) = self.execution_state(execution_id).await else {
            return Ok(());
        };
        d.subscribe_assigned_masked_inputs(sink).await
    }

    async fn submit_masked_input(
        &self,
        execution_id: ExecutionId,
        masked_input: Vec<u8>,
        reserved_index: u64,
    ) -> RpcResult<()> {
        self.submit_masked_inputs(execution_id, vec![masked_input], vec![reserved_index])
            .await
    }

    async fn submit_masked_inputs(
        &self,
        execution_id: ExecutionId,
        masked_inputs: Vec<Vec<u8>>,
        reserved_indices: Vec<u64>,
    ) -> RpcResult<()> {
        let (quorum, roster_head) = {
            let shared = self.d.lock().await;
            (shared.transition_quorum(), shared.mpc_nodes[0].clone())
        };
        let delivery = {
            let d = self.execution_state(execution_id).await?;
            d.masked_input_delivery.clone()
        };
        // Preserve submission order while allowing unrelated coordinator RPCs
        // and executions to progress during subscription delivery.
        let _delivery_guard = delivery.lock().await;
        let mut d = self.execution_state(execution_id).await?;

        if d.round != Round::InputCollection {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(WrongRound as i32).code(),
                format!(
                    "Need round {:?}, current round is {:?}",
                    Round::InputCollection,
                    d.round
                ),
                None::<()>,
            ));
        }

        if masked_inputs.len() != reserved_indices.len() {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(MismatchedBatchLengths as i32).code(),
                format!(
                    "Got {} masked inputs but {} reserved indices; these must match.",
                    masked_inputs.len(),
                    reserved_indices.len()
                ),
                None::<()>,
            ));
        }

        if reserved_indices.is_empty() {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(EmptyBatch as i32).code(),
                "Cannot submit an empty batch of masked inputs.",
                None::<()>,
            ));
        }

        // Validate every index before applying any of them, so the batch is atomic: either all
        // of `reserved_indices` end up with a masked input recorded, or (on error) none do.
        for &raw_reserved_index in &reserved_indices {
            let reserved_index = raw_reserved_index as usize;

            if reserved_index >= d.masked_inputs.len() {
                return Err(ErrorObjectOwned::owned(
                    ErrorCode::ServerError(IndexOutOfBounds as i32).code(),
                    format!(
                        "The index {} is out of bounds, there are only {} input masks.",
                        reserved_index,
                        d.masked_inputs.len()
                    ),
                    None::<()>,
                ));
            }

            match &d.reserved_indices[reserved_index] {
                Some(public_key) => {
                    if *public_key != self.id {
                        return Err(ErrorObjectOwned::owned(
                                ErrorCode::ServerError(BadID as i32).code(),
                                format!("Client {:?} cannot submit a masked input for index {}, since this index has been reserved by {:?}", self.id, reserved_index, *public_key),
                                None::<()>
                        ));
                    }
                    if d.masked_inputs[reserved_index].is_some() {
                        return Err(ErrorObjectOwned::owned(
                            ErrorCode::ServerError(MaskedInputAlreadySubmitted as i32).code(),
                            format!(
                                "Client {:?} has already submitted a masked input for index {}",
                                self.id, reserved_index
                            ),
                            None::<()>,
                        ));
                    }
                }
                None => {
                    return Err(ErrorObjectOwned::owned(
                        ErrorCode::ServerError(IndexNotReserved as i32).code(),
                        format!(
                            "Cannot submit a masked input for index {}, since it has not been reserved",
                            reserved_index
                        ),
                        None::<()>,
                    ));
                }
            }
        }

        let mut pairs = Vec::with_capacity(reserved_indices.len());
        let mut assigned_events = Vec::new();
        for (raw_reserved_index, masked_input) in reserved_indices.into_iter().zip(masked_inputs) {
            let reserved_index = raw_reserved_index as usize;
            d.masked_inputs[reserved_index] = Some(masked_input.clone());

            if let Some(slot) = d.input_assignments.get(reserved_index) {
                assigned_events.push(AssignedMaskedInputEvent {
                    client: self.id.clone(),
                    reserved_index: raw_reserved_index,
                    input_ordinal: slot.label,
                    masked_input: masked_input.clone(),
                });
            }

            pairs.push((raw_reserved_index, masked_input));
        }

        // One event carries every pair in this batch, so subscribers (and history replay) see
        // one message per `submit_masked_input(s)` call instead of one per index.
        let event = Event::MaskedInputEvent {
            client: self.id.clone(),
            masked_inputs: pairs,
        };
        d.masked_input_events.push(event.clone());
        d.assigned_masked_input_events
            .extend(assigned_events.iter().cloned());

        // Snapshot the sinks under the state lock, then release it before any
        // WebSocket I/O. The per-execution delivery guard above prevents a
        // concurrent submitter from observing the temporarily empty sink lists.
        let sinks = std::mem::take(&mut d.masked_input_sinks);
        let assigned_sinks = if assigned_events.is_empty() {
            Vec::new()
        } else {
            std::mem::take(&mut d.assigned_masked_input_sinks)
        };
        drop(d);

        let results = futures_util::future::join_all(sinks.iter().map(|sink| {
            let json = to_json_raw_value(&event).expect("failed convert to JSON");
            tokio::time::timeout(SUBSCRIPTION_SEND_TIMEOUT, sink.send(json))
        }))
        .await;
        let assigned_results = if assigned_sinks.is_empty() {
            Vec::new()
        } else {
            let results = futures_util::future::join_all(assigned_sinks.iter().map(|sink| {
                let json = to_json_raw_value(&assigned_events).expect("failed convert to JSON");
                tokio::time::timeout(SUBSCRIPTION_SEND_TIMEOUT, sink.send(json))
            }))
            .await;
            results
        };

        let Ok(mut d) = self.execution_state(execution_id).await else {
            // Delivery completed, but the execution was retired before its
            // subscription lists could be pruned.
            return Ok(());
        };
        for (sink, result) in sinks.into_iter().zip(results) {
            if matches!(result, Ok(Ok(()))) {
                d.masked_input_sinks.push(sink);
            } else {
                eprintln!("coordinator masked-input subscriber disconnected or timed out");
            }
        }
        for (sink, result) in assigned_sinks.into_iter().zip(assigned_results) {
            if matches!(result, Ok(Ok(()))) {
                d.assigned_masked_input_sinks.push(sink);
            } else {
                eprintln!("coordinator assigned masked-input subscriber disconnected or timed out");
            }
        }

        // This input may have been the last one the `MPCExecution` precondition was waiting on.
        // Re-checking here is what makes the precondition a wait rather than a rejection: parties
        // propose the round once, and the coordinator applies it as soon as it becomes legal.
        let transitions = d.try_advance(quorum, &roster_head);
        drop(d);
        deliver_transitions(transitions).await;

        Ok(())
    }

    async fn sub_reserved_indices(
        &self,
        pending: PendingSubscriptionSink,
        execution_id: ExecutionId,
    ) -> SubscriptionResult {
        let execution_exists = {
            let shared = self.d.lock().await;
            shared.executions.contains_key(&execution_id)
        };
        if !execution_exists {
            pending.reject(execution_not_found(execution_id)).await;
            return Ok(());
        }
        let sink = pending.accept().await?;
        let Ok(mut d) = self.execution_state(execution_id).await else {
            return Ok(());
        };
        d.subscribe_reserved_indices(sink).await
    }

    async fn sub_masked_inputs(
        &self,
        pending: PendingSubscriptionSink,
        execution_id: ExecutionId,
    ) -> SubscriptionResult {
        let execution_exists = {
            let shared = self.d.lock().await;
            shared.executions.contains_key(&execution_id)
        };
        if !execution_exists {
            pending.reject(execution_not_found(execution_id)).await;
            return Ok(());
        }
        let sink = pending.accept().await?;
        let Ok(mut d) = self.execution_state(execution_id).await else {
            return Ok(());
        };
        d.subscribe_masked_inputs(sink).await
    }

    async fn reserve_mask_index(&self, execution_id: ExecutionId, i: u64) -> RpcResult<()> {
        self.reserve_mask_indices(execution_id, vec![i]).await
    }

    async fn reserve_mask_indices(
        &self,
        execution_id: ExecutionId,
        indices: Vec<u64>,
    ) -> RpcResult<()> {
        let mut d = self.execution_state(execution_id).await?;

        if d.round != Round::InputMaskReservation {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(WrongRound as i32).code(),
                format!(
                    "Need round {:?}, current round is {:?}",
                    Round::InputMaskReservation,
                    d.round
                ),
                None::<()>,
            ));
        }

        if indices.is_empty() {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(EmptyBatch as i32).code(),
                "Cannot reserve an empty batch of indices.",
                None::<()>,
            ));
        }

        // Clients must reserve all of their indices in a single (batched) call: once a client
        // owns any entry in `reserved_indices`, it gets no second call to add more piecemeal.
        // An empty batch is rejected above, so every successful call leaves at least one such
        // entry -- no separate "has this client reserved" bookkeeping is needed.
        if d.reserved_indices
            .iter()
            .any(|owner| owner.as_ref() == Some(&self.id))
        {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(ClientAlreadyReserved as i32).code(),
                format!(
                    "Client {:?} has already made a reservation call; all indices must be reserved in a single call.",
                    self.id
                ),
                None::<()>,
            ));
        }

        // Validate every index before reserving any of them, so the batch is atomic: either all
        // of `indices` end up reserved, or (on error) none do.
        for &i in &indices {
            if i as usize >= d.reserved_indices.len() {
                return Err(ErrorObjectOwned::owned(
                    ErrorCode::ServerError(IndexOutOfBounds as i32).code(),
                    format!(
                        "The index {} is out of bounds, there are only {} input masks.",
                        i,
                        d.reserved_indices.len()
                    ),
                    None::<()>,
                ));
            }

            if d.reserved_indices[i as usize].is_some() {
                return Err(ErrorObjectOwned::owned(
                    ErrorCode::ServerError(IndexAlreadyReserved as i32).code(),
                    format!("Index {} already reserved.", i),
                    None::<()>,
                ));
            }

            // The duplicate-reservation check above only proves the index is free; assigned
            // input slots also need to be reserved by the client they were bound to.
            if let Some(slot) = d.input_assignments.get(i as usize) {
                let owner = d.input_slot_client(slot);
                if owner != Some(&self.id) {
                    return Err(ErrorObjectOwned::owned(
                        ErrorCode::ServerError(UnauthorizedClientIo as i32).code(),
                        format!(
                            "Client {:?} cannot reserve assigned input index {}, which belongs to {:?}",
                            self.id, i, owner
                        ),
                        None::<()>,
                    ));
                }
            }
        }

        let mut assigned_reservations = Vec::new();
        for &i in &indices {
            if let Some(slot) = d.input_assignments.get(i as usize) {
                assigned_reservations.push(AssignedMaskReservation {
                    client: self.id.clone(),
                    reserved_index: i,
                    input_ordinal: slot.label,
                });
            }

            d.reserved_indices[i as usize] = Some(self.id.clone());
            d.n_reserved += 1;
        }

        // One event carries every index in this batch, so subscribers (and history replay) see
        // one message per `reserve_mask_index(es)` call instead of one per index.
        let event = Event::ReservedInputEvent {
            client: self.id.clone(),
            reserved_indices: indices,
        };
        d.reserved_index_events.push(event.clone());
        d.assigned_reserved_index_events
            .extend(assigned_reservations.iter().cloned());

        // Broadcast the batch to all subscribed RPC clients concurrently -- sequential sends
        // here would hold the coordinator-wide execution lock for as long as the slowest
        // subscriber takes to drain its socket, stalling every other execution and client on
        // this coordinator. Disconnected subscribers are pruned; late/restarted nodes replay
        // from event history.
        let sinks = std::mem::take(&mut d.reserved_index_sinks);
        let results = futures_util::future::join_all(sinks.iter().map(|sink| {
            let json = to_json_raw_value(&event).expect("failed convert to JSON");
            tokio::time::timeout(SUBSCRIPTION_SEND_TIMEOUT, sink.send(json))
        }))
        .await;
        for (sink, result) in sinks.into_iter().zip(results) {
            if matches!(result, Ok(Ok(()))) {
                d.reserved_index_sinks.push(sink);
            } else {
                eprintln!("coordinator reserved-index subscriber disconnected or timed out");
            }
        }
        if !assigned_reservations.is_empty() {
            let assigned_sinks = std::mem::take(&mut d.assigned_reserved_index_sinks);
            let results = futures_util::future::join_all(assigned_sinks.iter().map(|sink| {
                let json =
                    to_json_raw_value(&assigned_reservations).expect("failed convert to JSON");
                tokio::time::timeout(SUBSCRIPTION_SEND_TIMEOUT, sink.send(json))
            }))
            .await;
            for (sink, result) in assigned_sinks.into_iter().zip(results) {
                if matches!(result, Ok(Ok(()))) {
                    d.assigned_reserved_index_sinks.push(sink);
                } else {
                    eprintln!(
                        "coordinator assigned reserved-index subscriber disconnected or timed out"
                    );
                }
            }
        }

        Ok(())
    }

    /// Proposes that `execution_id` advance to `next_round`.
    ///
    /// Any configured party may propose. The coordinator applies the transition once a quorum of
    /// distinct parties has proposed the same round and the round's preconditions hold, so no
    /// single party — designated or not — can either drive the protocol alone or halt it by
    /// falling silent.
    ///
    /// A proposal is never rejected for arriving early or late: it is recorded, and acted on when
    /// (or if) it becomes both current and supported. Callers therefore do not need to know how
    /// far the coordinator has progressed.
    async fn transition(&self, execution_id: ExecutionId, next_round: Round) -> RpcResult<()> {
        let (is_party, quorum, roster_head) = {
            let shared = self.d.lock().await;
            (
                shared.mpc_nodes.contains(&self.id),
                shared.transition_quorum(),
                shared.mpc_nodes[0].clone(),
            )
        };

        if !is_party {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(NotParty as i32).code(),
                "Only configured MPC parties can propose transitions.",
                None::<()>,
            ));
        }
        if round_before(next_round).is_none() {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::InvalidParams.code(),
                format!("Round {:?} cannot be transitioned to", Round::Idle),
                None::<()>,
            ));
        }

        let delivery = {
            let d = self.execution_state(execution_id).await?;
            d.masked_input_delivery.clone()
        };
        let _delivery_guard = delivery.lock().await;
        let mut d = self.execution_state(execution_id).await?;
        if round_index(next_round) <= round_index(d.round) {
            // Already applied. A party that proposes a round the quorum passed without it is
            // simply late, which is the normal outcome for the slowest `n - quorum` parties.
            return Ok(());
        }

        d.transition_votes
            .entry(next_round)
            .or_default()
            .insert(self.id.clone());
        let transitions = d.try_advance(quorum, &roster_head);
        drop(d);
        deliver_transitions(transitions).await;

        Ok(())
    }

    async fn send_output_shares(
        &self,
        execution_id: ExecutionId,
        client_id: ClientIdentity,
        enc_shares: (Vec<u8>, Vec<u8>),
    ) -> RpcResult<()> {
        let is_party = {
            let shared = self.d.lock().await;
            shared.mpc_nodes.contains(&self.id)
        };
        let mut d = self.execution_state(execution_id).await?;

        if !is_party {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(NotParty as i32).code(),
                "Only parties can send output shares.",
                None::<()>,
            ));
        }
        if !d.output_clients.contains(&client_id) {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(NotOutputClient as i32).code(),
                "Output client is not authorized for this execution.",
                None::<()>,
            ));
        }

        // a node cannot send output shares for a client twice
        if d.output_shares
            .contains_key(&(client_id.clone(), self.id.clone()))
        {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(OutputSharesAlreadySent as i32).code(),
                format!(
                    "Client {:?} already has submitted their output shares.",
                    client_id
                ),
                None::<()>,
            ));
        }

        // output shares for `client_id` from `self.id`
        d.output_shares
            .insert((client_id.clone(), self.id.clone()), enc_shares);

        let min_shares = d.registration.min_output_shares as usize;
        drop(d);
        deliver_ready_output_waiters(&self.d, execution_id, &client_id, min_shares).await;
        Ok(())
    }

    async fn obtain_output_shares(
        &self,
        pending: PendingSubscriptionSink,
        execution_id: ExecutionId,
    ) -> SubscriptionResult {
        // Validate under the execution lock, but never hold that lock while
        // completing the WebSocket subscription handshake. A client may open
        // this subscription concurrently with its masked-input RPC; awaiting
        // `accept` while locked can otherwise block that RPC response and all
        // round transitions for the execution.
        let rejection = match self.execution_state(execution_id).await {
            Err(error) => Some(error),
            Ok(d) if !d.output_clients.contains(&self.id) => Some(ErrorObjectOwned::owned(
                ErrorCode::ServerError(NotOutputClient as i32).code(),
                format!("Client {:?} is not an authorized output client.", self.id),
                None::<()>,
            )),
            Ok(d)
                if d.output_sinks
                    .get(&self.id)
                    .is_some_and(|sink| !sink.is_closed()) =>
            {
                Some(ErrorObjectOwned::owned(
                    ErrorCode::ServerError(OutputSharesAlreadyRequested as i32).code(),
                    "Output shares already requested.",
                    None::<()>,
                ))
            }
            Ok(_) => None,
        };
        if let Some(error) = rejection {
            pending.reject(error).await;
            return Ok(());
        }

        let sink = pending.accept().await?;
        let Ok(mut d) = self.execution_state(execution_id).await else {
            // The execution was retired during the handshake. Dropping the
            // accepted sink closes this subscription cleanly.
            return Ok(());
        };
        // Recheck after reacquiring the lock in case another subscription for
        // the same identity won the handshake race.
        if !d.output_clients.contains(&self.id)
            || d.output_sinks
                .get(&self.id)
                .is_some_and(|current| !current.is_closed())
        {
            return Ok(());
        }
        d.output_sinks.insert(self.id.clone(), Arc::new(sink));
        let min_shares = d.registration.min_output_shares as usize;
        drop(d);
        deliver_ready_output_waiters(&self.d, execution_id, &self.id, min_shares).await;

        Ok(())
    }
}

/// The pre-implemented RPC server-side connection can be used as a full-fledged RPC server
/// connection.
impl stoffel_mpc_coordinator_shared::rpc::RPCServerConnection
    for CoordinatorRPCServerConnectionBase
{
    type Internal = CoordinatorRPCServerSharedBase;

    fn new(internal: Arc<Mutex<Self::Internal>>, id: ClientIdentity) -> Self {
        Self { d: internal, id }
    }

    fn into_rpc(self) -> RpcModule<Self> {
        crate::CoordinatorRPCBaseServer::into_rpc(self)
    }
}

/// The exterior wrapper of the server-side coordinator.
pub struct OffChainCoordinatorServer<C: stoffel_mpc_coordinator_shared::rpc::RPCServerConnection> {
    addr: String,
    server_handle: RPCServerHandle,
    browser_handle: Option<jsonrpsee::server::ServerHandle>,
    _connection: std::marker::PhantomData<C>,
}

pub struct OffChainCoordinatorClient<F: FftField, S: ShareBound<F>> {
    rpc_coord: Client,
    execution_id: ExecutionId,
    t: u64,
    n_parties: u64,
    n_outputs: u64,
    key_der: Vec<u8>,
    _phantom: std::marker::PhantomData<(F, S)>,
}

impl<C: stoffel_mpc_coordinator_shared::rpc::RPCServerConnection> OffChainCoordinatorServer<C> {
    pub async fn start_coord_from_cert(
        shared: C::Internal,
        addr: &str,
        port: u16,
        t: u64,
        cert: Arc<rcgen::CertifiedKey<rcgen::KeyPair>>,
    ) -> Result<Self, CoordinatorError> {
        Self::start_coord(
            shared,
            addr,
            port,
            t,
            cert.cert.der().to_vec(),
            cert.signing_key.serialize_der(),
        )
        .await
    }

    pub async fn start_coord(
        shared: C::Internal,
        addr: &str,
        port: u16,
        _t: u64,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> Result<Self, CoordinatorError> {
        let rpc_server_data = Arc::new(Mutex::new(shared));
        let server_handle = stoffel_mpc_coordinator_shared::rpc::start_coord::<C>(
            addr,
            port,
            cert_der,
            key_der,
            rpc_server_data.clone(),
        )
        .await?;
        Ok(Self {
            addr: String::from(addr),
            server_handle,
            browser_handle: None,
            _connection: std::marker::PhantomData,
        })
    }

    pub fn get_addr(&self) -> String {
        self.addr.clone()
    }

    /// Runs the coordinator until `shutdown_requested` resolves, then shuts the listener down
    /// and returns. Intended for one-off invocations that serve exactly one execution: the
    /// caller arranges for `shutdown_requested` to resolve when a party calls `request_shutdown`
    /// (e.g. via `CoordinatorRPCServerSharedBase::watch_for_shutdown_request`), before `shared`
    /// is handed here, so that no client can call it before the coordinator is watching for it.
    pub async fn start_coord_one_off(
        shared: C::Internal,
        addr: &str,
        port: u16,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
        shutdown_requested: oneshot::Receiver<()>,
        shutdown: OneOffShutdownConfig,
    ) -> Result<(), CoordinatorError>
    where
        C: stoffel_mpc_coordinator_shared::rpc::RPCServerConnection<
            Internal = CoordinatorRPCServerSharedBase,
        >,
    {
        let rpc_server_data = Arc::new(Mutex::new(shared));
        let server_handle = stoffel_mpc_coordinator_shared::rpc::start_coord::<C>(
            addr,
            port,
            cert_der,
            key_der,
            rpc_server_data.clone(),
        )
        .await?;

        let _ = shutdown_requested.await;

        let drained = tokio::time::timeout(shutdown.grace, async {
            loop {
                let complete = {
                    let shared = rpc_server_data.lock().await;
                    shared.retirement_progress(shutdown.execution_id).2
                };
                if complete {
                    break;
                }
                tokio::time::sleep(ONE_OFF_RETIREMENT_POLL_INTERVAL).await;
            }
        })
        .await
        .is_ok();
        if !drained {
            let (acknowledged, parties, _) = {
                let shared = rpc_server_data.lock().await;
                shared.retirement_progress(shutdown.execution_id)
            };
            eprintln!(
                "one-off coordinator shutdown grace expired after {:?}: {acknowledged}/{parties} parties acknowledged ProgramFinished",
                shutdown.grace
            );
        }

        server_handle.shutdown().await;
        Ok(())
    }

    /// Stops the listener. Dropping the server state closes its connections.
    pub async fn shutdown(self) {
        if let Some(handle) = self.browser_handle {
            let _ = handle.stop();
            handle.stopped().await;
        }
        self.server_handle.shutdown().await;
    }

    /// Start an ordinary browser WebSocket listener alongside the existing mTLS
    /// listener. Signed requests retain the same P-256 public-key identities.
    pub async fn start_coord_with_browser(
        shared: CoordinatorRPCServerSharedBase,
        addr: &str,
        port: u16,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
        browser_bind: &str,
    ) -> Result<Self, CoordinatorError>
    where
        C: stoffel_mpc_coordinator_shared::rpc::RPCServerConnection<
            Internal = CoordinatorRPCServerSharedBase,
        >,
    {
        let rpc_server_data = Arc::new(Mutex::new(shared));
        let server_handle = stoffel_mpc_coordinator_shared::rpc::start_coord::<C>(
            addr,
            port,
            cert_der,
            key_der,
            rpc_server_data.clone(),
        )
        .await?;
        let browser_handle =
            crate::browser_rpc::start_coordinator_browser_rpc(browser_bind, rpc_server_data)
                .await?;
        Ok(Self {
            addr: String::from(addr),
            server_handle,
            browser_handle: Some(browser_handle),
            _connection: std::marker::PhantomData,
        })
    }
}

impl<F: FftField, S: ShareBound<F>> OffChainCoordinatorClient<F, S> {
    #[allow(clippy::too_many_arguments)]
    pub async fn start_rpc_client_for_execution(
        addr: &str,
        port: u16,
        t: u64,
        n_parties: u64,
        n_outputs: u64,
        execution_id: ExecutionId,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> Result<Self, CoordinatorError> {
        let rpc_coord = stoffel_mpc_coordinator_shared::self_signed_certs::setup_client(
            addr,
            port,
            cert_der,
            key_der.clone(),
        )
        .await?;

        Ok(Self {
            rpc_coord,
            execution_id,
            t,
            n_parties,
            n_outputs,
            key_der,
            _phantom: std::marker::PhantomData,
        })
    }

    pub async fn trigger_round(&self, round: Round) -> Result<(), CoordinatorError> {
        CoordinatorRPCBaseClient::transition(self.rpc(), self.execution_id, round)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))?;

        Ok(())
    }

    pub async fn register_execution(
        &self,
        registration: ExecutionRegistration,
    ) -> Result<(), CoordinatorError> {
        CoordinatorRPCBaseClient::register_execution(self.rpc(), registration)
            .await
            .map_err(|error| CoordinatorError::JSONError(error.to_string()))
    }

    pub async fn retire_execution(&self) -> Result<(), CoordinatorError> {
        CoordinatorRPCBaseClient::retire_execution(self.rpc(), self.execution_id)
            .await
            .map_err(|error| CoordinatorError::JSONError(error.to_string()))
    }

    /// Tells a one-off coordinator it may exit. Callers must only call this after they have
    /// themselves confirmed (e.g. via `wait_for_round(Round::ProgramFinished)`) that the
    /// execution actually finished — the coordinator does not infer this on its own, since a
    /// designated party's own round-transition call racing the coordinator's shutdown is exactly
    /// the bug this RPC method replaces.
    pub async fn request_shutdown(&self) -> Result<(), CoordinatorError> {
        CoordinatorRPCBaseClient::request_shutdown(self.rpc())
            .await
            .map_err(|error| CoordinatorError::JSONError(error.to_string()))
    }

    fn rpc(&self) -> &Client {
        &self.rpc_coord
    }
}

static ENC_INFO: &[u8] = b"StoffelOutputShareEncryption";

fn execution_enc_info(execution_id: ExecutionId) -> Vec<u8> {
    let mut info = Vec::with_capacity(ENC_INFO.len() + execution_id.as_bytes().len());
    info.extend_from_slice(ENC_INFO);
    info.extend_from_slice(execution_id.as_bytes());
    info
}

impl<F: FftField, S: ShareBound<F>> Coordinator<F, S> for OffChainCoordinatorClient<F, S> {
    type ClientIdentity = ClientIdentity;

    async fn start_preprocessing(&self) -> Result<(), CoordinatorError> {
        StoffelCoordinatorRPCClient::start_preprocessing(self.rpc(), self.execution_id)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }
    async fn reserve_input_masks(&self) -> Result<(), CoordinatorError> {
        StoffelCoordinatorRPCClient::reserve_input_masks(self.rpc(), self.execution_id)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }
    async fn collect_inputs(&self) -> Result<(), CoordinatorError> {
        StoffelCoordinatorRPCClient::collect_inputs(self.rpc(), self.execution_id)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }
    async fn start_mpc(&self) -> Result<(), CoordinatorError> {
        StoffelCoordinatorRPCClient::start_mpc(self.rpc(), self.execution_id)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }
    async fn send_output(&self) -> Result<(), CoordinatorError> {
        StoffelCoordinatorRPCClient::send_output(self.rpc(), self.execution_id)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }
    async fn finalize(&self) -> Result<(), CoordinatorError> {
        StoffelCoordinatorRPCClient::finalize(self.rpc(), self.execution_id)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }

    async fn wait_for_indices(
        &self,
        n_inputs: u64,
    ) -> Result<HashMap<ClientIdentity, Vec<u64>>, CoordinatorError> {
        // Wait for reserved index events.
        let mut sub = CoordinatorRPCBaseClient::sub_reserved_indices(self.rpc(), self.execution_id)
            .await
            .unwrap();

        let mut map: HashMap<ClientIdentity, Vec<u64>> = HashMap::new();

        // Each event now carries every index reserved by one `reserve_mask_index`/
        // `reserve_mask_indices` call, so a single event can satisfy several of the `n_inputs`
        // we're waiting for -- keep receiving events (not just `n_inputs` of them) until enough
        // indices have actually been seen.
        let mut received = 0u64;
        while received < n_inputs {
            if let Some(Ok(Event::ReservedInputEvent {
                client,
                reserved_indices,
            })) = sub.next().await
            {
                received += reserved_indices.len() as u64;
                map.entry(client).or_default().extend(reserved_indices);
            } else {
                return Err(CoordinatorError::JSONError(
                    "Subscription ended before event could be received".to_string(),
                ));
            }
        }

        Ok(map)
    }

    async fn wait_for_inputs(
        &self,
        n_inputs: u64,
        mask_shares: Vec<S>,
    ) -> Result<HashMap<ClientIdentity, Vec<S>>, CoordinatorError> {
        // Wait for masked input events.
        let mut sub = CoordinatorRPCBaseClient::sub_masked_inputs(self.rpc(), self.execution_id)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))?;

        let mut map: HashMap<ClientIdentity, Vec<(u64, S)>> = HashMap::new();

        // Each event now carries every (index, masked input) pair submitted by one
        // `submit_masked_input`/`submit_masked_inputs` call, so a single event can satisfy
        // several of the `n_inputs` we're waiting for -- keep receiving events (not just
        // `n_inputs` of them) until enough inputs have actually been seen.
        let mut received = 0u64;
        while received < n_inputs {
            if let Some(Ok(Event::MaskedInputEvent {
                client,
                masked_inputs,
            })) = sub.next().await
            {
                received += masked_inputs.len() as u64;
                for (reserved_index, masked_input) in masked_inputs {
                    let i = reserved_index as usize;
                    let mask_share = &mask_shares[i];
                    let masked_input =
                        S::ValueType::deserialize_compressed(masked_input.as_slice())
                            .map_err(|_| CoordinatorError::DeserializationError)?;
                    let input = S::compute_masked_input(masked_input, mask_share)
                        .map_err(|_| CoordinatorError::ShareError)?;

                    map.entry(client.clone())
                        .or_default()
                        .push((reserved_index, input));
                }
            } else {
                return Err(CoordinatorError::JSONError(
                    "Subscription ended before event could be received".to_string(),
                ));
            }
        }

        Ok(map
            .into_iter()
            .map(|(client, mut indexed_inputs)| {
                indexed_inputs.sort_by_key(|(reserved_index, _)| *reserved_index);
                let inputs = indexed_inputs
                    .into_iter()
                    .map(|(_, input)| input)
                    .collect::<Vec<_>>();
                (client, inputs)
            })
            .collect())
    }

    async fn wait_for_round(&self, round: Round) -> Result<(), CoordinatorError> {
        let mut sub = CoordinatorRPCBaseClient::sub_round(self.rpc(), self.execution_id, round)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))?;

        if let Some(Ok(_)) = sub.next().await {
            Ok(())
        } else {
            Err(CoordinatorError::JSONError(
                "Subscription ended before event could be received".to_string(),
            ))
        }
    }

    async fn send_masked_input(
        &self,
        masked_input: S::ValueType,
        i: u64,
    ) -> Result<(), CoordinatorError> {
        self.send_masked_inputs(&[(i, masked_input)]).await
    }

    async fn send_masked_inputs(
        &self,
        inputs: &[(u64, S::ValueType)],
    ) -> Result<(), CoordinatorError> {
        let mut reserved_indices = Vec::with_capacity(inputs.len());
        let mut masked_inputs = Vec::with_capacity(inputs.len());
        for (i, masked_input) in inputs {
            let mut masked_input_bytes = Vec::new();
            masked_input
                .serialize_compressed(&mut masked_input_bytes)
                .map_err(|_| CoordinatorError::SerializationError)?;
            reserved_indices.push(*i);
            masked_inputs.push(masked_input_bytes);
        }

        CoordinatorRPCBaseClient::submit_masked_inputs(
            self.rpc(),
            self.execution_id,
            masked_inputs,
            reserved_indices,
        )
        .await
        .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }

    async fn reserve_mask_index(&mut self, i: u64) -> Result<(), CoordinatorError> {
        self.reserve_mask_indices(&[i]).await
    }

    async fn reserve_mask_indices(&mut self, indices: &[u64]) -> Result<(), CoordinatorError> {
        CoordinatorRPCBaseClient::reserve_mask_indices(
            self.rpc(),
            self.execution_id,
            indices.to_vec(),
        )
        .await
        .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }

    async fn obtain_outputs(&self) -> Result<Vec<S::ValueType>, CoordinatorError> {
        // Wait for output shares.
        let mut sub =
            match CoordinatorRPCBaseClient::obtain_output_shares(self.rpc(), self.execution_id)
                .await
            {
                Ok(sub) => sub,
                Err(e) => {
                    return Err(CoordinatorError::JSONError(e.to_string()));
                }
            };

        // Parse the secret key for decryption.
        let client_sk = {
            let der_bytes = self.key_der.clone();
            let parsed_secret_key = SecretKey::from_pkcs8_der(&der_bytes)
                .map_err(|_| CoordinatorError::ParsingDERAsPKCS8Failed)?;
            let raw_sk = parsed_secret_key.to_bytes();

            <KemImpl as Kem>::PrivateKey::from_bytes(&raw_sk)
                .map_err(|_| CoordinatorError::ParsingPrivateKeyFailed)?
        };

        let enc_info = execution_enc_info(self.execution_id);

        // Try to decrypt and reconstruct outputs until it succeeds.
        while let Some(Ok(enc_output_shares)) = sub.next().await {
            let min_shares = S::min_shares(self.t as usize);
            if enc_output_shares.len() < min_shares {
                return Err(CoordinatorError::SubscriptionError(format!(
                    "Received {} output shares, but at least {} are required",
                    enc_output_shares.len(),
                    min_shares
                )));
            }

            let mut output_shares = Vec::new();
            for (encapped_key_bytes, c) in enc_output_shares.iter() {
                let encapped_key = <KemImpl as Kem>::EncappedKey::from_bytes(encapped_key_bytes)
                    .map_err(|_| CoordinatorError::ParsingEncapsulatedKeyFailed)?;
                let output_shares_bytes = single_shot_open::<AeadImpl, KdfImpl, KemImpl>(
                    &OpModeR::Base,
                    &client_sk,
                    &encapped_key,
                    &enc_info,
                    c,
                    b"",
                )
                .map_err(|_| CoordinatorError::DecryptionError)?;
                let shares: Vec<S> =
                    CanonicalDeserialize::deserialize_compressed(output_shares_bytes.as_slice())
                        .map_err(|_| CoordinatorError::DeserializationError)?;

                if shares.len() as u64 != self.n_outputs {
                    println!("Some node sent an invalid number of output shares, ignoring.");
                    continue;
                }

                output_shares.push(shares);
            }

            let outputs: Vec<_> = (0..self.n_outputs as usize)
                .filter_map(|i| {
                    // shares for the ith output
                    let shares_i: Vec<_> = output_shares
                        .iter()
                        .map(|shares| shares[i].clone())
                        .collect();

                    // At least S::min_shares(t) shares are available as checked above.
                    match S::recover_secret(&shares_i, self.n_parties as usize, self.t as usize) {
                        Ok((_, output_i)) => Some(output_i),
                        Err(_) => {
                            println!(
                                "Reconstruction failed for output {}, waiting for more shares.",
                                i
                            );
                            None
                        }
                    }
                })
                .collect();

            // Once all outputs have successfully been reconstructed, return them.
            if outputs.len() == self.n_outputs as usize {
                return Ok(outputs);
            }
        }

        Err(CoordinatorError::JSONError(
            "Output shares subscription ended before enough output shares could be obtained"
                .to_string(),
        ))
    }

    async fn send_output_shares(
        &self,
        client_id: Self::ClientIdentity,
        key: Vec<u8>,
        output_shares: Vec<S>,
    ) -> Result<(), CoordinatorError> {
        // Parse the inputs.
        let client_pk = <KemImpl as Kem>::PublicKey::from_bytes(&key)
            .map_err(|_| CoordinatorError::ParsingPublicKeyFailed)?;
        let mut output_shares_bytes = Vec::new();
        output_shares
            .serialize_compressed(&mut output_shares_bytes)
            .map_err(|_| CoordinatorError::SerializationError)?;

        // Encrypt the shares.
        let mut rng = StdRng::from_os_rng();
        let enc_info = execution_enc_info(self.execution_id);
        let (encapsulated_key, ciphertext) = single_shot_seal::<AeadImpl, KdfImpl, KemImpl, _>(
            &OpModeS::Base,
            &client_pk,
            &enc_info,
            &output_shares_bytes,
            b"",
            &mut rng,
        )
        .map_err(|_| CoordinatorError::EncryptionError)?;
        let c = (encapsulated_key.to_bytes().to_vec(), ciphertext);

        // Send the encrypted shares.
        if let Err(e) = CoordinatorRPCBaseClient::send_output_shares(
            self.rpc(),
            self.execution_id,
            client_id,
            c,
        )
        .await
        {
            return Err(CoordinatorError::JSONError(e.to_string()));
        }

        Ok(())
    }
}
