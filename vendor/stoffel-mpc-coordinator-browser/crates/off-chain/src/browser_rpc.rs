//! Polling JSON-RPC endpoints for browser clients.
//!
//! The existing off-chain transport uses a client certificate at the TLS layer,
//! which browsers cannot present to WebSockets. These endpoints preserve the
//! same P-256 public-key identity by authenticating each request envelope.

use crate::{
    node_rpc::NodeRPCServerInternal, AssignedMaskShare, ClientIdentity, CoordinatorRPCBaseServer,
    CoordinatorRPCServerConnectionBase, CoordinatorRPCServerSharedBase, Round,
};
use jsonrpsee::{
    core::RpcResult,
    server::{RpcModule, Server, ServerHandle},
    types::ErrorObjectOwned,
};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};
use stoffel_mpc_coordinator_shared::{CoordinatorError, ExecutionId};
use tokio::sync::Mutex;

const AUTH_DOMAIN: &[u8] = b"stoffel-browser-rpc-auth-v1";
const AUTH_ERROR: i32 = -32050;
const BAD_BODY: i32 = -32602;

#[derive(Clone, Debug, Deserialize)]
struct SignedBrowserRequest {
    public_key: Vec<u8>,
    nonce: u64,
    signature: Vec<u8>,
    body: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize)]
struct BrowserCall {
    execution_id: ExecutionId,
    request: SignedBrowserRequest,
}

#[derive(Clone, Debug, Deserialize)]
struct MaskRange {
    start: u64,
    count: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct MaskedInputBatch {
    reserved_indices: Vec<u64>,
    masked_inputs: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize)]
struct BrowserExecutionStatus {
    round: Round,
    input_indices: Vec<u64>,
    total_inputs: u64,
    reserved_inputs: u64,
    submitted_inputs: u64,
    total_clients: u64,
    submitted_clients: u64,
    own_input_reserved: bool,
    own_input_submitted: bool,
    output_ready: bool,
}

#[derive(Default)]
struct NonceBook {
    latest: HashMap<(ExecutionId, ClientIdentity), u64>,
}

impl NonceBook {
    fn accept(
        &mut self,
        execution_id: ExecutionId,
        identity: &ClientIdentity,
        nonce: u64,
    ) -> RpcResult<()> {
        let key = (execution_id, identity.clone());
        if self
            .latest
            .get(&key)
            .is_some_and(|latest| nonce <= *latest)
        {
            return Err(auth_error("request nonce was already used"));
        }
        self.latest.insert(key, nonce);
        Ok(())
    }
}

struct CoordinatorBrowserState {
    coordinator: Arc<Mutex<CoordinatorRPCServerSharedBase>>,
    nonces: Mutex<NonceBook>,
}

struct NodeBrowserState {
    node: Arc<Mutex<NodeRPCServerInternal>>,
    nonces: Mutex<NonceBook>,
}

pub(crate) async fn start_coordinator_browser_rpc(
    bind: &str,
    coordinator: Arc<Mutex<CoordinatorRPCServerSharedBase>>,
) -> Result<ServerHandle, CoordinatorError> {
    let server = Server::builder()
        .build(bind)
        .await
        .map_err(|error| CoordinatorError::BindError(format!("{bind}: {error}")))?;
    let state = Arc::new(CoordinatorBrowserState {
        coordinator,
        nonces: Mutex::new(NonceBook::default()),
    });
    let mut module = RpcModule::new(state);

    module
        .register_async_method::<RpcResult<BrowserExecutionStatus>, _, _>(
            "browser_execution_status",
            |params, state, _| async move {
                let call: BrowserCall = params.one()?;
                let identity =
                    authenticate("browser_execution_status", &call, &state.nonces).await?;
                state
                    .coordinator
                    .lock()
                    .await
                    .browser_execution_status(call.execution_id, &identity)
            },
        )
        .map_err(json_error)?;

    module
        .register_async_method::<RpcResult<Round>, _, _>(
            "browser_round",
            |params, state, _| async move {
                let call: BrowserCall = params.one()?;
                authenticate("browser_round", &call, &state.nonces).await?;
                state
                    .coordinator
                    .lock()
                    .await
                    .browser_round(call.execution_id)
            },
        )
        .map_err(json_error)?;

    module
        .register_async_method::<RpcResult<()>, _, _>(
            "browser_reserve_mask_indices",
            |params, state, _| async move {
                let call: BrowserCall = params.one()?;
                let identity =
                    authenticate("browser_reserve_mask_indices", &call, &state.nonces).await?;
                let indices: Vec<u64> = parse_body(&call.request.body)?;
                CoordinatorRPCServerConnectionBase::new(state.coordinator.clone(), identity)
                    .reserve_mask_indices(call.execution_id, indices)
                    .await
            },
        )
        .map_err(json_error)?;

    module
        .register_async_method::<RpcResult<()>, _, _>(
            "browser_submit_masked_inputs",
            |params, state, _| async move {
                let call: BrowserCall = params.one()?;
                let identity =
                    authenticate("browser_submit_masked_inputs", &call, &state.nonces).await?;
                let batch: MaskedInputBatch = parse_body(&call.request.body)?;
                CoordinatorRPCServerConnectionBase::new(state.coordinator.clone(), identity)
                    .submit_masked_inputs(
                        call.execution_id,
                        batch.masked_inputs,
                        batch.reserved_indices,
                    )
                    .await
            },
        )
        .map_err(json_error)?;

    module
        .register_async_method::<RpcResult<Option<Vec<(Vec<u8>, Vec<u8>)>>>, _, _>(
            "browser_output_shares",
            |params, state, _| async move {
                let call: BrowserCall = params.one()?;
                let identity = authenticate("browser_output_shares", &call, &state.nonces).await?;
                state
                    .coordinator
                    .lock()
                    .await
                    .browser_output_shares(call.execution_id, &identity)
            },
        )
        .map_err(json_error)?;

    Ok(server.start(module))
}

pub(crate) async fn start_node_browser_rpc(
    bind: &str,
    node: Arc<Mutex<NodeRPCServerInternal>>,
) -> Result<ServerHandle, CoordinatorError> {
    let server = Server::builder()
        .build(bind)
        .await
        .map_err(|error| CoordinatorError::BindError(format!("{bind}: {error}")))?;
    let state = Arc::new(NodeBrowserState {
        node,
        nonces: Mutex::new(NonceBook::default()),
    });
    let mut module = RpcModule::new(state);

    module
        .register_async_method::<RpcResult<Option<Vec<AssignedMaskShare>>>, _, _>(
            "browser_assigned_mask_shares",
            |params, state, _| async move {
                let call: BrowserCall = params.one()?;
                let identity =
                    authenticate("browser_assigned_mask_shares", &call, &state.nonces).await?;
                let range: MaskRange = parse_body(&call.request.body)?;
                let execution = state
                    .node
                    .lock()
                    .await
                    .execution_state(call.execution_id)
                    .ok_or_else(|| rpc_error(-32016, "execution is not registered"))?;
                let result = execution
                    .lock()
                    .await
                    .assigned_mask_shares_for_client(&identity, range.start, range.count)
                    .map_err(|error| rpc_error(-32051, error.to_string()))?;
                Ok(result)
            },
        )
        .map_err(json_error)?;

    Ok(server.start(module))
}

impl CoordinatorRPCServerSharedBase {
    fn browser_execution_status(
        &self,
        execution_id: ExecutionId,
        client: &ClientIdentity,
    ) -> RpcResult<BrowserExecutionStatus> {
        let execution = self
            .executions
            .get(&execution_id)
            .ok_or_else(|| rpc_error(-32016, "execution is not registered"))?;
        let input_indices = execution
            .input_assignments
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| {
                (execution.input_slot_client(slot) == Some(client)).then_some(index as u64)
            })
            .collect::<Vec<_>>();
        let authorized_for_output = execution.output_clients.contains(client);
        if input_indices.is_empty() && !authorized_for_output {
            return Err(rpc_error(
                -32012,
                "client is not assigned an input or authorized for output",
            ));
        }
        let own_input_reserved = !input_indices.is_empty()
            && input_indices
                .iter()
                .all(|index| execution.reserved_indices[*index as usize].as_ref() == Some(client));
        let own_input_submitted = !input_indices.is_empty()
            && input_indices
                .iter()
                .all(|index| execution.masked_inputs[*index as usize].is_some());
        let output_share_count = execution
            .output_shares
            .keys()
            .filter(|(candidate, _)| candidate == client)
            .count();
        let assigned_clients = execution
            .input_assignments
            .iter()
            .filter_map(|slot| execution.input_slot_client(slot).cloned())
            .collect::<std::collections::HashSet<_>>();
        let submitted_clients = assigned_clients
            .iter()
            .filter(|candidate| {
                execution
                    .input_assignments
                    .iter()
                    .enumerate()
                    .filter(|(_, slot)| execution.input_slot_client(slot) == Some(*candidate))
                    .all(|(index, _)| execution.masked_inputs[index].is_some())
            })
            .count() as u64;
        Ok(BrowserExecutionStatus {
            round: execution.round,
            input_indices,
            total_inputs: execution.registration.n_inputs,
            reserved_inputs: execution
                .reserved_indices
                .iter()
                .filter(|owner| owner.is_some())
                .count() as u64,
            submitted_inputs: execution
                .masked_inputs
                .iter()
                .filter(|input| input.is_some())
                .count() as u64,
            total_clients: assigned_clients.len() as u64,
            submitted_clients,
            own_input_reserved,
            own_input_submitted,
            output_ready: authorized_for_output
                && output_share_count >= execution.registration.min_output_shares as usize,
        })
    }

    fn browser_round(&self, execution_id: ExecutionId) -> RpcResult<Round> {
        self.executions
            .get(&execution_id)
            .map(|execution| execution.round)
            .ok_or_else(|| rpc_error(-32016, "execution is not registered"))
    }

    fn browser_output_shares(
        &self,
        execution_id: ExecutionId,
        client: &ClientIdentity,
    ) -> RpcResult<Option<Vec<(Vec<u8>, Vec<u8>)>>> {
        let execution = self
            .executions
            .get(&execution_id)
            .ok_or_else(|| rpc_error(-32016, "execution is not registered"))?;
        if !execution.output_clients.contains(client) {
            return Err(rpc_error(-32012, "client is not authorized for output"));
        }
        let shares = execution
            .output_shares
            .iter()
            .filter(|((candidate, _), _)| candidate == client)
            .map(|(_, shares)| shares.clone())
            .collect::<Vec<_>>();
        if shares.len() < execution.registration.min_output_shares as usize {
            return Ok(None);
        }
        Ok(Some(shares))
    }
}

async fn authenticate(
    method: &str,
    call: &BrowserCall,
    nonces: &Mutex<NonceBook>,
) -> RpcResult<ClientIdentity> {
    let key = VerifyingKey::from_sec1_bytes(&call.request.public_key)
        .map_err(|_| auth_error("invalid P-256 public key"))?;
    let signature = Signature::from_slice(&call.request.signature)
        .map_err(|_| auth_error("invalid P-256 signature"))?;
    let message = authentication_message(
        method,
        call.execution_id,
        call.request.nonce,
        &call.request.body,
    );
    key.verify(&message, &signature)
        .map_err(|_| auth_error("request signature did not verify"))?;
    nonces
        .lock()
        .await
        .accept(
            call.execution_id,
            &call.request.public_key,
            call.request.nonce,
        )?;
    Ok(call.request.public_key.clone())
}

fn authentication_message(
    method: &str,
    execution_id: ExecutionId,
    nonce: u64,
    body: &[u8],
) -> Vec<u8> {
    let body_hash = Sha256::digest(body);
    let mut message = Vec::with_capacity(
        AUTH_DOMAIN.len() + method.len() + execution_id.as_bytes().len() + body_hash.len() + 10,
    );
    message.extend_from_slice(AUTH_DOMAIN);
    message.push(0);
    message.extend_from_slice(method.as_bytes());
    message.push(0);
    message.extend_from_slice(execution_id.as_bytes());
    message.extend_from_slice(&nonce.to_le_bytes());
    message.extend_from_slice(&body_hash);
    message
}

fn parse_body<T: DeserializeOwned>(body: &[u8]) -> RpcResult<T> {
    serde_json::from_slice(body)
        .map_err(|error| rpc_error(BAD_BODY, format!("invalid signed request body: {error}")))
}

fn auth_error(message: impl Into<String>) -> ErrorObjectOwned {
    rpc_error(AUTH_ERROR, message)
}

fn rpc_error(code: i32, message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(code, message.into(), None::<()>)
}

fn json_error(error: impl std::fmt::Display) -> CoordinatorError {
    CoordinatorError::JSONError(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExecutionRegistration, InputAssignment, InputClientRange};

    fn execution_id() -> ExecutionId {
        ExecutionId::from_bytes([7; 32])
    }

    fn coordinator_with_two_browser_clients(
        client_a: ClientIdentity,
        client_b: ClientIdentity,
    ) -> CoordinatorRPCServerSharedBase {
        let mut coordinator =
            CoordinatorRPCServerSharedBase::new(3, 1, vec![vec![10], vec![11], vec![12]])
                .expect("valid topology");
        coordinator
            .register_execution(ExecutionRegistration {
                execution_id: execution_id(),
                program_hash: [9; 32],
                n_inputs: 2,
                output_clients: vec![client_a.clone(), client_b.clone()],
                input_assignment: InputAssignment {
                    clients: vec![client_a, client_b],
                    ranges: vec![
                        InputClientRange {
                            client_index: 0,
                            count: 1,
                        },
                        InputClientRange {
                            client_index: 1,
                            count: 1,
                        },
                    ],
                },
                min_output_shares: 3,
            })
            .expect("register execution");
        coordinator
            .executions
            .get_mut(&execution_id())
            .expect("execution")
            .round = Round::InputMaskReservation;
        coordinator
    }

    #[test]
    fn request_nonces_are_independent_between_executions() {
        let identity = vec![20];
        let first = ExecutionId::from_bytes([1; 32]);
        let second = ExecutionId::from_bytes([2; 32]);
        let mut nonces = NonceBook::default();

        nonces.accept(first, &identity, 1).expect("first request");
        nonces
            .accept(second, &identity, 1)
            .expect("same nonce in a different execution");
        assert!(nonces.accept(first, &identity, 1).is_err());
        nonces.accept(first, &identity, 2).expect("next request");
    }

    #[tokio::test]
    async fn two_browser_clients_are_bound_to_distinct_input_slots() {
        let client_a = vec![20];
        let client_b = vec![21];
        let shared = Arc::new(Mutex::new(coordinator_with_two_browser_clients(
            client_a.clone(),
            client_b.clone(),
        )));

        let a = CoordinatorRPCServerConnectionBase::new(shared.clone(), client_a.clone());
        let b = CoordinatorRPCServerConnectionBase::new(shared.clone(), client_b.clone());
        assert!(a
            .reserve_mask_indices(execution_id(), vec![1])
            .await
            .is_err());
        a.reserve_mask_indices(execution_id(), vec![0])
            .await
            .expect("Client A reserves its slot");
        b.reserve_mask_indices(execution_id(), vec![1])
            .await
            .expect("Client B reserves its slot");

        let coordinator = shared.lock().await;
        let a_status = coordinator
            .browser_execution_status(execution_id(), &client_a)
            .expect("Client A status");
        let b_status = coordinator
            .browser_execution_status(execution_id(), &client_b)
            .expect("Client B status");
        assert_eq!(a_status.input_indices, vec![0]);
        assert_eq!(b_status.input_indices, vec![1]);
        assert_eq!(a_status.reserved_inputs, 2);
        assert!(a_status.own_input_reserved);
        assert!(b_status.own_input_reserved);
        assert!(coordinator
            .browser_execution_status(execution_id(), &vec![99])
            .is_err());
    }
}
