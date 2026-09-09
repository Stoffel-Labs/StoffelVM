use crate::{
    CoordinatorRPCBaseServer, CoordinatorRPCServerConnectionBase, CoordinatorRPCServerSharedBase,
    OffChainCoordinatorClient, OffChainCoordinatorServer, StoffelCoordinatorRPCServer,
};
use async_trait::async_trait;
use jsonrpsee::{core::RpcResult, RpcModule};
use std::sync::Arc;
use stoffel_mpc_coordinator_shared::tests::fake_coord::{
    AvssShareType, AvssShareValueType, HoneyBadgerShareType, HoneyBadgerShareValueType,
};
use stoffel_mpc_coordinator_shared::{ExecutionId, Round};
use tokio::sync::Mutex;

pub type HoneyBadgerOffChainCoordinatorClient =
    OffChainCoordinatorClient<HoneyBadgerShareValueType, HoneyBadgerShareType>;
pub type AvssOffChainCoordinatorClient =
    OffChainCoordinatorClient<HoneyBadgerShareValueType, AvssShareType>;

pub type HoneyBadgerOffChainCoordinatorServer =
    OffChainCoordinatorServer<HoneyBadgerCoordinatorConnection>;
pub type HoneyBadgerCoordinatorRPCServerSharedBase = CoordinatorRPCServerSharedBase;
pub type AvssOffChainCoordinatorServer = OffChainCoordinatorServer<AvssCoordinatorConnection>;
pub type AvssCoordinatorRPCServerSharedBase = CoordinatorRPCServerSharedBase;

pub type HoneyBadgerNodeRPCClient =
    crate::node_rpc::NodeRPCClient<HoneyBadgerShareValueType, HoneyBadgerShareType>;
pub type AvssNodeRPCClient = crate::node_rpc::NodeRPCClient<AvssShareValueType, AvssShareType>;

pub type HoneyBadgerNodeRPCServer = crate::node_rpc::NodeRPCServer;
pub type AvssNodeRPCServer = crate::node_rpc::NodeRPCServer;

#[derive(Clone)]
pub struct CoordinatorConnection {
    base: CoordinatorRPCServerConnectionBase,
}

pub type HoneyBadgerCoordinatorConnection = CoordinatorConnection;
pub type AvssCoordinatorConnection = CoordinatorConnection;

impl stoffel_mpc_coordinator_shared::rpc::RPCServerConnection for CoordinatorConnection {
    type Internal = CoordinatorRPCServerSharedBase;

    fn new(internal: Arc<Mutex<Self::Internal>>, id: Vec<u8>) -> Self {
        Self {
            base: CoordinatorRPCServerConnectionBase::new(internal, id),
        }
    }

    fn into_rpc(self) -> RpcModule<Self> {
        let mut rpc = crate::StoffelCoordinatorRPCServer::into_rpc(self.clone());
        let base_rpc = crate::CoordinatorRPCBaseServer::into_rpc(self.base);
        rpc.merge(base_rpc).unwrap();
        rpc
    }
}

#[async_trait]
impl StoffelCoordinatorRPCServer for CoordinatorConnection {
    async fn start_preprocessing(&self, execution_id: ExecutionId) -> RpcResult<()> {
        self.base
            .transition(execution_id, Round::Preprocessing)
            .await
    }

    async fn reserve_input_masks(&self, execution_id: ExecutionId) -> RpcResult<()> {
        self.base
            .transition(execution_id, Round::InputMaskReservation)
            .await
    }

    async fn collect_inputs(&self, execution_id: ExecutionId) -> RpcResult<()> {
        self.base
            .transition(execution_id, Round::InputCollection)
            .await
    }

    async fn start_mpc(&self, execution_id: ExecutionId) -> RpcResult<()> {
        self.base
            .transition(execution_id, Round::MPCExecution)
            .await
    }

    async fn send_output(&self, execution_id: ExecutionId) -> RpcResult<()> {
        self.base
            .transition(execution_id, Round::OutputDistribution)
            .await
    }

    async fn finalize(&self, execution_id: ExecutionId) -> RpcResult<()> {
        self.base
            .transition(execution_id, Round::ProgramFinished)
            .await
    }
}
