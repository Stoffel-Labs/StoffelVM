use crate::core_vm::VirtualMachine;
use crate::net::client_store::ClientOutputShareCount;
use crate::net::curve::field_to_clear_share_value;
use crate::net::mpc_engine::{
    AsyncMpcEngine, MpcCapabilities, MpcEngine, MpcEngineClientOutput, MpcEngineError,
    MpcEngineMultiplication, MpcEngineResult, MpcSessionTopology,
};
use crate::net::open_registry::{InstanceRegistry, OpenMessageRouter};
use ark_bls12_381::{Fr, G1Projective};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use stoffel_vm_types::core_types::{ClearShareInput, ClearShareValue, ShareData, ShareType, Value};
use stoffel_vm_types::functions::VMFunction;
use stoffel_vm_types::instructions::Instruction;
use stoffelmpc_mpc::avss_mpc::triple_gen::BeaverTriple;
use stoffelmpc_mpc::avss_mpc::{AvssMPCClient, AvssMPCNode, AvssMPCNodeOpts, AvssSessionId};
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::share::avss::verify_feldman;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::common::{MPCProtocol, SecretSharingScheme};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::triple_gen::ShamirBeaverTriple;
use stoffelmpc_mpc::honeybadger::{
    HoneyBadgerMPCClient, HoneyBadgerMPCNode, HoneyBadgerMPCNodeOpts, SessionId as HbSessionId,
};
use stoffelnet::network_utils::{ClientId, Network, NetworkError, Node, PartyId, VerifiedOrdering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::Mutex;
use turmoil::net::{TcpListener, TcpStream};

type HbRbc = Avid<HbSessionId>;
type HbNode = HoneyBadgerMPCNode<Fr, HbRbc>;
type HbClient = HoneyBadgerMPCClient<Fr, HbRbc>;
type AvssRbc = Avid<AvssSessionId>;
type AvssNode = AvssMPCNode<Fr, AvssRbc, G1Projective>;
type AvssClient = AvssMPCClient<Fr, AvssRbc, G1Projective>;
type TestResult = Result<(), String>;

const N_PARTIES: usize = 4;
const THRESHOLD: usize = 1;
const INSTANCE_ID: u64 = 777;
const INPUT_CLIENT_ID: ClientId = 100;
const OUTPUT_CLIENT_ID: ClientId = 200;
const INPUT_VALUE: u64 = 7;
const INPUT_SQUARE: u64 = INPUT_VALUE * INPUT_VALUE;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum TurmoilSenderId {
    Node(PartyId),
    Client(ClientId),
}

impl TurmoilSenderId {
    fn id(self) -> usize {
        match self {
            Self::Node(id) | Self::Client(id) => id,
        }
    }
}

#[derive(Clone, Debug)]
struct VmTurmoilConfig {
    channel_buff_size: usize,
}

impl VmTurmoilConfig {
    fn new(channel_buff_size: usize) -> Self {
        Self { channel_buff_size }
    }
}

#[derive(Clone, Debug)]
struct VmTurmoilNode {
    id: PartyId,
}

impl VmTurmoilNode {
    fn new(id: PartyId) -> Self {
        Self { id }
    }
}

impl Node for VmTurmoilNode {
    fn id(&self) -> PartyId {
        self.id
    }

    fn scalar_id<F: Field>(&self) -> F {
        F::from(self.id as u64)
    }
}

#[derive(Clone)]
struct VmTurmoilInnerNetwork {
    config: VmTurmoilConfig,
    nodes: Vec<VmTurmoilNode>,
    hostnames: Vec<String>,
    ports: Vec<u16>,
    client_ids: Vec<ClientId>,
    client_hostnames: Vec<String>,
    client_ports: Vec<u16>,
}

impl VmTurmoilInnerNetwork {
    fn new(
        n_nodes: usize,
        client_ids: Vec<ClientId>,
        channel_buff_size: usize,
        base_port: u16,
        base_client_port: u16,
    ) -> Self {
        let nodes = (0..n_nodes).map(VmTurmoilNode::new).collect();
        let hostnames = (0..n_nodes).map(|i| format!("node{i}")).collect();
        let ports = (0..n_nodes).map(|i| base_port + i as u16).collect();
        let client_hostnames = client_ids.iter().map(|id| format!("client{id}")).collect();
        let client_ports = client_ids
            .iter()
            .enumerate()
            .map(|(i, _)| base_client_port + i as u16)
            .collect();

        Self {
            config: VmTurmoilConfig::new(channel_buff_size),
            nodes,
            hostnames,
            ports,
            client_ids,
            client_hostnames,
            client_ports,
        }
    }

    fn listen_addr(&self, id: PartyId) -> String {
        format!("0.0.0.0:{}", self.ports[id])
    }

    fn dial_addr(&self, id: PartyId) -> String {
        format!("{}:{}", self.hostnames[id], self.ports[id])
    }

    fn client_listen_addr(&self, client_id: ClientId) -> String {
        let idx = self
            .client_ids
            .iter()
            .position(|&id| id == client_id)
            .expect("test client id should be configured");
        format!("0.0.0.0:{}", self.client_ports[idx])
    }

    fn client_dial_addr(&self, client_id: ClientId) -> String {
        let idx = self
            .client_ids
            .iter()
            .position(|&id| id == client_id)
            .expect("test client id should be configured");
        format!("{}:{}", self.client_hostnames[idx], self.client_ports[idx])
    }
}

#[derive(Clone)]
struct VmTurmoilNetwork {
    sender: TurmoilSenderId,
    peers: HashMap<PartyId, Arc<Mutex<TcpStream>>>,
    client_streams: HashMap<ClientId, Arc<Mutex<TcpStream>>>,
    inner: VmTurmoilInnerNetwork,
    inbound_tx: Sender<(TurmoilSenderId, Vec<u8>)>,
}

impl VmTurmoilNetwork {
    async fn new(
        sender: TurmoilSenderId,
        inner: VmTurmoilInnerNetwork,
    ) -> (Self, Receiver<(TurmoilSenderId, Vec<u8>)>) {
        let (tx, rx) = mpsc::channel(inner.config.channel_buff_size);
        let my_addr = match sender {
            TurmoilSenderId::Node(id) => inner.listen_addr(id),
            TurmoilSenderId::Client(id) => inner.client_listen_addr(id),
        };
        tokio::spawn(start_listener(my_addr, tx.clone()));
        tokio::task::yield_now().await;

        let mut peers = HashMap::new();
        match sender {
            TurmoilSenderId::Node(id) => {
                for peer_id in 0..inner.nodes.len() {
                    if peer_id == id {
                        continue;
                    }
                    let stream = connect_with_handshake(sender, &inner.dial_addr(peer_id))
                        .await
                        .expect("node-to-node connection should be established");
                    peers.insert(peer_id, Arc::new(Mutex::new(stream)));
                }
            }
            TurmoilSenderId::Client(_) => {
                for node_id in 0..inner.nodes.len() {
                    let stream = connect_with_handshake(sender, &inner.dial_addr(node_id))
                        .await
                        .expect("client-to-node connection should be established");
                    peers.insert(node_id, Arc::new(Mutex::new(stream)));
                }
            }
        }

        let mut client_streams = HashMap::new();
        if matches!(sender, TurmoilSenderId::Node(_)) {
            for client_id in &inner.client_ids {
                let stream = connect_with_handshake(sender, &inner.client_dial_addr(*client_id))
                    .await
                    .expect("node-to-client connection should be established");
                client_streams.insert(*client_id, Arc::new(Mutex::new(stream)));
            }
        }

        (
            Self {
                sender,
                peers,
                client_streams,
                inner,
                inbound_tx: tx,
            },
            rx,
        )
    }

    async fn send_to_self(&self, message: &[u8]) -> Result<usize, NetworkError> {
        self.inbound_tx
            .send((self.sender, message.to_vec()))
            .await
            .map_err(|_| NetworkError::SendError)?;
        Ok(message.len())
    }
}

#[async_trait]
impl Network for VmTurmoilNetwork {
    type NodeType = VmTurmoilNode;
    type NetworkConfig = VmTurmoilConfig;

    async fn send(&self, recipient: PartyId, message: &[u8]) -> Result<usize, NetworkError> {
        if matches!(self.sender, TurmoilSenderId::Node(_)) && recipient == self.local_party_id() {
            return self.send_to_self(message).await;
        }

        let stream = self
            .peers
            .get(&recipient)
            .ok_or(NetworkError::PartyNotFound(recipient))?;
        write_frame(stream, message).await
    }

    async fn broadcast(&self, message: &[u8]) -> Result<usize, NetworkError> {
        let results = futures::future::join_all(
            (0..self.party_count()).map(|party| self.send(party, message)),
        )
        .await;
        if results.iter().any(Result::is_err) {
            return Err(NetworkError::SendError);
        }
        Ok(message.len())
    }

    fn parties(&self) -> Vec<&Self::NodeType> {
        self.inner.nodes.iter().collect()
    }

    fn parties_mut(&mut self) -> Vec<&mut Self::NodeType> {
        self.inner.nodes.iter_mut().collect()
    }

    fn config(&self) -> &Self::NetworkConfig {
        &self.inner.config
    }

    fn node(&self, id: PartyId) -> Option<&Self::NodeType> {
        self.inner.nodes.iter().find(|node| node.id == id)
    }

    fn node_mut(&mut self, id: PartyId) -> Option<&mut Self::NodeType> {
        self.inner.nodes.iter_mut().find(|node| node.id == id)
    }

    async fn send_to_client(
        &self,
        client: ClientId,
        message: &[u8],
    ) -> Result<usize, NetworkError> {
        if matches!(self.sender, TurmoilSenderId::Client(_)) {
            return Err(NetworkError::SendError);
        }
        let stream = self
            .client_streams
            .get(&client)
            .ok_or(NetworkError::ClientNotFound(client))?;
        write_frame(stream, message).await
    }

    fn clients(&self) -> Vec<ClientId> {
        self.inner.client_ids.clone()
    }

    fn is_client_connected(&self, client: ClientId) -> bool {
        self.inner.client_ids.contains(&client)
    }

    fn local_party_id(&self) -> PartyId {
        self.sender.id()
    }

    fn party_count(&self) -> usize {
        self.inner.nodes.len()
    }

    fn verified_ordering(&self) -> Option<VerifiedOrdering> {
        None
    }
}

async fn write_frame(
    stream: &Arc<Mutex<TcpStream>>,
    message: &[u8],
) -> Result<usize, NetworkError> {
    let mut stream = stream.lock().await;
    let len = (message.len() as u32).to_be_bytes();
    stream
        .write_all(&len)
        .await
        .map_err(|_| NetworkError::SendError)?;
    stream
        .write_all(message)
        .await
        .map_err(|_| NetworkError::SendError)?;
    stream.flush().await.map_err(|_| NetworkError::SendError)?;
    Ok(message.len())
}

async fn start_listener(addr: String, inbound: Sender<(TurmoilSenderId, Vec<u8>)>) {
    let listener = TcpListener::bind(addr)
        .await
        .expect("turmoil listener should bind");

    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            break;
        };
        let inbound = inbound.clone();
        tokio::spawn(async move {
            let mut id_buf = [0u8; 8];
            if socket.read_exact(&mut id_buf).await.is_err() {
                return;
            }

            let raw = u64::from_be_bytes(id_buf);
            let sender = if raw & (1u64 << 63) != 0 {
                TurmoilSenderId::Client((raw & !(1u64 << 63)) as ClientId)
            } else {
                TurmoilSenderId::Node(raw as PartyId)
            };

            loop {
                let mut len_buf = [0u8; 4];
                if socket.read_exact(&mut len_buf).await.is_err() {
                    break;
                }
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut message = vec![0u8; len];
                if socket.read_exact(&mut message).await.is_err() {
                    break;
                }
                if inbound.send((sender, message)).await.is_err() {
                    break;
                }
            }
        });
    }
}

async fn connect_with_handshake(
    sender: TurmoilSenderId,
    addr: &str,
) -> Result<TcpStream, NetworkError> {
    let handshake = match sender {
        TurmoilSenderId::Node(id) => id as u64,
        TurmoilSenderId::Client(id) => (1u64 << 63) | id as u64,
    };

    loop {
        match TcpStream::connect(addr).await {
            Ok(mut stream) => {
                stream
                    .write_all(&handshake.to_be_bytes())
                    .await
                    .map_err(|_| NetworkError::SendError)?;
                stream.flush().await.map_err(|_| NetworkError::SendError)?;
                return Ok(stream);
            }
            Err(_) => tokio::task::yield_now().await,
        }
    }
}

struct HbTurmoilVmEngine {
    topology: MpcSessionTopology,
    network: Arc<VmTurmoilNetwork>,
    node: Arc<Mutex<HbNode>>,
    open_registry: Arc<InstanceRegistry>,
}

impl HbTurmoilVmEngine {
    fn new(
        topology: MpcSessionTopology,
        network: Arc<VmTurmoilNetwork>,
        node: Arc<Mutex<HbNode>>,
        router: Arc<OpenMessageRouter>,
    ) -> Self {
        let open_registry = router.register_instance(topology.instance_id());
        Self {
            topology,
            network,
            node,
            open_registry,
        }
    }

    fn decode_share(bytes: &[u8]) -> Result<RobustShare<Fr>, String> {
        RobustShare::<Fr>::deserialize_compressed(bytes)
            .map_err(|error| format!("deserialize HB share: {error}"))
    }

    fn encode_share(share: &RobustShare<Fr>) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        share
            .serialize_compressed(&mut out)
            .map_err(|error| format!("serialize HB share: {error}"))?;
        Ok(out)
    }

    async fn broadcast_open_registry_payload(&self, payload: Vec<u8>) -> Result<(), String> {
        for party in 0..self.topology.n_parties() {
            if party == self.topology.party_id() {
                continue;
            }
            self.network
                .send(party, &payload)
                .await
                .map_err(|error| format!("send open registry payload to {party}: {error:?}"))?;
        }
        Ok(())
    }

    async fn clone_node(&self) -> HbNode {
        self.node.lock().await.clone()
    }
}

impl MpcEngine for HbTurmoilVmEngine {
    fn protocol_name(&self) -> &'static str {
        "hb-turmoil-vm-test"
    }

    fn topology(&self) -> MpcSessionTopology {
        self.topology
    }

    fn is_ready(&self) -> bool {
        true
    }

    fn start(&self) -> MpcEngineResult<()> {
        Ok(())
    }

    fn input_share(&self, _clear: ClearShareInput) -> MpcEngineResult<ShareData> {
        Err(MpcEngineError::operation_failed(
            "input_share",
            "sync input_share is not used by turmoil VM e2e tests",
        ))
    }

    fn open_share(&self, _ty: ShareType, _share_bytes: &[u8]) -> MpcEngineResult<ClearShareValue> {
        Err(MpcEngineError::operation_failed(
            "open_share",
            "sync open_share is not used by turmoil VM e2e tests",
        ))
    }

    fn capabilities(&self) -> MpcCapabilities {
        MpcCapabilities::MULTIPLICATION | MpcCapabilities::CLIENT_OUTPUT
    }

    fn as_multiplication(&self) -> Option<&dyn MpcEngineMultiplication> {
        Some(self)
    }

    fn as_client_output(&self) -> Option<&dyn MpcEngineClientOutput> {
        Some(self)
    }
}

impl MpcEngineMultiplication for HbTurmoilVmEngine {
    fn multiply_share(
        &self,
        _ty: ShareType,
        _left: &[u8],
        _right: &[u8],
    ) -> MpcEngineResult<ShareData> {
        Err(MpcEngineError::operation_failed(
            "multiply_share",
            "sync multiply_share is not used by turmoil VM e2e tests",
        ))
    }
}

impl MpcEngineClientOutput for HbTurmoilVmEngine {
    fn send_output_to_client(
        &self,
        _client_id: ClientId,
        _shares: &[u8],
        _output_share_count: ClientOutputShareCount,
    ) -> MpcEngineResult<()> {
        Err(MpcEngineError::operation_failed(
            "send_output_to_client",
            "sync send_output_to_client is not used by turmoil VM e2e tests",
        ))
    }
}

#[async_trait]
impl AsyncMpcEngine for HbTurmoilVmEngine {
    async fn multiply_share_async(
        &self,
        _ty: ShareType,
        left: &[u8],
        right: &[u8],
    ) -> MpcEngineResult<ShareData> {
        let left = Self::decode_share(left)
            .map_err(|error| MpcEngineError::operation_failed("decode_hb_left", error))?;
        let right = Self::decode_share(right)
            .map_err(|error| MpcEngineError::operation_failed("decode_hb_right", error))?;
        let mut node = self.clone_node().await;
        let result = node
            .mul(vec![left], vec![right], self.network.clone())
            .await
            .map_err(|error| MpcEngineError::operation_failed("hb_multiply", format!("{error:?}")))?
            .into_iter()
            .next()
            .ok_or_else(|| MpcEngineError::operation_failed("hb_multiply", "empty result"))?;
        let bytes = Self::encode_share(&result)
            .map_err(|error| MpcEngineError::operation_failed("encode_hb_share", error))?;
        Ok(ShareData::Opaque(bytes))
    }

    async fn open_share_async(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
    ) -> MpcEngineResult<ClearShareValue> {
        let type_key = format!("hb-vm-turmoil-open-{ty:?}");
        let wire_message = crate::net::open_registry::encode_single_share_wire_message(
            self.topology.instance_id(),
            &type_key,
            self.topology.party_id(),
            share_bytes,
        )
        .map_err(|error| MpcEngineError::operation_failed("hb_open_wire", error))?;
        self.broadcast_open_registry_payload(wire_message)
            .await
            .map_err(|error| MpcEngineError::operation_failed("hb_open_broadcast", error))?;

        let n = self.topology.n_parties();
        let t = self.topology.threshold();
        let required = 2 * t + 1;
        self.open_registry
            .open_share_async(
                self.topology.party_id(),
                type_key,
                share_bytes.to_vec(),
                required,
                |collected| {
                    let mut shares = Vec::with_capacity(collected.len());
                    for bytes in collected {
                        shares.push(Self::decode_share(bytes)?);
                    }
                    let (_, secret) = RobustShare::recover_secret(&shares, n, t)
                        .map_err(|error| format!("recover HB secret: {error:?}"))?;
                    field_to_clear_share_value(ty, secret).map_err(Into::into)
                },
            )
            .await
            .map_err(|error| MpcEngineError::operation_failed("hb_open", error))
    }

    async fn send_output_to_client_async(
        &self,
        client_id: ClientId,
        shares: &[u8],
        output_share_count: ClientOutputShareCount,
    ) -> MpcEngineResult<()> {
        let input_len = output_share_count.count();
        let output_shares = if input_len == 1 {
            vec![Self::decode_share(shares)
                .map_err(|error| MpcEngineError::operation_failed("decode_hb_output", error))?]
        } else {
            Vec::<RobustShare<Fr>>::deserialize_compressed(shares).map_err(|error| {
                MpcEngineError::operation_failed("decode_hb_outputs", error.to_string())
            })?
        };
        let node = self.clone_node().await;
        node.output
            .init(client_id, output_shares, input_len, self.network.clone())
            .await
            .map_err(|error| {
                MpcEngineError::operation_failed("hb_send_output", format!("{error:?}"))
            })
    }
}

struct AvssTurmoilVmEngine {
    topology: MpcSessionTopology,
    network: Arc<VmTurmoilNetwork>,
    node: Arc<Mutex<AvssNode>>,
    open_registry: Arc<InstanceRegistry>,
}

impl AvssTurmoilVmEngine {
    fn new(
        topology: MpcSessionTopology,
        network: Arc<VmTurmoilNetwork>,
        node: Arc<Mutex<AvssNode>>,
        router: Arc<OpenMessageRouter>,
    ) -> Self {
        let open_registry = router.register_instance(topology.instance_id());
        Self {
            topology,
            network,
            node,
            open_registry,
        }
    }

    fn decode_share(bytes: &[u8]) -> Result<FeldmanShamirShare<Fr, G1Projective>, String> {
        FeldmanShamirShare::<Fr, G1Projective>::deserialize_compressed(bytes)
            .map_err(|error| format!("deserialize AVSS Feldman share: {error}"))
    }

    fn encode_share(share: &FeldmanShamirShare<Fr, G1Projective>) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        share
            .serialize_compressed(&mut out)
            .map_err(|error| format!("serialize AVSS Feldman share: {error}"))?;
        Ok(out)
    }

    fn share_data(share: &FeldmanShamirShare<Fr, G1Projective>) -> Result<ShareData, String> {
        let data = Self::encode_share(share)?;
        let commitments = share
            .commitments
            .iter()
            .map(|commitment| {
                let mut out = Vec::new();
                commitment
                    .into_affine()
                    .serialize_compressed(&mut out)
                    .map_err(|error| format!("serialize AVSS commitment: {error}"))?;
                Ok(out)
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(ShareData::Feldman { data, commitments })
    }

    async fn broadcast_open_registry_payload(&self, payload: Vec<u8>) -> Result<(), String> {
        for party in 0..self.topology.n_parties() {
            if party == self.topology.party_id() {
                continue;
            }
            self.network
                .send(party, &payload)
                .await
                .map_err(|error| format!("send open registry payload to {party}: {error:?}"))?;
        }
        Ok(())
    }

    async fn clone_node(&self) -> AvssNode {
        self.node.lock().await.clone()
    }

    fn reconstruct_verified_secret(
        expected_share_bytes: &[u8],
        collected: &[Vec<u8>],
        n: usize,
        t: usize,
    ) -> Result<Fr, String> {
        let expected_share = Self::decode_share(expected_share_bytes)?;
        if !verify_feldman(expected_share.clone()) {
            return Err("local AVSS share failed Feldman verification".to_string());
        }

        let required_valid = t + 1;
        let mut verified = Vec::with_capacity(required_valid);
        for bytes in collected {
            let Ok(share) = Self::decode_share(bytes) else {
                continue;
            };
            if share.commitments != expected_share.commitments {
                continue;
            }
            if verify_feldman(share.clone()) {
                verified.push(share);
                if verified.len() == required_valid {
                    break;
                }
            }
        }

        if verified.len() < required_valid {
            return Err(format!(
                "only {} AVSS shares matched local commitments; need {required_valid}",
                verified.len()
            ));
        }
        let (_, secret) = FeldmanShamirShare::<Fr, G1Projective>::recover_secret(&verified, n, t)
            .map_err(|error| format!("recover AVSS secret: {error:?}"))?;
        Ok(secret)
    }
}

impl MpcEngine for AvssTurmoilVmEngine {
    fn protocol_name(&self) -> &'static str {
        "avss-turmoil-vm-test"
    }

    fn topology(&self) -> MpcSessionTopology {
        self.topology
    }

    fn is_ready(&self) -> bool {
        true
    }

    fn start(&self) -> MpcEngineResult<()> {
        Ok(())
    }

    fn input_share(&self, _clear: ClearShareInput) -> MpcEngineResult<ShareData> {
        Err(MpcEngineError::operation_failed(
            "input_share",
            "sync input_share is not used by turmoil VM e2e tests",
        ))
    }

    fn open_share(&self, _ty: ShareType, _share_bytes: &[u8]) -> MpcEngineResult<ClearShareValue> {
        Err(MpcEngineError::operation_failed(
            "open_share",
            "sync open_share is not used by turmoil VM e2e tests",
        ))
    }

    fn capabilities(&self) -> MpcCapabilities {
        MpcCapabilities::MULTIPLICATION | MpcCapabilities::CLIENT_OUTPUT
    }

    fn as_multiplication(&self) -> Option<&dyn MpcEngineMultiplication> {
        Some(self)
    }

    fn as_client_output(&self) -> Option<&dyn MpcEngineClientOutput> {
        Some(self)
    }
}

impl MpcEngineMultiplication for AvssTurmoilVmEngine {
    fn multiply_share(
        &self,
        _ty: ShareType,
        _left: &[u8],
        _right: &[u8],
    ) -> MpcEngineResult<ShareData> {
        Err(MpcEngineError::operation_failed(
            "multiply_share",
            "sync multiply_share is not used by turmoil VM e2e tests",
        ))
    }
}

impl MpcEngineClientOutput for AvssTurmoilVmEngine {
    fn send_output_to_client(
        &self,
        _client_id: ClientId,
        _shares: &[u8],
        _output_share_count: ClientOutputShareCount,
    ) -> MpcEngineResult<()> {
        Err(MpcEngineError::operation_failed(
            "send_output_to_client",
            "sync send_output_to_client is not used by turmoil VM e2e tests",
        ))
    }
}

#[async_trait]
impl AsyncMpcEngine for AvssTurmoilVmEngine {
    async fn multiply_share_async(
        &self,
        _ty: ShareType,
        left: &[u8],
        right: &[u8],
    ) -> MpcEngineResult<ShareData> {
        let left = Self::decode_share(left)
            .map_err(|error| MpcEngineError::operation_failed("decode_avss_left", error))?;
        let right = Self::decode_share(right)
            .map_err(|error| MpcEngineError::operation_failed("decode_avss_right", error))?;
        let mut node = self.clone_node().await;
        let result = node
            .mul(vec![left], vec![right], self.network.clone())
            .await
            .map_err(|error| {
                MpcEngineError::operation_failed("avss_multiply", format!("{error:?}"))
            })?
            .into_iter()
            .next()
            .ok_or_else(|| MpcEngineError::operation_failed("avss_multiply", "empty result"))?;
        let share_data = Self::share_data(&result)
            .map_err(|error| MpcEngineError::operation_failed("encode_avss_share", error))?;
        Ok(share_data)
    }

    async fn open_share_async(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
    ) -> MpcEngineResult<ClearShareValue> {
        let type_key = format!("avss-vm-turmoil-open-{ty:?}");
        let wire_message = crate::net::open_registry::encode_single_share_wire_message(
            self.topology.instance_id(),
            &type_key,
            self.topology.party_id(),
            share_bytes,
        )
        .map_err(|error| MpcEngineError::operation_failed("avss_open_wire", error))?;
        self.broadcast_open_registry_payload(wire_message)
            .await
            .map_err(|error| MpcEngineError::operation_failed("avss_open_broadcast", error))?;

        let n = self.topology.n_parties();
        let t = self.topology.threshold();
        let required = n - t;
        self.open_registry
            .open_share_async(
                self.topology.party_id(),
                type_key,
                share_bytes.to_vec(),
                required,
                |collected| {
                    let secret = Self::reconstruct_verified_secret(share_bytes, collected, n, t)?;
                    field_to_clear_share_value(ty, secret).map_err(Into::into)
                },
            )
            .await
            .map_err(|error| MpcEngineError::operation_failed("avss_open", error))
    }

    async fn send_output_to_client_async(
        &self,
        client_id: ClientId,
        shares: &[u8],
        output_share_count: ClientOutputShareCount,
    ) -> MpcEngineResult<()> {
        let input_len = output_share_count.count();
        let output_shares = if input_len == 1 {
            vec![Self::decode_share(shares)
                .map_err(|error| MpcEngineError::operation_failed("decode_avss_output", error))?]
        } else {
            Vec::<FeldmanShamirShare<Fr, G1Projective>>::deserialize_compressed(shares).map_err(
                |error| MpcEngineError::operation_failed("decode_avss_outputs", error.to_string()),
            )?
        };
        let node = self.clone_node().await;
        node.output_server
            .init(client_id, output_shares, input_len, self.network.clone())
            .await
            .map_err(|error| {
                MpcEngineError::operation_failed("avss_send_output", format!("{error:?}"))
            })
    }
}

fn share_ty() -> ShareType {
    ShareType::secret_int(64)
}

fn build_mul_open_vm_function() -> VMFunction {
    VMFunction::new(
        "mul_open".to_string(),
        vec!["left".to_string(), "right".to_string()],
        Vec::new(),
        None,
        2,
        vec![
            Instruction::PUSHARG(0),
            Instruction::PUSHARG(1),
            Instruction::CALL("Share.mul".to_string()),
            Instruction::PUSHARG(0),
            Instruction::CALL("Share.open".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    )
}

fn build_client_square_to_output_vm_function(output_client_id: ClientId) -> VMFunction {
    VMFunction::new(
        "client_square_to_output".to_string(),
        Vec::new(),
        Vec::new(),
        None,
        3,
        vec![
            Instruction::LDI(0, Value::I64(0)),
            Instruction::PUSHARG(0),
            Instruction::PUSHARG(0),
            Instruction::CALL("ClientStore.take_share".to_string()),
            Instruction::MOV(1, 0),
            Instruction::PUSHARG(1),
            Instruction::PUSHARG(1),
            Instruction::CALL("Share.mul".to_string()),
            Instruction::LDI(2, Value::I64(output_client_id as i64)),
            Instruction::PUSHARG(0),
            Instruction::PUSHARG(2),
            Instruction::CALL("Share.send_to_client".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    )
}

fn new_vm(runtime_engine: Arc<dyn MpcEngine>, function: VMFunction) -> VirtualMachine {
    let mut vm = VirtualMachine::builder()
        .with_mpc_engine(runtime_engine)
        .build();
    vm.register_function(function);
    vm
}

fn topology_for(party_id: PartyId) -> MpcSessionTopology {
    MpcSessionTopology::try_new(INSTANCE_ID, party_id, N_PARTIES, THRESHOLD)
        .expect("test topology should be valid")
}

fn hb_opts() -> HoneyBadgerMPCNodeOpts {
    HoneyBadgerMPCNodeOpts::new(
        N_PARTIES,
        THRESHOLD,
        2,
        1,
        INSTANCE_ID as u32,
        0,
        0,
        0,
        0,
        Duration::from_secs(30),
    )
    .expect("HB opts should be valid")
}

fn avss_opts(party_id: PartyId) -> AvssMPCNodeOpts<Fr, G1Projective> {
    let sk_i = Fr::from((party_id + 1) as u64);
    let pk_map = Arc::new(
        (0..N_PARTIES)
            .map(|idx| G1Projective::generator() * Fr::from((idx + 1) as u64))
            .collect(),
    );
    AvssMPCNodeOpts::new(
        N_PARTIES,
        THRESHOLD,
        1,
        2,
        sk_i,
        pk_map,
        INSTANCE_ID as u32,
        Duration::from_secs(30),
    )
    .expect("AVSS opts should be valid")
}

fn hb_shares(secret: u64, rng: &mut StdRng) -> Vec<RobustShare<Fr>> {
    RobustShare::compute_shares(Fr::from(secret), N_PARTIES, THRESHOLD, None, rng)
        .expect("HB shares should be generated")
}

fn avss_shares(secret: u64, rng: &mut StdRng) -> Vec<FeldmanShamirShare<Fr, G1Projective>> {
    let ids: Vec<_> = (1..=N_PARTIES).collect();
    FeldmanShamirShare::compute_shares(Fr::from(secret), N_PARTIES, THRESHOLD, Some(&ids), rng)
        .expect("AVSS shares should be generated")
}

fn hb_triples(count: usize, rng: &mut StdRng) -> Vec<Vec<ShamirBeaverTriple<Fr>>> {
    let mut per_party = vec![Vec::new(); N_PARTIES];
    for idx in 0..count {
        let a_secret = Fr::from(20 + idx as u64);
        let b_secret = Fr::from(90 + idx as u64);
        let c_secret = a_secret * b_secret;
        let shares_a = RobustShare::compute_shares(a_secret, N_PARTIES, THRESHOLD, None, rng)
            .expect("HB triple a shares should be generated");
        let shares_b = RobustShare::compute_shares(b_secret, N_PARTIES, THRESHOLD, None, rng)
            .expect("HB triple b shares should be generated");
        let shares_c = RobustShare::compute_shares(c_secret, N_PARTIES, THRESHOLD, None, rng)
            .expect("HB triple c shares should be generated");
        for party in 0..N_PARTIES {
            per_party[party].push(ShamirBeaverTriple::new(
                shares_a[party].clone(),
                shares_b[party].clone(),
                shares_c[party].clone(),
            ));
        }
    }
    per_party
}

fn avss_triples(count: usize, rng: &mut StdRng) -> Vec<Vec<BeaverTriple<Fr, G1Projective>>> {
    let mut per_party = vec![Vec::new(); N_PARTIES];
    let ids: Vec<_> = (1..=N_PARTIES).collect();
    for idx in 0..count {
        let a_secret = Fr::from(30 + idx as u64);
        let b_secret = Fr::from(70 + idx as u64);
        let c_secret = a_secret * b_secret;
        let shares_a =
            FeldmanShamirShare::compute_shares(a_secret, N_PARTIES, THRESHOLD, Some(&ids), rng)
                .expect("AVSS triple a shares should be generated");
        let shares_b =
            FeldmanShamirShare::compute_shares(b_secret, N_PARTIES, THRESHOLD, Some(&ids), rng)
                .expect("AVSS triple b shares should be generated");
        let shares_c =
            FeldmanShamirShare::compute_shares(c_secret, N_PARTIES, THRESHOLD, Some(&ids), rng)
                .expect("AVSS triple c shares should be generated");
        for party in 0..N_PARTIES {
            per_party[party].push(BeaverTriple {
                a: shares_a[party].clone(),
                b: shares_b[party].clone(),
                c: shares_c[party].clone(),
            });
        }
    }
    per_party
}

async fn create_hb_node(party_id: PartyId, input_ids: Vec<ClientId>) -> HbNode {
    <HbNode as MPCProtocol<Fr, RobustShare<Fr>, VmTurmoilNetwork>>::setup(
        party_id,
        hb_opts(),
        input_ids,
    )
    .expect("HB node should be created")
}

async fn create_avss_node(party_id: PartyId, input_ids: Vec<ClientId>) -> AvssNode {
    <AvssNode as MPCProtocol<Fr, FeldmanShamirShare<Fr, G1Projective>, VmTurmoilNetwork>>::setup(
        party_id,
        avss_opts(party_id),
        input_ids,
    )
    .expect("AVSS node should be created")
}

async fn process_hb_node_message(
    node: &Arc<Mutex<HbNode>>,
    router: &OpenMessageRouter,
    network: Arc<VmTurmoilNetwork>,
    sender: TurmoilSenderId,
    message: Vec<u8>,
) -> Result<(), String> {
    if router
        .try_handle_wire_message(sender.id(), &message)
        .map_err(|error| format!("HB open-router error: {error}"))?
    {
        return Ok(());
    }
    let mut node = node.lock().await;
    node.process(sender.id(), message, network)
        .await
        .map_err(|error| format!("HB node process error: {error:?}"))
}

async fn process_avss_node_message(
    node: &Arc<Mutex<AvssNode>>,
    router: &OpenMessageRouter,
    network: Arc<VmTurmoilNetwork>,
    sender: TurmoilSenderId,
    message: Vec<u8>,
) -> Result<(), String> {
    if router
        .try_handle_wire_message(sender.id(), &message)
        .map_err(|error| format!("AVSS open-router error: {error}"))?
    {
        return Ok(());
    }
    let mut node = node.lock().await;
    node.process(sender.id(), message, network)
        .await
        .map_err(|error| format!("AVSS node process error: {error:?}"))
}

async fn run_hb_vm_until_done(
    mut vm: VirtualMachine,
    engine: Arc<HbTurmoilVmEngine>,
    node: Arc<Mutex<HbNode>>,
    router: Arc<OpenMessageRouter>,
    network: Arc<VmTurmoilNetwork>,
    rx: &mut Receiver<(TurmoilSenderId, Vec<u8>)>,
    function: &'static str,
    args: Vec<Value>,
) -> Result<Value, String> {
    let future = vm.execute_async_with_args(function, &args, engine.as_ref());
    tokio::pin!(future);

    loop {
        tokio::select! {
            result = &mut future => {
                return result.map_err(|error| format!("HB VM execution failed: {error}"));
            }
            maybe_message = rx.recv() => {
                let Some((sender, message)) = maybe_message else {
                    return Err("HB turmoil receiver closed before VM completed".to_string());
                };
                process_hb_node_message(&node, &router, network.clone(), sender, message).await?;
            }
        }
    }
}

async fn run_avss_vm_until_done(
    mut vm: VirtualMachine,
    engine: Arc<AvssTurmoilVmEngine>,
    node: Arc<Mutex<AvssNode>>,
    router: Arc<OpenMessageRouter>,
    network: Arc<VmTurmoilNetwork>,
    rx: &mut Receiver<(TurmoilSenderId, Vec<u8>)>,
    function: &'static str,
    args: Vec<Value>,
) -> Result<Value, String> {
    let future = vm.execute_async_with_args(function, &args, engine.as_ref());
    tokio::pin!(future);

    loop {
        tokio::select! {
            result = &mut future => {
                return result.map_err(|error| format!("AVSS VM execution failed: {error}"));
            }
            maybe_message = rx.recv() => {
                let Some((sender, message)) = maybe_message else {
                    return Err("AVSS turmoil receiver closed before VM completed".to_string());
                };
                process_avss_node_message(&node, &router, network.clone(), sender, message).await?;
            }
        }
    }
}

fn turmoil_sim() -> turmoil::Sim<'static> {
    turmoil::Builder::new()
        .rng_seed(0x51_0ff_e1)
        .enable_random_order()
        .simulation_duration(Duration::from_secs(20))
        .min_message_latency(Duration::from_millis(1))
        .max_message_latency(Duration::from_millis(5))
        .build()
}

fn install_driver(
    sim: &mut turmoil::Sim<'static>,
    expected_reports: usize,
    mut done_rx: tokio::sync::broadcast::Receiver<()>,
) {
    sim.client("driver", async move {
        let mut count = 0;
        while count < expected_reports {
            if done_rx.recv().await.is_err() {
                break;
            }
            count += 1;
        }
        Ok(())
    });
}

fn collect_results(
    rx_done: std::sync::mpsc::Receiver<TestResult>,
    expected_reports: usize,
) -> TestResult {
    let results: Vec<_> = std::iter::from_fn(|| rx_done.try_recv().ok()).collect();
    if results.len() != expected_reports {
        return Err(format!(
            "not all turmoil hosts reported: got {}/{}",
            results.len(),
            expected_reports
        ));
    }
    for result in results {
        result?;
    }
    Ok(())
}

#[test]
fn hb_vm_turmoil_mul_open_e2e() {
    let mut rng = StdRng::seed_from_u64(0x4842);
    let left = hb_shares(6, &mut rng);
    let right = hb_shares(9, &mut rng);
    let triples = hb_triples(1, &mut rng);
    let inner = VmTurmoilInnerNetwork::new(N_PARTIES, Vec::new(), 512, 7000, 8000);
    let (tx, rx_done) = std::sync::mpsc::channel::<TestResult>();
    let (done_tx, done_rx) = tokio::sync::broadcast::channel(N_PARTIES);
    let barrier = Arc::new(tokio::sync::Barrier::new(N_PARTIES));
    let mut sim = turmoil_sim();

    for party_id in 0..N_PARTIES {
        let inner = inner.clone();
        let tx = tx.clone();
        let done_tx = done_tx.clone();
        let barrier = barrier.clone();
        let left_share = left[party_id].clone();
        let right_share = right[party_id].clone();
        let party_triples = triples[party_id].clone();

        sim.host(format!("node{party_id}"), move || {
            let inner = inner.clone();
            let tx = tx.clone();
            let done_tx = done_tx.clone();
            let barrier = barrier.clone();
            let left_share = left_share.clone();
            let right_share = right_share.clone();
            let party_triples = party_triples.clone();

            async move {
                let (network, mut rx) =
                    VmTurmoilNetwork::new(TurmoilSenderId::Node(party_id), inner).await;
                let network = Arc::new(network);
                let node = Arc::new(Mutex::new(create_hb_node(party_id, Vec::new()).await));
                node.lock().await.preprocessing_material.lock().await.add(
                    Some(party_triples),
                    None,
                    None,
                    None,
                );
                let router = Arc::new(OpenMessageRouter::new());
                let engine = Arc::new(HbTurmoilVmEngine::new(
                    topology_for(party_id),
                    network.clone(),
                    node.clone(),
                    router.clone(),
                ));
                let runtime_engine: Arc<dyn MpcEngine> = engine.clone();
                let vm = new_vm(runtime_engine, build_mul_open_vm_function());
                barrier.wait().await;

                let args = vec![
                    Value::Share(
                        share_ty(),
                        ShareData::Opaque(HbTurmoilVmEngine::encode_share(&left_share).unwrap()),
                    ),
                    Value::Share(
                        share_ty(),
                        ShareData::Opaque(HbTurmoilVmEngine::encode_share(&right_share).unwrap()),
                    ),
                ];
                let result = run_hb_vm_until_done(
                    vm, engine, node, router, network, &mut rx, "mul_open", args,
                )
                .await;

                let report = match result {
                    Ok(Value::I64(54)) => Ok(()),
                    Ok(value) => Err(format!("HB VM returned unexpected value: {value:?}")),
                    Err(error) => Err(error),
                };
                let _ = tx.send(report);
                let _ = done_tx.send(());
                Ok(())
            }
        });
    }

    drop(tx);
    drop(done_tx);
    install_driver(&mut sim, N_PARTIES, done_rx);
    sim.run().expect("HB turmoil VM sim should complete");
    collect_results(rx_done, N_PARTIES).expect("HB turmoil VM results should pass");
}

#[test]
fn avss_vm_turmoil_mul_open_e2e() {
    let mut rng = StdRng::seed_from_u64(0xa555);
    let left = avss_shares(6, &mut rng);
    let right = avss_shares(9, &mut rng);
    let triples = avss_triples(1, &mut rng);
    let inner = VmTurmoilInnerNetwork::new(N_PARTIES, Vec::new(), 512, 7100, 8100);
    let (tx, rx_done) = std::sync::mpsc::channel::<TestResult>();
    let (done_tx, done_rx) = tokio::sync::broadcast::channel(N_PARTIES);
    let barrier = Arc::new(tokio::sync::Barrier::new(N_PARTIES));
    let mut sim = turmoil_sim();

    for party_id in 0..N_PARTIES {
        let inner = inner.clone();
        let tx = tx.clone();
        let done_tx = done_tx.clone();
        let barrier = barrier.clone();
        let left_share = left[party_id].clone();
        let right_share = right[party_id].clone();
        let party_triples = triples[party_id].clone();

        sim.host(format!("node{party_id}"), move || {
            let inner = inner.clone();
            let tx = tx.clone();
            let done_tx = done_tx.clone();
            let barrier = barrier.clone();
            let left_share = left_share.clone();
            let right_share = right_share.clone();
            let party_triples = party_triples.clone();

            async move {
                let (network, mut rx) =
                    VmTurmoilNetwork::new(TurmoilSenderId::Node(party_id), inner).await;
                let network = Arc::new(network);
                let node = Arc::new(Mutex::new(create_avss_node(party_id, Vec::new()).await));
                node.lock()
                    .await
                    .preprocessing_material
                    .lock()
                    .await
                    .add(Some(party_triples), None);
                let router = Arc::new(OpenMessageRouter::new());
                let engine = Arc::new(AvssTurmoilVmEngine::new(
                    topology_for(party_id),
                    network.clone(),
                    node.clone(),
                    router.clone(),
                ));
                let runtime_engine: Arc<dyn MpcEngine> = engine.clone();
                let vm = new_vm(runtime_engine, build_mul_open_vm_function());
                barrier.wait().await;

                let args = vec![
                    Value::Share(
                        share_ty(),
                        AvssTurmoilVmEngine::share_data(&left_share).unwrap(),
                    ),
                    Value::Share(
                        share_ty(),
                        AvssTurmoilVmEngine::share_data(&right_share).unwrap(),
                    ),
                ];
                let result = run_avss_vm_until_done(
                    vm, engine, node, router, network, &mut rx, "mul_open", args,
                )
                .await;

                let report = match result {
                    Ok(Value::I64(54)) => Ok(()),
                    Ok(value) => Err(format!("AVSS VM returned unexpected value: {value:?}")),
                    Err(error) => Err(error),
                };
                let _ = tx.send(report);
                let _ = done_tx.send(());
                Ok(())
            }
        });
    }

    drop(tx);
    drop(done_tx);
    install_driver(&mut sim, N_PARTIES, done_rx);
    sim.run().expect("AVSS turmoil VM sim should complete");
    collect_results(rx_done, N_PARTIES).expect("AVSS turmoil VM results should pass");
}

#[test]
fn hb_vm_turmoil_full_client_flow_e2e() {
    let mut rng = StdRng::seed_from_u64(0x1001);
    let input_masks = hb_shares(11, &mut rng);
    let triples = hb_triples(1, &mut rng);
    let inner = VmTurmoilInnerNetwork::new(
        N_PARTIES,
        vec![INPUT_CLIENT_ID, OUTPUT_CLIENT_ID],
        512,
        7200,
        8200,
    );
    let (tx, rx_done) = std::sync::mpsc::channel::<TestResult>();
    let expected_reports = N_PARTIES + 2;
    let (done_tx, done_rx) = tokio::sync::broadcast::channel(expected_reports);
    let barrier = Arc::new(tokio::sync::Barrier::new(expected_reports));
    let mut sim = turmoil_sim();

    install_hb_input_client(
        &mut sim,
        inner.clone(),
        tx.clone(),
        done_tx.clone(),
        barrier.clone(),
    );
    install_hb_output_client(
        &mut sim,
        inner.clone(),
        tx.clone(),
        done_tx.clone(),
        barrier.clone(),
        Fr::from(INPUT_SQUARE),
    );

    for party_id in 0..N_PARTIES {
        let inner = inner.clone();
        let tx = tx.clone();
        let done_tx = done_tx.clone();
        let barrier = barrier.clone();
        let input_mask = input_masks[party_id].clone();
        let party_triples = triples[party_id].clone();

        sim.host(format!("node{party_id}"), move || {
            let inner = inner.clone();
            let tx = tx.clone();
            let done_tx = done_tx.clone();
            let barrier = barrier.clone();
            let input_mask = input_mask.clone();
            let party_triples = party_triples.clone();

            async move {
                let report = async {
                    let (network, mut rx) =
                        VmTurmoilNetwork::new(TurmoilSenderId::Node(party_id), inner).await;
                    let network = Arc::new(network);
                    let node = Arc::new(Mutex::new(
                        create_hb_node(party_id, vec![INPUT_CLIENT_ID]).await,
                    ));
                    node.lock()
                        .await
                        .preprocessing_material
                        .lock()
                        .await
                        .add(Some(party_triples), None, None, None);
                    let router = Arc::new(OpenMessageRouter::new());
                    let engine = Arc::new(HbTurmoilVmEngine::new(
                        topology_for(party_id),
                        network.clone(),
                        node.clone(),
                        router.clone(),
                    ));
                    let runtime_engine: Arc<dyn MpcEngine> = engine.clone();
                    let vm =
                        new_vm(runtime_engine, build_client_square_to_output_vm_function(OUTPUT_CLIENT_ID));
                    barrier.wait().await;

                    {
                        let mut node_guard = node.lock().await;
                        node_guard
                            .preprocess
                            .input
                            .init(INPUT_CLIENT_ID, vec![input_mask], 1, network.clone())
                            .await
                            .map_err(|error| format!("HB input init failed: {error:?}"))?;
                    }

                    let mut wait_node = node.lock().await.clone();
                    let input_future = wait_node
                        .preprocess
                        .input
                        .wait_for_all_inputs(Duration::from_secs(10));
                    tokio::pin!(input_future);
                    let inputs = loop {
                        tokio::select! {
                            result = &mut input_future => {
                                break result.map_err(|error| format!("HB input wait failed: {error:?}"))?;
                            }
                            maybe_message = rx.recv() => {
                                let Some((sender, message)) = maybe_message else {
                                    return Err("HB node receiver closed during input".to_string());
                                };
                                process_hb_node_message(&node, &router, network.clone(), sender, message).await?;
                            }
                        }
                    };
                    vm.try_store_client_input(
                        INPUT_CLIENT_ID,
                        inputs
                            .get(&INPUT_CLIENT_ID)
                            .cloned()
                            .ok_or_else(|| "HB input client shares missing".to_string())?,
                    )
                    .map_err(|error| format!("HB VM client-store hydration failed: {error}"))?;

                    let value = run_hb_vm_until_done(
                        vm,
                        engine,
                        node,
                        router,
                        network,
                        &mut rx,
                        "client_square_to_output",
                        Vec::new(),
                    )
                    .await?;
                    match value {
                        Value::Bool(true) | Value::Unit => Ok(()),
                        other => Err(format!("HB full-flow VM returned unexpected value: {other:?}")),
                    }
                }
                .await;

                let _ = tx.send(report);
                let _ = done_tx.send(());
                Ok(())
            }
        });
    }

    drop(tx);
    drop(done_tx);
    install_driver(&mut sim, expected_reports, done_rx);
    sim.run()
        .expect("HB full-client turmoil VM sim should complete");
    collect_results(rx_done, expected_reports).expect("HB full-client turmoil VM should pass");
}

#[test]
fn avss_vm_turmoil_full_client_flow_e2e() {
    let mut rng = StdRng::seed_from_u64(0xa001);
    let input_masks = avss_shares(11, &mut rng);
    let triples = avss_triples(1, &mut rng);
    let inner = VmTurmoilInnerNetwork::new(
        N_PARTIES,
        vec![INPUT_CLIENT_ID, OUTPUT_CLIENT_ID],
        512,
        7300,
        8300,
    );
    let (tx, rx_done) = std::sync::mpsc::channel::<TestResult>();
    let expected_reports = N_PARTIES + 2;
    let (done_tx, done_rx) = tokio::sync::broadcast::channel(expected_reports);
    let barrier = Arc::new(tokio::sync::Barrier::new(expected_reports));
    let mut sim = turmoil_sim();

    install_avss_input_client(
        &mut sim,
        inner.clone(),
        tx.clone(),
        done_tx.clone(),
        barrier.clone(),
    );
    install_avss_output_client(
        &mut sim,
        inner.clone(),
        tx.clone(),
        done_tx.clone(),
        barrier.clone(),
        Fr::from(INPUT_SQUARE),
    );

    for party_id in 0..N_PARTIES {
        let inner = inner.clone();
        let tx = tx.clone();
        let done_tx = done_tx.clone();
        let barrier = barrier.clone();
        let input_mask = input_masks[party_id].clone();
        let party_triples = triples[party_id].clone();

        sim.host(format!("node{party_id}"), move || {
            let inner = inner.clone();
            let tx = tx.clone();
            let done_tx = done_tx.clone();
            let barrier = barrier.clone();
            let input_mask = input_mask.clone();
            let party_triples = party_triples.clone();

            async move {
                let report = async {
                    let (network, mut rx) =
                        VmTurmoilNetwork::new(TurmoilSenderId::Node(party_id), inner).await;
                    let network = Arc::new(network);
                    let node = Arc::new(Mutex::new(
                        create_avss_node(party_id, vec![INPUT_CLIENT_ID]).await,
                    ));
                    node.lock()
                        .await
                        .preprocessing_material
                        .lock()
                        .await
                        .add(Some(party_triples), None);
                    let router = Arc::new(OpenMessageRouter::new());
                    let engine = Arc::new(AvssTurmoilVmEngine::new(
                        topology_for(party_id),
                        network.clone(),
                        node.clone(),
                        router.clone(),
                    ));
                    let runtime_engine: Arc<dyn MpcEngine> = engine.clone();
                    let vm =
                        new_vm(runtime_engine, build_client_square_to_output_vm_function(OUTPUT_CLIENT_ID));
                    barrier.wait().await;

                    {
                        let mut node_guard = node.lock().await;
                        node_guard
                            .input_server
                            .init(INPUT_CLIENT_ID, vec![input_mask], 1, network.clone())
                            .await
                            .map_err(|error| format!("AVSS input init failed: {error:?}"))?;
                    }

                    let mut wait_node = node.lock().await.clone();
                    let input_future = wait_node
                        .input_server
                        .wait_for_all_inputs(Duration::from_secs(10));
                    tokio::pin!(input_future);
                    let inputs = loop {
                        tokio::select! {
                            result = &mut input_future => {
                                break result.map_err(|error| format!("AVSS input wait failed: {error:?}"))?;
                            }
                            maybe_message = rx.recv() => {
                                let Some((sender, message)) = maybe_message else {
                                    return Err("AVSS node receiver closed during input".to_string());
                                };
                                process_avss_node_message(&node, &router, network.clone(), sender, message).await?;
                            }
                        }
                    };
                    vm.try_store_client_input_feldman(
                        INPUT_CLIENT_ID,
                        inputs
                            .get(&INPUT_CLIENT_ID)
                            .cloned()
                            .ok_or_else(|| "AVSS input client shares missing".to_string())?,
                    )
                    .map_err(|error| format!("AVSS VM client-store hydration failed: {error}"))?;

                    let value = run_avss_vm_until_done(
                        vm,
                        engine,
                        node,
                        router,
                        network,
                        &mut rx,
                        "client_square_to_output",
                        Vec::new(),
                    )
                    .await?;
                    match value {
                        Value::Bool(true) | Value::Unit => Ok(()),
                        other => Err(format!("AVSS full-flow VM returned unexpected value: {other:?}")),
                    }
                }
                .await;

                let _ = tx.send(report);
                let _ = done_tx.send(());
                Ok(())
            }
        });
    }

    drop(tx);
    drop(done_tx);
    install_driver(&mut sim, expected_reports, done_rx);
    sim.run()
        .expect("AVSS full-client turmoil VM sim should complete");
    collect_results(rx_done, expected_reports).expect("AVSS full-client turmoil VM should pass");
}

fn install_hb_input_client(
    sim: &mut turmoil::Sim<'static>,
    inner: VmTurmoilInnerNetwork,
    tx: std::sync::mpsc::Sender<TestResult>,
    done_tx: tokio::sync::broadcast::Sender<()>,
    barrier: Arc<tokio::sync::Barrier>,
) {
    sim.host(format!("client{INPUT_CLIENT_ID}"), move || {
        let inner = inner.clone();
        let tx = tx.clone();
        let done_tx = done_tx.clone();
        let barrier = barrier.clone();

        async move {
            let report = async {
                let (network, mut rx) =
                    VmTurmoilNetwork::new(TurmoilSenderId::Client(INPUT_CLIENT_ID), inner).await;
                let network = Arc::new(network);
                let mut client = HbClient::new(
                    INPUT_CLIENT_ID,
                    N_PARTIES,
                    THRESHOLD,
                    INSTANCE_ID as u32,
                    vec![Fr::from(INPUT_VALUE)],
                    1,
                )
                .map_err(|error| format!("HB input client creation failed: {error:?}"))?;
                barrier.wait().await;

                let mut processed = 0usize;
                loop {
                    let Some((sender, message)) = rx.recv().await else {
                        return Err("HB input client receiver closed".to_string());
                    };
                    client
                        .process(sender.id(), message, network.clone())
                        .await
                        .map_err(|error| format!("HB input client process failed: {error:?}"))?;
                    processed += 1;
                    if processed >= N_PARTIES {
                        return if client.input.client_data.lock().await.rbc_done {
                            Ok(())
                        } else {
                            Err("HB input client processed all mask shares but never broadcast masked input".to_string())
                        };
                    }
                }
            }
            .await;

            let _ = tx.send(report);
            let _ = done_tx.send(());
            Ok(())
        }
    });
}

fn install_hb_output_client(
    sim: &mut turmoil::Sim<'static>,
    inner: VmTurmoilInnerNetwork,
    tx: std::sync::mpsc::Sender<TestResult>,
    done_tx: tokio::sync::broadcast::Sender<()>,
    barrier: Arc<tokio::sync::Barrier>,
    expected_output: Fr,
) {
    sim.host(format!("client{OUTPUT_CLIENT_ID}"), move || {
        let inner = inner.clone();
        let tx = tx.clone();
        let done_tx = done_tx.clone();
        let barrier = barrier.clone();

        async move {
            let report = async {
                let (network, mut rx) =
                    VmTurmoilNetwork::new(TurmoilSenderId::Client(OUTPUT_CLIENT_ID), inner).await;
                let network = Arc::new(network);
                let mut client = HbClient::new(
                    OUTPUT_CLIENT_ID,
                    N_PARTIES,
                    THRESHOLD,
                    INSTANCE_ID as u32,
                    Vec::new(),
                    1,
                )
                .map_err(|error| format!("HB output client creation failed: {error:?}"))?;
                barrier.wait().await;

                loop {
                    let Some((sender, message)) = rx.recv().await else {
                        return Err("HB output client receiver closed".to_string());
                    };
                    client
                        .process(sender.id(), message, network.clone())
                        .await
                        .map_err(|error| format!("HB output client process failed: {error:?}"))?;
                    if let Some(output) = client.output.get_output() {
                        return if output == vec![expected_output] {
                            Ok(())
                        } else {
                            Err(format!(
                                "HB output mismatch: got {output:?}, expected {expected_output:?}"
                            ))
                        };
                    }
                }
            }
            .await;

            let _ = tx.send(report);
            let _ = done_tx.send(());
            Ok(())
        }
    });
}

fn install_avss_input_client(
    sim: &mut turmoil::Sim<'static>,
    inner: VmTurmoilInnerNetwork,
    tx: std::sync::mpsc::Sender<TestResult>,
    done_tx: tokio::sync::broadcast::Sender<()>,
    barrier: Arc<tokio::sync::Barrier>,
) {
    sim.host(format!("client{INPUT_CLIENT_ID}"), move || {
        let inner = inner.clone();
        let tx = tx.clone();
        let done_tx = done_tx.clone();
        let barrier = barrier.clone();

        async move {
            let report = async {
                let (network, mut rx) =
                    VmTurmoilNetwork::new(TurmoilSenderId::Client(INPUT_CLIENT_ID), inner).await;
                let network = Arc::new(network);
                let mut client = AvssClient::new(
                    INPUT_CLIENT_ID,
                    N_PARTIES,
                    THRESHOLD,
                    INSTANCE_ID as u32,
                    vec![Fr::from(INPUT_VALUE)],
                    1,
                )
                .map_err(|error| format!("AVSS input client creation failed: {error:?}"))?;
                barrier.wait().await;

                let mut processed = 0usize;
                loop {
                    let Some((sender, message)) = rx.recv().await else {
                        return Err("AVSS input client receiver closed".to_string());
                    };
                    client
                        .process(sender.id(), message, network.clone())
                        .await
                        .map_err(|error| format!("AVSS input client process failed: {error:?}"))?;
                    processed += 1;
                    if processed >= N_PARTIES {
                        return Ok(());
                    }
                }
            }
            .await;

            let _ = tx.send(report);
            let _ = done_tx.send(());
            Ok(())
        }
    });
}

fn install_avss_output_client(
    sim: &mut turmoil::Sim<'static>,
    inner: VmTurmoilInnerNetwork,
    tx: std::sync::mpsc::Sender<TestResult>,
    done_tx: tokio::sync::broadcast::Sender<()>,
    barrier: Arc<tokio::sync::Barrier>,
    expected_output: Fr,
) {
    sim.host(format!("client{OUTPUT_CLIENT_ID}"), move || {
        let inner = inner.clone();
        let tx = tx.clone();
        let done_tx = done_tx.clone();
        let barrier = barrier.clone();

        async move {
            let report = async {
                let (network, mut rx) =
                    VmTurmoilNetwork::new(TurmoilSenderId::Client(OUTPUT_CLIENT_ID), inner).await;
                let network = Arc::new(network);
                let mut client = AvssClient::new(
                    OUTPUT_CLIENT_ID,
                    N_PARTIES,
                    THRESHOLD,
                    INSTANCE_ID as u32,
                    Vec::new(),
                    1,
                )
                .map_err(|error| format!("AVSS output client creation failed: {error:?}"))?;
                barrier.wait().await;

                loop {
                    let Some((sender, message)) = rx.recv().await else {
                        return Err("AVSS output client receiver closed".to_string());
                    };
                    client
                        .process(sender.id(), message, network.clone())
                        .await
                        .map_err(|error| format!("AVSS output client process failed: {error:?}"))?;
                    if let Some(output) = client.output.get_output() {
                        return if output == vec![expected_output] {
                            Ok(())
                        } else {
                            Err(format!(
                                "AVSS output mismatch: got {output:?}, expected {expected_output:?}"
                            ))
                        };
                    }
                }
            }
            .await;

            let _ = tx.send(report);
            let _ = done_tx.send(());
            Ok(())
        }
    });
}
