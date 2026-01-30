use std::env;
use std::net::SocketAddr;
use std::process::exit;

use ark_bls12_381::Fr;
use ark_ff::{PrimeField, BigInteger};
use ark_serialize::CanonicalSerialize;
use std::fs::File;
use std::sync::Arc;
use std::str::FromStr;
use stoffel_vm::core_vm::VirtualMachine;
use stoffel_vm::net::hb_engine::HoneyBadgerMpcEngine;
use stoffel_vm::net::{
    honeybadger_node_opts, program_id_from_bytes, register_and_wait_for_session_with_program,
    run_bootnode_with_config, spawn_receive_loops,
};
use stoffel_vm::runtime_hooks::{HookContext, HookEvent};
use stoffel_vm::vm_state::VMState;
use stoffel_vm_types::{core_types::{ShareType, Value}, compiled_binary::CompiledBinary};
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::MPCProtocol;
use stoffelmpc_mpc::common::SecretSharingScheme;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::{HoneyBadgerMPCClient, HoneyBadgerMPCNode};
use stoffelnet::network_utils::ClientId;
use stoffelnet::network_utils::Network;
use stoffelnet::transports::quic::{NetworkManager, QuicNetworkConfig, QuicNetworkManager};
use tokio::sync::{mpsc, Semaphore, Mutex};
use tokio::time::{Duration, timeout};
use alloy::{
    sol_types::{SolValue, SolEvent},
    providers::{Provider, ProviderBuilder, WsConnect},
    rpc::types::{BlockNumberOrTag, Filter},
    signers::local::PrivateKeySigner,
    network::EthereumWallet,
    signers::Signer
};
use alloy_primitives::{U256, address, Address, Signature, Bytes, Keccak256, FixedBytes};
use stoffel_solidity_bindings::{
    fake_coordinator::FakeCoordinator::{CoordinatorInitialized, PreprocessingRoundExecuted, ClientInputMaskReservationEvent, MPCTaskExecuted, RoleAdminChanged, RoleGranted, RoleRevoked, OwnershipTransferred},
    fake_coordinator::FakeCoordinator::{IndexBufferEvent, MaskedInputEvent, ReservedInputEvent},
    fake_coordinator::FakeCoordinator::FakeCoordinatorInstance,
    fake_coordinator::FakeCoordinator
};
use futures_util::stream::StreamExt;
use serde::{Serialize, Deserialize};
use dashmap::DashMap;
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ClientSig {
    client_id: ClientId,
    i: U256,
    sig: Vec<u8>,
}

async fn generate_client_sig(i: U256, signer: PrivateKeySigner) -> Signature {
    let hash = {
        let mut hasher = Keccak256::new();
        hasher.update(i.abi_encode());
        hasher.finalize()
    };
    signer.sign_message(hash.as_slice()).await.expect("signing failed")
}

async fn verify_client_sig(client_sig: ClientSig, coord: FakeCoordinatorInstance<impl Provider>) -> Option<Address> {
    let hash = {
        let mut hasher = Keccak256::new();
        hasher.update(client_sig.i.abi_encode());
        hasher.finalize()
    };
    let sig = Signature::try_from(client_sig.sig.as_slice()).expect("invalid sig");
    let addr = sig.recover_address_from_msg(hash).expect("recovery failed");

    if coord.authenticateClient(client_sig.i, addr, Bytes::from(client_sig.sig))
        .call().await.expect("sending TX failed") {
            Some(addr)
    } else {
        None
    }
}

async fn coord_creation_block(coord: FakeCoordinatorInstance<impl Provider>) -> u64 {
        let x = coord.creationBlock().call().await.expect("sending TX failed");
        u256_to_u64(x)
}

static PK: [Address; 10] = [
    address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
    address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
    address!("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"),
    address!("0x90F79bf6EB2c4f870365E785982E1f101E93b906"),
    address!("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"),
    address!("0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc"),
    address!("0x976EA74026E726554dB657fA54763abd0C3a0aa9"),
    address!("0x14dC79964da2C08b23698B3D3cc7Ca32193d9955"),
    address!("0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f"),
    address!("0xa0Ee7A142d267C1f36714E4a8F75612F20a79720")
];

async fn init_input_masks(n_input_masks: usize, coord: FakeCoordinatorInstance<impl Provider>) {
    assert!(n_input_masks == 2);

    let builder = coord.initializeInputMaskBuffer(U256::from(n_input_masks));
    let result = builder.send().await;
    match result {
        Ok(r) => {
            r.watch().await.expect("TX failed");
        }
        Err(e) => {
            let err = e.as_decoded_error::<FakeCoordinator::IndexBufferAlreadySet>().unwrap();
            println!("nTotalIndices={}", err.nTotalIndices);
            panic!();
        }
    }
}


async fn wait_for_input_mask_init(coord: FakeCoordinatorInstance<impl Provider>, contract_block: u64) {
    let mut events = coord
        .IndexBufferEvent_filter()
        .from_block(contract_block)
        .watch()
        .await.unwrap().into_stream();

    if let Some(Ok((IndexBufferEvent { totalIndices, designatedParty }, _))) = events.next().await {
        
    } else {
        panic!();
    }
}

async fn grant_roles(n_parties: usize, coord: FakeCoordinatorInstance<impl Provider>) {
    assert!(n_parties == 5);

    let PARTY_ROLE = {
        let builder = coord.PARTY_ROLE();
        builder.call().await.expect("sending TX failed")
    };
    let DESIGNATED_PARTY_ROLE = {
        let builder = coord.DESIGNATED_PARTY_ROLE();
        builder.call().await.expect("sending TX failed")
    };

    // grant party roles
    for i in 0..n_parties {
        let builder = coord.grantRole(PARTY_ROLE, PK[i]);
        let result = builder.send().await;
        match result {
            Ok(r) => {
                r.watch().await.expect("TX failed");
            }
            Err(e) => {
                let err = e.as_decoded_error::<FakeCoordinator::TooManyMPCParties>().unwrap();
                println!("current={}, max={}, new account={}", err.currentParties, err.maxParties, err.account);
                panic!();
            }
        }
        builder.send().await.expect("sending TX failed").watch().await.expect("TX failed");
        println!("Granted party role to {}", PK[i]);
    }
}

async fn reserve_mask_index(i: U256, coord: FakeCoordinatorInstance<impl Provider>) {
    let builder = coord.reserveInputMask(i);
    let result = builder.send().await;
    match result {
        Ok(r) => {
            r.watch().await.expect("TX failed");
        }
        Err(_) => {
            panic!();
        }
    }
}

async fn send_masked_input(masked_input: Fr, i: U256, coord: FakeCoordinatorInstance<impl Provider>) {
    let builder = coord.submitMaskedInput(fr_to_u256(masked_input), i);
    let result = builder.send().await;
    match result {
        Ok(r) => {
            r.watch().await.expect("TX failed");
        }
        Err(e) => {
            panic!();
        }
    }
}

async fn trigger_mpc(coord: FakeCoordinatorInstance<impl Provider>) {
    let builder = coord.initiateMPCComputation();
    let result = builder.send().await;
    match result {
        Ok(r) => {
            r.watch().await.expect("TX failed");
        }
        Err(e) => {
            panic!();
        }
    }
}

async fn wait_for_mpc(coord: FakeCoordinatorInstance<impl Provider>, contract_block: u64) {
    let mut events = coord
        .MPCTaskExecuted_filter()
        .from_block(contract_block)
        .watch()
        .await.unwrap().into_stream();

    if let Some(Ok((_, _))) = events.next().await {
        
    } else {
        panic!();
    }
}

async fn trigger_outputs(coord: FakeCoordinatorInstance<impl Provider>) {
    let builder = coord.publishOutputs();
    let result = builder.send().await;
    match result {
        Ok(r) => {
            r.watch().await.expect("TX failed");
        }
        Err(_) => {
            panic!();
        }
    }
}

async fn wait_for_outputs(coord: FakeCoordinatorInstance<impl Provider>, contract_block: u64) {
    let mut events = coord
        .ClientOutputCollection_filter()
        .from_block(contract_block)
        .watch()
        .await.unwrap().into_stream();

    if let Some(Ok((_, _))) = events.next().await {
        
    } else {
        panic!();
    }
}

async fn trigger_input(coord: FakeCoordinatorInstance<impl Provider>) {
    let builder = coord.gatherInputs();
    let result = builder.send().await;
    match result {
        Ok(r) => {
            r.watch().await.expect("TX failed");
        }
        Err(e) => {
            panic!();
            //let err = e.as_decoded_error::<FakeCoordinator::NotAnExistingParty>().unwrap();
            //println!("No such account {}", err.account);
        }
    }
}

async fn wait_for_input(coord: FakeCoordinatorInstance<impl Provider>, contract_block: u64) {
    let mut events = coord
        .ClientInputMaskReservationEvent_filter()
        .from_block(contract_block)
        .watch()
        .await.unwrap().into_stream();

    if let Some(Ok((_, _))) = events.next().await {
        
    } else {
        panic!();
    }
}

async fn trigger_pp(coord: FakeCoordinatorInstance<impl Provider>) {
    let builder = coord.startPreprocessing();
    let result = builder.send().await;
    match result {
        Ok(r) => {
            r.watch().await.expect("TX failed");
        }
        Err(e) => {
            let err = e.as_decoded_error::<FakeCoordinator::NotAnExistingParty>().unwrap();
            println!("No such account {}", err.account);
        }
    }
}

async fn wait_for_pp(coord: FakeCoordinatorInstance<impl Provider>, contract_block: u64) {
    let mut events = coord
        .PreprocessingRoundExecuted_filter()
        .from_block(contract_block)
        .watch()
        .await.unwrap().into_stream();

    if let Some(Ok((_, _))) = events.next().await {
        
    } else {
        panic!();
    }
}

fn u256_to_u64(x: U256) -> u64 {
    x.try_into().expect("u256_to_u64: input out of range")
}

// lossless: Fr elements always fit into 256 bits
fn fr_to_u256(x: Fr) -> U256 {
    let bytes = x.into_bigint().to_bytes_le();
    U256::from_le_slice(&bytes)
}

fn u256_to_fr(x: U256) -> Fr {
    let r = {
        let r = <Fr as PrimeField>::MODULUS;
        let r_bytes = r.to_bytes_le();
        U256::from_le_slice(&r_bytes)
    };

    if x >= r {
        panic!("u256_to_fr: input out of range");
    }

    let bytes = x.to_le_bytes::<32>();
    Fr::from_le_bytes_mod_order(&bytes)
}

async fn wait_for_masked_inputs(coord: FakeCoordinatorInstance<impl Provider>, contract_block: u64, n_clients: usize) -> HashMap<Address, Vec<Fr>> {
    let mut events = coord
        .MaskedInputEvent_filter()
        .from_block(contract_block)
        .watch()
        .await.unwrap().into_stream();

    let mut masked_inputs: HashMap<Address, Vec<Fr>> = HashMap::new();
    for _ in 0..n_clients {
        if let Some(Ok((MaskedInputEvent { client, maskedInput, reservedIndex }, _))) = events.next().await {
            masked_inputs.insert(client, vec![u256_to_fr(maskedInput)]);
        } else {
            panic!();
        }
    }
    masked_inputs
}

//#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use alloy::signers::local::PrivateKeySigner;
    use ark_bls12_381::Fr;
    use alloy::{
        node_bindings::{Anvil, AnvilInstance},
        providers::{Provider, ProviderBuilder, WsConnect},
        network::EthereumWallet,
        sol_types::SolEvent,
        rpc::types::{BlockNumberOrTag, Filter}
    };
    use alloy_primitives::{Address, U256, FixedBytes};
    use std::str::FromStr;
    use stoffel_solidity_bindings::{
        fake_coordinator::FakeCoordinator,
    };

    static SK: [&str; 10] = [
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
        "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
        "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
        "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
        "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
        "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
        "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
        "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
        "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6"
    ];

    static ACC: [Address; 10] = [
        address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
        address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
        address!("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"),
        address!("0x90F79bf6EB2c4f870365E785982E1f101E93b906"),
        address!("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"),
        address!("0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc"),
        address!("0x976EA74026E726554dB657fA54763abd0C3a0aa9"),
        address!("0x14dC79964da2C08b23698B3D3cc7Ca32193d9955"),
        address!("0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f"),
        address!("0xa0Ee7A142d267C1f36714E4a8F75612F20a79720")
    ];

    fn spawn_anvil() -> AnvilInstance {
        Anvil::new().spawn()
    }
    
    async fn ws_connect(ws_addr: &str, key: &str) -> impl Provider + Clone {
        let ws = WsConnect::new(ws_addr);
        let wallet = EthereumWallet::from(PrivateKeySigner::from_str(key).expect("invalid private key"));
    
        ProviderBuilder::new()
            .wallet(wallet)
            .connect_ws(ws).await.expect("could not connect to Anvil via WebSockets")
    }

  //  #[tokio::test]
    pub async fn sig_gen_onchain() {
        let anvil = spawn_anvil();
        let provider = ws_connect(&anvil.ws_endpoint(), SK[0]).await;
        let n = U256::from(5);
        let t = U256::from(1);
        let hash = FixedBytes::from_str("0000000000000000000000000000000000000000000000000000000000000000").expect("invalid hash");
        let designated_party = ACC[0];
        let initial_mpc_nodes: Vec<Address> = ACC[0..5].to_vec();

        let coord = FakeCoordinator::deploy(provider.clone(), hash, n, t, designated_party, initial_mpc_nodes).await.expect("deployment failed");

        let sk = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let signer = PrivateKeySigner::from_str(sk).unwrap();
        let i = U256::from(42u64);

        // Generate signature
        let sig = generate_client_sig(i, signer.clone()).await;

        let client_sig = ClientSig {
            client_id: 1,
            i,
            sig: sig.as_bytes().to_vec(),
        };

        match verify_client_sig(client_sig, coord).await {
            Some(addr) => {
                let expected_addr = signer.address();
                assert_eq!(addr, expected_addr);
            }
            None => {
                panic!("signature verification failed");
            }
        }
    }

 //   #[test]
    pub fn fr_u256_conversion() {
        let mut rng = rand::rng();
        for _ in 0..100 {
            let n: u64 = rng.random();
            let fr = Fr::from(n);
            let u = fr_to_u256(fr);
            let fr2 = u256_to_fr(u);
            assert_eq!(fr, fr2);
        }
    }

 //   #[test]
    pub fn u64_u256_conversion() {
        let mut rng = rand::rng();
        for _ in 0..100 {
            let n1: u64 = rng.random();
            let n1_u256 = U256::from(n1);
            let n2 = u256_to_u64(n1_u256);
            assert_eq!(n1, n2);
        }
    }

  //  #[tokio::test]
    pub async fn coord_creation_block() {
        let anvil = spawn_anvil();
        let provider = ws_connect(&anvil.ws_endpoint(), SK[0]).await;
        let n = U256::from(5);
        let t = U256::from(1);
        let hash = FixedBytes::from_str("0000000000000000000000000000000000000000000000000000000000000000").expect("invalid hash");
        let designated_party = ACC[0];
        let initial_mpc_nodes: Vec<Address> = ACC[0..5].to_vec();

        let coord = FakeCoordinator::deploy(provider.clone(), hash, n, t, designated_party, initial_mpc_nodes).await.expect("deployment failed");

        let block = super::coord_creation_block(coord.clone()).await;

        assert_eq!(block, 1);
    }

  //  #[tokio::test]
    pub async fn event_listening() {
        // event triggered BEFORE waiting for the event
        {
            let anvil = spawn_anvil();
            let provider = ws_connect(&anvil.ws_endpoint(), SK[0]).await;
            //let provider = ws_connect("ws://127.0.0.1:8545", SK[0]).await;
            let n = U256::from(5);
            let t = U256::from(1);
            let hash = FixedBytes::from_str("0000000000000000000000000000000000000000000000000000000000000000").expect("invalid hash");
            let designated_party = ACC[0];
            let initial_mpc_nodes: Vec<Address> = ACC[0..5].to_vec();

            let coord = FakeCoordinator::deploy(provider.clone(), hash, n, t, designated_party, initial_mpc_nodes).await.expect("deployment failed");

            //let block = super::coord_creation_block(coord.clone()).await;
            let block = 1u64;
            assert_eq!(block, 1);

            super::trigger_input(coord.clone()).await;
            super::wait_for_input(coord.clone(), block).await;
        }

        // event triggered AFTER waiting for the event
        {
            let anvil = spawn_anvil();
            let provider = ws_connect(&anvil.ws_endpoint(), SK[0]).await;
            //let provider = ws_connect("ws://127.0.0.1:8545", SK[0]).await;
            let n = U256::from(5);
            let t = U256::from(1);
            let hash = FixedBytes::from_str("0000000000000000000000000000000000000000000000000000000000000000").expect("invalid hash");
            let designated_party = ACC[0];
            let initial_mpc_nodes: Vec<Address> = ACC[0..5].to_vec();

            let coord = FakeCoordinator::deploy(provider.clone(), hash, n, t, designated_party, initial_mpc_nodes).await.expect("deployment failed");

            let block = super::coord_creation_block(coord.clone()).await;
            assert_eq!(block, 1);

            tokio::spawn({
                let coord = coord.clone();
                async move {
                    if timeout(Duration::from_millis(500), super::wait_for_input(coord.clone(), block)).await.is_err() {
                        panic!();
                    }
                }
            });
                
            super::trigger_input(coord.clone()).await;
        }
    }
}

#[tokio::main]
async fn main() {
//    tests::sig_gen_onchain().await;
//    tests::fr_u256_conversion();
//    tests::u64_u256_conversion();
//    tests::event_listening().await;

    let raw_args = env::args().skip(1).collect::<Vec<_>>();

    if raw_args.is_empty() {
        // Allow bootnode-only mode without program path
        print_usage_and_exit();
    }

    let mut path_opt: Option<String> = None;
    let mut entry: String = "main".to_string();

    let mut trace_instr = false;
    let mut trace_regs = false;
    let mut trace_stack = false;
    let mut as_bootnode = false;
    let mut as_leader = false;
    let mut as_client = false;
    let mut bind_addr: Option<SocketAddr> = None;
    let mut party_id: Option<usize> = None;
    let mut bootstrap_addr: Option<SocketAddr> = None;
    let mut n_parties: Option<usize> = None;
    let mut threshold: Option<usize> = None;
    let mut client_id: Option<usize> = None;
    let mut client_inputs: Option<String> = None;
    let mut expected_clients: Option<String> = None;
    let mut enable_nat: bool = false;
    let mut stun_servers: Vec<SocketAddr> = Vec::new();
    let mut server_addrs: Vec<SocketAddr> = Vec::new();
    let mut eth_node_addr: Option<String> = None;
    let mut contract_addr: Option<Address> = None;
    let mut wallet_sk: Option<PrivateKeySigner> = None;

    for arg in &raw_args {
        if arg == "-h" || arg == "--help" {
            print_usage_and_exit();
        } else if arg == "--trace-instr" {
            trace_instr = true;
        } else if arg == "--trace-regs" {
            trace_regs = true;
        } else if arg == "--trace-stack" {
            trace_stack = true;
        } else if arg == "--bootnode" {
            as_bootnode = true;
        } else if arg == "--leader" {
            as_leader = true;
        } else if arg == "--client" {
            as_client = true;
        } else if arg == "--nat" {
            enable_nat = true;
        } else if let Some(_rest) = arg.strip_prefix("--bind") {
            // support "--bind" and "--bind=.."
            // actual value parsed later from positional with key
        } else if let Some(_rest) = arg.strip_prefix("--party-id") {
        } else if let Some(_rest) = arg.strip_prefix("--bootstrap") {
        } else if let Some(_rest) = arg.strip_prefix("--n-parties") {
        } else if let Some(_rest) = arg.strip_prefix("--threshold") {
        } else if let Some(_rest) = arg.strip_prefix("--client-id") {
        } else if let Some(_rest) = arg.strip_prefix("--inputs") {
        } else if let Some(_rest) = arg.strip_prefix("--expected-clients") {
        } else if let Some(_rest) = arg.strip_prefix("--stun-servers") {
        } else if let Some(_rest) = arg.strip_prefix("--servers") {
        } else if let Some(_rest) = arg.strip_prefix("--eth-node") {
        } else if let Some(_rest) = arg.strip_prefix("--coordinator") {
        } else if let Some(_rest) = arg.strip_prefix("--wallet-sk") {
        }
    }

    // collect positional args (non-flags)
    let mut positional = raw_args
        .into_iter()
        .filter(|a| !a.starts_with("--"))
        .collect::<Vec<_>>();

    if positional.is_empty() {
        // Allow bootnode-only mode without program path
        if !as_bootnode {
            print_usage_and_exit();
        }
    }

    // Parse key-value style flags
    let mut args_iter = env::args().skip(1).peekable();
    while let Some(a) = args_iter.next() {
        match a.as_str() {
            "--bind" => {
                if let Some(v) = args_iter.next() {
                    bind_addr = Some(v.parse().expect("Invalid --bind addr"));
                }
            }
            "--party-id" => {
                if let Some(v) = args_iter.next() {
                    party_id = Some(v.parse().expect("Invalid --party-id"));
                }
            }
            "--bootstrap" => {
                if let Some(v) = args_iter.next() {
                    bootstrap_addr = Some(v.parse().expect("Invalid --bootstrap addr"));
                }
            }
            "--n-parties" => {
                if let Some(v) = args_iter.next() {
                    n_parties = Some(v.parse().expect("Invalid --n-parties"));
                }
            }
            "--threshold" => {
                if let Some(v) = args_iter.next() {
                    threshold = Some(v.parse().expect("Invalid --threshold"));
                }
            }
            "--client-id" => {
                if let Some(v) = args_iter.next() {
                    client_id = Some(v.parse().expect("Invalid --client-id"));
                }
            }
            "--inputs" => {
                if let Some(v) = args_iter.next() {
                    client_inputs = Some(v);
                }
            }
            "--expected-clients" => {
                if let Some(v) = args_iter.next() {
                    expected_clients = Some(v);
                }
            }
            "--stun-servers" => {
                if let Some(v) = args_iter.next() {
                    stun_servers = v
                        .split(',')
                        .filter_map(|s| {
                            let s = s.trim();
                            s.parse::<SocketAddr>().ok().or_else(|| {
                                eprintln!("Warning: Invalid STUN server address '{}', skipping", s);
                                None
                            })
                        })
                        .collect();
                }
            }
            "--servers" => {
                if let Some(v) = args_iter.next() {
                    server_addrs = v
                        .split(',')
                        .filter_map(|s| {
                            let s = s.trim();
                            s.parse::<SocketAddr>().ok().or_else(|| {
                                eprintln!("Warning: Invalid server address '{}', skipping", s);
                                None
                            })
                        })
                        .collect();
                }
            }
            "--eth-node" => {
                if let Some(v) = args_iter.next() {
                    eth_node_addr = Some(v);
                }
            }
            "--coordinator" => {
                if let Some(v) = args_iter.next() {
                    contract_addr = match Address::from_str(&v) {
                        Ok(addr) => Some(addr),
                        Err(e) => {
                            eprintln!("Invalid contract address '{}', skipping", e);
                            None
                        }
                    }
                }
            }
            "--wallet-sk" => {
                if let Some(v) = args_iter.next() {
                    wallet_sk = match PrivateKeySigner::from_str(&v) {
                        Ok(sk) => Some(sk),
                        Err(e) => {
                            eprintln!("Invalid wallet secret key '{}', skipping", e);
                            None
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Connect to Ethereum node
    let eth = {
        if let (Some(addr), Some(wallet_sk)) = (eth_node_addr, wallet_sk.clone()) {
            let ws = WsConnect::new(addr.clone());
            let wallet = EthereumWallet::from(wallet_sk);
                
            Some(ProviderBuilder::new()
                .wallet(wallet)
                .connect_ws(ws).await.expect(format!("could not connect to Ethereum node at {} via WebSockets", addr.clone()).as_str()))
        } else {
            panic!();
        }
    };

    // Get an instance for the coordinator contract
    let coord = if let (Some(eth), Some(contract_addr)) = (eth.clone(), contract_addr) {
        Some(FakeCoordinator::new(contract_addr, eth.clone()))
    } else {
        panic!();
    };
    let contract_block = coord_creation_block(coord.clone().unwrap()).await;

    // Bootnode-only mode (no program execution)
    if as_bootnode && !as_leader {
        let bind = bind_addr.unwrap_or_else(|| "127.0.0.1:9000".parse().unwrap());
        eprintln!("Starting bootnode on {}", bind);
        // Install crypto provider for quinn/rustls
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("install rustls crypto");
        // Pass expected parties if specified, so bootnode waits for all before announcing session
        if let Err(e) = run_bootnode_with_config(bind, n_parties).await {
            eprintln!("Bootnode error: {}", e);
            exit(10);
        }
        return;
    }

    // Client mode: connect to MPC servers and provide inputs
    if as_client {
        let cid = client_id.unwrap_or_else(|| {
            eprintln!("Error: --client-id is required in client mode");
            exit(2);
        });

        let n = n_parties.unwrap_or_else(|| {
            eprintln!("Error: --n-parties is required in client mode");
            exit(2);
        });
        let t = threshold.unwrap_or(1);

        // Parse inputs (comma-separated integers or fixed-point values)
        let inputs_str = client_inputs.unwrap_or_else(|| {
            eprintln!("Error: --inputs is required in client mode (comma-separated values)");
            exit(2);
        });
        let input_values: Vec<Fr> = inputs_str
            .split(',')
            .map(|s| {
                let s = s.trim();
                // Support integer and fixed-point (interpret as integer for now)
                let val: i64 = s.parse().unwrap_or_else(|_| {
                    eprintln!("Invalid input value: {}", s);
                    exit(2);
                });
                Fr::from(val as u64)
            })
            .collect();

        let input_len = input_values.len();

        // Server addresses are required
        if server_addrs.is_empty() {
            eprintln!("Error: --servers is required in client mode (comma-separated addresses)");
            eprintln!("Example: --servers 172.18.0.2:9000,172.18.0.3:9000,172.18.0.4:9000,172.18.0.5:9000,172.18.0.6:9000");
            exit(2);
        }

        if server_addrs.len() != n {
            eprintln!("Warning: number of servers ({}) doesn't match n_parties ({})", server_addrs.len(), n);
        }

        eprintln!(
            "[client {}] Client mode (n={}, t={}, {} inputs, {} servers)",
            cid, n, t, input_len, server_addrs.len()
        );

        // Install crypto provider for quinn/rustls
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("install rustls crypto");

        // Create the MPC client
        // Instance ID 0 is fine for client - it doesn't participate in the instance negotiation
        let instance_id = 0u32;
        let mut mpc_client = match HoneyBadgerMPCClient::<Fr, Avid>::new(
            cid,
            n,
            t,
            instance_id,
            input_values.clone(),
            input_len,
        ) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[client {}] Failed to create MPC client: {:?}", cid, e);
                exit(20);
            }
        };

        // Create network manager for client connections
        let network = Arc::new(tokio::sync::Mutex::new(QuicNetworkManager::new()));

        // Add all server addresses as nodes (party IDs 0 to n-1)
        for (party_id, &addr) in server_addrs.iter().enumerate() {
            network.lock().await.add_node_with_party_id(party_id, addr);
            eprintln!("[client {}] Added server party {} at {}", cid, party_id, addr);
        }

        // Create channel for receiving messages
        let (msg_tx, mut msg_rx_raw) = mpsc::channel::<Vec<u8>>(1000);
        let msg_rx = Arc::new(Mutex::new(msg_rx_raw));

        // Connect to all servers as a client
        eprintln!("[client {}] Connecting to {} servers...", cid, server_addrs.len());
        for (party_id, &addr) in server_addrs.iter().enumerate() {
            let mut retry_count = 0;
            let max_retries = 10;
            let retry_delay = Duration::from_millis(500);

            loop {
                eprintln!("[client {}] Connecting to server {} at {} (attempt {}/{})",
                         cid, party_id, addr, retry_count + 1, max_retries);

                let connection_result = {
                    let mut net = network.lock().await;
                    net.connect_as_client(addr, cid).await
                };

                match connection_result {
                    Ok(connection) => {
                        eprintln!("[client {}] Connected to server {} at {}", cid, party_id, addr);

                        // Spawn message handler for this connection
                        let tx = msg_tx.clone();
                        let client_id = cid;

                        tokio::spawn(async move {
                            loop {
                                match connection.receive().await {
                                    Ok(data) => {
                                        if let Err(e) = tx.send(data).await {
                                            eprintln!("[client {}] Failed to forward message: {:?}", client_id, e);
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("[client {}] Connection to server closed: {}", client_id, e);
                                        break;
                                    }
                                }
                            }
                        });
                        break;
                    }
                    Err(e) => {
                        retry_count += 1;
                        if retry_count >= max_retries {
                            eprintln!("[client {}] Failed to connect to server {} at {} after {} attempts: {}",
                                     cid, party_id, addr, retry_count, e);
                            exit(21);
                        }
                        eprintln!("[client {}] Connection attempt {} failed: {}, retrying...", cid, retry_count, e);
                        tokio::time::sleep(retry_delay).await;
                    }
                }
            }
        }

        eprintln!("[client {}] Connected to all servers, waiting for input masks to be initialized...", cid);

        wait_for_input(coord.clone().unwrap(), contract_block).await;
        eprintln!("[client {}] Input masks initialized.", cid);
        wait_for_input_mask_init(coord.clone().unwrap(), contract_block).await;
        eprintln!("[client {}] Input mask initialization event received.", cid);

        // TODO: replace by something better, e.g., iterating through indices until a free one is
        // found, this only works as long as the ID is chosen appropriately
        let reserved_i = U256::from(cid);

        eprintln!("[client {}] Reserving mask index {}...", cid, reserved_i);
        reserve_mask_index(reserved_i, coord.clone().unwrap()).await;
        eprintln!("[client {}] Reserved mask indices, sending signatures...", cid);

        let sig = generate_client_sig(reserved_i, wallet_sk.clone().unwrap()).await;
        for (_, conn) in network.lock().await.get_all_connections().await {
            let sig_bytes = bincode::serialize::<ClientSig>(&ClientSig {
                client_id: cid,
                i: reserved_i,
                sig: sig.as_bytes().to_vec(),
            }).expect("serializing client signature failed");
            conn.send(&sig_bytes).await.expect("sending client signature failed");
        }

        eprintln!("[client {}] Starting input protocol...", cid);

        // Spawn a task to process incoming messages
        // The client receives mask shares from servers and broadcasts masked inputs
        // Once the broadcast is complete, the client's job is done
        let client_id_for_task = cid;
        let process_handle = tokio::spawn({ let msg_rx = msg_rx.clone(); let coord = coord.clone().unwrap(); async move {
            let mut shares_per_node: Vec<Vec<RobustShare<Fr>>> = Vec::new();
            let mut masked_inputs_sent = false;
            while let Some(data) = msg_rx.lock().await.recv().await {
                // TODO: this is not safe against duplicate messages, need sender ID for that
                let shares: Vec<RobustShare<Fr>> =
                    ark_serialize::CanonicalDeserialize::deserialize_compressed(data.as_slice()).expect("deserializing mask shares failed");

                if shares.len() != input_values.len() {
                    eprintln!("[client {}] Received invalid number of shares: {}, expected {}",
                             client_id_for_task, shares.len(), input_values.len());
                    continue;
                }

                shares_per_node.push(shares);

                if shares_per_node.len() >= 2 * t + 1 && !masked_inputs_sent {
                    let mut shares_per_mask: Vec<Vec<RobustShare<Fr>>> = vec![Vec::new(); input_values.len()];
                    for shares in shares_per_node.iter() {
                        for i in 0..input_values.len() {
                            shares_per_mask[i].push(shares[i].clone());
                        }
                    }

                    let mut recon_success = true;
                    let mut masks: Vec<Fr> = Vec::new();
                    for shares in shares_per_mask {
                        match RobustShare::recover_secret(&shares, n) {
                            Ok(secret) => {
                                masks.push(secret.1);
                            }
                            Err(_) => {
                                eprintln!("[client {}] Failed to recover mask from shares", client_id_for_task);
                                recon_success = false;
                            }
                        }
                    }

                    if recon_success {
                        eprintln!("[client {}] Recovered all input masks, sending masked inputs...",
                                 client_id_for_task);
                        let reserved_indices = [U256::from(reserved_i)];
                        for (i, (m, v)) in masks.into_iter().zip(input_values.iter()).enumerate() {
                            send_masked_input(m + v, reserved_indices[i], coord.clone()).await;
                        }

                        masked_inputs_sent = true;
                    }
                }

                // The client has done its job once it processes messages from all servers
                // and broadcasts its masked inputs. We give it some time to complete.
                if shares_per_node.len() >= n {
                    eprintln!("[client {}] Received shares from {} parties, input submission likely complete",
                             client_id_for_task, shares_per_node.len());
                    // Give some time for any final messages
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    break;
                }
            }
            eprintln!("[client {}] Reception complete ({} parties)",
                     client_id_for_task, shares_per_node.len());
        }});

        // Wait for input protocol to complete with timeout
        let timeout_duration = Duration::from_secs(120);
        match tokio::time::timeout(timeout_duration, process_handle).await {
            Ok(Ok(_)) => {
                eprintln!("[client {}] Successfully submitted inputs to MPC network", cid);
            }
            Ok(Err(e)) => {
                eprintln!("[client {}] Input task error: {:?}", cid, e);
                exit(22);
            }
            Err(_) => {
                eprintln!("[client {}] Timeout waiting for input protocol to complete", cid);
                exit(23);
            }
        }

        eprintln!("[client {}] Waiting for start of MPC phase...", cid);
        wait_for_mpc(coord.clone().unwrap(), contract_block).await;
        eprintln!("[client {}] MPC phase started.", cid);

        eprintln!("[client {}] Waiting for start of output phase...", cid);
        wait_for_outputs(coord.clone().unwrap(), contract_block).await;
        eprintln!("[client {}] Output phase started, receiving output shares...", cid);

        // receive output shares
        let client_id_for_task = cid;
        let mut shares_per_node: Vec<Vec<RobustShare<Fr>>> = Vec::new();

        let outputs = {
            let mut outputs: Vec<Fr> = Vec::new();
            while let Some(data) = msg_rx.lock().await.recv().await {
                // TODO: this is not safe against duplicate messages, need sender ID for that
                let shares: Vec<RobustShare<Fr>> =
                    ark_serialize::CanonicalDeserialize::deserialize_compressed(data.as_slice()).expect("deserializing mask shares failed");

                let no_outputs = 1;
                if shares.len() != no_outputs {
                    eprintln!("[client {}] Received invalid number of output shares: {}, expected {}",
                             client_id_for_task, shares.len(), no_outputs);
                    continue;
                }

                shares_per_node.push(shares);

                if shares_per_node.len() >= 2 * t + 1 {
                    let mut shares_per_mask: Vec<Vec<RobustShare<Fr>>> = vec![Vec::new(); no_outputs];
                    for shares in shares_per_node.iter() {
                        for i in 0..no_outputs {
                            shares_per_mask[i].push(shares[i].clone());
                        }
                    }

                    let mut recon_success = true;
                    outputs = Vec::new();
                    for shares in shares_per_mask {
                        match RobustShare::recover_secret(&shares, n) {
                            Ok(secret) => {
                                outputs.push(secret.1);
                            }
                            Err(_) => {
                                eprintln!("[client {}] Failed to recover output from shares", client_id_for_task);
                                recon_success = false;
                                break;
                            }
                        }
                    }

                    if recon_success {
                        eprintln!("[client {}] Recovered all outputs...", client_id_for_task);
                        break;
                    }
                }
            }
            outputs
        };

        eprintln!("[client {}] Outputs reconstructed: {:?}", cid, outputs);

        return;
    }

    path_opt = if !positional.is_empty() {
        Some(positional.remove(0))
    } else {
        None
    };
    entry = if !positional.is_empty() {
        positional.remove(0)
    } else {
        entry
    };

    // Optional: bring up networking in party mode if bootstrap provided or if leader
    let mut net_opt: Option<Arc<QuicNetworkManager>> = None;
    let mut program_id: [u8; 32] = [0u8; 32];
    let mut agreed_entry = entry.clone();
    let mut session_instance_id: Option<u64> = None;
    let mut session_n_parties: Option<usize> = None;
    let mut session_threshold: Option<usize> = None;

    // Leader mode: this party also runs the bootnode
    if as_leader {
        let bind = bind_addr.unwrap_or_else(|| "127.0.0.1:9000".parse().unwrap());
        let my_id = party_id.unwrap_or(0usize);

        // Install crypto provider for quinn/rustls
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("install rustls crypto");

        // Must have program path
        if path_opt.is_none() {
            eprintln!("Error: leader mode requires a program path");
            exit(2);
        }
        let program_path = path_opt.as_ref().unwrap();
        let bytes = std::fs::read(program_path).expect("read program");
        program_id = program_id_from_bytes(&bytes);

        // Get MPC parameters (required for session)
        let n = n_parties.unwrap_or_else(|| {
            eprintln!("Error: --n-parties is required for leader mode");
            exit(2);
        });
        let t = threshold.unwrap_or(1);

        eprintln!(
            "[leader/party {}] Starting bootnode on {} and participating in session (n={}, t={})",
            my_id, bind, n, t
        );

        // Spawn bootnode in background
        let bootnode_bind = bind;
        let bootnode_n = n;
        tokio::spawn(async move {
            if let Err(e) = run_bootnode_with_config(bootnode_bind, Some(bootnode_n)).await {
                eprintln!("Bootnode error: {}", e);
            }
        });

        // Give bootnode a moment to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Now connect to ourselves as the bootnode
        // Use with_node_id so connections are indexed by party ID (0-4), not random UUIDs
        let mut mgr = QuicNetworkManager::with_node_id(my_id);
        // Listen on a different port for peer connections
        let party_bind: SocketAddr = format!("{}:{}", bind.ip(), bind.port() + 1000)
            .parse()
            .unwrap();
        if let Err(e) = mgr.listen(party_bind).await {
            eprintln!("Failed to listen on {}: {}", party_bind, e);
            exit(11);
        }

        eprintln!(
            "[leader/party {}] Party listening on {}, registering with bootnode {}",
            my_id, party_bind, bind
        );

        // Register with our own bootnode and wait for session
        // Leader uploads program bytes so other parties can fetch them
        let session_info = match register_and_wait_for_session_with_program(
            &mut mgr,
            bind, // bootnode is on our bind address
            my_id,
            party_bind,
            program_id,
            &entry,
            n,
            t,
            Duration::from_secs(120), // 2 minute timeout for all parties to join
            Some(bytes),              // Leader uploads program bytes
        )
        .await
        {
            Ok(info) => info,
            Err(e) => {
                eprintln!("Session registration failed: {}", e);
                exit(12);
            }
        };

        // Use session parameters
        agreed_entry = session_info.entry.clone();
        session_instance_id = Some(session_info.instance_id);
        session_n_parties = Some(session_info.n_parties);
        session_threshold = Some(session_info.threshold);

        eprintln!(
            "[leader/party {}] Session started: instance_id={}, n={}, t={}, entry={}",
            my_id, session_info.instance_id, session_info.n_parties, session_info.threshold, agreed_entry
        );

        let net = Arc::new(mgr);
        net_opt = Some(net.clone());
    } else if let Some(bootnode) = bootstrap_addr {
        // Regular party mode: connect to external bootnode
        let bind = bind_addr.unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());
        let my_id = party_id.unwrap_or(0usize);
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("install rustls crypto");

        // Must have program path in party mode
        if path_opt.is_none() {
            eprintln!("Error: party mode requires a program path");
            exit(2);
        }
        let program_path = path_opt.as_ref().unwrap();
        let bytes = std::fs::read(program_path).expect("read program");
        program_id = program_id_from_bytes(&bytes);

        // Get MPC parameters (required for session)
        let n = n_parties.unwrap_or_else(|| {
            eprintln!("Error: --n-parties is required for party mode");
            exit(2);
        });
        let t = threshold.unwrap_or(1);

        // Prepare QUIC manager
        // Use with_node_id so connections are indexed by party ID (0-4), not random UUIDs
        let mut mgr = QuicNetworkManager::with_node_id(my_id);
        // Listen so peers can connect back directly
        if let Err(e) = mgr.listen(bind).await {
            eprintln!("Failed to listen on {}: {}", bind, e);
            exit(11);
        }

        // Note: if using port 0, the OS assigns a port. For now we use the bind address.
        // In a real deployment, you should use specific ports, not port 0.
        let actual_listen = bind;
        eprintln!(
            "[party {}] Listening on {}, connecting to bootnode {}",
            my_id, actual_listen, bootnode
        );

        // Register with bootnode and wait for session to be announced
        // This blocks until all n parties have registered
        // Upload program bytes so bootnode can distribute to parties that don't have it
        let session_info = match register_and_wait_for_session_with_program(
            &mut mgr,
            bootnode,
            my_id,
            actual_listen,
            program_id,
            &entry,
            n,
            t,
            Duration::from_secs(120), // 2 minute timeout for all parties to join
            Some(bytes),              // Upload program bytes
        )
        .await
        {
            Ok(info) => info,
            Err(e) => {
                eprintln!("Session registration failed: {}", e);
                exit(12);
            }
        };

        // Use session parameters
        agreed_entry = session_info.entry.clone();
        session_instance_id = Some(session_info.instance_id);
        session_n_parties = Some(session_info.n_parties);
        session_threshold = Some(session_info.threshold);

        eprintln!(
            "[party {}] Session started: instance_id={}, n={}, t={}, entry={}",
            my_id, session_info.instance_id, session_info.n_parties, session_info.threshold, agreed_entry
        );

        let net = Arc::new(mgr);
        net_opt = Some(net.clone());
    } else {
        // local run: must have path
        if let Some(p) = &path_opt {
            let bytes = std::fs::read(p).expect("read program");
            program_id = program_id_from_bytes(&bytes);
        } else {
            eprintln!("Error: local run requires a program path unless --bootnode or --leader");
            exit(2);
        }
    }

    // Load compiled binary from a file path
    let load_path: String = if let Some(p) = path_opt.clone() {
        p
    } else {
        // Use cached program path if we fetched it from bootnode
        let p = stoffel_vm::net::program_sync::program_path(&program_id);
        p.to_string_lossy().to_string()
    };
    let mut f = File::open(&load_path).expect("open binary file");
    let binary = CompiledBinary::deserialize(&mut f).expect("deserialize compiled binary");
    let functions = binary.to_vm_functions();
    if functions.is_empty() {
        eprintln!("Error: compiled program contains no functions");
        exit(3);
    }

    // Initialize VM
    let mut vm = VirtualMachine::new();
    // Register standard library in case the program uses builtins like `print`
    vm.register_standard_library();

    // Register all functions
    for f in functions {
        vm.register_function(f);
    }

    // Register debugging hooks based on flags
    if trace_instr {
        vm.register_hook(
            |event| {
                matches!(
                    event,
                    HookEvent::BeforeInstructionExecute(_) | HookEvent::AfterInstructionExecute(_)
                )
            },
            |event, ctx: &HookContext| match event {
                HookEvent::BeforeInstructionExecute(instr) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    let pc = ctx.get_current_instruction();
                    eprintln!(
                        "[instr][depth {}][{}][pc {}] BEFORE {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        pc,
                        instr
                    );
                    Ok(())
                }
                HookEvent::AfterInstructionExecute(instr) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    let pc = ctx.get_current_instruction();
                    eprintln!(
                        "[instr][depth {}][{}][pc {}] AFTER  {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        pc,
                        instr
                    );
                    Ok(())
                }
                _ => Ok(()),
            },
            0,
        );
    }

    if trace_regs {
        vm.register_hook(
            |event| {
                matches!(
                    event,
                    HookEvent::RegisterRead(_, _) | HookEvent::RegisterWrite(_, _, _)
                )
            },
            |event, ctx: &HookContext| match event {
                HookEvent::RegisterRead(idx, val) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    eprintln!(
                        "[regs][depth {}][{}] R{} -> {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        idx,
                        val
                    );
                    Ok(())
                }
                HookEvent::RegisterWrite(idx, old, new) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    eprintln!(
                        "[regs][depth {}][{}] R{}: {:?} -> {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        idx,
                        old,
                        new
                    );
                    Ok(())
                }
                _ => Ok(()),
            },
            0,
        );
    }

    if trace_stack {
        vm.register_hook(
            |event| {
                matches!(
                    event,
                    HookEvent::BeforeFunctionCall(_, _)
                        | HookEvent::AfterFunctionCall(_, _)
                        | HookEvent::StackPush(_)
                        | HookEvent::StackPop(_)
                )
            },
            |event, ctx: &HookContext| match event {
                HookEvent::BeforeFunctionCall(func, args) => {
                    eprintln!(
                        "[stack][depth {}] CALL {:?} with {:?}",
                        ctx.get_call_depth(),
                        func,
                        args
                    );
                    Ok(())
                }
                HookEvent::AfterFunctionCall(func, ret) => {
                    eprintln!(
                        "[stack][depth {}] RET  {:?} => {:?}",
                        ctx.get_call_depth(),
                        func,
                        ret
                    );
                    Ok(())
                }
                HookEvent::StackPush(v) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    eprintln!(
                        "[stack][depth {}][{}] PUSH {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        v
                    );
                    Ok(())
                }
                HookEvent::StackPop(v) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    eprintln!(
                        "[stack][depth {}][{}] POP  {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        v
                    );
                    Ok(())
                }
                _ => Ok(()),
            },
            0,
        );
    }

    // If in party mode, configure async HoneyBadger engine and preprocess
    if let Some(net) = net_opt.clone() {
        let my_id = party_id.unwrap_or(0usize);
        // Use session parameters (already agreed upon with bootnode)
        let n = session_n_parties.unwrap_or_else(|| net.parties().len());
        let t = session_threshold.unwrap_or(1);
        // Use the session instance_id (agreed with all parties via bootnode)
        let instance_id =
            session_instance_id.expect("session instance_id should be set in party mode");

        eprintln!(
            "[party {}] Creating MPC engine: instance_id={}, n={}, t={}",
            my_id, instance_id, n, t
        );

        // Parse expected client IDs (comma-separated)
        let input_ids: Vec<ClientId> = expected_clients
            .as_ref()
            .map(|s| {
                s.split(',')
                    .filter_map(|id| id.trim().parse::<ClientId>().ok())
                    .collect()
            })
            .unwrap_or_default();

        if !input_ids.is_empty() {
            eprintln!(
                "[party {}] Expecting inputs from {} clients: {:?}",
                my_id,
                input_ids.len(),
                input_ids
            );
        }

        // Debug: print established connections
        let connections = net.get_all_connections().await;
        let conn_ids: Vec<_> = connections.iter().map(|(id, _)| *id).collect();
        eprintln!(
            "[party {}] Connections before MPC: {:?} ({} total)",
            my_id,
            conn_ids,
            connections.len()
        );

        // Create HoneyBadger MPC node options
        let n_triples = 8;
        let n_random = 16;
        let mpc_opts = honeybadger_node_opts(n, t, n_triples, n_random, instance_id);

        // Create the MPC node directly with expected client IDs
        let mut mpc_node = match <HoneyBadgerMPCNode<Fr, Avid> as MPCProtocol<
            Fr,
            RobustShare<Fr>,
            QuicNetworkManager,
        >>::setup(my_id, mpc_opts, input_ids.clone())
        {
            Ok(node) => node,
            Err(e) => {
                eprintln!("Failed to create MPC node: {:?}", e);
                exit(13);
            }
        };

        // Spawn receive loops for MPC peer connections only
        eprintln!("[party {}] Spawning receive loops for {} MPC peers...", my_id, n);
        let mut msg_rx = spawn_receive_loops(net.clone(), my_id, n).await;

        // Clone node for the message processing task
        let mut processing_node = mpc_node.clone();
        let processing_net = net.clone();
        let processing_party_id = my_id;

        // Spawn message processing task
        tokio::spawn(async move {
            eprintln!(
                "[party {}] Message processing task started",
                processing_party_id
            );
            while let Some(raw_msg) = msg_rx.recv().await {
                if let Err(e) = processing_node.process(raw_msg, processing_net.clone()).await {
                    eprintln!(
                        "[party {}] Failed to process message: {:?}",
                        processing_party_id, e
                    );
                }
            }
            eprintln!(
                "[party {}] Message processing task ended",
                processing_party_id
            );
        });

        // Create engine wrapping the same node (shared via internal Arc state)
        let engine =
            HoneyBadgerMpcEngine::from_existing_node(instance_id, my_id, n, t, net.clone(), mpc_node.clone());

        if as_leader {
            if let (Some(n_parties), Some(coord)) = (n_parties, coord.clone()) {
                eprintln!("[party {}] Granting roles on-chain...", my_id);
                grant_roles(n_parties, coord.clone()).await;

                eprintln!("[party {}] About to trigger preprocessing on-chain...", my_id);
                tokio::time::sleep(Duration::from_millis(5000)).await;
                trigger_pp(coord).await;
                eprintln!("[party {}] Triggered preprocessing on-chain", my_id);
            } else {
                panic!();
            }
        } else {
            if let (Some(eth), Some(addr)) = (eth.clone(), contract_addr) {
                eprintln!("[party {}] Waiting for preprocessing to be triggered on-chain...", my_id);
                wait_for_pp(coord.clone().unwrap(), contract_block).await;
                eprintln!("[party {}] Preprocessing triggered on-chain", my_id);
            } else {
                panic!();
            }
        } 

        // Run preprocessing
        eprintln!("[party {}] Starting MPC preprocessing...", my_id);
        if let Err(e) = engine.preprocess().await {
            eprintln!("MPC preprocessing failed: {}", e);
            exit(14);
        }
        eprintln!("[party {}] MPC preprocessing complete", my_id);

        // If we have expected clients, start client accept loop and wait for connections
        if !input_ids.is_empty() {
            // currently fixed no. of inputs to 2
            let n_input_masks = 2;

            // obtain the input mask shares
            let input_mask_shares = match mpc_node
                .preprocessing_material
                .lock()
                .await
                .take_random_shares(n_input_masks)
            {
                Ok(shares) => shares,
                Err(e) => {
                    eprintln!("[party {}] Not enough random shares: {:?}", my_id, e);
                    exit(15);
                }
            };

            eprintln!("[party {}] Waiting for {} clients to connect...", my_id, input_ids.len());

            // Spawn client accept loop - this will accept incoming client connections
            // and register them in the network's client_connections
            // We need a mutable copy for accept(), but client_connections is shared via Arc<DashMap>
            let mut accept_net = (*net).clone();
            let expected_client_ids = input_ids.clone();
            let accept_party_id = my_id;

            tokio::spawn(async move {
                eprintln!("[party {}] Client accept loop started", accept_party_id);
                loop {
                    // Accept incoming connection (this blocks until a connection arrives)
                    match accept_net.accept().await {
                        Ok(_) => {
                            // Connection is automatically registered by stoffelnet
                            // based on the ROLE:CLIENT:{id} handshake
                            eprintln!("[party {}] Accepted a client connection", accept_party_id);

                        }
                        Err(e) => {
                            eprintln!("[party {}] Accept error: {}", accept_party_id, e);
                            // Don't break - keep accepting
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            });

            // Wait for all expected clients to connect with timeout
            let connect_timeout = Duration::from_secs(60);
            let check_interval = Duration::from_millis(500);
            let start = std::time::Instant::now();

            loop {
                let connected_clients: Vec<ClientId> = net.clients();
                let connected_count = connected_clients.iter()
                    .filter(|&cid| expected_client_ids.contains(cid))
                    .count();

                eprintln!("[party {}] {} of {} expected clients connected: {:?}",
                         my_id, connected_count, expected_client_ids.len(), connected_clients);

                if connected_count >= expected_client_ids.len() {
                    eprintln!("[party {}] All expected clients connected!", my_id);
                    break;
                }

                if start.elapsed() > connect_timeout {
                    eprintln!("[party {}] Timeout waiting for clients. Connected: {:?}, Expected: {:?}",
                             my_id, connected_clients, expected_client_ids);
                    exit(15);
                }

                tokio::time::sleep(check_interval).await;
            }

            let client_to_addr_and_i: Arc<DashMap<ClientId, (Address, U256)>> = Arc::new(DashMap::new());
            let sig_counter = Arc::new(Semaphore::new(0));

            eprintln!("[party {}] Spawning client message handlers...", my_id);

            for (cid, connection) in net.get_all_client_connections().await {
                // Spawn a handler for this client's messages
                let client_mpc_node = mpc_node.clone();
                let client_net = net.clone();
                let coord = coord.clone().unwrap();
                let client_to_addr_and_i = client_to_addr_and_i.clone();
                let sig_counter = sig_counter.clone();

                tokio::spawn(async move {
                    loop {
                        match connection.receive().await {
                            Ok(data) => {
                                // first message has to be the signed mask index reserved
                                // on-chain
                                if !client_to_addr_and_i.contains_key(&cid) {
                                    eprintln!("[party {}] Received signature of client {}...", my_id, cid);
                                    let sig = {
                                        match bincode::deserialize::<ClientSig>(&data) {
                                            Ok(s) => s,
                                            Err(e) => {
                                                eprintln!("[party {}] Failed to deserialize client signature: {:?}", my_id, e);
                                                continue;
                                            }
                                        }
                                    };

                                    if let Some(addr) = verify_client_sig(sig.clone(), coord.clone()).await {
                                        client_to_addr_and_i.insert(sig.client_id, (addr, sig.i.to()));
                                        eprintln!("[party {}] Signature of client {} is correct...", my_id, cid);
                                        sig_counter.add_permits(1);
                                    } else {
                                        panic!();
                                    }
                                } else {
                                    // Process the message through the MPC node
                                    if let Err(e) = client_mpc_node.clone().process(data, client_net.clone()).await {
                                        eprintln!("[party] Failed to process client message: {:?}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("[party] Client connection closed: {}", e);
                                break;
                            }
                        }
                    }
                });
            }

            let addr_to_i: Arc<DashMap<Address, U256>> = Arc::new(DashMap::new());

            // spawn thread to receive all ReservedInputEvents
            let reserve_inputs_handle = tokio::spawn({
                let contract_addr = contract_addr.unwrap();
                let eth = eth.clone().unwrap();
                let addr_to_i = addr_to_i.clone();
                let input_ids = input_ids.clone();
                async move {
                    let filter = Filter::new()
                        .address(contract_addr)
                        .event(ReservedInputEvent::SIGNATURE)
                        .from_block(contract_block);
            
                    let sub = eth.subscribe_logs(&filter).await.expect("could not subscribe to logs");
                    let mut stream = sub.into_stream();
            
                    while let Some(log) = stream.next().await {
                        match log.topic0() {
                            Some(&ReservedInputEvent::SIGNATURE_HASH) => {
                                let log = match log.log_decode() {
                                    Ok(l) => l,
                                    Err(e) => {
                                        eprintln!("Error decoding ClientInputMaskReservationEvent log: {}", e);
                                        continue;
                                    }
                                };
                                let ReservedInputEvent { client, reservedIndex } = log.inner.data;
                                addr_to_i.insert(client, reservedIndex);
                                eprintln!("[party {}] Recorded reserved mask index {} for client address {:?}",
                                         my_id, reservedIndex, client);
                            }
                            _ => { }
                        }

                        if addr_to_i.len() == input_ids.len() {
                            break;
                        }
                    }
                }
            });

            // tell contract about the number of input masks
            if as_leader {
                init_input_masks(n_input_masks, coord.clone().unwrap()).await;
                eprintln!("[party {}] Input masks initialized on-chain", my_id);
                trigger_input(coord.clone().unwrap()).await;
                eprintln!("[party {}] Input mask initialization triggered on-chain", my_id);
            } else {
                eprintln!("[party {}] Waiting for start of input phase...", my_id);
                wait_for_input(coord.clone().unwrap(), contract_block).await;
            }

            // wait for all clients to reserve their mask index and send a signature of the mask
            // index
            let _ = sig_counter.acquire_many(input_ids.len() as u32).await;
            eprintln!("[party {}] All clients have sent their signatures of reserved mask indices", my_id);

            let _ = reserve_inputs_handle.await;
            eprintln!("[party {}] All clients have reserved mask indices on-chain", my_id);

            // contract should make sure that only authenticated clients can reserve indices
            if client_to_addr_and_i.len() != addr_to_i.len() {
                panic!();
            }

            let mut client_to_index: HashMap<ClientId, usize> = HashMap::new();
            let mut addr_to_index: HashMap<Address, usize> = HashMap::new();
            let mut addr_to_client: HashMap<Address, ClientId> = HashMap::new();

            for e in client_to_addr_and_i.iter() {
                let (client, (addr, signed_i)) = e.pair();
                let reserved_i = {
                    let reserved_i = addr_to_i.get(addr);
                    // all addresses used for signatures should be used to request indices
                    if reserved_i.is_none() {
                        panic!();
                    }
                    *reserved_i.unwrap()
                };

                if reserved_i != *signed_i {
                    eprintln!("[party {}] Client {} signed index {} but reserved index {}",
                             my_id, client, signed_i, reserved_i);
                    panic!();
                }

                client_to_index.insert(*client, signed_i.to());
                addr_to_index.insert(*addr, signed_i.to());
                addr_to_client.insert(*addr, *client);
            }

            eprintln!("[party {}] Initializing InputServer for {} clients...", my_id, input_ids.len());
            // Initialize input server for each expected client
            // Each client needs random shares for their inputs (assume 1 input per client for now)
            for (cid, _) in net.get_all_client_connections().await {
                let mask_shares = vec![input_mask_shares[*client_to_index.get(&cid).unwrap()].clone()];
                let mut mask_shares_bytes = Vec::new();

                if mask_shares.serialize_compressed(&mut mask_shares_bytes).is_err() {
                    panic!();
                }
                eprintln!("[party {}] Sending {} mask shares to client {}...", my_id, mask_shares.len(), cid);
                match net.send_to_client(cid, &mask_shares_bytes).await {
                    Ok(_) => { }
                    Err(e) => {
                        eprintln!("[party {}] Failed to init InputServer for client {}: {:?}", my_id, cid, e);
                        exit(15);
                    }
                }
                eprintln!("[party {}] Sending done, InputServer initialized for client {}", my_id, cid);
            }

            eprintln!("[party {}] Waiting for client inputs...", my_id);

            //  wait for all masked client inputs on-chain
            let masked_inputs = wait_for_masked_inputs(coord.clone().unwrap(), contract_block, input_ids.len()).await;

            let client_inputs: HashMap<ClientId, Vec<RobustShare<Fr>>> = {
                let mut client_inputs: HashMap<ClientId, Vec<RobustShare<Fr>>> = HashMap::new();

                for (addr, masked_inputs_per_client) in masked_inputs {
                    let random_share = &input_mask_shares[*addr_to_index.get(&addr).unwrap()];
                    let cid = *addr_to_client.get(&addr).unwrap();

                    // calculate the masked input shares from the masked inputs
                    client_inputs.insert(cid, masked_inputs_per_client.iter().map(|masked_input| {
                        RobustShare::new(
                            *masked_input - random_share.share[0],
                            random_share.id,
                            random_share.degree
                        )
                    }).collect());
                }
                client_inputs
            };

            eprintln!(
                "[party {}] Received inputs from {} clients",
                my_id,
                client_inputs.len()
            );

            // Store client inputs in the VM's client store
            for (cid, shares) in client_inputs {
                vm.state.client_store().store_client_input(cid, shares);
                eprintln!("[party {}] Stored inputs for client {}", my_id, cid);
            }
        }

        vm.state.set_mpc_engine(engine);
        eprintln!("[party {}] MPC engine set, starting VM execution...", my_id);

        if as_leader {
            trigger_mpc(coord.clone().unwrap()).await;
            eprintln!("[party {}] MPC execution triggered", my_id);
        } else {
            eprintln!("[party {}] Waiting for start of MPC phase...", my_id);
            wait_for_mpc(coord.clone().unwrap(), contract_block).await;
        }
    }
    
    eprintln!("Starting VM execution of '{}'...", agreed_entry);

    let result = {
        // Execute entry function
        match vm.execute(&agreed_entry) {
            Ok(result) => {
                println!("Program returned: {:?}", result);
                result
            }
            Err(err) => {
                eprintln!("Execution error in '{}': {}", agreed_entry, err);
                exit(4);
            }
        }
    };

    // send outputs to clients
    if let Some(net) = net_opt.clone() {
        let my_id = party_id.unwrap_or(0usize);
        let output_share = match result {
            Value::Share(ty, share_bytes) => {
                assert!(matches!(ty, ShareType::SecretInt { .. }));
                let secret = {
                    match VMState::secret_int_from_bytes(ty, &share_bytes) {
                        Ok(secret) => { secret }
                        Err(_) => { panic!(); }
                    }
                };
                secret.share().clone()
            }
            _ => { panic!(); }
        };

        if as_leader {
            trigger_outputs(coord.clone().unwrap()).await;
            eprintln!("[party {}] MPC execution triggered", my_id);
        } else {
            eprintln!("[party {}] Waiting for start of MPC phase...", my_id);
            wait_for_outputs(coord.clone().unwrap(), contract_block).await;
            eprintln!("[party {}] Output phase started", my_id);
        }

        for (cid, _) in net.get_all_client_connections().await {
            let output_shares = vec![output_share.clone()];
            let mut output_share_bytes = Vec::new();

            if output_shares.serialize_compressed(&mut output_share_bytes).is_err() {
                panic!();
            }
            eprintln!("[party {}] Sending {} output shares to client {}...", my_id, output_shares.len(), cid);
            match net.send_to_client(cid, &output_share_bytes).await {
                Ok(_) => { }
                Err(e) => {
                    eprintln!("[party {}] Failed to send output shares to client {}: {:?}", my_id, cid, e);
                    exit(16);
                }
            }
            eprintln!("[party {}] Sending done, output shares sent to client {}", my_id, cid);
        }
    }
}

fn print_usage_and_exit() -> ! {
    eprintln!(
        r#"Stoffel VM Runner

Usage:
  stoffel-run <path-to-compiled-binary> [entry_function] [flags]

Flags:
  --trace-instr           Trace instructions before/after execution
  --trace-regs            Trace register reads/writes
  --trace-stack           Trace function calls and stack push/pop
  --bootnode              Run as bootnode only (coordinates party discovery)
  --leader                Run as leader: bootnode + party 0 in one process
  --client                Run as client (provide inputs to MPC network)
  --bind <addr:port>      Bind address for bootnode or party listen
  --party-id <usize>      Party id (party mode, 0-indexed)
  --bootstrap <addr:port> Bootnode address (party mode or client mode)
  --n-parties <usize>     Number of parties for MPC (required in party/leader/client mode)
  --threshold <usize>     Threshold t for HoneyBadger (default: 1)
  --client-id <usize>     Client ID (client mode)
  --inputs <values>       Comma-separated input values (client mode)
  --servers <addrs>       Comma-separated server addresses (client mode)
  --expected-clients <ids> Comma-separated client IDs expected (party/leader mode)
  -h, --help              Show this help

Multi-Party Execution:
  In party mode, all parties register with the bootnode and wait until
  all n-parties have joined. The bootnode then broadcasts a session with
  a shared instance_id to all parties, ensuring they all use the same
  MPC configuration.

  Use --leader on one party to have it also run the bootnode. This reduces
  the number of processes needed by one.

Examples:
  # Local execution (no MPC)
  stoffel-run program.stfbin
  stoffel-run program.stfbin main --trace-instr

  # Multi-party execution (5 parties, threshold 1) - Leader mode (recommended)
  # Terminal 1: Leader (bootnode + party 0)
  stoffel-run program.stfbin main --leader --bind 127.0.0.1:9000 --n-parties 5 --threshold 1

  # Terminals 2-5: Other parties
  stoffel-run program.stfbin main --party-id 1 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9002 --n-parties 5 --threshold 1
  stoffel-run program.stfbin main --party-id 2 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9003 --n-parties 5 --threshold 1
  stoffel-run program.stfbin main --party-id 3 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9004 --n-parties 5 --threshold 1
  stoffel-run program.stfbin main --party-id 4 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9005 --n-parties 5 --threshold 1

  # Alternative: Separate bootnode (6 processes total)
  # Terminal 1: Bootnode only
  stoffel-run --bootnode --bind 127.0.0.1:9000 --n-parties 5

  # Terminals 2-6: All parties
  stoffel-run program.stfbin main --party-id 0 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9001 --n-parties 5 --threshold 1
  stoffel-run program.stfbin main --party-id 1 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9002 --n-parties 5 --threshold 1
  # ... etc

  # Multi-party execution with client inputs
  # Terminal 1: Leader with expected clients
  stoffel-run program.stfbin main --leader --bind 127.0.0.1:9000 --n-parties 5 --threshold 1 --expected-clients 100,101

  # Terminals 2-5: Other parties (same expected-clients)
  stoffel-run program.stfbin main --party-id 1 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9002 --n-parties 5 --expected-clients 100,101
  # ... etc

  # Client mode: provide inputs to the MPC network
  # Note: clients connect directly to party servers, not the bootnode
  stoffel-run --client --client-id 100 --inputs 10,20 --servers 127.0.0.1:10000,127.0.0.1:9002,127.0.0.1:9003,127.0.0.1:9004,127.0.0.1:9005 --n-parties 5
  stoffel-run --client --client-id 101 --inputs 30,40 --servers 127.0.0.1:10000,127.0.0.1:9002,127.0.0.1:9003,127.0.0.1:9004,127.0.0.1:9005 --n-parties 5

  # Docker example with client inputs:
  # Start parties with expected-clients:
  # docker run ... -e STOFFEL_EXPECTED_CLIENTS=100,101 stoffelvm:latest
  # Then run clients connecting to the party servers:
  stoffel-run --client --client-id 100 --inputs 42 --servers 172.18.0.2:9000,172.18.0.3:9000,172.18.0.4:9000,172.18.0.5:9000,172.18.0.6:9000 --n-parties 5
"#
    );
    exit(1);
}
