use std::env;
use std::net::SocketAddr;
use std::process::exit;

use ark_bls12_381::Fr;
use std::fs::File;
use std::sync::Arc;
use std::time::Duration;
use stoffel_vm::core_vm::VirtualMachine;
use stoffel_vm::net::hb_engine::HoneyBadgerMpcEngine;
use stoffel_vm::net::{
    honeybadger_node_opts, program_id_from_bytes, register_and_wait_for_session_with_program,
    run_bootnode_with_config, spawn_receive_loops,
};
use stoffel_vm::runtime_hooks::{HookContext, HookEvent};
use stoffel_vm_types::compiled_binary::CompiledBinary;
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::MPCProtocol;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::HoneyBadgerMPCNode;
use stoffelnet::network_utils::ClientId;
use stoffelnet::network_utils::Network;
use stoffelnet::transports::quic::{NetworkManager, QuicNetworkConfig, QuicNetworkManager};

// Use a Tokio runtime for async operations
#[tokio::main]
async fn main() {
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
            _ => {}
        }
    }

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
    // NOTE: Client mode is currently a placeholder. Full client mode requires:
    // 1. Server addresses to be provided (not from bootnode - clients are separate)
    // 2. HoneyBadgerMPCClient to be wrapped in Arc for sharing
    // For now, client inputs should be provided via a separate client binary or
    // by using the test harness in mpc_multiplication_integration.rs
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

        eprintln!(
            "[client {}] Client mode (n={}, t={}, {} inputs)",
            cid, n, t, input_len
        );
        eprintln!("NOTE: Client mode is not yet fully implemented.");
        eprintln!("Currently, client inputs should be provided using the test harness or");
        eprintln!("by running parties with --expected-clients and waiting for direct connections.");
        eprintln!("");
        eprintln!("To provide inputs, parties should use:");
        eprintln!("  --expected-clients {}", cid);
        eprintln!("And the program should use secret_input(client_id) to receive them.");
        exit(0);
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

        // Run preprocessing
        eprintln!("[party {}] Starting MPC preprocessing...", my_id);
        if let Err(e) = engine.preprocess().await {
            eprintln!("MPC preprocessing failed: {}", e);
            exit(14);
        }
        eprintln!("[party {}] MPC preprocessing complete", my_id);

        // If we have expected clients, initialize InputServer and wait for inputs
        if !input_ids.is_empty() {
            eprintln!("[party {}] Initializing InputServer for {} clients...", my_id, input_ids.len());

            // Initialize input server for each expected client
            // Each client needs random shares for their inputs (assume 1 input per client for now)
            for &cid in &input_ids {
                // Take random shares from preprocessing material
                let local_shares = match mpc_node
                    .preprocessing_material
                    .lock()
                    .await
                    .take_random_shares(1) // 1 input per client
                {
                    Ok(shares) => shares,
                    Err(e) => {
                        eprintln!("[party {}] Not enough random shares for client {}: {:?}", my_id, cid, e);
                        exit(15);
                    }
                };

                if let Err(e) = mpc_node
                    .preprocess
                    .input
                    .init(cid, local_shares, 1, net.clone())
                    .await
                {
                    eprintln!("[party {}] Failed to init InputServer for client {}: {:?}", my_id, cid, e);
                    exit(15);
                }
                eprintln!("[party {}] InputServer initialized for client {}", my_id, cid);
            }

            // Wait for all client inputs with timeout
            eprintln!("[party {}] Waiting for client inputs (timeout: 60s)...", my_id);
            let client_inputs = match mpc_node
                .preprocess
                .input
                .wait_for_all_inputs(Duration::from_secs(60))
                .await
            {
                Ok(inputs) => inputs,
                Err(e) => {
                    eprintln!("[party {}] Failed to receive client inputs: {:?}", my_id, e);
                    exit(16);
                }
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
    }

    // Execute entry function
    match vm.execute(&agreed_entry) {
        Ok(result) => {
            println!("Program returned: {:?}", result);
        }
        Err(err) => {
            eprintln!("Execution error in '{}': {}", agreed_entry, err);
            exit(4);
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
  stoffel-run --client --client-id 100 --inputs 10,20 --bootstrap 127.0.0.1:9000 --n-parties 5
  stoffel-run --client --client-id 101 --inputs 30,40 --bootstrap 127.0.0.1:9000 --n-parties 5
"#
    );
    exit(1);
}
