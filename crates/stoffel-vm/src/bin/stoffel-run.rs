use std::env;
use std::process::exit;
use std::net::SocketAddr;

use stoffel_vm::core_vm::VirtualMachine;
use stoffel_vm::runtime_hooks::{HookContext, HookEvent};
use stoffel_vm_types::compiled_binary::{CompiledBinary};
use std::fs::File;
use std::io::Read;
use stoffel_vm::net::NetworkManager;
use stoffel_vm::net::{run_bootnode, wait_until_min_parties, agree_and_sync_program, program_id_from_bytes, bootstrap_with_bootnode};
use stoffel_vm::net::p2p::QuicNetworkManager;
use stoffelnet::network_utils::Network;
use std::sync::Arc;
use std::time::Duration;
use stoffel_vm::net::session::{agree_session_with_bootnode};
use stoffel_vm::net::hb_engine::HoneyBadgerMpcEngine;
use rand::RngCore;

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
    let mut bind_addr: Option<SocketAddr> = None;
    let mut party_id: Option<usize> = None;
    let mut bootstrap_addr: Option<SocketAddr> = None;
    let mut min_parties: Option<usize> = None;
    let mut n_parties: Option<usize> = None;
    let mut threshold: Option<usize> = None;

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
        } else if let Some(_rest) = arg.strip_prefix("--bind") {
            // support "--bind" and "--bind=.."
            // actual value parsed later from positional with key
        } else if let Some(_rest) = arg.strip_prefix("--party-id") {
        } else if let Some(_rest) = arg.strip_prefix("--bootstrap") {
        } else if let Some(_rest) = arg.strip_prefix("--min-parties") {
        } else if let Some(_rest) = arg.strip_prefix("--n-parties") {
        } else if let Some(_rest) = arg.strip_prefix("--threshold") {
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
            "--min-parties" => {
                if let Some(v) = args_iter.next() {
                    min_parties = Some(v.parse().expect("Invalid --min-parties"));
                }
            }
            "--n-parties" => {
                if let Some(v) = args_iter.next() { n_parties = Some(v.parse().expect("Invalid --n-parties")); }
            }
            "--threshold" => {
                if let Some(v) = args_iter.next() { threshold = Some(v.parse().expect("Invalid --threshold")); }
            }
            _ => {}
        }
    }

    // Bootnode mode
    if as_bootnode {
        let bind = bind_addr.unwrap_or_else(|| "127.0.0.1:9000".parse().unwrap());
        eprintln!("Starting bootnode on {}", bind);
        // Install crypto provider for quinn/rustls
        rustls::crypto::ring::default_provider().install_default().expect("install rustls crypto");
        if let Err(e) = run_bootnode(bind).await {
            eprintln!("Bootnode error: {}", e);
            exit(10);
        }
        return;
    }

    path_opt = if !positional.is_empty() { Some(positional.remove(0)) } else { None };
    entry = if !positional.is_empty() { positional.remove(0) } else { entry };

    // Optional: bring up networking in party mode if bootstrap provided
    let mut net_opt: Option<Arc<QuicNetworkManager>> = None;
    let mut program_bytes: Option<Vec<u8>> = None;
    let mut program_id: [u8; 32] = [0u8; 32];
    let mut agreed_entry = entry.clone();
    if let Some(bootnode) = bootstrap_addr {
        let bind = bind_addr.unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());
        let my_id = party_id.unwrap_or(0usize);
        rustls::crypto::ring::default_provider().install_default().expect("install rustls crypto");
        // Prepare QUIC manager
        let mut mgr = QuicNetworkManager::new();
        // Listen so peers can connect back directly
        if let Err(e) = mgr.listen(bind).await {
            eprintln!("Failed to listen on {}: {}", bind, e);
            exit(11);
        }
        if let Err(e) = bootstrap_with_bootnode(&mut mgr, bootnode, my_id, bind).await {
            eprintln!("bootstrap failed: {}", e);
            exit(12);
        }
        if let Some(n) = min_parties {
            if let Err(e) = wait_until_min_parties(&mgr, n, Duration::from_secs(10)).await {
                eprintln!("waiting for parties failed: {}", e);
                exit(13);
            }
        }
        // program agreement + sync
        let mut bn_conn = mgr.connect(bootnode).await.expect("connect bootnode");
        // local bytes if provided
        if let Some(p) = &path_opt {
            let bytes = std::fs::read(p).expect("read program");
            program_id = program_id_from_bytes(&bytes);
            program_bytes = Some(bytes);
        }
        let (pid, _sz, agreed_entry_s) = agree_and_sync_program(&mut *bn_conn, my_id, &entry, program_bytes.clone()).await.expect("program agree/sync");
        program_id = pid;
        agreed_entry = agreed_entry_s;
        let net = Arc::new(mgr);
        net_opt = Some(net.clone());
    } else {
        // local run: must have path
        if let Some(p) = &path_opt {
            program_bytes = Some(std::fs::read(p).expect("read program"));
            program_id = program_id_from_bytes(program_bytes.as_ref().unwrap());
        } else {
            eprintln!("Error: local run requires a program path unless --bootnode");
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
    if functions.is_empty() { eprintln!("Error: compiled program contains no functions"); exit(3); }

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
            |event| matches!(event, HookEvent::BeforeInstructionExecute(_) | HookEvent::AfterInstructionExecute(_)),
            |event, ctx: &HookContext| {
                match event {
                    HookEvent::BeforeInstructionExecute(instr) => {
                        let fn_name = ctx.get_function_name().unwrap_or_else(|| "<unknown>".to_string());
                        let pc = ctx.get_current_instruction();
                        eprintln!("[instr][depth {}][{}][pc {}] BEFORE {:?}", ctx.get_call_depth(), fn_name, pc, instr);
                        Ok(())
                    }
                    HookEvent::AfterInstructionExecute(instr) => {
                        let fn_name = ctx.get_function_name().unwrap_or_else(|| "<unknown>".to_string());
                        let pc = ctx.get_current_instruction();
                        eprintln!("[instr][depth {}][{}][pc {}] AFTER  {:?}", ctx.get_call_depth(), fn_name, pc, instr);
                        Ok(())
                    }
                    _ => Ok(())
                }
            },
            0,
        );
    }

    if trace_regs {
        vm.register_hook(
            |event| matches!(event, HookEvent::RegisterRead(_, _) | HookEvent::RegisterWrite(_, _, _)),
            |event, ctx: &HookContext| {
                match event {
                    HookEvent::RegisterRead(idx, val) => {
                        let fn_name = ctx.get_function_name().unwrap_or_else(|| "<unknown>".to_string());
                        eprintln!("[regs][depth {}][{}] R{} -> {:?}", ctx.get_call_depth(), fn_name, idx, val);
                        Ok(())
                    }
                    HookEvent::RegisterWrite(idx, old, new) => {
                        let fn_name = ctx.get_function_name().unwrap_or_else(|| "<unknown>".to_string());
                        eprintln!("[regs][depth {}][{}] R{}: {:?} -> {:?}", ctx.get_call_depth(), fn_name, idx, old, new);
                        Ok(())
                    }
                    _ => Ok(())
                }
            },
            0,
        );
    }

    if trace_stack {
        vm.register_hook(
            |event| matches!(event, HookEvent::BeforeFunctionCall(_, _) | HookEvent::AfterFunctionCall(_, _) | HookEvent::StackPush(_) | HookEvent::StackPop(_)),
            |event, ctx: &HookContext| {
                match event {
                    HookEvent::BeforeFunctionCall(func, args) => {
                        eprintln!("[stack][depth {}] CALL {:?} with {:?}", ctx.get_call_depth(), func, args);
                        Ok(())
                    }
                    HookEvent::AfterFunctionCall(func, ret) => {
                        eprintln!("[stack][depth {}] RET  {:?} => {:?}", ctx.get_call_depth(), func, ret);
                        Ok(())
                    }
                    HookEvent::StackPush(v) => {
                        let fn_name = ctx.get_function_name().unwrap_or_else(|| "<unknown>".to_string());
                        eprintln!("[stack][depth {}][{}] PUSH {:?}", ctx.get_call_depth(), fn_name, v);
                        Ok(())
                    }
                    HookEvent::StackPop(v) => {
                        let fn_name = ctx.get_function_name().unwrap_or_else(|| "<unknown>".to_string());
                        eprintln!("[stack][depth {}][{}] POP  {:?}", ctx.get_call_depth(), fn_name, v);
                        Ok(())
                    }
                    _ => Ok(())
                }
            },
            0,
        );
    }

    // If in party mode, configure async HoneyBadger engine and preprocess
    if let Some(net) = net_opt.clone() {
        let my_id = party_id.unwrap_or(0usize);
        let n = n_parties.unwrap_or_else(|| net.parties().len());
        let t = threshold.unwrap_or(1);
        // Generate a random instance ID locally for this run
        let mut b = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut b);
        let instance_id = u64::from_le_bytes(b);
        // Construct engine
        let engine = HoneyBadgerMpcEngine::new(
            instance_id,
            my_id,
            n,
            t,
            8, 16,
            net.clone(),
        );
        // Fully async preprocessing
        if let Err(e) = engine.start_async().await {
            eprintln!("MPC preprocessing failed: {}", e);
            exit(14);
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
        "Stoffel VM Runner\n\nUsage:\n  stoffel-run <path-to-compiled-binary> [entry_function] [flags]\n\nFlags:\n  --trace-instr   Trace instructions before/after execution\n  --trace-regs    Trace register reads/writes\n  --trace-stack   Trace function calls and stack push/pop\n  --bootnode              Run as bootnode only\n  --bind <addr:port>      Bind address for bootnode or party listen\n  --party-id <usize>      Party id (party mode)\n  --bootstrap <addr:port> Bootnode address (party mode)\n  --min-parties <usize>   Wait until this many parties discovered before VM run\n  --n-parties <usize>     Expected parties for MPC engine (default: discovered)\n  --threshold <usize>     Threshold t for HoneyBadger (default: 1)\n  -h, --help      Show this help\n\nExamples:\n  stoffel-run program.stfbin\n  stoffel-run program.stfbin main --trace-instr --trace-regs\n  stoffel-run --bootnode --bind 127.0.0.1:9000\n  stoffel-run program.stfbin main --bind 127.0.0.1:9001 --party-id 1 --bootstrap 127.0.0.1:9000 --min-parties 3 --n-parties 5 --threshold 1\n"
    );
    exit(1);
}
