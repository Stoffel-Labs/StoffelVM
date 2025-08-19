use std::env;
use std::process::exit;

use stoffel_vm::core_vm::VirtualMachine;
use stoffel_vm::runtime_hooks::{HookContext, HookEvent};
use stoffel_vm_types::compiled_binary::utils::{load_from_file, to_vm_functions};

fn print_usage_and_exit() -> ! {
    eprintln!(
        "Stoffel VM Runner\n\nUsage:\n  stoffel-run <path-to-compiled-binary> [entry_function] [flags]\n\nFlags:\n  --trace-instr   Trace instructions before/after execution\n  --trace-regs    Trace register reads/writes\n  --trace-stack   Trace function calls and stack push/pop\n  -h, --help      Show this help\n\nExamples:\n  stoffel-run program.stfbin\n  stoffel-run program.stfbin main --trace-instr --trace-regs\n"
    );
    exit(1);
}

fn main() {
    let raw_args = env::args().skip(1).collect::<Vec<_>>();

    if raw_args.is_empty() {
        print_usage_and_exit();
    }

    let mut path: Option<String> = None;
    let mut entry: Option<String> = None;

    let mut trace_instr = false;
    let mut trace_regs = false;
    let mut trace_stack = false;

    for arg in &raw_args {
        if arg == "-h" || arg == "--help" {
            print_usage_and_exit();
        } else if arg == "--trace-instr" {
            trace_instr = true;
        } else if arg == "--trace-regs" {
            trace_regs = true;
        } else if arg == "--trace-stack" {
            trace_stack = true;
        }
    }

    // collect positional args (non-flags)
    let mut positional = raw_args
        .into_iter()
        .filter(|a| !a.starts_with("--"))
        .collect::<Vec<_>>();

    if positional.is_empty() {
        print_usage_and_exit();
    }

    let path = positional.remove(0);
    let entry = if !positional.is_empty() { positional.remove(0) } else { "main".to_string() };

    // Load compiled binary
    let binary = match load_from_file(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: failed to load compiled binary from '{}': {:?}", path, e);
            exit(2);
        }
    };

    // Convert to VM functions
    let functions = to_vm_functions(&binary);

    if functions.is_empty() {
        eprintln!("Error: compiled binary '{}' contains no functions", path);
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

    // Execute entry function
    match vm.execute(&entry) {
        Ok(result) => {
            println!("Program returned: {:?}", result);
        }
        Err(err) => {
            eprintln!("Execution error in '{}': {}", entry, err);
            exit(4);
        }
    }
}