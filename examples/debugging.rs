use stoffel_vm::core_vm::VirtualMachine;
use stoffel_vm::functions::VMFunction;
use stoffel_vm::instructions::Instruction;
use stoffel_vm::core_types::Value;
use stoffel_vm::runtime_hooks::HookEvent;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

fn main() -> Result<(), String> {
    // Initialize the VM
    let mut vm = VirtualMachine::new();

    // Create a simple function to debug
    let mut factorial_labels = HashMap::new();
    factorial_labels.insert("base_case".to_string(), 6);
    factorial_labels.insert("recursive_case".to_string(), 8);

    let factorial = VMFunction::new(
        "factorial".to_string(),
        vec!["n".to_string()],
        vec![],
        None,
        5,
        vec![
            // Check if n == 1
            Instruction::LDI(1, Value::Int(1)),
            Instruction::CMP(0, 1),
            Instruction::JMPEQ("base_case".to_string()),
            // Check if n < 1
            Instruction::CMP(1, 0),
            Instruction::JMPNEQ("recursive_case".to_string()),
            Instruction::JMP("base_case".to_string()),
            // base_case: return 1
            Instruction::LDI(0, Value::Int(1)),
            Instruction::RET(0),
            // recursive_case: return n * factorial(n-1)
            Instruction::MOV(3, 0),
            Instruction::LDI(1, Value::Int(1)),
            Instruction::SUB(2, 0, 1),
            Instruction::PUSHARG(2),
            Instruction::CALL("factorial".to_string()),
            Instruction::MUL(0, 3, 0),
            Instruction::RET(0),
        ],
        factorial_labels,
    );

    // Register the function with the VM
    vm.register_function(factorial);

    // Set up debugging hooks

    // 1. Track instruction execution
    let instruction_log = Arc::new(Mutex::new(Vec::new()));
    let instruction_log_clone = Arc::clone(&instruction_log);

    vm.register_hook(
        |event| matches!(event, HookEvent::BeforeInstructionExecute(_)),
        move |event, ctx| {
            if let HookEvent::BeforeInstructionExecute(instruction) = event {
                if let Ok(mut log) = instruction_log_clone.lock() {
                    let function_name = ctx.get_function_name().unwrap_or_default();
                    let ip = ctx.get_current_instruction();
                    log.push(format!("[{}:{}] {:?}", function_name, ip, instruction));
                }
            }
            Ok(())
        },
        100,
    );

    // 2. Track register writes
    let register_log = Arc::new(Mutex::new(Vec::new()));
    let register_log_clone = Arc::clone(&register_log);

    vm.register_hook(
        |event| matches!(event, HookEvent::RegisterWrite(_, _, _)),
        move |event, ctx| {
            if let HookEvent::RegisterWrite(reg, old_value, new_value) = event {
                if let Ok(mut log) = register_log_clone.lock() {
                    log.push(format!("r{}: {:?} -> {:?}", reg, old_value, new_value));
                }
            }
            Ok(())
        },
        90,
    );

    // 3. Track function calls
    let call_log = Arc::new(Mutex::new(Vec::new()));
    let call_log_clone = Arc::clone(&call_log);

    vm.register_hook(
        |event| {
            matches!(event, HookEvent::BeforeFunctionCall(_, _)) || 
            matches!(event, HookEvent::AfterFunctionCall(_, _))
        },
        move |event, ctx| {
            if let Ok(mut log) = call_log_clone.lock() {
                match event {
                    HookEvent::BeforeFunctionCall(_, args) => {
                        let depth = ctx.get_call_depth();
                        let indent = "  ".repeat(depth);
                        let arg_str = if !args.is_empty() {
                            format!("{:?}", args[0])
                        } else {
                            "no args".to_string()
                        };
                        log.push(format!("{}-> CALL factorial({})", indent, arg_str));
                    },
                    HookEvent::AfterFunctionCall(_, result) => {
                        let depth = ctx.get_call_depth();
                        let indent = "  ".repeat(depth);
                        log.push(format!("{}<- RETURN {:?}", indent, result));
                    },
                    _ => {}
                }
            }
            Ok(())
        },
        80,
    );

    // Execute the factorial function with argument 5
    let args = vec![Value::Int(5)];
    let result = vm.execute_with_args("factorial", &args)?;

    println!("factorial(5) = {:?}", result);

    // Print debug logs
    println!("\nInstruction Execution Log:");
    println!("-------------------------");
    if let Ok(log) = instruction_log.lock() {
        for entry in log.iter() {
            println!("{}", entry);
        }
    }

    println!("\nRegister Write Log:");
    println!("-----------------");
    if let Ok(log) = register_log.lock() {
        for entry in log.iter() {
            println!("{}", entry);
        }
    }

    println!("\nFunction Call Log:");
    println!("----------------");
    if let Ok(log) = call_log.lock() {
        for entry in log.iter() {
            println!("{}", entry);
        }
    }

    Ok(())
}
