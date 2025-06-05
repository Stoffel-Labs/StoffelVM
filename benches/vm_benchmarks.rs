// VM Benchmarks
// This file contains benchmarks for the StoffelVM virtual machine.
//
// The benchmarks are designed to measure the performance of different aspects of the VM:
//
// 1. Basic Operations (bench_basic_operations):
//    - Original benchmarks that measure arithmetic and register operations
//    - Each benchmark creates a new VM instance, which includes initialization overhead
//
// 2. Optimized Operations (bench_optimized_operations):
//    - Improved benchmarks that separate setup from measurement
//    - VM is initialized once outside the benchmark, reducing initialization overhead
//    - Includes warmup runs to ensure instructions are cached and resolved
//
// 3. Individual Instructions (bench_individual_instructions):
//    - Microbenchmarks for individual instructions (ADD, MUL, MOV)
//    - Measures the performance of specific instructions in isolation
//
// 4. VM Components (bench_vm_components):
//    - Benchmarks that isolate different VM components
//    - Measures instruction dispatch overhead
//
// 5. Hook System (bench_hook_system, bench_optimized_hook_system):
//    - Measures the overhead of the hook system
//    - Compares execution with and without hooks
//    - The optimized version uses the same VM instance and enables/disables hooks
//
// 6. Parameterized Benchmarks (bench_parameterized):
//    - Measures how performance scales with different parameters
//    - Tests with different numbers of instructions
//
// 7. Memory Overhead (bench_memory_overhead):
//    - Measures memory allocation overhead
//    - Tests with different array sizes
//
// 8. Core Execution (bench_core_execution):
//    - Uses a custom VM execution method that bypasses certain overhead
//    - Compares regular execution with optimized execution
//    - Provides a more accurate measurement of the core execution loop

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use stoffel_vm::core_vm::VirtualMachine;
use stoffel_vm::functions::VMFunction;
use stoffel_vm::instructions::Instruction;
use stoffel_vm::core_types::Value;
use stoffel_vm::runtime_hooks::{HookEvent, HookContext};
use std::collections::HashMap;
use std::time::Duration;

fn bench_basic_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Basic Operations");

    // Benchmark arithmetic operations
    {
        let mut vm = VirtualMachine::new();
        let arithmetic = VMFunction::new(
            "arithmetic_test".to_string(),
            vec![],
            vec![],
            None,
            4,
            vec![
                Instruction::LDI(0, Value::Int(10)),
                Instruction::LDI(1, Value::Int(20)),
                Instruction::ADD(2, 0, 1),
                Instruction::MUL(3, 2, 1),
                Instruction::RET(3),
            ],
            HashMap::new(),
        );
        vm.register_function(arithmetic);

        group.bench_function("arithmetic", |b| {
            b.iter(|| {
                black_box(vm.execute("arithmetic_test").unwrap())
            });
        });
    }

    // Benchmark register operations
    {
        let mut vm = VirtualMachine::new();
        let registers = VMFunction::new(
            "register_test".to_string(),
            vec![],
            vec![],
            None,
            3,
            vec![
                Instruction::LDI(0, Value::Int(42)),
                Instruction::MOV(1, 0),
                Instruction::MOV(2, 1),
                Instruction::RET(2),
            ],
            HashMap::new(),
        );
        vm.register_function(registers);

        group.bench_function("registers", |b| {
            b.iter(|| {
                black_box(vm.execute("register_test").unwrap())
            });
        });
    }

    group.finish();
}

fn bench_function_calls(c: &mut Criterion) {
    let mut group = c.benchmark_group("Function Calls");

    // Benchmark regular function calls
    {
        let mut vm = VirtualMachine::new();
        let simple_func = VMFunction::new(
            "simple_function".to_string(),
            vec!["x".to_string()],
            vec![],
            None,
            2,
            vec![
                Instruction::ADD(1, 0, 0),  // Double the input
                Instruction::RET(1),
            ],
            HashMap::new(),
        );
        vm.register_function(simple_func);

        let caller = VMFunction::new(
            "caller".to_string(),
            vec![],
            vec![],
            None,
            2,
            vec![
                Instruction::LDI(0, Value::Int(42)),
                Instruction::PUSHARG(0),
                Instruction::CALL("simple_function".to_string()),
                Instruction::RET(0),
            ],
            HashMap::new(),
        );
        vm.register_function(caller);

        group.bench_function("regular_call", |b| {
            b.iter(|| {
                black_box(vm.execute("caller").unwrap())
            });
        });
    }

    // Benchmark closure creation and calls
    {
        let mut vm = VirtualMachine::new();
        let create_adder = VMFunction::new(
            "create_adder".to_string(),
            vec!["x".to_string()],
            vec![],
            None,
            3,
            vec![
                Instruction::LDI(1, Value::String("add".to_string())),
                Instruction::PUSHARG(1),
                Instruction::LDI(2, Value::String("x".to_string())),
                Instruction::PUSHARG(2),
                Instruction::CALL("create_closure".to_string()),
                Instruction::RET(0),
            ],
            HashMap::new(),
        );

        let add = VMFunction::new(
            "add".to_string(),
            vec!["y".to_string()],
            vec!["x".to_string()],
            Some("create_adder".to_string()),
            3,
            vec![
                Instruction::LDI(1, Value::String("x".to_string())),
                Instruction::PUSHARG(1),
                Instruction::CALL("get_upvalue".to_string()),
                Instruction::ADD(2, 0, 1),
                Instruction::RET(2),
            ],
            HashMap::new(),
        );

        vm.register_function(create_adder);
        vm.register_function(add);

        group.bench_function("closure", |b| {
            b.iter(|| {
                let args = vec![Value::Int(5)];
                black_box(vm.execute_with_args("create_adder", &args).unwrap())
            });
        });
    }

    group.finish();
}

fn bench_object_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Object Operations");

    // Benchmark object creation and field access
    {
        let mut vm = VirtualMachine::new();
        let object_ops = VMFunction::new(
            "object_ops".to_string(),
            vec![],
            vec![],
            None,
            4,
            vec![
                // Create object
                Instruction::CALL("create_object".to_string()),
                Instruction::MOV(1, 0),
                // Set field
                Instruction::PUSHARG(1),
                Instruction::LDI(2, Value::String("field".to_string())),
                Instruction::PUSHARG(2),
                Instruction::LDI(3, Value::Int(42)),
                Instruction::PUSHARG(3),
                Instruction::CALL("set_field".to_string()),
                // Get field
                Instruction::PUSHARG(1),
                Instruction::PUSHARG(2),
                Instruction::CALL("get_field".to_string()),
                Instruction::RET(0),
            ],
            HashMap::new(),
        );
        vm.register_function(object_ops);

        group.bench_function("object_access", |b| {
            b.iter(|| {
                black_box(vm.execute("object_ops").unwrap())
            });
        });
    }

    group.finish();
}

fn bench_array_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Array Operations");

    // Benchmark array creation and element access
    {
        let mut vm = VirtualMachine::new();
        let array_ops = VMFunction::new(
            "array_ops".to_string(),
            vec![],
            vec![],
            None,
            4,
            vec![
                // Create array
                Instruction::CALL("create_array".to_string()),
                Instruction::MOV(1, 0),
                // Push elements
                Instruction::PUSHARG(1),
                Instruction::LDI(2, Value::Int(42)),
                Instruction::PUSHARG(2),
                Instruction::CALL("array_push".to_string()),
                // Get element
                Instruction::PUSHARG(1),
                Instruction::LDI(3, Value::Int(1)),
                Instruction::PUSHARG(3),
                Instruction::CALL("get_field".to_string()),
                Instruction::RET(0),
            ],
            HashMap::new(),
        );
        vm.register_function(array_ops);

        group.bench_function("array_access", |b| {
            b.iter(|| {
                black_box(vm.execute("array_ops").unwrap())
            });
        });
    }

    group.finish();
}

fn bench_hook_system(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hook System");

    // Benchmark execution with and without hooks
    {
        let mut vm = VirtualMachine::new();
        let simple_prog = VMFunction::new(
            "simple_prog".to_string(),
            vec![],
            vec![],
            None,
            3,
            vec![
                Instruction::LDI(0, Value::Int(1)),
                Instruction::LDI(1, Value::Int(2)),
                Instruction::ADD(2, 0, 1),
                Instruction::RET(2),
            ],
            HashMap::new(),
        );
        vm.register_function(simple_prog);

        // Benchmark without hooks
        group.bench_function("no_hooks", |b| {
            b.iter(|| {
                black_box(vm.execute("simple_prog").unwrap())
            });
        });

        // Add a simple instruction hook
        vm.register_hook(
            |_| true,
            |_, _| Ok(()),
            100,
        );

        // Benchmark with hooks
        group.bench_function("with_hooks", |b| {
            b.iter(|| {
                black_box(vm.execute("simple_prog").unwrap())
            });
        });
    }

    group.finish();
}

fn bench_optimized_hook_system(c: &mut Criterion) {
    let mut group = c.benchmark_group("Optimized Hook System");

    // Configure the benchmark group
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(100);

    // Setup VM once outside the benchmark
    let mut vm = VirtualMachine::new();

    // Create a test program with different instruction types
    let test_prog = VMFunction::new(
        "test_prog".to_string(),
        vec![],
        vec![],
        None,
        5,
        vec![
            // Mix of different instruction types
            Instruction::LDI(0, Value::Int(10)),
            Instruction::LDI(1, Value::Int(20)),
            Instruction::ADD(2, 0, 1),
            Instruction::MUL(3, 2, 1),
            Instruction::MOV(4, 3),
            Instruction::RET(4),
        ],
        HashMap::new(),
    );
    vm.register_function(test_prog);

    // Warmup run
    vm.execute("test_prog").unwrap();

    // Benchmark without hooks
    group.bench_function("baseline_no_hooks", |b| {
        b.iter(|| {
            black_box(vm.execute("test_prog").unwrap())
        });
    });

    // Register different types of hooks to measure their overhead

    // 1. Simple instruction hook that does nothing
    let hook_id1 = vm.register_hook(
        |_| true,  // Match all instructions
        |_, _| Ok(()),  // Do nothing
        100,
    );

    // Warmup with hook
    vm.execute("test_prog").unwrap();

    // Benchmark with simple hook
    group.bench_function("simple_hook", |b| {
        b.iter(|| {
            black_box(vm.execute("test_prog").unwrap())
        });
    });

    // Unregister the simple hook instead of just disabling it
    vm.unregister_hook(hook_id1);

    // 2. Register hook that only matches specific instructions
    let hook_id2 = vm.register_hook(
        |event| {
            if let HookEvent::BeforeInstructionExecute(instruction) = event {
                matches!(instruction, Instruction::ADD(_, _, _))
            } else {
                false
            }
        },
        |_, _| Ok(()),
        100,
    );

    // Warmup with selective hook
    vm.execute("test_prog").unwrap();

    // Benchmark with selective hook
    group.bench_function("selective_hook", |b| {
        b.iter(|| {
            black_box(vm.execute("test_prog").unwrap())
        });
    });

    // Unregister the selective hook instead of just disabling it
    vm.unregister_hook(hook_id2);

    // 3. Register multiple hooks with different priorities
    let hook_id3 = vm.register_hook(
        |_| true,
        |_, _| Ok(()),
        100,
    );

    let hook_id4 = vm.register_hook(
        |_| true,
        |_, _| Ok(()),
        200,
    );

    let hook_id5 = vm.register_hook(
        |_| true,
        |_, _| Ok(()),
        300,
    );

    // Warmup with multiple hooks
    vm.execute("test_prog").unwrap();

    // Benchmark with multiple hooks
    group.bench_function("multiple_hooks", |b| {
        b.iter(|| {
            black_box(vm.execute("test_prog").unwrap())
        });
    });

    // Unregister all hooks instead of just disabling them
    vm.unregister_hook(hook_id3);
    vm.unregister_hook(hook_id4);
    vm.unregister_hook(hook_id5);

    group.finish();
}

fn bench_optimized_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Optimized Operations");

    // Configure the benchmark group
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(100);

    // Setup VM once outside the benchmark
    let mut vm = VirtualMachine::new();

    // Register arithmetic function
    let arithmetic = VMFunction::new(
        "arithmetic_test".to_string(),
        vec![],
        vec![],
        None,
        4,
        vec![
            Instruction::LDI(0, Value::Int(10)),
            Instruction::LDI(1, Value::Int(20)),
            Instruction::ADD(2, 0, 1),
            Instruction::MUL(3, 2, 1),
            Instruction::RET(3),
        ],
        HashMap::new(),
    );
    vm.register_function(arithmetic);

    // Ensure instructions are cached and resolved before benchmarking
    vm.execute("arithmetic_test").unwrap(); // Warmup run

    // Only measure the execution
    group.bench_function("arithmetic_optimized", |b| {
        b.iter(|| {
            black_box(vm.execute("arithmetic_test").unwrap())
        });
    });

    // Register register operations function
    let registers = VMFunction::new(
        "register_test".to_string(),
        vec![],
        vec![],
        None,
        3,
        vec![
            Instruction::LDI(0, Value::Int(42)),
            Instruction::MOV(1, 0),
            Instruction::MOV(2, 1),
            Instruction::RET(2),
        ],
        HashMap::new(),
    );
    vm.register_function(registers);

    // Warmup
    vm.execute("register_test").unwrap();

    // Benchmark
    group.bench_function("registers_optimized", |b| {
        b.iter(|| {
            black_box(vm.execute("register_test").unwrap())
        });
    });

    group.finish();
}

fn bench_core_execution(c: &mut Criterion) {
    let mut group = c.benchmark_group("Core Execution");

    // Configure the benchmark group
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(100);

    // Setup VM once outside the benchmark
    let mut vm = VirtualMachine::new();

    // Register a variety of functions to benchmark

    // 1. Simple arithmetic
    let arithmetic = VMFunction::new(
        "arithmetic_bench".to_string(),
        vec![],
        vec![],
        None,
        4,
        vec![
            Instruction::LDI(0, Value::Int(10)),
            Instruction::LDI(1, Value::Int(20)),
            Instruction::ADD(2, 0, 1),
            Instruction::MUL(3, 2, 1),
            Instruction::RET(3),
        ],
        HashMap::new(),
    );
    vm.register_function(arithmetic);

    // 2. Register operations
    let registers = VMFunction::new(
        "registers_bench".to_string(),
        vec![],
        vec![],
        None,
        3,
        vec![
            Instruction::LDI(0, Value::Int(42)),
            Instruction::MOV(1, 0),
            Instruction::MOV(2, 1),
            Instruction::RET(2),
        ],
        HashMap::new(),
    );
    vm.register_function(registers);

    // 3. Control flow
    let mut labels = HashMap::new();
    labels.insert("loop_start".to_string(), 2);
    labels.insert("loop_end".to_string(), 6);

    let control_flow = VMFunction::new(
        "control_flow_bench".to_string(),
        vec![],
        vec![],
        None,
        3,
        vec![
            Instruction::LDI(0, Value::Int(0)),  // Counter
            Instruction::LDI(1, Value::Int(10)), // Limit
            // loop_start:
            Instruction::CMP(0, 1),
            Instruction::JMPGT("loop_end".to_string()),
            Instruction::ADD(0, 0, 0), // Double the counter
            Instruction::JMP("loop_start".to_string()),
            // loop_end:
            Instruction::RET(0),
        ],
        labels,
    );
    vm.register_function(control_flow);

    // Ensure all functions are executed once to cache and resolve instructions
    vm.execute("arithmetic_bench").unwrap();
    vm.execute("registers_bench").unwrap();
    vm.execute("control_flow_bench").unwrap();

    // Benchmark using regular execute method
    group.bench_function("arithmetic_regular", |b| {
        b.iter(|| {
            black_box(vm.execute("arithmetic_bench").unwrap())
        });
    });

    // Benchmark using execute_for_benchmark method
    group.bench_function("arithmetic_benchmark", |b| {
        b.iter(|| {
            black_box(vm.execute_for_benchmark("arithmetic_bench").unwrap())
        });
    });

    // Benchmark register operations
    group.bench_function("registers_regular", |b| {
        b.iter(|| {
            black_box(vm.execute("registers_bench").unwrap())
        });
    });

    group.bench_function("registers_benchmark", |b| {
        b.iter(|| {
            black_box(vm.execute_for_benchmark("registers_bench").unwrap())
        });
    });

    // Benchmark control flow
    group.bench_function("control_flow_regular", |b| {
        b.iter(|| {
            black_box(vm.execute("control_flow_bench").unwrap())
        });
    });

    group.bench_function("control_flow_benchmark", |b| {
        b.iter(|| {
            black_box(vm.execute_for_benchmark("control_flow_bench").unwrap())
        });
    });

    group.finish();
}

fn bench_individual_instructions(c: &mut Criterion) {
    let mut group = c.benchmark_group("Individual Instructions");

    // Benchmark ADD instruction
    {
        let mut vm = VirtualMachine::new();
        let add_test = VMFunction::new(
            "add_test".to_string(),
            vec![],
            vec![],
            None,
            3,
            vec![
                Instruction::LDI(0, Value::Int(10)),
                Instruction::LDI(1, Value::Int(20)),
                // Only benchmark this instruction
                Instruction::ADD(2, 0, 1),
                Instruction::RET(2),
            ],
            HashMap::new(),
        );
        vm.register_function(add_test);
        vm.execute("add_test").unwrap(); // Warmup

        group.bench_function("add_instruction", |b| {
            b.iter(|| {
                black_box(vm.execute("add_test").unwrap())
            });
        });
    }

    // Benchmark MUL instruction
    {
        let mut vm = VirtualMachine::new();
        let mul_test = VMFunction::new(
            "mul_test".to_string(),
            vec![],
            vec![],
            None,
            3,
            vec![
                Instruction::LDI(0, Value::Int(10)),
                Instruction::LDI(1, Value::Int(20)),
                // Only benchmark this instruction
                Instruction::MUL(2, 0, 1),
                Instruction::RET(2),
            ],
            HashMap::new(),
        );
        vm.register_function(mul_test);
        vm.execute("mul_test").unwrap(); // Warmup

        group.bench_function("mul_instruction", |b| {
            b.iter(|| {
                black_box(vm.execute("mul_test").unwrap())
            });
        });
    }

    // Benchmark MOV instruction
    {
        let mut vm = VirtualMachine::new();
        let mov_test = VMFunction::new(
            "mov_test".to_string(),
            vec![],
            vec![],
            None,
            3,
            vec![
                Instruction::LDI(0, Value::Int(42)),
                // Only benchmark this instruction
                Instruction::MOV(1, 0),
                Instruction::RET(1),
            ],
            HashMap::new(),
        );
        vm.register_function(mov_test);
        vm.execute("mov_test").unwrap(); // Warmup

        group.bench_function("mov_instruction", |b| {
            b.iter(|| {
                black_box(vm.execute("mov_test").unwrap())
            });
        });
    }

    group.finish();
}

fn bench_vm_components(c: &mut Criterion) {
    let mut group = c.benchmark_group("VM Components");

    // Benchmark instruction dispatch overhead
    {
        let mut vm = VirtualMachine::new();
        let noop_test = VMFunction::new(
            "noop_test".to_string(),
            vec![],
            vec![],
            None,
            1,
            vec![
                // Just a sequence of MOVs to measure dispatch overhead
                Instruction::MOV(0, 0),
                Instruction::MOV(0, 0),
                Instruction::MOV(0, 0),
                Instruction::MOV(0, 0),
                Instruction::MOV(0, 0),
                Instruction::RET(0),
            ],
            HashMap::new(),
        );
        vm.register_function(noop_test);
        vm.execute("noop_test").unwrap(); // Warmup

        group.bench_function("instruction_dispatch", |b| {
            b.iter(|| {
                black_box(vm.execute("noop_test").unwrap())
            });
        });
    }

    group.finish();
}

fn bench_parameterized(c: &mut Criterion) {
    let mut group = c.benchmark_group("Scaling");

    // Test with different numbers of instructions
    for size in [10, 100, 1000].iter() {
        let mut vm = VirtualMachine::new();

        // Create a function with *size* instructions
        let mut instructions = Vec::new();
        for i in 0..*size {
            instructions.push(Instruction::LDI(0, Value::Int(i as i64)));
        }
        instructions.push(Instruction::RET(0));

        let test_func = VMFunction::new(
            format!("test_func_{}", size),
            vec![],
            vec![],
            None,
            1,
            instructions,
            HashMap::new(),
        );
        vm.register_function(test_func);
        vm.execute(&format!("test_func_{}", size)).unwrap(); // Warmup

        group.bench_with_input(BenchmarkId::new("instruction_count", size), size, |b, &size| {
            b.iter(|| {
                black_box(vm.execute(&format!("test_func_{}", size)).unwrap())
            });
        });
    }

    group.finish();
}

fn bench_memory_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("Memory Overhead");

    // Benchmark with different array sizes
    for size in [10, 100, 1000].iter() {
        let mut vm = VirtualMachine::new();

        // Create a function that creates an array of size *size*
        let mut instructions = Vec::new();

        // Create array
        instructions.push(Instruction::CALL("create_array".to_string()));
        instructions.push(Instruction::MOV(1, 0));

        // Push elements
        for i in 0..*size {
            instructions.push(Instruction::PUSHARG(1));
            instructions.push(Instruction::LDI(2, Value::Int(i as i64)));
            instructions.push(Instruction::PUSHARG(2));
            instructions.push(Instruction::CALL("array_push".to_string()));
        }

        instructions.push(Instruction::RET(1));

        let test_func = VMFunction::new(
            format!("array_test_{}", size),
            vec![],
            vec![],
            None,
            3,
            instructions,
            HashMap::new(),
        );
        vm.register_function(test_func);
        vm.execute(&format!("array_test_{}", size)).unwrap(); // Warmup

        group.bench_with_input(BenchmarkId::new("array_size", size), size, |b, &size| {
            b.iter(|| {
                black_box(vm.execute(&format!("array_test_{}", size)).unwrap())
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_basic_operations,
    bench_function_calls,
    bench_object_operations,
    bench_array_operations,
    bench_hook_system,
    bench_optimized_operations,
    bench_individual_instructions,
    bench_vm_components,
    bench_parameterized,
    bench_memory_overhead,
    // Temporarily remove bench_optimized_hook_system to avoid hanging
    // bench_optimized_hook_system,
    bench_core_execution
);
criterion_main!(benches);
