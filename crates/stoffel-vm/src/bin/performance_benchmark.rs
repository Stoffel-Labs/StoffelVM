use std::collections::HashMap;
use std::time::Instant;
use stoffel_vm::core_vm::VirtualMachine;
use stoffel_vm_types::core_types::Value;
use stoffel_vm_types::functions::VMFunction;
use stoffel_vm_types::instructions::Instruction;

fn main() {
    println!("Running StoffelVM performance benchmark...");

    // Create a VM instance
    let mut vm = VirtualMachine::new();

    // Create a benchmark function that performs a lot of arithmetic operations
    let mut labels = HashMap::new();
    labels.insert("loop_start".to_string(), 1);
    labels.insert("loop_end".to_string(), 8);

    let benchmark_function = VMFunction::new(
        "benchmark".to_string(),
        vec!["iterations".to_string()],
        Vec::new(),
        None,
        5, // 5 registers
        vec![
            // Initialize counter
            Instruction::LDI(1, Value::I64(0)),
            // loop_start:
            Instruction::CMP(1, 0),
            Instruction::JMPEQ("loop_end".to_string()),
            // Increment counter
            Instruction::LDI(2, Value::I64(1)),
            Instruction::ADD(1, 1, 2),
            // Do some work (arithmetic)
            Instruction::MUL(3, 1, 2),
            Instruction::ADD(4, 3, 1),
            // Loop back
            Instruction::JMP("loop_start".to_string()),
            // loop_end:
            Instruction::RET(1),
        ],
        labels,
    );

    // Register the function
    vm.register_function(benchmark_function);

    // Run the benchmark with different iteration counts
    // Using smaller values for quicker results
    let iterations = [1_000, 10_000, 100_000];

    for &iter_count in &iterations {
        // Prepare arguments
        let args = vec![Value::I64(iter_count)];

        // Run the benchmark and measure time
        let start = Instant::now();
        let result = vm.execute_with_args("benchmark", &args).unwrap();
        let duration = start.elapsed();

        // Print results
        println!("Benchmark with {} iterations:", iter_count);
        println!("  Result: {:?}", result);
        println!("  Time: {:?}", duration);
        println!(
            "  Instructions per second: {:.2}",
            iter_count as f64 / duration.as_secs_f64()
        );
        println!();
    }

    // Run the benchmark again with the benchmark-specific method
    println!("Running with execute_for_benchmark (should be faster):");

    // First execute once normally to ensure instructions are cached
    let args = vec![Value::I64(10)];
    vm.execute_with_args("benchmark", &args).unwrap();

    for &iter_count in &iterations {
        // Prepare arguments
        let args = vec![Value::I64(iter_count)];

        // Run the benchmark and measure time
        let start = Instant::now();
        let result = vm.execute_for_benchmark("benchmark").unwrap();
        let duration = start.elapsed();

        // Print results
        println!("Benchmark with {} iterations:", iter_count);
        println!("  Result: {:?}", result);
        println!("  Time: {:?}", duration);
        println!(
            "  Instructions per second: {:.2}",
            iter_count as f64 / duration.as_secs_f64()
        );
        println!();
    }
}
