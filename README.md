# StoffelVM
![Discord](https://img.shields.io/discord/1300834528042160150?label=discord)
![Static Badge](https://img.shields.io/badge/telegram-24A1DE?link=https%3A%2F%2Ft.me%2F%2B7L0HPi1U8pU1MzQx)
![GitHub License](https://img.shields.io/github/license/Stoffel-Labs/StoffelVM)

This repository contains the core crates of the Stoffel Virtual Machine, a virtual machine optimized for multiparty computation (MPC). 

> 🚧👷‍♂️ This repository is currently under construction and as such, doesn't contain MPC functionality yet. But the VM is mostly functional with some quirks 

## Background on Stoffel VM!

In its current form, Stoffel is designed to handle simple and complex programs. Our VM handle both basic types(integers, booleans, strings, and soon fixed point) and more complex types such as objects, arrays, closures, and foreign objects! The VM is designed as a register machine to enable easy optimization and mapping to physical hardware.

The VM contains instructions to handle memory operations, arithmetic, bitwise operations, and control flow. It has a closure system implemented that supports true lexical scoping, where functions can and will "capture" variables from their surrounding environment, preserving them even after the original scope has exited. This mechanism tracks these values as "upvalues" in order to maintain their state between function calls, allowing for users to adopt functional programming patterns.

Stoffel supports FFI out of the box between Rust <> Stoffel's runtime. This bridge allows for developers to upgrade the runtime with high performance functionality. The runtime implements a configurable hook system that allows for the interception of instruction execution, register access, activation stack operations, and more to facilitate debugging!  

> 🚧 Currently Stoffel's architecture supports recursion(soon with out-of-the-box forced/guaranteed tail calls), stateful closures, and allows for object-oriented patterns. Currently, the runtime lacks an automatic clear/secret memory management / garbage collection system, any concept of side effects, exception handling, being able to (un)load libraries, and most importantly handling MPC natively.

## Features

Stoffel VM supports the following instructions:

### Memory Operations

- `LD(dest_reg, stack_offset)`: Load value from stack to register
- `LDI(dest_reg, value)`: Load immediate value to register
- `MOV(dest_reg, src_reg)`: Move value from one register to another
- `PUSHARG(reg)`: Push register value as function argument

### Arithmetic Operations

- `ADD(dest_reg, src1_reg, src2_reg)`: Add two registers
- `SUB(dest_reg, src1_reg, src2_reg)`: Subtract two registers
- `MUL(dest_reg, src1_reg, src2_reg)`: Multiply two registers
- `DIV(dest_reg, src1_reg, src2_reg)`: Divide two registers
- `MOD(dest_reg, src1_reg, src2_reg)`: Modulo operation

### Bitwise Operations

- `AND(dest_reg, src1_reg, src2_reg)`: Bitwise AND
- `OR(dest_reg, src1_reg, src2_reg)`: Bitwise OR
- `XOR(dest_reg, src1_reg, src2_reg)`: Bitwise XOR
- `NOT(dest_reg, src_reg)`: Bitwise NOT
- `SHL(dest_reg, src_reg, amount_reg)`: Shift left
- `SHR(dest_reg, src_reg, amount_reg)`: Shift right

### Control Flow

- `JMP(label)`: Unconditional jump
- `JMPEQ(label)`: Jump if equal (compare_flag == 0)
- `JMPNEQ(label)`: Jump if not equal (compare_flag != 0)
- `CMP(reg1, reg2)`: Compare two registers
- `CALL(function_name)`: Call a function
- `RET(reg)`: Return from function with value in register

### Values

Stoffel VM supports the following value types:

- `Value::Int(i64)`: Integer value
- `Value::Float(i64)`: Fixed-point float value
- `Value::Bool(bool)`: Boolean value
- `Value::String(String)`: String value
- `Value::Object(usize)`: Object reference
- `Value::Array(usize)`: Array reference
- `Value::Foreign(usize)`: Foreign object reference
- `Value::Closure(Arc<Closure>)`: Function closure
- `Value::Unit`: Unit/void value

### Standard Library Builtins!

Stoffel VM includes several built-in functions:
- `print`: Print values to the console 
- `create_object`: Create a new object 
- `create_array`: Create a new array 
- `get_field`: Get a field from an object or array 
- `set_field`: Set a field in an object or array 
- `array_length`: Get the length of an array 
- `array_push`: Add an element to an array 
- `create_closure`: Create a closure 
- `call_closure`: Call a closure 
- `get_upvalue`: Get an upvalue from a closure 
- `set_upvalue`: Set an upvalue in a closure 
- `type`: Get the type of a value as a string

## How do I use it!?

I'm glad you asked! At the moment, the runtime should be embedded in a program to use. For example:

```rust
// Stoffel related imports 
use stoffel_vm::core_vm::VirtualMachine;
use stoffel_vm::functions::VMFunction;
use stoffel_vm::instructions::Instruction;
use stoffel_vm::core_types::Value;
// stdlib for hashmap
use std::collections::HashMap;

// main method to run our program!
fn main() -> Result<(), String> {
    // Initialize the VM
    let vm = VirtualMachine::new();
    
    // Create a simple hello world function
    let hello_world = VMFunction {
        name: "hello_world".to_string(), // The name that the method is identified by
        parameters: vec![], // The string names 
        upvalues: vec![], // Upvalues are the captured variables for true lexical scoping
        parent: None, // If this function is owned by another function
        register_count: 1, // Configurable amount of registers the function will use. In the future this is for optimization.
        instructions: vec![ // Holds all the instructions associated with this method
            // Load "Hello, World!" string into register 0
            Instruction::LDI(0, Value::String("Hello, World!".to_string())),
            // Push register 0 as argument for print function
            Instruction::PUSHARG(0), // Arguments go on a stack that is then accessed by activation records when creating the scope of the funcction.
            // Call the built-in print function
            Instruction::CALL("print".to_string()),
            // Return Unit (void)
            Instruction::RET(0),
        ],
        labels: HashMap::new(), // Labels for GOTO jumps. (<"label name">, <instruction offset to jump to>)
    };
    
    // Register the function with the VM
    vm.register_function(hello_world);
    
    // Execute the function
    let result = vm.execute("hello_world")?;
    
    // Print the result of the program, in this case nothing!
    println!("Program returned: {:?}", result);
    
    Ok(())
}
```

Now that you're familiar with the basics of Stoffel VM, you should:
1. Explore the [examples directory](examples) for example programs!
2. Create more complex programs with control flow and closures
