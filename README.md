# StoffelVM
![Discord](https://img.shields.io/discord/1300834528042160150?label=discord)
[![Telegram](https://img.shields.io/badge/telegram-24A1DE)](https://t.me/+7L0HPi1U8pU1MzQx)
[![GitHub License](https://img.shields.io/github/license/Stoffel-Labs/StoffelVM)](LICENSE)

This repository contains the core crates of the Stoffel Virtual Machine, a register-based VM built for both local execution and networked multiparty computation (MPC).

## Background on Stoffel VM!

In its current form, Stoffel is designed to handle both simple and complex programs. The VM supports basic values such as integers, booleans, strings, and floating point numbers, along with more complex runtime types such as objects, arrays, closures, foreign objects, and secret shares. The VM is designed as a register machine to make execution predictable and to map cleanly onto optimized runtimes and physical MPC backends.

The instruction set covers memory operations, arithmetic, bitwise operations, control flow, and function calls. Stoffel also has a closure system with true lexical scoping, where functions can capture values from their surrounding environment as upvalues and continue using them after the original scope has exited.

Stoffel supports Rust <> Stoffel FFI out of the box. This lets you extend the runtime with native Rust functions and objects while keeping the VM execution model intact. The runtime also exposes a configurable hook system that can intercept instruction execution, register access, stack events, object and array access, closure creation, and more for debugging or instrumentation.

The workspace currently includes:

- `crates/stoffel-vm`: the runtime, networking layer, MPC integrations, CLI binaries, and C FFI
- `crates/stoffel-vm-types`: shared VM types, instruction definitions, and the compiled bytecode format
- `include/`: the public C header and FFI notes

## Features

Stoffel VM currently supports the following instructions:

### Memory Operations

- `LD(dest_reg, stack_offset)`: Load a value from the current activation record into a register
- `LDI(dest_reg, value)`: Load an immediate value into a register
- `MOV(dest_reg, src_reg)`: Move a value from one register to another
- `PUSHARG(reg)`: Push a register value as a function argument

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
- `JMPEQ(label)`: Jump if equal
- `JMPNEQ(label)`: Jump if not equal
- `JMPLT(label)`: Jump if less than
- `JMPGT(label)`: Jump if greater than
- `CMP(reg1, reg2)`: Compare two registers
- `CALL(function_name)`: Call a function
- `RET(reg)`: Return from the current function with the value in a register

### Values

Stoffel VM currently exposes the following runtime value variants:

- `Value::I64(i64)`: 64-bit signed integer
- `Value::I32(i32)`: 32-bit signed integer
- `Value::I16(i16)`: 16-bit signed integer
- `Value::I8(i8)`: 8-bit signed integer
- `Value::U8(u8)`: 8-bit unsigned integer
- `Value::U16(u16)`: 16-bit unsigned integer
- `Value::U32(u32)`: 32-bit unsigned integer
- `Value::U64(u64)`: 64-bit unsigned integer
- `Value::Float(F64)`: 64-bit floating point
- `Value::Bool(bool)`: Boolean value
- `Value::String(String)`: String value
- `Value::Object(usize)`: Object reference
- `Value::Array(usize)`: Array reference
- `Value::Foreign(usize)`: Foreign object reference
- `Value::Closure(Arc<Closure>)`: Function closure with captured environment
- `Value::Unit`: Unit/void/nil value
- `Value::Share(ShareType, ShareData)`: Secret-shared value for MPC
- `Value::PendingReveal(usize)`: Internal marker used by batched reveal optimization

### Standard Library Builtins!

Stoffel VM registers the following general runtime builtins by default:

- `print`: Print values to the console
- `type`: Get the type of a value as a string
- `create_object`: Create a new object
- `create_array`: Create a new array
- `get_field`: Get a field from an object or array
- `set_field`: Set a field in an object or array
- `array_length`: Get the length of an array
- `array_push`: Append one or more values to an array
- `create_closure`: Create a closure
- `call_closure`: Call a closure
- `get_upvalue`: Read a captured upvalue from a closure
- `set_upvalue`: Update a captured upvalue in a closure
- `ClientStore.get_number_clients`: Get the number of connected clients
- `ClientStore.take_share`: Load a client share into the VM
- `ClientStore.take_share_fixed`: Load a client fixed-point share into the VM
- `MpcOutput.send_to_client`: Send a share result to a client

### MPC Builtins

The VM also registers MPC-focused module-style builtins:

- `Share.*`: clear-to-share conversion, arithmetic on shares, opening, random share generation, client output, local interpolation, and commitment inspection
- `Mpc.*`: runtime MPC metadata such as party id, threshold, instance id, readiness, and randomness helpers
- `Rbc.*`: reliable broadcast helpers
- `Aba.*`: asynchronous binary agreement helpers
- `Crypto.*`: hashing and curve/field conversion helpers
- `Bytes.*`: byte-array helpers
- `Avss.*`: AVSS-specific helpers when the `avss` feature is enabled

## How do I use it!?

At the moment, the most direct way to use the runtime is to embed it in a Rust program and register `VMFunction` values. `VirtualMachine::new()` automatically registers the standard library and MPC builtins.

```rust
use std::collections::HashMap;

use stoffel_vm::core_types::Value;
use stoffel_vm::core_vm::VirtualMachine;
use stoffel_vm::functions::VMFunction;
use stoffel_vm::instructions::Instruction;

fn main() -> Result<(), String> {
    let mut vm = VirtualMachine::new();

    let hello_world = VMFunction::new(
        "hello_world".to_string(),
        vec![],
        vec![],
        None,
        2,
        vec![
            Instruction::LDI(0, Value::String("Hello, World!".to_string())),
            Instruction::PUSHARG(0),
            Instruction::CALL("print".to_string()),
            Instruction::LDI(1, Value::Unit),
            Instruction::RET(1),
        ],
        HashMap::new(),
    );

    vm.register_function(hello_world);

    let result = vm.execute("hello_world")?;
    println!("Program returned: {:?}", result);

    Ok(())
}
```

Now that you're familiar with the basics of Stoffel VM, good places to explore next are:

1. `crates/stoffel-vm-types/examples/generate_client_mul_program.rs` for a bytecode-generation example
2. `crates/stoffel-vm/src/tests/vm_mpc_integration.rs` for VM + MPC execution flows
3. `tests/p2p_integration.rs` for QUIC networking coverage

## Compiled Bytecode

StoffelVM also ships a portable compiled binary format through `stoffel-vm-types::compiled_binary::CompiledBinary`. The format uses the magic bytes `STFL` and can round-trip between `VMFunction` definitions and serialized binaries.

You can generate a compiled binary from Rust-defined functions like this:

```rust
use stoffel_vm_types::compiled_binary::{utils::save_to_file, CompiledBinary};

// Assume `functions: Vec<VMFunction>` already exists.
let binary = CompiledBinary::from_vm_functions(&functions);
save_to_file(&binary, "program.stflb").unwrap();
```

This repository does not currently include a source-language compiler, so compiled binaries are usually produced either by Rust-side tooling or by an external compiler that targets the same format.

## Build and Test

Build everything:

```bash
cargo build
```

Run the test suite:

```bash
cargo test
```

Build the runtime and CLI in release mode:

```bash
cargo build --release -p stoffel-vm
```

`stoffel-vm` enables the `honeybadger` and `avss` features by default.

## CLI: Run a compiled Stoffel binary

A CLI is included to run a compiled Stoffel bytecode file locally or as part of a distributed MPC session.

Build the CLI:

```bash
cargo build --release -p stoffel-vm
```

Show the available flags:

```bash
cargo run -p stoffel-vm --bin stoffel-run -- --help
```

Run a compiled program locally (default entry function is `main`):

```bash
./target/release/stoffel-run path/to/program.stflb
./target/release/stoffel-run path/to/program.stflb main --trace-instr
```

Run a leader node for a 5-party MPC session:

```bash
STOFFEL_AUTH_TOKEN=replace-with-random-secret \
./target/release/stoffel-run path/to/program.stflb main \
  --leader \
  --bind 127.0.0.1:9000 \
  --n-parties 5 \
  --threshold 1
```

Join as another party:

```bash
STOFFEL_AUTH_TOKEN=replace-with-random-secret \
./target/release/stoffel-run path/to/program.stflb main \
  --party-id 1 \
  --bootstrap 127.0.0.1:9000 \
  --bind 127.0.0.1:9002 \
  --n-parties 5 \
  --threshold 1
```

Run in client mode to submit inputs to the party servers:

```bash
./target/release/stoffel-run --client \
  --inputs 10,20 \
  --servers 127.0.0.1:10000,127.0.0.1:9002,127.0.0.1:9003,127.0.0.1:9004,127.0.0.1:9005 \
  --n-parties 5
```

Notes:

- `STOFFEL_AUTH_TOKEN` is required for authenticated discovery in bootnode, leader, and party flows
- The CLI accepts any file path; this repository conventionally stores compiled fixtures as `.stflb`
- `--mpc-backend` supports `honeybadger` and `avss`
- `--mpc-curve` supports `bls12-381`, `bn254`, `curve25519`, and `ed25519`

## C Foreign Function Interface

`stoffel-vm` builds as both an `rlib` and a `cdylib`, so the runtime can also be embedded from C-compatible environments.

Relevant files:

- `include/stoffel_vm.h`
- `include/README.md`

Platform-specific library names:

- Linux: `libstoffel_vm.so`
- macOS: `libstoffel_vm.dylib`
- Windows: `stoffel_vm.dll`
