# Stoffel
[![GitHub License](https://img.shields.io/github/license/Stoffel-Labs/stoffel)](LICENSE)
[![Static Badge](https://img.shields.io/badge/docs-stoffel-%23FDC448)](https://docs.stoffelmpc.com)
[![Static Badge](https://img.shields.io/badge/built%20by-Stoffel%20Labs-%232D39E0)](https://stoffelmpc.com)



Stoffel is a toolchain for writing, compiling, and running programs that compute
over private data using secure Multi-Party Computation (MPC). You write ordinary
looking code, mark the values that must stay secret, and Stoffel compiles and
executes it so that no single party ever sees the secret inputs in the clear.

This repository is the Stoffel monorepo. It contains everything from the
language and compiler down to the runtime and the networking/MPC layer:

| Product | Crate | What it is |
|---------|-------|------------|
| **Stoffel CLI** | `crates/stoffel-cli` | The Cargo-like `stoffel` command for creating, building, and running MPC projects |
| **StoffelLang** | `crates/stoffel-lang` | The `stoffel` language compiler (`.stfl` → `.stflb` bytecode) |
| **Stoffel SDK** | `crates/stoffel-rust-sdk` | The Rust SDK (`stoffel` crate) for embedding compilation, execution, and MPC config in apps |
| **Stoffel VM** | `crates/stoffel-vm` | The register-based VM runtime, networking, and MPC backends (HoneyBadger, AVSS), plus the C FFI |

Supporting crates:

- `crates/stoffel-vm-runner`: the `stoffel-run` binary — local runner and distributed MPC party/client node
- `crates/stoffel-vm-types`: shared VM types, the instruction set, runtime `Value`s, and the compiled bytecode format
- `crates/stoffel-bindgen`: build-time generation of typed Rust bindings for Stoffel programs
- `include/`: the public C header and FFI notes for embedding the VM from C-compatible environments

```
StoffelLang source (.stfl)
        │  stoffel build / stoffel-lang
        ▼
Compiled bytecode (.stflb)        ← stoffel-vm-types::compiled_binary
        │  stoffel run / stoffel-run / Stoffel SDK
        ▼
Stoffel VM  ── local execution  (clear or simulated MPC)
            └─ distributed MPC  (HoneyBadger / AVSS over QUIC)
```

## Installation

Install the released Stoffel CLI with the installer:

```bash
curl -fsSL https://get.stoffelmpc.com | sh
```

The installer places `stoffel` in `~/.local/bin` by default. Add it to your shell path if needed:

```bash
export PATH="$HOME/.local/bin:$PATH"
stoffel --help
```

Create and run a project:

```bash
stoffel init hello-mpc
cd hello-mpc
stoffel run --input a=40 --input b=2
```

> **Runner caveat:** local runs need the `stoffel-run` MPC runner. The installer
> drops it next to `stoffel`, and the CLI discovers it automatically. If you
> installed `stoffel` another way, Stoffel also looks for `stoffel-run` on your
> `PATH` (e.g. after `cargo install stoffel-vm-runner`), or
> you can point at a specific binary with `--runner <path>` or the
> `STOFFEL_RUN_BIN` environment variable.

To build from source instead, see [Build and Test](#build-and-test).

## Stoffel CLI

The `stoffel` binary is a Cargo-like project CLI built on top of `crates/stoffel-rust-sdk`.
It reads `Stoffel.toml`, defaults to `src/main.stfl`, and writes bytecode to
`target/debug/<package>.stflb` or `target/release/<package>.stflb`.

> **Local runner:** local execution (`stoffel run` without `--network`, and
> `stoffel dev`) drives the `stoffel-run` MPC runner. Stoffel resolves it in order:
> an explicit `--runner <path>`, the `STOFFEL_RUN_BIN` environment variable, a
> `stoffel-run` sitting next to the `stoffel` binary (where the installer puts it),
> a `stoffel-run` on your `PATH` (e.g. via `cargo install stoffel-vm-runner`),
> then a `stoffel-run` built in the current
> Cargo workspace. See [Build and Test](#build-and-test) to build one from source.

### Create a project

```bash
stoffel init my-lib --lib
stoffel init rust-app --template rust
stoffel init py-app --template python
```

Solidity/EVM project templates (`solidity-foundry`, `solidity-hardhat`) are
planned but not yet available — see [Roadmap](#roadmap).

### Build, check, and inspect

```bash
stoffel build
stoffel check
stoffel compile src/main.stfl -O2 --output target/debug/hello-mpc.stflb
stoffel compile --disassemble target/debug/hello-mpc.stflb
```

`build` and `compile` default to all `src/**/*.stfl` files when no source path is
provided. Use `--output` when compiling a single file.

### Run

```bash
stoffel run target/debug/hello-mpc.stflb --entry main --input a=40 --input b=2
stoffel run --input a=40 --input b=2
stoffel run program.stfl --local --client-input 0=42 --parties 5 --threshold 1
stoffel run program.stfl --local --expected-output-clients 2
stoffel run target/debug/program.stflb --network --config offchain-client.toml --input x=42
stoffel run target/debug/program.stflb --network --config party-network.toml --connect-timeout-ms 1000
```

`run` accepts `.stfl` source or `.stflb` bytecode. By default it runs through the
local MPC coordinator; `--local` is accepted as an explicit local mode selector.
Use `--client-input SLOT=VALUE` for `ClientStore` input providers, and
`--expected-output-clients N` to declare output-capable local client slots
`0..N-1` for dynamic output loops or output-only runs (this does not synthesize
client inputs). `--network --config` uses SDK network configuration: an off-chain
client config executes through the coordinator/node RPC path, while a network
config validates and connects to real node addresses.

### Develop with live reload

```bash
stoffel dev --parties 5 --threshold 1 --input a=40 --input b=2
```

`stoffel dev` runs once, watches `Stoffel.toml` and the configured source tree,
then rebuilds and reruns whenever a `.stfl` file or project config changes. Use
`stoffel dev --once` for one-shot behavior, or `--poll-ms <N>` to tune reload latency.

### Test and manage projects

```bash
stoffel test
stoffel test --test selected --verbose
stoffel status --verbose
stoffel clean
stoffel clean --all
stoffel update --check
stoffel update
```

`status` validates project config, checks detected dependency managers, compiles
configured sources, and reports local MPC network configuration. `clean` removes
the project `target/` directory and Stoffel build cache; `--all` also removes
known ecosystem caches such as `node_modules`, Foundry cache/output, and Python
test caches. `update` checks for CLI/project dependency updates and runs detected
project dependency update commands; use `--check` to inspect without changing files.

## StoffelLang

StoffelLang (`.stfl`) is the source language compiled by `crates/stoffel-lang`
into Stoffel VM bytecode. It is a Python-flavored, statically typed language: it
uses indentation and `def`, but values carry concrete types and the `secret`
qualifier marks data that must remain private under MPC.

```python
def main(a: secret int64, b: secret int64) -> secret int64:
  return a + b
```

Arithmetic, comparisons, and control flow work transparently on both clear and
`secret` values; the compiler and VM insert the MPC operations needed for secret
operands. Programs interact with the runtime through module-style builtins such
as `Share.*`, `Field.*`, and `Mpc.*` (see [Builtins](#standard-library-builtins)).

Many worked programs live in `crates/stoffel-lang/examples/`, including local
collections/control-flow demos, AES-128 (CTR/CBC/circuit) under MPC, and
threshold ECDSA / certificate-signing flows. See
`crates/stoffel-lang/examples/README.md` for an index.

The compiler can be driven directly (`stoffel compile`) or through the SDK; bump
the binary format version when serialization changes (see
`crates/stoffel-vm-types/src/compiled_binary/`).

## Stoffel SDK (Rust)

`crates/stoffel-rust-sdk` publishes the `stoffel` crate: the library entry point
for embedding Stoffel-Lang compilation, bytecode loading, VM execution, and MPC
participant configuration in Rust applications. The CLI itself is built on it.

```toml
# Cargo.toml
stoffel-rust-sdk = "=0.2.0"
```

```rust
use stoffel::prelude::*;

let result = Stoffel::compile(
    "def main(a: int64, b: int64) -> int64:\n  return a + b",
)?
.with_inputs(&[("a", 42_i64), ("b", 58_i64)])
.execute_clear()?;

assert_eq!(result[0].as_i64(), Some(100));
# Ok::<(), stoffel::Error>(())
```

For local MPC smoke runs, use the same builder and call `execute_local().await`.
This starts real localhost VM parties through `stoffel-vm`'s local coordinator
runner when a built `stoffel-run` binary is available:

```rust
use stoffel::prelude::*;

# async fn example() -> stoffel::Result<()> {
let result = Stoffel::compile(
    "def main(a: secret int64, b: secret int64) -> int64:\n  var sum: secret int64 = a + b\n  return sum.open()",
)?
.parties(5)
.threshold(1)
.execute_local()
.await?;
# Ok(())
# }
```

When the VM return itself must remain secret, use the opaque-share result API.
It preserves the exact backend serialization held by each compute party and
never compares or reconstructs those payload bytes:

```rust
use stoffel::prelude::*;

# async fn example() -> stoffel::Result<()> {
let result = Stoffel::compile(
    "def main() -> secret int64:\n  var share: secret int64 = Share.random()\n  return share",
)?
.parties(5)
.threshold(1)
.avss(Curve::Bls12_381)
.execute_local_returning_party_shares()
.await?;

assert_eq!(result.party_outputs.len(), 5);
assert_eq!(result.shares().len(), 5);
# Ok(())
# }
```

The two execution APIs are intentionally disjoint: `execute_local()` accepts a
public VM return, while `execute_local_returning_party_shares()` requires
exactly one secret return share per compute party. A public return passed to the
share API—or a secret return passed to the public API—is reported as an error.
`client_outputs` remains reserved for values explicitly reconstructed with
`send_to_client`; it never contains the party-local VM return shares.

`crates/stoffel-bindgen` complements the SDK by generating typed Rust bindings
for a Stoffel program at build time, so host code can call into compiled
programs with a checked interface.

## Stoffel VM

`stoffel-vm` is a register machine optimized for MPC. The register design keeps
execution predictable and maps cleanly onto optimized runtimes and physical MPC
backends. It supports basic values (integers, booleans, strings, floats) and
complex runtime types (objects, arrays, closures, foreign objects, and secret
shares), and has a closure system with true lexical scoping where functions
capture upvalues from their surrounding environment.

Stoffel supports Rust ⇆ Stoffel FFI out of the box, so you can extend the
runtime with native Rust functions and objects while keeping the execution model
intact. A configurable hook system can intercept instruction execution, register
access, stack events, object/array access, closure creation, and more for
debugging or instrumentation.

HoneyBadger and AVSS MPC backends are built by default. Distributed party runs
select the backend from the compiled `.stflb` program manifest.

### Embedding the VM directly

The most direct low-level use of the runtime is to embed it in a Rust program
and register `VMFunction` values. `VirtualMachine::new()` automatically registers
the standard library and MPC builtins. (Most applications should prefer the SDK
above; this is the raw API.)

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

    vm.try_register_function(hello_world)?;

    let result = vm.execute("hello_world")?;
    println!("Program returned: {:?}", result);

    Ok(())
}
```

Good places to explore next:

1. `crates/stoffel-vm-types/examples/generate_client_mul_program.rs` — a bytecode-generation example
2. `crates/stoffel-vm/src/tests/vm_mpc_integration.rs` — VM + MPC execution flows
3. `tests/p2p_integration.rs` — QUIC networking coverage

### Instruction Set

**Memory Operations**

- `LD(dest_reg, stack_offset)`: Load a value from the current activation record into a register
- `LDI(dest_reg, value)`: Load an immediate value into a register
- `MOV(dest_reg, src_reg)`: Move a value from one register to another
- `PUSHARG(reg)`: Push a register value as a function argument

**Arithmetic Operations**

- `ADD`, `SUB`, `MUL`, `DIV`, `MOD` `(dest_reg, src1_reg, src2_reg)`

**Bitwise Operations**

- `AND`, `OR`, `XOR` `(dest_reg, src1_reg, src2_reg)`
- `NOT(dest_reg, src_reg)`
- `SHL`, `SHR` `(dest_reg, src_reg, amount_reg)`

**Control Flow**

- `JMP(label)`: Unconditional jump
- `JMPEQ`, `JMPNEQ`, `JMPLT`, `JMPGT` `(label)`: Conditional jumps
- `CMP(reg1, reg2)`: Compare two registers
- `CALL(function_name)`: Call a function
- `RET(reg)`: Return from the current function with the value in a register

### Values

```
Value::I64/I32/I16/I8   — signed integers
Value::U64/U32/U16/U8   — unsigned integers
Value::Float(F64)       — 64-bit floating point
Value::Bool(bool)       — boolean
Value::String(String)   — string
Value::Object(ObjectRef)        — object table reference
Value::Array(ArrayRef)          — array table reference
Value::Foreign(ForeignObjectRef) — foreign object reference
Value::Closure(Arc<Closure>)    — closure with captured environment
Value::Unit                     — unit/void/nil
Value::Share(ShareType, ShareData) — secret-shared value for MPC
```

### Standard Library Builtins

General runtime builtins registered by default:

- `print` / `type`: print values; get a value's type as a string
- `create_object` / `create_array`: create an object or array
- `get_field` / `set_field`: get/set a field on an object or array
- `array_length` / `array_push`: length of an array; append values
- `create_closure` / `call_closure`: create and invoke closures
- `get_upvalue` / `set_upvalue`: read/update captured upvalues
- `ClientStore.*`: client slot counts and `take_share` / `take_share_fixed`
- `MpcOutput.send_to_client`: send a share result to a client

MPC-focused, module-style builtins:

- `Share.*`: clear-to-share conversion, arithmetic on shares, opening, random share generation, client output, local interpolation, and commitment inspection
- `Mpc.*`: runtime MPC metadata such as party id, threshold, instance id, readiness, and randomness helpers
- `Rbc.*`: reliable broadcast helpers
- `Crypto.*`: hashing and curve/field conversion helpers
- `Bytes.*`: byte-array helpers
- `Avss.*`: AVSS-specific helper functions

### Compiled Bytecode

Stoffel ships a portable compiled binary format through
`stoffel-vm-types::compiled_binary::CompiledBinary`. The format uses the magic
bytes `STFL` and round-trips between `VMFunction` definitions and serialized binaries.

```rust
use stoffel_vm_types::compiled_binary::{utils::save_to_file, CompiledBinary};

// Assume `functions: Vec<VMFunction>` already exists.
let binary = CompiledBinary::from_vm_functions(&functions);
save_to_file(&binary, "program.stflb").unwrap();
```

## VM Runner CLI (`stoffel-run`)

`stoffel-vm-runner` provides `stoffel-run`, which executes a compiled Stoffel
bytecode file locally or as part of a distributed MPC session.

```bash
cargo build --release -p stoffel-vm-runner
cargo run -p stoffel-vm-runner --bin stoffel-run -- --help
```

Run a compiled program locally (default entry function is `main`):

```bash
./target/release/stoffel-run path/to/program.stflb
./target/release/stoffel-run path/to/program.stflb main --trace-instr
```

Run a leader node for a 5-party MPC session:

```bash
export STOFFEL_EXECUTION_ID="$(openssl rand -hex 32)"
STOFFEL_AUTH_TOKEN=replace-with-random-secret \
./target/release/stoffel-run path/to/program.stflb main \
  --leader \
  --bind 127.0.0.1:9000 \
  --n-parties 5 \
  --threshold 1 \
  --execution-id "$STOFFEL_EXECUTION_ID"
```

Join as another party:

```bash
STOFFEL_AUTH_TOKEN=replace-with-random-secret \
./target/release/stoffel-run path/to/program.stflb main \
  --party-id 1 \
  --bootstrap 127.0.0.1:9000 \
  --bind 127.0.0.1:9002 \
  --n-parties 5 \
  --threshold 1 \
  --execution-id "$STOFFEL_EXECUTION_ID"
```

Run in client mode to submit inputs to the party servers:

```bash
./target/release/stoffel-run --client \
  --inputs 10,20 \
  --servers 127.0.0.1:10000,127.0.0.1:9002,127.0.0.1:9003,127.0.0.1:9004,127.0.0.1:9005 \
  --n-parties 5 \
  --execution-id "$STOFFEL_EXECUTION_ID"
```

AVSS output-client mode can reconstruct private field outputs:

```bash
./target/release/stoffel-run --client \
  --mpc-backend avss \
  --mpc-curve secp256k1 \
  --inputs 0x<sha256-tbs-digest-hex> \
  --outputs 2 \
  --servers 127.0.0.1:9000,127.0.0.1:9001,127.0.0.1:9002,127.0.0.1:9003,127.0.0.1:9004 \
  --n-parties 5 \
  --execution-id "$STOFFEL_EXECUTION_ID"
```

Notes:

- `STOFFEL_AUTH_TOKEN` is required for authenticated discovery in bootnode, leader, and party flows
- All parties and clients in one run must use the same nonzero `--execution-id`; overlapping runs must use different IDs
- The CLI accepts any file path; this repository conventionally stores compiled fixtures as `.stflb`
- `--mpc-backend` supports `honeybadger` and `avss` for client mode; `.stflb` party runs use the backend recorded in the program manifest and reject conflicting CLI overrides
- `--mpc-curve` supports `bls12-381`, `bn254`, `curve25519`, `ed25519`, `secp256k1`, and `p-256` (`secp256r1`) for AVSS
- Returning a secret share does not open or reconstruct it. Each party emits its exact local backend bytes as `Program returned: share:v1[<type>;<format>;<byte-length>] 0x<hex>`. Party outputs are expected to differ; `LocalPartyOutput::returned_shares()` decodes the record for hashing or sealing. Treat this stdout as secret material. Programs that intentionally need a clear return must call `open()` or `reveal()` explicitly.

## Docker Flows

The API/coordinator topology is runnable with the reserve-index compose stack:

```bash
STOFFEL_AUTH_TOKEN=replace-with-random-secret \
STOFFEL_EXECUTION_ID="$(openssl rand -hex 32)" \
docker compose -f docker-compose.coordinator.reserve-index.yml up --build
```

That coordinator path runs through the HoneyBadger/BLS12-381 VM path. The AVSS compose stack is separate and covers AVSS curves and local share storage:

```bash
STOFFEL_AUTH_TOKEN=replace-with-random-secret \
STOFFEL_EXECUTION_ID="$(openssl rand -hex 32)" \
docker compose -f docker-compose.avss.yml up --build
```

`docker-compose.avss.yml` mounts a per-party local data volume and forwards `STOFFEL_LOCAL_STORE` to `stoffel-run`.

### Peer RTT emulation

The normal, benchmark, and standing-concurrency Compose stacks can emulate a
global peer-network RTT plus extra latency on selected parties. Values are
non-negative integer milliseconds:

```bash
NET_RTT_MS=80 \
PARTY3_EXTRA_RTT_MS=220 \
docker compose up --build
```

Every party-to-party pair receives `NET_RTT_MS`. A party's extra RTT is added
to every pair containing that party, so the resulting pairwise RTT is
approximately:

```text
global RTT + source party extra RTT + destination party extra RTT
```

In the example above, party 0 to party 1 is approximately 80 ms while party 0
to party 3 is approximately 300 ms. Multiple slow parties compose naturally;
with `PARTY2_EXTRA_RTT_MS=40` and `PARTY4_EXTRA_RTT_MS=160`, party 2 to party 4
receives the global RTT plus another 200 ms. `PARTY0_EXTRA_RTT_MS` through
`PARTY4_EXTRA_RTT_MS` are available in each stack.

The shaper selects only the five fixed party IPs. Coordinator, client, and
other container traffic remains unshaped, which keeps a slow-party experiment
focused on the MPC peer mesh. The existing `NET_LOSS` (percent) and
`NET_BANDWIDTH` (Mbit/s) controls remain whole-network egress controls. The
defaults are zero RTT and no loss or bandwidth limit.

The AVSS threshold ECDSA examples mirror the threshold signature fixtures:

```bash
STOFFEL_AUTH_TOKEN=replace-with-random-secret \
STOFFEL_PROGRAM=/app/programs/threshold_ecdsa_secp256k1.stflb \
STOFFEL_MPC_CURVE=secp256k1 \
docker compose -f docker-compose.avss.yml up --build

STOFFEL_AUTH_TOKEN=replace-with-random-secret \
STOFFEL_PROGRAM=/app/programs/threshold_ecdsa_p256.stflb \
STOFFEL_MPC_CURVE=p-256 \
docker compose -f docker-compose.avss.yml up --build
```

The Stoffel source for these programs lives in `crates/stoffel-lang/examples/threshold_signatures/threshold_ecdsa_secp256k1/main.stfl` and `crates/stoffel-lang/examples/threshold_signatures/threshold_ecdsa_p256/main.stfl`. The VM only provides primitive helpers for field inversion, converting an opened curve point to `x mod q`, and formatting the final ECDSA output. The threshold ECDSA protocol itself is expressed in the Stoffel program. The returned layout is fixed-width big-endian `r(32) || s(32) || sec1_compressed_pk(33)`, so callers can DER-encode `(r, s)` directly.

For the AVSS certificate-signing path, run `/app/programs/avss_certificate_keygen.stflb` with `STOFFEL_MPC_CURVE=secp256k1` or `STOFFEL_MPC_CURVE=p-256` to persist each party's CA signing share. Keygen is idempotent: it loads the existing share if the storage key already exists and only generates on first use. Then run `/app/programs/avss_certificate_sign.stflb` with `STOFFEL_WAIT_FOR_CLIENTS=1`; the client submits the real SHA-256 TBS digest and reconstructs fixed-width threshold ECDSA `r || s` material with `--outputs 2`. The corresponding Stoffel source lives in `crates/stoffel-lang/examples/avss_certificate/keygen/main.stfl` and `crates/stoffel-lang/examples/avss_certificate/sign/main.stfl`.

## Standing concurrent nodes

`stoffel-run --standing-node` keeps one authenticated party mesh alive until
the process receives SIGINT or SIGTERM (SIGKILL stops it immediately). It has
no finite run count. A trusted controller publishes the same monotonically
sequenced Prepare/Cancel command into each party's mounted
`--control-dir`; parties publish acknowledgements and lifecycle events back to
that mount. This mounted command log is the standing node's admission boundary.
The shared trusted controller owns deployment concurrency and resource limits;
nodes intentionally do not make independent local admission decisions, which
could otherwise make different parties select different executions.
The MPC coordinator remains execution-scoped protocol infrastructure, not a
second execution scheduler.

Programs are immutable content-addressed artifacts. Prepare launches the
execution after setup emits Ready; its online task then waits for the admitted
clients. Every admission
contains a new full 256-bit execution ID, the program ID and entry point, and an
exact `clients` list of `{certificate, manifest_slot}` bindings. The
program manifest supplies the MPC backend, curve, and client input shape; the
controller does not repeat those values. Each execution receives an isolated
transport inbox and storage scope, with preprocessing material destructively
allocated from its program reservoir. `--pool-id` must be globally unique for a
live deployment; never attach copies of one preprocessing volume to two live
pools. Reservoirs are warmed before readiness and refilled as execution bursts
consume them. The default nine-execution burst is admitted from ten warm
bundles before a refill owns the program's preprocessing lane.

The production-shaped five-party acceptance campaigns use the current VM,
coordinator, and networking worktrees:

```bash
STOFFEL_COORDINATOR_CONTEXT=/absolute/path/to/stoffel-mpc-coordinator \
STOFFEL_NETWORK_CONTEXT=/absolute/path/to/stoffel-networking \
docker/test-standing-concurrency.sh

STOFFEL_COORDINATOR_CONTEXT=/absolute/path/to/stoffel-mpc-coordinator \
STOFFEL_NETWORK_CONTEXT=/absolute/path/to/stoffel-networking \
docker/test-standing-adversarial.sh
```

## C Foreign Function Interface

`stoffel-vm` builds as both an `rlib` and a `cdylib`, so the runtime can also be embedded from C-compatible environments.

Relevant files:

- `include/stoffel_vm.h`
- `include/README.md`

Platform-specific library names:

- Linux: `libstoffel_vm.so`
- macOS: `libstoffel_vm.dylib`
- Windows: `stoffel_vm.dll`

## Build and Test

Build everything:

```bash
cargo build
```

Run the test suite:

```bash
cargo test
# Generated-Cargo and local-MPC CLI tests share one heavyweight serial group.
cargo test -p stoffel-cli --test cli -- --ignored --test-threads=1
# Run the coordinator lifecycle regressions as a separate serial step.
cargo test -p stoffel-vm-runner --test local_coordinator_e2e -- --ignored --test-threads=1 --skip optimized_aes --skip batch_mul
```

The ordinary suite remains parallel. Keep the heavyweight CLI group in its
separate serial invocation so nested Cargo builds cannot contend with
timeout-sensitive local MPC subprocesses; CI uses the same split.

Build the runtime and CLI in release mode:

```bash
cargo build --release -p stoffel-vm -p stoffel-vm-runner
```

HoneyBadger and AVSS backend code is built by default. Distributed party runs
select the backend from the compiled `.stflb` program manifest.

## Roadmap

Stoffel is under active development. The following capabilities are planned or
in progress and are **not yet supported**:

- **Solidity / EVM integration** — `solidity-foundry` and `solidity-hardhat`
  project templates, and tooling for using Stoffel MPC outputs from on-chain
  smart contracts. Referenced in some docs, but not yet shipped.
- **Additional SDKs** — Python and TypeScript/WASM SDKs to complement the Rust
  SDK. The C FFI surface exists today; higher-level language bindings are still
  in progress.
- **Hosted / managed deployment** — turnkey deployment of MPC party networks
  beyond the local runner and Docker Compose stacks.

Have a use case you don't see here? Open an issue or reach out — priorities are
shaped by what people are building.

## Learn More

To learn more about what you can build with Stoffel, visit
[stoffelmpc.com](https://stoffelmpc.com).
