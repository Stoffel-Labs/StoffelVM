# Stoffel Rust SDK

The Rust SDK is the library entry point for embedding Stoffel-Lang compilation,
bytecode loading, VM execution, and MPC participant configuration in Rust apps.

## Getting Started

Add the crate and import the prelude:

```toml
stoffel-rust-sdk = "=0.2.0"
```

```rust
use stoffel::prelude::*;

let result = Stoffel::compile(
    "def main(a: int64, b: int64) -> int64:\n  return a + b",
)?
.with_inputs(&[("a", 42_i64), ("b", 58_i64)])
.execute_clear()?;

assert_eq!(result, vec![Value::I64(100)]);
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
    "def main(a: secret int64, b: secret int64) -> secret int64:\n  return a + b",
)?
.parties(5)
.threshold(1)
.honeybadger()
.local_runner_path("target/debug/stoffel-run")
.with_inputs(&[("a", 42_i64), ("b", 58_i64)])
.execute_local()
.await?;

assert_eq!(result, vec![Value::I64(100)]);
# Ok(())
# }
```

## Current Execution Modes

- `execute_clear()` runs non-secret Stoffel programs through the embedded
  `stoffel-vm` and is intended for fast local development of clear logic.
- `execute_local()` uses `stoffel-vm`'s real local coordinator runner for
  local HoneyBadger and AVSS smoke runs. Build
  `stoffel-run` first with `cargo build -p stoffel-vm-runner --bin stoffel-run`, or
  set `STOFFEL_RUN_BIN` or `local_runner_path(...)`. Relative runner paths are
  resolved from the process working directory first and then from the workspace
  root, so `target/debug/stoffel-run` works for normal workspace runs. Named
  `with_inputs` values are adapted into local coordinator client input for
  source, file, and loaded-bytecode programs; source/file functions returning a
  `secret` value are opened by the generated wrapper so `execute_local()`
  returns clear SDK values. Programs that explicitly read from
  `ClientStore.take_share` can still receive local coordinator client input
  through `with_client_input` or replace the full local client input set through
  `with_client_inputs`.
  AVSS local coordinator execution and client input support every SDK curve:
  BLS12-381, BN254, Curve25519, Ed25519, secp256k1, and P-256.
- `runtime.local_network()` exposes the same coordinator-backed local run as a
  small builder for advanced local smoke tests that need a custom entrypoint,
  timeout, or runner binary path:

  ```rust
  # use std::time::Duration;
  # use stoffel::prelude::*;
  # async fn example(runtime: StoffelRuntime) -> stoffel::Result<()> {
  let result = runtime
      .local_network()
      .entry("main")
      .runner_path("target/debug/stoffel-run")
      .timeout(Duration::from_secs(180))
      .run()
      .await?;
  # let _ = result;
  # Ok(())
  # }
  ```
- Consensus ordering/gate/error types are re-exported from `stoffel-networking`.
  The SDK does not duplicate the digest exchange or networking protocol.
  When deployment code obtains a `VerifiedOrdering` from `stoffel-networking`,
  attach it with `ClientBuilder::with_verified_ordering(...)` or
  `ServerBuilder::with_verified_ordering(...)` so SDK participant summaries and
  `client.verify_ordering().await` can expose that consensus evidence.
- `NetworkConfig` validates PRD-style TOML and fallibly converts into
  `stoffel-networking`'s `QuicNetworkConfig` for code that needs direct
  transport setup.
- `MpcConfig::to_vm_topology(party_id)` delegates session topology validation to
  `stoffel-vm`.
- `MpcBackend::minimum_reconstruction_shares(t)` reports backend-specific
  reconstruction requirements: HoneyBadger uses `2 * t + 1`, AVSS uses
  `t + 1`. This is separate from Byzantine party-count validation
  (`n >= 4 * t + 1`).
- `StoffelClient::connect` opens real QUIC client connections through
  `stoffel-networking`. For programs with `ClientStore` metadata,
  `runtime.offchain_client_config(slot)` derives the typed client IO settings
  from the compiled program and MPC runtime; callers then provide coordinator
  address, node RPC addresses, a nonzero execution ID, timestamp, and client identity material before
  calling `client.run_typed(...)`, `client.submit_typed(...)`, `client.run(...)`,
  or `client.submit(...)`. Server launch for those programs uses
  `ServerBuilder::offchain_coordinator(...)` to pass the
  coordinator address, node RPC bind address, party identity files, timestamp,
  and expected client certificates through to `stoffel-run`.
- AVSS protocol operations are owned by `stoffel-vm` and `mpc-protocols`.
  The SDK exposes the intended API boundary but does not implement an in-memory
  AVSS substitute. Local AVSS programs on any supported curve delegate through the real
  `stoffel-run` coordinator path:

  ```rust
  use stoffel::prelude::*;

  # async fn example() -> stoffel::Result<()> {
  let result = Stoffel::compile("def main() -> int64:\n  return 7")?
      .avss(Curve::Bls12_381)
      .local_runner_path("target/debug/stoffel-run")
      .execute_local()
      .await?;
  # let _ = result;
  # Ok(())
  # }
  ```

  Programs that read `ClientStore.take_share` can receive AVSS local client
  input through `with_client_input` on every supported curve.

  When deployment/server code already owns a live generic VM AVSS engine, wrap
  it with `AvssEngine::from_engine(engine)` and attach it with
  `ServerBuilder::with_avss_engine(...)`. The SDK infers the curve from the VM
  engine's group type, so there is no curve-specific constructor or separate
  curve argument that can disagree with the engine. The builder validates that
  the inferred engine curve matches the selected AVSS backend. A configured
  `StoffelServer` that has not been started does not fabricate an engine;
  `engine.is_live()` reports whether calls delegate to a VM engine.

  AVSS/Feldman share payloads can still be represented at the SDK boundary and
  inspected without running protocol logic:

  ```rust
  use stoffel::prelude::*;

  let share = Share::feldman("threshold-key", [0x01, 0x02], [[0x10], [0x20]]);
  assert!(share.is_feldman());
  assert_eq!(share.commitment_count(), 2);
  assert_eq!(
      share.public_key(),
      Some(PublicKey::new("threshold-key", [0x10]))
  );
  ```

## Typed Client IO Bindings

Programs that use `ClientStore` carry ordered input and output types in the
`.stflb` manifest. Generate Rust bindings from that exact bytecode in your app's
`build.rs` to get compile-time input/output structs for the program you will
execute:

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::env::var("OUT_DIR")?;
    stoffel_bindgen::generate_bindings(
        "program.stflb",
        format!("{out_dir}/stoffel_bindings.rs"),
    )?;
    Ok(())
}
```

```rust
include!(concat!(env!("OUT_DIR"), "/stoffel_bindings.rs"));

# async fn example(client: stoffel::StoffelClient) -> stoffel::Result<()> {
let outputs: Client0Outputs = client
    .run_typed(Client0Inputs {
        input_0: 42_i64,
    })
    .await?;
# let _ = outputs;
# Ok(())
# }
```

Generated bindings use `Client{slot}Inputs` and `Client{slot}Outputs` with
ordered fields such as `input_0` and `output_0`. Integers map to `i64`, boolean
secret integers map to `bool`, and fixed-point shares map to `f64`. The SDK also
validates the generated type shape against the loaded program manifest before
submitting to the off-chain coordinator.

## Core Builders

Use `Stoffel` as the main entry point:

```rust
let runtime = Stoffel::compile_file("program.stfl")?
    .parties(9)
    .threshold(2)
    .avss(Curve::Bls12_381)
    .build()?;
# Ok::<(), stoffel::Error>(())
```

Compiled runtimes can be reused with different local inputs without compiling
again:

```rust
let runtime = Stoffel::compile("def main(a: int64, b: int64) -> int64:\n  return a + b")?
    .build()?;

let result = runtime
    .with_inputs(&[("a", 40_i64), ("b", 2_i64)])
    .execute_clear()?;
assert_eq!(result, vec![Value::I64(42)]);
# Ok::<(), stoffel::Error>(())
```

Use `NetworkConfig` when deploying servers from TOML:

```rust
let config = NetworkConfig::builder()
    .party_id(0)
    .bind_address("127.0.0.1:19200")
    .expected_parties(5)
    .expected_clients(1)
    .peers([
        (1, "127.0.0.1:19201"),
        (2, "127.0.0.1:19202"),
        (3, "127.0.0.1:19203"),
        (4, "127.0.0.1:19204"),
    ])
    .threshold(1)
    .honeybadger()
    .consensus_timeout(std::time::Duration::from_secs(60))
    .preprocessing(1000, 500)
    .build()?;

config.validate_server_addresses()?;
let server = StoffelServer::builder(0).network_config(&config).build()?;
let client = StoffelClient::builder().network_config(&config).build()?;
# Ok::<(), stoffel::Error>(())
```

For a local or staging cluster where all party addresses are known up front,
derive one validated config per party from a single deployment plan:

```rust
use std::time::Duration;
use stoffel::prelude::*;

let deployment = NetworkDeployment::builder([
    "127.0.0.1:19200",
    "127.0.0.1:19201",
    "127.0.0.1:19202",
    "127.0.0.1:19203",
    "127.0.0.1:19204",
])
.expected_clients(1)
.threshold(1)
.honeybadger()
.consensus_timeout(Duration::from_secs(60))
.preprocessing(1000, 500)
.build()?;

let server = StoffelServer::builder(0)
    .network_deployment(&deployment)
    .build()?;
let client = StoffelClient::builder()
    .network_deployment(&deployment)
    .build()?;
# let _ = (server, client);
# Ok::<(), stoffel::Error>(())
```

Use `deployment.save_toml_files("deploy/config")?` to write
`party-0.toml`, `party-1.toml`, and so on for operators or process managers.
Compiled runtimes can attach program metadata to the same deployment plan:

```rust
use stoffel::prelude::*;

let deployment = NetworkDeployment::builder([
    "127.0.0.1:19200",
    "127.0.0.1:19201",
    "127.0.0.1:19202",
    "127.0.0.1:19203",
    "127.0.0.1:19204",
])
.build()?;

let runtime = Stoffel::compile(
    "def main(a: secret int64, b: secret int64) -> secret int64:\n  return a + b",
)?
.build()?;

let server_builders = runtime.servers_for_deployment(&deployment);
let party_zero = server_builders[0].clone().build()?;
let client = runtime.client_for_deployment(&deployment).build()?;
assert!(party_zero.program().is_some());
assert!(client.has_program());
# Ok::<(), stoffel::Error>(())
```

When a `NetworkConfig` is attached to `Stoffel`, its `[network]` and `[mpc]`
sections are authoritative for runtime `parties`, `threshold`, and `backend`.
This keeps deployment TOML from drifting away from the compiled program
metadata. If the compiled program declares `ClientStore` inputs, the SDK also
validates that `expected_clients` covers the declared client slots.
Preprocessing `triples` and `random_shares` must both be greater than zero.
Use `NetworkConfig::to_mpc_config(instance_id)` when an application needs the
same runtime MPC settings without compiling a program.
Use `network_config.summary()?` for a serializable deployment summary that
captures party/client counts, peer count, backend, threshold, reconstruction
shares, and preprocessing sizes.
Built runtimes expose the same status payloads through
`runtime.mpc_summary()?` and `runtime.network_summary()?`. Use
`runtime.summary()?` for a serializable status payload that combines program,
MPC, network, and local input configuration.

`runtime.client()` reuses the compiled program metadata and, when network
config is present, pre-populates the client builder with the configured server
addresses in party-id order. That client path requires complete server
addresses for every party; call `NetworkConfig::validate_server_addresses()`
when validating deployment TOML up front.
`runtime.server(party_id)` also uses the attached network config, and fails
fast if `party_id` does not match the config's `[network].party_id`.
For deployment plans with all party addresses available, use
`runtime.servers_for_deployment(&deployment)` and
`runtime.client_for_deployment(&deployment)` to attach the compiled program
while reusing the validated server addresses in party-id order.
`StoffelClient::builder().network_config_file(path)` and
`StoffelServer::builder(party_id).network_config_file(path)` provide the same
validation for direct participant construction. Direct server builders also
validate that `expected_clients` covers the attached program's declared
`ClientStore` slots.

Advanced applications that already have bytecode/program deployment handled
elsewhere can construct participants without compiling through
`Stoffel::server(party_id)` and `Stoffel::client()`. These are thin aliases for
the server and client builders; live network operations still require the
lower-level networking and VM integration rather than SDK-side simulation.
Both builders expose `configured_*` accessors so deployment code can inspect
addresses, backend selection, preprocessing settings, and attached program
metadata before consuming the builder with `build()`.
Server builders accept either additive `.peer(...)` calls or batch
`.peers([...])` / `.with_peers(&[...])` replacement, matching
`NetworkConfigBuilder`.
Client builders likewise accept additive `.server(...)` calls or replacement
`.servers([...])` / `.with_servers(&[...])` configuration.
Built servers expose `server.summary()` for a serializable operational snapshot
containing party identity, bind address, peer count, backend, preprocessing,
state, readiness, health, and whether an AVSS engine has been configured.
Built clients expose `client.summary()` for a serializable status snapshot
containing client identity, server count, attached-program flag, and state.

Programs that use `ClientStore` expose their required local coordinator inputs
through `Program` metadata:

```rust
let runtime = Stoffel::compile(
    "def main() -> int64:\n  var share = ClientStore.take_share(0, 0)\n  var opened: int64 = share.open()\n  return opened",
)?
.parties(5)
.threshold(1)
.build()?;

let client = runtime.program().client(0).expect("client slot 0");
assert_eq!(client.input_count(), 1);
assert_eq!(runtime.program().client_slots().collect::<Vec<_>>(), vec![0]);
assert_eq!(runtime.program().total_client_input_count(), 1);
assert_eq!(runtime.program().minimum_expected_clients(), 1);
runtime.program().validate_expected_clients(1)?;
let client_values = [Value::I64(42)];
runtime.program().validate_client_inputs(&[(0, client_values.as_slice())])?;
runtime.clone().with_client_input(0, &[42_i64]).validate_client_inputs()?;
Stoffel::compile(
    "def main() -> int64:\n  var share = ClientStore.take_share(0, 0)\n  return share.open()",
)?
.parties(5)
.threshold(1)
.with_client_input(0, &[42_i64])
.validate_client_inputs()?;
# Ok::<(), stoffel::Error>(())
```

Program metadata also includes function iteration and bytecode summary helpers
such as `function_names()`, `total_instruction_count()`, and
`total_register_count()` for tooling and diagnostics.
Use `runtime.program().summary()` for a serializable view of function counts,
function names, bytecode backend, and ClientStore input/output metadata.
For CLI-compatible bytecode artifacts, use `runtime.to_bytecode()` or
`runtime.save_bytecode("program.stflb")`; these delegate to the underlying
`Program` serialization. Use `runtime.bytecode_summary()?` for a
serde-friendly artifact summary that includes byte length and program metadata.

```rust
for function in runtime.program().functions() {
    println!("{function}");
}
# Ok::<(), stoffel::Error>(())
```

`Value` and the small SDK crypto wrapper types (`Share`, `PublicKey`,
`FieldElement`, and `GroupElement`) implement serde so application payloads can
be persisted or passed through existing API layers without conversion glue.
For typed output extraction, `Value` supports exact fallible conversions such
as `i64::try_from(value)` and `String::try_from(value)` in addition to the
borrowed `as_*` helpers.
Use `value.summary()` for a serializable, shallow status view containing the
value kind plus byte length or item count when applicable.

`NetworkConfig::to_quic_config()` and `NetworkConfig::to_quic_manager()` bridge
to `stoffel-networking` for the transport settings that `QuicNetworkConfig`
owns, including expected party/client counts and consensus timeout. Bind
addresses and static peer maps remain in the SDK/server configuration layer
because the lower-level QUIC config does not model those fields.

Loaded bytecode keeps its own MPC backend metadata. If no backend or network
config is supplied, the SDK infers the runtime backend from the bytecode. If a
backend or network config is supplied, it must match the bytecode metadata.

`MpcConfig` validates Byzantine safety with `n >= 4 * t + 1`. Reconstruction
share requirements are backend-specific: HoneyBadger uses `2 * t + 1`, while
AVSS uses `t + 1`. Use `MpcConfig::minimum_parties_for_threshold(t)` and
`MpcConfig::maximum_threshold_for_parties(n)` when deriving deployment sizes.
Use `mpc_config.summary()?` for a serializable deployment summary that includes
party count, backend, Byzantine limits, and backend-specific reconstruction
shares.
`MpcConfig` and `MpcBackend` implement serde for applications that persist SDK
runtime settings directly; backends serialize as the same readable strings used
in network TOML, such as `honeybadger` and `avss:ed25519`.
The `Backend` trait and typed `HoneyBadgerBackend`/`AvssBackend` helpers expose
protocol identity for builder/configuration code; protocol execution remains in
the VM and MPC protocol crates.

## Observability

SDK operations create `tracing` spans on async lifecycle and protocol-boundary
methods. Applications that do not already install a subscriber can use the SDK
helper:

```rust
use stoffel::prelude::*;
use tracing::Level;

TracingConfig::builder()
    .max_level(Level::INFO)
    .ansi(false)
    .install()?;
# Ok::<(), stoffel::Error>(())
```

Use `TracingConfig::summary()` for a serde-friendly status payload:

```rust
let config = TracingConfig::builder()
    .service_name("my-stoffel-app")
    .ansi(false)
    .build();
config.validate()?;
let summary = config.summary();
assert_eq!(summary.service_name, "my-stoffel-app");
# Ok::<(), stoffel::Error>(())
```

For OpenTelemetry traces during development, install the stdout exporter and
hold the returned guard until shutdown:

```rust
use stoffel::prelude::*;
use tracing::Level;

let otel = TracingConfig::builder()
    .service_name("my-stoffel-app")
    .max_level(Level::INFO)
    .install_opentelemetry_stdout()?;

otel.shutdown()?;
# Ok::<(), stoffel::Error>(())
```

Servers expose lightweight metrics snapshots and health/readiness state:

```rust
let server = StoffelServer::builder(0)
    .bind("127.0.0.1:19200")
    .peer(1, "127.0.0.1:19201")
    .with_preprocessing(100, 50)
    .build()?;

server.metrics().record_connected_peers(4);
server.metrics().record_preprocessing_remaining(80, 40);
server.metrics().record_computation_latency_ms(25);
server.metrics().record_computation_latency_ms(35);
let snapshot = server.metrics().snapshot();
assert_eq!(snapshot.connected_peers, 4);
assert_eq!(snapshot.preprocessing_random_shares_remaining, 40);
assert_eq!(server.metrics().computation_latency_average_ms(), Some(30));
assert_eq!(snapshot.computation_latency_average_ms(), Some(30));
# Ok::<(), stoffel::Error>(())
```

`HealthStatus` and `ServerMetricsSnapshot` implement serde for health endpoints
and operator dashboards. `HealthStatus` also implements `Display`, producing
compact strings such as `healthy` or `unhealthy: server has been shut down`.
Lifecycle enums (`ClientState`, `ServerState`, and `ComputationStatus`) also
implement serde and `FromStr` with readable snake-case values for status APIs.
Clients can establish real QUIC transport connections, and programs with
`ClientStore` metadata can submit typed inputs through the configured off-chain
coordinator and node RPC endpoints:

```rust
# use std::time::Duration;
# use stoffel::prelude::*;
# async fn example() -> stoffel::Result<()> {
let client = StoffelClient::builder()
    .server("127.0.0.1:19200")
    .connection_timeout(Duration::from_secs(10))
    .connect()
    .await?;

assert_eq!(client.state(), ClientState::Connected);
assert!(client.is_connected());
assert!(client.transport_client_id().is_some());
# Ok(())
# }
```

Clients validate named computations before handing work to live networking:
`client.run_function("name", inputs).await` and
`client.submit_function("name", inputs).await` both check attached program
metadata. ClientStore submissions additionally validate the program's typed
client slot metadata before using the configured off-chain coordinator and node
RPC endpoints.

Computation handles expose stable local state for live client integrations and
tests. Pending handles do not synthesize network results:

```rust
# async fn example() -> stoffel::Result<()> {
let handle = ComputationHandle::pending();
assert_eq!(handle.status(), ComputationStatus::Pending);
assert_eq!(handle.status().to_string(), "pending");
assert!(handle.is_pending());
assert_eq!(handle.summary().result_count, 0);
assert!(matches!(
    handle.clone().await_result().await,
    Err(Error::Unsupported(_))
));

handle.cancel();
assert_eq!(handle.status(), ComputationStatus::Cancelled);
assert!(handle.is_cancelled());

let completed = ComputationHandle::completed(vec![Value::I64(100)]);
assert!(completed.is_completed());
assert_eq!(completed.summary().result_count, 1);
assert_eq!(completed.await_result().await?, vec![Value::I64(100)]);
# Ok(())
# }
```

Errors expose categories for recovery logic without string matching:

```rust
let error = Error::Preprocessing("not enough triples".to_owned());
assert_eq!(error.category(), ErrorCategory::Preprocessing);
assert_eq!(error.category().as_str(), "preprocessing");
assert!(ErrorCategory::Preprocessing.is_recoverable());
assert!(error.is_recoverable());
assert_eq!(
    error.recovery_hint(),
    Some("ensure each server has enough triples and random shares before retrying")
);
```

`ErrorCategory` implements serde and `FromStr` using the same strings returned
by `as_str()`, which keeps structured error summaries stable across logs,
status APIs, and persisted diagnostics.

## Core Crate Boundaries

The SDK is intentionally thin around protocol-owned functionality:

- Compilation delegates to `stoffellang`.
- Clear bytecode execution delegates to `stoffel-vm`.
- MPC session topology delegates to `stoffel-vm`.
- Consensus gates, verified ordering, network errors, and QUIC types are
  re-exported from `stoffel-networking`.
- Off-chain coordinator types are re-exported from
  `stoffel-mpc-coordinator`.
- AVSS and HoneyBadger protocol internals remain in `stoffel-vm` and
  `mpc-protocols`.

This keeps the SDK ergonomic without introducing redundant protocol,
networking, compiler, VM, or coordinator implementations.

The crate root uses `#![forbid(unsafe_code)]`; protocol crates remain
responsible for any lower-level cryptographic or networking internals.

## Release Readiness

The SDK is currently a monorepo-local crate and intentionally keeps
`publish = false` until the dependency graph is registry-ready. A crates.io
release requires these dependencies to be published or replaced with registry
dependencies first:

- `stoffellang`
- `stoffel-vm`
- `stoffel-vm-runner`
- `stoffel-vm-types`
- `stoffelnet`
- `stoffelmpc-mpc`

`cargo package -p stoffel-rust-sdk --allow-dirty --no-verify` currently fails
because local path dependencies are not registry-ready. Once those crates are
published and the SDK manifest no longer uses local path dependencies, remove
`publish = false` and run:

```sh
cargo package -p stoffel-rust-sdk
cargo publish -p stoffel-rust-sdk --dry-run
```

For the current monorepo-local state, `cargo sdk-package-probe` runs the
package-preparation command and is expected to fail with the unpublished
dependency blocker above.

## Examples

Run the examples with:

```sh
cargo run -p stoffel-rust-sdk --example quickstart
cargo run -p stoffel-rust-sdk --example local_clear
cargo run -p stoffel-rust-sdk --example bytecode_roundtrip
cargo run -p stoffel-rust-sdk --example client_server
cargo run -p stoffel-rust-sdk --example network_config
cargo run -p stoffel-rust-sdk --example observability
cargo run -p stoffel-rust-sdk --example avss
```

`network_config` demonstrates deriving one config per party with
`NetworkDeployment` and writing `party-*.toml` files for operators.

The local MPC examples use the real localhost coordinator/party runner. Build
the VM runner first, then run them:

```sh
cargo build -p stoffel-vm-runner --bin stoffel-run
cargo run -p stoffel-rust-sdk --example quickstart_mpc
cargo run -p stoffel-rust-sdk --example local_mpc_client_input
cargo run -p stoffel-rust-sdk --example local_mpc_named_inputs
```

The real coordinator-backed tests are marked ignored because they spawn local
processes. Run them explicitly when validating the local MPC path:

```sh
cargo vm-local-e2e
cargo sdk-local-e2e
```

The common SDK verification aliases are:

```sh
cargo sdk-test
cargo sdk-local-e2e
cargo sdk-examples
RUSTDOCFLAGS='-D warnings' cargo sdk-doc
cargo sdk-clippy
cargo sdk-coverage-report
```

Those aliases expand to:

```sh
cargo test -p stoffel-vm --test local_coordinator_e2e -- --ignored --test-threads=1
cargo test -p stoffel-rust-sdk --test sdk_usage -- --ignored --test-threads=1
```
