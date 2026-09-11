# Stoffel app

This project is a complete Stoffel application: a private program, a Rust application client, and the services that run its MPC network.

## Validate the Stoffel program

```sh
stoffel check
```

## Run the local MPC network

Start the coordinator and the number of MPC nodes configured by `[mpc].parties` in `Stoffel.toml`:

```sh
./scripts/run-local.sh
```

The script validates and compiles `src/main.stoffel`, builds the Rust binaries, and starts the coordinator and MPC nodes. It does not run a client.

## Integrate the client

In a second terminal, send the sample private input:

```sh
./scripts/run-client.sh 42
```

Expected output:

```text
Doubled result: 84
```

`src/client.rs` is the code to carry into your application. It gets a configured `StoffelClient`, submits typed private input with `run_typed`, and receives the typed result. `src/deployment.rs` keeps network addresses, identities, and bytecode loading outside the application flow so a real app can replace that module with its own configuration provider.

## Build bytecode

```sh
stoffel build --output artifacts/program.stflb
```

`cargo build` then generates typed Rust bindings from that exact bytecode through `build.rs`.

## Project structure

```text
.
├── Cargo.toml                 # Rust application and service binaries
├── Stoffel.toml               # Program, party count, threshold, and build settings
├── build.rs                   # Typed binding generation
├── src/
│   ├── client.rs              # Participant-owned application integration
│   ├── deployment.rs          # Deployment configuration adapter
│   ├── server.rs              # One MPC node built with stoffel-rust-sdk
│   ├── coordinator.rs         # Off-chain coordinator and local identities
│   ├── main.rs                # Local coordinator and node orchestration
│   └── main.stoffel           # Private computation
├── tests/                     # Stoffel and Rust tests
└── scripts/
    ├── run-local.sh           # Local coordinator and node launcher
    ├── run-client.sh          # Sample application client
    ├── docker-compose.yml     # Coordinator and five deployable MPC nodes
    └── Dockerfile             # Coordinator and node image
```

The local network is deployment-shaped: the application client, coordinator, and MPC nodes are separate processes. Private input goes from the participant-owned client directly to the MPC network.

## Run the tests

```sh
stoffel test
cargo test
```

## Run with Docker Compose

Build the program and prepare local development identities once:

```sh
stoffel build --output artifacts/program.stflb
cargo run --bin stoffel-coordinator -- prepare
docker compose -f scripts/docker-compose.yml up --build
```

The Compose stack runs one coordinator and five independently addressable MPC nodes. The image includes `stoffel-run`, while the generated `stoffel-server` binary keeps its command short. Keep the client in your application and run `./scripts/run-client.sh 42` after the nodes are healthy.

For a real deployment, provide each service its own identity and persistent runtime environment, replace loopback addresses in the deployment configuration, and manage secrets with your deployment platform.

## Learn more

Read the [Stoffel documentation](https://docs.stoffelmpc.com) for language guides, Rust SDK integration, MPC concepts, and deployment guidance.
