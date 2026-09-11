# Stoffel app

This project shows where Stoffel fits in an application:

```text
.
├── Cargo.toml
├── Stoffel.toml
├── src/{client.rs,server.rs,coordinator.rs,main.rs,main.stoffel}
├── tests/
└── scripts/{run-local.sh,run-client.sh,docker-compose.yml,Dockerfile}
```

- `src/client.rs` is participant-owned application code. Integrate this SDK flow into your API, CLI, mobile backend, or other end-user application.
- `src/server.rs` defines one MPC node. `[mpc].parties` in `Stoffel.toml` controls how many local nodes `src/main.rs` starts.
- `src/coordinator.rs` prepares participant identities and runs the off-chain coordinator.
- `src/main.rs` starts only the coordinator and MPC nodes. It never runs a client.
- `src/main.stoffel` is compiled to the bytecode every node executes.

The local services are a single-session development fixture, not reusable production daemons.

## Run locally

Install `stoffel`, `stoffel-run`, and Rust, then start the MPC services:

```sh
./scripts/run-local.sh
```

The script runs `stoffel check`, compiles `src/main.stoffel`, generates the typed Rust bindings, and starts the service binary.

When the services report that they are ready, use a second terminal for the participant client:

```sh
./scripts/run-client.sh
```

Enter `42`. The client secret-shares that value, invokes the generated typed interface with `run_typed`, and prints `Doubled result: 84` after MPC execution.

Generated identities and deployment metadata live under ignored `deploy/local/`. The typed Rust bindings are generated from `artifacts/program.stflb` during `cargo build`, keeping application types aligned with deployed bytecode.

## Run roles separately

The same Rust files can be operated as independent processes:

```sh
cargo run --bin stoffel-coordinator -- prepare
cargo run --bin stoffel-coordinator -- serve
STOFFEL_AUTH_TOKEN=stoffel-local-example cargo run --bin stoffel-server -- 0
# Repeat stoffel-server with each party ID through [mpc].parties - 1.
cargo run --bin stoffel-client -- deploy/local/deployment.json
```

Move these roles to separate machines by replacing loopback addresses in deployment metadata, giving each node its own identity files, and setting `STOFFEL_BIND_ADDRESS`, `STOFFEL_RPC_BIND_ADDRESS`, `STOFFEL_COORDINATOR_ADDRESS`, and `STOFFEL_BOOTSTRAP_ADDRESS`. Do not share private key files between machines.

## Container example

After building the bytecode and preparing identities, `scripts/docker-compose.yml` demonstrates a coordinator and five node containers on a private network:

```sh
stoffel build --output artifacts/program.stflb
cargo run --bin stoffel-coordinator -- prepare
docker compose -f scripts/docker-compose.yml up --build
```

Run `./scripts/run-client.sh` on the host after the nodes are ready. The Compose file expands the default five-party topology explicitly; update its node services if you change `[mpc].parties`.

Run the sample Stoffel test with:

```sh
stoffel test
```