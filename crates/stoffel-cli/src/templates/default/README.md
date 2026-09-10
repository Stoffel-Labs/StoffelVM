# Stoffel app

This project separates the app client from the MPC services:

```text
Participant's Rust app (src/main.rs)
    | typed private input, submitted through stoffel-rust-sdk
    v
Coordinator + five separately running stoffel-run nodes
    | authorized typed output
    v
Participant's Rust app
```

`src/main.stfl` doubles one private integer from client slot 0 and sends the
result only to that client. The nodes do not publicly open the result.
The Rust client loads compiled bytecode, derives its IO configuration from the
program manifest, and calls `StoffelClient::run_typed`. It never starts nodes or
compiles source at runtime. Replace the stdin read with your app's input handling.

## Run locally

Requirements: the matching `stoffel` and `stoffel-run` release binaries on PATH,
Rust/Cargo, and Python 3. Set `STOFFEL_RUN_BIN` if the runner lives elsewhere.

```sh
python3 scripts/local.py
```

Enter `42` when prompted. Expected app output: `Doubled result: 84`.
The script builds the program and Rust binaries, generates local identities on
first use, then starts a coordinator, five independent `stoffel-run` processes,
and the app client. It waits for service startup and stops its processes on
completion, failure, or Ctrl-C. Logs are under `target/local-logs/`.
This is real client/service IO over loopback, not an in-process local MPC API.
Each invocation runs one computation. Restart the services for another input.

`deploy/local/` contains generated private keys and is ignored by Git. Never
commit it or copy the whole directory to a server. On Unix it is owner-only.
Keep `Cargo.lock` in version control for your application.

## Build and run each role separately

Build bytecode first. Cargo generates typed bindings from that exact artifact:

```sh
stoffel check
stoffel build --output artifacts/program.stflb
cargo build --bins --examples
cargo run --example local-coordinator -- prepare  # once; refuses to overwrite identities
```

Start the local reference coordinator in its own terminal:

```sh
cargo run --example local-coordinator -- serve
```

Start the leader in another terminal. The leader hosts the bootnode on port
19200 and automatically listens for party/client mesh traffic on port 20200:

```sh
STOFFEL_AUTH_TOKEN=stoffel-local-example \
  stoffel-run artifacts/program.stflb main --leader --bind 127.0.0.1:19200 \
  --n-parties 5 --threshold 1 --mpc-backend honeybadger \
  --off-chain-coord 127.0.0.1:19300 --rpc-bind 127.0.0.1:19400 \
  --cert deploy/local/node-0.cert.der --key deploy/local/node-0.key.der \
  --expected-clients deploy/local/client-0.cert.der \
  --client-roster 0 --client-input-slots 0 --client-input-count 1 --client-input-total 1
```

Start each follower in its own terminal. Set `ID` to 1, 2, 3, then 4:

```sh
ID=1
STOFFEL_AUTH_TOKEN=stoffel-local-example \
  stoffel-run artifacts/program.stflb main --party-id "$ID" \
  --bind "127.0.0.1:$((19200 + 2 * ID))" --bootstrap 127.0.0.1:19200 \
  --n-parties 5 --threshold 1 --mpc-backend honeybadger \
  --off-chain-coord 127.0.0.1:19300 --rpc-bind "127.0.0.1:$((19400 + ID))" \
  --cert "deploy/local/node-$ID.cert.der" --key "deploy/local/node-$ID.key.der" \
  --expected-clients deploy/local/client-0.cert.der \
  --client-roster 0 --client-input-slots 0 --client-input-count 1 --client-input-total 1
```

After every node reports `Creating MPC engine`, run the app in a separate terminal:

```sh
cargo run -- deploy/local/deployment.json
```

Stop all service terminals after the result. The coordinator example uses the
published coordinator crate's reference RPC implementation, exposed under its
`tests::fake_coord` module. It performs real protocol coordination, but is a
single-session development fixture, not a production coordinator service.
Its dependencies are dev-dependencies and are not imported by the app client.

## Move the nodes to separate machines

Keep the same client code and compiled program. Operators run `stoffel-run`
independently of the app, as in the commands above, with their deployment's
coordinator, reachable addresses, and identity files:

- Give each node the same `program.stflb`, only its own certificate/private key,
  and the authorized client's public certificate. Give the client only its own
  identity and the program/config bundle. Never give nodes the client's private key.
- Configure the coordinator's node identity roster, client slot 0, one input,
  one output recipient, and the program. Replace the local reference coordinator
  with an operator-managed coordinator lifecycle before deploying an application.
- Change `--bind`/`--rpc-bind` to each machine's listening addresses, and
  `--bootstrap`/`--off-chain-coord` to reachable service addresses. If a node binds
  a wildcard address, set `--advertise` to its reachable mesh address. The leader
  needs its bootnode port and its mesh port (bootnode port + 1000) available.
- Supply an app `deployment.json` with five mesh addresses in `servers`, five
  `node_rpc_addresses`, coordinator host/port, a positive deployment timestamp,
  the bytecode path, and the participant's identity paths. Use reachable numeric
  IP socket addresses for mesh/RPC entries. Paths resolve relative to the config.
- Pass that config to the app binary. The application embeds the same SDK builder
  and `run_typed` call; it does not call a local runner or supervise nodes.

A shared app backend can distribute public deployment metadata, but should not
receive the participant's plaintext input. This example demonstrates a native
Rust participant, not a browser client. Provision production identities, session
authorization, artifact integrity, secure networking, process supervision and
persistent state as operator responsibilities; the loopback fixture supplies none
of those deployment guarantees.

After changing `src/main.stfl`, rebuild bytecode and then Cargo so the node program
and generated client bindings stay together. The example fixes five parties,
threshold one, and client slot zero deliberately; update the service configuration
and coordinator IO roster together if you change the program's client shape.
