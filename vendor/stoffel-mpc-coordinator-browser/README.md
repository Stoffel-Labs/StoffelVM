# Stoffel MPC Coordinator Library

`stoffel-mpc-coordinator` provides coordinator primitives for Stoffel MPC workflows. It manages the full protocol lifecycle: preprocessing, input-mask reservation, input collection, MPC execution, and output distribution.

The crate supports two coordinator transports:

- **On-chain**: Ethereum smart-contract coordination via Alloy and the Stoffel Solidity bindings.
- **Off-chain**: secure JSON-RPC over mutual TLS for local or non-chain deployments.

Default features enable both transports. Use `--no-default-features --features off-chain` or `--no-default-features --features on-chain` to build only one transport.

## Package status

This is a `0.1.0` release-prep crate. It currently depends on the pinned Stoffel Solidity SDK binding crates, which need to be published or removed from the public dependency graph before a crates.io publish can succeed.

## Deploying the coordinator

Start Anvil using `anvil`.

Install a mock on-chain coordinator with
`DEPLOY_SK='0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' cargo run --bin deploy-contract -- --eth-node-addr ws://127.0.0.1:8545 --program program.stflb --t 1 --initial-mpc-nodes 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266,0x70997970C51812dc3A010C7d01b50e0d17dc79C8,0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC,0x90F79bf6EB2c4f870365E785982E1f101E93b906,0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65 --output-clients 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`.
Deployment derives the program hash, input count, and MPC backend threshold from the compiled program manifest.

For the off-chain coordinator, generate identities using `cargo run --bin generate-ids -- ids 2 5` (output directory `ids`, 2 clients, 5 nodes).
Every program invocation needs one nonzero 256-bit execution ID shared by its coordinator, MPC
nodes, and clients. The commands below use
`0000000000000000000000000000000000000000000000000000000000000001` as a readable example;
use a freshly generated value (for example, `openssl rand -hex 32`) for each real invocation.
Then, run the off-chain coordinator with `cargo run --bin run-coord -- --one-off 0000000000000000000000000000000000000000000000000000000000000000,0000000000000000000000000000000000000000000000000000000000000001 --server-cert ids/pub/coord.crt --server-key ids/priv/coord.der --n 5 --t 1 --n-inputs 2 --initial-mpc-nodes ids/pub/nodes/node0.crt,ids/pub/nodes/node1.crt,ids/pub/nodes/node2.crt,ids/pub/nodes/node3.crt,ids/pub/nodes/node4.crt --output-clients ids/pub/clients/client0.crt,ids/pub/clients/client1.crt`.
`--one-off <hash>,<execution-id>` registers that single execution before listening and exits the coordinator once it reaches the ProgramFinished round; omit it to run a standing coordinator that keeps listening and accepts further registrations.

For VM-backed client IO, pass a compiled `.stflb` with an IO manifest and bind logical VM slots to off-chain client certificates:

`cargo run --bin run-coord -- --one-off 0000000000000000000000000000000000000000000000000000000000000000,0000000000000000000000000000000000000000000000000000000000000001 --server-cert ids/pub/coord.crt --server-key ids/priv/coord.der --n 5 --t 1 --initial-mpc-nodes ids/pub/nodes/node0.crt,ids/pub/nodes/node1.crt,ids/pub/nodes/node2.crt,ids/pub/nodes/node3.crt,ids/pub/nodes/node4.crt --output-clients ids/pub/clients/client0.crt --program program.stflb --client-bindings 0=ids/pub/clients/client0.crt`

The off-chain coordinator also selects the MPC share backend from the `.stflb` manifest. Compile
programs with `stoffel --mpc-backend honeybadger -b program.stfl` or
`stoffel --mpc-backend avss -b program.stfl`. Legacy/no-program startup defaults to HoneyBadger.

## Library overview

This library is generic over the share type used by the underlying MPC protocol.

## Share Types

The coordinator is parameterized as `<F: FftField, S: ShareBound<F>>`, where `S` is the share type used throughout the protocol. `ShareBound<F>` bundles the constraints the coordinator places on a share:

- **`SecretSharingScheme<F>`**: exposes secret reconstruction (`recover_secret`) and share generation (`compute_shares`).
- **`CanonicalSerialize` / `CanonicalDeserialize`**: shares are transmitted as compressed bytes over JSON-RPC.
- **`Clone`, `Send`, `'static`**: required for use across async Tokio tasks.

Two concrete share types are provided. Off-chain startup selects between them from the running
program manifest when `--program` is provided:

| Manifest backend | Share type | Description |
|---|---|---|
| `honeybadger` | `RobustShare<F>` | Plain Shamir share used by HoneyBadger MPC |
| `avss` | `FeldmanShamirShare<F, G>` | Shamir share with group-element commitments for verifiable secret sharing |

To add a new share type, implement `ShareBound<F>` for it, paying particular attention to `compute_masked_input`, which subtracts a mask share from a masked input while preserving any per-share metadata.

## Protocol Rounds

Every protocol execution traverses these rounds in order:

```
Idle → Preprocessing → InputMaskReservation → InputCollection → MPCExecution → OutputDistribution → ProgramFinished
```

The **designated party** (the first MPC node registered with the coordinator) drives all round transitions. Clients and nodes subscribe to round notifications and receive them regardless of whether the transition happened before or after they subscribed — the coordinator records each transition event with a Unix timestamp and replays missed events to late subscribers.

## The `Coordinator` Trait

Both on-chain and off-chain coordinators implement `Coordinator<F, S>`, which exposes:

- **Designated-party methods**: `start_preprocessing`, `reserve_input_masks`, `collect_inputs`, `start_mpc`, `send_output`, `finalize`, `reset_coord`
- **Node methods**: `wait_for_round`, `wait_for_indices`, `wait_for_inputs`, `send_output_shares`
- **Client methods**: `reserve_mask_index`, `send_masked_input`, `obtain_outputs`

## On-Chain Coordinator

`on_chain::OnChainCoordinator<P, F, S>` integrates with the `StoffelCoordinator` Ethereum smart contract via [Alloy](https://alloy.rs). Key behaviors:

- **Role management**: contract events and calls assign roles (party, designated party) to nodes.
- **Index reservation**: clients reserve input-mask indices via contract calls; the coordinator tracks ownership through `ReservedInputEvent` events.
- **Client authentication**: clients sign a nonce with their Ethereum private key; nodes verify the signature against the Ethereum address registered in the contract, binding the client's TLS identity to its Ethereum identity.
- **Input collection**: clients submit masked inputs (`x + m`) to the contract; nodes listen for `MaskedInputEvent` and compute a share of the unmasked input by subtracting their mask share.
- **Output distribution**: output shares are HPKE-encrypted for each client and delivered via the contract.

Client identities are Ethereum `Address` values. The on-chain node-side RPC server (`on_chain::node_rpc::NodeRPCServer`) watches for `ReservedInputEvent` from the contract to learn which client holds which mask index, then serves the corresponding mask share to the authenticated client.

## Off-Chain Coordinator

The off-chain coordinator operates over JSON-RPC (WebSockets) with mutual TLS, without any blockchain dependency. It consists of two components:

- **`OffChainCoordinatorServer<C>`**: the coordinator RPC server. It is generic over the connection type `C: RPCServerConnection`, so developers can extend both per-connection state and shared state. The provided `FakeCoordinatorConnection` and `CoordinatorRPCServerConnectionBase` are ready-to-use implementations.
- **`OffChainCoordinatorClient<F, S>`**: the RPC client used by both MPC nodes and MPC clients to communicate with the coordinator.

Key behaviors:

- **Round management**: the designated party triggers transitions by calling `transition(Round)` over RPC; all subscribers receive the corresponding event.
- **Index reservation**: clients call `reserve_mask_index(i)` during `InputMaskReservation`. The event is broadcast to all `sub_reserved_indices` subscribers, including MPC nodes.
- **Mask-share distribution**: each MPC node runs a `node_rpc::NodeRPCServer`. After learning a client's reserved index from the coordinator, the node delivers its mask share to the client over a dedicated WebSocket subscription authenticated by mTLS. The client collects `2t + 1` shares and reconstructs the mask locally.
- **Output distribution**: MPC nodes HPKE-encrypt their output shares under the client's P-256 public key and call `send_output_shares`. Once `2t + 1` shares have arrived at the coordinator, they are forwarded to the client's `obtain_output_shares` subscription.
- **Bound VM IO layout**: `.stflb` bytecode can carry a client IO manifest built from `ClientStore.take_share*` and client-output calls. Off-chain startup binds VM `client_slot` values to certificate public keys, derives input-mask capacity from bound input counts, and authorizes output clients from bound output counts. Scalar IO types stay with the SDK/VM manifest and are not interpreted by the coordinator. On-chain contracts/events do not yet carry this layout metadata; equivalent Solidity support is deferred.
- **Authentication**: all connections use mutual TLS with self-signed certificates. The client's identity is the DER-encoded public key from its certificate, used consistently towards both the coordinator and node RPC servers.
- **Late-subscriber safety**: subscribers pass the coordinator's startup timestamp so that events fired before the subscription is opened are replayed immediately.

### Extending the coordinator

The off-chain coordinator is split into two RPC trait layers:

1. **`StoffelCoordinatorRPC`**: the developer-facing interface containing only the round-transition methods (`start_preprocessing`, `reserve_input_masks`, etc.). Implement this on a custom connection type to embed application logic into each transition.
2. **`CoordinatorRPCBase<F, S>`**: pre-implemented by the library, covering index reservation, input submission, output distribution, and all subscriptions.

## Common Features

- **HPKE encryption**: output shares are encrypted.
- **Threshold**: secret reconstruction requires `2t + 1` shares; both the coordinator and clients enforce this before forwarding or accepting outputs.
- **Testing utilities**: `self_signed_certs` provides `server_cert()` / `client_cert()` helpers. `setup_test()` installs the default `rustls` crypto provider required before any TLS connections are made in tests.
