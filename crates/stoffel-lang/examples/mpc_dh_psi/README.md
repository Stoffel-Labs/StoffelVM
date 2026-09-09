# MPC Diffie-Hellman PSI

Threshold Diffie-Hellman private set intersection for two clients with 1,000
items each and a 500-item intersection. This size matches the first row of the
PETAce ECDH-PSI benchmark used for comparison.

This example implements the complete blinded OPRF flow rather than exposing raw
inputs to the compute nodes:

1. A client uses the IETF-style BLS12-381 G1 hash-to-curve construction to map
   each element to `H(x)`, samples a fresh non-zero scalar `r`, and computes the
   blinded point `P = r*H(x)`.
2. Each compressed blinded point is packed into two 24-byte field limbs for the
   existing secret client-input channel. The nodes batch-open those limbs; this
   reveals only independently blinded, uniformly distributed group points.
3. The nodes generate one threshold-shared key `k` and evaluate all 2,000
   points with `Share.batch_open_exp_custom`, reconstructing `k*P` without ever
   reconstructing `k` or an evaluated scalar.
4. Each client multiplies its responses by `r^-1`, obtaining stable tags
   `k*H(x)`, and computes the intersection locally with a hash set.

The Stoffel program uses `list(capacity)` plus sequential indexed writes for
the packed inputs, per-item generators, and 96 KB response buffer. Capacity is
reserved without changing the list's initial logical length.

Set cardinalities and response order are public. Production deployments must
also provide authenticated clients, request-size limits, replay protection, and
an application policy for which party receives the final intersection.

Build the optimized bytecode and the release runner from the repository root:

```sh
cargo build --workspace --release
target/release/stoffel build crates/stoffel-lang/examples/mpc_dh_psi --release
```

Then run the end-to-end client against that exact `.stflb`:

```sh
STOFFEL_RUN_BIN=target/release/stoffel-run \
STOFFEL_LOCAL_RUNNER_TEE=1 \
cargo run --release -p stoffel-rust-sdk --example dh_psi
```

The client implementation is
[`crates/stoffel-rust-sdk/examples/dh_psi.rs`](../../../stoffel-rust-sdk/examples/dh_psi.rs).
