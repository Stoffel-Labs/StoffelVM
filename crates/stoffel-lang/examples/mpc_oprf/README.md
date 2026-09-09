# MPC Oblivious PRF (OPRF)

A client-blinded threshold OPRF over BLS12-381 G1. Five AVSS nodes jointly
hold the scalar key `k`; no node reconstructs it. AVSS Feldman commitments and
DLEQ proofs authenticate the partial exponent contributions before
interpolation.

The complete flow is:

1. The client uses the IETF-style BLS12-381 G1 hash-to-curve construction to
   compute `H(x)` and samples a fresh non-zero scalar `r`.
2. It submits the blinded point `P = r*H(x)`. The compressed point is packed
   into two 24-byte field limbs for the existing secret client-input channel.
3. On first use, the nodes jointly generate `k` and persist only their own key
   shares under the versioned key ID `oprf:bls12-381-g1:sk:v1`. Later runs load
   the same shares from each node's private local store.
4. Nodes batch-reconstruct only those uniformly blinded public points and use
   `Share.batch_open_exp_custom` to compute `k*P`. The key scalar is never
   opened.
5. The client multiplies the response by `r^-1` to obtain `k*H(x)` and applies
   a length-delimited SHA-256 `Finalize` step to produce the OPRF output.

The example sends two independently blinded copies of `alice@example.com` and
one `bob@example.com`. After unblinding, the client verifies that equal inputs
produce equal tags and the distinct input produces a distinct tag.

Build the full release workspace, the exact O3 bytecode, and the release client:

```sh
cargo build --workspace --release
target/release/stoffel build crates/stoffel-lang/examples/mpc_oprf --release
cargo build --release -p stoffel-rust-sdk --example oprf
```

Run the exact artifact through the release runner:

```sh
STOFFEL_RUN_BIN=target/release/stoffel-run \
STOFFEL_LOCAL_RUNNER_TEE=1 \
target/release/examples/oprf
```

The SDK's local runner gives each temporary node an isolated local store so the
example exercises first-use DKG and persistence encoding. A deployment must use
a durable, private `--local-store` path per stable node identity, provision the
key in a controlled first run, back up the shares, and coordinate key rotation.

Production deployments must also authenticate clients, enforce input and batch
limits, prevent replay where the application requires freshness, and deliver
responses only to the requesting client. This is a custom BLS12-381 suite, not
an RFC 9497 ciphersuite, and it has not received an independent cryptographic
audit.
