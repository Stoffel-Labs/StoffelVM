# Private SHA-256 Client I/O

This example computes SHA-256 over exactly 32 secret bytes. Client 0 supplies
the 256 input bits as secret shares, all SHA-256 state stays secret throughout
the MPC computation, and eight packed 32-bit digest words are reconstructed only
by client 0 through `MpcOutput.send_to_client`. Compute parties see neither
plaintext nor digest; the public VM return is only the output word count (`8`).

The fixed message length is deliberate: it makes padding public, hides no
length-dependent control flow, and requires exactly one SHA-256 compression
block. For latency, the circuit uses minimum-depth Sklansky parallel-prefix
adders, carry-save state updates that avoid normalizing `T1`, fused round logic,
and wide `Share.batch_mul` calls. Message-schedule pairs are generated in the
otherwise-idle parallel lanes of the first 24 compression rounds, eliminating
their separate network path. The final state addition is specialized for the
public IV. Each party therefore executes exactly 965 multiplication batches and
no scalar multiplications, down from 1,254 batches. The compiler's exact
preprocessing manifest requests 78,520 triples (`dynamic: false`), which the
runtime rounds to its privacy band of 81,920.

```sh
stoffel build --release
STOFFEL_RUN_BIN=../../../../target/release/stoffel-run cargo run --release
```

From the repository root:

```sh
cargo build --release -p stoffel-vm-runner
STOFFEL_RUN_BIN=target/release/stoffel-run \
  cargo run --release --manifest-path crates/stoffel-lang/examples/mpc_sha256_client_io/Cargo.toml
```

The Rust client runs four fixed test vectors through the real five-party MPC
protocol: all-zero, incrementing, all-one, and ASCII inputs. Each result is
checked against a hard-coded digest (also sanity-checked with Rust's `sha2`),
and the harness prints per-vector and total wall time. Input and output use
normal hex strings in byte order; generated bindings perform the conversion
to/from little-endian secret bits within each byte. All 256 masked input bits
are submitted in one authenticated coordinator batch rather than 256 sequential
RPCs.

Set `SHA256_TEST_VECTOR` to one of the printed vector names, such as
`SHA256_TEST_VECTOR="all zeroes"`, to run a single-vector benchmark.

This is the optimized one-block primitive. Longer inputs should be exposed as
separate fixed-size entrypoints so message length remains an explicit public
parameter and the compiler can provision each circuit accurately.
