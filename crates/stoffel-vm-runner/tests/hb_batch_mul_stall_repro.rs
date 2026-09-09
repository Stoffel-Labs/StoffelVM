//! Minimal reproduction for the intermittent HoneyBadger online-multiply stall.
//!
//! Observed failure (5-party docker compose, `mpc_aes128_circuit`): preprocessing
//! completes cleanly, the post-preprocessing barrier passes, then the very first
//! `async_batch_multiply_share` makes zero progress and every party fails with
//! `MulError(Timeout([caller=8,exec_id=0,sub_id=0,round_id=0,...]))` after the
//! full 600 s protocol timeout. Nothing is logged by any party in between.
//!
//! This runs the *same program* the failure came from —
//! `examples/mpc_aes128_circuit/main.stfl`, which `docker-compose.yml` ships as
//! `mpc_aes128_circuit.stflb` — against real `stoffel-run` party processes, so
//! the real execution transport, inbox pump and QUIC mesh are exercised. (An
//! in-process harness would bypass the pump, which is the component the log
//! evidence puts under suspicion.) 5 parties / t=1 / HoneyBadger / bls12-381,
//! matching the deployment.
//!
//! Because the stall is rare, the test loops. AES is expensive, so there is also
//! a cheap proxy program selected with `STOFFEL_REPRO_PROGRAM=batchmul`: a single
//! `Share.batch_mul` sized to reproduce AES's *first* multiply exactly
//! (`groups=80`, `share_len = 160 % (t+1) = 0`, no RBC leg). The proxy iterates
//! ~8x faster but plans far less preprocessing, so prefer `aes` when hunting the
//! preprocessing -> online handoff and the proxy for raw iteration count.
//!
//! ```bash
//! # faithful: the real AES circuit (build --release; debug is far too slow)
//! STOFFEL_REPRO_ITERATIONS=100 \
//! STOFFEL_MPC_PROTOCOL_TIMEOUT_SECONDS=20 \
//! TOKIO_WORKER_THREADS=2 \
//! cargo test --release -p stoffel-vm-runner --test hb_batch_mul_stall_repro -- --ignored --nocapture
//!
//! # cheap proxy, higher iteration count
//! STOFFEL_REPRO_PROGRAM=batchmul STOFFEL_REPRO_ITERATIONS=500 \
//! STOFFEL_MPC_PROTOCOL_TIMEOUT_SECONDS=15 \
//! STOFFEL_HB_MUL_MAX_PAIRS_PER_SESSION=16 TOKIO_WORKER_THREADS=1 \
//! cargo test --release -p stoffel-vm-runner --test hb_batch_mul_stall_repro -- --ignored --nocapture
//! ```
//!
//! Knobs that matter, and why:
//!
//! * `STOFFEL_MPC_PROTOCOL_TIMEOUT_SECONDS` — the deployment default is 600 s,
//!   so one failing iteration costs ten minutes. At 20 s a failure is caught
//!   ~30x faster, which is what makes looping practical at all.
//! * `TOKIO_WORKER_THREADS` — the party's inbox pump is a spawned task while the
//!   VM runs on the main task. Under docker the five parties share a cgroup-
//!   limited host, so those tasks contend; a local run on many cores does not
//!   reproduce that. Pinning the parties to 1-2 workers restores the contention
//!   and is the highest-value knob if the pump is being starved or wedged.
//! * `STOFFEL_HB_MUL_MAX_PAIRS_PER_SESSION` — the engine awaits each chunk before
//!   starting the next, so lowering the cap splits one multiply session into
//!   several sequential ones: more exposures to the race per iteration.
//! * `STOFFEL_REPRO_BINARY=/path/to/mpc_aes128_circuit.stflb` — skip compilation
//!   and run the exact artifact from the docker image. The test otherwise
//!   compiles `main.stfl` with the same flags `Dockerfile` uses (`--opt-level 3`,
//!   unroll budgets at 100_000_000) and reproduces the deployment's
//!   `n_triples=36864` exactly, but the program hash still differs from the
//!   captured run (`145b5beb16d37625` vs `b16eb33848a4f510`), i.e. the image was
//!   built from a different commit of the compiler. Use this to rule that out.
//! * `STOFFEL_REPRO_DUMP_OUTPUT=1` — dump the party transcript on success too,
//!   which is where any pump instrumentation will show up.
//!
//! On failure the combined party output is printed.

use std::time::{Duration, Instant};

use stoffel_vm::net::{MpcBackendKind, MpcCurveConfig};
use stoffel_vm_runner::LocalCoordinatorRunner;

/// Default secret-pair multiplications issued in the single `Share.batch_mul`.
///
/// 160 reproduces the captured failure's wire shape exactly: `batch_recon` runs
/// with `groups = 160 / (t + 1) = 80` and `share_len = 160 % (t + 1) = 0`, so the
/// multiply is carried entirely by the two batched `batch_recon` sessions with
/// the RBC leg skipped.
///
/// This also sets preprocessing volume: the planner asks for one triple per
/// static multiply, so 160 pairs plans `n_triples=160` where the AES deployment
/// planned `n_triples=36864`. If the race lives in the preprocessing -> online
/// handoff, that 230x gap may matter — see `STOFFEL_REPRO_PAIRS`.
const DEFAULT_PAIRS: usize = 160;

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

/// One `Share.batch_mul` over `pairs` operands, then a single reveal.
///
/// `from_clear_int(_, 1)` makes these 1-bit shares, so the opened product of
/// `((pairs - 1) % 2) * 1` prints as `true` — matching the existing batch-mul e2e.
/// `pairs` is always even, so the last product is always 1.
fn program_source(pairs: usize) -> String {
    format!(
        r#"
def main() -> int64:
  var lefts: list[Share] = []
  var rights: list[Share] = []
  for i in 0..{pairs}:
    lefts.append(Share.from_clear_int(i % 2, 1))
    rights.append(Share.from_clear_int(1, 1))
  var products = Share.batch_mul(lefts, rights)
  return products[{last}].open()
"#,
        pairs = pairs,
        last = pairs - 1,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator and MPC party mesh; loops to catch a rare stall"]
async fn honeybadger_first_batch_multiply_does_not_stall() {
    // The faithful AES workload is suitable for release builds, but its 36,864
    // triples cannot finish inside the debug runner watchdog. The proxy reaches
    // the same first batch-multiply wire shape with 160 triples.
    let default_program = if cfg!(debug_assertions) {
        "batchmul"
    } else {
        "aes"
    };
    let program =
        std::env::var("STOFFEL_REPRO_PROGRAM").unwrap_or_else(|_| default_program.to_owned());
    // AES: the FIPS-197 known-answer ciphertext for the example's fixed
    // key/plaintext (69c4e0d8 6a7b0430 d8cdb780 70b4c55a). Proxy: the opened
    // product of the last pair, which is always 1 because `pairs` is even.
    let expected = match program.as_str() {
        "aes" => "[105, 196, 224, 216, 106, 123, 4, 48, 216, 205, 183, 128, 112, 180, 197, 90]",
        _ => "true",
    };
    let iterations = env_usize("STOFFEL_REPRO_ITERATIONS", 20);
    // Must stay even so `share_len = pairs % (t + 1)` is 0 and the RBC leg stays
    // out of the multiply, as in the captured failure.
    let pairs = env_usize("STOFFEL_REPRO_PAIRS", DEFAULT_PAIRS) & !1;
    assert!(pairs >= 2, "STOFFEL_REPRO_PAIRS must be >= 2");
    let run_timeout =
        Duration::from_secs(env_usize("STOFFEL_REPRO_RUN_TIMEOUT_SECONDS", 120) as u64);

    // Match how `Dockerfile` builds the deployed `mpc_aes128_circuit.stflb`:
    // `--opt-level 3` with STOFFEL_UNROLL_BUDGET / STOFFEL_UNROLL_MAX_EXPANSION
    // both at 100_000_000. -O3 restructures AES's round schedule (clustering
    // same-depth multiplies), so the *size of the first batch multiply* — the
    // operation that stalls — depends on this. Compiling at the default level
    // produces a different program hash and a different first multiply.
    let options = stoffellang::CompilerOptions {
        optimize: true,
        optimization_level: 3,
        unroll_budget: Some(100_000_000),
        unroll_max_expansion: Some(100_000_000),
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        ..Default::default()
    };
    // Strongest fidelity: run the exact artifact the deployment ran, bypassing
    // compiler drift entirely.
    //   docker cp <party-container>:/app/programs/mpc_aes128_circuit.stflb /tmp/
    //   STOFFEL_REPRO_BINARY=/tmp/mpc_aes128_circuit.stflb cargo test ...
    if let Ok(path) = std::env::var("STOFFEL_REPRO_BINARY") {
        let binary = stoffel_vm_types::compiled_binary::utils::load_from_file(&path)
            .unwrap_or_else(|error| panic!("load STOFFEL_REPRO_BINARY {path}: {error:?}"));
        eprintln!("repro: using prebuilt binary {path}");
        return run_iterations(binary, iterations, run_timeout, expected, &program, pairs).await;
    }

    let binary = match program.as_str() {
        // The program the captured failure actually ran.
        "aes" => {
            // Compiling the optimized AES circuit recurses deeply (the inlined
            // S-box network) and overflows the default test-thread stack, so do
            // it on a dedicated large-stack thread. `CompiledBinary` is `Send`,
            // so the result crosses back to this async context.
            std::thread::Builder::new()
                .stack_size(256 * 1024 * 1024)
                .spawn(move || {
                    let source =
                        include_str!("../../stoffel-lang/examples/mpc_aes128_circuit/main.stfl");
                    let compiled = stoffellang::compile(source, "<hb-aes-stall-repro>", &options)
                        .expect("compile AES circuit");
                    stoffellang::convert_to_binary(&compiled)
                })
                .expect("spawn AES compile thread")
                .join()
                .expect("AES compile thread panicked")
        }
        "batchmul" => {
            let compiled = stoffellang::compile(
                &program_source(pairs),
                "<hb-batch-mul-stall-repro>",
                &options,
            )
            .expect("compile batch mul proxy program");
            stoffellang::convert_to_binary(&compiled)
        }
        other => {
            panic!("unknown STOFFEL_REPRO_PROGRAM {other:?}: expected \"aes\" or \"batchmul\"")
        }
    };

    run_iterations(binary, iterations, run_timeout, expected, &program, pairs).await;
}

async fn run_iterations(
    binary: stoffel_vm_types::compiled_binary::CompiledBinary,
    iterations: usize,
    run_timeout: Duration,
    expected: &str,
    program: &str,
    pairs: usize,
) {
    eprintln!(
        "repro: program={program} {iterations} iterations, proxy_pairs={pairs}, \
         protocol_timeout={:?} mul_chunk={:?} tokio_workers={:?}",
        std::env::var("STOFFEL_MPC_PROTOCOL_TIMEOUT_SECONDS").ok(),
        std::env::var("STOFFEL_HB_MUL_MAX_PAIRS_PER_SESSION").ok(),
        std::env::var("TOKIO_WORKER_THREADS").ok(),
    );

    for iteration in 1..=iterations {
        let started = Instant::now();
        let output =
            LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary.clone())
                .parties(5)
                .threshold(1)
                .backend(MpcBackendKind::HoneyBadger)
                .curve(MpcCurveConfig::Bls12_381)
                .timeout(run_timeout)
                .build()
                .expect("local runner config")
                .run()
                .await;

        let elapsed = started.elapsed();

        let output = match output {
            Ok(output) => output,
            Err(error) => panic!(
                "iteration {iteration}/{iterations} failed after {elapsed:?}: {error}\n\
                 (a `MulError(Timeout([caller=8,...,round_id=0,...]))` here is the stall \
                 under investigation)"
            ),
        };

        // The stall surfaces as a per-party execution error rather than a runner
        // error, so check the transcript explicitly instead of trusting the exit.
        assert!(
            !output.combined_output.contains("MulError(Timeout"),
            "iteration {iteration}/{iterations} hit the multiply stall after {elapsed:?}:\n{}",
            output.combined_output
        );

        let values = output.consistent_returned_values().unwrap_or_else(|error| {
            panic!(
                "iteration {iteration}/{iterations} produced divergent party results \
                     after {elapsed:?}: {error}\n{}",
                output.combined_output
            )
        });
        assert_eq!(
            values,
            vec![expected],
            "iteration {iteration}/{iterations} returned the wrong value after {elapsed:?}"
        );

        if std::env::var("STOFFEL_REPRO_DUMP_OUTPUT").is_ok() {
            eprintln!("{}", output.combined_output);
        }

        eprintln!("repro: iteration {iteration}/{iterations} ok in {elapsed:?}");
    }
}
