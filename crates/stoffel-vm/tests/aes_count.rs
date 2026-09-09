use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use stoffel_vm::core_vm::VirtualMachine;
use stoffel_vm::net::mpc_engine::{
    MpcCapabilities, MpcEngine, MpcEngineMultiplication, MpcEngineResult, MpcSessionTopology,
    ShareAlgebraResult,
};
use stoffel_vm_types::core_types::{
    ClearShareInput, ClearShareValue, ShareData, ShareType, TableRef, Value,
};

#[derive(Default)]
struct CountingEngine {
    scalar_mul_calls: AtomicUsize,
    batch_mul_calls: AtomicUsize,
    batch_mul_items: AtomicUsize,
    // === Lever-B / depth instrumentation (measurement only) ===
    // public_operand_muls: number of individual multiply PAIRS executed whose
    // value (the round-charging `ab` term) has at least one operand that traces
    // back to a compile-time public literal (`Share.from_clear_int` / a literal
    // vector) through only LOCAL ops (never through a prior multiply). These are
    // exactly the `bits_xor` (secret⊕public) and constant-fold multiplies that
    // lever B could turn into a local `mul_scalar`, so this is lever B's headroom.
    public_operand_muls: AtomicUsize,
    // both_public_muls: subset where BOTH operands are public literals (the
    // multiply is fully constant-foldable, not just lever-B-local).
    both_public_muls: AtomicUsize,
    // max_mul_depth: critical-path multiply depth = the theoretical round floor
    // with perfect batching. A share's depth is the number of multiplies on the
    // longest data-dependency path from inputs; a multiply output is
    // max(operand depths)+1, local ops keep the max, inputs are depth 0.
    max_mul_depth: AtomicUsize,
    // === Per-depth histogram instrumentation (measurement only) ===
    // call_seq: monotonically allocated id per multiply ROUND (one scalar call or
    // one batch call). pair_log: one row per multiply pair executed, tagging the
    // round it ran in, the output depth, and whether it had a public operand.
    call_seq: AtomicUsize,
    pair_log: std::sync::Mutex<Vec<PairRecord>>,
}

/// One executed multiply pair, for the per-depth round histogram.
#[derive(Clone, Copy)]
struct PairRecord {
    /// Round id (one per scalar multiply call or per batch_multiply call).
    call_id: u32,
    /// Output (critical-path) depth of this pair: max(operand depths)+1.
    depth: u32,
    /// At least one operand traces to a public literal through only local ops.
    pub_operand: bool,
    /// Both operands public (fully constant-foldable).
    both_public: bool,
}

impl CountingEngine {
    fn counts(&self) -> (usize, usize, usize) {
        (
            self.scalar_mul_calls.load(Ordering::SeqCst),
            self.batch_mul_calls.load(Ordering::SeqCst),
            self.batch_mul_items.load(Ordering::SeqCst),
        )
    }

    /// (public_operand_muls, both_public_muls, max_mul_depth) — see field docs.
    fn lever_b_counts(&self) -> (usize, usize, usize) {
        (
            self.public_operand_muls.load(Ordering::SeqCst),
            self.both_public_muls.load(Ordering::SeqCst),
            self.max_mul_depth.load(Ordering::SeqCst),
        )
    }

    /// Snapshot of every executed multiply pair (for the per-depth histogram).
    fn pair_log_snapshot(&self) -> Vec<PairRecord> {
        self.pair_log.lock().map(|l| l.clone()).unwrap_or_default()
    }

    fn bool_byte(bytes: &[u8]) -> u8 {
        bytes.first().copied().unwrap_or_default() & 1
    }

    // --- Share metadata layout -------------------------------------------------
    // Every share this engine emits is `[value, public, d0, d1, d2, d3]`:
    //   byte 0      : the GF(2) value bit (read by `bool_byte`, unchanged).
    //   byte 1      : public-literal taint flag (1 = traces to a literal through
    //                 only local ops).
    //   bytes 2..6  : critical-path multiply depth as u32 little-endian.
    // Legacy 1-byte shares (e.g. raw client inputs) decode as public=false,
    // depth=0, which is the correct default for a secret input.
    fn pack(value: u8, public: bool, depth: u32) -> Vec<u8> {
        let d = depth.to_le_bytes();
        vec![value & 1, u8::from(public), d[0], d[1], d[2], d[3]]
    }

    fn is_public(bytes: &[u8]) -> bool {
        bytes.get(1).copied().unwrap_or(0) != 0
    }

    fn depth_of(bytes: &[u8]) -> u32 {
        if bytes.len() >= 6 {
            u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]])
        } else {
            0
        }
    }

    /// Execute one secret multiply `ab`: compute its value, record lever-B and
    /// depth instrumentation, and return packed metadata for the product (a
    /// product is never a public literal). Shared by scalar/async/batch paths.
    fn record_multiply(&self, call_id: u32, left: &[u8], right: &[u8]) -> Vec<u8> {
        let value = Self::bool_byte(left) & Self::bool_byte(right);
        let out_depth = Self::depth_of(left).max(Self::depth_of(right)) + 1;
        self.max_mul_depth
            .fetch_max(out_depth as usize, Ordering::SeqCst);
        let left_pub = Self::is_public(left);
        let right_pub = Self::is_public(right);
        if left_pub || right_pub {
            self.public_operand_muls.fetch_add(1, Ordering::SeqCst);
        }
        if left_pub && right_pub {
            self.both_public_muls.fetch_add(1, Ordering::SeqCst);
        }
        if let Ok(mut log) = self.pair_log.lock() {
            log.push(PairRecord {
                call_id,
                depth: out_depth,
                pub_operand: left_pub || right_pub,
                both_public: left_pub && right_pub,
            });
        }
        Self::pack(value, false, out_depth)
    }

    /// Allocate a fresh round id for one multiply call (scalar or batch).
    fn next_call_id(&self) -> u32 {
        self.call_seq.fetch_add(1, Ordering::SeqCst) as u32
    }

    fn share_from_clear(clear: ClearShareInput) -> ShareData {
        let byte = match clear.value() {
            ClearShareValue::Integer(value) => (value & 1) as u8,
            ClearShareValue::UnsignedInteger(value) => (value & 1) as u8,
            ClearShareValue::FixedPoint(value) => ((value.0 as i64) & 1) as u8,
            ClearShareValue::Boolean(value) => u8::from(value),
        };
        // A `from_clear` value is a compile-time public literal: public=true, depth 0.
        ShareData::Opaque(Self::pack(byte, true, 0).into())
    }

    fn open_bool(share_bytes: &[u8]) -> ClearShareValue {
        ClearShareValue::Boolean(Self::bool_byte(share_bytes) != 0)
    }
}

impl MpcEngine for CountingEngine {
    fn protocol_name(&self) -> &'static str {
        "counting"
    }

    fn topology(&self) -> MpcSessionTopology {
        MpcSessionTopology::try_new(1, 0, 1, 0).expect("valid counting topology")
    }

    fn is_ready(&self) -> bool {
        true
    }

    fn start(&self) -> MpcEngineResult<()> {
        Ok(())
    }

    fn input_share(&self, clear: ClearShareInput) -> MpcEngineResult<ShareData> {
        Ok(Self::share_from_clear(clear))
    }

    fn open_share(&self, _ty: ShareType, share_bytes: &[u8]) -> MpcEngineResult<ClearShareValue> {
        Ok(Self::open_bool(share_bytes))
    }

    fn capabilities(&self) -> MpcCapabilities {
        MpcCapabilities::MULTIPLICATION
    }

    fn as_multiplication(&self) -> Option<&dyn MpcEngineMultiplication> {
        Some(self)
    }

    fn add_share_local(
        &self,
        _ty: ShareType,
        lhs_bytes: &[u8],
        rhs_bytes: &[u8],
    ) -> ShareAlgebraResult<Vec<u8>> {
        // Local linear op: public iff both operands public; depth = max of inputs.
        let value = Self::bool_byte(lhs_bytes) ^ Self::bool_byte(rhs_bytes);
        let public = Self::is_public(lhs_bytes) && Self::is_public(rhs_bytes);
        let depth = Self::depth_of(lhs_bytes).max(Self::depth_of(rhs_bytes));
        Ok(Self::pack(value, public, depth))
    }

    fn sub_share_local(
        &self,
        _ty: ShareType,
        lhs_bytes: &[u8],
        rhs_bytes: &[u8],
    ) -> ShareAlgebraResult<Vec<u8>> {
        let value = Self::bool_byte(lhs_bytes) ^ Self::bool_byte(rhs_bytes);
        let public = Self::is_public(lhs_bytes) && Self::is_public(rhs_bytes);
        let depth = Self::depth_of(lhs_bytes).max(Self::depth_of(rhs_bytes));
        Ok(Self::pack(value, public, depth))
    }

    fn neg_share_local(&self, _ty: ShareType, share_bytes: &[u8]) -> ShareAlgebraResult<Vec<u8>> {
        // GF(2) negation == identity on the value; metadata is preserved.
        Ok(Self::pack(
            Self::bool_byte(share_bytes),
            Self::is_public(share_bytes),
            Self::depth_of(share_bytes),
        ))
    }

    fn mul_share_scalar_local(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> ShareAlgebraResult<Vec<u8>> {
        // Scalar (public constant) factor: keeps publicness and depth of the share.
        let value = Self::bool_byte(share_bytes) & ((scalar & 1) as u8);
        Ok(Self::pack(
            value,
            Self::is_public(share_bytes),
            Self::depth_of(share_bytes),
        ))
    }

    fn add_share_scalar_local(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> ShareAlgebraResult<Vec<u8>> {
        let value = Self::bool_byte(share_bytes) ^ ((scalar & 1) as u8);
        Ok(Self::pack(
            value,
            Self::is_public(share_bytes),
            Self::depth_of(share_bytes),
        ))
    }

    fn sub_share_scalar_local(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> ShareAlgebraResult<Vec<u8>> {
        let value = Self::bool_byte(share_bytes) ^ ((scalar & 1) as u8);
        Ok(Self::pack(
            value,
            Self::is_public(share_bytes),
            Self::depth_of(share_bytes),
        ))
    }

    fn scalar_sub_share_local(
        &self,
        _ty: ShareType,
        scalar: i64,
        share_bytes: &[u8],
    ) -> ShareAlgebraResult<Vec<u8>> {
        let value = ((scalar & 1) as u8) ^ Self::bool_byte(share_bytes);
        Ok(Self::pack(
            value,
            Self::is_public(share_bytes),
            Self::depth_of(share_bytes),
        ))
    }

    fn div_share_scalar_local(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> ShareAlgebraResult<Vec<u8>> {
        assert_ne!(scalar & 1, 0, "division by zero in GF(2)");
        Ok(Self::pack(
            Self::bool_byte(share_bytes),
            Self::is_public(share_bytes),
            Self::depth_of(share_bytes),
        ))
    }
}

impl MpcEngineMultiplication for CountingEngine {
    fn multiply_share(
        &self,
        _ty: ShareType,
        left: &[u8],
        right: &[u8],
    ) -> MpcEngineResult<ShareData> {
        self.scalar_mul_calls.fetch_add(1, Ordering::SeqCst);
        let call_id = self.next_call_id();
        Ok(ShareData::Opaque(
            self.record_multiply(call_id, left, right).into(),
        ))
    }
}

#[async_trait::async_trait]
impl stoffel_vm::net::mpc_engine::AsyncMpcEngine for CountingEngine {
    async fn input_share_async(&self, clear: ClearShareInput) -> MpcEngineResult<ShareData> {
        Ok(Self::share_from_clear(clear))
    }

    async fn multiply_share_async(
        &self,
        _ty: ShareType,
        left: &[u8],
        right: &[u8],
    ) -> MpcEngineResult<ShareData> {
        self.scalar_mul_calls.fetch_add(1, Ordering::SeqCst);
        let call_id = self.next_call_id();
        Ok(ShareData::Opaque(
            self.record_multiply(call_id, left, right).into(),
        ))
    }

    async fn batch_multiply_share_async(
        &self,
        _ty: ShareType,
        pairs: &[(Vec<u8>, Vec<u8>)],
    ) -> MpcEngineResult<Vec<ShareData>> {
        self.batch_mul_calls.fetch_add(1, Ordering::SeqCst);
        self.batch_mul_items
            .fetch_add(pairs.len(), Ordering::SeqCst);
        let call_id = self.next_call_id();
        Ok(pairs
            .iter()
            .map(|(left, right)| {
                ShareData::Opaque(self.record_multiply(call_id, left, right).into())
            })
            .collect())
    }

    async fn open_share_async(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
    ) -> MpcEngineResult<ClearShareValue> {
        Ok(Self::open_bool(share_bytes))
    }

    async fn batch_open_shares_async(
        &self,
        _ty: ShareType,
        shares: &[Vec<u8>],
    ) -> MpcEngineResult<Vec<ClearShareValue>> {
        Ok(shares.iter().map(|share| Self::open_bool(share)).collect())
    }

    async fn random_share_async(&self, _ty: ShareType) -> MpcEngineResult<ShareData> {
        Ok(ShareData::Opaque(vec![0].into()))
    }

    async fn random_integer_share_async(&self, _ty: ShareType) -> MpcEngineResult<ShareData> {
        Ok(ShareData::Opaque(vec![0].into()))
    }
}

/// Compiling and executing the optimized AES circuit recurses deeply (the
/// inlined S-box network and the VM interpreter), which overflows the default
/// ~2 MB cargo/tokio test-thread stack on some platforms. Run the work on a
/// dedicated large-stack thread with its own runtime.
fn run_on_large_stack<F>(future: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(256 * 1024 * 1024)
                .enable_all()
                .build()
                .expect("build tokio runtime")
                .block_on(future);
        })
        .expect("spawn large-stack test thread")
        .join()
        .expect("large-stack test thread panicked");
}

/// Regression test for the -O3 function inliner: a `secret`-typed helper that is
/// inlined must keep its arguments secret, so the secret `and`/multiply still runs
/// as an MPC multiplication (counted in `batch`/`scalar`) rather than collapsing
/// to a clear bitwise op. We compile the same secret program at -O0 and -O3 and
/// require (a) the revealed result is identical and (b) -O3 still performs a real
/// secret multiplication (a non-zero multiply count) — i.e. secrecy survived
/// inlining. If inlining dropped the secret flag, the `and` would compile to a
/// clear op and the multiply count would drop to zero.
#[test]
fn inlining_preserves_secret_multiplication() {
    run_on_large_stack(inlining_preserves_secret_multiplication_impl());
}

async fn inlining_preserves_secret_multiplication_impl() {
    // `gate_and` is a secret-bool helper (an MPC multiply in GF(2)); `combine`
    // chains two of them so inlining has something to fold. Client shares are
    // deliberately used instead of public `from_clear_int` values: public
    // constants are now correctly localized and would make this secrecy test
    // vacuous for the opposite reason.
    let source = r#"
def gate_and(a: secret bool, b: secret bool) -> secret bool:
  return a and b

def combine(a: secret bool, b: secret bool, c: secret bool) -> secret bool:
  return gate_and(gate_and(a, b), c)

def main() -> int64:
  var x: secret bool = ClientStore.take_share_bool(0, 0)
  var y: secret bool = ClientStore.take_share_bool(0, 1)
  var z: secret bool = ClientStore.take_share_bool(0, 2)
  var w: secret bool = combine(x, y, z)
  var r: bool = w.reveal()
  if r:
    return 1
  return 0
"#;

    let run_at = |level: u8| async move {
        let options = stoffellang::CompilerOptions {
            optimize: true,
            optimization_level: level,
            mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
            ..Default::default()
        };
        let compiled = stoffellang::compile(source, "<inline-secrecy>", &options)
            .unwrap_or_else(|e| panic!("compile at -O{level}: {e:?}"));
        let binary = stoffellang::convert_to_binary(&compiled);
        let functions = binary.try_to_vm_functions().expect("vm functions");
        let engine = Arc::new(CountingEngine::default());
        let mut vm = VirtualMachine::builder()
            .with_mpc_engine(engine.clone())
            .build();
        vm.store_client_shares(0, bits_as_bool_shares(&[0b0000_0111]));
        for function in functions {
            vm.try_register_function(function)
                .expect("register function");
        }
        let result = vm
            .execute_async("main", engine.as_ref())
            .await
            .unwrap_or_else(|e| panic!("execute at -O{level}: {e:?}"));
        let (scalar, _batch_calls, batch_items) = engine.counts();
        (result, scalar + batch_items)
    };

    let (base_result, base_muls) = run_at(0).await;
    let (opt_result, opt_muls) = run_at(3).await;

    assert_eq!(
        base_result, opt_result,
        "-O3 inlining changed the revealed secret result"
    );
    assert!(
        base_muls > 0,
        "baseline should perform secret multiplications (test would be vacuous otherwise)"
    );
    assert!(
        opt_muls > 0,
        "-O3 inlined `gate_and` lost its secret typing: the secret `and` compiled \
         to a clear op (zero MPC multiplications), which is the secrecy bug"
    );
}

#[test]
#[ignore = "counts optimized AES MPC multiplication demand"]
fn count_optimized_aes_batch_mul_items() {
    run_on_large_stack(count_optimized_aes_batch_mul_items_impl());
}

async fn count_optimized_aes_batch_mul_items_impl() {
    let source = include_str!("../../stoffel-lang/examples/mpc_aes128_circuit/main.stfl");
    let options = stoffellang::CompilerOptions {
        optimize: true,
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<aes-count>", &options).expect("compile AES");
    let binary = stoffellang::convert_to_binary(&compiled);
    let functions = binary.try_to_vm_functions().expect("vm functions");

    let engine = Arc::new(CountingEngine::default());
    let mut vm = VirtualMachine::builder()
        .with_mpc_engine(engine.clone())
        .build();
    for function in functions {
        vm.try_register_function(function)
            .expect("register function");
    }

    let _ = vm
        .execute_async("main", engine.as_ref())
        .await
        .expect("execute AES with counting engine");
    let (scalar, batch_calls, batch_items) = engine.counts();
    // The optimizer must convert EVERY secret multiplication into a batched one
    // (no leftover scalar `multiply_share` calls) and preserve the exact total
    // number of products — these are the real correctness invariants.
    assert_eq!(
        scalar, 0,
        "optimizer should batch every secret multiply; {scalar} ran as scalar"
    );
    assert_eq!(batch_items, 34_080);
    // This test compiles at the default optimization level (no -O3), so the
    // per-byte S-box loops are not unrolled and the round-minimizing scheduler
    // does not run. At this level the optimizer batches independent multiplies
    // only WITHIN each byte's S-box, yielding many smaller batches (~6.3k). At
    // -O3 (see `optimized_aes_at_o3_matches_nist_vector`) length-aware unrolling
    // plus the list scheduler batch across the formerly-separate iterations and
    // cut this to a few thousand rounds. The meaningful guarantee here is just
    // that batching still collapses the ~34k multiplies into far fewer calls.
    assert!(
        batch_calls < batch_items / 4,
        "multiplies should be meaningfully batched, not near one-call-each; \
         got {batch_calls} calls for {batch_items} items"
    );
}

#[test]
fn optimized_aes_matches_nist_vector_with_compiler_spills() {
    run_on_large_stack(optimized_aes_matches_nist_vector_with_compiler_spills_impl());
}

async fn optimized_aes_matches_nist_vector_with_compiler_spills_impl() {
    let source = include_str!("../../stoffel-lang/examples/mpc_aes128_circuit/main.stfl");
    let options = stoffellang::CompilerOptions {
        optimize: true,
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<aes-exec>", &options).expect("compile AES");
    let binary = stoffellang::convert_to_binary(&compiled);
    let functions = binary.try_to_vm_functions().expect("vm functions");

    let engine = Arc::new(CountingEngine::default());
    let mut vm = VirtualMachine::builder()
        .with_mpc_engine(engine.clone())
        .build();
    for function in functions {
        vm.try_register_function(function)
            .expect("register function");
    }

    let result = vm
        .execute_async("main", engine.as_ref())
        .await
        .expect("execute AES with boolean engine");
    let Value::Array(result_ref) = result else {
        panic!("AES main should return an array");
    };

    let mut ciphertext = Vec::new();
    for index in 0..vm.read_array_len(result_ref).expect("ciphertext length") {
        let value = vm
            .read_table_field(TableRef::from(result_ref), &Value::I64(index as i64))
            .expect("read ciphertext byte")
            .expect("ciphertext byte");
        let Value::I64(byte) = value else {
            panic!("ciphertext byte should be an int64, got {value:?}");
        };
        ciphertext.push(byte);
    }

    assert_eq!(
        ciphertext,
        vec![105, 196, 224, 216, 106, 123, 4, 48, 216, 205, 183, 128, 112, 180, 197, 90]
    );
}

/// Regression test for the ABI-result-register spill bug: at -O3, function
/// inlining turns `aes128_encrypt` into a large zero-parameter function full of
/// `CALL; MOV(dest, 0)` result captures. Register 0 (the ABI result register) has
/// no virtual-register def, so before the fix the allocator spilled it and emitted
/// `LDS` loads with no `STS` — reading an uninitialized `Unit` and failing in a
/// clear/secret conversion (`UnsupportedClearShareValue { value: () }`). Pinning
/// VR0 to physical R0 keeps the result register live and unspilled. This runs the
/// full AES circuit at -O3 (heavy inlining + spilling) and requires the NIST
/// SP 800-38A vector, proving the -O3 pipeline is now both crash-free and correct.
#[test]
fn optimized_aes_at_o3_matches_nist_vector() {
    run_on_large_stack(optimized_aes_at_o3_matches_nist_vector_impl());
}

async fn optimized_aes_at_o3_matches_nist_vector_impl() {
    let source = include_str!("../../stoffel-lang/examples/mpc_aes128_circuit/main.stfl");
    let options = stoffellang::CompilerOptions {
        optimize: true,
        optimization_level: 3,
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<aes-o3>", &options).expect("compile AES at -O3");
    let binary = stoffellang::convert_to_binary(&compiled);
    let functions = binary.try_to_vm_functions().expect("vm functions");

    let engine = Arc::new(CountingEngine::default());
    let mut vm = VirtualMachine::builder()
        .with_mpc_engine(engine.clone())
        .build();
    for function in functions {
        vm.try_register_function(function)
            .expect("register function");
    }

    let result = vm
        .execute_async("main", engine.as_ref())
        .await
        .expect("execute AES at -O3");
    let Value::Array(result_ref) = result else {
        panic!("AES main should return an array");
    };

    let mut ciphertext = Vec::new();
    for index in 0..vm.read_array_len(result_ref).expect("ciphertext length") {
        let value = vm
            .read_table_field(TableRef::from(result_ref), &Value::I64(index as i64))
            .expect("read ciphertext byte")
            .expect("ciphertext byte");
        let Value::I64(byte) = value else {
            panic!("ciphertext byte should be an int64, got {value:?}");
        };
        ciphertext.push(byte);
    }

    assert_eq!(
        ciphertext,
        vec![105, 196, 224, 216, 106, 123, 4, 48, 216, 205, 183, 128, 112, 180, 197, 90]
    );

    // The -O3 pipeline (length-aware unrolling + the round-minimizing list
    // scheduler) collapses the ~34k secret multiplies into far fewer
    // communication rounds than the unscheduled build (which needed ~25.7k
    // batch calls). Lock in the round reduction without over-fitting the exact
    // number: it must be well under the -O0 baseline (~6.3k) and the total work
    // and scalar-free invariants must hold.
    let (scalar, batch_calls, batch_items) = engine.counts();
    assert_eq!(scalar, 0, "every secret multiply must be batched at -O3");
    // One proof-driven peel establishes the state shape, then the recurrence-
    // aware unroller keeps the residual rounds rolled. That exposes additional
    // provably-local gates without replicating the full round body: 33,280
    // products remain interactive and are coalesced into 219 calls.
    assert_eq!(
        batch_items, 33_280,
        "interactive product count must match the optimized circuit"
    );
    assert!(
        batch_calls <= 225,
        "scheduler/fixpoint should stay near the 206-round dependency floor; \
         got {batch_calls} rounds"
    );
}

/// Regression for the cross-compile optimizer-budget leak.
///
/// The inline/unroll budgets used to be read from process-global environment
/// variables inside the optimizer. In a process that compiles more than once
/// (e.g. the parallel test runner), a sibling compile that raised those budgets
/// to flatten its program leaked the full-unroll regime into every other
/// compile — pushing this AES-O3 build into the known-buggy full-unroll path,
/// which crashes at runtime with
/// `get_field: array index 0 out of range (length 0)`.
///
/// Budgets are now threaded per-compile via `CompilerOptions`, so this ordering
/// — a heavy full-unroll compile immediately followed by a *default*-budget
/// AES-O3 compile in the same process/thread — must leave AES-O3 in its correct
/// rolled regime and still match the NIST vector.
#[test]
fn repro_aes_o3_double_compile() {
    run_on_large_stack(async move {
        // 1. A sibling compile that opts into the full-unroll regime via
        //    hermetic per-compile budgets (previously: leaking env vars). The
        //    literal-bound loop ensures the raised unroll budget is exercised.
        let sibling_src = "def main() -> int64:\n  var acc = 0\n  for i in 0..64:\n    acc = acc + i\n  return acc\n";
        let sibling_options = stoffellang::CompilerOptions {
            optimize: true,
            optimization_level: 3,
            mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
            inline_budget: Some(100_000_000),
            unroll_budget: Some(100_000_000),
            unroll_max_expansion: Some(100_000_000),
            ..Default::default()
        };
        stoffellang::compile(sibling_src, "<sibling-full-unroll>", &sibling_options)
            .expect("sibling full-unroll compile");

        // 2. AES at -O3 with DEFAULT budgets, in the same process/thread. If the
        //    sibling's budgets leaked, this would full-unroll and crash; instead
        //    it must reproduce the exact NIST ciphertext (asserted by the impl).
        optimized_aes_at_o3_matches_nist_vector_impl().await;
    });
}

/// Full-optimization path: with the unroll/inline budgets raised so the whole
/// circuit is flattened, the round-minimizing scheduler collapses the ~34k secret
/// multiplies into only a few hundred `batch_mul` communication rounds — a ~60x
/// reduction from the unscheduled ~25.7k. Ignored by default because flattening
/// AES is heavy in a debug build (~60s compile); run explicitly, ideally in
/// release:
///   STOFFEL_UNROLL_BUDGET=100000000 STOFFEL_UNROLL_MAX_EXPANSION=100000000 \
///   STOFFEL_INLINE_BUDGET=100000000 cargo test --release -p stoffel-vm \
///   --test aes_count optimized_aes_full_unroll_minimizes_rounds -- --ignored
#[test]
#[ignore]
fn optimized_aes_full_unroll_minimizes_rounds() {
    run_on_large_stack(async move {
        let source = include_str!("../../stoffel-lang/examples/mpc_aes128_circuit/main.stfl");
        // Full-unroll budgets are passed hermetically via CompilerOptions rather
        // than process-global env vars, so this heavy run can't pollute any
        // concurrent compile in the same test process.
        let options = stoffellang::CompilerOptions {
            optimize: true,
            optimization_level: 3,
            mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
            inline_budget: Some(100_000_000),
            unroll_budget: Some(100_000_000),
            unroll_max_expansion: Some(100_000_000),
            ..Default::default()
        };
        let compiled = stoffellang::compile(source, "<m>", &options).expect("compile");
        let binary = stoffellang::convert_to_binary(&compiled);
        let functions = binary.try_to_vm_functions().expect("fns");
        let engine = std::sync::Arc::new(CountingEngine::default());
        let mut vm = VirtualMachine::builder()
            .with_mpc_engine(engine.clone())
            .build();
        for f in functions {
            vm.try_register_function(f).expect("reg");
        }
        let result = vm
            .execute_async("main", engine.as_ref())
            .await
            .expect("exec");
        // Correct ciphertext (NIST AES-128 test vector).
        let Value::Array(result_ref) = result else {
            panic!("AES main should return an array");
        };
        let mut ciphertext = Vec::new();
        for index in 0..vm.read_array_len(result_ref).expect("len") {
            let value = vm
                .read_table_field(TableRef::from(result_ref), &Value::I64(index as i64))
                .expect("read")
                .expect("byte");
            let Value::I64(byte) = value else {
                panic!("byte")
            };
            ciphertext.push(byte);
        }
        assert_eq!(
            ciphertext,
            vec![105, 196, 224, 216, 106, 123, 4, 48, 216, 205, 183, 128, 112, 180, 197, 90]
        );
        let (scalar, batch_calls, batch_items) = engine.counts();
        assert_eq!(scalar, 0);
        // Full flattening changes the communication schedule, not the optimized
        // circuit's interactive product count.
        assert_eq!(batch_items, 33_280);
        assert!(
            batch_calls < 1_000,
            "fully-flattened AES should reach a few hundred multiply rounds; got {batch_calls}"
        );
    });
}

/// Regression for a loop-carried-state mis-optimization when a function with a
/// reassigned (loop-carried) local is inlined more than once. CTR's keystream
/// inlines `aes128_encrypt_rk` (loop-carried `state`) twice — once per block —
/// and at -O3 once produced a wrong block-1 result (C1 != NIST). The single-block
/// AES circuit inlines it only once and was unaffected. This calls a small
/// loop-carried folder twice with distinct inputs and requires -O3 to match -O0.
#[test]
fn loop_carried_state_inlined_twice_o3_matches_o0() {
    run_on_large_stack(loop_carried_state_inlined_twice_o3_matches_o0_impl());
}

async fn loop_carried_state_inlined_twice_o3_matches_o0_impl() {
    let source = r#"
def gate_xor(a: secret bool, b: secret bool) -> secret bool:
  return a xor b

# Loop-carried fold: `result` is reassigned each iteration.
def fold(bits: list[secret bool]) -> secret bool:
  var result: secret bool = Share.from_clear_int(0, 1)
  for i in 0..bits.len():
    result = gate_xor(result, bits[i])
  return result

def main() -> list[int64]:
  # Two INDEPENDENT folds with distinct inputs and distinct results, so a
  # cross-inline collision on `result` is detectable. fold([1,0,0,0]) = 1,
  # fold([0,0,0,0]) = 0.
  var r0 = fold([Share.from_clear_int(1, 1), Share.from_clear_int(0, 1), Share.from_clear_int(0, 1), Share.from_clear_int(0, 1)])
  var r1 = fold([Share.from_clear_int(0, 1), Share.from_clear_int(0, 1), Share.from_clear_int(0, 1), Share.from_clear_int(0, 1)])
  var out: list[int64] = []
  var b0: bool = r0.reveal()
  var b1: bool = r1.reveal()
  if b0:
    out.append(1)
  else:
    out.append(0)
  if b1:
    out.append(1)
  else:
    out.append(0)
  return out
"#;

    let run_at = |level: u8| async move {
        let options = stoffellang::CompilerOptions {
            optimize: level > 0,
            optimization_level: level,
            mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
            ..Default::default()
        };
        let compiled = stoffellang::compile(source, "<fold>", &options)
            .unwrap_or_else(|e| panic!("compile at -O{level}: {e:?}"));
        let binary = stoffellang::convert_to_binary(&compiled);
        let functions = binary.try_to_vm_functions().expect("vm functions");
        let engine = Arc::new(CountingEngine::default());
        let mut vm = VirtualMachine::builder()
            .with_mpc_engine(engine.clone())
            .build();
        for function in functions {
            vm.try_register_function(function)
                .expect("register function");
        }
        let result = vm
            .execute_async("main", engine.as_ref())
            .await
            .unwrap_or_else(|e| panic!("execute at -O{level}: {e:?}"));
        let Value::Array(result_ref) = result else {
            panic!("fold main should return an array");
        };
        let mut bits = Vec::new();
        for index in 0..vm.read_array_len(result_ref).expect("len") {
            let value = vm
                .read_table_field(TableRef::from(result_ref), &Value::I64(index as i64))
                .expect("read bit")
                .expect("bit");
            let Value::I64(b) = value else {
                panic!("bit should be int64, got {value:?}");
            };
            bits.push(b);
        }
        bits
    };

    let expected = vec![1, 0]; // fold([1,0,0,0])=1, fold([0,0,0,0])=0
    let o0 = run_at(0).await;
    let o3 = run_at(3).await;
    assert_eq!(o0, expected, "-O0 fold must be correct");
    assert_eq!(
        o3, expected,
        "-O3 must match -O0 when a loop-carried-state function is inlined twice"
    );
}

/// Differential test for the CTR -O3 full-unroll correctness bug using the
/// reduced counter-increment reproducer. The original AES CTR failure presented
/// as a wrong C1 block; shrinking showed the counter increment itself diverged
/// under -O3 inlining/unrolling/scheduling.
#[test]
fn ctr_full_unroll_c1_matches_o0() {
    run_on_large_stack(ctr_full_unroll_c1_matches_o0_impl());
}

async fn ctr_full_unroll_c1_matches_o0_impl() {
    let base = r#"
def gate_and(a: secret bool, b: secret bool) -> secret bool:
  return a and b

def gate_xor(a: secret bool, b: secret bool) -> secret bool:
  return a xor b

def reveal_byte(byte: list[secret bool]) -> int64:
  var value: int64 = 0
  var b0: bool = byte[0].reveal()
  if b0:
    value += 1
  var b1: bool = byte[1].reveal()
  if b1:
    value += 2
  var b2: bool = byte[2].reveal()
  if b2:
    value += 4
  var b3: bool = byte[3].reveal()
  if b3:
    value += 8
  var b4: bool = byte[4].reveal()
  if b4:
    value += 16
  var b5: bool = byte[5].reveal()
  if b5:
    value += 32
  var b6: bool = byte[6].reveal()
  if b6:
    value += 64
  var b7: bool = byte[7].reveal()
  if b7:
    value += 128
  return value

def reveal_block(block: list[list[secret bool]]) -> list[int64]:
  return [reveal_byte(block[0]), reveal_byte(block[1]), reveal_byte(block[2]), reveal_byte(block[3]), reveal_byte(block[4]), reveal_byte(block[5]), reveal_byte(block[6]), reveal_byte(block[7]), reveal_byte(block[8]), reveal_byte(block[9]), reveal_byte(block[10]), reveal_byte(block[11]), reveal_byte(block[12]), reveal_byte(block[13]), reveal_byte(block[14]), reveal_byte(block[15])]

def public_byte(value: int64) -> list[secret bool]:
  var bits: list[secret bool] = []
  var v: int64 = value
  for i in 0..8:
    bits.append(Share.from_clear_int(v % 2, 1))
    v = v / 2
  return bits

def public_block(values: list[int64]) -> list[list[secret bool]]:
  var block: list[list[secret bool]] = []
  for i in 0..16:
    block.append(public_byte(values[i]))
  return block

def increment_counter_byte(byte: list[secret bool], carry_in: secret bool) -> list[secret bool]:
  var out: list[secret bool] = []
  var carry = carry_in
  for bit_index in 0..8:
    out.append(gate_xor(byte[bit_index], carry))
    carry = gate_and(byte[bit_index], carry)
  return out

def increment_counter_byte_carry(byte: list[secret bool], carry_in: secret bool) -> secret bool:
  var carry = carry_in
  for bit_index in 0..8:
    carry = gate_and(byte[bit_index], carry)
  return carry

def increment_counter_block(counter: list[list[secret bool]]) -> list[list[secret bool]]:
  var out: list[list[secret bool]] = []
  var carry = Share.from_clear_int(1, 1)
  for offset in 0..16:
    var byte_index = 15 - offset
    out.insert(0, increment_counter_byte(counter[byte_index], carry))
    carry = increment_counter_byte_carry(counter[byte_index], carry)
  return out
"#;
    let main_lit = r#"
def main_lit() -> list[int64]:
  var ctr0 = public_block([240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255])
  var ctr1 = increment_counter_block(ctr0)
  return reveal_block(ctr1)
"#;
    let source = format!("{base}\n{main_lit}");

    let run_at = |level: u8, full_unroll: bool, source: String| async move {
        // Full-unroll budgets are threaded hermetically through CompilerOptions
        // (never via process-global env vars), so this test cannot leak a
        // full-unroll regime into any concurrent compile in the same process.
        let budget = if full_unroll { Some(100_000_000) } else { None };
        let options = stoffellang::CompilerOptions {
            optimize: level > 0,
            optimization_level: level,
            mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
            inline_budget: budget,
            unroll_budget: budget,
            unroll_max_expansion: budget,
            ..Default::default()
        };
        let compiled = stoffellang::compile(&source, "<ctr-lit>", &options)
            .unwrap_or_else(|e| panic!("compile at -O{level}: {e:?}"));
        let binary = stoffellang::convert_to_binary(&compiled);
        let functions = binary.try_to_vm_functions().expect("vm functions");
        let engine = Arc::new(CountingEngine::default());
        let mut vm = VirtualMachine::builder()
            .with_mpc_engine(engine.clone())
            .build();
        for function in functions {
            vm.try_register_function(function)
                .expect("register function");
        }
        let result = vm
            .execute_async("main_lit", engine.as_ref())
            .await
            .unwrap_or_else(|e| panic!("execute at -O{level}: {e:?}"));
        let Value::Array(result_ref) = result else {
            panic!("main_lit should return an array");
        };
        let mut out = Vec::new();
        for index in 0..vm.read_array_len(result_ref).expect("len") {
            let value = vm
                .read_table_field(TableRef::from(result_ref), &Value::I64(index as i64))
                .expect("read byte")
                .expect("byte");
            let Value::I64(b) = value else {
                panic!("byte should be int64, got {value:?}");
            };
            out.push(b);
        }
        out
    };

    let o0 = run_at(0, false, source.clone()).await;
    eprintln!("CTR1_O0 = {:?}", o0);
    // Full-unroll O3 via hermetic per-compile budgets (no env-var leak).
    let o3 = run_at(3, true, source).await;
    eprintln!("CTR1_O3 = {:?}", o3);
    eprintln!("match: {}", o0 == o3);
    assert_eq!(
        o0, o3,
        "ctr1 (counter increment) must match between -O0 and -O3"
    );
}

/// Full-unroll correctness gate for ALL THREE programs (AES circuit, CTR, CBC).
///
/// At large (`100_000_000`) inline/unroll/expansion budgets the whole circuit
/// flattens into one block, which used to trigger the multiply-batcher
/// dependency-model bug: `statement_reads_and_writes` did not model in-place
/// mutators (`append`/`extend`/`insert`) as writes of their receiver, so the
/// scheduler+batcher hoisted a fused `Share.batch_mul` ABOVE the loop that
/// populated its operand lists. At runtime the operands were still empty, the
/// product (and its slices) were empty, and the consumer indexed an empty array
/// — crashing with `get_field: array index 0 out of range (length 0)`.
///
/// With the dep-model fix, all three must run to completion and reveal their
/// NIST-correct output at full unroll. This is the authoritative cryptographic
/// gate for Step 1.
///
/// Ignored by default (flattening all three circuits is heavy: ~18 min in
/// release, longer in debug), matching `optimized_aes_full_unroll_minimizes_rounds`.
/// Run explicitly, ideally in release:
///   cargo test --release -p stoffel-vm --test aes_count \
///     full_unroll_aes_ctr_cbc_match_nist -- --ignored
#[test]
#[ignore = "heavy full-unroll cryptographic gate; run manually with --ignored"]
fn full_unroll_aes_ctr_cbc_match_nist() {
    run_on_large_stack(full_unroll_aes_ctr_cbc_match_nist_impl());
}

async fn full_unroll_aes_ctr_cbc_match_nist_impl() {
    let aes_src = include_str!("../../stoffel-lang/examples/mpc_aes128_circuit/main.stfl");
    let ctr_src = include_str!("../../stoffel-lang/examples/mpc_aes128_ctr/main.stfl");
    let cbc_src = include_str!("../../stoffel-lang/examples/mpc_aes128_cbc/main.stfl");

    let plaintext_shares = bits_as_bool_shares(&hex_bytes(CTR_CBC_PLAINTEXT_HEX));
    let key_shares = bits_as_bool_shares(&hex_bytes(CTR_CBC_KEY_HEX));
    type ClientInputs = Vec<(usize, Vec<stoffel_vm::ClientShare>)>;
    let ctr_cbc_inputs: ClientInputs = vec![(0usize, plaintext_shares), (1usize, key_shares)];

    let programs: Vec<(&str, &str, ClientInputs, &[i64])> = vec![
        ("AES", aes_src, Vec::new(), &AES_NIST_CIPHERTEXT[..]),
        (
            "CTR",
            ctr_src,
            ctr_cbc_inputs.clone(),
            &AES_NIST_PLAINTEXT_P1[..],
        ),
        (
            "CBC",
            cbc_src,
            ctr_cbc_inputs.clone(),
            &AES_NIST_PLAINTEXT_P1[..],
        ),
    ];

    for (label, source, inputs, expected) in &programs {
        // Full-unroll budgets threaded hermetically through CompilerOptions.
        let options = stoffellang::CompilerOptions {
            optimize: true,
            optimization_level: 3,
            mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
            inline_budget: Some(100_000_000),
            unroll_budget: Some(100_000_000),
            unroll_max_expansion: Some(100_000_000),
            ..Default::default()
        };
        let compiled = stoffellang::compile(source, "<full-unroll-gate>", &options)
            .unwrap_or_else(|e| panic!("{label}: full-unroll compile failed: {e:?}"));
        let binary = stoffellang::convert_to_binary(&compiled);
        let functions = binary.try_to_vm_functions().expect("vm functions");

        let engine = Arc::new(CountingEngine::default());
        let mut vm = VirtualMachine::builder()
            .with_mpc_engine(engine.clone())
            .build();
        for function in functions {
            vm.try_register_function(function)
                .expect("register function");
        }
        for (client_id, shares) in inputs {
            vm.store_client_shares(*client_id, shares.clone());
        }

        let result = vm
            .execute_async("main", engine.as_ref())
            .await
            .unwrap_or_else(|e| panic!("{label}: full-unroll execution failed: {e:?}"));
        let Value::Array(result_ref) = result else {
            panic!("{label}: main should return an array");
        };
        let mut out = Vec::new();
        for index in 0..vm.read_array_len(result_ref).expect("result length") {
            let value = vm
                .read_table_field(TableRef::from(result_ref), &Value::I64(index as i64))
                .expect("read byte")
                .expect("byte present");
            let Value::I64(byte) = value else {
                panic!("{label}: output byte should be int64, got {value:?}");
            };
            out.push(byte);
        }

        assert_eq!(
            out,
            expected.to_vec(),
            "{label}: full-unroll output must match the NIST vector"
        );
    }
}

// ===========================================================================
// Round-count + correctness gate
// ===========================================================================
//
// Reusable, reproducible gate for round-reducing optimizer work. For each of
// AES-circuit, CTR, and CBC at -O0/-O2/-O3 it COMPILES the live source, runs it
// through the GF(2) `CountingEngine`, and reports BOTH the multiply round count
// (each scalar `multiply_share` or batched `batch_multiply_share` call is one
// communication round) AND whether the revealed output is correct.
//
// Correctness oracle (per program, independent of optimization level):
//   * AES-circuit: the program returns the ciphertext block; it must equal the
//     NIST SP 800-38A AES-128 vector.
//   * CTR / CBC: the program returns the round-tripped second plaintext block
//     (encrypt then decrypt), so it must equal NIST plaintext block P1. This is
//     a true value oracle and ALSO implies -O2/-O3 == -O0 when all three match.
//
// Output: one stable line per (program, level):
//   ROUNDGATE <prog> O<level> mul_rounds=<n> correct=<true|false>
//
// Run with:
//   cargo test -p stoffel-vm --test aes_count round_gate -- --nocapture
//
// The test PRINTS the measurements for every (program, level) and only asserts
// the invariants that are known-stable (see assertions at the end), so it stays
// green as a measurement harness while still surfacing any regression.

/// NIST SP 800-38A AES-128 ciphertext for the single-block circuit example.
const AES_NIST_CIPHERTEXT: [i64; 16] = [
    105, 196, 224, 216, 106, 123, 4, 48, 216, 205, 183, 128, 112, 180, 197, 90,
];

/// NIST SP 800-38A AES-128 second plaintext block (P1 = ae2d8a57...8e51). Both
/// CTR and CBC encrypt then decrypt and return this round-tripped block.
const AES_NIST_PLAINTEXT_P1: [i64; 16] = [
    174, 45, 138, 87, 30, 3, 172, 156, 158, 183, 111, 172, 69, 175, 142, 81,
];

/// Two-block NIST plaintext (P0 || P1) and 128-bit key, as the client secret
/// inputs CTR/CBC consume via `ClientStore.take_share_bool`.
const CTR_CBC_PLAINTEXT_HEX: &str =
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51";
const CTR_CBC_KEY_HEX: &str = "2b7e151628aed2a6abf7158809cf4f3c";

/// Decode a hex string to bytes.
fn hex_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex byte"))
        .collect()
}

/// Expand bytes into one secret-bool client share per bit, LSB-first within each
/// byte (bit i = 2^i) — the exact ordering `take_client_byte` expects.
fn bits_as_bool_shares(bytes: &[u8]) -> Vec<stoffel_vm::ClientShare> {
    let mut shares = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for bit in 0..8 {
            let value = (byte >> bit) & 1;
            shares.push(stoffel_vm::ClientShare::typed(
                ShareType::boolean(),
                ShareData::Opaque(vec![value].into()),
            ));
        }
    }
    shares
}

/// Compile `source` at the given optimization level, seed any client inputs,
/// run `main` through the `CountingEngine`, and return
/// `(mul_rounds, revealed_output)`. `mul_rounds` is the number of multiply
/// communication rounds: scalar `multiply_share` calls (one round each) plus
/// `batch_multiply_share` calls (one round each, regardless of batch size).
/// Lever-B / depth measurements for one (program, level) run.
struct LeverMetrics {
    /// Multiply pairs with >=1 public-literal operand (lever B's headroom).
    public_operand_muls: usize,
    /// Subset of the above where BOTH operands are public (fully foldable).
    both_public_muls: usize,
    /// Critical-path multiply depth (theoretical round floor).
    mul_depth: usize,
}

async fn round_gate_run(
    source: &str,
    level: u8,
    client_inputs: &[(usize, Vec<stoffel_vm::ClientShare>)],
) -> Result<(usize, Vec<i64>, LeverMetrics), String> {
    let options = stoffellang::CompilerOptions {
        optimize: level > 0,
        optimization_level: level,
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<round-gate>", &options)
        .map_err(|e| format!("compile at -O{level}: {e:?}"))?;
    let binary = stoffellang::convert_to_binary(&compiled);
    let functions = binary
        .try_to_vm_functions()
        .map_err(|e| format!("vm functions at -O{level}: {e:?}"))?;

    let engine = Arc::new(CountingEngine::default());
    let mut vm = VirtualMachine::builder()
        .with_mpc_engine(engine.clone())
        .build();
    for function in functions {
        vm.try_register_function(function)
            .map_err(|e| format!("register function at -O{level}: {e:?}"))?;
    }
    for (client_id, shares) in client_inputs {
        vm.store_client_shares(*client_id, shares.clone());
    }

    let result = vm
        .execute_async("main", engine.as_ref())
        .await
        .map_err(|e| format!("execute at -O{level}: {e:?}"))?;
    let Value::Array(result_ref) = result else {
        return Err(format!("main should return an array at -O{level}"));
    };
    let mut out = Vec::new();
    let result_len = vm
        .read_array_len(result_ref)
        .map_err(|e| format!("result length at -O{level}: {e:?}"))?;
    for index in 0..result_len {
        let value = vm
            .read_table_field(TableRef::from(result_ref), &Value::I64(index as i64))
            .map_err(|e| format!("read byte at -O{level}: {e:?}"))?
            .ok_or_else(|| format!("byte {index} missing at -O{level}"))?;
        let Value::I64(byte) = value else {
            return Err(format!(
                "output byte should be int64 at -O{level}, got {value:?}"
            ));
        };
        out.push(byte);
    }

    let (scalar, batch_calls, _items) = engine.counts();
    let (public_operand_muls, both_public_muls, mul_depth) = engine.lever_b_counts();
    Ok((
        scalar + batch_calls,
        out,
        LeverMetrics {
            public_operand_muls,
            both_public_muls,
            mul_depth,
        },
    ))
}

// Heavy measurement harness (compiles + runs AES/CTR/CBC at O0/O2/O3): run
// manually as the round-reduction gate with `-- --ignored`. Ignored by default so
// it does not add parallel compile/VM load to the standard test run.
#[ignore = "round-reduction measurement gate; run manually with --ignored"]
#[test]
fn round_gate() {
    run_on_large_stack(round_gate_impl());
}

async fn round_gate_impl() {
    let aes_src = include_str!("../../stoffel-lang/examples/mpc_aes128_circuit/main.stfl");
    let ctr_src = include_str!("../../stoffel-lang/examples/mpc_aes128_ctr/main.stfl");
    let cbc_src = include_str!("../../stoffel-lang/examples/mpc_aes128_cbc/main.stfl");

    // CTR/CBC consume 2 plaintext blocks from client slot 0 and the key from
    // client slot 1. With no explicit roster the client store sorts by id, so
    // id 0 -> slot 0 (plaintext) and id 1 -> slot 1 (key).
    let plaintext_shares = bits_as_bool_shares(&hex_bytes(CTR_CBC_PLAINTEXT_HEX));
    let key_shares = bits_as_bool_shares(&hex_bytes(CTR_CBC_KEY_HEX));
    type ClientInputs = Vec<(usize, Vec<stoffel_vm::ClientShare>)>;
    let ctr_cbc_inputs: ClientInputs = vec![(0usize, plaintext_shares), (1usize, key_shares)];

    // (program label, source, no-input or client-input, expected output)
    let programs: Vec<(&str, &str, ClientInputs, &[i64])> = vec![
        ("AES", aes_src, Vec::new(), &AES_NIST_CIPHERTEXT[..]),
        (
            "CTR",
            ctr_src,
            ctr_cbc_inputs.clone(),
            &AES_NIST_PLAINTEXT_P1[..],
        ),
        (
            "CBC",
            cbc_src,
            ctr_cbc_inputs.clone(),
            &AES_NIST_PLAINTEXT_P1[..],
        ),
    ];

    // Collected so the measurement harness is also a correctness gate.
    let mut all_correct = true;
    let mut measured_rounds: std::collections::HashMap<(&str, u8), usize> =
        std::collections::HashMap::new();

    for (label, source, inputs, expected) in &programs {
        for level in [0u8, 2, 3] {
            match round_gate_run(source, level, inputs).await {
                Ok((mul_rounds, output, lever)) => {
                    measured_rounds.insert((*label, level), mul_rounds);
                    let correct = output == *expected;
                    // The stable, machine-parseable gate line.
                    println!(
                        "ROUNDGATE {label} O{level} mul_rounds={mul_rounds} correct={correct}"
                    );
                    // Lever-B headroom: multiplies whose `ab` term has a public-literal
                    // operand (could become a local `mul_scalar`). `both_public` is the
                    // fully-constant-foldable subset.
                    println!(
                        "PUBMUL {label} O{level} public_operand_muls={} both_public={}",
                        lever.public_operand_muls, lever.both_public_muls
                    );
                    // Critical-path multiply depth = theoretical round floor.
                    println!("MULDEPTH {label} O{level} mul_depth={}", lever.mul_depth);
                    if !correct {
                        eprintln!(
                            "ROUNDGATE {label} O{level} MISMATCH: got {output:?}, expected {expected:?}"
                        );
                    }
                    if !correct {
                        all_correct = false;
                    }
                }
                Err(error) => {
                    println!("ROUNDGATE {label} O{level} mul_rounds=ERR correct=false");
                    eprintln!("ROUNDGATE {label} O{level} ERROR: {error}");
                    all_correct = false;
                }
            }
        }
    }

    assert!(
        all_correct,
        "AES, CTR, and CBC must match their NIST outputs at every optimization level"
    );
    for label in ["CTR", "CBC"] {
        assert!(
            measured_rounds[&(label, 3)] < measured_rounds[&(label, 2)]
                && measured_rounds[&(label, 2)] < measured_rounds[&(label, 0)],
            "{label} must reduce online rounds monotonically from O0 to O2 to O3"
        );
    }
}

// ===========================================================================
// Per-dependency-depth round histogram (measurement only)
// ===========================================================================
//
// For each program at -O3 this compiles + runs the live source through the
// CountingEngine, then breaks the multiply ROUNDS down by critical-path output
// depth. Each scalar multiply call or batch_multiply call is one round (one
// `call_id`). For every output depth d it reports:
//   pairs   = number of multiply pairs whose output depth is d
//   ideal   = ceil(pairs/256)  (the minimum rounds depth d can take at the cap)
//   actual  = number of rounds whose pairs are (max-)at depth d
//   waste   = actual - ideal   (recoverable rounds at this depth: lever 1/3/5)
//   pub     = pairs at depth d with a public operand (lever 4 headroom)
// plus per-program totals: actual rounds, ideal floor (sum of per-depth ideals),
// max depth, singleton rounds (a round of exactly 1 pair), and mixed-depth
// rounds (a round whose pairs span more than one output depth).
//
// Run with:
//   cargo test --release -p stoffel-vm --test aes_count round_histogram \
//     -- --ignored --nocapture

async fn histogram_run(
    source: &str,
    level: u8,
    client_inputs: &[(usize, Vec<stoffel_vm::ClientShare>)],
) -> Result<(usize, Vec<i64>, Vec<PairRecord>), String> {
    let options = stoffellang::CompilerOptions {
        optimize: level > 0,
        optimization_level: level,
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<histogram>", &options)
        .map_err(|e| format!("compile at -O{level}: {e:?}"))?;
    let binary = stoffellang::convert_to_binary(&compiled);
    let functions = binary
        .try_to_vm_functions()
        .map_err(|e| format!("vm functions at -O{level}: {e:?}"))?;

    let engine = Arc::new(CountingEngine::default());
    let mut vm = VirtualMachine::builder()
        .with_mpc_engine(engine.clone())
        .build();
    for function in functions {
        vm.try_register_function(function)
            .map_err(|e| format!("register function at -O{level}: {e:?}"))?;
    }
    for (client_id, shares) in client_inputs {
        vm.store_client_shares(*client_id, shares.clone());
    }

    let result = vm
        .execute_async("main", engine.as_ref())
        .await
        .map_err(|e| format!("execute at -O{level}: {e:?}"))?;
    let Value::Array(result_ref) = result else {
        return Err(format!("main should return an array at -O{level}"));
    };
    let mut out = Vec::new();
    let result_len = vm
        .read_array_len(result_ref)
        .map_err(|e| format!("result length at -O{level}: {e:?}"))?;
    for index in 0..result_len {
        let value = vm
            .read_table_field(TableRef::from(result_ref), &Value::I64(index as i64))
            .map_err(|e| format!("read byte at -O{level}: {e:?}"))?
            .ok_or_else(|| format!("byte {index} missing at -O{level}"))?;
        let Value::I64(byte) = value else {
            return Err(format!(
                "output byte should be int64 at -O{level}, got {value:?}"
            ));
        };
        out.push(byte);
    }
    let (scalar, batch_calls, _items) = engine.counts();
    Ok((scalar + batch_calls, out, engine.pair_log_snapshot()))
}

fn print_depth_histogram(label: &str, rounds: usize, correct: bool, log: &[PairRecord]) {
    use std::collections::BTreeMap;
    // Per output depth: total pairs, pairs with a public operand.
    let mut pairs_at: BTreeMap<u32, usize> = BTreeMap::new();
    let mut pub_at: BTreeMap<u32, usize> = BTreeMap::new();
    // Per round (call_id): (min depth, max depth, pair count).
    let mut calls: BTreeMap<u32, (u32, u32, usize)> = BTreeMap::new();
    let mut total_pub = 0usize;
    let mut total_both = 0usize;
    for r in log {
        *pairs_at.entry(r.depth).or_default() += 1;
        if r.pub_operand {
            *pub_at.entry(r.depth).or_default() += 1;
            total_pub += 1;
        }
        if r.both_public {
            total_both += 1;
        }
        let e = calls.entry(r.call_id).or_insert((u32::MAX, 0, 0));
        e.0 = e.0.min(r.depth);
        e.1 = e.1.max(r.depth);
        e.2 += 1;
    }
    // Attribute each round to its max output depth; count singletons / mixed.
    let mut actual_at: BTreeMap<u32, usize> = BTreeMap::new();
    let mut singleton_rounds = 0usize;
    let mut mixed_rounds = 0usize;
    for (mn, mx, n) in calls.values() {
        *actual_at.entry(*mx).or_default() += 1;
        if *n == 1 {
            singleton_rounds += 1;
        }
        if mn != mx {
            mixed_rounds += 1;
        }
    }
    let mut ideal_total = 0usize;
    let depths: Vec<u32> = pairs_at.keys().copied().collect();
    println!(
        "HIST {label} O3 rounds={rounds} correct={correct} pairs={} max_depth={} pub_pairs={} both_public={}",
        log.len(),
        depths.last().copied().unwrap_or(0),
        total_pub,
        total_both,
    );
    println!("HIST {label} depth | pairs | ideal | actual | waste | pub");
    for d in &depths {
        let pairs = pairs_at[d];
        let ideal = pairs.div_ceil(256);
        ideal_total += ideal;
        let actual = actual_at.get(d).copied().unwrap_or(0);
        let pub_pairs = pub_at.get(d).copied().unwrap_or(0);
        let waste = actual as i64 - ideal as i64;
        println!(
            "HIST {label}  {d:>4} | {pairs:>5} | {ideal:>5} | {actual:>6} | {waste:>5} | {pub_pairs:>5}"
        );
    }
    let total_waste = rounds as i64 - ideal_total as i64;
    println!(
        "HIST {label} TOTALS actual_rounds={rounds} ideal_floor={ideal_total} waste={total_waste} \
distinct_depths={} singleton_rounds={singleton_rounds} mixed_depth_rounds={mixed_rounds}",
        depths.len(),
    );
    println!();
}

#[ignore = "per-depth round histogram measurement; run manually with --ignored --nocapture"]
#[test]
fn round_histogram() {
    run_on_large_stack(round_histogram_impl());
}

async fn round_histogram_impl() {
    let aes_src = include_str!("../../stoffel-lang/examples/mpc_aes128_circuit/main.stfl");
    let ctr_src = include_str!("../../stoffel-lang/examples/mpc_aes128_ctr/main.stfl");
    let cbc_src = include_str!("../../stoffel-lang/examples/mpc_aes128_cbc/main.stfl");

    let plaintext_shares = bits_as_bool_shares(&hex_bytes(CTR_CBC_PLAINTEXT_HEX));
    let key_shares = bits_as_bool_shares(&hex_bytes(CTR_CBC_KEY_HEX));
    type ClientInputs = Vec<(usize, Vec<stoffel_vm::ClientShare>)>;
    let ctr_cbc_inputs: ClientInputs = vec![(0usize, plaintext_shares), (1usize, key_shares)];

    let programs: Vec<(&str, &str, ClientInputs, &[i64])> = vec![
        ("AES", aes_src, Vec::new(), &AES_NIST_CIPHERTEXT[..]),
        (
            "CTR",
            ctr_src,
            ctr_cbc_inputs.clone(),
            &AES_NIST_PLAINTEXT_P1[..],
        ),
        (
            "CBC",
            cbc_src,
            ctr_cbc_inputs.clone(),
            &AES_NIST_PLAINTEXT_P1[..],
        ),
    ];

    for (label, source, inputs, expected) in &programs {
        match histogram_run(source, 3, inputs).await {
            Ok((rounds, output, log)) => {
                let correct = output == *expected;
                print_depth_histogram(label, rounds, correct, &log);
                assert!(correct, "{label} O3 must match its NIST output");
            }
            Err(error) => {
                panic!("HIST {label} O3 failed: {error}");
            }
        }
    }
}

/// Regression test for the opt-level >= 1 spill-slot reload cache: a value that
/// is reassigned inside a runtime loop while spilled (a multi-def spill slot
/// carried across the back edge) is exactly where a stale cached reload would
/// produce wrong values while straight-line code still passes. The program
/// keeps ~26 loop-invariant, data-dependent values live across a 128-iteration
/// `while` loop (forcing clear-bank spills) and accumulates through a spilled
/// loop-carried variable; every optimization level must agree with -O0.
#[test]
fn loop_carried_spill_slot_reloads_are_correct() {
    run_on_large_stack(loop_carried_spill_slot_reloads_are_correct_impl());
}

async fn loop_carried_spill_slot_reloads_are_correct_impl() {
    // Build the source: a first runtime loop makes `seed` opaque to constant
    // folding, a chain of 24 live-to-the-end variables plus 8 loop-carried
    // accumulators forces clear-bank spilling, and the second loop reassigns
    // the (spilled) accumulators on every iteration.
    let mut source = String::from(
        "def main() -> int64:\n\
         \x20 var n = 128\n\
         \x20 var i = 0\n\
         \x20 var seed = 0\n\
         \x20 while i < n:\n\
         \x20   seed = seed + i\n\
         \x20   i = i + 1\n\
         \x20 var a0 = seed + 1\n",
    );
    for k in 1..24 {
        source.push_str(&format!("  var a{k} = a{} + seed\n", k - 1));
    }
    for k in 0..8 {
        source.push_str(&format!("  var t{k} = seed + a{}\n", k * 3));
    }
    source.push_str("  var j = 0\n  while j < n:\n");
    for k in 0..8 {
        source.push_str(&format!("    t{k} = t{k} + a{}\n", 23 - k));
    }
    source.push_str("    j = j + 1\n  var sum = 0\n");
    for k in 0..24 {
        source.push_str(&format!("  sum = sum + a{k}\n"));
    }
    for k in 0..8 {
        source.push_str(&format!("  sum = sum + t{k}\n"));
    }
    source.push_str("  return sum\n");

    let run_at = |level: u8| {
        let source = source.clone();
        async move {
            let options = stoffellang::CompilerOptions {
                optimize: level > 0,
                optimization_level: level,
                mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
                ..Default::default()
            };
            let compiled = stoffellang::compile(&source, "<loop-carried-spill>", &options)
                .unwrap_or_else(|e| panic!("compile at -O{level}: {e:?}"));
            // The test is only meaningful if the accumulator actually spills:
            // require a multi-def spill slot (>= 2 static STS to one slot — the
            // loop-carried reassignments of `t`).
            if level > 0 {
                let mut sts_per_slot: std::collections::HashMap<usize, usize> =
                    std::collections::HashMap::new();
                for inst in &compiled.main_chunk.instructions {
                    if let stoffel_vm_types::instructions::Instruction::STS(slot, _) = inst {
                        *sts_per_slot.entry(*slot).or_default() += 1;
                    }
                }
                assert!(
                    !sts_per_slot.is_empty(),
                    "-O{level}: expected register pressure to spill (no STS emitted; \
                     raise the live-variable count in this test)"
                );
                assert!(
                    sts_per_slot.values().any(|&count| count >= 2),
                    "-O{level}: expected a multi-def (loop-carried) spill slot, got {sts_per_slot:?}"
                );
            }
            let binary = stoffellang::convert_to_binary(&compiled);
            let functions = binary.try_to_vm_functions().expect("vm functions");
            let engine = Arc::new(CountingEngine::default());
            let mut vm = VirtualMachine::builder()
                .with_mpc_engine(engine.clone())
                .build();
            for function in functions {
                vm.try_register_function(function)
                    .expect("register function");
            }
            vm.execute_async("main", engine.as_ref())
                .await
                .unwrap_or_else(|e| panic!("execute at -O{level}: {e:?}"))
        }
    };

    let baseline = run_at(0).await;
    for level in 1..=3 {
        let result = run_at(level).await;
        assert_eq!(
            result, baseline,
            "-O{level} disagrees with -O0 on the loop-carried spilled accumulator"
        );
    }
}

/// Regression test for the CTR-only -O3 SROA empty-husk crash.
///
/// SROA (`scalarize_local_arrays`) deletes the `append` builder calls of a
/// scalar-backed local list, emitting a length-0 array and substituting each
/// constant-index read with the captured element. The bug: when a scalar-backed
/// list's handle is *aliased* under a new name (`var counter = initial_counter`)
/// or *captured* into another list, the empty-husk handle escaped into a sibling
/// block (an inlined callee body scalarized in its own per-block pass) where it
/// was read as a real, length-0 array — faulting at runtime with
/// `get_field: array index 0 out of range (length 0)`. The name-keyed demotion
/// machinery never saw the cross-block read. The fix demotes a scalar-backed
/// source whenever its bare handle can escape via such an alias/capture
/// (fail-closed: the real array is rebuilt), leaving the MPC round structure
/// untouched.
///
/// This self-contained program exercises exactly that shape: CTR keystream with
/// a loop-carried `counter` alias, `list.insert(0, ...)`-built blocks, and
/// nested flatten/regroup lists — then encrypts and decrypts, so `main` must
/// round-trip back to the plaintext `[16..=31]` at every optimization level.
/// Before the fix it crashed at -O3 while -O0/-O2 were correct.
const CTR_SROA_HUSK_SRC: &str = include_str!("data/ctr_sroa_husk.stfl");

#[test]
fn ctr_sroa_husk_o3_matches_o0() {
    run_on_large_stack(ctr_sroa_husk_o3_matches_o0_impl());
}

async fn ctr_sroa_husk_o3_matches_o0_impl() {
    let inputs: Vec<(usize, Vec<stoffel_vm::ClientShare>)> = Vec::new();
    let expected: Vec<i64> = (16..=31).collect();
    for level in [0u8, 2u8, 3u8] {
        let out = round_gate_run(CTR_SROA_HUSK_SRC, level, &inputs)
            .await
            .unwrap_or_else(|e| panic!("CTR SROA husk repro failed at -O{level}: {e}"));
        assert_eq!(
            out.1, expected,
            "-O{level} CTR keystream round-trip diverged (SROA empty-husk regression)"
        );
    }
}
