# Stoffel Examples

This directory contains runnable Stoffel programs grouped by feature area. Each
example folder has a `main.stfl` source file and a short README.

## Layout

- `local_control_flow`: loops, ranges, functions, branching, and arithmetic.
- `local_collections`: list literals, indexing, and `append`/`push`/`len` aliases.
- `local_nested_generics`: generic functions over nested list shapes.
- `local_storage`: VM local storage through `LocalStorage`.
- `local_dynamic_workflow`: dynamic objects, runtime type inspection, arrays, and callbacks.
- `local_closure_counter`: captured upvalues and stateful closure callbacks.
- `local_text_processing`: string iteration for text checksums.
- `local_uint64_inverse`: overflow-safe unsigned modular inverse arithmetic.
- `language_policy_engine`: import-driven policy scoring with numeric widths and boolean logic.
- `language_mpc_schemas`: object schemas with secret-typed fields for MPC jobs.
- `mpc_client_private_score`: client input shares, private share computation, and client output shares.
- `mpc_share_arithmetic`: basic secret-share creation, arithmetic, and opening.
- `mpc_runtime_info`: MPC runtime metadata and capability builtins.
- `mpc_boolean_circuit`: `secret bool` random bits and boolean gates built from share arithmetic.
- `mpc_bitwise_share`: `secret bool` list inputs and native bitwise share operators.
- `mpc_polynomial_unbounded_or`: unbounded OR over `secret bool` lists as `1 - product(1 - bit)`.
- `mpc_random_bit`: joint random bit sharing via `Share.random_field()` and `Field.*` math (`a = 2⁻¹(r'⁻¹r + 1)`).
- `mpc_bit_decomposition`: decompose a secret into shared bits via a random mask, reveal, and a borrow-chain subtractor.
- `mpc_secure_comparison`: secret-shared `[a < b]` extracting only the comparison bit (masked reveal + carry chain, no full decomposition).
- `mpc_select_minmax`: oblivious `select`/mux, `min`/`max`, and equality built on secure comparison.
- `mpc_relu_sign`: sign extraction, `abs`, and ReLU (`x·[x≥0]`) on signed shares for private ML.
- `mpc_argmax`: secret-shared argmax/argmin index over a list (comparison tournament + select).
- `mpc_bitwise_int`: bitwise AND/OR/XOR and right shift on secret integers via bit-decomposition.
- `mpc_set_membership`: secret bit for `x ∈ S` over a public set (OR of equalities).
- `mpc_inner_product`: secure dot product via `batch_mul` + sum, and a small linear layer.
- `mpc_secret_exponentiation`: `base^e` with a secret exponent via oblivious square-and-multiply.
- `mpc_sorting_network`: data-oblivious sort via a fixed compare-and-swap network, plus median.
- `mpc_secure_division`: integer division by a secret divisor via comparison-based long division.
- `mpc_aes128_circuit`: AES-128 block encryption built from `secret bool` circuit gates.
- `mpc_sha256_client_io`: fixed-length SHA-256 over a secret 32-byte client input, with client-only digest reconstruction.
- `mpc_client_federated_average`: client-provided secret inputs via `ClientStore`.
- `mpc_protocol_coordination`: RBC coordination for distributed protocol phases.
- `mpc_share_toolkit`: broad Share builtin coverage for MPC service programs.
- `avss_share_auditor`: AVSS share metadata inspection helpers.
- `threshold_signatures/*`: threshold signature programs based on the VM fixtures.
- `avss_certificate/*`: AVSS certificate keygen/signing flows based on the VM fixtures.

MPC subprotocol library (built on the random-bit / comparison primitives):

- `mpc_oblivious_read`: read `arr[secret i]` via equality + select.
- `mpc_oblivious_write`: write `arr[secret i] = v` obliviously (select per cell).
- `mpc_range_check`: secret bit `[lo ≤ x ≤ hi]` (two comparisons + AND).
- `mpc_clamp`: clamp `x` to `[lo,hi]` = max(lo, min(x, hi)).
- `mpc_mux_tree`: log-depth n-way multiplexer over a secret index (select tree on index bits).
- `mpc_compare_family`: `>`, `≤`, `≥`, and compare-to-constant from `less_than`.
- `mpc_is_zero`: zero test `[x==0]` with a single comparison.
- `mpc_count_frequency`: count list elements equal to a secret target.
- `mpc_linear_search`: secret found-flag + first matching index.
- `mpc_popcount_secret`: population count of a secret int (decompose + sum bits).
- `mpc_msb_log2`: MSB index / floor(log2) via top-down prefix-OR.
- `mpc_lowest_set_bit`: trailing-zero count via bottom-up prefix-OR.
- `mpc_mod_constant`: secret `x mod 2ᵏ` via low-bit recombination.
- `mpc_parity`: parity (XOR-fold of bits) of a secret int.
- `mpc_bit_reverse_rotate`: reverse / rotate the bits of a secret word.
- `mpc_sign_extend`: reinterpret a secret unsigned value as signed two's complement.
- `mpc_modulo_secret`: remainder `a mod d` for a secret divisor (long division).
- `mpc_gcd`: Euclid GCD with a fixed iteration bound (secret modulo per round).
- `mpc_reciprocal`: fixed-point `1/d` = ⌊2^F/d⌋ via long division.
- `mpc_sqrt`: integer `⌊√n⌋` as a count of `k²≤n` comparisons.
- `mpc_horner_eval`: polynomial eval at a secret point via Horner.
- `mpc_abs_diff`: `|a-b|` via select on `[a<b]`.
- `mpc_secret_base_power`: `base^e` with secret base, public exponent.
- `mpc_transcendental`: fixed-point function approx (exp Taylor) via Horner + truncation.
- `mpc_mean`: mean = sum / n (division by public count).
- `mpc_variance`: variance via `n·Σx² − (Σx)²` (no division).
- `mpc_minmax_range`: min / max / range by select-fold over comparisons.
- `mpc_median`: median/percentile via sorting network + index.
- `mpc_weighted_average`: `Σwx / Σw` (batched multiply + division).
- `mpc_covariance`: covariance via `n·Σxy − Σx·Σy` (no division).
- `mpc_mode`: most frequent value over a public candidate domain (counts + argmax).
- `mpc_histogram`: counts per public bucket via range checks.
- `mpc_distance_metrics`: L1 and squared-L2 distances between secret vectors.
- `mpc_logistic_regression`: class = [w.x + b >= 0] on secret features.
- `mpc_decision_tree`: depth-2 tree on secret features (compare + select routing).
- `mpc_mlp_inference`: linear→ReLU→linear→argmax private inference.
- `mpc_knn`: nearest-neighbour classification (L2² + argmin).
- `mpc_naive_bayes`: multinomial NB scoring + argmax.
- `mpc_voting_tally`: tally secret votes, reveal only [tally ≥ τ].
- `mpc_first_price_auction`: winning bid + winner index (argmax).
- `mpc_second_price_auction`: Vickrey winner + second-highest clearing price.
- `mpc_threshold_gate`: k-of-n / majority gate on secret bits.
- `mpc_weighted_voting`: weighted tally vs threshold (batched multiply).
- `mpc_set_intersection`: `|A ∩ B|` of two secret sets (OR-of-equalities membership).
- `mpc_set_cardinality`: intersection and union sizes of two secret sets.
- `mpc_pattern_match`: count occurrences of a secret pattern in secret text.
- `mpc_lookup_table`: oblivious key→value lookup for a secret key.
- `mpc_secure_shuffle`: oblivious permutation by sorting (value, random-tag) pairs.
- `mpc_top_k`: k-th smallest (order statistic) via sorting network.
- `mpc_rank_order`: rank of each element = count of smaller.
- `mpc_bitonic_sort`: Batcher bitonic network for power-of-two lists.
- `mpc_modexp`: `base^e mod m` with a secret exponent (square-and-multiply + reduce).
- `mpc_modinv`: modular inverse via Fermat `a^(p-2) mod p`.
- `mpc_lcm`: `a·b / gcd(a,b)` (GCD + secure division).

## Algorithm gallery

Eighty self-checking programs organised as
`<category>/<clear|secret>/<name>` under `bits/`, `matrix/`, `polynomials/`
and `number_theory/`. Each category has ten clear programs varying
`uint64`/`int64`/`fix64` usage and ten secret programs whose private inputs
arrive from clients via `ClientStore`. Every program asserts its own results;
clear programs run with `stoffel run .`, secret ones document their
`--client-input` flags in a `# run-args:` header and in their READMEs.

Bit operations (clear):

- `bits/clear/popcount_uint64`: popcount three ways (naive, Kernighan, SWAR fold).
- `bits/clear/reverse_uint64`: bit reversal by loop and by mask-and-swap.
- `bits/clear/parity_int64`: xor-fold parity, including negative values.
- `bits/clear/rotate_uint64`: rotations built from shifts, with algebraic laws.
- `bits/clear/gray_code_uint64`: Gray code round trips and adjacency.
- `bits/clear/lowbit_int64`: two's-complement lowest-set-bit tricks.
- `bits/clear/clz_log2_uint64`: leading/trailing zeros and floor(log2).
- `bits/clear/flags_int64`: permission bitmasks with `and`/`or`/`xor`/`not`.
- `bits/clear/morton_uint64`: Morton Z-order interleaving and its inverse.
- `bits/clear/xorshift_uint64`: xorshift64 PRNG walked backwards to its seed.

Bit operations (secret, client inputs):

- `bits/secret/ripple_adder`: two clients' numbers added by full-adder gates.
- `bits/secret/equality_check`: access-code equality, one verdict bit revealed.
- `bits/secret/majority_vote`: five private ballots tallied by a counting circuit.
- `bits/secret/otp_xor`: one-time pad encrypt/decrypt over bool shares.
- `bits/secret/masks_meet`: permission mask intersection and union.
- `bits/secret/oblivious_mux`: per-bit blending under a private selection mask.
- `bits/secret/gt_comparator`: the millionaires' problem, bit by bit.
- `bits/secret/popcount_circuit`: private flags counted, positions hidden.
- `bits/secret/parity_checksum`: codeword validity verdicts via XOR folds.
- `bits/secret/pattern_match`: blind substring search, one found-bit revealed.

Matrix operations (clear):

- `matrix/clear/multiply_int64`: dense matmul, identity, associativity.
- `matrix/clear/transpose_uint64`: rectangular transpose and involution.
- `matrix/clear/determinant_int64`: cofactor determinants and det(AB)=det(A)det(B).
- `matrix/clear/fib_power_int64`: Fibonacci via matrix exponentiation.
- `matrix/clear/rotation_fix64`: fixed-point rotation matrices and isometry.
- `matrix/clear/gauss_fix64`: Gaussian elimination with partial pivoting.
- `matrix/clear/convolution_int64`: 2D convolution with zero padding.
- `matrix/clear/scalar_uint64`: trace, scalar and Hadamard algebra.
- `matrix/clear/markov_fix64`: Markov chain power iteration to steady state.
- `matrix/clear/paths_int64`: adjacency powers count walks and triangles.

Matrix operations (secret, client inputs):

- `matrix/secret/matvec`: client-owned matrix rows times a public query.
- `matrix/secret/average_fix64`: element-wise averaging of private matrices.
- `matrix/secret/scaled_mean_fix64`: secure mean with division on shares (only the mean opens).
- `matrix/secret/dot_similarity`: cross-client inner-product scoring.
- `matrix/secret/linear_layer`: private features through public weights.
- `matrix/secret/covariance`: covariance across split data ownership.
- `matrix/secret/trace_aggregate`: total load revealed via trace linearity.
- `matrix/secret/matmul`: full 2x2 share-by-share matrix product.
- `matrix/secret/outer_product`: rank-1 interaction table from private factors.
- `matrix/secret/weighted_fix64`: reliability-weighted fixed-point sensor fusion.
- `matrix/secret/hadamard_mask`: consent-masked disclosure of matrix cells.

Polynomial operations (clear):

- `polynomials/clear/horner_int64`: Horner vs naive evaluation.
- `polynomials/clear/multiply_uint64`: coefficient convolution and the evaluation homomorphism.
- `polynomials/clear/divmod_int64`: long division and the remainder theorem.
- `polynomials/clear/calculus_fix64`: derivatives, antiderivatives, definite integrals.
- `polynomials/clear/lagrange_fix64`: Lagrange interpolation through fixed-point samples.
- `polynomials/clear/newton_sqrt_fix64`: Newton root finding on x^2 - a and a cubic.
- `polynomials/clear/pascal_uint64`: binomial coefficients vs powers of 2 and 3.
- `polynomials/clear/finite_diff_int64`: difference-engine tables and sequence extension.
- `polynomials/clear/chebyshev_fix64`: Chebyshev recurrence, trig identity, composition.
- `polynomials/clear/taylor_exp_fix64`: the exp series with convergence and addition laws.

Polynomial operations (secret, client inputs):

- `polynomials/secret/membership`: allowlist membership via root polynomials.
- `polynomials/secret/aggregate_fix64`: consensus model from private coefficients.
- `polynomials/secret/oblivious_eval`: a public tariff at a private query point.
- `polynomials/secret/shamir_roundtrip`: Shamir dealing and reconstruction in-language.
- `polynomials/secret/blind_root_check`: root knowledge proven, both sides secret.
- `polynomials/secret/extrapolate`: next-quarter forecast from confidential samples.
- `polynomials/secret/cross_correlation`: private template matching by convolution.
- `polynomials/secret/vandermonde_encode`: Reed-Solomon coding of a private message.
- `polynomials/secret/power_sums`: pooled power sums and Newton's identities.
- `polynomials/secret/derivative_aggregate`: symbolic derivative of a combined model.

Number theory (clear, Euclid and extended Euclid):

- `number_theory/clear/gcd_iterative_int64`: remainder-based Euclid with signed inputs.
- `number_theory/clear/cf_euclid_uint64`: continued fractions from Euclid's quotients.
- `number_theory/clear/gcd_fix64_anthyphairesis`: subtraction-based Euclid on fix64 magnitudes.
- `number_theory/clear/gcd_binary_uint64`: Stein's shift-and-subtract binary GCD.
- `number_theory/clear/xgcd_iterative_int64`: iterative extended Euclid with Bezout certificates.
- `number_theory/clear/diophantine_int64`: linear Diophantine solver and solution families.
- `number_theory/clear/modinv_crt_int64`: modular inverses, congruences and CRT.
- `number_theory/clear/lcm_fold_uint64`: overflow-safe lcm/gcd folds and lattice laws.
- `number_theory/clear/fib_gcd_int64`: the gcd(F(m), F(n)) = F(gcd(m, n)) identity.
- `number_theory/clear/modexp_int64`: modular exponentiation and Fermat/Carmichael tests.

Number theory (secret, client inputs):

- `number_theory/secret/gcd_int64`: two clients' gcd with a share-verified Bezout certificate.
- `number_theory/secret/modinv_uint64`: modular inverse verified by one opened product.
- `number_theory/secret/crt_residues`: CRT combination on shares with public Bezout weights.
- `number_theory/secret/common_factor_audit`: pairwise gcd audit of private moduli.
- `number_theory/secret/wegman_mac`: Carter-Wegman tags from a split key and messages.
- `number_theory/secret/blind_divisibility`: divisibility proofs by quotient witness.
- `number_theory/secret/gcd_certificate`: gcd validity proven entirely on shares.
- `number_theory/secret/private_equality`: blinded difference equality testing.
- `number_theory/secret/egcd_chain`: three-party gcd with a three-term certificate.
- `number_theory/secret/diophantine`: settlement of a committed private amount.

See `COVERAGE.md` for the syntax, semantic, and builtin coverage matrix.

## Validate

Compile every example and run local-only examples through the VM:

```sh
./examples/validate_examples.sh
```

The script defaults to the workspace root that contains this crate.
Override it if needed:

```sh
STOFFEL_VM_DIR=/path/to/StoffelVM ./examples/validate_examples.sh
```

To run a distributed MPC example with Docker Compose after compiling:

```sh
STOFFEL_PROGRAM_NAME=mpc_runtime_info.stflb \
  ./examples/validate_examples.sh --docker-mpc
```

Docker examples default to git build contexts for the coordinator and
networking repos:

```sh
STOFFEL_COORDINATOR_CONTEXT='https://github.com/Stoffel-Labs/stoffel-mpc-coordinator.git#v0.2.0'
STOFFEL_NETWORK_CONTEXT='https://github.com/Stoffel-Labs/stoffel-networking.git#v0.1.1'
```

To test local uncommitted changes, point those contexts at local checkouts:

```sh
STOFFEL_COORDINATOR_CONTEXT=/path/to/stoffel-mpc-coordinator \
STOFFEL_NETWORK_CONTEXT=/path/to/stoffel-network \
  ./examples/validate_examples.sh --docker-mpc
```

If Docker is unavailable, run the same 5-party smoke test as local host
processes:

```sh
STOFFEL_PROGRAM_NAME=mpc_runtime_info.stflb \
  ./examples/validate_examples.sh --host-mpc
```

For threshold ECDSA over secp256k1:

```sh
STOFFEL_PROGRAM_NAME=threshold_signatures_threshold_ecdsa_secp256k1.stflb \
STOFFEL_MPC_BACKEND=avss \
STOFFEL_MPC_CURVE=secp256k1 \
  ./examples/validate_examples.sh --docker-mpc
```

Compiled binaries are written to `examples/dist/`.
