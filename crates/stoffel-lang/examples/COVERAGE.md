# Example Coverage

The examples are intended to be useful programs first and coverage fixtures
second. This matrix tracks the language and builtin surface that each program
exercises.

## Language Syntax And Semantics

| Surface | Example coverage |
| --- | --- |
| `main` entry points, typed and inferred-return `def` functions, explicit `return`, `discard` | Most examples; see `language_policy_engine`, `local_dynamic_workflow`, `mpc_client_private_score`, `mpc_share_toolkit` |
| Module imports and import aliases | `language_policy_engine` imports `math_rules as rules` |
| Type aliases and all core scalar type names | `language_policy_engine`, `language_mpc_schemas` |
| Integer literal widths and suffixes | `language_policy_engine` uses signed and unsigned 8/16/32/64-bit literals; `local_uint64_inverse` exercises `uint64` literals and arithmetic |
| `None`, `bool`, `float`/`float64`, `bytes` aliases | `language_policy_engine`, `language_mpc_schemas`, crypto and signature examples |
| Lists, dictionaries, nested generics, indexing, assignment through index | `language_policy_engine`, `language_mpc_schemas`, `local_dynamic_workflow`, `local_collections`, `local_nested_generics` |
| Dynamic objects and runtime field access | `local_dynamic_workflow` |
| Object schema declarations, base object syntax, secret-typed fields | `language_mpc_schemas` |
| Secret values and MPC secret flow | `mpc_boolean_circuit`, `mpc_aes128_circuit`, `mpc_sha256_client_io`, `mpc_client_federated_average`, `avss_certificate/sign`, `mpc_share_toolkit` |
| `if`/`elif`/`else`, `while`, `for` over ranges, lists, and strings | `language_policy_engine`, `local_control_flow`, `local_text_processing` |
| Unary `-` and `not`, arithmetic, comparison, boolean operators | `language_policy_engine`, `local_control_flow`, `local_uint64_inverse` |
| `mod` (floored modulo) vs `%` (truncating remainder) | `number_theory/clear/modinv_crt_int64`, `number_theory/clear/xgcd_iterative_int64` |
| Bitwise keywords `and`/`or`/`xor`/`not`/`shl`/`shr` on integers, hex literals, multi-line list literals | The `bits/clear/*` gallery (popcount, reversal, parity, rotation, Gray code, clz, flags) |
| Fixed-point `fix64` arithmetic, division, comparisons, tolerance checks | `matrix/clear/rotation_fix64`, `matrix/clear/gauss_fix64`, `polynomials/clear/*_fix64`, `number_theory/clear/gcd_fix64_anthyphairesis` |
| Secret-share arithmetic incl. share-by-public scaling, secret bool gate circuits | `bits/secret/*`, `matrix/secret/*`, `polynomials/secret/*`, `number_theory/secret/*` |
| `ClientStore.take_share`/`take_share_fixed` typed client inputs (int, uint, bool, fixed), multi-client and multi-input | the `*/secret/*` gallery (each documents its `--client-input` flags) |
| Secure fixed-point division by a public constant (`secret fix64 / <const>`) | `matrix/secret/scaled_mean_fix64` (division performed on shares; reciprocal + probabilistic truncation) |
| Compound assignment `+=`, `-=`, `*=`, `/=`, `%=` | `language_policy_engine` |
| Field-access method syntax and object builtin syntax | `local_collections`, `mpc_runtime_info`, `mpc_share_toolkit` |
| Closures exposed by the language stdlib | `local_dynamic_workflow`, `local_closure_counter` |
| `break` and `continue` loop control | `continue` in the `random_bit` rejection-sampling helper used across the `mpc_*` gallery; `break` for early loop exit |

`break` and `continue` are fully supported in `while`/`for` loops. `enum`
declarations parse (the parser expects `enum Name:` declaration syntax). `yield`
and `try/catch` are explicitly rejected by the compiler today (StoffelLang has no
generators or exception handling).

## Core Builtins

| Builtin surface | Example coverage |
| --- | --- |
| `print`, `type` | `local_dynamic_workflow`, `language_mpc_schemas` |
| `append`, `len` | `local_dynamic_workflow`, `local_collections`, `local_nested_generics` |
| `create_closure`, `create_closure_with_upvalue`, `call_closure`, `call_closure_with_arg`, `get_upvalue`, `set_upvalue` | `local_dynamic_workflow`, `local_closure_counter` |
| `LocalStorage.store`, `load`, `retrieve`, `delete`, `exists` | `local_storage`, `avss_share_auditor` |
| `LocalStorage.load_share` | `avss_certificate/sign` |

## MPC And Crypto Builtins

| Builtin surface | Example coverage |
| --- | --- |
| `Mpc.party_id`, `n_parties`, `threshold`, `is_ready`, `instance_id`, `protocol_name`, `curve`, `field`, `has_capability`, `capabilities` | `mpc_runtime_info` |
| `Mpc.rand`, `Mpc.rand_int` | `mpc_share_toolkit` |
| `ClientStore.take_share`, `take_share_fixed`, `get_number_clients` | `avss_certificate/sign`, `mpc_client_federated_average` |
| `MpcOutput.send_to_client` and `Share.send_to_client` | `mpc_client_private_score`, `mpc_sha256_client_io`, `mpc_share_toolkit`, `avss_certificate/sign` |
| Share creation, arithmetic, scalar ops, integer and fixed-point opening, batch opening, metadata, commitments, field arithmetic, client output, exponent opening | `mpc_boolean_circuit`, `mpc_aes128_circuit`, `mpc_client_private_score`, `mpc_share_toolkit`, `mpc_client_federated_average`, `mpc_share_arithmetic`, threshold signature examples |
| `Bytes.concat`, `Bytes.from_string` | threshold signature examples, `mpc_share_toolkit` |
| `Crypto.sha256`, `sha512`, `hash_to_field`, `field_inv`, `point_x_to_field`, `field_to_scalar_bytes`, `point_to_sec1`, `hash_to_g1` | threshold signature examples, `avss_certificate/keygen`, `avss_share_auditor` |
| `Avss.get_commitment`, `get_key_name`, `commitment_count`, `is_avss_share` | `avss_share_auditor` |
| `Rbc.broadcast`, `receive`, `receive_any` | `mpc_protocol_coordination` |
