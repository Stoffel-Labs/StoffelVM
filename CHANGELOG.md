# Changelog

All notable changes to the Stoffel crates are tracked here.

## [Unreleased]

### Changed

- Bumped `stoffelcrypto` (mpc-protocols) to `0.1.1` and `stoffelnet` to `0.1.1` across the workspace and coordinator wrapper. `stoffelmpc-network` follows to `0.1.1` via the lockfile. `stoffel-mpc-coordinator-shared` and `stoffel-mpc-coordinator-off-chain` remain on `0.1.0`.
- Adapted the AVSS engine to the `stoffelcrypto` 0.1.1 API: `verify_feldman` now takes an `expected_id`, and the AVSS share store values carry a receive timestamp alongside the shares. Existing verification semantics are preserved by binding shares to their own embedded evaluation id.

## [0.1.2] - 2026-09-03

### Added

- Added tag-driven crates.io release automation for `stoffel-bindgen`.
- Added keyless Sigstore signing, verification, checksums, and release bundles for published crates and CLI/runner archives.

### Changed

- Bumped the release-scoped Stoffel workspace crates to `0.1.2` and updated their internal path dependency requirements to the same exact version.
- Exact-pinned direct normal, development, and build dependencies across the workspace and coordinator wrapper for reproducible resolution.
- Kept independently released Stoffel dependencies on their published `0.1.0` versions: `stoffelcrypto`, `stoffelnet`, `stoffelmpc-network`, `stoffel-mpc-coordinator-shared`, and `stoffel-mpc-coordinator-off-chain`.
- Updated generated Rust project manifests to exact-pin `stoffel-rust-sdk` and `stoffel-bindgen` at `0.1.2`.

### Fixed

- Pinned `num-bigint` to the non-yanked `0.4.6` release so new package resolutions remain publishable.
- Pinned `tinyvec` to `1.11.0` so generated Rust projects avoid the broken `1.13.0` alloc-only build selected through `quinn-proto`.

## [0.1.1] - 2026-07-03

### PR #67 - runner release and install updates

#### Added

- Added a release workflow for standalone `stoffel-run` binaries and extended `install.sh` with runner-only installation via `--runner-only` or `--component runner`.

#### Changed

- Changed the Rust SDK runner lookup to resolve `stoffel-run` from `PATH` instead of assuming Cargo's bin directory.
- Updated runner release targets and prebuilt target listings to publish macOS `arm64` binaries only.

### Dev - full branch changelog

#### Added

- Added compiler and VM measurement coverage for AES/CTR/CBC MPC round counts, full-unroll correctness, and regression cases around batching, public-gate folding, and secret-multiplication preservation.

#### Changed

- Reworked resolved bytecode handling with operand validation, compact resolved operands, resolved function headers, and improved constant/label/function metadata resolution.
- Improved `-O3` MPC optimization substantially: batched independent `Share.batch_mul` calls, cross-block CTR scheduling, constant branch folding, public-gate folding, bounded multi-return inlining, loop vectorization, and faster dependency tracking.
- Reduced AES-family MPC round counts in the tracked examples while preserving NIST/equivalence checks, including AES `-O3` from 3306 to 296 rounds, CTR `-O3` from 4774 to 418 rounds, and CBC `-O3` from 22876 to 1061 rounds across the optimizer and example updates.
- Updated MPC examples to use `add_constant` in place of `add_scalar` for clearer API semantics.

#### Fixed

- Fixed non-hermetic compiler optimization budgets that could leak through process-global environment variables across tests or concurrent compiles.
- Fixed full-unroll AES/CTR/CBC miscompiles caused by incomplete dependency modeling for in-place mutators, indexed writes, and field writes.
- Fixed `Share.batch_mul` fusion cases that could pass nested arrays to runtime scalar-share extraction by flattening nested operands and restoring result shape safely.
- Fixed public secret-multiplication batching edge cases by localizing provably public operands to local `mul_scalar` operations where appropriate.
- Fixed AVSS runner preprocessing so it no longer depends on receiving a client input.
- Fixed MPC runtime cloning so independent clones preserve client-store counts.

## [0.1.0] - 2026-06-22

### Added

- Initial 0.1.0 crate release metadata for the Stoffel VM runtime, shared VM types, compiler, SDK, CLI, and binding generator crates.
- Documented the current CLI, SDK, VM runner, MPC, AVSS, and FFI workflows in the repository README.

### Notes

- `stoffel-bindgen` is currently marked `publish = false`; `stoffel-cli` is released as a GitHub binary artifact rather than a crates.io package.
- Publish order for the initial crate release is `stoffel-vm-types`, `stoffellang`, `stoffel-vm`, `stoffel-vm-runner`, `stoffel-rust-sdk`, then downstream binary artifacts such as `stoffel-cli`.
