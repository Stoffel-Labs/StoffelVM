#!/usr/bin/env bash
# AES-128 in CTR mode over MPC, with a secret-shared (threshold) key and a
# client-supplied secret plaintext. Verified against NIST SP 800-38A.
# (CBC lives in its own example: mpc_aes128_cbc.)
#
#   Client slot 0 (data owner): 2 secret plaintext blocks (32 bytes, 256 bits)
#   Client slot 1 (key holder): the 128-bit AES key (threshold key)
#
# NIST SP 800-38A AES-128 CTR vectors:
#   Key       : 2b7e151628aed2a6abf7158809cf4f3c
#   P0        : 6bc1bee22e409f96e93d7e117393172a
#   P1        : ae2d8a571e03ac9c9eb76fac45af8e51
#   CTR ctr0  : f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff   (block1 = ...feff + 1 = ...ff00)
#
#   CTR C0/C1 : 874d6191b620e3261bef6864990db6ce / 9806f66b7970fdff8617187bb9fffdff
#
# The program prints 4 decimal byte-lists in order:
#   CTR C0, CTR C1, CTR P0', CTR P1'
# (the primed values are the decrypted plaintext and must equal P0, P1).
set -euo pipefail

PLAINTEXT_HEX="6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
KEY_HEX="2b7e151628aed2a6abf7158809cf4f3c"

# One `--client-input <slot>=<bit>` per bit, LSB-first per byte, as booleans so
# the input protocol yields secret-bool shares the AES gates accept.
emit_bits() {
  local slot="$1" hex="$2" i byte bit val
  for ((i = 0; i < ${#hex}; i += 2)); do
    byte=$((16#${hex:i:2}))
    for ((bit = 0; bit < 8; bit++)); do
      if (((byte >> bit) & 1)); then val="true"; else val="false"; fi
      printf -- '--client-input %s=%s ' "$slot" "$val"
    done
  done
}

# Slot 0 supplies 256 bits (2 plaintext blocks), and slot 1 supplies the key.
# Clients may provide different numbers of inputs — the local runner pads the
# shorter client internally — so no manual padding is needed here.
ARGS="$(emit_bits 0 "$PLAINTEXT_HEX")$(emit_bits 1 "$KEY_HEX")"

REPO_ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
RUNNER="${STOFFEL_RUN_BIN:-$REPO_ROOT/target/release/stoffel-run}"
STOFFEL="${STOFFEL_BIN:-$REPO_ROOT/target/release/stoffel}"

# shellcheck disable=SC2086
STOFFEL_RUN_BIN="$RUNNER" "$STOFFEL" run "$(dirname "$0")" \
  --release --local --runner "$RUNNER" --timeout-secs 1100 $ARGS
