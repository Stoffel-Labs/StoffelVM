#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE_DIR="$(cd "${ROOT_DIR}/../.." && pwd)"
VM_DIR="${STOFFEL_VM_DIR:-${WORKSPACE_DIR}}"
OUT_DIR="${STOFFEL_EXAMPLES_OUT:-${ROOT_DIR}/examples/dist}"
PROGRAM_NAME="${STOFFEL_PROGRAM_NAME:-mpc_runtime_info.stflb}"
ENTRY="${STOFFEL_ENTRY:-main}"
N_PARTIES="${STOFFEL_N_PARTIES:-5}"
THRESHOLD="${STOFFEL_THRESHOLD:-1}"
MPC_BACKEND="${STOFFEL_MPC_BACKEND:-honeybadger}"
MPC_CURVE="${STOFFEL_MPC_CURVE:-bls12-381}"
BASE_PORT="${STOFFEL_BASE_PORT:-19100}"
AUTH_TOKEN="${STOFFEL_AUTH_TOKEN:-stoffel-local-examples-token}"
TIMEOUT_SECONDS="${STOFFEL_MPC_TIMEOUT_SECONDS:-90}"
EXECUTION_ID="${STOFFEL_EXECUTION_ID:-}"

if [ -z "$EXECUTION_ID" ]; then
  EXECUTION_ID="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
fi
if ! [[ "$EXECUTION_ID" =~ ^[[:xdigit:]]{64}$ ]] || [[ "$EXECUTION_ID" =~ ^0{64}$ ]]; then
  echo "STOFFEL_EXECUTION_ID must be a nonzero 64-character hexadecimal value" >&2
  exit 2
fi

if [ "$N_PARTIES" -lt 2 ]; then
  echo "run_mpc_local.sh requires at least 2 parties; got STOFFEL_N_PARTIES=${N_PARTIES}" >&2
  exit 2
fi

RUNNER="${VM_DIR}/target/debug/stoffel-run"
if [ ! -x "$RUNNER" ]; then
  echo "Building StoffelVM runner..."
  cargo build --quiet --manifest-path "${VM_DIR}/Cargo.toml" -p stoffel-vm-runner --bin stoffel-run
fi

PROGRAM="${OUT_DIR}/${PROGRAM_NAME}"
if [ ! -f "$PROGRAM" ]; then
  echo "Compiled program not found: ${PROGRAM}" >&2
  echo "Run examples/validate_examples.sh first." >&2
  exit 2
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stoffel-mpc-local.XXXXXX")"
PIDS=""

cleanup() {
  for pid in $PIDS; do
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
    fi
  done
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

run_party() {
  local name="$1"
  shift
  echo "Starting ${name}: $*" >&2
  STOFFEL_AUTH_TOKEN="$AUTH_TOKEN" "$@" >"${WORK_DIR}/${name}.log" 2>&1 &
  PIDS="${PIDS} $!"
}

BOOTNODE_PORT="$BASE_PORT"
run_party party0 \
  "$RUNNER" "$PROGRAM" "$ENTRY" \
  --leader \
  --bind "127.0.0.1:${BOOTNODE_PORT}" \
  --n-parties "$N_PARTIES" \
  --threshold "$THRESHOLD" \
  --mpc-backend "$MPC_BACKEND" \
  --mpc-curve "$MPC_CURVE" \
  --execution-id "$EXECUTION_ID" \
  --local-store "${WORK_DIR}/party0.redb"

sleep 2

for ((party_id = 1; party_id < N_PARTIES; party_id++)); do
  party_port="$((BASE_PORT + party_id))"
  run_party "party${party_id}" \
    "$RUNNER" "$PROGRAM" "$ENTRY" \
    --party-id "$party_id" \
    --bootstrap "127.0.0.1:${BOOTNODE_PORT}" \
    --bind "127.0.0.1:${party_port}" \
    --n-parties "$N_PARTIES" \
    --threshold "$THRESHOLD" \
    --mpc-backend "$MPC_BACKEND" \
    --mpc-curve "$MPC_CURVE" \
    --execution-id "$EXECUTION_ID" \
    --local-store "${WORK_DIR}/party${party_id}.redb"
done

deadline=$((SECONDS + TIMEOUT_SECONDS))
while [ "$SECONDS" -lt "$deadline" ]; do
  all_done=1

  for pid in $PIDS; do
    if kill -0 "$pid" >/dev/null 2>&1; then
      all_done=0
    fi
  done

  if [ "$all_done" -eq 1 ]; then
    failed=0
    for pid in $PIDS; do
      if ! wait "$pid"; then
        failed=1
      fi
    done
    if [ "$failed" -ne 0 ]; then
      echo "One or more parties failed." >&2
      cat "${WORK_DIR}"/*.log >&2
      exit 1
    fi
    cat "${WORK_DIR}"/*.log
    echo "Local MPC run complete."
    exit 0
  fi

  sleep 1
done

echo "Timed out waiting for local MPC run." >&2
cat "${WORK_DIR}"/*.log >&2
exit 1
