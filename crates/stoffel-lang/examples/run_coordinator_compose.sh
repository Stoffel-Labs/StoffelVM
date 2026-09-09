#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXAMPLES_DIR="${ROOT_DIR}/examples"
WORKSPACE_DIR="$(cd "${ROOT_DIR}/../.." && pwd)"
VM_DIR="${STOFFEL_VM_DIR:-${WORKSPACE_DIR}}"
COORDINATOR_CONTEXT="${STOFFEL_COORDINATOR_CONTEXT:-${STOFFEL_COORDINATOR_DIR:-https://github.com/Stoffel-Labs/stoffel-mpc-coordinator.git#v0.2.0}}"
NETWORK_CONTEXT="${STOFFEL_NETWORK_CONTEXT:-${STOFFEL_NETWORK_DIR:-https://github.com/Stoffel-Labs/stoffel-networking.git#v0.1.1}}"
OUT_DIR="${STOFFEL_EXAMPLES_OUT:-${EXAMPLES_DIR}/dist}"
COMPOSE_FILE="${EXAMPLES_DIR}/docker-compose.coordinator.yml"
AUTH_TOKEN="${STOFFEL_AUTH_TOKEN:-stoffel-examples-coord-token}"
WAIT_TIMEOUT_SECS="${WAIT_TIMEOUT_SECS:-300}"
EXPECTED_OUTPUT="${EXPECTED_OUTPUT:-315}"

WORKLOAD_CONTAINERS=(
  stoffel-examples-coord-party0
  stoffel-examples-coord-party1
  stoffel-examples-coord-party2
  stoffel-examples-coord-party3
  stoffel-examples-coord-party4
  stoffel-examples-coord-client0
  stoffel-examples-coord-client1
)

compose() {
  STOFFEL_AUTH_TOKEN="$AUTH_TOKEN" \
  STOFFEL_VM_DIR="$VM_DIR" \
  STOFFEL_COORDINATOR_CONTEXT="$COORDINATOR_CONTEXT" \
  STOFFEL_NETWORK_CONTEXT="$NETWORK_CONTEXT" \
  STOFFEL_EXAMPLES_OUT="$OUT_DIR" \
    docker compose -f "$COMPOSE_FILE" "$@"
}

cleanup() {
  compose down --remove-orphans -v >/dev/null 2>&1 || true
}

capture_logs() {
  compose logs --no-color coordinator party0 party1 party2 party3 party4 client0 client1
}

wait_for_workload_exit() {
  local start_ts
  start_ts="$(date +%s)"

  while true; do
    local all_exited=1
    local container
    for container in "${WORKLOAD_CONTAINERS[@]}"; do
      local state
      state="$(docker inspect -f '{{.State.Status}}' "$container")"
      if [ "$state" != "exited" ]; then
        all_exited=0
        break
      fi
    done

    if [ "$all_exited" -eq 1 ]; then
      return 0
    fi

    if (( "$(date +%s)" - start_ts >= WAIT_TIMEOUT_SECS )); then
      echo "Timed out after ${WAIT_TIMEOUT_SECS}s waiting for coordinator workload" >&2
      compose ps -a >&2 || true
      capture_logs >&2 || true
      return 1
    fi

    sleep 2
  done
}

assert_zero_exit_codes() {
  local container
  for container in "${WORKLOAD_CONTAINERS[@]}"; do
    local exit_code
    exit_code="$(docker inspect -f '{{.State.ExitCode}}' "$container")"
    if [ "$exit_code" != "0" ]; then
      echo "Container ${container} exited with ${exit_code}" >&2
      return 1
    fi
  done
}

if [ ! -f "${OUT_DIR}/${STOFFEL_PROGRAM_NAME:-mpc_share_arithmetic.stflb}" ]; then
  echo "Compiled coordinator program not found in ${OUT_DIR}." >&2
  echo "Run examples/validate_examples.sh first." >&2
  exit 2
fi

trap cleanup EXIT

compose down --remove-orphans -v >/dev/null 2>&1 || true
compose up --build -d
if ! wait_for_workload_exit; then
  capture_logs >&2 || true
  exit 1
fi
if ! assert_zero_exit_codes; then
  compose ps -a >&2 || true
  capture_logs >&2 || true
  exit 1
fi

logs="$(capture_logs)"
if ! grep -Fq "outputs: [${EXPECTED_OUTPUT}]" <<<"$logs"; then
  echo "Missing expected coordinator client output: outputs: [${EXPECTED_OUTPUT}]" >&2
  capture_logs >&2 || true
  exit 1
fi

echo "Coordinator client I/O example passed with outputs: [${EXPECTED_OUTPUT}]"
