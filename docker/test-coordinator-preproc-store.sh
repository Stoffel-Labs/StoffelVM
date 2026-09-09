#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_COMPOSE="${ROOT_DIR}/docker-compose.coordinator.reserve-index.yml"
PREPROC_COMPOSE="${ROOT_DIR}/docker-compose.coordinator.reserve-index.preproc.yml"
PROJECT_NAME="${PROJECT_NAME:-coordri-preproc}"
AUTH_TOKEN="${STOFFEL_AUTH_TOKEN:-coord-test-token}"
WAIT_TIMEOUT_SECS="${WAIT_TIMEOUT_SECS:-240}"
EXECUTION_ID="${STOFFEL_EXECUTION_ID:-$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')}"
DEFAULT_COORDINATOR_CONTEXT="${ROOT_DIR}/../stoffel-mpc-coordinator"
if [[ ! -d "${DEFAULT_COORDINATOR_CONTEXT}/crates/off-chain" ]]; then
    DEFAULT_COORDINATOR_CONTEXT="https://github.com/Stoffel-Labs/stoffel-mpc-coordinator.git#v0.2.0"
fi
COORDINATOR_CONTEXT="${STOFFEL_COORDINATOR_CONTEXT:-${STOFFEL_COORDINATOR_DIR:-${DEFAULT_COORDINATOR_CONTEXT}}}"
NETWORK_CONTEXT="${STOFFEL_NETWORK_CONTEXT:-${STOFFEL_NETWORK_DIR:-https://github.com/Stoffel-Labs/stoffel-networking.git#v0.1.1}}"
WORKLOAD_CONTAINERS=(
    stoffel-coord-party0
    stoffel-coord-party1
    stoffel-coord-party2
    stoffel-coord-party3
    stoffel-coord-party4
    stoffel-coord-client0
    stoffel-coord-client1
)

compose() {
    STOFFEL_AUTH_TOKEN="${AUTH_TOKEN}" \
    STOFFEL_EXECUTION_ID="${EXECUTION_ID}" \
    STOFFEL_COORDINATOR_CONTEXT="${COORDINATOR_CONTEXT}" \
    STOFFEL_NETWORK_CONTEXT="${NETWORK_CONTEXT}" \
        docker compose \
        -p "${PROJECT_NAME}" \
        -f "${BASE_COMPOSE}" \
        -f "${PREPROC_COMPOSE}" \
        "$@"
}

cleanup() {
    compose down --remove-orphans -v >/dev/null 2>&1 || true
}

wait_for_workload_exit() {
    local start_ts
    start_ts="$(date +%s)"

    while true; do
        local all_exited=1
        local container
        for container in "${WORKLOAD_CONTAINERS[@]}"; do
            local status
            status="$(docker inspect -f '{{.State.Status}}' "${container}")"
            if [[ "${status}" != "exited" ]]; then
                all_exited=0
                break
            fi
        done

        if [[ "${all_exited}" == "1" ]]; then
            return 0
        fi

        if (( "$(date +%s)" - start_ts >= WAIT_TIMEOUT_SECS )); then
            echo "Timed out after ${WAIT_TIMEOUT_SECS}s waiting for workload containers to exit" >&2
            docker compose \
                -p "${PROJECT_NAME}" \
                -f "${BASE_COMPOSE}" \
                -f "${PREPROC_COMPOSE}" \
                ps -a >&2 || true
            capture_logs >&2 || true
            return 1
        fi

        sleep 2
    done
}

assert_zero_exit_codes() {
    local container
    local exit_code
    for container in "${WORKLOAD_CONTAINERS[@]}"; do
        exit_code="$(docker inspect -f '{{.State.ExitCode}}' "${container}")"
        if [[ "${exit_code}" != "0" ]]; then
            echo "Container ${container} exited with ${exit_code}" >&2
            capture_logs >&2 || true
            return 1
        fi
    done
}

capture_logs() {
    compose logs --no-color coordinator party0 party1 party2 party3 party4 client0 client1
}

require_log() {
    local haystack="$1"
    local needle="$2"
    local description="$3"

    if ! grep -Fq "${needle}" <<<"${haystack}"; then
        echo "Missing ${description}: ${needle}" >&2
        return 1
    fi
}

require_log_count() {
    local haystack="$1"
    local needle="$2"
    local expected="$3"
    local description="$4"
    local actual
    actual="$(grep -Fc "${needle}" <<<"${haystack}" || true)"
    if (( actual < expected )); then
        echo "Missing ${description}: expected at least ${expected} occurrences of ${needle}, got ${actual}" >&2
        return 1
    fi
}

assert_all_parties_crossed_mpc_execution() {
    local run_label="$1"
    local party party_logs
    for party in party0 party1 party2 party3 party4; do
        party_logs="$(compose logs --no-color "${party}")"
        require_log \
            "${party_logs}" \
            "Starting VM execution of 'main'..." \
            "${run_label} ${party} MPCExecution subscription delivery"
        require_log \
            "${party_logs}" \
            "online VM execution complete!" \
            "${run_label} ${party} online completion"
    done
}

trap cleanup EXIT

if ! [[ "${EXECUTION_ID}" =~ ^[0-9a-fA-F]{64}$ ]] \
    || [[ "${EXECUTION_ID}" =~ ^0{64}$ ]]; then
    echo "STOFFEL_EXECUTION_ID must be a nonzero 64-character hexadecimal value" >&2
    exit 2
fi

compose down --remove-orphans -v >/dev/null 2>&1 || true

echo "== First run: build and persist preprocessing =="
first_up_args=(--build)
if [[ "${STOFFEL_SKIP_BUILD:-0}" == "1" ]]; then
    first_up_args=(--no-build)
fi
compose up "${first_up_args[@]}" -d
wait_for_workload_exit
assert_zero_exit_codes
first_logs="$(capture_logs)"
require_log "${first_logs}" "outputs: [-10]" "default subtraction output"
require_log_count "${first_logs}" "HB standing preprocessing agreement: action=Rebuild" 5 "fresh-volume rebuild agreement"
assert_all_parties_crossed_mpc_execution first-run

echo "== Second run: load preprocessing from LMDB =="
compose down --remove-orphans
compose up --no-build -d
wait_for_workload_exit
assert_zero_exit_codes
second_logs="$(capture_logs)"
require_log "${second_logs}" "outputs: [-10]" "default subtraction output after load"
require_log_count "${second_logs}" "HB standing preprocessing agreement: action=" 5 "retained-volume preprocessing agreement"
if grep -Fq "HB standing preprocessing agreement: action=Rebuild" <<<"${second_logs}"; then
    echo "Matching retained stores unexpectedly selected a rebuild" >&2
    exit 1
fi
assert_all_parties_crossed_mpc_execution retained-run

echo "== Third run: recover from one party's missing preprocessing volume =="
compose down --remove-orphans
docker volume rm "${PROJECT_NAME}_coordri-preproc-party2" >/dev/null
compose up --no-build -d
wait_for_workload_exit
assert_zero_exit_codes
third_logs="$(capture_logs)"
require_log "${third_logs}" "outputs: [-10]" "default subtraction output after asymmetric recovery"
require_log_count "${third_logs}" "HB standing preprocessing agreement: action=Rebuild" 5 "asymmetric-volume rebuild agreement"
assert_all_parties_crossed_mpc_execution asymmetric-run

if grep -Eq 'RanShaError|BatchReconError|Preprocessing failed' <<<"${third_logs}"; then
    echo "Protocol failure detected after asymmetric preprocessing recovery" >&2
    exit 1
fi

echo "Coordinator preprocessing fresh/load/asymmetric-recovery test passed."
