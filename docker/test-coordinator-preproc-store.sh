#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREPARE_COORDINATOR_SOURCE="${ROOT_DIR}/docker/prepare-coordinator-source.sh"
BASE_COMPOSE="${ROOT_DIR}/docker-compose.coordinator.reserve-index.yml"
PREPROC_COMPOSE="${ROOT_DIR}/docker-compose.coordinator.reserve-index.preproc.yml"
PROJECT_NAME="${PROJECT_NAME:-coordri-preproc}"
AUTH_TOKEN="${STOFFEL_AUTH_TOKEN:-coord-test-token}"
WAIT_TIMEOUT_SECS="${WAIT_TIMEOUT_SECS:-240}"
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
    STOFFEL_AUTH_TOKEN="${AUTH_TOKEN}" docker compose \
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

trap cleanup EXIT

"${PREPARE_COORDINATOR_SOURCE}"

compose down --remove-orphans -v >/dev/null 2>&1 || true

echo "== First run: build and persist preprocessing =="
compose up --build -d
wait_for_workload_exit
assert_zero_exit_codes
first_logs="$(capture_logs)"
require_log "${first_logs}" "outputs: [-10]" "default subtraction output"
require_log "${first_logs}" "Persisted preprocessing material to store" "preprocessing persistence log"

echo "== Second run: load preprocessing from LMDB =="
compose down --remove-orphans
compose up --no-build -d
wait_for_workload_exit
assert_zero_exit_codes
second_logs="$(capture_logs)"
require_log "${second_logs}" "outputs: [-10]" "default subtraction output after load"
require_log "${second_logs}" "Loaded preprocessing material from store" "preprocessing load log"

echo "Coordinator preprocessing store/load test passed."
