#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXAMPLES_DIR="${ROOT_DIR}/examples"
WORKSPACE_DIR="$(cd "${ROOT_DIR}/../.." && pwd)"
VM_DIR="${STOFFEL_VM_DIR:-${WORKSPACE_DIR}}"
COORDINATOR_CONTEXT="${STOFFEL_COORDINATOR_CONTEXT:-${STOFFEL_COORDINATOR_DIR:-https://github.com/Stoffel-Labs/stoffel-mpc-coordinator.git#v0.2.0}}"
NETWORK_CONTEXT="${STOFFEL_NETWORK_CONTEXT:-${STOFFEL_NETWORK_DIR:-https://github.com/Stoffel-Labs/stoffel-networking.git#v0.1.1}}"
OUT_DIR="${STOFFEL_EXAMPLES_OUT:-${EXAMPLES_DIR}/dist}"
RUN_DOCKER_MPC=0
RUN_HOST_MPC=0
RUN_LOCAL_MPC=0

for arg in "$@"; do
  case "$arg" in
    --docker-mpc)
      RUN_DOCKER_MPC=1
      ;;
    --host-mpc)
      RUN_HOST_MPC=1
      ;;
    --local-mpc)
      RUN_LOCAL_MPC=1
      ;;
    -h|--help)
      cat <<'USAGE'
Usage: examples/validate_examples.sh [--docker-mpc] [--host-mpc] [--local-mpc]

Compiles every examples/**/main.stfl program to examples/dist.
Runs local-only examples through StoffelVM.
--local-mpc runs every example project (each dir with a Stoffel.toml) through
  `stoffel run` against the in-process local 5-party simulator, using the
  `# run-args:` header in each main.stfl, and reports PASS/FAIL/TIMEOUT.
Optionally runs an MPC smoke test either through Docker Compose or through
five local StoffelVM host processes.

Environment:
  STOFFEL_VM_DIR          VM checkout path
  STOFFEL_COORDINATOR_CONTEXT Coordinator Docker build context; defaults to the git branch
  STOFFEL_NETWORK_CONTEXT     Networking Docker build context; defaults to the git branch
  STOFFEL_COORDINATOR_DIR     Backward-compatible local coordinator context override
  STOFFEL_NETWORK_DIR         Backward-compatible local networking context override
  STOFFEL_EXAMPLES_OUT   Output directory for .stflb files
  STOFFEL_PROGRAM_NAME   Compiled binary to run in docker compose
  STOFFEL_MPC_BACKEND    honeybadger or avss
  STOFFEL_MPC_CURVE      bls12-381, secp256k1, p-256, etc.
  STOFFEL_LOCAL_MPC_TIMEOUT  per-example timeout in seconds for --local-mpc (default 120)
USAGE
      exit 0
      ;;
    *)
      echo "unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

if [ ! -d "$VM_DIR" ]; then
  echo "VM checkout not found: $VM_DIR" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"

echo "Building Stoffel compiler..."
cargo build --quiet --manifest-path "${ROOT_DIR}/Cargo.toml"
COMPILER="${WORKSPACE_DIR}/target/debug/stoffellang"

echo "Compiling examples into ${OUT_DIR}..."
find "$EXAMPLES_DIR" -path "$OUT_DIR" -prune -o -name main.stfl -print | sort | while read -r source; do
  rel="${source#${EXAMPLES_DIR}/}"
  rel_dir="$(dirname "$rel")"
  binary_name="$(printf '%s' "$rel_dir" | tr '/ ' '__').stflb"
  output="${OUT_DIR}/${binary_name}"
  mpc_backend="honeybadger"
  mpc_curve="bls12-381"
  case "$rel_dir" in
    avss_certificate/*)
      mpc_backend="avss"
      mpc_curve="p-256"
      ;;
    threshold_signatures/threshold_ecdsa_p256)
      mpc_backend="avss"
      mpc_curve="p-256"
      ;;
    threshold_signatures/threshold_ecdsa_secp256k1)
      mpc_backend="avss"
      mpc_curve="secp256k1"
      ;;
    threshold_signatures/threshold_schnorr_ed25519|threshold_signatures/threshold_eddsa_ed25519)
      mpc_backend="avss"
      mpc_curve="ed25519"
      ;;
  esac
  echo "  ${rel} -> ${binary_name} (${mpc_backend}/${mpc_curve})"
  "$COMPILER" -b --mpc-backend "$mpc_backend" --mpc-curve "$mpc_curve" -o "$output" "$source" >/dev/null
done

run_vm() {
  local binary_name="$1"
  shift
  echo "Running local VM example: ${binary_name}"
  (
    cd "$VM_DIR"
    cargo run --quiet --manifest-path Cargo.toml -p stoffel-vm-runner --bin stoffel-run -- \
      "${OUT_DIR}/${binary_name}" main "$@"
  )
}

run_vm local_control_flow.stflb
run_vm local_collections.stflb
run_vm local_nested_generics.stflb
run_vm language_policy_engine.stflb
run_vm local_text_processing.stflb
run_vm local_dynamic_workflow.stflb
run_vm local_closure_counter.stflb
run_vm language_mpc_schemas.stflb
run_vm local_uint64_inverse.stflb

LOCAL_STORE="$(mktemp -d "${TMPDIR:-/tmp}/stoffel-local-store.XXXXXX")"
trap 'rm -rf "$LOCAL_STORE"' EXIT
LOCAL_CERT="${VM_DIR}/ids/nodes/cert0.crt"
LOCAL_KEY="${VM_DIR}/ids/nodes/key0.der"
run_vm local_storage.stflb --local-store "${LOCAL_STORE}/example.redb" --cert "$LOCAL_CERT" --key "$LOCAL_KEY"
run_vm avss_share_auditor.stflb --local-store "${LOCAL_STORE}/auditor.redb" --cert "$LOCAL_CERT" --key "$LOCAL_KEY"

if [ "$RUN_DOCKER_MPC" -eq 1 ]; then
  docker_mpc_down() {
    (
      cd "$EXAMPLES_DIR"
      STOFFEL_VM_DIR="$VM_DIR" \
      STOFFEL_COORDINATOR_CONTEXT="$COORDINATOR_CONTEXT" \
      STOFFEL_NETWORK_CONTEXT="$NETWORK_CONTEXT" \
      STOFFEL_EXAMPLES_OUT="$OUT_DIR" \
        docker compose -f docker-compose.mpc.yml down --remove-orphans >/dev/null 2>&1 || true
    )
  }

  run_docker_mpc() {
    local binary_name="$1"
    local backend="${2:-honeybadger}"
    local curve="${3:-bls12-381}"

    echo "Running docker compose MPC example: ${binary_name} (${backend}/${curve})"
    docker_mpc_down
    if ! (
      cd "$EXAMPLES_DIR"
      STOFFEL_VM_DIR="$VM_DIR" \
      STOFFEL_COORDINATOR_CONTEXT="$COORDINATOR_CONTEXT" \
      STOFFEL_NETWORK_CONTEXT="$NETWORK_CONTEXT" \
      STOFFEL_EXAMPLES_OUT="$OUT_DIR" \
      STOFFEL_PROGRAM_NAME="$binary_name" \
      STOFFEL_MPC_BACKEND="$backend" \
      STOFFEL_MPC_CURVE="$curve" \
        docker compose -f docker-compose.mpc.yml up --build --abort-on-container-exit --exit-code-from party0
    ); then
      docker_mpc_down
      return 1
    fi
    docker_mpc_down
  }

  run_coordinator_example() {
    local binary_name="$1"
    shift

    echo "Running coordinator compose example: ${binary_name}"
    STOFFEL_VM_DIR="$VM_DIR" \
    STOFFEL_COORDINATOR_CONTEXT="$COORDINATOR_CONTEXT" \
    STOFFEL_NETWORK_CONTEXT="$NETWORK_CONTEXT" \
    STOFFEL_EXAMPLES_OUT="$OUT_DIR" \
    STOFFEL_PROGRAM_NAME="$binary_name" \
      "$EXAMPLES_DIR/run_coordinator_compose.sh" "$@"
  }

  run_docker_mpc mpc_runtime_info.stflb
  run_docker_mpc mpc_share_arithmetic.stflb
  run_docker_mpc mpc_share_toolkit.stflb
  run_docker_mpc mpc_protocol_coordination.stflb
  run_docker_mpc threshold_signatures_threshold_bls_bls12381.stflb honeybadger bls12-381
  run_docker_mpc threshold_signatures_threshold_schnorr_ed25519.stflb avss ed25519
  run_docker_mpc threshold_signatures_threshold_eddsa_ed25519.stflb avss ed25519
  run_docker_mpc threshold_signatures_threshold_ecdsa_secp256k1.stflb avss secp256k1
  run_docker_mpc threshold_signatures_threshold_ecdsa_p256.stflb avss p-256
  run_docker_mpc avss_certificate_keygen.stflb avss p-256
  run_docker_mpc avss_certificate_sign.stflb avss p-256

  STOFFEL_CLIENT_INPUT_COUNT=1 \
  STOFFEL_COORDINATOR_N_INPUTS=2 \
  STOFFEL_OUTPUTS=1 \
  STOFFEL_CLIENT1_OUTPUTS=0 \
  STOFFEL_CLIENT0_INPUT=100 \
  STOFFEL_CLIENT1_INPUT=20 \
  STOFFEL_CLIENT0_INDEX=0 \
  STOFFEL_CLIENT1_INDEX=1 \
  EXPECTED_OUTPUT=320 \
  WAIT_TIMEOUT_SECS=420 \
    run_coordinator_example mpc_client_private_score.stflb

  STOFFEL_CLIENT_INPUT_COUNT=6 \
  STOFFEL_COORDINATOR_N_INPUTS=12 \
  STOFFEL_OUTPUTS=6 \
  STOFFEL_CLIENT1_OUTPUTS=0 \
  STOFFEL_OUTPUT_FIXED_POINT_FRACTIONAL_BITS=16 \
  STOFFEL_CLIENT0_INPUT='65536,131072,196608,262144,327680,393216' \
  STOFFEL_CLIENT1_INPUT='458752,524288,589824,655360,720896,786432' \
  STOFFEL_CLIENT0_INDEX=0 \
  STOFFEL_CLIENT1_INDEX=6 \
  EXPECTED_OUTPUT='8, 10, 12, 14, 16, 18' \
  WAIT_TIMEOUT_SECS=420 \
    run_coordinator_example mpc_client_federated_average.stflb
fi

if [ "$RUN_HOST_MPC" -eq 1 ]; then
  echo "Running host-process MPC example..."
  "${EXAMPLES_DIR}/run_mpc_local.sh"
fi

LOCAL_MPC_FAILED=0
if [ "$RUN_LOCAL_MPC" -eq 1 ]; then
  echo "Running every example project through 'stoffel run' (local 5-party simulator)..."
  CLI="${WORKSPACE_DIR}/target/debug/stoffel"
  if [ ! -x "$CLI" ]; then
    echo "Building stoffel CLI..."
    cargo build --quiet --manifest-path "${WORKSPACE_DIR}/Cargo.toml" -p stoffel
  fi
  CAP="${STOFFEL_LOCAL_MPC_TIMEOUT:-120}"
  lm_pass=0
  lm_fail=0
  lm_timeout=0
  lm_failures=()
  while IFS= read -r toml; do
    proj="$(dirname "$toml")"
    rel="${proj#${EXAMPLES_DIR}/}"
    args=""
    if [ -f "${proj}/main.stfl" ]; then
      hdr="$(grep -m1 '^# run-args:' "${proj}/main.stfl" || true)"
      args="${hdr#\# run-args:}"
    fi
    log="$(mktemp "${TMPDIR:-/tmp}/stoffel-localmpc.XXXXXX")"
    # shellcheck disable=SC2086
    ( "$CLI" run "$proj" $args >"$log" 2>&1; echo "RC=$?" >>"$log" ) &
    waited=0
    while [ "$waited" -lt "$CAP" ]; do
      grep -q '^RC=' "$log" 2>/dev/null && break
      sleep 2
      waited=$((waited + 2))
    done
    if grep -q '^RC=' "$log" 2>/dev/null; then
      rc="$(grep '^RC=' "$log" | tail -1 | cut -d= -f2)"
      if [ "$rc" = "0" ]; then
        lm_pass=$((lm_pass + 1))
        echo "  PASS    ${rel} (${waited}s)"
      else
        lm_fail=$((lm_fail + 1))
        lm_failures+=("FAIL    ${rel} (rc=${rc})")
        echo "  FAIL    ${rel} (rc=${rc})"
      fi
    else
      lm_timeout=$((lm_timeout + 1))
      lm_failures+=("TIMEOUT ${rel} (>${CAP}s)")
      pkill -f "$CLI run $proj" 2>/dev/null || true
      echo "  TIMEOUT ${rel} (>${CAP}s)"
    fi
    rm -f "$log"
  done < <(find "$EXAMPLES_DIR" -name Stoffel.toml | sort)
  echo "Local MPC run summary: PASS=${lm_pass} FAIL=${lm_fail} TIMEOUT=${lm_timeout}"
  if [ "${#lm_failures[@]}" -gt 0 ]; then
    echo "Examples that did not pass:"
    printf '  %s\n' "${lm_failures[@]}"
    LOCAL_MPC_FAILED=1
  fi
fi

if [ "$LOCAL_MPC_FAILED" -ne 0 ]; then
  echo "Example validation FAILED (see local MPC failures above)."
  exit 1
fi

echo "Example validation complete."
