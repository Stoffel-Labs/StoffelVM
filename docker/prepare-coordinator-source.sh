#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COORDINATOR_DIR="${ROOT_DIR}/.docker-cache/stoffel-mpc-coordinator"
COORDINATOR_REMOTE="${STOFFEL_COORDINATOR_GIT_REMOTE:-https://github.com/Stoffel-Labs/stoffel-mpc-coordinator.git}"
COORDINATOR_REF="${STOFFEL_COORDINATOR_GIT_REF:-6cb3e7e9f6c2f603153e3f2e1d0177507ad4dbad}"
COORDINATOR_PATCH="${ROOT_DIR}/docker/patches/stoffel-mpc-coordinator-subscription-disconnects.patch"

mkdir -p "$(dirname "${COORDINATOR_DIR}")"
rm -rf "${COORDINATOR_DIR}"
git clone "${COORDINATOR_REMOTE}" "${COORDINATOR_DIR}" >/dev/null 2>&1
git -C "${COORDINATOR_DIR}" checkout --quiet "${COORDINATOR_REF}"
git -C "${COORDINATOR_DIR}" apply --whitespace=nowarn "${COORDINATOR_PATCH}"

echo "Prepared coordinator source at ${COORDINATOR_DIR} (${COORDINATOR_REF})"
