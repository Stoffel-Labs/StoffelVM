#!/usr/bin/env sh
set -eu
stoffel check
stoffel build --output artifacts/program.stflb
cargo build --bins
export STOFFEL_AUTH_TOKEN="${STOFFEL_AUTH_TOKEN:-stoffel-local-example}"
exec cargo run --bin stoffel-services
