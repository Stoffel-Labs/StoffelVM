#!/usr/bin/env sh
set -eu
exec cargo run --bin stoffel-client -- "${1:-deploy/local/deployment.json}"
