# syntax=docker/dockerfile:1.4
# Multi-stage Dockerfile for StoffelVM
# Builds the stoffel-run binary and packages it for distributed MPC execution
#
# Build arguments:
#   ENABLE_NAT - Set to "true" to enable NAT traversal features (requires hole-punching branch)
#
# Example:
#   docker build \
#     --build-context coordinator=../stoffel-mpc-coordinator \
#     --build-context networking=../stoffel-networking \
#     --build-arg ENABLE_NAT=true \
#     -t stoffelvm:nat .
#
# The coordinator source context is required so the VM and coordinator images
# are compiled against the same execution-scoped RPC contract.
# The networking source context supplies the standing transport's physical
# frame bound and same-certificate multi-connection support.

# ============================================================================
# Stage 1: Builder
# ============================================================================
FROM rustlang/rust:nightly-bookworm AS builder

# Build argument to enable NAT traversal feature
ARG ENABLE_NAT=false
ARG STOFFEL_VM_PROFILE=false
# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY . .
# Keep external workspaces outside /build so Cargo does not attach their
# workspace-inherited manifests to the Stoffel workspace.
COPY --from=coordinator . /opt/stoffel-coordinator
COPY --from=networking . /opt/stoffelnet

RUN mkdir -p /build/.cargo && \
    printf '%s\n' \
      '[net]' \
      'git-fetch-with-cli = true' \
      '' \
      '[patch.crates-io]' \
      'stoffel-mpc-coordinator-off-chain = { path = "/opt/stoffel-coordinator/crates/off-chain" }' \
      'stoffel-mpc-coordinator-shared = { path = "/opt/stoffel-coordinator/crates/coord-shared" }' \
      'stoffelnet = { path = "/opt/stoffelnet" }' \
      '' \
      > /build/.cargo/config.toml

# Configure git for private repos if using SSH
# For private GitHub repos, mount SSH keys during build:
#   docker build --ssh default .
RUN mkdir -p ~/.ssh && \
    ssh-keyscan github.com >> ~/.ssh/known_hosts 2>/dev/null || true

# Build the release binary
# Note: If using private repos with SSH, run with: docker build --ssh default .
# If ENABLE_NAT is true, build with the nat feature
RUN --mount=type=ssh \
    export RUSTFLAGS="--cfg aes_armv8 --cfg polyval_armv8" && \
    if [ "$STOFFEL_VM_PROFILE" = "true" ]; then \
        export RUSTFLAGS="$RUSTFLAGS -C debuginfo=2 -C force-frame-pointers=yes"; \
    fi && \
    if [ "$ENABLE_NAT" = "true" ]; then \
        echo "Building with NAT traversal support..."; \
        cargo build --release --package stoffel-vm-runner --bin stoffel-run --features nat; \
    else \
        echo "Building without NAT traversal support..."; \
        cargo build --release --package stoffel-vm-runner --bin stoffel-run; \
    fi && \
    if [ "$STOFFEL_VM_PROFILE" != "true" ]; then \
        strip target/release/stoffel-run; \
    fi

# Compile the AES-128 secret-bit circuit example into VM bytecode for compose runs.
RUN cargo build --release --package stoffellang && \
    mkdir -p /build/crates/stoffel-lang/examples/mpc_aes128_circuit/target && \
    mkdir -p /build/docker/standing-concurrency/target && \
    STOFFEL_INLINE_BUDGET=100000000 \
    STOFFEL_UNROLL_BUDGET=100000000 \
    STOFFEL_UNROLL_MAX_EXPANSION=100000000 \
    /build/target/release/stoffellang \
      --binary \
      --opt-level 3 \
      --mpc-backend honeybadger \
      --mpc-curve bls12-381 \
      --output /build/crates/stoffel-lang/examples/mpc_aes128_circuit/target/mpc_aes128_circuit.stflb \
      /build/crates/stoffel-lang/examples/mpc_aes128_circuit/main.stfl && \
    /build/target/release/stoffellang \
      --binary \
      --mpc-backend honeybadger \
      --mpc-curve bls12-381 \
      --output /build/docker/standing-concurrency/target/single-client-io-honeybadger.stflb \
      /build/docker/standing-concurrency/programs/single_client_io.stfl && \
    /build/target/release/stoffellang \
      --binary \
      --mpc-backend honeybadger \
      --mpc-curve bls12-381 \
      --output /build/docker/standing-concurrency/target/slow-client-io-honeybadger.stflb \
      /build/docker/standing-concurrency/programs/slow_client_io.stfl && \
    /build/target/release/stoffellang \
      --binary \
      --opt-level 0 \
      --mpc-backend honeybadger \
      --mpc-curve bls12-381 \
      --output /build/docker/standing-concurrency/target/cpu-fairness-honeybadger.stflb \
      /build/docker/standing-concurrency/programs/cpu_fairness.stfl && \
    /build/target/release/stoffellang \
      --disassemble \
      /build/docker/standing-concurrency/target/cpu-fairness-honeybadger.stflb \
      > /build/docker/standing-concurrency/target/cpu-fairness-honeybadger.disassembly && \
    grep -Fqx '.function cpu_long' \
      /build/docker/standing-concurrency/target/cpu-fairness-honeybadger.disassembly && \
    grep -Fqx '.function cpu_short' \
      /build/docker/standing-concurrency/target/cpu-fairness-honeybadger.disassembly && \
    /build/target/release/stoffellang \
      --binary \
      --mpc-backend honeybadger \
      --mpc-curve bls12-381 \
      --output /build/docker/standing-concurrency/target/multi-client-io-honeybadger.stflb \
      /build/docker/standing-concurrency/programs/multi_client_io.stfl && \
    /build/target/release/stoffellang \
      --binary \
      --mpc-backend honeybadger \
      --mpc-curve bls12-381 \
      --output /build/docker/standing-concurrency/target/output-only-client-io-honeybadger.stflb \
      /build/docker/standing-concurrency/programs/output_only_client_io.stfl && \
    /build/target/release/stoffellang \
      --binary \
      --mpc-backend avss \
      --mpc-curve bls12-381 \
      --output /build/docker/standing-concurrency/target/single-client-io-avss.stflb \
      /build/docker/standing-concurrency/programs/single_client_io.stfl && \
    /build/target/release/stoffellang \
      --binary \
      --mpc-backend avss \
      --mpc-curve bls12-381 \
      --output /build/docker/standing-concurrency/target/multi-client-io-avss.stflb \
      /build/docker/standing-concurrency/programs/multi_client_io.stfl

# ============================================================================
# Stage 2: Credential-free runtime base
# ============================================================================
FROM debian:bookworm-slim AS runtime-base

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    iproute2 \
    libssl3 \
    netcat-openbsd \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /build/target/release/stoffel-run /app/stoffel-run

# Copy the test bytecode files
COPY --from=builder /build/crates/stoffel-vm/src/tests/binaries/matrix_average_fixed_point.stflb /app/programs/matrix_average_fixed_point.stflb
COPY --from=builder /build/crates/stoffel-vm/src/tests/binaries/client_mul.stflb /app/programs/client_mul.stflb
COPY --from=builder /build/crates/stoffel-vm/src/tests/binaries/client_sub_order.stflb /app/programs/client_sub_order.stflb
COPY --from=builder /build/crates/stoffel-vm/src/tests/binaries/avss_keygen.stflb /app/programs/avss_keygen.stflb
COPY --from=builder /build/crates/stoffel-vm/src/tests/binaries/avss_certificate_keygen.stflb /app/programs/avss_certificate_keygen.stflb
COPY --from=builder /build/crates/stoffel-vm/src/tests/binaries/avss_certificate_sign.stflb /app/programs/avss_certificate_sign.stflb
COPY --from=builder /build/crates/stoffel-vm/src/tests/binaries/threshold_schnorr_ed25519.stflb /app/programs/threshold_schnorr_ed25519.stflb
COPY --from=builder /build/crates/stoffel-vm/src/tests/binaries/threshold_eddsa_ed25519.stflb /app/programs/threshold_eddsa_ed25519.stflb
COPY --from=builder /build/crates/stoffel-vm/src/tests/binaries/threshold_bls_bls12381.stflb /app/programs/threshold_bls_bls12381.stflb
COPY --from=builder /build/crates/stoffel-vm/src/tests/binaries/threshold_ecdsa_secp256k1.stflb /app/programs/threshold_ecdsa_secp256k1.stflb
COPY --from=builder /build/crates/stoffel-vm/src/tests/binaries/threshold_ecdsa_p256.stflb /app/programs/threshold_ecdsa_p256.stflb
COPY --from=builder /build/crates/stoffel-lang/examples/mpc_aes128_circuit/target/mpc_aes128_circuit.stflb /app/programs/mpc_aes128_circuit.stflb
COPY --from=builder /build/docker/standing-concurrency/target/single-client-io-honeybadger.stflb /app/standing-fixtures/single-client-io-honeybadger.stflb
COPY --from=builder /build/docker/standing-concurrency/target/slow-client-io-honeybadger.stflb /app/standing-fixtures/slow-client-io-honeybadger.stflb
COPY --from=builder /build/docker/standing-concurrency/target/cpu-fairness-honeybadger.stflb /app/standing-fixtures/cpu-fairness-honeybadger.stflb
COPY --from=builder /build/docker/standing-concurrency/target/multi-client-io-honeybadger.stflb /app/standing-fixtures/multi-client-io-honeybadger.stflb
COPY --from=builder /build/docker/standing-concurrency/target/output-only-client-io-honeybadger.stflb /app/standing-fixtures/output-only-client-io-honeybadger.stflb
COPY --from=builder /build/docker/standing-concurrency/target/single-client-io-avss.stflb /app/standing-fixtures/single-client-io-avss.stflb
COPY --from=builder /build/docker/standing-concurrency/target/multi-client-io-avss.stflb /app/standing-fixtures/multi-client-io-avss.stflb

# Copy the entrypoint and peer-network shaping scripts
COPY docker/entrypoint.sh /app/entrypoint.sh
COPY docker/configure-peer-netem.sh /app/configure-peer-netem.sh
RUN chmod +x /app/entrypoint.sh /app/configure-peer-netem.sh

# Default environment variables (can be overridden in docker-compose)
ENV STOFFEL_BIND_ADDR="0.0.0.0:9000"
ENV STOFFEL_N_PARTIES="5"
ENV STOFFEL_THRESHOLD="1"
ENV STOFFEL_PROGRAM="/app/programs/mpc_aes128_circuit.stflb"
ENV STOFFEL_ENTRY="main"
ENV STOFFEL_ROLE="party"
ENV STOFFEL_PARTY_ID="0"
ENV STOFFEL_BOOTSTRAP_ADDR=""
ENV STOFFEL_COORD_ADDR=""
ENV STOFFEL_RPC_ADDR=""
ENV STOFFEL_CERT=""
ENV STOFFEL_KEY=""
ENV STOFFEL_TIMESTAMP="0"
ENV STOFFEL_CLIENT_INDEX=""
ENV STOFFEL_EXPECTED_CLIENTS=""
# NAT traversal settings (only effective if built with --features nat)
ENV STOFFEL_ENABLE_NAT="false"
ENV STOFFEL_STUN_SERVERS=""

# Expose ports for bootnode, party communication, and RPC
# Port 9000: bootnode coordination
# Port 10000: party-to-party communication (leader uses bind_port + 1000)
# Port 16180: node RPC server (mask distribution to clients)
EXPOSE 9000 10000 16180

ENTRYPOINT ["/app/entrypoint.sh"]

# ============================================================================
# Stage 3: Standing runtime (public admission rosters only)
# ============================================================================
# Private identities are supplied per principal as read-only Compose secrets.
# Do not COPY the full ids directory into this target: a faulty standing party
# must not be able to authenticate as another party or client.
FROM runtime-base AS standing-runtime

RUN mkdir -p /app/ids/nodes /app/ids/clients
COPY ids/server_cert.crt /app/ids/server_cert.crt
COPY ids/nodes/*.crt /app/ids/nodes/
COPY ids/clients/*.crt /app/ids/clients/

# ============================================================================
# Stage 4: Legacy runtime
# ============================================================================
# Preserve the default image contract for existing non-standing Compose stacks.
# New deployments should mount per-principal private credentials at runtime.
FROM runtime-base AS runtime

COPY ids /app/ids
