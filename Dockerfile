# Multi-stage Dockerfile for StoffelVM
# Builds the stoffel-run binary and packages it for distributed MPC execution
#
# Build arguments:
#   ENABLE_NAT - Set to "true" to enable NAT traversal features (requires hole-punching branch)
#
# Example:
#   docker build --build-arg ENABLE_NAT=true -t stoffelvm:nat .

# ============================================================================
# Stage 1: Builder
# ============================================================================
FROM rustlang/rust:nightly-bookworm AS builder

# Build argument to enable NAT traversal feature
ARG ENABLE_NAT=false

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the entire project (we need all crates for workspace build)
COPY . .

# Configure git for private repos if using SSH
# For private GitHub repos, mount SSH keys during build:
#   docker build --ssh default .
# Under Mac OS, run this before on the host:
#   ssh-add --apple-use-keychain
RUN mkdir -p ~/.ssh && \
    ssh-keyscan github.com >> ~/.ssh/known_hosts 2>/dev/null || true

# Build the release binary
# Note: If using private repos with SSH, run with: docker build --ssh default .
# If ENABLE_NAT is true, build with the nat feature
RUN --mount=type=ssh \
    if [ "$ENABLE_NAT" = "true" ]; then \
        echo "Building with NAT traversal support..."; \
        cargo build --release --package stoffel-vm --bin stoffel-run --features nat; \
    else \
        echo "Building without NAT traversal support..."; \
        cargo build --release --package stoffel-vm --bin stoffel-run; \
    fi

# ============================================================================
# Stage 2: Runtime
# ============================================================================
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
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

# Copy the entrypoint script
COPY docker/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Default environment variables (can be overridden in docker-compose)
ENV STOFFEL_BIND_ADDR="0.0.0.0:9000"
ENV STOFFEL_N_PARTIES="5"
ENV STOFFEL_THRESHOLD="1"
ENV STOFFEL_PROGRAM="/app/programs/matrix_average_fixed_point.stflb"
ENV STOFFEL_ENTRY="main"
ENV STOFFEL_ROLE="party"
ENV STOFFEL_PARTY_ID="0"
ENV STOFFEL_BOOTSTRAP_ADDR=""
# NAT traversal settings (only effective if built with --features nat)
ENV STOFFEL_ENABLE_NAT="false"
ENV STOFFEL_STUN_SERVERS=""
ENV STOFFEL_ETH_NODE_ADDR="ws://host.docker.internal:8545"
ENV STOFFEL_COORD_ADDR=""
ENV STOFFEL_WALLET_SK=""

# Expose ports for bootnode and party communication
# Port 9000: bootnode coordination
# Port 10000: party-to-party communication (leader uses bind_port + 1000)
EXPOSE 9000 10000

ENTRYPOINT ["/app/entrypoint.sh"]
