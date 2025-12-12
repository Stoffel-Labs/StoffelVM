# Multi-stage Dockerfile for StoffelVM
# Builds the stoffel-run binary and packages it for distributed MPC execution

# ============================================================================
# Stage 1: Builder
# ============================================================================
FROM rustlang/rust:nightly-bookworm AS builder

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
RUN mkdir -p ~/.ssh && \
    ssh-keyscan github.com >> ~/.ssh/known_hosts 2>/dev/null || true

# Build the release binary
# Note: If using private repos with SSH, run with: docker build --ssh default .
RUN --mount=type=ssh cargo build --release --package stoffel-vm --bin stoffel-run

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

# Copy the test bytecode file
COPY --from=builder /build/crates/stoffel-vm/src/tests/binaries/matrix_average_fixed_point.stflb /app/programs/matrix_average_fixed_point.stflb

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

# Expose ports for bootnode and party communication
# Port 9000: bootnode coordination
# Port 10000: party-to-party communication (leader uses bind_port + 1000)
EXPOSE 9000 10000

ENTRYPOINT ["/app/entrypoint.sh"]
