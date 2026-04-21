# syntax=docker/dockerfile:1.4
FROM rustlang/rust:nightly-bookworm AS builder

RUN apt-get update && apt-get install -y \
    ca-certificates \
    git \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY --from=coordsrc . /build/stoffel-mpc-coordinator

COPY docker/coordinator-wrapper /build/coordinator-wrapper

# The reserve-index coordinator currently locks the Solidity SDK to a broken
# branch tip; pin the copied checkout to a known-good revision for this image.
RUN sed -i 's|stoffel-solidity-bindings = { version = "0.1.0", git = "https://github.com/Stoffel-Labs/Stoffel-solidity-SDK.git", branch = "test-coord" }|stoffel-solidity-bindings = { version = "0.1.0", git = "https://github.com/Stoffel-Labs/Stoffel-solidity-SDK.git", rev = "e8f3dad12ff448045617ab484a23c8e1e408d103" }|' /build/stoffel-mpc-coordinator/Cargo.toml && \
    rm -f /build/stoffel-mpc-coordinator/Cargo.lock

WORKDIR /build/coordinator-wrapper
RUN cargo build --release

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/coordinator-wrapper/target/release/stoffel-coordinator-docker /app/stoffel-coordinator

ENTRYPOINT ["/app/stoffel-coordinator"]
