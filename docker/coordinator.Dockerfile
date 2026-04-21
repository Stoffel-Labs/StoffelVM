# syntax=docker/dockerfile:1.4
FROM rustlang/rust:nightly-bookworm AS builder

RUN apt-get update && apt-get install -y \
    ca-certificates \
    git \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY .cargo /build/.cargo
COPY docker/coordinator-wrapper /build/coordinator-wrapper

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
