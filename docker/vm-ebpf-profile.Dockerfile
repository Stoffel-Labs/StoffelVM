# syntax=docker/dockerfile:1.4

# Symbolized Linux build of the VM-only profiling workloads. Run this image
# privileged so bpftrace can sample the process through Linux eBPF.
FROM rustlang/rust:nightly-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Keep profiling builds on the toolchain already present in the base image.
# Otherwise an unpinned `nightly` repository override downloads a new compiler
# during every later-day rebuild and can change code generation between samples.
ENV RUSTUP_TOOLCHAIN=nightly-2026-08-19

WORKDIR /build
COPY . .
COPY --from=networking . /build/stoffelnet

RUN mkdir -p /build/.cargo && \
    printf '%s\n' \
      '[net]' \
      'git-fetch-with-cli = true' \
      '' \
      '[patch.crates-io]' \
      'stoffelnet = { path = "/build/stoffelnet" }' \
      > /build/.cargo/config.toml

ENV RUSTFLAGS="--cfg aes_armv8 --cfg polyval_armv8 -C debuginfo=2 -C force-frame-pointers=yes"
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release -p stoffel-vm --bin vm_ebpf_profile && \
    cp /build/target/release/vm_ebpf_profile /vm_ebpf_profile

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    binutils \
    bpftrace \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /vm_ebpf_profile /usr/local/bin/vm_ebpf_profile
ENTRYPOINT ["/bin/bash"]
