FROM rust:1.88-bookworm AS build
ARG STOFFEL_VERSION=0.1.2
WORKDIR /app
RUN cargo install stoffel-vm-runner --version "=${STOFFEL_VERSION}" --locked
COPY . .
RUN cargo build --release --bin stoffel-coordinator

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=build /usr/local/cargo/bin/stoffel-run /usr/local/bin/stoffel-run
COPY --from=build /app/target/release/stoffel-coordinator /usr/local/bin/stoffel-coordinator
COPY --from=build /app/artifacts/program.stflb /app/artifacts/program.stflb
CMD ["stoffel-coordinator", "serve"]
