FROM rust:1-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p agent \
 && cp target/release/agent /agent

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap0.8 ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /agent /usr/local/bin/agent
ENTRYPOINT ["/usr/local/bin/agent"]


