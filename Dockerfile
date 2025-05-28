# ---- Build Stage ----
FROM rust:1.76 as builder
WORKDIR /app
COPY . .
RUN apt-get update && apt-get install -y pkg-config libssl-dev libpq-dev clang
RUN cargo build --release

# ---- Runtime Stage ----
FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y libssl3 libpq5 ca-certificates nmap sqlmap && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/sarissa /usr/local/bin/sarissa
COPY config.toml ./
COPY migrations ./migrations
COPY logs ./logs
EXPOSE 8080 8081
ENV RUST_LOG=info
CMD ["/usr/local/bin/sarissa"] 