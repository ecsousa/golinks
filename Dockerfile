FROM rust:1-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/golinks /app/golinks

ENV GOLINKS_FILE=/data/config.yaml
ENV GOLINKS_ADDR=0.0.0.0:8080
ENV GOLINKS_SECURE_COOKIE=true

EXPOSE 8080
ENTRYPOINT ["/app/golinks"]
