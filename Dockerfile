FROM node:22-slim AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM rust:1-bookworm AS backend-builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY assets ./assets
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=backend-builder /app/target/release/golinks /app/golinks
COPY --from=frontend-builder /app/frontend/dist/index.html /app/public/index.html

ENV GOLINKS_FILE=/data/config.yaml
ENV GOLINKS_ADDR=0.0.0.0:8080
ENV GOLINKS_SECURE_COOKIE=true

EXPOSE 8080
ENTRYPOINT ["/app/golinks"]
