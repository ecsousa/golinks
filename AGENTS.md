# AGENTS.md

Instructions and conventions for AI agents working in this repository.

## Project Overview

`golinks` is a self-hosted "go links" HTTP redirect service written in **Rust (Axum + Tokio)** with a **React (Vite)** management UI bundled into a single HTML file.

## Repository Layout

- `Cargo.toml` / `Cargo.lock` — Rust binary crate (`edition = "2024"`).
- `src/main.rs` — Axum router, `/` UI & `?action=...` JSON APIs, redirect/URL-encoding logic, `/favicon.ico` handler, security-header middleware, and integration tests.
- `src/config.rs` — YAML config loading (`BTreeMap` links), `HMAC-SHA256` session token derivation, atomic YAML persistence (`save_config_to_path`), and parent-directory `notify` hot-reload watcher.
- `src/auth.rs` — Constant-time secret/cookie comparison (`subtle::ConstantTimeEq`) and `Set-Cookie` builder.
- `assets/favicon.ico` — Default magnifier icon embedded into the binary via `include_bytes!("../assets/favicon.ico")`.
- `frontend/` — React 18 + `react-router-dom` (`HashRouter`) + Vite + `vite-plugin-singlefile` app that builds to a single self-contained `frontend/dist/index.html`.
- `Dockerfile` — Multi-stage build (`node:22-slim` → `rust:1-bookworm` → `debian:bookworm-slim`) copying `frontend/dist/index.html` to `/app/public/index.html`.
- `Dockerfile.release` — Multi-arch release image packaging prebuilt `bin/golinks-${TARGETARCH}` + `public/`.
- `.github/workflows/docker-build.yml` & `release.yml` — CI/CD workflows building `frontend/`, Rust binaries (`cross` for `aarch64-unknown-linux-gnu`), GitHub Release assets, and multi-arch `ghcr.io` Docker images.

## Critical Architectural Invariants

Do **not** break these invariants without explicit user approval:

1. **No Path Collisions with Link Keywords:**
   - Top-level paths (`/<keyword>`) belong exclusively to go-links.
   - The React UI is served **only** at `GET /` as a single-file HTML bundle (`vite-plugin-singlefile`) so no `/assets/*` or `/bundle.js` paths are needed.
   - Client-side routing **must** use `HashRouter` (`/#/`, `/#/edit`, `/#/edit/:keyword`).
   - All backend API endpoints live on `/` differentiated by `?action=...` (`getLinks`, `login`, `saveLink`, `deleteLink`).
   - Only `/favicon.ico` is a reserved non-root path.
2. **Authentication & Security:**
   - Never put secrets in URLs. Authentication uses an `HttpOnly; SameSite=Lax; Path=/; Max-Age=157680000` (5-year) cookie named `golinks_auth` (plus `; Secure` unless `GOLINKS_SECURE_COOKIE=false`).
   - Store `HMAC-SHA256(key, "golinks-session-v1")` in the cookie—never the raw `key`.
   - Always use constant-time comparison (`auth::constant_time_eq`) for secrets and cookies.
   - Keep `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, and `X-Content-Type-Options: nosniff` on **every** response.
   - Sanitize `next` redirect targets (must start with `/`, not `//`, no `\`, `\r`, `\n`).
3. **Configuration & Hot Reload:**
   - Use **`GOLINKS_FILE`** as the config path environment variable (default `/data/config.yaml` in Docker).
   - Keep `notify` watching the **parent directory** of `GOLINKS_FILE` so atomic saves and symlink swaps are detected.
   - On invalid YAML during hot reload, log the error and **keep the last valid config** active.
   - `save_config_to_path` must try temp-file + rename and fall back to direct write (for single-file Docker bind mounts).
4. **Privacy (Public Repo):**
   - Never commit personal domains, personal self-hosted service names, or real secrets in code, tests, docs, or commit messages. Always use generic placeholders (`example.com`, `docs`, `notes`, `google`, etc.).

## Build, Test & Local Development

- **Backend tests:** `cargo test`
- **Build frontend single-file bundle:** `npm --prefix frontend run build` (outputs `frontend/dist/index.html`, which `cargo run` loads automatically).
- **Frontend dev server (with API proxy to `:8080`):** `npm --prefix frontend run dev`
- **Run locally (PowerShell):**
  ```powershell
  $env:GOLINKS_FILE = "$env:TEMP\golinks.yaml"
  $env:GOLINKS_SECURE_COOKIE = "false"
  cargo run
  ```
- **Verification before committing:** Run `cargo test` for any Rust changes and `npm --prefix frontend run build` for any `frontend/` changes.

## Keeping Documentation Updated

Whenever you add features, change API contracts, add/rename environment variables, alter routing/auth behavior, or update build/release workflows, **update both `AGENTS.md` and `MEMORY.md`** (and `README.md` for user-facing changes) in the same task so future sessions stay accurate.
