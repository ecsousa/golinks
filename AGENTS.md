# AGENTS.md

Instructions and conventions for AI agents working in this repository.

## Project Overview

`golinks` is a self-hosted "go links" HTTP redirect service written in **Rust (Axum + Tokio)** with a **React (Vite)** management UI bundled into a single HTML file.

## Repository Layout

- `Cargo.toml` / `Cargo.lock` — Rust binary crate (`edition = "2024"`, `sqlx` with `sqlite`, `postgres`, and `tls-rustls-ring-webpki`; `openidconnect` + `reqwest` with `rustls-tls` and no OpenSSL).
- `build.rs` — Build script scanning `db/sqlite/` and `db/postgres/` (`full_schema.sql` + `migration_vXXXXXXX.sql` with matching versions across engines) and generating `$OUT_DIR/embedded_db.rs`.
- `db/sqlite/` & `db/postgres/` — Full database schemas (`schema_migration`, `users`, `links`; `users.user_name VARCHAR(255)`) and incremental migrations (`migration_v0000002.sql`) embedded at compile time; PostgreSQL tables live in the `golinks` schema.
- `src/main.rs` — Axum router, `/` UI & `?action=...` JSON APIs, OIDC redirect/callback handling on `/`, sliding-window JWT authentication, redirect/URL-encoding logic, `/favicon.ico` handler, security-header middleware, and integration tests.
- `src/db/mod.rs` — `Database` connection pool wrapper (`SqlitePool` / `PgPool`), `sync_user`, `get_or_create_user`, user lookup, and `user_id`-scoped link CRUD queries.
- `src/db/config.rs` — Environment variable parsing (`AppConfig`, `AuthConfig`, `OidcConfig`, `DbConfig`, `DbEngine`).
- `src/db/migrations.rs` — Embedded schema bootstrap and incremental migration runner (`schema_migration` tracking, PostgreSQL advisory lock `pg_advisory_lock`).
- `src/auth.rs` — `HMAC-SHA256` secret derivation (`derive_auth_token`), random user secret generation (`generate_random_user_secret`), HS256 JWT signing/parsing/verification, constant-time comparison (`subtle::ConstantTimeEq`), cookie extraction, and `Set-Cookie` builder.
- `src/oidc.rs` — Generic OIDC client (`OidcService`) with cached discovery/JWKS (24h TTL + retry on verification failure), PKCE + nonce validation, stateless HMAC-signed `golinks_oidc_state` cookie, username claim extraction (ID token + `userinfo` fallback), and `sanitize_next_path`.
- `assets/favicon.ico` — Default magnifier icon embedded into the binary via `include_bytes!("../assets/favicon.ico")`.
- `frontend/` — React 18 + `react-router-dom` (`HashRouter`) + Vite + `vite-plugin-singlefile` app that builds to a single self-contained `frontend/dist/index.html`.
- `Dockerfile` — Multi-stage build (`node:22-slim` → `rust:1-bookworm` → `debian:bookworm-slim`) copying `build.rs`, `db/`, and `frontend/dist/index.html` to `/app/public/index.html`, defaulting to `GOLINKS_DB_ENGINE=sqlite` and `GOLINKS_DB_PATH=/data/golinks.db`.
- `Dockerfile.release` — Multi-arch release image packaging prebuilt `bin/golinks-${TARGETARCH}` + `public/`, defaulting to `GOLINKS_DB_ENGINE=sqlite` and `GOLINKS_DB_PATH=/data/golinks.db`.
- `.github/workflows/docker-build.yml` & `release.yml` — CI/CD workflows building `frontend/`, static Linux `musl` binaries via `cross` (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`), Windows/macOS release binaries (`windows-11-arm` for `aarch64-pc-windows-msvc`), GitHub Release assets, and multi-arch `ghcr.io` Docker images.

## Critical Architectural Invariants

Do **not** break these invariants without explicit user approval:

1. **No Path Collisions with Link Keywords:**
   - Top-level paths (`/<keyword>`) belong exclusively to go-links.
   - The React UI is served **only** at `GET /` as a single-file HTML bundle (`vite-plugin-singlefile`) so no `/assets/*` or `/bundle.js` paths are needed.
   - Client-side routing **must** use `HashRouter` (`/#/`, `/#/edit`, `/#/edit/:keyword`).
   - All backend API endpoints live on `/` differentiated by `?action=...` (`getLinks`, `login`, `saveLink`, `deleteLink`), and OIDC callbacks also land on `GET /` (`?code=...&state=...` or `?error=...`).
   - Only `/favicon.ico` is a reserved non-root path.
2. **Authentication & Security:**
   - Never put secrets in URLs. Both single-user and OIDC modes use an `HttpOnly; SameSite=Lax; Path=/` cookie named `golinks_auth` (plus `; Secure` unless `GOLINKS_SECURE_COOKIE=false`) holding a compact HS256 JWT (`sub`, `iat`, `exp`) signed with `users.user_secret`, with a sliding-window expiry controlled by `GOLINKS_SESSION_TTL_DAYS` (default `30` days) refreshed on every valid request.
   - Single-user mode (`GOLINKS_OIDC_ENABLED=false`, default) stores `HMAC-SHA256(key, "golinks-session-v1")` (`auth::derive_auth_token`) in `users.user_secret`—never the raw `GOLINKS_USER_SECRET_KEY`.
   - OIDC mode (`GOLINKS_OIDC_ENABLED=true`) ignores `GOLINKS_USERNAME` and `GOLINKS_USER_SECRET_KEY`, redirects unauthenticated `/` and `/<keyword>` requests directly to the OIDC provider using a stateless HMAC-signed `golinks_oidc_state` cookie, and auto-provisions users via `Database::get_or_create_user` with a random 64-char hex `user_secret` (preserving existing non-empty secrets and rotating empty secrets).
   - Always use constant-time comparison (`auth::constant_time_eq` / `verify_jwt_signature`, rejecting empty secrets) for derived secrets, JWT signatures, and OIDC state verification.
   - Keep `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, and `X-Content-Type-Options: nosniff` on **every** response.
   - Sanitize `next` redirect targets (must start with `/`, not `//`, no `\`, `\r`, `\n`).
3. **Database & Migrations:**
   - When `GOLINKS_OIDC_ENABLED=false`, `GOLINKS_USER_SECRET_KEY` is required (non-empty) and `GOLINKS_USERNAME` defaults to `golinks` (max 255 chars); startup syncs the active user via `Database::sync_user` and stores `AuthMode::SingleUser { active_user_id }` in `AppState`.
   - When `GOLINKS_OIDC_ENABLED=true`, `GOLINKS_OIDC_ISSUER_URL`, `GOLINKS_OIDC_CLIENT_ID`, `GOLINKS_OIDC_CLIENT_SECRET`, and `GOLINKS_OIDC_REDIRECT_URI` are required (`GOLINKS_OIDC_SCOPES` defaults to `openid profile email`, `GOLINKS_OIDC_USERNAME_CLAIM` defaults to `preferred_username`); startup warms OIDC discovery lazily and stores `AuthMode::Oidc(Arc<OidcService>)` in `AppState`.
   - `GOLINKS_DB_ENGINE` selects `sqlite` (default; uses `GOLINKS_DB_PATH`, defaulting to `./golinks.db` locally and `/data/golinks.db` in Docker) or `postgresql` (requires `GOLINKS_DB_HOST`, `GOLINKS_DB_NAME`, `GOLINKS_DB_USERNAME`, `GOLINKS_DB_PASSWORD`; `GOLINKS_DB_PORT` defaults to `5432`).
   - Keep all database DDL and incremental migrations in `db/sqlite/` and `db/postgres/` (`full_schema.sql` plus matching `migration_vXXXXXXX.sql` files across both engines); `build.rs` embeds them at compile time and fails the build on version mismatch.
   - PostgreSQL objects reside in the `golinks` schema (connections set `search_path=golinks`), while SQLite uses the default `main` schema.
   - All link queries and mutations (`list_links`, `get_link_target`, `save_link`, `delete_link`) must remain scoped by `user_id` to preserve multi-user data isolation.
4. **Privacy (Public Repo):**
   - Never commit personal domains, personal self-hosted service names, or real secrets in code, tests, docs, or commit messages. Always use generic placeholders (`example.com`, `docs`, `notes`, `google`, `someSuperSecretValue`, etc.).

## Build, Test & Local Development

- **Backend tests:** `cargo test` (optionally set `GOLINKS_TEST_PG_HOST` to run `optional_postgres_end_to_end`).
- **Build frontend single-file bundle:** `npm --prefix frontend run build` (outputs `frontend/dist/index.html`, which `cargo run` loads automatically).
- **Frontend dev server (with API proxy to `:8080`):** `npm --prefix frontend run dev`
- **Run locally (PowerShell):**
  ```powershell
  $env:GOLINKS_USER_SECRET_KEY = "someSuperSecretValue"
  $env:GOLINKS_DB_PATH = "$env:TEMP\golinks.db"
  $env:GOLINKS_SECURE_COOKIE = "false"
  cargo run
  ```
- **Verification before committing:** Run `cargo test` for any Rust changes and `npm --prefix frontend run build` for any `frontend/` changes.

## Keeping Documentation Updated

Whenever you add features, change API contracts, add/rename environment variables, alter routing/auth behavior, or update build/release workflows, **update both `AGENTS.md` and `MEMORY.md`** (and `README.md` for user-facing changes) in the same task so future sessions stay accurate.
