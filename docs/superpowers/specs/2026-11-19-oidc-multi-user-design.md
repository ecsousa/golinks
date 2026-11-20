# OIDC Integration & Multi-User Support Design

**Date:** 2026-11-19  
**Status:** Approved

## 1. Intent & Why

Enable `golinks` to serve multiple independent users (initially 1–3 users on a self-hosted Raspberry Pi 5 running Docker with PostgreSQL and Authentik) using any standard OpenID Connect (OIDC) provider, while preserving backward compatibility for single-user secret-key deployments.

At the same time, unify session authentication across both OIDC and non-OIDC modes onto signed HS256 JWT cookies with a configurable sliding-window expiration (defaulting to 30 days), so both modes share one simple, auditable session mechanism.

## 2. Goals, Non-Goals, and Anti-Goals

### Goals
- **Generic OIDC support** gated behind `GOLINKS_OIDC_ENABLED` (default `false`), tested and documented with Authentik.
- **Zero-click OIDC login:** Unauthenticated requests to `/` or `/<keyword>` redirect directly (`302 Found`) to the OIDC provider—no intermediate "Sign in with OIDC" page.
- **Automatic multi-user provisioning:** On successful OIDC callback, extract the configured username claim, create the user in `users` with a cryptographically random 64-char hex `user_secret` if absent, or preserve the existing `user_secret` if present. All link CRUD and redirects are scoped to the authenticated user's `user_id`.
- **Unified sliding-window JWT sessions:** Both OIDC and non-OIDC modes store an HS256 JWT (identifying the user and expiry, signed with `user.user_secret`) in `golinks_auth`. Every valid authenticated request refreshes the cookie with a new expiry extended by `GOLINKS_SESSION_TTL_DAYS` (default `30`).
- **Wider usernames:** Widen `users.user_name` from `VARCHAR(32)` to `VARCHAR(255)` via a database migration (`v0000002`) to accommodate OIDC username claims (e.g., emails or longer usernames).
- **Backward-compatible non-OIDC mode:** When `GOLINKS_OIDC_ENABLED=false`, `GOLINKS_USERNAME` and `GOLINKS_USER_SECRET_KEY` continue working with the existing `POST /?action=login` flow (issuing the unified JWT cookie instead of a raw HMAC token).
- **Setup documentation:** Add an Authentik + generic OIDC setup section to `README.md`, and update `AGENTS.md` and `MEMORY.md`.

### Non-Goals
- No in-memory caching for `users` or `links` (direct local SQLite/PostgreSQL queries are sub-millisecond for 1–3 users and keep the service stateless with immediate session-revocation consistency when `user_secret` changes). Only OIDC discovery metadata / JWKS is cached in memory.
- No UI redesign: no profile menu, user switcher, or logout button in this change.
- No OIDC RP-initiated logout or group/role-based authorization (any user permitted by the OIDC provider can use `golinks`).
- No shared/global links across users; every user's links remain strictly isolated by `user_id`.

### Anti-Goals
- **No keyword path collisions:** Do not reserve any new top-level path (like `/oidc/callback` or `/auth/callback`) that could collide with `/<keyword>`. Only `/` and `/favicon.ico` remain reserved.
- **No OpenSSL dependency:** Keep all HTTP/TLS dependencies on `rustls` so static Linux `musl` cross-compilation (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`) via `cross` continues working cleanly.
- **No redirect loops on OIDC errors:** Failed/cancelled OIDC callbacks or invalid state cookies must return an error response rather than redirecting back to the OIDC provider in a loop.

## 3. Constraints

- **Routing invariant:** Top-level paths (`/<keyword>`) belong exclusively to go-links. API endpoints live on `/` differentiated by `?action=...`. The single-file React bundle is served only at `GET /`.
- **Security headers:** `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, and `X-Content-Type-Options: nosniff` must remain on every response.
- **Database migrations:** `build.rs` enforces identical migration version lists across `db/sqlite/` and `db/postgres/`.
- **Privacy:** All docs, examples, and tests must use generic placeholders (`example.com`, `auth.example.com`, `go.example.com`, `alice`, `bob`, etc.).

## 4. Approaches Considered

### Approach A (Selected): `openidconnect` + `reqwest` (`rustls`) + minimal in-house HS256 JWT + signed state cookie
- Uses the `openidconnect` crate with `reqwest` (`rustls-tls`) for `.well-known/openid-configuration` discovery, PKCE (S256), authorization-code exchange, JWKS-backed ID token verification (signature, issuer, audience, nonce), and `userinfo` fallback.
- Implements compact HS256 JWT encode/verify directly on the existing `hmac`, `sha2`, `subtle`, and `serde_json` crates (plus `base64`), keeping dependencies minimal and `musl`-friendly.
- Stores OIDC transaction state (`state`, `nonce`, `pkce_verifier`, `next`, `exp`) in a short-lived `HttpOnly` signed cookie (`golinks_oidc_state`) MAC'd with a key derived from `GOLINKS_OIDC_CLIENT_SECRET`, keeping the server stateless.

### Approach B (Rejected): `openidconnect` + `jsonwebtoken` + in-memory login state map
- Uses `jsonwebtoken` for session JWTs and an in-memory `RwLock<HashMap>` for pending OIDC state.
- Rejected because in-memory state breaks across multiple replicas without sticky sessions and `jsonwebtoken` adds another crypto dependency surface to keep aligned across release targets.

### Approach C (Rejected): Hand-rolled OIDC HTTP calls without `openidconnect`
- Rejected because manually implementing JWKS verification, key rotation, PKCE, and nonce checks is error-prone and unnecessary when `openidconnect` handles them directly.

## 5. Detailed Design

### 5.1 Configuration (`src/db/config.rs`)

| Variable | Default | Required When | Description |
| --- | --- | --- | --- |
| `GOLINKS_OIDC_ENABLED` | `false` | Optional | Enables OIDC multi-user mode (`true`/`1`/`yes`/`on` vs `false`/`0`/`no`/`off`). |
| `GOLINKS_SESSION_TTL_DAYS` | `30` | Optional | Sliding-window session duration in days (integer `>= 1`) for both OIDC and non-OIDC JWT cookies. |
| `GOLINKS_USER_SECRET_KEY` | *(none)* | `GOLINKS_OIDC_ENABLED=false` | Secret key for single-user login; ignored when OIDC is enabled. |
| `GOLINKS_USERNAME` | `golinks` | `GOLINKS_OIDC_ENABLED=false` | Active single-user username (1–255 chars); ignored when OIDC is enabled. |
| `GOLINKS_OIDC_ISSUER_URL` | *(none)* | `GOLINKS_OIDC_ENABLED=true` | OIDC issuer URL (e.g., `https://auth.example.com/application/o/golinks/`). Must be `http://` or `https://`. |
| `GOLINKS_OIDC_CLIENT_ID` | *(none)* | `GOLINKS_OIDC_ENABLED=true` | OIDC client ID. |
| `GOLINKS_OIDC_CLIENT_SECRET` | *(none)* | `GOLINKS_OIDC_ENABLED=true` | OIDC client secret (also used to derive the HMAC key for `golinks_oidc_state`). |
| `GOLINKS_OIDC_REDIRECT_URI` | *(none)* | `GOLINKS_OIDC_ENABLED=true` | Full callback URI registered with the OIDC provider, pointing to the app root (e.g., `https://go.example.com/`). Must be `http://` or `https://`. |
| `GOLINKS_OIDC_SCOPES` | `openid profile email` | Optional (OIDC) | Whitespace-separated OIDC scopes. `openid` is always included even if omitted. |
| `GOLINKS_OIDC_USERNAME_CLAIM` | `preferred_username` | Optional (OIDC) | Claim name in ID token / `userinfo` response used as `users.user_name`. |

`AppConfig` stores `auth: AuthConfig` where:
- `AuthConfig::SingleUser { username, user_secret_key }` when `GOLINKS_OIDC_ENABLED=false`
- `AuthConfig::Oidc(OidcConfig)` when `GOLINKS_OIDC_ENABLED=true`
- Plus `session_ttl_days: u64` (default `30`, validated `>= 1` and `<= 3650` to avoid `u64` overflow in seconds).

### 5.2 Database Schema & Queries (`db/`, `src/db/mod.rs`)

- **Schema update (`v0000002`):**
  - Update `db/sqlite/full_schema.sql` and `db/postgres/full_schema.sql` so `users.user_name` is `VARCHAR(255) NOT NULL UNIQUE`.
  - Add `db/postgres/migration_v0000002.sql`:
    ```sql
    ALTER TABLE golinks.users ALTER COLUMN user_name TYPE VARCHAR(255);
    ```
  - Add `db/sqlite/migration_v0000002.sql`:
    ```sql
    -- SQLite VARCHAR columns have unbounded TEXT affinity; no table rebuild is needed.
    SELECT 1;
    ```
    *(Builder's call / safety note: avoids rebuilding `users` while `PRAGMA foreign_keys = ON` inside a transaction, which would otherwise risk cascading deletes on `links`.)*
- **User provisioning (`Database::get_or_create_user`):**
  - Accepts `(user_name: &str, new_secret: &str) -> Result<User, DbError>`.
  - First checks `get_user_by_name(user_name)`. If found and `user_secret` is non-empty, returns the existing `User` unchanged (preserving `user_secret`).
  - If found with an empty `user_secret` (e.g., cleared manually in the DB to force session revocation/rotation), updates `user_secret = new_secret` and `updated_on = CURRENT_TIMESTAMP`, and returns the updated `User`.
  - If absent, executes `INSERT INTO users (user_name, user_secret) VALUES (?, ?) ON CONFLICT (user_name) DO NOTHING RETURNING user_id, user_name, user_secret` (and falls back to `get_user_by_name` if a concurrent insert won the race).
  - Existing `sync_user` remains for single-user mode startup.

### 5.3 Unified HS256 JWT Session Auth (`src/auth.rs`)

- **Random secret generation:** `generate_random_user_secret() -> String` generates 32 cryptographically secure random bytes (via `getrandom`) and hex-encodes them into a 64-character lowercase hex string.
- **JWT format (HS256):**
  - Header: `{"alg":"HS256","typ":"JWT"}`
  - Payload: `{"sub":"<user_name>","iat":<unix_secs>,"exp":<unix_secs>}` where `exp = iat + session_ttl_secs`.
  - Signing input: `"{base64url(header)}.{base64url(payload)}"`
  - Signature: `base64url(HMAC-SHA256(key = user.user_secret.as_bytes(), data = signing_input))`
- **Verification flow (`authenticate_request`):**
  1. Scan all `Cookie` headers for `golinks_auth=<token>`.
  2. Parse 3 dot-separated segments, decode header (`alg == "HS256"`), decode payload (`sub`, `exp`).
  3. Reject if `sub` is empty or `exp <= now_unix_secs`.
  4. Look up `user = db.get_user_by_name(&claims.sub)`.
     - In `SingleUser` mode, also require `user.user_id == active_user_id`.
  5. Reject if `user.user_secret.is_empty()` (prevents forging tokens while a secret is cleared for rotation). Recompute `HMAC-SHA256(user.user_secret, signing_input)` and compare against the decoded signature using `subtle::ConstantTimeEq`.
  6. On success, mint a fresh JWT with `exp = now + session_ttl_secs` and return `(user, Set-Cookie header)`.
- **Cookie attributes:**
  - `golinks_auth=<jwt>; HttpOnly; SameSite=Lax; Path=/; Max-Age=<session_ttl_secs>[; Secure]`
- **Upgrade note for existing non-OIDC users:** Previous raw-HMAC cookies are not valid JWTs and will be rejected on first request after upgrade, prompting a one-time re-login.

### 5.4 OIDC Client & Callback Flow (`src/oidc.rs`, `src/main.rs`)

- **Discovery & caching:**
  - `OidcService` holds `OidcConfig`, a shared `reqwest::Client` (built with `rustls-tls`, redirects disabled per `openidconnect` SSRF recommendation), and a `tokio::sync::RwLock<Option<CachedOidcClient>>` storing the discovered `CoreProviderMetadata` + `CoreClient` + fetch timestamp.
  - On startup (when OIDC is enabled), attempt discovery once; if the OIDC provider is not yet reachable (e.g., Authentik still booting in the same Docker Compose stack), log a warning and retry lazily on the first OIDC request instead of crash-looping.
  - Refresh cached metadata/JWKS when older than 24 hours (or once on ID token verification failure to handle provider key rotation seamlessly).
- **Callback URL:**
  - Uses the root path `/` (`GOLINKS_OIDC_REDIRECT_URI`, e.g., `https://go.example.com/`).
  - When `GOLINKS_OIDC_ENABLED=true`, `GET /` inspects query parameters:
    - If `action` is present → handle API action (`getLinks`, etc.).
    - Else if `code` or `error` is present → handle OIDC callback.
    - Else → authenticate `golinks_auth` JWT cookie; if valid, serve UI HTML with refreshed `Set-Cookie`; if missing/invalid, initiate OIDC redirect (preserving sanitized `?next=...` if present, else `"/"`).
- **Stateless signed state cookie (`golinks_oidc_state`):**
  - Payload JSON: `{ "state": "...", "nonce": "...", "pkce_verifier": "...", "next": "...", "exp": <now + 600> }`.
  - Encoded as `base64url(payload).base64url(HMAC-SHA256(state_key, base64url(payload)))`, where `state_key = HMAC-SHA256(client_secret, "golinks-oidc-state-v1")`.
  - Cookie attributes: `HttpOnly; SameSite=Lax; Path=/; Max-Age=600[; Secure]`.
  - Cleared (`Max-Age=0`) on callback completion or error.
- **Callback handling:**
  1. If query contains `error`: clear `golinks_oidc_state` and return `401 Unauthorized` with a plain error page/text (no redirect loop).
  2. Require both `code` and `state` query params; verify `golinks_oidc_state` cookie signature, `exp > now`, and constant-time `state` equality. On failure, clear `golinks_oidc_state` and return `400 Bad Request`.
  3. Exchange `code` + `pkce_verifier` with the token endpoint.
  4. Verify ID token (signature, issuer, audience, `nonce`).
  5. Extract username from `GOLINKS_OIDC_USERNAME_CLAIM`:
     - First inspect the ID token's raw JSON claims payload (already cryptographically verified by `openidconnect`) for a string value at `username_claim`.
     - If absent or empty, fetch the `userinfo` endpoint (if advertised in provider metadata) using the access token and extract `username_claim` as a string.
     - Trim and validate non-empty and `<= 255` chars; otherwise return `403 Forbidden`.
  6. Provision/load user via `db.get_or_create_user(&username, &auth::generate_random_user_secret())`.
  7. Mint session JWT, set `golinks_auth` cookie, clear `golinks_oidc_state` cookie, and redirect (`302 Found`) to sanitized `next` (default `"/"`).
- **Unauthenticated `GET /<keyword>`:**
  - Non-OIDC mode: redirects (`302 Found`) to `/?next=<encoded path_and_query>` (unchanged).
  - OIDC mode: redirects (`302 Found`) directly to the OIDC provider authorization URL, storing `next = path_and_query` in `golinks_oidc_state` so the user lands directly on `/<keyword>` after login.
- **Authenticated `GET /<keyword>`:**
  - Validates JWT cookie, looks up link scoped to `user.user_id`, and returns `302 Found` to target (or `/#/edit/<key>`) **with** the refreshed `Set-Cookie: golinks_auth=...` header.
- **API Endpoints (`/?action=...`):**
  - `GET /?action=getLinks`, `POST /?action=saveLink`, `POST /?action=deleteLink`:
    - Require valid JWT cookie; on success, attach refreshed `Set-Cookie: golinks_auth=...` to the `200 OK` response.
    - On `401 Unauthorized`: return `{ "error": "Unauthorized", "oidcEnabled": <bool> }`.
  - `POST /?action=login`:
    - In non-OIDC mode: validates `derive_auth_token(&req.secret)` against `user.user_secret` in constant time, mints JWT cookie, returns `200 { "ok": true }`.
    - In OIDC mode: returns `403 Forbidden` (`{ "error": "Password login is disabled when OIDC is enabled." }`).

### 5.5 Frontend Changes (`frontend/`)

- `api.js`: `UnauthorizedError` carries `oidcEnabled` (parsed from the `401` JSON body).
- `App.jsx`: When `UnauthorizedError` has `oidcEnabled === true` (e.g., session expired while the tab was left open), call `window.location.replace('/')` to trigger the backend's direct OIDC redirect instead of rendering `<LoginPage />`.
- Non-OIDC behavior remains identical.

### 5.6 Testing & Verification Strategy

- **Unit tests:**
  - `src/auth.rs`: HS256 JWT encode/decode, expiry rejection, tampered signature/payload rejection, wrong user secret rejection, random secret format, `golinks_oidc_state` signing/verification/expiry.
  - `src/db/config.rs`: `GOLINKS_OIDC_ENABLED` true/false, `GOLINKS_SESSION_TTL_DAYS` defaults/bounds, required OIDC vars, ignoring `GOLINKS_USER_SECRET_KEY`/`GOLINKS_USERNAME` when OIDC is enabled.
  - `src/db/mod.rs` & `src/db/migrations.rs`: `v0000002` migration on both SQLite and PostgreSQL schema assertions, 255-char username insert, `get_or_create_user` preserving existing secret and handling concurrent inserts.
- **Integration tests (`src/main.rs`):**
  - Non-OIDC mode: login issues JWT cookie, authenticated requests slide `exp` forward and return refreshed `Set-Cookie`, expired/tampered JWTs are rejected.
  - OIDC mode with a local mock OIDC server (Axum test server serving `.well-known/openid-configuration`, JWKS, token endpoint, and `userinfo` endpoint using an ephemeral RSA key):
    - Unauthenticated `GET /` and `GET /docs` redirect directly to mock OIDC authorize URL with `golinks_oidc_state` cookie.
    - Callback with valid `code` + `state` creates user with random secret, sets `golinks_auth` JWT, clears `golinks_oidc_state`, and redirects to `next`.
    - Second login for the same user preserves the existing `user_secret`.
    - Two distinct OIDC users (`alice` and `bob`) have isolated links and cannot access each other's links.
    - Sliding window refreshes `golinks_auth` cookie on `GET /`, `GET /<keyword>`, and `/?action=...`.
    - Error cases: OIDC `error` param returns `401` without redirect loop; mismatched/missing `state` returns `400`; `POST /?action=login` returns `403`; `401` on `/?action=getLinks` includes `oidcEnabled: true`.
- **Frontend build:** `npm --prefix frontend run build`.

### 5.7 Documentation Updates

- **`README.md`:** Document `GOLINKS_OIDC_ENABLED`, `GOLINKS_SESSION_TTL_DAYS`, and all `GOLINKS_OIDC_*` variables; add a step-by-step **OIDC & Authentik Setup** section (creating OAuth2/OIDC Provider + Application in Authentik, setting Redirect URI to `https://go.example.com/`, configuring `golinks` env vars, Docker Compose example).
- **`AGENTS.md` & `MEMORY.md`:** Update auth invariants, environment variables, schema version (`v0000002`), and OIDC architecture notes.

## 6. Left to the Builder

- Exact crate versions in `Cargo.toml` (`openidconnect`, `reqwest`, `base64`, `getrandom` / `rand`, plus `rsa` or `ring` in `dev-dependencies` for the mock OIDC JWKS test server) chosen to compile cleanly with Rust 2024 and `rustls`.
- Exact error HTML/text formatting for failed OIDC callbacks (`400`/`401`/`403`).
- Helper struct/module decomposition within `src/auth.rs` and `src/oidc.rs`.
