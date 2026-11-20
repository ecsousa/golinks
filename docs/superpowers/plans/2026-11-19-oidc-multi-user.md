# OIDC Integration & Multi-User Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add generic OIDC authentication (targeted at Authentik) with automatic multi-user provisioning and unify session auth across both OIDC and non-OIDC modes onto HS256 JWT cookies with a configurable sliding-window expiration.

**Architecture:** Widen `users.user_name` to `VARCHAR(255)` (`v0000002`), replace raw-HMAC session cookies with compact HS256 JWTs signed per-user with `users.user_secret` (sliding window extended on every valid request), and add an `openidconnect`-based OIDC service (`rustls`-only) using `/` as the callback URI with a stateless HMAC-signed `golinks_oidc_state` cookie.

**Tech Stack:** Rust 2024, Axum 0.8, Tokio, `sqlx` (SQLite + PostgreSQL), `openidconnect` 4 + `reqwest` (`rustls-tls`), `hmac`/`sha2`/`subtle`/`base64`/`getrandom`, React 18 + Vite (`vite-plugin-singlefile`).

**Spec:** [docs/superpowers/specs/2026-11-19-oidc-multi-user-design.md](file:///C:/workspace/golinks/docs/superpowers/specs/2026-11-19-oidc-multi-user-design.md)

## Global Constraints

- Top-level paths (`/<keyword>`) belong exclusively to go-links; only `/` and `/favicon.ico` are reserved. OIDC callbacks MUST land on `GET /` (`?code=...&state=...` or `?error=...`).
- Zero OpenSSL dependencies: `reqwest` and `openidconnect` MUST use `rustls` (`default-features = false` + `rustls-tls`) so static `musl` cross-builds (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`) keep working.
- Security headers (`Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`) MUST remain on every response, including OIDC redirects and errors.
- All link queries and mutations MUST remain scoped by `user_id`.
- `build.rs` enforces identical migration versions across `db/sqlite/` and `db/postgres/`.
- Privacy: use only generic placeholders (`example.com`, `auth.example.com`, `go.example.com`, `alice`, `bob`) in all code, tests, docs, and commits.

## Review Focus

- **Open-redirect via `next` in OIDC state:** An attacker crafting `/?next=//evil.com` or `/?next=https://evil.com` before OIDC redirect must have `next` sanitized back to `/` both when building state and when redirecting after callback (pinned in Task 4 & Task 5).
- **Multiple `golinks_auth` cookies in one `Cookie` header:** A browser sending a stale cookie alongside a valid one must still authenticate if any `golinks_auth` cookie is valid (pinned in Task 3).
- **Cross-user cookie in single-user mode:** A valid JWT signed for user `bob` in the DB must be rejected when `GOLINKS_OIDC_ENABLED=false` and `active_user_id` is `golinks` (pinned in Task 5).
- **Username claim missing from ID token but present in `userinfo`:** OIDC providers (including some Authentik scope mappings) may omit `preferred_username` from the ID token and only return it from `/userinfo`; callback must seamlessly fall back to `userinfo` (pinned in Task 4 & Task 5).
- **OIDC provider temporarily unreachable at startup:** Starting `golinks` before Authentik finishes booting in Docker Compose must not crash-loop; startup logs a warning and retries discovery lazily on the first OIDC request (pinned in Task 4).

---

### File Structure

- `db/sqlite/full_schema.sql` & `db/postgres/full_schema.sql` — Widen `users.user_name` to `VARCHAR(255)`.
- `db/sqlite/migration_v0000002.sql` & `db/postgres/migration_v0000002.sql` — Incremental migration `v0000002`.
- `src/db/mod.rs` — Add `Database::get_or_create_user` (preserves existing `user_secret`, race-safe).
- `src/db/migrations.rs` — Update tests for `v0000002`.
- `src/db/config.rs` — Add `AuthConfig`, `OidcConfig`, `GOLINKS_OIDC_ENABLED`, `GOLINKS_SESSION_TTL_DAYS`, and `GOLINKS_OIDC_*` parsing.
- `src/auth.rs` — Add `generate_random_user_secret`, HS256 JWT `sign_session_jwt` / `parse_unverified_jwt` / `verify_jwt_signature`, and `build_auth_cookie(token, max_age_secs, secure)`.
- `src/oidc.rs` *(new)* — `OidcService` (lazy/cached discovery + 24h refresh + retry on verification failure), stateless signed `golinks_oidc_state` cookie, `build_authorize_redirect`, `handle_callback`, `sanitize_next_path`.
- `src/main.rs` — Unify `AppState` (`AuthMode::SingleUser` / `AuthMode::Oidc`), sliding-window JWT auth helper across all routes, OIDC redirect/callback on `/` and `/<keyword>`, `oidcEnabled` on `401` JSON, and full integration tests.
- `frontend/src/api.js` & `frontend/src/App.jsx` — Handle `oidcEnabled: true` on `401` by navigating to `/` instead of rendering `<LoginPage />`.
- `README.md`, `AGENTS.md`, `MEMORY.md` — Document OIDC + Authentik setup, env vars, unified sliding-window JWTs, and `v0000002` schema.

---

### Task 1: Database Migration `v0000002` & `get_or_create_user`

**Files:**
- Modify: `db/sqlite/full_schema.sql:8-14`
- Modify: `db/postgres/full_schema.sql:10-16`
- Create: `db/sqlite/migration_v0000002.sql`
- Create: `db/postgres/migration_v0000002.sql`
- Modify: `src/db/migrations.rs:282-324,551-561`
- Modify: `src/db/mod.rs:154-221` (and tests)

**Interfaces:**
- Produces: `Database::get_or_create_user(&self, user_name: &str, new_secret: &str) -> Result<User, DbError>` in `src/db/mod.rs`.

- [ ] **Step 1: Write failing tests for `v0000002` and `get_or_create_user`**

In `src/db/mod.rs` tests, add `get_or_create_user_preserves_existing_secret_supports_255_chars_and_handles_concurrency`:
- Creates a 255-char username `"u".repeat(255)` with `"a".repeat(64)` -> succeeds, returns that secret.
- Calls `get_or_create_user` again with same username and `"b".repeat(64)` -> returns identical `user_id` and keeps `"a".repeat(64)`.
- Clears `user_secret` to `""` via SQL `UPDATE users SET user_secret = '' WHERE user_id = ?`, then calls `get_or_create_user` with `"c".repeat(64)` -> returns identical `user_id` with rotated `user_secret == "c".repeat(64)`.
- Runs 4 concurrent `get_or_create_user("alice", ...)` calls with distinct secrets -> all 4 return the exact same `User` (same `user_id` and same winning `user_secret`), and `COUNT(*)` for `"alice"` is `1`.

In `src/db/migrations.rs` tests, update `fresh_sqlite_creates_parent_dir_and_runs_full_schema` and `embedded_postgres_schema_contains_golinks_schema_and_tables` to assert `latest_version == "v0000002"`, and update synthetic migration versions in `applies_pending_migrations_in_order` / `failed_migration_rolls_back_records_failure_and_blocks_next_startup` to `"v0000003"` / `"v0000004"`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test db::`
Expected: FAIL (`get_or_create_user` not found, version mismatch `v0000001` vs `v0000002`).

- [ ] **Step 3: Add `v0000002` migration files and update `full_schema.sql`**

- In `db/sqlite/full_schema.sql` and `db/postgres/full_schema.sql`, change `user_name VARCHAR(32) NOT NULL UNIQUE` to `user_name VARCHAR(255) NOT NULL UNIQUE`.
- Create `db/postgres/migration_v0000002.sql`:
  ```sql
  ALTER TABLE golinks.users ALTER COLUMN user_name TYPE VARCHAR(255);
  ```
- Create `db/sqlite/migration_v0000002.sql`:
  ```sql
  -- SQLite VARCHAR columns have unbounded TEXT affinity; no table rebuild is needed.
  SELECT 1;
  ```

- [ ] **Step 4: Implement `Database::get_or_create_user` in `src/db/mod.rs`**

Signature: `pub async fn get_or_create_user(&self, user_name: &str, new_secret: &str) -> Result<User, DbError>`.
Check `get_user_by_name(user_name)` first; if `Some(u)`: if `!u.user_secret.trim().is_empty()`, return `Ok(u)`; otherwise `UPDATE users SET user_secret = ?, updated_on = CURRENT_TIMESTAMP WHERE user_id = ? AND TRIM(user_secret) = '' RETURNING user_id, user_name, user_secret` (with `$1, $2` for Postgres, falling back to `get_user_by_id` if a concurrent login already rotated it). If `None`, run `INSERT INTO users (user_name, user_secret) VALUES (?, ?) ON CONFLICT (user_name) DO NOTHING RETURNING user_id, user_name, user_secret` (with `$1, $2` for Postgres); if `None` (concurrent insert), re-fetch via `get_user_by_name(user_name)`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test db::`
Expected: PASS (all `db::migrations::tests` and `db::tests` pass).

- [ ] **Step 6: Commit**

```bash
git add db/ src/db/mod.rs src/db/migrations.rs
git commit -m "feat(db): widen user_name to VARCHAR(255) and add get_or_create_user"
```

---

### Task 2: Configuration (`AuthConfig`, `OidcConfig`, `GOLINKS_SESSION_TTL_DAYS`)

**Files:**
- Modify: `src/db/config.rs`
- Modify: `src/main.rs:437-517` (minimal update to unpack `AppConfig.auth` so crate compiles)

**Interfaces:**
- Produces in `src/db/config.rs`:
  - `pub const DEFAULT_SESSION_TTL_DAYS: u64 = 30;`
  - `pub const MAX_USERNAME_CHARS: usize = 255;`
  - `pub struct OidcConfig { pub issuer_url: String, pub client_id: String, pub client_secret: String, pub redirect_uri: String, pub scopes: Vec<String>, pub username_claim: String }`
  - `pub enum AuthConfig { SingleUser { username: String, user_secret_key: String }, Oidc(OidcConfig) }`
  - `pub struct AppConfig { pub auth: AuthConfig, pub session_ttl_days: u64, pub db: DbConfig }`
  - `pub fn parse_bool_str(raw: &str) -> Result<bool, String>` (accepts `true`/`1`/`yes`/`on` and `false`/`0`/`no`/`off`, case-insensitive; errors on invalid values).

- [ ] **Step 1: Write failing config tests in `src/db/config.rs`**

Update existing tests to read `cfg.auth` (`AuthConfig::SingleUser { username, user_secret_key }`) and `cfg.session_ttl_days == 30`, and add tests:
- `session_ttl_days_defaults_to_30_and_validates_bounds`: missing -> `30`; `"7"` -> `7`; `"0"` -> Err; `"3651"` -> Err; `"abc"` -> Err.
- `oidc_enabled_ignores_single_user_vars_and_uses_defaults`: `GOLINKS_OIDC_ENABLED=true` + `GOLINKS_OIDC_ISSUER_URL`, `GOLINKS_OIDC_CLIENT_ID`, `GOLINKS_OIDC_CLIENT_SECRET`, `GOLINKS_OIDC_REDIRECT_URI` (without `GOLINKS_USER_SECRET_KEY`/`GOLINKS_USERNAME`) -> `AuthConfig::Oidc` with `scopes == ["openid", "profile", "email"]`, `username_claim == "preferred_username"`.
- `oidc_enabled_requires_all_mandatory_vars_and_valid_urls`: missing each of the 4 required vars fails; non-`http(s)://` issuer or redirect URI fails; custom `GOLINKS_OIDC_SCOPES="profile groups"` prepends `"openid"`; custom `GOLINKS_OIDC_USERNAME_CLAIM="email"` is respected; invalid `GOLINKS_OIDC_ENABLED="maybe"` fails.
- `username_allows_up_to_255_chars_and_rejects_256`: 255-char `GOLINKS_USERNAME` succeeds, 256-char fails.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test db::config::`
Expected: FAIL (`AuthConfig`, `OidcConfig`, `session_ttl_days` not defined).

- [ ] **Step 3: Implement `AuthConfig`, `OidcConfig`, and `session_ttl_days` in `src/db/config.rs` and update `main()` in `src/main.rs`**

- Implement parsing in `AppConfig::from_lookup` according to Spec §5.1.
- In `src/main.rs::main()`, match `app_cfg.auth`: handle `AuthConfig::SingleUser` as before, and for `AuthConfig::Oidc(_)` temporarily exit with `"OIDC mode not yet wired"` (replaced in Task 5) so the binary compiles and all existing tests stay green.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS (all unit and integration tests pass).

- [ ] **Step 5: Commit**

```bash
git add src/db/config.rs src/main.rs
git commit -m "feat(config): add OIDC and session TTL configuration"
```

---

### Task 3: Unified HS256 JWT Session Auth & Random Secret Generation (`src/auth.rs`)

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/auth.rs`

**Interfaces:**
- Produces in `src/auth.rs`:
  - `pub const AUTH_COOKIE_NAME: &str = "golinks_auth";`
  - `pub struct SessionClaims { pub sub: String, pub iat: u64, pub exp: u64 }`
  - `pub fn generate_random_user_secret() -> String` (64-char lowercase hex from 32 random bytes via `getrandom`)
  - `pub fn sign_session_jwt(user_name: &str, user_secret: &str, now_secs: u64, ttl_secs: u64) -> String`
  - `pub fn parse_unverified_jwt(token: &str) -> Option<(SessionClaims, String, Vec<u8>)>` (validates 3 segments, header `alg == "HS256"`, valid JSON `SessionClaims` with non-empty `sub`, returns `(claims, signing_input, sig_bytes)`)
  - `pub fn verify_jwt_signature(signing_input: &str, sig_bytes: &[u8], user_secret: &str) -> bool` (returns `false` immediately if `user_secret.trim().is_empty()`; otherwise constant-time HMAC-SHA256)
  - `pub fn extract_cookie_values<'a>(headers: &'a HeaderMap, cookie_name: &str) -> Vec<&'a str>` (returns all values matching `cookie_name` across all `Cookie` headers, supporting multiple cookies of the same name)
  - `pub fn build_auth_cookie(token: &str, max_age_secs: u64, secure: bool) -> String`
  - `pub fn current_unix_secs() -> u64`
  - Keeps `derive_auth_token` and `constant_time_eq` (and keeps `is_authenticated` temporarily until Task 5 removes it, so `main.rs` stays green).

- [ ] **Step 1: Add `base64 = "0.22"` and `getrandom = "0.2"` to `Cargo.toml` and write failing unit tests in `src/auth.rs`**

Add tests in `src/auth.rs`:
- `generate_random_user_secret_is_64_hex_and_unique`: two calls are 64 ASCII hex chars and unequal.
- `jwt_sign_parse_and_verify_roundtrip`: signs for `"alice"` with secret, parses claims (`sub == "alice"`, `iat == 1_700_000_000`, `exp == 1_700_000_000 + 86_400`), verifies signature with right secret (`true`) and wrong secret (`false`).
- `jwt_rejects_tampered_payload_non_hs256_alg_and_malformed_tokens`: tampered payload fails signature; `{"alg":"none"}` header returns `None` from `parse_unverified_jwt`; 2-part token returns `None`; empty `sub` returns `None`; empty `user_secret` returns `false` from `verify_jwt_signature` even if signed with `""`.
- `extract_cookie_values_returns_all_matching_cookies`: header `"golinks_auth=stale; other=1; golinks_auth=fresh"` returns `vec!["stale", "fresh"]`.
- `build_auth_cookie_sets_max_age_and_secure_flag`: verifies `HttpOnly`, `SameSite=Lax`, `Path=/`, `Max-Age=2592000`, and conditional `Secure`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test auth::`
Expected: FAIL (new functions not defined).

- [ ] **Step 3: Implement JWT helpers, random secret generator, and cookie extractor in `src/auth.rs`**

Use `base64::engine::general_purpose::URL_SAFE_NO_PAD` for compact JWS encoding/decoding, `getrandom::getrandom(&mut buf)` for 32 random bytes, and `Hmac<Sha256>` + `subtle::ConstantTimeEq` for signature verification.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test auth::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/auth.rs
git commit -m "feat(auth): add HS256 JWT session signing, verification, and random secret generator"
```

---

### Task 4: OIDC Service (`src/oidc.rs`)

**Files:**
- Modify: `Cargo.toml` (add `openidconnect`, `reqwest` with `rustls-tls` and `default-features = false`; add `rsa` / `rand` or `ring` in `dev-dependencies` for mock OIDC provider tests)
- Create: `src/oidc.rs`
- Modify: `src/main.rs` (declare `mod oidc;`)

**Interfaces:**
- Consumes: `crate::db::config::OidcConfig`, `crate::auth::{constant_time_eq, current_unix_secs, extract_cookie_values}`
- Produces in `src/oidc.rs`:
  - `pub const OIDC_STATE_COOKIE_NAME: &str = "golinks_oidc_state";`
  - `pub struct OidcService` (Cloneable via `Arc` or internal `Arc`s)
  - `pub enum OidcError { ProviderUnavailable(String), InvalidState(String), TokenExchange(String), InvalidIdToken(String), MissingUsernameClaim(String), InvalidUsername(String) }`
  - `pub fn sanitize_next_path(raw: Option<&str>) -> String` (returns `"/"` unless `raw` starts with `'/'`, does not start with `"//"`, and contains none of `'\\'`, `'\r'`, `'\n'`)
  - `pub fn build_clear_state_cookie(secure: bool) -> String`
  - `impl OidcService`:
    - `pub fn new(config: OidcConfig) -> Result<Self, String>`
    - `pub async fn warm_discovery(&self)` (attempts discovery at startup; logs warning on failure without failing startup)
    - `pub async fn start_login(&self, next_path: &str, secure_cookie: bool) -> Result<(String, String), OidcError>` (returns `(authorize_url, set_state_cookie_header)`)
    - `pub async fn complete_callback(&self, headers: &HeaderMap, code: &str, state: &str) -> Result<(String, String), OidcError>` (returns `(username, sanitized_next_path)`)

- [ ] **Step 1: Add `openidconnect` and `reqwest` (`rustls-tls`, no default features) to `Cargo.toml` and write unit + mock-provider tests in `src/oidc.rs`**

Add tests in `src/oidc.rs`:
- `sanitize_next_path_rejects_open_redirects`: `None` -> `"/"`, `Some("//evil.com")` -> `"/"`, `Some("https://evil.com")` -> `"/"`, `Some("/a\\b")` -> `"/"`, `Some("/docs?a=1")` -> `"/docs?a=1"`.
- `state_cookie_sign_verify_and_expiry`: roundtrip passes; tampered signature rejected; expired `exp` rejected; wrong `client_secret` rejected.
- `mock_oidc_full_flow_extracts_claim_from_id_token_and_falls_back_to_userinfo`:
  - Spins up a lightweight local Axum mock OIDC server with an ephemeral RSA keypair serving `/.well-known/openid-configuration`, `/jwks`, `/token`, and `/userinfo`.
  - Tests `start_login("/docs", true)` -> returns authorize URL with `code_challenge`, `nonce`, `state`, and `golinks_oidc_state` cookie.
  - Tests `complete_callback` when `preferred_username` is in the ID token -> returns `("alice", "/docs")`.
  - Tests `complete_callback` when `preferred_username` is omitted from the ID token and only returned by `/userinfo` -> returns `("bob", "/docs")`.
  - Tests `warm_discovery` against an unreachable localhost port -> logs warning and does not panic, and subsequent call when server is up succeeds.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test oidc::`
Expected: FAIL (`src/oidc.rs` not implemented).

- [ ] **Step 3: Implement `src/oidc.rs`**

Key details:
- Build `reqwest::Client` with `redirect(reqwest::redirect::Policy::none())` and `rustls` TLS only.
- Cache `(CoreProviderMetadata, Instant)` inside `Arc<RwLock<Option<(CoreProviderMetadata, Instant)>>>` with 24-hour TTL; if ID token verification fails once, force-refresh metadata/JWKS and retry verification once.
- Derive `state_key = HMAC-SHA256(client_secret, "golinks-oidc-state-v1")` for signing `golinks_oidc_state` (`Max-Age=600`, `HttpOnly; SameSite=Lax; Path=/[; Secure]`).
- For username claim extraction: after `openidconnect` cryptographically verifies the ID token (signature, issuer, audience, nonce), decode the verified ID token's raw JSON payload (middle base64url segment) to read `config.username_claim` as a JSON string (supports arbitrary custom claim names like `preferred_username`, `email`, `sub`, `upn`, etc.). If absent or empty, fetch `userinfo` using the access token (`reqwest` GET with `Authorization: Bearer <token>`) and read `config.username_claim` from the JSON response. Trim and validate `1..=255` chars.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test oidc::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/oidc.rs src/main.rs
git commit -m "feat(oidc): implement OidcService with discovery caching, state cookie, and claim extraction"
```

---

### Task 5: Router, Unified Sliding-Window JWT Sessions, & OIDC Handlers (`src/main.rs`)

**Files:**
- Modify: `src/main.rs`
- Modify: `src/auth.rs` (remove obsolete `is_authenticated` helper if unused)

**Interfaces:**
- Consumes: `crate::db::config::{AppConfig, AuthConfig}`, `crate::auth::*`, `crate::oidc::{OidcService, build_clear_state_cookie, sanitize_next_path}`
- Updates `AppState` in `src/main.rs`:
  - `pub enum AuthMode { SingleUser { active_user_id: i32 }, Oidc(Arc<OidcService>) }`
  - `pub struct AppState { pub db: Database, pub auth_mode: AuthMode, pub session_ttl_secs: u64, pub secure_cookie: bool, pub favicon: FaviconData, pub ui_html: Arc<String> }`
  - Helper `async fn authenticate_session(state: &AppState, headers: &HeaderMap) -> Result<Option<(User, HeaderValue)>, Response>`: iterates `extract_cookie_values(headers, AUTH_COOKIE_NAME)`, parses unverified JWT, checks `exp > now`, loads user by `sub`, enforces `user.user_id == active_user_id` in `SingleUser` mode, verifies HMAC signature against `user.user_secret`, and returns `Ok(Some((user, refreshed_set_cookie)))`.

- [ ] **Step 1: Update existing integration tests and add new JWT + OIDC integration tests in `src/main.rs`**

Update existing single-user tests to use JWT cookies (`sign_session_jwt`) and assert `Max-Age=2592000` (30 days) on login + refreshed `Set-Cookie` on authenticated requests.
Add integration tests:
- `single_user_jwt_sliding_window_and_rejects_expired_or_other_user_jwt`:
  - Valid JWT with `exp` near expiry gets a refreshed `Set-Cookie` with new `exp > old_exp` on `GET /?action=getLinks`, `GET /docs`, and `POST /?action=saveLink`.
  - Expired JWT returns `401` on `/?action=getLinks` and redirects to `/?next=...` on `GET /docs`.
  - Valid JWT signed for a different DB user (`bob`) is rejected in single-user mode.
- `oidc_unauthenticated_root_and_keyword_redirect_directly_to_provider`:
  - `GET /` -> `302` to mock OIDC authorize URL with `Set-Cookie: golinks_oidc_state=...` and security headers.
  - `GET /docs` -> `302` to mock OIDC authorize URL with `next=/docs` in signed state cookie.
  - `GET /?next=//evil.com` -> `next` sanitized to `"/"`.
  - `GET /?action=getLinks` -> `401` with JSON `{ "error": "Unauthorized", "oidcEnabled": true }`.
  - `POST /?action=login` -> `403`.
- `oidc_callback_provisions_users_preserves_secret_and_isolates_links`:
  - Full login flow for `alice` (targeting `/docs`) -> creates `alice` with 64-char random `user_secret`, sets `golinks_auth` JWT, clears `golinks_oidc_state`, redirects to `/docs`.
  - Second login for `alice` -> keeps the exact same `user_secret` in DB.
  - Full login flow for `bob` (claim via `userinfo` fallback) -> creates `bob` with distinct `user_secret`.
  - `alice` saves `docs -> https://alice.example.com`; `bob` saves `docs -> https://bob.example.com`; `GET /docs` with each user's cookie redirects to their own target and returns a refreshed `Set-Cookie: golinks_auth=...`.
- `oidc_callback_errors_do_not_loop`:
  - `GET /?error=access_denied&state=abc` -> `401` (not `302`), clears `golinks_oidc_state`, includes security headers.
  - `GET /?code=abc&state=wrong` -> `400`, clears `golinks_oidc_state`, includes security headers.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test`
Expected: FAIL (`AuthMode`, `session_ttl_secs`, OIDC handlers not implemented).

- [ ] **Step 3: Implement unified JWT auth and OIDC handlers in `src/main.rs`**

- Expand `RootQuery` to `{ action: Option<String>, code: Option<String>, state: Option<String>, error: Option<String>, error_description: Option<String>, next: Option<String> }`.
- `GET /`:
  - `action` present -> dispatch API action (`getLinks`, etc.).
  - Else in OIDC mode:
    - If `error` present -> clear `golinks_oidc_state` and return `401` plain text error.
    - If `code` present -> require `state`, run `oidc.complete_callback`, provision/load user via `db.get_or_create_user(&username, &auth::generate_random_user_secret())`, mint JWT cookie, clear `golinks_oidc_state`, `302 Found` to `next`.
    - Else -> `authenticate_session`; if authenticated, return `200` UI HTML with refreshed `Set-Cookie`; if not, call `oidc.start_login(&sanitize_next_path(query.next.as_deref()), state.secure_cookie)` and return `302 Found` with `golinks_oidc_state` cookie.
  - Else in SingleUser mode:
    - If `authenticate_session` succeeds, return `200` UI HTML with refreshed `Set-Cookie`; otherwise return `200` UI HTML (so `<LoginPage />` renders).
- `GET /<keyword>`:
  - `authenticate_session`; if unauthenticated:
    - SingleUser -> `302` to `/?next=...`.
    - OIDC -> `oidc.start_login(&sanitize_next_path(uri.path_and_query()), state.secure_cookie)` -> `302` directly to provider.
  - If authenticated -> look up link for `user.user_id` and return `302` (to target or `/#/edit/<key>`) with refreshed `Set-Cookie: golinks_auth=...`.
- `POST /?action=login`:
  - SingleUser -> verify `derive_auth_token(&req.secret)` against `user.user_secret`, mint JWT cookie, return `200 { "ok": true }`.
  - OIDC -> return `403` JSON error.
- `GET /?action=getLinks`, `POST /?action=saveLink`, `POST /?action=deleteLink`:
  - `authenticate_session`; if unauthenticated return `401` JSON `{ "error": "Unauthorized", "oidcEnabled": state.is_oidc() }`; if authenticated run DB op scoped to `user.user_id` and attach refreshed `Set-Cookie: golinks_auth=...`.
- Update `main()` to initialize either `AuthMode::SingleUser` (calling `sync_user`) or `AuthMode::Oidc` (calling `oidc.warm_discovery().await`), and wire `session_ttl_secs = app_cfg.session_ttl_days * 86_400`.
- Remove unused `auth::is_authenticated` from `src/auth.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS (all unit and integration tests pass with zero warnings).

- [ ] **Step 5: Commit**

```bash
git add src/main.rs src/auth.rs
git commit -m "feat(server): wire unified sliding-window JWT sessions and OIDC auth flow"
```

---

### Task 6: Frontend 401 OIDC Auto-Redirect (`frontend/`)

**Files:**
- Modify: `frontend/src/api.js:1-78`
- Modify: `frontend/src/App.jsx:25-75`

**Interfaces:**
- Consumes: Backend `401` JSON payload `{ "error": "Unauthorized", "oidcEnabled": boolean }`.
- Updates: `UnauthorizedError(oidcEnabled = false)` in `frontend/src/api.js`.

- [ ] **Step 1: Update `UnauthorizedError` and `401` handling in `frontend/src/api.js`**

On `resp.status === 401` in `getLinks`, `saveLink`, and `deleteLink`, parse the JSON body via `parseJsonSafe(resp)` and throw `new UnauthorizedError(Boolean(data.oidcEnabled))`.

- [ ] **Step 2: Update `frontend/src/App.jsx` to redirect on OIDC `401`**

- In `refreshLinks`: if `err instanceof UnauthorizedError`: if `err.oidcEnabled`, call `window.location.replace('/')` and return; otherwise `setStatus('unauthenticated')`.
- In `EditLink` -> `handleUnauthorized(oidcEnabled)`: if `oidcEnabled`, call `window.location.replace('/')`; otherwise `setStatus('unauthenticated')`. (Also pass `err.oidcEnabled` from `EditLink.jsx` when catching `UnauthorizedError`.)

- [ ] **Step 3: Build frontend bundle to verify**

Run: `npm --prefix frontend run build`
Expected: Build succeeds and outputs `frontend/dist/index.html` with zero errors.

- [ ] **Step 4: Commit**

```bash
git add frontend/src/
git commit -m "feat(frontend): auto-redirect to / on 401 when OIDC is enabled"
```

---

### Task 7: Documentation (`README.md`, `AGENTS.md`, `MEMORY.md`)

**Files:**
- Modify: `README.md`
- Modify: `AGENTS.md`
- Modify: `MEMORY.md`

- [ ] **Step 1: Update `README.md`**

- Update **Features** to mention generic OIDC multi-user authentication and unified sliding-window HS256 JWT sessions.
- Update **Environment Variables** table with `GOLINKS_OIDC_ENABLED`, `GOLINKS_SESSION_TTL_DAYS`, `GOLINKS_OIDC_ISSUER_URL`, `GOLINKS_OIDC_CLIENT_ID`, `GOLINKS_OIDC_CLIENT_SECRET`, `GOLINKS_OIDC_REDIRECT_URI`, `GOLINKS_OIDC_SCOPES`, `GOLINKS_OIDC_USERNAME_CLAIM`, and note that `GOLINKS_USER_SECRET_KEY` / `GOLINKS_USERNAME` are ignored when OIDC is enabled (and username max length is 255).
- Add a dedicated **OIDC & Authentik Setup** section with:
  - Step-by-step Authentik instructions (Create OAuth2/OpenID Provider, Confidential client, Redirect URI `https://go.example.com/`, Scopes `openid profile email`, attach to an Authentik Application, copy Issuer URL / Client ID / Client Secret).
  - Generic OIDC provider notes (PKCE S256, root `/` redirect URI, customizable `GOLINKS_OIDC_USERNAME_CLAIM`).
  - Example Docker / Docker Compose env config using generic `example.com` domains.

- [ ] **Step 2: Update `AGENTS.md` and `MEMORY.md`**

- Reflect `v0000002` schema (`users.user_name VARCHAR(255)`), `src/oidc.rs`, unified HS256 JWT + sliding window (`GOLINKS_SESSION_TTL_DAYS`), `GOLINKS_OIDC_*` env vars, OIDC callback on `GET /`, and frontend 401 redirect behavior.

- [ ] **Step 3: Run full verification suite**

Run: `cargo test` and `npm --prefix frontend run build`
Expected: All Rust tests pass; frontend single-file build succeeds.

- [ ] **Step 4: Commit**

```bash
git add README.md AGENTS.md MEMORY.md
git commit -m "docs: document OIDC integration, Authentik setup, and sliding-window JWT sessions"
```
