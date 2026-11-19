# Database Storage & Migration Layer Design

Date: 2026-11-19
Status: Ready for approval

## Intent & Why

Move `golinks` persistence out of the single-file YAML config (`GOLINKS_FILE` + `notify` file watcher) into a relational database supporting both **SQLite** and **PostgreSQL**. This establishes the relational schema (`users`, `links`, `schema_migration`) and user-scoped data access layer needed for future multi-user support and future system-generated JWT signing secrets, while preserving single-user runtime behavior for now.

## Goals

- Support **SQLite** (default) and **PostgreSQL** via `GOLINKS_DB_ENGINE`.
- Move auth configuration out of YAML into environment variables: `GOLINKS_USER_SECRET_KEY` (required) and `GOLINKS_USERNAME` (optional, default `golinks`).
- Provide an embedded SQL schema & migration system under `./db/sqlite/` and `./db/postgres/`, versioned in `schema_migration` (`v0000001`, `v0000002`, ...).
- Create `users` and `links` tables (in schema `golinks` on PostgreSQL; default `main` schema on SQLite) with unique constraints and foreign key enforcement.
- Sync the configured user and derived secret into `users` on startup after migrations succeed.
- Route all link reads and writes through user-scoped DB repository methods (`user_id` / `user_name` parameters) so multi-user support plugs in cleanly later.
- Preserve all existing HTTP routes, API contracts (`/?action=...`), cookie semantics, security headers, redirect/URL-encoding behavior, and frontend compatibility.
- Keep all 6 CI release targets and slim `debian:bookworm-slim` Docker images self-contained with no runtime native DB library dependencies or glibc version mismatch.
- Update `Dockerfile`, `Dockerfile.release`, `.github/workflows/docker-build.yml`, `.github/workflows/release.yml`, `AGENTS.md`, `MEMORY.md`, and `README.md`.

## Non-Goals (Out of Scope)

- Actual multi-user runtime support (user selection, registration, multi-user login UI, system-generated secrets, JWT cookies).
- Automated migration of existing YAML config files into the database.
- Migration checksum / tamper validation (explicitly dropped, along with UTF-8 BOM and strict line-ending constraints).
- Down/rollback migrations.
- In-memory link caching.
- Frontend UI changes (the existing React bundle works unchanged against `/?action=...`).

## Anti-Goals

- Breaking top-level keyword path ownership (no new non-root paths beyond `/favicon.ico`).
- Placing secrets in URLs or storing raw plaintext `GOLINKS_USER_SECRET_KEY` in `users.user_secret` or cookies.
- Requiring system `libsqlite3` or `libpq` packages in Docker or breaking cross-compilation.
- Leaving unused YAML / `notify` watcher code or `GOLINKS_FILE` handling behind.

## Constraints

- **Routing & API invariants (`AGENTS.md`):** React UI served only at `GET /` (single-file bundle, `HashRouter`), all JSON APIs on `/` via `?action=...` (`getLinks`, `login`, `saveLink`, `deleteLink`), only `/favicon.ico` reserved.
- **Auth & security invariants:** `golinks_auth` cookie (`HttpOnly; SameSite=Lax; Path=/; Max-Age=157680000[; Secure]`) storing `HMAC-SHA256(secret, "golinks-session-v1")`; constant-time comparison (`auth::constant_time_eq`) for secrets and cookies; `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` on every response.
- **Privacy (public repo):** Generic placeholders only (`example.com`, `docs`, `notes`, `google`) in all code, tests, SQL, and docs.
- **Packaging:** `./db/` SQL files must be embedded in the compiled Rust binary (`Dockerfile` must copy `./db` and `build.rs` into `backend-builder`).

## Approaches Considered

### Dropped Up Front
- **ORMs (`diesel` / `sea-orm`):** Unnecessary overhead for two tables and hand-written `./db/` SQL scripts; `diesel`'s default native `libpq` linking adds friction for cross-compilation and slim Docker builds.
- **In-memory link cache:** Indexed DB queries are already sub-millisecond (SQLite) to ~1 ms (PostgreSQL); skipping a cache eliminates invalidation bugs across multi-instance Postgres deployments and simplifies future multi-user work.

### Approach 1: Unified async layer with `sqlx` (`sqlite` + `postgres` + `tls-rustls`) — **Chosen**
- Use `sqlx` (`runtime-tokio`, `tls-rustls-ring-webpki`, `sqlite`, `postgres`, without compile-time DB macros) wrapped behind a `src/db/` module using `enum Backend { Sqlite(SqlitePool), Postgres(PgPool) }`.
- Bundled SQLite + pure-Rust Postgres/TLS keep `debian:bookworm-slim` and `cross` builds self-contained.
- `sqlx::raw_sql` runs multi-statement schema and migration scripts inside transactions on both engines.
- `build.rs` auto-discovers and embeds `./db/{sqlite,postgres}/` SQL files and verifies matching migration version sets across dialects at compile time.
- **Tradeoffs:** Unified async pool, transaction, TLS, and error handling that evolves cleanly for multi-user; slightly heavier cold compile time than hand-wired drivers.

### Approach 2: Separate native drivers (`rusqlite` bundled + `tokio-postgres` + `deadpool-postgres` + `rustls`)
- SQLite runs synchronously via `rusqlite` bridged with `spawn_blocking`; Postgres uses `tokio-postgres` + `deadpool-postgres` + manual `rustls` TLS wiring.
- **Tradeoffs:** Slightly smaller binary and faster cold builds, at the cost of maintaining two driver APIs, two pool crates, blocking bridges, and manual TLS plumbing.

**Decision:** Approach 1 (`sqlx`) was chosen by the user.

## Detailed Design

### 1. Configuration & Environment Variables

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `GOLINKS_USER_SECRET_KEY` | Yes | — | Must be set and non-empty. Used to derive the 64-char hex HMAC-SHA256 token stored in `users.user_secret`. |
| `GOLINKS_USERNAME` | No | `golinks` | Trimmed; must be non-empty and `<= 32` Unicode scalar chars. |
| `GOLINKS_DB_ENGINE` | No | `sqlite` | Case-insensitive, trimmed: `sqlite` or `postgresql`. Unknown values exit(1). |
| `GOLINKS_DB_PATH` | When `sqlite` | `./golinks.db` (Docker: `/data/golinks.db`) | File path for SQLite DB. Parent directories are created automatically if missing (unless `:memory:`). |
| `GOLINKS_DB_HOST` | When `postgresql` | — | Hostname; must be non-empty. |
| `GOLINKS_DB_PORT` | No | `5432` | `u16` port number. |
| `GOLINKS_DB_NAME` | When `postgresql` | — | Database name; must be non-empty. |
| `GOLINKS_DB_USERNAME` | When `postgresql` | — | Connection username; must be non-empty. |
| `GOLINKS_DB_PASSWORD` | When `postgresql` | — | Connection password; env var must be set (may be empty if server allows it). |

Existing HTTP/UI variables remain unchanged: `GOLINKS_ADDR` (`0.0.0.0:8080`), `GOLINKS_SECURE_COOKIE` (`true`), `GOLINKS_UI_FILE`, `FAVICON_FILE`. `GOLINKS_FILE` is removed.

`Dockerfile` and `Dockerfile.release` replace `ENV GOLINKS_FILE=/data/config.yaml` with:
```dockerfile
ENV GOLINKS_DB_ENGINE=sqlite
ENV GOLINKS_DB_PATH=/data/golinks.db
```

### 2. Embedded SQL Files & Database Schema

Directory structure:
- `db/sqlite/full_schema.sql`
- `db/postgres/full_schema.sql`
- Future migrations: `db/sqlite/migration_vXXXXXXX.sql` and `db/postgres/migration_vXXXXXXX.sql` (where `XXXXXXX` is 7 zero-padded digits, e.g. `migration_v0000002.sql`).

`build.rs` scans `db/sqlite/` and `db/postgres/`:
- Emits `cargo:rerun-if-changed=db` (and per-directory/file rerun directives).
- Embeds `full_schema.sql` for each engine via `include_str!`.
- Discovers any `migration_vXXXXXXX.sql` files, validates the `v\d{7}` format and rejects unexpected filenames, verifies SQLite and PostgreSQL have identical migration version lists, sorts ascending, and computes `LATEST_VERSION` (`"v0000001"` when no migration files exist yet, otherwise the highest discovered version, which must be `> "v0000001"`).

#### Schema Namespacing
- **PostgreSQL:** All tables live in schema `golinks`. `db/postgres/full_schema.sql` runs `CREATE SCHEMA IF NOT EXISTS golinks;` and qualifies table creation with `golinks.<table_name>`. Every pooled Postgres connection sets `search_path=golinks` via `PgConnectOptions::options([("search_path", "golinks")])` so runtime queries use unqualified table names (`users`, `links`, `schema_migration`).
- **SQLite:** Uses the default `main` schema (no schema prefix). `SqliteConnectOptions` enables `create_if_missing(true)`, `foreign_keys(true)`, and `journal_mode(SqliteJournalMode::Wal)` (non-memory DBs).

#### Tables (`v0000001`)

`schema_migration`:
- `version CHAR(8) PRIMARY KEY` (e.g., `'v0000001'`)
- `installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP`
- `execution_time_ms INTEGER`
- `success BOOLEAN NOT NULL DEFAULT TRUE` (SQLite: `DEFAULT 1`)

`users`:
- `user_id` — auto-increment integer primary key (`INTEGER PRIMARY KEY AUTOINCREMENT` on SQLite; `SERIAL PRIMARY KEY` on PostgreSQL)
- `user_name VARCHAR(32) NOT NULL UNIQUE`
- `user_secret VARCHAR(64) NOT NULL`
- `created_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP`
- `updated_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP`

`links`:
- `link_id` — auto-increment integer primary key (`INTEGER PRIMARY KEY AUTOINCREMENT` on SQLite; `SERIAL PRIMARY KEY` on PostgreSQL)
- `user_id INTEGER NOT NULL` — foreign key to `users(user_id) ON DELETE CASCADE`
- `link_keyword VARCHAR(32) NOT NULL`
- `link_target VARCHAR(512) NOT NULL`
- `created_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP`
- `updated_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP`
- `CONSTRAINT uq_links_user_keyword UNIQUE (user_id, link_keyword)`

*(Our call: `ON DELETE CASCADE` on `links.user_id` keeps referential integrity clean when multi-user user deletion is added later.)*

### 3. Startup Migration Algorithm

Runs immediately after connecting the DB pool and before user sync or HTTP listener bind:

1. *(Our call — PostgreSQL concurrency safety)* Acquire a Postgres session advisory lock (fixed 64-bit constant key for `golinks` migrations) before checking/running migrations, and release it when finished so concurrent container startups do not race on DDL.
2. Check if `schema_migration` exists:
   - SQLite: `SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migration'`
   - PostgreSQL: `SELECT 1 FROM information_schema.tables WHERE table_schema = 'golinks' AND table_name = 'schema_migration'`
3. If `schema_migration` does **not** exist, OR exists with `COUNT(*) = 0`:
   - Start timer (`Instant::now()`).
   - Begin transaction, execute embedded `full_schema.sql` via `sqlx::raw_sql`, insert `(LATEST_VERSION, elapsed_ms, true)` into `schema_migration`, and commit.
   - If execution fails: rollback and exit(1) with error log.
4. Otherwise (`schema_migration` exists and has >= 1 rows):
   - Query for any row with `success = false` (SQLite: `success = 0`). If found, log the failed version(s) and exit(1) without attempting further migrations.
   - Query `MAX(version)`.
   - If `max_version > LATEST_VERSION`, log that the database schema is newer than this binary and exit(1).
   - For each embedded migration with `version > max_version` in ascending version order:
     - Start timer.
     - Begin transaction, execute migration SQL via `sqlx::raw_sql`, insert `(version, elapsed_ms, true)` into `schema_migration`, and commit.
     - If execution fails: rollback the migration transaction, best-effort insert `(version, elapsed_ms, false)` into `schema_migration` on a fresh query so the failure is recorded, and exit(1).

### 4. Startup User Sync & Authentication Flow

1. Derive `expected_secret = auth::derive_auth_token(&user_secret_key)` (64-char hex `HMAC-SHA256(key, "golinks-session-v1")`; move `derive_auth_token` from removed `src/config.rs` to `src/auth.rs`).
2. Run `db.sync_user(&username, &expected_secret)`:
   - Look up `users` by `user_name`.
   - If absent: insert `(user_name, user_secret)` and return `User { user_id, user_name, user_secret }`.
   - If present and `!auth::constant_time_eq(&existing.user_secret, &expected_secret)`: update `user_secret` and `updated_on = CURRENT_TIMESTAMP` where `user_id = existing.user_id`, return updated `User`.
   - If present and equal: return `existing`.
3. Runtime auth (single-user now, user-scoped for future multi-user):
   - `AppState` holds `db: Database`, `active_user_id: i32`, `secure_cookie: bool`, `favicon: FaviconData`, `ui_html: Arc<String>`.
   - `POST /?action=login`: derives `candidate = auth::derive_auth_token(&req.secret)`, fetches user by `state.active_user_id` from DB, compares with `auth::constant_time_eq(&candidate, &user.user_secret)`. On match, sets `golinks_auth=<user.user_secret>` cookie and returns `200 { "ok": true }`; else `401`.
   - Authenticated handlers (`getLinks`, `saveLink`, `deleteLink`, redirect fallback): fetch user by `state.active_user_id` from DB and validate cookie via `auth::is_authenticated(&headers, &user.user_secret)`.
   - *(Our call: Reading the user record from DB instead of caching `auth_token` in `AppState` exercises the exact multi-user DB lookup path and keeps auth state strictly sourced from `users`.)*

### 5. User-Scoped Repository API & HTTP Handlers

All DB access lives under `src/db/` and exposes user-scoped async methods:
- `sync_user(&self, user_name: &str, user_secret: &str) -> Result<User, DbError>`
- `get_user_by_id(&self, user_id: i32) -> Result<Option<User>, DbError>`
- `get_user_by_name(&self, user_name: &str) -> Result<Option<User>, DbError>`
- `list_links(&self, user_id: i32) -> Result<BTreeMap<String, String>, DbError>`
- `get_link_target(&self, user_id: i32, keyword: &str) -> Result<Option<String>, DbError>`
- `save_link(&self, user_id: i32, original_key: Option<&str>, key: &str, target: &str) -> Result<BTreeMap<String, String>, DbError>`
  - Inside one transaction: if `original_key` is `Some(orig)` (trimmed, non-empty) and `orig != key`, delete `(user_id, orig)`; then upsert `(user_id, key, target)` via `INSERT ... ON CONFLICT (user_id, link_keyword) DO UPDATE SET link_target = EXCLUDED.link_target, updated_on = CURRENT_TIMESTAMP`; then return `list_links(user_id)`.
- `delete_link(&self, user_id: i32, keyword: &str) -> Result<Option<BTreeMap<String, String>>, DbError>`
  - Deletes `(user_id, keyword)`. If `rows_affected == 0`, returns `Ok(None)` (`404 Link not found.`). Otherwise returns `Ok(Some(list_links(user_id)))`.

#### Input Validation & Error Responses
- `validate_link_key`: non-empty, `<= 32` chars (`key.chars().count() <= 32`), no whitespace/`/`/`?`/`#`.
- `validate_link_target`: non-empty, `<= 512` chars (`target.chars().count() <= 512`), starts with `http://` or `https://`.
- *(Our call: Enforcing character lengths in Rust ensures identical `400 Bad Request` behavior across SQLite—which does not enforce `VARCHAR(n)`—and PostgreSQL.)*
- *(Our call: Unexpected DB errors during HTTP requests are logged to `stderr` and return `500 Internal Server Error` with a generic error message, never exposing DB connection details or falling through to `/#/edit/<keyword>` on redirect failures.)*

### 6. CI, Docker & Release Packaging

Because `sqlx` compiles bundled C/asm (`libsqlite3-sys` + `ring`), CI packaging is updated as chosen by the user:
- **Linux CI targets (`docker-build.yml` & `release.yml`):** Switch to static `musl` targets built with `cross`:
  - `x86_64-unknown-linux-musl` (`golinks-linux-x64`, `use-cross: true`)
  - `aarch64-unknown-linux-musl` (`golinks-linux-arm64`, `use-cross: true`)
  - In `docker-build.yml`, run `cargo test` natively on `ubuntu-latest` (gated on `matrix.target == 'x86_64-unknown-linux-musl'`) so tests still execute on every push without slowing down cross builds.
- **Windows ARM64 release target (`release.yml`):** Switch `aarch64-pc-windows-msvc` from `windows-latest` (x64) to native `windows-11-arm` (public repo) so C/asm crates compile natively without cross-MSVC/clang hacks.
- **Dockerfiles:**
  - `Dockerfile`: Copy `build.rs` and `db/` into `backend-builder` alongside `Cargo.toml`, `Cargo.lock`, `assets/`, `src/`; keep `rust:1-bookworm` → `debian:bookworm-slim`; replace `GOLINKS_FILE` env var with `GOLINKS_DB_ENGINE=sqlite` and `GOLINKS_DB_PATH=/data/golinks.db`.
  - `Dockerfile.release`: Keep `debian:bookworm-slim` (static `musl` binaries run directly with no glibc version coupling); replace `GOLINKS_FILE` env var with `GOLINKS_DB_ENGINE=sqlite` and `GOLINKS_DB_PATH=/data/golinks.db`.

### 7. Testing & Verification Strategy

- Automated `cargo test` suite (using temporary SQLite files / in-memory SQLite):
  - Migration lifecycle: fresh DB bootstrap via `full_schema.sql`, idempotent restart, applying pending synthetic migrations (`v0000002`, `v0000003`), blocking startup when `success = false` is recorded, recording `success = false` when a migration fails, rejecting a DB version newer than the binary.
  - User sync: creating a new user, idempotent restart with matching secret, updating secret and `updated_on` when secret changes.
  - Multi-user DB isolation: two users in `users` with identical keywords in `links` do not read, overwrite, rename, or delete each other's links.
  - Full HTTP router integration tests: unauthenticated redirect to `/?next=...`, login cookie attributes, authenticated redirects & `%s` URL encoding, unknown keyword redirect to `/#/edit/<key>`, `getLinks`/`saveLink` (create, update, rename, rename-onto-existing)/`deleteLink`, 32/512-char length validation, `/favicon.ico`, security headers on all responses.
- Optional PostgreSQL integration tests gated on env vars (e.g. `GOLINKS_TEST_PG_HOST` / `GOLINKS_TEST_PG_*`) so developers and CI can verify Postgres end-to-end when a Postgres instance is available, plus SQL embedding/build verification for `db/postgres/full_schema.sql`.

## Left to the Builder

- Exact module layout inside `src/db/` (e.g., `mod.rs`, `config.rs`, `migrations.rs`, `sqlite.rs`, `postgres.rs`) and `DbError` type structure.
- SQLx pool sizing defaults (`max_connections`, connect timeout) and PostgreSQL default TLS mode (`Prefer` via `sqlx`).
- Exact Postgres advisory lock constant ID.
- Exact wording of validation/startup error log lines and generic `500` error bodies.
- Documentation updates in `AGENTS.md`, `MEMORY.md`, and `README.md`.
