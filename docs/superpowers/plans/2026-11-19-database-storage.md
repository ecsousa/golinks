# Database Storage & Migration Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `golinks`'s YAML configuration file and file watcher with an embedded-migration SQLite/PostgreSQL database layer (`schema_migration`, `users`, `links`) and user-scoped repository API while preserving all HTTP/UI contracts.

**Architecture:** Use `sqlx` (`runtime-tokio`, `tls-rustls-ring-webpki`, `sqlite`, `postgres`, without compile-time macros) behind an enum-dispatched `Database` handle in `src/db/`. A `build.rs` script embeds `./db/{sqlite,postgres}/` SQL schemas and future `migration_vXXXXXXX.sql` files and enforces cross-dialect version parity at compile time; startup runs migrations, syncs the configured user's derived HMAC-SHA256 secret into `users`, and serves all HTTP handlers via direct user-scoped DB queries.

**Tech Stack:** Rust (edition 2024), Axum 0.8, Tokio 1, `sqlx` 0.8 (bundled SQLite + pure-Rust PostgreSQL with `rustls`), `hmac`/`sha2`/`hex`/`subtle`, GitHub Actions (`cross` with `musl` for Linux, `windows-11-arm` for Windows ARM64), Docker (`debian:bookworm-slim`).

**Spec:** [docs/superpowers/specs/2026-11-19-database-storage-design.md](file:///Users/esousa/workspace/golinks/docs/superpowers/specs/2026-11-19-database-storage-design.md)

## Global Constraints

- **No path collisions:** React UI served only at `GET /` (`HashRouter`, single-file bundle); all JSON APIs on `/` via `?action=...` (`getLinks`, `login`, `saveLink`, `deleteLink`); only `/favicon.ico` is a reserved non-root path.
- **Auth & security:** `golinks_auth` cookie (`HttpOnly; SameSite=Lax; Path=/; Max-Age=157680000[; Secure]`) stores `HMAC-SHA256(secret, "golinks-session-v1")`; use `auth::constant_time_eq` for all secret/cookie comparisons; keep `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, and `X-Content-Type-Options: nosniff` on every response.
- **Database schemas:** PostgreSQL uses schema `golinks` (`CREATE SCHEMA IF NOT EXISTS golinks` + `search_path=golinks` on every connection); SQLite uses its default `main` schema with `foreign_keys(true)` and WAL mode (for non-memory DBs).
- **No checksum validation:** `schema_migration` has columns `version`, `installed_on`, `execution_time_ms`, `success` (no `checksum` column, no UTF-8 BOM requirement).
- **Privacy (public repo):** Generic placeholders only (`example.com`, `docs`, `notes`, `google`) in all code, tests, SQL, and docs.
- **No frontend changes:** Do not modify `frontend/`; existing UI works unchanged against `/?action=...`.

## Review Focus

1. **Unicode multi-byte lengths at `32`/`512`-char boundaries:** `VARCHAR(32)`/`VARCHAR(512)` counts Unicode scalar characters, not UTF-8 bytes—32-char keywords and 512-char targets containing multi-byte UTF-8 must succeed, while 33/513 chars must return `400 Bad Request` on both SQLite and PostgreSQL. *(Pinned in Task 5.)*
2. **Renaming a link onto an already-existing keyword:** `saveLink` with `originalKey != key` where `key` already exists for that user must atomically delete `originalKey` and overwrite `key`'s target without failing on `UNIQUE(user_id, link_keyword)`. *(Pinned in Task 4 and Task 5.)*
3. **Database error during `GET /<keyword>` redirect:** If the DB fails while looking up a user or link target, `handle_redirect` must log to `stderr` and return `500 Internal Server Error` with security headers—never redirect to `/#/edit/<keyword>`. *(Pinned in Task 5.)*
4. **Failed migration (`success = false`) and version-downgrade guard:** Startup must refuse to run if any row in `schema_migration` has `success = false` OR if `MAX(version) > LATEST_VERSION`, and a failing migration must roll back its DDL/DML and record `success = false`. *(Pinned in Task 3.)*
5. **Nested SQLite parent directories & empty vs unset `GOLINKS_DB_PASSWORD`:** Connecting to a SQLite path whose parent directory does not yet exist must create the directory automatically; for PostgreSQL, `GOLINKS_DB_PASSWORD=""` (set to empty) must be accepted while an unset `GOLINKS_DB_PASSWORD` must fail startup. *(Pinned in Task 2 and Task 3.)*

## File Structure

- **Create:**
  - `db/sqlite/full_schema.sql` — SQLite v0000001 full schema (`schema_migration`, `users`, `links`).
  - `db/postgres/full_schema.sql` — PostgreSQL v0000001 full schema (`CREATE SCHEMA IF NOT EXISTS golinks` + `golinks.*` tables).
  - `build.rs` — Discovers, validates, and embeds `db/{sqlite,postgres}/{full_schema.sql,migration_v*.sql}` into `$OUT_DIR/embedded_db.rs`.
  - `src/db/config.rs` — `DbEngine`, `DbConfig`, `AppConfig`, env parsing & validation.
  - `src/db/migrations.rs` — Embedded SQL accessors (`MigrationSpec`, `embedded_spec`) and startup migration runner (`run_migrations`, `run_migrations_with_spec`).
  - `src/db/mod.rs` — `Database` (`SqlitePool` / `PgPool`), `DbError`, `User`, connection setup, and user-scoped repository methods.
- **Modify:**
  - `Cargo.toml` — Add `sqlx` (Task 1); remove `notify` and `serde_yaml_ng` once `src/config.rs` is deleted (Task 5).
  - `src/auth.rs` — Add `derive_auth_token` (moved from `src/config.rs`).
  - `src/main.rs` — Wire `AppState`, validation, HTTP handlers, startup, and integration tests to `src/db/`.
  - `Dockerfile`, `Dockerfile.release` — Copy `build.rs` & `db/`, replace `GOLINKS_FILE` with `GOLINKS_DB_ENGINE=sqlite` and `GOLINKS_DB_PATH=/data/golinks.db`.
  - `.github/workflows/docker-build.yml`, `.github/workflows/release.yml` — Static `musl` Linux builds via `cross`, native `cargo test`, `windows-11-arm` for Windows ARM64.
  - `AGENTS.md`, `MEMORY.md`, `README.md` — Update docs for DB storage, env vars, schema/migrations, Docker, and CI.
- **Delete:**
  - `src/config.rs` — Removed in Task 5 after `src/main.rs` switches to `src/db/` and `src/auth.rs`.

---

### Task 1: SQL Schemas, `build.rs` Embedding, `sqlx` Dependency & `auth::derive_auth_token`

**Files:**
- Create: `db/sqlite/full_schema.sql`
- Create: `db/postgres/full_schema.sql`
- Create: `build.rs`
- Modify: `Cargo.toml`
- Modify: `src/auth.rs`

**Interfaces:**
- Consumes: none.
- Produces:
  - `auth::derive_auth_token(key: &str) -> String` in `src/auth.rs` (HMAC-SHA256 of `b"golinks-session-v1"` hex-encoded to 64 lowercase chars).
  - Generated `$OUT_DIR/embedded_db.rs` exporting:
    - `pub const LATEST_VERSION: &str` (`"v0000001"` when no incremental migrations exist)
    - `pub const SQLITE_FULL_SCHEMA: &str`
    - `pub const POSTGRES_FULL_SCHEMA: &str`
    - `pub const SQLITE_MIGRATIONS: &[(&str, &str)]` (sorted ascending by version)
    - `pub const POSTGRES_MIGRATIONS: &[(&str, &str)]` (sorted ascending by version)

- [ ] **Step 1: Add `sqlx` to `Cargo.toml` and write failing unit tests in `src/auth.rs`**

Add `sqlx` to `[dependencies]` in `Cargo.toml` (keep `notify` and `serde_yaml_ng` until Task 5 so `cargo test` stays green at every task):
```toml
sqlx = { version = "0.8", default-features = false, features = ["runtime-tokio", "tls-rustls-ring-webpki", "sqlite", "postgres"] }
```

Add a `#[cfg(test)]` module at the bottom of `src/auth.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_auth_token_is_64_char_hex_and_matches_known_hmac() {
        let token = derive_auth_token("someSuperSecretValue");
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(token, derive_auth_token("someSuperSecretValue"));
        assert_ne!(token, derive_auth_token("differentSecret"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test auth::tests`
Expected: FAIL to compile (`cannot find function 'derive_auth_token' in this scope`).

- [ ] **Step 3: Implement `derive_auth_token` in `src/auth.rs`**

Add `derive_auth_token(key: &str) -> String` to `src/auth.rs` using `hmac::Hmac<sha2::Sha256>` with context `b"golinks-session-v1"` and `hex::encode`, matching the existing implementation in `src/config.rs:34-39`.

- [ ] **Step 4: Create `db/sqlite/full_schema.sql` and `db/postgres/full_schema.sql`**

Create `db/sqlite/full_schema.sql` with:
- `schema_migration` (`version CHAR(8) PRIMARY KEY`, `installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP`, `execution_time_ms INTEGER`, `success BOOLEAN NOT NULL DEFAULT 1`)
- `users` (`user_id INTEGER PRIMARY KEY AUTOINCREMENT`, `user_name VARCHAR(32) NOT NULL UNIQUE`, `user_secret VARCHAR(64) NOT NULL`, `created_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP`, `updated_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP`)
- `links` (`link_id INTEGER PRIMARY KEY AUTOINCREMENT`, `user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE`, `link_keyword VARCHAR(32) NOT NULL`, `link_target VARCHAR(512) NOT NULL`, `created_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP`, `updated_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP`, `CONSTRAINT uq_links_user_keyword UNIQUE (user_id, link_keyword)`)

Create `db/postgres/full_schema.sql` with:
- `CREATE SCHEMA IF NOT EXISTS golinks;`
- `golinks.schema_migration` (`version CHAR(8) PRIMARY KEY`, `installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP`, `execution_time_ms INTEGER`, `success BOOLEAN NOT NULL DEFAULT TRUE`)
- `golinks.users` (`user_id SERIAL PRIMARY KEY`, `user_name VARCHAR(32) NOT NULL UNIQUE`, `user_secret VARCHAR(64) NOT NULL`, `created_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP`, `updated_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP`)
- `golinks.links` (`link_id SERIAL PRIMARY KEY`, `user_id INTEGER NOT NULL REFERENCES golinks.users(user_id) ON DELETE CASCADE`, `link_keyword VARCHAR(32) NOT NULL`, `link_target VARCHAR(512) NOT NULL`, `created_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP`, `updated_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP`, `CONSTRAINT uq_links_user_keyword UNIQUE (user_id, link_keyword)`)

- [ ] **Step 5: Implement `build.rs` to discover, validate, and embed `./db/` SQL files**

Write `build.rs` in the repo root:
- Emit `cargo:rerun-if-changed=db`, `cargo:rerun-if-changed=db/sqlite`, `cargo:rerun-if-changed=db/postgres`, and per-file `cargo:rerun-if-changed=<path>`.
- Verify `db/sqlite/full_schema.sql` and `db/postgres/full_schema.sql` exist.
- Scan each engine directory for any other files: require every non-`full_schema.sql` file to match `migration_vXXXXXXX.sql` (exact 7 ASCII digits, version `> "v0000001"`), panic with a clear message on unexpected filenames.
- Sort migration versions ascending and panic if `db/sqlite` and `db/postgres` do not contain the exact same set of migration versions.
- Compute `LATEST_VERSION` (`"v0000001"` if migrations list is empty, else the last/highest version).
- Write `$OUT_DIR/embedded_db.rs` using `include_str!(...)` with canonicalized/escaped absolute paths so it builds cleanly on Linux, macOS, and Windows.

- [ ] **Step 6: Run tests to verify build script and `auth` tests pass**

Run: `cargo test`
Expected: PASS (all existing tests + `auth::tests::derive_auth_token_is_64_char_hex_and_matches_known_hmac` pass; `build.rs` compiles and generates `embedded_db.rs`).

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock build.rs db/sqlite/full_schema.sql db/postgres/full_schema.sql src/auth.rs
git commit -m "feat: add embedded SQL schemas, build.rs discovery, and sqlx dependency"
```

---

### Task 2: Environment Configuration Parser (`src/db/config.rs`)

**Files:**
- Create: `src/db/config.rs`
- Create: `src/db/mod.rs` (minimal `pub mod config;` stub for this task)
- Modify: `src/main.rs` (add `mod db;`)

**Interfaces:**
- Consumes: none.
- Produces in `crate::db::config`:
  - `pub enum DbEngine { Sqlite, Postgresql }`
  - `pub enum DbConfig { Sqlite { path: String }, Postgresql { host: String, port: u16, database: String, username: String, password: String } }`
  - `pub struct AppConfig { pub username: String, pub user_secret_key: String, pub db: DbConfig }`
  - `AppConfig::from_env() -> Result<Self, String>`
  - `AppConfig::from_lookup<F>(lookup: F) -> Result<Self, String> where F: Fn(&str) -> Option<String>`

- [ ] **Step 1: Write failing unit tests in `src/db/config.rs`**

Create `src/db/mod.rs` with `pub mod config;`, add `mod db;` to `src/main.rs`, and write tests in `src/db/config.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn parse(vars: &[(&str, &str)]) -> Result<AppConfig, String> {
        let map: HashMap<&str, &str> = vars.iter().copied().collect();
        AppConfig::from_lookup(|k| map.get(k).map(|v| (*v).to_string()))
    }

    #[test]
    fn sqlite_defaults_work_with_only_secret_key() {
        let cfg = parse(&[("GOLINKS_USER_SECRET_KEY", "super-secret")]).unwrap();
        assert_eq!(cfg.username, "golinks");
        assert_eq!(cfg.user_secret_key, "super-secret");
        assert_eq!(cfg.db, DbConfig::Sqlite { path: "./golinks.db".to_string() });
    }

    #[test]
    fn requires_non_empty_secret_key_and_valid_username() {
        assert!(parse(&[]).is_err());
        assert!(parse(&[("GOLINKS_USER_SECRET_KEY", "")]).is_err());
        assert!(parse(&[
            ("GOLINKS_USER_SECRET_KEY", "ok"),
            ("GOLINKS_USERNAME", "   "),
        ]).is_err());
        assert!(parse(&[
            ("GOLINKS_USER_SECRET_KEY", "ok"),
            ("GOLINKS_USERNAME", &"a".repeat(33)),
        ]).is_err());
        let ok = parse(&[
            ("GOLINKS_USER_SECRET_KEY", "ok"),
            ("GOLINKS_USERNAME", &"é".repeat(32)),
        ]).unwrap();
        assert_eq!(ok.username.chars().count(), 32);
    }

    #[test]
    fn rejects_unknown_db_engine() {
        assert!(parse(&[
            ("GOLINKS_USER_SECRET_KEY", "ok"),
            ("GOLINKS_DB_ENGINE", "mysql"),
        ]).is_err());
    }

    #[test]
    fn postgresql_config_requires_vars_and_allows_empty_password_when_set() {
        // Missing password fails
        assert!(parse(&[
            ("GOLINKS_USER_SECRET_KEY", "ok"),
            ("GOLINKS_DB_ENGINE", "PostgreSQL"),
            ("GOLINKS_DB_HOST", "db.example.com"),
            ("GOLINKS_DB_NAME", "golinks"),
            ("GOLINKS_DB_USERNAME", "app"),
        ]).is_err());

        // Explicitly empty password succeeds and port defaults to 5432
        let cfg = parse(&[
            ("GOLINKS_USER_SECRET_KEY", "ok"),
            ("GOLINKS_DB_ENGINE", " postgresql "),
            ("GOLINKS_DB_HOST", "db.example.com"),
            ("GOLINKS_DB_NAME", "golinks"),
            ("GOLINKS_DB_USERNAME", "app"),
            ("GOLINKS_DB_PASSWORD", ""),
        ]).unwrap();
        assert_eq!(
            cfg.db,
            DbConfig::Postgresql {
                host: "db.example.com".to_string(),
                port: 5432,
                database: "golinks".to_string(),
                username: "app".to_string(),
                password: "".to_string(),
            }
        );

        // Invalid port fails
        assert!(parse(&[
            ("GOLINKS_USER_SECRET_KEY", "ok"),
            ("GOLINKS_DB_ENGINE", "postgresql"),
            ("GOLINKS_DB_HOST", "db.example.com"),
            ("GOLINKS_DB_PORT", "not-a-port"),
            ("GOLINKS_DB_NAME", "golinks"),
            ("GOLINKS_DB_USERNAME", "app"),
            ("GOLINKS_DB_PASSWORD", "pw"),
        ]).is_err());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test db::config::tests`
Expected: FAIL to compile (`AppConfig` / `DbConfig` not defined).

- [ ] **Step 3: Implement `DbEngine`, `DbConfig`, and `AppConfig` in `src/db/config.rs`**

Implement `AppConfig::from_env` (delegating to `AppConfig::from_lookup(|k| std::env::var(k).ok())`) and `AppConfig::from_lookup` following the exact env var table in the spec:
- `GOLINKS_USER_SECRET_KEY`: required, non-empty (do not trim secret bytes).
- `GOLINKS_USERNAME`: optional, default `"golinks"`; trimmed, non-empty, `<= 32` Unicode scalar chars (`chars().count() <= 32`).
- `GOLINKS_DB_ENGINE`: optional, default `"sqlite"`; trimmed ASCII-lowercase: `"sqlite"` → `Sqlite`, `"postgresql"` → `Postgresql`, anything else → `Err`.
- `Sqlite`: `GOLINKS_DB_PATH` optional, default `"./golinks.db"`, trimmed non-empty.
- `Postgresql`: `GOLINKS_DB_HOST`, `GOLINKS_DB_NAME`, `GOLINKS_DB_USERNAME` required & trimmed non-empty; `GOLINKS_DB_PORT` optional default `5432` parsed as `u16`; `GOLINKS_DB_PASSWORD` required to be present (`Some(val)`), may be empty string.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test db::config::tests`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add src/db/config.rs src/db/mod.rs src/main.rs
git commit -m "feat: add database and user environment configuration parser"
```

---

### Task 3: Database Connection Pool & Migration Runner (`src/db/migrations.rs`, `src/db/mod.rs`)

**Files:**
- Create: `src/db/migrations.rs`
- Modify: `src/db/mod.rs`

**Interfaces:**
- Consumes:
  - `crate::db::config::DbConfig` (Task 2)
  - `$OUT_DIR/embedded_db.rs` constants (Task 1)
- Produces:
  - `crate::db::DbError` (`Debug`, `Display`, `std::error::Error`)
  - `crate::db::Database`:
    - `pub async fn connect(config: &DbConfig) -> Result<Self, DbError>`
    - `pub async fn run_migrations(&self) -> Result<(), DbError>`
  - `crate::db::migrations::MigrationSpec`:
    - `pub struct MigrationSpec<'a> { pub full_schema: &'a str, pub migrations: &'a [(&'a str, &'a str)], pub latest_version: &'a str }`
    - `pub fn embedded_sqlite_spec() -> MigrationSpec<'static>`
    - `pub fn embedded_postgres_spec() -> MigrationSpec<'static>`
    - `pub async fn run_sqlite_migrations(pool: &SqlitePool, spec: &MigrationSpec<'_>) -> Result<(), DbError>`
    - `pub async fn run_postgres_migrations(pool: &PgPool, spec: &MigrationSpec<'_>) -> Result<(), DbError>`

- [ ] **Step 1: Write failing migration & connection tests in `src/db/migrations.rs`**

Write tests covering:
1. `fresh_sqlite_creates_parent_dir_and_runs_full_schema`: connect to `<tempdir>/nested/sub/golinks.db`, run `run_migrations()`, verify parent dir exists, `schema_migration` has 1 row `('v0000001', success=true)`, `users` and `links` tables exist, and `PRAGMA foreign_keys` is `1`.
2. `idempotent_restart_does_not_reapply_or_fail`: running `run_migrations()` twice on the same DB succeeds and leaves 1 row in `schema_migration`.
3. `empty_schema_migration_table_triggers_full_schema_init`: if `schema_migration` exists with 0 rows (and `full_schema.sql` uses `CREATE TABLE IF NOT EXISTS` or fresh DB with empty `schema_migration`), running `run_migrations_with_spec` bootstraps and records `latest_version`. *(Note: ensure `CREATE TABLE IF NOT EXISTS` is used in both `db/sqlite/full_schema.sql` and `db/postgres/full_schema.sql` so an empty pre-existing `schema_migration` table succeeds cleanly!)*
4. `applies_pending_migrations_in_order`: start at `v0000001`, then run `run_sqlite_migrations` with a synthetic spec containing `v0000002` and `v0000003` (`ALTER TABLE` / `CREATE TABLE`), verify both execute in order and `schema_migration` contains `v0000001`, `v0000002`, `v0000003` with `success = 1` and `execution_time_ms >= 0`.
5. `failed_migration_rolls_back_records_failure_and_blocks_next_startup`: run a synthetic `v0000002` with a valid statement followed by invalid SQL; verify it returns `Err`, the valid statement was rolled back, `schema_migration` has `('v0000002', success=0)`, and a subsequent `run_sqlite_migrations` call fails immediately without applying `v0000002` or `v0000003`.
6. `rejects_database_newer_than_binary`: insert `('v0000099', 0, 1)` into `schema_migration`, run `run_migrations()`, verify it returns `Err` mentioning newer schema version.
7. `embedded_postgres_schema_contains_golinks_schema_and_tables`: assert `embedded_postgres_spec().latest_version == "v0000001"` and `full_schema` contains `CREATE SCHEMA IF NOT EXISTS golinks`, `golinks.schema_migration`, `golinks.users`, `golinks.links`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test db::migrations::tests`
Expected: FAIL to compile (`Database::connect` / `run_sqlite_migrations` not defined).

- [ ] **Step 3: Implement `Database::connect` in `src/db/mod.rs` and migration runner in `src/db/migrations.rs`**

Update `db/sqlite/full_schema.sql` and `db/postgres/full_schema.sql` to use `CREATE TABLE IF NOT EXISTS` so bootstrapping when `schema_migration` exists-but-empty is idempotent.

In `src/db/mod.rs`:
- Define `DbError` wrapping `sqlx::Error` and custom string errors (`Migration`, `Config`, `Io`).
- Define `#[derive(Clone)] pub struct Database { backend: Backend }` with `enum Backend { Sqlite(SqlitePool), Postgres(PgPool) }`.
- Implement `Database::connect(config: &DbConfig) -> Result<Self, DbError>`:
  - **SQLite:** If `path != ":memory:"`, ensure parent directory exists via `std::fs::create_dir_all` when `parent` is non-empty. Configure `SqliteConnectOptions::new().filename(path).create_if_missing(true).foreign_keys(true)` and `.journal_mode(SqliteJournalMode::Wal)` for non-memory paths. Use `SqlitePoolOptions::new().max_connections(if path == ":memory:" { 1 } else { 5 })`.
  - **PostgreSQL:** Configure `PgConnectOptions::new().host(host).port(*port).database(database).username(username).password(password).options([("search_path", "golinks")])` (keeping `sqlx` default `Prefer` SSL mode) with `PgPoolOptions::new().max_connections(10)`.
- Implement `Database::run_migrations(&self)` delegating to `migrations::run_sqlite_migrations` or `migrations::run_postgres_migrations`.

In `src/db/migrations.rs`:
- `include!(concat!(env!("OUT_DIR"), "/embedded_db.rs"));`
- Implement `run_sqlite_migrations` and `run_postgres_migrations` per spec Section 3:
  - **Postgres only:** Acquire a dedicated connection from the pool (`pool.acquire().await?`) and execute `SELECT pg_advisory_lock(0x676f6c696e6b7301)` before checking/applying migrations, and always execute `SELECT pg_advisory_unlock(0x676f6c696e6b7301)` before returning (whether `Ok` or `Err`).
  - Check table existence (`sqlite_master` for SQLite; `information_schema.tables` where `table_schema = 'golinks' AND table_name = 'schema_migration'` for Postgres).
  - If missing or `COUNT(*) == 0`: time `full_schema` + `INSERT INTO schema_migration (version, execution_time_ms, success) VALUES (?, ?, true)` inside a single transaction and commit.
  - Otherwise:
    - Check for any row with `success = false` (`0` on SQLite) → return `Err`.
    - Fetch `MAX(version)` (trim trailing CHAR(8) spaces if any); if `max_version > spec.latest_version` → return `Err`.
    - For each `(version, sql)` in `spec.migrations` where `version > max_version`:
      - Start timer, open transaction, `sqlx::raw_sql(sql).execute(&mut *tx).await`, insert `(version, elapsed_ms, true)`, commit.
      - On error: drop/rollback tx, best-effort `INSERT INTO schema_migration (version, execution_time_ms, success) VALUES (?, ?, false)` on the pool/connection, return `Err`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test db::migrations::tests`
Expected: PASS (all 7 tests pass).

- [ ] **Step 5: Commit**

```bash
git add db/sqlite/full_schema.sql db/postgres/full_schema.sql src/db/mod.rs src/db/migrations.rs
git commit -m "feat: implement SQLite/PostgreSQL pool connection and migration runner"
```

---

### Task 4: User-Scoped Repository Layer (`src/db/mod.rs`)

**Files:**
- Modify: `src/db/mod.rs`

**Interfaces:**
- Consumes:
  - `Database::connect`, `Database::run_migrations`, `DbError` (Task 3)
  - `crate::auth::constant_time_eq` (Task 1 / existing `src/auth.rs`)
- Produces on `crate::db`:
  - `#[derive(Debug, Clone, PartialEq, Eq)] pub struct User { pub user_id: i32, pub user_name: String, pub user_secret: String }`
  - `Database::sync_user(&self, user_name: &str, user_secret: &str) -> Result<User, DbError>`
  - `Database::get_user_by_id(&self, user_id: i32) -> Result<Option<User>, DbError>`
  - `Database::get_user_by_name(&self, user_name: &str) -> Result<Option<User>, DbError>`
  - `Database::list_links(&self, user_id: i32) -> Result<BTreeMap<String, String>, DbError>`
  - `Database::get_link_target(&self, user_id: i32, keyword: &str) -> Result<Option<String>, DbError>`
  - `Database::save_link(&self, user_id: i32, original_key: Option<&str>, key: &str, target: &str) -> Result<BTreeMap<String, String>, DbError>`
  - `Database::delete_link(&self, user_id: i32, keyword: &str) -> Result<Option<BTreeMap<String, String>>, DbError>`

- [ ] **Step 1: Write failing repository tests in `src/db/mod.rs`**

Add a `#[cfg(test)] mod tests` block in `src/db/mod.rs` covering:
1. `sync_user_creates_preserves_and_updates_secret`:
   - First `sync_user("golinks", &secret1)` creates user and returns `user_id > 0`.
   - Second `sync_user("golinks", &secret1)` returns same `user_id` and `secret1`.
   - Third `sync_user("golinks", &secret2)` updates `user_secret` to `secret2` on the same `user_id`, verified via `get_user_by_id` and `get_user_by_name`.
2. `save_rename_overwrite_and_delete_links`:
   - `save_link(uid, None, "docs", "https://docs.example.com")` inserts and returns map.
   - `save_link(uid, None, "gh", "https://github.com/%s")` inserts second link.
   - `save_link(uid, Some("gh"), "docs", "https://new-docs.example.com")` (rename onto existing key!) atomically removes `"gh"` and updates `"docs"` to `"https://new-docs.example.com"`.
   - `get_link_target(uid, "docs")` returns `Some("https://new-docs.example.com")`; `get_link_target(uid, "gh")` returns `None`.
   - `delete_link(uid, "missing")` returns `Ok(None)`.
   - `delete_link(uid, "docs")` returns `Ok(Some(empty_map))`.
3. `multi_user_link_isolation`:
   - Sync `"alice"` and `"bob"`, insert keyword `"docs"` for both with different targets; verify `list_links`, `get_link_target`, `save_link` (update/rename), and `delete_link` for `"alice"` never affect `"bob"`.
4. `optional_postgres_end_to_end` (early-returns if `GOLINKS_TEST_PG_HOST` is not set): connects to Postgres using `GOLINKS_TEST_PG_*` env vars, runs migrations, `sync_user`, `save_link`, `get_link_target`, `delete_link` to validate Postgres SQL syntax end-to-end when a Postgres instance is available.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test db::tests`
Expected: FAIL to compile (`User`, `sync_user`, `list_links`, etc. not defined).

- [ ] **Step 3: Implement `User` and all 7 repository methods in `src/db/mod.rs`**

Implement each method dispatching on `&self.backend` (`Backend::Sqlite(pool)` with `?` placeholders, `Backend::Postgres(pool)` with `$1, $2, ...` placeholders):
- `sync_user`: look up by `user_name`; if absent insert and fetch/return (`RETURNING user_id, user_name, user_secret` works on both SQLite 3.35+ bundled in sqlx 0.8 and PostgreSQL); if present and `!auth::constant_time_eq(&existing.user_secret, user_secret)` update `user_secret` and `updated_on = CURRENT_TIMESTAMP` and return updated `User`; else return `existing`.
- `list_links`: `SELECT link_keyword, link_target FROM links WHERE user_id = ?/$1 ORDER BY link_keyword ASC` collected into `BTreeMap<String, String>`.
- `get_link_target`: `SELECT link_target FROM links WHERE user_id = ?/$1 AND link_keyword = ?/$2`.
- `save_link`: inside a single transaction (`pool.begin().await?`), if `original_key` trimmed is non-empty and `orig != key`, `DELETE FROM links WHERE user_id = ?/$1 AND link_keyword = ?/$2`; then `INSERT INTO links (user_id, link_keyword, link_target) VALUES (?, ?, ?) ON CONFLICT (user_id, link_keyword) DO UPDATE SET link_target = EXCLUDED.link_target, updated_on = CURRENT_TIMESTAMP`; commit; return `self.list_links(user_id).await`.
- `delete_link`: `DELETE FROM links WHERE user_id = ?/$1 AND link_keyword = ?/$2`; if `rows_affected() == 0` return `Ok(None)`; else return `Ok(Some(self.list_links(user_id).await?))`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test db::tests`
Expected: PASS (all repository tests pass).

- [ ] **Step 5: Commit**

```bash
git add src/db/mod.rs
git commit -m "feat: add user-scoped database repository methods for users and links"
```

---

### Task 5: Wire Axum Application to Database & Remove YAML Config (`src/main.rs`, delete `src/config.rs`, clean `Cargo.toml`)

**Files:**
- Modify: `src/main.rs`
- Delete: `src/config.rs`
- Modify: `Cargo.toml`

**Interfaces:**
- Consumes:
  - `crate::auth::{build_auth_cookie, constant_time_eq, derive_auth_token, is_authenticated}` (Task 1)
  - `crate::db::config::AppConfig` (Task 2)
  - `crate::db::{Database, DbError, User}` (Task 3 & Task 4)
- Produces:
  - `AppState { pub db: Database, pub active_user_id: i32, pub secure_cookie: bool, pub favicon: FaviconData, pub ui_html: Arc<String> }`
  - `build_router(state: AppState) -> Router` preserving all HTTP routes, status codes, JSON shapes, cookie attributes, and security headers.

- [ ] **Step 1: Update `src/main.rs` integration tests to target `Database` (temp SQLite) and add new edge-case tests**

Update `src/main.rs`'s `#[cfg(test)] mod tests`:
- Replace `test_state` / `test_state_with_path` with async `test_state(secure_cookie: bool) -> (AppState, tempfile::TempDir)` backed by a temp SQLite file, running `run_migrations()`, `sync_user("golinks", &auth::derive_auth_token("someSuperSecretValue"))`, and seeding `google`, `docs`, `m`.
- Keep all existing test cases (`unauthenticated_root_serves_ui_and_links_redirect_to_next`, `login_api_validates_secret_and_sets_cookie`, `authenticated_redirects_url_encoding_and_unknown_redirect_to_edit`, `favicon_endpoint_serves_default_and_override`).
- Replace `api_get_save_rename_and_delete_links_persists_yaml` with `api_get_save_rename_and_delete_links_persists_db` (including renaming onto an existing key and reopening a fresh `Database::connect` to verify persistence on disk).
- Remove `hot_reload_updates_links_and_invalidates_old_key_while_surviving_bad_yaml` and add:
  - `validation_enforces_32_and_512_unicode_char_limits`:
    - `saveLink` with 32-char Unicode keyword (`"é".repeat(32)`) and 512-char Unicode target (`format!("https://example.com/{}", "é".repeat(512 - 20))`) returns `200 OK`.
    - `saveLink` with 33-char keyword returns `400 Bad Request`.
    - `saveLink` with 513-char target returns `400 Bad Request`.
  - `redirect_returns_500_with_security_headers_on_db_error`:
    - Drop the `links` table (or close/corrupt state) in a temp SQLite DB after authenticating, request `GET /google` with valid cookie, assert status is `500 Internal Server Error`, security headers are present, and `Location` header is `None` (never redirects to `/#/edit/google`).
  - `secret_rotation_via_sync_user_invalidates_old_cookie`:
    - Call `sync_user("golinks", &auth::derive_auth_token("secondSecret"))`, verify old cookie is rejected (`302 /?next=...`) and new cookie works.

- [ ] **Step 2: Run tests to verify they fail before refactoring `src/main.rs`**

Run: `cargo test`
Expected: FAIL to compile (`AppState` still has old YAML fields).

- [ ] **Step 3: Refactor `src/main.rs`, delete `src/config.rs`, and remove `notify` & `serde_yaml_ng` from `Cargo.toml`**

1. Delete `src/config.rs` and remove `mod config;` from `src/main.rs`.
2. Remove `notify` and `serde_yaml_ng` from `[dependencies]` in `Cargo.toml`.
3. Update `AppState` in `src/main.rs` to hold `db: Database`, `active_user_id: i32`, `secure_cookie: bool`, `favicon: FaviconData`, `ui_html: Arc<String>`.
4. Update `validate_link_key` to reject `key.chars().count() > 32` and `validate_link_target` to reject `target.chars().count() > 512`.
5. Add a helper `load_active_user(state: &AppState) -> Result<User, Response>` that calls `state.db.get_user_by_id(state.active_user_id).await`; on `Err(err)` or `Ok(None)`, logs to `stderr` (`eprintln!`) and returns `json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error")`.
6. Update handlers:
   - `handle_root_get` (`Some("getLinks")`): authenticate via `load_active_user`, fetch `state.db.list_links(user.user_id).await`, log & return `500` on DB error.
   - `handle_root_post` (`"login"`): parse `LoginRequest`, load active user, compute `candidate = auth::derive_auth_token(&req.secret)`, constant-time compare against `user.user_secret`, set `golinks_auth=<user.user_secret>` cookie on match.
   - `handle_root_post` (`"saveLink"`): authenticate via `load_active_user`, validate key & target, call `state.db.save_link(user.user_id, req.original_key.as_deref(), &key, &target).await`, return `200 { "links": links }` (or log & `500` on DB error).
   - `handle_root_post` (`"deleteLink"`): authenticate via `load_active_user`, validate non-empty key, call `state.db.delete_link(user.user_id, key).await`: `Ok(Some(links))` → `200`, `Ok(None)` → `404 Link not found.`, `Err` → log & `500`.
   - `handle_redirect`: load active user (on DB error, return `500` plain/JSON error, NOT redirect); check `auth::is_authenticated(&headers, &user.user_secret)`; look up `state.db.get_link_target(user.user_id, link_key.as_ref()).await` (on `Err`, log & return `500` — NOT `/#/edit/<key>`; on `Ok(None)`, redirect to `/#/edit/<encoded_key>`; on `Ok(Some(template))`, apply existing `%s` substitution and `302`).
7. Update `main()`:
   - Load `AppConfig::from_env()` (exit 1 on error).
   - Connect `Database::connect(&app_cfg.db).await` (exit 1 on error).
   - Run `db.run_migrations().await` (exit 1 on error).
   - Derive `derived_secret = auth::derive_auth_token(&app_cfg.user_secret_key)` and call `db.sync_user(&app_cfg.username, &derived_secret).await` (exit 1 on error).
   - Construct `AppState` with `active_user_id: user.user_id` and start Axum server.

- [ ] **Step 4: Run full test suite and verify zero unused warnings**

Run: `cargo test`
Expected: PASS (all unit + integration tests pass, zero compiler warnings).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/main.rs
git rm src/config.rs
git commit -m "feat: switch golinks handlers and startup to SQLite/PostgreSQL database"
```

---

### Task 6: Dockerfiles, CI Workflows, and Documentation

**Files:**
- Modify: `Dockerfile`
- Modify: `Dockerfile.release`
- Modify: `.github/workflows/docker-build.yml`
- Modify: `.github/workflows/release.yml`
- Modify: `AGENTS.md`
- Modify: `MEMORY.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: Final env vars, `./db/` layout, `build.rs`, and `src/db/` module layout from Tasks 1–5.
- Produces: Updated container build definitions, CI/release workflows, and repository documentation.

- [ ] **Step 1: Update `Dockerfile` and `Dockerfile.release`**

- In `Dockerfile`:
  - In `backend-builder`, add `COPY build.rs ./` and `COPY db ./db` before `RUN cargo build --release`.
  - Replace `ENV GOLINKS_FILE=/data/config.yaml` with:
    ```dockerfile
    ENV GOLINKS_DB_ENGINE=sqlite
    ENV GOLINKS_DB_PATH=/data/golinks.db
    ```
- In `Dockerfile.release`:
  - Replace `ENV GOLINKS_FILE=/data/config.yaml` with:
    ```dockerfile
    ENV GOLINKS_DB_ENGINE=sqlite
    ENV GOLINKS_DB_PATH=/data/golinks.db
    ```

- [ ] **Step 2: Update `.github/workflows/docker-build.yml` and `.github/workflows/release.yml`**

- In `.github/workflows/docker-build.yml`:
  - Change Linux matrix targets to:
    - `target: x86_64-unknown-linux-musl`, `name: golinks-linux-x64`, `use-cross: true`
    - `target: aarch64-unknown-linux-musl`, `name: golinks-linux-arm64`, `use-cross: true`
  - Keep running `cargo test` natively on `ubuntu-latest` by changing the test step condition from `if: matrix.use-cross == false` to `if: matrix.target == 'x86_64-unknown-linux-musl'`.
- In `.github/workflows/release.yml`:
  - Change Linux matrix targets to:
    - `target: x86_64-unknown-linux-musl`, `name: golinks-linux-x64`, `use-cross: true`
    - `target: aarch64-unknown-linux-musl`, `name: golinks-linux-arm64`, `use-cross: true`
  - Change the `aarch64-pc-windows-msvc` matrix entry `os` from `windows-latest` to `windows-11-arm`.

- [ ] **Step 3: Update `AGENTS.md`, `MEMORY.md`, and `README.md`**

- `AGENTS.md`: Update Repository Layout (`build.rs`, `db/`, `src/db/`, removed `src/config.rs`), replace Critical Architectural Invariant #3 (YAML/hot-reload) with Database & Migrations invariants (`GOLINKS_DB_ENGINE`, `GOLINKS_USER_SECRET_KEY`, `GOLINKS_USERNAME`, embedded `./db/` SQL files, Postgres `golinks` schema vs SQLite `main` schema, user-scoped DB methods), and update Local Development commands.
- `MEMORY.md`: Update Backend API persistence notes, Environment Variables table, and Key Decisions & Rationale (removing YAML/notify notes, adding `sqlx`, embedded migrations, `musl`/`windows-11-arm` CI, and derived secret storage in `users.user_secret`).
- `README.md`: Replace YAML configuration instructions with SQLite & PostgreSQL environment variable documentation, Docker `docker run` examples (passing `-e GOLINKS_USER_SECRET_KEY=...` and `-v /path/to/data:/data`), and local `cargo run` examples.

- [ ] **Step 4: Run final verification checks**

Run: `cargo test && cargo build`
Expected: PASS (all tests pass, binary builds cleanly).

Also verify no stale YAML/config references remain in code or Dockerfiles:
Run: `grep -rn "GOLINKS_FILE\|serde_yaml_ng\|notify" src/ Cargo.toml Dockerfile Dockerfile.release`
Expected: No matches (exit code 1).

- [ ] **Step 5: Commit**

```bash
git add Dockerfile Dockerfile.release .github/workflows/docker-build.yml .github/workflows/release.yml AGENTS.md MEMORY.md README.md
git commit -m "chore: update Dockerfiles, CI workflows, and docs for database storage"
```
