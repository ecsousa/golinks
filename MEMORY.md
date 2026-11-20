# MEMORY.md

Living project memory, design decisions, and current state for `golinks`.

> **Maintenance Note:** Update this file (and `AGENTS.md`) whenever requirements, API contracts, environment variables, UI flows, or architectural decisions change.

---

## Current Behavior & Flows

### 1. Routing & Redirect Semantics
- **`GET /` (no `action` query param):** Serves the single-file React UI (`index.html`). Loaded in priority order from `GOLINKS_UI_FILE` → `public/index.html` → `frontend/dist/index.html` → built-in fallback HTML.
- **`GET /favicon.ico`:** Serves `FAVICON_FILE` if set (inferring `Content-Type` from extension), otherwise serves the bundled `assets/favicon.ico` (`image/x-icon`). Does not require authentication so the login page displays the icon cleanly.
- **Unauthenticated `GET /<anything>`:** Redirects (`302 Found`) to `/?next=<url-encoded path_and_query>`. After logging in via the React UI, the browser navigates to `next` (validated to be a safe relative path) so the original go-link executes seamlessly.
- **Authenticated `GET /<keyword>[/<param> | <param>]`:**
  - Validates the `golinks_auth` cookie against the active user's `users.user_secret` in the database, then looks up `link_target` in `links` scoped by `active_user_id`.
  - Splits on the earliest separator among `/`, `%20`, ` `, `%2F`, `%2f` so both `go google/use curl/wget` and `go google use curl/wget` work identically.
  - **Link found, no `%s`:** Redirects (`302 Found`) directly to the target, ignoring trailing slashes and any extra segments.
  - **Link found, contains `%s`:** Percent-decodes the remainder, encodes it with `form_urlencoded::byte_serialize` (spaces → `+`, `/` → `%2F`), and substitutes `%s` (or `""` if no remainder was given).
  - **Link not found:** Redirects (`302 Found`) to `/#/edit/<percent-encoded keyword>` so the user can immediately create it.

### 2. Backend API Contract (all on `/`)
- `GET /?action=getLinks` *(auth required)* → loads active user from DB, checks `golinks_auth`, queries `links` for `user_id`, returns `200 { "links": { ... } }` (alphabetically sorted via `BTreeMap`) or `401`.
- `POST /?action=login` → JSON `{ "secret": "..." }` → derives `HMAC-SHA256(secret, "golinks-session-v1")`, constant-time checks against `user.user_secret` in DB; sets `golinks_auth` cookie (`HttpOnly; SameSite=Lax; Path=/; Max-Age=157680000[; Secure]`) and returns `200 { "ok": true }` or `401`.
- `POST /?action=saveLink` *(auth required)* → JSON `{ "originalKey"?: "...", "key": "...", "target": "..." }` → validates keyword (1–32 chars, no whitespace/`/`/`?`/`#`) and target (1–512 chars, `http://` or `https://`), atomically creates/updates/renames in `links` scoped by `user_id` via `Database::save_link`, returns `200 { "links": { ... } }`.
- `POST /?action=deleteLink` *(auth required)* → JSON `{ "key": "..." }` → deletes link for `user_id` via `Database::delete_link`, returns `200 { "links": { ... } }` or `404`.

### 3. React UI (`frontend/`)
- Built with **Vite + React 18 + `react-router-dom` (`HashRouter`) + `vite-plugin-singlefile`** (inlines JS & CSS into one `dist/index.html`).
- **Login view (`LoginPage.jsx`):** Shown whenever `GET /?action=getLinks` returns `401`. Supports `?next=...` redirect after login.
- **Links list (`LinkList.jsx`, `/#/`):** Sorted list, live search/filter box, **New** button (`/#/edit`), click row to edit (`/#/edit/<keyword>`), and **Open ↗** action.
  - If the link target contains `%s`, clicking **Open ↗** opens a modal dialog prompting for the parameter (**Go** / **Cancel**, `Escape` and backdrop dismiss) and opens `/<keyword>/<encoded-param>` in a new tab.
  - Otherwise **Open ↗** opens `/<keyword>` directly in a new tab.
- **Edit/Create view (`EditLink.jsx`, `/#/edit` and `/#/edit/:keyword`):** Keyword and Target inputs, **Save**, **Cancel**, and **Delete** (hidden when creating a new link or when `/#/edit/<keyword>` does not yet exist, with `<keyword>` pre-filled).

### 4. Environment Variables
| Variable | Default | Purpose |
| --- | --- | --- |
| `GOLINKS_USER_SECRET_KEY` | *(required)* | Raw secret key used to derive the active user's `HMAC-SHA256` token stored in `users.user_secret` and `golinks_auth`. |
| `GOLINKS_USERNAME` | `golinks` | Active username in `users` (max 32 chars). |
| `GOLINKS_DB_ENGINE` | `sqlite` | Database engine (`sqlite` or `postgresql`). |
| `GOLINKS_DB_PATH` | `./golinks.db` *(local)* / `/data/golinks.db` *(Docker)* | SQLite database file path (`sqlite` only; supports `:memory:` in tests). |
| `GOLINKS_DB_HOST` | *(required for `postgresql`)* | PostgreSQL hostname. |
| `GOLINKS_DB_PORT` | `5432` | PostgreSQL port. |
| `GOLINKS_DB_NAME` | *(required for `postgresql`)* | PostgreSQL database name. |
| `GOLINKS_DB_USERNAME` | *(required for `postgresql`)* | PostgreSQL username. |
| `GOLINKS_DB_PASSWORD` | *(required for `postgresql`; may be empty)* | PostgreSQL password. |
| `GOLINKS_ADDR` | `0.0.0.0:8080` | Bind address and port. |
| `GOLINKS_SECURE_COOKIE` | `true` | Adds `Secure` cookie attribute (`false` for local HTTP). |
| `GOLINKS_UI_FILE` | `public/index.html` / `frontend/dist/index.html` | Optional explicit path to UI HTML bundle. |
| `FAVICON_FILE` | *(bundled `assets/favicon.ico`)* | Optional custom favicon override. |

---

## Key Decisions & Rationale

1. **Cookie Auth over URL-embedded Secret:** Chosen to prevent the secret from leaking via `Referer` headers, browser history/sync, and reverse-proxy access logs.
2. **Stateless HMAC-SHA256 Cookie Token & Derived Secret Storage:** `auth::derive_auth_token` computes `HMAC-SHA256(GOLINKS_USER_SECRET_KEY, "golinks-session-v1")` and stores only the derived hex digest in `users.user_secret` and the `golinks_auth` cookie—never raw secrets. Changing `GOLINKS_USER_SECRET_KEY` updates `users.user_secret` on startup and automatically invalidates existing sessions.
3. **5-Year Cookie `Max-Age` (`157680000`):** Keeps sessions persistent for as long as the browser permits (Chrome caps at 400 days).
4. **Single-File Vite Bundle (`vite-plugin-singlefile`):** Avoids serving `/assets/*` or `/bundle.js` paths that would collide with link keywords or fail auth before login renders.
5. **SQLite & PostgreSQL via `sqlx` + Embedded Migrations:** Replaced YAML/`notify` storage with `sqlx` (`sqlite` with WAL + foreign keys, and `postgresql` with `tls-rustls-ring-webpki`, `golinks` schema, and `pg_advisory_lock`). `build.rs` embeds `db/{sqlite,postgres}/full_schema.sql` and sorted `migration_vXXXXXXX.sql` files at compile time and enforces version parity across engines. All link operations are scoped by `user_id` for clean multi-user isolation.
6. **Multi-Arch CI Strategy:** GitHub Actions builds `frontend/` once, builds static Linux `musl` binaries (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`) via `cross`, Windows (`x86_64-pc-windows-msvc` on `windows-latest`, `aarch64-pc-windows-msvc` on `windows-11-arm`), and macOS release binaries, and packages `public/` + Linux `musl` binaries with `Dockerfile.release` to `ghcr.io`.
7. **Public Repo Privacy:** All personal domains/service names were scrubbed; keep all examples and tests generic (`example.com`, `docs`, `notes`, `google`).
