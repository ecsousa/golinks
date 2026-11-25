# MEMORY.md

Living project memory, design decisions, and current state for `golinks`.

> **Maintenance Note:** Update this file (and `AGENTS.md`) whenever requirements, API contracts, environment variables, UI flows, or architectural decisions change.

---

## Current Behavior & Flows

### 1. Routing & Redirect Semantics
- **`GET /` (no `action` query param):**
  - **Single-user mode (`GOLINKS_OIDC_ENABLED=false`):** Serves the single-file React UI (`index.html`). If a valid `golinks_auth` JWT cookie is present, refreshes it with a new sliding-window expiry.
  - **OIDC mode (`GOLINKS_OIDC_ENABLED=true`):**
    - If `code` or `error` query param is present, handles the OIDC callback (verifies `golinks_oidc_state` cookie, exchanges code + PKCE, verifies ID token & nonce, extracts `GOLINKS_OIDC_USERNAME_CLAIM` from ID token or `userinfo` fallback, provisions/loads user via `Database::get_or_create_user`, sets `golinks_auth` JWT cookie, clears `golinks_oidc_state`, and redirects to sanitized `next`). OIDC errors return `400`/`401`/`403`/`502` without redirecting in a loop.
    - Otherwise, if authenticated via `golinks_auth` JWT, serves the UI HTML with a refreshed `Set-Cookie`; if unauthenticated, redirects (`302 Found`) directly to the OIDC provider with a signed `golinks_oidc_state` cookie.
- **`GET /favicon.ico`:** Serves `FAVICON_FILE` if set (inferring `Content-Type` from extension), otherwise serves the bundled `assets/favicon.ico` (`image/x-icon`). Does not require authentication.
- **Unauthenticated `GET /<anything>`:**
  - Single-user mode: redirects (`302 Found`) to `/?next=<url-encoded path_and_query>`.
  - OIDC mode: redirects (`302 Found`) directly to the OIDC provider with `next` preserved in `golinks_oidc_state`.
- **Authenticated `GET /<keyword>[ <param>]`:**
  - Validates the `golinks_auth` HS256 JWT cookie (`sub` -> DB user lookup -> constant-time HMAC-SHA256 verification against non-empty `user.user_secret`, plus `user_id == active_user_id` in single-user mode), looks up `link_target` in `links` scoped by `user.user_id`, and attaches a refreshed `Set-Cookie` (sliding window).
  - Splits on the earliest space separator (`%20` or literal space) only—`/` is allowed inside keywords (e.g., `key1/subitem something else` resolves keyword `key1/subitem` with substitution `something else`).
  - **Link found, no `%s`:** Redirects (`302 Found`) directly to the target, ignoring any space-separated remainder.
  - **Link found, contains `%s`:** Percent-decodes the remainder, encodes it with `form_urlencoded::byte_serialize` (spaces → `+`, `/` → `%2F`), and substitutes `%s` (or `""` if no remainder was given).
  - **Link not found:** Redirects (`302 Found`) to `/#/edit/<percent-encoded keyword>` so the user can immediately create it.

### 2. Backend API Contract (all on `/`)
- `GET /?action=getLinks` *(auth required)* → validates `golinks_auth` JWT, queries `links` for `user.user_id`, returns `200 { "links": { ... } }` with refreshed `Set-Cookie` or `401 { "error": "Unauthorized", "oidcEnabled": <bool> }`.
- `POST /?action=login` → Single-user mode only (returns `403` when OIDC is enabled): JSON `{ "secret": "..." }` → derives `HMAC-SHA256(secret, "golinks-session-v1")`, constant-time checks against `user.user_secret` in DB; sets HS256 JWT `golinks_auth` cookie (`HttpOnly; SameSite=Lax; Path=/; Max-Age=<session_ttl_secs>[; Secure]`) and returns `200 { "ok": true }` or `401`.
- `POST /?action=saveLink` *(auth required)* → JSON `{ "originalKey"?: "...", "key": "...", "target": "..." }` → validates keyword (1–32 chars, no whitespace/`?`/`#`, must not start with `/`; `/` allowed inside) and target (1–512 chars, `http://` or `https://`), atomically creates/updates/renames in `links` scoped by `user.user_id`, returns `200 { "links": { ... } }` with refreshed `Set-Cookie`.
- `POST /?action=deleteLink` *(auth required)* → JSON `{ "key": "..." }` → deletes link for `user.user_id`, returns `200 { "links": { ... } }` with refreshed `Set-Cookie` or `404`.

### 3. React UI (`frontend/`)
- Built with **Vite + React 18 + `react-router-dom` (`HashRouter`) + `vite-plugin-singlefile`** (inlines JS & CSS into one `dist/index.html`).
- **401 handling:** When an API call returns `401` with `oidcEnabled: true`, the SPA navigates to `/` (`window.location.replace('/')`) to trigger the backend's direct OIDC redirect. When `oidcEnabled` is false, it renders `<LoginPage />` (supporting `?next=...`).
- **Links list (`LinkList.jsx`, `/#/`):** Sorted list, live search/filter box, **New** button (`/#/edit`), click row to edit (`/#/edit/<keyword>`), and **Open ↗** action.
  - If the link target contains `%s`, clicking **Open ↗** opens a modal dialog prompting for the parameter (**Go** / **Cancel**, `Escape` and backdrop dismiss) and opens `/<keyword>%20<encoded-param>` in a new tab.
  - Otherwise **Open ↗** opens `/<keyword>` directly in a new tab.
- **Edit/Create view (`EditLink.jsx`, `/#/edit` and `/#/edit/:keyword`):** Keyword and Target inputs, **Save**, **Cancel**, and **Delete** (hidden when creating a new link or when `/#/edit/<keyword>` does not yet exist, with `<keyword>` pre-filled).

### 4. Environment Variables
| Variable | Default | Purpose |
| --- | --- | --- |
| `GOLINKS_OIDC_ENABLED` | `false` | Enables multi-user OIDC mode (`true`/`false`); ignores `GOLINKS_USER_SECRET_KEY` and `GOLINKS_USERNAME`. |
| `GOLINKS_SESSION_TTL_DAYS` | `30` | Sliding-window JWT session lifetime in days (`1`–`3650`) for both single-user and OIDC modes. |
| `GOLINKS_USER_SECRET_KEY` | *(required when OIDC disabled)* | Raw secret key used to derive the single user's `HMAC-SHA256` token stored in `users.user_secret`. |
| `GOLINKS_USERNAME` | `golinks` | Active username in `users` when OIDC is disabled (max 255 chars). |
| `GOLINKS_OIDC_ISSUER_URL` | *(required when OIDC enabled)* | OIDC issuer URL for discovery. |
| `GOLINKS_OIDC_CLIENT_ID` | *(required when OIDC enabled)* | OIDC client ID. |
| `GOLINKS_OIDC_CLIENT_SECRET` | *(required when OIDC enabled)* | OIDC client secret (also derives HMAC key for `golinks_oidc_state`). |
| `GOLINKS_OIDC_REDIRECT_URI` | *(required when OIDC enabled)* | Registered callback URL pointing to `/` (e.g., `https://go.example.com/`). |
| `GOLINKS_OIDC_SCOPES` | `openid profile email` | Whitespace-separated OIDC scopes (`openid` always included). |
| `GOLINKS_OIDC_USERNAME_CLAIM` | `preferred_username` | Claim name in ID token / `userinfo` used as `users.user_name`. |
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

1. **Cookie Auth over URL-embedded Secret:** Chosen to prevent secrets/tokens from leaking via `Referer` headers, browser history/sync, and reverse-proxy access logs.
2. **Unified HS256 JWT Sessions with Per-User Secrets & Sliding Window:** Both OIDC and single-user modes issue compact HS256 JWTs (`sub`, `iat`, `exp`) signed with `users.user_secret` and extend the expiry by `GOLINKS_SESSION_TTL_DAYS` (default `30`) on every valid request. Clearing `user_secret` to `''` in DB immediately invalidates a user's sessions and triggers automatic regeneration on their next OIDC login.
3. **Root `/` as OIDC Callback URI + Stateless Signed State Cookie:** Avoids reserving any top-level path (no keyword collisions) and works with strict OIDC providers that forbid query params in `redirect_uri`. `golinks_oidc_state` is HMAC-signed with a key derived from `GOLINKS_OIDC_CLIENT_SECRET`, keeping the service stateless.
4. **Rustls-Only OIDC (`openidconnect` + `reqwest`):** Avoids OpenSSL so static Linux `musl` cross-builds (`x86_64`, `aarch64`) keep working cleanly. Discovery metadata/JWKS is cached (24h TTL, lazy retry if provider is still booting at startup, and one-shot refresh on ID token verification failure).
5. **Single-File Vite Bundle (`vite-plugin-singlefile`):** Avoids serving `/assets/*` or `/bundle.js` paths that would collide with link keywords or fail auth before login renders.
6. **SQLite & PostgreSQL via `sqlx` + Embedded Migrations (`v0000002`):** Schema `v0000002` widens `users.user_name` to `VARCHAR(255)` for OIDC username claims. `build.rs` embeds `db/{sqlite,postgres}/full_schema.sql` and sorted `migration_vXXXXXXX.sql` files at compile time and enforces version parity across engines.
7. **Public Repo Privacy:** All personal domains/service names are scrubbed; keep all examples and tests generic (`example.com`, `auth.example.com`, `go.example.com`, `alice`, `bob`, `docs`, `notes`, `google`).
