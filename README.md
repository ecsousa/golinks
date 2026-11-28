# golinks

A lightweight, self-hosted "go links" HTTP redirect service written in Rust with a React management UI.

## Features

- **Cookie-based authentication with sliding-window JWTs:** Secrets are never placed in URLs, keeping them out of browser history, `Referer` headers, and reverse-proxy access logs. Both single-user and OIDC modes store an HS256 JWT signed with the user's `user_secret` in an `HttpOnly; SameSite=Lax` cookie (`golinks_auth`) whose expiry slides forward on every valid request (`GOLINKS_SESSION_TTL_DAYS`, default `30` days).
- **Multi-user OIDC authentication (optional):** Enable `GOLINKS_OIDC_ENABLED=true` to authenticate users against any standard OpenID Connect provider (such as Authentik). Unauthenticated requests redirect straight to the OIDC provider, auto-provision users on first login with a random per-user secret, and strictly isolate each user's links.
- **React management UI on `/`:** Sign in, browse/filter links by text or tags, organize links with per-user tags (multi-select OR filtering on the main page and chip-based tag entry when creating/editing), create new links, edit/rename keywords, and delete links—all served from `/` using `HashRouter` and `?action=...` API endpoints so link keywords never collide with UI or API routes.
- **Quick create for unknown links:** Visiting an unknown keyword while authenticated redirects to `/#/edit/<keyword>` with the keyword pre-filled so you can save it immediately.
- **SQLite & PostgreSQL storage:** Stores users and links in SQLite (zero-config default with WAL mode) or PostgreSQL (dedicated `golinks` schema), with embedded schema initialization and automatic migrations on startup.
- **Flexible `%s` substitution:** Uses space as the separator between the link keyword and parameter (allowing `/` inside keywords such as `docs/api`), with `application/x-www-form-urlencoded` encoding for the parameter.
- **Security headers on all responses:** `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, and `X-Content-Type-Options: nosniff`.

## Configuration

`golinks` is configured entirely via environment variables:

- **Single-user mode (default, `GOLINKS_OIDC_ENABLED=false`):** Set `GOLINKS_USER_SECRET_KEY` (and optionally `GOLINKS_USERNAME`).
- **Multi-user OIDC mode (`GOLINKS_OIDC_ENABLED=true`):** Set `GOLINKS_OIDC_ISSUER_URL`, `GOLINKS_OIDC_CLIENT_ID`, `GOLINKS_OIDC_CLIENT_SECRET`, and `GOLINKS_OIDC_REDIRECT_URI`. `GOLINKS_USER_SECRET_KEY` and `GOLINKS_USERNAME` are ignored in this mode.
- **SQLite (default):** Optionally set `GOLINKS_DB_PATH` (defaults to `./golinks.db` locally, or `/data/golinks.db` in Docker). Parent directories are created automatically.
- **PostgreSQL:** Set `GOLINKS_DB_ENGINE=postgresql` along with `GOLINKS_DB_HOST`, `GOLINKS_DB_NAME`, `GOLINKS_DB_USERNAME`, and `GOLINKS_DB_PASSWORD`. The target database and user must exist with permission to create and write to the `golinks` schema.

### Environment Variables

| Variable | Default | Description |
| --- | --- | --- |
| `GOLINKS_OIDC_ENABLED` | `false` | Enables multi-user OIDC authentication (`true`/`false`). When `true`, `GOLINKS_USER_SECRET_KEY` and `GOLINKS_USERNAME` are ignored. |
| `GOLINKS_SESSION_TTL_DAYS` | `30` | Sliding-window JWT session lifetime in days (`1`–`3650`), applied in both single-user and OIDC modes. |
| `GOLINKS_USER_SECRET_KEY` | *(required when OIDC disabled)* | Secret key used for single-user login and `user_secret` derivation. Never stored in plaintext in the database or cookies. |
| `GOLINKS_USERNAME` | `golinks` | Active username in the `users` table when OIDC is disabled (max 255 characters). |
| `GOLINKS_OIDC_ISSUER_URL` | *(required when OIDC enabled)* | OIDC provider issuer URL used for `.well-known/openid-configuration` discovery (e.g., `https://auth.example.com/application/o/golinks/`). |
| `GOLINKS_OIDC_CLIENT_ID` | *(required when OIDC enabled)* | OIDC client ID. |
| `GOLINKS_OIDC_CLIENT_SECRET` | *(required when OIDC enabled)* | OIDC client secret (also used to derive the HMAC signing key for the short-lived `golinks_oidc_state` cookie). |
| `GOLINKS_OIDC_REDIRECT_URI` | *(required when OIDC enabled)* | Full callback URL registered in the OIDC provider pointing to the root of `golinks` (e.g., `https://go.example.com/`). |
| `GOLINKS_OIDC_SCOPES` | `openid profile email` | Whitespace-separated OIDC scopes (`openid` is always included). |
| `GOLINKS_OIDC_USERNAME_CLAIM` | `preferred_username` | Claim name in the ID token (or `userinfo` fallback) used as `users.user_name`. |
| `GOLINKS_DB_ENGINE` | `sqlite` | Database backend: `sqlite` or `postgresql`. |
| `GOLINKS_DB_PATH` | `./golinks.db` *(local)* / `/data/golinks.db` *(Docker)* | Path to the SQLite database file (`sqlite` engine only). |
| `GOLINKS_DB_HOST` | *(required for `postgresql`)* | PostgreSQL server hostname. |
| `GOLINKS_DB_PORT` | `5432` | PostgreSQL server port. |
| `GOLINKS_DB_NAME` | *(required for `postgresql`)* | PostgreSQL database name. |
| `GOLINKS_DB_USERNAME` | *(required for `postgresql`)* | PostgreSQL username. |
| `GOLINKS_DB_PASSWORD` | *(required for `postgresql`; may be empty)* | PostgreSQL password. |
| `GOLINKS_ADDR` | `0.0.0.0:8080` | Address and port to bind the HTTP server. |
| `GOLINKS_SECURE_COOKIE` | `true` | Adds the `Secure` attribute to cookies. Set to `false` for local `http://localhost` testing. |
| `GOLINKS_UI_FILE` | `public/index.html` or `frontend/dist/index.html` | Optional explicit path to the built single-file UI `index.html`. |
| `FAVICON_FILE` | *(bundled magnifier `.ico`)* | Optional path to override the built-in `/favicon.ico` (`.ico`, `.png`, `.svg`, `.jpg`, `.webp`, `.gif`). |

## OIDC & Authentik Setup

When `GOLINKS_OIDC_ENABLED=true`, unauthenticated requests to `/` or `/<keyword>` redirect directly to your OIDC provider. After login, the provider redirects back to `/` (`GOLINKS_OIDC_REDIRECT_URI`), where `golinks` verifies the ID token (with PKCE and nonce validation), extracts the username from `GOLINKS_OIDC_USERNAME_CLAIM` (checking the ID token first and falling back to the `userinfo` endpoint), provisions the user with a random 64-character hex `user_secret` if new, and sets the sliding-window HS256 JWT cookie (`golinks_auth`).

> **Tip (forcing session revocation/rotation):** To revoke all active sessions for a specific OIDC user, clear their `user_secret` in the database (`UPDATE users SET user_secret = '' WHERE user_name = 'alice';`). Existing cookies immediately become invalid, and `golinks` automatically generates a fresh random secret on their next OIDC login.

### Setting Up Authentik

1. In the Authentik Admin Interface, go to **Applications → Providers → Create → OAuth2/OpenID Provider**:
   - **Name:** `golinks`
   - **Authentication flow:** your preferred authentication flow
   - **Authorization flow:** `default-provider-authorization-implicit-consent` (or explicit consent)
   - **Client type:** `Confidential`
   - **Client ID & Client Secret:** copy both values for `GOLINKS_OIDC_CLIENT_ID` and `GOLINKS_OIDC_CLIENT_SECRET`
   - **Redirect URIs/Origins (RegEx / Strict):** `https://go.example.com/` (exact root URL matching `GOLINKS_OIDC_REDIRECT_URI`—no `/callback` path so go-link keywords never collide)
   - **Signing Key:** select a signing key (e.g. `authentik Self-signed Certificate`)
   - **Advanced protocol settings → Scopes:** ensure `openid`, `profile`, and `email` are included
2. Go to **Applications → Applications → Create**:
   - **Name:** `Golinks`
   - **Slug:** `golinks`
   - **Provider:** select the `golinks` provider created above
3. Open the `golinks` provider page and copy the **OpenID Configuration Issuer** URL (typically `https://auth.example.com/application/o/golinks/`).
4. Configure `golinks` with those values:

```bash
docker run -d \
  --name golinks \
  -p 8080:8080 \
  -e GOLINKS_OIDC_ENABLED=true \
  -e GOLINKS_OIDC_ISSUER_URL=https://auth.example.com/application/o/golinks/ \
  -e GOLINKS_OIDC_CLIENT_ID=your-client-id \
  -e GOLINKS_OIDC_CLIENT_SECRET=your-client-secret \
  -e GOLINKS_OIDC_REDIRECT_URI=https://go.example.com/ \
  -e GOLINKS_SESSION_TTL_DAYS=30 \
  -e GOLINKS_DB_ENGINE=postgresql \
  -e GOLINKS_DB_HOST=db.example.com \
  -e GOLINKS_DB_NAME=golinks \
  -e GOLINKS_DB_USERNAME=golinks \
  -e GOLINKS_DB_PASSWORD=someDbPassword \
  ghcr.io/<owner>/golinks:latest
```

### Generic OIDC Providers

Any standards-compliant OIDC provider (Keycloak, Authelia, Pocket ID, Okta, Google, etc.) works with the same configuration:
- Register a **Confidential** authorization-code client with **PKCE (S256)** enabled.
- Set the redirect URI to your `golinks` root URL (`https://go.example.com/`).
- Set `GOLINKS_OIDC_ISSUER_URL` to the provider's issuer URL (the base URL serving `/.well-known/openid-configuration`).
- If your provider uses a different username claim (e.g., `email` or `sub`), set `GOLINKS_OIDC_USERNAME_CLAIM`.

## Browser Setup (Chrome / Brave)

1. Open **Settings → Search engine → Manage search engines and site search**.
2. Add a new site search:
   - **Name:** `Golinks`
   - **Shortcut:** `go`
   - **URL:** `https://go.example.com/%s`
3. Type in the address bar:
   - `go docs` → `https://docs.example.com`
   - `go google use curl/wget` → `https://www.google.com/search?q=use+curl%2Fwget`
   - `go docs/api auth` → substitutes `auth` into the `docs/api` link target
   - `go newlink` (not yet defined) → opens `/#/edit/newlink` to create it

On the first visit, you'll be redirected to `/?next=...` to enter your configured `GOLINKS_USER_SECRET_KEY`, after which the `HttpOnly` cookie is stored and you're redirected straight to your requested link.

## Running with Docker

By default, the Docker image uses SQLite at `/data/golinks.db`. Mount `/data` to persist your database across container restarts:

```bash
docker run -d \
  --name golinks \
  -p 8080:8080 \
  -e GOLINKS_USER_SECRET_KEY=someSuperSecretValue \
  -v /path/to/data:/data \
  ghcr.io/<owner>/golinks:latest
```

To use PostgreSQL instead:

```bash
docker run -d \
  --name golinks \
  -p 8080:8080 \
  -e GOLINKS_USER_SECRET_KEY=someSuperSecretValue \
  -e GOLINKS_DB_ENGINE=postgresql \
  -e GOLINKS_DB_HOST=db.example.com \
  -e GOLINKS_DB_PORT=5432 \
  -e GOLINKS_DB_NAME=golinks \
  -e GOLINKS_DB_USERNAME=golinks \
  -e GOLINKS_DB_PASSWORD=someDbPassword \
  ghcr.io/<owner>/golinks:latest
```

To build locally:

```bash
docker build -t golinks .
docker run -d \
  -p 8080:8080 \
  -e GOLINKS_USER_SECRET_KEY=someSuperSecretValue \
  -v /path/to/data:/data \
  golinks
```

## Running Locally

Build the frontend bundle:

```bash
cd frontend
npm ci
npm run build
```

Run the Rust server with SQLite (it automatically picks up `frontend/dist/index.html` and creates `./golinks.db`):

```bash
GOLINKS_USER_SECRET_KEY=someSuperSecretValue GOLINKS_SECURE_COOKIE=false cargo run
```

Or run against PostgreSQL:

```bash
GOLINKS_USER_SECRET_KEY=someSuperSecretValue \
GOLINKS_DB_ENGINE=postgresql \
GOLINKS_DB_HOST=localhost \
GOLINKS_DB_NAME=golinks \
GOLINKS_DB_USERNAME=golinks \
GOLINKS_DB_PASSWORD=someDbPassword \
GOLINKS_SECURE_COOKIE=false \
cargo run
```

For frontend hot-reloading during development, run the Rust server on `:8080` and start Vite on `:3000` (`npm --prefix frontend run dev`), which proxies `/?action=...` API requests to `:8080`.

Run backend tests:

```bash
cargo test
```
