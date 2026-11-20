# golinks

A lightweight, self-hosted "go links" HTTP redirect service written in Rust with a React management UI.

## Features

- **Cookie-based authentication:** Secrets are never placed in URLs, keeping them out of browser history, `Referer` headers, and reverse-proxy access logs.
- **React management UI on `/`:** Sign in, browse/filter links, create new links, edit/rename keywords, and delete links—all served from `/` using `HashRouter` and `?action=...` API endpoints so link keywords never collide with UI or API routes.
- **Quick create for unknown links:** Visiting an unknown keyword while authenticated redirects to `/#/edit/<keyword>` with the keyword pre-filled so you can save it immediately.
- **Stateless `HttpOnly` sessions:** Session cookies store an `HMAC-SHA256` token derived from `GOLINKS_USER_SECRET_KEY` (`SameSite=Lax`, 5-year `Max-Age`). Only the derived token is persisted in the database; changing `GOLINKS_USER_SECRET_KEY` rotates the stored token and invalidates existing sessions.
- **SQLite & PostgreSQL storage:** Stores users and links in SQLite (zero-config default with WAL mode) or PostgreSQL (dedicated `golinks` schema), with embedded schema initialization and automatic migrations on startup.
- **Flexible `%s` substitution:** Supports both `/` and space as the separator between the link key and parameter, with `application/x-www-form-urlencoded` encoding for the parameter.
- **Security headers on all responses:** `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, and `X-Content-Type-Options: nosniff`.

## Configuration

`golinks` is configured entirely via environment variables. At minimum, set `GOLINKS_USER_SECRET_KEY`:

- **SQLite (default):** Set `GOLINKS_USER_SECRET_KEY` and optionally `GOLINKS_DB_PATH` (defaults to `./golinks.db` locally, or `/data/golinks.db` in Docker). Parent directories are created automatically.
- **PostgreSQL:** Set `GOLINKS_DB_ENGINE=postgresql` along with `GOLINKS_DB_HOST`, `GOLINKS_DB_NAME`, `GOLINKS_DB_USERNAME`, and `GOLINKS_DB_PASSWORD`. The target database and user must exist with permission to create and write to the `golinks` schema.

### Environment Variables

| Variable | Default | Description |
| --- | --- | --- |
| `GOLINKS_USER_SECRET_KEY` | *(required)* | Secret key used for login and session token derivation. Never stored in plaintext in the database or cookies. |
| `GOLINKS_USERNAME` | `golinks` | Active username in the `users` table (max 32 characters). |
| `GOLINKS_DB_ENGINE` | `sqlite` | Database backend: `sqlite` or `postgresql`. |
| `GOLINKS_DB_PATH` | `./golinks.db` *(local)* / `/data/golinks.db` *(Docker)* | Path to the SQLite database file (`sqlite` engine only). |
| `GOLINKS_DB_HOST` | *(required for `postgresql`)* | PostgreSQL server hostname. |
| `GOLINKS_DB_PORT` | `5432` | PostgreSQL server port. |
| `GOLINKS_DB_NAME` | *(required for `postgresql`)* | PostgreSQL database name. |
| `GOLINKS_DB_USERNAME` | *(required for `postgresql`)* | PostgreSQL username. |
| `GOLINKS_DB_PASSWORD` | *(required for `postgresql`; may be empty)* | PostgreSQL password. |
| `GOLINKS_ADDR` | `0.0.0.0:8080` | Address and port to bind the HTTP server. |
| `GOLINKS_SECURE_COOKIE` | `true` | Adds the `Secure` attribute to the session cookie. Set to `false` for local `http://localhost` testing. |
| `GOLINKS_UI_FILE` | `public/index.html` or `frontend/dist/index.html` | Optional explicit path to the built single-file UI `index.html`. |
| `FAVICON_FILE` | *(bundled magnifier `.ico`)* | Optional path to override the built-in `/favicon.ico` (`.ico`, `.png`, `.svg`, `.jpg`, `.webp`, `.gif`). |

## Browser Setup (Chrome / Brave)

1. Open **Settings → Search engine → Manage search engines and site search**.
2. Add a new site search:
   - **Name:** `Golinks`
   - **Shortcut:** `go`
   - **URL:** `https://go.example.com/%s`
3. Type in the address bar:
   - `go docs` → `https://docs.example.com`
   - `go google/use curl/wget` → `https://www.google.com/search?q=use+curl%2Fwget`
   - `go google use curl/wget` → `https://www.google.com/search?q=use+curl%2Fwget`
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
