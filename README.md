# golinks

A lightweight, self-hosted "go links" HTTP redirect service written in Rust with a React management UI.

## Features

- **Cookie-based authentication:** Secrets are never placed in URLs, keeping them out of browser history, `Referer` headers, and reverse-proxy access logs.
- **React management UI on `/`:** Sign in, browse/filter links, create new links, edit/rename keywords, and delete links—all served from `/` using `HashRouter` and `?action=...` API endpoints so link keywords never collide with UI or API routes.
- **Quick create for unknown links:** Visiting an unknown keyword while authenticated redirects to `/#/edit/<keyword>` with the keyword pre-filled so you can save it immediately.
- **Stateless `HttpOnly` sessions:** Session cookies store an `HMAC-SHA256` token derived from the configured `key` (`SameSite=Lax`, 5-year `Max-Age`). Changing `key` automatically invalidates existing sessions.
- **Hot-reloading configuration:** Watches the configuration file's parent directory and reloads external edits automatically without restarting. Invalid YAML edits are logged and ignored while keeping the last valid configuration.
- **Flexible `%s` substitution:** Supports both `/` and space as the separator between the link key and parameter, with `application/x-www-form-urlencoded` encoding for the parameter.
- **Security headers on all responses:** `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, and `X-Content-Type-Options: nosniff`.

## Configuration

Create a YAML file (e.g., `config.yaml`):

```yaml
key: someSuperSecretValue
links:
  google: https://www.google.com/search?q=%s
  m: https://www.google.com/maps/preview?authuser=%s
  d: https://drive.google.com/drive/u/%s/my-drive
  docs: https://docs.example.com
```

### Environment Variables

| Variable | Default | Description |
| --- | --- | --- |
| `GOLINKS_FILE` | *(required locally; `/data/config.yaml` in Docker)* | Path to the YAML configuration file. |
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

On the first visit, you'll be redirected to `/?next=...` to enter your configured `key`, after which the `HttpOnly` cookie is stored and you're redirected straight to your requested link.

## Running with Docker

Mount `config.yaml` writable if you want to create/edit/delete links from the UI:

```bash
docker run -d \
  --name golinks \
  -p 8080:8080 \
  -v /path/to/data:/data \
  ghcr.io/<owner>/golinks:latest
```

To build locally:

```bash
docker build -t golinks .
docker run -d -p 8080:8080 -v /path/to/data:/data golinks
```

## Running Locally

Build the frontend bundle:

```bash
cd frontend
npm ci
npm run build
```

Run the Rust server (it automatically picks up `frontend/dist/index.html`):

```bash
GOLINKS_FILE=./config.yaml GOLINKS_SECURE_COOKIE=false cargo run
```

For frontend hot-reloading during development, run the Rust server on `:8080` and start Vite on `:3000` (`npm --prefix frontend run dev`), which proxies `/?action=...` API requests to `:8080`.

Run backend tests:

```bash
cargo test
```
