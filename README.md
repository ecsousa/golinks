# golinks

A lightweight, self-hosted "go links" HTTP redirect service written in Rust.

## Features

- **Cookie-based authentication:** Secrets are never placed in URLs, keeping them out of browser history, `Referer` headers, and reverse-proxy access logs.
- **Built-in login page:** Unauthenticated requests return `401 Unauthorized` with a minimal sign-in form and redirect back to the requested link after authentication.
- **Stateless `HttpOnly` sessions:** Session cookies store an `HMAC-SHA256` token derived from the configured `key` (`SameSite=Lax`, 5-year `Max-Age`). Changing `key` automatically invalidates existing sessions.
- **Hot-reloading configuration:** Watches the configuration file's parent directory and reloads changes automatically without restarting. Invalid YAML edits are logged and ignored while keeping the last valid configuration.
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
  site1: https://site1.example.com
  site2: https://site2.example.com
```

### Environment Variables

| Variable | Default | Description |
| --- | --- | --- |
| `GOLINKS_FILE` | *(required locally; `/data/config.yaml` in Docker)* | Path to the YAML configuration file. |
| `GOLINKS_ADDR` | `0.0.0.0:8080` | Address and port to bind the HTTP server. |
| `GOLINKS_SECURE_COOKIE` | `true` | Adds the `Secure` attribute to the session cookie. Set to `false` for local `http://localhost` testing. |

## Browser Setup (Chrome / Brave)

1. Open **Settings → Search engine → Manage search engines and site search**.
2. Add a new site search:
   - **Name:** `Golinks`
   - **Shortcut:** `go`
   - **URL:** `https://go.example.com/%s`
3. Type in the address bar:
   - `go site1` → `https://site1.example.com`
   - `go google/use curl/wget` → `https://www.google.com/search?q=use+curl%2Fwget`
   - `go google use curl/wget` → `https://www.google.com/search?q=use+curl%2Fwget`

On the first visit, you'll be prompted for your configured `key`, after which the `HttpOnly` cookie is stored and future redirects happen immediately.

## Running with Docker

```bash
docker run -d \
  --name golinks \
  -p 8080:8080 \
  -v /path/to/config.yaml:/data/config.yaml:ro \
  ghcr.io/ecsousa/golinks:latest
```

To build locally:

```bash
docker build -t golinks .
docker run -d -p 8080:8080 -v /path/to/config.yaml:/data/config.yaml:ro golinks
```

## Running Locally

```bash
GOLINKS_FILE=./config.yaml GOLINKS_SECURE_COOKIE=false cargo run
```

Run tests:

```bash
cargo test
```
