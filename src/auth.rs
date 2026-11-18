use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::AppState;

pub const AUTH_COOKIE_NAME: &str = "golinks_auth";
const COOKIE_MAX_AGE_SECS: u64 = 157_680_000; // 5 years

#[derive(Deserialize)]
pub struct AuthForm {
    pub secret: String,
    #[serde(default)]
    pub next: String,
}

/// Compares two strings in constant time to avoid timing side-channels.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Checks whether the incoming `Cookie` header contains a valid session token.
pub fn is_authenticated(headers: &HeaderMap, expected_token: &str) -> bool {
    for header_val in headers.get_all(header::COOKIE) {
        let Ok(cookie_str) = header_val.to_str() else {
            continue;
        };
        for pair in cookie_str.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if name.trim() == AUTH_COOKIE_NAME
                && constant_time_eq(value.trim(), expected_token)
            {
                return true;
            }
        }
    }
    false
}

/// Restricts redirect targets to safe relative paths on this origin.
pub fn sanitize_next(next: &str) -> &str {
    if next.starts_with('/')
        && !next.starts_with("//")
        && !next.contains('\\')
        && !next.contains('\r')
        && !next.contains('\n')
    {
        next
    } else {
        "/"
    }
}

fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Renders the `401 Unauthorized` HTML login page, preserving `next` for post-login redirect.
pub fn render_login_page(next: &str, error: Option<&str>) -> Response {
    let safe_next = escape_html(sanitize_next(next));
    let error_html = match error {
        Some(msg) => format!(r#"<p class="error" role="alert">{}</p>"#, escape_html(msg)),
        None => String::new(),
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Golinks — Sign In</title>
  <style>
    :root {{ color-scheme: light dark; }}
    body {{
      font-family: system-ui, -apple-system, sans-serif;
      display: grid;
      place-items: center;
      min-height: 100vh;
      margin: 0;
      padding: 1rem;
    }}
    main {{
      width: 100%;
      max-width: 340px;
      padding: 1.5rem;
      border: 1px solid color-mix(in srgb, currentColor 20%, transparent);
      border-radius: 8px;
    }}
    h1 {{ font-size: 1.15rem; margin: 0 0 1rem; }}
    .error {{ color: #d32f2f; font-size: 0.9rem; margin: 0 0 0.75rem; }}
    label {{ display: block; font-size: 0.9rem; margin-bottom: 0.4rem; }}
    input[type="password"] {{
      width: 100%;
      box-sizing: border-box;
      padding: 0.55rem 0.65rem;
      font-size: 1rem;
      border: 1px solid color-mix(in srgb, currentColor 30%, transparent);
      border-radius: 6px;
      margin-bottom: 0.9rem;
    }}
    button {{
      width: 100%;
      padding: 0.6rem;
      font-size: 1rem;
      border: none;
      border-radius: 6px;
      background: #2563eb;
      color: #fff;
      cursor: pointer;
    }}
    button:hover {{ background: #1d4ed8; }}
  </style>
</head>
<body>
  <main>
    <h1>Golinks Authentication</h1>
    {error_html}
    <form method="post" action="/_auth">
      <input type="hidden" name="next" value="{safe_next}">
      <label for="secret">Secret</label>
      <input id="secret" name="secret" type="password" autocomplete="current-password" autofocus required>
      <button type="submit">Continue</button>
    </form>
  </main>
</body>
</html>"#
    );

    (StatusCode::UNAUTHORIZED, Html(html)).into_response()
}

fn build_auth_cookie(token: &str, secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{AUTH_COOKIE_NAME}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={COOKIE_MAX_AGE_SECS}{secure_attr}"
    )
}

/// Handles `GET /_auth`: redirects to `/` if already authenticated, otherwise shows login form.
pub async fn handle_auth_get(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let cfg = state.current_config();
    if is_authenticated(&headers, &cfg.auth_token) {
        return Redirect::to("/").into_response();
    }
    render_login_page("/", None)
}

/// Handles `POST /_auth`: validates the submitted secret, sets the session cookie, and redirects.
pub async fn handle_auth_post(
    State(state): State<AppState>,
    Form(form): Form<AuthForm>,
) -> Response {
    let cfg = state.current_config();
    let safe_next = sanitize_next(&form.next);

    if !constant_time_eq(&form.secret, &cfg.key) {
        return render_login_page(safe_next, Some("Invalid secret."));
    }

    let cookie = build_auth_cookie(&cfg.auth_token, state.secure_cookie);
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, cookie),
            (header::LOCATION, safe_next.to_string()),
        ],
    )
        .into_response()
}
