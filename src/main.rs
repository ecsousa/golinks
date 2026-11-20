mod auth;
mod db;
mod oidc;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::get;
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use serde::Deserialize;
use serde_json::json;

use crate::db::config::{AppConfig, AuthConfig, DbConfig};
use crate::db::{Database, User};

const DEFAULT_FAVICON_BYTES: &[u8] = include_bytes!("../assets/favicon.ico");
const MAX_LINK_KEY_CHARS: usize = 32;
const MAX_LINK_TARGET_CHARS: usize = 512;

const FALLBACK_UI_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Golinks</title></head>
<body><p>Frontend bundle not found. Build <code>frontend/</code> and place <code>index.html</code> in <code>public/</code> or <code>frontend/dist/</code>.</p></body>
</html>"#;

#[derive(Clone)]
pub struct FaviconData {
    pub bytes: Bytes,
    pub content_type: &'static str,
}

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub active_user_id: i32,
    pub secure_cookie: bool,
    pub favicon: FaviconData,
    pub ui_html: Arc<String>,
}

#[derive(Deserialize)]
struct ActionQuery {
    action: Option<String>,
}

#[derive(Deserialize)]
struct LoginRequest {
    secret: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SaveLinkRequest {
    original_key: Option<String>,
    key: String,
    target: String,
}

#[derive(Deserialize)]
struct DeleteLinkRequest {
    key: String,
}

async fn add_security_headers(request: Request<axum::body::Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn json_error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "error": message.into() }))).into_response()
}

fn validate_link_key(key: &str) -> Result<(), &'static str> {
    if key.is_empty() {
        return Err("Keyword must not be empty.");
    }
    if key.chars().count() > MAX_LINK_KEY_CHARS {
        return Err("Keyword must be at most 32 characters.");
    }
    if key.chars().any(|c| c.is_whitespace() || c == '/' || c == '?' || c == '#') {
        return Err("Keyword must not contain spaces, '/', '?', or '#'.");
    }
    Ok(())
}

fn validate_link_target(target: &str) -> Result<(), &'static str> {
    if target.is_empty() {
        return Err("Target URL must not be empty.");
    }
    if target.chars().count() > MAX_LINK_TARGET_CHARS {
        return Err("Target URL must be at most 512 characters.");
    }
    if !(target.starts_with("http://") || target.starts_with("https://")) {
        return Err("Target URL must start with http:// or https://.");
    }
    Ok(())
}

async fn load_active_user(state: &AppState) -> Result<User, Response> {
    match state.db.get_user_by_id(state.active_user_id).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => {
            eprintln!(
                "Database error: active user id {} not found",
                state.active_user_id
            );
            Err(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error",
            ))
        }
        Err(err) => {
            eprintln!("Database error loading active user: {err}");
            Err(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error",
            ))
        }
    }
}

async fn handle_root_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ActionQuery>,
) -> Response {
    match query.action.as_deref() {
        None => (StatusCode::OK, Html(state.ui_html.as_str().to_string())).into_response(),
        Some("getLinks") => {
            let user = match load_active_user(&state).await {
                Ok(u) => u,
                Err(resp) => return resp,
            };
            if !auth::is_authenticated(&headers, &user.user_secret) {
                return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
            }
            match state.db.list_links(user.user_id).await {
                Ok(links) => (StatusCode::OK, Json(json!({ "links": links }))).into_response(),
                Err(err) => {
                    eprintln!("Database error listing links: {err}");
                    json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error")
                }
            }
        }
        Some(_) => json_error(StatusCode::BAD_REQUEST, "Unknown action"),
    }
}

async fn handle_root_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ActionQuery>,
    body: Bytes,
) -> Response {
    let action = match query.action.as_deref() {
        Some(a) => a,
        None => return json_error(StatusCode::BAD_REQUEST, "Missing action parameter"),
    };

    match action {
        "login" => {
            let req: LoginRequest = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(_) => return json_error(StatusCode::BAD_REQUEST, "Invalid JSON payload"),
            };

            let user = match load_active_user(&state).await {
                Ok(u) => u,
                Err(resp) => return resp,
            };
            let candidate = auth::derive_auth_token(&req.secret);
            if !auth::constant_time_eq(&candidate, &user.user_secret) {
                return json_error(StatusCode::UNAUTHORIZED, "Invalid secret.");
            }

            let cookie = auth::build_auth_cookie(&user.user_secret, state.secure_cookie);
            (
                StatusCode::OK,
                [(header::SET_COOKIE, cookie)],
                Json(json!({ "ok": true })),
            )
                .into_response()
        }
        "saveLink" => {
            let user = match load_active_user(&state).await {
                Ok(u) => u,
                Err(resp) => return resp,
            };
            if !auth::is_authenticated(&headers, &user.user_secret) {
                return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
            }

            let req: SaveLinkRequest = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(_) => return json_error(StatusCode::BAD_REQUEST, "Invalid JSON payload"),
            };

            let key = req.key.trim().to_string();
            let target = req.target.trim().to_string();
            if let Err(msg) = validate_link_key(&key) {
                return json_error(StatusCode::BAD_REQUEST, msg);
            }
            if let Err(msg) = validate_link_target(&target) {
                return json_error(StatusCode::BAD_REQUEST, msg);
            }

            match state
                .db
                .save_link(user.user_id, req.original_key.as_deref(), &key, &target)
                .await
            {
                Ok(links) => (StatusCode::OK, Json(json!({ "links": links }))).into_response(),
                Err(err) => {
                    eprintln!("Database error saving link: {err}");
                    json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error")
                }
            }
        }
        "deleteLink" => {
            let user = match load_active_user(&state).await {
                Ok(u) => u,
                Err(resp) => return resp,
            };
            if !auth::is_authenticated(&headers, &user.user_secret) {
                return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
            }

            let req: DeleteLinkRequest = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(_) => return json_error(StatusCode::BAD_REQUEST, "Invalid JSON payload"),
            };

            let key = req.key.trim();
            if key.is_empty() {
                return json_error(StatusCode::BAD_REQUEST, "Keyword must not be empty.");
            }

            match state.db.delete_link(user.user_id, key).await {
                Ok(Some(links)) => {
                    (StatusCode::OK, Json(json!({ "links": links }))).into_response()
                }
                Ok(None) => json_error(StatusCode::NOT_FOUND, "Link not found."),
                Err(err) => {
                    eprintln!("Database error deleting link: {err}");
                    json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error")
                }
            }
        }
        _ => json_error(StatusCode::BAD_REQUEST, "Unknown action"),
    }
}

async fn handle_redirect(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let user = match load_active_user(&state).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    if !auth::is_authenticated(&headers, &user.user_secret) {
        let next = uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let encoded_next: String = form_urlencoded::byte_serialize(next.as_bytes()).collect();
        return (
            StatusCode::FOUND,
            [(header::LOCATION, format!("/?next={encoded_next}"))],
        )
            .into_response();
    }

    let trimmed = uri.path().strip_prefix('/').unwrap_or(uri.path());
    if trimmed.is_empty() {
        return (StatusCode::FOUND, [(header::LOCATION, "/".to_string())]).into_response();
    }

    let (link_key_raw, rest_raw) = split_link_and_rest(trimmed);
    let link_key = percent_decode_str(link_key_raw).decode_utf8_lossy();

    let template = match state
        .db
        .get_link_target(user.user_id, link_key.as_ref())
        .await
    {
        Ok(Some(t)) => t,
        Ok(None) => {
            let encoded_key = utf8_percent_encode(link_key.as_ref(), NON_ALPHANUMERIC).to_string();
            return (
                StatusCode::FOUND,
                [(header::LOCATION, format!("/#/edit/{encoded_key}"))],
            )
                .into_response();
        }
        Err(err) => {
            eprintln!("Database error looking up link '{}': {err}", link_key);
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    let target = if !template.contains("%s") {
        template
    } else if rest_raw.is_empty() {
        template.replace("%s", "")
    } else {
        let decoded_rest = percent_decode_str(rest_raw).decode_utf8_lossy();
        let encoded_rest: String =
            form_urlencoded::byte_serialize(decoded_rest.as_bytes()).collect();
        template.replace("%s", &encoded_rest)
    };

    (StatusCode::FOUND, [(header::LOCATION, target)]).into_response()
}

/// Splits the request path on the first `/` or space separator (including `%20` / `%2F`).
fn split_link_and_rest(trimmed: &str) -> (&str, &str) {
    const SEPARATORS: [&str; 5] = ["/", "%20", " ", "%2F", "%2f"];

    let earliest = SEPARATORS
        .iter()
        .filter_map(|sep| trimmed.find(sep).map(|idx| (idx, sep.len())))
        .min_by_key(|&(idx, _)| idx);

    match earliest {
        Some((idx, len)) => (&trimmed[..idx], &trimmed[idx + len..]),
        None => (trimmed, ""),
    }
}

async fn handle_favicon(State(state): State<AppState>) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, state.favicon.content_type)],
        state.favicon.bytes.clone(),
    )
        .into_response()
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(handle_root_get).post(handle_root_post))
        .route("/favicon.ico", get(handle_favicon))
        .fallback(get(handle_redirect))
        .layer(middleware::from_fn(add_security_headers))
        .with_state(state)
}

fn parse_bool_env(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(val) => !matches!(
            val.trim().to_ascii_lowercase().as_str(),
            "false" | "0" | "no" | "off"
        ),
        Err(_) => default,
    }
}

fn favicon_content_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .as_deref()
    {
        Some("ico") => "image/x-icon",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        Some("gif") => "image/gif",
        _ => "image/x-icon",
    }
}

fn default_favicon() -> FaviconData {
    FaviconData {
        bytes: Bytes::from_static(DEFAULT_FAVICON_BYTES),
        content_type: "image/x-icon",
    }
}

fn load_favicon_from_env() -> Result<FaviconData, String> {
    let path = match std::env::var("FAVICON_FILE") {
        Ok(val) if !val.trim().is_empty() => PathBuf::from(val),
        _ => return Ok(default_favicon()),
    };

    let bytes = std::fs::read(&path)
        .map_err(|err| format!("failed to read FAVICON_FILE {}: {err}", path.display()))?;

    Ok(FaviconData {
        bytes: Bytes::from(bytes),
        content_type: favicon_content_type(&path),
    })
}

fn load_ui_html() -> Arc<String> {
    let candidates = [
        std::env::var("GOLINKS_UI_FILE").ok().map(PathBuf::from),
        Some(PathBuf::from("public/index.html")),
        Some(PathBuf::from("frontend/dist/index.html")),
    ];

    for path in candidates.into_iter().flatten() {
        if let Ok(html) = std::fs::read_to_string(&path) {
            eprintln!("Loaded UI bundle from {}", path.display());
            return Arc::new(html);
        }
    }

    eprintln!("Warning: UI bundle not found; serving fallback page on /");
    Arc::new(FALLBACK_UI_HTML.to_string())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[tokio::main]
async fn main() {
    let app_cfg = match AppConfig::from_env() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("Startup failed: {err}");
            std::process::exit(1);
        }
    };

    let db = match Database::connect(&app_cfg.db).await {
        Ok(db) => db,
        Err(err) => {
            eprintln!("Startup failed: {err}");
            std::process::exit(1);
        }
    };

    if let Err(err) = db.run_migrations().await {
        eprintln!("Startup failed: {err}");
        std::process::exit(1);
    }

    let (username, user) = match &app_cfg.auth {
        AuthConfig::SingleUser {
            username,
            user_secret_key,
        } => {
            let derived_secret = auth::derive_auth_token(user_secret_key);
            let user = match db.sync_user(username, &derived_secret).await {
                Ok(user) => user,
                Err(err) => {
                    eprintln!("Startup failed: {err}");
                    std::process::exit(1);
                }
            };
            (username.clone(), user)
        }
        AuthConfig::Oidc(_) => {
            eprintln!("Startup failed: OIDC mode not yet wired");
            std::process::exit(1);
        }
    };

    let addr = std::env::var("GOLINKS_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let secure_cookie = parse_bool_env("GOLINKS_SECURE_COOKIE", true);
    let favicon = match load_favicon_from_env() {
        Ok(fav) => fav,
        Err(err) => {
            eprintln!("Startup failed: {err}");
            std::process::exit(1);
        }
    };
    let ui_html = load_ui_html();

    let db_desc = match &app_cfg.db {
        DbConfig::Sqlite { path } => format!("sqlite:{path}"),
        DbConfig::Postgresql {
            host,
            port,
            database,
            ..
        } => format!("postgresql://{host}:{port}/{database}"),
    };

    let state = AppState {
        db,
        active_user_id: user.user_id,
        secure_cookie,
        favicon,
        ui_html,
    };

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(err) => {
            eprintln!("Failed to bind to {addr}: {err}");
            std::process::exit(1);
        }
    };

    eprintln!(
        "Listening on {addr} (db={db_desc}, user={username})"
    );
    if let Err(err) = axum::serve(listener, build_router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        eprintln!("Server error: {err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::config::DbConfig;
    use crate::db::Database;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn test_state(secure_cookie: bool) -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("golinks.db");
        let db = Database::connect(&DbConfig::Sqlite {
            path: db_path.to_string_lossy().into_owned(),
        })
        .await
        .unwrap();
        db.run_migrations().await.unwrap();

        let derived = auth::derive_auth_token("someSuperSecretValue");
        let user = db.sync_user("golinks", &derived).await.unwrap();

        db.save_link(
            user.user_id,
            None,
            "google",
            "https://www.google.com/search?q=%s",
        )
        .await
        .unwrap();
        db.save_link(user.user_id, None, "docs", "https://docs.example.com")
            .await
            .unwrap();
        db.save_link(
            user.user_id,
            None,
            "m",
            "https://www.google.com/maps/preview?authuser=%s",
        )
        .await
        .unwrap();

        let state = AppState {
            db,
            active_user_id: user.user_id,
            secure_cookie,
            favicon: default_favicon(),
            ui_html: Arc::new("<!DOCTYPE html><html><body>UI</body></html>".to_string()),
        };
        (state, dir)
    }

    fn assert_security_headers(headers: &HeaderMap) {
        assert_eq!(
            headers
                .get(header::REFERRER_POLICY)
                .and_then(|v| v.to_str().ok()),
            Some("no-referrer")
        );
        assert_eq!(
            headers
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            headers
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );
    }

    async fn body_text(response: Response) -> String {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn unauthenticated_root_serves_ui_and_links_redirect_to_next() {
        let (state, _dir) = test_state(true).await;
        let app = build_router(state);

        let root_resp = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(root_resp.status(), StatusCode::OK);
        assert_security_headers(root_resp.headers());
        assert!(body_text(root_resp).await.contains("<body>UI</body>"));

        let link_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/google/use%20curl/wget")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(link_resp.status(), StatusCode::FOUND);
        assert_security_headers(link_resp.headers());
        assert_eq!(
            link_resp
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("/?next=%2Fgoogle%2Fuse%2520curl%2Fwget")
        );

        let api_resp = app
            .oneshot(
                Request::builder()
                    .uri("/?action=getLinks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(api_resp.status(), StatusCode::UNAUTHORIZED);
        assert_security_headers(api_resp.headers());
    }

    #[tokio::test]
    async fn login_api_validates_secret_and_sets_cookie() {
        let (state, _dir) = test_state(true).await;
        let app = build_router(state);

        let bad = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/?action=login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"secret":"wrong"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);
        assert_security_headers(bad.headers());

        let good = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/?action=login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"secret":"someSuperSecretValue"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(good.status(), StatusCode::OK);
        assert_security_headers(good.headers());
        let cookie = good
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap();
        assert!(cookie.contains("golinks_auth="));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("Max-Age=157680000"));
        assert!(cookie.contains("Secure"));
    }

    #[tokio::test]
    async fn authenticated_redirects_url_encoding_and_unknown_redirect_to_edit() {
        let (state, _dir) = test_state(false).await;
        let token = auth::derive_auth_token("someSuperSecretValue");
        let cookie_hdr = format!("golinks_auth={token}");
        let app = build_router(state);

        let cases = [
            (
                "/google/use%20curl/wget",
                Some("https://www.google.com/search?q=use+curl%2Fwget"),
                StatusCode::FOUND,
            ),
            (
                "/google%20use%20curl/wget",
                Some("https://www.google.com/search?q=use+curl%2Fwget"),
                StatusCode::FOUND,
            ),
            (
                "/google%20",
                Some("https://www.google.com/search?q="),
                StatusCode::FOUND,
            ),
            (
                "/docs%20extra",
                Some("https://docs.example.com"),
                StatusCode::FOUND,
            ),
            (
                "/google",
                Some("https://www.google.com/search?q="),
                StatusCode::FOUND,
            ),
            (
                "/google/",
                Some("https://www.google.com/search?q="),
                StatusCode::FOUND,
            ),
            (
                "/docs",
                Some("https://docs.example.com"),
                StatusCode::FOUND,
            ),
            (
                "/docs/",
                Some("https://docs.example.com"),
                StatusCode::FOUND,
            ),
            (
                "/docs/extra/segments",
                Some("https://docs.example.com"),
                StatusCode::FOUND,
            ),
            (
                "/m/1",
                Some("https://www.google.com/maps/preview?authuser=1"),
                StatusCode::FOUND,
            ),
            ("/", None, StatusCode::OK),
            ("/newLink", Some("/#/edit/newLink"), StatusCode::FOUND),
        ];

        for (path, expected_loc, expected_status) in cases {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header(header::COOKIE, &cookie_hdr)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), expected_status, "path={path}");
            assert_security_headers(resp.headers());
            let loc = resp
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok());
            assert_eq!(loc, expected_loc, "path={path}");
        }
    }

    #[tokio::test]
    async fn api_get_save_rename_and_delete_links_persists_db() {
        let (state, dir) = test_state(false).await;
        let user_id = state.active_user_id;
        let db_path = dir.path().join("golinks.db");
        let token = auth::derive_auth_token("someSuperSecretValue");
        let cookie_hdr = format!("golinks_auth={token}");
        let app = build_router(state);

        // getLinks
        let get_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/?action=getLinks")
                    .header(header::COOKIE, &cookie_hdr)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_resp.status(), StatusCode::OK);
        let get_body: serde_json::Value =
            serde_json::from_str(&body_text(get_resp).await).unwrap();
        assert_eq!(get_body["links"]["docs"], "https://docs.example.com");

        // saveLink (create)
        let create_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/?action=saveLink")
                    .header(header::COOKIE, &cookie_hdr)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"key":"gh","target":"https://github.com/%s"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_resp.status(), StatusCode::OK);

        // saveLink (rename gh -> github)
        let rename_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/?action=saveLink")
                    .header(header::COOKIE, &cookie_hdr)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"originalKey":"gh","key":"github","target":"https://github.com/%s"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rename_resp.status(), StatusCode::OK);

        // saveLink (rename github onto existing key docs)
        let overwrite_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/?action=saveLink")
                    .header(header::COOKIE, &cookie_hdr)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"originalKey":"github","key":"docs","target":"https://new-docs.example.com"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(overwrite_resp.status(), StatusCode::OK);

        // deleteLink (missing returns 404)
        let missing_del_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/?action=deleteLink")
                    .header(header::COOKIE, &cookie_hdr)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"key":"github"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_del_resp.status(), StatusCode::NOT_FOUND);

        // deleteLink (existing m)
        let del_resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/?action=deleteLink")
                    .header(header::COOKIE, &cookie_hdr)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"key":"m"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(del_resp.status(), StatusCode::OK);

        // Reopen a fresh Database connection to verify persistence on disk.
        let reopened = Database::connect(&DbConfig::Sqlite {
            path: db_path.to_string_lossy().into_owned(),
        })
        .await
        .unwrap();
        let links = reopened.list_links(user_id).await.unwrap();
        assert!(!links.contains_key("gh"));
        assert!(!links.contains_key("github"));
        assert!(!links.contains_key("m"));
        assert_eq!(
            links.get("docs").map(String::as_str),
            Some("https://new-docs.example.com")
        );
        assert_eq!(
            links.get("google").map(String::as_str),
            Some("https://www.google.com/search?q=%s")
        );
    }

    #[tokio::test]
    async fn validation_enforces_32_and_512_unicode_char_limits() {
        let (state, _dir) = test_state(false).await;
        let token = auth::derive_auth_token("someSuperSecretValue");
        let cookie_hdr = format!("golinks_auth={token}");
        let app = build_router(state);

        let key_32 = "é".repeat(32);
        let target_512 = format!("https://example.com/{}", "é".repeat(512 - 20));
        assert_eq!(key_32.chars().count(), 32);
        assert_eq!(target_512.chars().count(), 512);

        let ok_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/?action=saveLink")
                    .header(header::COOKIE, &cookie_hdr)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_string(&json!({
                            "key": key_32,
                            "target": target_512,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok_resp.status(), StatusCode::OK);

        let key_33 = "é".repeat(33);
        let bad_key_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/?action=saveLink")
                    .header(header::COOKIE, &cookie_hdr)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_string(&json!({
                            "key": key_33,
                            "target": "https://example.com",
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_key_resp.status(), StatusCode::BAD_REQUEST);

        let target_513 = format!("https://example.com/{}", "é".repeat(513 - 20));
        assert_eq!(target_513.chars().count(), 513);
        let bad_target_resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/?action=saveLink")
                    .header(header::COOKIE, &cookie_hdr)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_string(&json!({
                            "key": "valid",
                            "target": target_513,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_target_resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn redirect_returns_500_with_security_headers_on_db_error() {
        let (state, _dir) = test_state(false).await;
        let token = auth::derive_auth_token("someSuperSecretValue");
        let cookie_hdr = format!("golinks_auth={token}");

        sqlx::query("DROP TABLE links")
            .execute(state.db.sqlite_pool())
            .await
            .unwrap();

        let app = build_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/google")
                    .header(header::COOKIE, &cookie_hdr)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_security_headers(resp.headers());
        assert!(resp.headers().get(header::LOCATION).is_none());
    }

    #[tokio::test]
    async fn secret_rotation_via_sync_user_invalidates_old_cookie() {
        let (state, _dir) = test_state(false).await;
        let old_token = auth::derive_auth_token("someSuperSecretValue");
        let new_token = auth::derive_auth_token("secondSecret");

        state.db.sync_user("golinks", &new_token).await.unwrap();

        let app = build_router(state);

        let old_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/docs")
                    .header(header::COOKIE, format!("golinks_auth={old_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(old_resp.status(), StatusCode::FOUND);
        assert_security_headers(old_resp.headers());
        assert_eq!(
            old_resp
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("/?next=%2Fdocs")
        );

        let new_resp = app
            .oneshot(
                Request::builder()
                    .uri("/docs")
                    .header(header::COOKIE, format!("golinks_auth={new_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(new_resp.status(), StatusCode::FOUND);
        assert_security_headers(new_resp.headers());
        assert_eq!(
            new_resp
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("https://docs.example.com")
        );
    }

    #[tokio::test]
    async fn favicon_endpoint_serves_default_and_override() {
        let (state_default, _dir1) = test_state(false).await;
        let app_default = build_router(state_default);
        let default_resp = app_default
            .oneshot(
                Request::builder()
                    .uri("/favicon.ico")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(default_resp.status(), StatusCode::OK);
        assert_security_headers(default_resp.headers());
        assert_eq!(
            default_resp
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("image/x-icon")
        );
        let default_body = default_resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(default_body.as_ref(), DEFAULT_FAVICON_BYTES);

        let (mut state_override, _dir2) = test_state(false).await;
        let payload = vec![0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
        state_override.favicon = FaviconData {
            bytes: Bytes::from(payload.clone()),
            content_type: favicon_content_type(Path::new("icon.png")),
        };
        let app_override = build_router(state_override);

        let override_resp = app_override
            .oneshot(
                Request::builder()
                    .uri("/favicon.ico")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(override_resp.status(), StatusCode::OK);
        assert_security_headers(override_resp.headers());
        assert_eq!(
            override_resp
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("image/png")
        );
        let override_body = override_resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(override_body.as_ref(), payload.as_slice());
    }
}
