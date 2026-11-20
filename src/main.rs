mod auth;
mod config;
mod db;

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

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

use crate::config::{RuntimeConfig, SharedConfig};

const DEFAULT_FAVICON_BYTES: &[u8] = include_bytes!("../assets/favicon.ico");

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
    pub config: SharedConfig,
    pub config_path: PathBuf,
    pub secure_cookie: bool,
    pub favicon: FaviconData,
    pub ui_html: Arc<String>,
}

impl AppState {
    pub fn current_config(&self) -> Arc<RuntimeConfig> {
        self.config.read().expect("config lock poisoned").clone()
    }
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
    if key.chars().any(|c| c.is_whitespace() || c == '/' || c == '?' || c == '#') {
        return Err("Keyword must not contain spaces, '/', '?', or '#'.");
    }
    Ok(())
}

fn validate_link_target(target: &str) -> Result<(), &'static str> {
    if target.is_empty() {
        return Err("Target URL must not be empty.");
    }
    if !(target.starts_with("http://") || target.starts_with("https://")) {
        return Err("Target URL must start with http:// or https://.");
    }
    Ok(())
}

async fn handle_root_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ActionQuery>,
) -> Response {
    match query.action.as_deref() {
        None => (StatusCode::OK, Html(state.ui_html.as_str().to_string())).into_response(),
        Some("getLinks") => {
            let cfg = state.current_config();
            if !auth::is_authenticated(&headers, &cfg.auth_token) {
                return json_error(StatusCode::UNAUTHORIZED, "Unauthorized");
            }
            (StatusCode::OK, Json(json!({ "links": cfg.links }))).into_response()
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

            let cfg = state.current_config();
            if !auth::constant_time_eq(&req.secret, &cfg.key) {
                return json_error(StatusCode::UNAUTHORIZED, "Invalid secret.");
            }

            let cookie = auth::build_auth_cookie(&cfg.auth_token, state.secure_cookie);
            (
                StatusCode::OK,
                [(header::SET_COOKIE, cookie)],
                Json(json!({ "ok": true })),
            )
                .into_response()
        }
        "saveLink" => {
            let cfg = state.current_config();
            if !auth::is_authenticated(&headers, &cfg.auth_token) {
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

            let mut guard = state.config.write().expect("config lock poisoned");
            let mut updated = (**guard).clone();

            if let Some(orig) = req.original_key.as_deref().map(str::trim).filter(|s| !s.is_empty())
                && orig != key
            {
                updated.links.remove(orig);
            }
            updated.links.insert(key, target);

            if let Err(err) = config::save_config_to_path(&state.config_path, &updated) {
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, err);
            }

            let links = updated.links.clone();
            *guard = Arc::new(updated);
            (StatusCode::OK, Json(json!({ "links": links }))).into_response()
        }
        "deleteLink" => {
            let cfg = state.current_config();
            if !auth::is_authenticated(&headers, &cfg.auth_token) {
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

            let mut guard = state.config.write().expect("config lock poisoned");
            let mut updated = (**guard).clone();

            if updated.links.remove(key).is_none() {
                return json_error(StatusCode::NOT_FOUND, "Link not found.");
            }

            if let Err(err) = config::save_config_to_path(&state.config_path, &updated) {
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, err);
            }

            let links = updated.links.clone();
            *guard = Arc::new(updated);
            (StatusCode::OK, Json(json!({ "links": links }))).into_response()
        }
        _ => json_error(StatusCode::BAD_REQUEST, "Unknown action"),
    }
}

async fn handle_redirect(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let cfg = state.current_config();

    if !auth::is_authenticated(&headers, &cfg.auth_token) {
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

    let Some(template) = cfg.links.get(link_key.as_ref()) else {
        let encoded_key = utf8_percent_encode(link_key.as_ref(), NON_ALPHANUMERIC).to_string();
        return (
            StatusCode::FOUND,
            [(header::LOCATION, format!("/#/edit/{encoded_key}"))],
        )
            .into_response();
    };

    let target = if !template.contains("%s") {
        template.clone()
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
    let config_path = match std::env::var("GOLINKS_FILE") {
        Ok(path) if !path.trim().is_empty() => PathBuf::from(path),
        _ => {
            eprintln!("GOLINKS_FILE environment variable must be set");
            std::process::exit(1);
        }
    };

    let initial_config = match config::load_config_from_path(&config_path) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("Startup failed: {err}");
            std::process::exit(1);
        }
    };

    let shared_config: SharedConfig = Arc::new(RwLock::new(Arc::new(initial_config)));
    let _watcher = match config::spawn_config_watcher(&config_path, shared_config.clone()) {
        Ok(w) => w,
        Err(err) => {
            eprintln!("Failed to start config watcher: {err}");
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

    let state = AppState {
        config: shared_config,
        config_path: config_path.clone(),
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

    eprintln!("Listening on {addr} (watching {})", config_path.display());
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
    use axum::body::Body;
    use http_body_util::BodyExt;
    use std::collections::BTreeMap;
    use std::time::Duration;
    use tower::ServiceExt;

    fn test_state_with_path(config_path: PathBuf, secure_cookie: bool) -> AppState {
        let mut links = BTreeMap::new();
        links.insert(
            "google".to_string(),
            "https://www.google.com/search?q=%s".to_string(),
        );
        links.insert("docs".to_string(), "https://docs.example.com".to_string());
        links.insert(
            "m".to_string(),
            "https://www.google.com/maps/preview?authuser=%s".to_string(),
        );

        let key = "someSuperSecretValue".to_string();
        let auth_token = config::derive_auth_token(&key);

        AppState {
            config: Arc::new(RwLock::new(Arc::new(RuntimeConfig {
                key,
                auth_token,
                links,
            }))),
            config_path,
            secure_cookie,
            favicon: default_favicon(),
            ui_html: Arc::new("<!DOCTYPE html><html><body>UI</body></html>".to_string()),
        }
    }

    fn test_state(secure_cookie: bool) -> AppState {
        test_state_with_path(PathBuf::from("nonexistent.yaml"), secure_cookie)
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
        let app = build_router(test_state(true));

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
        let app = build_router(test_state(true));

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
        let state = test_state(false);
        let token = state.current_config().auth_token.clone();
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
    async fn api_get_save_rename_and_delete_links_persists_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.yaml");
        let state = test_state_with_path(cfg_path.clone(), false);
        let token = state.current_config().auth_token.clone();
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
        let reloaded = config::load_config_from_path(&cfg_path).unwrap();
        assert_eq!(
            reloaded.links.get("gh").map(String::as_str),
            Some("https://github.com/%s")
        );

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
        let reloaded = config::load_config_from_path(&cfg_path).unwrap();
        assert!(!reloaded.links.contains_key("gh"));
        assert_eq!(
            reloaded.links.get("github").map(String::as_str),
            Some("https://github.com/%s")
        );

        // deleteLink
        let del_resp = app
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
        assert_eq!(del_resp.status(), StatusCode::OK);
        let reloaded = config::load_config_from_path(&cfg_path).unwrap();
        assert!(!reloaded.links.contains_key("github"));
    }

    #[tokio::test]
    async fn hot_reload_updates_links_and_invalidates_old_key_while_surviving_bad_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("golinks.yaml");
        std::fs::write(
            &cfg_path,
            "key: firstSecret\nlinks:\n  docs: https://docs.example.com\n",
        )
        .unwrap();

        let initial = config::load_config_from_path(&cfg_path).unwrap();
        let old_token = initial.auth_token.clone();
        let shared: SharedConfig = Arc::new(RwLock::new(Arc::new(initial)));
        let _watcher = config::spawn_config_watcher(&cfg_path, shared.clone()).unwrap();

        let app = build_router(AppState {
            config: shared.clone(),
            config_path: cfg_path.clone(),
            secure_cookie: false,
            favicon: default_favicon(),
            ui_html: Arc::new(FALLBACK_UI_HTML.to_string()),
        });

        // Update YAML with new key and new link
        std::fs::write(
            &cfg_path,
            "key: secondSecret\nlinks:\n  notes: https://notes.example.com\n",
        )
        .unwrap();

        // Wait up to 2s for watcher debounce + reload
        let mut reloaded = false;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if shared.read().unwrap().key == "secondSecret" {
                reloaded = true;
                break;
            }
        }
        assert!(reloaded, "config did not hot-reload in time");

        // Old cookie should now be rejected (redirected to login)
        let old_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/notes")
                    .header(header::COOKIE, format!("golinks_auth={old_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(old_resp.status(), StatusCode::FOUND);
        assert_eq!(
            old_resp
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("/?next=%2Fnotes")
        );

        // New cookie should resolve the newly added link
        let new_token = config::derive_auth_token("secondSecret");
        let new_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/notes")
                    .header(header::COOKIE, format!("golinks_auth={new_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(new_resp.status(), StatusCode::FOUND);
        assert_eq!(
            new_resp
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("https://notes.example.com")
        );

        // Write invalid YAML and verify previous valid config remains active
        std::fs::write(&cfg_path, "key: [unclosed").unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;

        let still_works = app
            .oneshot(
                Request::builder()
                    .uri("/notes")
                    .header(header::COOKIE, format!("golinks_auth={new_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(still_works.status(), StatusCode::FOUND);
    }

    #[tokio::test]
    async fn favicon_endpoint_serves_default_and_override() {
        let app_default = build_router(test_state(false));
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

        let mut state_override = test_state(false);
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
