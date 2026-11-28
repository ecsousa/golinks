mod auth;
mod db;
mod oidc;

use std::collections::BTreeSet;
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
use crate::oidc::{OidcError, OidcService, build_clear_state_cookie, sanitize_next_path};

const DEFAULT_FAVICON_BYTES: &[u8] = include_bytes!("../assets/favicon.ico");
const MAX_LINK_KEY_CHARS: usize = 32;
const MAX_LINK_TARGET_CHARS: usize = 512;
const MAX_TAG_CHARS: usize = 32;

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
pub enum AuthMode {
    SingleUser { active_user_id: i32 },
    Oidc(Arc<OidcService>),
}

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub auth_mode: AuthMode,
    pub session_ttl_secs: u64,
    pub secure_cookie: bool,
    pub favicon: FaviconData,
    pub ui_html: Arc<String>,
}

impl AppState {
    fn is_oidc(&self) -> bool {
        matches!(self.auth_mode, AuthMode::Oidc(_))
    }
}

#[derive(Deserialize)]
struct RootQuery {
    action: Option<String>,
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
    next: Option<String>,
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
    #[serde(default)]
    tags: Vec<String>,
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

fn unauthorized_json(state: &AppState) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": "Unauthorized",
            "oidcEnabled": state.is_oidc(),
        })),
    )
        .into_response()
}

fn with_set_cookie(mut response: Response, cookie_val: HeaderValue) -> Response {
    response.headers_mut().append(header::SET_COOKIE, cookie_val);
    response
}

fn issue_session_cookie(state: &AppState, user: &User) -> HeaderValue {
    let now = auth::current_unix_secs();
    let jwt = auth::sign_session_jwt(&user.user_name, &user.user_secret, now, state.session_ttl_secs);
    let cookie = auth::build_auth_cookie(&jwt, state.session_ttl_secs, state.secure_cookie);
    HeaderValue::from_str(&cookie).expect("valid Set-Cookie header")
}

async fn load_single_user(state: &AppState, active_user_id: i32) -> Result<User, Response> {
    match state.db.get_user_by_id(active_user_id).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => {
            eprintln!("Database error: active user id {active_user_id} not found");
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

/// Authenticates the incoming request using the `golinks_auth` HS256 JWT cookie.
/// Returns `Ok(Some((user, refreshed_set_cookie)))` on success, `Ok(None)` if unauthenticated,
/// or `Err(Response)` on database error.
async fn authenticate_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<(User, HeaderValue)>, Response> {
    let now = auth::current_unix_secs();
    for token in auth::extract_cookie_values(headers, auth::AUTH_COOKIE_NAME) {
        let Some((claims, signing_input, sig_bytes)) = auth::parse_unverified_jwt(token) else {
            continue;
        };
        if claims.exp <= now {
            continue;
        }
        let user = match state.db.get_user_by_name(&claims.sub).await {
            Ok(Some(u)) => u,
            Ok(None) => continue,
            Err(err) => {
                eprintln!("Database error looking up session user: {err}");
                return Err(json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Database error",
                ));
            }
        };
        if let AuthMode::SingleUser { active_user_id } = state.auth_mode {
            if user.user_id != active_user_id {
                continue;
            }
        }
        if auth::verify_jwt_signature(&signing_input, &sig_bytes, &user.user_secret) {
            let refreshed = issue_session_cookie(state, &user);
            return Ok(Some((user, refreshed)));
        }
    }
    Ok(None)
}

async fn redirect_to_oidc_login(
    state: &AppState,
    oidc: &OidcService,
    next_path: &str,
) -> Response {
    match oidc.start_login(next_path, state.secure_cookie).await {
        Ok((authorize_url, set_state_cookie)) => (
            StatusCode::FOUND,
            [
                (header::LOCATION, authorize_url),
                (header::SET_COOKIE, set_state_cookie),
            ],
        )
            .into_response(),
        Err(err) => {
            eprintln!("OIDC login redirect error: {err}");
            (
                StatusCode::BAD_GATEWAY,
                "Authentication provider is temporarily unavailable. Please try again.",
            )
                .into_response()
        }
    }
}

async fn handle_oidc_callback(
    state: &AppState,
    oidc: &OidcService,
    headers: &HeaderMap,
    query: &RootQuery,
) -> Response {
    let clear_state = build_clear_state_cookie(state.secure_cookie);

    if let Some(err_code) = query.error.as_deref() {
        let desc = query.error_description.as_deref().unwrap_or("");
        eprintln!("OIDC provider returned error: {err_code} {desc}");
        return (
            StatusCode::UNAUTHORIZED,
            [(header::SET_COOKIE, clear_state)],
            format!("OIDC authentication failed: {err_code}"),
        )
            .into_response();
    }

    let (Some(code), Some(state_param)) = (query.code.as_deref(), query.state.as_deref()) else {
        return (
            StatusCode::BAD_REQUEST,
            [(header::SET_COOKIE, clear_state)],
            "Missing OIDC code or state parameter.",
        )
            .into_response();
    };

    let (username, next_path) = match oidc.complete_callback(headers, code, state_param).await {
        Ok(res) => res,
        Err(err) => {
            eprintln!("OIDC callback failed: {err}");
            let status = match err {
                OidcError::InvalidState(_) => StatusCode::BAD_REQUEST,
                OidcError::MissingUsernameClaim(_) | OidcError::InvalidUsername(_) => {
                    StatusCode::FORBIDDEN
                }
                OidcError::ProviderUnavailable(_) => StatusCode::BAD_GATEWAY,
                OidcError::TokenExchange(_) | OidcError::InvalidIdToken(_) => {
                    StatusCode::UNAUTHORIZED
                }
            };
            return (
                status,
                [(header::SET_COOKIE, clear_state)],
                "OIDC authentication failed.",
            )
                .into_response();
        }
    };

    let random_secret = auth::generate_random_user_secret();
    let user = match state.db.get_or_create_user(&username, &random_secret).await {
        Ok(u) => u,
        Err(err) => {
            eprintln!("Database error provisioning OIDC user: {err}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::SET_COOKIE, clear_state)],
                "Database error",
            )
                .into_response();
        }
    };

    let auth_cookie = issue_session_cookie(state, &user);
    let mut response = (
        StatusCode::FOUND,
        [(header::LOCATION, next_path)],
    )
        .into_response();
    response
        .headers_mut()
        .append(header::SET_COOKIE, auth_cookie);
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_state).expect("valid clear state cookie"),
    );
    response
}

fn validate_link_key(key: &str) -> Result<(), &'static str> {
    if key.is_empty() {
        return Err("Keyword must not be empty.");
    }
    if key.chars().count() > MAX_LINK_KEY_CHARS {
        return Err("Keyword must be at most 32 characters.");
    }
    if key.starts_with('/') {
        return Err("Keyword must not start with '/'.");
    }
    if key.chars().any(|c| c.is_whitespace() || c == '?' || c == '#') {
        return Err("Keyword must not contain spaces, '?', or '#'.");
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

fn normalize_and_validate_tags(raw_tags: &[String]) -> Result<Vec<String>, &'static str> {
    let mut normalized = BTreeSet::new();
    for raw in raw_tags {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.chars().any(char::is_whitespace) {
            return Err("Tags must not contain whitespace.");
        }
        let lower = trimmed.to_lowercase();
        if lower.chars().count() > MAX_TAG_CHARS {
            return Err("Each tag must be at most 32 characters.");
        }
        normalized.insert(lower);
    }
    Ok(normalized.into_iter().collect())
}

async fn handle_root_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<RootQuery>,
) -> Response {
    match query.action.as_deref() {
        None => {
            if let AuthMode::Oidc(oidc) = &state.auth_mode {
                if query.code.is_some() || query.error.is_some() {
                    return handle_oidc_callback(&state, oidc, &headers, &query).await;
                }
                match authenticate_session(&state, &headers).await {
                    Ok(Some((_user, refreshed_cookie))) => {
                        let resp =
                            (StatusCode::OK, Html(state.ui_html.as_str().to_string())).into_response();
                        with_set_cookie(resp, refreshed_cookie)
                    }
                    Ok(None) => {
                        let next = sanitize_next_path(query.next.as_deref());
                        redirect_to_oidc_login(&state, oidc, &next).await
                    }
                    Err(resp) => resp,
                }
            } else {
                let resp =
                    (StatusCode::OK, Html(state.ui_html.as_str().to_string())).into_response();
                match authenticate_session(&state, &headers).await {
                    Ok(Some((_user, refreshed_cookie))) => with_set_cookie(resp, refreshed_cookie),
                    _ => resp,
                }
            }
        }
        Some("getLinks") => {
            let (user, refreshed_cookie) = match authenticate_session(&state, &headers).await {
                Ok(Some(auth_res)) => auth_res,
                Ok(None) => return unauthorized_json(&state),
                Err(resp) => return resp,
            };
            match state.db.list_links(user.user_id).await {
                Ok(payload) => {
                    let resp = (StatusCode::OK, Json(payload)).into_response();
                    with_set_cookie(resp, refreshed_cookie)
                }
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
            let active_user_id = match state.auth_mode {
                AuthMode::SingleUser { active_user_id } => active_user_id,
                AuthMode::Oidc(_) => {
                    return json_error(
                        StatusCode::FORBIDDEN,
                        "Password login is disabled when OIDC is enabled.",
                    );
                }
            };

            let req: LoginRequest = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(_) => return json_error(StatusCode::BAD_REQUEST, "Invalid JSON payload"),
            };

            let user = match load_single_user(&state, active_user_id).await {
                Ok(u) => u,
                Err(resp) => return resp,
            };
            let candidate = auth::derive_auth_token(&req.secret);
            if !auth::constant_time_eq(&candidate, &user.user_secret) {
                return json_error(StatusCode::UNAUTHORIZED, "Invalid secret.");
            }

            let cookie = issue_session_cookie(&state, &user);
            let resp = (StatusCode::OK, Json(json!({ "ok": true }))).into_response();
            with_set_cookie(resp, cookie)
        }
        "saveLink" => {
            let (user, refreshed_cookie) = match authenticate_session(&state, &headers).await {
                Ok(Some(auth_res)) => auth_res,
                Ok(None) => return unauthorized_json(&state),
                Err(resp) => return resp,
            };

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

            let tags = match normalize_and_validate_tags(&req.tags) {
                Ok(t) => t,
                Err(msg) => return json_error(StatusCode::BAD_REQUEST, msg),
            };

            match state
                .db
                .save_link(
                    user.user_id,
                    req.original_key.as_deref(),
                    &key,
                    &target,
                    &tags,
                )
                .await
            {
                Ok(payload) => {
                    let resp = (StatusCode::OK, Json(payload)).into_response();
                    with_set_cookie(resp, refreshed_cookie)
                }
                Err(err) => {
                    eprintln!("Database error saving link: {err}");
                    json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error")
                }
            }
        }
        "deleteLink" => {
            let (user, refreshed_cookie) = match authenticate_session(&state, &headers).await {
                Ok(Some(auth_res)) => auth_res,
                Ok(None) => return unauthorized_json(&state),
                Err(resp) => return resp,
            };

            let req: DeleteLinkRequest = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(_) => return json_error(StatusCode::BAD_REQUEST, "Invalid JSON payload"),
            };

            let key = req.key.trim();
            if key.is_empty() {
                return json_error(StatusCode::BAD_REQUEST, "Keyword must not be empty.");
            }

            match state.db.delete_link(user.user_id, key).await {
                Ok(Some(payload)) => {
                    let resp = (StatusCode::OK, Json(payload)).into_response();
                    with_set_cookie(resp, refreshed_cookie)
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
    let (user, refreshed_cookie) = match authenticate_session(&state, &headers).await {
        Ok(Some(auth_res)) => auth_res,
        Ok(None) => {
            let next = uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/");
            if let AuthMode::Oidc(oidc) = &state.auth_mode {
                let sanitized = sanitize_next_path(Some(next));
                return redirect_to_oidc_login(&state, oidc, &sanitized).await;
            }
            let encoded_next: String = form_urlencoded::byte_serialize(next.as_bytes()).collect();
            return (
                StatusCode::FOUND,
                [(header::LOCATION, format!("/?next={encoded_next}"))],
            )
                .into_response();
        }
        Err(resp) => return resp,
    };

    let trimmed = uri.path().strip_prefix('/').unwrap_or(uri.path());
    if trimmed.is_empty() {
        let resp = (StatusCode::FOUND, [(header::LOCATION, "/".to_string())]).into_response();
        return with_set_cookie(resp, refreshed_cookie);
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
            let resp = (
                StatusCode::FOUND,
                [(header::LOCATION, format!("/#/edit/{encoded_key}"))],
            )
                .into_response();
            return with_set_cookie(resp, refreshed_cookie);
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

    let resp = (StatusCode::FOUND, [(header::LOCATION, target)]).into_response();
    with_set_cookie(resp, refreshed_cookie)
}

/// Splits the request path on the first space separator (`%20` or literal space).
fn split_link_and_rest(trimmed: &str) -> (&str, &str) {
    const SEPARATORS: [&str; 2] = ["%20", " "];

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

    let (auth_mode, auth_desc) = match app_cfg.auth {
        AuthConfig::SingleUser {
            username,
            user_secret_key,
        } => {
            let derived_secret = auth::derive_auth_token(&user_secret_key);
            let user = match db.sync_user(&username, &derived_secret).await {
                Ok(user) => user,
                Err(err) => {
                    eprintln!("Startup failed: {err}");
                    std::process::exit(1);
                }
            };
            (
                AuthMode::SingleUser {
                    active_user_id: user.user_id,
                },
                format!("user={username}"),
            )
        }
        AuthConfig::Oidc(oidc_cfg) => {
            let issuer = oidc_cfg.issuer_url.clone();
            let service = match OidcService::new(oidc_cfg) {
                Ok(s) => Arc::new(s),
                Err(err) => {
                    eprintln!("Startup failed: {err}");
                    std::process::exit(1);
                }
            };
            service.warm_discovery().await;
            (AuthMode::Oidc(service), format!("oidc={issuer}"))
        }
    };

    let session_ttl_secs = app_cfg.session_ttl_days.saturating_mul(86_400);
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
        auth_mode,
        session_ttl_secs,
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
        "Listening on {addr} (db={db_desc}, {auth_desc}, session_ttl_days={})",
        app_cfg.session_ttl_days
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

    const TEST_SESSION_TTL_SECS: u64 = 30 * 86_400;

    fn make_jwt_cookie(username: &str, raw_secret: &str) -> String {
        let derived = auth::derive_auth_token(raw_secret);
        let jwt = auth::sign_session_jwt(
            username,
            &derived,
            auth::current_unix_secs(),
            TEST_SESSION_TTL_SECS,
        );
        format!("golinks_auth={jwt}")
    }

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
            &[],
        )
        .await
        .unwrap();
        db.save_link(user.user_id, None, "docs", "https://docs.example.com", &[])
            .await
            .unwrap();
        db.save_link(
            user.user_id,
            None,
            "m",
            "https://www.google.com/maps/preview?authuser=%s",
            &[],
        )
        .await
        .unwrap();
        db.save_link(
            user.user_id,
            None,
            "key1/subitem",
            "https://example.com/search?q=%s",
            &[],
        )
        .await
        .unwrap();

        let state = AppState {
            db,
            auth_mode: AuthMode::SingleUser {
                active_user_id: user.user_id,
            },
            session_ttl_secs: TEST_SESSION_TTL_SECS,
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
        assert!(cookie.contains("Max-Age=2592000"));
        assert!(cookie.contains("Secure"));
        let jwt = cookie
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("golinks_auth=")
            .unwrap();
        let (claims, _, _) = auth::parse_unverified_jwt(jwt).expect("login sets valid JWT");
        assert_eq!(claims.sub, "golinks");
    }

    #[tokio::test]
    async fn authenticated_redirects_url_encoding_and_unknown_redirect_to_edit() {
        let (state, _dir) = test_state(false).await;
        let cookie_hdr = make_jwt_cookie("golinks", "someSuperSecretValue");
        let app = build_router(state);

        let cases = [
            (
                "/google%20use%20curl/wget",
                Some("https://www.google.com/search?q=use+curl%2Fwget"),
                StatusCode::FOUND,
            ),
            (
                "/google/use%20curl/wget",
                Some("/#/edit/google%2Fuse"),
                StatusCode::FOUND,
            ),
            (
                "/key1/subitem%20something%20else",
                Some("https://example.com/search?q=something+else"),
                StatusCode::FOUND,
            ),
            (
                "/key1%2Fsubitem%20something%20else",
                Some("https://example.com/search?q=something+else"),
                StatusCode::FOUND,
            ),
            (
                "/key1/subitem",
                Some("https://example.com/search?q="),
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
                Some("/#/edit/google%2F"),
                StatusCode::FOUND,
            ),
            (
                "/docs",
                Some("https://docs.example.com"),
                StatusCode::FOUND,
            ),
            (
                "/docs/",
                Some("/#/edit/docs%2F"),
                StatusCode::FOUND,
            ),
            (
                "/docs/extra/segments",
                Some("/#/edit/docs%2Fextra%2Fsegments"),
                StatusCode::FOUND,
            ),
            (
                "/m%201",
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
        let user_id = match &state.auth_mode {
            AuthMode::SingleUser { active_user_id } => *active_user_id,
            AuthMode::Oidc(_) => unreachable!(),
        };
        let db_path = dir.path().join("golinks.db");
        let cookie_hdr = make_jwt_cookie("golinks", "someSuperSecretValue");
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
        assert_eq!(
            get_body["links"]["docs"]["target"],
            "https://docs.example.com"
        );
        assert_eq!(get_body["links"]["docs"]["tags"], json!([]));
        assert_eq!(get_body["tags"], json!([]));

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
        let payload = reopened.list_links(user_id).await.unwrap();
        assert!(!payload.links.contains_key("gh"));
        assert!(!payload.links.contains_key("github"));
        assert!(!payload.links.contains_key("m"));
        assert_eq!(
            payload.links.get("docs").map(|e| e.target.as_str()),
            Some("https://new-docs.example.com")
        );
        assert_eq!(
            payload.links.get("google").map(|e| e.target.as_str()),
            Some("https://www.google.com/search?q=%s")
        );
    }

    #[tokio::test]
    async fn validation_enforces_32_and_512_unicode_char_limits() {
        let (state, _dir) = test_state(false).await;
        let cookie_hdr = make_jwt_cookie("golinks", "someSuperSecretValue");
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
    async fn validation_allows_slash_in_keyword_and_rejects_leading_slash_or_space() {
        let (state, _dir) = test_state(false).await;
        let cookie_hdr = make_jwt_cookie("golinks", "someSuperSecretValue");
        let app = build_router(state);

        let slash_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/?action=saveLink")
                    .header(header::COOKIE, &cookie_hdr)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"key":"team/docs","target":"https://docs.example.com/%s"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(slash_resp.status(), StatusCode::OK);

        for invalid_key in ["/leading", "has space", "has?query", "has#frag"] {
            let bad_resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/?action=saveLink")
                        .header(header::COOKIE, &cookie_hdr)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            serde_json::to_string(&json!({
                                "key": invalid_key,
                                "target": "https://example.com",
                            }))
                            .unwrap(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                bad_resp.status(),
                StatusCode::BAD_REQUEST,
                "invalid_key={invalid_key}"
            );
        }
    }

    #[test]
    fn split_link_and_rest_splits_on_spaces_only() {
        assert_eq!(
            split_link_and_rest("key1/subitem something else"),
            ("key1/subitem", "something else")
        );
        assert_eq!(
            split_link_and_rest("key1/subitem%20something%20else"),
            ("key1/subitem", "something%20else")
        );
        assert_eq!(
            split_link_and_rest("key1/subitem"),
            ("key1/subitem", "")
        );
        assert_eq!(
            split_link_and_rest("key1%2Fsubitem%20a/b"),
            ("key1%2Fsubitem", "a/b")
        );
    }

    #[tokio::test]
    async fn redirect_returns_500_with_security_headers_on_db_error() {
        let (state, _dir) = test_state(false).await;
        let cookie_hdr = make_jwt_cookie("golinks", "someSuperSecretValue");

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
        let old_cookie = make_jwt_cookie("golinks", "someSuperSecretValue");
        let new_token = auth::derive_auth_token("secondSecret");

        state.db.sync_user("golinks", &new_token).await.unwrap();
        let new_cookie = make_jwt_cookie("golinks", "secondSecret");

        let app = build_router(state);

        let old_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/docs")
                    .header(header::COOKIE, &old_cookie)
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
                    .header(header::COOKIE, &new_cookie)
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
    async fn single_user_jwt_sliding_window_and_rejects_expired_or_other_user_jwt() {
        let (state, _dir) = test_state(false).await;
        let derived = auth::derive_auth_token("someSuperSecretValue");

        // Create another user "bob" in DB; bob's valid JWT must be rejected in single-user mode.
        let bob_secret = auth::generate_random_user_secret();
        state.db.get_or_create_user("bob", &bob_secret).await.unwrap();
        let bob_jwt = auth::sign_session_jwt(
            "bob",
            &bob_secret,
            auth::current_unix_secs(),
            TEST_SESSION_TTL_SECS,
        );

        // Near-expiry valid JWT for "golinks" (exp = now + 60s)
        let now = auth::current_unix_secs();
        let short_jwt = auth::sign_session_jwt("golinks", &derived, now - 100, 160);
        let (short_claims, _, _) = auth::parse_unverified_jwt(&short_jwt).unwrap();

        // Expired JWT for "golinks"
        let expired_jwt = auth::sign_session_jwt("golinks", &derived, now - 1000, 500);

        let app = build_router(state);

        // Sliding window refreshes Set-Cookie with exp > old_exp on getLinks and /docs
        for uri in ["/?action=getLinks", "/docs"] {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .header(header::COOKIE, format!("golinks_auth={short_jwt}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let set_cookie = resp
                .headers()
                .get(header::SET_COOKIE)
                .and_then(|v| v.to_str().ok())
                .expect("expected refreshed Set-Cookie");
            let refreshed_jwt = set_cookie
                .split(';')
                .next()
                .unwrap()
                .strip_prefix("golinks_auth=")
                .unwrap();
            let (new_claims, _, _) = auth::parse_unverified_jwt(refreshed_jwt).unwrap();
            assert!(
                new_claims.exp > short_claims.exp,
                "expected sliding window exp to advance for {uri}"
            );
        }

        // Expired JWT rejected
        let expired_api = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/?action=getLinks")
                    .header(header::COOKIE, format!("golinks_auth={expired_jwt}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(expired_api.status(), StatusCode::UNAUTHORIZED);

        // Other user's valid JWT rejected in single-user mode
        let bob_api = app
            .oneshot(
                Request::builder()
                    .uri("/?action=getLinks")
                    .header(header::COOKIE, format!("golinks_auth={bob_jwt}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bob_api.status(), StatusCode::UNAUTHORIZED);
    }

    async fn oidc_test_state() -> (
        AppState,
        crate::oidc::test_support::MockOidcServer,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("golinks_oidc.db");
        let db = Database::connect(&DbConfig::Sqlite {
            path: db_path.to_string_lossy().into_owned(),
        })
        .await
        .unwrap();
        db.run_migrations().await.unwrap();

        let server = crate::oidc::test_support::MockOidcServer::start("golinks-client").await;
        let cfg = server.oidc_config("golinks-client", "oidc-secret", "https://go.example.com/");
        let service = Arc::new(crate::oidc::OidcService::new(cfg).unwrap());

        let state = AppState {
            db,
            auth_mode: AuthMode::Oidc(service),
            session_ttl_secs: TEST_SESSION_TTL_SECS,
            secure_cookie: false,
            favicon: default_favicon(),
            ui_html: Arc::new("<!DOCTYPE html><html><body>UI</body></html>".to_string()),
        };
        (state, server, dir)
    }

    #[tokio::test]
    async fn oidc_unauthenticated_root_and_keyword_redirect_directly_to_provider() {
        let (state, server, _dir) = oidc_test_state().await;
        let app = build_router(state);

        // GET / redirects directly to OIDC provider
        let root_resp = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(root_resp.status(), StatusCode::FOUND);
        assert_security_headers(root_resp.headers());
        let loc = root_resp
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(loc.starts_with(&format!("{}/authorize", server.issuer_url)));
        let state_cookie = root_resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(state_cookie.contains("golinks_oidc_state="));

        // GET /docs redirects directly to OIDC provider
        let docs_resp = app
            .clone()
            .oneshot(Request::builder().uri("/docs").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(docs_resp.status(), StatusCode::FOUND);
        assert!(
            docs_resp
                .headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with(&format!("{}/authorize", server.issuer_url))
        );

        // GET /?action=getLinks returns 401 with oidcEnabled: true
        let api_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/?action=getLinks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(api_resp.status(), StatusCode::UNAUTHORIZED);
        let api_body: serde_json::Value =
            serde_json::from_str(&body_text(api_resp).await).unwrap();
        assert_eq!(api_body["oidcEnabled"], true);

        // POST /?action=login is disabled (403)
        let login_resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/?action=login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"secret":"anything"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login_resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn oidc_callback_provisions_users_preserves_secret_and_isolates_links() {
        use crate::oidc::test_support::{MockUserBehavior, extract_query_param};

        let (state, server, _dir) = oidc_test_state().await;
        let db = state.db.clone();
        let app = build_router(state);

        // Helper to complete an OIDC login flow targeting `initial_uri`
        let complete_login = |initial_uri: String, code: String, behavior_user: String, in_id: bool| {
            let app = app.clone();
            let server_ref = &server;
            async move {
                let start_resp = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .uri(&initial_uri)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(start_resp.status(), StatusCode::FOUND);
                let auth_url = start_resp
                    .headers()
                    .get(header::LOCATION)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string();
                let state_cookie = start_resp
                    .headers()
                    .get(header::SET_COOKIE)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .split(';')
                    .next()
                    .unwrap()
                    .to_string();
                let state_param = extract_query_param(&auth_url, "state").unwrap();
                let nonce = extract_query_param(&auth_url, "nonce").unwrap();

                server_ref.register_code(
                    &code,
                    MockUserBehavior {
                        username: behavior_user,
                        include_in_id_token: in_id,
                        include_in_userinfo: !in_id,
                        nonce,
                    },
                );

                let cb_resp = app
                    .oneshot(
                        Request::builder()
                            .uri(format!("/?code={code}&state={state_param}"))
                            .header(header::COOKIE, state_cookie)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(cb_resp.status(), StatusCode::FOUND);
                assert_security_headers(cb_resp.headers());
                let redirect_to = cb_resp
                    .headers()
                    .get(header::LOCATION)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string();
                let mut auth_cookie = None;
                let mut cleared_state = false;
                for val in cb_resp.headers().get_all(header::SET_COOKIE) {
                    let s = val.to_str().unwrap();
                    if s.starts_with("golinks_auth=") {
                        auth_cookie = Some(s.split(';').next().unwrap().to_string());
                    } else if s.starts_with("golinks_oidc_state=") && s.contains("Max-Age=0") {
                        cleared_state = true;
                    }
                }
                assert!(cleared_state, "expected golinks_oidc_state to be cleared");
                (auth_cookie.expect("expected golinks_auth cookie"), redirect_to)
            }
        };

        // 1. Alice logs in targeting /docs (claim in ID token)
        let (alice_cookie, alice_next) =
            complete_login("/docs".into(), "code-a1".into(), "alice".into(), true).await;
        assert_eq!(alice_next, "/docs");
        let alice_user = db.get_user_by_name("alice").await.unwrap().unwrap();
        assert_eq!(alice_user.user_secret.len(), 64);

        // 2. Alice logs in again -> user_secret preserved; open-redirect next=//evil.com sanitized to /
        let (_alice_cookie2, sanitized_next) =
            complete_login("/?next=//evil.com".into(), "code-a2".into(), "alice".into(), true)
                .await;
        assert_eq!(sanitized_next, "/");
        let alice_user2 = db.get_user_by_name("alice").await.unwrap().unwrap();
        assert_eq!(alice_user2.user_secret, alice_user.user_secret);

        // 3. Bob logs in (claim via userinfo fallback)
        let (bob_cookie, bob_next) =
            complete_login("/".into(), "code-b1".into(), "bob".into(), false).await;
        assert_eq!(bob_next, "/");
        let bob_user = db.get_user_by_name("bob").await.unwrap().unwrap();
        assert_ne!(bob_user.user_secret, alice_user.user_secret);

        // 4. Alice and Bob save conflicting link keyword "docs" -> strictly isolated
        let save_alice = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/?action=saveLink")
                    .header(header::COOKIE, &alice_cookie)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"key":"docs","target":"https://alice.example.com"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(save_alice.status(), StatusCode::OK);
        assert!(save_alice.headers().get(header::SET_COOKIE).is_some());

        let save_bob = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/?action=saveLink")
                    .header(header::COOKIE, &bob_cookie)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"key":"docs","target":"https://bob.example.com"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(save_bob.status(), StatusCode::OK);

        let alice_go = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/docs")
                    .header(header::COOKIE, &alice_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            alice_go.headers().get(header::LOCATION).unwrap(),
            "https://alice.example.com"
        );
        assert!(alice_go.headers().get(header::SET_COOKIE).is_some());

        let bob_go = app
            .oneshot(
                Request::builder()
                    .uri("/docs")
                    .header(header::COOKIE, &bob_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            bob_go.headers().get(header::LOCATION).unwrap(),
            "https://bob.example.com"
        );
        assert!(bob_go.headers().get(header::SET_COOKIE).is_some());
    }

    #[tokio::test]
    async fn oidc_callback_errors_do_not_loop() {
        let (state, _server, _dir) = oidc_test_state().await;
        let app = build_router(state);

        // Provider error param returns 401 (no redirect loop) and clears state cookie
        let err_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/?error=access_denied&state=abc")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(err_resp.status(), StatusCode::UNAUTHORIZED);
        assert_security_headers(err_resp.headers());
        assert!(
            err_resp
                .headers()
                .get(header::SET_COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );

        // Mismatched/missing state cookie returns 400 and clears state cookie
        let bad_state = app
            .oneshot(
                Request::builder()
                    .uri("/?code=abc&state=wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_state.status(), StatusCode::BAD_REQUEST);
        assert_security_headers(bad_state.headers());
        assert!(
            bad_state
                .headers()
                .get(header::SET_COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
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

    #[tokio::test]
    async fn tag_normalization_validation_and_lifecycle() {
        let (state, _dir) = test_state(false).await;
        let cookie_hdr = make_jwt_cookie("golinks", "someSuperSecretValue");
        let app = build_router(state);

        // Save with mixed case, padding, duplicates, and empty entries -> normalized & sorted
        let save_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/?action=saveLink")
                    .header(header::COOKIE, &cookie_hdr)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_string(&json!({
                            "key": "gh",
                            "target": "https://github.com/%s",
                            "tags": [" Work ", "work", "", "  ", "DOCS"],
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(save_resp.status(), StatusCode::OK);
        let save_body: serde_json::Value =
            serde_json::from_str(&body_text(save_resp).await).unwrap();
        assert_eq!(save_body["links"]["gh"]["target"], "https://github.com/%s");
        assert_eq!(save_body["links"]["gh"]["tags"], json!(["docs", "work"]));
        assert_eq!(save_body["tags"], json!(["docs", "work"]));

        // Redirect behavior is unaffected by tags
        let redir_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/gh%20rust")
                    .header(header::COOKIE, &cookie_hdr)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(redir_resp.status(), StatusCode::FOUND);
        assert_eq!(
            redir_resp.headers().get(header::LOCATION).unwrap(),
            "https://github.com/rust"
        );

        // Tag with internal whitespace -> 400
        let bad_ws_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/?action=saveLink")
                    .header(header::COOKIE, &cookie_hdr)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_string(&json!({
                            "key": "gh",
                            "target": "https://github.com/%s",
                            "tags": ["bad tag"],
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_ws_resp.status(), StatusCode::BAD_REQUEST);

        // Tag exceeding 32 Unicode chars -> 400
        let long_tag = "é".repeat(33);
        let bad_len_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/?action=saveLink")
                    .header(header::COOKIE, &cookie_hdr)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_string(&json!({
                            "key": "gh",
                            "target": "https://github.com/%s",
                            "tags": [long_tag],
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_len_resp.status(), StatusCode::BAD_REQUEST);

        // Omitting tags clears them and auto-deletes unused tags
        let clear_resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/?action=saveLink")
                    .header(header::COOKIE, &cookie_hdr)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_string(&json!({
                            "originalKey": "gh",
                            "key": "gh",
                            "target": "https://github.com/%s",
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(clear_resp.status(), StatusCode::OK);
        let clear_body: serde_json::Value =
            serde_json::from_str(&body_text(clear_resp).await).unwrap();
        assert_eq!(clear_body["links"]["gh"]["tags"], json!([]));
        assert_eq!(clear_body["tags"], json!([]));
    }

    #[tokio::test]
    async fn oidc_multi_user_tags_are_isolated() {
        let (state, _server, _dir) = oidc_test_state().await;
        let alice_secret = auth::generate_random_user_secret();
        let bob_secret = auth::generate_random_user_secret();
        state
            .db
            .get_or_create_user("alice", &alice_secret)
            .await
            .unwrap();
        state
            .db
            .get_or_create_user("bob", &bob_secret)
            .await
            .unwrap();

        let now = auth::current_unix_secs();
        let alice_cookie = format!(
            "golinks_auth={}",
            auth::sign_session_jwt("alice", &alice_secret, now, TEST_SESSION_TTL_SECS)
        );
        let bob_cookie = format!(
            "golinks_auth={}",
            auth::sign_session_jwt("bob", &bob_secret, now, TEST_SESSION_TTL_SECS)
        );
        let app = build_router(state);

        let save_alice = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/?action=saveLink")
                    .header(header::COOKIE, &alice_cookie)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"key":"docs","target":"https://alice.example.com","tags":["work","alice-only"]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(save_alice.status(), StatusCode::OK);

        let save_bob = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/?action=saveLink")
                    .header(header::COOKIE, &bob_cookie)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"key":"docs","target":"https://bob.example.com","tags":["work","bob-only"]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(save_bob.status(), StatusCode::OK);

        // Alice deletes her link -> Alice has no tags, Bob still has ["bob-only", "work"]
        let del_alice = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/?action=deleteLink")
                    .header(header::COOKIE, &alice_cookie)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"key":"docs"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(del_alice.status(), StatusCode::OK);
        let del_body: serde_json::Value =
            serde_json::from_str(&body_text(del_alice).await).unwrap();
        assert_eq!(del_body["tags"], json!([]));

        let bob_get = app
            .oneshot(
                Request::builder()
                    .uri("/?action=getLinks")
                    .header(header::COOKIE, &bob_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bob_get.status(), StatusCode::OK);
        let bob_body: serde_json::Value = serde_json::from_str(&body_text(bob_get).await).unwrap();
        assert_eq!(bob_body["tags"], json!(["bob-only", "work"]));
        assert_eq!(
            bob_body["links"]["docs"]["tags"],
            json!(["bob-only", "work"])
        );
    }

    #[test]
    fn normalize_and_validate_tags_checks_length_after_lowercasing() {
        // U+0130 ('İ') expands to 2 Unicode scalar values ("i\u{307}") on to_lowercase().
        let expanding = "\u{0130}".repeat(20);
        assert_eq!(expanding.chars().count(), 20);
        assert_eq!(expanding.to_lowercase().chars().count(), 40);
        assert!(normalize_and_validate_tags(&[expanding]).is_err());
    }
}
