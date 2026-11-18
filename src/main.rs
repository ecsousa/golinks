mod auth;
mod config;

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use percent_encoding::percent_decode_str;

use crate::config::{RuntimeConfig, SharedConfig};

#[derive(Clone)]
pub struct AppState {
    pub config: SharedConfig,
    pub secure_cookie: bool,
}

impl AppState {
    pub fn current_config(&self) -> Arc<RuntimeConfig> {
        self.config.read().expect("config lock poisoned").clone()
    }
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
        return auth::render_login_page(next, None);
    }

    let trimmed = uri.path().strip_prefix('/').unwrap_or(uri.path());
    if trimmed.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let (link_key_raw, rest_raw) = split_link_and_rest(trimmed);
    let link_key = percent_decode_str(link_key_raw).decode_utf8_lossy();

    let Some(template) = cfg.links.get(link_key.as_ref()) else {
        return StatusCode::NOT_FOUND.into_response();
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

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/_auth", get(auth::handle_auth_get).post(auth::handle_auth_post))
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

    let state = AppState {
        config: shared_config,
        secure_cookie,
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
    use std::collections::HashMap;
    use std::time::Duration;
    use tower::ServiceExt;

    fn test_state(secure_cookie: bool) -> AppState {
        let mut links = HashMap::new();
        links.insert(
            "google".to_string(),
            "https://www.google.com/search?q=%s".to_string(),
        );
        links.insert(
            "site1".to_string(),
            "https://site1.example.com".to_string(),
        );
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
            secure_cookie,
        }
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
    async fn unauthenticated_requests_return_401_login_page() {
        let app = build_router(test_state(true));

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/google/use%20curl/wget")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_security_headers(resp.headers());
        let html = body_text(resp).await;
        assert!(html.contains(r#"name="next" value="/google/use%20curl/wget""#));

        let root_resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(root_resp.status(), StatusCode::UNAUTHORIZED);
        assert_security_headers(root_resp.headers());
    }

    #[tokio::test]
    async fn auth_post_valid_and_invalid_and_open_redirect_guard() {
        let app = build_router(test_state(true));

        // Wrong secret
        let bad = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_auth")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("secret=wrong&next=%2Fsonarr"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);
        assert_security_headers(bad.headers());
        assert!(body_text(bad).await.contains("Invalid secret."));

        // Valid secret + open redirect attempt
        let good = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_auth")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "secret=someSuperSecretValue&next=https%3A%2F%2Fevil.com",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(good.status(), StatusCode::SEE_OTHER);
        assert_security_headers(good.headers());
        assert_eq!(
            good.headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("/")
        );
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
    async fn authenticated_redirects_and_url_encoding() {
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
                "/site1%20extra",
                Some("https://site1.example.com"),
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
                "/site1",
                Some("https://site1.example.com"),
                StatusCode::FOUND,
            ),
            (
                "/site1/",
                Some("https://site1.example.com"),
                StatusCode::FOUND,
            ),
            (
                "/site1/extra/segments",
                Some("https://site1.example.com"),
                StatusCode::FOUND,
            ),
            (
                "/m/1",
                Some("https://www.google.com/maps/preview?authuser=1"),
                StatusCode::FOUND,
            ),
            ("/", None, StatusCode::NOT_FOUND),
            ("/unknown", None, StatusCode::NOT_FOUND),
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
    async fn hot_reload_updates_links_and_invalidates_old_key_while_surviving_bad_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("golinks.yaml");
        std::fs::write(
            &cfg_path,
            "key: firstSecret\nlinks:\n  site1: https://site1.example.com\n",
        )
        .unwrap();

        let initial = config::load_config_from_path(&cfg_path).unwrap();
        let old_token = initial.auth_token.clone();
        let shared: SharedConfig = Arc::new(RwLock::new(Arc::new(initial)));
        let _watcher = config::spawn_config_watcher(&cfg_path, shared.clone()).unwrap();

        let app = build_router(AppState {
            config: shared.clone(),
            secure_cookie: false,
        });

        // Update YAML with new key and new link
        std::fs::write(
            &cfg_path,
            "key: secondSecret\nlinks:\n  site2: https://site2.example.com\n",
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

        // Old cookie should now be rejected
        let old_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/site2")
                    .header(header::COOKIE, format!("golinks_auth={old_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(old_resp.status(), StatusCode::UNAUTHORIZED);

        // New cookie should resolve the newly added link
        let new_token = config::derive_auth_token("secondSecret");
        let new_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/site2")
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
            Some("https://site2.example.com")
        );

        // Write invalid YAML and verify previous valid config remains active
        std::fs::write(&cfg_path, "key: [unclosed").unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;

        let still_works = app
            .oneshot(
                Request::builder()
                    .uri("/site2")
                    .header(header::COOKIE, format!("golinks_auth={new_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(still_works.status(), StatusCode::FOUND);
    }
}
