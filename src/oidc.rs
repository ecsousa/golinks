use std::fmt;
use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

use crate::auth::{constant_time_eq, current_unix_secs, extract_cookie_values};
use crate::db::config::{MAX_USERNAME_CHARS, OidcConfig};

type HmacSha256 = Hmac<Sha256>;

pub const OIDC_STATE_COOKIE_NAME: &str = "golinks_oidc_state";
const OIDC_STATE_TTL_SECS: u64 = 600; // 10 minutes
const DISCOVERY_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug)]
pub enum OidcError {
    ProviderUnavailable(String),
    InvalidState(String),
    TokenExchange(String),
    InvalidIdToken(String),
    MissingUsernameClaim(String),
    InvalidUsername(String),
}

impl fmt::Display for OidcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProviderUnavailable(msg) => write!(f, "OIDC provider unavailable: {msg}"),
            Self::InvalidState(msg) => write!(f, "invalid OIDC state: {msg}"),
            Self::TokenExchange(msg) => write!(f, "OIDC token exchange failed: {msg}"),
            Self::InvalidIdToken(msg) => write!(f, "invalid OIDC ID token: {msg}"),
            Self::MissingUsernameClaim(msg) => write!(f, "missing OIDC username claim: {msg}"),
            Self::InvalidUsername(msg) => write!(f, "invalid OIDC username: {msg}"),
        }
    }
}

impl std::error::Error for OidcError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OidcLoginState {
    state: String,
    nonce: String,
    pkce_verifier: String,
    next: String,
    exp: u64,
}

struct CachedDiscovery {
    metadata: CoreProviderMetadata,
    fetched_at: Instant,
}

/// Sanitizes a post-login redirect target to prevent open redirects.
pub fn sanitize_next_path(raw: Option<&str>) -> String {
    match raw {
        Some(next)
            if next.starts_with('/')
                && !next.starts_with("//")
                && !next.contains('\\')
                && !next.contains('\r')
                && !next.contains('\n') =>
        {
            next.to_string()
        }
        _ => "/".to_string(),
    }
}

/// Builds a `Set-Cookie` header that clears `golinks_oidc_state`.
pub fn build_clear_state_cookie(secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{OIDC_STATE_COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0{secure_attr}"
    )
}

fn derive_state_key(client_secret: &str) -> [u8; 32] {
    const STATE_CONTEXT: &[u8] = b"golinks-oidc-state-v1";
    let mut mac = HmacSha256::new_from_slice(client_secret.as_bytes())
        .expect("HMAC accepts keys of any length");
    mac.update(STATE_CONTEXT);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn encode_state_cookie_value(state: &OidcLoginState, client_secret: &str) -> String {
    let payload_json = serde_json::to_vec(state).expect("OidcLoginState serialization cannot fail");
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);
    let key = derive_state_key(client_secret);
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts 32-byte key");
    mac.update(payload_b64.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{payload_b64}.{sig_b64}")
}

fn decode_and_verify_state_cookie(
    cookie_val: &str,
    client_secret: &str,
    now_secs: u64,
) -> Option<OidcLoginState> {
    let (payload_b64, sig_b64) = cookie_val.split_once('.')?;
    if sig_b64.contains('.') {
        return None;
    }
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).ok()?;
    let key = derive_state_key(client_secret);
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts 32-byte key");
    mac.update(payload_b64.as_bytes());
    let expected = mac.finalize().into_bytes();
    let matches: bool = expected.as_slice().ct_eq(&sig_bytes).into();
    if !matches {
        return None;
    }
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let state: OidcLoginState = serde_json::from_slice(&payload_bytes).ok()?;
    if state.exp <= now_secs {
        return None;
    }
    Some(state)
}

fn build_state_cookie_header(value: &str, secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{OIDC_STATE_COOKIE_NAME}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={OIDC_STATE_TTL_SECS}{secure_attr}"
    )
}

fn extract_claim_from_jwt_payload(jwt_str: &str, claim_name: &str) -> Option<String> {
    let payload_b64 = jwt_str.split('.').nth(1)?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    json.get(claim_name)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

/// Manages OIDC discovery caching, authorization redirects, and callback verification.
pub struct OidcService {
    config: OidcConfig,
    issuer_url: IssuerUrl,
    redirect_url: RedirectUrl,
    http_client: reqwest::Client,
    discovery_cache: RwLock<Option<CachedDiscovery>>,
}

impl OidcService {
    /// Creates a new `OidcService` after validating URLs and constructing the `rustls` HTTP client.
    pub fn new(config: OidcConfig) -> Result<Self, String> {
        let issuer_url = IssuerUrl::new(config.issuer_url.clone())
            .map_err(|err| format!("invalid GOLINKS_OIDC_ISSUER_URL: {err}"))?;
        let redirect_url = RedirectUrl::new(config.redirect_uri.clone())
            .map_err(|err| format!("invalid GOLINKS_OIDC_REDIRECT_URI: {err}"))?;
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|err| format!("failed to build OIDC HTTP client: {err}"))?;

        Ok(Self {
            config,
            issuer_url,
            redirect_url,
            http_client,
            discovery_cache: RwLock::new(None),
        })
    }

    /// Best-effort discovery warmup at startup; logs a warning if the provider is not yet reachable.
    pub async fn warm_discovery(&self) {
        if let Err(err) = self.get_or_fetch_metadata(false).await {
            eprintln!("Warning: initial OIDC discovery failed (will retry lazily): {err}");
        }
    }

    async fn get_or_fetch_metadata(&self, force_refresh: bool) -> Result<CoreProviderMetadata, OidcError> {
        if !force_refresh {
            let guard = self.discovery_cache.read().await;
            if let Some(cached) = guard.as_ref() {
                if cached.fetched_at.elapsed() < DISCOVERY_CACHE_TTL {
                    return Ok(cached.metadata.clone());
                }
            }
        }

        let metadata =
            CoreProviderMetadata::discover_async(self.issuer_url.clone(), &self.http_client)
                .await
                .map_err(|err| OidcError::ProviderUnavailable(err.to_string()))?;

        let mut guard = self.discovery_cache.write().await;
        *guard = Some(CachedDiscovery {
            metadata: metadata.clone(),
            fetched_at: Instant::now(),
        });
        Ok(metadata)
    }

    /// Starts an OIDC login flow and returns `(authorize_url, set_state_cookie_header)`.
    pub async fn start_login(
        &self,
        next_path: &str,
        secure_cookie: bool,
    ) -> Result<(String, String), OidcError> {
        let metadata = self.get_or_fetch_metadata(false).await?;
        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(self.config.client_id.clone()),
            Some(ClientSecret::new(self.config.client_secret.clone())),
        )
        .set_redirect_uri(self.redirect_url.clone());

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let mut auth_req = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(pkce_challenge);

        for scope in &self.config.scopes {
            if scope != "openid" {
                auth_req = auth_req.add_scope(Scope::new(scope.clone()));
            }
        }

        let (authorize_url, csrf_token, nonce) = auth_req.url();
        let sanitized_next = sanitize_next_path(Some(next_path));
        let login_state = OidcLoginState {
            state: csrf_token.secret().clone(),
            nonce: nonce.secret().clone(),
            pkce_verifier: pkce_verifier.secret().clone(),
            next: sanitized_next,
            exp: current_unix_secs().saturating_add(OIDC_STATE_TTL_SECS),
        };
        let encoded = encode_state_cookie_value(&login_state, &self.config.client_secret);
        let set_cookie = build_state_cookie_header(&encoded, secure_cookie);
        Ok((authorize_url.to_string(), set_cookie))
    }

    /// Validates the callback `state` cookie, exchanges `code`, verifies the ID token,
    /// and extracts `(username, sanitized_next_path)`.
    pub async fn complete_callback(
        &self,
        headers: &HeaderMap,
        code: &str,
        state_param: &str,
    ) -> Result<(String, String), OidcError> {
        let now = current_unix_secs();
        let matched_state = extract_cookie_values(headers, OIDC_STATE_COOKIE_NAME)
            .into_iter()
            .filter_map(|v| decode_and_verify_state_cookie(v, &self.config.client_secret, now))
            .find(|s| constant_time_eq(&s.state, state_param))
            .ok_or_else(|| {
                OidcError::InvalidState("missing, expired, or mismatched state cookie".to_string())
            })?;

        let metadata = self.get_or_fetch_metadata(false).await?;
        let client = CoreClient::from_provider_metadata(
            metadata.clone(),
            ClientId::new(self.config.client_id.clone()),
            Some(ClientSecret::new(self.config.client_secret.clone())),
        )
        .set_redirect_uri(self.redirect_url.clone());

        let token_response = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .map_err(|err| OidcError::TokenExchange(err.to_string()))?
            .set_pkce_verifier(PkceCodeVerifier::new(matched_state.pkce_verifier))
            .request_async(&self.http_client)
            .await
            .map_err(|err| OidcError::TokenExchange(err.to_string()))?;

        let id_token = token_response
            .id_token()
            .ok_or_else(|| OidcError::InvalidIdToken("token response missing id_token".to_string()))?;

        let nonce = Nonce::new(matched_state.nonce);
        let verified_metadata = if id_token.claims(&client.id_token_verifier(), &nonce).is_ok() {
            metadata
        } else {
            // Refresh metadata/JWKS once in case the provider rotated signing keys.
            let refreshed = self.get_or_fetch_metadata(true).await?;
            let refreshed_client = CoreClient::from_provider_metadata(
                refreshed.clone(),
                ClientId::new(self.config.client_id.clone()),
                Some(ClientSecret::new(self.config.client_secret.clone())),
            )
            .set_redirect_uri(self.redirect_url.clone());
            id_token
                .claims(&refreshed_client.id_token_verifier(), &nonce)
                .map_err(|err| OidcError::InvalidIdToken(err.to_string()))?;
            refreshed
        };

        let mut username =
            extract_claim_from_jwt_payload(&id_token.to_string(), &self.config.username_claim);

        if username.is_none() {
            if let Some(userinfo_url) = verified_metadata.userinfo_endpoint() {
                let resp = self
                    .http_client
                    .get(userinfo_url.as_str())
                    .bearer_auth(token_response.access_token().secret())
                    .send()
                    .await
                    .map_err(|err| {
                        OidcError::MissingUsernameClaim(format!("userinfo request failed: {err}"))
                    })?;
                if resp.status().is_success() {
                    let body: serde_json::Value = resp.json().await.map_err(|err| {
                        OidcError::MissingUsernameClaim(format!("invalid userinfo JSON: {err}"))
                    })?;
                    username = body
                        .get(&self.config.username_claim)
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(ToOwned::to_owned);
                }
            }
        }

        let username = username.ok_or_else(|| {
            OidcError::MissingUsernameClaim(format!(
                "claim '{}' not found in ID token or userinfo response",
                self.config.username_claim
            ))
        })?;

        if username.chars().count() > MAX_USERNAME_CHARS {
            return Err(OidcError::InvalidUsername(format!(
                "username exceeds {MAX_USERNAME_CHARS} characters"
            )));
        }

        let next = sanitize_next_path(Some(&matched_state.next));
        Ok((username, next))
    }
}

/// Shared mock OIDC provider for unit and integration tests.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Json};
    use axum::routing::{get, post};
    use openidconnect::core::{
        CoreIdToken, CoreIdTokenClaims, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
        CoreRsaPrivateSigningKey,
    };
    use openidconnect::{
        Audience, EmptyAdditionalClaims, EndUserUsername, JsonWebKeyId, PrivateSigningKey,
        StandardClaims, SubjectIdentifier,
    };
    use rsa::RsaPrivateKey;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use serde_json::json;

    #[derive(Clone)]
    pub struct MockUserBehavior {
        pub username: String,
        pub include_in_id_token: bool,
        pub include_in_userinfo: bool,
        pub nonce: String,
    }

    #[derive(Clone)]
    struct MockState {
        issuer: String,
        client_id: String,
        signing_key: Arc<CoreRsaPrivateSigningKey>,
        jwks: Arc<CoreJsonWebKeySet>,
        codes: Arc<Mutex<HashMap<String, MockUserBehavior>>>,
        access_tokens: Arc<Mutex<HashMap<String, MockUserBehavior>>>,
    }

    pub struct MockOidcServer {
        pub issuer_url: String,
        codes: Arc<Mutex<HashMap<String, MockUserBehavior>>>,
        handle: tokio::task::JoinHandle<()>,
    }

    impl Drop for MockOidcServer {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    impl MockOidcServer {
        pub async fn start(client_id: &str) -> Self {
            let mut rng = rand::thread_rng();
            let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key");
            let pem = private_key
                .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
                .expect("encode PKCS1 PEM");
            let signing_key = CoreRsaPrivateSigningKey::from_pem(
                pem.as_str(),
                Some(JsonWebKeyId::new("test-key-1".to_string())),
            )
            .expect("create CoreRsaPrivateSigningKey");
            let jwks = CoreJsonWebKeySet::new(vec![signing_key.as_verification_key()]);

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind mock OIDC server");
            let addr = listener.local_addr().unwrap();
            let issuer = format!("http://{addr}");

            let codes = Arc::new(Mutex::new(HashMap::new()));
            let state = MockState {
                issuer: issuer.clone(),
                client_id: client_id.to_string(),
                signing_key: Arc::new(signing_key),
                jwks: Arc::new(jwks),
                codes: codes.clone(),
                access_tokens: Arc::new(Mutex::new(HashMap::new())),
            };

            let router = Router::new()
                .route(
                    "/.well-known/openid-configuration",
                    get(mock_discovery),
                )
                .route("/jwks", get(mock_jwks))
                .route("/token", post(mock_token))
                .route("/userinfo", get(mock_userinfo))
                .with_state(state);

            let handle = tokio::spawn(async move {
                let _ = axum::serve(listener, router).await;
            });

            Self {
                issuer_url: issuer,
                codes,
                handle,
            }
        }

        pub fn register_code(&self, code: &str, behavior: MockUserBehavior) {
            self.codes
                .lock()
                .unwrap()
                .insert(code.to_string(), behavior);
        }

        pub fn oidc_config(&self, client_id: &str, client_secret: &str, redirect_uri: &str) -> OidcConfig {
            OidcConfig {
                issuer_url: self.issuer_url.clone(),
                client_id: client_id.to_string(),
                client_secret: client_secret.to_string(),
                redirect_uri: redirect_uri.to_string(),
                scopes: vec![
                    "openid".to_string(),
                    "profile".to_string(),
                    "email".to_string(),
                ],
                username_claim: "preferred_username".to_string(),
            }
        }
    }

    async fn mock_discovery(State(state): State<MockState>) -> impl IntoResponse {
        Json(json!({
            "issuer": state.issuer,
            "authorization_endpoint": format!("{}/authorize", state.issuer),
            "token_endpoint": format!("{}/token", state.issuer),
            "userinfo_endpoint": format!("{}/userinfo", state.issuer),
            "jwks_uri": format!("{}/jwks", state.issuer),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"]
        }))
    }

    async fn mock_jwks(State(state): State<MockState>) -> impl IntoResponse {
        Json(state.jwks.as_ref().clone())
    }

    async fn mock_token(
        State(state): State<MockState>,
        body: String,
    ) -> impl IntoResponse {
        let params: HashMap<String, String> = form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
        let Some(code) = params.get("code") else {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_request" })))
                .into_response();
        };
        let Some(behavior) = state.codes.lock().unwrap().remove(code) else {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_grant" })))
                .into_response();
        };

        let now = chrono::Utc::now();
        let exp = now + chrono::Duration::minutes(10);
        let mut standard_claims = StandardClaims::new(SubjectIdentifier::new(format!(
            "sub-{}",
            behavior.username
        )));
        if behavior.include_in_id_token {
            standard_claims = standard_claims.set_preferred_username(Some(
                EndUserUsername::new(behavior.username.clone()),
            ));
        }

        let claims = CoreIdTokenClaims::new(
            IssuerUrl::new(state.issuer.clone()).unwrap(),
            vec![Audience::new(state.client_id.clone())],
            exp,
            now,
            standard_claims,
            EmptyAdditionalClaims {},
        )
        .set_nonce(Some(Nonce::new(behavior.nonce.clone())));

        let id_token = CoreIdToken::new(
            claims,
            state.signing_key.as_ref(),
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            None,
            None,
        )
        .expect("sign mock ID token");

        let access_token = format!("access-{}", behavior.username);
        state
            .access_tokens
            .lock()
            .unwrap()
            .insert(access_token.clone(), behavior);

        Json(json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 600,
            "id_token": id_token.to_string()
        }))
        .into_response()
    }

    async fn mock_userinfo(
        State(state): State<MockState>,
        headers: HeaderMap,
    ) -> impl IntoResponse {
        let token = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        let behavior = state.access_tokens.lock().unwrap().get(token).cloned();
        match behavior {
            Some(b) if b.include_in_userinfo => Json(json!({
                "sub": format!("sub-{}", b.username),
                "preferred_username": b.username
            }))
            .into_response(),
            Some(b) => Json(json!({ "sub": format!("sub-{}", b.username) })).into_response(),
            None => (StatusCode::UNAUTHORIZED, Json(json!({ "error": "invalid_token" })))
                .into_response(),
        }
    }

    pub fn extract_query_param(url: &str, key: &str) -> Option<String> {
        let query = url.split_once('?')?.1;
        form_urlencoded::parse(query.as_bytes())
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{MockOidcServer, MockUserBehavior, extract_query_param};
    use super::*;
    use axum::http::header;

    #[test]
    fn sanitize_next_path_rejects_open_redirects() {
        assert_eq!(sanitize_next_path(None), "/");
        assert_eq!(sanitize_next_path(Some("")), "/");
        assert_eq!(sanitize_next_path(Some("//evil.com")), "/");
        assert_eq!(sanitize_next_path(Some("https://evil.com")), "/");
        assert_eq!(sanitize_next_path(Some("/a\\b")), "/");
        assert_eq!(sanitize_next_path(Some("/a\nb")), "/");
        assert_eq!(sanitize_next_path(Some("/a\rb")), "/");
        assert_eq!(sanitize_next_path(Some("/docs?a=1")), "/docs?a=1");
        assert_eq!(sanitize_next_path(Some("/")), "/");
    }

    #[test]
    fn state_cookie_sign_verify_and_expiry() {
        let state = OidcLoginState {
            state: "csrf-123".to_string(),
            nonce: "nonce-456".to_string(),
            pkce_verifier: "pkce-789".to_string(),
            next: "/docs".to_string(),
            exp: 2_000_000_000,
        };
        let encoded = encode_state_cookie_value(&state, "client-secret");
        let decoded = decode_and_verify_state_cookie(&encoded, "client-secret", 1_999_999_000)
            .expect("valid state");
        assert_eq!(decoded, state);

        assert!(
            decode_and_verify_state_cookie(&encoded, "wrong-secret", 1_999_999_000).is_none()
        );
        assert!(
            decode_and_verify_state_cookie(&encoded, "client-secret", 2_000_000_000).is_none()
        );

        let mut tampered = encoded.clone();
        tampered.replace_range(0..1, if encoded.starts_with('A') { "B" } else { "A" });
        assert!(
            decode_and_verify_state_cookie(&tampered, "client-secret", 1_999_999_000).is_none()
        );
    }

    #[tokio::test]
    async fn mock_oidc_full_flow_extracts_claim_from_id_token_and_falls_back_to_userinfo() {
        let server = MockOidcServer::start("golinks-client").await;
        let cfg = server.oidc_config("golinks-client", "oidc-secret", "https://go.example.com/");
        let service = OidcService::new(cfg).expect("create OidcService");

        // 1. Claim in ID token
        let (auth_url, set_cookie) = service.start_login("/docs", true).await.unwrap();
        assert!(auth_url.contains("code_challenge="));
        assert!(set_cookie.contains("golinks_oidc_state="));
        let state = extract_query_param(&auth_url, "state").unwrap();
        let nonce = extract_query_param(&auth_url, "nonce").unwrap();

        server.register_code(
            "code-alice",
            MockUserBehavior {
                username: "alice".to_string(),
                include_in_id_token: true,
                include_in_userinfo: false,
                nonce,
            },
        );

        let cookie_pair = set_cookie.split(';').next().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, cookie_pair.parse().unwrap());
        let (user, next) = service
            .complete_callback(&headers, "code-alice", &state)
            .await
            .unwrap();
        assert_eq!(user, "alice");
        assert_eq!(next, "/docs");

        // 2. Claim omitted from ID token -> falls back to userinfo
        let (auth_url2, set_cookie2) = service.start_login("/notes", false).await.unwrap();
        let state2 = extract_query_param(&auth_url2, "state").unwrap();
        let nonce2 = extract_query_param(&auth_url2, "nonce").unwrap();

        server.register_code(
            "code-bob",
            MockUserBehavior {
                username: "bob".to_string(),
                include_in_id_token: false,
                include_in_userinfo: true,
                nonce: nonce2,
            },
        );

        let cookie_pair2 = set_cookie2.split(';').next().unwrap();
        let mut headers2 = HeaderMap::new();
        headers2.insert(header::COOKIE, cookie_pair2.parse().unwrap());
        let (user2, next2) = service
            .complete_callback(&headers2, "code-bob", &state2)
            .await
            .unwrap();
        assert_eq!(user2, "bob");
        assert_eq!(next2, "/notes");
    }

    #[tokio::test]
    async fn warm_discovery_does_not_fail_when_provider_is_unreachable() {
        let cfg = OidcConfig {
            issuer_url: "http://127.0.0.1:1".to_string(),
            client_id: "c".to_string(),
            client_secret: "s".to_string(),
            redirect_uri: "https://go.example.com/".to_string(),
            scopes: vec!["openid".to_string()],
            username_claim: "preferred_username".to_string(),
        };
        let service = OidcService::new(cfg).unwrap();
        service.warm_discovery().await;
    }
}
