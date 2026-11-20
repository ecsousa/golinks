use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{HeaderMap, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

pub const AUTH_COOKIE_NAME: &str = "golinks_auth";
const COOKIE_MAX_AGE_SECS: u64 = 157_680_000; // 5 years (removed in Task 5)

#[derive(Debug, Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
}

/// Session JWT payload claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionClaims {
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
}

/// Returns current UNIX timestamp in seconds.
pub fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Generates a cryptographically random 64-character lowercase hex secret (256 bits).
pub fn generate_random_user_secret() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("OS CSPRNG unavailable");
    hex::encode(bytes)
}

/// Derives a stateless hex-encoded HMAC-SHA256 session token from the configured secret key.
pub fn derive_auth_token(key: &str) -> String {
    const SESSION_CONTEXT: &[u8] = b"golinks-session-v1";

    let mut mac =
        HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(SESSION_CONTEXT);
    hex::encode(mac.finalize().into_bytes())
}

/// Compares two strings in constant time to avoid timing side-channels.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Signs an HS256 session JWT for `user_name` using `user_secret`.
pub fn sign_session_jwt(user_name: &str, user_secret: &str, now_secs: u64, ttl_secs: u64) -> String {
    const HEADER_JSON: &[u8] = br#"{"alg":"HS256","typ":"JWT"}"#;
    let claims = SessionClaims {
        sub: user_name.to_string(),
        iat: now_secs,
        exp: now_secs.saturating_add(ttl_secs),
    };
    let header_b64 = URL_SAFE_NO_PAD.encode(HEADER_JSON);
    let payload_json = serde_json::to_vec(&claims).expect("SessionClaims serialization cannot fail");
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);
    let signing_input = format!("{header_b64}.{payload_b64}");

    let mut mac = HmacSha256::new_from_slice(user_secret.as_bytes())
        .expect("HMAC accepts keys of any length");
    mac.update(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{signing_input}.{sig_b64}")
}

/// Parses an HS256 JWT without verifying its signature.
/// Rejects malformed tokens, non-HS256 headers, and empty `sub` claims.
pub fn parse_unverified_jwt(token: &str) -> Option<(SessionClaims, String, Vec<u8>)> {
    let mut parts = token.split('.');
    let header_b64 = parts.next()?;
    let payload_b64 = parts.next()?;
    let sig_b64 = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).ok()?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes).ok()?;
    if header.alg != "HS256" {
        return None;
    }

    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let claims: SessionClaims = serde_json::from_slice(&payload_bytes).ok()?;
    if claims.sub.trim().is_empty() {
        return None;
    }

    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).ok()?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    Some((claims, signing_input, sig_bytes))
}

/// Verifies an HS256 JWT signature against `user_secret` in constant time.
/// Always returns `false` if `user_secret` is empty or whitespace-only.
pub fn verify_jwt_signature(signing_input: &str, sig_bytes: &[u8], user_secret: &str) -> bool {
    if user_secret.trim().is_empty() {
        return false;
    }
    let mut mac = HmacSha256::new_from_slice(user_secret.as_bytes())
        .expect("HMAC accepts keys of any length");
    mac.update(signing_input.as_bytes());
    let expected = mac.finalize().into_bytes();
    expected.as_slice().ct_eq(sig_bytes).into()
}

/// Extracts all cookie values matching `cookie_name` across all incoming `Cookie` headers.
pub fn extract_cookie_values<'a>(headers: &'a HeaderMap, cookie_name: &str) -> Vec<&'a str> {
    let mut values = Vec::new();
    for header_val in headers.get_all(header::COOKIE) {
        let Ok(cookie_str) = header_val.to_str() else {
            continue;
        };
        for pair in cookie_str.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if name.trim() == cookie_name {
                values.push(value.trim());
            }
        }
    }
    values
}

/// Checks whether the incoming `Cookie` header contains a valid session token.
pub fn is_authenticated(headers: &HeaderMap, expected_token: &str) -> bool {
    extract_cookie_values(headers, AUTH_COOKIE_NAME)
        .into_iter()
        .any(|val| constant_time_eq(val, expected_token))
}

/// Builds the `Set-Cookie` header value for an authenticated session with an explicit `Max-Age`.
pub fn build_auth_cookie_with_max_age(token: &str, max_age_secs: u64, secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{AUTH_COOKIE_NAME}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age_secs}{secure_attr}"
    )
}

/// Builds the `Set-Cookie` header value for an authenticated session.
pub fn build_auth_cookie(token: &str, secure: bool) -> String {
    build_auth_cookie_with_max_age(token, COOKIE_MAX_AGE_SECS, secure)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_auth_token_is_64_char_hex_and_matches_known_hmac() {
        let token = derive_auth_token("someSuperSecretValue");
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(token, derive_auth_token("someSuperSecretValue"));
        assert_ne!(token, derive_auth_token("differentSecret"));
    }

    #[test]
    fn generate_random_user_secret_is_64_hex_and_unique() {
        let s1 = generate_random_user_secret();
        let s2 = generate_random_user_secret();
        assert_eq!(s1.len(), 64);
        assert_eq!(s2.len(), 64);
        assert!(s1.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(s2.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(s1, s2);
    }

    #[test]
    fn jwt_sign_parse_and_verify_roundtrip() {
        let secret = derive_auth_token("someSuperSecretValue");
        let now = 1_700_000_000;
        let ttl = 86_400;
        let jwt = sign_session_jwt("alice", &secret, now, ttl);

        let (claims, signing_input, sig_bytes) =
            parse_unverified_jwt(&jwt).expect("valid JWT structure");
        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.iat, now);
        assert_eq!(claims.exp, now + ttl);
        assert!(verify_jwt_signature(&signing_input, &sig_bytes, &secret));
        assert!(!verify_jwt_signature(
            &signing_input,
            &sig_bytes,
            &derive_auth_token("wrongSecret")
        ));
    }

    #[test]
    fn jwt_rejects_tampered_payload_non_hs256_alg_and_malformed_tokens() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let secret = derive_auth_token("someSuperSecretValue");
        let jwt = sign_session_jwt("alice", &secret, 1_700_000_000, 3600);
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Tampered payload
        let tampered_payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"bob","iat":1700000000,"exp":1700003600}"#);
        let tampered = format!("{}.{tampered_payload}.{}", parts[0], parts[2]);
        let (_, signing_input, sig_bytes) = parse_unverified_jwt(&tampered).unwrap();
        assert!(!verify_jwt_signature(&signing_input, &sig_bytes, &secret));

        // alg: none rejected
        let none_header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let none_jwt = format!("{none_header}.{}.{}", parts[1], parts[2]);
        assert!(parse_unverified_jwt(&none_jwt).is_none());

        // Malformed 2-part token rejected
        assert!(parse_unverified_jwt("abc.def").is_none());

        // Empty sub rejected
        let empty_sub_payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"","iat":1700000000,"exp":1700003600}"#);
        let empty_sub_jwt = format!("{}.{empty_sub_payload}.{}", parts[0], parts[2]);
        assert!(parse_unverified_jwt(&empty_sub_jwt).is_none());

        // Empty user_secret must never validate a token even if signed with ""
        let empty_secret_jwt = sign_session_jwt("alice", "", 1_700_000_000, 3600);
        let (_, empty_input, empty_sig) = parse_unverified_jwt(&empty_secret_jwt).unwrap();
        assert!(!verify_jwt_signature(&empty_input, &empty_sig, ""));
        assert!(!verify_jwt_signature(&empty_input, &empty_sig, "   "));
    }

    #[test]
    fn extract_cookie_values_returns_all_matching_cookies() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            "golinks_auth=stale; other=1; golinks_auth=fresh"
                .parse()
                .unwrap(),
        );
        headers.append(header::COOKIE, "golinks_auth=newest".parse().unwrap());
        assert_eq!(
            extract_cookie_values(&headers, AUTH_COOKIE_NAME),
            vec!["stale", "fresh", "newest"]
        );
    }

    #[test]
    fn build_auth_cookie_with_max_age_sets_attributes() {
        let secure = build_auth_cookie_with_max_age("tok", 2_592_000, true);
        assert!(secure.contains("golinks_auth=tok"));
        assert!(secure.contains("HttpOnly"));
        assert!(secure.contains("SameSite=Lax"));
        assert!(secure.contains("Path=/"));
        assert!(secure.contains("Max-Age=2592000"));
        assert!(secure.contains("; Secure"));

        let insecure = build_auth_cookie_with_max_age("tok", 2_592_000, false);
        assert!(!insecure.contains("Secure"));
    }
}
