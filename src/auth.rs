use axum::http::{HeaderMap, header};
use subtle::ConstantTimeEq;

pub const AUTH_COOKIE_NAME: &str = "golinks_auth";
const COOKIE_MAX_AGE_SECS: u64 = 157_680_000; // 5 years

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

/// Builds the `Set-Cookie` header value for an authenticated session.
pub fn build_auth_cookie(token: &str, secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{AUTH_COOKIE_NAME}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={COOKIE_MAX_AGE_SECS}{secure_attr}"
    )
}
