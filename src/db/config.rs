const DEFAULT_USERNAME: &str = "golinks";
pub const MAX_USERNAME_CHARS: usize = 255;
pub const DEFAULT_SESSION_TTL_DAYS: u64 = 30;
const MAX_SESSION_TTL_DAYS: u64 = 3650;
const DEFAULT_SQLITE_PATH: &str = "./golinks.db";
const DEFAULT_POSTGRES_PORT: u16 = 5432;
const DEFAULT_OIDC_SCOPES: &str = "openid profile email";
const DEFAULT_OIDC_USERNAME_CLAIM: &str = "preferred_username";

/// Parses a boolean string (`true`/`1`/`yes`/`on` or `false`/`0`/`no`/`off`).
pub fn parse_bool_str(raw: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        other => Err(format!(
            "invalid boolean value '{other}': expected true/false"
        )),
    }
}

/// Supported database backend engines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbEngine {
    Sqlite,
    Postgresql,
}

impl DbEngine {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "sqlite" => Ok(Self::Sqlite),
            "postgresql" => Ok(Self::Postgresql),
            other => Err(format!(
                "invalid GOLINKS_DB_ENGINE '{other}': expected 'sqlite' or 'postgresql'"
            )),
        }
    }
}

/// Engine-specific database connection configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbConfig {
    Sqlite {
        path: String,
    },
    Postgresql {
        host: String,
        port: u16,
        database: String,
        username: String,
        password: String,
    },
}

/// OIDC provider configuration when `GOLINKS_OIDC_ENABLED=true`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub username_claim: String,
}

/// Authentication mode configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthConfig {
    SingleUser {
        username: String,
        user_secret_key: String,
    },
    Oidc(OidcConfig),
}

/// Parsed application configuration from environment variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppConfig {
    pub auth: AuthConfig,
    pub session_ttl_days: u64,
    pub db: DbConfig,
}

impl AppConfig {
    /// Reads configuration from the process environment.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Parses configuration using a custom environment variable lookup function.
    pub fn from_lookup<F>(lookup: F) -> Result<Self, String>
    where
        F: Fn(&str) -> Option<String>,
    {
        let oidc_enabled = match lookup("GOLINKS_OIDC_ENABLED") {
            Some(raw) => parse_bool_str(&raw)
                .map_err(|err| format!("invalid GOLINKS_OIDC_ENABLED: {err}"))?,
            None => false,
        };

        let session_ttl_days = match lookup("GOLINKS_SESSION_TTL_DAYS") {
            Some(raw) => {
                let parsed = raw.trim().parse::<u64>().map_err(|err| {
                    format!("invalid GOLINKS_SESSION_TTL_DAYS '{raw}': {err}")
                })?;
                if parsed == 0 || parsed > MAX_SESSION_TTL_DAYS {
                    return Err(format!(
                        "GOLINKS_SESSION_TTL_DAYS must be between 1 and {MAX_SESSION_TTL_DAYS}"
                    ));
                }
                parsed
            }
            None => DEFAULT_SESSION_TTL_DAYS,
        };

        let auth = if oidc_enabled {
            let issuer_url = require_http_url(&lookup, "GOLINKS_OIDC_ISSUER_URL")?;
            let client_id = require_non_empty_trimmed(&lookup, "GOLINKS_OIDC_CLIENT_ID")?;
            let client_secret = lookup("GOLINKS_OIDC_CLIENT_SECRET")
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    "GOLINKS_OIDC_CLIENT_SECRET must be set and non-empty".to_string()
                })?;
            let redirect_uri = require_http_url(&lookup, "GOLINKS_OIDC_REDIRECT_URI")?;

            let raw_scopes = optional_non_empty_trimmed(&lookup, "GOLINKS_OIDC_SCOPES")?
                .unwrap_or_else(|| DEFAULT_OIDC_SCOPES.to_string());
            let mut scopes: Vec<String> = raw_scopes
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
            if !scopes.iter().any(|s| s == "openid") {
                scopes.insert(0, "openid".to_string());
            }

            let username_claim =
                optional_non_empty_trimmed(&lookup, "GOLINKS_OIDC_USERNAME_CLAIM")?
                    .unwrap_or_else(|| DEFAULT_OIDC_USERNAME_CLAIM.to_string());

            AuthConfig::Oidc(OidcConfig {
                issuer_url,
                client_id,
                client_secret,
                redirect_uri,
                scopes,
                username_claim,
            })
        } else {
            let user_secret_key = lookup("GOLINKS_USER_SECRET_KEY")
                .filter(|v| !v.is_empty())
                .ok_or_else(|| "GOLINKS_USER_SECRET_KEY must be set and non-empty".to_string())?;

            let username = match lookup("GOLINKS_USERNAME") {
                Some(raw) => {
                    let trimmed = raw.trim();
                    if trimmed.is_empty() {
                        return Err("GOLINKS_USERNAME must not be empty".to_string());
                    }
                    if trimmed.chars().count() > MAX_USERNAME_CHARS {
                        return Err(format!(
                            "GOLINKS_USERNAME must be at most {MAX_USERNAME_CHARS} characters"
                        ));
                    }
                    trimmed.to_string()
                }
                None => DEFAULT_USERNAME.to_string(),
            };

            AuthConfig::SingleUser {
                username,
                user_secret_key,
            }
        };

        let engine = match lookup("GOLINKS_DB_ENGINE") {
            Some(raw) => DbEngine::parse(&raw)?,
            None => DbEngine::Sqlite,
        };

        let db = match engine {
            DbEngine::Sqlite => {
                let path = optional_non_empty_trimmed(&lookup, "GOLINKS_DB_PATH")?
                    .unwrap_or_else(|| DEFAULT_SQLITE_PATH.to_string());
                DbConfig::Sqlite { path }
            }
            DbEngine::Postgresql => {
                let host = require_non_empty_trimmed(&lookup, "GOLINKS_DB_HOST")?;
                let port = match lookup("GOLINKS_DB_PORT") {
                    Some(raw) => {
                        let parsed = raw.trim().parse::<u16>().map_err(|err| {
                            format!("invalid GOLINKS_DB_PORT '{raw}': {err}")
                        })?;
                        if parsed == 0 {
                            return Err("GOLINKS_DB_PORT must be between 1 and 65535".to_string());
                        }
                        parsed
                    }
                    None => DEFAULT_POSTGRES_PORT,
                };
                let database = require_non_empty_trimmed(&lookup, "GOLINKS_DB_NAME")?;
                let username = require_non_empty_trimmed(&lookup, "GOLINKS_DB_USERNAME")?;
                let password = lookup("GOLINKS_DB_PASSWORD").ok_or_else(|| {
                    "GOLINKS_DB_PASSWORD must be set when GOLINKS_DB_ENGINE=postgresql".to_string()
                })?;

                DbConfig::Postgresql {
                    host,
                    port,
                    database,
                    username,
                    password,
                }
            }
        };

        Ok(Self {
            auth,
            session_ttl_days,
            db,
        })
    }
}

fn require_http_url<F>(lookup: &F, key: &str) -> Result<String, String>
where
    F: Fn(&str) -> Option<String>,
{
    let val = require_non_empty_trimmed(lookup, key)?;
    if !(val.starts_with("http://") || val.starts_with("https://")) {
        return Err(format!("{key} must start with http:// or https://"));
    }
    Ok(val)
}

fn require_non_empty_trimmed<F>(lookup: &F, key: &str) -> Result<String, String>
where
    F: Fn(&str) -> Option<String>,
{
    optional_non_empty_trimmed(lookup, key)?
        .ok_or_else(|| format!("{key} must be set and non-empty"))
}

fn optional_non_empty_trimmed<F>(lookup: &F, key: &str) -> Result<Option<String>, String>
where
    F: Fn(&str) -> Option<String>,
{
    match lookup(key) {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(format!("{key} must not be empty"));
            }
            Ok(Some(trimmed.to_string()))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn parse(vars: &[(&str, &str)]) -> Result<AppConfig, String> {
        let map: HashMap<&str, &str> = vars.iter().copied().collect();
        AppConfig::from_lookup(|k| map.get(k).map(|v| (*v).to_string()))
    }

    #[test]
    fn sqlite_defaults_work_with_only_secret_key() {
        let cfg = parse(&[("GOLINKS_USER_SECRET_KEY", "super-secret")]).unwrap();
        assert_eq!(
            cfg.auth,
            AuthConfig::SingleUser {
                username: "golinks".to_string(),
                user_secret_key: "super-secret".to_string(),
            }
        );
        assert_eq!(cfg.session_ttl_days, 30);
        assert_eq!(cfg.db, DbConfig::Sqlite { path: "./golinks.db".to_string() });
    }

    #[test]
    fn requires_non_empty_secret_key_and_valid_username() {
        assert!(parse(&[]).is_err());
        assert!(parse(&[("GOLINKS_USER_SECRET_KEY", "")]).is_err());
        assert!(parse(&[
            ("GOLINKS_USER_SECRET_KEY", "ok"),
            ("GOLINKS_USERNAME", "   "),
        ]).is_err());
        assert!(parse(&[
            ("GOLINKS_USER_SECRET_KEY", "ok"),
            ("GOLINKS_USERNAME", &"a".repeat(256)),
        ]).is_err());
        let ok = parse(&[
            ("GOLINKS_USER_SECRET_KEY", "ok"),
            ("GOLINKS_USERNAME", &"é".repeat(255)),
        ]).unwrap();
        match ok.auth {
            AuthConfig::SingleUser { username, .. } => assert_eq!(username.chars().count(), 255),
            _ => panic!("expected SingleUser"),
        }
    }

    #[test]
    fn session_ttl_days_defaults_to_30_and_validates_bounds() {
        let default_cfg = parse(&[("GOLINKS_USER_SECRET_KEY", "ok")]).unwrap();
        assert_eq!(default_cfg.session_ttl_days, 30);

        let custom = parse(&[
            ("GOLINKS_USER_SECRET_KEY", "ok"),
            ("GOLINKS_SESSION_TTL_DAYS", " 7 "),
        ]).unwrap();
        assert_eq!(custom.session_ttl_days, 7);

        for invalid in ["0", "3651", "-1", "abc", "   "] {
            assert!(
                parse(&[
                    ("GOLINKS_USER_SECRET_KEY", "ok"),
                    ("GOLINKS_SESSION_TTL_DAYS", invalid),
                ])
                .is_err(),
                "expected error for GOLINKS_SESSION_TTL_DAYS='{invalid}'"
            );
        }
    }

    #[test]
    fn oidc_enabled_ignores_single_user_vars_and_uses_defaults() {
        let cfg = parse(&[
            ("GOLINKS_OIDC_ENABLED", "true"),
            ("GOLINKS_OIDC_ISSUER_URL", "https://auth.example.com/application/o/golinks/"),
            ("GOLINKS_OIDC_CLIENT_ID", "golinks-client"),
            ("GOLINKS_OIDC_CLIENT_SECRET", "oidc-secret"),
            ("GOLINKS_OIDC_REDIRECT_URI", "https://go.example.com/"),
        ])
        .unwrap();

        assert_eq!(cfg.session_ttl_days, 30);
        assert_eq!(
            cfg.auth,
            AuthConfig::Oidc(OidcConfig {
                issuer_url: "https://auth.example.com/application/o/golinks/".to_string(),
                client_id: "golinks-client".to_string(),
                client_secret: "oidc-secret".to_string(),
                redirect_uri: "https://go.example.com/".to_string(),
                scopes: vec![
                    "openid".to_string(),
                    "profile".to_string(),
                    "email".to_string(),
                ],
                username_claim: "preferred_username".to_string(),
            })
        );
    }

    #[test]
    fn oidc_enabled_requires_all_mandatory_vars_and_valid_urls() {
        let base = vec![
            ("GOLINKS_OIDC_ENABLED", "true"),
            ("GOLINKS_OIDC_ISSUER_URL", "https://auth.example.com/application/o/golinks/"),
            ("GOLINKS_OIDC_CLIENT_ID", "golinks-client"),
            ("GOLINKS_OIDC_CLIENT_SECRET", "oidc-secret"),
            ("GOLINKS_OIDC_REDIRECT_URI", "https://go.example.com/"),
        ];

        for missing in [
            "GOLINKS_OIDC_ISSUER_URL",
            "GOLINKS_OIDC_CLIENT_ID",
            "GOLINKS_OIDC_CLIENT_SECRET",
            "GOLINKS_OIDC_REDIRECT_URI",
        ] {
            let mut vars = base.clone();
            vars.retain(|(k, _)| *k != missing);
            assert!(parse(&vars).is_err(), "expected error when {missing} missing");
        }

        // Non-http(s) URLs rejected
        let mut bad_issuer = base.clone();
        bad_issuer[1] = ("GOLINKS_OIDC_ISSUER_URL", "ftp://auth.example.com");
        assert!(parse(&bad_issuer).is_err());

        let mut bad_redirect = base.clone();
        bad_redirect[4] = ("GOLINKS_OIDC_REDIRECT_URI", "/callback");
        assert!(parse(&bad_redirect).is_err());

        // Custom scopes always ensure "openid" is included; custom username claim works
        let mut custom = base.clone();
        custom.push(("GOLINKS_OIDC_SCOPES", "profile groups"));
        custom.push(("GOLINKS_OIDC_USERNAME_CLAIM", "email"));
        let cfg = parse(&custom).unwrap();
        match cfg.auth {
            AuthConfig::Oidc(oidc) => {
                assert_eq!(oidc.scopes, vec!["openid", "profile", "groups"]);
                assert_eq!(oidc.username_claim, "email");
            }
            _ => panic!("expected Oidc"),
        }

        // Invalid boolean for GOLINKS_OIDC_ENABLED fails
        assert!(parse(&[
            ("GOLINKS_OIDC_ENABLED", "maybe"),
            ("GOLINKS_USER_SECRET_KEY", "ok"),
        ])
        .is_err());
    }

    #[test]
    fn rejects_unknown_db_engine() {
        assert!(parse(&[
            ("GOLINKS_USER_SECRET_KEY", "ok"),
            ("GOLINKS_DB_ENGINE", "mysql"),
        ]).is_err());
    }

    #[test]
    fn postgresql_config_requires_vars_and_allows_empty_password_when_set() {
        // Missing password fails
        assert!(parse(&[
            ("GOLINKS_USER_SECRET_KEY", "ok"),
            ("GOLINKS_DB_ENGINE", "PostgreSQL"),
            ("GOLINKS_DB_HOST", "db.example.com"),
            ("GOLINKS_DB_NAME", "golinks"),
            ("GOLINKS_DB_USERNAME", "app"),
        ]).is_err());

        // Explicitly empty password succeeds and port defaults to 5432
        let cfg = parse(&[
            ("GOLINKS_USER_SECRET_KEY", "ok"),
            ("GOLINKS_DB_ENGINE", " postgresql "),
            ("GOLINKS_DB_HOST", "db.example.com"),
            ("GOLINKS_DB_NAME", "golinks"),
            ("GOLINKS_DB_USERNAME", "app"),
            ("GOLINKS_DB_PASSWORD", ""),
        ]).unwrap();
        assert_eq!(
            cfg.db,
            DbConfig::Postgresql {
                host: "db.example.com".to_string(),
                port: 5432,
                database: "golinks".to_string(),
                username: "app".to_string(),
                password: "".to_string(),
            }
        );

        // Invalid port fails
        assert!(parse(&[
            ("GOLINKS_USER_SECRET_KEY", "ok"),
            ("GOLINKS_DB_ENGINE", "postgresql"),
            ("GOLINKS_DB_HOST", "db.example.com"),
            ("GOLINKS_DB_PORT", "not-a-port"),
            ("GOLINKS_DB_NAME", "golinks"),
            ("GOLINKS_DB_USERNAME", "app"),
            ("GOLINKS_DB_PASSWORD", "pw"),
        ]).is_err());

        // Port 0 fails
        let zero_port_err = parse(&[
            ("GOLINKS_USER_SECRET_KEY", "ok"),
            ("GOLINKS_DB_ENGINE", "postgresql"),
            ("GOLINKS_DB_HOST", "db.example.com"),
            ("GOLINKS_DB_PORT", "0"),
            ("GOLINKS_DB_NAME", "golinks"),
            ("GOLINKS_DB_USERNAME", "app"),
            ("GOLINKS_DB_PASSWORD", "pw"),
        ])
        .unwrap_err();
        assert!(
            zero_port_err.contains("GOLINKS_DB_PORT"),
            "unexpected error for port 0: {zero_port_err}"
        );
    }

    #[test]
    fn sqlite_custom_path_and_secret_preserves_whitespace() {
        let cfg = parse(&[
            ("GOLINKS_USER_SECRET_KEY", "  raw secret  "),
            ("GOLINKS_USERNAME", "  alice  "),
            ("GOLINKS_DB_ENGINE", "SQLITE"),
            ("GOLINKS_DB_PATH", " /var/lib/golinks/data.db "),
        ]).unwrap();
        match cfg.auth {
            AuthConfig::SingleUser {
                username,
                user_secret_key,
            } => {
                assert_eq!(user_secret_key, "  raw secret  ");
                assert_eq!(username, "alice");
            }
            _ => panic!("expected SingleUser"),
        }
        assert_eq!(
            cfg.db,
            DbConfig::Sqlite {
                path: "/var/lib/golinks/data.db".to_string(),
            }
        );

        assert!(parse(&[
            ("GOLINKS_USER_SECRET_KEY", "ok"),
            ("GOLINKS_DB_PATH", "   "),
        ]).is_err());
    }

    #[test]
    fn postgresql_custom_port_and_missing_required_fields() {
        let cfg = parse(&[
            ("GOLINKS_USER_SECRET_KEY", "ok"),
            ("GOLINKS_DB_ENGINE", "postgresql"),
            ("GOLINKS_DB_HOST", " db.example.com "),
            ("GOLINKS_DB_PORT", " 6432 "),
            ("GOLINKS_DB_NAME", " golinks_db "),
            ("GOLINKS_DB_USERNAME", " app_user "),
            ("GOLINKS_DB_PASSWORD", " secret "),
        ]).unwrap();
        assert_eq!(
            cfg.db,
            DbConfig::Postgresql {
                host: "db.example.com".to_string(),
                port: 6432,
                database: "golinks_db".to_string(),
                username: "app_user".to_string(),
                password: " secret ".to_string(),
            }
        );

        for missing in ["GOLINKS_DB_HOST", "GOLINKS_DB_NAME", "GOLINKS_DB_USERNAME"] {
            let mut vars = vec![
                ("GOLINKS_USER_SECRET_KEY", "ok"),
                ("GOLINKS_DB_ENGINE", "postgresql"),
                ("GOLINKS_DB_HOST", "db.example.com"),
                ("GOLINKS_DB_NAME", "golinks"),
                ("GOLINKS_DB_USERNAME", "app"),
                ("GOLINKS_DB_PASSWORD", "pw"),
            ];
            vars.retain(|(k, _)| *k != missing);
            assert!(parse(&vars).is_err(), "expected error when {missing} is missing");
        }
    }
}
