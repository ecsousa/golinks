const DEFAULT_USERNAME: &str = "golinks";
const MAX_USERNAME_CHARS: usize = 32;
const DEFAULT_SQLITE_PATH: &str = "./golinks.db";
const DEFAULT_POSTGRES_PORT: u16 = 5432;

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

/// Parsed application configuration from environment variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppConfig {
    pub username: String,
    pub user_secret_key: String,
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
                    Some(raw) => raw.trim().parse::<u16>().map_err(|err| {
                        format!("invalid GOLINKS_DB_PORT '{raw}': {err}")
                    })?,
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
            username,
            user_secret_key,
            db,
        })
    }
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
        assert_eq!(cfg.username, "golinks");
        assert_eq!(cfg.user_secret_key, "super-secret");
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
            ("GOLINKS_USERNAME", &"a".repeat(33)),
        ]).is_err());
        let ok = parse(&[
            ("GOLINKS_USER_SECRET_KEY", "ok"),
            ("GOLINKS_USERNAME", &"é".repeat(32)),
        ]).unwrap();
        assert_eq!(ok.username.chars().count(), 32);
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
    }

    #[test]
    fn sqlite_custom_path_and_secret_preserves_whitespace() {
        let cfg = parse(&[
            ("GOLINKS_USER_SECRET_KEY", "  raw secret  "),
            ("GOLINKS_USERNAME", "  alice  "),
            ("GOLINKS_DB_ENGINE", "SQLITE"),
            ("GOLINKS_DB_PATH", " /var/lib/golinks/data.db "),
        ]).unwrap();
        assert_eq!(cfg.user_secret_key, "  raw secret  ");
        assert_eq!(cfg.username, "alice");
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
