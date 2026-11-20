pub mod config;
pub mod migrations;

use std::fmt;
use std::path::Path;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{PgPool, SqlitePool};

use crate::db::config::DbConfig;

/// Database and migration error type.
#[derive(Debug)]
#[allow(dead_code)]
pub enum DbError {
    Sqlx(sqlx::Error),
    Migration(String),
    Config(String),
    Io(String),
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlx(err) => write!(f, "database error: {err}"),
            Self::Migration(msg) => write!(f, "migration error: {msg}"),
            Self::Config(msg) => write!(f, "database config error: {msg}"),
            Self::Io(msg) => write!(f, "database I/O error: {msg}"),
        }
    }
}

impl std::error::Error for DbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlx(err) => Some(err),
            Self::Migration(_) | Self::Config(_) | Self::Io(_) => None,
        }
    }
}

impl From<sqlx::Error> for DbError {
    fn from(err: sqlx::Error) -> Self {
        Self::Sqlx(err)
    }
}

#[derive(Clone)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum Backend {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

/// Active database connection pool wrapper supporting SQLite and PostgreSQL.
#[derive(Clone)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct Database {
    pub(crate) backend: Backend,
}

#[cfg_attr(not(test), allow(dead_code))]
impl Database {
    /// Connects to the configured database backend.
    pub async fn connect(config: &DbConfig) -> Result<Self, DbError> {
        match config {
            DbConfig::Sqlite { path } => {
                let is_memory = path == ":memory:";
                if !is_memory {
                    if let Some(parent) = Path::new(path).parent() {
                        if !parent.as_os_str().is_empty() {
                            std::fs::create_dir_all(parent).map_err(|err| {
                                DbError::Io(format!(
                                    "failed to create sqlite directory '{}': {err}",
                                    parent.display()
                                ))
                            })?;
                        }
                    }
                }

                let mut options = SqliteConnectOptions::new()
                    .filename(path)
                    .create_if_missing(true)
                    .foreign_keys(true);
                if !is_memory {
                    options = options.journal_mode(SqliteJournalMode::Wal);
                }

                let max_connections = if is_memory { 1 } else { 5 };
                let pool = SqlitePoolOptions::new()
                    .max_connections(max_connections)
                    .connect_with(options)
                    .await?;

                Ok(Self {
                    backend: Backend::Sqlite(pool),
                })
            }
            DbConfig::Postgresql {
                host,
                port,
                database,
                username,
                password,
            } => {
                let options = PgConnectOptions::new()
                    .host(host)
                    .port(*port)
                    .database(database)
                    .username(username)
                    .password(password)
                    .options([("search_path", "golinks")]);

                let pool = PgPoolOptions::new()
                    .max_connections(10)
                    .connect_with(options)
                    .await?;

                Ok(Self {
                    backend: Backend::Postgres(pool),
                })
            }
        }
    }

    /// Runs embedded schema initialization or incremental migrations for the active backend.
    pub async fn run_migrations(&self) -> Result<(), DbError> {
        match &self.backend {
            Backend::Sqlite(pool) => {
                migrations::run_sqlite_migrations(pool, &migrations::embedded_sqlite_spec()).await
            }
            Backend::Postgres(pool) => {
                migrations::run_postgres_migrations(pool, &migrations::embedded_postgres_spec())
                    .await
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn sqlite_pool(&self) -> &SqlitePool {
        match &self.backend {
            Backend::Sqlite(pool) => pool,
            Backend::Postgres(_) => panic!("expected SQLite backend"),
        }
    }
}
