pub mod config;
pub mod migrations;

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{PgPool, SqlitePool};

use crate::auth;
use crate::db::config::DbConfig;

/// Database and migration error type.
#[derive(Debug)]
pub enum DbError {
    Sqlx(sqlx::Error),
    Migration(String),
    Io(String),
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlx(err) => write!(f, "database error: {err}"),
            Self::Migration(msg) => write!(f, "migration error: {msg}"),
            Self::Io(msg) => write!(f, "database I/O error: {msg}"),
        }
    }
}

impl std::error::Error for DbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlx(err) => Some(err),
            Self::Migration(_) | Self::Io(_) => None,
        }
    }
}

impl From<sqlx::Error> for DbError {
    fn from(err: sqlx::Error) -> Self {
        Self::Sqlx(err)
    }
}

/// User record stored in the `users` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub user_id: i32,
    #[cfg_attr(not(test), allow(dead_code))]
    pub user_name: String,
    pub user_secret: String,
}

fn user_from_row((user_id, user_name, user_secret): (i32, String, String)) -> User {
    User {
        user_id,
        user_name,
        user_secret,
    }
}

#[derive(Clone)]
pub(crate) enum Backend {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

/// Active database connection pool wrapper supporting SQLite and PostgreSQL.
#[derive(Clone)]
pub struct Database {
    pub(crate) backend: Backend,
}

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

    /// Creates a user if absent, or updates `user_secret` if it changed.
    pub async fn sync_user(&self, user_name: &str, user_secret: &str) -> Result<User, DbError> {
        let existing = match self.get_user_by_name(user_name).await? {
            Some(user) => user,
            None => {
                let inserted = match &self.backend {
                    Backend::Sqlite(pool) => {
                        sqlx::query_as::<_, (i32, String, String)>(
                            "INSERT INTO users (user_name, user_secret) VALUES (?, ?) \
                             ON CONFLICT (user_name) DO NOTHING \
                             RETURNING user_id, user_name, user_secret",
                        )
                        .bind(user_name)
                        .bind(user_secret)
                        .fetch_optional(pool)
                        .await?
                    }
                    Backend::Postgres(pool) => {
                        sqlx::query_as::<_, (i32, String, String)>(
                            "INSERT INTO users (user_name, user_secret) VALUES ($1, $2) \
                             ON CONFLICT (user_name) DO NOTHING \
                             RETURNING user_id, user_name, user_secret",
                        )
                        .bind(user_name)
                        .bind(user_secret)
                        .fetch_optional(pool)
                        .await?
                    }
                };
                if let Some(row) = inserted {
                    return Ok(user_from_row(row));
                }
                self.get_user_by_name(user_name)
                    .await?
                    .ok_or_else(|| DbError::Sqlx(sqlx::Error::RowNotFound))?
            }
        };

        if auth::constant_time_eq(&existing.user_secret, user_secret) {
            return Ok(existing);
        }

        let row = match &self.backend {
            Backend::Sqlite(pool) => {
                sqlx::query_as::<_, (i32, String, String)>(
                    "UPDATE users SET user_secret = ?, updated_on = CURRENT_TIMESTAMP \
                     WHERE user_id = ? \
                     RETURNING user_id, user_name, user_secret",
                )
                .bind(user_secret)
                .bind(existing.user_id)
                .fetch_one(pool)
                .await?
            }
            Backend::Postgres(pool) => {
                sqlx::query_as::<_, (i32, String, String)>(
                    "UPDATE users SET user_secret = $1, updated_on = CURRENT_TIMESTAMP \
                     WHERE user_id = $2 \
                     RETURNING user_id, user_name, user_secret",
                )
                .bind(user_secret)
                .bind(existing.user_id)
                .fetch_one(pool)
                .await?
            }
        };
        Ok(user_from_row(row))
    }

    /// Returns an existing user (preserving any non-empty `user_secret`), rotates `user_secret`
    /// if the existing row has an empty secret, or creates a new user with `new_secret`.
    pub async fn get_or_create_user(
        &self,
        user_name: &str,
        new_secret: &str,
    ) -> Result<User, DbError> {
        let existing = match self.get_user_by_name(user_name).await? {
            Some(user) => user,
            None => {
                let inserted = match &self.backend {
                    Backend::Sqlite(pool) => {
                        sqlx::query_as::<_, (i32, String, String)>(
                            "INSERT INTO users (user_name, user_secret) VALUES (?, ?) \
                             ON CONFLICT (user_name) DO NOTHING \
                             RETURNING user_id, user_name, user_secret",
                        )
                        .bind(user_name)
                        .bind(new_secret)
                        .fetch_optional(pool)
                        .await?
                    }
                    Backend::Postgres(pool) => {
                        sqlx::query_as::<_, (i32, String, String)>(
                            "INSERT INTO users (user_name, user_secret) VALUES ($1, $2) \
                             ON CONFLICT (user_name) DO NOTHING \
                             RETURNING user_id, user_name, user_secret",
                        )
                        .bind(user_name)
                        .bind(new_secret)
                        .fetch_optional(pool)
                        .await?
                    }
                };
                if let Some(row) = inserted {
                    return Ok(user_from_row(row));
                }
                self.get_user_by_name(user_name)
                    .await?
                    .ok_or_else(|| DbError::Sqlx(sqlx::Error::RowNotFound))?
            }
        };

        if !existing.user_secret.trim().is_empty() {
            return Ok(existing);
        }

        let updated = match &self.backend {
            Backend::Sqlite(pool) => {
                sqlx::query_as::<_, (i32, String, String)>(
                    "UPDATE users SET user_secret = ?, updated_on = CURRENT_TIMESTAMP \
                     WHERE user_id = ? AND TRIM(user_secret) = '' \
                     RETURNING user_id, user_name, user_secret",
                )
                .bind(new_secret)
                .bind(existing.user_id)
                .fetch_optional(pool)
                .await?
            }
            Backend::Postgres(pool) => {
                sqlx::query_as::<_, (i32, String, String)>(
                    "UPDATE users SET user_secret = $1, updated_on = CURRENT_TIMESTAMP \
                     WHERE user_id = $2 AND TRIM(user_secret) = '' \
                     RETURNING user_id, user_name, user_secret",
                )
                .bind(new_secret)
                .bind(existing.user_id)
                .fetch_optional(pool)
                .await?
            }
        };
        if let Some(row) = updated {
            return Ok(user_from_row(row));
        }

        self.get_user_by_id(existing.user_id)
            .await?
            .ok_or_else(|| DbError::Sqlx(sqlx::Error::RowNotFound))
    }

    /// Fetches a user by primary key `user_id`.
    pub async fn get_user_by_id(&self, user_id: i32) -> Result<Option<User>, DbError> {
        let row = match &self.backend {
            Backend::Sqlite(pool) => {
                sqlx::query_as::<_, (i32, String, String)>(
                    "SELECT user_id, user_name, user_secret FROM users WHERE user_id = ?",
                )
                .bind(user_id)
                .fetch_optional(pool)
                .await?
            }
            Backend::Postgres(pool) => {
                sqlx::query_as::<_, (i32, String, String)>(
                    "SELECT user_id, user_name, user_secret FROM users WHERE user_id = $1",
                )
                .bind(user_id)
                .fetch_optional(pool)
                .await?
            }
        };
        Ok(row.map(user_from_row))
    }

    /// Fetches a user by unique `user_name`.
    pub async fn get_user_by_name(&self, user_name: &str) -> Result<Option<User>, DbError> {
        let row = match &self.backend {
            Backend::Sqlite(pool) => {
                sqlx::query_as::<_, (i32, String, String)>(
                    "SELECT user_id, user_name, user_secret FROM users WHERE user_name = ?",
                )
                .bind(user_name)
                .fetch_optional(pool)
                .await?
            }
            Backend::Postgres(pool) => {
                sqlx::query_as::<_, (i32, String, String)>(
                    "SELECT user_id, user_name, user_secret FROM users WHERE user_name = $1",
                )
                .bind(user_name)
                .fetch_optional(pool)
                .await?
            }
        };
        Ok(row.map(user_from_row))
    }

    /// Lists all links belonging to `user_id`, ordered by keyword.
    pub async fn list_links(&self, user_id: i32) -> Result<BTreeMap<String, String>, DbError> {
        let rows = match &self.backend {
            Backend::Sqlite(pool) => {
                sqlx::query_as::<_, (String, String)>(
                    "SELECT link_keyword, link_target FROM links \
                     WHERE user_id = ? ORDER BY link_keyword ASC",
                )
                .bind(user_id)
                .fetch_all(pool)
                .await?
            }
            Backend::Postgres(pool) => {
                sqlx::query_as::<_, (String, String)>(
                    "SELECT link_keyword, link_target FROM links \
                     WHERE user_id = $1 ORDER BY link_keyword ASC",
                )
                .bind(user_id)
                .fetch_all(pool)
                .await?
            }
        };
        Ok(rows.into_iter().collect())
    }

    /// Looks up a single link target for `user_id` and `keyword`.
    pub async fn get_link_target(
        &self,
        user_id: i32,
        keyword: &str,
    ) -> Result<Option<String>, DbError> {
        let target = match &self.backend {
            Backend::Sqlite(pool) => {
                sqlx::query_scalar::<_, String>(
                    "SELECT link_target FROM links WHERE user_id = ? AND link_keyword = ?",
                )
                .bind(user_id)
                .bind(keyword)
                .fetch_optional(pool)
                .await?
            }
            Backend::Postgres(pool) => {
                sqlx::query_scalar::<_, String>(
                    "SELECT link_target FROM links WHERE user_id = $1 AND link_keyword = $2",
                )
                .bind(user_id)
                .bind(keyword)
                .fetch_optional(pool)
                .await?
            }
        };
        Ok(target)
    }

    /// Atomically creates, updates, or renames a link for `user_id`, returning the updated map.
    pub async fn save_link(
        &self,
        user_id: i32,
        original_key: Option<&str>,
        key: &str,
        target: &str,
    ) -> Result<BTreeMap<String, String>, DbError> {
        let rename_from = original_key
            .map(str::trim)
            .filter(|orig| !orig.is_empty() && *orig != key);

        match &self.backend {
            Backend::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                if let Some(orig) = rename_from {
                    sqlx::query("DELETE FROM links WHERE user_id = ? AND link_keyword = ?")
                        .bind(user_id)
                        .bind(orig)
                        .execute(&mut *tx)
                        .await?;
                }
                sqlx::query(
                    "INSERT INTO links (user_id, link_keyword, link_target) VALUES (?, ?, ?) \
                     ON CONFLICT (user_id, link_keyword) \
                     DO UPDATE SET link_target = EXCLUDED.link_target, updated_on = CURRENT_TIMESTAMP",
                )
                .bind(user_id)
                .bind(key)
                .bind(target)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
            }
            Backend::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                if let Some(orig) = rename_from {
                    sqlx::query("DELETE FROM links WHERE user_id = $1 AND link_keyword = $2")
                        .bind(user_id)
                        .bind(orig)
                        .execute(&mut *tx)
                        .await?;
                }
                sqlx::query(
                    "INSERT INTO links (user_id, link_keyword, link_target) VALUES ($1, $2, $3) \
                     ON CONFLICT (user_id, link_keyword) \
                     DO UPDATE SET link_target = EXCLUDED.link_target, updated_on = CURRENT_TIMESTAMP",
                )
                .bind(user_id)
                .bind(key)
                .bind(target)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
            }
        }

        self.list_links(user_id).await
    }

    /// Deletes a link for `user_id` by `keyword`, returning `None` if no row was deleted.
    pub async fn delete_link(
        &self,
        user_id: i32,
        keyword: &str,
    ) -> Result<Option<BTreeMap<String, String>>, DbError> {
        let rows_affected = match &self.backend {
            Backend::Sqlite(pool) => {
                sqlx::query("DELETE FROM links WHERE user_id = ? AND link_keyword = ?")
                    .bind(user_id)
                    .bind(keyword)
                    .execute(pool)
                    .await?
                    .rows_affected()
            }
            Backend::Postgres(pool) => {
                sqlx::query("DELETE FROM links WHERE user_id = $1 AND link_keyword = $2")
                    .bind(user_id)
                    .bind(keyword)
                    .execute(pool)
                    .await?
                    .rows_affected()
            }
        };

        if rows_affected == 0 {
            return Ok(None);
        }

        Ok(Some(self.list_links(user_id).await?))
    }

    #[cfg(test)]
    pub(crate) fn sqlite_pool(&self) -> &SqlitePool {
        match &self.backend {
            Backend::Sqlite(pool) => pool,
            Backend::Postgres(_) => panic!("expected SQLite backend"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::auth::derive_auth_token;

    async fn setup_memory_db() -> Database {
        let db = Database::connect(&DbConfig::Sqlite {
            path: ":memory:".to_string(),
        })
        .await
        .expect("connect to in-memory sqlite");
        db.run_migrations().await.expect("run migrations");
        db
    }

    #[tokio::test]
    async fn sync_user_creates_preserves_and_updates_secret() {
        let db = setup_memory_db().await;
        let secret1 = derive_auth_token("initial-secret");
        let secret2 = derive_auth_token("rotated-secret");

        let created = db
            .sync_user("golinks", &secret1)
            .await
            .expect("create user");
        assert!(created.user_id > 0);
        assert_eq!(created.user_name, "golinks");
        assert_eq!(created.user_secret, secret1);

        let preserved = db
            .sync_user("golinks", &secret1)
            .await
            .expect("preserve user");
        assert_eq!(preserved, created);

        let updated = db
            .sync_user("golinks", &secret2)
            .await
            .expect("update user secret");
        assert_eq!(updated.user_id, created.user_id);
        assert_eq!(updated.user_name, "golinks");
        assert_eq!(updated.user_secret, secret2);

        let by_id = db
            .get_user_by_id(created.user_id)
            .await
            .expect("get_user_by_id");
        assert_eq!(by_id, Some(updated.clone()));

        let by_name = db
            .get_user_by_name("golinks")
            .await
            .expect("get_user_by_name");
        assert_eq!(by_name, Some(updated));

        assert_eq!(
            db.get_user_by_id(created.user_id + 999)
                .await
                .expect("missing user by id"),
            None
        );
        assert_eq!(
            db.get_user_by_name("nobody")
                .await
                .expect("missing user by name"),
            None
        );
    }

    #[tokio::test]
    async fn sync_user_handles_concurrent_startup_insert() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let db_path = dir.path().join("concurrent_sync_user.db");
        let db = Database::connect(&DbConfig::Sqlite {
            path: db_path.to_string_lossy().into_owned(),
        })
        .await
        .expect("connect to file-backed sqlite");
        db.run_migrations().await.expect("run migrations");

        let secret = derive_auth_token("concurrent-secret");
        let (r1, r2, r3, r4) = tokio::join!(
            db.sync_user("golinks", &secret),
            db.sync_user("golinks", &secret),
            db.sync_user("golinks", &secret),
            db.sync_user("golinks", &secret),
        );

        let u1 = r1.expect("concurrent sync_user 1");
        let u2 = r2.expect("concurrent sync_user 2");
        let u3 = r3.expect("concurrent sync_user 3");
        let u4 = r4.expect("concurrent sync_user 4");

        assert!(u1.user_id > 0);
        assert_eq!(u1, u2);
        assert_eq!(u1, u3);
        assert_eq!(u1, u4);
        assert_eq!(u1.user_name, "golinks");
        assert_eq!(u1.user_secret, secret);

        let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE user_name = ?")
            .bind("golinks")
            .fetch_one(db.sqlite_pool())
            .await
            .expect("count users");
        assert_eq!(user_count, 1);
    }

    #[tokio::test]
    async fn get_or_create_user_preserves_secret_rotates_empty_supports_255_chars_and_concurrency() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let db_path = dir.path().join("get_or_create_user.db");
        let db = Database::connect(&DbConfig::Sqlite {
            path: db_path.to_string_lossy().into_owned(),
        })
        .await
        .expect("connect to sqlite");
        db.run_migrations().await.expect("run migrations");

        let long_name = "u".repeat(255);
        let secret_a = "a".repeat(64);
        let secret_b = "b".repeat(64);
        let secret_c = "c".repeat(64);

        let created = db
            .get_or_create_user(&long_name, &secret_a)
            .await
            .expect("create 255-char user");
        assert_eq!(created.user_name, long_name);
        assert_eq!(created.user_secret, secret_a);

        // Existing non-empty secret must be preserved.
        let preserved = db
            .get_or_create_user(&long_name, &secret_b)
            .await
            .expect("preserve existing secret");
        assert_eq!(preserved, created);

        // Clearing user_secret to empty forces rotation on next login.
        sqlx::query("UPDATE users SET user_secret = '' WHERE user_id = ?")
            .bind(created.user_id)
            .execute(db.sqlite_pool())
            .await
            .expect("clear user_secret");
        let rotated = db
            .get_or_create_user(&long_name, &secret_c)
            .await
            .expect("rotate empty secret");
        assert_eq!(rotated.user_id, created.user_id);
        assert_eq!(rotated.user_secret, secret_c);

        // Concurrent first-time creation must converge on a single row and secret.
        let s1 = "1".repeat(64);
        let s2 = "2".repeat(64);
        let s3 = "3".repeat(64);
        let s4 = "4".repeat(64);
        let (r1, r2, r3, r4) = tokio::join!(
            db.get_or_create_user("alice", &s1),
            db.get_or_create_user("alice", &s2),
            db.get_or_create_user("alice", &s3),
            db.get_or_create_user("alice", &s4),
        );
        let u1 = r1.expect("concurrent get_or_create 1");
        let u2 = r2.expect("concurrent get_or_create 2");
        let u3 = r3.expect("concurrent get_or_create 3");
        let u4 = r4.expect("concurrent get_or_create 4");
        assert_eq!(u1, u2);
        assert_eq!(u1, u3);
        assert_eq!(u1, u4);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE user_name = ?")
            .bind("alice")
            .fetch_one(db.sqlite_pool())
            .await
            .expect("count alice");
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn save_rename_overwrite_and_delete_links() {
        let db = setup_memory_db().await;
        let secret = derive_auth_token("test-secret");
        let user = db.sync_user("golinks", &secret).await.expect("sync user");
        let uid = user.user_id;

        let links = db
            .save_link(uid, None, "docs", "https://docs.example.com")
            .await
            .expect("insert docs");
        assert_eq!(
            links,
            BTreeMap::from([("docs".to_string(), "https://docs.example.com".to_string())])
        );

        let links = db
            .save_link(uid, None, "gh", "https://github.com/%s")
            .await
            .expect("insert gh");
        assert_eq!(
            links,
            BTreeMap::from([
                ("docs".to_string(), "https://docs.example.com".to_string()),
                ("gh".to_string(), "https://github.com/%s".to_string()),
            ])
        );

        // Rename "gh" onto existing key "docs" atomically removes "gh" and overwrites "docs".
        let links = db
            .save_link(uid, Some("gh"), "docs", "https://new-docs.example.com")
            .await
            .expect("rename gh onto docs");
        assert_eq!(
            links,
            BTreeMap::from([(
                "docs".to_string(),
                "https://new-docs.example.com".to_string()
            )])
        );

        assert_eq!(
            db.get_link_target(uid, "docs")
                .await
                .expect("get docs target"),
            Some("https://new-docs.example.com".to_string())
        );
        assert_eq!(
            db.get_link_target(uid, "gh").await.expect("get gh target"),
            None
        );

        assert_eq!(
            db.delete_link(uid, "missing")
                .await
                .expect("delete missing"),
            None
        );

        assert_eq!(
            db.delete_link(uid, "docs").await.expect("delete docs"),
            Some(BTreeMap::new())
        );
        assert_eq!(db.list_links(uid).await.expect("list empty"), BTreeMap::new());
    }

    #[tokio::test]
    async fn multi_user_link_isolation() {
        let db = setup_memory_db().await;
        let alice = db
            .sync_user("alice", &derive_auth_token("alice-secret"))
            .await
            .expect("sync alice");
        let bob = db
            .sync_user("bob", &derive_auth_token("bob-secret"))
            .await
            .expect("sync bob");
        assert_ne!(alice.user_id, bob.user_id);

        db.save_link(alice.user_id, None, "docs", "https://alice.example.com/docs")
            .await
            .expect("insert alice docs");
        db.save_link(bob.user_id, None, "docs", "https://bob.example.com/docs")
            .await
            .expect("insert bob docs");

        assert_eq!(
            db.list_links(alice.user_id).await.expect("list alice"),
            BTreeMap::from([(
                "docs".to_string(),
                "https://alice.example.com/docs".to_string()
            )])
        );
        assert_eq!(
            db.list_links(bob.user_id).await.expect("list bob"),
            BTreeMap::from([(
                "docs".to_string(),
                "https://bob.example.com/docs".to_string()
            )])
        );

        assert_eq!(
            db.get_link_target(alice.user_id, "docs")
                .await
                .expect("get alice docs"),
            Some("https://alice.example.com/docs".to_string())
        );
        assert_eq!(
            db.get_link_target(bob.user_id, "docs")
                .await
                .expect("get bob docs"),
            Some("https://bob.example.com/docs".to_string())
        );

        // Alice updates & renames her link; Bob's link must remain untouched.
        db.save_link(
            alice.user_id,
            Some("docs"),
            "notes",
            "https://alice.example.com/notes",
        )
        .await
        .expect("rename alice docs -> notes");

        assert_eq!(
            db.list_links(alice.user_id).await.expect("list alice after rename"),
            BTreeMap::from([(
                "notes".to_string(),
                "https://alice.example.com/notes".to_string()
            )])
        );
        assert_eq!(
            db.list_links(bob.user_id).await.expect("list bob after alice rename"),
            BTreeMap::from([(
                "docs".to_string(),
                "https://bob.example.com/docs".to_string()
            )])
        );

        // Alice deletes her link; Bob's link must still be untouched.
        assert_eq!(
            db.delete_link(alice.user_id, "notes")
                .await
                .expect("delete alice notes"),
            Some(BTreeMap::new())
        );
        assert_eq!(
            db.delete_link(alice.user_id, "docs")
                .await
                .expect("delete alice missing docs"),
            None
        );
        assert_eq!(
            db.get_link_target(bob.user_id, "docs")
                .await
                .expect("bob docs still present"),
            Some("https://bob.example.com/docs".to_string())
        );
    }

    #[tokio::test]
    async fn optional_postgres_end_to_end() {
        let Ok(host) = std::env::var("GOLINKS_TEST_PG_HOST") else {
            return;
        };
        if host.trim().is_empty() {
            return;
        }

        let port = std::env::var("GOLINKS_TEST_PG_PORT")
            .ok()
            .and_then(|v| v.trim().parse::<u16>().ok())
            .unwrap_or(5432);
        let database = std::env::var("GOLINKS_TEST_PG_NAME")
            .or_else(|_| std::env::var("GOLINKS_TEST_PG_DATABASE"))
            .unwrap_or_else(|_| "golinks".to_string());
        let username = std::env::var("GOLINKS_TEST_PG_USERNAME")
            .unwrap_or_else(|_| "golinks".to_string());
        let password = std::env::var("GOLINKS_TEST_PG_PASSWORD").unwrap_or_default();

        let db = Database::connect(&DbConfig::Postgresql {
            host,
            port,
            database,
            username,
            password,
        })
        .await
        .expect("connect to postgres");
        db.run_migrations().await.expect("run postgres migrations");

        let user = db
            .sync_user("pg_e2e_user", &derive_auth_token("pg-e2e-secret"))
            .await
            .expect("sync postgres user");
        assert!(user.user_id > 0);

        let links = db
            .save_link(user.user_id, None, "docs", "https://docs.example.com")
            .await
            .expect("save postgres link");
        assert_eq!(
            links.get("docs").map(String::as_str),
            Some("https://docs.example.com")
        );

        assert_eq!(
            db.get_link_target(user.user_id, "docs")
                .await
                .expect("get postgres link target"),
            Some("https://docs.example.com".to_string())
        );

        let remaining = db
            .delete_link(user.user_id, "docs")
            .await
            .expect("delete postgres link")
            .expect("deleted row");
        assert!(!remaining.contains_key("docs"));
    }
}
