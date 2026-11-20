use std::time::Instant;

use sqlx::{Connection as _, PgConnection, PgPool, SqlitePool};

use crate::db::DbError;

include!(concat!(env!("OUT_DIR"), "/embedded_db.rs"));

const PG_MIGRATION_LOCK_KEY: i64 = 0x676f_6c69_6e6b_7301;

/// Specification of full schema bootstrap SQL and incremental migrations.
#[derive(Debug, Clone, Copy)]
pub struct MigrationSpec<'a> {
    pub full_schema: &'a str,
    pub migrations: &'a [(&'a str, &'a str)],
    pub latest_version: &'a str,
}

/// Returns the embedded SQLite migration specification generated at build time.
pub fn embedded_sqlite_spec() -> MigrationSpec<'static> {
    MigrationSpec {
        full_schema: SQLITE_FULL_SCHEMA,
        migrations: SQLITE_MIGRATIONS,
        latest_version: LATEST_VERSION,
    }
}

/// Returns the embedded PostgreSQL migration specification generated at build time.
pub fn embedded_postgres_spec() -> MigrationSpec<'static> {
    MigrationSpec {
        full_schema: POSTGRES_FULL_SCHEMA,
        migrations: POSTGRES_MIGRATIONS,
        latest_version: LATEST_VERSION,
    }
}

fn elapsed_ms(start: Instant) -> i32 {
    i32::try_from(start.elapsed().as_millis()).unwrap_or(i32::MAX)
}

/// Runs schema bootstrap or pending incremental migrations on a SQLite pool.
pub async fn run_sqlite_migrations(
    pool: &SqlitePool,
    spec: &MigrationSpec<'_>,
) -> Result<(), DbError> {
    let table_exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migration'",
    )
    .fetch_one(pool)
    .await?;

    let needs_bootstrap = if table_exists == 0 {
        true
    } else {
        let row_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM schema_migration")
            .fetch_one(pool)
            .await?;
        row_count == 0
    };

    if needs_bootstrap {
        let start = Instant::now();
        let mut tx = pool.begin().await?;
        sqlx::raw_sql(spec.full_schema).execute(&mut *tx).await?;
        sqlx::query(
            "INSERT INTO schema_migration (version, execution_time_ms, success) VALUES (?, ?, ?)",
        )
        .bind(spec.latest_version)
        .bind(elapsed_ms(start))
        .bind(true)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(());
    }

    if let Some(failed_version) = sqlx::query_scalar::<_, String>(
        "SELECT version FROM schema_migration WHERE success = 0 ORDER BY version ASC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?
    {
        return Err(DbError::Migration(format!(
            "previous migration '{}' failed; manual intervention required before restarting",
            failed_version.trim()
        )));
    }

    let max_version = sqlx::query_scalar::<_, Option<String>>(
        "SELECT MAX(version) FROM schema_migration",
    )
    .fetch_one(pool)
    .await?
    .unwrap_or_default();
    let max_version = max_version.trim();

    if max_version > spec.latest_version {
        return Err(DbError::Migration(format!(
            "database schema version '{}' is newer than binary version '{}'",
            max_version, spec.latest_version
        )));
    }

    for &(version, sql) in spec.migrations {
        if version <= max_version {
            continue;
        }

        let start = Instant::now();
        let mut tx = pool.begin().await?;
        match sqlx::raw_sql(sql).execute(&mut *tx).await {
            Ok(_) => {
                sqlx::query(
                    "INSERT INTO schema_migration (version, execution_time_ms, success) VALUES (?, ?, ?)",
                )
                .bind(version)
                .bind(elapsed_ms(start))
                .bind(true)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
            }
            Err(err) => {
                let duration_ms = elapsed_ms(start);
                let _ = tx.rollback().await;
                let _ = sqlx::query(
                    "INSERT INTO schema_migration (version, execution_time_ms, success) VALUES (?, ?, ?)",
                )
                .bind(version)
                .bind(duration_ms)
                .bind(false)
                .execute(pool)
                .await;
                return Err(DbError::Migration(format!(
                    "migration '{version}' failed: {err}"
                )));
            }
        }
    }

    Ok(())
}

/// Runs schema bootstrap or pending incremental migrations on a PostgreSQL pool under an advisory lock.
pub async fn run_postgres_migrations(
    pool: &PgPool,
    spec: &MigrationSpec<'_>,
) -> Result<(), DbError> {
    let mut conn = pool.acquire().await?;

    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(PG_MIGRATION_LOCK_KEY)
        .execute(&mut *conn)
        .await?;

    let result = run_postgres_migrations_locked(&mut conn, spec).await;

    let unlock_result = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(PG_MIGRATION_LOCK_KEY)
        .execute(&mut *conn)
        .await;

    match result {
        Ok(()) => {
            unlock_result?;
            Ok(())
        }
        Err(err) => Err(err),
    }
}

async fn run_postgres_migrations_locked(
    conn: &mut PgConnection,
    spec: &MigrationSpec<'_>,
) -> Result<(), DbError> {
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'golinks' AND table_name = 'schema_migration')",
    )
    .fetch_one(&mut *conn)
    .await?;

    let needs_bootstrap = if !table_exists {
        true
    } else {
        let row_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM golinks.schema_migration")
            .fetch_one(&mut *conn)
            .await?;
        row_count == 0
    };

    if needs_bootstrap {
        let start = Instant::now();
        let mut tx = conn.begin().await?;
        sqlx::raw_sql(spec.full_schema).execute(&mut *tx).await?;
        sqlx::query(
            "INSERT INTO golinks.schema_migration (version, execution_time_ms, success) VALUES ($1, $2, TRUE)",
        )
        .bind(spec.latest_version)
        .bind(elapsed_ms(start))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(());
    }

    if let Some(failed_version) = sqlx::query_scalar::<_, String>(
        "SELECT version FROM golinks.schema_migration WHERE success = FALSE ORDER BY version ASC LIMIT 1",
    )
    .fetch_optional(&mut *conn)
    .await?
    {
        return Err(DbError::Migration(format!(
            "previous migration '{}' failed; manual intervention required before restarting",
            failed_version.trim()
        )));
    }

    let max_version = sqlx::query_scalar::<_, Option<String>>(
        "SELECT MAX(version) FROM golinks.schema_migration",
    )
    .fetch_one(&mut *conn)
    .await?
    .unwrap_or_default();
    let max_version = max_version.trim();

    if max_version > spec.latest_version {
        return Err(DbError::Migration(format!(
            "database schema version '{}' is newer than binary version '{}'",
            max_version, spec.latest_version
        )));
    }

    for &(version, sql) in spec.migrations {
        if version <= max_version {
            continue;
        }

        let start = Instant::now();
        let mut tx = conn.begin().await?;
        match sqlx::raw_sql(sql).execute(&mut *tx).await {
            Ok(_) => {
                sqlx::query(
                    "INSERT INTO golinks.schema_migration (version, execution_time_ms, success) VALUES ($1, $2, TRUE)",
                )
                .bind(version)
                .bind(elapsed_ms(start))
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
            }
            Err(err) => {
                let duration_ms = elapsed_ms(start);
                let _ = tx.rollback().await;
                let _ = sqlx::query(
                    "INSERT INTO golinks.schema_migration (version, execution_time_ms, success) VALUES ($1, $2, FALSE)",
                )
                .bind(version)
                .bind(duration_ms)
                .execute(&mut *conn)
                .await;
                return Err(DbError::Migration(format!(
                    "migration '{version}' failed: {err}"
                )));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::config::DbConfig;
    use crate::db::Database;
    use sqlx::Row;

    #[tokio::test]
    async fn fresh_sqlite_creates_parent_dir_and_runs_full_schema() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("nested").join("sub").join("golinks.db");
        let parent_dir = db_path.parent().unwrap();
        assert!(!parent_dir.exists());

        let db = Database::connect(&DbConfig::Sqlite {
            path: db_path.to_string_lossy().into_owned(),
        })
        .await
        .unwrap();

        assert!(parent_dir.is_dir());
        db.run_migrations().await.unwrap();

        let pool = db.sqlite_pool();

        let rows = sqlx::query("SELECT version, success FROM schema_migration ORDER BY version")
            .fetch_all(pool)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get::<String, _>("version").trim(), "v0000001");
        assert!(rows[0].get::<bool, _>("success"));

        for table in ["users", "links"] {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
            )
            .bind(table)
            .fetch_one(pool)
            .await
            .unwrap();
            assert_eq!(count, 1, "expected table '{table}' to exist");
        }

        let fk: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(fk, 1);
    }

    #[tokio::test]
    async fn idempotent_restart_does_not_reapply_or_fail() {
        let db = Database::connect(&DbConfig::Sqlite {
            path: ":memory:".to_string(),
        })
        .await
        .unwrap();

        db.run_migrations().await.unwrap();
        db.run_migrations().await.unwrap();

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM schema_migration")
            .fetch_one(db.sqlite_pool())
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn empty_schema_migration_table_triggers_full_schema_init() {
        let db = Database::connect(&DbConfig::Sqlite {
            path: ":memory:".to_string(),
        })
        .await
        .unwrap();
        let pool = db.sqlite_pool();

        sqlx::raw_sql(
            "CREATE TABLE schema_migration (
                version CHAR(8) PRIMARY KEY,
                installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                execution_time_ms INTEGER,
                success BOOLEAN NOT NULL DEFAULT 1
            );",
        )
        .execute(pool)
        .await
        .unwrap();

        let spec = embedded_sqlite_spec();
        run_sqlite_migrations(pool, &spec).await.unwrap();

        let rows = sqlx::query("SELECT version, success FROM schema_migration")
            .fetch_all(pool)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].get::<String, _>("version").trim(),
            spec.latest_version
        );
        assert!(rows[0].get::<bool, _>("success"));

        let users_exists: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'users'",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(users_exists, 1);
    }

    #[tokio::test]
    async fn applies_pending_migrations_in_order() {
        let db = Database::connect(&DbConfig::Sqlite {
            path: ":memory:".to_string(),
        })
        .await
        .unwrap();
        let pool = db.sqlite_pool();

        db.run_migrations().await.unwrap();

        let base = embedded_sqlite_spec();
        let synthetic_spec = MigrationSpec {
            full_schema: base.full_schema,
            migrations: &[
                (
                    "v0000002",
                    "CREATE TABLE audit_log (id INTEGER PRIMARY KEY, note TEXT NOT NULL);",
                ),
                (
                    "v0000003",
                    "ALTER TABLE audit_log ADD COLUMN created_by TEXT NOT NULL DEFAULT 'system';",
                ),
            ],
            latest_version: "v0000003",
        };

        run_sqlite_migrations(pool, &synthetic_spec).await.unwrap();

        // Verify v0000002 ran before v0000003 by using both the table and the added column.
        sqlx::query("INSERT INTO audit_log (note, created_by) VALUES (?, ?)")
            .bind("migrated")
            .bind("tester")
            .execute(pool)
            .await
            .unwrap();

        let rows = sqlx::query(
            "SELECT version, execution_time_ms, success FROM schema_migration ORDER BY version",
        )
        .fetch_all(pool)
        .await
        .unwrap();
        assert_eq!(rows.len(), 3);

        let expected = ["v0000001", "v0000002", "v0000003"];
        for (row, exp_ver) in rows.iter().zip(expected.iter()) {
            assert_eq!(row.get::<String, _>("version").trim(), *exp_ver);
            assert!(row.get::<i64, _>("execution_time_ms") >= 0);
            assert!(row.get::<bool, _>("success"));
        }
    }

    #[tokio::test]
    async fn failed_migration_rolls_back_records_failure_and_blocks_next_startup() {
        let db = Database::connect(&DbConfig::Sqlite {
            path: ":memory:".to_string(),
        })
        .await
        .unwrap();
        let pool = db.sqlite_pool();

        db.run_migrations().await.unwrap();

        let base = embedded_sqlite_spec();
        let failing_spec = MigrationSpec {
            full_schema: base.full_schema,
            migrations: &[
                (
                    "v0000002",
                    "CREATE TABLE should_rollback (id INTEGER PRIMARY KEY); THIS IS INVALID SQL;",
                ),
                (
                    "v0000003",
                    "CREATE TABLE should_not_run (id INTEGER PRIMARY KEY);",
                ),
            ],
            latest_version: "v0000003",
        };

        let err = run_sqlite_migrations(pool, &failing_spec)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("v0000002"),
            "unexpected error: {err}"
        );

        let rolled_back_table: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'should_rollback'",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(rolled_back_table, 0);

        let failed_row =
            sqlx::query("SELECT success FROM schema_migration WHERE version = 'v0000002'")
                .fetch_one(pool)
                .await
                .unwrap();
        assert!(!failed_row.get::<bool, _>("success"));

        // Subsequent startup with fixed migrations must still fail immediately.
        let fixed_spec = MigrationSpec {
            full_schema: base.full_schema,
            migrations: &[
                (
                    "v0000002",
                    "CREATE TABLE should_rollback (id INTEGER PRIMARY KEY);",
                ),
                (
                    "v0000003",
                    "CREATE TABLE should_not_run (id INTEGER PRIMARY KEY);",
                ),
            ],
            latest_version: "v0000003",
        };

        let err2 = run_sqlite_migrations(pool, &fixed_spec).await.unwrap_err();
        assert!(
            err2.to_string().contains("v0000002"),
            "unexpected error: {err2}"
        );

        for table in ["should_rollback", "should_not_run"] {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
            )
            .bind(table)
            .fetch_one(pool)
            .await
            .unwrap();
            assert_eq!(count, 0, "table '{table}' should not have been created");
        }
    }

    #[tokio::test]
    async fn rejects_database_newer_than_binary() {
        let db = Database::connect(&DbConfig::Sqlite {
            path: ":memory:".to_string(),
        })
        .await
        .unwrap();
        let pool = db.sqlite_pool();

        db.run_migrations().await.unwrap();

        sqlx::query(
            "INSERT INTO schema_migration (version, execution_time_ms, success) VALUES ('v0000099', 0, 1)",
        )
        .execute(pool)
        .await
        .unwrap();

        let err = db.run_migrations().await.unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("newer"),
            "expected error mentioning newer schema version, got: {err}"
        );
    }

    #[test]
    fn embedded_postgres_schema_contains_golinks_schema_and_tables() {
        let spec = embedded_postgres_spec();
        assert_eq!(spec.latest_version, "v0000001");
        assert!(spec
            .full_schema
            .contains("CREATE SCHEMA IF NOT EXISTS golinks"));
        assert!(spec.full_schema.contains("golinks.schema_migration"));
        assert!(spec.full_schema.contains("golinks.users"));
        assert!(spec.full_schema.contains("golinks.links"));
    }
}
