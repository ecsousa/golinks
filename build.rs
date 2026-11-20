use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

const BASE_VERSION: &str = "v0000001";

struct EngineSql {
    full_schema: PathBuf,
    migrations: Vec<(String, PathBuf)>,
}

fn canonical_utf8_path(path: &Path) -> String {
    let canonical = fs::canonicalize(path)
        .unwrap_or_else(|err| panic!("failed to canonicalize {}: {err}", path.display()));
    canonical
        .to_str()
        .unwrap_or_else(|| panic!("non-UTF-8 path encountered: {}", canonical.display()))
        .to_owned()
}

fn parse_migration_version(file_name: &str) -> Option<&str> {
    let stem = file_name
        .strip_prefix("migration_")?
        .strip_suffix(".sql")?;
    let digits = stem.strip_prefix('v')?;
    if digits.len() != 7 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(stem)
}

fn scan_engine_dir(engine_dir: &Path, relative_dir: &str) -> EngineSql {
    let full_schema = engine_dir.join("full_schema.sql");
    if !full_schema.is_file() {
        panic!(
            "missing required full schema file: {}",
            full_schema.display()
        );
    }
    println!("cargo:rerun-if-changed={relative_dir}/full_schema.sql");

    let entries = fs::read_dir(engine_dir)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", engine_dir.display()));

    let mut migrations = Vec::new();

    for entry_res in entries {
        let entry = entry_res
            .unwrap_or_else(|err| panic!("failed to read entry in {}: {err}", engine_dir.display()));
        let path = entry.path();
        let file_name_os = entry.file_name();
        let file_name = file_name_os.to_str().unwrap_or_else(|| {
            panic!(
                "non-UTF-8 filename in {}: {}",
                engine_dir.display(),
                path.display()
            )
        });

        let file_type = entry
            .file_type()
            .unwrap_or_else(|err| panic!("failed to stat {}: {err}", path.display()));
        if !file_type.is_file() {
            panic!(
                "unexpected non-file entry in {}: {}",
                engine_dir.display(),
                path.display()
            );
        }

        if file_name == "full_schema.sql" {
            continue;
        }

        let Some(version) = parse_migration_version(file_name) else {
            panic!(
                "unexpected file '{}' in {}: expected 'full_schema.sql' or 'migration_vXXXXXXX.sql' (7 ASCII digits)",
                file_name,
                engine_dir.display()
            );
        };

        if version <= BASE_VERSION {
            panic!(
                "invalid migration version '{}' in {}: incremental migrations must be > '{}'",
                version,
                path.display(),
                BASE_VERSION
            );
        }

        println!("cargo:rerun-if-changed={relative_dir}/{file_name}");
        migrations.push((version.to_owned(), path));
    }

    migrations.sort_by(|a, b| a.0.cmp(&b.0));

    EngineSql {
        full_schema,
        migrations,
    }
}

fn format_migration_slice(out: &mut String, const_name: &str, migrations: &[(String, PathBuf)]) {
    writeln!(out, "pub const {const_name}: &[(&str, &str)] = &[").unwrap();
    for (version, path) in migrations {
        let abs = canonical_utf8_path(path);
        writeln!(out, "    ({version:?}, include_str!({abs:?})),").unwrap();
    }
    writeln!(out, "];").unwrap();
}

fn main() {
    println!("cargo:rerun-if-changed=db");
    println!("cargo:rerun-if-changed=db/sqlite");
    println!("cargo:rerun-if-changed=db/postgres");

    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set"),
    );
    let db_dir = manifest_dir.join("db");

    let sqlite = scan_engine_dir(&db_dir.join("sqlite"), "db/sqlite");
    let postgres = scan_engine_dir(&db_dir.join("postgres"), "db/postgres");

    let sqlite_versions: Vec<&str> = sqlite.migrations.iter().map(|(v, _)| v.as_str()).collect();
    let postgres_versions: Vec<&str> = postgres.migrations.iter().map(|(v, _)| v.as_str()).collect();
    if sqlite_versions != postgres_versions {
        panic!(
            "migration version mismatch between db/sqlite ({sqlite_versions:?}) and db/postgres ({postgres_versions:?})"
        );
    }

    let latest_version = sqlite_versions.last().copied().unwrap_or(BASE_VERSION);

    let mut out = String::new();
    writeln!(out, "pub const LATEST_VERSION: &str = {latest_version:?};").unwrap();
    let sqlite_schema = canonical_utf8_path(&sqlite.full_schema);
    let postgres_schema = canonical_utf8_path(&postgres.full_schema);
    writeln!(
        out,
        "pub const SQLITE_FULL_SCHEMA: &str = include_str!({sqlite_schema:?});"
    )
    .unwrap();
    writeln!(
        out,
        "pub const POSTGRES_FULL_SCHEMA: &str = include_str!({postgres_schema:?});"
    )
    .unwrap();
    format_migration_slice(&mut out, "SQLITE_MIGRATIONS", &sqlite.migrations);
    format_migration_slice(&mut out, "POSTGRES_MIGRATIONS", &postgres.migrations);

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is not set"));
    let dest_path = out_dir.join("embedded_db.rs");
    fs::write(&dest_path, out)
        .unwrap_or_else(|err| panic!("failed to write {}: {err}", dest_path.display()));
}
