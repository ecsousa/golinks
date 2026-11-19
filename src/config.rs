use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use hmac::{Hmac, Mac};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::mpsc;

type HmacSha256 = Hmac<Sha256>;

const SESSION_CONTEXT: &[u8] = b"golinks-session-v1";

#[derive(Debug, Deserialize, Serialize)]
struct RawConfig {
    key: String,
    #[serde(default)]
    links: BTreeMap<String, String>,
}

/// Validated runtime configuration with a precomputed session token.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub key: String,
    pub auth_token: String,
    pub links: BTreeMap<String, String>,
}

pub type SharedConfig = Arc<RwLock<Arc<RuntimeConfig>>>;

/// Derives a stateless hex-encoded HMAC-SHA256 session token from the configured secret key.
pub fn derive_auth_token(key: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(SESSION_CONTEXT);
    hex::encode(mac.finalize().into_bytes())
}

/// Loads and validates a YAML configuration file from `path`.
pub fn load_config_from_path(path: &Path) -> Result<RuntimeConfig, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read config file {}: {err}", path.display()))?;
    let raw: RawConfig = serde_yaml_ng::from_str(&contents)
        .map_err(|err| format!("failed to parse YAML in {}: {err}", path.display()))?;

    if raw.key.is_empty() {
        return Err(format!("config key in {} must not be empty", path.display()));
    }

    let auth_token = derive_auth_token(&raw.key);
    Ok(RuntimeConfig {
        key: raw.key,
        auth_token,
        links: raw.links,
    })
}

/// Persists `cfg` back to `path` as YAML.
///
/// Uses an atomic temp-file + rename when possible, falling back to direct overwrite
/// (e.g. when `path` is a single-file Docker bind mount where rename returns EXDEV/EBUSY).
pub fn save_config_to_path(path: &Path, cfg: &RuntimeConfig) -> Result<(), String> {
    let raw = RawConfig {
        key: cfg.key.clone(),
        links: cfg.links.clone(),
    };
    let yaml = serde_yaml_ng::to_string(&raw)
        .map_err(|err| format!("failed to serialize YAML config: {err}"))?;

    if let Some(parent) = path.parent() {
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("config.yaml");
        let tmp_path = parent.join(format!(".{file_name}.tmp.{}", std::process::id()));
        if std::fs::write(&tmp_path, &yaml).is_ok() {
            if std::fs::rename(&tmp_path, path).is_ok() {
                return Ok(());
            }
            let _ = std::fs::remove_file(&tmp_path);
        }
    }

    std::fs::write(path, &yaml)
        .map_err(|err| format!("failed to write config file {}: {err}", path.display()))
}

/// Resolves a potentially relative path against the current working directory.
fn absolutize_path(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|err| format!("failed to resolve current directory: {err}"))
    }
}

/// Watches the parent directory of `config_path` and hot-reloads `shared` on changes.
///
/// Watching the parent directory ensures atomic editor saves and symlink swaps are detected.
/// Invalid reloads are logged and ignored so the last valid configuration remains active.
pub fn spawn_config_watcher(
    config_path: &Path,
    shared: SharedConfig,
) -> Result<RecommendedWatcher, String> {
    let abs_path = absolutize_path(config_path)?;
    let parent_dir = abs_path
        .parent()
        .ok_or_else(|| format!("config path {} has no parent directory", abs_path.display()))?
        .to_path_buf();
    let target_name = abs_path
        .file_name()
        .ok_or_else(|| format!("config path {} has no file name", abs_path.display()))?
        .to_os_string();

    let (tx, mut rx) = mpsc::unbounded_channel::<()>();

    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        let Ok(event) = res else {
            return;
        };
        if !matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
            return;
        }
        let matches_target = event
            .paths
            .iter()
            .any(|p| p.file_name() == Some(target_name.as_os_str()));
        if matches_target {
            let _ = tx.send(());
        }
    })
    .map_err(|err| format!("failed to create config watcher: {err}"))?;

    watcher
        .watch(&parent_dir, RecursiveMode::NonRecursive)
        .map_err(|err| format!("failed to watch {}: {err}", parent_dir.display()))?;

    tokio::spawn(async move {
        while rx.recv().await.is_some() {
            // Debounce rapid filesystem events (e.g., truncate + write or atomic rename).
            tokio::time::sleep(Duration::from_millis(100)).await;
            while rx.try_recv().is_ok() {}

            match load_config_from_path(&abs_path) {
                Ok(new_cfg) => {
                    if let Ok(mut guard) = shared.write() {
                        *guard = Arc::new(new_cfg);
                    }
                    eprintln!("Reloaded configuration from {}", abs_path.display());
                }
                Err(err) => {
                    eprintln!("Failed to reload configuration (keeping previous): {err}");
                }
            }
        }
    });

    Ok(watcher)
}
