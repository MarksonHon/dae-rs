//! `/var/lib/dae-rs/` directory management (design §4.1 / §4.3).
//!
//! Directory layout:
//!
//! ```text
//! /var/lib/dae-rs/
//! ├── <name>.dat / <name>.txt        # actual data files (dat→.dat, text→.txt)
//! ├── .tmp/                          # temp download files (before verification)
//! ├── .checksum/<name>.sha256        # checksum files
//! └── .meta/<name>.json              # metadata (url/type/last_updated/sha256/size/state)
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tracing::{error, warn};

use crate::ruleset::types::{RuleSetConfig, RuleSetData, RuleSetType};

/// Default data directory.
pub const DEFAULT_DATA_DIR: &str = "/var/lib/dae-rs/";

/// Storage error.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("failed to create directory '{path}': {source}")]
    CreateDir { path: String, source: std::io::Error },
    #[error("io error on '{path}': {source}")]
    Io { path: String, source: std::io::Error },
    #[error("meta file '{name}' is invalid: {detail}")]
    MetaParse { name: String, detail: String },
    #[error("meta file '{name}' failed to serialize: {detail}")]
    MetaSerialize { name: String, detail: String },
    #[error("rule set data is corrupt: {0}")]
    Corrupt(String),
}

/// Data directory management.
///
/// Defaults to [`DEFAULT_DATA_DIR`] (`/var/lib/dae-rs/`); tests can inject a temporary path.
#[derive(Debug, Clone)]
pub struct DataDir {
    root: PathBuf,
}

impl DataDir {
    /// Create a new data directory (defaults to [`DEFAULT_DATA_DIR`]; tests can inject a temporary path).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The default `/var/lib/dae-rs/`.
    pub fn default_dir() -> Self {
        Self::new(DEFAULT_DATA_DIR)
    }

    /// Data directory root path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn tmp_dir(&self) -> PathBuf {
        self.root.join(".tmp")
    }

    fn checksum_dir(&self) -> PathBuf {
        self.root.join(".checksum")
    }

    fn meta_dir(&self) -> PathBuf {
        self.root.join(".meta")
    }

    /// Data file path: `root/<name><ext>` (dat→`.dat`, text→`.txt`).
    pub fn data_file_path(&self, name: &str, ty: RuleSetType) -> PathBuf {
        self.root.join(format!("{name}{}", ty.file_extension()))
    }

    /// Temp download file path: `root/.tmp/<name>.tmp.<pid>.<nanos>.<counter>`.
    pub fn tmp_file_path(&self, name: &str) -> PathBuf {
        self.tmp_dir().join(format!("{name}.tmp{}", random_suffix()))
    }

    /// Checksum file path: `root/.checksum/<name>.sha256`.
    pub fn checksum_file_path(&self, name: &str) -> PathBuf {
        self.checksum_dir().join(format!("{name}.sha256"))
    }

    /// Metadata file path: `root/.meta/<name>.json`.
    pub fn meta_file_path(&self, name: &str) -> PathBuf {
        self.meta_dir().join(format!("{name}.json"))
    }

    /// Ensure the `root/`, `.tmp/`, `.checksum/`, and `.meta/` directories exist,
    /// plus the `/run/dae-rs/` binary cache directory.
    pub async fn ensure_dirs(&self) -> Result<(), StoreError> {
        let mut dirs = vec![
            self.root.clone(),
            self.tmp_dir(),
            self.checksum_dir(),
            self.meta_dir(),
        ];
        dirs.push(crate::ruleset::compiled::RUN_DATA_DIR.into());
        for dir in dirs {
            tokio::fs::create_dir_all(&dir).await.map_err(|source| StoreError::CreateDir {
                path: dir.display().to_string(),
                source,
            })?;
        }
        Ok(())
    }

    /// Atomic replace: rename `tmp` to `dest` (same directory / same filesystem guarantees atomicity).
    /// fsync the temp file before replacing and fsync the destination directory afterwards to ensure durability.
    pub async fn atomic_replace(&self, tmp: &Path, dest: &Path) -> Result<(), StoreError> {
        {
            let file = tokio::fs::File::open(tmp)
                .await
                .map_err(|source| StoreError::Io { path: tmp.display().to_string(), source })?;
            file.sync_all()
                .await
                .map_err(|source| StoreError::Io { path: tmp.display().to_string(), source })?;
        }
        tokio::fs::rename(tmp, dest)
            .await
            .map_err(|source| StoreError::Io { path: dest.display().to_string(), source })?;
        if let Some(parent) = dest.parent() {
            if let Ok(dir) = tokio::fs::File::open(parent).await {
                let _ = dir.sync_all().await;
            }
        }
        Ok(())
    }

    /// Atomically write bytes to `path` (same-directory temp file + rename).
    async fn atomic_write_bytes(&self, path: &Path, data: &[u8]) -> Result<(), StoreError> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|source| StoreError::CreateDir {
                path: parent.display().to_string(),
                source,
            })?;
        }
        let tmp = path.with_extension(format!("tmp{}", random_suffix()));
        {
            let mut file = tokio::fs::File::create(&tmp)
                .await
                .map_err(|source| StoreError::Io { path: tmp.display().to_string(), source })?;
            file.write_all(data)
                .await
                .map_err(|source| StoreError::Io { path: tmp.display().to_string(), source })?;
            file.sync_all()
                .await
                .map_err(|source| StoreError::Io { path: tmp.display().to_string(), source })?;
        }
        tokio::fs::rename(&tmp, path)
            .await
            .map_err(|source| StoreError::Io { path: path.display().to_string(), source })?;
        Ok(())
    }

    /// Read the checksum (returns `None` if it does not exist).
    pub async fn read_checksum(&self, name: &str) -> Result<Option<String>, StoreError> {
        let path = self.checksum_file_path(name);
        match tokio::fs::read_to_string(&path).await {
            Ok(s) => Ok(Some(s.trim().to_ascii_lowercase())),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(StoreError::Io { path: path.display().to_string(), source }),
        }
    }

    /// Write the checksum.
    pub async fn write_checksum(&self, name: &str, sha256: &str) -> Result<(), StoreError> {
        let path = self.checksum_file_path(name);
        self.atomic_write_bytes(&path, format!("{sha256}\n").as_bytes()).await
    }

    /// Read the metadata (returns `None` if it does not exist).
    pub async fn read_meta(&self, name: &str) -> Result<Option<RuleSetMeta>, StoreError> {
        let path = self.meta_file_path(name);
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let meta: RuleSetMeta = serde_json::from_slice(&bytes).map_err(|e| {
                    StoreError::MetaParse { name: name.to_string(), detail: e.to_string() }
                })?;
                Ok(Some(meta))
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(StoreError::Io { path: path.display().to_string(), source }),
        }
    }

    /// Write the metadata (JSON).
    pub async fn write_meta(&self, name: &str, meta: &RuleSetMeta) -> Result<(), StoreError> {
        let json = serde_json::to_vec_pretty(meta).map_err(|e| StoreError::MetaSerialize {
            name: name.to_string(),
            detail: e.to_string(),
        })?;
        let path = self.meta_file_path(name);
        self.atomic_write_bytes(&path, &json).await
    }

    /// Startup scan: read and parse existing data files into the in-memory cache.
    ///
    /// - File missing → `data = None`, `damaged = false` (pending download);
    /// - File present but the checksum (if recorded) mismatches or parsing fails → `data = None`,
    ///   `damaged = true` (corrupt, marked for re-download; this layer does not delete the original file —
    ///   the caller decides the recovery strategy).
    pub async fn scan(
        &self,
        entries: &[RuleSetConfig],
    ) -> Result<HashMap<String, ScannedRuleSet>, StoreError> {
        let mut out = HashMap::with_capacity(entries.len());
        for cfg in entries {
            let path = self.data_file_path(&cfg.name, cfg.r#type);
            let meta = self.read_meta(&cfg.name).await?;
            let recorded_sha = self.read_checksum(&cfg.name).await?;

            let bytes = match tokio::fs::read(&path).await {
                Ok(bytes) => bytes,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                    warn!(name = %cfg.name, "rule set data file missing; marked for download");
                    out.insert(
                        cfg.name.clone(),
                        ScannedRuleSet {
                            name: cfg.name.clone(),
                            r#type: cfg.r#type,
                            data: None,
                            meta,
                            sha256: recorded_sha,
                            damaged: false,
                        },
                    );
                    continue;
                }
                Err(source) => {
                    return Err(StoreError::Io { path: path.display().to_string(), source });
                }
            };

            let actual_sha = crate::ruleset::sha256_hex(&bytes);
            let checksum_mismatch = match &recorded_sha {
                Some(rec) => !rec.eq_ignore_ascii_case(&actual_sha),
                None => false,
            };

            let data = if checksum_mismatch {
                error!(name = %cfg.name, "rule set checksum mismatch; marked as corrupt");
                None
            } else {
                let ty = cfg.r#type;
                let name = cfg.name.clone();
                let sha = actual_sha.clone();
                match tokio::task::spawn_blocking(move || {
                    crate::ruleset::compiled::load_rule_set_data_cached(ty, &name, &sha, &bytes)
                })
                .await
                {
                    Ok(Ok(parsed)) => Some(parsed),
                    Ok(Err(e)) => {
                        error!(name = %cfg.name, error = %e, "rule set data corrupt; marked for re-download");
                        None
                    }
                    Err(e) => {
                        error!(name = %cfg.name, join_error = %e, "rule set parse task failed");
                        None
                    }
                }
            };
            let damaged = checksum_mismatch || data.is_none();

            out.insert(
                cfg.name.clone(),
                ScannedRuleSet {
                    name: cfg.name.clone(),
                    r#type: cfg.r#type,
                    data,
                    meta,
                    sha256: recorded_sha,
                    damaged,
                },
            );
        }
        Ok(out)
    }
}

/// Rule set metadata (persisted in `.meta/<name>.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSetMeta {
    /// Unique name.
    pub name: String,
    /// Data source URL.
    pub url: String,
    /// Data type.
    pub r#type: RuleSetType,
    /// Last successful update time (RFC3339).
    pub last_updated: Option<String>,
    /// Server ETag (for conditional requests).
    pub etag: Option<String>,
    /// Server Last-Modified (for conditional requests).
    pub last_modified: Option<String>,
    /// sha256 of the most recent content.
    pub sha256: Option<String>,
    /// File size (bytes).
    pub size: u64,
    /// State.
    pub state: RuleSetState,
}

/// Rule set state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleSetState {
    /// Ready and normal.
    Ready,
    /// Pending download / recovery (missing or corrupt).
    Pending,
    /// Downloading.
    Downloading,
    /// Degraded after consecutive failures (warning only, no unlimited retries).
    Degraded,
    /// Failed (with reason).
    Failed(String),
}

/// Startup scan result entry.
#[derive(Debug, Clone)]
pub struct ScannedRuleSet {
    /// Unique name.
    pub name: String,
    /// Data type.
    pub r#type: RuleSetType,
    /// Parsed in-memory data; `None` = missing or corrupt (pending re-download).
    pub data: Option<RuleSetData>,
    /// Metadata (may be `None`).
    pub meta: Option<RuleSetMeta>,
    /// Recorded checksum (may be `None`).
    pub sha256: Option<String>,
    /// File present but checksum/parse failed.
    pub damaged: bool,
}

/// Generate a process-unique random suffix (pid + nanosecond timestamp + atomic counter).
fn random_suffix() -> String {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let counter = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!(".{}.{nanos}.{counter}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ruleset::types::{RuleSetConfig, RuleSetData, RuleSetType};

    #[tokio::test]
    async fn test_ensure_dirs_creates_layout() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(dir.path());
        data_dir.ensure_dirs().await.unwrap();
        assert!(dir.path().join(".tmp").is_dir());
        assert!(dir.path().join(".checksum").is_dir());
        assert!(dir.path().join(".meta").is_dir());
    }

    #[tokio::test]
    async fn test_atomic_replace() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(dir.path());
        data_dir.ensure_dirs().await.unwrap();
        let tmp = data_dir.tmp_file_path("chinaip");
        tokio::fs::write(&tmp, b"1.1.1.0/24").await.unwrap();
        let dest = dir.path().join("chinaip.txt");
        data_dir.atomic_replace(&tmp, &dest).await.unwrap();
        assert!(!tmp.exists());
        assert_eq!(tokio::fs::read(&dest).await.unwrap(), b"1.1.1.0/24");
    }

    #[tokio::test]
    async fn test_checksum_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(dir.path());
        data_dir.ensure_dirs().await.unwrap();
        assert_eq!(data_dir.read_checksum("a").await.unwrap(), None);
        data_dir.write_checksum("a", "abcd1234").await.unwrap();
        assert_eq!(data_dir.read_checksum("a").await.unwrap().as_deref(), Some("abcd1234"));
    }

    #[tokio::test]
    async fn test_meta_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(dir.path());
        data_dir.ensure_dirs().await.unwrap();
        assert!(data_dir.read_meta("a").await.unwrap().is_none());
        let meta = RuleSetMeta {
            name: "a".into(),
            url: "https://example.com/a.txt".into(),
            r#type: RuleSetType::IpList,
            last_updated: Some("2026-01-01T00:00:00Z".into()),
            etag: None,
            last_modified: None,
            sha256: Some("abcd".into()),
            size: 42,
            state: RuleSetState::Ready,
        };
        data_dir.write_meta("a", &meta).await.unwrap();
        let got = data_dir.read_meta("a").await.unwrap().unwrap();
        assert_eq!(got, meta);
    }

    #[tokio::test]
    async fn test_scan_valid_and_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(dir.path());
        data_dir.ensure_dirs().await.unwrap();

        // Valid text IP list
        let ip_path = data_dir.data_file_path("chinaip", RuleSetType::IpList);
        tokio::fs::write(&ip_path, "1.1.1.0/24\n2.2.2.2\n").await.unwrap();

        // Corrupt domain list (garbage bytes)
        let bad_path = data_dir.data_file_path("badsite", RuleSetType::DomainList);
        tokio::fs::write(&bad_path, b"\xff\xff\xff\xff not a valid text").await.unwrap();

        // Missing file
        let entries = vec![
            RuleSetConfig {
                name: "chinaip".into(),
                r#type: RuleSetType::IpList,
                url: "http://x/ip.txt".into(),
                expected_sha256: None,
                update: None,
                update_on_start: false,
                proxy: None,
            },
            RuleSetConfig {
                name: "badsite".into(),
                r#type: RuleSetType::DomainList,
                url: "http://x/domain.txt".into(),
                expected_sha256: None,
                update: None,
                update_on_start: false,
                proxy: None,
            },
            RuleSetConfig {
                name: "missing".into(),
                r#type: RuleSetType::DomainList,
                url: "http://x/d.txt".into(),
                expected_sha256: None,
                update: None,
                update_on_start: false,
                proxy: None,
            },
        ];
        let scanned = data_dir.scan(&entries).await.unwrap();

        let ip = &scanned["chinaip"];
        assert!(matches!(ip.data, Some(RuleSetData::IpList(_))));
        assert!(!ip.damaged);

        let bad = &scanned["badsite"];
        assert!(bad.data.is_none());
        assert!(bad.damaged);

        let missing = &scanned["missing"];
        assert!(missing.data.is_none());
        assert!(!missing.damaged);
    }
}
