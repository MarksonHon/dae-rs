//! `/var/dae-rs/` 目录管理（设计 §4.1 / §4.3）。
//!
//! 目录布局：
//!
//! ```text
//! /var/dae-rs/
//! ├── <name>.dat / <name>.txt        # 实际数据文件（dat→.dat，文本→.txt）
//! ├── .tmp/                          # 临时下载文件（未校验前）
//! ├── .checksum/<name>.sha256        # 校验和文件
//! └── .meta/<name>.json              # 元数据（url/type/last_updated/sha256/size/state）
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tracing::{error, warn};

use crate::ruleset::types::{RuleSetConfig, RuleSetData, RuleSetType};

/// 默认数据目录。
pub const DEFAULT_DATA_DIR: &str = "/var/dae-rs/";

/// 存储错误。
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

/// 数据目录管理。
///
/// 默认 [`DEFAULT_DATA_DIR`]（`/var/dae-rs/`），测试可注入临时路径。
#[derive(Debug, Clone)]
pub struct DataDir {
    root: PathBuf,
}

impl DataDir {
    /// 新建数据目录（默认 [`DEFAULT_DATA_DIR`]；测试可注入临时路径）。
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// 默认 `/var/dae-rs/`。
    pub fn default_dir() -> Self {
        Self::new(DEFAULT_DATA_DIR)
    }

    /// Data directory根路径。
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

    /// 数据文件路径：`root/<name><ext>`（dat→`.dat`，文本→`.txt`）。
    pub fn data_file_path(&self, name: &str, ty: RuleSetType) -> PathBuf {
        self.root.join(format!("{name}{}", ty.file_extension()))
    }

    /// 临时下载文件路径：`root/.tmp/<name>.tmp.<pid>.<nanos>.<counter>`。
    pub fn tmp_file_path(&self, name: &str) -> PathBuf {
        self.tmp_dir().join(format!("{name}.tmp{}", random_suffix()))
    }

    /// 校验和文件路径：`root/.checksum/<name>.sha256`。
    pub fn checksum_file_path(&self, name: &str) -> PathBuf {
        self.checksum_dir().join(format!("{name}.sha256"))
    }

    /// 元数据文件路径：`root/.meta/<name>.json`。
    pub fn meta_file_path(&self, name: &str) -> PathBuf {
        self.meta_dir().join(format!("{name}.json"))
    }

    /// 确保 `root/`、`.tmp/`、`.checksum/`、`.meta/` 目录存在。
    pub async fn ensure_dirs(&self) -> Result<(), StoreError> {
        for dir in [self.root.clone(), self.tmp_dir(), self.checksum_dir(), self.meta_dir()] {
            tokio::fs::create_dir_all(&dir).await.map_err(|source| StoreError::CreateDir {
                path: dir.display().to_string(),
                source,
            })?;
        }
        Ok(())
    }

    /// 原子替换：将 `tmp` 重命名为 `dest`（同目录/同文件系统保证原子性）。
    /// 替换前 fsync 临时文件，替换后 fsync 目标目录以确保持久化。
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

    /// 原子写入字节到 `path`（同目录临时文件 + rename）。
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

    /// 读取校验和（不存在返回 `None`）。
    pub async fn read_checksum(&self, name: &str) -> Result<Option<String>, StoreError> {
        let path = self.checksum_file_path(name);
        match tokio::fs::read_to_string(&path).await {
            Ok(s) => Ok(Some(s.trim().to_ascii_lowercase())),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(StoreError::Io { path: path.display().to_string(), source }),
        }
    }

    /// 写入校验和。
    pub async fn write_checksum(&self, name: &str, sha256: &str) -> Result<(), StoreError> {
        let path = self.checksum_file_path(name);
        self.atomic_write_bytes(&path, format!("{sha256}\n").as_bytes()).await
    }

    /// 读取元数据（不存在返回 `None`）。
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

    /// 写入元数据（JSON）。
    pub async fn write_meta(&self, name: &str, meta: &RuleSetMeta) -> Result<(), StoreError> {
        let json = serde_json::to_vec_pretty(meta).map_err(|e| StoreError::MetaSerialize {
            name: name.to_string(),
            detail: e.to_string(),
        })?;
        let path = self.meta_file_path(name);
        self.atomic_write_bytes(&path, &json).await
    }

    /// 启动扫描：读取并解析已有数据文件到内存缓存。
    ///
    /// - 文件缺失 → `data = None`、`damaged = false`（待下载）；
    /// - 文件存在但校验和（若记录）不匹配或解析失败 → `data = None`、
    ///   `damaged = true`（损坏，标记待重新下载；本层不删除原文件，由
    ///   调用方决定恢复策略）。
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
                match tokio::task::spawn_blocking(move || {
                    crate::ruleset::parse_rule_set_data(ty, &bytes)
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

/// 规则集元数据（持久化于 `.meta/<name>.json`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSetMeta {
    /// Unique name.
    pub name: String,
    /// 数据源 URL。
    pub url: String,
    /// Data type.
    pub r#type: RuleSetType,
    /// 上次成功Update time（RFC3339）。
    pub last_updated: Option<String>,
    /// 服务端 ETag（用于条件请求）。
    pub etag: Option<String>,
    /// 服务端 Last-Modified（用于条件请求）。
    pub last_modified: Option<String>,
    /// 最近一次内容的 sha256。
    pub sha256: Option<String>,
    /// File size (bytes).
    pub size: u64,
    /// 状态。
    pub state: RuleSetState,
}

/// 规则集状态。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleSetState {
    /// 正常就绪。
    Ready,
    /// 待下载 / 待恢复（缺失或损坏）。
    Pending,
    /// 下载中。
    Downloading,
    /// 连续失败降级（仅告警，不无限重试）。
    Degraded,
    /// 失败（附原因）。
    Failed(String),
}

/// 启动扫描结果条目。
#[derive(Debug, Clone)]
pub struct ScannedRuleSet {
    /// Unique name.
    pub name: String,
    /// Data type.
    pub r#type: RuleSetType,
    /// 解析后的内存数据；`None` = 缺失或损坏（待重新下载）。
    pub data: Option<RuleSetData>,
    /// 元数据（可能为 `None`）。
    pub meta: Option<RuleSetMeta>,
    /// 已记录校验和（可能为 `None`）。
    pub sha256: Option<String>,
    /// 文件存在但校验/解析失败。
    pub damaged: bool,
}

/// 生成进程内唯一的随机后缀（pid + 纳秒时间戳 + 原子计数）。
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
            url: "https://example.com/a.dat".into(),
            r#type: RuleSetType::GeoIp,
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

        // 有效文本 IP 列表
        let ip_path = data_dir.data_file_path("chinaip", RuleSetType::IpList);
        tokio::fs::write(&ip_path, "1.1.1.0/24\n2.2.2.2\n").await.unwrap();

        // 损坏的 geosite dat（垃圾字节）
        let bad_path = data_dir.data_file_path("badsite", RuleSetType::GeoSite);
        tokio::fs::write(&bad_path, b"\xff\xff\xff\xff not a protobuf").await.unwrap();

        // 缺失文件
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
                r#type: RuleSetType::GeoSite,
                url: "http://x/geosite.dat".into(),
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
