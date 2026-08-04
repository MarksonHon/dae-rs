//! 规则集（Rule Set）数据层。
//!
//! 本模块实现规则集支持的第一部分：**数据层**（设计文档 §2.2 / §2.3 / §4）。
//! 负责：
//!
//! - [`types`]：内存数据结构与规则集配置条目类型
//! - [`decode`]：v2ray `.dat`（geoip / geosite）手写 protobuf 解码
//! - [`list`]：文本Domain name / IP 列表解析
//! - [`store`]：`/var/lib/dae-rs/` 目录管理（原子替换、checksum、meta、启动扫描）
//! - [`download`]：下载器（直连 + 可选 SOCKS5、重试、ETag、sha256 校验）
//!
//! 本层**不**接入 matcher / DNS routing / 配置 parser-validator（由后续子任务负责）。

pub mod cache;
pub mod decode;
pub mod download;
pub mod list;
pub mod refparse;
pub mod scheduler;
pub mod store;
pub mod types;

pub use cache::{load_cache_from_dir, RuleSetCache};
pub use decode::DecodeError;
pub use download::{DownloadError, DownloadedInfo, DownloadOptions, UpdateOutcome};
pub use list::ListError;
pub use refparse::{
    domain_pattern_to_string, is_ruleset_ref, match_domain_pattern, match_domain_patterns,
    match_qname_value, parse_ref, ref_label, RuleSetRef,
};
pub use scheduler::{ProxyResolver, RuleSetScheduler, SchedulerHandle, UpdateSignal};
pub use store::{DataDir, RuleSetMeta, RuleSetState, ScannedRuleSet, StoreError};
pub use types::{DomainPattern, DomainPatternType, RuleSetConfig, RuleSetData, RuleSetType};

/// 规则集统一错误类型（各子模块错误经 `From` 汇总至此）。
#[derive(Debug, thiserror::Error)]
pub enum RuleSetError {
    #[error("rule set decode error: {0}")]
    Decode(#[from] DecodeError),
    #[error("rule set list parse error: {0}")]
    List(#[from] ListError),
    #[error("rule set store error: {0}")]
    Store(#[from] StoreError),
    #[error("rule set download error: {0}")]
    Download(#[from] DownloadError),
    #[error("rule set data is not valid utf-8: {0}")]
    InvalidUtf8(String),
}

/// 依据类型解析原始字节为内存数据结构（dat 解码 / 文本解析的统一入口）。
pub fn parse_rule_set_data(ty: RuleSetType, bytes: &[u8]) -> Result<RuleSetData, RuleSetError> {
    match ty {
        RuleSetType::GeoIp => decode::decode_geoip_list(bytes).map_err(RuleSetError::Decode),
        RuleSetType::GeoSite => decode::decode_geosite_list(bytes).map_err(RuleSetError::Decode),
        RuleSetType::DomainList => {
            let text = std::str::from_utf8(bytes)
                .map_err(|e| RuleSetError::InvalidUtf8(e.to_string()))?;
            list::parse_domain_list(text)
                .map(RuleSetData::DomainList)
                .map_err(RuleSetError::List)
        }
        RuleSetType::IpList => {
            let text = std::str::from_utf8(bytes)
                .map_err(|e| RuleSetError::InvalidUtf8(e.to_string()))?;
            list::parse_ip_list(text)
                .map(RuleSetData::IpList)
                .map_err(RuleSetError::List)
        }
    }
}

/// 计算字节的 sha256 十六进制摘要（小写）。
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;

    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();

    let mut out = String::with_capacity(64);
    for byte in digest.iter() {
        let _ = write!(out, "{:02x}", byte);
    }
    out
}
