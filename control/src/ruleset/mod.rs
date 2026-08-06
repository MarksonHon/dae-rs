//! Rule set data layer.
//!
//! This module implements the first part of rule set support: the **data layer** (design document §2.2 / §2.3 / §4).
//! It is responsible for:
//!
//! - [`types`]: in-memory data structures and rule set configuration entry types
//! - [`list`]: text domain name / IP list parsing
//! - [`store`]: `/var/lib/dae-rs/` directory management (atomic replace, checksum, meta, startup scan)
//! - [`download`]: downloader (direct + optional SOCKS5, retries, ETag, sha256 verification)
//!
//! This layer does **not** hook into matcher / configuration parser-validator (handled by later sub-tasks).

use std::sync::Arc;

pub mod cache;
pub mod compiled;
pub mod download;
pub mod list;
pub mod refparse;
pub mod scheduler;
pub mod store;
pub mod types;

pub use cache::{load_cache_from_dir, RuleSetCache};
pub use compiled::{compile_rule_set, CompiledDomainSet, CompiledIpSet, CompiledRuleSet};
pub use download::{DownloadError, DownloadedInfo, DownloadOptions, UpdateOutcome};
pub use list::ListError;
pub use refparse::{
    domain_pattern_to_string, is_ruleset_ref, match_domain_pattern, match_domain_patterns,
    match_qname_value, parse_ref, ref_label, RuleSetRef,
};
pub use scheduler::{ProxyResolver, RuleSetScheduler, SchedulerHandle, UpdateSignal};
pub use store::{DataDir, RuleSetMeta, RuleSetState, ScannedRuleSet, StoreError};
pub use types::{DomainPattern, DomainPatternType, RuleSetConfig, RuleSetData, RuleSetType};

/// Unified rule set error type (errors from each sub-module are aggregated here via `From`).
#[derive(Debug, thiserror::Error)]
pub enum RuleSetError {
    #[error("rule set list parse error: {0}")]
    List(#[from] ListError),
    #[error("rule set store error: {0}")]
    Store(#[from] StoreError),
    #[error("rule set download error: {0}")]
    Download(#[from] DownloadError),
    #[error("rule set data is not valid utf-8: {0}")]
    InvalidUtf8(String),
}

/// Parse raw bytes into an in-memory data structure based on the type (text parsing).
pub fn parse_rule_set_data(ty: RuleSetType, bytes: &[u8]) -> Result<RuleSetData, RuleSetError> {
    match ty {
        RuleSetType::DomainList => {
            let text = std::str::from_utf8(bytes)
                .map_err(|e| RuleSetError::InvalidUtf8(e.to_string()))?;
            list::parse_domain_list(text)
                .map(|v| RuleSetData::DomainList(Arc::new(v)))
                .map_err(RuleSetError::List)
        }
        RuleSetType::IpList => {
            let text = std::str::from_utf8(bytes)
                .map_err(|e| RuleSetError::InvalidUtf8(e.to_string()))?;
            list::parse_ip_list(text)
                .map(|v| RuleSetData::IpList(Arc::new(v)))
                .map_err(RuleSetError::List)
        }
    }
}

/// Compute the lowercase hex sha256 digest of bytes.
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
