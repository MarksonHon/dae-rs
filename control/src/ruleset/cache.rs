//! Rule set **global in-memory cache** (design §4.4 / §6.3).
//!
//! Provides:
//!
//! - [`RuleSetCache`]: an in-memory map of `name → RuleSetData`, queried at matcher compile time and
//!   at runtime by routing. Internally an
//!   `Arc<RwLock<HashMap<String, RuleSetData>>>`, it can be safely replaced by the update flow
//!   (scheduler notification → reload).
//! - [`load_cache_from_dir`]: scans the on-disk data directory and fills the cache (shared by startup and post-update).
//!
//! Typed query semantics:
//!
//! - `set:<name>` (ip_list) → [`RuleSetCache::get_set_ips`];
//! - `set:<name>` (domain_list) → [`RuleSetCache::get_set_domains`].
//!
//! Type mismatch or missing data both return `None`, handled by the caller as E2103 (compile time) or
//! warn+false (runtime).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use ipnet::IpNet;
use tracing::warn;

use crate::ruleset::compiled::{CompiledRuleSet, compile_rule_set};
use crate::ruleset::store::DataDir;
use crate::ruleset::types::{DomainPattern, RuleSetConfig, RuleSetData};

/// Raw parsed data + the compiled matching view of a rule set.
#[derive(Debug)]
struct CacheInner {
    data: HashMap<String, RuleSetData>,
    compiled: HashMap<String, CompiledRuleSet>,
}

impl Default for CacheInner {
    fn default() -> Self {
        Self {
            data: HashMap::new(),
            compiled: HashMap::new(),
        }
    }
}

/// In-memory rule set cache.
///
/// Holds both the raw parsed [`RuleSetData`] (used by the data-plane rule compiler, which needs
/// the original CIDR / domain lists to build eBPF LPM tries) and a **compiled matching view**
/// ([`CompiledRuleSet`]) used by the runtime matcher for O(log N) / O(labels) lookups.
#[derive(Debug, Clone, Default)]
pub struct RuleSetCache {
    inner: Arc<RwLock<CacheInner>>,
}

impl RuleSetCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or overwrite) a rule set data entry.
    pub fn insert(&self, name: String, data: RuleSetData) {
        if let Ok(mut guard) = self.inner.write() {
            let compiled = compile_rule_set(&data);
            guard.compiled.insert(name.clone(), compiled);
            guard.data.insert(name, data);
        }
    }

    /// Replace the entire cache content (used after an update completes).
    pub fn replace_all(&self, map: HashMap<String, RuleSetData>) {
        if let Ok(mut guard) = self.inner.write() {
            let compiled = map.iter().map(|(k, v)| (k.clone(), compile_rule_set(v))).collect();
            guard.data = map;
            guard.compiled = compiled;
        }
    }

    /// Read rule set data by name.
    pub fn get(&self, name: &str) -> Option<RuleSetData> {
        self.inner.read().ok()?.data.get(name).cloned()
    }

    /// Whether rule set data exists for the name.
    pub fn contains(&self, name: &str) -> bool {
        self.inner.read().map(|g| g.data.contains_key(name)).unwrap_or(false)
    }

    /// Number of cache entries.
    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.data.len()).unwrap_or(0)
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read the CIDR list for `set:<name>` (type must be `IpList`).
    ///
    /// Returns a shared [`Arc`] reference so callers avoid deep-cloning the whole
    /// list on every lookup.
    pub fn get_set_ips(&self, name: &str) -> Option<Arc<Vec<IpNet>>> {
        let g = self.inner.read().ok()?;
        match g.data.get(name)? {
            RuleSetData::IpList(nets) => Some(Arc::clone(nets)),
            _ => None,
        }
    }

    /// Read the domain name pattern list for `set:<name>` (type must be `DomainList`).
    ///
    /// Returns a shared [`Arc`] reference so callers avoid deep-cloning the whole
    /// list on every lookup.
    pub fn get_set_domains(&self, name: &str) -> Option<Arc<Vec<DomainPattern>>> {
        let g = self.inner.read().ok()?;
        match g.data.get(name)? {
            RuleSetData::DomainList(pats) => Some(Arc::clone(pats)),
            _ => None,
        }
    }

    /// Whether `ip` belongs to any CIDR in the `set:<name>` ip_list.
    pub fn domain_set_matches(&self, name: &str, qname: &str) -> bool {
        if let Ok(g) = self.inner.read() {
            if let Some(CompiledRuleSet::DomainList(c)) = g.compiled.get(name) {
                return c.matches(qname);
            }
        }
        false
    }
}

/// Scan the on-disk data directory and build the rule sets in-memory cache (shared by startup and post-update).
///
/// Calls [`DataDir::scan`] for each configuration entry; only successfully parsed entries are put
/// into the cache, while missing/corrupt entries are skipped with a warn (at compile time, the
/// matcher reports E2103).
pub async fn load_cache_from_dir(
    dir: &DataDir,
    entries: &[RuleSetConfig],
) -> HashMap<String, RuleSetData> {
    let mut map = HashMap::with_capacity(entries.len());
    match dir.scan(entries).await {
        Ok(scanned) => {
            for (name, item) in scanned {
                if let Some(data) = item.data {
                    map.insert(name, data);
                } else if item.damaged {
                    warn!(name = %name, "rule set data damaged; skipped from memory cache");
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "rule set scan failed; memory cache empty");
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ruleset::types::{DomainPattern, DomainPatternType, RuleSetData, RuleSetType};

    #[test]
    fn test_cache_insert_get_replace() {
        let cache = RuleSetCache::new();
        assert!(cache.is_empty());
        cache.insert(
            "chinaip".into(),
            RuleSetData::IpList(Arc::new(vec!["1.1.1.0/24".parse().unwrap()])),
        );
        assert!(cache.contains("chinaip"));
        assert_eq!(cache.len(), 1);
        assert!(matches!(cache.get("chinaip"), Some(RuleSetData::IpList(_))));

        cache.replace_all(HashMap::new());
        assert!(cache.is_empty());
    }

    #[test]
    fn test_set_typed_queries() {
        let cache = RuleSetCache::new();
        cache.insert(
            "chinaip".into(),
            RuleSetData::IpList(Arc::new(vec!["10.0.0.0/8".parse().unwrap()])),
        );
        cache.insert(
            "chinadom".into(),
            RuleSetData::DomainList(Arc::new(vec![DomainPattern {
                pattern_type: DomainPatternType::Full,
                value: "google.com".into(),
            }])),
        );

        // Typed set queries
        assert!(cache.get_set_ips("chinaip").is_some());
        assert!(cache.get_set_ips("chinadom").is_none(), "type mismatch");
        assert!(cache.get_set_domains("chinadom").is_some());
        assert!(cache.get_set_domains("chinaip").is_none(), "type mismatch");
        assert!(cache.get_set_ips("unknown").is_none());
    }

    #[tokio::test]
    async fn test_load_cache_from_dir() {
        use crate::ruleset::store::DataDir;
        let dir = DataDir::new(tempfile::tempdir().unwrap().path());
        dir.ensure_dirs().await.unwrap();
        // Valid ip_list file
        let path = dir.data_file_path("chinaip", RuleSetType::IpList);
        tokio::fs::write(&path, "1.1.1.0/24\n2.2.2.2\n").await.unwrap();
        // Missing entry
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
                name: "missing".into(),
                r#type: RuleSetType::DomainList,
                url: "http://x/d.txt".into(),
                expected_sha256: None,
                update: None,
                update_on_start: false,
                proxy: None,
            },
        ];
        let map = load_cache_from_dir(&dir, &entries).await;
        assert!(map.contains_key("chinaip"));
        assert!(!map.contains_key("missing"));
        assert!(map.get("chinaip").unwrap().clone()
            == RuleSetData::IpList(Arc::new(vec![
                "1.1.1.0/24".parse().unwrap(),
                "2.2.2.2/32".parse().unwrap()
            ])));
    }
}
