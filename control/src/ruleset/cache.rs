//! Rule set **global in-memory cache** (design §4.4 / §6.3).
//!
//! Provides:
//!
//! - [`RuleSetCache`]: an in-memory map of `name → RuleSetData`, queried at matcher compile time and
//!   at runtime by DNS query routing and DNS response routing. Internally an
//!   `Arc<RwLock<HashMap<String, RuleSetData>>>`, it can be safely replaced by the update flow
//!   (scheduler notification → reload).
//! - [`load_cache_from_dir`]: scans the on-disk data directory and fills the cache (shared by startup and post-update).
//!
//! Typed query semantics:
//!
//! - `geoip:<code>` → [`RuleSetCache::find_geoip_code`] (across all GeoIp data,
//!   code case-insensitive);
//! - `geosite:<code>` → [`RuleSetCache::find_geosite_code`];
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
/// ([`CompiledRuleSet`]) used by the runtime DNS matcher for O(log N) / O(labels) lookups.
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

    /// Find the CIDR list for a geoip `country_code` (case-insensitive).
    ///
    /// Iterates over all `GeoIp` data in the cache; returns `None` if not found.
    pub fn find_geoip_code(&self, code: &str) -> Option<Vec<IpNet>> {
        let guard = self.inner.read().ok()?;
        for data in guard.data.values() {
            if let RuleSetData::GeoIp { entries } = data {
                for (k, v) in entries {
                    if k.eq_ignore_ascii_case(code) {
                        return Some(v.clone());
                    }
                }
            }
        }
        None
    }

    /// Find the domain name pattern list for a geosite `country_code` (category name).
    ///
    /// A geosite dat's `country_code` is a lowercase category name; matching here is also case-insensitive for robustness.
    pub fn find_geosite_code(&self, code: &str) -> Option<Vec<DomainPattern>> {
        let guard = self.inner.read().ok()?;
        for data in guard.data.values() {
            if let RuleSetData::GeoSite { entries } = data {
                for (k, v) in entries {
                    if k.eq_ignore_ascii_case(code) {
                        return Some(v.clone());
                    }
                }
            }
        }
        None
    }

    /// Read the CIDR list for `set:<name>` (type must be `IpList`).
    pub fn get_set_ips(&self, name: &str) -> Option<Vec<IpNet>> {
        match self.get(name)? {
            RuleSetData::IpList(nets) => Some(nets),
            _ => None,
        }
    }

    /// Read the domain name pattern list for `set:<name>` (type must be `DomainList`).
    pub fn get_set_domains(&self, name: &str) -> Option<Vec<DomainPattern>> {
        match self.get(name)? {
            RuleSetData::DomainList(pats) => Some(pats),
            _ => None,
        }
    }

    // ==========================================================================
    // Compiled (fast) matching — used by the runtime DNS matcher.
    // ==========================================================================

    /// Whether `ip` belongs to any CIDR in the `geoip:<code>` set.
    pub fn geoip_contains(&self, code: &str, ip: std::net::IpAddr) -> bool {
        if let Ok(g) = self.inner.read() {
            for set in g.compiled.values() {
                if let CompiledRuleSet::GeoIp(entries) = set {
                    for (k, v) in entries {
                        if k.eq_ignore_ascii_case(code) && v.contains(ip) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Whether `ip` belongs to any CIDR in the `set:<name>` ip_list.
    pub fn ip_set_contains(&self, name: &str, ip: std::net::IpAddr) -> bool {
        if let Ok(g) = self.inner.read() {
            if let Some(CompiledRuleSet::IpList(c)) = g.compiled.get(name) {
                return c.contains(ip);
            }
        }
        false
    }

    /// Whether `qname` matches any domain pattern in the `geosite:<code>` set.
    pub fn geosite_matches(&self, code: &str, qname: &str) -> bool {
        if let Ok(g) = self.inner.read() {
            for set in g.compiled.values() {
                if let CompiledRuleSet::GeoSite(entries) = set {
                    for (k, v) in entries {
                        if k.eq_ignore_ascii_case(code) && v.matches(qname) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Whether `qname` matches any pattern in the `set:<name>` domain_list.
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
        cache.insert("chinaip".into(), RuleSetData::IpList(vec!["1.1.1.0/24".parse().unwrap()]));
        assert!(cache.contains("chinaip"));
        assert_eq!(cache.len(), 1);
        assert!(matches!(cache.get("chinaip"), Some(RuleSetData::IpList(_))));

        cache.replace_all(HashMap::new());
        assert!(cache.is_empty());
    }

    #[test]
    fn test_find_geoip_code_case_insensitive() {
        let cache = RuleSetCache::new();
        let mut entries = HashMap::new();
        entries.insert(
            "cn".to_string(),
            vec!["1.0.1.0/24".parse::<IpNet>().unwrap()],
        );
        cache.insert("geoip_main".into(), RuleSetData::GeoIp { entries });

        assert!(cache.find_geoip_code("cn").is_some());
        assert!(cache.find_geoip_code("CN").is_some());
        assert!(cache.find_geoip_code("us").is_none());
    }

    #[test]
    fn test_find_geosite_code_and_set_typed() {
        let cache = RuleSetCache::new();
        let mut entries = HashMap::new();
        entries.insert(
            "cn".to_string(),
            vec![DomainPattern { pattern_type: DomainPatternType::Suffix, value: "baidu.com".into() }],
        );
        cache.insert("geosite_main".into(), RuleSetData::GeoSite { entries });
        cache.insert(
            "chinaip".into(),
            RuleSetData::IpList(vec!["10.0.0.0/8".parse().unwrap()]),
        );
        cache.insert(
            "chinadom".into(),
            RuleSetData::DomainList(vec![DomainPattern {
                pattern_type: DomainPatternType::Full,
                value: "google.com".into(),
            }]),
        );

        assert!(cache.find_geosite_code("cn").is_some());
        assert!(cache.find_geosite_code("CN").is_some());
        assert!(cache.find_geosite_code("ads").is_none());

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
        assert!(map.get("chinaip").unwrap().clone() == RuleSetData::IpList(vec!["1.1.1.0/24".parse().unwrap(), "2.2.2.2/32".parse().unwrap()]));
    }
}
