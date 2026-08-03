//! 规则集**全局内存缓存**（设计 §4.4 / §6.3）。
//!
//! 提供：
//!
//! - [`RuleSetCache`]：`name → RuleSetData` 的内存映射，供 matcher 编译期、
//!   DNS 查询Routing与 DNS 响应Routing运行时查询。内部为
//!   `Arc<RwLock<HashMap<String, RuleSetData>>>`，可被更新流程（调度器通知 →
//!   重新加载）安全替换。
//! - [`load_cache_from_dir`]：从磁盘数据目录扫描并填充缓存（启动与更新后共用）。
//!
//! 类型化查询语义：
//!
//! - `geoip:<code>` → [`RuleSetCache::find_geoip_code`]（跨所有 GeoIp 数据，
//!   code 大小写不敏感）；
//! - `geosite:<code>` → [`RuleSetCache::find_geosite_code`]；
//! - `set:<name>`（ip_list）→ [`RuleSetCache::get_set_ips`]；
//! - `set:<name>`（domain_list）→ [`RuleSetCache::get_set_domains`]。
//!
//! 类型不匹配或数据缺失均返回 `None`，由调用方按 E2103（编译期）或
//! warn+false（运行时）处理。

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use ipnet::IpNet;
use tracing::warn;

use crate::ruleset::store::DataDir;
use crate::ruleset::types::{DomainPattern, RuleSetConfig, RuleSetData};

/// 规则集内存缓存。
#[derive(Debug, Clone, Default)]
pub struct RuleSetCache {
    inner: Arc<RwLock<HashMap<String, RuleSetData>>>,
}

impl RuleSetCache {
    /// 创建空缓存。
    pub fn new() -> Self {
        Self::default()
    }

    /// 插入（或覆盖）一个规则集数据。
    pub fn insert(&self, name: String, data: RuleSetData) {
        if let Ok(mut guard) = self.inner.write() {
            guard.insert(name, data);
        }
    }

    /// 整体替换缓存内容（更新完成后使用）。
    pub fn replace_all(&self, map: HashMap<String, RuleSetData>) {
        if let Ok(mut guard) = self.inner.write() {
            *guard = map;
        }
    }

    /// 按 name 读取规则集数据。
    pub fn get(&self, name: &str) -> Option<RuleSetData> {
        self.inner.read().ok()?.get(name).cloned()
    }

    /// 是否存在该 name 的规则集数据。
    pub fn contains(&self, name: &str) -> bool {
        self.inner.read().map(|g| g.contains_key(name)).unwrap_or(false)
    }

    /// 缓存条目数。
    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }

    /// 缓存是否为空。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 查找 geoip `country_code`（大小写不敏感）对应的 CIDR 列表。
    ///
    /// 遍历缓存中所有 `GeoIp` 数据；未找到返回 `None`。
    pub fn find_geoip_code(&self, code: &str) -> Option<Vec<IpNet>> {
        let guard = self.inner.read().ok()?;
        for data in guard.values() {
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

    /// 查找 geosite `country_code`（分类名）对应的Domain name模式列表。
    ///
    /// geosite dat 的 `country_code` 为小写分类名；这里也做大小写不敏感匹配以容错。
    pub fn find_geosite_code(&self, code: &str) -> Option<Vec<DomainPattern>> {
        let guard = self.inner.read().ok()?;
        for data in guard.values() {
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

    /// 读取 `set:<name>`（类型必须为 `IpList`）的 CIDR 列表。
    pub fn get_set_ips(&self, name: &str) -> Option<Vec<IpNet>> {
        match self.get(name)? {
            RuleSetData::IpList(nets) => Some(nets),
            _ => None,
        }
    }

    /// 读取 `set:<name>`（类型必须为 `DomainList`）的Domain name模式列表。
    pub fn get_set_domains(&self, name: &str) -> Option<Vec<DomainPattern>> {
        match self.get(name)? {
            RuleSetData::DomainList(pats) => Some(pats),
            _ => None,
        }
    }
}

/// 从磁盘数据目录扫描并Build rulesets内存缓存（启动与更新后共用）。
///
/// 对每个配置条目调用 [`DataDir::scan`]；仅把解析成功的条目装入缓存，
/// 缺失/损坏的条目跳过并记录 warn（编译期由 matcher 以 E2103 报错）。
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

        // 类型化 set 查询
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
        // 有效 ip_list 文件
        let path = dir.data_file_path("chinaip", RuleSetType::IpList);
        tokio::fs::write(&path, "1.1.1.0/24\n2.2.2.2\n").await.unwrap();
        // 缺失条目
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
