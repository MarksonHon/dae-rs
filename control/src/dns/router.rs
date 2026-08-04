use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::warn;

use crate::config::{DnsConfig, DnsGroupConfig};
use crate::ruleset::cache::RuleSetCache;
use crate::ruleset::refparse::{match_domain_patterns, match_qname_value, parse_ref, RuleSetRef};

/// Result of matching a DNS query to a group
#[derive(Debug, Clone)]
pub struct DnsRouteResult {
    /// The selected DNS group
    pub group: DnsGroupConfig,
    /// How to send this query: None = direct, Some(name) = through proxy group
    pub send_by: Option<String>,
}

/// Result of checking a DNS response
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsResponseAction {
    /// Accept the response as-is
    Accept,
    /// Reject the response (return empty response)
    Reject,
    /// Re-query using a different upstream
    Requery(String),
}

/// DNS Router — matches queries to groups, checks responses
#[derive(Debug, Clone)]
pub struct DnsRouter {
    /// DNS groups indexed by name
    groups: Arc<HashMap<String, DnsGroupConfig>>,
    /// Top-level DNS routing fallback group
    fallback_group: String,
    /// Top-level DNS routing rules
    rules: Vec<DnsRouteRule>,
    /// Ruleset in-memory cache (for `qname(geosite:...)` / `qname(set:...)` runtime matching).
    rule_set_cache: RuleSetCache,
}

/// Compiled DNS routing rule
#[derive(Debug, Clone)]
struct DnsRouteRule {
    /// Match type
    match_type: DnsMatchType,
    /// Match value
    match_value: String,
    /// Whether this rule has NOT operator
    negated: bool,
    /// Target group name
    target_group: String,
}

/// DNS match type
#[derive(Debug, Clone, PartialEq, Eq)]
enum DnsMatchType {
    /// Match by qname (domain name)
    QName,
    /// Match by query type (A, AAAA, etc.)
    QType,
    /// Match by geosite dat code (Domain name pattern, `qname(geosite:<code>)`).
    /// code stored in `match_value`.
    GeoSite,
    /// Match by `set:<name>`（domain_list）。
    /// name stored in `match_value`.
    Set,
    /// Always matches
    Any,
}

impl DnsRouter {
    /// Construct DNS router.
    ///
    /// * `config` — DNS configuration;
    /// * `rule_set_cache` — ruleset in-memory cache (`qname(geosite:...)` / `qname(set:...)`
    ///   for runtime matching).
    ///
    /// Compile Routing rules; unknown/invalid match expressions no longer silently discarded, returns error.
    pub fn new(config: &DnsConfig, rule_set_cache: RuleSetCache) -> Result<Self> {
        let mut groups = HashMap::new();
        for group in &config.groups {
            groups.insert(group.name.clone(), group.clone());
        }

        let rules: Vec<DnsRouteRule> = config
            .routing
            .rules
            .iter()
            .map(compile_route_rule)
            .collect::<Result<Vec<_>>>()?;

        let fallback_group = if config.routing.fallback.is_empty() {
            config
                .groups
                .first()
                .map(|g| g.name.clone())
                .unwrap_or_default()
        } else {
            config.routing.fallback.clone()
        };

        Ok(Self {
            groups: Arc::new(groups),
            fallback_group,
            rules,
            rule_set_cache,
        })
    }

    /// Match a DNS query to a group
    pub fn match_query(&self, qname: &str, qtype: u16) -> DnsRouteResult {
        // Try top-level rules first
        for rule in &self.rules {
            if self.evaluate_match(rule, qname, qtype) {
                if let Some(group) = self.groups.get(&rule.target_group) {
                    return self.select_group(group);
                }
            }
        }

        // Fallback
        if let Some(group) = self.groups.get(&self.fallback_group) {
            return self.select_group(group);
        }

        // Last resort: use first available group
        if let Some(group) = self.groups.values().next() {
            return self.select_group(group);
        }

        DnsRouteResult {
            group: DnsGroupConfig {
                name: "null".into(),
                send_by: "direct".into(),
                query_mode: crate::config::DnsQueryMode::default(),
                upstream: Vec::new(),
                response_routing: None,
            },
            send_by: None,
        }
    }

    /// Build the route result for a group: carries the group's send_by
    /// ("direct" → None, otherwise the proxy group name).
    fn select_group(&self, group: &DnsGroupConfig) -> DnsRouteResult {
        let send_by = if group.send_by == "direct" {
            None
        } else {
            Some(group.send_by.clone())
        };

        DnsRouteResult {
            group: group.clone(),
            send_by,
        }
    }

    /// Evaluate a match type (**without** NOT negation).
    ///
    /// - `QName`: normal suffix/pattern matching (`suffix:`/`full:`/`keyword:`/`regex:`/bare value),
    ///   **case insensitive** (fixes defect).
    /// - `GeoSite`: look up Ruleset cache geosite code → Domain name pattern match;
    /// - `Set`: look up Ruleset cache domain_list → Domain name pattern match;
    /// - `QType` / `Any`: original logic.
    fn eval_match_type(&self, mt: &DnsMatchType, value: &str, qname: &str, qtype: u16) -> bool {
        match mt {
            DnsMatchType::QName => match_qname_value(qname, value),
            DnsMatchType::GeoSite => match self.rule_set_cache.find_geosite_code(value) {
                Some(patterns) => match_domain_patterns(qname, &patterns),
                None => {
                    warn!(
                        code = %value,
                        "DNS qname(geosite:...) code not found in rule set cache; no match"
                    );
                    false
                }
            },
            DnsMatchType::Set => match self.rule_set_cache.get_set_domains(value) {
                Some(patterns) => match_domain_patterns(qname, &patterns),
                None => {
                    warn!(
                        name = %value,
                        "DNS qname(set:...) not found or not a domain_list; no match"
                    );
                    false
                }
            },
            DnsMatchType::QType => {
                let type_str = value.to_uppercase();
                match type_str.as_str() {
                    "A" => qtype == 1,
                    "NS" => qtype == 2,
                    "MD" => qtype == 3,
                    "MF" => qtype == 4,
                    "CNAME" => qtype == 5,
                    "SOA" => qtype == 6,
                    "MB" => qtype == 7,
                    "MG" => qtype == 8,
                    "MR" => qtype == 9,
                    "NULL" => qtype == 10,
                    "WKS" => qtype == 11,
                    "PTR" => qtype == 12,
                    "HINFO" => qtype == 13,
                    "MINFO" => qtype == 14,
                    "MX" => qtype == 15,
                    "TXT" => qtype == 16,
                    "AAAA" => qtype == 28,
                    "SRV" => qtype == 33,
                    "OPT" => qtype == 41,
                    "ANY" => qtype == 255,
                    _ => false,
                }
            }
            DnsMatchType::Any => true,
        }
    }

    /// Evaluate a single rule against query parameters
    fn evaluate_match(&self, rule: &DnsRouteRule, qname: &str, qtype: u16) -> bool {
        let matched = self.eval_match_type(&rule.match_type, &rule.match_value, qname, qtype);
        if rule.negated { !matched } else { matched }
    }
}

/// Compile the qname/qtype inner part of a match expression (`geosite:`/`set:`/bare value),
/// returns `(match_type, match_value)`.
fn compile_qname_value(value: &str, raw: &str) -> Result<(DnsMatchType, String)> {
    match parse_ref(value) {
        RuleSetRef::GeoSite(code) => Ok((DnsMatchType::GeoSite, code)),
        RuleSetRef::Set(name) => Ok((DnsMatchType::Set, name)),
        RuleSetRef::GeoIp(code) => Err(anyhow!(
            "qname does not support geoip: reference '{raw}' (code='{code}')"
        )),
        RuleSetRef::Plain(v) => Ok((DnsMatchType::QName, v.to_string())),
    }
}

/// Compile a routing rule string into a DnsRouteRule
///
/// Unknown/invalid match expressions no longer silently discarded, returns error (design §6.4).
fn compile_route_rule(rule: &crate::config::DnsRouteRule) -> Result<DnsRouteRule> {
    let raw = rule.r#match.trim();
    let target_group = rule.action.clone();

    if raw == "any" {
        return Ok(DnsRouteRule {
            match_type: DnsMatchType::Any,
            match_value: String::new(),
            negated: false,
            target_group,
        });
    }

    if let Some(value) = raw.strip_prefix("qname(") {
        let value = value
            .strip_suffix(')')
            .ok_or_else(|| anyhow!("invalid qname rule: '{raw}'"))?;
        let negated = value.starts_with('!');
        let value = if negated { &value[1..] } else { value };
        let (match_type, match_value) = compile_qname_value(value, raw)?;
        return Ok(DnsRouteRule {
            match_type,
            match_value,
            negated,
            target_group,
        });
    }

    if let Some(value) = raw.strip_prefix("qtype(") {
        let value = value
            .strip_suffix(')')
            .ok_or_else(|| anyhow!("invalid qtype rule: '{raw}'"))?;
        let negated = value.starts_with('!');
        let value = if negated { &value[1..] } else { value };
        return Ok(DnsRouteRule {
            match_type: DnsMatchType::QType,
            match_value: value.to_string(),
            negated,
            target_group,
        });
    }

    Err(anyhow!("unsupported DNS routing match expression: '{raw}'"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    fn make_config(groups: Vec<config::DnsGroupConfig>, routing_rules: Vec<config::DnsRouteRule>, fallback: &str) -> config::DnsConfig {
        config::DnsConfig {
            bind: "127.0.0.1:5353".into(),
            starting_dns: config::StartingDnsConfig {
                ip_version_prefer: 4,
                upstream: vec![],
            },
            groups,
            routing: config::DnsRoutingConfig {
                rules: routing_rules,
                fallback: fallback.to_string(),
            },
            cache: config::DnsCacheConfig::default(),
        }
    }

    fn make_group(name: &str, upstreams: &[(&str, &str)]) -> config::DnsGroupConfig {
        config::DnsGroupConfig {
            name: name.to_string(),
            send_by: "direct".to_string(),
            query_mode: config::DnsQueryMode::default(),
            upstream: upstreams
                .iter()
                .map(|(label, addr)| config::DnsUpstreamEntry {
                    label: label.to_string(),
                    address: addr.to_string(),
                })
                .collect(),
            response_routing: None,
        }
    }

    #[test]
    fn test_match_query_returns_group() {
        // Request routing removed: match_query routes to a group, not a specific upstream.
        let config = make_config(
            vec![make_group("g1", &[("a", "1.1.1.1"), ("b", "2.2.2.2")])],
            vec![],
            "g1",
        );
        let router = DnsRouter::new(&config, RuleSetCache::new()).unwrap();
        let result = router.match_query("example.com", 1);
        assert_eq!(result.group.name, "g1");
        assert_eq!(result.send_by, None);
        // All upstreams in the group are still present for group-level concurrent querying.
        assert_eq!(result.group.upstream.len(), 2);
    }

    #[test]
    fn test_match_query_send_by_proxy() {
        let mut group = make_group("g1", &[("a", "1.1.1.1")]);
        group.send_by = "proxy_primary".into();
        let config = make_config(vec![group], vec![], "g1");
        let router = DnsRouter::new(&config, RuleSetCache::new()).unwrap();
        let result = router.match_query("example.com", 1);
        assert_eq!(result.group.name, "g1");
        assert_eq!(result.send_by.as_deref(), Some("proxy_primary"));
    }

    #[test]
    fn test_top_level_routing_to_group() {
        let config = make_config(
            vec![
                make_group("cn_dns", &[("alidns", "223.5.5.5")]),
                make_group("trusted", &[("cloudflare", "1.1.1.1")]),
            ],
            vec![config::DnsRouteRule {
                r#match: "qname(suffix:cn)".into(),
                action: "cn_dns".into(),
            }],
            "trusted",
        );
        let router = DnsRouter::new(&config, RuleSetCache::new()).unwrap();

        // .cn → cn_dns group
        let result = router.match_query("example.cn", 1);
        assert_eq!(result.group.name, "cn_dns");

        // other → trusted group
        let result = router.match_query("example.com", 1);
        assert_eq!(result.group.name, "trusted");
    }

    /// Construct Ruleset cache with geosite/domain_list data.
    fn make_geosite_cache() -> RuleSetCache {
        use crate::ruleset::types::{DomainPattern, DomainPatternType, RuleSetData};
        let cache = RuleSetCache::new();
        let mut geosite = std::collections::HashMap::new();
        geosite.insert(
            "cn".to_string(),
            vec![DomainPattern {
                pattern_type: DomainPatternType::Suffix,
                value: "baidu.com".into(),
            }],
        );
        cache.insert("geosite_main".into(), RuleSetData::GeoSite { entries: geosite });
        cache.insert(
            "chinadom".into(),
            RuleSetData::DomainList(vec![DomainPattern {
                pattern_type: DomainPatternType::Full,
                value: "example.cn".into(),
            }]),
        );
        cache
    }

    #[test]
    fn test_top_level_qname_geosite_routing() {
        let config = make_config(
            vec![
                make_group("cn_dns", &[("alidns", "223.5.5.5")]),
                make_group("trusted", &[("cloudflare", "1.1.1.1")]),
            ],
            vec![config::DnsRouteRule {
                r#match: "qname(geosite:cn)".into(),
                action: "cn_dns".into(),
            }],
            "trusted",
        );
        let router = DnsRouter::new(&config, make_geosite_cache()).unwrap();

        // baidu.com hits geosite:cn → cn_dns
        let result = router.match_query("www.baidu.com", 1);
        assert_eq!(result.group.name, "cn_dns");
        // Case insensitive
        let result = router.match_query("WWW.BAIDU.COM", 1);
        assert_eq!(result.group.name, "cn_dns");
        // Others → trusted
        let result = router.match_query("www.google.com", 1);
        assert_eq!(result.group.name, "trusted");
    }

    #[test]
    fn test_top_level_qname_set_routing() {
        let config = make_config(
            vec![
                make_group("cn_dns", &[("alidns", "223.5.5.5")]),
                make_group("trusted", &[("cloudflare", "1.1.1.1")]),
            ],
            vec![config::DnsRouteRule {
                r#match: "qname(set:chinadom)".into(),
                action: "cn_dns".into(),
            }],
            "trusted",
        );
        let router = DnsRouter::new(&config, make_geosite_cache()).unwrap();

        // example.cn full hit
        let result = router.match_query("example.cn", 1);
        assert_eq!(result.group.name, "cn_dns");
        // Others → trusted
        let result = router.match_query("www.google.com", 1);
        assert_eq!(result.group.name, "trusted");
    }

    #[test]
    fn test_compile_route_rule_unknown_expression_errors() {
        // Unknown conditions no longer silently discarded, changed to compilation error
        let rule = config::DnsRouteRule {
            r#match: "bogus(foo)".into(),
            action: "g".into(),
        };
        assert!(compile_route_rule(&rule).is_err());
        // qname(geoip:...) invalid reference
        let rule = config::DnsRouteRule {
            r#match: "qname(geoip:cn)".into(),
            action: "g".into(),
        };
        assert!(compile_route_rule(&rule).is_err());
    }
}
