use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::warn;

use crate::config::{DnsConfig, DnsGroupConfig};
use crate::ruleset::cache::RuleSetCache;
use crate::ruleset::refparse::{match_domain_patterns, match_qname_value, parse_ref, RuleSetRef};

/// Result of matching a DNS query to a group and upstream
#[derive(Debug, Clone)]
pub struct DnsRouteResult {
    /// The selected DNS group
    pub group: DnsGroupConfig,
    /// The selected upstream label within the group
    pub upstream_label: String,
    /// Whether this group uses a proxy (None = direct)
    pub proxy_group: Option<String>,
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

/// Compiled in-group request routing rule
#[derive(Debug, Clone)]
struct CompiledRequestRule {
    match_type: DnsMatchType,
    match_value: String,
    negated: bool,
    upstream_label: String,
}

/// DNS Router — matches queries to groups and upstreams, checks responses
#[derive(Debug, Clone)]
pub struct DnsRouter {
    /// DNS groups indexed by name
    groups: Arc<HashMap<String, DnsGroupConfig>>,
    /// Compiled request routing rules per group (preprocessed at construction)
    request_rules: HashMap<String, Vec<CompiledRequestRule>>,
    /// Fallback upstream label per group
    request_fallback: HashMap<String, String>,
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

        // Pre-compile per-group request routing rules
        let mut request_rules = HashMap::new();
        let mut request_fallback = HashMap::new();
        for group in &config.groups {
            if let Some(ref routing) = group.request_routing {
                let compiled: Vec<CompiledRequestRule> = routing
                    .rules
                    .iter()
                    .map(compile_request_rule)
                    .collect::<Result<Vec<_>>>()?;
                request_rules.insert(group.name.clone(), compiled);
                request_fallback.insert(group.name.clone(), routing.fallback.clone());
            } else {
                // No request routing: use first upstream as fallback
                let fallback = group.upstream.first().map(|u| u.label.clone()).unwrap_or_default();
                request_fallback.insert(group.name.clone(), fallback);
            }
        }

        Ok(Self {
            groups: Arc::new(groups),
            request_rules,
            request_fallback,
            fallback_group,
            rules,
            rule_set_cache,
        })
    }

    /// Match a DNS query to a group and upstream
    pub fn match_query(&self, qname: &str, qtype: u16) -> DnsRouteResult {
        // Try top-level rules first
        for rule in &self.rules {
            if self.evaluate_match(rule, qname, qtype) {
                if let Some(group) = self.groups.get(&rule.target_group) {
                    return self.select_upstream(group, qname, qtype);
                }
            }
        }

        // Fallback
        if let Some(group) = self.groups.get(&self.fallback_group) {
            return self.select_upstream(group, qname, qtype);
        }

        // Last resort: use first available group
        if let Some(group) = self.groups.values().next() {
            return self.select_upstream(group, qname, qtype);
        }

        DnsRouteResult {
            group: DnsGroupConfig {
                name: "null".into(),
                proxy: "direct".into(),
                upstream: Vec::new(),
                request_routing: None,
                response_routing: None,
            },
            upstream_label: String::new(),
            proxy_group: None,
        }
    }

    /// Select an upstream within a group based on request routing rules
    fn select_upstream(&self, group: &DnsGroupConfig, qname: &str, qtype: u16) -> DnsRouteResult {
        let proxy_group = if group.proxy == "direct" {
            None
        } else {
            Some(group.proxy.clone())
        };

        // Evaluate compiled request routing rules
        let upstream_label = if let Some(rules) = self.request_rules.get(&group.name) {
            let mut matched_label = None;
            for rule in rules {
                let matched =
                    self.eval_match_type(&rule.match_type, &rule.match_value, qname, qtype);
                let matched = if rule.negated { !matched } else { matched };
                if matched {
                    matched_label = Some(rule.upstream_label.clone());
                    break;
                }
            }
            matched_label.unwrap_or_else(|| {
                self.request_fallback
                    .get(&group.name)
                    .cloned()
                    .unwrap_or_default()
            })
        } else {
            // No request routing configured: use first upstream
            group.upstream.first().map(|u| u.label.clone()).unwrap_or_default()
        };

        DnsRouteResult {
            group: group.clone(),
            upstream_label,
            proxy_group,
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

/// Compile a per-group request routing rule into a CompiledRequestRule
fn compile_request_rule(rule: &crate::config::DnsRouteRule) -> Result<CompiledRequestRule> {
    let raw = rule.r#match.trim();
    let upstream_label = rule.action.clone();

    if raw == "any" {
        return Ok(CompiledRequestRule {
            match_type: DnsMatchType::Any,
            match_value: String::new(),
            negated: false,
            upstream_label,
        });
    }

    if let Some(value) = raw.strip_prefix("qname(") {
        let value = value
            .strip_suffix(')')
            .ok_or_else(|| anyhow!("invalid qname rule: '{raw}'"))?;
        let negated = value.starts_with('!');
        let value = if negated { &value[1..] } else { value };
        let (match_type, match_value) = compile_qname_value(value, raw)?;
        return Ok(CompiledRequestRule {
            match_type,
            match_value,
            negated,
            upstream_label,
        });
    }

    if let Some(value) = raw.strip_prefix("qtype(") {
        let value = value
            .strip_suffix(')')
            .ok_or_else(|| anyhow!("invalid qtype rule: '{raw}'"))?;
        let negated = value.starts_with('!');
        let value = if negated { &value[1..] } else { value };
        return Ok(CompiledRequestRule {
            match_type: DnsMatchType::QType,
            match_value: value.to_string(),
            negated,
            upstream_label,
        });
    }

    Err(anyhow!("unsupported DNS request routing match expression: '{raw}'"))
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
            cache: config::DnsCacheConfig {
                enabled: true,
                max_size: 1024,
                max_ttl: 86400,
                min_ttl: 60,
                optimistic_cache: false,
                optimistic_cache_ttl: 3600,
            },
        }
    }

    fn make_group(name: &str, upstreams: &[(&str, &str)], request_routing: Option<config::DnsGroupRequestRouting>) -> config::DnsGroupConfig {
        config::DnsGroupConfig {
            name: name.to_string(),
            proxy: "direct".to_string(),
            upstream: upstreams
                .iter()
                .map(|(label, addr)| config::DnsUpstreamEntry {
                    label: label.to_string(),
                    address: addr.to_string(),
                })
                .collect(),
            request_routing,
            response_routing: None,
        }
    }

    #[test]
    fn test_select_upstream_no_routing_uses_first() {
        let config = make_config(
            vec![make_group("g1", &[("a", "1.1.1.1"), ("b", "2.2.2.2")], None)],
            vec![],
            "g1",
        );
        let router = DnsRouter::new(&config, RuleSetCache::new()).unwrap();
        let result = router.match_query("example.com", 1);
        assert_eq!(result.upstream_label, "a");
    }

    #[test]
    fn test_select_upstream_with_qname_rule() {
        let config = make_config(
            vec![make_group(
                "g1",
                &[("fast", "1.1.1.1"), ("slow", "2.2.2.2")],
                Some(config::DnsGroupRequestRouting {
                    rules: vec![config::DnsRouteRule {
                        r#match: "qname(google.com)".into(),
                        action: "fast".into(),
                    }],
                    fallback: "slow".into(),
                }),
            )],
            vec![],
            "g1",
        );
        let router = DnsRouter::new(&config, RuleSetCache::new()).unwrap();

        // google.com matches the rule → fast
        let result = router.match_query("google.com", 1);
        assert_eq!(result.upstream_label, "fast");

        // other.com does not match → fallback to slow
        let result = router.match_query("other.com", 1);
        assert_eq!(result.upstream_label, "slow");
    }

    #[test]
    fn test_select_upstream_with_qtype_rule() {
        let config = make_config(
            vec![make_group(
                "g1",
                &[("ipv4", "1.1.1.1"), ("ipv6", "2.2.2.2")],
                Some(config::DnsGroupRequestRouting {
                    rules: vec![config::DnsRouteRule {
                        r#match: "qtype(AAAA)".into(),
                        action: "ipv6".into(),
                    }],
                    fallback: "ipv4".into(),
                }),
            )],
            vec![],
            "g1",
        );
        let router = DnsRouter::new(&config, RuleSetCache::new()).unwrap();

        // AAAA query → ipv6
        let result = router.match_query("example.com", 28);
        assert_eq!(result.upstream_label, "ipv6");

        // A query → ipv4 (fallback)
        let result = router.match_query("example.com", 1);
        assert_eq!(result.upstream_label, "ipv4");
    }

    #[test]
    fn test_select_upstream_suffix_match() {
        let config = make_config(
            vec![make_group(
                "g1",
                &[("cn", "1.1.1.1"), ("intl", "2.2.2.2")],
                Some(config::DnsGroupRequestRouting {
                    rules: vec![config::DnsRouteRule {
                        r#match: "qname(suffix:cn)".into(),
                        action: "cn".into(),
                    }],
                    fallback: "intl".into(),
                }),
            )],
            vec![],
            "g1",
        );
        let router = DnsRouter::new(&config, RuleSetCache::new()).unwrap();

        // sub.example.cn matches suffix:cn → cn
        let result = router.match_query("sub.example.cn", 1);
        assert_eq!(result.upstream_label, "cn");

        // example.com does not match → intl
        let result = router.match_query("example.com", 1);
        assert_eq!(result.upstream_label, "intl");
    }

    #[test]
    fn test_select_upstream_any_rule() {
        let config = make_config(
            vec![make_group(
                "g1",
                &[("all", "1.1.1.1"), ("fallback", "2.2.2.2")],
                Some(config::DnsGroupRequestRouting {
                    rules: vec![config::DnsRouteRule {
                        r#match: "any".into(),
                        action: "all".into(),
                    }],
                    fallback: "fallback".into(),
                }),
            )],
            vec![],
            "g1",
        );
        let router = DnsRouter::new(&config, RuleSetCache::new()).unwrap();

        // any matches everything
        let result = router.match_query("anything.xyz", 1);
        assert_eq!(result.upstream_label, "all");
    }

    #[test]
    fn test_top_level_routing_to_group() {
        let config = make_config(
            vec![
                make_group("cn_dns", &[("alidns", "223.5.5.5")], None),
                make_group("trusted", &[("cloudflare", "1.1.1.1")], None),
            ],
            vec![config::DnsRouteRule {
                r#match: "qname(suffix:cn)".into(),
                action: "cn_dns".into(),
            }],
            "trusted",
        );
        let router = DnsRouter::new(&config, RuleSetCache::new()).unwrap();

        // .cn → cn_dns group → alidns
        let result = router.match_query("example.cn", 1);
        assert_eq!(result.upstream_label, "alidns");
        assert_eq!(result.group.name, "cn_dns");

        // other → trusted group → cloudflare
        let result = router.match_query("example.com", 1);
        assert_eq!(result.upstream_label, "cloudflare");
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
                make_group("cn_dns", &[("alidns", "223.5.5.5")], None),
                make_group("trusted", &[("cloudflare", "1.1.1.1")], None),
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
                make_group("cn_dns", &[("alidns", "223.5.5.5")], None),
                make_group("trusted", &[("cloudflare", "1.1.1.1")], None),
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
    fn test_request_routing_qname_geosite() {
        let config = make_config(
            vec![make_group(
                "g1",
                &[("cn_up", "1.1.1.1"), ("intl", "2.2.2.2")],
                Some(config::DnsGroupRequestRouting {
                    rules: vec![config::DnsRouteRule {
                        r#match: "qname(geosite:cn)".into(),
                        action: "cn_up".into(),
                    }],
                    fallback: "intl".into(),
                }),
            )],
            vec![],
            "g1",
        );
        let router = DnsRouter::new(&config, make_geosite_cache()).unwrap();

        let result = router.match_query("www.baidu.com", 1);
        assert_eq!(result.upstream_label, "cn_up");
        let result = router.match_query("www.google.com", 1);
        assert_eq!(result.upstream_label, "intl");
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
