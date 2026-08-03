use std::collections::HashMap;
use std::sync::Arc;
use crate::config::{DnsConfig, DnsGroupConfig};

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
    /// Always matches
    Any,
}

impl DnsRouter {
    pub fn new(config: &DnsConfig) -> Self {
        let mut groups = HashMap::new();
        for group in &config.groups {
            groups.insert(group.name.clone(), group.clone());
        }

        let rules: Vec<DnsRouteRule> = config
            .routing
            .rules
            .iter()
            .filter_map(compile_route_rule)
            .collect();

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
                    .filter_map(compile_request_rule)
                    .collect();
                request_rules.insert(group.name.clone(), compiled);
                request_fallback.insert(group.name.clone(), routing.fallback.clone());
            } else {
                // No request routing: use first upstream as fallback
                let fallback = group.upstream.first().map(|u| u.label.clone()).unwrap_or_default();
                request_fallback.insert(group.name.clone(), fallback);
            }
        }

        Self {
            groups: Arc::new(groups),
            request_rules,
            request_fallback,
            fallback_group,
            rules,
        }
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
                let matched = match rule.match_type {
                    DnsMatchType::QName => {
                        let value = rule.match_value.trim_start_matches("suffix:");
                        let value = value.trim_start_matches('.');
                        qname == value || qname.ends_with(&format!(".{}", value))
                    }
                    DnsMatchType::QType => {
                        let type_str = rule.match_value.to_uppercase();
                        match type_str.as_str() {
                            "A" => qtype == 1,
                            "AAAA" => qtype == 28,
                            "ANY" => qtype == 255,
                            _ => false,
                        }
                    }
                    DnsMatchType::Any => true,
                };
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

    /// Evaluate a single rule against query parameters
    fn evaluate_match(&self, rule: &DnsRouteRule, qname: &str, qtype: u16) -> bool {
        let matched = match rule.match_type {
            DnsMatchType::QName => {
                // Simple suffix match
                let value = rule.match_value.trim_start_matches("suffix:");
                let value = value.trim_start_matches('.');
                qname == value || qname.ends_with(&format!(".{}", value))
            }
            DnsMatchType::QType => {
                let type_str = rule.match_value.to_uppercase();
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
        };

        if rule.negated { !matched } else { matched }
    }
}

/// Compile a routing rule string into a DnsRouteRule
fn compile_route_rule(rule: &crate::config::DnsRouteRule) -> Option<DnsRouteRule> {
    let raw = rule.r#match.trim();
    let target_group = rule.action.clone();

    if raw == "any" {
        return Some(DnsRouteRule {
            match_type: DnsMatchType::Any,
            match_value: String::new(),
            negated: false,
            target_group,
        });
    }

    if let Some(value) = raw.strip_prefix("qname(") {
        let value = value.strip_suffix(')')?;
        let negated = value.starts_with('!');
        let value = if negated { &value[1..] } else { value };
        return Some(DnsRouteRule {
            match_type: DnsMatchType::QName,
            match_value: value.to_string(),
            negated,
            target_group,
        });
    }

    if let Some(value) = raw.strip_prefix("qtype(") {
        let value = value.strip_suffix(')')?;
        let negated = value.starts_with('!');
        let value = if negated { &value[1..] } else { value };
        return Some(DnsRouteRule {
            match_type: DnsMatchType::QType,
            match_value: value.to_string(),
            negated,
            target_group,
        });
    }

    None
}

/// Compile a per-group request routing rule into a CompiledRequestRule
fn compile_request_rule(rule: &crate::config::DnsRouteRule) -> Option<CompiledRequestRule> {
    let raw = rule.r#match.trim();
    let upstream_label = rule.action.clone();

    if raw == "any" {
        return Some(CompiledRequestRule {
            match_type: DnsMatchType::Any,
            match_value: String::new(),
            negated: false,
            upstream_label,
        });
    }

    if let Some(value) = raw.strip_prefix("qname(") {
        let value = value.strip_suffix(')')?;
        let negated = value.starts_with('!');
        let value = if negated { &value[1..] } else { value };
        return Some(CompiledRequestRule {
            match_type: DnsMatchType::QName,
            match_value: value.to_string(),
            negated,
            upstream_label,
        });
    }

    if let Some(value) = raw.strip_prefix("qtype(") {
        let value = value.strip_suffix(')')?;
        let negated = value.starts_with('!');
        let value = if negated { &value[1..] } else { value };
        return Some(CompiledRequestRule {
            match_type: DnsMatchType::QType,
            match_value: value.to_string(),
            negated,
            upstream_label,
        });
    }

    None
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
        let router = DnsRouter::new(&config);
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
        let router = DnsRouter::new(&config);

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
        let router = DnsRouter::new(&config);

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
        let router = DnsRouter::new(&config);

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
        let router = DnsRouter::new(&config);

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
        let router = DnsRouter::new(&config);

        // .cn → cn_dns group → alidns
        let result = router.match_query("example.cn", 1);
        assert_eq!(result.upstream_label, "alidns");
        assert_eq!(result.group.name, "cn_dns");

        // other → trusted group → cloudflare
        let result = router.match_query("example.com", 1);
        assert_eq!(result.upstream_label, "cloudflare");
        assert_eq!(result.group.name, "trusted");
    }
}
