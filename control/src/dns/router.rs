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

/// DNS Router — matches queries to groups and upstreams, checks responses
#[derive(Debug, Clone)]
pub struct DnsRouter {
    /// DNS groups indexed by name
    groups: Arc<HashMap<String, DnsGroupConfig>>,
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
            .filter_map(|rule| compile_route_rule(rule))
            .collect();

        let fallback_group = if config.routing.fallback.is_empty() {
            // Use first group as fallback
            config
                .groups
                .first()
                .map(|g| g.name.clone())
                .unwrap_or_default()
        } else {
            config.routing.fallback.clone()
        };

        Self {
            groups: Arc::new(groups),
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
                    return self.select_upstream(group);
                }
            }
        }

        // Fallback
        if let Some(group) = self.groups.get(&self.fallback_group) {
            return self.select_upstream(group);
        }

        // Last resort: use first available group
        if let Some(group) = self.groups.values().next() {
            return self.select_upstream(group);
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

    /// Select an upstream within a group based on request routing
    fn select_upstream(&self, group: &DnsGroupConfig) -> DnsRouteResult {
        let proxy_group = if group.proxy == "direct" {
            None
        } else {
            Some(group.proxy.clone())
        };

        // If no request routing, use first upstream
        let upstream_label = match &group.request_routing {
            Some(routing) => routing.fallback.clone(),
            None => group.upstream.first().map(|u| u.label.clone()).unwrap_or_default(),
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
