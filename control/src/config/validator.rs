//! Semantic validation for parsed configurations.
//!
//! Performs structure, range, uniqueness, reference and protocol-specific
//! checks after [`crate::config::parser::parse_daefile`] succeeds.

use super::*;
use std::collections::{HashMap, HashSet};

use crate::ruleset::types::{parse_period, parse_time};
// ============================================================================
// Semantic Validator
// ============================================================================

/// Perform semantic validation on a parsed configuration
///
/// Validation order (ref. plan §12.3):
/// 1. Structure validation — required sections exist
/// 2. Type validation — integer/boolean/hex format (done during parsing)
/// 3. Range validation — port 1-65535, MTU 576-9000, etc.
/// 4. Uniqueness validation — node names/group names not duplicated
/// 5. Reference validation — group references valid nodes, routing references valid groups
/// 6. Mutual exclusion — import vs explicit protocol
/// 7. Protocol validation — socks5 only
///
/// # Parameters
///
/// * `config` — Parsed configuration
///
/// # Errors
///
/// Returns the first semantic error detected.
pub fn validate_config(config: &DaefileConfig) -> std::result::Result<(), ConfigError> {
    // 1. Structure validation
    validate_structure(config)?;

    // 2. Range validation
    validate_ranges(config)?;

    // 3. Uniqueness validation
    validate_uniqueness(config)?;

    // 4. Reference validation (group→node, routing→group)
    validate_references(config)?;

    // 5. Mutual exclusion and protocol validation
    validate_node_fields(config)?;

    // 6. Group internal validation (select/auto rules)
    validate_group_internals(config)?;

    // 7. Routing fallback validation
    validate_fallback(config)?;

    // 8. API validation
    validate_api(config)?;

    // 9. DNS validation
    validate_dns(config)?;

    // 10. Rule set validation (E2101 / E2104 / E2105)
    validate_rule_set(config)?;

    Ok(())
}

/// Structure validation: ensure required sections exist
fn validate_structure(config: &DaefileConfig) -> std::result::Result<(), ConfigError> {
    if config.outbounds.nodes.is_empty() && config.outbounds.groups.is_empty() {
        return Err(ConfigError::MissingSection {
            section: "outbounds (至少一个节点和一个组)".into(),
        });
    }
    if config.routing.fallback.is_empty() {
        return Err(ConfigError::MissingSection {
            section: "routing.fallback".into(),
        });
    }
    Ok(())
}

/// Range validation
fn validate_ranges(config: &DaefileConfig) -> std::result::Result<(), ConfigError> {
    // tproxy_port: 1-65535
    if config.runtime.tproxy_port < 1 {
        return Err(ConfigError::OutOfRange {
            line: 0,
            field: "tproxy_port".into(),
            message: format!("port {} is less than minimum value 1", config.runtime.tproxy_port),
        });
    }

    // Node dial_timeout_ms: 100-600000
    for node in &config.outbounds.nodes {
        if node.dial_timeout_ms < 100 || node.dial_timeout_ms > 600_000 {
            return Err(ConfigError::OutOfRange {
                line: 0,
                field: "dial_timeout_ms".into(),
                message: format!(
                    "node '{}' dial_timeout_ms {} is not in range 100-600000",
                    node.name, node.dial_timeout_ms
                ),
            });
        }
    }

    // Process exclusion validation
    if let Some(ref pe) = config.process_exclusion {
        if pe.gc_interval_sec < 1 || pe.gc_interval_sec > 3600 {
            return Err(ConfigError::OutOfRange {
                line: 0,
                field: "gc_interval_sec".into(),
                message: format!("gc_interval_sec {} is not in range 1-3600", pe.gc_interval_sec),
            });
        }
        if pe.stale_after_sec < pe.gc_interval_sec {
            return Err(ConfigError::OutOfRange {
                line: 0,
                field: "stale_after_sec".into(),
                message: format!(
                    "stale_after_sec {} should be >= gc_interval_sec {}",
                    pe.stale_after_sec, pe.gc_interval_sec
                ),
            });
        }
    }

    Ok(())
}

/// Uniqueness validation: node names/group names must not be duplicated
fn validate_uniqueness(config: &DaefileConfig) -> std::result::Result<(), ConfigError> {
    let mut node_names = HashSet::new();
    for node in &config.outbounds.nodes {
        if !node_names.insert(&node.name) {
            return Err(ConfigError::DuplicateNode {
                name: node.name.clone(),
            });
        }
    }

    let mut group_names = HashSet::new();
    for group in &config.outbounds.groups {
        if !group_names.insert(&group.name) {
            return Err(ConfigError::DuplicateGroup {
                name: group.name.clone(),
            });
        }
    }

    Ok(())
}

/// Collect all node names into a set
fn collect_node_names(config: &DaefileConfig) -> HashSet<&str> {
    config.outbounds.nodes.iter().map(|n| n.name.as_str()).collect()
}

/// Collect all group names into a set
fn collect_group_names(config: &DaefileConfig) -> HashSet<&str> {
    config.outbounds.groups.iter().map(|g| g.name.as_str()).collect()
}

/// Reference validation
fn validate_references(config: &DaefileConfig) -> std::result::Result<(), ConfigError> {
    let node_names = collect_node_names(config);
    let group_names = collect_group_names(config);

    for group in &config.outbounds.groups {
        for selector in &group.selectors {
            if let NodeSelector::List { nodes } = selector {
                for node_name in nodes {
                    if !node_names.contains(node_name.as_str()) {
                        return Err(ConfigError::UnknownNode {
                            group: group.name.clone(),
                            node: node_name.clone(),
                        });
                    }
                }
            }
            if let NodeSelector::Regex { pattern } = selector {
                // Check if regex is compilable
                let pat = if pattern == "*" { ".*" } else { pattern.as_str() };
                if regex::Regex::new(pat).is_err() {
                    return Err(ConfigError::RegexSyntax {
                        group: group.name.clone(),
                        pattern: pattern.clone(),
                        detail: "regex compilation failed".into(),
                    });
                }
                // Check if it matches at least one node
                let re = regex::Regex::new(pat).unwrap();
                let matched: Vec<&str> = node_names.iter().filter(|n| re.is_match(n)).copied().collect();
                if matched.is_empty() {
                    return Err(ConfigError::RegexNoMatch {
                        group: group.name.clone(),
                        pattern: pattern.clone(),
                    });
                }
            }
        }
    }

    // Validate proxy(group_name) references in routing rules
    for rule in &config.routing.rules {
        if let Some(group_name) = extract_proxy_group(&rule.action) {
            if !group_names.contains(group_name) {
                return Err(ConfigError::UnknownGroup {
                    group: group_name.to_string(),
                });
            }
        }
    }

    Ok(())
}

/// Extract proxy group name from an action string
pub(crate) fn extract_proxy_group(action: &str) -> Option<&str> {
    let action = action.trim();
    if let Some(inner) = action.strip_prefix("proxy(") {
        if let Some(name) = inner.strip_suffix(')') {
            let name = name.trim();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

/// Mutual exclusion and protocol validation
fn validate_node_fields(config: &DaefileConfig) -> std::result::Result<(), ConfigError> {
    const SUPPORTED_PROTOCOLS: &[&str] = &["socks5", "shadowsocks", "trojan", "tuic", "juicity", "vmess"];

    for node in &config.outbounds.nodes {
        // Protocol validation
        if !SUPPORTED_PROTOCOLS.contains(&node.protocol.as_str()) {
            return Err(ConfigError::InvalidValue {
                line: 0,
                field: format!("节点 '{}'.protocol", node.name),
                message: format!(
                    "unsupported protocol '{}', supported protocols: {}",
                    node.protocol,
                    SUPPORTED_PROTOCOLS.join(", ")
                ),
            });
        }
        // Address must not be empty
        if node.address.is_empty() {
            return Err(ConfigError::FieldType {
                line: 0,
                field: format!("节点 '{}'.address", node.name),
                message: "address must not be empty".into(),
            });
        }
        // Protocol-specific required fields
        let missing = |field: &str| ConfigError::InvalidValue {
            line: 0,
            field: format!("节点 '{}'.{}", node.name, field),
            message: format!(
                "missing required field '{}' for protocol '{}'",
                field, node.protocol
            ),
        };
        match node.protocol.as_str() {
            "shadowsocks" => {
                if node.cipher.is_none() {
                    return Err(missing("cipher"));
                }
                if node.password.is_none() {
                    return Err(missing("password"));
                }
            }
            "trojan" => {
                if node.password.is_none() {
                    return Err(missing("password"));
                }
            }
            "tuic" | "juicity" if node.uuid.is_none() => {
                return Err(missing("uuid"));
            }
            "tuic" | "juicity" => {
                if node.password.is_none() {
                    return Err(missing("password"));
                }
            }
            "vmess" if node.uuid.is_none() => {
                return Err(missing("uuid"));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Group internal rule validation (select/auto mutual exclusion)
fn validate_group_internals(config: &DaefileConfig) -> std::result::Result<(), ConfigError> {
    for group in &config.outbounds.groups {
        match group.group_type {
            GroupType::Auto => {
                if group.selected.is_some() {
                    return Err(ConfigError::AutoHasSelected {
                        name: group.name.clone(),
                    });
                }
            }
            GroupType::Select => {
                if group.policy.is_some() {
                    return Err(ConfigError::SelectHasPolicy {
                        name: group.name.clone(),
                    });
                }
                // 'selected' must be present
                let selected = group.selected.as_ref().ok_or_else(|| {
                    ConfigError::SelectMissingSelected {
                        name: group.name.clone(),
                    }
                })?;
                // 'selected' must be in the group's reachable set
                let node_names = collect_node_names(config);
                if !node_names.contains(selected.as_str()) {
                    return Err(ConfigError::SelectSelectedUnreachable {
                        name: group.name.clone(),
                        selected: selected.clone(),
                    });
                }
            }
        }

        // At least one selector is required
        if group.selectors.is_empty() {
            return Err(ConfigError::MissingSection {
                section: format!("group '{}' has no node selectors", group.name),
            });
        }
    }
    Ok(())
}

/// Routing fallback validation
fn validate_fallback(config: &DaefileConfig) -> std::result::Result<(), ConfigError> {
    let fallback = config.routing.fallback.trim();
    if fallback == "direct" {
        return Ok(());
    }
    if let Some(group_name) = extract_proxy_group(fallback) {
        let group_names = collect_group_names(config);
        if !group_names.contains(group_name) {
            return Err(ConfigError::UnknownGroup {
                group: group_name.to_string(),
            });
        }
        return Ok(());
    }
    Err(ConfigError::InvalidValue {
        line: 0,
        field: "routing.fallback".into(),
        message: format!("fallback must be 'direct' or 'proxy(group_name)', got: '{}'", fallback),
    })
}

/// API validation
fn validate_api(config: &DaefileConfig) -> std::result::Result<(), ConfigError> {
    if let Some(ref api) = config.api {
        if api.enabled {
            // Listen address format validation (rough check for host:port)
            if !api.listen.contains(':') {
                return Err(ConfigError::ApiListenInvalid {
                    value: api.listen.clone(),
                });
            }
            let port_str = api.listen.rsplit(':').next().unwrap_or("");
            if let Ok(port) = port_str.parse::<u16>() {
                if port < 1 {
                    return Err(ConfigError::ApiListenInvalid {
                        value: api.listen.clone(),
                    });
                }
            } else {
                return Err(ConfigError::ApiListenInvalid {
                    value: api.listen.clone(),
                });
            }

            // Token must not be empty
            if api.token.is_empty() {
                return Err(ConfigError::ApiTokenEmpty);
            }

            // When tls: true, cert and key are required
            if api.tls
                && (api.cert.is_none() || api.key.is_none()) {
                    return Err(ConfigError::ApiTlsMissingCertKey);
                }
        }
    }
    Ok(())
}

/// DNS validation
fn validate_dns(config: &DaefileConfig) -> std::result::Result<(), ConfigError> {
    let dns = match config.dns.as_ref() {
        Some(d) => d,
        None => return Ok(()),
    };

    // Validate starting_dns
    if dns.starting_dns.ip_version_prefer != 4 && dns.starting_dns.ip_version_prefer != 6 {
        return Err(ConfigError::DnsIpVersionPreferInvalid {
            value: dns.starting_dns.ip_version_prefer,
        });
    }
    if dns.starting_dns.upstream.is_empty() {
        return Err(ConfigError::DnsStartingDnsNoUpstream);
    }

    // Collect DNS group names
    let dns_group_names: std::collections::HashSet<&str> =
        dns.groups.iter().map(|g| g.name.as_str()).collect();

    // Validate DNS group names uniqueness
    let mut seen = std::collections::HashSet::new();
    for group in &dns.groups {
        if !seen.insert(&group.name) {
            return Err(ConfigError::DnsDuplicateGroup {
                name: group.name.clone(),
            });
        }
    }

    // Validate each DNS group
    for group in &dns.groups {
        // proxy must be "direct" or reference a valid proxy group
        if group.proxy != "direct" {
            let proxy_group_names: std::collections::HashSet<&str> =
                config.outbounds.groups.iter().map(|g| g.name.as_str()).collect();
            if !proxy_group_names.contains(group.proxy.as_str()) {
                return Err(ConfigError::DnsUnknownProxyGroup {
                    dns_group: group.name.clone(),
                    proxy_group: group.proxy.clone(),
                });
            }
        }

        // At least one upstream
        if group.upstream.is_empty() {
            return Err(ConfigError::DnsGroupNoUpstream {
                group: group.name.clone(),
            });
        }

        // Validate request_routing actions reference valid upstream labels
        if let Some(ref rr) = group.request_routing {
            let upstream_labels: std::collections::HashSet<&str> =
                group.upstream.iter().map(|u| u.label.as_str()).collect();
            // Also check against DNS group names for cross-group routing
            for rule in &rr.rules {
                if !upstream_labels.contains(rule.action.as_str())
                    && !dns_group_names.contains(rule.action.as_str())
                {
                    return Err(ConfigError::DnsUnknownGroup {
                        group: rule.action.clone(),
                    });
                }
            }
            if !upstream_labels.contains(rr.fallback.as_str())
                && !dns_group_names.contains(rr.fallback.as_str())
            {
                return Err(ConfigError::DnsFallbackUnknownGroup {
                    group: rr.fallback.clone(),
                });
            }
        }

        // Validate response_routing
        if let Some(ref resp) = group.response_routing {
            if resp.fallback != "accept" && resp.fallback != "reject" {
                // Could also be an upstream label for requery
                let upstream_labels: std::collections::HashSet<&str> =
                    group.upstream.iter().map(|u| u.label.as_str()).collect();
                if !upstream_labels.contains(resp.fallback.as_str()) {
                    return Err(ConfigError::DnsUnknownGroup {
                        group: resp.fallback.clone(),
                    });
                }
            }
        }
    }

    // Validate top-level DNS routing references
    if !dns.routing.fallback.is_empty()
        && !dns_group_names.contains(dns.routing.fallback.as_str()) {
            return Err(ConfigError::DnsFallbackUnknownGroup {
                group: dns.routing.fallback.clone(),
            });
        }
    for rule in &dns.routing.rules {
        if !dns_group_names.contains(rule.action.as_str()) {
            return Err(ConfigError::DnsUnknownGroup {
                group: rule.action.clone(),
            });
        }
    }

    Ok(())
}

/// Rule set validation (design §5.3 / §8.2).
///
/// 1. name uniqueness (including default=block name, parser fills block name into `name`) → E2101;
///    Naming constraint `[a-zA-Z0-9_-]`, length ≤ 63 → E1203 `InvalidValue`;
/// 2. URL protocol / `#sha256=` validation → E2105;
/// 3. `update` missing / invalid time format (includes seconds) / `period` invalid unit → E2104;
/// 4. reference integrity (`set:`/`geoip:`/`geosite:` in data plane / DNS routing / DNS response Routing)
///    → E2102（§8.2）。
///
/// E2103 (compile-time data missing) triggered by matcher / DNS routing at compile phase.
fn validate_rule_set(config: &DaefileConfig) -> std::result::Result<(), ConfigError> {
    let mut seen = HashSet::new();
    // name → type (for E2102 reference integrity validation)
    let mut name_to_type: HashMap<String, RuleSetType> = HashMap::new();
    for entry in &config.rule_set {
        let name = &entry.name;
        name_to_type.insert(entry.name.clone(), entry.r#type);

        // Naming constraint: [a-zA-Z0-9_-], length ≤ 63
        if name.is_empty()
            || name.len() > 63
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(ConfigError::InvalidValue {
                line: 0,
                field: "rule_set.name".into(),
                message: format!(
                    "rule set name '{}' violates naming constraint `[a-zA-Z0-9_-]` and length <= 63",
                    name
                ),
            });
        }

        // E2101: name uniqueness (including default=block name)
        if !seen.insert(name.as_str()) {
            return Err(ConfigError::DuplicateRuleSet {
                name: name.clone(),
            });
        }

        // E2105: URL validation
        validate_rule_set_url(entry)?;

        // E2104: update validation
        validate_rule_set_update(entry)?;
    }

    // E2102: reference integrity (data plane / DNS routing / DNS response Routing)
    validate_ruleset_refs(config, &name_to_type)?;

    Ok(())
}

/// Ruleset reference extraction regex: `(geoip|geosite|set):<value>`.
///
/// value allows `[A-Za-z0-9_!@.\-]` (covering ruleset name naming constraint and geosite category names like
/// `geolocation-!cn`). Static phase only validates `set:` name integrity and geoip/geosite
/// entry existence; whether specific code exists in dat data is validated at compile time (E2103).
static RULESET_REF_RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
fn ruleset_ref_re() -> &'static regex::Regex {
    RULESET_REF_RE.get_or_init(|| {
        regex::Regex::new(r"(?i)(geoip|geosite|set):([A-Za-z0-9_!@.\-]+)")
            .expect("valid ruleset ref regex")
    })
}

/// E2102: ruleset reference integrity validation in Routing / DNS routing / DNS response Routing.
///
/// - `set:<name>` **must always** hit an entry in `rule_set` (name subject to naming constraint) → otherwise E2102;
/// - `geoip:<code>` / `geosite:<code>`: **when `rule_set` is configured** at least one
///   entry of corresponding type → otherwise E2102; when `rule_set` is not configured at all, allow (`geoip:private`
///   has built-in fallback; whether specific `geosite:`/`geoip:` code exists is validated at compile time E2103).
fn validate_ruleset_refs(
    config: &DaefileConfig,
    name_to_type: &HashMap<String, RuleSetType>,
) -> std::result::Result<(), ConfigError> {
    let has_geoip = name_to_type.values().any(|t| *t == RuleSetType::GeoIp);
    let has_geosite = name_to_type.values().any(|t| *t == RuleSetType::GeoSite);
    // When rule_set is not configured at all, geoip/geosite entry existence is handled at compile time (E2103)
    let rule_set_configured = !name_to_type.is_empty();

    let check_expr = |expr: &str| -> std::result::Result<(), ConfigError> {
        for cap in ruleset_ref_re().captures_iter(expr) {
            let kind = cap[1].to_ascii_lowercase();
            let value = cap[2].to_string();
            match kind.as_str() {
                "set" => {
                    if !name_to_type.contains_key(&value) {
                        return Err(ConfigError::UnknownRuleSetRef {
                            reference: format!("set:{value}"),
                        });
                    }
                }
                "geoip" => {
                    if rule_set_configured && !has_geoip {
                        return Err(ConfigError::UnknownRuleSetRef {
                            reference: format!("geoip:{value}"),
                        });
                    }
                }
                "geosite" => {
                    if rule_set_configured && !has_geosite {
                        return Err(ConfigError::UnknownRuleSetRef {
                            reference: format!("geosite:{value}"),
                        });
                    }
                }
                _ => {}
            }
        }
        Ok(())
    };

    // data plane Routing rules
    for rule in &config.routing.rules {
        check_expr(&rule.r#match)?;
    }

    // DNS top-level Routing + intra-group request/response Routing
    if let Some(dns) = &config.dns {
        for rule in &dns.routing.rules {
            check_expr(&rule.r#match)?;
        }
        for group in &dns.groups {
            if let Some(rr) = &group.request_routing {
                for rule in &rr.rules {
                    check_expr(&rule.r#match)?;
                }
            }
            if let Some(resp) = &group.response_routing {
                for rule in &resp.rules {
                    check_expr(&rule.r#match)?;
                }
            }
        }
    }

    Ok(())
}

/// E2105: URL must start with `http://` / `https://`; `#sha256=` fragment is 64 hex digits.
fn validate_rule_set_url(entry: &RuleSetConfig) -> std::result::Result<(), ConfigError> {
    let name = &entry.name;
    let url = entry.url.trim();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(ConfigError::InvalidRuleSetUrl {
            name: name.clone(),
            message: format!("url must start with http:// or https://, got: '{}'", entry.url),
        });
    }
    if let Some((_, fragment)) = url.split_once('#') {
        if let Some(hex) = fragment.strip_prefix("sha256=") {
            if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(ConfigError::InvalidRuleSetUrl {
                    name: name.clone(),
                    message: format!(
                        "#sha256= fragment must be a 64-char hex digest, got: '{}'",
                        hex
                    ),
                });
            }
        }
    }
    Ok(())
}

/// E2104: `update` missing / invalid time format (includes second-level) / `period` has invalid unit.
fn validate_rule_set_update(entry: &RuleSetConfig) -> std::result::Result<(), ConfigError> {
    let name = &entry.name;
    let update = match &entry.update {
        Some(u) => u,
        None => {
            return Err(ConfigError::InvalidRuleSetUpdate {
                name: name.clone(),
                message: "missing `update` (provide exactly one of `time: HH:MM` or `period: 3h2m`)"
                    .into(),
            });
        }
    };
    match update {
        RuleSetUpdate::Time(t) => {
            if let Err(e) = parse_time(t) {
                return Err(ConfigError::InvalidRuleSetUpdate {
                    name: name.clone(),
                    message: e,
                });
            }
        }
        RuleSetUpdate::Period(p) => {
            if let Err(e) = parse_period(p) {
                return Err(ConfigError::InvalidRuleSetUpdate {
                    name: name.clone(),
                    message: e,
                });
            }
        }
    }
    Ok(())
}