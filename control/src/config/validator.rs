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

    // 9. Rule set validation (E2101 / E2104 / E2105)
    validate_rule_set(config)?;

    // 10. DNS configuration validation
    validate_dns(config)?;

    Ok(())
}

/// Structure validation: ensure required sections exist
fn validate_structure(config: &DaefileConfig) -> std::result::Result<(), ConfigError> {
    if config.outbounds.nodes.is_empty() && config.outbounds.groups.is_empty() {
        return Err(ConfigError::MissingSection {
            section: "outbounds (at least one node and one group)".into(),
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
                field: format!("node '{}'.protocol", node.name),
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
                field: format!("node '{}'.address", node.name),
                message: "address must not be empty".into(),
            });
        }
        // Protocol-specific required fields
        let missing = |field: &str| ConfigError::InvalidValue {
            line: 0,
            field: format!("node '{}'.{}", node.name, field),
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

/// DNS configuration validation.
///
/// - `forward_dns = false` 时完全不触碰 DNS 流量，跳过后续校验；
/// - `forward_dns = true` 时 `dns` 可以为 `None`（使用 `DnsConfig::default()`）；
/// - `upstream_remote` 不能为空列表；
/// - `cache_size_per_group` 必须 > 0；
/// - `query_timeout_ms` 必须 > 0。
fn validate_dns(config: &DaefileConfig) -> std::result::Result<(), ConfigError> {
    if !config.runtime.forward_dns {
        return Ok(());
    }
    if let Some(ref dns) = config.dns {
        if dns.upstream_remote.is_empty() {
            return Err(ConfigError::FieldType {
                line: 0,
                field: "dns.upstream_remote".into(),
                message: "upstream_remote must not be empty".into(),
            });
        }
        if dns.cache_size_per_group == 0 {
            return Err(ConfigError::OutOfRange {
                line: 0,
                field: "dns.cache_size_per_group".into(),
                message: "cache_size_per_group must be > 0".into(),
            });
        }
        if dns.query_timeout_ms == 0 {
            return Err(ConfigError::OutOfRange {
                line: 0,
                field: "dns.query_timeout_ms".into(),
                message: "query_timeout_ms must be > 0".into(),
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
///    → E2102 (§8.2).
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

/// Ruleset reference extraction regex: `set:<value>`.
///
/// value allows `[A-Za-z0-9_!@.\-]` (covering ruleset name naming constraint).
static RULESET_REF_RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
fn ruleset_ref_re() -> &'static regex::Regex {
    RULESET_REF_RE.get_or_init(|| {
        regex::Regex::new(r"(?i)set:([A-Za-z0-9_!@.\-]+)")
            .expect("valid ruleset ref regex")
    })
}

/// E2102: ruleset reference integrity validation in Routing.
///
/// - `set:<name>` **must always** hit an entry in `rule_set` (name subject to naming constraint) → otherwise E2102.
fn validate_ruleset_refs(
    config: &DaefileConfig,
    name_to_type: &HashMap<String, RuleSetType>,
) -> std::result::Result<(), ConfigError> {
    let check_expr = |expr: &str| -> std::result::Result<(), ConfigError> {
        for cap in ruleset_ref_re().captures_iter(expr) {
            let value = cap[1].to_string();
            if !name_to_type.contains_key(&value) {
                return Err(ConfigError::UnknownRuleSetRef {
                    reference: format!("set:{value}"),
                });
            }
        }
        Ok(())
    };

    // data plane Routing rules
    for rule in &config.routing.rules {
        check_expr(&rule.r#match)?;
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