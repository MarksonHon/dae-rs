//! Configuration types, daefile parsing, validation and protocol conversion.
//!
//! Parses daefile (Caddyfile-like syntax) configuration text into a normalized
//! [`DaefileConfig`] structure, performs semantic validation, and converts
//! protocol import URIs into node fields. Core flow:
//!
//! 1. [`parser::parse_daefile`] — Parse daefile text into [`DaefileConfig`]
//! 2. [`validator::validate_config`] — Perform semantic validation on the parsed config
//! 3. [`protocol::parse_import_url`] — Convert protocol import URIs into node fields
//! 4. After validation, the config can be serialized to normalized JSON via `serde_json::to_string_pretty`
//!
//! # Module Organization
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`parser`] | daefile → [`DaefileConfig`] text parsing |
//! | [`validator`] | Semantic validation of parsed configs |
//! | [`protocol`] | Per-protocol import string conversion |
//! | [`example`] | Example daefile configurations |
//!
//! # Examples
//!
//! ```rust
//! use control::config::{parse_daefile, validate_config, default_config_example};
//!
//! let input = default_config_example();
//! let config = parse_daefile(input).unwrap();
//! validate_config(&config).unwrap();
//! let json = serde_json::to_string_pretty(&config).unwrap();
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use crate::ruleset::types::{RuleSetConfig, RuleSetType, RuleSetUpdate};

// ============================================================================
// Error Types & Diagnostic Codes
// ============================================================================

/// Configuration parsing and validation errors
///
/// Each error includes a diagnostic code (e.g., `E1001`) and line number for easy problem location.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    // ── Syntax Errors ──
    /// E1001: Syntax error (with line information)
    #[error("[E1001] Line {line}: syntax error: {message}")]
    Syntax {
        line: usize,
        message: String,
    },

    // ── Structure Errors ──
    /// E1101: Missing required section
    #[error("[E1101] Missing required section: {section}")]
    MissingSection {
        section: String,
    },

    // ── Type / Range Errors ──
    /// E1201: Field type error
    #[error("[E1201] Line {line}: field '{field}' type error: {message}")]
    FieldType {
        line: usize,
        field: String,
        message: String,
    },
    /// E1202: Field value out of range
    #[error("[E1202] Line {line}: field '{field}' out of range: {message}")]
    OutOfRange {
        line: usize,
        field: String,
        message: String,
    },
    /// E1203: Invalid field value (invalid enum variant)
    #[error("[E1203] Line {line}: field '{field}' invalid value: {message}")]
    InvalidValue {
        line: usize,
        field: String,
        message: String,
    },

    // ── Uniqueness Errors ──
    /// E1301: Duplicate node name
    #[error("[E1301] Duplicate node name: '{name}'")]
    DuplicateNode {
        name: String,
    },
    /// E1302: Duplicate group name
    #[error("[E1302] Duplicate group name: '{name}'")]
    DuplicateGroup {
        name: String,
    },

    // ── Reference Errors ──
    /// E1401: Group references unknown node
    #[error("[E1401] Group '{group}' references unknown node: '{node}'")]
    UnknownNode {
        group: String,
        node: String,
    },
    /// E1402: Routing references unknown group
    #[error("[E1402] Routing references unknown group: '{group}'")]
    UnknownGroup {
        group: String,
    },

    // ── Mutual Exclusion Errors ──
    /// E1501: Node declares both import and explicit fields
    #[error("[E1501] Node '{name}' declares both import and explicit protocol field")]
    ImportConflict {
        name: String,
    },
    /// E1502: Import link is unresolvable or protocol not implemented
    #[error("[E1502] Node '{name}' import link is unresolvable: {url}")]
    ImportInvalid {
        name: String,
        url: String,
    },

    // ── Regex Errors ──
    /// E1601: Invalid regex syntax in group
    #[error("[E1601] Group '{group}' invalid regex syntax: {pattern}, detail: {detail}")]
    RegexSyntax {
        group: String,
        pattern: String,
        detail: String,
    },
    /// E1602: Group regex matches no nodes
    #[error("[E1602] Group '{group}' regex '{pattern}' matches no nodes")]
    RegexNoMatch {
        group: String,
        pattern: String,
    },

    // ── Select/Auto Group Errors ──
    /// E1701: Select group missing 'selected' field
    #[error("[E1701] Select group '{name}' missing 'selected' field")]
    SelectMissingSelected {
        name: String,
    },
    /// E1702: Select group's 'selected' reference not in group's reachable set
    #[error("[E1702] Select group '{name}' selected node '{selected}' not in group's reachable set")]
    SelectSelectedUnreachable {
        name: String,
        selected: String,
    },
    /// E1703: Select group has 'policy' field
    #[error("[E1703] Select group '{name}' should not have 'policy' field")]
    SelectHasPolicy {
        name: String,
    },
    /// E1704: Auto group has 'selected' field
    #[error("[E1704] Auto group '{name}' should not have 'selected' field")]
    AutoHasSelected {
        name: String,
    },

    // ── API Errors ──
    /// E1901: Invalid api.listen format
    #[error("[E1901] Invalid api.listen format: {value}")]
    ApiListenInvalid {
        value: String,
    },
    /// E1902: api.token is empty
    #[error("[E1902] api.token cannot be empty")]
    ApiTokenEmpty,
    /// E1903: api.tls is true but cert/key not specified
    #[error("[E1903] api.tls is true but cert or key not specified")]
    ApiTlsMissingCertKey,

    // ── DNS Errors ──
    /// E2001: DNS group references unknown proxy group
    #[error("[E2001] DNS group '{dns_group}' references unknown proxy group: '{proxy_group}'")]
    DnsUnknownProxyGroup {
        dns_group: String,
        proxy_group: String,
    },
    /// E2002: DNS routing references unknown DNS group
    #[error("[E2002] DNS routing references unknown DNS group: '{group}'")]
    DnsUnknownGroup {
        group: String,
    },
    /// E2003: Duplicate DNS group name
    #[error("[E2003] Duplicate DNS group name: '{name}'")]
    DnsDuplicateGroup {
        name: String,
    },
    /// E2004: DNS starting_dns ip_version_prefer must be 4 or 6
    #[error("[E2004] starting_dns ip_version_prefer must be 4 or 6, got: {value}")]
    DnsIpVersionPreferInvalid {
        value: u8,
    },
    /// E2005: DNS group has no upstream
    #[error("[E2005] DNS group '{group}' has no upstream servers")]
    DnsGroupNoUpstream {
        group: String,
    },
    /// E2006: Starting DNS has no upstream
    #[error("[E2006] starting_dns has no upstream servers")]
    DnsStartingDnsNoUpstream,
    /// E2007: DNS routing fallback references unknown DNS group
    #[error("[E2007] DNS routing fallback references unknown DNS group: '{group}'")]
    DnsFallbackUnknownGroup {
        group: String,
    },

    // ── Rule Set Errors ──
    /// E2101: Duplicate rule set name (including default = block name)
    #[error("[E2101] Duplicate rule set name: '{name}'")]
    DuplicateRuleSet {
        name: String,
    },
    /// E2102: Routing/DNS references unknown rule set
    /// (Phase 3 enabled: this variant is reserved, not triggered in validator)
    #[error("[E2102] Unknown rule set reference: '{reference}'")]
    UnknownRuleSetRef {
        reference: String,
    },
    /// E2103: Rule set data missing at compile time
    /// (Phase 3 enabled: this variant is reserved, not triggered in validator)
    #[error("[E2103] Rule set data missing for '{reference}': {reason}")]
    RuleSetDataMissing {
        reference: String,
        reason: String,
    },
    /// E2104: Invalid rule set update expression (missing / conflict / bad time / bad period)
    #[error("[E2104] Rule set '{name}' invalid update expression: {message}")]
    InvalidRuleSetUpdate {
        name: String,
        message: String,
    },
    /// E2105: Invalid rule set URL (not http(s) or bad `#sha256=` fragment)
    #[error("[E2105] Rule set '{name}' invalid URL: {message}")]
    InvalidRuleSetUrl {
        name: String,
        message: String,
    },
    /// E2106: Rule set capacity exceeded at compile time (design §9.3)
    /// MatchSet / LPM trie / domain set index exceeded → reject compilation.
    #[error("[E2106] Rule set capacity exceeded: {detail}")]
    RuleSetCapacityExceeded {
        detail: String,
    },

    // ── Other ──
    /// Unknown section name
    #[error("[E1001] Line {line}: unknown section: '{name}'")]
    UnknownSection {
        line: usize,
        name: String,
    },
}

/// Configuration validation warnings
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigWarning {
    /// W1801: Auto group did not specify policy, using default value 'fixed'
    #[allow(dead_code)]
    AutoGroupDefaultPolicy {
        name: String,
    },
    /// W1901: API does not have TLS enabled
    #[allow(dead_code)]
    ApiNoTls,
    /// W1902: API token is too short
    #[allow(dead_code)]
    ApiTokenTooShort {
        length: usize,
    },
    /// W2001: DNS group request_routing not configured, using fallback
    #[allow(dead_code)]
    DnsGroupNoRequestRouting {
        group: String,
    },
    /// W2002: DNS group response_routing not configured, all responses accepted
    #[allow(dead_code)]
    DnsGroupNoResponseRouting {
        group: String,
    },
}

impl std::fmt::Display for ConfigWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigWarning::AutoGroupDefaultPolicy { name } => {
                write!(f, "[W1801] Auto group '{}' did not specify policy, using default value 'fixed'", name)
            }
            ConfigWarning::ApiNoTls => {
                write!(f, "[W1901] API does not have TLS enabled, running on plain HTTP")
            }
            ConfigWarning::ApiTokenTooShort { length } => {
                write!(f, "[W1902] API token length {} < recommended 16", length)
            }
            ConfigWarning::DnsGroupNoRequestRouting { group } => {
                write!(f, "[W2001] DNS group '{}' has no request_routing configured, using first upstream as fallback", group)
            }
            ConfigWarning::DnsGroupNoResponseRouting { group } => {
                write!(f, "[W2002] DNS group '{}' has no response_routing configured, all responses accepted", group)
            }
        }
    }
}

/// Parse and validation result
pub type Result<T> = std::result::Result<T, ConfigError>;
// ============================================================================
// Configuration Data Structures
// ============================================================================

// ============================================================================
// DNS Configuration Types
// ============================================================================

/// An upstream DNS server entry (label + URL)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DnsUpstreamEntry {
    /// Label (name) for this upstream, used in routing
    pub label: String,
    /// Upstream URL (e.g. udp://1.1.1.1:53, tcp+udp://dns.google:53, https://...)
    pub address: String,
}

/// Starting DNS configuration (bootstrap resolver, used before proxy is available)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StartingDnsConfig {
    /// IP version preference: 4 (IPv4 only) or 6 (IPv6 only)
    pub ip_version_prefer: u8,
    /// Bootstrap upstream server list (usually one)
    pub upstream: Vec<DnsUpstreamEntry>,
}

/// DNS cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DnsCacheConfig {
    /// Whether DNS caching is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Maximum number of cached entries
    #[serde(default = "default_dns_cache_max_size")]
    pub max_size: u32,
    /// Maximum TTL for cached entries (seconds)
    #[serde(default = "default_dns_cache_max_ttl")]
    pub max_ttl: u32,
    /// Minimum TTL for cached entries (seconds)
    #[serde(default = "default_dns_cache_min_ttl")]
    pub min_ttl: u32,
    /// Whether optimistic caching (RFC 8767) is enabled
    #[serde(default)]
    pub optimistic_cache: bool,
    /// How long expired entries are served during refresh (seconds)
    #[serde(default = "default_dns_optimistic_cache_ttl")]
    pub optimistic_cache_ttl: u32,
}

fn default_dns_cache_max_size() -> u32 { 4096 }
fn default_dns_cache_max_ttl() -> u32 { 86400 }
fn default_dns_cache_min_ttl() -> u32 { 60 }
fn default_dns_optimistic_cache_ttl() -> u32 { 3600 }

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_size: 4096,
            max_ttl: 86400,
            min_ttl: 60,
            optimistic_cache: false,
            optimistic_cache_ttl: 3600,
        }
    }
}

/// A single DNS routing rule (request or group-level)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DnsRouteRule {
    /// Match expression (e.g. `qname(geosite:cn)`, `qtype(a)`)
    pub r#match: String,
    /// Action: target group name or upstream label
    pub action: String,
}

/// DNS request routing configuration (within a group)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DnsGroupRequestRouting {
    /// Ordered list of routing rules
    #[serde(default)]
    pub rules: Vec<DnsRouteRule>,
    /// Default upstream if no rule matches
    pub fallback: String,
}

/// DNS response routing rule
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DnsResponseRule {
    /// Match expression (e.g. `upstream(googledns)`, `ip(geoip:private)`)
    pub r#match: String,
    /// Action: `accept`, `reject`, or upstream label to requery
    pub action: String,
}

/// DNS response routing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DnsGroupResponseRouting {
    /// Ordered list of response routing rules
    #[serde(default)]
    pub rules: Vec<DnsResponseRule>,
    /// Default action if no rule matches
    pub fallback: String,
}

/// DNS group configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DnsGroupConfig {
    /// Group name (used in routing)
    pub name: String,
    /// Proxy binding: "direct" or "proxy(group_name)" reference
    pub proxy: String,
    /// Upstream DNS servers in this group
    #[serde(default)]
    pub upstream: Vec<DnsUpstreamEntry>,
    /// Within-group request routing (which upstream to use)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_routing: Option<DnsGroupRequestRouting>,
    /// Response routing (pollution detection and fallback)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_routing: Option<DnsGroupResponseRouting>,
}

/// Top-level DNS routing: which group handles which query
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub struct DnsRoutingConfig {
    /// Ordered list of DNS routing rules
    #[serde(default)]
    pub rules: Vec<DnsRouteRule>,
    /// Default DNS group if no rule matches
    pub fallback: String,
}


/// DNS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DnsConfig {
    /// Starting DNS (bootstrap, IPv4/IPv6 only)
    pub starting_dns: StartingDnsConfig,
    /// Local DNS listener address (default: 127.0.0.1:5353)
    #[serde(default = "default_dns_bind")]
    pub bind: String,
    /// DNS cache settings
    #[serde(default)]
    pub cache: DnsCacheConfig,
    /// DNS groups
    #[serde(default)]
    pub groups: Vec<DnsGroupConfig>,
    /// DNS routing: which group handles which query
    #[serde(default)]
    pub routing: DnsRoutingConfig,
}

fn default_dns_bind() -> String { "127.0.0.1:5353".into() }

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            starting_dns: StartingDnsConfig {
                ip_version_prefer: 4,
                upstream: vec![DnsUpstreamEntry {
                    label: "bootstrap".into(),
                    address: "udp://1.1.1.1:53".into(),
                }],
            },
            bind: "127.0.0.1:5353".into(),
            cache: DnsCacheConfig::default(),
            groups: Vec::new(),
            routing: DnsRoutingConfig {
                rules: Vec::new(),
                fallback: String::new(),
            },
        }
    }
}

// ============================================================================
// Top-Level Config
// ============================================================================

/// Complete daefile configuration (corresponds to JSON top-level structure)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DaefileConfig {
    /// Configuration version number
    pub version: u32,
    /// Runtime parameters
    pub runtime: RuntimeConfig,
    /// Network interface configuration (WAN/LAN)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<InterfaceConfig>,
    /// Process exclusion configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_exclusion: Option<ProcessExclusionConfig>,
    /// Outbound configuration
    pub outbounds: OutboundsConfig,
    /// Routing rule configuration
    pub routing: RoutingConfig,
    /// API configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api: Option<ApiConfig>,
    /// DNS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsConfig>,
    /// Rule set configuration (design §5).
    ///
    /// - daefile: top-level `rule_set { <name> { ... } }` block;
    /// - JSON: object (key = ruleset name, value = entry object).
    ///
    /// Internally unified as `Vec<RuleSetConfig>`, JSON object↔array mapping by
    /// [`rule_set_serde`] adapts.
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "rule_set_serde")]
    pub rule_set: Vec<RuleSetConfig>,
}

impl Default for DaefileConfig {
    fn default() -> Self {
        Self {
            version: 1,
            runtime: RuntimeConfig::default(),
            interface: None,
            process_exclusion: Some(ProcessExclusionConfig::default()),
            outbounds: OutboundsConfig::default(),
            routing: RoutingConfig::default(),
            api: None,
            dns: None,
            rule_set: Vec::new(),
        }
    }
}

/// serde adaptation: `rule_set` in JSON is an **object** (key = ruleset name, value = entry),
/// in memory (daefile parse result / scheduler input) is `Vec<RuleSetConfig>`.
///
/// When deserializing, the object key serves as the entry's default `name` (if not explicitly provided in value), and from
/// `url#sha256=` extracts `expected_sha256` (if not explicitly provided), consistent with daefile path.
pub mod rule_set_serde {
    // Note: do not `use super::*` — it would introduce `super::Result` (`ConfigError` alias),
    // conflicting with `Result<_, D::Error>` here.
    use crate::ruleset::types::RuleSetConfig;
    use serde::Deserialize;

    /// `Vec<RuleSetConfig>` → JSON object `{ "<name>": <entry>, ... }`.
    pub fn serialize<S>(
        entries: &[RuleSetConfig],
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(entries.len()))?;
        for entry in entries {
            map.serialize_entry(&entry.name, entry)?;
        }
        map.end()
    }

    /// JSON object → `Vec<RuleSetConfig>`.
    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Vec<RuleSetConfig>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let map = std::collections::HashMap::<String, serde_json::Value>::deserialize(
            deserializer,
        )?;
        let mut entries = Vec::with_capacity(map.len());
        for (key, value) in map {
            let mut obj = match value {
                serde_json::Value::Object(o) => o,
                _ => {
                    return Err(D::Error::custom(format!(
                        "rule_set entry '{key}' must be an object"
                    )));
                }
            };
            // default name = object key
            if !obj.contains_key("name") {
                obj.insert("name".to_string(), serde_json::Value::String(key));
            }
            let mut cfg: RuleSetConfig = RuleSetConfig::deserialize(serde_json::Value::Object(obj))
                .map_err(D::Error::custom)?;
            if cfg.expected_sha256.is_none() {
                cfg.expected_sha256 = RuleSetConfig::expected_sha256_from_url(&cfg.url);
            }
            entries.push(cfg);
        }
        // Deterministic order (JSON objects are inherently unordered)
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }
}

/// Runtime configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RuntimeConfig {
    /// TProxy listen port (1-65535)
    pub tproxy_port: u16,
    /// Log level (info / debug / warn / error)
    pub log_level: String,
    /// Whether to generate a temp JSON file
    #[serde(default = "default_true")]
    pub temp_json: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            tproxy_port: 15080,
            log_level: "info".into(),
            temp_json: true,
        }
    }
}

fn default_true() -> bool {
    true
}

/// Network interface configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct InterfaceConfig {
    /// WAN interface names (space-separated in daefile).
    ///
    /// Each entry may be:
    ///   - `auto` — follow the interface(s) carrying the default route,
    ///   - `regex('<pattern>')` — a regular expression,
    ///   - otherwise a glob pattern (`*` / `?`), e.g. `eth*`, `enp?*`.
    #[serde(default)]
    pub wan_interface: Vec<String>,
    /// LAN interface names (space-separated in daefile).
    ///
    /// Same pattern syntax as `wan_interface` (glob / `regex(...)`).
    #[serde(default)]
    pub lan_interface: Vec<String>,
    /// Bind interface (auto-detect if set to "auto")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_interface: Option<String>,
}

/// Process exclusion match rules
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct ProcessMatchConfig {
    /// Process name match list
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub comm: Vec<String>,
    /// PID match list
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pid: Vec<u32>,
    /// TGID match list
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tgid: Vec<u32>,
}

/// Process exclusion configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProcessExclusionConfig {
    /// Whether process exclusion is enabled
    pub enabled: bool,
    /// Protect the proxy process itself
    pub protect_self: bool,
    /// Protect child processes of the proxy
    pub protect_children: bool,
    /// Garbage collection interval (seconds)
    pub gc_interval_sec: u32,
    /// Stale entry timeout (seconds)
    pub stale_after_sec: u32,
    /// Match rules
    #[serde(default)]
    pub r#match: ProcessMatchConfig,
}

impl Default for ProcessExclusionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            protect_self: true,
            protect_children: true,
            gc_interval_sec: 30,
            stale_after_sec: 120,
            r#match: ProcessMatchConfig::default(),
        }
    }
}

/// Outbound node selector
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeSelector {
    /// Explicit node name list
    #[serde(rename = "list")]
    List {
        /// List of node names
        nodes: Vec<String>,
    },
    /// Regex-based selection
    #[serde(rename = "regex")]
    Regex {
        /// Regex pattern
        pattern: String,
    },
}

/// Outbound node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OutboundNodeConfig {
    /// Node name (must be unique within the config)
    pub name: String,
    /// Outbound protocol (socks5, shadowsocks, trojan, tuic, juicity, vmess)
    pub protocol: String,
    /// Node address (host:port)
    pub address: String,
    /// Import URL (mutually exclusive with explicit fields)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import: Option<String>,

    // ── SOCKS5 ──
    /// Optional SOCKS5 username
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Optional SOCKS5 password
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    // ── Shadowsocks ──
    /// Shadowsocks cipher
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cipher: Option<String>,

    // ── Trojan ──
    /// TLS SNI
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// Certificate SHA256 fingerprint for pinning
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_sha256: Option<String>,

    // ── TUIC / Juicity ──
    /// User UUID
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// Congestion control (TUIC)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub congestion_control: Option<String>,
    /// ALPN protocols
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<String>>,

    // ── VMess ──
    /// VMess security / encryption
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    /// VMess alter_id
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alter_id: Option<u32>,
    /// VMess transport network
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    // ── VMess WebSocket ──
    /// WebSocket path
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_path: Option<String>,
    /// WebSocket headers
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_headers: Option<std::collections::HashMap<String, String>>,

    // ── VMess HTTP/2 ──
    /// HTTP/2 path
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h2_path: Option<String>,
    /// HTTP/2 host
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h2_host: Option<String>,

    // ── VMess gRPC ──
    /// gRPC service name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc_service_name: Option<String>,

    /// Dial timeout (milliseconds)
    #[serde(default = "default_dial_timeout")]
    pub dial_timeout_ms: u64,
}

fn default_dial_timeout() -> u64 {
    5000
}

/// Outbound group type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum GroupType {
    /// Auto-select nodes
    #[default]
    Auto,
    /// Manually select nodes
    Select,
}


/// Outbound group node selection policy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum PolicyType {
    /// Always select the first alive node
    #[default]
    Fixed,
    /// Randomly select an alive node
    Random,
    /// Select the node with the lowest latest latency
    Min,
    /// Select the node with the lowest average latency over last 10 probes
    MinAvg10,
    /// Select the node with the lowest moving average latency
    MinMovingAvg,
}


/// Outbound group configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OutboundGroupConfig {
    /// Group name (must be unique within the config)
    pub name: String,
    /// Group type
    #[serde(default)]
    pub group_type: GroupType,
    /// Node selection policy (only needed for auto type)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyType>,
    /// Initially selected node (only needed for select type)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected: Option<String>,
    /// Node selector list
    pub selectors: Vec<NodeSelector>,
}

/// Outbound configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub struct OutboundsConfig {
    /// List of outbound nodes
    #[serde(default)]
    pub nodes: Vec<OutboundNodeConfig>,
    /// List of outbound groups
    #[serde(default)]
    pub groups: Vec<OutboundGroupConfig>,
}


/// Single routing rule
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RouteRule {
    /// Match expression (e.g., `dip(geoip:private)`, `dport(22)`)
    pub r#match: String,
    /// Action to execute (`direct` or `proxy(group_name)`)
    pub action: String,
}

/// Routing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RoutingConfig {
    /// List of routing rules
    #[serde(default)]
    pub rules: Vec<RouteRule>,
    /// Default action (used when no rules match)
    pub fallback: String,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            fallback: "proxy(proxy_primary)".into(),
        }
    }
}

/// API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ApiConfig {
    /// Whether the API server is enabled
    pub enabled: bool,
    /// Listen address (host:port)
    pub listen: String,
    /// Whether TLS is enabled
    #[serde(default)]
    pub tls: bool,
    /// TLS certificate path
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,
    /// TLS private key path
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Bearer Token (static secret)
    pub token: String,
}
// ============================================================================
// Module Organization
// ============================================================================

pub mod example;
pub mod parser;
pub mod protocol;
pub mod validator;

#[cfg(test)]
mod tests;

pub use example::default_config_example;
pub use parser::parse_daefile;
pub use protocol::parse_import_url;
pub use validator::validate_config;
