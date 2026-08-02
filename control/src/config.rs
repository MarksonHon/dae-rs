//! daefile configuration parsing and compilation module
//!
//! This module parses daefile (Caddyfile-like syntax) configuration text into a normalized JSON
//! config structure and performs semantic validation. Core flow:
//!
//! 1. [`parse_daefile`] — Parse daefile text into [`DaefileConfig`]
//! 2. [`validate_config`] — Perform semantic validation on the parsed config
//! 3. After validation, the config can be serialized to normalized JSON via `serde_json::to_string_pretty`
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
use std::collections::HashSet;
use thiserror::Error;

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
pub struct DnsRoutingConfig {
    /// Ordered list of DNS routing rules
    #[serde(default)]
    pub rules: Vec<DnsRouteRule>,
    /// Default DNS group if no rule matches
    pub fallback: String,
}

impl Default for DnsRoutingConfig {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            fallback: String::new(),
        }
    }
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
        }
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
    /// Outbound protocol (Phase 1 only supports socks5)
    pub protocol: String,
    /// Node address (host:port)
    pub address: String,
    /// Optional SOCKS5 username
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Optional SOCKS5 password
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
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
pub enum GroupType {
    /// Auto-select nodes
    Auto,
    /// Manually select nodes
    Select,
}

impl Default for GroupType {
    fn default() -> Self {
        Self::Auto
    }
}

/// Outbound group node selection policy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyType {
    /// Always select the first alive node
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

impl Default for PolicyType {
    fn default() -> Self {
        Self::Fixed
    }
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
pub struct OutboundsConfig {
    /// List of outbound nodes
    #[serde(default)]
    pub nodes: Vec<OutboundNodeConfig>,
    /// List of outbound groups
    #[serde(default)]
    pub groups: Vec<OutboundGroupConfig>,
}

impl Default for OutboundsConfig {
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            groups: Vec::new(),
        }
    }
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
// daefile Parser
// ============================================================================

/// Parser internal state
#[derive(Debug, Clone, PartialEq, Eq)]
enum ParseState {
    /// Top-level, waiting for section declaration
    Top,
    /// Inside global section
    Global,
    /// Inside interface section
    Interface,
    /// Inside process_exclusion section
    ProcessExclusion,
    /// Inside process_exclusion > match block
    ProcessMatch,
    /// Inside outbounds section
    Outbounds,
    /// Inside outbounds > nodes level
    OutboundNodes,
    /// Inside a specific node declaration block
    OutboundNode(String),
    /// Inside outbounds > groups level
    OutboundGroups,
    /// Inside a specific group declaration block
    OutboundGroup(String),
    /// Inside routing section
    Routing,
    /// Inside api section
    Api,
    // ── DNS states ──
    /// Inside dns section
    Dns,
    /// Inside dns > starting_dns block
    DnsStartingDns,
    /// Inside dns > cache block
    DnsCache,
    /// Inside dns > groups section
    DnsGroups,
    /// Inside a specific dns group block
    DnsGroup(String),
    /// Inside dns group > upstream block
    DnsGroupUpstream(String), // group_name
    /// Inside dns > routing block (DNS routing)
    DnsRouting,
    /// Inside dns group > request_routing block
    DnsGroupRequestRouting(String), // group_name
    /// Inside dns group > response_routing block
    DnsGroupResponseRouting(String), // group_name
}

/// Parse daefile text into [`DaefileConfig`]
///
/// Uses a simple line-and-indent based state machine parser:
/// - Split by lines, strip comments and blank lines
/// - Track current section state
/// - `section_name {` enters corresponding state
/// - `}` exits current state
/// - Parse key-value pairs `key: value` within states
/// - Special handling for `match { comm(...) }`, `nodes(main, backup)` and other non-standard syntax
///
/// # Parameters
///
/// * `input` — daefile format configuration text
///
/// # Errors
///
/// Returns [`ConfigError::Syntax`] with line number information.
pub fn parse_daefile(input: &str) -> Result<DaefileConfig> {
    let mut config = DaefileConfig::default();
    let mut state = ParseState::Top;
    let mut state_stack: Vec<ParseState> = Vec::new();

    let mut current_node = OutboundNodeConfig {
        name: String::new(),
        protocol: String::new(),
        address: String::new(),
        username: None,
        password: None,
        dial_timeout_ms: 5000,
    };
    let mut current_node_has_protocol = false;
    let mut current_node_has_import = false;
    let mut current_node_import_url = String::new();

    let mut current_group = OutboundGroupConfig {
        name: String::new(),
        group_type: GroupType::Auto,
        policy: None,
        selected: None,
        selectors: Vec::new(),
    };

    let mut process_match = ProcessMatchConfig::default();

    // DNS section parsing temporary variables
    let mut current_dns_config: Option<DnsConfig> = None;
    let mut current_dns_group = DnsGroupConfig {
        name: String::new(),
        proxy: String::new(),
        upstream: Vec::new(),
        request_routing: None,
        response_routing: None,
    };
    let mut current_dns_route_rules: Vec<DnsRouteRule> = Vec::new();
    let mut current_dns_route_fallback = String::new();
    let mut current_dns_resp_rules: Vec<DnsResponseRule> = Vec::new();
    let mut current_dns_resp_fallback = String::new();

    // Preprocess: merge continuation lines (lines ending with `\`)
    let preprocessed = preprocess_multiline(input);

    for (line_num, raw_line) in preprocessed.lines().enumerate() {
        // Strip inline comments (respecting quoted strings)
        let line = strip_inline_comment(raw_line).trim();
        let line_number = line_num + 1; // 1-based

        // Skip blank lines and full-line comment lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        match &state {
            // ── Top-level: waiting for section declaration ──
            ParseState::Top => {
                if let Some(section_name) = line.strip_suffix('{').map(|s| s.trim()) {
                    match section_name {
                        "global" => state = ParseState::Global,
                        "interface" => state = ParseState::Interface,
                        "process_exclusion" => state = ParseState::ProcessExclusion,
                        "outbounds" => state = ParseState::Outbounds,
                        "routing" => state = ParseState::Routing,
                        "api" => state = ParseState::Api,
                        "dns" => {
                            current_dns_config = Some(DnsConfig::default());
                            state = ParseState::Dns;
                        }
                        _ => {
                            return Err(ConfigError::UnknownSection {
                                line: line_number,
                                name: section_name.to_string(),
                            });
                        }
                    }
                } else {
                    return Err(ConfigError::Syntax {
                        line: line_number,
                        message: format!("expected section declaration (e.g. `global {{`), got: '{}'", line),
                    });
                }
            }

            // ── global ──
            ParseState::Global => {
                if line == "}" {
                    state = ParseState::Top;
                    continue;
                }
                parse_kv_pair(line, line_number, |key, value| {
                    match key {
                        "tproxy_port" => {
                            let port: u16 = value.parse().map_err(|_| ConfigError::FieldType {
                                line: line_number,
                                field: key.into(),
                                message: format!("无法解析为整数: '{}'", value),
                            })?;
                            config.runtime.tproxy_port = port;
                        }
                        "log_level" => {
                            config.runtime.log_level = unquote(value).to_string();
                        }
                        _ => {
                            return Err(ConfigError::Syntax {
                                line: line_number,
                                message: format!("未知 global 字段: '{}'", key),
                            });
                        }
                    }
                    Ok(())
                })?;
            }

            // ── interface ──
            ParseState::Interface => {
                if line == "}" {
                    state = ParseState::Top;
                    continue;
                }
                let iface = config.interface.get_or_insert_with(InterfaceConfig::default);
                parse_kv_pair(line, line_number, |key, value| {
                    match key {
                        "wan_interface" => {
                            iface.wan_interface = value.split_whitespace()
                                .map(|s| unquote(s).to_string())
                                .collect();
                        }
                        "lan_interface" => {
                            iface.lan_interface = value.split_whitespace()
                                .map(|s| unquote(s).to_string())
                                .collect();
                        }
                        "bind_interface" => {
                            iface.bind_interface = Some(unquote(value).to_string());
                        }
                        _ => {
                            return Err(ConfigError::Syntax {
                                line: line_number,
                                message: format!("unknown interface field: '{}'", key),
                            });
                        }
                    }
                    Ok(())
                })?;
            }

            // ── process_exclusion ──
            ParseState::ProcessExclusion => {
                if line == "}" {
                    let pe = config.process_exclusion.get_or_insert_with(ProcessExclusionConfig::default);
                    pe.r#match = std::mem::take(&mut process_match);
                    state = ParseState::Top;
                    continue;
                }
                if line.starts_with("match") && line.contains('{') {
                    state_stack.push(ParseState::ProcessExclusion);
                    state = ParseState::ProcessMatch;
                    // match { 可能在同一行或跨行
                    let after_brace = line.trim_start_matches("match").trim();
                    if after_brace == "{" {
                        // Multi-line, wait for next line content
                        continue;
                    } else if let Some(rest) = after_brace.strip_prefix('{').map(|s| s.trim()) {
                        // match { ... } on the same line
                        if let Some(inner) = rest.strip_suffix('}').map(|s| s.trim()) {
                            parse_match_stmts(inner, line_number, &mut process_match)?;
                            state = ParseState::ProcessExclusion;
                            continue;
                        }
                    }
                    continue;
                }
                let pe = config.process_exclusion.get_or_insert_with(ProcessExclusionConfig::default);
                parse_kv_pair(line, line_number, |key, value| {
                    match key {
                        "enabled" => {
                            pe.enabled = parse_bool(value).map_err(|_| ConfigError::FieldType {
                                line: line_number,
                                field: key.into(),
                                message: format!("cannot parse as boolean: '{}'", value),
                            })?;
                        }
                        "protect_self" => {
                            pe.protect_self = parse_bool(value).map_err(|_| ConfigError::FieldType {
                                line: line_number,
                                field: key.into(),
                                message: format!("cannot parse as boolean: '{}'", value),
                            })?;
                        }
                        "protect_children" => {
                            pe.protect_children = parse_bool(value).map_err(|_| ConfigError::FieldType {
                                line: line_number,
                                field: key.into(),
                                message: format!("cannot parse as boolean: '{}'", value),
                            })?;
                        }
                        "gc_interval_sec" => {
                            pe.gc_interval_sec = value.parse().map_err(|_| ConfigError::FieldType {
                                line: line_number,
                                field: key.into(),
                                message: format!("cannot parse as integer: '{}'", value),
                            })?;
                        }
                        "stale_after_sec" => {
                            pe.stale_after_sec = value.parse().map_err(|_| ConfigError::FieldType {
                                line: line_number,
                                field: key.into(),
                                message: format!("cannot parse as integer: '{}'", value),
                            })?;
                        }
                        _ => {
                            return Err(ConfigError::Syntax {
                                line: line_number,
                                message: format!("unknown process_exclusion field: '{}'", key),
                            });
                        }
                    }
                    Ok(())
                })?;
            }

            // ── process_exclusion > match ──
            ParseState::ProcessMatch => {
                if line == "}" {
                    state = state_stack.pop().unwrap_or(ParseState::ProcessExclusion);
                    continue;
                }
                parse_match_stmts(line, line_number, &mut process_match)?;
            }

            // ── outbounds ──
            ParseState::Outbounds => {
                if line == "}" {
                    state = ParseState::Top;
                    continue;
                }
                if line == "nodes {" {
                    state = ParseState::OutboundNodes;
                } else if line == "groups {" {
                    state = ParseState::OutboundGroups;
                } else {
                    return Err(ConfigError::Syntax {
                        line: line_number,
                        message: format!("expected 'nodes {{' or 'groups {{' inside outbounds, got: '{}'", line),
                    });
                }
            }

            // ── outbounds > nodes ──
            ParseState::OutboundNodes => {
                if line == "}" {
                    state = ParseState::Outbounds;
                    continue;
                }
                // Node declaration: node_name {
                if let Some(name) = line.strip_suffix('{').map(|s| s.trim()) {
                    if !name.is_empty() && !name.contains(' ') {
                        // Reset node temporary variables
                        current_node = OutboundNodeConfig {
                            name: name.to_string(),
                            protocol: String::new(),
                            address: String::new(),
                            username: None,
                            password: None,
                            dial_timeout_ms: 5000,
                        };
                        current_node_has_protocol = false;
                        current_node_has_import = false;
                        current_node_import_url.clear();
                        state = ParseState::OutboundNode(name.to_string());
                        continue;
                    }
                }
                return Err(ConfigError::Syntax {
                    line: line_number,
                    message: format!("expected node declaration in nodes (e.g. `main {{`), got: '{}'", line),
                });
            }

            // ── outbounds > nodes > node_name ──
            ParseState::OutboundNode(node_name) => {
                if line == "}" {
                    // Finish node construction, add to list
                    let mut node = std::mem::replace(&mut current_node, OutboundNodeConfig {
                        name: String::new(),
                        protocol: String::new(),
                        address: String::new(),
                        username: None,
                        password: None,
                        dial_timeout_ms: 5000,
                    });

                    if current_node_has_import {
                        // Parse import URL
                        let url = &current_node_import_url;
                        if let Some(rest) = url.strip_prefix("socks5://").or_else(|| url.strip_prefix("socks://")) {
                            node.protocol = "socks5".into();
                            node.address = rest.to_string();
                            // Parse possible auth info from address
                            if let Some(at_pos) = node.address.rfind('@') {
                                let cred = node.address[..at_pos].to_string();
                                node.address = node.address[at_pos + 1..].to_string();
                                if let Some(colon_pos) = cred.find(':') {
                                    node.username = Some(cred[..colon_pos].to_string());
                                    node.password = Some(cred[colon_pos + 1..].to_string());
                                } else {
                                    node.username = Some(cred);
                                }
                            }
                        } else {
                            return Err(ConfigError::ImportInvalid {
                                name: node_name.clone(),
                                url: url.to_string(),
                            });
                        }
                    }

                    config.outbounds.nodes.push(node);
                    state = ParseState::OutboundNodes;
                    continue;
                }

                // Handle import line
                if let Some(import_val) = parse_import_line(line) {
                    current_node_has_import = true;
                    current_node_import_url = import_val;
                    continue;
                }

                // 解析键值对
                parse_kv_pair(line, line_number, |key, value| {
                    if current_node_has_import {
                        return Err(ConfigError::ImportConflict {
                            name: node_name.clone(),
                        });
                    }
                    match key {
                        "protocol" => {
                            current_node.protocol = unquote(value).to_string();
                            current_node_has_protocol = true;
                        }
                        "address" => {
                            current_node.address = unquote(value).to_string();
                        }
                        "username" => {
                            current_node.username = Some(unquote(value).to_string());
                        }
                        "password" => {
                            current_node.password = Some(unquote(value).to_string());
                        }
                        "dial_timeout_ms" => {
                            current_node.dial_timeout_ms = value.parse().map_err(|_| {
                                ConfigError::FieldType {
                                    line: line_number,
                                    field: key.into(),
                                    message: format!("无法解析为整数: '{}'", value),
                                }
                            })?;
                        }
                        _ => {
                            return Err(ConfigError::Syntax {
                                line: line_number,
                                message: format!("未知节点字段: '{}'", key),
                            });
                        }
                    }
                    Ok(())
                })?;
            }

            // ── outbounds > groups ──
            ParseState::OutboundGroups => {
                if line == "}" {
                    state = ParseState::Outbounds;
                    continue;
                }
                // Group declaration: group_name {
                if let Some(name) = line.strip_suffix('{').map(|s| s.trim()) {
                    if !name.is_empty() && !name.contains(' ') {
                        current_group = OutboundGroupConfig {
                            name: name.to_string(),
                            group_type: GroupType::Auto,
                            policy: None,
                            selected: None,
                            selectors: Vec::new(),
                        };
                        state = ParseState::OutboundGroup(name.to_string());
                        continue;
                    }
                }
                return Err(ConfigError::Syntax {
                    line: line_number,
                    message: format!("expected group declaration in groups (e.g. `proxy_primary {{`), got: '{}'", line),
                });
            }

            // ── outbounds > groups > group_name ──
            ParseState::OutboundGroup(_group_name) => {
                if line == "}" {
                    // Finish group construction, add to list
                    let group = std::mem::replace(&mut current_group, OutboundGroupConfig {
                        name: String::new(),
                        group_type: GroupType::Auto,
                        policy: None,
                        selected: None,
                        selectors: Vec::new(),
                    });
                    config.outbounds.groups.push(group);
                    state = ParseState::OutboundGroups;
                    continue;
                }

                // Handle nodes(...) selectors
                if let Some(selectors) = parse_nodes_selector(line) {
                    current_group.selectors.extend(selectors);
                    continue;
                }

                // Parse key-value pair
                parse_kv_pair(line, line_number, |key, value| {
                    match key {
                        "type" => {
                            let v = unquote(value);
                            current_group.group_type = match v {
                                "auto" => GroupType::Auto,
                                "select" => GroupType::Select,
                                _ => {
                                    return Err(ConfigError::InvalidValue {
                                        line: line_number,
                                        field: key.into(),
                                        message: format!("unknown group type '{}', expected auto or select", v),
                                    });
                                }
                            };
                        }
                        "policy" => {
                            let v = unquote(value);
                            current_group.policy = Some(match v {
                                "fixed" => PolicyType::Fixed,
                                "random" => PolicyType::Random,
                                "min" => PolicyType::Min,
                                "min_avg10" => PolicyType::MinAvg10,
                                "min_moving_avg" => PolicyType::MinMovingAvg,
                                _ => {
                                    return Err(ConfigError::InvalidValue {
                                        line: line_number,
                                        field: key.into(),
                                        message: format!(
                                            "unknown policy '{}', expected fixed/random/min/min_avg10/min_moving_avg",
                                            v
                                        ),
                                    });
                                }
                            });
                        }
                        "selected" => {
                            current_group.selected = Some(unquote(value).to_string());
                        }
                        _ => {
                            return Err(ConfigError::Syntax {
                                line: line_number,
                                message: format!("unknown group field: '{}'", key),
                            });
                        }
                    }
                    Ok(())
                })?;
            }

            // ── routing ──
            ParseState::Routing => {
                if line == "}" {
                    state = ParseState::Top;
                    continue;
                }
                // Handle fallback: action
                if let Some(action) = line.strip_prefix("fallback:").map(|s| s.trim()) {
                    config.routing.fallback = action.to_string();
                    continue;
                }
                // Handle rule line: expr -> action
                if let Some(arrow_pos) = line.find("->") {
                    let expr = line[..arrow_pos].trim();
                    let action = line[arrow_pos + 2..].trim();
                    if !expr.is_empty() && !action.is_empty() {
                        config.routing.rules.push(RouteRule {
                            r#match: expr.to_string(),
                            action: action.to_string(),
                        });
                        continue;
                    }
                }
                return Err(ConfigError::Syntax {
                    line: line_number,
                    message: format!("expected rule line (`expr -> action`) or `fallback: action` in routing, got: '{}'", line),
                });
            }

            // ── api ──
            ParseState::Api => {
                if line == "}" {
                    state = ParseState::Top;
                    continue;
                }
                let api = config.api.get_or_insert_with(|| ApiConfig {
                    enabled: true,
                    listen: "127.0.0.1:9090".into(),
                    tls: false,
                    cert: None,
                    key: None,
                    token: String::new(),
                });
                parse_kv_pair(line, line_number, |key, value| {
                    match key {
                        "enabled" => {
                            api.enabled = parse_bool(value).map_err(|_| ConfigError::FieldType {
                                line: line_number,
                                field: key.into(),
                                message: format!("cannot parse as boolean: '{}'", value),
                            })?;
                        }
                        "listen" => {
                            api.listen = unquote(value).to_string();
                        }
                        "tls" => {
                            api.tls = parse_bool(value).map_err(|_| ConfigError::FieldType {
                                line: line_number,
                                field: key.into(),
                                message: format!("cannot parse as boolean: '{}'", value),
                            })?;
                        }
                        "cert" => {
                            api.cert = Some(unquote(value).to_string());
                        }
                        "key" => {
                            api.key = Some(unquote(value).to_string());
                        }
                        "token" => {
                            api.token = unquote(value).to_string();
                        }
                        _ => {
                            return Err(ConfigError::Syntax {
                                line: line_number,
                                message: format!("unknown api field: '{}'", key),
                            });
                        }
                    }
                    Ok(())
                })?;
            }

            // ── dns (top-level) ──
            ParseState::Dns => {
                if line == "}" {
                    // Finalize DNS config
                    if let Some(dns_cfg) = current_dns_config.take() {
                        config.dns = Some(dns_cfg);
                    }
                    state = ParseState::Top;
                    continue;
                }
                // Handle sub-sections inside dns
                if let Some(section_name) = line.strip_suffix('{').map(|s| s.trim()) {
                    match section_name {
                        "starting_dns" => {
                            state = ParseState::DnsStartingDns;
                        }
                        "cache" => {
                            state = ParseState::DnsCache;
                        }
                        "groups" => {
                            state = ParseState::DnsGroups;
                        }
                        "routing" => {
                            current_dns_route_rules.clear();
                            current_dns_route_fallback.clear();
                            state = ParseState::DnsRouting;
                        }
                        _ => {
                            return Err(ConfigError::Syntax {
                                line: line_number,
                                message: format!("unknown dns sub-section: '{}'", section_name),
                            });
                        }
                    }
                    continue;
                }
                // Handle key-value pairs at dns level (e.g. bind)
                parse_kv_pair(line, line_number, |key, value| {
                    match key {
                        "bind" => {
                            if let Some(ref mut dns) = current_dns_config {
                                dns.bind = unquote(value).to_string();
                            }
                        }
                        _ => {
                            return Err(ConfigError::Syntax {
                                line: line_number,
                                message: format!("unknown dns field: '{}'", key),
                            });
                        }
                    }
                    Ok(())
                })?;
            }

            // ── dns > starting_dns ──
            ParseState::DnsStartingDns => {
                if line == "}" {
                    // Pop from stack first; if stack has DnsStartingDns,
                    // we were in the upstream sub-block — return to parent level
                    if let Some(parent) = state_stack.pop() {
                        state = parent;
                    } else {
                        state = ParseState::Dns;
                    }
                    continue;
                }
                if let Some(section_name) = line.strip_suffix('{').map(|s| s.trim()) {
                    match section_name {
                        "upstream" => {
                            // Enter upstream sub-block: push current state and stay
                            state_stack.push(ParseState::DnsStartingDns);
                        }
                        _ => {
                            return Err(ConfigError::Syntax {
                                line: line_number,
                                message: format!("unknown starting_dns sub-section: '{}'", section_name),
                            });
                        }
                    }
                    continue;
                }
                // Inside upstream sub-block or at starting_dns level — parse label: 'url' pairs
                parse_kv_pair(line, line_number, |key, value| {
                    match key {
                        "ip_version_prefer" => {
                            let v: u8 = value.parse().map_err(|_| ConfigError::FieldType {
                                line: line_number,
                                field: key.into(),
                                message: format!("cannot parse as integer: '{}'", value),
                            })?;
                            if let Some(ref mut dns) = current_dns_config {
                                dns.starting_dns.ip_version_prefer = v;
                            }
                        }
                        // Allow inline upstream entries: label: 'url'
                        _ => {
                            if let Some(ref mut dns) = current_dns_config {
                                dns.starting_dns.upstream.push(DnsUpstreamEntry {
                                    label: key.to_string(),
                                    address: unquote(value).to_string(),
                                });
                            }
                        }
                    }
                    Ok(())
                })?;
            }

            // ── dns > cache ──
            ParseState::DnsCache => {
                if line == "}" {
                    state = ParseState::Dns;
                    continue;
                }
                parse_kv_pair(line, line_number, |key, value| {
                    if let Some(ref mut dns) = current_dns_config {
                        match key {
                            "enabled" => {
                                dns.cache.enabled = parse_bool(value).map_err(|_| ConfigError::FieldType {
                                    line: line_number,
                                    field: key.into(),
                                    message: format!("cannot parse as boolean: '{}'", value),
                                })?;
                            }
                            "max_size" => {
                                dns.cache.max_size = value.parse().map_err(|_| ConfigError::FieldType {
                                    line: line_number,
                                    field: key.into(),
                                    message: format!("cannot parse as integer: '{}'", value),
                                })?;
                            }
                            "max_ttl" => {
                                dns.cache.max_ttl = value.parse().map_err(|_| ConfigError::FieldType {
                                    line: line_number,
                                    field: key.into(),
                                    message: format!("cannot parse as integer: '{}'", value),
                                })?;
                            }
                            "min_ttl" => {
                                dns.cache.min_ttl = value.parse().map_err(|_| ConfigError::FieldType {
                                    line: line_number,
                                    field: key.into(),
                                    message: format!("cannot parse as integer: '{}'", value),
                                })?;
                            }
                            "optimistic_cache" => {
                                dns.cache.optimistic_cache = parse_bool(value).map_err(|_| ConfigError::FieldType {
                                    line: line_number,
                                    field: key.into(),
                                    message: format!("cannot parse as boolean: '{}'", value),
                                })?;
                            }
                            "optimistic_cache_ttl" => {
                                dns.cache.optimistic_cache_ttl = value.parse().map_err(|_| ConfigError::FieldType {
                                    line: line_number,
                                    field: key.into(),
                                    message: format!("cannot parse as integer: '{}'", value),
                                })?;
                            }
                            _ => {
                                return Err(ConfigError::Syntax {
                                    line: line_number,
                                    message: format!("unknown dns cache field: '{}'", key),
                                });
                            }
                        }
                    }
                    Ok(())
                })?;
            }

            // ── dns > groups ──
            ParseState::DnsGroups => {
                if line == "}" {
                    state = ParseState::Dns;
                    continue;
                }
                // Group declaration: group_name {
                let name = line.strip_suffix('{').map(|s| s.trim()).map(String::from);
                if let Some(ref name) = name {
                    if !name.is_empty() && !name.contains(' ') {
                        current_dns_group = DnsGroupConfig {
                            name: name.clone(),
                            proxy: String::new(),
                            upstream: Vec::new(),
                            request_routing: None,
                            response_routing: None,
                        };
                        state = ParseState::DnsGroup(name.clone());
                        continue;
                    }
                }
                return Err(ConfigError::Syntax {
                    line: line_number,
                    message: format!("expected DNS group declaration (e.g. `trusted_dns {{`), got: '{}'", line),
                });
            }

            // ── dns > groups > group_name ──
            ParseState::DnsGroup(group_name) => {
                if line == "}" {
                    // Finalize group and add to config
                    let group = std::mem::replace(&mut current_dns_group, DnsGroupConfig {
                        name: String::new(),
                        proxy: String::new(),
                        upstream: Vec::new(),
                        request_routing: None,
                        response_routing: None,
                    });
                    if let Some(ref mut dns) = current_dns_config {
                        dns.groups.push(group);
                    }
                    state = ParseState::DnsGroups;
                    continue;
                }
                // Handle sub-sections inside group
                if let Some(section_name) = line.strip_suffix('{').map(|s| s.trim()) {
                    match section_name {
                        "upstream" => {
                            state = ParseState::DnsGroupUpstream(group_name.clone());
                        }
                        "request_routing" => {
                            current_dns_route_rules.clear();
                            current_dns_route_fallback.clear();
                            state = ParseState::DnsGroupRequestRouting(group_name.clone());
                        }
                        "response_routing" => {
                            current_dns_resp_rules.clear();
                            current_dns_resp_fallback = "accept".into();
                            state = ParseState::DnsGroupResponseRouting(group_name.clone());
                        }
                        _ => {
                            return Err(ConfigError::Syntax {
                                line: line_number,
                                message: format!("unknown DNS group sub-section: '{}'", section_name),
                            });
                        }
                    }
                    continue;
                }
                // Handle proxy binding
                parse_kv_pair(line, line_number, |key, value| {
                    match key {
                        "proxy" => {
                            current_dns_group.proxy = unquote(value).to_string();
                        }
                        _ => {
                            return Err(ConfigError::Syntax {
                                line: line_number,
                                message: format!("unknown DNS group field: '{}'", key),
                            });
                        }
                    }
                    Ok(())
                })?;
            }

            // ── dns group > upstream ──
            ParseState::DnsGroupUpstream(group_name) => {
                if line == "}" {
                    state = ParseState::DnsGroup(group_name.clone());
                    continue;
                }
                // Parse label: 'url' pairs
                parse_kv_pair(line, line_number, |key, value| {
                    current_dns_group.upstream.push(DnsUpstreamEntry {
                        label: key.to_string(),
                        address: unquote(value).to_string(),
                    });
                    Ok(())
                })?;
            }

            // ── dns > routing (top-level DNS routing) ──
            ParseState::DnsRouting => {
                if line == "}" {
                    if let Some(ref mut dns) = current_dns_config {
                        dns.routing = DnsRoutingConfig {
                            rules: std::mem::take(&mut current_dns_route_rules),
                            fallback: std::mem::take(&mut current_dns_route_fallback),
                        };
                    }
                    state = ParseState::Dns;
                    continue;
                }
                // Handle fallback: action
                if let Some(action) = line.strip_prefix("fallback:").map(|s| s.trim()) {
                    current_dns_route_fallback = action.to_string();
                    continue;
                }
                // Handle rule line: expr -> action
                if let Some(arrow_pos) = line.find("->") {
                    let expr = line[..arrow_pos].trim();
                    let action = line[arrow_pos + 2..].trim();
                    if !expr.is_empty() && !action.is_empty() {
                        current_dns_route_rules.push(DnsRouteRule {
                            r#match: expr.to_string(),
                            action: action.to_string(),
                        });
                        continue;
                    }
                }
                return Err(ConfigError::Syntax {
                    line: line_number,
                    message: format!("expected DNS routing rule or fallback, got: '{}'", line),
                });
            }

            // ── dns group > request_routing ──
            ParseState::DnsGroupRequestRouting(group_name) => {
                if line == "}" {
                    current_dns_group.request_routing = Some(DnsGroupRequestRouting {
                        rules: std::mem::take(&mut current_dns_route_rules),
                        fallback: std::mem::take(&mut current_dns_route_fallback),
                    });
                    state = ParseState::DnsGroup(group_name.clone());
                    continue;
                }
                // Handle fallback: action
                if let Some(action) = line.strip_prefix("fallback:").map(|s| s.trim()) {
                    current_dns_route_fallback = action.to_string();
                    continue;
                }
                // Handle rule line: expr -> action
                if let Some(arrow_pos) = line.find("->") {
                    let expr = line[..arrow_pos].trim();
                    let action = line[arrow_pos + 2..].trim();
                    if !expr.is_empty() && !action.is_empty() {
                        current_dns_route_rules.push(DnsRouteRule {
                            r#match: expr.to_string(),
                            action: action.to_string(),
                        });
                        continue;
                    }
                }
                return Err(ConfigError::Syntax {
                    line: line_number,
                    message: format!("expected request routing rule or fallback, got: '{}'", line),
                });
            }

            // ── dns group > response_routing ──
            ParseState::DnsGroupResponseRouting(group_name) => {
                if line == "}" {
                    current_dns_group.response_routing = Some(DnsGroupResponseRouting {
                        rules: std::mem::take(&mut current_dns_resp_rules),
                        fallback: std::mem::take(&mut current_dns_resp_fallback),
                    });
                    state = ParseState::DnsGroup(group_name.clone());
                    continue;
                }
                // Handle fallback: action
                if let Some(action) = line.strip_prefix("fallback:").map(|s| s.trim()) {
                    current_dns_resp_fallback = action.to_string();
                    continue;
                }
                // Handle rule line: expr -> action
                if let Some(arrow_pos) = line.find("->") {
                    let expr = line[..arrow_pos].trim();
                    let action = line[arrow_pos + 2..].trim();
                    if !expr.is_empty() && !action.is_empty() {
                        current_dns_resp_rules.push(DnsResponseRule {
                            r#match: expr.to_string(),
                            action: action.to_string(),
                        });
                        continue;
                    }
                }
                return Err(ConfigError::Syntax {
                    line: line_number,
                    message: format!("expected response routing rule or fallback, got: '{}'", line),
                });
            }
        }
    }

    // Check if all blocks are closed
    if state != ParseState::Top {
        return Err(ConfigError::Syntax {
            line: input.lines().count(),
            message: format!("unclosed {:?} block", state),
        });
    }

    Ok(config)
}

// ============================================================================
// Parse Helper Functions
// ============================================================================

/// Parse a key-value pair line `key: value`
fn parse_kv_pair<F>(line: &str, line_number: usize, f: F) -> Result<()>
where
    F: FnOnce(&str, &str) -> Result<()>,
{
    if let Some(colon_pos) = line.find(':') {
        let key = line[..colon_pos].trim();
        let value = line[colon_pos + 1..].trim();
        if key.is_empty() {
            return Err(ConfigError::Syntax {
                line: line_number,
                message: format!("empty key name: '{}'", line),
            });
        }
        f(key, value)
    } else {
        Err(ConfigError::Syntax {
            line: line_number,
            message: format!("expected `key: value` format, got: '{}'", line),
        })
    }
}

/// Parse an import line: `import: 'url'` or `import: "url"`
fn parse_import_line(line: &str) -> Option<String> {
    let line = line.trim();
    if let Some(rest) = line.strip_prefix("import:").map(|s| s.trim()) {
        Some(unquote(rest).to_string())
    } else {
        None
    }
}

/// Parse nodes(selector) syntax
fn parse_nodes_selector(line: &str) -> Option<Vec<NodeSelector>> {
    let line = line.trim();
    if let Some(inner) = line.strip_prefix("nodes(") {
        if let Some(content) = inner.strip_suffix(')') {
            let content = content.trim();
            if content.is_empty() {
                return Some(vec![]);
            }
            // Check if it's a regex selector
            if let Some(pattern) = content.strip_prefix("regex:").map(|s| s.trim()) {
                let pattern = unquote(pattern).to_string();
                return Some(vec![NodeSelector::Regex { pattern }]);
            }
            // Otherwise it's a comma-separated node name list
            let nodes: Vec<String> = content
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !nodes.is_empty() {
                return Some(vec![NodeSelector::List { nodes }]);
            }
            return Some(vec![]);
        }
    }
    None
}

/// Parse statements inside match blocks: `comm(a, b)`, `pid(1, 2)`, `tgid(3, 4)`
fn parse_match_stmts(line: &str, line_number: usize, match_cfg: &mut ProcessMatchConfig) -> Result<()> {
    let line = line.trim();
    if let Some(inner) = line.strip_prefix("comm(") {
        if let Some(args) = inner.strip_suffix(')') {
            for item in args.split(',') {
                let item = item.trim();
                if !item.is_empty() {
                    match_cfg.comm.push(unquote(item).to_string());
                }
            }
            return Ok(());
        }
    }
    if let Some(inner) = line.strip_prefix("pid(") {
        if let Some(args) = inner.strip_suffix(')') {
            for item in args.split(',') {
                let item = item.trim();
                if !item.is_empty() {
                    let pid: u32 = item.parse().map_err(|_| ConfigError::FieldType {
                        line: line_number,
                        field: "pid".into(),
                        message: format!("cannot parse as integer: '{}'", item),
                    })?;
                    match_cfg.pid.push(pid);
                }
            }
            return Ok(());
        }
    }
    if let Some(inner) = line.strip_prefix("tgid(") {
        if let Some(args) = inner.strip_suffix(')') {
            for item in args.split(',') {
                let item = item.trim();
                if !item.is_empty() {
                    let tgid: u32 = item.parse().map_err(|_| ConfigError::FieldType {
                        line: line_number,
                        field: "tgid".into(),
                        message: format!("cannot parse as integer: '{}'", item),
                    })?;
                    match_cfg.tgid.push(tgid);
                }
            }
            return Ok(());
        }
    }
    Err(ConfigError::Syntax {
        line: line_number,
        message: format!("expected comm(...)/pid(...)/tgid(...) in match, got: '{}'", line),
    })
}

/// Strip string quotes (single or double quotes)
fn unquote(s: &str) -> &str {
    let s = s.trim();
    if (s.starts_with('\'') && s.ends_with('\'')) || (s.starts_with('"') && s.ends_with('"')) {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Strip inline comment from a line, respecting quoted strings.
///
/// Finds the first unquoted `#` character and removes it and everything after,
/// then trims trailing whitespace from the result.
///
/// This is a private helper; see unit tests in the `tests` module for examples.
fn strip_inline_comment(line: &str) -> &str {
    let mut in_quote: Option<char> = None;
    for (i, ch) in line.char_indices() {
        match ch {
            '"' | '\'' if in_quote == Some(ch) => {
                // Closing quote
                in_quote = None;
            }
            '"' | '\'' if in_quote.is_none() => {
                // Opening quote
                in_quote = Some(ch);
            }
            '#' if in_quote.is_none() => {
                return line[..i].trim_end();
            }
            _ => {}
        }
    }
    line
}

/// Preprocess input to merge continuation lines (lines ending with `\`).
///
/// Lines ending with `\` are joined with the next line, with the trailing `\`
/// removed. This allows long configuration values to span multiple lines.
/// Leading whitespace on continuation lines is preserved (user controls spacing).
/// Chained continuations are supported.
///
/// # Examples
///
/// ```text
/// address: 127.0.0.1:\
///   1080
/// ```
/// is equivalent to: `address: 127.0.0.1:  1080`
fn preprocess_multiline(input: &str) -> String {
    let lines: Vec<&str> = input.lines().collect();
    let mut result = String::with_capacity(input.len());
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_end();

        if trimmed.ends_with('\\') {
            // Remove the trailing backslash and merge with the next line(s)
            result.push_str(&trimmed[..trimmed.len() - 1]);
            i += 1;
        } else {
            result.push_str(line);
            i += 1;
            if i < lines.len() {
                result.push('\n');
            }
        }
    }

    result
}

/// Parse a hex string (e.g., `0x02000000`) to u32
fn parse_hex(s: &str) -> std::result::Result<u32, std::num::ParseIntError> {
    let s = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    u32::from_str_radix(s, 16)
}

/// Parse a boolean value
fn parse_bool(s: &str) -> std::result::Result<bool, ()> {
    match s.trim() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        _ => Err(()),
    }
}

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
fn extract_proxy_group(action: &str) -> Option<&str> {
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
    for node in &config.outbounds.nodes {
        // Protocol validation: Phase 1 only supports socks5
        if node.protocol != "socks5" {
            return Err(ConfigError::InvalidValue {
                line: 0,
                field: format!("节点 '{}'.protocol", node.name),
                message: format!("unsupported protocol '{}', Phase 1 only supports socks5", node.protocol),
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
            if api.tls {
                if api.cert.is_none() || api.key.is_none() {
                    return Err(ConfigError::ApiTlsMissingCertKey);
                }
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
    if !dns.routing.fallback.is_empty() {
        if !dns_group_names.contains(dns.routing.fallback.as_str()) {
            return Err(ConfigError::DnsFallbackUnknownGroup {
                group: dns.routing.fallback.clone(),
            });
        }
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

// ============================================================================
// Example Config
// ============================================================================

/// Returns a minimal valid daefile example (for unit tests)
///
/// Corresponds to the minimal example from plan §12.6.
pub fn default_config_example() -> &'static str {
    r#"global {
  tproxy_port: 15080
  log_level: info
}

outbounds {
  nodes {
    main {
      protocol: socks5
      address: 127.0.0.1:1080
      dial_timeout_ms: 5000
    }
  }

  groups {
    proxy_primary {
      policy: fixed
      nodes(main)
    }

    a_group {
      type: auto
      policy: min_avg10
      nodes(regex: '*')
    }
  }
}

routing {
  l4proto(tcp) -> proxy(proxy_primary)
  fallback: proxy(proxy_primary)
}
"#
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Full Config Parse Tests ──

    /// Complete daefile config example (includes all sections)
    const FULL_CONFIG: &str = r#"global {
  tproxy_port: 15080
  log_level: info
}

process_exclusion {
  enabled: true
  protect_self: true
  protect_children: true
  gc_interval_sec: 30
  stale_after_sec: 120

  match {
    comm(dae-rs, naiveproxy)
    pid(100, 200)
    tgid(300)
  }
}

outbounds {
  nodes {
    main {
      protocol: socks5
      address: 127.0.0.1:1080
      dial_timeout_ms: 5000
    }

    backup {
      import: 'socks5://127.0.0.1:2080'
    }
  }

  groups {
    proxy_primary {
      policy: min_moving_avg
      nodes(main, backup)
    }

    a_group {
      type: auto
      policy: min_avg10
      nodes(regex: '*')
    }

    manual {
      type: select
      selected: main
      nodes(main, backup)
    }
  }
}

routing {
  dip(geoip:private) -> direct
  dport(22) -> direct
  l4proto(tcp) -> proxy(proxy_primary)
  fallback: proxy(proxy_primary)
}

api {
  enabled: true
  listen: 127.0.0.1:9090
  token: 'your-secret-token'
}
"#;

    #[test]
    fn test_parse_full_config() {
        let config = parse_daefile(FULL_CONFIG).expect("full config parse failed");
        assert_eq!(config.version, 1);
        assert_eq!(config.runtime.tproxy_port, 15080);
        assert_eq!(config.runtime.log_level, "info");
        assert!(config.runtime.temp_json);

        // process_exclusion
        let pe = config.process_exclusion.as_ref().expect("process_exclusion should exist");
        assert!(pe.enabled);
        assert!(pe.protect_self);
        assert!(pe.protect_children);
        assert_eq!(pe.gc_interval_sec, 30);
        assert_eq!(pe.stale_after_sec, 120);
        assert_eq!(pe.r#match.comm, vec!["dae-rs", "naiveproxy"]);
        assert_eq!(pe.r#match.pid, vec![100, 200]);
        assert_eq!(pe.r#match.tgid, vec![300]);

        // outbounds.nodes
        assert_eq!(config.outbounds.nodes.len(), 2);
        let main_node = &config.outbounds.nodes[0];
        assert_eq!(main_node.name, "main");
        assert_eq!(main_node.protocol, "socks5");
        assert_eq!(main_node.address, "127.0.0.1:1080");
        assert_eq!(main_node.dial_timeout_ms, 5000);

        let backup_node = &config.outbounds.nodes[1];
        assert_eq!(backup_node.name, "backup");
        assert_eq!(backup_node.protocol, "socks5");
        assert_eq!(backup_node.address, "127.0.0.1:2080");

        // outbounds.groups
        assert_eq!(config.outbounds.groups.len(), 3);

        let g1 = &config.outbounds.groups[0];
        assert_eq!(g1.name, "proxy_primary");
        assert_eq!(g1.group_type, GroupType::Auto);
        assert_eq!(g1.policy, Some(PolicyType::MinMovingAvg));
        assert_eq!(g1.selectors.len(), 1);
        if let NodeSelector::List { nodes } = &g1.selectors[0] {
            assert_eq!(nodes, &vec!["main".to_string(), "backup".to_string()]);
        } else {
            panic!("expected List selector");
        }

        let g2 = &config.outbounds.groups[1];
        assert_eq!(g2.name, "a_group");
        assert_eq!(g2.group_type, GroupType::Auto);
        assert_eq!(g2.policy, Some(PolicyType::MinAvg10));
        if let NodeSelector::Regex { pattern } = &g2.selectors[0] {
            assert_eq!(pattern, "*");
        } else {
            panic!("expected Regex selector");
        }

        let g3 = &config.outbounds.groups[2];
        assert_eq!(g3.name, "manual");
        assert_eq!(g3.group_type, GroupType::Select);
        assert_eq!(g3.selected, Some("main".to_string()));

        // routing
        assert_eq!(config.routing.rules.len(), 3);
        assert_eq!(config.routing.rules[0].r#match, "dip(geoip:private)");
        assert_eq!(config.routing.rules[0].action, "direct");
        assert_eq!(config.routing.rules[1].r#match, "dport(22)");
        assert_eq!(config.routing.rules[1].action, "direct");
        assert_eq!(config.routing.rules[2].r#match, "l4proto(tcp)");
        assert_eq!(config.routing.rules[2].action, "proxy(proxy_primary)");
        assert_eq!(config.routing.fallback, "proxy(proxy_primary)");

        // api
        let api = config.api.as_ref().expect("api should exist");
        assert!(api.enabled);
        assert_eq!(api.listen, "127.0.0.1:9090");
        assert!(!api.tls);
        assert_eq!(api.token, "your-secret-token");

        // Verify serialization
        let json = serde_json::to_string_pretty(&config).expect("JSON serialization failed");
        assert!(json.contains("tproxy_port"));
        assert!(json.contains("socks5"));
    }

    #[test]
    fn test_parse_minimal_config() {
        let config = parse_daefile(default_config_example()).expect("minimal config parse failed");
        assert_eq!(config.runtime.tproxy_port, 15080);
        assert_eq!(config.outbounds.nodes.len(), 1);
        assert_eq!(config.outbounds.nodes[0].name, "main");
        assert_eq!(config.outbounds.groups.len(), 2);
        assert_eq!(config.routing.rules.len(), 1);
        assert_eq!(config.routing.fallback, "proxy(proxy_primary)");
    }

    // ── Validation Tests ──

    #[test]
    fn test_validate_full_config() {
        let config = parse_daefile(FULL_CONFIG).expect("parse failed");
        validate_config(&config).expect("validation failed");
    }

    #[test]
    fn test_validate_minimal_config() {
        let input = default_config_example();
        let config = parse_daefile(input).expect("parse failed");
        validate_config(&config).expect("validation failed");
    }

    #[test]
    fn test_duplicate_node_name() {
        let input = r#"global {
  tproxy_port: 15080
  log_level: info
}

outbounds {
  nodes {
    main {
      protocol: socks5
      address: 127.0.0.1:1080
    }
    main {
      protocol: socks5
      address: 127.0.0.1:2080
    }
  }

  groups {
    g {
      policy: fixed
      nodes(main)
    }
  }
}

routing {
  fallback: proxy(g)
}
"#;
        let config = parse_daefile(input).expect("解析失败");
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, ConfigError::DuplicateNode { .. }));
    }

    #[test]
    fn test_duplicate_group_name() {
        let input = r#"global {
  tproxy_port: 15080
  log_level: info
}

outbounds {
  nodes {
    main {
      protocol: socks5
      address: 127.0.0.1:1080
    }
  }

  groups {
    g {
      policy: fixed
      nodes(main)
    }
    g {
      policy: fixed
      nodes(main)
    }
  }
}

routing {
  fallback: proxy(g)
}
"#;
        let config = parse_daefile(input).expect("解析失败");
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, ConfigError::DuplicateGroup { .. }));
    }

    #[test]
    fn test_unknown_node_reference() {
        let input = r#"global {
  tproxy_port: 15080
  log_level: info
}

outbounds {
  nodes {
    main {
      protocol: socks5
      address: 127.0.0.1:1080
    }
  }

  groups {
    g {
      policy: fixed
      nodes(nonexistent)
    }
  }
}

routing {
  fallback: proxy(g)
}
"#;
        let config = parse_daefile(input).expect("解析失败");
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, ConfigError::UnknownNode { .. }));
    }

    #[test]
    fn test_unknown_group_in_routing() {
        let input = r#"global {
  tproxy_port: 15080
  log_level: info
}

outbounds {
  nodes {
    main {
      protocol: socks5
      address: 127.0.0.1:1080
    }
  }

  groups {
    g {
      policy: fixed
      nodes(main)
    }
  }
}

routing {
  l4proto(tcp) -> proxy(nonexistent_group)
  fallback: proxy(g)
}
"#;
        let config = parse_daefile(input).expect("解析失败");
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, ConfigError::UnknownGroup { .. }));
    }

    #[test]
    fn test_invalid_fallback() {
        let input = r#"global {
  tproxy_port: 15080
  log_level: info
}

outbounds {
  nodes {
    main {
      protocol: socks5
      address: 127.0.0.1:1080
    }
  }

  groups {
    g {
      policy: fixed
      nodes(main)
    }
  }
}

routing {
  fallback: invalid_action
}
"#;
        let config = parse_daefile(input).expect("解析失败");
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn test_select_group_missing_selected() {
        let input = r#"global {
  tproxy_port: 15080
  log_level: info
}

outbounds {
  nodes {
    main {
      protocol: socks5
      address: 127.0.0.1:1080
    }
  }

  groups {
    g {
      type: select
      nodes(main)
    }
  }
}

routing {
  fallback: proxy(g)
}
"#;
        let config = parse_daefile(input).expect("解析失败");
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, ConfigError::SelectMissingSelected { .. }));
    }

    #[test]
    fn test_select_group_has_policy() {
        let input = r#"global {
  tproxy_port: 15080
  log_level: info
}

outbounds {
  nodes {
    main {
      protocol: socks5
      address: 127.0.0.1:1080
    }
  }

  groups {
    g {
      type: select
      policy: fixed
      selected: main
      nodes(main)
    }
  }
}

routing {
  fallback: proxy(g)
}
"#;
        let config = parse_daefile(input).expect("parse failed");
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, ConfigError::SelectHasPolicy { .. }));
    }

    #[test]
    fn test_auto_group_has_selected() {
        let input = r#"global {
  tproxy_port: 15080
  log_level: info
}

outbounds {
  nodes {
    main {
      protocol: socks5
      address: 127.0.0.1:1080
    }
  }

  groups {
    g {
      type: auto
      selected: main
      nodes(main)
    }
  }
}

routing {
  fallback: proxy(g)
}
"#;
        let config = parse_daefile(input).expect("parse failed");
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, ConfigError::AutoHasSelected { .. }));
    }

    #[test]
    fn test_unsupported_protocol() {
        let input = r#"global {
  tproxy_port: 15080
  log_level: info
}

outbounds {
  nodes {
    main {
      protocol: vmess
      address: 127.0.0.1:1080
    }
  }

  groups {
    g {
      policy: fixed
      nodes(main)
    }
  }
}

routing {
  fallback: proxy(g)
}
"#;
        let config = parse_daefile(input).expect("解析失败");
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    // test_mtu_out_of_range removed: namespace/marks are now hardcoded,
    // no longer configurable via daefile.

    #[test]
    fn test_import_node() {
        let input = r#"global {
  tproxy_port: 15080
  log_level: info
}

outbounds {
  nodes {
    backup {
      import: 'socks5://127.0.0.1:2080'
    }
  }

  groups {
    g {
      policy: fixed
      nodes(backup)
    }
  }
}

routing {
  fallback: proxy(g)
}
"#;
        let config = parse_daefile(input).expect("parse failed");
        assert_eq!(config.outbounds.nodes.len(), 1);
        assert_eq!(config.outbounds.nodes[0].name, "backup");
        assert_eq!(config.outbounds.nodes[0].protocol, "socks5");
        assert_eq!(config.outbounds.nodes[0].address, "127.0.0.1:2080");
    }

    #[test]
    fn test_empty_config_fails_validation() {
        let config = DaefileConfig::default();
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, ConfigError::MissingSection { .. }));
    }

    // ── JSON Serialization / Deserialization ──

    #[test]
    fn test_serde_roundtrip() {
        let config = parse_daefile(FULL_CONFIG).expect("parse failed");
        let json = serde_json::to_string_pretty(&config).expect("serialization failed");
        let deserialized: DaefileConfig = serde_json::from_str(&json).expect("deserialization failed");
        assert_eq!(deserialized.runtime.tproxy_port, config.runtime.tproxy_port);
        assert_eq!(deserialized.outbounds.nodes.len(), config.outbounds.nodes.len());
        assert_eq!(deserialized.outbounds.groups.len(), config.outbounds.groups.len());
        assert_eq!(deserialized.routing.rules.len(), config.routing.rules.len());
    }

    // ── Helper Function Tests ──

    #[test]
    fn test_parse_hex() {
        assert_eq!(parse_hex("0x02000000").unwrap(), 0x02000000);
        assert_eq!(parse_hex("0x0f000000").unwrap(), 0x0f000000);
        assert_eq!(parse_hex("0xff").unwrap(), 255);
        assert!(parse_hex("not_hex").is_err());
    }

    #[test]
    fn test_parse_bool() {
        assert_eq!(parse_bool("true"), Ok(true));
        assert_eq!(parse_bool("false"), Ok(false));
        assert_eq!(parse_bool("yes"), Ok(true));
        assert_eq!(parse_bool("no"), Ok(false));
        assert!(parse_bool("maybe").is_err());
    }

    #[test]
    fn test_unquote() {
        assert_eq!(unquote("'hello'"), "hello");
        assert_eq!(unquote("\"hello\""), "hello");
        assert_eq!(unquote("hello"), "hello");
        assert_eq!(unquote("'nested\"quote'"), "nested\"quote");
    }

    #[test]
    fn test_extract_proxy_group() {
        assert_eq!(extract_proxy_group("proxy(proxy_primary)"), Some("proxy_primary"));
        assert_eq!(extract_proxy_group("direct"), None);
        assert_eq!(extract_proxy_group("proxy()"), None);
    }

    #[test]
    fn test_parse_nodes_selector() {
        let result = parse_nodes_selector("nodes(main, backup)").unwrap();
        assert_eq!(result.len(), 1);
        if let NodeSelector::List { nodes } = &result[0] {
            assert_eq!(nodes, &vec!["main".to_string(), "backup".to_string()]);
        } else {
            panic!("expected List");
        }

        let result = parse_nodes_selector("nodes(regex: '*')").unwrap();
        assert_eq!(result.len(), 1);
        if let NodeSelector::Regex { pattern } = &result[0] {
            assert_eq!(pattern, "*");
        } else {
            panic!("expected Regex");
        }
    }

    // ── Error Tests ──

    #[test]
    fn test_unknown_section() {
        let input = r#"unknown_section {
  key: value
}
"#;
        let err = parse_daefile(input).unwrap_err();
        assert!(matches!(err, ConfigError::UnknownSection { .. }));
    }

    #[test]
    fn test_syntax_error_missing_brace() {
        let input = r#"global {
  tproxy_port: 15080
"#;
        let err = parse_daefile(input).unwrap_err();
        assert!(matches!(err, ConfigError::Syntax { .. }));
    }

    #[test]
    fn test_regex_no_match() {
        let input = r#"global {
  tproxy_port: 15080
  log_level: info
}

outbounds {
  nodes {
    main {
      protocol: socks5
      address: 127.0.0.1:1080
    }
  }

  groups {
    g {
      policy: fixed
      nodes(regex: 'zzz_nonexistent')
    }
  }
}

routing {
  fallback: proxy(g)
}
"#;
        let config = parse_daefile(input).expect("parse failed");
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, ConfigError::RegexNoMatch { .. }));
    }

    #[test]
    fn test_diagnostic_codes_display() {
        let err = ConfigError::MissingSection { section: "outbounds".into() };
        let msg = format!("{}", err);
        assert!(msg.contains("E1101"));

        let err = ConfigError::DuplicateNode { name: "main".into() };
        let msg = format!("{}", err);
        assert!(msg.contains("E1301"));

        let err = ConfigError::UnknownGroup { group: "g".into() };
        let msg = format!("{}", err);
        assert!(msg.contains("E1402"));
    }

    #[test]
    fn test_api_config() {
        let input = r#"global {
  tproxy_port: 15080
  log_level: info
}

outbounds {
  nodes {
    main {
      protocol: socks5
      address: 127.0.0.1:1080
    }
  }

  groups {
    g {
      policy: fixed
      nodes(main)
    }
  }
}

routing {
  fallback: proxy(g)
}

api {
  enabled: true
  listen: 127.0.0.1:9090
  tls: true
  cert: /etc/dae-rs/api.crt
  key: /etc/dae-rs/api.key
  token: 'my-super-secret-token-12345'
}
"#;
        let config = parse_daefile(input).expect("parse failed");
        let api = config.api.as_ref().expect("api should exist");
        assert!(api.enabled);
        assert!(api.tls);
        assert_eq!(api.cert.as_deref(), Some("/etc/dae-rs/api.crt"));
        assert_eq!(api.key.as_deref(), Some("/etc/dae-rs/api.key"));
        assert_eq!(api.token, "my-super-secret-token-12345");
    }

    #[test]
    fn test_api_token_empty() {
        let input = r#"global {
  tproxy_port: 15080
  log_level: info
}

outbounds {
  nodes {
    main {
      protocol: socks5
      address: 127.0.0.1:1080
    }
  }

  groups {
    g {
      policy: fixed
      nodes(main)
    }
  }
}

routing {
  fallback: proxy(g)
}

api {
  enabled: true
  listen: 127.0.0.1:9090
  token: ''
}
"#;
        let config = parse_daefile(input).expect("parse failed");
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, ConfigError::ApiTokenEmpty));
    }

    #[test]
    fn test_disabled_api_validation_skipped() {
        let input = r#"global {
  tproxy_port: 15080
  log_level: info
}

outbounds {
  nodes {
    main {
      protocol: socks5
      address: 127.0.0.1:1080
    }
  }

  groups {
    g {
      policy: fixed
      nodes(main)
    }
  }
}

routing {
  fallback: proxy(g)
}

api {
  enabled: false
  listen: 127.0.0.1:9090
  token: ''
}
"#;
        let config = parse_daefile(input).expect("parse failed");
        // API disabled, so empty token should be fine
        validate_config(&config).expect("validation should pass (API disabled)");
    }

    // ── Inline Comment Tests ──

    #[test]
    fn test_strip_inline_comment_basic() {
        assert_eq!(strip_inline_comment("key: value # comment"), "key: value");
        assert_eq!(strip_inline_comment("key: value  # comment"), "key: value");
        assert_eq!(strip_inline_comment("# full comment"), "");
        assert_eq!(strip_inline_comment("key: value"), "key: value");
    }

    #[test]
    fn test_strip_inline_comment_in_quotes() {
        // # inside double quotes should NOT be treated as a comment
        assert_eq!(
            strip_inline_comment("key: \"hello # world\" # comment"),
            "key: \"hello # world\""
        );
        // # inside single quotes should NOT be treated as a comment
        assert_eq!(
            strip_inline_comment("key: 'hello # world' # comment"),
            "key: 'hello # world'"
        );
        // No comment at all
        assert_eq!(
            strip_inline_comment("key: \"hello # world\""),
            "key: \"hello # world\""
        );
    }

    #[test]
    fn test_strip_inline_comment_unclosed_quote() {
        // Unclosed quote — # is still treated as inside the quote
        assert_eq!(
            strip_inline_comment("key: \"hello # world"),
            "key: \"hello # world"
        );
    }

    #[test]
    fn test_inline_comment_in_config() {
        let input = r#"global {
  tproxy_port: 15080 # main listen port
  log_level: info    # debug level
}

outbounds {
  nodes {
    main {
      protocol: socks5
      address: 127.0.0.1:1080 # local proxy
    }
  }

  groups {
    g {
      policy: fixed
      nodes(main)
    }
  }
}

routing {
  fallback: proxy(g) # default route
}
"#;
        let config = parse_daefile(input).expect("inline comment config parse failed");
        assert_eq!(config.runtime.tproxy_port, 15080);
        assert_eq!(config.runtime.log_level, "info");
        assert_eq!(config.outbounds.nodes[0].address, "127.0.0.1:1080");
        assert_eq!(config.routing.fallback, "proxy(g)");
    }

    #[test]
    fn test_inline_comment_with_quotes_in_config() {
        let input = r#"global {
  tproxy_port: 15080
  log_level: info
}

outbounds {
  nodes {
    main {
      protocol: socks5
      address: 127.0.0.1:1080
    }
  }

  groups {
    g {
      policy: fixed
      nodes(main)
    }
  }
}

routing {
  fallback: proxy(g)
}

api {
  enabled: true
  listen: 127.0.0.1:9090
  token: 'secret#token' # this is the token
}
"#;
        let config = parse_daefile(input).expect("quote+comment config parse failed");
        let api = config.api.as_ref().expect("api should exist");
        // The # inside quotes should be preserved
        assert_eq!(api.token, "secret#token");
    }

    // ── Multiline (continuation) Tests ──

    #[test]
    fn test_preprocess_multiline_basic() {
        // "line1 \\\n  line2" → after removing `\` and newline: "line1   line2"
        let input = "line1 \\\n  line2";
        assert_eq!(preprocess_multiline(input), "line1   line2");
    }

    #[test]
    fn test_preprocess_multiline_no_continuation() {
        let input = "line1\nline2";
        assert_eq!(preprocess_multiline(input), "line1\nline2");
    }

    #[test]
    fn test_preprocess_multiline_chained() {
        // All three lines joined: "line1   line2   line3"
        let input = "line1 \\\n  line2 \\\n  line3";
        assert_eq!(preprocess_multiline(input), "line1   line2   line3");
    }

    #[test]
    fn test_multiline_in_config() {
        // Demonstrate multiline value continuation for a long address field
        let input = r#"global {
  tproxy_port: 15080
  log_level: info
}

outbounds {
  nodes {
    main {
      protocol: socks5
      address: 127.0.0.1:\
        1080
    }
  }

  groups {
    g {
      policy: fixed
      nodes(main)
    }
  }
}

routing {
  fallback: proxy(g)
}
"#;
        let config = parse_daefile(input).expect("multiline config parse failed");
        assert_eq!(config.outbounds.nodes[0].protocol, "socks5");
        // After continuation: "127.0.0.1:        1080" — address value is joined
        assert_eq!(config.outbounds.nodes[0].address, "127.0.0.1:        1080");
    }

    #[test]
    fn test_multiline_chained_in_config() {
        // Demonstrate chained multiline continuation
        let input = r#"global {
  tproxy_port: 15080
  log_level: info
}

outbounds {
  nodes {
    main {
      protocol: socks5
      address: http://very-long-\
        url.example.com:\
        8080/proxy
    }
  }

  groups {
    g {
      policy: fixed
      nodes(main)
    }
  }
}

routing {
  fallback: proxy(g)
}
"#;
        let config = parse_daefile(input).expect("chained multiline config parse failed");
        assert_eq!(config.outbounds.nodes[0].address, "http://very-long-        url.example.com:        8080/proxy");
    }

    #[test]
    fn test_combined_multiline_and_comment() {
        let input = r#"global {
  tproxy_port: 15080 \
  log_level: info  # both multiline and comment
}

outbounds {
  nodes {
    main {
      protocol: socks5
      address: 127.0.0.1:1080
    }
  }

  groups {
    g {
      policy: fixed
      nodes(main)
    }
  }
}

routing {
  fallback: proxy(g)
}
"#;
        // The multiline joins "15080" and "log_level: info  # comment"
        // After joining: "15080 log_level: info  # comment"
        // Comment stripping happens after multiline, so: "15080 log_level: info"
        // This should fail to parse because "15080 log_level..." is not a valid global key-value pair
        let result = parse_daefile(input);
        assert!(result.is_err(), "should fail because multiline merges two separate fields");
    }
}
