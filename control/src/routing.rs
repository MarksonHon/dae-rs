//! Routing rule compiler
//!
//! Compiles daefile routing rules into eBPF MatchSet entries that tproxy.c can evaluate.
//! This mirrors the functionality of dae's `routing_matcher_builder.go` and `routing/normalize.go`.
//!
//! Pipeline:
//!   1. Parse raw match expressions into [`NormalizedProgram`] (IR with AND/OR structure)
//!   2. Use [`RulesBuilder`] with registered [`FunctionParser`]s to lower the IR
//!   3. Collect [`MatchSet`] entries, LPM tries, and domain sets for eBPF map writing

use anyhow::{anyhow, Context, Result};
use bytemuck::Zeroable;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use tracing::{debug, info};

use crate::config;
use crate::ebpf::{match_type, outbound};
use crate::ebpf::{CidrEntry, LpmKey, MatchSet, MatchSetValue, PortRange};

// ============================================================================
// Constants (must match tproxy.c and common/consts/ebpf_generated.go)
// ============================================================================

/// Maximum number of match sets in routing_map
pub const MAX_MATCH_SET_LEN: usize = 32 * 32; // 1024

/// Maximum number of LPM tries
pub const MAX_LPM_NUM: usize = MAX_MATCH_SET_LEN + 8;

// ============================================================================
// IR: Intermediate Representation for Routing Rules
// ============================================================================

/// A parsed routing function, such as `dport(80,443)` or `!domain(suffix:google.com)`.
///
/// Parameters are kept as raw strings. Key:value extraction (e.g. `suffix:` prefix for domain)
/// is handled by the individual function parsers below.
#[derive(Debug, Clone)]
pub struct Function {
    /// Function name: "dport", "domain", "dip", "sip", etc.
    pub name: String,
    /// Whether this function is negated with `!`
    pub not: bool,
    /// Raw comma-separated parameter values.
    /// For `dport(80,443)` → ["80", "443"]
    /// For `domain(suffix:google.com)` → ["suffix:google.com"]
    /// For `mac(00:11:22:33:44:55)` → ["00:11:22:33:44:55"]
    pub raw_params: Vec<String>,
}

impl FromStr for Function {
    type Err = anyhow::Error;

    /// Parse a function from its string representation.
    ///
    /// Supported forms:
    /// - `dport(80,443)` → name="dport", not=false, raw_params=["80", "443"]
    /// - `!domain(suffix:google.com)` → name="domain", not=true, raw_params=["suffix:google.com"]
    /// - `mac(00:11:22:33:44:55)` → name="mac", not=false, raw_params=["00:11:22:33:44:55"]
    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Err(anyhow!("empty function"));
        }

        // Check for negation
        let (not, rest) = if let Some(stripped) = s.strip_prefix('!') {
            (true, stripped.trim())
        } else {
            (false, s)
        };

        // Find the opening parenthesis
        let paren_pos = rest
            .find('(')
            .ok_or_else(|| anyhow!("expected '(' in function: {rest}"))?;

        let name = rest[..paren_pos].trim().to_string();
        let inner = rest[paren_pos + 1..]
            .strip_suffix(')')
            .ok_or_else(|| anyhow!("expected ')' to close function: {rest}"))?;

        // Parse comma-separated parameters, respecting parentheses nesting.
        // Values are kept as raw strings — each function parser handles key:value extraction.
        let raw_params = parse_comma_separated(inner)?
            .into_iter()
            .map(|p| p.trim().to_string())
            .collect();

        Ok(Function {
            name,
            not,
            raw_params,
        })
    }
}

/// Parse a comma-separated list respecting nested parentheses.
///
/// For example: `suffix:google.com, suffix:baidu.com` → ["suffix:google.com", "suffix:baidu.com"]
fn parse_comma_separated(input: &str) -> Result<Vec<String>> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;

    for ch in input.chars() {
        match ch {
            '(' => {
                depth += 1;
                current.push(ch);
            }
            ')' if depth > 0 => {
                depth -= 1;
                current.push(ch);
            }
            ')' => {
                current.push(ch);
            }
            ',' if depth == 0 => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    parts.push(trimmed);
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        parts.push(trimmed);
    }

    Ok(parts)
}

/// A parsed outbound action.
///
/// Examples:
/// - `direct` → name="direct", mark=0, must=false
/// - `block` → name="block"
/// - `proxy(my_group, mark=0x100, must)` → name="my_group", mark=0x100, must=true
#[derive(Debug, Clone)]
pub struct Outbound {
    /// Outbound/group name, or "direct"/"block"
    pub name: String,
    /// Optional mark value
    pub mark: u32,
    /// Whether this outbound is marked as "must" (force proxy even for DNS)
    pub must: bool,
}

impl Outbound {
    /// Create a new outbound with default mark/must.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            mark: 0,
            must: false,
        }
    }

    /// Parse an outbound from its string representation.
    ///
    /// Supports `proxy(name, mark=0x100, must)` syntax.
    pub fn parse_action(action: &str) -> Result<Self> {
        let action = action.trim();

        // Handle simple keywords
        if action == "direct" || action == "block" {
            return Ok(Outbound::new(action));
        }

        // Handle `proxy(name)` or `proxy(name, mark=0x100, must)` or bare `name`
        if let Some(inner) = action
            .strip_prefix("proxy(")
            .and_then(|s| s.strip_suffix(')'))
        {
            Self::parse_proxy_params(inner)
        } else {
            // Try parsing as a bare group name
            Ok(Outbound::new(action))
        }
    }

    /// Parse the parameters inside `proxy(...)`.
    fn parse_proxy_params(inner: &str) -> Result<Self> {
        let parts = parse_comma_separated(inner)?;
        if parts.is_empty() {
            return Err(anyhow!("empty proxy outbound"));
        }

        let mut name = String::new();
        let mut mark = 0u32;
        let mut must = false;

        for part in parts {
            let part = part.trim();
            if part == "must" {
                must = true;
            } else if let Some(mark_val) = part.strip_prefix("mark=") {
                mark = parse_mark_value(mark_val).context("invalid mark value in outbound")?;
            } else if name.is_empty() {
                name = part.to_string();
            } else {
                return Err(anyhow!("unexpected parameter in outbound: {part}"));
            }
        }

        if name.is_empty() {
            return Err(anyhow!("missing group name in proxy outbound"));
        }

        Ok(Outbound { name, mark, must })
    }
}

/// Parse a mark value that can be decimal or hex.
fn parse_mark_value(s: &str) -> Result<u32> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        s.parse::<u32>()
    }
    .with_context(|| format!("cannot parse mark value: {s}"))
}

/// A single normalized routing rule.
#[derive(Debug, Clone)]
pub struct NormalizedRule {
    /// The AND-separated functions in this rule.
    /// `dport(80) && domain(suffix:google.com)` → [Function("dport"), Function("domain")]
    pub and_functions: Vec<Function>,
    /// The outbound action for this rule.
    pub outbound: Outbound,
}

/// A NormalizedProgram is the shared routing IR consumed by matcher builders.
///
/// This mirrors dae's `routing.NormalizedProgram` — rules are immutable after
/// construction and may be lowered into kernel-space MatchSet entries.
pub struct NormalizedProgram {
    pub rules: Vec<NormalizedRule>,
    pub fallback: Outbound,
}

impl NormalizedProgram {
    /// Build a NormalizedProgram from a daefile routing config.
    pub fn from_config(routing: &config::RoutingConfig) -> Result<Self> {
        let mut rules = Vec::with_capacity(routing.rules.len());

        for rule in &routing.rules {
            let normalized = Self::parse_rule(rule)?;
            rules.push(normalized);
        }

        let fallback = Outbound::parse_action(&routing.fallback)
            .with_context(|| format!("invalid fallback: {}", routing.fallback))?;

        Ok(NormalizedProgram { rules, fallback })
    }

    /// Parse a single RouteRule into a NormalizedRule.
    ///
    /// The match expression is split on `&&` to extract AND-separated functions.
    /// Each part is then parsed as a `Function`.
    fn parse_rule(rule: &config::RouteRule) -> Result<NormalizedRule> {
        let match_expr = rule.r#match.trim();

        if match_expr.is_empty() || match_expr == "fallback" {
            // Empty/fallback rules are handled by the overall fallback
            return Ok(NormalizedRule {
                and_functions: Vec::new(),
                outbound: Outbound::parse_action(&rule.action)?,
            });
        }

        let outbound = Outbound::parse_action(&rule.action)?;

        // Split on `&&` to get AND-separated functions.
        // But we must respect parentheses: `domain(suffix:a&&b)` should not be split.
        let func_strs = split_and_respecting_parens(match_expr);
        let mut and_functions = Vec::with_capacity(func_strs.len());

        for func_str in func_strs {
            let func_str = func_str.trim();
            if func_str.is_empty() {
                continue;
            }
            let f: Function = func_str.parse().with_context(|| {
                format!(
                    "failed to parse function in rule '{}': {func_str}",
                    rule.r#match
                )
            })?;
            and_functions.push(f);
        }

        Ok(NormalizedRule {
            and_functions,
            outbound,
        })
    }
}

/// Split a match expression on `&&` while respecting parentheses nesting.
///
/// `dport(80) && domain(suffix:google.com)` → ["dport(80)", "domain(suffix:google.com)"]
fn split_and_respecting_parens(input: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;

    for ch in input.chars() {
        match ch {
            '(' => {
                depth += 1;
                current.push(ch);
            }
            ')' if depth > 0 => {
                depth -= 1;
                current.push(ch);
            }
            ')' => {
                current.push(ch);
            }
            '&' if depth == 0 => {
                // Check for `&&`
                if current.ends_with('&') {
                    // Pop the previous '&' and push the part
                    current.pop(); // remove trailing '&'
                    let trimmed = current.trim().to_string();
                    if !trimmed.is_empty() {
                        parts.push(trimmed);
                    }
                    current.clear();
                } else {
                    current.push(ch);
                }
            }
            _ => current.push(ch),
        }
    }

    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        parts.push(trimmed);
    }

    parts
}

// ============================================================================
// RulesBuilder: Function Parsing Pipeline
// ============================================================================

/// The result of lowering a single function invocation to MatchSet entries.
///
/// This is the intermediate output from a FunctionParser callback. It collects
/// MatchSet entries that will be written to the eBPF routing_map, along with
/// any side data (LPM tries, domain sets) that must also be recorded.
pub struct FunctionLowering {
    /// The MatchSet entries generated for this function invocation.
    pub match_sets: Vec<MatchSet>,
}

impl FunctionLowering {
    pub fn new() -> Self {
        Self {
            match_sets: Vec::new(),
        }
    }

    pub fn single(ms: MatchSet) -> Self {
        Self {
            match_sets: vec![ms],
        }
    }
}

/// Type alias for a function parser callback.
///
/// Parameters:
/// - `f`: The parsed function (contains `not`, `name`, `params`)
/// - `key`: The current parameter key (for functions with multiple key groups)
/// - `param_values`: The values for this key group
/// - `override_outbound`: The outbound to use (handles LOGICAL_OR/LOGICAL_AND chaining)
///
/// Returns:
/// - A list of MatchSet entries for this function invocation
pub type FunctionParser = fn(
    f: &Function,
    key: &str,
    param_values: &[String],
    override_outbound: &Outbound,
) -> Result<Vec<MatchSet>>;

/// A RulesBuilder registers function parsers and applies a NormalizedProgram.
///
/// This mirrors dae's `RoutingMatcherBuilder` which uses `RulesBuilder` internally.
pub struct RulesBuilder {
    parsers: HashMap<String, FunctionParser>,
}

impl RulesBuilder {
    pub fn new() -> Self {
        Self {
            parsers: HashMap::new(),
        }
    }

    /// Register a function parser for a specific function name.
    pub fn register(&mut self, name: &str, parser: FunctionParser) {
        self.parsers.insert(name.to_string(), parser);
    }

    /// Apply the NormalizedProgram: walk all rules and collect MatchSet entries.
    ///
    /// The `outbound_id_map` maps group names to eBPF outbound IDs.
    /// Returns the flattened MatchSet list (with proper LOGICAL_OR/LOGICAL_AND markers).
    pub fn apply(
        &self,
        program: &NormalizedProgram,
        outbound_id_map: &HashMap<String, u8>,
    ) -> Result<Vec<MatchSet>> {
        let mut all_sets = Vec::new();

        for rule in &program.rules {
            let outbound_id = resolve_outbound_id(&rule.outbound, outbound_id_map)?;

            if rule.and_functions.is_empty() {
                all_sets.push(build_fallback_matchset(outbound_id, &rule.outbound));
                continue;
            }

            // Process each AND-separated function in order.
            for (i_func, func) in rule.and_functions.iter().enumerate() {
                let parser = self
                    .parsers
                    .get(&func.name)
                    .ok_or_else(|| anyhow!("unknown function: '{}' in rule", func.name))?;

                let (key_to_values, key_order) = group_params_by_key(&func.raw_params);
                let is_last_function = i_func == rule.and_functions.len() - 1;

                for (j_match_set, key) in key_order.iter().enumerate() {
                    let values = &key_to_values[key.as_str()];
                    let is_last_in_function = j_match_set == key_order.len() - 1;

                    let override_outbound =
                        compute_override_outbound(is_last_in_function, is_last_function, &rule.outbound);

                    debug!(
                        "apply: {}({}) key={} -> outbound={} (func={}/{}, part={}/{})",
                        if func.not { "!" } else { "" },
                        func.name,
                        key,
                        override_outbound.name,
                        i_func + 1,
                        rule.and_functions.len(),
                        j_match_set + 1,
                        key_order.len()
                    );

                    let ms_list = parser(func, key, values, &override_outbound)?;
                    all_sets.extend(ms_list);
                }
            }
        }

        Ok(all_sets)
    }
}

impl Default for RulesBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Group raw parameters by their key prefix (before `:`), preserving insertion order.
///
/// For `["suffix:google.com", "suffix:baidu.com", "keyword:example"]`:
/// → key_to_values: {"suffix" → ["google.com", "baidu.com"], "keyword" → ["example"]}
/// → key_order: ["suffix", "keyword"]
///
/// For `["10.0.0.0/8", "192.168.0.0/16"]` (no key prefix):
/// → key_to_values: {"" → ["10.0.0.0/8", "192.168.0.0/16"]}
/// → key_order: [""]
fn group_params_by_key(raw_params: &[String]) -> (HashMap<String, Vec<String>>, Vec<String>) {
    let mut key_to_values: HashMap<String, Vec<String>> = HashMap::new();
    let mut key_order: Vec<String> = Vec::new();

    for raw in raw_params {
        let (key, val) = if let Some((k, v)) = raw.split_once(':') {
            (k.trim().to_string(), v.trim().to_string())
        } else {
            (String::new(), raw.trim().to_string())
        };

        let entry = key_to_values.entry(key.clone());
        let inserted = matches!(&entry, std::collections::hash_map::Entry::Vacant(_));
        let values = entry.or_insert_with(Vec::new);
        values.push(val);
        if inserted && !key.is_empty() {
            key_order.push(key);
        }
    }

    // If there are unkeyed params, add them as a "" key group at the end
    if let Some(unkeyed) = key_to_values.get("") {
        if unkeyed.iter().any(|v| !v.is_empty()) {
            key_order.push(String::new());
        }
    }

    (key_to_values, key_order)
}

// ============================================================================
// Shared Lowering Helpers
// ============================================================================

/// Determine the override outbound for a given position within a rule.
///
/// Within a function's key groups, all except the last get `LOGICAL_OR`.
/// Between AND-separated functions, all except the last get `LOGICAL_AND`.
/// The final entry uses the real outbound.
fn compute_override_outbound(
    is_last_in_function: bool,
    is_last_function: bool,
    rule_outbound: &Outbound,
) -> Outbound {
    if !is_last_in_function {
        Outbound {
            name: "LOGICAL_OR".to_string(),
            mark: rule_outbound.mark,
            must: rule_outbound.must,
        }
    } else if !is_last_function {
        Outbound {
            name: "LOGICAL_AND".to_string(),
            mark: rule_outbound.mark,
            must: rule_outbound.must,
        }
    } else {
        Outbound {
            name: rule_outbound.name.clone(),
            mark: rule_outbound.mark,
            must: rule_outbound.must,
        }
    }
}

/// Resolve an outbound name to its eBPF outbound ID.
///
/// Handles special built-in names ("direct", "block", "LOGICAL_OR", etc.)
/// and looks up user-defined outbounds via `outbound_id_map`.
fn resolve_outbound_id(
    outbound: &Outbound,
    outbound_id_map: &HashMap<String, u8>,
) -> Result<u8> {
    match outbound.name.as_str() {
        "direct" => Ok(outbound::DIRECT),
        "block" => Ok(outbound::BLOCK),
        "LOGICAL_OR" => Ok(outbound::LOGICAL_OR),
        "LOGICAL_AND" => Ok(outbound::LOGICAL_AND),
        "must" | "must_direct" => Ok(outbound::MUST_RULES),
        "control_plane_routing" => Ok(outbound::CONTROL_PLANE_ROUTING),
        name => outbound_id_map
            .get(name)
            .copied()
            .ok_or_else(|| anyhow!("outbound '{}' not found in outbound_id_map", name)),
    }
}

/// Build a FALLBACK MatchSet entry for a rule with no match conditions.
fn build_fallback_matchset(outbound_id: u8, rule_outbound: &Outbound) -> MatchSet {
    let mut ms = MatchSet::zeroed();
    ms.r#type = match_type::FALLBACK;
    ms.outbound = outbound_id;
    ms.not = 0;
    ms.must = if rule_outbound.must { 1 } else { 0 };
    ms.mark = rule_outbound.mark;
    ms
}

// ============================================================================
// Function Parsers
// ============================================================================

/// Domain key constants matching dae's consts.RoutingDomainKey
pub mod domain_key {
    pub const SUFFIX: &str = "suffix";
    pub const KEYWORD: &str = "keyword";
    pub const REGEX: &str = "regex";
    pub const FULL: &str = "full";
}

/// Built-in function parsers. These mirror dae's `routing_matcher_builder.go` callbacks.

/// Parser for `dip(...)` / `ip(...)` — destination IP set.
pub fn parse_dip_fn(
    f: &Function,
    _key: &str,
    values: &[String],
    override_outbound: &Outbound,
) -> Result<Vec<MatchSet>> {
    let _cidrs = parse_cidr_values(values)?;
    // cidrs are accumulated into the LPM trie during compile_rules
    // The MatchSet is written with index = 0 (the caller fixes it later)
    let mut ms = MatchSet::zeroed();
    ms.r#type = match_type::IP_SET;
    ms.value.index = 0; // placeholder
    ms.not = if f.not { 1 } else { 0 };
    ms.outbound = lookup_outbound_id_for_ms(override_outbound)?;
    ms.must = if override_outbound.must { 1 } else { 0 };
    ms.mark = override_outbound.mark;
    Ok(vec![ms])
}

/// Parser for `sip(...)` / `source_ip(...)` — source IP set.
pub fn parse_sip_fn(
    f: &Function,
    _key: &str,
    values: &[String],
    override_outbound: &Outbound,
) -> Result<Vec<MatchSet>> {
    let _cidrs = parse_cidr_values(values)?;
    let mut ms = MatchSet::zeroed();
    ms.r#type = match_type::SOURCE_IP_SET;
    ms.value.index = 0; // placeholder
    ms.not = if f.not { 1 } else { 0 };
    ms.outbound = lookup_outbound_id_for_ms(override_outbound)?;
    ms.must = if override_outbound.must { 1 } else { 0 };
    ms.mark = override_outbound.mark;
    Ok(vec![ms])
}

/// Parser for `dport(...)` — destination port or port range.
pub fn parse_dport_fn(
    f: &Function,
    _key: &str,
    values: &[String],
    override_outbound: &Outbound,
) -> Result<Vec<MatchSet>> {
    let mut match_sets = Vec::new();

    for val in values {
        if let Some((start_str, end_str)) = val.split_once('-') {
            let start: u16 = start_str.trim().parse().context("invalid port start")?;
            let end: u16 = end_str.trim().parse().context("invalid port end")?;
            let mut ms = MatchSet::zeroed();
            ms.r#type = match_type::PORT;
            ms.value = MatchSetValue {
                port_range: PortRange {
                    port_start: start,
                    port_end: end,
                },
            };
            ms.not = if f.not { 1 } else { 0 };
            ms.outbound = lookup_outbound_id_for_ms(override_outbound)?;
            ms.must = if override_outbound.must { 1 } else { 0 };
            ms.mark = override_outbound.mark;
            match_sets.push(ms);
        } else {
            let port: u16 = val.parse().context("invalid port value")?;
            let mut ms = MatchSet::zeroed();
            ms.r#type = match_type::PORT;
            ms.value = MatchSetValue {
                port_range: PortRange {
                    port_start: port,
                    port_end: port,
                },
            };
            ms.not = if f.not { 1 } else { 0 };
            ms.outbound = lookup_outbound_id_for_ms(override_outbound)?;
            ms.must = if override_outbound.must { 1 } else { 0 };
            ms.mark = override_outbound.mark;
            match_sets.push(ms);
        }
    }

    Ok(match_sets)
}

/// Parser for `sport(...)` — source port or port range.
pub fn parse_sport_fn(
    f: &Function,
    _key: &str,
    values: &[String],
    override_outbound: &Outbound,
) -> Result<Vec<MatchSet>> {
    let mut match_sets = Vec::new();

    for val in values {
        if let Some((start_str, end_str)) = val.split_once('-') {
            let start: u16 = start_str.trim().parse().context("invalid port start")?;
            let end: u16 = end_str.trim().parse().context("invalid port end")?;
            let mut ms = MatchSet::zeroed();
            ms.r#type = match_type::SOURCE_PORT;
            ms.value = MatchSetValue {
                port_range: PortRange {
                    port_start: start,
                    port_end: end,
                },
            };
            ms.not = if f.not { 1 } else { 0 };
            ms.outbound = lookup_outbound_id_for_ms(override_outbound)?;
            ms.must = if override_outbound.must { 1 } else { 0 };
            ms.mark = override_outbound.mark;
            match_sets.push(ms);
        } else {
            let port: u16 = val.parse().context("invalid port value")?;
            let mut ms = MatchSet::zeroed();
            ms.r#type = match_type::SOURCE_PORT;
            ms.value = MatchSetValue {
                port_range: PortRange {
                    port_start: port,
                    port_end: port,
                },
            };
            ms.not = if f.not { 1 } else { 0 };
            ms.outbound = lookup_outbound_id_for_ms(override_outbound)?;
            ms.must = if override_outbound.must { 1 } else { 0 };
            ms.mark = override_outbound.mark;
            match_sets.push(ms);
        }
    }

    Ok(match_sets)
}

/// Parser for `l4proto(...)` — L4 protocol type.
pub fn parse_l4proto_fn(
    f: &Function,
    _key: &str,
    values: &[String],
    override_outbound: &Outbound,
) -> Result<Vec<MatchSet>> {
    let mut proto: u8 = 0;
    for val in values {
        match val.to_lowercase().as_str() {
            "tcp" => proto |= 0x01, // L4ProtoType_TCP
            "udp" => proto |= 0x02, // L4ProtoType_UDP
            other => return Err(anyhow!("unknown L4 protocol: {other}")),
        }
    }

    let mut ms = MatchSet::zeroed();
    ms.r#type = match_type::L4_PROTO;
    ms.value.l4proto_type = proto;
    ms.not = if f.not { 1 } else { 0 };
    ms.outbound = lookup_outbound_id_for_ms(override_outbound)?;
    ms.must = if override_outbound.must { 1 } else { 0 };
    ms.mark = override_outbound.mark;
    Ok(vec![ms])
}

/// Parser for `ipversion(...)` — IP version.
pub fn parse_ipversion_fn(
    f: &Function,
    _key: &str,
    values: &[String],
    override_outbound: &Outbound,
) -> Result<Vec<MatchSet>> {
    let mut version: u8 = 0;
    for val in values {
        match val.trim() {
            "4" => version |= 0x01, // IpVersionType_4
            "6" => version |= 0x02, // IpVersionType_6
            other => return Err(anyhow!("unknown IP version: {other}")),
        }
    }

    let mut ms = MatchSet::zeroed();
    ms.r#type = match_type::IP_VERSION;
    ms.value.ip_version = version;
    ms.not = if f.not { 1 } else { 0 };
    ms.outbound = lookup_outbound_id_for_ms(override_outbound)?;
    ms.must = if override_outbound.must { 1 } else { 0 };
    ms.mark = override_outbound.mark;
    Ok(vec![ms])
}

/// Parser for `domain(...)` — domain matching.
pub fn parse_domain_fn(
    f: &Function,
    #[allow(unused)] key: &str,
    #[allow(unused)] values: &[String],
    override_outbound: &Outbound,
) -> Result<Vec<MatchSet>> {
    // Validate domain key
    match key {
        "" | "suffix" | "keyword" | "regex" | "full" | "domain" => {}
        other => return Err(anyhow!("unknown domain key: {other}")),
    }

    let mut ms = MatchSet::zeroed();
    ms.r#type = match_type::DOMAIN_SET;
    ms.value.index = 0; // placeholder; resolved by caller based on domain_sets index
    ms.not = if f.not { 1 } else { 0 };
    ms.outbound = lookup_outbound_id_for_ms(override_outbound)?;
    ms.must = if override_outbound.must { 1 } else { 0 };
    ms.mark = override_outbound.mark;
    // NOTE: domain values are accumulated in compile_rules and written to domain_routing_map
    Ok(vec![ms])
}

/// Parser for `process_name(...)` — process name matching.
pub fn parse_process_name_fn(
    f: &Function,
    _key: &str,
    values: &[String],
    override_outbound: &Outbound,
) -> Result<Vec<MatchSet>> {
    fn comm_bytes(s: &str) -> [u8; 16] {
        let mut buf = [0u8; 16];
        let len = s.len().min(16);
        buf[..len].copy_from_slice(&s.as_bytes()[..len]);
        buf
    }

    let mut match_sets = Vec::new();
    for val in values {
        let mut ms = MatchSet::zeroed();
        ms.r#type = match_type::PROCESS_NAME;
        ms.value.pname = comm_bytes(val);
        ms.not = if f.not { 1 } else { 0 };
        ms.outbound = lookup_outbound_id_for_ms(override_outbound)?;
        ms.must = if override_outbound.must { 1 } else { 0 };
        ms.mark = override_outbound.mark;
        match_sets.push(ms);
    }
    Ok(match_sets)
}

/// Parser for `dscp(...)` — DSCP value matching.
pub fn parse_dscp_fn(
    f: &Function,
    _key: &str,
    values: &[String],
    override_outbound: &Outbound,
) -> Result<Vec<MatchSet>> {
    let mut match_sets = Vec::new();
    for val in values {
        let dscp: u8 = val.parse().context("invalid DSCP value")?;
        let mut ms = MatchSet::zeroed();
        ms.r#type = match_type::DSCP;
        ms.value.dscp = dscp;
        ms.not = if f.not { 1 } else { 0 };
        ms.outbound = lookup_outbound_id_for_ms(override_outbound)?;
        ms.must = if override_outbound.must { 1 } else { 0 };
        ms.mark = override_outbound.mark;
        match_sets.push(ms);
    }
    Ok(match_sets)
}

/// Parser for `mac(...)` — source MAC address matching.
pub fn parse_mac_fn(
    f: &Function,
    _key: &str,
    values: &[String],
    override_outbound: &Outbound,
) -> Result<Vec<MatchSet>> {
    let mut mac_addrs: Vec<[u8; 6]> = Vec::new();
    for val in values {
        let mac = parse_mac_address(val)?;
        mac_addrs.push(mac);
    }

    if f.not {
        // For negative MAC rules, add zero MAC to exclude internal traffic
        mac_addrs.push([0u8; 6]);
    }

    // mac_addrs are accumulated into LPM trie during compile_rules
    let mut ms = MatchSet::zeroed();
    ms.r#type = match_type::MAC;
    ms.value.index = 0; // placeholder
    ms.not = if f.not { 1 } else { 0 };
    ms.outbound = lookup_outbound_id_for_ms(override_outbound)?;
    ms.must = if override_outbound.must { 1 } else { 0 };
    ms.mark = override_outbound.mark;
    Ok(vec![ms])
}

/// Parser for `qtype(...)` — DNS query type matching.
pub fn parse_qtype_fn(
    f: &Function,
    _key: &str,
    _values: &[String],
    override_outbound: &Outbound,
) -> Result<Vec<MatchSet>> {
    let mut ms = MatchSet::zeroed();
    ms.r#type = match_type::QTYPE;
    // QType is a placeholder; full DNS query type matching is TBD
    ms.not = if f.not { 1 } else { 0 };
    ms.outbound = lookup_outbound_id_for_ms(override_outbound)?;
    ms.must = if override_outbound.must { 1 } else { 0 };
    ms.mark = override_outbound.mark;
    Ok(vec![ms])
}

/// Parser for `upstream(...)` — upstream group matching.
pub fn parse_upstream_fn(
    f: &Function,
    _key: &str,
    values: &[String],
    override_outbound: &Outbound,
) -> Result<Vec<MatchSet>> {
    let mut match_sets = Vec::new();
    for val in values {
        let mut ms = MatchSet::zeroed();
        ms.r#type = match_type::UPSTREAM;
        // Upstream name is stored in pname field (16 bytes)
        let mut name = [0u8; 16];
        let len = val.len().min(16);
        name[..len].copy_from_slice(&val.as_bytes()[..len]);
        ms.value.pname = name;
        ms.not = if f.not { 1 } else { 0 };
        ms.outbound = lookup_outbound_id_for_ms(override_outbound)?;
        ms.must = if override_outbound.must { 1 } else { 0 };
        ms.mark = override_outbound.mark;
        match_sets.push(ms);
    }
    Ok(match_sets)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert an Outbound to an eBPF outbound ID for writing into a MatchSet.
fn lookup_outbound_id_for_ms(outbound: &Outbound) -> Result<u8> {
    match outbound.name.as_str() {
        "direct" => Ok(outbound::DIRECT),
        "block" => Ok(outbound::BLOCK),
        "LOGICAL_OR" => Ok(outbound::LOGICAL_OR),
        "LOGICAL_AND" => Ok(outbound::LOGICAL_AND),
        "must" | "must_direct" => Ok(outbound::MUST_RULES),
        "control_plane_routing" => Ok(outbound::CONTROL_PLANE_ROUTING),
        // Other names are looked up later via outbound_id_map
        _ => Ok(outbound::CONTROL_PLANE_ROUTING), // placeholder
    }
}

/// Parse CIDR values from string representations.
fn parse_cidr_values(values: &[String]) -> Result<Vec<ipnet::IpNet>> {
    let mut cidrs = Vec::new();

    for val in values {
        if val == "geoip:private" {
            cidrs.push("10.0.0.0/8".parse().unwrap());
            cidrs.push("172.16.0.0/12".parse().unwrap());
            cidrs.push("192.168.0.0/16".parse().unwrap());
            cidrs.push("127.0.0.0/8".parse().unwrap());
            continue;
        }

        // Try parsing as CIDR
        if let Ok(cidr) = val.parse::<ipnet::IpNet>() {
            cidrs.push(cidr);
            continue;
        }

        // Try parsing as plain IP
        if let Ok(addr) = val.parse::<Ipv4Addr>() {
            cidrs.push(ipnet::IpNet::new(addr.into(), 32).unwrap());
            continue;
        }
        if let Ok(addr) = val.parse::<Ipv6Addr>() {
            cidrs.push(ipnet::IpNet::new(addr.into(), 128).unwrap());
            continue;
        }

        return Err(anyhow!("cannot parse CIDR or IP: {val}"));
    }

    Ok(cidrs)
}

/// Parse a MAC address in hex notation.
fn parse_mac_address(s: &str) -> Result<[u8; 6]> {
    let s = s.trim();
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(anyhow!(
            "invalid MAC address format: {s} (expected xx:xx:xx:xx:xx:xx)"
        ));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .map_err(|_| anyhow!("invalid MAC address byte: {part}"))?;
    }
    Ok(mac)
}

/// FNV-1a hash for deterministic CIDR deduplication (same algorithm as original dae).
///
/// This ensures consistent dedup behavior across platforms.
fn hash_cidrs(cidrs: &[ipnet::IpNet]) -> u64 {
    const FNV_OFFSET_BASIS: u64 = 14695981039346656037;
    const FNV_PRIME: u64 = 1099511628211;

    let mut h = FNV_OFFSET_BASIS;
    for cidr in cidrs {
        // Hash prefix length
        h ^= cidr.prefix_len() as u64;
        h = h.wrapping_mul(FNV_PRIME);

        // Hash address bytes
        match cidr.addr() {
            std::net::IpAddr::V4(v4) => {
                for b in v4.octets() {
                    h ^= b as u64;
                    h = h.wrapping_mul(FNV_PRIME);
                }
            }
            std::net::IpAddr::V6(v6) => {
                for b in v6.octets() {
                    h ^= b as u64;
                    h = h.wrapping_mul(FNV_PRIME);
                }
            }
        }
    }
    h
}

/// Find or create an LPM trie for the given CIDR set.
/// Returns the index in lpm_tries.
fn find_or_create_lpm_trie(
    cidrs: &[ipnet::IpNet],
    lpm_tries: &mut Vec<Vec<ipnet::IpNet>>,
    lpm_dedup: &mut HashMap<u64, usize>,
) -> usize {
    let hash = hash_cidrs(cidrs);

    if let Some(&index) = lpm_dedup.get(&hash) {
        if lpm_tries[index] == cidrs {
            return index;
        }
    }

    let index = lpm_tries.len();
    lpm_tries.push(cidrs.to_vec());
    lpm_dedup.insert(hash, index);
    index
}

// ============================================================================
// Public API: compile_rules
// ============================================================================

/// Compiled routing rules ready to be written to eBPF maps.
pub struct CompiledRouting {
    /// MatchSet entries for routing_map
    pub match_sets: Vec<MatchSet>,
    /// LPM trie data: index -> list of CIDR prefixes
    pub lpm_tries: Vec<Vec<ipnet::IpNet>>,
    /// Domain routing data: rule_index -> list of domain suffixes/patterns
    pub domain_sets: Vec<Vec<String>>,
    /// Fallback outbound ID
    pub fallback_outbound: u8,
    /// Fallback mark value
    pub fallback_mark: u32,
    /// Fallback must flag
    pub fallback_must: u8,
}

/// Build a domain routing bitmap for a given (domain, IP) pair.
///
/// Checks which domain sets contain the given domain, and sets the
/// corresponding bits in the bitmap. The bitmap is stored in the eBPF
/// `domain_routing_map` keyed by the IP address.
///
/// Each `domain_sets[N]` is a list of domain patterns (with key prefix
/// stripped, e.g., `["baidu.com", "google.com"]`). The matching logic:
/// - Patterns stored during compilation of `domain(suffix:...)` → suffix match
/// - Patterns from `domain(keyword:...)` → substring match
/// - Patterns from `domain(full:...)` → exact match
/// - No prefix → treated as suffix (backward compat)
///
/// Returns a dynamically-sized bitmap where bit N is set if `domain` matches
/// `domain_sets[N]`. The bitmap length is `(domain_sets.len() + 31) / 32` words.
pub fn build_domain_routing_bitmap(
    domain: &str,
    domain_sets: &[Vec<String>],
) -> Vec<u32> {
    let num_words = (domain_sets.len() + 31) / 32;
    let mut bitmap = vec![0u32; num_words];
    let domain_lower = domain.to_lowercase();

    for (rule_idx, patterns) in domain_sets.iter().enumerate() {
        for pattern in patterns {
            // Check against the raw pattern (it may have a key: prefix)
            if let Some((key, pat)) = pattern.split_once(':') {
                let matched = match key {
                    "suffix" | "domain" => domain_lower.ends_with(pat) || domain_lower == pat,
                    "keyword" | "contains" => domain_lower.contains(pat),
                    "full" => domain_lower == pat,
                    _ => {
                        // Unknown key — try as bare pattern
                        domain_lower.ends_with(pat) || domain_lower == pat
                    }
                };
                if matched {
                    let word_idx = rule_idx / 32;
                    let bit_idx = rule_idx % 32;
                    if word_idx >= bitmap.len() {
                        // Safety boundary — should not happen as bitmap is sized
                        // from domain_sets.len(), but guard against races.
                        debug!(
                            rule_idx,
                            bitmap_len = bitmap.len(),
                            "build_domain_routing_bitmap: rule_idx exceeds bitmap length, expanding"
                        );
                        bitmap.resize(word_idx + 1, 0);
                    }
                    bitmap[word_idx] |= 1 << bit_idx;
                    break;
                }
            } else {
                // No key prefix — treat as suffix
                if domain_lower.ends_with(pattern) || domain_lower == *pattern {
                    let word_idx = rule_idx / 32;
                    let bit_idx = rule_idx % 32;
                    if word_idx >= bitmap.len() {
                        debug!(
                            rule_idx,
                            bitmap_len = bitmap.len(),
                            "build_domain_routing_bitmap: rule_idx exceeds bitmap length, expanding"
                        );
                        bitmap.resize(word_idx + 1, 0);
                    }
                    bitmap[word_idx] |= 1 << bit_idx;
                    break;
                }
            }
        }
    }

    bitmap
}

/// Compile daefile routing rules into MatchSet entries for eBPF.
///
/// This function produces a linear sequence of MatchSet entries that tproxy.c's
/// `route()` function can evaluate using `bpf_loop()`.
///
/// Automatically adds `dip(<proxy_server_ip>) -> direct` rules for all proxy
/// server IPs, matching the original dae behavior. This prevents traffic to
/// proxy servers from being re-proxied (loop prevention).
///
/// # Pipeline
///
/// 1. [`NormalizedProgram::from_config`] — parse raw rules into structured IR
/// 2. LPM trie creation & domain set collection (first pass)
/// 3. Lower IR to MatchSet entries with correct indices (second pass)
/// 4. Proxy server auto-direct rule insertion
/// 5. Fallback rule appending
pub fn compile_rules(
    routing: &config::RoutingConfig,
    outbounds: &config::OutboundsConfig,
    proxy_server_ips: &[std::net::IpAddr],
) -> Result<CompiledRouting> {
    let start = std::time::Instant::now();
    debug!(
        n_rules = routing.rules.len(),
        n_outbounds = outbounds.nodes.len(),
        n_proxy_ips = proxy_server_ips.len(),
        fallback = %routing.fallback,
        "compile_rules: starting"
    );

    // ── Step 1: Build NormalizedProgram from config ──
    let program =
        NormalizedProgram::from_config(routing).context("Failed to normalize routing rules")?;
    debug!("Step 1: NormalizedProgram built ({} rules)", program.rules.len());

    // ── Step 2: Build outbound ID map ──
    let outbound_id_map = build_outbound_id_map(outbounds);
    debug!("Step 2: outbound_id_map built ({} entries)", outbound_id_map.len());

    // ── Step 2.5: Prepare proxy server IP CIDRs for LPM trie ──
    // Convert each proxy server IP to a /32 (IPv4) or /128 (IPv6) CIDR entry.
    // These will be placed into an LPM trie for efficient matching.
    let proxy_cidrs: Vec<ipnet::IpNet> = proxy_server_ips
        .iter()
        .filter_map(|ip| {
            let prefix_len = match ip {
                std::net::IpAddr::V4(_) => 32u8,
                std::net::IpAddr::V6(_) => 128u8,
            };
            ipnet::IpNet::new(*ip, prefix_len).ok()
        })
        .collect();
    debug!("Step 2.5: {} proxy CIDRs prepared", proxy_cidrs.len());

    // ── Step 3: First pass — collect LPM trie and domain set data ──
    let mut lpm_tries: Vec<Vec<ipnet::IpNet>> = Vec::new();
    let mut lpm_dedup: HashMap<u64, usize> = HashMap::new();
    let mut dedup_count = 0usize;
    let mut domain_sets: Vec<Vec<String>> = Vec::new();
    let mut final_match_sets: Vec<MatchSet> = Vec::new();

    // ── Step 3.5: Create LPM trie for proxy server IPs ──
    // Add proxy server IPs as a dedicated LPM trie BEFORE user rules,
    // so the auto-direct MatchSet can reference it.
    // The trie index is stored for later MatchSet creation.
    let proxy_lpm_index = if !proxy_cidrs.is_empty() {
        Some(find_or_create_lpm_trie(
            &proxy_cidrs,
            &mut lpm_tries,
            &mut lpm_dedup,
        ))
    } else {
        None
    };

    // First pass over rules: collect LPM trie and domain set data.
    for rule in &program.rules {
        for func in &rule.and_functions {
            match func.name.as_str() {
                "dip" | "ip" => {
                    if let Ok(_cidrs) = parse_cidr_values(&func.raw_params) {
                        let old_len = lpm_tries.len();
                        let idx = find_or_create_lpm_trie(&_cidrs, &mut lpm_tries, &mut lpm_dedup);
                        if idx < old_len {
                            dedup_count += 1;
                        }
                    }
                }
                "sip" | "source_ip" => {
                    if let Ok(cidrs) = parse_cidr_values(&func.raw_params) {
                        let old_len = lpm_tries.len();
                        let idx = find_or_create_lpm_trie(&cidrs, &mut lpm_tries, &mut lpm_dedup);
                        if idx < old_len {
                            dedup_count += 1;
                        }
                    }
                }
                "mac" => {
                    // MAC addresses go into LPM trie as well (use raw_params to avoid colon splitting)
                    let mut mac_addrs: Vec<ipnet::IpNet> = Vec::new();
                    for val in &func.raw_params {
                        if let Ok(mac) = parse_mac_address(val) {
                            // Encode MAC as IPv6 LPM key (like tproxy.c does)
                            let mut addr16 = [0u8; 16];
                            addr16[10..16].copy_from_slice(&mac);
                            if let Ok(ipnet) = ipnet::IpNet::new(
                                std::net::IpAddr::V6(std::net::Ipv6Addr::from(addr16)),
                                128,
                            ) {
                                mac_addrs.push(ipnet);
                            }
                        }
                    }
                    if func.not {
                        // Add zero MAC for negative rules
                        let mut zero = [0u8; 16];
                        zero[10..16].copy_from_slice(&[0u8; 6]);
                        if let Ok(ipnet) = ipnet::IpNet::new(
                            std::net::IpAddr::V6(std::net::Ipv6Addr::from(zero)),
                            128,
                        ) {
                            mac_addrs.push(ipnet);
                        }
                    }
                    if !mac_addrs.is_empty() {
                        let old_len = lpm_tries.len();
                        let idx =
                            find_or_create_lpm_trie(&mac_addrs, &mut lpm_tries, &mut lpm_dedup);
                        if idx < old_len {
                            dedup_count += 1;
                        }
                    }
                }
                "domain" => {
                    // Strip key: prefix from domain values (e.g. "suffix:baidu.com" → "baidu.com")
                    let values: Vec<String> = func
                        .raw_params
                        .iter()
                        .map(|raw| {
                            if let Some((_, v)) = raw.split_once(':') {
                                v.trim().to_string()
                            } else {
                                raw.trim().to_string()
                            }
                        })
                        .collect();
                    if !values.is_empty() {
                        domain_sets.push(values);
                    }
                }
                _ => {}
            }
        }
    }

    // Second pass: build final match sets with correct LPM/domain indices.
    // We walk the program again, using shared helpers for outbound chaining
    // and fallback creation, then call build_match_set_for_function which
    // handles LPM trie and domain set index assignment.
    let mut rule_domain_idx = 0usize;

    for rule in &program.rules {
        let outbound_id = resolve_outbound_id(&rule.outbound, &outbound_id_map)?;

        if rule.and_functions.is_empty() {
            final_match_sets.push(build_fallback_matchset(outbound_id, &rule.outbound));
            continue;
        }

        for (i_func, func) in rule.and_functions.iter().enumerate() {
            let (key_to_values, key_order) = group_params_by_key(&func.raw_params);
            let is_last_function = i_func == rule.and_functions.len() - 1;

            for (j_match_set, key) in key_order.iter().enumerate() {
                let values = key_to_values
                    .get(key.as_str())
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]);
                let is_last_in_function = j_match_set == key_order.len() - 1;

                let ov_outbound =
                    compute_override_outbound(is_last_in_function, is_last_function, &rule.outbound);
                let ov_outbound_id = resolve_outbound_id(&ov_outbound, &outbound_id_map)?;

                let match_sets = build_match_set_for_function(
                    func,
                    key,
                    values,
                    ov_outbound_id,
                    &ov_outbound,
                    &mut lpm_tries,
                    &mut lpm_dedup,
                    &domain_sets,
                    &mut rule_domain_idx,
                )?;
                final_match_sets.extend(match_sets);
            }
        }
    }

    // ── Step 4: Prepend proxy server auto-direct rules ──
    // Insert `dip(<proxy_server_ip>) -> direct` at the FRONT of the match set list,
    // so they are evaluated BEFORE any user-defined rules.
    // This prevents traffic destined for proxy servers from being re-proxied,
    // which would create a loop: eBPF intercepts → TProxy → proxy server → eBPF intercepts again.
    if let Some(proxy_idx) = proxy_lpm_index {
        let mut ms = MatchSet::zeroed();
        ms.r#type = match_type::IP_SET;
        ms.value.index = proxy_idx as u32;
        ms.not = 0;
        ms.outbound = outbound::DIRECT;
        ms.must = 0;
        ms.mark = 0;
        final_match_sets.insert(0, ms);
        info!(
            proxy_ips = proxy_cidrs.len(),
            lpm_index = proxy_idx,
            "Auto-added direct rule for proxy server IPs",
        );
    }

    // ── Step 5: Append fallback rule (MUST be the last entry) ──
    let fallback_outbound = program.fallback.name.clone();
    let fallback_id = *outbound_id_map
        .get(&fallback_outbound)
        .unwrap_or(&outbound::CONTROL_PLANE_ROUTING);
    let fallback_mark = program.fallback.mark;
    let fallback_must = if program.fallback.must { 1 } else { 0 };

    final_match_sets.push(MatchSet {
        value: MatchSetValue::zeroed(),
        not: 0,
        r#type: match_type::FALLBACK,
        outbound: fallback_id,
        must: fallback_must,
        mark: fallback_mark,
    });

    let total_lpm = lpm_tries.len() + dedup_count;
    if total_lpm > 0 && dedup_count > 0 {
        let reduction = (dedup_count as f64 / total_lpm as f64) * 100.0;
        info!(
            match_sets = final_match_sets.len(),
            lpm_tries = lpm_tries.len(),
            dedup_saved = dedup_count,
            reduction = format!("{:.1}%", reduction),
            domain_sets = domain_sets.len(),
            fallback = %fallback_outbound,
            "Compiled routing rules with LPM dedup",
        );
    } else {
        info!(
            match_sets = final_match_sets.len(),
            lpm_tries = lpm_tries.len(),
            domain_sets = domain_sets.len(),
            fallback = %fallback_outbound,
            "Compiled routing rules",
        );
    }

    debug!(
        "compile_rules completed: {}ms ({} match_sets, {} lpm_tries, {} domain_sets, fallback={})",
        start.elapsed().as_millis(),
        final_match_sets.len(),
        lpm_tries.len(),
        domain_sets.len(),
        fallback_outbound,
    );

    Ok(CompiledRouting {
        match_sets: final_match_sets,
        lpm_tries,
        domain_sets,
        fallback_outbound: fallback_id,
        fallback_mark,
        fallback_must,
    })
}

// ============================================================================
// Userspace RoutingMatcher
// ============================================================================

/// Connection parameters for userspace routing decisions.
#[derive(Debug, Clone, Default)]
pub struct RoutingParams {
    pub src_ip: Option<std::net::IpAddr>,
    pub dst_ip: Option<std::net::IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub l4proto: Option<u8>,
    pub domain: Option<String>,
    pub process_name: Option<String>,
    pub dscp: Option<u8>,
}

/// Result of a userspace routing match.
#[derive(Debug, Clone, Default)]
pub struct RoutingResult {
    pub outbound: u8,
    pub mark: u32,
    pub must: bool,
}

/// Userspace routing matcher.
///
/// Mirrors dae's `RoutingMatcher` which evaluates routing rules in userspace
/// using LPM tries (IP matching) and domain suffix matching.
/// Used for DNS response processing, diagnostics, and fallback routing.
pub struct RoutingMatcher {
    /// MatchSet entries (same order as written to routing_map).
    match_sets: Vec<MatchSet>,
    /// LPM trie data: index -> list of CIDR prefixes.
    lpm_tries: Vec<Vec<ipnet::IpNet>>,
    /// Domain set data: rule_index -> list of domain patterns.
    domain_sets: Vec<Vec<String>>,
    /// Fallback outbound.
    fallback_outbound: u8,
    fallback_mark: u32,
    fallback_must: bool,
}

impl RoutingMatcher {
    /// Build a matcher from compiled routing data.
    pub fn from_compiled(compiled: &CompiledRouting) -> Self {
        Self {
            match_sets: compiled.match_sets.clone(),
            lpm_tries: compiled.lpm_tries.clone(),
            domain_sets: compiled.domain_sets.clone(),
            fallback_outbound: compiled.fallback_outbound,
            fallback_mark: compiled.fallback_mark,
            fallback_must: compiled.fallback_must != 0,
        }
    }

    /// Evaluate routing rules for the given connection parameters.
    ///
    /// Walks the MatchSet array the same way the eBPF `route()` function does:
    /// each rule is a sequence of MatchSet entries ending with a terminal outbound
    /// (not LOGICAL_OR/LOGICAL_AND). Within a rule, LOGICAL_OR separates subrule
    /// alternatives, and LOGICAL_AND links successive subrules.
    pub fn match_routing(&self, params: &RoutingParams) -> RoutingResult {
        let len = self.match_sets.len();
        let mut i = 0;

        while i < len {
            let mut good_subrule = false;
            let mut bad_rule = false;
            let mut must_flag = false;

            // Walk entries belonging to one rule.
            while i < len {
                let ms = &self.match_sets[i];
                let outbound = ms.outbound;

                // If we already have a subrule result, check whether this is
                // a continuation (LOGICAL_OR/LOGICAL_AND) or a new rule start.
                if good_subrule || bad_rule {
                    let is_logical_or = (outbound & outbound::LOGICAL_MASK) == outbound::LOGICAL_OR;
                    let is_logical_and = outbound == outbound::LOGICAL_AND;
                    if !is_logical_or && !is_logical_and {
                        // Not a continuation — we've reached the terminal entry
                        // (or a new rule). The result is already determined.
                        break;
                    }
                    // Continue to next entry in the same rule
                    i += 1;
                    continue;
                }

                // No prior result — evaluate this match entry
                let matched = self.eval_match(ms, params);

                if ms.not != 0 {
                    // NOT inverts the match logic
                    if matched {
                        bad_rule = true;
                    } else {
                        good_subrule = true;
                    }
                } else if matched {
                    good_subrule = true;
                }

                // Check if this is a terminal entry (not LOGICAL_OR/LOGICAL_AND).
                // LOGICAL_MASK = 0xFE catches both LOGICAL_OR (0xFE) and LOGICAL_AND (0xFF).
                if (outbound & outbound::LOGICAL_MASK) != outbound::LOGICAL_MASK {
                    // Terminal: end of this rule.
                    if !bad_rule && good_subrule {
                        if outbound == outbound::MUST_RULES {
                            must_flag = true;
                            good_subrule = false;
                            bad_rule = false;
                            i += 1;
                            continue; // Continue to next rule with must flag
                        }
                        return RoutingResult {
                            outbound,
                            mark: ms.mark,
                            must: must_flag || ms.must != 0,
                        };
                    }
                    // Rule didn't match, move to next
                    break;
                }

                // LOGICAL_OR or LOGICAL_AND — continue to next entry in the same rule
                i += 1;
            }

            i += 1;
        }

        // No rule matched — use fallback
        RoutingResult {
            outbound: self.fallback_outbound,
            mark: self.fallback_mark,
            must: self.fallback_must,
        }
    }

    /// Evaluate a single MatchSet entry against connection params.
    fn eval_match(&self, ms: &MatchSet, params: &RoutingParams) -> bool {
        match ms.r#type {
            t if t == match_type::DOMAIN_SET => {
                let idx = unsafe { ms.value.index } as usize;
                if let Some(ref domain) = params.domain {
                    let domain_lower = domain.to_lowercase();
                    if idx < self.domain_sets.len() {
                        self.domain_sets[idx].iter().any(|pattern| {
                            if let Some((key, pat)) = pattern.split_once(':') {
                                match key {
                                    "suffix" | "domain" => {
                                        domain_lower.ends_with(pat) || domain_lower == pat
                                    }
                                    "keyword" | "contains" => domain_lower.contains(pat),
                                    "full" => domain_lower == pat,
                                    _ => domain_lower.ends_with(pat) || domain_lower == pat,
                                }
                            } else {
                                domain_lower.ends_with(pattern) || domain_lower == *pattern
                            }
                        })
                    } else {
                        false
                    }
                } else {
                    // No domain info — check if the destination IP matches domain_routing_map
                    // which would have been populated by DNS response processing.
                    // Since we're in userspace, we can't check the eBPF map here.
                    false
                }
            }
            t if t == match_type::IP_SET => params.dst_ip.map_or(false, |ip| {
                let idx = unsafe { ms.value.index } as usize;
                idx < self.lpm_tries.len()
                    && self.lpm_tries[idx].iter().any(|cidr| cidr.contains(&ip))
            }),
            t if t == match_type::SOURCE_IP_SET => params.src_ip.map_or(false, |ip| {
                let idx = unsafe { ms.value.index } as usize;
                idx < self.lpm_tries.len()
                    && self.lpm_tries[idx].iter().any(|cidr| cidr.contains(&ip))
            }),
            t if t == match_type::MAC => {
                // MAC matching is not available in userspace context
                // (the eBPF program handles it from packet headers)
                false
            }
            t if t == match_type::PORT => {
                let port_range = unsafe { ms.value.port_range };
                params.dst_port.map_or(false, |p| {
                    p >= port_range.port_start && p <= port_range.port_end
                })
            }
            t if t == match_type::SOURCE_PORT => {
                let port_range = unsafe { ms.value.port_range };
                params.src_port.map_or(false, |p| {
                    p >= port_range.port_start && p <= port_range.port_end
                })
            }
            t if t == match_type::L4_PROTO => {
                let proto = unsafe { ms.value.l4proto_type };
                params.l4proto.map_or(false, |p| (p & proto) != 0)
            }
            t if t == match_type::IP_VERSION => {
                let version = unsafe { ms.value.ip_version };
                params
                    .dst_ip
                    .or(params.src_ip)
                    .map_or(false, |ip| match ip {
                        std::net::IpAddr::V4(_) => (version & 0x01) != 0,
                        std::net::IpAddr::V6(_) => (version & 0x02) != 0,
                    })
            }
            t if t == match_type::PROCESS_NAME => {
                let pname = unsafe { ms.value.pname };
                let pname_str = std::str::from_utf8(&pname)
                    .unwrap_or("")
                    .trim_end_matches('\0');
                params
                    .process_name
                    .as_deref()
                    .map_or(false, |pn| pn == pname_str)
            }
            t if t == match_type::DSCP => {
                let dscp = unsafe { ms.value.dscp };
                params.dscp.map_or(false, |d| d == dscp)
            }
            t if t == match_type::FALLBACK => true,
            _ => false,
        }
    }
}

/// Build MatchSet entries for a single function invocation, assigning correct LPM/domain indices.
fn build_match_set_for_function(
    func: &Function,
    #[allow(unused)] key: &str,
    #[allow(unused)] values: &[String],
    outbound_id: u8,
    ov_outbound: &Outbound,
    lpm_tries: &mut Vec<Vec<ipnet::IpNet>>,
    lpm_dedup: &mut HashMap<u64, usize>,
    #[allow(unused)] domain_sets: &[Vec<String>],
    rule_domain_idx: &mut usize,
) -> Result<Vec<MatchSet>> {
    let mut result = Vec::new();

    match func.name.as_str() {
        "dip" | "ip" => {
            if let Ok(cidrs) = parse_cidr_values(values) {
                let lpm_index = find_or_create_lpm_trie(&cidrs, lpm_tries, lpm_dedup);
                let mut ms = MatchSet::zeroed();
                ms.r#type = match_type::IP_SET;
                ms.value.index = lpm_index as u32;
                ms.not = if func.not { 1 } else { 0 };
                ms.outbound = outbound_id;
                ms.must = if ov_outbound.must { 1 } else { 0 };
                ms.mark = ov_outbound.mark;
                result.push(ms);
            }
        }
        "sip" | "source_ip" => {
            if let Ok(cidrs) = parse_cidr_values(values) {
                let lpm_index = find_or_create_lpm_trie(&cidrs, lpm_tries, lpm_dedup);
                let mut ms = MatchSet::zeroed();
                ms.r#type = match_type::SOURCE_IP_SET;
                ms.value.index = lpm_index as u32;
                ms.not = if func.not { 1 } else { 0 };
                ms.outbound = outbound_id;
                ms.must = if ov_outbound.must { 1 } else { 0 };
                ms.mark = ov_outbound.mark;
                result.push(ms);
            }
        }
        "mac" => {
            // For MAC, use raw params directly (key:value splitting on colons corrupts MAC addresses).
            let mut mac_addrs: Vec<ipnet::IpNet> = Vec::new();
            for val in &func.raw_params {
                if let Ok(mac) = parse_mac_address(val) {
                    let mut addr16 = [0u8; 16];
                    addr16[10..16].copy_from_slice(&mac);
                    if let Ok(ipnet) = ipnet::IpNet::new(
                        std::net::IpAddr::V6(std::net::Ipv6Addr::from(addr16)),
                        128,
                    ) {
                        mac_addrs.push(ipnet);
                    }
                }
            }
            if func.not {
                let mut zero = [0u8; 16];
                zero[10..16].copy_from_slice(&[0u8; 6]);
                if let Ok(ipnet) =
                    ipnet::IpNet::new(std::net::IpAddr::V6(std::net::Ipv6Addr::from(zero)), 128)
                {
                    mac_addrs.push(ipnet);
                }
            }
            if !mac_addrs.is_empty() {
                let lpm_index = find_or_create_lpm_trie(&mac_addrs, lpm_tries, lpm_dedup);
                let mut ms = MatchSet::zeroed();
                ms.r#type = match_type::MAC;
                ms.value.index = lpm_index as u32;
                ms.not = if func.not { 1 } else { 0 };
                ms.outbound = outbound_id;
                ms.must = if ov_outbound.must { 1 } else { 0 };
                ms.mark = ov_outbound.mark;
                result.push(ms);
            }
        }
        "dport" | "port" => {
            for val in values {
                if let Some((start_str, end_str)) = val.split_once('-') {
                    let start: u16 = start_str.trim().parse()?;
                    let end: u16 = end_str.trim().parse()?;
                    let mut ms = MatchSet::zeroed();
                    ms.r#type = match_type::PORT;
                    ms.value = MatchSetValue {
                        port_range: PortRange {
                            port_start: start,
                            port_end: end,
                        },
                    };
                    ms.not = if func.not { 1 } else { 0 };
                    ms.outbound = outbound_id;
                    ms.must = if ov_outbound.must { 1 } else { 0 };
                    ms.mark = ov_outbound.mark;
                    result.push(ms);
                } else {
                    let port: u16 = val.parse()?;
                    let mut ms = MatchSet::zeroed();
                    ms.r#type = match_type::PORT;
                    ms.value = MatchSetValue {
                        port_range: PortRange {
                            port_start: port,
                            port_end: port,
                        },
                    };
                    ms.not = if func.not { 1 } else { 0 };
                    ms.outbound = outbound_id;
                    ms.must = if ov_outbound.must { 1 } else { 0 };
                    ms.mark = ov_outbound.mark;
                    result.push(ms);
                }
            }
        }
        "sport" | "source_port" => {
            for val in values {
                if let Some((start_str, end_str)) = val.split_once('-') {
                    let start: u16 = start_str.trim().parse()?;
                    let end: u16 = end_str.trim().parse()?;
                    let mut ms = MatchSet::zeroed();
                    ms.r#type = match_type::SOURCE_PORT;
                    ms.value = MatchSetValue {
                        port_range: PortRange {
                            port_start: start,
                            port_end: end,
                        },
                    };
                    ms.not = if func.not { 1 } else { 0 };
                    ms.outbound = outbound_id;
                    ms.must = if ov_outbound.must { 1 } else { 0 };
                    ms.mark = ov_outbound.mark;
                    result.push(ms);
                } else {
                    let port: u16 = val.parse()?;
                    let mut ms = MatchSet::zeroed();
                    ms.r#type = match_type::SOURCE_PORT;
                    ms.value = MatchSetValue {
                        port_range: PortRange {
                            port_start: port,
                            port_end: port,
                        },
                    };
                    ms.not = if func.not { 1 } else { 0 };
                    ms.outbound = outbound_id;
                    ms.must = if ov_outbound.must { 1 } else { 0 };
                    ms.mark = ov_outbound.mark;
                    result.push(ms);
                }
            }
        }
        "l4proto" => {
            let mut proto = 0u8;
            for val in values {
                match val.to_lowercase().as_str() {
                    "tcp" => proto |= 0x01,
                    "udp" => proto |= 0x02,
                    _ => {}
                }
            }
            let mut ms = MatchSet::zeroed();
            ms.r#type = match_type::L4_PROTO;
            ms.value.l4proto_type = proto;
            ms.not = if func.not { 1 } else { 0 };
            ms.outbound = outbound_id;
            ms.must = if ov_outbound.must { 1 } else { 0 };
            ms.mark = ov_outbound.mark;
            result.push(ms);
        }
        "ipversion" => {
            let mut version = 0u8;
            for val in values {
                match val.trim() {
                    "4" => version |= 0x01,
                    "6" => version |= 0x02,
                    _ => {}
                }
            }
            let mut ms = MatchSet::zeroed();
            ms.r#type = match_type::IP_VERSION;
            ms.value.ip_version = version;
            ms.not = if func.not { 1 } else { 0 };
            ms.outbound = outbound_id;
            ms.must = if ov_outbound.must { 1 } else { 0 };
            ms.mark = ov_outbound.mark;
            result.push(ms);
        }
        "domain" => {
            let idx = *rule_domain_idx;
            *rule_domain_idx += 1;
            let mut ms = MatchSet::zeroed();
            ms.r#type = match_type::DOMAIN_SET;
            ms.value.index = idx as u32;
            ms.not = if func.not { 1 } else { 0 };
            ms.outbound = outbound_id;
            ms.must = if ov_outbound.must { 1 } else { 0 };
            ms.mark = ov_outbound.mark;
            result.push(ms);
        }
        "process_name" | "pname" => {
            for val in values {
                let mut ms = MatchSet::zeroed();
                ms.r#type = match_type::PROCESS_NAME;
                let mut buf = [0u8; 16];
                let len = val.len().min(16);
                buf[..len].copy_from_slice(&val.as_bytes()[..len]);
                ms.value.pname = buf;
                ms.not = if func.not { 1 } else { 0 };
                ms.outbound = outbound_id;
                ms.must = if ov_outbound.must { 1 } else { 0 };
                ms.mark = ov_outbound.mark;
                result.push(ms);
            }
        }
        "dscp" => {
            for val in values {
                let dscp: u8 = val.parse()?;
                let mut ms = MatchSet::zeroed();
                ms.r#type = match_type::DSCP;
                ms.value.dscp = dscp;
                ms.not = if func.not { 1 } else { 0 };
                ms.outbound = outbound_id;
                ms.must = if ov_outbound.must { 1 } else { 0 };
                ms.mark = ov_outbound.mark;
                result.push(ms);
            }
        }
        "qtype" => {
            let mut ms = MatchSet::zeroed();
            ms.r#type = match_type::QTYPE;
            ms.not = if func.not { 1 } else { 0 };
            ms.outbound = outbound_id;
            ms.must = if ov_outbound.must { 1 } else { 0 };
            ms.mark = ov_outbound.mark;
            result.push(ms);
        }
        "upstream" => {
            for val in values {
                let mut ms = MatchSet::zeroed();
                ms.r#type = match_type::UPSTREAM;
                let mut buf = [0u8; 16];
                let len = val.len().min(16);
                buf[..len].copy_from_slice(&val.as_bytes()[..len]);
                ms.value.pname = buf;
                ms.not = if func.not { 1 } else { 0 };
                ms.outbound = outbound_id;
                ms.must = if ov_outbound.must { 1 } else { 0 };
                ms.mark = ov_outbound.mark;
                result.push(ms);
            }
        }
        _ => {
            return Err(anyhow!("unknown function type: {}", func.name));
        }
    }

    Ok(result)
}

/// 用户空间路由回退选择。
///
/// 当 eBPF 路由无法决策时（outbound == [`outbound::CONTROL_PLANE_ROUTING`]），
/// 由用户空间根据 [`RoutingParams`] 做出路由选择。
///
/// 这对应原始 dae Go 中 `control_plane.go` 的 `ChooseDialTarget()` 函数。
/// eBPF 程序 `tproxy.c` 中定义了 `OUTBOUND_CONTROL_PLANE_ROUTING` 常量（0xFD），
/// 当 eBPF 中的路由规则无法匹配时（例如域名尚未解析），流量回退到用户空间进行决策。
///
/// # 参数
///
/// * `routing` — 编译好的 [`RoutingMatcher`]，包含 MatchSet 规则和 LPM/domain 数据
/// * `ctx` — 连接的 [`RoutingParams`]，包含源/目标 IP、端口、协议、域名等信息
///
/// # 返回值
///
/// 返回 [`RoutingResult`]，包含最终的 outbound 选择、mark 值和 must 标志。
pub fn choose_dial_target(routing: &RoutingMatcher, ctx: &RoutingParams) -> RoutingResult {
    routing.match_routing(ctx)
}

/// Build outbound name → ID mapping.
///
/// Mapping rules:
/// - "direct" → OUTBOUND_DIRECT (0x0)
/// - "block" → OUTBOUND_BLOCK (0x1)
/// - "must" / "must_direct" → OUTBOUND_MUST_RULES (0xFC)
/// - "control_plane_routing" → OUTBOUND_CONTROL_PLANE_ROUTING (0xFD)
/// - proxy nodes/groups → their assigned IDs
fn build_outbound_id_map(outbounds: &config::OutboundsConfig) -> HashMap<String, u8> {
    let mut map = HashMap::new();
    map.insert("direct".to_string(), outbound::DIRECT);
    map.insert("block".to_string(), outbound::BLOCK);
    map.insert("must".to_string(), outbound::MUST_RULES);
    map.insert("must_direct".to_string(), outbound::MUST_RULES);
    map.insert(
        "control_plane_routing".to_string(),
        outbound::CONTROL_PLANE_ROUTING,
    );

    // Map proxy nodes to CONTROL_PLANE_ROUTING
    for node in &outbounds.nodes {
        map.insert(node.name.clone(), outbound::CONTROL_PLANE_ROUTING);
    }

    // Map proxy groups to CONTROL_PLANE_ROUTING
    for group in &outbounds.groups {
        map.insert(group.name.clone(), outbound::CONTROL_PLANE_ROUTING);
    }

    map
}

// ============================================================================
// eBPF Map Building Helpers
// ============================================================================

/// Convert match sets to byte vectors for writing to routing_map.
pub fn match_sets_to_bytes(match_sets: &[MatchSet]) -> Vec<Vec<u8>> {
    match_sets
        .iter()
        .map(|ms| bytemuck::bytes_of(ms).to_vec())
        .collect()
}

/// Convert CIDR prefixes to eBPF LPM key-value pairs.
pub fn cidrs_to_lpm_entries(cidrs: &[ipnet::IpNet]) -> Vec<(LpmKey, u32)> {
    cidrs
        .iter()
        .map(|cidr| {
            let (addr, prefix_len) = match cidr {
                ipnet::IpNet::V4(v4) => {
                    let mut addr = [0u8; 16];
                    addr[10] = 0xff;
                    addr[11] = 0xff;
                    addr[12..16].copy_from_slice(&v4.addr().octets());
                    (addr, v4.prefix_len() as u32 + 96)
                }
                ipnet::IpNet::V6(v6) => {
                    let mut addr = [0u8; 16];
                    addr.copy_from_slice(&v6.addr().octets());
                    (addr, v6.prefix_len() as u32)
                }
            };

            let key = LpmKey {
                prefixlen: prefix_len,
                data: addr,
            };
            (key, 1u32)
        })
        .collect()
}

/// Convert CIDR prefixes to CidrEntry for the lpm_array_map.
pub fn cidrs_to_cidr_entries(cidrs: &[ipnet::IpNet]) -> Vec<(u32, CidrEntry)> {
    cidrs
        .iter()
        .enumerate()
        .map(|(i, cidr)| {
            let entry = match cidr {
                ipnet::IpNet::V4(v4) => {
                    let mut ip = [0u8; 16];
                    ip[10] = 0xff;
                    ip[11] = 0xff;
                    ip[12..16].copy_from_slice(&v4.addr().octets());
                    CidrEntry {
                        ip,
                        prefix_len: v4.prefix_len() + 96,
                        _pad: [0u8; 7],
                    }
                }
                ipnet::IpNet::V6(v6) => {
                    let mut ip = [0u8; 16];
                    ip.copy_from_slice(&v6.addr().octets());
                    CidrEntry {
                        ip,
                        prefix_len: v6.prefix_len(),
                        _pad: [0u8; 7],
                    }
                }
            };
            (i as u32, entry)
        })
        .collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── IR Parsing Tests ──

    #[test]
    fn test_parse_function() {
        let f: Function = "dport(80,443)".parse().unwrap();
        assert_eq!(f.name, "dport");
        assert!(!f.not);
        assert_eq!(f.raw_params.len(), 2);
        assert_eq!(f.raw_params[0], "80");
        assert_eq!(f.raw_params[1], "443");

        let f: Function = "!domain(suffix:google.com)".parse().unwrap();
        assert_eq!(f.name, "domain");
        assert!(f.not);
        assert_eq!(f.raw_params.len(), 1);
        assert_eq!(f.raw_params[0], "suffix:google.com");
    }

    #[test]
    fn test_parse_outbound() {
        let o = Outbound::parse_action("direct").unwrap();
        assert_eq!(o.name, "direct");

        let o = Outbound::parse_action("proxy(my_group)").unwrap();
        assert_eq!(o.name, "my_group");

        let o = Outbound::parse_action("proxy(my_group, mark=0x100, must)").unwrap();
        assert_eq!(o.name, "my_group");
        assert_eq!(o.mark, 0x100);
        assert!(o.must);
    }

    #[test]
    fn test_split_and() {
        let parts = split_and_respecting_parens("dport(80) && domain(suffix:google.com)");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "dport(80)");
        assert_eq!(parts[1], "domain(suffix:google.com)");
    }

    #[test]
    fn test_normalized_program() {
        let mut routing = config::RoutingConfig::default();
        routing.rules.push(config::RouteRule {
            r#match: "dport(80,443) && l4proto(tcp)".to_string(),
            action: "proxy".to_string(),
        });
        routing.rules.push(config::RouteRule {
            r#match: "domain(suffix:baidu.com)".to_string(),
            action: "direct".to_string(),
        });

        let program = NormalizedProgram::from_config(&routing).unwrap();
        assert_eq!(program.rules.len(), 2);

        // Rule 1: dport(80,443) && l4proto(tcp)
        assert_eq!(program.rules[0].and_functions.len(), 2);
        assert_eq!(program.rules[0].and_functions[0].name, "dport");
        assert_eq!(program.rules[0].and_functions[1].name, "l4proto");
        assert_eq!(program.rules[0].outbound.name, "proxy");

        // Rule 2: domain(suffix:baidu.com)
        assert_eq!(program.rules[1].and_functions.len(), 1);
        assert_eq!(program.rules[1].and_functions[0].name, "domain");
        assert_eq!(program.rules[1].outbound.name, "direct");
    }

    // ── Compile Rules Tests ──

    #[test]
    fn test_compile_simple_rule() {
        let mut routing = config::RoutingConfig::default();
        routing.rules.push(config::RouteRule {
            r#match: "dport(80)".to_string(),
            action: "proxy(proxy_primary)".to_string(),
        });

        let mut outbounds = config::OutboundsConfig::default();
        outbounds.groups.push(config::OutboundGroupConfig {
            name: "proxy_primary".to_string(),
            group_type: config::GroupType::Select,
            policy: None,
            selected: None,
            selectors: vec![],
        });

        let compiled = compile_rules(&routing, &outbounds, &[]).unwrap();

        // Should have 1 match set + 1 fallback
        assert_eq!(compiled.match_sets.len(), 2);
        assert_eq!(compiled.match_sets[0].r#type, match_type::PORT);
        assert_eq!(compiled.match_sets[1].r#type, match_type::FALLBACK);
    }

    #[test]
    fn test_compile_and_rule() {
        let mut routing = config::RoutingConfig::default();
        routing.rules.push(config::RouteRule {
            r#match: "dport(443) && l4proto(tcp)".to_string(),
            action: "proxy(proxy_primary)".to_string(),
        });

        let mut outbounds = config::OutboundsConfig::default();
        outbounds.groups.push(config::OutboundGroupConfig {
            name: "proxy_primary".to_string(),
            group_type: config::GroupType::Select,
            policy: None,
            selected: None,
            selectors: vec![],
        });

        let compiled = compile_rules(&routing, &outbounds, &[]).unwrap();

        // Should have: PORT(LOGICAL_AND) + L4PROTO(proxy_id) + FALLBACK
        // The LOGICAL_AND separates the dport and l4proto subrules
        assert_eq!(compiled.match_sets.len(), 3);
        assert_eq!(compiled.match_sets[0].r#type, match_type::PORT);
        assert_eq!(compiled.match_sets[0].outbound, outbound::LOGICAL_AND);
        assert_eq!(compiled.match_sets[1].r#type, match_type::L4_PROTO);
        assert_eq!(
            compiled.match_sets[1].outbound,
            outbound::CONTROL_PLANE_ROUTING
        );
        assert_eq!(compiled.match_sets[2].r#type, match_type::FALLBACK);
    }

    #[test]
    fn test_compile_domain_rule() {
        let mut routing = config::RoutingConfig::default();
        routing.rules.push(config::RouteRule {
            r#match: "domain(suffix:baidu.com)".to_string(),
            action: "proxy(proxy_primary)".to_string(),
        });

        let mut outbounds = config::OutboundsConfig::default();
        outbounds.groups.push(config::OutboundGroupConfig {
            name: "proxy_primary".to_string(),
            group_type: config::GroupType::Select,
            policy: None,
            selected: None,
            selectors: vec![],
        });

        let compiled = compile_rules(&routing, &outbounds, &[]).unwrap();

        assert_eq!(compiled.match_sets.len(), 2);
        assert_eq!(compiled.match_sets[0].r#type, match_type::DOMAIN_SET);
        assert_eq!(compiled.domain_sets.len(), 1);
        assert_eq!(compiled.domain_sets[0], vec!["baidu.com"]);
    }

    #[test]
    fn test_compile_direct_and_block() {
        let mut routing = config::RoutingConfig::default();
        routing.rules.push(config::RouteRule {
            r#match: "dport(22)".to_string(),
            action: "direct".to_string(),
        });
        routing.rules.push(config::RouteRule {
            r#match: "dport(25)".to_string(),
            action: "block".to_string(),
        });

        let outbounds = config::OutboundsConfig::default();
        let compiled = compile_rules(&routing, &outbounds, &[]).unwrap();

        // dport(22) -> direct, dport(25) -> block, + fallback
        assert_eq!(compiled.match_sets[0].r#type, match_type::PORT);
        assert_eq!(compiled.match_sets[0].outbound, outbound::DIRECT);
        assert_eq!(compiled.match_sets[1].r#type, match_type::PORT);
        assert_eq!(compiled.match_sets[1].outbound, outbound::BLOCK);
        assert_eq!(compiled.match_sets[2].r#type, match_type::FALLBACK);
    }

    #[test]
    fn test_cidrs_to_lpm_entries() {
        let cidrs: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let entries = cidrs_to_lpm_entries(&cidrs);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0.prefixlen, 96 + 8);
    }

    #[test]
    fn test_parse_function_with_not() {
        let f: Function = "!dport(22)".parse().unwrap();
        assert_eq!(f.name, "dport");
        assert!(f.not);
        assert_eq!(f.raw_params[0], "22");

        let f: Function = "!domain(suffix:google.com)".parse().unwrap();
        assert!(f.not);
    }

    #[test]
    fn test_parse_mac() {
        let mac = parse_mac_address("00:11:22:33:44:55").unwrap();
        assert_eq!(mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn test_compile_with_not() {
        let mut routing = config::RoutingConfig::default();
        routing.rules.push(config::RouteRule {
            r#match: "!dport(22)".to_string(),
            action: "proxy(proxy_primary)".to_string(),
        });

        let mut outbounds = config::OutboundsConfig::default();
        outbounds.groups.push(config::OutboundGroupConfig {
            name: "proxy_primary".to_string(),
            group_type: config::GroupType::Select,
            policy: None,
            selected: None,
            selectors: vec![],
        });

        let compiled = compile_rules(&routing, &outbounds, &[]).unwrap();
        assert_eq!(compiled.match_sets[0].not, 1);
    }

    #[test]
    fn test_compile_all_match_types() {
        let mut routing = config::RoutingConfig::default();
        routing.rules.push(config::RouteRule {
            r#match: "dip(10.0.0.0/8)".to_string(),
            action: "direct".to_string(),
        });
        routing.rules.push(config::RouteRule {
            r#match: "sip(192.168.0.0/16)".to_string(),
            action: "block".to_string(),
        });
        routing.rules.push(config::RouteRule {
            r#match: "ipversion(4)".to_string(),
            action: "proxy(proxy_primary)".to_string(),
        });
        routing.rules.push(config::RouteRule {
            r#match: "dscp(10)".to_string(),
            action: "block".to_string(),
        });
        routing.rules.push(config::RouteRule {
            r#match: "mac(00:11:22:33:44:55)".to_string(),
            action: "direct".to_string(),
        });

        let mut outbounds = config::OutboundsConfig::default();
        outbounds.groups.push(config::OutboundGroupConfig {
            name: "proxy_primary".to_string(),
            group_type: config::GroupType::Select,
            policy: None,
            selected: None,
            selectors: vec![],
        });

        let compiled = compile_rules(&routing, &outbounds, &[]).unwrap();

        // Should have: DIP + SIP + IPVERSION + DSCP + MAC + FALLBACK
        assert_eq!(compiled.match_sets.len(), 6);
        assert_eq!(compiled.match_sets[0].r#type, match_type::IP_SET);
        assert_eq!(compiled.match_sets[1].r#type, match_type::SOURCE_IP_SET);
        assert_eq!(compiled.match_sets[2].r#type, match_type::IP_VERSION);
        assert_eq!(compiled.match_sets[3].r#type, match_type::DSCP);
        assert_eq!(compiled.match_sets[4].r#type, match_type::MAC);
        assert_eq!(compiled.match_sets[5].r#type, match_type::FALLBACK);

        // Verify LPM tries
        // dip(10.0.0.0/8) + sip(192.168.0.0/16) + mac(00:11:22:33:44:55) = 3 tries
        assert_eq!(compiled.lpm_tries.len(), 3);
    }

    #[test]
    fn test_fallback_mark_and_must() {
        // The compile_ruses function uses the program's fallback which now
        // preserves mark and must
        let routing = config::RoutingConfig {
            rules: vec![],
            fallback: "proxy(proxy_primary)".to_string(),
        };

        let mut outbounds = config::OutboundsConfig::default();
        outbounds.groups.push(config::OutboundGroupConfig {
            name: "proxy_primary".to_string(),
            group_type: config::GroupType::Select,
            policy: None,
            selected: None,
            selectors: vec![],
        });

        let compiled = compile_rules(&routing, &outbounds, &[]).unwrap();
        assert_eq!(compiled.match_sets.len(), 1); // just fallback
        assert_eq!(compiled.match_sets[0].r#type, match_type::FALLBACK);
        assert_eq!(
            compiled.match_sets[0].outbound,
            outbound::CONTROL_PLANE_ROUTING
        );
    }

    #[test]
    fn test_raw_match_fallback() {
        // Test that a rule with empty/fallback match expression compiles
        let mut routing = config::RoutingConfig::default();
        routing.rules.push(config::RouteRule {
            r#match: "fallback".to_string(),
            action: "direct".to_string(),
        });

        let outbounds = config::OutboundsConfig::default();
        let compiled = compile_rules(&routing, &outbounds, &[]).unwrap();

        // The "empty" rule creates a FALLBACK match set, plus the program fallback
        // So we should have 2 fallbacks
        assert_eq!(compiled.match_sets.len(), 2);
        assert_eq!(compiled.match_sets[0].r#type, match_type::FALLBACK);
    }

    #[test]
    fn test_routing_matcher_dport() {
        let mut routing = config::RoutingConfig::default();
        routing.rules.push(config::RouteRule {
            r#match: "dport(80,443)".to_string(),
            action: "proxy(proxy_primary)".to_string(),
        });

        let mut outbounds = config::OutboundsConfig::default();
        outbounds.groups.push(config::OutboundGroupConfig {
            name: "proxy_primary".to_string(),
            group_type: config::GroupType::Select,
            policy: None,
            selected: None,
            selectors: vec![],
        });

        let compiled = compile_rules(&routing, &outbounds, &[]).unwrap();
        let matcher = RoutingMatcher::from_compiled(&compiled);

        // Should match dport 80
        let result = matcher.match_routing(&RoutingParams {
            dst_port: Some(80),
            ..Default::default()
        });
        assert_eq!(result.outbound, outbound::CONTROL_PLANE_ROUTING);

        // Should NOT match dport 22
        let result = matcher.match_routing(&RoutingParams {
            dst_port: Some(22),
            ..Default::default()
        });
        assert_eq!(result.outbound, compiled.fallback_outbound);
    }

    #[test]
    fn test_routing_matcher_domain() {
        let mut routing = config::RoutingConfig::default();
        routing.rules.push(config::RouteRule {
            r#match: "domain(suffix:baidu.com)".to_string(),
            action: "direct".to_string(),
        });

        let outbounds = config::OutboundsConfig::default();
        let compiled = compile_rules(&routing, &outbounds, &[]).unwrap();
        let matcher = RoutingMatcher::from_compiled(&compiled);

        // Should match www.baidu.com
        let result = matcher.match_routing(&RoutingParams {
            domain: Some("www.baidu.com".to_string()),
            ..Default::default()
        });
        assert_eq!(result.outbound, outbound::DIRECT);

        // Should NOT match www.google.com
        let result = matcher.match_routing(&RoutingParams {
            domain: Some("www.google.com".to_string()),
            ..Default::default()
        });
        assert_eq!(result.outbound, compiled.fallback_outbound);
    }

    #[test]
    fn test_routing_matcher_and_rule() {
        let mut routing = config::RoutingConfig::default();
        routing.rules.push(config::RouteRule {
            r#match: "dport(443) && l4proto(tcp)".to_string(),
            action: "proxy(proxy_primary)".to_string(),
        });

        let mut outbounds = config::OutboundsConfig::default();
        outbounds.groups.push(config::OutboundGroupConfig {
            name: "proxy_primary".to_string(),
            group_type: config::GroupType::Select,
            policy: None,
            selected: None,
            selectors: vec![],
        });

        let compiled = compile_rules(&routing, &outbounds, &[]).unwrap();
        let matcher = RoutingMatcher::from_compiled(&compiled);

        // TCP port 443 should match
        let result = matcher.match_routing(&RoutingParams {
            dst_port: Some(443),
            l4proto: Some(0x01), // TCP
            ..Default::default()
        });
        assert_eq!(result.outbound, outbound::CONTROL_PLANE_ROUTING);

        // UDP port 443 should NOT match
        let result = matcher.match_routing(&RoutingParams {
            dst_port: Some(443),
            l4proto: Some(0x02), // UDP
            ..Default::default()
        });
        assert_eq!(result.outbound, compiled.fallback_outbound);

        // TCP port 80 should NOT match
        let result = matcher.match_routing(&RoutingParams {
            dst_port: Some(80),
            l4proto: Some(0x01),
            ..Default::default()
        });
        assert_eq!(result.outbound, compiled.fallback_outbound);
    }

    #[test]
    fn test_routing_matcher_ip_and_not() {
        let mut routing = config::RoutingConfig::default();
        routing.rules.push(config::RouteRule {
            r#match: "dip(10.0.0.0/8)".to_string(),
            action: "direct".to_string(),
        });
        routing.rules.push(config::RouteRule {
            r#match: "!dport(22)".to_string(),
            action: "proxy(proxy_primary)".to_string(),
        });

        let mut outbounds = config::OutboundsConfig::default();
        outbounds.groups.push(config::OutboundGroupConfig {
            name: "proxy_primary".to_string(),
            group_type: config::GroupType::Select,
            policy: None,
            selected: None,
            selectors: vec![],
        });

        let compiled = compile_rules(&routing, &outbounds, &[]).unwrap();
        let matcher = RoutingMatcher::from_compiled(&compiled);

        // 10.x.x.x should match direct
        let result = matcher.match_routing(&RoutingParams {
            dst_ip: Some("10.1.2.3".parse().unwrap()),
            ..Default::default()
        });
        assert_eq!(result.outbound, outbound::DIRECT);

        // Non-10.x.x.x, not port 22 should match proxy
        let result = matcher.match_routing(&RoutingParams {
            dst_ip: Some("8.8.8.8".parse().unwrap()),
            dst_port: Some(443),
            ..Default::default()
        });
        assert_eq!(result.outbound, outbound::CONTROL_PLANE_ROUTING);

        // Port 22 should not match the !dport rule, fall through to fallback
        let result = matcher.match_routing(&RoutingParams {
            dst_ip: Some("8.8.8.8".parse().unwrap()),
            dst_port: Some(22),
            ..Default::default()
        });
        assert_eq!(result.outbound, compiled.fallback_outbound);
    }
}
