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
use crate::config::ConfigError;
use crate::net::ebpf::{match_type, outbound};
use crate::net::ebpf::{CidrEntry, LpmKey, MatchSet, MatchSetValue, PortRange, QtypeList};
use crate::ruleset::cache::RuleSetCache;
use crate::ruleset::compiled::{CompiledDomainSet, CompiledIpSet};
use crate::ruleset::refparse::{domain_pattern_to_string, parse_ref, RuleSetRef};
use crate::ruleset::types::{DomainPattern, DomainPatternType};

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

impl Default for FunctionLowering {
    fn default() -> Self {
        Self::new()
    }
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

                    let override_outbound = compute_override_outbound(
                        is_last_in_function,
                        is_last_function,
                        &rule.outbound,
                    );

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
                    if is_last_in_function && ms_list.len() > 1 {
                        // Multiple match sets from the final group of this function
                        // are OR alternatives (e.g. `dport(80,443)`): every entry
                        // except the last must keep the LOGICAL_OR marker so GOOD
                        // state carries across them (mirrors eBPF route_finalize_match).
                        let last = ms_list.len() - 1;
                        all_sets.extend(
                            ms_list
                                .into_iter()
                                .enumerate()
                                .map(|(idx, mut ms)| {
                                    if idx != last {
                                        ms.outbound = outbound::LOGICAL_OR;
                                    }
                                    ms
                                }),
                        );
                    } else {
                        all_sets.extend(ms_list);
                    }
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
        let values = entry.or_default();
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
fn resolve_outbound_id(outbound: &Outbound, outbound_id_map: &HashMap<String, u8>) -> Result<u8> {
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
///
/// Parser for `dip(...)` / `ip(...)` — destination IP set.
pub fn parse_dip_fn(
    f: &Function,
    _key: &str,
    values: &[String],
    override_outbound: &Outbound,
) -> Result<Vec<MatchSet>> {
    let _cidrs = parse_cidr_values(values, None)?;
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
    let _cidrs = parse_cidr_values(values, None)?;
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
///
/// 将 DNS 查询类型（数字或常见类型名，如 `A`/`AAAA`/`ANY`）解析为
/// [`QtypeList`] 存入 MatchSet，供 userspace（DNS 转发器）的
/// [`RoutingMatcher::match_routing`] 求值。
pub fn parse_qtype_fn(
    f: &Function,
    _key: &str,
    values: &[String],
    override_outbound: &Outbound,
) -> Result<Vec<MatchSet>> {
    let qtypes = qtype_values_to_list(values)?;
    let mut ms = MatchSet::zeroed();
    ms.r#type = match_type::QTYPE;
    ms.value = MatchSetValue { qtypes };
    ms.not = if f.not { 1 } else { 0 };
    ms.outbound = lookup_outbound_id_for_ms(override_outbound)?;
    ms.must = if override_outbound.must { 1 } else { 0 };
    ms.mark = override_outbound.mark;
    Ok(vec![ms])
}

/// 解析 `qtype(...)` 的参数值为 `[u16; 8]`（0 终止）。
///
/// 支持数字（如 `1`、`28`）与常见类型名（大小写不敏感，如 `A`、`AAAA`、`ANY`）。
/// 超出 8 个值或无法解析的值返回错误。
pub fn qtype_values_to_list(values: &[String]) -> Result<QtypeList> {
    const MAX_QTYPES: usize = 8;
    if values.is_empty() || values.len() > MAX_QTYPES {
        return Err(anyhow!(
            "qtype() requires 1..={MAX_QTYPES} values, got {}",
            values.len()
        ));
    }
    let mut types = [0u16; MAX_QTYPES];
    for (i, v) in values.iter().enumerate() {
        types[i] = parse_qtype_value(v)?;
    }
    Ok(QtypeList { types })
}

/// 将单个 qtype 值解析为 u16。数字按字面解析；否则按常见类型名匹配（不区分大小写）。
fn parse_qtype_value(v: &str) -> Result<u16> {
    if let Ok(num) = v.trim().parse::<u16>() {
        return Ok(num);
    }
    let upper = v.trim().to_ascii_uppercase();
    let val = match upper.as_str() {
        "A" => 1,
        "NS" => 2,
        "MD" => 3,
        "MF" => 4,
        "CNAME" => 5,
        "SOA" => 6,
        "MB" => 7,
        "MG" => 8,
        "MR" => 9,
        "NULL" => 10,
        "WKS" => 11,
        "PTR" => 12,
        "HINFO" => 13,
        "MINFO" => 14,
        "MX" => 15,
        "TXT" => 16,
        "RP" => 17,
        "AFSDB" => 18,
        "X25" => 19,
        "ISDN" => 20,
        "RT" => 21,
        "NSAP" => 22,
        "SIG" => 24,
        "KEY" => 25,
        "PX" => 26,
        "GPOS" => 27,
        "AAAA" => 28,
        "LOC" => 29,
        "SRV" => 33,
        "NAPTR" => 35,
        "KX" => 36,
        "CERT" => 37,
        "DNAME" => 39,
        "OPT" => 41,
        "APL" => 42,
        "DS" => 43,
        "SSHFP" => 44,
        "IPSECKEY" => 45,
        "RRSIG" => 46,
        "NSEC" => 47,
        "DNSKEY" => 48,
        "DHCID" => 49,
        "NSEC3" => 50,
        "NSEC3PARAM" => 51,
        "TLSA" => 52,
        "HIP" => 55,
        "CDS" => 59,
        "CDNSKEY" => 60,
        "OPENPGPKEY" => 61,
        "CSYNC" => 62,
        "ZONEMD" => 63,
        "SVCB" => 64,
        "HTTPS" => 65,
        "SPF" => 99,
        "TKEY" => 249,
        "TSIG" => 250,
        "IXFR" => 251,
        "AXFR" => 252,
        "MAILB" => 253,
        "MAILA" => 254,
        "ANY" => 255,
        "URI" => 256,
        "CAA" => 257,
        "TA" => 32768,
        "DLV" => 32769,
        _ => {
            return Err(anyhow!(
                "invalid qtype value: '{}' (expect a number or a DNS type name like A/AAAA/ANY)",
                v
            ))
        }
    };
    Ok(val)
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

/// Construct an E2103 error (compile-time data missing; default to compilation failure).
fn ruleset_data_missing(reference: &str, reason: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(ConfigError::RuleSetDataMissing {
        reference: reference.to_string(),
        reason: reason.into(),
    })
}

/// Parse CIDR values from string representations.
///
/// Recognizes `set:<name>` (ip_list); everything else is parsed as CIDR / bare IP.
fn parse_cidr_values(values: &[String], cache: Option<&RuleSetCache>) -> Result<Vec<ipnet::IpNet>> {
    let mut cidrs = Vec::new();

    for val in values {
        match parse_ref(val) {
            RuleSetRef::Set(name) => {
                let cache = cache.ok_or_else(|| {
                    ruleset_data_missing(val, "rule set memory cache not available")
                })?;
                let list = cache.get_set_ips(&name).ok_or_else(|| {
                    ruleset_data_missing(
                        val,
                        "ip_list rule set not found or rule set type mismatch",
                    )
                })?;
                cidrs.extend(list.iter().copied());
            }
            RuleSetRef::Plain(v) => {
                // Try parsing as CIDR
                if let Ok(cidr) = v.parse::<ipnet::IpNet>() {
                    cidrs.push(cidr);
                    continue;
                }

                // Try parsing as plain IP
                if let Ok(addr) = v.parse::<Ipv4Addr>() {
                    cidrs.push(ipnet::IpNet::new(addr.into(), 32).unwrap());
                    continue;
                }
                if let Ok(addr) = v.parse::<Ipv6Addr>() {
                    cidrs.push(ipnet::IpNet::new(addr.into(), 128).unwrap());
                    continue;
                }

                return Err(anyhow!("cannot parse CIDR or IP: {val}"));
            }
        }
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
    /// Outbound name → ID map (including unique per-group IDs).
    pub outbound_id_map: HashMap<String, u8>,
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
    rule_set_cache: Option<&RuleSetCache>,
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
    debug!(
        "Step 1: NormalizedProgram built ({} rules)",
        program.rules.len()
    );

    // ── Step 2: Build outbound ID map ──
    let outbound_id_map = build_outbound_id_map(outbounds);
    debug!(
        "Step 2: outbound_id_map built ({} entries)",
        outbound_id_map.len()
    );

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

    // ── Step 3: Collect domain set data (needed before building MatchSets) ──
    // LPM trie data is collected inline during MatchSet construction via
    // find_or_create_lpm_trie, avoiding a separate function-dispatch pass.
    let mut lpm_tries: Vec<Vec<ipnet::IpNet>> = Vec::new();
    let mut lpm_dedup: HashMap<u64, usize> = HashMap::new();
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

    // Collect domain set data from rules (needed before building MatchSets
    // because build_match_set_for_function references domain sets by index).
    // LPM trie data is collected inline during the second pass via
    // find_or_create_lpm_trie, so no separate pass is needed for that.
    //
    // Rule set integration (design §6.3 / §9.1):
    // - `target_domain(set:<name>)` (domain_list) → look up the cached domain patterns;
    // - Plain `domain(...)` / `target_domain(...)` parameters keep their key prefix.
    //
    // **Note**: each domain/target_domain function unconditionally pushes an entry (even if empty),
    // strictly aligned with the `rule_domain_idx` increments in build_match_set_for_function.
    for rule in &program.rules {
        for func in &rule.and_functions {
            if func.name.as_str() == "domain" || func.name.as_str() == "target_domain" {
                let mut patterns: Vec<String> = Vec::new();
                for raw in &func.raw_params {
                    match parse_ref(raw) {
                        RuleSetRef::Set(name) => {
                            let cache = rule_set_cache.ok_or_else(|| {
                                ruleset_data_missing(raw, "rule set memory cache not available")
                            })?;
                            let pats = cache.get_set_domains(&name).ok_or_else(|| {
                                ruleset_data_missing(
                                    raw,
                                    "domain_list rule set not found or rule set type mismatch",
                                )
                            })?;
                            patterns.extend(pats.iter().map(domain_pattern_to_string));
                        }
                        RuleSetRef::Plain(v) => {
                            // Plain domain pattern: keep the key prefix (suffix:/keyword:/full:/regex:/domain: or bare value)
                            patterns.push(v.to_string());
                        }
                    }
                }
                domain_sets.push(patterns);
            }
        }
    }

    // Build MatchSets: walks the program once, using shared helpers for outbound
    // chaining and fallback creation. LPM trie data is populated inline via
    // find_or_create_lpm_trie within build_match_set_for_function.
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

                let ov_outbound = compute_override_outbound(
                    is_last_in_function,
                    is_last_function,
                    &rule.outbound,
                );
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
                        rule_set_cache,
                    )?;
                    if is_last_in_function && match_sets.len() > 1 {
                        // Multiple match sets from the final group of this function
                        // are OR alternatives (e.g. `dport(80,443)`): every entry
                        // except the last must carry the LOGICAL_OR marker so GOOD
                        // state persists across them (mirrors eBPF route_finalize_match).
                        let last = match_sets.len() - 1;
                        final_match_sets.extend(
                            match_sets
                                .into_iter()
                                .enumerate()
                                .map(|(idx, mut ms)| {
                                    if idx != last {
                                        ms.outbound = outbound::LOGICAL_OR;
                                    }
                                    ms
                                }),
                        );
                    } else {
                        final_match_sets.extend(match_sets);
                    }
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

    info!(
        match_sets = final_match_sets.len(),
        lpm_tries = lpm_tries.len(),
        domain_sets = domain_sets.len(),
        fallback = %fallback_outbound,
        "Compiled routing rules",
    );

    // ── Step 6: Capacity check (design §9.3) → E2106 ──
    // MatchSet total / LPM trie count / domain set index count exceeding limits → refuse compilation.
    if final_match_sets.len() > MAX_MATCH_SET_LEN {
        return Err(anyhow::Error::new(ConfigError::RuleSetCapacityExceeded {
            detail: format!(
                "MatchSet count {} exceeds MAX_MATCH_SET_LEN {MAX_MATCH_SET_LEN}; reduce rules or merge rule set references",
                final_match_sets.len()
            ),
        }));
    }
    if lpm_tries.len() > MAX_LPM_NUM {
        return Err(anyhow::Error::new(ConfigError::RuleSetCapacityExceeded {
            detail: format!(
                "LPM trie count {} exceeds MAX_LPM_NUM {MAX_LPM_NUM}; reduce distinct IP rule sets",
                lpm_tries.len()
            ),
        }));
    }
    if domain_sets.len() > MAX_MATCH_SET_LEN {
        return Err(anyhow::Error::new(ConfigError::RuleSetCapacityExceeded {
            detail: format!(
                "domain set index {} exceeds MAX_MATCH_SET_LEN {MAX_MATCH_SET_LEN}; domain_routing_map bitmap has {MAX_MATCH_SET_LEN} bits",
                domain_sets.len()
            ),
        }));
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
        outbound_id_map,
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
    /// DNS 查询类型（1=A, 28=AAAA ...）。仅在 DNS 路由上下文（DNS 转发器）中填充，
    /// 供 `qtype(...)` 规则匹配。
    pub qtype: Option<u16>,
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
    /// Compiled LPM trie data: index -> compiled IP set (O(log N) lookups).
    compiled_lpm: Vec<CompiledIpSet>,
    /// Compiled domain set data: rule_index -> compiled domain matcher.
    compiled_domains: Vec<CompiledDomainSet>,
    /// Fallback outbound.
    fallback_outbound: u8,
    fallback_mark: u32,
    fallback_must: bool,
    /// Outbound name → ID map (including unique per-group IDs).
    outbound_id_map: HashMap<String, u8>,
}

impl RoutingMatcher {
    /// Build a matcher from compiled routing data.
    ///
    /// The raw LPM tries / domain pattern strings are pre-compiled once into
    /// [`CompiledIpSet`] / [`CompiledDomainSet`] so runtime matching is O(log N)
    /// instead of a linear scan over every CIDR / pattern on each evaluation.
    pub fn from_compiled(compiled: &CompiledRouting) -> Self {
        Self {
            match_sets: compiled.match_sets.clone(),
            compiled_lpm: compiled
                .lpm_tries
                .iter()
                .map(|nets| CompiledIpSet::compile(nets))
                .collect(),
            compiled_domains: compiled
                .domain_sets
                .iter()
                .map(|pats| CompiledDomainSet::compile(&domain_strings_to_patterns(pats)))
                .collect(),
            fallback_outbound: compiled.fallback_outbound,
            fallback_mark: compiled.fallback_mark,
            fallback_must: compiled.fallback_must != 0,
            outbound_id_map: compiled.outbound_id_map.clone(),
        }
    }

    /// Access the outbound name → ID map.
    ///
    /// Callers (e.g. [`crate::net::dns_forwarder::DnsForwarder`] initialization)
    /// use the exact IDs returned by [`Self::match_routing`] so they can reverse
    /// a routing result back to a specific proxy group.
    pub fn get_outbound_id_map(&self) -> &HashMap<String, u8> {
        &self.outbound_id_map
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
        let mut must_flag = false;

        // Mirrors the eBPF state machine (tproxy.c: route_finalize_match):
        // a rule is a run of MatchSet entries where LOGICAL_OR (0xFE) joins
        // subrule alternatives without finalizing, LOGICAL_AND (0xFF) finalizes
        // a subrule, and any other outbound is the rule tail that carries the
        // rule's real outbound. GOOD_SUBRULE / BAD_RULE accumulate across entries
        // until a rule tail decides the result; a tail with BAD_RULE clears it
        // and continues to the next rule.
        while i < len {
            let mut good_subrule = false;
            let mut bad_rule = false;

            // Walk entries belonging to one rule.
            while i < len {
                let ms = &self.match_sets[i];
                let outbound = ms.outbound;
                let match_not = ms.not != 0;

                let is_logical_or = outbound == outbound::LOGICAL_OR;
                // LOGICAL_OR / LOGICAL_AND are the only values with
                // (outbound & LOGICAL_MASK) == LOGICAL_MASK.
                let is_tail = !is_logical_or && outbound != outbound::LOGICAL_AND;

                // Evaluate this entry unless a prior subrule already settled the
                // state (mirrors route_loop_cb skipping route_eval_match).
                if !good_subrule && !bad_rule && self.eval_match(ms, params) {
                    good_subrule = true;
                }

                if !is_logical_or {
                    // This entry reaches the end of a subrule.
                    // A subrule that did not hit (good == not) fails the rule.
                    if good_subrule == match_not {
                        bad_rule = true;
                    }
                    // Reset good_subrule.
                    good_subrule = false;
                }

                if is_tail {
                    // Tail of a rule: decide whether to hit.
                    if !bad_rule {
                        if outbound == outbound::MUST_RULES {
                            must_flag = true;
                            // Continue to the next rule with the must flag set.
                            i += 1;
                            break;
                        }
                        return RoutingResult {
                            outbound,
                            mark: ms.mark,
                            must: must_flag || ms.must != 0,
                        };
                    }
                    // Rule didn't match, clear bad state and move to next rule.
                    bad_rule = false;
                }

                i += 1;
            }
        }

        // No rule matched — use fallback
        RoutingResult {
            outbound: self.fallback_outbound,
            mark: self.fallback_mark,
            must: must_flag || self.fallback_must,
        }
    }

    /// Evaluate a single MatchSet entry against connection params.
    fn eval_match(&self, ms: &MatchSet, params: &RoutingParams) -> bool {
        match ms.r#type {
            t if t == match_type::DOMAIN_SET => {
                let idx = unsafe { ms.value.index } as usize;
                if let Some(domain) = params.domain.as_deref() {
                    idx < self.compiled_domains.len()
                        && self.compiled_domains[idx].matches(domain)
                } else {
                    // No domain info — check if the destination IP matches domain_routing_map
                    // which would have been populated by DNS response processing.
                    // Since we're in userspace, we can't check the eBPF map here.
                    false
                }
            }
            t if t == match_type::IP_SET => params.dst_ip.is_some_and(|ip| {
                let idx = unsafe { ms.value.index } as usize;
                idx < self.compiled_lpm.len() && self.compiled_lpm[idx].contains(ip)
            }),
            t if t == match_type::SOURCE_IP_SET => params.src_ip.is_some_and(|ip| {
                let idx = unsafe { ms.value.index } as usize;
                idx < self.compiled_lpm.len() && self.compiled_lpm[idx].contains(ip)
            }),
            t if t == match_type::MAC => {
                // MAC matching is not available in userspace context
                // (the eBPF program handles it from packet headers)
                false
            }
            t if t == match_type::PORT => {
                let port_range = unsafe { ms.value.port_range };
                params.dst_port.is_some_and(|p| {
                    p >= port_range.port_start && p <= port_range.port_end
                })
            }
            t if t == match_type::SOURCE_PORT => {
                let port_range = unsafe { ms.value.port_range };
                params.src_port.is_some_and(|p| {
                    p >= port_range.port_start && p <= port_range.port_end
                })
            }
            t if t == match_type::L4_PROTO => {
                let proto = unsafe { ms.value.l4proto_type };
                params.l4proto.is_some_and(|p| (p & proto) != 0)
            }
            t if t == match_type::IP_VERSION => {
                let version = unsafe { ms.value.ip_version };
                params
                    .dst_ip
                    .or(params.src_ip)
                    .is_some_and(|ip| match ip {
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
                    .as_deref() == Some(pname_str)
            }
            t if t == match_type::QTYPE => params.qtype.is_some_and(|q| {
                let qtypes = unsafe { ms.value.qtypes };
                qtypes
                    .types
                    .iter()
                    .take_while(|t| **t != 0)
                    .any(|t| *t == q)
            }),
            t if t == match_type::DSCP => {
                let dscp = unsafe { ms.value.dscp };
                params.dscp == Some(dscp)
            }
            t if t == match_type::FALLBACK => true,
            _ => false,
        }
    }
}

/// Convert `domain_sets` pattern strings (with a `key:` prefix or bare) into
/// [`DomainPattern`]s so they can be compiled into a [`CompiledDomainSet`].
///
/// Prefix semantics mirror the linear-scan evaluation this compiled set replaces:
/// `suffix:` / bare → Suffix, `full:` → Full, `keyword:`/`contains:` → Keyword,
/// `regex:` → Regex, `domain:` → Domain.
fn domain_strings_to_patterns(patterns: &[String]) -> Vec<DomainPattern> {
    patterns
        .iter()
        .map(|s| {
            if let Some((key, val)) = s.split_once(':') {
                let pattern_type = match key {
                    "full" => DomainPatternType::Full,
                    "keyword" | "contains" => DomainPatternType::Keyword,
                    "regex" => DomainPatternType::Regex,
                    "domain" => DomainPatternType::Domain,
                    _ => DomainPatternType::Suffix, // "suffix:" and unknown keys
                };
                DomainPattern {
                    pattern_type,
                    value: val.to_string(),
                }
            } else {
                // Bare value uses suffix semantics (including itself)
                DomainPattern {
                    pattern_type: DomainPatternType::Suffix,
                    value: s.clone(),
                }
            }
        })
        .collect()
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
    rule_set_cache: Option<&RuleSetCache>,
) -> Result<Vec<MatchSet>> {
    let mut result = Vec::new();

    // Normalized aliases (design §6.2): `dip`/`ip` → `target_ip`; `sip` → `source_ip`;
    // `domain` (including the `geosite:` prefix) → `target_domain`. The function name branches are
    // handled uniformly; no separate renaming at parse time, the behavior is equivalent.
    match func.name.as_str() {
        "dip" | "ip" | "target_ip" => {
            // Use the raw parameters (func.raw_params): `group_params_by_key` would split
            // `geoip:cn` / `set:chinaip` into key/value, so `parse_cidr_values` only receives
            // `cn`/`chinaip` and cannot recognize the rule set prefix (related to defect 3).
            //
            // Defect 2 fix: parse failures (missing data E2103 / syntax errors) are no longer
            // silently dropped; errors are propagated directly.
            let cidrs = parse_cidr_values(&func.raw_params, rule_set_cache)?;
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
        "sip" | "source_ip" => {
            let cidrs = parse_cidr_values(&func.raw_params, rule_set_cache)?;
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
        "domain" | "target_domain" => {
            // Strictly aligned with the compile_rules collection phase: each domain/target_domain
            // function corresponds to exactly one domain_sets entry (its index comes from rule_domain_idx).
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
            // 注意：`qtype()` 是 DNS 上下文规则。数据面（eBPF）当前不实现 QTYPE 匹配，
            // 但 userspace DNS 转发器会用它做 DNS 查询路由。此处写入真实的类型值。
            let qtypes = qtype_values_to_list(values)?;
            let mut ms = MatchSet::zeroed();
            ms.r#type = match_type::QTYPE;
            ms.value = MatchSetValue { qtypes };
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

/// Userspace routing fallback selection.
///
/// When eBPF routing cannot make a decision (outbound == [`outbound::CONTROL_PLANE_ROUTING`]),
/// the userspace side makes the routing choice based on [`RoutingParams`].
///
/// This corresponds to the `ChooseDialTarget()` function in `control_plane.go` of the original
/// dae Go implementation. The eBPF program `tproxy.c` defines the
/// `OUTBOUND_CONTROL_PLANE_ROUTING` constant (0xFD); when the routing rules in eBPF cannot
/// match (e.g. the domain name has not yet been resolved), traffic falls back to userspace
/// for the decision.
///
/// # Parameters
///
/// * `routing` — the compiled [`RoutingMatcher`], containing MatchSet rules and LPM/domain data
/// * `ctx` — the connection's [`RoutingParams`], including source/destination IP, port, protocol, domain name, etc.
///
/// # Returns
///
/// Returns a [`RoutingResult`] containing the final outbound selection, mark value, and must flag.
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
/// - proxy nodes → OUTBOUND_CONTROL_PLANE_ROUTING (real outbound chosen in userspace)
/// - proxy groups → a unique ID in `0x02..=0xFB` so userspace (e.g. [`crate::net::dns_forwarder::DnsForwarder`])
///   can distinguish one group from another via the routing result.
///
/// The unique group IDs avoid all reserved values: DIRECT (0x0), BLOCK (0x1),
/// MUST_RULES (0xFC), CONTROL_PLANE_ROUTING (0xFD), LOGICAL_OR (0xFE) and
/// LOGICAL_AND (0xFF). `0x02..=0xFB` therefore offers 250 usable group IDs.
pub fn build_outbound_id_map(outbounds: &config::OutboundsConfig) -> HashMap<String, u8> {
    let mut map = HashMap::new();
    map.insert("direct".to_string(), outbound::DIRECT);
    map.insert("block".to_string(), outbound::BLOCK);
    map.insert("must".to_string(), outbound::MUST_RULES);
    map.insert("must_direct".to_string(), outbound::MUST_RULES);
    map.insert(
        "control_plane_routing".to_string(),
        outbound::CONTROL_PLANE_ROUTING,
    );

    // Proxy nodes: the real outbound depends on connectivity health / load-balancing
    // policies evaluated in userspace, so keep them on control-plane routing.
    for node in &outbounds.nodes {
        map.insert(node.name.clone(), outbound::CONTROL_PLANE_ROUTING);
    }

    // Proxy groups: assign each a unique ID (first group → 0x02, then increment).
    // If the u8 unique-ID space is exhausted we fall back to control-plane routing
    // so the group still works, just without a distinguishable ID.
    const GROUP_ID_START: u8 = 0x02;
    const GROUP_ID_END: u8 = outbound::MUST_RULES - 1; // 0xFB
    let mut next_id = GROUP_ID_START;
    for group in &outbounds.groups {
        if next_id > GROUP_ID_END {
            map.insert(group.name.clone(), outbound::CONTROL_PLANE_ROUTING);
            continue;
        }
        map.insert(group.name.clone(), next_id);
        next_id += 1;
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

        let compiled = compile_rules(&routing, &outbounds, &[], None).unwrap();

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

        let compiled = compile_rules(&routing, &outbounds, &[], None).unwrap();

        // Should have: PORT(LOGICAL_AND) + L4PROTO(proxy_id) + FALLBACK
        // The LOGICAL_AND separates the dport and l4proto subrules
        assert_eq!(compiled.match_sets.len(), 3);
        assert_eq!(compiled.match_sets[0].r#type, match_type::PORT);
        assert_eq!(compiled.match_sets[0].outbound, outbound::LOGICAL_AND);
        assert_eq!(compiled.match_sets[1].r#type, match_type::L4_PROTO);
        assert_eq!(
            compiled.match_sets[1].outbound,
            *compiled.outbound_id_map.get("proxy_primary").unwrap()
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

        let compiled = compile_rules(&routing, &outbounds, &[], None).unwrap();

        assert_eq!(compiled.match_sets.len(), 2);
        assert_eq!(compiled.match_sets[0].r#type, match_type::DOMAIN_SET);
        assert_eq!(compiled.domain_sets.len(), 1);
        // Keep the key prefix to support suffix/full/regex/domain semantics (no longer degraded to a bare suffix)
        assert_eq!(compiled.domain_sets[0], vec!["suffix:baidu.com"]);
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
        let compiled = compile_rules(&routing, &outbounds, &[], None).unwrap();

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

        let compiled = compile_rules(&routing, &outbounds, &[], None).unwrap();
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

        let compiled = compile_rules(&routing, &outbounds, &[], None).unwrap();

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

        let compiled = compile_rules(&routing, &outbounds, &[], None).unwrap();
        assert_eq!(compiled.match_sets.len(), 1); // just fallback
        assert_eq!(compiled.match_sets[0].r#type, match_type::FALLBACK);
        assert_eq!(
            compiled.match_sets[0].outbound,
            *compiled.outbound_id_map.get("proxy_primary").unwrap()
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
        let compiled = compile_rules(&routing, &outbounds, &[], None).unwrap();

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

        let compiled = compile_rules(&routing, &outbounds, &[], None).unwrap();
        let matcher = RoutingMatcher::from_compiled(&compiled);

        // Should match dport 80 → proxy_primary's unique outbound id
        let result = matcher.match_routing(&RoutingParams {
            dst_port: Some(80),
            ..Default::default()
        });
        assert_eq!(
            result.outbound,
            *matcher.get_outbound_id_map().get("proxy_primary").unwrap()
        );

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
        let compiled = compile_rules(&routing, &outbounds, &[], None).unwrap();
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
    fn test_qtype_parse() {
        // 数字与常见类型名
        assert_eq!(parse_qtype_value("A").unwrap(), 1);
        assert_eq!(parse_qtype_value("aaaa").unwrap(), 28); // 大小写不敏感
        assert_eq!(parse_qtype_value("ANY").unwrap(), 255);
        assert_eq!(parse_qtype_value("28").unwrap(), 28);
        assert_eq!(parse_qtype_value("HTTPS").unwrap(), 65);
        // 非法值 → 错误
        assert!(parse_qtype_value("NOT_A_TYPE").is_err());
        assert!(parse_qtype_value("99999").is_err()); // 超出 u16

        let list = qtype_values_to_list(&["A".into(), "AAAA".into()]).unwrap();
        assert_eq!(&list.types[..2], &[1, 28]);
        assert_eq!(list.types[2], 0); // 0 终止
        // 空列表 / 超 8 个 → 错误
        assert!(qtype_values_to_list(&[]).is_err());
        assert!(qtype_values_to_list(&["1".repeat(9).into()]).is_err());
    }

    #[test]
    fn test_routing_matcher_qtype() {
        let mut routing = config::RoutingConfig::default();
        routing.rules.push(config::RouteRule {
            r#match: "qtype(AAAA)".to_string(),
            action: "direct".to_string(),
        });

        let outbounds = config::OutboundsConfig::default();
        let compiled = compile_rules(&routing, &outbounds, &[], None).unwrap();
        let matcher = RoutingMatcher::from_compiled(&compiled);

        // AAAA (28) → 命中 DIRECT
        let result = matcher.match_routing(&RoutingParams {
            qtype: Some(28),
            ..Default::default()
        });
        assert_eq!(result.outbound, outbound::DIRECT);

        // A (1) → 不命中，走 fallback
        let result = matcher.match_routing(&RoutingParams {
            qtype: Some(1),
            ..Default::default()
        });
        assert_eq!(result.outbound, compiled.fallback_outbound);

        // 无 qtype 上下文（普通数据面连接）→ 不命中
        let result = matcher.match_routing(&RoutingParams {
            dst_port: Some(443),
            ..Default::default()
        });
        assert_eq!(result.outbound, compiled.fallback_outbound);
    }

    #[test]
    fn test_routing_matcher_qtype_negated() {
        let mut routing = config::RoutingConfig::default();
        routing.rules.push(config::RouteRule {
            r#match: "!qtype(A, AAAA)".to_string(),
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

        let compiled = compile_rules(&routing, &outbounds, &[], None).unwrap();
        let matcher = RoutingMatcher::from_compiled(&compiled);

        // TXT (16) 非 A/AAAA → 命中代理组
        let result = matcher.match_routing(&RoutingParams {
            qtype: Some(16),
            ..Default::default()
        });
        assert_eq!(
            result.outbound,
            *matcher.get_outbound_id_map().get("proxy_primary").unwrap()
        );

        // A (1) → 不命中
        let result = matcher.match_routing(&RoutingParams {
            qtype: Some(1),
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

        let compiled = compile_rules(&routing, &outbounds, &[], None).unwrap();
        let matcher = RoutingMatcher::from_compiled(&compiled);

        // TCP port 443 should match → proxy_primary's unique outbound id
        let result = matcher.match_routing(&RoutingParams {
            dst_port: Some(443),
            l4proto: Some(0x01), // TCP
            ..Default::default()
        });
        assert_eq!(
            result.outbound,
            *matcher.get_outbound_id_map().get("proxy_primary").unwrap()
        );

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
    fn test_routing_matcher_and_rule_distinct_outbound() {
        // Regression test: an AND-composed rule whose action outbound differs
        // from the fallback. Previously match_routing returned the fallback
        // (or the wrong rule) because it bailed out at the rule's tail instead
        // of finalizing the pending good_subrule. This breaks DNS routing, e.g.
        // `dport(...) && qtype(...) -> proxy_group` when fallback is direct.
        let mut routing = config::RoutingConfig::default();
        routing.rules.push(config::RouteRule {
            r#match: "dport(443) && l4proto(tcp)".to_string(),
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

        let compiled = compile_rules(&routing, &outbounds, &[], None).unwrap();
        let matcher = RoutingMatcher::from_compiled(&compiled);
        // fallback = proxy_primary (unique id), rule action = direct (0x0).
        assert_ne!(compiled.fallback_outbound, outbound::DIRECT);

        // Matching AND rule must yield the rule's action (DIRECT), not fallback.
        let result = matcher.match_routing(&RoutingParams {
            dst_port: Some(443),
            l4proto: Some(0x01), // TCP
            ..Default::default()
        });
        assert_eq!(result.outbound, outbound::DIRECT);

        // A later distinct rule must still be reachable after a non-matching AND rule.
        let result = matcher.match_routing(&RoutingParams {
            dst_port: Some(443),
            l4proto: Some(0x02), // UDP
            ..Default::default()
        });
        assert_eq!(result.outbound, compiled.fallback_outbound);

        let result = matcher.match_routing(&RoutingParams {
            dst_port: Some(80),
            l4proto: Some(0x01),
            ..Default::default()
        });
        assert_eq!(result.outbound, compiled.fallback_outbound);
    }

    #[test]
    fn test_routing_matcher_multi_value_or_in_and() {
        // Regression test: `dport(80,443) && l4proto(tcp)` — the two port values
        // are OR alternatives and must not be compiled as AND-joined subrules
        // (previously both entries got LOGICAL_AND, so the rule could never match).
        let mut routing = config::RoutingConfig::default();
        routing.rules.push(config::RouteRule {
            r#match: "dport(80,443) && l4proto(tcp)".to_string(),
            action: "direct".to_string(),
        });
        let outbounds = config::OutboundsConfig::default();
        let compiled = compile_rules(&routing, &outbounds, &[], None).unwrap();

        // PORT[80] is an OR alternative, PORT[443] ends the dport group with
        // LOGICAL_AND, and L4PROTO carries the real outbound (direct).
        assert_eq!(compiled.match_sets[0].r#type, match_type::PORT);
        assert_eq!(compiled.match_sets[0].outbound, outbound::LOGICAL_OR);
        assert_eq!(compiled.match_sets[1].r#type, match_type::PORT);
        assert_eq!(compiled.match_sets[1].outbound, outbound::LOGICAL_AND);
        assert_eq!(compiled.match_sets[2].r#type, match_type::L4_PROTO);
        assert_eq!(compiled.match_sets[2].outbound, outbound::DIRECT);
        assert_eq!(compiled.match_sets[3].r#type, match_type::FALLBACK);

        let matcher = RoutingMatcher::from_compiled(&compiled);
        for dport in [80u16, 443] {
            let result = matcher.match_routing(&RoutingParams {
                dst_port: Some(dport),
                l4proto: Some(0x01), // TCP
                ..Default::default()
            });
            assert_eq!(result.outbound, outbound::DIRECT, "dport={dport}");
        }

        // A non-listed port still falls through to fallback.
        let result = matcher.match_routing(&RoutingParams {
            dst_port: Some(22),
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

        let compiled = compile_rules(&routing, &outbounds, &[], None).unwrap();
        let matcher = RoutingMatcher::from_compiled(&compiled);

        // 10.x.x.x should match direct
        let result = matcher.match_routing(&RoutingParams {
            dst_ip: Some("10.1.2.3".parse().unwrap()),
            ..Default::default()
        });
        assert_eq!(result.outbound, outbound::DIRECT);

        // Non-10.x.x.x, not port 22 should match proxy → unique outbound id
        let result = matcher.match_routing(&RoutingParams {
            dst_ip: Some("8.8.8.8".parse().unwrap()),
            dst_port: Some(443),
            ..Default::default()
        });
        assert_eq!(
            result.outbound,
            *matcher.get_outbound_id_map().get("proxy_primary").unwrap()
        );

        // Port 22 should not match the !dport rule, fall through to fallback
        let result = matcher.match_routing(&RoutingParams {
            dst_ip: Some("8.8.8.8".parse().unwrap()),
            dst_port: Some(22),
            ..Default::default()
        });
        assert_eq!(result.outbound, compiled.fallback_outbound);
    }

    // ── Rule set integration tests (design §6.3 / §9) ──

    /// Build an in-memory cache containing ip_list/domain_list.
    fn make_rule_set_cache() -> RuleSetCache {
        use crate::ruleset::types::{DomainPattern, DomainPatternType, RuleSetData};
        use std::sync::Arc;

        let cache = RuleSetCache::new();
        cache.insert(
            "chinaip".into(),
            RuleSetData::IpList(Arc::new(vec![
                "1.0.0.0/8".parse().unwrap(),
                "192.168.0.0/16".parse().unwrap(),
            ])),
        );
        cache.insert(
            "chinadom".into(),
            RuleSetData::DomainList(Arc::new(vec![
                DomainPattern { pattern_type: DomainPatternType::Suffix, value: "baidu.com".into() },
                DomainPattern { pattern_type: DomainPatternType::Full, value: "google.cn".into() },
                DomainPattern { pattern_type: DomainPatternType::Suffix, value: "example.cn".into() },
            ])),
        );
        cache
    }

    #[test]
    fn test_compile_ruleset_set_ip() {
        let mut routing = config::RoutingConfig::default();
        routing.rules.push(config::RouteRule {
            r#match: "source_ip(set:chinaip)".to_string(),
            action: "block".to_string(),
        });
        routing.rules.push(config::RouteRule {
            r#match: "dip(10.0.0.0/8)".to_string(),
            action: "direct".to_string(),
        });
        let outbounds = config::OutboundsConfig::default();

        let cache = make_rule_set_cache();
        let compiled = compile_rules(&routing, &outbounds, &[], Some(&cache)).unwrap();

        assert_eq!(compiled.match_sets.len(), 3); // SOURCE_IP_SET + IP_SET + FALLBACK
        assert_eq!(compiled.match_sets[0].r#type, match_type::SOURCE_IP_SET);
        assert_eq!(compiled.match_sets[0].outbound, outbound::BLOCK);
        assert_eq!(compiled.match_sets[1].r#type, match_type::IP_SET);
        assert_eq!(compiled.match_sets[1].outbound, outbound::DIRECT);
        // set:chinaip (2 networks) and dip(10.0.0.0/8) (1 network) → 2 LPM tries
        assert_eq!(compiled.lpm_tries.len(), 2);

        // Userspace evaluation verification
        let matcher = RoutingMatcher::from_compiled(&compiled);
        let r = matcher.match_routing(&RoutingParams {
            src_ip: Some("192.168.1.1".parse().unwrap()),
            ..Default::default()
        });
        assert_eq!(r.outbound, outbound::BLOCK, "set:chinaip matched");

        let r = matcher.match_routing(&RoutingParams {
            dst_ip: Some("10.0.0.1".parse().unwrap()),
            ..Default::default()
        });
        assert_eq!(r.outbound, outbound::DIRECT, "dip(10.0.0.0/8) matched");

        let r = matcher.match_routing(&RoutingParams {
            dst_ip: Some("8.8.8.8".parse().unwrap()),
            ..Default::default()
        });
        assert_eq!(r.outbound, compiled.fallback_outbound);
    }

    #[test]
    fn test_compile_ruleset_domain_list() {
        let mut routing = config::RoutingConfig::default();
        routing.rules.push(config::RouteRule {
            r#match: "target_domain(set:chinadom)".to_string(),
            action: "direct".to_string(),
        });
        let outbounds = config::OutboundsConfig::default();

        let cache = make_rule_set_cache();
        let compiled = compile_rules(&routing, &outbounds, &[], Some(&cache)).unwrap();

        assert_eq!(compiled.domain_sets.len(), 1);
        assert_eq!(compiled.domain_sets[0], vec!["suffix:baidu.com", "full:google.cn", "suffix:example.cn"]);

        // Userspace evaluation verification
        let matcher = RoutingMatcher::from_compiled(&compiled);
        let r = matcher.match_routing(&RoutingParams {
            domain: Some("www.baidu.com".to_string()),
            ..Default::default()
        });
        assert_eq!(r.outbound, outbound::DIRECT, "set:chinadom matched subdomain");

        let r = matcher.match_routing(&RoutingParams {
            domain: Some("google.cn".to_string()),
            ..Default::default()
        });
        assert_eq!(r.outbound, outbound::DIRECT, "set:chinadom full matched");

        let r = matcher.match_routing(&RoutingParams {
            domain: Some("www.google.com".to_string()),
            ..Default::default()
        });
        assert_eq!(r.outbound, compiled.fallback_outbound);
    }

    #[test]
    fn test_compile_ruleset_missing_data_fails_e2103() {
        // Missing data defaults to a compilation failure (E2103)
        let mut routing = config::RoutingConfig::default();
        routing.rules.push(config::RouteRule {
            r#match: "target_ip(set:chinaip)".to_string(),
            action: "direct".to_string(),
        });
        let outbounds = config::OutboundsConfig::default();
        // No cache provided → E2103
        let err = match compile_rules(&routing, &outbounds, &[], None) {
            Ok(_) => panic!("expected E2103 error"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("E2103"), "expected E2103, got: {msg}");
    }

    #[test]
    fn test_compile_ruleset_capacity_exceeded_e2106() {
        // Build a MatchSet exceeding MAX_MATCH_SET_LEN → E2106
        let mut routing = config::RoutingConfig::default();
        for i in 0..(MAX_MATCH_SET_LEN + 10) {
            routing.rules.push(config::RouteRule {
                r#match: format!("dport({})", 1000 + (i % 60000) as u16),
                action: "direct".to_string(),
            });
        }
        let outbounds = config::OutboundsConfig::default();
        let err = match compile_rules(&routing, &outbounds, &[], None) {
            Ok(_) => panic!("expected E2106 error"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("E2106"), "expected E2106, got: {msg}");
    }
}
