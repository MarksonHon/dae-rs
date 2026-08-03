//! daefile text parser.
//!
//! Implements the line-and-indent state machine that turns daefile text into a
//! [`DaefileConfig`] structure.

use super::*;
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
        import: None,
        username: None,
        password: None,
        cipher: None,
        sni: None,
        ca_sha256: None,
        uuid: None,
        congestion_control: None,
        alpn: None,
        security: None,
        alter_id: None,
        network: None,
        ws_path: None,
        ws_headers: None,
        h2_path: None,
        h2_host: None,
        grpc_service_name: None,
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
                            import: None,
                            username: None,
                            password: None,
                            cipher: None,
                            sni: None,
                            ca_sha256: None,
                            uuid: None,
                            congestion_control: None,
                            alpn: None,
                            security: None,
                            alter_id: None,
                            network: None,
                            ws_path: None,
                            ws_headers: None,
                            h2_path: None,
                            h2_host: None,
                            grpc_service_name: None,
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
                        import: None,
                        username: None,
                        password: None,
                        cipher: None,
                        sni: None,
                        ca_sha256: None,
                        uuid: None,
                        congestion_control: None,
                        alpn: None,
                        security: None,
                        alter_id: None,
                        network: None,
                        ws_path: None,
                        ws_headers: None,
                        h2_path: None,
                        h2_host: None,
                        grpc_service_name: None,
                        dial_timeout_ms: 5000,
                    });

                    if current_node_has_import {
                        node = parse_import_url(node_name, &current_node_import_url, node)?;
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
                        // ── Shadowsocks ──
                        "cipher" => {
                            current_node.cipher = Some(unquote(value).to_string());
                        }
                        // ── TLS (Trojan / TUIC / Juicity / VMess) ──
                        "sni" => {
                            current_node.sni = Some(unquote(value).to_string());
                        }
                        "ca_sha256" => {
                            current_node.ca_sha256 = Some(unquote(value).to_string());
                        }
                        // ── TUIC / Juicity ──
                        "uuid" => {
                            current_node.uuid = Some(unquote(value).to_string());
                        }
                        "congestion_control" => {
                            current_node.congestion_control = Some(unquote(value).to_string());
                        }
                        "alpn" => {
                            current_node.alpn = Some(
                                value.split(',')
                                    .map(|s| unquote(s).to_string())
                                    .filter(|s| !s.is_empty())
                                    .collect(),
                            );
                        }
                        // ── VMess ──
                        "security" => {
                            current_node.security = Some(unquote(value).to_string());
                        }
                        "alter_id" => {
                            current_node.alter_id = Some(value.parse().map_err(|_| {
                                ConfigError::FieldType {
                                    line: line_number,
                                    field: key.into(),
                                    message: format!("无法解析为整数: '{}'", value),
                                }
                            })?);
                        }
                        "network" => {
                            current_node.network = Some(unquote(value).to_string());
                        }
                        "ws_path" => {
                            current_node.ws_path = Some(unquote(value).to_string());
                        }
                        "ws_headers" => {
                            current_node.ws_headers = Some(parse_map_value(value, line_number, key)?);
                        }
                        "h2_path" => {
                            current_node.h2_path = Some(unquote(value).to_string());
                        }
                        "h2_host" => {
                            current_node.h2_host = Some(unquote(value).to_string());
                        }
                        "grpc_service_name" => {
                            current_node.grpc_service_name = Some(unquote(value).to_string());
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
                            // Enter upstream sub-block: push current state and stay.
                            // 清空 Default 预置的 bootstrap，避免与解析出的条目重复。
                            if let Some(ref mut dns) = current_dns_config {
                                dns.starting_dns.upstream.clear();
                            }
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

/// Parse a map value of the form `{ "key1": "val1", "key2": "val2" }` into a HashMap.
///
/// Used for fields like `ws_headers`.
fn parse_map_value(
    value: &str,
    line_number: usize,
    field: &str,
) -> Result<std::collections::HashMap<String, String>> {
    let value = value.trim();
    let inner = value
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .ok_or_else(|| ConfigError::Syntax {
            line: line_number,
            message: format!("field '{}' expected map syntax `{{ \"key\": \"value\" }}`, got: '{}'", field, value),
        })?;
    let mut map = std::collections::HashMap::new();
    for entry in inner.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let colon_pos = entry.find(':').ok_or_else(|| ConfigError::Syntax {
            line: line_number,
            message: format!("field '{}' map entry expected `\"key\": \"value\"`, got: '{}'", field, entry),
        })?;
        let key = unquote(entry[..colon_pos].trim());
        let val = unquote(entry[colon_pos + 1..].trim());
        if key.is_empty() {
            return Err(ConfigError::Syntax {
                line: line_number,
                message: format!("field '{}' map entry has empty key: '{}'", field, entry),
            });
        }
        map.insert(key.to_string(), val.to_string());
    }
    Ok(map)
}

/// Parse an import line: `import: 'url'` or `import: "url"`
fn parse_import_line(line: &str) -> Option<String> {
    let line = line.trim();
    line.strip_prefix("import:").map(|s| s.trim()).map(|rest| unquote(rest).to_string())
}

/// Parse nodes(selector) syntax
pub(crate) fn parse_nodes_selector(line: &str) -> Option<Vec<NodeSelector>> {
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
pub(crate) fn unquote(s: &str) -> &str {
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
pub(crate) fn strip_inline_comment(line: &str) -> &str {
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
pub(crate) fn preprocess_multiline(input: &str) -> String {
    let lines: Vec<&str> = input.lines().collect();
    let mut result = String::with_capacity(input.len());
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_end();

        if let Some(stripped) = trimmed.strip_suffix('\\') {
            // Remove the trailing backslash and merge with the next line(s)
            result.push_str(stripped);
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

/// Parse a boolean value
pub(crate) fn parse_bool(s: &str) -> std::result::Result<bool, ()> {
    match s.trim() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        _ => Err(()),
    }
}