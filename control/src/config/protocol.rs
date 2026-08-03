//! Per-protocol string conversion.
//!
//! Converts protocol-specific import URI strings into [`OutboundNodeConfig`]
//! fields. Each protocol has its own parser in this file:
//!
//! | Scheme | Protocol | Format |
//! |--------|----------|--------|
//! | `socks5://` / `socks://` | SOCKS5 | `socks5://[user:pass@]host:port` |
//! | `ss://` | Shadowsocks | `ss://[cipher:password@]host:port` (SIP002, base64 forms) |
//! | `trojan://` | Trojan | `trojan://password@host:port?sni=...` |
//! | `tuic://` | TUIC v5 | `tuic://uuid:password@host:port?congestion_control=...&alpn=...` |
//! | `juicity://` | Juicity | `juicity://uuid:password@host:port?sni=...` |
//! | `vmess://` | VMess | `vmess://uuid@host:port?...` or v2rayN base64 JSON |
//!
//! The entry point is [`parse_import_url`], called by the daefile parser when a
//! node uses `import: 'scheme://...'`.

use super::parser::unquote;
use super::{ConfigError, OutboundNodeConfig, Result};

/// Parse an import URL and fill the node's protocol-specific fields.
///
/// Dispatches by URL scheme to the per-protocol parser below.
///
/// # Errors
///
/// Returns [`ConfigError::ImportInvalid`] if the scheme is unsupported or the
/// URI is malformed for the given protocol.
pub fn parse_import_url(
    node_name: &str,
    url: &str,
    mut node: OutboundNodeConfig,
) -> Result<OutboundNodeConfig> {
    if let Some(rest) = url
        .strip_prefix("socks5://")
        .or_else(|| url.strip_prefix("socks://"))
    {
        parse_socks5_import(rest, &mut node)?;
    } else if let Some(rest) = url.strip_prefix("ss://") {
        parse_ss_import(rest, &mut node)?;
    } else if let Some(rest) = url.strip_prefix("trojan://") {
        parse_trojan_import(rest, &mut node)?;
    } else if let Some(rest) = url.strip_prefix("tuic://") {
        parse_tuic_import(rest, &mut node)?;
    } else if let Some(rest) = url.strip_prefix("juicity://") {
        parse_juicity_import(rest, &mut node)?;
    } else if let Some(rest) = url.strip_prefix("vmess://") {
        parse_vmess_import(rest, &mut node)?;
    } else {
        return Err(ConfigError::ImportInvalid {
            name: node_name.to_string(),
            url: url.to_string(),
        });
    }
    Ok(node)
}

// ── SOCKS5 ──

/// `socks5://[user:pass@]host:port`
fn parse_socks5_import(rest: &str, node: &mut OutboundNodeConfig) -> Result<()> {
    node.protocol = "socks5".into();
    node.address = rest.to_string();
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
    Ok(())
}

// ── Shadowsocks ──

/// `ss://[cipher:password@]host:port` (SIP002)
///
/// Supports three forms:
/// - `ss://cipher:password@host:port` — legacy plaintext userinfo
/// - `ss://base64(cipher:password)@host:port` — base64 userinfo
/// - `ss://base64(method:password@host:port)` — full URI base64-encoded
fn parse_ss_import(rest: &str, node: &mut OutboundNodeConfig) -> Result<()> {
    node.protocol = "shadowsocks".into();
    let rest = rest.split('#').next().unwrap_or(rest);
    let mut assigned = false;
    if let Some(at_pos) = rest.rfind('@') {
        node.address = rest[at_pos + 1..].to_string();
        assigned = assign_ss_userinfo(&rest[..at_pos], node);
    }
    if !assigned {
        // Full-URI base64 form: base64(method:password@host:port)
        if let Some(decoded) = base64_decode(rest) {
            if let Some(at_pos) = decoded.rfind('@') {
                node.address = decoded[at_pos + 1..].to_string();
                assigned = assign_ss_userinfo(&decoded[..at_pos], node);
            }
        }
    }
    if !assigned || node.address.is_empty() {
        return Err(ConfigError::ImportInvalid {
            name: node.name.clone(),
            url: format!("ss://{}", rest),
        });
    }
    Ok(())
}

/// Fill `cipher`/`password` from a plaintext or base64-encoded userinfo.
fn assign_ss_userinfo(userinfo: &str, node: &mut OutboundNodeConfig) -> bool {
    if let Some(colon_pos) = userinfo.find(':') {
        node.cipher = Some(userinfo[..colon_pos].to_string());
        node.password = Some(userinfo[colon_pos + 1..].to_string());
        return true;
    }
    if let Some(decoded) = base64_decode(userinfo) {
        if let Some(colon_pos) = decoded.find(':') {
            node.cipher = Some(decoded[..colon_pos].to_string());
            node.password = Some(decoded[colon_pos + 1..].to_string());
            return true;
        }
    }
    false
}

// ── Trojan ──

/// `trojan://password@host:port?sni=...&allowInsecure=...`
fn parse_trojan_import(rest: &str, node: &mut OutboundNodeConfig) -> Result<()> {
    node.protocol = "trojan".into();
    let (main, query) = split_url(rest);
    if let Some(at_pos) = main.rfind('@') {
        node.password = Some(main[..at_pos].to_string());
        node.address = main[at_pos + 1..].to_string();
    }
    for (key, value) in query {
        match key.as_str() {
            "sni" | "peer" => node.sni = Some(value),
            "ca_sha256" => node.ca_sha256 = Some(value),
            _ => {}
        }
    }
    if node.password.is_none() || node.address.is_empty() {
        return Err(ConfigError::ImportInvalid {
            name: node.name.clone(),
            url: format!("trojan://{}", rest),
        });
    }
    Ok(())
}

// ── TUIC ──

/// `tuic://uuid:password@host:port?congestion_control=...&alpn=h3,h2&sni=...`
fn parse_tuic_import(rest: &str, node: &mut OutboundNodeConfig) -> Result<()> {
    node.protocol = "tuic".into();
    let (main, query) = split_url(rest);
    assign_uuid_password(main, node);
    for (key, value) in query {
        match key.as_str() {
            "congestion_control" => node.congestion_control = Some(value),
            "alpn" => {
                node.alpn = Some(
                    value
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect(),
                );
            }
            "sni" => node.sni = Some(value),
            "ca_sha256" => node.ca_sha256 = Some(value),
            _ => {}
        }
    }
    if node.uuid.is_none() || node.password.is_none() || node.address.is_empty() {
        return Err(ConfigError::ImportInvalid {
            name: node.name.clone(),
            url: format!("tuic://{}", rest),
        });
    }
    Ok(())
}

// ── Juicity ──

/// `juicity://uuid:password@host:port?sni=...&congestion_control=...`
fn parse_juicity_import(rest: &str, node: &mut OutboundNodeConfig) -> Result<()> {
    node.protocol = "juicity".into();
    let (main, query) = split_url(rest);
    assign_uuid_password(main, node);
    for (key, value) in query {
        match key.as_str() {
            "congestion_control" => node.congestion_control = Some(value),
            "sni" => node.sni = Some(value),
            "ca_sha256" => node.ca_sha256 = Some(value),
            _ => {}
        }
    }
    if node.uuid.is_none() || node.password.is_none() || node.address.is_empty() {
        return Err(ConfigError::ImportInvalid {
            name: node.name.clone(),
            url: format!("juicity://{}", rest),
        });
    }
    Ok(())
}

/// Fill `uuid`/`password`/`address` from a `uuid:password@host:port` userinfo.
fn assign_uuid_password(main: &str, node: &mut OutboundNodeConfig) {
    if let Some(at_pos) = main.rfind('@') {
        let cred = &main[..at_pos];
        node.address = main[at_pos + 1..].to_string();
        if let Some(colon_pos) = cred.find(':') {
            node.uuid = Some(cred[..colon_pos].to_string());
            node.password = Some(cred[colon_pos + 1..].to_string());
        } else {
            node.uuid = Some(cred.to_string());
        }
    }
}

// ── VMess ──

/// `vmess://uuid@host:port?security=...&alterId=...&network=...&sni=...`
///
/// Also accepts the v2rayN base64 JSON form: `vmess://base64(json)`.
fn parse_vmess_import(rest: &str, node: &mut OutboundNodeConfig) -> Result<()> {
    node.protocol = "vmess".into();
    // v2rayN base64 JSON format
    if let Some(decoded) = base64_decode(rest) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&decoded) {
            return parse_vmess_json(&json, node);
        }
    }
    // Standard URI format
    let (main, query) = split_url(rest);
    if let Some(at_pos) = main.rfind('@') {
        node.uuid = Some(main[..at_pos].to_string());
        node.address = main[at_pos + 1..].to_string();
    }
    for (key, value) in query {
        match key.as_str() {
            "security" | "scy" => node.security = Some(value),
            "alterId" | "aid" => node.alter_id = value.parse().ok(),
            "network" | "net" => node.network = Some(value),
            "sni" => node.sni = Some(value),
            "path" | "wsPath" => node.ws_path = Some(value),
            "grpcServiceName" => node.grpc_service_name = Some(value),
            "host" => {
                let network = node.network.clone().unwrap_or_default();
                if network == "h2" {
                    node.h2_host = Some(value);
                } else if network == "ws" {
                    node.ws_headers
                        .get_or_insert_with(Default::default)
                        .insert("Host".into(), value);
                }
            }
            _ => {}
        }
    }
    if node.uuid.is_none() || node.address.is_empty() {
        return Err(ConfigError::ImportInvalid {
            name: node.name.clone(),
            url: format!("vmess://{}", rest),
        });
    }
    Ok(())
}

/// Convert a v2rayN base64 JSON object into node fields.
fn parse_vmess_json(json: &serde_json::Value, node: &mut OutboundNodeConfig) -> Result<()> {
    let get = |key: &str| {
        json.get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };
    // v2rayN encodes numeric fields as strings, tolerate both forms
    let as_u64 = |v: &serde_json::Value| {
        v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    };
    if let (Some(add), Some(port)) = (get("add"), json.get("port").and_then(as_u64)) {
        node.address = format!("{add}:{port}");
    }
    node.uuid = get("id").or_else(|| node.uuid.clone());
    node.alter_id = json.get("aid").and_then(as_u64).map(|v| v as u32);
    node.security = get("scy").or_else(|| get("security"));
    node.network = get("net");
    node.sni = get("sni").or_else(|| get("tls").filter(|s| s != "none"));
    if let Some(path) = get("path") {
        node.ws_path = Some(path);
    }
    if let Some(host) = get("host") {
        match node.network.as_deref() {
            Some("h2") => node.h2_host = Some(host),
            Some("ws") => {
                node.ws_headers
                    .get_or_insert_with(Default::default)
                    .insert("Host".into(), host);
            }
            _ => {}
        }
    }
    if node.uuid.is_none() || node.address.is_empty() {
        return Err(ConfigError::ImportInvalid {
            name: node.name.clone(),
            url: "vmess://<base64>".into(),
        });
    }
    Ok(())
}

// ── Shared helpers ──

/// Split `main?key=value&key2=value2` into its main part and query pairs.
fn split_url(rest: &str) -> (&str, Vec<(String, String)>) {
    let (main, query) = match rest.split_once('?') {
        Some((m, q)) => (m, q),
        None => (rest, ""),
    };
    let pairs = query
        .split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|kv| {
            kv.split_once('=')
                .map(|(k, v)| (k.to_string(), unquote(v).to_string()))
        })
        .collect();
    (main, pairs)
}

/// Decode standard base64 to UTF-8 string, tolerating missing padding.
fn base64_decode(input: &str) -> Option<String> {
    use base64::Engine as _;
    let input = input.trim();
    let padded = match input.len() % 4 {
        0 => input.to_string(),
        n => format!("{}{}", input, "=".repeat(4 - n)),
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(padded.as_bytes())
        .ok()?;
    String::from_utf8(bytes).ok()
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(url: &str) -> OutboundNodeConfig {
        parse_import_url("imported", url, OutboundNodeConfig {
            name: "imported".into(),
            protocol: String::new(),
            address: String::new(),
            import: Some(url.to_string()),
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
        })
        .expect("import parse should succeed")
    }

    #[test]
    fn test_socks5_import() {
        let node = parse_ok("socks5://user:pass@127.0.0.1:1080");
        assert_eq!(node.protocol, "socks5");
        assert_eq!(node.address, "127.0.0.1:1080");
        assert_eq!(node.username.as_deref(), Some("user"));
        assert_eq!(node.password.as_deref(), Some("pass"));
    }

    #[test]
    fn test_socks5_import_no_auth() {
        let node = parse_ok("socks5://127.0.0.1:1080");
        assert_eq!(node.address, "127.0.0.1:1080");
        assert!(node.username.is_none());
    }

    #[test]
    fn test_ss_import_plaintext() {
        let node = parse_ok("ss://aes-256-gcm:password@server.example.com:8388");
        assert_eq!(node.protocol, "shadowsocks");
        assert_eq!(node.cipher.as_deref(), Some("aes-256-gcm"));
        assert_eq!(node.password.as_deref(), Some("password"));
        assert_eq!(node.address, "server.example.com:8388");
    }

    #[test]
    fn test_ss_import_base64_userinfo() {
        let node = parse_ok("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@server.example.com:8388");
        assert_eq!(node.cipher.as_deref(), Some("aes-256-gcm"));
        assert_eq!(node.password.as_deref(), Some("password"));
    }

    #[test]
    fn test_ss_import_base64_full() {
        // base64("aes-256-gcm:password@server.example.com:8388")
        let node = parse_ok("ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAc2VydmVyLmV4YW1wbGUuY29tOjgzODg=");
        assert_eq!(node.cipher.as_deref(), Some("aes-256-gcm"));
        assert_eq!(node.password.as_deref(), Some("password"));
        assert_eq!(node.address, "server.example.com:8388");
    }

    #[test]
    fn test_trojan_import() {
        let node = parse_ok("trojan://pass123@server.example.com:443?sni=example.com");
        assert_eq!(node.protocol, "trojan");
        assert_eq!(node.password.as_deref(), Some("pass123"));
        assert_eq!(node.address, "server.example.com:443");
        assert_eq!(node.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_tuic_import() {
        let node = parse_ok(
            "tuic://d0529668-8835-11ec-a8a3-0242ac120002:pw@server.example.com:443?congestion_control=bbr&alpn=h3,h2&sni=example.com",
        );
        assert_eq!(node.protocol, "tuic");
        assert_eq!(node.uuid.as_deref(), Some("d0529668-8835-11ec-a8a3-0242ac120002"));
        assert_eq!(node.password.as_deref(), Some("pw"));
        assert_eq!(node.congestion_control.as_deref(), Some("bbr"));
        assert_eq!(node.alpn.as_ref(), Some(&vec!["h3".to_string(), "h2".to_string()]));
        assert_eq!(node.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_juicity_import() {
        let node = parse_ok(
            "juicity://d0529668-8835-11ec-a8a3-0242ac120002:pw@server.example.com:443?sni=example.com",
        );
        assert_eq!(node.protocol, "juicity");
        assert_eq!(node.uuid.as_deref(), Some("d0529668-8835-11ec-a8a3-0242ac120002"));
        assert_eq!(node.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_vmess_import_standard() {
        let node = parse_ok(
            "vmess://d0529668-8835-11ec-a8a3-0242ac120002@server.example.com:443?security=auto&network=ws&path=/ws&host=cdn.example.com&sni=example.com",
        );
        assert_eq!(node.protocol, "vmess");
        assert_eq!(node.uuid.as_deref(), Some("d0529668-8835-11ec-a8a3-0242ac120002"));
        assert_eq!(node.address, "server.example.com:443");
        assert_eq!(node.security.as_deref(), Some("auto"));
        assert_eq!(node.network.as_deref(), Some("ws"));
        assert_eq!(node.ws_path.as_deref(), Some("/ws"));
        assert_eq!(node.sni.as_deref(), Some("example.com"));
        let headers = node.ws_headers.as_ref().expect("ws_headers");
        assert_eq!(headers.get("Host").map(String::as_str), Some("cdn.example.com"));
    }

    #[test]
    fn test_vmess_import_base64_json() {
        // v2rayN JSON: {"v":"2","ps":"name","add":"1.2.3.4","port":"32000","id":"1386f85e-...","aid":"100","scy":"auto","net":"ws","type":"none","host":"www.bbb.com","path":"/","tls":"tls","sni":"www.ccc.net"}
        let json = r#"{"v":"2","ps":"name","add":"1.2.3.4","port":"32000","id":"1386f85e-65bb-4e6e-9d56-78badb75e1fd","aid":"100","scy":"auto","net":"ws","type":"none","host":"www.bbb.com","path":"/","tls":"tls","sni":"www.ccc.net"}"#;
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json);
        let node = parse_ok(&format!("vmess://{}", b64));
        assert_eq!(node.protocol, "vmess");
        assert_eq!(node.uuid.as_deref(), Some("1386f85e-65bb-4e6e-9d56-78badb75e1fd"));
        assert_eq!(node.address, "1.2.3.4:32000");
        assert_eq!(node.alter_id, Some(100));
        assert_eq!(node.security.as_deref(), Some("auto"));
        assert_eq!(node.network.as_deref(), Some("ws"));
        assert_eq!(node.ws_path.as_deref(), Some("/"));
        assert_eq!(node.sni.as_deref(), Some("www.ccc.net"));
        let headers = node.ws_headers.as_ref().expect("ws_headers");
        assert_eq!(headers.get("Host").map(String::as_str), Some("www.bbb.com"));
    }

    #[test]
    fn test_import_unsupported_scheme() {
        let node = OutboundNodeConfig {
            name: "x".into(),
            protocol: String::new(),
            address: String::new(),
            import: Some("vless://...".into()),
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
        let err = parse_import_url("x", "vless://...", node).unwrap_err();
        assert!(matches!(err, ConfigError::ImportInvalid { .. }));
    }

    #[test]
    fn test_import_malformed_ss() {
        let node = OutboundNodeConfig {
            name: "x".into(),
            protocol: String::new(),
            address: String::new(),
            import: Some("ss://broken".into()),
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
        let err = parse_import_url("x", "ss://broken", node).unwrap_err();
        assert!(matches!(err, ConfigError::ImportInvalid { .. }));
    }
}
