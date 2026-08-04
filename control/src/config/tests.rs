//! Unit tests for the config subsystem.

use super::*;
use super::parser::{parse_bool, parse_nodes_selector, preprocess_multiline, strip_inline_comment, unquote};
use super::validator::extract_proxy_group;
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

    // ── New Protocol Tests ──

    /// Config with all supported protocols and their fields (mirrors config-example/config.daefile)
    const ALL_PROTOCOLS_CONFIG: &str = r#"global {
  tproxy_port: 15080
  log_level: info
}

outbounds {
  nodes {
    ss_node {
      protocol: shadowsocks
      address: 192.168.12.1:9697
      cipher: aes-128-gcm
      password: password123
      dial_timeout_ms: 5000
    }
    trojan_node {
      protocol: trojan
      address: server.example.com:443
      password: your-password
      sni: server.example.com
      ca_sha256: "fb3a01e4..."
      dial_timeout_ms: 5000
    }
    tuic_node {
      protocol: tuic
      address: server.example.com:443
      uuid: d0529668-8835-11ec-a8a3-0242ac120002
      password: your-password
      congestion_control: bbr
      alpn: h3, h2
      sni: server.example.com
      dial_timeout_ms: 5000
    }
    juicity_node {
      protocol: juicity
      address: server.example.com:443
      uuid: d0529668-8835-11ec-a8a3-0242ac120002
      password: your-password
      sni: server.example.com
      dial_timeout_ms: 5000
    }
    vmess_ws_node {
      protocol: vmess
      address: server.example.com:80
      uuid: d0529668-8835-11ec-a8a3-0242ac120002
      security: none
      alter_id: 0
      network: ws
      ws_path: /ws
      ws_headers: { "Host": "example.com" }
      dial_timeout_ms: 5000
    }
    vmess_grpc_node {
      protocol: vmess
      address: server.example.com:443
      uuid: d0529668-8835-11ec-a8a3-0242ac120002
      security: none
      alter_id: 0
      network: grpc
      grpc_service_name: grpc
      sni: server.example.com
      dial_timeout_ms: 5000
    }
  }

  groups {
    g {
      policy: fixed
      nodes(regex: '*')
    }
  }
}

routing {
  fallback: proxy(g)
}
"#;

    #[test]
    fn test_parse_all_protocols() {
        let config = parse_daefile(ALL_PROTOCOLS_CONFIG).expect("all-protocols config parse failed");
        assert_eq!(config.outbounds.nodes.len(), 6);

        let ss = &config.outbounds.nodes[0];
        assert_eq!(ss.protocol, "shadowsocks");
        assert_eq!(ss.cipher.as_deref(), Some("aes-128-gcm"));
        assert_eq!(ss.password.as_deref(), Some("password123"));

        let trojan = &config.outbounds.nodes[1];
        assert_eq!(trojan.protocol, "trojan");
        assert_eq!(trojan.password.as_deref(), Some("your-password"));
        assert_eq!(trojan.sni.as_deref(), Some("server.example.com"));
        assert_eq!(trojan.ca_sha256.as_deref(), Some("fb3a01e4..."));

        let tuic = &config.outbounds.nodes[2];
        assert_eq!(tuic.protocol, "tuic");
        assert_eq!(tuic.uuid.as_deref(), Some("d0529668-8835-11ec-a8a3-0242ac120002"));
        assert_eq!(tuic.congestion_control.as_deref(), Some("bbr"));
        assert_eq!(tuic.alpn.as_ref(), Some(&vec!["h3".to_string(), "h2".to_string()]));
        assert_eq!(tuic.sni.as_deref(), Some("server.example.com"));

        let juicity = &config.outbounds.nodes[3];
        assert_eq!(juicity.protocol, "juicity");
        assert_eq!(juicity.uuid.as_deref(), Some("d0529668-8835-11ec-a8a3-0242ac120002"));

        let ws = &config.outbounds.nodes[4];
        assert_eq!(ws.protocol, "vmess");
        assert_eq!(ws.security.as_deref(), Some("none"));
        assert_eq!(ws.alter_id, Some(0));
        assert_eq!(ws.network.as_deref(), Some("ws"));
        assert_eq!(ws.ws_path.as_deref(), Some("/ws"));
        let headers = ws.ws_headers.as_ref().expect("ws_headers should exist");
        assert_eq!(headers.get("Host").map(String::as_str), Some("example.com"));

        let grpc = &config.outbounds.nodes[5];
        assert_eq!(grpc.protocol, "vmess");
        assert_eq!(grpc.network.as_deref(), Some("grpc"));
        assert_eq!(grpc.grpc_service_name.as_deref(), Some("grpc"));
    }

    #[test]
    fn test_all_protocols_validate_and_to_json() {
        let config = parse_daefile(ALL_PROTOCOLS_CONFIG).expect("parse failed");
        validate_config(&config).expect("validation failed");
        let json = serde_json::to_string_pretty(&config).expect("JSON serialization failed");
        for key in [
            "shadowsocks",
            "cipher",
            "trojan",
            "tuic",
            "juicity",
            "vmess",
            "uuid",
            "congestion_control",
            "ws_headers",
            "grpc_service_name",
        ] {
            assert!(json.contains(key), "JSON should contain '{}'", key);
        }
    }

    #[test]
    fn test_shadowsocks_missing_cipher() {
        let input = r#"global {
  tproxy_port: 15080
  log_level: info
}

outbounds {
  nodes {
    ss_node {
      protocol: shadowsocks
      address: 192.168.12.1:9697
      password: password123
    }
  }

  groups {
    g {
      policy: fixed
      nodes(ss_node)
    }
  }
}

routing {
  fallback: proxy(g)
}
"#;
        let config = parse_daefile(input).expect("parse failed");
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn test_invalid_ws_headers_map() {
        let input = r#"global {
  tproxy_port: 15080
  log_level: info
}

outbounds {
  nodes {
    vmess_node {
      protocol: vmess
      address: server.example.com:80
      uuid: d0529668-8835-11ec-a8a3-0242ac120002
      network: ws
      ws_headers: "Host: example.com"
    }
  }

  groups {
    g {
      policy: fixed
      nodes(vmess_node)
    }
  }
}

routing {
  fallback: proxy(g)
}
"#;
        let err = parse_daefile(input).unwrap_err();
        assert!(matches!(err, ConfigError::Syntax { .. }));
    }

    #[test]
    fn test_example_config_daefile_to_json() {
        let input = include_str!("../../../config-example/config.daefile");
        let config = parse_daefile(input).expect("config.daefile parse failed");
        validate_config(&config).expect("config.daefile validation failed");
        let json = serde_json::to_string_pretty(&config).expect("JSON serialization failed");
        assert!(json.contains("shadowsocks"));
        assert!(json.contains("trojan"));
        assert!(json.contains("tuic"));
        assert!(json.contains("juicity"));
        assert!(json.contains("vmess"));
        assert!(json.contains("ws_headers"));
        assert!(json.contains("grpc_service_name"));
        // Example config includes rule_set block
        assert!(json.contains("rule_set"));
        assert!(json.contains("geoip_main"));
    }

    #[test]
    fn test_example_config_daefile_ruleset() {
        // Phase 4: rule_set block and ruleset references in config-example/config.daefile must be parseable/validated
        let input = include_str!("../../../config-example/config.daefile");
        let config = parse_daefile(input).expect("config.daefile parse failed");
        validate_config(&config).expect("config.daefile validation failed");

        // All four entry types present and names unique
        assert_eq!(config.rule_set.len(), 4);
        let types: Vec<RuleSetType> = config.rule_set.iter().map(|e| e.r#type).collect();
        assert!(types.contains(&RuleSetType::GeoIp));
        assert!(types.contains(&RuleSetType::GeoSite));
        assert!(types.contains(&RuleSetType::DomainList));
        assert!(types.contains(&RuleSetType::IpList));

        let geoip = config.rule_set.iter().find(|e| e.name == "geoip_main").unwrap();
        assert_eq!(geoip.r#type, RuleSetType::GeoIp);
        assert_eq!(geoip.update, Some(RuleSetUpdate::Time("21:47".into())));
        assert!(geoip.update_on_start);

        let geosite = config.rule_set.iter().find(|e| e.name == "geosite_main").unwrap();
        assert_eq!(geosite.r#type, RuleSetType::GeoSite);
        assert_eq!(geosite.update, Some(RuleSetUpdate::Period("3h2m".into())));

        let chinadomain = config.rule_set.iter().find(|e| e.name == "chinadomain").unwrap();
        assert_eq!(chinadomain.r#type, RuleSetType::DomainList);
        assert_eq!(chinadomain.update, Some(RuleSetUpdate::Time("04:30".into())));

        let chinaip = config.rule_set.iter().find(|e| e.name == "chinaip").unwrap();
        assert_eq!(chinaip.r#type, RuleSetType::IpList);
        assert_eq!(chinaip.update, Some(RuleSetUpdate::Period("1d".into())));
        assert_eq!(chinaip.proxy.as_deref(), Some("proxy_primary"));

        // Data plane Routing references (Phase 3 syntax)
        let matches: Vec<&str> = config.routing.rules.iter().map(|r| r.r#match.as_str()).collect();
        assert!(matches.contains(&"source_ip(set:chinaip)"));
        assert!(matches.contains(&"target_ip(geoip:cn)"));
        assert!(matches.contains(&"target_domain(geosite:cn)"));
        assert!(matches.contains(&"target_domain(set:chinadomain)"));

        // DNS query Routing / response Routing references
        let dns = config.dns.as_ref().expect("dns config");
        assert!(
            dns.routing.rules.iter().any(|r| r.r#match == "qname(set:chinadomain)"),
            "DNS query routing should reference set:chinadomain"
        );
        let trusted = dns.groups.iter().find(|g| g.name == "trusted_dns").unwrap();
        let resp = trusted.response_routing.as_ref().expect("response_routing");
        assert!(resp.rules.iter().any(|r| r.r#match == "ip(set:chinaip)"));
    }

    #[test]
    fn test_example_config_json_parse_validate() {
        // Phase 4: config-example/config.json consistent with daefile semantics, parse + validate passes
        let input = include_str!("../../../config-example/config.json");
        let config: DaefileConfig =
            serde_json::from_str(input).expect("config.json deserialize failed");
        validate_config(&config).expect("config.json validation failed");

        // rule_set is an object (key = name) → four entry types
        assert_eq!(config.rule_set.len(), 4);
        let geoip = config.rule_set.iter().find(|e| e.name == "geoip_main").unwrap();
        assert_eq!(geoip.r#type, RuleSetType::GeoIp);
        assert!(geoip.update_on_start);
        assert_eq!(geoip.update, Some(RuleSetUpdate::Time("21:47".into())));

        let chinaip = config.rule_set.iter().find(|e| e.name == "chinaip").unwrap();
        assert_eq!(chinaip.r#type, RuleSetType::IpList);
        assert_eq!(chinaip.update, Some(RuleSetUpdate::Period("1d".into())));
        assert_eq!(chinaip.proxy.as_deref(), Some("proxy_primary"));

        // reference rules align with daefile
        let matches: Vec<&str> = config.routing.rules.iter().map(|r| r.r#match.as_str()).collect();
        assert!(matches.contains(&"source_ip(set:chinaip)"));
        assert!(matches.contains(&"target_ip(geoip:cn)"));
        assert!(matches.contains(&"target_domain(set:chinadomain)"));
        let dns = config.dns.as_ref().expect("dns config");
        assert!(dns.routing.rules.iter().any(|r| r.r#match == "qname(set:chinadomain)"));
    }

    #[test]
    fn test_minimal_example_daefile_to_json() {
        let input = include_str!("../../../config-example/config-minimal.daefile");
        let config = parse_daefile(input).expect("config-minimal.daefile parse failed");
        validate_config(&config).expect("config-minimal.daefile validation failed");
        let json = serde_json::to_string_pretty(&config).expect("JSON serialization failed");
        // example node is shadowsocks (cipher/password fields)
        assert!(json.contains("shadowsocks"));
        assert!(json.contains("aes-128-gcm"));
        assert!(json.contains("192.168.12.1:9697"));
        // starting_dns is a flat IP list; config-minimal uses 2 bootstrap servers
        let dns = config.dns.as_ref().expect("dns config");
        assert_eq!(dns.starting_dns.upstream.len(), 2);
        assert!(dns.starting_dns.upstream.iter().all(|a| a.starts_with("udp://")));
        // default query_mode is Concurrent when not specified
        let g = dns.groups.iter().find(|g| g.name == "default_dns").unwrap();
        assert_eq!(g.query_mode, DnsQueryMode::Concurrent);
    }

    // ── Rule Set parse / validation tests ──

    /// Complete daefile config with two ruleset entries (simplified from design §5.1 example).
    const RULE_SET_CONFIG: &str = r#"global {
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

rule_set {
  geoip_main {
    type: geoip
    url: 'https://example.com/geoip.dat'
    name: geoip_main
    update: time: 21:47
    update_on_start: true
  }
  geosite_main {
    type: geosite
    url: 'https://example.com/geosite.dat'
    update: period: 3h2m
    proxy: g
  }
}
"#;

    /// Generate complete daefile text with "base config + specified rule_set block".
    fn config_with_rule_set(rule_set_block: &str) -> String {
        format!(
            r#"global {{
  tproxy_port: 15080
  log_level: info
}}

outbounds {{
  nodes {{
    main {{
      protocol: socks5
      address: 127.0.0.1:1080
    }}
  }}
  groups {{
    g {{
      policy: fixed
      nodes(main)
    }}
  }}
}}

routing {{
  fallback: proxy(g)
}}

rule_set {{
{}
}}
"#,
            rule_set_block
        )
    }

    #[test]
    fn test_parse_rule_set_daefile() {
        let config = parse_daefile(RULE_SET_CONFIG).expect("rule_set config parse failed");
        assert_eq!(config.rule_set.len(), 2);

        let geo = &config.rule_set[0];
        assert_eq!(geo.name, "geoip_main");
        assert_eq!(geo.r#type, RuleSetType::GeoIp);
        assert_eq!(geo.url, "https://example.com/geoip.dat");
        assert_eq!(geo.update, Some(RuleSetUpdate::Time("21:47".into())));
        assert!(geo.update_on_start);
        assert_eq!(geo.proxy, None);

        let site = &config.rule_set[1];
        assert_eq!(site.name, "geosite_main");
        assert_eq!(site.r#type, RuleSetType::GeoSite);
        assert_eq!(site.update, Some(RuleSetUpdate::Period("3h2m".into())));
        assert!(!site.update_on_start);
        assert_eq!(site.proxy.as_deref(), Some("g"));

        // default name = block name (entries without explicit name)
        assert_eq!(site.name, "geosite_main");

        validate_config(&config).expect("rule_set config validation failed");
    }

    #[test]
    fn test_rule_set_sha256_extracted_from_url_fragment() {
        let block = r#"chinaip {
  type: ip_list
  url: 'https://example.com/ip.txt#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  update: period: 1d
}
"#;
        let config = parse_daefile(&config_with_rule_set(block)).unwrap();
        assert_eq!(
            config.rule_set[0].expected_sha256.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }

    #[test]
    fn test_rule_set_duplicate_name_e2101() {
        let block = r#"a {
  type: geoip
  url: 'https://example.com/a.dat'
  update: time: 00:00
}
b {
  type: geosite
  url: 'https://example.com/b.dat'
  name: a
  update: time: 00:00
}
"#;
        let config = parse_daefile(&config_with_rule_set(block)).unwrap();
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, ConfigError::DuplicateRuleSet { name } if name == "a"));
    }

    #[test]
    fn test_rule_set_invalid_name() {
        let block = r#"bad name {
  type: geoip
  url: 'https://example.com/a.dat'
  update: time: 00:00
}
"#;
        // spaces cause parse failure (block names cannot contain spaces)
        assert!(parse_daefile(&config_with_rule_set(block)).is_err());

        // illegal characters (including '/') enter structure via explicit name → validator error
        let block2 = r#"a {
  type: geoip
  url: 'https://example.com/a.dat'
  name: 'a/b'
  update: time: 00:00
}
"#;
        let config = parse_daefile(&config_with_rule_set(block2)).unwrap();
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn test_rule_set_invalid_url_e2105() {
        // not http/https
        let block = r#"a {
  type: geoip
  url: 'ftp://example.com/a.dat'
  update: time: 00:00
}
"#;
        let config = parse_daefile(&config_with_rule_set(block)).unwrap();
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRuleSetUrl { .. }));

        // #sha256= not 64 hex
        let block2 = r#"a {
  type: geoip
  url: 'https://example.com/a.dat#sha256=xyz'
  update: time: 00:00
}
"#;
        let config = parse_daefile(&config_with_rule_set(block2)).unwrap();
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRuleSetUrl { .. }));
    }

    #[test]
    fn test_rule_set_missing_update_e2104() {
        let block = r#"a {
  type: geoip
  url: 'https://example.com/a.dat'
}
"#;
        let config = parse_daefile(&config_with_rule_set(block)).unwrap();
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRuleSetUpdate { .. }));
    }

    #[test]
    fn test_rule_set_invalid_time_e2104() {
        let block = r#"a {
  type: geoip
  url: 'https://example.com/a.dat'
  update: time: 25:99
}
"#;
        let config = parse_daefile(&config_with_rule_set(block)).unwrap();
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRuleSetUpdate { .. }));
    }

    #[test]
    fn test_rule_set_time_with_seconds_e2104() {
        let block = r#"a {
  type: geoip
  url: 'https://example.com/a.dat'
  update: time: 21:47:30
}
"#;
        let config = parse_daefile(&config_with_rule_set(block)).unwrap();
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRuleSetUpdate { .. }));
    }

    #[test]
    fn test_rule_set_invalid_period_e2104() {
        // second-level
        let block = r#"a {
  type: geoip
  url: 'https://example.com/a.dat'
  update: period: 1s
}
"#;
        let config = parse_daefile(&config_with_rule_set(block)).unwrap();
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRuleSetUpdate { .. }));

        // Invalid unit
        let block2 = r#"a {
  type: geoip
  url: 'https://example.com/a.dat'
  update: period: 3x
}
"#;
        let config = parse_daefile(&config_with_rule_set(block2)).unwrap();
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRuleSetUpdate { .. }));
    }

    #[test]
    fn test_rule_set_update_conflict_in_daefile() {
        let block = r#"a {
  type: geoip
  url: 'https://example.com/a.dat'
  update: time: 21:47
  update: period: 3h2m
}
"#;
        let err = parse_daefile(&config_with_rule_set(block)).unwrap_err();
        assert!(matches!(err, ConfigError::Syntax { .. }));
    }

    #[test]
    fn test_rule_set_invalid_type() {
        let block = r#"a {
  type: bogus
  url: 'https://example.com/a.dat'
  update: time: 00:00
}
"#;
        let err = parse_daefile(&config_with_rule_set(block)).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn test_rule_set_json_deserialize_map() {
        // rule_set in JSON is an object (key = name)
        let json = r#"{
            "version": 1,
            "runtime": { "tproxy_port": 15080, "log_level": "info" },
            "outbounds": { "nodes": [], "groups": [] },
            "routing": { "rules": [], "fallback": "direct" },
            "rule_set": {
                "geoip_main": {
                    "type": "geoip",
                    "url": "https://example.com/geoip.dat#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "update": { "time": "21:47" },
                    "update_on_start": true
                },
                "chinaip": {
                    "type": "ip_list",
                    "url": "https://example.com/ip.txt",
                    "update": { "period": "1d" }
                }
            }
        }"#;
        let cfg: DaefileConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.rule_set.len(), 2);

        let geo = cfg.rule_set.iter().find(|e| e.name == "geoip_main").unwrap();
        assert_eq!(geo.r#type, RuleSetType::GeoIp);
        assert_eq!(geo.update, Some(RuleSetUpdate::Time("21:47".into())));
        assert!(geo.update_on_start);
        assert_eq!(
            geo.expected_sha256.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );

        let ip = cfg.rule_set.iter().find(|e| e.name == "chinaip").unwrap();
        assert_eq!(ip.r#type, RuleSetType::IpList);
        assert_eq!(ip.update, Some(RuleSetUpdate::Period("1d".into())));
        assert_eq!(ip.proxy, None);
    }

    #[test]
    fn test_rule_set_serde_roundtrip() {
        let config = parse_daefile(RULE_SET_CONFIG).unwrap();
        let json = serde_json::to_string_pretty(&config).unwrap();
        // rule_set in JSON is an object (key=name)
        let deserialized: DaefileConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.rule_set.len(), config.rule_set.len());
        for a in &config.rule_set {
            let b = deserialized.rule_set.iter().find(|b| b.name == a.name).unwrap();
            assert_eq!(a, b, "rule set entry {} should roundtrip", a.name);
        }
    }
