//! Example daefile configurations.

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