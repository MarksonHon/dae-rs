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
  # DNS 转发全局开关，默认为 true。设为 false 则完全不触碰 DNS 流量
  forward_dns: true
}

dns {
  # 远端上游 DNS（通过代理查询），默认 Google DNS
  upstream_remote: ["8.8.8.8:53", "[2001:4860:4860::8888]:53"]
  # 上游策略：parallel（并发）或 sequential（顺序）
  upstream_strategy: parallel
  # 每代理组缓存条目数
  cache_size_per_group: 1024
  # 查询超时（毫秒）
  query_timeout_ms: 5000
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