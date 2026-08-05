pub mod upstream;
pub mod cache;
pub mod router;
pub mod handler;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::{info, warn};

use protocols::OutboundDialer;
use crate::config::DnsConfig;
use crate::dns::handler::{DnsListener, DnsResolveCallback};
use crate::dns::upstream::DnsUpstreamPool;
use crate::dns::cache::DnsCache;
use crate::dns::router::DnsRouter;
use crate::ruleset::cache::RuleSetCache;

/// DNS Manager — main orchestrator for DNS operations
pub struct DnsManager {
    /// Configuration
    config: DnsConfig,
    /// Upstream connection pool (label -> pool)
    upstream_pools: HashMap<String, Arc<DnsUpstreamPool>>,
    /// DNS response cache
    cache: Arc<tokio::sync::RwLock<DnsCache>>,
    /// DNS router (request matching)
    router: DnsRouter,
    /// DNS listener (UDP + TCP)
    listener: Option<DnsListener>,
    /// Whether the manager is running
    running: bool,
    /// Callback invoked on each accepted DNS resolution (domain, ip, ttl).
    /// Used to feed the domain_routing_map eBPF map for domain-based routing.
    on_resolve: Option<DnsResolveCallback>,
    /// Ruleset in-memory cache (for DNS routing / response Routing evaluation).
    rule_set_cache: RuleSetCache,
    /// Outbound dialers keyed by proxy **group name** for proxied DNS upstream
    /// queries (`send_by != "direct"`). The DNS group's `send_by` value names an
    /// outbound group; the query goes through that group's dialer.
    dialers: HashMap<String, Arc<dyn OutboundDialer>>,
}

impl DnsManager {
    /// Construct DNS manager.
    ///
    /// * `config` — DNS configuration;
    /// * `rule_set_cache` — ruleset in-memory cache;
    /// * `dialers` — outbound dialers keyed by proxy group name, used for
    ///   proxied DNS upstream queries (`send_by`).
    ///
    /// Returns error when DNS Routing compilation fails (unknown/invalid match expression).
    pub fn new(
        config: DnsConfig,
        rule_set_cache: RuleSetCache,
        dialers: HashMap<String, Arc<dyn OutboundDialer>>,
    ) -> anyhow::Result<Self> {
        let router = DnsRouter::new(&config, rule_set_cache.clone())?;
        let cache = Arc::new(tokio::sync::RwLock::new(DnsCache::new(&config.cache)));

        Ok(Self {
            config,
            upstream_pools: HashMap::new(),
            cache,
            router,
            listener: None,
            running: false,
            on_resolve: None,
            rule_set_cache,
            dialers,
        })
    }

    /// Set the callback invoked on each accepted DNS resolution.
    /// Used to feed domain routing into the eBPF domain_routing_map.
    pub fn set_on_resolve(&mut self, on_resolve: Option<DnsResolveCallback>) {
        self.on_resolve = on_resolve;
    }

    /// Initialize upstream pools for all DNS groups.
    ///
    /// Upstream entries whose address is a hostname (e.g. `udp://dns.google:53`)
    /// are resolved via the `starting_dns` (bootstrap) pools. A single failing
    /// upstream is skipped with a warning instead of aborting the whole init —
    /// otherwise one bad entry would make every DNS query return SERVFAIL.
    pub async fn init_upstreams(&mut self) -> anyhow::Result<()> {
        // Bootstrap pools first. They MUST be IP addresses: resolving a hostname
        // bootstrap would create a chicken-and-egg problem (nothing to resolve it with).
        let mut bootstrap_pools: HashMap<String, Arc<DnsUpstreamPool>> = HashMap::new();
        for (i, addr) in self.config.starting_dns.upstream.iter().enumerate() {
            match DnsUpstreamPool::new(addr) {
                Ok(pool) => {
                    bootstrap_pools.insert(format!("__starting__{}", i), Arc::new(pool));
                }
                Err(e) => {
                    warn!(
                        "Skipping starting_dns upstream '{}' ({}): {}",
                        i, addr, e
                    );
                }
            }
        }

        // Hostname → resolved IP cache so repeated hostnames only resolve once.
        let mut resolved: HashMap<String, IpAddr> = HashMap::new();

        for group in &self.config.groups {
            for entry in &group.upstream {
                let key = format!("{}__{}", group.name, entry.label);
                match build_upstream_pool(&entry.address, &bootstrap_pools, &mut resolved).await {
                    Some(pool) => {
                        self.upstream_pools.insert(key, Arc::new(pool));
                    }
                    None => {
                        warn!(
                            "Skipping DNS upstream '{}' ({}): failed to parse or resolve",
                            entry.label, entry.address
                        );
                    }
                }
            }
        }

        self.upstream_pools.extend(bootstrap_pools);

        info!(
            "DNS upstream pools initialized: {} total",
            self.upstream_pools.len()
        );
        Ok(())
    }

    /// Start the DNS listener
    pub async fn start(&mut self) -> anyhow::Result<()> {
        if self.running {
            warn!("DNS manager already running");
            return Ok(());
        }

        let bind_addr: SocketAddr = self.config.bind.parse().map_err(|e| {
            anyhow::anyhow!("invalid DNS bind address '{}': {}", self.config.bind, e)
        })?;

        let config = self.config.clone();
        let upstream_pools = Arc::new(
            self.upstream_pools
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<HashMap<_, _>>(),
        );
        let cache = self.cache.clone();
        let router = self.router.clone();

        let mut listener = DnsListener::new(
            bind_addr,
            config,
            upstream_pools,
            cache,
            router,
            self.on_resolve.clone(),
            self.rule_set_cache.clone(),
            self.dialers.clone(),
        );
        listener.start().await?;
        self.listener = Some(listener);
        self.running = true;

        info!("DNS manager started, listening on {}", bind_addr);
        Ok(())
    }

    /// Stop the DNS listener
    pub async fn stop(&mut self) -> anyhow::Result<()> {
        if let Some(mut listener) = self.listener.take() {
            listener.stop().await?;
        }
        self.running = false;
        info!("DNS manager stopped");
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.running
    }
}

/// Build an upstream pool for an upstream URL.
///
/// IP-literal addresses are used directly. Hostnames are resolved through the
/// bootstrap (`starting_dns`) pools; returns `None` if resolution fails so the
/// caller can skip the entry instead of aborting.
async fn build_upstream_pool(
    url: &str,
    bootstrap_pools: &HashMap<String, Arc<DnsUpstreamPool>>,
    resolved: &mut HashMap<String, IpAddr>,
) -> Option<DnsUpstreamPool> {
    use crate::dns::upstream::{parse_dns_url_parts, DnsUpstreamPool};
    use std::net::{IpAddr, SocketAddr};

    let parts = parse_dns_url_parts(url).ok()?;

    // IP literal → use directly
    if let Ok(ip) = parts.host.parse::<IpAddr>() {
        return Some(DnsUpstreamPool::new_with_addr(
            parts.transport,
            SocketAddr::new(ip, parts.port),
        ));
    }

    // Hostname → resolve once via bootstrap, then reuse the cached IP
    let ip = if let Some(ip) = resolved.get(&parts.host) {
        *ip
    } else {
        let ip = resolve_via_bootstrap(&parts.host, bootstrap_pools).await?;
        resolved.insert(parts.host.clone(), ip);
        ip
    };

    Some(DnsUpstreamPool::new_with_addr(
        parts.transport,
        SocketAddr::new(ip, parts.port),
    ))
}

/// Resolve `hostname` to an IP using the available bootstrap pools.
///
/// Queries A records first, then AAAA, trying each bootstrap pool in turn.
/// The bootstrap sockets carry SO_MARK=0x100, so the queries bypass the eBPF
/// proxy pipeline (no hijack loop).
async fn resolve_via_bootstrap(
    hostname: &str,
    bootstrap_pools: &HashMap<String, Arc<DnsUpstreamPool>>,
) -> Option<IpAddr> {
    use crate::dns::upstream::{build_dns_query, parse_answers_for_addr};

    let pools: Vec<Arc<DnsUpstreamPool>> = bootstrap_pools.values().cloned().collect();
    if pools.is_empty() {
        return None;
    }

    let a_query = build_dns_query(hostname, 1);
    let aaaa_query = build_dns_query(hostname, 28);
    for pool in &pools {
        if let Ok(resp) = pool.query(&a_query).await {
            if let Some(ip) = parse_answers_for_addr(&resp).first() {
                return Some(*ip);
            }
        }
    }
    for pool in &pools {
        if let Ok(resp) = pool.query(&aaaa_query).await {
            if let Some(ip) = parse_answers_for_addr(&resp).first() {
                return Some(*ip);
            }
        }
    }

    None
}
