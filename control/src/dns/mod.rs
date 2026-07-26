pub mod upstream;
pub mod cache;
pub mod router;
pub mod handler;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::config::DnsConfig;
use crate::dns::upstream::DnsUpstreamPool;
use crate::dns::cache::DnsCache;
use crate::dns::router::DnsRouter;
use crate::dns::handler::DnsListener;

/// DNS Manager — main orchestrator for DNS operations
pub struct DnsManager {
    /// Configuration
    config: DnsConfig,
    /// Upstream connection pool (label -> pool)
    upstream_pools: HashMap<String, Arc<DnsUpstreamPool>>,
    /// DNS response cache
    cache: Arc<RwLock<DnsCache>>,
    /// DNS router (request matching)
    router: DnsRouter,
    /// DNS listener (UDP + TCP)
    listener: Option<DnsListener>,
    /// Whether the manager is running
    running: bool,
}

impl DnsManager {
    pub fn new(config: DnsConfig) -> Self {
        let router = DnsRouter::new(&config);
        let cache = Arc::new(RwLock::new(DnsCache::new(&config.cache)));

        Self {
            config,
            upstream_pools: HashMap::new(),
            cache,
            router,
            listener: None,
            running: false,
        }
    }

    /// Initialize upstream pools for all DNS groups
    pub fn init_upstreams(&mut self) -> anyhow::Result<()> {
        // Create pools for starting_dns upstreams
        for entry in &self.config.starting_dns.upstream {
            let pool = DnsUpstreamPool::new(&entry.address)?;
            self.upstream_pools
                .insert(format!("__starting__{}", entry.label), Arc::new(pool));
        }

        // Create pools for each DNS group's upstreams
        for group in &self.config.groups {
            for entry in &group.upstream {
                let pool = DnsUpstreamPool::new(&entry.address)?;
                self.upstream_pools
                    .insert(format!("{}__{}", group.name, entry.label), Arc::new(pool));
            }
        }

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

        let mut listener = DnsListener::new(bind_addr, config, upstream_pools, cache, router);
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
