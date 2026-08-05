use anyhow::Context;
use futures::future::select_ok;
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, info, warn};

use protocols::OutboundDialer;
use crate::dns::upstream::query_dns_via_proxy;
use crate::ruleset::cache::RuleSetCache;
use crate::ruleset::refparse::{match_qname_value, parse_ref, RuleSetRef};

// ============================================================================
// Linux socket option constants for IP_TRANSPARENT
// ============================================================================

/// `IP_TRANSPARENT` socket option value (Linux).
/// Allows a socket to bind to a non-local address and send responses with a
/// source address that does not belong to the local machine.
/// Requires `CAP_NET_ADMIN` capability.
const IP_TRANSPARENT: libc::c_int = 19;

/// `IPV6_TRANSPARENT` socket option value (Linux).
/// IPv6 variant of IP_TRANSPARENT.
const IPV6_TRANSPARENT: libc::c_int = 75;

/// `SO_MARK` socket option value (Linux).
/// Used to mark dae-rs's own traffic so the eBPF program recognizes it as
/// control plane traffic and lets it pass without proxy interception.
const SO_MARK: libc::c_int = 36;

/// Maximum time to wait for a full TCP DNS request to arrive.
///
/// Bounds the per-connection reads so a half-open connection (a peer that
/// connects but never sends a complete request) is reaped instead of blocking
/// its task forever. Without this, each half-open connection leaks one tokio
/// task + one TCP fd monotonically until the fd table is exhausted — at which
/// point every DNS query fails (each UDP response allocates a fresh socket),
/// i.e. "DNS dies after long uptime".
const TCP_DNS_READ_TIMEOUT: Duration = Duration::from_secs(10);

use crate::config::DnsConfig;
use crate::dns::cache::{CacheLookup, DnsCache};
use crate::dns::router::{DnsResponseAction, DnsRouter};
use crate::dns::upstream::DnsUpstreamPool;

/// Callback invoked on each accepted DNS resolution (domain, ip, ttl).
/// Used to feed the domain_routing_map eBPF map for domain-based routing.
pub type DnsResolveCallback = Arc<dyn Fn(&str, IpAddr, u32) + Send + Sync>;

/// Singleflight key: (DNS group, qname, qtype). Concurrent identical queries
/// (same group + name + type) share a single upstream lookup.
type InflightKey = (String, String, u16);

/// Singleflight result. `Arc<anyhow::Error>` makes the value `Clone` so waiters
/// can copy it out of the watch channel.
type InflightResult = Result<Vec<u8>, Arc<anyhow::Error>>;

/// In-flight request deduplication map.
///
/// Key → watch sender. The first query for a key becomes the "leader" and
/// inserts its sender; concurrent identical queries subscribe and wait for the
/// leader's result instead of querying upstream again (prevents cache stampede).
type InflightMap =
    std::sync::Mutex<std::collections::HashMap<InflightKey, tokio::sync::watch::Sender<InflightResult>>>;

/// Keys currently being background-refreshed (dedup for refresh tasks).
type RefreshSet = std::sync::Mutex<std::collections::HashSet<InflightKey>>;

/// Try to join an in-flight query for `key`.
///
/// Returns `Some(receiver)` if another query with the same key is in progress
/// (caller should await the result), `None` if this query becomes the leader
/// (caller must insert its own result via [`notify_inflight`]).
fn try_join_inflight(
    inflight: &Arc<InflightMap>,
    key: &InflightKey,
) -> Option<tokio::sync::watch::Receiver<InflightResult>> {
    let mut map = inflight.lock().unwrap();
    if let Some(tx) = map.get(key) {
        Some(tx.subscribe())
    } else {
        let (tx, _rx) = tokio::sync::watch::channel::<InflightResult>(Err(Arc::new(
            anyhow::anyhow!("pending"),
        )));
        map.insert(key.clone(), tx);
        None
    }
}

/// Remove the in-flight entry for `key` and publish `result` to waiters.
fn notify_inflight(
    inflight: &Arc<InflightMap>,
    key: &InflightKey,
    result: anyhow::Result<Vec<u8>>,
) {
    if let Some(tx) = inflight.lock().unwrap().remove(key) {
        let _ = tx.send(result.map_err(Arc::new));
    }
}

/// RAII guard for the singleflight leader.
///
/// The leader MUST publish a result before returning (otherwise waiters hang on
/// `rx.changed()`). This guard publishes the result on Drop if the leader
/// hasn't notified explicitly (covers early returns and `?` error paths).
struct LeaderNotify {
    inflight: Arc<InflightMap>,
    key: InflightKey,
    defused: bool,
}

impl LeaderNotify {
    /// Publish `result` to waiters (idempotent).
    fn notify(&mut self, result: anyhow::Result<Vec<u8>>) {
        if !self.defused {
            self.defused = true;
            notify_inflight(&self.inflight, &self.key, result);
        }
    }
}

impl Drop for LeaderNotify {
    fn drop(&mut self) {
        if !self.defused {
            notify_inflight(
                &self.inflight,
                &self.key,
                Err(anyhow::anyhow!("singleflight leader dropped")),
            );
        }
    }
}

/// DNS Listener — handles incoming DNS queries (UDP + TCP)
pub struct DnsListener {
    /// Bind address
    bind_addr: SocketAddr,
    /// DNS configuration
    config: DnsConfig,
    /// Upstream pools (key: "group__label" -> pool)
    upstream_pools: Arc<HashMap<String, Arc<DnsUpstreamPool>>>,
    /// DNS response cache
    cache: Arc<tokio::sync::RwLock<DnsCache>>,
    /// DNS router
    router: DnsRouter,
    /// UDP listener task handle
    udp_handle: Option<tokio::task::JoinHandle<()>>,
    /// TCP listener task handle
    tcp_handle: Option<tokio::task::JoinHandle<()>>,
    /// Shutdown signal sender
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// Callback invoked on each accepted DNS resolution (domain, ip, ttl).
    /// Feeds the domain_routing_map eBPF map for domain-based routing.
    on_resolve: Option<DnsResolveCallback>,
    /// Ruleset in-memory cache (for DNS response Routing `ip(geoip:/set:)` / `qname(geosite:/set:)` evaluation).
    rule_set_cache: RuleSetCache,
    /// Outbound dialers keyed by proxy **group name**, used for proxied DNS
    /// upstream queries (`send_by` names an outbound group).
    dialers: HashMap<String, Arc<dyn OutboundDialer>>,
    /// In-flight request deduplication map (singleflight).
    inflight: Arc<InflightMap>,
    /// Keys currently being background-refreshed (dedup for refresh tasks).
    refreshing: Arc<std::sync::Mutex<std::collections::HashSet<InflightKey>>>,
}

impl DnsListener {
    pub fn new(
        bind_addr: SocketAddr,
        config: DnsConfig,
        upstream_pools: Arc<HashMap<String, Arc<DnsUpstreamPool>>>,
        cache: Arc<tokio::sync::RwLock<DnsCache>>,
        router: DnsRouter,
        on_resolve: Option<DnsResolveCallback>,
        rule_set_cache: RuleSetCache,
        dialers: HashMap<String, Arc<dyn OutboundDialer>>,
    ) -> Self {
        Self {
            bind_addr,
            config,
            upstream_pools,
            cache,
            router,
            udp_handle: None,
            tcp_handle: None,
            shutdown_tx: None,
            on_resolve,
            rule_set_cache,
            dialers,
            inflight: Arc::new(InflightMap::default()),
            refreshing: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        }
    }

    /// Start UDP and TCP DNS listeners.
    ///
    /// Binds with SO_REUSEADDR to handle rapid restart without TIME_WAIT conflicts.
    /// Also creates an additional listener on 169.254.0.1:port for cross-namespace
    /// DNS forwarding from the TProxy (which runs in the proxy namespace daens).
    pub async fn start(&mut self) -> anyhow::Result<()> {
        let start = std::time::Instant::now();
        let (shutdown_tx, _shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        self.shutdown_tx = Some(shutdown_tx);

        let bind = self.bind_addr;
        let config = Arc::new(self.config.clone());
        let upstream_pools = self.upstream_pools.clone();
        let cache = self.cache.clone();
        let router = Arc::new(self.router.clone());
        let on_resolve = self.on_resolve.clone();
        let rule_set_cache = self.rule_set_cache.clone();
        let inflight = self.inflight.clone();
        let refreshing = self.refreshing.clone();

        debug!(bind = %bind, "DNS listener starting");

        // UDP listener: bind with SO_REUSEADDR so rapid restart works
        let udp_socket = bind_udp_with_reuseaddr(bind).await.map_err(|e| {
            anyhow::anyhow!("failed to bind DNS UDP listener on {}: {}", bind, e)
        })?;
        debug!("DNS UDP listener bound to {}", bind);
        let u_dialers = self.dialers.clone();
        let u_config = config.clone();
        let u_pools = upstream_pools.clone();
        let u_cache = cache.clone();
        let u_router = router.clone();
        let u_on_resolve = on_resolve.clone();
        let u_ruleset = rule_set_cache.clone();
        let u_inflight = inflight.clone();
        let u_refreshing = refreshing.clone();
        let udp_handle = tokio::spawn(async move {
            run_udp_listener(
                udp_socket,
                u_config,
                u_pools,
                u_cache,
                u_router,
                u_on_resolve,
                u_ruleset,
                u_dialers,
                u_inflight,
                u_refreshing,
            )
            .await;
        });
        self.udp_handle = Some(udp_handle);

        // TCP listener: bind with SO_REUSEADDR
        let tcp_listener = bind_tcp_with_reuseaddr(bind).await.map_err(|e| {
            anyhow::anyhow!("failed to bind DNS TCP listener on {}: {}", bind, e)
        })?;
        let tcp_dialers = self.dialers.clone();
        let tcp_inflight = inflight.clone();
        let tcp_refreshing = refreshing.clone();
        let tcp_handle = tokio::spawn(async move {
            run_tcp_listener(
                tcp_listener,
                config,
                upstream_pools,
                cache,
                router,
                on_resolve,
                rule_set_cache,
                tcp_dialers,
                tcp_inflight,
                tcp_refreshing,
            )
            .await;
        });
        self.tcp_handle = Some(tcp_handle);

        debug!(
            "DNS listener started on {} ({}ms)",
            bind,
            start.elapsed().as_millis()
        );
        info!("DNS listener started on {} (UDP + TCP)", bind);

        // Create an additional UDP listener on 169.254.0.1:port for cross-namespace
        // DNS forwarding. The TProxy runs in the proxy NS (daens) and forwards DNS
        // queries intercepted by eBPF to this address instead of going through SOCKS5.
        // 169.254.0.1 is assigned to the host's dae0 interface, reachable from daens
        // via the veth pair.
        let internal_addr: SocketAddr = format!("169.254.0.1:{}", bind.port())
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid internal DNS address: {}", e))?;
        debug!("DNS internal listener address: {}", internal_addr);
        match bind_udp_with_reuseaddr(internal_addr).await {
            Ok(internal_socket) => {
                let i_dialers = self.dialers.clone();
                let i_config = Arc::new(self.config.clone());
                let i_pools = self.upstream_pools.clone();
                let i_cache = self.cache.clone();
                let i_router = Arc::new(self.router.clone());
                let i_on_resolve = self.on_resolve.clone();
                let i_ruleset = self.rule_set_cache.clone();
                let i_inflight = inflight.clone();
                let i_refreshing = refreshing.clone();
                tokio::spawn(async move {
                    run_udp_listener(
                        internal_socket,
                        i_config,
                        i_pools,
                        i_cache,
                        i_router,
                        i_on_resolve,
                        i_ruleset,
                        i_dialers,
                        i_inflight,
                        i_refreshing,
                    )
                    .await;
                });
                info!(
                    "DNS internal listener started on {} for cross-namespace forwarding",
                    internal_addr
                );
            }
            Err(e) => {
                warn!(
                    "Failed to bind DNS internal listener on {}: {} (cross-namespace DNS may not work)",
                    internal_addr, e
                );
            }
        }

        // TCP cross-namespace listener: receives DNS-over-TCP sessions forwarded
        // by the TProxy TCP DNS hijack (orig_dst port 53). Same address family
        // (IPv4 169.254.0.1) as the UDP internal listener.
        match bind_tcp_with_reuseaddr(internal_addr).await {
            Ok(internal_tcp) => {
                let t_dialers = self.dialers.clone();
                let t_config = Arc::new(self.config.clone());
                let t_pools = self.upstream_pools.clone();
                let t_cache = self.cache.clone();
                let t_router = Arc::new(self.router.clone());
                let t_on_resolve = self.on_resolve.clone();
                let t_ruleset = self.rule_set_cache.clone();
                let t_inflight = inflight.clone();
                let t_refreshing = refreshing.clone();
                tokio::spawn(async move {
                    run_tcp_listener(
                        internal_tcp,
                        t_config,
                        t_pools,
                        t_cache,
                        t_router,
                        t_on_resolve,
                        t_ruleset,
                        t_dialers,
                        t_inflight,
                        t_refreshing,
                    )
                    .await;
                });
                info!(
                    "DNS internal TCP listener started on {} for cross-namespace forwarding",
                    internal_addr
                );
            }
            Err(e) => {
                warn!(
                    "Failed to bind DNS internal TCP listener on {}: {} (TCP DNS hijack may not work)",
                    internal_addr, e
                );
            }
        }

        Ok(())
    }

    /// Stop the DNS listener.
    ///
    /// Uses abort() instead of cooperative cancellation because the listener
    /// tasks run infinite recv/accept loops and never check for shutdown signals.
    /// Abort is safe: tokio tasks are cancel-safe at await points.
    pub async fn stop(&mut self) -> anyhow::Result<()> {
        if let Some(handle) = self.udp_handle.take() {
            handle.abort();
            let _ = handle.await;
        }
        if let Some(handle) = self.tcp_handle.take() {
            handle.abort();
            let _ = handle.await;
        }
        info!("DNS listener stopped");
        Ok(())
    }
}

/// Run the UDP DNS listener
///
/// Receives incoming DNS queries and spawns a task per query.
/// The response socket with IP_TRANSPARENT is created inside [`handle_dns_query`]
/// after determining the upstream DNS server address, so the response appears
/// to originate from the upstream DNS server rather than the local listener.
async fn run_udp_listener(
    socket: UdpSocket,
    config: Arc<DnsConfig>,
    upstream_pools: Arc<HashMap<String, Arc<DnsUpstreamPool>>>,
    cache: Arc<tokio::sync::RwLock<DnsCache>>,
    router: Arc<DnsRouter>,
    on_resolve: Option<DnsResolveCallback>,
    rule_set_cache: RuleSetCache,
    dialers: HashMap<String, Arc<dyn OutboundDialer>>,
    inflight: Arc<InflightMap>,
    refreshing: Arc<RefreshSet>,
) {
    let mut buf = vec![0u8; 4096];
    loop {
        let result = socket.recv_from(&mut buf).await;
        let (len, src) = match result {
            Ok(v) => v,
            Err(e) => {
                warn!("DNS UDP recv error: {}", e);
                continue;
            }
        };
        let request = buf[..len].to_vec();
        // Info-level log for DNS queries arriving from the TProxy cross-namespace
        // path (source is NOT 127.0.0.1). This lets operators see whether hijacked
        // DNS queries actually reach the handler, without spamming for localhost
        // clients that talk to the bind address directly.
        if src.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) {
            info!(
                "DNS query received from {} on {}: {} bytes",
                src,
                socket.local_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into()),
                len
            );
        } else {
            debug!(
                "DNS query received from {}: {} bytes",
                src, len
            );
        }
        let config = config.clone();
        let upstream_pools = upstream_pools.clone();
        let cache = cache.clone();
        let router = router.clone();
        let on_resolve = on_resolve.clone();
        let rule_set_cache = rule_set_cache.clone();
        let dialers = dialers.clone();
        let inflight = inflight.clone();
        let refreshing = refreshing.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_dns_query(
                src,
                &request,
                &config,
                &upstream_pools,
                &cache,
                &router,
                &on_resolve,
                &rule_set_cache,
                dialers,
                inflight,
                refreshing,
            )
            .await
            {
                warn!("DNS query handling failed: {}", e);
            }
        });
    }
}

/// Run the TCP DNS listener
async fn run_tcp_listener(
    listener: TcpListener,
    config: Arc<DnsConfig>,
    upstream_pools: Arc<HashMap<String, Arc<DnsUpstreamPool>>>,
    cache: Arc<tokio::sync::RwLock<DnsCache>>,
    router: Arc<DnsRouter>,
    on_resolve: Option<DnsResolveCallback>,
    rule_set_cache: RuleSetCache,
    dialers: HashMap<String, Arc<dyn OutboundDialer>>,
    inflight: Arc<InflightMap>,
    refreshing: Arc<RefreshSet>,
) {
    loop {
        let result = listener.accept().await;
        let (stream, _src) = match result {
            Ok(v) => v,
            Err(e) => {
                warn!("DNS TCP accept error: {}", e);
                continue;
            }
        };
        let config = config.clone();
        let upstream_pools = upstream_pools.clone();
        let cache = cache.clone();
        let router = router.clone();
        let on_resolve = on_resolve.clone();
        let rule_set_cache = rule_set_cache.clone();
        let dialers = dialers.clone();
        let inflight = inflight.clone();
        let refreshing = refreshing.clone();

        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let mut stream = stream;

            // Serve multiple length-prefixed queries per connection (RFC 7766
            // persistent connections). Previously this was one-shot: a single
            // query was read, answered, and the connection was dropped.
            // Dropping a TCP socket that still has unread data in its receive
            // buffer makes the kernel send an RST instead of a FIN, and
            // clients that reuse/pipeline the connection (e.g.
            // systemd-resolved's TCP queries to the router DNS) saw
            // "Connection reset by peer" and the resolution failed.
            loop {
                // TCP DNS: 2-byte length prefix, read exactly.
                // Bound by TCP_DNS_READ_TIMEOUT so a peer that connects but never
                // sends a length prefix cannot block this task forever.
                let mut len_buf = [0u8; 2];
                match tokio::time::timeout(TCP_DNS_READ_TIMEOUT, stream.read_exact(&mut len_buf))
                    .await
                {
                    Ok(Ok(_)) => {}
                    // EOF / reset / timeout: the client is done with this connection.
                    Ok(Err(e)) => {
                        debug!(peer = %_src, error = %e, "TCP DNS read length failed; closing connection");
                        break;
                    }
                    Err(_) => {
                        debug!("TCP DNS read length timed out");
                        break;
                    }
                }
                let msg_len = u16::from_be_bytes(len_buf) as usize;
                if msg_len == 0 || msg_len > 4096 {
                    debug!(msg_len, "TCP DNS invalid message length; closing connection");
                    break;
                }

                // Read message body exactly (bounded by the same timeout)
                let mut request = vec![0u8; msg_len];
                match tokio::time::timeout(TCP_DNS_READ_TIMEOUT, stream.read_exact(&mut request))
                    .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        debug!(peer = %_src, error = %e, "TCP DNS read body failed; closing connection");
                        break;
                    }
                    Err(_) => {
                        debug!("TCP DNS read body timed out");
                        break;
                    }
                }

                debug!(
                    peer = %_src,
                    msg_len = msg_len,
                    "DNS TCP query received"
                );

                if let Ok((response, _upstream_addr)) = handle_dns_internal(
                    &request,
                    &config,
                    &upstream_pools,
                    &cache,
                    &router,
                    &on_resolve,
                    &rule_set_cache,
                    &dialers,
                    &inflight,
                    &refreshing,
                    false,
                )
                .await
                {
                    // Write response with length prefix. write_all (with a
                    // timeout) must be used instead of try_write: a partial
                    // write or WouldBlock must not silently drop the response.
                    let resp_len = (response.len() as u16).to_be_bytes();
                    let mut framed = Vec::with_capacity(2 + response.len());
                    framed.extend_from_slice(&resp_len);
                    framed.extend_from_slice(&response);

                    if tokio::time::timeout(TCP_DNS_READ_TIMEOUT, stream.write_all(&framed))
                        .await
                        .is_err()
                    {
                        debug!("TCP DNS write timed out; closing connection");
                        break;
                    }
                }
            }

            // Graceful half-close: flush pending data and send FIN. Draining
            // any remaining unread data first prevents the socket drop from
            // emitting an RST (which surfaces as "Connection reset by peer"
            // in the TProxy TCP DNS relay).
            let _ = stream.shutdown().await;
            let _ = tokio::time::timeout(Duration::from_millis(500), async {
                let mut drain = [0u8; 4096];
                loop {
                    match stream.read(&mut drain).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => continue,
                    }
                }
            })
            .await;
        });
    }
}

/// Handle a single DNS query (from UDP)
///
/// Processes the query via [`handle_dns_internal`], then creates an
/// `IP_TRANSPARENT` UDP socket bound to the upstream DNS server's address
/// to send the response. This ensures the response's source address matches
/// the upstream DNS server that the client originally queried, rather than
/// the local DNS listener address (e.g. 169.254.0.1:5353).
///
/// For cached responses (where no upstream address is available), a regular
/// marked socket bound to an ephemeral port is used as fallback.
async fn handle_dns_query(
    src: SocketAddr,
    request: &[u8],
    config: &Arc<DnsConfig>,
    upstream_pools: &HashMap<String, Arc<DnsUpstreamPool>>,
    cache: &Arc<tokio::sync::RwLock<DnsCache>>,
    router: &Arc<DnsRouter>,
    on_resolve: &Option<DnsResolveCallback>,
    rule_set_cache: &RuleSetCache,
    dialers: HashMap<String, Arc<dyn OutboundDialer>>,
    inflight: Arc<InflightMap>,
    refreshing: Arc<RefreshSet>,
) -> anyhow::Result<()> {
    let (response, upstream_addr) = handle_dns_internal(
        request,
        config,
        upstream_pools,
        cache,
        router,
        on_resolve,
        rule_set_cache,
        &dialers,
        &inflight,
        &refreshing,
        false,
    )
    .await?;

    // Determine the bind address for the response socket:
    // - Upstream query result: bind to the upstream DNS server address with IP_TRANSPARENT
    //   so the response appears to come from the DNS server the client queried.
    // - Cache hit (None): bind to ephemeral port as fallback.
    let mut bind_addr = upstream_addr.unwrap_or_else(|| {
        // Fallback: ephemeral address (0.0.0.0:0). The kernel assigns a local
        // source address. This is the same behavior as before IP_TRANSPARENT support.
        ([0u8; 4], 0u16).into()
    });
    // The response socket must share the address family of the client `src`,
    // otherwise send_to() fails (an AF_INET6 socket cannot send_to an IPv4
    // address, EAFNOSUPPORT) and the response is silently lost. This happens
    // when the upstream is IPv6 while the client is IPv4 on the internal
    // 169.254.0.1 handler path (and vice versa). Fall back to an ephemeral
    // bind in the client's family in that case.
    if bind_addr.is_ipv6() != src.is_ipv6() {
        bind_addr = if src.is_ipv6() {
            ([0u16; 8], 0u16).into()
        } else {
            ([0u8; 4], 0u16).into()
        };
    }

    let resp_socket = create_marked_udp_socket_for_dns(bind_addr, shared::DAE_SOCKET_MARK).await
        .ok_or_else(|| anyhow::anyhow!(
            "failed to create IP_TRANSPARENT socket for DNS response (bind={})",
            bind_addr
        ))?;

    resp_socket.send_to(&response, src).await?;
    debug!(
        src = %src,
        upstream = %upstream_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "cache".into()),
        resp_len = response.len(),
        "DNS response sent"
    );
    Ok(())
}

/// Internal DNS query processing
///
/// Returns the DNS response bytes along with the upstream server address used
/// (if any). The upstream address is needed by [`handle_dns_query`] to create
/// an `IP_TRANSPARENT` socket so the response appears to come from the correct
/// upstream DNS server.
///
/// Returns `None` for the upstream address when the response came from cache
/// (no upstream was contacted), in which case the caller should use a fallback
/// source address.
///
/// Queries all upstreams in the selected DNS group concurrently and returns
/// the first successful response. When `send_by` is a proxy group name, the
/// upstream queries are sent through that proxy; when `send_by` is `"direct"`,
/// they are sent directly.
async fn handle_dns_internal(
    request: &[u8],
    config: &Arc<DnsConfig>,
    upstream_pools: &HashMap<String, Arc<DnsUpstreamPool>>,
    cache: &Arc<tokio::sync::RwLock<DnsCache>>,
    router: &Arc<DnsRouter>,
    on_resolve: &Option<DnsResolveCallback>,
    rule_set_cache: &RuleSetCache,
    dialers: &HashMap<String, Arc<dyn OutboundDialer>>,
    inflight: &Arc<InflightMap>,
    refreshing: &Arc<RefreshSet>,
    skip_cache: bool,
) -> anyhow::Result<(Vec<u8>, Option<SocketAddr>)> {
    // Parse query name and type
    let (qname, qtype) = parse_dns_question(request);

    // Route to group (needed for the per-group cache partition)
    let route = router.match_query(&qname, qtype);
    debug!(
        qname = %qname,
        qtype,
        group = %route.group.name,
        send_by = %route.send_by.as_deref().unwrap_or("direct"),
        query_mode = %query_mode_label(route.group.query_mode),
        "DNS query routed"
    );
    if route.group.name == "null" || route.group.upstream.is_empty() {
        return Ok((build_empty_response(request), None));
    }
    let group_name = route.group.name.clone();

    // Check cache (per DNS group partition). Background refresh calls this with
    // `skip_cache = true` so it always queries upstream for fresh data.
    let cache_key = DnsCache::cache_key(&qname, qtype, 1); // class IN = 1
    if !skip_cache {
        let cache_guard = cache.read().await;
        match cache_guard.lookup_state(&group_name, cache_key) {
            Some(CacheLookup::Fresh {
                bytes,
                elapsed_secs,
                remaining_ttl,
            }) => {
                debug!("DNS cache hit: {} type={} group={}", qname, qtype, group_name);
                let mut response = bytes.to_vec();
                // Patch transaction ID to match the current query — DNS clients
                // discard responses whose ID doesn't match the outstanding query.
                if response.len() >= 2 && request.len() >= 2 {
                    response[0..2].copy_from_slice(&request[0..2]);
                }
                // RFC 1035 §5.2: decrement TTLs by residence time so the cached
                // reply reports its true remaining lifetime.
                if elapsed_secs > 0 {
                    crate::dns::upstream::patch_ttls(&mut response, elapsed_secs);
                }
                // Background refresh: kick an async re-query when the entry is
                // nearing expiry so the next lookup finds fresh data.
                if config.cache.background_refresh
                    && config.cache.refresh_threshold_percent > 0
                {
                    let threshold = (remaining_ttl as u64
                        * config.cache.refresh_threshold_percent as u64)
                        / 100;
                    if remaining_ttl <= threshold as u32 {
                        debug!(
                            "DNS background refresh trigger: {} type={} remaining={} threshold={}",
                            qname, qtype, remaining_ttl, threshold
                        );
                        spawn_background_refresh(
                            refreshing,
                            request.to_vec(),
                            (group_name.clone(), qname.clone(), qtype),
                            config.clone(),
                            upstream_pools,
                            cache,
                            router,
                            on_resolve,
                            rule_set_cache,
                            dialers,
                            inflight,
                        );
                    }
                }
                return Ok((response, None));
            }
            Some(CacheLookup::Stale { bytes }) => {
                // RFC 8767 serve-stale: return the expired entry with a short
                // TTL and refresh in the background.
                warn!(
                    "DNS serve-stale: {} type={} group={} (upstream refresh kicked)",
                    qname, qtype, group_name
                );
                let mut response = bytes.to_vec();
                if response.len() >= 2 && request.len() >= 2 {
                    response[0..2].copy_from_slice(&request[0..2]);
                }
                crate::dns::upstream::set_all_ttls(
                    &mut response,
                    config.cache.serve_stale_ttl.max(1),
                );
                spawn_background_refresh(
                    refreshing,
                    request.to_vec(),
                    (group_name.clone(), qname.clone(), qtype),
                    config.clone(),
                    upstream_pools,
                    cache,
                    router,
                    on_resolve,
                    rule_set_cache,
                    dialers,
                    inflight,
                );
                return Ok((response, None));
            }
            None => {}
        }
    }

    // Singleflight: if an identical query is already in flight, wait for its
    // result instead of querying upstream again (prevents cache stampede when
    // many clients resolve the same name concurrently). Background refreshes
    // (`skip_cache`) skip this — they must always query upstream.
    let inflight_key: InflightKey = (group_name.clone(), qname.clone(), qtype);
    if !skip_cache {
        if let Some(mut rx) = try_join_inflight(inflight, &inflight_key) {
        // Fast path: leader already finished before we subscribed.
        if let Ok(resp) = (*rx.borrow()).clone() {
            debug!(
                "DNS singleflight join (already finished): {} type={} group={}",
                qname, qtype, group_name
            );
            let mut response = resp;
            if response.len() >= 2 && request.len() >= 2 {
                response[0..2].copy_from_slice(&request[0..2]);
            }
            return Ok((response, None));
        }
        // Wait for the leader's result.
        if rx.changed().await.is_ok() {
            match (*rx.borrow()).clone() {
                Ok(resp) => {
                    debug!(
                        "DNS singleflight join: {} type={} group={}",
                        qname, qtype, group_name
                    );
                    let mut response = resp;
                    if response.len() >= 2 && request.len() >= 2 {
                        response[0..2].copy_from_slice(&request[0..2]);
                    }
                    return Ok((response, None));
                }
                Err(e) => {
                    // Leader failed; share the failure rather than re-querying.
                    debug!("DNS singleflight leader failed ({}), returning SERVFAIL", e);
                    return Ok((build_empty_response(request), None));
                }
            }
        }
        // Channel closed without a value: leader vanished; fall through and
        // query upstream ourselves.
        debug!("DNS singleflight channel closed, querying upstream ourselves");
        }
    }

    // We are the leader for this query. Must publish a result before returning
    // so waiters don't hang.
    let mut leader =
        LeaderNotify {
            inflight: inflight.clone(),
            key: inflight_key,
            defused: false,
        };

    // Resolve the dialer for this group's `send_by` (an outbound group name).
    // None → direct connection; Some(d) → proxied through that group.
    let dialer: Option<&dyn OutboundDialer> = match &route.send_by {
        Some(group) => dialers.get(group).map(|d| d.as_ref()),
        None => None,
    };

    // Collect all upstreams in the group.
    // Each query yields (response, upstream_addr, upstream_label) so that
    // response routing can match `upstream(<label>)` against the actual
    // upstream that produced the winning response.
    let timeout = Duration::from_secs(5);
    let is_proxied = dialer.is_some();

    let mut candidates: Vec<(String, SocketAddr, Arc<DnsUpstreamPool>)> = Vec::new();
    for upstream in &route.group.upstream {
        let pool_key = format!("{}__{}", route.group.name, upstream.label);
        if let Some(pool) = upstream_pools.get(&pool_key) {
            candidates.push((upstream.label.clone(), pool.address(), pool.clone()));
        }
    }

    if candidates.is_empty() {
        warn!("DNS group '{}' has no available upstreams", route.group.name);
        let empty = build_empty_response(request);
        leader.notify(Ok(empty.clone()));
        return Ok((empty, None));
    }

    // Query one upstream candidate (direct or via proxy), returning
    // (response, upstream_addr, upstream_label).
    async fn query_one(
        is_proxied: bool,
        dialer: Option<&dyn OutboundDialer>,
        pool: &DnsUpstreamPool,
        upstream_addr: SocketAddr,
        upstream_label: String,
        request: &[u8],
        timeout: Duration,
    ) -> anyhow::Result<(Vec<u8>, SocketAddr, String)> {
        if is_proxied {
            let d = dialer.ok_or_else(|| {
                anyhow::anyhow!("DNS group has send_by configured but no dialer available")
            })?;
            let transport = pool.transport();
            debug!(
                upstream = %upstream_addr,
                label = %upstream_label,
                transport = ?transport,
                "DNS query via proxy started"
            );
            let resp = query_dns_via_proxy(d, upstream_addr, transport, request, timeout).await?;
            Ok((resp, upstream_addr, upstream_label))
        } else {
            debug!(
                upstream = %upstream_addr,
                label = %upstream_label,
                "DNS query direct started"
            );
            let resp = pool.query(request).await?;
            Ok((resp, upstream_addr, upstream_label))
        }
    }

    let query_mode = route.group.query_mode;
    let result = match query_mode {
        crate::config::DnsQueryMode::Concurrent => {
            let mut futures: Vec<
                std::pin::Pin<
                    Box<
                        dyn std::future::Future<
                                Output = anyhow::Result<(Vec<u8>, SocketAddr, String)>,
                            > + Send,
                    >,
                >,
            > = Vec::new();
            for (label, addr, pool) in &candidates {
                let req = request.to_vec();
                if is_proxied {
                    if let Some(d) = dialer {
                        let transport = pool.transport();
                        let label = label.clone();
                        let addr = *addr;
                        futures.push(Box::pin(async move {
                            let resp =
                                query_dns_via_proxy(d, addr, transport, &req, timeout).await?;
                            Ok::<_, anyhow::Error>((resp, addr, label))
                        }));
                    } else {
                        warn!(
                            "DNS group '{}' has send_by configured but no dialer available",
                            route.group.name
                        );
                    }
                } else {
                    let pool = pool.clone();
                    let label = label.clone();
                    let addr = *addr;
                    futures.push(Box::pin(async move {
                        let resp = pool.query(&req).await?;
                        Ok::<_, anyhow::Error>((resp, addr, label))
                    }));
                }
            }
            if futures.is_empty() {
                let empty = build_empty_response(request);
                leader.notify(Ok(empty.clone()));
                return Ok((empty, None));
            }
            match select_ok(futures).await {
                Ok((result, _remaining)) => Ok(result),
                Err(e) => Err(anyhow::anyhow!("all upstreams failed: {}", e)),
            }
        }
        crate::config::DnsQueryMode::Random => {
            // Pick one random candidate and query it.
            let idx = fastrand::usize(..candidates.len());
            let (label, addr, pool) = &candidates[idx];
            query_one(
                is_proxied,
                dialer,
                pool,
                *addr,
                label.clone(),
                request,
                timeout,
            )
            .await
        }
        crate::config::DnsQueryMode::Sequence => {
            // Try upstreams in order, use the first success.
            // The per-query timeout is a shared overall budget across ALL
            // upstreams, so the whole sequence never exceeds `timeout`. This
            // keeps the handler's worst-case response (including SERVFAIL)
            // within the tproxy DNS-hijack wait window; otherwise the response
            // arrives after that socket is dropped and is silently lost, and
            // the client sees a hard timeout instead of a SERVFAIL.
            let start = std::time::Instant::now();
            let mut last_err: Option<String> = None;
            let mut result: Option<anyhow::Result<(Vec<u8>, SocketAddr, String)>> = None;
            for (label, addr, pool) in &candidates {
                let remaining = timeout.saturating_sub(start.elapsed());
                if remaining.is_zero() {
                    break;
                }
                match query_one(
                    is_proxied,
                    dialer,
                    pool,
                    *addr,
                    label.clone(),
                    request,
                    remaining,
                )
                .await
                {
                    Ok(res) => {
                        result = Some(Ok(res));
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e.to_string());
                        continue;
                    }
                }
            }
            match result {
                Some(r) => r,
                None => Err(anyhow::anyhow!(
                    "all upstreams failed: {}",
                    last_err.unwrap_or_else(|| "no candidates".into())
                )),
            }
        }
    };

    let (response, upstream_addr, upstream_label) = match result {
        Ok(r) => r,
        Err(e) => {
            warn!("DNS group '{}' {} query failed: {}", route.group.name, query_mode_label(query_mode), e);
            let empty = build_empty_response(request);
            leader.notify(Ok(empty.clone()));
            return Ok((empty, None));
        }
    };

    // Apply the module-level response action against the upstream that actually
    // produced the winning response, so `upstream(<label>)` conditions match
    // correctly.
    let action = check_dns_response(
        &response,
        &qname,
        &config.response_action,
        &upstream_label,
        rule_set_cache,
    );

    match action {
        DnsResponseAction::Accept => {
            debug!(
                qname = %qname,
                qtype,
                group = %group_name,
                upstream = %upstream_label,
                ttl = extract_min_ttl(&response),
                "DNS response accepted"
            );
            // Cache the response
            let ttl = extract_min_ttl(&response);
            {
                let mut cache_guard = cache.write().await;
                cache_guard.insert(&group_name, cache_key, response.clone(), ttl);
            }
            // Feed accepted resolutions into the domain routing tracker so the
            // eBPF domain_routing_map is populated for domain-based routing.
            // NOTE: notify_resolve acquires the eBPF lock (see
            // add_dns_result_to_tracker). Do NOT hold the cache write lock while
            // taking it — an eBPF op stalled behind long-running map updates
            // would otherwise block every DNS query at the cache lock.
            notify_resolve(on_resolve, &qname, &response);
            leader.notify(Ok(response.clone()));
            Ok((response, Some(upstream_addr)))
        }
        DnsResponseAction::Reject => {
            debug!(
                qname = %qname,
                qtype,
                group = %group_name,
                upstream = %upstream_label,
                "DNS response rejected"
            );
            let empty = build_empty_response(request);
            leader.notify(Ok(empty.clone()));
            Ok((empty, Some(upstream_addr)))
        }
        DnsResponseAction::Requery(new_upstream) => {
            debug!(
                qname = %qname,
                qtype,
                group = %group_name,
                original_upstream = %upstream_label,
                new_upstream = %new_upstream,
                "DNS response action: requery"
            );
            let new_pool_key = format!("{}__{}", route.group.name, new_upstream);
            if let Some(new_pool) = upstream_pools.get(&new_pool_key) {
                let new_upstream_addr = new_pool.address();
                let response = if is_proxied {
                    if let Some(d) = dialer {
                        match query_dns_via_proxy(
                            d,
                            new_upstream_addr,
                            new_pool.transport(),
                            request,
                            timeout,
                        )
                        .await
                        {
                            Ok(resp) => resp,
                            Err(e) => {
                                warn!("DNS requery via proxy failed: {}", e);
                                let empty = build_empty_response(request);
                                leader.notify(Ok(empty.clone()));
                                return Ok((empty, None));
                            }
                        }
                    } else {
                        let empty = build_empty_response(request);
                        leader.notify(Ok(empty.clone()));
                        return Ok((empty, None));
                    }
                } else {
                    match new_pool.query(request).await {
                        Ok(resp) => resp,
                        Err(e) => {
                            warn!("DNS requery direct failed: {}", e);
                            let empty = build_empty_response(request);
                            leader.notify(Ok(empty.clone()));
                            return Ok((empty, None));
                        }
                    }
                };
                let ttl = extract_min_ttl(&response);
                {
                    let mut cache_guard = cache.write().await;
                    cache_guard.insert(&group_name, cache_key, response.clone(), ttl);
                }
                // Keep the cache write lock out of the eBPF lock path (see the
                // Accept branch above).
                notify_resolve(on_resolve, &qname, &response);
                leader.notify(Ok(response.clone()));
                Ok((response, Some(new_upstream_addr)))
            } else {
                // Fallback: accept original response
                let ttl = extract_min_ttl(&response);
                {
                    let mut cache_guard = cache.write().await;
                    cache_guard.insert(&group_name, cache_key, response.clone(), ttl);
                }
                // Keep the cache write lock out of the eBPF lock path (see the
                // Accept branch above).
                notify_resolve(on_resolve, &qname, &response);
                leader.notify(Ok(response.clone()));
                Ok((response, Some(upstream_addr)))
            }
        }
    }
}

/// Spawn an asynchronous background refresh for a cached entry.
///
/// Deduplicates concurrent refreshes for the same key. The task re-runs
/// [`handle_dns_internal`] with `skip_cache = true` so it always queries
/// upstream and re-populates the cache with fresh data.
#[allow(clippy::too_many_arguments)]
fn spawn_background_refresh(
    refreshing: &Arc<RefreshSet>,
    request: Vec<u8>,
    key: InflightKey,
    config: Arc<DnsConfig>,
    upstream_pools: &HashMap<String, Arc<DnsUpstreamPool>>,
    cache: &Arc<tokio::sync::RwLock<DnsCache>>,
    router: &Arc<DnsRouter>,
    on_resolve: &Option<DnsResolveCallback>,
    rule_set_cache: &RuleSetCache,
    dialers: &HashMap<String, Arc<dyn OutboundDialer>>,
    inflight: &Arc<InflightMap>,
) {
    // Dedup: skip if a refresh for this key is already in flight.
    {
        let mut set = refreshing.lock().unwrap();
        if !set.insert(key.clone()) {
            return;
        }
    }

    let refreshing = refreshing.clone();
    let upstream_pools = upstream_pools.clone();
    let cache = cache.clone();
    let router = router.clone();
    let on_resolve = on_resolve.clone();
    let rule_set_cache = rule_set_cache.clone();
    let dialers = dialers.clone();
    let inflight = inflight.clone();

    tokio::spawn(async move {
        debug!(
            group = %key.0,
            qname = %key.1,
            qtype = key.2,
            "DNS background refresh spawned"
        );
        let result = handle_dns_internal(
            &request,
            &config,
            &upstream_pools,
            &cache,
            &router,
            &on_resolve,
            &rule_set_cache,
            &dialers,
            &inflight,
            &refreshing,
            true, // skip_cache
        )
        .await;
        if let Err(e) = result {
            debug!("DNS background refresh failed for {:?}: {}", key, e);
        }
        refreshing.lock().unwrap().remove(&key);
    });
}

/// Return a human-readable label for a DNS group query mode (used in debug logs).
fn query_mode_label(mode: crate::config::DnsQueryMode) -> &'static str {
    match mode {
        crate::config::DnsQueryMode::Concurrent => "concurrent",
        crate::config::DnsQueryMode::Random => "random",
        crate::config::DnsQueryMode::Sequence => "sequence",
    }
}

/// Notify the domain routing callback for every A/AAAA record in an accepted response.
fn notify_resolve(
    on_resolve: &Option<DnsResolveCallback>,
    qname: &str,
    response: &[u8],
) {
    let Some(cb) = on_resolve.as_ref() else {
        return;
    };
    // Extract per-record TTLs alongside the IPs so the domain_routing_map entry
    // expires in sync with the DNS cache.
    for (ip, ttl) in extract_answer_addrs(response) {
        cb(qname, ip, ttl);
    }
}

/// Extract A/AAAA records from a DNS response: (IP, TTL) pairs.
fn extract_answer_addrs(response: &[u8]) -> Vec<(IpAddr, u32)> {
    use crate::dns::upstream::skip_question_section;

    if response.len() < 12 {
        return Vec::new();
    }
    let ancount = u16::from_be_bytes([response[6], response[7]]);
    if ancount == 0 {
        return Vec::new();
    }

    let mut pos = skip_question_section(response, 12);
    let mut out = Vec::new();

    for _ in 0..ancount {
        if pos >= response.len() {
            break;
        }
        pos = crate::dns::upstream::skip_name(response, pos);
        if pos + 10 > response.len() {
            break;
        }
        let rtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let ttl = u32::from_be_bytes([
            response[pos + 4],
            response[pos + 5],
            response[pos + 6],
            response[pos + 7],
        ]);
        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        let rdata_start = pos + 10;
        let rdata_end = rdata_start + rdlength;
        if rdata_end > response.len() {
            break;
        }
        let rdata = &response[rdata_start..rdata_end];
        match rtype {
            1 if rdata.len() == 4 => {
                out.push((
                    IpAddr::V4(std::net::Ipv4Addr::new(
                        rdata[0], rdata[1], rdata[2], rdata[3],
                    )),
                    ttl,
                ));
            }
            28 if rdata.len() == 16 => {
                let mut oct = [0u8; 16];
                oct.copy_from_slice(rdata);
                out.push((IpAddr::V6(std::net::Ipv6Addr::from(oct)), ttl));
            }
            _ => {}
        }
        pos = rdata_end;
    }

    out
}

/// Apply the module-level DNS response action to a response.
///
/// The action is configured at the `dns` level (not per-group) and applies to
/// the response of whichever group answered. Rules match against the response
/// and the answering upstream's label; actions are `accept`, `reject`, or an
/// upstream label to requery within the answering group.
fn check_dns_response(
    response: &[u8],
    qname: &str,
    response_action: &Option<crate::config::DnsResponseActionConfig>,
    upstream_label: &str,
    rule_set_cache: &RuleSetCache,
) -> DnsResponseAction {
    let Some(action_cfg) = response_action else {
        return DnsResponseAction::Accept;
    };

    // Check response rules
    for rule in &action_cfg.rules {
        let raw = rule.r#match.trim();
        let action = rule.action.trim();

        let matched =
            evaluate_response_condition(raw, qname, response, upstream_label, rule_set_cache);
        match action {
            "accept" => {
                if matched {
                    return DnsResponseAction::Accept;
                }
            }
            "reject" => {
                if matched {
                    return DnsResponseAction::Reject;
                }
            }
            requery_label => {
                // Requery with different upstream
                if matched {
                    return DnsResponseAction::Requery(requery_label.to_string());
                }
            }
        }
    }

    // Fallback
    match action_cfg.fallback.as_str() {
        "accept" => DnsResponseAction::Accept,
        "reject" => DnsResponseAction::Reject,
        upstream => DnsResponseAction::Requery(upstream.to_string()),
    }
}

/// Split condition expression by `&&` (DNS conditions have no parenthetical nesting, simple split suffices).
fn split_condition_and(expr: &str) -> Vec<&str> {
    expr.split("&&")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Split function arguments by comma (DNS condition arguments contain no nested parentheses).
fn split_condition_params(inner: &str) -> Vec<&str> {
    inner.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect()
}

/// Evaluate a single response condition.
///
/// Supports `&&` and `!` combinations (design §6.5 / §10.3): **AND** between atomic conditions, `!` negates.
///
/// Atomic conditions:
/// - `any` / `*` / empty → always true;
/// - `upstream(label)` → matches this upstream;
/// - `nocontent` → response has no answer;
/// - `ip(geoip:<code> / set:<name> / CIDR / bare IP)` → any A/AAAA address in response hits;
/// - `qname(geosite:<code> / set:<name> / normal Domain name pattern)` → query name hits.
///
/// Unknown conditions default to **return false and warn** (fixes "unimplemented always true" defect 5).
fn evaluate_response_condition(
    condition: &str,
    qname: &str,
    response: &[u8],
    upstream_label: &str,
    rule_set_cache: &RuleSetCache,
) -> bool {
    let parts = split_condition_and(condition);
    if parts.is_empty() {
        // Empty condition → always true (equivalent to any)
        return true;
    }
    for part in parts {
        let (negated, cond) = if let Some(stripped) = part.strip_prefix('!') {
            (true, stripped.trim())
        } else {
            (false, part)
        };
        let v = eval_atomic_condition(cond, qname, response, upstream_label, rule_set_cache);
        let result = if negated { !v } else { v };
        if !result {
            return false;
        }
    }
    true
}

/// Evaluate a single atomic condition (**without** NOT negation).
fn eval_atomic_condition(
    cond: &str,
    qname: &str,
    response: &[u8],
    upstream_label: &str,
    rule_set_cache: &RuleSetCache,
) -> bool {
    if cond.is_empty() || cond == "any" || cond == "*" {
        return true;
    }

    // upstream(label) — matches this actual upstream
    if let Some(label) = cond.strip_prefix("upstream(") {
        if let Some(label) = label.strip_suffix(')') {
            return label == upstream_label;
        }
    }

    // nocontent (NODATA)
    if cond == "nocontent" {
        if response.len() < 12 {
            return true;
        }
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        return ancount == 0;
    }

    // ip(...) — response address hits geoip/set/CIDR/bare IP
    if let Some(inner) = cond.strip_prefix("ip(") {
        if let Some(inner) = inner.strip_suffix(')') {
            let addrs = extract_answer_addrs(response);
            return eval_ip_condition(inner, &addrs, rule_set_cache);
        }
    }

    // qname(...) — query name hits geosite/set/normal Domain name pattern
    if let Some(inner) = cond.strip_prefix("qname(") {
        if let Some(inner) = inner.strip_suffix(')') {
            return eval_qname_condition(inner, qname, rule_set_cache);
        }
    }

    // Unknown condition → fix "always true" defect: default false and warn
    warn!(
        condition = cond,
        "unsupported DNS response condition; returning false"
    );
    false
}

/// `ip(...)` inner evaluation: any A/AAAA address hits any parameter (geoip:/set:/CIDR/bare IP).
fn eval_ip_condition(inner: &str, addrs: &[(IpAddr, u32)], rule_set_cache: &RuleSetCache) -> bool {
    for val in split_condition_params(inner) {
        let hit = match parse_ref(val) {
            // Compiled matching: O(log N) via merged range binary search.
            RuleSetRef::GeoIp(code) => {
                let hit = addrs.iter().any(|(ip, _)| rule_set_cache.geoip_contains(&code, *ip));
                if !hit {
                    // Keep the not-found warning for diagnostics (the set may genuinely be empty).
                    if !rule_set_cache.find_geoip_code(&code).is_some_and(|n| !n.is_empty()) {
                        warn!(code = %code, "DNS response ip(geoip:...) code not found; no match");
                    }
                }
                hit
            }
            RuleSetRef::Set(name) => {
                let hit = addrs.iter().any(|(ip, _)| rule_set_cache.ip_set_contains(&name, *ip));
                if !hit && rule_set_cache.get_set_ips(&name).is_none() {
                    warn!(
                        name = %name,
                        "DNS response ip(set:...) not found or not an ip_list; no match"
                    );
                }
                hit
            }
            RuleSetRef::GeoSite(code) => {
                warn!(code = %code, "DNS response ip(geosite:...) is invalid; no match");
                false
            }
            RuleSetRef::Plain(v) => {
                // CIDR or bare IP (/32, /128)
                if let Ok(cidr) = v.parse::<IpNet>() {
                    addrs.iter().any(|(ip, _)| cidr.contains(ip))
                } else if let Ok(addr) = v.parse::<IpAddr>() {
                    let bits = if addr.is_ipv4() { 32 } else { 128 };
                    let cidr = IpNet::new(addr, bits);
                    addrs
                        .iter()
                        .any(|(ip, _)| cidr.as_ref().map_or(false, |c| c.contains(ip)))
                } else {
                    false
                }
            }
        };
        if hit {
            return true;
        }
    }
    false
}

/// `qname(...)` inner evaluation: query name hits any parameter (geosite:/set:/normal Domain name pattern).
fn eval_qname_condition(inner: &str, qname: &str, rule_set_cache: &RuleSetCache) -> bool {
    for val in split_condition_params(inner) {
        let hit = match parse_ref(val) {
            // Compiled matching: O(qname labels) via suffix trie.
            RuleSetRef::GeoSite(code) => {
                let hit = rule_set_cache.geosite_matches(&code, qname);
                if !hit && rule_set_cache.find_geosite_code(&code).is_none() {
                    warn!(code = %code, "DNS response qname(geosite:...) code not found; no match");
                }
                hit
            }
            RuleSetRef::Set(name) => {
                let hit = rule_set_cache.domain_set_matches(&name, qname);
                if !hit && rule_set_cache.get_set_domains(&name).is_none() {
                    warn!(
                        name = %name,
                        "DNS response qname(set:...) not found or not a domain_list; no match"
                    );
                }
                hit
            }
            RuleSetRef::GeoIp(code) => {
                warn!(code = %code, "DNS response qname(geoip:...) is invalid; no match");
                false
            }
            RuleSetRef::Plain(v) => match_qname_value(qname, &v),
        };
        if hit {
            return true;
        }
    }
    false
}

/// Parse DNS question section to extract qname and qtype
fn parse_dns_question(packet: &[u8]) -> (String, u16) {
    if packet.len() < 12 {
        return (String::new(), 0);
    }

    // Read qtype from offset after the question name
    let mut pos = 12usize;
    let mut labels = Vec::new();

    loop {
        if pos >= packet.len() {
            return (labels.join("."), 0);
        }
        let len = packet[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer — skip to qtype
            pos += 2;
            break;
        }
        pos += 1;
        if pos + len > packet.len() {
            return (labels.join("."), 0);
        }
        if let Ok(label) = std::str::from_utf8(&packet[pos..pos + len]) {
            labels.push(label.to_string());
        }
        pos += len;
    }

    // Read qtype (2 bytes at current position)
    if pos + 2 > packet.len() {
        return (labels.join("."), 0);
    }
    let qtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);

    (labels.join("."), qtype)
}

/// Extract the cache TTL from a DNS response.
///
/// RFC 1035 §5.2: for positive responses use the minimum TTL of the answer
/// RRset.
///
/// RFC 2308 §5 (negative caching): for negative responses (NXDOMAIN/NODATA,
/// no answers) use `min(SOA.ttl, SOA.minimum)` from the authority section.
/// Without an SOA the response MUST NOT be cached (return 0).
///
/// Returns 0 when the response must not be cached.
fn extract_min_ttl(response: &[u8]) -> u32 {
    use crate::dns::upstream::{skip_name, skip_question_section};

    if response.len() < 12 {
        return 0;
    }
    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    let nscount = u16::from_be_bytes([response[8], response[9]]) as usize;

    // Positive response: min TTL over the answer section only.
    if ancount > 0 {
        let mut min_ttl = u32::MAX;
        let mut pos = skip_question_section(response, 12);
        for _ in 0..ancount {
            if pos >= response.len() {
                break;
            }
            pos = skip_name(response, pos);
            if pos + 10 > response.len() {
                break;
            }
            let ttl = u32::from_be_bytes([
                response[pos + 4],
                response[pos + 5],
                response[pos + 6],
                response[pos + 7],
            ]);
            if ttl < min_ttl {
                min_ttl = ttl;
            }
            let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
            pos += 10 + rdlength;
        }
        return if min_ttl == u32::MAX { 0 } else { min_ttl };
    }

    // Negative response (no answers): RFC 2308 — SOA in authority section.
    let mut pos = skip_question_section(response, 12);
    for _ in 0..nscount {
        if pos >= response.len() {
            break;
        }
        pos = skip_name(response, pos);
        if pos + 10 > response.len() {
            break;
        }
        let rtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let ttl = u32::from_be_bytes([
            response[pos + 4],
            response[pos + 5],
            response[pos + 6],
            response[pos + 7],
        ]);
        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        let rdata_start = pos + 10;
        let rdata_end = rdata_start + rdlength;
        if rtype == 6 && rdata_end <= response.len() && rdlength >= 4 {
            // SOA: MINIMUM is the last 4 bytes of the rdata.
            let minimum = u32::from_be_bytes([
                response[rdata_end - 4],
                response[rdata_end - 3],
                response[rdata_end - 2],
                response[rdata_end - 1],
            ]);
            return ttl.min(minimum);
        }
        pos = rdata_end;
    }
    // No SOA: must not cache (RFC 2308 §4).
    0
}

/// Build an empty DNS response (SERVFAIL or NXDOMAIN-like)
fn build_empty_response(query: &[u8]) -> Vec<u8> {
    if query.len() < 12 {
        return vec![
            0x00, 0x00, // ID = 0
            0x84, 0x02, // flags: response + SERVFAIL
            0x00, 0x01, // qdcount
            0x00, 0x00, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
        ];
    }

    let mut resp = Vec::with_capacity(query.len().max(12));
    // Copy ID
    resp.extend_from_slice(&query[0..2]);
    // Set flags: response + SERVFAIL (0x8182)
    resp.extend_from_slice(&[0x81, 0x82]);
    // Copy question count
    resp.extend_from_slice(&query[4..6]);
    // Zero answer/authority/additional counts
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // Copy question section
    if query.len() > 12 {
        resp.extend_from_slice(&query[12..]);
    }
    resp
}

/// Bind a UDP socket to `addr` with SO_REUSEADDR set before bind.
/// This avoids EADDRINUSE errors during rapid restart or when the port
/// is in TIME_WAIT state.
async fn bind_udp_with_reuseaddr(addr: SocketAddr) -> anyhow::Result<tokio::net::UdpSocket> {
    use std::os::unix::io::FromRawFd;

    let domain = if addr.is_ipv6() {
        libc::AF_INET6
    } else {
        libc::AF_INET
    };
    let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0) };
    if fd < 0 {
        return Err(anyhow::anyhow!("socket() failed: {}", std::io::Error::last_os_error()));
    }

    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    let sock_addr = socket2::SockAddr::from(addr);
    let ret = unsafe {
        libc::bind(fd, sock_addr.as_ptr() as *const libc::sockaddr, sock_addr.len())
    };
    if ret != 0 {
        unsafe { libc::close(fd) };
        return Err(anyhow::anyhow!("bind({}) failed: {}", addr, std::io::Error::last_os_error()));
    }

    let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    tokio::net::UdpSocket::from_std(std_socket)
        .map_err(|e| anyhow::anyhow!("from_std failed: {}", e))
}

/// Bind a TCP listener to `addr` with SO_REUSEADDR set before bind.
async fn bind_tcp_with_reuseaddr(addr: SocketAddr) -> anyhow::Result<tokio::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .context("Failed to create TCP socket")?;
    socket.set_reuse_address(true)?;
    let sock_addr = socket2::SockAddr::from(addr);
    socket.bind(&sock_addr)?;
    socket.listen(128)?;
    let std_listener: std::net::TcpListener = socket.into();
    std_listener.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(std_listener)
        .map_err(|e| anyhow::anyhow!("from_std failed: {}", e))
}

/// Create a UDP socket with IP_TRANSPARENT, SO_REUSEADDR, and SO_MARK, bound to
/// `orig_dst` — the address the client expects the response to come from.
///
/// # Why IP_TRANSPARENT
///
/// DNS clients expect the response source address to match the DNS server they
/// queried (e.g. 8.8.8.8:53). However, the dae-rs DNS handler listens on a local
/// address (e.g. 169.254.0.1:5353). Without IP_TRANSPARENT, responses would appear
/// to come from the listener address, which clients may reject or misroute.
///
/// IP_TRANSPARENT allows the socket to bind to a non-local address (the upstream
/// DNS server's IP), so the response appears to originate from the correct DNS
/// server. This requires `CAP_NET_ADMIN` capability.
///
/// # Why SO_MARK
///
/// SO_MARK=0x100 marks the response traffic so the eBPF program identifies it
/// as dae-rs control plane traffic and lets it pass through without proxy
/// interception, preventing routing loops.
///
/// # Parameters
///
/// Create IP_TRANSPARENT UDP socket for DNS response (bound to orig_dst).
///
/// Uniformly delegates to [`protocols::hostns::create_transparent_udp`] to implement the
/// "dae-rs's own traffic must go direct" convention (SO_MARK=0x100 self-exclusion + host NS).
async fn create_marked_udp_socket_for_dns(
    orig_dst: SocketAddr,
    _mark: u32,
) -> Option<tokio::net::UdpSocket> {
    let sock = protocols::hostns::DirectSocket::control_plane(None);
    match protocols::hostns::create_transparent_udp(&orig_dst, &sock) {
        Ok(s) => match tokio::net::UdpSocket::from_std(s) {
            Ok(s) => Some(s),
            Err(e) => {
                warn!("create_marked_udp_socket_for_dns: from_std failed: {}", e);
                None
            }
        },
        Err(e) => {
            warn!(
                "create_marked_udp_socket_for_dns: create failed for {}: {}",
                orig_dst, e
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ruleset::types::{DomainPattern, DomainPatternType, RuleSetData};
    use std::collections::HashMap;

    /// Construct Ruleset cache with geoip/geosite/ip_list/domain_list.
    fn make_cache() -> RuleSetCache {
        let cache = RuleSetCache::new();
        let mut geoip = HashMap::new();
        geoip.insert(
            "cn".to_string(),
            vec![
                "1.0.1.0/24".parse::<IpNet>().unwrap(),
                "223.5.5.0/24".parse::<IpNet>().unwrap(),
            ],
        );
        cache.insert("geoip_main".into(), RuleSetData::GeoIp { entries: geoip });

        let mut geosite = HashMap::new();
        geosite.insert(
            "cn".to_string(),
            vec![DomainPattern {
                pattern_type: DomainPatternType::Suffix,
                value: "baidu.com".into(),
            }],
        );
        cache.insert("geosite_main".into(), RuleSetData::GeoSite { entries: geosite });

        cache.insert(
            "chinaip".into(),
            RuleSetData::IpList(vec!["10.0.0.0/8".parse().unwrap()]),
        );
        cache.insert(
            "chinadom".into(),
            RuleSetData::DomainList(vec![DomainPattern {
                pattern_type: DomainPatternType::Full,
                value: "example.cn".into(),
            }]),
        );
        cache
    }

    fn encode_qname(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    /// Construct DNS response with A record.
    fn make_a_response(qname: &str, ips: &[IpAddr]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x12, 0x34, 0x81, 0x80, 0x00, 0x01]);
        buf.extend_from_slice(&(ips.len() as u16).to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // nscount, arcount
        buf.extend_from_slice(&encode_qname(qname));
        buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // qtype A, qclass IN
        for ip in ips {
            buf.extend_from_slice(&[0xC0, 0x0C]); // name pointer
            buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // type A, class IN
            buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // ttl 60
            buf.extend_from_slice(&[0x00, 0x04]); // rdlength 4
            match ip {
                IpAddr::V4(v4) => buf.extend_from_slice(&v4.octets()),
                IpAddr::V6(_) => panic!("A-record helper expects IPv4"),
            }
        }
        buf
    }

    fn eval(cond: &str, qname: &str, resp: &[u8], upstream: &str) -> bool {
        evaluate_response_condition(cond, qname, resp, upstream, &make_cache())
    }

    #[test]
    fn test_response_ip_geoip() {
        let resp = make_a_response("www.test.com", &["1.0.1.5".parse().unwrap()]);
        assert!(eval("ip(geoip:cn)", "www.test.com", &resp, "u1"), "geoip:cn matched");
        assert!(eval("ip(geoip:CN)", "www.test.com", &resp, "u1"), "case insensitive");
        assert!(eval("ip(geoip:cn)", "www.test.com", &[], "u1") == false, "empty response does not match");
    }

    #[test]
    fn test_response_ip_set() {
        let resp = make_a_response("www.test.com", &["10.1.1.1".parse().unwrap()]);
        assert!(eval("ip(set:chinaip)", "www.test.com", &resp, "u1"), "set:chinaip matched");
    }

    #[test]
    fn test_response_ip_plain_cidr_and_miss() {
        let resp = make_a_response("www.test.com", &["8.8.8.8".parse().unwrap()]);
        assert!(eval("ip(8.8.8.0/24)", "www.test.com", &resp, "u1"), "plain CIDR matched");
        assert!(!eval("ip(geoip:cn)", "www.test.com", &resp, "u1"), "geoip not matched");
    }

    #[test]
    fn test_response_qname_geosite() {
        let resp = make_a_response("www.baidu.com", &["1.2.3.4".parse().unwrap()]);
        assert!(eval("qname(geosite:cn)", "www.baidu.com", &resp, "u1"));
        assert!(eval("qname(geosite:cn)", "WWW.BAIDU.COM", &resp, "u1"), "case insensitive");
        assert!(!eval("qname(geosite:cn)", "www.google.com", &resp, "u1"));
    }

    #[test]
    fn test_response_qname_set() {
        let resp = make_a_response("example.cn", &["1.2.3.4".parse().unwrap()]);
        assert!(eval("qname(set:chinadom)", "example.cn", &resp, "u1"), "set full matched");
        assert!(!eval("qname(set:chinadom)", "sub.example.cn", &resp, "u1"), "full does not include subdomain");
    }

    #[test]
    fn test_response_any_and_upstream_and_nocontent() {
        let resp = make_a_response("www.test.com", &["1.2.3.4".parse().unwrap()]);
        assert!(eval("any", "www.test.com", &resp, "u1"));
        assert!(eval("*", "www.test.com", &resp, "u1"));
        assert!(eval("upstream(u1)", "www.test.com", &resp, "u1"));
        assert!(!eval("upstream(u2)", "www.test.com", &resp, "u1"));
        // nocontent: empty response
        assert!(eval("nocontent", "www.test.com", &[], "u1"));
        assert!(!eval("nocontent", "www.test.com", &resp, "u1"));
    }

    #[test]
    fn test_response_unknown_condition_false() {
        // Fix defect 5: unknown condition defaults to false (no longer always true)
        let resp = make_a_response("www.test.com", &["1.2.3.4".parse().unwrap()]);
        assert!(!eval("bogus(x)", "www.test.com", &resp, "u1"), "unknown condition should be false");
        assert!(!eval("ip(geoip:unknown-code)", "www.test.com", &resp, "u1"));
    }

    #[test]
    fn test_response_condition_and_not() {
        // ip(geoip:cn) && !qname(geosite:cn)
        let resp = make_a_response("www.google.com", &["1.0.1.5".parse().unwrap()]);
        // IP hits and Domain name does not hit → true
        assert!(eval(
            "ip(geoip:cn) && !qname(geosite:cn)",
            "www.google.com",
            &resp,
            "u1"
        ));
        // IP hits but Domain name also hits → false
        let resp2 = make_a_response("www.baidu.com", &["1.0.1.5".parse().unwrap()]);
        assert!(!eval(
            "ip(geoip:cn) && !qname(geosite:cn)",
            "www.baidu.com",
            &resp2,
            "u1"
        ));
        // Single negation
        assert!(!eval("!ip(geoip:cn)", "www.google.com", &resp, "u1"));
        assert!(eval("!qname(geosite:cn)", "www.google.com", &resp, "u1"));
    }

    #[test]
    fn test_extract_min_ttl_positive_uses_answer_ttl() {
        let resp = make_a_response("www.test.com", &["1.2.3.4".parse().unwrap()]);
        assert_eq!(extract_min_ttl(&resp), 60);
    }

    #[test]
    fn test_extract_min_ttl_negative_soa_rfc2308() {
        // NXDOMAIN with SOA in authority. RFC 2308 §5:
        // negative TTL = min(SOA.ttl, SOA.minimum).
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0x12, 0x34, 0x81, 0x83]); // ID + NXDOMAIN
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]);
        // Question: example.com A IN
        resp.extend_from_slice(&[
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
        ]);
        // Authority: name ptr 0xc00c, SOA(6), IN, ttl=300, rdlen=56
        resp.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x06, 0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]);
        resp.extend_from_slice(&[0x00, 0x38]);
        // SOA rdata: MNAME ns1.example.com, RNAME admin.example.com,
        // serial/refresh/retry/expire (4x4=16), minimum=60 → rdlen 17+19+20=56
        resp.extend_from_slice(&[0x03, b'n', b's', b'1', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00]);
        resp.extend_from_slice(&[0x05, b'a', b'd', b'm', b'i', b'n', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00]);
        resp.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        resp.extend_from_slice(&60u32.to_be_bytes()); // minimum

        assert_eq!(extract_min_ttl(&resp), 60);
    }

    #[test]
    fn test_extract_min_ttl_negative_no_soa_not_cacheable() {
        // NXDOMAIN without SOA: must not be cached (RFC 2308 §4).
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0x12, 0x34, 0x81, 0x83]);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        resp.extend_from_slice(&[
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
        ]);
        assert_eq!(extract_min_ttl(&resp), 0);
    }
}
