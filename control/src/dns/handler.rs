use anyhow::Context;
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, info, warn};

use crate::ruleset::cache::RuleSetCache;
use crate::ruleset::refparse::{match_domain_patterns, match_qname_value, parse_ref, RuleSetRef};

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

use crate::config::DnsConfig;
use crate::dns::cache::DnsCache;
use crate::dns::router::{DnsResponseAction, DnsRouter};
use crate::dns::upstream::DnsUpstreamPool;

/// Callback invoked on each accepted DNS resolution (domain, ip, ttl).
/// Used to feed the domain_routing_map eBPF map for domain-based routing.
pub type DnsResolveCallback = Arc<dyn Fn(&str, IpAddr, u32) + Send + Sync>;

/// DNS Listener — handles incoming DNS queries (UDP + TCP)
pub struct DnsListener {
    /// Bind address
    bind_addr: SocketAddr,
    /// DNS configuration
    config: DnsConfig,
    /// Upstream pools (key: "group__label" -> pool)
    upstream_pools: Arc<HashMap<String, Arc<DnsUpstreamPool>>>,
    /// DNS response cache
    cache: Arc<std::sync::RwLock<DnsCache>>,
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
}

impl DnsListener {
    pub fn new(
        bind_addr: SocketAddr,
        config: DnsConfig,
        upstream_pools: Arc<HashMap<String, Arc<DnsUpstreamPool>>>,
        cache: Arc<std::sync::RwLock<DnsCache>>,
        router: DnsRouter,
        on_resolve: Option<DnsResolveCallback>,
        rule_set_cache: RuleSetCache,
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

        debug!(bind = %bind, "DNS listener starting");

        // UDP listener: bind with SO_REUSEADDR so rapid restart works
        let udp_socket = bind_udp_with_reuseaddr(bind).await.map_err(|e| {
            anyhow::anyhow!("failed to bind DNS UDP listener on {}: {}", bind, e)
        })?;
        debug!("DNS UDP listener bound to {}", bind);
        let u_config = config.clone();
        let u_pools = upstream_pools.clone();
        let u_cache = cache.clone();
        let u_router = router.clone();
        let u_on_resolve = on_resolve.clone();
        let u_ruleset = rule_set_cache.clone();
        let udp_handle = tokio::spawn(async move {
            run_udp_listener(
                udp_socket,
                u_config,
                u_pools,
                u_cache,
                u_router,
                u_on_resolve,
                u_ruleset,
            )
            .await;
        });
        self.udp_handle = Some(udp_handle);

        // TCP listener: bind with SO_REUSEADDR
        let tcp_listener = bind_tcp_with_reuseaddr(bind).await.map_err(|e| {
            anyhow::anyhow!("failed to bind DNS TCP listener on {}: {}", bind, e)
        })?;
        let tcp_handle = tokio::spawn(async move {
            run_tcp_listener(
                tcp_listener,
                config,
                upstream_pools,
                cache,
                router,
                on_resolve,
                rule_set_cache,
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
                let i_config = Arc::new(self.config.clone());
                let i_pools = self.upstream_pools.clone();
                let i_cache = self.cache.clone();
                let i_router = Arc::new(self.router.clone());
                let i_on_resolve = self.on_resolve.clone();
                let i_ruleset = self.rule_set_cache.clone();
                tokio::spawn(async move {
                    run_udp_listener(
                        internal_socket,
                        i_config,
                        i_pools,
                        i_cache,
                        i_router,
                        i_on_resolve,
                        i_ruleset,
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
    cache: Arc<std::sync::RwLock<DnsCache>>,
    router: Arc<DnsRouter>,
    on_resolve: Option<DnsResolveCallback>,
    rule_set_cache: RuleSetCache,
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
        let config = config.clone();
        let upstream_pools = upstream_pools.clone();
        let cache = cache.clone();
        let router = router.clone();
        let on_resolve = on_resolve.clone();
        let rule_set_cache = rule_set_cache.clone();

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
            )
            .await
            {
                debug!("DNS query handling failed: {}", e);
            }
        });
    }
}

/// Run the TCP DNS listener
async fn run_tcp_listener(
    listener: TcpListener,
    config: Arc<DnsConfig>,
    upstream_pools: Arc<HashMap<String, Arc<DnsUpstreamPool>>>,
    cache: Arc<std::sync::RwLock<DnsCache>>,
    router: Arc<DnsRouter>,
    on_resolve: Option<DnsResolveCallback>,
    rule_set_cache: RuleSetCache,
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

        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;

            let mut stream = stream;

            // TCP DNS: 2-byte length prefix, read exactly
            let mut len_buf = [0u8; 2];
            if let Err(e) = stream.read_exact(&mut len_buf).await {
                debug!("TCP DNS read length error: {}", e);
                return;
            }
            let msg_len = u16::from_be_bytes(len_buf) as usize;
            if msg_len == 0 || msg_len > 4096 {
                return;
            }

            // Read message body exactly
            let mut request = vec![0u8; msg_len];
            if let Err(e) = stream.read_exact(&mut request).await {
                debug!("TCP DNS read body error: {}", e);
                return;
            }

            if let Ok((response, _upstream_addr)) = handle_dns_internal(
                &request,
                &config,
                &upstream_pools,
                &cache,
                &router,
                &on_resolve,
                &rule_set_cache,
            )
            .await
            {
                // Write response with length prefix
                let resp_len = (response.len() as u16).to_be_bytes();
                let mut framed = Vec::with_capacity(2 + response.len());
                framed.extend_from_slice(&resp_len);
                framed.extend_from_slice(&response);

                let _ = stream.writable().await;
                let _ = stream.try_write(&framed);
            }
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
    cache: &Arc<std::sync::RwLock<DnsCache>>,
    router: &Arc<DnsRouter>,
    on_resolve: &Option<DnsResolveCallback>,
    rule_set_cache: &RuleSetCache,
) -> anyhow::Result<()> {
    let (response, upstream_addr) = handle_dns_internal(
        request,
        config,
        upstream_pools,
        cache,
        router,
        on_resolve,
        rule_set_cache,
    )
    .await?;

    // Determine the bind address for the response socket:
    // - Upstream query result: bind to the upstream DNS server address with IP_TRANSPARENT
    //   so the response appears to come from the DNS server the client queried.
    // - Cache hit (None): bind to ephemeral port as fallback.
    let bind_addr = upstream_addr.unwrap_or_else(|| {
        // Fallback: ephemeral address (0.0.0.0:0). The kernel assigns a local
        // source address. This is the same behavior as before IP_TRANSPARENT support.
        ([0u8; 4], 0u16).into()
    });

    let resp_socket = create_marked_udp_socket_for_dns(bind_addr, shared::DAE_SOCKET_MARK).await
        .ok_or_else(|| anyhow::anyhow!(
            "failed to create IP_TRANSPARENT socket for DNS response (bind={})",
            bind_addr
        ))?;

    resp_socket.send_to(&response, src).await?;
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
async fn handle_dns_internal(
    request: &[u8],
    #[allow(unused)] config: &Arc<DnsConfig>,
    upstream_pools: &HashMap<String, Arc<DnsUpstreamPool>>,
    cache: &Arc<std::sync::RwLock<DnsCache>>,
    router: &Arc<DnsRouter>,
    on_resolve: &Option<DnsResolveCallback>,
    rule_set_cache: &RuleSetCache,
) -> anyhow::Result<(Vec<u8>, Option<SocketAddr>)> {
    // Parse query name and type
    let (qname, qtype) = parse_dns_question(request);

    // Check cache first
    let cache_key = DnsCache::cache_key(&qname, qtype, 1); // class IN = 1
    {
        let cache_guard = cache.read().unwrap();
        if let Some(cached) = cache_guard.lookup(cache_key) {
            debug!("DNS cache hit: {} type={}", qname, qtype);
            let mut response = cached.to_vec();
            // Patch transaction ID to match the current query — DNS clients
            // discard responses whose ID doesn't match the outstanding query.
            if response.len() >= 2 && request.len() >= 2 {
                response[0..2].copy_from_slice(&request[0..2]);
            }
            return Ok((response, None));
        }
    }

    // Route to group and upstream
    let route = router.match_query(&qname, qtype);
    if route.upstream_label.is_empty() {
        // No upstream found — return empty response
        return Ok((build_empty_response(request), None));
    }

    // Look up upstream pool
    let pool_key = format!("{}__{}", route.group.name, route.upstream_label);
    let pool = match upstream_pools.get(&pool_key) {
        Some(p) => p,
        None => {
            // Try starting DNS pools as fallback
            let starting_key = format!("__starting__{}", route.upstream_label);
            match upstream_pools.get(&starting_key) {
                Some(p) => p,
                None => {
                    warn!("DNS upstream not found: {}", pool_key);
                    return Ok((build_empty_response(request), None));
                }
            }
        }
    };

    let upstream_addr = pool.address();

    // Forward query to upstream
    let response = pool.query(request).await?;

    // Apply response routing
    let action = check_dns_response(
        &response,
        &qname,
        &route.group,
        router,
        &route.upstream_label,
        rule_set_cache,
    );

    match action {
        DnsResponseAction::Accept => {
            // Cache the response
            let ttl = extract_min_ttl(&response);
            let mut cache_guard = cache.write().unwrap();
            cache_guard.insert(cache_key, response.clone(), ttl);
            // Feed accepted resolutions into the domain routing tracker so the
            // eBPF domain_routing_map is populated for domain-based routing.
            notify_resolve(on_resolve, &qname, &response);
            Ok((response, Some(upstream_addr)))
        }
        DnsResponseAction::Reject => Ok((build_empty_response(request), Some(upstream_addr))),
        DnsResponseAction::Requery(new_upstream) => {
            let new_pool_key = format!("{}__{}", route.group.name, new_upstream);
            if let Some(new_pool) = upstream_pools.get(&new_pool_key) {
                let new_upstream_addr = new_pool.address();
                let response = new_pool.query(request).await?;
                let ttl = extract_min_ttl(&response);
                let mut cache_guard = cache.write().unwrap();
                cache_guard.insert(cache_key, response.clone(), ttl);
                notify_resolve(on_resolve, &qname, &response);
                Ok((response, Some(new_upstream_addr)))
            } else {
                // Fallback: accept original response
                let ttl = extract_min_ttl(&response);
                let mut cache_guard = cache.write().unwrap();
                cache_guard.insert(cache_key, response.clone(), ttl);
                notify_resolve(on_resolve, &qname, &response);
                Ok((response, Some(upstream_addr)))
            }
        }
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

/// Check DNS response routing
fn check_dns_response(
    response: &[u8],
    qname: &str,
    group: &crate::config::DnsGroupConfig,
    #[allow(unused)] router: &Arc<DnsRouter>,
    upstream_label: &str,
    rule_set_cache: &RuleSetCache,
) -> DnsResponseAction {
    let routing = match &group.response_routing {
        Some(r) => r,
        None => return DnsResponseAction::Accept,
    };

    // Check response rules
    for rule in &routing.rules {
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
    match routing.fallback.as_str() {
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

    // nocontent（NODATA）
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
            RuleSetRef::GeoIp(code) => match rule_set_cache.find_geoip_code(&code) {
                Some(nets) => addrs.iter().any(|(ip, _)| nets.iter().any(|n| n.contains(ip))),
                None => {
                    warn!(code = %code, "DNS response ip(geoip:...) code not found; no match");
                    false
                }
            },
            RuleSetRef::Set(name) => match rule_set_cache.get_set_ips(&name) {
                Some(nets) => addrs.iter().any(|(ip, _)| nets.iter().any(|n| n.contains(ip))),
                None => {
                    warn!(
                        name = %name,
                        "DNS response ip(set:...) not found or not an ip_list; no match"
                    );
                    false
                }
            },
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
            RuleSetRef::GeoSite(code) => match rule_set_cache.find_geosite_code(&code) {
                Some(patterns) => match_domain_patterns(qname, &patterns),
                None => {
                    warn!(code = %code, "DNS response qname(geosite:...) code not found; no match");
                    false
                }
            },
            RuleSetRef::Set(name) => match rule_set_cache.get_set_domains(&name) {
                Some(patterns) => match_domain_patterns(qname, &patterns),
                None => {
                    warn!(
                        name = %name,
                        "DNS response qname(set:...) not found or not a domain_list; no match"
                    );
                    false
                }
            },
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

/// Extract minimum TTL from DNS response
fn extract_min_ttl(response: &[u8]) -> u32 {
    if response.len() < 12 {
        return 60;
    }

    let ancount = u16::from_be_bytes([response[6], response[7]]);
    let nscount = u16::from_be_bytes([response[8], response[9]]);
    let arcount = u16::from_be_bytes([response[10], response[11]]);
    let total_rrs = ancount as usize + nscount as usize + arcount as usize;

    if total_rrs == 0 {
        return 60;
    }

    // Skip question section
    let mut pos = 12usize;
    loop {
        if pos >= response.len() {
            return 60;
        }
        let len = response[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer in question name — skip 2 bytes
            pos += 2;
            break;
        }
        pos += 1 + len;
    }
    // Skip qtype + qclass
    pos += 4;

    let mut min_ttl = u32::MAX;
    for _ in 0..total_rrs {
        if pos >= response.len() {
            break;
        }

        // Skip NAME field (variable length or compression pointer)
        loop {
            if pos >= response.len() {
                return if min_ttl == u32::MAX { 60 } else { min_ttl };
            }
            let len = response[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if len & 0xC0 == 0xC0 {
                // Compression pointer (2 bytes)
                pos += 2;
                break;
            }
            pos += 1 + len;
        }

        // Now at TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) + RDATA
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

    if min_ttl == u32::MAX {
        60
    } else {
        min_ttl
    }
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
/// 统一委托 [`protocols::hostns::create_transparent_udp`] 实现“dae-rs 自身
/// 流量必须直连”的约定（SO_MARK=0x100 自排除 + 宿主 NS）。
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
        assert!(eval("ip(geoip:cn)", "www.test.com", &resp, "u1"), "geoip:cn 命中");
        assert!(eval("ip(geoip:CN)", "www.test.com", &resp, "u1"), "大小写不敏感");
        assert!(eval("ip(geoip:cn)", "www.test.com", &[], "u1") == false, "空响应不命中");
    }

    #[test]
    fn test_response_ip_set() {
        let resp = make_a_response("www.test.com", &["10.1.1.1".parse().unwrap()]);
        assert!(eval("ip(set:chinaip)", "www.test.com", &resp, "u1"), "set:chinaip 命中");
    }

    #[test]
    fn test_response_ip_plain_cidr_and_miss() {
        let resp = make_a_response("www.test.com", &["8.8.8.8".parse().unwrap()]);
        assert!(eval("ip(8.8.8.0/24)", "www.test.com", &resp, "u1"), "普通 CIDR 命中");
        assert!(!eval("ip(geoip:cn)", "www.test.com", &resp, "u1"), "geoip 未命中");
    }

    #[test]
    fn test_response_qname_geosite() {
        let resp = make_a_response("www.baidu.com", &["1.2.3.4".parse().unwrap()]);
        assert!(eval("qname(geosite:cn)", "www.baidu.com", &resp, "u1"));
        assert!(eval("qname(geosite:cn)", "WWW.BAIDU.COM", &resp, "u1"), "大小写不敏感");
        assert!(!eval("qname(geosite:cn)", "www.google.com", &resp, "u1"));
    }

    #[test]
    fn test_response_qname_set() {
        let resp = make_a_response("example.cn", &["1.2.3.4".parse().unwrap()]);
        assert!(eval("qname(set:chinadom)", "example.cn", &resp, "u1"), "set full 命中");
        assert!(!eval("qname(set:chinadom)", "sub.example.cn", &resp, "u1"), "full 不含子域");
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
        assert!(!eval("bogus(x)", "www.test.com", &resp, "u1"), "未知条件应 false");
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
}
