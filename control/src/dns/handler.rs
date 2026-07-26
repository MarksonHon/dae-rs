use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Helper: extract the UdpSocket's local addr so we can create new sockets per query
fn udp_local_addr(socket: &UdpSocket) -> SocketAddr {
    socket.local_addr().unwrap_or(([0, 0, 0, 0], 0).into())
}

use crate::config::DnsConfig;
use crate::dns::cache::DnsCache;
use crate::dns::router::{DnsResponseAction, DnsRouter};
use crate::dns::upstream::DnsUpstreamPool;

/// DNS Listener — handles incoming DNS queries (UDP + TCP)
pub struct DnsListener {
    /// Bind address
    bind_addr: SocketAddr,
    /// DNS configuration
    config: DnsConfig,
    /// Upstream pools (key: "group__label" -> pool)
    upstream_pools: Arc<HashMap<String, Arc<DnsUpstreamPool>>>,
    /// DNS response cache
    cache: Arc<RwLock<DnsCache>>,
    /// DNS router
    router: DnsRouter,
    /// UDP listener task handle
    udp_handle: Option<tokio::task::JoinHandle<()>>,
    /// TCP listener task handle
    tcp_handle: Option<tokio::task::JoinHandle<()>>,
    /// Shutdown signal sender
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl DnsListener {
    pub fn new(
        bind_addr: SocketAddr,
        config: DnsConfig,
        upstream_pools: Arc<HashMap<String, Arc<DnsUpstreamPool>>>,
        cache: Arc<RwLock<DnsCache>>,
        router: DnsRouter,
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
        }
    }

    /// Start UDP and TCP DNS listeners
    pub async fn start(&mut self) -> anyhow::Result<()> {
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        self.shutdown_tx = Some(shutdown_tx);

        let bind = self.bind_addr;
        let config = Arc::new(self.config.clone());
        let upstream_pools = self.upstream_pools.clone();
        let cache = self.cache.clone();
        let router = Arc::new(self.router.clone());

        // UDP listener
        let udp_socket = UdpSocket::bind(bind)
            .await
            .map_err(|e| anyhow::anyhow!("failed to bind DNS UDP listener on {}: {}", bind, e))?;
        let u_config = config.clone();
        let u_pools = upstream_pools.clone();
        let u_cache = cache.clone();
        let u_router = router.clone();
        let udp_handle = tokio::spawn(async move {
            run_udp_listener(udp_socket, u_config, u_pools, u_cache, u_router).await;
        });
        self.udp_handle = Some(udp_handle);

        // TCP listener
        let tcp_listener = TcpListener::bind(bind)
            .await
            .map_err(|e| anyhow::anyhow!("failed to bind DNS TCP listener on {}: {}", bind, e))?;
        let tcp_handle = tokio::spawn(async move {
            run_tcp_listener(tcp_listener, config, upstream_pools, cache, router).await;
        });
        self.tcp_handle = Some(tcp_handle);

        info!("DNS listener started on {} (UDP + TCP)", bind);
        Ok(())
    }

    /// Stop the DNS listener
    pub async fn stop(&mut self) -> anyhow::Result<()> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.udp_handle.take() {
            let _ = handle.await;
        }
        if let Some(handle) = self.tcp_handle.take() {
            let _ = handle.await;
        }
        info!("DNS listener stopped");
        Ok(())
    }
}

/// Run the UDP DNS listener
async fn run_udp_listener(
    socket: UdpSocket,
    config: Arc<DnsConfig>,
    upstream_pools: Arc<HashMap<String, Arc<DnsUpstreamPool>>>,
    cache: Arc<RwLock<DnsCache>>,
    router: Arc<DnsRouter>,
) {
    let local_addr = udp_local_addr(&socket);
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

        tokio::spawn(async move {
            // Create a new socket for each query response
            if let Ok(resp_socket) = UdpSocket::bind(local_addr).await {
                if let Err(e) = handle_dns_query(
                    &resp_socket,
                    src,
                    &request,
                    &config,
                    &upstream_pools,
                    &cache,
                    &router,
                )
                .await
                {
                    debug!("DNS query handling failed: {}", e);
                }
            }
        });
    }
}

/// Run the TCP DNS listener
async fn run_tcp_listener(
    listener: TcpListener,
    config: Arc<DnsConfig>,
    upstream_pools: Arc<HashMap<String, Arc<DnsUpstreamPool>>>,
    cache: Arc<RwLock<DnsCache>>,
    router: Arc<DnsRouter>,
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

        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

            if let Ok(response) =
                handle_dns_internal(&request, &config, &upstream_pools, &cache, &router).await
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
async fn handle_dns_query(
    socket: &UdpSocket,
    src: SocketAddr,
    request: &[u8],
    config: &Arc<DnsConfig>,
    upstream_pools: &HashMap<String, Arc<DnsUpstreamPool>>,
    cache: &Arc<RwLock<DnsCache>>,
    router: &Arc<DnsRouter>,
) -> anyhow::Result<()> {
    let response = handle_dns_internal(request, config, upstream_pools, cache, router).await?;
    socket.send_to(&response, src).await?;
    Ok(())
}

/// Internal DNS query processing
async fn handle_dns_internal(
    request: &[u8],
    config: &Arc<DnsConfig>,
    upstream_pools: &HashMap<String, Arc<DnsUpstreamPool>>,
    cache: &Arc<RwLock<DnsCache>>,
    router: &Arc<DnsRouter>,
) -> anyhow::Result<Vec<u8>> {
    // Parse query name and type
    let (qname, qtype) = parse_dns_question(request);

    // Check cache first
    let cache_key = DnsCache::cache_key(&qname, qtype, 1); // class IN = 1
    {
        let cache_guard = cache.read().await;
        if let Some(cached) = cache_guard.lookup(cache_key) {
            debug!("DNS cache hit: {} type={}", qname, qtype);
            return Ok(cached.to_vec());
        }
    }

    // Route to group and upstream
    let route = router.match_query(&qname, qtype);
    if route.upstream_label.is_empty() {
        // No upstream found — return empty response
        return Ok(build_empty_response(request));
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
                    return Ok(build_empty_response(request));
                }
            }
        }
    };

    // Forward query to upstream
    let response = pool.query(request).await?;

    // Apply response routing
    let action = check_dns_response(&response, &route.group, router);

    match action {
        DnsResponseAction::Accept => {
            // Cache the response
            let ttl = extract_min_ttl(&response);
            let mut cache_guard = cache.write().await;
            cache_guard.insert(cache_key, response.clone(), ttl);
            Ok(response)
        }
        DnsResponseAction::Reject => Ok(build_empty_response(request)),
        DnsResponseAction::Requery(new_upstream) => {
            let new_pool_key = format!("{}__{}", route.group.name, new_upstream);
            if let Some(new_pool) = upstream_pools.get(&new_pool_key) {
                let response = new_pool.query(request).await?;
                let ttl = extract_min_ttl(&response);
                let mut cache_guard = cache.write().await;
                cache_guard.insert(cache_key, response.clone(), ttl);
                Ok(response)
            } else {
                // Fallback: accept original response
                let ttl = extract_min_ttl(&response);
                let mut cache_guard = cache.write().await;
                cache_guard.insert(cache_key, response.clone(), ttl);
                Ok(response)
            }
        }
    }
}

/// Check DNS response routing
fn check_dns_response(
    response: &[u8],
    group: &crate::config::DnsGroupConfig,
    router: &Arc<DnsRouter>,
) -> DnsResponseAction {
    let routing = match &group.response_routing {
        Some(r) => r,
        None => return DnsResponseAction::Accept,
    };

    // Check response rules
    for rule in &routing.rules {
        let raw = rule.r#match.trim();
        let action = rule.action.trim();

        match action {
            "accept" => {
                if evaluate_response_condition(raw, response) {
                    return DnsResponseAction::Accept;
                }
            }
            "reject" => {
                if evaluate_response_condition(raw, response) {
                    return DnsResponseAction::Reject;
                }
            }
            upstream_label => {
                // Requery with different upstream
                if evaluate_response_condition(raw, response) {
                    return DnsResponseAction::Requery(upstream_label.to_string());
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

/// Evaluate a single response condition
fn evaluate_response_condition(condition: &str, response: &[u8]) -> bool {
    if condition.is_empty() || condition == "any" || condition == "*" {
        return true;
    }

    // Check for upstream(label) condition
    if let Some(label) = condition.strip_prefix("upstream(") {
        if let Some(_) = label.strip_suffix(')') {
            // upstream(label) — match depends on which upstream was used
            // For now, accept all (this requires tracking which upstream responded)
            return true;
        }
    }

    // Check for nocontent (NODATA) response
    if condition == "nocontent" {
        if response.len() < 12 {
            return true;
        }
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        return ancount == 0;
    }

    // Default: accept
    true
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
