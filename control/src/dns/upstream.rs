use anyhow::Context;
use protocols::{OutboundDialer, UdpSession};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::debug;

// SO_MARK value for control plane sockets (must match dae_socket_mark in eBPF PARAM).
// Setting this mark on all dae-rs internal sockets ensures `pid_is_control_plane()`
// in the eBPF program returns true, bypassing the proxy pipeline for dae-rs's own traffic.

/// DNS upstream connection pool
///
/// Manages connections to a single DNS upstream server.
/// Supports udp://, tcp://, tcp+udp:// schemes.
/// DoH and DoT require additional dependencies and are not yet implemented.
///
/// All upstream sockets are created with SO_MARK=0x100 so that the eBPF program
/// identifies them as dae-rs control plane traffic and allows them to pass through
/// without proxy interception. This prevents DNS routing loops when dae-rs
/// resolves domain names for proxy servers or routing rules.
pub struct DnsUpstreamPool {
    /// Upstream address (parsed from URL)
    address: SocketAddr,
    /// Transport type
    transport: DnsTransport,
    /// Connection timeout
    timeout: Duration,
    /// Reusable UDP socket pool (lazily created on first UDP query).
    ///
    /// Instead of creating a fresh marked socket per query, the pool keeps one
    /// socket per upstream and multiplexes concurrent queries by rewriting the
    /// DNS transaction ID (RFC-style, same technique as kixdns).
    udp_pool: Mutex<Option<Arc<UdpPool>>>,
}

/// DNS transport protocol
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsTransport {
    /// Plain UDP
    Udp,
    /// Plain TCP
    Tcp,
    /// UDP with TCP fallback
    TcpUdp,
    /// DNS-over-HTTPS (not yet implemented)
    Doh,
    /// DNS-over-TLS (not yet implemented)
    Dot,
}

impl DnsUpstreamPool {
    /// Get the upstream server address.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Get the upstream transport type (UDP / TCP / TCP+UDP / DoH / DoT).
    pub fn transport(&self) -> DnsTransport {
        self.transport.clone()
    }

    pub fn new(url: &str) -> anyhow::Result<Self> {
        let parts = parse_dns_url_parts(url)?;
        let ip: IpAddr = parts
            .host
            .parse()
            .map_err(|e| anyhow::anyhow!("DNS upstream '{}' must be an IP address (hostnames must be resolved by the bootstrap DNS): {}", url, e))?;
        Ok(Self::new_with_addr(
            parts.transport,
            SocketAddr::new(ip, parts.port),
        ))
    }

    /// Create a pool directly from a parsed transport and socket address.
    /// Used by `init_upstreams` after resolving hostname upstreams via the
    /// bootstrap (starting_dns) resolver.
    pub fn new_with_addr(transport: DnsTransport, address: SocketAddr) -> Self {
        Self {
            address,
            transport,
            timeout: Duration::from_secs(5),
            udp_pool: Mutex::new(None),
        }
    }

    /// Send a DNS query and receive response
    pub async fn query(&self, request: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self.transport {
            DnsTransport::Udp => self.query_udp(request).await,
            DnsTransport::Tcp => self.query_tcp(request).await,
            DnsTransport::TcpUdp => {
                match self.query_udp(request).await {
                    Ok(resp) => Ok(resp),
                    Err(_) => self.query_tcp(request).await,
                }
            }
            DnsTransport::Doh => {
                Err(anyhow::anyhow!("DoH not yet implemented; use udp://, tcp://, or tcp+udp://"))
            }
            DnsTransport::Dot => {
                Err(anyhow::anyhow!("DoT not yet implemented; use udp://, tcp://, or tcp+udp://"))
            }
        }
    }

    async fn query_udp(&self, request: &[u8]) -> anyhow::Result<Vec<u8>> {
        let pool = self.ensure_udp_pool()?;
        pool.query(request, self.timeout).await
    }

    /// Lazily create the shared UDP pool for this upstream.
    ///
    /// The pool owns a single marked socket (SO_MARK=0x100 so the eBPF program
    /// lets dae-rs's own queries pass — critical to avoid a DNS hijack loop)
    /// and multiplexes concurrent queries via TXID rewriting.
    fn ensure_udp_pool(&self) -> anyhow::Result<Arc<UdpPool>> {
        let mut guard = self.udp_pool.lock().unwrap();
        if let Some(pool) = guard.as_ref() {
            return Ok(pool.clone());
        }
        let pool = Arc::new(UdpPool::new_with_socket(
            self.address,
            &protocols::hostns::DirectSocket::control_plane(None),
        )?);
        guard.replace(pool.clone());
        Ok(pool)
    }

    async fn query_tcp(&self, request: &[u8]) -> anyhow::Result<Vec<u8>> {
        // TCP query socket: uniformly uses hostns::connect_tcp (control plane mark → direct)
        let mut stream = protocols::hostns::connect_tcp(
            self.address,
            &protocols::hostns::DirectSocket::control_plane(None),
            false,
            std::time::Duration::from_secs(5),
        )
        .await
        .map_err(|e| anyhow::anyhow!("failed to create marked TCP socket: {}", e))?;

        Self::send_tcp_dns_query(&mut stream, request, self.timeout).await
    }

    /// Send a DNS query over an existing TCP stream (2-byte length prefix framing).
    async fn send_tcp_dns_query(
        stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
        request: &[u8],
        timeout: Duration,
    ) -> anyhow::Result<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let len = (request.len() as u16).to_be_bytes();
        let mut framed = Vec::with_capacity(2 + request.len());
        framed.extend_from_slice(&len);
        framed.extend_from_slice(request);

        tokio::time::timeout(timeout, stream.write_all(&framed)).await??;

        let mut len_buf = [0u8; 2];
        tokio::time::timeout(timeout, stream.read_exact(&mut len_buf)).await??;
        let resp_len = u16::from_be_bytes(len_buf) as usize;

        let mut response = vec![0u8; resp_len];
        tokio::time::timeout(timeout, stream.read_exact(&mut response)).await??;
        Ok(response)
    }
}

// ============================================================================
// Reusable UDP socket pool (kixdns-style)
// ============================================================================

/// In-flight UDP request: (original TXID, upstream addr, response sender).
type UdpInflight =
    (u16, SocketAddr, tokio::sync::oneshot::Sender<anyhow::Result<Vec<u8>>>);

/// RAII guard that removes the in-flight entry on drop, so timeouts,
/// cancellation and early returns never leak entries or hang waiters.
struct UdpInflightGuard {
    inflight: Arc<Mutex<HashMap<u16, UdpInflight>>>,
    id: u16,
}

impl Drop for UdpInflightGuard {
    fn drop(&mut self) {
        self.inflight.lock().unwrap().remove(&self.id);
    }
}

/// A shared UDP socket multiplexing concurrent DNS queries to one upstream.
///
/// Each query's transaction ID is rewritten to a locally-unique ID before
/// sending; a background reader matches responses by ID and restores the
/// original TXID. The socket is `connect()`ed to the upstream, so the kernel
/// filters out spoofed/foreign packets (only the connected peer is accepted).
///
/// This replaces the previous per-query socket creation: one marked socket per
/// upstream serves all concurrent queries.
struct UdpPool {
    socket: Arc<UdpSocket>,
    /// upstream address (for logging only; the socket is connected).
    upstream: SocketAddr,
    /// new_id → (original_id, upstream, tx)
    inflight: Arc<Mutex<HashMap<u16, UdpInflight>>>,
    next_id: AtomicU16,
}

impl UdpPool {
    /// Create the marked, connected UDP socket and start the response reader.
    fn new(upstream: SocketAddr) -> anyhow::Result<Self> {
        Self::new_with_socket(
            upstream,
            &protocols::hostns::DirectSocket::control_plane(None),
        )
    }

    /// Create the UDP pool socket using an explicit [`protocols::hostns::DirectSocket`]
    /// configuration (tests pass `plain()` to avoid requiring `CAP_NET_ADMIN`).
    fn new_with_socket(upstream: SocketAddr, sock: &protocols::hostns::DirectSocket) -> anyhow::Result<Self> {
        let std_socket = protocols::hostns::create_udp(upstream, sock)
            .context("Failed to create marked UDP pool socket")?;
        std_socket.set_nonblocking(true)?;
        std_socket
            .connect(upstream)
            .context("Failed to connect UDP pool socket")?;
        let socket = Arc::new(UdpSocket::from_std(std_socket)?);
        let pool = Self {
            socket: socket.clone(),
            upstream,
            inflight: Arc::new(Mutex::new(HashMap::new())),
            next_id: AtomicU16::new(0),
        };
        pool.spawn_reader();
        Ok(pool)
    }

    /// Background reader: dispatches responses to the matching in-flight query.
    fn spawn_reader(&self) {
        let socket = self.socket.clone();
        let inflight = self.inflight.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let len = match socket.recv(&mut buf).await {
                    Ok(n) => n,
                    Err(e) => {
                        debug!("UDP pool recv error: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                if len < 2 {
                    continue;
                }
                let id = u16::from_be_bytes([buf[0], buf[1]]);
                // Extract the waiter before touching buf (avoids holding the
                // lock across the restore/send).
                let entry = inflight.lock().unwrap().remove(&id);
                let Some((original_id, _upstream, tx)) = entry else {
                    debug!(id, "UDP pool response with unknown TXID (ignored)");
                    continue;
                };
                // Restore the original TXID so the response matches the client's query.
                let mut response = buf[..len].to_vec();
                response[0..2].copy_from_slice(&original_id.to_be_bytes());
                let _ = tx.send(Ok(response));
            }
        });
    }

    /// Send `request` and await the matched response.
    async fn query(&self, request: &[u8], timeout: Duration) -> anyhow::Result<Vec<u8>> {
        if request.len() < 2 {
            anyhow::bail!("DNS query too short");
        }
        let original_id = u16::from_be_bytes([request[0], request[1]]);

        // Register the in-flight entry with a fresh local ID.
        let (tx, rx) = tokio::sync::oneshot::channel();
        let new_id = {
            let mut map = self.inflight.lock().unwrap();
            let mut attempts = 0;
            loop {
                let cand = self.next_id.fetch_add(1, Ordering::Relaxed);
                if !map.contains_key(&cand) {
                    map.insert(cand, (original_id, self.upstream, tx));
                    break cand;
                }
                attempts += 1;
                if attempts > 1000 {
                    anyhow::bail!("UDP pool exhausted (too many concurrent queries)");
                }
            }
        };
        // Guard guarantees the entry is removed on timeout/cancel/early-return.
        let _guard = UdpInflightGuard {
            inflight: self.inflight.clone(),
            id: new_id,
        };

        // Rewrite the TXID in a copy and send.
        let mut pkt = request.to_vec();
        pkt[0..2].copy_from_slice(&new_id.to_be_bytes());
        if let Err(e) = self.socket.send(&pkt).await {
            return Err(e.into());
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => Err(anyhow::anyhow!(
                "UDP upstream {}: response channel closed",
                self.upstream
            )),
            Err(_) => Err(anyhow::anyhow!(
                "UDP upstream {}: query timed out",
                self.upstream
            )),
        }
    }
}

/// Send a DNS query through a proxy dialer, respecting the upstream's
/// configured transport type:
///
/// - `Udp` — via the proxy's UDP relay session (`dialer.udp_dial()`);
/// - `Tcp` — via a proxied TCP connection to the upstream DNS server;
/// - `TcpUdp` — try UDP relay first, fall back to TCP;
/// - `Doh`/`Dot` — not supported through the proxy yet.
///
/// This allows DNS queries to be routed through proxy groups when
/// `send_by` is configured.
pub async fn query_dns_via_proxy(
    dialer: &dyn OutboundDialer,
    upstream_addr: SocketAddr,
    transport: DnsTransport,
    request: &[u8],
    timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
    match transport {
        // UDP transport through a proxy: try the proxy's UDP relay first, and
        // fall back to TCP if UDP relay is unsupported/unreachable (e.g. some
        // Shadowsocks servers only implement TCP). DNS servers commonly serve
        // both UDP and TCP on port 53, so the TCP fallback keeps DNS working.
        // The UDP attempt gets most of the timeout budget (leaving some margin
        // for the TCP fallback) instead of a hard 2s cap, so a working but
        // slow relay is not forced over to TCP unnecessarily.
        DnsTransport::Udp => {
            let udp_budget = (timeout * 3 / 4).max(Duration::from_secs(2));
            let session = match udp_dial_with_timeout(dialer, timeout).await {
                Ok(s) => s,
                Err(e) => {
                    debug!(
                        "DNS proxy UDP relay unavailable ({}), falling back to TCP",
                        e
                    );
                    return query_dns_tcp_via_proxy(dialer, upstream_addr, request, timeout).await;
                }
            };
            match query_dns_udp_via_proxy(session.as_ref(), upstream_addr, request, udp_budget)
                .await
            {
                Ok(resp) => Ok(resp),
                Err(e) => {
                    debug!(
                        "DNS proxy UDP relay query failed ({}), falling back to TCP",
                        e
                    );
                    query_dns_tcp_via_proxy(dialer, upstream_addr, request, timeout).await
                }
            }
        }
        DnsTransport::Tcp => query_dns_tcp_via_proxy(dialer, upstream_addr, request, timeout).await,
        DnsTransport::TcpUdp => {
            let udp_budget = (timeout * 3 / 4).max(Duration::from_secs(2));
            let session = match udp_dial_with_timeout(dialer, timeout).await {
                Ok(s) => s,
                Err(_) => {
                    return query_dns_tcp_via_proxy(dialer, upstream_addr, request, timeout).await
                }
            };
            match query_dns_udp_via_proxy(session.as_ref(), upstream_addr, request, udp_budget)
                .await
            {
                Ok(resp) => Ok(resp),
                Err(_) => query_dns_tcp_via_proxy(dialer, upstream_addr, request, timeout).await,
            }
        }
        DnsTransport::Doh | DnsTransport::Dot => Err(anyhow::anyhow!(
            "DoH/DoT through proxy not implemented; use udp://, tcp://, or tcp+udp://"
        )),
    }
}

/// Open a proxy UDP relay session, bounded by `timeout`.
///
/// `udp_dial()` performs the protocol handshake (e.g. SOCKS5 UDP ASSOCIATE is a
/// full TCP connection + handshake). Without a bound here, a stuck handshake
/// could hold up the whole DNS query past the client's own deadline.
async fn udp_dial_with_timeout(
    dialer: &dyn OutboundDialer,
    timeout: Duration,
) -> anyhow::Result<Box<dyn UdpSession>> {
    tokio::time::timeout(timeout, dialer.udp_dial())
        .await
        .map_err(|_| anyhow::anyhow!("UDP relay session establishment timed out"))?
}

/// Send a DNS query over TCP through a proxy dialer.
async fn query_dns_tcp_via_proxy(
    dialer: &dyn OutboundDialer,
    upstream_addr: SocketAddr,
    request: &[u8],
    timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
    let target = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let mut conn = dialer.dial(&target).await.map_err(|e| {
        anyhow::anyhow!("failed to dial upstream DNS {} via proxy: {}", target, e)
    })?;

    // Send DNS query over TCP through the proxy
    DnsUpstreamPool::send_tcp_dns_query(&mut conn.stream, request, timeout).await
}

/// Send a DNS query as a UDP datagram through a proxy's UDP relay session.
async fn query_dns_udp_via_proxy(
    session: &dyn UdpSession,
    upstream_addr: SocketAddr,
    request: &[u8],
    timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
    session.send(&upstream_addr, request).await?;
    let (_, resp) = tokio::time::timeout(timeout, session.recv()).await??;
    Ok(resp)
}

/// Parsed DNS upstream URL components: transport, host, and port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsUrlParts {
    /// Transport protocol (UDP/TCP/TCP+UDP/DoH/DoT)
    pub transport: DnsTransport,
    /// Host part — either an IP literal or a hostname to be resolved by the bootstrap DNS.
    pub host: String,
    /// Port number (defaulted per-scheme when omitted).
    pub port: u16,
}

/// Parse a DNS upstream URL into transport, host, and port.
///
/// Unlike [`parse_dns_url`], the host may be a hostname (e.g. `dns.google`);
/// callers are responsible for resolving it (normally via the bootstrap DNS).
///
/// Supported formats:
/// - `udp://1.1.1.1:53`, `udp://dns.google` (default port 53)
/// - `tcp://1.1.1.1:53`
/// - `tcp+udp://dns.google:53`
/// - `https://cloudflare-dns.com/dns-query` (parsed, not yet functional)
/// - `tls://dns.google:853` (parsed, not yet functional)
/// - `1.1.1.1:53` (default: UDP)
pub fn parse_dns_url_parts(url: &str) -> anyhow::Result<DnsUrlParts> {
    let (transport, rest) = if let Some(r) = url.strip_prefix("udp://") {
        (DnsTransport::Udp, r)
    } else if let Some(r) = url.strip_prefix("tcp://") {
        (DnsTransport::Tcp, r)
    } else if let Some(r) = url.strip_prefix("tcp+udp://") {
        (DnsTransport::TcpUdp, r)
    } else if url.starts_with("https://") || url.starts_with("doh://") {
        let r = url
            .trim_start_matches("https://")
            .trim_start_matches("doh://");
        let r = r.split('/').next().unwrap_or(r);
        (DnsTransport::Doh, r)
    } else if url.starts_with("tls://") || url.starts_with("dot://") {
        let r = url
            .trim_start_matches("tls://")
            .trim_start_matches("dot://");
        (DnsTransport::Dot, r)
    } else {
        (DnsTransport::Udp, url)
    };

    let (host, port) = split_host_port(rest).map_err(|e| {
        anyhow::anyhow!("invalid DNS upstream address '{}': {}", url, e)
    })?;

    let default_port = match transport {
        DnsTransport::Doh => 443,
        DnsTransport::Dot => 853,
        _ => 53,
    };
    let port = port.unwrap_or(default_port);

    Ok(DnsUrlParts {
        transport,
        host,
        port,
    })
}

/// Split a `host[:port]` authority into host and optional port.
/// Handles IPv6 literals in brackets (`[::1]:53`).
fn split_host_port(authority: &str) -> anyhow::Result<(String, Option<u16>)> {
    let auth = authority.trim();
    if let Some(rest) = auth.strip_prefix('[') {
        // IPv6 literal
        let end = rest.find(']').ok_or_else(|| anyhow::anyhow!("missing ']' in IPv6 address"))?;
        let host = rest[..end].to_string();
        let after = &rest[end + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            Some(p.parse().map_err(|e| anyhow::anyhow!("invalid port: {}", e))?)
        } else if after.is_empty() {
            None
        } else {
            return Err(anyhow::anyhow!("unexpected characters after IPv6 address: '{}'", after));
        };
        Ok((host, port))
    } else if let Some(idx) = auth.rfind(':') {
        let host = auth[..idx].to_string();
        let port = auth[idx + 1..]
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid port: {}", e))?;
        Ok((host, Some(port)))
    } else {
        Ok((auth.to_string(), None))
    }
}

/// Parse a DNS upstream URL into transport type and socket address.
///
/// The host must be an IP address (hostnames cannot be parsed here — use
/// [`parse_dns_url_parts`] plus bootstrap resolution instead).
///
/// Supported formats:
/// - `udp://1.1.1.1:53`
/// - `tcp://1.1.1.1:53`
/// - `tcp+udp://dns.google:53` (parsed, not yet functional for hostnames)
/// - `https://cloudflare-dns.com/dns-query` (parsed, not yet functional)
/// - `tls://dns.google:853` (parsed, not yet functional)
/// - `1.1.1.1:53` (default: UDP)
pub fn parse_dns_url(url: &str) -> anyhow::Result<(DnsTransport, SocketAddr)> {
    let parts = parse_dns_url_parts(url)?;
    let ip: IpAddr = parts.host.parse().map_err(|e| {
        anyhow::anyhow!(
            "DNS upstream '{}' uses hostname '{}' which requires bootstrap resolution: {}",
            url, parts.host, e
        )
    })?;
    Ok((parts.transport, SocketAddr::new(ip, parts.port)))
}

/// Build a minimal DNS query for `hostname` of the given qtype (1=A, 28=AAAA).
///
/// Used by `init_upstreams` to resolve hostname-based upstreams via the
/// bootstrap (starting_dns) resolver.
pub fn build_dns_query(hostname: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(64);
    // Header: ID=0x0001, flags=0x0100 (RD), 1 question, 0 answer/authority/additional
    q.extend_from_slice(&[0x00, 0x01, 0x01, 0x00]);
    q.extend_from_slice(&[0x00, 0x01]);
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // Question: qname (RFC 1035 label format)
    for label in hostname.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            continue;
        }
        q.push(bytes.len() as u8);
        q.extend_from_slice(bytes);
    }
    q.push(0);
    // qtype + qclass (IN)
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0x00, 0x01]);
    q
}

/// Extract A/AAAA addresses from a DNS response's answer section.
///
/// Returns the list of IPs found (both IPv4 and IPv6). Compression pointers
/// in record names are handled.
pub fn parse_answers_for_addr(response: &[u8]) -> Vec<IpAddr> {
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
        pos = skip_name(response, pos);
        if pos + 10 > response.len() {
            break;
        }
        let rtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        let rdata_start = pos + 10;
        let rdata_end = rdata_start + rdlength;
        if rdata_end > response.len() {
            break;
        }
        let rdata = &response[rdata_start..rdata_end];
        match rtype {
            1 if rdata.len() == 4 => {
                out.push(IpAddr::V4(std::net::Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                )));
            }
            28 if rdata.len() == 16 => {
                let mut oct = [0u8; 16];
                oct.copy_from_slice(rdata);
                out.push(IpAddr::V6(std::net::Ipv6Addr::from(oct)));
            }
            _ => {}
        }
        pos = rdata_end;
    }

    out
}

/// Skip the question section starting at `pos`, returning the offset of the first answer.
pub fn skip_question_section(response: &[u8], mut pos: usize) -> usize {
    pos = skip_name(response, pos);
    if pos + 4 <= response.len() {
        pos + 4 // qtype + qclass
    } else {
        response.len()
    }
}

/// Decrement the TTL of every resource record in a DNS response by `elapsed`
/// seconds (RFC 1035 §5.2). Used on cache hits so the reply reports its true
/// remaining lifetime. TTLs are clamped at 0 (never negative).
pub fn patch_ttls(response: &mut [u8], elapsed: u32) {
    if response.len() < 12 || elapsed == 0 {
        return;
    }
    let ancount = u16::from_be_bytes([response[6], response[7]]);
    let nscount = u16::from_be_bytes([response[8], response[9]]);
    let arcount = u16::from_be_bytes([response[10], response[11]]);
    let total_rrs = ancount as usize + nscount as usize + arcount as usize;
    if total_rrs == 0 {
        return;
    }

    let mut pos = skip_question_section(response, 12);
    for _ in 0..total_rrs {
        if pos >= response.len() {
            return;
        }
        pos = skip_name(response, pos);
        if pos + 10 > response.len() {
            return;
        }
        let ttl = u32::from_be_bytes([
            response[pos + 4],
            response[pos + 5],
            response[pos + 6],
            response[pos + 7],
        ]);
        let new_ttl = ttl.saturating_sub(elapsed);
        response[pos + 4..pos + 8].copy_from_slice(&new_ttl.to_be_bytes());
        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        pos += 10 + rdlength;
    }
}

/// Skip a possibly-compressed DNS name at `pos`, returning the next offset.
pub fn skip_name(response: &[u8], mut pos: usize) -> usize {
    loop {
        if pos >= response.len() {
            return response.len();
        }
        let len = response[pos] as usize;
        if len == 0 {
            return pos + 1;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer — skip 2 bytes
            return pos + 2;
        }
        pos += 1 + len;
        if pos > response.len() {
            return response.len();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_url_parts_ipv4() {
        let parts = parse_dns_url_parts("udp://1.1.1.1:53").unwrap();
        assert_eq!(parts.transport, DnsTransport::Udp);
        assert_eq!(parts.host, "1.1.1.1");
        assert_eq!(parts.port, 53);
    }

    #[test]
    fn test_parse_dns_url_parts_hostname() {
        let parts = parse_dns_url_parts("tcp+udp://dns.google:53").unwrap();
        assert_eq!(parts.transport, DnsTransport::TcpUdp);
        assert_eq!(parts.host, "dns.google");
        assert_eq!(parts.port, 53);
    }

    #[test]
    fn test_parse_dns_url_parts_default_port() {
        let parts = parse_dns_url_parts("udp://1.1.1.1").unwrap();
        assert_eq!(parts.port, 53);
        let parts = parse_dns_url_parts("tls://dns.google").unwrap();
        assert_eq!(parts.port, 853);
        assert_eq!(parts.transport, DnsTransport::Dot);
    }

    #[test]
    fn test_parse_dns_url_parts_ipv6_literal() {
        let parts = parse_dns_url_parts("udp://[2001:4860:4860::8888]:53").unwrap();
        assert_eq!(parts.host, "2001:4860:4860::8888");
        assert_eq!(parts.port, 53);
    }

    #[test]
    fn test_parse_dns_url_hostname_rejected() {
        assert!(parse_dns_url("udp://dns.google:53").is_err());
        assert!(parse_dns_url("udp://1.1.1.1:53").is_ok());
    }

    #[test]
    fn test_build_dns_query_and_parse_answers() {
        let query = build_dns_query("example.com", 1);
        // Header (12) + name + qtype/qclass
        assert!(query.len() > 12);
        // qtype A
        assert_eq!(&query[query.len() - 4..query.len() - 2], &[0x00, 0x01]);
        // qclass IN
        assert_eq!(&query[query.len() - 2..], &[0x00, 0x01]);

        // Build a synthetic response: ID + flags(0x8180) + qd=1 an=2 ns=0 ar=0
        // question: example.com + qtype/qclass
        // answers: A 93.184.216.34 ttl=300, AAAA 2606:2800:220:1::248 ttl=600
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0x00, 0x01, 0x81, 0x80]);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]);
        resp.extend_from_slice(&query[12..]); // question
        // Answer 1: name pointer 0xc00c, type A, class IN, ttl 300, rdlen 4
        resp.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]); // ttl 300
        resp.extend_from_slice(&[0x00, 0x04]);
        resp.extend_from_slice(&[93, 184, 216, 34]);
        // Answer 2: name pointer, type AAAA, class IN, ttl 600, rdlen 16
        resp.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x00, 0x02, 0x58]); // ttl 600
        resp.extend_from_slice(&[0x00, 0x10]);
        resp.extend_from_slice(&[
            0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x48,
        ]);

        let addrs = parse_answers_for_addr(&resp);
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(addrs[1], "2606:2800:220:1::248".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_parse_answers_handles_truncated_response() {
        // Truncated: header only, no question section
        let addrs = parse_answers_for_addr(&[0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        assert!(addrs.is_empty());
    }

    /// Build a synthetic DNS response echoing a query, with a single A answer.
    fn make_response(txid: u16, qname: &str, ttl: u32) -> Vec<u8> {
        let query = build_dns_query(qname, 1);
        let mut resp = Vec::new();
        resp.extend_from_slice(&txid.to_be_bytes());
        resp.extend_from_slice(&[0x81, 0x80]);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        resp.extend_from_slice(&query[12..]); // question
        resp.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]);
        resp.extend_from_slice(&ttl.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x04]);
        resp.extend_from_slice(&[93, 184, 216, 34]);
        resp
    }

    #[test]
    fn test_patch_ttls_decrements() {
        let mut resp = make_response(0x1234, "example.com", 300);
        patch_ttls(&mut resp, 30);
        // TTL should be 300 - 30 = 270 at answer offset.
        // Answer NAME is a compression pointer (0xc00c) → skip 2, then type(2) class(2) ttl(4).
        let mut pos = crate::dns::upstream::skip_question_section(&resp, 12);
        pos = crate::dns::upstream::skip_name(&resp, pos);
        let ttl = u32::from_be_bytes([resp[pos + 4], resp[pos + 5], resp[pos + 6], resp[pos + 7]]);
        assert_eq!(ttl, 270);
    }

    #[test]
    fn test_patch_ttls_clamps_at_zero() {
        let mut resp = make_response(1, "example.com", 10);
        patch_ttls(&mut resp, 1000);
        let mut pos = crate::dns::upstream::skip_question_section(&resp, 12);
        pos = crate::dns::upstream::skip_name(&resp, pos);
        let ttl = u32::from_be_bytes([resp[pos + 4], resp[pos + 5], resp[pos + 6], resp[pos + 7]]);
        assert_eq!(ttl, 0);
    }

    #[tokio::test]
    async fn test_udp_pool_txid_roundtrip() {
        // Mock upstream: echoes every query back as a response (carrying the
        // pool's rewritten TXID), for a short window.
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<()>(1);
        let upstream_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (len, peer) = tokio::select! {
                    _ = done_rx.recv() => break,
                    r = upstream.recv_from(&mut buf) => match r {
                        Ok(v) => v,
                        Err(_) => break,
                    },
                };
                // Respond with the same query bytes (already carries the rewritten TXID).
                if upstream.send_to(&buf[..len], peer).await.is_err() {
                    break;
                }
            }
        });

        let pool = UdpPool::new_with_socket(
            upstream_addr,
            &protocols::hostns::DirectSocket::plain(),
        )
        .unwrap();
        // Two different queries both with TXID 0x1111 — must each get back a
        // response with TXID 0x1111 restored (not the pool's internal IDs).
        let q1 = build_dns_query("a.com", 1);
        let q2 = build_dns_query("b.com", 1);
        let mut q1 = q1;
        let mut q2 = q2;
        q1[0..2].copy_from_slice(&0x1111u16.to_be_bytes());
        q2[0..2].copy_from_slice(&0x1111u16.to_be_bytes());

        let (r1, r2) = tokio::join!(
            pool.query(&q1, Duration::from_secs(5)),
            pool.query(&q2, Duration::from_secs(5)),
        );
        let r1 = r1.expect("query1 ok");
        let r2 = r2.expect("query2 ok");
        // TXID restored to the original.
        assert_eq!(&r1[0..2], &0x1111u16.to_be_bytes());
        assert_eq!(&r2[0..2], &0x1111u16.to_be_bytes());
        // Each response carries its own question (length-prefixed qname).
        assert!(r1.windows(5).any(|w| w == b"a\x03com"));
        assert!(r2.windows(5).any(|w| w == b"b\x03com"));

        let _ = done_tx.send(()).await;
        upstream_task.abort();
    }

    #[tokio::test]
    async fn test_udp_pool_timeout_removes_inflight() {
        // Upstream that never responds.
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let _upstream_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                if upstream.recv_from(&mut buf).await.is_err() {
                    break;
                }
            }
        });

        let pool = UdpPool::new_with_socket(
            upstream_addr,
            &protocols::hostns::DirectSocket::plain(),
        )
        .unwrap();
        let q = build_dns_query("timeout.com", 1);
        let err = pool.query(&q, Duration::from_millis(200)).await;
        assert!(err.is_err(), "query should time out");
        // In-flight entry must be cleaned up.
        assert_eq!(pool.inflight.lock().unwrap().len(), 0);
    }
}
