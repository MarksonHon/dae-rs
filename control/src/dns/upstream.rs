use anyhow::Context;
use protocols::{OutboundDialer, UdpSession};
use std::net::{IpAddr, SocketAddr};
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
        }
    }

    /// Create a raw UDP socket bound to an ephemeral port with
    /// SO_MARK=DAE_SOCKET_MARK for eBPF self-exclusion.
    ///
    /// 通过 [`protocols::hostns::create_udp`] 统一实现“dae-rs 自身流量必须直连”
    /// convention (control plane mark + host NS), ensuring DNS queries bypass the transparent proxy pipeline.
    fn create_marked_udp_socket(addr: &SocketAddr) -> anyhow::Result<std::net::UdpSocket> {
        protocols::hostns::create_udp(*addr, &protocols::hostns::DirectSocket::control_plane(None))
            .context("Failed to create marked UDP socket")
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
        // Create UDP socket with SO_MARK=0x100 to bypass eBPF proxy pipeline.
        // This is critical: without the mark, dae-rs's own DNS queries would be
        // intercepted by the transparent proxy, creating a DNS resolution loop.
        let std_socket = Self::create_marked_udp_socket(&self.address)?;
        std_socket.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(std_socket)?;
        socket.connect(self.address).await?;
        socket.send(request).await?;

        let mut buf = vec![0u8; 4096];
        let len = tokio::time::timeout(self.timeout, socket.recv(&mut buf)).await??;
        buf.truncate(len);
        Ok(buf)
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
        // The UDP attempt uses a short budget so an unresponsive relay fails
        // over to TCP quickly instead of stalling the whole DNS query.
        DnsTransport::Udp => {
            let udp_budget = timeout.min(Duration::from_secs(2));
            let session = match dialer.udp_dial().await {
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
            let udp_budget = timeout.min(Duration::from_secs(2));
            let session = match dialer.udp_dial().await {
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
}
