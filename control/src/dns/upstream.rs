use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

/// DNS upstream connection pool
///
/// Manages connections to a single DNS upstream server.
/// Supports udp://, tcp://, tcp+udp:// schemes.
/// DoH and DoT require additional dependencies and are not yet implemented.
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
    pub fn new(url: &str) -> anyhow::Result<Self> {
        let (transport, addr_str) = parse_dns_url(url)?;
        let timeout = Duration::from_secs(5);

        Ok(Self {
            address: addr_str,
            transport,
            timeout,
        })
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
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(self.address).await?;
        socket.send(request).await?;

        let mut buf = vec![0u8; 4096];
        let len = tokio::time::timeout(self.timeout, socket.recv(&mut buf)).await??;
        buf.truncate(len);
        Ok(buf)
    }

    async fn query_tcp(&self, request: &[u8]) -> anyhow::Result<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::time::timeout(
            self.timeout,
            tokio::net::TcpStream::connect(self.address),
        )
        .await??;

        // TCP DNS: 2-byte length prefix
        let len = (request.len() as u16).to_be_bytes();
        let mut framed = Vec::with_capacity(2 + request.len());
        framed.extend_from_slice(&len);
        framed.extend_from_slice(request);

        tokio::time::timeout(self.timeout, stream.write_all(&framed)).await??;

        // Read response: 2-byte length prefix
        let mut len_buf = [0u8; 2];
        tokio::time::timeout(self.timeout, stream.read_exact(&mut len_buf)).await??;
        let resp_len = u16::from_be_bytes(len_buf) as usize;

        let mut response = vec![0u8; resp_len];
        tokio::time::timeout(self.timeout, stream.read_exact(&mut response)).await??;
        Ok(response)
    }
}

/// Parse a DNS upstream URL into transport type and socket address.
///
/// Supported formats:
/// - `udp://1.1.1.1:53`
/// - `tcp://1.1.1.1:53`
/// - `tcp+udp://dns.google:53`
/// - `https://cloudflare-dns.com/dns-query` (parsed, not yet functional)
/// - `tls://dns.google:853` (parsed, not yet functional)
/// - `1.1.1.1:53` (default: UDP)
pub fn parse_dns_url(url: &str) -> anyhow::Result<(DnsTransport, SocketAddr)> {
    if url.starts_with("udp://") {
        let addr = url.trim_start_matches("udp://").parse()?;
        Ok((DnsTransport::Udp, addr))
    } else if url.starts_with("tcp://") {
        let addr = url.trim_start_matches("tcp://").parse()?;
        Ok((DnsTransport::Tcp, addr))
    } else if url.starts_with("tcp+udp://") {
        let addr = url.trim_start_matches("tcp+udp://").parse()?;
        Ok((DnsTransport::TcpUdp, addr))
    } else if url.starts_with("https://") || url.starts_with("doh://") {
        let host_port = url
            .trim_start_matches("https://")
            .trim_start_matches("doh://");
        let addr: SocketAddr = host_port.parse().map_err(|e| {
            anyhow::anyhow!(
                "invalid DoH address '{}': {}. For DoH, use format 'doh://host:port'",
                host_port, e
            )
        })?;
        Ok((DnsTransport::Doh, addr))
    } else if url.starts_with("tls://") || url.starts_with("dot://") {
        let addr = url
            .trim_start_matches("tls://")
            .trim_start_matches("dot://")
            .parse()?;
        Ok((DnsTransport::Dot, addr))
    } else {
        // Default: UDP
        let addr: SocketAddr = url.parse()?;
        Ok((DnsTransport::Udp, addr))
    }
}
