use anyhow::Context;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

/// SO_MARK value for control plane sockets (must match dae_socket_mark in eBPF PARAM).
/// Setting this mark on all dae-rs internal sockets ensures `pid_is_control_plane()`
/// in the eBPF program returns true, bypassing the proxy pipeline for dae-rs's own traffic.
const DAE_SOCKET_MARK: u32 = 0x100;

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

    pub fn new(url: &str) -> anyhow::Result<Self> {
        let (transport, addr_str) = parse_dns_url(url)?;
        let timeout = Duration::from_secs(5);

        Ok(Self {
            address: addr_str,
            transport,
            timeout,
        })
    }

    /// Create a raw UDP socket bound to an ephemeral port with SO_MARK=DAE_SOCKET_MARK
    /// for eBPF self-exclusion. This ensures dae-rs's own DNS queries bypass the
    /// transparent proxy pipeline and go directly to the upstream DNS server.
    fn create_marked_udp_socket(addr: &SocketAddr) -> anyhow::Result<std::net::UdpSocket> {
        use socket2::{Domain, Socket, Type};
        use std::os::unix::io::AsRawFd;

        let domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
        let socket = Socket::new(domain, Type::DGRAM, None)
            .context("Failed to create marked UDP socket")?;
        let fd = socket.as_raw_fd();

        let mark_val = DAE_SOCKET_MARK as libc::c_int;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark_val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        // Bind to ephemeral port before converting
        let bind_addr: SocketAddr = if addr.is_ipv6() {
            ([0u16; 8], 0u16).into()
        } else {
            ([0u8; 4], 0u16).into()
        };
        socket.bind(&socket2::SockAddr::from(bind_addr))?;

        let std_socket: std::net::UdpSocket = socket.into();
        Ok(std_socket)
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
        use std::os::unix::io::FromRawFd;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Create TCP socket with SO_MARK=0x100 (same rationale as UDP)
        let domain = if self.address.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
        if fd < 0 {
            return Err(anyhow::anyhow!("failed to create marked TCP socket: {}", std::io::Error::last_os_error()));
        }
        let mark_val = DAE_SOCKET_MARK as libc::c_int;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark_val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        let std_stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
        let mut stream = tokio::net::TcpStream::from_std(std_stream)?;

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
