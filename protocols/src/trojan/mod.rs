//! Trojan 协议Dialer
//!
//! Implements Trojan outbound proxy protocol, based on TLS transport, disguising as HTTPS traffic.
//! Reference: https://github.com/trojan-gfw/trojan/blob/master/docs/protocol.md

use async_trait::async_trait;
use sha2::{Sha224, Digest};
use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};

use crate::{OutboundDialer, ProxyConn};

/// Trojan Dialer错误
#[derive(Debug, thiserror::Error)]
pub enum TrojanError {
    #[error("Trojan dial timeout: {0}")]
    Timeout(String),
    #[error("Trojan connection refused: {0}")]
    ConnectionRefused(String),
    #[error("Trojan TLS error: {0}")]
    Tls(String),
    #[error("Trojan protocol error: {0}")]
    ProtocolError(String),
    #[error("Trojan IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Trojan error: {0}")]
    Other(String),
}

/// Trojan Dialer
pub struct TrojanDialer {
    /// Upstream Trojan server address
    pub proxy_addr: SocketAddr,
    /// Dial timeout duration
    pub dial_timeout: Duration,
    /// Authentication password
    pub password: String,
    /// TLS SNI
    pub sni: String,
    /// Certificate SHA256 fingerprint (for certificate pinning)
    pub ca_sha256: Option<String>,
    /// fwmark for eBPF self-exclusion
    pub self_mark: u32,
    /// Host network namespace fd
    pub host_ns_fd: Option<RawFd>,
}

impl TrojanDialer {
    /// 创建新的 Trojan Dialer
    pub fn new(
        proxy_addr: SocketAddr,
        password: impl Into<String>,
        sni: impl Into<String>,
        dial_timeout_ms: u64,
    ) -> Self {
        Self {
            proxy_addr,
            dial_timeout: Duration::from_millis(dial_timeout_ms),
            password: password.into(),
            sni: sni.into(),
            ca_sha256: None,
            self_mark: 0,
            host_ns_fd: None,
        }
    }

    /// Create dialer with self-mark
    pub fn new_with_mark(
        proxy_addr: SocketAddr,
        password: impl Into<String>,
        sni: impl Into<String>,
        dial_timeout_ms: u64,
        self_mark: u32,
    ) -> Self {
        Self {
            proxy_addr,
            dial_timeout: Duration::from_millis(dial_timeout_ms),
            password: password.into(),
            sni: sni.into(),
            ca_sha256: None,
            self_mark,
            host_ns_fd: None,
        }
    }

    /// Set certificate SHA256 fingerprint
    pub fn set_ca_sha256(&mut self, ca_sha256: Option<String>) -> &mut Self {
        self.ca_sha256 = ca_sha256;
        self
    }

    /// Set host network namespace fd
    pub fn set_host_ns_fd(&mut self, host_ns_fd: Option<RawFd>) -> &mut Self {
        self.host_ns_fd = host_ns_fd;
        self
    }

    /// Connect to the Trojan proxy with SO_MARK set.
    async fn connect_with_mark(&self) -> Result<TcpStream, TrojanError> {
        // Shared host-ns-aware TCP connect (SO_MARK + IP_TRANSPARENT + host NS).
        crate::hostns::connect_tcp(
            self.proxy_addr,
            &crate::hostns::DirectSocket {
                self_mark: self.self_mark,
                host_ns_fd: self.host_ns_fd,
            },
            true,
            self.dial_timeout,
        )
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::TimedOut {
                TrojanError::Timeout(format!("connect to proxy {}", self.proxy_addr))
            } else {
                TrojanError::Io(e)
            }
        })
    }

    /// Create TLS connector
    fn create_tls_connector(&self) -> Result<TlsConnector, TrojanError> {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(TlsConnector::from(Arc::new(config)))
    }

    /// Perform TLS handshake
    async fn tls_handshake(
        &self,
        stream: TcpStream,
    ) -> Result<TlsStream<TcpStream>, TrojanError> {
        let connector = self.create_tls_connector()?;
        
        let sni = if self.sni.is_empty() {
            self.proxy_addr.ip().to_string()
        } else {
            self.sni.clone()
        };

        let domain = ServerName::try_from(sni)
            .map_err(|e| TrojanError::Tls(format!("invalid SNI: {}", e)))?;

        let tls_stream = connector
            .connect(domain, stream)
            .await
            .map_err(|e| TrojanError::Tls(format!("TLS handshake failed: {}", e)))?;

        Ok(tls_stream)
    }

    /// Calculate Trojan authentication hash (hex of SHA224(password))
    fn auth_hash(&self) -> String {
        let mut hasher = Sha224::new();
        hasher.update(self.password.as_bytes());
        let hash = hasher.finalize();
        hex::encode(hash)
    }

    /// Build Trojan request header: CRLF + HASH + CRLF + CMD + CRLF + ADDR + CRLF
    fn build_header(&self, cmd: u8, host: &str, port: u16) -> Result<Vec<u8>, TrojanError> {
        // Trojan protocol header:
        // CRLF(2) + HASH(56) + CRLF(2) + CMD(1) + CRLF(2) + ATYP(1) + ADDR + PORT(2) + CRLF(2)
        let mut header = Vec::new();
        header.extend_from_slice(b"\r\n");
        header.extend_from_slice(self.auth_hash().as_bytes());
        header.extend_from_slice(b"\r\n");
        header.push(cmd);
        header.extend_from_slice(b"\r\n");
        header.extend_from_slice(&encode_addr(host, port)?);
        header.extend_from_slice(b"\r\n");
        Ok(header)
    }

    /// Perform Trojan handshake
    async fn handshake(
        &self,
        stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
        target: &str,
    ) -> Result<(), TrojanError> {
        let (host, port) = split_target(target)?;
        let header = self.build_header(0x01, host, port)?;
        stream.write_all(&header).await?;
        Ok(())
    }
}

/// Split `host:port` target string (supports [ipv6]:port)
fn split_target(target: &str) -> Result<(&str, u16), TrojanError> {
    let (mut host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| TrojanError::ProtocolError(format!("invalid target '{}'", target)))?;
    let port: u16 = port
        .parse()
        .map_err(|_| TrojanError::ProtocolError(format!("invalid target port '{}'", target)))?;
    if host.starts_with('[') && host.ends_with(']') {
        host = &host[1..host.len() - 1];
    }
    Ok((host, port))
}

/// 编码 Trojan 地址：ATYP + ADDR + PORT（1=IPv4, 3=Domain name, 4=IPv6）
fn encode_addr(host: &str, port: u16) -> Result<Vec<u8>, TrojanError> {
    let mut addr = Vec::with_capacity(1 + 16 + 2);
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        addr.push(0x01);
        addr.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        addr.push(0x04);
        addr.extend_from_slice(&ip.octets());
    } else {
        let b = host.as_bytes();
        addr.push(0x03);
        addr.push(b.len() as u8);
        addr.extend_from_slice(b);
    }
    addr.extend_from_slice(&port.to_be_bytes());
    Ok(addr)
}

/// Decode Trojan address, return `(SocketAddr, bytes consumed)`
fn decode_addr(data: &[u8]) -> Result<(SocketAddr, usize), TrojanError> {
    if data.is_empty() {
        return Err(TrojanError::ProtocolError("empty address".into()));
    }
    match data[0] {
        0x01 => {
            if data.len() < 7 {
                return Err(TrojanError::ProtocolError("short ipv4".into()));
            }
            let ip = std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            Ok((
                SocketAddr::from((ip, u16::from_be_bytes([data[5], data[6]]))),
                7,
            ))
        }
        0x04 => {
            if data.len() < 19 {
                return Err(TrojanError::ProtocolError("short ipv6".into()));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let ip = std::net::Ipv6Addr::from(octets);
            Ok((
                SocketAddr::from((ip, u16::from_be_bytes([data[17], data[18]]))),
                19,
            ))
        }
        0x03 => {
            if data.len() < 2 {
                return Err(TrojanError::ProtocolError("short domain".into()));
            }
            let len = data[1] as usize;
            if data.len() < 2 + len + 2 {
                return Err(TrojanError::ProtocolError("short domain".into()));
            }
            let port = u16::from_be_bytes([data[2 + len], data[3 + len]]);
            Ok((SocketAddr::from(([0, 0, 0, 0], port)), 2 + len + 2))
        }
        other => Err(TrojanError::ProtocolError(format!(
            "unknown address type: {}",
            other
        ))),
    }
}

#[async_trait]
impl OutboundDialer for TrojanDialer {
    async fn dial(&self, target: &str) -> anyhow::Result<ProxyConn> {
        // 1. TCP connect to proxy (host-ns aware)
        let stream = self.connect_with_mark().await?;

        // 2. TLS handshake
        let mut tls_stream = self.tls_handshake(stream).await?;

        // 3. Trojan handshake (auth + target address)
        self.handshake(&mut tls_stream, target).await?;

        // 4. Return the TLS stream as a boxed duplex stream
        Ok(ProxyConn::new_boxed(Box::new(tls_stream)))
    }

    /// Establish Trojan UDP relay session.
    ///
    /// 1. Establish TLS control connection and send UDP ASSOCIATE (CMD=0x03) command;
    /// 2. UDP datagram sent directly to proxy server, format `[ATYP][ADDR][PORT][LEN(2)][PAYLOAD]`.
    async fn udp_dial(&self) -> anyhow::Result<Box<dyn crate::UdpSession>> {
        // Control connection: TLS + UDP ASSOCIATE command (address 0.0.0.0:0)
        let tcp = self.connect_with_mark().await?;
        let mut control = self.tls_handshake(tcp).await?;
        let header = self.build_header(0x03, "0.0.0.0", 0)?;
        control.write_all(&header).await?;

        // UDP socket (host NS, connecting to proxy server)
        let socket = crate::hostns::create_udp(
            self.proxy_addr,
            &crate::hostns::DirectSocket {
                self_mark: self.self_mark,
                host_ns_fd: self.host_ns_fd,
            },
        )
        .map_err(TrojanError::Io)?;
        socket.connect(self.proxy_addr).map_err(TrojanError::Io)?;
        let socket = tokio::net::UdpSocket::from_std(socket).map_err(TrojanError::Io)?;

        Ok(Box::new(TrojanUdpSession { control, socket }))
    }

    fn protocol_name(&self) -> &'static str {
        "trojan"
    }
    fn proxy_addr(&self) -> std::net::SocketAddr {
        self.proxy_addr
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Trojan UDP relay session (control connection keepalive + UDP datagram forwarding).
pub struct TrojanUdpSession {
    /// TLS control connection (kept alive to maintain server's UDP allowance)
    #[allow(dead_code)]
    control: tokio_rustls::client::TlsStream<TcpStream>,
    /// UDP data socket (host NS, connecting to proxy server)
    socket: tokio::net::UdpSocket,
}

#[async_trait]
impl crate::UdpSession for TrojanUdpSession {
    async fn send(&self, dest: &SocketAddr, payload: &[u8]) -> anyhow::Result<()> {
        // [ATYP][ADDR][PORT][LEN(2)][PAYLOAD]
        let mut datagram = Vec::with_capacity(1 + 16 + 2 + 2 + payload.len());
        datagram.extend_from_slice(&encode_addr(&dest.ip().to_string(), dest.port())?);
        datagram.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        datagram.extend_from_slice(payload);
        self.socket.send(&datagram).await?;
        Ok(())
    }

    async fn recv(&self) -> anyhow::Result<(SocketAddr, Vec<u8>)> {
        let mut buf = vec![0u8; 65535];
        let len = self.socket.recv(&mut buf).await?;
        let (dest, consumed) = decode_addr(&buf[..len])?;
        if len < consumed + 2 {
            return Err(anyhow::anyhow!("trojan udp: short packet"));
        }
        let pkt_len = u16::from_be_bytes([buf[consumed], buf[consumed + 1]]) as usize;
        if len < consumed + 2 + pkt_len {
            return Err(anyhow::anyhow!("trojan udp: truncated payload"));
        }
        Ok((dest, buf[consumed + 2..consumed + 2 + pkt_len].to_vec()))
    }
}
