//! Trojan 协议拨号器
//!
//! 实现 Trojan 出站代理协议，基于 TLS 传输，伪装成 HTTPS 流量。
//! 参考: https://github.com/trojan-gfw/trojan/blob/master/docs/protocol.md

use async_trait::async_trait;
use sha2::{Sha224, Digest};
use std::net::SocketAddr;
use std::os::fd::FromRawFd;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{TlsConnector, client::TlsStream};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};

use crate::{OutboundDialer, ProxyConn};

/// Trojan 拨号器错误
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

/// `IP_TRANSPARENT` socket 选项值（Linux）
const IP_TRANSPARENT: libc::c_int = 19;

/// `IPV6_TRANSPARENT` socket 选项值（Linux）
const IPV6_TRANSPARENT: libc::c_int = 75;

/// Trojan 拨号器
pub struct TrojanDialer {
    /// 上游 Trojan 服务器地址
    pub proxy_addr: SocketAddr,
    /// 拨号超时时间
    pub dial_timeout: Duration,
    /// 认证密码
    pub password: String,
    /// TLS SNI
    pub sni: String,
    /// 证书 SHA256 指纹（用于证书固定）
    pub ca_sha256: Option<String>,
    /// fwmark 用于 eBPF 自排除
    pub self_mark: u32,
    /// 宿主网络命名空间 fd
    pub host_ns_fd: Option<RawFd>,
}

impl TrojanDialer {
    /// 创建新的 Trojan 拨号器
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

    /// 创建带 self-mark 的拨号器
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

    /// 设置证书 SHA256 指纹
    pub fn set_ca_sha256(&mut self, ca_sha256: Option<String>) -> &mut Self {
        self.ca_sha256 = ca_sha256;
        self
    }

    /// 设置宿主网络命名空间 fd
    pub fn set_host_ns_fd(&mut self, host_ns_fd: Option<RawFd>) -> &mut Self {
        self.host_ns_fd = host_ns_fd;
        self
    }

    /// Connect to the Trojan proxy with SO_MARK set.
    async fn connect_with_mark(&self) -> Result<TcpStream, TrojanError> {
        if self.self_mark == 0 && self.host_ns_fd.is_none() {
            return timeout(self.dial_timeout, TcpStream::connect(&self.proxy_addr))
                .await
                .map_err(|_| TrojanError::Timeout(format!("connect to proxy {}", self.proxy_addr)))?
                .map_err(TrojanError::Io);
        }

        let domain = if self.proxy_addr.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };

        let create_and_connect = || -> Result<RawFd, TrojanError> {
            let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
            if fd < 0 {
                return Err(TrojanError::Io(std::io::Error::last_os_error()));
            }

            if self.self_mark != 0 {
                let mark_val = self.self_mark as libc::c_int;
                let ret = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_MARK,
                        &mark_val as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
                if ret != 0 {
                    unsafe { libc::close(fd) };
                    return Err(TrojanError::Io(std::io::Error::last_os_error()));
                }
            }

            let one: libc::c_int = 1;
            let (level, opt): (libc::c_int, libc::c_int) = if self.proxy_addr.is_ipv4() {
                (libc::SOL_IP, IP_TRANSPARENT)
            } else {
                (libc::SOL_IPV6, IPV6_TRANSPARENT)
            };
            unsafe {
                libc::setsockopt(
                    fd,
                    level,
                    opt,
                    &one as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }

            let sockaddr = socket2::SockAddr::from(self.proxy_addr);
            let ret = unsafe {
                libc::connect(
                    fd,
                    sockaddr.as_ptr() as *const libc::sockaddr,
                    sockaddr.len(),
                )
            };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::WouldBlock {
                    unsafe { libc::close(fd) };
                    return Err(TrojanError::Io(err));
                }
            }

            Ok(fd)
        };

        let fd = if self.host_ns_fd.is_some() {
            let host_ns_fd = self.host_ns_fd.unwrap();
            let current_fd =
                unsafe { libc::open(c"/proc/self/ns/net".as_ptr(), libc::O_RDONLY) };
            if current_fd < 0 {
                return Err(TrojanError::Io(std::io::Error::last_os_error()));
            }
            if unsafe { libc::setns(host_ns_fd, libc::CLONE_NEWNET) } != 0 {
                unsafe { libc::close(current_fd) };
                return Err(TrojanError::Io(std::io::Error::last_os_error()));
            }
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                create_and_connect()
            }));
            if unsafe { libc::setns(current_fd, libc::CLONE_NEWNET) } != 0 {
                tracing::warn!("Failed to return to original netns");
            }
            unsafe { libc::close(current_fd) };
            match result {
                Ok(Ok(fd)) => fd,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(TrojanError::Other("panic in namespace switch".into())),
            }
        } else {
            create_and_connect()?
        };

        // Convert raw fd to std TcpStream then to tokio TcpStream
        let std_stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
        std_stream.set_nonblocking(true)?;
        let stream = TcpStream::from_std(std_stream)?;
        Ok(stream)
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

    /// Perform Trojan handshake
    async fn handshake(
        &self,
        stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
        target: &str,
    ) -> Result<(), TrojanError> {
        // Parse target
        let (host, port) = if let Some(pos) = target.rfind(':') {
            (&target[..pos], target[pos + 1..].to_string())
        } else {
            return Err(TrojanError::ProtocolError("invalid target".into()));
        };

        let port_num: u16 = port
            .parse()
            .map_err(|_| TrojanError::ProtocolError("invalid port".into()))?;

        // Trojan protocol header:
        // CRLF(2 bytes) + HASH(56 bytes) + CRLF(2 bytes) + CMD(1 byte) + CRLF(2 bytes) + ATYP(1 byte) + ADDR + PORT(2 bytes) + CRLF(2 bytes)
        
        // 1. Calculate SHA224(password)
        let mut hasher = Sha224::new();
        hasher.update(self.password.as_bytes());
        let hash = hasher.finalize();
        let hash_hex = hex::encode(hash);

        // 2. Build header
        let mut header = Vec::new();
        
        // CRLF
        header.extend_from_slice(b"\r\n");
        
        // HASH (56 hex chars = 28 bytes SHA224)
        header.extend_from_slice(hash_hex.as_bytes());
        
        // CRLF
        header.extend_from_slice(b"\r\n");
        
        // CMD: 0x01 = CONNECT
        header.push(0x01);
        
        // CRLF
        header.extend_from_slice(b"\r\n");
        
        // ATYP: 0x03 = Domain
        header.push(0x03);
        
        // ADDR: domain length + domain
        let host_bytes = host.as_bytes();
        header.push(host_bytes.len() as u8);
        header.extend_from_slice(host_bytes);
        
        // PORT
        header.extend_from_slice(&port_num.to_be_bytes());
        
        // CRLF
        header.extend_from_slice(b"\r\n");

        stream.write_all(&header).await?;

        Ok(())
    }
}

#[async_trait]
impl OutboundDialer for TrojanDialer {
    async fn dial(&self, target: &str) -> anyhow::Result<ProxyConn> {
        // 1. TCP connect to proxy
        let stream = self.connect_with_mark().await?;
        
        // 2. TLS handshake
        let mut tls_stream = self.tls_handshake(stream).await?;
        
        // 3. Trojan handshake
        self.handshake(&mut tls_stream, target).await?;
        
        // 4. Get the inner TCP stream back
        // Note: tokio-rustls TlsStream doesn't have into_inner() in async context
        // We need to split and handle differently
        // For now, return error - this needs proper implementation
        Err(anyhow::anyhow!("Trojan dialer needs further implementation"))
    }

    fn protocol_name(&self) -> &'static str {
        "trojan"
    }
}
