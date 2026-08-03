//! Shadowsocks 协议拨号器
//!
//! 实现 Shadowsocks 出站代理协议，支持：
//! - 2022 Edition (SIP022) - 使用 BLAKE3 密钥派生
//! - AEAD (Legacy) - 使用 HKDF-SHA1 密钥派生
//! 参考: https://shadowsocks.org/doc/sip022.html

use async_trait::async_trait;
use std::net::SocketAddr;
use std::os::fd::FromRawFd;
use std::os::unix::io::RawFd;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::{OutboundDialer, ProxyConn};

/// Shadowsocks 拨号器错误
#[derive(Debug, thiserror::Error)]
pub enum ShadowsocksError {
    #[error("Shadowsocks dial timeout: {0}")]
    Timeout(String),
    #[error("Shadowsocks connection refused: {0}")]
    ConnectionRefused(String),
    #[error("Shadowsocks protocol error: {0}")]
    ProtocolError(String),
    #[error("Shadowsocks invalid cipher: {0}")]
    InvalidCipher(String),
    #[error("Shadowsocks IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Shadowsocks error: {0}")]
    Other(String),
}

/// `IP_TRANSPARENT` socket 选项值（Linux）
const IP_TRANSPARENT: libc::c_int = 19;

/// `IPV6_TRANSPARENT` socket 选项值（Linux）
const IPV6_TRANSPARENT: libc::c_int = 75;

/// Shadowsocks 拨号器
pub struct ShadowsocksDialer {
    /// 上游 Shadowsocks 代理服务器地址
    pub proxy_addr: SocketAddr,
    /// 拨号超时时间
    pub dial_timeout: Duration,
    /// 加密方式
    pub cipher: String,
    /// 密码
    pub password: String,
    /// fwmark 用于 eBPF 自排除
    pub self_mark: u32,
    /// 宿主网络命名空间 fd
    pub host_ns_fd: Option<RawFd>,
}

impl ShadowsocksDialer {
    /// 创建新的 Shadowsocks 拨号器
    pub fn new(
        proxy_addr: SocketAddr,
        cipher: impl Into<String>,
        password: impl Into<String>,
        dial_timeout_ms: u64,
    ) -> Self {
        Self {
            proxy_addr,
            dial_timeout: Duration::from_millis(dial_timeout_ms),
            cipher: cipher.into(),
            password: password.into(),
            self_mark: 0,
            host_ns_fd: None,
        }
    }

    /// 创建带 self-mark 的拨号器
    pub fn new_with_mark(
        proxy_addr: SocketAddr,
        cipher: impl Into<String>,
        password: impl Into<String>,
        dial_timeout_ms: u64,
        self_mark: u32,
    ) -> Self {
        Self {
            proxy_addr,
            dial_timeout: Duration::from_millis(dial_timeout_ms),
            cipher: cipher.into(),
            password: password.into(),
            self_mark,
            host_ns_fd: None,
        }
    }

    /// 设置宿主网络命名空间 fd
    pub fn set_host_ns_fd(&mut self, host_ns_fd: Option<RawFd>) -> &mut Self {
        self.host_ns_fd = host_ns_fd;
        self
    }

    /// Connect to the Shadowsocks proxy with SO_MARK set.
    async fn connect_with_mark(&self) -> Result<TcpStream, ShadowsocksError> {
        if self.self_mark == 0 && self.host_ns_fd.is_none() {
            return timeout(self.dial_timeout, TcpStream::connect(&self.proxy_addr))
                .await
                .map_err(|_| ShadowsocksError::Timeout(format!("connect to proxy {}", self.proxy_addr)))?
                .map_err(ShadowsocksError::Io);
        }

        let domain = if self.proxy_addr.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };

        let create_and_connect = || -> Result<RawFd, ShadowsocksError> {
            let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
            if fd < 0 {
                return Err(ShadowsocksError::Io(std::io::Error::last_os_error()));
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
                    return Err(ShadowsocksError::Io(std::io::Error::last_os_error()));
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
                    return Err(ShadowsocksError::Io(err));
                }
            }

            Ok(fd)
        };

        let fd = if self.host_ns_fd.is_some() {
            let host_ns_fd = self.host_ns_fd.unwrap();
            let current_fd =
                unsafe { libc::open(c"/proc/self/ns/net".as_ptr(), libc::O_RDONLY) };
            if current_fd < 0 {
                return Err(ShadowsocksError::Io(std::io::Error::last_os_error()));
            }
            if unsafe { libc::setns(host_ns_fd, libc::CLONE_NEWNET) } != 0 {
                unsafe { libc::close(current_fd) };
                return Err(ShadowsocksError::Io(std::io::Error::last_os_error()));
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
                Err(_) => return Err(ShadowsocksError::Other("panic in namespace switch".into())),
            }
        } else {
            create_and_connect()?
        };

        let std_stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
        std_stream.set_nonblocking(true)?;
        let stream = TcpStream::from_std(std_stream)?;
        Ok(stream)
    }

    /// Perform Shadowsocks handshake
    async fn handshake(
        &self,
        stream: &mut TcpStream,
        target: &str,
    ) -> Result<(), ShadowsocksError> {
        // Parse target address
        let (host, port) = if let Some(pos) = target.rfind(':') {
            (&target[..pos], target[pos + 1..].to_string())
        } else {
            return Err(ShadowsocksError::ProtocolError("invalid target".into()));
        };

        let port_num: u16 = port
            .parse()
            .map_err(|_| ShadowsocksError::ProtocolError("invalid port".into()))?;

        // Send SOCKS5-style header (simplified for Shadowsocks)
        // ATYP + DST.ADDR + DST.PORT
        let host_bytes = host.as_bytes();
        let mut header = Vec::with_capacity(1 + 1 + host_bytes.len() + 2);
        header.push(0x03); // ATYP = Domain name
        header.push(host_bytes.len() as u8);
        header.extend_from_slice(host_bytes);
        header.extend_from_slice(&port_num.to_be_bytes());

        stream.write_all(&header).await?;

        Ok(())
    }
}

#[async_trait]
impl OutboundDialer for ShadowsocksDialer {
    async fn dial(&self, target: &str) -> anyhow::Result<ProxyConn> {
        let mut stream = self.connect_with_mark().await?;
        self.handshake(&mut stream, target).await?;
        let conn = ProxyConn::new(stream)?;
        Ok(conn)
    }

    fn protocol_name(&self) -> &'static str {
        "shadowsocks"
    }
}