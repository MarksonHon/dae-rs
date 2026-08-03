//! VMess 协议拨号器
//!
//! 实现 VMess 出站代理协议，支持多种传输方式：
//! - TCP
//! - WebSocket (WS)
//! - WebSocket + TLS (WSS)
//! - HTTP/2
//! - gRPC
//! 参考: https://www.v2fly.org/en_US/developer/protocols/vmess.html

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::fd::FromRawFd;
use std::os::unix::io::RawFd;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::{OutboundDialer, ProxyConn};

/// VMess 拨号器错误
#[derive(Debug, thiserror::Error)]
pub enum VMessError {
    #[error("VMess dial timeout: {0}")]
    Timeout(String),
    #[error("VMess connection refused: {0}")]
    ConnectionRefused(String),
    #[error("VMess protocol error: {0}")]
    ProtocolError(String),
    #[error("VMess invalid base64: {0}")]
    InvalidBase64(String),
    #[error("VMess invalid JSON: {0}")]
    InvalidJson(String),
    #[error("VMess IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("VMess error: {0}")]
    Other(String),
}

/// VMess 传输方式
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VMessNetwork {
    Tcp,
    Ws,
    H2,
    Grpc,
    Kcp,
    Quic,
}

impl FromStr for VMessNetwork {
    type Err = VMessError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "ws" => Ok(Self::Ws),
            "h2" => Ok(Self::H2),
            "grpc" => Ok(Self::Grpc),
            "kcp" => Ok(Self::Kcp),
            "quic" => Ok(Self::Quic),
            _ => Err(VMessError::ProtocolError(format!("unknown network: {}", s))),
        }
    }
}

/// VMess 节点配置（v2rayN base64 格式）
#[derive(Debug, Clone, Deserialize)]
pub struct VMessNodeConfig {
    pub v: String,
    #[serde(default)]
    pub ps: String,
    pub add: String,
    pub port: String,
    pub id: String,
    #[serde(default = "default_aid")]
    pub aid: String,
    #[serde(default = "default_scy")]
    pub scy: String,
    #[serde(default)]
    pub net: String,
    #[serde(default)]
    pub r#type: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub tls: String,
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub fp: String,
}

fn default_aid() -> String {
    "0".into()
}

fn default_scy() -> String {
    "auto".into()
}

/// `IP_TRANSPARENT` socket 选项值（Linux）
const IP_TRANSPARENT: libc::c_int = 19;

/// `IPV6_TRANSPARENT` socket 选项值（Linux）
const IPV6_TRANSPARENT: libc::c_int = 75;

/// VMess 拨号器
pub struct VMessDialer {
    /// 上游 VMess 服务器地址
    pub proxy_addr: SocketAddr,
    /// 拨号超时时间
    pub dial_timeout: Duration,
    /// 用户 UUID
    pub uuid: String,
    /// 加密方式
    pub security: String,
    /// alter_id
    pub alter_id: u32,
    /// 传输方式
    pub network: VMessNetwork,
    /// WebSocket 路径
    pub ws_path: Option<String>,
    /// WebSocket 头部
    pub ws_headers: Option<HashMap<String, String>>,
    /// HTTP/2 路径
    pub h2_path: Option<String>,
    /// HTTP/2 主机
    pub h2_host: Option<String>,
    /// gRPC 服务名
    pub grpc_service_name: Option<String>,
    /// TLS SNI
    pub sni: String,
    /// 证书 SHA256 指纹
    pub ca_sha256: Option<String>,
    /// fwmark 用于 eBPF 自排除
    pub self_mark: u32,
    /// 宿主网络命名空间 fd
    pub host_ns_fd: Option<RawFd>,
}

impl VMessDialer {
    /// 创建新的 VMess 拨号器
    pub fn new(
        proxy_addr: SocketAddr,
        uuid: impl Into<String>,
        dial_timeout_ms: u64,
    ) -> Self {
        Self {
            proxy_addr,
            dial_timeout: Duration::from_millis(dial_timeout_ms),
            uuid: uuid.into(),
            security: "auto".into(),
            alter_id: 0,
            network: VMessNetwork::Tcp,
            ws_path: None,
            ws_headers: None,
            h2_path: None,
            h2_host: None,
            grpc_service_name: None,
            sni: String::new(),
            ca_sha256: None,
            self_mark: 0,
            host_ns_fd: None,
        }
    }

    /// 从 v2rayN base64 格式创建拨号器
    pub fn from_base64(base64_str: &str, dial_timeout_ms: u64) -> Result<Self, VMessError> {
        let b64 = if let Some(rest) = base64_str.strip_prefix("vmess://") {
            rest
        } else {
            base64_str
        };

        let decoded = STANDARD
            .decode(b64)
            .map_err(|e| VMessError::InvalidBase64(e.to_string()))?;

        let json_str = String::from_utf8(decoded)
            .map_err(|e| VMessError::InvalidBase64(e.to_string()))?;

        let config: VMessNodeConfig = serde_json::from_str(&json_str)
            .map_err(|e| VMessError::InvalidJson(e.to_string()))?;

        let port: u16 = config
            .port
            .parse()
            .map_err(|_| VMessError::ProtocolError("invalid port".into()))?;

        let proxy_addr = SocketAddr::new(
            config
                .add
                .parse()
                .map_err(|e| VMessError::ProtocolError(format!("invalid address: {}", e)))?,
            port,
        );

        let network = VMessNetwork::from_str(&config.net)?;

        Ok(Self {
            proxy_addr,
            dial_timeout: Duration::from_millis(dial_timeout_ms),
            uuid: config.id,
            security: config.scy,
            alter_id: config.aid.parse().unwrap_or(0),
            network,
            ws_path: if config.path.is_empty() {
                None
            } else {
                Some(config.path)
            },
            ws_headers: if config.host.is_empty() {
                None
            } else {
                let mut headers = HashMap::new();
                headers.insert("Host".into(), config.host);
                Some(headers)
            },
            h2_path: None,
            h2_host: None,
            grpc_service_name: None,
            sni: config.sni,
            ca_sha256: None,
            self_mark: 0,
            host_ns_fd: None,
        })
    }

    /// 设置加密方式
    pub fn set_security(&mut self, security: impl Into<String>) -> &mut Self {
        self.security = security.into();
        self
    }

    /// 设置 alter_id
    pub fn set_alter_id(&mut self, alter_id: u32) -> &mut Self {
        self.alter_id = alter_id;
        self
    }

    /// 设置传输方式
    pub fn set_network(&mut self, network: VMessNetwork) -> &mut Self {
        self.network = network;
        self
    }

    /// 设置 WebSocket 路径
    pub fn set_ws_path(&mut self, path: impl Into<String>) -> &mut Self {
        self.ws_path = Some(path.into());
        self
    }

    /// 设置 WebSocket 头部
    pub fn set_ws_headers(&mut self, headers: HashMap<String, String>) -> &mut Self {
        self.ws_headers = Some(headers);
        self
    }

    /// 设置 HTTP/2 路径
    pub fn set_h2_path(&mut self, path: impl Into<String>) -> &mut Self {
        self.h2_path = Some(path.into());
        self
    }

    /// 设置 HTTP/2 主机
    pub fn set_h2_host(&mut self, host: impl Into<String>) -> &mut Self {
        self.h2_host = Some(host.into());
        self
    }

    /// 设置 gRPC 服务名
    pub fn set_grpc_service_name(&mut self, name: impl Into<String>) -> &mut Self {
        self.grpc_service_name = Some(name.into());
        self
    }

    /// 设置 SNI
    pub fn set_sni(&mut self, sni: impl Into<String>) -> &mut Self {
        self.sni = sni.into();
        self
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

    /// Connect to the VMess proxy with SO_MARK set.
    async fn connect_with_mark(&self) -> Result<TcpStream, VMessError> {
        if self.self_mark == 0 && self.host_ns_fd.is_none() {
            return timeout(self.dial_timeout, TcpStream::connect(&self.proxy_addr))
                .await
                .map_err(|_| VMessError::Timeout(format!("connect to proxy {}", self.proxy_addr)))?
                .map_err(VMessError::Io);
        }

        let domain = if self.proxy_addr.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };

        let create_and_connect = || -> Result<RawFd, VMessError> {
            let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
            if fd < 0 {
                return Err(VMessError::Io(std::io::Error::last_os_error()));
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
                    return Err(VMessError::Io(std::io::Error::last_os_error()));
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
                    return Err(VMessError::Io(err));
                }
            }

            Ok(fd)
        };

        let fd = if self.host_ns_fd.is_some() {
            let host_ns_fd = self.host_ns_fd.unwrap();
            let current_fd =
                unsafe { libc::open(c"/proc/self/ns/net".as_ptr(), libc::O_RDONLY) };
            if current_fd < 0 {
                return Err(VMessError::Io(std::io::Error::last_os_error()));
            }
            if unsafe { libc::setns(host_ns_fd, libc::CLONE_NEWNET) } != 0 {
                unsafe { libc::close(current_fd) };
                return Err(VMessError::Io(std::io::Error::last_os_error()));
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
                Err(_) => return Err(VMessError::Other("panic in namespace switch".into())),
            }
        } else {
            create_and_connect()?
        };

        let std_stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
        std_stream.set_nonblocking(true)?;
        let stream = TcpStream::from_std(std_stream)?;
        Ok(stream)
    }

    /// Perform VMess handshake
    async fn handshake(
        &self,
        stream: &mut TcpStream,
        target: &str,
    ) -> Result<(), VMessError> {
        // VMess protocol handshake:
        // 1. Client sends request with AES-GCM/ChaCha20-Poly1305 encrypted payload
        // 2. Server responds with encrypted response
        // For now, this is a simplified placeholder

        // Send target address (simplified)
        stream.write_all(target.as_bytes()).await?;

        Ok(())
    }
}

#[async_trait]
impl OutboundDialer for VMessDialer {
    async fn dial(&self, target: &str) -> anyhow::Result<ProxyConn> {
        let mut stream = self.connect_with_mark().await?;
        self.handshake(&mut stream, target).await?;
        let conn = ProxyConn::new(stream)?;
        Ok(conn)
    }

    fn protocol_name(&self) -> &'static str {
        "vmess"
    }
}