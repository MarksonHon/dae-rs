//! TUIC v5 协议拨号器
//!
//! 实现 TUIC v5 出站代理协议，基于 QUIC 传输。
//! 参考: https://github.com/tuic-protocol/tuic/blob/master/SPEC.md

use async_trait::async_trait;
use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::{OutboundDialer, ProxyConn};

/// TUIC 拨号器错误
#[derive(Debug, thiserror::Error)]
pub enum TuicError {
    #[error("TUIC dial timeout: {0}")]
    Timeout(String),
    #[error("TUIC connection refused: {0}")]
    ConnectionRefused(String),
    #[error("TUIC protocol error: {0}")]
    ProtocolError(String),
    #[error("TUIC IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TUIC error: {0}")]
    Other(String),
}

/// TUIC v5 拨号器
pub struct TuicDialer {
    /// 上游 TUIC 服务器地址
    pub proxy_addr: SocketAddr,
    /// 拨号超时时间
    pub dial_timeout: Duration,
    /// 用户 UUID
    pub uuid: String,
    /// 认证密码
    pub password: String,
    /// 拥塞控制算法
    pub congestion_control: String,
    /// ALPN 协议列表
    pub alpn: Vec<String>,
    /// TLS SNI
    pub sni: String,
    /// 证书 SHA256 指纹
    pub ca_sha256: Option<String>,
    /// fwmark 用于 eBPF 自排除
    pub self_mark: u32,
    /// 宿主网络命名空间 fd
    pub host_ns_fd: Option<RawFd>,
}

impl TuicDialer {
    /// 创建新的 TUIC 拨号器
    pub fn new(
        proxy_addr: SocketAddr,
        uuid: impl Into<String>,
        password: impl Into<String>,
        dial_timeout_ms: u64,
    ) -> Self {
        Self {
            proxy_addr,
            dial_timeout: Duration::from_millis(dial_timeout_ms),
            uuid: uuid.into(),
            password: password.into(),
            congestion_control: "bbr".into(),
            alpn: vec!["h3".into()],
            sni: String::new(),
            ca_sha256: None,
            self_mark: 0,
            host_ns_fd: None,
        }
    }

    /// 设置拥塞控制算法
    pub fn set_congestion_control(&mut self, cc: impl Into<String>) -> &mut Self {
        self.congestion_control = cc.into();
        self
    }

    /// 设置 ALPN 协议
    pub fn set_alpn(&mut self, alpn: Vec<String>) -> &mut Self {
        self.alpn = alpn;
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

    /// Connect to TUIC server (TCP fallback for now)
    async fn connect(&self) -> Result<TcpStream, TuicError> {
        // Note: Full TUIC implementation requires QUIC
        // This is a TCP-based placeholder
        timeout(self.dial_timeout, TcpStream::connect(&self.proxy_addr))
            .await
            .map_err(|_| TuicError::Timeout(format!("connect to {}", self.proxy_addr)))?
            .map_err(TuicError::Io)
    }
}

#[async_trait]
impl OutboundDialer for TuicDialer {
    async fn dial(&self, target: &str) -> anyhow::Result<ProxyConn> {
        let mut stream = self.connect().await?;

        // Send target address (simplified)
        stream.write_all(target.as_bytes()).await?;

        let conn = ProxyConn::new(stream)?;
        Ok(conn)
    }

    fn protocol_name(&self) -> &'static str {
        "tuic"
    }
}