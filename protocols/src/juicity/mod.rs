//! Juicity 协议拨号器
//!
//! 实现 Juicity 出站代理协议，基于 QUIC 传输。
//! 参考: https://github.com/juicity/juicity/blob/main/docs/spec.md

use async_trait::async_trait;
use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::{OutboundDialer, ProxyConn};

/// Juicity 拨号器错误
#[derive(Debug, thiserror::Error)]
pub enum JuicityError {
    #[error("Juicity dial timeout: {0}")]
    Timeout(String),
    #[error("Juicity connection refused: {0}")]
    ConnectionRefused(String),
    #[error("Juicity protocol error: {0}")]
    ProtocolError(String),
    #[error("Juicity IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Juicity error: {0}")]
    Other(String),
}

/// Juicity 拨号器
pub struct JuicityDialer {
    /// 上游 Juicity 服务器地址
    pub proxy_addr: SocketAddr,
    /// 拨号超时时间
    pub dial_timeout: Duration,
    /// 用户 UUID
    pub uuid: String,
    /// 认证密码
    pub password: String,
    /// TLS SNI
    pub sni: String,
    /// 证书 SHA256 指纹
    pub ca_sha256: Option<String>,
    /// fwmark 用于 eBPF 自排除
    pub self_mark: u32,
    /// 宿主网络命名空间 fd
    pub host_ns_fd: Option<RawFd>,
}

impl JuicityDialer {
    /// 创建新的 Juicity 拨号器
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
            sni: String::new(),
            ca_sha256: None,
            self_mark: 0,
            host_ns_fd: None,
        }
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

    /// Connect to Juicity server (TCP fallback for now)
    async fn connect(&self) -> Result<TcpStream, JuicityError> {
        // Note: Full Juicity implementation requires QUIC
        // This is a TCP-based placeholder
        timeout(self.dial_timeout, TcpStream::connect(&self.proxy_addr))
            .await
            .map_err(|_| JuicityError::Timeout(format!("connect to {}", self.proxy_addr)))?
            .map_err(JuicityError::Io)
    }
}

#[async_trait]
impl OutboundDialer for JuicityDialer {
    async fn dial(&self, target: &str) -> anyhow::Result<ProxyConn> {
        let mut stream = self.connect().await?;

        // Send target address (simplified)
        stream.write_all(target.as_bytes()).await?;

        let conn = ProxyConn::new(stream)?;
        Ok(conn)
    }

    fn protocol_name(&self) -> &'static str {
        "juicity"
    }
}