//! 协议层（Protocols）
//!
//! 本模块提供统一的出站拨号接口和协议实现。
//! - `OutboundDialer` trait：定义统一出站接口
//! - `Socks5Dialer`：SOCKS5 协议拨号器实现
//! - `ProxyConn`：代理连接类型
//!
//! 第一阶段仅实现 SOCKS5 出站，预留扩展点以接入其他协议。

pub mod socks5;

use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// 代理连接类型
///
/// 封装已建立的代理连接，提供双向读写能力。
pub struct ProxyConn {
    /// 底层 TCP 流
    pub stream: TcpStream,
    /// 目标地址（对端）
    pub peer_addr: SocketAddr,
    /// 本地地址
    pub local_addr: SocketAddr,
}

impl ProxyConn {
    /// 创建新的代理连接
    pub fn new(stream: TcpStream) -> std::io::Result<Self> {
        let peer_addr = stream.peer_addr()?;
        let local_addr = stream.local_addr()?;
        Ok(Self {
            stream,
            peer_addr,
            local_addr,
        })
    }
}

impl AsyncRead for ProxyConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProxyConn {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// 出站拨号器统一接口
///
/// 所有出站协议（SOCKS5、HTTP 代理等）需实现此 trait。
#[async_trait]
pub trait OutboundDialer: Send + Sync {
    /// 拨号到目标地址
    ///
    /// 通过代理协议与上游代理服务器建立连接，并返回已连接到
    /// 最终目标的 `ProxyConn`。
    async fn dial(&self, target: &str) -> anyhow::Result<ProxyConn>;

    /// 返回出站协议名称
    fn protocol_name(&self) -> &'static str;
}
