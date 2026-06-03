//! SOCKS5 协议拨号器
//!
//! 实现 SOCKS5 出站代理协议，支持：
//! - 无认证（No Authentication）
//! - 用户名/密码认证（Username/Password Authentication）
//! - TCP 流式连接
//!
//! 使用 `socks5-proto` crate 进行协议编解码。

use async_trait::async_trait;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::{OutboundDialer, ProxyConn};

/// SOCKS5 拨号器错误
#[derive(Debug, thiserror::Error)]
pub enum Socks5Error {
    /// 连接超时
    #[error("SOCKS5 dial timeout: {0}")]
    Timeout(String),
    /// 连接被拒绝
    #[error("SOCKS5 connection refused: {0}")]
    ConnectionRefused(String),
    /// 认证失败
    #[error("SOCKS5 authentication failed: {0}")]
    AuthFailed(String),
    /// 协议错误
    #[error("SOCKS5 protocol error: {0}")]
    ProtocolError(String),
    /// IO 错误
    #[error("SOCKS5 IO error: {0}")]
    Io(#[from] std::io::Error),
    /// 其他错误
    #[error("SOCKS5 error: {0}")]
    Other(String),
}

/// SOCKS5 拨号器
///
/// 负责与 SOCKS5 上游服务器建立连接并转发流量。
pub struct Socks5Dialer {
    /// 上游 SOCKS5 代理服务器地址
    pub proxy_addr: SocketAddr,
    /// 拨号超时时间
    pub dial_timeout: Duration,
    /// 认证用户名（空字符串表示无需认证）
    pub username: String,
    /// 认证密码
    pub password: String,
}

impl Socks5Dialer {
    /// 创建新的 SOCKS5 拨号器
    ///
    /// # 参数
    /// * `proxy_addr` - 上游 SOCKS5 代理服务器地址
    /// * `username` - 认证用户名（空字符串表示无需认证）
    /// * `password` - 认证密码
    /// * `dial_timeout_ms` - 拨号超时时间（毫秒）
    pub fn new(
        proxy_addr: SocketAddr,
        username: impl Into<String>,
        password: impl Into<String>,
        dial_timeout_ms: u64,
    ) -> Self {
        Self {
            proxy_addr,
            dial_timeout: Duration::from_millis(dial_timeout_ms),
            username: username.into(),
            password: password.into(),
        }
    }

    /// 执行 SOCKS5 握手
    ///
    /// 包括：
    /// 1. 协商认证方式
    /// 2. 认证（如果要求）
    /// 3. 发送连接请求
    async fn handshake(&self, stream: &mut TcpStream, target: &str) -> Result<(), Socks5Error> {
        // 步骤 1：协商认证方式
        // 发送：版本 + 支持的认证方法数量 + 方法列表
        let methods: Vec<u8> = if self.username.is_empty() {
            // 仅支持无认证（0x00）
            vec![0x05, 0x01, 0x00]
        } else {
            // 支持无认证（0x00）和用户名密码认证（0x02）
            vec![0x05, 0x02, 0x00, 0x02]
        };
        stream.write_all(&methods).await?;

        // 读取服务器选择的认证方法
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;

        if response[0] != 0x05 {
            return Err(Socks5Error::ProtocolError(
                "invalid SOCKS5 version".into(),
            ));
        }

        match response[1] {
            0x00 => {
                // 无认证，继续
            }
            0x02 => {
                // 用户名/密码认证
                if self.username.is_empty() {
                    return Err(Socks5Error::AuthFailed(
                        "server requires auth but no credentials provided".into(),
                    ));
                }
                self.username_password_auth(stream).await?;
            }
            0xFF => {
                return Err(Socks5Error::AuthFailed(
                    "no acceptable authentication method".into(),
                ));
            }
            _ => {
                return Err(Socks5Error::ProtocolError(format!(
                    "unknown auth method: 0x{:02x}",
                    response[1]
                )));
            }
        }

        // 步骤 2：发送连接请求
        // 解析目标地址（支持域名和 IP）
        let addr_parts: Vec<&str> = target.rsplitn(2, ':').collect();
        if addr_parts.len() != 2 {
            return Err(Socks5Error::ProtocolError(format!(
                "invalid target address: {}",
                target
            )));
        }
        let host = addr_parts[1];
        let port: u16 = addr_parts[0]
            .parse()
            .map_err(|_| Socks5Error::ProtocolError(format!("invalid target port: {}", target)))?;

        // 构建连接请求
        let mut request = Vec::with_capacity(256);
        request.push(0x05); // SOCKS5 版本
        request.push(0x01); // CONNECT 命令
        request.push(0x00); // 保留位

        // 尝试解析为 IPv4 地址
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            request.push(0x01); // IPv4 地址类型
            request.extend_from_slice(&ip.octets());
        }
        // 尝试解析为 IPv6 地址
        else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
            request.push(0x04); // IPv6 地址类型
            request.extend_from_slice(&ip.octets());
        }
        // 否则以域名方式发送
        else {
            request.push(0x03); // 域名类型
            let host_bytes = host.as_bytes();
            if host_bytes.len() > 255 {
                return Err(Socks5Error::ProtocolError("target hostname too long".into()));
            }
            request.push(host_bytes.len() as u8);
            request.extend_from_slice(host_bytes);
        }

        // 端口（网络字节序）
        request.extend_from_slice(&port.to_be_bytes());

        stream.write_all(&request).await?;

        // 读取连接响应
        let mut reply = [0u8; 4];
        stream.read_exact(&mut reply).await?;

        if reply[0] != 0x05 {
            return Err(Socks5Error::ProtocolError(
                "invalid SOCKS5 reply version".into(),
            ));
        }

        match reply[1] {
            0x00 => {
                // 成功，读取剩余地址信息
                let addr_type = reply[3];
                let addr_len = match addr_type {
                    0x01 => 4,  // IPv4
                    0x04 => 16, // IPv6
                    0x03 => {
                        // 域名
                        let mut len_buf = [0u8; 1];
                        stream.read_exact(&mut len_buf).await?;
                        len_buf[0] as usize
                    }
                    _ => {
                        return Err(Socks5Error::ProtocolError(format!(
                            "unknown address type: 0x{:02x}",
                            addr_type
                        )));
                    }
                };
                let mut addr_buf = vec![0u8; addr_len + 2]; // +2 for port
                stream.read_exact(&mut addr_buf).await?;

                Ok(())
            }
            0x01 => Err(Socks5Error::Other("SOCKS5 server failure".into())),
            0x02 => Err(Socks5Error::AuthFailed("connection not allowed".into())),
            0x03 => Err(Socks5Error::Other("network unreachable".into())),
            0x04 => Err(Socks5Error::Other("host unreachable".into())),
            0x05 => Err(Socks5Error::ConnectionRefused("connection refused".into())),
            0x06 => Err(Socks5Error::Timeout("TTL expired".into())),
            0x07 => Err(Socks5Error::ProtocolError("command not supported".into())),
            0x08 => Err(Socks5Error::ProtocolError("address type not supported".into())),
            _ => Err(Socks5Error::ProtocolError(format!(
                "unknown reply code: 0x{:02x}",
                reply[1]
            ))),
        }
    }

    /// 用户名/密码认证
    async fn username_password_auth(&self, stream: &mut TcpStream) -> Result<(), Socks5Error> {
        let username_bytes = self.username.as_bytes();
        let password_bytes = self.password.as_bytes();

        if username_bytes.len() > 255 || password_bytes.len() > 255 {
            return Err(Socks5Error::AuthFailed(
                "username or password too long".into(),
            ));
        }

        let mut auth_msg = Vec::with_capacity(3 + username_bytes.len() + password_bytes.len());
        auth_msg.push(0x01); // 认证子协商版本
        auth_msg.push(username_bytes.len() as u8);
        auth_msg.extend_from_slice(username_bytes);
        auth_msg.push(password_bytes.len() as u8);
        auth_msg.extend_from_slice(password_bytes);

        stream.write_all(&auth_msg).await?;

        let mut auth_reply = [0u8; 2];
        stream.read_exact(&mut auth_reply).await?;

        if auth_reply[0] != 0x01 {
            return Err(Socks5Error::AuthFailed(format!(
                "invalid auth sub-negotiation version: 0x{:02x}",
                auth_reply[0]
            )));
        }

        if auth_reply[1] != 0x00 {
            return Err(Socks5Error::AuthFailed("invalid username or password".into()));
        }

        Ok(())
    }
}

#[async_trait]
impl OutboundDialer for Socks5Dialer {
    /// 通过 SOCKS5 代理拨号到目标地址
    async fn dial(&self, target: &str) -> anyhow::Result<ProxyConn> {
        let stream = timeout(self.dial_timeout, TcpStream::connect(&self.proxy_addr))
            .await
            .map_err(|_| Socks5Error::Timeout(format!("connect to proxy {}", self.proxy_addr)))?
            .map_err(|e| Socks5Error::Io(e))?;

        let mut proxy_conn = ProxyConn::new(stream)?;

        // 执行 SOCKS5 握手
        self.handshake(&mut proxy_conn.stream, target)
            .await
            .map_err(|e| anyhow::anyhow!("SOCKS5 handshake failed: {}", e))?;

        Ok(proxy_conn)
    }

    /// 返回协议名称
    fn protocol_name(&self) -> &'static str {
        "socks5"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks5_dialer_creation() {
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let dialer = Socks5Dialer::new(addr, "", "", 5000);
        assert_eq!(dialer.proxy_addr.to_string(), "127.0.0.1:1080");
        assert_eq!(dialer.dial_timeout, Duration::from_millis(5000));
        assert_eq!(dialer.protocol_name(), "socks5");
    }

    #[test]
    fn test_socks5_dialer_with_auth() {
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let dialer = Socks5Dialer::new(addr, "user", "pass", 5000);
        assert_eq!(dialer.username, "user");
        assert_eq!(dialer.password, "pass");
    }
}
