//! TUIC v5 协议拨号器（基于 QUIC）
//!
//! 实现 TUIC v5 出站代理协议：
//! - QUIC 传输（quinn + rustls，ALPN `tuic-v5`，0-RTT 早期数据）
//! - `Authenticate` 命令：UUID + RFC 5705 Keying Material Exporter token
//! - `Connect` 命令：双向流上多路复用 TCP 连接
//! - BBR 拥塞控制
//!
//! 参考: https://github.com/tuic-protocol/tuic/blob/master/SPEC.md

use async_trait::async_trait;
use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::{ClientConfig as QuinnClientConfig, Endpoint as QuinnEndpoint, TokioRuntime};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::{OutboundDialer, ProxyConn};

/// TUIC 协议版本
const TUIC_VERSION: u8 = 0x05;
/// 命令类型
const CMD_AUTHENTICATE: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const CMD_PACKET: u8 = 0x02;
/// ALPN
const TUIC_ALPN: &[u8] = b"tuic-v5";

/// TUIC 拨号器错误
#[derive(Debug, thiserror::Error)]
pub enum TuicError {
    #[error("TUIC dial timeout: {0}")]
    Timeout(String),
    #[error("TUIC connection refused: {0}")]
    ConnectionRefused(String),
    #[error("TUIC TLS error: {0}")]
    Tls(String),
    #[error("TUIC QUIC error: {0}")]
    Quic(String),
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
    /// 懒创建的 QUIC endpoint + 连接（TUIC 连接可复用，多路复用流）
    state: Mutex<Option<QuinnConnection>>,
}

/// QUIC 连接状态（endpoint 保持存活，连接惰性建立）
struct QuinnConnection {
    #[allow(dead_code)]
    endpoint: QuinnEndpoint,
    conn: quinn::Connection,
    authenticated: bool,
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
            state: Mutex::new(None),
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

    /// 设置 fwmark 用于 eBPF 自排除（0 表示不设置）
    pub fn set_self_mark(&mut self, self_mark: u32) -> &mut Self {
        self.self_mark = self_mark;
        self
    }

    /// 设置宿主网络命名空间 fd
    pub fn set_host_ns_fd(&mut self, host_ns_fd: Option<RawFd>) -> &mut Self {
        self.host_ns_fd = host_ns_fd;
        self
    }

    /// 建立 QUIC 连接（0-RTT；已存在则复用）
    async fn ensure_connection(&self) -> Result<quinn::Connection, TuicError> {
        let mut guard = self.state.lock().await;
        if let Some(state) = guard.as_ref() {
            if state.conn.close_reason().is_none() {
                return Ok(state.conn.clone());
            }
        }

        // ---- 构造 rustls ClientConfig ----
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut crypto = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        // TUIC 必须使用 TLS 1.3
        crypto.alpn_protocols = if self.alpn.is_empty() {
            vec![TUIC_ALPN.to_vec()]
        } else {
            self.alpn.iter().map(|a| a.as_bytes().to_vec()).collect()
        };
        crypto.enable_early_data = true;

        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(crypto))
            .map_err(|e| TuicError::Tls(format!("quinn rustls config failed: {}", e)))?;
        let mut config = QuinnClientConfig::new(Arc::new(quic_crypto));

        // ---- TransportConfig ----
        let mut tp_cfg = quinn::TransportConfig::default();
        tp_cfg
            .max_concurrent_bidi_streams(1024u32.into())
            .max_concurrent_uni_streams(1024u32.into())
            .max_idle_timeout(None);
        // 允许 datagram（Heartbeat）
        tp_cfg.datagram_receive_buffer_size(Some(1024 * 1024));
        tp_cfg.datagram_send_buffer_size(1024 * 1024);
        match self.congestion_control.as_str() {
            "bbr" => tp_cfg.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default())),
            "cubic" => tp_cfg
                .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default())),
            "new_reno" => tp_cfg
                .congestion_controller_factory(Arc::new(quinn::congestion::NewRenoConfig::default())),
            _ => tp_cfg
                .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default())),
        };
        config.transport_config(Arc::new(tp_cfg));

        // ---- Endpoint（UDP socket 在宿主 NS 中创建）----
        let socket = crate::hostns::create_udp(
            self.proxy_addr,
            &crate::hostns::DirectSocket {
                self_mark: self.self_mark,
                host_ns_fd: self.host_ns_fd,
            },
        )
        .map_err(|e| TuicError::Other(format!("create UDP socket failed: {}", e)))?;
        let mut endpoint = QuinnEndpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(TokioRuntime),
        )
        .map_err(|e| TuicError::Other(format!("create QUIC endpoint failed: {}", e)))?;
        endpoint.set_default_client_config(config);

        // ---- Connect ----
        let sni = if self.sni.is_empty() {
            self.proxy_addr.ip().to_string()
        } else {
            self.sni.clone()
        };
        let _ = ServerName::try_from(sni.clone())
            .map_err(|e| TuicError::Tls(format!("invalid SNI: {}", e)))?;
        let connecting = endpoint
            .connect(self.proxy_addr, &sni)
            .map_err(|e| TuicError::Quic(format!("QUIC connect failed: {}", e)))?;

        let conn = timeout(self.dial_timeout, connecting)
            .await
            .map_err(|_| TuicError::Timeout(format!("QUIC handshake to {} timed out", self.proxy_addr)))?
            .map_err(|e| TuicError::Quic(format!("QUIC handshake failed: {}", e)))?;

        let state = QuinnConnection {
            endpoint,
            conn: conn.clone(),
            authenticated: false,
        };
        *guard = Some(state);
        Ok(conn)
    }

    /// 发送 Authenticate 命令（UUID + RFC 5705 exporter token）
    async fn authenticate(&self, conn: &quinn::Connection) -> Result<(), TuicError> {
        let uuid = parse_uuid(&self.uuid)?;

        // RFC 5705 Keying Material Exporter：label = UUID，context = 密码
        let mut token = [0u8; 32];
        conn.export_keying_material(&mut token, &uuid, self.password.as_bytes())
            .map_err(|e| TuicError::Quic(format!("key exporter failed: {:?}", e)))?;

        let mut header = Vec::with_capacity(2 + 16 + 32);
        header.push(TUIC_VERSION);
        header.push(CMD_AUTHENTICATE);
        header.extend_from_slice(&uuid);
        header.extend_from_slice(&token);

        let mut send = conn
            .open_uni()
            .await
            .map_err(|e| TuicError::Quic(format!("open_uni failed: {}", e)))?;
        send.write_all(&header)
            .await
            .map_err(|e| TuicError::Io(e.into()))?;
        send.finish()
            .map_err(|e| TuicError::Io(e.into()))?;
        Ok(())
    }
}

/// 编码 TUIC 目标地址：TYPE(1) + ADDR + PORT(2)
fn encode_tuic_address(target: &str) -> Result<Vec<u8>, TuicError> {
    let (mut host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| TuicError::ProtocolError(format!("invalid target '{}'", target)))?;
    let port: u16 = port
        .parse()
        .map_err(|_| TuicError::ProtocolError(format!("invalid target port '{}'", target)))?;
    if host.starts_with('[') && host.ends_with(']') {
        host = &host[1..host.len() - 1];
    }

    let mut addr = Vec::with_capacity(1 + 16 + 2);
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        addr.push(0x01);
        addr.extend_from_slice(&ip.octets());
        addr.extend_from_slice(&port.to_be_bytes());
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        addr.push(0x02);
        for seg in ip.segments() {
            addr.extend_from_slice(&seg.to_be_bytes());
        }
        addr.extend_from_slice(&port.to_be_bytes());
    } else {
        let b = host.as_bytes();
        addr.push(0x00);
        addr.push(b.len() as u8);
        addr.extend_from_slice(b);
        addr.extend_from_slice(&port.to_be_bytes());
    }
    Ok(addr)
}

fn parse_uuid(uuid: &str) -> Result<[u8; 16], TuicError> {
    let hex: String = uuid.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return Err(TuicError::ProtocolError(format!("invalid uuid: '{}'", uuid)));
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| TuicError::ProtocolError(format!("invalid uuid: '{}'", uuid)))?;
    }
    Ok(out)
}

/// QUIC 双向流双工适配（tokio AsyncRead/AsyncWrite）
pub struct QuicStreamDuplex {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicStreamDuplex {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for QuicStreamDuplex {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStreamDuplex {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(|e| std::io::Error::other(format!("quic write: {}", e)))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

#[async_trait]
impl OutboundDialer for TuicDialer {
    async fn dial(&self, target: &str) -> anyhow::Result<ProxyConn> {
        // 1. 建立（或复用）QUIC 连接
        let conn = self.ensure_connection().await?;

        // 2. 首次连接发送 Authenticate（可与 Connect 并行，这里简单串行）
        {
            let mut guard = self.state.lock().await;
            if let Some(state) = guard.as_mut() {
                if !state.authenticated {
                    self.authenticate(&conn).await?;
                    state.authenticated = true;
                }
            }
        }

        // 3. 打开双向流并发送 Connect 命令
        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| TuicError::Quic(format!("open_bi failed: {}", e)))?;
        let mut header = Vec::with_capacity(2 + 1 + 255 + 2);
        header.push(TUIC_VERSION);
        header.push(CMD_CONNECT);
        header.extend_from_slice(&encode_tuic_address(target)?);
        let mut send = send;
        send.write_all(&header)
            .await
            .map_err(|e| TuicError::Io(e.into()))?;

        Ok(ProxyConn::new_boxed(Box::new(QuicStreamDuplex::new(send, recv))))
    }

    /// 建立 TUIC UDP 中继会话（quic 模式：每个 Packet 走 unidirectional stream）。
    ///
    /// 全锥形 NAT：assoc_id 标识服务端 UDP socket，响应经 accept_uni 回传，
    /// 由后台任务解析后转发到通道。
    async fn udp_dial(&self) -> anyhow::Result<Box<dyn crate::UdpSession>> {
        let conn = self.ensure_connection().await?;

        // 首次连接时发送 Authenticate
        {
            let mut guard = self.state.lock().await;
            if let Some(state) = guard.as_mut() {
                if !state.authenticated {
                    self.authenticate(&conn).await?;
                    state.authenticated = true;
                }
            }
        }

        let assoc_id = rand_assoc_id();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        // 后台任务：接收服务端 Packet 命令（unidirectional stream）
        let conn2 = conn.clone();
        tokio::spawn(async move {
            loop {
                let mut recv = match conn2.accept_uni().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                match parse_packet_command(&mut recv).await {
                    Ok(Some((dest, payload))) => {
                        if tx.send((dest, payload)).is_err() {
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
        });

        Ok(Box::new(TuicUdpSession {
            conn,
            assoc_id,
            pkt_id: std::sync::atomic::AtomicU16::new(0),
            rx: std::sync::Arc::new(tokio::sync::Mutex::new(rx)),
        }))
    }

    fn protocol_name(&self) -> &'static str {
        "tuic"
    }
    fn proxy_addr(&self) -> std::net::SocketAddr {
        self.proxy_addr
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// TUIC UDP 中继会话（全锥形，quic 模式）。
pub struct TuicUdpSession {
    conn: quinn::Connection,
    assoc_id: u16,
    pkt_id: std::sync::atomic::AtomicU16,
    rx: UdpRx,
}

/// 后台任务 → 会话的响应通道
type UdpRx = std::sync::Arc<tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<(SocketAddr, Vec<u8>)>>>;

/// 生成递增 assoc_id
fn rand_assoc_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static COUNTER: AtomicU16 = AtomicU16::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed).wrapping_add(0xBEEF)
}

/// 编码 TUIC 地址：TYPE + ADDR + PORT
fn encode_tuic_addr(host: &str, port: u16) -> Vec<u8> {
    let mut addr = Vec::with_capacity(1 + 16 + 2);
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        addr.push(0x01);
        addr.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        addr.push(0x02);
        for seg in ip.segments() {
            addr.extend_from_slice(&seg.to_be_bytes());
        }
    } else {
        let b = host.as_bytes();
        addr.push(0x00);
        addr.push(b.len() as u8);
        addr.extend_from_slice(b);
    }
    addr.extend_from_slice(&port.to_be_bytes());
    addr
}

/// 从 unidirectional stream 解析 Packet 命令（第 2 字节必须是 Packet 类型）。
///
/// 返回 `(dest, payload)`；非 Packet 命令返回 None。
async fn parse_packet_command(
    recv: &mut quinn::RecvStream,
) -> anyhow::Result<Option<(SocketAddr, Vec<u8>)>> {
    // VER(1) TYPE(1)
    let mut head = [0u8; 2];
    recv.read_exact(&mut head).await?;
    if head[1] != CMD_PACKET {
        return Ok(None);
    }
    // ASSOC_ID(2) PKT_ID(2) FRAG_TOTAL(1) FRAG_ID(1) SIZE(2)
    let mut meta = [0u8; 8];
    recv.read_exact(&mut meta).await?;
    let size = u16::from_be_bytes([meta[6], meta[7]]) as usize;

    // 地址：TYPE(1) + ADDR + PORT(2)
    let mut typ = [0u8; 1];
    recv.read_exact(&mut typ).await?;
    let dest = match typ[0] {
        0x01 => {
            let mut buf = [0u8; 4 + 2];
            recv.read_exact(&mut buf).await?;
            let ip = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            SocketAddr::from((ip, u16::from_be_bytes([buf[4], buf[5]])))
        }
        0x02 => {
            let mut buf = [0u8; 16 + 2];
            recv.read_exact(&mut buf).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[..16]);
            let ip = std::net::Ipv6Addr::from(octets);
            SocketAddr::from((ip, u16::from_be_bytes([buf[16], buf[17]])))
        }
        0x00 => {
            let mut lenb = [0u8; 1];
            recv.read_exact(&mut lenb).await?;
            let mut name = vec![0u8; lenb[0] as usize];
            recv.read_exact(&mut name).await?;
            let mut portb = [0u8; 2];
            recv.read_exact(&mut portb).await?;
            SocketAddr::from(([0, 0, 0, 0], u16::from_be_bytes(portb)))
        }
        other => anyhow::bail!("tuic: unknown address type {}", other),
    };

    let mut payload = vec![0u8; size];
    recv.read_exact(&mut payload).await?;
    Ok(Some((dest, payload)))
}

#[async_trait]
impl crate::UdpSession for TuicUdpSession {
    async fn send(&self, dest: &SocketAddr, payload: &[u8]) -> anyhow::Result<()> {
        // Packet: VER(1) TYPE(1) ASSOC_ID(2) PKT_ID(2) FRAG_TOTAL(1) FRAG_ID(1) SIZE(2) ADDR + payload
        let pkt_id = self.pkt_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut header = Vec::with_capacity(2 + 2 + 2 + 1 + 1 + 2 + 1 + 16 + 2);
        header.push(TUIC_VERSION);
        header.push(CMD_PACKET);
        header.extend_from_slice(&self.assoc_id.to_be_bytes());
        header.extend_from_slice(&pkt_id.to_be_bytes());
        header.push(1); // FRAG_TOTAL
        header.push(0); // FRAG_ID
        header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        header.extend_from_slice(&encode_tuic_addr(&dest.ip().to_string(), dest.port()));

        let mut send = self
            .conn
            .open_uni()
            .await
            .map_err(|e| TuicError::Quic(format!("open_uni failed: {}", e)))?;
        send.write_all(&header)
            .await
            .map_err(|e| TuicError::Quic(format!("udp packet write failed: {}", e)))?;
        send.write_all(payload)
            .await
            .map_err(|e| TuicError::Quic(format!("udp packet write failed: {}", e)))?;
        send.finish()
            .map_err(|e| TuicError::Quic(format!("udp packet finish failed: {}", e)))?;
        Ok(())
    }

    async fn recv(&self) -> anyhow::Result<(SocketAddr, Vec<u8>)> {
        let mut rx = self.rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("tuic udp: channel closed"))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_parse() {
        let bytes = parse_uuid("d0529668-8835-11ec-a8a3-0242ac120002").unwrap();
        assert_eq!(bytes.len(), 16);
        assert!(parse_uuid("bad").is_err());
    }

    #[test]
    fn test_encode_address_ipv4() {
        let addr = encode_tuic_address("1.2.3.4:443").unwrap();
        assert_eq!(addr, vec![0x01, 1, 2, 3, 4, 0x01, 0xBB]);
    }

    #[test]
    fn test_encode_address_ipv6() {
        let addr = encode_tuic_address("[2001:db8::1]:443").unwrap();
        assert_eq!(addr[0], 0x02);
        assert_eq!(addr.len(), 1 + 16 + 2);
        assert_eq!(&addr[17..19], &[0x01, 0xBB]);
    }

    #[test]
    fn test_encode_address_domain() {
        let addr = encode_tuic_address("example.com:80").unwrap();
        assert_eq!(addr[0], 0x00);
        assert_eq!(addr[1], 11);
        assert_eq!(&addr[2..13], b"example.com");
        assert_eq!(&addr[13..15], &[0x00, 0x50]);
    }
}
