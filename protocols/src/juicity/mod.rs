//! Juicity protocol dialer (based on QUIC)
//!
//! Implements Juicity outbound proxy protocol:
//! - QUIC transport (quinn + rustls, ALPN `h3`, TLS 1.3)
//! - `Authenticate`: UUID + RFC 5705 Keying Material Exporter token
//! - TCP carried on QUIC stream, proxy header = [network][addr_type][address][port]
//! - Each QUIC connection carries at most 30 streams, then new connection
//!
//! Reference: https://github.com/juicity/juicity/blob/main/docs/spec.md
//! (address types per daeuniverse/outbound implementation: IPv4=1, Domain=3, IPv6=4)

use async_trait::async_trait;
use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::{ClientConfig as QuinnClientConfig, Endpoint as QuinnEndpoint, TokioRuntime};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::{OutboundDialer, ProxyConn};

/// Juicity protocol version
const JUICITY_VERSION: u8 = 0x00;
/// Command type (authentication)
const CMD_AUTHENTICATE: u8 = 0x00;
/// ALPN
const JUICITY_ALPN: &[u8] = b"h3";
/// Maximum streams per QUIC connection (server maxOpenIncomingStreams >= 30)
const MAX_STREAMS_PER_CONN: u32 = 30;
/// Network type
const NETWORK_TCP: u8 = 1;
const NETWORK_UDP: u8 = 3;
/// Address type (daeuniverse/outbound implementation)
const ADDR_IPV4: u8 = 1;
const ADDR_DOMAIN: u8 = 3;
const ADDR_IPV6: u8 = 4;

/// Juicity Dialer error
#[derive(Debug, thiserror::Error)]
pub enum JuicityError {
    #[error("Juicity dial timeout: {0}")]
    Timeout(String),
    #[error("Juicity connection refused: {0}")]
    ConnectionRefused(String),
    #[error("Juicity TLS error: {0}")]
    Tls(String),
    #[error("Juicity QUIC error: {0}")]
    Quic(String),
    #[error("Juicity protocol error: {0}")]
    ProtocolError(String),
    #[error("Juicity IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Juicity error: {0}")]
    Other(String),
}

/// Juicity Dialer
pub struct JuicityDialer {
    /// Upstream Juicity server address
    pub proxy_addr: SocketAddr,
    /// Dial timeout duration
    pub dial_timeout: Duration,
    /// User UUID
    pub uuid: String,
    /// Authentication password
    pub password: String,
    /// Congestion control algorithm
    pub congestion_control: String,
    /// TLS SNI
    pub sni: String,
    /// Certificate SHA256 fingerprint
    pub ca_sha256: Option<String>,
    /// fwmark for eBPF self-exclusion
    pub self_mark: u32,
    /// Host network namespace fd
    pub host_ns_fd: Option<RawFd>,
    /// Lazily created QUIC connection list (each connection carries at most MAX_STREAMS_PER_CONN streams)
    state: Mutex<Vec<JuicityConnState>>,
}

/// A usable QUIC connection state
struct JuicityConnState {
    #[allow(dead_code)]
    endpoint: QuinnEndpoint,
    conn: quinn::Connection,
    authenticated: bool,
    stream_count: AtomicU32,
}

impl JuicityDialer {
    /// Create a new Juicity Dialer
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
            sni: String::new(),
            ca_sha256: None,
            self_mark: 0,
            host_ns_fd: None,
            state: Mutex::new(Vec::new()),
        }
    }

    /// Set Congestion control algorithm
    pub fn set_congestion_control(&mut self, cc: impl Into<String>) -> &mut Self {
        self.congestion_control = cc.into();
        self
    }

    /// Set SNI
    pub fn set_sni(&mut self, sni: impl Into<String>) -> &mut Self {
        self.sni = sni.into();
        self
    }

    /// Set certificate SHA256 fingerprint
    pub fn set_ca_sha256(&mut self, ca_sha256: Option<String>) -> &mut Self {
        self.ca_sha256 = ca_sha256;
        self
    }

    /// Set fwmark for eBPF self-exclusion (0 means not set)
    pub fn set_self_mark(&mut self, self_mark: u32) -> &mut Self {
        self.self_mark = self_mark;
        self
    }

    /// Set host network namespace fd
    pub fn set_host_ns_fd(&mut self, host_ns_fd: Option<RawFd>) -> &mut Self {
        self.host_ns_fd = host_ns_fd;
        self
    }

    /// Get an available connection: prefer reusing existing connections that aren't full, otherwise create new.
    ///
    /// The Mutex guard is held only for the quick check-and-push operations;
    /// all blocking I/O (socket creation, endpoint setup) and the async QUIC
    /// handshake run *outside* the guard so we never stall a tokio worker
    /// thread while the lock is held. This prevents cascading stalls where
    /// one slow connection setup blocks every concurrent DNS query that also
    /// needs a connection.
    async fn get_connection(&self) -> Result<quinn::Connection, JuicityError> {
        // ── 1. Quick check: reuse an existing connection if possible ──
        {
            let guard = self.state.lock().await;
            for state in guard.iter() {
                if state.conn.close_reason().is_none()
                    && state.stream_count.load(Ordering::Relaxed) < MAX_STREAMS_PER_CONN
                {
                    return Ok(state.conn.clone());
                }
            }
        } // guard dropped – no lock held during connection setup

        // ── 2. Create new QUIC connection (blocking I/O + async handshake) ──
        //    Done *without* holding the state Mutex so that other tasks can
        //    proceed (or at least not be blocked by a held guard) while this
        //    potentially slow operation runs.
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut crypto = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        crypto.alpn_protocols = vec![JUICITY_ALPN.to_vec()];
        crypto.enable_early_data = true;

        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(crypto))
            .map_err(|e| JuicityError::Tls(format!("quinn rustls config failed: {}", e)))?;
        let mut config = QuinnClientConfig::new(Arc::new(quic_crypto));

        let mut tp_cfg = quinn::TransportConfig::default();
        tp_cfg
            .max_concurrent_bidi_streams(1024u32.into())
            .max_concurrent_uni_streams(1024u32.into())
            .max_idle_timeout(None);
        match self.congestion_control.as_str() {
            "bbr" => tp_cfg.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default())),
            "cubic" => tp_cfg
                .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default())),
            _ => tp_cfg
                .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default())),
        };
        config.transport_config(Arc::new(tp_cfg));

        let socket = crate::hostns::create_udp(
            self.proxy_addr,
            &crate::hostns::DirectSocket {
                self_mark: self.self_mark,
                host_ns_fd: self.host_ns_fd,
            },
        )
        .map_err(|e| JuicityError::Other(format!("create UDP socket failed: {}", e)))?;
        let mut endpoint = QuinnEndpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(TokioRuntime),
        )
        .map_err(|e| JuicityError::Other(format!("create QUIC endpoint failed: {}", e)))?;
        endpoint.set_default_client_config(config);

        let sni = if self.sni.is_empty() {
            self.proxy_addr.ip().to_string()
        } else {
            self.sni.clone()
        };
        let _ = ServerName::try_from(sni.clone())
            .map_err(|e| JuicityError::Tls(format!("invalid SNI: {}", e)))?;
        let connecting = endpoint
            .connect(self.proxy_addr, &sni)
            .map_err(|e| JuicityError::Quic(format!("QUIC connect failed: {}", e)))?;

        let conn = timeout(self.dial_timeout, connecting)
            .await
            .map_err(|_| {
                JuicityError::Timeout(format!("QUIC handshake to {} timed out", self.proxy_addr))
            })?
            .map_err(|e| JuicityError::Quic(format!("QUIC handshake failed: {}", e)))?;

        // ── 3. Re-acquire lock and store the new connection ──
        {
            let mut guard = self.state.lock().await;
            // Double-check: another task may have created a usable connection
            // while we were connecting. If so, prefer reusing it and let ours
            // be garbage-collected when `endpoint` is dropped.
            for state in guard.iter() {
                if state.conn.close_reason().is_none()
                    && state.stream_count.load(Ordering::Relaxed) < MAX_STREAMS_PER_CONN
                {
                    return Ok(state.conn.clone());
                }
            }
            guard.push(JuicityConnState {
                endpoint,
                conn: conn.clone(),
                authenticated: false,
                stream_count: AtomicU32::new(0),
            });
        }
        Ok(conn)
    }

    /// Send Authenticate command (UUID + RFC 5705 exporter token)
    async fn authenticate(&self, conn: &quinn::Connection) -> Result<(), JuicityError> {
        let uuid = parse_uuid(&self.uuid)?;

        let mut token = [0u8; 32];
        conn.export_keying_material(&mut token, &uuid, self.password.as_bytes())
            .map_err(|e| JuicityError::Quic(format!("key exporter failed: {:?}", e)))?;

        let mut header = Vec::with_capacity(2 + 16 + 32);
        header.push(JUICITY_VERSION);
        header.push(CMD_AUTHENTICATE);
        header.extend_from_slice(&uuid);
        header.extend_from_slice(&token);

        let mut send = conn
            .open_uni()
            .await
            .map_err(|e| JuicityError::Quic(format!("open_uni failed: {}", e)))?;
        send.write_all(&header)
            .await
            .map_err(|e| JuicityError::Io(e.into()))?;
        send.finish()
            .map_err(|e| JuicityError::Io(e.into()))?;
        Ok(())
    }
}

/// Encode Juicity proxy header: [network][addr_type][address][port]
fn encode_proxy_header(target: &str) -> Result<Vec<u8>, JuicityError> {
    let (host, port) = split_target(target)?;
    encode_header(NETWORK_TCP, host, port)
}

/// Encode Juicity datagram header: [network][addr_type][address][port][len(2)]
fn encode_packet_header(network: u8, host: &str, port: u16, payload_len: usize) -> Vec<u8> {
    let mut header = encode_header(network, host, port).expect("valid addr");
    header.extend_from_slice(&(payload_len as u16).to_be_bytes());
    header
}

/// Encode Juicity header (network + address + port)
fn encode_header(network: u8, host: &str, port: u16) -> Result<Vec<u8>, JuicityError> {
    let mut header = Vec::with_capacity(2 + 16 + 2);
    header.push(network);
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        header.push(ADDR_IPV4);
        header.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        header.push(ADDR_IPV6);
        header.extend_from_slice(&ip.octets());
    } else {
        let b = host.as_bytes();
        header.push(ADDR_DOMAIN);
        header.push(b.len() as u8);
        header.extend_from_slice(b);
    }
    header.extend_from_slice(&port.to_be_bytes());
    Ok(header)
}

/// Split `host:port` target string (supports [ipv6]:port)
fn split_target(target: &str) -> Result<(&str, u16), JuicityError> {
    let (mut host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| JuicityError::ProtocolError(format!("invalid target '{}'", target)))?;
    let port: u16 = port
        .parse()
        .map_err(|_| JuicityError::ProtocolError(format!("invalid target port '{}'", target)))?;
    if host.starts_with('[') && host.ends_with(']') {
        host = &host[1..host.len() - 1];
    }
    Ok((host, port))
}

fn parse_uuid(uuid: &str) -> Result<[u8; 16], JuicityError> {
    let hex: String = uuid.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return Err(JuicityError::ProtocolError(format!("invalid uuid: '{}'", uuid)));
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| JuicityError::ProtocolError(format!("invalid uuid: '{}'", uuid)))?;
    }
    Ok(out)
}

/// QUIC bidirectional stream duplex adapter (tokio AsyncRead/AsyncWrite)
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
        Pin::new(&mut self.send)
            .poll_flush(cx)
            .map_err(|e| std::io::Error::other(format!("quic flush: {}", e)))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(|e| std::io::Error::other(format!("quic shutdown: {}", e)))
    }
}

#[async_trait]
impl OutboundDialer for JuicityDialer {
    async fn dial(&self, target: &str) -> anyhow::Result<ProxyConn> {
        // 1. Get (or create) QUIC connection (bounded by dial_timeout)
        let conn = timeout(self.dial_timeout, self.get_connection())
            .await
            .map_err(|_| anyhow::anyhow!(
                "juicity connection establishment to {} timed out",
                self.proxy_addr
            ))??;

        // 2. Send Authenticate when first using the connection
        {
            let mut guard = self.state.lock().await;
            for state in guard.iter_mut() {
                if state.conn.close_reason().is_none()
                    && std::ptr::eq(&state.conn, &conn)
                {
                    if !state.authenticated {
                        self.authenticate(&conn).await?;
                        state.authenticated = true;
                    }
                    break;
                }
            }
        }

        // 3. Open bidirectional stream, send proxy header, then carry data directly
        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| JuicityError::Quic(format!("open_bi failed: {}", e)))?;
        {
            let mut guard = self.state.lock().await;
            for state in guard.iter_mut() {
                if std::ptr::eq(&state.conn, &conn) {
                    state.stream_count.fetch_add(1, Ordering::Relaxed);
                    break;
                }
            }
        }
        let header = encode_proxy_header(target)?;
        let mut send = send;
        send.write_all(&header)
            .await
            .map_err(|e| JuicityError::Io(e.into()))?;

        Ok(ProxyConn::new_boxed(Box::new(QuicStreamDuplex::new(send, recv))))
    }

    /// Establish Juicity UDP relay session (UDP over Stream).
    ///
    /// Session occupies one bidirectional stream: each datagram = `[network=3][addr][port][len(2)][payload]`.
    async fn udp_dial(&self) -> anyhow::Result<Box<dyn crate::UdpSession>> {
        // Get (or create) QUIC connection (bounded by dial_timeout)
        let conn = timeout(self.dial_timeout, self.get_connection())
            .await
            .map_err(|_| anyhow::anyhow!(
                "juicity connection establishment to {} timed out",
                self.proxy_addr
            ))??;

        // Send Authenticate when first using the connection
        {
            let mut guard = self.state.lock().await;
            for state in guard.iter_mut() {
                if state.conn.close_reason().is_none() && std::ptr::eq(&state.conn, &conn) {
                    if !state.authenticated {
                        self.authenticate(&conn).await?;
                        state.authenticated = true;
                    }
                    break;
                }
            }
        }

        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| JuicityError::Quic(format!("open_bi failed: {}", e)))?;
        {
            let mut guard = self.state.lock().await;
            for state in guard.iter_mut() {
                if std::ptr::eq(&state.conn, &conn) {
                    state.stream_count.fetch_add(1, Ordering::Relaxed);
                    break;
                }
            }
        }

        Ok(Box::new(JuicityUdpSession {
            send: tokio::sync::Mutex::new(send),
            recv: tokio::sync::Mutex::new(recv),
        }))
    }

    fn protocol_name(&self) -> &'static str {
        "juicity"
    }
    fn proxy_addr(&self) -> std::net::SocketAddr {
        self.proxy_addr
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Juicity UDP relay session (UDP over Stream, full cone).
pub struct JuicityUdpSession {
    send: tokio::sync::Mutex<quinn::SendStream>,
    recv: tokio::sync::Mutex<quinn::RecvStream>,
}

#[async_trait]
impl crate::UdpSession for JuicityUdpSession {
    async fn send(&self, dest: &SocketAddr, payload: &[u8]) -> anyhow::Result<()> {
        // [network=3][addr_type][address][port(2)][len(2)][payload]
        let mut datagram =
            encode_packet_header(NETWORK_UDP, &dest.ip().to_string(), dest.port(), payload.len());
        datagram.extend_from_slice(payload);
        let mut send = self.send.lock().await;
        send.write_all(&datagram)
            .await
            .map_err(|e| JuicityError::Quic(format!("udp datagram write failed: {}", e)))?;
        Ok(())
    }

    async fn recv(&self) -> anyhow::Result<(SocketAddr, Vec<u8>)> {
        let mut recv = self.recv.lock().await;

        // network(1)
        let mut network = [0u8; 1];
        recv.read_exact(&mut network).await?;
        if network[0] != NETWORK_UDP {
            return Err(anyhow::anyhow!(
                "juicity udp: unexpected network type {}",
                network[0]
            ));
        }

        // addr_type(1) + address + port(2)
        let mut typ = [0u8; 1];
        recv.read_exact(&mut typ).await?;
        let dest = match typ[0] {
            ADDR_IPV4 => {
                let mut buf = [0u8; 4 + 2];
                recv.read_exact(&mut buf).await?;
                let ip = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                SocketAddr::from((ip, u16::from_be_bytes([buf[4], buf[5]])))
            }
            ADDR_IPV6 => {
                let mut buf = [0u8; 16 + 2];
                recv.read_exact(&mut buf).await?;
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[..16]);
                let ip = std::net::Ipv6Addr::from(octets);
                SocketAddr::from((ip, u16::from_be_bytes([buf[16], buf[17]])))
            }
            ADDR_DOMAIN => {
                let mut lenb = [0u8; 1];
                recv.read_exact(&mut lenb).await?;
                let mut name = vec![0u8; lenb[0] as usize];
                recv.read_exact(&mut name).await?;
                let mut portb = [0u8; 2];
                recv.read_exact(&mut portb).await?;
                SocketAddr::from(([0, 0, 0, 0], u16::from_be_bytes(portb)))
            }
            other => {
                return Err(anyhow::anyhow!(
                    "juicity udp: unknown address type {}",
                    other
                ))
            }
        };

        // len(2) + payload
        let mut lenb = [0u8; 2];
        recv.read_exact(&mut lenb).await?;
        let pkt_len = u16::from_be_bytes(lenb) as usize;
        let mut payload = vec![0u8; pkt_len];
        recv.read_exact(&mut payload).await?;
        Ok((dest, payload))
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
    fn test_encode_header_ipv4() {
        let h = encode_proxy_header("1.2.3.4:443").unwrap();
        assert_eq!(h, vec![NETWORK_TCP, ADDR_IPV4, 1, 2, 3, 4, 0x01, 0xBB]);
    }

    #[test]
    fn test_encode_header_ipv6() {
        let h = encode_proxy_header("[2001:db8::1]:443").unwrap();
        assert_eq!(h[0], NETWORK_TCP);
        assert_eq!(h[1], ADDR_IPV6);
        assert_eq!(h.len(), 2 + 16 + 2);
        assert_eq!(&h[18..20], &[0x01, 0xBB]);
    }

    #[test]
    fn test_encode_header_domain() {
        let h = encode_proxy_header("example.com:80").unwrap();
        assert_eq!(h[0], NETWORK_TCP);
        assert_eq!(h[1], ADDR_DOMAIN);
        assert_eq!(h[2], 11);
        assert_eq!(&h[3..14], b"example.com");
        assert_eq!(&h[14..16], &[0x00, 0x50]);
    }

    #[test]
    fn test_encode_header_invalid() {
        assert!(encode_proxy_header("no-port").is_err());
    }
}
