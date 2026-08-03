//! Protocol abstraction layer for dae-rs.
//!
//! Defines the [`OutboundDialer`] trait and a registry of supported protocols.
//! Each protocol lives in its own subdirectory under `protocols/src/` and is
//! gated by a Cargo feature flag.
//!
//! # Supported Protocols
//!
//! | Protocol | Feature | Module | Status |
//! |----------|---------|--------|--------|
//! | SOCKS5   | `socks` | [`socks`] | ✅ Complete (TCP + UDP ASSOCIATE) |
//! | Shadowsocks | `shadowsocks` | [`shadowsocks`] | ✅ Complete (AEAD legacy + 2022, TCP + UDP) |
//! | Trojan | `trojan` | [`trojan`] | ✅ Complete (TLS, TCP + UDP ASSOCIATE) |
//! | TUIC v5 | `tuic` | [`tuic`] | ✅ Complete (QUIC + 0-RTT + BBR, TCP + Packet) |
//! | Juicity | `juicity` | [`juicity`] | ✅ Complete (QUIC + BBR, TCP + UDP over Stream) |
//! | VMess | `vmess` | [`vmess`] | ✅ Complete (AEAD, TCP/WS + UDP) |
//!
//! # Adding a New Protocol
//!
//! 1. Create `protocols/src/<name>/mod.rs`
//! 2. Implement `OutboundDialer` for your dialer struct
//! 3. Add a `#[cfg(feature = "<name>")]` pub mod in this file
//! 4. Add the feature to `Cargo.toml`
//! 5. Register in [`ProtocolRegistry::builtin()`]

use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

// ── Shared host-namespace socket helpers ──

/// Generic helpers to create upstream sockets in the host network namespace
/// (see [`hostns::with_host_ns`]).
pub mod hostns;

// ── Protocol modules (gated by features) ──

/// SOCKS5 protocol support (mandatory — only outbound protocol currently).
///
/// - RFC 1928 (SOCKS5)
/// - TCP CONNECT + UDP ASSOCIATE
/// - No Auth (0x00) + Username/Password (0x02)
/// - Target: IPv4, IPv6, Domain name
/// - UDP endpoint pool with auto-cleanup
pub mod socks;
pub use socks::Socks5Dialer;
pub use socks::Socks5Error;
pub use socks::UdpAssociateSession;
pub use socks::UdpEndpointPool;

/// Shadowsocks protocol support.
///
/// - 2022 Edition (SIP022) with BLAKE3 key derivation
/// - AEAD Legacy with HKDF-SHA1 key derivation
/// - TCP + UDP support
#[cfg(feature = "shadowsocks")]
pub mod shadowsocks;
#[cfg(feature = "shadowsocks")]
pub use shadowsocks::ShadowsocksDialer;
#[cfg(feature = "shadowsocks")]
pub use shadowsocks::ShadowsocksError;

/// Trojan protocol support.
///
/// - TLS-based proxy protocol
/// -伪装成 HTTPS traffic
/// - Certificate verification mandatory
#[cfg(feature = "trojan")]
pub mod trojan;
#[cfg(feature = "trojan")]
pub use trojan::TrojanDialer;
#[cfg(feature = "trojan")]
pub use trojan::TrojanError;

/// TUIC v5 protocol support.
///
/// - QUIC-based proxy protocol
/// - 0-RTT connection establishment
/// - BBR congestion control
#[cfg(feature = "tuic")]
pub mod tuic;
#[cfg(feature = "tuic")]
pub use tuic::TuicDialer;
#[cfg(feature = "tuic")]
pub use tuic::TuicError;

/// Juicity protocol support.
///
/// - QUIC-based proxy protocol
/// - UDP over Stream
/// - Requires BBR congestion control
#[cfg(feature = "juicity")]
pub mod juicity;
#[cfg(feature = "juicity")]
pub use juicity::JuicityDialer;
#[cfg(feature = "juicity")]
pub use juicity::JuicityError;

/// VMess protocol support.
///
/// - Multiple transport: TCP, WebSocket, HTTP/2, gRPC
/// - TLS support (WSS, H2, gRPC)
/// - v2rayN base64 import format
#[cfg(feature = "vmess")]
pub mod vmess;
#[cfg(feature = "vmess")]
pub use vmess::VMessDialer;
#[cfg(feature = "vmess")]
pub use vmess::VMessError;
#[cfg(feature = "vmess")]
pub use vmess::VMessNetwork;

// ── Protocol registry ──

/// Information about a supported outbound protocol.
#[derive(Debug, Clone)]
pub struct ProtocolInfo {
    /// Protocol name (e.g., "socks5", "http", "vless")
    pub name: &'static str,
    /// Human-readable description
    pub description: &'static str,
    /// Supported features
    pub features: &'static [&'static str],
    /// Minimum version
    pub version: &'static str,
    /// Link to RFC or specification
    pub spec_link: &'static str,
}

/// Registry of all outbound protocols compiled into the binary.
///
/// Built at compile time based on enabled Cargo features.
pub struct ProtocolRegistry;

impl ProtocolRegistry {
    /// Return list of all built-in protocols with their details.
    pub fn builtin() -> Vec<ProtocolInfo> {
        let mut protocols = vec![ProtocolInfo {
            name: "socks5",
            description: "SOCKS5 proxy protocol with TCP CONNECT and UDP ASSOCIATE",
            features: &["tcp", "udp", "auth-none", "auth-userpass"],
            version: "RFC 1928",
            spec_link: "https://datatracker.ietf.org/doc/html/rfc1928",
        }];

        #[cfg(feature = "shadowsocks")]
        protocols.push(ProtocolInfo {
            name: "shadowsocks",
            description: "Shadowsocks proxy protocol with 2022 Edition and AEAD support",
            features: &["tcp", "udp", "aead", "2022"],
            version: "SIP022",
            spec_link: "https://shadowsocks.org/doc/sip022.html",
        });

        #[cfg(feature = "trojan")]
        protocols.push(ProtocolInfo {
            name: "trojan",
            description: "Trojan proxy protocol over TLS",
            features: &["tcp", "tls"],
            version: "1.0",
            spec_link: "https://github.com/trojan-gfw/trojan/blob/master/docs/protocol.md",
        });

        #[cfg(feature = "tuic")]
        protocols.push(ProtocolInfo {
            name: "tuic",
            description: "TUIC v5 proxy protocol over QUIC",
            features: &["udp", "quic", "0-rtt"],
            version: "v5",
            spec_link: "https://github.com/tuic-protocol/tuic/blob/master/SPEC.md",
        });

        #[cfg(feature = "juicity")]
        protocols.push(ProtocolInfo {
            name: "juicity",
            description: "Juicity proxy protocol over QUIC with UDP over Stream",
            features: &["udp", "quic", "stream"],
            version: "1.0",
            spec_link: "https://github.com/juicity/juicity/blob/main/docs/spec.md",
        });

        #[cfg(feature = "vmess")]
        protocols.push(ProtocolInfo {
            name: "vmess",
            description: "VMess proxy protocol with multiple transports",
            features: &["tcp", "ws", "h2", "grpc", "tls"],
            version: "1.0",
            spec_link: "https://www.v2fly.org/en_US/developer/protocols/vmess.html",
        });

        protocols
    }
}

// ── OutboundDialer trait ──

/// Object-safe helper trait combining [`AsyncRead`] + [`AsyncWrite`]
/// (Rust does not allow `dyn AsyncRead + AsyncWrite` directly).
pub trait AsyncDuplex: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> AsyncDuplex for T {}

/// A proxy connection's data stream.
///
/// - [`ProxyStream::Tcp`] — plain TCP stream (supports the zero-copy splice
///   relay path in the control plane).
/// - [`ProxyStream::Boxed`] — any wrapped duplex stream (TLS, WebSocket,
///   QUIC stream, ...) used by the non-TCP transports.
pub enum ProxyStream {
    /// Plain TCP connection to the proxy server.
    Tcp(TcpStream),
    /// Wrapped duplex stream (TLS / WebSocket / QUIC ...).
    Boxed(Box<dyn AsyncDuplex + Unpin + Send>),
}

impl AsyncRead for ProxyStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            ProxyStream::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            ProxyStream::Boxed(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ProxyStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            ProxyStream::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            ProxyStream::Boxed(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            ProxyStream::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
            ProxyStream::Boxed(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            ProxyStream::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            ProxyStream::Boxed(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Proxy connection wrapping a duplex stream.
pub struct ProxyConn {
    pub stream: ProxyStream,
    pub peer_addr: SocketAddr,
    pub local_addr: SocketAddr,
}

impl ProxyConn {
    /// Wrap a plain TCP stream (splice-capable).
    pub fn new_tcp(stream: TcpStream) -> std::io::Result<Self> {
        let peer_addr = stream.peer_addr()?;
        let local_addr = stream.local_addr()?;
        Ok(Self {
            stream: ProxyStream::Tcp(stream),
            peer_addr,
            local_addr,
        })
    }

    /// Wrap an arbitrary duplex stream (TLS / WebSocket / QUIC ...).
    pub fn new_boxed(stream: Box<dyn AsyncDuplex + Unpin + Send>) -> Self {
        Self {
            stream: ProxyStream::Boxed(stream),
            peer_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            local_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
        }
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

/// Unified outbound dialer interface.
///
/// All outbound protocols must implement this trait.
#[async_trait]
pub trait OutboundDialer: Send + Sync {
    /// Dial the target through the proxy.
    async fn dial(&self, target: &str) -> anyhow::Result<ProxyConn>;

    /// Open a UDP relay session through the proxy (full-cone).
    ///
    /// The returned session can send datagrams to any destination and
    /// receive relayed responses. Each protocol implements its own UDP
    /// framing on top of this abstraction.
    async fn udp_dial(&self) -> anyhow::Result<Box<dyn UdpSession>>;

    /// Return the protocol name (e.g., "socks5").
    fn protocol_name(&self) -> &'static str;

    /// Return the upstream proxy server address this dialer connects to.
    fn proxy_addr(&self) -> SocketAddr;

    /// Downcast support (e.g. for the SOCKS5-only UDP relay path).
    fn as_any(&self) -> &dyn std::any::Any;
}

/// A full-cone UDP relay session through a proxy.
///
/// `send` forwards a datagram to `dest` via the proxy; `recv` returns the
/// next relayed datagram together with its original destination address.
#[async_trait]
pub trait UdpSession: Send + Sync {
    /// Send a payload to the destination through the proxy.
    async fn send(&self, dest: &SocketAddr, payload: &[u8]) -> anyhow::Result<()>;

    /// Receive the next relayed datagram: `(original destination, payload)`.
    async fn recv(&self) -> anyhow::Result<(SocketAddr, Vec<u8>)>;
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_registry() {
        let protocols = ProtocolRegistry::builtin();
        assert!(protocols.iter().any(|p| p.name == "socks5"));
        #[cfg(feature = "shadowsocks")]
        assert!(protocols.iter().any(|p| p.name == "shadowsocks"));
        #[cfg(feature = "trojan")]
        assert!(protocols.iter().any(|p| p.name == "trojan"));
        #[cfg(feature = "tuic")]
        assert!(protocols.iter().any(|p| p.name == "tuic"));
        #[cfg(feature = "juicity")]
        assert!(protocols.iter().any(|p| p.name == "juicity"));
        #[cfg(feature = "vmess")]
        assert!(protocols.iter().any(|p| p.name == "vmess"));
    }

    #[test]
    fn test_protocol_info_fields() {
        for p in ProtocolRegistry::builtin() {
            assert!(!p.name.is_empty());
            assert!(!p.description.is_empty());
            assert!(!p.features.is_empty());
            assert!(!p.version.is_empty());
            assert!(!p.spec_link.is_empty());
        }
    }
}
