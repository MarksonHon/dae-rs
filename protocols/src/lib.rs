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
//! | SOCKS5   | `socks` | [`socks`] | ✅ Complete (TCP CONNECT + UDP ASSOCIATE) |
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
        vec![ProtocolInfo {
            name: "socks5",
            description: "SOCKS5 proxy protocol with TCP CONNECT and UDP ASSOCIATE",
            features: &["tcp", "udp", "auth-none", "auth-userpass"],
            version: "RFC 1928",
            spec_link: "https://datatracker.ietf.org/doc/html/rfc1928",
        }]
    }
}

// ── OutboundDialer trait ──

/// Proxy connection wrapping a TCP stream.
pub struct ProxyConn {
    pub stream: TcpStream,
    pub peer_addr: SocketAddr,
    pub local_addr: SocketAddr,
}

impl ProxyConn {
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

/// Unified outbound dialer interface.
///
/// All outbound protocols must implement this trait.
#[async_trait]
pub trait OutboundDialer: Send + Sync {
    /// Dial the target through the proxy.
    async fn dial(&self, target: &str) -> anyhow::Result<ProxyConn>;

    /// Return the protocol name (e.g., "socks5").
    fn protocol_name(&self) -> &'static str;
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_registry() {
        let protocols = ProtocolRegistry::builtin();
        assert!(protocols.iter().any(|p| p.name == "socks5"));
        assert_eq!(protocols.len(), 1);
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
