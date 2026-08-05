//! SOCKS5 protocol dialer
//!
//! Implements the SOCKS5 outbound proxy protocol, supporting:
//! - No Authentication
//! - Username/Password Authentication
//! - TCP stream connection
//! - UDP ASSOCIATE (UDP relay)

use async_trait::async_trait;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tracing::debug;

use crate::{OutboundDialer, ProxyConn};

/// SOCKS5 Dialer error
#[derive(Debug, thiserror::Error)]
pub enum Socks5Error {
    /// Connection timeout
    #[error("SOCKS5 dial timeout: {0}")]
    Timeout(String),
    /// Connection refused
    #[error("SOCKS5 connection refused: {0}")]
    ConnectionRefused(String),
    /// Authentication failed
    #[error("SOCKS5 authentication failed: {0}")]
    AuthFailed(String),
    /// Protocol error
    #[error("SOCKS5 protocol error: {0}")]
    ProtocolError(String),
    /// IO error
    #[error("SOCKS5 IO error: {0}")]
    Io(#[from] std::io::Error),
    /// Other error
    #[error("SOCKS5 error: {0}")]
    Other(String),
}

/// SOCKS5 Dialer
///
/// Responsible for establishing connections with SOCKS5 upstream servers and forwarding traffic.
/// Automatically sets SO_MARK=self_mark to prevent eBPF from intercepting self-traffic.
pub struct Socks5Dialer {
    /// Upstream SOCKS5 proxy server address
    pub proxy_addr: SocketAddr,
    /// Dial timeout duration
    pub dial_timeout: Duration,
    /// Authentication username (empty string means no authentication required)
    pub username: String,
    /// Authentication password
    pub password: String,
    /// fwmark for eBPF self-exclusion (0 means not set)
    pub self_mark: u32,
    /// Host network namespace fd.
    ///
    /// After setting, all upstream sockets (TCP connections to SOCKS5 proxy, UDP ASSOCIATE
    /// UDP sockets) are created and issued in the host NS (aligned with kdae), source address is the host real
    /// WAN address instead of daens internal address `169.254.0.11`. `None` means create in the current namespace
    /// (default behavior, direct use scenario).
    pub host_ns_fd: Option<RawFd>,
}

impl Socks5Dialer {
    /// Create a new SOCKS5 Dialer
    ///
    /// # Parameters
    /// * `proxy_addr` - Upstream SOCKS5 proxy server address
    /// * `username` - Authentication username (empty string means no authentication required)
    /// * `password` - Authentication password
    /// * `dial_timeout_ms` - Dial timeout in milliseconds
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
            self_mark: 0,
            host_ns_fd: None,
        }
    }

    /// Create a dialer with a self-mark for eBPF self-exclusion.
    pub fn new_with_mark(
        proxy_addr: SocketAddr,
        username: impl Into<String>,
        password: impl Into<String>,
        dial_timeout_ms: u64,
        self_mark: u32,
    ) -> Self {
        Self {
            proxy_addr,
            dial_timeout: Duration::from_millis(dial_timeout_ms),
            username: username.into(),
            password: password.into(),
            self_mark,
            host_ns_fd: None,
        }
    }

    /// Set host network namespace fd.
    ///
    /// After setting, upstream sockets will be created in the host NS (aligned with kdae),
    /// making the source address the host real WAN address instead of daens internal address.
    pub fn set_host_ns_fd(&mut self, host_ns_fd: Option<RawFd>) -> &mut Self {
        self.host_ns_fd = host_ns_fd;
        self
    }

    /// Connect to the SOCKS5 proxy with SO_MARK set before the TCP SYN is sent.
    ///
    /// Uses a raw libc socket to set SO_MARK before connect(), then hands
    /// the fd to tokio for async completion monitoring.
    ///
    /// When `host_ns_fd` is set (proxy NS scenario), the socket is created and
    /// connect() is initiated in the **host** network namespace, so the SYN
    /// source address is the host's real WAN address instead of the daens
    /// internal address `169.254.0.11`. This matches kdae's behavior.
    async fn connect_with_mark(&self) -> Result<TcpStream, Socks5Error> {
        debug!(
            proxy = %self.proxy_addr,
            self_mark = %format!("{:#x}", self.self_mark),
            host_ns_fd = ?self.host_ns_fd,
            timeout_ms = %self.dial_timeout.as_millis(),
            "SOCKS5 proxy TCP connect started"
        );

        let result = crate::hostns::connect_tcp(
            self.proxy_addr,
            &crate::hostns::DirectSocket {
                self_mark: self.self_mark,
                host_ns_fd: self.host_ns_fd,
            },
            true,
            self.dial_timeout,
        )
        .await;

        match result {
            Ok(stream) => {
                debug!(
                    proxy = %self.proxy_addr,
                    "SOCKS5 proxy TCP connect succeeded"
                );
                Ok(stream)
            }
            Err(e) => {
                debug!(
                    proxy = %self.proxy_addr,
                    error = ?e,
                    "SOCKS5 proxy TCP connect failed"
                );
                if e.kind() == std::io::ErrorKind::TimedOut {
                    Err(Socks5Error::Timeout(format!("connect to proxy {}", self.proxy_addr)))
                } else {
                    Err(Socks5Error::Io(e))
                }
            }
        }
    }

    /// Execute SOCKS5 handshake
    ///
    /// Includes:
    /// 1. Negotiate authentication method
    /// 2. Authenticate (if required)
    /// 3. Send connection request
    async fn handshake(&self, stream: &mut TcpStream, target: &str) -> Result<(), Socks5Error> {
        // Step 1: Negotiate authentication method
        // Send: version + number of supported authentication methods + method list
        let methods: Vec<u8> = if self.username.is_empty() {
            // Only no authentication supported (0x00)
            vec![0x05, 0x01, 0x00]
        } else {
            // Support no authentication (0x00) and username/password authentication (0x02)
            vec![0x05, 0x02, 0x00, 0x02]
        };
        stream.write_all(&methods).await?;
        debug!(
            proxy = %self.proxy_addr,
            methods = ?methods,
            "SOCKS5 auth methods sent"
        );

        // Read the authentication method selected by the server
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;

        if response[0] != 0x05 {
            return Err(Socks5Error::ProtocolError("invalid SOCKS5 version".into()));
        }

        debug!(
            proxy = %self.proxy_addr,
            auth_method = response[1],
            "SOCKS5 auth method selected"
        );

        match response[1] {
            0x00 => {
                // No authentication, continue
            }
            0x02 => {
                // Username/password authentication
                if self.username.is_empty() {
                    return Err(Socks5Error::AuthFailed(
                        "server requires auth but no credentials provided".into(),
                    ));
                }
                self.auth_username_password(stream).await?;
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

        // Step 2: Send connection request
        // Parse target address (supports domain names and IP)
        // Note: target format is "host:port", IPv6 is "[::1]:80"
        let port = parse_port_from_target(target)?;
        let host = parse_host_from_target(target);

        // Build connection request
        let mut request = Vec::with_capacity(256);
        request.push(0x05); // SOCKS5 version
        request.push(0x01); // CONNECT command
        request.push(0x00); // reserved

        // Try to parse as IPv4 address
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            request.push(0x01); // IPv4 address type
            request.extend_from_slice(&ip.octets());
        }
        // Try to parse as IPv6 address (need to remove brackets)
        else if let Ok(ip) = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::Ipv6Addr>()
        {
            request.push(0x04); // IPv6 address type
            request.extend_from_slice(&ip.octets());
        }
        // Otherwise send as domain name
        else {
            request.push(0x03); // domain name type
            let host_bytes = host.as_bytes();
            if host_bytes.len() > 255 {
                return Err(Socks5Error::ProtocolError(
                    "target hostname too long".into(),
                ));
            }
            request.push(host_bytes.len() as u8);
            request.extend_from_slice(host_bytes);
        }

        // Port (network byte order)
        request.extend_from_slice(&port.to_be_bytes());

        stream.write_all(&request).await?;
        debug!(
            proxy = %self.proxy_addr,
            target = %target,
            request_len = request.len(),
            "SOCKS5 CONNECT request sent"
        );

        // Read connection response
        let mut reply = [0u8; 4];
        stream.read_exact(&mut reply).await?;

        if reply[0] != 0x05 {
            return Err(Socks5Error::ProtocolError(
                "invalid SOCKS5 reply version".into(),
            ));
        }

        match reply[1] {
            0x00 => {
                // Success, read remaining address info
                let addr_type = reply[3];
                let addr_len = match addr_type {
                    0x01 => 4,  // IPv4
                    0x04 => 16, // IPv6
                    0x03 => {
                        // Domain name
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
            0x08 => Err(Socks5Error::ProtocolError(
                "address type not supported".into(),
            )),
            _ => Err(Socks5Error::ProtocolError(format!(
                "unknown reply code: 0x{:02x}",
                reply[1]
            ))),
        }
    }
}

// ============================================================================
// SOCKS5 UDP ASSOCIATE
// ============================================================================

/// A UDP ASSOCIATE session with a SOCKS5 server.
///
/// Keeps the TCP control connection open and provides a UDP socket
/// for sending/receiving relayed UDP datagrams.
pub struct UdpAssociateSession {
    /// TCP control connection (must stay alive for the session)
    #[allow(dead_code)]
    control: TcpStream,
    /// UDP data socket bound locally for the relay
    pub udp: UdpSocket,
    /// The SOCKS5 server's UDP relay address
    pub relay_addr: SocketAddr,
    /// When this session was last used (for cache eviction)
    pub last_used: Instant,
}

impl UdpAssociateSession {
    /// Build the SOCKS5 UDP request header for a given target.
    ///
    /// Format:
    /// ```text
    /// +----+------+------+----------+----------+----------+
    /// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
    /// +----+------+------+----------+----------+----------+
    /// | 2  |  1   |  1   | variable |    2     | variable |
    /// +----+------+------+----------+----------+----------+
    /// ```
    pub fn build_udp_request_header(target: &SocketAddr, data_len: usize) -> Vec<u8> {
        let mut header = Vec::with_capacity(7 + data_len);
        header.extend_from_slice(&[0x00, 0x00]); // RSV
        header.push(0x00); // FRAG = 0 (no fragmentation)

        match target {
            SocketAddr::V4(v4) => {
                header.push(0x01); // ATYP IPv4
                header.extend_from_slice(&v4.ip().octets());
            }
            SocketAddr::V6(v6) => {
                header.push(0x04); // ATYP IPv6
                header.extend_from_slice(&v6.ip().octets());
            }
        }
        header.extend_from_slice(&target.port().to_be_bytes()); // DST.PORT
        header
    }

    /// Parse a SOCKS5 UDP response header and return (peer_addr, payload_offset).
    /// Returns None if the header is invalid.
    pub fn parse_udp_response_header(data: &[u8]) -> Option<(SocketAddr, usize)> {
        if data.len() < 4 {
            return None;
        }
        // RSV (2 bytes) + FRAG (1 byte)
        let frag = data[2];
        if frag != 0 {
            // Fragmentation not supported
            return None;
        }
        let atyp = data[3];
        let (addr, header_len): (SocketAddr, usize) = match atyp {
            0x01 => {
                // IPv4
                if data.len() < 10 {
                    return None;
                }
                let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                let port = u16::from_be_bytes([data[8], data[9]]);
                (SocketAddr::new(std::net::IpAddr::V4(ip), port), 10)
            }
            0x04 => {
                // IPv6
                if data.len() < 22 {
                    return None;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[4..20]);
                let ip = std::net::Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([data[20], data[21]]);
                (SocketAddr::new(std::net::IpAddr::V6(ip), port), 22)
            }
            0x03 => {
                // Domain name
                if data.len() < 5 {
                    return None;
                }
                let name_len = data[4] as usize;
                if data.len() < 5 + name_len + 2 {
                    return None;
                }
                let _name = std::str::from_utf8(&data[5..5 + name_len]).ok()?;
                let port = u16::from_be_bytes([data[5 + name_len], data[5 + name_len + 1]]);
                (
                    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), port),
                    5 + name_len + 2,
                )
            }
            _ => return None,
        };
        Some((addr, header_len))
    }
}

/// A pool of UDP ASSOCIATE sessions, keyed by target address.
///
/// Reuses sessions for the same target to avoid re-handshaking.
/// Idle sessions expire after [`UDP_POOL_TIMEOUT`].
const UDP_POOL_TIMEOUT: Duration = Duration::from_secs(120);

pub struct UdpEndpointPool {
    inner: Mutex<HashMap<String, Arc<Mutex<UdpAssociateSession>>>>,
}

impl UdpEndpointPool {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Get or create a UDP associate session for the given target.
    pub async fn get_or_create(
        &self,
        target: &str,
        dialer: &Socks5Dialer,
    ) -> anyhow::Result<Arc<Mutex<UdpAssociateSession>>> {
        let key = target.to_string();
        let mut map = self.inner.lock().await;

        // Check for existing session
        if let Some(session) = map.get(&key) {
            let mut sess = session.lock().await;
            sess.last_used = Instant::now();
            debug!(target = %target, "SOCKS5 UDP session reused");
            return Ok(session.clone());
        }

        // Create new session
        debug!(target = %target, "SOCKS5 UDP session creating");
        let session = Arc::new(Mutex::new(dialer.udp_associate().await?));
        map.insert(key, session.clone());
        Ok(session)
    }

    /// Clean up expired sessions.
    pub async fn cleanup(&self) {
        let mut map = self.inner.lock().await;
        map.retain(|_, session| {
            if let Ok(sess) = session.try_lock() {
                sess.last_used.elapsed() < UDP_POOL_TIMEOUT
            } else {
                true // skip locked sessions
            }
        });
    }

    /// Remove a specific session (for error recovery).
    pub async fn remove(&self, target: &str) {
        self.inner.lock().await.remove(target);
    }
}

impl Default for UdpEndpointPool {
    fn default() -> Self {
        Self::new()
    }
}

impl Socks5Dialer {
    /// Establish a UDP ASSOCIATE session with the SOCKS5 server.
    ///
    /// 1. Connect to proxy via TCP
    /// 2. Perform auth handshake
    /// 3. Send UDP ASSOCIATE command
    /// 4. Get relay address back
    /// 5. Bind a local UDP socket
    /// 6. Return session with control TCP + data UDP
    pub async fn udp_associate(&self) -> Result<UdpAssociateSession, Socks5Error> {
        let mut control = self.connect_with_mark().await?;
        debug!(
            proxy = %self.proxy_addr,
            "SOCKS5 UDP ASSOCIATE connect established"
        );

        // Perform auth handshake
        self.handshake_inner(&mut control, false).await?;

        debug!(
            proxy = %self.proxy_addr,
            "SOCKS5 UDP ASSOCIATE handshake completed"
        );

        // Send UDP ASSOCIATE command (CMD=0x03) with BND.ADDR=0/BND.PORT=0
        let request: Vec<u8> = vec![
            0x05, // SOCKS5 version
            0x03, // UDP ASSOCIATE
            0x00, // RSV
            0x01, // ATYP: IPv4
            0x00, 0x00, 0x00, 0x00, // BND.ADDR: 0.0.0.0
            0x00, 0x00, // BND.PORT: 0
        ];
        control.write_all(&request).await.map_err(Socks5Error::Io)?;

        // Read response
        let mut reply = [0u8; 4];
        control
            .read_exact(&mut reply)
            .await
            .map_err(Socks5Error::Io)?;

        if reply[0] != 0x05 {
            return Err(Socks5Error::ProtocolError(
                "invalid SOCKS5 version in ASSOCIATE reply".into(),
            ));
        }
        if reply[1] != 0x00 {
            return Err(Socks5Error::ProtocolError(format!(
                "UDP ASSOCIATE failed: code 0x{:02x}",
                reply[1]
            )));
        }

        // Parse BND.ADDR and BND.PORT from the response
        let addr_type = reply[3];
        let relay_addr = match addr_type {
            0x01 => {
                // IPv4
                let mut addr_buf = [0u8; 6]; // 4 bytes IP + 2 bytes port
                control
                    .read_exact(&mut addr_buf)
                    .await
                    .map_err(Socks5Error::Io)?;
                let ip =
                    std::net::Ipv4Addr::new(addr_buf[0], addr_buf[1], addr_buf[2], addr_buf[3]);
                let port = u16::from_be_bytes([addr_buf[4], addr_buf[5]]);
                let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);
                debug!(
                    proxy = %self.proxy_addr,
                    relay_addr = %addr,
                    "SOCKS5 UDP ASSOCIATE relay address parsed"
                );
                addr
            }
            0x04 => {
                // IPv6
                let mut addr_buf = [0u8; 18]; // 16 bytes IP + 2 bytes port
                control
                    .read_exact(&mut addr_buf)
                    .await
                    .map_err(Socks5Error::Io)?;
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&addr_buf[..16]);
                let ip = std::net::Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([addr_buf[16], addr_buf[17]]);
                SocketAddr::new(std::net::IpAddr::V6(ip), port)
            }
            0x03 => {
                // Domain name
                let mut len_buf = [0u8; 1];
                control
                    .read_exact(&mut len_buf)
                    .await
                    .map_err(Socks5Error::Io)?;
                let name_len = len_buf[0] as usize;
                let mut name_buf = vec![0u8; name_len + 2]; // name + port
                control
                    .read_exact(&mut name_buf)
                    .await
                    .map_err(Socks5Error::Io)?;
                let port = u16::from_be_bytes([name_buf[name_len], name_buf[name_len + 1]]);
                // Resolve domain name
                let ip = tokio::net::lookup_host(format!(
                    "{}:{}",
                    std::str::from_utf8(&name_buf[..name_len]).unwrap_or(""),
                    port
                ))
                .await
                .map_err(|e| Socks5Error::Other(format!("DNS resolve failed: {}", e)))?
                .next()
                .ok_or_else(|| Socks5Error::Other("DNS returned no addresses".into()))?;
                ip
            }
            _ => {
                return Err(Socks5Error::ProtocolError(format!(
                    "unknown address type in ASSOCIATE reply: 0x{:02x}",
                    addr_type
                )));
            }
        };

        // Bind a local UDP socket.
        // When host_ns_fd is set, create the relay socket in the host NS so
        // UDP datagrams to the SOCKS5 relay leave from the host's real source
        // address (kdae-aligned). The fd is namespace-independent after
        // creation, so tokio I/O can continue from the original context.
        let local_udp: UdpSocket = {
            let std_udp = crate::hostns::create_udp(
                relay_addr,
                &crate::hostns::DirectSocket {
                    self_mark: self.self_mark,
                    host_ns_fd: self.host_ns_fd,
                },
            )
            .map_err(Socks5Error::Io)?;
            // Connect the UDP socket to the relay address (so we can use send()).
            std_udp.connect(relay_addr).map_err(Socks5Error::Io)?;
            tokio::net::UdpSocket::from_std(std_udp).map_err(Socks5Error::Io)?
        };

        debug!(
            proxy = %self.proxy_addr,
            relay_addr = %relay_addr,
            host_ns_fd = ?self.host_ns_fd,
            "SOCKS5 UDP ASSOCIATE session created"
        );
        debug!(
            proxy = %self.proxy_addr,
            relay_addr = %relay_addr,
            "SOCKS5 UDP ASSOCIATE local UDP socket bound"
        );
        Ok(UdpAssociateSession {
            control,
            udp: local_udp,
            relay_addr,
            last_used: Instant::now(),
        })
    }

    /// Internal handshake that can skip the CONNECT command (for ASSOCIATE).
    async fn handshake_inner(
        &self,
        stream: &mut TcpStream,
        do_connect: bool,
    ) -> Result<(), Socks5Error> {
        // Auth method negotiation
        let methods: Vec<u8> = if self.username.is_empty() {
            vec![0x05, 0x01, 0x00]
        } else {
            vec![0x05, 0x02, 0x00, 0x02]
        };
        stream.write_all(&methods).await?;

        debug!(
            proxy = %self.proxy_addr,
            methods = ?methods,
            do_connect = %do_connect,
            "SOCKS5 auth methods sent (handshake_inner)"
        );

        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;

        if response[0] != 0x05 {
            return Err(Socks5Error::ProtocolError(
                "invalid SOCKS5 version during auth".into(),
            ));
        }

        debug!(
            proxy = %self.proxy_addr,
            auth_method = response[1],
            "SOCKS5 auth method selected (handshake_inner)"
        );

        match response[1] {
            0x00 => {}
            0x02 => {
                if self.username.is_empty() {
                    return Err(Socks5Error::AuthFailed(
                        "server requires auth but no credentials provided".into(),
                    ));
                }
                self.auth_username_password(stream).await?;
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

        if do_connect {
            // CONNECT command is done by the caller via the standard handshake
        }

        Ok(())
    }

    /// Username/password auth (RFC 1929).
    async fn auth_username_password(&self, stream: &mut TcpStream) -> Result<(), Socks5Error> {
        let username_bytes = self.username.as_bytes();
        let password_bytes = self.password.as_bytes();

        if username_bytes.len() > 255 || password_bytes.len() > 255 {
            return Err(Socks5Error::AuthFailed(
                "username or password too long".into(),
            ));
        }

        let mut auth_msg = Vec::with_capacity(3 + username_bytes.len() + password_bytes.len());
        auth_msg.push(0x01);
        auth_msg.push(username_bytes.len() as u8);
        auth_msg.extend_from_slice(username_bytes);
        auth_msg.push(password_bytes.len() as u8);
        auth_msg.extend_from_slice(password_bytes);

        stream.write_all(&auth_msg).await?;

        let mut auth_reply = [0u8; 2];
        stream.read_exact(&mut auth_reply).await?;

        debug!(
            proxy = %self.proxy_addr,
            status = auth_reply[1],
            "SOCKS5 username/password auth reply received"
        );

        if auth_reply[0] != 0x01 {
            return Err(Socks5Error::AuthFailed(format!(
                "invalid auth sub-negotiation version: 0x{:02x}",
                auth_reply[0]
            )));
        }

        if auth_reply[1] != 0x00 {
            return Err(Socks5Error::AuthFailed(
                "invalid username or password".into(),
            ));
        }

        Ok(())
    }
}

// ============================================================================
// Target address parsing helpers
// ============================================================================

/// Parse port from "host:port" or "[ipv6]:port" string.
fn parse_port_from_target(target: &str) -> Result<u16, Socks5Error> {
    // For IPv6 like "[::1]:80", find ']' first
    if let Some(bracket_end) = target.rfind(']') {
        let port_str = target[bracket_end + 1..].trim_start_matches(':');
        return port_str.parse().map_err(|_| {
            Socks5Error::ProtocolError(format!("invalid target (IPv6 parse): {}", target))
        });
    }
    // IPv4 or hostname: split at last colon
    let parts: Vec<&str> = target.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(Socks5Error::ProtocolError(format!(
            "invalid target address: {}",
            target
        )));
    }
    parts[0]
        .parse()
        .map_err(|_| Socks5Error::ProtocolError(format!("invalid target port: {}", target)))
}

/// Parse host from "host:port" or "[ipv6]:port" string (returns bare host without brackets).
fn parse_host_from_target(target: &str) -> &str {
    if let Some(bracket_end) = target.rfind(']') {
        // IPv6: extract content between brackets
        let start = target.find('[').unwrap_or(bracket_end);
        &target[start + 1..bracket_end]
    } else if let Some(colon_pos) = target.rfind(':') {
        // IPv4 or hostname: extract before last colon
        &target[..colon_pos]
    } else {
        target
    }
}

// ============================================================================
// OutboundDialer trait implementation
// ============================================================================

#[async_trait]
impl OutboundDialer for Socks5Dialer {
    /// Dial to target address through SOCKS5 proxy
    async fn dial(&self, target: &str) -> anyhow::Result<ProxyConn> {
        debug!(
            proxy = %self.proxy_addr,
            target = %target,
            "SOCKS5 dial starting"
        );
        let mut stream = self.connect_with_mark().await?;

        debug!(
            proxy = %self.proxy_addr,
            target = %target,
            "SOCKS5 handshake starting"
        );

        // Execute SOCKS5 handshake
        self.handshake(&mut stream, target)
            .await
            .map_err(|e| anyhow::anyhow!("SOCKS5 handshake failed: {}", e))?;

        debug!(
            proxy = %self.proxy_addr,
            target = %target,
            "SOCKS5 dial completed"
        );
        ProxyConn::new_tcp(stream).map_err(Into::into)
    }

    /// Establish SOCKS5 UDP ASSOCIATE session
    async fn udp_dial(&self) -> anyhow::Result<Box<dyn crate::UdpSession>> {
        let session = self.udp_associate().await?;
        Ok(Box::new(SocksUdpSession { session }))
    }

    /// Return protocol name
    fn protocol_name(&self) -> &'static str {
        "socks5"
    }
    fn proxy_addr(&self) -> std::net::SocketAddr {
        self.proxy_addr
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// SOCKS5 UDP ASSOCIATE session `UdpSession` adapter.
///
/// Send: SOCKS5 UDP request header (RSV/FRAG/ATYP/ADDR/PORT) + payload.
/// Receive: parse SOCKS5 UDP response header, return original target address + payload.
pub struct SocksUdpSession {
    session: UdpAssociateSession,
}

#[async_trait]
impl crate::UdpSession for SocksUdpSession {
    async fn send(&self, dest: &std::net::SocketAddr, payload: &[u8]) -> anyhow::Result<()> {
        let mut send_buf = UdpAssociateSession::build_udp_request_header(dest, payload.len());
        send_buf.extend_from_slice(payload);
        debug!(
            dest = %dest,
            payload_len = payload.len(),
            relay = %self.session.relay_addr,
            "SOCKS5 UDP relay send"
        );
        self.session.udp.send(&send_buf).await?;
        Ok(())
    }

    async fn recv(&self) -> anyhow::Result<(std::net::SocketAddr, Vec<u8>)> {
        let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];
        loop {
            let len = self.session.udp.recv(&mut buf).await?;
            if let Some((dest, offset)) =
                UdpAssociateSession::parse_udp_response_header(&buf[..len])
            {
                debug!(
                    dest = %dest,
                    relay = %self.session.relay_addr,
                    response_len = len - offset,
                    "SOCKS5 UDP relay response received"
                );
                return Ok((dest, buf[offset..len].to_vec()));
            }
            // Non-SOCKS5 UDP packets (like fragments), ignore and retry
        }
    }
}

/// SOCKS5 UDP packet maximum size
const MAX_UDP_PACKET_SIZE: usize = 65535;

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
