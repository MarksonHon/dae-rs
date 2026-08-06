//! Shadowsocks protocol dialer
//!
//! Implements Shadowsocks outbound proxy protocol (TCP), supporting:
//! - AEAD (Legacy) - EVP_BytesToKey master key + HKDF-SHA1 session sub-key
//! - 2022 Edition (SIP022) - BLAKE3 identity key + session sub-key
//!
//! Encryption and framing implemented using `shadowsocks-crypto` crate:
//! - Client sends random salt first (`kind.salt_len()` bytes)
//! - Each subsequent packet: `[encrypted 2-byte length][encrypted payload]`, each with 16-byte AEAD tag
//! - Length 0 indicates EOF
//! Reference: https://shadowsocks.org/doc/sip022.html

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use std::str::FromStr;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use shadowsocks_crypto::kind::CipherCategory;
use shadowsocks_crypto::utils::random_iv_or_salt;
use shadowsocks_crypto::v1::{openssl_bytes_to_key, Cipher as V1Cipher};
use shadowsocks_crypto::v2::tcp::TcpCipher as V2TcpCipher;
use shadowsocks_crypto::CipherKind;

use crate::{OutboundDialer, ProxyConn};

/// Shadowsocks Dialer error
#[derive(Debug, thiserror::Error)]
pub enum ShadowsocksError {
    #[error("Shadowsocks dial timeout: {0}")]
    Timeout(String),
    #[error("Shadowsocks connection refused: {0}")]
    ConnectionRefused(String),
    #[error("Shadowsocks protocol error: {0}")]
    ProtocolError(String),
    #[error("Shadowsocks invalid cipher: {0}")]
    InvalidCipher(String),
    #[error("Shadowsocks IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Shadowsocks error: {0}")]
    Other(String),
}

/// AEAD TCP packet maximum payload length (0x3FFF)
const MAX_PAYLOAD: usize = 0x3FFF;

/// BLAKE3 derive-key context for the AEAD-2022 identity key (SIP022)
const BLAKE3_IDENTITY_CONTEXT: &str = "shadowsocks 2022 identity";

/// Generate a random AEAD 2022 UDP client session ID (shadowsocks-rust uses a
/// stable per-relay-socket session ID; each `udp_dial` gets its own).
fn random_session_id() -> u64 {
    let mut buf = [0u8; 8];
    random_iv_or_salt(&mut buf);
    u64::from_be_bytes(buf)
}

/// Shadowsocks Dialer
pub struct ShadowsocksDialer {
    /// Upstream Shadowsocks proxy server address
    pub proxy_addr: SocketAddr,
    /// Dial timeout duration
    pub dial_timeout: Duration,
    /// Encryption method (e.g., `aes-256-gcm`, `2022-blake3-aes-256-gcm`)
    pub cipher: String,
    /// Password
    pub password: String,
    /// fwmark for eBPF self-exclusion
    pub self_mark: u32,
    /// Host network namespace fd
    pub host_ns_fd: Option<RawFd>,
}

impl ShadowsocksDialer {
    /// Create a new Shadowsocks Dialer
    pub fn new(
        proxy_addr: SocketAddr,
        cipher: impl Into<String>,
        password: impl Into<String>,
        dial_timeout_ms: u64,
    ) -> Self {
        Self {
            proxy_addr,
            dial_timeout: Duration::from_millis(dial_timeout_ms),
            cipher: cipher.into(),
            password: password.into(),
            self_mark: 0,
            host_ns_fd: None,
        }
    }

    /// Create dialer with self-mark
    pub fn new_with_mark(
        proxy_addr: SocketAddr,
        cipher: impl Into<String>,
        password: impl Into<String>,
        dial_timeout_ms: u64,
        self_mark: u32,
    ) -> Self {
        Self {
            proxy_addr,
            dial_timeout: Duration::from_millis(dial_timeout_ms),
            cipher: cipher.into(),
            password: password.into(),
            self_mark,
            host_ns_fd: None,
        }
    }

    /// Set host network namespace fd
    pub fn set_host_ns_fd(&mut self, host_ns_fd: Option<RawFd>) -> &mut Self {
        self.host_ns_fd = host_ns_fd;
        self
    }

    /// Connect to the Shadowsocks proxy via the shared host-ns TCP helper.
    async fn connect_with_mark(&self) -> Result<TcpStream, ShadowsocksError> {
        crate::hostns::connect_tcp(
            self.proxy_addr,
            &crate::hostns::DirectSocket {
                self_mark: self.self_mark,
                host_ns_fd: self.host_ns_fd,
            },
            true,
            self.dial_timeout,
        )
        .await
        .map_err(|e| {
            if e.kind() == io::ErrorKind::TimedOut {
                ShadowsocksError::Timeout(format!("connect to proxy {}", self.proxy_addr))
            } else {
                ShadowsocksError::Io(e)
            }
        })
    }

    /// Parse encryption method (kind) and derive master key.
    fn cipher_kind(&self) -> Result<CipherKind, ShadowsocksError> {
        CipherKind::from_str(&self.cipher)
            .map_err(|e| ShadowsocksError::InvalidCipher(format!("'{}': {}", self.cipher, e)))
    }

    /// Derive master key: legacy = EVP_BytesToKey(password), 2022 = BLAKE3 derive-key.
    fn master_key(kind: CipherKind, password: &str) -> Vec<u8> {
        let mut key = vec![0u8; kind.key_len()];
        match kind.category() {
            CipherCategory::Aead => openssl_bytes_to_key(password.as_bytes(), &mut key),
            CipherCategory::Aead2022 => {
                let mut hasher = blake3::Hasher::new_derive_key(BLAKE3_IDENTITY_CONTEXT);
                hasher.update(password.as_bytes());
                let mut output = hasher.finalize_xof();
                output.fill(&mut key);
            }
            _ => {}
        }
        key
    }

    /// Derive master key and construct cipher (once per connection, carrying client random salt).
    ///
    /// Ciphertext decryptor left empty, lazily initialized after receiving server salt.
    fn new_cipher_pair(&self) -> Result<SsCipherPair, ShadowsocksError> {
        let kind = self.cipher_kind()?;
        let mut salt = vec![0u8; kind.salt_len()];
        random_iv_or_salt(&mut salt);
        let key = Self::master_key(kind, &self.password);

        let enc = match kind.category() {
            CipherCategory::Aead => SsCipher::Legacy(V1Cipher::new(kind, &key, &salt)),
            CipherCategory::Aead2022 => SsCipher::V2022(V2TcpCipher::new(kind, &key, &salt)),
            other => {
                return Err(ShadowsocksError::InvalidCipher(format!(
                    "cipher '{}' category {:?} is not supported",
                    self.cipher, other
                )))
            }
        };
        Ok(SsCipherPair {
            salt,
            enc,
            kind,
            master_key: key,
        })
    }

    /// Encode the target address: ATYP + ADDR + PORT (1=IPv4, 3=Domain name, 4=IPv6)
    fn encode_address(target: &str) -> Result<Vec<u8>, ShadowsocksError> {
        let (host, port) = split_target(target)?;
        encode_addr(host, port)
    }
}

/// Split `host:port` target string (supports [ipv6]:port)
fn split_target(target: &str) -> Result<(&str, u16), ShadowsocksError> {
    let (mut host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| ShadowsocksError::ProtocolError(format!("invalid target '{}'", target)))?;
    let port: u16 = port
        .parse()
        .map_err(|_| ShadowsocksError::ProtocolError(format!("invalid target port '{}'", target)))?;
    if host.starts_with('[') && host.ends_with(']') {
        host = &host[1..host.len() - 1];
    }
    Ok((host, port))
}

/// Encode Shadowsocks address: ATYP + ADDR + PORT
fn encode_addr(host: &str, port: u16) -> Result<Vec<u8>, ShadowsocksError> {
    let mut addr = Vec::with_capacity(1 + 16 + 2);
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        addr.push(0x01);
        addr.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        addr.push(0x04);
        addr.extend_from_slice(&ip.octets());
    } else {
        let host_bytes = host.as_bytes();
        if host_bytes.len() > 255 {
            return Err(ShadowsocksError::ProtocolError(format!(
                "target domain too long: '{}'",
                host
            )));
        }
        addr.push(0x03);
        addr.push(host_bytes.len() as u8);
        addr.extend_from_slice(host_bytes);
    }
    addr.extend_from_slice(&port.to_be_bytes());
    Ok(addr)
}

/// Encode Shadowsocks address from a `SocketAddr`: ATYP + ADDR + PORT (1=IPv4, 4=IPv6).
/// Writes the address octets directly, avoiding an intermediate string allocation.
fn encode_socket_addr(dest: &SocketAddr) -> Result<Vec<u8>, ShadowsocksError> {
    let mut addr = Vec::with_capacity(1 + 16 + 2);
    match dest {
        SocketAddr::V4(v4) => {
            addr.push(0x01);
            addr.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            addr.push(0x04);
            addr.extend_from_slice(&v6.ip().octets());
        }
    }
    addr.extend_from_slice(&dest.port().to_be_bytes());
    Ok(addr)
}

/// Decode Shadowsocks address, return `(SocketAddr, bytes consumed)`.
/// Domain names resolve to 0.0.0.0:port (the port is preserved when the address
/// cannot be resolved in a DNS-free scenario).
fn decode_addr(data: &[u8]) -> Result<(SocketAddr, usize), ShadowsocksError> {
    if data.is_empty() {
        return Err(ShadowsocksError::ProtocolError("empty address".into()));
    }
    match data[0] {
        0x01 => {
            if data.len() < 7 {
                return Err(ShadowsocksError::ProtocolError("short ipv4 address".into()));
            }
            let ip = std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok((SocketAddr::from((ip, port)), 7))
        }
        0x04 => {
            if data.len() < 19 {
                return Err(ShadowsocksError::ProtocolError("short ipv6 address".into()));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok((SocketAddr::from((ip, port)), 19))
        }
        0x03 => {
            if data.len() < 2 {
                return Err(ShadowsocksError::ProtocolError("short domain address".into()));
            }
            let len = data[1] as usize;
            if data.len() < 2 + len + 2 {
                return Err(ShadowsocksError::ProtocolError("short domain address".into()));
            }
            let port = u16::from_be_bytes([data[2 + len], data[3 + len]]);
            Ok((SocketAddr::from(([0, 0, 0, 0], port)), 2 + len + 2))
        }
        other => Err(ShadowsocksError::ProtocolError(format!(
            "unknown address type: {}",
            other
        ))),
    }
}

#[async_trait]
impl OutboundDialer for ShadowsocksDialer {
    async fn dial(&self, target: &str) -> anyhow::Result<ProxyConn> {
        let mut stream = self.connect_with_mark().await?;

        // 1. Construct cipher and send random salt
        let mut cipher = self.new_cipher_pair()?;
        stream.write_all(&cipher.salt).await.map_err(ShadowsocksError::Io)?;

        // 2. Send encrypted target address
        let target_addr = Self::encode_address(target)?;
        let framed = cipher.frame_packet(&target_addr)?;
        // [DEBUG] Temporary debug log: to locate "length tag verification failed", prints the
        // target, the address header hex and the first-frame prefix hex (for comparison against
        // sslocal packet captures). Kept at trace level so it is off by default.
        let first_frame_prefix32 = framed.iter().take(32).copied().collect::<Vec<_>>();
        tracing::trace!(
            "shadowsocks debug dial: target={} encode_address={} salt={} first_frame_prefix32={}",
            target,
            hex::encode(&target_addr),
            hex::encode(&cipher.salt),
            hex::encode(&first_frame_prefix32),
        );
        stream.write_all(&framed).await.map_err(ShadowsocksError::Io)?;

        // 3. Wrap into encrypted stream and return
        let ss_stream = SsStream::new(stream, cipher);
        Ok(ProxyConn::new_boxed(Box::new(ss_stream)))
    }

    /// Establish Shadowsocks UDP relay session.
    ///
    /// Legacy AEAD: each datagram independently salted encrypted
    /// (`[salt][AEAD(addr + payload)]`). AEAD 2022: SIP022 UDP wire format.
    /// No handshake needed; datagrams go straight to the proxy server.
    async fn udp_dial(&self) -> anyhow::Result<Box<dyn crate::UdpSession>> {
        let kind = self.cipher_kind()?;
        let key = Self::master_key(kind, &self.password);
        let socket = crate::hostns::create_udp(
            self.proxy_addr,
            &crate::hostns::DirectSocket {
                self_mark: self.self_mark,
                host_ns_fd: self.host_ns_fd,
            },
        )
        .map_err(ShadowsocksError::Io)?;
        socket.connect(self.proxy_addr).map_err(ShadowsocksError::Io)?;
        let socket = tokio::net::UdpSocket::from_std(socket).map_err(ShadowsocksError::Io)?;
        Ok(Box::new(SsUdpSession {
            socket,
            kind,
            key,
            is_2022: kind.is_aead_2022(),
            client_session_id: random_session_id(),
            packet_id: std::sync::atomic::AtomicU64::new(0),
            recv_buf: tokio::sync::Mutex::new(BytesMut::zeroed(65535)),
        }))
    }

    fn protocol_name(&self) -> &'static str {
        "shadowsocks"
    }
    fn proxy_addr(&self) -> std::net::SocketAddr {
        self.proxy_addr
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Shadowsocks UDP relay session.
///
/// Legacy AEAD datagram: `[salt][AEAD(addr + payload)]` (each datagram
/// independently salted; key = master key, nonce derived from salt).
///
/// AEAD 2022 (SIP022) datagram — matches shadowsocks-rust's
/// `relay/udprelay/aead_2022.rs`:
///
/// AES-*-GCM:
/// ```text
/// [AES-ECB(PSK, SessionID||PacketID)] [TYPE][Timestamp][PadLen][Padding][Addr][Payload][TAG]
///     ^^^^^^^^^ 16 bytes ^^^^^^^^^^         ^^^^^^^^  AEAD message ^^^^^^^^
/// AEAD nonce  = header[4..16];  session key = derive(master_key, SessionID)
/// ```
///
/// ChaCha20-Poly1305: same body but nonce (24B) is prepended and the PSK is
/// used directly as the AEAD key (no derived session key).
struct SsUdpSession {
    socket: tokio::net::UdpSocket,
    kind: CipherKind,
    key: Vec<u8>,
    /// Whether this session uses the AEAD 2022 wire format.
    is_2022: bool,
    /// Client session ID (2022): random per session, echoed by the server.
    client_session_id: u64,
    /// Per-packet monotonically increasing ID (2022).
    packet_id: std::sync::atomic::AtomicU64,
    /// Reused receive buffer (avoids a per-datagram 64 KiB allocation).
    recv_buf: tokio::sync::Mutex<BytesMut>,
}

const SS_UDP_TAG_LEN: usize = 16;
/// Server->client socket type marker (AEAD 2022).
const SS_UDP_SERVER_SOCKET_TYPE: u8 = 1;

impl SsUdpSession {
    /// Build a legacy AEAD UDP datagram: `[salt][AEAD(addr + payload)]`.
    fn build_legacy_packet(
        &self,
        dest: &std::net::SocketAddr,
        payload: &[u8],
    ) -> Result<Vec<u8>, ShadowsocksError> {
        let mut salt = vec![0u8; self.kind.salt_len()];
        random_iv_or_salt(&mut salt);

        let addr = encode_socket_addr(dest)?;
        let mut pkt = vec![0u8; addr.len() + payload.len() + SS_UDP_TAG_LEN];
        pkt[..addr.len()].copy_from_slice(&addr);
        pkt[addr.len()..addr.len() + payload.len()].copy_from_slice(payload);

        let mut cipher = V1Cipher::new(self.kind, &self.key, &salt);
        cipher.encrypt_packet(&mut pkt);

        let mut datagram = salt;
        datagram.extend_from_slice(&pkt);
        Ok(datagram)
    }

    /// Build an AEAD 2022 UDP datagram (client -> server).
    fn build_2022_packet(
        &self,
        dest: &std::net::SocketAddr,
        payload: &[u8],
    ) -> Result<Vec<u8>, ShadowsocksError> {
        let addr = encode_socket_addr(dest)?;
        let packet_id = self.packet_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| ShadowsocksError::Other(format!("system clock before epoch: {}", e)))?
            .as_secs();

        match self.kind {
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM | CipherKind::AEAD2022_BLAKE3_AES_256_GCM => {
                // [SessionID(8)][PacketID(8)] ECB-encrypted header + AEAD body
                let body_len = 1 + 8 + 2 + addr.len() + payload.len();
                let mut buf = vec![0u8; 16 + body_len + SS_UDP_TAG_LEN];
                buf[0..8].copy_from_slice(&self.client_session_id.to_be_bytes());
                buf[8..16].copy_from_slice(&packet_id.to_be_bytes());

                // AEAD nonce is the plaintext header[4..16] — capture before ECB.
                let nonce: [u8; 12] = buf[4..16].try_into().expect("12-byte nonce");
                {
                    let body = &mut buf[16..16 + body_len];
                    body[0] = 0; // client socket type
                    body[1..9].copy_from_slice(&now.to_be_bytes());
                    body[9..11].copy_from_slice(&0u16.to_be_bytes()); // padding size
                    body[11..11 + addr.len()].copy_from_slice(&addr);
                    body[11 + addr.len()..].copy_from_slice(payload);
                }

                let cipher = shadowsocks_crypto::v2::udp::UdpCipher::new(
                    self.kind,
                    &self.key,
                    self.client_session_id,
                );
                cipher.encrypt_packet(&nonce, &mut buf[16..]);

                aes_ecb_2022(self.kind, &self.key, &mut buf[0..16], true)
                    .map_err(ShadowsocksError::ProtocolError)?;
                Ok(buf)
            }
            CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305 => {
                let nonce_size = shadowsocks_crypto::v2::udp::ChaCha20Poly1305Cipher::nonce_size();
                let body_len = 8 + 8 + 1 + 8 + 2 + addr.len() + payload.len();
                let mut buf = vec![0u8; nonce_size + body_len + SS_UDP_TAG_LEN];
                let mut nonce = vec![0u8; nonce_size];
                random_iv_or_salt(&mut nonce);
                buf[..nonce_size].copy_from_slice(&nonce);

                let body = &mut buf[nonce_size..nonce_size + body_len];
                body[0..8].copy_from_slice(&self.client_session_id.to_be_bytes());
                body[8..16].copy_from_slice(&packet_id.to_be_bytes());
                body[16] = 0; // client socket type
                body[17..25].copy_from_slice(&now.to_be_bytes());
                body[25..27].copy_from_slice(&0u16.to_be_bytes()); // padding size
                body[27..27 + addr.len()].copy_from_slice(&addr);
                body[27 + addr.len()..].copy_from_slice(payload);

                let cipher = shadowsocks_crypto::v2::udp::UdpCipher::new(
                    self.kind,
                    &self.key,
                    self.client_session_id,
                );
                cipher.encrypt_packet(&nonce, &mut buf[nonce_size..]);
                Ok(buf)
            }
            other => Err(ShadowsocksError::InvalidCipher(format!(
                "cipher '{}' category {:?} not supported for UDP 2022",
                self.kind, other
            ))),
        }
    }

    /// Decrypt and parse a server (server -> client) AEAD 2022 datagram.
    fn recv_2022(&self, data: &[u8]) -> Result<(std::net::SocketAddr, Vec<u8>), ShadowsocksError> {
        let mut buf = data.to_vec();

        // Decrypted server body differs by kind:
        //  - AES-GCM: body starts with TYPE (header `[SessionID||PacketID]` is the ECB block)
        //  - ChaCha:  body starts with `[server_session_id||packet_id]`, TYPE follows
        // `skip` = offset of the TYPE byte within the body.
        let (body, skip) = match self.kind {
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM | CipherKind::AEAD2022_BLAKE3_AES_256_GCM => {
                if buf.len() < 16 + 1 + 8 + 8 + 2 + SS_UDP_TAG_LEN {
                    return Err(ShadowsocksError::ProtocolError(
                        "short AEAD 2022 server UDP packet".into(),
                    ));
                }
                let header_len = 16;
                aes_ecb_2022(self.kind, &self.key, &mut buf[0..header_len], false)
                    .map_err(ShadowsocksError::ProtocolError)?;
                let server_session_id = u64::from_be_bytes(buf[0..8].try_into().unwrap());
                let nonce: [u8; 12] = buf[4..16].try_into().expect("12-byte nonce");
                let cipher = shadowsocks_crypto::v2::udp::UdpCipher::new(
                    self.kind,
                    &self.key,
                    server_session_id,
                );
                // decrypt_packet takes the full ciphertext (payload + tag) and
                // strips the tag internally.
                if !cipher.decrypt_packet(&nonce, &mut buf[header_len..]) {
                    return Err(ShadowsocksError::ProtocolError(
                        "AEAD 2022 UDP decrypt failed".into(),
                    ));
                }
                (buf[header_len..buf.len() - SS_UDP_TAG_LEN].to_vec(), 0usize)
            }
            CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305 => {
                let nonce_size = shadowsocks_crypto::v2::udp::ChaCha20Poly1305Cipher::nonce_size();
                if buf.len() < nonce_size + 8 + 8 + 1 + 8 + 8 + 2 + SS_UDP_TAG_LEN {
                    return Err(ShadowsocksError::ProtocolError(
                        "short AEAD 2022 server UDP packet".into(),
                    ));
                }
                let (nonce, msg) = buf.split_at_mut(nonce_size);
                let session_id = u64::from_be_bytes(msg[0..8].try_into().unwrap());
                let cipher =
                    shadowsocks_crypto::v2::udp::UdpCipher::new(self.kind, &self.key, session_id);
                if !cipher.decrypt_packet(nonce, msg) {
                    return Err(ShadowsocksError::ProtocolError(
                        "AEAD 2022 UDP decrypt failed".into(),
                    ));
                }
                (msg[..msg.len() - SS_UDP_TAG_LEN].to_vec(), 16usize)
            }
            other => {
                return Err(ShadowsocksError::InvalidCipher(format!(
                    "cipher '{}' category {:?} not supported for UDP 2022",
                    self.kind, other
                )))
            }
        };

        // Server payload layout (fields after TYPE):
        // [TYPE(1)][timestamp(8)][client_session_id(8)][pad_len(2)][padding][addr][payload]
        if body.len() < skip + 1 + 8 + 8 + 2 {
            return Err(ShadowsocksError::ProtocolError(
                "short AEAD 2022 server UDP body".into(),
            ));
        }
        let socket_type = body[skip];
        if socket_type != SS_UDP_SERVER_SOCKET_TYPE {
            return Err(ShadowsocksError::ProtocolError(format!(
                "invalid AEAD 2022 server socket type {}",
                socket_type
            )));
        }
        let client_session_id =
            u64::from_be_bytes(body[skip + 9..skip + 17].try_into().unwrap());
        if client_session_id != self.client_session_id {
            return Err(ShadowsocksError::ProtocolError(format!(
                "AEAD 2022 server echoed unknown client session id {}",
                client_session_id
            )));
        }
        let padding_len = u16::from_be_bytes(body[skip + 17..skip + 19].try_into().unwrap()) as usize;
        let pos = skip + 19 + padding_len;
        if pos >= body.len() {
            return Err(ShadowsocksError::ProtocolError(
                "AEAD 2022 server UDP body too short for address".into(),
            ));
        }
        let (dest, consumed) = decode_addr(&body[pos..])?;
        let payload = body[pos + consumed..].to_vec();
        Ok((dest, payload))
    }
}

/// AES-ECB encrypt/decrypt a single 16-byte block for the AEAD 2022 UDP header
/// (`[SessionID||PacketID]`). Uses the master key directly (single-key setup,
/// matching shadowsocks-rust where `ipsk == key` when no identity keys).
fn aes_ecb_2022(kind: CipherKind, key: &[u8], block: &mut [u8], encrypt: bool) -> Result<(), String> {
    use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
    match kind {
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM => {
            let cipher =
                aes::Aes128::new_from_slice(key).map_err(|e| format!("AES-128 key init: {}", e))?;
            let b = aes::Block::from_mut_slice(block);
            if encrypt {
                cipher.encrypt_block(b);
            } else {
                cipher.decrypt_block(b);
            }
        }
        CipherKind::AEAD2022_BLAKE3_AES_256_GCM => {
            let cipher =
                aes::Aes256::new_from_slice(key).map_err(|e| format!("AES-256 key init: {}", e))?;
            let b = aes::Block::from_mut_slice(block);
            if encrypt {
                cipher.encrypt_block(b);
            } else {
                cipher.decrypt_block(b);
            }
        }
        other => {
            return Err(format!(
                "AES-ECB header block only valid for AES-GCM 2022, got {}",
                other
            ))
        }
    }
    Ok(())
}

#[async_trait]
impl crate::UdpSession for SsUdpSession {
    async fn send(&self, dest: &std::net::SocketAddr, payload: &[u8]) -> anyhow::Result<()> {
        let datagram = if self.is_2022 {
            self.build_2022_packet(dest, payload).map_err(|e| {
                anyhow::anyhow!("ss udp 2022: failed to build packet: {}", e)
            })?
        } else {
            self.build_legacy_packet(dest, payload).map_err(|e| {
                anyhow::anyhow!("ss udp: failed to build packet: {}", e)
            })?
        };
        self.socket.send(&datagram).await?;
        Ok(())
    }

    async fn recv(&self) -> anyhow::Result<(std::net::SocketAddr, Bytes)> {
        let mut buf = self.recv_buf.lock().await;
        buf.resize(65535, 0);
        let len = self.socket.recv(&mut buf).await?;
        if self.is_2022 {
            let (dest, payload) = self
                .recv_2022(&buf[..len])
                .map_err(|e| anyhow::anyhow!("ss udp 2022: recv failed: {}", e))?;
            return Ok((dest, Bytes::from(payload)));
        }

        // Legacy AEAD: [salt][AEAD(addr + payload + tag)]
        let salt_len = self.kind.salt_len();
        if len < salt_len {
            return Err(anyhow::anyhow!("ss udp: packet too short for salt"));
        }
        let (salt, data) = buf[..len].split_at_mut(salt_len);
        let mut cipher = V1Cipher::new(self.kind, &self.key, salt);
        if !cipher.decrypt_packet(data) {
            return Err(anyhow::anyhow!("ss udp: decrypt failed"));
        }
        let tag_len = cipher.tag_len();
        if data.len() < tag_len {
            return Err(anyhow::anyhow!("ss udp: packet too short for tag"));
        }
        let data = &data[..data.len() - tag_len];
        let (dest, consumed) = decode_addr(data)?;
        Ok((dest, Bytes::copy_from_slice(&data[consumed..])))
    }
}

// ============================================================================
// AEAD framing
// ============================================================================

/// Encrypt/decryptor pair (unified interface for legacy and 2022)
enum SsCipher {
    Legacy(V1Cipher),
    V2022(V2TcpCipher),
}

impl SsCipher {
    fn encrypt_packet(&mut self, buf: &mut [u8]) {
        match self {
            SsCipher::Legacy(c) => c.encrypt_packet(buf),
            SsCipher::V2022(c) => c.encrypt_packet(buf),
        }
    }

    fn decrypt_packet(&mut self, buf: &mut [u8]) -> bool {
        match self {
            SsCipher::Legacy(c) => c.decrypt_packet(buf),
            SsCipher::V2022(c) => c.decrypt_packet(buf),
        }
    }

    fn tag_len(&self) -> usize {
        match self {
            SsCipher::Legacy(c) => c.tag_len(),
            SsCipher::V2022(c) => c.tag_len(),
        }
    }
}

/// Cipher for one connection + client salt already sent.
///
/// Decryptor must derive using **server**'s salt (the first segment of server response is its own random
/// salt), so initially None, lazily initialized when SsStream first reads data.
struct SsCipherPair {
    /// Client salt (already sent to server)
    salt: Vec<u8>,
    /// Encryptor (derived from client salt)
    enc: SsCipher,
    /// Encryption method and master key (for deriving server sub-key)
    kind: CipherKind,
    master_key: Vec<u8>,
}

impl SsCipherPair {
    /// Encode a plaintext segment into framed ciphertext (2-byte length + payload, each with tag)
    fn frame_packet(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ShadowsocksError> {
        let tag = self.enc.tag_len();
        let mut out = Vec::with_capacity(2 + tag + plaintext.len() + tag);

        // AEAD in-place encryption: buffer must reserve tag space (len(2) + tag(16))
        let mut len_buf = vec![0u8; 2 + tag];
        len_buf[..2].copy_from_slice(&(plaintext.len() as u16).to_be_bytes());
        self.enc.encrypt_packet(&mut len_buf);
        out.extend_from_slice(&len_buf);

        let mut payload = vec![0u8; plaintext.len() + tag];
        payload[..plaintext.len()].copy_from_slice(plaintext);
        self.enc.encrypt_packet(&mut payload);
        out.extend_from_slice(&payload);
        Ok(out)
    }
}

/// Shadowsocks TCP stream with AEAD framing.
///
/// Write path: chunk by 0x3FFF + 2-byte length prefix encryption.
/// Read path: decrypt length frame (2+tag bytes) first, then read decrypted payload (len+tag bytes);
/// Length 0 indicates peer closed.
pub struct SsStream {
    inner: TcpStream,
    enc: SsCipher,
    /// Decryptor (lazily initialized after server salt received)
    dec: Option<SsCipher>,
    /// Server salt length (need to read this many bytes before decryptor initialization)
    salt_len: usize,
    kind: CipherKind,
    master_key: Vec<u8>,
    tag: usize,
    /// [DEBUG] Temporary debug field: the most recently read server salt (used only for debug
    /// logging, does not affect normal logic)
    debug_server_salt: Vec<u8>,
    /// Write path output buffer (framed ciphertext)
    write_out: Vec<u8>,
    write_pos: usize,
    /// Read path: accumulated frame bytes (consumed with `split_to`, no memmove)
    read_buf: BytesMut,
    /// Payload length to read (None = currently reading length frame)
    read_payload_len: Option<usize>,
    /// Decrypted but unconsumed bytes
    read_decoded: BytesMut,
    read_decoded_pos: usize,
    eof: bool,
}

impl SsStream {
    fn new(inner: TcpStream, pair: SsCipherPair) -> Self {
        let tag = pair.enc.tag_len();
        let salt_len = pair.kind.salt_len();
        let kind = pair.kind;
        let master_key = pair.master_key;
        Self {
            inner,
            enc: pair.enc,
            dec: None,
            salt_len,
            kind,
            master_key,
            tag,
            debug_server_salt: Vec::new(),
            write_out: Vec::new(),
            write_pos: 0,
            read_buf: BytesMut::with_capacity(0x4000),
            read_payload_len: None,
            read_decoded: BytesMut::new(),
            read_decoded_pos: 0,
            eof: false,
        }
    }

    /// Try to read n bytes from inner into read_buf (returns Ok(0) if full).
    ///
    /// Reads directly into the uninitialized spare capacity of `read_buf`,
    /// avoiding a temporary Vec allocation on every poll.
    fn poll_fill_frame(&mut self, cx: &mut Context<'_>, need: usize) -> Poll<io::Result<()>> {
        while self.read_buf.len() < need {
            self.read_buf.reserve(need - self.read_buf.len());
            let filled = {
                let mut rb = ReadBuf::uninit(self.read_buf.spare_capacity_mut());
                match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => rb.filled().len(),
                }
            };
            if filled == 0 {
                return Poll::Ready(Ok(())); // EOF; caller checks len
            }
            // SAFETY: `rb` was created over `read_buf`'s spare capacity and
            // `poll_read` initialized exactly `filled` bytes.
            unsafe { self.read_buf.set_len(self.read_buf.len() + filled) };
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for SsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Consume remaining decrypted bytes first
        if self.read_decoded_pos < self.read_decoded.len() {
            let remaining = &self.read_decoded[self.read_decoded_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.read_decoded_pos += n;
            if self.read_decoded_pos >= self.read_decoded.len() {
                self.read_decoded.clear();
                self.read_decoded_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        if self.eof {
            return Poll::Ready(Ok(()));
        }

        // First read: consume server salt (first segment of response stream) first, then derive decryptor.
        if self.dec.is_none() {
            let salt_len = self.salt_len;
            match self.poll_fill_frame(cx, salt_len) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
            if self.read_buf.len() < salt_len {
                self.eof = true;
                return Poll::Ready(Ok(()));
            }
            let server_salt = self.read_buf.split_to(salt_len);
            self.debug_server_salt = server_salt.to_vec();
            self.dec = Some(match self.kind.category() {
                CipherCategory::Aead => SsCipher::Legacy(V1Cipher::new(
                    self.kind,
                    &self.master_key,
                    &server_salt,
                )),
                CipherCategory::Aead2022 => SsCipher::V2022(V2TcpCipher::new(
                    self.kind,
                    &self.master_key,
                    &server_salt,
                )),
                _ => unreachable!(),
            });
            // [DEBUG] Temporary debug log: prints the server salt hex and peer addr.
            // Kept at trace level so it is off by default.
            tracing::trace!(
                "shadowsocks debug server_salt: salt={} peer={:?}",
                hex::encode(&self.debug_server_salt),
                self.inner.peer_addr(),
            );
        }

        // Need to read a complete frame: length frame (2+tag) + payload frame (len+tag)
        loop {
            // Resume an in-progress payload frame read. The length frame was
            // already consumed, but the payload may still be arriving in
            // multiple TCP segments (common for large responses). Restarting
            // from the top of the loop here would misparse the partial payload
            // bytes as a new length frame and fail AEAD tag verification.
            if let Some(payload_len) = self.read_payload_len.take() {
                let need_payload = payload_len + self.tag;
                match self.poll_fill_frame(cx, need_payload) {
                    Poll::Pending => {
                        self.read_payload_len = Some(payload_len);
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {}
                }
                if self.read_buf.len() < need_payload {
                    // EOF: incomplete payload frame
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }

                // Zero-copy view of the payload ciphertext (no Vec allocation).
                let mut payload = self.read_buf.split_to(need_payload);
                if !self
                    .dec
                    .as_mut()
                    .expect("dec initialized before frame reads")
                    .decrypt_packet(&mut payload)
                {
                    return Poll::Ready(Err(io::Error::other("shadowsocks: payload tag verification failed")));
                }
                payload.truncate(payload_len);

                if buf.remaining() >= payload_len {
                    buf.put_slice(&payload);
                    return Poll::Ready(Ok(()));
                }
                // User buffer too small, store remaining temporarily
                self.read_decoded = payload;
                self.read_decoded_pos = 0;
                let n = buf.remaining();
                buf.put_slice(&self.read_decoded[..n]);
                self.read_decoded_pos = n;
                return Poll::Ready(Ok(()));
            }

            let need_len_frame = 2 + self.tag;
            match self.poll_fill_frame(cx, need_len_frame) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
            if self.read_buf.len() < need_len_frame {
                // EOF: incomplete length frame
                self.eof = true;
                return Poll::Ready(Ok(()));
            }

            // Decrypt length frame: complete ciphertext = 2-byte length + tag.
            // Snapshot the ciphertext for the debug log before consuming it.
            let debug_len_frame_hex = hex::encode(&self.read_buf[..need_len_frame]);
            let mut len_buf = self.read_buf.split_to(need_len_frame);
            if !self
                .dec
                .as_mut()
                .expect("dec initialized before frame reads")
                .decrypt_packet(&mut len_buf)
            {
                // [DEBUG] Temporary debug log: on failure `len_buf` has already been overwritten
                // in place by decrypt, so print the original bytes from the snapshot
                tracing::info!(
                    "shadowsocks debug length_tag_verify_failed: len_frame={} server_salt={} peer={:?} tag={} salt_len={}",
                    debug_len_frame_hex,
                    hex::encode(&self.debug_server_salt),
                    self.inner.peer_addr(),
                    self.tag,
                    self.salt_len,
                );
                return Poll::Ready(Err(io::Error::other("shadowsocks: length tag verification failed")));
            }
            let payload_len = u16::from_be_bytes([len_buf[0], len_buf[1]]) as usize;
            if payload_len == 0 {
                self.eof = true;
                return Poll::Ready(Ok(()));
            }

            // Read and decrypt payload frame
            let need_payload = payload_len + self.tag;
            match self.poll_fill_frame(cx, need_payload) {
                Poll::Pending => {
                    self.read_payload_len = Some(payload_len);
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
            if self.read_buf.len() < need_payload {
                self.eof = true;
                return Poll::Ready(Ok(()));
            }

            let mut payload = self.read_buf.split_to(need_payload);
            if !self
                .dec
                .as_mut()
                .expect("dec initialized before frame reads")
                .decrypt_packet(&mut payload)
            {
                return Poll::Ready(Err(io::Error::other("shadowsocks: payload tag verification failed")));
            }
            payload.truncate(payload_len);

            if buf.remaining() >= payload_len {
                buf.put_slice(&payload);
                return Poll::Ready(Ok(()));
            }
            // User buffer too small, store remaining temporarily
            self.read_decoded = payload;
            self.read_decoded_pos = 0;
            let n = buf.remaining();
            buf.put_slice(&self.read_decoded[..n]);
            self.read_decoded_pos = n;
            return Poll::Ready(Ok(()));
        }
    }
}

impl AsyncWrite for SsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // If there's unfinished framed output still to send, send it first
        if self.write_pos < self.write_out.len() {
            return match self.poll_flush(cx) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(0)),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            };
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Chunking: each chunk ≤ 0x3FFF (AEAD in-place encryption needs to reserve tag space)
        let chunk_len = buf.len().min(MAX_PAYLOAD);
        let mut len_buf = vec![0u8; 2 + self.tag];
        len_buf[..2].copy_from_slice(&(chunk_len as u16).to_be_bytes());
        self.enc.encrypt_packet(&mut len_buf);
        let mut payload = vec![0u8; chunk_len + self.tag];
        payload[..chunk_len].copy_from_slice(&buf[..chunk_len]);
        self.enc.encrypt_packet(&mut payload);

        self.write_out = len_buf.to_vec();
        self.write_out.extend_from_slice(&payload);
        self.write_pos = 0;
        match self.poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(chunk_len)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Self {
            inner,
            write_out,
            write_pos,
            ..
        } = &mut *self;
        while *write_pos < write_out.len() {
            let chunk = &write_out[*write_pos..];
            match Pin::new(&mut *inner).poll_write(cx, chunk) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "shadowsocks: write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => *write_pos += n,
            }
        }
        write_out.clear();
        *write_pos = 0;
        Pin::new(&mut *inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// AsyncDuplex marker: SsStream implements both AsyncRead + AsyncWrite
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_address_ipv4() {
        let addr = ShadowsocksDialer::encode_address("1.2.3.4:80").unwrap();
        assert_eq!(addr, vec![0x01, 1, 2, 3, 4, 0x00, 0x50]);
    }

    #[test]
    fn test_encode_address_ipv6() {
        let addr = ShadowsocksDialer::encode_address("[2001:db8::1]:443").unwrap();
        assert_eq!(addr[0], 0x04);
        assert_eq!(addr.len(), 1 + 16 + 2);
        assert_eq!(&addr[17..19], &[0x01, 0xBB]);
    }

    #[test]
    fn test_encode_address_domain() {
        let addr = ShadowsocksDialer::encode_address("example.com:8080").unwrap();
        assert_eq!(addr[0], 0x03);
        assert_eq!(addr[1], 11);
        assert_eq!(&addr[2..13], b"example.com");
        assert_eq!(&addr[13..15], &[0x1F, 0x90]);
    }

    #[test]
    fn test_encode_address_invalid() {
        assert!(ShadowsocksDialer::encode_address("no-port").is_err());
    }

    #[test]
    fn test_cipher_kind_parse() {
        for c in ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-256-gcm"] {
            assert!(CipherKind::from_str(c).is_ok(), "{}", c);
        }
    }

    #[test]
    fn test_frame_packet_roundtrip() {
        for cipher in ["aes-128-gcm", "aes-256-gcm", "2022-blake3-aes-256-gcm"] {
            let d = ShadowsocksDialer::new(
                "127.0.0.1:1".parse().unwrap(),
                cipher,
                "password",
                5000,
            );
            let kind = d.cipher_kind().unwrap();
            let key = ShadowsocksDialer::master_key(kind, "password");
            // Encrypt/decrypt must share the same salt (new_cipher_pair generates random salt each time)
            let mut salt = vec![0u8; kind.salt_len()];
            random_iv_or_salt(&mut salt);
            let enc = match kind.category() {
                CipherCategory::Aead => SsCipher::Legacy(V1Cipher::new(kind, &key, &salt)),
                CipherCategory::Aead2022 => SsCipher::V2022(V2TcpCipher::new(kind, &key, &salt)),
                _ => unreachable!(),
            };
            let mut pair = SsCipherPair {
                salt: salt.clone(),
                enc,
                kind,
                master_key: key.clone(),
            };
            let tag = pair.enc.tag_len();

            let plain = b"hello shadowsocks world";
            let framed = pair.frame_packet(plain).unwrap();
            // Frame = [length(2+tag)][payload(len+tag)]
            assert_eq!(framed.len(), 2 + tag + plain.len() + tag, "{}", cipher);

            // Simulate server: derive decryptor using client salt (client salt sent with the stream)
            let mut dec = match kind.category() {
                CipherCategory::Aead => SsCipher::Legacy(V1Cipher::new(kind, &key, &salt)),
                CipherCategory::Aead2022 => SsCipher::V2022(V2TcpCipher::new(kind, &key, &salt)),
                _ => unreachable!(),
            };

            // Verify: a decryptor derived from the server's own salt cannot decrypt the client frame
            // (proves lazy initialization must use server salt, not client salt --- regression test for the fix)
            let mut server_salt = vec![0u8; kind.salt_len()];
            random_iv_or_salt(&mut server_salt);
            let mut wrong_dec = match kind.category() {
                CipherCategory::Aead => {
                    SsCipher::Legacy(V1Cipher::new(kind, &key, &server_salt))
                }
                CipherCategory::Aead2022 => {
                    SsCipher::V2022(V2TcpCipher::new(kind, &key, &server_salt))
                }
                _ => unreachable!(),
            };
            let mut wrong_len = framed[..2 + tag].to_vec();
            assert!(!wrong_dec.decrypt_packet(&mut wrong_len), "{}", cipher);

            // Decrypt length frame
            let mut len_buf = framed[..2 + tag].to_vec();
            assert!(dec.decrypt_packet(&mut len_buf), "{}", cipher);
            let plen = u16::from_be_bytes([len_buf[0], len_buf[1]]) as usize;
            assert_eq!(plen, plain.len(), "{}", cipher);

            // Decrypt payload frame
            let mut payload = framed[2 + tag..].to_vec();
            assert!(dec.decrypt_packet(&mut payload), "{}", cipher);
            assert_eq!(&payload[..plain.len()], plain, "{}", cipher);
        }
    }

    /// Regression test: the server closes immediately after sending the salt (no valid length
    /// frame is delivered). Before the fix, `poll_fill_frame` padded the EOF with `buf.len()`
    /// zeros into an 18-byte zero frame, misreporting the server close as `length tag verification
    /// failed`; after the fix it should return a clean EOF (Ok(0)).
    #[tokio::test]
    async fn test_read_eof_after_salt_is_clean() {
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let kind = CipherKind::from_str("aes-128-gcm").unwrap();
        let server_task = tokio::spawn(async move {
            let mut server = server;
            let mut server_salt = vec![0u8; kind.salt_len()];
            random_iv_or_salt(&mut server_salt);
            server.write_all(&server_salt).await.unwrap();
            // drop(server): close the connection without sending any length frame
        });

        let d = ShadowsocksDialer::new(addr, "aes-128-gcm", "password", 5000);
        let pair = d.new_cipher_pair().unwrap();
        let mut stream = SsStream::new(client, pair);
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
        server_task.await.unwrap();
    }

    /// Regression test: the server response is split across multiple writes (simulating TCP
    /// fragmentation/partial reads); the client should correctly reassemble and decrypt the
    /// plaintext.
    #[tokio::test]
    async fn test_read_server_response_split_writes() {
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let kind = CipherKind::from_str("aes-128-gcm").unwrap();
        let key = ShadowsocksDialer::master_key(kind, "password");
        let plain = b"hello response payload from server";

        let server_task = tokio::spawn(async move {
            let mut server = server;
            // Server salt + encryptor derived from server_salt
            let mut server_salt = vec![0u8; kind.salt_len()];
            random_iv_or_salt(&mut server_salt);
            let mut enc = V1Cipher::new(kind, &key, &server_salt);
            let tag = enc.tag_len();
            // Length frame [2-byte len][tag]
            let mut len_buf = vec![0u8; 2 + tag];
            len_buf[..2].copy_from_slice(&(plain.len() as u16).to_be_bytes());
            enc.encrypt_packet(&mut len_buf);
            // Payload frame [plain][tag]
            let mut payload = vec![0u8; plain.len() + tag];
            payload[..plain.len()].copy_from_slice(plain);
            enc.encrypt_packet(&mut payload);

            // Split across multiple writes to simulate TCP fragmentation/partial reads
            server.write_all(&server_salt).await.unwrap();
            server.write_all(&len_buf[..5]).await.unwrap();
            server.write_all(&len_buf[5..]).await.unwrap();
            server.write_all(&payload[..3]).await.unwrap();
            server.write_all(&payload[3..]).await.unwrap();
            server.flush().await.unwrap();
        });

        let d = ShadowsocksDialer::new(addr, "aes-128-gcm", "password", 5000);
        let pair = d.new_cipher_pair().unwrap();
        let mut stream = SsStream::new(client, pair);
        let mut buf = vec![0u8; plain.len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf[..], plain);
        server_task.await.unwrap();
    }

    /// Regression test: a payload frame that arrives in multiple TCP segments,
    /// with the reader polling `Pending` between them.
    ///
    /// Previously the partial payload bytes were misparsed as a new length
    /// frame on resume, producing "length tag verification failed" and cutting
    /// the stream (observed as TLS truncation / "unexpected eof while reading"
    /// on large downloads). The reader must resume filling the in-progress
    /// payload frame instead of restarting the length-frame parse.
    #[tokio::test]
    async fn test_read_payload_frame_split_with_delay() {
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let kind = CipherKind::from_str("aes-128-gcm").unwrap();
        let key = ShadowsocksDialer::master_key(kind, "password");
        // One full-size AEAD frame (max payload 0x3FFF). A single frame is
        // split so that it cannot be delivered in one burst.
        let plain = vec![0xABu8; MAX_PAYLOAD];
        let plain_clone = plain.clone();

        let server_task = tokio::spawn(async move {
            let mut server = server;
            let mut server_salt = vec![0u8; kind.salt_len()];
            random_iv_or_salt(&mut server_salt);
            let mut enc = V1Cipher::new(kind, &key, &server_salt);
            let tag = enc.tag_len();
            // Length frame [2-byte len][tag]
            let mut len_buf = vec![0u8; 2 + tag];
            len_buf[..2].copy_from_slice(&(plain_clone.len() as u16).to_be_bytes());
            enc.encrypt_packet(&mut len_buf);
            // Payload frame [plain][tag]
            let mut payload = vec![0u8; plain_clone.len() + tag];
            payload[..plain_clone.len()].copy_from_slice(&plain_clone);
            enc.encrypt_packet(&mut payload);

            // Send salt + length + FIRST HALF of the payload, then pause so the
            // reader observes an incomplete payload frame and returns Pending.
            let split = payload.len() / 2;
            server.write_all(&server_salt).await.unwrap();
            server.write_all(&len_buf).await.unwrap();
            server.write_all(&payload[..split]).await.unwrap();
            server.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            // Second half arrives after the reader already hit Pending.
            server.write_all(&payload[split..]).await.unwrap();
            server.flush().await.unwrap();
        });

        let d = ShadowsocksDialer::new(addr, "aes-128-gcm", "password", 5000);
        let pair = d.new_cipher_pair().unwrap();
        let mut stream = SsStream::new(client, pair);
        let mut buf = vec![0u8; plain.len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[..], plain);
        server_task.await.unwrap();
    }

    // ==========================================================================
    // AEAD 2022 UDP wire-format regression tests
    //
    // These verify dae-rs's SsUdpSession speaks the standard SIP022 UDP protocol
    // as implemented by shadowsocks-rust (relay/udprelay/aead_2022.rs). A
    // reference-style "server" encoder/decoder is used to prove interop:
    //   - dae-rs client packet  -> reference-style server decrypts correctly
    //   - reference-style server response -> dae-rs recv_2022 decrypts correctly
    // ==========================================================================

    fn make_2022_session(kind: CipherKind) -> SsUdpSession {
        let key = ShadowsocksDialer::master_key(kind, "password");
        let std_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        std_socket.set_nonblocking(true).unwrap();
        let socket = tokio::net::UdpSocket::from_std(std_socket).unwrap();
        SsUdpSession {
            socket,
            kind,
            key,
            is_2022: true,
            client_session_id: 0xdead_beef_cafe_babe,
            packet_id: std::sync::atomic::AtomicU64::new(0),
            recv_buf: tokio::sync::Mutex::new(BytesMut::zeroed(65535)),
        }
    }

    /// Reference-style server decryption of a client->server AEAD 2022 packet.
    fn server_decrypt_client_2022(
        key: &[u8],
        kind: CipherKind,
        packet: &[u8],
    ) -> anyhow::Result<(SocketAddr, Vec<u8>)> {
        let tag = SS_UDP_TAG_LEN;
        let mut buf = packet.to_vec();
        match kind {
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM | CipherKind::AEAD2022_BLAKE3_AES_256_GCM => {
                if buf.len() < 16 + 11 + tag {
                    anyhow::bail!("packet too short");
                }
                aes_ecb_2022(kind, key, &mut buf[0..16], false)
                    .map_err(|e| anyhow::anyhow!(e))?;
                let session_id = u64::from_be_bytes(buf[0..8].try_into().unwrap());
                let nonce: [u8; 12] = buf[4..16].try_into().unwrap();
                let cipher = shadowsocks_crypto::v2::udp::UdpCipher::new(kind, key, session_id);
                if !cipher.decrypt_packet(&nonce, &mut buf[16..]) {
                    anyhow::bail!("decrypt failed");
                }
                parse_client_body(&buf[16..buf.len() - tag], 0)
            }
            CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305 => {
                let nonce_size =
                    shadowsocks_crypto::v2::udp::ChaCha20Poly1305Cipher::nonce_size();
                if buf.len() < nonce_size + 8 + 8 + 1 + 8 + 2 + tag {
                    anyhow::bail!("packet too short");
                }
                let (nonce, msg) = buf.split_at_mut(nonce_size);
                let session_id = u64::from_be_bytes(msg[0..8].try_into().unwrap());
                let cipher = shadowsocks_crypto::v2::udp::UdpCipher::new(kind, key, session_id);
                if !cipher.decrypt_packet(nonce, msg) {
                    anyhow::bail!("decrypt failed");
                }
                parse_client_body(&msg[..msg.len() - tag], 16)
            }
            _ => anyhow::bail!("not a 2022 kind"),
        }
    }

    /// Parse a decrypted client->server body. `skip` = 0 for AES-GCM (body starts
    /// with TYPE), 16 for ChaCha (body starts with SessionID||PacketID).
    fn parse_client_body(body: &[u8], skip: usize) -> anyhow::Result<(SocketAddr, Vec<u8>)> {
        if body.len() < skip + 11 {
            anyhow::bail!("short client body");
        }
        if body[skip] != 0 {
            anyhow::bail!("expected client socket type, got {}", body[skip]);
        }
        let pad_len = u16::from_be_bytes(body[skip + 9..skip + 11].try_into().unwrap()) as usize;
        let pos = skip + 11 + pad_len;
        if pos >= body.len() {
            anyhow::bail!("short client body for address");
        }
        let (dest, consumed) = decode_addr(&body[pos..])?;
        Ok((dest, body[pos + consumed..].to_vec()))
    }

    /// Reference-style server encryption of a server->client AEAD 2022 packet.
    fn server_encrypt_response_2022(
        key: &[u8],
        kind: CipherKind,
        client_session_id: u64,
        dest: &SocketAddr,
        payload: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let addr = encode_socket_addr(dest)?;
        let server_session_id = 0x1111_2222_3333_4444u64;
        let packet_id = 1u64;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        match kind {
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM | CipherKind::AEAD2022_BLAKE3_AES_256_GCM => {
                let body_len = 1 + 8 + 8 + 2 + addr.len() + payload.len();
                let mut buf = vec![0u8; 16 + body_len + SS_UDP_TAG_LEN];
                buf[0..8].copy_from_slice(&server_session_id.to_be_bytes());
                buf[8..16].copy_from_slice(&packet_id.to_be_bytes());
                let nonce: [u8; 12] = buf[4..16].try_into().unwrap();
                let body = &mut buf[16..16 + body_len];
                body[0] = SS_UDP_SERVER_SOCKET_TYPE;
                body[1..9].copy_from_slice(&now.to_be_bytes());
                body[9..17].copy_from_slice(&client_session_id.to_be_bytes());
                body[17..19].copy_from_slice(&0u16.to_be_bytes());
                body[19..19 + addr.len()].copy_from_slice(&addr);
                body[19 + addr.len()..].copy_from_slice(payload);
                let cipher = shadowsocks_crypto::v2::udp::UdpCipher::new(kind, key, server_session_id);
                cipher.encrypt_packet(&nonce, &mut buf[16..]);
                aes_ecb_2022(kind, key, &mut buf[0..16], true).map_err(|e| anyhow::anyhow!(e))?;
                Ok(buf)
            }
            CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305 => {
                let nonce_size =
                    shadowsocks_crypto::v2::udp::ChaCha20Poly1305Cipher::nonce_size();
                let body_len = 8 + 8 + 1 + 8 + 8 + 2 + addr.len() + payload.len();
                let mut buf = vec![0u8; nonce_size + body_len + SS_UDP_TAG_LEN];
                let mut nonce = vec![0u8; nonce_size];
                random_iv_or_salt(&mut nonce);
                buf[..nonce_size].copy_from_slice(&nonce);
                let body = &mut buf[nonce_size..nonce_size + body_len];
                body[0..8].copy_from_slice(&server_session_id.to_be_bytes());
                body[8..16].copy_from_slice(&packet_id.to_be_bytes());
                body[16] = SS_UDP_SERVER_SOCKET_TYPE;
                body[17..25].copy_from_slice(&now.to_be_bytes());
                body[25..33].copy_from_slice(&client_session_id.to_be_bytes());
                body[33..35].copy_from_slice(&0u16.to_be_bytes());
                body[35..35 + addr.len()].copy_from_slice(&addr);
                body[35 + addr.len()..].copy_from_slice(payload);
                let cipher = shadowsocks_crypto::v2::udp::UdpCipher::new(kind, key, server_session_id);
                cipher.encrypt_packet(&nonce, &mut buf[nonce_size..]);
                Ok(buf)
            }
            _ => anyhow::bail!("not a 2022 kind"),
        }
    }

    #[tokio::test]
    async fn test_udp_2022_aes_gcm_interop() {
        for cipher in ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"] {
            let kind = CipherKind::from_str(cipher).unwrap();
            let session = make_2022_session(kind);
            let dest: SocketAddr = "1.1.1.1:53".parse().unwrap();
            let payload = b"hello dns payload";

            // client -> server
            let packet = session.build_2022_packet(&dest, payload).unwrap();
            let (got_dest, got_payload) =
                server_decrypt_client_2022(&session.key, kind, &packet).unwrap();
            assert_eq!(got_dest, dest, "{}", cipher);
            assert_eq!(got_payload, payload, "{}", cipher);

            // server -> client
            let resp =
                server_encrypt_response_2022(&session.key, kind, session.client_session_id, &dest, payload).unwrap();
            let (got_dest2, got_payload2) = session.recv_2022(&resp).unwrap();
            assert_eq!(got_dest2, dest, "{}", cipher);
            assert_eq!(got_payload2, payload, "{}", cipher);
        }
    }

    #[tokio::test]
    async fn test_udp_2022_chacha20_poly1305_interop() {
        let kind = CipherKind::from_str("2022-blake3-chacha20-poly1305").unwrap();
        let session = make_2022_session(kind);
        let dest: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        let payload = b"hello dns payload v6";

        let packet = session.build_2022_packet(&dest, payload).unwrap();
        let (got_dest, got_payload) =
            server_decrypt_client_2022(&session.key, kind, &packet).unwrap();
        assert_eq!(got_dest, dest);
        assert_eq!(got_payload, payload);

        let resp = server_encrypt_response_2022(&session.key, kind, session.client_session_id, &dest, payload).unwrap();
        let (got_dest2, got_payload2) = session.recv_2022(&resp).unwrap();
        assert_eq!(got_dest2, dest);
        assert_eq!(got_payload2, payload);
    }

    #[tokio::test]
    async fn test_udp_legacy_aead_roundtrip() {
        // Legacy AEAD: dae-rs build + decrypt must round-trip (regression guard).
        for cipher in ["aes-256-gcm", "chacha20-ietf-poly1305"] {
            let kind = CipherKind::from_str(cipher).unwrap();
            let key = ShadowsocksDialer::master_key(kind, "password");
            let std_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            std_socket.set_nonblocking(true).unwrap();
            let session = SsUdpSession {
                socket: tokio::net::UdpSocket::from_std(std_socket).unwrap(),
                kind,
                key,
                is_2022: false,
                client_session_id: 0,
                packet_id: std::sync::atomic::AtomicU64::new(0),
                recv_buf: tokio::sync::Mutex::new(BytesMut::zeroed(65535)),
            };
            let dest: SocketAddr = "8.8.8.8:53".parse().unwrap();
            let payload = b"legacy dns payload";

            let packet = session.build_legacy_packet(&dest, payload).unwrap();
            // Simulate server decrypt: split salt, V1Cipher decrypt, strip tag, decode addr
            let salt_len = kind.salt_len();
            let (salt, data) = packet.split_at(salt_len);
            let mut cipher = V1Cipher::new(kind, &session.key, salt);
            let mut data = data.to_vec();
            assert!(cipher.decrypt_packet(&mut data));
            let tag_len = cipher.tag_len();
            let data = &data[..data.len() - tag_len];
            let (got_dest, consumed) = decode_addr(data).unwrap();
            assert_eq!(got_dest, dest);
            assert_eq!(&data[consumed..], payload);
        }
    }
}
