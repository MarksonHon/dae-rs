//! Shadowsocks 协议Dialer
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

/// Shadowsocks Dialer错误
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
    /// 创建新的 Shadowsocks Dialer
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

    /// 编码目标地址：ATYP + ADDR + PORT（1=IPv4, 3=Domain name, 4=IPv6）
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

/// Decode Shadowsocks address, return `(SocketAddr, bytes consumed)`.
/// Domain name为 0.0.0.0:port（无法在无 DNS 场景解析时保留端口）。
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
        stream.write_all(&framed).await.map_err(ShadowsocksError::Io)?;

        // 3. Wrap into encrypted stream and return
        let ss_stream = SsStream::new(stream, cipher);
        Ok(ProxyConn::new_boxed(Box::new(ss_stream)))
    }

    /// Establish Shadowsocks UDP relay session.
    ///
    /// Each datagram independently salted encrypted: `[salt][AEAD(addr + payload)]`,
    /// no handshake needed, sent directly to proxy server.
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
/// Each datagram = `[salt][AEAD(addr + payload)]`; legacy uses HKDF-SHA1 to derive
/// session sub-key, 2022 uses BLAKE3 (session_id = 0).
struct SsUdpSession {
    socket: tokio::net::UdpSocket,
    kind: CipherKind,
    key: Vec<u8>,
}

impl SsUdpSession {
    fn salt_len(&self) -> usize {
        self.kind.salt_len()
    }

    fn encrypt(&self, addr_and_payload: &mut [u8], salt: &[u8]) -> Result<(), ShadowsocksError> {
        match self.kind.category() {
            CipherCategory::Aead => {
                let mut cipher = V1Cipher::new(self.kind, &self.key, salt);
                cipher.encrypt_packet(addr_and_payload);
            }
            CipherCategory::Aead2022 => {
                let cipher = shadowsocks_crypto::v2::udp::UdpCipher::new(self.kind, &self.key, 0);
                cipher.encrypt_packet(salt, addr_and_payload);
            }
            other => {
                return Err(ShadowsocksError::InvalidCipher(format!(
                    "cipher '{}' category {:?} not supported for UDP",
                    self.kind, other
                )))
            }
        }
        Ok(())
    }

    fn decrypt(&self, data: &mut [u8], salt: &[u8]) -> Result<bool, ShadowsocksError> {
        match self.kind.category() {
            CipherCategory::Aead => {
                let mut cipher = V1Cipher::new(self.kind, &self.key, salt);
                Ok(cipher.decrypt_packet(data))
            }
            CipherCategory::Aead2022 => {
                let cipher = shadowsocks_crypto::v2::udp::UdpCipher::new(self.kind, &self.key, 0);
                Ok(cipher.decrypt_packet(salt, data))
            }
            other => Err(ShadowsocksError::InvalidCipher(format!(
                "cipher '{}' category {:?} not supported for UDP",
                self.kind, other
            ))),
        }
    }
}

#[async_trait]
impl crate::UdpSession for SsUdpSession {
    async fn send(&self, dest: &std::net::SocketAddr, payload: &[u8]) -> anyhow::Result<()> {
        let mut salt = vec![0u8; self.salt_len()];
        random_iv_or_salt(&mut salt);

        // [addr][payload] encrypted as a whole
        let addr = encode_addr(&dest.ip().to_string(), dest.port())?;
        let mut pkt = vec![0u8; addr.len() + payload.len() + 16];
        pkt[..addr.len()].copy_from_slice(&addr);
        pkt[addr.len()..addr.len() + payload.len()].copy_from_slice(payload);
        self.encrypt(&mut pkt, &salt)?;

        let mut datagram = salt;
        datagram.extend_from_slice(&pkt);
        self.socket.send(&datagram).await?;
        Ok(())
    }

    async fn recv(&self) -> anyhow::Result<(std::net::SocketAddr, Vec<u8>)> {
        let mut buf = vec![0u8; 65535];
        let len = self.socket.recv(&mut buf).await?;
        let salt_len = self.salt_len();
        if len < salt_len {
            return Err(anyhow::anyhow!("ss udp: packet too short for salt"));
        }
        let (salt, data) = buf[..len].split_at_mut(salt_len);
        if !self.decrypt(data, salt)? {
            return Err(anyhow::anyhow!("ss udp: decrypt failed"));
        }
        let (dest, consumed) = decode_addr(data)?;
        let payload = data[consumed..].to_vec();
        Ok((dest, payload))
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

/// 带 AEAD framing的 Shadowsocks TCP 流。
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
    /// Write path output buffer (framed ciphertext)
    write_out: Vec<u8>,
    write_pos: usize,
    /// Read path: accumulated frame bytes
    read_frame: Vec<u8>,
    /// Payload length to read (None = currently reading length frame)
    read_payload_len: Option<usize>,
    /// Decrypted but unconsumed bytes
    read_decoded: Vec<u8>,
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
            write_out: Vec::new(),
            write_pos: 0,
            read_frame: Vec::new(),
            read_payload_len: None,
            read_decoded: Vec::new(),
            read_decoded_pos: 0,
            eof: false,
        }
    }

    /// Try to read n bytes from inner into read_frame (returns Ok(0) if full)
    fn poll_fill_frame(&mut self, cx: &mut Context<'_>, need: usize) -> Poll<io::Result<()>> {
        while self.read_frame.len() < need {
            let mut buf = vec![0u8; need - self.read_frame.len()];
            match Pin::new(&mut self.inner).poll_read(cx, &mut ReadBuf::new(&mut buf)) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) => {
                    let n = buf.len();
                    if n == 0 {
                        return Poll::Ready(Ok(())); // EOF; caller checks len
                    }
                    self.read_frame.extend_from_slice(&buf[..n]);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
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
            if self.read_frame.len() < salt_len {
                self.eof = true;
                return Poll::Ready(Ok(()));
            }
            let server_salt: Vec<u8> = self.read_frame.drain(..salt_len).collect();
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
        }

        // Need to read a complete frame: length frame (2+tag) + payload frame (len+tag)
        loop {
            let need_len_frame = 2 + self.tag;
            match self.poll_fill_frame(cx, need_len_frame) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
            if self.read_frame.len() < need_len_frame {
                // EOF: incomplete length frame
                self.eof = true;
                return Poll::Ready(Ok(()));
            }

            // Decrypt length frame: complete ciphertext = 2-byte length + tag (in-place decryption requires full frame input)
            let mut len_buf = vec![0u8; need_len_frame];
            len_buf.copy_from_slice(&self.read_frame[..need_len_frame]);
            if !self
                .dec
                .as_mut()
                .expect("dec initialized before frame reads")
                .decrypt_packet(&mut len_buf)
            {
                return Poll::Ready(Err(io::Error::other("shadowsocks: length tag verification failed")));
            }
            self.read_frame.drain(..need_len_frame);
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
            if self.read_frame.len() < need_payload {
                self.eof = true;
                return Poll::Ready(Ok(()));
            }

            let mut payload = vec![0u8; payload_len + self.tag];
            payload.copy_from_slice(&self.read_frame[..need_payload]);
            self.read_frame.drain(..need_payload);
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

            // 验证：用“服务端自己的 salt”派生解密器无法解开客户端帧
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
}
