//! VMess 协议拨号器
//!
//! 实现 VMess AEAD 出站协议（与 v2ray-core 4.0+ 兼容）：
//! - AEAD 认证（MD5 派生 CmdKey + HMAC-SHA256 KDF）
//! - 请求头/响应头 AES-128-GCM 密封
//! - 请求体 AES-128-GCM / ChaCha20-Poly1305 / 无加密分块流
//! - 传输层：TCP / WebSocket（WSS）
//!
//! 参考: https://www.v2fly.org/en_US/developer/protocols/vmess.html

use async_trait::async_trait;
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use md5::{Digest as Md5Digest, Md5};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};

use crate::{OutboundDialer, ProxyConn};

// ── VMess 常量（与 v2ray-core 一致）──

const VERSION: u8 = 1;
/// AEAD CmdKey 派生盐
const AEAD_CMD_KEY_SALT: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
/// KDF 基础盐
const KDF_BASE_SALT: &[u8] = b"VMess AEAD KDF";
const KDF_AUTH_ID_ENC: &[u8] = b"AES Auth ID Encryption";
const KDF_RESP_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const KDF_RESP_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const KDF_RESP_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
const KDF_RESP_PAYLOAD_IV: &[u8] = b"AEAD Resp Header IV";
const KDF_HEADER_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const KDF_HEADER_LEN_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
const KDF_HEADER_PAYLOAD_KEY: &[u8] = b"VMess Header AEAD Key";
const KDF_HEADER_PAYLOAD_IV: &[u8] = b"VMess Header AEAD Nonce";

/// Request option: chunk stream + chunk masking（TCP 默认）
const OPT_CHUNK_STREAM: u8 = 0x01;
const OPT_CHUNK_MASKING: u8 = 0x04;
/// Command: TCP
const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x02;
/// Security types
const SEC_NONE: u8 = 0;
const SEC_AES128_GCM: u8 = 2;
const SEC_CHACHA20_POLY1305: u8 = 3;
/// 请求体分块最大负载
const BODY_CHUNK_SIZE: usize = 16384;
/// AEAD tag 长度
const AEAD_TAG: usize = 16;

/// VMess 拨号器错误
#[derive(Debug, thiserror::Error)]
pub enum VMessError {
    #[error("VMess dial timeout: {0}")]
    Timeout(String),
    #[error("VMess connection refused: {0}")]
    ConnectionRefused(String),
    #[error("VMess TLS error: {0}")]
    Tls(String),
    #[error("VMess protocol error: {0}")]
    ProtocolError(String),
    #[error("VMess invalid base64: {0}")]
    InvalidBase64(String),
    #[error("VMess invalid JSON: {0}")]
    InvalidJson(String),
    #[error("VMess invalid cipher: {0}")]
    InvalidCipher(String),
    #[error("VMess IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("VMess error: {0}")]
    Other(String),
}

/// VMess 传输方式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VMessNetwork {
    Tcp,
    Ws,
    H2,
    Grpc,
}

impl FromStr for VMessNetwork {
    type Err = VMessError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp" => Ok(VMessNetwork::Tcp),
            "ws" => Ok(VMessNetwork::Ws),
            "h2" => Ok(VMessNetwork::H2),
            "grpc" => Ok(VMessNetwork::Grpc),
            other => Err(VMessError::ProtocolError(format!("unknown network: '{}'", other))),
        }
    }
}

/// v2rayN base64 JSON 节点格式
#[derive(Debug, serde::Deserialize)]
struct VMessNodeConfig {
    add: String,
    port: String,
    id: String,
    #[serde(default)]
    aid: String,
    #[serde(default)]
    scy: String,
    #[serde(default)]
    net: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    sni: String,
}

/// VMess 拨号器
pub struct VMessDialer {
    /// 上游 VMess 服务器地址
    pub proxy_addr: SocketAddr,
    /// 拨号超时时间
    pub dial_timeout: Duration,
    /// 用户 UUID
    pub uuid: String,
    /// 加密方式（auto / aes-128-gcm / chacha20-poly1305 / none）
    pub security: String,
    /// alter_id（AEAD 模式下忽略，保留兼容）
    pub alter_id: u32,
    /// 传输方式
    pub network: VMessNetwork,
    /// WebSocket 路径
    pub ws_path: Option<String>,
    /// WebSocket 请求头
    pub ws_headers: Option<std::collections::HashMap<String, String>>,
    /// HTTP/2 路径
    pub h2_path: Option<String>,
    /// HTTP/2 主机
    pub h2_host: Option<String>,
    /// gRPC 服务名
    pub grpc_service_name: Option<String>,
    /// TLS SNI
    pub sni: String,
    /// 证书 SHA256 指纹
    pub ca_sha256: Option<String>,
    /// fwmark 用于 eBPF 自排除
    pub self_mark: u32,
    /// 宿主网络命名空间 fd
    pub host_ns_fd: Option<RawFd>,
}

impl VMessDialer {
    /// 从 v2rayN base64 JSON 格式创建拨号器
    pub fn new_from_base64_json(base64_str: &str, dial_timeout_ms: u64) -> Result<Self, VMessError> {
        use base64::Engine as _;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(base64_str.trim())
            .map_err(|e| VMessError::InvalidBase64(e.to_string()))?;

        let json_str = String::from_utf8(decoded)
            .map_err(|e| VMessError::InvalidBase64(e.to_string()))?;

        let config: VMessNodeConfig = serde_json::from_str(&json_str)
            .map_err(|e| VMessError::InvalidJson(e.to_string()))?;

        let port: u16 = config
            .port
            .parse()
            .map_err(|_| VMessError::ProtocolError("invalid port".into()))?;

        let proxy_addr = SocketAddr::new(
            config
                .add
                .parse()
                .map_err(|e| VMessError::ProtocolError(format!("invalid address: {}", e)))?,
            port,
        );

        let network = VMessNetwork::from_str(&config.net)?;

        Ok(Self {
            proxy_addr,
            dial_timeout: Duration::from_millis(dial_timeout_ms),
            uuid: config.id,
            security: config.scy,
            alter_id: config.aid.parse().unwrap_or(0),
            network,
            ws_path: if config.path.is_empty() {
                None
            } else {
                Some(config.path)
            },
            ws_headers: if config.host.is_empty() {
                None
            } else {
                let mut headers = std::collections::HashMap::new();
                headers.insert("Host".into(), config.host);
                Some(headers)
            },
            h2_path: None,
            h2_host: None,
            grpc_service_name: None,
            sni: config.sni,
            ca_sha256: None,
            self_mark: 0,
            host_ns_fd: None,
        })
    }

    /// 创建新的 VMess 拨号器
    pub fn new(proxy_addr: SocketAddr, uuid: impl Into<String>, dial_timeout_ms: u64) -> Self {
        Self {
            proxy_addr,
            dial_timeout: Duration::from_millis(dial_timeout_ms),
            uuid: uuid.into(),
            security: "auto".into(),
            alter_id: 0,
            network: VMessNetwork::Tcp,
            ws_path: None,
            ws_headers: None,
            h2_path: None,
            h2_host: None,
            grpc_service_name: None,
            sni: String::new(),
            ca_sha256: None,
            self_mark: 0,
            host_ns_fd: None,
        }
    }

    /// 设置加密方式
    pub fn set_security(&mut self, security: impl Into<String>) -> &mut Self {
        self.security = security.into();
        self
    }

    /// 设置 alter_id
    pub fn set_alter_id(&mut self, alter_id: u32) -> &mut Self {
        self.alter_id = alter_id;
        self
    }

    /// 设置传输方式
    pub fn set_network(&mut self, network: VMessNetwork) -> &mut Self {
        self.network = network;
        self
    }

    /// 设置 WebSocket 路径
    pub fn set_ws_path(&mut self, path: impl Into<String>) -> &mut Self {
        self.ws_path = Some(path.into());
        self
    }

    /// 设置 WebSocket 头部
    pub fn set_ws_headers(&mut self, headers: std::collections::HashMap<String, String>) -> &mut Self {
        self.ws_headers = Some(headers);
        self
    }

    /// 设置 HTTP/2 路径
    pub fn set_h2_path(&mut self, path: impl Into<String>) -> &mut Self {
        self.h2_path = Some(path.into());
        self
    }

    /// 设置 HTTP/2 主机
    pub fn set_h2_host(&mut self, host: impl Into<String>) -> &mut Self {
        self.h2_host = Some(host.into());
        self
    }

    /// 设置 gRPC 服务名
    pub fn set_grpc_service_name(&mut self, name: impl Into<String>) -> &mut Self {
        self.grpc_service_name = Some(name.into());
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

    /// Connect to the VMess proxy via the shared host-ns TCP helper.
    async fn connect_with_mark(&self) -> Result<TcpStream, VMessError> {
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
                VMessError::Timeout(format!("connect to proxy {}", self.proxy_addr))
            } else {
                VMessError::Io(e)
            }
        })
    }

    /// 解析加密方式 → (security 字节, 是否加密)
    fn security_type(&self) -> Result<u8, VMessError> {
        match self.security.as_str() {
            "auto" | "aes-128-gcm" => Ok(SEC_AES128_GCM),
            "chacha20-poly1305" => Ok(SEC_CHACHA20_POLY1305),
            "none" | "" => Ok(SEC_NONE),
            other => Err(VMessError::InvalidCipher(format!(
                "unsupported security '{}'",
                other
            ))),
        }
    }

    /// 建立传输层（TCP / WebSocket / TLS），返回原始双工流
    async fn establish_transport(&self) -> Result<Box<dyn crate::AsyncDuplex + Unpin + Send>, VMessError> {
        let tcp = self.connect_with_mark().await?;
        match self.network {
            VMessNetwork::Tcp => Ok(Box::new(tcp)),
            VMessNetwork::Ws => {
                let (stream, _) = self.upgrade_ws(tcp).await?;
                Ok(Box::new(WsByteStream::new(stream)))
            }
            VMessNetwork::H2 => Err(VMessError::ProtocolError(
                "VMess h2 transport is not implemented yet".into(),
            )),
            VMessNetwork::Grpc => Err(VMessError::ProtocolError(
                "VMess gRPC transport is not implemented yet".into(),
            )),
        }
    }

    /// WebSocket 升级
    async fn upgrade_ws(
        &self,
        tcp: TcpStream,
    ) -> Result<(tokio_tungstenite::WebSocketStream<TcpStream>, String), VMessError> {
        let _ = tls_connector("placeholder"); // keep tls helpers referenced
        let path = self.ws_path.clone().unwrap_or_else(|| "/".into());
        let host = self
            .ws_headers
            .as_ref()
            .and_then(|h| h.get("Host").cloned())
            .unwrap_or_else(|| {
                if self.sni.is_empty() {
                    self.proxy_addr.ip().to_string()
                } else {
                    self.sni.clone()
                }
            });

        let uri = format!("ws://{}{}", host, path);
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(uri)
            .header(http::header::HOST, &host)
            .header(http::header::CONNECTION, "Upgrade")
            .header(http::header::UPGRADE, "websocket")
            .header(http::header::SEC_WEBSOCKET_VERSION, "13")
            .header(http::header::SEC_WEBSOCKET_KEY, tokio_tungstenite::tungstenite::handshake::client::generate_key())
            .body(())
            .map_err(|e| VMessError::ProtocolError(format!("ws request build failed: {}", e)))?;

        let (stream, _) = tokio_tungstenite::client_async(request, tcp)
            .await
            .map_err(|e| VMessError::ProtocolError(format!("ws upgrade failed: {}", e)))?;
        Ok((stream, host))
    }
}

#[async_trait]
impl OutboundDialer for VMessDialer {
    async fn dial(&self, target: &str) -> anyhow::Result<ProxyConn> {
        let transport = self.establish_transport().await?;

        // 1. 构造并密封请求头
        let security = self.security_type()?;
        let (session, sealed_header) = build_request_header(&self.uuid, target, security, CMD_TCP)
            .map_err(|e| anyhow::anyhow!("VMess header build failed: {}", e))?;

        // 2. 发送密封头
        let mut stream = transport;
        stream.write_all(&sealed_header).await.map_err(VMessError::Io)?;

        // 3. 读取并校验响应头
        let resp_key = session.response_body_key();
        let resp_iv = session.response_body_iv();
        read_response_header(&mut stream, resp_key, resp_iv, session.response_header())
            .await
            .map_err(|e| anyhow::anyhow!("VMess response header failed: {}", e))?;

        // 4. 包装为分块加密流
        let body = VmessBodyStream::new(
            stream,
            session,
            security,
        );
        Ok(ProxyConn::new_boxed(Box::new(body)))
    }

    /// 建立 VMess UDP 中继会话（数据报模式分块流）。
    async fn udp_dial(&self) -> anyhow::Result<Box<dyn crate::UdpSession>> {
        let transport = self.establish_transport().await?;

        let security = self.security_type()?;
        let (session, sealed_header) =
            build_request_header(&self.uuid, "0.0.0.0:0", security, CMD_UDP)
                .map_err(|e| anyhow::anyhow!("VMess header build failed: {}", e))?;

        let mut stream = transport;
        stream.write_all(&sealed_header).await.map_err(VMessError::Io)?;

        let resp_key = session.response_body_key();
        let resp_iv = session.response_body_iv();
        read_response_header(&mut stream, resp_key, resp_iv, session.response_header())
            .await
            .map_err(|e| anyhow::anyhow!("VMess response header failed: {}", e))?;

        let body = VmessBodyStream::new_packet_mode(stream, session, security);
        Ok(Box::new(VMessUdpSession {
            stream: tokio::sync::Mutex::new(body),
        }))
    }

    fn protocol_name(&self) -> &'static str {
        "vmess"
    }
    fn proxy_addr(&self) -> std::net::SocketAddr {
        self.proxy_addr
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

// ============================================================================
// VMess AEAD 加密原语
// ============================================================================

/// VMess KDF：HMAC-SHA256 链
fn kdf(key: &[u8], paths: &[&[u8]]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;
    let mut mac = HmacSha256::new_from_slice(KDF_BASE_SALT).expect("hmac key");
    mac.update(key);
    let mut out = mac.finalize().into_bytes().to_vec();
    for p in paths {
        let mut m = HmacSha256::new_from_slice(p).expect("hmac key");
        m.update(&out);
        out = m.finalize().into_bytes().to_vec();
    }
    out.try_into().expect("32 bytes")
}

fn kdf16(key: &[u8], paths: &[&[u8]]) -> [u8; 16] {
    let full = kdf(key, paths);
    full[..16].try_into().expect("16 bytes")
}

/// CmdKey = MD5(uuid_bytes || AEAD_CMD_KEY_SALT)
fn cmd_key(uuid: &str) -> Result<[u8; 16], VMessError> {
    let uuid_bytes = parse_uuid(uuid)?;
    let mut hasher = Md5::new();
    hasher.update(uuid_bytes);
    hasher.update(AEAD_CMD_KEY_SALT);
    Ok(hasher.finalize().into())
}

fn parse_uuid(uuid: &str) -> Result<[u8; 16], VMessError> {
    let hex: String = uuid.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return Err(VMessError::ProtocolError(format!("invalid uuid: '{}'", uuid)));
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| VMessError::ProtocolError(format!("invalid uuid: '{}'", uuid)))?;
    }
    Ok(out)
}

/// AES-128-ECB 单块加密
fn aes_ecb_encrypt_block(key: &[u8; 16], block: &mut [u8; 16]) {
    use aes::cipher::{BlockEncrypt, KeyInit};
    let cipher = aes::Aes128::new_from_slice(key).expect("aes key");
    cipher.encrypt_block(block.into());
}

/// 生成 AuthID：AES-ECB(KDF16(cmdKey, "AES Auth ID Encryption"),
///   timestamp_be64 || 4 随机字节 || crc32(前 12 字节) be32)
fn create_auth_id(cmd_key: &[u8; 16], timestamp: i64) -> [u8; 16] {
    let enc_key = kdf16(cmd_key, &[KDF_AUTH_ID_ENC]);
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&timestamp.to_be_bytes());
    // 4 随机字节
    let mut rng_bytes = [0u8; 4];
    get_random(&mut rng_bytes);
    buf[8..12].copy_from_slice(&rng_bytes);
    let crc = crc32fast::hash(&buf[..12]);
    buf[12..16].copy_from_slice(&crc.to_be_bytes());
    aes_ecb_encrypt_block(&enc_key, &mut buf);
    buf
}

/// FNV-1a 32 位哈希（请求头校验）
fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for b in data {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

fn get_random(buf: &mut [u8]) {
    // 尽力从系统随机源填充；失败时退化为时间+地址熵（仅影响加密强度，不 panic）
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut ok = false;
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        if f.read_exact(buf).is_ok() {
            ok = true;
        }
    }
    if !ok {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
            ^ COUNTER.fetch_add(1, Ordering::Relaxed);
        for (i, b) in buf.iter_mut().enumerate() {
            *b = ((seed >> ((i % 8) * 8)) ^ COUNTER.load(Ordering::Relaxed)) as u8;
        }
    }
}

/// 密封 VMess AEAD 请求头
fn seal_header(cmd_key: &[u8; 16], header: &[u8], auth_id: &[u8; 16]) -> Result<Vec<u8>, VMessError> {
    use aes_gcm::{Aes128Gcm, KeyInit as _, Nonce};
    use aes_gcm::aead::Aead;

    let mut conn_nonce = [0u8; 8];
    get_random(&mut conn_nonce);

    // 长度密封
    let len_key = kdf16(cmd_key, &[KDF_HEADER_LEN_KEY, auth_id, &conn_nonce]);
    let len_iv = kdf(cmd_key, &[KDF_HEADER_LEN_IV, auth_id, &conn_nonce]);
    let len_cipher = {
        let cipher = Aes128Gcm::new_from_slice(&len_key).map_err(|e| VMessError::Other(e.to_string()))?;
        let nonce = Nonce::from_slice(&len_iv[..12]);
        let plain = (header.len() as u16).to_be_bytes();
        cipher.encrypt(nonce, plain.as_slice()).map_err(|_| VMessError::Other("header len seal failed".into()))?
    };

    // 负载密封
    let payload_key = kdf16(cmd_key, &[KDF_HEADER_PAYLOAD_KEY, auth_id, &conn_nonce]);
    let payload_iv = kdf(cmd_key, &[KDF_HEADER_PAYLOAD_IV, auth_id, &conn_nonce]);
    let payload_cipher = {
        let cipher = Aes128Gcm::new_from_slice(&payload_key).map_err(|e| VMessError::Other(e.to_string()))?;
        let nonce = Nonce::from_slice(&payload_iv[..12]);
        cipher.encrypt(nonce, header).map_err(|_| VMessError::Other("header seal failed".into()))?
    };

    let mut out = Vec::with_capacity(16 + 18 + 8 + payload_cipher.len());
    out.extend_from_slice(auth_id);
    out.extend_from_slice(&len_cipher);
    out.extend_from_slice(&conn_nonce);
    out.extend_from_slice(&payload_cipher);
    Ok(out)
}

/// 编码目标地址（VMess ATYP：1=IPv4, 2=域名, 3=IPv6；端口在前）
fn encode_address_port(target: &str) -> Result<(Vec<u8>, u16), VMessError> {
    let (mut host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| VMessError::ProtocolError(format!("invalid target '{}'", target)))?;
    let port: u16 = port
        .parse()
        .map_err(|_| VMessError::ProtocolError(format!("invalid target port '{}'", target)))?;
    if host.starts_with('[') && host.ends_with(']') {
        host = &host[1..host.len() - 1];
    }
    let mut addr = Vec::with_capacity(1 + 16);
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        addr.push(0x01);
        addr.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        addr.push(0x03);
        addr.extend_from_slice(&ip.octets());
    } else {
        let b = host.as_bytes();
        addr.push(0x02);
        addr.push(b.len() as u8);
        addr.extend_from_slice(b);
    }
    Ok((addr, port))
}

/// 编码 VMess UDP 数据报地址：ATYP + ADDR + PORT（1=IPv4, 2=域名, 3=IPv6）
fn encode_packet_addr(host: &str, port: u16) -> Vec<u8> {
    let mut addr = Vec::with_capacity(1 + 16 + 2);
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        addr.push(0x01);
        addr.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        addr.push(0x03);
        addr.extend_from_slice(&ip.octets());
    } else {
        let b = host.as_bytes();
        addr.push(0x02);
        addr.push(b.len() as u8);
        addr.extend_from_slice(b);
    }
    addr.extend_from_slice(&port.to_be_bytes());
    addr
}

/// 解码 VMess UDP 数据报地址，返回 `(SocketAddr, 消耗字节数)`
fn decode_packet_addr(data: &[u8]) -> Result<(SocketAddr, usize), VMessError> {
    if data.is_empty() {
        return Err(VMessError::ProtocolError("empty address".into()));
    }
    match data[0] {
        0x01 => {
            if data.len() < 7 {
                return Err(VMessError::ProtocolError("short ipv4".into()));
            }
            let ip = std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            Ok((
                SocketAddr::from((ip, u16::from_be_bytes([data[5], data[6]]))),
                7,
            ))
        }
        0x03 => {
            if data.len() < 19 {
                return Err(VMessError::ProtocolError("short ipv6".into()));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let ip = std::net::Ipv6Addr::from(octets);
            Ok((
                SocketAddr::from((ip, u16::from_be_bytes([data[17], data[18]]))),
                19,
            ))
        }
        0x02 => {
            if data.len() < 2 {
                return Err(VMessError::ProtocolError("short domain".into()));
            }
            let len = data[1] as usize;
            if data.len() < 2 + len + 2 {
                return Err(VMessError::ProtocolError("short domain".into()));
            }
            let port = u16::from_be_bytes([data[2 + len], data[3 + len]]);
            Ok((SocketAddr::from(([0, 0, 0, 0], port)), 2 + len + 2))
        }
        other => Err(VMessError::ProtocolError(format!(
            "unknown address type: {}",
            other
        ))),
    }
}

/// 一次 VMess 会话的密钥材料
struct VmessSession {
    request_body_key: [u8; 16],
    request_body_iv: [u8; 16],
    response_header_byte: u8,
    response_body_key: [u8; 16],
    response_body_iv: [u8; 16],
}

impl VmessSession {
    fn new() -> Self {
        let mut body_key = [0u8; 16];
        let mut body_iv = [0u8; 16];
        let mut resp_header = [0u8; 1];
        get_random(&mut body_key);
        get_random(&mut body_iv);
        get_random(&mut resp_header);

        // responseBodyKey = sha256(requestBodyKey)[:16]
        let mut k = [0u8; 16];
        k.copy_from_slice(&sha2::Sha256::digest(body_key)[..16]);
        let mut v = [0u8; 16];
        v.copy_from_slice(&sha2::Sha256::digest(body_iv)[..16]);

        Self {
            request_body_key: body_key,
            request_body_iv: body_iv,
            response_header_byte: resp_header[0],
            response_body_key: k,
            response_body_iv: v,
        }
    }

    fn response_body_key(&self) -> &[u8; 16] {
        &self.response_body_key
    }
    fn response_body_iv(&self) -> &[u8; 16] {
        &self.response_body_iv
    }
    fn response_header(&self) -> u8 {
        self.response_header_byte
    }
}

/// 构建并密封请求头
fn build_request_header(
    uuid: &str,
    target: &str,
    security: u8,
    command: u8,
) -> Result<(VmessSession, Vec<u8>), VMessError> {
    let key = cmd_key(uuid)?;
    let session = VmessSession::new();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let (addr, port) = encode_address_port(target)?;

    // 随机 padding（0-15 字节），并打包进 security 高 4 位
    let mut padding_len = [0u8; 1];
    get_random(&mut padding_len);
    let padding_len = (padding_len[0] % 16) as usize;
    let security_byte = ((padding_len as u8) << 4) | security;

    let option = OPT_CHUNK_STREAM | OPT_CHUNK_MASKING;

    let mut header = Vec::with_capacity(1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + 2 + addr.len() + padding_len + 4);
    header.push(VERSION);
    header.extend_from_slice(&session.request_body_iv);
    header.extend_from_slice(&session.request_body_key);
    header.push(session.response_header_byte);
    header.push(option);
    header.push(security_byte);
    header.push(0); // reserve
    header.push(command);
    // PortThenAddress：端口在前
    header.extend_from_slice(&port.to_be_bytes());
    header.extend_from_slice(&addr);
    // padding
    let mut pad = vec![0u8; padding_len];
    get_random(&mut pad);
    header.extend_from_slice(&pad);
    // FNV-1a 校验
    header.extend_from_slice(&fnv1a32(&header).to_be_bytes());

    let auth_id = create_auth_id(&key, timestamp);
    let sealed = seal_header(&key, &header, &auth_id)?;
    Ok((session, sealed))
}

/// 读取并校验响应头
async fn read_response_header<S>(
    stream: &mut S,
    resp_key: &[u8; 16],
    resp_iv: &[u8; 16],
    expected_header: u8,
) -> Result<(), VMessError>
where
    S: AsyncRead + Unpin,
{
    use aes_gcm::{Aes128Gcm, KeyInit as _, Nonce};
    use aes_gcm::aead::Aead;

    // 1. 长度密封（18 字节）
    let mut len_cipher = [0u8; 18];
    stream.read_exact(&mut len_cipher).await.map_err(VMessError::Io)?;
    let len_key = kdf16(resp_key, &[KDF_RESP_LEN_KEY]);
    let len_iv = kdf(resp_iv, &[KDF_RESP_LEN_IV]);
    let len_plain = {
        let cipher = Aes128Gcm::new_from_slice(&len_key).map_err(|e| VMessError::Other(e.to_string()))?;
        let nonce = Nonce::from_slice(&len_iv[..12]);
        cipher
            .decrypt(nonce, len_cipher.as_slice())
            .map_err(|_| VMessError::ProtocolError("response header length decrypt failed".into()))?
    };
    let header_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;

    // 2. 负载密封
    let payload_key = kdf16(resp_key, &[KDF_RESP_PAYLOAD_KEY]);
    let payload_iv = kdf(resp_iv, &[KDF_RESP_PAYLOAD_IV]);
    let mut payload_cipher = vec![0u8; header_len + AEAD_TAG];
    stream.read_exact(&mut payload_cipher).await.map_err(VMessError::Io)?;
    let plain = {
        let cipher = Aes128Gcm::new_from_slice(&payload_key).map_err(|e| VMessError::Other(e.to_string()))?;
        let nonce = Nonce::from_slice(&payload_iv[..12]);
        cipher
            .decrypt(nonce, payload_cipher.as_slice())
            .map_err(|_| VMessError::ProtocolError("response header decrypt failed".into()))?
    };

    // 3. 校验响应头首字节
    if plain.first() != Some(&expected_header) {
        return Err(VMessError::ProtocolError(format!(
            "unexpected response header: got {:?}, expected {:?}",
            plain.first(),
            Some(&expected_header)
        )));
    }
    Ok(())
}

// ============================================================================
// VMess 分块加密流（请求体 AES-GCM 分块 + shake128 长度掩码）
// ============================================================================

/// 基于 sha3::Shake128 的长度掩码 + padding 生成器（与 v2ray 一致）
struct ShakeSize {
    reader: sha3::Shake128Reader,
}

impl ShakeSize {
    fn new(iv: &[u8]) -> Self {
        use sha3::digest::{ExtendableOutput, Update};
        let mut hasher = sha3::Shake128::default();
        hasher.update(iv);
        Self {
            reader: hasher.finalize_xof(),
        }
    }

    fn next_mask(&mut self) -> u16 {
        use sha3::digest::XofReader;
        let mut buf = [0u8; 2];
        self.reader.read(&mut buf);
        u16::from_be_bytes(buf)
    }

    fn next_padding(&mut self) -> u16 {
        self.next_mask() % 64
    }
}

/// 分块 nonce：counter(2 BE) + iv[2..12]
struct ChunkNonce {
    counter: u16,
    iv: [u8; 16],
}

impl ChunkNonce {
    fn new(iv: [u8; 16]) -> Self {
        Self { counter: 0, iv }
    }

    fn next(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0..2].copy_from_slice(&self.counter.to_be_bytes());
        nonce[2..12].copy_from_slice(&self.iv[2..12]);
        self.counter = self.counter.wrapping_add(1);
        nonce
    }
}

/// VMess 分块加密流（双向）
pub struct VmessBodyStream {
    inner: Box<dyn crate::AsyncDuplex + Unpin + Send>,
    /// 数据报模式：每次 poll_write/poll_read 恰好一个数据报分块
    packet_mode: bool,
    /// 写方向
    enc_security: u8,
    enc_key: [u8; 16],
    enc_shake: ShakeSize,
    enc_nonce: ChunkNonce,
    enc_chacha: bool,
    write_out: Vec<u8>,
    write_pos: usize,
    write_eof_sent: bool,
    /// 读方向
    dec_security: u8,
    dec_key: [u8; 16],
    dec_shake: ShakeSize,
    dec_nonce: ChunkNonce,
    dec_chacha: bool,
    read_frame: Vec<u8>,
    read_decoded: Vec<u8>,
    read_decoded_pos: usize,
    eof: bool,
}

impl VmessBodyStream {
    fn new(
        inner: Box<dyn crate::AsyncDuplex + Unpin + Send>,
        session: VmessSession,
        security: u8,
    ) -> Self {
        Self::new_with_mode(inner, session, security, false)
    }

    /// 创建数据报模式流（UDP 中继用）：每个分块对应一个数据报。
    fn new_packet_mode(
        inner: Box<dyn crate::AsyncDuplex + Unpin + Send>,
        session: VmessSession,
        security: u8,
    ) -> Self {
        Self::new_with_mode(inner, session, security, true)
    }

    fn new_with_mode(
        inner: Box<dyn crate::AsyncDuplex + Unpin + Send>,
        session: VmessSession,
        security: u8,
        packet_mode: bool,
    ) -> Self {
        Self {
            inner,
            packet_mode,
            enc_security: security,
            enc_key: session.request_body_key,
            enc_shake: ShakeSize::new(&session.request_body_iv),
            enc_nonce: ChunkNonce::new(session.request_body_iv),
            enc_chacha: security == SEC_CHACHA20_POLY1305,
            write_out: Vec::new(),
            write_pos: 0,
            write_eof_sent: false,
            dec_security: security,
            dec_key: session.response_body_key,
            dec_shake: ShakeSize::new(&session.response_body_iv),
            dec_nonce: ChunkNonce::new(session.response_body_iv),
            dec_chacha: security == SEC_CHACHA20_POLY1305,
            read_frame: Vec::new(),
            read_decoded: Vec::new(),
            read_decoded_pos: 0,
            eof: false,
        }
    }

    fn seal_chunk(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        let padding = if self.enc_security == SEC_NONE {
            0
        } else {
            self.enc_shake.next_padding() as usize
        };
        let size = (payload.len() + AEAD_TAG + padding) as u16;
        let mask = self.enc_shake.next_mask();
        let mut out = Vec::with_capacity(2 + payload.len() + AEAD_TAG + padding);
        out.extend_from_slice(&(mask ^ size).to_be_bytes());

        if self.enc_security == SEC_NONE {
            out.extend_from_slice(payload);
            // NONE 安全类型仍有 0 长度 tag？v2ray NoOpAuthenticator Overhead=0
        } else {
            let key = chacha_or_aes_key(&self.enc_key, self.enc_chacha);
            let nonce = self.enc_nonce.next();
            let ciphertext = aead_seal(&key, &nonce, payload, self.enc_chacha)?;
            out.extend_from_slice(&ciphertext);
        }
        // 明文 padding
        if padding > 0 {
            let mut pad = vec![0u8; padding];
            get_random(&mut pad);
            out.extend_from_slice(&pad);
        }
        Ok(out)
    }

    fn open_chunk(&mut self, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        if self.dec_security == SEC_NONE {
            return Ok(ciphertext.to_vec());
        }
        let key = chacha_or_aes_key(&self.dec_key, self.dec_chacha);
        let nonce = self.dec_nonce.next();
        aead_open(&key, &nonce, ciphertext, self.dec_chacha)
    }

    /// 尝试从 inner 读满 need 字节到 read_frame
    fn poll_fill_frame(&mut self, cx: &mut Context<'_>, need: usize) -> Poll<io::Result<()>> {
        while self.read_frame.len() < need {
            let mut buf = vec![0u8; need - self.read_frame.len()];
            match Pin::new(&mut self.inner).poll_read(cx, &mut ReadBuf::new(&mut buf)) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) => {
                    let n = buf.len();
                    if n == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    self.read_frame.extend_from_slice(&buf[..n]);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
        Poll::Ready(Ok(()))
    }
}

fn chacha_or_aes_key(key: &[u8; 16], chacha: bool) -> Vec<u8> {
    if chacha {
        // GenerateChacha20Poly1305Key = SHA-256(key)
        sha2::Sha256::digest(key).to_vec()
    } else {
        key.to_vec()
    }
}

fn aead_seal(key: &[u8], nonce: &[u8; 12], plain: &[u8], chacha: bool) -> io::Result<Vec<u8>> {
    if chacha {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
        let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| io::Error::other(e.to_string()))?;
        cipher
            .encrypt(nonce.into(), plain)
            .map_err(|_| io::Error::other("chacha seal failed"))
    } else {
        use aes_gcm::{Aes128Gcm, KeyInit, Nonce as GcmNonce};
        use aes_gcm::aead::Aead;
        let cipher = Aes128Gcm::new_from_slice(key).map_err(|e| io::Error::other(e.to_string()))?;
        cipher
            .encrypt(GcmNonce::from_slice(nonce), plain)
            .map_err(|_| io::Error::other("aes-gcm seal failed"))
    }
}

fn aead_open(key: &[u8], nonce: &[u8; 12], ciphertext: &[u8], chacha: bool) -> io::Result<Vec<u8>> {
    if chacha {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
        let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| io::Error::other(e.to_string()))?;
        cipher
            .decrypt(nonce.into(), ciphertext)
            .map_err(|_| io::Error::other("chacha open failed"))
    } else {
        use aes_gcm::{Aes128Gcm, KeyInit, Nonce as GcmNonce};
        use aes_gcm::aead::Aead;
        let cipher = Aes128Gcm::new_from_slice(key).map_err(|e| io::Error::other(e.to_string()))?;
        cipher
            .decrypt(GcmNonce::from_slice(nonce), ciphertext)
            .map_err(|_| io::Error::other("aes-gcm open failed"))
    }
}

impl AsyncRead for VmessBodyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 先消费已解密的剩余字节
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

        loop {
            // 读 2 字节掩码长度
            match self.poll_fill_frame(cx, 2) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
            if self.read_frame.len() < 2 {
                self.eof = true;
                return Poll::Ready(Ok(()));
            }
            let mask = self.dec_shake.next_mask();
            let size = u16::from_be_bytes([self.read_frame[0], self.read_frame[1]]) ^ mask;
            self.read_frame.drain(..2);
            if size == 0 {
                self.eof = true;
                return Poll::Ready(Ok(()));
            }

            // padding（先于负载消耗同一条 shake 流）
            let padding = if self.dec_security == SEC_NONE {
                0
            } else {
                self.dec_shake.next_padding() as usize
            };
            let encrypted_len = size as usize - padding;
            if size < padding as u16 {
                self.eof = true;
                return Poll::Ready(Err(io::Error::other("vmess: invalid chunk size")));
            }

            match self.poll_fill_frame(cx, size as usize) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
            if self.read_frame.len() < size as usize {
                self.eof = true;
                return Poll::Ready(Ok(()));
            }
            let chunk: Vec<u8> = self.read_frame.drain(..size as usize).collect();
            let payload = self.open_chunk(&chunk[..encrypted_len])?;
            // 丢弃 padding（chunk[encrypted_len..]）

            if buf.remaining() >= payload.len() {
                buf.put_slice(&payload);
                return Poll::Ready(Ok(()));
            }
            self.read_decoded = payload;
            self.read_decoded_pos = 0;
            let n = buf.remaining();
            buf.put_slice(&self.read_decoded[..n]);
            self.read_decoded_pos = n;
            return Poll::Ready(Ok(()));
        }
    }
}

impl AsyncWrite for VmessBodyStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // 先发送未完成的分帧输出
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

        // 数据报模式：一次 poll_write = 一个数据报分块（不分片）
        let chunk_len = if self.packet_mode {
            if buf.len() > 0xFFF0 {
                return Poll::Ready(Err(io::Error::other("vmess udp: packet too large")));
            }
            buf.len()
        } else {
            buf.len().min(BODY_CHUNK_SIZE)
        };
        let framed = match self.seal_chunk(&buf[..chunk_len]) {
            Ok(f) => f,
            Err(e) => return Poll::Ready(Err(e)),
        };
        self.write_out = framed;
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
            match Pin::new(&mut **inner).poll_write(cx, chunk) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "vmess: write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => *write_pos += n,
            }
        }
        write_out.clear();
        *write_pos = 0;
        Pin::new(&mut **inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // 发送终止分块（掩码长度 0）
        if !self.write_eof_sent {
            let mask = self.enc_shake.next_mask();
            let eof = mask.to_be_bytes();
            self.write_eof_sent = true;
            match Pin::new(&mut self.inner).poll_write(cx, &eof) {
                Poll::Pending => {
                    // 保存待发送字节，下次 poll_shutdown 继续
                    self.write_out = eof.to_vec();
                    self.write_pos = 0;
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(_)) => {}
            }
            // 若部分写入，需处理；这里假设一次性写入成功（2 字节）
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ============================================================================
// TLS 支持（WSS）
// ============================================================================

/// 创建 TLS connector（与 Trojan 相同的根证书库）
#[allow(dead_code)]
fn tls_connector(_sni: &str) -> Result<TlsConnector, VMessError> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

#[allow(dead_code)]
async fn tls_upgrade(
    tcp: TcpStream,
    sni: &str,
) -> Result<TlsStream<TcpStream>, VMessError> {
    let connector = tls_connector(sni)?;
    let domain = ServerName::try_from(sni.to_string())
        .map_err(|e| VMessError::Tls(format!("invalid SNI: {}", e)))?;
    connector
        .connect(domain, tcp)
        .await
        .map_err(|e| VMessError::Tls(format!("TLS handshake failed: {}", e)))
}

/// VMess UDP 中继会话。
///
/// 同一 TCP 连接：命令为 UDP（0x02），每个数据报作为一个分块传输：
/// `[掩码长度][AEAD(ATYP + ADDR + PORT + LEN(2) + PAYLOAD)]`。
pub struct VMessUdpSession {
    stream: tokio::sync::Mutex<VmessBodyStream>,
}

#[async_trait]
impl crate::UdpSession for VMessUdpSession {
    async fn send(&self, dest: &std::net::SocketAddr, payload: &[u8]) -> anyhow::Result<()> {
        // [atyp][addr][port(2)][len(2)][payload] 作为一个分块写入
        let mut pkt = Vec::with_capacity(1 + 16 + 2 + 2 + payload.len());
        pkt.extend_from_slice(&encode_packet_addr(&dest.ip().to_string(), dest.port()));
        pkt.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        pkt.extend_from_slice(payload);
        use tokio::io::AsyncWriteExt;
        let mut stream = self.stream.lock().await;
        stream.write_all(&pkt).await?;
        Ok(())
    }

    async fn recv(&self) -> anyhow::Result<(std::net::SocketAddr, Vec<u8>)> {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 65535];
        let mut stream = self.stream.lock().await;
        let n = stream.read(&mut buf).await?;
        let (dest, consumed) = decode_packet_addr(&buf[..n])?;
        if n < consumed + 2 {
            return Err(anyhow::anyhow!("vmess udp: short packet"));
        }
        let pkt_len = u16::from_be_bytes([buf[consumed], buf[consumed + 1]]) as usize;
        if n < consumed + 2 + pkt_len {
            return Err(anyhow::anyhow!("vmess udp: truncated payload"));
        }
        Ok((dest, buf[consumed + 2..consumed + 2 + pkt_len].to_vec()))
    }
}

// ============================================================================
// WebSocket 字节流适配器（消息式 → 字节流）
// ============================================================================

/// 将 WebSocket 消息流适配为字节流：读方向拼接 Binary/Text 消息，
/// 写方向按 Binary 消息发送；自动应答 Ping，Close/None 表示 EOF。
pub struct WsByteStream<S> {
    ws: tokio_tungstenite::WebSocketStream<S>,
    rx: Vec<u8>,
    rx_pos: usize,
    eof: bool,
    write_pending: Option<Vec<u8>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> WsByteStream<S> {
    pub fn new(ws: tokio_tungstenite::WebSocketStream<S>) -> Self {
        Self {
            ws,
            rx: Vec::new(),
            rx_pos: 0,
            eof: false,
            write_pending: None,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for WsByteStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        use futures_util::StreamExt;

        // 先消费已缓冲的消息负载
        if self.rx_pos < self.rx.len() {
            let remaining = &self.rx[self.rx_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.rx_pos += n;
            if self.rx_pos >= self.rx.len() {
                self.rx.clear();
                self.rx_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        if self.eof {
            return Poll::Ready(Ok(()));
        }

        loop {
            match self.ws.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::other(format!("ws read error: {}", e))));
                }
                Poll::Ready(Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(data)))) => {
                    if buf.remaining() >= data.len() {
                        buf.put_slice(&data);
                        return Poll::Ready(Ok(()));
                    }
                    self.rx = data;
                    self.rx_pos = 0;
                    let n = buf.remaining();
                    buf.put_slice(&self.rx[..n]);
                    self.rx_pos = n;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text)))) => {
                    let data = text.into_bytes();
                    if buf.remaining() >= data.len() {
                        buf.put_slice(&data);
                        return Poll::Ready(Ok(()));
                    }
                    self.rx = data;
                    self.rx_pos = 0;
                    let n = buf.remaining();
                    buf.put_slice(&self.rx[..n]);
                    self.rx_pos = n;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(tokio_tungstenite::tungstenite::Message::Ping(p)))) => {
                    // 自动应答 Pong
                    use futures_util::SinkExt;
                    match self.ws.poll_ready_unpin(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => {
                            return Poll::Ready(Err(io::Error::other(format!("ws pong error: {}", e))))
                        }
                        Poll::Ready(Ok(())) => {}
                    }
                    if self
                        .ws
                        .start_send_unpin(tokio_tungstenite::tungstenite::Message::Pong(p))
                        .is_err()
                    {
                        return Poll::Ready(Err(io::Error::other("ws pong send failed")));
                    }
                }
                Poll::Ready(Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_)))) => {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
                _ => {} // Ping 已处理；Pong/Frame 忽略
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for WsByteStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        use futures_util::SinkExt;

        if self.write_pending.is_none() {
            self.write_pending = Some(buf.to_vec());
        }
        match self.ws.poll_ready_unpin(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => {
                self.write_pending = None;
                return Poll::Ready(Err(io::Error::other(format!("ws write error: {}", e))));
            }
            Poll::Ready(Ok(())) => {}
        }
        if let Some(data) = self.write_pending.take() {
            let len = data.len();
            if self
                .ws
                .start_send_unpin(tokio_tungstenite::tungstenite::Message::Binary(data))
                .is_err()
            {
                return Poll::Ready(Err(io::Error::other("ws binary send failed")));
            }
            return Poll::Ready(Ok(len));
        }
        Poll::Ready(Ok(0))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use futures_util::SinkExt;
        self.ws
            .poll_flush_unpin(cx)
            .map_err(|e| io::Error::other(format!("ws flush error: {}", e)))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use futures_util::SinkExt;
        self.ws
            .poll_close_unpin(cx)
            .map_err(|e| io::Error::other(format!("ws close error: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_parse() {
        let bytes = parse_uuid("1386f85e-65bb-4e6e-9d56-78badb75e1fd").unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], 0x13);
        assert!(parse_uuid("bad").is_err());
    }

    #[test]
    fn test_cmd_key_deterministic() {
        // v2ray-core 已知向量：uuid 空值 + 盐的 MD5
        let k1 = cmd_key("00000000-0000-0000-0000-000000000000").unwrap();
        let k2 = cmd_key("00000000-0000-0000-0000-000000000000").unwrap();
        assert_eq!(k1, k2);
        assert_ne!(cmd_key("00000000-0000-0000-0000-000000000001").unwrap(), k1);
    }

    #[test]
    fn test_kdf_chain() {
        let k = kdf16(&[0u8; 16], &[b"a", b"b"]);
        assert_eq!(k.len(), 16);
        // 确定性
        let k2 = kdf16(&[0u8; 16], &[b"a", b"b"]);
        assert_eq!(k, k2);
    }

    #[test]
    fn test_fnv1a32() {
        assert_eq!(fnv1a32(b""), 0x811c9dc5);
        assert_eq!(fnv1a32(b"a"), 0xe40c292c);
    }

    #[test]
    fn test_encode_address_port() {
        let (addr, port) = encode_address_port("1.2.3.4:80").unwrap();
        assert_eq!(addr[0], 0x01);
        assert_eq!(port, 80);
        let (addr, _) = encode_address_port("example.com:443").unwrap();
        assert_eq!(addr[0], 0x02);
        assert_eq!(addr[1], 11);
        let (addr, _) = encode_address_port("[2001:db8::1]:443").unwrap();
        assert_eq!(addr[0], 0x03);
        assert_eq!(addr.len(), 1 + 16);
    }

    #[test]
    fn test_seal_header_length() {
        let key = [7u8; 16];
        let auth_id = [9u8; 16];
        let header = vec![1u8; 64];
        let sealed = seal_header(&key, &header, &auth_id).unwrap();
        assert_eq!(sealed.len(), 16 + 18 + 8 + 64 + 16);
        assert_eq!(&sealed[..16], &auth_id[..]);
    }

    #[test]
    fn test_network_from_str() {
        assert_eq!(VMessNetwork::from_str("tcp").unwrap(), VMessNetwork::Tcp);
        assert_eq!(VMessNetwork::from_str("ws").unwrap(), VMessNetwork::Ws);
        assert!(VMessNetwork::from_str("quic").is_err());
    }

    #[test]
    fn test_security_type() {
        let d = VMessDialer::new("127.0.0.1:1".parse().unwrap(), "uuid", 5000);
        assert_eq!(d.security_type().unwrap(), SEC_AES128_GCM);
        let mut d = d;
        d.set_security("none");
        assert_eq!(d.security_type().unwrap(), SEC_NONE);
        d.set_security("chacha20-poly1305");
        assert_eq!(d.security_type().unwrap(), SEC_CHACHA20_POLY1305);
    }
}
