//! SOCKS5 协议拨号器
//!
//! 实现 SOCKS5 出站代理协议，支持：
//! - 无认证（No Authentication）
//! - 用户名/密码认证（Username/Password Authentication）
//! - TCP 流式连接
//! - UDP ASSOCIATE（UDP 中继）

use async_trait::async_trait;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::warn;

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

/// `IP_TRANSPARENT` socket 选项值（Linux）
///
/// 允许 socket 绑定/连接到非本机地址。与 kdae 对齐，上行 socket
/// 即使不显式绑定源地址也设置该选项，确保在透明代理环境下可用。
const IP_TRANSPARENT: libc::c_int = 19;

/// `IPV6_TRANSPARENT` socket 选项值（Linux）
const IPV6_TRANSPARENT: libc::c_int = 75;

/// 在宿主网络命名空间中同步执行闭包，并在执行后恢复当前命名空间。
///
/// 由于 `protocols` crate 不能依赖 `control` crate，这里使用裸 libc 调用实现，
/// 语义与 `control::netns::with_host_ns_fd` 一致：
/// 1. 保存当前线程的网络命名空间 fd
/// 2. `setns(host_ns_fd)` 切换到宿主 NS
/// 3. 执行 `f()`（捕获 panic 以确保恢复）
/// 4. 恢复为原始命名空间
///
/// 注意：闭包内不能出现 `.await` 点。
fn with_host_ns_fd<T>(
    host_ns_fd: RawFd,
    f: impl FnOnce() -> Result<T, Socks5Error>,
) -> Result<T, Socks5Error> {
    // 1. 保存当前命名空间 fd
    let current_fd = unsafe { libc::open(c"/proc/self/ns/net".as_ptr(), libc::O_RDONLY) };
    if current_fd < 0 {
        return Err(Socks5Error::Io(std::io::Error::last_os_error()));
    }

    // 2. 切换到宿主 NS
    if unsafe { libc::setns(host_ns_fd, libc::CLONE_NEWNET) } != 0 {
        unsafe { libc::close(current_fd) };
        return Err(Socks5Error::Io(std::io::Error::last_os_error()));
    }

    // 3. 执行闭包（捕获 panic 以确保恢复命名空间）
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));

    // 4. 恢复原始命名空间
    if unsafe { libc::setns(current_fd, libc::CLONE_NEWNET) } != 0 {
        let e = std::io::Error::last_os_error();
        warn!(
            "CRITICAL: Failed to return to original netns after with_host_ns_fd: {}. \
             The current thread may be in the wrong namespace!",
            e
        );
    }
    unsafe { libc::close(current_fd) };

    match result {
        Ok(v) => v,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

/// SOCKS5 拨号器
///
/// 负责与 SOCKS5 上游服务器建立连接并转发流量。
/// 自动设置 SO_MARK=self_mark 以防止 eBPF 拦截自身流量。
pub struct Socks5Dialer {
    /// 上游 SOCKS5 代理服务器地址
    pub proxy_addr: SocketAddr,
    /// 拨号超时时间
    pub dial_timeout: Duration,
    /// 认证用户名（空字符串表示无需认证）
    pub username: String,
    /// 认证密码
    pub password: String,
    /// fwmark 用于 eBPF 自排除（0 表示不设置）
    pub self_mark: u32,
    /// 宿主网络命名空间 fd。
    ///
    /// 设置后，所有上行 socket（到 SOCKS5 代理的 TCP 连接、UDP ASSOCIATE 的
    /// UDP socket）都在宿主 NS 中创建并发出（与 kdae 对齐），源地址为宿主真实
    /// WAN 地址而非 daens 内部地址 `169.254.0.11`。`None` 表示在当前命名空间
    /// 中创建（默认行为，单机直接使用场景）。
    pub host_ns_fd: Option<RawFd>,
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

    /// 设置宿主网络命名空间 fd。
    ///
    /// 设置后，上行 socket 将在宿主 NS 中创建（与 kdae 对齐），
    /// 使得源地址为宿主真实 WAN 地址而非 daens 内部地址。
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
        if self.self_mark == 0 && self.host_ns_fd.is_none() {
            return timeout(self.dial_timeout, TcpStream::connect(&self.proxy_addr))
                .await
                .map_err(|_| Socks5Error::Timeout(format!("connect to proxy {}", self.proxy_addr)))?
                .map_err(Socks5Error::Io);
        }

        let domain = if self.proxy_addr.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };

        // Create socket, set SO_MARK / IP_TRANSPARENT, start non-blocking connect.
        // The whole phase is synchronous (no .await) so it can run inside a
        // temporary host-namespace switch.
        let create_and_connect = || -> Result<RawFd, Socks5Error> {
            let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
            if fd < 0 {
                return Err(Socks5Error::Io(std::io::Error::last_os_error()));
            }

            if self.self_mark != 0 {
                let mark_val = self.self_mark as libc::c_int;
                let ret = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_MARK,
                        &mark_val as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
                if ret != 0 {
                    unsafe {
                        libc::close(fd);
                    }
                    return Err(Socks5Error::Io(std::io::Error::last_os_error()));
                }
            }

            // IP_TRANSPARENT — aligned with kdae, harmless for client sockets.
            let one: libc::c_int = 1;
            let (level, opt): (libc::c_int, libc::c_int) = if self.proxy_addr.is_ipv4() {
                (libc::SOL_IP, IP_TRANSPARENT)
            } else {
                (libc::SOL_IPV6, IPV6_TRANSPARENT)
            };
            unsafe {
                libc::setsockopt(
                    fd,
                    level,
                    opt,
                    &one as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }

            // Connect (non-blocking, returns EINPROGRESS)
            let sockaddr = socket2::SockAddr::from(self.proxy_addr);
            let sockaddr_ptr = sockaddr.as_ptr();
            let sockaddr_len = sockaddr.len();
            let ret =
                unsafe { libc::connect(fd, sockaddr_ptr as *const libc::sockaddr, sockaddr_len) };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EINPROGRESS) {
                    unsafe {
                        libc::close(fd);
                    }
                    return Err(Socks5Error::Io(err));
                }
            }

            Ok(fd)
        };

        // Run the socket creation + connect in the host NS when configured.
        let fd = match self.host_ns_fd {
            Some(host_fd) => with_host_ns_fd(host_fd, create_and_connect)?,
            None => create_and_connect()?,
        };

        // Wrap in std TcpStream, then tokio TcpStream.
        // tokio will register the fd with epoll and wait for writability
        // (connected) or error. Note: the fd is namespace-independent after
        // creation, so I/O can continue from the original (daens) context.
        let std_stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
        let tokio_stream = tokio::net::TcpStream::from_std(std_stream).map_err(Socks5Error::Io)?;

        // Wait for the connection to complete with the same dial timeout used
        // by the plain TcpStream::connect path.
        timeout(self.dial_timeout, tokio_stream.writable())
            .await
            .map_err(|_| Socks5Error::Timeout(format!("connect to proxy {}", self.proxy_addr)))?
            .map_err(Socks5Error::Io)?;

        // Check for connection errors (e.g., ECONNREFUSED, ECONNRESET)
        if let Ok(Some(err)) = tokio_stream.take_error() {
            return Err(Socks5Error::Io(err));
        }

        Ok(tokio_stream)
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
            return Err(Socks5Error::ProtocolError("invalid SOCKS5 version".into()));
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

        // 步骤 2：发送连接请求
        // 解析目标地址（支持域名和 IP）
        // 注意: target 格式为 "host:port"，IPv6 为 "[::1]:80"
        let port = parse_port_from_target(target)?;
        let host = parse_host_from_target(target);

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
        // 尝试解析为 IPv6 地址（需去除方括号）
        else if let Ok(ip) = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::Ipv6Addr>()
        {
            request.push(0x04); // IPv6 地址类型
            request.extend_from_slice(&ip.octets());
        }
        // 否则以域名方式发送
        else {
            request.push(0x03); // 域名类型
            let host_bytes = host.as_bytes();
            if host_bytes.len() > 255 {
                return Err(Socks5Error::ProtocolError(
                    "target hostname too long".into(),
                ));
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
            return Ok(session.clone());
        }

        // Create new session
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

        // Perform auth handshake
        self.handshake_inner(&mut control, false).await?;

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
                SocketAddr::new(std::net::IpAddr::V4(ip), port)
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
            let create_relay = || -> Result<std::net::UdpSocket, Socks5Error> {
                let domain = if relay_addr.is_ipv4() {
                    libc::AF_INET
                } else {
                    libc::AF_INET6
                };
                let fd = unsafe {
                    libc::socket(domain, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0)
                };
                if fd < 0 {
                    return Err(Socks5Error::Io(std::io::Error::last_os_error()));
                }

                if self.self_mark != 0 {
                    let mark_val = self.self_mark as libc::c_int;
                    let ret = unsafe {
                        libc::setsockopt(
                            fd,
                            libc::SOL_SOCKET,
                            libc::SO_MARK,
                            &mark_val as *const _ as *const libc::c_void,
                            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                        )
                    };
                    if ret != 0 {
                        unsafe { libc::close(fd) };
                        return Err(Socks5Error::Io(std::io::Error::last_os_error()));
                    }
                }

                // Bind to port 0 so the OS assigns an ephemeral port.
                let bind_addr: SocketAddr = if relay_addr.is_ipv4() {
                    "0.0.0.0:0".parse().expect("valid bind addr")
                } else {
                    "[::]:0".parse().expect("valid bind addr")
                };
                let sock_addr = socket2::SockAddr::from(bind_addr);
                let ret = unsafe {
                    libc::bind(fd, sock_addr.as_ptr() as *const libc::sockaddr, sock_addr.len())
                };
                if ret != 0 {
                    unsafe { libc::close(fd) };
                    return Err(Socks5Error::Io(std::io::Error::last_os_error()));
                }

                // Connect the UDP socket to the relay address (so we can use send()).
                let sock_addr = socket2::SockAddr::from(relay_addr);
                let ret = unsafe {
                    libc::connect(fd, sock_addr.as_ptr() as *const libc::sockaddr, sock_addr.len())
                };
                if ret != 0 {
                    unsafe { libc::close(fd) };
                    return Err(Socks5Error::Io(std::io::Error::last_os_error()));
                }

                let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
                std_socket.set_nonblocking(true)?;
                Ok(std_socket)
            };

            let std_udp = match self.host_ns_fd {
                Some(host_fd) => with_host_ns_fd(host_fd, create_relay)?,
                None => create_relay()?,
            };
            tokio::net::UdpSocket::from_std(std_udp).map_err(Socks5Error::Io)?
        };

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

        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;

        if response[0] != 0x05 {
            return Err(Socks5Error::ProtocolError(
                "invalid SOCKS5 version during auth".into(),
            ));
        }

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
    /// 通过 SOCKS5 代理拨号到目标地址
    async fn dial(&self, target: &str) -> anyhow::Result<ProxyConn> {
        let stream = self.connect_with_mark().await?;
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
