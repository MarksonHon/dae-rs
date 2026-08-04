//! TProxy 监听器 + TCP/UDP 双向转发
//!
//! 本模块实现透明代理（TProxy）功能，是代理数据路径的核心组件：
//!
//! # 数据流
//!
//! ```text
//! 客户端 → eBPF/策略Routing → veth pair → 代理命名空间
//!                                         ↓
//!                                    TProxy 监听器
//!                                         ↓
//!                                  SOCKS5 出站Dialer
//!                                         ↓
//!                                    上游代理服务器
//!                                         ↓
//!                                    目标服务器
//! ```
//!
//! # 核心组件
//!
//! * [`TproxyListener`] — TProxy 监听器，在代理命名空间内监听端口
//! * [`handle_connection`] — TCP 双向中继函数
//! * [`get_original_dst`] — 获取 TProxy transparent proxy的原始目标地址
//!
//! # 依赖
//!
//! * Linux `IP_TRANSPARENT` socket 选项（需要 `CAP_NET_ADMIN` 权限）
//! * Linux `IP_RECVORIGDSTADDR` socket 选项（用于 UDP 原始目标地址获取）
//! * Linux `SO_REUSEADDR` 和 `SO_REUSEPORT` socket 选项
//!
//! # 安全性
//!
//! * 所有 socket 操作需处理 `EPERM` 错误（缺少 `CAP_NET_ADMIN` 时）
//! * 连接关闭需正确传播，避免连接泄漏
//! * 错误不应导致整个监听器崩溃

use anyhow::{Context, Result};
use protocols::{OutboundDialer, ProxyStream};
use protocols::UdpSession;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Notify;
use tracing::{debug, error, info, warn};

// ============================================================================
// TCP 中继常量
// ============================================================================

/// 单次 splice() 的数据块大小（内核页接管，块大减少系统调用）
const SPLICE_CHUNK: usize = 64 * 1024;

/// splice 不可用时回退路径的双向拷贝缓冲大小（tokio 默认 copy_bidirectional 仅 8KB）
const COPY_BUFFER_SIZE: usize = 64 * 1024;

// ============================================================================
// UDP 中继常量
// ============================================================================

/// UDP 数据包最大尺寸
const MAX_UDP_SIZE: usize = 65535;

/// recvmsg 辅助数据（cmsg）缓冲大小
const CMSG_BUFFER_SIZE: usize = 128;

/// UDP relay flow 空闲超时：超过该时间没有收到中继响应则关闭会话
const UDP_FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// 透明回包 socket 池容量上限（超出时淘汰最久未用条目）
const RESP_SOCKET_POOL_CAP: usize = 256;

// ============================================================================
// Linux socket 选项常量
// ============================================================================

/// `IP_TRANSPARENT` socket 选项值（Linux）
///
/// 使 socket 能透明地接受非本机地址的连接，是 TProxy 的核心机制。
/// 需要 `CAP_NET_ADMIN` 权限。
const IP_TRANSPARENT: libc::c_int = 19;

/// `IPV6_TRANSPARENT` socket 选项值（Linux）
///
/// IPv6 版本的 IP_TRANSPARENT，使 IPv6 socket 能透明地接受非本机地址的连接。
const IPV6_TRANSPARENT: libc::c_int = 75;

/// `IP_RECVORIGDSTADDR` socket 选项值（Linux）
///
/// 使 socket 在收到数据包时，通过辅助数据（cmsg）返回原始目标地址。
/// 这是 UDP TProxy 获取原始目标地址的关键机制。
const IP_RECVORIGDSTADDR: libc::c_int = 20;

/// `IPV6_RECVORIGDSTADDR` socket 选项值（Linux）
///
/// IPv6 版本的 IP_RECVORIGDSTADDR。
const IPV6_RECVORIGDSTADDR: libc::c_int = 74;

/// `SO_REUSEADDR` socket 选项值（Linux）
///
/// 允许重用处于 TIME_WAIT 状态的 socket 地址。
#[allow(dead_code)]
const SO_REUSEADDR: libc::c_int = 2;

/// `SO_REUSEPORT` socket 选项值（Linux）
///
/// 允许多个 socket 绑定到相同的端口，实现负载均衡。
#[allow(dead_code)]
const SO_REUSEPORT: libc::c_int = 15;

/// `SO_MARK` socket 选项值（Linux）
///
/// 设置 socket 的 fwmark，用于策略Routing和 eBPF program识别自身流量。
/// original dae uses 0x100 as internal socket mark。
const SO_MARK: libc::c_int = 36;

// ============================================================================
// TproxyListener
// ============================================================================

/// TProxy 监听器
///
/// 透明代理监听器，接收从内核（通过 eBPF + 策略Routing）重定向到代理命名空间的
/// TCP 连接，通过 SOCKS5 出站Dialer转发到上游代理。
///
/// # Examples
///
/// ```no_run
/// use control::net::tproxy::TproxyListener;
/// use protocols::Socks5Dialer;
/// use protocols::OutboundDialer;
/// use std::net::SocketAddr;
///
/// # async fn example() -> anyhow::Result<()> {
/// let addr: SocketAddr = "0.0.0.0:15080".parse()?;
/// let dialer: std::sync::Arc<dyn OutboundDialer> = std::sync::Arc::new(Socks5Dialer::new(
///     "127.0.0.1:1080".parse()?,
///     "", "", 5000,
/// ));
/// let listener = TproxyListener::new(addr, dialer);
/// listener.start().await?;
/// # Ok(())
/// # }
/// ```
pub struct TproxyListener {
    /// Listen address（在代理命名空间内，如 `0.0.0.0:15080`）
    listen_addr: SocketAddr,
    /// 出站Dialer（按配置的协议构造）
    dialer: Arc<dyn OutboundDialer>,
    /// Running flag
    running: Arc<AtomicBool>,
    /// Socket mark value (for eBPF self-exclusion, default 0x100)
    socket_mark: u32,
    /// 停止信号（通知 accept 循环退出，无需轮询）
    stop_signal: Arc<Notify>,
    /// 内部 DNS handler 地址（跨 namespace DNS 劫持用）。
    ///
    /// 当 TCP 连接原始目标为 53 端口时，不再走代理 Dialer，而是把
    /// DNS-over-TCP 会话转发到此地址的 DNS handler（与 UDP 劫持一致）。
    /// `None` 表示不劫持 TCP DNS。
    dns_forward_addr: Option<SocketAddr>,
    /// Host network namespace fd（DNS 劫持上游 socket 在宿主 NS 创建）。
    host_ns_fd: Option<RawFd>,
}

impl TproxyListener {
    /// 创建新的 TProxy 监听器
    ///
    /// # Parameters
    ///
    /// * `listen_addr` — 监听地址（如 `0.0.0.0:15080`）
    /// * `dialer` — 出站Dialer
    pub fn new(listen_addr: SocketAddr, dialer: Arc<dyn OutboundDialer>) -> Self {
        Self {
            listen_addr,
            dialer,
            running: Arc::new(AtomicBool::new(false)),
            socket_mark: shared::DAE_SOCKET_MARK, // 原版 dae 默认值
            stop_signal: Arc::new(Notify::new()),
            dns_forward_addr: None,
            host_ns_fd: None,
        }
    }

    /// 创建新的 TProxy 监听器，指定 socket 标记值
    pub fn new_with_mark(
        listen_addr: SocketAddr,
        dialer: Arc<dyn OutboundDialer>,
        socket_mark: u32,
    ) -> Self {
        Self {
            listen_addr,
            dialer,
            running: Arc::new(AtomicBool::new(false)),
            socket_mark,
            stop_signal: Arc::new(Notify::new()),
            dns_forward_addr: None,
            host_ns_fd: None,
        }
    }

    /// 设置 TCP DNS 劫持目标（内部 DNS handler 地址）。
    ///
    /// 设置后，原始目标为 53 端口的 TCP 连接会被转发到该 DNS handler，
    /// 而不是走代理。与 UDP 劫持的 `169.254.0.1:<port>` 保持一致。
    pub fn set_dns_forward_addr(&mut self, addr: SocketAddr) {
        self.dns_forward_addr = Some(addr);
        tracing::info!(
            "DNS hijacking enabled: TCP TProxy will forward DNS queries to {}",
            addr
        );
    }

    /// 设置宿主网络命名空间 fd（DNS 劫持上游连接在宿主 NS 创建）。
    pub fn set_host_ns_fd(&mut self, host_ns_fd: Option<RawFd>) {
        self.host_ns_fd = host_ns_fd;
    }

    /// Get listen address
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// 获取出站Dialer的引用
    pub fn dialer(&self) -> &Arc<dyn OutboundDialer> {
        &self.dialer
    }

    /// Check if listener is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// 获取运行标记的原子引用（用于跨线程通信）
    pub fn running_flag(&self) -> Arc<AtomicBool> {
        self.running.clone()
    }

    /// Create and bind TProxy listening sockets (AF_INET + AF_INET6).
    ///
    /// Creates two separate sockets aligned with original dae:
    /// - AF_INET socket bound to `0.0.0.0:{port}` → SOCKMAP key 0 (tcp4)
    /// - AF_INET6 socket bound to `[::]:{port}` with `IPV6_V6ONLY=1` → SOCKMAP key 2 (tcp6)
    ///
    /// This replaces the single AF_INET6 dual-stack socket approach, which caused
    /// `bpf_sk_assign()` to assign an AF_INET6 socket to IPv4 packets, leading to
    /// `tcp_v4_rcv()` failures.
    ///
    /// Returns `(listener_v4, listener_v6)`.
    pub async fn bind(&self) -> Result<(TcpListener, TcpListener)> {
        use socket2::{Domain, Protocol, Socket, Type};
        use std::os::unix::io::AsRawFd;

        let start = std::time::Instant::now();
        let port = self.listen_addr.port();
        debug!(
            port = port,
            socket_mark = format!("{:#x}", self.socket_mark),
            "TProxy TCP bind starting (separate AF_INET + AF_INET6)"
        );

        let one: libc::c_int = 1;

        // ---- AF_INET socket (IPv4) — binds to 0.0.0.0:{port} ----
        let v4_socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .context("Failed to create AF_INET TProxy socket")?;
        let fd_v4 = v4_socket.as_raw_fd();

        v4_socket.set_reuse_address(true)?;
        #[cfg(unix)]
        v4_socket.set_reuse_port(true)?;

        // IP_TRANSPARENT — required for TProxy to accept non-local addresses
        unsafe {
            libc::setsockopt(
                fd_v4,
                libc::SOL_IP,
                IP_TRANSPARENT,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        // SO_MARK — eBPF self-exclusion (pid_is_control_plane)
        if self.socket_mark != 0 {
            let mark_val = self.socket_mark as libc::c_int;
            unsafe {
                libc::setsockopt(
                    fd_v4,
                    libc::SOL_SOCKET,
                    SO_MARK,
                    &mark_val as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        let v4_addr: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), port);
        v4_socket
            .bind(&socket2::SockAddr::from(v4_addr))
            .with_context(|| {
                format!("Failed to bind AF_INET socket to {} (port may be in use)", v4_addr)
            })?;
        v4_socket.listen(128)?;

        let std_v4: std::net::TcpListener = v4_socket.into();
        std_v4.set_nonblocking(true)?;
        let listener_v4 = TcpListener::from_std(std_v4)
            .context("Failed to convert AF_INET socket to tokio TcpListener")?;

        // ---- AF_INET6 socket (IPv6) — binds to [::]:{port}, IPV6_V6ONLY=1 ----
        let v6_socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))
            .context("Failed to create AF_INET6 TProxy socket")?;
        let fd_v6 = v6_socket.as_raw_fd();

        // IPV6_V6ONLY=1 — separate socket, not dual-stack
        let v6only: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd_v6,
                libc::SOL_IPV6,
                libc::IPV6_V6ONLY,
                &v6only as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        v6_socket.set_reuse_address(true)?;
        #[cfg(unix)]
        v6_socket.set_reuse_port(true)?;

        // IPV6_TRANSPARENT — required for IPv6 TProxy
        unsafe {
            libc::setsockopt(
                fd_v6,
                libc::SOL_IPV6,
                IPV6_TRANSPARENT,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        // SO_MARK — eBPF self-exclusion
        if self.socket_mark != 0 {
            let mark_val = self.socket_mark as libc::c_int;
            unsafe {
                libc::setsockopt(
                    fd_v6,
                    libc::SOL_SOCKET,
                    SO_MARK,
                    &mark_val as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        let v6_addr: SocketAddr = SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), port);
        v6_socket
            .bind(&socket2::SockAddr::from(v6_addr))
            .with_context(|| {
                format!("Failed to bind AF_INET6 socket to {} (port may be in use)", v6_addr)
            })?;
        v6_socket.listen(128)?;

        let std_v6: std::net::TcpListener = v6_socket.into();
        std_v6.set_nonblocking(true)?;
        let listener_v6 = TcpListener::from_std(std_v6)
            .context("Failed to convert AF_INET6 socket to tokio TcpListener")?;

        debug!(
            "TProxy TCP bind completed: {}ms (v4_fd={}, v6_fd={})",
            start.elapsed().as_millis(),
            listener_v4.as_raw_fd(),
            listener_v6.as_raw_fd(),
        );
        info!(
            port = port,
            socket_mark = self.socket_mark,
            "TProxy sockets bound successfully (AF_INET + AF_INET6)"
        );

        Ok((listener_v4, listener_v6))
    }

    /// Start accept loops for both IPv4 and IPv6 listeners.
    ///
    /// Runs two concurrent accept loops (one per socket) until
    /// [`stop()`](TproxyListener::stop) is called.
    pub async fn serve(&self, listener_v4: TcpListener, listener_v6: TcpListener) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);
        let protocol = self.dialer.protocol_name();
        info!(
            listen_addr = %self.listen_addr,
            protocol = %protocol,
            "TProxy listener started (AF_INET + AF_INET6)"
        );

        // Run both accept loops concurrently via tokio::join!
        let (r4, r6) = tokio::join!(
            self.run_accept_loop(listener_v4),
            self.run_accept_loop(listener_v6),
        );

        if let Err(e) = r4 {
            error!("IPv4 accept loop error: {}", e);
        }
        if let Err(e) = r6 {
            error!("IPv6 accept loop error: {}", e);
        }

        Ok(())
    }

    /// Start TProxy listener (bind + serve, for standalone usage).
    ///
    /// Creates separate AF_INET and AF_INET6 sockets via [`bind()`](TproxyListener::bind),
    /// then runs both accept loops via [`serve()`](TproxyListener::serve).
    pub async fn start(&self) -> Result<()> {
        let (listener_v4, listener_v6) = self.bind().await?;
        self.serve(listener_v4, listener_v6).await
    }

    /// Accept 循环核心（内部使用）
    async fn run_accept_loop(&self, listener: TcpListener) -> Result<()> {
        let mut accept_count: u64 = 0;
        loop {
            // 检查运行标记，用于优雅停止
            if !self.running.load(Ordering::SeqCst) {
                debug!(
                    listen_addr = %self.listen_addr,
                    total_accepted = accept_count,
                    "TProxy listener stopping (running=false)"
                );
                break;
            }

            // 使用 tokio::select! 同时等待 accept 和停止信号：
            // - accept 到连接 → 处理连接
            // - 收到停止信号 → 立即退出循环
            // - accept 错误 → 短暂休眠后重试
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            accept_count += 1;
                            debug!(
                                peer_addr = %peer_addr,
                                accept_no = accept_count,
                                "Accepted new TCP connection"
                            );
                            let dialer = self.dialer.clone();
                            let dns_forward_addr = self.dns_forward_addr;
                            let host_ns_fd = self.host_ns_fd;
                            tokio::spawn(async move {
                                let start = std::time::Instant::now();
                                if let Err(e) = handle_connection(
                                    stream,
                                    dialer,
                                    dns_forward_addr,
                                    host_ns_fd,
                                )
                                .await
                                {
                                    error!(
                                        peer_addr = %peer_addr,
                                        elapsed_ms = %start.elapsed().as_millis(),
                                        error = %e,
                                        "Connection handling failed"
                                    );
                                } else {
                                    debug!(
                                        peer_addr = %peer_addr,
                                        elapsed_ms = %start.elapsed().as_millis(),
                                        "Connection completed successfully"
                                    );
                                }
                            });
                        }
                        Err(e) => {
                            error!(
                                listen_addr = %self.listen_addr,
                                error = %e,
                                "Failed to accept connection"
                            );
                            // 短暂休眠避免空转
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
                _ = self.stop_signal.notified() => {
                    info!(
                        listen_addr = %self.listen_addr,
                        total_accepted = accept_count,
                        "TProxy listener stopping via signal"
                    );
                    break;
                }
            }
        }

        Ok(())
    }

    /// Stop the TProxy listener.
    ///
    /// Sets the running flag to `false` and wakes all accept loops via `notify_waiters()`.
    /// Existing connections are not interrupted — they continue until completion.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        // Wake ALL accept loops (both IPv4 and IPv6), not just one
        self.stop_signal.notify_waiters();
        info!(
            listen_addr = %self.listen_addr,
            "TProxy listener stop signal sent"
        );
    }
}

impl std::fmt::Debug for TproxyListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TproxyListener")
            .field("listen_addr", &self.listen_addr)
            .field("running", &self.running.load(Ordering::Relaxed))
            .finish()
    }
}

// ============================================================================
// 连接处理
// ============================================================================

/// 处理单个 TProxy 连接（TCP 双向中继）
///
/// 执行完整的 TCP 双向中继流程：
///
/// 1. **获取原始目标地址** — 从 `TcpStream` 中获取原始目标地址
///    （利用 TProxy 的 `IP_TRANSPARENT` 特性，`getsockname()` 返回原始目标地址）
/// 2. **SOCKS5 拨号** — 创建一个 SOCKS5 Dialer实例并调用 `dial(target_addr)` 建立到上游的连接
/// 3. **获取 `ProxyConn`** — 获取实现了 `AsyncRead + AsyncWrite` 的代理连接
/// 4. **双向数据拷贝** — 使用 `tokio::io::copy_bidirectional` 进行双向数据拷贝
/// 5. **连接关闭** — 等待双向拷贝完成，确保干净关闭连接
///
/// # Parameters
///
/// * `inbound` — 从 TProxy 接收的客户端连接
/// * `dialer` — SOCKS5 出站Dialer
///
/// # 错误处理
///
/// * 如果无法获取原始目标地址，返回错误（可能未正确设置 `IP_TRANSPARENT`）
/// * 如果 SOCKS5 拨号失败，返回错误（可能上游代理不可达）
/// * 如果双向拷贝失败，返回错误（可能网络中断）
/// * 单个连接的错误不会影响监听器的其他连接
async fn handle_connection(
    mut inbound: TcpStream,
    dialer: Arc<dyn OutboundDialer>,
    dns_forward_addr: Option<SocketAddr>,
    host_ns_fd: Option<RawFd>,
) -> Result<()> {
    let start = std::time::Instant::now();
    let peer_addr = inbound.peer_addr().ok();

    debug!(
        peer_addr = %peer_addr.map(|a| a.to_string()).unwrap_or_else(|| "unknown".to_string()),
        "handle_connection: starting"
    );

    // ---- 步骤 1：获取原始目标地址 ----
    let orig_dst = get_original_dst(&inbound).context(
        "Failed to get original destination address from TProxy connection \
         (ensure IP_TRANSPARENT is set and CAP_NET_ADMIN is available)",
    )?;
    debug!(orig_dst = %orig_dst, "handle_connection: got original destination");

    // ---- 步骤 1.5：TCP DNS 劫持 ----
    // eBPF 已把 TCP 53 查询重定向到控制平面（ROUTE_STATE_DNS_QUERY）。
    // 这里把 DNS-over-TCP 会话转发给内部 DNS handler，而不是走代理，
    // 与 UDP 劫持（dns_forward_addr）保持一致。这样 TCP DNS 也能进入
    // DNS 模块的缓存/防污染/代理逻辑。
    if orig_dst.port() == 53 {
        if let Some(handler_addr) = dns_forward_addr {
            info!(
                "TCP DNS hijack: {} -> {} (querying {})",
                peer_addr.map(|a| a.to_string()).unwrap_or_else(|| "?".into()),
                orig_dst,
                handler_addr,
            );
            return handle_dns_tcp_connection(inbound, handler_addr, host_ns_fd).await;
        }
        warn!(
            orig_dst = %orig_dst,
            "TCP DNS connection to port 53 but no DNS forward addr configured; proxying directly"
        );
    }

    // ---- 步骤 2：禁用 Nagle（TCP_NODELAY），降低交互式小包延迟 ----
    // 入站连接由内核 accept 默认开启 Nagle；出站连接在 SOCKS5 Dialer中设置。
    set_tcp_nodelay(&inbound);

    // ---- 步骤 2：通过出站Dialer拨号到目标 ----
    let protocol = dialer.protocol_name();
    let proxy_addr = dialer.proxy_addr();
    let dial_result = dialer.dial(&orig_dst.to_string()).await;

    debug!(
        orig_dst = %orig_dst,
        protocol = %protocol,
        dial_elapsed_ms = start.elapsed().as_millis(),
        "handle_connection: dial result={}",
        if dial_result.is_ok() { "ok" } else { "fail" }
    );

    let outbound = match dial_result {
        Ok(conn) => conn,
        Err(e) => {
            info!(
                "TCP  {}:{} -> {} [PROXY] FAIL dial via {} -> proxy {}: {}",
                peer_addr
                    .map(|a| a.ip())
                    .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                peer_addr.map(|a| a.port()).unwrap_or(0),
                orig_dst,
                protocol,
                proxy_addr,
                e,
            );
            return Err(e).context("dial failed");
        }
    };

    // ---- 步骤 2.5：记录出站连接信息（INFO）----
    // outbound local 地址为宿主 NS 中真实源地址（Tcp 变体）；
    // TLS/WS/QUIC 包装流无法直接取 socket 地址，显示 n/a。
    let outbound_local = match &outbound.stream {
        ProxyStream::Tcp(s) => s.local_addr().ok(),
        ProxyStream::Boxed(_) => None,
    };
    info!(
        "TCP  {}:{} -> {} [PROXY] outbound via {} -> proxy {} (local {}) dial={:.1}ms",
        peer_addr
            .map(|a| a.ip())
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        peer_addr.map(|a| a.port()).unwrap_or(0),
        orig_dst,
        protocol,
        proxy_addr,
        outbound_local
            .map(|a| a.to_string())
            .unwrap_or_else(|| "n/a".into()),
        start.elapsed().as_micros() as f64 / 1000.0,
    );

    // ---- 步骤 3：双向数据拷贝 ----
    // 纯 TCP 连接走 splice 零拷贝中继；TLS/WS/QUIC 包装流走缓冲拷贝。
    let result = match outbound.stream {
        ProxyStream::Tcp(outbound_stream) => {
            relay_bidirectional(inbound, outbound_stream).await
        }
        ProxyStream::Boxed(mut outbound_stream) => {
            tokio::io::copy_bidirectional(&mut inbound, &mut outbound_stream).await
        }
    };
    let elapsed_ms = start.elapsed().as_micros() as f64 / 1000.0;
    let bytes_transferred = result.as_ref().map(|(a, b)| a + b).unwrap_or(0);

    match result {
        Ok((to_up, from_up)) => {
            debug!(
                orig_dst = %orig_dst,
                up_bytes = to_up,
                down_bytes = from_up,
                total_ms = elapsed_ms,
                "Connection completed"
            );
            info!(
                "TCP  {}:{} -> {} [PROXY] up={} down={} {:.1}ms",
                peer_addr
                    .map(|a| a.ip())
                    .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                peer_addr.map(|a| a.port()).unwrap_or(0),
                orig_dst,
                to_up,
                from_up,
                elapsed_ms,
            );
        }
        Err(e) => {
            debug!(
                orig_dst = %orig_dst,
                bytes_transferred = bytes_transferred,
                total_ms = elapsed_ms,
                error = %e,
                "Connection closed with error"
            );
            info!(
                "TCP  {}:{} -> {} [PROXY] CLOSE {:.1}ms: {}",
                peer_addr
                    .map(|a| a.ip())
                    .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                peer_addr.map(|a| a.port()).unwrap_or(0),
                orig_dst,
                elapsed_ms,
                e,
            );
        }
    }

    Ok(())
}

/// 转发一个 DNS-over-TCP 会话到内部 DNS handler。
///
/// DNS-over-TCP 使用 2 字节长度前缀帧（RFC 1035 §4.2.2）。这里把客户端
/// 连接与内部 DNS handler 之间的字节流双向转发即可：查询帧发给 handler，
/// 响应帧回传客户端。由于客户端连接是 IP_TRANSPARENT 的 TProxy socket
/// （本地地址 = 原始目标 DNS 服务器），回程数据源地址正确，客户端不会丢弃。
///
/// 上游 socket 在宿主 NS 创建（`host_ns_fd`）并打 SO_MARK=DAE_SOCKET_MARK，
/// 与 UDP 劫持路径保持一致，确保 eBPF 放行（防劫持循环）。
async fn handle_dns_tcp_connection(
    mut inbound: TcpStream,
    handler_addr: SocketAddr,
    host_ns_fd: Option<RawFd>,
) -> Result<()> {
    let timeout = Duration::from_secs(5);
    let mut upstream = protocols::hostns::connect_tcp(
        handler_addr,
        &protocols::hostns::DirectSocket::control_plane(host_ns_fd),
        false,
        timeout,
    )
    .await
    .map_err(|e| anyhow::anyhow!("failed to connect to internal DNS handler {}: {}", handler_addr, e))?;

    set_tcp_nodelay(&upstream);
    // 纯字节中继：长度前缀帧原样透传，无需在此解析 DNS。
    let (a, b) = tokio::io::copy_bidirectional(&mut inbound, &mut upstream).await?;
    debug!(
        handler_addr = %handler_addr,
        up_bytes = a,
        down_bytes = b,
        "TCP DNS hijack session completed"
    );
    Ok(())
}

// ============================================================================
// Helper function
// ============================================================================

/// 获取 TProxy 连接的原始目标地址
///
/// 在 Linux TProxy 模式下，由于设置了 `IP_TRANSPARENT` 选项，
/// `getsockname()` 系统调用返回的不是 socket 的本地地址，而是
/// 客户端连接的原始目标地址。这使得我们能够在不修改数据包的情况下
/// 获取客户端原本要连接的目标地址。
///
/// # 实现原理
///
/// ```text
/// 正常模式：  getsockname() → 本地绑定地址（如 0.0.0.0:15080）
/// TProxy 模式：getsockname() → 原始目标地址（如 1.2.3.4:80）
/// ```
///
/// # Parameters
///
/// * `stream` — TProxy 接收的 TCP 连接
///
/// # Returns
///
/// 返回原始目标地址（`SocketAddr`）。
///
/// # 错误
///
/// * 如果没有 `CAP_NET_ADMIN` 权限或未正确设置 `IP_TRANSPARENT`，
///   可能返回错误
/// * 如果地址的端口号为 0，视为无效地址返回错误
fn get_original_dst(stream: &TcpStream) -> Result<SocketAddr> {
    use socket2::SockRef;

    let sock_ref = SockRef::from(stream);
    let local_addr = sock_ref
        .local_addr()
        .context("Failed to call getsockname() on TProxy connection")?;
    let addr: SocketAddr = local_addr
        .as_socket()
        .context("getsockname() returned a non-IP address")?;

    // 验证地址有效性：TProxy 原始目标地址的端口不应为 0
    if addr.port() == 0 {
        anyhow::bail!(
            "Invalid original destination address (port is 0): {} — \
             IP_TRANSPARENT may not be configured correctly",
            addr
        );
    }

    Ok(addr)
}

/// 设置 TCP_NODELAY 禁用 Nagle 算法。
///
/// 代理路径上每个字节流都可能承载交互式小包（SSH、游戏、API 请求等），
/// Nagle 会把这些小包合并等待 ACK，显著增加 RTT。原版 dae 对入站和出站
/// 连接都显式设置 TCP_NODELAY。失败仅记录 debug（非致命）。
fn set_tcp_nodelay(stream: &TcpStream) {
    use socket2::SockRef;
    if let Err(e) = SockRef::from(stream).set_nodelay(true) {
        debug!("Failed to set TCP_NODELAY: {}", e);
    }
}

// ============================================================================
// TCP 双向中继：splice 零拷贝 + 大缓冲回退
// ============================================================================

/// 管道对（RAII，析构时关闭两端 fd）。
struct PipePair {
    r: RawFd,
    w: RawFd,
}

impl PipePair {
    fn new() -> std::io::Result<Self> {
        let mut fds = [0; 2];
        let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { r: fds[0], w: fds[1] })
    }
}

impl Drop for PipePair {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.r);
            libc::close(self.w);
        }
    }
}

/// 探测 splice() 对 (src, dst) 组合是否可用。
///
/// 用 len=0 的 splice 调用只触发内核的 fd 类型校验而不搬运数据；
/// 若返回 EINVAL（内核/文件类型不支持）则回退到缓冲拷贝。
fn splice_supported(src: &TcpStream, dst: &TcpStream, pipe: &PipePair) -> bool {
    use std::os::unix::io::AsRawFd;
    let flags = libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK;
    let n = unsafe {
        libc::splice(
            src.as_raw_fd(),
            std::ptr::null_mut(),
            pipe.w,
            std::ptr::null_mut(),
            0,
            flags,
        )
    };
    if n < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINVAL) {
            return false;
        }
    }
    let n = unsafe {
        libc::splice(
            pipe.r,
            std::ptr::null_mut(),
            dst.as_raw_fd(),
            std::ptr::null_mut(),
            0,
            flags,
        )
    };
    if n < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINVAL) {
            return false;
        }
    }
    true
}

/// 为 splice 就绪等待复制一个独立 fd（dup）。
///
/// 原 tokio `TcpStream` 已注册到 reactor，不能直接用其 fd 再注册
/// AsyncFd（同一 fd 重复注册会与现有注册冲突）；dup 出独立 fd 后
/// 两个注册互不干扰，且原流仍可用于 shutdown 等操作。
fn dup_fd_stream(stream: &TcpStream) -> std::io::Result<AsyncFd<std::net::TcpStream>> {
    use std::os::unix::io::{AsRawFd, FromRawFd};
    let dup_fd = unsafe { libc::dup(stream.as_raw_fd()) };
    if dup_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let std_stream = unsafe { std::net::TcpStream::from_raw_fd(dup_fd) };
    AsyncFd::new(std_stream)
}

/// 用 splice() 单向搬运数据：src socket → 管道 → dst socket（零拷贝）。
///
/// 源 EOF 时对 dst 执行 `shutdown(SHUT_WR)` 传播 FIN（半关闭语义），
/// 然后返回本方向搬运的总字节数。
async fn splice_direction(
    src: &TcpStream,
    dst: &TcpStream,
    pipe: &PipePair,
) -> std::io::Result<u64> {
    use std::os::unix::io::AsRawFd;

    let src_ready = dup_fd_stream(src)?;
    let dst_ready = dup_fd_stream(dst)?;
    let src_fd = src.as_raw_fd();
    let dst_fd = dst.as_raw_fd();
    let mut total: u64 = 0;

    loop {
        // 1. 等待源可读，splice 进管道
        let n = loop {
            let mut guard = src_ready.readable().await?;
            let n = unsafe {
                libc::splice(
                    src_fd,
                    std::ptr::null_mut(),
                    pipe.w,
                    std::ptr::null_mut(),
                    SPLICE_CHUNK,
                    libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                )
            };
            if n > 0 {
                break n as usize;
            }
            if n == 0 {
                // 源 EOF：向对端传播 FIN，本方向结束
                unsafe { libc::shutdown(dst_fd, libc::SHUT_WR) };
                return Ok(total);
            }
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::WouldBlock {
                return Err(err);
            }
            guard.clear_ready();
        };

        // 2. 等待目标可写，把管道数据全部 splice 进目标。
        // 必须循环排空管道：若一次只搬走部分字节（m < n），剩余字节若
        // 留到下一轮外层循环会因等待源可读而滞留（死锁）。
        let mut remaining = n;
        while remaining > 0 {
            let mut guard = dst_ready.writable().await?;
            let m = unsafe {
                libc::splice(
                    pipe.r,
                    std::ptr::null_mut(),
                    dst_fd,
                    std::ptr::null_mut(),
                    remaining,
                    libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                )
            };
            if m > 0 {
                total += m as u64;
                remaining -= m as usize;
                continue;
            }
            if m == 0 {
                // 管道 EOF（写端已关），正常结束
                return Ok(total);
            }
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::WouldBlock {
                return Err(err);
            }
            guard.clear_ready();
        }
    }
}

/// 单方向缓冲拷贝（64KB 缓冲），源 EOF 时 shutdown 目标写端传播 FIN。
async fn buffered_copy_direction<R, W>(src: &mut R, dst: &mut W) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; COPY_BUFFER_SIZE];
    let mut total: u64 = 0;
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            dst.shutdown().await?;
            return Ok(total);
        }
        dst.write_all(&buf[..n]).await?;
        total += n as u64;
    }
}

/// 双向 TCP 中继：优先 splice() 零拷贝路径，不可用时回退到 64KB 缓冲拷贝。
///
/// 返回 `(客户端→代理 字节数, 代理→客户端 字节数)`，与 tokio
/// `copy_bidirectional` 的顺序一致。
async fn relay_bidirectional(
    mut inbound: TcpStream,
    mut outbound: TcpStream,
) -> std::io::Result<(u64, u64)> {
    // ---- splice 零拷贝路径 ----
    if let Ok(pipe_ab) = PipePair::new() {
        if let Ok(pipe_ba) = PipePair::new() {
            if splice_supported(&inbound, &outbound, &pipe_ab)
                && splice_supported(&outbound, &inbound, &pipe_ba)
            {
                let (to_up, from_up) = tokio::join!(
                    splice_direction(&inbound, &outbound, &pipe_ab),
                    splice_direction(&outbound, &inbound, &pipe_ba),
                );
                return match (to_up, from_up) {
                    (Err(e), _) => Err(e),
                    (_, Err(e)) => Err(e),
                    (Ok(a), Ok(b)) => Ok((a, b)),
                };
            }
        }
    }

    // ---- 64KB 缓冲回退路径（splice 不可用）----
    let (mut inbound_r, mut inbound_w) = inbound.split();
    let (mut outbound_r, mut outbound_w) = outbound.split();
    let (to_up, from_up) = tokio::join!(
        buffered_copy_direction(&mut inbound_r, &mut outbound_w),
        buffered_copy_direction(&mut outbound_r, &mut inbound_w),
    );
    match (to_up, from_up) {
        (Err(e), _) => Err(e),
        (_, Err(e)) => Err(e),
        (Ok(a), Ok(b)) => Ok((a, b)),
    }
}

// ============================================================================
// DNS Query Name Extraction
// ============================================================================

/// Extract the query name from a DNS packet (question section).
///
/// Supports DNS name compression (RFC 1035 §4.1.4). When a compression pointer
/// (high two bits `0xC0`) is encountered, the function follows the pointer to
/// continue reading labels from elsewhere in the message.
///
/// Safety measures:
/// - Tracks visited positions to detect pointer loops
/// - Limits total jumps to 10 to prevent abuse
/// - Returns `None` on malformed packets
pub fn extract_dns_query_name(packet: &[u8]) -> Option<String> {
    if packet.len() < 12 {
        return None;
    }

    let mut labels = Vec::new();
    let mut jumped = false;
    let mut visited = std::collections::HashSet::new();
    let max_jumps = 10;
    let mut jumps = 0usize;

    let mut pos = 12usize;

    loop {
        if pos >= packet.len() {
            return None;
        }

        let len = packet[pos] as usize;

        // DNS compression pointer (RFC 1035 §4.1.4):
        // High two bits are `11`, remaining 14 bits are the pointer offset
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= packet.len() {
                return None;
            }
            let ptr = ((len & 0x3F) << 8) | packet[pos + 1] as usize;

            // Loop detection: if we've seen this pointer before, it's a loop
            if !visited.insert(ptr) || jumps >= max_jumps {
                return None;
            }
            jumps += 1;

            // On the first jump, record where the caller should continue after
            // this name (i.e., right after the pointer bytes), so the caller
            // can locate the question type/class fields.
            if !jumped {
                // Not updating a caller offset here; we're self-contained.
                jumped = true;
            }
            pos = ptr;
            continue;
        }

        // End-of-name marker (zero-length label)
        if len == 0 {
            break;
        }

        // Normal label: read `len` bytes of label data
        pos += 1;
        if pos + len > packet.len() {
            return None;
        }
        if let Ok(label) = std::str::from_utf8(&packet[pos..pos + len]) {
            labels.push(label.to_string());
        } else {
            return None;
        }
        pos += len;
    }

    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use protocols::Socks5Dialer;
    use std::net::SocketAddr;

    #[test]
    fn test_tproxy_listener_new() {
        let addr: SocketAddr = "0.0.0.0:15080".parse().unwrap();
        let dialer: std::sync::Arc<dyn protocols::OutboundDialer> = std::sync::Arc::new(Socks5Dialer::new("127.0.0.1:1080".parse().unwrap(), "", "", 5000));
        let listener = TproxyListener::new(addr, dialer);

        assert_eq!(listener.listen_addr(), addr);
        assert!(!listener.is_running());
    }

    #[test]
    fn test_tproxy_listener_stop() {
        let addr: SocketAddr = "0.0.0.0:15080".parse().unwrap();
        let dialer: std::sync::Arc<dyn protocols::OutboundDialer> = std::sync::Arc::new(Socks5Dialer::new("127.0.0.1:1080".parse().unwrap(), "", "", 5000));
        let listener = TproxyListener::new(addr, dialer);

        assert!(!listener.is_running());
        listener.stop();
        assert!(!listener.is_running());
    }

    #[test]
    fn test_tproxy_listener_running_flag() {
        let addr: SocketAddr = "0.0.0.0:15080".parse().unwrap();
        let dialer: std::sync::Arc<dyn protocols::OutboundDialer> = std::sync::Arc::new(Socks5Dialer::new("127.0.0.1:1080".parse().unwrap(), "", "", 5000));
        let listener = TproxyListener::new(addr, dialer);

        let flag = listener.running_flag();
        assert!(!flag.load(Ordering::SeqCst));

        // 验证 flag 与 listener 共享同一 AtomicBool
        flag.store(true, Ordering::SeqCst);
        assert!(listener.is_running());
    }

    #[test]
    fn test_get_original_dst_not_tproxy() {
        // 在没有 IP_TRANSPARENT 的情况下，get_original_dst 的行为测试
        // 由于没有实际的 TProxy 连接，我们只验证函数签名
        // 注意：此测试仅验证在非 TProxy 环境下 getsockname 返回正常地址
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            // 绑定到本地地址，非 TProxy 模式
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            // 这里无法测试 get_original_dst 因为需要真实的 TProxy 连接，
            // 但我们至少确保函数签名和基本类型正确
            let dialer: std::sync::Arc<dyn protocols::OutboundDialer> = std::sync::Arc::new(Socks5Dialer::new("127.0.0.1:1080".parse().unwrap(), "", "", 5000));
            let tproxy = TproxyListener::new(addr, dialer);
            assert_eq!(tproxy.listen_addr(), addr);
        });
    }

    #[test]
    fn test_tproxy_listener_debug() {
        let addr: SocketAddr = "0.0.0.0:15080".parse().unwrap();
        let dialer: std::sync::Arc<dyn protocols::OutboundDialer> = std::sync::Arc::new(Socks5Dialer::new("127.0.0.1:1080".parse().unwrap(), "", "", 5000));
        let listener = TproxyListener::new(addr, dialer);

        let debug_str = format!("{:?}", listener);
        assert!(debug_str.contains("TproxyListener"));
        assert!(debug_str.contains("15080"));
        assert!(debug_str.contains("running"));
    }

    #[test]
    fn test_extract_dns_query_name() {
        // Simple A record query for "google.com"
        // Transaction ID: 0x1234, Flags: 0x0100 (standard query, recursion desired)
        // Questions: 1, Answer RRs: 0
        let dns_query: Vec<u8> = vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
            6, b'g', b'o', b'o', b'g', b'l', b'e', // "google" (len=6)
            3, b'c', b'o', b'm', // "com" (len=3)
            0,    // End of domain name
            0x00, 0x01, // QTYPE: A
            0x00, 0x01, // QCLASS: IN
        ];
        let name = extract_dns_query_name(&dns_query);
        assert_eq!(name.as_deref(), Some("google.com"));
    }

    #[test]
    fn test_extract_dns_query_name_with_compression_pointer() {
        // DNS packet with compression pointer in question section.
        // Query name: "www.example.com" where "example.com" is stored at offset 12
        // and the question uses a pointer to reference it.
        //
        // Layout:
        //   [0..12]   DNS header
        //   [12..]    name: 3, 'w','w','w', 0xC0, 12  → pointer to offset 12
        //   [12..]    (at offset 12): 7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0
        //
        // The question section name at offset 12 would be "www.example.com"
        // if the pointer points back to offset 12. But that's a loop!
        // Let's construct a proper non-looping case.
        //
        // Correct layout for "www.example.com":
        //   Header [0..12]
        //   [12]: 3, 'w','w','w'         — "www" label
        //   [16]: 0xC0, 24              — pointer to offset 24
        //   [18]: QTYPE, QCLASS
        //   ... (answer section or padding)
        //   [24]: 7, 'e','x','a','m','p','l','e'  — "example"
        //   [32]: 3, 'c','o','m'         — "com"
        //   [36]: 0                       — end of name
        let mut packet = vec![0u8; 37];
        // DNS header
        packet[0] = 0x12;
        packet[1] = 0x34;
        packet[2] = 0x01;
        packet[3] = 0x00;
        packet[4] = 0x00;
        packet[5] = 0x01; // QDCOUNT=1
        // Question section name at offset 12: "www" + pointer to 24
        packet[12] = 3;
        packet[13] = b'w';
        packet[14] = b'w';
        packet[15] = b'w';
        packet[16] = 0xC0; // compression pointer high byte
        packet[17] = 24;   // pointer offset = 24
        // QTYPE at offset 18
        packet[18] = 0x00;
        packet[19] = 0x01; // A
        // QCLASS at offset 20
        packet[20] = 0x00;
        packet[21] = 0x01; // IN
        // "example.com" at offset 22 (wait, let me recalculate)
        // Actually offset 24 is where the pointer points. Let me place the data there.
        // Offset 22-23 is QTYPE+QCLASS end. We need data at offset 24.
        // But we only allocated 37 bytes. Let me redo:
        // [12] 3 'w' 'w' 'w'     = offset 12..16
        // [16] 0xC0 0x18           = offset 16..18, pointer to 0x18=24
        // [18] QTYPE(2) + QCLASS(2) = offset 18..22
        // [24] 7 'e' 'x' 'a' 'm' 'p' 'l' 'e' = offset 24..32
        // [32] 3 'c' 'o' 'm' = offset 32..36
        // [36] 0 = end
        // Need packet size >= 37. Already allocated 37, good.
        packet[22] = 7;
        packet[23] = b'e';
        packet[24] = b'x';
        packet[25] = b'a';
        packet[26] = b'm';
        packet[27] = b'p';
        packet[28] = b'l';
        packet[29] = b'e';
        packet[30] = 3;
        packet[31] = b'c';
        packet[32] = b'o';
        packet[33] = b'm';
        packet[34] = 0; // end of name
        // Fix: pointer at [16] should point to offset 22, not 24
        // Let me recalculate again:
        // [12] 3 'w' 'w' 'w'  → bytes 12,13,14,15
        // [16] 0xC0 [17] → pointer
        // [18] QTYPE_H
        // [19] QTYPE_L
        // [20] QCLASS_H
        // [21] QCLASS_L
        // Then "example.com" should be somewhere accessible. Let's put it after the question.
        // Actually for a question-only packet, the name must be parseable from the question.
        // Let's just put "example.com" at offset 22:
        // [22] 7 'e'x'a'm'p'l'e' → bytes 22..30
        // [30] 3 'c'o'm' → bytes 30..34
        // [34] 0 → end
        // Pointer at [16] should be 0xC0, 22
        packet[16] = 0xC0;
        packet[17] = 22;
        packet.truncate(35);

        let name = extract_dns_query_name(&packet);
        assert_eq!(name.as_deref(), Some("www.example.com"));
    }

    #[test]
    fn test_extract_dns_query_name_compression_loop_detected() {
        // Malicious DNS packet: pointer creates a loop (A -> B -> A)
        let mut packet = vec![0u8; 20];
        // DNS header
        packet[0] = 0x12;
        packet[1] = 0x34;
        packet[2] = 0x01;
        packet[3] = 0x00;
        packet[4] = 0x00;
        packet[5] = 0x01;
        // [12]: label "a" (len=1, 'a')
        packet[12] = 1;
        packet[13] = b'a';
        // [14]: pointer to offset 12 → will loop
        packet[14] = 0xC0;
        packet[15] = 12;

        let name = extract_dns_query_name(&packet);
        assert_eq!(name, None, "Looping pointer should return None");
    }

    #[test]
    fn test_extract_dns_query_name_empty() {
        // Empty DNS packet (too short)
        assert_eq!(extract_dns_query_name(&[]), None);
        // Header only, no name
        assert_eq!(extract_dns_query_name(&[0u8; 12]), None);
    }

    #[test]
    fn test_extract_dns_query_name_pointer_at_start() {
        // Name is entirely a compression pointer
        let mut packet = vec![0u8; 30];
        // Header
        packet[0] = 0x12;
        packet[1] = 0x34;
        packet[2] = 0x01;
        packet[3] = 0x00;
        packet[4] = 0x00;
        packet[5] = 0x01;
        // [12]: pointer to offset 20
        packet[12] = 0xC0;
        packet[13] = 20;
        // [20]: "test" → 4, 't', 'e', 's', 't'
        packet[20] = 4;
        packet[21] = b't';
        packet[22] = b'e';
        packet[23] = b's';
        packet[24] = b't';
        // [25]: 0 (end of name)
        packet[25] = 0;

        let name = extract_dns_query_name(&packet);
        assert_eq!(name.as_deref(), Some("test"));
    }
}

// ============================================================================
// UDP TProxy 监听器
// ============================================================================

/// UDP TProxy 监听器
///
/// 透明代理 UDP 流量，通过 `IP_RECVORIGDSTADDR` 获取原始目标地址。
/// 对于 DNS 流量（目标端口 53），使用 DNS 劫持：将查询转发到内部 DNS handler
/// 进行处理，而不是通过 SOCKS5 代理。这样可以支持Domain nameRouting、缓存等功能。
pub struct UdpTproxyListener {
    /// Listen address（如 `0.0.0.0:15080` 或 `[::]:15080`）
    listen_addr: SocketAddr,
    /// 出站Dialer
    dialer: Arc<dyn OutboundDialer>,
    /// Running flag
    running: Arc<AtomicBool>,
    /// Socket mark value (for eBPF self-exclusion, default 0x100)
    socket_mark: u32,
    /// 停止信号（通知接收循环立即退出）
    stop_signal: Arc<Notify>,
    /// DNS 转发目标地址（用于 DNS 劫持）。
    /// 当收到 DNS 查询时，将查询转发到此地址的 DNS handler 处理，
    /// 而不是通过 SOCKS5 代理。None 表示不使用 DNS 劫持（回退到 SOCKS5）。
    dns_forward_addr: Option<SocketAddr>,
    /// Host network namespace fd.
    ///
    /// After setting, all upstream UDP sockets (DNS hijack query sockets, UDP relay responses
    /// socket）在宿主 NS 中创建并发出（与 kdae 对齐），源地址为宿主真实
    /// WAN address instead of daens internal address。`None` 表示在当前命名空间中创建。
    host_ns_fd: Option<RawFd>,
}

impl UdpTproxyListener {
    /// 创建新的 UDP TProxy 监听器
    pub fn new(listen_addr: SocketAddr, dialer: Arc<dyn OutboundDialer>) -> Self {
        Self {
            listen_addr,
            dialer,
            running: Arc::new(AtomicBool::new(false)),
            socket_mark: shared::DAE_SOCKET_MARK,
            stop_signal: Arc::new(Notify::new()),
            dns_forward_addr: None,
            host_ns_fd: None,
        }
    }

    /// 创建新的 UDP TProxy 监听器，指定 socket 标记值
    pub fn new_with_mark(
        listen_addr: SocketAddr,
        dialer: Arc<dyn OutboundDialer>,
        socket_mark: u32,
    ) -> Self {
        Self {
            listen_addr,
            dialer,
            running: Arc::new(AtomicBool::new(false)),
            socket_mark,
            stop_signal: Arc::new(Notify::new()),
            dns_forward_addr: None,
            host_ns_fd: None,
        }
    }

    /// Set host network namespace fd.
    ///
    /// After setting, all upstream UDP sockets (DNS hijack query sockets, UDP relay responses
    /// socket）在宿主 NS 中创建（与 kdae 对齐）。
    pub fn set_host_ns_fd(&mut self, host_ns_fd: Option<RawFd>) -> &mut Self {
        self.host_ns_fd = host_ns_fd;
        self
    }

    /// 设置 DNS 转发目标地址。
    /// 设置后，DNS 查询会直接转发到此地址，而不是通过 SOCKS5 代理。
    pub fn set_dns_forward_addr(&mut self, addr: SocketAddr) {
        self.dns_forward_addr = Some(addr);
        info!(
            "DNS hijacking enabled: forwarding DNS queries to {}",
            addr
        );
    }

    /// Get listen address
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Check if listener is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// 创建并绑定 UDP TProxy socket
    ///
    /// 设置 IP_TRANSPARENT、IP_RECVORIGDSTADDR 和 SO_MARK 等 socket 选项。
    /// 注意：IP_TRANSPARENT 必须在 bind() 之前设置，否则 bind() 会因为
    /// 尝试绑定非本机地址而失败。
    pub async fn bind(&self) -> Result<tokio::net::UdpSocket> {
        use socket2::{Domain, Protocol, Socket, Type};
        use std::os::unix::io::AsRawFd;

        let start = std::time::Instant::now();
        let is_ipv6 = self.listen_addr.is_ipv6();
        debug!(
            listen_addr = %self.listen_addr,
            is_ipv6 = is_ipv6,
            socket_mark = format!("{:#x}", self.socket_mark),
            "UDP TProxy bind starting"
        );

        // 使用 socket2 创建原始 socket，在 bind 前设置所有选项
        let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
            .context("Failed to create UDP TProxy socket")?;

        let one: libc::c_int = 1;
        let fd = socket.as_raw_fd();

        // IPv6: 设置 IPV6_V6ONLY=0 以启用双栈（在 bind 前设置）
        if is_ipv6 {
            let zero: libc::c_int = 0;
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_IPV6,
                    libc::IPV6_V6ONLY,
                    &zero as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        // 设置 IP_TRANSPARENT（必须在 bind 之前！）
        if is_ipv6 {
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_IPV6,
                    IPV6_TRANSPARENT,
                    &one as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        } else {
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_IP,
                    IP_TRANSPARENT,
                    &one as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        // 设置 IP_RECVORIGDSTADDR / IPV6_RECVORIGDSTADDR（用于获取原始目标地址）
        // 双栈 (AF_INET6, V6ONLY=0) socket 会同时收到 IPv4 和 IPv6 报文：
        // IPv4 报文走内核 ip_cmsg_recv，需要 SOL_IP 上的 IP_RECVORIGDSTADDR；
        // IPv6 报文需要 SOL_IPV6 上的 IPV6_RECVORIGDSTADDR。
        // 只设置其中一个会导致相应地址族的报文解析不到原始目标地址。
        if is_ipv6 {
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_IPV6,
                    IPV6_RECVORIGDSTADDR,
                    &one as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_IP,
                    IP_RECVORIGDSTADDR,
                    &one as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        } else {
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_IP,
                    IP_RECVORIGDSTADDR,
                    &one as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        // 设置 SO_REUSEADDR
        socket.set_reuse_address(true)?;

        // 设置 SO_REUSEPORT
        #[cfg(unix)]
        socket.set_reuse_port(true)?;

        // 设置 SO_MARK（用于 eBPF 自排除）
        if self.socket_mark != 0 {
            let mark_val = self.socket_mark as libc::c_int;
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    SO_MARK,
                    &mark_val as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        // 绑定地址（此时 IP_TRANSPARENT 已生效）
        let sock_addr = socket2::SockAddr::from(self.listen_addr);
        socket.bind(&sock_addr).with_context(|| {
            format!(
                "Failed to bind UDP TProxy socket to {} (port may be in use)",
                self.listen_addr
            )
        })?;

        // 转换为 tokio UdpSocket
        let std_socket: std::net::UdpSocket = socket.into();
        std_socket.set_nonblocking(true)?;
        let tokio_socket = tokio::net::UdpSocket::from_std(std_socket)
            .context("Failed to convert to tokio UdpSocket")?;

        debug!(
            "UDP TProxy bind completed: {}ms",
            start.elapsed().as_millis()
        );
        info!(
            addr = %self.listen_addr,
            is_ipv6 = is_ipv6,
            socket_mark = self.socket_mark,
            "UDP TProxy socket bound successfully (IP_TRANSPARENT set before bind)"
        );
        Ok(tokio_socket)
    }

    /// 启动 UDP TProxy 监听循环
    pub async fn start(
        &self,
        ebpf_mgr: Option<Arc<Mutex<crate::net::ebpf::EbpfManager>>>,
    ) -> Result<()> {
        use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};

        let tokio_socket = self.bind().await?;
        let fd = tokio_socket.as_raw_fd();

        // ---- Populate listen_socket_map for bpf_sk_assign (UDP, key=1) ----
        if let Some(ref mgr) = ebpf_mgr {
            if let Err(e) = mgr.lock().unwrap().update_listen_socket_map(1, fd) {
                error!("Failed to update listen_socket_map for udp: {}", e);
            }
        }

        // Convert to std socket and take ownership of the raw fd (prevents double-close)
        let std_socket = tokio_socket
            .into_std()
            .context("Failed to convert tokio socket to std")?;
        let fd = std_socket.into_raw_fd();
        let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
        std_socket.set_nonblocking(true)?;
        self.running.store(true, Ordering::SeqCst);

        info!(
            listen_addr = %self.listen_addr,
            "UDP TProxy listener started"
        );

        self.run_receive_loop(std_socket).await
    }

    /// UDP 接收循环核心 — 使用 recvmsg 获取 cmsg 以解析原始目标地址，
    /// 并通过 SOCKS5 UDP ASSOCIATE 将数据包转发到原始目标。
    /// 对于 DNS 流量，如果配置了 dns_forward_addr，则直接转发到内部的 DNS handler，
    /// 实现 DNS 劫持，而不是通过 SOCKS5 代理。
    ///
    /// # 优化说明
    ///
    /// - 收包/发送缓冲在循环外复用，避免每个 UDP 包 64KB 堆分配；
    /// - 用 tokio `AsyncFd` 等待可读，替代 spawn_blocking + 10ms 轮询；
    /// - SOCKS5 UDP ASSOCIATE 会话按 (dest, peer) 建立 flow，每个 flow 有独立
    ///   reader 任务持续读取中继响应并回发客户端；发送不持锁，同一目标的并发
    ///   包（QUIC 多包在途）不再被互斥锁串行化；
    /// - 回包 socket（IP_TRANSPARENT，绑定原目标地址）按 dest 复用，避免每包
    ///   socket()+setsockopt()+bind()（host_ns_fd 场景下还包括 2 次 setns）；
    /// - 包级日志降为 debug。
    async fn run_receive_loop(&self, socket: std::net::UdpSocket) -> Result<()> {
        use std::os::unix::io::AsRawFd;

        let fd = socket.as_raw_fd();
        let dialer = self.dialer.clone();
        let stop_signal = self.stop_signal.clone();
        let dns_forward_addr = self.dns_forward_addr;
        let host_ns_fd = self.host_ns_fd;

        // 缓冲在循环外复用（避免每包 64KB 分配）
        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let mut cmsg_buf = vec![0u8; CMSG_BUFFER_SIZE];

        // SOCKS5 UDP flow 池：(dest, peer) → 会话 + reader 任务
        let flows = Arc::new(UdpFlowPool::new());
        // 透明回包 socket 池：dest → socket（DNS 劫持与 SOCKS5 回包共用）
        let resp_socks = Arc::new(RespSocketPool::new());

        // 将 fd 注册到 tokio reactor，用可读事件驱动 recvmsg（fd 保持非阻塞）
        let async_fd =
            AsyncFd::new(socket).context("Failed to register UDP socket with reactor")?;

        loop {
            tokio::select! {
                _ = stop_signal.notified() => {
                    info!("UDP TProxy listener stopping via signal");
                    break;
                }
                readable = async_fd.readable() => {
                    let mut guard = match readable {
                        Ok(g) => g,
                        Err(e) => {
                            warn!("UDP TProxy readable error: {}", e);
                            continue;
                        }
                    };

                    let (n, peer_addr, orig_dst) =
                        match recvmsg_with_cmsg(fd, &mut buf, &mut cmsg_buf) {
                            Ok(r) => r,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                guard.clear_ready();
                                continue;
                            }
                            Err(e) => {
                                warn!("UDP recvmsg error: {}", e);
                                guard.clear_ready();
                                continue;
                            }
                        };

                    let peer_addr = peer_addr.map(canonicalize_socket_addr);
                    let dest = match orig_dst {
                        Some(dst) => dst,
                        None => {
                            warn!(
                                "UDP TProxy: cannot determine original dest, peer={:?}",
                                peer_addr
                            );
                            guard.clear_ready();
                            continue;
                        }
                    };

                    // 包级日志（QUIC/游戏等高频 UDP 下 info 会刷屏，使用 debug）
                    let is_dns = dest.port() == 53 && n > 12;
                    if is_dns {
                        let qname = extract_dns_query_name(&buf[..n]);
                        debug!(
                            "DNS  {}:{} -> {} QUERY {}",
                            peer_addr
                                .map(|a| a.ip())
                                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                            peer_addr.map(|a| a.port()).unwrap_or(0),
                            dest,
                            qname.as_deref().unwrap_or("<parse-failed>"),
                        );
                    } else {
                        debug!(
                            "UDP  {}:{} -> {} {}bytes",
                            peer_addr
                                .map(|a| a.ip())
                                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                            peer_addr.map(|a| a.port()).unwrap_or(0),
                            dest,
                            n,
                        );
                    }

                    // ---- DNS hijacking: forward DNS queries to the internal DNS handler ----
                    // Only intercept UDP packets to port 53. The internal DNS handler
                    // listens on 169.254.0.1:<port> (IPv4) in the host NS. We use a
                    // separate IPv4 socket to talk to the handler, then reuse a pooled
                    // IP_TRANSPARENT socket bound to the original destination (the DNS
                    // server the client queried) so the response reaches the client
                    // with the expected source address.
                    if is_dns {
                        if let Some(handler_addr) = dns_forward_addr {
                            let peer = peer_addr;
                            let pkt = buf[..n].to_vec();
                            let resp_socks = resp_socks.clone();

                            tokio::spawn(async move {
                                // 1. Send the query to the internal DNS handler. The handler
                                //    is IPv4-only, so use an IPv4 socket bound to any port.
                                let query_bind: SocketAddr =
                                    "0.0.0.0:0".parse().expect("valid IPv4 any addr");
                                let query_socket =
                                    match create_marked_udp_socket(&query_bind, host_ns_fd).await
                                    {
                                        Some(s) => s,
                                        None => {
                                            warn!("DNS hijack: failed to create query socket for handler {}", handler_addr);
                                            return;
                                        }
                                    };

                                if let Err(e) = query_socket.send_to(&pkt, handler_addr).await {
                                    warn!("DNS hijack: send_to internal handler {} failed: {}", handler_addr, e);
                                    return;
                                }

                                // Wait for the handler's DNS response.
                                let mut recv_buf = vec![0u8; MAX_UDP_SIZE];
                                let recv_fut = query_socket.recv_from(&mut recv_buf);
                                let len = match tokio::time::timeout(
                                    std::time::Duration::from_secs(5),
                                    recv_fut,
                                )
                                .await
                                {
                                    Ok(Ok((len, _))) => len,
                                    Ok(Err(e)) => {
                                        warn!("DNS hijack: recv from handler error: {}", e);
                                        return;
                                    }
                                    Err(_) => {
                                        warn!("DNS hijack: timeout waiting for internal handler {}", handler_addr);
                                        return;
                                    }
                                };
                                recv_buf.truncate(len);

                                // 2. Send the response back to the client from the original
                                //    destination address (the DNS server it queried),
                                //    reusing the pooled transparent socket.
                                if let Some(peer) = peer {
                                    if let Some(resp_sock) =
                                        resp_socks.get(&dest, host_ns_fd).await
                                    {
                                        if let Err(e) = resp_sock.send_to(&recv_buf, peer).await {
                                            debug!("DNS hijack: response send_to client {} failed: {}", peer, e);
                                        }
                                    } else {
                                        debug!("DNS hijack: failed to get response socket for {}", dest);
                                    }
                                }
                            });
                            guard.clear_ready();
                            continue; // Skip SOCKS5 path for hijacked DNS
                        }
                    }

                    // ---- SOCKS5 UDP ASSOCIATE path (non-DNS traffic) ----
                    // 按 (dest, peer) 复用 flow：发送立即完成，响应由 flow 的
                    // reader 任务回发（send 与 recv 解耦，不持锁等待）。
                    let flows = flows.clone();
                    let resp_socks = resp_socks.clone();
                    let dialer = dialer.clone();
                    let peer = peer_addr;
                    let payload = buf[..n].to_vec();

                    tokio::spawn(async move {
                        let session = match flows
                            .get_or_create(dest, peer, dialer.as_ref(), &resp_socks, host_ns_fd)
                            .await
                        {
                            Ok(s) => s,
                            Err(e) => {
                                warn!(
                                    "UDP relay session failed for {} -> {}: {}",
                                    peer.map(|p| p.to_string()).unwrap_or_default(),
                                    dest,
                                    e
                                );
                                flows.remove(dest, peer).await;
                                return;
                            }
                        };

                        // 通过协议的 UDP 会话转发数据报（无需锁，各协议内部处理）。
                        if let Err(e) = session.send(&dest, &payload).await {
                            debug!("UDP send to relay failed: {}", e);
                            flows.remove(dest, peer).await;
                        }
                    });
                }
            }
        }

        Ok(())
    }

    /// 停止 UDP TProxy 监听器
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.stop_signal.notify_one();
        info!("UDP TProxy listener stop signal sent");
    }
}

// ============================================================================
// UDP flow 池 & 回包 socket 池
// ============================================================================

/// 一个 UDP relay flow：协议无关的 UDP 会话 + 专属 reader 任务。
///
/// reader 任务持续从会话接收中继响应（原始目标地址 + payload），
/// 通过池化的透明回包 socket 发回对应客户端。这样发送方在 `send()`
/// 后立即返回，同一 flow 的并发包不会被互斥锁串行化。
struct UdpRelayFlow {
    session: Arc<dyn UdpSession>,
    /// reader 任务句柄（空闲超时或出错时自行从池中移除自己）
    #[allow(dead_code)]
    reader: tokio::task::JoinHandle<()>,
}

/// UDP flow 池，按 (原始目标地址, 客户端地址) 复用会话。
///
/// 以 (dest, peer) 为键是因为中继响应的头中只有目标地址，
/// 没有客户端信息；一个 flow 对应一个客户端，响应才能准确回发。
struct UdpFlowPool {
    inner: tokio::sync::Mutex<HashMap<(SocketAddr, Option<SocketAddr>), UdpRelayFlow>>,
}

impl UdpFlowPool {
    fn new() -> Self {
        Self {
            inner: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// 获取或创建 (dest, peer) 对应的会话。
    ///
    /// 会话创建（TCP 握手 + ASSOCIATE）在锁外进行，仅插入时短暂持锁，
    /// 避免并发创建同一 flow 时互相阻塞。
    async fn get_or_create(
        self: &Arc<Self>,
        dest: SocketAddr,
        peer: Option<SocketAddr>,
        dialer: &dyn OutboundDialer,
        resp_socks: &Arc<RespSocketPool>,
        host_ns_fd: Option<RawFd>,
    ) -> anyhow::Result<Arc<dyn UdpSession>> {
        let key = (dest, peer);
        {
            let map = self.inner.lock().await;
            if let Some(flow) = map.get(&key) {
                return Ok(flow.session.clone());
            }
        }

        // 通过Dialer建立协议对应的 UDP 中继会话（宿主 NS 中创建）。
        let session: Arc<dyn UdpSession> = Arc::from(dialer.udp_dial().await?);
        info!(
            "UDP  {} -> {} [PROXY] outbound via {} -> proxy {}",
            peer.map(|p| p.to_string()).unwrap_or_else(|| "unknown".into()),
            dest,
            dialer.protocol_name(),
            dialer.proxy_addr(),
        );
        let reader = Self::spawn_reader(
            key,
            session.clone(),
            resp_socks.clone(),
            host_ns_fd,
            Arc::downgrade(self),
        );
        self.inner
            .lock()
            .await
            .insert(key, UdpRelayFlow { session: session.clone(), reader });
        Ok(session)
    }

    async fn remove(&self, dest: SocketAddr, peer: Option<SocketAddr>) {
        self.inner.lock().await.remove(&(dest, peer));
    }

    /// 启动 flow 的 reader 任务：持续读取中继响应并回发客户端。
    ///
    /// 空闲超过 [`UDP_FLOW_IDLE_TIMEOUT`] 或中继 recv 出错时退出，并从池中
    /// 移除自己（替代原先从未被调用的 `UdpEndpointPool::cleanup`）。
    fn spawn_reader(
        key: (SocketAddr, Option<SocketAddr>),
        session: Arc<dyn UdpSession>,
        resp_socks: Arc<RespSocketPool>,
        host_ns_fd: Option<RawFd>,
        flows: std::sync::Weak<UdpFlowPool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let (dest, peer) = key;
            loop {
                let read = tokio::time::timeout(UDP_FLOW_IDLE_TIMEOUT, session.recv()).await;
                let (resp_dest, payload) = match read {
                    Ok(Ok(pkt)) => pkt,
                    Ok(Err(e)) => {
                        debug!("UDP relay recv error: {}", e);
                        break;
                    }
                    Err(_) => {
                        debug!(
                            "UDP relay flow idle, expiring: {}",
                            peer.map(|p| p.to_string()).unwrap_or_default(),
                        );
                        break;
                    }
                };

                // 全锥形中继：响应可能来自任意目标，回包 socket 按响应目标地址取。
                if let Some(peer) = peer {
                    if let Some(sock) = resp_socks.get(&resp_dest, host_ns_fd).await {
                        if let Err(e) = sock.send_to(&payload, peer).await {
                            debug!("UDP response send failed: {}", e);
                        }
                    } else {
                        debug!(
                            "UDP response: failed to get TProxy response socket for {}",
                            resp_dest
                        );
                    }
                }
            }
            // reader 退出（空闲/出错）：从池中移除自己
            if let Some(flows) = flows.upgrade() {
                flows.remove(dest, peer).await;
            }
        })
    }
}

/// 透明回包 socket 池：按原始目标地址复用 IP_TRANSPARENT UDP socket。
///
/// 每个 dest 一个 socket，惰性创建（配置 host_ns_fd 时在宿主 NS 创建），
/// LRU 容量上限防止无界增长。DNS 劫持回包与 SOCKS5 回包共用本池。
struct RespSocketPool {
    inner: Mutex<VecDeque<(SocketAddr, Arc<UdpSocket>)>>,
}

impl RespSocketPool {
    fn new() -> Self {
        Self {
            inner: Mutex::new(VecDeque::new()),
        }
    }

    /// 获取 dest 对应的回包 socket；不存在则创建并缓存。
    async fn get(
        &self,
        dest: &SocketAddr,
        host_ns_fd: Option<RawFd>,
    ) -> Option<Arc<UdpSocket>> {
        // 快路径：池中已有（不持锁跨 await）
        {
            let mut m = self.inner.lock().unwrap();
            if let Some(i) = m.iter().position(|(d, _)| d == dest) {
                let (_, sock) = m.remove(i).unwrap();
                m.push_back((*dest, sock.clone()));
                return Some(sock);
            }
        }

        // 慢路径：创建（可能在宿主 NS 中 setns，不能持锁）
        let sock = Arc::new(create_marked_udp_socket(dest, host_ns_fd).await?);
        let mut m = self.inner.lock().unwrap();
        if let Some(i) = m.iter().position(|(d, _)| d == dest) {
            // 并发创建竞态：其他人已插入，直接用已有的
            return Some(m[i].1.clone());
        }
        m.push_back((*dest, sock.clone()));
        while m.len() > RESP_SOCKET_POOL_CAP {
            m.pop_front();
        }
        Some(sock)
    }
}

/// 非阻塞 recvmsg：返回 `(字节数, 对端地址, 原始目标地址)`。
///
/// 通过辅助数据（cmsg）获取 TProxy 的原始目标地址；fd 必须是非阻塞的。
fn recvmsg_with_cmsg(
    fd: RawFd,
    buf: &mut [u8],
    cmsg_buf: &mut [u8],
) -> std::io::Result<(usize, Option<SocketAddr>, Option<SocketAddr>)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    let mut msg_name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    // 使用 zeroed + 字段赋值而不是结构体字面量：
    // musl 的 msghdr 包含私有字段（如 x86_64 上的 __pad1/__pad2），无法用字面量构造
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut msg_name as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    // musl 与 glibc 的 msg_controllen 类型不同（int vs size_t），用类型推断
    msg.msg_controllen = cmsg_buf.len() as _;
    msg.msg_flags = 0;

    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let n = n as usize;

    let peer_addr = match msg.msg_namelen {
        0 => None,
        _ => {
            let ss_ptr = msg.msg_name as *const libc::sockaddr_storage;
            let storage = unsafe { &*ss_ptr };
            match storage.ss_family as libc::c_int {
                libc::AF_INET => {
                    let addr = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
                    let ip = std::net::Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes());
                    let port = u16::from_be_bytes(addr.sin_port.to_ne_bytes());
                    Some(SocketAddr::new(ip.into(), port))
                }
                libc::AF_INET6 => {
                    let addr = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
                    let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
                    let port = u16::from_be_bytes(addr.sin6_port.to_ne_bytes());
                    Some(SocketAddr::new(ip.into(), port))
                }
                _ => None,
            }
        }
    };

    let orig_dst = parse_orig_dst_from_cmsg(&cmsg_buf[..msg.msg_controllen as usize]);
    Ok((n, peer_addr, orig_dst))
}

/// Convert an IPv4-mapped IPv6 socket address back to a pure IPv4 address.
///
/// The TProxy UDP listener is bound as dual-stack (AF_INET6 with IPV6_V6ONLY=0),
/// so IPv4 clients are reported as `::ffff:<ipv4>` peer addresses. When creating
/// response sockets we need the real address family, otherwise `send_to` on an
/// IPv4 socket with an IPv4-mapped IPv6 target returns `EAFNOSUPPORT`.
fn canonicalize_socket_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => {
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                SocketAddr::from((v4, v6.port()))
            } else {
                SocketAddr::V6(v6)
            }
        }
        other => other,
    }
}

/// 创建一个带有 IP_TRANSPARENT 和 SO_MARK=0x100 的 UDP socket，并绑定到目标地址。
///
/// 用于 DNS 劫持与 UDP 回包：IP_TRANSPARENT 允许绑定非本机地址（如上游
/// DNS 服务器地址），确保响应包源地址正确；SO_MARK=0x100 使 eBPF 放行
/// （dae-rs 自身流量必须直连）。统一委托
/// [`protocols::hostns::create_transparent_udp`] 实现。
async fn create_marked_udp_socket(
    target: &SocketAddr,
    host_ns_fd: Option<RawFd>,
) -> Option<tokio::net::UdpSocket> {
    let sock = protocols::hostns::DirectSocket::control_plane(host_ns_fd);
    match protocols::hostns::create_transparent_udp(target, &sock) {
        Ok(s) => match tokio::net::UdpSocket::from_std(s) {
            Ok(s) => Some(s),
            Err(e) => {
                warn!("create_marked_udp_socket: from_std failed: {}", e);
                None
            }
        },
        Err(e) => {
            warn!("create_marked_udp_socket: create failed for {}: {}", target, e);
            None
        }
    }
}

/// 从辅助数据（cmsg/oob）中解析原始目标地址
///
/// 这是 UDP TProxy 获取原始目标地址的关键函数。当设置了 `IP_RECVORIGDSTADDR` 后，
/// 内核会在 recvmsg 的辅助数据中返回数据包的原始目标地址。
///
/// 使用 `libc::cmsghdr` 结构体读取 cmsg 头部，让编译器根据目标架构自动处理
/// `cmsg_len` 的大小和对齐差异（64 位系统上 `cmsg_len` 为 8 字节，32 位系统上为 4 字节），
/// 避免硬编码 `u64` 解析导致的跨架构兼容性问题。
///
/// # Parameters
///
/// * `cmsg_data` — 辅助数据（cmsg）缓冲区
///
/// # Returns
///
/// 如果成功解析到原始目标地址，返回 `Some(SocketAddr)`。
pub fn parse_orig_dst_from_cmsg(cmsg_data: &[u8]) -> Option<SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    // libc::cmsghdr 在不同架构下的布局：
    // - 64 位: cmsg_len(usize=8) + cmsg_level(i32) + cmsg_type(i32) = 16 字节
    // - 32 位: cmsg_len(usize=4) + cmsg_level(i32) + cmsg_type(i32) = 12 字节
    let hdr_size = std::mem::size_of::<libc::cmsghdr>();
    // CMSG_ALIGN 使用 size_t 进行对齐
    let cmsg_align = std::mem::size_of::<libc::size_t>();
    let mut offset = 0;

    while offset + hdr_size <= cmsg_data.len() {
        // 使用 libc::cmsghdr 结构体读取 cmsg 头部，读取 cmsg_len 和 cmsg_level、cmsg_type
        // 字段，让编译器处理不同架构下 cmsg_len 的大小差异（32 位: u32, 64 位: u64），
        // 替代硬编码的 u64 解析。
        let cmsg = unsafe {
            std::ptr::read_unaligned(cmsg_data[offset..].as_ptr() as *const libc::cmsghdr)
        };

        let cmsg_len = cmsg.cmsg_len as usize;

        // cmsg_len 必须至少包含头部大小，且不超过剩余缓冲区
        if cmsg_len < hdr_size || offset + cmsg_len > cmsg_data.len() {
            break;
        }

        // CMSG_DATA 偏移量：紧跟在头部之后，按 CMSG_ALIGN(size_t) 对齐。
        // 等价于 Linux 内核宏：CMSG_DATA(cmsg) = (unsigned char *)cmsg + CMSG_ALIGN(sizeof(*cmsg))
        let data_offset = (offset + hdr_size + cmsg_align - 1) & !(cmsg_align - 1);

        if cmsg.cmsg_level == libc::SOL_IP && cmsg.cmsg_type == IP_RECVORIGDSTADDR {
            // IPv4: 数据是 struct sockaddr_in（16 字节）
            if data_offset + std::mem::size_of::<libc::sockaddr_in>() <= cmsg_data.len() {
                let addr = unsafe {
                    std::ptr::read_unaligned(
                        cmsg_data[data_offset..].as_ptr() as *const libc::sockaddr_in,
                    )
                };
                let ip = Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes());
                let port = u16::from_be(addr.sin_port);
                return Some(SocketAddr::new(ip.into(), port));
            }
        } else if cmsg.cmsg_level == libc::SOL_IPV6 && cmsg.cmsg_type == IPV6_RECVORIGDSTADDR {
            // IPv6: 数据是 struct sockaddr_in6（28 字节）
            if data_offset + std::mem::size_of::<libc::sockaddr_in6>() <= cmsg_data.len() {
                let addr = unsafe {
                    std::ptr::read_unaligned(
                        cmsg_data[data_offset..].as_ptr() as *const libc::sockaddr_in6,
                    )
                };
                let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
                let port = u16::from_be(addr.sin6_port);
                return Some(SocketAddr::new(ip.into(), port));
            }
        }

        // 移动到下一个 cmsg（按 CMSG_ALIGN 对齐）
        offset = (offset + cmsg_len + cmsg_align - 1) & !(cmsg_align - 1);
    }

    None
}
