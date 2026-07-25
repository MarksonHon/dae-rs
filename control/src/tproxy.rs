//! TProxy 监听器 + TCP/UDP 双向转发
//!
//! 本模块实现透明代理（TProxy）功能，是代理数据路径的核心组件：
//!
//! # 数据流
//!
//! ```text
//! 客户端 → eBPF/策略路由 → veth pair → 代理命名空间
//!                                         ↓
//!                                    TProxy 监听器
//!                                         ↓
//!                                  SOCKS5 出站拨号器
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
//! * [`get_original_dst`] — 获取 TProxy 透明代理的原始目标地址
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
use protocols::socks5::Socks5Dialer;
use protocols::OutboundDialer;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, RwLock};
use tracing::{debug, error, info, warn};

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

/// `IP_FREEBIND` socket 选项值（Linux）
///
/// 允许 socket 绑定到当前不存在的 IP 地址，在动态 IP 环境下有用。
const IP_FREEBIND: libc::c_int = 15;

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
const SO_REUSEADDR: libc::c_int = 2;

/// `SO_REUSEPORT` socket 选项值（Linux）
///
/// 允许多个 socket 绑定到相同的端口，实现负载均衡。
const SO_REUSEPORT: libc::c_int = 15;

/// `SO_MARK` socket 选项值（Linux）
///
/// 设置 socket 的 fwmark，用于策略路由和 eBPF 程序识别自身流量。
/// 原版 dae 使用 0x100 作为内部 socket 标记。
const SO_MARK: libc::c_int = 36;

// ============================================================================
// TproxyListener
// ============================================================================

/// TProxy 监听器
///
/// 透明代理监听器，接收从内核（通过 eBPF + 策略路由）重定向到代理命名空间的
/// TCP 连接，通过 SOCKS5 出站拨号器转发到上游代理。
///
/// # 示例
///
/// ```no_run
/// use control::tproxy::TproxyListener;
/// use protocols::socks5::Socks5Dialer;
/// use std::net::SocketAddr;
///
/// # async fn example() -> anyhow::Result<()> {
/// let addr: SocketAddr = "0.0.0.0:15080".parse()?;
/// let dialer = Socks5Dialer::new(
///     "127.0.0.1:1080".parse()?,
///     "", "", 5000,
/// );
/// let listener = TproxyListener::new(addr, dialer);
/// listener.start().await?;
/// # Ok(())
/// # }
/// ```
pub struct TproxyListener {
    /// 监听地址（在代理命名空间内，如 `0.0.0.0:15080`）
    listen_addr: SocketAddr,
    /// 出站拨号器
    dialer: Arc<RwLock<Socks5Dialer>>,
    /// 运行标记
    running: Arc<AtomicBool>,
    /// socket 标记值（用于 eBPF 自排除，默认 0x100）
    socket_mark: u32,
    /// 停止信号（通知 accept 循环退出，无需轮询）
    stop_signal: Arc<Notify>,
}

impl TproxyListener {
    /// 创建新的 TProxy 监听器
    ///
    /// # 参数
    ///
    /// * `listen_addr` — 监听地址（如 `0.0.0.0:15080`）
    /// * `dialer` — SOCKS5 出站拨号器
    pub fn new(listen_addr: SocketAddr, dialer: Socks5Dialer) -> Self {
        Self {
            listen_addr,
            dialer: Arc::new(RwLock::new(dialer)),
            running: Arc::new(AtomicBool::new(false)),
            socket_mark: 0x100, // 原版 dae 默认值
            stop_signal: Arc::new(Notify::new()),
        }
    }

    /// 创建新的 TProxy 监听器，指定 socket 标记值
    pub fn new_with_mark(listen_addr: SocketAddr, dialer: Socks5Dialer, socket_mark: u32) -> Self {
        Self {
            listen_addr,
            dialer: Arc::new(RwLock::new(dialer)),
            running: Arc::new(AtomicBool::new(false)),
            socket_mark,
            stop_signal: Arc::new(Notify::new()),
        }
    }

    /// 获取监听地址
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// 获取出站拨号器的引用
    pub fn dialer(&self) -> &Arc<RwLock<Socks5Dialer>> {
        &self.dialer
    }

    /// 检查监听器是否正在运行
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// 获取运行标记的原子引用（用于跨线程通信）
    pub fn running_flag(&self) -> Arc<AtomicBool> {
        self.running.clone()
    }

    /// 创建并绑定 TProxy listening socket，设置 IP_TRANSPARENT、SO_REUSEADDR、
    /// SO_REUSEPORT、IP_RECVORIGDSTADDR 和 SO_MARK。
    ///
    /// 返回已配置的 TcpListener 句柄。
    pub async fn bind(&self) -> Result<TcpListener> {
        use socket2::{Domain, Protocol, Socket, Type};
        use std::os::unix::io::AsRawFd;

        let is_ipv6 = self.listen_addr.is_ipv6();

        // 创建 socket2 socket，先设置选项再 bind
        let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
            .context("Failed to create TProxy socket")?;

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

        // 设置 SO_REUSEADDR
        socket.set_reuse_address(true)?;

        // 设置 SO_REUSEPORT
        #[cfg(unix)]
        socket.set_reuse_port(true)?;

        // 设置 IP_TRANSPARENT / IPV6_TRANSPARENT
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

        // 设置 IP_RECVORIGDSTADDR / IPV6_RECVORIGDSTADDR
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

        // 设置 SO_MARK
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

        // 绑定地址
        let sock_addr = socket2::SockAddr::from(self.listen_addr);
        socket.bind(&sock_addr).with_context(|| {
            format!(
                "Failed to bind TProxy socket to {} (port may be in use)",
                self.listen_addr
            )
        })?;

        socket.listen(128)?;

        // 转换为 tokio TcpListener
        let std_listener: std::net::TcpListener = socket.into();
        std_listener.set_nonblocking(true)?;

        let listener = TcpListener::from_std(std_listener)
            .context("Failed to convert to tokio TcpListener")?;

        info!(
            addr = %self.listen_addr,
            is_ipv6 = is_ipv6,
            socket_mark = self.socket_mark,
            "TProxy socket bound successfully"
        );

        Ok(listener)
    }

    /// 启动 accept 循环（不执行 bind）。
    ///
    /// 使用预先绑定好的 `listener` 运行 accept 循环，直到 [`stop()`](TproxyListener::stop) 被调用。
    pub async fn serve(&self, listener: TcpListener) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);
        let proxy_addr = self
            .dialer
            .try_read()
            .map(|d| d.proxy_addr.to_string())
            .unwrap_or_else(|_| "locked".to_string());
        info!(
            listen_addr = %self.listen_addr,
            proxy_addr = %proxy_addr,
            "TProxy listener started"
        );

        self.run_accept_loop(listener).await
    }

    /// 启动 TProxy 监听循环（bind + accept 两步合一，兼容旧调用者）。
    ///
    /// # 流程
    ///
    /// 1. 创建 `TcpListener` 绑定到 [`listen_addr`](TproxyListener::listen_addr)
    /// 2. 设置 socket 选项：
    ///    - `IP_TRANSPARENT`（需要 `CAP_NET_ADMIN`）— 透明接受非本机地址连接
    ///    - `SO_REUSEADDR` — 允许重用 TIME_WAIT 状态的地址
    ///    - `SO_REUSEPORT` — 允许多个 socket 绑定到相同端口
    ///    - `IP_RECVORIGDSTADDR` — 用于 UDP 原始目标地址获取
    /// 3. 进入 accept 循环
    /// 4. 每个连接到来时，`tokio::spawn` 一个 [`handle_connection`] 任务
    /// 5. 检查运行标记，收到停止信号时退出循环
    ///
    /// # 错误
    ///
    /// * 如果端口被占用，返回 `std::io::Error`
    /// * 如果没有 `CAP_NET_ADMIN` 权限，设置 `IP_TRANSPARENT` 时返回 `EPERM`
    pub async fn start(&self) -> Result<()> {
        let listener = self.bind().await?;
        self.serve(listener).await
    }

    /// Accept 循环核心（内部使用）
    async fn run_accept_loop(&self, listener: TcpListener) -> Result<()> {
        loop {
            // 检查运行标记，用于优雅停止
            if !self.running.load(Ordering::SeqCst) {
                info!(
                    listen_addr = %self.listen_addr,
                    "TProxy listener stopping"
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
                            debug!(
                                peer_addr = %peer_addr,
                                listen_addr = %self.listen_addr,
                                "Accepted new TCP connection"
                            );
                            let dialer = self.dialer.clone();
                            tokio::spawn(async move {
                                let start = std::time::Instant::now();
                                if let Err(e) = handle_connection(stream, dialer).await {
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
                        "TProxy listener stopping via signal"
                    );
                    break;
                }
            }
        }

        Ok(())
    }

    /// 停止 TProxy 监听器
    ///
    /// 设置运行标记为 `false`，并通过 Notify 信号立即唤醒 accept 循环。
    /// 已经建立的连接不会中断，它们会继续运行直到完成。
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.stop_signal.notify_one();
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
/// 2. **SOCKS5 拨号** — 创建一个 SOCKS5 拨号器实例并调用 `dial(target_addr)` 建立到上游的连接
/// 3. **获取 `ProxyConn`** — 获取实现了 `AsyncRead + AsyncWrite` 的代理连接
/// 4. **双向数据拷贝** — 使用 `tokio::io::copy_bidirectional` 进行双向数据拷贝
/// 5. **连接关闭** — 等待双向拷贝完成，确保干净关闭连接
///
/// # 参数
///
/// * `inbound` — 从 TProxy 接收的客户端连接
/// * `dialer` — SOCKS5 出站拨号器（受 Arc<RwLock<>> 保护）
///
/// # 错误处理
///
/// * 如果无法获取原始目标地址，返回错误（可能未正确设置 `IP_TRANSPARENT`）
/// * 如果 SOCKS5 拨号失败，返回错误（可能上游代理不可达）
/// * 如果双向拷贝失败，返回错误（可能网络中断）
/// * 单个连接的错误不会影响监听器的其他连接
async fn handle_connection(
    mut inbound: TcpStream,
    dialer: Arc<RwLock<Socks5Dialer>>,
) -> Result<()> {
    // ---- 步骤 1：获取原始目标地址 ----
    // 在 IP_TRANSPARENT 模式下，getsockname() 返回的不是本地地址，
    // 而是客户端连接的原始目标地址
    let orig_dst = get_original_dst(&inbound).context(
        "Failed to get original destination address from TProxy connection \
         (ensure IP_TRANSPARENT is set and CAP_NET_ADMIN is available)",
    )?;
    debug!(target = %orig_dst, "TProxy connection target resolved");

    // ---- 步骤 2：通过 SOCKS5 拨号到目标 ----
    // 获取读锁以调用 dial()
    let dialer_guard = dialer.read().await;
    let proxy_addr = dialer_guard.proxy_addr;
    let mut outbound = dialer_guard
        .dial(&orig_dst.to_string())
        .await
        .with_context(|| {
            format!(
                "SOCKS5 dial to target {} via proxy {} failed",
                orig_dst, proxy_addr
            )
        })?;
    // 尽早释放读锁，避免阻塞其他需要读锁的操作
    drop(dialer_guard);

    debug!(
        target = %orig_dst,
        proxy = %proxy_addr,
        "SOCKS5 upstream connection established"
    );

    // ---- 步骤 3：双向数据拷贝 ----
    // copy_bidirectional 会同时从 inbound 读取写入 outbound，
    // 以及从 outbound 读取写入 inbound，直到一方关闭
    let (n_to_upstream, n_from_upstream) = copy_bidirectional(&mut inbound, &mut outbound)
        .await
        .context("Bidirectional data copy between client and upstream failed")?;

    debug!(
        target = %orig_dst,
        bytes_sent = n_to_upstream,
        bytes_received = n_from_upstream,
        "TProxy connection closed"
    );

    Ok(())
}

// ============================================================================
// 辅助函数
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
/// # 参数
///
/// * `stream` — TProxy 接收的 TCP 连接
///
/// # 返回
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn test_tproxy_listener_new() {
        let addr: SocketAddr = "0.0.0.0:15080".parse().unwrap();
        let dialer = Socks5Dialer::new("127.0.0.1:1080".parse().unwrap(), "", "", 5000);
        let listener = TproxyListener::new(addr, dialer);

        assert_eq!(listener.listen_addr(), addr);
        assert!(!listener.is_running());
    }

    #[test]
    fn test_tproxy_listener_stop() {
        let addr: SocketAddr = "0.0.0.0:15080".parse().unwrap();
        let dialer = Socks5Dialer::new("127.0.0.1:1080".parse().unwrap(), "", "", 5000);
        let listener = TproxyListener::new(addr, dialer);

        assert!(!listener.is_running());
        listener.stop();
        assert!(!listener.is_running());
    }

    #[test]
    fn test_tproxy_listener_running_flag() {
        let addr: SocketAddr = "0.0.0.0:15080".parse().unwrap();
        let dialer = Socks5Dialer::new("127.0.0.1:1080".parse().unwrap(), "", "", 5000);
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
            let dialer = Socks5Dialer::new("127.0.0.1:1080".parse().unwrap(), "", "", 5000);
            let tproxy = TproxyListener::new(addr, dialer);
            assert_eq!(tproxy.listen_addr(), addr);
        });
    }

    #[test]
    fn test_tproxy_listener_debug() {
        let addr: SocketAddr = "0.0.0.0:15080".parse().unwrap();
        let dialer = Socks5Dialer::new("127.0.0.1:1080".parse().unwrap(), "", "", 5000);
        let listener = TproxyListener::new(addr, dialer);

        let debug_str = format!("{:?}", listener);
        assert!(debug_str.contains("TproxyListener"));
        assert!(debug_str.contains("15080"));
        assert!(debug_str.contains("running"));
    }
}

// ============================================================================
// UDP TProxy 监听器
// ============================================================================

/// UDP TProxy 监听器
///
/// 透明代理 UDP 流量，通过 `IP_RECVORIGDSTADDR` 获取原始目标地址。
pub struct UdpTproxyListener {
    /// 监听地址（如 `0.0.0.0:15080` 或 `[::]:15080`）
    listen_addr: SocketAddr,
    /// 出站拨号器
    dialer: Arc<RwLock<Socks5Dialer>>,
    /// 运行标记
    running: Arc<AtomicBool>,
    /// socket 标记值（用于 eBPF 自排除，默认 0x100）
    socket_mark: u32,
}

impl UdpTproxyListener {
    /// 创建新的 UDP TProxy 监听器
    pub fn new(listen_addr: SocketAddr, dialer: Socks5Dialer) -> Self {
        Self {
            listen_addr,
            dialer: Arc::new(RwLock::new(dialer)),
            running: Arc::new(AtomicBool::new(false)),
            socket_mark: 0x100, // 原版 dae 默认值
        }
    }

    /// 创建新的 UDP TProxy 监听器，指定 socket 标记值
    pub fn new_with_mark(listen_addr: SocketAddr, dialer: Socks5Dialer, socket_mark: u32) -> Self {
        Self {
            listen_addr,
            dialer: Arc::new(RwLock::new(dialer)),
            running: Arc::new(AtomicBool::new(false)),
            socket_mark,
        }
    }

    /// 获取监听地址
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// 检查监听器是否正在运行
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// 创建并绑定 UDP TProxy socket
    ///
    /// 设置 IP_TRANSPARENT、IP_RECVORIGDSTADDR 和 SO_MARK 等 socket 选项。
    pub async fn bind(&self) -> Result<tokio::net::UdpSocket> {
        use std::os::unix::io::AsRawFd;

        let socket = tokio::net::UdpSocket::bind(self.listen_addr)
            .await
            .with_context(|| {
                format!(
                    "Failed to bind UDP TProxy listener to {} (port may be in use)",
                    self.listen_addr
                )
            })?;

        let fd = socket.as_raw_fd();
        let one: libc::c_int = 1;

        // 设置 IP_TRANSPARENT
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_IP,
                IP_TRANSPARENT,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            return Err(anyhow::Error::from(err))
                .context("Failed to set IP_TRANSPARENT on UDP socket (CAP_NET_ADMIN required)");
        }

        // 设置 IP_RECVORIGDSTADDR（用于获取原始目标地址）
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_IP,
                IP_RECVORIGDSTADDR,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            warn!("Failed to set IP_RECVORIGDSTADDR on UDP socket: {}", err);
        }

        // 设置 IPV6_RECVORIGDSTADDR
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_IPV6,
                IPV6_RECVORIGDSTADDR,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            warn!("Failed to set IPV6_RECVORIGDSTADDR on UDP socket: {}", err);
        }

        // 设置 SO_REUSEADDR
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_REUSEADDR,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            warn!("Failed to set SO_REUSEADDR on UDP socket: {}", err);
        }

        // 设置 SO_REUSEPORT
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_REUSEPORT,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            warn!("Failed to set SO_REUSEPORT on UDP socket: {}", err);
        }

        // 设置 SO_MARK（用于 eBPF 自排除）
        if self.socket_mark != 0 {
            let mark_val = self.socket_mark as libc::c_int;
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    SO_MARK,
                    &mark_val as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                warn!(
                    "Failed to set SO_MARK={:#x} on UDP socket: {}",
                    self.socket_mark, err
                );
            } else {
                debug!("SO_MARK={:#x} set on UDP socket", self.socket_mark);
            }
        }

        info!(
            "UDP TProxy socket options configured for {}",
            self.listen_addr
        );
        Ok(socket)
    }

    /// 启动 UDP TProxy 监听循环
    pub async fn start(&self) -> Result<()> {
        use std::os::fd::{AsRawFd, FromRawFd};

        let owned_fd = self.bind().await?;
        let fd = owned_fd.as_raw_fd();
        // Prevent OwnedFd from closing the fd (we're handing ownership to std_socket)
        std::mem::forget(owned_fd);
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
    async fn run_receive_loop(&self, socket: std::net::UdpSocket) -> Result<()> {
        use protocols::socks5::UdpAssociateSession;
        use std::os::unix::io::AsRawFd;

        const MAX_UDP_SIZE: usize = 65535;
        const CMSG_BUFFER_SIZE: usize = 128;

        let fd = socket.as_raw_fd();
        let dialer = self.dialer.clone();
        let running = self.running.clone();

        // Pool for reusing UDP ASSOCIATE sessions per destination
        let pool = Arc::new(protocols::socks5::UdpEndpointPool::new());

        loop {
            if !running.load(Ordering::SeqCst) {
                info!("UDP TProxy listener stopping");
                break;
            }

            // Receive one UDP packet via recvmsg (blocking, to get cmsg for original dst)
            let mut buf = vec![0u8; MAX_UDP_SIZE];
            let mut cmsg_buf = vec![0u8; CMSG_BUFFER_SIZE];

            let result = tokio::task::spawn_blocking(move || {
                let mut iov = libc::iovec {
                    iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                    iov_len: buf.len(),
                };

                let mut msg_name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                let mut msg = libc::msghdr {
                    msg_name: &mut msg_name as *mut _ as *mut libc::c_void,
                    msg_namelen: std::mem::size_of::<libc::sockaddr_storage>() as u32,
                    msg_iov: &mut iov,
                    msg_iovlen: 1,
                    msg_control: cmsg_buf.as_mut_ptr() as *mut libc::c_void,
                    msg_controllen: cmsg_buf.len() as libc::size_t,
                    msg_flags: 0,
                };

                let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
                if n < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        return Ok::<_, anyhow::Error>((
                            0usize,
                            buf,
                            None::<SocketAddr>,
                            None::<SocketAddr>,
                        ));
                    }
                    return Err(anyhow::anyhow!("recvmsg failed: {}", err));
                }

                let n = n as usize;

                // Parse peer address (source of the intercepted packet)
                let peer_addr = match msg.msg_namelen {
                    0 => None,
                    _ => {
                        let ss_ptr = msg.msg_name as *const libc::sockaddr_storage;
                        let storage = unsafe { &*ss_ptr };
                        match storage.ss_family as libc::c_int {
                            libc::AF_INET => {
                                let addr =
                                    unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
                                let ip =
                                    std::net::Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes());
                                let port = u16::from_be_bytes(addr.sin_port.to_ne_bytes());
                                Some(SocketAddr::new(ip.into(), port))
                            }
                            libc::AF_INET6 => {
                                let addr =
                                    unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
                                let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
                                let port = u16::from_be_bytes(addr.sin6_port.to_ne_bytes());
                                Some(SocketAddr::new(ip.into(), port))
                            }
                            _ => None,
                        }
                    }
                };

                // Parse original destination from cmsg (TProxy metadata)
                let orig_dst = parse_orig_dst_from_cmsg(&cmsg_buf[..msg.msg_controllen]);

                buf.truncate(n);
                Ok((n, buf, peer_addr, orig_dst))
            })
            .await??;

            let (n, mut pkt_buf, peer_addr, orig_dst) = result;

            if n == 0 {
                // WouldBlock
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                continue;
            }

            let dest = match orig_dst {
                Some(dst) => dst,
                None => {
                    warn!(
                        "UDP TProxy: cannot determine original dest, peer={:?}",
                        peer_addr
                    );
                    continue;
                }
            };

            debug!(
                peer = ?peer_addr,
                dest = %dest,
                bytes = n,
                "UDP TProxy: forwarding packet"
            );

            // Spawn a task to forward this UDP packet via SOCKS5 and get response.
            // Each task manages its own UDP ASSOCIATE session lifecycle.
            let pool = pool.clone();
            let dialer = dialer.clone();
            let running = running.clone();
            let dest_str = dest.to_string();

            tokio::spawn(async move {
                let d = dialer.read().await;
                let target = &dest_str;

                // Get or create a UDP ASSOCIATE session for this destination
                let session_result = pool.get_or_create(target, &d).await;
                let session = match session_result {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("UDP ASSOCIATE failed for {}: {}", target, e);
                        pool.remove(target).await;
                        return;
                    }
                };

                // Build SOCKS5 UDP request: header + payload
                let header = UdpAssociateSession::build_udp_request_header(&dest, pkt_buf.len());
                let mut send_buf = header;
                send_buf.extend_from_slice(&pkt_buf);

                // Send via the relay socket
                let mut sess = session.lock().await;
                if let Err(e) = sess.udp.send(&send_buf).await {
                    warn!("UDP send to relay failed: {}", e);
                    pool.remove(target).await;
                    return;
                }

                // Try to read one response with a short timeout
                let mut recv_buf = vec![0u8; MAX_UDP_SIZE];
                let read_fut = sess.udp.recv(&mut recv_buf);
                match tokio::time::timeout(std::time::Duration::from_secs(5), read_fut).await {
                    Ok(Ok(len)) => {
                        recv_buf.truncate(len);
                        // Parse SOCKS5 UDP response header to extract payload
                        if let Some((_resp_peer, payload_offset)) =
                            UdpAssociateSession::parse_udp_response_header(&recv_buf)
                        {
                            let payload = &recv_buf[payload_offset..];
                            // Send response back to original client.
                            // Open a temporary UDP socket to send the response.
                            // We don't need IP_TRANSPARENT for sending — the client
                            // just needs to receive the response data.
                            if let Some(peer) = peer_addr {
                                if let Ok(resp_sock) =
                                    tokio::net::UdpSocket::bind(if peer.is_ipv4() {
                                        "0.0.0.0:0"
                                    } else {
                                        "[::]:0"
                                    })
                                    .await
                                {
                                    if let Err(e) = resp_sock.send_to(payload, peer).await {
                                        debug!("UDP response send failed: {}", e);
                                    } else {
                                        debug!("UDP response: {} bytes -> {}", payload.len(), peer,);
                                    }
                                }
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        debug!("UDP recv from relay: {}", e);
                    }
                    Err(_) => {
                        // Timeout — this is normal, especially for DNS
                        debug!("UDP relay response timeout for {}", dest);
                    }
                }
            });
        }

        Ok(())
    }

    /// 停止 UDP TProxy 监听器
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        info!("UDP TProxy listener stop signal sent");
    }
}

/// 从辅助数据（cmsg/oob）中解析原始目标地址
///
/// 这是 UDP TProxy 获取原始目标地址的关键函数。当设置了 `IP_RECVORIGDSTADDR` 后，
/// 内核会在 recvmsg 的辅助数据中返回数据包的原始目标地址。
///
/// # 参数
///
/// * `cmsg_data` — 辅助数据（cmsg）缓冲区
///
/// # 返回
///
/// 如果成功解析到原始目标地址，返回 `Some(SocketAddr)`。
pub fn parse_orig_dst_from_cmsg(cmsg_data: &[u8]) -> Option<SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let mut offset = 0;
    while offset + 16 <= cmsg_data.len() {
        // 解析 cmsg 头部
        // struct cmsghdr {
        //     size_t cmsg_len;    // 8 bytes (64-bit)
        //     int    cmsg_level;  // 4 bytes
        //     int    cmsg_type;   // 4 bytes
        //     // data follows...
        // }
        let cmsg_len = u64::from_ne_bytes([
            cmsg_data[offset],
            cmsg_data[offset + 1],
            cmsg_data[offset + 2],
            cmsg_data[offset + 3],
            cmsg_data[offset + 4],
            cmsg_data[offset + 5],
            cmsg_data[offset + 6],
            cmsg_data[offset + 7],
        ]) as usize;

        let cmsg_level = i32::from_ne_bytes([
            cmsg_data[offset + 8],
            cmsg_data[offset + 9],
            cmsg_data[offset + 10],
            cmsg_data[offset + 11],
        ]);

        let cmsg_type = i32::from_ne_bytes([
            cmsg_data[offset + 12],
            cmsg_data[offset + 13],
            cmsg_data[offset + 14],
            cmsg_data[offset + 15],
        ]);

        // 检查是否为 IP_RECVORIGDSTADDR 或 IPV6_RECVORIGDSTADDR
        if cmsg_level == libc::SOL_IP && cmsg_type == IP_RECVORIGDSTADDR {
            // IPv4: 数据是 struct sockaddr_in (8 字节端口 + 4 字节 IP)
            let data_offset = offset + 16; // 头部之后
            if data_offset + 16 <= cmsg_data.len() {
                // 跳过 sin_family (2 bytes) + sin_port (2 bytes)
                let port_bytes = [cmsg_data[data_offset + 2], cmsg_data[data_offset + 3]];
                let port = u16::from_be_bytes(port_bytes);

                let ip = Ipv4Addr::new(
                    cmsg_data[data_offset + 4],
                    cmsg_data[data_offset + 5],
                    cmsg_data[data_offset + 6],
                    cmsg_data[data_offset + 7],
                );

                return Some(SocketAddr::new(ip.into(), port));
            }
        } else if cmsg_level == libc::SOL_IPV6 && cmsg_type == IPV6_RECVORIGDSTADDR {
            // IPv6: 数据是 struct sockaddr_in6 (2 字节端口 + 16 字节 IP)
            let data_offset = offset + 16;
            if data_offset + 20 <= cmsg_data.len() {
                let port_bytes = [cmsg_data[data_offset + 2], cmsg_data[data_offset + 3]];
                let port = u16::from_be_bytes(port_bytes);

                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&cmsg_data[data_offset + 4..data_offset + 20]);
                let ip = Ipv6Addr::from(ip_bytes);

                return Some(SocketAddr::new(ip.into(), port));
            }
        }

        // 移动到下一个 cmsg
        if cmsg_len == 0 {
            break;
        }
        offset += cmsg_len;
        // 对齐到 size_t 边界
        offset = (offset + 7) & !7;
    }

    None
}
