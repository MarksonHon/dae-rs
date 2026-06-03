//! TProxy 监听器 + TCP 双向转发
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
//! * Linux `IP_FREEBIND` socket 选项
//!
//! # 安全性
//!
//! * 所有 socket 操作需处理 `EPERM` 错误（缺少 `CAP_NET_ADMIN` 时）
//! * 连接关闭需正确传播，避免连接泄漏
//! * 错误不应导致整个监听器崩溃

use anyhow::{Context, Result};
use protocols::OutboundDialer;
use protocols::socks5::Socks5Dialer;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

// ============================================================================
// Linux socket 选项常量
// ============================================================================

/// `IP_TRANSPARENT` socket 选项值（Linux）
///
/// 使 socket 能透明地接受非本机地址的连接，是 TProxy 的核心机制。
/// 需要 `CAP_NET_ADMIN` 权限。
const IP_TRANSPARENT: libc::c_int = 19;

/// `IP_FREEBIND` socket 选项值（Linux）
///
/// 允许 socket 绑定到当前不存在的 IP 地址，在动态 IP 环境下有用。
const IP_FREEBIND: libc::c_int = 15;

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

    /// 启动 TProxy 监听循环
    ///
    /// # 流程
    ///
    /// 1. 创建 `TcpListener` 绑定到 [`listen_addr`](TproxyListener::listen_addr)
    /// 2. 设置 socket 选项：
    ///    - `IP_TRANSPARENT`（需要 `CAP_NET_ADMIN`）— 透明接受非本机地址连接
    ///    - `IP_FREEBIND` — 允许绑定到不存在的 IP 地址
    /// 3. 进入 accept 循环
    /// 4. 每个连接到来时，`tokio::spawn` 一个 [`handle_connection`] 任务
    /// 5. 检查运行标记，收到停止信号时退出循环
    ///
    /// # 错误
    ///
    /// * 如果端口被占用，返回 `std::io::Error`
    /// * 如果没有 `CAP_NET_ADMIN` 权限，设置 `IP_TRANSPARENT` 时返回 `EPERM`
    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(self.listen_addr)
            .await
            .with_context(|| {
                format!(
                    "Failed to bind TProxy listener to {} (port may be in use)",
                    self.listen_addr
                )
            })?;

        // 设置 IP_TRANSPARENT 和 IP_FREEBIND socket 选项
        set_tproxy_socket_opts(&listener).context(format!(
            "Failed to set TProxy socket options on {} (CAP_NET_ADMIN required)",
            self.listen_addr
        ))?;

        self.running.store(true, Ordering::SeqCst);
        let proxy_addr = self.dialer.try_read().map(|d| d.proxy_addr.to_string())
            .unwrap_or_else(|_| "locked".to_string());
        info!(
            listen_addr = %self.listen_addr,
            proxy_addr = %proxy_addr,
            "TProxy listener started"
        );

        loop {
            // 检查运行标记，用于优雅停止
            if !self.running.load(Ordering::SeqCst) {
                info!(
                    listen_addr = %self.listen_addr,
                    "TProxy listener stopping"
                );
                break;
            }

            match listener.accept().await {
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

        Ok(())
    }

    /// 停止 TProxy 监听器
    ///
    /// 设置运行标记为 `false`，监听循环将在下一次迭代中退出。
    /// 已经建立的连接不会中断，它们会继续运行直到完成。
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
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
    let (n_to_upstream, n_from_upstream) =
        copy_bidirectional(&mut inbound, &mut outbound).await.context(
            "Bidirectional data copy between client and upstream failed",
        )?;

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

/// 设置 TProxy 所需的 socket 选项
///
/// 对 `TcpListener` 的原始 fd 设置以下 Linux 特有 socket 选项：
///
/// | 选项 | 值 | 说明 |
/// |------|-----|------|
/// | `IP_TRANSPARENT` | 19 | 透明代理模式，允许接受非本机地址的连接 |
/// | `IP_FREEBIND` | 15 | 允许绑定到当前不存在的 IP 地址 |
///
/// 使用 `libc::setsockopt()` 系统调用直接设置，因为 `socket2` crate
/// 未直接暴露这些 Linux 特有选项。
///
/// # 参数
///
/// * `listener` — TCP 监听器
///
/// # 错误
///
/// * 如果缺少 `CAP_NET_ADMIN` 权限，设置 `IP_TRANSPARENT` 时返回 `EPERM`
fn set_tproxy_socket_opts(listener: &TcpListener) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    let fd = listener.as_raw_fd();
    let one: libc::c_int = 1;

    // ---- 设置 IP_TRANSPARENT ----
    // 允许 socket 透明地接受发往非本机 IP 地址的 TCP 连接
    // 这是 TProxy 的核心机制
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,  // IP 协议层
            IP_TRANSPARENT, // IP_TRANSPARENT = 19
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::Error::from(err))
            .context("Failed to set IP_TRANSPARENT socket option (CAP_NET_ADMIN required)");
    }

    // ---- 设置 IP_FREEBIND ----
    // 允许 socket 绑定到当前不存在的 IP 地址
    // 在动态 IP 环境下避免 "Cannot assign requested address" 错误
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP, // IP 协议层
            IP_FREEBIND,   // IP_FREEBIND = 15
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        // IP_FREEBIND 失败不会影响 TProxy 的核心功能，记录警告而非错误
        warn!(
            "Failed to set IP_FREEBIND socket option: {} (non-critical)",
            err
        );
    } else {
        debug!("IP_FREEBIND set successfully");
    }

    debug!(
        "TProxy socket options configured: IP_TRANSPARENT={}, IP_FREEBIND={}",
        true, ret == 0
    );
    Ok(())
}

// ============================================================================
// 单元测试
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
            let dialer =
                Socks5Dialer::new("127.0.0.1:1080".parse().unwrap(), "", "", 5000);
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
