//! Host network namespace socket helpers.
//!
//! In the TProxy architecture, dae-rs runs its listener inside the proxy
//! namespace (`daens`), but **all upstream sockets must be created in the host
//! namespace** so that proxy connections and their responses egress via the
//! host's real WAN address (kdae-aligned behavior).
//!
//! This module provides the shared primitive used by every protocol dialer:
//!
//! - [`with_host_ns`] — run a synchronous socket-creation closure inside the
//!   host namespace, then restore the original namespace (panic-safe).
//! - [`connect_tcp`] — generic TCP connect with optional `SO_MARK`,
//!   `IP_TRANSPARENT` and host-namespace socket creation; used by the
//!   TCP-based protocols (SOCKS5, Shadowsocks, Trojan, VMess).
//! - [`create_udp`] — generic UDP socket creation in the host namespace;
//!   the building block for QUIC-based protocols (TUIC, Juicity).
//!
//! # Note
//!
//! The closure passed to [`with_host_ns`] must be fully synchronous
//! (no `.await` points): namespace switches apply to the calling thread, and
//! an `await` inside the switch would expose other tasks to the wrong
//! namespace.

use std::io;
use std::net::SocketAddr;
use std::os::unix::io::{FromRawFd, RawFd};
use std::time::Duration;
use tokio::net::TcpStream;

// ── dae-rs 自身流量专用 socket（“必须直连”约定）──

/// dae-rs 自身流量专用 socket 配置。
///
/// 设计约定：**所有从 dae-rs 进程发出的流量都必须直连**——不能被 eBPF
/// 透明代理管道劫持，否则会形成“代理连接 → 又被劫持 → 再代理”的循环。
///
/// 实现依赖两层机制：
/// 1. `self_mark = shared::DAE_SOCKET_MARK`（0x100）：eBPF
///    `pid_is_control_plane()` 的 SO_MARK 兜底判断命中 → 直接放行；
/// 2. `host_ns_fd`：在宿主网络命名空间创建 socket（kdae-aligned）。
///
/// 所有 dae-rs 出站 socket（拨号器、DNS 上游、透明回包等）都应通过
/// [`connect_tcp`] / [`create_udp`] / [`create_transparent_udp`] 创建，
/// 并传入本结构，而不是手动拼 SO_MARK。
#[derive(Debug, Clone, Copy)]
pub struct DirectSocket {
    /// SO_MARK 用于 eBPF 自排除（0 = 不设置）
    pub self_mark: u32,
    /// 宿主网络命名空间 fd（None = 当前命名空间）
    pub host_ns_fd: Option<RawFd>,
}

impl DirectSocket {
    /// 控制面默认：DAE_SOCKET_MARK + 宿主 NS。
    pub fn control_plane(host_ns_fd: Option<RawFd>) -> Self {
        Self {
            self_mark: shared::DAE_SOCKET_MARK,
            host_ns_fd,
        }
    }

    /// 无标记（测试 / 无需自排除的场景）。
    pub fn plain() -> Self {
        Self {
            self_mark: 0,
            host_ns_fd: None,
        }
    }
}

/// `IP_TRANSPARENT` socket option value (Linux)
const IP_TRANSPARENT: libc::c_int = 19;

/// `IPV6_TRANSPARENT` socket option value (Linux)
const IPV6_TRANSPARENT: libc::c_int = 75;

/// Run a synchronous closure inside the host network namespace.
///
/// 1. Saves the calling thread's current network namespace fd
/// 2. `setns(host_ns_fd)` switches to the host namespace
/// 3. Runs `f()` (wrapped in `catch_unwind` to guarantee restoration)
/// 4. Restores the original namespace and closes the saved fd
///
/// When `host_ns_fd` is `None`, `f()` runs in the current namespace without
/// any switching.
///
/// Sockets created inside `f()` are namespace-independent after creation, so
/// subsequent tokio I/O can continue from the original context.
pub fn with_host_ns<T>(
    host_ns_fd: Option<RawFd>,
    f: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    let Some(host_ns_fd) = host_ns_fd else {
        return f();
    };

    // 1. Save current namespace fd
    let current_fd = unsafe { libc::open(c"/proc/self/ns/net".as_ptr(), libc::O_RDONLY) };
    if current_fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // 2. Switch to the host namespace
    if unsafe { libc::setns(host_ns_fd, libc::CLONE_NEWNET) } != 0 {
        unsafe { libc::close(current_fd) };
        return Err(io::Error::last_os_error());
    }

    // 3. Run the closure (catch panic so the namespace is always restored)
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));

    // 4. Restore the original namespace
    if unsafe { libc::setns(current_fd, libc::CLONE_NEWNET) } != 0 {
        tracing::warn!(
            "CRITICAL: Failed to return to original netns after with_host_ns. \
             The current thread may be in the wrong namespace!"
        );
    }
    unsafe { libc::close(current_fd) };

    match result {
        Ok(v) => v,
        Err(_) => Err(io::Error::other("panic while inside host namespace switch")),
    }
}

/// Create a non-blocking TCP socket, apply socket options, and initiate a
/// connect() to `addr`.
///
/// - `self_mark != 0` → sets `SO_MARK` (eBPF self-exclusion)
/// - `transparent` → sets `IP_TRANSPARENT` / `IPV6_TRANSPARENT`
///   (allows binding/connecting to non-local addresses, kdae-aligned)
/// - `host_ns_fd = Some` → the socket is created and connect() is initiated
///   inside the host namespace, so the SYN source address is the host's real
///   WAN address.
///
/// Returns a tokio [`TcpStream`] with `TCP_NODELAY` enabled. Fails with
/// `io::ErrorKind::TimedOut` when `dial_timeout` elapses.
pub async fn connect_tcp(
    addr: SocketAddr,
    sock: &DirectSocket,
    transparent: bool,
    dial_timeout: Duration,
) -> io::Result<TcpStream> {
    let self_mark = sock.self_mark;
    let host_ns_fd = sock.host_ns_fd;
    // Fast path: nothing special to configure.
    if self_mark == 0 && host_ns_fd.is_none() && !transparent {
        let stream = tokio::time::timeout(dial_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("connect to {} timed out", addr)))??;
        set_tcp_nodelay(&stream);
        return Ok(stream);
    }

    tokio::time::timeout(dial_timeout, async {
        let domain = if addr.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };

        // Socket creation + connect is fully synchronous so it can run inside
        // a temporary host-namespace switch.
        let fd = with_host_ns(host_ns_fd, || {
            let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            if self_mark != 0 {
                let mark_val = self_mark as libc::c_int;
                if unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_MARK,
                        &mark_val as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                } != 0
                {
                    unsafe { libc::close(fd) };
                    return Err(io::Error::last_os_error());
                }
            }

            if transparent {
                let one: libc::c_int = 1;
                let (level, opt): (libc::c_int, libc::c_int) = if addr.is_ipv4() {
                    (libc::SOL_IP, IP_TRANSPARENT)
                } else {
                    (libc::SOL_IPV6, IPV6_TRANSPARENT)
                };
                // IP_TRANSPARENT failure is non-fatal for client sockets.
                unsafe {
                    libc::setsockopt(
                        fd,
                        level,
                        opt,
                        &one as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
            }

            // Non-blocking connect: EINPROGRESS (and EAGAIN) is expected.
            // 注意：Rust 将 EINPROGRESS(115) 映射为 ErrorKind::Other，
            // 不能只用 kind() == WouldBlock 判断，必须检查原始 errno。
            let sockaddr = socket2::SockAddr::from(addr);
            let ret = unsafe {
                libc::connect(
                    fd,
                    sockaddr.as_ptr() as *const libc::sockaddr,
                    sockaddr.len(),
                )
            };
            if ret != 0 {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EINPROGRESS) | Some(libc::EAGAIN) => {}
                    _ => {
                        unsafe { libc::close(fd) };
                        return Err(err);
                    }
                }
            }

            Ok(fd)
        })?;

        let std_stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
        std_stream.set_nonblocking(true)?;
        let stream = TcpStream::from_std(std_stream)?;
        // Wait for the connection to complete (or fail, e.g. ECONNREFUSED).
        // Bounded by the outer dial_timeout.
        // Wait for the connection to complete (or fail, e.g. ECONNREFUSED).
        // Bounded by the outer dial_timeout. EPOLLOUT 可能先于连接完成触发
        // （此时 SO_ERROR 仍为 EINPROGRESS），需要继续等待而非报错。
        loop {
            stream.writable().await?;
            match stream.take_error() {
                Ok(Some(err)) if err.raw_os_error() == Some(libc::EINPROGRESS) => continue,
                Ok(Some(err)) => return Err(err),
                _ => break,
            }
        }
        set_tcp_nodelay(&stream);
        Ok(stream)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("connect to {} timed out", addr)))?
}

/// Create a non-blocking UDP socket in the (optional) host namespace, bound to
/// an ephemeral port of the same family as `addr`.
///
/// Used by the SOCKS5 UDP ASSOCIATE relay and as the building block for
/// QUIC-based protocols (TUIC, Juicity): create the socket here, then hand it
/// to the QUIC endpoint.
pub fn create_udp(
    addr: SocketAddr,
    sock: &DirectSocket,
) -> io::Result<std::net::UdpSocket> {
    let self_mark = sock.self_mark;
    let host_ns_fd = sock.host_ns_fd;
    with_host_ns(host_ns_fd, || {
        let domain = if addr.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        if self_mark != 0 {
            let mark_val = self_mark as libc::c_int;
            if unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &mark_val as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            } != 0
            {
                unsafe { libc::close(fd) };
                return Err(io::Error::last_os_error());
            }
        }

        let bind_addr: SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse().expect("valid bind addr")
        } else {
            "[::]:0".parse().expect("valid bind addr")
        };
        let sock_addr = socket2::SockAddr::from(bind_addr);
        if unsafe {
            libc::bind(fd, sock_addr.as_ptr() as *const libc::sockaddr, sock_addr.len())
        } != 0
        {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }

        let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
        std_socket.set_nonblocking(true)?;
        Ok(std_socket)
    })
}

/// Create a transparent UDP socket bound to `target` (IP_TRANSPARENT).
///
/// Used for transparent reply sockets: bound to the original destination
/// (e.g. upstream DNS server IP) so responses carry the correct source
/// address. Also sets `SO_REUSEADDR`/`SO_REUSEPORT` (concurrent queries to
/// the same target must not hit `EADDRINUSE`) and the self-exclusion mark.
pub fn create_transparent_udp(
    target: &SocketAddr,
    sock: &DirectSocket,
) -> io::Result<std::net::UdpSocket> {
    let self_mark = sock.self_mark;
    let host_ns_fd = sock.host_ns_fd;
    with_host_ns(host_ns_fd, || {
        let domain = if target.is_ipv6() {
            libc::AF_INET6
        } else {
            libc::AF_INET
        };
        let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let one: libc::c_int = 1;
        unsafe {
            // IP_TRANSPARENT MUST be set before bind().
            let (level, opt): (libc::c_int, libc::c_int) = if target.is_ipv6() {
                (libc::SOL_IPV6, IPV6_TRANSPARENT)
            } else {
                (libc::SOL_IP, IP_TRANSPARENT)
            };
            if libc::setsockopt(
                fd,
                level,
                opt,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                unsafe { libc::close(fd) };
                return Err(io::Error::last_os_error());
            }

            if self_mark != 0 {
                let mark_val = self_mark as libc::c_int;
                if libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &mark_val as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                ) != 0
                {
                    unsafe { libc::close(fd) };
                    return Err(io::Error::last_os_error());
                }
            }

            // SO_REUSEADDR + SO_REUSEPORT: 并发查询同一目标地址时不 EADDRINUSE。
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        // Bind to the target address (works with IP_TRANSPARENT for non-local
        // addresses). The socket then sends responses with the target address
        // as the source.
        let sock_addr = socket2::SockAddr::from(*target);
        if unsafe {
            libc::bind(fd, sock_addr.as_ptr() as *const libc::sockaddr, sock_addr.len())
        } != 0
        {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }

        let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
        std_socket.set_nonblocking(true)?;
        Ok(std_socket)
    })
}

/// Enable TCP_NODELAY (proxy path latency is sensitive to small packets).
fn set_tcp_nodelay(stream: &TcpStream) {
    use socket2::SockRef;
    if let Err(e) = SockRef::from(stream).set_nodelay(true) {
        tracing::warn!("Failed to set TCP_NODELAY on proxy connection: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_with_host_ns_none() {
        let v = with_host_ns(None, || Ok::<_, io::Error>(42)).unwrap();
        assert_eq!(v, 42);
    }

    #[test]
    fn test_with_host_ns_error_propagates() {
        let err = with_host_ns(None, || -> io::Result<()> {
            Err(io::Error::other("boom"))
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }
}
