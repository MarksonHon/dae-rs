//! TProxy listener + bidirectional TCP/UDP forwarding
//!
//! This module implements transparent proxying (TProxy), a core component of the
//! proxy data path:
//!
//! # Data flow
//!
//! ```text
//! Client → eBPF/Policy Routing → veth pair → proxy namespace
//!                                         ↓
//!                                   TProxy listener
//!                                         ↓
//!                                SOCKS5 outbound dialer
//!                                         ↓
//!                                upstream proxy server
//!                                         ↓
//!                                  target server
//! ```
//!
//! # Core components
//!
//! * [`TproxyListener`] — TProxy listener, listens on a port inside the proxy namespace
//! * [`handle_connection`] — TCP bidirectional relay function
//! * [`get_original_dst`] — gets the original destination address of a TProxy connection
//!
//! # Dependencies
//!
//! * Linux `IP_TRANSPARENT` socket option (requires `CAP_NET_ADMIN`)
//! * Linux `IP_RECVORIGDSTADDR` socket option (for getting the UDP original destination)
//! * Linux `SO_REUSEADDR` and `SO_REUSEPORT` socket options
//!
//! # Safety
//!
//! * All socket operations must handle `EPERM` errors (when `CAP_NET_ADMIN` is missing)
//! * Connection shutdown must propagate correctly to avoid connection leaks
//! * An error must not crash the whole listener

use anyhow::{Context, Result};
use protocols::{OutboundDialer, ProxyStream};
use protocols::UdpSession;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
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
// TCP relay constants
// ============================================================================

/// Data chunk size for a single splice() call (kernel page reclaim; larger chunks reduce syscalls)
const SPLICE_CHUNK: usize = 64 * 1024;

/// Bidirectional copy buffer size for the fallback path when splice is unavailable
/// (tokio's default copy_bidirectional is only 8KB)
const COPY_BUFFER_SIZE: usize = 64 * 1024;

/// Half-close protection timeout for the TCP bidirectional relay.
///
/// When one direction's copy completes (source EOF), the other direction is given
/// at most this much time to shut down gracefully.
/// On timeout the whole connection is force-closed to avoid relay task leaks caused
/// by a peer that neither sends data nor closes.
/// Matches kdae's `relayHalfCloseTimeout` (10s).
const RELAY_HALF_CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

// ============================================================================
// UDP relay constants
// ============================================================================

/// Maximum UDP packet size
const MAX_UDP_SIZE: usize = 65535;

/// recvmsg ancillary data (cmsg) buffer size
const CMSG_BUFFER_SIZE: usize = 128;

/// UDP relay flow idle timeout: the session is closed if no relay response is
/// received within this time
const UDP_FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// DNS UDP flow idle timeout (RFC 5452 recommends 17s)
const DNS_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(17);

/// Idle timeout for long-lived UDP flows such as QUIC/DTLS (matches kdae's QuicNatTimeout)
const QUIC_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Write deadline for UDP sends (upstream forwarding / responses).
///
/// Prevents the send path from blocking indefinitely when the proxy upstream stalls
/// or the client stops reading.
/// Matches kdae's `udpEndpointWriteTimeout` (10s).
const UDP_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Select the UDP flow idle timeout by original destination port (tiered timeout).
///
/// * 53 (DNS) → 17s (RFC 5452)
/// * 443 (QUIC/DTLS) → 2min
/// * others → 30s (default)
fn udp_flow_idle_timeout(dest: SocketAddr) -> Duration {
    match dest.port() {
        53 => DNS_UDP_IDLE_TIMEOUT,
        443 => QUIC_UDP_IDLE_TIMEOUT,
        _ => UDP_FLOW_IDLE_TIMEOUT,
    }
}

/// Transparent response socket pool capacity limit (least-recently-used entries are evicted)
const RESP_SOCKET_POOL_CAP: usize = 256;

// ============================================================================
// Linux socket option constants
// ============================================================================

/// `IP_TRANSPARENT` socket option value (Linux)
///
/// Lets a socket transparently accept connections for non-local addresses; this is
/// the core mechanism of TProxy.
/// Requires `CAP_NET_ADMIN`.
const IP_TRANSPARENT: libc::c_int = 19;

/// `IPV6_TRANSPARENT` socket option value (Linux)
///
/// The IPv6 counterpart of IP_TRANSPARENT, letting an IPv6 socket transparently
/// accept connections for non-local addresses.
const IPV6_TRANSPARENT: libc::c_int = 75;

/// `IP_RECVORIGDSTADDR` socket option value (Linux)
///
/// Makes the socket return the original destination address via ancillary data (cmsg)
/// when receiving packets.
/// This is the key mechanism for obtaining the original destination address in UDP TProxy.
const IP_RECVORIGDSTADDR: libc::c_int = 20;

/// `IPV6_RECVORIGDSTADDR` socket option value (Linux)
///
/// The IPv6 counterpart of IP_RECVORIGDSTADDR.
const IPV6_RECVORIGDSTADDR: libc::c_int = 74;

/// `SO_REUSEADDR` socket option value (Linux)
///
/// Allows reusing a socket address in the TIME_WAIT state.
#[allow(dead_code)]
const SO_REUSEADDR: libc::c_int = 2;

/// `SO_REUSEPORT` socket option value (Linux)
///
/// Allows multiple sockets to bind to the same port for load balancing.
#[allow(dead_code)]
const SO_REUSEPORT: libc::c_int = 15;

/// `SO_MARK` socket option value (Linux)
///
/// Sets the socket's fwmark, used by policy routing and eBPF programs to identify
/// self traffic.
/// original dae uses 0x100 as internal socket mark.
const SO_MARK: libc::c_int = 36;

// ============================================================================
// TproxyListener
// ============================================================================

/// TProxy listener
///
/// Transparent proxy listener that receives TCP connections redirected by the kernel
/// (via eBPF + policy routing) into the proxy namespace, forwarding them to the
/// upstream proxy via the SOCKS5 outbound dialer.
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
    /// Listen address (inside the proxy namespace, e.g. `0.0.0.0:15080`)
    listen_addr: SocketAddr,
    /// Outbound dialer (constructed per the configured protocol)
    dialer: Arc<dyn OutboundDialer>,
    /// Running flag
    running: Arc<AtomicBool>,
    /// Socket mark value (for eBPF self-exclusion, default 0x100)
    socket_mark: u32,
    /// Stop signal (notifies the accept loop to exit; no polling needed)
    stop_signal: Arc<Notify>,
    /// Internal DNS handler address (for cross-namespace DNS hijacking).
    ///
    /// When a TCP connection's original destination is port 53, the connection is not
    /// sent through the proxy dialer; instead the DNS-over-TCP session is forwarded to
    /// the DNS handler at this address (consistent with UDP hijacking).
    /// `None` means no TCP DNS hijacking.
    dns_forward_addr: Option<SocketAddr>,
    /// Host network namespace fd (upstream sockets for DNS hijacking are created in the host NS).
    host_ns_fd: Option<RawFd>,
}

impl TproxyListener {
    /// Create a new TProxy listener
    ///
    /// # Parameters
    ///
    /// * `listen_addr` — listen address (e.g. `0.0.0.0:15080`)
    /// * `dialer` — outbound dialer
    pub fn new(listen_addr: SocketAddr, dialer: Arc<dyn OutboundDialer>) -> Self {
        Self {
            listen_addr,
            dialer,
            running: Arc::new(AtomicBool::new(false)),
            socket_mark: shared::DAE_SOCKET_MARK, // default value from the original dae
            stop_signal: Arc::new(Notify::new()),
            dns_forward_addr: None,
            host_ns_fd: None,
        }
    }

    /// Create a new TProxy listener with a specified socket mark value
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

    /// Set the TCP DNS hijacking target (the internal DNS handler address).
    ///
    /// After setting, TCP connections whose original destination is port 53 are forwarded
    /// to this DNS handler instead of the proxy. Consistent with UDP hijacking's
    /// `169.254.0.1:<port>`.
    pub fn set_dns_forward_addr(&mut self, addr: SocketAddr) {
        self.dns_forward_addr = Some(addr);
        tracing::info!(
            "DNS hijacking enabled: TCP TProxy will forward DNS queries to {}",
            addr
        );
    }

    /// Set the host network namespace fd (upstream connections for DNS hijacking are
    /// created in the host NS).
    pub fn set_host_ns_fd(&mut self, host_ns_fd: Option<RawFd>) {
        self.host_ns_fd = host_ns_fd;
    }

    /// Get listen address
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Get a reference to the outbound dialer
    pub fn dialer(&self) -> &Arc<dyn OutboundDialer> {
        &self.dialer
    }

    /// Check if listener is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get an atomic reference to the running flag (for cross-thread communication)
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

    /// Core accept loop (internal use)
    async fn run_accept_loop(&self, listener: TcpListener) -> Result<()> {
        let mut accept_count: u64 = 0;
        loop {
            // Check the running flag for graceful shutdown
            if !self.running.load(Ordering::SeqCst) {
                debug!(
                    listen_addr = %self.listen_addr,
                    total_accepted = accept_count,
                    "TProxy listener stopping (running=false)"
                );
                break;
            }

            // Use tokio::select! to wait for both accept and the stop signal:
            // - accept a connection → handle the connection
            // - receive the stop signal → exit the loop immediately
            // - accept error → sleep briefly and retry
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
                            // Sleep briefly to avoid busy-looping
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
// Connection handling
// ============================================================================

/// Handle a single TProxy connection (bidirectional TCP relay)
///
/// Runs the full bidirectional TCP relay flow:
///
/// 1. **Get the original destination address** — obtain it from the `TcpStream`
///    (via TProxy's `IP_TRANSPARENT` feature, `getsockname()` returns the original destination)
/// 2. **SOCKS5 dial** — create a SOCKS5 dialer instance and call `dial(target_addr)` to
///    establish the connection upstream
/// 3. **Get a `ProxyConn`** — obtain a proxy connection implementing `AsyncRead + AsyncWrite`
/// 4. **Bidirectional copy** — copy data in both directions with `tokio::io::copy_bidirectional`
/// 5. **Connection close** — wait for the bidirectional copy to finish, ensuring a clean close
///
/// # Parameters
///
/// * `inbound` — the client connection received from TProxy
/// * `dialer` — the SOCKS5 outbound dialer
///
/// # Error handling
///
/// * If the original destination address cannot be obtained, an error is returned
///   (`IP_TRANSPARENT` may not be set correctly)
/// * If the SOCKS5 dial fails, an error is returned (the upstream proxy may be unreachable)
/// * If the bidirectional copy fails, an error is returned (the network may be interrupted)
/// * An error in one connection does not affect the listener's other connections
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

    // ---- Step 1: Get the original destination address ----
    let orig_dst = get_original_dst(&inbound).context(
        "Failed to get original destination address from TProxy connection \
         (ensure IP_TRANSPARENT is set and CAP_NET_ADMIN is available)",
    )?;
    debug!(orig_dst = %orig_dst, "handle_connection: got original destination");

    // ---- Step 1.5: TCP DNS hijacking ----
    // eBPF has already redirected TCP port 53 queries to the control plane
    // (ROUTE_STATE_DNS_QUERY).
    // Here the DNS-over-TCP session is forwarded to the internal DNS handler instead of
    // the proxy, consistent with UDP hijacking (dns_forward_addr). This way TCP DNS also
    // enters the DNS module's caching/anti-pollution/proxy logic.
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

    // ---- Step 2: Disable Nagle (TCP_NODELAY) to reduce interactive small-packet latency ----
    // Inbound connections have Nagle enabled by default on kernel accept; outbound
    // connections set it in the SOCKS5 dialer.
    set_tcp_nodelay(&inbound);

    // ---- Step 2: Dial the target via the outbound dialer ----
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

    // ---- Step 2.5: Log outbound connection info (INFO) ----
    // The outbound local address is the real source address in the host NS (Tcp variant);
    // TLS/WS/QUIC wrapped streams cannot directly read socket addresses, shown as n/a.
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

    // ---- Step 3: Bidirectional data copy ----
    // Pure TCP connections use splice zero-copy relay; TLS/WS/QUIC wrapped streams use buffered copy.
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

/// Forward a DNS-over-TCP session to the internal DNS handler.
///
/// DNS-over-TCP uses a 2-byte length-prefix framing (RFC 1035 §4.2.2). The byte stream
/// between the client connection and the internal DNS handler is relayed bidirectionally:
/// query frames go to the handler, response frames come back to the client. Since the
/// client connection is an IP_TRANSPARENT TProxy socket (local address = original
/// destination DNS server), the return-path source address is correct and the client
/// will not drop the packets.
///
/// The upstream socket is created in the host NS (`host_ns_fd`) and marked with
/// SO_MARK=DAE_SOCKET_MARK, consistent with the UDP hijack path, ensuring eBPF lets
/// it through (preventing a hijack loop).
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
    // Pure byte relay: length-prefixed frames pass through as-is, no DNS parsing here.
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

/// Get the original destination address of a TProxy connection
///
/// In Linux TProxy mode, with the `IP_TRANSPARENT` option set, the `getsockname()`
/// system call returns not the socket's local address but the client connection's
/// original destination address. This lets us obtain the address the client originally
/// intended to connect to, without modifying packets.
///
/// # Implementation details
///
/// ```text
/// Normal mode:   getsockname() → local bound address (e.g. 0.0.0.0:15080)
/// TProxy mode:   getsockname() → original destination address (e.g. 1.2.3.4:80)
/// ```
///
/// # Parameters
///
/// * `stream` — the TCP connection received by TProxy
///
/// # Returns
///
/// Returns the original destination address (`SocketAddr`).
///
/// # Errors
///
/// * May return an error if `CAP_NET_ADMIN` is missing or `IP_TRANSPARENT` is not
///   set correctly
/// * Returns an error if the address's port is 0, treating it as invalid
fn get_original_dst(stream: &TcpStream) -> Result<SocketAddr> {
    use socket2::SockRef;

    let sock_ref = SockRef::from(stream);
    let local_addr = sock_ref
        .local_addr()
        .context("Failed to call getsockname() on TProxy connection")?;
    let addr: SocketAddr = local_addr
        .as_socket()
        .context("getsockname() returned a non-IP address")?;

    // Validate the address: a TProxy original destination address's port must not be 0
    if addr.port() == 0 {
        anyhow::bail!(
            "Invalid original destination address (port is 0): {} — \
             IP_TRANSPARENT may not be configured correctly",
            addr
        );
    }

    Ok(addr)
}

/// Set TCP_NODELAY to disable the Nagle algorithm.
///
/// Every byte stream on the proxy path may carry interactive small packets (SSH, games,
/// API requests, etc.); Nagle coalesces these and waits for an ACK, significantly
/// increasing RTT. The original dae explicitly sets TCP_NODELAY on both inbound and
/// outbound connections. Failure is only logged at debug level (non-fatal).
fn set_tcp_nodelay(stream: &TcpStream) {
    use socket2::SockRef;
    if let Err(e) = SockRef::from(stream).set_nodelay(true) {
        debug!("Failed to set TCP_NODELAY: {}", e);
    }
}

// ============================================================================
// TCP bidirectional relay: splice zero-copy + large-buffer fallback
// ============================================================================

/// Pipe pair (RAII; closes both fds on drop).
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

/// Probe whether splice() supports the (src, dst) combination.
///
/// A splice call with len=0 only triggers the kernel's fd type check without moving
/// data; if it returns EINVAL (kernel/file type unsupported), fall back to buffered copy.
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

/// Duplicate the fd (dup) for splice readiness waiting.
///
/// The original tokio `TcpStream` is already registered with the reactor, so its fd
/// cannot be registered again with AsyncFd (re-registering the same fd conflicts with
/// the existing registration); after dup-ing an independent fd, the two registrations
/// do not interfere, and the original stream can still be used for operations like shutdown.
fn dup_fd_stream(stream: &TcpStream) -> std::io::Result<AsyncFd<std::net::TcpStream>> {
    use std::os::unix::io::{AsRawFd, FromRawFd};
    let dup_fd = unsafe { libc::dup(stream.as_raw_fd()) };
    if dup_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let std_stream = unsafe { std::net::TcpStream::from_raw_fd(dup_fd) };
    AsyncFd::new(std_stream)
}

/// Move data in one direction with splice(): src socket → pipe → dst socket (zero-copy).
///
/// On source EOF, `shutdown(SHUT_WR)` is called on dst to propagate FIN (half-close
/// semantics), then the total number of bytes moved in this direction is returned.
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
        // 1. Wait for the source to be readable, then splice into the pipe
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
                // Source EOF: propagate FIN to the peer, this direction ends
                unsafe { libc::shutdown(dst_fd, libc::SHUT_WR) };
                return Ok(total);
            }
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::WouldBlock {
                return Err(err);
            }
            guard.clear_ready();
        };

        // 2. Wait for the target to be writable, then splice all pipe data into it.
        // Must loop to drain the pipe: if only part of the bytes (m < n) is moved in
        // one pass, the remaining bytes would stall in the next outer iteration because
        // it waits for the source to be readable (deadlock).
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
                // Pipe EOF (write end closed), normal end
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

/// Single-direction buffered copy (64KB buffer); on source EOF, shuts down the target
/// write side to propagate FIN.
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

/// Bidirectional relay half-close protection: when one direction completes, the other
/// side is given [`RELAY_HALF_CLOSE_TIMEOUT`] time to shut down gracefully; on timeout an
/// error is returned (the caller closes the whole connection).
///
/// Mirrors kdae's `forceClose()`: prevents the other direction's `read()` from blocking
/// forever when the peer neither sends data nor closes, which would leak the relay task.
enum RelaySide {
    /// Client → proxy direction (`f1`)
    Up,
    /// Proxy → client direction (`f2`)
    Down,
}

/// Wrap the two single-direction copy futures with half-close timeout protection.
async fn half_close_guard<F1, F2>(
    f1: F1,
    f2: F2,
) -> std::io::Result<(u64, u64)>
where
    F1: Future<Output = std::io::Result<u64>>,
    F2: Future<Output = std::io::Result<u64>>,
{
    tokio::pin!(f1);
    tokio::pin!(f2);

    let (first, side) = tokio::select! {
        r = &mut f1 => (r, RelaySide::Up),
        r = &mut f2 => (r, RelaySide::Down),
    };
    let first = first?;

    let second = tokio::time::timeout(RELAY_HALF_CLOSE_TIMEOUT, async {
        match side {
            RelaySide::Up => (&mut f2).await,
            RelaySide::Down => (&mut f1).await,
        }
    })
    .await;

    match second {
        Ok(Ok(b)) => Ok(match side {
            RelaySide::Up => (first, b),
            RelaySide::Down => (b, first),
        }),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "relay half-close timed out, forcing connection close",
        )),
    }
}

/// Bidirectional TCP relay: prefers the splice() zero-copy path, falls back to a 64KB
/// buffered copy when unavailable.
///
/// Returns `(client→proxy bytes, proxy→client bytes)`, consistent with tokio's
/// `copy_bidirectional` ordering.
async fn relay_bidirectional(
    mut inbound: TcpStream,
    mut outbound: TcpStream,
) -> std::io::Result<(u64, u64)> {
    // ---- splice zero-copy path ----
    if let Ok(pipe_ab) = PipePair::new() {
        if let Ok(pipe_ba) = PipePair::new() {
            if splice_supported(&inbound, &outbound, &pipe_ab)
                && splice_supported(&outbound, &inbound, &pipe_ba)
            {
                return half_close_guard(
                    splice_direction(&inbound, &outbound, &pipe_ab),
                    splice_direction(&outbound, &inbound, &pipe_ba),
                )
                .await;
            }
        }
    }

    // ---- 64KB buffered fallback path (splice unavailable) ----
    let (mut inbound_r, mut inbound_w) = inbound.split();
    let (mut outbound_r, mut outbound_w) = outbound.split();
    half_close_guard(
        buffered_copy_direction(&mut inbound_r, &mut outbound_w),
        buffered_copy_direction(&mut outbound_r, &mut inbound_w),
    )
    .await
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

        // Verify that the flag shares the same AtomicBool as the listener
        flag.store(true, Ordering::SeqCst);
        assert!(listener.is_running());
    }

    #[test]
    fn test_get_original_dst_not_tproxy() {
        // Behavior test of get_original_dst without IP_TRANSPARENT
        // Since there is no real TProxy connection, we only verify the function signature
        // Note: this test only verifies that getsockname returns a normal address in a non-TProxy environment
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            // Bind to a local address, non-TProxy mode
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            // get_original_dst cannot be tested here because it needs a real TProxy connection,
            // but we at least ensure the function signature and basic types are correct
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

    #[test]
    fn test_udp_flow_idle_timeout_tiers() {
        let dns: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let quic: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let other: SocketAddr = "9.9.9.9:1234".parse().unwrap();

        assert_eq!(udp_flow_idle_timeout(dns), DNS_UDP_IDLE_TIMEOUT);
        assert_eq!(udp_flow_idle_timeout(quic), QUIC_UDP_IDLE_TIMEOUT);
        assert_eq!(udp_flow_idle_timeout(other), UDP_FLOW_IDLE_TIMEOUT);
    }

    #[tokio::test]
    async fn test_half_close_guard_both_complete() {
        // Both directions complete normally, returning the (up, down) byte counts.
        let (up, down) = half_close_guard(
            std::future::ready(Ok::<u64, std::io::Error>(10)),
            std::future::ready(Ok::<u64, std::io::Error>(20)),
        )
        .await
        .unwrap();
        assert_eq!((up, down), (10, 20));
    }

    #[tokio::test]
    async fn test_half_close_guard_first_error_propagates() {
        // The first direction errors immediately; the error should propagate without
        // waiting for the other direction.
        let err = half_close_guard(
            std::future::ready(Err::<u64, std::io::Error>(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "broken",
            ))),
            std::future::ready(Ok::<u64, std::io::Error>(20)),
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn test_half_close_guard_timeout_forces_close() {
        // After one direction completes, the other never completes → timeout forces a TimedOut error.
        let never = std::future::pending::<std::io::Result<u64>>();
        let err = half_close_guard(std::future::ready(Ok::<u64, std::io::Error>(10)), never)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }
}

// ============================================================================
// UDP TProxy listener
// ============================================================================

/// UDP TProxy listener
///
/// Transparently proxies UDP traffic, obtaining the original destination address via
/// `IP_RECVORIGDSTADDR`.
/// For DNS traffic (destination port 53), DNS hijacking is used: queries are forwarded
/// to the internal DNS handler instead of through the SOCKS5 proxy. This enables
/// domain-based routing, caching, and other features.
pub struct UdpTproxyListener {
    /// Listen address (e.g. `0.0.0.0:15080` or `[::]:15080`)
    listen_addr: SocketAddr,
    /// Outbound dialer
    dialer: Arc<dyn OutboundDialer>,
    /// Running flag
    running: Arc<AtomicBool>,
    /// Socket mark value (for eBPF self-exclusion, default 0x100)
    socket_mark: u32,
    /// Stop signal (notifies the receive loop to exit immediately)
    stop_signal: Arc<Notify>,
    /// DNS forwarding target address (for DNS hijacking).
    /// When a DNS query is received, it is forwarded to the DNS handler at this address
    /// instead of through the SOCKS5 proxy. None disables DNS hijacking (falls back to SOCKS5).
    dns_forward_addr: Option<SocketAddr>,
    /// Host network namespace fd.
    ///
    /// After setting, all upstream UDP sockets (DNS hijack query sockets, UDP relay responses
    /// sockets) are created and sent from the host NS (aligned with kdae), so the source
    /// address is the host's real WAN address instead of the daens internal address.
    /// `None` creates sockets in the current namespace.
    host_ns_fd: Option<RawFd>,
}

impl UdpTproxyListener {
    /// Create a new UDP TProxy listener
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

    /// Create a new UDP TProxy listener with a specified socket mark value
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
    /// sockets) are created in the host NS (aligned with kdae).
    pub fn set_host_ns_fd(&mut self, host_ns_fd: Option<RawFd>) -> &mut Self {
        self.host_ns_fd = host_ns_fd;
        self
    }

    /// Set the DNS forwarding target address.
    /// After setting, DNS queries are forwarded directly to this address instead of
    /// through the SOCKS5 proxy.
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

    /// Create and bind the UDP TProxy socket
    ///
    /// Sets socket options such as IP_TRANSPARENT, IP_RECVORIGDSTADDR and SO_MARK.
    /// Note: IP_TRANSPARENT must be set before bind(), otherwise bind() fails because
    /// it tries to bind a non-local address.
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

        // Use socket2 to create the raw socket, setting all options before bind
        let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
            .context("Failed to create UDP TProxy socket")?;

        let one: libc::c_int = 1;
        let fd = socket.as_raw_fd();

        // IPv6: set IPV6_V6ONLY=0 to enable dual-stack (before bind)
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

        // Set IP_TRANSPARENT (must be before bind!)
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

        // Set IP_RECVORIGDSTADDR / IPV6_RECVORIGDSTADDR (to get the original destination address)
        // A dual-stack (AF_INET6, V6ONLY=0) socket receives both IPv4 and IPv6 packets:
        // IPv4 packets go through the kernel's ip_cmsg_recv, needing IP_RECVORIGDSTADDR on SOL_IP;
        // IPv6 packets need IPV6_RECVORIGDSTADDR on SOL_IPV6.
        // Setting only one of them leaves the other address family unable to parse the original destination.
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

        // Set SO_REUSEADDR
        socket.set_reuse_address(true)?;

        // Set SO_REUSEPORT
        #[cfg(unix)]
        socket.set_reuse_port(true)?;

        // Set SO_MARK (for eBPF self-exclusion)
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

        // Bind the address (IP_TRANSPARENT is now in effect)
        let sock_addr = socket2::SockAddr::from(self.listen_addr);
        socket.bind(&sock_addr).with_context(|| {
            format!(
                "Failed to bind UDP TProxy socket to {} (port may be in use)",
                self.listen_addr
            )
        })?;

        // Convert to a tokio UdpSocket
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

    /// Start the UDP TProxy receive loop
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

    /// UDP receive loop core — uses recvmsg to get cmsg for parsing the original
    /// destination address, and forwards packets to the original destination via
    /// SOCKS5 UDP ASSOCIATE.
    /// For DNS traffic, if dns_forward_addr is configured, queries are forwarded
    /// directly to the internal DNS handler, implementing DNS hijacking instead of
    /// going through the SOCKS5 proxy.
    ///
    /// # Optimization notes
    ///
    /// - Receive/send buffers are reused outside the loop, avoiding a 64KB heap allocation per UDP packet;
    /// - tokio `AsyncFd` waits for readability instead of spawn_blocking + 10ms polling;
    /// - SOCKS5 UDP ASSOCIATE sessions are per (dest, peer) flow, each with an independent
    ///   reader task continuously reading relay responses and sending them back to the client;
    ///   sends do not hold the lock, so concurrent packets to the same destination
    ///   (QUIC multiple in-flight packets) are no longer serialized by the mutex;
    /// - response sockets (IP_TRANSPARENT, bound to the original destination address) are
    ///   reused per dest, avoiding socket()+setsockopt()+bind() per packet (2 extra setns
    ///   calls in the host_ns_fd scenario);
    /// - per-packet logging is downgraded to debug.
    async fn run_receive_loop(&self, socket: std::net::UdpSocket) -> Result<()> {
        use std::os::unix::io::AsRawFd;

        let fd = socket.as_raw_fd();
        let dialer = self.dialer.clone();
        let stop_signal = self.stop_signal.clone();
        let dns_forward_addr = self.dns_forward_addr;
        let host_ns_fd = self.host_ns_fd;

        // Buffers are reused outside the loop (avoiding a 64KB allocation per packet)
        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let mut cmsg_buf = vec![0u8; CMSG_BUFFER_SIZE];

        // SOCKS5 UDP flow pool: (dest, peer) → session + reader task
        let flows = Arc::new(UdpFlowPool::new());
        // Transparent response socket pool: dest → socket (shared by DNS hijack and SOCKS5 responses)
        let resp_socks = Arc::new(RespSocketPool::new());

        // Register the fd with the tokio reactor, driving recvmsg by readability (fd stays non-blocking)
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

                    // Per-packet logging (info would flood under high-frequency UDP like QUIC/games; use debug)
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
                                        match tokio::time::timeout(
                                            UDP_WRITE_TIMEOUT,
                                            resp_sock.send_to(&recv_buf, peer),
                                        )
                                        .await
                                        {
                                            Ok(Ok(_)) => {}
                                            Ok(Err(e)) => debug!(
                                                "DNS hijack: response send_to client {} failed: {}",
                                                peer, e
                                            ),
                                            Err(_) => debug!(
                                                "DNS hijack: response send_to client {} timed out",
                                                peer
                                            ),
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
                    // Flows are reused by (dest, peer): sends complete immediately, and responses
                    // are sent back by the flow's reader task (send and recv are decoupled,
                    // no lock held while waiting).
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

                        // Forward the datagram through the protocol's UDP session (no lock needed;
                        // each protocol handles it internally).
                        // Write deadline protection: prevents indefinite blocking when upstream stalls.
                        let send_fut = session.send(&dest, &payload);
                        match tokio::time::timeout(UDP_WRITE_TIMEOUT, send_fut).await {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => {
                                debug!("UDP send to relay failed: {}", e);
                                flows.remove(dest, peer).await;
                            }
                            Err(_) => {
                                debug!("UDP send to relay timed out after {}s", UDP_WRITE_TIMEOUT.as_secs());
                                flows.remove(dest, peer).await;
                            }
                        }
                    });
                }
            }
        }

        Ok(())
    }

    /// Stop the UDP TProxy listener
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.stop_signal.notify_one();
        info!("UDP TProxy listener stop signal sent");
    }
}

// ============================================================================
// UDP flow pool & response socket pool
// ============================================================================

/// A UDP relay flow: a protocol-agnostic UDP session + a dedicated reader task.
///
/// The reader task continuously receives relay responses (original destination address +
/// payload) from the session and sends them back to the corresponding client through the
/// pooled transparent response socket. This way the sender returns immediately after `send()`,
/// and concurrent packets in the same flow are not serialized by a mutex.
struct UdpRelayFlow {
    session: Arc<dyn UdpSession>,
    /// Reader task handle (removes itself from the pool on idle timeout or error)
    #[allow(dead_code)]
    reader: tokio::task::JoinHandle<()>,
}

/// UDP flow pool, reusing sessions by (original destination address, client address).
///
/// Keying by (dest, peer) is needed because the relay response header only carries the
/// destination address, not the client info; one flow corresponds to one client so the
/// response can be sent back accurately.
struct UdpFlowPool {
    inner: tokio::sync::Mutex<HashMap<(SocketAddr, Option<SocketAddr>), UdpRelayFlow>>,
}

impl UdpFlowPool {
    fn new() -> Self {
        Self {
            inner: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Get or create the session for (dest, peer).
    ///
    /// Session creation (TCP handshake + ASSOCIATE) happens outside the lock; the lock is
    /// only briefly held for insertion, avoiding concurrent creation of the same flow from
    /// blocking each other.
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

        // Create the protocol-specific UDP relay session via the dialer (in the host NS).
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

    /// Start the flow's reader task: continuously read relay responses and send them back
    /// to the client.
    ///
    /// Exits when idle beyond the tiered timeout ([`udp_flow_idle_timeout`]: DNS 17s / QUIC
    /// 2min / default 30s) or when the relay recv errors, and removes itself from the pool
    /// (replacing the never-called `UdpEndpointPool::cleanup`).
    fn spawn_reader(
        key: (SocketAddr, Option<SocketAddr>),
        session: Arc<dyn UdpSession>,
        resp_socks: Arc<RespSocketPool>,
        host_ns_fd: Option<RawFd>,
        flows: std::sync::Weak<UdpFlowPool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let (dest, peer) = key;
            let idle_timeout = udp_flow_idle_timeout(dest);
            loop {
                let read = tokio::time::timeout(idle_timeout, session.recv()).await;
                let (resp_dest, payload) = match read {
                    Ok(Ok(pkt)) => pkt,
                    Ok(Err(e)) => {
                        debug!("UDP relay recv error: {}", e);
                        break;
                    }
                    Err(_) => {
                        debug!(
                            "UDP relay flow idle ({}s), expiring: {}",
                            idle_timeout.as_secs(),
                            peer.map(|p| p.to_string()).unwrap_or_default(),
                        );
                        break;
                    }
                };

                // Full-cone relay: the response may come from any destination, so the
                // response socket is taken by the response's destination address.
                if let Some(peer) = peer {
                    if let Some(sock) = resp_socks.get(&resp_dest, host_ns_fd).await {
                        // Response write deadline: prevents blocking the reader forever when
                        // the client is not reading UDP.
                        match tokio::time::timeout(UDP_WRITE_TIMEOUT, sock.send_to(&payload, peer))
                            .await
                        {
                            Ok(Ok(_)) => {}
                            Ok(Err(e)) => debug!("UDP response send failed: {}", e),
                            Err(_) => debug!(
                                "UDP response send to {} timed out after {}s",
                                peer,
                                UDP_WRITE_TIMEOUT.as_secs()
                            ),
                        }
                    } else {
                        debug!(
                            "UDP response: failed to get TProxy response socket for {}",
                            resp_dest
                        );
                    }
                }
            }
            // Reader exit (idle/error): remove itself from the pool
            if let Some(flows) = flows.upgrade() {
                flows.remove(dest, peer).await;
            }
        })
    }
}

/// Transparent response socket pool: reuses IP_TRANSPARENT UDP sockets by original destination.
///
/// One socket per dest, lazily created (in the host NS when host_ns_fd is configured),
/// with an LRU capacity limit to prevent unbounded growth. DNS hijack responses and
/// SOCKS5 responses share this pool.
struct RespSocketPool {
    inner: Mutex<VecDeque<(SocketAddr, Arc<UdpSocket>)>>,
}

impl RespSocketPool {
    fn new() -> Self {
        Self {
            inner: Mutex::new(VecDeque::new()),
        }
    }

    /// Get the response socket for dest; create and cache it if absent.
    async fn get(
        &self,
        dest: &SocketAddr,
        host_ns_fd: Option<RawFd>,
    ) -> Option<Arc<UdpSocket>> {
        // Fast path: already in the pool (no lock held across await)
        {
            let mut m = self.inner.lock().unwrap();
            if let Some(i) = m.iter().position(|(d, _)| d == dest) {
                let (_, sock) = m.remove(i).unwrap();
                m.push_back((*dest, sock.clone()));
                return Some(sock);
            }
        }

        // Slow path: create (may setns into the host NS, so the lock cannot be held)
        let sock = Arc::new(create_marked_udp_socket(dest, host_ns_fd).await?);
        let mut m = self.inner.lock().unwrap();
        if let Some(i) = m.iter().position(|(d, _)| d == dest) {
            // Concurrent creation race: someone else already inserted, just use theirs
            return Some(m[i].1.clone());
        }
        m.push_back((*dest, sock.clone()));
        while m.len() > RESP_SOCKET_POOL_CAP {
            m.pop_front();
        }
        Some(sock)
    }
}

/// Non-blocking recvmsg: returns `(byte count, peer address, original destination address)`.
///
/// Gets the TProxy original destination address via ancillary data (cmsg); the fd must
/// be non-blocking.
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
    // Use zeroed + field assignment instead of a struct literal:
    // musl's msghdr contains private fields (such as __pad1/__pad2 on x86_64),
    // which cannot be constructed with a literal
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut msg_name as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    // musl and glibc have different msg_controllen types (int vs size_t); use type inference
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

/// Create a UDP socket with IP_TRANSPARENT and SO_MARK=0x100, bound to the target address.
///
/// Used for DNS hijacking and UDP responses: IP_TRANSPARENT allows binding a non-local
/// address (such as the upstream DNS server address), ensuring the response packet's
/// source address is correct; SO_MARK=0x100 lets eBPF let it through (dae-rs's own
/// traffic must connect directly). Delegates to the unified
/// [`protocols::hostns::create_transparent_udp`] implementation.
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

/// Parse the original destination address from ancillary data (cmsg/oob)
///
/// This is the key function for UDP TProxy to obtain the original destination address.
/// When `IP_RECVORIGDSTADDR` is set, the kernel returns the packet's original destination
/// address in recvmsg's ancillary data.
///
/// Uses the `libc::cmsghdr` struct to read the cmsg header, letting the compiler handle
/// the `cmsg_len` size and alignment differences per target architecture
/// (8 bytes for `cmsg_len` on 64-bit systems, 4 bytes on 32-bit), avoiding
/// cross-architecture compatibility issues from hardcoding `u64` parsing.
///
/// # Parameters
///
/// * `cmsg_data` — the ancillary data (cmsg) buffer
///
/// # Returns
///
/// Returns `Some(SocketAddr)` if the original destination address is successfully parsed.
pub fn parse_orig_dst_from_cmsg(cmsg_data: &[u8]) -> Option<SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    // libc::cmsghdr layout on different architectures:
    // - 64-bit: cmsg_len(usize=8) + cmsg_level(i32) + cmsg_type(i32) = 16 bytes
    // - 32-bit: cmsg_len(usize=4) + cmsg_level(i32) + cmsg_type(i32) = 12 bytes
    let hdr_size = std::mem::size_of::<libc::cmsghdr>();
    // CMSG_ALIGN uses size_t for alignment
    let cmsg_align = std::mem::size_of::<libc::size_t>();
    let mut offset = 0;

    while offset + hdr_size <= cmsg_data.len() {
        // Read the cmsg header with libc::cmsghdr, reading the cmsg_len, cmsg_level and
        // cmsg_type fields, letting the compiler handle the cmsg_len size difference across
        // architectures (32-bit: u32, 64-bit: u64), instead of hardcoded u64 parsing.
        let cmsg = unsafe {
            std::ptr::read_unaligned(cmsg_data[offset..].as_ptr() as *const libc::cmsghdr)
        };

        let cmsg_len = cmsg.cmsg_len as usize;

        // cmsg_len must at least include the header size and not exceed the remaining buffer
        if cmsg_len < hdr_size || offset + cmsg_len > cmsg_data.len() {
            break;
        }

        // CMSG_DATA offset: immediately after the header, aligned to CMSG_ALIGN(size_t).
        // Equivalent to the Linux kernel macro:
        // CMSG_DATA(cmsg) = (unsigned char *)cmsg + CMSG_ALIGN(sizeof(*cmsg))
        let data_offset = (offset + hdr_size + cmsg_align - 1) & !(cmsg_align - 1);

        if cmsg.cmsg_level == libc::SOL_IP && cmsg.cmsg_type == IP_RECVORIGDSTADDR {
            // IPv4: the data is a struct sockaddr_in (16 bytes)
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
            // IPv6: the data is a struct sockaddr_in6 (28 bytes)
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

        // Move to the next cmsg (aligned by CMSG_ALIGN)
        offset = (offset + cmsg_len + cmsg_align - 1) & !(cmsg_align - 1);
    }

    None
}
