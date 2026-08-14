//! DNS forwarder — 纯用户空间 DNS 转发器。
//!
//! 监听 dae 内部地址（默认 `169.254.0.1:53`，不对外暴露），按域名规则分流转发查询：
//!
//! - **命中 `proxy_domains` 的域名** → 换用 `proxy_dns_servers`，经代理转发
//!   （复用 [`OutboundDialer::udp_dial`] 的 full-cone UDP 会话，与现有 UDP 数据面一致）；
//! - **其余域名** → 用 `direct_dns_servers`（为空则回退系统 `/etc/resolv.conf`），
//!   在 host NS 直连。
//!
//! 响应**原样透传**（不解析答案、不改写 ID/TTL），保持透明转发语义。
//!
//! # 数据流
//!
//! ```text
//! 本机进程 DNS 查询 ──> 169.254.0.1:53 (host NS lo 上的地址, 本地交付)
//!      │
//!      ▼
//!  DnsForwarder
//!      │  1. 解析 query（域名 + qtype，最小报文解析）
//!      │  2. 域名分流
//!      │     ├─ 命中 proxy_domains ──> 换用 proxy_dns_servers, 走代理
//!      │     │                        (dialer.udp_dial() → UdpSession::send/recv)
//!      │     └─ 否则 ──> 用系统 DNS(/etc/resolv.conf), host NS 直连
//!      │  3. 响应透传
//!      ▼
//!  客户端
//! ```

use crate::config::DnsConfig;
use anyhow::{Context, Result};
use protocols::hostns::{with_host_ns, DirectSocket};
use protocols::OutboundDialer;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

/// 最大 UDP 报文长度（DNS 走 UDP 理论上限 65535）。
const MAX_UDP_SIZE: usize = 65535;
/// DNS 报文头部长度。
const DNS_HEADER_LEN: usize = 12;

/// A parsed DNS query: only the question is needed to pick an upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    /// DNS 事务 ID（透传响应时保持原样）。
    pub id: u16,
    /// 查询域名（小写、无末尾点，如 `example.com`）。
    pub qname: String,
    /// 查询类型（如 1=A, 28=AAAA, 5=CNAME）。
    pub qtype: u16,
}

/// 解析 DNS 查询报文的最小实现：只读取 header + 第一个 question。
///
/// 不做压缩指针 / EDNS 等高级处理——查询报文里 question 的 QNAME 通常为普通
/// label 序列；遇到压缩指针或非法结构返回 `None`（调用方按无法分流处理）。
pub fn parse_dns_query(buf: &[u8]) -> Option<DnsQuery> {
    if buf.len() < DNS_HEADER_LEN {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut pos = DNS_HEADER_LEN;
    let mut labels: Vec<String> = Vec::new();
    loop {
        if pos >= buf.len() {
            return None;
        }
        let len = buf[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        // 0xC0 0xC1: 压缩指针（查询报文不应出现，保守返回 None）
        if len & 0xC0 == 0xC0 || len > 63 || pos + 1 + len > buf.len() {
            return None;
        }
        let label = std::str::from_utf8(&buf[pos + 1..pos + 1 + len])
            .ok()?
            .to_ascii_lowercase();
        labels.push(label);
        pos += 1 + len;
    }
    if pos + 4 > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);

    Some(DnsQuery {
        id,
        qname: labels.join("."),
        qtype,
    })
}

/// 读取系统 DNS 服务器（`/etc/resolv.conf` 的 `nameserver` 行）。
///
/// 兼容 `127.0.0.53`（systemd-resolved）、带端口的 `ip:port` 形式。读取失败
/// 返回空列表（调用方需保证至少有一个直连上游，否则直连查询会失败）。
pub fn read_system_dns() -> Vec<SocketAddr> {
    let mut out = Vec::new();
    let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") else {
        return out;
    };
    for line in content.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("nameserver") else {
            continue;
        };
        let ns = rest.trim();
        if let Ok(ip) = ns.parse::<IpAddr>() {
            out.push(SocketAddr::new(ip, 53));
        } else if let Ok(sa) = ns.parse::<SocketAddr>() {
            out.push(sa);
        }
    }
    out
}

/// DNS 转发器。
pub struct DnsForwarder {
    /// 监听地址（内部地址，默认 `169.254.0.1:53`）。
    listen_addr: SocketAddr,
    /// 代理域名换用的 DNS 服务器。
    proxy_dns_servers: Vec<SocketAddr>,
    /// 直连域名使用的 DNS 服务器（空 → 回退系统 DNS）。
    direct_dns_servers: Vec<SocketAddr>,
    /// 直连域名是否回退到系统 DNS。
    direct_use_system_dns: bool,
    /// 命中即走代理的域名后缀（精确域名或 `.suffix` 结尾）。
    proxy_domains: Vec<String>,
    /// 代理拨号器（`proxy_domains` 非空时必需）。
    dialer: Option<Arc<dyn OutboundDialer>>,
    /// Host 网络命名空间 fd（用于在 host NS 创建上游 socket / 监听 socket）。
    host_ns_fd: Option<RawFd>,
    /// 上游查询超时。
    query_timeout: Duration,
    /// 运行标志。
    running: Arc<AtomicBool>,
    /// 停止信号。
    stop_signal: Arc<Notify>,
}

impl DnsForwarder {
    /// 构建转发器。
    ///
    /// * `cfg` — DNS 配置（`listen_addr` / 上游 / 分流规则）。
    /// * `dialer` — 代理拨号器；仅当配置了 `proxy_domains` 时需要。
    /// * `host_ns_fd` — host 网络命名空间 fd（`None` = 当前命名空间）。
    ///
    /// # Errors
    ///
    /// 配置了 `proxy_domains` 但没有可用拨号器时返回错误（配置不完整）。
    pub fn new(
        cfg: &DnsConfig,
        dialer: Option<Arc<dyn OutboundDialer>>,
        host_ns_fd: Option<RawFd>,
    ) -> Result<Self> {
        if !cfg.proxy_domains.is_empty() && dialer.is_none() {
            anyhow::bail!(
                "DNS forwarder: proxy_domains configured ({} rules) but no outbound dialer available",
                cfg.proxy_domains.len()
            );
        }

        let listen_addr = cfg
            .listen_addr
            .parse::<SocketAddr>()
            .with_context(|| format!("invalid dns.listen_addr '{}'", cfg.listen_addr))?;
        let proxy_dns_servers = parse_servers(&cfg.proxy_dns_servers, "dns.proxy_dns_servers")?;
        let direct_dns_servers =
            parse_servers(&cfg.direct_dns_servers, "dns.direct_dns_servers")?;

        let mut proxy_domains: Vec<String> = cfg
            .proxy_domains
            .iter()
            .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
        proxy_domains.sort();
        proxy_domains.dedup();

        Ok(Self {
            listen_addr,
            proxy_dns_servers,
            direct_dns_servers,
            direct_use_system_dns: cfg.direct_use_system_dns,
            proxy_domains,
            dialer,
            host_ns_fd,
            query_timeout: Duration::from_millis(cfg.query_timeout_ms),
            running: Arc::new(AtomicBool::new(false)),
            stop_signal: Arc::new(Notify::new()),
        })
    }

    /// 监听地址。
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// 是否有需要走代理的域名规则。
    pub fn needs_proxy(&self) -> bool {
        !self.proxy_domains.is_empty()
    }

    /// 开始接收循环（UDP）。
    ///
    /// 监听 socket 在 host NS 创建（`host_ns_fd` 非空时），因此调用方应确保
    /// `listen_addr` 已配置到对应命名空间（如 host NS `lo` 上的 `169.254.0.1`）。
    pub async fn start(self: &Arc<Self>) -> Result<()> {
        let sock = self.bind_udp().await?;
        self.running.store(true, Ordering::SeqCst);
        info!(
            listen = %self.listen_addr,
            proxy_domains = self.proxy_domains.len(),
            proxy_dns = self.proxy_dns_servers.len(),
            "DNS forwarder started"
        );

        let this = self.clone();
        this.run_udp_loop(sock).await
    }

    /// 停止接收循环（正在处理的查询不受影响）。
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.stop_signal.notify_waiters();
        info!("DNS forwarder stop signal sent");
    }

    /// 在 host NS 绑定监听 socket。
    async fn bind_udp(&self) -> Result<UdpSocket> {
        let listen = self.listen_addr;
        let host_ns_fd = self.host_ns_fd;
        let std_sock = with_host_ns(host_ns_fd, || bind_udp_in_ns(listen)).with_context(|| {
            format!("Failed to bind DNS forwarder UDP socket to {}", self.listen_addr)
        })?;
        let sock = tokio::net::UdpSocket::from_std(std_sock)
            .context("Failed to convert DNS forwarder socket to tokio")?;
        Ok(sock)
    }

    /// UDP 接收主循环：每收到一个查询 spawn 一个处理任务。
    async fn run_udp_loop(self: Arc<Self>, sock: UdpSocket) -> Result<()> {
        let sock = Arc::new(sock);
        let mut buf = vec![0u8; MAX_UDP_SIZE];
        loop {
            tokio::select! {
                _ = self.stop_signal.notified() => {
                    info!("DNS forwarder stopping via signal");
                    break;
                }
                r = sock.recv_from(&mut buf) => {
                    let (n, client) = match r {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("DNS forwarder recv error: {}", e);
                            continue;
                        }
                    };
                    let query = buf[..n].to_vec();
                    let this = self.clone();
                    let sock = sock.clone();
                    tokio::spawn(async move {
                        if let Err(e) = this.handle_query(&query, client, &sock).await {
                            debug!(
                                client = %client,
                                error = %e,
                                "DNS query handling failed"
                            );
                        }
                    });
                }
            }
        }
        Ok(())
    }

    /// 处理单个 DNS 查询：解析 → 分流 → 转发 → 响应透传。
    async fn handle_query(
        &self,
        query: &[u8],
        client: SocketAddr,
        sock: &UdpSocket,
    ) -> Result<()> {
        let response = self.resolve(query).await?;
        // 响应透传（保持原始 ID，客户端与我们的查询 ID 一致）
        sock.send_to(&response, client)
            .await
            .context("DNS response send_to failed")?;
        debug!(
            client = %client,
            resp_bytes = response.len(),
            "DNS response relayed"
        );
        Ok(())
    }

    /// 解析单个 DNS 查询并返回上游响应（不含回发逻辑）。
    ///
    /// 供两个入口复用：
    /// - 监听版 [`DnsForwarder::start`] 的接收循环（`handle_query`）；
    /// - TProxy 数据面（[`crate::net::tproxy::UdpTproxyListener`]）识别出 53 端口
    ///   DNS 流量后调用——eBPF 无需改动，DNS 仍按普通 UDP 拦截进 TProxy，
    ///   仅在用户空间改走本模块。
    pub async fn resolve(&self, query: &[u8]) -> Result<Vec<u8>> {
        let parsed = parse_dns_query(query).context("unparseable DNS query")?;
        let via_proxy = self.route_domain(&parsed.qname);
        if via_proxy {
            let server = self
                .proxy_dns_servers
                .first()
                .copied()
                .context("no proxy DNS server configured")?;
            debug!(
                domain = %parsed.qname,
                qtype = parsed.qtype,
                via = "proxy",
                server = %server,
                "DNS query routed via proxy"
            );
            self.forward_via_proxy(query, server).await
        } else {
            let server = self.pick_direct_server()?;
            debug!(
                domain = %parsed.qname,
                qtype = parsed.qtype,
                via = "direct",
                server = %server,
                "DNS query routed direct"
            );
            self.forward_direct(query, server).await
        }
    }

    /// 域名分流：返回 true 表示走代理。
    fn route_domain(&self, qname: &str) -> bool {
        if self.proxy_domains.is_empty() {
            return false;
        }
        let qname = qname.trim_end_matches('.');
        self.proxy_domains.iter().any(|suffix| {
            qname == suffix || qname.ends_with(&format!(".{}", suffix))
        })
    }

    /// 选择直连上游：优先 `direct_dns_servers`，其次系统 DNS。
    fn pick_direct_server(&self) -> Result<SocketAddr> {
        if let Some(addr) = self.direct_dns_servers.first().copied() {
            return Ok(addr);
        }
        if self.direct_use_system_dns {
            if let Some(addr) = read_system_dns().into_iter().next() {
                return Ok(addr);
            }
        }
        anyhow::bail!(
            "DNS forwarder: no direct upstream available \
             (dns.direct_dns_servers empty and system DNS unavailable)"
        )
    }

    /// 直连转发：在 host NS 创建 UDP socket，发到 `server`，等待响应。
    async fn forward_direct(&self, query: &[u8], server: SocketAddr) -> Result<Vec<u8>> {
        let sock = DirectSocket::control_plane(self.host_ns_fd);
        let udp = protocols::hostns::create_udp(server, &sock)?;
        let udp = tokio::net::UdpSocket::from_std(udp)
            .context("DNS forward_direct: from_std failed")?;
        udp.send_to(query, server)
            .await
            .context("DNS forward_direct: send_to failed")?;
        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let (n, _) = tokio::time::timeout(self.query_timeout, udp.recv_from(&mut buf))
            .await
            .with_context(|| format!("DNS direct query to {} timed out", server))??;
        buf.truncate(n);
        Ok(buf)
    }

    /// 代理转发：经 `dialer.udp_dial()` 的 full-cone UDP 会话发送到 `server`。
    async fn forward_via_proxy(&self, query: &[u8], server: SocketAddr) -> Result<Vec<u8>> {
        let dialer = self
            .dialer
            .as_ref()
            .context("DNS forward_via_proxy: no outbound dialer")?;
        let session = dialer
            .udp_dial()
            .await
            .context("DNS forward_via_proxy: udp_dial failed")?;
        session
            .send(&server, query)
            .await
            .with_context(|| format!("DNS proxy query to {} send failed", server))?;
        let (_resp_dest, payload) = tokio::time::timeout(self.query_timeout, session.recv())
            .await
            .with_context(|| format!("DNS proxy query to {} timed out", server))??;
        Ok(payload.to_vec())
    }
}

/// 解析 `ip:port` 服务器列表（允许 `ip` 缺省端口时补 53）。
fn parse_servers(list: &[String], field: &str) -> Result<Vec<SocketAddr>> {
    let mut out = Vec::new();
    for s in list {
        let s = s.trim();
        if s.is_empty() {
            continue;
        }
        if let Ok(ip) = s.parse::<IpAddr>() {
            out.push(SocketAddr::new(ip, 53));
        } else if let Ok(sa) = s.parse::<SocketAddr>() {
            out.push(sa);
        } else {
            anyhow::bail!("invalid {} entry '{}'", field, s);
        }
    }
    Ok(out)
}

/// 在**当前**网络命名空间创建绑定到 `listen` 的 UDP socket。
///
/// 由 [`with_host_ns`] 包裹调用以在 host NS 内执行。
fn bind_udp_in_ns(listen: SocketAddr) -> io::Result<std::net::UdpSocket> {
    use std::os::unix::io::AsRawFd;

    let domain = if listen.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // SO_REUSEADDR：允许快速重启时复用 TIME_WAIT / 已关闭端口
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    let sock_addr = socket2::SockAddr::from(listen);
    if unsafe { libc::bind(fd, sock_addr.as_ptr() as *const libc::sockaddr, sock_addr.len()) }
        != 0
    {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    std_sock.set_nonblocking(true)?;
    let _ = std_sock.as_raw_fd(); // keep AsRawFd import used
    Ok(std_sock)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn build_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&[0x01, 0x00]); // RD=1
        buf.extend_from_slice(&[0, 1]); // QDCOUNT=1
        buf.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR
        for label in qname.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&[0, 1]); // CLASS=IN
        buf
    }

    #[test]
    fn test_parse_dns_query_basic() {
        let q = build_query(0x1234, "example.com", 1);
        let parsed = parse_dns_query(&q).expect("should parse");
        assert_eq!(parsed.id, 0x1234);
        assert_eq!(parsed.qname, "example.com");
        assert_eq!(parsed.qtype, 1);
    }

    #[test]
    fn test_parse_dns_query_aaaa_and_case() {
        let q = build_query(1, "Www.Example.COM", 28);
        let parsed = parse_dns_query(&q).unwrap();
        assert_eq!(parsed.qname, "www.example.com");
        assert_eq!(parsed.qtype, 28);
    }

    #[test]
    fn test_parse_dns_query_truncated() {
        assert!(parse_dns_query(&[]).is_none());
        assert!(parse_dns_query(&[0u8; 11]).is_none());
        // header with QDCOUNT=0 → no question
        let mut q = vec![0u8; 12];
        assert!(parse_dns_query(&q).is_none());
        q[5] = 1; // QDCOUNT=1 but no question bytes
        assert!(parse_dns_query(&q).is_none());
    }

    #[test]
    fn test_route_domain_suffix() {
        let cfg = DnsConfig {
            proxy_domains: vec!["google.com".into(), "example.org".into()],
            ..Default::default()
        };
        // proxy_domains 非空需要拨号器；用指向不可达地址的 SOCKS5 拨号器即可（不实际连接）。
        let dialer: std::sync::Arc<dyn OutboundDialer> =
            std::sync::Arc::new(protocols::Socks5Dialer::new(
                "127.0.0.1:1".parse().unwrap(),
                "",
                "",
                1000,
            ));
        let f = DnsForwarder::new(&cfg, Some(dialer), None).unwrap();
        assert!(f.route_domain("google.com"));
        assert!(f.route_domain("www.google.com"));
        assert!(f.route_domain("a.b.example.org"));
        assert!(!f.route_domain("notgoogle.com"));
        assert!(!f.route_domain("example.com")); // 精确后缀才匹配，不反向包含
        assert!(!f.route_domain("other.com"));
    }

    #[test]
    fn test_route_domain_empty_rules() {
        let f = DnsForwarder::new(&DnsConfig::default(), None, None).unwrap();
        assert!(!f.needs_proxy());
        assert!(!f.route_domain("anything.com"));
    }

    #[test]
    fn test_proxy_domains_require_dialer() {
        let cfg = DnsConfig {
            proxy_domains: vec!["google.com".into()],
            ..Default::default()
        };
        assert!(DnsForwarder::new(&cfg, None, None).is_err());
    }

    #[test]
    fn test_parse_servers_ports() {
        let list = vec!["8.8.8.8".into(), "1.1.1.1:5353".into()];
        let servers = parse_servers(&list, "test").expect("valid entries should parse");
        assert_eq!(
            servers,
            vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 5353),
            ]
        );
    }

    #[test]
    fn test_parse_servers_invalid() {
        let list = vec!["not an address".into()];
        assert!(parse_servers(&list, "test").is_err());
    }

    #[test]
    fn test_read_system_dns_never_panics() {
        // 只验证不 panic（沙箱/CI 中 /etc/resolv.conf 内容不定）
        let _ = read_system_dns();
    }

    #[tokio::test]
    async fn test_resolve_rejects_invalid_query() {
        let f = DnsForwarder::new(&DnsConfig::default(), None, None).unwrap();
        // 非法/截断报文 → 解析失败即返回，不发起任何网络转发
        assert!(f.resolve(&[]).await.is_err());
        assert!(f.resolve(&[0u8; 12]).await.is_err());
    }
}
