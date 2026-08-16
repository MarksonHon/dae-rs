//! DNS forwarder — 纯用户空间 DNS 转发器。
//!
//! **DNS 自身不定义代理规则**：一个查询走哪个代理组（或直连/阻断）由现有
//! `routing` 规则的 `domain(...)` / `target_domain(...)` 推导——域名命中哪个组
//! 的代理规则，查询就走哪个组。每个代理组（含直连）独立维护 DNS 缓存，遵循
//! 响应 TTL。
//!
//! 两个入口：
//! - 监听版：绑定内部地址（默认 `169.254.0.1:53`，仅 dae 内部、不对外）；
//! - TProxy 注入版：[`crate::net::tproxy::UdpTproxyListener`] 识别 53 端口 DNS
//!   流量后调用 [`DnsForwarder::resolve`]（eBPF 不改动）。
//!
//! 转发复用现有抽象：
//! - 代理组 → [`OutboundDialer::udp_dial`] 的 full-cone UDP 会话；
//! - 直连 → [`protocols::hostns::create_udp`]（host NS 直连系统 DNS）。
//!
//! # 数据流
//!
//! ```text
//! DNS 查询（监听版 169.254.0.1:53 或 TProxy 识别 53 端口）
//!      │  1. 解析 query（域名 + qtype，最小报文解析）
//!      ▼  2. route_domain：用 routing 的 domain 规则判定走向
//!  DnsForwarder        ├─ 命中组 A → 组 A 拨号器转发（组 A 独立缓存）
//!      │               ├─ 命中组 B → 组 B 拨号器转发（组 B 独立缓存）
//!      │               ├─ direct   → host NS 直连系统 DNS（direct 独立缓存）
//!      │               └─ block    → 返回 NXDOMAIN
//!      │  3. 未命中缓存 → 转发 → 解析 TTL 存入所属组的缓存
//!      ▼  4. 响应透传（缓存命中时重写事务 ID）
//!  客户端
//! ```

use crate::config::DnsConfig;
use crate::group::GroupDialer;
use crate::routing::matcher::{DnsDomainRoute, DnsOutbound};
use anyhow::{Context, Result};
use protocols::hostns::{with_host_ns, DirectSocket};
use protocols::{OutboundDialer, UdpSession};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
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
    /// 查询是否携带 EDNS(0) OPT 记录（影响响应是否含 OPT）。
    pub has_edns: bool,
    /// EDNS DO 位（DNSSEC OK）：影响响应是否包含 RRSIG 等 DNSSEC 记录。
    pub do_bit: bool,
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
    pos += 4; // QTYPE + QCLASS

    // 扫描 additional 段，识别 EDNS(0) OPT 记录与 DO 位（影响响应内容与缓存键）。
    let (has_edns, do_bit) = parse_edns(buf, pos);

    Some(DnsQuery {
        id,
        qname: labels.join("."),
        qtype,
        has_edns,
        do_bit,
    })
}

/// 扫描 DNS 报文 additional 段，寻找 EDNS(0) OPT 记录（TYPE 41）。
///
/// OPT 的 TTL 字段（4 字节）编码为：ext-rcode(8) | version(8) | DO+Z(8) | Z(16)，
/// DO 位是第 3 个字节的最高位（bit 15）。返回 `(has_edns, do_bit)`。
fn parse_edns(buf: &[u8], mut pos: usize) -> (bool, bool) {
    const TYPE_OPT: u16 = 41;
    loop {
        if pos + 11 > buf.len() {
            return (false, false);
        }
        pos = match skip_name(buf, pos) {
            Some(p) => p,
            None => return (false, false),
        };
        if pos + 10 > buf.len() {
            return (false, false);
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ttl = [buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]];
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > buf.len() {
            return (false, false);
        }
        if rtype == TYPE_OPT {
            return (true, ttl[2] & 0x80 != 0);
        }
        pos += rdlength;
    }
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
/// 直连路径 in-flight 查询合并的键（与缓存键一致：域/类型/EDNS/DO）。
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct FlightKey {
    outbound: String,
    qname: String,
    qtype: u16,
    has_edns: bool,
    do_bit: bool,
}

pub struct DnsForwarder {
    /// 监听地址（内部地址，默认 `169.254.0.1:53`）。
    listen_addr: SocketAddr,
    /// 走代理的查询使用的上游 DNS 服务器（取第一个）。
    proxy_dns_servers: Vec<SocketAddr>,
    /// 直连查询使用的 DNS 服务器（空 → 回退系统 DNS）。
    direct_dns_servers: Vec<SocketAddr>,
    /// 直连查询是否回退到系统 DNS。
    direct_use_system_dns: bool,
    /// 上游查询超时。
    query_timeout: Duration,
    /// 是否启用按组隔离的 TTL 缓存。
    enable_cache: bool,
    /// DNS 域名路由（来自数据面 routing 规则）。
    routes: Vec<DnsDomainRoute>,
    /// 代理组名 → 拨号器。
    group_dialers: HashMap<String, Arc<dyn OutboundDialer>>,
    /// 未命中 domain 规则时的 fallback 走向。
    fallback: DnsOutbound,
    /// Host 网络命名空间 fd（用于在 host NS 创建上游 socket / 监听 socket）。
    host_ns_fd: Option<RawFd>,
    /// 每组（含 direct）独立 DNS 缓存：outbound key → cache。
    caches: Mutex<HashMap<String, Arc<Mutex<DnsCache>>>>,
    /// 每个代理组的持久 UDP 会话（组名 → (建会话时的节点名, 会话)），复用避免每个
    /// 查询重新握手（SOCKS5 的 TCP+UDP ASSOCIATE、TUIC/Juicity 的全新 QUIC 连接都很
    /// 昂贵）。记录节点名用于在建会话的节点失效/切换后识别并重建会话。
    proxy_sessions: Mutex<HashMap<String, (String, Arc<dyn UdpSession>)>>,
    /// 每组合并锁：持久会话共享时同一时刻每组至多一个 in-flight 查询。
    group_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// 直连路径 in-flight 查询合并：key → 完成通知器。同一 key（域/类型/EDNS/DO）
    /// 的并发查询共享一次上游请求——发起者转发并写缓存后唤醒等待者重查缓存。
    inflight: Mutex<HashMap<FlightKey, Arc<Notify>>>,
    /// 运行标志。
    running: Arc<AtomicBool>,
    /// 停止信号。
    stop_signal: Arc<Notify>,
}

impl DnsForwarder {
    /// 构建转发器。
    ///
    /// * `cfg` — DNS 配置（`listen_addr` / 上游 DNS / 缓存开关）。
    /// * `routes` — 从数据面 `routing` 规则构建的 DNS 域名路由表。
    /// * `group_dialers` — 代理组名 → 拨号器（用于把查询交给对应组）。
    /// * `fallback` — 未命中 domain 规则时的 DNS 走向（来自 `routing.fallback`）。
    /// * `host_ns_fd` — host 网络命名空间 fd（`None` = 当前命名空间）。
    ///
    /// # Errors
    ///
    /// `listen_addr` / DNS 服务器列表解析失败时返回错误。
    pub fn new(
        cfg: &DnsConfig,
        routes: Vec<DnsDomainRoute>,
        group_dialers: HashMap<String, Arc<dyn OutboundDialer>>,
        fallback: DnsOutbound,
        host_ns_fd: Option<RawFd>,
    ) -> Result<Self> {
        let listen_addr = cfg
            .listen_addr
            .parse::<SocketAddr>()
            .with_context(|| format!("invalid dns.listen_addr '{}'", cfg.listen_addr))?;
        let proxy_dns_servers = parse_servers(&cfg.proxy_dns_servers, "dns.proxy_dns_servers")?;
        let direct_dns_servers =
            parse_servers(&cfg.direct_dns_servers, "dns.direct_dns_servers")?;

        Ok(Self {
            listen_addr,
            proxy_dns_servers,
            direct_dns_servers,
            direct_use_system_dns: cfg.direct_use_system_dns,
            query_timeout: Duration::from_millis(cfg.query_timeout_ms),
            enable_cache: cfg.enable_cache,
            routes,
            group_dialers,
            fallback,
            host_ns_fd,
            caches: Mutex::new(HashMap::new()),
            proxy_sessions: Mutex::new(HashMap::new()),
            group_locks: Mutex::new(HashMap::new()),
            inflight: Mutex::new(HashMap::new()),
            running: Arc::new(AtomicBool::new(false)),
            stop_signal: Arc::new(Notify::new()),
        })
    }

    /// 监听地址。
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
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
            domain_routes = self.routes.len(),
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
    ///
    /// 走向由现有 `routing` 规则的 domain 规则推导（见 [`DnsForwarder::route_domain`]），
    /// 每个代理组（含直连）独立缓存、遵循 TTL。
    pub async fn resolve(&self, query: &[u8]) -> Result<Vec<u8>> {
        let parsed = parse_dns_query(query).context("unparseable DNS query")?;
        let outbound = self.route_domain(&parsed.qname);
        // INFO：每次 DNS 查询记录域名走了哪个代理组（或直连/阻断）。
        info!(
            domain = %parsed.qname,
            via = %dns_outbound_label(&outbound),
            "DNS query"
        );

        match outbound {
            DnsOutbound::Block => {
                Ok(build_error_response(query, 3)) // NXDOMAIN
            }
            DnsOutbound::Direct => {
                let server = self.pick_direct_server()?;
                let cache = self.get_cache("direct");
                if let Some(resp) = self.cached_lookup(
                    &cache,
                    &parsed.qname,
                    parsed.qtype,
                    parsed.has_edns,
                    parsed.do_bit,
                    parsed.id,
                ) {
                    return Ok(resp);
                }
                // In-flight 合并：同 key（域/类型/EDNS/DO）的并发查询共享一次上游请求。
                let fkey = FlightKey {
                    outbound: "direct".to_string(),
                    qname: parsed.qname.clone(),
                    qtype: parsed.qtype,
                    has_edns: parsed.has_edns,
                    do_bit: parsed.do_bit,
                };
                let (is_creator, notifier) = self.begin_inflight(&fkey);
                if !is_creator {
                    // 等待发起者完成；发起者成功后已写缓存，重查即可命中。
                    notifier.notified().await;
                    if let Some(resp) = self.cached_lookup(
                        &cache,
                        &parsed.qname,
                        parsed.qtype,
                        parsed.has_edns,
                        parsed.do_bit,
                        parsed.id,
                    ) {
                        return Ok(resp);
                    }
                    // 发起者失败未写缓存 → 自己转发保证响应（不重复登记）。
                }
                let response = match self.forward_direct(query, server).await {
                    Ok(r) => r,
                    Err(e) => {
                        self.end_inflight(&fkey);
                        return Err(e);
                    }
                };
                self.end_inflight(&fkey);
                Self::log_dns_result(&parsed.qname, "direct", server, &response);
                self.cache_store(
                    &cache,
                    &parsed.qname,
                    parsed.qtype,
                    parsed.has_edns,
                    parsed.do_bit,
                    &response,
                );
                Ok(response)
            }
            DnsOutbound::Group(group) => {
                let cache_key = format!("group:{}", group);
                let cache = self.get_cache(&cache_key);
                if let Some(resp) = self.cached_lookup(
                    &cache,
                    &parsed.qname,
                    parsed.qtype,
                    parsed.has_edns,
                    parsed.do_bit,
                    parsed.id,
                ) {
                    return Ok(resp);
                }
                match self.group_dialers.get(&group) {
                    Some(dialer) => match self.proxy_dns_servers.first().copied() {
                        Some(server) => {
                            // 持久会话共享需每组合并：同一时刻每组至多一个 in-flight
                            // 查询，否则并发查询会在共享会话上互相抢走对方响应。
                            let _lock = self.group_lock(&group).await;
                            // 等锁期间前面的查询可能已填充本组缓存。
                            if let Some(resp) = self.cached_lookup(
                                &cache,
                                &parsed.qname,
                                parsed.qtype,
                                parsed.has_edns,
                                parsed.do_bit,
                                parsed.id,
                            ) {
                                return Ok(resp);
                            }
                            let response = match self
                                .forward_via_proxy(&group, query, dialer.as_ref(), server)
                                .await
                            {
                                Ok(r) => r,
                                Err(e) => {
                                    // 组内节点全挂/组冷却 → 回退直连，避免丢查询
                                    // （与"无拨号器/无上游"的回退一致）。
                                    warn!(
                                        group = %group,
                                        error = %e,
                                        "DNS: proxy group unavailable, falling back to direct"
                                    );
                                    let server = self.pick_direct_server()?;
                                    let dcache = self.get_cache("direct");
                                    let response = self.forward_direct(query, server).await?;
                                    Self::log_dns_result(&parsed.qname, "direct-fallback", server, &response);
                                    self.cache_store(
                                        &dcache,
                                        &parsed.qname,
                                        parsed.qtype,
                                        parsed.has_edns,
                                        parsed.do_bit,
                                        &response,
                                    );
                                    return Ok(response);
                                }
                            };
                            Self::log_dns_result(&parsed.qname, "proxy", server, &response);
                            self.cache_store(
                                &cache,
                                &parsed.qname,
                                parsed.qtype,
                                parsed.has_edns,
                                parsed.do_bit,
                                &response,
                            );
                            Ok(response)
                        }
                        None => {
                            // 与 validator 注释一致：未配置代理上游 → 回退直连，避免丢查询。
                            warn!(
                                group = %group,
                                "DNS: no proxy DNS server configured, falling back to direct"
                            );
                            let server = self.pick_direct_server()?;
                            let dcache = self.get_cache("direct");
                            let response = self.forward_direct(query, server).await?;
                            Self::log_dns_result(&parsed.qname, "direct-fallback", server, &response);
                            self.cache_store(
                                &dcache,
                                &parsed.qname,
                                parsed.qtype,
                                parsed.has_edns,
                                parsed.do_bit,
                                &response,
                            );
                            Ok(response)
                        }
                    },
                    None => {
                        // 组没有可用拨号器（无节点被跳过）→ 回退直连，避免丢查询。
                        warn!(
                            group = %group,
                            "DNS: group has no dialer, falling back to direct"
                        );
                        let server = self.pick_direct_server()?;
                        let dcache = self.get_cache("direct");
                        let response = self.forward_direct(query, server).await?;
                        Self::log_dns_result(&parsed.qname, "direct-fallback", server, &response);
                        self.cache_store(
                            &dcache,
                            &parsed.qname,
                            parsed.qtype,
                            parsed.has_edns,
                            parsed.do_bit,
                            &response,
                        );
                        Ok(response)
                    }
                }
            }
        }
    }

    /// 记录一次 DNS 查询结果：来源（proxy / direct / direct-fallback）+ 上游
    /// + RCODE（flags 低 4 位：0=NOERROR, 2=SERVFAIL, 3=NXDOMAIN）。
    ///
    /// 用于定位"SERVFAIL / 无响应"来自哪条路径（代理上游还是回退直连）。
    fn log_dns_result(domain: &str, source: &str, server: SocketAddr, resp: &[u8]) {
        let rcode = if resp.len() >= 4 {
            u16::from_be_bytes([resp[2], resp[3]]) & 0x000F
        } else {
            u16::MAX
        };
        info!(
            domain = domain,
            source = source,
            server = %server,
            rcode = rcode,
            "DNS response"
        );
    }

    /// 域名分流：返回该域名在数据面 routing 规则里对应的走向。
    ///
    /// 顺序匹配 [`DnsForwarder::routes`]（与 routing 规则同序，先定义先命中）；
    /// 未命中任何 domain 规则 → `routing.fallback`。
    fn route_domain(&self, qname: &str) -> DnsOutbound {
        for route in &self.routes {
            if route.matches(qname) {
                return route.outbound().clone();
            }
        }
        self.fallback.clone()
    }

    /// 查缓存并重写事务 ID；未启用缓存或未命中返回 `None`。
    fn cached_lookup(
        &self,
        cache: &Mutex<DnsCache>,
        qname: &str,
        qtype: u16,
        has_edns: bool,
        do_bit: bool,
        id: u16,
    ) -> Option<Vec<u8>> {
        if !self.enable_cache {
            return None;
        }
        let cache = cache.lock().unwrap();
        let mut resp = cache.get(qname, qtype, has_edns, do_bit)?;
        rewrite_response_id(&mut resp, id);
        debug!(domain = %qname, "DNS cache hit");
        Some(resp)
    }

    /// 将新响应按 TTL 存入所属组的缓存（未启用缓存或 TTL 为 0 时跳过）。
    fn cache_store(
        &self,
        cache: &Mutex<DnsCache>,
        qname: &str,
        qtype: u16,
        has_edns: bool,
        do_bit: bool,
        response: &[u8],
    ) {
        if !self.enable_cache {
            return;
        }
        if let Some(ttl) = parse_response_min_ttl(response) {
            cache
                .lock()
                .unwrap()
                .insert(qname.to_string(), qtype, has_edns, do_bit, response.to_vec(), ttl);
            debug!(domain = %qname, ttl = ttl, "DNS cache updated");
        }
    }

    /// 取（或懒创建）某个走向的独立缓存。
    fn get_cache(&self, key: &str) -> Arc<Mutex<DnsCache>> {
        let mut caches = self.caches.lock().unwrap();
        caches
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(DnsCache::new())))
            .clone()
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

    /// 登记一个 in-flight 查询。
    ///
    /// 返回 `(is_creator, notifier)`：
    /// - `is_creator == true`：本调用是发起者，需要转发上游、写缓存，最后调用
    ///   [`Self::end_inflight`] 唤醒等待者。
    /// - `is_creator == false`：已有同 key 查询在途，`notifier` 是其完成通知器；
    ///   等待其触发后应重查缓存（发起者成功后会写缓存）。
    fn begin_inflight(&self, key: &FlightKey) -> (bool, Arc<Notify>) {
        let mut inflight = self.inflight.lock().unwrap();
        match inflight.get(key) {
            Some(n) => (false, n.clone()),
            None => {
                let n = Arc::new(Notify::new());
                inflight.insert(key.clone(), n.clone());
                (true, n)
            }
        }
    }

    /// 结束一个 in-flight 查询并唤醒所有等待者。
    fn end_inflight(&self, key: &FlightKey) {
        if let Some(n) = self.inflight.lock().unwrap().remove(key) {
            n.notify_waiters();
        }
    }

    /// 取（或懒创建）某个代理组的合并锁，串行化该组的 in-flight 查询。
    ///
    /// 返回 [`tokio::sync::OwnedMutexGuard`]（自持 `Arc`，无借用），可安全跨 await。
    async fn group_lock(&self, group: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.group_locks.lock().unwrap();
            locks
                .entry(group.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        lock.lock_owned().await
    }

    /// 代理转发：经指定代理组拨号器的 full-cone UDP 会话发送到 `server`。
    ///
    /// 每个代理组复用**持久** UDP 会话（[`DnsForwarder::proxy_sessions`]），避免每个
    /// 查询重新握手（SOCKS5 的 TCP+UDP ASSOCIATE、TUIC/Juicity 的全新 QUIC 连接都很
    /// 昂贵）。会话失联（send/recv 报连接错误）时移除，下次查询重建。
    ///
    /// 持久会话绑定**建会话时的节点**：若组内当前节点已切换（原节点死亡被
    /// `GroupDialer` 回退到其它节点），旧会话打向失效节点，这里按节点名识别并重建。
    /// 非 `GroupDialer`（测试 fake 等）不比较节点名，仅按组复用。
    ///
    /// 响应校验 `resp_dest == server`：full-cone 会话可能收到发往其它目标的杂散
    /// 数据报，不匹配则忽略并继续等待（受 `query_timeout` 约束）。
    async fn forward_via_proxy(
        &self,
        group: &str,
        query: &[u8],
        dialer: &dyn OutboundDialer,
        server: SocketAddr,
    ) -> Result<Vec<u8>> {
        // 组当前选中的节点名（GroupDialer 才有效；否则为空串 = 不做节点比较）。
        let node_key = dialer
            .as_any()
            .downcast_ref::<GroupDialer>()
            .and_then(|g| g.current_node_name())
            .map(|s| s.to_string())
            .unwrap_or_default();

        // ---- 取（或建）本组的持久会话 ----
        // 快路径先查缓存（锁不跨 await）；未命中/节点已切换再创建，创建期间不持锁。
        let cached = self.proxy_sessions.lock().unwrap().get(group).cloned();
        let session = match cached {
            // 会话存在，且（非 GroupDialer，或）仍绑定当前节点 → 直接复用。
            Some((stored_node, s)) if node_key.is_empty() || stored_node == node_key => s,
            _ => {
                // 会话缺失，或组内当前节点已切换（旧会话绑定失效节点）→ 重建。
                // 先移除旧会话；创建期间不持 std MutexGuard，避免跨 await 不 Send。
                self.proxy_sessions.lock().unwrap().remove(group);
                let boxed = dialer
                    .udp_dial()
                    .await
                    .context("DNS forward_via_proxy: udp_dial failed")?;
                let arc: Arc<dyn UdpSession> = Arc::from(boxed);
                self.proxy_sessions
                    .lock()
                    .unwrap()
                    .insert(group.to_string(), (node_key, arc.clone()));
                arc
            }
        };

        // ---- 发送 ----
        if let Err(e) = session.send(&server, query).await {
            self.proxy_sessions.lock().unwrap().remove(group);
            return Err(anyhow::anyhow!(
                "DNS proxy query to {} send failed: {}",
                server,
                e
            ));
        }

        // ---- 接收：校验来源 == server，杂散数据报忽略 ----
        let payload = tokio::time::timeout(self.query_timeout, async {
            loop {
                let (resp_dest, payload) = match session.recv().await {
                    Ok(v) => v,
                    Err(e) => {
                        // 底层连接/会话失联（TCP 断开、QUIC 失效等）→ 移除以便重建。
                        self.proxy_sessions.lock().unwrap().remove(group);
                        return Err(anyhow::anyhow!("DNS proxy query recv failed: {}", e));
                    }
                };
                if resp_dest == server {
                    return Ok(payload.to_vec());
                }
                debug!(
                    got = %resp_dest,
                    want = %server,
                    "DNS: ignoring relay datagram from unexpected destination"
                );
            }
        })
        .await
        .with_context(|| format!("DNS proxy query to {} timed out", server))??;
        Ok(payload)
    }
}

/// 将 DNS 走向转换为可读标签，用于 INFO 日志：只标注域名走了哪个代理组。
fn dns_outbound_label(o: &DnsOutbound) -> String {
    match o {
        DnsOutbound::Direct => "direct".to_string(),
        DnsOutbound::Block => "block".to_string(),
        DnsOutbound::Group(g) => format!("proxy group {}", g),
    }
}

/// 每个代理组缓存的条目数上限（超出时先清理过期项，仍满则整体清空）。
const DNS_CACHE_MAX: usize = 2048;

/// 单个代理组（含直连）的 DNS 缓存条目。
struct CacheEntry {
    /// 上游原始响应（含其原始事务 ID；命中时由调用方重写为当前查询 ID）。
    response: Vec<u8>,
    /// 过期时间（基于响应 TTL）。
    expires: Instant,
}

/// 每个代理组（含直连）独立维护的 DNS 缓存，遵循响应 TTL。
///
/// 各组的缓存互不共享——不同代理组解析同一域名可能得到不同结果（污染隔离）。
struct DnsCache {
    entries: HashMap<(String, u16, bool, bool), CacheEntry>,
}

impl DnsCache {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// 命中且未过期时返回缓存响应；否则 `None`。
    ///
    /// 缓存键包含 `has_edns` / `do_bit`：EDNS 或 DNSSEC(DO) 查询与普通查询互不
    /// 共享响应，避免缓存中带 OPT / RRSIG 的响应被错误提供给普通查询（反之亦然）。
    fn get(&self, qname: &str, qtype: u16, has_edns: bool, do_bit: bool) -> Option<Vec<u8>> {
        let e = self.entries.get(&(qname.to_string(), qtype, has_edns, do_bit))?;
        if Instant::now() < e.expires {
            Some(e.response.clone())
        } else {
            None
        }
    }

    /// 存入缓存（TTL 为 0 不缓存）。超容量时先清理过期项，仍满则整体清空。
    fn insert(
        &mut self,
        qname: String,
        qtype: u16,
        has_edns: bool,
        do_bit: bool,
        response: Vec<u8>,
        ttl: u32,
    ) {
        if ttl == 0 {
            return;
        }
        if self.entries.len() >= DNS_CACHE_MAX {
            self.entries.retain(|_, e| Instant::now() < e.expires);
            if self.entries.len() >= DNS_CACHE_MAX {
                self.entries.clear();
            }
        }
        let expires = Instant::now() + Duration::from_secs(u64::from(ttl));
        self.entries.insert(
            (qname, qtype, has_edns, do_bit),
            CacheEntry { response, expires },
        );
    }
}

/// 解析 DNS 响应中 answer 记录的最小 TTL（秒）。
///
/// 只遍历 answer 段：每条记录 = NAME（可变/压缩指针）+ TYPE(2) + CLASS(2) +
/// TTL(4) + RDLENGTH(2) + RDATA(RDLENGTH)。NAME 支持普通 label 与压缩指针，
/// 但指针不影响后续固定字段的位置。
fn parse_response_min_ttl(response: &[u8]) -> Option<u32> {
    if response.len() < DNS_HEADER_LEN {
        return None;
    }
    // 仅当 QR=1（响应）时解析
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x8000 == 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;
    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    let nscount = u16::from_be_bytes([response[8], response[9]]) as usize;

    // 跳过 question 段
    let mut pos = DNS_HEADER_LEN;
    for _ in 0..qdcount {
        pos = skip_name(response, pos)?;
        if pos + 4 > response.len() {
            return None;
        }
        pos += 4; // QTYPE + QCLASS
    }

    if ancount == 0 {
        // 负缓存（RFC 2308）：仅对 NODATA(rcode=0) / NXDOMAIN(rcode=3) 生效，
        // TTL 取 authority 段 SOA 的 min(TTL, MINIMUM)，上限 1 小时；无 SOA 不缓存。
        let rcode = flags & 0x000F;
        if rcode != 0 && rcode != 3 {
            return Some(0);
        }
        return parse_negative_ttl(response, pos, nscount);
    }

    let mut min_ttl: Option<u32> = None;
    for _ in 0..ancount {
        pos = skip_name(response, pos)?;
        if pos + 10 > response.len() {
            return None;
        }
        let ttl = u32::from_be_bytes([
            response[pos + 4],
            response[pos + 5],
            response[pos + 6],
            response[pos + 7],
        ]);
        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > response.len() {
            return None;
        }
        pos += rdlength;
        min_ttl = Some(match min_ttl {
            Some(m) => m.min(ttl),
            None => ttl,
        });
    }
    min_ttl
}

/// RFC 2308 负缓存 TTL：在 authority 段找 SOA 记录，返回 `min(SOA TTL, MINIMUM)`，
/// 上限 1 小时；无 SOA 返回 0（不缓存）。`pos` 为 question 段结束位置。
const TYPE_SOA: u16 = 6;
const NEGATIVE_TTL_CAP_SECS: u32 = 3600;

fn parse_negative_ttl(response: &[u8], mut pos: usize, nscount: usize) -> Option<u32> {
    for _ in 0..nscount {
        pos = skip_name(response, pos)?;
        if pos + 10 > response.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let ttl = u32::from_be_bytes([
            response[pos + 4],
            response[pos + 5],
            response[pos + 6],
            response[pos + 7],
        ]);
        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > response.len() {
            return None;
        }
        if rtype == TYPE_SOA {
            // SOA RDATA = MNAME + RNAME + 5×u32（serial/refresh/retry/expire/minimum），
            // MINIMUM 是 RDATA 末尾 4 字节；最小 RDATA 为 22 字节（两个根名 + 20）。
            if rdlength < 22 {
                return None;
            }
            let minimum = u32::from_be_bytes([
                response[pos + rdlength - 4],
                response[pos + rdlength - 3],
                response[pos + rdlength - 2],
                response[pos + rdlength - 1],
            ]);
            return Some(ttl.min(minimum).min(NEGATIVE_TTL_CAP_SECS));
        }
        pos += rdlength;
    }
    Some(0)
}

/// 跳过 DNS 名称（普通 label 序列或压缩指针），返回名称结束后的位置。
fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= buf.len() {
            return None;
        }
        let len = buf[pos] as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            // 压缩指针：2 字节，指向别处，名称到此结束
            return Some(pos + 2);
        }
        if len > 63 || pos + 1 + len > buf.len() {
            return None;
        }
        pos += 1 + len;
    }
}

/// 将响应前 2 字节（事务 ID）重写为 `id`。用于缓存命中时匹配当前查询。
fn rewrite_response_id(response: &mut [u8], id: u16) {
    if response.len() >= 2 {
        response[0] = (id >> 8) as u8;
        response[1] = (id & 0xff) as u8;
    }
}

/// 构造一个最小错误应答：复制查询 ID，设置 QR=1 与 `rcode`，回显 question。
fn build_error_response(query: &[u8], rcode: u8) -> Vec<u8> {
    let mut resp = Vec::with_capacity(DNS_HEADER_LEN + 8);
    if query.len() >= 2 {
        resp.extend_from_slice(&query[..2]); // ID
    } else {
        resp.extend_from_slice(&[0, 0]);
    }
    // FLAGS: QR=1 | 复制 RD 位(0x0100) | RCODE
    let rd = if query.len() >= 4 && (query[2] & 0x01) != 0 { 0x0100 } else { 0 };
    let flags = 0x8000u16 | rd | (u16::from(rcode) & 0x000F);
    resp.extend_from_slice(&flags.to_be_bytes());
    // QDCOUNT=1（回显 question），AN/NS/AR=0
    resp.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    // 回显 question（若有）
    if query.len() > DNS_HEADER_LEN {
        resp.extend_from_slice(&query[DNS_HEADER_LEN..]);
    }
    resp
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
    use crate::config::{PolicyType, RouteRule, RoutingConfig};
    use crate::group::{GroupDialer, GroupNode};
    use crate::routing::matcher::{build_dns_domain_routes, dns_outbound_from_action};
    use protocols::ProxyConn;
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;
    use std::sync::atomic::AtomicUsize;

    /// 构造测试用转发器（空路由表 + 指定 fallback，无拨号器）。
    fn test_forwarder(routes: Vec<DnsDomainRoute>, fallback: DnsOutbound) -> DnsForwarder {
        DnsForwarder::new(&DnsConfig::default(), routes, HashMap::new(), fallback, None)
            .unwrap()
    }

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

    /// 构造带单条 A 记录的 DNS 响应（answer 的 NAME 用压缩指针指向 question）。
    fn build_response(id: u16, qname: &str, ttl: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&[0x81, 0x80]); // QR=1, RD=1, RA=1
        buf.extend_from_slice(&[0, 1]); // QDCOUNT
        buf.extend_from_slice(&[0, 1]); // ANCOUNT
        buf.extend_from_slice(&[0, 0, 0, 0]); // NS/AR
        for label in qname.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf.extend_from_slice(&[0, 1, 0, 1]); // QTYPE=A, QCLASS=IN
        // answer: NAME = 压缩指针 (0xC00C) → question QNAME
        buf.extend_from_slice(&[0xC0, 0x0C]);
        buf.extend_from_slice(&[0, 1]); // TYPE=A
        buf.extend_from_slice(&[0, 1]); // CLASS=IN
        buf.extend_from_slice(&ttl.to_be_bytes());
        buf.extend_from_slice(&[0, 4]); // RDLENGTH=4
        buf.extend_from_slice(&[8, 8, 8, 8]); // RDATA
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
    fn test_route_domain_from_routing_rules() {
        // DNS 走向完全由现有 routing 规则推导，无独立代理规则
        let routing = RoutingConfig {
            rules: vec![
                RouteRule {
                    r#match: "domain(suffix:google.com)".into(),
                    action: "proxy(group_a)".into(),
                },
                RouteRule {
                    r#match: "domain(suffix:baidu.com)".into(),
                    action: "direct".into(),
                },
                RouteRule {
                    r#match: "domain(suffix:example.org)".into(),
                    action: "block".into(),
                },
            ],
            fallback: "proxy(group_b)".into(),
        };
        let routes = build_dns_domain_routes(&routing, None).unwrap();
        let fallback = dns_outbound_from_action(&routing.fallback).unwrap();
        let f = test_forwarder(routes, fallback);

        assert_eq!(
            f.route_domain("google.com"),
            DnsOutbound::Group("group_a".into())
        );
        assert_eq!(
            f.route_domain("www.google.com"),
            DnsOutbound::Group("group_a".into())
        );
        assert_eq!(f.route_domain("baidu.com"), DnsOutbound::Direct);
        assert_eq!(f.route_domain("a.example.org"), DnsOutbound::Block);
        // 未命中任何 domain 规则 → fallback
        assert_eq!(
            f.route_domain("unknown.org"),
            DnsOutbound::Group("group_b".into())
        );
    }

    #[test]
    fn test_route_domain_empty_routes_fallback() {
        let f = test_forwarder(vec![], DnsOutbound::Direct);
        assert_eq!(f.route_domain("anything.com"), DnsOutbound::Direct);
    }

    #[test]
    fn test_parse_response_min_ttl() {
        let resp = build_response(1, "example.com", 300);
        assert_eq!(parse_response_min_ttl(&resp), Some(300));
        // 非响应（QR=0）→ None
        let query = build_query(1, "example.com", 1);
        assert_eq!(parse_response_min_ttl(&query), None);
        // 响应但无 answer → Some(0)
        let mut empty = build_query(1, "example.com", 1);
        empty[2] = 0x81; // QR=1
        assert_eq!(parse_response_min_ttl(&empty), Some(0));
    }

    #[test]
    fn test_build_error_response_rcode() {
        let q = build_query(0xABCD, "example.com", 1);
        let resp = build_error_response(&q, 3); // NXDOMAIN
        assert_eq!(resp[..2], [0xAB, 0xCD]); // ID 保留
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_ne!(flags & 0x8000, 0); // QR=1
        assert_eq!(flags & 0x000F, 3); // RCODE=NXDOMAIN
        assert_eq!(&resp[12..], &q[12..]); // question 回显
    }

    #[test]
    fn test_rewrite_response_id() {
        let mut resp = vec![0x12, 0x34, 0x81, 0x80];
        rewrite_response_id(&mut resp, 0xABCD);
        assert_eq!(resp[..2], [0xAB, 0xCD]);
    }

    #[test]
    fn test_cache_isolation_per_group() {
        // 每组独立缓存：组 A 有该条目，组 B 没有
        let f = test_forwarder(vec![], DnsOutbound::Direct);
        let cache_a = f.get_cache("group:a");
        cache_a.lock().unwrap().insert(
            "example.com".into(),
            1,
            false,
            false,
            build_response(1, "example.com", 300),
            300,
        );
        let cache_b = f.get_cache("group:b");
        assert!(cache_b.lock().unwrap().get("example.com", 1, false, false).is_none());
        assert!(cache_a.lock().unwrap().get("example.com", 1, false, false).is_some());
    }

    #[test]
    fn test_cache_ttl_zero_not_cached() {
        let f = test_forwarder(vec![], DnsOutbound::Direct);
        let cache = f.get_cache("direct");
        cache.lock().unwrap().insert(
            "example.com".into(),
            1,
            false,
            false,
            build_response(1, "example.com", 300),
            0,
        );
        assert!(cache.lock().unwrap().get("example.com", 1, false, false).is_none());
    }

    /// 构造带 EDNS(0) OPT 的查询（DO 位可选）。
    fn build_query_edns(id: u16, qname: &str, qtype: u16, do_bit: bool) -> Vec<u8> {
        let mut buf = build_query(id, qname, qtype);
        buf[11] = 1; // ARCOUNT=1
        buf.push(0); // OPT NAME = root
        buf.extend_from_slice(&[0, 41]); // TYPE=OPT
        buf.extend_from_slice(&[0x10, 0x00]); // CLASS = UDP payload 4096
        let mut ttl = [0u8, 0, 0, 0];
        if do_bit {
            ttl[2] = 0x80; // DO
        }
        buf.extend_from_slice(&ttl);
        buf.extend_from_slice(&[0, 0]); // RDLENGTH=0
        buf
    }

    /// 构造 NXDOMAIN 响应：authority 段含一条 SOA（负缓存用）。
    fn build_nxdomain_response(id: u16, qname: &str, soa_ttl: u32, soa_minimum: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&[0x81, 0x83]); // QR=1, RD=1, RA=1, RCODE=3
        buf.extend_from_slice(&[0, 1]); // QDCOUNT
        buf.extend_from_slice(&[0, 0]); // ANCOUNT
        buf.extend_from_slice(&[0, 1]); // NSCOUNT=1
        buf.extend_from_slice(&[0, 0]); // ARCOUNT
        for label in qname.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf.extend_from_slice(&[0, 1, 0, 1]); // QTYPE=A, QCLASS=IN
        // authority: NAME = 压缩指针 → question QNAME
        buf.extend_from_slice(&[0xC0, 0x0C]);
        buf.extend_from_slice(&[0, 6]); // TYPE=SOA
        buf.extend_from_slice(&[0, 1]); // CLASS=IN
        buf.extend_from_slice(&soa_ttl.to_be_bytes());
        // RDATA: MNAME(1 root) + RNAME(1 root) + 5×u32
        let mut rdata = Vec::new();
        rdata.push(0);
        rdata.push(0);
        rdata.extend_from_slice(&1u32.to_be_bytes()); // serial
        rdata.extend_from_slice(&3600u32.to_be_bytes()); // refresh
        rdata.extend_from_slice(&600u32.to_be_bytes()); // retry
        rdata.extend_from_slice(&86400u32.to_be_bytes()); // expire
        rdata.extend_from_slice(&soa_minimum.to_be_bytes()); // MINIMUM
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rdata);
        buf
    }

    #[test]
    fn test_parse_dns_query_edns_do() {
        // 普通查询：无 EDNS
        let parsed = parse_dns_query(&build_query(1, "example.com", 1)).unwrap();
        assert!(!parsed.has_edns);
        assert!(!parsed.do_bit);

        // EDNS 无 DO
        let parsed = parse_dns_query(&build_query_edns(1, "example.com", 1, false)).unwrap();
        assert!(parsed.has_edns);
        assert!(!parsed.do_bit);

        // EDNS + DO
        let parsed = parse_dns_query(&build_query_edns(1, "example.com", 1, true)).unwrap();
        assert!(parsed.has_edns);
        assert!(parsed.do_bit);
    }

    #[test]
    fn test_cache_isolates_edns_do() {
        let f = test_forwarder(vec![], DnsOutbound::Direct);
        let cache = f.get_cache("direct");
        cache.lock().unwrap().insert(
            "example.com".into(),
            1,
            true, // has_edns
            true, // do_bit
            build_response(1, "example.com", 300),
            300,
        );
        // 不同 EDNS/DO 组合互不命中
        assert!(cache.lock().unwrap().get("example.com", 1, false, false).is_none());
        assert!(cache.lock().unwrap().get("example.com", 1, true, false).is_none());
        assert!(cache.lock().unwrap().get("example.com", 1, true, true).is_some());
    }

    #[test]
    fn test_parse_response_min_ttl_nxdomain_soa() {
        // NXDOMAIN + SOA：负缓存 TTL = min(TTL, MINIMUM)
        let resp = build_nxdomain_response(1, "example.com", 600, 300);
        assert_eq!(parse_response_min_ttl(&resp), Some(300));
        // MINIMUM 更大时取 TTL
        let resp = build_nxdomain_response(1, "example.com", 120, 300);
        assert_eq!(parse_response_min_ttl(&resp), Some(120));
        // 上限 1 小时
        let resp = build_nxdomain_response(1, "example.com", 7200, 7200);
        assert_eq!(parse_response_min_ttl(&resp), Some(3600));
        // NXDOMAIN 但无 SOA → 不缓存
        let mut no_soa = build_query(1, "example.com", 1);
        no_soa[2] = 0x81;
        no_soa[3] = 0x83; // RCODE=3
        assert_eq!(parse_response_min_ttl(&no_soa), Some(0));
    }

    #[tokio::test]
    async fn test_negative_cache_nxdomain() {
        let f = test_forwarder(vec![], DnsOutbound::Direct);
        let cache = f.get_cache("direct");
        let nx = build_nxdomain_response(0xAAAA, "example.com", 600, 300);
        f.cache_store(&cache, "example.com", 1, false, false, &nx);
        // 命中并重写事务 ID
        let resp = f
            .cached_lookup(&cache, "example.com", 1, false, false, 0x1234)
            .expect("NXDOMAIN should be negatively cached");
        assert_eq!(resp[..2], [0x12, 0x34]);
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(flags & 0x000F, 3); // NXDOMAIN
    }

    #[test]
    fn test_inflight_coalescing_helpers() {
        let f = test_forwarder(vec![], DnsOutbound::Direct);
        let key = FlightKey {
            outbound: "direct".to_string(),
            qname: "example.com".to_string(),
            qtype: 1,
            has_edns: false,
            do_bit: false,
        };
        // 第一个是发起者，第二个是等待者
        assert!(f.begin_inflight(&key).0);
        assert!(!f.begin_inflight(&key).0);
        // 结束后可重新成为发起者
        f.end_inflight(&key);
        assert!(f.begin_inflight(&key).0);
        f.end_inflight(&key);
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
        let f = test_forwarder(vec![], DnsOutbound::Direct);
        // 非法/截断报文 → 解析失败即返回，不发起任何网络转发
        assert!(f.resolve(&[]).await.is_err());
        assert!(f.resolve(&[0u8; 12]).await.is_err());
    }

    #[tokio::test]
    async fn test_resolve_block_returns_nxdomain() {
        let f = test_forwarder(vec![], DnsOutbound::Block);
        let q = build_query(0x1234, "blocked.com", 1);
        let resp = f.resolve(&q).await.expect("block should return NXDOMAIN");
        assert_eq!(resp[..2], [0x12, 0x34]); // ID 保留
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(flags & 0x000F, 3); // NXDOMAIN
    }

    // ------------------------------------------------------------------------
    // Fakes + new behavior tests (persistent session / resp_dest validation /
    // no-proxy-upstream direct fallback)
    // ------------------------------------------------------------------------

    /// 可控的 fake UDP 会话：按序弹出 (来源, payload)，send 可配置失败。
    #[derive(Clone)]
    struct FakeUdpSession {
        replies: Arc<tokio::sync::Mutex<VecDeque<(SocketAddr, Vec<u8>)>>>,
        fail_send: Arc<std::sync::atomic::AtomicBool>,
    }

    impl FakeUdpSession {
        fn new(replies: VecDeque<(SocketAddr, Vec<u8>)>) -> Self {
            Self {
                replies: Arc::new(tokio::sync::Mutex::new(replies)),
                fail_send: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            }
        }
        fn fail_send(self) -> Self {
            self.fail_send.store(true, Ordering::SeqCst);
            self
        }
    }

    #[async_trait::async_trait]
    impl UdpSession for FakeUdpSession {
        async fn send(&self, _dest: &SocketAddr, _payload: &[u8]) -> anyhow::Result<()> {
            if self.fail_send.load(Ordering::SeqCst) {
                anyhow::bail!("simulated send failure");
            }
            Ok(())
        }
        async fn recv(&self) -> anyhow::Result<(SocketAddr, bytes::Bytes)> {
            let mut q = self.replies.lock().await;
            let Some((dest, payload)) = q.pop_front() else {
                // 无更多预置数据 → 挂起（模拟真实会话持续等待），由外层超时中断。
                drop(q);
                std::future::pending::<()>().await;
                unreachable!()
            };
            Ok((dest, payload.into()))
        }
    }

    /// fake 拨号器：返回预置的 fake 会话，记录 udp_dial 调用次数。
    struct FakeDialer {
        session: FakeUdpSession,
        dial_count: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl OutboundDialer for FakeDialer {
        async fn dial(&self, _target: &str) -> anyhow::Result<ProxyConn> {
            anyhow::bail!("fake dialer: dial not implemented")
        }
        async fn udp_dial(&self) -> anyhow::Result<Box<dyn UdpSession>> {
            self.dial_count.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(self.session.clone()))
        }
        fn protocol_name(&self) -> &'static str {
            "fake"
        }
        fn proxy_addr(&self) -> SocketAddr {
            "127.0.0.1:1080".parse().unwrap()
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    /// 来自错误来源（非目标 DNS 服务器）的杂散数据报应被忽略，等待正确来源。
    #[tokio::test]
    async fn test_forward_via_proxy_ignores_unexpected_dest() {
        let f = test_forwarder(vec![], DnsOutbound::Direct);
        let server: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let q = build_query(0x1234, "example.com", 1);

        let mut replies = VecDeque::new();
        replies.push_back(("9.9.9.9:53".parse().unwrap(), vec![0xde, 0xad])); // 杂散
        replies.push_back((server, vec![0xbe, 0xef])); // 正确来源
        let dialer = FakeDialer {
            session: FakeUdpSession::new(replies),
            dial_count: Arc::new(AtomicUsize::new(0)),
        };

        let resp = f
            .forward_via_proxy("proxy", &q, &dialer, server)
            .await
            .unwrap();
        assert_eq!(resp, vec![0xbe, 0xef]);
    }

    /// 只有错误来源时，等待至超时并报错（不返回杂散数据）。
    #[tokio::test]
    async fn test_forward_via_proxy_timeout_on_wrong_dest_only() {
        let mut cfg = DnsConfig::default();
        cfg.query_timeout_ms = 200; // 缩短等待
        let f = DnsForwarder::new(&cfg, vec![], HashMap::new(), DnsOutbound::Direct, None)
            .unwrap();
        let server: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let q = build_query(0x1234, "example.com", 1);

        let mut replies = VecDeque::new();
        replies.push_back(("9.9.9.9:53".parse().unwrap(), vec![0xde, 0xad])); // 只有杂散
        let dialer = FakeDialer {
            session: FakeUdpSession::new(replies),
            dial_count: Arc::new(AtomicUsize::new(0)),
        };

        let err = f
            .forward_via_proxy("proxy", &q, &dialer, server)
            .await
            .expect_err("should time out waiting for correct source");
        assert!(
            err.to_string().contains("timed out"),
            "unexpected error: {}",
            err
        );
    }

    /// send 失败会移除持久会话，后续调用重新 udp_dial。
    #[tokio::test]
    async fn test_forward_via_proxy_send_failure_removes_session() {
        let f = test_forwarder(vec![], DnsOutbound::Direct);
        let server: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let q = build_query(0x1234, "example.com", 1);
        let dialer = FakeDialer {
            session: FakeUdpSession::new(VecDeque::new()).fail_send(),
            dial_count: Arc::new(AtomicUsize::new(0)),
        };
        assert!(f
            .forward_via_proxy("proxy", &q, &dialer, server)
            .await
            .is_err());
        assert!(f.proxy_sessions.lock().unwrap().get("proxy").is_none());
    }

    /// 持久会话复用：连续两次查询只调用一次 udp_dial。
    #[tokio::test]
    async fn test_forward_via_proxy_reuses_persistent_session() {
        let f = test_forwarder(vec![], DnsOutbound::Direct);
        let server: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let q = build_query(0x1234, "example.com", 1);

        let mut replies = VecDeque::new();
        replies.push_back((server, vec![1]));
        replies.push_back((server, vec![2]));
        let dialer = FakeDialer {
            session: FakeUdpSession::new(replies),
            dial_count: Arc::new(AtomicUsize::new(0)),
        };

        let r1 = f
            .forward_via_proxy("proxy", &q, &dialer, server)
            .await
            .unwrap();
        let r2 = f
            .forward_via_proxy("proxy", &q, &dialer, server)
            .await
            .unwrap();
        assert_eq!(r1, vec![1]);
        assert_eq!(r2, vec![2]);
        assert_eq!(dialer.dial_count.load(Ordering::SeqCst), 1);
    }

    /// 组有拨号器但 proxy_dns_servers 为空 → 回退直连（validator 声称的行为）；
    /// 直连无上游时错误应为 "no direct upstream available" 而非 "no proxy DNS server"。
    #[tokio::test]
    async fn test_resolve_group_no_proxy_server_falls_back_to_direct() {
        let mut cfg = DnsConfig::default();
        cfg.proxy_dns_servers = Vec::new();
        cfg.direct_dns_servers = Vec::new();
        cfg.direct_use_system_dns = false;
        let mut dialers: HashMap<String, Arc<dyn OutboundDialer>> = HashMap::new();
        dialers.insert(
            "proxy".into(),
            Arc::new(FakeDialer {
                session: FakeUdpSession::new(VecDeque::new()),
                dial_count: Arc::new(AtomicUsize::new(0)),
            }),
        );
        let f = DnsForwarder::new(&cfg, vec![], dialers, DnsOutbound::Group("proxy".into()), None)
            .unwrap();
        let q = build_query(0x1234, "example.com", 1);
        let err = f.resolve(&q).await.unwrap_err();
        assert!(
            err.to_string().contains("no direct upstream available"),
            "unexpected error: {}",
            err
        );
    }

    /// 持久会话绑定建会话时的节点：组内当前节点切换后应重建会话（重新 udp_dial），
    /// 而不是继续复用绑定旧节点的会话。
    #[tokio::test]
    async fn test_forward_via_proxy_rebuilds_when_group_node_changes() {
        let f = test_forwarder(vec![], DnsOutbound::Direct);
        let server: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let q = build_query(0x1234, "example.com", 1);

        // 单节点组，当前节点 = "a"。
        let mut replies = VecDeque::new();
        replies.push_back((server, vec![0xaa]));
        let node_dialer = Arc::new(FakeDialer {
            session: FakeUdpSession::new(replies),
            dial_count: Arc::new(AtomicUsize::new(0)),
        });
        let dial_count = node_dialer.dial_count.clone();
        let group: Arc<dyn OutboundDialer> = Arc::new(GroupDialer::new(
            "g".into(),
            vec![GroupNode::new("a".into(), node_dialer)],
            PolicyType::Fixed,
        ));

        // 预置一个绑定到其它节点名（"stale"）的持久会话 → 应识别为节点已切换而重建。
        {
            let mut sessions = f.proxy_sessions.lock().unwrap();
            sessions.insert(
                "proxy".to_string(),
                ("stale".to_string(), Arc::new(FakeUdpSession::new(VecDeque::new()))),
            );
        }

        let resp = f
            .forward_via_proxy("proxy", &q, group.as_ref(), server)
            .await
            .unwrap();
        assert_eq!(resp, vec![0xaa]);
        // 重建 = 底层节点拨号器被调用一次，且会话按新节点名记录。
        assert_eq!(dial_count.load(Ordering::SeqCst), 1);
        let (stored_node, _) = f
            .proxy_sessions
            .lock()
            .unwrap()
            .get("proxy")
            .cloned()
            .expect("session should exist");
        assert_eq!(stored_node, "a");
    }

    /// 组内节点全挂（udp_dial 失败）→ resolve 回退直连；直连无上游时报
    /// "no direct upstream available"（证明走的是直连路径而非代理错误）。
    #[tokio::test]
    async fn test_resolve_group_unavailable_falls_back_to_direct() {
        let mut cfg = DnsConfig::default();
        cfg.proxy_dns_servers = vec!["8.8.8.8:53".into()];
        cfg.direct_dns_servers = Vec::new();
        cfg.direct_use_system_dns = false;
        let mut dialers: HashMap<String, Arc<dyn OutboundDialer>> = HashMap::new();
        dialers.insert("proxy".into(), Arc::new(AlwaysFailDialer));
        let f = DnsForwarder::new(&cfg, vec![], dialers, DnsOutbound::Group("proxy".into()), None)
            .unwrap();
        let q = build_query(0x1234, "example.com", 1);
        let err = f.resolve(&q).await.unwrap_err();
        assert!(
            err.to_string().contains("no direct upstream available"),
            "unexpected error: {}",
            err
        );
    }

    /// udp_dial 总是失败的拨号器（模拟组内节点全部不可用）。
    struct AlwaysFailDialer;

    #[async_trait::async_trait]
    impl OutboundDialer for AlwaysFailDialer {
        async fn dial(&self, _target: &str) -> anyhow::Result<ProxyConn> {
            anyhow::bail!("always fail dial")
        }
        async fn udp_dial(&self) -> anyhow::Result<Box<dyn UdpSession>> {
            anyhow::bail!("simulated group udp dial failure")
        }
        fn protocol_name(&self) -> &'static str {
            "fake"
        }
        fn proxy_addr(&self) -> SocketAddr {
            "127.0.0.1:1080".parse().unwrap()
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }
}
