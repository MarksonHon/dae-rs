//! DNS 转发器
//!
//! 基于 eBPF TProxy 基础设施构建的 UDP DNS 透明转发器，实现按代理组粒度的
//! DNS 查询转发与缓存。
//!
//! # 数据流
//!
//! ```text
//! UdpTproxyListener (IP_RECVORIGDSTADDR 获取 orig_dst)
//!         │  packet, orig_dst, client_addr
//!         ▼
//! DnsForwarder::handle_query
//!   ├─ extract_query_info → (domain, qtype)
//!   ├─ RoutingMatcher::match_routing（基于被查询域名）
//!   └─ 三路分派:
//!        ├─ DIRECT → 原包透传到 orig_dst（不打 mark，不缓存）
//!        ├─ PROXY_GROUP → 缓存 / 并发去重 / 经代理组查远端 DNS / 缓存 / 伪装响应
//!        └─ BLOCK → 构造 NXDOMAIN 响应
//! ```
//!
//! 响应统一通过绑定到 `orig_dst` 的 `IP_TRANSPARENT` UDP socket 伪装源地址
//! 发回客户端，客户端无感知。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use lru::LruCache;
use protocols::hostns::DirectSocket;
use protocols::OutboundDialer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, warn};

use crate::config::DnsConfig;
use crate::net::ebpf::outbound;
use crate::net::tproxy::extract_dns_query_name;
use crate::routing::matcher::{RoutingMatcher, RoutingParams};

// ============================================================================
// DnsCache —— 单个代理组的 DNS 缓存
// ============================================================================

/// 单个代理组的 DNS 缓存。
///
/// 使用 LRU 淘汰 + TTL 惰性过期，缓存完整的 DNS 响应包（可直接发回客户端）。
#[derive(Debug)]
pub struct DnsCache {
    entries: LruCache<DnsCacheKey, DnsCacheEntry>,
    stats: CacheStats,
}

/// 缓存键：规范化小写域名 + 查询类型 + 查询类。
#[derive(Hash, PartialEq, Eq, Clone)]
struct DnsCacheKey {
    /// 规范化的小写域名
    domain: String,
    /// DNS 查询类型（1=A, 28=AAAA）
    qtype: u16,
    /// DNS 查询类（1=IN），默认 IN
    qclass: u16,
}

/// 缓存条目。
struct DnsCacheEntry {
    /// 完整 DNS 响应包（可直接发回客户端）
    response_raw: Vec<u8>,
    /// 过期时间 = 插入时间 + 上游返回的原始 TTL
    expire_at: Instant,
}

/// 缓存统计信息。
#[derive(Debug, Default, Clone, Copy)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
}

impl DnsCache {
    /// 创建一个容量为 `max_size` 的 DNS 缓存。
    ///
    /// `max_size` 为 0 时退化为最小容量 1，避免 `NonZeroUsize` 构造失败。
    pub fn new(max_size: usize) -> Self {
        let cap = NonZeroUsize::new(max_size).unwrap_or_else(|| NonZeroUsize::new(1).unwrap());
        Self {
            entries: LruCache::new(cap),
            stats: CacheStats::default(),
        }
    }

    /// 查询缓存，自动惰性淘汰过期条目，更新统计。
    ///
    /// 命中且未过期 → `Some(完整响应包)`；未命中或已过期 → `None`。
    pub fn get(&mut self, domain: &str, qtype: u16, qclass: u16) -> Option<Vec<u8>> {
        let key = DnsCacheKey {
            domain: domain.to_ascii_lowercase(),
            qtype,
            qclass,
        };
        let now = Instant::now();
        match self.entries.get(&key) {
            Some(entry) if entry.expire_at > now => {
                self.stats.hits += 1;
                Some(entry.response_raw.clone())
            }
            Some(_) => {
                // 已过期：惰性淘汰，不改变 LRU 顺序以外的状态
                self.entries.pop(&key);
                self.stats.misses += 1;
                None
            }
            None => {
                self.stats.misses += 1;
                None
            }
        }
    }

    /// 写入缓存，TTL 原样使用不钳制。
    pub fn put(&mut self, domain: &str, qtype: u16, qclass: u16, response: Vec<u8>, ttl_secs: u32) {
        let key = DnsCacheKey {
            domain: domain.to_ascii_lowercase(),
            qtype,
            qclass,
        };
        let expire_at = Instant::now() + Duration::from_secs(ttl_secs as u64);
        self.entries.put(
            key,
            DnsCacheEntry {
                response_raw: response,
                expire_at,
            },
        );
    }

    /// 当前缓存条目数。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 缓存是否为空。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 缓存统计信息。
    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }
}

// ============================================================================
// InflightQueries —— 并发查询去重
// ============================================================================

/// 并发查询去重：相同 `(group, domain, qtype)` 的查询合并为一次上游请求。
#[derive(Debug, Default)]
pub struct InflightQueries {
    queries: DashMap<String, broadcast::Sender<Vec<u8>>>,
}

impl InflightQueries {
    /// 创建一个空的并发查询去重表。
    pub fn new() -> Self {
        Self {
            queries: DashMap::new(),
        }
    }

    /// 尝试发起一个查询。
    ///
    /// key = `"{group}:{domain}:{qtype}"`
    ///
    /// - key 不存在 → 创建 `broadcast::channel(1)` 存储 sender，返回 `None`
    ///   （表示调用方需要发起上游查询）
    /// - key 存在 → 订阅 receiver，返回 `Some(receiver)`（表示等待已有查询结果）
    pub fn try_start(
        &self,
        group: &str,
        domain: &str,
        qtype: u16,
    ) -> Option<broadcast::Receiver<Vec<u8>>> {
        let key = format!("{group}:{domain}:{qtype}");
        if let Some(sender) = self.queries.get(&key) {
            // 已有查询进行中：订阅其结果
            let sender = sender.value().clone();
            return Some(sender.subscribe());
        }
        // 无进行中查询：创建 channel 并存储 sender
        let (tx, _rx) = broadcast::channel(1);
        self.queries.insert(key, tx);
        None
    }

    /// 上游查询成功：向所有等待者广播结果，并从 map 中移除 key。
    pub fn complete(&self, group: &str, domain: &str, qtype: u16, response: Vec<u8>) {
        let key = format!("{group}:{domain}:{qtype}");
        if let Some((_, sender)) = self.queries.remove(&key) {
            // 无接收者时 send 返回 Err，忽略即可
            let _ = sender.send(response);
        }
    }

    /// 上游查询失败：移除 key（丢弃 sender），等待者会收到 `RecvError::Closed`
    /// 从而按失败路径（SERVFAIL）处理。
    pub fn complete_failed(&self, group: &str, domain: &str, qtype: u16) {
        let key = format!("{group}:{domain}:{qtype}");
        self.queries.remove(&key);
    }

    /// 当前进行中的查询数量（主要用于诊断）。
    pub fn len(&self) -> usize {
        self.queries.len()
    }

    /// 是否没有进行中的查询。
    pub fn is_empty(&self) -> bool {
        self.queries.is_empty()
    }
}

/// Drop guard：确保 leader 查询无论以何种方式结束（成功/失败/被取消/panic）都会清理
/// [`InflightQueries`] 中的 key，避免 leader 被 abort 时 key 永久残留，导致该
/// `(group, domain, qtype)` 后续所有查询永久卡死（订阅到永远不会有结果的 channel）。
///
/// 正常成功路径调用 [`complete`](InflightGuard::disarm) 后必须 [`disarm`](InflightGuard::disarm)，
/// 因为 [`InflightQueries::complete`] 已移除 key 并广播结果。
struct InflightGuard<'a> {
    inflight: &'a InflightQueries,
    key: String,
    disarmed: bool,
}

impl<'a> InflightGuard<'a> {
    fn new(inflight: &'a InflightQueries, group: &str, domain: &str, qtype: u16) -> Self {
        Self {
            inflight,
            key: format!("{group}:{domain}:{qtype}"),
            disarmed: false,
        }
    }

    fn disarm(&mut self) {
        self.disarmed = true;
    }
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        if !self.disarmed {
            // 移除 key 并通知等待者失败（channel 关闭 → 等待者按 SERVFAIL 处理）。
            self.inflight.queries.remove(&self.key);
        }
    }
}

// ============================================================================
// GroupDnsDialer —— 代理组 DNS 拨号器
// ============================================================================

/// 代理组的 DNS 拨号器，封装该组的出站拨号器和远端 DNS 服务器地址。
pub struct GroupDnsDialer {
    /// 代理组的出站拨号器
    pub dialer: Arc<dyn OutboundDialer>,
    /// 远端 DNS 服务器地址（如 `8.8.8.8:53`）
    pub remote_dns: SocketAddr,
}

// ============================================================================
// DnsForwardError —— 错误类型
// ============================================================================

/// DNS 转发错误。
#[derive(Debug, thiserror::Error)]
pub enum DnsForwardError {
    /// DNS 查询超时
    #[error("DNS 查询超时")]
    Timeout,
    /// 无效的 DNS 包
    #[error("无效的 DNS 包")]
    InvalidPacket,
    /// 上游查询失败
    #[error("上游查询失败: {0}")]
    UpstreamFailed(String),
    /// IO 错误
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
}

// ============================================================================
// DnsForwarder —— 核心转发器
// ============================================================================

/// DNS 转发器核心。
///
/// 响应伪装 socket 池容量上限（LRU 淘汰）。
///
/// 与 [`crate::net::tproxy`] 的 `RespSocketPool` 上限保持一致，防止对每个不同的
/// `orig_dst` 创建的 `IP_TRANSPARENT` socket 无限累积。
const RESP_SOCKET_POOL_CAP: usize = 256;

/// 接收来自 [`crate::net::tproxy`] 的 DNS 查询，基于被查询域名路由并分派到
/// DIRECT / 代理组 / BLOCK 三条路径，统一通过 `IP_TRANSPARENT` socket 伪装响应。
pub struct DnsForwarder {
    /// DNS 转发器配置
    config: DnsConfig,
    /// 路由匹配器
    routing_matcher: Arc<RoutingMatcher>,
    /// outbound id → 组名 反向映射（O(1) 从路由结果还原具体代理组名）
    group_by_outbound_id: HashMap<u8, String>,
    /// 按代理组维护的 DNS 缓存池，key = outbound_group_name
    group_caches: RwLock<HashMap<String, DnsCache>>,
    /// 按代理组维护的远端 dialer
    group_dialers: HashMap<String, Arc<GroupDnsDialer>>,
    /// 并发查询去重
    inflight_queries: InflightQueries,
    /// 响应伪装 socket 池（`IP_TRANSPARENT`），key = orig_dst，LRU 淘汰
    resp_sockets: Mutex<LruCache<SocketAddr, Arc<UdpSocket>>>,
    /// 宿主网络命名空间 fd。
    ///
    /// TProxy 线程运行在 daens 中，DIRECT 查询 socket 必须在宿主命名空间创建
    /// （回包源地址才是宿主真实 WAN 地址，kdae-aligned）。IP_TRANSPARENT 响应
    /// socket 则在 daens 创建：响应经 dae0peer → dae0 → redirect_track 被重定向到
    /// WAN 物理网卡 ingress 投递给客户端。若在宿主 NS 创建，发往本机自身地址
    /// （local 路由，走 lo）的伪源响应会被内核按 martian/rp_filter 丢弃。
    /// `None` 表示在当前命名空间创建。
    host_ns_fd: Option<RawFd>,
}

impl DnsForwarder {
    /// 创建一个 DNS 转发器。
    ///
    /// # 参数
    ///
    /// - `config` — DNS 转发器配置
    /// - `routing_matcher` — 路由匹配器
    /// - `group_outbound_ids` — 组名 → outbound id 映射，用于从路由结果还原代理组名
    /// - `group_caches` — 按代理组预建的 DNS 缓存池
    /// - `group_dialers` — 按代理组预建的远端 dialer
    pub fn new(
        config: DnsConfig,
        routing_matcher: Arc<RoutingMatcher>,
        group_outbound_ids: HashMap<String, u8>,
        group_caches: HashMap<String, DnsCache>,
        group_dialers: HashMap<String, Arc<GroupDnsDialer>>,
        host_ns_fd: Option<RawFd>,
    ) -> Self {
        let group_by_outbound_id = group_outbound_ids
            .into_iter()
            .map(|(n, id)| (id, n))
            .collect();
        Self {
            config,
            routing_matcher,
            group_by_outbound_id,
            group_caches: RwLock::new(group_caches),
            group_dialers,
            inflight_queries: InflightQueries::new(),
            resp_sockets: Mutex::new(LruCache::new(
                NonZeroUsize::new(RESP_SOCKET_POOL_CAP)
                    .expect("RESP_SOCKET_POOL_CAP must be non-zero"),
            )),
            host_ns_fd,
        }
    }

    /// 处理被劫持的 DNS 查询。
    ///
    /// # 参数
    ///
    /// - `packet` — 原始 DNS 查询包
    /// - `orig_dst` — 客户端原目标 DNS 服务器地址（用于伪装响应源地址）
    /// - `client_addr` — 客户端地址（用于发送响应）
    pub async fn handle_query(
        &self,
        packet: &[u8],
        orig_dst: SocketAddr,
        client_addr: SocketAddr,
    ) -> Result<(), DnsForwardError> {
        // 1. 提取域名、查询类型和查询类
        let Some((domain, qtype, qclass)) = extract_query_info(packet) else {
            // 解析失败 → 透传到 orig_dst（无法匹配路由，安全兜底）
            warn!("DNS 查询解析失败，透传到 {}", orig_dst);
            return self.handle_direct(packet, orig_dst, client_addr).await;
        };

        // 2. 基于被查询域名匹配路由。同时填充 dst_ip（被查询的 DNS 服务器地址）和
        //    src_ip（发起查询的客户端地址），使 `dip()`/`sip()` 规则在 DNS 上下文中
        //    也能表达"基于被查询的 DNS 服务器 / 发起客户端"分流。
        let params = RoutingParams {
            domain: Some(domain.clone()),
            qtype: Some(qtype),
            dst_ip: Some(orig_dst.ip()),
            src_ip: Some(client_addr.ip()),
            ..Default::default()
        };
        let result = self.routing_matcher.match_routing(&params);

        // 3. 分派
        if result.outbound == outbound::DIRECT {
            // DIRECT：原包透传，不缓存
            return self.handle_direct(packet, orig_dst, client_addr).await;
        }

        if result.outbound == outbound::BLOCK {
            // BLOCK：构造 NXDOMAIN 响应
            return self.handle_block(packet, orig_dst, client_addr).await;
        }

        // 具体代理组：通过 outbound id 反向解析组名
        let group_name = match self.group_name_for_outbound(result.outbound) {
            Some(name) => name,
            None => {
                if result.must {
                    // must 规则要求走代理，但找不到对应代理组：不能退回 DIRECT，直接 SERVFAIL
                    warn!(
                        "must 规则无法解析 outbound id {} 对应的代理组，返回 SERVFAIL",
                        result.outbound
                    );
                    let resp = build_servfail_response(packet);
                    return self.send_response(orig_dst, client_addr, &resp).await;
                }
                // 未知组 → 按 DIRECT 兜底透传
                warn!(
                    "无法解析 outbound id {} 对应的代理组，透传到 {}",
                    result.outbound, orig_dst
                );
                return self.handle_direct(packet, orig_dst, client_addr).await;
            }
        };

        self.handle_via_proxy(
            packet,
            &domain,
            qtype,
            qclass,
            group_name,
            orig_dst,
            client_addr,
        )
        .await
    }

    /// 反向解析 outbound id → 代理组名（O(1)）。
    fn group_name_for_outbound(&self, outbound_id: u8) -> Option<&str> {
        self.group_by_outbound_id
            .get(&outbound_id)
            .map(|name| name.as_str())
    }

    /// DIRECT 路径：原包经 UDP socket 发往 orig_dst（带 SO_MARK=DAE_SOCKET_MARK
    /// 做 eBPF 自排除，避免 dport-53 查询被重新劫持形成环路），
    /// 等待校验通过（txid 匹配且 QR=1）的响应后通过 `IP_TRANSPARENT` 伪装发回客户端。
    /// 不查/不写缓存。
    async fn handle_direct(
        &self,
        packet: &[u8],
        orig_dst: SocketAddr,
        client_addr: SocketAddr,
    ) -> Result<(), DnsForwardError> {
        // 创建带 SO_MARK=DAE_SOCKET_MARK 的 UDP socket（eBPF 自排除），避免 dport-53
        // 查询被 eBPF 重新劫持形成环路。与 create_resp_socket()/dialer 一致。
        let std_sock =
            protocols::hostns::create_udp(orig_dst, &DirectSocket::control_plane(self.host_ns_fd))?;
        let socket = UdpSocket::from_std(std_sock)?;
        // DIAG: verify socket binding & namespace. Created in the host NS via
        // control_plane(self.host_ns_fd); a local_addr of 0.0.0.0:ephemeral just
        // means it was bound to any, not that it was created in daens.
        match socket.local_addr() {
            Ok(la) => debug!(
                orig_dst = %orig_dst,
                local_addr = %la,
                "DNS DIRECT: query socket created (SO_MARK=DAE_SOCKET_MARK)"
            ),
            Err(e) => warn!(orig_dst = %orig_dst, err = %e, "DNS DIRECT: cannot read local_addr"),
        }
        let orig_txid = u16::from_be_bytes([packet[0], packet[1]]);
        debug!(
            orig_dst = %orig_dst,
            orig_txid = orig_txid,
            socket_marked = true,
            "DNS DIRECT: marked query socket created (SO_MARK=DAE_SOCKET_MARK)"
        );
        if let Err(e) = socket.send_to(packet, orig_dst).await {
            warn!(orig_dst = %orig_dst, err = %e, "DNS DIRECT: send_to failed");
            return Err(e.into());
        }
        // connect() 到 orig_dst：内核只投递来自该地址的数据报，天然过滤无关来源（抗污染）。
        if let Err(e) = socket.connect(orig_dst).await {
            warn!(orig_dst = %orig_dst, err = %e, "DNS DIRECT: connect() failed");
            return Err(e.into());
        }

        let timeout = Duration::from_millis(self.config.query_timeout_ms);
        let deadline = Instant::now() + timeout;
        let mut buf = vec![0u8; 65535];
        let response = loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                warn!(
                    orig_dst = %orig_dst,
                    orig_txid = orig_txid,
                    "DNS DIRECT: query timed out (possible eBPF re-hijack loop on unmarked socket)"
                );
                return Err(DnsForwardError::Timeout);
            }
            let (n, _src) = match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await
            {
                Ok(Ok(x)) => x,
                Ok(Err(e)) => {
                    warn!(orig_dst = %orig_dst, err = %e, "DNS DIRECT: recv_from IO error");
                    return Err(e.into());
                }
                Err(_) => {
                    warn!(
                        orig_dst = %orig_dst,
                        orig_txid = orig_txid,
                        "DNS DIRECT: query timed out (possible eBPF re-hijack loop on unmarked socket)"
                    );
                    return Err(DnsForwardError::Timeout);
                }
            };
            // 校验 txid 匹配且 QR=1，过滤过期/伪造/无关数据报后继续等待
            let resp = &buf[..n];
            let valid = resp.len() >= 12
                && resp[0] == packet[0]
                && resp[1] == packet[1]
                && resp[2] & 0x80 != 0;
            if valid {
                break resp.to_vec();
            }
            debug!(
                orig_dst = %orig_dst,
                orig_txid = orig_txid,
                "DNS DIRECT: discarding mismatched datagram (txid/QR), retrying within timeout"
            );
        };
        let resp_txid = u16::from_be_bytes([response[0], response[1]]);
        debug!(orig_dst = %orig_dst, orig_txid = orig_txid, resp_txid = resp_txid, "DNS DIRECT: response received");

        // 通过 IP_TRANSPARENT 伪装响应发回客户端
        self.send_response(orig_dst, client_addr, &response).await
    }

    /// BLOCK 路径：构造 NXDOMAIN 响应并通过 `IP_TRANSPARENT` 发回客户端。不缓存。
    async fn handle_block(
        &self,
        packet: &[u8],
        orig_dst: SocketAddr,
        client_addr: SocketAddr,
    ) -> Result<(), DnsForwardError> {
        let resp = build_nxdomain_response(packet);
        if resp.is_empty() {
            return Err(DnsForwardError::InvalidPacket);
        }
        self.send_response(orig_dst, client_addr, &resp).await
    }

    /// 代理组路径：缓存 → 并发去重 → 上游查询 → 缓存/广播 → 伪装响应。
    #[allow(clippy::too_many_arguments)]
    async fn handle_via_proxy(
        &self,
        packet: &[u8],
        domain: &str,
        qtype: u16,
        qclass: u16,
        group_name: &str,
        orig_dst: SocketAddr,
        client_addr: SocketAddr,
    ) -> Result<(), DnsForwardError> {
        // 1. 查缓存
        {
            let mut caches = self.group_caches.write().await;
            if let Some(cache) = caches.get_mut(group_name) {
                if let Some(resp) = cache.get(domain, qtype, qclass) {
                    debug!("DNS 缓存命中: {} {}", group_name, domain);
                    // 缓存中的响应带的是上游查询的 txid，改写为当前客户端原查询的 txid
                    let client_resp = match_client_txid(&resp, packet);
                    return self
                        .send_response(orig_dst, client_addr, &client_resp)
                        .await;
                }
            }
        }

        // 2. 并发查询去重
        if let Some(mut rx) = self.inflight_queries.try_start(group_name, domain, qtype) {
            // 已有查询进行中，等待其结果。等待上限与 leader 的最坏总耗时一致，
            // 避免 leader 尚未完成时等待者提前 SERVFAIL。
            debug!("DNS 查询去重，等待已有查询: {} {}", group_name, domain);
            let wait_budget = self.total_query_budget();
            match tokio::time::timeout(wait_budget, rx.recv()).await {
                Ok(Ok(resp)) => {
                    let client_resp = match_client_txid(&resp, packet);
                    return self
                        .send_response(orig_dst, client_addr, &client_resp)
                        .await;
                }
                _ => {
                    // 等待超时或上游失败（channel 关闭）→ 返回 SERVFAIL
                    let resp = build_servfail_response(packet);
                    return self.send_response(orig_dst, client_addr, &resp).await;
                }
            }
        }

        // 3. None 表示由我们发起上游查询。InflightGuard 保证无论查询以何种方式结束
        //    （成功/失败/被取消）都会清理 inflight 表中的 key，避免 key 永久残留。
        let mut guard = InflightGuard::new(&self.inflight_queries, group_name, domain, qtype);
        let result = self.query_upstream(group_name, domain, qtype).await;

        match result {
            Ok(resp) => {
                // 写缓存（TTL 原样使用不钳制）
                let ttl = extract_min_ttl(&resp);
                {
                    let mut caches = self.group_caches.write().await;
                    if let Some(cache) = caches.get_mut(group_name) {
                        cache.put(domain, qtype, qclass, resp.clone(), ttl);
                    }
                }
                // 向并发等待者广播结果，guard 已完成使命
                self.inflight_queries
                    .complete(group_name, domain, qtype, resp.clone());
                guard.disarm();
                let client_txid = u16::from_be_bytes([packet[0], packet[1]]);
                let resp_txid = u16::from_be_bytes([resp[0], resp[1]]);
                if client_txid != resp_txid {
                    debug!(
                        client_txid = client_txid,
                        resp_txid = resp_txid,
                        "DNS proxy: upstream response txid differs from client query txid, rewriting to client txid"
                    );
                }
                let client_resp = match_client_txid(&resp, packet);
                self.send_response(orig_dst, client_addr, &client_resp)
                    .await
            }
            Err(e) => {
                // 上游失败：通知等待者（channel 关闭 → 等待者走 SERVFAIL）
                self.inflight_queries
                    .complete_failed(group_name, domain, qtype);
                guard.disarm();
                warn!("DNS 上游查询失败 {} {}: {}", group_name, domain, e);
                // 返回 SERVFAIL
                let resp = build_servfail_response(packet);
                self.send_response(orig_dst, client_addr, &resp).await
            }
        }
    }

    /// leader 上游查询的最坏总耗时。
    ///
    /// - `Parallel`：所有上游并发，≤ 单次超时；
    /// - `Sequential`：按顺序故障转移，≤ 目标数 × 单次超时。
    ///
    /// 用于两处：① 为 [`query_upstream`](Self::query_upstream) 提供整体超时上界；
    /// ② 并发去重等待者用它作为等待上限，保证不会在 leader 完成前提前 SERVFAIL。
    fn total_query_budget(&self) -> Duration {
        let timeout = Duration::from_millis(self.config.query_timeout_ms);
        let n = self.config.upstream_remote.len().max(1) as u32;
        match self.config.upstream_strategy {
            crate::config::UpstreamStrategy::Parallel => timeout,
            crate::config::UpstreamStrategy::Sequential => timeout.saturating_mul(n),
        }
    }

    /// Send DNS query over TCP through the proxy (DNS-over-TCP, RFC 1035 §4.2.2).
    ///
    /// Uses `dial()` (TCP CONNECT) instead of `udp_dial()` so the proxy only needs
    /// to support TCP forwarding — eliminating the dependency on UDP relay support
    /// which many proxy servers do not implement.
    ///
    /// Respects [`UpstreamStrategy`] to query multiple upstream DNS servers:
    /// - `Parallel`: query all concurrently, take the fastest success.
    /// - `Sequential`: try one by one, fall through to the next on failure.
    async fn query_upstream(
        &self,
        group_name: &str,
        domain: &str,
        qtype: u16,
    ) -> Result<Vec<u8>, DnsForwardError> {
        let dialer = self.group_dialers.get(group_name).ok_or_else(|| {
            DnsForwardError::UpstreamFailed(format!("代理组不存在: {group_name}"))
        })?;

        let query = build_dns_query(domain, qtype)?;
        let query_txid = u16::from_be_bytes([query[0], query[1]]);

        // Collect all upstream targets to try.
        let targets: Vec<SocketAddr> = if self.config.upstream_remote.is_empty() {
            vec![dialer.remote_dns]
        } else {
            self.config.upstream_remote.clone()
        };

        debug!(
            group = group_name,
            domain = domain,
            qtype = qtype,
            query_txid = query_txid,
            targets = ?targets,
            strategy = ?self.config.upstream_strategy,
            timeout_ms = self.config.query_timeout_ms,
            "DNS proxy: starting upstream query via TCP over proxy"
        );

        let timeout = Duration::from_millis(self.config.query_timeout_ms);
        let budget = self.total_query_budget();

        // 整个上游查询受整体超时上界约束（parallel ≤ 单次超时，sequential ≤ N×单次超时），
        // 保证 leader 一定能按时结束，等待者也能在相同上界内等到结果。
        use std::future::Future;
        use std::pin::Pin;
        let fut: Pin<Box<dyn Future<Output = Result<Vec<u8>, DnsForwardError>> + Send + '_>> =
            match self.config.upstream_strategy {
                crate::config::UpstreamStrategy::Parallel => {
                    Box::pin(self.query_upstream_parallel(
                        dialer, &query, query_txid, &targets, group_name, domain, timeout,
                    ))
                }
                crate::config::UpstreamStrategy::Sequential => {
                    Box::pin(self.query_upstream_sequential(
                        dialer, &query, query_txid, &targets, group_name, domain, timeout,
                    ))
                }
            };
        match tokio::time::timeout(budget, fut).await {
            Ok(r) => r,
            Err(_) => {
                warn!(
                    group = group_name,
                    domain = domain,
                    qtype = qtype,
                    budget_ms = budget.as_millis(),
                    "DNS proxy: upstream query hit overall budget cap"
                );
                Err(DnsForwardError::Timeout)
            }
        }
    }

    /// Try a single DNS-over-TCP query to one upstream. Returns the raw DNS
    /// response on success.
    ///
    /// Each phase (dial / write / read-len / read-body) is logged at `debug`
    /// level so timeouts can be pinpointed.
    async fn try_query_single(
        &self,
        dialer: &Arc<GroupDnsDialer>,
        query: &[u8],
        query_txid: u16,
        target: SocketAddr,
        group_name: &str,
        domain: &str,
        timeout: Duration,
    ) -> Result<Vec<u8>, DnsForwardError> {
        // ── Phase 1: dial ──
        let dial_start = Instant::now();
        let mut conn = dialer.dialer.dial(&target.to_string()).await.map_err(|e| {
            warn!(
                group = group_name,
                domain = domain,
                target = %target,
                elapsed_ms = dial_start.elapsed().as_millis(),
                error = %e,
                "DNS proxy: dial() FAILED"
            );
            DnsForwardError::UpstreamFailed(e.to_string())
        })?;
        debug!(
            group = group_name,
            domain = domain,
            target = %target,
            elapsed_ms = dial_start.elapsed().as_millis(),
            "DNS proxy: dial() OK, TCP connection established through proxy"
        );

        // ── Phase 2: send DNS-over-TCP framed query ──
        let len_be = (query.len() as u16).to_be_bytes();
        let mut tcp_frame = Vec::with_capacity(2 + query.len());
        tcp_frame.extend_from_slice(&len_be);
        tcp_frame.extend_from_slice(query);

        let write_start = Instant::now();
        tokio::time::timeout(timeout, conn.write_all(&tcp_frame))
            .await
            .map_err(|_| {
                warn!(
                    group = group_name,
                    domain = domain,
                    target = %target,
                    elapsed_ms = write_start.elapsed().as_millis(),
                    "DNS proxy: write_all() TIMED OUT after sending DNS-over-TCP query"
                );
                DnsForwardError::Timeout
            })?
            .map_err(|e| {
                warn!(
                    group = group_name,
                    domain = domain,
                    target = %target,
                    elapsed_ms = write_start.elapsed().as_millis(),
                    error = %e,
                    "DNS proxy: write_all() IO ERROR"
                );
                DnsForwardError::UpstreamFailed(e.to_string())
            })?;
        debug!(
            group = group_name,
            domain = domain,
            target = %target,
            query_len = query.len(),
            elapsed_ms = write_start.elapsed().as_millis(),
            "DNS proxy: write_all() OK, DNS-over-TCP query sent"
        );

        // ── Phase 3: read 2-byte response length prefix ──
        let mut len_buf = [0u8; 2];
        let read_len_start = Instant::now();
        tokio::time::timeout(timeout, conn.read_exact(&mut len_buf))
            .await
            .map_err(|_| {
                warn!(
                    group = group_name,
                    domain = domain,
                    target = %target,
                    query_txid = query_txid,
                    elapsed_ms = read_len_start.elapsed().as_millis(),
                    "DNS proxy: read_exact(len) TIMED OUT — upstream DNS {} did not respond (TCP/53 blocked?)",
                    target
                );
                DnsForwardError::Timeout
            })?
            .map_err(|e| {
                warn!(
                    group = group_name,
                    domain = domain,
                    target = %target,
                    query_txid = query_txid,
                    elapsed_ms = read_len_start.elapsed().as_millis(),
                    error = %e,
                    "DNS proxy: read_exact(len) IO ERROR"
                );
                DnsForwardError::UpstreamFailed(e.to_string())
            })?;
        debug!(
            group = group_name,
            domain = domain,
            target = %target,
            elapsed_ms = read_len_start.elapsed().as_millis(),
            "DNS proxy: read_exact(len) OK"
        );

        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len == 0 || resp_len > 65535 {
            warn!(
                group = group_name,
                domain = domain,
                target = %target,
                resp_len = resp_len,
                "DNS proxy: invalid DNS-over-TCP response length"
            );
            return Err(DnsForwardError::UpstreamFailed(format!(
                "invalid DNS-over-TCP response length: {resp_len}"
            )));
        }
        debug!(
            group = group_name,
            domain = domain,
            target = %target,
            resp_len = resp_len,
            "DNS proxy: response length = {resp_len} bytes"
        );

        // ── Phase 4: read DNS response body ──
        let mut resp = vec![0u8; resp_len];
        let read_body_start = Instant::now();
        tokio::time::timeout(timeout, conn.read_exact(&mut resp))
            .await
            .map_err(|_| {
                warn!(
                    group = group_name,
                    domain = domain,
                    target = %target,
                    resp_len = resp_len,
                    elapsed_ms = read_body_start.elapsed().as_millis(),
                    "DNS proxy: read_exact(body) TIMED OUT"
                );
                DnsForwardError::Timeout
            })?
            .map_err(|e| {
                warn!(
                    group = group_name,
                    domain = domain,
                    target = %target,
                    resp_len = resp_len,
                    elapsed_ms = read_body_start.elapsed().as_millis(),
                    error = %e,
                    "DNS proxy: read_exact(body) IO ERROR"
                );
                DnsForwardError::UpstreamFailed(e.to_string())
            })?;

        // ── Phase 5: validate ──
        if resp.len() < 12 || resp[2] & 0x80 == 0 {
            warn!(
                group = group_name,
                domain = domain,
                target = %target,
                resp_len = resp.len(),
                "DNS proxy: response is not a valid DNS response (QR != 1)"
            );
            return Err(DnsForwardError::UpstreamFailed(
                "TCP DNS response is not a valid DNS response (QR != 1)".into(),
            ));
        }
        // 验证问题段回显，防止响应污染/伪造
        if !validate_response_echo(query, &resp) {
            warn!(
                group = group_name,
                domain = domain,
                target = %target,
                "DNS proxy: response question section does not match query (possible pollution)"
            );
            return Err(DnsForwardError::UpstreamFailed(
                "DNS response question section mismatch".into(),
            ));
        }

        let resp_txid = u16::from_be_bytes([resp[0], resp[1]]);
        debug!(
            group = group_name,
            domain = domain,
            target = %target,
            query_txid = query_txid,
            resp_txid = resp_txid,
            len = resp.len(),
            total_elapsed_ms = read_body_start.elapsed().as_millis(),
            "DNS proxy: TCP DNS response received successfully"
        );
        Ok(resp)
    }

    /// Query all upstreams concurrently (Parallel strategy), return the first
    /// successful response.
    ///
    /// 使用 [`JoinSet`] 跟踪所有查询任务：一旦某个上游成功，立即 `abort_all()`
    /// 取消其余仍在进行的查询，避免已返回后任务继续占用经代理的 TCP 连接。
    async fn query_upstream_parallel(
        &self,
        dialer: &Arc<GroupDnsDialer>,
        query: &[u8],
        query_txid: u16,
        targets: &[SocketAddr],
        group_name: &str,
        domain: &str,
        timeout: Duration,
    ) -> Result<Vec<u8>, DnsForwardError> {
        use tokio::task::JoinSet;

        let mut set = JoinSet::new();
        for &target in targets {
            let dialer = Arc::clone(dialer);
            let query = query.to_vec();
            let group_name = group_name.to_string();
            let domain = domain.to_string();
            set.spawn(async move {
                let result = Self::try_query_single_inline(
                    &dialer,
                    &query,
                    query_txid,
                    target,
                    &group_name,
                    &domain,
                    timeout,
                )
                .await;
                (target, result)
            });
        }

        let mut last_err: Option<(SocketAddr, DnsForwardError)> = None;
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((target, Ok(resp))) => {
                    // 首个成功：取消其余仍在进行的查询（连接随之关闭，不泄漏）。
                    set.abort_all();
                    debug!(
                        group = group_name,
                        domain = domain,
                        target = %target,
                        "DNS proxy parallel: got response from {}, cancelled other queries",
                        target
                    );
                    return Ok(resp);
                }
                Ok((target, Err(e))) => {
                    warn!(
                        group = group_name,
                        domain = domain,
                        target = %target,
                        error = %e,
                        "DNS proxy parallel: upstream {} failed",
                        target
                    );
                    last_err = Some((target, e));
                }
                Err(e) if e.is_cancelled() => {
                    // 其他任务被 abort_all() 取消，正常。
                }
                Err(e) => {
                    warn!(
                        group = group_name,
                        domain = domain,
                        error = %e,
                        "DNS proxy parallel: query task panicked"
                    );
                }
            }
        }

        Err(last_err.map(|(_, e)| e).unwrap_or_else(|| {
            DnsForwardError::UpstreamFailed("all upstreams failed (parallel)".into())
        }))
    }

    /// Query upstreams one by one (Sequential strategy).
    async fn query_upstream_sequential(
        &self,
        dialer: &Arc<GroupDnsDialer>,
        query: &[u8],
        query_txid: u16,
        targets: &[SocketAddr],
        group_name: &str,
        domain: &str,
        timeout: Duration,
    ) -> Result<Vec<u8>, DnsForwardError> {
        let mut last_err: Option<DnsForwardError> = None;

        for &target in targets {
            debug!(
                group = group_name,
                domain = domain,
                target = %target,
                "DNS proxy sequential: trying upstream {}",
                target
            );
            match self
                .try_query_single(
                    dialer, query, query_txid, target, group_name, domain, timeout,
                )
                .await
            {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    warn!(
                        group = group_name,
                        domain = domain,
                        target = %target,
                        error = %e,
                        "DNS proxy sequential: upstream {} failed, trying next",
                        target
                    );
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            DnsForwardError::UpstreamFailed("all upstreams failed (sequential)".into())
        }))
    }

    /// Inline single-upstream query (used by parallel spawn tasks that cannot
    /// borrow `&self`).
    ///
    /// This is a static copy of the dial/write/read logic kept in sync with
    /// [`try_query_single`].
    #[allow(clippy::too_many_arguments)]
    async fn try_query_single_inline(
        dialer: &Arc<GroupDnsDialer>,
        query: &[u8],
        query_txid: u16,
        target: SocketAddr,
        group_name: &str,
        domain: &str,
        timeout: Duration,
    ) -> Result<Vec<u8>, DnsForwardError> {
        // Phase 1: dial
        let mut conn = dialer.dialer.dial(&target.to_string()).await.map_err(|e| {
            warn!(
                group = group_name,
                domain = domain,
                target = %target,
                error = %e,
                "DNS proxy (inline): dial() FAILED"
            );
            DnsForwardError::UpstreamFailed(e.to_string())
        })?;

        // Phase 2: send
        let len_be = (query.len() as u16).to_be_bytes();
        let mut tcp_frame = Vec::with_capacity(2 + query.len());
        tcp_frame.extend_from_slice(&len_be);
        tcp_frame.extend_from_slice(query);

        tokio::time::timeout(timeout, conn.write_all(&tcp_frame))
            .await
            .map_err(|_| DnsForwardError::Timeout)?
            .map_err(|e| DnsForwardError::UpstreamFailed(e.to_string()))?;

        // Phase 3: read length
        let mut len_buf = [0u8; 2];
        tokio::time::timeout(timeout, conn.read_exact(&mut len_buf))
            .await
            .map_err(|_| {
                warn!(
                    group = group_name,
                    domain = domain,
                    target = %target,
                    query_txid = query_txid,
                    "DNS proxy (inline): read_exact(len) TIMED OUT"
                );
                DnsForwardError::Timeout
            })?
            .map_err(|e| DnsForwardError::UpstreamFailed(e.to_string()))?;

        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len == 0 || resp_len > 65535 {
            return Err(DnsForwardError::UpstreamFailed(format!(
                "invalid DNS-over-TCP response length: {resp_len}"
            )));
        }

        // Phase 4: read body
        let mut resp = vec![0u8; resp_len];
        tokio::time::timeout(timeout, conn.read_exact(&mut resp))
            .await
            .map_err(|_| DnsForwardError::Timeout)?
            .map_err(|e| DnsForwardError::UpstreamFailed(e.to_string()))?;

        // Phase 5: validate
        if resp.len() < 12 || resp[2] & 0x80 == 0 {
            return Err(DnsForwardError::UpstreamFailed(
                "TCP DNS response is not a valid DNS response (QR != 1)".into(),
            ));
        }
        // 验证问题段回显，防止响应污染/伪造
        if !validate_response_echo(query, &resp) {
            return Err(DnsForwardError::UpstreamFailed(
                "DNS response question section mismatch".into(),
            ));
        }

        let resp_txid = u16::from_be_bytes([resp[0], resp[1]]);
        debug!(
            group = group_name,
            domain = domain,
            target = %target,
            query_txid = query_txid,
            resp_txid = resp_txid,
            len = resp.len(),
            "DNS proxy (inline): response received"
        );
        Ok(resp)
    }

    // ========================================================================
    // IP_TRANSPARENT 响应发送
    // ========================================================================

    /// 获取或创建绑定到 `orig_dst` 的 `IP_TRANSPARENT` UDP socket。
    ///
    /// 在 daens（当前命名空间）创建，响应经 redirect_track 重定向回 WAN 物理网卡，
    /// 保证"客户端是本机地址"时响应也能投递（lo 上伪源响应会被内核丢弃）。
    /// LRU 容量上限 [`RESP_SOCKET_POOL_CAP`]，超出时淘汰最久未使用的 socket。
    async fn get_resp_socket(
        &self,
        orig_dst: SocketAddr,
    ) -> Result<Arc<UdpSocket>, DnsForwardError> {
        // 快速路径：已缓存
        {
            let mut pool = self.resp_sockets.lock().unwrap();
            if let Some(sock) = pool.get(&orig_dst) {
                return Ok(sock.clone());
            }
        }

        // 慢路径：创建 IP_TRANSPARENT socket 并绑定到 orig_dst（非本地地址）
        let sock = Arc::new(create_resp_socket(orig_dst).await?);

        // 并发创建竞态：已有人插入则复用其 socket
        let mut pool = self.resp_sockets.lock().unwrap();
        if let Some(existing) = pool.get(&orig_dst) {
            return Ok(existing.clone());
        }
        pool.put(orig_dst, sock.clone());
        Ok(sock)
    }

    /// 通过 `IP_TRANSPARENT` socket 发送 DNS 响应给客户端。
    async fn send_response(
        &self,
        orig_dst: SocketAddr,
        client_addr: SocketAddr,
        response: &[u8],
    ) -> Result<(), DnsForwardError> {
        let socket = self.get_resp_socket(orig_dst).await?;
        socket.send_to(response, client_addr).await?;
        Ok(())
    }
}

/// 创建绑定到 `target` 的 `IP_TRANSPARENT` UDP socket。
///
/// 复用 [`protocols::hostns::create_transparent_udp`]：在 bind 之前设置
/// `IP_TRANSPARENT`/`IPV6_TRANSPARENT`，并设置 `SO_MARK = DAE_SOCKET_MARK`
/// 让 eBPF 放行（转发器自身流量必须直连）。
///
/// 在**当前（daens）命名空间**创建：响应从 dae0peer 发出，经 dae0_ingress 命中
/// redirect_track 后被 bpf_redirect 到 WAN 物理网卡 ingress，再由 wan_ingress
/// 交给本地栈投递到客户端。不能在宿主 NS 创建——对"客户端是本机"的流量，伪源
/// 响应发往本机 local 地址会走 lo，且永远不会经过 eBPF 重定向路径，会被内核按
/// martian/rp_filter 丢弃（`net.ipv4.conf.lo.rp_filter=2`、`accept_local=0`）。
async fn create_resp_socket(target: SocketAddr) -> std::io::Result<UdpSocket> {
    let sock = DirectSocket::control_plane(None);
    let std_sock = protocols::hostns::create_transparent_udp(&target, &sock)?;
    UdpSocket::from_std(std_sock)
}

// ============================================================================
// DNS 包解析与构造辅助
// ============================================================================

/// 从 DNS 查询包提取域名、查询类型和查询类。
///
/// 复用 [`extract_dns_query_name`] 提取域名，并解析 QTYPE 和 QCLASS。返回
/// `(domain, qtype, qclass)`；包无效时返回 `None`。
fn extract_query_info(packet: &[u8]) -> Option<(String, u16, u16)> {
    let domain = extract_dns_query_name(packet)?;
    // 定位 QNAME 结束位置以读取 QTYPE 和 QCLASS
    let end = qname_end(packet, 12)?;
    if end + 4 > packet.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([packet[end], packet[end + 1]]);
    let qclass = u16::from_be_bytes([packet[end + 2], packet[end + 3]]);
    Some((domain, qtype, qclass))
}

/// 定位 DNS 问题段中 QNAME 结束后的偏移。
///
/// 支持压缩指针：若 QNAME 以压缩指针结尾，偏移为指针所在位置 + 2。
/// 返回紧跟在名字之后的位置；包无效返回 `None`。
fn qname_end(packet: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    let mut end = start;
    let mut jumped = false;
    let mut jumps = 0usize;
    loop {
        if pos >= packet.len() {
            return None;
        }
        let len = packet[pos] as usize;
        // 压缩指针（RFC 1035 §4.1.4）
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= packet.len() {
                return None;
            }
            if !jumped {
                end = pos + 2;
                jumped = true;
            }
            if jumps >= 10 {
                return None;
            }
            jumps += 1;
            let ptr = ((len & 0x3F) << 8) | packet[pos + 1] as usize;
            pos = ptr;
            continue;
        }
        if len == 0 {
            // 根标签（名字结束）
            if !jumped {
                end = pos + 1;
            }
            return Some(end);
        }
        pos += 1;
        if pos + len > packet.len() {
            return None;
        }
        pos += len;
    }
}

/// 跳过一条资源记录（RR）的 NAME 字段，返回紧随其后的偏移。
///
/// NAME 可能是普通标签序列或压缩指针（2 字节），因此需要按长度推进。
fn skip_rr_name(packet: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    loop {
        if pos >= packet.len() {
            return None;
        }
        let len = packet[pos] as usize;
        if len & 0xC0 == 0xC0 {
            // 压缩指针占 2 字节
            if pos + 1 >= packet.len() {
                return None;
            }
            return Some(pos + 2);
        }
        if len == 0 {
            return Some(pos + 1);
        }
        pos += 1;
        if pos + len > packet.len() {
            return None;
        }
        pos += len;
    }
}

/// 构造新的 DNS 查询包（针对指定域名和类型，QCLASS=IN，RD=1，随机事务 ID）。
///
/// 包含 EDNS0 OPT 伪记录（RFC 6891），UDP payload size = 4096。
/// 校验每个 label（RFC 1035：1..=63 字节）与总长度（≤255 字节），非法域名返回
/// [`DnsForwardError::InvalidPacket`]，避免静默构造出与请求不符的查询包。
fn build_dns_query(domain: &str, qtype: u16) -> Result<Vec<u8>, DnsForwardError> {
    // 校验 label 与总长度（点分隔后的总字节数）
    let mut total = 0usize;
    for label in domain.split('.') {
        let len = label.len();
        if len == 0 || len > 63 {
            return Err(DnsForwardError::InvalidPacket);
        }
        total += 1 + len;
    }
    total += 1; // 根标签
    if total > 255 {
        return Err(DnsForwardError::InvalidPacket);
    }

    let mut buf = Vec::with_capacity(64 + domain.len() + 11);
    // 事务 ID（随机）
    let txid = fastrand::u16(..);
    buf.extend_from_slice(&txid.to_be_bytes());
    // 标志：RD=1
    buf.extend_from_slice(&0x0100u16.to_be_bytes());
    // QDCOUNT=1
    buf.extend_from_slice(&1u16.to_be_bytes());
    // ANCOUNT=0, NSCOUNT=0
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    // ARCOUNT=1 (EDNS0 OPT pseudo-record)
    buf.extend_from_slice(&1u16.to_be_bytes());
    // QNAME
    for label in domain.split('.') {
        let len = label.len();
        buf.push(len as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // 根标签
                 // QTYPE
    buf.extend_from_slice(&qtype.to_be_bytes());
    // QCLASS = IN (1)
    buf.extend_from_slice(&1u16.to_be_bytes());
    // EDNS0 OPT pseudo-record (RFC 6891)
    // NAME = 0 (root label)
    buf.push(0);
    // TYPE = OPT (41)
    buf.extend_from_slice(&41u16.to_be_bytes());
    // CLASS = UDP payload size (4096)
    buf.extend_from_slice(&4096u16.to_be_bytes());
    // TTL = extended RCODE(0) | version(0) | flags(0)
    buf.extend_from_slice(&0u32.to_be_bytes());
    // RDLEN = 0 (no options)
    buf.extend_from_slice(&0u16.to_be_bytes());
    Ok(buf)
}

/// 构造错误响应（回显原查询 ID 和问题段）。
///
/// 将 DNS 响应的事务 ID（前两字节）改写为客户端原始查询的事务 ID。
///
/// 代理路径用 [`build_dns_query`] 重建查询，其事务 ID 为随机值，与客户端原查询
/// 不同。直接回传会导致客户端因 txid 不匹配而丢弃该响应（表现为客户端可见超时）。
/// 注意：缓存与并发广播仍保留上游原始响应（只改写一次、按客户端分别适配）。
fn match_client_txid(response: &[u8], client_query: &[u8]) -> Vec<u8> {
    if response.len() >= 2 && client_query.len() >= 2 {
        let mut r = response.to_vec();
        r[0] = client_query[0];
        r[1] = client_query[1];
        r
    } else {
        response.to_vec()
    }
}

/// `rcode`：0=NOERROR, 2=SERVFAIL, 3=NXDOMAIN。回显原始查询的 OPCODE 和 QDCOUNT。
fn build_error_response(query_packet: &[u8], rcode: u16) -> Vec<u8> {
    if query_packet.len() < 12 {
        return Vec::new();
    }
    let mut resp = Vec::with_capacity(query_packet.len() + 16);
    // 事务 ID 回显
    resp.extend_from_slice(&query_packet[..2]);
    // flags: 从原始查询提取 OPCODE 并回显，同时设置 QR=1, RD=1, RA=1, RCODE=rcode
    let q_opcode = (query_packet[2] >> 3) & 0x0F;
    let flags: u16 = 0x8000                          // QR=1
        | ((q_opcode as u16) << 11)                  // OPCODE（回显原始查询）
        | 0x0100                                      // RD=1
        | 0x0080                                      // RA=1
        | (rcode & 0x0F); // RCODE
    resp.extend_from_slice(&flags.to_be_bytes());
    // QDCOUNT 回显原始查询
    resp.extend_from_slice(&query_packet[4..6]);
    // ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    // 回显问题段（QNAME + QTYPE + QCLASS）
    if let Some(end) = qname_end(query_packet, 12) {
        let qend = end + 4;
        if qend <= query_packet.len() {
            resp.extend_from_slice(&query_packet[12..qend]);
        }
    }
    resp
}

/// 构造 NXDOMAIN 响应（RCODE=3）。
fn build_nxdomain_response(query_packet: &[u8]) -> Vec<u8> {
    build_error_response(query_packet, 3)
}

/// 构造 SERVFAIL 响应（RCODE=2），用于超时或上游失败。
fn build_servfail_response(query_packet: &[u8]) -> Vec<u8> {
    build_error_response(query_packet, 2)
}

/// 验证上游 DNS 响应的问题段是否回显了查询的问题段（RFC 1035 §4.1.2）。
///
/// 检查：
/// - QDCOUNT 匹配
/// - OPCODE 匹配
/// - 问题段（QNAME + QTYPE + QCLASS）内容一致
///
/// 返回 `true` 表示验证通过，`false` 表示响应不合法（可能是伪造/污染）。
fn validate_response_echo(query: &[u8], resp: &[u8]) -> bool {
    if query.len() < 12 || resp.len() < 12 {
        return false;
    }
    // QDCOUNT 匹配
    let qdcount_query = u16::from_be_bytes([query[4], query[5]]);
    let qdcount_resp = u16::from_be_bytes([resp[4], resp[5]]);
    if qdcount_query != qdcount_resp {
        return false;
    }
    // OPCODE 匹配
    let opcode_query = (query[2] >> 3) & 0x0F;
    let opcode_resp = (resp[2] >> 3) & 0x0F;
    if opcode_query != opcode_resp {
        return false;
    }
    // 问题段（QNAME + QTYPE + QCLASS）完全匹配
    let q_end = match qname_end(query, 12) {
        Some(end) => end,
        None => return false,
    };
    let qsec_end = q_end + 4; // QTYPE(2) + QCLASS(2)
    if qsec_end > query.len() {
        return false;
    }
    // 从响应中提取同样长度的问题段并比较
    let resp_q_end = match qname_end(resp, 12) {
        Some(end) => end,
        None => return false,
    };
    let resp_qsec_end = resp_q_end + 4;
    if resp_qsec_end > resp.len() {
        return false;
    }
    // 长度一致且内容一致
    let qsec_len = qsec_end - 12;
    if resp_qsec_end - 12 != qsec_len {
        return false;
    }
    query[12..qsec_end] == resp[12..resp_qsec_end]
}

/// 从 DNS 响应包提取答案记录中的最小 TTL。
///
/// 遍历所有 Answer 记录求 TTL 最小值；无答案或解析失败返回 0。
fn extract_min_ttl(response: &[u8]) -> u32 {
    if response.len() < 12 {
        return 0;
    }
    let ancount = u16::from_be_bytes([response[6], response[7]]);
    // 跳过问题段
    let mut pos = match qname_end(response, 12) {
        Some(end) => end + 4,
        None => return 0,
    };
    let mut min_ttl = u32::MAX;
    for _ in 0..ancount {
        // NAME
        let Some(next) = skip_rr_name(response, pos) else {
            break;
        };
        pos = next;
        // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
        if pos + 10 > response.len() {
            break;
        }
        let ttl = u32::from_be_bytes([
            response[pos + 4],
            response[pos + 5],
            response[pos + 6],
            response[pos + 7],
        ]);
        let rdlen = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        if ttl < min_ttl {
            min_ttl = ttl;
        }
        pos += 10 + rdlen;
    }
    if min_ttl == u32::MAX {
        0
    } else {
        min_ttl
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    /// 构造一个 DNS A 查询包（www.example.com, qtype=1, qclass=IN）。
    fn sample_query() -> Vec<u8> {
        let mut p = Vec::new();
        // header
        p.extend_from_slice(&0x1234u16.to_be_bytes());
        p.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
        p.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        p.extend_from_slice(&0u16.to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes());
        // QNAME: www.example.com
        p.push(3);
        p.extend_from_slice(b"www");
        p.push(7);
        p.extend_from_slice(b"example");
        p.push(3);
        p.extend_from_slice(b"com");
        p.push(0);
        // QTYPE=1, QCLASS=IN
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        p
    }

    #[test]
    fn test_extract_query_info() {
        let (domain, qtype, qclass) = extract_query_info(&sample_query()).unwrap();
        assert_eq!(domain, "www.example.com");
        assert_eq!(qtype, 1);
        assert_eq!(qclass, 1); // IN
    }

    #[test]
    fn test_extract_query_info_invalid() {
        assert!(extract_query_info(&[0u8; 4]).is_none());
    }

    #[test]
    fn test_build_dns_query() {
        let q = build_dns_query("example.com", 28).unwrap();
        let (domain, qtype, qclass) = extract_query_info(&q).unwrap();
        assert_eq!(domain, "example.com");
        assert_eq!(qtype, 28);
        assert_eq!(qclass, 1); // IN
                               // 验证 EDNS0 OPT 伪记录存在
                               // 最小长度 = header(12) + QNAME(13) + QTYPE(2) + QCLASS(2) + OPT(11) = 40
        assert!(
            q.len() >= 40,
            "query too short for OPT record, len={}",
            q.len()
        );
        // ARCOUNT = 1
        assert_eq!(u16::from_be_bytes([q[10], q[11]]), 1);
        // OPT record: NAME=0, TYPE=41, CLASS=4096
        let opt_start = q.len() - 11;
        assert_eq!(q[opt_start], 0, "OPT NAME must be root label");
        assert_eq!(
            u16::from_be_bytes([q[opt_start + 1], q[opt_start + 2]]),
            41,
            "OPT TYPE must be 41"
        );
        assert_eq!(
            u16::from_be_bytes([q[opt_start + 3], q[opt_start + 4]]),
            4096,
            "OPT CLASS must be 4096"
        );
        // 事务 ID 随机，两次构造不应相同（极小概率碰撞，可接受）
        let q2 = build_dns_query("example.com", 28).unwrap();
        assert!(q != q2);
        // 非法 label：>63 字节或空标签 → 拒绝而非静默丢弃
        assert!(build_dns_query(&"a".repeat(64), 1).is_err());
        assert!(build_dns_query("a..b", 1).is_err());
        // 总长度超 255 → 拒绝
        let long = (0..8)
            .map(|i| format!("{i:0>63}"))
            .collect::<Vec<_>>()
            .join(".");
        assert!(build_dns_query(&long, 1).is_err());
    }

    #[test]
    fn test_build_nxdomain_response() {
        let query = sample_query();
        let resp = build_nxdomain_response(&query);
        // 回显事务 ID
        assert_eq!(&resp[..2], &query[..2]);
        // RCODE = 3
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(flags & 0x0F, 3);
        // OPCODE 回显原始查询（标准查询 OPCODE=0，flags 高字节 0x81 中 bits 6-4 应为 0）
        assert_eq!((resp[2] >> 3) & 0x0F, 0);
        // QDCOUNT 回显原始查询（原始 QDCOUNT=1）
        assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), 1);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);
    }

    #[test]
    fn test_build_servfail_response() {
        let query = sample_query();
        let resp = build_servfail_response(&query);
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(flags & 0x0F, 2);
    }

    /// 构造带两条 A 记录的 DNS 响应（TTL 分别为 60 和 30）。
    fn sample_response() -> Vec<u8> {
        let mut p = Vec::new();
        // header：回显 0x1234，flags=0x8180，QD=1，AN=2
        p.extend_from_slice(&0x1234u16.to_be_bytes());
        p.extend_from_slice(&0x8180u16.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&2u16.to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes());
        // question：www.example.com A IN
        p.push(3);
        p.extend_from_slice(b"www");
        p.push(7);
        p.extend_from_slice(b"example");
        p.push(3);
        p.extend_from_slice(b"com");
        p.push(0);
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        // answer 1：NAME=0xC00C（指向 offset 12），A，IN，TTL=60，RDLEN=4，8.8.8.8
        p.extend_from_slice(&[0xC0, 0x0C]);
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&60u32.to_be_bytes());
        p.extend_from_slice(&4u16.to_be_bytes());
        p.extend_from_slice(&[8, 8, 8, 8]);
        // answer 2：NAME=0xC00C，A，IN，TTL=30，RDLEN=4，1.1.1.1
        p.extend_from_slice(&[0xC0, 0x0C]);
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&30u32.to_be_bytes());
        p.extend_from_slice(&4u16.to_be_bytes());
        p.extend_from_slice(&[1, 1, 1, 1]);
        p
    }

    #[test]
    fn test_extract_min_ttl() {
        assert_eq!(extract_min_ttl(&sample_response()), 30);
    }

    #[test]
    fn test_dns_cache() {
        let mut cache = DnsCache::new(4);
        let resp = sample_response();
        cache.put("www.example.com", 1, 1, resp.clone(), 60);
        assert_eq!(cache.len(), 1);
        // 命中（大小写不敏感）
        assert_eq!(cache.get("WWW.EXAMPLE.COM", 1, 1).unwrap(), resp);
        // 未命中不同 qtype
        assert!(cache.get("www.example.com", 28, 1).is_none());
        // 未命中不同 qclass
        assert!(cache.get("www.example.com", 1, 3).is_none()); // QCLASS=CH
                                                               // 统计
        let stats = *cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 2);
        // TTL 过期
        let mut cache2 = DnsCache::new(4);
        cache2.put("a.example", 1, 1, vec![1], 0);
        assert!(cache2.get("a.example", 1, 1).is_none());
        assert_eq!(cache2.len(), 0);
    }

    #[test]
    fn test_inflight_queries() {
        let inflight = InflightQueries::new();
        // 首次发起 → None（需要自己查询）
        let first = inflight.try_start("g", "example.com", 1);
        assert!(first.is_none());
        // 并发等待 → Some(receiver)
        let mut second = inflight.try_start("g", "example.com", 1).unwrap();
        // 完成并广播
        inflight.complete("g", "example.com", 1, vec![1, 2, 3]);
        // 完成后 key 已移除，再次发起应返回 None
        let again = inflight.try_start("g", "example.com", 1);
        assert!(again.is_none());
        // 等待者收到结果
        let recv = futures::executor::block_on(async { second.recv().await });
        assert_eq!(recv.unwrap(), vec![1, 2, 3]);
    }
}
