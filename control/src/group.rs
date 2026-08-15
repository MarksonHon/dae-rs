//! Outbound group dialer.
//!
//! A [`GroupDialer`] wraps every concrete node that a config outbound group
//! selects (via `List`/`Regex` selectors) behind the unified
//! [`OutboundDialer`] interface. It implements the group's node-selection
//! policy (fixed / random / min-latency) **and** alive-node fallback:
//!
//! * On `dial()` / `udp_dial()` it walks the candidates in policy order,
//!   returning the first connection that succeeds.
//! * A failed attempt marks the node dead for a cooldown window
//!   ([`NODE_DEAD_COOLDOWN`]); dead nodes are skipped during selection so the
//!   next best candidate is tried instead. After the cooldown expires the node
//!   is retried automatically (lazy recovery — no separate probe loop needed).
//! * A successful dial revives the node and records the dial latency, which
//!   feeds the `Min` / `MinAvg10` / `MinMovingAvg` policies.
//!
//! This lets callers such as the DNS forwarder and the rule-set scheduler use
//! an `Arc<dyn OutboundDialer>` per group and transparently get node
//! selection + failure fallback.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;
use async_trait::async_trait;
use protocols::{OutboundDialer, ProxyConn, UdpSession};

use crate::config::PolicyType;

/// How long a node stays marked dead after a failed dial before it is retried.
const NODE_DEAD_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(60);

/// How long a group stays in "fast-fail" mode after every candidate fails.
///
/// Without this, when all nodes are down the caller retries *every* node on
/// every query (each with its own dial timeout), so a single query can stall
/// for seconds. During the cooldown the group fails fast and the caller can
/// react immediately (e.g. DNS falls back to direct).
const GROUP_ALL_DEAD_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(10);

/// A single candidate node inside a group.
pub struct GroupNode {
    name: String,
    dialer: Arc<dyn OutboundDialer>,
    alive: AtomicBool,
    /// Monotonic instant until which the node is considered dead; `None` = alive.
    dead_until: Mutex<Option<Instant>>,
    /// Last successful dial latency in milliseconds (0 = unknown).
    last_latency_ms: AtomicU64,
}

impl GroupNode {
    /// Wrap a concrete node dialer as a group candidate.
    pub fn new(name: String, dialer: Arc<dyn OutboundDialer>) -> Self {
        Self {
            name,
            dialer,
            alive: AtomicBool::new(true),
            dead_until: Mutex::new(None),
            last_latency_ms: AtomicU64::new(0),
        }
    }

    /// Node name (logging / selection anchor).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the node is currently considered alive (cooldown expired or
    /// never failed).
    pub fn is_alive(&self) -> bool {
        if !self.alive.load(Ordering::Relaxed) {
            let now = Instant::now();
            if let Ok(guard) = self.dead_until.lock() {
                if let Some(deadline) = *guard {
                    return now >= deadline;
                }
            }
        }
        true
    }

    /// Last recorded dial latency in milliseconds (0 = unknown).
    pub fn last_latency_ms(&self) -> u64 {
        self.last_latency_ms.load(Ordering::Relaxed)
    }

    /// Mark the node alive and record a successful dial latency.
    fn mark_alive(&self, latency_ms: u64) {
        self.alive.store(true, Ordering::Relaxed);
        self.last_latency_ms.store(latency_ms, Ordering::Relaxed);
        if let Ok(mut guard) = self.dead_until.lock() {
            *guard = None;
        }
    }

    /// Mark the node dead for [`NODE_DEAD_COOLDOWN`].
    fn mark_dead(&self) {
        self.alive.store(false, Ordering::Relaxed);
        if let Ok(mut guard) = self.dead_until.lock() {
            *guard = Some(Instant::now() + NODE_DEAD_COOLDOWN);
        }
    }
}

/// Group-level dialer implementing policy-based node selection + fallback.
pub struct GroupDialer {
    /// Group name (logging).
    name: String,
    /// Candidate nodes in selector order (already anchored for `select` groups).
    nodes: Vec<GroupNode>,
    /// Node-selection policy (only meaningful for `auto` groups).
    policy: PolicyType,
    /// Monotonic instant until which the whole group is in fast-fail mode
    /// (set after a full pass fails, cleared on any successful dial).
    all_dead_until: Mutex<Option<Instant>>,
}

impl GroupDialer {
    /// Build a group dialer.
    ///
    /// * `name` — group name.
    /// * `nodes` — candidate nodes in selector order.
    /// * `policy` — selection policy. `auto` groups use it directly; `select`
    ///   groups should already have their selected node anchored first (the
    ///   caller reorders the vector) and typically pass `PolicyType::Fixed`.
    pub fn new(name: String, nodes: Vec<GroupNode>, policy: PolicyType) -> Self {
        Self {
            name,
            nodes,
            policy,
            all_dead_until: Mutex::new(None),
        }
    }

    /// Number of candidate nodes (for logging).
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// The group's selection policy.
    pub fn policy(&self) -> &PolicyType {
        &self.policy
    }

    /// Name of the node the group currently resolves to (policy-best alive
    /// node). `None` if the group has no nodes.
    pub fn current_node_name(&self) -> Option<&str> {
        self.current_node().map(|n| n.name())
    }

    /// Whether the group is currently in fast-fail mode (a recent full pass
    /// failed and the cooldown has not yet expired).
    fn in_group_cooldown(&self) -> bool {
        if let Ok(guard) = self.all_dead_until.lock() {
            if let Some(deadline) = *guard {
                if Instant::now() < deadline {
                    return true;
                }
            }
        }
        false
    }

    /// Enter group fast-fail mode for [`GROUP_ALL_DEAD_COOLDOWN`].
    fn enter_group_cooldown(&self) {
        if let Ok(mut guard) = self.all_dead_until.lock() {
            *guard = Some(Instant::now() + GROUP_ALL_DEAD_COOLDOWN);
        }
    }

    /// Clear group fast-fail mode (called on any successful dial).
    fn clear_group_cooldown(&self) {
        if let Ok(mut guard) = self.all_dead_until.lock() {
            *guard = None;
        }
    }

    /// Candidate nodes in policy order.
    ///
    /// Only alive nodes are candidates; if every node is dead, all nodes are
    /// returned (best-effort retry). `Fixed` keeps selector order, `Random`
    /// shuffles, and the latency policies sort by the last recorded dial
    /// latency ascending (unknown latency sorts last, falling back to selector
    /// order via stable sort).
    fn ordered_candidates(&self) -> Vec<&GroupNode> {
        let pool: Vec<&GroupNode> = self
            .nodes
            .iter()
            .filter(|n| n.is_alive())
            .collect();
        let pool = if pool.is_empty() {
            self.nodes.iter().collect()
        } else {
            pool
        };

        match self.policy {
            PolicyType::Fixed => pool,
            PolicyType::Random => {
                let mut v = pool;
                fastrand::shuffle(&mut v);
                v
            }
            PolicyType::Min | PolicyType::MinAvg10 | PolicyType::MinMovingAvg => {
                let mut v = pool;
                v.sort_by(|a, b| {
                    let la = a.last_latency_ms();
                    let lb = b.last_latency_ms();
                    // Unknown latency (0) sorts last so known-good nodes win.
                    let ka = if la == 0 { u64::MAX } else { la };
                    let kb = if lb == 0 { u64::MAX } else { lb };
                    ka.cmp(&kb)
                });
                v
            }
        }
    }

    /// The node the group currently resolves to (policy-best alive node).
    pub fn current_node(&self) -> Option<&GroupNode> {
        self.ordered_candidates().into_iter().next()
    }

    /// Dial through the candidates, falling back to the next alive node on
    /// failure.
    async fn try_dial(&self, target: &str) -> Result<ProxyConn> {
        // 全组冷却期内快速失败，避免每个查询都把（已死的）节点按策略全试一遍。
        if self.in_group_cooldown() {
            return Err(anyhow::anyhow!(
                "group '{}' all nodes dead (cooling down)",
                self.name
            ));
        }

        let candidates = self.ordered_candidates();
        let mut last_err: Option<anyhow::Error> = None;

        for node in candidates {
            let started = Instant::now();
            match node.dialer.dial(target).await {
                Ok(conn) => {
                    node.mark_alive(started.elapsed().as_millis() as u64);
                    self.clear_group_cooldown();
                    return Ok(conn);
                }
                Err(e) => {
                    node.mark_dead();
                    tracing::warn!(
                        group = %self.name,
                        node = %node.name(),
                        "Node dial failed, marked dead and trying next candidate: {}",
                        e
                    );
                    last_err = Some(e);
                }
            }
        }

        // 本轮候选全部失败 → 进入组冷却。
        self.enter_group_cooldown();
        Err(last_err.unwrap_or_else(|| {
            anyhow::anyhow!("group '{}' has no candidate nodes", self.name)
        }))
    }

    /// Open a UDP relay session through the best candidate, falling back on
    /// failure.
    async fn try_udp_dial(&self) -> Result<Box<dyn UdpSession>> {
        if self.in_group_cooldown() {
            return Err(anyhow::anyhow!(
                "group '{}' all nodes dead (cooling down)",
                self.name
            ));
        }

        let candidates = self.ordered_candidates();
        let mut last_err: Option<anyhow::Error> = None;

        for node in candidates {
            let started = Instant::now();
            match node.dialer.udp_dial().await {
                Ok(session) => {
                    node.mark_alive(started.elapsed().as_millis() as u64);
                    self.clear_group_cooldown();
                    return Ok(session);
                }
                Err(e) => {
                    node.mark_dead();
                    tracing::warn!(
                        group = %self.name,
                        node = %node.name(),
                        "Node UDP dial failed, marked dead and trying next candidate: {}",
                        e
                    );
                    last_err = Some(e);
                }
            }
        }

        self.enter_group_cooldown();
        Err(last_err.unwrap_or_else(|| {
            anyhow::anyhow!("group '{}' has no candidate nodes", self.name)
        }))
    }
}

#[async_trait]
impl OutboundDialer for GroupDialer {
    async fn dial(&self, target: &str) -> Result<ProxyConn> {
        self.try_dial(target).await
    }

    async fn udp_dial(&self) -> Result<Box<dyn UdpSession>> {
        self.try_udp_dial().await
    }

    fn protocol_name(&self) -> &'static str {
        "group"
    }

    fn proxy_addr(&self) -> SocketAddr {
        self.current_node()
            .map(|n| n.dialer.proxy_addr())
            .unwrap_or_else(|| "0.0.0.0:0".parse().expect("static addr"))
    }

    /// A group only counts as a SOCKS5 endpoint when its currently selected
    /// node is a real SOCKS5 dialer (see [`OutboundDialer::is_socks5`]).
    fn is_socks5(&self) -> bool {
        self.current_node()
            .map(|n| n.dialer.is_socks5())
            .unwrap_or(false)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PolicyType;
    use protocols::{ProxyConn, UdpSession};
    use std::sync::atomic::AtomicUsize;

    /// Fake dialer with a configurable number of dial / udp_dial failures.
    ///
    /// `dial` returns a fake [`ProxyConn`] once the failure budget is spent;
    /// `udp_dial` returns a fake [`UdpSession`] likewise.
    #[derive(Clone)]
    struct FakeNode {
        addr: SocketAddr,
        fail_remaining: Arc<AtomicUsize>,
    }

    impl FakeNode {
        fn new(port: u16, fail: usize) -> Self {
            Self {
                addr: format!("127.0.0.1:{}", port).parse().unwrap(),
                fail_remaining: Arc::new(AtomicUsize::new(fail)),
            }
        }
    }

    /// Fake UDP session that never yields datagrams (only used as a success
    /// marker for `udp_dial`).
    struct FakeUdp;

    #[async_trait::async_trait]
    impl UdpSession for FakeUdp {
        async fn send(&self, _dest: &SocketAddr, _payload: &[u8]) -> Result<()> {
            Ok(())
        }
        async fn recv(&self) -> Result<(SocketAddr, bytes::Bytes)> {
            std::future::pending::<()>().await;
            unreachable!()
        }
    }

    #[async_trait::async_trait]
    impl OutboundDialer for FakeNode {
        async fn dial(&self, _target: &str) -> Result<ProxyConn> {
            if self.fail_remaining.load(Ordering::Relaxed) > 0 {
                self.fail_remaining.fetch_sub(1, Ordering::Relaxed);
                anyhow::bail!("simulated dial failure");
            }
            let (tx, _rx) = tokio::io::duplex(1024);
            Ok(ProxyConn::new_boxed(Box::new(tx)))
        }
        async fn udp_dial(&self) -> Result<Box<dyn UdpSession>> {
            if self.fail_remaining.load(Ordering::Relaxed) > 0 {
                self.fail_remaining.fetch_sub(1, Ordering::Relaxed);
                anyhow::bail!("simulated udp dial failure");
            }
            Ok(Box::new(FakeUdp))
        }
        fn protocol_name(&self) -> &'static str {
            "fake"
        }
        fn proxy_addr(&self) -> SocketAddr {
            self.addr
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[test]
    fn test_current_node_fixed_selector_order() {
        let nodes = vec![
            GroupNode::new("b".into(), Arc::new(FakeNode::new(1, 0))),
            GroupNode::new("a".into(), Arc::new(FakeNode::new(2, 0))),
        ];
        let g = GroupDialer::new("g".into(), nodes, PolicyType::Fixed);
        assert_eq!(g.current_node().map(|n| n.name()), Some("b"));
    }

    #[test]
    fn test_current_node_skips_dead_nodes() {
        let b = GroupNode::new("b".into(), Arc::new(FakeNode::new(1, 0)));
        let a = GroupNode::new("a".into(), Arc::new(FakeNode::new(2, 0)));
        b.mark_dead();
        let g = GroupDialer::new("g".into(), vec![b, a], PolicyType::Fixed);
        assert_eq!(g.current_node().map(|n| n.name()), Some("a"));
    }

    #[test]
    fn test_current_node_all_dead_falls_back_to_all() {
        let b = GroupNode::new("b".into(), Arc::new(FakeNode::new(1, 0)));
        let a = GroupNode::new("a".into(), Arc::new(FakeNode::new(2, 0)));
        b.mark_dead();
        a.mark_dead();
        let g = GroupDialer::new("g".into(), vec![b, a], PolicyType::Fixed);
        // All dead → best effort returns the policy-best (first) anyway.
        assert_eq!(g.current_node().map(|n| n.name()), Some("b"));
    }

    #[test]
    fn test_min_policy_prefers_low_latency() {
        let slow = GroupNode::new("slow".into(), Arc::new(FakeNode::new(1, 0)));
        slow.last_latency_ms.store(500, Ordering::Relaxed);
        let fast = GroupNode::new("fast".into(), Arc::new(FakeNode::new(2, 0)));
        fast.last_latency_ms.store(50, Ordering::Relaxed);
        let unknown = GroupNode::new("unknown".into(), Arc::new(FakeNode::new(3, 0)));
        let g = GroupDialer::new(
            "g".into(),
            vec![slow, fast, unknown],
            PolicyType::Min,
        );
        assert_eq!(g.current_node().map(|n| n.name()), Some("fast"));
    }

    #[test]
    fn test_mark_dead_then_cooldown_recovery() {
        let node = GroupNode::new("n".into(), Arc::new(FakeNode::new(1, 0)));
        assert!(node.is_alive());
        node.mark_dead();
        // Immediately after marking dead the node is not alive...
        assert!(!node.is_alive());
        // ...and recovers once the cooldown deadline has passed. Manually clear
        // the deadline to simulate the cooldown expiring.
        node.dead_until.lock().unwrap().take();
        assert!(node.is_alive());
    }

    #[tokio::test]
    async fn test_dial_falls_back_to_next_alive_node() {
        let failing = Arc::new(FakeNode::new(1, 1)); // fails once, then succeeds
        let good = Arc::new(FakeNode::new(2, 0));
        let g = GroupDialer::new(
            "g".into(),
            vec![
                GroupNode::new("failing".into(), failing),
                GroupNode::new("good".into(), good),
            ],
            PolicyType::Fixed,
        );
        // First call: candidate 1 fails → falls back to candidate 2.
        g.dial("example.com:443").await.unwrap();
        assert!(!g.nodes[0].is_alive()); // failing node marked dead
        assert!(g.nodes[1].is_alive());
        // Second call: failing node is dead → goes straight to candidate 2.
        g.dial("example.com:443").await.unwrap();
        assert!(g.nodes[1].is_alive());
    }

    #[tokio::test]
    async fn test_dial_all_nodes_fail_returns_error() {
        let a = Arc::new(FakeNode::new(1, 10));
        let b = Arc::new(FakeNode::new(2, 10));
        let g = GroupDialer::new(
            "g".into(),
            vec![
                GroupNode::new("a".into(), a),
                GroupNode::new("b".into(), b),
            ],
            PolicyType::Fixed,
        );
        let res = g.dial("example.com:443").await;
        let err = match res {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected dial failure"),
        };
        assert!(err.contains("dial failure"));
        assert!(!g.nodes[0].is_alive());
        assert!(!g.nodes[1].is_alive());
    }

    #[tokio::test]
    async fn test_udp_dial_falls_back() {
        let failing = Arc::new(FakeNode::new(1, 1));
        let good = Arc::new(FakeNode::new(2, 0));
        let g = GroupDialer::new(
            "g".into(),
            vec![
                GroupNode::new("failing".into(), failing),
                GroupNode::new("good".into(), good),
            ],
            PolicyType::Fixed,
        );
        let _sess = g.udp_dial().await.unwrap();
        assert!(!g.nodes[0].is_alive());
        assert!(g.nodes[1].is_alive());
    }

    #[test]
    fn test_proxy_addr_tracks_current_node() {
        let g = GroupDialer::new(
            "g".into(),
            vec![
                GroupNode::new("a".into(), Arc::new(FakeNode::new(1080, 0))),
                GroupNode::new("b".into(), Arc::new(FakeNode::new(2080, 0))),
            ],
            PolicyType::Fixed,
        );
        assert_eq!(g.proxy_addr().port(), 1080);
        g.nodes[0].mark_dead();
        assert_eq!(g.proxy_addr().port(), 2080);
    }

    #[test]
    fn test_current_node_name_tracks_selection() {
        let g = GroupDialer::new(
            "g".into(),
            vec![
                GroupNode::new("a".into(), Arc::new(FakeNode::new(1080, 0))),
                GroupNode::new("b".into(), Arc::new(FakeNode::new(2080, 0))),
            ],
            PolicyType::Fixed,
        );
        assert_eq!(g.current_node_name(), Some("a"));
        g.nodes[0].mark_dead();
        assert_eq!(g.current_node_name(), Some("b"));
    }

    #[test]
    fn test_is_socks5_false_for_fake_protocol() {
        // FakeNode does not advertise SOCKS5 → the group must not be treated
        // as a SOCKS5 endpoint (rule-set downloader would mis-handshake).
        let g = GroupDialer::new(
            "g".into(),
            vec![GroupNode::new("a".into(), Arc::new(FakeNode::new(1080, 0)))],
            PolicyType::Fixed,
        );
        assert!(!g.is_socks5());
    }

    #[tokio::test]
    async fn test_group_cooldown_fast_fails_after_all_dead() {
        // Both nodes fail every dial. First call does a full pass and enters
        // group cooldown; subsequent calls must fail fast without dialing.
        let a = Arc::new(FakeNode::new(1, 100));
        let b = Arc::new(FakeNode::new(2, 100));
        let g = GroupDialer::new(
            "g".into(),
            vec![
                GroupNode::new("a".into(), a),
                GroupNode::new("b".into(), b),
            ],
            PolicyType::Fixed,
        );

        let err = match g.dial("example.com:443").await {
            Err(e) => e,
            Ok(_) => panic!("expected dial failure"),
        };
        assert!(err.to_string().contains("dial failure"));
        // Full pass failed → group enters cooldown → next dial fails fast.
        assert!(g.in_group_cooldown());
        let err2 = match g.dial("example.com:443").await {
            Err(e) => e,
            Ok(_) => panic!("expected fast-fail during cooldown"),
        };
        assert!(
            err2.to_string().contains("cooling down"),
            "expected fast-fail during cooldown, got: {}",
            err2
        );

        // Cooldown expiry clears fast-fail mode (retry allowed).
        g.all_dead_until.lock().unwrap().take();
        assert!(!g.in_group_cooldown());
    }

    #[tokio::test]
    async fn test_successful_dial_clears_group_cooldown() {
        // Node a fails every dial, node b always succeeds. Once the group
        // cooldown has naturally expired, a successful dial clears the stored
        // deadline (so later checks don't recompute a stale deadline).
        let a = Arc::new(FakeNode::new(1, 100));
        let b = Arc::new(FakeNode::new(2, 0));
        let g = GroupDialer::new(
            "g".into(),
            vec![
                GroupNode::new("a".into(), a),
                GroupNode::new("b".into(), b),
            ],
            PolicyType::Fixed,
        );
        // 模拟冷却已自然到期（deadline 落后于当前时间）但尚未清理。
        g.all_dead_until
            .lock()
            .unwrap()
            .replace(Instant::now() - std::time::Duration::from_secs(1));
        assert!(!g.in_group_cooldown());
        // 到期后拨号成功 → 清理组冷却 deadline。
        g.dial("example.com:443").await.unwrap();
        assert!(!g.in_group_cooldown());
        assert!(g.all_dead_until.lock().unwrap().is_none());
    }
}
