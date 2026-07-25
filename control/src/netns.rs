//! 匿名网络命名空间 + veth/netkit pair 管理
//!
//! 本模块负责创建和管理匿名网络命名空间及 veth 对，用于将代理流量
//! 从宿主命名空间导入到代理命名空间进行处理。
//!
//! ## 架构
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │                   宿主网络命名空间                         │
//! │                                                          │
//! │  ┌─────────────┐  ┌──────────────┐                       │
//! │  │   eth0      │  │   dae0       │                       │
//! │  │  (外网)     │  │ 169.254.0.1  │                       │
//! │  └─────────────┘  └──────┬───────┘                       │
//! │                           │                               │
//! ├───────────────────────────┼───────────────────────────────┤
//! │       veth/netkit pair    │                               │
//! ├───────────────────────────┼───────────────────────────────┤
//! │                           │                               │
//! │  ┌────────────────────┐ ┌─┴──────────────┐               │
//! │  │   lo               │ │ dae0peer       │               │
//! │  │   route table 2023 │ │169.254.0.11/16 │               │
//! │  └────────────────────┘ └────────────────┘               │
//! │                   代理网络命名空间                          │
//! └──────────────────────────────────────────────────────────┘
//! ```
//!
//! ## 设计决策
//!
//! - `dae0` 在宿主 NS — 作为 veth/netkit 的主端，TC(tproxy_dae0_ingress) 在这里
//! - `dae0peer` 在代理 NS — 作为对端，TC(tproxy_dae0peer_ingress) 在这里
//! - IPv4: `169.254.0.1/16`（宿主）和 `169.254.0.11/16`（代理）
//! - IPv6: 内核自动分配链路本地地址（`fe80::/10`）
//! - 策略路由表 2023：fwmark `0x8000000` → table 2023 → local default dev lo
//! - netkit 优先（内核 ≥ 6.7），失败回退 veth
//!
//! ## MVP 策略
//!
//! 本模块 MVP 阶段使用 `std::process::Command` 调用 iproute2 命令，
//! 而非直接使用 netlink syscall。原因：
//! - iproute2 命令更稳定、更易调试
//! - nix crate 对 netlink 的封装可能不够完整
//! - 后续可逐步替换为原生 netlink 实现

use crate::Config;
use anyhow::{Context, Result};
use std::fs::File;
use std::os::linux::fs::MetadataExt;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::process::{Child, Command};
use std::os::unix::process::CommandExt;
use nix::sched::{self, CloneFlags};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use tracing::{info, warn, error};

// ============================================================================
// NetnsGuard — RAII 命名空间守卫
// ============================================================================

/// RAII guard：进入代理网络命名空间，在 Drop 时自动切回宿主命名空间。
///
/// 解决了 `let _ = self.join_host_ns()` 模式中，如果 `join_host_ns()` 失败
/// 导致线程停留在错误命名空间的命名空间泄露问题。
///
/// # 使用示例
///
/// ```ignore
/// let _guard = netns_mgr.enter_proxy_ns()?;
/// // 在代理 NS 中操作...
/// // _guard drop 时自动切回宿主 NS
/// ```
struct NetnsGuard<'a> {
    mgr: &'a NetnsManager,
}

impl<'a> NetnsGuard<'a> {
    fn new(mgr: &'a NetnsManager) -> Result<Self> {
        // 进入代理 NS
        mgr.join_proxy_ns()?;
        Ok(Self { mgr })
    }
}

impl<'a> Drop for NetnsGuard<'a> {
    /// 自动切回宿主 NS
    ///
    /// 即使 `join_host_ns()` 失败，也记录警告而不是静默忽略，
    /// 这样至少日志中会留下线索。
    fn drop(&mut self) {
        if let Err(e) = self.mgr.join_host_ns() {
            // 无法切回宿主 NS 是严重问题，因为后续所有操作都会在错误命名空间中执行
            error!(
                "CRITICAL: Failed to return to host network namespace: {}. \
                 The current thread may be in the wrong namespace!",
                e
            );
        }
    }
}

// ============================================================================
// 错误类型
// ============================================================================

/// 网络命名空间管理错误
#[derive(Debug, thiserror::Error)]
pub enum NetnsError {
    /// 命名空间已创建，操作冲突
    #[error("Network namespace already created")]
    AlreadyCreated,
    /// 命名空间未创建，操作无效
    #[error("Network namespace not created")]
    NotCreated,
    /// 子进程相关错误
    #[error("Child process error: {0}")]
    ChildProcess(String),
    /// iproute2 命令执行失败
    #[error("ip command failed: {cmd}\nstderr: {stderr}")]
    IpCommand {
        /// 执行的命令
        cmd: String,
        /// 标准错误输出
        stderr: String,
    },
}

// ============================================================================
// 常量
// ============================================================================

/// 当前进程的 netns 路径
const PROC_SELF_NETNS: &str = "/proc/self/ns/net";

// ============================================================================
// 辅助函数
// ============================================================================

/// 从 /sys/class/net/<ifname>/address 读取 MAC 地址
fn read_mac_from_sysfs(ifname: &str) -> Result<[u8; 6]> {
    let path = format!("/sys/class/net/{}/address", ifname);
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read MAC from {}", path))?;
    let content = content.trim();
    let parts: Vec<&str> = content.split(':').collect();
    if parts.len() != 6 {
        return Err(anyhow::anyhow!("Invalid MAC address format: {}", content));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .map_err(|e| anyhow::anyhow!("Invalid MAC byte '{}': {}", part, e))?;
    }
    Ok(mac)
}

/// 为 netkit 设备生成本地管理的合成 MAC 地址
///
/// Netkit 设备没有真实 MAC 地址（内核返回 00:00:00:00:00:00），
/// 但 eBPF 程序需要 DMAC 来重定向数据包。此函数生成一个确定性
/// 的本地管理地址（LAA），前缀为 `02:`。
///
/// 生成算法：结合接口名和 PID 计算 hash，填充到 MAC 的后 3 字节。
///
/// # 参数
///
/// * `ifname` — 接口名，用于生成确定性 hash
///
/// # 返回
///
/// 6 字节 MAC 地址，第一个字节为 `0x02`（本地管理地址标志）
fn generate_synthetic_mac(ifname: &str) -> [u8; 6] {
    let mut mac = [0x02u8, 0x00, 0x00, 0x00, 0x00, 0x00];
    let hash = {
        let s = format!("{}-{}", ifname, std::process::id());
        let mut h = 0u64;
        for b in s.bytes() {
            h = h.wrapping_mul(31).wrapping_add(b as u64);
        }
        h
    };
    mac[3] = (hash >> 16) as u8;
    mac[4] = (hash >> 8) as u8;
    mac[5] = hash as u8;
    mac
}

// ============================================================================
// NetnsManager
// ============================================================================

/// 网络命名空间管理器
///
/// 管理匿名网络命名空间的生命周期，包括：
/// - 保存宿主 netns fd（持有引用防止 GC 回收）
/// - 使用 `unshare(CLONE_NEWNET)` 创建匿名命名空间
/// - 创建并配置 veth/netkit pair（netkit 优先）
/// - 配置 IPv4 地址
/// - 配置策略路由将代理流量导入代理命名空间
/// - 在代理命名空间中启动子进程
/// - 销毁时完整清理所有资源
///
/// # 示例
///
/// ```no_run
/// use control::netns::NetnsManager;
/// use control::Config;
///
/// let config = Config::default();
/// let mut mgr = NetnsManager::new(&config);
/// mgr.create().expect("Failed to create netns");
/// // ... 使用代理命名空间 ...
/// mgr.destroy().expect("Failed to destroy netns");
/// ```
pub struct NetnsManager {
    /// veth 宿主侧接口名（默认 dae0）— 位于宿主 NS
    host_if: String,
    /// veth 代理侧接口名（默认 dae0peer）— 位于代理 NS
    peer_if: String,
    /// 宿主侧 IPv4 地址（CIDR，默认 169.254.0.1/16）
    host_addr: String,
    /// 代理侧 IPv4 地址（CIDR，默认 169.254.0.11/16）
    peer_addr: String,
    /// MTU（默认 1500）
    mtu: u32,
    /// 策略路由表 ID（默认 2023）
    route_table: u32,
    /// TPROXY_MARK（默认 0x8000000）
    proxy_mark: u32,
    /// TPROXY_MARK 掩码（默认 0x8000000）
    proxy_mask: u32,
    /// 是否使用了 netkit（而非 veth）
    use_netkit: bool,
    /// 宿主侧 netns fd（持有引用防止 GC）
    host_ns_fd: Option<OwnedFd>,
    /// 代理命名空间 fd（在 unshare 后、setns 回宿主前保存）
    proxy_ns_fd: Option<OwnedFd>,
    /// 子进程 PID
    child_pid: Option<u32>,
}

impl NetnsManager {
    /// 从配置对象创建管理器
    ///
    /// 此时不会创建命名空间，仅保存配置参数。
    /// 调用 [`create()`](NetnsManager::create) 后才实际创建。
    pub fn new(config: &Config) -> Self {
        Self {
            host_if: config.veth_host.clone(),
            peer_if: config.veth_peer.clone(),
            host_addr: config.host_addr.clone(),
            peer_addr: config.peer_addr.clone(),
            mtu: config.mtu,
            route_table: config.route_table,
            proxy_mark: config.fwmark_proxy,
            proxy_mask: config.fwmark_mask,
            use_netkit: false,
            host_ns_fd: None,
            proxy_ns_fd: None,
            child_pid: None,
        }
    }

    /// 创建匿名网络命名空间和 veth/netkit pair
    ///
    /// # 拓扑
    ///
    /// 与原始 dae 一致：
    /// - `dae0`（主端）留在**宿主 NS**
    /// - `dae0peer`（对端）留在**代理 NS**
    ///
    /// # 完整流程
    ///
    /// 1. 保存宿主 netns fd
    /// 2. `unshare(CLONE_NEWNET)` → 进入代理 NS
    /// 3. **在代理 NS 中**创建 link pair（netkit 优先，veth 回退）
    /// 4. 保存代理 netns fd
    /// 5. 将 `dae0`（主端）移回宿主 NS：`ip link set dae0 netns 1`
    /// 6. 配置 `dae0peer`（代理 NS）：IPv4 + MTU + up
    /// 7. `setns` 回到宿主 NS
    /// 8. 配置 `dae0`（宿主 NS）：IPv4 + MTU + up
    /// 9. 配置策略路由（IPv4 + IPv6）
    ///
    /// # 错误
    ///
    /// - 如果命名空间已创建，返回 [`NetnsError::AlreadyCreated`]
    /// - 任何 iproute2 命令失败都会返回 [`NetnsError::IpCommand`]
    pub fn create(&mut self) -> Result<()> {
        if self.host_ns_fd.is_some() {
            return Err(NetnsError::AlreadyCreated.into());
        }

        // === 崩溃安全：启动时清理上次可能残留的接口 ===
        // 无论上次运行如何退出（正常、崩溃、SIGKILL），
        // 确保同名接口不存在，使 create() 幂等。
        self.cleanup_stale_interfaces();

        info!(
            host_if = %self.host_if,
            peer_if = %self.peer_if,
            host_addr = %self.host_addr,
            peer_addr = %self.peer_addr,
            mtu = %self.mtu,
            route_table = %self.route_table,
            proxy_mark = %format!("{:#x}", self.proxy_mark),
            "Creating anonymous network namespace and veth/netkit pair"
        );

        // ----------------------------------------------------------------
        // 核心创建逻辑包装在 IIFE 中，以便在任一步骤失败时统一回滚
        // ----------------------------------------------------------------
        let mut host_ns_fd: Option<OwnedFd> = None;
        let mut proxy_ns_fd: Option<OwnedFd> = None;
        let mut link_created = false;
        let mut host_moved = false;

        let result = (|| -> Result<()> {
            // ---- Step 1: 保存宿主 netns fd ----
            {
                let host_ns_file = File::open(PROC_SELF_NETNS)
                    .context("Failed to open /proc/self/ns/net to save host netns fd")?;
                host_ns_fd = Some(OwnedFd::from(host_ns_file));
                info!("Saved host netns fd: {}", host_ns_fd.as_ref().unwrap().as_raw_fd());
            }

            // ---- Step 2: 创建新网络命名空间（进入代理 NS） ----
            sched::unshare(CloneFlags::CLONE_NEWNET)
                .context("Failed to create new network namespace via unshare(CLONE_NEWNET)")?;
            info!("Created new anonymous network namespace");

            // ---- Step 3: 在代理 NS 中创建 link pair（netkit 优先） ----
            // 此时我们在新创建的代理 NS 中，创建的 veth pair 两端都位于代理 NS。
            // 后续通过 `ip link set dae0 netns 1` 将 dae0 移回宿主 NS。
            let use_netkit = self.try_create_netkit().unwrap_or_else(|_| {
                info!("netkit not available, falling back to veth");
                self.create_veth()
                    .expect("Failed to create veth pair as fallback");
                false
            });
            self.use_netkit = use_netkit;
            link_created = true;
            info!(
                "Created link pair in proxy network namespace: {} <-> {}",
                self.host_if, self.peer_if
            );

            // ---- Step 4: 保存代理 netns fd ----
            {
                let proxy_ns_file = File::open(PROC_SELF_NETNS)
                    .context("Failed to open /proc/self/ns/net to save proxy netns fd")?;
                proxy_ns_fd = Some(OwnedFd::from(proxy_ns_file));
                info!("Saved proxy netns fd: {}", proxy_ns_fd.as_ref().unwrap().as_raw_fd());
            }

            // ---- Step 5: 将 dae0（主端）移回宿主 NS ----
            // 此时我们在代理 NS 中，PID 1 始终位于宿主（init）NS。
            // 因此 `ip link set dae0 netns 1` 将 dae0 从代理 NS 移到宿主 NS。
            self.run_ip(&[
                "link", "set", "dev", &self.host_if, "netns", "1",
            ])
            .context(format!(
                "Failed to move {} to host network namespace",
                self.host_if
            ))?;
            host_moved = true;
            info!(
                "Moved {} (host side) to host network namespace",
                self.host_if
            );

            // ---- Step 6: 配置 dae0peer（代理 NS） ----
            // IPv4
            self.run_ip(&["addr", "add", &self.peer_addr, "dev", &self.peer_if])
                .context("Failed to set peer interface IPv4 address")?;
            // MTU + up
            self.run_ip(&["link", "set", "dev", &self.peer_if, "mtu", &self.mtu.to_string()])
                .context("Failed to set peer interface MTU")?;
            self.run_ip(&["link", "set", &self.peer_if, "up"])
                .context("Failed to bring up peer interface")?;
            info!(
                "Configured {} (proxy NS): ipv4={}, mtu={}, up",
                self.peer_if, self.peer_addr, self.mtu
            );

            // ---- Step 6.25: 确保 lo 在代理 NS 中已 up ----
            // 新命名空间的 lo 默认是 down 的，而策略路由需要 lo up
            // 来接收 local default dev lo 路由。
            self.run_ip(&["link", "set", "lo", "up"])
                .context("Failed to bring up lo in proxy network namespace")?;
            info!("Brought lo up in proxy network namespace");

            // ---- Step 6.5: 配置策略路由（IPv4 + IPv6）in 代理 NS ----
            // Policy routing MUST be in the proxy namespace because:
            // tproxy_dae0peer_ingress sets skb->mark = TPROXY_MARK, and the
            // kernel in the PROXY NS uses fwmark-based policy routing to
            // deliver the packet to lo → TProxy listener.
            self.add_policy_routing()?;

            // ---- Step 7: setns 回到宿主 NS ----
            sched::setns(
                host_ns_fd.as_ref().ok_or(NetnsError::NotCreated)?,
                CloneFlags::CLONE_NEWNET,
            )
            .context("Failed to switch back to host network namespace")?;
            info!("Switched back to host network namespace");

            // ---- Step 8: 配置 dae0（宿主 NS） ----
            // IPv4
            self.run_ip(&["addr", "add", &self.host_addr, "dev", &self.host_if])
                .context("Failed to set host interface IPv4 address")?;
            // MTU + up
            self.run_ip(&["link", "set", "dev", &self.host_if, "mtu", &self.mtu.to_string()])
                .context("Failed to set host interface MTU")?;
            self.run_ip(&["link", "set", &self.host_if, "up"])
                .context("Failed to bring up host interface")?;
            info!(
                "Configured {} (host NS): ipv4={}, mtu={}, up",
                self.host_if, self.host_addr, self.mtu
            );

            Ok(())
        })();

        match result {
            Ok(()) => {
                self.host_ns_fd = host_ns_fd.take();
                self.proxy_ns_fd = proxy_ns_fd.take();
                info!("Network namespace and veth/netkit pair created successfully");
                Ok(())
            }
            Err(e) => {
                // 回滚：清理已创建的中间资源
                self.rollback_create(
                    host_ns_fd.as_ref(),
                    link_created,
                    host_moved,
                );
                error!("Failed to create network namespace: {}", e);
                Err(e)
            }
        }
    }

    /// 尝试创建 netkit pair
    ///
    /// 内核 ≥ 6.7 支持 netkit，失败返回错误以触发 veth 回退。
    fn try_create_netkit(&self) -> Result<bool> {
        match self.run_ip(&[
            "link", "add", "dev", &self.host_if, "type", "netkit",
            "peer", "name", &self.peer_if,
        ]) {
            Ok(_) => {
                info!("Created netkit pair: {} <-> {}", self.host_if, self.peer_if);
                Ok(true)
            }
            Err(e) => {
                info!("netkit creation failed (kernel < 6.7?): {}", e);
                Err(anyhow::anyhow!("netkit not supported"))
            }
        }
    }

    /// 创建 veth pair（netkit 回退方案）
    fn create_veth(&self) -> Result<()> {
        self.run_ip(&[
            "link", "add", "dev", &self.host_if, "type", "veth",
            "peer", "name", &self.peer_if,
        ])
        .context("Failed to create veth pair")?;
        info!("Created veth pair: {} <-> {}", self.host_if, self.peer_if);
        Ok(())
    }

    /// 添加策略路由规则（IPv4 + IPv6）
    ///
    /// 幂等操作：先尝试删除可能残留的相同规则，再添加。
    fn add_policy_routing(&self) -> Result<()> {
        let mark_str = format!("{:#x}/{:#x}", self.proxy_mark, self.proxy_mask);
        let table_str = self.route_table.to_string();

        // ---- 代理 NS：标记包路由回宿主 NS ----
        // 删除残留
        let _ = self.run_ip(&["rule", "del", "fwmark", &mark_str, "table", &table_str]);
        let _ = self.run_ip(&["route", "del", "default", "dev", &self.peer_if, "table", &table_str]);

        // 规则：标记包使用自定义路由表
        self.run_ip(&["rule", "add", "fwmark", &mark_str, "table", &table_str])
            .context("Failed to add proxy IPv4 policy routing rule")?;
        // 路由：默认路由通过 dae0peer 发回宿主 NS
        self.run_ip(&["route", "add", "default", "dev", &self.peer_if, "table", &table_str])
            .context("Failed to add proxy IPv4 policy route")?;
        info!(
            "Proxy NS IPv4 policy: fwmark {} table {} -> default dev {} (back to host)",
            mark_str, table_str, self.peer_if
        );

        // IPv6
        let _ = self.run_ip(&["-6", "rule", "del", "fwmark", &mark_str, "table", &table_str]);
        let _ = self.run_ip(&["-6", "route", "del", "default", "dev", &self.peer_if, "table", &table_str]);

        self.run_ip(&["-6", "rule", "add", "fwmark", &mark_str, "table", &table_str])
            .context("Failed to add proxy IPv6 policy routing rule")?;
        self.run_ip(&["-6", "route", "add", "default", "dev", &self.peer_if, "table", &table_str])
            .context("Failed to add proxy IPv6 policy route")?;
        info!(
            "Proxy NS IPv6 policy: fwmark {} table {} -> default dev {} (back to host)",
            mark_str, table_str, self.peer_if
        );

        Ok(())
    }

    /// 在宿主命名空间添加策略路由规则
    ///
    /// 使从代理 NS 返回的标记包被路由到本地 TProxy socket。
    pub fn add_host_policy_routing(&self) -> Result<()> {
        let mark_str = format!("{:#x}/{:#x}", self.proxy_mark, self.proxy_mask);
        let table_str = self.route_table.to_string();

        // ---- 宿主 NS：标记包 → local default dev lo → TProxy socket ----
        // IPv4
        let _ = std::process::Command::new("ip")
            .args(["rule", "del", "fwmark", &mark_str, "table", &table_str])
            .output();
        let _ = std::process::Command::new("ip")
            .args(["route", "del", "local", "default", "dev", "lo", "table", &table_str])
            .output();

        let output = std::process::Command::new("ip")
            .args(["rule", "add", "fwmark", &mark_str, "table", &table_str])
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to add host IPv4 ip rule: {}", e))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("File exists") {
                warn!("Failed to add host IPv4 ip rule: {}", stderr);
            }
        }

        let output = std::process::Command::new("ip")
            .args(["route", "add", "local", "default", "dev", "lo", "table", &table_str])
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to add host IPv4 ip route: {}", e))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("File exists") {
                warn!("Failed to add host IPv4 ip route: {}", stderr);
            }
        }
        info!(
            "Host NS IPv4 policy: fwmark {} table {} -> local default dev lo",
            mark_str, table_str
        );

        // IPv6
        let _ = std::process::Command::new("ip")
            .args(["-6", "rule", "del", "fwmark", &mark_str, "table", &table_str])
            .output();
        let _ = std::process::Command::new("ip")
            .args(["-6", "route", "del", "local", "default", "dev", "lo", "table", &table_str])
            .output();

        let output = std::process::Command::new("ip")
            .args(["-6", "rule", "add", "fwmark", &mark_str, "table", &table_str])
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to add host IPv6 ip rule: {}", e))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("File exists") {
                warn!("Failed to add host IPv6 ip rule: {}", stderr);
            }
        }

        let output = std::process::Command::new("ip")
            .args(["-6", "route", "add", "local", "default", "dev", "lo", "table", &table_str])
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to add host IPv6 ip route: {}", e))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("File exists") {
                warn!("Failed to add host IPv6 ip route: {}", stderr);
            }
        }
        info!(
            "Host NS IPv6 policy: fwmark {} table {} -> local default dev lo",
            mark_str, table_str
        );

        Ok(())
    }

    /// 删除宿主命名空间的策略路由规则
    ///
    /// 在 destroy() 时调用，确保清理宿主 NS 中的 ip rule 和 ip route。
    pub fn remove_host_policy_routing(&self) -> Result<()> {
        let mark_str = format!("{:#x}/{:#x}", self.proxy_mark, self.proxy_mask);
        let table_str = self.route_table.to_string();

        info!("Removing host NS policy routing (fwmark {}, table {})", mark_str, table_str);

        // IPv4
        let _ = std::process::Command::new("ip")
            .args(["route", "del", "local", "default", "dev", "lo", "table", &table_str])
            .output();
        let _ = std::process::Command::new("ip")
            .args(["rule", "del", "fwmark", &mark_str, "table", &table_str])
            .output();

        // IPv6
        let _ = std::process::Command::new("ip")
            .args(["-6", "route", "del", "local", "default", "dev", "lo", "table", &table_str])
            .output();
        let _ = std::process::Command::new("ip")
            .args(["-6", "rule", "del", "fwmark", &mark_str, "table", &table_str])
            .output();

        Ok(())
    }

    // ================================================================
    // 清理残留接口（崩溃安全）
    // ================================================================

    /// 清理可能残留的旧接口
    ///
    /// **崩溃安全核心**：无论上次运行如何退出（正常、崩溃、SIGKILL），
    /// 在创建新接口前先清理可能残留的同名接口。这使得 `create()` 幂等。
    ///
    /// ## 清理策略
    ///
    /// 同时尝试从宿主 NS 和代理 NS 两侧删除：
    /// - `dae0`（宿主侧）：上次崩溃后可能残留在宿主 NS 中
    /// - `dae0peer`（代理侧）：上次崩溃后代理 NS 被销毁时随之消失，
    ///   但安全起见也尝试删除
    ///
    /// 所有错误被忽略（接口不存在是正常情况）。
    fn cleanup_stale_interfaces(&self) {
        // 在宿主 NS 中删除残留接口
        // 删除 host_if（如 dae0）会自动销毁整个 veth pair
        let _ = self.run_ip(&["link", "del", &self.host_if]);
        let _ = self.run_ip(&["link", "del", &self.peer_if]);
        info!(
            "Cleaned up stale interfaces: {} / {}",
            self.host_if, self.peer_if
        );
    }

    /// 回滚 create() 中已创建的中间资源
    ///
    /// 当 [`create()`](NetnsManager::create) 中间步骤失败时，清理所有已创建的资源。
    /// 处理两种场景：
    /// 1. **仍在代理 NS 中**（步骤 2~7 之间失败）：从代理 NS 删除 link pair，然后切回宿主 NS
    /// 2. **已回到宿主 NS**（步骤 8~9 失败）：直接从宿主 NS 删除 link pair
    ///
    /// # 参数
    ///
    /// * `host_ns_fd` — 宿主 NS 的 fd（用于 `setns` 切回宿主 NS）
    /// * `link_created` — link pair 是否已创建
    /// * `host_moved` — `dae0`（host_if）是否已移到宿主 NS
    fn rollback_create(
        &self,
        host_ns_fd: Option<&OwnedFd>,
        link_created: bool,
        host_moved: bool,
    ) {
        if !link_created && !host_moved {
            // 未创建任何资源，无需回滚
            return;
        }

        warn!("Rolling back partially created resources");

        if host_moved {
            // dae0 已在宿主 NS 中，切换到宿主 NS 删除它
            // 这也会自动销毁 veth pair 的对端（dae0peer 在代理 NS 中）
            if let Some(fd) = host_ns_fd {
                let _ = sched::setns(fd, CloneFlags::CLONE_NEWNET);
            }
            let _ = self.run_ip(&["link", "del", &self.host_if]);
            info!("Rollback: deleted {} from host NS", self.host_if);
        } else if link_created {
            // 仍在代理 NS 中，从代理 NS 删除 link pair
            let _ = self.run_ip(&["link", "del", &self.host_if]);
            let _ = self.run_ip(&["link", "del", &self.peer_if]);
            // 切回宿主 NS
            if let Some(fd) = host_ns_fd {
                let _ = sched::setns(fd, CloneFlags::CLONE_NEWNET);
            }
            info!("Rollback: deleted link pair from proxy NS and returned to host NS");
        }

        // 最终保险：始终尝试从宿主 NS 清理可能残留的接口
        let _ = self.run_ip(&["link", "del", &self.host_if]);
        let _ = self.run_ip(&["link", "del", &self.peer_if]);
    }

    // ================================================================
    // 接口信息获取方法
    // ================================================================

    /// 获取 dae0 在宿主 NS 中的 ifindex
    pub fn get_host_ifindex(&self) -> Result<u32> {
        let cstr = std::ffi::CString::new(self.host_if.as_str())
            .map_err(|e| anyhow::anyhow!("Invalid interface name: {}", e))?;
        let ifindex = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
        if ifindex == 0 {
            return Err(anyhow::anyhow!(
                "Failed to get ifindex for {} in host netns",
                self.host_if
            ));
        }
        info!("{} ifindex in host NS: {}", self.host_if, ifindex);
        Ok(ifindex)
    }

    /// 获取 dae0peer 在代理 NS 中的 MAC 地址
    ///
    /// 需要短暂切换到代理 NS 读取 sysfs，然后切换回来。
    /// **保证**即使读取失败，也切换回宿主 NS（防止命名空间泄漏）。
    ///
    /// # 错误安全保证
    ///
    /// 此函数保证在返回时（无论成功或失败），当前线程的网络命名空间
    /// 已恢复到调用前的宿主 NS。这是通过 RAII guard 实现的。
    ///
    /// # 回退策略
    ///
    /// 1. 尝试从 `/sys/class/net/<if>/address` 读取 MAC
    /// 2. 如果 sysfs 失败（setns 后 sysfs 不反映新 netns），回退到
    ///    `ip link show dev <if>` 解析 MAC
    /// 3. 如果 MAC 全零（netkit 设备），生成本地管理的合成 MAC 地址
    pub fn get_peer_mac(&self) -> Result<[u8; 6]> {
        // 使用 RAII guard 确保命名空间切换不会被泄露
        let _guard = self.enter_proxy_ns()?;

        // 尝试 sysfs 读取
        let mac_result = read_mac_from_sysfs(&self.peer_if);

        // 记录是否为 netkit（MAC 全零），后续回退逻辑需要
        // 使用引用匹配避免消费 mac_result
        let is_netkit_zero = match &mac_result {
            Ok(mac) => *mac == [0u8; 6],
            Err(_) => false,
        };

        match mac_result {
            Ok(mac) if mac != [0u8; 6] => {
                // sysfs 成功且 MAC 非零：直接返回
                info!("{} MAC in proxy NS: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    self.peer_if, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                return Ok(mac);
            }
            _ => {
                // sysfs 失败（setns 后 sysfs 不更新）或 MAC 全零（netkit）
                // 回退到 ip link show 解析 MAC
                let output = std::process::Command::new("ip")
                    .args(["link", "show", "dev", &self.peer_if])
                    .output()
                    .with_context(|| format!("Failed to run ip link show for {}", self.peer_if))?;

                if !output.status.success() {
                    return Err(anyhow::anyhow!(
                        "ip link show dev {} failed: {}",
                        self.peer_if,
                        String::from_utf8_lossy(&output.stderr)
                    ));
                }

                let stdout = String::from_utf8_lossy(&output.stdout);

                // 从 "link/ether xx:xx:xx:xx:xx:xx" 解析 MAC
                // 例如: "    link/ether 02:00:00:03:e8:6b brd ff:ff:ff:ff:ff:ff"
                if let Some(line) = stdout.lines().find(|l| l.trim().starts_with("link/ether")) {
                    let parts: Vec<&str> = line.trim().split_whitespace().collect();
                    if parts.len() >= 2 {
                        let mac_str = parts[1];
                        let bytes: Vec<u8> = mac_str
                            .split(':')
                            .filter_map(|h| u8::from_str_radix(h, 16).ok())
                            .collect();
                        if bytes.len() == 6 {
                            let mut mac = [0u8; 6];
                            mac.copy_from_slice(&bytes);

                            if mac == [0u8; 6] {
                                // Netkit 设备：生成合成 MAC
                                let synthetic = generate_synthetic_mac(&self.peer_if);
                                info!("Netkit device, using synthetic MAC: \
                                    {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                    synthetic[0], synthetic[1], synthetic[2],
                                    synthetic[3], synthetic[4], synthetic[5]);
                                return Ok(synthetic);
                            }

                            info!("{} MAC in proxy NS (from ip link): \
                                {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                self.peer_if,
                                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                            return Ok(mac);
                        }
                    }
                }

                // 如果是 netkit（MAC 全零），生成合成 MAC
                if is_netkit_zero || stdout.contains("00:00:00:00:00:00") {
                    let synthetic = generate_synthetic_mac(&self.peer_if);
                    info!("Netkit device, using synthetic MAC: \
                        {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        synthetic[0], synthetic[1], synthetic[2],
                        synthetic[3], synthetic[4], synthetic[5]);
                    return Ok(synthetic);
                }

                // sysfs 和 ip link 都失败，返回详细错误
                return Err(anyhow::anyhow!(
                    "Failed to get MAC for {}: sysfs failed, ip link show output: {}",
                    self.peer_if, stdout
                ));
            }
        };
    }

    /// 获取 dae0peer 在代理 NS 中的 ifindex
    ///
    /// **保证**即使读取失败，也切换回宿主 NS（防止命名空间泄漏）。
    /// 通过 RAII guard 实现。
    pub fn get_peer_ifindex(&self) -> Result<u32> {
        let _guard = self.enter_proxy_ns()?;
        let cstr = std::ffi::CString::new(self.peer_if.as_str())
            .map_err(|e| anyhow::anyhow!("Invalid interface name: {}", e))?;
        let ifindex = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
        // _guard 在此 drop，自动切回宿主 NS（即使上面出错返回）
        if ifindex == 0 {
            return Err(anyhow::anyhow!(
                "Failed to get ifindex for {} in proxy netns",
                self.peer_if
            ));
        }
        info!("{} ifindex in proxy NS: {}", self.peer_if, ifindex);
        Ok(ifindex)
    }

    /// 获取代理命名空间的 inode 号（用于 PARAM.dae_netns_id）
    pub fn get_proxy_netns_inode(&self) -> Result<u32> {
        let fd = self.proxy_ns_fd.as_ref()
            .ok_or(NetnsError::NotCreated)?;
        let fd_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
        let metadata = std::fs::metadata(&fd_path)
            .with_context(|| format!("Failed to stat {}", fd_path))?;
        let inode = metadata.st_ino() as u32;
        info!("Proxy netns inode (dae_netns_id): {}", inode);
        Ok(inode)
    }

    /// 检查是否使用了 netkit
    pub fn is_netkit(&self) -> bool {
        self.use_netkit
    }

    // ================================================================
    // 销毁
    // ================================================================

    /// 销毁网络命名空间和 veth/netkit pair
    ///
    /// 完整清理流程：
    /// 1. 终止子进程（先 SIGTERM 优雅终止，1 秒后 SIGKILL 强制终止）
    /// 2. 删除宿主 NS 策略路由规则（ip rule/route）
    /// 3. 删除代理 NS 策略路由规则（IPv4 + IPv6）
    /// 4. 删除 veth/netkit pair（删除宿主侧的 host_if 即可删除整个 pair）
    /// 5. 关闭持有 netns 的 fd
    ///
    /// # 错误处理策略
    ///
    /// 即使中间步骤失败，也继续尝试后续清理步骤。
    /// 确保尽可能多的资源被释放。
    pub fn destroy(&mut self) -> Result<()> {
        info!("Destroying network namespace and veth/netkit pair");

        let mut has_error = false;

        // ---- Step 1：终止子进程 ----
        if let Some(pid) = self.child_pid.take() {
            if let Err(e) = self.kill_child_process(pid) {
                warn!("Failed to kill child process {}: {}", pid, e);
                has_error = true;
            }
        }

        // ---- Step 2：删除宿主 NS 策略路由规则 ----
        if let Err(e) = self.remove_host_policy_routing() {
            warn!("Failed to remove host NS policy routing: {}", e);
        }

        // ---- Step 3：删除代理 NS 策略路由规则（IPv4 + IPv6）----
        // Policy routing is in proxy NS, so join it first to delete.
        if let Err(e) = self.join_proxy_ns() {
            warn!("Failed to join proxy NS for policy routing cleanup: {}", e);
        } else {
            let mark_str = format!("{:#x}/{:#x}", self.proxy_mark, self.proxy_mask);
            let table_str = self.route_table.to_string();
            // IPv6 路由和规则
            let _ = self.run_ip(&["-6", "route", "del", "local", "default", "dev", "lo", "table", &table_str]);
            let _ = self.run_ip(&["-6", "rule", "del", "fwmark", &mark_str, "table", &table_str]);
            // IPv4 路由和规则
            let _ = self.run_ip(&["route", "del", "local", "default", "dev", "lo", "table", &table_str]);
            let _ = self.run_ip(&["rule", "del", "fwmark", &mark_str, "table", &table_str]);
            // 切回宿主 NS
            if let Err(e) = self.join_host_ns() {
                warn!("Failed to return to host NS after policy routing cleanup: {}", e);
            }
        }

        // ---- Step 4：删除 link pair ----
        // 现在我们位于宿主 NS，直接删除 host_if（dae0）
        // 这会自动删除 pair 的另一端（dae0peer 在代理 NS 中也会被删除）
        let delete_link_result = self.run_ip(&["link", "delete", &self.host_if]);
        if let Err(e) = delete_link_result {
            // 也尝试删除 peer_if（可能 host_if 已被删除或 netkit 残留）
            warn!(
                "Failed to delete {} (trying {}): {}",
                self.host_if, self.peer_if, e
            );
            if let Err(e2) = self.run_ip(&["link", "delete", &self.peer_if]) {
                warn!("Failed to delete {}: {}", self.peer_if, e2);
                has_error = true;
            }
        } else {
            info!("Deleted link pair (via {})", self.host_if);
        }

        // ---- Step 5：关闭 netns fd ----
        self.host_ns_fd.take();
        info!("Closed host netns fd");
        self.proxy_ns_fd.take();
        info!("Closed proxy netns fd");

        // ---- 重置状态 ----
        self.child_pid = None;

        if has_error {
            warn!("Network namespace destruction completed with some errors");
        } else {
            info!("Network namespace and veth/netkit pair destroyed successfully");
        }

        Ok(())
    }

    /// 在代理命名空间中启动子进程
    ///
    /// 此方法会 fork 一个子进程，子进程进入代理网络命名空间后：
    /// 1. 设置 `PR_SET_PDEATHSIG(SIGTERM)` — 父进程退出时子进程自动收到 SIGTERM
    /// 2. 执行指定的代理程序
    ///
    /// # 参数
    ///
    /// * `program` — 要执行的程序路径
    /// * `args` — 程序参数列表
    ///
    /// # 返回
    ///
    /// 返回子进程的 `std::process::Child` 句柄。
    ///
    /// # 错误
    ///
    /// - 如果命名空间尚未创建，返回 [`NetnsError::NotCreated`]
    /// - 如果已经有子进程在运行，返回 [`NetnsError::ChildProcess`]
    pub fn spawn_proxy_process(&mut self, program: &str, args: &[&str]) -> Result<Child> {
        let proxy_ns_fd = self.proxy_ns_fd.as_ref()
            .ok_or(NetnsError::NotCreated)?;
        let _host_ns_fd = self.host_ns_fd.as_ref()
            .ok_or(NetnsError::NotCreated)?;

        if self.child_pid.is_some() {
            return Err(NetnsError::ChildProcess("A child process is already running".into()).into());
        }

        // 获取代理 netns 的 fd 路径，用于 nsenter
        let ns_fd_path = format!("/proc/self/fd/{}", proxy_ns_fd.as_raw_fd());

        info!(
            program = %program,
            args = ?args,
            ns_fd = %proxy_ns_fd.as_raw_fd(),
            "Spawning proxy process in proxy network namespace via nsenter"
        );

        // 使用 nsenter 在代理命名空间中启动子进程
        let child = unsafe {
            Command::new("nsenter")
                .arg("--net")
                .arg(&ns_fd_path)
                .arg(program)
                .args(args)
                .pre_exec(move || {
                    #[cfg(target_os = "linux")]
                    {
                        let rc = libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                        if rc != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }

                    Ok(())
                })
                .spawn()
                .context("Failed to spawn proxy process via nsenter")?
        };

        let pid = child.id();
        self.child_pid = Some(pid);
        info!("Proxy process started with PID: {} in proxy namespace", pid);

        Ok(child)
    }

    // ================================================================
    // 查询方法
    // ================================================================

    /// 获取当前管理的子进程 PID
    pub fn child_pid(&self) -> Option<u32> {
        self.child_pid
    }

    /// 获取宿主侧接口名
    pub fn host_if(&self) -> &str {
        &self.host_if
    }

    /// 获取代理侧接口名
    pub fn peer_if(&self) -> &str {
        &self.peer_if
    }

    /// 检查命名空间是否已创建
    pub fn is_created(&self) -> bool {
        self.host_ns_fd.is_some()
    }

    /// 获取代理命名空间的原始 fd
    ///
    /// 返回代理网络命名空间的文件描述符，可用于 `setns()` 系统调用
    /// 以将当前线程/进程切换到代理命名空间。
    ///
    /// # 返回
    ///
    /// * `Some(RawFd)` — 代理命名空间的 fd
    /// * `None` — 命名空间尚未创建
    pub fn get_proxy_ns_fd(&self) -> Option<std::os::unix::io::RawFd> {
        self.proxy_ns_fd.as_ref().map(|fd| fd.as_raw_fd())
    }

    /// 将当前进程加入代理网络命名空间
    ///
    /// 使用 `setns()` 系统调用将当前线程切换到代理网络命名空间。
    /// 这在启动 TProxy 监听器前调用，使 TProxy 在代理命名空间中监听。
    ///
    /// # 注意
    ///
    /// `setns()` 是线程级别的操作，在多线程程序中会影响调用线程。
    /// 在 tokio 异步运行时中，应使用 `spawn_blocking` 或在独立线程中调用。
    ///
    /// # 错误
    ///
    /// * 如果命名空间尚未创建，返回 [`NetnsError::NotCreated`]
    /// * 如果 `setns()` 系统调用失败，返回 IO 错误
    pub fn join_proxy_ns(&self) -> Result<()> {
        let fd = self.proxy_ns_fd.as_ref()
            .ok_or(NetnsError::NotCreated)?;
        sched::setns(fd, CloneFlags::CLONE_NEWNET)
            .context("Failed to switch to proxy network namespace via setns()")?;
        info!("Switched to proxy network namespace");
        Ok(())
    }

    /// 切换到宿主网络命名空间
    ///
    /// 与 [`join_proxy_ns()`](NetnsManager::join_proxy_ns) 对应，
    /// 将当前线程切换回宿主网络命名空间。
    ///
    /// # 错误
    ///
    /// * 如果命名空间尚未创建，返回 [`NetnsError::NotCreated`]
    /// * 如果 `setns()` 系统调用失败，返回 IO 错误
    pub fn join_host_ns(&self) -> Result<()> {
        let fd = self.host_ns_fd.as_ref()
            .ok_or(NetnsError::NotCreated)?;
        sched::setns(fd, CloneFlags::CLONE_NEWNET)
            .context("Failed to switch to host network namespace via setns()")?;
        info!("Switched to host network namespace");
        Ok(())
    }

    /// 进入代理网络命名空间并返回 RAII guard
    ///
    /// 返回的 `NetnsGuard` 在 Drop 时自动切回宿主命名空间，
    /// 确保即使中间发生 panic 或提前 return，命名空间也不会泄露。
    ///
    /// # 示例
    ///
    /// ```ignore
    /// let _guard = self.enter_proxy_ns()?;
    /// // 在代理 NS 中操作，无需手动切回
    /// // _guard drop 时自动切回宿主 NS
    /// ```
    pub fn enter_proxy_ns(&self) -> Result<NetnsGuard<'_>> {
        NetnsGuard::new(self)
    }

    // ========================================================================
    // 辅助方法
    // ========================================================================

    /// 运行 iproute2 命令
    ///
    /// 封装 `ip` 命令调用，提供统一的错误处理和日志。
    ///
    /// # 参数
    ///
    /// * `args` — ip 命令的参数列表
    ///
    /// # 返回
    ///
    /// 成功返回命令的 stdout 字符串，失败返回 [`NetnsError::IpCommand`]
    fn run_ip(&self, args: &[&str]) -> Result<String> {
        let output = Command::new("ip")
            .args(args)
            .output()
            .with_context(|| format!("Failed to execute ip command with args: {:?}", args))?;

        let cmd_str = format!("ip {}", args.join(" "));

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            error!(cmd = %cmd_str, stderr = %stderr, "ip command failed");
            return Err(NetnsError::IpCommand {
                cmd: cmd_str,
                stderr,
            }.into());
        }

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        info!(cmd = %cmd_str, "ip command succeeded");
        Ok(stdout)
    }

    /// 终止子进程
    ///
    /// 先尝试 SIGTERM 优雅终止，等待 1 秒后如果进程仍在运行则 SIGKILL。
    ///
    /// # 参数
    ///
    /// * `pid` — 子进程 PID
    fn kill_child_process(&self, pid: u32) -> Result<()> {
        let pid = Pid::from_raw(pid as i32);

        info!("Terminating child process {}", pid);

        // 先尝试 SIGTERM
        if let Err(e) = signal::kill(pid, Signal::SIGTERM) {
            // ESRCH 表示进程已不存在，这是正常情况
            if e == nix::errno::Errno::ESRCH {
                info!("Child process {} already exited", pid);
                return Ok(());
            }
            warn!("Failed to send SIGTERM to {}: {}", pid, e);
        }

        // 等待 1 秒后检查进程是否还在运行
        std::thread::sleep(std::time::Duration::from_secs(1));

        // 再次检查：发送 SIGKILL 强制终止
        match signal::kill(pid, Signal::SIGKILL) {
            Ok(_) => {
                info!("Force killed child process {}", pid);
            }
            Err(nix::errno::Errno::ESRCH) => {
                info!("Child process {} exited after SIGTERM", pid);
            }
            Err(e) => {
                warn!("Failed to send SIGKILL to {}: {}", pid, e);
            }
        }

        Ok(())
    }
}

impl Drop for NetnsManager {
    /// Drop 时自动清理资源
    ///
    /// ## 清理策略
    ///
    /// 1. **检查每个资源的状态** — 不依赖单一标志，而是分别检查
    ///    `host_ns_fd`、`proxy_ns_fd`、`child_pid`，确保任何泄漏都能被捕获
    /// 2. **调用 `destroy()`** — 如果发现未清理的资源，尝试执行完整销毁流程
    /// 3. **最终保险** — 无论 `destroy()` 是否已调用，都尝试从宿主机删除
    ///    残留接口（幂等操作，崩溃安全）
    ///
    /// ## 注意事项
    ///
    /// Drop 中不应 panic 或传播错误，所有失败都被静默记录为 `warn!` 日志。
    /// 此实现符合 RAII 原则，确保 NetnsManager 在以下场景都能释放资源：
    /// - 正常作用域结束
    /// - 提前 return 忘记调用 destroy()
    /// - panic 栈展开（只要不是 double panic）
    fn drop(&mut self) {
        // ---- Step 1: 检查每个资源的状态 ----
        let has_host_ns = self.host_ns_fd.is_some();
        let has_proxy_ns = self.proxy_ns_fd.is_some();
        let has_child = self.child_pid.is_some();
        let has_resources = has_host_ns || has_proxy_ns || has_child;

        if has_resources {
            warn!(
                has_host_ns_fd = has_host_ns,
                has_proxy_ns_fd = has_proxy_ns,
                child_pid = self.child_pid,
                "NetnsManager dropped without explicit destroy(), cleaning up"
            );
            // ---- Step 2: 执行完整销毁流程 ----
            let _ = self.destroy();
        }

        // ---- Step 3: 最终保险：尝试清理宿主机上可能残留的接口 ----
        // 即使 destroy() 已成功调用，此操作也是幂等的。
        // 这是崩溃安全的最后一道防线：确保无论如何退出，
        // 宿主机命名空间中不会残留 dae0/dae0peer 接口。
        self.cleanup_stale_interfaces();
    }
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netns_manager_new() {
        let config = Config::default();
        let mgr = NetnsManager::new(&config);

        assert_eq!(mgr.host_if, "dae0");
        assert_eq!(mgr.peer_if, "dae0peer");
        assert_eq!(mgr.host_addr, "169.254.0.1/16");
        assert_eq!(mgr.peer_addr, "169.254.0.11/16");
        assert_eq!(mgr.mtu, 1500);
        assert_eq!(mgr.route_table, 2023);
        assert_eq!(mgr.proxy_mark, 0x8000000);
        assert_eq!(mgr.proxy_mask, 0x8000000);
        assert!(!mgr.use_netkit);
        assert!(mgr.host_ns_fd.is_none());
        assert!(mgr.proxy_ns_fd.is_none());
        assert!(mgr.child_pid.is_none());
        assert!(!mgr.is_created());
    }

    #[test]
    fn test_netns_manager_new_with_custom_config() {
        let config = Config {
            veth_host: "test0".into(),
            veth_peer: "test0peer".into(),
            host_addr: "10.0.0.1/24".into(),
            peer_addr: "10.0.0.2/24".into(),
            mtu: 9000,
            route_table: 100,
            fwmark_proxy: 0x01000000,
            fwmark_mask: 0xff000000,
            ..Default::default()
        };
        let mgr = NetnsManager::new(&config);

        assert_eq!(mgr.host_if, "test0");
        assert_eq!(mgr.peer_if, "test0peer");
        assert_eq!(mgr.host_addr, "10.0.0.1/24");
        assert_eq!(mgr.peer_addr, "10.0.0.2/24");
        assert_eq!(mgr.mtu, 9000);
        assert_eq!(mgr.route_table, 100);
        assert_eq!(mgr.proxy_mark, 0x01000000);
        assert_eq!(mgr.proxy_mask, 0xff000000);
    }

    #[test]
    fn test_destroy_without_create() {
        let config = Config::default();
        let mut mgr = NetnsManager::new(&config);

        // destroy() 应该在不创建的情况下安全调用
        assert!(mgr.destroy().is_ok());
    }

    #[test]
    fn test_read_mac_from_sysfs_format() {
        // 仅测试 MAC 解析逻辑（不需要 root）
        let content = "00:11:22:33:44:55\n";
        let path = "/tmp/_test_mac_addr";
        std::fs::write(path, content).unwrap();
        let result = std::fs::read_to_string(path).unwrap();
        let parts: Vec<&str> = result.trim().split(':').collect();
        assert_eq!(parts.len(), 6);
        let mut mac = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            mac[i] = u8::from_str_radix(part, 16).unwrap();
        }
        assert_eq!(mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let _ = std::fs::remove_file("/tmp/_test_mac_addr");
    }
}
