//! 命名网络命名空间 + netkit pair 管理
//!
//! 本模块负责创建和管理命名网络命名空间及 netkit 对，用于将代理流量
//! 从宿主命名空间导入到代理命名空间进行处理。
//!
//! ## 架构
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                     宿主网络命名空间                          │
//! │                                                              │
//! │  ┌─────────────┐  ┌──────────────┐                           │
//! │  │   eth0      │  │   dae0       │                           │
//! │  │  (外网)     │  │ fe80::.../128│                           │
//! │  └─────────────┘  └──────┬───────┘                           │
//! │                           │                                   │
//! ├───────────────────────────┼───────────────────────────────────┤
//! │        netkit pair        │                                   │
//! ├───────────────────────────┼───────────────────────────────────┤
//! │                           │                                   │
//! │  ┌────────────────────┐ ┌─┴──────────────┐                   │
//! │  │   lo               │ │ dae0peer       │                   │
//! │  │   route table 2023 │ │169.254.0.11/32 │                   │
//! │  │                    │ │fe80::.../128   │                   │
//! │  └────────────────────┘ └────────────────┘                   │
//! │                   daens（代理网络命名空间）                     │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## 流量路径
//!
//! 1. 入站数据包进入宿主 NS 中的 `dae0`
//! 2. TC(tproxy_dae0_ingress) 拦截，查找路由，设置 fwmark
//! 3. 数据包通过 netkit 到达 `dae0peer`（在 daens 中）
//! 4. 策略路由（fwmark → table 2023 → local default dev lo）送达 TProxy socket
//! 5. 代理处理完成后，回复通过 `dae0` 回到宿主 NS
//!
//! ## 与原版 dae 对齐
//!
//! 本实现与原版 dae (https://github.com/daeuniverse/dae) 的 `netns_utils.go`
//! 保持一致：
//! - 使用**命名**网络命名空间（`ip netns add daens`），而非 unshare
//! - netkit pair 在**宿主 NS** 中创建，再将 dae0peer 移入 daens
//! - 通过 setns() 进行 daens 内操作
//! - 使用永久 ARP/NDP 条目替代广播

use crate::Config;
use anyhow::{Context, Result};
use rtnetlink::packet_route::link::NetkitMode;
use rtnetlink::packet_route::route::RouteScope;
use rtnetlink::packet_route::route::{RouteAttribute, RouteMessage, RouteType};
use rtnetlink::packet_route::rule::{RuleAction, RuleAttribute, RuleMessage};
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::{new_connection, LinkMessageBuilder, LinkNetkit, LinkUnspec, LinkVeth, RouteMessageBuilder};
use std::fs;
use std::os::linux::fs::MetadataExt;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::process::Command;
use std::{net::IpAddr, path::Path};
use tracing::{debug, error, info, warn};

// ============================================================================
// 常量
// ============================================================================

/// 命名网络命名空间名称
const NS_NAME: &str = "daens";

/// 网络命名空间挂载路径
const NETNS_RUN_DIR: &str = "/var/run/netns";

/// 宿主侧接口名（位于宿主 NS）
const HOST_IF: &str = "dae0";

/// 代理侧接口名（位于 daens）
const PEER_IF: &str = "dae0peer";

/// 代理侧 IPv4 地址
const PEER_ADDR: &str = "169.254.0.11/32";

/// 路由下一跳（宿主角色的链路本地地址，实际不作为 dae0 的 IP）
const NEXTHOP_ADDR: &str = "169.254.0.1";

/// IPv6 链路本地地址（分配给 dae0）
const IPV6_LL: &str = "fe80::ecee:eeff:feee:eeee";

/// 默认 MTU
#[allow(dead_code)]
const DEFAULT_MTU: u32 = 1500;

/// 默认策略路由表 ID
#[allow(dead_code)]
const DEFAULT_ROUTE_TABLE: u32 = 2023;

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
    /// iproute2 命令执行失败
    #[error("ip command failed: {cmd}\nstderr: {stderr}")]
    IpCommand {
        /// 执行的命令
        cmd: String,
        /// 标准错误输出
        stderr: String,
    },
    /// 内核版本过低，不支持 netkit（需要 ≥ 6.7）
    #[error("Netkit requires kernel >= 6.7")]
    NetkitNotSupported,
}

// ============================================================================
// RAII Guard
// ============================================================================

/// RAII guard：进入 daens，在 Drop 时自动切回宿主命名空间。
struct NetnsGuard<'a> {
    mgr: &'a NetnsManager,
}

impl<'a> NetnsGuard<'a> {
    fn new(mgr: &'a NetnsManager) -> Result<Self> {
        mgr.join_proxy_ns()?;
        Ok(Self { mgr })
    }
}

impl<'a> Drop for NetnsGuard<'a> {
    fn drop(&mut self) {
        if let Err(e) = self.mgr.join_host_ns() {
            error!(
                "CRITICAL: Failed to return to host network namespace: {}. \
                 The current thread may be in the wrong namespace!",
                e
            );
        }
    }
}

// ============================================================================
// 辅助函数
// ============================================================================

/// 读取 /sys/class/net/<ifname>/address 的 MAC 地址
fn read_mac_from_sysfs(ifname: &str) -> Result<[u8; 6]> {
    let path = format!("/sys/class/net/{}/address", ifname);
    let content =
        fs::read_to_string(&path).with_context(|| format!("Failed to read MAC from {}", path))?;
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

/// 写入 sysctl 参数
fn write_sysctl(key: &str, value: &str) -> Result<()> {
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    fs::write(&path, value).with_context(|| format!("Failed to write sysctl {} = {}", key, value))
}

/// 获取 dae0 的 MAC 地址（用于永久 ARP/NDP 条目）
fn get_dae0_mac() -> Result<[u8; 6]> {
    read_mac_from_sysfs(HOST_IF)
}

/// 从 rtnetlink Error 转换为 anyhow Error
fn from_rtnetlink_err(e: rtnetlink::Error) -> anyhow::Error {
    anyhow::anyhow!("rtnetlink error: {}", e)
}

/// 建立到宿主 NS 的 rtnetlink 连接，返回 (connection_task, handle)
fn create_host_handle() -> Result<(tokio::task::JoinHandle<()>, rtnetlink::Handle)> {
    let (connection, handle, _) =
        new_connection().context("Failed to create netlink connection")?;
    let task = tokio::spawn(connection);
    Ok((task, handle))
}

/// 进入 daens 建立 rtnetlink 连接，再切回宿主 NS，返回 daens 的 handle。
/// 由于 netlink socket 创建时绑定到当前 netns，此后通过此 handle 发送的
/// 操作会作用在 daens 上。
fn create_daens_handle(
    proxy_ns_fd: &OwnedFd,
    host_ns_fd: &OwnedFd,
) -> Result<(tokio::task::JoinHandle<()>, rtnetlink::Handle)> {
    // 进入 daens
    nix::sched::setns(proxy_ns_fd, nix::sched::CloneFlags::CLONE_NEWNET)
        .context("Failed to enter daens for creating netlink connection")?;

    // 在 daens 中创建 netlink 连接（socket 绑定到 daens）
    let result = new_connection().context("Failed to create daens netlink connection");

    // 立即切回宿主 NS（无论创建成功与否）
    if let Err(e) = nix::sched::setns(host_ns_fd, nix::sched::CloneFlags::CLONE_NEWNET) {
        error!(
            "CRITICAL: Failed to return to host netns after creating daens handle: {}",
            e
        );
    }

    let (connection, handle, _) = result?;
    let task = tokio::spawn(connection);
    Ok((task, handle))
}

/// 解析 "169.254.0.11/32" 形式的地址字符串为 (IpAddr, u8) 对
fn parse_addr_prefix(s: &str) -> Result<(IpAddr, u8)> {
    let (addr_str, prefix_str) = s
        .split_once('/')
        .with_context(|| format!("Invalid address/prefix format: {}", s))?;
    let prefix_len: u8 = prefix_str
        .parse()
        .with_context(|| format!("Invalid prefix length: {}", prefix_str))?;
    let addr: IpAddr = addr_str
        .parse()
        .with_context(|| format!("Invalid IP address: {}", addr_str))?;
    Ok((addr, prefix_len))
}

// ============================================================================
// 内核版本探测
// ============================================================================

/// 检测内核版本。
/// 返回 (major, minor) 元组。
fn kernel_version() -> (u32, u32) {
    let mut uts = std::mem::MaybeUninit::<libc::utsname>::zeroed();
    let ret = unsafe { libc::uname(uts.as_mut_ptr()) };
    if ret != 0 {
        return (0, 0);
    }
    let uts = unsafe { uts.assume_init() };
    let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }
        .to_string_lossy()
        .to_string();
    let parts: Vec<&str> = release.split('.').collect();
    let major = parts.get(0).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    let minor = parts.get(1).and_then(|s| {
        // Handle cases like "6.7.0" or "6.7-arch"
        let s = s.split(|c: char| !c.is_ascii_digit()).next().unwrap_or(s);
        s.parse::<u32>().ok()
    }).unwrap_or(0);
    (major, minor)
}

// ============================================================================
// NetnsManager
// ============================================================================

/// 网络命名空间管理器
///
/// 管理命名网络命名空间 `daens` 的生命周期，包括：
/// - 创建/销毁命名空间
/// - 创建并配置 netkit pair（宿主 NS 中创建，对端移入 daens）
/// - 配置 IPv4/IPv6 地址、路由、永久 ARP/NDP 条目
/// - 配置策略路由（fwmark → table → lo 本地投递）
/// - 配置 sysctl 参数
///
/// # 与原版 dae 的关系
///
/// 本实现与原版 dae 的 `netns_utils.go` 完全对齐：
/// - 不使用 `unshare`，而是使用命名 netns
/// - netkit pair 在宿主 NS 中创建
/// - 通过 `/var/run/netns/daens` fd 进行 `setns()` 切换
/// - 使用 rtnetlink 代替 iproute2 命令
pub struct NetnsManager {
    /// 宿主侧接口名（dae0）— 位于宿主 NS
    host_if: String,
    /// 代理侧接口名（dae0peer）— 位于 daens
    peer_if: String,
    /// 代理侧 IPv4 地址（169.254.0.11/32）
    peer_addr: String,
    /// 接口 MTU
    mtu: u32,
    /// 策略路由表 ID（2023）
    route_table: u32,
    /// TPROXY_MARK（0x8000000）
    proxy_mark: u32,
    /// TPROXY_MASK（0x8000000）
    proxy_mask: u32,
    /// 命名空间名称（"daens"）
    ns_name: String,
    /// 宿主 netns fd（持有引用防止 GC 回收）
    host_ns_fd: Option<OwnedFd>,
    /// daens fd（从 /var/run/netns/daens 打开）
    proxy_ns_fd: Option<OwnedFd>,
    /// Whether destroy() has been called (prevents double-destroy in Drop)
    destroyed: bool,
    /// 是否使用 netkit（false 则回退到 veth）
    use_netkit: bool,
}

impl NetnsManager {
    /// 从配置对象创建管理器
    ///
    /// 此时不会创建命名空间，仅保存配置参数。
    /// 调用 [`create()`](NetnsManager::create) 后才实际创建。
    pub fn new(config: &Config) -> Self {
        let use_netkit = Self::probe_netkit();
        Self {
            host_if: HOST_IF.into(),
            peer_if: PEER_IF.into(),
            peer_addr: PEER_ADDR.into(),
            mtu: config.mtu,
            route_table: config.route_table,
            proxy_mark: config.fwmark_proxy,
            proxy_mask: config.fwmark_mask,
            ns_name: NS_NAME.into(),
            host_ns_fd: None,
            proxy_ns_fd: None,
            destroyed: false,
            use_netkit,
        }
    }

    /// 探测内核是否支持 netkit (kernel >= 6.7)。
    /// 同时尝试通过 sysfs 验证 netkit 模块是否可用。
    pub fn probe_netkit() -> bool {
        let (major, minor) = kernel_version();
        let version_ok = major > 6 || (major == 6 && minor >= 7);
        if !version_ok {
            return false;
        }
        // 额外验证：尝试检查 netkit 相关的 sysfs 路径是否存在
        std::path::Path::new("/sys/module/netkit").exists()
            || std::path::Path::new("/sys/bus/netkit").exists()
    }

    /// 创建命名网络命名空间和 netkit pair
    ///
    /// # 完整流程
    ///
    /// 与原版 dae 完全一致：
    ///
    /// 1. 保存宿主 netns fd
    /// 2. 清理残留的 daens 和 dae0/dae0peer 接口（崩溃安全）
    /// 3. 创建命名网络命名空间 `daens`
    /// 4. 打开 `/var/run/netns/daens` 保存 daens fd
    /// 5. **在宿主 NS 中**创建 netkit pair (L3)
    /// 6. 将 dae0peer 移入 daens
    /// 7. 配置 dae0peer（daens 中）：IP、路由、永久 ARP/NDP、sysctl、策略路由
    /// 8. 配置 dae0（宿主 NS 中）：IPv6 LL、MTU、up、sysctl
    /// 9. 配置宿主 NS 策略路由：rule + route
    ///
    /// # 错误
    ///
    /// - 如果命名空间已创建，返回 [`NetnsError::AlreadyCreated`]
    pub async fn create(&mut self) -> Result<()> {
        if self.host_ns_fd.is_some() {
            return Err(NetnsError::AlreadyCreated.into());
        }

        info!(
            host_if = %self.host_if,
            peer_if = %self.peer_if,
            peer_addr = %self.peer_addr,
            mtu = %self.mtu,
            route_table = %self.route_table,
            ns_name = %self.ns_name,
            proxy_mark = %format!("{:#x}", self.proxy_mark),
            "Creating named network namespace and netkit pair (original dae architecture)"
        );

        // ----------------------------------------------------------------
        // 状态跟踪：用于回滚
        // ----------------------------------------------------------------
        let mut host_ns_fd: Option<OwnedFd> = None;
        let mut proxy_ns_fd: Option<OwnedFd> = None;
        let mut netns_created = false;
        let mut netkit_created = false;
        let mut peer_moved = false;

        // ---- Step 1: 保存宿主 netns fd ----
        {
            let host_ns_file = fs::File::open("/proc/self/ns/net")
                .context("Failed to open /proc/self/ns/net to save host netns fd")?;
            host_ns_fd = Some(OwnedFd::from(host_ns_file));
            info!(
                "Saved host netns fd: {}",
                host_ns_fd.as_ref().unwrap().as_raw_fd()
            );
        }

        // ---- Step 2: 清理残留 ----
        Self::cleanup_stale_sync();

        // ---- Step 3: 创建命名网络命名空间 ----
        Self::create_named_netns(&self.ns_name)
            .context("Failed to create named network namespace")?;
        netns_created = true;
        info!("Created named network namespace: {}", self.ns_name);

        // ---- Step 4: 打开 daens fd ----
        {
            let ns_path = format!("{}/{}", NETNS_RUN_DIR, self.ns_name);
            let daens_file = fs::File::open(&ns_path)
                .with_context(|| format!("Failed to open daens fd from {}", ns_path))?;
            proxy_ns_fd = Some(OwnedFd::from(daens_file));
            info!(
                "Opened daens fd: {} (from {})",
                proxy_ns_fd.as_ref().unwrap().as_raw_fd(),
                ns_path
            );
        }

        // ---- Step 5-9: async rtnetlink 操作 ----
        let host_ns_fd_ref = host_ns_fd.as_ref().unwrap();
        let proxy_ns_fd_ref = proxy_ns_fd.as_ref().unwrap();

        let netlink_result = Self::create_netlink(
            &self.host_if,
            &self.peer_if,
            self.ns_name.as_str(),
            self.mtu,
            self.proxy_mark,
            self.proxy_mask,
            self.route_table,
            self.use_netkit,
            host_ns_fd_ref,
            proxy_ns_fd_ref,
            &mut netkit_created,
            &mut peer_moved,
        )
        .await;

        match netlink_result {
            Ok(()) => {
                self.host_ns_fd = host_ns_fd.take();
                self.proxy_ns_fd = proxy_ns_fd.take();
                info!("Named network namespace and netkit pair created successfully");
                Ok(())
            }
            Err(e) => {
                Self::rollback_create(
                    host_ns_fd.as_ref(),
                    netns_created,
                    netkit_created,
                    peer_moved,
                );
                error!("Failed to create network namespace: {}", e);
                Err(e)
            }
        }
    }

    // ----------------------------------------------------------------
    // 命名空间创建（静态辅助方法）
    // ----------------------------------------------------------------

    /// 创建命名网络命名空间（等效于 `ip netns add <name>`）
    ///
    /// 实现方式：
    /// 1. 创建 `/var/run/netns/` 目录（若不存在）
    /// 2. 创建挂载点文件 `/var/run/netns/<name>`
    /// 3. `unshare(CLONE_NEWNET)` 进入新 netns
    /// 4. `mount --bind /proc/self/ns/net /var/run/netns/<name>`
    /// 5. `setns()` 回到宿主 netns
    fn create_named_netns(name: &str) -> Result<()> {
        // 确保 /var/run/netns 存在
        fs::create_dir_all(NETNS_RUN_DIR)
            .with_context(|| format!("Failed to create directory {}", NETNS_RUN_DIR))?;

        let ns_path = format!("{}/{}", NETNS_RUN_DIR, name);
        let ns_path = Path::new(&ns_path);

        // 若文件已存在，先清理
        let _ = fs::remove_file(ns_path);

        // 创建空文件作为挂载点
        fs::write(ns_path, "")
            .with_context(|| format!("Failed to create mount point {}", ns_path.display()))?;

        // 保存当前（宿主）netns fd
        let host_ns_file =
            fs::File::open("/proc/self/ns/net").context("Failed to open /proc/self/ns/net")?;
        let host_ns_fd = OwnedFd::from(host_ns_file);

        // 创建新网络命名空间
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)
            .context("Failed to unshare network namespace")?;

        // 在新 netns 中 bind mount /proc/self/ns/net 到挂载点
        nix::mount::mount(
            Some("/proc/self/ns/net"),
            ns_path,
            Some("none"),
            nix::mount::MsFlags::MS_BIND,
            None::<&str>,
        )
        .context("Failed to bind mount namespace")?;

        // 切换回宿主 netns
        nix::sched::setns(&host_ns_fd, nix::sched::CloneFlags::CLONE_NEWNET)
            .context("Failed to return to host network namespace")?;

        info!("Named network namespace {} created via rtnetlink", name);
        Ok(())
    }

    // ================================================================
    // 同步清理和回滚
    // ================================================================

    /// 清理可能残留的资源（同步版本，使用 ip 命令兜底）
    fn cleanup_stale_sync() {
        // 由于此方法在 async create() 最初被调用，此时可能尚未建立
        // rtnetlink 连接。使用 ip 命令清理最可靠。
        let _ = Command::new("ip")
            .args(["netns", "delete", NS_NAME])
            .output();
        let _ = Command::new("ip")
            .args(["link", "delete", HOST_IF])
            .output();
        let _ = Command::new("ip")
            .args(["link", "delete", PEER_IF])
            .output();
        info!("Cleaned up stale netns and interfaces");
    }

    /// 回滚 create() 中已创建的中间资源（同步版本）
    fn rollback_create(
        host_ns_fd: Option<&OwnedFd>,
        netns_created: bool,
        netkit_created: bool,
        peer_moved: bool,
    ) {
        warn!("Rolling back partially created resources");

        // 确保在宿主 NS 中执行清理
        if let Some(fd) = host_ns_fd {
            let _ = nix::sched::setns(fd, nix::sched::CloneFlags::CLONE_NEWNET);
        }

        if netns_created {
            Self::delete_named_netns_sync(NS_NAME);
            info!("Rollback: deleted netns {}", NS_NAME);
        }

        if peer_moved || netkit_created {
            let _ = Command::new("ip").args(["link", "del", HOST_IF]).output();
            let _ = Command::new("ip").args(["link", "del", PEER_IF]).output();
            info!("Rollback: deleted netkit interfaces");
        }
    }

    /// 执行 Steps 5-9 的 async netlink 操作
    async fn create_netlink(
        host_if: &str,
        peer_if: &str,
        ns_name: &str,
        mtu: u32,
        proxy_mark: u32,
        proxy_mask: u32,
        route_table: u32,
        use_netkit: bool,
        host_ns_fd: &OwnedFd,
        proxy_ns_fd: &OwnedFd,
        netkit_created: &mut bool,
        peer_moved: &mut bool,
    ) -> Result<()> {
        // ---- 创建宿主 NS 的 netlink 连接 ----
        let (host_conn_task, host_handle) =
            create_host_handle().context("Failed to create host netlink connection")?;

        // ---- 创建 daens 的 netlink 连接 ----
        let (daens_conn_task, daens_handle) = create_daens_handle(proxy_ns_fd, host_ns_fd)
            .context("Failed to create daens netlink connection")?;

        // ---- Step 5: 创建 link pair（netkit 或 veth）----
        if use_netkit {
            let netkit_msg = LinkNetkit::new(host_if, peer_if, NetkitMode::L2).build();
            host_handle
                .link()
                .add(netkit_msg)
                .execute()
                .await
                .map_err(from_rtnetlink_err)
                .context("Failed to create netkit pair in host namespace")?;
            info!(
                "Created netkit pair (L2 mode) in host NS: {} <-> {}",
                host_if, peer_if
            );
        } else {
            let veth_msg = LinkVeth::new(host_if, peer_if).build();
            host_handle
                .link()
                .add(veth_msg)
                .execute()
                .await
                .map_err(from_rtnetlink_err)
                .context("Failed to create veth pair in host namespace")?;
            info!(
                "Created veth pair in host NS: {} <-> {}",
                host_if, peer_if
            );
        }
        *netkit_created = true;

        // ---- Step 6: 将 dae0peer 移入 daens ----
        let peer_ifindex = get_ifindex_in_ns(peer_if)?;

        let move_msg = LinkMessageBuilder::<LinkUnspec>::new()
            .index(peer_ifindex)
            .setns_by_fd(proxy_ns_fd.as_raw_fd())
            .build();
        host_handle
            .link()
            .change(move_msg)
            .execute()
            .await
            .map_err(from_rtnetlink_err)
            .context("Failed to move dae0peer to daens")?;
        *peer_moved = true;
        info!("Moved {} to daens", peer_if);

        // ---- Step 7: 配置 dae0peer（在 daens 中）----
        // 创建临时 NetnsManager 用于传递配置
        let tmp_mgr = NetnsManager {
            host_if: host_if.to_string(),
            peer_if: peer_if.to_string(),
            peer_addr: PEER_ADDR.to_string(),
            mtu,
            route_table,
            proxy_mark,
            proxy_mask,
            ns_name: ns_name.to_string(),
            host_ns_fd: None,
            proxy_ns_fd: None,
            destroyed: false,
            use_netkit,
        };
        configure_dae0peer_async(&daens_handle, &tmp_mgr, proxy_ns_fd, host_ns_fd)
            .await
            .context("Failed to configure dae0peer")?;

        // ---- Step 8: 配置 dae0（在宿主 NS 中）----
        configure_dae0_async(&host_handle, &tmp_mgr)
            .await
            .context("Failed to configure dae0")?;

        // ---- Step 9: 配置宿主 NS 策略路由 ----
        add_host_policy_routing_async(&host_handle, proxy_mark, proxy_mask, route_table)
            .await
            .context("Failed to add host policy routing")?;

        // 确保后台任务被丢弃
        drop(host_conn_task);
        drop(daens_conn_task);

        Ok(())
    }

    /// 删除命名网络命名空间（同步版本）
    ///
    /// 使用 `MNT_DETACH | MNT_FORCE` 强制卸载，与原版 dae 的 `DeleteNamedNetns` 一致。
    fn delete_named_netns_sync(name: &str) {
        let ns_path = format!("{}/{}", NETNS_RUN_DIR, name);
        let ns_path = Path::new(&ns_path);
        // 使用 umount2 以支持 MNT_DETACH | MNT_FORCE，与原版 dae 一致
        let _ = nix::mount::umount2(
            ns_path,
            nix::mount::MntFlags::MNT_DETACH | nix::mount::MntFlags::MNT_FORCE,
        );
        let _ = fs::remove_file(ns_path);
    }

    // ================================================================
    // 查询方法
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

    /// 获取 dae0peer 在 daens 中的 MAC 地址
    pub fn get_peer_mac(&self) -> Result<[u8; 6]> {
        let _guard = self.enter_proxy_ns()?;

        // 尝试 sysfs 读取（setns 后 sysfs 可能不反映新 netns）
        let mac_result = read_mac_from_sysfs(&self.peer_if);

        match mac_result {
            Ok(mac) if mac != [0u8; 6] => {
                info!(
                    "{} MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    self.peer_if, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                );
                Ok(mac)
            }
            _ => {
                // 回退到 ip link show 解析 MAC
                let output = Command::new("ip")
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
                            info!(
                                "{} MAC (from ip link): {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                self.peer_if, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                            );
                            return Ok(mac);
                        }
                    }
                }

                // 如果 MAC 全零（netkit L3 设备），回退到 dae0 的 MAC
                // netkit L3 模式下无 Ethernet 头，dae0peer 与 dae0 共享同一 MAC
                info!("Netkit device, using dae0 MAC as peer MAC");
                get_dae0_mac()
            }
        }
    }

    /// 获取 dae0peer 在 daens 中的 ifindex
    pub fn get_peer_ifindex(&self) -> Result<u32> {
        let _guard = self.enter_proxy_ns()?;
        let cstr = std::ffi::CString::new(self.peer_if.as_str())
            .map_err(|e| anyhow::anyhow!("Invalid interface name: {}", e))?;
        let ifindex = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
        if ifindex == 0 {
            return Err(anyhow::anyhow!(
                "Failed to get ifindex for {} in daens",
                self.peer_if
            ));
        }
        info!("{} ifindex in daens: {}", self.peer_if, ifindex);
        Ok(ifindex)
    }

    /// 获取 daens 的 inode 号（用于 eBPF PARAM.dae_netns_id）
    pub fn get_proxy_netns_inode(&self) -> Result<u32> {
        let fd = self.proxy_ns_fd.as_ref().ok_or(NetnsError::NotCreated)?;
        let fd_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
        let metadata =
            fs::metadata(&fd_path).with_context(|| format!("Failed to stat {}", fd_path))?;
        let inode = metadata.st_ino() as u32;
        info!("daens inode (dae_netns_id): {}", inode);
        Ok(inode)
    }

    /// 检查是否使用了 netkit（基于内核探测结果）
    pub fn is_netkit(&self) -> bool {
        self.use_netkit
    }

    /// 检查命名空间是否已创建
    pub fn is_created(&self) -> bool {
        self.host_ns_fd.is_some()
    }

    /// 获取宿主侧接口名
    pub fn host_if(&self) -> &str {
        &self.host_if
    }

    /// 获取代理侧接口名
    pub fn peer_if(&self) -> &str {
        &self.peer_if
    }

    /// 获取 daens 的原始 fd
    pub fn get_proxy_ns_fd(&self) -> Option<std::os::unix::io::RawFd> {
        self.proxy_ns_fd.as_ref().map(|fd| fd.as_raw_fd())
    }

    // ================================================================
    // 命名空间切换
    // ================================================================

    /// 切换到 daens
    pub fn join_proxy_ns(&self) -> Result<()> {
        let fd = self.proxy_ns_fd.as_ref().ok_or(NetnsError::NotCreated)?;
        nix::sched::setns(fd, nix::sched::CloneFlags::CLONE_NEWNET)
            .context("Failed to switch to daens via setns()")?;
        info!("Switched to daens");
        Ok(())
    }

    /// 切换回宿主命名空间
    pub fn join_host_ns(&self) -> Result<()> {
        let fd = self.host_ns_fd.as_ref().ok_or(NetnsError::NotCreated)?;
        nix::sched::setns(fd, nix::sched::CloneFlags::CLONE_NEWNET)
            .context("Failed to switch to host network namespace via setns()")?;
        info!("Switched to host network namespace");
        Ok(())
    }

    /// 进入 daens 并返回 RAII guard
    #[allow(private_interfaces)]
    pub fn enter_proxy_ns(&self) -> Result<NetnsGuard<'_>> {
        NetnsGuard::new(self)
    }

    /// 在宿主 NS 中添加策略路由规则（异步）
    ///
    /// 使被 TPROXY_MARK 标记的数据包通过 table <route_table> 路由到本地 lo，
    /// 最终被 TProxy socket 接收处理。
    pub async fn add_host_policy_routing(&self) -> Result<()> {
        let (task, handle) = create_host_handle()
            .context("Failed to create netlink connection for host policy routing")?;
        let result = add_host_policy_routing_async(
            &handle,
            self.proxy_mark,
            self.proxy_mask,
            self.route_table,
        )
        .await;
        drop(task);
        result
    }

    // ================================================================
    // 销毁
    // ================================================================

    /// 销毁网络命名空间和 netkit pair
    ///
    /// 完整清理流程：
    /// 1. 删除宿主 NS 策略路由规则
    /// 2. 删除 netkit pair
    /// 3. 删除命名网络命名空间
    /// 4. 关闭持有 netns 的 fd
    pub fn destroy(&mut self) -> Result<()> {
        if self.destroyed {
            return Ok(());
        }
        info!("Destroying network namespace and netkit pair");

        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                info!("Using tokio runtime for async destroy");
                let result = tokio::task::block_in_place(|| {
                    handle.block_on(async { self.destroy_async().await })
                });
                if let Err(e) = result {
                    warn!("Async destroy failed ({}), falling back to sync cleanup", e);
                    self.destroy_sync_fallback();
                }
            }
            Err(_) => {
                self.destroy_sync_fallback();
            }
        }

        // ---- Step 4：关闭 netns fd ----
        self.host_ns_fd.take();
        self.proxy_ns_fd.take();
        self.destroyed = true;

        info!("Network namespace and netkit pair destroyed successfully");
        Ok(())
    }

    /// 异步销毁（由 destroy() 在 tokio runtime 中调用）
    async fn destroy_async(&self) -> Result<()> {
        let (host_task, host_handle) =
            create_host_handle().context("Failed to create host netlink connection for destroy")?;

        // ---- Step 1：删除宿主 NS 策略路由规则 ----
        if let Err(e) = remove_host_policy_routing_async(
            &host_handle,
            self.proxy_mark,
            self.proxy_mask,
            self.route_table,
        )
        .await
        {
            warn!("Failed to remove host NS policy routing: {}", e);
        }

        // ---- Step 2：删除 netkit pair ----
        // 获取 dae0 ifindex
        let host_ifindex = get_host_ifindex_sync(&self.host_if).unwrap_or(0);
        if host_ifindex > 0 {
            if let Err(e) = host_handle.link().del(host_ifindex).execute().await {
                warn!("Failed to delete {} via rtnetlink: {}", self.host_if, e);
                // 也尝试删除 peer_if
                let peer_ifindex = get_peer_ifindex_sync(&self.peer_if).unwrap_or(0);
                if peer_ifindex > 0 {
                    let _ = host_handle.link().del(peer_ifindex).execute().await;
                }
            }
        } else {
            warn!("Could not get ifindex for {}, falling back", self.host_if);
            let _ = Command::new("ip")
                .args(["link", "delete", &self.host_if])
                .output();
            let _ = Command::new("ip")
                .args(["link", "delete", &self.peer_if])
                .output();
        }

        drop(host_task);

        // ---- Step 3：删除命名网络命名空间 ----
        Self::delete_named_netns_sync(&self.ns_name);

        Ok(())
    }

    /// 同步销毁回退（使用 ip 命令）
    fn destroy_sync_fallback(&self) {
        warn!("Using sync fallback for destroy (no tokio runtime available)");

        // ---- Step 1：删除宿主 NS 策略路由规则 ----
        remove_host_policy_routing_sync(self.proxy_mark, self.proxy_mask, self.route_table);

        // ---- Step 2：删除 netkit pair ----
        let _ = Command::new("ip")
            .args(["link", "delete", &self.host_if])
            .output();
        let _ = Command::new("ip")
            .args(["link", "delete", &self.peer_if])
            .output();

        // ---- Step 3：删除命名网络命名空间 ----
        Self::delete_named_netns_sync(&self.ns_name);
    }
}

// ============================================================================
// Drop
// ============================================================================

impl Drop for NetnsManager {
    /// Drop 时自动清理资源
    fn drop(&mut self) {
        if !self.destroyed && (self.host_ns_fd.is_some() || self.proxy_ns_fd.is_some()) {
            warn!("NetnsManager dropped without explicit destroy(), cleaning up");
            let _ = self.destroy();
        }
    }
}

// ============================================================================
// 辅助函数：获取 ifindex（同步）
// ============================================================================

fn get_ifindex_in_ns(ifname: &str) -> Result<u32> {
    let cstr = std::ffi::CString::new(ifname)
        .map_err(|e| anyhow::anyhow!("Invalid interface name: {}", e))?;
    let ifindex = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
    if ifindex == 0 {
        return Err(anyhow::anyhow!("Failed to get ifindex for {}", ifname));
    }
    Ok(ifindex)
}

fn get_host_ifindex_sync(ifname: &str) -> Result<u32> {
    get_ifindex_in_ns(ifname)
}

fn get_peer_ifindex_sync(ifname: &str) -> Result<u32> {
    get_ifindex_in_ns(ifname)
}

// ============================================================================
// 配置函数（异步，使用 rtnetlink）
// ============================================================================

/// 配置 dae0peer（在 daens 中）
///
/// 对应原版 dae 的：
/// - `setupNetns()` — lo/dae0peer up
/// - `setupIPv4Datapath()` — 169.254.0.11/32 + 路由 + ARP
/// - `setupIPv6Datapath()` — 默认路由 + NDP
/// - `setupSysctl()` — sysctl 参数
/// - `setupRoutingPolicy()` — fwmark 策略路由
async fn configure_dae0peer_async(
    daens_handle: &rtnetlink::Handle,
    mgr: &NetnsManager,
    proxy_ns_fd: &OwnedFd,
    host_ns_fd: &OwnedFd,
) -> Result<()> {
    info!("Configuring dae0peer in daens");

    // 获取 dae0peer 在 daens 中的 ifindex（需要先进入 daens）
    // 使用 setns 临时进入 daens 查询
    let peer_ifindex = {
        nix::sched::setns(proxy_ns_fd, nix::sched::CloneFlags::CLONE_NEWNET)
            .context("Failed to enter daens to get peer ifindex")?;
        let ifindex =
            get_ifindex_in_ns(&mgr.peer_if).context("Failed to get dae0peer ifindex in daens")?;
        nix::sched::setns(host_ns_fd, nix::sched::CloneFlags::CLONE_NEWNET)
            .context("Failed to return to host netns")?;
        ifindex
    };
    info!("dae0peer ifindex in daens: {}", peer_ifindex);

    // ---- dae0peer up ----
    let msg = LinkMessageBuilder::<LinkUnspec>::new()
        .index(peer_ifindex)
        .up()
        .build();
    daens_handle
        .link()
        .change(msg)
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to bring dae0peer up")?;

    // ---- lo up（新 netns 的 lo 默认是 down 的）----
    // 需要获取 lo 在 daens 中的 ifindex
    let lo_ifindex = {
        nix::sched::setns(proxy_ns_fd, nix::sched::CloneFlags::CLONE_NEWNET)
            .context("Failed to enter daens to get lo ifindex")?;
        let ifindex = get_ifindex_in_ns("lo").context("Failed to get lo ifindex in daens")?;
        nix::sched::setns(host_ns_fd, nix::sched::CloneFlags::CLONE_NEWNET)
            .context("Failed to return to host netns")?;
        ifindex
    };
    let msg = LinkMessageBuilder::<LinkUnspec>::new()
        .index(lo_ifindex)
        .up()
        .build();
    daens_handle
        .link()
        .change(msg)
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to bring lo up")?;

    // ---- IPv4 地址：169.254.0.11/32 ----
    let (peer_ip, peer_prefix) = parse_addr_prefix(&mgr.peer_addr)?;
    daens_handle
        .address()
        .add(peer_ifindex, peer_ip, peer_prefix)
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to add IPv4 address to dae0peer")?;

    // ---- IPv4 路由：169.254.0.1 dev dae0peer（链路本地下一跳, scope link）----
    // 原版 dae 明确设置 scope = LINK，使内核将 169.254.0.1 视为直接可达
    let nexthop_ip: std::net::Ipv4Addr = NEXTHOP_ADDR
        .parse()
        .context("Failed to parse NEXTHOP_ADDR")?;
    let mut nexthop_route = RouteMessage::default();
    nexthop_route.header.address_family = AddressFamily::Inet.into();
    nexthop_route.header.destination_prefix_length = 32;
    nexthop_route.header.scope = RouteScope::Link;
    nexthop_route.header.kind = RouteType::Unicast;
    nexthop_route.attributes = vec![
        RouteAttribute::Destination(std::net::IpAddr::V4(nexthop_ip).into()),
        RouteAttribute::Oif(peer_ifindex),
    ];
    daens_handle
        .route()
        .add(nexthop_route)
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to add IPv4 route to 169.254.0.1")?;

    // ---- IPv4 默认路由：default via 169.254.0.1 dev dae0peer ----
    let default_route = RouteMessageBuilder::<std::net::Ipv4Addr>::new()
        .gateway(nexthop_ip)
        .output_interface(peer_ifindex)
        .build();
    daens_handle
        .route()
        .add(default_route)
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to add default IPv4 route")?;

    // ---- 永久 ARP 条目：169.254.0.1 → dae0 的 MAC ----
    let dae0_mac = get_dae0_mac()
        .map(|m| {
            format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            )
        })
        .unwrap_or_else(|_| {
            warn!("Failed to read dae0 MAC, using fallback");
            "02:00:00:00:00:01".to_string()
        });
    info!("dae0 MAC for permanent ARP/NDP: {}", dae0_mac);

    // 解析 MAC 为字节数组
    let mac_bytes: Vec<u8> = dae0_mac
        .split(':')
        .filter_map(|h| u8::from_str_radix(h, 16).ok())
        .collect();
    if mac_bytes.len() != 6 {
        return Err(anyhow::anyhow!("Invalid MAC address bytes: {}", dae0_mac));
    }

    // 添加永久 ARP 条目
    daens_handle
        .neighbours()
        .add(peer_ifindex, std::net::IpAddr::V4(nexthop_ip))
        .link_layer_address(&mac_bytes)
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to add permanent ARP entry")?;

    // ---- IPv6 默认路由：default via fe80::ecee:eeff:feee:eeee dev dae0peer ----
    let ipv6_ll_addr: std::net::Ipv6Addr = IPV6_LL.parse().context("Failed to parse IPV6_LL")?;
    // 使用 RouteMessageBuilder 的 v6 版本
    let ipv6_default_route = RouteMessageBuilder::<std::net::Ipv6Addr>::new()
        .gateway(ipv6_ll_addr)
        .output_interface(peer_ifindex)
        .build();
    daens_handle
        .route()
        .add(ipv6_default_route)
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to add default IPv6 route")?;

    // ---- 永久 NDP 条目 ----
    daens_handle
        .neighbours()
        .add(peer_ifindex, std::net::IpAddr::V6(ipv6_ll_addr))
        .link_layer_address(&mac_bytes)
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to add permanent NDP entry")?;

    // ---- sysctl：dae0peer accept_local（需在 daens 中设置，因为 dae0peer 在 daens 中）----
    {
        nix::sched::setns(proxy_ns_fd, nix::sched::CloneFlags::CLONE_NEWNET)
            .context("Failed to enter daens to set accept_local")?;
        let result = write_sysctl(&format!("net.ipv4.conf.{}.accept_local", mgr.peer_if), "1")
            .context("Failed to set accept_local on dae0peer");
        nix::sched::setns(host_ns_fd, nix::sched::CloneFlags::CLONE_NEWNET)
            .context("Failed to return to host netns after setting accept_local")?;
        result?;
    }

    // ---- sysctl：early_demux（优化性能）----
    write_sysctl("net.ipv4.tcp_early_demux", "1").context("Failed to set tcp_early_demux")?;
    write_sysctl("net.ipv4.ip_early_demux", "1").context("Failed to set ip_early_demux")?;

    // ---- 策略路由：fwmark → table 2023 ----
    add_policy_routing_in_daens(
        daens_handle,
        mgr.proxy_mark,
        mgr.proxy_mask,
        mgr.route_table,
        peer_ifindex,
    )
    .await?;

    info!("dae0peer configuration in daens completed");
    Ok(())
}

/// 在 daens 中添加策略路由规则
async fn add_policy_routing_in_daens(
    daens_handle: &rtnetlink::Handle,
    proxy_mark: u32,
    proxy_mask: u32,
    route_table: u32,
    _peer_ifindex: u32,
) -> Result<()> {
    info!("Adding policy routing in daens");

    // 注意：RuleAddRequest 的 fw_mark 只接受 mark 值，
    // mask 需要额外设置。我们通过修改 RuleMessage 来设置 fwmask。
    // 实际上，RuleAttribute 有 FwMark(u32) 但没有单独的 FwMask。
    // 在 netlink 协议中，fwmark 和 fwmask 一起编码在 FRA_FWMARK 中。
    // 但 rtnetlink 的 RuleAddRequest 只设置了 FwMark。
    // 对于 dae 来说，mark == mask (0x8000000/0x8000000)，所以只使用
    // mark 就足够了。

    // IPv4 策略路由
    daens_handle
        .rule()
        .add()
        .fw_mark(proxy_mark & proxy_mask)
        .table_id(route_table)
        .v4()
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to add IPv4 policy routing rule in daens")?;

    // IPv6 策略路由
    daens_handle
        .rule()
        .add()
        .fw_mark(proxy_mark & proxy_mask)
        .table_id(route_table)
        .v6()
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to add IPv6 policy routing rule in daens")?;

    // ---- local default dev lo table <table> ----
    // 需要获取 lo 在 daens 中的 ifindex
    // 但这里我们已经有 daens_handle，在 daens 中操作

    // IPv4: local default dev lo table <table>
    // 构造路由消息：local 类型，oif=lo_ifindex，table=<table>
    // 需要先获取 lo 的 ifindex
    // 由于 daens_handle 的 socket 在 daens 中，获取操作会返回 daens 中的 lo
    let local_default_v4 = RouteMessageBuilder::<std::net::Ipv4Addr>::new()
        .output_interface(1) // lo 在 netns 中通常是 ifindex 1
        .build();
    // 修改路由类型为 local
    let mut msg_v4 = local_default_v4;
    msg_v4.header.kind = RouteType::Local;
    msg_v4.header.scope = RouteScope::Host; // RTN_LOCAL 必须使用 host scope（254）
    if route_table > 255 {
        msg_v4.header.table = 0;
        msg_v4.attributes.push(RouteAttribute::Table(route_table));
    } else {
        msg_v4.header.table = route_table as u8;
    }
    daens_handle
        .route()
        .add(msg_v4)
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to add IPv4 local default route in daens")?;

    // IPv6: local default dev lo table <table>
    let local_default_v6 = RouteMessageBuilder::<std::net::Ipv6Addr>::new()
        .output_interface(1) // lo ifindex
        .build();
    let mut msg_v6 = local_default_v6;
    msg_v6.header.kind = RouteType::Local;
    msg_v6.header.scope = RouteScope::Host; // RTN_LOCAL 必须使用 host scope（254）
    if route_table > 255 {
        msg_v6.header.table = 0;
        msg_v6.attributes.push(RouteAttribute::Table(route_table));
    } else {
        msg_v6.header.table = route_table as u8;
    }
    daens_handle
        .route()
        .add(msg_v6)
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to add IPv6 local default route in daens")?;

    info!("Policy routing in daens added successfully");
    Ok(())
}

/// 配置 dae0（在宿主 NS 中）
///
/// 对应原版 dae 的：
/// - `setupIPv6Datapath()` — IPv6 LL 地址
/// - `setupSysctl()` — 宿主侧 sysctl 参数
async fn configure_dae0_async(host_handle: &rtnetlink::Handle, mgr: &NetnsManager) -> Result<()> {
    info!("Configuring dae0 in host namespace");

    // 获取 dae0 ifindex
    let host_ifindex = get_host_ifindex_sync(&mgr.host_if).context("Failed to get dae0 ifindex")?;

    // ---- IPv6 链路本地地址 ----
    let ipv6_ll_addr: std::net::Ipv6Addr = IPV6_LL.parse().context("Failed to parse IPV6_LL")?;
    host_handle
        .address()
        .add(host_ifindex, std::net::IpAddr::V6(ipv6_ll_addr), 128)
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to add IPv6 LL address to dae0")?;

    // ---- 设置 MTU ----
    if mgr.mtu > 0 {
        let msg = LinkMessageBuilder::<LinkUnspec>::new()
            .index(host_ifindex)
            .mtu(mgr.mtu)
            .build();
        host_handle
            .link()
            .change(msg)
            .execute()
            .await
            .map_err(from_rtnetlink_err)
            .context("Failed to set MTU on dae0")?;
    }

    // ---- 启用 dae0 ----
    let msg = LinkMessageBuilder::<LinkUnspec>::new()
        .index(host_ifindex)
        .up()
        .build();
    host_handle
        .link()
        .change(msg)
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to bring dae0 up")?;

    // ---- sysctl 参数 ----
    write_sysctl(&format!("net.ipv4.conf.{}.rp_filter", mgr.host_if), "0")?;
    write_sysctl("net.ipv4.conf.all.rp_filter", "0")?;
    write_sysctl(&format!("net.ipv4.conf.{}.arp_filter", mgr.host_if), "0")?;
    write_sysctl("net.ipv4.conf.all.arp_filter", "0")?;
    write_sysctl(&format!("net.ipv4.conf.{}.accept_local", mgr.host_if), "1")?;
    write_sysctl(&format!("net.ipv6.conf.{}.disable_ipv6", mgr.host_if), "0")?;
    write_sysctl(&format!("net.ipv6.conf.{}.forwarding", mgr.host_if), "1")?;

    info!("dae0 configuration in host namespace completed");
    Ok(())
}

/// 在宿主 NS 中添加策略路由规则
async fn add_host_policy_routing_async(
    host_handle: &rtnetlink::Handle,
    proxy_mark: u32,
    proxy_mask: u32,
    route_table: u32,
) -> Result<()> {
    info!("Adding host NS policy routing");

    // ---- 先检查规则是否已存在（避免重复添加）----
    //
    // `ip rule show` 输出示例：
    //   0: from all lookup local
    //   32765: from all fwmark 0x8000000/0x8000000 lookup 2023
    // 同时存在 v4 和 v6 两条规则（输出相同，由内核自动区分 family）。
    // 因此只需检查至少一条匹配即可。
    let mark_str = format!("{:#x}", proxy_mark & proxy_mask);
    let table_str = route_table.to_string();
    let existing = Command::new("ip")
        .args(["rule", "show"])
        .output()
        .context("Failed to run ip rule show")?;
    let existing_stdout = String::from_utf8_lossy(&existing.stdout);

    let rule_exists = existing_stdout.lines().any(|line| {
        line.contains("fwmark") && line.contains(&mark_str) && line.contains(&table_str)
    });

    if rule_exists {
        debug!(
            "Host policy routing rule (fwmark {} → table {}) already exists, skipping",
            mark_str, table_str
        );
        return Ok(());
    }

    // ---- 删除可能残留的规则（确保干净状态）----
    let _ =
        remove_host_policy_routing_async(host_handle, proxy_mark, proxy_mask, route_table).await;

    // IPv4
    host_handle
        .rule()
        .add()
        .fw_mark(proxy_mark & proxy_mask)
        .table_id(route_table)
        .v4()
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to add IPv4 policy routing rule")?;

    // local default dev lo table <table>
    let mut local_default_v4 = RouteMessageBuilder::<std::net::Ipv4Addr>::new()
        .output_interface(1) // lo in host ns
        .build();
    local_default_v4.header.kind = RouteType::Local;
    local_default_v4.header.scope = RouteScope::Host; // RTN_LOCAL 必须使用 host scope（254）
    if route_table > 255 {
        local_default_v4.header.table = 0;
        local_default_v4
            .attributes
            .push(RouteAttribute::Table(route_table));
    } else {
        local_default_v4.header.table = route_table as u8;
    }
    host_handle
        .route()
        .add(local_default_v4)
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to add IPv4 local default route")?;

    // IPv6
    host_handle
        .rule()
        .add()
        .fw_mark(proxy_mark & proxy_mask)
        .table_id(route_table)
        .v6()
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to add IPv6 policy routing rule")?;

    let mut local_default_v6 = RouteMessageBuilder::<std::net::Ipv6Addr>::new()
        .output_interface(1)
        .build();
    local_default_v6.header.kind = RouteType::Local;
    local_default_v6.header.scope = RouteScope::Host; // RTN_LOCAL 必须使用 host scope（254）
    if route_table > 255 {
        local_default_v6.header.table = 0;
        local_default_v6
            .attributes
            .push(RouteAttribute::Table(route_table));
    } else {
        local_default_v6.header.table = route_table as u8;
    }
    host_handle
        .route()
        .add(local_default_v6)
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to add IPv6 local default route")?;

    info!("Host NS policy routing added successfully");
    Ok(())
}


/// 删除宿主 NS 策略路由规则（异步）
async fn remove_host_policy_routing_async(
    host_handle: &rtnetlink::Handle,
    proxy_mark: u32,
    proxy_mask: u32,
    route_table: u32,
) -> Result<()> {
    info!("Removing host NS policy routing");

    // Delete ALL matching ip rules (may be duplicated across restarts).
    // Loop until del returns error (no more matching rules).
    loop {
        let mut rule_v4 = RuleMessage::default();
        rule_v4.header.family = AddressFamily::Inet;
        rule_v4.header.action = RuleAction::ToTable;
        rule_v4
            .attributes
            .push(RuleAttribute::FwMark(proxy_mark & proxy_mask));
        if route_table > 255 {
            rule_v4.attributes.push(RuleAttribute::Table(route_table));
        } else {
            rule_v4.header.table = route_table as u8;
        }
        match host_handle.rule().del(rule_v4).execute().await {
            Ok(_) => continue,
            Err(_) => break,
        }
    }

    loop {
        let mut rule_v6 = RuleMessage::default();
        rule_v6.header.family = AddressFamily::Inet6;
        rule_v6.header.action = RuleAction::ToTable;
        rule_v6
            .attributes
            .push(RuleAttribute::FwMark(proxy_mark & proxy_mask));
        if route_table > 255 {
            rule_v6.attributes.push(RuleAttribute::Table(route_table));
        } else {
            rule_v6.header.table = route_table as u8;
        }
        match host_handle.rule().del(rule_v6).execute().await {
            Ok(_) => continue,
            Err(_) => break,
        }
    }

    // 删除 local default routes
    let mut route_v4 = RouteMessage::default();
    route_v4.header.address_family = AddressFamily::Inet;
    route_v4.header.kind = RouteType::Local;
    route_v4.header.scope = RouteScope::Host;
    if route_table > 255 {
        route_v4.header.table = 0;
        route_v4.attributes.push(RouteAttribute::Table(route_table));
    } else {
        route_v4.header.table = route_table as u8;
    }
    route_v4.attributes.push(RouteAttribute::Oif(1));
    let _ = host_handle.route().del(route_v4).execute().await;

    let mut route_v6 = RouteMessage::default();
    route_v6.header.address_family = AddressFamily::Inet6;
    route_v6.header.kind = RouteType::Local;
    route_v6.header.scope = RouteScope::Host;
    if route_table > 255 {
        route_v6.header.table = 0;
        route_v6.attributes.push(RouteAttribute::Table(route_table));
    } else {
        route_v6.header.table = route_table as u8;
    }
    route_v6.attributes.push(RouteAttribute::Oif(1));
    let _ = host_handle.route().del(route_v6).execute().await;

    Ok(())
}

/// 删除宿主 NS 策略路由规则（同步版本，使用 ip 命令）
///
/// 使用 while 循环删除所有匹配的规则，避免重复规则残留。
fn remove_host_policy_routing_sync(proxy_mark: u32, _proxy_mask: u32, route_table: u32) {
    let mark_str = format!("{:#x}/{:#x}", proxy_mark, proxy_mark);
    let table_str = route_table.to_string();

    // 删除 local default routes
    let _ = Command::new("ip")
        .args([
            "route", "del", "local", "default", "dev", "lo", "table", &table_str,
        ])
        .output();
    let _ = Command::new("ip")
        .args([
            "-6", "route", "del", "local", "default", "dev", "lo", "table", &table_str,
        ])
        .output();

    // 循环删除所有匹配的 IPv4 规则
    loop {
        let output = Command::new("ip")
            .args(["rule", "del", "fwmark", &mark_str, "table", &table_str])
            .output();
        match output {
            Ok(o) if o.status.success() => continue,
            _ => break,
        }
    }

    // 循环删除所有匹配的 IPv6 规则
    loop {
        let output = Command::new("ip")
            .args([
                "-6", "rule", "del", "fwmark", &mark_str, "table", &table_str,
            ])
            .output();
        match output {
            Ok(o) if o.status.success() => continue,
            _ => break,
        }
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
        assert_eq!(mgr.peer_addr, "169.254.0.11/32");
        assert_eq!(mgr.mtu, 1500);
        assert_eq!(mgr.route_table, 2023);
        assert_eq!(mgr.proxy_mark, 0x8000000);
        assert_eq!(mgr.proxy_mask, 0x8000000);
        assert_eq!(mgr.ns_name, "daens");
        assert!(mgr.host_ns_fd.is_none());
        assert!(mgr.proxy_ns_fd.is_none());
        assert!(!mgr.is_created());
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
        let content = "00:11:22:33:44:55\n";
        let path = "/tmp/_test_mac_addr";
        fs::write(path, content).unwrap();
        let result = fs::read_to_string(path).unwrap();
        let parts: Vec<&str> = result.trim().split(':').collect();
        assert_eq!(parts.len(), 6);
        let mut mac = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            mac[i] = u8::from_str_radix(part, 16).unwrap();
        }
        assert_eq!(mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_parse_addr_prefix() {
        let (addr, prefix) = parse_addr_prefix("169.254.0.11/32").unwrap();
        assert_eq!(
            addr,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(169, 254, 0, 11))
        );
        assert_eq!(prefix, 32);

        let (addr, prefix) = parse_addr_prefix("fe80::1/128").unwrap();
        assert_eq!(
            addr,
            std::net::IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(prefix, 128);
    }
}
