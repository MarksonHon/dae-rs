//!
//! This module implements the core control plane logic, including:
//! - Loading/unloading eBPF programs and maps
//! - Parsing configuration and compiling into kernel-executable rules
//! - Managing SOCKS outbound configuration
//! - Handling TCP session forwarding through the proxy path
//! - Outputting runtime logs and basic metrics
//! - Managing network namespace and veth pair lifecycle
//!
//! # Architecture Overview
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │                    ControlPlane                          │
//! │                                                          │
//! │  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  │
//! │  │  NetnsManager │  │ EbpfManager  │  │ Config        │  │
//! │  │              │  │              │  │               │  │
//! │  │ · veth pair  │  │ · load/unload│  │ · port/mark   │  │
//! │  │ · policy     │  │ · TC attach  │  │ · addr/MTU    │  │
//! │  │   routing    │  │ · map R/W    │  │               │  │
//! │  │ · subprocess │  │              │  │               │  │
//! │  └──────────────┘  └──────────────┘  └───────────────┘  │
//! └──────────────────────────────────────────────────────────┘
//! ```
//!
//! # Module Organization
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`ebpf`] | eBPF program load/unload/attach |
//! | [`netns`] | Network namespace & veth management |
//! | [`tproxy`] | TProxy transparent proxy listener |
//! | [`config`] | daefile config parsing & compilation |
//!
//! # Quick Start
//!
//! ```no_run
//! use control::ControlPlane;
//! use control::Config;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = Config::default();
//!     let mut cp = ControlPlane::new(config);
//!     cp.start().await?;
//!     // ... running ...
//!     cp.stop().await?;
//!
//!     Ok(())
//! }
//! ```

pub mod api;
pub mod config;
pub mod dns;
pub mod domain_routing;
pub mod ebpf;
pub mod iface_mgr;
pub mod netns;
pub mod routing;
pub mod tproxy;
pub mod udp_tracker;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use libbpf_rs::MapCore;
use protocols::Socks5Dialer;
use tproxy::{TproxyListener, UdpTproxyListener};

use crate::ebpf::CidrEntry;

// Ringbuf event constants (must match tproxy.c)
const DAE_EVENT_BLOCKED: u32 = 0;
const DAE_EVENT_UDP_CONN_OVERFLOW: u32 = 1;
const DAE_EVENT_TCP_CONN_OVERFLOW: u32 = 2;

// ============================================================================
// Control Plane Configuration
// ============================================================================

/// Control plane configuration
///
/// Contains all parameters required for control plane operation, with sensible defaults.
///
/// # Default Values
///
/// | Parameter | Default | Description |
/// |-----------|---------|-------------|
/// | `tproxy_port` | 15080 | TProxy listen port |
/// | `route_table` | 2023 | Policy routing table ID |
/// | `fwmark_proxy` | 0x8000000 | Proxy traffic mark (TPROXY_MARK) |
/// | `fwmark_bypass` | 0x04000000 | Bypass mark |
/// | `fwmark_mask` | 0x8000000 | Mark mask |
/// | `mtu` | 1500 | Interface MTU |
/// | `log_level` | "info" | Log level |
/// | `proxy_addr` | 127.0.0.1:1080 | SOCKS5 proxy address |
/// | `proxy_username` | "" | SOCKS5 username (empty = no auth) |
/// | `proxy_password` | "" | SOCKS5 password |
/// | `proxy_dial_timeout_ms` | 5000 | SOCKS5 dial timeout (ms) |
#[derive(Debug, Clone)]
pub struct Config {
    /// TProxy listen port
    pub tproxy_port: u16,
    /// Proxy link routing table ID
    pub route_table: u32,
    /// Proxy fwmark
    pub fwmark_proxy: u32,
    /// Bypass fwmark
    pub fwmark_bypass: u32,
    /// fwmark mask
    pub fwmark_mask: u32,
    /// Interface MTU
    pub mtu: u32,
    /// Log level
    pub log_level: String,
    /// eBPF bytecode file path
    pub ebpf_path: String,
    /// SOCKS5 proxy server address (e.g., "127.0.0.1:1080")
    pub proxy_addr: String,
    /// SOCKS5 auth username (empty string means no auth)
    pub proxy_username: String,
    /// SOCKS5 auth password
    pub proxy_password: String,
    /// SOCKS5 dial timeout (milliseconds)
    pub proxy_dial_timeout_ms: u64,
    /// API server configuration
    pub api_config: Option<config::ApiConfig>,
    /// Raw daefile config (for exclusion list / routing rule compilation and API queries)
    pub daefile_config: Option<config::DaefileConfig>,
    /// WAN interface names (TC attach targets for wan_egress/wan_ingress)
    pub wan_interface: Vec<String>,
    /// LAN interface names (TC attach targets for lan_ingress/lan_egress)
    pub lan_interface: Vec<String>,
    /// DNS configuration
    pub dns_config: Option<config::DnsConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tproxy_port: 15080,
            route_table: 2023,
            fwmark_proxy: 0x8000000,
            fwmark_bypass: 0x04000000,
            fwmark_mask: 0x8000000,
            mtu: 1500,
            log_level: "info".into(),
            ebpf_path: ebpf::DEFAULT_EBPF_PATH.to_string(),
            proxy_addr: "127.0.0.1:1080".into(),
            proxy_username: String::new(),
            proxy_password: String::new(),
            proxy_dial_timeout_ms: 5000,
            api_config: None,
            daefile_config: None,
            wan_interface: Vec::new(),
            lan_interface: Vec::new(),
            dns_config: None,
        }
    }
}

impl Config {
    /// Parse and validate configuration from daefile format text
    ///
    /// Parses daefile (Caddyfile-like syntax) into a normalized config structure,
    /// then performs full semantic validation. On success, the result can be used
    /// to construct a [`ControlPlane`].
    ///
    /// # Parameters
    ///
    /// * `input` — daefile format configuration text
    ///
    /// # Returns
    ///
    /// Returns a [`Config`] instance after validation, where fields are mapped from
    /// [`DaefileConfig`](config::DaefileConfig).
    ///
    /// # Errors
    ///
    /// Returns [`anyhow::Error`] if parsing or validation fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use control::Config;
    ///
    /// let daefile = r#"
    ///     global { tproxy_port: 15080; log_level: info; }
    ///     outbounds { ... }
    ///     routing { fallback: direct; }
    /// "#;
    /// let config = Config::from_daefile(daefile)?;
    /// # Ok::<_, anyhow::Error>(())
    /// ```
    pub fn from_daefile(input: &str) -> anyhow::Result<Self> {
        let daefile_config = config::parse_daefile(input)
            .map_err(|e| anyhow::anyhow!("daefile parse failed: {}", e))?;

        config::validate_config(&daefile_config)
            .map_err(|e| anyhow::anyhow!("config validation failed: {}", e))?;

        // Map DaefileConfig to Config (flat control plane structure)
        let runtime = &daefile_config.runtime;
        let ns = daefile_config.namespace.as_ref();
        let marks = daefile_config.marks.as_ref();
        let iface = daefile_config.interface.as_ref();

        // Get proxy address from the first node (Phase 1 simplification: take first socks5 node)
        let (proxy_addr, proxy_username, proxy_password, proxy_dial_timeout_ms) =
            if let Some(first_node) = daefile_config.outbounds.nodes.first() {
                (
                    first_node.address.clone(),
                    first_node.username.clone().unwrap_or_default(),
                    first_node.password.clone().unwrap_or_default(),
                    first_node.dial_timeout_ms,
                )
            } else {
                ("127.0.0.1:1080".into(), String::new(), String::new(), 5000)
            };

        let api_config = daefile_config.api.clone();
        let dns_config = daefile_config.dns.clone();

        Ok(Self {
            tproxy_port: runtime.tproxy_port,
            route_table: ns.map(|n| n.route_table).unwrap_or(2023),
            fwmark_proxy: marks.map(|m| m.proxy).unwrap_or(0x8000000),
            fwmark_bypass: marks.map(|m| m.bypass).unwrap_or(0x04000000),
            fwmark_mask: marks.map(|m| m.mask).unwrap_or(0x8000000),
            mtu: ns.map(|n| n.mtu).unwrap_or(1500),
            log_level: runtime.log_level.clone(),
            ebpf_path: ebpf::DEFAULT_EBPF_PATH.to_string(),
            proxy_addr,
            proxy_username,
            proxy_password,
            proxy_dial_timeout_ms,
            api_config,
            daefile_config: Some(daefile_config.clone()),
            wan_interface: iface.map(|i| i.wan_interface.clone()).unwrap_or_default(),
            lan_interface: iface.map(|i| i.lan_interface.clone()).unwrap_or_default(),
            dns_config,
        })
    }
}

// ============================================================================
// ControlPlane
// ============================================================================

/// Control plane main structure
///
/// Holds references to sub-modules like the eBPF loader, network namespace manager, etc.
/// Provides a unified start/stop interface.
///
/// # Lifecycle
///
/// ```text
/// new(config) -> start() -> ...running... -> stop()
/// ```
///
/// # Examples
///
/// ```no_run
/// use control::ControlPlane;
/// use control::Config;
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     let config = Config::default();
///     let mut cp = ControlPlane::new(config);
///     cp.start().await?;
///     // ... running ...
///     cp.stop().await?;
///     Ok(())
/// }
/// ```
pub struct ControlPlane {
    /// Control plane configuration
    pub config: Config,
    /// eBPF program manager (shared with background tasks via Mutex)
    pub ebpf_mgr: Arc<Mutex<ebpf::EbpfManager>>,
    /// Network namespace manager
    pub netns_mgr: netns::NetnsManager,
    /// TProxy TCP listener (runs in the proxy namespace)
    pub tproxy: Option<Arc<TproxyListener>>,
    /// TProxy UDP listener
    pub tproxy_udp: Option<Arc<UdpTproxyListener>>,
    /// JoinHandle for the TProxy child thread
    tproxy_thread: Option<std::thread::JoinHandle<()>>,
    /// Whether the control plane is running
    pub running: bool,
    /// Raw daefile config (for API queries of outbound groups/nodes/routing)
    pub daefile_config: Option<config::DaefileConfig>,
    /// Interface event monitor for dynamic WAN/LAN TC attach/detach
    iface_mgr: Option<crate::iface_mgr::InterfaceManager>,
    /// Raw daefile text content (for API config reload)
    pub daefile_content: Option<String>,
    /// Tokio task handle for the API server
    pub api_handle: Option<tokio::task::JoinHandle<()>>,
    /// Tokio task handle for the conn_state janitor (with pressure detection)
    janitor_handle: Option<tokio::task::JoinHandle<()>>,
    /// Tokio task handle for the redirect_track janitor
    redirect_track_handle: Option<tokio::task::JoinHandle<()>>,
    /// Tokio task handle for the cookie_pid_map janitor
    cookie_pid_handle: Option<tokio::task::JoinHandle<()>>,
    /// Tokio task handle for the connectivity checker
    connectivity_handle: Option<tokio::task::JoinHandle<()>>,
    /// Ringbuf consumer background thread
    ringbuf_thread: Option<std::thread::JoinHandle<()>>,
    /// Signal to stop the ringbuf thread
    ringbuf_running: Option<Arc<AtomicBool>>,
    /// Embedded eBPF bytecode (compiled into the binary).
    /// When set, `load()` uses this instead of reading from file.
    pub embedded_ebpf: Option<&'static [u8]>,
    /// Daeparam to pass to the eBPF program before loading.
    pub ebpf_param: Option<crate::ebpf::Daeparam>,
    /// Domain routing tracker for DNS-driven domain_routing_map updates.
    pub domain_routing: Option<crate::domain_routing::DomainRoutingTracker>,
    /// DNS manager (handles DNS query routing, upstream forwarding, caching)
    pub dns_manager: Option<crate::dns::DnsManager>,
    /// UDP connection state tracker (for UDP flow cleanup in janitor)
    udp_tracker: Option<Arc<Mutex<crate::udp_tracker::UdpConnStateTracker>>>,
}

impl ControlPlane {
    /// Convenience accessor for the locked eBPF manager.
    /// Panics if the mutex is poisoned.
    fn ebpf(&self) -> std::sync::MutexGuard<'_, ebpf::EbpfManager> {
        self.ebpf_mgr.lock().expect("ebpf_mgr lock poisoned")
    }

    /// Create a new control plane instance
    ///
    /// Initializes all sub-module managers, but does not start any services.
    /// Call [`start()`](ControlPlane::start) to start.
    ///
    /// # Parameters
    ///
    /// * `config` — Control plane configuration
    pub fn new(config: Config) -> Self {
        let ebpf_mgr = Arc::new(Mutex::new(ebpf::EbpfManager::new_with_path(
            "dae0",
            &config.ebpf_path,
        )));
        let netns_mgr = netns::NetnsManager::new(&config);
        let daefile_config = config.daefile_config.clone();

        Self {
            config,
            ebpf_mgr,
            netns_mgr,
            tproxy: None,
            tproxy_udp: None,
            tproxy_thread: None,
            running: false,
            daefile_config,
            daefile_content: None,
            api_handle: None,
            janitor_handle: None,
            redirect_track_handle: None,
            cookie_pid_handle: None,
            connectivity_handle: None,
            domain_routing: None,
            dns_manager: None,
            udp_tracker: None,
            iface_mgr: None,
            ringbuf_thread: None,
            ringbuf_running: None,
            embedded_ebpf: None,
            ebpf_param: None,
        }
    }

    /// Start the control plane
    ///
    /// Executes the following startup sequence in order:
    ///
    /// 1. **Create network namespace** — Call [`NetnsManager::create()`]
    ///    - Create anonymous network namespace
    ///    - Create and configure veth pair
    ///    - Configure policy routing
    /// 2. **Load eBPF program** — Call [`EbpfManager::load()`]
    ///    - Load eBPF object from bytecode file
    /// 3. **Attach TC programs** — Call [`EbpfManager::attach_tc()`]
    ///    - Attach ingress/egress programs to the host-side veth interface
    /// 3.5. **Write eBPF maps** — Write exclusion list and routing rules
    ///    - Compile process exclusion list from daefile config
    ///    - Compile routing rules from daefile config
    /// 4. **Start TProxy listener** — Start TProxy inside the proxy namespace
    ///    - Create SOCKS5 dialer
    ///    - Enter proxy namespace in a separate thread and start TProxy
    ///
    /// # Errors
    ///
    /// If any step fails, the error is returned and subsequent steps are not executed.
    /// The caller should decide whether to call [`stop()`](ControlPlane::stop) for cleanup based on the error.
    pub async fn start(&mut self) -> Result<()> {
        info!("Control plane starting...");

        // ---- Step 1: Create network namespace ----
        info!("Step 1/5: Creating network namespace and veth pair");
        self.netns_mgr.create().await.map_err(|e| {
            error!("Failed to create network namespace: {}", e);
            e
        })?;

        // ---- Step 1.25: 诊断：记录 link pair 类型 ----
        info!(
            "Netns create completed, use_netkit={}, host_if={}, peer_if={}",
            self.netns_mgr.is_netkit(),
            self.netns_mgr.host_if(),
            self.netns_mgr.peer_if(),
        );

        // ---- Step 1.5: Set eBPF PARAM with netns information ----
        // Now that netns is created, we can set dae0_ifindex, dae_netns_id, dae0peer_mac
        if let Some(ref mut param) = self.ebpf_param {
            // Get dae0 ifindex in host NS
            param.dae0_ifindex = self
                .netns_mgr
                .get_host_ifindex()
                .map_err(|e| anyhow::anyhow!("获取 dae0 ifindex 失败: {}", e))?;
            info!("Set PARAM.dae0_ifindex = {}", param.dae0_ifindex);

            // Get proxy netns inode (dae_netns_id)
            param.dae_netns_id = self
                .netns_mgr
                .get_proxy_netns_inode()
                .map_err(|e| anyhow::anyhow!("获取代理命名空间 inode 失败: {}", e))?;
            info!("Set PARAM.dae_netns_id = {}", param.dae_netns_id);

            // Get dae0peer MAC address
            param.dae0peer_mac = self
                .netns_mgr
                .get_peer_mac()
                .map_err(|e| anyhow::anyhow!("获取 dae0peer MAC 地址失败: {}", e))?;
            info!(
                "Set PARAM.dae0peer_mac = {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                param.dae0peer_mac[0],
                param.dae0peer_mac[1],
                param.dae0peer_mac[2],
                param.dae0peer_mac[3],
                param.dae0peer_mac[4],
                param.dae0peer_mac[5]
            );

            // Set tproxy_port
            param.tproxy_port = self.config.tproxy_port as u32;
            info!("Set PARAM.tproxy_port = {}", param.tproxy_port);

            // Set control_plane_pid
            param.control_plane_pid = std::process::id();
            info!("Set PARAM.control_plane_pid = {}", param.control_plane_pid);

            // Set use_redirect_peer based on kernel support
            param.use_redirect_peer = crate::ebpf::probe_redirect_peer();
            info!("Set PARAM.use_redirect_peer = {}", param.use_redirect_peer);
        }

        // ---- Step 1.75: Initialize flip bit for TC handle ----
        // 检查是否有 pinned maps 来判断是否是热重载/重启恢复
        // 如果有 pinned maps，说明之前有过运行实例，需要翻转 flip 位
        // 以避免与旧 filter 的 handle 冲突
        let flip = if crate::ebpf::EbpfManager::pinned_maps_exist(crate::ebpf::BPFFS_PATH) {
            info!("Pinned maps detected — setting flip=1 for TC handle rotation");
            1u32
        } else {
            0u32
        };
        self.ebpf().set_flip(flip);

        // ---- Step 2: Load eBPF program ----
        info!("Step 2/5: Loading eBPF program");

        // Set PARAM global variable before loading (if configured)
        if let Some(param) = self.ebpf_param {
            self.ebpf().set_param(&param);
            info!("eBPF PARAM configured: tproxy_port={}", param.tproxy_port);
        }

        // 设置 eBPF map pinning 路径，使 maps 在 load 后自动 pin 到 bpffs
        // 这样 dae-rs 重启后连接状态可以持久化
        self.ebpf()
            .set_pin_path(crate::ebpf::BPFFS_PATH.to_string());
        info!("eBPF map pinning enabled: {}", crate::ebpf::BPFFS_PATH);

        if let Some(ebpf_bytes) = self.embedded_ebpf {
            info!("Using embedded eBPF bytecode ({} bytes)", ebpf_bytes.len());
            self.ebpf().load_from_bytes(ebpf_bytes).map_err(|e| {
                error!("Failed to load embedded eBPF program: {}", e);
                e
            })?;
        } else {
            self.ebpf().load().map_err(|e| {
                error!("Failed to load eBPF program: {}", e);
                e
            })?;
        }

        // ---- Step 2.5: Initialize outbound_connectivity_map ----
        // BPF ARRAY maps are zero-initialized, but wan_outbound_is_alive()
        // treats 0 as dead. Without this, ALL proxied traffic is SHOT until
        // the first connectivity check runs (~30s after startup).
        if let Err(e) = self.ebpf().init_outbound_connectivity_map() {
            warn!("Failed to init outbound_connectivity_map: {}", e);
        }

        // ---- Step 2.6: Initialize InterfaceManager for dynamic WAN/LAN management ----
        // Replaces the static WAN/LAN TC attachment loop with a dynamic monitor
        // that scans /sys/class/net/ and automatically binds/unbinds eBPF programs
        // as interfaces appear/disappear (lazy-bind/rebind).
        let use_iface_mgr =
            !self.config.wan_interface.is_empty() || !self.config.lan_interface.is_empty();
        if use_iface_mgr {
            info!("Step 2.6/5: Initializing InterfaceManager for WAN/LAN interfaces");
            let mut iface_mgr = crate::iface_mgr::InterfaceManager::new();

            // Register WAN interface patterns with bind/unbind callbacks
            for pattern in &self.config.wan_interface {
                let ebpf_bind = self.ebpf_mgr.clone();
                let ebpf_unbind = self.ebpf_mgr.clone();
                iface_mgr
                    .register(
                        pattern,
                        Arc::new(move |ifname| {
                            let mut mgr = ebpf_bind.lock().expect("ebpf lock");
                            mgr.attach_wan(ifname)?;
                            configure_kernel_if(ifname);
                            info!("InterfaceManager: WAN TC attached to {}", ifname);
                            Ok(())
                        }),
                        Some(Arc::new(move |ifname| {
                            let mut mgr = ebpf_unbind.lock().expect("ebpf lock");
                            mgr.detach_by_iface(ifname)?;
                            info!("InterfaceManager: WAN TC detached from {}", ifname);
                            Ok(())
                        })),
                    )
                    .await?;
            }

            // Register LAN interface patterns with bind/unbind callbacks
            for pattern in &self.config.lan_interface {
                let ebpf_bind = self.ebpf_mgr.clone();
                let ebpf_unbind = self.ebpf_mgr.clone();
                iface_mgr
                    .register(
                        pattern,
                        Arc::new(move |ifname| {
                            let mut mgr = ebpf_bind.lock().expect("ebpf lock");
                            mgr.attach_lan(ifname)?;
                            configure_kernel_if(ifname);
                            info!("InterfaceManager: LAN TC attached to {}", ifname);
                            Ok(())
                        }),
                        Some(Arc::new(move |ifname| {
                            let mut mgr = ebpf_unbind.lock().expect("ebpf lock");
                            mgr.detach_by_iface(ifname)?;
                            info!("InterfaceManager: LAN TC detached from {}", ifname);
                            Ok(())
                        })),
                    )
                    .await?;
            }

            // Start the background polling task
            iface_mgr.start().await?;
            self.iface_mgr = Some(iface_mgr);
            info!(
                "InterfaceManager started with {} WAN + {} LAN patterns",
                self.config.wan_interface.len(),
                self.config.lan_interface.len(),
            );
        } else {
            info!("No WAN/LAN interfaces configured — InterfaceManager not started");
        }

        // ---- Step 3: Attach TC programs ----
        // Now that the topology is fixed (dae0 in host NS, dae0peer in proxy NS),
        // we must attach programs in the correct namespace:
        //   - dae0_ingress → host NS (dae0 is there)
        //   - dae0peer_ingress → proxy NS (dae0peer is there)
        //   - wan/lan programs → host NS (physical interfaces are there;
        //     handled dynamically by InterfaceManager if configured)
        //   - cgroup programs → proxy NS (sock_create/release etc.)
        info!("Step 3/5: Attaching TC programs and configuring kernel");
        // Attach dae0_ingress in host NS
        self.ebpf().attach_dae0("dae0").map_err(|e| {
            error!("Failed to attach dae0_ingress TC: {}", e);
            e
        })?;
        configure_kernel_if("dae0");
        // Attach dae0peer_ingress in proxy NS
        {
            self.netns_mgr.join_proxy_ns()?;
            self.ebpf().attach_dae0peer("dae0peer").map_err(|e| {
                error!("Failed to attach dae0peer_ingress TC: {}", e);
                e
            })?;
            configure_kernel_if("dae0peer");
            self.netns_mgr.join_host_ns()?;
        }
        // If InterfaceManager is active, WAN/LAN TC attachment is handled dynamically
        // by the background polling task (see Step 2.6 above).
        // The static loops below are only used when InterfaceManager is NOT available.
        if self.iface_mgr.is_none() {
            // Static WAN/LAN TC attachment (legacy path — no dynamic interface monitor)
            if self.config.wan_interface.is_empty() {
                warn!("No WAN interfaces configured — eBPF will NOT intercept outbound traffic. \
                       Set wan_interface in the config (e.g. `interface {{ wan_interface: eth0 }}`)");
            }
            for wan_if in &self.config.wan_interface {
                info!("Attaching WAN eBPF TC programs to {}", wan_if);
                self.ebpf().attach_wan(wan_if)?;
                configure_kernel_if(wan_if);
                info!("WAN TC attached to {}", wan_if);
            }
            if self.config.lan_interface.is_empty() {
                info!("No LAN interfaces configured — LAN ingress interception disabled");
            }
            for lan_if in &self.config.lan_interface {
                info!("Attaching LAN eBPF TC programs to {}", lan_if);
                self.ebpf().attach_lan(lan_if)?;
                configure_kernel_if(lan_if);
                info!("LAN TC attached to {}", lan_if);
            }
        } else {
            info!("WAN/LAN TC attachment delegated to InterfaceManager (dynamic)");
        }

        // ---- Step 3.5: Write eBPF maps (exclusion list + rules) ----
        info!("Step 3.5/5: Writing eBPF maps (exclusion list + rules)");

        // 3.5a. Write excluded process names (from daefile config)
        if let Some(ref dc) = self.daefile_config {
            if let Some(ref pe) = dc.process_exclusion {
                if pe.enabled {
                    // Write comm exclusion list
                    if !pe.r#match.comm.is_empty() {
                        let comm_hashes: Vec<u32> = pe
                            .r#match
                            .comm
                            .iter()
                            .map(|c| crate::ebpf::hash_comm(c))
                            .collect();
                        self.ebpf().write_excluded_comm(&comm_hashes)?;
                        info!(
                            "Wrote {} excluded comm hashes to eBPF map",
                            comm_hashes.len()
                        );
                    }
                    // Write pid exclusion list
                    if !pe.r#match.pid.is_empty() {
                        self.ebpf().write_excluded_pids(&pe.r#match.pid)?;
                        info!("Wrote {} excluded PIDs to eBPF map", pe.r#match.pid.len());
                    }
                    // Write tgid exclusion list (shares the same map as pid)
                    if !pe.r#match.tgid.is_empty() {
                        self.ebpf().write_excluded_pids(&pe.r#match.tgid)?;
                        info!("Wrote {} excluded TGIDs to eBPF map", pe.r#match.tgid.len());
                    }
                }
            }
        }

        // 3.5b. Compile routing rules into MatchSet and write to eBPF maps
        if let Some(ref dc) = self.daefile_config {
            if !dc.routing.rules.is_empty() {
                // Collect proxy server IPs from all outbound nodes for auto-direct rules.
                // This prevents traffic destined for proxy servers from being re-proxied (loop prevention).
                let proxy_server_ips = collect_proxy_server_ips(&self.config, &dc.outbounds);
                if !proxy_server_ips.is_empty() {
                    info!(
                        "Collected {} proxy server IP(s) for auto-direct rules: {:?}",
                        proxy_server_ips.len(),
                        proxy_server_ips
                    );
                }
                let compiled =
                    routing::compile_rules(&dc.routing, &dc.outbounds, &proxy_server_ips)
                        .context("Failed to compile routing rules")?;

                // Write MatchSet entries to routing_map
                if !compiled.match_sets.is_empty() {
                    self.ebpf().write_routing_rules(&compiled.match_sets)?;
                    info!(
                        "Wrote {} MatchSet entries to routing_map",
                        compiled.match_sets.len()
                    );
                }

                // Write LPM trie data to inner LPM trie maps via lpm_array_map
                // Each trie (at index trie_idx) gets its CIDR entries written to
                // the inner LPM_TRIE map at that position in the ARRAY_OF_MAPS.
                {
                    let mut all_cidr_entries: Vec<(u32, CidrEntry)> = Vec::new();
                    for (trie_idx, cidrs) in compiled.lpm_tries.iter().enumerate() {
                        let entries = crate::routing::cidrs_to_cidr_entries(cidrs);
                        for (_, entry) in entries {
                            all_cidr_entries.push((trie_idx as u32, entry));
                        }
                    }
                    if !all_cidr_entries.is_empty() {
                        self.ebpf().write_cidr_table(&all_cidr_entries)?;
                        info!(
                            "Wrote {} CIDR entries across {} LPM tries",
                            all_cidr_entries.len(),
                            compiled.lpm_tries.len()
                        );
                    }
                }

                // Set up domain routing tracker
                if !compiled.domain_sets.is_empty() {
                    self.domain_routing = Some(crate::domain_routing::DomainRoutingTracker::new(
                        std::sync::Arc::new(compiled.domain_sets),
                    ));
                    info!(
                        "Domain routing tracker initialized with {} domain sets",
                        self.domain_routing.as_ref().unwrap().len(),
                    );
                }
            }
        }

        // ---- Step 3.7: Attach cgroup programs in proxy NS ----
        info!("Step 3.7/5: Attaching cgroup programs in proxy namespace");
        {
            // Switch to proxy NS to attach cgroup programs
            self.netns_mgr.join_proxy_ns()?;

            // Open cgroup fd for the proxy namespace
            // Use /sys/fs/cgroup as the cgroup root
            let cgroup_fd = unsafe {
                libc::open(
                    b"/sys/fs/cgroup\0".as_ptr() as *const libc::c_char,
                    libc::O_RDONLY | libc::O_DIRECTORY,
                )
            };

            if cgroup_fd >= 0 {
                match self.ebpf().attach_cgroup(cgroup_fd) {
                    Ok(()) => {
                        info!("cgroup programs attached successfully");
                    }
                    Err(e) => {
                        warn!("Failed to attach cgroup programs: {}", e);
                    }
                }
                unsafe {
                    libc::close(cgroup_fd);
                }
            } else {
                warn!(
                    "Failed to open /sys/fs/cgroup: {}",
                    std::io::Error::last_os_error()
                );
            }

            // Switch back to host NS
            self.netns_mgr.join_host_ns()?;
        }

        // ---- Step 4: Start TProxy listener ----
        info!("Step 4/5: Starting TProxy listener in proxy namespace");
        self.start_tproxy().await?;

        // ---- Step 4.5: Start DNS manager ----
        if let Some(ref dns_cfg) = self.config.dns_config {
            info!("Step 4.5/5: Starting DNS manager");
            let mut dns_mgr = crate::dns::DnsManager::new(dns_cfg.clone());
            if let Err(e) = dns_mgr.init_upstreams() {
                warn!("DNS upstream initialization failed (non-fatal): {}", e);
            }
            if let Err(e) = dns_mgr.start().await {
                warn!("DNS manager start failed (non-fatal): {}", e);
            } else {
                info!("DNS manager started successfully");
                self.dns_manager = Some(dns_mgr);
            }
        }

        // ---- Step 5: Start background tasks ----
        info!("Step 5/5: Starting background tasks");
        // Ringbuf event consumer (get fd first to release the lock before assigning fields)
        let ringbuf_fd = self.ebpf().event_ringbuf_fd().ok();
        if let Some(fd) = ringbuf_fd {
            let (handle, running) = ebpf::EbpfManager::spawn_ringbuf_consumer(fd);
            self.ringbuf_thread = Some(handle);
            self.ringbuf_running = Some(running);
        } else {
            warn!("Failed to get ringbuf fd, ringbuf consumer not started");
        }
        // Conn_state janitor (with pressure detection)
        self.janitor_handle = Some(Self::spawn_conn_state_janitor(
            self.ebpf_mgr.clone(),
            None, // UDP tracker — will be wired up when available
        ));

        // Redirect track janitor (30s interval, 5min TTL)
        self.redirect_track_handle =
            Some(Self::spawn_redirect_track_janitor(self.ebpf_mgr.clone()));

        // Cookie PID map janitor (60s interval, 5min TTL)
        self.cookie_pid_handle = Some(Self::spawn_cookie_pid_map_janitor(self.ebpf_mgr.clone()));

        // Connectivity checker (proxies health)
        let proxy_addr: std::net::SocketAddr =
            self.config.proxy_addr.parse().expect("valid proxy address");
        self.connectivity_handle = Some(Self::start_connectivity_checker(
            self.ebpf_mgr.clone(),
            proxy_addr,
            0,
        ));

        self.running = true;
        info!("Control plane started successfully");

        // Log network diagnostics after startup
        match std::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output()
        {
            Ok(o) => info!(
                "Default route: {}",
                String::from_utf8_lossy(&o.stdout).trim()
            ),
            Err(_) => warn!("Could not query default route"),
        }
        match std::process::Command::new("ip").args(["link"]).output() {
            Ok(o) => info!("Links:\n{}", String::from_utf8_lossy(&o.stdout)),
            Err(_) => {}
        }

        Ok(())
    }

    /// Start the TProxy listener in the proxy namespace
    ///
    /// Creates a SOCKS5 dialer and TProxy listener in the HOST namespace.
    /// Policy routing ensures marked packets from the proxy namespace are
    /// delivered to the local TProxy socket via `local default dev lo`.
    ///
    /// # Flow
    ///
    /// 1. Create `Socks5Dialer` from config
    /// 2. Create `TproxyListener` (IPv6 dual-stack) in host namespace
    /// 3. Add host namespace policy routing (`ip rule/route`)
    /// 4. Bind and start the TProxy accept loop
    ///
    /// # Errors
    ///
    /// * Returns a parse error if the proxy address format is invalid
    /// * Returns an error if the proxy namespace has not been created
    /// * Returns a bind error if the port is already in use
    async fn start_tproxy(&mut self) -> Result<()> {
        // ---- Create SOCKS5 dialer ----
        let proxy_addr: SocketAddr = self.config.proxy_addr.parse().map_err(|e| {
            anyhow::anyhow!("Invalid proxy address '{}': {}", self.config.proxy_addr, e)
        })?;

        // ---- Create TProxy listener in DAENS (proxy namespace) ----
        // eBPF 数据流：
        // 1. WAN egress TC 拦截 SYN 包
        // 2. 重定向到 dae0 → dae0peer（进入 daens）
        // 3. dae0peer_ingress TC：设置 skb->mark = TPROXY_MARK
        // 4. daens 中的策略路由：fwmark → table 2023 → local default dev lo
        // 5. TProxy socket（在 daens 中）接受连接
        // 6. TProxy 通过 dae0peer → dae0 转发到宿主 NS → 上游 SOCKS5 代理
        let listen_addr: SocketAddr = format!("[::]:{}", self.config.tproxy_port)
            .parse()
            .map_err(|e| {
                anyhow::anyhow!(
                    "Invalid TProxy listen address (port {}): {}",
                    self.config.tproxy_port,
                    e
                )
            })?;

        let socket_mark = 0x100u32;
        let dialer_tcp = Socks5Dialer::new_with_mark(
            proxy_addr,
            &self.config.proxy_username,
            &self.config.proxy_password,
            self.config.proxy_dial_timeout_ms,
            socket_mark,
        );
        let dialer_udp = Socks5Dialer::new_with_mark(
            proxy_addr,
            &self.config.proxy_username,
            &self.config.proxy_password,
            self.config.proxy_dial_timeout_ms,
            socket_mark,
        );

        let tproxy_tcp = Arc::new(TproxyListener::new(listen_addr, dialer_tcp));
        let tproxy_udp = Arc::new(UdpTproxyListener::new(listen_addr, dialer_udp));

        // ---- Add host namespace policy routing ----
        // 宿主 NS 策略路由：标记包 → local default dev lo → TProxy socket
        // （用于从 daens 通过 dae0peer → dae0 进入宿主 NS 的标记包）
        self.netns_mgr
            .add_host_policy_routing()
            .await
            .context("Failed to add host namespace policy routing")?;

        info!(
            listen_addr = %listen_addr,
            "Launching TProxy in DAENS (proxy namespace)"
        );

        // ---- Start TProxy INSIDE daens ----
        // 原版 dae 在 daens 中启动 TProxy listener。
        // 这样 eBPF 路由后的标记包通过 daens 的策略路由直接投递到 TProxy socket。
        // TProxy 的上游连接（到 SOCKS5 代理）使用 SO_MARK=0x100，
        // 被 eBPF 的 pid_is_control_plane() 识别并放行。
        let proxy_ns_fd = self
            .netns_mgr
            .get_proxy_ns_fd()
            .ok_or_else(|| anyhow::anyhow!("Proxy namespace not created"))?;

        let tproxy_tcp_clone = tproxy_tcp.clone();
        let tproxy_udp_clone = tproxy_udp.clone();
        let ebpf_mgr_clone = self.ebpf_mgr.clone();
        use std::os::unix::io::BorrowedFd;
        let thread_handle = std::thread::spawn(move || {
            // ---- 进入 daens ----
            // TProxy 必须运行在 daens 中，因为 eBPF 路由后的标记包
            // 通过 daens 的策略路由投递到本地 lo。
            let borrowed_fd = unsafe { BorrowedFd::borrow_raw(proxy_ns_fd) };
            if let Err(e) = nix::sched::setns(&borrowed_fd, nix::sched::CloneFlags::CLONE_NEWNET) {
                error!("Failed to enter daens for TProxy listener: {}", e);
                return;
            }
            info!("Entered daens for TProxy listener");

            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    error!("Failed to create tokio runtime for TProxy: {}", e);
                    return;
                }
            };

            let result = rt.block_on(async {
                // Bind the dual-stack TCP listener (in daens)
                info!(
                    "Binding TProxy TCP listener on {} in daens",
                    tproxy_tcp_clone.listen_addr()
                );
                let listener_tcp = match tproxy_tcp_clone.bind().await {
                    Ok(l) => l,
                    Err(e) => {
                        error!("Failed to bind TProxy TCP socket: {}", e);
                        return Err(e);
                    }
                };

                // ---- Populate listen_socket_map for bpf_sk_assign ----
                // Insert the TCP listener socket FD into the SOCKMAP so that
                // dae0peer_ingress can use assign_listener() via bpf_sk_assign.
                // Key 0 = tcp4, key 2 = tcp6. The dual-stack socket handles both.
                {
                    use std::os::unix::io::AsRawFd;
                    let raw_fd = listener_tcp.as_raw_fd();
                    let mut mgr = ebpf_mgr_clone.lock().unwrap();
                    // Key 0 = tcp4 (dual-stack covers both v4 and v6)
                    if let Err(e) = mgr.update_listen_socket_map(0, raw_fd) {
                        error!("Failed to update listen_socket_map for tcp4: {}", e);
                    }
                    // Key 2 = tcp6 (same socket, also for tcp6 traffic)
                    if let Err(e) = mgr.update_listen_socket_map(2, raw_fd) {
                        error!("Failed to update listen_socket_map for tcp6: {}", e);
                    }
                }

                info!(
                    "TProxy TCP listener starting on {} in daens",
                    tproxy_tcp_clone.listen_addr()
                );

                // Run TCP and UDP listeners concurrently
                let (tcp_result, udp_result) = tokio::join!(
                    tproxy_tcp_clone.serve(listener_tcp),
                    tproxy_udp_clone.start(Some(ebpf_mgr_clone.clone()))
                );

                if let Err(e) = tcp_result {
                    error!("TProxy TCP listener error: {}", e);
                }
                if let Err(e) = udp_result {
                    error!("TProxy UDP listener error: {}", e);
                }

                Ok(())
            });

            match result {
                Ok(_) => {
                    info!("TProxy listeners exited normally");
                }
                Err(e) => {
                    error!("TProxy listeners exited with error: {}", e);
                }
            }
        });

        self.tproxy = Some(tproxy_tcp);
        self.tproxy_udp = Some(tproxy_udp);
        self.tproxy_thread = Some(thread_handle);

        info!("TProxy listener launching in background thread (in daens)");
        Ok(())
    }

    // ========================================================================
    // Janitor: Connection State + Pressure Detection
    // ========================================================================

    /// Spawn the conn_state janitor with dynamic interval and pressure detection.
    ///
    /// Mirrors dae's `controlPlaneDatapathJanitor`:
    /// - Steady-state interval: 5s
    /// - Pressure mode interval: 1s (when map usage > 70%)
    /// - Exits pressure mode when usage < 50% for 3 consecutive rounds
    /// - Also cleans up expired entries from the eBPF map
    ///
    /// If `udp_tracker` is provided, expired UDP flows from the tracker are
    /// also deleted from conn_state_map.
    pub fn spawn_conn_state_janitor(
        ebpf_mgr: Arc<Mutex<crate::ebpf::EbpfManager>>,
        udp_tracker: Option<Arc<Mutex<crate::udp_tracker::UdpConnStateTracker>>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            info!("ConnState janitor started with pressure detection");

            use crate::ebpf::{PRESSURE_ENTER_USAGE, PRESSURE_EXIT_ROUNDS, PRESSURE_EXIT_USAGE};

            let mut pressure_rounds: u32 = 0;
            let mut in_pressure = false;

            loop {
                let interval = if in_pressure {
                    std::time::Duration::from_secs(1) // 压力模式 1s
                } else {
                    std::time::Duration::from_secs(5) // 稳态模式 5s
                };
                tokio::time::sleep(interval).await;

                let now_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;

                // ---- Step 1: Clean up UDP tracker expired entries ----
                if let Some(ref tracker) = udp_tracker {
                    if let Ok(mut tracker_guard) = tracker.lock() {
                        let expired = tracker_guard.cleanup_expired();
                        if !expired.is_empty() {
                            // Delete expired UDP tracker entries from conn_state_map
                            if let Ok(mut mgr) = ebpf_mgr.lock() {
                                for key in &expired {
                                    let _ = mgr.delete_conntrack(key);
                                }
                                debug!(
                                    "Janitor: deleted {} expired entries from UDP tracker",
                                    expired.len()
                                );
                            }
                        }
                    }
                }

                // ---- Step 2: Scan conn_state_map for expired entries ----
                let mut mgr = match ebpf_mgr.lock() {
                    Ok(m) => m,
                    Err(e) => {
                        warn!("Janitor lock error: {}", e);
                        continue;
                    }
                };

                match mgr.janitor_scan_conn_state(now_ns) {
                    Ok((deleted, remaining)) => {
                        if deleted > 0 {
                            info!(
                                "Janitor conn_state: deleted {} expired, {} remaining",
                                deleted, remaining
                            );
                        }

                        // ---- Step 3: Pressure detection ----
                        if let Ok(usage) = mgr.conn_state_map_usage() {
                            if in_pressure {
                                // Check if we should exit pressure mode
                                if usage < PRESSURE_EXIT_USAGE {
                                    pressure_rounds += 1;
                                    if pressure_rounds >= PRESSURE_EXIT_ROUNDS {
                                        in_pressure = false;
                                        info!(
                                            "conn_state_map pressure exited (usage={:.1}%, {} rounds below threshold)",
                                            usage * 100.0,
                                            pressure_rounds
                                        );
                                    }
                                } else {
                                    pressure_rounds = 0; // 高于阈值，重置计数
                                }
                            } else {
                                // Check if we should enter pressure mode
                                if usage > PRESSURE_ENTER_USAGE {
                                    in_pressure = true;
                                    pressure_rounds = 0;
                                    info!(
                                        "conn_state_map pressure entered (usage={:.1}%, remaining={})",
                                        usage * 100.0,
                                        remaining
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Janitor conn_state scan failed: {}", e);
                    }
                }
            }
        })
    }

    /// Spawn the redirect_track janitor.
    ///
    /// Mirrors dae's `redirectTrackJanitor`:
    /// - Steady-state interval: 30s
    /// - redirect_track TTL: 5 minutes
    /// - Capacity: 65536 entries (HASH map, auto-overwrite when full)
    pub fn spawn_redirect_track_janitor(
        ebpf_mgr: Arc<Mutex<crate::ebpf::EbpfManager>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            info!("RedirectTrack janitor started (interval: 30s)");

            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;

                let now_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;

                if let Ok(mut mgr) = ebpf_mgr.lock() {
                    if let Err(e) = mgr.janitor_scan_redirect_track(now_ns) {
                        warn!("RedirectTrack janitor error: {}", e);
                    }
                }
            }
        })
    }

    /// Spawn the cookie_pid_map janitor.
    ///
    /// Cleans up stale cookie→pid/pname mappings that may accumulate
    /// if `cgroup/sock_release` doesn't fire for some sockets.
    /// TTL: 5 minutes based on `last_seen_ns` in the ProcInfo value.
    pub fn spawn_cookie_pid_map_janitor(
        ebpf_mgr: Arc<Mutex<crate::ebpf::EbpfManager>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            info!("CookiePidMap janitor started (interval: 60s)");

            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;

                let now_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;

                if let Ok(mut mgr) = ebpf_mgr.lock() {
                    if let Err(e) = mgr.janitor_scan_cookie_pid_map(now_ns) {
                        warn!("CookiePidMap janitor error: {}", e);
                    }
                }
            }
        })
    }

    /// Start the connectivity checker in a background tokio task.
    ///
    /// Periodically probes each outbound for liveness and updates the eBPF
    /// `outbound_connectivity_map` so the kernel program can make routing decisions.
    ///
    /// Key format: `outbound_id * 6 + domain * 2 + ipversion`
    /// - domain: 0=TCP, 1=DNS UDP, 2=data UDP
    /// - ipversion: 0=IPv4, 1=IPv6
    pub fn start_connectivity_checker(
        ebpf_mgr: Arc<Mutex<crate::ebpf::EbpfManager>>,
        proxy_addr: std::net::SocketAddr,
        outbound_id: u8,
    ) -> tokio::task::JoinHandle<()> {
        let interval_secs = 30; // Check every 30 seconds

        tokio::spawn(async move {
            info!(
                "Connectivity checker started (interval: {}s)",
                interval_secs
            );

            loop {
                tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;

                // TCP health check: try marked (SO_MARK=0x100) first, then plain
                let marked_result = connect_with_mark(&proxy_addr, 0x100, 5).await;
                let plain_result = tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    tokio::net::TcpStream::connect(&proxy_addr),
                )
                .await;

                // Log diagnostics
                if let Err(ref e) = marked_result {
                    info!(
                        "marked(0x100) connect to {} failed: {:?} (expected if eBPF is working)",
                        proxy_addr, e
                    );
                }
                if let Ok(Ok(_)) = &plain_result {
                    info!(
                        "plain connect to {}: OK (proxy reachable). \
                         Note: eBPF interception is not tested here because \
                         the connectivity checker runs in the same PID as the \
                         control plane and gets skipped by pid_is_control_plane(). \
                         Actual app traffic will be intercepted based on WAN TC \
                         attachment and routing rules.",
                        proxy_addr
                    );
                }
                if let Ok(Err(e)) = &plain_result {
                    info!("plain connect to {} err: {:?}", proxy_addr, e.kind());
                }
                if let Err(_) = &plain_result {
                    info!(
                        "plain connect to {}: timed out (network unreachable?)",
                        proxy_addr
                    );
                }

                let tcp_alive = marked_result.is_ok()
                    || plain_result
                        .as_ref()
                        .ok()
                        .and_then(|r| r.as_ref().ok())
                        .is_some();

                let mut mgr = ebpf_mgr.lock().expect("connectivity lock");

                // Update TCP-IPv4 (outbound=0, domain=TCP, ipv4)
                // Assume outbound_id 0 = CONTROL_PLANE_ROUTING for the proxy group

                let _ = mgr.update_outbound_connectivity(
                    outbound_id,
                    0, // domain: 0=TCP
                    false,
                    false, // ipv: 0=IPv4
                    tcp_alive,
                );
                let _ = mgr.update_outbound_connectivity(
                    outbound_id,
                    0, // domain: 0=TCP
                    false,
                    true, // ipv: 1=IPv6
                    tcp_alive,
                );

                // For DNS and data UDP, we use the same TCP health as a proxy
                // In a full implementation, actual UDP probing would be done.
                let _ = mgr.update_outbound_connectivity(
                    outbound_id,
                    1, // domain: 1=DNS UDP
                    false,
                    false, // ipv: 0=IPv4
                    tcp_alive,
                );
                let _ = mgr.update_outbound_connectivity(
                    outbound_id,
                    2, // domain: 2=data UDP
                    false,
                    false, // ipv: 0=IPv4
                    tcp_alive,
                );

                debug!(
                    "Connectivity: tcp={}, dns={}",
                    if tcp_alive { "up" } else { "down" },
                    if tcp_alive { "up" } else { "down" },
                );
            }
        })
    }

    /// Create and start the REST API server
    ///
    /// Uses Axum to start an HTTP API service on the current tokio runtime.
    /// All endpoints are protected by Bearer Token authentication.
    ///
    /// # Parameters
    ///
    /// * `control` — Arc reference to the control plane (for accessing shared state in handlers)
    /// * `api_config` — API configuration (listen address, token, TLS, etc.)
    ///
    /// # Returns
    ///
    /// Returns `tokio::task::JoinHandle<()>`, which can be used to wait for server exit or cancel the task.
    ///
    /// # Errors
    ///
    /// * Returns an IO error if port binding fails
    /// * Returns an error if the listen address format is invalid
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use control::ControlPlane;
    /// use std::sync::Arc;
    /// use tokio::sync::RwLock;
    ///
    /// # async fn example() {
    /// let mut cp = ControlPlane::new(Default::default());
    /// let cp = Arc::new(RwLock::new(cp));
    ///
    /// let api_config = control::config::ApiConfig {
    ///     enabled: true,
    ///     listen: "127.0.0.1:9090".into(),
    ///     tls: false,
    ///     cert: None,
    ///     key: None,
    ///     token: "my-secret-token".into(),
    /// };
    ///
    /// if let Ok(handle) = ControlPlane::start_api(cp.clone(), api_config).await {
    ///     // API server runs in the background
    ///     // handle.abort() can stop the server
    /// }
    /// # }
    /// ```
    pub async fn start_api(
        control: Arc<RwLock<ControlPlane>>,
        api_config: config::ApiConfig,
    ) -> Result<tokio::task::JoinHandle<()>> {
        use crate::api::{ApiServer, ApiState};

        info!(
            listen = %api_config.listen,
            tls = api_config.tls,
            "Starting REST API server"
        );

        let state = ApiState {
            control,
            config: api_config,
            start_time: std::time::Instant::now(),
        };

        let server = ApiServer::new(state);
        let handle = server.start().await?;

        info!("REST API server started successfully");
        Ok(handle)
    }

    /// Stop the control plane
    ///
    /// Executes the cleanup sequence in reverse order:
    ///
    /// 1. **Stop TProxy listener** — Send stop signal, wait for thread exit
    /// 2. **Detach TC programs** — Call [`EbpfManager::detach_tc()`]
    /// 3. **Unload eBPF program** — Call [`EbpfManager::unload()`]
    /// 4. **Destroy network namespace** — Call [`NetnsManager::destroy()`]
    ///
    /// # Error handling strategy
    ///
    /// Even if intermediate steps fail, subsequent cleanup steps are still attempted.
    /// Ensures as many resources as possible are released. Returns the first error encountered (if any).
    /// Emergency BPF hook detachment — called FIRST on SIGTERM to restore network.
    ///
    /// Only detaches TC and cgroup hooks; does NOT clean up other resources.
    /// This is safe to call multiple times.
    /// Add a DNS resolution result to the domain routing tracker.
    /// The `ebpf_mgr` and `domain_routing` are separate fields, passed individually
    /// to avoid borrow checker conflicts.
    pub fn add_dns_result_to_tracker(
        domain_routing: &mut Option<crate::domain_routing::DomainRoutingTracker>,
        ebpf_mgr: &Arc<Mutex<crate::ebpf::EbpfManager>>,
        domain: &str,
        ip: std::net::IpAddr,
        ttl_secs: u32,
    ) -> Result<()> {
        if let Some(ref mut tracker) = domain_routing {
            let mut ebpf_guard = ebpf_mgr.lock().expect("ebpf lock");
            tracker.add_dns_result(domain, ip, ttl_secs, &mut *ebpf_guard)?;
        }
        Ok(())
    }

    pub fn detach_bpf_hooks(&mut self) {
        info!("Emergency BPF hook detachment");
        // Detach dae0peer hooks in proxy NS first (before host NS hooks)
        // because dae0peer interface only exists in proxy NS
        if let Ok(()) = self.netns_mgr.join_proxy_ns() {
            let _ = self.ebpf().detach_by_iface("dae0peer");
            let _ = self.netns_mgr.join_host_ns();
        }
        // Detach all remaining hooks in host NS
        let _ = self.ebpf().detach_all();
    }

    pub async fn stop(&mut self) -> Result<()> {
        info!("Control plane stopping...");

        let mut errors: Vec<anyhow::Error> = Vec::new();

        // ---- Step 0: Stop API server ----
        if let Some(handle) = self.api_handle.take() {
            info!("Step 0/5: Stopping REST API server");
            handle.abort();
            let _ = handle.await;
            info!("REST API server stopped");
        }

        // ---- Step 0.5: Stop DNS manager ----
        if let Some(mut dns_mgr) = self.dns_manager.take() {
            info!("Step 0.5/5: Stopping DNS manager");
            if let Err(e) = dns_mgr.stop().await {
                warn!("DNS manager stop error: {}", e);
            }
        }

        // ---- Step 1: Stop TProxy listener ----
        info!("Step 1/5: Stopping TProxy listener");
        // Send stop signals to both TCP and UDP before waiting for thread exit
        // (the thread runs both via tokio::join!, so both must stop for it to exit)
        if let Some(tproxy) = &self.tproxy {
            tproxy.stop();
            info!("TProxy TCP stop signal sent");
        }
        if let Some(udp) = &self.tproxy_udp {
            udp.stop();
            info!("TProxy UDP stop signal sent");
        }
        // Wait for TProxy thread to exit (with timeout, non-blocking for async runtime)
        if let Some(handle) = self.tproxy_thread.take() {
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                tokio::task::spawn_blocking(move || {
                    let _ = handle.join();
                }),
            )
            .await;
            match result {
                Ok(Ok(_)) => info!("TProxy thread joined successfully"),
                Ok(Err(_)) => warn!("TProxy thread panicked"),
                Err(_) => warn!("TProxy thread did not exit within 5s timeout"),
            }
        }
        self.tproxy.take();
        self.tproxy_udp.take();

        // ---- Step 1.5a: Stop ringbuf consumer ----
        if let Some(running) = self.ringbuf_running.take() {
            info!("Step 1.5a/5: Stopping ringbuf consumer");
            running.store(false, Ordering::Relaxed);
        }
        if let Some(handle) = self.ringbuf_thread.take() {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                tokio::task::spawn_blocking(move || {
                    let _ = handle.join();
                }),
            )
            .await;
            info!("Ringbuf consumer stopped");
        }

        // ---- Step 1.5b: Stop connectivity checker ----
        if let Some(handle) = self.connectivity_handle.take() {
            info!("Step 1.5b/5: Stopping connectivity checker");
            handle.abort();
        }

        // ---- Step 1.5c: Stop conn_state janitor ----
        if let Some(handle) = self.janitor_handle.take() {
            info!("Step 1.5c/5: Stopping conn_state janitor");
            handle.abort();
        }

        // ---- Step 1.5c1: Stop redirect_track janitor ----
        if let Some(handle) = self.redirect_track_handle.take() {
            info!("Step 1.5c1/5: Stopping redirect_track janitor");
            handle.abort();
        }

        // ---- Step 1.5c2: Stop cookie_pid_map janitor ----
        if let Some(handle) = self.cookie_pid_handle.take() {
            info!("Step 1.5c2/5: Stopping cookie_pid_map janitor");
            handle.abort();
        }

        // ---- Step 1.5d: Stop InterfaceManager ----
        // Stop the background polling task before detaching TC programs,
        // so it doesn't try to attach/detach during shutdown.
        if let Some(mut iface_mgr) = self.iface_mgr.take() {
            info!("Step 1.5d/5: Stopping InterfaceManager");
            iface_mgr.stop().await;
        }

        // ---- Step 2: Detach all TC and cgroup programs ----
        // The TC hooks are on interfaces in both namespaces:
        //   - Host NS: dae0_ingress, wan_*, lan_*
        //   - Proxy NS: dae0peer_ingress, cgroup programs
        // detach_all() handles both sides.
        info!("Step 2/5: Detaching all TC and cgroup programs");
        if let Err(e) = self.ebpf().detach_all() {
            error!("Failed to detach programs: {}", e);
            errors.push(e);
        }

        // ---- Step 3: Unload eBPF program ----
        info!("Step 3/5: Unloading eBPF program");
        if let Err(e) = self.ebpf().unload() {
            error!("Failed to unload eBPF program: {}", e);
            errors.push(e);
        }

        // ---- Step 3.5: Unpin eBPF maps from bpffs ----
        // 在完全停止时清理 pinned maps，确保下次启动时使用新的 maps
        // 如果希望在重启后保留连接状态，可以注释掉此步骤
        info!("Step 3.5/5: Unpinning eBPF maps");
        if let Err(e) = self.ebpf().unpin_maps(crate::ebpf::BPFFS_PATH) {
            warn!("Failed to unpin eBPF maps: {}", e);
        }

        // ---- Step 4: Destroy network namespace ----
        info!("Step 4/5: Destroying network namespace and veth pair");
        if let Err(e) = self.netns_mgr.destroy() {
            error!("Failed to destroy network namespace: {}", e);
            errors.push(e);
        }

        self.running = false;

        if errors.is_empty() {
            info!("Control plane stopped successfully");
            Ok(())
        } else {
            for e in &errors {
                warn!("Control plane stop error: {}", e);
            }
            Err(anyhow::anyhow!(
                "Control plane stopped with {} error(s)",
                errors.len()
            ))
        }
    }

    /// Hot-reload configuration without restarting eBPF or TProxy.
    ///
    /// Re-parses the daefile and updates all eBPF maps in-place.
    /// Also toggles the flip bit for TC handle rotation to support
    /// filter switching on hot-reload.
    /// Safe to call even when eBPF is not loaded (maps are skipped).
    pub fn reload_config(&mut self, daefile_content: &str) -> Result<()> {
        info!("Hot-reloading configuration");

        // ---- Step 0: Toggle flip bit for TC handle rotation ----
        // 翻转 flip 位，使后续 attach 使用新的 handle，
        // 旧 filter 在 detach 时使用旧 handle 被删除。
        let new_flip = self.ebpf().flip() ^ 1;
        self.ebpf().set_flip(new_flip);
        info!("Hot-reload: toggled flip bit to {}", new_flip);

        // 1. Re-parse daefile
        let daefile_config = config::parse_daefile(daefile_content)
            .map_err(|e| anyhow::anyhow!("Config parse error: {:?}", e))?;
        config::validate_config(&daefile_config)?;
        self.daefile_config = Some(daefile_config.clone());
        self.daefile_content = Some(daefile_content.to_string());

        // Update hot-reloadable config fields from the new daefile
        if let Some(first_node) = daefile_config.outbounds.nodes.first() {
            self.config.proxy_addr = first_node.address.clone();
            self.config.proxy_username = first_node.username.clone().unwrap_or_default();
            self.config.proxy_password = first_node.password.clone().unwrap_or_default();
            self.config.proxy_dial_timeout_ms = first_node.dial_timeout_ms;
        }
        self.config.log_level = daefile_config.runtime.log_level.clone();

        // 2. Re-compile routing rules (with proxy server auto-direct)
        let proxy_server_ips = collect_proxy_server_ips(&self.config, &daefile_config.outbounds);
        let compiled = routing::compile_rules(
            &daefile_config.routing,
            &daefile_config.outbounds,
            &proxy_server_ips,
        )
        .context("Failed to compile routing rules")?;

        // 3. Write to eBPF maps (skip if not loaded)
        {
            let mut ebpf = self.ebpf();
            if !ebpf.is_loaded() {
                info!("Hot-reload: eBPF not loaded, skipping map writes");
            } else {
                // 3a. 清空 domain_routing_map 中的旧条目（对应 dae Go 的 clearReloadDomainRoutingMap）
                // 必须在写入新规则之前清理，避免残留的旧映射导致错误路由
                if let Err(e) = ebpf.clear_domain_routing_map() {
                    warn!("Hot-reload: failed to clear domain_routing_map: {}", e);
                } else {
                    info!("Hot-reload: domain_routing_map cleared");
                }

                if !compiled.match_sets.is_empty() {
                    ebpf.write_routing_rules(&compiled.match_sets)?;
                    info!(
                        "Hot-reload: wrote {} match sets to routing_map",
                        compiled.match_sets.len()
                    );
                }

                // Write LPM trie data to inner LPM trie maps via lpm_array_map
                {
                    let mut all_cidr_entries: Vec<(u32, CidrEntry)> = Vec::new();
                    for (trie_idx, cidrs) in compiled.lpm_tries.iter().enumerate() {
                        let entries = crate::routing::cidrs_to_cidr_entries(cidrs);
                        for (_, entry) in entries {
                            all_cidr_entries.push((trie_idx as u32, entry));
                        }
                    }
                    if !all_cidr_entries.is_empty() {
                        if let Err(e) = ebpf.write_cidr_table(&all_cidr_entries) {
                            warn!("Hot-reload: failed to write CIDR entries: {}", e);
                        } else {
                            info!(
                                "Hot-reload: wrote {} CIDR entries across {} LPM tries",
                                all_cidr_entries.len(),
                                compiled.lpm_tries.len()
                            );
                        }
                    }
                }

                // Update excluded comm/PID lists
                if let Some(ref pe) = daefile_config.process_exclusion {
                    if pe.enabled {
                        if !pe.r#match.comm.is_empty() {
                            let hashes: Vec<u32> = pe
                                .r#match
                                .comm
                                .iter()
                                .map(|c| crate::ebpf::hash_comm(c))
                                .collect();
                            let _ = ebpf.write_excluded_comm(&hashes);
                        }
                        if !pe.r#match.pid.is_empty() {
                            let _ = ebpf.write_excluded_pids(&pe.r#match.pid);
                        }
                        if !pe.r#match.tgid.is_empty() {
                            let _ = ebpf.write_excluded_pids(&pe.r#match.tgid);
                        }
                    }
                }
            }
        }

        // 4. Re-initialize domain routing tracker
        if !compiled.domain_sets.is_empty() {
            self.domain_routing = Some(crate::domain_routing::DomainRoutingTracker::new(
                std::sync::Arc::new(compiled.domain_sets),
            ));
            info!(
                "Hot-reload: domain routing tracker updated ({} sets)",
                self.domain_routing.as_ref().unwrap().len(),
            );
        }

        info!("Hot-reload completed successfully");
        Ok(())
    }
}

impl Drop for ControlPlane {
    /// Automatic stop on drop
    ///
    /// If the control plane is still running and the user forgot to call [`stop()`](ControlPlane::stop),
    /// the Drop implementation will automatically perform cleanup. However, since async is not available
    /// in Drop, this performs cleanup synchronously (a non-async version of stop).
    fn drop(&mut self) {
        if self.running {
            warn!("ControlPlane dropped without explicit stop()");
            // Each sub-module's Drop implementation handles its own cleanup
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

// ============================================================================
// Temp JSON File Lifecycle
// ============================================================================

/// Default temp JSON directory
pub const TEMP_JSON_DIR: &str = "/run/dae-rs";

/// Get the temp JSON file path
fn temp_json_path() -> std::path::PathBuf {
    let pid = std::process::id();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    std::path::PathBuf::from(format!("{}/config.{}.{}.json", TEMP_JSON_DIR, pid, ts))
}

/// Write the normalized JSON config to a temp file
///
/// Creates the directory if it doesn't exist, writes with 0600 permissions.
pub fn write_temp_json(config: &config::DaefileConfig) -> Result<std::path::PathBuf> {
    let path = temp_json_path();

    // Create directory if needed
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("Failed to create temp JSON directory: {}", parent.display())
        })?;
    }

    // Serialize to JSON with pretty printing
    let json =
        serde_json::to_string_pretty(config).context("Failed to serialize config to JSON")?;

    // Write atomically: write to temp file, then rename
    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, &json)
        .with_context(|| format!("Failed to write temp JSON to {}", tmp_path.display()))?;

    // Set permissions to 0600
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;

    // Atomic rename
    std::fs::rename(&tmp_path, &path)
        .with_context(|| format!("Failed to rename temp JSON to {}", path.display()))?;

    Ok(path)
}

/// Clean up temp JSON files older than the specified retention period
pub fn cleanup_temp_json(max_age_secs: u64) {
    let dir = std::path::Path::new(TEMP_JSON_DIR);
    if !dir.exists() {
        return;
    }
    let now = std::time::SystemTime::now();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(metadata) = std::fs::metadata(&path) {
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(duration) = now.duration_since(modified) {
                            if duration.as_secs() > max_age_secs {
                                let _ = std::fs::remove_file(&path);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Connect to an address with SO_MARK set (bypasses eBPF self-intercept).
/// Used by the connectivity checker and other internal health probes.
pub async fn connect_with_mark(
    addr: &std::net::SocketAddr,
    mark: u32,
    timeout_secs: u64,
) -> std::io::Result<tokio::net::TcpStream> {
    use std::os::unix::io::FromRawFd;

    let domain = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };

    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mark_val = mark as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark_val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        unsafe {
            libc::close(fd);
        }
        return Err(std::io::Error::last_os_error());
    }

    let sockaddr = socket2::SockAddr::from(*addr);
    let sockaddr_ptr = sockaddr.as_ptr();
    let sockaddr_len = sockaddr.len();
    let ret = unsafe { libc::connect(fd, sockaddr_ptr as *const libc::sockaddr, sockaddr_len) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINPROGRESS) {
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }
    }

    let std_stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
    let tokio_stream = tokio::net::TcpStream::from_std(std_stream)?;

    // Wait for the connection to complete
    let writable = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        tokio_stream.writable(),
    )
    .await;

    writable
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out"))??;

    // Check for connection errors
    if let Some(err) = tokio_stream.take_error()? {
        return Err(err);
    }

    Ok(tokio_stream)
}

// ============================================================================
// Kernel Parameter Configuration
// ============================================================================

/// Configure kernel parameters for a WAN/LAN interface.
///
/// Mirrors original dae's `SetSendRedirects` and `SetForwarding`:
/// - `net.ipv4.conf.<iface>.send_redirects = 0` — disable ICMP redirects
/// - `net.ipv4.conf.<iface>.forwarding = 1` — enable IP forwarding
///
/// These are needed for transparent proxying to work correctly.
/// Errors are logged but not propagated (best-effort).
fn configure_kernel_if(iface: &str) {
    // net.ipv4.conf.<iface>.send_redirects = 0
    let path_send_redirects = format!("/proc/sys/net/ipv4/conf/{}/send_redirects", iface);
    if let Err(e) = std::fs::write(&path_send_redirects, b"0\n") {
        warn!(
            "Failed to set send_redirects=0 on {}: {} (non-critical)",
            iface, e
        );
    } else {
        info!("Kernel: {}=0", path_send_redirects);
    }

    // net.ipv4.conf.<iface>.forwarding = 1
    let path_forwarding = format!("/proc/sys/net/ipv4/conf/{}/forwarding", iface);
    if let Err(e) = std::fs::write(&path_forwarding, b"1\n") {
        warn!(
            "Failed to set forwarding=1 on {}: {} (non-critical)",
            iface, e
        );
    } else {
        info!("Kernel: {}=1", path_forwarding);
    }

    // net.ipv6.conf.<iface>.forwarding = 1 (if IPv6 is enabled on the interface)
    let path_fwd6 = format!("/proc/sys/net/ipv6/conf/{}/forwarding", iface);
    // Don't error if IPv6 is not configured on this interface
    let _ = std::fs::write(&path_fwd6, b"1\n");

    // net.ipv4.conf.<iface>.rp_filter = 2 (loose mode, required for TProxy)
    let path_rp = format!("/proc/sys/net/ipv4/conf/{}/rp_filter", iface);
    if let Err(e) = std::fs::write(&path_rp, b"2\n") {
        warn!(
            "Failed to set rp_filter=2 on {}: {} (may affect TProxy)",
            iface, e
        );
    } else {
        info!("Kernel: {}=2", path_rp);
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

/// Collect all proxy server IP addresses from the configuration.
///
/// Extracts IPs from:
/// 1. `config.proxy_addr` — the main SOCKS5 proxy address that dae-rs connects to
/// 2. All outbound node addresses — all proxy servers defined in the configuration
///
/// These IPs are used to auto-generate `dip(<ip>) -> direct` routing rules,
/// preventing traffic destined for proxy servers from being re-proxied (loop prevention).
/// This matches the behavior of the original dae (Go) implementation.
///
/// Domain names in addresses are silently skipped (cannot resolve at this stage
/// without creating a chicken-and-egg problem with the proxy).
fn collect_proxy_server_ips(
    config: &Config,
    outbounds: &config::OutboundsConfig,
) -> Vec<std::net::IpAddr> {
    use std::collections::HashSet;
    let mut ips = HashSet::new();

    // 1. Extract IP from the main proxy_addr
    if let Ok(addr) = config.proxy_addr.parse::<std::net::SocketAddr>() {
        ips.insert(addr.ip());
    }

    // 2. Extract IPs from all outbound node addresses
    for node in &outbounds.nodes {
        if let Ok(addr) = node.address.parse::<std::net::SocketAddr>() {
            ips.insert(addr.ip());
        }
    }

    ips.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.tproxy_port, 15080);
        assert_eq!(config.route_table, 2023);
        assert_eq!(config.fwmark_proxy, 0x8000000);
        assert_eq!(config.fwmark_bypass, 0x04000000);
        assert_eq!(config.fwmark_mask, 0x8000000);
        assert_eq!(config.mtu, 1500);
        assert_eq!(config.log_level, "info");
        assert_eq!(config.proxy_addr, "127.0.0.1:1080");
        assert_eq!(config.proxy_username, "");
        assert_eq!(config.proxy_password, "");
        assert_eq!(config.proxy_dial_timeout_ms, 5000);
        assert!(config.wan_interface.is_empty());
        assert!(config.lan_interface.is_empty());
    }

    #[test]
    fn test_control_plane_new() {
        let config = Config::default();
        let cp = ControlPlane::new(config);

        assert!(!cp.running);
        assert_eq!(cp.ebpf().iface(), "dae0");
        assert!(!cp.ebpf().is_loaded());
        assert!(!cp.netns_mgr.is_created());
    }

    #[test]
    fn test_from_daefile_minimal() {
        let daefile = config::default_config_example();
        let config = Config::from_daefile(daefile).expect("from_daefile failed");
        assert_eq!(config.tproxy_port, 15080);
        assert_eq!(config.log_level, "info");
        assert_eq!(config.mtu, 1500);
        assert_eq!(config.route_table, 2023);
        assert_eq!(config.fwmark_proxy, 0x8000000);
        assert_eq!(config.fwmark_bypass, 0x04000000);
        assert_eq!(config.fwmark_mask, 0x0f000000);
        assert_eq!(config.proxy_addr, "127.0.0.1:1080");
        assert_eq!(config.proxy_dial_timeout_ms, 5000);
    }

    #[test]
    fn test_compile_rules_fallback() {
        // This test was removed - compile_rules in lib.rs is deprecated.
        // Routing tests are in routing::tests.
    }

    #[test]
    fn test_compile_rules_action_mapping() {
        // This test was removed - compile_rules in lib.rs is deprecated.
        // Routing tests are in routing::tests.
    }
}
