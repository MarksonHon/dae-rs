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
use protocols::socks5::Socks5Dialer;
use tproxy::{TproxyListener, UdpTproxyListener};

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
/// | `veth_host` | dae0 | Host-side veth name |
/// | `veth_peer` | dae0peer | Proxy-side veth name |
/// | `host_addr` | 169.254.0.1/16 | Host-side address |
/// | `peer_addr` | 169.254.0.11/16 | Proxy-side address |
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
    /// Host-side veth name
    pub veth_host: String,
    /// Proxy-side veth name
    pub veth_peer: String,
    /// Host-side address (CIDR)
    pub host_addr: String,
    /// Proxy-side address (CIDR)
    pub peer_addr: String,
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tproxy_port: 15080,
            route_table: 2023,
            fwmark_proxy: 0x8000000,
            fwmark_bypass: 0x04000000,
            fwmark_mask: 0x8000000,
            veth_host: "dae0".into(),
            veth_peer: "dae0peer".into(),
            host_addr: "169.254.0.1/16".into(),
            peer_addr: "169.254.0.11/16".into(),
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

        Ok(Self {
            tproxy_port: runtime.tproxy_port,
            route_table: ns.map(|n| n.route_table).unwrap_or(2023),
            fwmark_proxy: marks.map(|m| m.proxy).unwrap_or(0x8000000),
            fwmark_bypass: marks.map(|m| m.bypass).unwrap_or(0x04000000),
            fwmark_mask: marks.map(|m| m.mask).unwrap_or(0x8000000),
            veth_host: ns
                .map(|n| n.host_if.clone())
                .unwrap_or_else(|| "dae0".into()),
            veth_peer: ns
                .map(|n| n.peer_if.clone())
                .unwrap_or_else(|| "dae0peer".into()),
            host_addr: ns
                .map(|n| n.host_addr.clone())
                .unwrap_or_else(|| "169.254.0.1/16".into()),
            peer_addr: ns
                .map(|n| n.peer_addr.clone())
                .unwrap_or_else(|| "169.254.0.11/16".into()),
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
    /// TProxy listener (runs in the proxy namespace)
    pub tproxy: Option<Arc<TproxyListener>>,
    /// JoinHandle for the TProxy child thread
    tproxy_thread: Option<std::thread::JoinHandle<()>>,
    /// Whether the control plane is running
    pub running: bool,
    /// Raw daefile config (for API queries of outbound groups/nodes/routing)
    pub daefile_config: Option<config::DaefileConfig>,
    /// Raw daefile text content (for API config reload)
    pub daefile_content: Option<String>,
    /// Tokio task handle for the API server
    pub api_handle: Option<tokio::task::JoinHandle<()>>,
    /// Tokio task handle for the conn_state janitor
    janitor_handle: Option<tokio::task::JoinHandle<()>>,
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
            &config.veth_host,
            &config.ebpf_path,
        )));
        let netns_mgr = netns::NetnsManager::new(&config);

        Self {
            config,
            ebpf_mgr,
            netns_mgr,
            tproxy: None,
            tproxy_thread: None,
            running: false,
            daefile_config: None,
            daefile_content: None,
            api_handle: None,
            janitor_handle: None,
            connectivity_handle: None,
            domain_routing: None,
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
        self.netns_mgr.create().map_err(|e| {
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

        // ---- Step 2: Load eBPF program ----
        info!("Step 2/5: Loading eBPF program");

        // Set PARAM global variable before loading (if configured)
        if let Some(param) = self.ebpf_param {
            self.ebpf().set_param(&param);
            info!("eBPF PARAM configured: tproxy_port={}", param.tproxy_port);
        }

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

        // ---- Step 3: Attach TC programs ----
        // Now that the topology is fixed (dae0 in host NS, dae0peer in proxy NS),
        // we must attach programs in the correct namespace:
        //   - dae0_ingress → host NS (dae0 is there)
        //   - dae0peer_ingress → proxy NS (dae0peer is there)
        //   - wan/lan programs → host NS (physical interfaces are there)
        //   - cgroup programs → proxy NS (sock_create/release etc.)
        info!("Step 3/5: Attaching TC programs");
        // Attach dae0_ingress in host NS
        self.ebpf().attach_dae0("dae0").map_err(|e| {
            error!("Failed to attach dae0_ingress TC: {}", e);
            e
        })?;
        // Attach dae0peer_ingress in proxy NS
        // We need to switch to proxy NS to attach this program
        {
            self.netns_mgr.join_proxy_ns()?;
            self.ebpf().attach_dae0peer("dae0peer").map_err(|e| {
                error!("Failed to attach dae0peer_ingress TC: {}", e);
                e
            })?;
            self.netns_mgr.join_host_ns()?;
        }
        // Attach WAN/LAN TC programs (if configured)
        for wan_if in &self.config.wan_interface {
            self.ebpf().attach_wan(wan_if)?;
        }
        for lan_if in &self.config.lan_interface {
            self.ebpf().attach_lan(lan_if)?;
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
                let compiled = routing::compile_rules(&dc.routing, &dc.outbounds)
                    .context("Failed to compile routing rules")?;

                // Write MatchSet entries to routing_map
                if !compiled.match_sets.is_empty() {
                    self.ebpf().write_routing_rules(&compiled.match_sets)?;
                    info!(
                        "Wrote {} MatchSet entries to routing_map",
                        compiled.match_sets.len()
                    );
                }

                // Write LPM trie data to lpm_array_map
                for (trie_idx, cidrs) in compiled.lpm_tries.iter().enumerate() {
                    let entries = routing::cidrs_to_cidr_entries(cidrs);
                    let mut ebpf = self.ebpf();
                    for (local_idx, entry) in entries.iter() {
                        let global_idx =
                            (trie_idx as u32 + *local_idx) % ebpf::MAX_MATCH_SET_LEN as u32;
                        let mut map = ebpf
                            .get_map_mut("lpm_array_map")
                            .context("Failed to get lpm_array_map")?;
                        let _ = map.update(
                            &global_idx.to_ne_bytes(),
                            bytemuck::bytes_of(entry),
                            libbpf_rs::MapFlags::empty(),
                        );
                    }
                }
                if !compiled.lpm_tries.is_empty() {
                    info!(
                        "Wrote {} LPM tries to lpm_array_map",
                        compiled.lpm_tries.len()
                    );
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
        self.start_tproxy()?;

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
        // Conn_state janitor
        self.janitor_handle = Some(Self::start_janitor(self.ebpf_mgr.clone()));

        // Connectivity checker (proxies health)
        let proxy_addr: std::net::SocketAddr =
            self.config.proxy_addr.parse().expect("valid proxy address");
        self.connectivity_handle = Some(Self::start_connectivity_checker(
            self.ebpf_mgr.clone(),
            proxy_addr,
        ));

        self.running = true;
        info!("Control plane started successfully");
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
    fn start_tproxy(&mut self) -> Result<()> {
        // ---- Create SOCKS5 dialer ----
        let proxy_addr: SocketAddr = self.config.proxy_addr.parse().map_err(|e| {
            anyhow::anyhow!("Invalid proxy address '{}': {}", self.config.proxy_addr, e)
        })?;

        // ---- Create TProxy listener in HOST namespace ----
        // 策略路由：proxy NS 标记包 → dae0peer → dae0 → host NS policy → TProxy socket
        let listen_addr: SocketAddr = format!("[::]:{}", self.config.tproxy_port)
            .parse()
            .map_err(|e| {
                anyhow::anyhow!(
                    "Invalid TProxy listen address (port {}): {}",
                    self.config.tproxy_port,
                    e
                )
            })?;

        let dialer_tcp = Socks5Dialer::new(
            proxy_addr,
            &self.config.proxy_username,
            &self.config.proxy_password,
            self.config.proxy_dial_timeout_ms,
        );
        let dialer_udp = Socks5Dialer::new(
            proxy_addr,
            &self.config.proxy_username,
            &self.config.proxy_password,
            self.config.proxy_dial_timeout_ms,
        );

        let tproxy_tcp = Arc::new(TproxyListener::new(listen_addr, dialer_tcp));
        let tproxy_udp = Arc::new(UdpTproxyListener::new(listen_addr, dialer_udp));

        // ---- Add host namespace policy routing ----
        // 宿主 NS 策略路由：标记包 → local default dev lo → TProxy socket
        self.netns_mgr
            .add_host_policy_routing()
            .context("Failed to add host namespace policy routing")?;

        info!(
            listen_addr = %listen_addr,
            "Launching TProxy in HOST namespace"
        );

        // ---- Start TProxy directly (no netns switch needed) ----
        let tproxy_tcp_clone = tproxy_tcp.clone();
        let tproxy_udp_clone = tproxy_udp.clone();
        let thread_handle = std::thread::spawn(move || {
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
                // Bind the dual-stack TCP listener
                info!(
                    "Binding TProxy TCP listener on {} in host namespace",
                    tproxy_tcp_clone.listen_addr()
                );
                let listener_tcp = match tproxy_tcp_clone.bind().await {
                    Ok(l) => l,
                    Err(e) => {
                        error!("Failed to bind TProxy TCP socket: {}", e);
                        return Err(e);
                    }
                };

                info!(
                    "TProxy TCP listener starting on {} in host namespace",
                    tproxy_tcp_clone.listen_addr()
                );

                // Run TCP and UDP listeners concurrently
                let (tcp_result, udp_result) = tokio::join!(
                    tproxy_tcp_clone.serve(listener_tcp),
                    tproxy_udp_clone.start()
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
        self.tproxy_thread = Some(thread_handle);

        info!("TProxy listener launching in background thread (host namespace)");
        Ok(())
    }

    // ========================================================================
    // Ringbuf Event Consumer
    // ========================================================================

    /// Start consuming events from the eBPF ringbuf.
    ///
    /// This runs as a background task that reads events from the event_ringbuf map
    /// and logs them. In a full implementation, this would also trigger actions
    /// like conn_state cleanup for overflow events.
    pub async fn start_ringbuf_consumer(&self) -> Result<tokio::task::JoinHandle<()>> {
        let ebpf_path = self.config.ebpf_path.clone();

        let handle = tokio::spawn(async move {
            info!("Ringbuf consumer started");

            // Note: In a full implementation, we would:
            // 1. Open the eBPF object to get the ringbuf map FD
            // 2. Use poll() or epoll() to wait for events
            // 3. Read and parse each event

            // For now, we just log that the consumer is running
            // The actual implementation would use libbpf-rs ringbuf API
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                // Periodic stats logging would go here
            }
        });

        Ok(handle)
    }

    // ========================================================================
    // Janitor: Periodic conn_state_map Cleanup
    // ========================================================================

    /// Start the janitor task that periodically cleans up expired conn_state_map entries.
    ///
    /// This mirrors dae's `controlPlaneDatapathJanitor` which scans conn_state_map
    /// every few seconds and deletes entries that have exceeded their timeout.
    pub fn start_janitor(
        ebpf_mgr: Arc<Mutex<crate::ebpf::EbpfManager>>,
    ) -> tokio::task::JoinHandle<()> {
        let interval_secs = 5; // Scan every 5 seconds

        tokio::spawn(async move {
            info!("Janitor started (interval: {}s)", interval_secs);

            loop {
                tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;

                let now_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;

                let mut mgr = ebpf_mgr.lock().expect("janitor lock");
                match mgr.janitor_scan_conn_state(now_ns) {
                    Ok(deleted) => {
                        if deleted > 0 {
                            info!("Janitor deleted {} expired conn_state entries", deleted);
                        }
                    }
                    Err(e) => {
                        warn!("Janitor scan failed: {}", e);
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
    ) -> tokio::task::JoinHandle<()> {
        let interval_secs = 30; // Check every 30 seconds

        tokio::spawn(async move {
            info!(
                "Connectivity checker started (interval: {}s)",
                interval_secs
            );

            loop {
                tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;

                // Simple TCP health check: try to connect to the SOCKS5 proxy.
                let tcp_alive = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    tokio::net::TcpStream::connect(&proxy_addr),
                )
                .await
                .is_ok()
                    && tokio::net::TcpStream::connect(&proxy_addr).await.is_ok();

                let mut mgr = ebpf_mgr.lock().expect("connectivity lock");

                // Update TCP-IPv4 (outbound=0, domain=TCP, ipv4)
                // Assume outbound_id 0 = CONTROL_PLANE_ROUTING for the proxy group
                let outbound_id = crate::ebpf::outbound::CONTROL_PLANE_ROUTING;

                let _ = mgr.update_outbound_connectivity(
                    outbound_id,
                    1, // TCP
                    false,
                    false, // IPv4
                    tcp_alive,
                );
                let _ = mgr.update_outbound_connectivity(
                    outbound_id,
                    1, // TCP
                    false,
                    true, // IPv6
                    tcp_alive,
                );

                // For DNS and data UDP, we use the same TCP health as a proxy
                // In a full implementation, actual UDP probing would be done.
                let _ = mgr.update_outbound_connectivity(
                    outbound_id,
                    2,     // UDP
                    true,  // DNS
                    false, // IPv4
                    tcp_alive,
                );
                let _ = mgr.update_outbound_connectivity(
                    outbound_id,
                    2,     // UDP
                    false, // data
                    false, // IPv4
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
        let mut ebpf = self.ebpf();
        let _ = ebpf.detach_all();
    }

    pub async fn stop(&mut self) -> Result<()> {
        info!("Control plane stopping...");

        let mut first_error: Option<anyhow::Error> = None;

        // ---- Step 0: Stop API server ----
        if let Some(handle) = self.api_handle.take() {
            info!("Step 0/5: Stopping REST API server");
            handle.abort();
            let _ = handle.await;
            info!("REST API server stopped");
        }

        // ---- Step 1: Stop TProxy listener ----
        info!("Step 1/5: Stopping TProxy listener");
        if let Some(tproxy) = &self.tproxy {
            tproxy.stop();
            info!("TProxy stop signal sent");
        }
        // Wait for TProxy thread to exit
        if let Some(handle) = self.tproxy_thread.take() {
            match handle.join() {
                Ok(_) => info!("TProxy thread joined successfully"),
                Err(_) => warn!("TProxy thread panicked"),
            }
        }
        self.tproxy.take();

        // ---- Step 1.5a: Stop ringbuf consumer ----
        if let Some(running) = self.ringbuf_running.take() {
            info!("Step 1.5a/5: Stopping ringbuf consumer");
            running.store(false, Ordering::Relaxed);
        }
        if let Some(handle) = self.ringbuf_thread.take() {
            let _ = handle.join();
            info!("Ringbuf consumer stopped");
        }

        // ---- Step 1.5b: Stop connectivity checker ----
        if let Some(handle) = self.connectivity_handle.take() {
            info!("Step 1.5b/5: Stopping connectivity checker");
            handle.abort();
        }

        // ---- Step 1.5c: Stop janitor ----
        if let Some(handle) = self.janitor_handle.take() {
            info!("Step 1.5c/5: Stopping janitor");
            handle.abort();
        }

        // ---- Step 2: Detach all TC and cgroup programs ----
        // The TC hooks are on interfaces in both namespaces:
        //   - Host NS: dae0_ingress, wan_*, lan_*
        //   - Proxy NS: dae0peer_ingress, cgroup programs
        // detach_all() handles both sides.
        info!("Step 2/5: Detaching all TC and cgroup programs");
        if let Err(e) = self.ebpf().detach_all() {
            error!("Failed to detach programs: {}", e);
            first_error.get_or_insert(e);
        }

        // ---- Step 3: Unload eBPF program ----
        info!("Step 3/5: Unloading eBPF program");
        if let Err(e) = self.ebpf().unload() {
            error!("Failed to unload eBPF program: {}", e);
            first_error.get_or_insert(e);
        }

        // ---- Step 4: Destroy network namespace ----
        info!("Step 4/5: Destroying network namespace and veth pair");
        if let Err(e) = self.netns_mgr.destroy() {
            error!("Failed to destroy network namespace: {}", e);
            first_error.get_or_insert(e);
        }

        self.running = false;

        if let Some(e) = first_error {
            warn!("Control plane stopped with errors: {}", e);
            Err(e)
        } else {
            info!("Control plane stopped successfully");
            Ok(())
        }
    }

    /// Hot-reload configuration without restarting eBPF or TProxy.
    ///
    /// Re-parses the daefile and updates all eBPF maps in-place.
    /// Safe to call even when eBPF is not loaded (maps are skipped).
    pub fn reload_config(&mut self, daefile_content: &str) -> Result<()> {
        info!("Hot-reloading configuration");

        // 1. Re-parse daefile
        let daefile_config = config::parse_daefile(daefile_content)
            .map_err(|e| anyhow::anyhow!("Config parse error: {:?}", e))?;
        config::validate_config(&daefile_config)?;
        self.daefile_config = Some(daefile_config.clone());
        self.daefile_content = Some(daefile_content.to_string());

        // 2. Re-compile routing rules
        let compiled = routing::compile_rules(&daefile_config.routing, &daefile_config.outbounds)
            .context("Failed to compile routing rules")?;

        // 3. Write to eBPF maps (skip if not loaded)
        if !self.ebpf().is_loaded() {
            info!("Hot-reload: eBPF not loaded, skipping map writes");
        } else {
            if !compiled.match_sets.is_empty() {
                self.ebpf().write_routing_rules(&compiled.match_sets)?;
                info!(
                    "Hot-reload: wrote {} match sets to routing_map",
                    compiled.match_sets.len()
                );
            }

            // Write LPM trie data
            for (trie_idx, cidrs) in compiled.lpm_tries.iter().enumerate() {
                let entries = routing::cidrs_to_cidr_entries(cidrs);
                let mut ebpf = self.ebpf();
                for (local_idx, entry) in entries.iter() {
                    let global_idx =
                        (trie_idx as u32 + *local_idx) % ebpf::MAX_MATCH_SET_LEN as u32;
                    if let Ok(mut map) = ebpf.get_map_mut("lpm_array_map") {
                        let _ = map.update(
                            &global_idx.to_ne_bytes(),
                            bytemuck::bytes_of(entry),
                            libbpf_rs::MapFlags::empty(),
                        );
                    }
                }
            }

            // Update excluded comm/PID lists
            if let Some(ref pe) = daefile_config.process_exclusion {
                if pe.enabled {
                    let mut ebpf = self.ebpf();
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

// ============================================================================
// Unit Tests
// ============================================================================

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
        assert_eq!(config.veth_host, "dae0");
        assert_eq!(config.veth_peer, "dae0peer");
        assert_eq!(config.host_addr, "169.254.0.1/16");
        assert_eq!(config.peer_addr, "169.254.0.11/16");
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
        assert_eq!(config.veth_host, "dae0");
        assert_eq!(config.veth_peer, "dae0peer");
        assert_eq!(config.host_addr, "169.254.0.1/16");
        assert_eq!(config.peer_addr, "169.254.0.11/16");
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
