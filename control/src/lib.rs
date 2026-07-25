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
//!     // Method 1: Start with default config
//!     let config = Config::default();
//!     let mut cp = ControlPlane::new(config);
//!     cp.start().await?;
//!     // ... running ...
//!     cp.stop().await?;
//!
//!     // Method 2: Parse config from daefile
//!     let config = Config::from_daefile(daefile_content)?;
//!     let mut cp = ControlPlane::new(config);
//!     cp.start().await?;
//!     cp.stop().await?;
//!     Ok(())
//! }
//! ```

pub mod ebpf;
pub mod netns;
pub mod tproxy;
pub mod config;
pub mod api;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use protocols::socks5::Socks5Dialer;
use tproxy::TproxyListener;

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
                (
                    "127.0.0.1:1080".into(),
                    String::new(),
                    String::new(),
                    5000,
                )
            };

        let api_config = daefile_config.api.clone();

        Ok(Self {
            tproxy_port: runtime.tproxy_port,
            route_table: ns.map(|n| n.route_table).unwrap_or(2023),
            fwmark_proxy: marks.map(|m| m.proxy).unwrap_or(0x8000000),
            fwmark_bypass: marks.map(|m| m.bypass).unwrap_or(0x04000000),
            fwmark_mask: marks.map(|m| m.mask).unwrap_or(0x8000000),
            veth_host: ns.map(|n| n.host_if.clone()).unwrap_or_else(|| "dae0".into()),
            veth_peer: ns.map(|n| n.peer_if.clone()).unwrap_or_else(|| "dae0peer".into()),
            host_addr: ns.map(|n| n.host_addr.clone()).unwrap_or_else(|| "169.254.0.1/16".into()),
            peer_addr: ns.map(|n| n.peer_addr.clone()).unwrap_or_else(|| "169.254.0.11/16".into()),
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
    /// eBPF program manager
    pub ebpf_mgr: ebpf::EbpfManager,
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
    /// Embedded eBPF bytecode (compiled into the binary).
    /// When set, `load()` uses this instead of reading from file.
    pub embedded_ebpf: Option<&'static [u8]>,
    /// Daeparam to pass to the eBPF program before loading.
    pub ebpf_param: Option<crate::ebpf::Daeparam>,
}

impl ControlPlane {
    /// Create a new control plane instance
    ///
    /// Initializes all sub-module managers, but does not start any services.
    /// Call [`start()`](ControlPlane::start) to start.
    ///
    /// # Parameters
    ///
    /// * `config` — Control plane configuration
    pub fn new(config: Config) -> Self {
        let ebpf_mgr = ebpf::EbpfManager::new_with_path(
            &config.veth_host,
            &config.ebpf_path,
        );
        let netns_mgr = netns::NetnsManager::new(&config);

        Self {
            daefile_config: config.daefile_config.clone(),
            daefile_content: None,
            config,
            ebpf_mgr,
            netns_mgr,
            tproxy: None,
            tproxy_thread: None,
            running: false,
            api_handle: None,
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
        self.netns_mgr.create()
            .map_err(|e| {
                error!("Failed to create network namespace: {}", e);
                e
            })?;

        // ---- Step 1.5: Set eBPF PARAM with netns information ----
        // Now that netns is created, we can set dae0_ifindex, dae_netns_id, dae0peer_mac
        if let Some(ref mut param) = self.ebpf_param {
            // Get dae0 ifindex in host NS
            match self.netns_mgr.get_host_ifindex() {
                Ok(ifindex) => {
                    param.dae0_ifindex = ifindex;
                    info!("Set PARAM.dae0_ifindex = {}", ifindex);
                }
                Err(e) => {
                    warn!("Failed to get dae0 ifindex: {}", e);
                }
            }
            
            // Get proxy netns inode (dae_netns_id)
            match self.netns_mgr.get_proxy_netns_inode() {
                Ok(inode) => {
                    param.dae_netns_id = inode;
                    info!("Set PARAM.dae_netns_id = {}", inode);
                }
                Err(e) => {
                    warn!("Failed to get proxy netns inode: {}", e);
                }
            }
            
            // Get dae0peer MAC address
            match self.netns_mgr.get_peer_mac() {
                Ok(mac) => {
                    param.dae0peer_mac = mac;
                    info!("Set PARAM.dae0peer_mac = {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                }
                Err(e) => {
                    warn!("Failed to get dae0peer MAC: {}", e);
                }
            }
            
            // Set tproxy_port
            param.tproxy_port = self.config.tproxy_port as u32;
            info!("Set PARAM.tproxy_port = {}", param.tproxy_port);
            
            // Set control_plane_pid
            param.control_plane_pid = std::process::id();
            info!("Set PARAM.control_plane_pid = {}", param.control_plane_pid);
            
            // Set use_redirect_peer based on kernel support
            // For now, set to 0 (disabled) as default
            param.use_redirect_peer = 0;
            info!("Set PARAM.use_redirect_peer = {}", param.use_redirect_peer);
        }

        // ---- Step 2: Load eBPF program ----
        info!("Step 2/5: Loading eBPF program");

        // Set PARAM global variable before loading (if configured)
        if let Some(param) = self.ebpf_param {
            self.ebpf_mgr.set_param(&param);
            info!("eBPF PARAM configured: tproxy_port={}", param.tproxy_port);
        }

        if let Some(ebpf_bytes) = self.embedded_ebpf {
            info!("Using embedded eBPF bytecode ({} bytes)", ebpf_bytes.len());
            self.ebpf_mgr.load_from_bytes(ebpf_bytes)
                .map_err(|e| {
                    error!("Failed to load embedded eBPF program: {}", e);
                    e
                })?;
        } else {
            self.ebpf_mgr.load()
                .map_err(|e| {
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
        self.ebpf_mgr.attach_dae0("dae0")
            .map_err(|e| {
                error!("Failed to attach dae0_ingress TC: {}", e);
                e
            })?;
        // Attach dae0peer_ingress in proxy NS
        // We need to switch to proxy NS to attach this program
        {
            self.netns_mgr.join_proxy_ns()?;
            self.ebpf_mgr.attach_dae0peer("dae0peer")
                .map_err(|e| {
                    error!("Failed to attach dae0peer_ingress TC: {}", e);
                    e
                })?;
            self.netns_mgr.join_host_ns()?;
        }
        // Attach WAN/LAN TC programs (if configured)
        for wan_if in &self.config.wan_interface {
            self.ebpf_mgr.attach_wan(wan_if)?;
        }
        for lan_if in &self.config.lan_interface {
            self.ebpf_mgr.attach_lan(lan_if)?;
        }

        // ---- Step 3.5: Write eBPF maps (exclusion list + rules) ----
        info!("Step 3.5/5: Writing eBPF maps (exclusion list + rules)");

        // 3.5a. Write excluded process names (from daefile config)
        if let Some(ref dc) = self.daefile_config {
            if let Some(ref pe) = dc.process_exclusion {
                if pe.enabled {
                    // Write comm exclusion list
                    if !pe.r#match.comm.is_empty() {
                        let comm_hashes: Vec<u32> = pe.r#match.comm.iter()
                            .map(|c| crate::ebpf::hash_comm(c))
                            .collect();
                        self.ebpf_mgr.write_excluded_comm(&comm_hashes)?;
                        info!("Wrote {} excluded comm hashes to eBPF map", comm_hashes.len());
                    }
                    // Write pid exclusion list
                    if !pe.r#match.pid.is_empty() {
                        self.ebpf_mgr.write_excluded_pids(&pe.r#match.pid)?;
                        info!("Wrote {} excluded PIDs to eBPF map", pe.r#match.pid.len());
                    }
                    // Write tgid exclusion list (shares the same map as pid)
                    if !pe.r#match.tgid.is_empty() {
                        self.ebpf_mgr.write_excluded_pids(&pe.r#match.tgid)?;
                        info!("Wrote {} excluded TGIDs to eBPF map", pe.r#match.tgid.len());
                    }
                }
            }
        }

        // 3.5b. Compile routing rules into RuleEntry and write to RULES_MAP
        if let Some(ref dc) = self.daefile_config {
            if !dc.routing.rules.is_empty() {
                let entries = compile_rules(&dc.routing, &dc.outbounds)?;
                if !entries.is_empty() {
                    self.ebpf_mgr.write_rules(&entries)?;
                    info!("Wrote {} rules to RULES_MAP", entries.len());
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
                match self.ebpf_mgr.attach_cgroup(cgroup_fd) {
                    Ok(()) => {
                        info!("cgroup programs attached successfully");
                    }
                    Err(e) => {
                        warn!("Failed to attach cgroup programs: {}", e);
                    }
                }
                unsafe { libc::close(cgroup_fd); }
            } else {
                warn!("Failed to open /sys/fs/cgroup: {}", std::io::Error::last_os_error());
            }
            
            // Switch back to host NS
            self.netns_mgr.join_host_ns()?;
        }

        // ---- Step 4: Start TProxy listener ----
        info!("Step 4/5: Starting TProxy listener in proxy namespace");
        self.start_tproxy()?;

        self.running = true;
        info!("Control plane started successfully");
        Ok(())
    }

    /// Start the TProxy listener in the proxy namespace
    ///
    /// Creates a SOCKS5 dialer and TProxy listener, then switches to the
    /// proxy network namespace in a separate thread and starts the listen loop.
    ///
    /// # Flow
    ///
    /// 1. Create `Socks5Dialer` from config
    /// 2. Create `TproxyListener` from config
    /// 3. Get the proxy namespace fd
    /// 4. Spawn a separate thread which:
    ///    a. Saves the host namespace fd
    ///    b. Switches to the proxy namespace via `setns()`
    ///    c. Creates a local tokio runtime
    ///    d. Starts the TProxy listen loop
    ///    e. Switches back to host namespace after listening stops
    ///
    /// # Errors
    ///
    /// * Returns a parse error if the proxy address format is invalid
    /// * Returns an error if the proxy namespace has not been created
    /// * Returns a bind error if the port is already in use
    fn start_tproxy(&mut self) -> Result<()> {
        // ---- Create SOCKS5 dialer ----
        let proxy_addr: SocketAddr = self.config.proxy_addr
            .parse()
            .map_err(|e| anyhow::anyhow!(
                "Invalid proxy address '{}': {}",
                self.config.proxy_addr, e
            ))?;

        let dialer = Socks5Dialer::new(
            proxy_addr,
            &self.config.proxy_username,
            &self.config.proxy_password,
            self.config.proxy_dial_timeout_ms,
        );

        info!(
            proxy_addr = %proxy_addr,
            has_auth = !self.config.proxy_username.is_empty(),
            "Created SOCKS5 dialer for TProxy"
        );

        // ---- Create TProxy listener ----
        let listen_addr: SocketAddr = format!("0.0.0.0:{}", self.config.tproxy_port)
            .parse()
            .map_err(|e| anyhow::anyhow!(
                "Invalid TProxy listen address (port {}): {}",
                self.config.tproxy_port, e
            ))?;

        let tproxy = Arc::new(TproxyListener::new(listen_addr, dialer));

        // ---- Get proxy namespace fd ----
        let proxy_ns_fd = self.netns_mgr
            .get_proxy_ns_fd()
            .ok_or_else(|| anyhow::anyhow!(
                "Proxy namespace not created — cannot start TProxy"
            ))?;

        info!(
            listen_addr = %listen_addr,
            proxy_ns_fd = %proxy_ns_fd,
            "Launching TProxy in proxy network namespace"
        );

        // ---- Start TProxy in a separate thread (needs netns switch) ----
        let tproxy_clone = tproxy.clone();
        let thread_handle = std::thread::spawn(move || {
            // Save current (host) namespace fd
            let host_ns_file = match std::fs::File::open("/proc/self/ns/net") {
                Ok(f) => f,
                Err(e) => {
                    error!("Failed to open host netns fd for saving: {}", e);
                    return;
                }
            };
            let host_ns_fd = host_ns_file.as_raw_fd();
            let proxy_ns_fd = unsafe { BorrowedFd::borrow_raw(proxy_ns_fd) };
            let host_ns_borrowed = unsafe { BorrowedFd::borrow_raw(host_ns_fd) };

            // Switch to proxy namespace
            match nix::sched::setns(
                &proxy_ns_fd,
                nix::sched::CloneFlags::CLONE_NEWNET,
            ) {
                Ok(_) => {
                    info!("TProxy thread entered proxy network namespace");
                }
                Err(e) => {
                    error!("Failed to enter proxy namespace via setns: {}", e);
                    return;
                }
            }

            // Create local tokio runtime for TProxy listener
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
                info!(
                    "TProxy listener starting on {} in proxy namespace",
                    tproxy_clone.listen_addr()
                );
                tproxy_clone.start().await
            });

            match result {
                Ok(_) => {
                    info!("TProxy listener exited normally");
                }
                Err(e) => {
                    error!("TProxy listener exited with error: {}", e);
                }
            }

            // Switch back to host namespace
            if let Err(e) = nix::sched::setns(
                &host_ns_borrowed,
                nix::sched::CloneFlags::CLONE_NEWNET,
            ) {
                warn!("Failed to re-enter host namespace: {}", e);
            } else {
                info!("TProxy thread re-entered host network namespace");
            }
        });

        self.tproxy = Some(tproxy);
        self.tproxy_thread = Some(thread_handle);

        info!("TProxy listener launching in background thread");
        Ok(())
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

        // ---- Step 2: Detach all TC and cgroup programs ----
        // The TC hooks are on interfaces in both namespaces:
        //   - Host NS: dae0_ingress, wan_*, lan_*
        //   - Proxy NS: dae0peer_ingress, cgroup programs
        // detach_all() handles both sides.
        info!("Step 2/5: Detaching all TC and cgroup programs");
        if let Err(e) = self.ebpf_mgr.detach_all() {
            error!("Failed to detach programs: {}", e);
            first_error.get_or_insert(e);
        }

        // ---- Step 3: Unload eBPF program ----
        info!("Step 3/5: Unloading eBPF program");
        if let Err(e) = self.ebpf_mgr.unload() {
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

/// Compile daefile routing rules into an eBPF RuleEntry array
///
/// Compiles human-readable routing expressions (e.g., `dport(22) -> direct`) into
/// a flat, kernel-executable rule structure.
pub fn compile_rules(
    routing: &config::RoutingConfig,
    _outbounds: &config::OutboundsConfig,
) -> Result<Vec<crate::ebpf::RuleEntry>> {
    use crate::ebpf::RuleEntry;
    use std::net::Ipv4Addr;

    let mut entries = Vec::new();

    for rule in &routing.rules {
        let mut entry = RuleEntry::default();
        let match_expr = &rule.r#match;
        let mut parsed = false;

        // Parse dip(...)
        if let Some(cidr) = match_expr.strip_prefix("dip(").and_then(|s| s.strip_suffix(')')) {
            let cidr = cidr.trim();
            // Handle the special geoip:private tag
            if cidr == "geoip:private" {
                // Add common private network ranges
                for (ip, prefix) in &[
                    ("10.0.0.0", 8u8),
                    ("172.16.0.0", 12u8),
                    ("192.168.0.0", 16u8),
                    ("127.0.0.0", 8u8),
                ] {
                    let mut e = RuleEntry::default();
                    let addr: Ipv4Addr = ip.parse().unwrap();
                    e.dip[12..16].copy_from_slice(&addr.octets());
                    e.dip_prefix_len = *prefix;
                    e.action = if rule.action == "direct" { 0 } else { 1 };
                    entries.push(e);
                }
                parsed = true;
            } else if let Ok(addr) = cidr.parse::<Ipv4Addr>() {
                // Plain IP address
                entry.dip[12..16].copy_from_slice(&addr.octets());
                entry.dip_prefix_len = 32;
                parsed = true;
            } else if let Some((ip_str, prefix_str)) = cidr.split_once('/') {
                // CIDR format
                if let Ok(addr) = ip_str.parse::<Ipv4Addr>() {
                    if let Ok(prefix) = prefix_str.parse::<u8>() {
                        entry.dip[12..16].copy_from_slice(&addr.octets());
                        entry.dip_prefix_len = prefix.min(32);
                        parsed = true;
                    }
                }
            }
        }

        // Parse dport(...)
        if !parsed {
            if let Some(port_str) = match_expr.strip_prefix("dport(").and_then(|s| s.strip_suffix(')')) {
                if let Ok(port) = port_str.trim().parse::<u16>() {
                    entry.dport = port.to_be();
                    parsed = true;
                }
            }
        }

        // Parse l4proto(...)
        if !parsed {
            if let Some(proto) = match_expr.strip_prefix("l4proto(").and_then(|s| s.strip_suffix(')')) {
                match proto.trim() {
                    "tcp" => { entry.l4proto = 1; parsed = true; },
                    "udp" => { entry.l4proto = 2; parsed = true; },
                    _ => {},
                }
            }
        }

        // If parsed successfully, set the action
        if parsed {
            if rule.action.starts_with("proxy") || rule.action == "proxy" {
                entry.action = 1; // ACTION_PROXY
            } else {
                entry.action = 0; // ACTION_DIRECT
            }
            entries.push(entry);
        }
    }

    Ok(entries)
}

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
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create temp JSON directory: {}", parent.display()))?;
    }

    // Serialize to JSON with pretty printing
    let json = serde_json::to_string_pretty(config)
        .context("Failed to serialize config to JSON")?;

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
        assert_eq!(cp.ebpf_mgr.iface(), "dae0");
        assert!(!cp.ebpf_mgr.is_loaded());
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
        assert_eq!(config.host_addr, "169.254.100.1/30");
        assert_eq!(config.peer_addr, "169.254.100.2/30");
        assert_eq!(config.mtu, 1500);
        assert_eq!(config.route_table, 20230);
        assert_eq!(config.fwmark_proxy, 0x02000000);
        assert_eq!(config.fwmark_bypass, 0x04000000);
        assert_eq!(config.fwmark_mask, 0x0f000000);
        assert_eq!(config.proxy_addr, "127.0.0.1:1080");
        assert_eq!(config.proxy_dial_timeout_ms, 5000);
    }
}
