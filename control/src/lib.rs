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
//! | [`config`] | daefile config parsing, validation & protocol conversion |
//! | [`net`] | Network data plane: eBPF / TProxy / netns / interfaces |
//! | [`routing`] | Routing rule matching & proxy handoff |
//! | [`api`] | REST API server |
//! | [`ruleset`] | Rule set data layer (text domain/IP lists) |
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
pub mod dialer;
pub mod config;
pub mod group;
pub mod net;
pub mod routing;
pub mod ruleset;

use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use protocols::{OutboundDialer, Socks5Dialer};
use net::tproxy::{TproxyListener, UdpTproxyListener};

use crate::net::ebpf::CidrEntry;

// Ringbuf event constants (must match tproxy.c)
#[allow(dead_code)]
const DAE_EVENT_BLOCKED: u32 = 0;
#[allow(dead_code)]
const DAE_EVENT_UDP_CONN_OVERFLOW: u32 = 1;
#[allow(dead_code)]
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
/// | `fwmark_proxy` | 0x08000000 | Proxy traffic mark (TPROXY_MARK) |
/// | `fwmark_bypass` | 0x04000000 | Bypass mark |
/// | `fwmark_mask` | 0x08000000 | Mark mask |
/// | `mtu` | 1500 | Interface MTU |
/// | `log_level` | "info" | Log level |
/// | `proxy_addr` | 127.0.0.1:1080 | SOCKS5 proxy address |
/// | `proxy_username` | "" | SOCKS5 username (empty = no auth) |
/// | `proxy_password` | "" | SOCKS5 password |
/// | `proxy_dial_timeout_ms` | 5000 | SOCKS5 dial timeout (ms) |
#[derive(Debug, Clone, Serialize)]
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tproxy_port: 15080,
            route_table: 2023,
            fwmark_proxy: 0x08000000,
            fwmark_bypass: 0x04000000,
            fwmark_mask: 0x08000000,
            mtu: 1500,
            log_level: "info".into(),
            ebpf_path: net::ebpf::DEFAULT_EBPF_PATH.to_string(),
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
            route_table: runtime.route_table,
            fwmark_proxy: runtime.fwmark_proxy,
            fwmark_bypass: runtime.fwmark_bypass,
            fwmark_mask: runtime.fwmark_mask,
            mtu: runtime.mtu,
            log_level: runtime.log_level.clone(),
            ebpf_path: net::ebpf::DEFAULT_EBPF_PATH.to_string(),
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
    pub ebpf_mgr: Arc<Mutex<net::ebpf::EbpfManager>>,
    /// Network namespace manager
    pub netns_mgr: net::netns::NetnsManager,
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
    iface_mgr: Option<crate::net::iface_mgr::InterfaceManager>,
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
    /// Tokio task handle for the routing handoff consumer
    routing_handoff_handle: Option<tokio::task::JoinHandle<()>>,
    /// Ringbuf consumer background thread
    ringbuf_thread: Option<std::thread::JoinHandle<()>>,
    /// Signal to stop the ringbuf thread
    ringbuf_running: Option<Arc<AtomicBool>>,
    /// Embedded eBPF bytecode (compiled into the binary).
    /// When set, `load()` uses this instead of reading from file.
    pub embedded_ebpf: Option<&'static [u8]>,
    /// Daeparam to pass to the eBPF program before loading.
    pub ebpf_param: Option<crate::net::ebpf::Daeparam>,

    /// UDP connection state tracker (for UDP flow cleanup in janitor)
    udp_tracker: Option<Arc<Mutex<crate::net::udp_tracker::UdpConnStateTracker>>>,
    /// Userspace routing matcher (used by routing handoff consumer)
    routing_matcher: Option<Arc<crate::routing::matcher::RoutingMatcher>>,
    /// Outbound dialer built from the configured proxy node/group.
    ///
    /// Built once before the TProxy starts, then shared between the TProxy
    /// listeners.
    outbound_dialer: Option<Arc<dyn OutboundDialer>>,
    /// Outbound dialers keyed by outbound **group name**. TProxy keeps using
    /// [`Self::outbound_dialer`] (first node / default).
    outbound_group_dialers: HashMap<String, Arc<dyn OutboundDialer>>,
    /// Current routing epoch slot (0 or 1) for double-buffering.
    /// On each reload, we write to the non-active slot, then flip.
    current_epoch_slot: u32,
    /// Datapath generation counter. Incremented on each reload so the
    /// eBPF datapath can detect stale conn_state entries.
    datapath_generation: u16,
    /// Rule set scheduler background task (Phase 2). `None` means no `rule_set` configured.
    rule_set_scheduler: Option<ruleset::scheduler::SchedulerHandle>,
    /// Rule set update completion notification receiver (value increments on successful update).
    /// Used for Phase 3 hot-reload wiring (Routing recompilation / eBPF double-buffer switch).
    pub rule_set_notifier: Option<tokio::sync::watch::Receiver<u64>>,
    /// Pre-compiled routing rules (compiled before eBPF loading).
    ///
    /// Compilation is moved before eBPF loading so that once TC is attached
    /// (Step 3), the routing maps can be written immediately instead of waiting
    /// ~33 seconds for CIDR processing. This eliminates the `wan_route_fail`
    /// spike during startup where TCP SYNs arrive before any rules exist.
    compiled_routing: Option<routing::matcher::CompiledRouting>,
    /// Ruleset in-memory cache (shared by matcher compilation).
    ///
    /// Scanned and populated from `/var/lib/dae-rs/` at startup; refreshed by background watcher after scheduler updates complete.
    pub rule_set_cache: ruleset::cache::RuleSetCache,
    /// Ruleset update → hot-reload signal receiver (filled by background watcher).
    ///
    /// Consumed by the external main loop (or [`ControlPlane::handle_rule_set_reloads`]),
    /// to execute Routing recompilation + eBPF double-buffer hot-reload.
    rule_set_reload_rx: Option<tokio::sync::mpsc::UnboundedReceiver<()>>,
    /// Internal DNS forwarder (runs in the host namespace; `None` when disabled).
    dns_forwarder: Option<Arc<crate::net::dns::DnsForwarder>>,
    /// Tokio task handle for the DNS forwarder.
    dns_handle: Option<tokio::task::JoinHandle<()>>,
}

impl ControlPlane {
    /// Convenience accessor for the locked eBPF manager.
    /// Recovers from mutex poisoning by extracting the inner guard.
    fn ebpf(&self) -> std::sync::MutexGuard<'_, net::ebpf::EbpfManager> {
        self.ebpf_mgr.lock().unwrap_or_else(|poisoned| {
            tracing::warn!("ebpf_mgr mutex was poisoned, recovering");
            poisoned.into_inner()
        })
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
        let ebpf_mgr = Arc::new(Mutex::new(net::ebpf::EbpfManager::new_with_path(
            net::netns::HOST_IF,
            &config.ebpf_path,
        )));
        let netns_mgr = net::netns::NetnsManager::new();
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
            routing_handoff_handle: None,
            udp_tracker: Some(Arc::new(
                Mutex::new(net::udp_tracker::UdpConnStateTracker::new()),
            )),
            iface_mgr: None,
            ringbuf_thread: None,
            ringbuf_running: None,
            embedded_ebpf: None,
            ebpf_param: None,
            routing_matcher: None,
            outbound_dialer: None,
            outbound_group_dialers: HashMap::new(),
            current_epoch_slot: 0,
            datapath_generation: 0,
            rule_set_scheduler: None,
            rule_set_notifier: None,
            rule_set_cache: ruleset::cache::RuleSetCache::new(),
            compiled_routing: None,
            rule_set_reload_rx: None,
            dns_forwarder: None,
            dns_handle: None,
        }
    }

    /// Start the control plane
    ///
    /// Executes the following startup sequence in order:
    ///
    /// 0. **Download rule set data files** — Fetch missing sets (with SOCKS5 proxy if needed)
    /// 0.5. **Compile routing rules** — CPU-intensive compilation before eBPF is even loaded
    /// 1. **Create network namespace** — Call [`NetnsManager::create()`]
    ///    - Create anonymous network namespace
    ///    - Create and configure veth pair
    ///    - Configure policy routing
    /// 2. **Load eBPF program** — Call [`EbpfManager::load()`]
    ///    - Load eBPF object from bytecode file
    /// 3. **Attach TC programs** — Call [`EbpfManager::attach_tc()`]
    ///    - Attach ingress/egress programs to the host-side veth interface
    /// 3.5. **Write eBPF maps** — Write exclusion list and pre-compiled routing rules
    ///    - Write process exclusion list from daefile config
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
        let start_time = std::time::Instant::now();
        info!("Control plane starting...");

        debug!(
            tproxy_port = self.config.tproxy_port,
            route_table = self.config.route_table,
            fwmark_proxy = format!("{:#x}", self.config.fwmark_proxy),
            mtu = self.config.mtu,
            proxy_addr = %self.config.proxy_addr,
            "Control plane start() invoked with config"
        );

        // ---- Step 0: Download missing rule set data files ----
        // Before creating the network namespace or loading eBPF, ensure all rule set
        // data files are available on disk. This prevents E2103 compilation errors
        // in Step 3.5 when rule set data is referenced in routing rules but the
        // corresponding files have not been downloaded yet.
        //
        // If the download requires a proxy (e.g., the rule set URL is only
        // reachable through the proxy), we start a local SOCKS5 server that
        // forwards through the outbound dialer. This way, any protocol
        // (Shadowsocks, Trojan, etc.) is supported — the download only needs
        // a plain SOCKS5 endpoint on localhost.
        if let Some(ref dc) = self.daefile_config {
            if !dc.rule_set.is_empty() {
                let dir = ruleset::DataDir::default_dir();
                let scanned = match dir.scan(&dc.rule_set).await {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(error = %e, "rule set scan failed; proceeding without pre-download");
                        Default::default()
                    }
                };
                let missing: Vec<&str> = scanned
                    .iter()
                    .filter(|(_, s)| s.data.is_none() && !s.damaged)
                    .map(|(name, _)| name.as_str())
                    .collect();
                if !missing.is_empty() {
                    info!(
                        "Step 0/5: {} rule set data file(s) missing — downloading before startup: {:?}",
                        missing.len(),
                        missing
                    );
                    // Build the outbound dialer and start a local SOCKS5 server
                    // so downloads can use any proxy protocol (Shadowsocks,
                    // Trojan, etc.) not just SOCKS5.
                    let (socks5_server, socks5_addr) =
                        if !dc.outbounds.nodes.is_empty() {
                            match self.build_outbound_dialer(None, 0) {
                                Ok(dialer) => {
                                    let local_addr: SocketAddr =
                                        ([127, 0, 0, 1], 0).into();
                                    match crate::net::socks5_server::Socks5LocalServer::start(
                                        dialer, local_addr,
                                    )
                                    .await
                                    {
                                        Ok(server) => {
                                            let addr = server.addr();
                                            info!(
                                                "Local SOCKS5 proxy started at {} for rule set downloads",
                                                addr
                                            );
                                            (Some(server), Some(addr))
                                        }
                                        Err(e) => {
                                            warn!(
                                                error = %e,
                                                "Failed to start local SOCKS5 server; \
                                                 falling back to direct download"
                                            );
                                            (None, None)
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        error = %e,
                                        "Failed to build outbound dialer; \
                                         falling back to direct download"
                                    );
                                    (None, None)
                                }
                            }
                        } else {
                            (None, None)
                        };
                    for cfg in &dc.rule_set {
                        if missing.contains(&cfg.name.as_str()) {
                            info!("Downloading rule set '{}' (url: {})", cfg.name, cfg.url);
                            match ruleset::download::update_rule_set(
                                cfg,
                                &dir,
                                socks5_addr,
                            )
                            .await
                            {
                                Ok(outcome) => {
                                    match outcome {
                                        ruleset::UpdateOutcome::Updated(_) => {
                                            info!(
                                                "Rule set '{}' downloaded successfully",
                                                cfg.name
                                            );
                                        }
                                        ruleset::UpdateOutcome::NotModified => {
                                            info!("Rule set '{}' not modified (304)", cfg.name);
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        name = %cfg.name,
                                        error = %e,
                                        "Failed to download rule set; \
                                         will retry in background via scheduler"
                                    );
                                }
                            }
                        }
                    }
                    // Drop the SOCKS5 server (shuts down the background task)
                    drop(socks5_server);
                } else {
                    debug!("All rule set data files present on disk");
                }
            }
        }

        // ---- Step 0.4: Suppress redundant update_on_start ----
        // Step 0 just verified all rule set data files are on disk (either
        // already existed or were freshly downloaded). The scheduler's
        // `update_on_start` would fire another HTTP request for the same data,
        // which is redundant — Step 0 already got the latest version via ETag.
        // Clear the flag so the scheduler skips the startup download.
        if let Some(ref mut dc) = self.daefile_config {
            for entry in &mut dc.rule_set {
                entry.update_on_start = false;
            }
        }

        // ---- Step 0.5: Compile routing rules before eBPF loading ----
        // Compilation is done here so that once TC is attached (Step 3), the
        // routing maps can be written immediately. This eliminates the ~33s
        // window where TCP SYNs arrive before any rules exist.
        if let Some(ref dc) = self.daefile_config {
            if self.compiled_routing.is_none() {
                let compile_start = std::time::Instant::now();
                // Load rule set cache from disk if not already loaded.
                if !dc.rule_set.is_empty() && self.rule_set_cache.is_empty() {
                    let dir = ruleset::DataDir::default_dir();
                    let map = ruleset::load_cache_from_dir(&dir, &dc.rule_set).await;
                    info!(
                        n = map.len(),
                        n_configured = dc.rule_set.len(),
                        "Pre-loaded rule set memory cache from disk"
                    );
                    self.rule_set_cache.replace_all(map);
                }
                let proxy_server_ips = collect_proxy_server_ips(&self.config, &dc.outbounds);
                if !proxy_server_ips.is_empty() {
                    info!(
                        "Collected {} proxy server IP(s) for auto-direct rules: {:?}",
                        proxy_server_ips.len(),
                        proxy_server_ips
                    );
                }
                let compiled = routing::matcher::compile_rules(
                    &dc.routing,
                    &dc.outbounds,
                    &proxy_server_ips,
                    Some(&self.rule_set_cache),
                )
                .context("Failed to compile routing rules")?;
                info!(
                    "Step 0.5/5: Routing rules pre-compiled ({} match_sets, {} lpm_tries, {} domain_sets) in {}ms",
                    compiled.match_sets.len(),
                    compiled.lpm_tries.len(),
                    compiled.domain_sets.len(),
                    compile_start.elapsed().as_millis(),
                );
                self.compiled_routing = Some(compiled);
            }
        }

        // ---- Step 1: Create network namespace ----
        info!("Step 1/5: Creating network namespace and veth pair");
        let step_start = std::time::Instant::now();
        self.netns_mgr.create().await.map_err(|e| {
            error!("Failed to create network namespace: {}", e);
            e
        })?;
        debug!("Step 1 completed: {}ms", step_start.elapsed().as_millis());

        // ---- Step 1.25: Diagnostic: record link pair type ----
        info!(
            "Netns create completed, use_netkit={}, host_if={}, peer_if={}",
            self.netns_mgr.is_netkit(),
            self.netns_mgr.host_if(),
            self.netns_mgr.peer_if(),
        );

        // ---- Step 1.5: Set eBPF PARAM with netns information ----
        // Now that netns is created, we can set dae0_ifindex, dae_netns_id, dae0peer_mac
        let step_start = std::time::Instant::now();
        if let Some(ref mut param) = self.ebpf_param {
            // Get dae0 ifindex in host NS
            param.dae0_ifindex = self
                .netns_mgr
                .get_host_ifindex()
                .map_err(|e| anyhow::anyhow!("failed to get dae0 ifindex: {}", e))?;
            info!("Set PARAM.dae0_ifindex = {}", param.dae0_ifindex);

            // Get proxy netns inode (dae_netns_id)
            param.dae_netns_id = self
                .netns_mgr
                .get_proxy_netns_inode()
                .map_err(|e| anyhow::anyhow!("failed to get proxy namespace inode: {}", e))?;
            info!("Set PARAM.dae_netns_id = {}", param.dae_netns_id);

            // Get dae0peer MAC address
            param.dae0peer_mac = self
                .netns_mgr
                .get_peer_mac()
                .map_err(|e| anyhow::anyhow!("failed to get dae0peer MAC address: {}", e))?;
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
            param.use_redirect_peer = crate::net::ebpf::probe_redirect_peer();
            info!("Set PARAM.use_redirect_peer = {}", param.use_redirect_peer);

            debug!(
                dae0_ifindex = param.dae0_ifindex,
                dae_netns_id = param.dae_netns_id,
                dae0peer_mac = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    param.dae0peer_mac[0], param.dae0peer_mac[1], param.dae0peer_mac[2],
                    param.dae0peer_mac[3], param.dae0peer_mac[4], param.dae0peer_mac[5]),
                tproxy_port = param.tproxy_port,
                control_plane_pid = param.control_plane_pid,
                use_redirect_peer = param.use_redirect_peer,
                "Full PARAM fields set"
            );
        }
        debug!("Step 1.5 completed: {}ms", step_start.elapsed().as_millis());

        // ---- Step 1.75: Verify TCX kernel support ----
        // TCX (BPF_LINK_TYPE_TCX) is the datapath attach mechanism and requires
        // Linux >= 6.6. There is no classic-TC fallback, so fail fast. The old
        // flip-bit handle rotation is gone: TCX links form a chain per hook and
        // carry no handle, so stale-handle conflicts from previous runs cannot
        // occur (links are auto-detached when the process exits).
        if !crate::net::ebpf::probe_tcx_supported() {
            anyhow::bail!("TCX requires Linux >= 6.6; current kernel is unsupported");
        }
        debug!("TCX kernel support verified");

        // ---- Step 2: Load eBPF program ----
        info!("Step 2/5: Loading eBPF program");

        // Set PARAM global variable before loading (if configured)
        if let Some(param) = self.ebpf_param {
            self.ebpf().set_param(&param);
            debug!("eBPF PARAM configured: full struct {:?}", param);
        }

        // Set eBPF map pinning path so maps are automatically pinned to bpffs after load
        // This way connection state can be persisted after dae-rs restart
        self.ebpf()
            .set_pin_path(crate::net::ebpf::BPFFS_PATH.to_string());
        info!("eBPF map pinning enabled: {}", crate::net::ebpf::BPFFS_PATH);

        let load_start = std::time::Instant::now();
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
        debug!("eBPF load completed: {}ms", load_start.elapsed().as_millis());

        // ---- Step 2.5: Initialize outbound_connectivity_map ----
        // BPF ARRAY maps are zero-initialized, but wan_outbound_is_alive()
        // treats 0 as dead. Without this, ALL proxied traffic is SHOT until
        // the first connectivity check runs (~30s after startup).
        if let Err(e) = self.ebpf().init_outbound_connectivity_map() {
            warn!("Failed to init outbound_connectivity_map: {}", e);
            debug!("outbound_connectivity_map init error: {:?}", e);
        } else {
            debug!("outbound_connectivity_map initialized (all outbounds marked alive)");
        }

        // ---- Step 2.51: Initialize dae_ifindex_map with current dae0 ifindex ----
        // This allows the BPF datapath to pick up the ifindex via get_dae0_ifindex()
        // without relying solely on the frozen .rodata PARAM.dae0_ifindex.
        if let Some(ref param) = self.ebpf_param {
            if param.dae0_ifindex != 0 {
                if let Err(e) = self.ebpf().update_dae_ifindex_map(param.dae0_ifindex) {
                    warn!("Failed to init dae_ifindex_map: {}", e);
                } else {
                    debug!("dae_ifindex_map initialized with ifindex={}", param.dae0_ifindex);
                }
            }
        }

        // ---- Step 2.6: Initialize InterfaceManager for dynamic WAN/LAN management ----
        // Replaces the static WAN/LAN TC attachment loop with a dynamic monitor
        // that scans /sys/class/net/ and automatically binds/unbinds eBPF programs
        // as interfaces appear/disappear (lazy-bind/rebind).
        let use_iface_mgr =
            !self.config.wan_interface.is_empty() || !self.config.lan_interface.is_empty();
        if use_iface_mgr {
            info!("Step 2.6/5: Initializing InterfaceManager for WAN/LAN interfaces");
            debug!(
                wan_patterns = ?self.config.wan_interface,
                lan_patterns = ?self.config.lan_interface,
                "InterfaceManager configuration"
            );
            let mut iface_mgr = crate::net::iface_mgr::InterfaceManager::new();

            // Register WAN interface patterns with bind/unbind callbacks
            for pattern in &self.config.wan_interface {
                debug!(pattern = %pattern, "Registering WAN interface pattern");
                let ebpf_bind = self.ebpf_mgr.clone();
                let ebpf_unbind = self.ebpf_mgr.clone();
                iface_mgr
                    .register(
                        pattern,
                        Arc::new(move |ifname| {
                            let mut mgr = ebpf_bind.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                            mgr.attach_wan(ifname)?;
                            configure_kernel_if(ifname);
                            info!("InterfaceManager: WAN TC attached to {}", ifname);
                            Ok(())
                        }),
                        Some(Arc::new(move |ifname| {
                            let mut mgr = ebpf_unbind.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                            mgr.detach_by_iface(ifname)?;
                            restore_kernel_if(ifname);
                            info!("InterfaceManager: WAN TC detached from {}", ifname);
                            Ok(())
                        })),
                    )
                    .await?;
            }

            // Register LAN interface patterns with bind/unbind callbacks
            for pattern in &self.config.lan_interface {
                debug!(pattern = %pattern, "Registering LAN interface pattern");
                let ebpf_bind = self.ebpf_mgr.clone();
                let ebpf_unbind = self.ebpf_mgr.clone();
                iface_mgr
                    .register(
                        pattern,
                        Arc::new(move |ifname| {
                            let mut mgr = ebpf_bind.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                            mgr.attach_lan(ifname)?;
                            configure_kernel_if(ifname);
                            info!("InterfaceManager: LAN TC attached to {}", ifname);
                            Ok(())
                        }),
                        Some(Arc::new(move |ifname| {
                            let mut mgr = ebpf_unbind.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                            mgr.detach_by_iface(ifname)?;
                            restore_kernel_if(ifname);
                            info!("InterfaceManager: LAN TC detached from {}", ifname);
                            Ok(())
                        })),
                    )
                    .await?;
            }

            // Start the background polling task
            let iface_start = std::time::Instant::now();
            iface_mgr.start().await?;
            debug!("InterfaceManager started: {}ms", iface_start.elapsed().as_millis());
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
        let step_start = std::time::Instant::now();
        // Attach dae0_ingress in host NS
        let host_if = self.netns_mgr.host_if().to_string();
        let peer_if = self.netns_mgr.peer_if().to_string();
        self.ebpf().attach_dae0(&host_if).map_err(|e| {
            error!("Failed to attach {}_ingress TC: {}", host_if, e);
            e
        })?;
        configure_kernel_if(&host_if);
        debug!("dae0 ingress TC attached to {}", host_if);
        // Attach dae0peer_ingress in proxy NS
        {
            self.netns_mgr.join_proxy_ns()?;
            self.ebpf().attach_dae0peer(&peer_if).map_err(|e| {
                error!("Failed to attach dae0peer_ingress TC: {}", e);
                e
            })?;
            configure_kernel_if(&peer_if);
            self.netns_mgr.join_host_ns()?;
            debug!("dae0peer ingress TC attached to {} (in proxy NS)", peer_if);
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
                debug!(iface = %wan_if, "WAN TC attach: calling attach_wan + configure_kernel_if");
                self.ebpf().attach_wan(wan_if)?;
                configure_kernel_if(wan_if);
                info!("WAN TC attached to {}", wan_if);
            }
            if self.config.lan_interface.is_empty() {
                info!("No LAN interfaces configured — LAN ingress interception disabled");
            }
            for lan_if in &self.config.lan_interface {
                info!("Attaching LAN eBPF TC programs to {}", lan_if);
                debug!(iface = %lan_if, "LAN TC attach: calling attach_lan + configure_kernel_if");
                self.ebpf().attach_lan(lan_if)?;
                configure_kernel_if(lan_if);
                info!("LAN TC attached to {}", lan_if);
            }
        } else {
            info!("WAN/LAN TC attachment delegated to InterfaceManager (dynamic)");
        }
        debug!("Step 3 completed: {}ms", step_start.elapsed().as_millis());

        // ---- Step 3.5: Write eBPF maps (exclusion list + rules) ----
        info!("Step 3.5/5: Writing eBPF maps (exclusion list + rules)");
        let step_start = std::time::Instant::now();

        // 3.5a. Write excluded process names and PIDs (from daefile config)
        if let Some(ref dc) = self.daefile_config {
            if let Some(ref pe) = dc.process_exclusion {
                if pe.enabled {
                    debug!("Process exclusion is enabled");
                    // Write comm exclusion list
                    if !pe.r#match.comm.is_empty() {
                        let comm_hashes: Vec<u32> = pe
                            .r#match
                            .comm
                            .iter()
                            .map(|c| crate::net::ebpf::hash_comm(c))
                            .collect();
                        debug!(
                            comms = ?pe.r#match.comm,
                            hashes = ?comm_hashes,
                            "Writing excluded comm hashes"
                        );
                        self.ebpf().write_excluded_comm(&comm_hashes)?;
                        info!(
                            "Wrote {} excluded comm hashes to eBPF map",
                            comm_hashes.len()
                        );
                    }
                    // Write pid exclusion list
                    if !pe.r#match.pid.is_empty() {
                        debug!(pids = ?pe.r#match.pid, "Writing excluded PIDs");
                        self.ebpf().write_excluded_pids(&pe.r#match.pid)?;
                        info!("Wrote {} excluded PIDs to eBPF map", pe.r#match.pid.len());
                    }
                    // Write tgid exclusion list (shares the same map as pid)
                    if !pe.r#match.tgid.is_empty() {
                        debug!(tgids = ?pe.r#match.tgid, "Writing excluded TGIDs");
                        self.ebpf().write_excluded_pids(&pe.r#match.tgid)?;
                        info!("Wrote {} excluded TGIDs to eBPF map", pe.r#match.tgid.len());
                    }
                } else {
                    debug!("Process exclusion is disabled in config");
                }
            }
        }

        // Note: write_excluded_pids and write_excluded_comm are NOT called here
        // because they write to cookie_pid_map with PID/comm hash keys, but the
        // eBPF program's pid_is_control_plane() looks up by socket cookie (u64),
        // not by PID. Writing PID keys would pollute the map without providing
        // any actual exclusion. dae-rs's own sockets are identified via:
        //   1. cgroup hooks (now attached in both host and proxy NS) register
        //      real socket cookies → pid_is_control_plane cookie match
        //   2. SO_MARK=0x100 fallback on dae-rs's outgoing sockets

        // 3.5b. Write pre-compiled routing rules to eBPF maps.
        // Compilation was done in Step 0.5; this is just fast map writes.
        if let Some(ref compiled) = self.compiled_routing {
            debug!(
                match_sets = compiled.match_sets.len(),
                lpm_tries = compiled.lpm_tries.len(),
                domain_sets = compiled.domain_sets.len(),
                "Writing pre-compiled routing rules to eBPF maps"
            );

            let init_slot = self.current_epoch_slot;

            // Write MatchSet entries to routing_map
            if !compiled.match_sets.is_empty() {
                let write_start = std::time::Instant::now();
                self.ebpf().write_routing_rules(&compiled.match_sets, init_slot)?;
                info!(
                    "Wrote {} MatchSet entries to routing_map slot {} ({}ms)",
                    compiled.match_sets.len(),
                    init_slot,
                    write_start.elapsed().as_millis()
                );
            }

            // Write LPM trie data to inner LPM trie maps
            {
                let mut all_cidr_entries: Vec<(u32, CidrEntry)> = Vec::new();
                for (trie_idx, cidrs) in compiled.lpm_tries.iter().enumerate() {
                    let entries = crate::routing::matcher::cidrs_to_cidr_entries(cidrs);
                    for (_, entry) in entries {
                        all_cidr_entries.push((trie_idx as u32, entry));
                    }
                }
                if !all_cidr_entries.is_empty() {
                    let write_start = std::time::Instant::now();
                    self.ebpf().write_cidr_table(&all_cidr_entries, init_slot)?;
                    info!(
                        "Wrote {} CIDR entries across {} LPM tries slot {} ({}ms)",
                        all_cidr_entries.len(),
                        compiled.lpm_tries.len(),
                        init_slot,
                        write_start.elapsed().as_millis(),
                    );
                } else {
                    debug!("No CIDR entries to write (no LPM rules)");
                }
            }

            // Set the initial active routing epoch
            if let Err(e) = self.ebpf().update_active_routing_epoch(init_slot) {
                warn!("Failed to set initial active_routing_epoch: {}", e);
            } else {
                info!("Initial active_routing_epoch set to slot {}", init_slot);
            }

            // Set up userspace routing matcher
            self.routing_matcher = Some(Arc::new(
                crate::routing::matcher::RoutingMatcher::from_compiled(compiled),
            ));
            debug!("RoutingMatcher built from pre-compiled rules");

        }
        debug!("Step 3.5 completed: {}ms", step_start.elapsed().as_millis());

        // ---- Step 3.6: Dump generated configuration as JSON for debugging ----
        // This helps diagnose why traffic might not be hijacked — verify routing rules,
        // outbound nodes, process exclusions, etc. are correctly parsed.
        match serde_json::to_string_pretty(&self.config) {
            Ok(json_str) => {
                tracing::debug!("Generated configuration:\n{}", json_str);
            }
            Err(e) => {
                tracing::warn!("Failed to serialize config to JSON: {}", e);
            }
        }

        // ---- Step 3.7: Attach cgroup programs in BOTH namespaces ----
        // The eBPF programs need to track all dae-rs sockets regardless of
        // which network namespace they're created in. Since dae-rs runs
        // components in both:
        //   - Host NS: API server, connectivity checker
        //   - Proxy NS (daens): TProxy listener, SOCKS5 dialer
        //
        // We attach the cgroup programs to both namespaces' cgroups.
        // The cookie_pid_map is shared, so socket cookies from both
        // namespaces are tracked and recognized by pid_is_control_plane().
        info!("Step 3.7/5: Attaching cgroup programs (host NS + proxy NS)");
        let step_start = std::time::Instant::now();

        // Attach in host NS first
        {
            let cgroup_fd = unsafe {
                libc::open(
                    c"/sys/fs/cgroup".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY,
                )
            };
            debug!("cgroup_fd for host NS: {}", cgroup_fd);
            if cgroup_fd >= 0 {
                match self.ebpf().attach_cgroup(cgroup_fd) {
                    Ok(()) => {
                        info!("cgroup programs attached in HOST namespace");
                    }
                    Err(e) => {
                        warn!(
                            "Failed to attach cgroup programs in HOST namespace: {}",
                            e
                        );
                        debug!("cgroup attach host NS error details: {:?}", e);
                    }
                }
                unsafe { libc::close(cgroup_fd) };
            } else {
                warn!("Failed to open /sys/fs/cgroup in host NS (errno={})", unsafe { *libc::__errno_location() });
            }
        }

        // Attach in proxy NS
        {
            self.netns_mgr.join_proxy_ns()?;
            let cgroup_fd = unsafe {
                libc::open(
                    c"/sys/fs/cgroup".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY,
                )
            };
            debug!("cgroup_fd for proxy NS: {}", cgroup_fd);
            if cgroup_fd >= 0 {
                match self.ebpf().attach_cgroup(cgroup_fd) {
                    Ok(()) => {
                        info!("cgroup programs attached in PROXY namespace (daens)");
                    }
                    Err(e) => {
                        warn!(
                            "Failed to attach cgroup programs in PROXY namespace: {}",
                            e
                        );
                        debug!("cgroup attach proxy NS error details: {:?}", e);
                    }
                }
                unsafe { libc::close(cgroup_fd) };
            } else {
                warn!("Failed to open /sys/fs/cgroup in proxy NS (errno={})", unsafe { *libc::__errno_location() });
            }
            self.netns_mgr.join_host_ns()?;
        }
        debug!("Step 3.7 completed: {}ms", step_start.elapsed().as_millis());

        // ---- Step 4: Start TProxy listener ----
        info!("Step 4/5: Starting TProxy listener in proxy namespace");
        let step_start = std::time::Instant::now();
        self.start_tproxy().await?;
        debug!("Step 4 completed: {}ms", step_start.elapsed().as_millis());

        // ---- Step 4.1: Start internal DNS forwarder (if configured) ----
        if self
            .daefile_config
            .as_ref()
            .and_then(|c| c.dns.as_ref())
            .is_some()
        {
            info!("Step 4.1/5: Starting internal DNS forwarder");
            self.start_dns_forwarder().await?;
        }

        // ---- Step 4.5: Start routing handoff consumer ----
        // Consumes entries from routing_handoff_map that the eBPF program
        // produces when it cannot determine the outbound (CONTROL_PLANE_ROUTING).
        // The consumer uses the userspace RoutingMatcher to make the final
        // routing decision and writes it to conn_state_map.
        if let Some(ref matcher) = self.routing_matcher {
            info!("Step 4.5/5: Starting routing handoff consumer");
            let consumer = crate::routing::routing_handoff::RoutingHandoffConsumer::new(
                self.ebpf_mgr.clone(),
                matcher.clone(),
            );
            self.routing_handoff_handle = Some(tokio::spawn(async move {
                consumer.run().await;
            }));
            info!("Routing handoff consumer started");
        } else {
            warn!("No RoutingMatcher available — routing handoff consumer NOT started");
        }

        // ---- Step 4.6: Start rule set scheduler ----
        if let Some(ref dc) = self.daefile_config {
            if !dc.rule_set.is_empty() {
                info!(
                    "Step 4.6/5: Starting rule set scheduler ({} entries)",
                    dc.rule_set.len()
                );
                let entries = dc.rule_set.clone();
                let dir = std::sync::Arc::new(ruleset::DataDir::default_dir());
                // Proxy resolution: every outbound group name → SOCKS5 address
                // of the group's currently selected (alive, policy-best) node.
                // Group dialers are built earlier in start_tproxy().
                let first_node_addr = dc
                    .outbounds
                    .nodes
                    .first()
                    .and_then(|n| n.address.parse::<std::net::SocketAddr>().ok());
                let default_proxy = dc.outbounds.groups.first().map(|g| g.name.clone());
                let proxy_resolver: std::sync::Arc<dyn ruleset::scheduler::ProxyResolver> =
                    std::sync::Arc::new(DefaultProxyResolver {
                        group_dialers: std::sync::Arc::new(self.outbound_group_dialers.clone()),
                        legacy_addr: first_node_addr,
                        default_group: default_proxy.clone(),
                    });
                let scheduler = ruleset::scheduler::RuleSetScheduler::spawn(
                    entries.clone(),
                    dir.clone(),
                    proxy_resolver,
                    default_proxy,
                );
                self.rule_set_notifier = Some(scheduler.notifier.clone());
                self.rule_set_scheduler = Some(scheduler);
                info!("Rule set scheduler spawned");

                // Ruleset update → refresh in-memory cache + trigger Routing hot-reload signal.
                //
                // After each successful update, the watcher:
                //   1. Re-scan disk data directory → refresh `RuleSetCache` (shared with matcher);
                //   2. Send signal via mpsc; main control plane via
                //      [`ControlPlane::handle_rule_set_reloads`] consumes the signal and recompiles
                //      Routing and performs eBPF double-buffer hot-reload (reuses `reload_config`).
                if let Some(notifier) = self.rule_set_notifier.clone() {
                    let cache = self.rule_set_cache.clone();
                    let (reload_tx, reload_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
                    self.rule_set_reload_rx = Some(reload_rx);
                    tokio::spawn(async move {
                        let mut notifier = notifier;
                        while notifier.changed().await.is_ok() {
                            let map = ruleset::load_cache_from_dir(&dir, &entries).await;
                            info!(
                                n = map.len(),
                                "Rule set update detected; refreshed memory cache"
                            );
                            cache.replace_all(map);
                            // Notify main control plane to execute Routing hot-reload
                            let _ = reload_tx.send(());
                        }
                    });
                }
            } else {
                debug!("No rule_set entries — rule set scheduler not started");
            }
        }

        // ---- Step 5: Start background tasks ----
        info!("Step 5/5: Starting background tasks");
        // Ringbuf event consumer (get fd first to release the lock before assigning fields)
        let ringbuf_fd = self.ebpf().event_ringbuf_fd().ok();
        if let Some(fd) = ringbuf_fd {
            debug!("Ringbuf fd obtained: {}", fd);
            let (handle, running) = net::ebpf::EbpfManager::spawn_ringbuf_consumer(fd);
            self.ringbuf_thread = Some(handle);
            self.ringbuf_running = Some(running);
            debug!("Ringbuf consumer spawned");
        } else {
            warn!("Failed to get ringbuf fd, ringbuf consumer not started");
        }
        // Conn_state janitor (with pressure detection)
        debug!("Spawning conn_state janitor");
        self.janitor_handle = Some(Self::spawn_conn_state_janitor(
            self.ebpf_mgr.clone(),
            self.udp_tracker.clone(),
        ));
        debug!("Conn_state janitor spawned");

        // Redirect track janitor (30s interval, 5min TTL)
        debug!("Spawning redirect track janitor");
        self.redirect_track_handle =
            Some(Self::spawn_redirect_track_janitor(self.ebpf_mgr.clone()));
        debug!("Redirect track janitor spawned");

        // Cookie PID map janitor (60s interval, 5min TTL)
        debug!("Spawning cookie PID map janitor");
        self.cookie_pid_handle = Some(Self::spawn_cookie_pid_map_janitor(self.ebpf_mgr.clone()));
        debug!("Cookie PID map janitor spawned");

        // Connectivity checker (proxies health)
        let proxy_addr: std::net::SocketAddr = self.config.proxy_addr.parse()
            .context("Invalid proxy_addr in config")?;
        debug!(
            proxy_addr = %proxy_addr,
            "Starting connectivity checker"
        );
        self.connectivity_handle = Some(Self::start_connectivity_checker(
            self.ebpf_mgr.clone(),
            proxy_addr,
            0,
        ));
        debug!("Connectivity checker spawned");

        self.running = true;
        let total_ms = start_time.elapsed().as_millis();
        debug!("Control plane total startup time: {}ms", total_ms);
        info!("Control plane started successfully");

        // Dump eBPF debug counters for data path diagnosis.
        // This helps identify where in the eBPF pipeline packets are being
        // dropped (e.g., bpf_sk_assign failures, redirect failures, etc.).
        {
            let mut mgr = self.ebpf_mgr.lock().unwrap();
            mgr.log_debug_counters("startup");
        }

        // Log network diagnostics after startup
        match std::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output()
        {
            Ok(o) => info!(
                "Default route: {}",
                String::from_utf8_lossy(&o.stdout).trim()
            ),
            Err(e) => warn!("Could not query default route: {}", e),
        }
        if let Ok(o) = std::process::Command::new("ip").args(["link"]).output() { info!("Links:\n{}", String::from_utf8_lossy(&o.stdout)) }

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
    /// Build the outbound dialer from the configured proxy node, or the legacy
    /// flat config fields (single SOCKS5 node) when no daefile nodes exist.
    ///
    /// The result is cached in `self.outbound_dialer` so the TProxy listeners
    /// share one dialer.
    fn build_outbound_dialer(
        &self,
        host_ns_fd: Option<i32>,
        socket_mark: u32,
    ) -> anyhow::Result<Arc<dyn OutboundDialer>> {
        match self
            .config
            .daefile_config
            .as_ref()
            .and_then(|c| c.outbounds.nodes.first())
        {
            Some(node) => {
                let d = dialer::build_dialer(node, host_ns_fd, socket_mark)?;
                info!(
                    node = %node.name,
                    protocol = %node.protocol,
                    address = %node.address,
                    "Outbound dialer built from node config"
                );
                Ok(d)
            }
            None => {
                // Fallback: legacy flat config fields (single SOCKS5 node).
                let proxy_addr: SocketAddr = self.config.proxy_addr.parse().map_err(|e| {
                    anyhow::anyhow!("Invalid proxy address '{}': {}", self.config.proxy_addr, e)
                })?;
                debug!(
                    proxy_addr = %proxy_addr,
                    proxy_has_username = !self.config.proxy_username.is_empty(),
                    proxy_dial_timeout_ms = self.config.proxy_dial_timeout_ms,
                    "Legacy SOCKS5 dialer configuration (no daefile nodes)"
                );
                let mut d = Socks5Dialer::new_with_mark(
                    proxy_addr,
                    &self.config.proxy_username,
                    &self.config.proxy_password,
                    self.config.proxy_dial_timeout_ms,
                    socket_mark,
                );
                d.set_host_ns_fd(host_ns_fd);
                Ok(Arc::new(d))
            }
        }
    }

    /// Build outbound dialers for every outbound **group**, keyed by group name.
    ///
    /// Each group gets a [`group::GroupDialer`] wrapping **every** concrete
    /// node its selectors reference. The group dialer implements the group's
    /// selection policy and alive-node fallback: on a failed dial it marks the
    /// node dead (with cooldown) and retries the next best candidate, so a
    /// single group can span multiple nodes.
    ///
    /// Groups that fail to resolve any node are skipped.
    fn build_outbound_group_dialers(
        &self,
        host_ns_fd: Option<i32>,
        socket_mark: u32,
    ) -> HashMap<String, Arc<dyn OutboundDialer>> {
        let mut map: HashMap<String, Arc<dyn OutboundDialer>> = HashMap::new();
        let Some(cfg) = self.config.daefile_config.as_ref() else {
            return map;
        };

        for group in &cfg.outbounds.groups {
            // Resolve every concrete node referenced by the group's selectors.
            let candidates = resolve_group_nodes(group, &cfg.outbounds.nodes);
            if candidates.is_empty() {
                warn!(
                    group = %group.name,
                    "Outbound group has no resolvable node (skipped)"
                );
                continue;
            }

            // Build a dialer per candidate node; skip nodes that fail to build.
            let mut group_nodes: Vec<group::GroupNode> = Vec::new();
            for node in candidates {
                match dialer::build_dialer(node, host_ns_fd, socket_mark) {
                    Ok(d) => group_nodes.push(group::GroupNode::new(node.name.clone(), d)),
                    Err(e) => {
                        warn!(
                            group = %group.name,
                            node = %node.name,
                            "Failed to build node dialer (skipped from group): {}",
                            e
                        );
                    }
                }
            }
            if group_nodes.is_empty() {
                warn!(
                    group = %group.name,
                    "Outbound group has no buildable node dialer (skipped)"
                );
                continue;
            }

            // `select` groups anchor on their chosen node: move it to the front
            // and force Fixed selection (selection = the anchored node, with
            // fallback to the rest when it's dead). `auto` groups use policy.
            let (policy, group_nodes) = match (
                group.group_type.clone(),
                group.selected.clone().as_deref(),
            ) {
                (config::GroupType::Select, Some(selected)) => {
                    let mut anchored = Vec::with_capacity(group_nodes.len());
                    if let Some(pos) = group_nodes.iter().position(|n| n.name() == selected) {
                        anchored.push(group_nodes.remove(pos));
                    }
                    anchored.extend(group_nodes);
                    (config::PolicyType::Fixed, anchored)
                }
                _ => (group.policy.clone().unwrap_or_default(), group_nodes),
            };

            let dialer = group::GroupDialer::new(group.name.clone(), group_nodes, policy);
            debug!(
                group = %group.name,
                nodes = dialer.node_count(),
                policy = ?&dialer.policy(),
                "Outbound group dialer built (node selection + fallback enabled)"
            );
            map.insert(group.name.clone(), Arc::new(dialer));
        }
        map
    }

    /// Creates a SOCKS5 dialer and TProxy listener in the HOST namespace.
    async fn start_tproxy(&mut self) -> Result<()> {
        let start_time = std::time::Instant::now();
        debug!("start_tproxy: beginning TProxy setup");

        // ---- Host network namespace fd ----
        // TProxy listen socket remains in daens, but all upstream connections (to proxy,
        // TCP, UDP ASSOCIATE, UDP relay response sockets) are created in host NS
        // and issued (aligned with kdae), source address is the host real WAN address.
        let host_ns_fd = self.netns_mgr.get_host_ns_fd();
        info!(
            host_ns_fd = host_ns_fd.map(|fd| fd.to_string()).unwrap_or_else(|| "none".to_string()),
            "Upstream sockets will be created in host namespace (kdae-aligned)"
        );

        let socket_mark = shared::DAE_SOCKET_MARK;
        debug!(socket_mark = format!("{:#x}", socket_mark), "Socket mark for eBPF self-exclusion");
        let tproxy_listener_mark = 0u32;
        debug!(
            tproxy_listener_mark = format!("{:#x}", tproxy_listener_mark),
            "TProxy listener socket mark for daens policy routing"
        );

        // ---- Construct outbound Dialer according to configured protocol ----
        // Reuse the already-built dialer if present; otherwise build it now.
        let dialer: Arc<dyn OutboundDialer> = if let Some(d) = self.outbound_dialer.clone() {
            d
        } else {
            let d = self.build_outbound_dialer(host_ns_fd, socket_mark)?;
            self.outbound_dialer = Some(d.clone());
            d
        };
        debug!("Outbound dialer created: {}", dialer.protocol_name());

        // ---- Build per-group outbound dialers ----
        // Build a dialer for every outbound group once, keyed by group name.
        if self.outbound_group_dialers.is_empty() {
            let group_dialers = self.build_outbound_group_dialers(host_ns_fd, socket_mark);
            self.outbound_group_dialers = group_dialers;
            debug!(
                groups = self.outbound_group_dialers.len(),
                "Per-group outbound dialers built"
            );
        }

        // ---- Main data plane: use the default group's GroupDialer ----
        // 主数据面（TCP/UDP 中继）默认走"第一个出站组"的 GroupDialer，从而获得
        // 与 DNS/规则集调度器一致的组内节点选择 + 存活回退。无组配置
        // （legacy 平铺单节点）时保留上面的单节点拨号器。
        if let Some(default_group) = self
            .daefile_config
            .as_ref()
            .and_then(|c| c.outbounds.groups.first())
        {
            if let Some(group_dialer) = self.outbound_group_dialers.get(&default_group.name) {
                info!(
                    group = %default_group.name,
                    "Main data plane uses default outbound group dialer (node selection + fallback)"
                );
                self.outbound_dialer = Some(group_dialer.clone());
            }
        }
        let dialer = self
            .outbound_dialer
            .clone()
            .expect("outbound dialer must be present after start_tproxy");

        // ---- TProxy listener (in DAENS) ----
        // eBPF data flow:
        // 1. WAN egress TC intercepts SYN packets
        // 2. Redirect to dae0 → dae0peer (enter daens)
        // 3. dae0peer_ingress TC: set skb->mark = TPROXY_MARK
        // 4. Policy Routing in daens: fwmark → table 2023 → local default dev lo
        // 5. TProxy socket (in daens) accepts connection
        // 6. TProxy forwards via dae0peer → dae0 to host NS → upstream proxy
        let listen_addr: SocketAddr = format!("[::]:{}", self.config.tproxy_port)
            .parse()
            .map_err(|e| {
                anyhow::anyhow!(
                    "Invalid TProxy listen address (port {}): {}",
                    self.config.tproxy_port,
                    e
                )
            })?;
        debug!(listen_addr = %listen_addr, "TProxy listen address");

        let tproxy_tcp = {
            let tcp = TproxyListener::new_with_mark(
                listen_addr,
                dialer.clone(),
                tproxy_listener_mark,
            );
            Arc::new(tcp)
        };
        let tproxy_udp = {
            let mut udp = UdpTproxyListener::new_with_mark(
                listen_addr,
                dialer,
                tproxy_listener_mark,
            );
            // Upstream UDP sockets are created in the host NS when host_ns_fd is available.
            udp.set_host_ns_fd(host_ns_fd);
            // ---- Attach the internal DNS forwarder (transparent port-53 hijack) ----
            // eBPF 不改动：DNS 仍被当作普通 UDP 拦截进 TProxy；这里仅在用户空间把
            // 53 端口 DNS 流量交给 DNS 模块。DNS 自身不定义代理规则——域名路由表
            // 与 fallback 全部由现有 `routing` 规则推导，查询走域名命中的代理组。
            if let Some(cfg) = self.daefile_config.as_ref().and_then(|c| c.dns.clone()) {
                let (routes, fallback) = match self.daefile_config.as_ref() {
                    Some(c) => {
                        let routes = crate::routing::matcher::build_dns_domain_routes(
                            &c.routing,
                            Some(&self.rule_set_cache),
                        )?;
                        let fallback = crate::routing::matcher::dns_outbound_from_action(
                            &c.routing.fallback,
                        )?;
                        (routes, fallback)
                    }
                    None => (
                        Vec::new(),
                        crate::routing::matcher::DnsOutbound::Direct,
                    ),
                };
                let dns_fwd = Arc::new(crate::net::dns::DnsForwarder::new(
                    &cfg,
                    routes,
                    self.outbound_group_dialers.clone(),
                    fallback,
                    host_ns_fd,
                )?);
                info!(
                    listen = %cfg.listen_addr,
                    "DNS forwarder attached to UDP TProxy (transparent port-53 DNS, \
                     routing-derived domain split)"
                );
                udp.set_dns_forwarder(dns_fwd.clone());
                self.dns_forwarder = Some(dns_fwd);
            }
            Arc::new(udp)
        };

        // ---- Add host namespace policy routing ----
        // Host NS policy Routing: marked packet → local default dev lo → TProxy socket
        // (for marked packets entering host NS via daens through dae0peer → dae0)
        debug!("Adding host namespace policy routing");
        let route_start = std::time::Instant::now();
        self.netns_mgr
            .add_host_policy_routing()
            .await
            .context("Failed to add host namespace policy routing")?;
        debug!(
            "Host policy routing added: {}ms",
            route_start.elapsed().as_millis()
        );

        info!(
            listen_addr = %listen_addr,
            "Launching TProxy in DAENS (proxy namespace)"
        );

        // ---- Start TProxy INSIDE daens ----
        // Original dae starts TProxy listener in daens.
        // This way eBPF Routed marked packets are directly delivered to TProxy socket via daens policy Routing.
        // TProxy upstream connections (to SOCKS5 proxy) use SO_MARK=0x100,
        // identified and passed through by eBPF pid_is_control_plane().
        let proxy_ns_fd = self
            .netns_mgr
            .get_proxy_ns_fd()
            .ok_or_else(|| anyhow::anyhow!("Proxy namespace not created"))?;
        debug!(proxy_ns_fd, "Proxy namespace fd obtained for TProxy thread");

        let tproxy_tcp_clone = tproxy_tcp.clone();
        let tproxy_udp_clone = tproxy_udp.clone();
        let ebpf_mgr_clone = self.ebpf_mgr.clone();
        use std::os::unix::io::BorrowedFd;
        let thread_handle = std::thread::spawn(move || {
            debug!("TProxy thread spawned, entering daens...");
            // ---- Enter daens ----
            // TProxy must run in daens because eBPF Routed marked packets
            // are delivered to local lo via daens policy Routing.
            let borrowed_fd = unsafe { BorrowedFd::borrow_raw(proxy_ns_fd) };
            if let Err(e) = nix::sched::setns(borrowed_fd, nix::sched::CloneFlags::CLONE_NEWNET) {
                error!("Failed to enter daens for TProxy listener: {}", e);
                return;
            }
            info!("Entered daens for TProxy listener");

            let rt_start = std::time::Instant::now();
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
            debug!(
                "TProxy tokio runtime created: {}ms",
                rt_start.elapsed().as_millis()
            );

            let result = rt.block_on(async {
                // Bind separate AF_INET + AF_INET6 TCP listeners (in daens).
                // AF_INET  socket → SOCKMAP key 0 (tcp4) — handles IPv4 traffic
                // AF_INET6 socket → SOCKMAP key 2 (tcp6) — handles IPv6 traffic
                // This matches the original dae implementation and avoids the bug
                // where bpf_sk_assign() assigns an AF_INET6 socket to IPv4 packets.
                info!(
                    "Binding TProxy TCP listeners on port {} in daens",
                    tproxy_tcp_clone.listen_addr().port()
                );
                let bind_start = std::time::Instant::now();
                let (listener_tcp_v4, listener_tcp_v6) = match tproxy_tcp_clone.bind().await {
                    Ok(pair) => pair,
                    Err(e) => {
                        error!("Failed to bind TProxy TCP sockets: {}", e);
                        return Err(e);
                    }
                };
                debug!(
                    "TProxy TCP bind completed: {}ms",
                    bind_start.elapsed().as_millis()
                );

                // ---- Populate listen_socket_map for bpf_sk_assign ----
                // Insert separate socket FDs into the SOCKMAP:
                //   key 0 → AF_INET  socket (tcp4) — for IPv4 traffic
                //   key 2 → AF_INET6 socket (tcp6) — for IPv6 traffic
                {
                    use std::os::unix::io::AsRawFd;
                    let raw_fd_v4 = listener_tcp_v4.as_raw_fd();
                    let raw_fd_v6 = listener_tcp_v6.as_raw_fd();
                    let mut mgr = ebpf_mgr_clone.lock().unwrap();
                    // Key 0 = tcp4 (AF_INET socket)
                    if let Err(e) = mgr.update_listen_socket_map(0, raw_fd_v4) {
                        error!("Failed to update listen_socket_map for tcp4: {}", e);
                    } else {
                        debug!("listen_socket_map[0] = {} (AF_INET)", raw_fd_v4);
                    }
                    // Key 2 = tcp6 (AF_INET6 socket)
                    if let Err(e) = mgr.update_listen_socket_map(2, raw_fd_v6) {
                        error!("Failed to update listen_socket_map for tcp6: {}", e);
                    } else {
                        debug!("listen_socket_map[2] = {} (AF_INET6)", raw_fd_v6);
                    }
                }

                info!(
                    "TProxy TCP listeners starting on port {} in daens",
                    tproxy_tcp_clone.listen_addr().port()
                );

                // Run TCP and UDP listeners concurrently
                let serve_start = std::time::Instant::now();
                let (tcp_result, udp_result) = tokio::join!(
                    tproxy_tcp_clone.serve(listener_tcp_v4, listener_tcp_v6),
                    tproxy_udp_clone.start(Some(ebpf_mgr_clone.clone()))
                );

                if let Err(e) = tcp_result {
                    error!("TProxy TCP listener error: {}", e);
                }
                if let Err(e) = udp_result {
                    error!("TProxy UDP listener error: {}", e);
                }

                debug!(
                    "TProxy serve duration: {}ms",
                    serve_start.elapsed().as_millis()
                );

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

        let elapsed_ms = start_time.elapsed().as_millis();
        debug!("start_tproxy completed: {}ms", elapsed_ms);
        info!("TProxy listener launching in background thread (in daens)");
        Ok(())
    }

    /// Start the internal DNS forwarder listener (if configured).
    ///
    /// The forwarder instance itself is built during [`ControlPlane::start_tproxy`] and
    /// attached to the UDP TProxy listener (transparent port-53 DNS hijack, no eBPF
    /// change). This step additionally starts the standalone listener on the internal
    /// address (e.g. `169.254.0.1:53`) for dae-rs's own / explicitly-pointed queries.
    async fn start_dns_forwarder(&mut self) -> Result<()> {
        let start_time = std::time::Instant::now();
        let Some(forwarder) = self.dns_forwarder.clone() else {
            debug!("dns not configured — internal DNS forwarder disabled");
            return Ok(());
        };

        // ---- Ensure the internal listen address exists on host lo ----
        let listen_addr = forwarder.listen_addr();
        let prefix = if listen_addr.is_ipv4() { 32 } else { 128 };
        let cidr = format!("{}/{}", listen_addr.ip(), prefix);
        self.netns_mgr.add_internal_lo_addr(&cidr).await?;

        // ---- Spawn the standalone listener on the shared runtime (host NS) ----
        let f = forwarder.clone();
        self.dns_handle = Some(tokio::spawn(async move {
            if let Err(e) = f.start().await {
                error!("DNS forwarder listener exited with error: {}", e);
            }
        }));

        info!(
            "DNS forwarder listener started in {}ms (listen {})",
            start_time.elapsed().as_millis(),
            listen_addr,
        );
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
        ebpf_mgr: Arc<Mutex<crate::net::ebpf::EbpfManager>>,
        udp_tracker: Option<Arc<Mutex<crate::net::udp_tracker::UdpConnStateTracker>>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            info!("ConnState janitor started with pressure detection");

            use crate::net::ebpf::{PRESSURE_ENTER_USAGE, PRESSURE_EXIT_ROUNDS, PRESSURE_EXIT_USAGE};

            let mut pressure_rounds: u32 = 0;
            let mut in_pressure = false;

            loop {
                let interval = if in_pressure {
                    std::time::Duration::from_secs(1) // pressure mode: 1s
                } else {
                    std::time::Duration::from_secs(5) // steady-state mode: 5s
                };
                tokio::time::sleep(interval).await;

                let now_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;

                // ---- Step 1: Collect expired UDP tracker entries (without holding ebpf lock) ----
                // Acquire ebpf_mgr lock FIRST, then udp_tracker lock SECOND.
                // This guarantees a single lock acquisition order (ebpf → udp_tracker) across
                // all code paths, preventing AB-BA deadlock.
                let (expired_udp_keys, mut mgr) = {
                    let mgr = match ebpf_mgr.lock() {
                        Ok(m) => m,
                        Err(e) => {
                            warn!("Janitor lock error: {}", e);
                            continue;
                        }
                    };
                    let expired_udp_keys = if let Some(ref tracker) = udp_tracker {
                        if let Ok(mut tracker_guard) = tracker.lock() {
                            tracker_guard.cleanup_expired()
                        } else {
                            Vec::new()
                        }
                    } else {
                        Vec::new()
                    };
                    (expired_udp_keys, mgr)
                };

                // ---- Step 1b: Delete expired UDP entries from conn_state_map ----
                if !expired_udp_keys.is_empty() {
                    for key in &expired_udp_keys {
                        let _ = mgr.delete_conntrack(key);
                    }
                    debug!(
                        "Janitor: deleted {} expired entries from UDP tracker",
                        expired_udp_keys.len()
                    );
                }

                // ---- Step 2: Scan conn_state_map for expired entries ----
                match mgr.janitor_scan_conn_state(now_ns, in_pressure) {
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
                                    pressure_rounds = 0; // above threshold, reset the counter
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
        ebpf_mgr: Arc<Mutex<crate::net::ebpf::EbpfManager>>,
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
        ebpf_mgr: Arc<Mutex<crate::net::ebpf::EbpfManager>>,
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
    /// - domain: 0=TCP, 1=reserved, 2=data UDP
    /// - ipversion: 0=IPv4, 1=IPv6
    pub fn start_connectivity_checker(
        ebpf_mgr: Arc<Mutex<crate::net::ebpf::EbpfManager>>,
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
                // Dump eBPF debug counters periodically (helps diagnose data path issues)
                {
                    if let Ok(mut mgr) = ebpf_mgr.lock() {
                        mgr.log_debug_counters("connectivity");
                    }
                }

                tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;

                // TCP health check: try marked (SO_MARK=0x100) first, then plain
                let marked_result = connect_with_mark(&proxy_addr, shared::DAE_SOCKET_MARK, 5).await;
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
                if plain_result.is_err() {
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

                // For data UDP, we use the same TCP health as a proxy.
                // In a full implementation, actual UDP probing would be done.
                let _ = mgr.update_outbound_connectivity(
                    outbound_id,
                    2, // domain: 2=data UDP
                    false,
                    false, // ipv: 0=IPv4
                    tcp_alive,
                );

                debug!(
                    "Connectivity: tcp={}, udp={}",
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
    pub fn detach_bpf_hooks(&mut self) {
        info!("Emergency BPF hook detachment");
        let start = std::time::Instant::now();
        // Detach dae0peer hooks in proxy NS first (before host NS hooks)
        // because dae0peer interface only exists in proxy NS
        if let Ok(()) = self.netns_mgr.join_proxy_ns() {
            debug!("Detaching proxy NS hooks...");
            let _ = self.ebpf().detach_by_iface(self.netns_mgr.peer_if());
            let _ = self.netns_mgr.join_host_ns();
        } else {
            debug!("Could not join proxy NS for detach (may not exist)");
        }
        // Detach all remaining hooks in host NS
        let _ = self.ebpf().detach_all();
        debug!("Emergency BPF hook detachment completed: {}ms", start.elapsed().as_millis());
    }

    pub async fn stop(&mut self) -> Result<()> {
        let start_time = std::time::Instant::now();
        info!("Control plane stopping...");

        let mut errors: Vec<anyhow::Error> = Vec::new();

        // ---- Step 0: Stop all background tasks first ----
        // These must be stopped before service listeners to prevent:
        // 1. Connectivity checker printing logs during shutdown
        // 2. Janitors holding eBPF map locks while we try to detach
        // 3. Race conditions with InterfaceManager unbinding programs
        // All use abort() for immediate cancellation.
        info!("Step 0/5: Stopping all background tasks");
        let step_start = std::time::Instant::now();
        // 0a. Connectivity checker
        if let Some(handle) = self.connectivity_handle.take() {
            handle.abort();
            debug!("Connectivity checker task aborted");
        }
        // 0b. conn_state janitor
        if let Some(handle) = self.janitor_handle.take() {
            handle.abort();
            debug!("ConnState janitor task aborted");
        }
        // 0c. redirect_track janitor
        if let Some(handle) = self.redirect_track_handle.take() {
            handle.abort();
            debug!("Redirect track janitor task aborted");
        }
        // 0d. cookie_pid_map janitor
        if let Some(handle) = self.cookie_pid_handle.take() {
            handle.abort();
            debug!("Cookie PID map janitor task aborted");
        }
        // 0e. InterfaceManager
        if let Some(mut iface_mgr) = self.iface_mgr.take() {
            iface_mgr.stop().await;
            debug!("InterfaceManager stopped");
        }
        // 0f. Ringbuf consumer
        if let Some(running) = self.ringbuf_running.take() {
            running.store(false, Ordering::Relaxed);
        }
        if let Some(handle) = self.ringbuf_thread.take() {
            let join_start = std::time::Instant::now();
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                tokio::task::spawn_blocking(move || {
                    let _ = handle.join();
                }),
            )
            .await;
            debug!("Ringbuf consumer joined: {}ms", join_start.elapsed().as_millis());
        }
        // 0g. Internal DNS forwarder (graceful stop, then abort the task)
        if let Some(f) = self.dns_forwarder.take() {
            f.stop();
            debug!("DNS forwarder stop signal sent");
        }
        if let Some(handle) = self.dns_handle.take() {
            handle.abort();
            debug!("DNS forwarder task aborted");
        }
        // 0g. Routing handoff consumer
        if let Some(handle) = self.routing_handoff_handle.take() {
            handle.abort();
            debug!("Routing handoff consumer task aborted");
        }

        // 0h. Rule set scheduler (graceful shutdown, wait up to 3s)
        if let Some(sched) = self.rule_set_scheduler.take() {
            let sched_start = std::time::Instant::now();
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                sched.stop(),
            )
            .await;
            debug!("Rule set scheduler stopped: {}ms", sched_start.elapsed().as_millis());
        }
        debug!("Step 0 completed: {}ms", step_start.elapsed().as_millis());

        // ---- Step 1: Stop API server ----
        if let Some(handle) = self.api_handle.take() {
            info!("Step 1/5: Stopping REST API server");
            handle.abort();
            let _ = handle.await;
            debug!("API server stopped");
        }

        // ---- Step 2: Stop TProxy listener ----
        info!("Step 2/5: Stopping TProxy listener");
        let step_start = std::time::Instant::now();
        if let Some(tproxy) = &self.tproxy {
            tproxy.stop();
        }
        if let Some(udp) = &self.tproxy_udp {
            udp.stop();
        }
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
        debug!("Step 3 completed: {}ms", step_start.elapsed().as_millis());

        // ---- Step 5: Detach all TC and cgroup programs ----
        info!("Step 4/5: Detaching all TC and cgroup programs");
        let step_start = std::time::Instant::now();
        if let Err(e) = self.ebpf().detach_all() {
            error!("Failed to detach programs: {}", e);
            errors.push(e);
        }
        debug!("Detach completed: {}ms", step_start.elapsed().as_millis());

        // ---- Step 5.5: Restore kernel sysctl settings changed by configure_kernel_if ----
        // configure_kernel_if() sets forwarding=1 / rp_filter / proxy_arp on WAN/LAN
        // interfaces; restore the originals so the host is left clean.
        for iface in self
            .config
            .wan_interface
            .iter()
            .chain(self.config.lan_interface.iter())
        {
            restore_kernel_if(iface);
        }

        // ---- Step 6: Unload eBPF program ----
        info!("Step 5/5: Unloading eBPF program");
        let step_start = std::time::Instant::now();
        if let Err(e) = self.ebpf().unload() {
            error!("Failed to unload eBPF program: {}", e);
            errors.push(e);
        }
        debug!("Unload completed: {}ms", step_start.elapsed().as_millis());

        // ---- Step 7: Unpin eBPF maps from bpffs ----
        info!("Step 6/6: Unpinning eBPF maps");
        let step_start = std::time::Instant::now();
        if let Err(e) = self.ebpf().unpin_maps(crate::net::ebpf::BPFFS_PATH) {
            warn!("Failed to unpin eBPF maps: {}", e);
        }
        debug!("Unpin completed: {}ms", step_start.elapsed().as_millis());

        // ---- Step 8: Destroy network namespace ----
        info!("Step 7/7: Destroying network namespace and veth pair");
        let step_start = std::time::Instant::now();
        if let Err(e) = self.netns_mgr.destroy() {
            error!("Failed to destroy network namespace: {}", e);
            errors.push(e);
        }
        debug!("Destroy completed: {}ms", step_start.elapsed().as_millis());

        self.running = false;

        let total_ms = start_time.elapsed().as_millis();
        if errors.is_empty() {
            debug!("Control plane stop total time: {}ms", total_ms);
            info!("Control plane stopped successfully");
            Ok(())
        } else {
            for e in &errors {
                warn!("Control plane stop error: {}", e);
            }
            debug!(
                "Control plane stop completed with {} errors (total: {}ms)",
                errors.len(),
                total_ms
            );
            Err(anyhow::anyhow!(
                "Control plane stopped with {} error(s)",
                errors.len()
            ))
        }
    }

    /// Hot-reload configuration without restarting eBPF or TProxy.
    ///
    /// Re-parses the daefile and updates all eBPF maps in-place.
    /// TCX hooks are NOT re-attached on reload (routing updates are applied via
    /// the epoch double-buffer maps), so no re-attach / handle concerns apply.
    /// Safe to call even when eBPF is not loaded (maps are skipped).
    ///
    /// # Reload Coverage
    ///
    /// **Supported (live):**
    /// - Routing rules (MatchSet, LPM tries, domain routing)
    /// - Process exclusion lists (comm/PID/TGID)
    ///
    /// **NOT supported — require full restart:**
    /// - Proxy address / credentials (TProxy dialer is immutable at runtime)
    /// - `tproxy_port` (TProxy listener socket is immutable)
    /// - WAN/LAN interface patterns (`InterfaceManager` bindings are immutable)
    /// - MTU, fwmark values (kernel network stack parameters)
    ///
    /// Changing proxy credentials or address here will update `self.config.*`
    /// fields but the active `Socks5Dialer` and `TproxyListener` instances
    /// continue using the old values until the next restart.
    pub fn reload_config(&mut self, daefile_content: &str) -> Result<()> {
        let start = std::time::Instant::now();
        info!("Hot-reloading configuration");
        debug!("reload_config: input size {} bytes", daefile_content.len());

        // 1. Re-parse daefile
        let daefile_config = config::parse_daefile(daefile_content)
            .map_err(|e| anyhow::anyhow!("Config parse error: {:?}", e))?;
        config::validate_config(&daefile_config)?;
        self.daefile_config = Some(daefile_config.clone());
        self.daefile_content = Some(daefile_content.to_string());
        debug!("Hot-reload: daefile re-parsed and validated");

        // Update hot-reloadable config fields from the new daefile.
        // Note: these updates are recorded but the active Socks5Dialer and
        // TproxyListener instances are NOT recreated — new proxy credentials
        // and address only take effect on the next restart.
        if let Some(first_node) = daefile_config.outbounds.nodes.first() {
            if self.config.proxy_addr != first_node.address {
                warn!(
                    "Hot-reload: proxy_addr changed '{}' -> '{}'. \
                     Active dialer still uses old address; restart required for new proxy.",
                    self.config.proxy_addr, first_node.address,
                );
            }
            self.config.proxy_addr = first_node.address.clone();
            self.config.proxy_username = first_node.username.clone().unwrap_or_default();
            self.config.proxy_password = first_node.password.clone().unwrap_or_default();
            self.config.proxy_dial_timeout_ms = first_node.dial_timeout_ms;
        } else {
            warn!("Hot-reload: no outbound nodes defined; proxy config unchanged");
        }
        self.config.log_level = daefile_config.runtime.log_level.clone();

        // 2. Re-compile routing rules (with proxy server auto-direct)
        let proxy_server_ips = collect_proxy_server_ips(&self.config, &daefile_config.outbounds);
        let compiled = routing::matcher::compile_rules(
            &daefile_config.routing,
            &daefile_config.outbounds,
            &proxy_server_ips,
            Some(&self.rule_set_cache),
        )
        .context("Failed to compile routing rules")?;

        // 3. Epoch double-buffer: write to non-active slot, then flip
        //
        // The routing epoch double-buffer mechanism works as follows:
        //   - Compute next_slot = (current + 1) % 2
        //   - Clear the NEXT slot's domain_routing entries (prepare fresh state)
        //   - Write new rules to next_slot's routing_map and lpm_array_map
        //   - Switch active_routing_epoch_map to next_slot
        //   - Flip current_epoch_slot to next_slot
        //   - Clear the PREVIOUS slot's domain_routing entries (stale now)
        //
        // This ensures the eBPF datapath always sees a consistent routing state:
        // either the old rules (until the flip) or the new rules (after the flip).
        //
        // Note: domain_routing entries are cleared on reload but not re-populated
        // (domain-driven routing is not re-populated after reload).

        // 3a. Increment datapath_generation
        self.datapath_generation = self.datapath_generation.wrapping_add(1);
        info!(
            "Hot-reload: datapath_generation incremented to {}",
            self.datapath_generation
        );

        // Compute the next (target) epoch slot
        let next_slot = (self.current_epoch_slot + 1) % crate::net::ebpf::ROUTING_EPOCH_SLOT_NUM;
        let prev_slot = self.current_epoch_slot;
        info!(
            "Hot-reload: epoch switching slot {} -> {}",
            prev_slot, next_slot
        );

        // 3b. Write to eBPF maps (skip if not loaded)
        {
            let mut ebpf = self.ebpf();
            if !ebpf.is_loaded() {
                info!("Hot-reload: eBPF not loaded, skipping map writes");
            } else {
                // Clear the TARGET slot's domain_routing entries (fresh start)
                if let Err(e) = ebpf.clear_domain_routing_slot(next_slot) {
                    warn!("Hot-reload: failed to clear domain_routing slot {}: {}", next_slot, e);
                }

                // Write new rules to the NEXT slot
                if !compiled.match_sets.is_empty() {
                    ebpf.write_routing_rules(&compiled.match_sets, next_slot)?;
                    info!(
                        "Hot-reload: wrote {} match sets to routing_map slot {}",
                        compiled.match_sets.len(),
                        next_slot
                    );
                }

                // Write LPM trie data to inner LPM trie maps via lpm_array_map
                {
                    let mut all_cidr_entries: Vec<(u32, CidrEntry)> = Vec::new();
                    for (trie_idx, cidrs) in compiled.lpm_tries.iter().enumerate() {
                        let entries = crate::routing::matcher::cidrs_to_cidr_entries(cidrs);
                        for (_, entry) in entries {
                            all_cidr_entries.push((trie_idx as u32, entry));
                        }
                    }
                    if !all_cidr_entries.is_empty() {
                        if let Err(e) = ebpf.write_cidr_table(&all_cidr_entries, next_slot) {
                            warn!("Hot-reload: failed to write CIDR entries to slot {}: {}", next_slot, e);
                        } else {
                            info!(
                                "Hot-reload: wrote {} CIDR entries across {} LPM tries to slot {}",
                                all_cidr_entries.len(),
                                compiled.lpm_tries.len(),
                                next_slot
                            );
                        }
                    }
                }

                // Atomically switch the active routing epoch to the new slot
                if let Err(e) = ebpf.update_active_routing_epoch(next_slot) {
                    warn!("Hot-reload: failed to update active_routing_epoch: {}", e);
                } else {
                    info!("Hot-reload: active_routing_epoch switched to slot {}", next_slot);
                }

                // Clear the PREVIOUS slot's domain_routing entries (now stale)
                if let Err(e) = ebpf.clear_domain_routing_slot(prev_slot) {
                    warn!("Hot-reload: failed to clear domain_routing slot {}: {}", prev_slot, e);
                }

                // Update excluded comm/PID lists
                if let Some(ref pe) = daefile_config.process_exclusion {
                    if pe.enabled {
                        if !pe.r#match.comm.is_empty() {
                            let hashes: Vec<u32> = pe
                                .r#match
                                .comm
                                .iter()
                                .map(|c| crate::net::ebpf::hash_comm(c))
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

        // 4. Flip epoch slot and update domain routing tracker
        self.current_epoch_slot = next_slot;

        let elapsed_ms = start.elapsed().as_millis();
        debug!("Hot-reload completed: {}ms", elapsed_ms);
        info!("Hot-reload completed successfully");
        Ok(())
    }

    /// Handle Routing hot-reload after ruleset update.
    ///
    /// Consume reload signal from [`ControlPlane::rule_set_reload_rx`] (filled by background watcher
    // after ruleset successfully updated and in-memory cache refreshed). When signal exists, recompile
    // Routing (using refreshed [`ControlPlane::rule_set_cache`]) and perform eBPF double-buffer
    // hot-reload (reuses [`ControlPlane::reload_config`]).
    ///
    /// Returns whether hot-reload was performed. Should be called periodically (e.g., main event loop); returns
    /// `false`.
    ///
    /// # Legacy
    ///
    /// Full "auto" hot-reload requires periodically calling this method in the main event loop (`src/lib.rs`); this method provides
    /// Explicit interface + cache refresh already done by background watcher (satisfies "at least refresh in-memory cache + logging").
    pub async fn handle_rule_set_reloads(&mut self) -> Result<bool> {
        let mut rx = match self.rule_set_reload_rx.take() {
            Some(rx) => rx,
            None => return Ok(false),
        };
        // Merge all pending signals into one reload
        let mut reloaded = false;
        while rx.try_recv().is_ok() {
            reloaded = true;
        }
        self.rule_set_reload_rx = Some(rx);
        if !reloaded {
            return Ok(false);
        }

        if let Some(content) = self.daefile_content.clone() {
            info!("Rule set update: hot-reloading routing with refreshed data");
            if let Err(e) = self.reload_config(&content) {
                warn!("Rule set hot-reload failed: {:#}", e);
            }
        } else {
            warn!("Rule set update detected but no daefile content available for reload");
        }
        Ok(true)
    }
}

impl Drop for ControlPlane {
    /// Automatic stop on drop
    ///
    /// If the control plane is still running and the user forgot to call [`stop()`](ControlPlane::stop),
    /// the Drop implementation will automatically perform cleanup. However, since async is not available
    /// in Drop, this performs cleanup synchronously (a non-async version of stop).
    ///
    /// Temp JSON files are cleaned up here as a best-effort, since the caller may not
    /// have reached the normal shutdown path (e.g. process killed with SIGKILL).
    fn drop(&mut self) {
        if self.running {
            warn!("ControlPlane dropped without explicit stop()");
        }
        // Each sub-module's Drop implementation handles its own cleanup.
        // Also clean up any leftover temp JSON config files (best-effort).
        cleanup_temp_json(0);
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Default proxy resolution for the ruleset scheduler.
///
/// Resolves a proxy group name to the SOCKS5 address of the group's
/// **currently selected** node via the group dialer ([`group::GroupDialer`]).
/// Group dialers implement intra-group node selection + alive-node fallback, so
/// the resolved address tracks the policy-best alive node.
///
/// When no group dialers exist (legacy flat config with a single SOCKS5 node),
/// `legacy_addr` is returned for the default proxy group as a fallback.
struct DefaultProxyResolver {
    /// Per-group dialers (group name → dialer), shared with the TProxy path.
    group_dialers: Arc<HashMap<String, Arc<dyn OutboundDialer>>>,
    /// Legacy single-node address used when the group map is empty.
    legacy_addr: Option<SocketAddr>,
    /// Default proxy group name (legacy fallback anchor).
    default_group: Option<String>,
}

impl ruleset::scheduler::ProxyResolver for DefaultProxyResolver {
    fn resolve(&self, proxy: &str) -> Option<SocketAddr> {
        if let Some(dialer) = self.group_dialers.get(proxy) {
            // 调度器只会对解析到的地址做 SOCKS5 握手来下载规则集；只有当前选中
            // 节点是真正的 SOCKS5 拨号器时才可复用该地址，否则（TUIC/vmess/
            // trojan/shadowsocks/juicity）返回 None → 调度器回退直连下载。
            if dialer.is_socks5() {
                return Some(dialer.proxy_addr());
            }
            warn!(
                proxy = proxy,
                "proxy group does not resolve to a SOCKS5 node; \
                 falling back to direct for rule-set download"
            );
            return None;
        }
        // Legacy flat config: the default group maps to a single SOCKS5 node.
        if self.default_group.as_deref() == Some(proxy) {
            return self.legacy_addr;
        }
        None
    }
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

/// Clean up temp JSON files. If `max_age_secs` is 0, delete all JSON files.
/// Otherwise, delete files older than the specified retention period.
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
                let should_delete = if max_age_secs == 0 {
                    true
                } else if let Ok(metadata) = std::fs::metadata(&path) {
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(duration) = now.duration_since(modified) {
                            duration.as_secs() > max_age_secs
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                };
                if should_delete {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }
}

/// Connect to an address with SO_MARK set (bypasses eBPF self-intercept).
/// Used by the connectivity checker and other internal health probes.
/// TCP connection with SO_MARK (for connectivity check).
///
/// Delegates to [`protocols::hostns::connect_tcp`] implementation, mark semantics consistent with Dialer:
/// dae-rs self-traffic must direct connect (eBPF pid_is_control_plane passes through).
pub async fn connect_with_mark(
    addr: &std::net::SocketAddr,
    mark: u32,
    timeout_secs: u64,
) -> std::io::Result<tokio::net::TcpStream> {
    let sock = protocols::hostns::DirectSocket {
        self_mark: mark,
        host_ns_fd: None,
    };
    protocols::hostns::connect_tcp(
        *addr,
        &sock,
        false,
        std::time::Duration::from_secs(timeout_secs),
    )
    .await
}

// ============================================================================
// Kernel Parameter Configuration
// ============================================================================

/// Original sysctl values overwritten by [`configure_kernel_if`], keyed by
/// interface name → (sysctl path → original value). Used to restore the host to
/// its prior state on shutdown / interface unbind.
static SYSCTL_SNAPSHOT: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, std::collections::HashMap<String, String>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Read the current value of a sysctl path (trimmed), if readable.
fn read_sysctl(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

/// Record the original value of `path` for `iface` if not already recorded
/// (first write wins, so re-configuration never clobbers the true original).
fn snapshot_sysctl(iface: &str, path: &str, value: &str) {
    if let Ok(mut map) = SYSCTL_SNAPSHOT.lock() {
        let entry = map.entry(iface.to_string()).or_default();
        entry.entry(path.to_string()).or_insert_with(|| value.to_string());
    }
}

/// Snapshot the current value of `path` for `iface`, then write `value`.
fn write_sysctl_snapshot(iface: &str, path: &str, value: &str) -> std::io::Result<()> {
    if let Some(orig) = read_sysctl(path) {
        snapshot_sysctl(iface, path, &orig);
    }
    std::fs::write(path, format!("{}\n", value))
}

/// Restore every sysctl that [`configure_kernel_if`] changed on `iface` back to
/// its original value. Called on interface unbind and on control-plane shutdown.
fn restore_kernel_if(iface: &str) {
    let originals = if let Ok(mut map) = SYSCTL_SNAPSHOT.lock() {
        map.remove(iface)
    } else {
        None
    };
    if let Some(originals) = originals {
        for (path, value) in originals {
            match std::fs::write(&path, format!("{}\n", value)) {
                Ok(()) => info!("Kernel: restored {}={} on {}", path, value, iface),
                Err(e) => warn!("Failed to restore sysctl {} on {}: {}", path, iface, e),
            }
        }
    }
}

/// Configure kernel parameters for a WAN/LAN interface.
///
/// Mirrors original dae's `SetSendRedirects` and `SetForwarding`:
/// - `net.ipv4.conf.<iface>.send_redirects = 0` — disable ICMP redirects
/// - `net.ipv4.conf.<iface>.forwarding = 1` — enable IP forwarding
///
/// These are needed for transparent proxying to work correctly.
/// Each original value is snapshotted so [`restore_kernel_if`] can put the host
/// back to its prior state on shutdown / unbind. Errors are logged but not
/// propagated (best-effort).
fn configure_kernel_if(iface: &str) {
    let is_dae_iface = iface.starts_with("dae");

    // net.ipv4.conf.<iface>.send_redirects = 0
    if !is_dae_iface {
        let path_send_redirects = format!("/proc/sys/net/ipv4/conf/{}/send_redirects", iface);
        if let Err(e) = write_sysctl_snapshot(iface, &path_send_redirects, "0") {
            warn!(
                "Failed to set send_redirects=0 on {}: {} (non-critical)",
                iface, e
            );
        } else {
            info!("Kernel: {}=0", path_send_redirects);
        }
    }

    // net.ipv4.conf.<iface>.forwarding = 1
    if !is_dae_iface {
        let path_forwarding = format!("/proc/sys/net/ipv4/conf/{}/forwarding", iface);
        if let Err(e) = write_sysctl_snapshot(iface, &path_forwarding, "1") {
            warn!(
                "Failed to set forwarding=1 on {}: {} (non-critical)",
                iface, e
            );
        } else {
            info!("Kernel: {}=1", path_forwarding);
        }
    }

    // net.ipv6.conf.<iface>.forwarding = 1 (if IPv6 is enabled on the interface)
    if !is_dae_iface {
        let path_fwd6 = format!("/proc/sys/net/ipv6/conf/{}/forwarding", iface);
        // Don't error if IPv6 is not configured on this interface
        let _ = write_sysctl_snapshot(iface, &path_fwd6, "1");
    }

    // net.ipv4.conf.<iface>.rp_filter
    // Keep dae netkit path aligned with original kdae: dae0/dae0peer use 0.
    // Other interfaces keep loose mode (2).
    let path_rp = format!("/proc/sys/net/ipv4/conf/{}/rp_filter", iface);
    let rp_value = if iface.starts_with("dae") { "0" } else { "2" };
    if let Err(e) = write_sysctl_snapshot(iface, &path_rp, rp_value) {
        warn!(
            "Failed to set rp_filter on {}: {} (may affect TProxy)",
            iface, e
        );
    } else {
        info!("Kernel: {}={}", path_rp, rp_value);
    }

    // net.ipv4.conf.<iface>.proxy_arp = 1
    // The SOCKS5 dial and upstream sockets live in daens and therefore source their
    // packets from 169.254.0.11 (the dae0peer address). That address is not
    // reachable from the WAN/router side: the proxy's reply targets 169.254.0.11
    // (link-local) and is ARP-resolved on the LAN, but nothing answers — the host
    // only holds that address inside daens. proxy_arp makes this host answer ARP
    // for addresses whose route exits a different interface (169.254.0.11 routes
    // via dae0), so reply packets reach wlp3s0 and are forwarded back into daens.
    // This is required for control-plane dialing to ever complete.
    if !is_dae_iface {
        let path_proxy_arp = format!("/proc/sys/net/ipv4/conf/{}/proxy_arp", iface);
        if let Err(e) = write_sysctl_snapshot(iface, &path_proxy_arp, "1") {
            warn!(
                "Failed to set proxy_arp=1 on {}: {} (dial replies may not return)",
                iface, e
            );
        } else {
            info!("Kernel: {}=1", path_proxy_arp);
        }
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

/// Resolve an outbound group to **all** concrete nodes its selectors reference.
///
/// Evaluates each selector in order, collecting the matching nodes without
/// duplicates:
/// - `List` → each named node that exists in `nodes`;
/// - `Regex` → every node whose name matches the pattern.
fn resolve_group_nodes<'a>(
    group: &config::OutboundGroupConfig,
    nodes: &'a [config::OutboundNodeConfig],
) -> Vec<&'a config::OutboundNodeConfig> {
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    let push = |node: &'a config::OutboundNodeConfig,
                seen: &mut std::collections::HashSet<&'a str>,
                result: &mut Vec<&'a config::OutboundNodeConfig>| {
        if seen.insert(&node.name) {
            result.push(node);
        }
    };

    for selector in &group.selectors {
        match selector {
            config::NodeSelector::List { nodes: names } => {
                for name in names {
                    if let Some(node) = nodes.iter().find(|n| n.name == *name) {
                        push(node, &mut seen, &mut result);
                    }
                }
            }
            config::NodeSelector::Regex { pattern } => {
                match regex::Regex::new(pattern) {
                    Ok(re) => {
                        for node in nodes {
                            if re.is_match(&node.name) {
                                push(node, &mut seen, &mut result);
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            group = %group.name,
                            pattern = %pattern,
                            "Invalid node selector regex (ignored): {}",
                            e
                        );
                    }
                }
            }
        }
    }
    result
}

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
    use crate::ruleset::scheduler::ProxyResolver;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.tproxy_port, 15080);
        assert_eq!(config.route_table, 2023);
        assert_eq!(config.fwmark_proxy, 0x08000000);
        assert_eq!(config.fwmark_bypass, 0x04000000);
        assert_eq!(config.fwmark_mask, 0x08000000);
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
        assert_eq!(config.fwmark_proxy, 0x08000000);
        assert_eq!(config.fwmark_bypass, 0x04000000);
        assert_eq!(config.fwmark_mask, 0x08000000);
        assert_eq!(config.proxy_addr, "127.0.0.1:1080");
        assert_eq!(config.proxy_dial_timeout_ms, 5000);
    }

    #[test]
    fn test_compile_rules_fallback() {
        // This test was removed - compile_rules in lib.rs is deprecated.
        // Routing tests are in routing::matcher::tests.
    }

    #[test]
    fn test_compile_rules_action_mapping() {
        // This test was removed - compile_rules in lib.rs is deprecated.
        // Routing tests are in routing::matcher::tests.
    }

    // ------------------------------------------------------------------------
    // resolve_group_nodes
    // ------------------------------------------------------------------------

    fn node(name: &str, addr: &str) -> config::OutboundNodeConfig {
        config::OutboundNodeConfig {
            name: name.into(),
            protocol: "socks5".into(),
            address: addr.into(),
            import: None,
            username: None,
            password: None,
            cipher: None,
            sni: None,
            ca_sha256: None,
            uuid: None,
            congestion_control: None,
            alpn: None,
            security: None,
            alter_id: None,
            network: None,
            ws_path: None,
            ws_headers: None,
            h2_path: None,
            h2_host: None,
            grpc_service_name: None,
            dial_timeout_ms: 5000,
        }
    }

    #[test]
    fn test_resolve_group_nodes_list_and_regex() {
        let nodes = vec![
            node("hk-a", "1.1.1.1:443"),
            node("hk-b", "2.2.2.2:443"),
            node("us-c", "3.3.3.3:443"),
            node("us-d", "4.4.4.4:443"),
        ];
        // List selector + regex selector, with a duplicate name to test dedup.
        let group = config::OutboundGroupConfig {
            name: "g".into(),
            group_type: config::GroupType::Auto,
            policy: None,
            selected: None,
            selectors: vec![
                config::NodeSelector::List {
                    nodes: vec!["hk-b".into(), "missing".into(), "hk-a".into(), "hk-b".into()],
                },
                config::NodeSelector::Regex {
                    pattern: "^us-".into(),
                },
            ],
        };
        let resolved = resolve_group_nodes(&group, &nodes);
        let names: Vec<&str> = resolved.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["hk-b", "hk-a", "us-c", "us-d"]);
    }

    #[test]
    fn test_resolve_group_nodes_no_match() {
        let nodes = vec![node("hk-a", "1.1.1.1:443")];
        let group = config::OutboundGroupConfig {
            name: "g".into(),
            group_type: config::GroupType::Auto,
            policy: None,
            selected: None,
            selectors: vec![config::NodeSelector::List {
                nodes: vec!["nope".into()],
            }],
        };
        assert!(resolve_group_nodes(&group, &nodes).is_empty());
    }

    // ------------------------------------------------------------------------
    // DefaultProxyResolver
    // ------------------------------------------------------------------------

    /// Minimal fake dialer exposing a fixed proxy address.
    struct FixedAddrDialer(SocketAddr);

    #[async_trait::async_trait]
    impl protocols::OutboundDialer for FixedAddrDialer {
        async fn dial(&self, _target: &str) -> anyhow::Result<protocols::ProxyConn> {
            anyhow::bail!("unused in tests")
        }
        async fn udp_dial(&self) -> anyhow::Result<Box<dyn protocols::UdpSession>> {
            anyhow::bail!("unused in tests")
        }
        fn protocol_name(&self) -> &'static str {
            "fake"
        }
        fn proxy_addr(&self) -> SocketAddr {
            self.0
        }
        fn is_socks5(&self) -> bool {
            true
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    /// Fake dialer that does NOT advertise SOCKS5 (models TUIC/vmess/etc.).
    struct NonSocks5Dialer(SocketAddr);

    #[async_trait::async_trait]
    impl protocols::OutboundDialer for NonSocks5Dialer {
        async fn dial(&self, _target: &str) -> anyhow::Result<protocols::ProxyConn> {
            anyhow::bail!("unused in tests")
        }
        async fn udp_dial(&self) -> anyhow::Result<Box<dyn protocols::UdpSession>> {
            anyhow::bail!("unused in tests")
        }
        fn protocol_name(&self) -> &'static str {
            "tuic"
        }
        fn proxy_addr(&self) -> SocketAddr {
            self.0
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[test]
    fn test_default_proxy_resolver_resolves_any_group() {
        let mut dialers: HashMap<String, Arc<dyn OutboundDialer>> = HashMap::new();
        let group_dialer = group::GroupDialer::new(
            "proxy_a".into(),
            vec![group::GroupNode::new(
                "node1".into(),
                Arc::new(FixedAddrDialer("10.0.0.1:443".parse().unwrap())),
            )],
            config::PolicyType::Fixed,
        );
        dialers.insert("proxy_a".into(), Arc::new(group_dialer));
        dialers.insert(
            "proxy_b".into(),
            Arc::new(FixedAddrDialer("10.0.0.2:8443".parse().unwrap())),
        );

        let resolver = DefaultProxyResolver {
            group_dialers: Arc::new(dialers),
            legacy_addr: Some("127.0.0.1:1080".parse().unwrap()),
            default_group: Some("proxy_a".into()),
        };

        // Any configured group name resolves (to its selected node's addr).
        assert_eq!(resolver.resolve("proxy_a"), Some("10.0.0.1:443".parse().unwrap()));
        assert_eq!(resolver.resolve("proxy_b"), Some("10.0.0.2:8443".parse().unwrap()));
        // Unknown group → None.
        assert_eq!(resolver.resolve("unknown"), None);
    }

    #[test]
    fn test_default_proxy_resolver_non_socks5_falls_back_to_none() {
        // 规则集调度器只会做 SOCKS5 握手：非 SOCKS5 组（TUIC/vmess 等）不得
        // 被当作 SOCKS5 地址返回 → resolve 返回 None（调度器回退直连）。
        let mut dialers: HashMap<String, Arc<dyn OutboundDialer>> = HashMap::new();
        dialers.insert("proxy_tuic".into(), Arc::new(NonSocks5Dialer("1.2.3.4:443".parse().unwrap())));
        let group_dialer = group::GroupDialer::new(
            "proxy_vmess".into(),
            vec![group::GroupNode::new(
                "n".into(),
                Arc::new(NonSocks5Dialer("5.6.7.8:443".parse().unwrap())),
            )],
            config::PolicyType::Fixed,
        );
        dialers.insert("proxy_vmess".into(), Arc::new(group_dialer));

        let resolver = DefaultProxyResolver {
            group_dialers: Arc::new(dialers),
            legacy_addr: None,
            default_group: None,
        };
        assert_eq!(resolver.resolve("proxy_tuic"), None);
        assert_eq!(resolver.resolve("proxy_vmess"), None);
    }

    #[test]
    fn test_default_proxy_resolver_legacy_fallback() {
        let resolver = DefaultProxyResolver {
            group_dialers: Arc::new(HashMap::new()),
            legacy_addr: Some("127.0.0.1:1080".parse().unwrap()),
            default_group: Some("proxy_a".into()),
        };
        assert_eq!(resolver.resolve("proxy_a"), Some("127.0.0.1:1080".parse().unwrap()));
        assert_eq!(resolver.resolve("proxy_b"), None);
    }
}
