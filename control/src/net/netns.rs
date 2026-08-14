//! Named Network namespace + netkit pair management
//!
//! This module is responsible for creating and managing named Network namespaces and netkit pairs, used to import proxy traffic
//! from the host namespace into the proxy namespace for processing.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                     Host Network namespace                          │
//! │                                                              │
//! │  ┌─────────────┐  ┌──────────────┐                           │
//! │  │   eth0      │  │   dae0       │                           │
//! │  │  (external)   │  │ fe80::.../128│                           │
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
//! │                   daens (Proxy Network namespace)                     │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Traffic path
//!
//! 1. Inbound packet enters `dae0` in host NS
//! 2. TC(tproxy_dae0_ingress) intercepts, looks up Routing, sets fwmark
//! 3. Packet reaches `dae0peer` via netkit (in daens)
//! 4. Policy Routing (fwmark → table 2023 → local default dev lo) delivers to TProxy socket
//! 5. After proxy processing, reply returns to host NS via `dae0`
//!
//! ## Aligned with original dae
//!
//! This implementation aligns with the original dae (https://github.com/daeuniverse/dae) `netns_utils.go`
//! remains consistent:
//! - Uses **named** Network namespace (`ip netns add daens`), not unshare
//! - netkit pair is created in the **host NS**, then dae0peer is moved into daens
//! - Operations inside daens are performed via setns()
//! - Permanent ARP/NDP entries are used instead of broadcast

use anyhow::{Context, Result};
use rtnetlink::packet_route::link::{NetkitMode, NetkitScrub};
use rtnetlink::packet_route::route::RouteScope;
use rtnetlink::packet_route::route::{RouteAttribute, RouteMessage, RouteType};
use rtnetlink::packet_route::rule::{RuleAction, RuleAttribute, RuleMessage};
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::{
    new_connection, LinkMessageBuilder, LinkNetkit, LinkUnspec, LinkVeth, RouteMessageBuilder,
};
use std::fs;
use std::os::linux::fs::MetadataExt;
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};
use std::process::Command;
use std::{net::IpAddr, path::Path};
use tracing::{debug, error, info, warn};

// ============================================================================
// Constants
// ============================================================================

/// Named Network namespace name
const NS_NAME: &str = "dae-rs";

/// Network namespace mount path
const NETNS_RUN_DIR: &str = "/var/run/netns";

/// Host-side interface name (in the host NS)
pub const HOST_IF: &str = "dae0";

/// Proxy-side interface name (in daens)
pub const PEER_IF: &str = "dae0peer";

/// Proxy-side IPv4 address
const PEER_ADDR: &str = "169.254.0.11/32";

/// Routing next hop (link-local address in the host role; not actually used as dae0's IP)
const NEXTHOP_ADDR: &str = "169.254.0.1";

/// IPv6 link-local address (assigned to dae0)
const IPV6_LL: &str = "fe80::ecee:eeff:feee:eeee";

/// Default MTU
const DEFAULT_MTU: u32 = 1500;

/// Default policy routing table ID
const DEFAULT_ROUTE_TABLE: u32 = 2023;

/// TPROXY_MARK (consistent with original dae)
const PROXY_MARK: u32 = 0x08000000;

/// TPROXY_MASK (consistent with original dae)
const PROXY_MASK: u32 = 0x08000000;

// ============================================================================
// Error Types
// ============================================================================

/// Network namespace management error
#[derive(Debug, thiserror::Error)]
pub enum NetnsError {
    /// Namespace already created, operation conflicts
    #[error("Network namespace already created")]
    AlreadyCreated,
    /// Namespace not created, operation is invalid
    #[error("Network namespace not created")]
    NotCreated,
    /// iproute2 command execution failed
    #[error("ip command failed: {cmd}\nstderr: {stderr}")]
    IpCommand {
        /// The executed command
        cmd: String,
        /// Standard error output
        stderr: String,
    },
    /// Kernel too old, netkit not supported (requires >= 6.7)
    #[error("Netkit requires kernel >= 6.7")]
    NetkitNotSupported,
}

// ============================================================================
// RAII Guard
// ============================================================================

/// RAII guard: enters daens and automatically switches back to the host namespace on Drop.
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

/// RAII guard: on Drop, automatically switches the current thread's Network namespace
/// back to `host_fd`.
///
/// Used by `configure_dae0peer_async` and other places that need to temporarily switch
/// between the host NS and daens. Even if an intermediate operation returns early via `?`,
/// the Guard's Drop ensures the namespace is restored.
struct NetnsSwitchGuard<'a> {
    host_fd: &'a OwnedFd,
    active: bool,
}

impl<'a> NetnsSwitchGuard<'a> {
    /// Create the guard without performing the switch (the caller must first setns to daens manually)
    fn new(host_fd: &'a OwnedFd) -> Self {
        Self {
            host_fd,
            active: true,
        }
    }
}

impl<'a> Drop for NetnsSwitchGuard<'a> {
    fn drop(&mut self) {
        if self.active {
            if let Err(e) = nix::sched::setns(self.host_fd, nix::sched::CloneFlags::CLONE_NEWNET) {
                error!(
                    "CRITICAL: Failed to return to host netns in NetnsSwitchGuard: {}. \
                     The current thread may be in the wrong namespace!",
                    e
                );
            }
        }
    }
}

// ============================================================================
// Helper function
// ============================================================================

/// Synchronously execute a closure in the host Network namespace and restore the current
/// namespace afterwards.
///
/// # Flow
///
/// 1. Save the current thread's Network namespace fd
/// 2. `setns(host_ns_fd)` switches to the host NS
/// 3. Execute `f()`
/// 4. Restore the original namespace regardless of whether `f()` panics
///
/// # Notes
///
/// - This function is synchronous; the closure must not contain `.await` points.
/// - Must not be called across `.await` in an async context that holds namespace-related
///   resources (such as tokio I/O being polled) — the function itself has no `.await`,
///   so it is safe.
///
/// # Usage
///
/// Aligned with kdae: the TProxy listening socket stays in daens, while all upstream
/// connections (to the SOCKS5 proxy, to upstream DNS) must be created and sent from the
/// host NS.
pub fn with_host_ns_fd<F, T>(host_ns_fd: RawFd, f: F) -> Result<T>
where
    F: FnOnce() -> T,
{
    // Delegate to the unified protocols::hostns implementation (setns + panic-safe restore).
    protocols::hostns::with_host_ns(Some(host_ns_fd), || Ok(f()))
        .map_err(|e| anyhow::anyhow!("with_host_ns failed: {}", e))
}

/// Read the MAC address from /sys/class/net/<ifname>/address
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

/// Write a sysctl parameter
fn write_sysctl(key: &str, value: &str) -> Result<()> {
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    fs::write(&path, value).with_context(|| format!("Failed to write sysctl {} = {}", key, value))
}

/// Get the MAC address of dae0 (for permanent ARP/NDP entries)
fn get_dae0_mac() -> Result<[u8; 6]> {
    read_mac_from_sysfs(HOST_IF)
}

/// Convert an rtnetlink Error into an anyhow Error
fn from_rtnetlink_err(e: rtnetlink::Error) -> anyhow::Error {
    anyhow::anyhow!("rtnetlink error: {}", e)
}

/// Create an rtnetlink connection to the host NS, returning (connection_task, handle)
fn create_host_handle() -> Result<(tokio::task::JoinHandle<()>, rtnetlink::Handle)> {
    let (connection, handle, _) =
        new_connection().context("Failed to create netlink connection")?;
    let task = tokio::spawn(connection);
    Ok((task, handle))
}

/// Enter daens to create an rtnetlink connection, then switch back to the host NS,
/// returning the daens handle.
/// Since the netlink socket is bound to the current netns when created, subsequent
/// operations sent through this handle will take effect in daens.
fn create_daens_handle(
    proxy_ns_fd: &OwnedFd,
    host_ns_fd: &OwnedFd,
) -> Result<(tokio::task::JoinHandle<()>, rtnetlink::Handle)> {
    // Enter daens
    nix::sched::setns(proxy_ns_fd, nix::sched::CloneFlags::CLONE_NEWNET)
        .context("Failed to enter daens for creating netlink connection")?;

    // Create the netlink connection in daens (the socket is bound to daens)
    let result = new_connection().context("Failed to create daens netlink connection");

    // Switch back to the host NS immediately (whether or not creation succeeded)
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

/// Parse an address string in the form "169.254.0.11/32" into an (IpAddr, u8) pair
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
// Kernel Version Detection
// ============================================================================

/// Detect the kernel version.
/// Returns a (major, minor) tuple.
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
    let major = parts.first()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    let minor = parts
        .get(1)
        .and_then(|s| {
            // Handle cases like "6.7.0" or "6.7-arch"
            let s = s.split(|c: char| !c.is_ascii_digit()).next().unwrap_or(s);
            s.parse::<u32>().ok()
        })
        .unwrap_or(0);
    (major, minor)
}

// ============================================================================
// NetnsManager
// ============================================================================

/// Network namespace manager
///
/// Manages the lifecycle of the named Network namespace `daens`, including:
/// - Creating/destroying the namespace
/// - Creating and configuring the netkit pair (created in the host NS, peer moved into daens)
/// - Configuring IPv4/IPv6 addresses, Routing, permanent ARP/NDP entries
/// - Configuring policy routing (fwmark → table → lo local delivery)
/// - Configuring sysctl parameters
///
/// # Relationship with the original dae
///
/// This implementation is fully aligned with the original dae's `netns_utils.go`:
/// - Does not use `unshare`; uses a named netns instead
/// - The netkit pair is created in the host NS
/// - `setns()` switches via the `/var/run/netns/daens` fd
/// - Uses rtnetlink instead of iproute2 commands
pub struct NetnsManager {
    /// Host-side interface name (dae0) — in the host NS
    host_if: String,
    /// Proxy-side interface name (dae0peer) — in daens
    peer_if: String,
    /// Proxy-side IPv4 address (169.254.0.11/32)
    peer_addr: String,
    /// Interface MTU
    mtu: u32,
    /// Policy routing table ID (2023)
    route_table: u32,
    /// TPROXY_MARK (0x8000000)
    proxy_mark: u32,
    /// TPROXY_MASK (0x8000000)
    proxy_mask: u32,
    /// Namespace name ("daens")
    ns_name: String,
    /// Host netns fd (held to prevent GC reclamation)
    host_ns_fd: Option<OwnedFd>,
    /// daens fd (opened from /var/run/netns/daens)
    proxy_ns_fd: Option<OwnedFd>,
    /// Whether destroy() has been called (prevents double-destroy in Drop)
    destroyed: bool,
    /// Whether to use netkit (false falls back to veth)
    use_netkit: bool,
}

impl Default for NetnsManager {
    fn default() -> Self {
        Self::new()
    }
}

impl NetnsManager {
    /// Create the manager (using hardcoded values)
    ///
    /// The namespace is not created here; only configuration parameters are stored.
    /// The actual creation happens when [`create()`](NetnsManager::create) is called.
    ///
    /// # Hardcoded values
    ///
    /// | Parameter | Value | Description |
    /// |------|------|------|
    /// | ns_name | "dae-rs" | Namespace name |
    /// | host_if | "dae0" | Host-side interface name |
    /// | peer_if | "dae0peer" | Proxy-side interface name |
    /// | peer_addr | "169.254.0.11/32" | Proxy-side address |
    /// | mtu | 1500 | Interface MTU |
    /// | route_table | 2023 | Policy routing table ID |
    /// | proxy_mark | 0x08000000 | TPROXY_MARK |
    /// | proxy_mask | 0x08000000 | TPROXY_MASK |
    pub fn new() -> Self {
        let use_netkit = Self::probe_netkit();
        Self {
            host_if: HOST_IF.into(),
            peer_if: PEER_IF.into(),
            peer_addr: PEER_ADDR.into(),
            mtu: DEFAULT_MTU,
            route_table: DEFAULT_ROUTE_TABLE,
            proxy_mark: PROXY_MARK,
            proxy_mask: PROXY_MASK,
            ns_name: NS_NAME.into(),
            host_ns_fd: None,
            proxy_ns_fd: None,
            destroyed: false,
            use_netkit,
        }
    }

    /// Probe whether the kernel supports netkit (kernel >= 6.7).
    /// Aligned with upstream dae: only checks kernel version, no sysfs presence check.
    /// sysfs paths like `/sys/module/netkit` are unreliable on some distros where
    /// netkit is built-in rather than as a loadable module.
    pub fn probe_netkit() -> bool {
        let (major, minor) = kernel_version();
        let supported = major > 6 || (major == 6 && minor >= 7);
        info!(
            kernel_version = %format!("{}.{}", major, minor),
            major,
            minor,
            netkit_supported = supported,
            "Netkit probe result"
        );
        supported
    }

    /// Create the named Network namespace and netkit pair
    ///
    /// # Full flow
    ///
    /// Identical to the original dae:
    ///
    /// 1. Save the host netns fd
    /// 2. Clean up residual daens and dae0/dae0peer interfaces (crash-safe)
    /// 3. Create the named Network namespace `daens`
    /// 4. Open `/var/run/netns/daens` to save the daens fd
    /// 5. **In the host NS** create the netkit pair (L2)
    /// 6. Move dae0peer into daens
    /// 7. Configure dae0peer (in daens): IP, Routing, permanent ARP/NDP, sysctl, policy routing
    /// 8. Configure dae0 (in the host NS): IPv6 LL, MTU, up, sysctl
    /// 9. Configure host NS policy routing: rule + route
    ///
    /// # Errors
    ///
    /// - If the namespace is already created, returns [`NetnsError::AlreadyCreated`]
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
        // State tracking: for rollback
        // ----------------------------------------------------------------
        #[allow(unused_assignments)]
        let mut host_ns_fd: Option<OwnedFd> = None;
        #[allow(unused_assignments)]
        let mut proxy_ns_fd: Option<OwnedFd> = None;
        #[allow(unused_assignments)]
        let mut netns_created = false;
        let mut netkit_created = false;
        let mut peer_moved = false;

        // ---- Step 1: Save the host netns fd ----
        {
            let host_ns_file = fs::File::open("/proc/self/ns/net")
                .context("Failed to open /proc/self/ns/net to save host netns fd")?;
            host_ns_fd = Some(OwnedFd::from(host_ns_file));
            info!(
                "Saved host netns fd: {}",
                host_ns_fd.as_ref().unwrap().as_raw_fd()
            );
        }

        // ---- Step 2: Clean up residuals ----
        Self::cleanup_stale_sync();

        // ---- Step 3: Create the named Network namespace ----
        Self::create_named_netns(&self.ns_name)
            .context("Failed to create named network namespace")?;
        netns_created = true;
        info!("Created named network namespace: {}", self.ns_name);

        // ---- Step 4: Open the daens fd ----
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

        // ---- Steps 5-9: async rtnetlink operations ----
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
    // Namespace creation (static helper methods)
    // ----------------------------------------------------------------

    /// Create a named Network namespace (equivalent to `ip netns add <name>`)
    ///
    /// Implementation:
    /// 1. Create the `/var/run/netns/` directory (if it does not exist)
    /// 2. Create the mount point file `/var/run/netns/<name>`
    /// 3. `unshare(CLONE_NEWNET)` to enter the new netns
    /// 4. `mount --bind /proc/self/ns/net /var/run/netns/<name>`
    /// 5. `setns()` back to the host netns
    fn create_named_netns(name: &str) -> Result<()> {
        let start = std::time::Instant::now();
        // Ensure /var/run/netns exists
        fs::create_dir_all(NETNS_RUN_DIR)
            .with_context(|| format!("Failed to create directory {}", NETNS_RUN_DIR))?;

        let ns_path = format!("{}/{}", NETNS_RUN_DIR, name);
        let ns_path = Path::new(&ns_path);

        // Clean up first if the file already exists
        let _ = fs::remove_file(ns_path);

        // Create an empty file as the mount point
        fs::write(ns_path, "")
            .with_context(|| format!("Failed to create mount point {}", ns_path.display()))?;

        // Save the current (host) netns fd
        let host_ns_file =
            fs::File::open("/proc/self/ns/net").context("Failed to open /proc/self/ns/net")?;
        let host_ns_fd = OwnedFd::from(host_ns_file);
        let host_fd_raw = host_ns_fd.as_raw_fd();

        // Create a new Network namespace
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)
            .context("Failed to unshare network namespace")?;

        // Bind mount /proc/self/ns/net to the mount point in the new netns
        nix::mount::mount(
            Some("/proc/self/ns/net"),
            ns_path,
            Some("none"),
            nix::mount::MsFlags::MS_BIND,
            None::<&str>,
        )
        .context("Failed to bind mount namespace")?;

        // Switch back to the host netns
        nix::sched::setns(&host_ns_fd, nix::sched::CloneFlags::CLONE_NEWNET)
            .context("Failed to return to host network namespace")?;

        debug!(
            "Named netns '{}' created (host_fd={}): {}ms",
            name,
            host_fd_raw,
            start.elapsed().as_millis()
        );
        info!("Named network namespace {} created via rtnetlink", name);
        Ok(())
    }

    // ================================================================
    // Sync cleanup and rollback
    // ================================================================

    /// Clean up possibly residual resources (sync version, uses ip commands as fallback)
    fn cleanup_stale_sync() {
        // This method is called at the start of async create(), when the rtnetlink
        // connection may not yet exist. Using ip commands is the most reliable cleanup.
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

    /// Roll back intermediate resources already created in create() (sync version)
    fn rollback_create(
        host_ns_fd: Option<&OwnedFd>,
        netns_created: bool,
        netkit_created: bool,
        peer_moved: bool,
    ) {
        warn!("Rolling back partially created resources");

        // Ensure cleanup runs in the host NS
        if let Some(fd) = host_ns_fd {
            let _ = nix::sched::setns(fd, nix::sched::CloneFlags::CLONE_NEWNET);
        }

        if netns_created {
            if let Err(e) = Self::delete_named_netns_sync(NS_NAME) {
                warn!("Rollback: failed to delete netns {}: {}", NS_NAME, e);
            } else {
                info!("Rollback: deleted netns {}", NS_NAME);
            }
        }

        if peer_moved || netkit_created {
            let _ = Command::new("ip").args(["link", "del", HOST_IF]).output();
            let _ = Command::new("ip").args(["link", "del", PEER_IF]).output();
            info!("Rollback: deleted netkit interfaces");
        }
    }

    /// Execute the async netlink operations for Steps 5-9
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
        // ---- Create the host NS netlink connection ----
        let (host_conn_task, host_handle) =
            create_host_handle().context("Failed to create host netlink connection")?;

        // ---- Create the daens netlink connection ----
        let (daens_conn_task, daens_handle) = create_daens_handle(proxy_ns_fd, host_ns_fd)
            .context("Failed to create daens netlink connection")?;

        // ---- Step 5: Create the link pair (netkit or veth) ----
        if use_netkit {
            debug!("Creating netkit pair (L3 mode) in host NS");
            // L3 mode ensures packets pass through the eBPF TC programs; L2 mode bypasses
            // TC BPF, breaking transparent proxying.
            // probe_netkit() already ensures kernel >= 6.7, so L3 mode is fully compatible.
            let netkit_msg = LinkNetkit::new(host_if, peer_if, NetkitMode::L3)
                .scrub(NetkitScrub::None)
                .peer_scrub(NetkitScrub::None)
                .build();
            host_handle
                .link()
                .add(netkit_msg)
                .execute()
                .await
                .map_err(from_rtnetlink_err)
                .context("Failed to create netkit pair in host namespace")?;
            info!(
                "Created netkit pair (L3 mode) in host NS: {} <-> {}",
                host_if, peer_if
            );
        } else {
            debug!("Creating veth pair in host NS");
            let veth_msg = LinkVeth::new(host_if, peer_if).build();
            host_handle
                .link()
                .add(veth_msg)
                .execute()
                .await
                .map_err(from_rtnetlink_err)
                .context("Failed to create veth pair in host namespace")?;
            info!("Created veth pair in host NS: {} <-> {}", host_if, peer_if);
        }
        *netkit_created = true;

        // ---- Step 5b: netkit forwarding policy ----
        // When creating LinkNetkit via rtnetlink, the kernel default policy is already forward.
        // No extra `ip link set ... type netkit ...` is run here, to avoid false positives from
        // command syntax differences (such as `unknown option "on"?`) and to keep this path
        // purely netlink.

        // ---- Step 6: Move dae0peer into daens ----
        let peer_ifindex = get_ifindex_in_ns(peer_if)?;
        debug!("peer {} ifindex: {}", peer_if, peer_ifindex);

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
        info!("Moved {} to daens (ifindex={})", peer_if, peer_ifindex);

        // ---- Step 7: Configure dae0peer (in daens) ----
        // Create a temporary NetnsManager to pass the configuration
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

        // ---- Step 8: Configure dae0 (in the host NS) ----
        configure_dae0_async(&host_handle, &tmp_mgr)
            .await
            .context("Failed to configure dae0")?;

        // ---- Step 9: Configure host NS policy routing ----
        add_host_policy_routing_async(&host_handle, proxy_mark, proxy_mask, route_table)
            .await
            .context("Failed to add host policy routing")?;

        // Ensure background tasks are dropped
        drop(host_conn_task);
        drop(daens_conn_task);

        Ok(())
    }

    /// Delete the named Network namespace (sync version)
    ///
    /// Uses `MNT_DETACH | MNT_FORCE` to force unmount, consistent with the original dae's
    /// `DeleteNamedNetns`. Returns an error if the unmount or the mount-point file
    /// removal fails, so residual mount points are not silently left behind.
    fn delete_named_netns_sync(name: &str) -> Result<()> {
        let ns_path = format!("{}/{}", NETNS_RUN_DIR, name);
        let ns_path = Path::new(&ns_path);
        // Use umount2 to support MNT_DETACH | MNT_FORCE, consistent with the original dae
        if let Err(e) = nix::mount::umount2(
            ns_path,
            nix::mount::MntFlags::MNT_DETACH | nix::mount::MntFlags::MNT_FORCE,
        ) {
            // Nothing mounted (EINVAL) or path gone (ENOENT) is fine.
            if e != nix::errno::Errno::EINVAL && e != nix::errno::Errno::ENOENT {
                return Err(anyhow::anyhow!(
                    "failed to unmount netns mount point {}: {}",
                    ns_path.display(),
                    e
                ));
            }
        }
        match fs::remove_file(ns_path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(anyhow::anyhow!(
                "failed to remove netns mount point {}: {}",
                ns_path.display(),
                e
            )),
        }
    }

    // ================================================================
    // Query methods
    // ================================================================

    /// Get the ifindex of dae0 in the host NS
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

    /// Get the MAC address of dae0peer in daens
    pub fn get_peer_mac(&self) -> Result<[u8; 6]> {
        let _guard = self.enter_proxy_ns()?;

        // Try sysfs first (sysfs may not reflect the new netns after setns)
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
                // Fall back to parsing MAC from `ip link show`
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
                    let parts: Vec<&str> = line.split_whitespace().collect();
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

                // If the MAC is all zeros (abnormal case), fall back to dae0's MAC
                // In L2 mode the netkit device preserves ethernet frames, so the MAC should be non-zero
                info!("Netkit device with zero MAC, using dae0 MAC as fallback");
                get_dae0_mac()
            }
        }
    }

    /// Get the ifindex of dae0peer in daens
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

    /// Get the inode number of daens (used for eBPF PARAM.dae_netns_id)
    pub fn get_proxy_netns_inode(&self) -> Result<u32> {
        let fd = self.proxy_ns_fd.as_ref().ok_or(NetnsError::NotCreated)?;
        let fd_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
        let metadata =
            fs::metadata(&fd_path).with_context(|| format!("Failed to stat {}", fd_path))?;
        let inode = metadata.st_ino() as u32;
        info!("daens inode (dae_netns_id): {}", inode);
        Ok(inode)
    }

    /// Check whether netkit is used (based on the kernel detection result)
    pub fn is_netkit(&self) -> bool {
        self.use_netkit
    }

    /// Check whether the namespace has been created
    pub fn is_created(&self) -> bool {
        self.host_ns_fd.is_some()
    }

    /// Get the host-side interface name
    pub fn host_if(&self) -> &str {
        &self.host_if
    }

    /// Get the proxy-side interface name
    pub fn peer_if(&self) -> &str {
        &self.peer_if
    }

    /// Get the raw fd of daens
    pub fn get_proxy_ns_fd(&self) -> Option<std::os::unix::io::RawFd> {
        self.proxy_ns_fd.as_ref().map(|fd| fd.as_raw_fd())
    }

    /// Get the raw fd of the host Network namespace (if created).
    ///
    /// Used to pass `host_ns_fd` to the SOCKS5 Dialer / UDP TProxy listener,
    /// so upstream sockets are created in the host NS (aligned with kdae).
    pub fn get_host_ns_fd(&self) -> Option<std::os::unix::io::RawFd> {
        self.host_ns_fd.as_ref().map(|fd| fd.as_raw_fd())
    }

    // ================================================================
    // Namespace switching
    // ================================================================

    /// Switch to daens
    pub fn join_proxy_ns(&self) -> Result<()> {
        let fd = self.proxy_ns_fd.as_ref().ok_or(NetnsError::NotCreated)?;
        nix::sched::setns(fd, nix::sched::CloneFlags::CLONE_NEWNET)
            .context("Failed to switch to daens via setns()")?;
        info!("Switched to daens");
        Ok(())
    }

    /// Switch back to the host namespace
    pub fn join_host_ns(&self) -> Result<()> {
        let fd = self.host_ns_fd.as_ref().ok_or(NetnsError::NotCreated)?;
        nix::sched::setns(fd, nix::sched::CloneFlags::CLONE_NEWNET)
            .context("Failed to switch to host network namespace via setns()")?;
        info!("Switched to host network namespace");
        Ok(())
    }

    /// Enter daens and return an RAII guard
    #[allow(private_interfaces)]
    pub fn enter_proxy_ns(&self) -> Result<NetnsGuard<'_>> {
        NetnsGuard::new(self)
    }

    /// Add a policy routing rule in the host NS (async)
    ///
    /// Makes packets marked with TPROXY_MARK route to local lo via table <route_table>,
    /// where they are eventually received and processed by the TProxy socket.
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

    /// Add an internal address (e.g. `169.254.0.1/32`) to the host `lo` interface.
    ///
    /// Used by the internal DNS forwarder: it listens on an internal link-local
    /// address that must be a local (host NS) address so queries are delivered
    /// locally without hitting the eBPF TProxy path. Binding to `lo` keeps the
    /// address strictly internal — never announced on WAN/LAN.
    ///
    /// Idempotent: any existing address is removed first, then re-added (avoids
    /// `EEXIST` on restart). Must be called from the host namespace.
    pub async fn add_internal_lo_addr(&self, addr: &str) -> Result<()> {
        let addr = addr.to_string();
        // Delete-then-add keeps the operation idempotent across restarts.
        let _ = tokio::process::Command::new("ip")
            .args(["addr", "del", &addr, "dev", "lo"])
            .status()
            .await;
        let status = tokio::process::Command::new("ip")
            .args(["addr", "add", &addr, "dev", "lo"])
            .status()
            .await
            .context("Failed to execute `ip addr add`")?;
        if !status.success() {
            anyhow::bail!(
                "`ip addr add {} dev lo` failed with status {:?}",
                addr,
                status.code()
            );
        }
        info!(addr = %addr, "Internal address added to host lo");
        Ok(())
    }

    // ================================================================
    // Destruction
    // ================================================================

    /// Destroy Network namespace and netkit pair
    ///
    /// Complete cleanup flow:
    /// 1. Delete host NS policy routing rules
    /// 2. Delete the netkit pair
    /// 3. Delete the named Network namespace
    /// 4. Close the fds holding the netns
    ///
    /// Destroy Network namespace and netkit pair
    ///
    /// Uses synchronous cleanup only — avoids `tokio::task::block_in_place`
    /// which can panic if called during tokio runtime shutdown (Drop context).
    /// The sync fallback uses `ip` commands which are reliable for cleanup.
    pub fn destroy(&mut self) -> Result<()> {
        if self.destroyed {
            return Ok(());
        }
        info!("Destroying network namespace and netkit pair");

        // Always use synchronous cleanup to avoid block_in_place panics
        // in tokio runtime shutdown context (e.g. Drop).
        let errors = self.destroy_sync_fallback();

        // ---- Step 4: Close the netns fds ----
        self.host_ns_fd.take();
        self.proxy_ns_fd.take();
        self.destroyed = true;

        if errors.is_empty() {
            info!("Network namespace and netkit pair destroyed successfully");
            Ok(())
        } else {
            for e in &errors {
                error!("Network namespace cleanup error: {}", e);
            }
            Err(anyhow::anyhow!(
                "Network namespace cleanup completed with {} error(s)",
                errors.len()
            ))
        }
    }

    /// Async destruction (called by destroy() in the tokio runtime)
    #[allow(dead_code)]
    async fn destroy_async(&self) -> Result<()> {
        let (host_task, host_handle) =
            create_host_handle().context("Failed to create host netlink connection for destroy")?;

        // ---- Step 1: Delete host NS policy Routing rules ----
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

        // ---- Step 2: Delete netkit pair ----
        // Get dae0 ifindex
        let host_ifindex = get_host_ifindex_sync(&self.host_if).unwrap_or(0);
        if host_ifindex > 0 {
            if let Err(e) = host_handle.link().del(host_ifindex).execute().await {
                warn!("Failed to delete {} via rtnetlink: {}", self.host_if, e);
                // Also try to delete peer_if
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

        // ---- Step 3: Delete named Network namespace ----
        if let Err(e) = Self::delete_named_netns_sync(&self.ns_name) {
            warn!("Failed to delete named netns {}: {}", self.ns_name, e);
        }

        Ok(())
    }

    /// Sync destruction fallback (uses ip commands).
    ///
    /// Collects every cleanup failure instead of silently swallowing it, so
    /// residual netkit/veth links or netns mount points are reported to the
    /// caller (and logged) rather than left invisible.
    fn destroy_sync_fallback(&self) -> Vec<anyhow::Error> {
        warn!("Using sync fallback for destroy (no tokio runtime available)");
        let mut errors: Vec<anyhow::Error> = Vec::new();

        // ---- Step 1: Delete host NS policy Routing rules ----
        // Best-effort: remove_host_policy_routing_sync() retries until the
        // rules are gone and swallows individual failures internally.
        remove_host_policy_routing_sync(self.proxy_mark, self.proxy_mask, self.route_table);

        // ---- Step 2: Delete netkit pair ----
        for link in [&self.host_if, &self.peer_if] {
            match Command::new("ip").args(["link", "delete", link]).output() {
                Ok(o) if o.status.success() => {}
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    // "Cannot find device" / "No such device" = the link was never
                    // created or is already gone — not an error.
                    if stderr.contains("Cannot find device")
                        || stderr.contains("No such device")
                    {
                        debug!("ip link delete {}: already gone ({})", link, stderr.trim());
                    } else {
                        errors.push(anyhow::anyhow!(
                            "ip link delete {} failed: {}",
                            link,
                            stderr.trim()
                        ));
                    }
                }
                Err(e) => errors.push(anyhow::anyhow!(
                    "failed to run ip link delete {}: {}",
                    link,
                    e
                )),
            }
        }

        // ---- Step 3: Delete named Network namespace ----
        if let Err(e) = Self::delete_named_netns_sync(&self.ns_name) {
            errors.push(e);
        }

        errors
    }
}

// ============================================================================
// Drop
// ============================================================================

impl Drop for NetnsManager {
    /// Clean up resources automatically on Drop
    ///
    /// Calls the synchronous cleanup directly, avoiding the use of `block_in_place`
    /// in a tokio runtime context, because Drop may be invoked during tokio runtime
    /// shutdown, when `block_in_place` would panic.
    fn drop(&mut self) {
        if !self.destroyed && (self.host_ns_fd.is_some() || self.proxy_ns_fd.is_some()) {
            warn!("NetnsManager dropped without explicit destroy(), cleaning up via sync fallback");
            for e in self.destroy_sync_fallback() {
                error!("Network namespace cleanup (Drop) error: {}", e);
            }

            // Close the fds holding the netns
            self.host_ns_fd.take();
            self.proxy_ns_fd.take();
            self.destroyed = true;
        }
    }
}

// ============================================================================
// Helper function: get ifindex (sync)
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

#[allow(dead_code)]
fn get_peer_ifindex_sync(ifname: &str) -> Result<u32> {
    get_ifindex_in_ns(ifname)
}

// ============================================================================
// Configuration functions (async, using rtnetlink)
// ============================================================================

/// Configure dae0peer (in daens)
///
/// Corresponds to the original dae's:
/// - `setupNetns()` — lo/dae0peer up
/// - `setupIPv4Datapath()` — 169.254.0.11/32 + Routing + ARP
/// - `setupIPv6Datapath()` — default routing + NDP
/// - `setupSysctl()` — sysctl parameters
/// - `setupRoutingPolicy()` — fwmark policy routing
async fn configure_dae0peer_async(
    daens_handle: &rtnetlink::Handle,
    mgr: &NetnsManager,
    proxy_ns_fd: &OwnedFd,
    host_ns_fd: &OwnedFd,
) -> Result<()> {
    let start = std::time::Instant::now();
    info!("Configuring dae0peer in daens");
    debug!(
        peer_if = %mgr.peer_if,
        mtu = mgr.mtu,
        route_table = mgr.route_table,
        proxy_mark = format!("{:#x}", mgr.proxy_mark),
        "dae0peer config parameters"
    );

    // Get the ifindex of dae0peer in daens (requires entering daens first)
    // Use setns to temporarily enter daens for the lookup
    let peer_ifindex = {
        nix::sched::setns(proxy_ns_fd, nix::sched::CloneFlags::CLONE_NEWNET)
            .context("Failed to enter daens to get peer ifindex")?;
        let _guard = NetnsSwitchGuard::new(host_ns_fd);
        let ifindex =
            get_ifindex_in_ns(&mgr.peer_if).context("Failed to get dae0peer ifindex in daens")?;
        drop(_guard);
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

    // ---- lo up (the lo in a new netns is down by default) ----
    // Need to get lo's ifindex in daens
    let lo_ifindex = {
        nix::sched::setns(proxy_ns_fd, nix::sched::CloneFlags::CLONE_NEWNET)
            .context("Failed to enter daens to get lo ifindex")?;
        let _guard = NetnsSwitchGuard::new(host_ns_fd);
        let ifindex = get_ifindex_in_ns("lo").context("Failed to get lo ifindex in daens")?;
        drop(_guard);
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

    // ---- IPv4 address: 169.254.0.11/32 ----
    let (peer_ip, peer_prefix) = parse_addr_prefix(&mgr.peer_addr)?;
    daens_handle
        .address()
        .add(peer_ifindex, peer_ip, peer_prefix)
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to add IPv4 address to dae0peer")?;

    // ---- IPv4 Routing: 169.254.0.1 dev dae0peer (link-local next hop, scope link) ----
    // The original dae explicitly sets scope = LINK so the kernel treats 169.254.0.1 as directly reachable
    let nexthop_ip: std::net::Ipv4Addr = NEXTHOP_ADDR
        .parse()
        .context("Failed to parse NEXTHOP_ADDR")?;
    let mut nexthop_route = RouteMessage::default();
    nexthop_route.header.address_family = AddressFamily::Inet;
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

    // ---- IPv4 default routing: default via 169.254.0.1 dev dae0peer ----
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

    // ---- Permanent ARP entry: 169.254.0.1 → dae0's MAC ----
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

    // Parse the MAC into a byte array
    let mac_bytes: Vec<u8> = dae0_mac
        .split(':')
        .filter_map(|h| u8::from_str_radix(h, 16).ok())
        .collect();
    if mac_bytes.len() != 6 {
        return Err(anyhow::anyhow!("Invalid MAC address bytes: {}", dae0_mac));
    }

    // Add the permanent ARP entry
    daens_handle
        .neighbours()
        .add(peer_ifindex, std::net::IpAddr::V4(nexthop_ip))
        .link_layer_address(&mac_bytes)
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to add permanent ARP entry")?;

    // ---- IPv6 default routing: default via fe80::ecee:eeff:feee:eeee dev dae0peer ----
    let ipv6_ll_addr: std::net::Ipv6Addr = IPV6_LL.parse().context("Failed to parse IPV6_LL")?;
    // Use the v6 version of RouteMessageBuilder
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

    // ---- Permanent NDP entry ----
    daens_handle
        .neighbours()
        .add(peer_ifindex, std::net::IpAddr::V6(ipv6_ll_addr))
        .link_layer_address(&mac_bytes)
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to add permanent NDP entry")?;

    // ---- sysctl: daens accept_local (must be set in daens) ----
    // Fully aligned with the original dae (kdae): only accept_local and early_demux
    // are set in daens.
    // Note: ip_forward=1 and rp_filter=0 are NOT set — the original dae does not set
    // them in daens.
    // ip_forward=1 enables the kernel IP forwarding path, which may interfere with the
    // return-path routing of TProxy sockets.
    {
        nix::sched::setns(proxy_ns_fd, nix::sched::CloneFlags::CLONE_NEWNET)
            .context("Failed to enter daens to set accept_local")?;
        let _guard = NetnsSwitchGuard::new(host_ns_fd);
        write_sysctl("net.ipv4.conf.all.accept_local", "1")
            .context("Failed to set accept_local on all in daens")?;
        write_sysctl("net.ipv4.conf.lo.accept_local", "1")
            .context("Failed to set accept_local on lo in daens")?;
        write_sysctl(&format!("net.ipv4.conf.{}.accept_local", mgr.peer_if), "1")
            .context("Failed to set accept_local on dae0peer")?;
        drop(_guard);
    }

    // ---- sysctl: early_demux (must be set in daens) ----
    {
        nix::sched::setns(proxy_ns_fd, nix::sched::CloneFlags::CLONE_NEWNET)
            .context("Failed to enter daens to set early_demux")?;
        let _guard = NetnsSwitchGuard::new(host_ns_fd);
        write_sysctl("net.ipv4.tcp_early_demux", "1")
            .context("Failed to set tcp_early_demux in daens")?;
        write_sysctl("net.ipv4.ip_early_demux", "1")
            .context("Failed to set ip_early_demux in daens")?;
        drop(_guard);
    }

    // ---- Policy routing: fwmark/mask → table 2023 ----
    add_policy_routing_in_daens(
        daens_handle,
        mgr.proxy_mark,
        mgr.proxy_mask,
        mgr.route_table,
    )
    .await?;

    debug!(
        "dae0peer configuration in daens completed: {}ms",
        start.elapsed().as_millis()
    );
    info!("dae0peer configuration in daens completed");
    Ok(())
}

/// Add a policy routing rule in daens
///
/// Adds the rule: `fwmark <proxy_mark>/<proxy_mask> → table <route_table>`
/// Note that proxy_mask covers both the fwmark_proxy and fwmark_bypass bits
/// (mask=0x0f000000), so both FRA_FWMARK and FRA_FWMASK must be set.
async fn add_policy_routing_in_daens(
    daens_handle: &rtnetlink::Handle,
    proxy_mark: u32,
    proxy_mask: u32,
    route_table: u32,
) -> Result<()> {
    let start = std::time::Instant::now();
    info!("Adding policy routing in daens");
    debug!(
        proxy_mark = format!("{:#x}", proxy_mark),
        proxy_mask = format!("{:#x}", proxy_mask),
        route_table = route_table,
        "Policy routing params"
    );

    // IPv4 policy routing: fwmark <proxy_mark>/<proxy_mask> → table <route_table>
    let mut v4_req = daens_handle.rule().add();
    v4_req = v4_req.fw_mark(proxy_mark);
    v4_req.message_mut().header.action = RuleAction::ToTable;
    v4_req
        .message_mut()
        .attributes
        .push(RuleAttribute::FwMask(proxy_mask));
    v4_req = v4_req.table_id(route_table);
    v4_req
        .v4()
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to add IPv4 policy routing rule in daens")?;

    // IPv6 policy routing: fwmark <proxy_mark>/<proxy_mask> → table <route_table>
    let mut v6_req = daens_handle.rule().add();
    v6_req = v6_req.fw_mark(proxy_mark);
    v6_req.message_mut().header.action = RuleAction::ToTable;
    v6_req
        .message_mut()
        .attributes
        .push(RuleAttribute::FwMask(proxy_mask));
    v6_req = v6_req.table_id(route_table);
    v6_req
        .v6()
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to add IPv6 policy routing rule in daens")?;

    // ---- local default dev lo table <table> ----
    // Need to get lo's ifindex in daens
    // But we already have the daens_handle, which operates in daens.

    // IPv4: local default dev lo table <table>
    // Build the routing message: local type, oif=lo_ifindex, table=<table>
    // Need to get lo's ifindex first
    // Since the daens_handle socket is in daens, lookups return daens' lo
    let local_default_v4 = RouteMessageBuilder::<std::net::Ipv4Addr>::new()
        .output_interface(1) // lo is usually ifindex 1 in a netns
        .build();
    // Change the routing type to local
    let mut msg_v4 = local_default_v4;
    msg_v4.header.kind = RouteType::Local;
    msg_v4.header.scope = RouteScope::Host; // RTN_LOCAL must use host scope (254)
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
    msg_v6.header.scope = RouteScope::Host; // RTN_LOCAL must use host scope (254)
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

    debug!(
        "Policy routing in daens added: {}ms",
        start.elapsed().as_millis()
    );
    info!("Policy routing in daens added successfully");

    Ok(())
}

/// Configure dae0 (in the host NS)
///
/// Corresponds to the original dae's:
/// - `setupIPv6Datapath()` — IPv6 LL address
/// - `setupSysctl()` — host-side sysctl parameters
async fn configure_dae0_async(host_handle: &rtnetlink::Handle, mgr: &NetnsManager) -> Result<()> {
    let start = std::time::Instant::now();
    info!("Configuring dae0 in host namespace");
    debug!(
        host_if = %mgr.host_if,
        mtu = mgr.mtu,
        "dae0 config parameters"
    );

    // Get dae0 ifindex
    let host_ifindex = get_host_ifindex_sync(&mgr.host_if).context("Failed to get dae0 ifindex")?;

    // ---- IPv6 link-local address ----
    let ipv6_ll_addr: std::net::Ipv6Addr = IPV6_LL.parse().context("Failed to parse IPV6_LL")?;
    host_handle
        .address()
        .add(host_ifindex, std::net::IpAddr::V6(ipv6_ll_addr), 128)
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to add IPv6 LL address to dae0")?;

    // ---- Set MTU ----
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

    // ---- Bring dae0 up ----
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

    // ---- sysctl parameters ----
    write_sysctl(&format!("net.ipv4.conf.{}.rp_filter", mgr.host_if), "0")?;
    write_sysctl("net.ipv4.conf.all.rp_filter", "0")?;
    write_sysctl(&format!("net.ipv4.conf.{}.arp_filter", mgr.host_if), "0")?;
    write_sysctl("net.ipv4.conf.all.arp_filter", "0")?;
    write_sysctl(&format!("net.ipv4.conf.{}.accept_local", mgr.host_if), "1")?;
    write_sysctl(&format!("net.ipv4.conf.{}.forwarding", mgr.host_if), "1")?;
    write_sysctl(&format!("net.ipv6.conf.{}.disable_ipv6", mgr.host_if), "0")?;
    write_sysctl(&format!("net.ipv6.conf.{}.forwarding", mgr.host_if), "1")?;

    debug!(
        "dae0 configuration in host NS completed: {}ms",
        start.elapsed().as_millis()
    );
    info!("dae0 configuration in host namespace completed");
    Ok(())
}

/// Add a policy routing rule in the host NS
async fn add_host_policy_routing_async(
    host_handle: &rtnetlink::Handle,
    proxy_mark: u32,
    proxy_mask: u32,
    route_table: u32,
) -> Result<()> {
    info!("Adding host NS policy routing");
    debug!(
        proxy_mark = format!("{:#x}", proxy_mark),
        proxy_mask = format!("{:#x}", proxy_mask),
        route_table = route_table,
        "Host policy routing params"
    );

    // ---- First check whether the rule already exists (avoid duplicates) ----
    //
    // Example `ip rule show` output:
    //   0: from all lookup local
    //   32765: from all fwmark 0x8000000/0x8000000 lookup 2023
    // There are both v4 and v6 rules (same output; the kernel distinguishes family automatically).
    // Therefore only at least one match needs to be checked.
    let mark_str = format!("{:#x}", proxy_mark);
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

    // ---- Delete possibly residual rules (ensure a clean state) ----
    let _ =
        remove_host_policy_routing_async(host_handle, proxy_mark, proxy_mask, route_table).await;

    // IPv4: fwmark <proxy_mark>/<proxy_mask> → table <route_table>
    let mut v4_req = host_handle.rule().add();
    v4_req = v4_req.fw_mark(proxy_mark);
    v4_req.message_mut().header.action = RuleAction::ToTable;
    v4_req
        .message_mut()
        .attributes
        .push(RuleAttribute::FwMask(proxy_mask));
    v4_req = v4_req.table_id(route_table);
    v4_req
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
    local_default_v4.header.scope = RouteScope::Host; // RTN_LOCAL must use host scope (254)
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

    // IPv6: fwmark <proxy_mark>/<proxy_mask> → table <route_table>
    let mut v6_req = host_handle.rule().add();
    v6_req = v6_req.fw_mark(proxy_mark);
    v6_req.message_mut().header.action = RuleAction::ToTable;
    v6_req
        .message_mut()
        .attributes
        .push(RuleAttribute::FwMask(proxy_mask));
    v6_req = v6_req.table_id(route_table);
    v6_req
        .v6()
        .execute()
        .await
        .map_err(from_rtnetlink_err)
        .context("Failed to add IPv6 policy routing rule")?;

    let mut local_default_v6 = RouteMessageBuilder::<std::net::Ipv6Addr>::new()
        .output_interface(1)
        .build();
    local_default_v6.header.kind = RouteType::Local;
    local_default_v6.header.scope = RouteScope::Host; // RTN_LOCAL must use host scope (254)
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

/// Remove the host NS policy routing rule (async)
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
        rule_v4.attributes.push(RuleAttribute::FwMark(proxy_mark));
        rule_v4.attributes.push(RuleAttribute::FwMask(proxy_mask));
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
        rule_v6.attributes.push(RuleAttribute::FwMark(proxy_mark));
        rule_v6.attributes.push(RuleAttribute::FwMask(proxy_mask));
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

    // Delete local default routes
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

/// Remove the host NS policy routing rule (sync version, uses ip commands)
///
/// Uses a while loop to delete all matching rules, avoiding residual duplicates.
fn remove_host_policy_routing_sync(proxy_mark: u32, proxy_mask: u32, route_table: u32) {
    let mark_str = format!("{:#x}/{:#x}", proxy_mark, proxy_mask);
    let table_str = route_table.to_string();

    // Delete local default routes
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

    // Loop to delete all matching IPv4 rules
    loop {
        let output = Command::new("ip")
            .args(["rule", "del", "fwmark", &mark_str, "table", &table_str])
            .output();
        match output {
            Ok(o) if o.status.success() => continue,
            _ => break,
        }
    }

    // Loop to delete all matching IPv6 rules
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
// Unit test
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netns_manager_new() {
        let mgr = NetnsManager::new();

        assert_eq!(mgr.host_if, "dae0");
        assert_eq!(mgr.peer_if, "dae0peer");
        assert_eq!(mgr.peer_addr, "169.254.0.11/32");
        assert_eq!(mgr.mtu, 1500);
        assert_eq!(mgr.route_table, 2023);
        assert_eq!(mgr.proxy_mark, 0x08000000);
        assert_eq!(mgr.proxy_mask, 0x08000000);
        assert_eq!(mgr.ns_name, "dae-rs");
        assert!(mgr.host_ns_fd.is_none());
        assert!(mgr.proxy_ns_fd.is_none());
        assert!(!mgr.is_created());
    }

    #[test]
    fn test_destroy_without_create() {
        let mut mgr = NetnsManager::new();

        // destroy() should be safely callable without prior creation
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
