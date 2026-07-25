//! eBPF program lifecycle manager
//!
//! This module manages the full lifecycle of eBPF programs in userspace,
//! including loading from bytecode, TC attachment/detachment, and map I/O.
//!
//! Uses libbpf-rs (replacing aya-rs) to load and manage eBPF programs
//! compiled from dae's C eBPF source (tproxy.c).

use anyhow::{Context, Result};
use bytemuck::{self, Zeroable};
use libbpf_rs::{MapCore, MapFlags, ProgramType};
use libbpf_rs::{Object, ObjectBuilder, TcHook, TC_EGRESS, TC_INGRESS};
use std::ffi::OsStr;
use std::os::unix::io::AsFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum EbpfError {
    #[error("eBPF program not loaded")]
    NotLoaded,
    #[error("eBPF program already loaded")]
    AlreadyLoaded,
    #[error("Map '{name}' not found")]
    MapNotFound { name: String },
    #[error("TC attach failed on interface {iface}: {detail}")]
    TcAttachError { iface: String, detail: String },
    #[error("Interface {0} not found")]
    InterfaceNotFound(String),
}

// ============================================================================
// Constants
// ============================================================================

pub const DEFAULT_EBPF_PATH: &str = "/etc/dae-rs/ebpf.o";
pub const ROUTING_MAP_MAX: u32 = 1024;
pub const STATS_MAP_SIZE: u32 = 2;
pub const MAX_MATCH_SET_LEN: usize = 32 * 32; // 1024, must match tproxy.c

// ============================================================================
// Data Structures (must match tproxy.c definitions exactly)
// ============================================================================

// ---- tproxy.c: struct dae_param ----
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct Daeparam {
    pub tproxy_port: u32,
    pub control_plane_pid: u32,
    pub dae0_ifindex: u32,
    pub dae_netns_id: u32,
    pub dae0peer_mac: [u8; 6],
    pub padding_after_mac: [u8; 2],
    pub use_redirect_peer: u8,
    pub has_bpf_get_current_task: u8,
    pub padding2: u16,
    pub dae_socket_mark: u32,
}

impl Default for Daeparam {
    fn default() -> Self {
        Self {
            tproxy_port: 0,
            control_plane_pid: 0,
            dae0_ifindex: 0,
            dae_netns_id: 0,
            dae0peer_mac: [0u8; 6],
            padding_after_mac: [0u8; 2],
            use_redirect_peer: 0,
            has_bpf_get_current_task: 0,
            padding2: 0,
            // 原版 dae 使用 0x100 作为内部 socket 标记
            // 用于 bpf_sock_is_dae_socket() 和 pid_is_control_plane() 中的 mark 检查
            dae_socket_mark: 0x100,
        }
    }
}

// ---- tproxy.c: struct tuples_key ----
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, bytemuck::Pod, bytemuck::Zeroable)]
pub struct TuplesKey {
    pub sip: [u8; 16],
    pub dip: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub l4proto: u8,
    pub _pad: [u8; 3],
}

impl TuplesKey {
    pub fn from_ipv4(
        src_ip: &[u8; 4],
        dst_ip: &[u8; 4],
        src_port: u16,
        dst_port: u16,
        l4proto: u8,
    ) -> Self {
        let mut sip = [0u8; 16];
        let mut dip = [0u8; 16];
        sip[10] = 0xff;
        sip[11] = 0xff;
        sip[12..16].copy_from_slice(src_ip);
        dip[10] = 0xff;
        dip[11] = 0xff;
        dip[12..16].copy_from_slice(dst_ip);
        Self {
            sip,
            dip,
            sport: src_port,
            dport: dst_port,
            l4proto,
            _pad: [0u8; 3],
        }
    }
    pub fn from_ipv6(
        src_ip: &[u8; 16],
        dst_ip: &[u8; 16],
        src_port: u16,
        dst_port: u16,
        l4proto: u8,
    ) -> Self {
        Self {
            sip: *src_ip,
            dip: *dst_ip,
            sport: src_port,
            dport: dst_port,
            l4proto,
            _pad: [0u8; 3],
        }
    }
    pub fn reverse(&self) -> Self {
        Self {
            sip: self.dip,
            dip: self.sip,
            sport: self.dport,
            dport: self.sport,
            l4proto: self.l4proto,
            _pad: [0u8; 3],
        }
    }
}

// ---- tproxy.c: union routing_meta ----
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct RoutingMeta {
    pub mark: u32,
    pub outbound: u8,
    pub must: u8,
    pub dscp: u8,
    pub has_routing: u8,
}

// ---- tproxy.c: struct conn_state ----
/// Size: 56 bytes (aligned to 8). Explicit tail padding for bytemuck::Pod compatibility.
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ConnState {
    pub is_wan_ingress_direction_raw: u8,
    pub state: u8,
    pub _pad1: [u8; 6], // pad to align u64
    pub last_seen_ns: u64,
    pub meta: RoutingMeta,
    pub mac: [u8; 6],
    pub _pad2: [u8; 2], // pad to align pname
    pub pname: [u8; 16],
    pub pid: u32,
    pub _tail_pad: [u8; 4], // pad total to 56 (multiple of max alignment 8)
}

impl ConnState {
    pub fn is_wan_ingress_direction(&self) -> bool {
        self.is_wan_ingress_direction_raw != 0
    }
}

// ---- tproxy.c: struct pid_pname ----
/// Size: 32 bytes (aligned to 8). Explicit tail padding for bytemuck::Pod.
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ProcInfo {
    pub last_seen_ns: u64,
    pub pid: u32,
    pub pname: [u8; 16],
    pub _tail_pad: [u8; 4],
}

/// Stats map indices (bpf_stats_map in tproxy.c)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatIndex {
    UdpConnOverflow = 0,
    TcpConnOverflow = 1,
}

// ---- tproxy.c: struct match_set ----
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct PortRange {
    pub port_start: u16,
    pub port_end: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union MatchSetValue {
    pub index: u32,
    pub port_range: PortRange,
    pub l4proto_type: u8,
    pub ip_version: u8,
    pub pname: [u8; 16],
    pub dscp: u8,
    pub raw: [u8; 16],
}
unsafe impl bytemuck::Zeroable for MatchSetValue {}
unsafe impl bytemuck::Pod for MatchSetValue {}

#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct LpmKey {
    pub prefixlen: u32,
    pub data: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct CidrEntry {
    pub ip: [u8; 16],
    pub prefix_len: u8,
    pub _pad: [u8; 7],
}

impl std::fmt::Debug for MatchSetValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe { write!(f, "MatchSetValue {{ raw: {:?} }}", self.raw) }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct MatchSet {
    pub value: MatchSetValue,
    pub not: u8,
    pub r#type: u8,
    pub outbound: u8,
    pub must: u8,
    pub mark: u32,
}

pub mod match_type {
    pub const DOMAIN_SET: u8 = 0;
    pub const IP_SET: u8 = 1;
    pub const SOURCE_IP_SET: u8 = 2;
    pub const PORT: u8 = 3;
    pub const SOURCE_PORT: u8 = 4;
    pub const L4_PROTO: u8 = 5;
    pub const IP_VERSION: u8 = 6;
    pub const MAC: u8 = 7;
    pub const PROCESS_NAME: u8 = 8;
    pub const DSCP: u8 = 9;
    pub const FALLBACK: u8 = 10;
    pub const MUST_RULES: u8 = 11;
    pub const UPSTREAM: u8 = 12;
    pub const QTYPE: u8 = 13;
}

pub mod outbound {
    pub const DIRECT: u8 = 0x0;
    pub const BLOCK: u8 = 0x1;
    pub const MUST_RULES: u8 = 0xFC;
    pub const CONTROL_PLANE_ROUTING: u8 = 0xFD;
    pub const LOGICAL_OR: u8 = 0xFE;
    pub const LOGICAL_AND: u8 = 0xFF;
    pub const LOGICAL_MASK: u8 = 0xFE;
}

// ---- tproxy.c: struct dae_event (for RingBuffer) ----
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct Daeevent {
    pub timestamp: u64,
    pub type_: u32,
    pub pid: u32,
    pub pname: [u8; 16],
    pub outbound: u8,
    pub l4proto: u8,
    pub pad: [u8; 2],
    pub sip: [u32; 4],
    pub dip: [u32; 4],
    pub sport: u16,
    pub dport: u16,
}

// ============================================================================
// Helpers
// ============================================================================

pub fn if_nametoindex(ifname: &str) -> Result<i32> {
    let cstr = std::ffi::CString::new(ifname)
        .map_err(|e| anyhow::anyhow!("Invalid interface name '{}': {}", ifname, e))?;
    let ifindex = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
    if ifindex == 0 {
        return Err(EbpfError::InterfaceNotFound(ifname.to_string()).into());
    }
    Ok(ifindex as i32)
}

pub fn hash_comm(comm: &str) -> u32 {
    let mut hash: u32 = 5381;
    let bytes = comm.as_bytes();
    let mut i = 0;
    while i < 16 && i < bytes.len() {
        let c = bytes[i];
        if c == 0 {
            break;
        }
        hash = hash.wrapping_mul(33).wrapping_add(c as u32);
        i += 1;
    }
    hash
}

/// Find a program by name in the loaded object.
fn find_prog<'a>(obj: &'a Object, name: &str) -> Result<libbpf_rs::ProgramMut<'a>> {
    let name_os = OsStr::new(name);
    obj.progs_mut()
        .find(|p| p.name() == name_os)
        .ok_or_else(|| anyhow::anyhow!("Program '{}' not found", name))
}

/// Find a map by name in the loaded object (mutable).
fn find_map_mut<'a>(obj: &'a mut Object, name: &str) -> Result<libbpf_rs::MapMut<'a>> {
    let name_os = OsStr::new(name);
    obj.maps_mut().find(|m| m.name() == name_os).ok_or_else(|| {
        EbpfError::MapNotFound {
            name: name.to_string(),
        }
        .into()
    })
}

/// Probe kernel support for bpf_redirect_peer (requires Linux >= 6.8).
///
/// `bpf_redirect_peer` provides performance improvements by bypassing the
/// per-CPU peer backlog and avoiding a cache miss on the destination CPU.
/// However, it must only be used on kernels with the CVE-2025-37959 fix.
///
/// Returns 1 if supported, 0 otherwise.
pub fn probe_redirect_peer() -> u8 {
    let version = match kernel_version() {
        Some(v) => v,
        None => return 0,
    };
    let (major, minor) = version;
    // bpf_redirect_peer was introduced/fixed in Linux 6.8
    if major > 6 || (major == 6 && minor >= 8) {
        info!("Kernel {}.{}: bpf_redirect_peer supported", major, minor);
        1
    } else {
        info!(
            "Kernel {}.{}: bpf_redirect_peer not supported (need >= 6.8)",
            major, minor
        );
        0
    }
}

/// Get kernel version as (major, minor) by reading /proc/sys/kernel/osrelease.
fn kernel_version() -> Option<(u32, u32)> {
    // Try /proc first, fallback to uname -r
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_else(|_| {
        std::process::Command::new("uname")
            .arg("-r")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default()
    });
    let release = release.trim().to_string();
    let parts: Vec<&str> = release.splitn(3, '.').collect();
    if parts.len() < 2 {
        return None;
    }
    let major: u32 = parts[0].parse().ok()?;
    let minor: u32 = parts[1]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .ok()?;
    Some((major, minor))
}

/// Find a map by name in the loaded object (immutable).
fn find_map<'a>(obj: &'a Object, name: &str) -> Result<libbpf_rs::Map<'a>> {
    let name_os = OsStr::new(name);
    obj.maps().find(|m| m.name() == name_os).ok_or_else(|| {
        EbpfError::MapNotFound {
            name: name.to_string(),
        }
        .into()
    })
}

// ============================================================================
// Helpers: set program types for non-standard SEC() names
// ============================================================================

/// The C eBPF source (tproxy.c) uses non-standard TC section names like
/// `SEC("tc/lan_egress_l2")`, `SEC("tc/dae0_ingress")`, etc.
/// Standard libbpf only auto-detects `tc/ingress` and `tc/egress`.
/// This function sets the correct program type for each unrecognized TC section
/// so that `bpf_object__load()` will succeed.
fn set_tc_prog_types(open_obj: &mut libbpf_rs::OpenObject) {
    for mut prog in open_obj.progs_mut() {
        let section = prog.section().to_str().unwrap_or("").to_string();
        let name = prog.name().to_str().unwrap_or("").to_string();
        if section.starts_with("tc/") {
            let old_type = prog.prog_type();
            if matches!(old_type, ProgramType::Unspec) {
                prog.set_prog_type(ProgramType::SchedCls);
                info!(
                    "Set program type: '{}' (section '{}'): {:?} -> SchedCls",
                    name, section, old_type
                );
            } else {
                info!(
                    "Program '{}' (section '{}') already has type {:?}, skipping",
                    name, section, old_type
                );
            }
        } else {
            info!(
                "Program '{}' (section '{}'): type is {:?} (auto-detected)",
                name,
                section,
                prog.prog_type()
            );
        }
    }
}

// ============================================================================
// EbpfManager
// ============================================================================

/// Metadata for a TC hook attachment
#[derive(Debug)]
struct TcAttachInfo {
    hook: TcHook,
    iface: String,
    prog_name: String,
}

/// eBPF program lifecycle manager.
pub struct EbpfManager {
    obj: Option<Object>,
    tc_hooks: Vec<TcAttachInfo>,
    cgroup_links: Vec<libbpf_rs::Link>,
    iface: String,
    bpf_path: String,
    param: Option<Daeparam>,
}

// Safety: EbpfManager is only accessed through RwLock<ControlPlane>
unsafe impl Sync for EbpfManager {}
unsafe impl Send for EbpfManager {}

impl EbpfManager {
    pub fn new(iface: &str) -> Self {
        Self {
            obj: None,
            tc_hooks: Vec::new(),
            cgroup_links: Vec::new(),
            iface: iface.to_string(),
            bpf_path: DEFAULT_EBPF_PATH.to_string(),
            param: None,
        }
    }

    pub fn new_with_path(iface: &str, bpf_path: &str) -> Self {
        Self {
            obj: None,
            tc_hooks: Vec::new(),
            cgroup_links: Vec::new(),
            iface: iface.to_string(),
            bpf_path: bpf_path.to_string(),
            param: None,
        }
    }

    pub fn set_param(&mut self, param: &Daeparam) {
        self.param = Some(*param);
    }

    /// Load eBPF from file using libbpf ObjectBuilder.
    pub fn load(&mut self) -> Result<()> {
        if self.obj.is_some() {
            return Err(EbpfError::AlreadyLoaded.into());
        }

        let path = Path::new(&self.bpf_path);
        info!(bpf_path = %self.bpf_path, iface = %self.iface, "Loading eBPF program via libbpf-rs");

        let mut builder = ObjectBuilder::default();
        let mut open_obj = builder
            .open_file(path)
            .with_context(|| format!("Failed to open eBPF object from {}", self.bpf_path))?;

        // Set PARAM in .rodata map before loading
        if let Some(ref param) = self.param {
            let param_bytes = bytemuck::bytes_of(param);
            for mut map in open_obj.maps_mut() {
                if map.name() == OsStr::new(".rodata") {
                    map.set_initial_value(param_bytes)
                        .with_context(|| "Failed to set .rodata initial value")?;
                    info!("PARAM set in .rodata ({} bytes)", param_bytes.len());
                    break;
                }
            }
        }

        // Fix program types for non-standard TC section names before loading
        set_tc_prog_types(&mut open_obj);

        let obj = open_obj
            .load()
            .context("Failed to load eBPF object into kernel")?;
        info!("eBPF program loaded successfully via libbpf-rs");
        self.obj = Some(obj);
        Ok(())
    }

    /// Load eBPF from memory buffer.
    pub fn load_from_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        if self.obj.is_some() {
            return Err(EbpfError::AlreadyLoaded.into());
        }

        info!(
            len = bytes.len(),
            "Loading eBPF from byte slice via libbpf-rs"
        );

        let mut builder = ObjectBuilder::default();
        let mut open_obj = builder
            .open_memory(bytes)
            .context("Failed to open eBPF object from memory")?;

        if let Some(ref param) = self.param {
            let param_bytes = bytemuck::bytes_of(param);
            for mut map in open_obj.maps_mut() {
                if map.name() == OsStr::new(".rodata") {
                    map.set_initial_value(param_bytes)
                        .with_context(|| "Failed to set .rodata initial value")?;
                    info!("PARAM set in .rodata ({} bytes)", param_bytes.len());
                    break;
                }
            }
        }

        // Fix program types for non-standard TC section names before loading
        set_tc_prog_types(&mut open_obj);

        let obj = open_obj
            .load()
            .context("Failed to load eBPF object from memory into kernel")?;
        info!("eBPF program loaded from byte slice via libbpf-rs");
        self.obj = Some(obj);
        Ok(())
    }

    // ========================================================================
    // 通用 TC attach — 将指定程序列表挂载到目标接口
    // ========================================================================

    /// 通用 TC attach：将指定的程序列表挂载到目标接口
    ///
    /// # 参数
    ///
    /// * `ifname` — 目标接口名称
    /// * `progs` — 程序列表，每项为 (程序名, attach_point)
    ///   attach_point 使用 libbpf_rs::TC_INGRESS 或 libbpf_rs::TC_EGRESS
    pub fn attach_tc(&mut self, ifname: &str, progs: &[(&str, u32)]) -> Result<()> {
        let obj = self.obj.as_ref().ok_or(EbpfError::NotLoaded)?;
        let ifindex = if_nametoindex(ifname).map_err(|e| EbpfError::TcAttachError {
            iface: ifname.into(),
            detail: format!("if_nametoindex: {}", e),
        })?;

        info!(iface = %ifname, ifindex = %ifindex, count = %progs.len(), "Attaching TC programs");

        for (prog_name, attach_point) in progs {
            let prog = match find_prog(obj, prog_name) {
                Ok(p) => p,
                Err(_) => {
                    warn!("TC program '{}' not found, skipping", prog_name);
                    continue;
                }
            };

            let mut hook = TcHook::new(prog.as_fd());
            hook.ifindex(ifindex);
            hook.attach_point(*attach_point);

            // Create clsact qdisc (no-op if already exists)
            hook.create().map_err(|e| EbpfError::TcAttachError {
                iface: ifname.into(),
                detail: format!("create({}): {}", prog_name, e),
            })?;

            // Attach the program
            let attached = hook.attach().map_err(|e| EbpfError::TcAttachError {
                iface: ifname.into(),
                detail: format!("attach({}): {}", prog_name, e),
            })?;

            self.tc_hooks.push(TcAttachInfo {
                hook: attached,
                iface: ifname.into(),
                prog_name: prog_name.to_string(),
            });
            info!(
                "TC program '{}' attached to {} (ifindex={})",
                prog_name, ifname, ifindex
            );
        }

        info!(
            "TC programs attached to {} (total hooks: {})",
            ifname,
            self.tc_hooks.len()
        );
        Ok(())
    }

    // ========================================================================
    // 按接口分组 TC attach
    // ========================================================================

    /// 根据接口链路头长度选择 attach L2 或 L3 版本的 eBPF 程序
    ///
    /// 读取 `/sys/class/net/<ifname>/type` 判断接口类型：
    /// - ARPHRD_ETHER (1) → 14 字节（有以太网头，使用 L2 版本）
    /// - 其他类型（如 ARPHRD_NONE/ARPHRD_TUNNEL）→ 0 字节（无链路头，使用 L3 版本）
    fn get_link_header_len(ifname: &str) -> Result<u32> {
        let path = format!("/sys/class/net/{}/type", ifname);
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read interface type for {}", ifname))?;
        let if_type: u32 = content
            .trim()
            .parse()
            .with_context(|| format!("Invalid interface type value for {}", ifname))?;

        // ARPHRD_ETHER = 1 — 有以太网头
        if if_type == 1 {
            Ok(14) // 以太网头长度
        } else {
            Ok(0) // 无链路头
        }
    }

    /// WAN 接口：根据链路头长度选择 L2 或 L3 版本
    ///
    /// - 有以太网头（link_h_len > 0）→ attach L2 版本
    /// - 无链路头（link_h_len == 0）→ attach L3 版本
    pub fn attach_wan(&mut self, ifname: &str) -> Result<()> {
        let link_h_len = Self::get_link_header_len(ifname)?;
        info!(
            "Attaching WAN TC programs to {} (link_h_len={})",
            ifname, link_h_len
        );

        let egress_progs = if link_h_len > 0 {
            vec![("tproxy_wan_egress_l2", TC_EGRESS)]
        } else {
            vec![("tproxy_wan_egress_l3", TC_EGRESS)]
        };

        let ingress_progs = if link_h_len > 0 {
            vec![("tproxy_wan_ingress_l2", TC_INGRESS)]
        } else {
            vec![("tproxy_wan_ingress_l3", TC_INGRESS)]
        };

        let mut all_progs = egress_progs;
        all_progs.extend(ingress_progs);

        self.attach_tc(ifname, &all_progs)
    }

    /// LAN 接口：根据链路头长度选择 L2 或 L3 版本
    ///
    /// - 有以太网头（link_h_len > 0）→ attach L2 版本
    /// - 无链路头（link_h_len == 0）→ attach L3 版本
    pub fn attach_lan(&mut self, ifname: &str) -> Result<()> {
        let link_h_len = Self::get_link_header_len(ifname)?;
        info!(
            "Attaching LAN TC programs to {} (link_h_len={})",
            ifname, link_h_len
        );

        let ingress_progs = if link_h_len > 0 {
            vec![("tproxy_lan_ingress_l2", TC_INGRESS)]
        } else {
            vec![("tproxy_lan_ingress_l3", TC_INGRESS)]
        };

        let egress_progs = if link_h_len > 0 {
            vec![("tproxy_lan_egress_l2", TC_EGRESS)]
        } else {
            vec![("tproxy_lan_egress_l3", TC_EGRESS)]
        };

        let mut all_progs = ingress_progs;
        all_progs.extend(egress_progs);

        self.attach_tc(ifname, &all_progs)
    }

    /// dae0（宿主 NS）：挂载 tproxy_dae0_ingress
    pub fn attach_dae0(&mut self, ifname: &str) -> Result<()> {
        info!("Attaching dae0 TC program to {}", ifname);
        self.attach_tc(ifname, &[("tproxy_dae0_ingress", TC_INGRESS)])
    }

    /// dae0peer（代理 NS）：挂载 tproxy_dae0peer_ingress
    pub fn attach_dae0peer(&mut self, ifname: &str) -> Result<()> {
        info!("Attaching dae0peer TC program to {}", ifname);
        self.attach_tc(ifname, &[("tproxy_dae0peer_ingress", TC_INGRESS)])
    }

    // ========================================================================
    // cgroup 程序 attach
    // ========================================================================

    /// 在代理 NS 中 attach cgroup 程序
    ///
    /// tproxy.c 中有 6 个 cgroup 程序需要 attach：
    /// - tproxy_wan_cg_sock_create (cgroup/sock_create)
    /// - tproxy_wan_cg_sock_release (cgroup/sock_release)
    /// - tproxy_wan_cg_connect4 (cgroup/connect4)
    /// - tproxy_wan_cg_connect6 (cgroup/connect6)
    /// - tproxy_wan_cg_sendmsg4 (cgroup/sendmsg4)
    /// - tproxy_wan_cg_sendmsg6 (cgroup/sendmsg6)
    ///
    /// # 参数
    ///
    /// * `cgroup_fd` — cgroup 文件描述符（通常为 /sys/fs/cgroup 的 fd）
    pub fn attach_cgroup(&mut self, cgroup_fd: std::os::unix::io::RawFd) -> Result<()> {
        let obj = self.obj.as_ref().ok_or(EbpfError::NotLoaded)?;

        let cgroup_progs = [
            "tproxy_wan_cg_sock_create",
            "tproxy_wan_cg_sock_release",
            "tproxy_wan_cg_connect4",
            "tproxy_wan_cg_connect6",
            "tproxy_wan_cg_sendmsg4",
            "tproxy_wan_cg_sendmsg6",
        ];

        for name in &cgroup_progs {
            let prog = match find_prog(obj, name) {
                Ok(p) => p,
                Err(_) => {
                    warn!("cgroup program '{}' not found, skipping", name);
                    continue;
                }
            };

            // libbpf-rs ProgramMut::attach_cgroup takes a raw fd (i32)
            match prog.attach_cgroup(cgroup_fd) {
                Ok(link) => {
                    self.cgroup_links.push(link);
                    info!("cgroup program '{}' attached", name);
                }
                Err(e) => {
                    warn!("Failed to attach cgroup program '{}': {}", name, e);
                }
            }
        }

        info!(
            "cgroup programs attached ({} links)",
            self.cgroup_links.len()
        );
        Ok(())
    }

    // ========================================================================
    // 分离 & 卸载
    // ========================================================================

    /// 分离所有 TC 程序和 cgroup 程序
    pub fn detach_all(&mut self) -> Result<()> {
        // Detach TC hooks
        if !self.tc_hooks.is_empty() {
            info!(count = self.tc_hooks.len(), "Detaching TC programs");
            for info in self.tc_hooks.iter_mut() {
                if let Err(e) = info.hook.detach() {
                    warn!(
                        "Failed to detach TC hook '{}' on {}: {}",
                        info.prog_name, info.iface, e
                    );
                }
            }
            self.tc_hooks.clear();
        }

        // Detach cgroup links (drop the ProgramAttachment)
        if !self.cgroup_links.is_empty() {
            info!(count = self.cgroup_links.len(), "Detaching cgroup programs");
            self.cgroup_links.clear();
        }

        Ok(())
    }

    /// 卸载 eBPF 程序（先分离所有 hook，再释放对象）
    pub fn unload(&mut self) -> Result<()> {
        info!("Unloading eBPF program");
        self.detach_all()?;
        self.obj.take();
        Ok(())
    }

    // ============================================================================
    // Map Operations
    // ============================================================================

    pub fn get_map_mut(&mut self, name: &str) -> Result<libbpf_rs::MapMut<'_>> {
        let obj = self.obj.as_mut().ok_or(EbpfError::NotLoaded)?;
        find_map_mut(obj, name)
    }

    /// Write MatchSet entries to routing_map using batch update (single syscall).
    ///
    /// Falls back to individual updates if the kernel doesn't support batch operations.
    pub fn write_routing_rules(&mut self, match_sets: &[MatchSet]) -> Result<()> {
        use std::ffi::c_void;
        use std::os::unix::io::AsRawFd;

        info!(
            count = match_sets.len(),
            "Writing routing rules to routing_map"
        );
        let mut map = self.get_map_mut("routing_map")?;
        let fd = map.as_fd().as_raw_fd();

        // Batch update active rules via libbpf-sys bpf_map_update_batch
        if !match_sets.is_empty() {
            let num = match_sets.len() as u32;
            let mut count = num;
            let keys: Vec<u32> = (0..num).collect();
            let values: Vec<MatchSet> = match_sets.to_vec();

            let ret = unsafe {
                libbpf_sys::bpf_map_update_batch(
                    fd,
                    keys.as_ptr() as *const c_void,
                    values.as_ptr() as *const c_void,
                    &mut count as *mut u32,
                    std::ptr::null(), // opts = NULL
                )
            };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                warn!(
                    "Batch update failed ({}), falling back to individual updates",
                    err
                );
                // Fall back to individual updates
                for (i, ms) in match_sets.iter().enumerate() {
                    let key = (i as u32).to_ne_bytes();
                    map.update(&key, bytemuck::bytes_of(ms), MapFlags::empty())
                        .with_context(|| format!("Failed to write match_set at index {}", i))?;
                }
            } else if count != num {
                warn!("Batch update only wrote {} of {} entries", count, num);
            }
        }

        // Zero-fill unused entries (individually — they're few and rarely change)
        let empty = MatchSet::zeroed();
        for i in match_sets.len()..ROUTING_MAP_MAX as usize {
            let key = (i as u32).to_ne_bytes();
            let _ = map.update(&key, bytemuck::bytes_of(&empty), MapFlags::empty())?;
        }

        // Update routing_meta_map with active rule count
        drop(map);
        let mut meta_map = self.get_map_mut("routing_meta_map")?;
        let meta_key = 0u32.to_ne_bytes();
        let active_len = match_sets.len() as u32;
        meta_map.update(&meta_key, &active_len.to_ne_bytes(), MapFlags::empty())?;
        info!(
            "Wrote {} match sets (active_len={})",
            match_sets.len(),
            active_len
        );
        Ok(())
    }

    /// Write CIDR entries to lpm_array_map using batch update.
    pub fn write_cidr_table(&mut self, entries: &[(u32, CidrEntry)]) -> Result<()> {
        use std::ffi::c_void;
        use std::os::unix::io::AsRawFd;

        if entries.is_empty() {
            return Ok(());
        }

        let mut map = self.get_map_mut("lpm_array_map")?;
        let fd = map.as_fd().as_raw_fd();
        let num = entries.len() as u32;

        let mut count = num;
        let keys: Vec<u32> = entries.iter().map(|(k, _)| *k).collect();
        let values: Vec<CidrEntry> = entries.iter().map(|(_, v)| *v).collect();

        let ret = unsafe {
            libbpf_sys::bpf_map_update_batch(
                fd,
                keys.as_ptr() as *const c_void,
                values.as_ptr() as *const c_void,
                &mut count as *mut u32,
                std::ptr::null(),
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            warn!(
                "CIDR batch update failed ({}), falling back to individual",
                err
            );
            for (index, entry) in entries {
                let key = bytemuck::bytes_of(index);
                let val = bytemuck::bytes_of(entry);
                map.update(key, val, MapFlags::empty())
                    .with_context(|| format!("CIDR entry at index {}", index))?;
            }
        }
        info!("Wrote {} CIDR entries", entries.len());
        Ok(())
    }

    /// Read conntrack entry from conn_state_map.
    pub fn read_conntrack(&mut self, key: &TuplesKey) -> Result<Option<ConnState>> {
        let mut map = self.get_map_mut("conn_state_map")?;
        let key_bytes = bytemuck::bytes_of(key);
        match map.lookup(key_bytes, MapFlags::empty()) {
            Ok(Some(val)) => Ok(Some(bytemuck::pod_read_unaligned(&val))),
            Ok(None) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("conn_state_map lookup: {}", e)),
        }
    }

    /// Delete conntrack entry from conn_state_map.
    pub fn delete_conntrack(&mut self, key: &TuplesKey) -> Result<()> {
        let mut map = self.get_map_mut("conn_state_map")?;
        let _ = map.delete(bytemuck::bytes_of(key));
        Ok(())
    }

    /// Read stats from bpf_stats_map.
    pub fn read_stats(&mut self) -> Result<[u64; STATS_MAP_SIZE as usize]> {
        let mut map = self.get_map_mut("bpf_stats_map")?;
        let mut stats = [0u64; STATS_MAP_SIZE as usize];
        for i in 0..STATS_MAP_SIZE {
            let key = i.to_ne_bytes();
            if let Ok(Some(val_bytes)) = map.lookup(&key, MapFlags::empty()) {
                if val_bytes.len() >= 8 {
                    stats[i as usize] = u64::from_ne_bytes(val_bytes[..8].try_into().unwrap());
                }
            }
        }
        Ok(stats)
    }

    /// Write excluded comm hashes to cookie_pid_map.
    pub fn write_excluded_comm(&mut self, comm_hashes: &[u32]) -> Result<()> {
        info!(count = comm_hashes.len(), "Writing excluded comm hashes");
        let mut map = self.get_map_mut("cookie_pid_map")?;
        for hash in comm_hashes {
            let key = (*hash as u64).to_ne_bytes();
            let val = ProcInfo::zeroed();
            map.update(&key, bytemuck::bytes_of(&val), MapFlags::empty())
                .with_context(|| format!("insert comm hash {}", hash))?;
        }
        Ok(())
    }

    /// Write excluded PIDs to cookie_pid_map.
    pub fn write_excluded_pids(&mut self, pids: &[u32]) -> Result<()> {
        info!(count = pids.len(), "Writing excluded PIDs");
        let mut map = self.get_map_mut("cookie_pid_map")?;
        for pid in pids {
            let key = (*pid as u64).to_ne_bytes();
            let val = ProcInfo {
                last_seen_ns: 0,
                pid: *pid,
                pname: [0u8; 16],
                _tail_pad: [0u8; 4],
            };
            map.update(&key, bytemuck::bytes_of(&val), MapFlags::empty())
                .with_context(|| format!("insert PID {}", pid))?;
        }
        Ok(())
    }

    // ============================================================================
    // Status Queries
    // ============================================================================

    /// eBPF 程序是否已加载
    pub fn is_loaded(&self) -> bool {
        self.obj.is_some()
    }

    /// 是否有任何 TC 程序已 attach
    pub fn is_attached(&self) -> bool {
        !self.tc_hooks.is_empty()
    }

    /// 默认接口名（兼容旧代码）
    pub fn iface(&self) -> &str {
        &self.iface
    }

    /// TC hook 总数
    pub fn tc_link_count(&self) -> usize {
        self.tc_hooks.len()
    }

    /// cgroup link 总数
    pub fn cgroup_link_count(&self) -> usize {
        self.cgroup_links.len()
    }

    /// 所有 link 总数（TC + cgroup）
    pub fn link_count(&self) -> usize {
        self.tc_hooks.len() + self.cgroup_links.len()
    }

    // ============================================================================
    // Ringbuf Consumer
    // ============================================================================

    /// Get the file descriptor of the event_ringbuf map for polling.
    pub fn event_ringbuf_fd(&mut self) -> Result<i32> {
        use std::os::fd::AsRawFd;
        let map = self.get_map_mut("event_ringbuf")?;
        let fd = map.as_fd();
        Ok(fd.as_raw_fd())
    }

    /// Start the ringbuf consumer in a background thread.
    ///
    /// Uses the libbpf C API directly so the ringbuf lifecycle is independent of
    /// Rust borrows. Returns a (JoinHandle, Arc<AtomicBool>) pair; set the bool to
    /// false to stop the thread gracefully.
    pub fn spawn_ringbuf_consumer(map_fd: i32) -> (std::thread::JoinHandle<()>, Arc<AtomicBool>) {
        use std::ffi::c_void;
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        // C callback for ringbuf samples.
        // Signature: int callback(void *ctx, void *data, size_t size)
        extern "C" fn event_callback(_ctx: *mut c_void, data: *mut c_void, size: u64) -> i32 {
            if (size as usize) < std::mem::size_of::<Daeevent>() {
                warn!(
                    "Ringbuf event too small: got {} bytes, expected {}",
                    size,
                    std::mem::size_of::<Daeevent>()
                );
                return 0;
            }
            let event = unsafe { &*(data as *const Daeevent) };

            let (_event_type, sip, dip) = if event.sip[1..4].iter().all(|&x| x == 0) {
                // IPv4: eBPF stores __be32, so convert from big-endian.
                (
                    4u8,
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(event.sip[0]))),
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(event.dip[0]))),
                )
            } else {
                // IPv6
                (
                    6u8,
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(bytemuck::cast::<
                        [u32; 4],
                        [u8; 16],
                    >(event.sip))),
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(bytemuck::cast::<
                        [u32; 4],
                        [u8; 16],
                    >(event.dip))),
                )
            };
            let sport = event.sport;
            let dport = event.dport;
            let l4proto = if event.l4proto == 1 { "tcp" } else { "udp" };
            let pname = std::str::from_utf8(&event.pname)
                .unwrap_or("<invalid>")
                .trim_end_matches('\0');
            let _ = (sip, sport, dip, dport, l4proto, pname);

            match event.type_ {
                0 => {
                    // DAE_EVENT_BLOCKED
                    info!(
                        "BLOCKED: {} {}:{} -> {}:{} (pid={}, pname={})",
                        l4proto, sip, sport, dip, dport, event.pid, pname,
                    );
                }
                1 => debug!("UDP conn_state overflow"),
                2 => debug!("TCP conn_state overflow"),
                other => warn!("Unknown ringbuf event type: {}", other),
            }
            0
        }

        let handle = std::thread::spawn(move || {
            // Create ringbuf manager using libbpf-sys C API.
            let ringbuf = unsafe {
                libbpf_sys::ring_buffer__new(
                    map_fd,
                    Some(event_callback),
                    std::ptr::null_mut(), // ctx
                    std::ptr::null_mut(), // opts
                )
            };

            if ringbuf.is_null() {
                error!("Failed to create ringbuf");
                return;
            }

            info!("Ringbuf consumer started");

            // Poll for events with 100ms timeout. Check running flag between polls.
            while running_clone.load(std::sync::atomic::Ordering::Relaxed) {
                let ret = unsafe { libbpf_sys::ring_buffer__poll(ringbuf, 100) };
                if ret < 0 {
                    let err = std::io::Error::last_os_error();
                    warn!("Ringbuf poll error: {}", err);
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }

            // Clean up the ringbuf manager.
            unsafe { libbpf_sys::ring_buffer__free(ringbuf) };
            info!("Ringbuf consumer stopped");
        });

        (handle, running)
    }

    // ============================================================================
    // Domain Routing Map Operations
    // ============================================================================

    /// Write IP → domain bitmap entries to domain_routing_map.
    ///
    /// Each entry maps an IPv6 address (IPv4 mapped as ::ffff:x.x.x.x) to a bitmap
    /// where each bit corresponds to a domain set rule in routing_map.
    pub fn write_domain_routing_map(
        &mut self,
        entries: &[([u8; 16], [u32; MAX_MATCH_SET_LEN / 32])],
    ) -> Result<()> {
        info!(count = entries.len(), "Writing domain routing entries");
        let mut map = self.get_map_mut("domain_routing_map")?;

        for (ip, bitmap) in entries {
            map.update(
                bytemuck::bytes_of(ip),
                bytemuck::bytes_of(bitmap),
                MapFlags::empty(),
            )
            .with_context(|| "Failed to write domain routing entry")?;
        }
        Ok(())
    }

    /// Delete IP entries from domain_routing_map.
    pub fn delete_domain_routing_entries(&mut self, ips: &[[u8; 16]]) -> Result<()> {
        let mut map = self.get_map_mut("domain_routing_map")?;
        for ip in ips {
            let _ = map.delete(bytemuck::bytes_of(ip));
        }
        Ok(())
    }

    // ============================================================================
    // Outbound Connectivity Map Operations
    // ============================================================================

    /// Update outbound_connectivity_map for a specific outbound.
    ///
    /// Key format: outbound_id * 6 + domain * 2 + ipversion
    /// - domain: 0=TCP, 1=DNS UDP, 2=data UDP
    /// - ipversion: 0=IPv4, 1=IPv6
    pub fn update_outbound_connectivity(
        &mut self,
        outbound_id: u8,
        l4proto: u8,
        is_dns: bool,
        is_ipv6: bool,
        alive: bool,
    ) -> Result<()> {
        let domain_idx = if l4proto == 1 {
            // TCP
            0
        } else if is_dns {
            1
        } else {
            2
        };
        let ip_idx = if is_ipv6 { 1 } else { 0 };
        let key = (outbound_id as u32) * 6 + (domain_idx as u32) * 2 + (ip_idx as u32);

        let mut map = self.get_map_mut("outbound_connectivity_map")?;
        let value = if alive { 1u32 } else { 0u32 };
        map.update(&key.to_ne_bytes(), &value.to_ne_bytes(), MapFlags::empty())?;
        Ok(())
    }

    // ============================================================================
    // Janitor: Expired conn_state_map Cleanup
    // ============================================================================

    /// Scan and delete expired entries from conn_state_map.
    ///
    /// Iterates all entries via raw BPF syscall, checks `last_seen_ns`
    /// against timeout thresholds, and deletes expired ones.
    /// Returns the number of entries deleted.
    pub fn janitor_scan_conn_state(&mut self, now_ns: u64) -> Result<usize> {
        use std::os::fd::AsRawFd;

        // Timeout constants from tproxy.c (in nanoseconds)
        const TCP_CLOSING_TIMEOUT_NS: u64 = 10_000_000_000; // 10s
        const DEFAULT_TIMEOUT_NS: u64 = 120_000_000_000; // 120s (UDP + TCP established)

        // TCP CLOSING state (include/uapi/linux/tcp.h)
        const TCP_CLOSING: u8 = 7;

        let map = self.get_map_mut("conn_state_map")?;
        let map_fd = map.as_fd().as_raw_fd();

        let mut expired_keys: Vec<Vec<u8>> = Vec::new();
        let mut prev_key: Vec<u8> = Vec::new();

        loop {
            let next_key = {
                let mut buf = vec![0u8; 45]; // tuples_key size: 16+16+2+2+1 = 37, rounded up
                let ret = unsafe {
                    libc::syscall(
                        libc::SYS_bpf,
                        3i64, // BPF_MAP_GET_NEXT_KEY
                        &(map_fd as u32),
                        if prev_key.is_empty() {
                            std::ptr::null::<u8>()
                        } else {
                            prev_key.as_ptr()
                        },
                        buf.as_mut_ptr(),
                    )
                };
                if ret < 0 {
                    break;
                }
                buf
            };

            // Lookup value
            let mut val = vec![0u8; 64];
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_bpf,
                    4i64, // BPF_MAP_LOOKUP_ELEM
                    &(map_fd as u32),
                    next_key.as_ptr(),
                    val.as_mut_ptr(),
                )
            };
            if ret < 0 {
                prev_key = next_key;
                continue;
            }

            // conn_state layout: is_wan_ingress(1) + state(1) + padding(6) + last_seen_ns(8)
            if val.len() >= 16 {
                let last_seen_ns = u64::from_ne_bytes(val[8..16].try_into().unwrap_or([0; 8]));
                let state = val[1];

                let timeout_ns = if state == TCP_CLOSING {
                    TCP_CLOSING_TIMEOUT_NS
                } else {
                    DEFAULT_TIMEOUT_NS
                };

                if now_ns.saturating_sub(last_seen_ns) > timeout_ns {
                    expired_keys.push(next_key.clone());
                }
            }

            prev_key = next_key;
        }

        // Delete expired entries
        let count = expired_keys.len();
        for key in &expired_keys {
            unsafe {
                libc::syscall(
                    libc::SYS_bpf,
                    5i64, // BPF_MAP_DELETE_ELEM
                    &(map_fd as u32),
                    key.as_ptr(),
                    std::ptr::null::<u8>(),
                );
            }
        }

        if count > 0 {
            info!("Janitor scan: deleted {} expired conn_state entries", count);
        }

        Ok(count)
    }
}

impl Drop for EbpfManager {
    fn drop(&mut self) {
        if self.obj.is_some() || !self.tc_hooks.is_empty() || !self.cgroup_links.is_empty() {
            warn!("EbpfManager dropped without explicit unload()");
            let _ = self.unload();
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tuples_key_size() {
        assert_eq!(std::mem::size_of::<TuplesKey>(), 40);
    }
    #[test]
    fn test_conn_state_size() {
        assert_eq!(std::mem::size_of::<ConnState>(), 56);
    }
    #[test]
    fn test_routing_meta_size() {
        assert_eq!(std::mem::size_of::<RoutingMeta>(), 8);
    }
    #[test]
    fn test_cidr_entry_size() {
        assert_eq!(std::mem::size_of::<CidrEntry>(), 24);
    }
    #[test]
    fn test_daeparam_size() {
        assert_eq!(std::mem::size_of::<Daeparam>(), 32);
    }
    #[test]
    fn test_match_set_size() {
        assert_eq!(std::mem::size_of::<MatchSet>(), 24);
    }

    #[test]
    fn test_tuples_key_reverse() {
        let key = TuplesKey::from_ipv4(&[10, 0, 0, 1], &[8, 8, 8, 8], 12345, 443, 6);
        let rev = key.reverse();
        assert_eq!(rev.sip, key.dip);
        assert_eq!(rev.sport, key.dport);
    }

    #[test]
    fn test_hash_comm() {
        assert_eq!(hash_comm(""), 5381);
        assert_eq!(hash_comm("a"), 5381 * 33 + 97);
    }
}
