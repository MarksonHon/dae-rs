//! eBPF program lifecycle manager
//!
//! This module manages the full lifecycle of eBPF programs in userspace,
//! including loading from bytecode, TC attachment/detachment, and map I/O.
//!
//! Uses libbpf-rs (replacing aya-rs) to load and manage eBPF programs
//! compiled from dae's C eBPF source (tproxy.c).

use anyhow::{Context, Result};
use bytemuck::Zeroable;
use libbpf_rs::{MapCore, MapFlags, ProgramType};
use libbpf_rs::{ObjectBuilder, Object, TcHook, TC_INGRESS, TC_EGRESS};
use std::os::unix::io::AsFd;
use std::path::Path;
use std::ffi::OsStr;
use tracing::{info, warn};

// ============================================================================
// Compat: RuleEntry (用于 compile_rules 转换层)
// ============================================================================

/// Routing rule entry compiled from daefile by userspace.
/// This is a compatibility shim; rules are stored as MatchSet in tproxy.c's routing_map.
///
/// Layout: dip(16) + dip_prefix_len(1) + pad1(1) + dport(2) + l4proto(1) + action(1) + pad(12) = 34
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct RuleEntry {
    pub dip: [u8; 16],
    pub dip_prefix_len: u8,
    /// Explicit padding to align dport: u16 to 2-byte boundary
    pub _pad1: u8,
    pub dport: u16,
    pub l4proto: u8,
    pub action: u8,
    pub _pad: [u8; 12],
}

impl Default for RuleEntry {
    fn default() -> Self {
        Self {
            dip: [0u8; 16],
            dip_prefix_len: 0,
            _pad1: 0,
            dport: 0,
            l4proto: 0,
            action: 0,
            _pad: [0u8; 12],
        }
    }
}

impl From<&RuleEntry> for MatchSet {
    fn from(rule: &RuleEntry) -> Self {
        let mut ms = MatchSet::zeroed();
        ms.outbound = rule.action;
        ms.must = 0;
        ms.mark = 0;

        if rule.dport != 0 {
            ms.r#type = match_type::PORT;
            ms.value = MatchSetValue {
                port_range: PortRange {
                    port_start: u16::from_be(rule.dport),
                    port_end: u16::from_be(rule.dport),
                },
            };
        } else if rule.l4proto != 0 {
            ms.r#type = match_type::L4_PROTO;
            ms.value = MatchSetValue {
                l4proto_type: rule.l4proto,
            };
        } else {
            ms.r#type = match_type::IP_SET;
            ms.value = MatchSetValue { index: 0 };
        }
        ms
    }
}

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
            tproxy_port: 15080,
            control_plane_pid: 0,
            dae0_ifindex: 0,
            dae_netns_id: 0,
            dae0peer_mac: [0u8; 6],
            padding_after_mac: [0u8; 2],
            use_redirect_peer: 0,
            has_bpf_get_current_task: 0,
            padding2: 0,
            dae_socket_mark: 0,
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
    pub fn from_ipv4(src_ip: &[u8; 4], dst_ip: &[u8; 4], src_port: u16, dst_port: u16, l4proto: u8) -> Self {
        let mut sip = [0u8; 16];
        let mut dip = [0u8; 16];
        sip[10] = 0xff; sip[11] = 0xff;
        sip[12..16].copy_from_slice(src_ip);
        dip[10] = 0xff; dip[11] = 0xff;
        dip[12..16].copy_from_slice(dst_ip);
        Self { sip, dip, sport: src_port, dport: dst_port, l4proto, _pad: [0u8; 3] }
    }
    pub fn from_ipv6(src_ip: &[u8; 16], dst_ip: &[u8; 16], src_port: u16, dst_port: u16, l4proto: u8) -> Self {
        Self { sip: *src_ip, dip: *dst_ip, sport: src_port, dport: dst_port, l4proto, _pad: [0u8; 3] }
    }
    pub fn reverse(&self) -> Self {
        Self { sip: self.dip, dip: self.sip, sport: self.dport, dport: self.sport, l4proto: self.l4proto, _pad: [0u8; 3] }
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
    pub _pad1: [u8; 6],        // pad to align u64
    pub last_seen_ns: u64,
    pub meta: RoutingMeta,
    pub mac: [u8; 6],
    pub _pad2: [u8; 2],        // pad to align pname
    pub pname: [u8; 16],
    pub pid: u32,
    pub _tail_pad: [u8; 4],    // pad total to 56 (multiple of max alignment 8)
}

impl ConnState {
    pub fn is_wan_ingress_direction(&self) -> bool { self.is_wan_ingress_direction_raw != 0 }
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
    pub const DOMAIN_SET: u8 = 0;   pub const IP_SET: u8 = 1;
    pub const SOURCE_IP_SET: u8 = 2; pub const PORT: u8 = 3;
    pub const SOURCE_PORT: u8 = 4;   pub const L4_PROTO: u8 = 5;
    pub const IP_VERSION: u8 = 6;    pub const MAC: u8 = 7;
    pub const PROCESS_NAME: u8 = 8;  pub const DSCP: u8 = 9;
    pub const FALLBACK: u8 = 10;     pub const MUST_RULES: u8 = 11;
    pub const UPSTREAM: u8 = 12;     pub const QTYPE: u8 = 13;
}

pub mod outbound {
    pub const DIRECT: u8 = 0x0;      pub const BLOCK: u8 = 0x1;
    pub const MUST_RULES: u8 = 0xFC; pub const CONTROL_PLANE_ROUTING: u8 = 0xFD;
    pub const LOGICAL_OR: u8 = 0xFE; pub const LOGICAL_AND: u8 = 0xFF;
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
        if c == 0 { break; }
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
    obj.maps_mut()
        .find(|m| m.name() == name_os)
        .ok_or_else(|| EbpfError::MapNotFound { name: name.to_string() }.into())
}

/// Find a map by name in the loaded object (immutable).
fn find_map<'a>(obj: &'a Object, name: &str) -> Result<libbpf_rs::Map<'a>> {
    let name_os = OsStr::new(name);
    obj.maps()
        .find(|m| m.name() == name_os)
        .ok_or_else(|| EbpfError::MapNotFound { name: name.to_string() }.into())
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

        let obj = open_obj.load().context("Failed to load eBPF object into kernel")?;
        info!("eBPF program loaded successfully via libbpf-rs");
        self.obj = Some(obj);
        Ok(())
    }

    /// Load eBPF from memory buffer.
    pub fn load_from_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        if self.obj.is_some() {
            return Err(EbpfError::AlreadyLoaded.into());
        }

        info!(len = bytes.len(), "Loading eBPF from byte slice via libbpf-rs");

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

        let obj = open_obj.load().context("Failed to load eBPF object from memory into kernel")?;
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
        let ifindex = if_nametoindex(ifname)
            .map_err(|e| EbpfError::TcAttachError {
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
            hook.create()
                .map_err(|e| EbpfError::TcAttachError {
                    iface: ifname.into(),
                    detail: format!("create({}): {}", prog_name, e),
                })?;

            // Attach the program
            let attached = hook.attach()
                .map_err(|e| EbpfError::TcAttachError {
                    iface: ifname.into(),
                    detail: format!("attach({}): {}", prog_name, e),
                })?;

            self.tc_hooks.push(TcAttachInfo {
                hook: attached,
                iface: ifname.into(),
                prog_name: prog_name.to_string(),
            });
            info!("TC program '{}' attached to {} (ifindex={})", prog_name, ifname, ifindex);
        }

        info!("TC programs attached to {} (total hooks: {})", ifname, self.tc_hooks.len());
        Ok(())
    }

    // ========================================================================
    // 按接口分组 TC attach
    // ========================================================================

    /// WAN 接口：挂载 wan_egress + wan_ingress（各 L2/L3 两版本）
    ///
    /// 程序列表：
    /// - tproxy_wan_egress_l2 (EGRESS), tproxy_wan_egress_l3 (EGRESS)
    /// - tproxy_wan_ingress_l2 (INGRESS), tproxy_wan_ingress_l3 (INGRESS)
    pub fn attach_wan(&mut self, ifname: &str) -> Result<()> {
        info!("Attaching WAN TC programs to {}", ifname);
        self.attach_tc(ifname, &[
            ("tproxy_wan_egress_l2", TC_EGRESS),
            ("tproxy_wan_egress_l3", TC_EGRESS),
            ("tproxy_wan_ingress_l2", TC_INGRESS),
            ("tproxy_wan_ingress_l3", TC_INGRESS),
        ])
    }

    /// LAN 接口：挂载 lan_ingress + lan_egress（各 L2/L3 两版本）
    ///
    /// 程序列表：
    /// - tproxy_lan_ingress_l2 (INGRESS), tproxy_lan_ingress_l3 (INGRESS)
    /// - tproxy_lan_egress_l2 (EGRESS), tproxy_lan_egress_l3 (EGRESS)
    pub fn attach_lan(&mut self, ifname: &str) -> Result<()> {
        info!("Attaching LAN TC programs to {}", ifname);
        self.attach_tc(ifname, &[
            ("tproxy_lan_ingress_l2", TC_INGRESS),
            ("tproxy_lan_ingress_l3", TC_INGRESS),
            ("tproxy_lan_egress_l2", TC_EGRESS),
            ("tproxy_lan_egress_l3", TC_EGRESS),
        ])
    }

    /// dae0（宿主 NS）：挂载 tproxy_dae0_ingress
    pub fn attach_dae0(&mut self, ifname: &str) -> Result<()> {
        info!("Attaching dae0 TC program to {}", ifname);
        self.attach_tc(ifname, &[
            ("tproxy_dae0_ingress", TC_INGRESS),
        ])
    }

    /// dae0peer（代理 NS）：挂载 tproxy_dae0peer_ingress
    pub fn attach_dae0peer(&mut self, ifname: &str) -> Result<()> {
        info!("Attaching dae0peer TC program to {}", ifname);
        self.attach_tc(ifname, &[
            ("tproxy_dae0peer_ingress", TC_INGRESS),
        ])
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

        info!("cgroup programs attached ({} links)", self.cgroup_links.len());
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
                    warn!("Failed to detach TC hook '{}' on {}: {}",
                        info.prog_name, info.iface, e);
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

    fn get_map_mut(&mut self, name: &str) -> Result<libbpf_rs::MapMut<'_>> {
        let obj = self.obj.as_mut().ok_or(EbpfError::NotLoaded)?;
        find_map_mut(obj, name)
    }

    /// Write rules (RuleEntry → MatchSet conversion) to routing_map.
    pub fn write_rules(&mut self, rules: &[RuleEntry]) -> Result<()> {
        let match_sets: Vec<MatchSet> = rules.iter().map(MatchSet::from).collect();
        self.write_routing_rules(&match_sets)
    }

    /// Write MatchSet entries to routing_map.
    pub fn write_routing_rules(&mut self, match_sets: &[MatchSet]) -> Result<()> {
        info!(count = match_sets.len(), "Writing routing rules to routing_map");
        let mut map = self.get_map_mut("routing_map")?;

        for (i, ms) in match_sets.iter().enumerate() {
            let key = (i as u32).to_ne_bytes();
            map.update(&key, bytemuck::bytes_of(ms), MapFlags::empty())
                .with_context(|| format!("Failed to write match_set at index {}", i))?;
        }

        let empty = MatchSet::zeroed();
        for i in match_sets.len()..ROUTING_MAP_MAX as usize {
            let key = (i as u32).to_ne_bytes();
            let _ = map.update(&key, bytemuck::bytes_of(&empty), MapFlags::empty())?;
        }

        let mut meta_map = self.get_map_mut("routing_meta_map")?;
        let meta_key = 0u32.to_ne_bytes();
        let active_len = match_sets.len() as u32;
        meta_map.update(&meta_key, &active_len.to_ne_bytes(), MapFlags::empty())?;
        info!("Wrote {} match sets, active_len={}", match_sets.len(), active_len);
        Ok(())
    }

    /// Write CIDR entries to lpm_array_map.
    pub fn write_cidr_table(&mut self, entries: &[(u32, CidrEntry)]) -> Result<()> {
        info!(count = entries.len(), "Writing CIDR entries");
        let mut map = self.get_map_mut("lpm_array_map")?;
        for (index, entry) in entries {
            let key = bytemuck::bytes_of(index);
            let val = bytemuck::bytes_of(entry);
            map.update(key, val, MapFlags::empty()).with_context(|| format!("CIDR entry at index {}", index))?;
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
            let val = ProcInfo { last_seen_ns: 0, pid: *pid, pname: [0u8; 16], _tail_pad: [0u8; 4] };
            map.update(&key, bytemuck::bytes_of(&val), MapFlags::empty())
                .with_context(|| format!("insert PID {}", pid))?;
        }
        Ok(())
    }

    // ============================================================================
    // Status Queries
    // ============================================================================

    /// eBPF 程序是否已加载
    pub fn is_loaded(&self) -> bool { self.obj.is_some() }

    /// 是否有任何 TC 程序已 attach
    pub fn is_attached(&self) -> bool { !self.tc_hooks.is_empty() }

    /// 默认接口名（兼容旧代码）
    pub fn iface(&self) -> &str { &self.iface }

    /// TC hook 总数
    pub fn tc_link_count(&self) -> usize { self.tc_hooks.len() }

    /// cgroup link 总数
    pub fn cgroup_link_count(&self) -> usize { self.cgroup_links.len() }

    /// 所有 link 总数（TC + cgroup）
    pub fn link_count(&self) -> usize { self.tc_hooks.len() + self.cgroup_links.len() }
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
    fn test_tuples_key_size() { assert_eq!(std::mem::size_of::<TuplesKey>(), 40); }
    #[test]
    fn test_conn_state_size() { assert_eq!(std::mem::size_of::<ConnState>(), 56); }
    #[test]
    fn test_routing_meta_size() { assert_eq!(std::mem::size_of::<RoutingMeta>(), 8); }
    #[test]
    fn test_cidr_entry_size() { assert_eq!(std::mem::size_of::<CidrEntry>(), 24); }
    #[test]
    fn test_daeparam_size() { assert_eq!(std::mem::size_of::<Daeparam>(), 32); }
    #[test]
    fn test_rule_entry_size() { assert_eq!(std::mem::size_of::<RuleEntry>(), 34); }
    #[test]
    fn test_match_set_size() { assert_eq!(std::mem::size_of::<MatchSet>(), 24); }

    #[test]
    fn test_tuples_key_reverse() {
        let key = TuplesKey::from_ipv4(&[10,0,0,1], &[8,8,8,8], 12345, 443, 6);
        let rev = key.reverse();
        assert_eq!(rev.sip, key.dip);
        assert_eq!(rev.sport, key.dport);
    }

    #[test]
    fn test_hash_comm() {
        assert_eq!(hash_comm(""), 5381);
        assert_eq!(hash_comm("a"), 5381 * 33 + 97);
    }

    #[test]
    fn test_rule_entry_to_match_set_port() {
        let rule = RuleEntry { dip: [0u8;16], dip_prefix_len:0, _pad1:0, dport:80u16.to_be(), l4proto:0, action:0, _pad:[0u8;12] };
        let ms = MatchSet::from(&rule);
        assert_eq!(ms.r#type, match_type::PORT);
        unsafe { assert_eq!(ms.value.port_range.port_start, 80); }
    }

    #[test]
    fn test_rule_entry_to_match_set_l4proto() {
        let rule = RuleEntry { dip: [0u8;16], dip_prefix_len:0, _pad1:0, dport:0, l4proto:6, action:1, _pad:[0u8;12] };
        let ms = MatchSet::from(&rule);
        assert_eq!(ms.r#type, match_type::L4_PROTO);
        unsafe { assert_eq!(ms.value.l4proto_type, 6); }
    }
}
