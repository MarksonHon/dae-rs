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
use std::ffi::{CString, OsStr};
use std::os::unix::io::AsFd;
use std::path::Path;
use std::collections::HashSet;
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, LazyLock};
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
/// Max entries per inner LPM trie (must match tproxy.c MAX_LPM_SIZE)
pub const MAX_LPM_SIZE: u32 = 2_048_000;

/// Number of routing epoch slots for double-buffering (must match tproxy.c ROUTING_EPOCH_SLOT_NUM).
pub const ROUTING_EPOCH_SLOT_NUM: u32 = 2;
/// Encoded value for "unknown" epoch slot (not slot 0 or 1).
pub const ROUTING_EPOCH_SLOT_UNKNOWN: u8 = 0;

/// eBPF 文件系统 pinning 路径
pub const BPFFS_PATH: &str = "/sys/fs/bpf/dae";

// ---- Map capacity constants (must match tproxy.c) ----
/// conn_state_map max_entries (MAX_CONN_STATE_NUM = 65536 * 4)
pub const CONN_STATE_MAX_ENTRIES: u32 = 262144;
/// redirect_track max_entries
pub const REDIRECT_TRACK_MAX_ENTRIES: u32 = 65536;
/// cookie_pid_map max_entries
pub const COOKIE_PID_MAP_MAX_ENTRIES: u32 = 65536;

// ---- Timeout constants (nanoseconds) ----
/// redirect_track TTL: 5 minutes
pub const REDIRECT_TRACK_TIMEOUT_NS: u64 = 300_000_000_000;
/// cookie_pid_map TTL: 5 minutes
pub const COOKIE_PID_MAP_TIMEOUT_NS: u64 = 300_000_000_000;

// ---- Pressure detection thresholds ----
/// conn_state_map usage above this triggers pressure mode
pub const PRESSURE_ENTER_USAGE: f64 = 0.70;
/// conn_state_map usage below this exits pressure mode
pub const PRESSURE_EXIT_USAGE: f64 = 0.50;
/// Number of consecutive rounds below exit threshold to leave pressure mode
pub const PRESSURE_EXIT_ROUNDS: u32 = 3;

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
    /// Datapath generation counter. Initial value is 0; incremented on datapath
    /// reload (e.g. configuration change). Must match `struct dae_param` in tproxy.c.
    pub datapath_generation: u16,
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
            datapath_generation: 0,
            // 原版 dae 使用 0x100 作为内部 socket 标记
            // 用于 bpf_sock_is_dae_socket() 和 pid_is_control_plane() 中的 mark 检查
            dae_socket_mark: shared::DAE_SOCKET_MARK,
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

// ---- tproxy.c: struct redirect_tuple ----
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, bytemuck::Pod, bytemuck::Zeroable)]
pub struct RedirectTuple {
    pub sip: [u8; 16],
    pub dip: [u8; 16],
}

// ---- tproxy.c: struct redirect_entry ----
/// Size: 32 bytes. The original C struct has __u8 padding[3] followed
/// by __u64 last_seen_ns; the C compiler adds 4 bytes of implicit alignment
/// padding. We expand _pad to 7 bytes so bytemuck::Pod is satisfied.
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct RedirectEntry {
    pub ifindex: u32,
    pub smac: [u8; 6],
    pub dmac: [u8; 6],
    pub from_wan: u8,
    /// Combined: explicit C padding (3) + alignment padding to u64 (4)
    pub _pad: [u8; 7],
    pub last_seen_ns: u64,
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
/// Size: 64 bytes (aligned to 8). Must match C struct layout exactly.
/// Field layout:
/// - is_wan_ingress_direction: offset 0,  1 byte  (bool)
/// - state:                     offset 1,  1 byte  (u8)
/// - _pad1:                     offset 2,  6 bytes (pad to align u64)
/// - last_seen_ns:             offset 8,  8 bytes (u64)
/// - meta:                      offset 16, ? bytes (RoutingMeta)
/// - mac:                       ?        , 6 bytes
/// - _pad2:                     ?        , 2 bytes
/// - pname:                     ?        , 16 bytes
/// - pid:                       ?        , 4 bytes
/// - routing_epoch_slot:        ?        , 1 byte
/// - padding_after_pid:         ?        , 1 byte
/// - datapath_generation:       ?        , 2 bytes
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
    /// 0 is unknown; active routing slots 0 and 1 are encoded as 1 and 2.
    /// Must match `struct conn_state.routing_epoch_slot` in tproxy.c.
    pub routing_epoch_slot: u8,
    pub padding_after_pid: u8,
    /// Datapath generation counter from PARAM. Used to detect stale routing entries
    /// when the datapath is reloaded. Must match `struct conn_state.datapath_generation` in tproxy.c.
    pub datapath_generation: u16,
}

impl ConnState {
    pub fn is_wan_ingress_direction(&self) -> bool {
        self.is_wan_ingress_direction_raw != 0
    }
}

// ---- tproxy.c: struct routing_result ----
/// Size: 36 bytes (aligned to 4). Must match C struct layout exactly.
///
/// Field layout:
/// - mark:        offset 0,  4 bytes (u32)
/// - must:        offset 4,  1 byte  (u8)
/// - mac:         offset 5,  6 bytes (u8[6])
/// - outbound:    offset 11, 1 byte  (u8)
/// - pname:       offset 12, 16 bytes (u8[16])
/// - pid:         offset 28, 4 bytes (u32)
/// - dscp:        offset 32, 1 byte  (u8)
/// - routing_epoch_slot: offset 33, 1 byte (u8)
/// - datapath_generation: offset 34, 2 bytes (u16)
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct RoutingResult {
    pub mark: u32,
    pub must: u8,
    pub mac: [u8; 6],
    pub outbound: u8,
    pub pname: [u8; 16],
    pub pid: u32,
    pub dscp: u8,
    /// Active routing epoch slot. 0 = unknown; slots 0 and 1 encoded as 1 and 2.
    /// Must match `struct routing_result.routing_epoch_slot` in tproxy.c.
    pub routing_epoch_slot: u8,
    /// Datapath generation counter from PARAM. Used to detect stale routing entries
    /// when the datapath is reloaded. Must match `struct routing_result.datapath_generation` in tproxy.c.
    pub datapath_generation: u16,
}

// ---- tproxy.c: struct routing_epoch_ip ----
/// Key for domain_routing_map: (slot, addr) → routing bitmap cache.
/// Must match `struct routing_epoch_ip` in tproxy.c exactly.
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct RoutingEpochIp {
    /// Epoch slot (0 or 1)
    pub slot: u32,
    /// IPv6 address (IPv4 mapped as ::ffff:x.x.x.x), stored as __be32[4]
    pub addr: [u32; 4],
}

// ---- tproxy.c: struct routing_handoff_entry ----
/// Size: 48 bytes (aligned to 8).
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct RoutingHandoffEntry {
    pub last_seen_ns: u64,
    pub result: RoutingResult,
    pub _pad: [u8; 4],
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

/// 确保 bpffs 已挂载到 /sys/fs/bpf。
/// 如果未挂载则尝试挂载。
/// bpffs mount 相关的静态 CString（避免重复创建）
static BPFFS_SOURCE: LazyLock<CString> = LazyLock::new(|| CString::new("bpffs").unwrap());
static BPFFS_TARGET: LazyLock<CString> =
    LazyLock::new(|| CString::new("/sys/fs/bpf").unwrap());
static BPFFS_FSTYPE: LazyLock<CString> = LazyLock::new(|| CString::new("bpf").unwrap());

fn ensure_bpffs_mounted() -> std::io::Result<()> {
    let bpffs_path = std::path::Path::new("/sys/fs/bpf");
    if !bpffs_path.exists() {
        std::fs::create_dir_all(bpffs_path)?;
    }
    // 检查是否已挂载（精确匹配挂载点，避免误匹配 /sys/fs/bpf_extra 等路径）
    let mounts = std::fs::read_to_string("/proc/mounts")?;
    let already_mounted = mounts.lines().any(|line| {
        line.split_whitespace().nth(1) == Some("/sys/fs/bpf")
    });
    if already_mounted {
        return Ok(());
    }
    // 挂载 bpffs（使用缓存的 CString）
    let ret = unsafe {
        libc::mount(
            BPFFS_SOURCE.as_ptr(),
            BPFFS_TARGET.as_ptr(),
            BPFFS_FSTYPE.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

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

/// Compute the base index in routing_map/lpm_array_map for a given epoch slot.
///
/// Each epoch slot owns `MAX_MATCH_SET_LEN` entries in routing_map and
/// `MAX_MATCH_SET_LEN` entries in lpm_array_map.
///
/// Matches kdae's `routingEpochSlotBase()` function.
pub fn routing_epoch_slot_base(slot: u32) -> Result<u32> {
    if slot >= ROUTING_EPOCH_SLOT_NUM {
        return Err(anyhow::anyhow!(
            "invalid routing epoch slot {} (max {})",
            slot,
            ROUTING_EPOCH_SLOT_NUM
        ));
    }
    Ok(slot * MAX_MATCH_SET_LEN as u32)
}

/// Encode an epoch slot for wire use in routing_result and conn_state.
///
/// The C side encodes slot N as (N + 1), with 0 meaning "unknown".
/// Matches `routing_epoch_slot_encode()` in tproxy.c.
pub fn routing_epoch_slot_encode(slot: u32) -> u8 {
    if slot >= ROUTING_EPOCH_SLOT_NUM {
        ROUTING_EPOCH_SLOT_UNKNOWN
    } else {
        (slot + 1) as u8
    }
}

/// Decode a wire-encoded epoch slot back to the slot number.
///
/// Returns `(slot, true)` if valid, or `(0, false)` if unknown.
/// Matches `decodeBpfRoutingEpochSlot()` in kdae.
pub fn routing_epoch_slot_decode(encoded: u8) -> (u32, bool) {
    match encoded {
        1 => (0, true),
        2 => (1, true),
        _ => (0, false),
    }
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
    let release = release.trim();
    let parts: Vec<&str> = release.splitn(3, '.').collect();
    if parts.len() < 2 {
        return None;
    }
    let major: u32 = parts[0].parse().ok()?;
    // 只取数字部分解析 minor 版本（避免 "8-generic" 等后缀干扰）
    let minor_str: String = parts[1].chars().take_while(|c| c.is_ascii_digit()).collect();
    let minor: u32 = minor_str.parse().ok()?;
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
    /// eBPF map pinning 路径，如果设置则在 load 后自动 pin maps
    pin_path: Option<String>,
    /// Flip 位，用于 TC handle 翻转（热重载时切换 filter）
    flip: u32,
    /// conn_state_map 最大条目数（从 tproxy.c MAX_CONN_STATE_NUM 同步）
    conn_state_map_max_entries: u32,
    /// 跟踪已进行 clsact qdisc 清理的接口，避免重复删除
    /// （重复删除会销毁已挂载的 egress 程序）
    clsact_cleaned: HashSet<String>,
}

// Safety: EbpfManager is only ever accessed through `Arc<Mutex<EbpfManager>>`.
// The caller MUST hold the Mutex lock before calling any mutating method.
// Direct access to the underlying Object (e.g. via pinned_maps_exist or
// other static helpers) does not touch Object internals and is thread-safe.
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
            pin_path: None,
            flip: 0,
            conn_state_map_max_entries: CONN_STATE_MAX_ENTRIES,
            clsact_cleaned: HashSet::new(),
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
            pin_path: None,
            flip: 0,
            conn_state_map_max_entries: CONN_STATE_MAX_ENTRIES,
            clsact_cleaned: HashSet::new(),
        }
    }

    /// 获取当前 flip 位
    pub fn flip(&self) -> u32 {
        self.flip
    }

    /// 设置 flip 位（热重载时用于 TC handle 翻转）
    pub fn set_flip(&mut self, flip: u32) {
        self.flip = flip;
        info!("Flip set to {}", flip);
    }

    pub fn set_param(&mut self, param: &Daeparam) {
        self.param = Some(*param);
    }

    /// 设置 eBPF map pinning 路径。
    /// 设置后，调用 load() 或 load_from_bytes() 时会自动将 maps pin 到该路径。
    pub fn set_pin_path(&mut self, path: String) {
        self.pin_path = Some(path);
    }

    /// 设置 conn_state_map 的最大条目数。
    /// 必须在 load() 前调用才生效。
    pub fn set_conn_state_max_entries(&mut self, n: u32) {
        self.conn_state_map_max_entries = n;
        info!("conn_state_map max_entries set to {}", n);
    }

    /// 在 OpenObject 阶段调整 eBPF maps 的参数（load 前）。
    /// 包括：
    /// - fast_sock: 设置 max_entries=1 禁用 sockhash 路径
    /// - conn_state_map: 设置可配置的 max_entries
    fn adjust_maps_pre_load(&self, open_obj: &mut libbpf_rs::OpenObject) {
        // fast_sock: 设置 max_entries=1 以禁用 sockhash 路径
        if let Some(mut map) = open_obj
            .maps_mut()
            .find(|m| m.name().to_str().unwrap_or("") == "fast_sock")
        {
            if let Err(e) = map.set_max_entries(1) {
                warn!("Failed to set fast_sock max_entries=1: {}", e);
            } else {
                info!("fast_sock max_entries set to 1 (sockhash path disabled)");
            }
        } else {
            debug!("fast_sock map not found in eBPF object (may be removed)");
        }

        // conn_state_map: 使用可配置的 max_entries
        if let Some(mut map) = open_obj
            .maps_mut()
            .find(|m| m.name().to_str().unwrap_or("") == "conn_state_map")
        {
            if let Err(e) = map.set_max_entries(self.conn_state_map_max_entries) {
                warn!(
                    "Failed to set conn_state_map max_entries={}: {}",
                    self.conn_state_map_max_entries, e
                );
            } else {
                info!(
                    "conn_state_map max_entries set to {}",
                    self.conn_state_map_max_entries
                );
            }
        } else {
            warn!("conn_state_map not found in eBPF object");
        }
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

        // Adjust map parameters before loading
        self.adjust_maps_pre_load(&mut open_obj);

        // Write PARAM to .rodata BEFORE loading (read-only after load)
        self.update_param_pre_load(&mut open_obj)?;

        // Fix program types for non-standard TC section names before loading
        set_tc_prog_types(&mut open_obj);

        let obj = open_obj
            .load()
            .context("Failed to load eBPF object into kernel")?;
        info!("eBPF program loaded successfully via libbpf-rs");

        self.obj = Some(obj);

        // Auto-pin maps if pin_path is configured
        if let Some(ref bpffs_path) = self.pin_path.clone() {
            if let Err(e) = self.pin_maps(bpffs_path) {
                warn!("Failed to pin eBPF maps: {}", e);
            }
        }

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

        // Adjust map parameters before loading
        self.adjust_maps_pre_load(&mut open_obj);

        // Write PARAM to .rodata BEFORE loading — .rodata becomes read-only
        // after bpf_object__load(), so post-load writes get EPERM.
        self.update_param_pre_load(&mut open_obj)?;

        // Fix program types for non-standard TC section names before loading
        set_tc_prog_types(&mut open_obj);

        let obj = open_obj
            .load()
            .context("Failed to load eBPF object from memory into kernel")?;
        info!("eBPF program loaded from byte slice via libbpf-rs");

        // Store the loaded object first so update_param_post_load can access it
        self.obj = Some(obj);

        // After loading, PARAM was already written via update_param_pre_load.
        // No post-load update needed (rodata is read-only after load).

        // Auto-pin maps if pin_path is configured
        if let Some(ref bpffs_path) = self.pin_path.clone() {
            if let Err(e) = self.pin_maps(bpffs_path) {
                warn!("Failed to pin eBPF maps: {}", e);
            }
        }

        Ok(())
    }

    /// Write PARAM to the .rodata map BEFORE loading.
    /// Must be called on the OpenObject — .rodata is writable before load.
    fn update_param_pre_load(&self, open_obj: &mut libbpf_rs::OpenObject) -> Result<()> {
        let param = match self.param.as_ref() {
            Some(p) => p,
            None => {
                warn!("Cannot update PARAM: no PARAM configured");
                return Ok(());
            }
        };
        let param_bytes = bytemuck::bytes_of(param);
        let rodata_map = open_obj.maps_mut().find(|m| {
            let name = m.name().to_str().unwrap_or("");
            name == ".rodata" || name == "rodata" || name.ends_with(".rodata")
        });
        if let Some(mut map) = rodata_map {
            // Use initial_value_mut to read/write the pre-load .rodata buffer
            if let Some(initial) = map.initial_value_mut() {
                if param_bytes.len() <= initial.len() {
                    initial[..param_bytes.len()].copy_from_slice(param_bytes);
                    info!(
                        "PARAM written to .rodata pre-load ({} bytes, initial_value size: {} bytes)",
                        param_bytes.len(),
                        initial.len()
                    );
                } else {
                    warn!(
                        "PARAM size ({}) exceeds .rodata initial_value size ({})",
                        param_bytes.len(),
                        initial.len()
                    );
                }
            } else {
                // No initial value buffer; fall back to constructing a fresh .rodata
                // buffer. Use 4 KiB (covers typical kernel rodata sections). Param
                // is only ~40 bytes, so this is more than sufficient.
                let value_size = 4096;
                let mut full_value = vec![0u8; value_size];
                let copy_len = std::cmp::min(param_bytes.len(), value_size);
                full_value[..copy_len].copy_from_slice(&param_bytes[..copy_len]);
                map.set_initial_value(&full_value)?;
                info!(
                    "PARAM written to .rodata via set_initial_value ({} bytes in {}-byte buffer)",
                    param_bytes.len(),
                    value_size,
                );
            }
        } else {
            warn!("Could not find .rodata map to write PARAM");
        }
        Ok(())
    }

    /// Update PARAM in the .rodata map after loading (fallback, may fail with EPERM).
    ///
    /// This is kept for potential future use as a post-load fallback. Currently,
    /// PARAM is written via `update_param_pre_load()` before load (the preferred path),
    /// because `.rodata` becomes read-only after `bpf_object__load()`.
    #[allow(dead_code)]
    fn update_param_post_load(&self) {
        let obj = match self.obj.as_ref() {
            Some(obj) => obj,
            None => {
                warn!("Cannot update PARAM: eBPF object not loaded");
                return;
            }
        };
        let param = match self.param.as_ref() {
            Some(p) => p,
            None => {
                warn!("Cannot update PARAM: no PARAM configured");
                return;
            }
        };
        let param_bytes = bytemuck::bytes_of(param);
        let rodata_map = obj.maps().find(|m| {
            let name = m.name().to_str().unwrap_or("");
            name == ".rodata" || name == "rodata" || name.ends_with(".rodata")
        });
        if let Some(map) = rodata_map {
            // Read current .rodata value
            let current = match map.lookup(&0u32.to_ne_bytes(), libbpf_rs::MapFlags::empty()) {
                Ok(Some(v)) => v,
                _ => {
                    warn!(".rodata map lookup failed, PARAM not updated");
                    return;
                }
            };
            let mut full_value = current;
            if full_value.len() < param_bytes.len() {
                warn!(
                    ".rodata map too small ({} bytes) for PARAM ({} bytes)",
                    full_value.len(),
                    param_bytes.len()
                );
                return;
            }
            // Patch PARAM bytes at the beginning of .rodata
            full_value[..param_bytes.len()].copy_from_slice(param_bytes);
            if let Err(e) = map.update(
                &0u32.to_ne_bytes(),
                &full_value,
                libbpf_rs::MapFlags::empty(),
            ) {
                warn!("Failed to update .rodata map with PARAM: {}", e);
            } else {
                info!(
                    "PARAM updated via .rodata map ({} bytes, map value size: {} bytes)",
                    param_bytes.len(),
                    full_value.len()
                );
            }
        } else {
            warn!("Could not find .rodata map after load to update PARAM");
        }
    }

    // ============================================================================
    // eBPF Map Pinning
    // ============================================================================

    /// 将所有 eBPF maps pin 到 bpffs 指定路径。
    /// 每个 map 在 bpffs 路径下以其名称创建文件。
    ///
    /// 自动跳过内部 map（如 .rodata、.bss、.data 等）。
    pub fn pin_maps(&mut self, bpffs_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        // 确保 bpffs 已挂载
        ensure_bpffs_mounted()?;

        // 创建 dae 专属目录
        let dir = std::path::Path::new(bpffs_path);
        if !dir.exists() {
            std::fs::create_dir_all(dir)?;
        }

        // 获取 eBPF 对象（可变引用，因为 Map::pin() 需要 &mut self）
        let obj = self.obj.as_mut().ok_or("eBPF object not loaded")?;

        // 收集所有需要 pin 的 map 名称（先收集，再清理旧 pin，最后 pin）
        // 这样避免在遍历 maps_mut() 时同时做清理操作。
        let map_names: Vec<String> = obj
            .maps()
            .filter_map(|m| {
                let name = m.name().to_string_lossy().to_string();
                if name.starts_with('.') || name.is_empty() {
                    None
                } else {
                    Some(name)
                }
            })
            .collect();

        // 清理旧 pin：移除 /sys/fs/bpf/ 根目录下的旧 dae map 文件
        // 上一次 dae-rs 运行可能在 /sys/fs/bpf/<map_name> 留下了旧 pin，
        // 而 libbpf 要求 map 只能 pin 到一个路径，否则 pin 会失败。
        let bpffs_root = std::path::Path::new("/sys/fs/bpf");
        if bpffs_root.exists() {
            for name in &map_names {
                let old_pin = bpffs_root.join(name);
                if old_pin.exists() && old_pin != dir.join(name) {
                    debug!("Removing stale pin at {:?}", old_pin);
                    let _ = std::fs::remove_file(&old_pin);
                }
            }
        }

        // 遍历所有 maps 并 pin
        for mut map in obj.maps_mut() {
            let map_name = map.name().to_string_lossy().to_string();
            // 跳过内部 map（如 .rodata、.bss 等）
            if map_name.starts_with('.') || map_name.is_empty() {
                continue;
            }
            let pin_path = dir.join(&map_name);
            // 如果已存在，先移除再重新 pin
            if pin_path.exists() {
                std::fs::remove_file(&pin_path)?;
            }
            map.pin(&pin_path)?;
            debug!("Pinned map '{}' to {:?}", map_name, pin_path);
        }

        Ok(())
    }

    /// 从 bpffs 卸载所有 dae 的 pinned maps。
    pub fn unpin_maps(&self, bpffs_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::path::Path::new(bpffs_path);
        if !dir.exists() {
            return Ok(());
        }

        // 遍历目录删除所有 pinned map 文件
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                std::fs::remove_file(&path)?;
                debug!("Unpinned map at {:?}", path);
            }
        }

        Ok(())
    }

    /// 检查 bpffs 中是否存在 dae 的 pinned maps。
    pub fn pinned_maps_exist(bpffs_path: &str) -> bool {
        let dir = std::path::Path::new(bpffs_path);
        if !dir.exists() {
            return false;
        }
        // 检查是否有至少一个 map 文件
        dir.read_dir()
            .map(|mut entries| entries.any(|e| e.is_ok()))
            .unwrap_or(false)
    }

    // ========================================================================
    // 通用 TC attach — 将指定程序列表挂载到目标接口
    // ========================================================================

    /// 从程序名推导 TC attach point（ingress/egress）
    fn prog_attach_point(prog_name: &str) -> u32 {
        if prog_name.contains("egress") {
            TC_EGRESS
        } else {
            // 默认 ingress（包含 "ingress" 或不确定时）
            TC_INGRESS
        }
    }

    /// 通用 TC attach：将指定的程序列表挂载到目标接口
    ///
    /// # 参数
    ///
    /// * `ifname` — 目标接口名称
    /// * `progs` — 程序列表，每项为 (程序名, 优先级)
    /// * `handle` — 可选 handle（调用方已将 flip 位合并到 handle 中）
    pub fn attach_tc(
        &mut self,
        ifname: &str,
        progs: &[(&str, u32)],
        handle: Option<u32>,
    ) -> Result<()> {
        let obj = self.obj.as_ref().ok_or(EbpfError::NotLoaded)?;
        let ifindex = if_nametoindex(ifname).map_err(|e| EbpfError::TcAttachError {
            iface: ifname.into(),
            detail: format!("if_nametoindex: {}", e),
        })?;

        info!(iface = %ifname, ifindex = %ifindex, count = %progs.len(), "Attaching TC programs");

        for (prog_name, priority) in progs {
            let prog = match find_prog(obj, prog_name) {
                Ok(p) => p,
                Err(_) => {
                    warn!("TC program '{}' not found, skipping", prog_name);
                    continue;
                }
            };

            let attach_point = Self::prog_attach_point(prog_name);
            let mut hook = TcHook::new(prog.as_fd());
            hook.ifindex(ifindex);
            hook.attach_point(attach_point);
            hook.priority(*priority);

            if let Some(h) = handle {
                hook.handle(h);
            }

            // 对所有接口（包括 WAN、LAN、netkit 设备），先删除已存在的 clsact qdisc，
            // 再重新创建。原因：
            // 1. netkit 设备上的 clsact 如果已存在，hook.create() 是 no-op，
            //    导致之前设置的 priority 不生效。
            // 2. WAN/LAN 接口上可能有上一次 dae-rs 运行遗留的旧 TC filter，
            //    "Exclusivity flag on, cannot modify" 错误会导致新 filter 无法安装，
            //    使得 egress_entered=0，整个代理管道失效。
            //
            // 注意：同一接口可能被 attach_tc() 调用多次（如 attach_wan 先挂载
            // egress 再挂载 ingress），重复删除 clsact 会销毁已挂载的程序。
            // 通过 clsact_cleaned HashSet 确保每个接口只删除一次。
            if !self.clsact_cleaned.contains(ifname) {
                let output = Command::new("tc")
                    .args(["qdisc", "del", "dev", ifname, "clsact"])
                    .output()
                    .map_err(|e| EbpfError::TcAttachError {
                        iface: ifname.into(),
                        detail: format!("delete clsact qdisc failed: {}", e),
                    })?;
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    // "No such file or directory" is expected on first attach — not an error.
                    // "Cannot find specified qdisc" is the same error on some kernel versions.
                    // Any other failure (permission denied, invalid interface, etc.)
                    // is serious: leaving a stale qdisc will cause hook.create() to be a
                    // no-op, silently breaking priority/handle configuration. Abort.
                    if stderr.contains("No such file")
                        || stderr.contains("Cannot find specified qdisc")
                    {
                        debug!(
                            iface = %ifname,
                            "clsact qdisc did not exist on {}, OK",
                            ifname,
                        );
                    } else {
                        return Err(EbpfError::TcAttachError {
                            iface: ifname.into(),
                            detail: format!(
                                "Failed to delete existing clsact qdisc on {}: {}",
                                ifname,
                                stderr.trim(),
                            ),
                        }
                        .into());
                    }
                }
                self.clsact_cleaned.insert(ifname.to_string());
            } else {
                debug!(
                    iface = %ifname,
                    "clsact qdisc already cleaned on {}, skipping delete",
                    ifname,
                );
            }

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
                "TC program '{}' attached to {} (ifindex={}, priority={}, handle={:?})",
                prog_name, ifname, ifindex, priority, handle
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
    /// 读取 `/sys/class/net/<ifname>/type` 判断接口类型。
    /// 与原始 dae Go 行为对齐：dae 使用 netlink EncapType 判断，
    /// 如果是 "none"/"ipip"/"ppp"/"tun" 则为 L3，否则为 L2。
    /// 这里通过 ARPHRD 类型做等价映射。
    fn get_link_header_len(ifname: &str) -> Result<u32> {
        let path = format!("/sys/class/net/{}/type", ifname);
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read interface type for {}", ifname))?;
        let if_type: u32 = content
            .trim()
            .parse()
            .with_context(|| format!("Invalid interface type value for {}", ifname))?;

        // 与 dae Go 的 EncapType 判断对齐：
        // dae Go: EncapType in ["none", "ipip", "ppp", "tun"] → L3 (0), else → L2 (14)
        // ARPHRD 常量映射:
        //   ARPHRD_PPP = 512 (0x200)       → "ppp"
        //   ARPHRD_TUNNEL = 768 (0x300)    → "tun"/"ipip"
        //   ARPHRD_TUNNEL6 = 769 (0x301)   → "tun"
        //   ARPHRD_SIT = 776 (0x308)       → "ipip"
        //   ARPHRD_IPIP = 778 (0x30A)      → "ipip"
        //   ARPHRD_NONE = 65534            → "none" (tun 设备)
        match if_type {
            512 |    // ARPHRD_PPP
            768 |    // ARPHRD_TUNNEL
            769 |    // ARPHRD_TUNNEL6
            776 |    // ARPHRD_SIT
            778 |    // ARPHRD_IPIP
            65534    // ARPHRD_NONE
            => Ok(0),   // L3: 无链路头
            _ => Ok(14), // L2: 默认以太网头 (与 dae 一致)
        }
    }

    /// WAN 接口：根据链路头长度选择 L2 或 L3 版本
    ///
    /// 与原始 dae Go 行为对齐：
    /// - Egress 方向优先级 2，handle sub = 4
    /// - Ingress 方向优先级 1，handle sub = 2
    pub fn attach_wan(&mut self, ifname: &str) -> Result<()> {
        let link_h_len = Self::get_link_header_len(ifname)?;
        let handle_major = 0x2023u32;
        let flip = self.flip;
        info!(
            "Attaching WAN TC programs to {} (link_h_len={}, flip={})",
            ifname, link_h_len, flip
        );

        // Egress (优先级 2, handle sub=4)
        self.attach_tc(
            ifname,
            &[if link_h_len > 0 {
                ("tproxy_wan_egress_l2", 2)
            } else {
                ("tproxy_wan_egress_l3", 2)
            }],
            Some((handle_major << 16) | ((4 & !1u32) | flip)),
        )?;

        // Ingress (优先级 1, handle sub=2)
        self.attach_tc(
            ifname,
            &[if link_h_len > 0 {
                ("tproxy_wan_ingress_l2", 1)
            } else {
                ("tproxy_wan_ingress_l3", 1)
            }],
            Some((handle_major << 16) | ((2 & !1u32) | flip)),
        )?;

        Ok(())
    }

    /// LAN 接口：根据链路头长度选择 L2 或 L3 版本
    ///
    /// 与原始 dae Go 行为对齐：
    /// - Ingress 方向优先级 2，handle sub = 4
    /// - Egress 方向优先级 1，handle sub = 2
    ///
    /// 注意：与 WAN 相反，LAN 的 Egress 优先级更高。
    pub fn attach_lan(&mut self, ifname: &str) -> Result<()> {
        let link_h_len = Self::get_link_header_len(ifname)?;
        let handle_major = 0x2023u32;
        let flip = self.flip;
        info!(
            "Attaching LAN TC programs to {} (link_h_len={}, flip={})",
            ifname, link_h_len, flip
        );

        // Ingress (优先级 2, handle sub=4)
        self.attach_tc(
            ifname,
            &[if link_h_len > 0 {
                ("tproxy_lan_ingress_l2", 2)
            } else {
                ("tproxy_lan_ingress_l3", 2)
            }],
            Some((handle_major << 16) | ((4 & !1u32) | flip)),
        )?;

        // Egress (优先级 1, handle sub=2)
        self.attach_tc(
            ifname,
            &[if link_h_len > 0 {
                ("tproxy_lan_egress_l2", 1)
            } else {
                ("tproxy_lan_egress_l3", 1)
            }],
            Some((handle_major << 16) | ((2 & !1u32) | flip)),
        )?;

        Ok(())
    }

    /// dae0（宿主 NS）：挂载 tproxy_dae0_ingress
    ///
    /// 优先级 0，handle major=0x2022，handle sub=2
    pub fn attach_dae0(&mut self, ifname: &str) -> Result<()> {
        let handle_major = 0x2022u32;
        let flip = self.flip;
        info!("Attaching dae0 TC program to {} (flip={})", ifname, flip);
        self.attach_tc(
            ifname,
            &[("tproxy_dae0_ingress", 0)],
            Some((handle_major << 16) | ((2 & !1u32) | flip)),
        )
    }

    /// dae0peer（代理 NS）：挂载 tproxy_dae0peer_ingress
    ///
    /// 优先级 0，handle major=0x2022，handle sub=2
    pub fn attach_dae0peer(&mut self, ifname: &str) -> Result<()> {
        let handle_major = 0x2022u32;
        let flip = self.flip;
        info!(
            "Attaching dae0peer TC program to {} (flip={})",
            ifname, flip
        );
        self.attach_tc(
            ifname,
            &[("tproxy_dae0peer_ingress", 0)],
            Some((handle_major << 16) | ((2 & !1u32) | flip)),
        )
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
    ///
    /// # 错误回滚
    ///
    /// 如果部分程序 attach 失败，已成功 attach 的程序会被自动 detach 清理。
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

        let mut attached: Vec<(String, libbpf_rs::Link)> = Vec::new();

        let result = (|| -> Result<()> {
            for name in &cgroup_progs {
                let prog = match find_prog(obj, name) {
                    Ok(p) => p,
                    Err(_) => {
                        warn!("cgroup program '{}' not found, skipping", name);
                        continue;
                    }
                };

                match prog.attach_cgroup(cgroup_fd) {
                    Ok(link) => {
                        attached.push((name.to_string(), link));
                        info!("cgroup program '{}' attached", name);
                    }
                    Err(e) => {
                        // 失败时回滚所有已 attach 的 link
                        warn!(
                            "Failed to attach cgroup program '{}': {}, rolling back {} attached link(s)",
                            name,
                            e,
                            attached.len()
                        );
                        for (prog_name, link) in attached.drain(..) {
                            if let Err(e2) = link.detach() {
                                warn!(
                                    "Failed to detach cgroup program '{}' during rollback: {}",
                                    prog_name, e2
                                );
                            }
                        }
                        return Err(anyhow::anyhow!(
                            "Failed to attach cgroup program '{}': {}",
                            name,
                            e
                        ));
                    }
                }
            }
            Ok(())
        })();

        // 如果成功，将 links 转移到 self.cgroup_links
        if result.is_ok() {
            self.cgroup_links
                .extend(attached.into_iter().map(|(_, link)| link));
            info!(
                "cgroup programs attached ({} links)",
                self.cgroup_links.len()
            );
        }

        result
    }

    // ========================================================================
    // 分离 & 卸载
    // ========================================================================

    /// 分离所有 TC 程序和 cgroup 程序
    pub fn detach_all(&mut self) -> Result<()> {
        let start = std::time::Instant::now();
        // Detach TC hooks
        if !self.tc_hooks.is_empty() {
            info!(count = self.tc_hooks.len(), "Detaching TC programs");
            let mut detached = 0u32;
            let mut failed = 0u32;
            for info in self.tc_hooks.iter_mut() {
                if let Err(e) = info.hook.detach() {
                    warn!(
                        "Failed to detach TC hook '{}' on {}: {}",
                        info.prog_name, info.iface, e
                    );
                    failed += 1;
                } else {
                    detached += 1;
                }
            }
            self.tc_hooks.clear();
            debug!(
                "TC detach: {} succeeded, {} failed ({}ms)",
                detached,
                failed,
                start.elapsed().as_millis()
            );
        }

        // Detach cgroup links (drop the ProgramAttachment)
        if !self.cgroup_links.is_empty() {
            info!(count = self.cgroup_links.len(), "Detaching cgroup programs");
            let n = self.cgroup_links.len();
            self.cgroup_links.clear();
            debug!("cgroup links detached: {}", n);
        }

        Ok(())
    }

    /// Detach TC hooks for a specific interface only.
    /// Used for namespace-aware shutdown: dae0peer hooks must be detached
    /// in the proxy namespace before detaching host-NS hooks.
    pub fn detach_by_iface(&mut self, iface: &str) -> Result<()> {
        let start = std::time::Instant::now();
        let before = self.tc_hooks.len();
        let mut to_detach: Vec<usize> = Vec::new();
        for (i, info) in self.tc_hooks.iter().enumerate() {
            if info.iface == iface {
                to_detach.push(i);
            }
        }
        debug!(
            "detach_by_iface: {} hooks match interface {}",
            to_detach.len(),
            iface
        );
        // Detach in reverse order to preserve indices
        for &i in to_detach.iter().rev() {
            let mut info = self.tc_hooks.swap_remove(i);
            if let Err(e) = info.hook.detach() {
                warn!(
                    "Failed to detach TC hook '{}' on {}: {}",
                    info.prog_name, info.iface, e
                );
            }
        }
        let detached = before - self.tc_hooks.len();
        if detached > 0 {
            info!(iface = %iface, count = detached, "Detached TC hooks for interface");
        }
        debug!(
            "detach_by_iface {}: {} hooks ({}ms)",
            iface,
            detached,
            start.elapsed().as_millis()
        );
        Ok(())
    }

    /// 卸载 eBPF 程序（先分离所有 hook，再释放对象）
    pub fn unload(&mut self) -> Result<()> {
        let start = std::time::Instant::now();
        info!("Unloading eBPF program");
        self.detach_all()?;
        self.obj.take();
        debug!("eBPF program unloaded: {}ms", start.elapsed().as_millis());
        Ok(())
    }

    // ============================================================================
    // Map Operations
    // ============================================================================

    pub fn get_map_mut(&mut self, name: &str) -> Result<libbpf_rs::MapMut<'_>> {
        let obj = self.obj.as_mut().ok_or(EbpfError::NotLoaded)?;
        find_map_mut(obj, name)
    }

    /// Update the `dae_ifindex_map` with the current dae0 ifindex.
    ///
    /// This allows the BPF datapath to pick up a new ifindex without reloading
    /// the eBPF program (e.g. when the kernel recreates dae0).
    pub fn update_dae_ifindex_map(&mut self, ifindex: u32) -> Result<()> {
        let map = self.get_map_mut("dae_ifindex_map")?;
        let key = 0u32.to_ne_bytes();
        let val = ifindex.to_ne_bytes();
        map.update(&key, &val, MapFlags::empty())
            .context("Failed to update dae_ifindex_map")?;
        info!("Updated dae_ifindex_map: ifindex={}", ifindex);
        Ok(())
    }

    /// Update the `active_routing_epoch_map` to point to the given slot.
    ///
    /// The eBPF datapath reads this map at the start of every `route()` call
    /// to determine which epoch slot is active. Writing to this map atomically
    /// switches the datapath to the new routing rules.
    pub fn update_active_routing_epoch(&mut self, slot: u32) -> Result<()> {
        let map = self.get_map_mut("active_routing_epoch_map")?;
        let key = 0u32.to_ne_bytes();
        let val = slot.to_ne_bytes();
        map.update(&key, &val, MapFlags::empty())
            .context("Failed to update active_routing_epoch_map")?;
        info!("Updated active_routing_epoch_map: slot={}", slot);
        Ok(())
    }

    /// Write MatchSet entries to routing_map using batch update (single syscall).
    ///
    /// `epoch_slot` specifies which routing epoch slot to write into (0 or 1).
    /// Each slot owns `MAX_MATCH_SET_LEN` entries in routing_map, starting at
    /// `epoch_slot * MAX_MATCH_SET_LEN`.
    ///
    /// Also writes the active rules length to `routing_meta_map[epoch_slot]`.
    ///
    /// Falls back to individual updates if the kernel doesn't support batch operations.
    pub fn write_routing_rules(&mut self, match_sets: &[MatchSet], epoch_slot: u32) -> Result<()> {
        use std::ffi::c_void;
        use std::os::unix::io::AsRawFd;

        let slot_base = routing_epoch_slot_base(epoch_slot)?;
        let start = std::time::Instant::now();
        info!(
            count = match_sets.len(),
            epoch_slot,
            "Writing routing rules to routing_map"
        );
        debug!("First match_set type={}, outbound={}", match_sets.first().map(|m| m.r#type).unwrap_or(0), match_sets.first().map(|m| m.outbound).unwrap_or(0));
        let map = self.get_map_mut("routing_map")?;
        let fd = map.as_fd().as_raw_fd();

        // Batch update active rules via libbpf-sys bpf_map_update_batch
        // Keys are offset by slot_base so each epoch slot gets its own range.
        if !match_sets.is_empty() {
            let num = match_sets.len() as u32;
            let mut count = num;
            let keys: Vec<u32> = (0..num).map(|i| i + slot_base).collect();
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
                    let key = (slot_base + i as u32).to_ne_bytes();
                    map.update(&key, bytemuck::bytes_of(ms), MapFlags::empty())
                        .with_context(|| format!("Failed to write match_set at index {}", i))?;
                }
            } else if count != num {
                warn!("Batch update only wrote {} of {} entries", count, num);
            }
        }

        // Zero-fill unused entries in this slot's range
        let empty = MatchSet::zeroed();
        for i in match_sets.len()..MAX_MATCH_SET_LEN {
            let key = (slot_base + i as u32).to_ne_bytes();
            map.update(&key, bytemuck::bytes_of(&empty), MapFlags::empty())?;
        }

        // Update routing_meta_map[epoch_slot] with active rule count
        let meta_map = self.get_map_mut("routing_meta_map")?;
        let meta_key = epoch_slot.to_ne_bytes();
        let active_len = match_sets.len() as u32;
        meta_map.update(&meta_key, &active_len.to_ne_bytes(), MapFlags::empty())?;
        debug!(
            "routing_map write: {} entries (slot={}, base={}), {}ms",
            match_sets.len(),
            epoch_slot,
            slot_base,
            start.elapsed().as_millis()
        );
        info!(
            "Wrote {} match sets to slot {} (active_len={})",
            match_sets.len(),
            epoch_slot,
            active_len
        );
        Ok(())
    }

    /// Write CIDR entries to inner LPM trie maps via the `lpm_array_map` (ARRAY_OF_MAPS).
    ///
    /// `lpm_array_map` is `BPF_MAP_TYPE_ARRAY_OF_MAPS` whose inner maps are
    /// `BPF_MAP_TYPE_LPM_TRIE`. Each entry tuple `(index, CidrEntry)` specifies:
    ///   - `index`: slot index in the outer ARRAY_OF_MAPS (corresponds to `match_set->index`)
    ///   - `CidrEntry`: the CIDR entry containing IP (16 bytes) and prefix_len
    ///
    /// `epoch_slot` offsets the outer array index by `epoch_slot * MAX_MATCH_SET_LEN`
    /// so each epoch slot gets its own LPM index range.
    ///
    /// This function groups entries by index, looks up the inner LPM trie FD for each
    /// index from the outer map, and writes `(LpmKey, u32)` entries to the inner trie.
    pub fn write_cidr_table(&mut self, entries: &[(u32, CidrEntry)], epoch_slot: u32) -> Result<()> {
        let slot_base = routing_epoch_slot_base(epoch_slot)?;
        let start = std::time::Instant::now();
        use std::ffi::c_void;
        use std::os::unix::io::AsRawFd;

        if entries.is_empty() {
            debug!("write_cidr_table: no entries, skipping");
            return Ok(());
        }

        debug!(
            "write_cidr_table: {} entries to process",
            entries.len()
        );

        // Group entries by outer array index (each index → an inner LPM trie)
        let mut by_index: std::collections::BTreeMap<u32, Vec<LpmKey>> =
            std::collections::BTreeMap::new();
        for (idx, entry) in entries {
            let lpm_key = LpmKey {
                prefixlen: entry.prefix_len as u32,
                data: entry.ip,
            };
            by_index.entry(*idx).or_default().push(lpm_key);
        }
        debug!(
            "CIDR entries grouped into {} inner LPM tries",
            by_index.len()
        );

        // Get outer map FD then release the mutable borrow so we can use raw syscalls
        let outer_fd = {
            let map = self.get_map_mut("lpm_array_map")?;
            map.as_fd().as_raw_fd()
        };
        debug!("lpm_array_map outer FD: {}", outer_fd);

        let mut total_written: usize = 0;

        for (&array_idx, lpm_keys) in &by_index {
            // Create a new LPM_TRIE inner map for this slot.
            // lpm_array_map is BPF_MAP_TYPE_ARRAY_OF_MAPS; each slot must hold
            // an inner map FD before entries can be written to it.
            let inner_map_name = format!("lpm_{}", array_idx);
            let create_opts = libbpf_sys::bpf_map_create_opts {
                sz: std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as u64,
                map_flags: libbpf_sys::BPF_F_NO_PREALLOC,
                ..Default::default()
            };

            let inner_map = libbpf_rs::MapHandle::create(
                libbpf_rs::MapType::LpmTrie,
                Some(inner_map_name.as_str()),
                std::mem::size_of::<LpmKey>() as u32,
                std::mem::size_of::<u32>() as u32,
                MAX_LPM_SIZE,
                &create_opts,
            )
            .with_context(|| {
                format!(
                    "Failed to create inner LPM trie for index {}",
                    array_idx
                )
            })?;

            // Populate the inner map with LPM key → value entries
            let one: u32 = 1;
            for lpm_key in lpm_keys {
                let key_bytes = bytemuck::bytes_of(lpm_key);
                let val_bytes = bytemuck::bytes_of(&one);
                inner_map
                    .update(key_bytes, val_bytes, MapFlags::empty())
                    .with_context(|| {
                        format!(
                            "Failed to write LPM key at inner map index {}",
                            array_idx
                        )
                    })?;
            }

            // Insert the inner map FD into the outer ARRAY_OF_MAPS.
            // For BPF_MAP_TYPE_ARRAY_OF_MAPS, the value in update_elem is the
            // FD of the inner map (as an i32 in native byte order).
            let inner_fd = inner_map.as_fd().as_raw_fd() as i32;
            let outer_idx = slot_base + array_idx;
            let idx_bytes = outer_idx.to_ne_bytes();
            let fd_bytes = inner_fd.to_ne_bytes();
            let ret = unsafe {
                libbpf_sys::bpf_map_update_elem(
                    outer_fd,
                    idx_bytes.as_ptr() as *const c_void,
                    fd_bytes.as_ptr() as *const c_void,
                    0u64, // BPF_ANY
                )
            };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                warn!(
                    "Failed to insert inner LPM trie FD at lpm_array_map[{}]: {}",
                    array_idx, err
                );
                continue;
            }

            total_written += lpm_keys.len();
            debug!(
                "Inner LPM trie at index {}: created, {} keys written",
                array_idx,
                lpm_keys.len()
            );
        }

        debug!(
            "CIDR table write: {} entries in {} tries, {}ms",
            total_written,
            by_index.len(),
            start.elapsed().as_millis()
        );
        info!(
            "Wrote {} CIDR entries across {} inner LPM tries",
            total_written,
            by_index.len()
        );
        Ok(())
    }

    /// Read conntrack entry from conn_state_map.
    pub fn read_conntrack(&mut self, key: &TuplesKey) -> Result<Option<ConnState>> {
        let map = self.get_map_mut("conn_state_map")?;
        let key_bytes = bytemuck::bytes_of(key);
        match map.lookup(key_bytes, MapFlags::empty()) {
            Ok(Some(val)) => Ok(Some(bytemuck::pod_read_unaligned(&val))),
            Ok(None) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("conn_state_map lookup: {}", e)),
        }
    }

    /// Delete conntrack entry from conn_state_map.
    pub fn delete_conntrack(&mut self, key: &TuplesKey) -> Result<()> {
        let map = self.get_map_mut("conn_state_map")?;
        let _ = map.delete(bytemuck::bytes_of(key));
        Ok(())
    }

    /// Read stats from bpf_stats_map.
    pub fn read_stats(&mut self) -> Result<[u64; STATS_MAP_SIZE as usize]> {
        let map = self.get_map_mut("bpf_stats_map")?;
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

    /// Read debug counters from debug_counter_map.
    ///
    /// Map keys (from tproxy.c):
    /// Failure counters (0-5):
    ///   0 = DBG_LISTEN_SOCKET_NULL   — SOCKMAP lookup in assign_listener returned NULL
    ///   1 = DBG_ASSIGN_LISTENER_FAIL — bpf_sk_assign() in dae0peer_ingress failed
    ///   2 = DBG_WAN_REDIRECT_FAIL    — bpf_redirect() from WAN egress to dae0 failed
    ///   3 = DBG_WAN_ROUTE_FAIL       — route() returned error in WAN egress
    ///   4 = DBG_WAN_OUTBOUND_DEAD    — outbound marked dead by wan_outbound_is_alive()
    ///   5 = DBG_WAN_PARSE_FAIL       — parse_packet/parse_transport failed
    /// All-path counters (6-14):
    ///   6 = DBG_WAN_EGRESS_ENTERED   — do_tproxy_wan_egress was called
    ///   7 = DBG_WAN_EGRESS_SKIPPED   — skipped due to ingress_ifindex check
    ///   8 = DBG_WAN_TCP_ENTERED      — do_tproxy_wan_egress_tcp was called
    ///   9 = DBG_WAN_TCP_DIRECT       — TCP went DIRECT path (TC_ACT_OK)
    ///  10 = DBG_WAN_TCP_PROXY        — TCP went PROXY path (redirect)
    ///  11 = DBG_WAN_UDP_ENTERED      — do_tproxy_wan_egress_udp was called
    ///  12 = DBG_WAN_UDP_DIRECT       — UDP went DIRECT path
    ///  13 = DBG_WAN_UDP_PROXY        — UDP went PROXY path
    ///  14 = DBG_DAE0PEER_ENTERED     — dae0peer_ingress was called
    ///  15 = DBG_ASSIGN_CALLED        — bpf_sk_assign called in dae0peer_ingress
    ///  16 = DBG_BPF_SK_ASSIGN_OK     — bpf_sk_assign returned success
    ///  17 = DBG_SK_MATCH              — skb->sk lookup matched
    ///  18 = DBG_SK_NULL               — skb->sk lookup returned NULL
    ///  19 = DBG_SK_MISMATCH           — skb->sk socket mismatch detected
    ///  20 = DBG_DAE0_INGRESS_ENTERED — dae0_ingress was called
    ///  21 = DBG_DAE0_REDIRECT_TUPLE_OK — redirect_tuple_ok in dae0_ingress
    ///  22 = DBG_DAE0_REDIRECT_TRACK_HIT — redirect_track_hit in dae0_ingress
    ///  23 = DBG_DAE0_REDIRECT_SUCCESS — redirect succeeded in dae0_ingress
    ///  24 = DBG_CHG_TYPE_FAIL       — change type failed
    ///  25 = DBG_REDIRECT_TRACK_PUBLISH — publish_redirect_track_for_packet called
    ///  26 = DBG_REDIRECT_TUPLE_LOAD_FAIL — load_redirect_tuple returned error
    ///  27 = DBG_REDIRECT_TRACK_MISS — redirect_track map lookup found nothing
    ///  28 = DBG_REDIRECT_TUPLE_FAST_FALLBACK — fast parser fell back to slow path
    ///  29 = DBG_REDIRECT_TUPLE_SLOW_FAIL — slow parser failed to load tuple
    ///  30 = DBG_REDIRECT_INVALID_IFINDEX — redirect_track hit but ifindex is 0
    ///  31 = DBG_REDIRECT_TRACK_REVERSE_HIT — redirect_track reverse-key lookup hit
    ///  32 = DBG_REDIRECT_TRACK_UPDATE_FAIL — redirect_track map update failed
    ///  33 = DBG_ASSIGN_SELECT_TCP4 — assign_listener selected tcp4 listen key
    ///  34 = DBG_ASSIGN_SELECT_UDP  — assign_listener selected udp listen key
    ///  35 = DBG_ASSIGN_SELECT_TCP6 — assign_listener selected tcp6 listen key
    pub fn read_debug_counters(&mut self) -> Result<[u64; 36]> {
        let map = self.get_map_mut("debug_counter_map")?;
        let mut counters = [0u64; 36];
        for i in 0u32..36 {
            let key = i.to_ne_bytes();
            if let Ok(Some(val_bytes)) = map.lookup(&key, MapFlags::empty()) {
                if val_bytes.len() >= 8 {
                    counters[i as usize] = u64::from_ne_bytes(val_bytes[..8].try_into().unwrap());
                }
            }
        }
        Ok(counters)
    }

    /// Log debug counters for diagnostic purposes.
    pub fn log_debug_counters(&mut self, label: &str) {
        match self.read_debug_counters() {
            Ok(counters) => {
                info!("[{}] Debug counters: egress_entered={} skipped={} tcp_entered={} tcp_direct={} tcp_proxy={} udp_entered={} udp_direct={} udp_proxy={} dae0peer_entered={} listen_null={} assign_fail={} redirect_fail={} route_fail={} outbound_dead={} parse_fail={}",
                    label,
                    counters[6],  // DBG_WAN_EGRESS_ENTERED
                    counters[7],  // DBG_WAN_EGRESS_SKIPPED
                    counters[8],  // DBG_WAN_TCP_ENTERED
                    counters[9],  // DBG_WAN_TCP_DIRECT
                    counters[10], // DBG_WAN_TCP_PROXY
                    counters[11], // DBG_WAN_UDP_ENTERED
                    counters[12], // DBG_WAN_UDP_DIRECT
                    counters[13], // DBG_WAN_UDP_PROXY
                    counters[14], // DBG_DAE0PEER_ENTERED
                    counters[0],  // DBG_LISTEN_SOCKET_NULL
                    counters[1],  // DBG_ASSIGN_LISTENER_FAIL
                    counters[2],  // DBG_WAN_REDIRECT_FAIL
                    counters[3],  // DBG_WAN_ROUTE_FAIL
                    counters[4],  // DBG_WAN_OUTBOUND_DEAD
                    counters[5],  // DBG_WAN_PARSE_FAIL
                );
                info!(
                    "[{}] Assign counters: assign_called={} bpf_sk_assign_ok={}",
                    label,
                    counters[15], // DBG_ASSIGN_CALLED
                    counters[16], // DBG_BPF_SK_ASSIGN_OK
                );
                info!(
                    "[{}] Assign listener selection: tcp4={} udp={} tcp6={}",
                    label,
                    counters[33], // DBG_ASSIGN_SELECT_TCP4
                    counters[34], // DBG_ASSIGN_SELECT_UDP
                    counters[35], // DBG_ASSIGN_SELECT_TCP6
                );
                info!(
                    sk_match = counters[17],
                    sk_null = counters[18],
                    sk_mismatch = counters[19],
                    "[{}] skb->sk verification",
                    label,
                );
                info!(
                    dae0_ingress_entered = counters[20],
                    dae0_redirect_tuple_ok = counters[21],
                    dae0_redirect_track_hit = counters[22],
                    dae0_redirect_success = counters[23],
                    chg_type_fail = counters[24],
                    "[{}] dae0_ingress return path",
                    label,
                );
                info!(
                    redirect_track_publish = counters[25],
                    redirect_tuple_load_fail = counters[26],
                    redirect_track_miss = counters[27],
                    redirect_tuple_fast_fallback = counters[28],
                    redirect_tuple_slow_fail = counters[29],
                    redirect_invalid_ifindex = counters[30],
                    redirect_track_reverse_hit = counters[31],
                    redirect_track_update_fail = counters[32],
                    "[{}] redirect_track diagnostics",
                    label,
                );
                // Log individual failure counters for diagnostic detail
                let failure_names = [
                    "listen_sock_null",
                    "assign_listener_fail",
                    "wan_redirect_fail",
                    "wan_route_fail",
                    "wan_outbound_dead",
                    "wan_parse_fail",
                ];
                for (i, &val) in counters[..6].iter().enumerate() {
                    if val > 0 {
                        info!(
                            "[{}]  ! {} = {} (check tproxy.c for details)",
                            label, failure_names[i], val
                        );
                    }
                }
                if counters.iter().all(|&v| v == 0) {
                    info!(
                        "[{}] All debug counters are zero — no failures detected in eBPF data path",
                        label
                    );
                }
            }
            Err(e) => {
                warn!("[{}] Failed to read debug counters: {}", label, e);
            }
        }
    }

    /// Write excluded comm hashes to cookie_pid_map.
    pub fn write_excluded_comm(&mut self, comm_hashes: &[u32]) -> Result<()> {
        info!(count = comm_hashes.len(), "Writing excluded comm hashes");
        let map = self.get_map_mut("cookie_pid_map")?;
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
        let map = self.get_map_mut("cookie_pid_map")?;
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

    /// Update listen_socket_map with a TProxy listener socket FD.
    ///
    /// The SOCKMAP keys are: 0 = tcp4, 1 = udp, 2 = tcp6.
    /// The value is the socket file descriptor (as u64).
    pub fn update_listen_socket_map(&mut self, key: u32, fd: i32) -> Result<()> {
        let start = std::time::Instant::now();
        let map = self.get_map_mut("listen_socket_map")?;
        let fd_val = fd as u64;
        map.update(&key.to_ne_bytes(), &fd_val.to_ne_bytes(), MapFlags::empty())
            .with_context(|| format!("update listen_socket_map key={}", key))?;
        debug!("listen_socket_map[{}] = {} ({}ms)", key, fd, start.elapsed().as_micros());
        info!(key = key, fd = fd, "Updated listen_socket_map");
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
    /// Each entry maps a `(epoch_slot, IPv6 address)` pair to a bitmap where
    /// each bit corresponds to a domain set rule in routing_map.
    ///
    /// The key is `RoutingEpochIp { slot, addr }` (20 bytes) to match the C-side
    /// `struct routing_epoch_ip`. The bitmap is padded to `MAX_MATCH_SET_LEN / 8`
    /// bytes (128 bytes) before writing.
    ///
    /// `epoch_slot` specifies which routing epoch slot the domain entries belong to.
    pub fn write_domain_routing_map(
        &mut self,
        entries: &[([u8; 16], Vec<u32>)],
        epoch_slot: u32,
    ) -> Result<()> {
        info!(count = entries.len(), epoch_slot, "Writing domain routing entries");
        let map = self.get_map_mut("domain_routing_map")?;
        let expected_bytes = MAX_MATCH_SET_LEN / 8; // 128 bytes = 32 u32 words

        for (ip, bitmap) in entries {
            // Build RoutingEpochIp key: slot + IPv6 address (as __be32[4])
            let addr_u32: [u32; 4] = [
                u32::from_ne_bytes([ip[0], ip[1], ip[2], ip[3]]),
                u32::from_ne_bytes([ip[4], ip[5], ip[6], ip[7]]),
                u32::from_ne_bytes([ip[8], ip[9], ip[10], ip[11]]),
                u32::from_ne_bytes([ip[12], ip[13], ip[14], ip[15]]),
            ];
            let key = RoutingEpochIp {
                slot: epoch_slot,
                addr: addr_u32,
            };

            // Convert Vec<u32> to bytes, padding to expected size for eBPF map.
            let raw = bytemuck::cast_slice::<u32, u8>(bitmap);
            let mut padded = vec![0u8; expected_bytes];
            let copy_len = raw.len().min(expected_bytes);
            padded[..copy_len].copy_from_slice(&raw[..copy_len]);

            map.update(
                bytemuck::bytes_of(&key),
                &padded,
                MapFlags::empty(),
            )
            .with_context(|| "Failed to write domain routing entry")?;
        }
        Ok(())
    }

    /// Delete IP entries from domain_routing_map for a specific epoch slot.
    pub fn delete_domain_routing_entries(&mut self, ips: &[[u8; 16]], epoch_slot: u32) -> Result<()> {
        let map = self.get_map_mut("domain_routing_map")?;
        for ip in ips {
            let addr_u32: [u32; 4] = [
                u32::from_ne_bytes([ip[0], ip[1], ip[2], ip[3]]),
                u32::from_ne_bytes([ip[4], ip[5], ip[6], ip[7]]),
                u32::from_ne_bytes([ip[8], ip[9], ip[10], ip[11]]),
                u32::from_ne_bytes([ip[12], ip[13], ip[14], ip[15]]),
            ];
            let key = RoutingEpochIp {
                slot: epoch_slot,
                addr: addr_u32,
            };
            let _ = map.delete(bytemuck::bytes_of(&key));
        }
        Ok(())
    }

    /// 清空 domain_routing_map 中指定 epoch slot 的所有条目。
    ///
    /// 遍历所有 key（`RoutingEpochIp` = slot + addr，20 字节）并逐个删除
    /// 属于指定 slot 的条目。
    /// 在热重载（reload_config）时调用，以清除旧的路由规则映射。
    /// 返回删除的条目数。
    pub fn clear_domain_routing_slot(&mut self, epoch_slot: u32) -> Result<u32> {
        use std::os::fd::AsRawFd;

        let map = self.get_map_mut("domain_routing_map")?;
        let map_fd = map.as_fd().as_raw_fd();

        let mut count: u32 = 0;
        let mut prev_key: Vec<u8> = Vec::new();

        loop {
            let next_key = {
                let mut buf = vec![0u8; std::mem::size_of::<RoutingEpochIp>()];
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

            // Only delete entries belonging to the specified epoch slot
            if next_key.len() >= 4 {
                let key_slot = u32::from_ne_bytes([
                    next_key[0], next_key[1], next_key[2], next_key[3],
                ]);
                if key_slot == epoch_slot {
                    unsafe {
                        libc::syscall(
                            libc::SYS_bpf,
                            5i64, // BPF_MAP_DELETE_ELEM
                            &(map_fd as u32),
                            next_key.as_ptr(),
                            std::ptr::null::<u8>(),
                        );
                    }
                    count += 1;
                }
            }
            prev_key = next_key;
        }

        if count > 0 {
            info!("Cleared {} entries from domain_routing_map slot {}", count, epoch_slot);
        }

        Ok(count)
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

        let map = self.get_map_mut("outbound_connectivity_map")?;
        let value = if alive { 1u32 } else { 0u32 };
        map.update(&key.to_ne_bytes(), &value.to_ne_bytes(), MapFlags::empty())?;
        Ok(())
    }

    /// Initialize outbound_connectivity_map so all outbounds start as alive.
    ///
    /// BPF ARRAY maps are zero-initialized, but `wan_outbound_is_alive()` in
    /// tproxy.c treats 0 as dead. Without this initialization, ALL proxied
    /// traffic is SHOT (dropped) until the first connectivity check writes 1.
    ///
    /// Uses the ARRAY whole-map update (key = -1) to write all 1536 entries
    /// with a single syscall instead of 1536 individual updates; falls back
    /// to per-key updates if the kernel rejects the batch write.
    pub fn init_outbound_connectivity_map(&mut self) -> Result<()> {
        let start = std::time::Instant::now();
        let map = self.get_map_mut("outbound_connectivity_map")?;
        // 256 outbounds * 3 domains * 2 ipversions
        let whole: [u32; 1536] = [1; 1536];
        if map
            .update(
                &(-1i32).to_ne_bytes(),
                bytemuck::cast_slice(&whole),
                MapFlags::empty(),
            )
            .is_ok()
        {
            debug!(
                "outbound_connectivity_map initialized via whole-map update (1536 entries): {}ms",
                start.elapsed().as_millis()
            );
        } else {
            // Fallback: per-key updates (older kernels / unexpected map size)
            let one: u32 = 1;
            for key in 0u32..1536 {
                map.update(&key.to_ne_bytes(), &one.to_ne_bytes(), MapFlags::empty())?;
            }
            debug!(
                "outbound_connectivity_map initialized via per-key updates (1536 entries): {}ms",
                start.elapsed().as_millis()
            );
        }
        info!("Initialized outbound_connectivity_map (all outbounds alive)");
        Ok(())
    }

    // ============================================================================
    // Janitor: Expired conn_state_map Cleanup + Pressure Detection
    // ============================================================================

    /// Count the number of entries in an eBPF map by iterating keys.
    /// Uses `bpf_map_get_next_key` syscall.
    fn count_map_entries(&self, map_name: &str) -> Result<u32> {
        use std::os::fd::AsRawFd;

        let obj = self.obj.as_ref().ok_or(EbpfError::NotLoaded)?;
        let map = find_map(obj, map_name)?;
        let fd = map.as_fd().as_raw_fd();

        let mut count: u32 = 0;
        let mut prev_key: Vec<u8> = Vec::new();

        loop {
            let mut next_key = vec![0u8; 64]; // large enough for any key
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_bpf,
                    3i64, // BPF_MAP_GET_NEXT_KEY
                    &(fd as u32),
                    if prev_key.is_empty() {
                        std::ptr::null::<u8>()
                    } else {
                        prev_key.as_ptr()
                    },
                    next_key.as_mut_ptr(),
                )
            };
            if ret < 0 {
                break;
            }
            count += 1;
            prev_key = next_key;
        }

        Ok(count)
    }

    /// Detect conn_state_map usage ratio.
    ///
    /// Iterates map keys to count entries, returns usage as f64 (0.0 – 1.0).
    /// Uses the stored `conn_state_map_max_entries` as denominator.
    pub fn conn_state_map_usage(&self) -> Result<f64> {
        let count = self.count_map_entries("conn_state_map")?;
        Ok(count as f64 / self.conn_state_map_max_entries as f64)
    }

    /// Scan and delete expired entries from conn_state_map.
    ///
    /// Iterates all entries via raw BPF syscall, checks `last_seen_ns`
    /// against timeout thresholds, and deletes expired ones.
    /// Returns (deleted_count, remaining_count).
    pub fn janitor_scan_conn_state(&mut self, now_ns: u64) -> Result<(usize, u32)> {
        use std::os::fd::AsRawFd;

        // Timeout constants from tproxy.c (in nanoseconds)
        const TCP_CLOSING_TIMEOUT_NS: u64 = 10_000_000_000; // 10s
        const DEFAULT_TIMEOUT_NS: u64 = 120_000_000_000; // 120s (UDP + TCP established)

        // TCP CLOSING state (include/uapi/linux/tcp.h)
        const TCP_CLOSING: u8 = 7;

        let map = self.get_map_mut("conn_state_map")?;
        let map_fd = map.as_fd().as_raw_fd();

        let mut expired_keys: Vec<Vec<u8>> = Vec::new();
        let mut total_count: u32 = 0;
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

            total_count += 1;

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

        let remaining = total_count.saturating_sub(count as u32);
        if count > 0 {
            info!(
                "Janitor conn_state scan: deleted {} expired, {} remaining",
                count, remaining
            );
        }

        Ok((count, remaining))
    }

    // ============================================================================
    // Janitor: redirect_track Cleanup
    // ============================================================================

    /// Scan and delete expired entries from redirect_track map.
    ///
    /// redirect_track entries have a 5-minute TTL. The kernel updates
    /// `last_seen_ns` on each matching reply packet.
    /// Returns the number of entries deleted.
    pub fn janitor_scan_redirect_track(&mut self, now_ns: u64) -> Result<u32> {
        use std::os::fd::AsRawFd;

        let map = self.get_map_mut("redirect_track")?;
        let map_fd = map.as_fd().as_raw_fd();

        let mut expired_keys: Vec<Vec<u8>> = Vec::new();
        let mut prev_key: Vec<u8> = Vec::new();

        loop {
            let next_key = {
                let mut buf = vec![0u8; 40]; // redirect_tuple: 16+16 = 32, rounded up
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

            // Lookup value to check last_seen_ns
            let mut val = vec![0u8; 40]; // redirect_entry: larger than 32
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

            // redirect_entry C layout (with implicit alignment padding for u64):
            //   ifindex(4) + smac(6) + dmac(6) + from_wan(1) + _pad(7) + last_seen_ns(8)
            // last_seen_ns is at offset 24 (20 + 4 bytes implicit C alignment padding)
            if val.len() >= 32 {
                let last_seen_ns = u64::from_ne_bytes(val[24..32].try_into().unwrap_or([0; 8]));
                if now_ns.saturating_sub(last_seen_ns) > REDIRECT_TRACK_TIMEOUT_NS {
                    expired_keys.push(next_key.clone());
                }
            }

            prev_key = next_key;
        }

        let count = expired_keys.len() as u32;
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
            info!("Janitor redirect_track: deleted {} expired entries", count);
        }

        Ok(count)
    }

    // ============================================================================
    // Janitor: cookie_pid_map Cleanup
    // ============================================================================

    /// Scan and delete expired entries from cookie_pid_map.
    ///
    /// cookie_pid_map entries have a 5-minute TTL based on `last_seen_ns`
    /// in the `ProcInfo` value. The kernel updates this on each matched packet.
    /// Returns the number of entries deleted.
    pub fn janitor_scan_cookie_pid_map(&mut self, now_ns: u64) -> Result<u32> {
        use std::os::fd::AsRawFd;

        let map = self.get_map_mut("cookie_pid_map")?;
        let map_fd = map.as_fd().as_raw_fd();

        let mut expired_keys: Vec<Vec<u8>> = Vec::new();
        let mut prev_key: Vec<u8> = Vec::new();

        loop {
            let next_key = {
                let mut buf = vec![0u8; 16]; // u64 key, rounded up
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

            // Lookup value to check last_seen_ns
            let mut val = vec![0u8; 32]; // ProcInfo: last_seen_ns(8) + pid(4) + pname(16) + pad(4) = 32
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

            // ProcInfo layout: last_seen_ns is at offset 0
            if val.len() >= 8 {
                let last_seen_ns = u64::from_ne_bytes(val[0..8].try_into().unwrap_or([0; 8]));
                if now_ns.saturating_sub(last_seen_ns) > COOKIE_PID_MAP_TIMEOUT_NS {
                    expired_keys.push(next_key.clone());
                }
            }

            prev_key = next_key;
        }

        let count = expired_keys.len() as u32;
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
            info!("Janitor cookie_pid_map: deleted {} expired entries", count);
        }

        Ok(count)
    }

    // ============================================================================
    // Janitor: routing_handoff_map Cleanup
    // ============================================================================

    /// 清理 routing_handoff_map 中的条目。
    ///
    /// routing_handoff_map 是一个短生命周期的交接 map，用于从 eBPF 到用户态的
    /// 路由决策传递。条目应该在用户态读取后尽快清理。这个方法直接清空所有条目。
    ///
    /// 返回删除的条目数。
    pub fn janitor_scan_routing_handoff(&mut self) -> Result<u32> {
        use std::os::fd::AsRawFd;

        let map = self.get_map_mut("routing_handoff_map")?;
        let map_fd = map.as_fd().as_raw_fd();

        let mut count: u32 = 0;
        let mut prev_key: Vec<u8> = Vec::new();

        loop {
            let next_key = {
                let mut buf = vec![0u8; 48]; // tuples_key size is ~37, rounded up
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

            // Delete the entry
            unsafe {
                libc::syscall(
                    libc::SYS_bpf,
                    5i64, // BPF_MAP_DELETE_ELEM
                    &(map_fd as u32),
                    next_key.as_ptr(),
                    std::ptr::null::<u8>(),
                );
            }
            count += 1;
            prev_key = next_key;
        }

        if count > 0 {
            info!("Janitor routing_handoff_map: deleted {} entries", count);
        }

        Ok(count)
    }

    // ============================================================================
    // Routing Handoff Map Operations
    // ============================================================================

    /// Read all entries from routing_handoff_map.
    ///
    /// Iterates the HASH map via `BPF_MAP_GET_NEXT_KEY`, reads the value for each
    /// key, and returns a vector of `(TuplesKey, RoutingHandoffEntry)` pairs.
    pub fn get_routing_handoff_entries(&mut self) -> Result<Vec<(TuplesKey, RoutingHandoffEntry)>> {
        use std::os::fd::AsRawFd;

        let map = self.get_map_mut("routing_handoff_map")?;
        let map_fd = map.as_fd().as_raw_fd();

        let mut entries: Vec<(TuplesKey, RoutingHandoffEntry)> = Vec::new();
        let mut prev_key: Vec<u8> = Vec::new();

        loop {
            let next_key = {
                let mut buf = vec![0u8; 48]; // TuplesKey is 40 bytes, rounded up
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

            // Read the value for this key
            let mut val = vec![0u8; std::mem::size_of::<RoutingHandoffEntry>()];
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

            // Parse key and value
            if next_key.len() >= std::mem::size_of::<TuplesKey>()
                && val.len() >= std::mem::size_of::<RoutingHandoffEntry>()
            {
                let key: TuplesKey = bytemuck::pod_read_unaligned(&next_key[..std::mem::size_of::<TuplesKey>()]);
                let entry: RoutingHandoffEntry = bytemuck::pod_read_unaligned(&val[..std::mem::size_of::<RoutingHandoffEntry>()]);
                entries.push((key, entry));
            }

            prev_key = next_key;
        }

        Ok(entries)
    }

    /// Delete a single entry from routing_handoff_map by key.
    pub fn delete_routing_handoff_entry(&mut self, key: &TuplesKey) -> Result<()> {
        use std::os::fd::AsRawFd;

        let map = self.get_map_mut("routing_handoff_map")?;
        let map_fd = map.as_fd().as_raw_fd();

        unsafe {
            libc::syscall(
                libc::SYS_bpf,
                5i64, // BPF_MAP_DELETE_ELEM
                &(map_fd as u32),
                bytemuck::bytes_of(key).as_ptr(),
                std::ptr::null::<u8>(),
            );
        }

        Ok(())
    }

    /// Write a ConnState entry to conn_state_map.
    ///
    /// This is used by the routing handoff consumer to inject the final routing
    /// decision (outbound, mark, etc.) into the connection state so that subsequent
    /// packets of the same flow are properly handled by the eBPF program.
    pub fn set_conn_state(&mut self, key: &TuplesKey, value: &ConnState) -> Result<()> {
        let map = self.get_map_mut("conn_state_map")?;
        map.update(
            bytemuck::bytes_of(key),
            bytemuck::bytes_of(value),
            MapFlags::empty(),
        )
        .with_context(|| "Failed to write conn_state_map entry")?;
        Ok(())
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
    fn test_redirect_tuple_size() {
        assert_eq!(std::mem::size_of::<RedirectTuple>(), 32);
    }
    #[test]
    fn test_redirect_entry_size() {
        assert_eq!(std::mem::size_of::<RedirectEntry>(), 32);
    }

    #[test]
    fn test_routing_result_size() {
        assert_eq!(std::mem::size_of::<RoutingResult>(), 36);
    }

    #[test]
    fn test_routing_epoch_ip_size() {
        // RoutingEpochIp: slot(u32) + addr(__be32[4]) = 4 + 16 = 20 bytes
        assert_eq!(std::mem::size_of::<RoutingEpochIp>(), 20);
    }

    #[test]
    fn test_routing_handoff_entry_size() {
        assert_eq!(std::mem::size_of::<RoutingHandoffEntry>(), 48);
    }

    #[test]
    fn test_routing_epoch_slot_base() {
        assert_eq!(routing_epoch_slot_base(0).unwrap(), 0);
        assert_eq!(routing_epoch_slot_base(1).unwrap(), MAX_MATCH_SET_LEN as u32);
        assert!(routing_epoch_slot_base(2).is_err());
    }

    #[test]
    fn test_routing_epoch_slot_encode_decode() {
        // Encode/decode round-trip
        assert_eq!(routing_epoch_slot_encode(0), 1);
        assert_eq!(routing_epoch_slot_encode(1), 2);
        assert_eq!(routing_epoch_slot_encode(2), ROUTING_EPOCH_SLOT_UNKNOWN);

        assert_eq!(routing_epoch_slot_decode(1), (0, true));
        assert_eq!(routing_epoch_slot_decode(2), (1, true));
        assert_eq!(routing_epoch_slot_decode(0), (0, false));
        assert_eq!(routing_epoch_slot_decode(3), (0, false));
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
