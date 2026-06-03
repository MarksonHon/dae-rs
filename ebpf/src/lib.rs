//! eBPF 内核程序入口
//!
//! 本模块是 eBPF 数据平面的核心，运行于 Linux 内核的 TC（Traffic Control）
//! 挂载点。职责包括：
//! - 在 TC ingress/egress 挂载点解析数据包元信息（五元组、协议、端口）
//! - 查询规则映射并做直连/代理二选一决策
//! - 在规则决策前执行进程排除检查（命中则 direct）
//! - 对代理流量打标并重定向到用户态控制面
//! - 对已建立连接使用 conntrack map 快速命中

#![no_std]
#![no_main]

use aya_ebpf::bindings::*;
use aya_ebpf::helpers;
use aya_ebpf::macros::{map, tc};
use aya_ebpf::maps::{Array, HashMap};
use aya_ebpf::programs::TcContext;
use aya_log_ebpf::info;

// ============================================================================
// 常量定义
// ============================================================================

/// 代理流量标记：命中 proxy 规则的数据包打此标记，由策略路由导入代理命名空间
const MARK_PROXY: u32 = 0x02000000;
/// 放行流量标记：需跳过劫持的流量打此标记，防止代理进程流量被重复劫持
const MARK_BYPASS: u32 = 0x04000000;
/// 标记匹配掩码：覆盖代理相关高位区间，与策略路由规则对应
const MARK_MASK: u32 = 0x0f000000;

/// 规则映射最大遍历条目数
const MAX_RULES: u32 = 256;
/// 连接跟踪映射大小
const CONNTRACK_SIZE: u32 = 65536;

/// 统计计数索引（STATS_MAP）
const STAT_TOTAL_PKTS: u32 = 0; // 总包数
const STAT_DIRECT: u32 = 1; // direct 决策数
const STAT_PROXY: u32 = 2; // proxy 决策数
const STAT_BYPASS: u32 = 3; // bypass 数
const STAT_CONNTRACK_HIT: u32 = 4; // conntrack 命中数
const STAT_RULE_MISS: u32 = 5; // 规则未命中数
const STAT_IPV4: u32 = 6; // IPv4 包数
const STAT_IPV6: u32 = 7; // IPv6 包数

/// 动作常量
const ACTION_DIRECT: u8 = 0; // 直连
const ACTION_PROXY: u8 = 1; // 代理

/// 协议常量
const IPPROTO_IP: u8 = 0; // IP 协议（占位）
const IPPROTO_TCP: u8 = 6; // TCP
const IPPROTO_UDP: u8 = 17; // UDP

/// 头部长度常量
const IPV4_HDR_MIN_LEN: usize = 20; // IPv4 头部最小长度（不含选项）
const IPV6_HDR_LEN: usize = 40; // IPv6 头部固定长度
const TCP_HDR_MIN_LEN: usize = 20; // TCP 头部最小长度（不含选项）
const UDP_HDR_LEN: usize = 8; // UDP 头部固定长度

// ============================================================================
// eBPF Maps
// ============================================================================

/// 规则映射：存储编译后的规则数组
/// 用户态将规则编译为扁平结构写入此 map，eBPF 程序按顺序匹配
#[map]
pub static RULES_MAP: Array<RuleEntry> = Array::<RuleEntry>::with_max_entries(1024, 0);

/// 连接跟踪映射：五元组 hash -> 决策缓存
/// 用于后续包快速命中，减少重复规则计算
#[map]
pub static CONNTRACK_MAP: HashMap<u64, ConntrackEntry> =
    HashMap::<u64, ConntrackEntry>::with_max_entries(65536, 0);

/// Socket cookie 到进程信息的映射
/// 用于进程归因，判断连接归属进程
#[map]
pub static COOKIE_PROC_MAP: HashMap<u64, ProcInfo> =
    HashMap::<u64, ProcInfo>::with_max_entries(65536, 0);

/// 排除进程名映射：comm_hash -> 1
/// 命中此映射的进程流量直接放行，不经过规则判断
#[map]
pub static EXCLUDED_COMM_MAP: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(128, 0);

/// 排除 PID 映射：pid/tgid -> 1
/// 用户态维护，排除代理自身及指定进程
#[map]
pub static EXCLUDED_PID_MAP: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(128, 0);

/// 统计计数映射：记录各种事件命中次数
#[map]
pub static STATS_MAP: Array<u64> = Array::<u64>::with_max_entries(16, 0);

// ============================================================================
// 数据结构
// ============================================================================

/// 规则条目数据结构
/// 由用户态编译后写入 RULES_MAP
#[repr(C)]
pub struct RuleEntry {
    /// 目的 IP（大端序，IPv4 为 4 字节，IPv6 为 16 字节）
    pub dip: [u8; 16],
    /// 目的 IP 前缀长度（用于 CIDR 匹配）
    pub dip_prefix_len: u8,
    /// 目的端口（网络字节序），0 表示匹配所有端口
    pub dport: u16,
    /// L4 协议类型：0=任意, 1=TCP, 2=UDP
    pub l4proto: u8,
    /// 动作：0=直连, 1=代理
    pub action: u8,
    /// 保留字段，对齐用
    pub _pad: [u8; 12],
}

/// 连接跟踪条目
#[repr(C)]
pub struct ConntrackEntry {
    /// 动作：0=直连, 1=代理
    pub action: u8,
    /// 保留字段
    pub _pad: [u8; 7],
}

/// 进程信息
#[repr(C)]
pub struct ProcInfo {
    /// 进程 ID
    pub pid: u32,
    /// 线程组 ID
    pub tgid: u32,
    /// 进程名（最多 16 字节，与内核 TASK_COMM_LEN 一致）
    pub comm: [u8; 16],
    /// 最后更新时间戳（纳秒）
    pub last_seen_ns: u64,
}

// ============================================================================
// SkBuf：安全的数据包缓冲区封装
// ============================================================================

/// 安全的数据包缓冲区封装
///
/// 封装 TcContext，提供带边界检查的字节读取方法。
/// 所有读取操作均会验证偏移量是否在数据包长度范围内，
/// 确保不会触发 eBPF verifier 的越界告警。
struct SkBuf<'a> {
    ctx: &'a TcContext,
    /// 数据包数据起始指针
    data: *const u8,
    /// 数据包总长度
    len: usize,
}

impl<'a> SkBuf<'a> {
    /// 从 TcContext 创建 SkBuf 封装
    #[inline(always)]
    fn new(ctx: &'a TcContext) -> Self {
        let data = unsafe { ctx.data() } as *const u8;
        let len = ctx.len() as usize;
        SkBuf { ctx, data, len }
    }

    /// 返回数据包总长度
    #[inline(always)]
    fn len(&self) -> usize {
        self.len
    }

    /// 返回数据起始指针
    #[inline(always)]
    fn data(&self) -> *const u8 {
        self.data
    }

    /// 从指定偏移量读取一个 u8 值
    #[inline(always)]
    fn read_u8(&self, offset: usize) -> Option<u8> {
        if offset + 1 > self.len {
            return None;
        }
        Some(unsafe { *self.data.add(offset) })
    }

    /// 从指定偏移量读取一个 u16（大端序，网络字节序）
    #[inline(always)]
    fn read_u16_be(&self, offset: usize) -> Option<u16> {
        if offset + 2 > self.len {
            return None;
        }
        let data = unsafe { core::ptr::read_unaligned(self.data.add(offset) as *const [u8; 2]) };
        Some(u16::from_be_bytes(data))
    }

    /// 从指定偏移量读取一个 u32（大端序，网络字节序）
    #[inline(always)]
    fn read_u32_be(&self, offset: usize) -> Option<u32> {
        if offset + 4 > self.len {
            return None;
        }
        let data = unsafe { core::ptr::read_unaligned(self.data.add(offset) as *const [u8; 4]) };
        Some(u32::from_be_bytes(data))
    }

    /// 从指定偏移量读取一个固定长度字节数组
    #[inline(always)]
    fn read_bytes<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
        if offset + N > self.len {
            return None;
        }
        Some(unsafe { core::ptr::read_unaligned(self.data.add(offset) as *const [u8; N]) })
    }
}

// ============================================================================
// 数据包解析函数
// ============================================================================

/// 解析 IPv4 头，返回 (总长度, 协议, 源IP, 目的IP)
///
/// # 参数
/// - `skb`: 数据包缓冲区
///
/// # 返回值
/// - `Some((total_len, protocol, src_ip, dst_ip))`: 成功解析
/// - `None`: 数据包过短或头部格式异常
#[inline(always)]
fn parse_ipv4(skb: &SkBuf) -> Option<(u16, u8, u32, u32)> {
    // IPv4 头至少 20 字节
    if skb.len() < IPV4_HDR_MIN_LEN {
        return None;
    }

    // 读取版本号和 IHL（Internet Header Length）
    // 字节 0: version(高 4 位) + ihl(低 4 位)
    let version_ihl = skb.read_u8(0)?;
    let ihl = (version_ihl & 0x0f) as usize;

    // IHL 必须 >= 5（20 字节），且以 4 字节为单位
    if ihl < 5 {
        return None;
    }
    let hdr_len = ihl * 4;

    // 确保整个头部在数据包范围内
    if hdr_len > skb.len() {
        return None;
    }

    // 读取总长度（字节 2-3），包含头部和数据
    let total_len = skb.read_u16_be(2)?;

    // 读取协议（字节 9）：标识载荷使用的 L4 协议
    let protocol = skb.read_u8(9)?;

    // 读取源 IP 地址（字节 12-15）
    let src_ip = skb.read_u32_be(12)?;

    // 读取目的 IP 地址（字节 16-19）
    let dst_ip = skb.read_u32_be(16)?;

    Some((total_len, protocol, src_ip, dst_ip))
}

/// 解析 IPv6 头，返回 (载荷长度, 下一协议头, 源IP, 目的IP)
///
/// # 参数
/// - `skb`: 数据包缓冲区
///
/// # 返回值
/// - `Some((payload_len, next_hdr, src_ip, dst_ip))`: 成功解析
/// - `None`: 数据包过短
#[inline(always)]
/// Parse IPv6 header
///
/// Returns (payload_length, next_header, src_ip, dst_ip) where:
/// - payload_length: length of payload after IPv6 header
/// - next_header: L4 protocol number
/// - src_ip: first 4 bytes of source IP (for flow key hashing)
/// - dst_ip: first 4 bytes of destination IP (for flow key hashing)
///
/// Note: We hash the full 128-bit src/dst for conntrack but for the
/// flow_key we use the first 32 bits as a simplification in MVP.
#[inline(always)]
fn parse_ipv6(skb: &SkBuf) -> Option<(u16, u8, u32, u32)> {
    if skb.len() < IPV6_HDR_LEN {
        return None;
    }
    // Read payload length (bytes 4-5)
    let payload_len = (skb.read_u16_be(4)? as u16);
    // Read next header (byte 6)
    let next_header = skb.read_u8(6)?;
    // Read first 4 bytes of source IP (bytes 8-11) for flow key
    let src_ip = skb.read_u32_be(8)?;
    // Read first 4 bytes of destination IP (bytes 24-27) for flow key
    let dst_ip = skb.read_u32_be(24)?;

    Some((payload_len, next_header, src_ip, dst_ip))
}

/// 解析 TCP/UDP 端口，根据协议类型和 L4 头偏移
///
/// TCP 和 UDP 头部的前 4 字节布局相同：
///   - 字节 0-1: 源端口（网络字节序）
///   - 字节 2-3: 目的端口（网络字节序）
///
/// # 参数
/// - `skb`: 数据包缓冲区
/// - `protocol`: L4 协议类型（IPPROTO_TCP 或 IPPROTO_UDP）
/// - `offset`: L4 头在数据包中的起始偏移量（即 IP 头长度）
///
/// # 返回值
/// - `Some((src_port, dst_port))`: 成功解析
/// - `None`: 数据包过短或协议不支持
#[inline(always)]
fn parse_l4_ports(skb: &SkBuf, protocol: u8, offset: usize) -> Option<(u16, u16)> {
    match protocol {
        IPPROTO_TCP => {
            // TCP 头至少 20 字节
            if offset + TCP_HDR_MIN_LEN > skb.len() {
                return None;
            }
            // 源端口（偏移 0-1）
            let src_port = skb.read_u16_be(offset)?;
            // 目的端口（偏移 2-3）
            let dst_port = skb.read_u16_be(offset + 2)?;
            Some((src_port, dst_port))
        }
        IPPROTO_UDP => {
            // UDP 头固定 8 字节
            if offset + UDP_HDR_LEN > skb.len() {
                return None;
            }
            // 源端口（偏移 0-1）
            let src_port = skb.read_u16_be(offset)?;
            // 目的端口（偏移 2-3）
            let dst_port = skb.read_u16_be(offset + 2)?;
            Some((src_port, dst_port))
        }
        _ => None,
    }
}

// ============================================================================
// 进程排除检查
// ============================================================================

/// 检查 skb 是否带有 bypass mark
///
/// 这是进程排除的最主要手段，优先级最高。
/// 如果 `skb_mark & MARK_MASK == MARK_BYPASS`，则跳过劫持直接放行。
///
/// 使用场景：
/// - 代理进程自身发出的流量已被设置 bypass mark
/// - 管理员通过 iptables/nftables 显式标记的流量
///
/// # 参数
/// - `ctx`: TC 上下文
///
/// # 返回值
/// - `true`: 命中 bypass，应直接放行
/// - `false`: 未命中，继续后续判断
#[inline(always)]
fn is_bypass_marked(ctx: &TcContext) -> bool {
    // 读取 skb->mark 字段
    let mark = unsafe { ctx.skb.mark };
    (mark & MARK_MASK) == MARK_BYPASS
}

/// 设置 skb mark 为代理标记
///
/// 使用"先清除高位再设新值"的策略，避免与已有标记冲突。
/// 设置后，后续策略路由规则将该流量导入代理命名空间。
///
/// # 参数
/// - `ctx`: TC 上下文
#[inline(always)]
fn set_proxy_mark(ctx: &TcContext) {
    let current_mark = unsafe { ctx.skb.mark };
    // 先清除 MARK_MASK 覆盖的位，再设置代理 mark
    let new_mark = (current_mark & !MARK_MASK) | MARK_PROXY;
    unsafe {
        ctx.skb.mark = new_mark;
    }
}

/// 通过 socket cookie 检查进程是否在排除列表
///
/// 从 COOKIE_PROC_MAP 查找 cookie 获取进程信息，
/// 然后依次检查：
/// 1. EXCLUDED_PID_MAP（按 pid 匹配）
/// 2. EXCLUDED_PID_MAP（按 tgid 匹配）
/// 3. EXCLUDED_COMM_MAP（按进程名 hash 匹配）
///
/// # 参数
/// - `cookie`: socket cookie 值
///
/// # 返回值
/// - `true`: 进程命中排除列表，应直接放行
/// - `false`: 未命中排除，继续后续判断
#[inline(always)]
fn is_process_excluded(cookie: u64) -> bool {
    // 从 cookie 映射中查找进程信息
    if let Some(proc_info) = unsafe { COOKIE_PROC_MAP.get(&cookie) } {
        // 检查 PID 是否在排除列表中
        if unsafe { EXCLUDED_PID_MAP.get(&proc_info.pid).is_some() } {
            return true;
        }
        // 检查 TGID（线程组 ID）是否在排除列表中
        if unsafe { EXCLUDED_PID_MAP.get(&proc_info.tgid).is_some() } {
            return true;
        }

        // 计算 comm 的 hash 并检查是否在排除 comm 列表中
        let comm_hash = hash_comm(&proc_info.comm);
        if unsafe { EXCLUDED_COMM_MAP.get(&comm_hash).is_some() } {
            return true;
        }
    }
    false
}

/// 计算进程名的 djb2 hash
///
/// djb2 是一种简单高效的字符串哈希算法，由 Dan Bernstein 提出。
/// 选择理由：
/// - 计算开销极低（仅乘法和加法），适合 eBPF 环境
/// - 分布均匀，冲突概率低
/// - 对短字符串（<=16 字节）表现良好
///
/// # 参数
/// - `comm`: 16 字节的进程名数组（以 null 结尾）
///
/// # 返回值
/// 32 位哈希值
#[inline(always)]
fn hash_comm(comm: &[u8; 16]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < 16 {
        let c = comm[i];
        if c == 0 {
            // 遇到 Null 终止符，停止计算
            break;
        }
        // hash = hash * 33 + c
        hash = hash.wrapping_mul(33).wrapping_add(c as u32);
        i += 1;
    }
    hash
}

// ============================================================================
// 规则匹配逻辑
// ============================================================================

/// 检查 IPv4 地址是否匹配 CIDR 规则
///
/// # 参数
/// - `ip`: 待匹配的 IPv4 地址（大端序网络字节序）
/// - `rule_ip`: 规则中的 IP 地址（16 字节数组，IPv4 存储在最后 4 字节）
/// - `prefix_len`: CIDR 前缀长度（0-32）
///
/// # 返回值
/// - `true`: IP 地址在规则 CIDR 范围内
#[inline(always)]
fn ipv4_match_cidr(ip: u32, rule_ip: &[u8; 16], prefix_len: u8) -> bool {
    // 前缀长度为 0 表示匹配所有地址
    if prefix_len == 0 {
        return true;
    }

    // 从 rule_ip 的字节 12-15 提取 IPv4 地址（大端序）
    let rule_ip_u32 = u32::from_be_bytes([rule_ip[12], rule_ip[13], rule_ip[14], rule_ip[15]]);

    // 前缀长度为 32 表示精确匹配
    if prefix_len >= 32 {
        return ip == rule_ip_u32;
    }

    // 计算 CIDR 掩码并执行按位匹配
    let mask = if prefix_len == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix_len)
    };
    (ip & mask) == (rule_ip_u32 & mask)
}

/// 从 RULES_MAP 获取规则数组，按优先级顺序匹配
///
/// 遍历 RULES_MAP，对每条规则按序匹配以下字段：
/// 1. L4 协议类型（0=任意, 1=TCP, 2=UDP）
/// 2. 目的端口（0=任意）
/// 3. 目的 IP（CIDR 匹配）
///
/// 所有条件满足时返回规则对应的动作。
/// 规则按优先级排序，首条命中即返回。
///
/// # 参数
/// - `dip`: 目的 IPv4 地址（大端序）
/// - `dport`: 目的端口（网络字节序）
/// - `protocol`: L4 协议号（6=TCP, 17=UDP）
///
/// # 返回值
/// - `Some(action)`: 命中规则，返回动作（0=direct, 1=proxy）
/// - `None`: 未命中任何规则
#[inline(always)]
fn match_rules(dip: u32, dport: u16, protocol: u8) -> Option<u8> {
    // 遍历 RULES_MAP 中的规则
    // 使用 bounded loop（MAX_RULES=256 为编译期常量），verifier 可接受
    let mut i: u32 = 0;
    while i < MAX_RULES {
        // 尝试获取第 i 条规则
        if let Some(rule) = unsafe { RULES_MAP.get(i) } {
            // ---- 步骤 1：匹配 L4 协议 ----
            // rule.l4proto: 0=任意, 1=TCP, 2=UDP
            let proto_match = match rule.l4proto {
                0 => true, // 匹配所有协议
                1 => protocol == IPPROTO_TCP,
                2 => protocol == IPPROTO_UDP,
                _ => false, // 未定义的协议类型，不匹配
            };

            if !proto_match {
                i += 1;
                continue;
            }

            // ---- 步骤 2：匹配目的端口 ----
            // rule.dport: 0 表示匹配所有端口
            if rule.dport != 0 && rule.dport != dport {
                i += 1;
                continue;
            }

            // ---- 步骤 3：匹配目的 IP（CIDR） ----
            if !ipv4_match_cidr(dip, &rule.dip, rule.dip_prefix_len) {
                i += 1;
                continue;
            }

            // 所有条件匹配，返回规则动作
            return Some(rule.action);
        } else {
            // 读取到无效条目（超出用户态实际写入数量），停止遍历
            break;
        }
        i += 1;
    }

    // 遍历完所有规则均未命中
    None
}

/// 更新指定规则索引的命中统计
///
/// # 参数
/// - `rule_idx`: 规则在 RULES_MAP 中的索引
#[inline(always)]
fn update_rule_stats(rule_idx: u32) {
    // 规则统计索引从 8 开始，避免与通用统计重叠
    let stats_idx = 8 + rule_idx;
    if stats_idx >= 16 {
        return; // 超出 STATS_MAP 容量
    }
    increment_stat(stats_idx);
}

// ============================================================================
// Conntrack 缓存
// ============================================================================

/// 计算五元组 hash 作为 flow key
///
/// 将五元组（源IP、目的IP、源端口、目的端口、协议）压缩为
/// 64 位哈希值，用于 CONNTRACK_MAP 的键。
///
/// 注意：此处不使用密码学哈希，仅用于 map 寻址。
/// 哈希碰撞由 HashMap 内部处理。
///
/// # 参数
/// - `ip_src`: 源 IP 地址（大端序）
/// - `ip_dst`: 目的 IP 地址（大端序）
/// - `port_src`: 源端口（网络字节序）
/// - `port_dst`: 目的端口（网络字节序）
/// - `proto`: 协议号
///
/// # 返回值
/// 64 位 flow key
#[inline(always)]
fn flow_key(ip_src: u32, ip_dst: u32, port_src: u16, port_dst: u16, proto: u8) -> u64 {
    // 将 IP 对组合为高 64 位
    let ip_part = (ip_src as u64) << 32 | (ip_dst as u64);
    // 将端口对和协议组合为低 40 位
    let port_part = (port_src as u64) << 24 | (port_dst as u64) << 8 | (proto as u64);
    // 通过 XOR 混合两部分
    ip_part ^ port_part
}

/// 在 CONNTRACK_MAP 中查找已有决策
///
/// # 参数
/// - `key`: flow key（五元组哈希）
///
/// # 返回值
/// - `Some(action)`: 命中 conntrack，返回缓存的动作
/// - `None`: 未命中，需要执行规则匹配
#[inline(always)]
fn conntrack_lookup(key: u64) -> Option<u8> {
    if let Some(entry) = unsafe { CONNTRACK_MAP.get(&key) } {
        Some(entry.action)
    } else {
        None
    }
}

/// 更新 conntrack 条目
///
/// 将规则决策结果缓存到 CONNTRACK_MAP，供后续包快速命中。
/// 缓存动作后，同一流（五元组相同）的后续包无需重复规则匹配。
///
/// # 参数
/// - `key`: flow key
/// - `action`: 决策结果（0=direct, 1=proxy）
///
/// # 返回值
/// - `true`: 更新成功
/// - `false`: 更新失败（如 map 已满）
#[inline(always)]
fn conntrack_update(key: u64, action: u8) -> bool {
    let entry = ConntrackEntry {
        action,
        _pad: [0u8; 7],
    };
    unsafe { CONNTRACK_MAP.insert(&key, &entry, 0).is_ok() }
}

// ============================================================================
// 统计更新
// ============================================================================

/// 原子增加 STATS_MAP 中指定索引的计数
///
/// 使用 `get_ptr_mut` 获取 map 中对应索引的可变指针，
/// 然后执行原子加 1 操作。
///
/// # 参数
/// - `index`: 统计项索引
#[inline(always)]
fn increment_stat(index: u32) {
    if let Some(val) = unsafe { STATS_MAP.get_ptr_mut(index) } {
        unsafe {
            *val = (*val).wrapping_add(1);
        }
    }
}

// ============================================================================
// 决策仲裁：conntrack 优先 + 规则匹配兜底
// ============================================================================

/// 解析数据包的分流决策
///
/// 决策优先级：
/// 1. conntrack 缓存命中 -> 直接返回缓存动作
/// 2. 规则匹配命中 -> 更新 conntrack，返回动作
/// 3. 规则匹配未命中 -> fallback 到代理（proxy）
///
/// # 参数
/// - `ctx`: TC 上下文（用于日志输出）
/// - `dst_ip`: 目的 IPv4 地址（大端序）
/// - `dst_port`: 目的端口（网络字节序）
/// - `protocol`: L4 协议号
///
/// # 返回值
/// - `action`: 决策结果（ACTION_DIRECT=0 或 ACTION_PROXY=1）
#[inline(always)]
fn resolve_action(ctx: &TcContext, dst_ip: u32, dst_port: u16, protocol: u8) -> u8 {
    // 计算 flow key
    // 对于 ingress 方向，使用（源IP=0, 目的IP=dst_ip, 源端口=0, 目的端口=dst_port, 协议）
    // 注意：实际五元组应包括源IP和源端口以实现双向 conntrack，
    // 但第一阶段简化为一元组（仅目的），后续可升级为完整五元组
    let key = flow_key(0, dst_ip, 0, dst_port, protocol);

    // ---- 步骤 1：查 conntrack 缓存 ----
    if let Some(cached_action) = conntrack_lookup(key) {
        // conntrack 命中，直接返回缓存的动作
        info!(ctx, "conntrack hit, action={}", cached_action);
        increment_stat(STAT_CONNTRACK_HIT);
        match cached_action {
            ACTION_DIRECT => increment_stat(STAT_DIRECT),
            ACTION_PROXY => increment_stat(STAT_PROXY),
            _ => {}
        }
        return cached_action;
    }

    // ---- 步骤 2：conntrack 未命中，执行规则匹配 ----
    if let Some(rule_action) = match_rules(dst_ip, dst_port, protocol) {
        // 规则命中：更新 conntrack 供后续包使用
        conntrack_update(key, rule_action);

        match rule_action {
            ACTION_DIRECT => {
                info!(ctx, "rule matched -> direct");
                increment_stat(STAT_DIRECT);
            }
            ACTION_PROXY => {
                info!(ctx, "rule matched -> proxy");
                increment_stat(STAT_PROXY);
            }
            _ => {}
        }
        return rule_action;
    }

    // ---- 步骤 3：规则未命中，执行 fallback 动作 ----
    // 默认 fallback 到 proxy，确保流量被代理处理
    info!(ctx, "no rule matched, fallback to proxy");
    increment_stat(STAT_RULE_MISS);
    increment_stat(STAT_PROXY);

    // 更新 conntrack 缓存 fallback 决策
    conntrack_update(key, ACTION_PROXY);
    ACTION_PROXY
}

// ============================================================================
// TC ingress 完整处理逻辑
// ============================================================================

/// TC ingress 程序入口点
///
/// 处理入站流量，执行规则匹配与分流决策。
/// 包装 try_tc_ingress 的错误处理。
#[tc]
pub fn tc_ingress(ctx: TcContext) -> i32 {
    match try_tc_ingress(ctx) {
        Ok(ret) => ret,
        Err(e) => {
            // 发生错误时静默放行，不中断内核正常处理路径
            e
        }
    }
}

/// TC ingress 处理逻辑
///
/// 完整处理流程：
///
/// 1. 统计总包数
/// 2. 检查 bypass mark
///    - 命中 → 直接放行（TC_ACT_OK），记录 bypass 统计
/// 3. 解析数据包版本号
///    - IPv4 → 进入 `process_ipv4_ingress`
///    - IPv6 → 第一阶段简化放行
///    - 其他 → 直接放行
/// 4. IPv4 处理子流程 `process_ipv4_ingress`:
///    a. 解析 IPv4 头获取协议和目的 IP
///    b. 仅处理 TCP/UDP，其余直接放行
///    c. 解析 L4 端口
///    d. 调用 `resolve_action` 获取决策
///    e. Direct → 放行（TC_ACT_OK）
///    f. Proxy → 设置 proxy mark，放行（由策略路由处理）
/// 5. 更新统计计数
fn try_tc_ingress(ctx: TcContext) -> Result<i32, i32> {
    // ---- 步骤 1：统计总包数 ----
    increment_stat(STAT_TOTAL_PKTS);

    // ---- 步骤 2：创建 SkBuf 安全封装 ----
    let skb = SkBuf::new(&ctx);

    // ---- 步骤 3：检查 bypass mark ----
    // 优先级最高：如果 skb 已标记为 bypass，直接放行
    if is_bypass_marked(&ctx) {
        info!(&ctx, "tc_ingress: bypass mark hit, direct pass");
        increment_stat(STAT_BYPASS);
        increment_stat(STAT_DIRECT);
        return Ok(TC_ACT_OK as i32);
    }

    // ---- 步骤 4：socket cookie 获取和进程排除检查 ----
    // 获取 socket cookie，判断数据包所属进程是否在排除列表中
    let cookie = unsafe { helpers::bpf_get_socket_cookie(ctx.ctx as *mut core::ffi::c_void) };
    if cookie > 0 && is_process_excluded(cookie) {
        info!(&ctx, "tc_ingress: process excluded, direct pass");
        increment_stat(STAT_BYPASS);
        increment_stat(STAT_DIRECT);
        return Ok(TC_ACT_OK as i32);
    }

    // ---- 步骤 5：判断 IP 版本 ----
    // 数据包至少要有 1 字节才能读取版本号
    if skb.len() < 1 {
        return Ok(TC_ACT_OK as i32);
    }

    // 读取第一个字节的高 4 位获取 IP 版本号
    let first_byte = match skb.read_u8(0) {
        Some(v) => v,
        None => return Ok(TC_ACT_OK as i32),
    };
    let version = (first_byte >> 4) & 0x0f;

    match version {
        4 => {
            // IPv4：进入完整处理逻辑
            increment_stat(STAT_IPV4);
            process_ipv4_ingress(&ctx, &skb)
        }
        6 => {
            increment_stat(STAT_IPV6);
            process_ipv6_ingress(&ctx, &skb)
        }
        _ => {
            // 非 IPv4/IPv6 协议（如 ARP、PPPoE 等），直接放行
            info!(&ctx, "tc_ingress: non-IP packet, direct pass");
            Ok(TC_ACT_OK as i32)
        }
    }
}

/// IPv4 ingress 处理子流程
///
/// 解析 IPv4 数据包并执行分流决策。
///
/// # 处理步骤
/// 1. 解析 IPv4 头获取协议、源/目的 IP
/// 2. 非 TCP/UDP 直接放行
/// 3. 计算 L4 头偏移并解析端口
/// 4. 调用 resolve_action 获取决策
/// 5. 根据决策执行动作
///
/// # 参数
/// - `ctx`: TC 上下文
/// - `skb`: 数据包缓冲区
///
/// # 返回值
/// - `Ok(TC_ACT_OK)`: 正常处理完成（无论 direct 还是 proxy 均放行）
/// - `Err(negative)`: 错误码（实际不使用）
#[inline(always)]
fn process_ipv4_ingress(ctx: &TcContext, skb: &SkBuf) -> Result<i32, i32> {
    // ---- 步骤 1：解析 IPv4 头 ----
    let (_total_len, protocol, _src_ip, dst_ip) = match parse_ipv4(skb) {
        Some(v) => v,
        None => {
            info!(ctx, "tc_ingress: failed to parse IPv4 header, direct pass");
            return Ok(TC_ACT_OK as i32);
        }
    };

    // ---- 步骤 2：仅处理 TCP 和 UDP ----
    if protocol != IPPROTO_TCP && protocol != IPPROTO_UDP {
        return Ok(TC_ACT_OK as i32);
    }

    // ---- 步骤 3：计算 L4 头偏移 ----
    // 从 IPv4 头的 IHL 字段获取 IP 头长度
    let version_ihl = skb.read_u8(0).unwrap_or(0);
    let ip_hdr_len = ((version_ihl & 0x0f) as usize) * 4;
    let l4_offset = ip_hdr_len;

    // 解析 L4 端口
    let (_src_port, dst_port) = match parse_l4_ports(skb, protocol, l4_offset) {
        Some(v) => v,
        None => {
            // 端口解析失败，直接放行
            return Ok(TC_ACT_OK as i32);
        }
    };

    // ---- 步骤 4：执行分流决策 ----
    let action = resolve_action(ctx, dst_ip, dst_port, protocol);

    // ---- 步骤 5：根据决策执行动作 ----
    match action {
        ACTION_DIRECT => {
            // 直连：直接放行，由系统路由处理
            info!(ctx, "tc_ingress: direct action");
            Ok(TC_ACT_OK as i32)
        }
        ACTION_PROXY => {
            // 代理：打 proxy mark，由策略路由导入代理命名空间
            info!(ctx, "tc_ingress: proxy action, setting mark");
            set_proxy_mark(ctx);
            Ok(TC_ACT_OK as i32)
        }
        _ => {
            // 未知动作，安全起见放行
            Ok(TC_ACT_OK as i32)
        }
    }
}

/// IPv6 ingress processing
#[inline(always)]
fn process_ipv6_ingress(ctx: &TcContext, skb: &SkBuf) -> Result<i32, i32> {
    let (_payload_len, next_header, _src_ip, dst_ip) = match parse_ipv6(skb) {
        Some(v) => v,
        None => {
            info!(ctx, "tc_ingress: failed to parse IPv6 header, direct pass");
            return Ok(TC_ACT_OK as i32);
        }
    };

    if next_header != IPPROTO_TCP && next_header != IPPROTO_UDP {
        return Ok(TC_ACT_OK as i32);
    }

    let l4_offset = IPV6_HDR_LEN;
    let (_src_port, dst_port) = match parse_l4_ports(skb, next_header, l4_offset) {
        Some(v) => v,
        None => return Ok(TC_ACT_OK as i32),
    };

    let action = resolve_action(ctx, dst_ip, dst_port, next_header);

    match action {
        ACTION_DIRECT => {
            info!(ctx, "tc_ingress: IPv6 direct action");
            Ok(TC_ACT_OK as i32)
        }
        ACTION_PROXY => {
            info!(ctx, "tc_ingress: IPv6 proxy action, setting mark");
            set_proxy_mark(ctx);
            Ok(TC_ACT_OK as i32)
        }
        _ => Ok(TC_ACT_OK as i32),
    }
}

// ============================================================================
// TC egress 处理逻辑
// ============================================================================

/// TC egress 程序入口点
///
/// 处理出站流量，执行规则匹配与分流决策。
/// 包装 try_tc_egress 的错误处理。
#[tc]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(ctx) {
        Ok(ret) => ret,
        Err(e) => {
            // 发生错误时静默放行
            e
        }
    }
}

/// TC egress 处理逻辑
///
/// Egress 路径与 ingress 对称，处理流程类似但简化：
///
/// 1. 统计总包数
/// 2. 检查 bypass mark
///    - 命中 → 直接放行
/// 3. 解析 IPv4 头获取五元组
/// 4. 非 TCP/UDP 直接放行
/// 5. 执行决策：
///    - 规则匹配 / conntrack 缓存
///    - Direct → 放行
///    - Proxy → 打 proxy mark 放行
///    - 未匹配 → fallback proxy
/// 6. 更新统计计数
///
/// 与 ingress 的区别：
/// - egress 方向不在本地打 conntrack 缓存（由 ingress 侧负责）
/// - egress 主要作用是确保出站代理流量正确打标
fn try_tc_egress(ctx: TcContext) -> Result<i32, i32> {
    // ---- 步骤 1：统计总包数 ----
    increment_stat(STAT_TOTAL_PKTS);

    // ---- 步骤 2：创建 SkBuf 安全封装 ----
    let skb = SkBuf::new(&ctx);

    // ---- 步骤 3：检查 bypass mark ----
    if is_bypass_marked(&ctx) {
        info!(&ctx, "tc_egress: bypass mark hit, direct pass");
        increment_stat(STAT_BYPASS);
        increment_stat(STAT_DIRECT);
        return Ok(TC_ACT_OK as i32);
    }

    // ---- 步骤 4：socket cookie 获取和进程排除检查 ----
    let cookie = unsafe { helpers::bpf_get_socket_cookie(ctx.ctx as *mut core::ffi::c_void) };
    if cookie > 0 && is_process_excluded(cookie) {
        info!(&ctx, "tc_egress: process excluded, direct pass");
        increment_stat(STAT_BYPASS);
        increment_stat(STAT_DIRECT);
        return Ok(TC_ACT_OK as i32);
    }

    // ---- 步骤 5：判断 IP 版本 ----
    if skb.len() < 1 {
        return Ok(TC_ACT_OK as i32);
    }

    let first_byte = match skb.read_u8(0) {
        Some(v) => v,
        None => return Ok(TC_ACT_OK as i32),
    };
    let version = (first_byte >> 4) & 0x0f;

    match version {
        4 => {
            increment_stat(STAT_IPV4);
            process_ipv4_egress(&ctx, &skb)
        }
        6 => {
            increment_stat(STAT_IPV6);
            process_ipv6_egress(&ctx, &skb)
        }
        _ => {
            info!(&ctx, "tc_egress: non-IP packet, direct pass");
            Ok(TC_ACT_OK as i32)
        }
    }
}

/// IPv4 egress 处理子流程
///
/// # 参数
/// - `ctx`: TC 上下文
/// - `skb`: 数据包缓冲区
///
/// # 返回值
/// - `Ok(TC_ACT_OK)`: 正常处理完成
#[inline(always)]
fn process_ipv4_egress(ctx: &TcContext, skb: &SkBuf) -> Result<i32, i32> {
    // 解析 IPv4 头
    let (_total_len, protocol, _src_ip, dst_ip) = match parse_ipv4(skb) {
        Some(v) => v,
        None => {
            info!(ctx, "tc_egress: failed to parse IPv4 header, direct pass");
            return Ok(TC_ACT_OK as i32);
        }
    };

    // 仅处理 TCP 和 UDP
    if protocol != IPPROTO_TCP && protocol != IPPROTO_UDP {
        return Ok(TC_ACT_OK as i32);
    }

    // 计算 L4 头偏移并解析端口
    let version_ihl = skb.read_u8(0).unwrap_or(0);
    let ip_hdr_len = ((version_ihl & 0x0f) as usize) * 4;
    let l4_offset = ip_hdr_len;

    let (_src_port, dst_port) = match parse_l4_ports(skb, protocol, l4_offset) {
        Some(v) => v,
        None => return Ok(TC_ACT_OK as i32),
    };

    // egress 方向执行规则匹配
    // 注意：egress 方向不写 conntrack（由 ingress 负责），避免双写冲突
    if let Some(action) = match_rules(dst_ip, dst_port, protocol) {
        match action {
            ACTION_DIRECT => {
                info!(ctx, "tc_egress: direct action");
                increment_stat(STAT_DIRECT);
                Ok(TC_ACT_OK as i32)
            }
            ACTION_PROXY => {
                // 出站代理流量打标记，由策略路由处理
                info!(ctx, "tc_egress: proxy action, setting mark");
                set_proxy_mark(ctx);
                increment_stat(STAT_PROXY);
                Ok(TC_ACT_OK as i32)
            }
            _ => Ok(TC_ACT_OK as i32),
        }
    } else {
        // 规则未命中：fallback 到 proxy
        info!(ctx, "tc_egress: no rule matched, fallback to proxy");
        increment_stat(STAT_RULE_MISS);
        increment_stat(STAT_PROXY);
        set_proxy_mark(ctx);
        Ok(TC_ACT_OK as i32)
    }
}

/// IPv6 egress processing
#[inline(always)]
fn process_ipv6_egress(ctx: &TcContext, skb: &SkBuf) -> Result<i32, i32> {
    let (_payload_len, next_header, _src_ip, dst_ip) = match parse_ipv6(skb) {
        Some(v) => v,
        None => {
            info!(ctx, "tc_egress: failed to parse IPv6 header, direct pass");
            return Ok(TC_ACT_OK as i32);
        }
    };

    if next_header != IPPROTO_TCP && next_header != IPPROTO_UDP {
        return Ok(TC_ACT_OK as i32);
    }

    let l4_offset = IPV6_HDR_LEN;
    let (_src_port, dst_port) = match parse_l4_ports(skb, next_header, l4_offset) {
        Some(v) => v,
        None => return Ok(TC_ACT_OK as i32),
    };

    if let Some(action) = match_rules(dst_ip, dst_port, next_header) {
        match action {
            ACTION_DIRECT => {
                info!(ctx, "tc_egress: IPv6 direct action");
                increment_stat(STAT_DIRECT);
                Ok(TC_ACT_OK as i32)
            }
            ACTION_PROXY => {
                info!(ctx, "tc_egress: IPv6 proxy action, setting mark");
                set_proxy_mark(ctx);
                increment_stat(STAT_PROXY);
                Ok(TC_ACT_OK as i32)
            }
            _ => Ok(TC_ACT_OK as i32),
        }
    } else {
        info!(ctx, "tc_egress: IPv6 no rule matched, fallback to proxy");
        increment_stat(STAT_RULE_MISS);
        increment_stat(STAT_PROXY);
        set_proxy_mark(ctx);
        Ok(TC_ACT_OK as i32)
    }
}

// ============================================================================
// eBPF Panic Handler
// ============================================================================

/// eBPF panic handler
///
/// eBPF 程序不允许 panic，此 handler 确保如果出现 panic
/// 不会导致内核崩溃，而是进入 unreachable 状态。
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
