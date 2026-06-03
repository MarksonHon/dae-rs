//! eBPF 加载/卸载/附着管理器
//!
//! 本模块负责 eBPF 程序在用户态控制面的完整生命周期管理，包括：
//! - 从编译后的字节码文件加载 eBPF 程序
//! - 将 TC（Traffic Control）程序附着到目标网卡
//! - 从网卡分离 TC 程序并卸载 eBPF
//! - 管理 eBPF map 的读写（规则写入、统计读取等）
//!
//! ## 架构
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │                    EbpfManager                      │
//! │                                                     │
//! │  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
//! │  │ 加载字节码 │  │ TC 附着  │  │ Map 管理        │  │
//! │  │          │  │          │  │                  │  │
//! │  │ Ebpf::load│  │ ingress  │  │ RULES_MAP 写入   │  │
//! │  │          │  │ egress   │  │ STATS_MAP 读取   │  │
//! │  └──────────┘  └──────────┘  └──────────────────┘  │
//! └─────────────────────┬───────────────────────────────┘
//!                       │
//!              ┌────────┴────────┐
//!              │   Linux Kernel  │
//!              │   TC hooks      │
//!              └─────────────────┘
//! ```

use anyhow::{Context, Result};
use aya::maps::{Array, HashMap, Map};
use aya::programs::tc::{SchedClassifier, SchedClassifierLink, TcAttachType};
use aya::Ebpf;
use std::path::Path;
use tracing::{info, warn, error};

// ============================================================================
// 错误类型
// ============================================================================

/// eBPF 管理错误
#[derive(Debug, thiserror::Error)]
pub enum EbpfError {
    /// eBPF 程序未加载
    #[error("eBPF program not loaded")]
    NotLoaded,
    /// eBPF 程序已加载
    #[error("eBPF program already loaded")]
    AlreadyLoaded,
    /// Map 不存在
    #[error("Map '{name}' not found")]
    MapNotFound {
        /// Map 名称
        name: String,
    },
    /// Map 类型不匹配
    #[error("Map '{name}' type mismatch: expected {expected}, got {actual}")]
    MapTypeMismatch {
        /// Map 名称
        name: String,
        /// 期望类型
        expected: &'static str,
        /// 实际类型
        actual: &'static str,
    },
    /// TC 附着失败
    #[error("TC attach failed on interface {iface}: {detail}")]
    TcAttachError {
        /// 目标网卡
        iface: String,
        /// 错误详情
        detail: String,
    },
}

// ============================================================================
// 常量
// ============================================================================

/// 默认 eBPF 字节码文件路径
pub const DEFAULT_EBPF_PATH: &str = "/etc/dae-rs/ebpf.o";
/// 规则映射最大条目数（必须与 eBPF 端一致）
pub const RULES_MAP_MAX: u32 = 1024;
/// 统计映射大小
pub const STATS_MAP_SIZE: u32 = 16;

// ============================================================================
// 数据结构（必须与 eBPF 端的定义完全一致）
// ============================================================================

/// 规则条目（与 [`ebpf/src/lib.rs`](ebpf/src/lib.rs) 中的定义一致）
///
/// 用户态将分流规则编译为此结构并写入 `RULES_MAP`，
/// eBPF 程序按序匹配并执行对应动作。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RuleEntry {
    /// 目的 IP（大端序，IPv4 为最后 4 字节）
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

// 安全地实现 aya::Pod trait，因为 RuleEntry 是 repr(C) 且只包含原始类型
unsafe impl aya::Pod for RuleEntry {}

impl Default for RuleEntry {
    fn default() -> Self {
        Self {
            dip: [0u8; 16],
            dip_prefix_len: 0,
            dport: 0,
            l4proto: 0,
            action: 0,
            _pad: [0u8; 12],
        }
    }
}

/// 连接跟踪条目（与 eBPF 端定义一致）
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ConntrackEntry {
    /// 动作：0=直连, 1=代理
    pub action: u8,
    /// 保留字段
    pub _pad: [u8; 7],
}

/// 进程信息（与 eBPF 端定义一致）
#[repr(C)]
#[derive(Debug, Clone, Copy)]
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

/// 统计计数索引（必须与 eBPF 端 STATS_MAP 索引一致）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatIndex {
    /// 总包数
    TotalPkts = 0,
    /// direct 决策数
    Direct = 1,
    /// proxy 决策数
    Proxy = 2,
    /// bypass 数
    Bypass = 3,
    /// conntrack 命中数
    ConntrackHit = 4,
    /// 规则未命中数
    RuleMiss = 5,
    /// IPv4 包数
    Ipv4 = 6,
    /// IPv6 包数
    Ipv6 = 7,
}

// ============================================================================
// EbpfManager
// ============================================================================

/// eBPF 程序管理器
///
/// 管理 eBPF 程序的完整生命周期，包括加载、附着、分离和卸载。
/// 支持 TC ingress/egress 双方向附着，以及 eBPF map 的读写操作。
///
/// # 生命周期
///
/// ```text
/// new() -> load() -> attach_tc() -> ...使用中... -> detach_tc() -> unload()
/// ```
///
/// # 示例
///
/// ```no_run
/// use control::ebpf::EbpfManager;
///
/// let mut mgr = EbpfManager::new("eth0");
/// mgr.load().expect("Failed to load eBPF");
/// mgr.attach_tc().expect("Failed to attach TC");
/// // ... 运行中 ...
/// mgr.detach_tc().expect("Failed to detach TC");
/// mgr.unload().expect("Failed to unload eBPF");
/// ```
pub struct EbpfManager {
    /// 已加载的 eBPF 对象
    ebpf: Option<Ebpf>,
    /// TC 程序链接（用于卸载）
    links: Vec<SchedClassifierLink>,
    /// 目标网卡
    iface: String,
    /// eBPF 字节码文件路径
    bpf_path: String,
}

impl EbpfManager {
    /// 创建 eBPF 管理器
    ///
    /// 指定 eBPF 程序要附着的网卡名。
    /// 此时不会加载 eBPF 程序，需要调用 [`load()`](EbpfManager::load)。
    ///
    /// # 参数
    ///
    /// * `iface` — 目标网卡名（如 `"eth0"`、`"dae0"`）
    pub fn new(iface: &str) -> Self {
        Self {
            ebpf: None,
            links: Vec::new(),
            iface: iface.to_string(),
            bpf_path: DEFAULT_EBPF_PATH.to_string(),
        }
    }

    /// 创建 eBPF 管理器，指定自定义字节码路径
    ///
    /// # 参数
    ///
    /// * `iface` — 目标网卡名
    /// * `bpf_path` — eBPF 字节码文件路径
    pub fn new_with_path(iface: &str, bpf_path: &str) -> Self {
        Self {
            ebpf: None,
            links: Vec::new(),
            iface: iface.to_string(),
            bpf_path: bpf_path.to_string(),
        }
    }

    /// 加载 eBPF 程序
    ///
    /// 从字节码文件加载 eBPF 对象，aya 会自动解析 map 定义。
    /// 加载后可以通过 map API 获取 map 句柄。
    ///
    /// # 加载流程
    ///
    /// 1. 调用 [`Ebpf::load_file`] 从字节码文件加载
    /// 2. aya 自动验证字节码并创建 map
    /// 3. 保存 Ebpf 对象供后续操作
    ///
    /// # 错误
    ///
    /// - 如果 eBPF 已加载，返回 [`EbpfError::AlreadyLoaded`]
    /// - 字节码文件不存在或格式错误
    /// - 内核拒绝加载（如 verifier 失败）
    pub fn load(&mut self) -> Result<()> {
        if self.ebpf.is_some() {
            return Err(EbpfError::AlreadyLoaded.into());
        }

        let path = Path::new(&self.bpf_path);
        info!(
            bpf_path = %self.bpf_path,
            iface = %self.iface,
            "Loading eBPF program"
        );

        // 使用 aya 的 Ebpf::load_file 从编译后的 .o 文件加载
        let ebpf = Ebpf::load_file(path)
            .with_context(|| format!("Failed to load eBPF bytecode from {}", self.bpf_path))?;

        info!("eBPF program loaded successfully from {}", self.bpf_path);

        self.ebpf = Some(ebpf);
        Ok(())
    }

    /// 从字节切片加载 eBPF 程序（替代从文件加载）
    ///
    /// 适用于 eBPF 字节码内嵌到二进制或从其他来源获取的场景。
    ///
    /// # 参数
    ///
    /// * `bytes` — eBPF 字节码切片
    pub fn load_from_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        if self.ebpf.is_some() {
            return Err(EbpfError::AlreadyLoaded.into());
        }

        info!(
            len = bytes.len(),
            iface = %self.iface,
            "Loading eBPF program from byte slice"
        );

        let ebpf = Ebpf::load(bytes)
            .context("Failed to load eBPF bytecode from memory")?;

        info!("eBPF program loaded successfully from byte slice");

        self.ebpf = Some(ebpf);
        Ok(())
    }

    /// 附着 TC 程序到目标网卡
    ///
    /// 将 ingress 和 egress 两个 TC 程序附着到目标网卡。
    /// 附着后，所有经过该网卡的流量都会经过 eBPF 程序处理。
    ///
    /// # 附着流程
    ///
    /// 1. 从 `Ebpf` 对象获取 `tc_ingress` 程序
    /// 2. 使用 [`SchedClassifier::attach`] 附着到 Ingress 方向
    /// 3. 通过 `take_link` 获取链接所有权，保存到 links 列表
    /// 4. 从 `Ebpf` 对象获取 `tc_egress` 程序
    /// 5. 使用 [`SchedClassifier::attach`] 附着到 Egress 方向
    /// 6. 通过 `take_link` 获取链接所有权，保存到 links 列表
    ///
    /// # 错误
    ///
    /// - 如果 eBPF 未加载，返回 [`EbpfError::NotLoaded`]
    /// - TC 程序名不存在或类型不匹配
    /// - 内核拒绝附着
    pub fn attach_tc(&mut self) -> Result<()> {
        let ebpf = self.ebpf.as_mut()
            .ok_or(EbpfError::NotLoaded)?;

        info!(
            iface = %self.iface,
            "Attaching TC programs (ingress + egress)"
        );

        // ---- 附着 Ingress ----
        let ingress_prog: &mut SchedClassifier = ebpf
            .program_mut("tc_ingress")
            .context("Failed to get 'tc_ingress' program from eBPF object")?
            .try_into()
            .context("Program 'tc_ingress' is not a SchedClassifier")?;

        let ingress_link_id = ingress_prog
            .attach(&self.iface, TcAttachType::Ingress)
            .map_err(|e| EbpfError::TcAttachError {
                iface: self.iface.clone(),
                detail: format!("ingress attach failed: {}", e),
            })?;

        // 通过 take_link 获取链接所有权，确保 Drop 时自动分离
        let ingress_link = ingress_prog
            .take_link(ingress_link_id)
            .context("Failed to take ownership of ingress link")?;

        info!("TC ingress attached to {}", self.iface);

        // ---- 附着 Egress ----
        let egress_prog: &mut SchedClassifier = ebpf
            .program_mut("tc_egress")
            .context("Failed to get 'tc_egress' program from eBPF object")?
            .try_into()
            .context("Program 'tc_egress' is not a SchedClassifier")?;

        let egress_link_id = egress_prog
            .attach(&self.iface, TcAttachType::Egress)
            .map_err(|e| EbpfError::TcAttachError {
                iface: self.iface.clone(),
                detail: format!("egress attach failed: {}", e),
            })?;

        let egress_link = egress_prog
            .take_link(egress_link_id)
            .context("Failed to take ownership of egress link")?;

        info!("TC egress attached to {}", self.iface);

        // 保存 links（Drop 时会自动 detach）
        self.links.push(ingress_link);
        self.links.push(egress_link);

        info!("Both TC programs attached successfully to {}", self.iface);
        Ok(())
    }

    /// 分离 TC 程序
    ///
    /// 从目标网卡分离 ingress 和 egress 两端的 TC 程序。
    /// 分离后流量不再经过 eBPF 处理。
    ///
    /// # 分离流程
    ///
    /// drop 保存的 [`SchedClassifierLink`] 列表，自动分离 TC 程序。
    pub fn detach_tc(&mut self) -> Result<()> {
        if self.links.is_empty() {
            info!("No TC links to detach");
            return Ok(());
        }

        info!(
            iface = %self.iface,
            count = self.links.len(),
            "Detaching TC programs"
        );

        // 清空 links 列表，SchedClassifierLink 的 Drop 实现会自动 detach
        self.links.clear();

        info!("All TC programs detached from {}", self.iface);
        Ok(())
    }

    /// 卸载 eBPF 程序
    ///
    /// 完整的卸载流程：
    /// 1. 先分离 TC 程序（如果还未分离）
    /// 2. 销毁 `Ebpf` 对象（自动释放内核资源，包括 maps、programs）
    ///
    /// # 注意
    ///
    /// 卸载后管理器回到初始状态，可以重新调用 [`load()`](EbpfManager::load) 加载。
    pub fn unload(&mut self) -> Result<()> {
        info!("Unloading eBPF program");

        // 先分离 TC（如果还未分离）
        self.detach_tc()?;

        // 销毁 Ebpf 对象，释放所有内核资源
        self.ebpf.take();

        info!("eBPF program unloaded successfully");
        Ok(())
    }

    /// 获取指定的 eBPF map（只读引用）
    ///
    /// 获取指定的 eBPF map（只读引用）
    ///
    /// 按名称获取 map 的引用，用于后续读写操作。
    ///
    /// # 参数
    ///
    /// * `name` — map 名称（如 `"RULES_MAP"`、`"STATS_MAP"`）
    ///
    /// # 错误
    ///
    /// - 如果 eBPF 未加载，返回 [`EbpfError::NotLoaded`]
    /// - map 不存在，返回 [`EbpfError::MapNotFound`]
    pub fn get_map(&self, name: &str) -> Result<&Map> {
        let ebpf = self.ebpf.as_ref()
            .ok_or(EbpfError::NotLoaded)?;

        ebpf.map(name)
            .ok_or_else(|| EbpfError::MapNotFound { name: name.to_string() }.into())
    }

    /// 获取指定的 eBPF map（可变引用）
    ///
    /// 按名称获取 map 的可变引用，用于写入操作。
    pub fn get_map_mut(&mut self, name: &str) -> Result<&mut Map> {
        let ebpf = self.ebpf.as_mut()
            .ok_or(EbpfError::NotLoaded)?;

        ebpf.map_mut(name)
            .ok_or_else(|| EbpfError::MapNotFound { name: name.to_string() }.into())
    }

    /// 将规则列表写入 RULES_MAP
    ///
    /// 按索引逐个写入规则条目。规则按优先级排序，索引越小优先级越高。
    /// 写入后清空剩余槽位（写入空规则），确保旧规则不会残留。
    ///
    /// # 参数
    ///
    /// * `rules` — 规则条目列表，按优先级排序
    pub fn write_rules(&mut self, rules: &[RuleEntry]) -> Result<()> {
        let ebpf = self.ebpf.as_mut()
            .ok_or(EbpfError::NotLoaded)?;

        info!(
            rule_count = rules.len(),
            max_entries = RULES_MAP_MAX,
            "Writing rules to RULES_MAP"
        );

        // 获取 RULES_MAP 并转换为 Array
        let map = ebpf.map_mut("RULES_MAP")
            .ok_or_else(|| EbpfError::MapNotFound { name: "RULES_MAP".to_string() })?;

        let mut array = Array::<&mut aya::maps::MapData, RuleEntry>::try_from(map)
            .map_err(|_| EbpfError::MapTypeMismatch {
                name: "RULES_MAP".to_string(),
                expected: "Array<RuleEntry>",
                actual: "unknown",
            })?;

        // 写入规则
        for (i, rule) in rules.iter().enumerate() {
            let index = i as u32;
            array.set(index, *rule, 0)
                .with_context(|| format!("Failed to write rule at index {}", i))?;
        }

        // 清空剩余槽位
        if rules.len() < RULES_MAP_MAX as usize {
            let empty_rule = RuleEntry::default();
            for i in rules.len()..RULES_MAP_MAX as usize {
                let index = i as u32;
                let _ = array.set(index, empty_rule, 0);
                // 忽略错误：剩余槽位可能未初始化
            }
        }

        info!("Successfully wrote {} rules to RULES_MAP", rules.len());
        Ok(())
    }

    /// 写入排除进程名到 EXCLUDED_COMM_MAP
    ///
    /// # 参数
    ///
    /// * `comm_hashes` — 进程名 hash 列表
    pub fn write_excluded_comm(&mut self, comm_hashes: &[u32]) -> Result<()> {
        let ebpf = self.ebpf.as_mut()
            .ok_or(EbpfError::NotLoaded)?;

        let map = ebpf.map_mut("EXCLUDED_COMM_MAP")
            .ok_or_else(|| EbpfError::MapNotFound { name: "EXCLUDED_COMM_MAP".to_string() })?;

        let mut hmap = HashMap::<&mut aya::maps::MapData, u32, u8>::try_from(map)
            .map_err(|_| EbpfError::MapTypeMismatch {
                name: "EXCLUDED_COMM_MAP".to_string(),
                expected: "HashMap<u32, u8>",
                actual: "unknown",
            })?;

        for hash in comm_hashes {
            hmap.insert(*hash, 1, 0)
                .with_context(|| format!("Failed to insert excluded comm hash {}", hash))?;
        }

        info!("Wrote {} excluded comm hashes", comm_hashes.len());
        Ok(())
    }

    /// 写入排除 PID 到 EXCLUDED_PID_MAP
    ///
    /// # 参数
    ///
    /// * `pids` — 要排除的 PID 列表
    pub fn write_excluded_pids(&mut self, pids: &[u32]) -> Result<()> {
        let ebpf = self.ebpf.as_mut()
            .ok_or(EbpfError::NotLoaded)?;

        let map = ebpf.map_mut("EXCLUDED_PID_MAP")
            .ok_or_else(|| EbpfError::MapNotFound { name: "EXCLUDED_PID_MAP".to_string() })?;

        let mut hmap = HashMap::<&mut aya::maps::MapData, u32, u8>::try_from(map)
            .map_err(|_| EbpfError::MapTypeMismatch {
                name: "EXCLUDED_PID_MAP".to_string(),
                expected: "HashMap<u32, u8>",
                actual: "unknown",
            })?;

        for pid in pids {
            hmap.insert(*pid, 1, 0)
                .with_context(|| format!("Failed to insert excluded pid {}", pid))?;
        }

        info!("Wrote {} excluded PIDs", pids.len());
        Ok(())
    }

    /// 读取统计计数
    ///
    /// 从 STATS_MAP 读取所有统计值。
    ///
    /// # 返回
    ///
    /// 包含所有统计项的数组，索引对应 [`StatIndex`] 枚举。
    pub fn read_stats(&mut self) -> Result<[u64; STATS_MAP_SIZE as usize]> {
        let ebpf = self.ebpf.as_mut()
            .ok_or(EbpfError::NotLoaded)?;

        let map = ebpf.map_mut("STATS_MAP")
            .ok_or_else(|| EbpfError::MapNotFound { name: "STATS_MAP".to_string() })?;

        let array = Array::<&mut aya::maps::MapData, u64>::try_from(map)
            .map_err(|_| EbpfError::MapTypeMismatch {
                name: "STATS_MAP".to_string(),
                expected: "Array<u64>",
                actual: "unknown",
            })?;

        let mut stats = [0u64; STATS_MAP_SIZE as usize];
        for i in 0..STATS_MAP_SIZE {
            if let Ok(value) = array.get(&i, 0) {
                stats[i as usize] = value;
            }
        }

        Ok(stats)
    }

    /// 检查 eBPF 是否已加载
    pub fn is_loaded(&self) -> bool {
        self.ebpf.is_some()
    }

    /// 检查 TC 是否已附着
    pub fn is_attached(&self) -> bool {
        !self.links.is_empty()
    }

    /// 获取目标网卡名
    pub fn iface(&self) -> &str {
        &self.iface
    }

    /// 获取 TC 链接数量
    pub fn link_count(&self) -> usize {
        self.links.len()
    }
}

impl Drop for EbpfManager {
    /// Drop 时自动卸载
    ///
    /// 如果用户忘记调用 [`unload()`](EbpfManager::unload)，
    /// Drop 实现会自动分离 TC 并释放 eBPF 资源。
    fn drop(&mut self) {
        if self.ebpf.is_some() || !self.links.is_empty() {
            warn!("EbpfManager dropped without explicit unload(), cleaning up");
            let _ = self.unload();
        }
    }
}

// ============================================================================
// 辅助函数
// ============================================================================

/// 计算进程名的 djb2 hash（与 eBPF 端的 hash_comm 完全一致）
///
/// 使用与内核 TASK_COMM_LEN 一致的 16 字节限制。
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

/// 构建默认的 eBPF 字节码路径
///
/// 在目标系统上，eBPF .o 文件通常安装到以下路径之一：
/// - `/etc/dae-rs/ebpf.o`（系统安装）
/// - `/usr/local/lib/dae-rs/ebpf.o`（本地安装）
/// - 相对于可执行文件的路径（开发阶段）
pub fn default_bpf_path() -> String {
    DEFAULT_EBPF_PATH.to_string()
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ebpf_manager_new() {
        let mgr = EbpfManager::new("eth0");
        assert_eq!(mgr.iface, "eth0");
        assert_eq!(mgr.bpf_path, DEFAULT_EBPF_PATH);
        assert!(!mgr.is_loaded());
        assert!(!mgr.is_attached());
        assert_eq!(mgr.link_count(), 0);
    }

    #[test]
    fn test_ebpf_manager_new_with_path() {
        let mgr = EbpfManager::new_with_path("dae0", "/tmp/test_ebpf.o");
        assert_eq!(mgr.iface, "dae0");
        assert_eq!(mgr.bpf_path, "/tmp/test_ebpf.o");
    }

    #[test]
    fn test_rule_entry_default() {
        let rule = RuleEntry::default();
        assert_eq!(rule.dip, [0u8; 16]);
        assert_eq!(rule.dip_prefix_len, 0);
        assert_eq!(rule.dport, 0);
        assert_eq!(rule.l4proto, 0);
        assert_eq!(rule.action, 0);
    }

    #[test]
    fn test_rule_entry_size() {
        // 检查 RuleEntry 的内存布局
        // dip=[u8;16]=16, dip_prefix_len=1, [padding=1], dport=2, l4proto=1, action=1, _pad=12
        // 总 = 16+1+1+2+1+1+12 = 34, 对齐到 4 => 36
        assert_eq!(std::mem::size_of::<RuleEntry>(), 36);
    }

    #[test]
    fn test_conntrack_entry_size() {
        assert_eq!(std::mem::size_of::<ConntrackEntry>(), 8);
    }

    #[test]
    fn test_proc_info_size() {
        assert_eq!(std::mem::size_of::<ProcInfo>(), 32);
    }
}
