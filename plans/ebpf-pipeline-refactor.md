# dae-rs eBPF 代理管道重构方案

## 1. 问题分析

### 1.1 当前 dae-rs vs 原始 dae 差异对比表

| 项目 | 原始 dae | dae-rs（当前） | 修正方向 |
|------|----------|---------------|---------|
| veth 拓扑 | `dae0`→宿主NS, `dae0peer`→代理NS | `dae0`→代理NS, `dae0peer`→宿主NS | 交换 |
| 宿主侧地址（IPv4） | `169.254.0.1/16` | `169.254.100.1/30` | 改为 `169.254.0.1/16` |
| 代理侧地址（IPv4） | `169.254.0.11/16` | `169.254.100.2/30` | 改为 `169.254.0.11/16` |
| 宿主侧地址（IPv6） | 无 | 无 | 新增，在 `ff09::/8` 随机生成 |
| 代理侧地址（IPv6） | 无 | 无 | 新增，在 `ff09::/8` 随机生成 |
| 路由表 ID | 2023 | 20230 | 改为 2023 |
| TPROXY_MARK | `0x8000000` (tproxy.c 写死) | `0x02000000` | 保持一致 |
| `PARAM.dae0_ifindex` | 设置 | **未设置（=0）** | 必须设置 |
| `PARAM.dae0peer_mac` | 设置 | 可能未正确设置 | 从代理NS获取并设置 |
| `PARAM.dae_netns_id` | 设置 | **未设置（=0）** | 必须设置 |
| `PARAM.tproxy_port` | 设置 | 部分设置 | 统一设置 |
| `PARAM.use_redirect_peer` | 自动检测 | **未设置（=0）** | 探测内核支持 |
| `PARAM.control_plane_pid` | 设置 | **未设置（=0）** | 必须设置 |
| WAN TC 挂载 | 物理接口 egress+ingress | **无** | 新增 |
| LAN TC 挂载 | 物理接口 ingress+egress | **无** | 新增 |
| `tproxy_dae0_ingress` | 挂在 `dae0`（宿主NS） | 挂在 `dae0`（代理NS） | NS 修正 |
| `tproxy_dae0peer_ingress` | 挂在 `dae0peer`（代理NS） | **未挂载** | 新增 |
| cgroup 程序 | 在代理NS中 attach | **未 attach** | 新增 |
| `wan_interface` 配置 | 支持 | **不存在** | 新增 |
| `lan_interface` 配置 | 支持 | **不存在** | 新增 |
| netkit 支持 | 内核≥6.7 使用 netkit | **不支持** | 新增 |

### 1.2 数据流差异

**当前 dae-rs（错误）**：
```
应用 (eth0) → [无 TC Hook] → 直接出站
  ↑ 流量完全未被拦截
```

**原始 dae（正确）**：
```
应用 → WAN/LAN 接口 TC Hook → 路由决策
  ├── direct → 直接出站
  └── proxy → bpf_redirect(dae0_ifindex, 0) → dae0 (宿主NS)
              → dae0_ingress → redirect_track 查找 → 转发到目标接口
              → [来回] → dae0peer (代理NS) → dae0peer_ingress
              → skb->mark = TPROXY_MARK → 查路由表2023 → lo
              → TProxy 监听器接管
```

---

## 2. 整体架构

### 2.1 最终拓扑

```
┌──────────────────────────────────────────────────────────────┐
│                     宿主网络命名空间                           │
│                                                              │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │   eth0      │  │   dae0       │  │  WAN/LAN 接口       │  │
│  │  (物理接口)  │  │ 169.254.0.1  │  │  TC: wan_egress    │  │
│  │             │  │ /16         │  │  TC: wan_ingress   │  │
│  │             │  │ TC: dae0_    │  │  TC: lan_ingress   │  │
│  │             │  │     ingress  │  │  TC: lan_egress    │  │
│  └─────────────┘  └──────┬───────┘  └────────────────────┘  │
│                          │                                    │
├──────────────────────────┼───────────────────────────────────┤
│         veth/netkit pair │                                   │
├──────────────────────────┼───────────────────────────────────┤
│                          │                                    │
│  ┌──────────────────┐ ┌─┴──────────┐  ┌──────────────────┐  │
│  │   lo             │ │ dae0peer   │  │  cgroup attach    │  │
│  │   (loopback)     │ │169.254.0.11│  │  sock_create     │  │
│  │   route table    │ │/16         │  │  sock_release    │  │
│  │   2023 → local   │ │TC: dae0peer│  │  connect4/6      │  │
│  │   default dev lo │ │   _ingress │  │  sendmsg4/6      │  │
│  └──────────────────┘ └────────────┘  └──────────────────┘  │
│                    代理网络命名空间                            │
│                    TProxy 监听器 (:15080)                     │
└──────────────────────────────────────────────────────────────┘
```

### 2.2 模块依赖关系

```
┌─────────────────────────────────────────────────────────┐
│                     ControlPlane                         │
│                    (control/src/lib.rs)                  │
│                                                          │
│  ┌─────────┐  ┌───────────┐  ┌─────────┐  ┌─────────┐  │
│  │ Config  │  │ NetnsMgr  │  │EbpfMgr │  │ TProxy  │  │
│  │ 解析    │  │ veth/     │  │ 加载/   │  │ 监听器  │  │
│  │ daefile │  │ netkit    │  │ 挂载/   │  │ 代理 NS │  │
│  │         │  │ 策略路由  │  │ map I/O │  │         │  │
│  └─────────┘  └───────────┘  └─────────┘  └─────────┘  │
│       │              │              │            │       │
│       └──────────────┴──────────────┴────────────┘       │
│                         协调                              │
└─────────────────────────────────────────────────────────┘
```

---

## 3. 模块 1：NetnsManager — 网络命名空间管理

**文件**: [`control/src/netns.rs`](../control/src/netns.rs)

### 3.1 核心变更

1. **交换 veth 拓扑**：`dae0` 留在宿主 NS，`dae0peer` 移入代理 NS
2. **netkit 支持**：优先 `ip link add dev dae0 type netkit`，失败回退 veth
3. **IPv4 地址对齐**：宿主侧 `169.254.0.1/16`，代理侧 `169.254.0.11/16`
4. **IPv6 地址新增**：在 `ff09::/8` 范围内随机生成一对 IPv6 地址

   ```
   生成方式：生成 120 位随机数 R，构造 ff09::/8 范围内地址
   宿主侧（dae0）：   ff09:<R[0]:R[1]:R[2]:R[3]>::1/64
   代理侧（dae0peer）：ff09:<R[0]:R[1]:R[2]:R[3]>::11/64
   ```

   Rust 实现：
   ```rust
   use rand::Rng;

   fn generate_veth_ipv6() -> (String, String) {
       let mut rng = rand::thread_rng();
       // 生成 4 组随机 16 位值
       let groups: Vec<u16> = (0..4).map(|_| rng.gen::<u16>()).collect();
       let host_ip = format!("ff09:{:04x}:{:04x}:{:04x}:{:04x}::1/64",
           groups[0], groups[1], groups[2], groups[3]);
       let peer_ip = format!("ff09:{:04x}:{:04x}:{:04x}:{:04x}::11/64",
           groups[0], groups[1], groups[2], groups[3]);
       (host_ip, peer_ip)
   }
   ```

5. **路由表对齐**：表 ID 2023
6. **TPROXY_MARK 对齐**：`0x8000000` 对应 `tproxy.c` 中写死的常量

### 3.2 新增/修改接口

```rust
/// 网络命名空间管理器
pub struct NetnsManager {
    // ── 现有字段（值修改）──
    host_if: String,         // "dae0" → 不变
    peer_if: String,         // "dae0peer" → 不变
    host_addr: String,       // "169.254.100.1/30" → "169.254.0.1/16" (IPv4)
    peer_addr: String,       // "169.254.100.2/30" → "169.254.0.11/16" (IPv4)
    mtu: u32,                // 不变
    route_table: u32,        // 20230 → 2023
    proxy_mark: u32,         // 0x02000000 → 0x8000000 (TPROXY_MARK)
    proxy_mask: u32,         // 0x0f000000 → 0x8000000 (仅匹配 bit 27)

    // ── 新增字段 ──
    use_netkit: bool,        // 是否成功使用 netkit
    host_ns_fd: Option<OwnedFd>,
    proxy_ns_fd: Option<OwnedFd>,
    child_pid: Option<u32>,
    /// 宿主侧 IPv6 地址（在 ff09::/8 中随机生成）
    host_ipv6: Option<String>,
    /// 代理侧 IPv6 地址（在 ff09::/8 中随机生成）
    peer_ipv6: Option<String>,
}

impl NetnsManager {
    // ── 修改方法 ──
    pub fn new(config: &Config) -> Self;

    // create() 流程彻底重写
    pub fn create(&mut self) -> Result<()>;

    // ── 新增方法 ──
    /// 获取 dae0 在宿主 NS 中的 ifindex（用于 PARAM.dae0_ifindex）
    pub fn get_host_ifindex(&self) -> Result<u32>;

    /// 获取 dae0peer 在代理 NS 中的 ifindex（用于 tproxy_dae0peer_ingress 挂载）
    pub fn get_peer_ifindex(&self) -> Result<u32>;

    /// 获取 dae0peer 的 MAC 地址（用于 PARAM.dae0peer_mac）
    pub fn get_peer_mac(&self) -> Result<[u8; 6]>;

    /// 检查是否使用了 netkit
    pub fn is_netkit(&self) -> bool;
}
```

### 3.3 veth/netkit 创建流程

```
create() 流程:

1. 保存宿主 NS fd
   ↓
2. unshare(CLONE_NEWNET) → 进入新 NS
   ↓
3. 尝试 netkit（内核 ≥ 6.7）:
   ├── ip link add dev dae0 type netkit
   │   ↓ 成功
   │   ip link set dev dae0peer netns 1  → 将 dae0peer 移到宿主 NS
   │   use_netkit = true
   │
   └── 失败（ENOTSUP/ENODEV 等）:
       ip link add dev dae0 type veth peer name dae0peer
       ip link set dev dae0peer netns 1  → 将 dae0peer 移到宿主 NS
       use_netkit = false
   ↓
4. 配置 dae0（在代理 NS 中配置）:
   ip addr add 169.254.0.11/16 dev dae0
   ip link set dev dae0 mtu <mtu> up
   ↓
5. 保存代理 NS fd
   ↓
6. setns → 回到宿主 NS
   ↓
7. 配置 dae0peer（在宿主 NS 中配置）:
   ip addr add 169.254.0.1/16 dev dae0peer
   ip link set dev dae0peer mtu <mtu> up
   ↓
8. 配置 TPROXY_MARK 策略路由（在宿主 NS）:
   # 注意：TPROXY_MARK = 0x8000000
   ip rule add fwmark 0x8000000/0x8000000 table 2023
   ip route add local default dev lo table 2023
   # IPv6
   ip -6 rule add fwmark 0x8000000/0x8000000 table 2023
   ip -6 route add local default dev lo table 2023
```

**注意**：在第 3 步中，`dae0` 创建在代理 NS 中，然后通过 `ip link set dae0peer netns 1` 将对端移到宿主 NS。这与原始 dae 的行为完全一致——原始 dae 也是先进入新 NS 创建 veth，再将一端移到 init netns（PID 1 的 NS）。

但等一下——仔细看原始 dae 的代码。原始 dae 的做法是：

1. 保存当前（宿主）NS fd
2. `unshare(CLONE_NEWNET)` → 进入新的代理 NS
3. 创建 veth pair：`ip link add dae0 type veth peer name dae0peer`
   - 此时 `dae0` 和 `dae0peer` 都在代理 NS 中
4. 将 `dae0` 移到宿主 NS：`ip link set dae0 netns 1`
   - 因为 `dae0` 是 veth 的"主端"，在宿主 NS 从 `dae0` 视角看流量
5. 配置 `dae0peer`（代理 NS 中）：`ip addr add 169.254.0.11/16 dev dae0peer`
6. 保存代理 NS fd
7. `setns` 回到宿主 NS
8. 配置 `dae0`（宿主 NS 中）：`ip addr add 169.254.0.1/16 dev dae0`

所以正确的拓扑是：
- `dae0` → **宿主 NS**（veth 主端）
- `dae0peer` → **代理 NS**（veth 对端）

### 3.4 创建流程（修正版 + IPv6）

```
1. 保存宿主 NS fd
   ↓
2. unshare(CLONE_NEWNET) → 进入代理 NS
   ↓
3. 生成随机 IPv6 地址（在 ff09::/8 范围内）:
   R = 随机生成 4 组 16 位值 [R0, R1, R2, R3]
   host_ipv6 = ff09:R0:R1:R2:R3::1/64
   peer_ipv6 = ff09:R0:R1:R2:R3::11/64
   ↓
4. 创建 veth/netkit pair:
   ├── 优先: ip link add dev dae0 type netkit peer name dae0peer
   │   use_netkit = true
   └── 失败: ip link add dev dae0 type veth peer name dae0peer
       use_netkit = false
   ↓
5. 将 dae0（主端）移到宿主 NS:
   ip link set dev dae0 netns 1
   ↓
6. 配置 dae0peer（代理 NS 中）:
   ip addr add 169.254.0.11/16 dev dae0peer
   ip -6 addr add <peer_ipv6> dev dae0peer
   ip link set dev dae0peer mtu <mtu> up
   ↓
7. 保存代理 NS fd
   ↓
8. setns → 回到宿主 NS
   ↓
9. 配置 dae0（宿主 NS 中）:
   ip addr add 169.254.0.1/16 dev dae0
   ip -6 addr add <host_ipv6> dev dae0
   ip link set dev dae0 mtu <mtu> up
   ↓
10. 配置策略路由（宿主 NS）:
    ip rule add fwmark 0x8000000/0x8000000 table 2023
    ip route add local default dev lo table 2023
    ip -6 rule add fwmark 0x8000000/0x8000000 table 2023
    ip -6 route add local default dev lo table 2023
```

### 3.5 MAC/ifindex 获取方法

```rust
/// 获取 dae0peer 在代理 NS 中的 MAC 地址
pub fn get_peer_mac(&self) -> Result<[u8; 6]> {
    // 通过 setns 到代理 NS，读取 /sys/class/net/dae0peer/address
    // 或使用 ip link show dae0peer 解析
    self.join_proxy_ns()?;
    let mac = read_mac_from_sysfs("dae0peer")?;
    self.join_host_ns()?;
    Ok(mac)
}

/// 获取 dae0 在宿主 NS 中的 ifindex
pub fn get_host_ifindex(&self) -> Result<u32> {
    // 在宿主 NS 中调用 if_nametoindex("dae0")
    let ifindex = if_nametoindex("dae0")?;
    Ok(ifindex as u32)
}

/// 获取 dae0peer 在代理 NS 中的 ifindex
pub fn get_peer_ifindex(&self) -> Result<u32> {
    // 需要切换到代理 NS 获取
    self.join_proxy_ns()?;
    let ifindex = if_nametoindex("dae0peer")?;
    self.join_host_ns()?;
    Ok(ifindex as u32)
}
```

### 3.6 销毁流程变更

```rust
pub fn destroy(&mut self) -> Result<()> {
    // 1. 终止子进程（不变）
    // 2. 删除策略路由规则（IPv4 + IPv6）
    ip -6 rule del fwmark 0x8000000/0x8000000 table 2023
    ip -6 route del local default dev lo table 2023
    ip rule del fwmark 0x8000000/0x8000000 table 2023
    ip route del local default dev lo table 2023
    // 3. 删除 veth: ip link delete dae0
    //    注意：现在 dae0 在宿主 NS，dae0peer 在代理 NS
    //    删除 dae0 会自动删除 veth pair 两端
    ip link delete dae0
    // 4. 清除 IPv6 地址（ip link delete 会自动清理地址）
    //    但显式删除更安全，避免 netkit 残留
    // 5. 关闭 netns fd（不变）
}
```

---

## 4. 模块 2：EbpfManager — eBPF 程序生命周期管理

**文件**: [`control/src/ebpf.rs`](../control/src/ebpf.rs)

### 4.1 架构变更

当前 `EbpfManager` 将 TC 程序硬编码挂载到单个接口。重构后需要：

1. **按目标接口分组挂载** — 支持 WAN/LAN/dae0/dae0peer 多接口
2. **支持 cgroup 程序 attach** — 在代理 NS 中 attach cgroup 程序
3. **完整设置 `Daeparam`** — 所有字段

### 4.2 接口设计

```rust
/// 每个 TC 挂钩的元数据
struct TcAttachInfo {
    hook: TcHook,
    iface: String,
    prog_name: String,
}

pub struct EbpfManager {
    obj: Option<Object>,
    tc_hooks: Vec<TcAttachInfo>,     // 所有 TC hook
    cgroup_fd: Option<OwnedFd>,      // cgroup link fd
    iface: String,                   // 废弃或保留兼容
    bpf_path: String,
    param: Option<Daeparam>,
}

impl EbpfManager {
    // ── 构造函数（不变）──
    pub fn new(iface: &str) -> Self;
    pub fn new_with_path(iface: &str, bpf_path: &str) -> Self;

    // ── PARAM 设置（增强）──
    pub fn set_param(&mut self, param: &Daeparam);

    // ── 加载（不变）──
    pub fn load(&mut self) -> Result<()>;
    pub fn load_from_bytes(&mut self, bytes: &[u8]) -> Result<()>;

    // ================================================================
    // 新增：按接口分组挂载方法
    // ================================================================

    /// 通用方法：将指定程序列表挂载到目标接口的指定方向
    /// 参数 prog_names: [(程序名, attach_point), ...]
    /// attach_point: libbpf_rs::TC_INGRESS 或 TC_EGRESS
    pub fn attach_tc(
        &mut self,
        ifname: &str,
        progs: &[(&str, u32)],  // (program_name, attach_point)
    ) -> Result<()>;

    /// 挂载 WAN 接口的 TC 程序
    /// WAN: tproxy_wan_egress_l2/l3 (EGRESS)
    ///      tproxy_wan_ingress_l2/l3 (INGRESS)
    pub fn attach_wan(&mut self, ifname: &str) -> Result<()>;

    /// 挂载 LAN 接口的 TC 程序
    /// LAN: tproxy_lan_ingress_l2/l3 (INGRESS)
    ///      tproxy_lan_egress_l2/l3 (EGRESS)
    pub fn attach_lan(&mut self, ifname: &str) -> Result<()>;

    /// 挂载 dae0（宿主 NS）的 TC 程序
    /// dae0: tproxy_dae0_ingress (INGRESS)
    pub fn attach_dae0(&mut self, ifname: &str) -> Result<()>;

    /// 挂载 dae0peer（代理 NS）的 TC 程序
    /// dae0peer: tproxy_dae0peer_ingress (INGRESS)
    pub fn attach_dae0peer(&mut self, ifname: &str) -> Result<()>;

    /// 在代理 NS 中 attach cgroup 程序
    /// 需要 cgroup 文件描述符（通常是 /sys/fs/cgroup 或自建 cgroup）
    pub fn attach_cgroup(&mut self, cgroup_fd: RawFd) -> Result<()>;

    // ================================================================
    // 清理
    // ================================================================

    /// 分离所有 TC 程序
    pub fn detach_all(&mut self) -> Result<()>;

    /// 卸载 eBPF 对象
    pub fn unload(&mut self) -> Result<()>;
}
```

### 4.3 TC 程序分组表

| 程序名 | SEC | 挂载位置 | 方向 | 条件 |
|--------|-----|---------|------|------|
| `tproxy_wan_egress_l2` | `tc/wan_egress_l2` | WAN 接口（宿主NS） | EGRESS | 有 wan_interface |
| `tproxy_wan_egress_l3` | `tc/wan_egress_l3` | WAN 接口（宿主NS） | EGRESS | 有 wan_interface |
| `tproxy_wan_ingress_l2` | `tc/wan_ingress_l2` | WAN 接口（宿主NS） | INGRESS | 有 wan_interface |
| `tproxy_wan_ingress_l3` | `tc/wan_ingress_l3` | WAN 接口（宿主NS） | INGRESS | 有 wan_interface |
| `tproxy_lan_ingress_l2` | `tc/lan_ingress_l2` | LAN 接口（宿主NS） | INGRESS | 有 lan_interface |
| `tproxy_lan_ingress_l3` | `tc/lan_ingress_l3` | LAN 接口（宿主NS） | INGRESS | 有 lan_interface |
| `tproxy_lan_egress_l2` | `tc/lan_egress_l2` | LAN 接口（宿主NS） | EGRESS | 有 lan_interface |
| `tproxy_lan_egress_l3` | `tc/lan_egress_l3` | LAN 接口（宿主NS） | EGRESS | 有 lan_interface |
| `tproxy_dae0_ingress` | `tc/dae0_ingress` | dae0（宿主NS） | INGRESS | 始终 |
| `tproxy_dae0peer_ingress` | `tc/dae0peer_ingress` | dae0peer（代理NS） | INGRESS | 始终 |

**为什么是 L2/L3 双程序？**
- `L2` 版本：`link_h_len = 14`（有 Ethernet 头），用于物理接口
- `L3` 版本：`link_h_len = 0`（无 Ethernet 头），用于 veth/netkit 等 L3 接口
- dae0_ingress 和 dae0peer_ingress 本身就是 L3-only（没有 L2/L3 变体）

### 4.4 attach_tc 通用方法实现

```rust
pub fn attach_tc(
    &mut self,
    ifname: &str,
    progs: &[(&str, u32)],  // (program_name, attach_point)
) -> Result<()> {
    let obj = self.obj.as_ref().ok_or(EbpfError::NotLoaded)?;
    let ifindex = if_nametoindex(ifname)
        .map_err(|e| EbpfError::TcAttachError { iface: ifname.into(), detail: e.to_string() })?;

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
    Ok(())
}
```

### 4.5 cgroup 程序 attach

tproxy.c 中有 6 个 cgroup 程序需要 attach 在代理 NS 中：

- `tproxy_wan_cg_sock_create` — `cgroup/sock_create`
- `tproxy_wan_cg_sock_release` — `cgroup/sock_release`
- `tproxy_wan_cg_connect4` — `cgroup/connect4`
- `tproxy_wan_cg_connect6` — `cgroup/connect6`
- `tproxy_wan_cg_sendmsg4` — `cgroup/sendmsg4`
- `tproxy_wan_cg_sendmsg6` — `cgroup/sendmsg6`

这些程序通过 libbpf-rs 的 `CgroupSkb` 或通用 `Program::attach_cgroup()` 来 attach。

```rust
/// 在代理 NS 中 attach cgroup 程序
pub fn attach_cgroup(&mut self, cgroup_fd: RawFd) -> Result<()> {
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
        // 使用 libbpf-rs 的 attach_cgroup 方法
        // libbpf_rs::Program::attach_cgroup(cgroup_fd) -> Result<ProgramAttachment>
        let link = prog.attach_cgroup(cgroup_fd)
            .map_err(|e| anyhow::anyhow!("Failed to attach cgroup program '{}': {}", name, e))?;
        // 保存 link fd 以便 detach
        // ...
    }
    Ok(())
}
```

### 4.6 Daeparam 完整设置

```rust
/// 构建完整的 Daeparam
pub fn build_param(
    tproxy_port: u16,
    pid: u32,
    dae0_ifindex: u32,
    dae0peer_mac: [u8; 6],
    dae_netns_id: u32,      // 代理 NS 的 inode 号
    use_redirect_peer: bool,
    has_bpf_get_current_task: bool,
    dae_socket_mark: u32,
) -> Daeparam {
    Daeparam {
        tproxy_port: tproxy_port as u32,
        control_plane_pid: pid,
        dae0_ifindex,           // 宿主 NS 中 dae0 的 ifindex
        dae_netns_id,           // 代理 NS 的 inode 号
        dae0peer_mac,           // 代理 NS 中 dae0peer 的 MAC
        padding_after_mac: [0u8; 2],
        use_redirect_peer: if use_redirect_peer { 1 } else { 0 },
        has_bpf_get_current_task: if has_bpf_get_current_task { 1 } else { 0 },
        padding2: 0,
        dae_socket_mark,
    }
}
```

**`dae_netns_id` 的获取**：
```rust
/// 获取代理 NS 的 inode 号（用于 PARAM.dae_netns_id）
pub fn get_netns_inode(fd: RawFd) -> Result<u32> {
    use std::os::linux::fs::MetadataExt;
    let stat = std::fs::metadata(format!("/proc/self/fd/{}", fd))?;
    // netns 的 inode 就是其标识符
    Ok(stat.st_ino() as u32)
}
```

**`use_redirect_peer` 探测**：
```rust
/// 探测是否支持 bpf_redirect_peer（内核 ≥ 6.8 且修复了 CVE-2025-37959）
pub fn probe_redirect_peer() -> bool {
    // 通过检查内核版本来决定
    // 简化实现：读取 /proc/sys/kernel/osrelease
    // 内核 ≥ 6.8 返回 true
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default();
    // 解析 Linux 版本号 ...
    // 简化：由配置或自动探测决定
    false  // 默认关闭，使用 bpf_redirect
}
```

---

## 5. 模块 3：Config — 配置解析

**文件**: [`control/src/config.rs`](../control/src/config.rs)

### 5.1 新增配置结构体

```rust
/// 网络接口配置（新增）
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct InterfaceConfig {
    /// WAN 接口列表（空格分隔）
    pub wan_interface: Vec<String>,
    /// LAN 接口列表（空格分隔）
    pub lan_interface: Vec<String>,
    /// 绑定接口（自动模式时使用）
    pub bind_interface: Option<String>,
}
```

### 5.2 daefile 解析扩展

新增 `interface` 区块：

```daefile
interface {
    wan_interface: eth0
    lan_interface: eth1 docker0
    # bind_interface: auto  # 可选，自动检测
}
```

### 5.3 Parser 状态扩展

```rust
enum ParseState {
    // ... 现有状态 ...
    /// Inside interface section
    Interface,
}
```

在 `parse_daefile` 的 `ParseState::Top` 分支中添加：
```rust
"interface" => state = ParseState::Interface,
```

处理逻辑：
```rust
ParseState::Interface => {
    if line == "}" {
        state = ParseState::Top;
        continue;
    }
    // 解析 wan_interface: eth0 eth1
    // 解析 lan_interface: eth1 docker0
    parse_kv_pair(line, line_number, |key, value| {
        match key {
            "wan_interface" | "lan_interface" | "bind_interface" => {
                let ifaces: Vec<String> = value.split_whitespace()
                    .map(|s| unquote(s).to_string())
                    .collect();
                // 设置到 config
            }
            _ => Err(...)
        }
    })?;
}
```

### 5.4 DaefileConfig 扩展

```rust
pub struct DaefileConfig {
    // ... 现有字段 ...
    /// Network interface configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<InterfaceConfig>,
}
```

### 5.5 Config（lib.rs）扩展

```rust
pub struct Config {
    // ... 现有字段 ...
    /// WAN 接口列表
    pub wan_interface: Vec<String>,
    /// LAN 接口列表
    pub lan_interface: Vec<String>,
}
```

---

## 6. 模块 4：ControlPlane — 控制面协调

**文件**: [`control/src/lib.rs`](../control/src/lib.rs)

### 6.1 start() 完整流程

```
start() 流程:

┌────────────────────────────────────────────────────────────────┐
│ Step 1: 创建代理命名空间                                         │
│ netns_mgr.create()                                              │
│  ├── unshare(CLONE_NEWNET)                                     │
│  ├── 创建 netkit/veth pair                                      │
│  │   dae0 → 宿主 NS                                            │
│  │   dae0peer → 代理 NS                                        │
│  ├── 配置 dae0peer IP: 169.254.0.11/16（代理 NS）              │
│  └── 配置 dae0 IP: 169.254.0.1/16（宿主 NS）                  │
│     + 策略路由: fwmark 0x8000000 → table 2023 → lo            │
└────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌────────────────────────────────────────────────────────────────┐
│ Step 2: 构建 Daeparam                                           │
│  ├── 进入代理 NS 获取 dae0peer MAC 地址                         │
│  ├── 在宿主 NS 获取 dae0 ifindex                                │
│  ├── 获取代理 NS inode（dae_netns_id）                          │
│  ├── 获取当前 PID（control_plane_pid）                           │
│  ├── 探测 bpf_redirect_peer 支持                                │
│  └── 组装 Daeparam                                              │
└────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌────────────────────────────────────────────────────────────────┐
│ Step 3: 进入代理 NS → 加载 eBPF → 设置 PARAM                    │
│  ├── setns → 代理 NS                                           │
│  ├── ebpf_mgr.set_param(&param)                                │
│  ├── ebpf_mgr.load()                                           │
│  └── 此时 eBPF 程序已加载但尚未 attach                          │
└────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌────────────────────────────────────────────────────────────────┐
│ Step 4: 在代理 NS 中 attach cgroup 程序                         │
│  ├── 打开 /sys/fs/cgroup（或使用 cgroup2 挂载点）               │
│  └── ebpf_mgr.attach_cgroup(cgroup_fd)                         │
│       attach 6 个 cgroup 程序                                  │
└────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌────────────────────────────────────────────────────────────────┐
│ Step 5: 在代理 NS 中 attach dae0peer_ingress TC                  │
│  ├── ebpf_mgr.attach_dae0peer("dae0peer")                      │
│  └── 只挂载 tproxy_dae0peer_ingress (INGRESS)                   │
└────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌────────────────────────────────────────────────────────────────┐
│ Step 6: 回到宿主 NS → attach WAN/LAN/dae0 TC 程序              │
│  ├── setns → 宿主 NS                                           │
│  ├── ebpf_mgr.attach_dae0("dae0")                              │
│  │   挂载 tproxy_dae0_ingress (INGRESS)                        │
│  ├── for each wan_if in wan_interface:                         │
│  │   ebpf_mgr.attach_wan(wan_if)                               │
│  │   挂载 tproxy_wan_egress_l2/l3 (EGRESS)                    │
│  │   挂载 tproxy_wan_ingress_l2/l3 (INGRESS)                  │
│  └── for each lan_if in lan_interface:                         │
│      ebpf_mgr.attach_lan(lan_if)                               │
│      挂载 tproxy_lan_ingress_l2/l3 (INGRESS)                  │
│      挂载 tproxy_lan_egress_l2/l3 (EGRESS)                    │
└────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌────────────────────────────────────────────────────────────────┐
│ Step 7: 写入 eBPF maps                                          │
│  ├── 写入排除进程列表（cookie_pid_map）                         │
│  └── 写入路由规则（routing_map + routing_meta_map）             │
└────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌────────────────────────────────────────────────────────────────┐
│ Step 8: 启动 TProxy 监听器（在代理 NS）                         │
│  ├── 创建 SOCKS5 dialer                                        │
│  ├── 创建 TproxyListener                                       │
│  └── 在独立线程中 setns → 代理 NS → 启动 tokio runtime         │
└────────────────────────────────────────────────────────────────┘
```

### 6.2 stop() 完整流程

```
stop() 流程:

1. 停止 API 服务器
   ↓
2. 停止 TProxy 监听器（发送 stop 信号，等待线程退出）
   ↓
3. 回到宿主 NS → detach 所有 WAN/LAN/dae0 TC 程序
   ↓
4. 进入代理 NS → detach dae0peer TC 程序 + cgroup 程序
   ↓
5. 卸载 eBPF 程序
   ↓
6. 销毁网络命名空间
```

### 6.3 start() 伪代码

```rust
pub async fn start(&mut self) -> Result<()> {
    info!("=== dae-rs eBPF Proxy Pipeline Starting ===");

    // ---- Step 1: 创建网络命名空间 ----
    info!("Step 1/8: Creating network namespace");
    self.netns_mgr.create()?;

    // ---- Step 2: 构建 Daeparam ----
    info!("Step 2/8: Building Daeparam");
    let dae0_ifindex = self.netns_mgr.get_host_ifindex()?;   // 宿主 NS
    let dae0peer_mac = self.netns_mgr.get_peer_mac()?;       // 代理 NS
    let dae_netns_id = self.netns_mgr.get_proxy_netns_inode()?;
    let pid = std::process::id();
    let use_redirect_peer = probe_redirect_peer();           // 内核 ≥ 6.8
    let has_bpf_get_current_task = probe_bpf_get_current_task(); // 内核 ≥ 5.x
    let dae_socket_mark = self.config.fwmark_proxy;          // 或 TPROXY_MARK

    let param = Daeparam {
        tproxy_port: self.config.tproxy_port as u32,
        control_plane_pid: pid,
        dae0_ifindex,
        dae_netns_id,
        dae0peer_mac,
        padding_after_mac: [0u8; 2],
        use_redirect_peer: if use_redirect_peer { 1 } else { 0 },
        has_bpf_get_current_task: if has_bpf_get_current_task { 1 } else { 0 },
        padding2: 0,
        dae_socket_mark,
    };
    self.ebpf_param = Some(param);

    // ---- Step 3: 进入代理 NS → 加载 eBPF（设置 PARAM） ----
    info!("Step 3/8: Entering proxy NS to load eBPF");
    self.netns_mgr.join_proxy_ns()?;
    self.ebpf_mgr.set_param(&self.ebpf_param.unwrap());
    if let Some(ebpf_bytes) = self.embedded_ebpf {
        self.ebpf_mgr.load_from_bytes(ebpf_bytes)?;
    } else {
        self.ebpf_mgr.load()?;
    }

    // ---- Step 4: 在代理 NS 中 attach cgroup 程序 ----
    info!("Step 4/8: Attaching cgroup programs in proxy NS");
    let cgroup_fd = open_cgroup_fd()?;   // /sys/fs/cgroup
    self.ebpf_mgr.attach_cgroup(cgroup_fd)?;

    // ---- Step 5: 在代理 NS 中 attach dae0peer_ingress ----
    info!("Step 5/8: Attaching dae0peer_ingress TC in proxy NS");
    self.ebpf_mgr.attach_dae0peer("dae0peer")?;

    // ---- Step 6: 回到宿主 NS → attach WAN/LAN/dae0 TC ----
    info!("Step 6/8: Returning to host NS to attach TC programs");
    self.netns_mgr.join_host_ns()?;

    // 挂载 dae0_ingress
    self.ebpf_mgr.attach_dae0("dae0")?;

    // 挂载 WAN 接口
    for wan_if in &self.config.wan_interface {
        info!("Attaching WAN TC programs to {}", wan_if);
        self.ebpf_mgr.attach_wan(wan_if)?;
    }

    // 挂载 LAN 接口
    for lan_if in &self.config.lan_interface {
        info!("Attaching LAN TC programs to {}", lan_if);
        self.ebpf_mgr.attach_lan(lan_if)?;
    }

    // ---- Step 7: 写入 eBPF maps ----
    info!("Step 7/8: Writing eBPF maps");
    write_exclusion_list(&mut self.ebpf_mgr, &self.daefile_config)?;
    write_routing_rules(&mut self.ebpf_mgr, &self.daefile_config)?;

    // ---- Step 8: 启动 TProxy ----
    info!("Step 8/8: Starting TProxy in proxy namespace");
    self.start_tproxy()?;

    self.running = true;
    info!("=== dae-rs eBPF Proxy Pipeline Started Successfully ===");
    Ok(())
}
```

### 6.4 cgroup fd 获取

对于 cgroup attach，dae 使用自建 cgroup 或系统 cgroup：

```rust
fn open_cgroup_fd() -> Result<OwnedFd> {
    // 方式1：使用系统 cgroup2 挂载点
    let cgroup_path = "/sys/fs/cgroup";
    if Path::new(cgroup_path).exists() {
        let file = File::open(cgroup_path)?;
        return Ok(OwnedFd::from(file));
    }
    // 方式2：自建 cgroup（需要权限）
    // ...
    Err(anyhow::anyhow!("No cgroup filesystem found"))
}
```

---

## 7. 完整时序图

```
时间
│
│  ControlPlane.start()
│    │
│    ├─ netns_mgr.create()
│    │   ├─ 生成随机 IPv6 地址 ff09::/8 范围
│    │   ├─ unshare(CLONE_NEWNET) ──────────────→ [代理 NS]
│    │   ├─ ip link add ... type netkit/veth
│    │   ├─ ip link set dae0 netns 1 ───────────→ [宿主 NS]
│    │   ├─ ip addr add 169.254.0.11/16 dev dae0peer
│    │   ├─ ip -6 addr add <random>::11/64 dev dae0peer
│    │   ├─ 保存 proxy_ns_fd
│    │   ├─ setns(host_ns_fd) ──────────────────→ [宿主 NS]
│    │   ├─ ip addr add 169.254.0.1/16 dev dae0
│    │   ├─ ip -6 addr add <random>::1/64 dev dae0
│    │   ├─ ip rule add fwmark 0x8000000 table 2023
│    │   └─ ip route add local default dev lo table 2023
│    │                                                            
│    ├─ 构建 Daeparam                                             
│    │   ├─ get_host_ifindex("dae0") → dae0_ifindex              
│    │   ├─ get_peer_mac() → dae0peer_mac                        
│    │   ├─ get_netns_inode(proxy_ns_fd) → dae_netns_id          
│    │   └─ probe_kernel_features()                              
│    │                                                            
│    ├─ setns(proxy_ns_fd) ────────────────────→ [代理 NS]      
│    ├─ ebpf_mgr.load() / set PARAM                              
│    ├─ ebpf_mgr.attach_cgroup(cgroup_fd)                        
│    ├─ ebpf_mgr.attach_dae0peer("dae0peer")                    
│    │                                                            
│    ├─ setns(host_ns_fd) ────────────────────→ [宿主 NS]      
│    ├─ ebpf_mgr.attach_dae0("dae0")                            
│    ├─ for wan_if → ebpf_mgr.attach_wan(wan_if)                
│    ├─ for lan_if → ebpf_mgr.attach_lan(lan_if)                
│    │                                                            
│    ├─ write eBPF maps                                          
│    └─ start_tproxy() ── spawn_thread ── setns(proxy_ns) ──> [代理 NS]
│                                       └─ TproxyListener::start()
│                                                                
│  运行中...                                                      
│                                                                
│  ControlPlane.stop()                                           
│    ├─ tproxy.stop() → wait thread exit                         
│    ├─ setns(host_ns) → ebpf_mgr.detach_all()  [宿主 NS]      
│    ├─ setns(proxy_ns) → ebpf_mgr.detach_all() [代理 NS]      
│    ├─ ebpf_mgr.unload()                                       
│    └─ netns_mgr.destroy()                                      
```

---

## 8. 配置示例（完整 daefile）

```daefile
global {
  tproxy_port: 15080
  log_level: info
}

interface {
  wan_interface: eth0
  lan_interface: eth1 docker0
}

namespace {
  mode: isolated
  host_addr: 169.254.0.1/16
  peer_addr: 169.254.0.11/16
  mtu: 1500
  route_table: 2023
}

mark {
  proxy: 0x8000000
  bypass: 0x04000000
  mask: 0x8000000
}

# ... outbounds, routing, api 等保持不变 ...

# 注意：IPv6 地址（ff09::/8 范围）由 NetnsManager 在
# create() 时自动随机生成，无需在配置文件中指定。
# 生成规则：ff09:<4组随机16位值>::1/64（宿主侧dae0）
#          ff09:<4组随机16位值>::11/64（代理侧dae0peer）
```

---

## 9. 实施步骤

### 9.1 依赖关系图

```
Step 1: 配置解析（Config）
  └── 新增 interface 区块 + wan_interface/lan_interface 字段
       │
Step 2: NetnsManager 重构
  ├── 交换 veth 拓扑（dae0 → 宿主NS, dae0peer → 代理NS）
  ├── IP 地址改为 169.254.0.1/16 和 169.254.0.11/16
  ├── 路由表 ID 改为 2023
  ├── TPROXY_MARK 改为 0x8000000
  ├── netkit 支持（优先尝试，失败回退 veth）
  └── 新增 get_host_ifindex / get_peer_mac / get_peer_ifindex 方法
       │
Step 3: EbpfManager 重构
  ├── attach_tc() 改为通用方法（指定 ifname + 程序列表）
  ├── 新增 attach_wan / attach_lan / attach_dae0 / attach_dae0peer
  ├── 新增 attach_cgroup（cgroup 程序）
  ├── detach_all() 清理所有 hook
  └── Daeparam 完整设置
       │
Step 4: ControlPlane 重构
  ├── start() 流程重写（8 步流程）
  ├── stop() 流程重写（双向 NS 切换）
  ├── 构建完整 Daeparam
  └── NS 切换顺序：代理NS加载 → 宿主NS挂载WAN/LAN
       │
Step 5: 配置示例更新
  ├── config-example/config.daefile 添加 interface 区块
  └── 更新默认配置值
```

### 9.2 详细实施清单

#### Step 1: Config 配置解析

**文件**: [`control/src/config.rs`](../control/src/config.rs)

- [ ] 新增 `InterfaceConfig` 结构体（wan_interface, lan_interface, bind_interface）
- [ ] `DaefileConfig` 新增 `interface: Option<InterfaceConfig>` 字段
- [ ] `ParseState::Interface` 状态处理
- [ ] 解析 `wan_interface: eth0 eth1` 语法
- [ ] 解析 `lan_interface: eth1 docker0` 语法

**文件**: [`control/src/lib.rs`](../control/src/lib.rs)

- [ ] `Config` 结构体新增 `wan_interface: Vec<String>`, `lan_interface: Vec<String>`
- [ ] `Config::from_daefile()` 映射新字段
- [ ] 默认值：`wan_interface: vec![]`, `lan_interface: vec![]`

#### Step 2: NetnsManager 重构

**文件**: [`control/src/netns.rs`](../control/src/netns.rs)

- [ ] 修改常量：
  - `host_addr`: `"169.254.0.1/16"`（原 `"169.254.100.1/30"`）
  - `peer_addr`: `"169.254.0.11/16"`（原 `"169.254.100.2/30"`）
  - `route_table`: `2023`（原 `20230`）
  - `proxy_mark`: `0x8000000`（原 `0x02000000`）
  - `proxy_mask`: `0x8000000`（原 `0x0f000000`）
- [ ] 重写 `create()` 流程：
  - netkit 优先：`ip link add dev dae0 type netkit peer name dae0peer`
  - 失败回退：`ip link add dev dae0 type veth peer name dae0peer`
  - 移动 `dae0`（主端）到宿主 NS：`ip link set dev dae0 netns 1`
  - 在代理 NS 配置 `dae0peer`（`169.254.0.11/16`）
  - 在宿主 NS 配置 `dae0`（`169.254.0.1/16`）
  - 策略路由使用表 2023、TPROXY_MARK `0x8000000`
  - 添加 IPv6 策略路由
- [ ] 新增 `get_host_ifindex()` — 在宿主 NS 调用 `if_nametoindex("dae0")`
- [ ] 新增 `get_peer_mac()` — 进入代理 NS 读取 MAC
- [ ] 新增 `get_peer_ifindex()` — 进入代理 NS 调用 `if_nametoindex("dae0peer")`
- [ ] 新增 `get_proxy_netns_inode()` — 获取代理 NS 的 stat.st_ino
- [ ] 重写 `destroy()` — 先删 `dae0`（在宿主 NS），清理 IPv6 路由规则
- [ ] 新增 `use_netkit` 字段追踪

#### Step 3: EbpfManager 重构

**文件**: [`control/src/ebpf.rs`](../control/src/ebpf.rs)

- [ ] 修改 `TcAttachInfo` 结构体，存储 iface + prog_name 元数据
- [ ] 重写 `attach_tc(ifname, &[(&str, u32)])` — 通用 attach 方法
- [ ] 新增 `attach_wan(ifname)` — 挂载 4 个 wan 程序
- [ ] 新增 `attach_lan(ifname)` — 挂载 4 个 lan 程序
- [ ] 新增 `attach_dae0(ifname)` — 挂载 `tproxy_dae0_ingress`
- [ ] 新增 `attach_dae0peer(ifname)` — 挂载 `tproxy_dae0peer_ingress`
- [ ] 新增 `attach_cgroup(cgroup_fd)` — 挂载 6 个 cgroup 程序
- [ ] 新增 `detach_all()` — 分离所有 TC + cgroup
- [ ] `unload()` 调用 `detach_all()`
- [ ] `Daeparam` 公开所有字段的设置方法

#### Step 4: ControlPlane 重构

**文件**: [`control/src/lib.rs`](../control/src/lib.rs)

- [ ] `ControlPlane::new()` 传递 wan/lan interface 到 ebpf_mgr
- [ ] 重写 `start()` 流程为 8 步流程
- [ ] 新增 `build_daeparam()` 辅助方法
- [ ] 代理 NS 加载 eBPF + attach cgroup + dae0peer
- [ ] 宿主 NS attach WAN/LAN/dae0
- [ ] 重写 `stop()` 流程：先 detach 宿主 NS hook，再 detach 代理 NS hook
- [ ] 更新文档注释

#### Step 5: 配置示例和构建

- [ ] 更新 [`config-example/config.daefile`](../config-example/config.daefile) 添加 interface 区块
- [ ] 更新 [`config-example/config-minimal.daefile`](../config-example/config-minimal.daefile)
- [ ] 确保 Makefile 中 ebpf 编译不受影响
- [ ] 确保 `build.rs` 不受影响

---

## 10. 数据流详解

### 10.1 WAN 出站流量（代理）

```
WAN 出站代理场景（如浏览器访问 google.com:443）：

1. 应用 → eth0 (宿主 NS)
2. TC(tproxy_wan_egress) 拦截:
   ├── parse_packet() → 解析 TCP SYN
   ├── pid_is_control_plane() → 不是 dae 自身
   ├── route() → 匹配 routing rules → outbound=proxy, mark=0x8000000
   └── 决策: 需要代理
3. redirect_to_control_plane_egress():
   ├── bpf_skb_store_bytes: 设置 dmac = dae0peer_mac
   ├── publish_redirect_track() → 保存 ifindex/smac/dmac
   ├── skb->cb[0] = TPROXY_MARK
   ├── skb->cb[1] = IPPROTO_TCP (listener_l4proto)
   └── bpf_redirect(PARAM.dae0_ifindex, 0) → 重定向到 dae0
       │
4. dae0 (宿主 NS) → TC(tproxy_dae0_ingress):
   ├── load_redirect_tuple() → 查找 redirect_track
   ├── 还原原始 smac/dmac
   ├── bpf_skb_change_type(PACKET_HOST/PACKET_OTHERHOST)
   └── bpf_redirect(redirect_entry->ifindex, BPF_F_INGRESS)
       │   ↓ 回退到对端
5. veth/netkit pair → dae0peer (代理 NS)
       │
6. TC(tproxy_dae0peer_ingress):
   ├── skb->cb[0] == TPROXY_MARK? 是
   ├── skb->mark = TPROXY_MARK (0x8000000)
   ├── bpf_skb_change_type(PACKET_HOST)
   └── assign_listener() → bpf_sk_assign → TProxy 监听器
       │
7. 路由查找: fwmark 0x8000000 → table 2023 → local default dev lo
   ↓
8. TProxy 监听器 (127.0.0.1:15080) 接收:
   ├── 目标: google.com:443
   └── SOCKS5 → 上游代理
```

### 10.2 WAN 入站流量（回程）

```
WAN 入站（代理回程流量）：

1. TProxy → dae0peer (代理 NS) → eth0
2. TC(tproxy_wan_ingress):
   ├── parse_packet() → 检测到反向流量
   ├── mark_tcp_seen → 刷新 conntrack（反向 tuple）
   └── TC_ACT_PIPE → 通过
```

### 10.3 LAN 入站流量

```
LAN 入站（如本地应用通过 lo 发起的连接）：

1. 应用 → lo (宿主 NS)
2. TC(tproxy_lan_ingress):
   ├── parse_packet() → 解析 TCP SYN
   ├── socket lookup → 非本地服务（或 TPROXY 重定向）
   ├── route() → 匹配 routing rules
   └── 决策：
       ├── direct → TC_ACT_OK（不做重定向）
       └── proxy → redirect_lan_packet_to_control_plane()
                     → 类似 WAN 的重定向流程
```

---

## 11. 与原始 dae 的逐项对比（修正后）

| 项目 | 原始 dae | dae-rs（修正后） |
|------|----------|----------------|
| 拓扑 | `dae0`→宿主NS, `dae0peer`→代理NS | 一致 |
| IP 地址 | `169.254.0.1/16` + `169.254.0.11/16` | 一致 |
| 路由表 | 2023 | 一致 |
| TPROXY_MARK | `0x8000000` | 一致 |
| PARAM.dae0_ifindex | `dae0` 在宿主 NS 的 ifindex | 一致 |
| PARAM.dae0peer_mac | `dae0peer` 在代理 NS 的 MAC | 一致 |
| PARAM.dae_netns_id | 代理 NS inode | 一致 |
| WAN TC | 物理接口 egress+ingress | 一致 |
| LAN TC | 物理接口 ingress+egress | 一致 |
| dae0 TC | INGRESS on dae0（宿主NS） | 一致 |
| dae0peer TC | INGRESS on dae0peer（代理NS） | 一致 |
| cgroup 程序 | attach 在代理 NS | 一致 |
| netkit | 内核≥6.7 优先使用 | 一致（新增） |
| `use_redirect_peer` | 内核≥6.8 检测 | 一致（新增） |
| Rust 实现优势 | — | 保留（类型安全、内存安全） |

---

## 12. 风险与注意事项

1. **setns 切换的线程安全性**：`setns()` 是线程级别操作。`start()` 中涉及多次 NS 切换，需要确保所有 eBPF 操作在正确的 NS 中执行。建议在 `spawn_blocking` 或专用线程中执行 NS 切换敏感操作。

2. **netkit 回退机制**：`ip link add type netkit` 在旧内核上会返回 `ENOTSUP`，捕获错误后回退 veth。需测试不同内核版本的兼容性。

3. **cgroup 程序 attach 的 fd 生命周期**：`attach_cgroup()` 要求 cgroup fd 在整个程序生命周期内保持打开。需确保 `CgroupFd` 不被提前 drop。

4. **IPv6 策略路由**：原始 dae 同时添加 IPv4 和 IPv6 的策略路由。当前 dae-rs 缺少 IPv6 规则，需补充。

5. **`use_redirect_peer` 的安全影响**：`bpf_redirect_peer()` 绕过了一些 checksum 验证，这依赖于 CVE-2025-37959 的修复内核。需仔细检测内核版本。

6. **多 WAN/LAN 接口**：一个接口可以同时是 WAN 和 LAN（如单臂路由场景），此时需要挂载完整的 WAN+LAN 程序。
