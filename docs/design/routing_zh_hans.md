# 路由子系统设计

> 双语文档。英文版本见 [`routing_en.md`](./routing_en.md)。

## 1. 范围

本文档描述 dae-rs 路由子系统**当前已实现**的实际情况。涵盖规则语言、
用户空间编译管线（`control/src/routing/matcher.rs`）、`bpf/kern/tproxy.c` 中的内核侧
求值，以及让用户空间补全 eBPF 数据通路无法完成决策的"路由交接"
（routing handoff）机制。

本模块对应原 dae 的 `routing_matcher_builder.go` 与 `routing/normalize.go`。

## 2. 规则语言

路由规则形如 `匹配表达式 -> 动作`，自上而下逐条匹配，最后一条为回退：

```
routing {
  dip(10.0.0.0/8) -> direct
  dport(22) -> direct
  dport(443) && l4proto(tcp) -> proxy(proxy_primary)
  fallback: proxy(proxy_primary)
}
```

### 匹配函数

| 函数 | 匹配类型 | 示例 |
|------|----------|------|
| `dip(...)` / `ip(...)` / `target_ip(...)` | 目标 CIDR 集合（LPM 前缀树）；`set:<name>` 引用规则集 | `target_ip(10.0.0.0/8)`、`target_ip(set:chinaip)` |
| `sip(...)` / `source_ip(...)` | 源 CIDR 集合；`set:<name>` 引用规则集 | `source_ip(set:chinaip)`、`source_ip(192.168.0.0/16)` |
| `mac(...)` | 源 MAC 集合（以 IPv6 映射形式存进 LPM 前缀树） | `mac(00:11:22:33:44:55)` |
| `dport(...)` / `port(...)` | 目标端口 / 端口段 | `dport(80,443)`、`port(8000-9000)` |
| `sport(...)` / `source_port(...)` | 源端口 / 端口段 | `sport(1024-65535)` |
| `l4proto(tcp,udp)` | 四层协议位掩码 | `l4proto(tcp)` |
| `ipversion(4,6)` | IP 版本位掩码 | `ipversion(4)` |
| `domain(suffix:..., keyword:..., full:..., regex:...)` / `target_domain(...)` | 域名集合；`set:<name>` 引用规则集 | `target_domain(suffix:example.com)`、`target_domain(set:chinadomain)` |
| `process_name(...)` / `pname(...)` | 进程 comm 名（≤16 字节） | `process_name(qbittorrent)` |
| `dscp(...)` | DSCP 值 | `dscp(10)` |


- 函数之间用 `&&` 求 AND（按括号感知拆分）。
- 函数可用 `!` 取反：`!domain(suffix:google.com)`。
- 函数内多个逗号分隔的值按 OR 处理；参数可带 `key:value` 前缀（`suffix:`、
  `keyword:`、`full:`、`regex:`、`set:`），同 key 的参数构成一个 OR 组。

### 规则集引用（数据面）

`source_ip` / `target_ip` / `target_domain` 支持引用 `rule_set` 区块配置的
规则集（完整设计见 [`rule_set_zh_hans.md`](./rule_set_zh_hans.md)）：

- `source_ip(set:chinaip)` / `target_ip(set:chinaip)` — 命中 `ip_list` 条目；
- `target_domain(set:chinadomain)` — 命中 `domain_list` 条目。

归一化：`sip`→`source_ip`、`dip`/`ip`→`target_ip`，旧别名保持兼容。
引用数据缺失时编译报错（E2103）。

### 动作

- `direct` — 直接出站（outbound ID `OUTBOUND_DIRECT`）。
- `block` — 丢弃（outbound ID `OUTBOUND_BLOCK`）。
- `proxy(<group>)` — 经分组走代理。
- `proxy(<group>, mark=0x..., must)` — 携带 fwmark 覆盖和/或 `must`（强制）
  标志的代理。
- `control_plane_routing` — 交给用户空间（特殊 outbound ID，见 §6）。

## 3. 编译管线

`control/src/routing/matcher.rs` 中的
`compile_rules(routing, outbounds, proxy_server_ips)`：

```
daefile 路由配置
   │
   ▼
1. NormalizedProgram::from_config()      # IR：由 AND 分隔的 Function 组成的规则
   │
2. build_outbound_id_map(outbounds)      # 分组/节点名 → eBPF outbound ID
   │
3. 收集 domain_sets（第一遍）              # 每条域名规则的域名模式
   │
4. 把规则降级为 MatchSet 条目             # 经函数解析器；内联创建 LPM 前缀树
   │                                      # 并按 FNV-1a 去重
5. 前置"代理服务器 IP 自动直连"规则        # dip(proxy_ip) -> direct
   │
6. 追加回退 MatchSet（必须位于末尾）
   │
▼
CompiledRouting { match_sets, lpm_tries, domain_sets, fallback_* }
```

### 中间表示

- `Function { name, not, raw_params }` — 单个已解析的函数，参数保留原始
  字符串（`key:value` 提取由各解析器完成）。
- `Outbound { name, mark, must }` — 已解析的动作。
- `NormalizedRule { and_functions: Vec<Function>, outbound: Outbound }`。
- `NormalizedProgram { rules, fallback }` — 共享 IR。

### 降级为 MatchSet

每个函数调用生成一个或多个 `MatchSet` 条目（定义在 `control/src/net/ebpf.rs`，
与 `tproxy.c` 同步）。每个 MatchSet 携带：

- `type` — `IP_SET`、`SOURCE_IP_SET`、`MAC`、`PORT`、`SOURCE_PORT`、
  `L4_PROTO`、`IP_VERSION`、`DOMAIN_SET`、`PROCESS_NAME`、`DSCP`、`QTYPE`、
  `UPSTREAM`、`FALLBACK` 之一。
- `not` — 匹配是否取反。
- `outbound` — 出站 ID，或逻辑标记。
- `mark` / `must` — fwmark 覆盖 / 强制标志。
- `value` — LPM 前缀树索引、端口区间、位掩码或内联 16 字节名称。

**逻辑链**：一条规则内的条目构成链。除最后一条外，规则内的条目使用由
`compute_override_outbound()` 计算的特殊 outbound ID `LOGICAL_OR` /
`LOGICAL_AND`：函数内各 key 组之间 OR，AND 分隔的函数之间 AND，末条携带
真实 outbound ID。eBPF `route()` 遍历器（以及与之镜像的用户空间
`RoutingMatcher`）据此求值 `A && B`、`A || B` 与 `!A`。

**LPM 前缀树**：CIDR 值经 `find_or_create_lpm_trie()` 收集进前缀树
（按 FNV-1a 哈希去重，与原始 dae 一致）。`IP_SET` / `SOURCE_IP_SET` / `MAC`
类型的 MatchSet 按索引引用前缀树。IPv4 地址以 IPv4-mapped IPv6 形式存储
（前缀 96+len）。规则集引用 `source_ip(set:chinaip)` 在 `parse_cidr_values()`
中解析为 `Vec<IpNet>`，经同一函数汇入前缀树（§9）。

**域名集合**：`domain(...)` / `target_domain(...)` 值累积进 `domain_sets`，
MatchSet 按索引引用。规则集引用 `target_domain(set:chinadomain)` 查内存缓存，
把 Domain 列表经 `domain_pattern_to_string()` 映射为带 key 前缀的模式条目
（`suffix:`/`full:`/`regex:`/`domain:`/`keyword:`）后进入同一 `domain_sets`。

**代理服务器自动直连**：所有已配置的代理服务器 IP 会收集进专属 LPM 前缀树，
并前置一条 `dip(proxy_server_ip) -> direct` 规则，防止发往代理服务器的流量
被再次代理（防循环）。

**回退**：编译后的回退动作以 `FALLBACK` 类型作为最后一条追加。

## 4. 内核侧求值（`bpf/kern/tproxy.c`）

eBPF TC 程序在 `wan_egress` / `wan_ingress` / `lan_ingress` /
`dae0_ingress` / `dae0peer_ingress` 挂载，拦截流量并执行路由逻辑：

- `routing_map` 是 `MatchSet` 条目的 `BPF_MAP_TYPE_ARRAY`，采用**双缓冲**的
  两个 epoch 槽（`ROUTING_EPOCH_SLOT_NUM = 2`），从而支持无撕裂的热重载。
  每条 conn_state 记录记录用的是哪个槽（移入结果，
  见 `ROUTING_EPOCH_SLOT_RESULT_SHIFT`）。
- LPM 前缀树位于 array-of-maps（`lpm_array_map`）中，按 MatchSet 中的
  前缀树 id 索引。
- `route()` 函数用 `bpf_loop()` 遍历 MatchSet 链，应用
  `LOGICAL_OR` / `LOGICAL_AND` / `NOT` 语义。
- 出站 ID：`OUTBOUND_DIRECT (0x0)`、`OUTBOUND_BLOCK (0x1)`、
  `OUTBOUND_MUST_RULES (0xFC)`、`OUTBOUND_CONTROL_PLANE_ROUTING (0xFD)`、
  `LOGICAL_OR` / `LOGICAL_AND`（掩码 `LOGICAL_MASK = 0xFE`）。
- `outbound_connectivity_map` 跟踪每个出站的存活状态；决策前会查询
  `wan_outbound_is_alive()`。
- 决策后，流量要么直接交付（经 `bpf_sk_assign` / 直接重定向），要么打上
  `TPROXY_MARK`（`0x8000000`）进入策略路由送往代理命名空间的 TProxy
  监听器，要么交给用户空间（见 §6）。

## 5. 用户空间 RoutingMatcher

`RoutingMatcher`（`control/src/routing/matcher.rs`）是 eBPF 求值器的用户空间镜像，
由同一份 `CompiledRouting` 数据构建。`match_routing(params)` 以相同方式遍历
MatchSet 链，返回 `RoutingResult { outbound, mark, must }`。它会对 LPM 前缀树
求 `dip`/`sip`、对 `domain_sets` 求 `domain`、端口、四层协议、IP 版本、
进程名、DSCP 等。

`choose_dial_target(routing, ctx)` 是对应 dae `ChooseDialTarget()` 的入口，
由路由交接消费者使用。

## 6. 路由交接（用户空间补全 eBPF 决策）

有些决策无法在内核完成（如域名规则匹配）。设计如下：

1. eBPF 路由无法决策时，MatchSet 链以 `OUTBOUND_CONTROL_PLANE_ROUTING (0xFD)`
   收尾。
2. 报文/连接记录进 `routing_handoff_map`（`MAX_ROUTING_HANDOFF_NUM` 条）。
3. **路由交接消费者**（`control/src/routing/routing_handoff.rs`）排空该 map，重建
   连接参数，调用 `choose_dial_target()` 对照用户空间 `RoutingMatcher` 决策，
   并把最终决策写入 `conn_state_map`。
4. 数据通路后续报文按连接五元组读取 `conn_state_map`。每条记录带路由 epoch
   槽与 `datapath_generation` 计数器，配置重载后旧条目即失效。

配套机制：

- `conn_state_map`（上限 `MAX_CONN_STATE_NUM = 65536 * 4`），带一个 janitor
  清理过期/失效连接并检测 map 压力。
- `redirect_track_map` 与 `cookie_pid_map` 的 janitor 保持重定向与
  控制面 socket cookie 跟踪规模有界。
- `current_epoch_slot`（0/1）每次重载交替；重载写入非活动槽后翻转
  `active_routing_epoch`。

## 7. 当前限制

- 分组/节点 outbound ID 目前映射到 `OUTBOUND_CONTROL_PLANE_ROUTING`，
  即走代理分组的决策由用户空间补全。
- `MAC` 匹配只在内核中有意义（用户空间无对应物）；用户空间匹配器对其
  返回 `false`。
- 仅支持 `&&` 组合；OR 逻辑通过函数内列多个值或多条规则表达。

## 8. 规则集容量约束（要点，见 [`rule_set_zh_hans.md`](./rule_set_zh_hans.md) §9）

规则集数据接入 eBPF 后受既有容量限制约束，编译期检测超限并报错（E2106）：

| 资源 | 上限 | 约束说明 |
|------|------|----------|
| MatchSet 条目总数（每 epoch 槽） | `MAX_MATCH_SET_LEN = 1024` | 含逻辑链与 fallback；规则集函数与既有函数共用此池 |
| LPM trie 数（用户空间编译期） | `MAX_LPM_NUM = 1032` | [`matcher.rs`](../config/../../control/src/routing/matcher.rs:30) |
| LPM trie 外层数组（eBPF 双缓冲） | `2 * 1024 + 8 = 2056` | `bpf/kern/tproxy.c` |
| 单个 LPM trie 内部条目 | `MAX_LPM_SIZE = 2_048_000` | 单 trie 可容纳约 200 万 CIDR |
| domain_routing_map 位图 | 32 个 u32（=1024 bit） | **域名集规则索引上限 1024**（每个 set 域名引用占 1 bit） |

- **瓶颈在 MatchSet 总数与域名集索引数（规则数量）**。
- 超限时**拒绝编译并报错**（E2106），提示精简规则 / 合并引用；采样截断等
  降级策略为阶段 5 可选（默认关闭）。
