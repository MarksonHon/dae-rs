# 规则集（Rule Set）支持 — 设计文档

> 双语文档。英文版本见 [`rule_set_en.md`](./rule_set_en.md)（已建）。
>
> **状态**：已实现（阶段 0-3 完成；阶段 4「示例与文档」为本文档的配套子任务）。
>
> **范围**：本设计为 dae-rs 的"规则集支持"子任务提供完整方案，覆盖数据格式、
> 存储/下载/更新生命周期、配置扩展、调度、路由引用语法、eBPF 集成、自由组合
> 语义、错误处理与实施阶段划分。阶段 0-3（数据层、配置与调度、语法/matcher/
> DNS 集成）已实现；阶段 4 更新示例配置与文档（见 §12）。

## 摘要（Abstract）

本设计为 dae-rs 引入完整的 GeoSite/GeoIP（v2ray `.dat`）与文本域名/IP 列表的
规则集支持：

- **数据格式**：原生解析 v2ray protobuf `.dat`（对齐 Loyalsoldier/v2ray-rules-dat
  的 geoip.dat / geosite.dat），以及"每行一条"的纯文本域名/IP 列表。
- **统一存储与生命周期**：全部数据文件存放于 `/var/dae-rs/`，由 dae-rs 自行下载、
  校验、原子替换与损坏恢复；本地缺失时默认通过**第一个代理组**下载。
- **配置扩展**：在 `config.daefile` 与 `config.json` 中新增规则集管理区块，每类
  文件均有**唯一名称/备注**，可配置 URL、更新时间段（`time: HH:MM` /
  `period: 3h2m`，不精确到秒）与启动无条件更新开关。
- **引用语法**：`source_ip(set:chinaip)` / `target_ip(geoip:cn)` /
  `target_domain(geosite:cn)` 等，并保留/映射现有 `dip()`/`sip()`/`domain()`/
  `qname()` 等语法。
- **自由组合**：完整复刻原版 dae 的规则组合语义（AND/OR/NOT/多条件单 action/
  顺序匹配/fallback/`any`）。
- **eBPF 集成**：数据编译进 LPM 前缀树与 `domain_routing_map` 位图，明确容量约束
  与超限时的拒绝/降级策略。

## 1. 背景与现状（Background & Current State）

### 1.1 问题综述（专项审查结论）

阶段 0-3 已实现前的原始缺陷如下（均已修复）：

| # | 位置 | 缺陷 |
|---|------|------|
| 1 | [`matcher.rs`](control/src/routing/matcher.rs:964) `parse_cidr_values()` | 仅 `geoip:private` 被硬编码展开为 4 个 RFC1918/回环网段，其余 `geoip:xx` 无法解析 |
| 2 | [`matcher.rs`](control/src/routing/matcher.rs:1626) `build_match_set_for_function()` | `geoip:cn` 等解析失败被**静默丢弃**（`if let Ok(cidrs)` 分支不命中则无任何 MatchSet 生成） |
| 3 | [`matcher.rs`](control/src/routing/matcher.rs:1242) 域名收集 | `domain(geosite:cn)` 被当作普通后缀域名模式 `cn` 处理 → 退化为"以 .cn 结尾"匹配 |
| 4 | [`router.rs`](control/src/dns/router.rs:270) `compile_route_rule()` | DNS 查询路由 `qname(geosite:cn)` 被编译为普通后缀字符串 `geosite:cn`，恒不匹配 |
| 5 | [`handler.rs`](control/src/dns/handler.rs:585) `evaluate_response_condition()` | DNS 响应路由 `ip(geoip:...)` 未实现，条件恒为 `true` |
| 6 | 全局 | 无数据文件加载/解析/更新机制，无数据源配置项 |

### 1.2 现有架构要点（设计约束）

- **数据面匹配**经 [`compile_rules()`](control/src/routing/matcher.rs:1172) 编译进 eBPF：
  - IP 走 LPM 前缀树（`MatchType_IpSet` / `MatchType_SourceIpSet`），LPM trie 由
    [`find_or_create_lpm_trie()`](control/src/routing/matcher.rs:1045) 管理（FNV-1a 去重）。
  - 域名经 `domain_sets`（每条域名规则一个 `Vec<String>` 模式集）→ eBPF
    `domain_routing_map`（IP → 位图），由 [`domain_routing.rs`](control/src/routing/domain_routing.rs)
    在 DNS 解析结果到达时写入位图，eBPF 侧 [`tproxy.c`](bpf/kern/tproxy.c:1398)
    `route_match_domain_set()` 查询。
  - 容量约束：`MAX_MATCH_SET_LEN = 1024`（[`matcher.rs`](control/src/routing/matcher.rs:27)）；
    `MAX_LPM_NUM = MAX_MATCH_SET_LEN + 8 = 1032`（用户空间编译期 trie 数上限）；
    eBPF 侧 `lpm_array_map` 外层数组 = `ROUTING_EPOCH_SLOT_NUM * MAX_MATCH_SET_LEN + 8`
    （双缓冲 2×1024+8 = 2056）；单个 LPM trie 内部 `MAX_LPM_SIZE = 2_048_000` 条；
    `domain_routing_map` 位图固定 `MAX_MATCH_SET_LEN / 32 = 32` 个 u32（即域名集
    规则索引上限 1024）。
- **DNS 路由**（[`router.rs`](control/src/dns/router.rs)）与 **DNS 响应路由**
  （[`handler.rs`](control/src/dns/handler.rs:564)）有各自独立的规则编译/求值路径，
  目前均为简单后缀/类型匹配，需接入规则集数据。
- **配置解析**在 [`parser.rs`](control/src/config/parser.rs)（行缩进状态机）、
  校验在 [`validator.rs`](control/src/config/validator.rs)、结构定义在
  [`mod.rs`](control/src/config/mod.rs)。
- 主事件循环在 [`src/lib.rs`](src/lib.rs) `run()`，用 `tokio::select!` 等待
  SIGINT/SIGTERM/SIGHUP；`ControlPlane` 在 [`lib.rs`](control/src/lib.rs)。
- 现有依赖（[`control/Cargo.toml`](control/Cargo.toml)）：tokio(full)、serde、
  serde_json、base64、ipnet、regex、chrono 等；**暂无** HTTP 客户端（reqwest/ureq）
  与 protobuf（prost/protobuf）依赖，实施阶段需新增。

## 2. 调研结果（Research Findings）

### 2.1 原版 dae 的规则集与规则组合能力

> 调研来源：dae 官方仓库 https://github.com/daeuniverse/dae 的文档与代码
> （`docs/en/configuration/routing.md`、`routing/` 源码、`consts`）。

**规则集（GeoSite/GeoIP）**：

- dae 原生支持 `geosite:` 与 `geoip:` 前缀引用，如 `domain(geosite:cn)`、
  `dip(geoip:cn)`、`dip(geoip:private)`。数据文件为 v2ray `.dat`。
- dae 通过配置项（`global` 内的 `geoip_dat_url` / `geosite_dat_url` 等）或命令行
  指定数据源下载地址，并支持定时更新。
- dae 的匹配函数（`routing.md`）：
  - `domain(...)`（含 `geosite:` 前缀、`suffix:`/`keyword:`/`full:`/`regex:` 前缀）
  - `dip(...)` / `sip(...)`（含 `geoip:` 前缀）
  - `dport` / `sport` / `l4proto` / `ipversion` / `mac` / `pname` / `process_name` /
    `dscp` / `qtype` / `utc_time` 等。

**规则组合语义（关键设计依据）**：

dae 的规则语言是"一条规则 = 一组匹配条件 + 一个动作"：

1. **多条件 AND**：一条规则内的多个匹配条件用 `&&` 组合，全部命中才执行动作。
   例如 `dport(443) && domain(geosite:cn) -> direct`。
2. **条件内 OR**：单个函数内的多个参数用逗号分隔，命中任意一个即算该条件命中。
   例如 `dport(80,443)`。
3. **NOT 取反**：条件前加 `!` 表示取反，如 `!domain(geosite:cn)`。
4. **顺序匹配 + fallback**：规则自上而下逐条求值，**第一条完全命中**的规则生效；
   全部未命中则用 `fallback`。
5. **`any` 通配**：`any -> 动作` 匹配所有流量。
6. **动作**：`direct` / `block` / `proxy(<group>)` 等，多条规则可指向不同动作。
7. **"自由组合"**：dae 允许在同一规则中自由混用任意数量的不同函数（IP、域名、
   端口、协议等）做 AND 组合，不受函数类型限制——这是本设计必须复刻的能力。

> 对齐/差异说明：dae-rs 的 [`matcher.rs`](control/src/routing/matcher.rs:104)
> 已实现 `LOGICAL_OR` / `LOGICAL_AND` / NOT 链（`compute_override_outbound()`），
> 与 dae 的 `RoutingMatcherBuilder` 语义一致。本设计**保留该机制**，仅扩展其
> 数据来源（规则集）。差异点：dae-rs 将函数名统一为 `source_ip` / `target_ip` /
> `target_domain` 的新语法，并保留旧别名（详见 §6）。

### 2.2 v2ray `.dat` protobuf 确切结构

> 依据：v2ray-core `app/router/config.proto` 与 Loyalsoldier/v2ray-rules-dat 仓库
> （https://github.com/Loyalsoldier/v2ray-rules-dat）生成的 geoip.dat / geosite.dat。

`.dat` 文件是**未压缩**的 protobuf 序列化（无 gzip、无封装头），可直接用 protobuf
解码。

#### geoip.dat — 顶层 `GeoIPList`

```proto
// 参考 v2ray-core app/router/config.proto
message CIDR {
  bytes ip = 1;        // 4（IPv4）或 16（IPv6）字节
  uint32 prefix = 2;   // 前缀长度
}

message GeoIP {
  string country_code = 1;   // 例如 "CN"、"PRIVATE"、"LAN"、"CLOUDFLARE"
  repeated CIDR cidr = 2;
  bool reverse_match = 3;    // 通常为 false
}

message GeoIPList {
  repeated GeoIP entry = 1;
}
```

- Loyalsoldier 的 geoip.dat 中 `entry` 按 `country_code` 分组（大写），如
  `CN`、`PRIVATE`、`LAN`、`GOOGLE` 等。匹配时 `geoip:cn` 对 `country_code`
  做**大小写不敏感**比较。
- `geoip:private` 对应 `country_code == "private"` 的 entry，包含 RFC1918、
  回环、链路本地等网段——比当前硬编码的 4 个网段更完整，应优先用数据。

#### geosite.dat — 顶层 `GeoSiteList`

```proto
// 参考 v2ray-core app/router/config.proto
enum DomainType {
  Plain = 0;    // 匹配域名及其子域（后缀匹配，含自身）
  Regex = 1;    // 正则匹配
  Domain = 2;   // 匹配子域（不含自身？——见 v2ray 匹配语义）
  Full = 3;     // 精确匹配（含域名本身）
}

message Domain {
  DomainType type = 1;
  string value = 2;             // 如 "baidu.com"、"google.com"
  repeated Attribute attribute = 3; // 属性（分类），见下
}

message Attribute {
  string key = 1;               // 如 "cn"、"ads"
  // value 的语义在不同版本略有差异；常见为 bool / string
}

message GeoSite {
  string country_code = 1;      // 如 "cn"、"geolocation-!cn"、"category-ads-all"
  repeated Domain domain = 2;
}

message GeoSiteList {
  repeated GeoSite entry = 1;
}
```

- geosite 的 `country_code` 是分类名（小写），如 `cn`、`geolocation-!cn`、
  `category-ads-all`、`google`、`youtube` 等（v2fly/domain-list-community 及
  Loyalsoldier 生成规则）。
- **Domain.type 匹配语义**（对齐 v2ray 的 `domain_matcher` / geosite 加载逻辑）：
  - `Plain`：`value` 命中自身及其所有子域（后缀匹配，含根域本身）。
  - `Domain`：命中 value 的子域（**不含** value 自身）——与 `Plain` 的区别在于
    是否含自身。实现时以 v2ray `domain_matcher` 为准（`strings.HasSuffix` 语义）。
  - `Full`：精确匹配 `value` 本身。
  - `Regex`：`value` 作为正则表达式匹配完整域名。
- **attributes（属性分类）**：geosite.dat 中每个 `Domain` 可携带 attribute，
  用于二级分类（如 `geosite:cn@ads`）。本设计 v0.1 **仅支持按一级 `country_code`
  分组匹配**，`@attribute` 二级分类列为后续扩展（§12 阶段 5 可选）。

### 2.3 文本列表格式约定

- **域名列表**（如 `chinaip-domain.txt`）：每行一条域名或域名模式，支持
  `full:` / `domain:` / `suffix:` / `keyword:` / `regex:` 前缀（对齐 dae 的
  domain key），无前缀默认按 `Plain`（后缀，含自身）语义处理。
- **IP 列表**（如 `chinaip.txt`）：每行一条 CIDR（`a.b.c.d/nn`）或裸 IP（按 /32
  或 /128 处理），`#` 开头为注释，空行忽略。

## 3. 格式定义（Formats）

见 §2.2 / §2.3。本设计**原生解析 protobuf**，不依赖外部工具链，并内置对 v2ray
`GeoIPList` / `GeoSiteList` 的完整解码（通过 prost 生成或手写轻量解码器）。

## 4. 存储与生命周期（Storage & Lifecycle）

### 4.1 目录布局：`/var/dae-rs/`

```
/var/dae-rs/
├── geoip.dat                  # 实际数据文件（dat 类型，文件名=配置 name + .dat）
├── geosite.dat
├── chinaip.txt                # 文本列表（域名/IP），文件名=配置 name + .txt
├── chinadomain.txt
├── .tmp/                      # 临时下载文件（未校验前）
│   └── <name>.tmp.<rand>
├── .checksum/                 # 校验和文件
│   ├── geoip.dat.sha256
│   └── chinaip.txt.sha256
└── .meta/                     # 元数据/版本/状态
    └── <name>.json            # { url, type, last_updated, etag?, sha256, size, state }
```

- 数据文件与元数据分离：`.tmp/`、`.checksum/`、`.meta/` 为**隐藏目录**，仅
  dae-rs 读写。
- **命名空间隔离**：文件名 = `<唯一 name>` + 类型后缀（dat 为 `.dat`，文本为
  `.txt`）。name 由配置指定（§5），用于路由引用（`set:<name>`）与文件定位。
- 启动时若 `/var/dae-rs/` 不存在则创建（需 root；dae-rs 以 root/特权运行）。
- 数据文件路径可在未来通过 CLI/配置覆盖（默认 `/var/dae-rs/`）。

### 4.2 下载管理

- **触发源**：
  1. 启动更新（`update_on_start: true`，§5）；
  2. 调度器到点（§5.3）；
  3. 编译/引用时发现本地文件缺失（兜底，见 §4.4）。
- **下载通道（通过代理）**：本地文件缺失时，若需代理，使用**第一个代理组**
  （`outbounds.groups[0]`）的当前选中节点（或该组第一个存活节点）作为 SOCKS5
  代理发起 HTTP(S) 下载。实现：HTTP 客户端（reqwest/ureq）配置 socks5 代理，
  或复用 `Socks5Dialer` 建连后做 CONNECT 隧道。
  - 规则集条目可显式指定 `proxy: <group>` 覆盖；未指定则默认第一个代理组。
  - 若第一个代理组为空/不可用，回退为直连下载（并记录告警）。
- **下载重试**：指数退避重试（默认 3 次，间隔 2s/4s/8s），单次超时 30s；重试
  期间不阻塞主循环（在独立 tokio 任务中执行）。
- **ETag / Last-Modified**：服务端支持时携带上次 ETag/时间做条件请求，返回 304
  则视为无需更新。

### 4.3 校验、原子替换与损坏处理

1. **临时下载**：先写入 `.tmp/<name>.tmp.<rand>`，全程记录已下载字节数。
2. **校验和校验**：下载完成后：
   - 若配置/URL 提供期望 sha256（`url#sha256=...` 或 meta 中记录），强制校验；
   - 否则计算 sha256 并与 `.checksum/` 中上次记录对比；若相同且服务端未变更
     （304/ETag 命中）可跳过替换。
   - 校验失败 → 删除临时文件，记录错误日志，**保留旧文件继续使用**，进入重试
     或等待下次调度；连续失败次数超过阈值（默认 5 次）后该规则集标记为
     `degraded`，仅告警不无限重试。
3. **解析校验**：对 dat 用 protobuf 解码、对文本逐行解析，解析失败同样判为损坏。
4. **原子替换**：校验通过后 `rename()` 临时文件 → 正式文件（同目录内 rename
   保证原子性），再更新 `.meta/<name>.json` 与 `.checksum/<name>.sha256`。
5. **损坏恢复**：若正式文件在**启动时**发现解析失败（上次退出异常），删除损坏
   文件并触发重新下载；下载仍失败则跳过该规则集并告警（不影响其它规则集）。
6. **并发安全**：下载/替换/读取互斥（`tokio::sync::Mutex` 或按文件锁）；读取
   侧（matcher 编译）始终读**内存缓存**而非磁盘文件，更新完成后重建内存缓存并
   触发路由热重载。

### 4.4 内存缓存与热重载联动

- 加载后的规则集解析为**内存数据结构**：
  - `geoip`：`country_code → Vec<IpNet>`；
  - `geosite`：`country_code → Vec<DomainPattern>`（保留 type：suffix/regex/full/domain）；
  - 文本列表：直接为 `Vec<IpNet>` 或 `Vec<DomainPattern>`。
- 更新完成后，通过现有 eBPF 双缓冲 epoch 机制重新执行
  [`compile_rules()`](control/src/routing/matcher.rs:1172) 与 DNS 路由重编译，
  原子切换（对齐现有热重载）。

## 5. 配置格式（Configuration）

### 5.1 新增顶层区块：`rule_set`

在 `DaefileConfig`（[`mod.rs`](control/src/config/mod.rs:462)）中新增
`rule_set` 字段；parser（[`parser.rs`](control/src/config/parser.rs)）新增
`ParseState::RuleSet` 状态。

#### daefile 完整示例

```
rule_set {
  # ── dat 类型（geoip）──
  geoip_main {
    type: geoip                  # dat 数据：geoip
    url: 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat'
    name: geoip_main             # 唯一备注/名称（可选，缺省用块名）
    update: time: 21:47          # 每天 21:47 更新
    update_on_start: true        # 启动时无条件更新一次
  }

  # ── dat 类型（geosite）──
  geosite_main {
    type: geosite                # dat 数据：geosite
    url: 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat'
    name: geosite_main
    update: period: 3h2m         # 每 3 小时 2 分钟更新一次
  }

  # ── 文本域名列表 ──
  chinadomain {
    type: domain_list
    url: 'https://example.com/rules/chinadomain.txt'
    name: chinadomain
    update: time: 04:30
    update_on_start: false
  }

  # ── 文本 IP 列表 ──
  chinaip {
    type: ip_list
    url: 'https://example.com/rules/chinaip.txt'
    name: chinaip
    update: period: 1d
    proxy: proxy_primary         # 显式指定下载用代理组（可选，默认第一个代理组）
  }
}
```

#### config.json 完整示例

```json
{
  "rule_set": {
    "geoip_main": {
      "type": "geoip",
      "url": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
      "name": "geoip_main",
      "update": { "time": "21:47" },
      "update_on_start": true
    },
    "geosite_main": {
      "type": "geosite",
      "url": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
      "name": "geosite_main",
      "update": { "period": "3h2m" }
    },
    "chinadomain": {
      "type": "domain_list",
      "url": "https://example.com/rules/chinadomain.txt",
      "name": "chinadomain",
      "update": { "time": "04:30" },
      "update_on_start": false
    },
    "chinaip": {
      "type": "ip_list",
      "url": "https://example.com/rules/chinaip.txt",
      "name": "chinaip",
      "update": { "period": "1d" },
      "proxy": "proxy_primary"
    }
  }
}
```

> `update` 字段为互斥二选一：`time: HH:MM` 或 `period: 3h2m`（详见 §5.4）。

### 5.2 字段定义

| 字段 | 必填 | 类型 | 说明 |
|------|------|------|------|
| `type` | 是 | enum | `geoip`（dat）、`geosite`（dat）、`domain_list`（文本域名）、`ip_list`（文本 IP） |
| `url` | 是 | string | 下载地址（http/https）；可带 `#sha256=...` 片段强制校验 |
| `name` | 否（缺省=块名） | string | **唯一备注/名称**，用于 `set:<name>` 引用与文件命名 |
| `update` | 是 | `{time}` / `{period}` | 更新时间段（互斥） |
| `update_on_start` | 否 | bool | 启动时无条件更新一次（默认 false） |
| `proxy` | 否 | string | 指定下载用代理组；缺省用**第一个代理组** |

### 5.3 唯一备注约束与校验

- **唯一性**：`rule_set` 内所有条目的 `name`（含缺省=块名）全局唯一，且不得与
  其它类型引用冲突。违反 → `ConfigError`（新增 E2101 `DuplicateRuleSet`）。
- **命名约束**：`name` 仅允许 `[a-zA-Z0-9_-]`（避免路径穿越与引用歧义），长度
  ≤ 63。
- **引用完整性（validator）**：
  - 路由规则中 `set:<name>`（§6）必须命中 `rule_set` 中某 `domain_list` /
    `ip_list` 条目的 name；`geoip:<code>` / `geosite:<code>` 必须命中已配置 dat
    类型条目（**运行时**按 dat 内 country_code 校验，静态阶段仅校验至少有一个
    geoip/geosite 条目）。
  - 未知引用 → `ConfigError`（新增 E2102 `UnknownRuleSetRef`）。
- **URL 校验**：必须以 `http://` / `https://` 开头；`#sha256=` 片段为 64 位十六进制。

### 5.4 更新时间段语义（不精确到秒）

- **`time: HH:MM`**：每天本地时区的 `HH:MM`（00-23:00-59）触发一次；**无秒字段**。
- **`period: 3h2m`**：周期触发，单位支持 `d`（天）/`h`（小时）/`m`（分钟），
  可组合（如 `1d12h30m`），**最小单位为分钟，禁止秒**；周期从"上次成功更新"
  或"上次触发"起算（见 §5.5 语义决策）。
- **启动更新**：`update_on_start: true` 时，进程启动后立即无条件下载一次（即使
  本地已有文件），并重置调度基准。

### 5.5 调度语义（决策）

- `period` 的基准：以**上次成功更新时刻**为基准（失败不消耗周期），与 dae /
  mihomo 惯例一致。
- `time` 的基准：每天固定时刻；若进程在设定时刻之后才启动，则顺延到次日该时刻。
- 多个规则集各自独立调度，由**单一调度器**聚合（§7）。

## 6. 引用语法与解析（Reference Syntax & Parsing）

### 6.1 新语法

| 形式 | 含义 | 数据来源 |
|------|------|----------|
| `source_ip(set:chinaip)` | 源 IP 命中文本 IP 列表 `chinaip` | `ip_list` 条目 |
| `source_ip(geoip:cn)` | 源 IP 命中 geoip dat 的 `cn` | geoip dat 条目 |
| `target_ip(set:chinaip)` | 目标 IP 命中文本 IP 列表 | `ip_list` 条目 |
| `target_ip(geoip:cn)` | 目标 IP 命中 geoip dat 的 `cn` | geoip dat 条目 |
| `target_domain(set:chinadomain)` | 目标域名命中文本域名列表 | `domain_list` 条目 |
| `target_domain(geosite:cn)` | 目标域名命中 geosite dat 的 `cn` | geosite dat 条目 |
| `source_ip(geoip:private)` | 源 IP 命中私有网段（数据驱动） | geoip dat `private` |

### 6.2 与现有语法的映射 / 弃用方案

| 现有语法 | 新语法（推荐） | 处理 |
|----------|----------------|------|
| `sip(...)` | `source_ip(...)` | 保留为别名，内部归一化 |
| `dip(...)` / `ip(...)` | `target_ip(...)` | 保留为别名，内部归一化 |
| `domain(geosite:cn)` | `target_domain(geosite:cn)` | 保留 `domain(...)` 兼容；内部识别 `geosite:` 前缀 |
| `domain(suffix:.../keyword:/full:/regex:)` | 同（保留） | 普通域名模式，与规则集并存 |
| `dip(geoip:private)` | `target_ip(geoip:private)` | 数据驱动替换硬编码展开 |
| DNS `qname(geosite:cn)` | DNS 侧 `qname(geosite:cn)`（保留） | 接入 geosite 数据匹配（§6.4） |
| DNS 响应 `ip(geoip:cn)` | 同（保留） | 接入 geoip 数据匹配（§6.5） |

**归一化策略**：在 [`NormalizedProgram::from_config()`](control/src/routing/matcher.rs:253)
解析阶段，将 `sip`→`source_ip`、`dip`/`ip`→`target_ip`、`domain(geosite:*)`→
`target_domain(geosite:*)`，并识别 `set:`/`geoip:`/`geosite:` 前缀，统一进入
`Function { name, params }` IR。`domain(...)`（非 geosite 前缀）继续作为普通域名
函数。

### 6.3 数据面（matcher / `compile_rules()`）求值语义

- **`source_ip(geoip:cn)` / `target_ip(geoip:cn)`**：在 [`parse_cidr_values()`](control/src/routing/matcher.rs:960)
  中识别 `geoip:<code>` 前缀 → 查内存 geosite/geoip 缓存得到 `Vec<IpNet>` → 经
  [`find_or_create_lpm_trie()`](control/src/routing/matcher.rs:1045) 生成 LPM trie →
  生成 `MatchType_SourceIpSet` / `MatchType_IpSet` MatchSet（value.index = trie 索引）。
- **`source_ip(set:chinaip)` / `target_ip(set:chinaip)`**：同样解析为 CIDR 集合。
- **`target_domain(geosite:cn)`**：在 [`compile_rules()`](control/src/routing/matcher.rs:1242)
  域名收集阶段，把 geosite `cn` 的 Domain 列表（含 type 语义）映射为 domain_sets
  的模式条目（`suffix:`/`full:`/`regex:`/`domain:`），生成
  `MatchType_DomainSet` MatchSet。eBPF 侧由 DNS 解析填充位图后经
  [`route_match_domain_set()`](bpf/kern/tproxy.c:1398) 求值。
- **编译期缺失处理**：若 `geoip:<code>` / `geosite:<code>` / `set:<name>` 在内存
  缓存中不存在（数据未下载/损坏）：
  - 静默丢弃不再被允许（修复现状缺陷）；
  - 默认**编译失败并报错**（错误码 E2103 `RuleSetDataMissing`），提示用户检查
    数据源；或提供配置开关 `rule_set.missing_policy = fail | ignore`（默认 fail）。
- **容量检查**：见 §9。

### 6.4 DNS 查询路由（`router.rs`）求值语义

- 将 [`compile_route_rule()`](control/src/dns/router.rs:257) 扩展：识别
  `qname(geosite:cn)`、`qname(set:chinadomain)` 前缀 → 编译为
  `DnsMatchType::GeoSite` / `DnsMatchType::Set`，携带规则集引用。
- 运行时 `evaluate_match()`：对 qname 计算是否命中 geosite/set 的域名模式
  （用户空间直接匹配内存缓存，不依赖 eBPF）。
- `qname(suffix:...)` 等普通模式继续走现有后缀逻辑。

### 6.5 DNS 响应路由（`handler.rs`）求值语义（修复"恒 true"缺陷）

- 将 [`evaluate_response_condition()`](control/src/dns/handler.rs:564) 扩展：
  - `ip(geoip:cn)` / `ip(set:chinaip)`：解析响应中所有 A/AAAA 地址
    （复用 [`extract_answer_addrs()`](control/src/dns/handler.rs:460)），任一地址
    命中 geoip/set 的 IP 集合 → 条件真。
  - `qname(geosite:cn)` / `qname(set:chinadomain)`：对查询名做域名模式匹配。
  - 保留 `upstream(label)` / `nocontent` / `any`。
- 条件组合：`ip(geoip:private) && !qname(geosite:cn)` 需支持 AND/NOT——为响应路由
  引入轻量条件求值器（解析 `&&` 与 `!`，复用 matcher 的分割函数或新增共享工具）。

## 7. 调度器设计（Scheduler）

### 7.1 调度器定位与主循环关系

- 新增 `control/src/ruleset/scheduler.rs`（`RuleSetScheduler`），作为 tokio 后台
  任务在 `ControlPlane.start()` 阶段 `tokio::spawn`，持有：
  - `RuleSetManager`（下载/存储/校验/内存缓存）句柄；
  - 配置 `rule_set` 条目（含调度表达式）。
- 与主循环关系：
  - 独立任务 + 基于 `tokio::time` 的定时器；
  - 用 `tokio::sync::watch` / `oneshot` 与主循环通信：更新完成 → 通知 ControlPlane
    重新编译路由并热重载（复用现有 eBPF 双缓冲 epoch）；
  - 不阻塞 [`src/lib.rs`](src/lib.rs) 的 `tokio::select!` 信号循环；关停时通过
    关闭信号（`CancellationToken` 或 `watch`）优雅退出。

### 7.2 调度聚合

- 单任务统一调度所有规则集：维护每条目的**下次触发时刻**（`Instant`/`DateTime`），
  用 `tokio::time::sleep_until(最近时刻)` 唤醒后，集中处理所有到点条目，再排下一次。
- `time: HH:MM` → 计算下一次 `Local` 时刻；`period: X` → `last_update + X`（基准
  为上次成功更新，见 §5.5）。
- 启动时若 `update_on_start: true` 立即触发下载（异步，不阻塞启动完成）。

## 8. 错误处理与可观测性（Error Handling & Observability）

### 8.1 错误路径与日志

| 阶段 | 失败行为 | 日志级别 | 用户可见行为 |
|------|----------|----------|--------------|
| 下载失败 | 指数退避重试（默认 3 次）；仍失败保留旧文件 | `warn`/`error` | 该规则集不更新；数据缺失时相关规则编译报错（E2103，§6.3） |
| 校验和失败 | 删除临时文件，保留旧文件，标记 degraded | `error` | 同上；连续 5 次后停止自动重试（仍可手动/启动更新） |
| protobuf/文本解析失败 | 视为损坏，按 §4.3 恢复 | `error` | 数据缺失时相关规则编译报错（E2103，§6.3） |
| 规则集引用缺失（编译期） | 默认编译失败；`missing_policy=ignore` 时跳过该规则 | `error`/`warn` | 配置报错（E2103）或日志告警 |
| 容量超限 | 拒绝编译并报错（§9） | `error` | 配置报错，提示精简规则 |
| 代理组下载失败 | 回退直连（记录告警）；直连也失败按下载失败处理 | `warn` | 同上 |

- 统一通过 `tracing` 输出，带规则集 `name`、`url`、错误上下文。
- 规则集更新状态（`state`、`last_updated`、`sha256`、失败原因）持久化于
  `.meta/<name>.json`，供 API/诊断查询。

### 8.2 配置校验（validator）扩展

- [`validator.rs`](control/src/config/validator.rs) `validate_config()` 新增
  `validate_rule_set(config)`：
  1. `rule_set` 条目 name 唯一性 + 命名约束（E2101）；
  2. URL 协议/`#sha256=` 校验；
  3. `update` 二选一互斥 + 时间/周期格式（拒绝秒级）；
  4. 路由规则中 `set:<name>` / `geoip:<code>` / `geosite:<code>` 引用完整性
     （E2102）；
  5. DNS 路由 / DNS 响应路由中同类引用校验（E2102）。

### 8.3 新错误码

在 [`mod.rs`](control/src/config/mod.rs:43) 的 `ConfigError` 中新增：

- `E2101 DuplicateRuleSet { name }` — 规则集 name 重复；
- `E2102 UnknownRuleSetRef { reference }` — 引用未知规则集；
- `E2103 RuleSetDataMissing { reference, reason }` — 编译期数据缺失；
- `E2104 InvalidRuleSetUpdate { name, message }` — 调度表达式非法（含秒级）；
- `E2105 InvalidRuleSetUrl { name }` — URL 非法；
- `E2106 RuleSetCapacityExceeded { detail }` — 容量超限（§9）。

## 9. eBPF 集成与容量（eBPF Integration & Capacity）

### 9.1 编译目标

- **geoip / IP 列表** → LPM 前缀树：
  - 每个 `geoip:<code>` / `set:<ip_list>` 引用解析为一组 `IpNet`，经
    [`find_or_create_lpm_trie()`](control/src/routing/matcher.rs:1045) 去重后映射到
    一个 LPM trie 索引，写入 `MatchType_IpSet` / `MatchType_SourceIpSet`。
- **geosite / 域名列表** → `domain_sets` 模式 + `domain_routing_map` 位图：
  - 每个 `geosite:<code>` / `set:<domain_list>` 引用映射为一个 domain_sets 条目
    （含 suffix/full/regex/domain 模式），DNS 解析结果写入
    `domain_routing_map`（IP → 位图），eBPF 侧查询位图。

### 9.2 容量约束评估

| 资源 | 上限 | 约束说明 |
|------|------|----------|
| routing_map（每 epoch 槽） | `MAX_MATCH_SET_LEN = 1024` | MatchSet 条目总数（含逻辑链与 fallback） |
| lpm trie 数（用户空间编译期） | `MAX_LPM_NUM = 1032` | [`matcher.rs`](control/src/routing/matcher.rs:30) |
| lpm trie 外层数组（eBPF 双缓冲） | `2 * 1024 + 8 = 2056` | [`tproxy.c`](bpf/kern/tproxy.c:63) |
| 单个 LPM trie 内部条目 | `MAX_LPM_SIZE = 2_048_000` | 单 trie 可容纳 200 万 CIDR（GeoIP CN 远小于此） |
| domain_routing_map 位图 | 32 个 u32（=1024 bit） | **域名集规则索引上限 1024**（每个 geosite/set 域名单占 1 bit） |

- 典型量级：GeoIP `cn` 约 2k-10k 条 CIDR、geosite `cn` 约 5k-50k 域名，均远小于
  单 trie / 位图单索引的容量，**瓶颈在 MatchSet 总数与域名集索引数**（规则数量）。
- **注意**：域名集索引 = 编译期出现的 `target_domain(geosite:*)` / `set:*` /
  `domain(...)` 规则条目数（按引用去重），上限 1024。

### 9.3 超限与降级策略

- **优先策略：拒绝编译并报错**（E2106），提示用户：
  - 减少规则数 / 合并规则集引用；
  - 拆分为更小的 geosite code；
  - 调整 `MAX_MATCH_SET_LEN`（需同步 `matcher.rs` 与 `tproxy.c` 的常量，且受 eBPF
    栈/位图内存限制）。
- **可选降级（阶段 5，默认关闭）**：
  - 域名集索引超限：对 geosite code 做**采样/截断**（如按后缀前缀哈希取子集）并
    告警——不推荐，因会改变匹配语义；
  - 分段：多个超大数据集拆分进多个 epoch 槽——与当前双缓冲架构冲突，仅作为远期
    方案记录。
- 编译期即检测，不做运行时动态扩容；eBPF map 尺寸保持编译期常量以兼容
  `bytemuck` 布局。

## 10. 自由组合能力（Free Combination）

### 10.1 语义模型（对齐 dae）

在 §2.1 基础上，明确 dae-rs 的组合模型：

```
路由 = [规则1, 规则2, ..., fallback]
规则 = { 条件组合, 动作 }
条件组合 = 条件1 AND 条件2 AND ...      # 全命中才执行
条件   = 函数(值1, 值2, ...) | !函数(...)  # 值之间 OR；NOT 取反
动作   = direct | block | proxy(<group>) | control_plane_routing
any    = 无条件真
```

- **多条件单 action**：任意多个不同函数自由 AND（IP+域名+端口+协议可混用）。
- **优先级**：顺序匹配，第一条完全命中生效；否则 fallback。
- **`any` 通配**：`any -> 动作`。

### 10.2 数据面求值流程（已实现，保持）

[`matcher.rs`](control/src/routing/matcher.rs:1269) 通过 `LOGICAL_OR`/`LOGICAL_AND`
outbound 链把"函数内多值 OR + 函数间 AND + NOT"降级为线性 MatchSet 序列；eBPF
`route()`（[`tproxy.c`](bpf/kern/tproxy.c)）与用户空间 `RoutingMatcher::match_routing()`
（[`matcher.rs`](control/src/routing/matcher.rs:1438)）一致求值。规则集函数
（`source_ip`/`target_ip`/`target_domain`）与既有函数共用此链。

### 10.3 DNS 面组合求值流程

- **DNS 查询路由**（[`router.rs`](control/src/dns/router.rs)）：当前每条规则单条件；
  阶段 3 升级为支持 `&&`/`!` 组合（复用 §6.5 的条件求值器），语义对齐数据面。
- **DNS 响应路由**（[`handler.rs`](control/src/dns/handler.rs)）：条件求值器支持
  `&&`/`!` 与规则集条件（§6.5）。

## 11. 与 dae 的对齐与差异总结

| 维度 | dae | dae-rs（本设计） | 说明 |
|------|-----|------------------|------|
| geosite/geoip 数据 | v2ray `.dat` | 同（原生 protobuf 解析） | 对齐 |
| 规则集管理 | global 内 URL + 定时更新 | 独立 `rule_set` 区块，多文件、唯一 name、可独立调度 | 增强 |
| 数据目录 | `/usr/local/share/dae`（可配） | `/var/dae-rs/`（固定默认，未来可配） | 差异（用户指定） |
| 引用语法 | `geosite:xx`/`geoip:xx` | 新增 `set:name`；保留 `geoip:`/`geosite:` | 超集 |
| 函数命名 | `dip`/`sip`/`domain` | 新增 `source_ip`/`target_ip`/`target_domain`，保留旧别名 | 超集 |
| 组合语义 | AND/OR/NOT/any/顺序/fallback | 完全一致 | 对齐 |
| DNS 响应 IP 匹配 | 支持 | 修复"恒 true"缺陷后支持 | 对齐+修复 |
| `@attribute` 二级分类 | 支持 | v0.1 仅一级 code；列为阶段 5 可选 | 差异（待扩展） |

## 12. 实施阶段划分（Implementation Phases）

> 供 orchestrator 分派 Code 子任务。每阶段独立可验证。

### 阶段 0：依赖与骨架
- 新增依赖：HTTP 客户端（`reqwest` 或 `ureq`，含 socks 代理）、protobuf
  （`prost` + 构建脚本生成 `v2ray router` proto，或手写轻量解码器避免重依赖）。
- 新增模块骨架 `control/src/ruleset/`（`mod.rs`、`types.rs`）。

### 阶段 1：数据层（格式 + 存储 + 下载 + 校验）
- v2ray `.dat` protobuf 解码（geoip `GeoIPList`/`GeoIP`/`CIDR`；geosite
  `GeoSiteList`/`GeoSite`/`Domain`），内存缓存结构。
- 文本域名/IP 列表解析（含 `full:`/`domain:`/`suffix:`/`keyword:`/`regex:` 前缀）。
- `/var/dae-rs/` 目录布局、`.tmp/`/`.checksum/`/`.meta/` 管理。
- 下载器：直连 + 通过代理组（SOCKS5 隧道）下载、重试、ETag、sha256 校验、
  原子替换、损坏恢复。
- **验证**：单元测试（解析已知 dat 样本、文本列表、校验/替换逻辑）。

### 阶段 2：配置与调度
- `DaefileConfig.rule_set` 结构 + parser（`ParseState::RuleSet`）+ validator
  （E2101/E2102/E2104/E2105）+ 错误码。
- `RuleSetScheduler`（time/period、update_on_start、tokio 任务、聚合、优雅关停）。
- **验证**：配置解析/校验单测；调度器时间计算单测。

### 阶段 3：语法 / matcher / DNS 集成
- 引用语法解析与归一化（`source_ip`/`target_ip`/`target_domain` + `set:`/`geoip:`/
  `geosite:`；旧别名映射）。
- matcher：`compile_rules()` 接入规则集 → LPM trie / domain_sets；缺失处理
  （E2103）；容量检查（E2106）。
- DNS 查询路由：`qname(geosite:cn)` / `qname(set:...)` 求值。
- DNS 响应路由：`ip(geoip:cn)` / `ip(set:...)` 求值，修复"恒 true"；条件求值器
  （`&&`/`!`）。
- **验证**：路由编译单测（规则集 → MatchSet/LPM/domain_sets）、DNS 路由单测。

### 阶段 4：示例与文档
- 更新 [`config-example/config.daefile`](config-example/config.daefile) 与
  [`config-example/config.json`](config-example/config.json)（新增 `rule_set` 区块
  与 `source_ip`/`target_ip`/`target_domain` 示例规则）。
- 更新 [`docs/config/config_zh_hans.md`](docs/config/config_zh_hans.md)（配置字段）、
  [`docs/design/routing_zh_hans.md`](docs/design/routing_zh_hans.md) 与
  [`docs/design/dns_zh_hans.md`](docs/design/dns_zh_hans.md)（数据面/DNS 求值），
  以及英文版。
- **验证**：示例配置可解析/校验通过；文档评审。

### 阶段 5（可选）：测试与扩展
- 端到端测试：真实数据源下载 → 路由编译 → eBPF 加载 → 匹配验证。
- geosite `@attribute` 二级分类支持。
- `missing_policy=ignore`、域名集超限采样等降级选项。

## 13. 已确定决策（Confirmed Decisions）

> 以下四项技术选型已与项目方确认（2026-08-03），作为实现阶段的硬性约束：

1. **`period` 周期基准**：采用 **"上次成功更新"** 为基准（失败不消耗周期）。
   相关章节：§5.5、§7.2。
2. **HTTP 客户端**：采用 **`reqwest`**（异步，开启 `socks` feature 支持经代理组
   的 SOCKS5 下载）。相关章节：§4.2、阶段 0。
3. **dat 解码方式**：采用**手写轻量 protobuf 解码器**（零新依赖，v2ray dat 结构
   简单稳定）。相关章节：§2.2、阶段 1。
4. **编译期数据缺失策略**：默认**编译失败并报错**（E2103），修复现状"静默丢弃"
   缺陷；`missing_policy=ignore` 作为阶段 5 可选降级项。相关章节：§6.3、§8.1。

## 14. 参考（References）

- dae 官方仓库：https://github.com/daeuniverse/dae （`docs/en/configuration/routing.md`）
- Loyalsoldier/v2ray-rules-dat：https://github.com/Loyalsoldier/v2ray-rules-dat
- v2fly/domain-list-community（geosite 格式说明）：https://github.com/v2fly/domain-list-community
- v2ray-core `app/router/config.proto`（GeoIPList/GeoSiteList 定义）
- dae-rs 现有文档：`docs/design/routing_zh_hans.md`、`docs/design/dns_zh_hans.md`、
  `docs/config/config_zh_hans.md`
