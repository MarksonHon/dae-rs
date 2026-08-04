# dae-rs 配置说明

> 双语文档。英文版本见 [`config_en.md`](./config_en.md)。

## 1. 概述

dae-rs 是一个基于 eBPF 的透明代理系统，是原 `dae` 项目的 Rust 重写版本。
本文档描述配置系统当前的实际实现情况。

配置有两种等价形式：

| 格式 | 说明 |
|------|------|
| **daefile**（`.daefile`） | 类 Caddyfile 的易读文本语法，是主要输入格式。 |
| **JSON**（`config.json`） | daefile 解析后得到的规范化、机器可读的结构。 |

`daefile` 由 `parse_daefile()`（位于 `control/src/config/`）解析，再经
`validate_config()` 做语义校验。校验后的结果即规范化 JSON 结构，可输出为
"temp JSON" 文件用于调试（见 `runtime.temp_json`）。参考示例位于
`config-example/` 目录（`config.daefile`、`config-minimal.daefile`、`config.json`）。

## 2. 运行入口

- dae-rs 二进制目前仅支持 `run` 子命令：`dae-rs run -c <config.daefile>`。
- 未指定配置文件时，使用内置示例配置。
- 日志通过 `--log-level` 与 `--json-log` 配置（或 `RUST_LOG` 环境变量）。
- 需要 root 权限（或具备 `CAP_NET_ADMIN`、`CAP_SYS_ADMIN`、`CAP_BPF`），
  因为涉及 eBPF 加载与网络命名空间操作。

## 3. 顶层区块

daefile 以命名区块 `{ ... }` 组织。目前支持的顶层区块：

```
global            # 运行参数
interface         # WAN / LAN / bind 网卡
process_exclusion # 排除不走代理的进程
outbounds         # 代理节点与分组
routing           # 哪些流量直连 / 代理 / 阻断
api               # 可选 REST API
dns               # DNS 劫持 / 路由 / 缓存
rule_set          # 规则集（GeoIP/GeoSite/文本列表）下载与调度
```

示例骨架：

```
global { ... }

interface { ... }

process_exclusion { ... }

outbounds {
  nodes { ... }
  groups { ... }
}

routing { ... }

api { ... }

dns { ... }

rule_set { ... }
```

## 4. 各区块说明

### 4.1 `global`

运行参数。

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `tproxy_port` | `15080` | TProxy 监听端口（1–65535）。 |
| `log_level` | `info` | 日志级别：`info`、`debug`、`warn`、`error`。 |

### 4.2 `interface`

控制哪些网络接口被拦截。

| 字段 | 说明 |
|------|------|
| `wan_interface` | 拦截出站流量的 WAN 接口。支持三种模式：`auto`（跟随承载 IPv4/IPv6 默认路由的接口）、`regex('...')`（如 `regex('^enp[0-9]+$')`）、glob 通配（如 `eth*`、`enp?*`）。 |
| `lan_interface` | 拦截入站流量的 LAN 接口，模式语法同上。 |
| `bind_interface` | 绑定接口（`auto` 表示自动探测）。可选，当前数据通路中还不是核心配置。 |

若 `wan_interface` 为空，eBPF 将完全不拦截出站流量（启动时会输出警告日志）。

### 4.3 `process_exclusion`

让指定进程绕过代理。

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `enabled` | `true` | 总开关。 |
| `protect_self` | `true` | 保护 dae-rs 自身进程。 |
| `protect_children` | `true` | 保护 dae-rs 的子进程。 |
| `gc_interval_sec` | `30` | 被跟踪进程的垃圾回收间隔（秒）。 |
| `stale_after_sec` | `120` | 被跟踪进程条目存活多久后回收（秒）。 |
| `match` | — | 匹配规则块。 |

`match` 块支持 `comm(name1, name2)`、`pid(1234)`、`tgid(1234)`。

> 当前实现说明：daefile 中的排除列表会被解析和编译，但运行时的进程注册
> 主要由 eBPF cgroup 钩子以及 dae-rs 自身 socket 上的 `SO_MARK=0x100`
> 自排除来驱动（详见设计文档）。启动时不会直接写入 PID 键，因为数据通路
> 是按 socket cookie 而非 PID 做排除匹配的。

### 4.4 `outbounds`

#### 节点（nodes）

每个节点是一个代理服务器条目。有两种定义节点的方式：

1. **显式字段** - 直接定义所有参数
2. **导入（import）** - 使用订阅/链接 URL

> **import 行为**：当使用 `import` 时，同一节点内的其他字段被忽略。
> 如果同时存在 `import` 和其他字段，日志会发出警告。

```
nodes {
  # 显式字段
  main {
    protocol: socks5
    address: 127.0.0.1:1080
    # username: user
    # password: pass
    dial_timeout_ms: 5000
  }

  # 从链接导入
  backup {
    import: 'socks5://127.0.0.1:2080'
  }
}
```

| 字段 | 说明 |
|------|------|
| `protocol` | 出站协议（见下方支持的协议）。 |
| `address` | 服务器地址 `host:port`。 |
| `username` / `password` | 可选认证（取决于协议）。 |
| `dial_timeout_ms` | 拨号超时（毫秒），默认 `5000`。 |
| `import` | 节点定义的简写形式，接受协议 URL；与显式字段互斥。 |

#### 支持的协议

| 协议 | `protocol` 值 | 文档 |
|------|---------------|------|
| SOCKS5 | `socks5` | [SOCKS5](../config/config_zh_hans.md) |
| Shadowsocks | `shadowsocks` | [Shadowsocks](../protocols/shadowsocks/shadowsocks_zh_hans.md) |
| Trojan | `trojan` | [Trojan](../protocols/trojan/trojan_zh_hans.md) |
| TUIC v5 | `tuic` | [TUIC](../protocols/tuic/tuic_zh_hans.md) |
| Juicity | `juicity` | [Juicity](../protocols/juicity/juicity_zh_hans.md) |
| VMess | `vmess` | [VMess](../protocols/vmess/vmess_zh_hans.md) |

#### TLS 证书固定

对于使用 TLS 的协议（Trojan、TUIC、Juicity、VMess），可以固定服务器证书
的 SHA256 指纹：

```
ca_sha256: "fb3a01e4..."
```

**重要**：证书验证是**强制的**，无法禁用。dae-rs 中没有 `skip_cert_verify` 选项。

#### 分组（groups）

分组引用一组节点并定义节点的选择方式。

```
groups {
  proxy_primary {
    # type: auto      # 默认
    # policy: fixed   # 总是取第一个存活节点
    # policy: random
    # policy: min          # 最近一次探测延迟最低
    # policy: min_avg10    # 最近 10 次探测平均延迟最低
    policy: min_moving_avg # 移动平均延迟最低（推荐）
    nodes(main, backup)
  }

  manual {
    type: select
    selected: main      # 初始选中节点，可通过 REST API 切换
    nodes(main, backup)
  }
}
```

| 字段 | 说明 |
|------|------|
| `name` | 分组名（即块名），全局唯一。 |
| `type` | `auto`（自动探测，默认）或 `select`（手动选择节点）。 |
| `policy` | `auto` 组的节点选择策略：`fixed`、`random`、`min`、`min_avg10`、`min_moving_avg`。`select` 组不得设置。 |
| `selected` | `select` 组的初始选中节点，必须在组的选择器可达集合内。`auto` 组不得设置。 |
| `nodes(...)` | 显式节点列表选择器，如 `nodes(main, backup)`。 |
| `regex(...)` | 正则选择器，如 `nodes(regex: '*')` 选择全部节点。 |

### 4.5 `routing`

决定每条连接的归宿。规则自上而下逐条匹配。

```
routing {
  dip(geoip:private) -> direct
  dport(22) -> direct
  l4proto(tcp) -> proxy(proxy_primary)
  fallback: proxy(proxy_primary)
}
```

- 规则行格式：`<匹配表达式> -> <动作>`。
- 动作：`direct`、`block`、`proxy(<group>)`。编译器还支持
  `proxy(<group>, mark=0x..., must)`。
- `fallback:` 表示无规则命中时使用的动作（默认 `proxy(proxy_primary)`）。

已实现的匹配函数（位于 `control/src/routing/matcher.rs`）：

| 函数 | 含义 |
|------|------|
| `dport(80,443)` / `port(80-90)` | 目标端口 / 端口段。 |
| `sport(...)` / `source_port(...)` | 源端口 / 端口段。 |
| `dip(10.0.0.0/8)` / `ip(...)` / `target_ip(...)` | 目标 CIDR；`geoip:<code>` / `set:<name>` 引用规则集。 |
| `sip(...)` / `source_ip(...)` | 源 CIDR；`geoip:<code>` / `set:<name>` 引用规则集。 |
| `mac(xx:xx:xx:xx:xx:xx)` | 源 MAC 地址。 |
| `l4proto(tcp,udp)` | 四层协议。 |
| `ipversion(4,6)` | IP 版本。 |
| `domain(suffix:example.com, keyword:..., full:..., regex:...)` / `target_domain(...)` | 域名规则；`geosite:<code>` / `set:<name>` 引用规则集，其余无前缀的值默认按后缀匹配。 |
| `process_name(...)` / `pname(...)` | 进程 comm 名（最多 16 字节）。 |
| `dscp(...)` | DSCP 值。 |
| `qtype(...)` | DNS 查询类型（完整匹配尚未实现，占位）。 |
| `upstream(...)` | DNS 上游分组匹配。 |

表达式可用 `&&` 组合（如 `dport(443) && l4proto(tcp)`），函数可用 `!`
取反（如 `!domain(suffix:google.com)`）。

#### 规则集引用语法

在 `routing` 中可引用 §4.8 `rule_set` 区块配置的规则集（详见
[`docs/design/rule_set_zh_hans.md`](../design/rule_set_zh_hans.md)）：

| 语法 | 含义 |
|------|------|
| `source_ip(set:chinaip)` | 源 IP 命中 `ip_list` 条目 `chinaip`。 |
| `source_ip(geoip:cn)` / `target_ip(geoip:cn)` | 源/目标 IP 命中 GeoIP dat 的 `CN`（`geoip:private` 命中私有网段，数据驱动）。 |
| `target_ip(set:chinaip)` | 目标 IP 命中文本 IP 列表 `chinaip`。 |
| `target_domain(geosite:cn)` | 目标域名命中 GeoSite dat 的 `cn` 分类。 |
| `target_domain(set:chinadomain)` | 目标域名命中 `domain_list` 条目 `chinadomain`。 |

`set:` 必须引用 `rule_set` 中已定义的条目（`geoip`/`geosite` 引用在配置了
对应类型条目后可用），否则校验报错（E2102）。

### 4.6 `api`

可选的 REST API，用于运行时控制（如切换 `select` 组的节点）。

| 字段 | 说明 |
|------|------|
| `enabled` | 是否启用 API 服务。 |
| `listen` | 监听地址，如 `127.0.0.1:9090`。 |
| `tls` | 是否启用 TLS（需配置 `cert` + `key`）。 |
| `cert` / `key` | TLS 证书 / 私钥路径。 |
| `token` | Bearer Token（静态密钥），用于请求鉴权。 |

### 4.7 `dns`

完整设计见 [`docs/design/dns_zh_hans.md`](../design/dns_zh_hans.md)。简要说明：

| 字段 | 说明 |
|------|------|
| `starting_dns` | 代理可用前的引导解析器。包含 `ip_version_prefer`（`4` 或 `6`）与 `upstream` 列表（必须是 IP 字面量，避免先有鸡还是先有蛋的问题）。 |
| `bind` | 本地 DNS 监听地址（默认 `127.0.0.1:5353`）。 |
| `cache` | 缓存设置：`enabled`、`max_size`、`max_ttl`、`min_ttl`、`optimistic_cache`、`optimistic_cache_ttl`。 |
| `groups` | DNS 分组。每组含 `proxy`（`direct` 或 `proxy(<group>)`）、`upstream` 条目（label + URL，如 `udp://1.1.1.1:53`、`tcp+udp://dns.google:53`）、`request_routing` 与 `response_routing`。响应路由支持 `ip(geoip:<code>)` / `ip(set:<name>)` / `qname(geosite:<code>)` / `qname(set:<name>)` 条件，可用 `&&` 与 `!` 组合。 |
| `routing` | 顶层 DNS 查询路由：`qname(geosite:cn) -> china_dns`、`qname(set:chinadomain) -> china_dns` 等，外加 `fallback`。 |

可解析的 URL scheme：`udp://`、`tcp://`、`tcp+udp://`、`https://` / `doh://`、
`tls://` / `dot://`。DoH 与 DoT 目前**仅能解析、不可用**，使用会返回错误。

### 4.8 `rule_set`

规则集区块声明可供 `routing` / `dns` 引用的 GeoIP / GeoSite（v2ray `.dat`）
与文本域名 / IP 列表数据源，并配置下载与定时更新。完整设计与语法见
[`docs/design/rule_set_zh_hans.md`](../design/rule_set_zh_hans.md)。

```
rule_set {
  geoip_main {
    type: geoip
    url: 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat'
    name: geoip_main
    update: time: 21:47
    update_on_start: true
  }

  geosite_main {
    type: geosite
    url: 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat'
    name: geosite_main
    update: period: 3h2m
  }

  chinadomain {
    type: domain_list
    url: 'https://example.com/rules/chinadomain.txt'   # 占位 URL，可替换
    name: chinadomain
    update: time: 04:30
  }

  chinaip {
    type: ip_list
    url: 'https://example.com/rules/chinaip.txt'       # 占位 URL，可替换
    name: chinaip
    update: period: 1d
    proxy: proxy_primary
  }
}
```

| 字段 | 必填 | 说明 |
|------|------|------|
| `type` | 是 | `geoip`（dat）、`geosite`（dat）、`domain_list`（文本域名）、`ip_list`（文本 IP）。 |
| `url` | 是 | 下载地址（`http://` / `https://`），可带 `#sha256=<64位hex>` 片段强制校验。 |
| `name` | 否（缺省 = 块名） | **唯一备注/名称**（`[a-zA-Z0-9_-]`，≤63），用于 `set:<name>` 引用与文件命名。 |
| `update` | 是 | 调度表达式，`time: HH:MM`（每天固定时刻）与 `period: 3h2m`（周期，`d`/`h`/`m` 组合、禁止秒）**互斥二选一**。 |
| `update_on_start` | 否 | 启动时无条件更新一次（默认 `false`）。 |
| `proxy` | 否 | 指定下载用代理组；缺省用第一个代理组。 |

- **唯一性**：`rule_set` 内所有条目的 `name`（含缺省 = 块名）全局唯一，违反报
  E2101。
- 数据文件存放于 `/var/lib/dae-rs/`（dat 为 `<name>.dat`，文本为 `<name>.txt`），
  由 dae-rs 自行下载、校验、原子替换与损坏恢复；缺失时通过第一个代理组（或
  条目显式 `proxy`）下载。
- 路由引用语法见 §4.5「规则集引用语法」与 §4.7（DNS 侧）。

## 5. 配置校验

`validate_config()` 做语义校验并给出带稳定错误码的诊断信息：

| 错误码 | 含义 |
|--------|------|
| `E1001` | 语法错误（带行号）/ 未知区块。 |
| `E1101` | 缺少必需区块。 |
| `E1201` / `E1202` / `E1203` | 字段类型 / 范围 / 取值错误。 |
| `E1301` / `E1302` | 节点 / 分组重名。 |
| `E1401` / `E1402` | 引用了不存在的节点 / 分组。 |
| `E1501` / `E1502` | 节点 import 与显式字段冲突 / import URL 非法。 |
| `E1601` / `E1602` | 正则语法错误 / 正则未匹配到任何节点。 |
| `E1701` – `E1704` | select / auto 分组配置错误。 |
| `E1901` – `E1903` | API 监听格式 / token / TLS 问题。 |
| `E2001` – `E2007` | DNS 分组 / 路由 / starting_dns 问题。 |
| `E2101` – `E2106` | 规则集：name 重复 / 引用未知规则集 / 数据缺失 / 调度表达式非法（含秒级）/ URL 非法 / 容量超限。 |

警告（`W1801`、`W1901`、`W1902`、`W2001`、`W2002`）用于提示非致命问题，
如缺少 policy、缺少 DNS response_routing 等。

## 6. 默认值一览

- TProxy 端口 `15080`，路由表 `2023`，代理 fwmark `0x08000000`，
  绕过 fwmark `0x04000000`，MTU `1500`。
- SOCKS5 拨号超时 `5000` 毫秒。
- DNS 绑定 `127.0.0.1:5353`；缓存默认开启，`max_size=4096`、
  `max_ttl=86400`、`min_ttl=60`。
- 路由回退 `proxy(proxy_primary)`。

## 7. 当前已知限制（按已实现代码）

- 仅支持 `socks5` 出站节点（阶段一）。
- 控制面实际只使用一个 SOCKS5 上游地址（配置文件中的第一个节点）；
  出站分组会做节点选择并写入连通性 map，但节点间切换仍在开发中。
- DNS 的 DoH / DoT 传输仅解析、未实现。
- GeoIP / GeoSite 数据不随二进制内置，而是通过 `rule_set` 区块配置的 URL
  下载到 `/var/lib/dae-rs/` 并由 dae-rs 解析加载；`geoip:<code>` /
  `geosite:<code>` / `set:<name>` 已接入数据面与 DNS 路由求值。编译期若引用
  的数据缺失会报错（E2103）。
