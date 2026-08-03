# DNS 子系统设计

> 双语文档。英文版本见 [`dns_en.md`](./dns_en.md)。

## 1. 范围

本文档描述 dae-rs DNS 子系统**当前已实现**的实际情况
（位于 `control/src/dns/*`），涵盖 DNS 管理器、上游连接池、请求/响应路由、
缓存、监听器，以及与基于域名的 eBPF 路由的集成。

模块结构：

```
control/src/dns/
├── mod.rs       # DnsManager — 编排器
├── upstream.rs  # DnsUpstreamPool — 单个上游的连接池、URL 解析
├── cache.rs     # DnsCache — 响应缓存
├── router.rs    # DnsRouter — 查询 → 分组 → 上游匹配、响应检查
└── handler.rs   # DnsListener — UDP/TCP 监听器、查询处理
```

## 2. 数据通路总览

```
 客户端查询
    │
    ▼
 eBPF TC 钩子（WAN egress）拦截 UDP/53，重定向进入代理命名空间（daens）
    │
    ▼
 DNS 监听器（宿主机命名空间 <bind>，另加 169.254.0.1:<port> 内部监听）
    │
    ├─ 缓存查找 ................... 命中 → 从缓存回复
    │
    ├─ DnsRouter.match_query(qname, qtype)
    │      └─ 选择分组 → 选择上游（request_routing / fallback）
    │
    ├─ DnsUpstreamPool.query(...)  → 转发到上游 DNS 服务器
    │      （socket 打上 SO_MARK=0x100 以绕过代理管线）
    │
    ├─ 响应路由（accept / reject / requery）
    │
    ├─ 写入缓存
    │
    └─ 通过 IP_TRANSPARENT socket 回复客户端，使响应的源地址
       看起来来自客户端原始查询的上游 DNS 服务器
```

## 3. 组件

### 3.1 `DnsManager`（`mod.rs`）

编排器，持有配置、上游池映射（键为 `"<分组>__<标签>"`）、共享缓存、
路由器与监听器。

- **`init_upstreams()`** — 构建全部上游池：
  - 先构建 `starting_dns`（引导）池，键为 `"__starting__<标签>"`。这些
    **必须是 IP 字面量**。
  - 分组上游若地址是域名（如 `udp://dns.google:53`），则通过引导解析器
    解析一次（`resolve_via_bootstrap`，先查 A 再查 AAAA），并缓存在本地 map。
  - 单个上游失败只跳过并告警，不会中止整个初始化。
- **`start()` / `stop()`** — 创建绑定到 `config.bind` 的 `DnsListener`，
  共享池/缓存/路由器后运行。

### 3.2 `DnsUpstreamPool`（`upstream.rs`）

单个上游 DNS 服务器的连接池。

- URL 解析（`parse_dns_url_parts`）支持 `udp://`、`tcp://`、`tcp+udp://`、
  `https://` / `doh://`、`tls://` / `dot://`，以及裸 `host:port`（默认 UDP）。
  默认端口：53（明文）、443（DoH）、853（DoT）。
- 传输枚举：`Udp`、`Tcp`、`TcpUdp`、`Doh`、`Dot`。**DoH 与 DoT 仅解析、
  未实现**——对它们调用 `query()` 会返回错误。
- `tcp+udp` 先走 UDP，失败回退 TCP。
- **关键细节**：每个上游 socket 都以 `SO_MARK=0x100`（`DAE_SOCKET_MARK`）
  创建。这使 eBPF 程序把该查询视为 dae-rs 控制面流量放行而不拦截——
  否则 dae-rs 自身的 DNS 解析会被重新劫持进代理，形成解析死循环。
- 每次查询超时 5 秒。

### 3.3 `DnsRouter`（`router.rs`）

把查询匹配到分组与上游，并检查响应。

- 顶层规则支持 `qname(...)`、`qtype(...)`（A/AAAA/…）、`any`；每条规则可用
  `!` 取反。`qname(geosite:cn)` / `qname(set:chinadomain)` 等规则集引用按
  GeoSite 分类 / `domain_list` 条目匹配（见 §3.6）。
- 无规则命中时用 `config.routing.fallback`；若为空则用第一个配置的分组；
  若无分组则返回 "null" 空结果。
- 组内上游的选择来自 `request_routing.fallback`（组内 `request_routing.rules`
  会被解析，但当前 `select_upstream` 实现直接使用 fallback），未配置时用
  第一个上游。
- `proxy` 字段：`"direct"` 表示直接出站；`"proxy(<group>)"` 会把分组名放入
  `DnsRouteResult.proxy_group`（DNS 实际走 SOCKS5 代理不属于本模块职责）。

### 3.4 `DnsListener` / 处理逻辑（`handler.rs`）

实际的 UDP/TCP 监听器与逐查询处理。

- **UDP + TCP** 两个监听器都会绑定，且设置 `SO_REUSEADDR`，快速重启不会
  撞上 `EADDRINUSE`。
- 另外在 `169.254.0.1:<port>`（169.254.0.1 分配在宿主机侧 `dae0` 接口上）
  创建**内部 UDP 监听器**，用于跨命名空间 DNS 转发：代理命名空间（daens）
  内的 eBPF TProxy 通路把拦截到的 DNS 查询转发到该地址，而不是走 SOCKS5。
- 逐查询流程（`handle_dns_internal`）：
  1. 解析 qname + qtype。
  2. 查缓存（键 = qname + qtype + class IN）。
  3. 经 `DnsRouter` 路由 → 解析池键（`"<group>__<label>"`，回退
     `"__starting__<label>"`）。
  4. 转发到上游。
  5. 应用响应路由（accept / reject / 换上游 requery）。
  6. accept 时写入缓存，并把被接受的 A/AAAA 解析结果喂给域名路由回调。
- **IP_TRANSPARENT 响应**：回复使用设置了 `IP_TRANSPARENT`/`IPV6_TRANSPARENT`、
  `SO_REUSEADDR`、`SO_REUSEPORT` 与 `SO_MARK=0x100`、并绑定到**上游 DNS
  服务器地址**的 socket 发出。DNS 客户端期望响应源地址与所查服务器一致
  （如 8.8.8.8:53），而不是本地监听地址（169.254.0.1:5353）。
  `IP_TRANSPARENT` 允许绑定到该非本地地址；`SO_MARK` 让响应绕过代理管线。
  命中缓存时没有上游地址，退化为临时端口绑定。

### 3.5 `DnsCache`（`cache.rs`）

以 `(qname, qtype, class)` 为键的响应缓存。

- 配置：`enabled`、`max_size`（4096）、`max_ttl`（86400 秒）、
  `min_ttl`（60 秒）、`optimistic_cache`（RFC 8767，默认关）、
  `optimistic_cache_ttl`（3600 秒）。
- 过期条目会重新校验/刷新；开启乐观缓存后，过期条目在刷新期间仍可被返回。

### 3.6 DNS 路由中的规则集求值

- **DNS 查询路由**（[`router.rs`](control/src/dns/router.rs)）：`qname(geosite:cn)`
  / `qname(set:chinadomain)` 编译为规则集引用（`DnsMatchType::GeoSite` /
  `DnsMatchType::Set`），运行时对查询名做域名模式匹配（用户空间直接匹配内存
  缓存，不依赖 eBPF）。`qname(suffix:...)` 等普通模式继续走既有后缀逻辑。
- **DNS 响应路由**（[`handler.rs`](control/src/dns/handler.rs)）：
  - `ip(geoip:cn)` / `ip(set:chinaip)` — 解析响应中所有 A/AAAA 地址
    （复用 `extract_answer_addrs()`），任一地址命中 GeoIP / IP 列表 → 条件真；
  - `ip(CIDR)` — 直接 CIDR 匹配；
  - `qname(geosite:cn)` / `qname(set:chinadomain)` — 对查询名做域名模式匹配。
  - 条件支持 `&&`（AND）与 `!`（NOT）组合，如
    `ip(geoip:private) && !qname(geosite:cn)`。

## 4. 引导解析 / starting_dns

`starting_dns` 是"信任锚"解析器，在一切就绪前使用：

- 其上游**必须是 IP 字面量**——解析域名形式的引导 DNS 是鸡生蛋问题。
- 两个用途：
  1. 初始化时解析基于域名的上游（如 `udp://dns.google:53`）。
  2. 查询时若分组自身上游查找失败，作为回退池。

## 5. 与基于域名的 eBPF 路由集成

DNS 解析结果会写入 eBPF `domain_routing_map`，使 `domain(...)` 路由规则可在
数据通路内求值：

1. `ControlPlane` 编译路由规则，若存在域名规则则创建
   `DomainRoutingTracker`（见 `control/src/routing/domain_routing.rs`）。
2. 从 DNS 管理器到 tracker 接入 `DnsResolveCallback`（`on_resolve`）。
3. 每条**被接受**的 DNS 响应中，每个 A/AAAA 记录以上报为 `(domain, ip, ttl)`。
4. tracker 计算路由位图（该域名命中了哪些域名集规则），把 `ip → 位图`
   写入 eBPF `domain_routing_map`（带 epoch 槽前缀，用于双缓冲）。
5. janitor 在 TTL 到期时删除条目，与 DNS 缓存保持同步。

这对应原 dae 的 `control/domain_routing_tracker.go`。

## 6. 当前限制

- DoH / DoT 传输仅解析、不可用。
- 组内 `request_routing.rules` 会被解析，但当前上游选择直接使用 fallback
  （规则列表尚未完整求值）。
- `upstream(...)` 响应条件当前匹配一切。
- DNS 监听任务运行无限收发循环，用 `abort()` 停止（安全：tokio 任务在
  await 点可取消）。

> 规则集求值已实现：DNS 查询路由的 `qname(geosite:/set:)` 与 DNS 响应路由的
> `ip(geoip:/set:)` / `qname(...)` / `&&` / `!` 均接入规则集数据（§3.6），
> 不再按简单后缀比较。数据缺失时相关规则编译报错（E2103）。
