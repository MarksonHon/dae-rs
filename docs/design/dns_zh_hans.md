# DNS 子系统设计

> 双语文档。英文版本见 [`dns_en.md`](./dns_en.md)。

## 1. 范围

本文档描述 dae-rs DNS 子系统**当前已实现**的实际情况
（位于 `control/src/dns/*`），涵盖 DNS 管理器、上游连接池、请求/响应动作、
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
    │      └─ 选择分组（request_routing / fallback）
    │
    ├─ 以 DNS 组为单位并发查询全部上游：
    │      send_by=direct      → 直连上游（socket 打 SO_MARK=0x100 绕过代理）
    │      send_by=<代理组>    → 通过该代理组走 TCP 转发到上游
    │      首个成功的响应胜出
    │
    ├─ 响应动作（accept / reject / requery）
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

- URL 解析（`parse_dns_url_parts`）支持 `udp://`、`tcp://`、`udp+tcp://`、
  `tcp+udp://`、`https://` / `doh://`、`tls://` / `dot://`，以及裸 `host:port`
  （默认 UDP）。默认端口：53（明文）、443（DoH）、853（DoT）。
- 传输枚举：`Udp`、`Tcp`、`UdpTcp`、`TcpUdp`、`Doh`、`Dot`。**DoH 与 DoT
  仅解析、未实现**——对它们调用 `query()` 会返回错误。
- `udp+tcp://` 先走 UDP，失败回退 TCP。
- `tcp+udp://` 先走 TCP，失败回退 UDP。
- **关键细节**：每个上游 socket 都以 `SO_MARK=0x100`（`DAE_SOCKET_MARK`）
  创建。这使 eBPF 程序把该查询视为 dae-rs 控制面流量放行而不拦截——
  否则 dae-rs 自身的 DNS 解析会被重新劫持进代理，形成解析死循环。
- 每次查询超时 5 秒。

### 3.3 `DnsRouter`（`router.rs`）

把查询匹配到分组，并检查响应。

- 顶层规则支持 `qname(...)`、`qtype(...)`（A/AAAA/…）、`any`；每条规则可用
  `!` 取反。`qname(geosite:cn)` / `qname(set:chinadomain)` 等规则集引用按
  GeoSite 分类 / `domain_list` 条目匹配（见 §3.6）。
- 无规则命中时用 `config.routing.fallback`；若为空则用第一个配置的分组；
  若无分组则返回 "null" 空结果。
- **所有路由均通过顶层 `dns.routing`**：组内 `request_routing` 已移除，组内
  不再选择具体上游，`DnsRouteResult` 只携带分组与 `send_by`。
- `send_by` 字段：`"direct"` 表示本组上游查询直连；否则填写一个代理分组名
  （如 `send_by: proxy_primary`），表示本组上游查询通过该代理组出站。
  `"direct"` 是保留关键字，任何 DNS 服务器或 DNS 组不得命名为 `direct`。
  分组名被放入 `DnsRouteResult.send_by`。
- `query_mode` 字段：控制本组如何选择上游服务器，取值：
  - `concurrent`（默认）— 并发查询组内全部上游，取首个成功响应；
  - `random` — 随机挑选组内一个上游查询；
  - `sequence` — 按配置顺序（自上而下）逐个尝试，首个成功即用。

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
  3. 经 `DnsRouter` 路由到分组，再按分组 `query_mode` 选择上游并查询
     （直连或经 `send_by` 代理组）。
  4. 应用响应动作（accept / reject / 换上游 requery）。
  5. accept 时写入缓存，并把被接受的 A/AAAA 解析结果喂给域名路由回调。
- **IP_TRANSPARENT 响应**：回复使用设置了 `IP_TRANSPARENT`/`IPV6_TRANSPARENT`、
  `SO_REUSEADDR`、`SO_REUSEPORT` 与 `SO_MARK=0x100`、并绑定到**上游 DNS
  服务器地址**的 socket 发出。DNS 客户端期望响应源地址与所查服务器一致
  （如 8.8.8.8:53），而不是本地监听地址（169.254.0.1:5353）。
  `IP_TRANSPARENT` 允许绑定到该非本地地址；`SO_MARK` 让响应绕过代理管线。
  命中缓存时没有上游地址，退化为临时端口绑定。

### 3.5 `DnsCache`（`cache.rs`）

以 `(qname, qtype, class)` 为键、**按 DNS 分组分区**的响应缓存。每个分组
（如 `china_dns`、`trusted_dns`）拥有独立的 `HashMap`，同一 `(qname, qtype)`
可在不同分组中各存各的答案——避免"被污染的国内上游"与"可信境外上游"相互
污染缓存。`max_size` 为每个分组各自的容量上限。

- 配置：`enabled`、`max_size`（4096，每分组）、`max_ttl`（86400 秒）、
  `min_ttl`（60 秒）、`optimistic_cache`（RFC 8767，默认关）、
  `optimistic_cache_ttl`（3600 秒）。
- 过期条目会重新校验/刷新；开启乐观缓存后，过期条目在刷新期间仍可被返回。
- 缓存查询在 `DnsRouter` 路由出分组之后进行，写入与读取都带分组名。

### 3.6 DNS 路由中的规则集求值

- **DNS 查询路由**（[`router.rs`](control/src/dns/router.rs)）：`qname(geosite:cn)`
  / `qname(set:chinadomain)` 编译为规则集引用（`DnsMatchType::GeoSite` /
  `DnsMatchType::Set`），运行时对查询名做域名模式匹配（用户空间直接匹配内存
  缓存，不依赖 eBPF）。`qname(suffix:...)` 等普通模式继续走既有后缀逻辑。
- **DNS 响应动作**（[`handler.rs`](control/src/dns/handler.rs)）：
  - `ip(geoip:cn)` / `ip(set:chinaip)` — 解析响应中所有 A/AAAA 地址
    （复用 `extract_answer_addrs()`），任一地址命中 GeoIP / IP 列表 → 条件真；
  - `ip(CIDR)` — 直接 CIDR 匹配；
  - `upstream(label)` — 当实际响应来自指定标签的上游时条件为真，可用于区分
    同一组内不同上游的响应；
  - `nocontent` — 响应中无 answer 记录（NODATA）；
  - `qname(geosite:cn)` / `qname(set:chinadomain)` — 对查询名做域名模式匹配。
  - 条件支持 `&&`（AND）与 `!`（NOT）组合，如
    `ip(geoip:private) && !qname(geosite:cn)`。
  - 未知条件默认返回 false 并告警（不再像早期实现那样始终返回 true）。

## 4. 引导解析 / starting_dns

`starting_dns` 是"信任锚"解析器，在一切就绪前使用：

- 其上游**必须是 IP 字面量**——解析域名形式的引导 DNS 是鸡生蛋问题。
- 配置为**扁平列表**，直接填写几个 IP 类型 DNS 服务器地址：
  ```
  starting_dns {
    ip_version_prefer: 4
    upstream: ['udp+tcp://223.5.5.5:53', 'udp+tcp://1.1.1.1:53']
  }
  ```
- 该组 DNS **全部直连**（不经过代理），用于初始化时解析 DNS 组中带域名的
  上游（如 `udp://dns.google:53`）。查询时按顺序遍历全部引导 DNS，先查 A
  记录再查 AAAA 记录，找到任一可用 IP 即停止。
- `ip_version_prefer` 字段（`4` 或 `6`）在配置中声明且会被校验，但**当前
  代码未使用**——bootstrap 解析固定按"先 A 后 AAAA"的顺序。如需支持 IPv6
  优先解析，需修改 `mod.rs` 中的 `resolve_via_bootstrap()` 函数。

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
- `ip_version_prefer` 字段在配置中存在但 bootstrap 解析未使用（固定先 A 后
  AAAA）。
- DNS 监听任务运行无限收发循环，用 `abort()` 停止（安全：tokio 任务在
  await 点可取消）。

> 规则集求值已实现：DNS 查询路由的 `qname(geosite:/set:)` 与 DNS 响应动作的
> `ip(geoip:/set:)` / `qname(...)` / `&&` / `!` 均接入规则集数据（§3.6），
> 不再按简单后缀比较。数据缺失时相关规则编译报错（E2103）。
