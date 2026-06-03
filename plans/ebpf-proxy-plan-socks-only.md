# eBPF 代理项目计划（第一阶段：仅支持 SOCKS 出站）

## 1. 目标与范围

### 1.1 项目目标
构建一个类似 dae 的 eBPF 代理系统，在内核侧截获流量并做分流决策：
- 直连：直接放行走系统路由
- 代理：重定向到用户态控制面并通过 SOCKS 出站

### 1.2 第一阶段范围（本计划覆盖）
仅实现最小可用闭环（MVP）：
- 支持 TCP 与 UDP 流量分流（IPv4 与 IPv6）
- 支持基础规则匹配：目的 IP/CIDR、目的端口、L4 协议、fallback
- 支持 SOCKS5 作为出站协议
- eBPF 模块仅做直连/代理二选一判断
- 代理路径使用单独网络命名空间（匿名 netns）
- 宿主与代理命名空间之间通过 veth 传输流量
- 支持进程排除能力（至少覆盖代理进程自身、可配置进程名）
- 提供最基础日志与观测指标

### 1.3 明确不做（第一阶段）
- 不支持 VMess/VLESS/Trojan/Hysteria 等协议
- 不做完整域名分流（可先保留接口）
- 不做 DNS 模块
- 不做高级负载均衡与健康探测策略
- 不在 eBPF 中实现 block 动作（阻断能力后续再评估）
- 不在第一阶段引入 netkit（后续仅作为性能优化选项）
- 不做通用全量 pname 路由，仅实现进程排除相关最小集

## 2. 架构设计（按当前仓库结构落地）

当前仓库已有目录：
- ebpf/
- protocols/

建议在后续实现时增加（本计划先定义职责，不立即写代码）：
- control/：控制面、规则编译、eBPF 加载、TProxy 监听
- shared/：跨模块共享数据结构（可选）

### 2.1 数据平面（ebpf）
职责：
- 在 TC 挂载点解析数据包元信息（五元组、协议、端口）
- 查询规则映射并做直连/代理二选一决策
- 在规则决策前执行进程排除检查（命中则 direct）
- 对代理流量打标并重定向到用户态监听路径
- 对已建立连接使用 conntrack map 快速命中

建议挂载点：
- tc ingress（LAN）
- tc egress（WAN）

第一阶段暂不引入更多挂载点（如 sockops、sk_lookup），降低复杂度。

### 2.4 进程归因约定（用于后续 pname 规则扩展）
- 在 cgroup 相关挂载点采集 socket 事件（如 bind/connect/sendmsg）并建立映射。
- 优先使用 bpf_get_current_task（或 bpf_get_current_task_btf）获取进程上下文。
- 若 bpf_get_current_task 不可用，则回退使用 bpf_get_current_comm。
- 采用 socket cookie 作为主键关联进程与连接信息，避免仅用 pid 带来的复用问题。
- tc 路径不直接依赖 current_task 判定进程归属，而是查询上述映射结果。

### 2.7 进程排除策略（第一阶段必做）
- 目标：避免代理程序自身和指定进程被再次劫持，防止流量回环。
- 排除来源：
  - 代理主进程及其子进程（按 pid/tgid 维护）。
  - 配置文件声明的排除进程名列表（固定长度 comm 匹配）。
  - 宿主侧设置的显式 bypass mark。
- 判定顺序（高到低）：
  1. skb 已带 bypass mark，直接放行。
  2. 通过 socket cookie 查到进程归属且命中排除列表，直接放行。
  3. 未命中排除时，再执行 direct/proxy 规则判断。
- 失效与清理：
  - 在 cgroup sock_release 清理 cookie 映射。
  - 对 pid 相关映射增加 last_seen 时间戳，用户态定期兜底清理。

### 2.2 控制平面（control）
职责：
- 加载/卸载 eBPF 程序与 map
- 解析配置并编译为内核可执行规则
- 维护 SOCKS 出站配置
- 处理代理路径上的 TCP 会话转发
- 输出运行日志与基础指标

### 2.3 协议层（protocols）
职责：
- 提供统一出站接口（OutboundDialer）
- 第一阶段仅实现 Socks5Dialer
- 预留扩展点，后续可接入其他协议

### 2.5 命名空间与链路设计（第一阶段确定）
- TProxy 监听进程运行在单独网络命名空间中，不与宿主网络栈混跑。
- 宿主与代理命名空间通过 veth pair 互联（第一阶段固定使用 veth）。
- eBPF 程序挂在宿主侧接口，命中 proxy 动作后将流量导入 veth 对端，再由命名空间内 TProxy 接管。
- 第一阶段不采用 netkit，待功能稳定后再评估是否以可选驱动方式引入。

### 2.6 命名空间生命周期策略
- 使用匿名 netns（不创建 `/var/run/netns/*` 命名条目），避免持久引用导致泄漏。
- 主进程拉起代理子进程并进入该 netns；子进程设置 `PR_SET_PDEATHSIG` 监听父进程退出。
- 主进程退出时终止 netns 内进程并关闭相关 fd；无引用后命名空间由内核自动回收。
- 控制面需避免长期持有 netns fd，防止命名空间无法销毁。

## 3. 数据流（第一阶段）

### 3.1 首包路径
1. 数据包进入 TC。
2. eBPF 提取五元组并进行规则匹配。
3. eBPF 先执行进程排除检查（bypass mark 或 cookie 归属命中排除列表则 direct）。
4. 未命中排除时进行动作判断：
  - direct：放行。
  - proxy：重定向到 veth 链路并导入代理命名空间。
5. 代理命名空间内 TProxy 监听端口接收连接，并通过 SOCKS5 与上游建立隧道。

### 3.3 命名空间跨域路径
1. 宿主侧识别到 proxy 流量后导入 veth-host。
2. 报文经 veth-peer 进入代理命名空间。
3. 命名空间内 TProxy 处理并发起 SOCKS5 出站。
4. 返回流量经 veth 回到宿主侧后继续常规转发。

### 3.2 后续包路径
1. eBPF 通过 conntrack map 查找既有决策。
2. 命中后直接执行动作，减少重复规则计算。

## 4. 规则模型（MVP）

### 4.1 规则语法（建议）
采用顺序匹配、首条命中：
- 条件：dip、dport、l4proto
- 动作：direct、proxy(组名)
- fallback：未命中时动作（建议默认 proxy(组名) 或 direct，按配置）

示意：
- dip(geoip:private) -> direct
- dport(22) -> direct
- l4proto(tcp) -> proxy(proxy_primary)
- fallback: proxy(proxy_primary)

### 4.2 规则下发策略
- 用户态解析后编译为扁平数组结构写入 map
- eBPF 只做快速判断，不做复杂字符串处理

## 5. 依赖库预估（第一阶段，仅 SOCKS 出站）

## 5.1 Rust 依赖（Cargo）
核心必选：
- aya-ebpf（内核 eBPF 程序）
- aya（用户态加载与 map 管理）
- aya-log-ebpf、aya-log（eBPF 日志）
- tokio（异步运行时）
- socket2（底层 socket 配置）
- nix 或 libc（TProxy/mark 相关系统调用）
- serde（配置序列化）
- ipnet（CIDR 处理）
- thiserror、anyhow（错误处理）
- tracing、tracing-subscriber（日志）
- clap（命令行）

SOCKS 相关：
- socks5-proto（可选，协议编码/解码）
- 若不引库：可自实现 SOCKS5 握手（更可控，但开发成本略高）

建议数量：
- 第一阶段总依赖约 15 到 25 个（含间接依赖除外）

## 5.2 系统依赖（非 Cargo）
- Linux 内核 >= 5.17（建议更高版本）
- clang/llvm（建议 15+）
- bpftool（调试）
- iproute2（tc/ip rule/ip route）
- util-linux（unshare/nsenter 等命名空间工具，便于运维与排障）
- cgroup v2（若后续要做进程名路由）

## 5.3 veth 地址、路由、mark 推荐默认值（第一阶段）

| 项目 | 推荐默认值 | 说明 |
| --- | --- | --- |
| veth 宿主侧名称 | dae0 | 宿主网络命名空间接口名 |
| veth 代理侧名称 | dae0peer | 代理命名空间接口名 |
| 宿主侧地址 | 169.254.100.1/30 | 点对点链路地址（IPv4） |
| 代理侧地址 | 169.254.100.2/30 | 点对点链路地址（IPv4） |
| veth MTU | 1500 | 默认先与宿主主链路一致，后续按压测调整 |
| TProxy 监听端口 | 15080 | 代理命名空间内监听端口 |
| 代理链路路由表 | 20230 | 专用于 tproxy 导流策略路由 |
| fwmark_proxy | 0x02000000 | 标记需导入代理命名空间的流量 |
| fwmark_bypass | 0x04000000 | 标记需跳过劫持与重入检测的流量 |
| fwmark_mask | 0x0f000000 | mark 匹配掩码，覆盖代理相关高位区间 |

配套策略路由建议：
- 使用 `ip rule add fwmark 0x02000000/0x0f000000 table 20230` 将 proxy 流量导入专用路由表。
- 使用 `ip route add local default dev lo table 20230` 配合 TProxy 接管。
- 对 `0x04000000/0x0f000000` 设定优先放行规则，避免代理进程流量被重复劫持。

## 6. 里程碑与排期建议

### M1：骨架与可加载（约 3-5 天）
- 建立项目模块骨架
- 完成 eBPF 对象加载、附着、卸载
- 完成匿名 netns 与 veth pair 的创建、回收流程
- 打通最小日志

验收：
- 程序可启动并成功附着到目标网卡 tc。
- 主进程退出后 netns 与相关子进程可自动回收。

### M2：内核分流闭环（约 5-8 天）
- 实现规则 map 与首包匹配
- 实现 direct/proxy 二动作
- 打通 proxy 流量经 veth 导入代理命名空间路径
- 实现进程排除判定链路（bypass mark + cookie 归因）
- 增加 conntrack map 简单缓存

验收：
- 按规则可稳定直连、代理。
- 代理流量可稳定跨宿主/netns 往返。
- 代理进程及配置排除进程不会被再次劫持。

### M3：SOCKS 出站（约 4-7 天）
- 实现用户态代理入口到 SOCKS5 出站拨号
- 完成 TCP 双向转发与异常关闭处理

验收：
- 代理流量可通过 SOCKS5 成功访问公网目标。

### M4：稳定性与观测（约 3-5 天）
- 增加基础指标与关键事件日志
- 处理常见错误路径（map 满、上游超时、连接中断）

验收：
- 连续压测下进程稳定，无明显连接泄漏。

总计预估：
- 3 到 5 周（1 人，第一阶段仅 SOCKS）

## 7. 验收标准（第一阶段）
- 功能：
  - 支持 TCP 分流
  - 支持 direct/proxy
  - 仅 SOCKS5 出站可用
  - 支持进程排除（代理自身和配置名单）
- 性能：
  - 后续包命中 conntrack，CPU 占用明显低于“全量用户态转发”
- 稳定性：
  - 长连接与并发短连接场景无明显泄漏
- 可运维：
  - 可观测到规则命中统计与关键错误日志

## 8. 主要风险与缓解
- eBPF verifier 复杂度超限：
  - 缓解：规则扁平化、拆分函数、减少分支与循环。
- 内核差异导致行为不一致：
  - 缓解：限定最低内核版本并建立兼容性测试矩阵。
- TProxy 与策略路由配置复杂：
  - 缓解：提供启动时自检与可读错误提示。
- 命名空间与 veth 生命周期管理不当导致资源残留：
  - 缓解：匿名 netns + PDEATHSIG + fd 收敛 + 退出清理顺序校验。
- 进程排除误判导致流量绕过策略：
  - 缓解：先只支持确定性排除源（代理自身 pid/tgid、显式 comm 列表、bypass mark），并记录命中日志便于审计。
- SOCKS 上游不稳定：
  - 缓解：连接超时、重试与熔断（MVP 可先实现超时与失败快返）。

## 9. 下一步（进入实现前）
1. 确认第一阶段是否只做 IPv4。
2. 确认 fallback 默认策略（proxy 或 direct）。
3. 确认 SOCKS 认证方式范围（无认证/用户名密码）。
4. 确认 veth 两端地址规划、MTU 与路由表编号约定。
5. 确认 cgroup 归因最小实现是否随 MVP 一起落地，或先预留接口。
6. 确认进程排除配置格式（按 comm、pid/tgid、或两者并存）。
7. 基于本计划输出模块级接口草案（不写实现）。

## 10. 进程排除配置草案（第一阶段建议稿）

### 10.1 设计目标
- 提供可预测的排除行为，优先满足“防回环”和“代理自身不被重捕获”。
- 在 MVP 阶段只支持确定性排除源：bypass mark、代理自身 pid/tgid、comm 白名单。
- 配置字段保持最小集，避免引入过早复杂度。

### 10.2 配置字段参考（daefile process_exclusion 块）

参见 §11.3 `process_exclusion { ... }` 示例。

### 10.3 字段语义与默认值
- `enabled`：是否开启进程排除能力，默认 `true`。
- `protect_self`：自动排除主进程，默认 `true`。
- `protect_children`：自动排除主进程派生子进程，默认 `true`。
- `bypass_mark`：显式放行 mark，默认 `0x04000000`。
- `bypass_mask`：mark 匹配掩码，默认 `0x0f000000`。
- `gc_interval_sec`：用户态清理陈旧映射周期，默认 `30` 秒。
- `stale_after_sec`：映射超过该时间未刷新即视为陈旧，默认 `120` 秒。
- `match.comm`：按进程名排除列表，建议仅放稳定进程名。
- `match.pid`：按线程 pid 排除，重启后可能变化，仅建议临时使用。
- `match.tgid`：按进程组 id 排除，稳定性优于 pid。

### 10.4 内核侧判定优先级（固定）
1. 若 `skb->mark & bypass_mask == bypass_mark`，直接 `direct`。
2. 若 cookie 归因命中 `pid/tgid/comm` 排除集合，直接 `direct`。
3. 其余流量进入既有 direct/proxy 规则判断。

### 10.5 建议的 Map 规划（MVP）
- `cookie_proc_map`：`cookie -> {pid, tgid, comm, last_seen_ns}`。
- `excluded_comm_map`：`comm_hash -> 1`（或固定 key 数组）。
- `excluded_pid_map`：`pid/tgid -> 1`（用户态维护）。
- `exclusion_stats_map`：记录命中来源计数（mark、comm、pid/tgid）。

### 10.6 控制面更新策略
- 启动时一次性写入 `excluded_comm_map` 与初始 `excluded_pid_map`。
- 运行期支持热更新：先写新配置，再切换生效标记，最后清理旧键。
- 每 `gc_interval_sec` 执行一次陈旧清理，避免 pid 重用造成误判。

### 10.7 验收用例（新增）
1. 代理主进程发起外连，命中排除并直连，不回流至 TProxy。
2. 配置中 comm 命中（如 naiveproxy）时，其流量稳定直连。
3. 未命中排除且命中 proxy 规则的流量可进入 veth + netns 路径。
4. 主进程退出后，排除映射与 netns 相关资源可随进程回收。
5. 人工注入 bypass mark 的流量必定放行且计数可观测。

## 11. 配置体系设计（daefile -> 临时 JSON）

### 11.1 目标与流程
- 面向用户提供类 Caddyfile 的简化配置（后缀 `.daefile`），语法参考 dae。
- 服务启动时自动将 `.daefile` 解析并转换为规范化 JSON（临时文件）。
- 运行时仅消费 JSON 配置，减少核心模块的解析复杂度。

建议启动流程：
1. 读取 `xxx.daefile`。
2. 词法/语法解析得到 AST。
3. 语义校验（字段范围、冲突、引用完整性）。
4. 编译为规范化 JSON 对象。
5. 写入临时 JSON（如 `/run/dae-rs/config.<pid>.<ts>.json`）。
6. 以该 JSON 启动控制面与数据面。
7. 进程退出时删除临时 JSON。

### 11.2 规范化 JSON 结构草案

```json
{
  "version": 1,
  "runtime": {
    "tproxy_port": 15080,
    "log_level": "info",
    "temp_json": true
  },
  "namespace": {
    "mode": "isolated",
    "host_if": "dae0",
    "peer_if": "dae0peer",
    "host_addr": "169.254.100.1/30",
    "peer_addr": "169.254.100.2/30",
    "mtu": 1500,
    "route_table": 20230
  },
  "marks": {
    "proxy": "0x02000000",
    "bypass": "0x04000000",
    "mask": "0x0f000000"
  },
  "process_exclusion": {
    "enabled": true,
    "protect_self": true,
    "protect_children": true,
    "gc_interval_sec": 30,
    "stale_after_sec": 120,
    "match": {
      "comm": ["dae-rs", "naiveproxy"],
      "pid": [],
      "tgid": []
    }
  },
  "outbounds": {
    "nodes": [
      {
        "name": "main",
        "protocol": "socks5",
        "params": {
          "address": "127.0.0.1:1080",
          "username": "",
          "password": "",
          "dial_timeout_ms": 5000
        }
      },
      {
        "name": "backup",
        "protocol": "socks5",
        "params": {
          "address": "127.0.0.1:2080",
          "username": "",
          "password": "",
          "dial_timeout_ms": 5000
        }
      }
    ],
    "groups": [
      {
        "name": "proxy_primary",
        "type": "auto",
        "policy": "min_moving_avg",
        "selectors": [
          { "type": "list", "nodes": ["main", "backup"] }
        ]
      },
      {
        "name": "a_group",
        "type": "auto",
        "policy": "min_avg10",
        "selectors": [
          { "type": "regex", "pattern": ".*" }
        ]
      },
      {
        "name": "manual",
        "type": "select",
        "selected": "main",
        "selectors": [
          { "type": "list", "nodes": ["main", "backup"] }
        ]
      }
    ]
  },
  "routing": {
    "rules": [
      { "match": "dip(geoip:private)", "action": "direct" },
      { "match": "dport(22)", "action": "direct" },
      { "match": "l4proto(tcp)", "action": "proxy(proxy_primary)" }
    ],
    "fallback": "proxy(proxy_primary)"
  }
}
```

JSON 结构说明：
- `version`：配置版本号，用于未来迁移。
- `runtime`：服务运行参数。
- `namespace`：netns + veth + 路由表参数。
- `marks`：proxy/bypass mark 与掩码。
- `process_exclusion`：进程排除策略。
- `outbounds.nodes`：出站节点列表；每个节点必须有唯一 `name`，再定义 `protocol` 与 `params`。
- `outbounds.groups`：出站组列表；每个组必须有唯一 `name`，并通过 `selectors` 选择一个或多个节点。
- `routing`：规则列表与 fallback。

### 11.3 类 Caddyfile 的 daefile 结构草案

语法风格对齐 dae：
- 块结构：`section { ... }`
- 赋值：`key: value`
- 规则：`expr -> action`
- 注释：`#` 开头

示例（`config.daefile`）：

```shell
global {
  tproxy_port: 15080
  log_level: info
}

namespace {
  mode: isolated
  veth_host: dae0
  veth_peer: dae0peer
  host_addr: 169.254.100.1/30
  peer_addr: 169.254.100.2/30
  mtu: 1500
  route_table: 20230
}

mark {
  proxy: 0x02000000
  bypass: 0x04000000
  mask: 0x0f000000
}

process_exclusion {
  enabled: true
  protect_self: true
  protect_children: true
  gc_interval_sec: 30
  stale_after_sec: 120

  match {
    comm(dae-rs, naiveproxy)
    #pid(1234)
    #tgid(1234)
  }
}

outbounds {
  nodes {
    main {
      protocol: socks5
      address: 127.0.0.1:1080
      #username: user
      #password: pass
      dial_timeout_ms: 5000
    }

    backup {
      import: 'socks5://127.0.0.1:2080'
    }
  }

  groups {
    proxy_primary {
      # type: auto           # 默认值，可省略
      # policy: fixed        # 始终选第一个节点
      # policy: random       # 随机选节点
      # policy: min          # 选最近一次延迟最低的节点
      # policy: min_avg10    # 选最近 10 次平均延迟最低的节点
      policy: min_moving_avg # 选移动平均延迟最低的节点（推荐）
      nodes(main, backup)
    }

    a_group {
      type: auto
      policy: min_avg10
      nodes(regex: '*')
    }

    # select 类型：节点由 REST API 手动切换，不自动探测
    manual {
      type: select
      selected: main         # 初始选中节点，可通过 API 动态更新
      nodes(main, backup)
    }
  }
}

routing {
  dip(geoip:private) -> direct
  dport(22) -> direct
  l4proto(tcp) -> proxy(proxy_primary)
  fallback: proxy(proxy_primary)
}
```

### 11.4 daefile 到 JSON 的关键映射

| daefile 路径 | JSON 路径 |
| --- | --- |
| `global.tproxy_port` | `runtime.tproxy_port` |
| `global.log_level` | `runtime.log_level` |
| `namespace.veth_host` | `namespace.host_if` |
| `namespace.veth_peer` | `namespace.peer_if` |
| `namespace.host_addr` | `namespace.host_addr` |
| `namespace.peer_addr` | `namespace.peer_addr` |
| `namespace.mtu` | `namespace.mtu` |
| `namespace.route_table` | `namespace.route_table` |
| `mark.proxy` | `marks.proxy` |
| `mark.bypass` | `marks.bypass` |
| `mark.mask` | `marks.mask` |
| `process_exclusion.match.comm(...)` | `process_exclusion.match.comm[]` |
| `process_exclusion.match.pid(...)` | `process_exclusion.match.pid[]` |
| `process_exclusion.match.tgid(...)` | `process_exclusion.match.tgid[]` |
| `outbounds.nodes.<name>.protocol` | `outbounds.nodes[i].protocol` |
| `outbounds.nodes.<name>.*` | `outbounds.nodes[i].params.*` |
| `outbounds.nodes.<name>.import` | 解析分享链接后写入 `outbounds.nodes[i]` 的 `protocol + params` |
| `outbounds.groups.<name>.type` | `outbounds.groups[i].type`（`auto`/`select`，省略默认 `auto`） |
| `outbounds.groups.<name>.policy` | `outbounds.groups[i].policy`（仅 `auto` 类型需要） |
| `outbounds.groups.<name>.selected` | `outbounds.groups[i].selected`（仅 `select` 类型需要） |
| `outbounds.groups.<name>.nodes(a, b)` | `outbounds.groups[i].selectors += {type:list,nodes:[a,b]}` |
| `outbounds.groups.<name>.nodes(regex: '...')` | `outbounds.groups[i].selectors += {type:regex,pattern:'...'}` |
| `routing` 规则行 | `routing.rules[]` |
| `routing.fallback` | `routing.fallback` |

节点转换规则：
- 节点名 `name` 在同一配置中必须唯一（大小写敏感），否则语义校验失败。
- 节点可用“显式字段”定义（`protocol + 参数`），也可用 `import: '分享链接'` 定义。
- 无论节点来源是显式字段还是 import，后端都转换成统一 JSON 节点结构：`name + protocol + params`。
- 若 import 链接解析出的协议不是第一阶段支持的 `socks/socks5`，则报“协议未实现”。

出站组转换规则：
- 组名 `name` 在同一配置中必须唯一（大小写敏感）。
- 每个组必须至少声明一个选择器（list 或 regex）。
- list 选择器中引用不存在节点时语义校验失败。
- regex 选择器在节点全集上求并集；若最终匹配为空则语义校验失败。
- `routing` 中 `proxy(<group>)` 只能引用已定义组名；引用不存在组时语义校验失败。
- 当 `regex: '*'` 出现时，按兼容语义自动规范化为 `.*`（等价“匹配全部节点”）。
- 正则语法目标为“尽可能完整”：
  - 默认使用 PCRE2 解析（支持更完整语法）。
  - 若构建未启用 PCRE2，则回退 Rust `regex` 能力，并在日志中提示功能降级。

### 11.5 临时 JSON 文件生命周期
- 默认落盘目录：`/run/dae-rs/`（内存文件系统优先）。
- 文件名建议：`config.<pid>.<start_unix_ts>.json`。
- 权限建议：`0600`，仅服务用户可读写。
- 热重载策略：
  - 重新解析 daefile 生成新 JSON。
  - 校验通过后原子替换（rename）。
  - 失败时保持旧 JSON 与旧进程配置继续运行。
- 退出清理：主进程正常退出与异常退出都尝试清理临时 JSON。

### 11.6 错误处理与用户体验
- 语法错误：输出行号、列号、原始片段。
- 语义错误：指出冲突字段和建议修复方式。
- 引用错误：如 `proxy(proxy_primary)` 未定义时给出可用组名列表。
- 节点错误：重复节点名、同时出现 `import` 与显式协议字段、import 无法解析时给出精确报错。
- 组错误：重复组名、组内节点列表为空、组引用未知节点时给出精确报错。
- 正则错误：组内 regex 语法非法或匹配结果为空时给出精确报错。
- 启动失败策略：若 daefile 转换失败，不进入半启动状态，直接失败退出。

### 11.7 第一阶段约束
- `.daefile` 的 `outbounds` 分为两层：`nodes {}` 与 `groups {}`。
- `nodes` 层下节点名必须唯一，`groups` 层下组名必须唯一。
- 节点定义支持两种方式：
  - 显式字段：`protocol: socks5` + 参数。
  - 导入链接：`import: '分享链接'`（格式参考 dae 的分享链接）。
- `routing` 中代理动作必须写为 `proxy(组名)`，不直接引用节点名。
- 组节点选择支持：
  - 显式列表：`nodes(main, backup)`。
  - regex 选择器：`nodes(regex: '...')`，兼容 `nodes(regex: '*')`。- 组类型（`type`）支持两个值：
  - `auto`（默认，可省略）：根据 `policy` 自动选节点，支持探测延迟切换。
  - `select`：节点由运维人员或 REST API 手动指定，不做自动探测切换。
- `auto` 组的 `policy` 枚举（与 dae 对齐）：
  - `fixed`：始终选列表第一个存活节点（默认值）。
  - `random`：从存活节点中随机选取。
  - `min`：选最近一次探测延迟最低的节点。
  - `min_avg10`：选最近 10 次探测平均延迟最低的节点。
  - `min_moving_avg`：选移动平均延迟最低的节点（推荐）。
- `select` 组必须指定 `selected` 字段（初始选中节点名）；不需要也不应出现 `policy` 字段。- 第一阶段 import 只接受可解析为 `socks/socks5` 的链接；其他协议报“未实现”。
- 仅支持 direct/proxy 两类 routing 动作。
- JSON 中不暴露未实现字段，避免给出误导性兼容承诺。

## 12. daefile 语法规范与校验清单（实现草案）

### 12.1 词法约定（简化）
- 注释：`#` 到行尾。
- 空白：空格、Tab、换行；仅用于分隔 token。
- 标识符：`[A-Za-z_][A-Za-z0-9_-]*`。
- 十六进制：`0x` 前缀。
- 字符串：支持单引号或双引号。
- 裸值：未加引号的字母数字与常见符号组合（如 `info`、`127.0.0.1:1080`）。

### 12.2 EBNF（第一阶段）

```ebnf
File              = { Section } ;

Section           = GlobalSection
                  | NamespaceSection
                  | MarkSection
                  | ProcessExclusionSection
                  | OutboundsSection
                  | RoutingSection ;

GlobalSection     = "global" BlockGlobal ;
NamespaceSection  = "namespace" BlockNamespace ;
MarkSection       = "mark" BlockMark ;
ProcessExclusionSection = "process_exclusion" BlockProcessExclusion ;
OutboundsSection  = "outbounds" BlockOutbounds ;
RoutingSection    = "routing" BlockRouting ;

BlockGlobal       = "{" { GlobalStmt } "}" ;
GlobalStmt        = "tproxy_port" ":" Int
                  | "log_level" ":" Value ;

BlockNamespace    = "{" { NamespaceStmt } "}" ;
NamespaceStmt     = "mode" ":" Value
                  | "veth_host" ":" Value
                  | "veth_peer" ":" Value
                  | "host_addr" ":" Value
                  | "peer_addr" ":" Value
                  | "mtu" ":" Int
                  | "route_table" ":" Int ;

BlockMark         = "{" { MarkStmt } "}" ;
MarkStmt          = "proxy" ":" Hex
                  | "bypass" ":" Hex
                  | "mask" ":" Hex ;

BlockProcessExclusion = "{" { ProcessExclusionStmt } "}" ;
ProcessExclusionStmt  = "enabled" ":" Bool
                      | "protect_self" ":" Bool
                      | "protect_children" ":" Bool
                      | "gc_interval_sec" ":" Int
                      | "stale_after_sec" ":" Int
                      | MatchBlock ;

MatchBlock        = "match" "{" { MatchStmt } "}" ;
MatchStmt         = "comm" "(" IdentList ")"
                  | "pid" "(" IntList ")"
                  | "tgid" "(" IntList ")" ;

BlockOutbounds    = "{" NodesLayer GroupsLayer "}" ;
NodesLayer        = "nodes" "{" { NodeDecl } "}" ;
NodeDecl          = Ident "{" { NodeStmt } "}" ;
NodeStmt          = "protocol" ":" Value
                  | "import" ":" String
                  | "address" ":" Value
                  | "username" ":" Value
                  | "password" ":" Value
                  | "dial_timeout_ms" ":" Int ;

GroupsLayer       = "groups" "{" { GroupDecl } "}" ;
GroupDecl         = Ident "{" { GroupStmt } "}" ;
GroupStmt         = "type" ":" GroupType
                  | "policy" ":" PolicyValue
                  | "selected" ":" Ident
                  | "nodes" "(" NodeSelectorList ")" ;

GroupType         = "auto" | "select" ;
PolicyValue       = "fixed" | "random" | "min" | "min_avg10" | "min_moving_avg" ;

NodeSelectorList  = NodeSelector { "," NodeSelector } ;
NodeSelector      = Ident
                  | "regex" ":" String ;

BlockRouting      = "{" { RoutingStmt } "}" ;
RoutingStmt       = RuleStmt | FallbackStmt ;
RuleStmt          = Expr "->" Action ;
FallbackStmt      = "fallback" ":" Action ;
Action            = "direct"
                  | "proxy" "(" Ident ")" ;

Expr              = Value ;

IdentList         = Ident { "," Ident } ;
IntList           = Int { "," Int } ;

Bool              = "true" | "false" ;
Hex               = "0x" HexDigit { HexDigit } ;
Int               = Digit { Digit } ;
String            = SingleQuoted | DoubleQuoted ;
Value             = String | Bare ;
Bare              = BareChar { BareChar } ;
```

说明：
- `Expr` 在 MVP 中按“整行原样保留”为字符串，由路由表达式解析器二阶段处理。
- `NodesLayer` 与 `GroupsLayer` 在 `outbounds` 内均为必选层，允许为空但需通过语义校验进一步约束。

### 12.3 语义校验顺序（建议）
1. 结构校验：section/block 结构完整性。
2. 类型校验：整数、布尔、十六进制、字符串格式正确。
3. 值域校验：端口、MTU、路由表、超时等范围合法。
4. 唯一性校验：节点名、组名不重复。
5. 引用校验：组内节点引用存在；`proxy(组名)` 引用存在。
5.1 选择器校验：组内 regex 可成功编译。
5.2 选择器求值：regex/list 选择器求并集后结果非空。
6. 互斥校验：节点内 `import` 与显式 `protocol` 同时出现时报错。
7. 协议校验：第一阶段仅允许 `socks/socks5`。
8. 产物校验：可成功归一化生成 JSON 且字段完整。

### 12.4 字段校验规则（第一阶段）
- `global.tproxy_port`：`1..65535`。
- `namespace.mtu`：`576..9000`（建议默认 1500）。
- `namespace.route_table`：`1..4294967295`。
- `mark.proxy/bypass/mask`：必须为十六进制；`proxy & mask != 0`，`bypass & mask != 0`。
- `process_exclusion.gc_interval_sec`：`1..3600`。
- `process_exclusion.stale_after_sec`：`>= gc_interval_sec`。
- `outbounds.nodes.<name>.dial_timeout_ms`：`100..600000`。
- `outbounds.nodes.<name>`：
  - 显式模式：必须存在 `protocol` 与 `address`。
  - import 模式：必须存在 `import`，且不能同时声明 `protocol/address/...`。
- `outbounds.groups.<name>.nodes(...)`：至少一个选择器。
- `outbounds.groups.<name>.type`：枚举 `auto`/`select`，省略默认 `auto`。
- `auto` 组：
  - `policy` 必须是 `fixed`/`random`/`min`/`min_avg10`/`min_moving_avg` 之一；省略时默认 `fixed`。
  - 不允许出现 `selected` 字段。
- `select` 组：
  - 必须有 `selected` 字段，且 `selected` 必须能在该组的选择器求值集合中命中至少一个节点名。
  - 不允许出现 `policy` 字段。
- `outbounds.groups.<name>.nodes(regex: '...')`：
  - regex 必须可编译。
  - 若值为 `"*"`，先规范化为 `".*"` 再编译。
  - 选择结果至少命中一个节点。
- `routing.fallback`：必填，且必须是 `direct` 或 `proxy(已定义组)`。

### 12.5 诊断码建议（用于 CLI 输出）
- `E1001`：语法错误（含行列信息）。
- `E1101`：缺少必选 section（如 `outbounds`、`routing`）。
- `E1201`：字段类型错误。
- `E1202`：字段值越界。
- `E1301`：节点名重复。
- `E1302`：组名重复。
- `E1401`：组引用未知节点。
- `E1402`：路由引用未知组。
- `E1501`：节点同时声明 `import` 与显式字段。
- `E1502`：import 链接不可解析或协议未实现。
- `E1601`：group regex 语法非法。
- `E1602`：group regex 匹配为空。
- `E1701`：`select` 组缺少 `selected` 字段。
- `E1702`：`select` 组的 `selected` 字段引用节点不在组可达集合内。
- `E1703`：`select` 组出现了 `policy` 字段（互斥）。
- `E1704`：`auto` 组出现了 `selected` 字段（互斥）。
- `W1801`：`auto` 组未指定 `policy`，已使用默认值 `fixed`（警告级）。
- `E1203`：`policy` 字段值非法（不在 `fixed`/`random`/`min`/`min_avg10`/`min_moving_avg` 范围内）。

### 12.6 最小合法示例（用于单元测试）

```shell
global {
  tproxy_port: 15080
  log_level: info
}

outbounds {
  nodes {
    main {
      protocol: socks5
      address: 127.0.0.1:1080
      dial_timeout_ms: 5000
    }
  }
  groups {
    proxy_primary {
      policy: fixed
      nodes(main)
    }

    a_group {
      type: auto
      policy: min_avg10
      nodes(regex: '*')
    }

    manual {
      type: select
      selected: main
      nodes(main)
    }
  }
}

routing {
  l4proto(tcp) -> proxy(proxy_primary)
  fallback: proxy(proxy_primary)
}
```

## 13. REST API 设计（控制接口）

### 13.1 设计原则
- 资源导向：URL 表示资源，HTTP 方法表示操作，不在 URL 中出现动词。
- 版本前缀：所有端点以 `/api/v1/` 开头，便于未来不兼容变更。
- 传输：默认启用 TLS（HTTPS），开发模式可通过配置项降级为 HTTP。
- 认证：通过 Bearer Token（静态密钥，在配置文件中设置），MVP 可先用固定 Token。
- 请求/响应格式：`Content-Type: application/json`。
- 错误格式：`{ "code": "E_XXXX", "message": "..." }`。
- 状态码：严格遵循语义（200/201/204/400/401/404/409/422/500）。

### 13.2 配置（daefile 中）

```shell
api {
  enabled: true
  listen: 127.0.0.1:9090    # 监听地址，建议仅本地
  tls: true                  # 是否启用 TLS
  cert: /etc/dae-rs/api.crt  # TLS 证书路径（tls: true 时必填）
  key: /etc/dae-rs/api.key   # TLS 私钥路径
  token: 'your-secret-token' # Bearer Token，不可为空
}
```

对应 JSON 字段（`runtime.api`）：
```json
"api": {
  "enabled": true,
  "listen": "127.0.0.1:9090",
  "tls": true,
  "cert": "/etc/dae-rs/api.crt",
  "key": "/etc/dae-rs/api.key",
  "token": "your-secret-token"
}
```

### 13.3 端点清单

#### 系统状态

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/api/v1/status` | 返回运行状态（uptime、版本、eBPF 加载状态） |
| `GET` | `/api/v1/metrics` | 返回基础指标（连接数、规则命中计数、bypass 计数） |

`GET /api/v1/status` 响应示例：
```json
{
  "version": "0.1.0",
  "uptime_sec": 3600,
  "ebpf": { "loaded": true, "programs": ["tc_ingress", "tc_egress"] },
  "tproxy_port": 15080,
  "netns": "active"
}
```

#### 节点

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/api/v1/nodes` | 列出所有节点及其当前延迟快照 |
| `GET` | `/api/v1/nodes/{name}` | 查询单个节点详情 |

`GET /api/v1/nodes` 响应示例：
```json
[
  {
    "name": "main",
    "protocol": "socks5",
    "address": "127.0.0.1:1080",
    "alive": true,
    "latency_ms": { "last": 42, "avg10": 45, "moving_avg": 43 }
  }
]
```

#### 出站组

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/api/v1/groups` | 列出所有出站组 |
| `GET` | `/api/v1/groups/{name}` | 查询单个组详情（含当前选中节点） |
| `PUT` | `/api/v1/groups/{name}/policy` | 修改 `auto` 组的策略（热更新，无需重启） |
| `PUT` | `/api/v1/groups/{name}/selected` | 修改 `select` 组当前选中节点 |

`GET /api/v1/groups/{name}` 响应示例（auto 组）：
```json
{
  "name": "proxy_primary",
  "type": "auto",
  "policy": "min_moving_avg",
  "active_node": "backup",
  "nodes": ["main", "backup"]
}
```

`GET /api/v1/groups/{name}` 响应示例（select 组）：
```json
{
  "name": "manual",
  "type": "select",
  "selected": "main",
  "nodes": ["main", "backup"]
}
```

`PUT /api/v1/groups/{name}/policy` 请求体：
```json
{ "policy": "random" }
```
- 仅对 `type: auto` 的组有效；对 `select` 组返回 `422 Unprocessable Entity`。

`PUT /api/v1/groups/{name}/selected` 请求体：
```json
{ "selected": "backup" }
```
- 仅对 `type: select` 的组有效；对 `auto` 组返回 `422 Unprocessable Entity`。
- `selected` 节点必须在该组可达集合内，否则返回 `422`。
- 切换立即生效，新连接使用新节点，旧连接不强制中断。

#### 路由规则

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/api/v1/routing` | 查看当前生效的规则列表和 fallback |

> 第一阶段不支持通过 API 动态修改路由规则（规则变更通过重载配置触发）。

#### 配置重载

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/api/v1/reload` | 触发配置热重载（重新解析 daefile，原子替换 JSON，不中断已有连接） |

`POST /api/v1/reload` 响应：
```json
{ "status": "reloaded", "config_ts": 1748822400 }
```
- 重载失败时返回 `500`，附带错误详情；原配置继续运行。

### 13.4 认证方式

所有请求须携带 `Authorization: Bearer <token>` 头。Token 在 `api.token` 字段中静态配置。缺失或错误时返回 `401 Unauthorized`。

MVP 不支持多 Token 或 RBAC，仅单一静态 Token。

### 13.5 EBNF 补充（api section）

```ebnf
ApiSection        = "api" BlockApi ;
BlockApi          = "{" { ApiStmt } "}" ;
ApiStmt           = "enabled" ":" Bool
                  | "listen" ":" Value
                  | "tls" ":" Bool
                  | "cert" ":" Value
                  | "key" ":" Value
                  | "token" ":" String ;
```

对应补充到 §12.2 的 `Section` 产生式：
```ebnf
Section           = GlobalSection
                  | NamespaceSection
                  | MarkSection
                  | ProcessExclusionSection
                  | OutboundsSection
                  | RoutingSection
                  | ApiSection ;
```

### 13.6 字段校验规则（补充）
- `api.listen`：必须是合法的 `host:port` 格式，port 范围 `1..65535`。
- `api.token`：不可为空字符串；长度建议 ≥ 16 字符（W 级警告若过短）。
- `api.tls` 为 `true` 时：`cert` 与 `key` 均必填，文件路径必须存在且可读。
- `api.tls` 为 `false` 时：`cert` 与 `key` 可省略；启动时输出安全警告（`W_API_NO_TLS`）。

### 13.7 诊断码补充（api）
- `E1901`：`api.listen` 格式非法。
- `E1902`：`api.token` 为空。
- `E1903`：`api.tls: true` 但 `cert`/`key` 未指定。
- `E1904`：`api.cert`/`api.key` 路径不存在或不可读。
- `W1901`：`api.tls: false`，API 以明文 HTTP 运行（安全警告）。
- `W1902`：`api.token` 长度过短（< 16 字符）。

### 13.8 第一阶段约束
- `PUT /api/v1/groups/{name}/selected` 切换仅影响新建连接，已有连接不重置。
- `PUT /api/v1/groups/{name}/policy` 变更同步写入运行时状态，不持久化到 daefile（重启后恢复配置值）。
- API 监听与 TProxy 监听互相独立，分别绑定不同端口。
- 第一阶段不支持 WebSocket 订阅或 SSE 事件流。
