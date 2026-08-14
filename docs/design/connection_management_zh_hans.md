# 长连接管理设计

> 双语文档。英文版本见 [`connection_management_en.md`](./connection_management_en.md)。

## 1. 范围

本文档描述 dae-rs 目前对长连接的管理方式（`control/src/net/tproxy.rs`、
`control/src/net/udp_tracker.rs`、`control/src/net/ebpf.rs`、
`bpf/kern/tproxy.c`），识别可能导致长连接被突然中断的失败模式，
与参考实现 Go 版 **kdae** 对比，并给出改进方案。

## 2. 当前实现

### 2.1 分层连接管理

dae-rs 采用**分层池化 + 惰性创建 + 超时回收**架构：

| 层级 | 组件 | 键 | 容量 / 超时 |
|------|------|-----|-------------|
| TCP 中继 | `handle_connection` → `relay_bidirectional` | 按连接 | 无空闲超时 |
| UDP flow 池 | `UdpFlowPool` | `(dest, peer)` | 30s 空闲（硬编码） |
| UDP 回包 socket 池 | `RespSocketPool` | `dest` | 256（LRU） |
| UDP 连接状态追踪器 | `UdpConnStateTracker` | `TuplesKey` | 10s / 300s 两阶段 |
| eBPF conn_state | `conn_state_map` | 五元组 | 内核 120s backstop |
| 用户态 janitor | `janitor_scan_conn_state` | 五元组 | 稳态 5s / 压力 1s |

### 2.2 eBPF conn_state 布局

```c
struct tuples_key {            // 37 字节
    union ip6 sip;             // 16
    union ip6 dip;             // 16
    __u16 sport;               //  2
    __u16 dport;               //  2
    __u8  l4proto;             //  1  ← 字节偏移 36
};

// conn_state 值：is_wan_ingress(1) + state(1) + padding(6) + last_seen_ns(8)
```

`state` 字段使用 `tproxy.c` 中定义的**自定义枚举**：

```c
TCP_STATE_ACTIVE  = 0,
TCP_STATE_CLOSING = 1,   // 已观测到 FIN 或 RST
```

UDP 条目将 `state` 保持为 `TCP_STATE_ACTIVE`（`tproxy.c:423`）。

## 3. 会导致长连接中断的失败模式

### 3.1 TCP：无 half-close 保护

`relay_bidirectional`（`tproxy.rs:1008`）并行运行两个方向的拷贝。当一个方向
遇到 EOF 时，只对对端调用 `shutdown(SHUT_WR)`；如果对端既不再发送数据也
不关闭连接，另一方向会在 `read()` 上**永久阻塞**。没有超时来强制解除阻塞，
导致：

- 对端停发数据但保持 socket 打开时，relay 任务泄漏；
- 中间 NAT/防火墙静默丢弃空闲路径时，直到内核 TCP keepalive（默认 2 小时）
  才被发现。

参考（kdae）：`relayHalfCloseTimeout = 10s` + `forceClose()`，通过
`SetReadDeadline(past)` 强制解除阻塞读。

### 3.2 TCP：用户态 janitor 在 120s 后删除 ACTIVE 条目

`janitor_scan_conn_state`（`ebpf.rs:2512`）对任何非 CLOSING 状态使用 120s
超时。由于 §3.3 中的状态值 bug，**所有**条目（包括 TCP ACTIVE 和 UDP）都按
120s 默认值判断，因此空闲超过 120s 的 TCP 长连接的 `conn_state_map` 条目会
被删除。删除条目会丢失缓存的路由元数据（outbound/mark/must），迫使下一个
数据包重新走完整路由；还可能使环路保护状态失效。

内核自身**永远不会**让 TCP ACTIVE 条目过期 —— `tcp_conn_state_expired`
（`tproxy.c:2161`）只对 `TCP_STATE_CLOSING` 返回 true。因此用户态 janitor
与内核的生命周期语义相矛盾。

### 3.3 BUG：状态常量不匹配

`ebpf.rs:2520` 定义了：

```rust
const TCP_CLOSING: u8 = 7;   // include/uapi/linux/tcp.h 中的 TCP_CLOSING
```

但 `conn_state.state` 字段使用上述自定义枚举，其中 `TCP_STATE_CLOSING = 1`。
比较 `state == 7` **永远不会成立**，导致：

- TCP CLOSING 条目无法按预期的 10s 窗口清理（泄漏）；
- 所有条目统一落入 120s 默认分支。

### 3.4 UDP：单一 30s 空闲超时

`UDP_FLOW_IDLE_TIMEOUT = 30s`（`tproxy.rs:73`）应用于所有 UDP flow。QUIC
（可能空闲数分钟）在 30s 后被拆除，尽管内核 `conn_state_map` 会保留 UDP
条目 120s（`UDP_CONN_STATE_TIMEOUT_NS`）。参考（kdae）使用分级超时：
`DefaultNatTimeout = 30s`、`QuicNatTimeout = 2min`、`DnsNatTimeout = 17s`
（RFC 5452）。

### 3.5 UDP：无写 deadline

上游 `session.send()`（`tproxy.rs:1862`）和回包 `sock.send_to()`
（`tproxy.rs:1993`）都没有超时。如果代理上游停滞或客户端停止读取，发送路径
可能无限期阻塞。参考（kdae）：`armWriteDeadline()` 每 T/2 窗口重置 10s 写
超时。

### 3.6 其他

- `RespSocketPool` 淘汰（LRU，上限 256）时无日志。
- DNS-over-TCP 劫持使用硬编码的 5s 超时。
- `UdpConnStateTracker` 已实现 retain/release 两阶段清理，功能上等价于
  kdae 的 "pinned" 概念。

## 4. 与 kdae 的对比

| 机制 | dae-rs（改进前） | kdae（参考） |
|------|------------------|--------------|
| TCP half-close 超时 | 无 | 10s + forceClose |
| TCP ACTIVE conn_state 过期 | 120s（用户态） | 永不（内核负责） |
| conn_state 状态常量 | 有 bug（`7` vs 自定义 `1`） | n/a |
| UDP NAT 超时分级 | 单一 30s | 30s / 2min / 17s |
| UDP 写 deadline | 无 | 10s 窗口 |
| janitor 扫描节奏 | 5s / 1s 压力 | 1s / 5s / 30s 退避 |
| eBPF UDP backstop | 120s | 2min（QUIC）/ 17s（DNS） |

## 5. 改进方案

### P0 — 关键缺陷（已实现）

| # | 改动 | 文件 |
|---|------|------|
| 1 | 添加 half-close 保护：当一个中继方向完成时，给另一方 `RELAY_HALF_CLOSE_TIMEOUT`（10s）优雅关闭，否则强制关闭整个连接 | `tproxy.rs` |
| 2 | 为 UDP 上游发送与回包发送添加写 deadline 保护 | `tproxy.rs` |
| 3 | 修正 `TCP_STATE_CLOSING` 常量不匹配（`1` 而非 `7`）；用户态不再删除 TCP ACTIVE 条目；为压力模式下的陈旧 ACTIVE 条目添加 backstop | `ebpf.rs` |
| 4 | UDP 空闲超时分级（DNS 17s / 默认 30s / QUIC 2min） | `tproxy.rs` |

### P1 — 后续加固

| # | 改动 | 文件 |
|---|------|------|
| 5 | `RespSocketPool` 淘汰时记录 WARN 日志 | `tproxy.rs` |
| 6 | 添加第三档 janitor 扫描节奏（最大退避 30s） | `lib.rs` |
| 7 | DNS-over-TCP 劫持超时改为可配置 | `tproxy.rs` |

## 6. 实现细节

### 6.1 Half-close 保护

```rust
const RELAY_HALF_CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

enum RelaySide { Up, Down }

/// 当一个中继方向完成时，最多等待 RELAY_HALF_CLOSE_TIMEOUT 让另一方向完成。
/// 超时则返回错误，由调用方关闭连接（镜像 kdae 的 forceClose）。
async fn half_close_guard<F1, F2>(
    f1: F1, f2: F2,
) -> std::io::Result<(u64, u64)>
where
    F1: Future<Output = std::io::Result<u64>> + Unpin,
    F2: Future<Output = std::io::Result<u64>> + Unpin,
{
    tokio::pin!(f1);
    tokio::pin!(f2);

    let (first, side) = tokio::select! {
        r = &mut f1 => (r, RelaySide::Up),
        r = &mut f2 => (r, RelaySide::Down),
    };
    let first = first?;

    let second = tokio::time::timeout(RELAY_HALF_CLOSE_TIMEOUT, async {
        match side {
            RelaySide::Up => (&mut f2).await,
            RelaySide::Down => (&mut f1).await,
        }
    })
    .await;

    match second {
        Ok(Ok(b)) => Ok(match side {
            RelaySide::Up => (first, b),
            RelaySide::Down => (b, first),
        }),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "relay half-close timed out, forcing connection close",
        )),
    }
}
```

splice 路径与缓冲拷贝路径都经由该 guard 处理。

### 6.2 UDP 写 deadline

用 `tokio::time::timeout(UDP_WRITE_TIMEOUT, ...)` 包装上游 `session.send()`
与回包 `sock.send_to()`，其中 `UDP_WRITE_TIMEOUT = 10s`。超时后记录 debug
日志并丢弃该 flow/响应。

### 6.3 Janitor 状态修复 + TCP ACTIVE 语义

- 使用 `TCP_STATE_CLOSING = 1`（自定义枚举，而非 linux tcp.h 的 `7`）。
- 从 key 字节偏移 36 解码 `l4proto`，区分 TCP（6）与 UDP（17）。
- 稳态下**永不删除** TCP ACTIVE 条目（生命周期由内核负责）。压力模式
  （使用率 >70%）下，删除空闲超过 `TCP_ACTIVE_PRESSURE_TIMEOUT_NS`
  （10min）的 ACTIVE 条目作为回收 backstop。
- TCP CLOSING 条目：10s 超时。
- UDP 条目：120s backstop（与内核一致），主要清理由
  `UdpConnStateTracker` 负责。

### 6.4 UDP 空闲超时分级

```rust
fn udp_flow_idle_timeout(dest: SocketAddr) -> Duration {
    match dest.port() {
        443 => QUIC_UDP_IDLE_TIMEOUT,    // 2min（QUIC/DTLS 长连接）
        _   => UDP_FLOW_IDLE_TIMEOUT,    // 30s（默认）
    }
}
```

> 注：DNS 被视为普通流量（DNS 劫持模块已移除），端口 53 不再有专用的 17s 档，使用默认超时。

## 7. 验证计划

1. `cargo build` 与 `cargo test`（为 `half_close_guard`、
   `udp_flow_idle_timeout`、janitor 状态/l4proto 解码添加单元测试）。
2. `cargo clippy` 保持代码无 lint 告警。
3. 手动：通过代理建立长 TCP 连接（如 SSH），停止发送超过 2 分钟，确认 relay
   任务未被拆除且流量可正确恢复。
4. 手动：建立 QUIC flow，空闲超过 30s，确认 flow 保留至 2min QUIC 超时。
5. 观察 janitor 日志：TCP CLOSING 条目约 10s 清理；TCP ACTIVE 条目在稳态下
   不被删除。
