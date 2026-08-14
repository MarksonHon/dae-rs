# Long Connection Management Design

> Bilingual documentation. The Chinese version is available at
> [`connection_management_zh_hans.md`](./connection_management_zh_hans.md).

## 1. Scope

This document describes how dae-rs manages long-lived connections today
(`control/src/net/tproxy.rs`, `control/src/net/udp_tracker.rs`,
`control/src/net/ebpf.rs`, `bpf/kern/tproxy.c`), identifies the failure modes
that can cause a long-lived connection to be abruptly torn down, compares the
approach with the reference Go implementation **kdae**, and specifies the
improvement plan.

## 2. Current Implementation

### 2.1 Layered Connection Management

dae-rs uses a **layered pooling + lazy creation + timeout reclamation**
architecture:

| Layer | Component | Key | Capacity / Timeout |
|-------|-----------|-----|--------------------|
| TCP relay | `handle_connection` → `relay_bidirectional` | per-connection | no idle timeout |
| UDP flow pool | `UdpFlowPool` | `(dest, peer)` | 30 s idle (hard-coded) |
| UDP response socket pool | `RespSocketPool` | `dest` | 256 (LRU) |
| UDP conn state tracker | `UdpConnStateTracker` | `TuplesKey` | 10 s / 300 s two-phase |
| eBPF conn_state | `conn_state_map` | 5-tuple | kernel 120 s backstop |
| userspace janitor | `janitor_scan_conn_state` | 5-tuple | 5 s steady / 1 s pressure |

### 2.2 eBPF conn_state Layout

```c
struct tuples_key {            // 37 bytes
    union ip6 sip;             // 16
    union ip6 dip;             // 16
    __u16 sport;               //  2
    __u16 dport;               //  2
    __u8  l4proto;             //  1  ← byte offset 36
};

// conn_state value: is_wan_ingress(1) + state(1) + padding(6) + last_seen_ns(8)
```

The `state` field uses a **custom enum** defined in `tproxy.c`:

```c
TCP_STATE_ACTIVE  = 0,
TCP_STATE_CLOSING = 1,   // FIN or RST seen
```

UDP entries leave `state` as `TCP_STATE_ACTIVE` (`tproxy.c:423`).

## 3. Failure Modes That Tear Down Long-lived Connections

### 3.1 TCP: no half-close protection

`relay_bidirectional` (`tproxy.rs:1008`) runs two directional copies in
parallel. When one direction hits EOF it only calls `shutdown(SHUT_WR)` on the
peer; the other direction keeps blocking on `read()` forever if the peer never
sends another byte nor closes. There is **no timeout to force the blocked
direction to give up**, so:

- a peer that stops sending but keeps the socket open leaks the relay task;
- a NAT/firewall in the middle that silently drops the idle path is never
  detected until kernel TCP keepalive (default 2 h) fires.

Reference (kdae): `relayHalfCloseTimeout = 10 s` + `forceClose()` which unblocks
a pending read via `SetReadDeadline(past)`.

### 3.2 TCP: userspace janitor deletes ACTIVE entries after 120 s

`janitor_scan_conn_state` (`ebpf.rs:2512`) treats any non-CLOSING state with a
120 s timeout. Because of the state-value bug described in §3.3 below, **every**
entry (including TCP ACTIVE and UDP) is judged with the 120 s default, so an
idle TCP connection (no traffic for >120 s) gets its `conn_state_map` entry
deleted. Deleting the entry drops the cached routing metadata
(outbound/mark/must), forcing the next packet to re-run full routing; it can
also invalidate loop-protection state.

The kernel itself never expires TCP ACTIVE entries — `tcp_conn_state_expired`
(`tproxy.c:2161`) only ever returns true for `TCP_STATE_CLOSING`. The userspace
janitor therefore contradicts the kernel's lifecycle semantics.

### 3.3 BUG: state constant mismatch

`ebpf.rs:2520` defines:

```rust
const TCP_CLOSING: u8 = 7;   // include/uapi/linux/tcp.h TCP_CLOSING
```

but the `conn_state.state` field uses the custom enum above where
`TCP_STATE_CLOSING = 1`. The comparison `state == 7` is **never true**, so:

- TCP CLOSING entries are never cleaned at the intended 10 s window (leak);
- all entries uniformly fall into the 120 s default branch.

### 3.4 UDP: single 30 s idle timeout

`UDP_FLOW_IDLE_TIMEOUT = 30 s` (`tproxy.rs:73`) applies to every UDP flow. QUIC
(which can idle for minutes) gets torn down after 30 s even though the kernel
`conn_state_map` keeps UDP entries for 120 s (`UDP_CONN_STATE_TIMEOUT_NS`).
Reference (kdae) uses tiered timeouts: `DefaultNatTimeout = 30 s`,
`QuicNatTimeout = 2 min`, `DnsNatTimeout = 17 s` (RFC 5452).

### 3.5 UDP: no write deadline

Both `session.send()` (`tproxy.rs:1862`, upstream direction) and the response
`sock.send_to()` (`tproxy.rs:1993`, client direction) have no timeout. If the
proxy upstream stalls or the client stops reading, the send path can block a
goroutine/task indefinitely. Reference (kdae): `armWriteDeadline()` resets a
10 s write deadline every T/2 window.

### 3.6 Others

- `RespSocketPool` eviction (LRU, cap 256) drops a socket with no log.
- DNS-over-TCP hijack uses a hard-coded 5 s timeout.
- `UdpConnStateTracker` already implements retain/release two-phase cleanup,
  which is functionally equivalent to kdae's "pinned" concept.

## 4. Comparison With kdae

| Mechanism | dae-rs (before) | kdae (reference) |
|-----------|-----------------|------------------|
| TCP half-close timeout | none | 10 s + forceClose |
| TCP ACTIVE conn_state expiry | 120 s (userspace) | never (kernel owns) |
| conn_state state constant | buggy (`7` vs custom `1`) | n/a |
| UDP NAT timeout tiers | single 30 s | 30 s / 2 min / 17 s |
| UDP write deadline | none | 10 s windowed |
| janitor scan cadence | 5 s / 1 s pressure | 1 s / 5 s / 30 s backoff |
| eBPF UDP backstop | 120 s | 2 min (QUIC) / 17 s (DNS) |

## 5. Improvement Plan

### P0 — Critical defects (implemented)

| # | Change | File |
|---|--------|------|
| 1 | Add half-close guard: when one relay direction finishes, give the other `RELAY_HALF_CLOSE_TIMEOUT` (10 s) to close gracefully, else force-close the whole connection | `tproxy.rs` |
| 2 | Add write deadline protection for UDP upstream send and response send | `tproxy.rs` |
| 3 | Fix `TCP_STATE_CLOSING` mismatch (`1`, not `7`); stop deleting TCP ACTIVE entries from userspace; add a pressure-mode backstop for stale ACTIVE entries | `ebpf.rs` |
| 4 | Tiered UDP idle timeout (DNS 17 s / default 30 s / QUIC 2 min) | `tproxy.rs` |

### P1 — Follow-up hardening

| # | Change | File |
|---|--------|------|
| 5 | Log LRU eviction in `RespSocketPool` (warn on evict) | `tproxy.rs` |
| 6 | Add third janitor cadence tier (30 s max backoff) | `lib.rs` |
| 7 | Make DNS-over-TCP hijack timeout configurable | `tproxy.rs` |

## 6. Implementation Details

### 6.1 Half-close guard

```rust
const RELAY_HALF_CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

enum RelaySide { Up, Down }

/// When one relay direction finishes, wait at most RELAY_HALF_CLOSE_TIMEOUT
/// for the other. On timeout, return an error so the caller drops the
/// connection (mirrors kdae's forceClose).
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

Both the splice path and the buffered-copy path are routed through the guard.

### 6.2 UDP write deadline

Wrap upstream `session.send()` and response `sock.send_to()` with
`tokio::time::timeout(UDP_WRITE_TIMEOUT, ...)` where
`UDP_WRITE_TIMEOUT = 10 s`. On timeout, log at debug and drop the flow/response.

### 6.3 Janitor state fix + TCP ACTIVE semantics

- Use `TCP_STATE_CLOSING = 1` (custom enum, not linux tcp.h `7`).
- Decode `l4proto` from key byte offset 36 to distinguish TCP (6) vs UDP (17).
- TCP ACTIVE entries are never deleted in steady state (kernel owns the
  lifecycle). In pressure mode (>70 % usage), delete ACTIVE entries idle longer
  than `TCP_ACTIVE_PRESSURE_TIMEOUT_NS` (10 min) as a reclamation backstop.
- TCP CLOSING entries: 10 s timeout.
- UDP entries: 120 s backstop (matches kernel), primary cleanup handled by
  `UdpConnStateTracker`.

### 6.4 Tiered UDP idle timeout

```rust
fn udp_flow_idle_timeout(dest: SocketAddr) -> Duration {
    match dest.port() {
        443 => QUIC_UDP_IDLE_TIMEOUT,    // 2 min (QUIC/DTLS long-lived)
        _   => UDP_FLOW_IDLE_TIMEOUT,    // 30 s  (default)
    }
}
```

> Note: DNS is treated as ordinary traffic (DNS hijacking module removed), so
> port 53 no longer has a dedicated 17 s tier and uses the default timeout.

## 7. Verification Plan

1. `cargo build` and `cargo test` (unit tests for `half_close_guard`,
   `udp_flow_idle_timeout`, janitor state/l4proto decoding).
2. `cargo clippy` to keep the code lint-clean.
3. Manual: open a long-lived TCP connection (e.g. SSH) through the proxy, stop
   sending for >2 min, confirm the relay task is not torn down and traffic
   resumes correctly.
4. Manual: open a QUIC flow, idle >30 s, confirm the flow is retained until the
   2 min QUIC timeout.
5. Observe janitor logs: TCP CLOSING entries cleaned at ~10 s; TCP ACTIVE
   entries are not deleted in steady state.
