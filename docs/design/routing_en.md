# Routing Subsystem Design

> Bilingual documentation. The Chinese version is available at
> [`routing_zh_hans.md`](./routing_zh_hans.md).

## 1. Scope

This document describes the routing subsystem of dae-rs **as it is implemented
today**. It covers the rule language, the userspace compile pipeline
(`control/src/routing/matcher.rs`), the kernel-side evaluation in `bpf/kern/tproxy.c`,
and the "routing handoff" mechanism that lets userspace finish decisions the
eBPF data path cannot.

This module mirrors dae's `routing_matcher_builder.go` and
`routing/normalize.go`.

## 2. Rule Language

A routing rule is `match_expression -> action`, evaluated top to bottom; the
last entry is the fallback:

```
routing {
  dip(geoip:private) -> direct
  dport(22) -> direct
  dport(443) && l4proto(tcp) -> proxy(proxy_primary)
  fallback: proxy(proxy_primary)
}
```

### Match functions

| Function | Match type | Example |
|----------|-----------|---------|
| `dip(...)` / `ip(...)` | Destination CIDR set (LPM trie) | `dip(10.0.0.0/8)` |
| `sip(...)` / `source_ip(...)` | Source CIDR set | `sip(192.168.0.0/16)` |
| `mac(...)` | Source MAC set (stored as IPv6-mapped LPM trie) | `mac(00:11:22:33:44:55)` |
| `dport(...)` / `port(...)` | Destination port / range | `dport(80,443)`, `port(8000-9000)` |
| `sport(...)` / `source_port(...)` | Source port / range | `sport(1024-65535)` |
| `l4proto(tcp,udp)` | L4 protocol bitmask | `l4proto(tcp)` |
| `ipversion(4,6)` | IP version bitmask | `ipversion(4)` |
| `domain(suffix:..., keyword:..., full:..., regex:...)` | Domain set (DNS-driven) | `domain(suffix:baidu.com)` |
| `process_name(...)` / `pname(...)` | Process comm (≤16 bytes) | `process_name(qbittorrent)` |
| `dscp(...)` | DSCP value | `dscp(10)` |
| `qtype(...)` | DNS query type (placeholder) | `qtype(a)` |
| `upstream(...)` | DNS upstream group (≤16 bytes) | `upstream(googledns)` |

- Functions are ANDed together with `&&` (parenthesis-aware splitting).
- A function may be negated with `!`: `!domain(suffix:google.com)`.
- Multiple comma-separated values are OR'd within a function; parameters can
  carry `key:value` prefixes (`suffix:`, `keyword:`, `full:`, `regex:`) and
  parameters sharing a key form one OR-group.

### Actions

- `direct` — send straight out (outbound ID `OUTBOUND_DIRECT`).
- `block` — drop (outbound ID `OUTBOUND_BLOCK`).
- `proxy(<group>)` — proxy via a group.
- `proxy(<group>, mark=0x..., must)` — proxy with a fwmark override and/or the
  `must` (force, bypass DNS-based routing) flag.
- `control_plane_routing` — yield to userspace (special outbound ID, see §6).

## 3. Compile Pipeline

`compile_rules(routing, outbounds, proxy_server_ips)` in
`control/src/routing/matcher.rs`:

```
daefile routing config
   │
   ▼
1. NormalizedProgram::from_config()      # IR: rules of AND-separated Functions
   │
2. build_outbound_id_map(outbounds)      # group/node name → eBPF outbound ID
   │
3. collect domain_sets (first pass)      # domain patterns per domain rule
   │
4. lower rules → MatchSet entries        # via function parsers, inline LPM trie
   │                                      # creation + dedup (FNV-1a)
5. prepend auto-direct for proxy server IPs   # dip(proxy_ip) -> direct
   │
6. append fallback MatchSet (must be last)
   │
▼
CompiledRouting { match_sets, lpm_tries, domain_sets, fallback_* }
```

### Intermediate representation

- `Function { name, not, raw_params }` — a single parsed function, parameters
  kept as raw strings (`key:value` extraction happens per parser).
- `Outbound { name, mark, must }` — a parsed action.
- `NormalizedRule { and_functions: Vec<Function>, outbound: Outbound }`.
- `NormalizedProgram { rules, fallback }` — the shared IR.

### Lowering to MatchSet

Each function invocation becomes one or more `MatchSet` entries (defined in
`control/src/net/ebpf.rs`, synced with `tproxy.c`). Every MatchSet carries:

- `type` — one of `IP_SET`, `SOURCE_IP_SET`, `MAC`, `PORT`, `SOURCE_PORT`,
  `L4_PROTO`, `IP_VERSION`, `DOMAIN_SET`, `PROCESS_NAME`, `DSCP`, `QTYPE`,
  `UPSTREAM`, `FALLBACK`.
- `not` — whether the match is inverted.
- `outbound` — an outbound ID, or a logical marker.
- `mark` / `must` — fwmark override / force flag.
- `value` — index into an LPM trie, a port range, a bitmask, or an inline
  16-byte name.

**Logical chaining**: within one rule the entries form a chain. All but the last
entry of a rule use the special outbound IDs `LOGICAL_OR` / `LOGICAL_AND`
computed by `compute_override_outbound()`: entries within a function's key
groups are OR'd, and AND-separated functions are AND'd. The final entry carries
the real outbound ID. The eBPF `route()` walker (and the userspace
`RoutingMatcher`, which mirrors it) consumes this chain to evaluate `A && B`,
`A || B`, and `!A`.

**LPM tries**: CIDR values are collected into tries via
`find_or_create_lpm_trie()` (deduplicated by an FNV-1a hash to match the
original dae). A MatchSet of type `IP_SET`/`SOURCE_IP_SET`/`MAC` references a
trie by index. IPv4 addresses are stored as IPv4-mapped IPv6 (96+len prefix).

**Domain sets**: `domain(...)` values (prefix stripped) are accumulated into
`domain_sets`; the MatchSet references a set by index. At runtime, DNS
resolutions populate `domain_routing_map` (IP → bitmap of matching sets) — see
`docs/design/dns_en.md` §5.

**Proxy auto-direct**: all configured proxy server IPs are collected into a
dedicated LPM trie, and a `dip(proxy_server_ip) -> direct` rule is prepended.
This prevents traffic destined for a proxy server from being re-proxied (loop
prevention).

**Fallback**: the compiled fallback action is appended as the last entry with
type `FALLBACK`.

## 4. Kernel-Side Evaluation (`bpf/kern/tproxy.c`)

The eBPF TC programs intercept traffic at `wan_egress` / `wan_ingress` /
`lan_ingress` / `dae0_ingress` / `dae0peer_ingress` and run the routing logic:

- `routing_map` is a `BPF_MAP_TYPE_ARRAY` of `MatchSet` entries, **double
  buffered** in two epoch slots (`ROUTING_EPOCH_SLOT_NUM = 2`) so rules can be
  hot-reloaded without tearing. Each conn_state entry records which slot was
  used (shifted into the result, see `ROUTING_EPOCH_SLOT_RESULT_SHIFT`).
- LPM tries live in an array-of-maps (`lpm_array_map`), indexed by the trie id
  from the MatchSet.
- The `route()` function walks the MatchSet chain (with `bpf_loop()`) applying
  `LOGICAL_OR` / `LOGICAL_AND` / `NOT` semantics.
- Outbound IDs: `OUTBOUND_DIRECT (0x0)`, `OUTBOUND_BLOCK (0x1)`,
  `OUTBOUND_MUST_RULES (0xFC)`, `OUTBOUND_CONTROL_PLANE_ROUTING (0xFD)`,
  `LOGICAL_OR` / `LOGICAL_AND` (mask `LOGICAL_MASK = 0xFE`).
- `outbound_connectivity_map` tracks per-outbound liveness; `wan_outbound_is_alive()`
  is consulted before deciding to proxy.
- After a decision, traffic is either delivered directly (via `bpf_sk_assign`
  / direct redirect), marked with `TPROXY_MARK` (`0x8000000`) for the policy
  route into the proxy namespace's TProxy listener, or handed off to userspace
  (see §6).

## 5. Userspace RoutingMatcher

`RoutingMatcher` (`control/src/routing/matcher.rs`) is a userspace mirror of the eBPF
evaluator, built from the same `CompiledRouting` data. `match_routing(params)`
walks the MatchSet chain identically and returns `RoutingResult { outbound,
mark, must }`. It evaluates `dip`/`sip` against the LPM tries, `domain` against
`domain_sets`, ports, L4 proto, IP version, process name, DSCP, etc.

`choose_dial_target(routing, ctx)` is the entry point corresponding to dae's
`ChooseDialTarget()` — it is used by the routing handoff consumer.

## 6. Routing Handoff (userspace completion of eBPF decisions)

Some decisions cannot be made in the kernel (e.g. domain rules before the DNS
resolution is known). The design is:

1. When the eBPF route cannot decide, the MatchSet chain ends at
   `OUTBOUND_CONTROL_PLANE_ROUTING (0xFD)`.
2. The packet/connection is recorded in `routing_handoff_map`
   (`MAX_ROUTING_HANDOFF_NUM` entries).
3. The **routing handoff consumer** (`control/src/routing/routing_handoff.rs`) drains
   the map, reconstructs the connection params, calls `choose_dial_target()`
   against the userspace `RoutingMatcher`, and writes the final decision into
   `conn_state_map`.
4. The datapath reads `conn_state_map` (keyed by the connection 5-tuple) on
   subsequent packets. Each entry carries the routing epoch slot and a
   `datapath_generation` counter so stale entries are invalidated after a
   config reload.

Supporting machinery:

- `conn_state_map` (up to `MAX_CONN_STATE_NUM = 65536 * 4`) with a janitor that
  prunes stale/expired connections and detects map pressure.
- `redirect_track_map` and `cookie_pid_map` janitors keep the redirect and
  control-plane socket-cookie tracking bounded.
- `current_epoch_slot` (0/1) alternates on each reload; reloads write to the
  inactive slot and then flip `active_routing_epoch`.

## 7. Current Limitations

- `qtype(...)` compiles to a placeholder MatchSet (full DNS query-type matching
  is not implemented).
- `upstream(...)` is a placeholder for DNS upstream-group matching in the data
  path.
- Group/node outbound IDs currently map to `OUTBOUND_CONTROL_PLANE_ROUTING`,
  so proxying decisions for proxied groups are completed in userspace.
- `MAC` matching is only meaningful in the kernel (no userspace equivalent);
  the userspace matcher returns `false` for it.
- Only `&&` combinations are supported; OR logic is expressed by listing
  multiple values within one function or multiple rules.
