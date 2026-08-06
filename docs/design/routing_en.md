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
  dip(10.0.0.0/8) -> direct
  dport(22) -> direct
  dport(443) && l4proto(tcp) -> proxy(proxy_primary)
  fallback: proxy(proxy_primary)
}
```

### Match functions

| Function | Match type | Example |
|----------|-----------|---------|
| `dip(...)` / `ip(...)` / `target_ip(...)` | Destination CIDR set (LPM trie); `set:<name>` references rule sets | `target_ip(10.0.0.0/8)`, `target_ip(set:chinaip)` |
| `sip(...)` / `source_ip(...)` | Source CIDR set; `set:<name>` references rule sets | `source_ip(set:chinaip)`, `source_ip(192.168.0.0/16)` |
| `mac(...)` | Source MAC set (stored as IPv6-mapped LPM trie) | `mac(00:11:22:33:44:55)` |
| `dport(...)` / `port(...)` | Destination port / range | `dport(80,443)`, `port(8000-9000)` |
| `sport(...)` / `source_port(...)` | Source port / range | `sport(1024-65535)` |
| `l4proto(tcp,udp)` | L4 protocol bitmask | `l4proto(tcp)` |
| `ipversion(4,6)` | IP version bitmask | `ipversion(4)` |
| `domain(suffix:..., keyword:..., full:..., regex:...)` / `target_domain(...)` | Domain set; `set:<name>` references rule sets | `target_domain(suffix:example.com)`, `target_domain(set:chinadomain)` |
| `process_name(...)` / `pname(...)` | Process comm (≤16 bytes) | `process_name(qbittorrent)` |
| `dscp(...)` | DSCP value | `dscp(10)` |


- Functions are ANDed together with `&&` (parenthesis-aware splitting).
- A function may be negated with `!`: `!domain(suffix:google.com)`.
- Multiple comma-separated values are OR'd within a function; parameters can
  carry `key:value` prefixes (`suffix:`, `keyword:`, `full:`, `regex:`, `set:`)
  and parameters sharing a key form one OR-group.

### Rule-set references (data path)

`source_ip` / `target_ip` / `target_domain` can reference rule sets declared in
the `rule_set` section (full design in [`rule_set_en.md`](./rule_set_en.md)):

- `source_ip(set:chinaip)` / `target_ip(set:chinaip)` — match an `ip_list` entry;
- `target_domain(set:chinadomain)` — match a `domain_list` entry.

Normalization: `sip`→`source_ip`, `dip`/`ip`→`target_ip`; the old aliases stay
compatible. References fail to compile with E2103 when data is missing.

### Actions

- `direct` — send straight out (outbound ID `OUTBOUND_DIRECT`).
- `block` — drop (outbound ID `OUTBOUND_BLOCK`).
- `proxy(<group>)` — proxy via a group.
- `proxy(<group>, mark=0x..., must)` — proxy with a fwmark override and/or the
  `must` (force) flag.
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
Rule-set references `source_ip(set:chinaip)` are resolved to `Vec<IpNet>` in
`parse_cidr_values()` and fed into the same trie (see §8).

**Domain sets**: `domain(...)` / `target_domain(...)` values are accumulated
into `domain_sets`; the MatchSet references a set by index. Rule-set references
`target_domain(set:chinadomain)` look up the in-memory cache and map the
Domain list via `domain_pattern_to_string()` into prefixed patterns
(`suffix:`/`full:`/`regex:`/`domain:`/`keyword:`) in the same `domain_sets`.

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

Some decisions cannot be made in the kernel (e.g. domain rule matching). The
design is:

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

- Group/node outbound IDs currently map to `OUTBOUND_CONTROL_PLANE_ROUTING`,
  so proxying decisions for proxied groups are completed in userspace.
- `MAC` matching is only meaningful in the kernel (no userspace equivalent);
  the userspace matcher returns `false` for it.
- Only `&&` combinations are supported; OR logic is expressed by listing
  multiple values within one function or multiple rules.

## 8. Rule-set Capacity Constraints (key points; see
[`rule_set_en.md`](./rule_set_en.md) §9)

Rule-set data wired into eBPF is subject to the existing capacity limits;
overflow is detected at compile time and rejected with E2106:

| Resource | Limit | Constraint |
|----------|-------|------------|
| MatchSet entries per epoch slot | `MAX_MATCH_SET_LEN = 1024` | Includes logical chains and fallback; rule-set functions share the pool with existing functions |
| LPM tries (userspace compile time) | `MAX_LPM_NUM = 1032` | `matcher.rs` |
| LPM trie outer array (eBPF double buffer) | `2 * 1024 + 8 = 2056` | `bpf/kern/tproxy.c` |
| Entries inside one LPM trie | `MAX_LPM_SIZE = 2_048_000` | ~2M CIDRs per trie |
| domain_routing_map bitmap | 32 × u32 (=1024 bit) | **Domain-set rule index limit 1024** (each set domain reference uses 1 bit) |

- **The bottleneck is the MatchSet count and the domain-set index count (rule
  count)**.
- On overflow, compilation is **rejected with E2106**, prompting fewer rules /
  merged references; sampling truncation is an optional Phase-5 degradation
  (off by default).
