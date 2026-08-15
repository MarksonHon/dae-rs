# dae-rs Configuration

> Bilingual documentation. The Chinese version is available at
> [`config_zh_hans.md`](./config_zh_hans.md).

## 1. Overview

dae-rs is an eBPF-based transparent proxy system, a Rust rewrite of the original
`dae` project. This document describes the configuration system as it is
actually implemented today.

The configuration lives in two equivalent forms:

| Format | Description |
|--------|-------------|
| **daefile** (`.daefile`) | Human-friendly, Caddyfile-like text syntax. This is the primary input format. |
| **JSON** (`config.json`) | The normalized, machine-readable representation produced after parsing a daefile. |

A `daefile` is parsed by `parse_daefile()` (in `control/src/config/`), then
validated semantically by `validate_config()`. The result is a normalized JSON
structure which can be written out as a "temp JSON" file for debugging (see
`runtime.temp_json` below). Reference examples live under `config-example/`
(`config.daefile`, `config-minimal.daefile`, `config.json`).

## 2. Runtime Entry Points

- The dae-rs binary only supports the `run` subcommand: `dae-rs run -c <config.daefile>`.
- Without a config file, a built-in example config is used.
- Logging is configured via `--log-level` and `--json-log` (or the `RUST_LOG`
  environment variable).
- Running as root (or with `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_BPF`) is
  required, since eBPF loading and network namespace manipulation need it.

## 3. Top-Level Sections

The daefile format is organized into named sections with `{ ... }` blocks.
Currently supported top-level sections:

```
global            # runtime parameters
interface         # WAN / LAN / bind interfaces
process_exclusion # exclude processes from proxying
outbounds         # proxy nodes and groups
routing           # which traffic goes direct / proxy / block
api               # optional REST API
rule_set          # rule sets (text domain/IP lists) download & scheduling
dns               # optional DNS forwarder (domain-based split)
```

Example skeleton:

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

rule_set { ... }

dns { ... }
```

## 4. Section Details

### 4.1 `global`

Runtime parameters.

| Field | Default | Description |
|-------|---------|-------------|
| `tproxy_port` | `15080` | TProxy listening port (1–65535). |
| `log_level` | `info` | Log level: `info`, `debug`, `warn`, `error`. |

### 4.2 `interface`

Controls which network interfaces are intercepted.

| Field | Description |
|-------|-------------|
| `wan_interface` | WAN interfaces to intercept outbound traffic. Supports three pattern forms: `auto` (follow the interface(s) carrying the IPv4/IPv6 default route), `regex('...')` (e.g. `regex('^enp[0-9]+$')`), or glob (e.g. `eth*`, `enp?*`). |
| `lan_interface` | LAN interfaces whose ingress traffic is intercepted. Same pattern syntax as above. |
| `bind_interface` | Bind interface (`auto` for auto-detection). Optional, not yet central to the current data path. |

If `wan_interface` is empty, the eBPF programs will not intercept outbound
traffic at all (a warning is logged at startup).

### 4.3 `process_exclusion`

Prevents specific processes from being routed through the proxy.

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Master switch. |
| `protect_self` | `true` | Protect the dae-rs process itself. |
| `protect_children` | `true` | Protect child processes of dae-rs. |
| `gc_interval_sec` | `30` | Garbage-collection interval for tracked processes (s). |
| `stale_after_sec` | `120` | How long a tracked process entry is kept before being GC'd (s). |
| `match` | — | Match rules block. |

The `match` block supports `comm(name1, name2)`, `pid(1234)`, `tgid(1234)`.

> Note on current implementation: the daefile-level exclusion list is parsed and
> compiled, but the running process registry is primarily driven by the eBPF
> cgroup hooks and the `SO_MARK=0x100` self-exclusion on dae-rs's own sockets
> (see the design docs). Writing PID keys directly is not performed at startup,
> because the datapath keys exclusion by socket cookie rather than by PID.

### 4.4 `outbounds`

#### Nodes

Each node is a proxy server entry. There are two ways to define a node:

1. **Explicit fields** - Define all parameters directly
2. **Import** - Use a subscription/link URL

> **Import behavior**: When `import` is used, all other fields in the same node
> are ignored. If both `import` and other fields are present, a warning is logged.

```
nodes {
  # Explicit fields
  main {
    protocol: socks5
    address: 127.0.0.1:1080
    # username: user
    # password: pass
    dial_timeout_ms: 5000
  }

  # Import from link
  backup {
    import: 'socks5://127.0.0.1:2080'
  }
}
```

| Field | Description |
|-------|-------------|
| `protocol` | Outbound protocol (see Supported Protocols below). |
| `address` | Server address `host:port`. |
| `username` / `password` | Optional auth (protocol-dependent). |
| `dial_timeout_ms` | Dial timeout in milliseconds (default `5000`). |
| `import` | Shorthand for a full node definition; accepts protocol URLs. Mutually exclusive with explicit fields. |

#### Supported Protocols

| Protocol | `protocol` value | Documentation |
|----------|-----------------|---------------|
| SOCKS5 | `socks5` | [SOCKS5](../config/config_en.md) |
| Shadowsocks | `shadowsocks` | [Shadowsocks](../protocols/shadowsocks/shadowsocks_en.md) |
| Trojan | `trojan` | [Trojan](../protocols/trojan/trojan_en.md) |
| TUIC v5 | `tuic` | [TUIC](../protocols/tuic/tuic_en.md) |
| Juicity | `juicity` | [Juicity](../protocols/juicity/juicity_en.md) |
| VMess | `vmess` | [VMess](../protocols/vmess/vmess_en.md) |

#### TLS Certificate Pinning

For protocols that use TLS (Trojan, TUIC, Juicity, VMess), you can pin the
server certificate's SHA256 fingerprint:

```
ca_sha256: "fb3a01e4..."
```

**Important**: Certificate verification is **mandatory** and cannot be disabled.
The `skip_cert_verify` option is not available in dae-rs.

#### Groups

A group references a set of nodes and defines how a node is chosen.

```
groups {
  proxy_primary {
    # type: auto      # default
    # policy: fixed   # always first alive node
    # policy: random
    # policy: min          # lowest last-probe latency
    # policy: min_avg10    # lowest avg of last 10 probes
    policy: min_moving_avg # lowest moving average (recommended)
    nodes(main, backup)
  }

  manual {
    type: select
    selected: main      # initial selected node, switchable via REST API
    nodes(main, backup)
  }
}
```

| Field | Description |
|-------|-------------|
| `name` | Unique group name (the block name). |
| `type` | `auto` (automatic probing, default) or `select` (manually selected node). |
| `policy` | Node-selection policy for `auto` groups: `fixed`, `random`, `min`, `min_avg10`, `min_moving_avg`. Must not be set on `select` groups. |
| `selected` | Initial selected node for `select` groups; must be reachable from the group's selector set. Must not be set on `auto` groups. |
| `nodes(...)` | Explicit node list selector, e.g. `nodes(main, backup)`. |
| `regex(...)` | Regex selector, e.g. `nodes(regex: '*')` selects all nodes. |

### 4.5 `routing`

Decides what happens to each connection. Rules are evaluated top to bottom.

```
routing {
  dip(10.0.0.0/8) -> direct
  dport(22) -> direct
  l4proto(tcp) -> proxy(proxy_primary)
  fallback: proxy(proxy_primary)
}
```

- Rule line: `<match expression> -> <action>`.
- Actions: `direct`, `block`, `proxy(<group_name>)`. Also supported in the
  compiler: `proxy(<group>, mark=0x..., must)`.
- `fallback:` is the action used when no rule matches (default
  `proxy(proxy_primary)`).

Supported match functions (implemented in `control/src/routing/matcher.rs`):

| Function | Meaning |
|----------|---------|
| `dport(80,443)` / `port(80-90)` | Destination port / port range. |
| `sport(...)` / `source_port(...)` | Source port / port range. |
| `dip(10.0.0.0/8)` / `ip(...)` / `target_ip(...)` | Destination CIDR; `set:<name>` references rule sets. |
| `sip(...)` / `source_ip(...)` | Source CIDR; `set:<name>` references rule sets. |
| `mac(xx:xx:xx:xx:xx:xx)` | Source MAC. |
| `l4proto(tcp,udp)` | L4 protocol. |
| `ipversion(4,6)` | IP version. |
| `domain(suffix:example.com, keyword:..., full:..., regex:...)` / `target_domain(...)` | Domain rules; `set:<name>` references rule sets, other bare values default to suffix match. |
| `process_name(...)` / `pname(...)` | Process comm name (16 bytes max). |
| `dscp(...)` | DSCP value. |

Expressions may be combined with `&&` (e.g. `dport(443) && l4proto(tcp)`), and
functions can be negated with `!` (e.g. `!domain(suffix:google.com)`).

#### Rule-set reference syntax

Inside `routing` you can reference rule sets declared in the `rule_set` section
(§4.7; full design in
[`docs/design/rule_set_en.md`](../design/rule_set_en.md)):

| Syntax | Meaning |
|--------|---------|
| `source_ip(set:chinaip)` | Source IP matches the `ip_list` entry `chinaip`. |
| `target_ip(set:chinaip)` | Destination IP matches the text IP list `chinaip`. |
| `target_domain(set:chinadomain)` | Destination domain matches the `domain_list` entry `chinadomain`. |

`set:` must reference a defined entry in `rule_set`; unknown references fail
validation (E2102).

### 4.6 `api`

Optional REST API for runtime control (e.g. switching the node of a `select`
group).

| Field | Description |
|-------|-------------|
| `enabled` | Whether the API server runs. |
| `listen` | Listen address, e.g. `127.0.0.1:9090`. |
| `tls` | Whether TLS is enabled (requires `cert` + `key`). |
| `cert` / `key` | TLS certificate / private key paths. |
| `token` | Bearer token (static secret) for request authentication. |

### 4.7 `rule_set`

The `rule_set` section declares text domain / IP list data sources referenced by
`routing`, together with download and scheduled-update settings. Full design and
syntax in [`docs/design/rule_set_en.md`](../design/rule_set_en.md).

```
rule_set {
  chinadomain {
    type: domain_list
    url: 'https://cdn.jsdelivr.net/gh/Loyalsoldier/surge-rules@release/direct.txt'   # placeholder URL, replaceable
    name: chinadomain
    update: time: 04:30
  }

  chinaip {
    type: ip_list
    url: 'https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/surge/cn.txt'       # placeholder URL, replaceable
    name: chinaip
    update: period: 1d
    proxy: proxy_primary
  }
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `type` | yes | `domain_list` (text domains), `ip_list` (text IPs). |
| `url` | yes | Download URL (`http://` / `https://`); may carry a `#sha256=<64-hex>` fragment for mandatory verification. |
| `name` | no (default = block name) | **Unique** label/name (`[a-zA-Z0-9_-]`, ≤63), used for `set:<name>` references and file naming. |
| `update` | yes | Schedule expression; `time: HH:MM` (daily at a fixed time) and `period: 3h2m` (periodic; `d`/`h`/`m` units, seconds forbidden) are **mutually exclusive**. |
| `update_on_start` | no | Force one unconditional update at startup (default `false`). |
| `proxy` | no | Download proxy group; defaults to the first proxy group. |

- **Uniqueness**: every entry's `name` (including the block-name default) is
  globally unique; a duplicate raises E2101.
- Data files live in `/var/lib/dae-rs/` (`<name>.txt`). dae-rs downloads,
  verifies, atomically replaces and recovers them; missing data is downloaded
  through the first proxy group (or the entry's explicit `proxy`).
- Reference syntax: see §4.5 "Rule-set reference syntax".

### 4.8 `dns`

Optional. dae-rs removed the original dae eBPF DNS-hijack module in favor of a
**userspace DNS forwarder**: port-53 queries are still intercepted as ordinary
UDP by TProxy, recognized in userspace, and split by **domain**. The outbound is
derived from the existing `routing` rules (`domain` / `target_domain` → the
proxy group the domain matches; each group — and direct — keeps its own TTL
cache and reuses a persistent UDP relay session).

```
dns {
  listen_addr: 169.254.0.1:53        # optional listen entry point
  proxy_dns_servers: 1.1.1.1:53, 8.8.8.8   # unified upstream for proxied queries
  direct_dns_servers: 223.5.5.5      # upstream for direct queries
  direct_use_system_dns: true        # fall back to /etc/resolv.conf when direct list is empty
  query_timeout_ms: 5000             # query timeout (100–60000)
  enable_cache: true                 # per-group TTL cache
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `listen_addr` | no | Internal listen address (default `169.254.0.1:53`, dae-internal only). Bound on host-NS `lo`; clients must explicitly point DNS at it. |
| `proxy_dns_servers` | no | Unified upstream used for proxied queries (`ip` or `ip:port`). When empty, proxied queries fall back to direct. |
| `direct_dns_servers` | no | Upstream for direct queries (`ip` or `ip:port`); when empty, falls back to system `/etc/resolv.conf`. |
| `direct_use_system_dns` | no | Whether to fall back to system DNS when the direct list is empty (default `true`). |
| `query_timeout_ms` | no | Query timeout in ms (default `5000`, range 100–60000). |
| `enable_cache` | no | Enable per-group TTL cache (default `true`). |

Behavior notes:

- **Domain split**: DNS defines no proxy rules of its own. `domain(...)` /
  `target_domain(...)`-matched proxy groups decide the outbound; unmatched
  queries go to `routing.fallback`.
- **Group unavailable** (no dialer / no proxy upstream / all nodes down) →
  falls back to direct with a warning, so queries are not dropped.
- **Persistent sessions**: each proxy group reuses one full-cone UDP session to
  avoid per-query re-handshakes; the session is bound to the node it was
  created on and is rebuilt automatically when the group's selected node
  changes.
- Without a `dns` section, DNS is treated as ordinary UDP traffic (default
  TProxy path).

## 5. Configuration Validation

`validate_config()` performs semantic validation and produces diagnostics with
stable error codes:

| Code | Meaning |
|------|---------|
| `E1001` | Syntax error (with line number) / unknown section. |
| `E1101` | Missing required section. |
| `E1201` / `E1202` / `E1203` | Field type / range / value errors. |
| `E1301` / `E1302` | Duplicate node / group name. |
| `E1401` / `E1402` | Reference to unknown node / group. |
| `E1501` / `E1502` | Node import conflicts with explicit fields / invalid import URL. |
| `E1601` / `E1602` | Invalid regex / regex matches no nodes. |
| `E1701` – `E1704` | Select/auto group misconfiguration. |
| `E1901` – `E1903` | API listen format / token / TLS issues. |
| `E2101` – `E2106` | Rule sets: duplicate name / unknown reference / missing data / invalid schedule (incl. seconds) / invalid URL / capacity exceeded. |

Warnings (`W1801`, `W1901`, `W1902`) are emitted for
non-fatal issues such as missing policies.

## 6. Defaults at a Glance

- TProxy port `15080`, route table `2023`, proxy fwmark `0x08000000`,
  bypass fwmark `0x04000000`, MTU `1500`.
- SOCKS5 dial timeout `5000` ms.
- Routing fallback `proxy(proxy_primary)`.

## 7. Known Limitations (as implemented today)

- Outbound nodes support `socks5`, `shadowsocks`, `trojan`, `vmess`, `tuic`
  and `juicity` (feature-gated at build time).
- **Group selection & fallback**: `GroupDialer` implements in-group node
  selection (select-anchored / auto policies) and alive-node fallback (dead
  marking + cooldown), wired into the DNS forwarder, rule-set download proxy
  and the **default group** of the main data plane. However, the main data
  plane (TProxy relay) currently always dials through the **default (first)
  group's** dialer — traffic routed to other groups still goes out via the
  default group; per-group relaying for non-default groups is not wired yet.
- Rule-set data (`domain_list` / `ip_list`) is downloaded via the URLs
  configured in `rule_set` into `/var/lib/dae-rs/` and parsed by dae-rs.
  `set:<name>` is wired into the data path. A missing dataset referenced at
  compile time raises E2103; DNS domain routing skips the affected rule with a
  warning (fallback applies) instead of failing data-plane startup.
