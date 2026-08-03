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
dns               # DNS hijacking / routing / cache
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
  dip(geoip:private) -> direct
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
| `dip(10.0.0.0/8)` / `ip(...)` | Destination CIDR; `geoip:private` expands to RFC1918 + loopback. |
| `sip(...)` / `source_ip(...)` | Source CIDR. |
| `mac(xx:xx:xx:xx:xx:xx)` | Source MAC. |
| `l4proto(tcp,udp)` | L4 protocol. |
| `ipversion(4,6)` | IP version. |
| `domain(suffix:example.com, keyword:..., full:..., regex:...)` | Domain rules; bare values default to suffix match. |
| `process_name(...)` / `pname(...)` | Process comm name (16 bytes max). |
| `dscp(...)` | DSCP value. |
| `qtype(...)` | DNS query type (placeholder for full matching). |
| `upstream(...)` | DNS upstream group matching. |

Expressions may be combined with `&&` (e.g. `dport(443) && l4proto(tcp)`), and
functions can be negated with `!` (e.g. `!domain(suffix:google.com)`).

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

### 4.7 `dns`

See [`docs/design/dns_en.md`](../design/dns_en.md) for the full design. Summary:

| Field | Description |
|-------|-------------|
| `starting_dns` | Bootstrap resolver used before the proxy is available. Contains `ip_version_prefer` (`4` or `6`) and a `upstream` list (must be IP literals to avoid a chicken-and-egg problem). |
| `bind` | Local DNS listener address (default `127.0.0.1:5353`). |
| `cache` | Cache settings: `enabled`, `max_size`, `max_ttl`, `min_ttl`, `optimistic_cache`, `optimistic_cache_ttl`. |
| `groups` | DNS groups, each with `proxy` (`direct` or `proxy(<group>)`), `upstream` entries (label + URL like `udp://1.1.1.1:53`, `tcp+udp://dns.google:53`), `request_routing` and `response_routing`. |
| `routing` | Top-level DNS routing: `qname(geosite:cn) -> china_dns`, etc., plus `fallback`. |

URL schemes parsed: `udp://`, `tcp://`, `tcp+udp://`, `https://` / `doh://`,
`tls://` / `dot://`. DoH and DoT are parsed but **not yet functional**; using
them returns an error.

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
| `E2001` – `E2007` | DNS group / routing / starting_dns issues. |

Warnings (`W1801`, `W1901`, `W1902`, `W2001`, `W2002`) are emitted for
non-fatal issues such as missing policies or missing DNS response routing.

## 6. Defaults at a Glance

- TProxy port `15080`, route table `2023`, proxy fwmark `0x08000000`,
  bypass fwmark `0x04000000`, MTU `1500`.
- SOCKS5 dial timeout `5000` ms.
- DNS bind `127.0.0.1:5353`; cache enabled with `max_size=4096`,
  `max_ttl=86400`, `min_ttl=60`.
- Routing fallback `proxy(proxy_primary)`.

## 7. Known Limitations (as implemented today)

- Only `socks5` outbound nodes are supported (Phase 1).
- Only one SOCKS5 upstream address is actively used by the control plane
  (the first node in the config); outbound groups select nodes and feed the
  connectivity map, but node-to-node switching is a work in progress.
- DNS DoH / DoT transports are parsed but not yet implemented.
- GeoIP/GeoSite data is not bundled; `geoip:private` is expanded in
  userspace, while `geosite:` sets used in DNS routing are matched by simple
  suffix comparison in the DNS router.
