# DNS Subsystem Design

> Bilingual documentation. The Chinese version is available at
> [`dns_zh_hans.md`](./dns_zh_hans.md).

## 1. Scope

This document describes the DNS subsystem of dae-rs **as it is implemented
today** (`control/src/dns/*`). It covers the DNS manager, upstream pools,
request/response action, caching, the listener, and the integration with
domain-based eBPF routing.

Module layout:

```
control/src/dns/
├── mod.rs       # DnsManager — orchestrator
├── upstream.rs  # DnsUpstreamPool — per-upstream connection pool, URL parsing
├── cache.rs     # DnsCache — response cache
├── router.rs    # DnsRouter — query→group→upstream matching, response checks
└── handler.rs   # DnsListener — UDP/TCP listener, query processing
```

## 2. Data Path Overview

```
 client query
    │
    ▼
 eBPF TC hook (WAN egress) intercepts UDP/53, redirects into proxy NS (daens)
    │
    ▼
 DNS listener (host NS on <bind>, + internal listener on 169.254.0.1:<port>)
    │
    ├─ cache lookup ................. hit → reply from cache
    │
    ├─ DnsRouter.match_query(qname, qtype)
    │      └─ select group → select upstream (request_routing / fallback)
    │
    ├─ DnsUpstreamPool.query(...)  → forward to upstream DNS server
    │      (sockets marked SO_MARK=0x100 to bypass the proxy pipeline)
    │
    ├─ response action (accept / reject / requery)
    │
    ├─ cache insert
    │
    └─ reply to client via IP_TRANSPARENT socket so the response
       appears to come from the original upstream DNS server
```

## 3. Components

### 3.1 `DnsManager` (`mod.rs`)

The orchestrator. Holds the config, a map of upstream pools (keyed
`"<group>__<label>"`), the shared cache, the router, and the listener.

- **`init_upstreams()`** — builds all upstream pools:
  - `starting_dns` (bootstrap) pools are built first and keyed
    `"__starting__<label>"`. They **must** be IP literals.
  - For group upstreams whose address is a hostname (e.g. `udp://dns.google:53`),
    the hostname is resolved once through the bootstrap resolver
    (`resolve_via_bootstrap`, queries A then AAAA) and cached in a local map.
  - A failing upstream is skipped with a warning instead of aborting the whole
    initialization.
- **`start()` / `stop()`** — creates a `DnsListener` bound to `config.bind`,
  shares the pools/cache/router, then runs it.

### 3.2 `DnsUpstreamPool` (`upstream.rs`)

A connection pool for a single upstream DNS server.

- URL parsing (`parse_dns_url_parts`) supports `udp://`, `tcp://`, `tcp+udp://`,
  `https://` / `doh://`, `tls://` / `dot://`, and bare `host:port` (default UDP).
  Default ports: 53 (plain), 443 (DoH), 853 (DoT).
- Transport enum: `Udp`, `Tcp`, `TcpUdp`, `Doh`, `Dot`. **DoH and DoT are parsed
  but not implemented** — calling `query()` on them returns an error.
- `tcp+udp` queries UDP first and falls back to TCP.
- **Critical detail**: every upstream socket is created with
  `SO_MARK=0x100` (`DAE_SOCKET_MARK`). This makes the eBPF program treat the
  query as dae-rs control-plane traffic and let it pass without interception —
  otherwise dae-rs's own DNS resolution would be hijacked back into the proxy,
  creating a resolution loop.
- Timeout is 5s per query.

### 3.3 `DnsRouter` (`router.rs`)

Matches a query to a group and checks responses.

- Top-level rules support `qname(...)`, `qtype(...)` (A/AAAA/…), and `any`;
  each rule may be negated with `!`. Rule-set references such as
  `qname(geosite:cn)` / `qname(set:chinadomain)` are matched against the
  GeoSite category / `domain_list` entry (see §3.6).
- If no rule matches, uses `config.routing.fallback`; if that is empty, the first
  configured group; if there are no groups, a "null" empty result.
- **All routing goes through the top-level `dns.routing`**: the in-group
  `request_routing` has been removed. `DnsRouteResult` carries only the selected
  group and `send_by`.
- `send_by` field: `"direct"` → this group's upstream queries go out directly;
  otherwise a proxy group name (e.g. `send_by: proxy_primary`) → this group's
  upstream queries are sent through that proxy group. `"direct"` is a reserved
  keyword — no DNS server or DNS group may be named `direct`. The group name is
  carried in `DnsRouteResult.send_by`.
- `query_mode` field: how this group picks its upstream, one of:
  - `concurrent` (default) — query all upstreams concurrently, use the first success;
  - `random` — pick one random upstream and query it;
  - `sequence` — try upstreams in config order (top to bottom), use the first success.

### 3.4 `DnsListener` / handler (`handler.rs`)

The actual UDP/TCP listener and per-query processing.

- **UDP + TCP** listeners are both bound, with `SO_REUSEADDR` so rapid restarts
  don't hit `EADDRINUSE`.
- An **additional UDP listener** is created on `169.254.0.1:<port>`
  (169.254.0.1 is assigned to the host-side `dae0` interface) for
  cross-namespace DNS forwarding: the eBPF TProxy path inside the proxy
  namespace (daens) forwards intercepted DNS queries to this address instead of
  going through SOCKS5.
- Per-query flow (`handle_dns_internal`):
  1. Parse qname + qtype.
  2. Cache lookup (key = qname + qtype + class IN).
  3. Route via `DnsRouter` to a group, then pick the upstream according to the
     group's `query_mode` and query it (direct, or through the `send_by` proxy group).
  4. Apply response action (accept / reject / requery with another upstream).
  5. On accept, insert into cache and feed accepted A/AAAA resolutions into the
     domain-routing callback.
- **IP_TRANSPARENT responses**: the reply is sent from a socket created with
  `IP_TRANSPARENT`/`IPV6_TRANSPARENT`, `SO_REUSEADDR`, `SO_REUSEPORT` and
  `SO_MARK=0x100`, bound to the *upstream DNS server's address*. DNS clients
  expect the response source to match the server they queried (e.g. 8.8.8.8:53),
  not the local listener (169.254.0.1:5353). `IP_TRANSPARENT` allows binding to
  that non-local address. `SO_MARK` keeps the response out of the proxy
  pipeline. On cache hits there is no upstream address, so an ephemeral bind is
  used instead.

### 3.5 `DnsCache` (`cache.rs`)

A response cache keyed by `(qname, qtype, class)`, **partitioned per DNS group**.
Each group (e.g. `china_dns`, `trusted_dns`) has its own independent `HashMap`,
so the same `(qname, qtype)` can hold different cached answers in different
groups — a polluted domestic upstream and a trusted overseas upstream never
contaminate each other's cache. `max_size` is the per-group capacity.

- Config: `enabled`, `max_size` (4096 per group), `max_ttl` (86400s), `min_ttl` (60s),
  `optimistic_cache` (RFC 8767, default off), `optimistic_cache_ttl` (3600s).
- Expired entries are revalidated/refreshed; with optimistic caching enabled,
  expired entries may still be served while being refreshed.
- Cache reads/writes happen after `DnsRouter` has selected the group, and carry
  the group name.

### 3.6 Rule-set evaluation in DNS routing

- **DNS query routing** ([`router.rs`](control/src/dns/router.rs)):
  `qname(geosite:cn)` / `qname(set:chinadomain)` compile into rule-set
  references (`DnsMatchType::GeoSite` / `DnsMatchType::Set`); at runtime the
  query name is matched against the domain patterns in userspace (directly
  against the in-memory cache, no eBPF involvement). Plain patterns like
  `qname(suffix:...)` keep using the existing suffix logic.
- **DNS response action** ([`handler.rs`](control/src/dns/handler.rs)):
  - `ip(geoip:cn)` / `ip(set:chinaip)` — parse all A/AAAA addresses in the
    response (reusing `extract_answer_addrs()`); the condition is true when any
    address hits the GeoIP / IP list;
  - `ip(CIDR)` — direct CIDR match;
  - `upstream(label)` — true when the response actually came from the upstream
    with the given label, useful for distinguishing responses from different
    upstreams within the same group;
  - `nocontent` — response has no answer records (NODATA);
  - `qname(geosite:cn)` / `qname(set:chinadomain)` — domain-pattern match on the
    query name;
  - Conditions support `&&` (AND) and `!` (NOT), e.g.
    `ip(geoip:private) && !qname(geosite:cn)`.
  - Unknown conditions default to false with a warning (no longer returning true
    as in the original implementation).

## 4. Bootstrap / starting_dns

`starting_dns` is the "trust anchor" resolver used before anything else works:

- Its upstreams **must be IP literals** — resolving a hostname bootstrap would be
  a chicken-and-egg problem.
- It is configured as a **flat list** of IP DNS server addresses:
  ```
  starting_dns {
    ip_version_prefer: 4
    upstream: ['udp://223.5.5.5:53', 'udp://1.1.1.1:53']
  }
  ```
- All of its DNS servers are queried **directly** (never through a proxy). They
  resolve hostname-based group upstreams (e.g. `udp://dns.google:53`) at init
  time by iterating the bootstrap servers in order, querying A records first and
  then AAAA, stopping at the first usable IP.
- The `ip_version_prefer` field (`4` or `6`) is declared and validated in
  config, but **the current code does not use it** — bootstrap resolution is
  hardcoded to A-first-then-AAAA. To support IPv6-priority resolution,
  `resolve_via_bootstrap()` in `mod.rs` must be changed.

## 5. Integration with Domain-Based eBPF Routing

DNS resolution results feed the eBPF `domain_routing_map` so that
`domain(...)` routing rules can be evaluated in the data path:

1. `ControlPlane` compiles routing rules and, when domain rules exist, creates a
   `DomainRoutingTracker` (see `control/src/routing/domain_routing.rs`).
2. A `DnsResolveCallback` (`on_resolve`) is wired from the DNS manager to the
   tracker.
3. On every **accepted** DNS response, each A/AAAA record is reported as
   `(domain, ip, ttl)`.
4. The tracker computes a routing bitmap (which domain-set rules match the
   domain) and writes `ip → bitmap` into the `domain_routing_map` eBPF map
   (with an epoch-slot prefix for double buffering).
5. A janitor removes entries when their TTL expires, keeping the map in sync
   with the DNS cache.

This mirrors the original dae `control/domain_routing_tracker.go`.

## 6. Current Limitations

- DoH / DoT transports are parsed but not functional.
- The `ip_version_prefer` config field exists but is not used by bootstrap
  resolution (hardcoded A-first-then-AAAA).
- The DNS listener tasks run infinite receive loops and are stopped by
  `abort()` (safe because tokio tasks are cancel-safe at await points).

> Rule-set evaluation is implemented: DNS query routing `qname(geosite:/set:)`
> and DNS response action `ip(geoip:/set:)` / `qname(...)` / `&&` / `!` are all
> wired to rule-set data (§3.6), no longer simple suffix comparison. A missing
> dataset referenced at compile time raises E2103.
