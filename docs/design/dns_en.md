# DNS Subsystem Design

> Bilingual documentation. The Chinese version is available at
> [`dns_zh_hans.md`](./dns_zh_hans.md).

## 1. Scope

This document describes the DNS subsystem of dae-rs **as it is implemented
today** (`control/src/dns/*`). It covers the DNS manager, upstream pools,
request/response routing, caching, the listener, and the integration with
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
    ├─ response routing (accept / reject / requery)
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

Matches a query to a group and an upstream, and checks responses.

- Top-level rules support `qname(...)` (suffix match), `qtype(...)` (A/AAAA/…),
  and `any`; each rule may be negated with `!`.
- If no rule matches, uses `config.routing.fallback`; if that is empty, the first
  configured group; if there are no groups, a "null" empty result.
- Within a group, the upstream is chosen from `request_routing.fallback`
  (in-group `request_routing.rules` are parsed but the current `select_upstream`
  implementation uses the fallback directly), or the first upstream if no
  request routing is set.
- `proxy` field: `"direct"` → query goes out directly; `"proxy(<group>)"` → the
  selected group name is returned in `DnsRouteResult.proxy_group` (the actual
  proxying of DNS over the SOCKS5 path is a separate concern from this module).

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
  3. Route via `DnsRouter` → resolve pool key (`"<group>__<label>"`, falling
     back to `"__starting__<label>"`).
  4. Forward to upstream.
  5. Apply response routing (accept / reject / requery with another upstream).
  6. On accept, insert into cache and feed accepted A/AAAA resolutions into the
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

A response cache keyed by `(qname, qtype, class)`.

- Config: `enabled`, `max_size` (4096), `max_ttl` (86400s), `min_ttl` (60s),
  `optimistic_cache` (RFC 8767, default off), `optimistic_cache_ttl` (3600s).
- Expired entries are revalidated/refreshed; with optimistic caching enabled,
  expired entries may still be served while being refreshed.

## 4. Bootstrap / starting_dns

`starting_dns` is the "trust anchor" resolver used before anything else works:

- Its upstreams **must be IP literals** — resolving a hostname bootstrap would be
  a chicken-and-egg problem.
- It is used in two places:
  1. Resolving hostname-based upstreams (e.g. `udp://dns.google:53`) at init
     time.
  2. As a fallback pool if a group's own upstream lookup fails at query time.

## 5. Integration with Domain-Based eBPF Routing

DNS resolution results feed the eBPF `domain_routing_map` so that
`domain(...)` routing rules can be evaluated in the data path:

1. `ControlPlane` compiles routing rules and, when domain rules exist, creates a
   `DomainRoutingTracker` (see `control/src/domain_routing.rs`).
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
- `geosite:` sets in DNS routing are evaluated as simple suffix matches (no
  bundled GeoIP/GeoSite datasets).
- In-group `request_routing.rules` are parsed but the upstream choice currently
  uses the fallback (the rule list is not yet fully evaluated).
- `upstream(...)` response conditions currently match everything.
- The DNS listener tasks run infinite receive loops and are stopped by
  `abort()` (safe because tokio tasks are cancel-safe at await points).
