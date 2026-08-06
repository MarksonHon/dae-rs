# Rule Set Support — Design Document

> Bilingual documentation. The Chinese version is available at
> [`rule_set_zh_hans.md`](./rule_set_zh_hans.md).
>
> **Status**: Implemented (Phases 0–3 complete; Phase 4 — example configs and
> docs — is this document's companion task).
>
> **Scope**: This design provides the complete plan for dae-rs's "rule set
> support" sub-task: data formats, the storage/download/update lifecycle,
> configuration extension, scheduling, routing reference syntax, eBPF
> integration, free-combination semantics, error handling and implementation
> phases. Phases 0–3 have been implemented; this English document mirrors the
> Chinese one and reflects the current implemented state (text domain/IP lists only).

## Abstract

This design introduces text domain/IP-list rule set support to dae-rs:

- **Data formats**: plain-text one-entry-per-line domain/IP lists.
- **Unified storage & lifecycle**: all data files live in `/var/lib/dae-rs/`;
  dae-rs downloads, verifies, atomically replaces and recovers them itself;
  missing local data is by default downloaded through the **first proxy group**.
- **Configuration extension**: a new rule-set management section in both
  `config.daefile` and `config.json`; every file has a **unique name/label**,
  configurable URL, update schedule (`time: HH:MM` / `period: 3h2m`, no
  second-level precision) and an unconditional startup-update switch.
- **Reference syntax**: `source_ip(set:chinaip)` / `target_domain(set:chinadomain)`,
  keeping the existing `dip()`/`sip()`/`domain()` syntax as aliases.
- **Free combination**: full reproduction of the original dae rule-combination
  semantics (AND/OR/NOT/multi-condition single action/ordered matching/
  fallback/`any`).
- **eBPF integration**: IP data is compiled into LPM prefix tries, domain data
  into `domain_sets`, with explicit capacity constraints and reject/degrade
  policies on overflow.

## 1. Background & Current State

### 1.1 Problem statement (special review conclusion)

Before this sub-task, dae-rs had **no real GeoSite/GeoIP parsing and matching**.
The key defects, all fixed by Phases 0–3, were:

| # | Location | Defect |
|---|----------|--------|
| 1 | [`matcher.rs`](control/src/routing/matcher.rs) `parse_cidr_values()` | `set:xx` references could not be resolved; CIDR parse failures were silently dropped |
| 2 | [`matcher.rs`](control/src/routing/matcher.rs) `build_match_set_for_function()` | `set:cn` resolution failures were **silently dropped** |
| 3 | [`matcher.rs`](control/src/routing/matcher.rs) domain collection | `domain(set:cn)` was treated as a bare suffix pattern `cn` → degraded to "ends with .cn" matching |
| 4 | Global | No data-file loading/parsing/update mechanism, no data-source config item |

### 1.2 Current architecture constraints

- **Data-plane matching** is compiled by [`compile_rules()`](control/src/routing/matcher.rs) into eBPF:
  - IPs go into LPM prefix tries (`MatchType_IpSet` / `MatchType_SourceIpSet`),
    managed by [`find_or_create_lpm_trie()`](control/src/routing/matcher.rs)
    (FNV-1a dedup).
  - Domains go through `domain_sets` (one `Vec<String>` pattern set per domain
    rule) → eBPF domain set matching in [`tproxy.c`](bpf/kern/tproxy.c).
  - Capacity: `MAX_MATCH_SET_LEN = 1024`; `MAX_LPM_NUM = MAX_MATCH_SET_LEN + 8
    = 1032`; the eBPF `lpm_array_map` outer array is
    `ROUTING_EPOCH_SLOT_NUM * MAX_MATCH_SET_LEN + 8` (double buffering 2×1024+8
    = 2056); a single LPM trie holds `MAX_LPM_SIZE = 2_048_000` entries; the
    `domain_routing_map` bitmap is fixed at `MAX_MATCH_SET_LEN / 32 = 32` u32s
    (i.e. domain-set rule index limit 1024).
- **Config parsing** lives in [`parser.rs`](control/src/config/parser.rs)
  (line-and-indent state machine), validation in
  [`validator.rs`](control/src/config/validator.rs), structures in
  [`mod.rs`](control/src/config/mod.rs).
- Dependencies added for this sub-task: `reqwest` (with `socks` feature) for
  proxied HTTP downloads and `ipnet`/`regex` (already present) for matching.

## 2. Research Findings

### 2.1 Original dae's rule-set & combination capability

> Sources: dae official repo https://github.com/daeuniverse/dae (docs
> `docs/en/configuration/routing.md`, `routing/` sources, `consts`).

**Rule sets**: dae natively supports text domain/IP lists and `geoip:`/`geosite:`
data files. dae-rs currently supports only text domain/IP lists (`domain_list` /
`ip_list`).

**Combination semantics (key design basis)** — a rule = a set of match
conditions + one action:

1. **Multi-condition AND**: conditions within one rule are combined with `&&`,
   e.g. `dport(443) && domain(set:cn) -> direct`.
2. **In-condition OR**: comma-separated values inside one function, e.g.
   `dport(80,443)`.
3. **NOT**: prefix `!`, e.g. `!domain(set:cn)`.
4. **Ordered matching + fallback**: rules are evaluated top to bottom; the
   **first fully-matched** rule wins; otherwise `fallback`.
5. **`any` wildcard**: `any -> action` matches all traffic.
6. **Actions**: `direct` / `block` / `proxy(<group>)`, etc.
7. **"Free combination"**: dae lets you freely mix any number of functions (IP,
   domain, port, protocol, …) ANDed in one rule, unrestricted by function type
   — a capability this design must reproduce.

> Alignment: dae-rs's [`matcher.rs`](control/src/routing/matcher.rs) already
> implements `LOGICAL_OR` / `LOGICAL_AND` / NOT chains
> (`compute_override_outbound()`), consistent with dae's
> `RoutingMatcherBuilder`. This design **keeps that mechanism** and only
> extends its data source (rule sets). Difference: dae-rs unifies function
> names to the new `source_ip` / `target_ip` / `target_domain` syntax while
> keeping old aliases (see §6).

### 2.2 Text list format convention

- **Domain list**: one domain/domain-pattern per line; supports `full:` /
  `domain:` / `suffix:` / `keyword:` / `regex:` prefixes (aligned with dae's
  domain keys); a bare value defaults to `Plain` (suffix incl. self).
- **IP list**: one CIDR (`a.b.c.d/nn`) or bare IP (as /32 or /128) per line;
  `#` starts a comment, blank lines are ignored.

## 3. Formats

See §2.2. The design supports plain-text domain/IP list parsing.

## 4. Storage & Lifecycle

### 4.1 Directory layout: `/var/lib/dae-rs/`

```
/var/lib/dae-rs/
├── chinaip.txt                # text list (domain/IP); filename = config name + .txt
├── chinadomain.txt
├── .tmp/                      # temporary downloads (before verification)
│   └── <name>.tmp.<rand>
├── .checksum/                 # checksum files
│   └── chinaip.txt.sha256
└── .meta/                     # metadata/version/status
    └── <name>.json            # { url, type, last_updated, etag?, sha256, size, state }
```

- Data files and metadata are separated; `.tmp/`, `.checksum/`, `.meta/` are
  hidden directories written only by dae-rs.
- **Namespace isolation**: filename = `<unique name>.txt`. `name` comes from
  the config (§5) and is used for `set:<name>` references and file location.
- `/var/lib/dae-rs/` is created at startup if missing (needs root; dae-rs runs
  privileged). The path may be overridable via CLI/config in the future.

### 4.2 Download management

- **Triggers**: (1) startup update (`update_on_start: true`, §5); (2) scheduler
  due-time (§5.3); (3) compile/reference-time local file missing (fallback,
  §4.4).
- **Download channel (through a proxy)**: when a local file is missing and a
  proxy is needed, use the **first proxy group** (`outbounds.groups[0]`)'s
  currently-selected node (or its first alive node) as a SOCKS5 proxy for the
  HTTP(S) download. Implemented with `reqwest` (socks feature) or by reusing
  the SOCKS5 dialer.
  - A rule-set entry can explicitly set `proxy: <group>` to override; otherwise
    the first proxy group is the default.
  - If the first group is empty/unavailable, fall back to direct download (with
    a warning).
- **Retry**: exponential backoff (default 3 attempts, 2s/4s/8s), single timeout
  30s; retries run in a separate tokio task and never block the main loop.
- **ETag / Last-Modified**: conditional requests when the server supports it;
  304 means no update needed.

### 4.3 Verification, atomic replacement & corruption recovery

1. **Temporary download**: write to `.tmp/<name>.tmp.<rand>` first.
2. **Checksum verification**: after download —
   - if an expected sha256 is configured/URL-provided (`url#sha256=...` or in
     meta), verify it strictly;
   - otherwise compute sha256 and compare with the last recorded one; if equal
     and the server did not change (304/ETag), replacement can be skipped.
   - on failure: delete the temp file, log an error, **keep the old file in
     use**, retry or wait for the next schedule; after a threshold of
     consecutive failures (default 5) the rule set is marked `degraded` and
     only warned about (no infinite retries).
3. **Parse verification**: parse text lines; parse failure is treated as corruption.
4. **Atomic replacement**: after verification `rename()` the temp file over the
   real one (same-directory rename is atomic), then update
   `.meta/<name>.json` and `.checksum/<name>.sha256`.
5. **Corruption recovery**: if the real file fails to parse **at startup** (e.g.
   previous abnormal exit), delete it and re-download; if download also fails,
   skip the rule set with a warning (does not affect others).
6. **Concurrency**: download/replace/read are mutually excluded
   (`tokio::sync::Mutex`); readers (matcher compile) always read the
   **in-memory cache**, never disk; after an update the memory cache is
   rebuilt and routing hot-reloaded.

### 4.4 In-memory cache & hot-reload linkage

- Loaded rule sets are parsed into **in-memory structures**:
  - `ip_list`: `Vec<IpNet>`;
  - `domain_list`: `Vec<DomainPattern>` (type retained:
    suffix/regex/full/domain/keyword).
- After an update, the existing eBPF double-buffer epoch mechanism re-runs
  [`compile_rules()`](control/src/routing/matcher.rs), switching atomically
  (aligned with existing hot reload).

## 5. Configuration

### 5.1 New top-level section: `rule_set`

`DaefileConfig` (in [`mod.rs`](control/src/config/mod.rs)) gained a
`rule_set` field; the parser ([`parser.rs`](control/src/config/parser.rs))
gained a `ParseState::RuleSet` state.

#### Full daefile example

```
rule_set {
  # ── text domain list ──
  chinadomain {
    type: domain_list
    url: 'https://cdn.jsdelivr.net/gh/Loyalsoldier/surge-rules@release/direct.txt'
    name: chinadomain
    update: time: 04:30
    update_on_start: false
  }

  # ── text IP list ──
  chinaip {
    type: ip_list
    url: 'https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/surge/cn.txt'
    name: chinaip
    update: period: 1d
    proxy: proxy_primary         # explicit download proxy group (optional; default first group)
  }
}
```

#### Full config.json example

```json
{
  "rule_set": {
    "chinadomain": {
      "type": "domain_list",
      "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/surge-rules@release/direct.txt",
      "name": "chinadomain",
      "update": { "time": "04:30" },
      "update_on_start": false
    },
    "chinaip": {
      "type": "ip_list",
      "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/surge/cn.txt",
      "name": "chinaip",
      "update": { "period": "1d" },
      "proxy": "proxy_primary"
    }
  }
}
```

> In JSON, `rule_set` is an **object** keyed by entry `name`; the serde
> adapter maps it to/from the in-memory `Vec<RuleSetConfig>`.

> `update` is mutually exclusive: `time: HH:MM` or `period: 3h2m` (see §5.4).

### 5.2 Field definitions

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `type` | yes | enum | `domain_list` (text domains), `ip_list` (text IPs) |
| `url` | yes | string | Download URL (http/https); may carry a `#sha256=...` fragment for mandatory verification |
| `name` | no (default = block name) | string | **Unique** label/name, used for `set:<name>` references and file naming |
| `update` | yes | `{time}` / `{period}` | Update schedule (mutually exclusive) |
| `update_on_start` | no | bool | Force one unconditional update at startup (default false) |
| `proxy` | no | string | Download proxy group; default = the first proxy group |

### 5.3 Unique-name constraint & validation

- **Uniqueness**: all entries' `name` (incl. the block-name default) in
  `rule_set` are globally unique and must not collide with other reference
  kinds. Violation → `ConfigError` (new E2101 `DuplicateRuleSet`).
- **Naming constraint**: `name` allows only `[a-zA-Z0-9_-]` (avoids path
  traversal and reference ambiguity), length ≤ 63.
- **Reference integrity (validator)**:
  - `set:<name>` in routing rules (§6) must hit a `domain_list` / `ip_list`
    entry's name.
  - Unknown reference → `ConfigError` (new E2102 `UnknownRuleSetRef`).
- **URL validation**: must start with `http://` / `https://`; the
  `#sha256=` fragment must be 64 hex chars.

### 5.4 Update schedule semantics (no second-level precision)

- **`time: HH:MM`**: triggers once per day at local `HH:MM` (00-23:00-59);
  **no seconds**.
- **`period: 3h2m`**: periodic trigger; units `d` (days)/`h` (hours)/`m`
  (minutes), combinable (e.g. `1d12h30m`); **minimum unit is minutes,
  seconds are forbidden**; the period is counted from the "last successful
  update" or "last trigger" (see §5.5 decision).
- **Startup update**: with `update_on_start: true`, the process downloads
  unconditionally right after startup (even if the file exists) and resets the
  schedule baseline.

### 5.5 Scheduling semantics (decisions)

- `period` baseline: the **last successful update** (failed runs do not consume
  the period), consistent with dae / mihomo.
- `time` baseline: a fixed daily time; if the process starts after the set
  time, it defers to the next day's same time.
- Multiple rule sets are scheduled independently and aggregated by a **single
  scheduler** (§7).

## 6. Reference Syntax & Parsing

### 6.1 New syntax

| Form | Meaning | Data source |
|------|---------|-------------|
| `source_ip(set:chinaip)` | Source IP hits text IP list `chinaip` | `ip_list` entry |
| `target_ip(set:chinaip)` | Destination IP hits text IP list | `ip_list` entry |
| `target_domain(set:chinadomain)` | Destination domain hits text domain list | `domain_list` entry |

### 6.2 Mapping to / deprecation of existing syntax

| Existing syntax | New syntax (recommended) | Handling |
|-----------------|--------------------------|----------|
| `sip(...)` | `source_ip(...)` | kept as alias, normalized internally |
| `dip(...)` / `ip(...)` | `target_ip(...)` | kept as alias, normalized internally |
| `domain(suffix:.../keyword:/full:/regex:)` | same (kept) | plain domain patterns, coexist with rule sets |

**Normalization**: in the `NormalizedProgram::from_config()` parse stage,
`sip`→`source_ip`, `dip`/`ip`→`target_ip`, recognizing `set:` prefixes and
unifying them into the `Function { name, params }` IR. `domain(...)` stays a
plain domain function.

### 6.3 Data plane (`matcher` / `compile_rules()`) evaluation semantics

- **`source_ip(set:chinaip)` / `target_ip(set:chinaip)`**: in
  `parse_cidr_values()`, recognize the `set:<name>` prefix → look up the
  in-memory cache for `Vec<IpNet>` → build an LPM trie via
  `find_or_create_lpm_trie()` → generate a `MatchType_SourceIpSet` /
  `MatchType_IpSet` MatchSet (value.index = trie index).
- **`target_domain(set:chinadomain)`**: in the domain-collection stage of
  `compile_rules()`, map the Domain list into domain_sets pattern entries
  (`suffix:`/`full:`/`regex:`/`domain:`/`keyword:`), generating a
  `MatchType_DomainSet` MatchSet.
- **Missing data at compile time**: if `set:<name>` is not in the in-memory
  cache (not downloaded/corrupt):
  - silent dropping is no longer allowed (the defect is fixed);
  - default is **compile failure with an error** (E2103
    `RuleSetDataMissing`) prompting a check of the data source; a
    `missing_policy = fail | ignore` switch is a Phase-5 option (default fail).
- **Capacity check**: see §9.

## 7. Scheduler Design

### 7.1 Scheduler role & main-loop relationship

- New `control/src/ruleset/scheduler.rs` (`RuleSetScheduler`), spawned as a
  tokio background task in `ControlPlane.start()`, holding:
  - a `RuleSetManager` (download/storage/verify/in-memory cache) handle;
  - the config `rule_set` entries (with schedule expressions).
- Relationship with the main loop:
  - independent task with `tokio::time` timers;
  - `tokio::sync::watch` / `oneshot` to the main loop: on update completion,
    notify `ControlPlane` to re-compile routing and hot-reload (reusing the
    eBPF double-buffer epoch);
  - does not block [`src/lib.rs`](src/lib.rs)'s `tokio::select!` signal loop;
    shutdown is graceful via a cancellation signal (`CancellationToken` or
    `watch`).

### 7.2 Schedule aggregation

- A single task schedules all rule sets: maintain each entry's next trigger
  time (`Instant`/`DateTime`), wake with `sleep_until(nearest)`, process all
  due entries, then schedule the next.
- `time: HH:MM` → next `Local` time; `period: X` → `last_update + X`
  (baseline = last successful update, §5.5).
- At startup, entries with `update_on_start: true` trigger downloads
  immediately (async, without blocking startup completion).

## 8. Error Handling & Observability

### 8.1 Error paths & logging

| Stage | Failure behavior | Log level | User-visible behavior |
|-------|------------------|-----------|-----------------------|
| Download failure | exponential backoff (3 attempts); keep old file on final failure | `warn`/`error` | rule set not updated; missing data → related rule compile error (E2103, §6.3) |
| Checksum failure | delete temp file, keep old file, mark degraded | `error` | same; after 5 consecutive failures automatic retries stop (manual/startup update still possible) |
| text parse failure | treated as corruption, recover per §4.3 | `error` | missing data → related rule compile error (E2103, §6.3) |
| Missing rule-set reference (compile time) | default compile failure; `missing_policy=ignore` skips the rule | `error`/`warn` | config error (E2103) or log warning |
| Capacity overflow | refuse to compile and error (§9) | `error` | config error prompting fewer rules |
| Proxy-group download failure | fall back to direct (with warning); direct failure → download failure | `warn` | same as above |

- All via `tracing`, with rule-set `name`, `url` and error context.
- Update status (`state`, `last_updated`, `sha256`, failure reason) is
  persisted in `.meta/<name>.json` for API/diagnostics.

### 8.2 Config validation (validator) extension

- `validate_config()` adds `validate_rule_set(config)`:
  1. `rule_set` entry name uniqueness + naming constraint (E2101);
  2. URL protocol / `#sha256=` validation;
  3. `update` mutual exclusion + time/period format (seconds rejected);
  4. `set:<name>` reference integrity in routing rules (E2102).

### 8.3 New error codes

In the `ConfigError` enum ([`mod.rs`](control/src/config/mod.rs)):

- `E2101 DuplicateRuleSet { name }` — duplicate rule set name;
- `E2102 UnknownRuleSetRef { reference }` — unknown rule set reference;
- `E2103 RuleSetDataMissing { reference, reason }` — compile-time data missing;
- `E2104 InvalidRuleSetUpdate { name, message }` — invalid schedule expression
  (incl. seconds);
- `E2105 InvalidRuleSetUrl { name }` — invalid URL;
- `E2106 RuleSetCapacityExceeded { detail }` — capacity overflow (§9).

## 9. eBPF Integration & Capacity

### 9.1 Compile targets

- **IP list** → LPM prefix tries:
  - each `set:<ip_list>` reference resolves to a set of `IpNet`s, deduplicated
    and mapped to an LPM trie index via `find_or_create_lpm_trie()`, written
    into `MatchType_IpSet` / `MatchType_SourceIpSet`.
- **Domain list** → `domain_sets` patterns:
  - each `set:<domain_list>` reference maps to one domain_sets entry
    (suffix/full/regex/domain patterns).

### 9.2 Capacity constraint assessment

| Resource | Limit | Constraint |
|----------|-------|-----------|
| routing_map (per epoch slot) | `MAX_MATCH_SET_LEN = 1024` | total MatchSet entries (incl. logical chains & fallback) |
| LPM tries (userspace compile time) | `MAX_LPM_NUM = 1032` | `matcher.rs` |
| LPM trie outer array (eBPF double buffer) | `2 * 1024 + 8 = 2056` | `tproxy.c` |
| entries inside one LPM trie | `MAX_LPM_SIZE = 2_048_000` | ~2M CIDRs per trie |
| domain_routing_map bitmap | 32 u32 (=1024 bit) | **domain-set rule index limit 1024** (each set domain reference uses 1 bit) |

- **The bottleneck is the MatchSet total and the domain-set index count (rule
  count)**.
- **Note**: domain-set index = count of `target_domain(set:*)` / `domain(...)`
  rule entries appearing at compile time (deduplicated by reference), capped
  at 1024.

### 9.3 Overflow & degrade policy

- **Primary: refuse to compile and error** (E2106), prompting:
  - fewer rules / merged rule-set references;
  - adjusting `MAX_MATCH_SET_LEN` (must keep `matcher.rs` and `tproxy.c` in
    sync; constrained by eBPF stack/bitmap memory).
- **Optional degradation (Phase 5, off by default)**:
  - domain-set index overflow: sample/truncate a domain set (e.g. subset by
    suffix/prefix hash) with a warning — not recommended as it changes matching
    semantics;
  - segmentation: split oversized sets across epoch slots — conflicts with the
    double-buffer architecture, recorded as a long-term option.
- Detected at compile time; no runtime dynamic expansion; eBPF map sizes stay
  compile-time constants for `bytemuck` layout compatibility.

## 10. Free Combination

### 10.1 Semantic model (aligned with dae)

```
routing = [rule1, rule2, ..., fallback]
rule    = { condition combination, action }
combination = condition1 AND condition2 AND ...   # all must match
condition   = function(v1, v2, ...) | !function(...)  # values OR'd; NOT negates
action      = direct | block | proxy(<group>) | control_plane_routing
any         = unconditionally true
```

- **Multi-condition single action**: any number of different functions freely
  ANDed (IP+domain+port+protocol may mix).
- **Priority**: ordered matching; the first fully-matched rule wins; otherwise
  fallback.
- **`any` wildcard**: `any -> action`.

### 10.2 Data-plane evaluation flow (implemented, kept)

[`matcher.rs`](control/src/routing/matcher.rs) lowers "in-function multi-value
OR + inter-function AND + NOT" into a linear MatchSet sequence via the
`LOGICAL_OR`/`LOGICAL_AND` outbound chain; eBPF `route()` and the userspace
`RoutingMatcher::match_routing()` evaluate identically. Rule-set functions
(`source_ip`/`target_ip`/`target_domain`) share this chain with existing
functions.

## 11. Alignment & Differences vs. dae

| Dimension | dae | dae-rs (this design) | Notes |
|-----------|-----|----------------------|-------|
| rule-set data | v2ray `.dat` + text lists | text lists only | difference |
| rule-set management | URLs + scheduled update in `global` | standalone `rule_set` section, multiple files, unique names, independent scheduling | enhanced |
| data directory | `/usr/local/share/dae` (configurable) | `/var/lib/dae-rs/` (fixed default, future-configurable) | difference (user-specified) |
| reference syntax | `geosite:xx`/`geoip:xx` + `set:name` | `set:name` | difference |
| function naming | `dip`/`sip`/`domain` | adds `source_ip`/`target_ip`/`target_domain`, keeps old aliases | superset |
| combination semantics | AND/OR/NOT/any/order/fallback | fully consistent | aligned |

## 12. Implementation Phases

> For orchestrator dispatch of Code sub-tasks. Each phase is independently
> verifiable. **Phases 0–3 are implemented; Phase 4 (examples & docs) is the
> companion task of this document.**

### Phase 0: Dependencies & skeleton
- Add dependencies: HTTP client (`reqwest`, with socks proxy).
- Add module skeleton `control/src/ruleset/` (`mod.rs`, `types.rs`).

### Phase 1: Data layer (formats + storage + download + verification)
- Text domain/IP list parsing (`full:`/`domain:`/`suffix:`/`keyword:`/`regex:`
  prefixes).
- `/var/lib/dae-rs/` layout, `.tmp/`/`.checksum/`/`.meta/` management.
- Downloader: direct + proxied (SOCKS5 tunnel), retry, ETag, sha256
  verification, atomic replacement, corruption recovery.
- **Verify**: unit tests (parse text lists, verify/replace logic).

### Phase 2: Configuration & scheduling
- `DaefileConfig.rule_set` structure + parser (`ParseState::RuleSet`) +
  validator (E2101/E2102/E2104/E2105) + error codes.
- `RuleSetScheduler` (time/period, update_on_start, tokio task, aggregation,
  graceful shutdown).
- **Verify**: config parse/validate unit tests; scheduler time-computation
  tests.

### Phase 3: Syntax / matcher integration
- Reference syntax parsing & normalization (`source_ip`/`target_ip`/
  `target_domain` + `set:`; old-alias mapping).
- matcher: `compile_rules()` wired to rule sets → LPM trie / domain_sets;
  missing-data handling (E2103); capacity check (E2106).
- **Verify**: routing compile tests (rule sets → MatchSet/LPM/domain_sets).

### Phase 4: Examples & docs
- Update [`config-example/config.daefile`](config-example/config.daefile) and
  [`config-example/config.json`](config-example/config.json) (add `rule_set`
  section and `source_ip`/`target_ip`/`target_domain` example rules).
- Update [`docs/config/config_zh_hans.md`](docs/config/config_zh_hans.md)
  (config fields), [`docs/design/routing_zh_hans.md`](docs/design/routing_zh_hans.md)
  (data path evaluation), plus the English counterparts.
- **Verify**: example configs parse/validate; doc review.

### Phase 5 (optional): testing & extensions
- End-to-end tests: real data-source download → routing compile → eBPF load →
  match verification.
- `missing_policy=ignore`, domain-set overflow sampling degrade options.

## 13. Confirmed Decisions

> The following four technical choices were confirmed with the project owner
> (2026-08-03) as hard constraints for the implementation phases:

1. **`period` baseline**: the **"last successful update"** is the baseline
   (failed runs do not consume the period). See §5.5, §7.2.
2. **HTTP client**: **`reqwest`** (async, `socks` feature enabled for
   SOCKS5 downloads through proxy groups). See §4.2, Phase 0.

4. **Compile-time missing-data policy**: default **compile failure with error**
   (E2103), fixing the old "silent drop" defect; `missing_policy=ignore` is a
   Phase-5 optional degrade. See §6.3, §8.1.

## 14. References

- dae official repo: https://github.com/daeuniverse/dae
  (`docs/en/configuration/routing.md`)
- dae-rs existing docs: `docs/design/routing_zh_hans.md`,
  `docs/config/config_zh_hans.md`
