# dae-rs

**dae-rs** is an AI-generated rewrite of [dae](https://github.com/daeuniverse/dae)
(github.com/daeuniverse/dae), an eBPF-based, high-performance transparent proxy
solution for Linux.

## Purpose

This project exists **primarily to test an AI's ability to rewrite a
Linux kernel-level development project**. It is an experiment / benchmark, not a
product:

- It is **not guaranteed to be usable** in any real environment.
- Do not rely on it for production traffic.
- Expect rough edges, incomplete features, and potential instability.

For a stable, battle-tested proxy, please use the original
[dae](https://github.com/daeuniverse/dae).

## License

This project is licensed under the **GNU Affero General Public License v3.0
(AGPL-3.0)**. See [LICENSE](./LICENSE).

> The eBPF kernel programs under `bpf/kern/` are derived from the original dae
> project and carry their own AGPL-3.0-only license headers.

## Documentation

- Configuration: [`docs/config/config_en.md`](./docs/config/config_en.md)
  · [`docs/config/config_zh_hans.md`](./docs/config/config_zh_hans.md)
- Routing subsystem design: [`docs/design/routing_en.md`](./docs/design/routing_en.md)
  · [`docs/design/routing_zh_hans.md`](./docs/design/routing_zh_hans.md)

## Requirements

- **Linux kernel >= 6.6** (required): the data plane attaches its eBPF programs
  via **TCX** (`BPF_LINK_TYPE_TCX`). There is no classic-TC fallback — startup
  aborts on older kernels.
- **root** privileges (creating network namespaces, attaching eBPF programs,
  configuring interfaces), plus `clang` / `llvm-strip` to build the eBPF object.
- A supported proxy backend: SOCKS5, Shadowsocks, Trojan, VMess, TUIC, Juicity.

## DNS

dae-rs ships a userspace **DNS forwarder** (replacing the removed eBPF DNS
hijack): port-53 queries are still intercepted as ordinary UDP by TProxy, then
split by domain using the existing `routing` rules (`domain` / `target_domain`
→ proxy group / direct / block). Each group keeps its own TTL cache and
persistent UDP relay sessions. See
[`docs/config/config_en.md`](./docs/config/config_en.md) for the `dns` section.
