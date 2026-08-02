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
- DNS subsystem design: [`docs/design/dns_en.md`](./docs/design/dns_en.md)
  · [`docs/design/dns_zh_hans.md`](./docs/design/dns_zh_hans.md)
- Routing subsystem design: [`docs/design/routing_en.md`](./docs/design/routing_en.md)
  · [`docs/design/routing_zh_hans.md`](./docs/design/routing_zh_hans.md)
