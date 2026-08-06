# dae-rs

**dae-rs** 是 [dae](https://github.com/daeuniverse/dae)
（github.com/daeuniverse/dae）的 AI 重写版本。dae 是一个基于 eBPF 的
Linux 高性能透明代理解决方案。

## 项目用途

本项目存在的**主要目的是测试 AI 重写 Linux 内核级别开发项目的能力**，
属于实验 / 基准验证，而非产品：

- **不保证任何可用性**，无法保证能在任何真实环境中运行。
- 请勿依赖它承载生产流量。
- 预期存在粗糙之处、不完整的功能以及潜在的不稳定问题。

如需稳定、久经考验的代理，请使用原版 [dae](https://github.com/daeuniverse/dae)。

## 许可证

本项目采用 **GNU Affero General Public License v3.0（AGPL-3.0）** 授权。
详见 [LICENSE](./LICENSE)。

> `bpf/kern/` 下的 eBPF 内核程序源自原 dae 项目，带有独立的
> AGPL-3.0-only 许可证头。

## 文档入口

- 配置说明：[`docs/config/config_zh_hans.md`](./docs/config/config_zh_hans.md)
  · [`docs/config/config_en.md`](./docs/config/config_en.md)
- 路由子系统设计：[`docs/design/routing_zh_hans.md`](./docs/design/routing_zh_hans.md)
  · [`docs/design/routing_en.md`](./docs/design/routing_en.md)
