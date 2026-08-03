# 支持的协议

> 双语文档。英文版本见 [`protocols_en.md`](./protocols_en.md)。

## 概述

dae-rs 支持多种出站代理协议。本目录包含每个支持协议的文档。

## 协议列表

| 协议 | 传输 | 加密 | UDP 支持 | 文档 |
|------|------|------|----------|------|
| SOCKS5 | TCP | 无（明文） | ✓ | [socks5](../config/config_zh_hans.md) |
| Shadowsocks | TCP + UDP | AEAD | ✓ | [shadowsocks](./shadowsocks/shadowsocks_zh_hans.md) |
| Trojan | TCP | TLS 1.2/1.3 | 可选 | [trojan](./trojan/trojan_zh_hans.md) |
| TUIC v5 | QUIC (UDP) | TLS 1.3 | ✓ | [tuic](./tuic/tuic_zh_hans.md) |
| Juicity | QUIC (UDP) | TLS 1.3 | ✓ | [juicity](./juicity/juicity_zh_hans.md) |
| VMess | TCP/WS/gRPC/H2 | 多种 | ✓ | [vmess](./vmess/vmess_zh_hans.md) |

## 快速对比

### 按安全级别

| 级别 | 协议 |
|------|------|
| 高（TLS 1.3） | Trojan、TUIC v5、Juicity |
| 高（AEAD） | Shadowsocks 2022 |
| 中（TLS 可选） | VMess、SOCKS5 |

### 按使用场景

| 场景 | 推荐协议 |
|------|----------|
| 通用用途 | Shadowsocks、SOCKS5 |
| 高审查环境 | Trojan、VMess+WS |
| 高性能/低延迟 | TUIC v5、Juicity |
| CDN 兼容性 | VMess+WS、Trojan+WS |

## TLS 证书固定

对于使用 TLS 的协议（Trojan、TUIC、Juicity、VMess），您可以固定服务器证书
的 SHA256 指纹以获得额外安全性：

```
ca_sha256: "fb3a01e4..."
```

**注意**：Trojan 协议不允许使用 `skip_cert_verify`。证书验证是强制的。

## 导入链接

dae-rs 支持从订阅链接导入节点：

```
import: 'ss://cipher:password@server:port'
import: 'trojan://password@server:port?sni=example.com'
import: 'tuic://uuid:password@server:port?congestion_control=bbr'
import: 'juicity://uuid:password@server:port'
import: 'vmess://uuid@server:port?security=auto'
```

## 参考资料

- [配置指南](../config/config_zh_hans.md)
- [协议规范](#协议列表)
