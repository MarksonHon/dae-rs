# TUIC 协议

> 双语文档。英文版本见 [`tuic_en.md`](./tuic_en.md)。

## 概述

TUIC 是一种轻量级的基于 QUIC 的代理协议，专为低延迟和高吞吐量而设计。
版本 5（v5）是最新的稳定版本，兼容 mihomo 和其他实现。

**规范文档**: https://github.com/tuic-protocol/tuic/blob/master/SPEC.md

## 协议特性

- **传输**: QUIC（基于 UDP）
- **加密**: TLS 1.3（内置于 QUIC）
- **多路复用**: 原生 QUIC 流
- **认证**: UUID + 密码
- **0-RTT**: 支持快速连接建立

## 命令类型

| 命令 | 代码 | 说明 |
|------|------|------|
| Authenticate | `0x00` | 认证多路复用流 |
| Connect | `0x01` | 建立 TCP 中继 |
| Packet | `0x02` | 中继 UDP 数据包（支持分片） |
| Dissociate | `0x03` | 终止 UDP 中继会话 |
| Heartbeat | `0x04` | 保持 QUIC 连接活跃 |

## 配置

### daefile 格式

```
nodes {
  tuic_node {
    protocol: tuic
    address: server.example.com:443
    uuid: d0529668-8835-11ec-a8a3-0242ac120002
    password: your-password
    congestion_control: bbr
    alpn: h3
    sni: server.example.com
    # ca_sha256: "fb3a01e4..."
    dial_timeout_ms: 5000
  }
}
```

### JSON 格式

```json
{
  "name": "tuic_node",
  "protocol": "tuic",
  "params": {
    "address": "server.example.com:443",
    "uuid": "d0529668-8835-11ec-a8a3-0242ac120002",
    "password": "your-password",
    "congestion_control": "bbr",
    "alpn": ["h3"],
    "sni": "server.example.com",
    "ca_sha256": "",
    "dial_timeout_ms": 5000
  }
}
```

### 链接格式

```
tuic://uuid:password@server.example.com:443?congestion_control=bbr&alpn=h3
```

### 导入

```
nodes {
  tuic_import {
    import: 'tuic://uuid:password@server.example.com:443?congestion_control=bbr&alpn=h3'
  }
}
```

## 配置参数

| 参数 | 必需 | 说明 |
|------|------|------|
| `address` | 是 | 服务器地址，格式为 `host:port` |
| `uuid` | 是 | 用户 UUID，用于认证 |
| `password` | 是 | 用户密码，用于认证 |
| `congestion_control` | 否 | 拥塞控制算法（默认：`bbr`） |
| `alpn` | 否 | ALPN 协议列表（默认：`["h3"]`） |
| `sni` | 否 | TLS 的服务器名称指示 |
| `ca_sha256` | 否 | 固定服务器证书 SHA256 指纹 |
| `dial_timeout_ms` | 否 | 拨号超时（毫秒），默认：5000 |

## 安全说明

- TUIC 使用内置于 QUIC 的 TLS 1.3 进行加密
- 默认启用证书验证
- 用户可以使用 `ca_sha256` 固定服务器证书以获得额外安全性
- 协议支持 0-RTT 以实现快速连接建立

## 兼容性

TUIC v5 兼容：
- mihomo (Clash.Meta)
- sing-box
- 其他 TUIC v5 实现

## 参考资料

- [TUIC 协议规范](https://github.com/tuic-protocol/tuic/blob/master/SPEC.md)
- [TUIC GitHub](https://github.com/tuic-protocol/tuic)
