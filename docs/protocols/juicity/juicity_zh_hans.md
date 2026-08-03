# Juicity 协议

> 双语文档。英文版本见 [`juicity_en.md`](./juicity_en.md)。

## 概述

Juicity 是一种基于 QUIC 的代理协议，灵感来自 TUIC，通过"UDP over Stream"
改进了 UDP 处理。与 TUIC 的原生 UDP 模式相比，它提供了更好的稳定性和性能。

**规范文档**: https://github.com/juicity/juicity/blob/main/docs/spec.md

## 协议特性

- **传输**: QUIC（基于 UDP）
- **加密**: TLS 1.3（内置于 QUIC）
- **多路复用**: 原生 QUIC 流
- **认证**: UUID + 密码
- **UDP 处理**: UDP over Stream（改进自 TUIC）

## 工作原理

1. 客户端与服务器建立 QUIC 连接
2. 客户端打开一个单向流并发送认证信息
3. 对于 TCP：客户端打开一个带有代理头的双向流
4. 对于 UDP：数据通过双向流多路复用
5. 认证是按连接进行的，而不是按流

## 配置

### daefile 格式

```
nodes {
  juicity_node {
    protocol: juicity
    address: server.example.com:443
    uuid: d0529668-8835-11ec-a8a3-0242ac120002
    password: your-password
    sni: server.example.com
    # ca_sha256: "fb3a01e4..."
    dial_timeout_ms: 5000
  }
}
```

### JSON 格式

```json
{
  "name": "juicity_node",
  "protocol": "juicity",
  "params": {
    "address": "server.example.com:443",
    "uuid": "d0529668-8835-11ec-a8a3-0242ac120002",
    "password": "your-password",
    "sni": "server.example.com",
    "ca_sha256": "",
    "dial_timeout_ms": 5000
  }
}
```

### 链接格式

```
juicity://uuid:password@server.example.com:443
```

### 导入

```
nodes {
  juicity_import {
    import: 'juicity://uuid:password@server.example.com:443'
  }
}
```

## 配置参数

| 参数 | 必需 | 说明 |
|------|------|------|
| `address` | 是 | 服务器地址，格式为 `host:port` |
| `uuid` | 是 | 用户 UUID，用于认证 |
| `password` | 是 | 用户密码，用于认证 |
| `sni` | 否 | TLS 的服务器名称指示 |
| `ca_sha256` | 否 | 固定服务器证书 SHA256 指纹 |
| `dial_timeout_ms` | 否 | 拨号超时（毫秒），默认：5000 |

## 安全说明

- Juicity 使用内置于 QUIC 的 TLS 1.3 进行加密
- 默认启用证书验证
- 用户可以使用 `ca_sha256` 固定服务器证书以获得额外安全性
- 协议要求使用 BBR 拥塞控制

## 与 TUIC 的区别

| 特性 | TUIC | Juicity |
|------|------|---------|
| UDP 处理 | 原生或 QUIC 流 | UDP over Stream |
| 分片 | 支持 | 不需要（基于流） |
| 稳定性 | 良好 | 更好 |

## 参考资料

- [Juicity 协议规范（中文）](https://github.com/juicity/juicity/blob/main/docs/spec.md)
- [Juicity 协议规范（英文）](https://github.com/juicity/juicity/blob/main/docs/spec_en.md)
- [Juicity GitHub](https://github.com/juicity/juicity)
