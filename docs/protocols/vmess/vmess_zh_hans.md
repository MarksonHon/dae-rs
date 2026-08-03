# VMess 协议

> 双语文档。英文版本见 [`vmess_en.md`](./vmess_en.md)。

## 概述

VMess 是来自 V2Ray 项目的加密传输协议。它使用 UUID 进行认证，支持多种
加密方法。VMess 可以通过多种传输方式工作，包括 TCP、WebSocket、gRPC 和 HTTP/2。

**规范文档**: https://www.v2fly.org/en_US/developer/protocols/vmess.html

## 协议特性

- **加密**: 多种密码（AES-128-GCM、ChaCha20-Poly1305 等）
- **传输**: TCP、WebSocket、gRPC、HTTP/2
- **认证**: 基于 UUID，带有时间戳验证
- **AEAD 认证**: 推荐（提供头部完整性保护）

## 认证方法

| 方法 | 状态 | 说明 |
|------|------|------|
| AEAD | 推荐 | 使用 AES-128-GCM 进行头部加密 |
| MD5 | 已弃用 | 旧方法，不推荐 |

## 传输选项

### TCP（默认）
直接 TCP 连接到服务器。

### WebSocket (WS)
用于 CDN 中继和绕过 DPI。

### WebSocket + TLS (WSS)
带 TLS 加密的 WebSocket。推荐用于 CDN 场景。

### HTTP/2 (H2)
基于 HTTP/2 的多路复用传输。需要 TLS。

### gRPC
现代化传输，性能良好。需要 TLS。

## 配置

### daefile 格式

```
nodes {
  # TCP 传输（默认）
  vmess_tcp_node {
    protocol: vmess
    address: server.example.com:443
    uuid: d0529668-8835-11ec-a8a3-0242ac120002
    security: auto
    alter_id: 0
    sni: server.example.com
    # ca_sha256: "fb3a01e4..."
    dial_timeout_ms: 5000
  }

  # WebSocket 传输
  vmess_ws_node {
    protocol: vmess
    address: server.example.com:80
    uuid: d0529668-8835-11ec-a8a3-0242ac120002
    security: none
    alter_id: 0
    network: ws
    ws_path: /ws
    ws_headers: { "Host": "example.com" }
    dial_timeout_ms: 5000
  }

  # WebSocket + TLS 传输（WSS）
  vmess_ws_tls_node {
    protocol: vmess
    address: server.example.com:443
    uuid: d0529668-8835-11ec-a8a3-0242ac120002
    security: none
    alter_id: 0
    network: ws
    ws_path: /ws
    ws_headers: { "Host": "example.com" }
    sni: server.example.com
    # ca_sha256: "fb3a01e4..."
    dial_timeout_ms: 5000
  }

  # HTTP/2 传输（需要 TLS）
  vmess_h2_node {
    protocol: vmess
    address: server.example.com:443
    uuid: d0529668-8835-11ec-a8a3-0242ac120002
    security: none
    alter_id: 0
    network: h2
    h2_path: /h2
    h2_host: example.com
    sni: server.example.com
    # ca_sha256: "fb3a01e4..."
    dial_timeout_ms: 5000
  }

  # gRPC 传输（需要 TLS）
  vmess_grpc_node {
    protocol: vmess
    address: server.example.com:443
    uuid: d0529668-8835-11ec-a8a3-0242ac120002
    security: none
    alter_id: 0
    network: grpc
    grpc_service_name: grpc
    sni: server.example.com
    # ca_sha256: "fb3a01e4..."
    dial_timeout_ms: 5000
  }
}
```

### JSON 格式

```json
{
  "name": "vmess_ws_tls_node",
  "protocol": "vmess",
  "params": {
    "address": "server.example.com:443",
    "uuid": "d0529668-8835-11ec-a8a3-0242ac120002",
    "security": "none",
    "alter_id": 0,
    "network": "ws",
    "ws_path": "/ws",
    "ws_headers": { "Host": "example.com" },
    "sni": "server.example.com",
    "ca_sha256": "",
    "dial_timeout_ms": 5000
  }
}
```

### 链接格式

```
vmess://uuid@server.example.com:443?security=auto
vmess://uuid@server.example.com:443?security=none&type=ws&path=/ws&host=example.com
```

### v2rayN Base64 格式

VMess 还支持 v2rayN base64 编码格式。URL 格式为：

```
vmess://base64(json)
```

其中 JSON 包含：

| 字段 | 说明 |
|------|------|
| `v` | 版本号，固定为 `"2"` |
| `ps` | 节点名称/别名 |
| `add` | 服务器地址 |
| `port` | 服务器端口 |
| `id` | 用户 UUID |
| `aid` | alterId |
| `scy` | 加密方法 |
| `net` | 传输协议：`tcp`、`ws`、`h2`、`grpc`、`kcp`、`quic` |
| `type` | 伪装类型（用于 KCP） |
| `host` | 伪装主机名 |
| `path` | 路径（用于 ws/h2/grpc） |
| `tls` | 是否启用 TLS：`tls` 或空 |
| `sni` | SNI |
| `fp` | TLS 指纹 |

### 导入

```
nodes {
  # 标准 URI 导入
  vmess_uri_import {
    import: 'vmess://uuid@server.example.com:443?security=auto'
  }

  # v2rayN base64 导入
  vmess_base64_import {
    import: 'vmess://eyJ2IjoiMiIsInBzIjoi5Zu95LyB5LqM5L2T5L2N572uIiwicCI6IjExMS4xMTEuMTExLjExMSIsInBvcnQiOiIzMjAwMCIsImlkIjoiMTM4NmY4NWUtNjViYi00ZTZlLTlkNTYtNzhiYWRiNzVlMWZkIiwiYWlkIjoiMTAwIiwic2N5IjoiYXV0byIsIm5ldCI6IndzIiwidHlwZSI6Im5vbmUiLCJob3N0Ijoid3d3LmJiYi5jb20iLCJwYXRoIjoiLyIsInRscyI6InRscyIsInNuaSI6Ind3dy5jY2MubmV0IiwidmVyc2lvbiI6IjIifQ=='
  }
}
```

## 配置参数

| 参数 | 必需 | 说明 |
|------|------|------|
| `address` | 是 | 服务器地址，格式为 `host:port` |
| `uuid` | 是 | 用户 UUID，用于认证 |
| `security` | 否 | 加密方法：`auto`、`aes-128-gcm`、`chacha20-poly1305`、`none`（默认：`auto`） |
| `alter_id` | 否 | 旧版兼容字段（默认：`0`） |
| `network` | 否 | 传输方式：`tcp`、`ws`、`grpc`、`h2`（默认：`tcp`） |
| `ws_path` | 否 | WebSocket 路径（当 network 为 `ws` 时） |
| `ws_headers` | 否 | WebSocket 头部（当 network 为 `ws` 时） |
| `h2_path` | 否 | HTTP/2 路径（当 network 为 `h2` 时） |
| `h2_host` | 否 | HTTP/2 主机头（当 network 为 `h2` 时） |
| `grpc_service_name` | 否 | gRPC 服务名称（当 network 为 `grpc` 时） |
| `sni` | 否 | TLS 的服务器名称指示 |
| `ca_sha256` | 否 | 固定服务器证书 SHA256 指纹 |
| `dial_timeout_ms` | 否 | 拨号超时（毫秒），默认：5000 |

## 安全说明

- VMess 依赖系统时间 - 确保配置了 NTP
- 推荐使用 AEAD 认证而不是 MD5
- 使用 `alter_id: 0` 进行 AEAD 模式
- 默认启用证书验证
- 用户可以使用 `ca_sha256` 固定服务器证书以获得额外安全性
- 使用 TLS 传输（WSS、H2、gRPC）时，设置 `security: none` 以避免双重加密

## 传输选择指南

| 场景 | 推荐传输 |
|------|----------|
| 通用用途 | TCP |
| CDN 中继 | WebSocket + TLS (WSS) |
| 高性能 | gRPC |
| HTTP/2 基础设施 | HTTP/2 |

## 参考资料

- [VMess 协议（V2Fly）](https://www.v2fly.org/en_US/developer/protocols/vmess.html)
- [VMess 协议（Xray）](https://xtls.github.io/en/development/protocols/vmess.html)
- [V2Ray 文档](https://www.v2ray.com/en/configuration/protocols/vmess.html)
