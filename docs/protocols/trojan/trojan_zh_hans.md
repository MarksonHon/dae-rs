# Trojan 协议

> 双语文档。英文版本见 [`trojan_en.md`](./trojan_en.md)。

## 概述

Trojan 是一种不可识别的机制，用于绕过网络审查。它通过使用 TLS 加密和模拟
Web 服务器，将代理流量伪装成正常的 HTTPS 连接。协议简单而有效。

**规范文档**: https://github.com/trojan-gfw/trojan/blob/master/docs/protocol.md

## 协议特性

- **加密**: TLS 1.2/1.3（必需）
- **传输**: TCP（+ 可选的 UDP ASSOCIATE）
- **认证**: 密码哈希（SHA224）
- **伪装**: 与 HTTPS 流量无法区分

## 工作原理

1. 客户端与服务器进行真实的 TLS 握手
2. 如果 TLS 握手失败，服务器表现得像普通 HTTPS 服务器
3. TLS 成功后，客户端发送带有密码哈希的 Trojan 头部
4. 服务器验证哈希并建立到目标的连接

## 配置

### daefile 格式

```
nodes {
  trojan_node {
    protocol: trojan
    address: server.example.com:443
    password: your-password
    sni: server.example.com
    # ca_sha256: "fb3a01e4..." # 固定证书 SHA256
    dial_timeout_ms: 5000
  }
}
```

### JSON 格式

```json
{
  "name": "trojan_node",
  "protocol": "trojan",
  "params": {
    "address": "server.example.com:443",
    "password": "your-password",
    "sni": "server.example.com",
    "ca_sha256": "",
    "dial_timeout_ms": 5000
  }
}
```

### 链接格式

```
trojan://password@server.example.com:443?sni=example.com
```

### 导入

```
nodes {
  trojan_import {
    import: 'trojan://password@server.example.com:443?sni=example.com'
  }
}
```

## 配置参数

| 参数 | 必需 | 说明 |
|------|------|------|
| `address` | 是 | 服务器地址，格式为 `host:port` |
| `password` | 是 | 认证密码 |
| `sni` | 否 | TLS 的服务器名称指示（默认使用地址中的主机名） |
| `ca_sha256` | 否 | 固定服务器证书 SHA256 指纹（十六进制，不带冒号） |
| `dial_timeout_ms` | 否 | 拨号超时（毫秒），默认：5000 |

## 安全说明

- **证书验证是强制的** - 无法禁用
- 用户可以使用 `ca_sha256` 固定服务器证书以获得额外安全性
- 服务器应使用有效的 TLS 证书监听 443 端口
- 失败的连接会被重定向到回退端点（默认：127.0.0.1:80）

## 参考资料

- [Trojan 协议规范](https://github.com/trojan-gfw/trojan/blob/master/docs/protocol.md)
- [Trojan 文档](https://trojan-gfw.github.io/trojan/protocol.html)
