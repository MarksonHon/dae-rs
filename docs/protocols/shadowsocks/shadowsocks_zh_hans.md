# Shadowsocks 协议

> 双语文档。英文版本见 [`shadowsocks_en.md`](./shadowsocks_en.md)。

## 概述

Shadowsocks 是一个用于 TCP 和 UDP 流量的安全代理协议。它支持两个加密系列：

- **2022 版本（SIP022）**：使用 AEAD 和 BLAKE3 密钥派生（推荐）
- **AEAD（旧版）**：使用 AEAD 和 HKDF-SHA1 密钥派生

**规范文档**: https://shadowsocks.org/doc/sip022.html

## 协议特性

- **加密**: AEAD 密码（AES-GCM、ChaCha20-Poly1305）
- **传输**: TCP + UDP
- **认证**: 预共享密钥（PSK）
- **混淆**: 流量与随机字节无法区分

## 支持的密码

### 2022 版本（SIP022）- 推荐

| 密码 | 密钥字节 | 盐值字节 | 状态 |
|------|----------|----------|------|
| `2022-blake3-aes-128-gcm` | 16 | 16 | 必需 |
| `2022-blake3-aes-256-gcm` | 32 | 32 | 必需 |
| `2022-blake3-chacha20-poly1305` | 32 | 32 | 可选 |

### AEAD（旧版）

| 密码 | 密钥字节 | 盐值字节 | 状态 |
|------|----------|----------|------|
| `aes-128-gcm` | 16 | 16 | 可选 |
| `aes-192-gcm` | 24 | 24 | 可选 |
| `aes-256-gcm` | 32 | 32 | 可选 |
| `chacha20-ietf-poly1305` | 32 | 32 | 必需 |

## 配置

### daefile 格式

```
nodes {
  # 2022 版本（推荐）
  ss2022_node {
    protocol: shadowsocks
    address: server.example.com:8388
    cipher: 2022-blake3-aes-256-gcm
    password: your-psk-here
    dial_timeout_ms: 5000
  }

  # AEAD（旧版）
  ss_aead_node {
    protocol: shadowsocks
    address: server.example.com:8388
    cipher: aes-256-gcm
    password: your-password
    dial_timeout_ms: 5000
  }
}
```

### JSON 格式

```json
{
  "name": "ss2022_node",
  "protocol": "shadowsocks",
  "params": {
    "address": "server.example.com:8388",
    "cipher": "2022-blake3-aes-256-gcm",
    "password": "your-psk-here",
    "dial_timeout_ms": 5000
  }
}
```

### 链接格式

```
ss://2022-blake3-aes-256-gcm:password@server.example.com:8388
ss://aes-256-gcm:password@server.example.com:8388
```

### 导入

```
nodes {
  ss_import {
    import: 'ss://2022-blake3-aes-256-gcm:password@server.example.com:8388'
  }
}
```

## 配置参数

| 参数 | 必需 | 说明 |
|------|------|------|
| `address` | 是 | 服务器地址，格式为 `host:port` |
| `cipher` | 是 | 加密密码（见支持的密码） |
| `password` | 是 | 预共享密钥（2022 版本需要密码学安全） |
| `dial_timeout_ms` | 否 | 拨号超时（毫秒），默认：5000 |

## 安全说明

- **2022 版本**要求使用密码学安全的固定长度 PSK
- **AEAD**接受基于密码的密钥（通过 EVP_BytesToKey 派生）
- 协议通过 AEAD 加密提供机密性和完整性
- 流量与随机字节流无法区分

## 参考资料

- [SIP022 规范](https://shadowsocks.org/doc/sip022.html)
- [AEAD 密码](https://shadowsocks.org/doc/aead.html)
- [可扩展身份头](https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-2-shadowsocks-2022-extensible-identity-headers.md)
