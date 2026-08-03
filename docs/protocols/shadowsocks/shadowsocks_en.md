# Shadowsocks Protocol

> Bilingual documentation. The Chinese version is available at
> [`shadowsocks_zh_hans.md`](./shadowsocks_zh_hans.md).

## Overview

Shadowsocks is a secure proxy protocol for TCP and UDP traffic. It supports
two encryption families:

- **2022 Edition (SIP022)**: Uses AEAD with BLAKE3 key derivation (recommended)
- **AEAD (Legacy)**: Uses AEAD with HKDF-SHA1 key derivation

**Specification**: https://shadowsocks.org/doc/sip022.html

## Protocol Features

- **Encryption**: AEAD ciphers (AES-GCM, ChaCha20-Poly1305)
- **Transport**: TCP + UDP
- **Authentication**: Pre-shared key (PSK)
- **Obfuscation**: Traffic indistinguishable from random bytes

## Supported Ciphers

### 2022 Edition (SIP022) - Recommended

| Cipher | Key Bytes | Salt Bytes | Status |
|--------|-----------|------------|--------|
| `2022-blake3-aes-128-gcm` | 16 | 16 | Required |
| `2022-blake3-aes-256-gcm` | 32 | 32 | Required |
| `2022-blake3-chacha20-poly1305` | 32 | 32 | Optional |

### AEAD (Legacy)

| Cipher | Key Bytes | Salt Bytes | Status |
|--------|-----------|------------|--------|
| `aes-128-gcm` | 16 | 16 | Optional |
| `aes-192-gcm` | 24 | 24 | Optional |
| `aes-256-gcm` | 32 | 32 | Optional |
| `chacha20-ietf-poly1305` | 32 | 32 | Required |

## Configuration

### daefile Format

```
nodes {
  # 2022 Edition (Recommended)
  ss2022_node {
    protocol: shadowsocks
    address: server.example.com:8388
    cipher: 2022-blake3-aes-256-gcm
    password: your-psk-here
    dial_timeout_ms: 5000
  }

  # AEAD (Legacy)
  ss_aead_node {
    protocol: shadowsocks
    address: server.example.com:8388
    cipher: aes-256-gcm
    password: your-password
    dial_timeout_ms: 5000
  }
}
```

### JSON Format

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

### Link Format

```
ss://2022-blake3-aes-256-gcm:password@server.example.com:8388
ss://aes-256-gcm:password@server.example.com:8388
```

### Import

```
nodes {
  ss_import {
    import: 'ss://2022-blake3-aes-256-gcm:password@server.example.com:8388'
  }
}
```

## Configuration Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `address` | Yes | Server address in `host:port` format |
| `cipher` | Yes | Encryption cipher (see Supported Ciphers) |
| `password` | Yes | Pre-shared key (cryptographically secure for 2022) |
| `dial_timeout_ms` | No | Dial timeout in milliseconds (default: 5000) |

## Security Notes

- **2022 Edition** requires a cryptographically-secure fixed-length PSK
- **AEAD** accepts password-based keys (derived via EVP_BytesToKey)
- The protocol provides confidentiality and integrity through AEAD encryption
- Traffic is indistinguishable from random byte streams

## References

- [SIP022 Specification](https://shadowsocks.org/doc/sip022.html)
- [AEAD Ciphers](https://shadowsocks.org/doc/aead.html)
- [Extensible Identity Headers](https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-2-shadowsocks-2022-extensible-identity-headers.md)
