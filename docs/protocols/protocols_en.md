# Supported Protocols

> Bilingual documentation. The Chinese version is available at
> [`protocols_zh_hans.md`](./protocols_zh_hans.md).

## Overview

dae-rs supports multiple outbound proxy protocols. This directory contains
documentation for each supported protocol.

## Protocol List

| Protocol | Transport | Encryption | UDP Support | Documentation |
|----------|-----------|------------|-------------|---------------|
| SOCKS5 | TCP | None (plain) | ✓ | [socks5](../config/config_en.md) |
| Shadowsocks | TCP + UDP | AEAD | ✓ | [shadowsocks](./shadowsocks/shadowsocks_en.md) |
| Trojan | TCP | TLS 1.2/1.3 | Optional | [trojan](./trojan/trojan_en.md) |
| TUIC v5 | QUIC (UDP) | TLS 1.3 | ✓ | [tuic](./tuic/tuic_en.md) |
| Juicity | QUIC (UDP) | TLS 1.3 | ✓ | [juicity](./juicity/juicity_en.md) |
| VMess | TCP/WS/gRPC/H2 | Multiple | ✓ | [vmess](./vmess/vmess_en.md) |

## Quick Comparison

### By Security Level

| Level | Protocols |
|-------|-----------|
| High (TLS 1.3) | Trojan, TUIC v5, Juicity |
| High (AEAD) | Shadowsocks 2022 |
| Medium (TLS optional) | VMess, SOCKS5 |

### By Use Case

| Use Case | Recommended Protocol |
|----------|---------------------|
| General-purpose | Shadowsocks, SOCKS5 |
| High censorship environments | Trojan, VMess+WS |
| High performance/low latency | TUIC v5, Juicity |
| CDN compatibility | VMess+WS, Trojan+WS |

## TLS Certificate Pinning

For protocols that use TLS (Trojan, TUIC, Juicity, VMess), you can pin the
server certificate's SHA256 fingerprint for additional security:

```
ca_sha256: "fb3a01e4..."
```

**Note**: `skip_cert_verify` is NOT allowed for Trojan protocol. Certificate
verification is mandatory.

## Import Links

dae-rs supports importing nodes from subscription links:

```
import: 'ss://cipher:password@server:port'
import: 'trojan://password@server:port?sni=example.com'
import: 'tuic://uuid:password@server:port?congestion_control=bbr'
import: 'juicity://uuid:password@server:port'
import: 'vmess://uuid@server:port?security=auto'
```

## References

- [Configuration Guide](../config/config_en.md)
- [Protocol Specifications](#protocol-list)
