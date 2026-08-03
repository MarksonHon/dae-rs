# Trojan Protocol

> Bilingual documentation. The Chinese version is available at
> [`trojan_zh_hans.md`](./trojan_zh_hans.md).

## Overview

Trojan is an unidentifiable mechanism for bypassing network censorship. It
disguises proxy traffic as normal HTTPS connections by using TLS encryption and
mimicking a web server. The protocol is simple and effective.

**Specification**: https://github.com/trojan-gfw/trojan/blob/master/docs/protocol.md

## Protocol Features

- **Encryption**: TLS 1.2/1.3 (required)
- **Transport**: TCP (+ optional UDP ASSOCIATE)
- **Authentication**: Password hash (SHA224)
- **Camouflage**: Indistinguishable from HTTPS traffic

## How It Works

1. Client performs a real TLS handshake with the server
2. If TLS handshake fails, server behaves like a normal HTTPS server
3. After TLS succeeds, client sends Trojan header with password hash
4. Server verifies the hash and establishes connection to target

## Configuration

### daefile Format

```
nodes {
  trojan_node {
    protocol: trojan
    address: server.example.com:443
    password: your-password
    sni: server.example.com
    # ca_sha256: "fb3a01e4..." # Pin certificate SHA256
    dial_timeout_ms: 5000
  }
}
```

### JSON Format

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

### Link Format

```
trojan://password@server.example.com:443?sni=example.com
```

### Import

```
nodes {
  trojan_import {
    import: 'trojan://password@server.example.com:443?sni=example.com'
  }
}
```

## Configuration Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `address` | Yes | Server address in `host:port` format |
| `password` | Yes | Authentication password |
| `sni` | No | Server Name Indication for TLS (defaults to address host) |
| `ca_sha256` | No | Pin server certificate SHA256 fingerprint (hex, without colons) |
| `dial_timeout_ms` | No | Dial timeout in milliseconds (default: 5000) |

## Security Notes

- **Certificate verification is mandatory** - cannot be disabled
- Users can pin the server certificate using `ca_sha256` for additional security
- The server should listen on port 443 with a valid TLS certificate
- Failed connections are redirected to a fallback endpoint (default: 127.0.0.1:80)

## References

- [Trojan Protocol Specification](https://github.com/trojan-gfw/trojan/blob/master/docs/protocol.md)
- [Trojan Documentation](https://trojan-gfw.github.io/trojan/protocol.html)
