# TUIC Protocol

> Bilingual documentation. The Chinese version is available at
> [`tuic_zh_hans.md`](./tuic_zh_hans.md).

## Overview

TUIC is a lightweight QUIC-based proxy protocol designed for low latency and high
throughput. Version 5 (v5) is the latest stable version, compatible with mihomo
and other implementations.

**Specification**: https://github.com/tuic-protocol/tuic/blob/master/SPEC.md

## Protocol Features

- **Transport**: QUIC (UDP-based)
- **Encryption**: TLS 1.3 (built into QUIC)
- **Multiplexing**: Native QUIC streams
- **Authentication**: UUID + password
- **0-RTT**: Support for quick connection establishment

## Command Types

| Command | Code | Description |
|---------|------|-------------|
| Authenticate | `0x00` | Authenticate the multiplexed stream |
| Connect | `0x01` | Establish a TCP relay |
| Packet | `0x02` | Relay UDP packets (with fragmentation support) |
| Dissociate | `0x03` | Terminate a UDP relaying session |
| Heartbeat | `0x04` | Keep the QUIC connection alive |

## Configuration

### daefile Format

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

### JSON Format

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

### Link Format

```
tuic://uuid:password@server.example.com:443?congestion_control=bbr&alpn=h3
```

### Import

```
nodes {
  tuic_import {
    import: 'tuic://uuid:password@server.example.com:443?congestion_control=bbr&alpn=h3'
  }
}
```

## Configuration Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `address` | Yes | Server address in `host:port` format |
| `uuid` | Yes | User UUID for authentication |
| `password` | Yes | User password for authentication |
| `congestion_control` | No | Congestion control algorithm (default: `bbr`) |
| `alpn` | No | ALPN protocol list (default: `["h3"]`) |
| `sni` | No | Server Name Indication for TLS |
| `ca_sha256` | No | Pin server certificate SHA256 fingerprint |
| `dial_timeout_ms` | No | Dial timeout in milliseconds (default: 5000) |

## Security Notes

- TUIC uses TLS 1.3 built into QUIC for encryption
- Certificate verification is enabled by default
- Users can pin the server certificate using `ca_sha256` for additional security
- The protocol supports 0-RTT for quick connection establishment

## Compatibility

TUIC v5 is compatible with:
- mihomo (Clash.Meta)
- sing-box
- Other TUIC v5 implementations

## References

- [TUIC Protocol Specification](https://github.com/tuic-protocol/tuic/blob/master/SPEC.md)
- [TUIC GitHub](https://github.com/tuic-protocol/tuic)
