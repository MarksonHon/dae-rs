# Juicity Protocol

> Bilingual documentation. The Chinese version is available at
> [`juicity_zh_hans.md`](./juicity_zh_hans.md).

## Overview

Juicity is a QUIC-based proxy protocol inspired by TUIC, with improved UDP handling
through "UDP over Stream". It provides better stability and performance compared
to TUIC's native UDP mode.

**Specification**: https://github.com/juicity/juicity/blob/main/docs/spec.md

## Protocol Features

- **Transport**: QUIC (UDP-based)
- **Encryption**: TLS 1.3 (built into QUIC)
- **Multiplexing**: Native QUIC streams
- **Authentication**: UUID + password
- **UDP Handling**: UDP over Stream (improved over TUIC)

## How It Works

1. Client establishes a QUIC connection to the server
2. Client opens a unidirectional stream and sends authentication
3. For TCP: Client opens a bidirectional stream with proxy header
4. For UDP: Data is multiplexed over bidirectional streams
5. Authentication is per-connection, not per-stream

## Configuration

### daefile Format

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

### JSON Format

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

### Link Format

```
juicity://uuid:password@server.example.com:443
```

### Import

```
nodes {
  juicity_import {
    import: 'juicity://uuid:password@server.example.com:443'
  }
}
```

## Configuration Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `address` | Yes | Server address in `host:port` format |
| `uuid` | Yes | User UUID for authentication |
| `password` | Yes | User password for authentication |
| `sni` | No | Server Name Indication for TLS |
| `ca_sha256` | No | Pin server certificate SHA256 fingerprint |
| `dial_timeout_ms` | No | Dial timeout in milliseconds (default: 5000) |

## Security Notes

- Juicity uses TLS 1.3 built into QUIC for encryption
- Certificate verification is enabled by default
- Users can pin the server certificate using `ca_sha256` for additional security
- The protocol requires BBR congestion control

## Differences from TUIC

| Feature | TUIC | Juicity |
|---------|------|---------|
| UDP Handling | Native or QUIC streams | UDP over Stream |
| Fragmentation | Supported | Not needed (stream-based) |
| Stability | Good | Better |

## References

- [Juicity Protocol Specification (Chinese)](https://github.com/juicity/juicity/blob/main/docs/spec.md)
- [Juicity Protocol Specification (English)](https://github.com/juicity/juicity/blob/main/docs/spec_en.md)
- [Juicity GitHub](https://github.com/juicity/juicity)
