# VMess Protocol

> Bilingual documentation. The Chinese version is available at
> [`vmess_zh_hans.md`](./vmess_zh_hans.md).

## Overview

VMess is an encrypted transport protocol from the V2Ray project. It uses UUID for
authentication and supports multiple encryption methods. VMess can work over various
transports including TCP, WebSocket, gRPC, and HTTP/2.

**Specification**: https://www.v2fly.org/en_US/developer/protocols/vmess.html

## Protocol Features

- **Encryption**: Multiple ciphers (AES-128-GCM, ChaCha20-Poly1305, etc.)
- **Transport**: TCP, WebSocket, gRPC, HTTP/2
- **Authentication**: UUID-based with timestamp validation
- **AEAD Authentication**: Recommended (provides header integrity)

## Authentication Methods

| Method | Status | Description |
|--------|--------|-------------|
| AEAD | Recommended | Uses AES-128-GCM for header encryption |
| MD5 | Deprecated | Legacy method, not recommended |

## Transport Options

### TCP (Default)
Direct TCP connection to the server.

### WebSocket (WS)
Useful for CDN relay and bypassing DPI.

### WebSocket + TLS (WSS)
WebSocket with TLS encryption. Recommended for CDN usage.

### HTTP/2 (H2)
Multiplexed transport over HTTP/2. Requires TLS.

### gRPC
Modern transport with good performance. Requires TLS.

## Configuration

### daefile Format

```
nodes {
  # TCP transport (default)
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

  # WebSocket transport
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

  # WebSocket + TLS transport (WSS)
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

  # HTTP/2 transport (requires TLS)
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

  # gRPC transport (requires TLS)
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

### JSON Format

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

### Link Format

```
vmess://uuid@server.example.com:443?security=auto
vmess://uuid@server.example.com:443?security=none&type=ws&path=/ws&host=example.com
```

### v2rayN Base64 Format

VMess also supports the v2rayN base64-encoded format. The URL format is:

```
vmess://base64(json)
```

Where the JSON contains:

| Field | Description |
|-------|-------------|
| `v` | Version, always `"2"` |
| `ps` | Node name/alias |
| `add` | Server address |
| `port` | Server port |
| `id` | User UUID |
| `aid` | alterId |
| `scy` | Cipher method |
| `net` | Transport protocol: `tcp`, `ws`, `h2`, `grpc`, `kcp`, `quic` |
| `type` | Camouflage type (for KCP) |
| `host` | Camouflage host |
| `path` | Path (for ws/h2/grpc) |
| `tls` | TLS enabled: `tls` or empty |
| `sni` | SNI |
| `fp` | TLS fingerprint |

### Import

```
nodes {
  # Standard URI import
  vmess_uri_import {
    import: 'vmess://uuid@server.example.com:443?security=auto'
  }

  # v2rayN base64 import
  vmess_base64_import {
    import: 'vmess://eyJ2IjoiMiIsInBzIjoi5Zu95LyB5LqM5L2T5L2N572uIiwicCI6IjExMS4xMTEuMTExLjExMSIsInBvcnQiOiIzMjAwMCIsImlkIjoiMTM4NmY4NWUtNjViYi00ZTZlLTlkNTYtNzhiYWRiNzVlMWZkIiwiYWlkIjoiMTAwIiwic2N5IjoiYXV0byIsIm5ldCI6IndzIiwidHlwZSI6Im5vbmUiLCJob3N0Ijoid3d3LmJiYi5jb20iLCJwYXRoIjoiLyIsInRscyI6InRscyIsInNuaSI6Ind3dy5jY2MubmV0IiwidmVyc2lvbiI6IjIifQ=='
  }
}
```

## Configuration Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `address` | Yes | Server address in `host:port` format |
| `uuid` | Yes | User UUID for authentication |
| `security` | No | Encryption: `auto`, `aes-128-gcm`, `chacha20-poly1305`, `none` (default: `auto`) |
| `alter_id` | No | Legacy compatibility field (default: `0`) |
| `network` | No | Transport: `tcp`, `ws`, `grpc`, `h2` (default: `tcp`) |
| `ws_path` | No | WebSocket path (when network is `ws`) |
| `ws_headers` | No | WebSocket headers (when network is `ws`) |
| `h2_path` | No | HTTP/2 path (when network is `h2`) |
| `h2_host` | No | HTTP/2 host header (when network is `h2`) |
| `grpc_service_name` | No | gRPC service name (when network is `grpc`) |
| `sni` | No | Server Name Indication for TLS |
| `ca_sha256` | No | Pin server certificate SHA256 fingerprint |
| `dial_timeout_ms` | No | Dial timeout in milliseconds (default: 5000) |

## Security Notes

- VMess depends on system time - ensure NTP is configured
- AEAD authentication is recommended over MD5
- Use `alter_id: 0` for AEAD mode
- Certificate verification is enabled by default
- Users can pin the server certificate using `ca_sha256` for additional security
- When using TLS transport (WSS, H2, gRPC), set `security: none` to avoid double encryption

## Transport Selection Guide

| Scenario | Recommended Transport |
|----------|----------------------|
| General purpose | TCP |
| CDN relay | WebSocket + TLS (WSS) |
| High performance | gRPC |
| HTTP/2 infrastructure | HTTP/2 |

## References

- [VMess Protocol (V2Fly)](https://www.v2fly.org/en_US/developer/protocols/vmess.html)
- [VMess Protocol (Xray)](https://xtls.github.io/en/development/protocols/vmess.html)
- [V2Ray Documentation](https://www.v2ray.com/en/configuration/protocols/vmess.html)
