//! Outbound dialer factory.
//!
//! Maps a parsed [`OutboundNodeConfig`] to a concrete protocol dialer
//! ([`Arc<dyn OutboundDialer>`](protocols::OutboundDialer)), wired with the
//! host-namespace fd and eBPF self-exclusion mark.

use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::sync::Arc;

use anyhow::Context;
use std::str::FromStr;

use crate::config;

/// Build a dialer for the given node.
///
/// * `host_ns_fd` — when set, all upstream sockets are created in the host
///   network namespace (kdae-aligned).
/// * `socket_mark` — SO_MARK for eBPF self-exclusion (0 = skip).
pub fn build_dialer(
    node: &config::OutboundNodeConfig,
    host_ns_fd: Option<RawFd>,
    socket_mark: u32,
) -> anyhow::Result<Arc<dyn protocols::OutboundDialer>> {
    let addr: SocketAddr = node
        .address
        .parse()
        .with_context(|| format!("invalid node '{}' address: {}", node.name, node.address))?;
    let timeout_ms = node.dial_timeout_ms;
    let password = node.password.clone().unwrap_or_default();
    let sni = node.sni.clone().unwrap_or_default();

    let dialer: Arc<dyn protocols::OutboundDialer> = match node.protocol.as_str() {
        "socks5" => Arc::new(protocols::Socks5Dialer::new_with_mark(
            addr,
            node.username.clone().unwrap_or_default(),
            password,
            timeout_ms,
            socket_mark,
        )),
        "shadowsocks" => {
            let cipher = node.cipher.clone().unwrap_or_default();
            let mut d = protocols::ShadowsocksDialer::new_with_mark(
                addr, cipher, password, timeout_ms, socket_mark,
            );
            d.set_host_ns_fd(host_ns_fd);
            Arc::new(d)
        }
        "trojan" => {
            let mut d = protocols::TrojanDialer::new_with_mark(
                addr, password, sni, timeout_ms, socket_mark,
            );
            d.set_ca_sha256(node.ca_sha256.clone());
            d.set_host_ns_fd(host_ns_fd);
            Arc::new(d)
        }
        "tuic" => {
            let uuid = node.uuid.clone().unwrap_or_default();
            let mut d = protocols::TuicDialer::new(addr, uuid, password, timeout_ms);
            if let Some(cc) = &node.congestion_control {
                d.set_congestion_control(cc);
            }
            if let Some(alpn) = &node.alpn {
                d.set_alpn(alpn.clone());
            }
            d.set_sni(sni);
            d.set_ca_sha256(node.ca_sha256.clone());
            d.set_self_mark(socket_mark);
            d.set_host_ns_fd(host_ns_fd);
            Arc::new(d)
        }
        "juicity" => {
            let uuid = node.uuid.clone().unwrap_or_default();
            let mut d = protocols::JuicityDialer::new(addr, uuid, password, timeout_ms);
            if let Some(cc) = &node.congestion_control {
                d.set_congestion_control(cc);
            }
            d.set_sni(sni);
            d.set_ca_sha256(node.ca_sha256.clone());
            d.set_self_mark(socket_mark);
            d.set_host_ns_fd(host_ns_fd);
            Arc::new(d)
        }
        "vmess" => {
            let uuid = node.uuid.clone().unwrap_or_default();
            let mut d = protocols::VMessDialer::new(addr, uuid, timeout_ms);
            if let Some(sec) = &node.security {
                d.set_security(sec);
            }
            if let Some(aid) = node.alter_id {
                d.set_alter_id(aid);
            }
            if let Some(net) = &node.network {
                let network = protocols::VMessNetwork::from_str(net).map_err(|e| {
                    anyhow::anyhow!("node '{}' invalid vmess network '{}': {}", node.name, net, e)
                })?;
                d.set_network(network);
            }
            if let Some(p) = &node.ws_path {
                d.set_ws_path(p);
            }
            if let Some(h) = &node.ws_headers {
                d.set_ws_headers(h.clone());
            }
            if let Some(p) = &node.h2_path {
                d.set_h2_path(p);
            }
            if let Some(h) = &node.h2_host {
                d.set_h2_host(h);
            }
            if let Some(s) = &node.grpc_service_name {
                d.set_grpc_service_name(s);
            }
            d.set_sni(sni);
            d.set_ca_sha256(node.ca_sha256.clone());
            d.set_self_mark(socket_mark);
            d.set_host_ns_fd(host_ns_fd);
            Arc::new(d)
        }
        other => anyhow::bail!(
            "node '{}' has unsupported protocol '{}'",
            node.name,
            other
        ),
    };

    Ok(dialer)
}
