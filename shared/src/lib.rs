#![allow(dead_code)]

//! Shared data structures
//!
//! Common data type definitions used across modules (control plane, eBPF, protocol layer) for inter-module communication.
//! All types derive `Serialize`/`Deserialize` for serialization support.

use serde::{Deserialize, Serialize};

/// The fwmark value for dae-rs internal sockets.
///
/// eBPF programs identify proxy self-originated traffic via `pid_is_control_plane()` and this mark
/// socket traffic and skip it (preventing self-forwarding dead loops). Must be consistent with TProxy (`SO_MARK`) and
/// the SOCKS5 dialer's mark value. The original dae uses `0x100`.
pub const DAE_SOCKET_MARK: u32 = 0x100;

/// Split/flow action
///
/// The action to take after a rule matches, determining traffic direction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Action {
    /// Direct: let traffic pass through the system routing
    Direct,
    /// Proxy: forward through the specified outbound group
    Proxy(String),
}

/// Rule entry
///
/// Represents a split/flow rule consisting of a match condition and an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Destination IP or CIDR
    pub dip: Option<String>,
    /// Destination port
    pub dport: Option<u16>,
    /// L4 protocol type
    pub l4proto: Option<L4Proto>,
    /// Action to take after a match
    pub action: Action,
}

/// Network endpoint
///
/// Represents a combination of an IP address and port.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Endpoint {
    /// IP address (IPv4 or IPv6 string form)
    pub ip: String,
    /// Port number
    pub port: u16,
}

impl Endpoint {
    /// Create a new endpoint
    pub fn new(ip: impl Into<String>, port: u16) -> Self {
        Self {
            ip: ip.into(),
            port,
        }
    }
}

/// L4 protocol type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum L4Proto {
    /// TCP protocol
    Tcp,
    /// UDP protocol
    Udp,
}

impl L4Proto {
    /// Convert protocol type to the numeric representation used in eBPF maps
    pub fn to_u8(&self) -> u8 {
        match self {
            L4Proto::Tcp => 1,
            L4Proto::Udp => 2,
        }
    }

    /// Create L4Proto from IP protocol number
    pub fn from_ip_protocol(protocol: u8) -> Option<Self> {
        match protocol {
            6 => Some(L4Proto::Tcp),
            17 => Some(L4Proto::Udp),
            _ => None,
        }
    }
}

/// Split/flow decision result
///
/// The split/flow decision made by the eBPF program for each packet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProxyDecision {
    /// Direct
    Direct,
    /// Proxy (includes outbound group name)
    Proxy(String),
    /// Block (reserved, not implemented in phase 1)
    Block,
}

/// Connection quadruplet (for conntrack)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// Source IP
    pub src_ip: [u8; 16],
    /// Destination IP
    pub dst_ip: [u8; 16],
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Protocol type
    pub protocol: u8,
}

/// Configuration version info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigMeta {
    /// Configuration version number
    pub version: u32,
    /// Configuration generation timestamp
    pub generated_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_l4proto_conversion() {
        assert_eq!(L4Proto::Tcp.to_u8(), 1);
        assert_eq!(L4Proto::Udp.to_u8(), 2);
        assert_eq!(L4Proto::from_ip_protocol(6), Some(L4Proto::Tcp));
        assert_eq!(L4Proto::from_ip_protocol(17), Some(L4Proto::Udp));
        assert_eq!(L4Proto::from_ip_protocol(1), None);
    }

    #[test]
    fn test_endpoint() {
        let ep = Endpoint::new("192.168.1.1", 1080);
        assert_eq!(ep.ip, "192.168.1.1");
        assert_eq!(ep.port, 1080);
    }

    #[test]
    fn test_action_serialization() {
        let direct = Action::Direct;
        let proxy = Action::Proxy("test_group".into());
        assert_eq!(serde_json::to_string(&direct).unwrap(), r#""Direct""#);
        assert_eq!(
            serde_json::to_string(&proxy).unwrap(),
            r#"{"Proxy":"test_group"}"#
        );
    }
}
