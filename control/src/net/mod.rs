//! Network data plane modules.
//!
//! Kernel- and socket-level networking that carries the actual proxy traffic:
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`ebpf`] | eBPF program load/unload/attach + maps |
//! | [`tproxy`] | TProxy transparent proxy listener (TCP + UDP) |
//! | [`netns`] | Network namespace & veth pair management |
//! | [`iface_mgr`] | WAN/LAN interface discovery and matching |
//! | [`udp_tracker`] | UDP connection tracking for TProxy |

pub mod ebpf;
pub mod iface_mgr;
pub mod netns;
pub mod tproxy;
pub mod udp_tracker;
