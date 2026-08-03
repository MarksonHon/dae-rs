//! Routing handoff consumer — userspace routing decision engine.
//!
//! The eBPF program (`tproxy.c`) tags traffic that requires userspace routing
//! with `outbound == OUTBOUND_CONTROL_PLANE_ROUTING` (0xFD) and writes the
//! flow tuple to `routing_handoff_map`. This module implements the background
//! task [`RoutingHandoffConsumer`] that:
//!
//! 1. Polls `routing_handoff_map` for new entries
//! 2. For each entry, performs a userspace routing decision via [`RoutingMatcher`]
//! 3. Writes the final routing decision (outbound, mark, must) back to
//!    `conn_state_map` so the eBPF program can forward subsequent packets
//!    correctly
//! 4. Deletes the processed entry from `routing_handoff_map`
//!
//! # Why this is necessary
//!
//! All proxy nodes and groups are currently mapped to
//! `OUTBOUND_CONTROL_PLANE_ROUTING` (0xFD) in the eBPF routing table because
//! the real outbound (DIRECT, or a specific proxy group) depends on connectivity
//! health, latency, and load-balancing policies that are evaluated in userspace.
//! The eBPF program cannot make this decision alone — it hands off the decision
//! to userspace via `routing_handoff_map`.
//!
//! # Lifecycle
//!
//! ```text
//! eBPF TC hook                  RoutingHandoffConsumer
//! ─────────────                  ──────────────────────
//!     │                                │
//!     │  route() → outbound=0xFD       │
//!     │  publish_routing_handoff()     │
//!     │  ─────────────────────────►    │  poll routing_handoff_map
//!     │                                │  match_routing() via RoutingMatcher
//!     │                                │  set_conn_state(key, result)
//!     │                                │  delete_routing_handoff_entry(key)
//!     │                                │
//!     │  subsequent packets now        │
//!     │  look up conn_state_map        │
//!     │  → find final outbound         │
//!     │  → forward correctly           │
//! ```

use anyhow::Result;
use bytemuck::Zeroable;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use tracing::{debug, info, warn};

use crate::net::ebpf::{
    ConnState, EbpfManager, RoutingHandoffEntry, RoutingMeta, TuplesKey,
};
use crate::routing::matcher::{RoutingMatcher, RoutingParams, RoutingResult};

// ============================================================================
// Constants
// ============================================================================

/// Poll interval for the routing handoff map (100ms).
const POLL_INTERVAL_MS: u64 = 100;

/// Timeout for entries in routing_handoff_map (30 seconds).
/// Entries older than this are discarded without processing to avoid
/// processing stale flow information for long-dead connections.
const ENTRY_TIMEOUT_NS: u64 = 30_000_000_000;

// ============================================================================
// RoutingHandoffConsumer
// ============================================================================

/// Background task that consumes entries from `routing_handoff_map`.
///
/// For each entry, it uses the userspace [`RoutingMatcher`] to determine the
/// actual outbound, writes the decision to `conn_state_map`, and removes the
/// entry from the handoff map.
pub struct RoutingHandoffConsumer {
    /// Shared eBPF manager (locked for map I/O).
    ebpf_mgr: Arc<Mutex<EbpfManager>>,
    /// Userspace routing matcher with compiled MatchSet/LPM/domain rules.
    matcher: Arc<RoutingMatcher>,
    /// Poll interval duration.
    poll_interval: std::time::Duration,
}

impl RoutingHandoffConsumer {
    /// Create a new `RoutingHandoffConsumer`.
    ///
    /// # Parameters
    ///
    /// * `ebpf_mgr` — Shared eBPF manager, typically `Arc<Mutex<EbpfManager>>`
    ///   from the control plane.
    /// * `matcher` — Compiled [`RoutingMatcher`] containing the userspace
    ///   routing rules. Must be built from the same config as the eBPF rules.
    pub fn new(ebpf_mgr: Arc<Mutex<EbpfManager>>, matcher: Arc<RoutingMatcher>) -> Self {
        Self {
            ebpf_mgr,
            matcher,
            poll_interval: std::time::Duration::from_millis(POLL_INTERVAL_MS),
        }
    }

    /// Run the consumer loop (blocking, designed for `tokio::spawn`).
    ///
    /// This method runs indefinitely, polling `routing_handoff_map` every
    /// 100ms and processing any entries found.
    pub async fn run(&self) {
        info!("RoutingHandoffConsumer started (poll interval: {}ms)", POLL_INTERVAL_MS);

        loop {
            tokio::time::sleep(self.poll_interval).await;

            // ── Step 1: Read all entries from routing_handoff_map ──
            let entries = match self.read_handoff_entries() {
                Ok(entries) => entries,
                Err(e) => {
                    warn!("RoutingHandoffConsumer: failed to read entries: {}", e);
                    continue;
                }
            };

            if entries.is_empty() {
                continue;
            }

            let now_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;

            debug!(
                "RoutingHandoffConsumer: processing {} entries",
                entries.len()
            );

            // ── Step 2: Process each entry ──
            for (key, entry) in &entries {
                // Skip stale entries (e.g., from a previous lifecycle)
                if now_ns.saturating_sub(entry.last_seen_ns) > ENTRY_TIMEOUT_NS {
                    debug!(
                        "RoutingHandoffConsumer: skipping stale entry (age={}ns)",
                        now_ns.saturating_sub(entry.last_seen_ns)
                    );
                    // Delete stale entries to prevent map bloat
                    let _ = self.delete_handoff_entry(key);
                    continue;
                }

                // Build routing params from the 5-tuple + process info
                let params = build_routing_params(key, entry);

                // Make userspace routing decision
                let decision = self.matcher.match_routing(&params);

                // Build conn_state entry with the routing decision
                let conn_state = build_conn_state(entry, &decision);

                // Write to conn_state_map and delete from routing_handoff_map
                if let Err(e) = self.commit_routing_decision(key, &conn_state) {
                    warn!(
                        "RoutingHandoffConsumer: failed to commit decision for flow \
                         {:?}: {}",
                        key, e
                    );
                }
            }

            if !entries.is_empty() {
                info!(
                    "RoutingHandoffConsumer: processed {} handoff entries",
                    entries.len()
                );
            }
        }
    }

    /// Read all entries from `routing_handoff_map` (holds lock briefly).
    fn read_handoff_entries(
        &self,
    ) -> Result<Vec<(TuplesKey, RoutingHandoffEntry)>> {
        let mut mgr = self
            .ebpf_mgr
            .lock()
            .map_err(|e| anyhow::anyhow!("ebpf_mgr lock: {}", e))?;
        mgr.get_routing_handoff_entries()
    }

    /// Delete a single entry from `routing_handoff_map` (holds lock briefly).
    fn delete_handoff_entry(&self, key: &TuplesKey) -> Result<()> {
        let mut mgr = self
            .ebpf_mgr
            .lock()
            .map_err(|e| anyhow::anyhow!("ebpf_mgr lock: {}", e))?;
        mgr.delete_routing_handoff_entry(key)
    }

    /// Atomically write to `conn_state_map` and delete from `routing_handoff_map`.
    ///
    /// Both operations are performed while holding the same lock to ensure
    /// consistency: the entry is removed from the handoff map only after the
    /// conn_state has been written, preventing duplicate processing.
    fn commit_routing_decision(
        &self,
        key: &TuplesKey,
        conn_state: &ConnState,
    ) -> Result<()> {
        let mut mgr = self
            .ebpf_mgr
            .lock()
            .map_err(|e| anyhow::anyhow!("ebpf_mgr lock: {}", e))?;

        // Write to conn_state_map first
        mgr.set_conn_state(key, conn_state)?;

        // Then delete from routing_handoff_map
        mgr.delete_routing_handoff_entry(key)?;

        Ok(())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Build [`RoutingParams`] from the eBPF handoff tuple and entry.
///
/// Extracts source/destination IPs, ports, protocol, and process info from
/// the handoff entry so the userspace [`RoutingMatcher`] can evaluate rules.
fn build_routing_params(key: &TuplesKey, entry: &RoutingHandoffEntry) -> RoutingParams {
    let src_ip = ip_from_tuples_key(&key.sip);
    let dst_ip = ip_from_tuples_key(&key.dip);

    let process_name = if entry.result.pname.iter().any(|&b| b != 0) {
        Some(
            std::str::from_utf8(&entry.result.pname)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_string(),
        )
    } else {
        None
    };

    RoutingParams {
        src_ip,
        dst_ip,
        src_port: Some(key.sport),
        dst_port: Some(key.dport),
        l4proto: Some(key.l4proto),
        domain: None, // Domain info is not available from eBPF handoff
        process_name,
        dscp: Some(entry.result.dscp),
    }
}

/// Convert a 16-byte IPv6-style address to an [`IpAddr`].
///
/// IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) are detected and converted
/// to [`Ipv4Addr`].
fn ip_from_tuples_key(addr: &[u8; 16]) -> Option<IpAddr> {
    if addr[0..10].iter().all(|&b| b == 0) && addr[10] == 0xff && addr[11] == 0xff {
        // IPv4-mapped IPv6 address
        Some(IpAddr::V4(std::net::Ipv4Addr::new(
            addr[12], addr[13], addr[14], addr[15],
        )))
    } else {
        Some(IpAddr::V6(std::net::Ipv6Addr::from(*addr)))
    }
}

/// Build a [`ConnState`] from the handoff entry and routing decision.
///
/// The `is_wan_ingress_direction` is set to `1` because routing handoff
/// entries are only produced by WAN egress processing in the eBPF program
/// (LAN egress has its own direct path).
fn build_conn_state(entry: &RoutingHandoffEntry, decision: &RoutingResult) -> ConnState {
    let mut state = ConnState::zeroed();

    state.is_wan_ingress_direction_raw = 1;
    state.state = 0; // TCP_STATE_ACTIVE
    state.last_seen_ns = entry.last_seen_ns;
    state.meta = RoutingMeta {
        mark: decision.mark,
        outbound: decision.outbound,
        must: if decision.must { 1 } else { 0 },
        dscp: entry.result.dscp,
        has_routing: 1,
    };
    state.mac = entry.result.mac;
    state.pname = entry.result.pname;
    state.pid = entry.result.pid;

    state
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::ebpf::outbound;

    /// Helper: create a zeroed eBPF RoutingResult for test entries.
    fn zero_ebpf_result() -> crate::net::ebpf::RoutingResult {
        crate::net::ebpf::RoutingResult::zeroed()
    }

    #[test]
    fn test_build_routing_params_ipv4() {
        let key = TuplesKey::from_ipv4(
            &[192, 168, 1, 100],
            &[8, 8, 8, 8],
            12345,
            443,
            6, // TCP
        );

        let mut result = zero_ebpf_result();
        result.dscp = 10;
        let entry = RoutingHandoffEntry {
            last_seen_ns: 1_000_000,
            result,
            _pad: [0u8; 4],
        };

        let params = build_routing_params(&key, &entry);

        assert_eq!(
            params.src_ip,
            Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100)))
        );
        assert_eq!(
            params.dst_ip,
            Some(IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)))
        );
        assert_eq!(params.src_port, Some(12345));
        assert_eq!(params.dst_port, Some(443));
        assert_eq!(params.l4proto, Some(6));
        assert_eq!(params.dscp, Some(10));
        assert!(params.process_name.is_none());
    }

    #[test]
    fn test_build_routing_params_with_pname() {
        let key = TuplesKey::from_ipv4(
            &[10, 0, 0, 1],
            &[1, 1, 1, 1],
            54321,
            80,
            6,
        );

        let mut pname = [0u8; 16];
        pname[..8].copy_from_slice(b"firefox\x00");

        let mut result = zero_ebpf_result();
        result.pname = pname;
        let entry = RoutingHandoffEntry {
            last_seen_ns: 2_000_000,
            result,
            _pad: [0u8; 4],
        };

        let params = build_routing_params(&key, &entry);

        assert_eq!(params.process_name, Some("firefox".to_string()));
    }

    #[test]
    fn test_build_conn_state_direct() {
        let mut ebpf_result = zero_ebpf_result();
        ebpf_result.mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        ebpf_result.dscp = 0;

        let entry = RoutingHandoffEntry {
            last_seen_ns: 5_000_000,
            result: ebpf_result,
            _pad: [0u8; 4],
        };

        // This is the userspace RoutingResult (from routing::RoutingResult)
        // that build_conn_state expects.
        let decision = crate::routing::matcher::RoutingResult {
            outbound: outbound::DIRECT,
            mark: 0,
            must: false,
        };

        let state = build_conn_state(&entry, &decision);

        assert_eq!(state.is_wan_ingress_direction_raw, 1);
        assert_eq!(state.meta.outbound, outbound::DIRECT);
        assert_eq!(state.meta.mark, 0);
        assert_eq!(state.meta.has_routing, 1);
        assert_eq!(state.mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(state.last_seen_ns, 5_000_000);
    }
}
