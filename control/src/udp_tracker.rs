//! UDP connection state tracker — userspace shadow of conn_state_map for UDP flows.
//!
//! Mirrors dae's `udpConnStateTracker` which manages UDP connection state
//! lifecycle from userspace. This is needed because:
//!
//! 1. UDP is connectionless — the kernel eBPF program needs userspace help
//!    to determine when a UDP "connection" is truly done.
//! 2. DNS responses create short-lived UDP flows that should be cleaned up
//!    immediately after the response is received.
//! 3. Long-lived UDP flows (QUIC, DTLS) need to be retained until idle timeout.
//!
//! # Flow
//!
//! 1. Userspace (DNS proxy, UDP forwarder) calls `Retain(keys)` to mark UDP
//!    flows as "active" — preventing the janitor from deleting them.
//! 2. After the flow is done, calls `BeginRelease(keys)` / `FinalizeRelease(releases)`
//!    to safely mark them for deletion.
//! 3. The janitor only deletes entries not in the retained set.

use crate::ebpf::TuplesKey;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

/// Minimum time (seconds) to retain a UDP flow after it was last seen.
const MIN_RETAIN_SECS: u64 = 10;
/// Maximum time (seconds) to retain a UDP flow — even if actively retained.
const MAX_RETAIN_SECS: u64 = 300; // 5 minutes

/// A UDP flow tracked by the userspace tracker.
struct TrackedFlow {
    /// When this flow was first retained.
    created: Instant,
    /// When this flow was last reported as active.
    last_active: Instant,
}

/// Userspace shadow tracker for UDP conn_state entries.
///
/// Tracks which UDP flows should be kept alive in the eBPF conn_state_map.
/// Used by `UdpTproxyListener` and the domain routing system to prevent
/// the janitor from deleting UDP entries that are still in use.
pub struct UdpConnStateTracker {
    /// Flows currently retained (keyed by TuplesKey directly — zero-copy).
    retained: HashMap<TuplesKey, TrackedFlow>,
    /// Flows pending release (returned from BeginRelease, awaiting FinalizeRelease).
    pending_release: HashSet<TuplesKey>,
}

impl UdpConnStateTracker {
    pub fn new() -> Self {
        Self {
            retained: HashMap::new(),
            pending_release: HashSet::new(),
        }
    }

    /// Mark one or more UDP flows as active/retained.
    ///
    /// The janitor will not delete these entries from conn_state_map.
    pub fn retain(&mut self, keys: &[TuplesKey]) {
        let now = Instant::now();
        for &key in keys {
            let entry = self.retained.entry(key).or_insert_with(|| TrackedFlow {
                created: now,
                last_active: now,
            });
            entry.last_active = now;
        }
    }

    /// Remove from retention (stop protecting from janitor).
    pub fn forget(&mut self, keys: &[TuplesKey]) {
        for &key in keys {
            self.retained.remove(&key);
        }
    }

    /// Begin the release process for a set of UDP flows.
    ///
    /// Returns the list of entries that are safe to delete from conn_state_map.
    /// The caller MUST call `finalize_release()` after deleting from the map.
    pub fn begin_release(&mut self, keys: &[TuplesKey]) -> Vec<TuplesKey> {
        let mut releases = Vec::new();
        for &key in keys {
            if self.retained.remove(&key).is_some() {
                self.pending_release.insert(key);
                releases.push(key);
            }
        }
        releases
    }

    /// Finalize the release — clean up pending state after the caller
    /// has deleted the entries from conn_state_map.
    pub fn finalize_release(&mut self, releases: &[TuplesKey]) {
        for &key in releases {
            self.pending_release.remove(&key);
        }
    }

    /// Check if a key is currently retained.
    pub fn is_retained(&self, key: &TuplesKey) -> bool {
        self.retained.contains_key(key)
    }

    /// Clean up expired retained entries.
    /// Returns the list of keys that should be deleted from conn_state_map.
    pub fn cleanup_expired(&mut self) -> Vec<TuplesKey> {
        let now = Instant::now();
        let mut expired = Vec::new();

        self.retained.retain(|&key, flow| {
            let age = now.duration_since(flow.created).as_secs();
            let idle = now.duration_since(flow.last_active).as_secs();

            if age > MAX_RETAIN_SECS || idle > MIN_RETAIN_SECS {
                expired.push(key);
                false // remove from retained
            } else {
                true // keep
            }
        });

        expired
    }

    /// Number of currently tracked flows.
    pub fn len(&self) -> usize {
        self.retained.len()
    }

    pub fn is_empty(&self) -> bool {
        self.retained.is_empty()
    }
}

impl Default for UdpConnStateTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::TuplesKey;

    #[test]
    fn test_retain_and_forget() {
        let mut tracker = UdpConnStateTracker::new();
        let key = TuplesKey::from_ipv4(&[8, 8, 8, 8], &[1, 1, 1, 1], 12345, 53, 17);

        tracker.retain(&[key]);
        assert!(tracker.is_retained(&key));
        assert_eq!(tracker.len(), 1);

        tracker.forget(&[key]);
        assert!(!tracker.is_retained(&key));
        assert_eq!(tracker.len(), 0);
    }

    #[test]
    fn test_begin_and_finalize_release() {
        let mut tracker = UdpConnStateTracker::new();
        let key = TuplesKey::from_ipv4(&[8, 8, 8, 8], &[1, 1, 1, 1], 12345, 53, 17);

        tracker.retain(&[key]);
        let releases = tracker.begin_release(&[key]);
        assert_eq!(releases.len(), 1);
        assert_eq!(tracker.len(), 0);

        tracker.finalize_release(&releases);
        // Pending release should be cleared
        assert!(!tracker.is_retained(&key));
    }

    #[test]
    fn test_cleanup_expired() {
        let mut tracker = UdpConnStateTracker::new();
        let key = TuplesKey::from_ipv4(&[8, 8, 8, 8], &[1, 1, 1, 1], 12345, 53, 17);

        tracker.retain(&[key]);
        // Immediately cleanup — should not expire MIN_RETAIN_SECS yet
        let expired = tracker.cleanup_expired();
        assert!(expired.is_empty());
    }
}
