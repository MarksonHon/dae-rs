//! Domain routing bitmap tracker.
//!
//! Manages the `domain_routing_map` eBPF map which maps IP addresses
//! to bitmaps indicating which domain routing rules match.
//!
//! When a DNS response resolves a domain to an IP, this module:
//! 1. Computes which domain set rules match the domain
//! 2. Writes the IP→bitmap mapping to the eBPF map
//! 3. On DNS TTL expiry, removes the mapping
//!
//! This mirrors dae's `control/domain_routing_tracker.go`.

use crate::net::ebpf::EbpfManager;
use crate::routing::matcher::build_domain_routing_bitmap;
use anyhow::Result;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// Shared handle to the current domain routing tracker.
///
/// The outer `Mutex` guards replacement of the tracker during hot reload; the
/// inner `Arc<Mutex<_>>` guards the tracker's own state, which is touched from
/// both the DNS listener task (on every accepted resolution) and the janitor
/// (for TTL expiry). Lock order convention:
///
/// 1. Lock the outer handle briefly to clone the inner `Arc`, then release it.
/// 2. Lock `EbpfManager`, then lock the inner tracker.
///
/// The outer handle must NEVER be held while holding the ebpf lock, otherwise
/// hot-reload (which holds the outer handle) and DNS/janitor paths could
/// deadlock (AB-BA).
pub type DomainRoutingHandle =
    Arc<std::sync::Mutex<Option<Arc<std::sync::Mutex<DomainRoutingTracker>>>>>;

/// A single domain→IP mapping with expiry.
#[allow(dead_code)]
struct DomainIpMapping {
    ip: IpAddr,
    domain: String,
    expires_at: Instant,
}

/// Tracks domain→IP mappings and syncs to the eBPF `domain_routing_map`.
///
/// # Usage
///
/// 1. Call `add_dns_result(domain, ip, ttl_secs)` when a DNS response arrives.
/// 2. The tracker computes the routing bitmap and writes it to the eBPF map.
/// 3. On TTL expiry or `remove_dns_result()`, the entry is deleted from the map.
pub struct DomainRoutingTracker {
    /// Active domain→IP mappings (keyed by IP string for fast lookup).
    entries: HashMap<String, DomainIpMapping>,
    /// Reference to domain sets from compiled routing rules.
    domain_sets: Arc<Vec<Vec<String>>>,
    /// Current routing epoch slot (0 or 1) that domain entries are written to.
    epoch_slot: u32,
}

impl DomainRoutingTracker {
    pub fn new(domain_sets: Arc<Vec<Vec<String>>>, epoch_slot: u32) -> Self {
        Self {
            entries: HashMap::new(),
            domain_sets,
            epoch_slot,
        }
    }

    /// Update the epoch slot for subsequent writes.
    pub fn set_epoch_slot(&mut self, slot: u32) {
        self.epoch_slot = slot;
    }

    /// Get the current epoch slot.
    pub fn epoch_slot(&self) -> u32 {
        self.epoch_slot
    }

    /// Add a DNS resolution result.
    ///
    /// * `domain` — The resolved domain name (e.g., `www.baidu.com`).
    /// * `ip` — The resolved IP address.
    /// * `ttl_secs` — DNS TTL in seconds (entry will be removed after this).
    /// * `ebpf` — Mutable reference to the EbpfManager for map writes.
    pub fn add_dns_result(
        &mut self,
        domain: &str,
        ip: IpAddr,
        ttl_secs: u32,
        ebpf: &mut EbpfManager,
    ) -> Result<()> {
        let key = ip.to_string();
        let domain_lower = domain.to_lowercase();

        debug!(
            "DomainRouting: processing {} -> {} (ttl={}s)",
            domain, ip, ttl_secs
        );

        // Compute the routing bitmap for this domain
        let bitmap = build_domain_routing_bitmap(&domain_lower, &self.domain_sets);

        // Check if any bits are set (if not, no rule matches — skip writing)
        if bitmap.iter().all(|&w| w == 0) {
            debug!(
                "DomainRouting: no rules match {} -> {}, skipping",
                domain, ip
            );
            return Ok(());
        }

        let ttl = Duration::from_secs(ttl_secs as u64);
        let expires_at = Instant::now() + ttl;

        self.entries.insert(
            key.clone(),
            DomainIpMapping {
                ip,
                domain: domain_lower,
                expires_at,
            },
        );

        // Write to eBPF domain_routing_map (with epoch slot prefix)
        let ip_bytes = ip_to_16_bytes(ip);
        ebpf.write_domain_routing_map(&[(ip_bytes, bitmap.clone())], self.epoch_slot)?;

        info!(
            "DomainRouting: {} -> {} (ttl={}s, bitmap={:08x?})",
            domain, ip, ttl_secs, bitmap
        );

        Ok(())
    }

    /// Remove a DNS result and delete from the eBPF map.
    pub fn remove_dns_result(&mut self, ip: &IpAddr, ebpf: &mut EbpfManager) -> Result<()> {
        let key = ip.to_string();
        if self.entries.remove(&key).is_some() {
            let ip_bytes = ip_to_16_bytes(*ip);
            ebpf.delete_domain_routing_entries(&[ip_bytes], self.epoch_slot)?;
            debug!("DomainRouting: removed {}", ip);
        }
        Ok(())
    }

    /// Clean up expired entries.
    pub fn cleanup_expired(&mut self, ebpf: &mut EbpfManager) -> Result<usize> {
        let now = Instant::now();
        let expired: Vec<IpAddr> = self
            .entries
            .iter()
            .filter(|(_, e)| e.expires_at <= now)
            .map(|(_, e)| e.ip)
            .collect();

        for ip in &expired {
            let ip_bytes = ip_to_16_bytes(*ip);
            ebpf.delete_domain_routing_entries(&[ip_bytes], self.epoch_slot)?;
            self.entries.remove(&ip.to_string());
        }

        if !expired.is_empty() {
            debug!("DomainRouting: cleaned {} expired entries", expired.len());
        }

        Ok(expired.len())
    }

    /// Number of tracked entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Convert an IpAddr to a 16-byte array (IPv4-mapped IPv6 for IPv4).
fn ip_to_16_bytes(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => {
            let mut bytes = [0u8; 16];
            bytes[10] = 0xff;
            bytes[11] = 0xff;
            bytes[12..16].copy_from_slice(&v4.octets());
            bytes
        }
        IpAddr::V6(v6) => v6.octets(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_domain_routing_bitmap() {
        let domain_sets = vec![
            vec!["baidu.com".to_string()],
            vec!["google.com".to_string()],
            vec!["suffix:example.com".to_string()],
        ];

        let bitmap = build_domain_routing_bitmap("www.baidu.com", &domain_sets);
        assert!(bitmap[0] & 0x01 != 0, "bit 0 should be set for baidu.com");
        assert!(bitmap[0] & 0x02 == 0, "bit 1 should not be set");
        assert!(bitmap[0] & 0x04 == 0, "bit 2 should not be set");

        let bitmap = build_domain_routing_bitmap("sub.example.com", &domain_sets);
        assert!(
            bitmap[0] & 0x04 != 0,
            "bit 2 should be set for sub.example.com"
        );

        let bitmap = build_domain_routing_bitmap("unknown.com", &domain_sets);
        assert!(
            bitmap.iter().all(|&w| w == 0),
            "no bits should be set for unknown.com"
        );
    }

    #[test]
    fn test_ip_to_16_bytes() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let bytes = ip_to_16_bytes(ip);
        assert_eq!(bytes[15], 4);
        assert_eq!(bytes[14], 3);
        assert_eq!(bytes[13], 2);
        assert_eq!(bytes[12], 1);
        assert_eq!(bytes[10], 0xff);
        assert_eq!(bytes[11], 0xff);

        let ip: IpAddr = "::1".parse().unwrap();
        let bytes = ip_to_16_bytes(ip);
        assert_eq!(bytes[15], 1);
    }
}
