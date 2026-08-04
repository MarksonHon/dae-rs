use crate::config::DnsCacheConfig;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A cached DNS response
struct CachedResponse {
    /// Raw DNS response bytes (pre-packed for fast return)
    raw_response: Vec<u8>,
    /// When this entry was created
    created_at: Instant,
    /// Original TTL from response (retained for future use)
    #[allow(dead_code)]
    original_ttl: u32,
    /// Effective deadline (after min/max TTL clamping)
    deadline: Instant,
}

/// Result of a cache lookup: fresh entry or an expired (stale) entry that is
/// still servable within the optimistic (RFC 8767) window.
pub enum CacheLookup<'a> {
    /// Valid, unexpired entry.
    Fresh {
        /// Response bytes
        bytes: &'a [u8],
        /// Seconds since insertion (for RFC 1035 §5.2 TTL decrement)
        elapsed_secs: u32,
        /// Seconds remaining until expiry (for background-refresh decisions)
        remaining_ttl: u32,
    },
    /// Expired entry within the serve-stale window. The caller should serve it
    /// with a low TTL and trigger a background refresh.
    Stale {
        /// Response bytes
        bytes: &'a [u8],
    },
}

/// DNS response cache, partitioned per DNS group.
///
/// Each DNS group has its own independent `HashMap`, so the same `(qname, qtype)`
/// may resolve to different cached answers in different groups (e.g. a polluted
/// upstream vs. a trusted one).
pub struct DnsCache {
    /// Cache configuration
    config: DnsCacheConfig,
    /// Cache entries per group: group name → (key = hash(qname, qtype, qclass) → response)
    entries: HashMap<String, HashMap<u64, CachedResponse>>,
}

impl DnsCache {
    pub fn new(config: &DnsCacheConfig) -> Self {
        Self {
            config: config.clone(),
            entries: HashMap::new(),
        }
    }

    /// Compute cache key from DNS query parameters
    pub fn cache_key(qname: &str, qtype: u16, qclass: u16) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        qname.hash(&mut hasher);
        qtype.hash(&mut hasher);
        qclass.hash(&mut hasher);
        hasher.finish()
    }

    /// Look up a cached response for a specific DNS group.
    pub fn lookup(&self, group: &str, key: u64) -> Option<&[u8]> {
        match self.lookup_state(group, key) {
            Some(CacheLookup::Fresh { bytes, .. }) => Some(bytes),
            _ => None,
        }
    }

    /// Look up a cached response for a specific DNS group, returning the
    /// response bytes and the seconds elapsed since insertion.
    ///
    /// The elapsed time is used by the caller to decrement TTLs per
    /// RFC 1035 §5.2 so cached responses report their true remaining lifetime.
    /// Only fresh entries are returned (stale entries are handled via
    /// [`DnsCache::lookup_state`]).
    pub fn lookup_with_age(&self, group: &str, key: u64) -> Option<(&[u8], u32)> {
        match self.lookup_state(group, key) {
            Some(CacheLookup::Fresh {
                bytes,
                elapsed_secs,
                ..
            }) => Some((bytes, elapsed_secs)),
            _ => None,
        }
    }

    /// Look up a cached response, distinguishing fresh vs. serve-stale.
    ///
    /// - Fresh: within the entry's TTL.
    /// - Stale: expired but still inside the optimistic (`optimistic_cache_ttl`)
    ///   window when `optimistic_cache` is enabled.
    /// - None: miss or stale data outside the servable window.
    pub fn lookup_state(&self, group: &str, key: u64) -> Option<CacheLookup<'_>> {
        let entry = self.entries.get(group)?.get(&key)?;
        let now = Instant::now();

        if now < entry.deadline {
            // Fresh entry
            let elapsed = now.duration_since(entry.created_at).as_secs() as u32;
            let remaining_ttl = entry.deadline.duration_since(now).as_secs() as u32;
            Some(CacheLookup::Fresh {
                bytes: &entry.raw_response,
                elapsed_secs: elapsed,
                remaining_ttl,
            })
        } else if self.config.optimistic_cache {
            // Serve-stale (RFC 8767): keep expired entries within the window.
            let stale_deadline = entry.deadline
                + Duration::from_secs(self.config.optimistic_cache_ttl as u64);
            if now < stale_deadline {
                Some(CacheLookup::Stale {
                    bytes: &entry.raw_response,
                })
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Insert a response into the cache for a specific DNS group.
    pub fn insert(&mut self, group: &str, key: u64, response: Vec<u8>, ttl_secs: u32) {
        if !self.config.enabled {
            return;
        }

        // Clamp TTL
        let ttl = ttl_secs.max(self.config.min_ttl).min(self.config.max_ttl);

        let group_entries = self.entries.entry(group.to_string()).or_default();

        // Evict if at capacity
        if group_entries.len() >= self.config.max_size as usize {
            // Simple: remove the oldest entry
            if let Some(oldest_key) = group_entries
                .iter()
                .min_by_key(|(_, e)| e.created_at)
                .map(|(k, _)| *k)
            {
                group_entries.remove(&oldest_key);
            }
        }

        group_entries.insert(
            key,
            CachedResponse {
                raw_response: response,
                created_at: Instant::now(),
                original_ttl: ttl_secs,
                deadline: Instant::now() + Duration::from_secs(ttl as u64),
            },
        );
    }

    /// Remove expired entries across all groups.
    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();
        for group_entries in self.entries.values_mut() {
            group_entries.retain(|_, entry| {
                if self.config.optimistic_cache {
                    // Keep stale entries within the optimistic window
                    let stale_deadline =
                        entry.deadline + Duration::from_secs(self.config.optimistic_cache_ttl as u64);
                    now < stale_deadline
                } else {
                    now < entry.deadline
                }
            });
        }
        // Drop groups that became empty.
        self.entries.retain(|_, group_entries| !group_entries.is_empty());
    }

    /// Clear all cached entries
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.values().map(|m| m.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.values().all(|m| m.is_empty())
    }

    /// Number of groups that currently have cached entries.
    #[cfg(test)]
    pub fn group_count(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_cache_config() -> DnsCacheConfig {
        DnsCacheConfig {
            enabled: true,
            max_size: 10,
            max_ttl: 3600,
            min_ttl: 10,
            optimistic_cache: false,
            optimistic_cache_ttl: 60,
            background_refresh: false,
            refresh_threshold_percent: 20,
            serve_stale_ttl: 30,
        }
    }

    #[test]
    fn test_cache_hit_and_miss() {
        let mut cache = DnsCache::new(&default_cache_config());
        let key = DnsCache::cache_key("example.com", 1, 1);

        // Miss
        assert!(cache.lookup("g1", key).is_none());

        // Insert with TTL 60
        cache.insert("g1", key, vec![1, 2, 3, 4], 60);

        // Hit
        assert!(cache.lookup("g1", key).is_some());
        assert_eq!(cache.lookup("g1", key).unwrap(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_cache_partitioned_by_group() {
        let mut cache = DnsCache::new(&default_cache_config());
        let key = DnsCache::cache_key("example.com", 1, 1);

        // Same qname cached differently in two groups.
        cache.insert("china_dns", key, vec![1], 60);
        cache.insert("trusted_dns", key, vec![2], 60);

        assert_eq!(cache.lookup("china_dns", key), Some(&[1][..]));
        assert_eq!(cache.lookup("trusted_dns", key), Some(&[2][..]));
        // Unknown group → miss
        assert!(cache.lookup("other", key).is_none());
        assert_eq!(cache.group_count(), 2);
    }

    #[test]
    fn test_ttl_clamping() {
        let config = DnsCacheConfig {
            max_ttl: 100,
            min_ttl: 20,
            ..default_cache_config()
        };
        let mut cache = DnsCache::new(&config);
        let key = DnsCache::cache_key("example.com", 1, 1);

        // TTL 5 should be clamped to min_ttl=20
        cache.insert("g1", key, vec![1], 5);
        let entry = cache.entries.get("g1").unwrap().get(&key).unwrap();
        let ttl_secs = entry.deadline.duration_since(entry.created_at).as_secs();
        assert!(ttl_secs >= 20 && ttl_secs <= 21);

        // TTL 500 should be clamped to max_ttl=100
        let key2 = DnsCache::cache_key("example.com", 28, 1);
        cache.insert("g1", key2, vec![2], 500);
        let entry2 = cache.entries.get("g1").unwrap().get(&key2).unwrap();
        let ttl2 = entry2.deadline.duration_since(entry2.created_at).as_secs();
        assert!(ttl2 >= 100 && ttl2 <= 101);
    }

    #[test]
    fn test_eviction_at_capacity() {
        let config = DnsCacheConfig {
            max_size: 3,
            ..default_cache_config()
        };
        let mut cache = DnsCache::new(&config);

        // Fill to capacity (per-group)
        for i in 0..3 {
            let key = DnsCache::cache_key(&format!("host{}.com", i), 1, 1);
            cache.insert("g1", key, vec![i as u8], 60);
        }
        assert_eq!(cache.len(), 3);

        // Insert one more — should evict oldest
        let key_new = DnsCache::cache_key("new.com", 1, 1);
        cache.insert("g1", key_new, vec![99], 60);
        assert_eq!(cache.len(), 3);
        assert!(cache.lookup("g1", key_new).is_some());
    }

    #[test]
    fn test_cleanup_expired() {
        let mut cache = DnsCache::new(&default_cache_config());
        let key = DnsCache::cache_key("example.com", 1, 1);

        // Insert with min TTL (10s) — it will expire quickly in cleanup
        cache.insert("g1", key, vec![1], 10);

        // Force expiry by backdating created_at
        if let Some(entry) = cache.entries.get_mut("g1").unwrap().get_mut(&key) {
            entry.created_at = Instant::now() - Duration::from_secs(60);
            entry.deadline = Instant::now() - Duration::from_secs(1);
        }

        cache.cleanup_expired();
        assert!(cache.lookup("g1", key).is_none());
        // Empty group should be dropped
        assert_eq!(cache.group_count(), 0);
    }

    #[test]
    fn test_disabled_cache() {
        let config = DnsCacheConfig {
            enabled: false,
            ..default_cache_config()
        };
        let mut cache = DnsCache::new(&config);
        let key = DnsCache::cache_key("example.com", 1, 1);

        cache.insert("g1", key, vec![1, 2, 3], 60);
        assert!(cache.lookup("g1", key).is_none());
    }

    #[test]
    fn test_lookup_state_serve_stale() {
        let config = DnsCacheConfig {
            optimistic_cache: true,
            optimistic_cache_ttl: 3600,
            ..default_cache_config()
        };
        let mut cache = DnsCache::new(&config);
        let key = DnsCache::cache_key("example.com", 1, 1);

        cache.insert("g1", key, vec![1, 2, 3], 60);
        // Fresh within TTL
        assert!(matches!(
            cache.lookup_state("g1", key),
            Some(CacheLookup::Fresh { .. })
        ));

        // Force expiry: backdate deadline into the past but inside the
        // optimistic window (expired 10s ago, window 3600s).
        if let Some(entry) = cache
            .entries
            .get_mut("g1")
            .and_then(|m| m.get_mut(&key))
        {
            entry.deadline = Instant::now() - Duration::from_secs(10);
        }
        assert!(matches!(
            cache.lookup_state("g1", key),
            Some(CacheLookup::Stale { .. })
        ));

        // Beyond the serve-stale window → miss
        if let Some(entry) = cache
            .entries
            .get_mut("g1")
            .and_then(|m| m.get_mut(&key))
        {
            entry.deadline = Instant::now() - Duration::from_secs(3601);
        }
        assert!(cache.lookup_state("g1", key).is_none());
        assert!(cache.lookup("g1", key).is_none());
    }

    #[test]
    fn test_lookup_state_serve_stale_disabled() {
        // optimistic_cache = false → expired entries are a miss.
        let mut cache = DnsCache::new(&default_cache_config());
        let key = DnsCache::cache_key("example.com", 1, 1);
        cache.insert("g1", key, vec![1], 60);
        if let Some(entry) = cache
            .entries
            .get_mut("g1")
            .and_then(|m| m.get_mut(&key))
        {
            entry.deadline = Instant::now() - Duration::from_secs(1);
        }
        assert!(cache.lookup_state("g1", key).is_none());
    }
}
