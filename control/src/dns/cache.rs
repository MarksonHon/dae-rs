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
    /// Whether this entry is stale (being refreshed)
    stale: bool,
}

/// DNS response cache
pub struct DnsCache {
    /// Cache configuration
    config: DnsCacheConfig,
    /// Cache entries: key = hash(qname, qtype, qclass)
    entries: HashMap<u64, CachedResponse>,
}

impl DnsCache {
    pub fn new(config: &DnsCacheConfig) -> Self {
        Self {
            config: config.clone(),
            entries: HashMap::with_capacity(config.max_size as usize),
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

    /// Look up a cached response
    pub fn lookup(&self, key: u64) -> Option<&[u8]> {
        let entry = self.entries.get(&key)?;
        let now = Instant::now();

        if now < entry.deadline {
            // Fresh entry
            Some(&entry.raw_response)
        } else if self.config.optimistic_cache && entry.stale {
            // Stale entry but optimistic cache enabled
            let stale_deadline =
                entry.deadline + Duration::from_secs(self.config.optimistic_cache_ttl as u64);
            if now < stale_deadline {
                Some(&entry.raw_response)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Insert a response into the cache
    pub fn insert(&mut self, key: u64, response: Vec<u8>, ttl_secs: u32) {
        if !self.config.enabled {
            return;
        }

        // Clamp TTL
        let ttl = ttl_secs.max(self.config.min_ttl).min(self.config.max_ttl);

        // Evict if at capacity
        if self.entries.len() >= self.config.max_size as usize {
            // Simple: remove the oldest entry
            if let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.created_at)
                .map(|(k, _)| *k)
            {
                self.entries.remove(&oldest_key);
            }
        }

        self.entries.insert(
            key,
            CachedResponse {
                raw_response: response,
                created_at: Instant::now(),
                original_ttl: ttl_secs,
                deadline: Instant::now() + Duration::from_secs(ttl as u64),
                stale: false,
            },
        );
    }

    /// Mark an entry as stale (for optimistic cache refresh)
    pub fn mark_stale(&mut self, key: u64) {
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.stale = true;
        }
    }

    /// Remove expired entries
    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| {
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

    /// Clear all cached entries
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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
        }
    }

    #[test]
    fn test_cache_hit_and_miss() {
        let mut cache = DnsCache::new(&default_cache_config());
        let key = DnsCache::cache_key("example.com", 1, 1);

        // Miss
        assert!(cache.lookup(key).is_none());

        // Insert with TTL 60
        cache.insert(key, vec![1, 2, 3, 4], 60);

        // Hit
        assert!(cache.lookup(key).is_some());
        assert_eq!(cache.lookup(key).unwrap(), &[1, 2, 3, 4]);
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
        cache.insert(key, vec![1], 5);
        let entry = cache.entries.get(&key).unwrap();
        let ttl_secs = entry.deadline.duration_since(entry.created_at).as_secs();
        assert!(ttl_secs >= 20 && ttl_secs <= 21);

        // TTL 500 should be clamped to max_ttl=100
        let key2 = DnsCache::cache_key("example.com", 28, 1);
        cache.insert(key2, vec![2], 500);
        let entry2 = cache.entries.get(&key2).unwrap();
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

        // Fill to capacity
        for i in 0..3 {
            let key = DnsCache::cache_key(&format!("host{}.com", i), 1, 1);
            cache.insert(key, vec![i as u8], 60);
        }
        assert_eq!(cache.len(), 3);

        // Insert one more — should evict oldest
        let key_new = DnsCache::cache_key("new.com", 1, 1);
        cache.insert(key_new, vec![99], 60);
        assert_eq!(cache.len(), 3);
        assert!(cache.lookup(key_new).is_some());
    }

    #[test]
    fn test_cleanup_expired() {
        let mut cache = DnsCache::new(&default_cache_config());
        let key = DnsCache::cache_key("example.com", 1, 1);

        // Insert with min TTL (10s) — it will expire quickly in cleanup
        cache.insert(key, vec![1], 10);

        // Force expiry by backdating created_at
        if let Some(entry) = cache.entries.get_mut(&key) {
            entry.created_at = Instant::now() - Duration::from_secs(60);
            entry.deadline = Instant::now() - Duration::from_secs(1);
        }

        cache.cleanup_expired();
        assert!(cache.lookup(key).is_none());
    }

    #[test]
    fn test_disabled_cache() {
        let config = DnsCacheConfig {
            enabled: false,
            ..default_cache_config()
        };
        let mut cache = DnsCache::new(&config);
        let key = DnsCache::cache_key("example.com", 1, 1);

        cache.insert(key, vec![1, 2, 3], 60);
        assert!(cache.lookup(key).is_none());
    }
}
