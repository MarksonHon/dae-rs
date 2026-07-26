use std::collections::HashMap;
use std::time::{Duration, Instant};
use crate::config::DnsCacheConfig;

/// A cached DNS response
struct CachedResponse {
    /// Raw DNS response bytes (pre-packed for fast return)
    raw_response: Vec<u8>,
    /// When this entry was created
    created_at: Instant,
    /// Original TTL from response
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
            let stale_deadline = entry.deadline
                + Duration::from_secs(self.config.optimistic_cache_ttl as u64);
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
        let ttl = ttl_secs
            .max(self.config.min_ttl)
            .min(self.config.max_ttl);

        // Evict if at capacity
        if self.entries.len() >= self.config.max_size as usize {
            // Simple: remove the oldest entry
            if let Some(oldest_key) = self.entries.iter()
                .min_by_key(|(_, e)| e.created_at)
                .map(|(k, _)| *k)
            {
                self.entries.remove(&oldest_key);
            }
        }

        self.entries.insert(key, CachedResponse {
            raw_response: response,
            created_at: Instant::now(),
            original_ttl: ttl_secs,
            deadline: Instant::now() + Duration::from_secs(ttl as u64),
            stale: false,
        });
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
                let stale_deadline = entry.deadline
                    + Duration::from_secs(self.config.optimistic_cache_ttl as u64);
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
}
