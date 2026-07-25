//! Network interface event monitor with lazy-bind/rebind support.
//!
//! Mirrors dae's `component/interface_manager.go` — polls `/sys/class/net/`
//! for interface changes and automatically binds/unbinds eBPF TC programs
//! as interfaces appear/disappear.
//!
//! Uses polling (rather than netlink) for simplicity and portability.
//! The interval is 2 seconds — fine for lazy-bind/rebind scenarios.

use anyhow::Result;
use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// Callback invoked when a matching interface appears.
pub type BindCallback = Arc<dyn Fn(&str) -> Result<()> + Send + Sync>;
/// Callback invoked when a matching interface disappears.
pub type UnbindCallback = Arc<dyn Fn(&str) -> Result<()> + Send + Sync>;

/// A registered interface binding pattern with its callbacks.
struct InterfaceBinding {
    pattern: String,
    on_bind: BindCallback,
    on_unbind: Option<UnbindCallback>,
}

/// Network interface event monitor.
///
/// Periodically scans `/sys/class/net/` to detect interface changes
/// and invokes registered callbacks. Supports glob pattern matching.
pub struct InterfaceManager {
    bindings: Arc<Mutex<Vec<InterfaceBinding>>>,
    /// Tracked interfaces (name → visible)
    tracked: Arc<Mutex<HashSet<String>>>,
    running: Arc<AtomicBool>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl InterfaceManager {
    pub fn new() -> Self {
        Self {
            bindings: Arc::new(Mutex::new(Vec::new())),
            tracked: Arc::new(Mutex::new(HashSet::new())),
            running: Arc::new(AtomicBool::new(false)),
            handle: None,
        }
    }

    /// Register a binding pattern.
    ///
    /// * `pattern` — Glob pattern (e.g., `eth*`, `wan*`, `ppp*`).
    /// * `on_bind` — Called when a matching interface appears.
    /// * `on_unbind` — Called when a matching interface is deleted.
    pub async fn register(
        &self,
        pattern: &str,
        on_bind: BindCallback,
        on_unbind: Option<UnbindCallback>,
    ) -> Result<()> {
        // Scan existing interfaces first (before moving on_bind into the binding)
        let links = list_sys_links();
        {
            let mut tracked = self.tracked.lock().await;
            for name in &links {
                if glob_match(pattern, name) {
                    tracked.insert(name.clone());
                    info!(
                        "InterfaceManager: initial bind {} (pattern={})",
                        name, pattern
                    );
                    if let Err(e) = on_bind(name) {
                        warn!("InterfaceManager: bind failed {}: {}", name, e);
                    }
                }
            }
        }

        // Register the binding
        let mut bindings = self.bindings.lock().await;
        bindings.push(InterfaceBinding {
            pattern: pattern.to_string(),
            on_bind,
            on_unbind,
        });

        Ok(())
    }

    /// Start the background polling task.
    pub async fn start(&mut self) -> Result<()> {
        if self.running.swap(true, Ordering::Relaxed) {
            return Ok(());
        }

        let bindings = self.bindings.clone();
        let tracked = self.tracked.clone();
        let running = self.running.clone();

        self.handle = Some(tokio::spawn(async move {
            info!("InterfaceManager: started (poll interval: 2s)");

            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;

                if !running.load(Ordering::Relaxed) {
                    break;
                }

                let current_links = list_sys_links();
                let mut tracked_set = tracked.lock().await;

                // Detect new interfaces
                for name in &current_links {
                    if !tracked_set.contains(name) {
                        let b = bindings.lock().await;
                        for binding in b.iter() {
                            if glob_match(&binding.pattern, name) {
                                info!(
                                    "InterfaceManager: new interface {} (pattern={})",
                                    name, binding.pattern
                                );
                                tracked_set.insert(name.clone());
                                if let Err(e) = (binding.on_bind)(name) {
                                    warn!("InterfaceManager: bind failed {}: {}", name, e);
                                }
                            }
                        }
                    }
                }

                // Detect removed interfaces
                let tracked_snapshot: Vec<String> = tracked_set.iter().cloned().collect();
                let removed: Vec<String> = tracked_snapshot
                    .into_iter()
                    .filter(|name| !current_links.contains(name))
                    .collect();

                for name in &removed {
                    let b = bindings.lock().await;
                    for binding in b.iter() {
                        if glob_match(&binding.pattern, name) {
                            info!(
                                "InterfaceManager: interface removed {} (pattern={})",
                                name, binding.pattern
                            );
                            if let Some(ref unbind) = binding.on_unbind {
                                if let Err(e) = unbind(name) {
                                    warn!("InterfaceManager: unbind failed {}: {}", name, e);
                                }
                            }
                        }
                    }
                    tracked_set.remove(name);
                }

                debug!(
                    "InterfaceManager: scan complete ({} interfaces)",
                    current_links.len()
                );
            }

            info!("InterfaceManager: stopped");
        }));

        Ok(())
    }

    /// Stop the monitor.
    pub async fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
        info!("InterfaceManager: stopped");
    }
}

impl Default for InterfaceManager {
    fn default() -> Self {
        Self::new()
    }
}

fn list_sys_links() -> Vec<String> {
    let sys_class_net = Path::new("/sys/class/net");
    let mut links = Vec::new();

    if !sys_class_net.exists() {
        return links;
    }

    if let Ok(entries) = std::fs::read_dir(sys_class_net) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                links.push(name.to_string());
            }
        }
    }

    links.sort();
    links
}

/// Simple glob matching (supports `*` and `?`).
fn glob_match(pattern: &str, name: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let nam: Vec<char> = name.chars().collect();

    fn rec(pat: &[char], nam: &[char]) -> bool {
        match (pat.first(), nam.first()) {
            (None, None) => true,
            (None, _) => false,
            (Some('*'), _) => rec(&pat[1..], nam) || (!nam.is_empty() && rec(pat, &nam[1..])),
            (Some('?'), Some(_)) => rec(&pat[1..], &nam[1..]),
            (Some(p), Some(n)) if p == n => rec(&pat[1..], &nam[1..]),
            _ => false,
        }
    }

    rec(&pat, &nam)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_match() {
        assert!(glob_match("eth*", "eth0"));
        assert!(glob_match("eth*", "eth1"));
        assert!(glob_match("wan*", "wan0"));
        assert!(glob_match("ppp*", "ppp0"));
        assert!(!glob_match("eth*", "wlan0"));
        assert!(glob_match("enp*", "enp0s3"));
        assert!(glob_match("enp?*", "enp0s3"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("eth*", "eth")); // * can match zero chars
        assert!(glob_match("eth?", "eth0"));
        assert!(!glob_match("eth?", "eth01"));
        assert!(!glob_match("wan*", "eth0"));
        assert!(!glob_match("eth*", "wlan0"));
    }
}
