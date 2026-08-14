//! Network interface event monitor with lazy-bind/rebind support.
//!
//! Mirrors dae's `component/interface_manager.go` — polls `/sys/class/net/`
//! for interface changes and automatically binds/unbinds eBPF TC programs
//! as interfaces appear/disappear.
//!
//! Uses polling (rather than netlink) for simplicity and portability.
//! The interval is 2 seconds — fine for lazy-bind/rebind scenarios.
//!
//! # Patterns
//!
//! Each registered pattern may be:
//!   - `auto` — resolve the interface(s) carrying the IPv4/IPv6 default
//!     route from the main routing table, and keep tracking route changes
//!     (e.g. PPPoE dial-up, Wi-Fi handover) while running.
//!   - `regex(<regex>)` — a Rust regular expression, e.g. `regex('^enp[0-9]+$')`.
//!   - anything else — a glob pattern, e.g. `eth*`, `wan?`, `ppp*`
//!     (`*` matches any run, `?` matches a single char).

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// Callback invoked when a matching interface appears.
pub type BindCallback = Arc<dyn Fn(&str) -> Result<()> + Send + Sync>;
/// Callback invoked when a matching interface disappears.
pub type UnbindCallback = Arc<dyn Fn(&str) -> Result<()> + Send + Sync>;

/// How an interface pattern is matched against `/sys/class/net/` names.
enum InterfaceMatcher {
    /// Track the interface(s) that currently carry the default route.
    Auto,
    /// Glob pattern (`*` / `?`).
    Glob(String),
    /// Compiled regular expression.
    Regex(regex::Regex),
}

impl InterfaceMatcher {
    /// Parse a user-provided pattern string.
    fn parse(pattern: &str) -> Result<InterfaceMatcher> {
        if pattern == "auto" {
            return Ok(InterfaceMatcher::Auto);
        }
        if let Some(inner) = pattern.strip_prefix("regex(") {
            let inner = inner
                .strip_suffix(')')
                .context("malformed regex pattern: missing closing ')'")?;
            let inner = strip_quotes(inner.trim());
            let re = regex::Regex::new(inner)
                .with_context(|| format!("invalid interface regex pattern: '{}'", inner))?;
            return Ok(InterfaceMatcher::Regex(re));
        }
        Ok(InterfaceMatcher::Glob(pattern.to_string()))
    }

    fn is_auto(&self) -> bool {
        matches!(self, InterfaceMatcher::Auto)
    }

    /// Whether a concrete interface name matches (glob/regex only; `Auto`
    /// never matches directly — it is resolved via the routing table).
    fn matches(&self, name: &str) -> bool {
        match self {
            InterfaceMatcher::Auto => false,
            InterfaceMatcher::Glob(p) => glob_match(p, name),
            InterfaceMatcher::Regex(re) => re.is_match(name),
        }
    }
}

/// A registered interface binding pattern with its callbacks.
struct InterfaceBinding {
    matcher: InterfaceMatcher,
    on_bind: BindCallback,
    on_unbind: Option<UnbindCallback>,
    /// Interfaces currently bound through `auto` (default-route) resolution.
    auto_bound: HashSet<String>,
}

/// Network interface event monitor.
///
/// Periodically scans `/sys/class/net/` to detect interface changes
/// and invokes registered callbacks. Supports glob, regex and `auto`
/// (default-route) pattern matching.
pub struct InterfaceManager {
    bindings: Arc<Mutex<Vec<InterfaceBinding>>>,
    /// Tracked interfaces (name → visible)
    tracked: Arc<Mutex<HashSet<String>>>,
    running: Arc<AtomicBool>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

/// Resolve the interface(s) that currently carry the IPv4/IPv6 default route.
///
/// Reads the main routing table from `/proc/net/route` (IPv4) and
/// `/proc/net/ipv6_route` (IPv6), then returns the union of output
/// interface names (excluding `lo`, `dae0` and `dae0peer`).
pub fn default_route_ifaces() -> Vec<String> {
    let mut set = HashSet::new();

    if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 8 {
                let (iface, dest, mask) = (fields[0], fields[1], fields[7]);
                if dest == "00000000" && mask == "00000000" {
                    set.insert(iface.to_string());
                }
            }
        }
    }

    if let Ok(content) = std::fs::read_to_string("/proc/net/ipv6_route") {
        for line in content.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 10 {
                let (dest, plen, iface) = (fields[0], fields[1], fields[9]);
                if dest.chars().all(|c| c == '0') && plen == "00" {
                    set.insert(iface.to_string());
                }
            }
        }
    }

    // Never bind dae-rs's own virtual links or loopback.
    set.remove("lo");
    set.remove("dae0");
    set.remove("dae0peer");

    let mut v: Vec<String> = set.into_iter().collect();
    v.sort();
    v
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
    /// * `pattern` — `auto`, a regex wrapped as `regex(...)`, or a glob
    ///   (e.g., `eth*`, `wan*`, `ppp*`).
    /// * `on_bind` — Called when a matching interface appears.
    /// * `on_unbind` — Called when a matching interface is deleted.
    pub async fn register(
        &self,
        pattern: &str,
        on_bind: BindCallback,
        on_unbind: Option<UnbindCallback>,
    ) -> Result<()> {
        let matcher = InterfaceMatcher::parse(pattern)?;

        // Resolve the initial set of interfaces to bind (before the binding
        // is pushed, so `auto_bound` is consistent with the first scan).
        let mut pending_binds: Vec<(String, BindCallback)> = Vec::new();
        let mut auto_bound = HashSet::new();
        {
            let mut tracked = self.tracked.lock().await;
            match &matcher {
                InterfaceMatcher::Auto => {
                    for name in default_route_ifaces() {
                        auto_bound.insert(name.clone());
                        if !tracked.contains(&name) {
                            tracked.insert(name.clone());
                        }
                        pending_binds.push((name.clone(), on_bind.clone()));
                    }
                }
                _ => {
                    for name in list_sys_links() {
                        if matcher.matches(&name) {
                            if !tracked.contains(&name) {
                                tracked.insert(name.clone());
                            }
                            pending_binds.push((name.clone(), on_bind.clone()));
                        }
                    }
                }
            }
        }

        // Call callbacks outside the lock
        for (name, cb) in pending_binds {
            info!(
                "InterfaceManager: initial bind {} (pattern={})",
                name, pattern
            );
            if let Err(e) = cb(&name) {
                warn!("InterfaceManager: bind failed {}: {}", name, e);
                // A failed bind must not be left tracked: forget it so the next
                // poll can retry (the interface may not have been ready yet).
                let mut tracked = self.tracked.lock().await;
                tracked.remove(&name);
                auto_bound.remove(&name);
            }
        }

        // Register the binding
        let mut bindings = self.bindings.lock().await;
        bindings.push(InterfaceBinding {
            matcher,
            on_bind,
            on_unbind,
            auto_bound,
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

                // Pending callback invocations, collected while holding the
                // locks and dispatched afterwards (avoid holding locks during
                // eBPF attach/detach).
                let mut pending_binds: Vec<(String, BindCallback)> = Vec::new();
                let mut pending_unbinds: Vec<(String, Option<UnbindCallback>)> = Vec::new();

                {
                    let mut tracked_set = tracked.lock().await;
                    let mut bindings_guard = bindings.lock().await;

                    // Resolve default-route targets once per cycle if any
                    // `auto` binding is registered.
                    let auto_targets: Option<HashSet<String>> =
                        if bindings_guard.iter().any(|b| b.matcher.is_auto()) {
                            Some(default_route_ifaces().into_iter().collect())
                        } else {
                            None
                        };

                    // (a) Detect newly appeared interfaces → glob/regex bindings
                    for name in &current_links {
                        if tracked_set.contains(name) {
                            continue;
                        }
                        let mut matched = false;
                        for binding in bindings_guard.iter() {
                            if !binding.matcher.is_auto() && binding.matcher.matches(name) {
                                matched = true;
                                pending_binds.push((name.clone(), binding.on_bind.clone()));
                            }
                        }
                        if matched {
                            tracked_set.insert(name.clone());
                        }
                    }

                    // (b) Auto re-resolution: bind ifaces that newly carry the
                    // default route, unbind ifaces that no longer do (covers
                    // route handover where both ifaces still exist).
                    if let Some(targets) = &auto_targets {
                        for binding in bindings_guard.iter_mut() {
                            if !binding.matcher.is_auto() {
                                continue;
                            }
                            for name in targets {
                                if !binding.auto_bound.contains(name) {
                                    binding.auto_bound.insert(name.clone());
                                    tracked_set.insert(name.clone());
                                    pending_binds.push((name.clone(), binding.on_bind.clone()));
                                }
                            }
                            let removed: Vec<String> = binding
                                .auto_bound
                                .iter()
                                .filter(|n| !targets.contains(*n))
                                .cloned()
                                .collect();
                            for name in removed {
                                binding.auto_bound.remove(&name);
                                pending_unbinds.push((name.clone(), binding.on_unbind.clone()));
                            }
                        }
                    }

                    // (c) Detect removed interfaces (gone from /sys/class/net).
                    // `auto` bindings are already handled in (b) since a gone
                    // iface can no longer be a default route target.
                    let tracked_snapshot: Vec<String> = tracked_set.iter().cloned().collect();
                    for name in &tracked_snapshot {
                        if current_links.contains(name) {
                            continue;
                        }
                        tracked_set.remove(name);
                        for binding in bindings_guard.iter() {
                            if binding.matcher.is_auto() {
                                continue;
                            }
                            if binding.matcher.matches(name) {
                                pending_unbinds.push((name.clone(), binding.on_unbind.clone()));
                            }
                        }
                    }
                }

                // Dispatch callbacks outside the locks
                for (name, cb) in pending_binds {
                    info!("InterfaceManager: bind {}", name);
                    if let Err(e) = cb(&name) {
                        warn!("InterfaceManager: bind failed {}: {}", name, e);
                        // Forget the failed bind so the next scan retries it
                        // (the interface may not have been ready yet).
                        {
                            let mut tracked_set = tracked.lock().await;
                            tracked_set.remove(&name);
                        }
                        {
                            let mut bindings_guard = bindings.lock().await;
                            for binding in bindings_guard.iter_mut() {
                                binding.auto_bound.remove(&name);
                            }
                        }
                    }
                }
                for (name, cb) in pending_unbinds {
                    info!("InterfaceManager: unbind {}", name);
                    if let Some(cb) = cb {
                        if let Err(e) = cb(&name) {
                            warn!("InterfaceManager: unbind failed {}: {}", name, e);
                        }
                    }
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

/// Strip a matching pair of surrounding single/double quotes.
fn strip_quotes(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 {
        let (first, last) = (bytes[0], bytes[bytes.len() - 1]);
        if (first == b'\'' && last == b'\'') || (first == b'"' && last == b'"') {
            return &s[1..s.len() - 1];
        }
    }
    s
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

    #[test]
    fn test_matcher_auto() {
        assert!(InterfaceMatcher::parse("auto").unwrap().is_auto());
        assert!(!InterfaceMatcher::parse("eth*").unwrap().is_auto());
    }

    #[test]
    fn test_matcher_glob() {
        let m = InterfaceMatcher::parse("eth*").unwrap();
        assert!(m.matches("eth0"));
        assert!(m.matches("eth"));
        assert!(!m.matches("wlan0"));
    }

    #[test]
    fn test_matcher_regex() {
        let m = InterfaceMatcher::parse("regex('^enp[0-9]+s[0-9]+$')").unwrap();
        assert!(m.matches("enp0s3"));
        assert!(m.matches("enp2s0"));
        assert!(!m.matches("wlan0"));
        assert!(!m.matches("enp00"));

        let m = InterfaceMatcher::parse("regex(^ppp\\d+$)").unwrap();
        assert!(m.matches("ppp0"));
        assert!(!m.matches("pppx"));
    }

    #[test]
    fn test_matcher_regex_invalid() {
        assert!(InterfaceMatcher::parse("regex([)").is_err());
        assert!(InterfaceMatcher::parse("regex('')").is_ok());
    }

    #[test]
    fn test_strip_quotes() {
        assert_eq!(strip_quotes("'^eth[0-9]+$'"), "^eth[0-9]+$");
        assert_eq!(strip_quotes("\"ppp.*\""), "ppp.*");
        assert_eq!(strip_quotes("eth*"), "eth*");
        assert_eq!(strip_quotes(""), "");
        assert_eq!(strip_quotes("'"), "'");
    }
}
