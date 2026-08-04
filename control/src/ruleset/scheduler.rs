//! Ruleset scheduler (design document §7).
//!
//! A single tokio task aggregates the scheduled updates of all rule sets:
//!
//! - `update_on_start: true`: triggers one unconditional update **asynchronously and immediately** after startup (does not block startup);
//! - `time: HH:MM`: triggers daily at that time in the local timezone; if already passed at startup, postponed to the next day;
//! - `period: 3h2m`: based on the last **successful update** (failures do not consume the period), supports `d`/`h`/`m`
//!   combinations, minimum unit is minutes, seconds forbidden.
//!
//! After an update completes, external parties are notified through a `watch` channel
//! ([`UpdateSignal`], with a monotonically increasing success counter) —
//! this layer only emits notification signals; the actual hot-reload wiring
//! (Routing recompilation / eBPF double-buffer switching) is handled by the integration layer / phase 3.
//!
//! **Clock basis**: both the scheduled time and the "last successful update" are recorded using the
//! monotonic clock [`tokio::time::Instant`] (`Local` time is only used to convert `HH:MM` into an instant),
//! keeping consistency with `tokio::time::sleep_until` and allowing the virtual clock to advance under `start_paused` tests.
//!
//! The time-computation helpers ([`next_time_trigger`] / [`next_period_trigger`] /
//! [`parse_period`]) are all **pure functions that do not depend on the current time** (`now` is injected as a parameter), so they can be unit-tested independently.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Local};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant as TokioInstant;
use tracing::{info, warn};

use crate::ruleset::download::{update_rule_set, UpdateOutcome};
use crate::ruleset::store::DataDir;
use crate::ruleset::types::{parse_time, RuleSetConfig, RuleSetUpdate};
use crate::ruleset::RuleSetError;

// ============================================================================
// Public interface
// ============================================================================

/// Proxy resolution interface: `proxy` proxy group name → SOCKS5 address.
///
/// This layer does **not** implement proxy group resolution (e.g. determining the "first proxy
/// group" or selecting nodes within a group); it only defines the interface and accepts an
/// injected implementation. `None` means the proxy group is unknown/unavailable (fall back to
/// direct download with a warning). Phase 3 / the integration layer provides the real implementation.
pub trait ProxyResolver: Send + Sync {
    /// Parse proxy group name → SOCKS5 address; `None` means unavailable (direct).
    fn resolve(&self, proxy: &str) -> Option<SocketAddr>;
}

/// Update-complete notification signal.
///
/// Sent once on every successful update with a monotonically increasing value; receivers use
/// [`watch::Receiver::changed`] to detect that a rule set has been updated and hot reload can be triggered.
pub type UpdateSignal = watch::Sender<u64>;

/// Scheduler handle (the return value of [`RuleSetScheduler::spawn`]).
pub struct SchedulerHandle {
    /// Scheduled task handle (ends after calling [`SchedulerHandle::shutdown`]).
    pub handle: JoinHandle<()>,
    /// Graceful shutdown signal sender.
    pub shutdown: watch::Sender<bool>,
    /// Update-complete notification receiver (value increments on successful update).
    pub notifier: watch::Receiver<u64>,
}

impl SchedulerHandle {
    /// Trigger a graceful shutdown (sends the signal; the Scheduled task exits at its next wake-up).
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    /// Gracefully shut down and wait for the Scheduled task to finish.
    pub async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = self.handle.await;
    }
}

// ============================================================================
// Scheduler
// ============================================================================

/// Update execution function type (injectable for testing; production uses [`default_updater`]).
type UpdateFuture =
    Pin<Box<dyn Future<Output = Result<UpdateOutcome, RuleSetError>> + Send>>;
type UpdateFn =
    Arc<dyn Fn(&RuleSetConfig, &DataDir, Option<SocketAddr>) -> UpdateFuture + Send + Sync>;

/// Parsed scheduling trigger kind.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TriggerKind {
    /// Trigger once daily at `HH:MM` in the local timezone.
    Time { hh: u8, mm: u8 },
    /// Periodic trigger (base = last successful update).
    Period { period: Duration },
}

/// Scheduling state for a single entry.
#[derive(Debug, Clone)]
struct Entry {
    config: RuleSetConfig,
    kind: TriggerKind,
    /// Next trigger instant (monotonic clock).
    next: TokioInstant,
}

/// Ruleset scheduler.
///
/// Creates a background task via [`RuleSetScheduler::spawn`]; it holds:
/// - configuration entries (including scheduling expressions);
/// - a [`DataDir`] (download/storage);
/// - a proxy resolution function (injected);
/// - a notification channel (incremented on successful update).
pub struct RuleSetScheduler {
    dir: Arc<DataDir>,
    proxy_resolver: Arc<dyn ProxyResolver>,
    /// Default proxy group name ("first proxy group", resolved and injected by the caller; used by entries with `proxy: None`).
    default_proxy: Option<String>,
    entries: Vec<Entry>,
    /// name → last successful update instant (monotonic clock; the basis for failures not consuming the period).
    last_success: Arc<tokio::sync::Mutex<HashMap<String, TokioInstant>>>,
    notifier: watch::Sender<u64>,
    shutdown: watch::Receiver<bool>,
}

impl RuleSetScheduler {
    /// Create and `tokio::spawn` the Scheduled task.
    ///
    /// * `entries` — rule set configuration entries (already validated by the validator).
    /// * `dir` — data directory.
    /// * `proxy_resolver` — proxy resolution interface (this layer does not implement proxy group resolution).
    /// * `default_proxy` — the "first proxy group" name (default proxy; determined by the caller / phase 3).
    ///
    /// Returns a [`SchedulerHandle`] (containing a `JoinHandle`, a shutdown sender, and a notification receiver).
    pub fn spawn(
        entries: Vec<RuleSetConfig>,
        dir: Arc<DataDir>,
        proxy_resolver: Arc<dyn ProxyResolver>,
        default_proxy: Option<String>,
    ) -> SchedulerHandle {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (notifier_tx, notifier_rx) = watch::channel(0u64);
        let scheduler = Self {
            dir,
            proxy_resolver,
            default_proxy,
            entries: Vec::new(),
            last_success: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            notifier: notifier_tx,
            shutdown: shutdown_rx,
        };
        let handle = tokio::spawn(scheduler.run(entries, default_updater()));
        SchedulerHandle { handle, shutdown: shutdown_tx, notifier: notifier_rx }
    }

    /// Scheduler main loop.
    async fn run(mut self, configs: Vec<RuleSetConfig>, updater: UpdateFn) {
        // Parse configuration → schedule entries (invalid updates are already caught by the validator; skip defensively here)
        for cfg in configs {
            let kind = match &cfg.update {
                Some(RuleSetUpdate::Time(t)) => match parse_time(t) {
                    Ok((hh, mm)) => TriggerKind::Time { hh, mm },
                    Err(e) => {
                        warn!(name = %cfg.name, error = %e, "skip rule set: invalid time schedule");
                        continue;
                    }
                },
                Some(RuleSetUpdate::Period(p)) => match parse_period(p) {
                    Ok(d) => TriggerKind::Period { period: d },
                    Err(e) => {
                        warn!(name = %cfg.name, error = %e, "skip rule set: invalid period schedule");
                        continue;
                    }
                },
                None => {
                    warn!(name = %cfg.name, "skip rule set: no update schedule");
                    continue;
                }
            };
            self.entries.push(Entry { config: cfg, kind, next: TokioInstant::now() });
        }

        // Initialize the first trigger instant of each entry
        let now_local = Local::now();
        let now_inst = TokioInstant::now();
        for i in 0..self.entries.len() {
            let next = {
                let e = &self.entries[i];
                self.initial_next(e, now_local, now_inst).await
            };
            self.entries[i].next = next;
        }

        // update_on_start: fire immediately and asynchronously (independent task; does not block the scheduler loop / startup)
        let on_start: Vec<Entry> = self
            .entries
            .iter()
            .filter(|e| e.config.update_on_start)
            .cloned()
            .collect();
        for entry in on_start {
            self.spawn_immediate(entry, updater.clone());
        }

        info!("Rule set scheduler started with {} entries", self.entries.len());

        loop {
            // Compute the nearest trigger instant first (immutable borrow), then enter select (`changed()` needs a mutable borrow).
            let next = self.next_instant();
            tokio::select! {
                _ = self.shutdown.changed() => {
                    info!("Rule set scheduler shutting down");
                    break;
                }
                _ = tokio::time::sleep_until(next) => {
                    let now = TokioInstant::now();
                    let due: Vec<usize> = self
                        .entries
                        .iter()
                        .enumerate()
                        .filter(|(_, e)| e.next <= now)
                        .map(|(i, _)| i)
                        .collect();
                    let mut updated = false;
                    for i in due {
                        updated |= self.process_entry(i, now, &updater).await;
                    }
                    if updated {
                        // Increment the notification counter (receivers detect it via changed()).
                        // Take a local value before send: avoids the `watch::Ref` read lock returned by `borrow()`
                        // staying alive across the `send()` (write lock) call, which would re-enter the RwLock and deadlock on the same thread.
                        let next = self.notifier.borrow().wrapping_add(1);
                        let _ = self.notifier.send(next);
                    }
                }
            }
        }
    }

    /// Compute the entry's first trigger instant (period base: in-process last successful update → disk meta → startup time).
    async fn initial_next(
        &self,
        entry: &Entry,
        now_local: DateTime<Local>,
        now_inst: TokioInstant,
    ) -> TokioInstant {
        match &entry.kind {
            TriggerKind::Time { hh, mm } => {
                local_to_instant(now_local, now_inst, next_time_trigger(now_local, *hh, *mm))
            }
            TriggerKind::Period { period } => {
                let base = {
                    let guard = self.last_success.lock().await;
                    guard.get(&entry.config.name).copied()
                };
                match base {
                    Some(t) => next_period_point(t, *period, now_inst),
                    None => {
                        // Persist across restarts: recover the last successful update instant from meta
                        let base_dt = self
                            .dir
                            .read_meta(&entry.config.name)
                            .await
                            .ok()
                            .flatten()
                            .and_then(|m| m.last_updated)
                            .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                            .map(|dt| dt.with_timezone(&Local))
                            .unwrap_or(now_local);
                        next_period_point(
                            local_to_instant(now_local, now_inst, base_dt),
                            *period,
                            now_inst,
                        )
                    }
                }
            }
        }
    }

    /// Nearest trigger instant (sleep a long interval defensively when there are no entries).
    fn next_instant(&self) -> TokioInstant {
        let now = TokioInstant::now();
        let mut nearest: Option<TokioInstant> = None;
        for e in &self.entries {
            if e.next <= now {
                // Already due, return immediately (processed in the next round)
                return now;
            }
            nearest = Some(nearest.map_or(e.next, |n: TokioInstant| n.min(e.next)));
        }
        nearest.unwrap_or_else(|| now + Duration::from_secs(3600))
    }

    /// Process a due entry: run the update, advance the last-success instant, and schedule the next one.
    /// Returns whether the update succeeded (used to decide whether to notify).
    async fn process_entry(&mut self, idx: usize, now: TokioInstant, updater: &UpdateFn) -> bool {
        let (config, kind) = {
            let e = &self.entries[idx];
            (e.config.clone(), e.kind.clone())
        };
        let proxy = resolve_proxy_addr(
            &config,
            self.proxy_resolver.as_ref(),
            self.default_proxy.as_deref(),
        );

        match updater(&config, &self.dir, proxy).await {
            Ok(_outcome) => {
                info!(name = %config.name, "rule set update succeeded");
                // Success: advance the base to the current instant
                self.last_success.lock().await.insert(config.name.clone(), now);
                let next = match &kind {
                    TriggerKind::Time { hh, mm } => {
                        let nl = Local::now();
                        local_to_instant(
                            nl,
                            TokioInstant::now(),
                            next_time_trigger(nl, *hh, *mm),
                        )
                    }
                    TriggerKind::Period { period } => next_period_point(now, *period, now),
                };
                self.entries[idx].next = next;
                true
            }
            Err(err) => {
                warn!(name = %config.name, error = %err, "rule set update failed; period base not consumed");
                // Failure does not consume the period: the period base stays at the last successful update (or now if none),
                // and the next future period point is taken (avoiding spin retries); time rolls over to the next day.
                let next = match &kind {
                    TriggerKind::Time { hh, mm } => {
                        let nl = Local::now();
                        local_to_instant(
                            nl,
                            TokioInstant::now(),
                            next_time_trigger(nl, *hh, *mm),
                        )
                    }
                    TriggerKind::Period { period } => {
                        let base = self
                            .last_success
                            .lock()
                            .await
                            .get(&config.name)
                            .copied()
                            .unwrap_or(now);
                        next_period_point(base, *period, now)
                    }
                };
                self.entries[idx].next = next;
                false
            }
        }
    }

    /// Trigger an update immediately (for update_on_start entries, as an independent task).
    fn spawn_immediate(&self, entry: Entry, updater: UpdateFn) {
        let dir = self.dir.clone();
        let resolver = self.proxy_resolver.clone();
        let default_proxy = self.default_proxy.clone();
        let last_success = self.last_success.clone();
        let notifier = self.notifier.clone();
        let name = entry.config.name.clone();
        tokio::spawn(async move {
            let proxy =
                resolve_proxy_addr(&entry.config, resolver.as_ref(), default_proxy.as_deref());
            match updater(&entry.config, &dir, proxy).await {
                Ok(_) => {
                    info!(name = %name, "rule set update_on_start succeeded");
                    last_success.lock().await.insert(name, TokioInstant::now());
                    // Take a local value before send to avoid the Ref read lock deadlocking with the send write lock.
                    let next = notifier.borrow().wrapping_add(1);
                    let _ = notifier.send(next);
                }
                Err(err) => {
                    warn!(name = %name, error = %err, "rule set update_on_start failed");
                }
            }
        });
    }
}

/// Production update executor: calls [`update_rule_set`].
fn default_updater() -> UpdateFn {
    Arc::new(|config, dir, proxy| {
        let config = config.clone();
        let dir = dir.clone();
        Box::pin(async move { update_rule_set(&config, &dir, proxy).await })
    })
}

/// Determine the proxy address used to download an entry: explicit `proxy` > default proxy group; unavailable → direct (with a warning).
fn resolve_proxy_addr(
    config: &RuleSetConfig,
    resolver: &dyn ProxyResolver,
    default_proxy: Option<&str>,
) -> Option<SocketAddr> {
    let proxy = config.proxy.as_deref().or(default_proxy);
    match proxy {
        Some(name) => match resolver.resolve(name) {
            Some(addr) => Some(addr),
            None => {
                warn!(name = %config.name, proxy = name, "proxy group not resolvable; falling back to direct");
                None
            }
        },
        None => None,
    }
}

// ============================================================================
// Time-computation helper functions (pure, unit-testable)
// ============================================================================

/// Compute the next `HH:MM` trigger instant after `now` (local time).
///
/// If that time on `now`'s day has already passed (**including exactly equal**), defer to the next day (design §5.5).
/// Pure function: `now` is injected by the caller and does not depend on the system's current time.
pub fn next_time_trigger(now: DateTime<Local>, hh: u8, mm: u8) -> DateTime<Local> {
    let naive = now
        .date_naive()
        .and_hms_opt(hh as u32, mm as u32, 0)
        .expect("valid hh:mm");
    let target = naive
        .and_local_timezone(Local)
        .single()
        .unwrap_or_else(|| naive.and_utc().with_timezone(&Local));
    if target > now {
        target
    } else {
        target + ChronoDuration::days(1)
    }
}

/// Compute the next `period` trigger instant after the last successful update (failures do not consume the period).
/// Pure function: `last_success` is injected by the caller.
pub fn next_period_trigger(last_success: DateTime<Local>, period: Duration) -> DateTime<Local> {
    last_success + ChronoDuration::from_std(period).expect("period fits chrono duration")
}

/// Compute the next **future** period trigger point: `last_success + k * period` (where `k` is the smallest
/// positive integer making the result strictly greater than `now`).
///
/// The base `last_success` is not changed by failures (failures do not consume the period); if the point at
/// base instant + period has already passed, defer to the next period point — avoiding spin retries after failures.
fn next_period_point(
    last_success: TokioInstant,
    period: Duration,
    now: TokioInstant,
) -> TokioInstant {
    let elapsed = now.saturating_duration_since(last_success);
    let step: u128 = if period.is_zero() {
        1
    } else {
        elapsed.as_nanos() / period.as_nanos() + 1
    };
    last_success + period.saturating_mul(step.min(u32::MAX as u128) as u32)
}

/// Convert a local time to a monotonic-clock `Instant` (relative to `now_local` / `now_inst`).
fn local_to_instant(
    now_local: DateTime<Local>,
    now_inst: TokioInstant,
    dt: DateTime<Local>,
) -> TokioInstant {
    let dur = (dt - now_local).to_std().unwrap_or(Duration::ZERO);
    now_inst + dur
}

/// Parse a period string (`3h2m` / `1d12h30m`) into a [`std::time::Duration`].
///
/// Same as [`crate::ruleset::types::parse_period`]; re-exported here so the scheduler
/// and external callers can access it through the scheduler namespace.
pub use crate::ruleset::types::parse_period;

// ============================================================================
// Unit test
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ruleset::store::DataDir;
    use crate::ruleset::types::RuleSetType;
    use chrono::{TimeZone, Timelike};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FakeResolver;
    impl ProxyResolver for FakeResolver {
        fn resolve(&self, _proxy: &str) -> Option<SocketAddr> {
            Some("127.0.0.1:1080".parse().unwrap())
        }
    }

    fn base_config(name: &str) -> RuleSetConfig {
        RuleSetConfig {
            name: name.into(),
            r#type: RuleSetType::IpList,
            url: "http://example.com/x.txt".into(),
            expected_sha256: None,
            update: None,
            update_on_start: false,
            proxy: None,
        }
    }

    fn local(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> DateTime<Local> {
        Local
            .with_ymd_and_hms(y, mo, d, h, mi, s)
            .single()
            .expect("valid local datetime")
    }

    // ── Time-computation pure functions ──

    #[test]
    fn test_next_time_trigger_same_day() {
        let now = local(2026, 8, 3, 20, 0, 0);
        let t = next_time_trigger(now, 21, 47);
        assert_eq!(t.date_naive(), now.date_naive(), "same day");
        assert_eq!((t.hour(), t.minute()), (21, 47));
    }

    #[test]
    fn test_next_time_trigger_next_day_when_passed() {
        let now = local(2026, 8, 3, 20, 0, 0);
        let t = next_time_trigger(now, 19, 30);
        assert_eq!(
            t.date_naive(),
            now.date_naive() + chrono::Days::new(1),
            "past time rolls to next day"
        );
        assert_eq!((t.hour(), t.minute()), (19, 30));
    }

    #[test]
    fn test_next_time_trigger_equal_is_next_day() {
        let now = local(2026, 8, 3, 21, 47, 0);
        let t = next_time_trigger(now, 21, 47);
        assert_eq!(t.date_naive(), now.date_naive() + chrono::Days::new(1));
    }

    #[test]
    fn test_parse_period_valid() {
        assert_eq!(parse_period("3h2m").unwrap(), Duration::from_secs(3 * 3600 + 2 * 60));
        assert_eq!(parse_period("1d").unwrap(), Duration::from_secs(86400));
        assert_eq!(parse_period("1d12h30m").unwrap(), Duration::from_secs(86400 + 43200 + 1800));
        assert_eq!(parse_period(" 90m ").unwrap(), Duration::from_secs(5400));
    }

    #[test]
    fn test_parse_period_invalid() {
        // seconds forbidden
        assert!(parse_period("1s").is_err());
        assert!(parse_period("3h2m5s").is_err());
        // Invalid unit
        assert!(parse_period("3x").is_err());
        // missing unit / missing number / empty / zero
        assert!(parse_period("3").is_err());
        assert!(parse_period("h").is_err());
        assert!(parse_period("").is_err());
        assert!(parse_period("0m").is_err());
        assert!(parse_period("3h2").is_err());
    }

    #[test]
    fn test_parse_time_valid_and_invalid() {
        assert_eq!(parse_time("21:47").unwrap(), (21, 47));
        assert_eq!(parse_time("00:00").unwrap(), (0, 0));
        assert_eq!(parse_time("23:59").unwrap(), (23, 59));
        assert!(parse_time("24:00").is_err());
        assert!(parse_time("21:60").is_err());
        assert!(parse_time("21:47:30").is_err(), "seconds forbidden");
        assert!(parse_time("2147").is_err());
        assert!(parse_time("abc").is_err());
    }

    #[test]
    fn test_next_period_trigger() {
        let base = local(2026, 8, 3, 10, 0, 0);
        let next = next_period_trigger(base, Duration::from_secs(3 * 3600 + 2 * 60));
        assert_eq!(next, local(2026, 8, 3, 13, 2, 0));
        // crosses a day
        let next2 = next_period_trigger(base, Duration::from_secs(86400));
        assert_eq!(next2, local(2026, 8, 4, 10, 0, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn test_next_period_point_skips_past() {
        // Base T, period 1m; now = T + 61s (T+P already passed) → next period point T + 2m
        let t = TokioInstant::now();
        let now = t + Duration::from_secs(61);
        let next = next_period_point(t, Duration::from_secs(60), now);
        assert_eq!(next, t + Duration::from_secs(120));
        // Before the period: now = T + 10s → next period point T + 1m
        let now2 = t + Duration::from_secs(10);
        assert_eq!(next_period_point(t, Duration::from_secs(60), now2), t + Duration::from_secs(60));
    }

    // ── Scheduler integration (paused time) ──

    fn build_scheduler(
        dir: Arc<DataDir>,
        default_proxy: Option<String>,
    ) -> (RuleSetScheduler, watch::Sender<bool>, watch::Receiver<u64>) {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (notifier_tx, notifier_rx) = watch::channel(0u64);
        let scheduler = RuleSetScheduler {
            dir,
            proxy_resolver: Arc::new(FakeResolver),
            default_proxy,
            entries: Vec::new(),
            last_success: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            notifier: notifier_tx,
            shutdown: shutdown_rx,
        };
        (scheduler, shutdown_tx, notifier_rx)
    }

    #[tokio::test(start_paused = true)]
    async fn test_scheduler_update_on_start_fires_immediately() {
        // update_on_start entries fire immediately and asynchronously after startup (without waiting for the schedule).
        // Use paused time + a current_thread runtime: it does not depend on the real clock / OS thread scheduling,
        // avoiding flaky hangs under the default parallel test runner (--test-threads) — the previous multi_thread + yield_now
        // polling + a real-clock 3s deadline could not guarantee timely scheduling of the background task under
        // high parallel load and was once observed to hang for over 60s (fixed in phase 5).
        let dir = Arc::new(DataDir::new(tempfile::tempdir().unwrap().path()));
        let calls = Arc::new(AtomicUsize::new(0));
        let updater: UpdateFn = {
            let calls = calls.clone();
            Arc::new(move |_c, _d, _p| {
                calls.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(UpdateOutcome::NotModified) })
            })
        };
        let mut cfg = base_config("start");
        cfg.update = Some(RuleSetUpdate::Time("23:59".into()));
        cfg.update_on_start = true;

        let (scheduler, _shutdown_tx, _notifier_rx) = build_scheduler(dir, None);
        let _handle = tokio::spawn(scheduler.run(vec![cfg], updater));

        // Deterministic yield of control: scheduler.run completes initialization and fires the update_on_start independent task.
        // Advance the virtual clock (independent of real time); cap the polling to avoid accidental infinite loops.
        for _ in 0..100 {
            if calls.load(Ordering::SeqCst) >= 1 {
                break;
            }
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_millis(1)).await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1, "update_on_start should fire immediately");

        // Do not await the handle: when the test ends, the runtime drop cleans up the background Scheduled task automatically;
        // graceful shutdown is covered by the shutdown tests.
    }

    #[tokio::test(start_paused = true)]
    async fn test_scheduler_shutdown_stops_task() {
        let dir = Arc::new(DataDir::new(tempfile::tempdir().unwrap().path()));
        let updater: UpdateFn = Arc::new(|_c, _d, _p| {
            Box::pin(async { Ok(UpdateOutcome::NotModified) })
        });
        let (scheduler, shutdown_tx, _notifier_rx) = build_scheduler(dir, None);
        let handle = tokio::spawn(scheduler.run(vec![], updater));

        shutdown_tx.send(true).unwrap();
        tokio::time::advance(Duration::from_millis(10)).await;
        // The Scheduled task should exit gracefully
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_scheduler_shutdown_with_entry_real_time() {
        // Not paused (real time): verify that graceful shutdown can promptly interrupt a long sleep (when there are active entries),
        // covering the scenario ControlPlane.stop() actually calls.
        let dir = Arc::new(DataDir::new(tempfile::tempdir().unwrap().path()));
        let updater: UpdateFn = Arc::new(|_c, _d, _p| {
            Box::pin(async { Ok(UpdateOutcome::NotModified) })
        });
        let mut cfg = base_config("shutdown-entry");
        cfg.update = Some(RuleSetUpdate::Period("1d".into())); // long period → sleeps for a long time

        let (scheduler, shutdown_tx, _notifier_rx) = build_scheduler(dir, None);
        // Pre-seed last_success to avoid initial_next reading disk meta
        scheduler
            .last_success
            .lock()
            .await
            .insert("shutdown-entry".into(), TokioInstant::now());
        let handle = tokio::spawn(scheduler.run(vec![cfg], updater));

        // Let run finish initialization and enter sleep
        tokio::task::yield_now().await;
        shutdown_tx.send(true).unwrap();
        // Graceful shutdown should complete within the timeout (interrupting the 1d sleep)
        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(result.is_ok(), "scheduler should shut down promptly with an active entry");
    }
}
