//! Ruleset scheduler（设计文档 §7）。
//!
//! 单 tokio 任务聚合所有规则集的定时更新：
//!
//! - `update_on_start: true`：启动后**立即异步**触发一次无条件更新（不阻塞启动）；
//! - `time: HH:MM`：每天本地时区该时刻触发；启动时若已过则顺延次日；
//! - `period: 3h2m`：以上次**成功更新**为基准（失败不消耗周期），支持 `d`/`h`/`m`
//!   组合、最小单位分钟、禁止秒。
//!
//! 更新完成后通过 `watch` 通道（[`UpdateSignal`]，成功计数递增）通知外部——
//! 本层只发通知信号，具体热重载接线（Routing重编译 / eBPF 双缓冲切换）由集成处 / 阶段 3 负责。
//!
//! **时钟基准**：调度时刻与"上次成功更新"统一用单调时钟 [`tokio::time::Instant`]
//! 记录（`Local` 时间仅用于 `HH:MM` 到时刻的换算），保证与 `tokio::time::sleep_until`
//! 一致、可在 `start_paused` 测试下推进虚拟时钟。
//!
//! 时间计算辅助函数（[`next_time_trigger`] / [`next_period_trigger`] /
//! [`parse_period`]）均为**纯函数、不依赖当前时刻**（`now` 作为参数注入），可独立单测。

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
// 公共接口
// ============================================================================

/// 代理解析接口：`proxy` 代理组名 → SOCKS5 地址。
///
/// 本层**不实现**代理组解析（如"第一个代理组"的确定、组内节点选择等），仅定义
/// 接口并接收调用方注入。`None` 表示该代理组未知/不可用（回退直连下载并告警）。
/// 阶段 3 / 集成处负责提供真实实现。
pub trait ProxyResolver: Send + Sync {
    /// Parse proxy group名 → SOCKS5 地址；`None` 表示不可用（直连）。
    fn resolve(&self, proxy: &str) -> Option<SocketAddr>;
}

/// 更新完成通知信号。
///
/// 每次成功更新发送一次，值单调递增；接收方用 [`watch::Receiver::changed`]
/// 感知"有规则集已更新，可触发热重载"。
pub type UpdateSignal = watch::Sender<u64>;

/// 调度器句柄（[`RuleSetScheduler::spawn`] 的返回值）。
pub struct SchedulerHandle {
    /// Scheduled task句柄（调用 [`SchedulerHandle::shutdown`] 后结束）。
    pub handle: JoinHandle<()>,
    /// 优雅关停信号发送端。
    pub shutdown: watch::Sender<bool>,
    /// 更新完成通知接收端（成功更新时值递增）。
    pub notifier: watch::Receiver<u64>,
}

impl SchedulerHandle {
    /// 触发优雅关停（发送信号，Scheduled task在下次唤醒时退出）。
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    /// 优雅关停并等待Scheduled task结束。
    pub async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = self.handle.await;
    }
}

// ============================================================================
// 调度器
// ============================================================================

/// 更新执行函数类型（可注入以便测试；生产使用 [`default_updater`]）。
type UpdateFuture =
    Pin<Box<dyn Future<Output = Result<UpdateOutcome, RuleSetError>> + Send>>;
type UpdateFn =
    Arc<dyn Fn(&RuleSetConfig, &DataDir, Option<SocketAddr>) -> UpdateFuture + Send + Sync>;

/// 解析后的调度触发类型。
#[derive(Debug, Clone, PartialEq, Eq)]
enum TriggerKind {
    /// 每天本地时区 `HH:MM` 触发一次。
    Time { hh: u8, mm: u8 },
    /// 周期触发（基准 = 上次成功更新）。
    Period { period: Duration },
}

/// 单条目的调度状态。
#[derive(Debug, Clone)]
struct Entry {
    config: RuleSetConfig,
    kind: TriggerKind,
    /// 下次触发时刻（单调时钟）。
    next: TokioInstant,
}

/// Ruleset scheduler。
///
/// 通过 [`RuleSetScheduler::spawn`] 创建后台任务；持有：
/// - 配置条目（含调度表达式）；
/// - [`DataDir`]（下载/存储）；
/// - 代理解析函数（注入）；
/// - 通知通道（成功更新时递增）。
pub struct RuleSetScheduler {
    dir: Arc<DataDir>,
    proxy_resolver: Arc<dyn ProxyResolver>,
    /// 缺省代理组名（"第一个代理组"，由调用方解析后注入；`proxy: None` 的条目使用）。
    default_proxy: Option<String>,
    entries: Vec<Entry>,
    /// name → 上次成功更新时刻（单调时钟；失败不消耗周期的基础）。
    last_success: Arc<tokio::sync::Mutex<HashMap<String, TokioInstant>>>,
    notifier: watch::Sender<u64>,
    shutdown: watch::Receiver<bool>,
}

impl RuleSetScheduler {
    /// 创建并 `tokio::spawn` Scheduled task。
    ///
    /// * `entries` — 规则集配置条目（已通过 validator 校验）。
    /// * `dir` — data directory.
    /// * `proxy_resolver` — 代理解析接口（本层不实现代理组解析）。
    /// * `default_proxy` — "第一个代理组"名（缺省代理；由调用方/阶段 3 确定）。
    ///
    /// 返回 [`SchedulerHandle`]（含 `JoinHandle`、关停发送端、通知接收端）。
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

    /// 调度主循环。
    async fn run(mut self, configs: Vec<RuleSetConfig>, updater: UpdateFn) {
        // Parse configuration → 调度条目（非法 update 已被 validator 拦截，这里防御性跳过）
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

        // 初始化各条目首次触发时刻
        let now_local = Local::now();
        let now_inst = TokioInstant::now();
        for i in 0..self.entries.len() {
            let next = {
                let e = &self.entries[i];
                self.initial_next(e, now_local, now_inst).await
            };
            self.entries[i].next = next;
        }

        // update_on_start：立即异步触发（独立任务，不阻塞调度循环 / 启动）
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
            // 先计算最近触发时刻（不可变借用），再进入 select（`changed()` 需可变借用）。
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
                        // 递增通知计数（接收方用 changed() 感知）。
                        // 先取局部值再 send：避免 `borrow()` 返回的 `watch::Ref` 读锁
                        // 临时值存活到 `send()`（写锁）调用期间，同一线程重入 RwLock 死锁。
                        let next = self.notifier.borrow().wrapping_add(1);
                        let _ = self.notifier.send(next);
                    }
                }
            }
        }
    }

    /// 计算条目首次触发时刻（period 基准：进程内上次成功更新 → 磁盘 meta → 启动时刻）。
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
                        // 跨重启延续：从 meta 恢复上次成功更新时刻
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

    /// 最近触发时刻（无条目时睡较长间隔防御）。
    fn next_instant(&self) -> TokioInstant {
        let now = TokioInstant::now();
        let mut nearest: Option<TokioInstant> = None;
        for e in &self.entries {
            if e.next <= now {
                // 已到点，立即返回（下一轮处理）
                return now;
            }
            nearest = Some(nearest.map_or(e.next, |n: TokioInstant| n.min(e.next)));
        }
        nearest.unwrap_or_else(|| now + Duration::from_secs(3600))
    }

    /// 处理一个到点条目：执行更新、更新上次成功时刻并排下次。
    /// 返回是否成功更新（用于决定是否发通知）。
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
                // 成功：基准前移为当前时刻
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
                // 失败不消耗周期：period 基准仍为上次成功更新（若无则为当前），
                // 取下一个未来周期点（避免空转重试）；time 顺延次日。
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

    /// 立即触发一次更新（update_on_start 条目，独立任务）。
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
                    // 先取局部值再 send，避免 Ref 读锁临时值与 send 写锁重入死锁。
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

/// 生产更新执行器：调用 [`update_rule_set`]。
fn default_updater() -> UpdateFn {
    Arc::new(|config, dir, proxy| {
        let config = config.clone();
        let dir = dir.clone();
        Box::pin(async move { update_rule_set(&config, &dir, proxy).await })
    })
}

/// 确定条目下载用的代理地址：显式 `proxy` > 缺省代理组；不可用 → 直连（告警）。
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
// 时间计算辅助函数（纯函数，可单测）
// ============================================================================

/// 计算从 `now`（本地时间）起的下一个 `HH:MM` 触发时刻。
///
/// 若 `now` 当日该时刻已过（**含恰好相等**），则顺延次日（设计 §5.5）。
/// 纯函数：`now` 由调用方注入，不依赖系统当前时刻。
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

/// 从上一次成功更新时刻起计算下一次 `period` 触发时刻（失败不消耗周期）。
/// 纯函数：`last_success` 由调用方注入。
pub fn next_period_trigger(last_success: DateTime<Local>, period: Duration) -> DateTime<Local> {
    last_success + ChronoDuration::from_std(period).expect("period fits chrono duration")
}

/// 计算下一个**未来**的周期触发点：`last_success + k * period`（`k` 为使结果
/// 严格大于 `now` 的最小正整数）。
///
/// 基准 `last_success` 不因失败改变（失败不消耗周期）；若基准时刻 + 周期的点
/// 已经过去，则顺延到下一个周期点——避免失败后空转重试。
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

/// 将本地时刻换算为单调时钟 `Instant`（相对 `now_local` / `now_inst`）。
fn local_to_instant(
    now_local: DateTime<Local>,
    now_inst: TokioInstant,
    dt: DateTime<Local>,
) -> TokioInstant {
    let dur = (dt - now_local).to_std().unwrap_or(Duration::ZERO);
    now_inst + dur
}

/// 解析周期字符串（`3h2m` / `1d12h30m`）为 [`std::time::Duration`]。
///
/// 与 [`crate::ruleset::types::parse_period`] 相同，此处 re-export 以便调度器
/// 与外部经调度器命名空间访问。
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

    // ── 时间计算纯函数 ──

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
        // 禁止秒
        assert!(parse_period("1s").is_err());
        assert!(parse_period("3h2m5s").is_err());
        // Invalid unit
        assert!(parse_period("3x").is_err());
        // 缺单位 / 缺数字 / 空 / 零
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
        // 跨天
        let next2 = next_period_trigger(base, Duration::from_secs(86400));
        assert_eq!(next2, local(2026, 8, 4, 10, 0, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn test_next_period_point_skips_past() {
        // 基准 T，周期 1m；now = T + 61s（T+P 已过）→ 下一个周期点 T + 2m
        let t = TokioInstant::now();
        let now = t + Duration::from_secs(61);
        let next = next_period_point(t, Duration::from_secs(60), now);
        assert_eq!(next, t + Duration::from_secs(120));
        // 未到周期：now = T + 10s → 下一个周期点 T + 1m
        let now2 = t + Duration::from_secs(10);
        assert_eq!(next_period_point(t, Duration::from_secs(60), now2), t + Duration::from_secs(60));
    }

    // ── 调度器集成（paused 时间）──

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
        // update_on_start 条目在启动后立即异步触发（不等待调度周期）。
        // 使用 paused 时间 + current_thread runtime：不依赖真实时钟 / OS 线程调度，
        // 避免默认并行测试（--test-threads）下偶发卡死——原 multi_thread + yield_now
        // 轮询 + 真实时钟 3s deadline 在高负载并行下无法保证后台任务及时被调度，
        // 曾被观察到卡死超过 60s（阶段 5 修复）。
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

        // Deterministic让出控制权：scheduler.run 完成初始化并触发 update_on_start 独立任务。
        // 虚拟时钟推进（不依赖真实时间）；轮询设上限避免意外死循环。
        for _ in 0..100 {
            if calls.load(Ordering::SeqCst) >= 1 {
                break;
            }
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_millis(1)).await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1, "update_on_start should fire immediately");

        // 不等待 handle：测试结束 runtime drop 自动清理后台Scheduled task；
        // 优雅关停由 shutdown 测试覆盖。
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
        // Scheduled task应优雅退出
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_scheduler_shutdown_with_entry_real_time() {
        // 非 paused（真实时间）：验证优雅关停能立即中断长 sleep（存在活跃条目时），
        // 覆盖 ControlPlane.stop() 实际调用的场景。
        let dir = Arc::new(DataDir::new(tempfile::tempdir().unwrap().path()));
        let updater: UpdateFn = Arc::new(|_c, _d, _p| {
            Box::pin(async { Ok(UpdateOutcome::NotModified) })
        });
        let mut cfg = base_config("shutdown-entry");
        cfg.update = Some(RuleSetUpdate::Period("1d".into())); // 长周期 → sleep 很久

        let (scheduler, shutdown_tx, _notifier_rx) = build_scheduler(dir, None);
        // 预置 last_success，避免 initial_next 读取磁盘 meta
        scheduler
            .last_success
            .lock()
            .await
            .insert("shutdown-entry".into(), TokioInstant::now());
        let handle = tokio::spawn(scheduler.run(vec![cfg], updater));

        // 让 run 完成初始化并进入 sleep
        tokio::task::yield_now().await;
        shutdown_tx.send(true).unwrap();
        // 优雅关停应在超时内完成（中断 1d 的 sleep）
        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(result.is_ok(), "scheduler should shut down promptly with an active entry");
    }
}
