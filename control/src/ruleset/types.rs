//! 规则集内存数据结构与配置条目类型。
//!
//! 本模块只定义数据与配置类型，不参与任何 matcher / DNS / parser 接线
//! （由后续子任务接入）。

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 规则集数据类型（对应配置条目 `type` 字段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleSetType {
    /// dat 数据：geoip（`GeoIPList`）。
    #[serde(rename = "geoip")]
    GeoIp,
    /// dat 数据：geosite（`GeoSiteList`）。
    #[serde(rename = "geosite")]
    GeoSite,
    /// Text domain list.
    #[serde(rename = "domain_list")]
    DomainList,
    /// Text IP list.
    #[serde(rename = "ip_list")]
    IpList,
}

impl RuleSetType {
    /// 文件类型后缀：dat → `.dat`，文本 → `.txt`。
    pub fn file_extension(&self) -> &'static str {
        match self {
            RuleSetType::GeoIp | RuleSetType::GeoSite => ".dat",
            RuleSetType::DomainList | RuleSetType::IpList => ".txt",
        }
    }

    /// 与配置 `type` 字符串一致的名字（日志/诊断用）。
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleSetType::GeoIp => "geoip",
            RuleSetType::GeoSite => "geosite",
            RuleSetType::DomainList => "domain_list",
            RuleSetType::IpList => "ip_list",
        }
    }
}

/// Domain name模式类型。
///
/// 对齐 v2ray `DomainType`（Plain/Regex/Domain/Full）与文本列表前缀
/// （`suffix:`/`keyword:`/`full:`/`domain:`/`regex:`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DomainPatternType {
    /// 后缀匹配，含自身（v2ray Plain；文本无前缀或 `suffix:`）。
    Suffix,
    /// 子串匹配（文本 `keyword:`）。
    Keyword,
    /// 精确匹配（v2ray Full；文本 `full:`）。
    Full,
    /// 正则匹配（v2ray Regex；文本 `regex:`）。
    Regex,
    /// 子域匹配，不含自身（v2ray Domain；文本 `domain:`）。
    Domain,
}

/// 单条Domain name模式。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainPattern {
    /// 模式类型。
    pub pattern_type: DomainPatternType,
    /// 模式值（Domain name / 关键字 / 正则表达式）。
    pub value: String,
}

/// Ruleset scheduler表达式（设计 §5.4）。
///
/// `update` 字段为**互斥二选一**：
/// - `time: HH:MM` — 每天本地时区该时刻触发一次；
/// - `period: 3h2m` — 周期触发（`d`/`h`/`m` 组合，最小单位分钟，**禁止秒**）。
///
/// 枚举保存**原始文本**（而非解析后的值），这样配置校验器（E2104）能在
/// `update` 层面报告格式错误（时间/周期非法、含秒等），而调度器经
/// [`parse_time`] / [`parse_period`] 纯函数解析为结构化数据。
///
/// JSON 表示为 `{ "time": "21:47" }` / `{ "period": "3h2m" }`
/// （serde 枚举带 payload + `rename` 天然匹配该布局）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleSetUpdate {
    /// 每天本地时区 `HH:MM`（00-23:00-59，无秒）触发一次。
    #[serde(rename = "time")]
    Time(String),
    /// 周期触发：`d`/`h`/`m` 组合（如 `3h2m`、`1d12h30m`），最小单位分钟，禁止秒。
    #[serde(rename = "period")]
    Period(String),
}

/// 解析 `HH:MM` 时间字符串为 `(时, 分)`。
///
/// 校验：严格 `HH:MM`，小时 00-23，分钟 00-59；**不允许秒**。
/// 纯函数，供 validator（E2104）与调度器使用，可独立单测。
pub fn parse_time(hhmm: &str) -> Result<(u8, u8), String> {
    let s = hhmm.trim();
    let (hh, mm) = s
        .split_once(':')
        .ok_or_else(|| format!("invalid time '{hhmm}': expected `HH:MM`"))?;
    if mm.contains(':') {
        return Err(format!(
            "invalid time '{hhmm}': seconds are forbidden (expected `HH:MM`)"
        ));
    }
    if hh.is_empty() || mm.is_empty() {
        return Err(format!("invalid time '{hhmm}': expected `HH:MM`"));
    }
    let hh: u8 = hh
        .parse()
        .map_err(|_| format!("invalid time '{hhmm}': hour is not a number"))?;
    let mm: u8 = mm
        .parse()
        .map_err(|_| format!("invalid time '{hhmm}': minute is not a number"))?;
    if hh > 23 {
        return Err(format!("invalid time '{hhmm}': hour {hh} out of range 0-23"));
    }
    if mm > 59 {
        return Err(format!("invalid time '{hhmm}': minute {mm} out of range 0-59"));
    }
    Ok((hh, mm))
}

/// 解析周期字符串（`3h2m`、`1d12h30m`）为 [`std::time::Duration`]。
///
/// 支持单位 `d`（天）/ `h`（小时）/ `m`（分钟），可任意组合；**最小单位为分钟，
/// 禁止秒**。纯函数，供 validator（E2104）与调度器使用，可独立单测。
pub fn parse_period(spec: &str) -> Result<std::time::Duration, String> {
    let s = spec.trim();
    if s.is_empty() {
        return Err("empty period".to_string());
    }
    let chars: Vec<char> = s.chars().collect();
    let mut total_secs: u64 = 0;
    let mut seen = false;
    let mut i = 0;
    while i < chars.len() {
        let num_start = i;
        while i < chars.len() && chars[i].is_ascii_digit() {
            i += 1;
        }
        if i == num_start {
            return Err(format!(
                "invalid period '{spec}': expected number before unit at position {i}"
            ));
        }
        let num: u64 = chars[num_start..i]
            .iter()
            .collect::<String>()
            .parse()
            .map_err(|_| format!("invalid period '{spec}': bad number"))?;
        let unit = chars.get(i).copied().ok_or_else(|| {
            format!("invalid period '{spec}': missing unit after number (allowed: d/h/m)")
        })?;
        i += 1;
        let unit_secs: u64 = match unit {
            'd' => 24 * 60 * 60,
            'h' => 60 * 60,
            'm' => 60,
            c => {
                return Err(format!(
                    "invalid period '{spec}': illegal unit '{c}' (allowed: d/h/m; seconds are forbidden)"
                ));
            }
        };
        total_secs = total_secs
            .checked_add(
                num.checked_mul(unit_secs)
                    .ok_or_else(|| format!("invalid period '{spec}': overflow"))?,
            )
            .ok_or_else(|| format!("invalid period '{spec}': overflow"))?;
        seen = true;
    }
    if !seen || total_secs == 0 {
        return Err(format!("invalid period '{spec}': must be positive"));
    }
    Ok(std::time::Duration::from_secs(total_secs))
}

/// 规则集配置条目。
///
/// 本层定义该类型供下载/存储/调度使用；阶段 2（Configuration subsystem）从
/// `config.daefile` / `config.json` to fill `name/type/url/update/update_on_start/proxy`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RuleSetConfig {
    /// Unique name (used for file naming and `set:<name>` references).
    pub name: String,
    /// Data type.
    pub r#type: RuleSetType,
    /// Download URL; can include `#sha256=<hex>` fragment for forced verification.
    pub url: String,
    /// Explicit sha256 expectation (optional, takes priority over URL fragment; config layer extracts from `url#sha256=`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_sha256: Option<String>,
    /// Scheduling expression (`time` / `period` mutually exclusive, optional; default = no auto-update).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update: Option<RuleSetUpdate>,
    /// Unconditionally update once on startup (default false).
    #[serde(default)]
    pub update_on_start: bool,
    /// Proxy group name for download (optional; default uses the first proxy group, resolved by the integration layer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
}

impl RuleSetConfig {
    /// Parse expected checksum from the `#sha256=<hex>` fragment of the URL (lowercase).
    pub fn expected_sha256_from_url(url: &str) -> Option<String> {
        url.split_once('#')
            .and_then(|(_, fragment)| fragment.strip_prefix("sha256="))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase)
    }
}

/// Parsed ruleset data (in-memory cache).
#[derive(Debug, Clone, PartialEq)]
pub enum RuleSetData {
    /// geoip dat: `country_code` (lowercase) → CIDR list.
    GeoIp {
        /// `country_code` (lowercase) → CIDR list.
        entries: HashMap<String, Vec<IpNet>>,
    },
    /// geosite dat: `country_code` (lowercase) → domain pattern list.
    GeoSite {
        /// `country_code`（统一小写）→ Domain name模式列表。
        entries: HashMap<String, Vec<DomainPattern>>,
    },
    /// Text domain list.
    DomainList(Vec<DomainPattern>),
    /// Text IP list.
    IpList(Vec<IpNet>),
}
