//! Rule set in-memory data structures and configuration entry types.
//!
//! This module only defines data and configuration types; it does not take part in any
//! matcher / parser wiring (handled by later sub-tasks).

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Rule set data type (corresponds to the `type` field of a configuration entry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleSetType {
    /// Text domain list.
    #[serde(rename = "domain_list")]
    DomainList,
    /// Text IP list.
    #[serde(rename = "ip_list")]
    IpList,
}

impl RuleSetType {
    /// File type extension: text → `.txt`.
    pub fn file_extension(&self) -> &'static str {
        match self {
            RuleSetType::DomainList | RuleSetType::IpList => ".txt",
        }
    }

    /// Name matching the configuration `type` string (for logs / diagnostics).
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleSetType::DomainList => "domain_list",
            RuleSetType::IpList => "ip_list",
        }
    }
}

/// Domain name pattern type.
///
/// Aligned with the v2ray `DomainType` (Plain/Regex/Domain/Full) and text-list prefixes
/// (`suffix:`/`keyword:`/`full:`/`domain:`/`regex:`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DomainPatternType {
    /// Suffix match, including itself (v2ray Plain; text with no prefix or `suffix:`).
    Suffix,
    /// Substring match (text `keyword:`).
    Keyword,
    /// Exact match (v2ray Full; text `full:`).
    Full,
    /// Regex match (v2ray Regex; text `regex:`).
    Regex,
    /// Subdomain match, excluding itself (v2ray Domain; text `domain:`).
    Domain,
}

/// A single domain name pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainPattern {
    /// Pattern type.
    pub pattern_type: DomainPatternType,
    /// Pattern value (domain name / keyword / regular expression).
    pub value: String,
}

/// Rule set scheduler expression (design §5.4).
///
/// The `update` field is **mutually exclusive between two options**:
/// - `time: HH:MM` — triggers once daily at that time in the local timezone;
/// - `period: 3h2m` — periodic trigger (`d`/`h`/`m` combinations, minimum unit minutes, **seconds forbidden**).
///
/// The enum stores the **raw text** (rather than parsed values), so the configuration validator (E2104) can
/// report format errors at the `update` level (invalid time/period, contains seconds, etc.), while the
/// scheduler parses it into structured data via the [`parse_time`] / [`parse_period`] pure functions.
///
/// JSON representation: `{ "time": "21:47" }` / `{ "period": "3h2m" }`
/// (a serde enum with payload + `rename` naturally matches this layout).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleSetUpdate {
    /// Trigger once daily at `HH:MM` (00-23:00-59, no seconds) in the local timezone.
    #[serde(rename = "time")]
    Time(String),
    /// Periodic trigger: `d`/`h`/`m` combinations (e.g. `3h2m`, `1d12h30m`), minimum unit minutes, seconds forbidden.
    #[serde(rename = "period")]
    Period(String),
}

/// Parse an `HH:MM` time string into `(hour, minute)`.
///
/// Validation: strict `HH:MM`, hours 00-23, minutes 00-59; **seconds are not allowed**.
/// Pure function, used by the validator (E2104) and the scheduler; unit-testable independently.
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

/// Parse a period string (`3h2m`, `1d12h30m`) into a [`std::time::Duration`].
///
/// Supports the units `d` (days) / `h` (hours) / `m` (minutes) in any combination; **the minimum unit
/// is minutes, seconds are forbidden**. Pure function, used by the validator (E2104) and the scheduler; unit-testable independently.
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

/// Rule set configuration entry.
///
/// This layer defines the type for download/storage/scheduling use; phase 2 (Configuration subsystem)
/// fills `name/type/url/update/update_on_start/proxy` from `config.daefile` / `config.json`.
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
///
/// Serialize/Deserialize are used by the binary cache in `/run/dae-rs/` so a
/// restart can load already-parsed lists without re-parsing the source text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RuleSetData {
    /// Text domain list.
    DomainList(Vec<DomainPattern>),
    /// Text IP list.
    IpList(Vec<IpNet>),
}
