//! Ruleset reference parsing与共享匹配工具（设计 §6）。
//!
//! 本模块提供：
//!
//! - [`RuleSetRef`]：识别参数中的 `set:<name>` / `geoip:<code>` / `geosite:<code>`
//!   前缀，其余视为普通值（§6.1 / §6.2）。
//! - Domain name模式匹配（[`match_domain_pattern`] / [`match_domain_patterns`] /
//!   [`match_qname_value`]）：供 DNS 查询Routing与 DNS 响应Routing共享，统一
//!   Suffix / Keyword / Full / Regex / Domain 语义，**qname 大小写不敏感**。
//!
//! 本模块**不依赖** matcher / DNS 具体模块，可被 `matcher`、`dns::router`、
//! `dns::handler` 复用，避免重复实现。

use crate::ruleset::types::{DomainPattern, DomainPatternType};

/// 解析后的规则集引用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleSetRef {
    /// `geoip:<code>` — geoip dat 中的 `country_code`（如 `cn`、`private`）。
    GeoIp(String),
    /// `geosite:<code>` — geosite dat 中的分类名（如 `cn`、`geolocation-!cn`）。
    GeoSite(String),
    /// `set:<name>` — 配置中的规则集条目名（`domain_list` / `ip_list`）。
    Set(String),
    /// 其它：普通值（CIDR / Domain name模式 / 关键字等），无前缀。
    Plain(String),
}

/// 识别 `set:<name>` / `geoip:<code>` / `geosite:<code>` 前缀；其余视为普通值。
pub fn parse_ref(value: &str) -> RuleSetRef {
    let v = value.trim();
    if let Some(code) = v.strip_prefix("geoip:") {
        RuleSetRef::GeoIp(code.trim().to_string())
    } else if let Some(code) = v.strip_prefix("geosite:") {
        RuleSetRef::GeoSite(code.trim().to_string())
    } else if let Some(name) = v.strip_prefix("set:") {
        RuleSetRef::Set(name.trim().to_string())
    } else {
        RuleSetRef::Plain(v.to_string())
    }
}

/// 是否为规则集引用（`geoip:` / `geosite:` / `set:`）。
pub fn is_ruleset_ref(value: &str) -> bool {
    matches!(
        parse_ref(value),
        RuleSetRef::GeoIp(_) | RuleSetRef::GeoSite(_) | RuleSetRef::Set(_)
    )
}

/// 生成可读引用标识（错误信息用）：保留原始前缀形式。
pub fn ref_label(value: &str) -> String {
    value.trim().to_string()
}

/// 判断 `qname` 是否命中单条Domain name模式（**大小写不敏感**）。
///
/// 语义对齐设计 §2.2 / §2.3：
/// - `Suffix`（Plain/`suffix:`）：命中自身及其所有子域；
/// - `Domain`（`domain:`）：命中 value 的子域（**不含** value 自身）；
/// - `Full`（`full:`）：精确匹配 value 本身；
/// - `Regex`（`regex:`）：value 作为正则匹配完整Domain name；
/// - `Keyword`（`keyword:`）：子串匹配。
pub fn match_domain_pattern(qname: &str, pattern: &DomainPattern) -> bool {
    let qname = normalize_qname(qname);
    match pattern.pattern_type {
        DomainPatternType::Suffix => {
            let v = pattern.value.trim_start_matches('.').to_ascii_lowercase();
            qname == v || qname.ends_with(&format!(".{v}"))
        }
        DomainPatternType::Domain => {
            let v = pattern.value.trim_start_matches('.').to_ascii_lowercase();
            qname != v && qname.ends_with(&format!(".{v}"))
        }
        DomainPatternType::Full => {
            let v = pattern.value.trim_end_matches('.').to_ascii_lowercase();
            qname == v
        }
        DomainPatternType::Keyword => {
            let v = pattern.value.to_ascii_lowercase();
            !v.is_empty() && qname.contains(&v)
        }
        DomainPatternType::Regex => regex::Regex::new(&pattern.value)
            .map(|re| re.is_match(&qname))
            .unwrap_or(false),
    }
}

/// 判断 `qname` 是否命中模式列表（任一命中即真）。
pub fn match_domain_patterns(qname: &str, patterns: &[DomainPattern]) -> bool {
    patterns.iter().any(|p| match_domain_pattern(qname, p))
}

/// 匹配一个普通 qname 值（`suffix:`/`full:`/`keyword:`/`regex:`/`domain:` 前缀或裸值）。
///
/// 裸值按**后缀**（含自身）语义处理，与 dae / 设计 §6.4 一致；大小写不敏感。
/// 供 DNS 查询Routing（`qname(...)`）与 DNS 响应Routing（`qname(...)`）复用。
pub fn match_qname_value(qname: &str, value: &str) -> bool {
    let qname = normalize_qname(qname);
    let v = value.trim();
    if let Some(rest) = v.strip_prefix("suffix:").or_else(|| v.strip_prefix("domain:")) {
        let rest = rest.trim_start_matches('.').to_ascii_lowercase();
        qname == rest || qname.ends_with(&format!(".{rest}"))
    } else if let Some(rest) = v.strip_prefix("full:") {
        qname == rest.trim().trim_end_matches('.').to_ascii_lowercase()
    } else if let Some(rest) = v.strip_prefix("keyword:") {
        let rest = rest.trim().to_ascii_lowercase();
        !rest.is_empty() && qname.contains(&rest)
    } else if let Some(rest) = v.strip_prefix("regex:") {
        regex::Regex::new(rest.trim())
            .map(|re| re.is_match(&qname))
            .unwrap_or(false)
    } else {
        // 裸值按后缀（含自身）
        let v = v.trim_start_matches('.').to_ascii_lowercase();
        qname == v || qname.ends_with(&format!(".{v}"))
    }
}

/// 归一化 qname：去除末尾 `.` 并转小写。
fn normalize_qname(qname: &str) -> String {
    qname.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// 将 [`DomainPattern`] 转换为带 key 前缀的模式字符串（供 matcher `domain_sets`）。
///
/// `Suffix` → `suffix:<value>`、`Full` → `full:<value>`、`Regex` → `regex:<value>`、
/// `Domain` → `domain:<value>`、`Keyword` → `keyword:<value>`。
///
/// eBPF `domain_routing_map` 位图侧只关心规则索引；模式字符串由用户空间
/// [`crate::routing::matcher::build_domain_routing_bitmap`] 与 eBPF 侧
/// `route_match_domain_set()`（按位图）协作，key 前缀供用户空间求值。
pub fn domain_pattern_to_string(p: &DomainPattern) -> String {
    match p.pattern_type {
        DomainPatternType::Suffix => format!("suffix:{}", p.value),
        DomainPatternType::Full => format!("full:{}", p.value),
        DomainPatternType::Regex => format!("regex:{}", p.value),
        DomainPatternType::Domain => format!("domain:{}", p.value),
        DomainPatternType::Keyword => format!("keyword:{}", p.value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ruleset::types::DomainPatternType;

    #[test]
    fn test_parse_ref() {
        assert_eq!(parse_ref("geoip:cn"), RuleSetRef::GeoIp("cn".into()));
        assert_eq!(parse_ref("geosite:cn"), RuleSetRef::GeoSite("cn".into()));
        assert_eq!(parse_ref("set:chinaip"), RuleSetRef::Set("chinaip".into()));
        assert_eq!(parse_ref("  set:  mylist  "), RuleSetRef::Set("mylist".into()));
        assert_eq!(parse_ref("10.0.0.0/8"), RuleSetRef::Plain("10.0.0.0/8".into()));
        assert_eq!(parse_ref("suffix:baidu.com"), RuleSetRef::Plain("suffix:baidu.com".into()));
        assert!(is_ruleset_ref("geoip:cn"));
        assert!(is_ruleset_ref("set:x"));
        assert!(!is_ruleset_ref("suffix:baidu.com"));
        assert!(!is_ruleset_ref("10.0.0.0/8"));
    }

    #[test]
    fn test_match_domain_pattern_semantics() {
        let mk = |t: DomainPatternType, v: &str| DomainPattern {
            pattern_type: t,
            value: v.to_string(),
        };
        // Suffix 含自身与子域
        assert!(match_domain_pattern("baidu.com", &mk(DomainPatternType::Suffix, "baidu.com")));
        assert!(match_domain_pattern("www.baidu.com", &mk(DomainPatternType::Suffix, "baidu.com")));
        assert!(!match_domain_pattern("notbaidu.com", &mk(DomainPatternType::Suffix, "baidu.com")));
        // Domain 不含自身
        assert!(!match_domain_pattern("baidu.com", &mk(DomainPatternType::Domain, "baidu.com")));
        assert!(match_domain_pattern("www.baidu.com", &mk(DomainPatternType::Domain, "baidu.com")));
        // Full 精确
        assert!(match_domain_pattern("google.com", &mk(DomainPatternType::Full, "google.com")));
        assert!(!match_domain_pattern("www.google.com", &mk(DomainPatternType::Full, "google.com")));
        // Keyword 子串
        assert!(match_domain_pattern("foo.ads.bar.com", &mk(DomainPatternType::Keyword, "ads")));
        // Regex
        assert!(match_domain_pattern("x.y", &mk(DomainPatternType::Regex, r"^x\.y$")));
        // Case insensitive
        assert!(match_domain_pattern("WWW.BAIDU.COM", &mk(DomainPatternType::Suffix, "baidu.com")));
        assert!(match_domain_pattern("BaIdU.CoM", &mk(DomainPatternType::Full, "baidu.com")));
    }

    #[test]
    fn test_match_qname_value() {
        assert!(match_qname_value("example.cn", "suffix:cn"));
        assert!(match_qname_value("sub.example.cn", "cn"));
        assert!(!match_qname_value("example.com", "suffix:cn"));
        assert!(match_qname_value("www.google.com", "full:www.google.com"));
        assert!(match_qname_value("ads.example.com", "keyword:ads"));
        assert!(match_qname_value("WWW.GOOGLE.COM", "full:www.google.com"), "case-insensitive");
    }

    #[test]
    fn test_domain_pattern_to_string() {
        assert_eq!(domain_pattern_to_string(&DomainPattern { pattern_type: DomainPatternType::Suffix, value: "a.com".into() }), "suffix:a.com");
        assert_eq!(domain_pattern_to_string(&DomainPattern { pattern_type: DomainPatternType::Regex, value: r"^x$".into() }), "regex:^x$");
    }
}
