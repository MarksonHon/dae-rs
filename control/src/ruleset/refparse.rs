//! Ruleset reference parsing and shared matching utilities (design §6).
//!
//! This module provides:
//!
//! - [`RuleSetRef`]: recognizes the `set:<name>` prefix in arguments;
//!   anything else is treated as a plain value (§6.1 / §6.2).
//! - Domain name pattern matching ([`match_domain_pattern`] / [`match_domain_patterns`] /
//!   [`match_qname_value`]): shared by matcher and other routing, unifying the
//!   Suffix / Keyword / Full / Regex / Domain semantics; **qname is case-insensitive**.
//!
//! This module does **not depend** on matcher-specific modules; it can be reused by
//! `matcher`, avoiding duplicate implementations.

use crate::ruleset::types::{DomainPattern, DomainPatternType};

/// A parsed rule set reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleSetRef {
    /// `set:<name>` — a rule set entry name from the configuration (`domain_list` / `ip_list`).
    Set(String),
    /// Other: a plain value (CIDR / domain name pattern / keyword, etc.), with no prefix.
    Plain(String),
}

/// Recognize the `set:<name>` prefix; anything else is treated as a plain value.
pub fn parse_ref(value: &str) -> RuleSetRef {
    let v = value.trim();
    if let Some(name) = v.strip_prefix("set:") {
        RuleSetRef::Set(name.trim().to_string())
    } else {
        RuleSetRef::Plain(v.to_string())
    }
}

/// Whether the value is a rule set reference (`set:`).
pub fn is_ruleset_ref(value: &str) -> bool {
    matches!(parse_ref(value), RuleSetRef::Set(_))
}

/// Generate a human-readable reference label (for error messages): preserves the original prefix form.
pub fn ref_label(value: &str) -> String {
    value.trim().to_string()
}

/// Determine whether `qname` matches a single domain name pattern (**case-insensitive**).
///
/// Semantics aligned with design §2.2 / §2.3:
/// - `Suffix` (Plain/`suffix:`): matches itself and all of its subdomains;
/// - `Domain` (`domain:`): matches subdomains of the value (**excluding** the value itself);
/// - `Full` (`full:`): exactly matches the value itself;
/// - `Regex` (`regex:`): the value is used as a regex to match the full domain name;
/// - `Keyword` (`keyword:`): substring match.
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

/// Determine whether `qname` matches any pattern in the list (true if any matches).
pub fn match_domain_patterns(qname: &str, patterns: &[DomainPattern]) -> bool {
    patterns.iter().any(|p| match_domain_pattern(qname, p))
}

/// Match a plain qname value (`suffix:`/`full:`/`keyword:`/`regex:`/`domain:` prefix or a bare value).
///
/// A bare value is handled with **suffix** semantics (including itself), consistent with dae / design §6.4; case-insensitive.
/// Reused by routing (`qname(...)`).
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
        // Bare value uses suffix semantics (including itself)
        let v = v.trim_start_matches('.').to_ascii_lowercase();
        qname == v || qname.ends_with(&format!(".{v}"))
    }
}

/// Normalize qname: strip the trailing `.` and lowercase.
fn normalize_qname(qname: &str) -> String {
    qname.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Convert a [`DomainPattern`] into a pattern string with a key prefix (for matcher `domain_sets`).
///
/// `Suffix` → `suffix:<value>`, `Full` → `full:<value>`, `Regex` → `regex:<value>`,
/// `Domain` → `domain:<value>`, `Keyword` → `keyword:<value>`.
///
/// The eBPF `domain_routing_map` bitmap side only cares about rule indices; the pattern string is
/// coordinated by the user-space [`crate::routing::matcher::build_domain_routing_bitmap`] with the eBPF side's
/// `route_match_domain_set()` (by bitmap), and the key prefix is used by user space for evaluation.
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
        assert_eq!(parse_ref("set:chinaip"), RuleSetRef::Set("chinaip".into()));
        assert_eq!(parse_ref("  set:  mylist  "), RuleSetRef::Set("mylist".into()));
        assert_eq!(parse_ref("10.0.0.0/8"), RuleSetRef::Plain("10.0.0.0/8".into()));
        assert_eq!(parse_ref("suffix:baidu.com"), RuleSetRef::Plain("suffix:baidu.com".into()));
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
        // Suffix includes itself and subdomains
        assert!(match_domain_pattern("baidu.com", &mk(DomainPatternType::Suffix, "baidu.com")));
        assert!(match_domain_pattern("www.baidu.com", &mk(DomainPatternType::Suffix, "baidu.com")));
        assert!(!match_domain_pattern("notbaidu.com", &mk(DomainPatternType::Suffix, "baidu.com")));
        // Domain excludes itself
        assert!(!match_domain_pattern("baidu.com", &mk(DomainPatternType::Domain, "baidu.com")));
        assert!(match_domain_pattern("www.baidu.com", &mk(DomainPatternType::Domain, "baidu.com")));
        // Full exact match
        assert!(match_domain_pattern("google.com", &mk(DomainPatternType::Full, "google.com")));
        assert!(!match_domain_pattern("www.google.com", &mk(DomainPatternType::Full, "google.com")));
        // Keyword substring
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
