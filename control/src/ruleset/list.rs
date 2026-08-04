//! Text domain name / IP list parsing (design §2.3).
//!
//! Supports three input styles, so the same list file works with mihomo/clash,
//! Surge and dae-rs native formats:
//!
//! - **Bare lists** (mihomo `geoip/ipcidr/` and Surge `geoip/surge/` IP lists,
//!   dae-rs native domain lists): one CIDR / domain per line.
//! - **Rule lists** (mihomo `clash-rules/` and Surge `surge-rules/`):
//!   `DOMAIN,xxx` / `DOMAIN-SUFFIX,xxx` / `DOMAIN-KEYWORD,xxx` /
//!   `DOMAIN-REGEX,xxx` / `IP-CIDR,xxx` / `IP-CIDR6,xxx`, plus `GEOIP`,
//!   `MATCH` / `FINAL` etc.
//!
//! IP list parsing:
//! - `a.b.c.d/nn`, `2001:db8::/nn` (CIDR) or a bare IP (treated as /32 or /128);
//! - `IP-CIDR,x` / `IP-CIDR6,x` rule lines (optional `,no-resolve` etc. ignored);
//! - non-IP rule lines (domains, GEOIP, MATCH/FINAL, ...) are skipped.
//!
//! Domain list parsing:
//! - dae-rs native prefixes `full:` / `domain:` / `suffix:` / `keyword:` / `regex:`
//!   (case-insensitive); without a prefix it defaults to
//!   [`DomainPatternType::Suffix`] (Plain, suffix including itself);
//! - mihomo/clash & Surge rules: `DOMAIN,xxx` → Full, `DOMAIN-SUFFIX,xxx` → Suffix,
//!   `DOMAIN-KEYWORD,xxx` → Keyword, `DOMAIN-REGEX,xxx` → Regex;
//! - non-domain rule lines (IP-CIDR, GEOIP, MATCH/FINAL, ...) are skipped.
//!
//! Lines starting with `#` are comments, and empty lines are ignored.

use ipnet::IpNet;
use std::net::IpAddr;
use thiserror::Error;

use crate::ruleset::types::{DomainPattern, DomainPatternType};

/// Text list parse error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ListError {
    #[error("line {line}: invalid CIDR or IP: '{value}'")]
    InvalidIp { line: usize, value: String },
    #[error("line {line}: invalid domain pattern: '{value}'")]
    InvalidDomain { line: usize, value: String },
    #[error("line {line}: unrecognized rule line: '{value}'")]
    UnrecognizedRule { line: usize, value: String },
}

/// Rule keywords that are NOT representable as an IP (skipped when parsing an IP list).
const NON_IP_RULE_PREFIXES: &[&str] = &[
    "domain",
    "domain-suffix",
    "domain-keyword",
    "domain-regex",
    "geoip",
    "match",
    "final",
    "rule-set",
    "process-name",
    "process-path",
    "user-agent",
    "src-ip",
    "src-port",
    "dst-port",
    "protocol",
    "network",
    "url-regex",
    "ip-asn",
];

/// Rule keywords that are NOT a domain pattern (skipped when parsing a domain list).
const NON_DOMAIN_RULE_PREFIXES: &[&str] = &[
    "ip-cidr",
    "ip-cidr6",
    "ip-asn",
    "geoip",
    "match",
    "final",
    "rule-set",
    "process-name",
    "process-path",
    "user-agent",
    "src-ip",
    "src-port",
    "dst-port",
    "protocol",
    "network",
    "url-regex",
];

/// Strip a case-insensitive rule keyword prefix (`KEYWORD,<rest>`) and return `<rest>`,
/// or `None` if the line does not start with that keyword followed by a comma.
fn strip_rule_keyword<'a>(line: &'a str, keyword: &str) -> Option<&'a str> {
    let kw = keyword.as_bytes();
    if line.len() > kw.len()
        && line.as_bytes().get(kw.len()) == Some(&b',')
        && line[..kw.len()].eq_ignore_ascii_case(keyword)
    {
        Some(line[kw.len() + 1..].trim())
    } else {
        None
    }
}

/// Whether a line is (or starts with) one of the given rule keywords, case-insensitively.
/// Matches both `KEYWORD` (bare) and `KEYWORD,<value>` forms.
fn line_is_rule_keyword(line: &str, keywords: &[&str]) -> bool {
    let lower = line.to_ascii_lowercase();
    keywords
        .iter()
        .any(|k| lower == *k || lower.starts_with(&format!("{},", k)))
}

/// Take the first comma-separated argument (trailing rule options like `no-resolve`
/// or `force-remote-dns` are ignored).
fn first_arg(rest: &str) -> &str {
    rest.split(',').next().unwrap_or("").trim()
}

/// Parse IP list text into a CIDR list (mihomo `ipcidr/`, Surge `surge/`, and dae-rs native).
pub fn parse_ip_list(text: &str) -> Result<Vec<IpNet>, ListError> {
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // mihomo/clash & Surge IP-CIDR / IP-CIDR6 rule lines
        if let Some(rest) = strip_rule_keyword(line, "IP-CIDR") {
            let cidr = first_arg(rest);
            let net = parse_ip_line(cidr).ok_or_else(|| ListError::InvalidIp {
                line: idx + 1,
                value: line.to_string(),
            })?;
            out.push(net);
            continue;
        }
        if let Some(rest) = strip_rule_keyword(line, "IP-CIDR6") {
            let cidr = first_arg(rest);
            let net = parse_ip_line(cidr).ok_or_else(|| ListError::InvalidIp {
                line: idx + 1,
                value: line.to_string(),
            })?;
            out.push(net);
            continue;
        }

        // Non-IP rules (domains, GEOIP, MATCH/FINAL, ...) → skip
        if line_is_rule_keyword(line, NON_IP_RULE_PREFIXES) {
            continue;
        }

        // Bare CIDR / bare IP
        if let Some(net) = parse_ip_line(line) {
            out.push(net);
            continue;
        }

        // Unrecognized rule line (contains a keyword we don't know) → treat as corrupt
        if line.contains(',') {
            return Err(ListError::UnrecognizedRule {
                line: idx + 1,
                value: line.to_string(),
            });
        }
        return Err(ListError::InvalidIp {
            line: idx + 1,
            value: line.to_string(),
        });
    }
    Ok(out)
}

/// Parse a CIDR or a bare IP (IPv4 → /32, IPv6 → /128).
fn parse_ip_line(line: &str) -> Option<IpNet> {
    // Try parsing as CIDR first
    if let Ok(net) = line.parse::<IpNet>() {
        return Some(net);
    }
    // Otherwise treat it as a bare IP
    let addr: IpAddr = line.parse().ok()?;
    let bits = if addr.is_ipv4() { 32 } else { 128 };
    IpNet::new(addr, bits).ok()
}

/// Parse domain name list text into a list of domain name patterns
/// (mihomo/clash `clash-rules/`, Surge `surge-rules/`, and dae-rs native).
pub fn parse_domain_list(text: &str) -> Result<Vec<DomainPattern>, ListError> {
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // mihomo/clash & Surge domain rules (longest keyword matched first)
        if let Some(pat) = parse_rule_domain(line) {
            out.push(pat);
            continue;
        }

        // Non-domain rules (IP-CIDR, GEOIP, MATCH/FINAL, ...) → skip
        if line_is_rule_keyword(line, NON_DOMAIN_RULE_PREFIXES) {
            continue;
        }

        // dae-rs native prefixes (`full:` etc.) or bare domain
        if let Some(pat) = parse_domain_line(line) {
            out.push(pat);
            continue;
        }

        // A recognized native prefix (`full:` / `suffix:` / ...) with an empty value
        // is a malformed domain pattern, not an unrecognized rule.
        if is_native_domain_prefix(line) {
            return Err(ListError::InvalidDomain {
                line: idx + 1,
                value: line.to_string(),
            });
        }

        // Unrecognized rule line → treat as corrupt
        return Err(ListError::UnrecognizedRule {
            line: idx + 1,
            value: line.to_string(),
        });
    }
    Ok(out)
}

/// Whether a line starts with a dae-rs native domain prefix (`full:` / `domain:` /
/// `suffix:` / `keyword:` / `regex:`), case-insensitively.
fn is_native_domain_prefix(line: &str) -> bool {
    ["full:", "domain:", "suffix:", "keyword:", "regex:"]
        .iter()
        .any(|p| line.len() >= p.len() && line[..p.len()].eq_ignore_ascii_case(p))
}

/// Parse a mihomo/clash & Surge domain rule line (`DOMAIN,xxx` etc.).
fn parse_rule_domain(line: &str) -> Option<DomainPattern> {
    // Order matters: `DOMAIN-SUFFIX` / `DOMAIN-KEYWORD` / `DOMAIN-REGEX` must be
    // tried before the generic `DOMAIN`.
    for (keyword, pattern_type) in [
        ("DOMAIN-SUFFIX", DomainPatternType::Suffix),
        ("DOMAIN-KEYWORD", DomainPatternType::Keyword),
        ("DOMAIN-REGEX", DomainPatternType::Regex),
        ("DOMAIN", DomainPatternType::Full),
    ] {
        if let Some(rest) = strip_rule_keyword(line, keyword) {
            let value = first_arg(rest);
            if value.is_empty() {
                return None;
            }
            return Some(DomainPattern {
                pattern_type,
                value: value.to_string(),
            });
        }
    }
    None
}

/// Parse a dae-rs native domain line (`full:` / `domain:` / `suffix:` / `keyword:` /
/// `regex:` prefix, or a bare domain → Suffix).
fn parse_domain_line(line: &str) -> Option<DomainPattern> {
    // Prefix matching (case-insensitive)
    for (prefix, ty) in [
        ("full:", DomainPatternType::Full),
        ("domain:", DomainPatternType::Domain),
        ("suffix:", DomainPatternType::Suffix),
        ("keyword:", DomainPatternType::Keyword),
        ("regex:", DomainPatternType::Regex),
    ] {
        if line.len() >= prefix.len() && line[..prefix.len()].eq_ignore_ascii_case(prefix) {
            let value = line[prefix.len()..].trim();
            if value.is_empty() {
                return None;
            }
            return Some(DomainPattern { pattern_type: ty, value: value.to_string() });
        }
    }
    // No prefix → Plain (suffix including itself)
    if line.is_empty() {
        return None;
    }
    Some(DomainPattern { pattern_type: DomainPatternType::Suffix, value: line.to_string() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ruleset::types::DomainPatternType;

    #[test]
    fn test_parse_ip_list() {
        let text = "# comment\n1.1.1.0/24\n\n2.2.2.2\n10.0.0.0/8\n# another\n";
        let nets = parse_ip_list(text).unwrap();
        assert_eq!(nets.len(), 3);
        assert_eq!(nets[0].to_string(), "1.1.1.0/24");
        assert_eq!(nets[1].to_string(), "2.2.2.2/32");
        assert_eq!(nets[2].to_string(), "10.0.0.0/8");
    }

    #[test]
    fn test_parse_ip_list_ipv6() {
        let nets = parse_ip_list("::1\n2001:db8::/32\n").unwrap();
        assert_eq!(nets.len(), 2);
        assert_eq!(nets[0].to_string(), "::1/128");
        assert_eq!(nets[1].to_string(), "2001:db8::/32");
    }

    #[test]
    fn test_parse_ip_list_invalid() {
        let err = parse_ip_list("not-an-ip\n").unwrap_err();
        assert_eq!(err, ListError::InvalidIp { line: 1, value: "not-an-ip".into() });
    }

    #[test]
    fn test_parse_ip_list_mihomo_rule_format() {
        // mihomo `clash-rules/*.txt` style mixed list: bare CIDRs + IP-CIDR rules,
        // with non-IP rules (domains / GEOIP / MATCH) skipped.
        let text = "\
# mihomo/clash rule list
1.0.1.0/24
IP-CIDR,8.8.8.0/24,no-resolve
IP-CIDR6,2001:db8::/32
DOMAIN-SUFFIX,google.com
GEOIP,CN
MATCH,DIRECT
";
        let nets = parse_ip_list(text).unwrap();
        assert_eq!(nets.len(), 3);
        assert_eq!(nets[0].to_string(), "1.0.1.0/24");
        assert_eq!(nets[1].to_string(), "8.8.8.0/24");
        assert_eq!(nets[2].to_string(), "2001:db8::/32");
    }

    #[test]
    fn test_parse_ip_list_surge_rule_format() {
        // Surge `surge-rules/*.txt` style: bare CIDRs + IP-CIDR with options.
        let text = "\
# surge rule list
1.1.1.0/24
IP-CIDR,2.2.2.0/24,no-resolve
IP-CIDR6,::/0
FINAL,Direct
";
        let nets = parse_ip_list(text).unwrap();
        assert_eq!(nets.len(), 3);
        assert_eq!(nets[0].to_string(), "1.1.1.0/24");
        assert_eq!(nets[1].to_string(), "2.2.2.0/24");
        assert_eq!(nets[2].to_string(), "::/0");
    }

    #[test]
    fn test_parse_ip_list_unrecognized_rule() {
        let err = parse_ip_list("SOME-NEW-RULE,value\n").unwrap_err();
        assert!(matches!(err, ListError::UnrecognizedRule { line: 1, .. }));
    }

    #[test]
    fn test_parse_domain_list() {
        let text = "\
# comment
baidu.com
full:google.com
domain:example.com
suffix:foo.org
keyword:hello
regex:^x\\.y$
";
        let pats = parse_domain_list(text).unwrap();
        assert_eq!(pats.len(), 6);
        assert_eq!(pats[0].pattern_type, DomainPatternType::Suffix);
        assert_eq!(pats[0].value, "baidu.com");
        assert_eq!(pats[1].pattern_type, DomainPatternType::Full);
        assert_eq!(pats[1].value, "google.com");
        assert_eq!(pats[2].pattern_type, DomainPatternType::Domain);
        assert_eq!(pats[2].value, "example.com");
        assert_eq!(pats[3].pattern_type, DomainPatternType::Suffix);
        assert_eq!(pats[3].value, "foo.org");
        assert_eq!(pats[4].pattern_type, DomainPatternType::Keyword);
        assert_eq!(pats[4].value, "hello");
        assert_eq!(pats[5].pattern_type, DomainPatternType::Regex);
        assert_eq!(pats[5].value, r"^x\.y$");
    }

    #[test]
    fn test_parse_domain_list_mihomo_rule_format() {
        // mihomo `clash-rules/*.txt` style: DOMAIN-* rules + non-domain rules skipped.
        let text = "\
# mihomo/clash rule list
DOMAIN,exact.com
DOMAIN-SUFFIX,google.com
DOMAIN-KEYWORD,youtube
DOMAIN-REGEX,^ads\\.example\\.com$
IP-CIDR,8.8.8.0/24,no-resolve
GEOIP,CN
MATCH,DIRECT
";
        let pats = parse_domain_list(text).unwrap();
        assert_eq!(pats.len(), 4);
        assert_eq!(pats[0].pattern_type, DomainPatternType::Full);
        assert_eq!(pats[0].value, "exact.com");
        assert_eq!(pats[1].pattern_type, DomainPatternType::Suffix);
        assert_eq!(pats[1].value, "google.com");
        assert_eq!(pats[2].pattern_type, DomainPatternType::Keyword);
        assert_eq!(pats[2].value, "youtube");
        assert_eq!(pats[3].pattern_type, DomainPatternType::Regex);
        assert_eq!(pats[3].value, "^ads\\.example\\.com$");
    }

    #[test]
    fn test_parse_domain_list_surge_rule_format() {
        // Surge `surge-rules/*.txt` style: same DOMAIN-* rules, trailing options ignored.
        let text = "\
# surge rule list
DOMAIN-SUFFIX,google.com,force-remote-dns
DOMAIN,example.com
IP-CIDR,1.2.3.0/24,no-resolve
FINAL,Direct
";
        let pats = parse_domain_list(text).unwrap();
        assert_eq!(pats.len(), 2);
        assert_eq!(pats[0].pattern_type, DomainPatternType::Suffix);
        assert_eq!(pats[0].value, "google.com");
        assert_eq!(pats[1].pattern_type, DomainPatternType::Full);
        assert_eq!(pats[1].value, "example.com");
    }

    #[test]
    fn test_parse_domain_list_domain_prefix_beats_bare() {
        // `DOMAIN-SUFFIX` must be matched before the generic `DOMAIN` keyword.
        let pats = parse_domain_list("DOMAIN-SUFFIX,foo.com\n").unwrap();
        assert_eq!(pats[0].pattern_type, DomainPatternType::Suffix);
        assert_eq!(pats[0].value, "foo.com");
    }

    #[test]
    fn test_parse_domain_list_prefix_case_insensitive() {
        let pats = parse_domain_list("FULL:example.com\n").unwrap();
        assert_eq!(pats[0].pattern_type, DomainPatternType::Full);
        assert_eq!(pats[0].value, "example.com");
    }

    #[test]
    fn test_parse_domain_list_empty_prefix() {
        let err = parse_domain_list("full:\n").unwrap_err();
        assert!(matches!(err, ListError::InvalidDomain { line: 1, .. }));
    }

    #[test]
    fn test_parse_domain_list_trailing_spaces() {
        let pats = parse_domain_list("  baidu.com  \n").unwrap();
        assert_eq!(pats[0].value, "baidu.com");
    }
}
