//! 文本Domain name / IP 列表解析（设计 §2.3）。
//!
//! - **IP 列表**：每行一条 CIDR（`a.b.c.d/nn`）或裸 IP（按 /32 或 /128 处理）；
//!   `#` 开头为注释，空行忽略。
//! - **Domain name列表**：每行一条，支持 `full:` / `domain:` / `suffix:` / `keyword:` /
//!   `regex:` 前缀（大小写不敏感）；无前缀默认按 [`DomainPatternType::Suffix`]
//!   （Plain，后缀含自身）处理。

use ipnet::IpNet;
use std::net::IpAddr;
use thiserror::Error;

use crate::ruleset::types::{DomainPattern, DomainPatternType};

/// 文本列表解析错误。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ListError {
    #[error("line {line}: invalid CIDR or IP: '{value}'")]
    InvalidIp { line: usize, value: String },
    #[error("line {line}: invalid domain pattern: '{value}'")]
    InvalidDomain { line: usize, value: String },
}

/// 解析 IP 列表文本为 CIDR 列表。
pub fn parse_ip_list(text: &str) -> Result<Vec<IpNet>, ListError> {
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let net = parse_ip_line(line).ok_or_else(|| ListError::InvalidIp {
            line: idx + 1,
            value: line.to_string(),
        })?;
        out.push(net);
    }
    Ok(out)
}

fn parse_ip_line(line: &str) -> Option<IpNet> {
    // 优先按 CIDR 解析
    if let Ok(net) = line.parse::<IpNet>() {
        return Some(net);
    }
    // 否则按裸 IP 处理（IPv4 → /32，IPv6 → /128）
    let addr: IpAddr = line.parse().ok()?;
    let bits = if addr.is_ipv4() { 32 } else { 128 };
    IpNet::new(addr, bits).ok()
}

/// 解析Domain name列表文本为Domain name模式列表。
pub fn parse_domain_list(text: &str) -> Result<Vec<DomainPattern>, ListError> {
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let pat = parse_domain_line(line).ok_or_else(|| ListError::InvalidDomain {
            line: idx + 1,
            value: line.to_string(),
        })?;
        out.push(pat);
    }
    Ok(out)
}

fn parse_domain_line(line: &str) -> Option<DomainPattern> {
    // 前缀匹配（大小写不敏感）
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
    // 无前缀 → Plain（后缀含自身）
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
