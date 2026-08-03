//! v2ray `.dat` protobuf 轻量解码器（手写，零 protobuf 依赖）。
//!
//! 依据设计 §2.2 / §13-3：
//!
//! - `geoip.dat`：顶层 `GeoIPList { repeated GeoIP entry = 1 }`，
//!   `GeoIP { string country_code = 1, repeated CIDR cidr = 2, bool reverse_match = 3 }`，
//!   `CIDR { bytes ip = 1, uint32 prefix = 2 }`。
//! - `geosite.dat`：顶层 `GeoSiteList { repeated GeoSite entry = 1 }`，
//!   `GeoSite { string country_code = 1, repeated Domain domain = 2 }`，
//!   `Domain { enum DomainType type = 1, string value = 2, repeated Attribute attribute = 3 }`。
//!
//! 文件为未压缩 protobuf 序列化。本模块手写 varint / wire type / length-delimited /
//! 嵌入式消息解析；对截断或畸形数据一律返回错误（[`DecodeError`]）而非 panic。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use thiserror::Error;

use crate::ruleset::types::{DomainPattern, DomainPatternType, RuleSetData};

/// `.dat` 解码错误。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("protobuf data truncated")]
    Truncated,
    #[error("varint overflow")]
    VarintOverflow,
    #[error("unsupported wire type {0}")]
    UnsupportedWireType(u8),
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("invalid IP byte length {0} (expected 4 or 16)")]
    InvalidIpLen(usize),
    #[error("prefix {0} exceeds address bit length")]
    InvalidPrefix(u32),
    #[error("invalid CIDR")]
    InvalidCidr,
    #[error("invalid utf8: {0}")]
    InvalidUtf8(String),
    #[error("dataset is empty")]
    Empty,
    #[error("domain value is empty")]
    EmptyDomain,
    #[error("unknown domain type {0}")]
    UnknownDomainType(u64),
}

/// 轻量 protobuf wire-format 解码器。
struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn read_varint(&mut self) -> Result<u64, DecodeError> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            if self.pos >= self.buf.len() {
                return Err(DecodeError::Truncated);
            }
            let byte = self.buf[self.pos];
            self.pos += 1;
            result |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift >= 64 {
                return Err(DecodeError::VarintOverflow);
            }
        }
    }

    fn skip(&mut self, n: usize) -> Result<(), DecodeError> {
        if self.pos + n > self.buf.len() {
            return Err(DecodeError::Truncated);
        }
        self.pos += n;
        Ok(())
    }

    /// 读取 length-delimited 字段载荷切片（wire type 2）。
    fn read_bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = self.read_varint()? as usize;
        if self.pos + len > self.buf.len() {
            return Err(DecodeError::Truncated);
        }
        let slice = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    /// 读取下一个字段 tag，返回 `(field_number, wire_type)`；无更多字段返回 `None`。
    fn read_tag(&mut self) -> Result<Option<(u64, u8)>, DecodeError> {
        if self.is_empty() {
            return Ok(None);
        }
        let tag = self.read_varint()?;
        Ok(Some((tag >> 3, (tag & 0x07) as u8)))
    }

    /// 跳过未知字段（前向兼容：忽略未识别的字段）。
    fn skip_field(&mut self, wire: u8) -> Result<(), DecodeError> {
        match wire {
            0 => {
                self.read_varint()?;
                Ok(())
            }
            1 => self.skip(8),
            2 => {
                let len = self.read_varint()? as usize;
                self.skip(len)
            }
            5 => self.skip(4),
            _ => Err(DecodeError::UnsupportedWireType(wire)),
        }
    }
}

/// 解码 `geoip.dat`（`GeoIPList`）为 [`RuleSetData::GeoIp`]。
///
/// `country_code` 统一转为小写存储（设计 §2.2：匹配时大小写不敏感）。
pub fn decode_geoip_list(data: &[u8]) -> Result<RuleSetData, DecodeError> {
    let mut entries: HashMap<String, Vec<IpNet>> = HashMap::new();
    let mut dec = Decoder::new(data);
    while let Some((field, wire)) = dec.read_tag()? {
        if field == 1 && wire == 2 {
            let entry = dec.read_bytes()?;
            let (code, cidrs) = decode_geoip_entry(entry)?;
            if !code.is_empty() {
                entries.entry(code).or_default().extend(cidrs);
            }
        } else {
            dec.skip_field(wire)?;
        }
    }
    if entries.is_empty() {
        return Err(DecodeError::Empty);
    }
    Ok(RuleSetData::GeoIp { entries })
}

/// 解码单个 `GeoIP` 消息，返回 `(country_code 小写, cidr 列表)`。
fn decode_geoip_entry(data: &[u8]) -> Result<(String, Vec<IpNet>), DecodeError> {
    let mut code = String::new();
    let mut cidrs = Vec::new();
    let mut dec = Decoder::new(data);
    while let Some((field, wire)) = dec.read_tag()? {
        match (field, wire) {
            (1, 2) => {
                let raw = dec.read_bytes()?;
                code = String::from_utf8(raw.to_vec())
                    .map_err(|e| DecodeError::InvalidUtf8(e.to_string()))?;
            }
            (2, 2) => cidrs.push(decode_cidr(dec.read_bytes()?)?),
            (3, 0) => {
                // reverse_match（v2ray 中通常为 false，本层仅消费字段、忽略语义）
                let _ = dec.read_varint()?;
            }
            _ => dec.skip_field(wire)?,
        }
    }
    Ok((code.to_ascii_lowercase(), cidrs))
}

/// 解码单个 `CIDR` 消息为 [`IpNet`]。
fn decode_cidr(data: &[u8]) -> Result<IpNet, DecodeError> {
    let mut ip: Option<Vec<u8>> = None;
    let mut prefix: u32 = 0;
    let mut dec = Decoder::new(data);
    while let Some((field, wire)) = dec.read_tag()? {
        match (field, wire) {
            (1, 2) => ip = Some(dec.read_bytes()?.to_vec()),
            (2, 0) => prefix = dec.read_varint()? as u32,
            _ => dec.skip_field(wire)?,
        }
    }
    let ip = ip.ok_or(DecodeError::MissingField("cidr.ip"))?;
    let addr: IpAddr = match ip.len() {
        4 => IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
        16 => {
            let octets: [u8; 16] =
                ip.try_into().map_err(|_| DecodeError::InvalidIpLen(16))?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        n => return Err(DecodeError::InvalidIpLen(n)),
    };
    let max_bits = if addr.is_ipv4() { 32 } else { 128 };
    if prefix > max_bits {
        return Err(DecodeError::InvalidPrefix(prefix));
    }
    IpNet::new(addr, prefix as u8).map_err(|_| DecodeError::InvalidCidr)
}

/// 解码 `geosite.dat`（`GeoSiteList`）为 [`RuleSetData::GeoSite`]。
///
/// `country_code`（分类名）统一转为小写存储；`@attribute` 二级分类
/// （阶段 5 可选）本层忽略（字段 3 被跳过）。
pub fn decode_geosite_list(data: &[u8]) -> Result<RuleSetData, DecodeError> {
    let mut entries: HashMap<String, Vec<DomainPattern>> = HashMap::new();
    let mut dec = Decoder::new(data);
    while let Some((field, wire)) = dec.read_tag()? {
        if field == 1 && wire == 2 {
            let entry = dec.read_bytes()?;
            let (code, domains) = decode_geosite_entry(entry)?;
            if !code.is_empty() {
                entries.entry(code).or_default().extend(domains);
            }
        } else {
            dec.skip_field(wire)?;
        }
    }
    if entries.is_empty() {
        return Err(DecodeError::Empty);
    }
    Ok(RuleSetData::GeoSite { entries })
}

/// 解码单个 `GeoSite` 消息，返回 `(country_code 小写, domain 模式列表)`。
fn decode_geosite_entry(data: &[u8]) -> Result<(String, Vec<DomainPattern>), DecodeError> {
    let mut code = String::new();
    let mut domains = Vec::new();
    let mut dec = Decoder::new(data);
    while let Some((field, wire)) = dec.read_tag()? {
        match (field, wire) {
            (1, 2) => {
                let raw = dec.read_bytes()?;
                code = String::from_utf8(raw.to_vec())
                    .map_err(|e| DecodeError::InvalidUtf8(e.to_string()))?;
            }
            (2, 2) => domains.push(decode_domain(dec.read_bytes()?)?),
            _ => dec.skip_field(wire)?,
        }
    }
    Ok((code.to_ascii_lowercase(), domains))
}

/// 解码单个 `Domain` 消息为 [`DomainPattern`]。
///
/// `DomainType` 映射：Plain=0→Suffix、Regex=1→Regex、Domain=2→Domain、Full=3→Full。
/// `attribute`（字段 3）被跳过。
fn decode_domain(data: &[u8]) -> Result<DomainPattern, DecodeError> {
    let mut domain_type: u64 = 0;
    let mut value = String::new();
    let mut dec = Decoder::new(data);
    while let Some((field, wire)) = dec.read_tag()? {
        match (field, wire) {
            (1, 0) => domain_type = dec.read_varint()?,
            (2, 2) => {
                let raw = dec.read_bytes()?;
                value = String::from_utf8(raw.to_vec())
                    .map_err(|e| DecodeError::InvalidUtf8(e.to_string()))?;
            }
            _ => dec.skip_field(wire)?,
        }
    }
    if value.is_empty() {
        return Err(DecodeError::EmptyDomain);
    }
    let pattern_type = match domain_type {
        0 => DomainPatternType::Suffix,
        1 => DomainPatternType::Regex,
        2 => DomainPatternType::Domain,
        3 => DomainPatternType::Full,
        other => return Err(DecodeError::UnknownDomainType(other)),
    };
    Ok(DomainPattern { pattern_type, value })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ruleset::types::DomainPatternType;

    // ── protobuf 编码辅助（测试用；真实样本：Loyalsoldier/v2ray-rules-dat）──

    fn varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
        out
    }

    fn tag(field: u64, wire: u8) -> Vec<u8> {
        varint((field << 3) | u64::from(wire))
    }

    fn varint_field(field: u64, v: u64) -> Vec<u8> {
        let mut out = tag(field, 0);
        out.extend(varint(v));
        out
    }

    fn bytes_field(field: u64, data: &[u8]) -> Vec<u8> {
        let mut out = tag(field, 2);
        out.extend(varint(data.len() as u64));
        out.extend_from_slice(data);
        out
    }

    fn string_field(field: u64, s: &str) -> Vec<u8> {
        bytes_field(field, s.as_bytes())
    }

    fn encode_cidr(ip: &[u8], prefix: u32) -> Vec<u8> {
        let mut out = bytes_field(1, ip);
        out.extend(varint_field(2, u64::from(prefix)));
        out
    }

    fn encode_geoip_entry(code: &str, cidrs: &[Vec<u8>], reverse: bool) -> Vec<u8> {
        let mut out = string_field(1, code);
        for c in cidrs {
            out.extend(bytes_field(2, c));
        }
        if reverse {
            out.extend(varint_field(3, 1));
        }
        out
    }

    fn encode_geoip_list(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for e in entries {
            out.extend(bytes_field(1, e));
        }
        out
    }

    fn encode_domain(ty: u64, value: &str) -> Vec<u8> {
        let mut out = varint_field(1, ty);
        out.extend(string_field(2, value));
        out
    }

    fn encode_geosite_entry(code: &str, domains: &[Vec<u8>]) -> Vec<u8> {
        let mut out = string_field(1, code);
        for d in domains {
            out.extend(bytes_field(2, d));
        }
        out
    }

    fn encode_geosite_list(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for e in entries {
            out.extend(bytes_field(1, e));
        }
        out
    }

    // ── geoip ──

    #[test]
    fn test_decode_geoip_basic() {
        let data = encode_geoip_list(&[
            encode_geoip_entry(
                "CN",
                &[encode_cidr(&[8, 8, 8, 8], 32), encode_cidr(&[1, 1, 1, 0], 24)],
                true,
            ),
            encode_geoip_entry("US", &[encode_cidr(&[9, 9, 9, 9], 32)], false),
        ]);
        let RuleSetData::GeoIp { entries } = decode_geoip_list(&data).unwrap() else {
            panic!("expected GeoIp");
        };
        assert_eq!(entries.len(), 2);
        // country_code 统一小写
        let cn = &entries["cn"];
        assert_eq!(cn.len(), 2);
        assert_eq!(cn[0].to_string(), "8.8.8.8/32");
        assert_eq!(cn[1].to_string(), "1.1.1.0/24");
        let us = &entries["us"];
        assert_eq!(us[0].to_string(), "9.9.9.9/32");
    }

    #[test]
    fn test_decode_geoip_ipv6() {
        let data = encode_geoip_list(&[encode_geoip_entry(
            "v6",
            &[encode_cidr(
                &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                32,
            )],
            false,
        )]);
        let RuleSetData::GeoIp { entries } = decode_geoip_list(&data).unwrap() else {
            panic!("expected GeoIp");
        };
        assert_eq!(entries["v6"][0].to_string(), "2001:db8::/32");
    }

    #[test]
    fn test_decode_geoip_truncated() {
        let mut data = encode_geoip_list(&[encode_geoip_entry(
            "CN",
            &[encode_cidr(&[8, 8, 8, 8], 32)],
            false,
        )]);
        data.truncate(data.len() / 2);
        assert_eq!(decode_geoip_list(&data).unwrap_err(), DecodeError::Truncated);
    }

    #[test]
    fn test_decode_geoip_invalid_ip_len() {
        let data = encode_geoip_list(&[encode_geoip_entry(
            "CN",
            &[encode_cidr(&[1, 2, 3], 24)],
            false,
        )]);
        assert_eq!(decode_geoip_list(&data).unwrap_err(), DecodeError::InvalidIpLen(3));
    }

    #[test]
    fn test_decode_geoip_invalid_prefix() {
        let data = encode_geoip_list(&[encode_geoip_entry(
            "CN",
            &[encode_cidr(&[1, 2, 3, 4], 40)],
            false,
        )]);
        assert_eq!(decode_geoip_list(&data).unwrap_err(), DecodeError::InvalidPrefix(40));
    }

    #[test]
    fn test_decode_geoip_empty() {
        assert_eq!(decode_geoip_list(&[]).unwrap_err(), DecodeError::Empty);
    }

    #[test]
    fn test_decode_geoip_unknown_wire_type() {
        // 构造一个 wire type 3（StartGroup）的未知字段 → UnsupportedWireType
        let mut data = Vec::new();
        data.extend(tag(9, 3));
        data.extend(varint(0));
        assert_eq!(decode_geoip_list(&data).unwrap_err(), DecodeError::UnsupportedWireType(3));
    }

    // ── geosite ──

    #[test]
    fn test_decode_geosite_basic() {
        let domains = vec![
            encode_domain(0, "baidu.com"),   // Plain → Suffix
            encode_domain(3, "google.com"),  // Full → Full
            encode_domain(1, r"^a\.b$"),     // Regex → Regex
            encode_domain(2, "example.com"), // Domain → Domain
        ];
        let data = encode_geosite_list(&[encode_geosite_entry("cn", &domains)]);
        let RuleSetData::GeoSite { entries } = decode_geosite_list(&data).unwrap() else {
            panic!("expected GeoSite");
        };
        let cn = &entries["cn"];
        assert_eq!(cn.len(), 4);
        assert_eq!(cn[0].pattern_type, DomainPatternType::Suffix);
        assert_eq!(cn[0].value, "baidu.com");
        assert_eq!(cn[1].pattern_type, DomainPatternType::Full);
        assert_eq!(cn[1].value, "google.com");
        assert_eq!(cn[2].pattern_type, DomainPatternType::Regex);
        assert_eq!(cn[2].value, r"^a\.b$");
        assert_eq!(cn[3].pattern_type, DomainPatternType::Domain);
        assert_eq!(cn[3].value, "example.com");
    }

    #[test]
    fn test_decode_geosite_unknown_domain_type() {
        let data = encode_geosite_list(&[encode_geosite_entry("cn", &[encode_domain(9, "x")])]);
        assert_eq!(decode_geosite_list(&data).unwrap_err(), DecodeError::UnknownDomainType(9));
    }

    #[test]
    fn test_decode_geosite_invalid_utf8() {
        // value 字段使用非法 utf8 字节
        let mut domain = varint_field(1, 0);
        domain.extend(bytes_field(2, &[0xff, 0xfe]));
        let data = encode_geosite_list(&[encode_geosite_entry("cn", &[domain])]);
        assert!(matches!(decode_geosite_list(&data), Err(DecodeError::InvalidUtf8(_))));
    }
}
