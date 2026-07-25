//! 共享数据结构
//!
//! 本项目中共用的数据类型定义，用于跨模块（控制面、eBPF、协议层）通信。
//! 所有类型均派生 `Serialize`/`Deserialize`，支持序列化传输。

use serde::{Deserialize, Serialize};

/// 分流动作
///
/// 规则匹配后的执行动作，决定流量去向。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Action {
    /// 直连：放行走系统路由
    Direct,
    /// 代理：通过指定出站组转发
    Proxy(String),
}

/// 规则条目
///
/// 表示一条分流规则，由匹配条件和执行动作组成。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// 目的 IP 或 CIDR
    pub dip: Option<String>,
    /// 目的端口
    pub dport: Option<u16>,
    /// L4 协议类型
    pub l4proto: Option<L4Proto>,
    /// 匹配后的执行动作
    pub action: Action,
}

/// 网络端点
///
/// 表示一个 IP 地址和端口的组合。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Endpoint {
    /// IP 地址（IPv4 或 IPv6 字符串形式）
    pub ip: String,
    /// 端口号
    pub port: u16,
}

impl Endpoint {
    /// 创建新的端点
    pub fn new(ip: impl Into<String>, port: u16) -> Self {
        Self {
            ip: ip.into(),
            port,
        }
    }
}

/// L4 协议类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum L4Proto {
    /// TCP 协议
    Tcp,
    /// UDP 协议
    Udp,
}

impl L4Proto {
    /// 将协议类型转换为 eBPF map 中使用的数值表示
    pub fn to_u8(&self) -> u8 {
        match self {
            L4Proto::Tcp => 1,
            L4Proto::Udp => 2,
        }
    }

    /// 从 IP 协议号创建 L4Proto
    pub fn from_ip_protocol(protocol: u8) -> Option<Self> {
        match protocol {
            6 => Some(L4Proto::Tcp),
            17 => Some(L4Proto::Udp),
            _ => None,
        }
    }
}

/// 分流决策结果
///
/// eBPF 程序对每个数据包作出的分流决策。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProxyDecision {
    /// 直连
    Direct,
    /// 代理（包含出站组名）
    Proxy(String),
    /// 阻断（预留，第一阶段未实现）
    Block,
}

/// 连接四元组（用于 conntrack）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// 源 IP
    pub src_ip: [u8; 16],
    /// 目的 IP
    pub dst_ip: [u8; 16],
    /// 源端口
    pub src_port: u16,
    /// 目的端口
    pub dst_port: u16,
    /// 协议类型
    pub protocol: u8,
}

/// 配置版本信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigMeta {
    /// 配置版本号
    pub version: u32,
    /// 配置生成时间戳
    pub generated_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_l4proto_conversion() {
        assert_eq!(L4Proto::Tcp.to_u8(), 1);
        assert_eq!(L4Proto::Udp.to_u8(), 2);
        assert_eq!(L4Proto::from_ip_protocol(6), Some(L4Proto::Tcp));
        assert_eq!(L4Proto::from_ip_protocol(17), Some(L4Proto::Udp));
        assert_eq!(L4Proto::from_ip_protocol(1), None);
    }

    #[test]
    fn test_endpoint() {
        let ep = Endpoint::new("192.168.1.1", 1080);
        assert_eq!(ep.ip, "192.168.1.1");
        assert_eq!(ep.port, 1080);
    }

    #[test]
    fn test_action_serialization() {
        let direct = Action::Direct;
        let proxy = Action::Proxy("test_group".into());
        assert_eq!(serde_json::to_string(&direct).unwrap(), r#""Direct""#);
        assert_eq!(
            serde_json::to_string(&proxy).unwrap(),
            r#"{"Proxy":"test_group"}"#
        );
    }
}
