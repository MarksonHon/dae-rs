//! Internationalization (i18n) support
//!
//! Provides Chinese and English message lookup for CLI and log output.
//! Language is selected via the `DAE_RS_LANG` environment variable.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Supported languages
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Lang {
    /// English
    En,
    /// Chinese (Simplified)
    Zh,
}

impl Default for Lang {
    fn default() -> Self {
        // Check DAE_RS_LANG env var, default to English
        match std::env::var("DAE_RS_LANG").as_deref() {
            Ok("zh" | "zh-CN" | "zh_SG" | "zh_CN") => Lang::Zh,
            _ => Lang::En,
        }
    }
}

/// A localized message that can be rendered in Chinese or English
#[derive(Debug, Clone)]
pub struct Msg {
    en: &'static str,
    zh: &'static str,
}

impl Msg {
    /// Create a new bilingual message pair
    pub const fn new(en: &'static str, zh: &'static str) -> Self {
        Msg { en, zh }
    }

    /// Render the message in the given language
    pub fn render(&self, lang: Lang) -> &'static str {
        match lang {
            Lang::En => self.en,
            Lang::Zh => self.zh,
        }
    }
}

impl fmt::Display for Msg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lang = Lang::default();
        write!(f, "{}", self.render(lang))
    }
}

// Re-export commonly used messages as constants
// This makes usage concise: `i18n::ERR_CONFIG_NOT_FOUND`
pub const ERR_CONFIG_NOT_FOUND: Msg = Msg::new(
    "Config file not found: {path}",
    "配置文件未找到: {path}",
);
pub const ERR_ROOT_REQUIRED: Msg = Msg::new(
    "dae-rs requires root privileges.\neBPF programs and network operations require: CAP_BPF, CAP_NET_ADMIN, CAP_SYS_ADMIN.\nPlease run with sudo or as root",
    "dae-rs 需要 root 权限。\neBPF 程序和网络操作需要: CAP_BPF, CAP_NET_ADMIN, CAP_SYS_ADMIN。\n请使用 sudo 或以 root 身份运行",
);
pub const STARTUP_BANNER: Msg = Msg::new(
    "dae-rs v{version} starting up",
    "dae-rs v{version} 正在启动",
);
pub const SHUTDOWN_MSG: Msg = Msg::new(
    "Shutdown signal received",
    "收到关闭信号",
);
pub const RUNNING_MSG: Msg = Msg::new(
    "dae-rs is running. Press Ctrl+C to stop.",
    "dae-rs 正在运行。按 Ctrl+C 停止。",
);
pub const LOG_LEVEL: Msg = Msg::new("log_level", "日志级别");
pub const CONFIG_LOADED: Msg = Msg::new(
    "Configuration loaded",
    "配置已加载",
);
pub const CONTROL_PLANE_STARTING: Msg = Msg::new(
    "Control plane starting",
    "控制面正在启动",
);
pub const CONTROL_PLANE_STARTED: Msg = Msg::new(
    "Control plane started successfully",
    "控制面启动成功",
);
pub const CONTROL_PLANE_STOPPING: Msg = Msg::new(
    "Control plane stopping",
    "控制面正在停止",
);
pub const CONTROL_PLANE_STOPPED: Msg = Msg::new(
    "Control plane stopped successfully",
    "控制面已停止",
);
pub const SHUTDOWN_COMPLETE: Msg = Msg::new(
    "dae-rs shutdown complete",
    "dae-rs 关闭完成",
);
pub const API_SERVER_STARTING: Msg = Msg::new(
    "Starting API server on {addr}",
    "API 服务器正在启动于 {addr}",
);
pub const API_SERVER_STOPPED: Msg = Msg::new(
    "API server stopped",
    "API 服务器已停止",
);
pub const CONFIG_PARSE_FAILED: Msg = Msg::new(
    "Failed to parse configuration",
    "配置解析失败",
);
pub const NETNS_CREATE_FAILED: Msg = Msg::new(
    "Failed to create network namespace",
    "网络命名空间创建失败",
);
pub const EBPF_LOAD_FAILED: Msg = Msg::new(
    "Failed to load eBPF program",
    "eBPF 程序加载失败",
);
pub const TC_ATTACH_FAILED: Msg = Msg::new(
    "Failed to attach TC programs",
    "TC 程序附着失败",
);
