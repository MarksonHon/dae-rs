//! 匿名网络命名空间 + veth pair 管理
//!
//! 本模块负责创建和管理匿名网络命名空间及 veth 对，用于将代理流量
//! 从宿主命名空间导入到代理命名空间进行处理。
//!
//! ## 架构
//!
//! ```text
//! ┌──────────────────────────────────────────┐
//! │          宿主网络命名空间                  │
//! │                                          │
//! │  ┌─────────────┐      ┌──────────────┐   │
//! │  │   eth0      │      │   dae0peer   │   │
//! │  │  (外网)     │      │ 169.254.100.2│   │
//! │  └─────────────┘      └──────┬───────┘   │
//! │                               │           │
//! ├───────────────────────────────┼───────────┤
//! │           veth pair           │           │
//! ├───────────────────────────────┼───────────┤
//! │                               │           │
//! │  ┌────────────────────────┐ ┌─┴────────┐  │
//! │  │       dae0             │ │  lo       │  │
//! │  │  169.254.100.1/30      │ │  (loop)   │  │
//! │  └────────────────────────┘ └──────────┘  │
//! │        代理网络命名空间                     │
//! └──────────────────────────────────────────┘
//! ```
//!
//! ## MVP 策略
//!
//! 本模块 MVP 阶段使用 `std::process::Command` 调用 iproute2 命令，
//! 而非直接使用 netlink syscall。原因：
//! - iproute2 命令更稳定、更易调试
//! - nix crate 对 netlink 的封装可能不够完整
//! - 后续可逐步替换为原生 netlink 实现

use crate::Config;
use anyhow::{Context, Result};
use std::fs::File;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::process::{Child, Command};
use std::os::unix::process::CommandExt;
use nix::sched::{self, CloneFlags};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use tracing::{info, warn, error};

// ============================================================================
// 错误类型
// ============================================================================

/// 网络命名空间管理错误
#[derive(Debug, thiserror::Error)]
pub enum NetnsError {
    /// 命名空间已创建，操作冲突
    #[error("Network namespace already created")]
    AlreadyCreated,
    /// 命名空间未创建，操作无效
    #[error("Network namespace not created")]
    NotCreated,
    /// 子进程相关错误
    #[error("Child process error: {0}")]
    ChildProcess(String),
    /// iproute2 命令执行失败
    #[error("ip command failed: {cmd}\nstderr: {stderr}")]
    IpCommand {
        /// 执行的命令
        cmd: String,
        /// 标准错误输出
        stderr: String,
    },
}

// ============================================================================
// 常量
// ============================================================================

/// 当前进程的 netns 路径
const PROC_SELF_NETNS: &str = "/proc/self/ns/net";

// ============================================================================
// NetnsManager
// ============================================================================

/// 网络命名空间管理器
///
/// 管理匿名网络命名空间的生命周期，包括：
/// - 保存宿主 netns fd（持有引用防止 GC 回收）
/// - 使用 `unshare(CLONE_NEWNET)` 创建匿名命名空间
/// - 创建并配置 veth pair
/// - 配置策略路由将代理流量导入代理命名空间
/// - 在代理命名空间中启动子进程
/// - 销毁时完整清理所有资源
///
/// # 示例
///
/// ```no_run
/// use control::netns::NetnsManager;
/// use control::Config;
///
/// let config = Config::default();
/// let mut mgr = NetnsManager::new(&config);
/// mgr.create().expect("Failed to create netns");
/// // ... 使用代理命名空间 ...
/// mgr.destroy().expect("Failed to destroy netns");
/// ```
pub struct NetnsManager {
    /// veth 宿主侧接口名（默认 dae0）
    host_if: String,
    /// veth 代理侧接口名（默认 dae0peer）
    peer_if: String,
    /// 宿主侧地址（CIDR，默认 169.254.100.1/30）
    host_addr: String,
    /// 代理侧地址（CIDR，默认 169.254.100.2/30）
    peer_addr: String,
    /// MTU（默认 1500）
    mtu: u32,
    /// 策略路由表 ID（默认 20230）
    route_table: u32,
    /// 代理 mark 值
    proxy_mark: u32,
    /// 代理 mark 掩码
    proxy_mask: u32,
    /// 宿主侧 netns fd（持有引用防止 GC）
    host_ns_fd: Option<OwnedFd>,
    /// 代理命名空间 fd（在 unshare 后、setns 回宿主前保存）
    proxy_ns_fd: Option<OwnedFd>,
    /// 子进程 PID
    child_pid: Option<u32>,
}

impl NetnsManager {
    /// 从配置对象创建管理器
    ///
    /// 此时不会创建命名空间，仅保存配置参数。
    /// 调用 [`create()`](NetnsManager::create) 后才实际创建。
    pub fn new(config: &Config) -> Self {
        Self {
            host_if: config.veth_host.clone(),
            peer_if: config.veth_peer.clone(),
            host_addr: config.host_addr.clone(),
            peer_addr: config.peer_addr.clone(),
            mtu: config.mtu,
            route_table: config.route_table,
            proxy_mark: config.fwmark_proxy,
            proxy_mask: config.fwmark_mask,
            host_ns_fd: None,
            proxy_ns_fd: None,
            child_pid: None,
        }
    }

    /// 创建匿名网络命名空间和 veth pair
    ///
    /// 完整流程：
    /// 1. **保存宿主 netns fd**：打开 `/proc/self/ns/net` 并持有引用
    /// 2. **`unshare(CLONE_NEWNET)`**：创建新网络命名空间（当前进程进入新 ns）
    /// 3. **在新命名空间内**：
    ///    - 创建 veth pair：`dae0 <-> dae0peer`
    ///    - 将 `dae0peer` 移动到宿主命名空间
    ///    - 设置 `dae0` 的 IP 地址、MTU，启用接口
    /// 4. **`setns` 回到宿主命名空间**：
    ///    - 设置 `dae0peer` 的 IP 地址、MTU，启用接口
    /// 5. **配置策略路由**：
    ///    - `ip rule add fwmark <proxy_mark>/<proxy_mask> table <route_table>`
    ///    - `ip route add local default dev lo table <route_table>`
    ///
    /// # 错误
    ///
    /// - 如果命名空间已创建，返回 [`NetnsError::AlreadyCreated`]
    /// - 任何 iproute2 命令失败都会返回 [`NetnsError::IpCommand`]
    pub fn create(&mut self) -> Result<()> {
        if self.host_ns_fd.is_some() {
            return Err(NetnsError::AlreadyCreated.into());
        }

        info!(
            host_if = %self.host_if,
            peer_if = %self.peer_if,
            host_addr = %self.host_addr,
            peer_addr = %self.peer_addr,
            mtu = %self.mtu,
            route_table = %self.route_table,
            "Creating anonymous network namespace and veth pair"
        );

        // ---- 步骤 1：保存宿主 netns fd ----
        let host_ns_file = File::open(PROC_SELF_NETNS)
            .context("Failed to open /proc/self/ns/net to save host netns fd")?;
        let host_ns_fd = OwnedFd::from(host_ns_file);
        info!("Saved host netns fd: {}", host_ns_fd.as_raw_fd());

        // ---- 步骤 2：创建新网络命名空间 ----
        sched::unshare(CloneFlags::CLONE_NEWNET)
            .context("Failed to create new network namespace via unshare(CLONE_NEWNET)")?;
        info!("Created new anonymous network namespace");

        // ---- 步骤 3：在新命名空间内操作 ----
        // 此时当前进程已在新 netns 中

        // 3a. 创建 veth pair
        self.run_ip(&[
            "link", "add", &self.host_if, "type", "veth", "peer", "name", &self.peer_if,
        ])
        .context("Failed to create veth pair")?;
        info!("Created veth pair: {} <-> {}", self.host_if, self.peer_if);

        // 3b. 将 peer_if 移动到宿主命名空间
        // 使用 init（PID 1）的 netns 作为宿主命名空间的引用
        // 注意：这要求宿主进程有权限访问 /proc/1/ns/net
        self.run_ip(&[
            "link", "set", &self.peer_if, "netns", "1",
        ])
        .context("Failed to move peer interface to host netns")?;
        info!("Moved {} to host network namespace", self.peer_if);

        // 3c. 配置 host_if
        self.run_ip(&["addr", "add", &self.host_addr, "dev", &self.host_if])
            .context("Failed to set host interface address")?;
        self.run_ip(&["link", "set", "dev", &self.host_if, "mtu", &self.mtu.to_string()])
            .context("Failed to set host interface MTU")?;
        self.run_ip(&["link", "set", &self.host_if, "up"])
            .context("Failed to bring up host interface")?;
        info!(
            "Configured {}: addr={}, mtu={}, up",
            self.host_if, self.host_addr, self.mtu
        );

        // ---- 保存代理 netns fd（在切换回宿主前） ----
        // 打开 /proc/self/ns/net 保存当前（代理）命名空间的 fd
        // 以便后续在代理命名空间中启动 TProxy 等进程
        let proxy_ns_file = File::open(PROC_SELF_NETNS)
            .context("Failed to open /proc/self/ns/net to save proxy netns fd")?;
        let proxy_ns_fd = OwnedFd::from(proxy_ns_file);
        info!("Saved proxy netns fd: {}", proxy_ns_fd.as_raw_fd());

        // ---- 步骤 4：回到宿主命名空间 ----
        sched::setns(&host_ns_fd, CloneFlags::CLONE_NEWNET)
            .context("Failed to switch back to host network namespace")?;
        info!("Switched back to host network namespace");

        // ---- 步骤 5：在宿主命名空间中配置 peer_if ----
        self.run_ip(&["addr", "add", &self.peer_addr, "dev", &self.peer_if])
            .context("Failed to set peer interface address")?;
        self.run_ip(&["link", "set", "dev", &self.peer_if, "mtu", &self.mtu.to_string()])
            .context("Failed to set peer interface MTU")?;
        self.run_ip(&["link", "set", &self.peer_if, "up"])
            .context("Failed to bring up peer interface")?;
        info!(
            "Configured {}: addr={}, mtu={}, up",
            self.peer_if, self.peer_addr, self.mtu
        );

        // ---- 步骤 6：配置策略路由 ----
        // 添加策略路由规则：将带有 fwmark 的流量路由到指定路由表
        self.run_ip(&[
            "rule",
            "add",
            "fwmark",
            &format!("{:#x}/{:#x}", self.proxy_mark, self.proxy_mask),
            "table",
            &self.route_table.to_string(),
        ])
        .context("Failed to add policy routing rule")?;
        info!(
            "Added policy rule: fwmark {:#x}/{:#x} table {}",
            self.proxy_mark, self.proxy_mask, self.route_table
        );

        // 添加路由表条目：将路由表中的所有流量指向本地回环
        self.run_ip(&[
            "route",
            "add",
            "local",
            "default",
            "dev",
            "lo",
            "table",
            &self.route_table.to_string(),
        ])
        .context("Failed to add route to policy routing table")?;
        info!(
            "Added route: local default dev lo table {}",
            self.route_table
        );

        // ---- 保存 host ns fd 和 proxy ns fd ----
        self.host_ns_fd = Some(host_ns_fd);
        self.proxy_ns_fd = Some(proxy_ns_fd);

        info!("Network namespace and veth pair created successfully");
        Ok(())
    }

    /// 销毁网络命名空间和 veth pair
    ///
    /// 完整清理流程：
    /// 1. 终止子进程（先 SIGTERM 优雅终止，1 秒后 SIGKILL 强制终止）
    /// 2. 删除策略路由规则和路由表条目
    /// 3. 删除 veth pair（删除宿主侧的 peer_if 即可删除整个 pair）
    /// 4. 关闭持有宿主 netns 的 fd
    ///
    /// # 错误处理策略
    ///
    /// 即使中间步骤失败，也继续尝试后续清理步骤。
    /// 确保尽可能多的资源被释放。
    pub fn destroy(&mut self) -> Result<()> {
        info!("Destroying network namespace and veth pair");

        let mut has_error = false;

        // ---- 步骤 1：终止子进程 ----
        if let Some(pid) = self.child_pid.take() {
            if let Err(e) = self.kill_child_process(pid) {
                warn!("Failed to kill child process {}: {}", pid, e);
                has_error = true;
            }
        }

        // ---- 步骤 2：删除策略路由规则和路由表条目 ----
        // 先删除路由表条目
        let delete_route_result = self.run_ip(&[
            "route",
            "del",
            "local",
            "default",
            "dev",
            "lo",
            "table",
            &self.route_table.to_string(),
        ]);
        if let Err(e) = delete_route_result {
            warn!("Failed to delete policy route: {}", e);
            // 路由表条目可能不存在（如果之前未配置成功），不视为严重错误
        }

        // 删除策略路由规则
        let delete_rule_result = self.run_ip(&[
            "rule",
            "del",
            "fwmark",
            &format!("{:#x}/{:#x}", self.proxy_mark, self.proxy_mask),
            "table",
            &self.route_table.to_string(),
        ]);
        if let Err(e) = delete_rule_result {
            warn!("Failed to delete policy routing rule: {}", e);
            // 规则可能不存在，不视为严重错误
        }

        // ---- 步骤 3：删除 veth pair ----
        // 删除宿主侧的 peer_if（会自动删除 pair 的另一端）
        // 注意：我们现在在宿主命名空间中，所以直接删除 peer_if
        let delete_veth_result = self.run_ip(&["link", "delete", &self.peer_if]);
        if let Err(e) = delete_veth_result {
            // 也尝试删除 host_if（可能 peer_if 已被删除）
            warn!(
                "Failed to delete veth {} (trying {}): {}",
                self.peer_if, self.host_if, e
            );
            if let Err(e2) = self.run_ip(&["link", "delete", &self.host_if]) {
                warn!("Failed to delete veth {}: {}", self.host_if, e2);
                has_error = true;
            }
        } else {
            info!("Deleted veth pair (via {})", self.peer_if);
        }

        // ---- 步骤 4：关闭 netns fd ----
        self.host_ns_fd.take();
        info!("Closed host netns fd");
        self.proxy_ns_fd.take();
        info!("Closed proxy netns fd");

        // ---- 重置子进程 PID ----
        self.child_pid = None;

        if has_error {
            warn!("Network namespace destruction completed with some errors");
        } else {
            info!("Network namespace and veth pair destroyed successfully");
        }

        Ok(())
    }

    /// 在代理命名空间中启动子进程
    ///
    /// 此方法会 fork 一个子进程，子进程进入代理网络命名空间后：
    /// 1. 设置 `PR_SET_PDEATHSIG(SIGTERM)` — 父进程退出时子进程自动收到 SIGTERM
    /// 2. 执行指定的代理程序
    ///
    /// # 参数
    ///
    /// * `program` — 要执行的程序路径
    /// * `args` — 程序参数列表
    ///
    /// # 返回
    ///
    /// 返回子进程的 `std::process::Child` 句柄。
    ///
    /// # 错误
    ///
    /// - 如果命名空间尚未创建，返回 [`NetnsError::NotCreated`]
    /// - 如果已经有子进程在运行，返回 [`NetnsError::ChildProcess`]
    pub fn spawn_proxy_process(&mut self, program: &str, args: &[&str]) -> Result<Child> {
        let proxy_ns_fd = self.proxy_ns_fd.as_ref()
            .ok_or(NetnsError::NotCreated)?;
        let _host_ns_fd = self.host_ns_fd.as_ref()
            .ok_or(NetnsError::NotCreated)?;

        if self.child_pid.is_some() {
            return Err(NetnsError::ChildProcess("A child process is already running".into()).into());
        }

        // 获取代理 netns 的 fd 路径，用于 nsenter
        let ns_fd_path = format!("/proc/self/fd/{}", proxy_ns_fd.as_raw_fd());

        info!(
            program = %program,
            args = ?args,
            ns_fd = %proxy_ns_fd.as_raw_fd(),
            "Spawning proxy process in proxy network namespace via nsenter"
        );

        // 使用 nsenter 在代理命名空间中启动子进程
        // pre_exec 闭包设置 PR_SET_PDEATHSIG，确保父进程退出时子进程收到 SIGTERM
        let child = unsafe {
            Command::new("nsenter")
                .arg("--net")
                .arg(&ns_fd_path)
                .arg(program)
                .args(args)
                .pre_exec(move || {
                    #[cfg(target_os = "linux")]
                    {
                        let rc = libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                        if rc != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }

                    Ok(())
                })
                .spawn()
                .context("Failed to spawn proxy process via nsenter")?
        };

        let pid = child.id();
        self.child_pid = Some(pid);
        info!("Proxy process started with PID: {} in proxy namespace", pid);

        Ok(child)
    }

    /// 获取当前管理的子进程 PID
    pub fn child_pid(&self) -> Option<u32> {
        self.child_pid
    }

    /// 获取宿主侧接口名
    pub fn host_if(&self) -> &str {
        &self.host_if
    }

    /// 获取代理侧接口名
    pub fn peer_if(&self) -> &str {
        &self.peer_if
    }

    /// 检查命名空间是否已创建
    pub fn is_created(&self) -> bool {
        self.host_ns_fd.is_some()
    }

    /// 获取代理命名空间的原始 fd
    ///
    /// 返回代理网络命名空间的文件描述符，可用于 `setns()` 系统调用
    /// 以将当前线程/进程切换到代理命名空间。
    ///
    /// # 返回
    ///
    /// * `Some(RawFd)` — 代理命名空间的 fd
    /// * `None` — 命名空间尚未创建
    pub fn get_proxy_ns_fd(&self) -> Option<std::os::unix::io::RawFd> {
        self.proxy_ns_fd.as_ref().map(|fd| fd.as_raw_fd())
    }

    /// 将当前进程加入代理网络命名空间
    ///
    /// 使用 `setns()` 系统调用将当前线程切换到代理网络命名空间。
    /// 这在启动 TProxy 监听器前调用，使 TProxy 在代理命名空间中监听。
    ///
    /// # 注意
    ///
    /// `setns()` 是线程级别的操作，在多线程程序中会影响调用线程。
    /// 在 tokio 异步运行时中，应使用 `spawn_blocking` 或在独立线程中调用。
    ///
    /// # 错误
    ///
    /// * 如果命名空间尚未创建，返回 [`NetnsError::NotCreated`]
    /// * 如果 `setns()` 系统调用失败，返回 IO 错误
    pub fn join_proxy_ns(&self) -> Result<()> {
        let fd = self.proxy_ns_fd.as_ref()
            .ok_or(NetnsError::NotCreated)?;
        sched::setns(fd, CloneFlags::CLONE_NEWNET)
            .context("Failed to switch to proxy network namespace via setns()")?;
        info!("Switched to proxy network namespace");
        Ok(())
    }

    /// 切换到宿主网络命名空间
    ///
    /// 与 [`join_proxy_ns()`](NetnsManager::join_proxy_ns) 对应，
    /// 将当前线程切换回宿主网络命名空间。
    ///
    /// # 错误
    ///
    /// * 如果命名空间尚未创建，返回 [`NetnsError::NotCreated`]
    /// * 如果 `setns()` 系统调用失败，返回 IO 错误
    pub fn join_host_ns(&self) -> Result<()> {
        let fd = self.host_ns_fd.as_ref()
            .ok_or(NetnsError::NotCreated)?;
        sched::setns(fd, CloneFlags::CLONE_NEWNET)
            .context("Failed to switch to host network namespace via setns()")?;
        info!("Switched to host network namespace");
        Ok(())
    }

    // ========================================================================
    // 辅助方法
    // ========================================================================

    /// 运行 iproute2 命令
    ///
    /// 封装 `ip` 命令调用，提供统一的错误处理和日志。
    ///
    /// # 参数
    ///
    /// * `args` — ip 命令的参数列表
    ///
    /// # 返回
    ///
    /// 成功返回命令的 stdout 字符串，失败返回 [`NetnsError::IpCommand`]
    fn run_ip(&self, args: &[&str]) -> Result<String> {
        let output = Command::new("ip")
            .args(args)
            .output()
            .with_context(|| format!("Failed to execute ip command with args: {:?}", args))?;

        let cmd_str = format!("ip {}", args.join(" "));

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            error!(cmd = %cmd_str, stderr = %stderr, "ip command failed");
            return Err(NetnsError::IpCommand {
                cmd: cmd_str,
                stderr,
            }.into());
        }

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        info!(cmd = %cmd_str, "ip command succeeded");
        Ok(stdout)
    }

    /// 终止子进程
    ///
    /// 先尝试 SIGTERM 优雅终止，等待 1 秒后如果进程仍在运行则 SIGKILL。
    ///
    /// # 参数
    ///
    /// * `pid` — 子进程 PID
    fn kill_child_process(&self, pid: u32) -> Result<()> {
        let pid = Pid::from_raw(pid as i32);

        info!("Terminating child process {}", pid);

        // 先尝试 SIGTERM
        if let Err(e) = signal::kill(pid, Signal::SIGTERM) {
            // ESRCH 表示进程已不存在，这是正常情况
            if e == nix::errno::Errno::ESRCH {
                info!("Child process {} already exited", pid);
                return Ok(());
            }
            warn!("Failed to send SIGTERM to {}: {}", pid, e);
        }

        // 等待 1 秒后检查进程是否还在运行
        std::thread::sleep(std::time::Duration::from_secs(1));

        // 再次检查：发送 SIGKILL 强制终止
        match signal::kill(pid, Signal::SIGKILL) {
            Ok(_) => {
                info!("Force killed child process {}", pid);
            }
            Err(nix::errno::Errno::ESRCH) => {
                info!("Child process {} exited after SIGTERM", pid);
            }
            Err(e) => {
                warn!("Failed to send SIGKILL to {}: {}", pid, e);
            }
        }

        Ok(())
    }
}

impl Drop for NetnsManager {
    /// Drop 时自动清理资源
    ///
    /// 如果命名空间已创建但用户忘记调用 [`destroy()`](NetnsManager::destroy)，
    /// Drop 实现会尝试清理。但需要注意的是，Drop 中不应 panic 或传播错误，
    /// 所以清理失败时会静默记录警告日志。
    fn drop(&mut self) {
        if self.host_ns_fd.is_some() || self.proxy_ns_fd.is_some() || self.child_pid.is_some() {
            warn!("NetnsManager dropped without explicit destroy() call, cleaning up");
            let _ = self.destroy();
        }
    }
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netns_manager_new() {
        let config = Config::default();
        let mgr = NetnsManager::new(&config);

        assert_eq!(mgr.host_if, "dae0");
        assert_eq!(mgr.peer_if, "dae0peer");
        assert_eq!(mgr.host_addr, "169.254.100.1/30");
        assert_eq!(mgr.peer_addr, "169.254.100.2/30");
        assert_eq!(mgr.mtu, 1500);
        assert_eq!(mgr.route_table, 20230);
        assert_eq!(mgr.proxy_mark, 0x02000000);
        assert_eq!(mgr.proxy_mask, 0x0f000000);
        assert!(mgr.host_ns_fd.is_none());
        assert!(mgr.child_pid.is_none());
        assert!(!mgr.is_created());
    }

    #[test]
    fn test_netns_manager_new_with_custom_config() {
        let config = Config {
            veth_host: "test0".into(),
            veth_peer: "test0peer".into(),
            host_addr: "10.0.0.1/24".into(),
            peer_addr: "10.0.0.2/24".into(),
            mtu: 9000,
            route_table: 100,
            fwmark_proxy: 0x01000000,
            fwmark_mask: 0xff000000,
            ..Default::default()
        };
        let mgr = NetnsManager::new(&config);

        assert_eq!(mgr.host_if, "test0");
        assert_eq!(mgr.peer_if, "test0peer");
        assert_eq!(mgr.host_addr, "10.0.0.1/24");
        assert_eq!(mgr.peer_addr, "10.0.0.2/24");
        assert_eq!(mgr.mtu, 9000);
        assert_eq!(mgr.route_table, 100);
        assert_eq!(mgr.proxy_mark, 0x01000000);
        assert_eq!(mgr.proxy_mask, 0xff000000);
    }

    #[test]
    fn test_destroy_without_create() {
        let config = Config::default();
        let mut mgr = NetnsManager::new(&config);

        // destroy() 应该在不创建的情况下安全调用
        assert!(mgr.destroy().is_ok());
    }
}
