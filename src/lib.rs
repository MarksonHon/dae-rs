//! dae-rs main library entry point
//!
//! This library is the core of the dae-rs proxy system, integrating the control plane,
//! protocol layer, eBPF program management, and shared data structures.
//! The `run()` function is the system's main entry point, orchestrating the full
//! startup/shutdown lifecycle.

// Global memory allocator (dae-rs only supports Linux):
// - gnu target: jemalloc, good multi-threaded performance, low memory fragmentation, suitable for long-running proxy processes
// - musl target: mimalloc, lightweight, fully compatible with musl
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[global_allocator]
static GLOBAL_ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(all(target_os = "linux", target_env = "musl"))]
#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anyhow::Context;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::RwLock;
use tracing::debug;

/// Main run logic
///
/// Executes the full startup/shutdown lifecycle:
///
/// 1. **Startup banner** — Print dae-rs version information
/// 2. **Read configuration** — Read from file or use built-in example
/// 3. **Parse configuration** — Call [`control::Config::from_daefile()`]
/// 4. **Print config summary** — Display key configuration items
/// 5. **Create control plane** — Initialize [`control::ControlPlane`]
/// 6. **Start control plane** — Create netns/veth, load eBPF, start TProxy
/// 7. **Start API server** — Optional, based on configuration
/// 8. **Wait for exit signal** — Ctrl+C
/// 9. **Graceful shutdown** — Stop API, then stop control plane
///
/// # Parameters
///
/// * `config_path` — Path to config file. `None` uses built-in example.
/// * `log_level` — Log level (only for display; actual log filtering is configured in main.rs).
/// * `json_log` — Whether to use JSON log output.
///
/// # Errors
///
/// Failure at any stage returns [`anyhow::Error`] with context.
pub async fn run(
    config_path: Option<PathBuf>,
    log_level: String,
    json_log: bool,
) -> anyhow::Result<()> {
    let start_time = std::time::Instant::now();

    // ── Phase 1: Startup banner ──
    tracing::info!("========================================");
    tracing::info!("  dae-rs v{} starting up", env!("CARGO_PKG_VERSION"));
    tracing::info!("  log_level: {}, json_log: {}", log_level, json_log);
    tracing::info!("========================================");
    debug!(
        config_path = ?config_path,
        log_level = %log_level,
        json_log = json_log,
        pid = std::process::id(),
        "Startup phase 1: banner displayed"
    );

    // ── Phase 2: Read configuration file ──
    debug!(config_path = ?config_path, "Phase 2: reading configuration");
    let config_content = if let Some(path) = &config_path {
        if !path.exists() {
            anyhow::bail!("Config file not found: {}", path.display());
        }
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config: {}", path.display()))?;
        debug!(
            size = content.len(),
            path = %path.display(),
            "Configuration file read successfully"
        );
        content
    } else {
        tracing::warn!("No config file specified, using built-in example config");
        let example = control::config::default_config_example().to_string();
        debug!(size = example.len(), "Using built-in example config");
        example
    };

    // ── Phase 3: Parse configuration ──
    tracing::info!("Parsing configuration...");
    let parse_start = std::time::Instant::now();
    let config =
        control::Config::from_daefile(&config_content).context("Failed to parse configuration")?;
    debug!(
    elapsed_us = parse_start.elapsed().as_micros(),
    "Configuration parsed successfully"
    );

    // ── Phase 4: Print config summary ──
    tracing::info!("Configuration loaded:");
    tracing::info!("  TProxy port: {}", config.tproxy_port);
    tracing::info!("  Netkit: dae0 <-> dae0peer (always netkit)");
    tracing::info!("  Route table: {}", config.route_table);
    tracing::info!("  Proxy mark:  {:08x}", config.fwmark_proxy);
    tracing::info!("  Bypass mark: {:08x}", config.fwmark_bypass);
    tracing::info!(
        "  API enabled: {}",
        config
            .api_config
            .as_ref()
            .map(|a| a.enabled)
            .unwrap_or(false)
    );

    debug!(
        tproxy_port = config.tproxy_port,
        route_table = config.route_table,
        fwmark_proxy = format!("{:#x}", config.fwmark_proxy),
        fwmark_bypass = format!("{:#x}", config.fwmark_bypass),
        fwmark_mask = format!("{:#x}", config.fwmark_mask),
        mtu = config.mtu,
        proxy_addr = %config.proxy_addr,
        wan_count = config.wan_interface.len(),
        lan_count = config.lan_interface.len(),
        "Full config summary (debug)"
    );

    // ── Phase 4.5: Write normalized config as temp JSON ──
    if let Some(ref daefile_cfg) = config.daefile_config {
        match control::write_temp_json(daefile_cfg) {
            Ok(path) => {
                tracing::info!("Normalized config written to {}", path.display());
                debug!("Temp JSON config written (daefile has {} rules, {} outbounds)", daefile_cfg.routing.rules.len(), daefile_cfg.outbounds.nodes.len());
            }
            Err(e) => tracing::warn!("Failed to write temp JSON config: {}", e),
        }
    }

    // ── Phase 5: Create control plane ──
    tracing::info!("Initializing control plane...");
    let mut cp = control::ControlPlane::new(config);
    // Embed eBPF bytecode compiled by build.rs
    const EMBEDDED_EBPF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ebpf.o"));
    cp.embedded_ebpf = Some(EMBEDDED_EBPF);
    debug!(
        ebpf_bytes = EMBEDDED_EBPF.len(),
        "Embedded eBPF bytecode"
    );

    // Set eBPF PARAM global variable
    // This must be done after netns creation but before eBPF loading
    // We'll set it in start() after netns is created
    let ebpf_param = control::net::ebpf::Daeparam {
        tproxy_port: cp.config.tproxy_port as u32,
        control_plane_pid: std::process::id(),
        // dae_socket_mark: used by eBPF pid_is_control_plane() to identify
        // dae-rs's own sockets and skip them (prevents self-loop).
        // Must match socket_mark used by TProxy and SOCKS5 dialers.
        dae_socket_mark: shared::DAE_SOCKET_MARK,
        // DNS hijacking is disabled (DNS module removed).
        dns_hijack_enabled: 0,
        // dae0_ifindex, dae_netns_id, dae0peer_mac will be set after netns creation
        ..Default::default()
    };
    cp.ebpf_param = Some(ebpf_param);
    debug!(
        tproxy_port = ebpf_param.tproxy_port,
        control_plane_pid = ebpf_param.control_plane_pid,
        dae_socket_mark = ebpf_param.dae_socket_mark,
        dns_hijack_enabled = ebpf_param.dns_hijack_enabled,
        "Initial eBPF PARAM configured"
    );

    let control = Arc::new(RwLock::new(cp));

    // Store daefile content for config reload
    {
        let mut ctrl = control.write().await;
        ctrl.daefile_content = Some(config_content.clone());
        let content_len = config_content.len();
        debug!(content_len, "daefile content stored for reload");
    }

    // ── Phase 6: Start control plane (netns + eBPF + TProxy) ──
    tracing::info!("Starting control plane...");
    {
        let mut ctrl = control.write().await;
        let step_start = std::time::Instant::now();
        ctrl.start()
            .await
            .context("Failed to start control plane")?;
        debug!(
            elapsed_ms = step_start.elapsed().as_millis(),
            "Control plane start() completed"
        );
    }
    tracing::info!("Control plane started successfully");

    // ── Phase 7: Optional: Start API server ──
    let api_handle = {
        let ctrl = control.read().await;
        if let Some(ref api_cfg) = ctrl.config.api_config {
            if api_cfg.enabled {
                tracing::info!("Starting API server on {}...", api_cfg.listen);
                debug!(
                    api_listen = %api_cfg.listen,
                    api_enabled = api_cfg.enabled,
                    "Starting API server"
                );
                let handle = control::ControlPlane::start_api(control.clone(), api_cfg.clone())
                    .await
                    .context("Failed to start API server")?;
                tracing::info!("API server started");
                Some(handle)
            } else {
                tracing::info!("API server is disabled in config");
                None
            }
        } else {
            tracing::info!("No API configuration found, API server not started");
            None
        }
    };

    // ── Phase 8: Wait for exit signal or SIGHUP reload ──
    tracing::info!("dae-rs is running. Press Ctrl+C to stop, SIGHUP to reload.");
    debug!(
        total_elapsed_ms = start_time.elapsed().as_millis(),
        "dae-rs fully started"
    );

    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;

    loop {
        tokio::select! {
            _ = sigint.recv() => {
                tracing::info!("Received SIGINT, initiating graceful shutdown");
                debug!("Signal handler: SIGINT received");
                break;
            }
            _ = sigterm.recv() => {
                tracing::info!("Received SIGTERM, initiating graceful shutdown");
                debug!("Signal handler: SIGTERM received");
                break;
            }
            _ = sighup.recv() => {
                tracing::info!("Received SIGHUP, reloading configuration");
                debug!("Signal handler: SIGHUP received, reloading");
                let mut ctrl = control.write().await;
                let content = ctrl.daefile_content.clone().unwrap_or_default();
                let reload_start = std::time::Instant::now();
                match ctrl.reload_config(&content) {
                    Ok(()) => {
                        debug!(elapsed_ms = reload_start.elapsed().as_millis(), "SIGHUP reload completed");
                        tracing::info!("SIGHUP reload completed");
                    }
                    Err(e) => tracing::error!("SIGHUP reload failed: {}", e),
                }
            }
        }
    }

    // ── Phase 10: Emergency BPF hook detachment ──
    // Detach BPF hooks FIRST so network is restored immediately, even if
    // the rest of the shutdown process is slow or gets SIGKILL'd.
    tracing::info!("Phase 10/12: Emergency BPF hook detachment");
    {
        let start = std::time::Instant::now();
        let mut ctrl = control.write().await;
        ctrl.detach_bpf_hooks();
        debug!(
            elapsed_ms = start.elapsed().as_millis(),
            "Emergency BPF hook detachment completed"
        );
    }
    tracing::info!("BPF hooks detached, network restored");

    // ── Phase 11: Graceful shutdown ──
    // 11a. Stop API server
    if let Some(handle) = api_handle {
        tracing::info!("Stopping API server...");
        handle.abort();
        tracing::info!("API server stopped");
        debug!("API server task aborted");
    }

    // 11b. Stop control plane
    tracing::info!("Stopping control plane...");
    {
        let mut ctrl = control.write().await;
        let stop_start = std::time::Instant::now();
        ctrl.stop().await.context("Failed to stop control plane")?;
        debug!(
            elapsed_ms = stop_start.elapsed().as_millis(),
            "Control plane stop() completed"
        );
    }
    tracing::info!("Control plane stopped");

    // ── Phase 12: Cleanup temp JSON files ──
    tracing::info!("Phase 12/12: Cleaning up all temp JSON files...");
    {
        let cleanup_start = std::time::Instant::now();
        control::cleanup_temp_json(0); // Clean all temp JSON files
        debug!(
            elapsed_ms = cleanup_start.elapsed().as_millis(),
            "Temp JSON cleanup completed"
        );
    }

    // ── Phase 12: Complete ──
    let total_ms = start_time.elapsed().as_millis();
    debug!(total_ms, total_uptime_ms = total_ms, "dae-rs shutdown complete");
    tracing::info!("dae-rs shutdown complete");
    Ok(())
}
