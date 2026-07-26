//! dae-rs main library entry point
//!
//! This library is the core of the dae-rs proxy system, integrating the control plane,
//! protocol layer, eBPF program management, and shared data structures.
//! The `run()` function is the system's main entry point, orchestrating the full
//! startup/shutdown lifecycle.

use anyhow::Context;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::RwLock;

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
    // ── Phase 1: Startup banner ──
    tracing::info!("========================================");
    tracing::info!("  dae-rs v{} starting up", env!("CARGO_PKG_VERSION"));
    tracing::info!("  log_level: {}, json_log: {}", log_level, json_log);
    tracing::info!("========================================");

    // ── Phase 2: Read configuration file ──
    let config_content = if let Some(path) = &config_path {
        if !path.exists() {
            anyhow::bail!("Config file not found: {}", path.display());
        }
        std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config: {}", path.display()))?
    } else {
        tracing::warn!("No config file specified, using built-in example config");
        control::config::default_config_example().to_string()
    };

    // ── Phase 3: Parse configuration ──
    tracing::info!("Parsing configuration...");
    let config =
        control::Config::from_daefile(&config_content).context("Failed to parse configuration")?;

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

    // ── Phase 4.5: Write normalized config as temp JSON ──
    if let Some(ref daefile_cfg) = config.daefile_config {
        match control::write_temp_json(daefile_cfg) {
            Ok(path) => tracing::info!("Normalized config written to {}", path.display()),
            Err(e) => tracing::warn!("Failed to write temp JSON config: {}", e),
        }
    }

    // ── Phase 5: Create control plane ──
    tracing::info!("Initializing control plane...");
    let mut cp = control::ControlPlane::new(config);
    // Embed eBPF bytecode compiled by build.rs
    const EMBEDDED_EBPF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ebpf.o"));
    cp.embedded_ebpf = Some(EMBEDDED_EBPF);
    tracing::info!("Embedded eBPF bytecode: {} bytes", EMBEDDED_EBPF.len());

    // Set eBPF PARAM global variable
    // This must be done after netns creation but before eBPF loading
    // We'll set it in start() after netns is created
    let mut ebpf_param = control::ebpf::Daeparam::default();
    ebpf_param.tproxy_port = cp.config.tproxy_port as u32;
    ebpf_param.control_plane_pid = std::process::id();
    // dae0_ifindex, dae_netns_id, dae0peer_mac will be set after netns creation
    cp.ebpf_param = Some(ebpf_param);

    let control = Arc::new(RwLock::new(cp));

    // Store daefile content for config reload
    {
        let mut ctrl = control.write().await;
        ctrl.daefile_content = Some(config_content.clone());
    }

    // ── Phase 6: Start control plane (netns + eBPF + TProxy) ──
    tracing::info!("Starting control plane...");
    {
        let mut ctrl = control.write().await;
        ctrl.start()
            .await
            .context("Failed to start control plane")?;
    }
    tracing::info!("Control plane started successfully");

    // ── Phase 7: Optional: Start API server ──
    let api_handle = {
        let ctrl = control.read().await;
        if let Some(ref api_cfg) = ctrl.config.api_config {
            if api_cfg.enabled {
                tracing::info!("Starting API server on {}...", api_cfg.listen);
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

    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;

    loop {
        tokio::select! {
            _ = sigint.recv() => {
                tracing::info!("Received SIGINT, initiating graceful shutdown");
                break;
            }
            _ = sigterm.recv() => {
                tracing::info!("Received SIGTERM, initiating graceful shutdown");
                break;
            }
            _ = sighup.recv() => {
                tracing::info!("Received SIGHUP, reloading configuration");
                let mut ctrl = control.write().await;
                let content = ctrl.daefile_content.clone().unwrap_or_default();
                match ctrl.reload_config(&content) {
                    Ok(()) => tracing::info!("SIGHUP reload completed"),
                    Err(e) => tracing::error!("SIGHUP reload failed: {}", e),
                }
            }
        }
    }

    // ── Phase 9: Emergency BPF hook detachment ──
    // Detach BPF hooks FIRST so network is restored immediately, even if
    // the rest of the shutdown process is slow or gets SIGKILL'd.
    tracing::info!("Phase 9/10: Emergency BPF hook detachment");
    {
        let mut ctrl = control.write().await;
        ctrl.detach_bpf_hooks();
    }
    tracing::info!("BPF hooks detached, network restored");

    // ── Phase 11: Graceful shutdown ──
    // 11a. Stop API server
    if let Some(handle) = api_handle {
        tracing::info!("Stopping API server...");
        handle.abort();
        tracing::info!("API server stopped");
    }

    // 11b. Stop control plane
    tracing::info!("Stopping control plane...");
    {
        let mut ctrl = control.write().await;
        ctrl.stop().await.context("Failed to stop control plane")?;
    }
    tracing::info!("Control plane stopped");

    // ── Phase 12: Cleanup temp JSON files ──
    tracing::info!("Cleaning up old temp JSON files...");
    control::cleanup_temp_json(3600); // Clean files older than 1 hour

    // ── Phase 12: Complete ──
    tracing::info!("dae-rs shutdown complete");
    Ok(())
}
