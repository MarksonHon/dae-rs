//! dae-rs main binary entry point
//!
//! An eBPF-based proxy system (Phase 1: SOCKS5 outbound only).
//! Parses CLI arguments, initializes tracing logging, checks root privileges
//! or required capabilities, then calls `dae_rs::run()` to enter the main loop.

use caps::Capability;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

/// CLI arguments
#[derive(Parser, Debug)]
#[command(name = "dae-rs", version, about = "eBPF-based proxy system")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the proxy service
    Run(RunArgs),
}

#[derive(Parser, Debug)]
struct RunArgs {
    /// Path to config file (.daefile)
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Enable JSON log output
    #[arg(long, default_value_t = false)]
    json_log: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let Commands::Run(args) = cli.command;

    // Initialize tracing logging
    init_tracing(&args.log_level, args.json_log);

    debug!(
        config = ?args.config,
        log_level = %args.log_level,
        json_log = args.json_log,
        "CLI arguments parsed"
    );

    // Check runtime privileges (eBPF and network operations require root)
    check_privileges()?;

    // Run the main loop
    debug!("Entering dae_rs::run()");
    dae_rs::run(args.config, args.log_level, args.json_log).await
}

/// Initialize the tracing logging system
///
/// Configures log level and output format based on parameters.
/// - `json = true`: JSON line output, suitable for log collection systems (e.g., Loki, Elasticsearch)
/// - `json = false`: Pretty format, suitable for terminal viewing
///
/// Prefers the `RUST_LOG` environment variable; falls back to the provided `level` parameter.
fn init_tracing(level: &str, json: bool) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    if json {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .pretty()
            .with_env_filter(filter)
            .init();
    }
}

/// Check runtime privileges
///
/// eBPF program loading and network namespace operations require these capabilities:
/// - `CAP_NET_ADMIN`: Manage network interfaces, routing tables, netns
/// - `CAP_SYS_ADMIN`: Execute `setns()` and other system administration operations
/// - `CAP_BPF`: Load and attach eBPF programs (Linux 5.8+)
///
/// On Linux, these are typically obtained by running as root.
/// However, modern container environments may grant specific capabilities
/// (e.g. `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_SYS_ADMIN`) to non-root users.
///
/// # Errors
///
/// If the current process is neither root nor in possession of all required
/// capabilities, returns a clear error message listing the missing capabilities.
fn check_privileges() -> anyhow::Result<()> {
    let uid = nix::unistd::Uid::effective();
    let euid = uid.as_raw();
    debug!(euid, "Checking effective user ID");

    // Root users pass the check immediately
    if uid.is_root() {
        tracing::info!("Running with root privileges (euid={})", euid);
        return Ok(());
    }

    // Non-root users: check capabilities
    let caps_set = match caps::read(None, caps::CapSet::Effective) {
        Ok(c) => c,
        Err(e) => {
            anyhow::bail!(
                "Failed to read process capabilities: {}\n\
                 Please run as root or grant capabilities via:\n\
                 sudo setcap cap_net_admin,cap_sys_admin+ep ./dae-rs",
                e
            );
        }
    };

    // Required capabilities (CAP_BPF is Linux 5.8+; only check if available in the crate)
    let required_caps = [
        Capability::CAP_NET_ADMIN,
        Capability::CAP_SYS_ADMIN,
        Capability::CAP_BPF, // Linux 5.8+ 需要
    ];

    let missing: Vec<String> = required_caps
        .iter()
        .filter(|&&cap| !caps_set.contains(&cap))
        .map(|cap| format!("{:?}", cap))
        .collect();

    if !missing.is_empty() {
        anyhow::bail!(
            "Missing required capabilities: [{}]\n\
             Please run as root or grant capabilities, e.g.:\n\
             sudo setcap cap_net_admin,cap_sys_admin,cap_bpf+ep ./dae-rs",
            missing.join(", ")
        );
    }

    info!("Running with limited capabilities (not root, euid={})", euid);
    Ok(())
}
