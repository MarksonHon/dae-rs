//! dae-rs main binary entry point
//!
//! An eBPF-based proxy system (Phase 1: SOCKS5 outbound only).
//! Parses CLI arguments, initializes tracing logging, checks root privileges,
//! then calls `dae_rs::run()` to enter the main loop.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
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

    // Check runtime privileges (eBPF and network operations require root)
    check_privileges()?;

    // Run the main loop
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
/// - `CAP_BPF`: Load and attach eBPF programs
/// - `CAP_NET_ADMIN`: Manage network interfaces, routing tables, netns
/// - `CAP_SYS_ADMIN`: Execute `setns()` and other system administration operations
///
/// On Linux, these are typically obtained by running as root.
///
/// # Errors
///
/// If the current process is not running as root, returns a clear error message
/// informing the user about the required privileges.
fn check_privileges() -> anyhow::Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        anyhow::bail!(
            "dae-rs requires root privileges\n\
             eBPF programs and network operations require:\n\
             ་ CAP_BPF\n\
             ་ CAP_NET_ADMIN\n\
             ་ CAP_SYS_ADMIN\n\
             Please run with sudo or as root"
        );
    }
    tracing::info!("Running with root privileges");
    Ok(())
}
