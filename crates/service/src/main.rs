// SPDX-License-Identifier: GPL-3.0-or-later
//! OpenShield service entry point.
//!
//! `--console` runs DNS filtering in the foreground (stage 1). Without flags
//! the binary will run as a Windows service (stage 2).

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;

#[cfg(windows)]
mod console;
#[cfg(windows)]
mod os;

#[derive(Debug, Parser)]
#[command(
    name = "openshield-service",
    version,
    about = "OpenShield filtering service"
)]
struct Args {
    /// Run in the foreground until Ctrl+C (requires administrator rights).
    #[arg(long)]
    console: bool,

    /// Data directory (default: %ProgramData%\OpenShield).
    #[arg(long, value_name = "DIR")]
    data_dir: Option<PathBuf>,

    /// Directory with WinDivert.dll and WinDivert64.sys (default: next to
    /// this executable).
    #[arg(long, value_name = "DIR")]
    windivert_dir: Option<PathBuf>,

    /// Seconds between statistics lines.
    #[arg(long, default_value_t = 60, value_name = "SECS")]
    stats_interval: u64,

    /// Do not download filter lists; use the cache only.
    #[arg(long)]
    no_update: bool,

    /// Debug-level logging to the console (nothing is written to disk).
    #[arg(short, long)]
    verbose: bool,

    /// Testing only: hang while processing the N-th packet to verify that the
    /// watchdog releases capture.
    #[cfg(feature = "fault-injection")]
    #[arg(long, value_name = "N")]
    debug_stall_after: Option<u64>,
}

fn init_logging(verbose: bool) {
    let default = if verbose { "debug" } else { "info" };
    let filter = tracing_subscriber::EnvFilter::try_from_env("OPENSHIELD_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
}

fn main() -> ExitCode {
    let args = Args::parse();
    init_logging(args.verbose);
    if !args.console {
        eprintln!("Windows service mode arrives in stage 2; use --console for now.");
        eprintln!("ipc pipe (stage 2): {}", openshield_ipc::PIPE_NAME);
        return ExitCode::FAILURE;
    }
    run_console(args)
}

#[cfg(windows)]
fn run_console(args: Args) -> ExitCode {
    #[allow(unused_mut)]
    let mut loop_options = openshield_dns::run::LoopOptions::default();
    #[cfg(feature = "fault-injection")]
    {
        loop_options.stall_after = args.debug_stall_after;
    }
    console::run(console::ConsoleArgs {
        data_dir: args.data_dir,
        windivert_dir: args.windivert_dir,
        stats_interval: Duration::from_secs(args.stats_interval.max(5)),
        no_update: args.no_update,
        loop_options,
    })
}

#[cfg(not(windows))]
fn run_console(_args: Args) -> ExitCode {
    let _ = Duration::ZERO;
    eprintln!("{}", openshield_intercept::InterceptError::Unsupported);
    ExitCode::FAILURE
}
