// SPDX-License-Identifier: GPL-3.0-or-later
//! `--console` mode: runs DNS filtering in the foreground until Ctrl+C.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use arc_swap::ArcSwap;
use openshield_core::config::Config;
use openshield_core::filtering::{self, LoadReport};
use openshield_core::lists::UpdateOutcome;
use openshield_core::matcher::Matcher;
use openshield_core::paths::DataDir;
use openshield_core::stats::{Stats, StatsSnapshot};
use openshield_core::watchdog::{Heartbeat, Watchdog};
use openshield_dns::packet::Policy;
use openshield_dns::run::{LoopOptions, LoopSummary};
use openshield_intercept::windivert::{Layer, WinDivert, WinDivertLib};
use openshield_intercept::{InterceptError, Interceptor};
use tracing::{error, info, warn};

use crate::os;

/// How often lists are checked for updates while running.
const UPDATE_CHECK: Duration = Duration::from_secs(3600);
const TOP_N: usize = 20;

#[derive(Debug, Clone)]
pub struct ConsoleArgs {
    pub data_dir: Option<PathBuf>,
    pub windivert_dir: Option<PathBuf>,
    pub stats_interval: Duration,
    pub no_update: bool,
    pub loop_options: LoopOptions,
}

pub fn run(args: ConsoleArgs) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!("cannot start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run_async(args)) {
        Ok(code) => code,
        Err(message) => {
            error!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn log_report(report: &LoadReport, matcher: &Matcher) {
    for id in &report.invalid_subscriptions {
        warn!("ignoring unknown or invalid list '{id}' in config");
    }
    for source in &report.sources {
        if source.missing {
            warn!("{}: not downloaded yet", source.name);
            continue;
        }
        let s = &source.stats;
        if s.rules + s.unsupported + s.invalid == 0 {
            continue;
        }
        info!(
            "{}: {} rules, {} unsupported (skipped), {} invalid",
            source.name, s.rules, s.unsupported, s.invalid
        );
    }
    if report.disabled_by_badfilter > 0 {
        info!("$badfilter disabled {} rules", report.disabled_by_badfilter);
    }
    info!("matcher ready: {} domains", matcher.len());
}

fn log_updates(results: &[(openshield_core::lists::Subscription, UpdateOutcome)]) -> bool {
    let mut changed = false;
    for (sub, outcome) in results {
        match outcome {
            UpdateOutcome::Updated { bytes } => {
                changed = true;
                info!("{}: updated ({bytes} bytes)", sub.name);
            }
            UpdateOutcome::NotModified => info!("{}: not modified", sub.name),
            UpdateOutcome::Fresh | UpdateOutcome::Embedded => {}
            UpdateOutcome::Failed(e) => {
                warn!("{}: update failed, keeping cached copy: {e}", sub.name)
            }
        }
    }
    changed
}

fn print_stats(snapshot: &StatsSnapshot) {
    let percent = if snapshot.total == 0 {
        0.0
    } else {
        snapshot.blocked as f64 * 100.0 / snapshot.total as f64
    };
    let join = |items: &[(String, u64)]| {
        items
            .iter()
            .map(|(d, n)| format!("{d} ({n})"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    info!(
        "stats: {} queries, {} blocked ({percent:.1}%)",
        snapshot.total, snapshot.blocked
    );
    if !snapshot.top_blocked.is_empty() {
        info!("  top blocked: {}", join(&snapshot.top_blocked));
    }
    if !snapshot.top_queried.is_empty() {
        info!("  top queried: {}", join(&snapshot.top_queried));
    }
    if snapshot.dropped_events > 0 {
        info!(
            "  ({} per-domain events dropped; totals are exact)",
            snapshot.dropped_events
        );
    }
}

fn make_policy(config: &Config, matcher: Matcher) -> Policy {
    Policy {
        matcher: Arc::new(matcher),
        mode: config.dns.blocking_mode,
        blocked_ttl: config.dns.blocked_ttl,
    }
}

async fn run_async(args: ConsoleArgs) -> Result<ExitCode, String> {
    let data = args
        .data_dir
        .clone()
        .map(DataDir::new)
        .unwrap_or_else(DataDir::default_location);
    info!(
        "{} starting (console mode)",
        openshield_core::version_line()
    );
    info!("data directory: {}", data.root().display());
    let config = Config::load_or_default(&data.config_file()).map_err(|e| e.to_string())?;
    if !config.dns.enabled {
        warn!("DNS filtering is disabled in config.toml; nothing to do");
        return Ok(ExitCode::SUCCESS);
    }

    let doh = os::system_doh_indicators();
    if !doh.is_empty() {
        warn!(
            "Windows DNS over HTTPS seems to be enabled; OpenShield cannot see encrypted system DNS queries:"
        );
        for reason in &doh {
            warn!("  - {reason}");
        }
    }

    if !args.no_update {
        match filtering::update_lists(&data, &config.lists, false).await {
            Ok(results) => {
                log_updates(&results);
            }
            Err(e) => warn!("cannot create HTTP client, using cached lists: {e}"),
        }
    }
    let (matcher, report) = filtering::build_matcher(&data, &config.lists);
    log_report(&report, &matcher);
    let policy = Arc::new(ArcSwap::from_pointee(make_policy(&config, matcher)));

    let windivert_dir = match args.windivert_dir.clone() {
        Some(dir) => dir,
        None => std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(PathBuf::from))
            .ok_or("cannot determine executable directory; pass --windivert-dir")?,
    };
    let lib = WinDivertLib::load(&windivert_dir).map_err(|e| e.to_string())?;
    info!("loaded {}", lib.path().display());
    let divert = Arc::new(
        WinDivert::open(lib, openshield_dns::WINDIVERT_FILTER, Layer::Network, 0, 0)
            .map_err(|e| e.to_string())?,
    );
    if let Ok((major, minor)) = divert.version() {
        info!("WinDivert driver {major}.{minor}; capturing outbound DNS");
    }
    os::flush_dns_cache();

    let stats = Stats::start().map_err(|e| e.to_string())?;
    let heartbeat = Heartbeat::new();
    let stalled = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(tokio::sync::Notify::new());

    let (result_tx, result_rx) = mpsc::channel::<Result<LoopSummary, InterceptError>>();
    {
        let (divert, policy, heartbeat, finished) = (
            Arc::clone(&divert),
            Arc::clone(&policy),
            Arc::clone(&heartbeat),
            Arc::clone(&finished),
        );
        let recorder = stats.recorder();
        let options = args.loop_options.clone();
        std::thread::Builder::new()
            .name("openshield-dns-loop".to_owned())
            .spawn(move || {
                let result =
                    openshield_dns::run::run(&*divert, &policy, &heartbeat, &recorder, &options);
                let _ = result_tx.send(result);
                finished.notify_one();
            })
            .map_err(|e| e.to_string())?;
    }

    let watchdog = {
        let (divert, stalled, finished) = (
            Arc::clone(&divert),
            Arc::clone(&stalled),
            Arc::clone(&finished),
        );
        Watchdog::spawn(
            Arc::clone(&heartbeat),
            config.watchdog.stall_timeout(),
            move |busy| {
                stalled.store(true, Ordering::SeqCst);
                let released = divert.shutdown();
                error!(
                    "watchdog: packet loop stuck for {:.1}s; capture released, traffic flows unfiltered (fail open). released={}",
                    busy.as_secs_f64(),
                    released.is_ok()
                );
                finished.notify_one();
            },
        )
        .map_err(|e| e.to_string())?
    };
    info!("DNS filtering active. Press Ctrl+C to stop.");

    let mut stats_tick = tokio::time::interval(args.stats_interval);
    stats_tick.tick().await;
    let mut update_tick = tokio::time::interval(UPDATE_CHECK);
    update_tick.tick().await;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("stopping");
                break;
            }
            () = finished.notified() => break,
            _ = stats_tick.tick() => print_stats(&stats.snapshot(TOP_N)),
            _ = update_tick.tick(), if !args.no_update => {
                if let Ok(results) = filtering::update_lists(&data, &config.lists, false).await
                    && log_updates(&results)
                {
                    let (matcher, report) = filtering::build_matcher(&data, &config.lists);
                    log_report(&report, &matcher);
                    policy.store(Arc::new(make_policy(&config, matcher)));
                }
            }
        }
    }

    if let Err(e) = divert.shutdown() {
        warn!("shutdown: {e}");
    }
    watchdog.stop();
    let code = if stalled.load(Ordering::SeqCst) {
        // The loop thread may be stuck forever; exiting the process is the
        // final fail-open step.
        ExitCode::from(2)
    } else {
        match result_rx.recv_timeout(Duration::from_secs(3)) {
            Ok(Ok(summary)) => {
                info!(
                    "packet loop finished: {} packets, {} answered, {} send errors",
                    summary.packets, summary.replies, summary.send_errors
                );
                ExitCode::SUCCESS
            }
            Ok(Err(e)) => {
                error!("packet loop failed: {e}");
                ExitCode::FAILURE
            }
            Err(_) => {
                warn!("packet loop did not stop in time");
                ExitCode::FAILURE
            }
        }
    };
    drop(divert);
    os::flush_dns_cache();
    print_stats(&stats.snapshot(TOP_N));
    Ok(code)
}
