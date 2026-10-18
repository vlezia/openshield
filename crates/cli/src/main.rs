// SPDX-License-Identifier: GPL-3.0-or-later
//! `openshield-cli`: filter list management and offline domain checks.
//!
//! `lists` and `test` work directly on the data directory. `status`,
//! `enable` and `disable` talk to the service over IPC (stage 2).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use openshield_core::config::Config;
use openshield_core::filtering;
use openshield_core::lists::{self, ListSource, UpdateOutcome};
use openshield_core::matcher::{LineClass, Verdict, classify_line, normalize_domain};
use openshield_core::paths::DataDir;

#[derive(Debug, Parser)]
#[command(
    name = "openshield-cli",
    version,
    about = "OpenShield command-line client"
)]
struct Cli {
    /// Data directory (default: %ProgramData%\OpenShield).
    #[arg(long, global = true, value_name = "DIR")]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Manage filter lists.
    Lists {
        #[command(subcommand)]
        action: ListsAction,
    },
    /// Check whether a domain would be blocked, and by which rule.
    Test { domain: String },
    /// Service status (stage 2).
    Status,
    /// Enable protection (stage 2).
    Enable,
    /// Disable protection (stage 2).
    Disable,
}

#[derive(Debug, Subcommand)]
enum ListsAction {
    /// Download enabled lists (conditional requests; keeps cache on failure).
    Update {
        /// Check every list now, ignoring the update interval.
        #[arg(long)]
        force: bool,
    },
    /// Show enabled lists and their cache state.
    Show,
    /// Show lines of a cached list that are skipped (unsupported) or invalid.
    Lint {
        /// List id, as shown by `lists show`.
        id: String,
        /// Maximum lines to print per category.
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let data = cli
        .data_dir
        .map(DataDir::new)
        .unwrap_or_else(DataDir::default_location);
    let config = match Config::load_or_default(&data.config_file()) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    match cli.command {
        Command::Lists {
            action: ListsAction::Update { force },
        } => lists_update(&data, &config, force),
        Command::Lists {
            action: ListsAction::Show,
        } => lists_show(&data, &config),
        Command::Lists {
            action: ListsAction::Lint { id, limit },
        } => lists_lint(&data, &config, &id, limit),
        Command::Test { domain } => test_domain(&data, &config, &domain),
        Command::Status | Command::Enable | Command::Disable => {
            eprintln!(
                "not implemented yet: needs the service IPC ({}) from stage 2",
                openshield_ipc::PIPE_NAME
            );
            ExitCode::FAILURE
        }
    }
}

fn lists_update(data: &DataDir, config: &Config, force: bool) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let results = match runtime.block_on(filtering::update_lists(data, &config.lists, force)) {
        Ok(results) => results,
        Err(e) => {
            eprintln!("error: cannot create HTTP client: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut failed = false;
    for (sub, outcome) in results {
        let status = match outcome {
            UpdateOutcome::Updated { bytes } => format!("updated, {bytes} bytes"),
            UpdateOutcome::NotModified => "not modified".to_owned(),
            UpdateOutcome::Fresh => "up to date".to_owned(),
            UpdateOutcome::Embedded => "built in".to_owned(),
            UpdateOutcome::Failed(e) => {
                failed = true;
                format!("FAILED ({e}); cached copy kept")
            }
        };
        println!("{:<45} {status}", sub.name);
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn lists_show(data: &DataDir, config: &Config) -> ExitCode {
    let (subs, invalid) = lists::subscriptions(&config.lists);
    let dir = data.lists_dir();
    for sub in subs {
        let state = match &sub.source {
            ListSource::Embedded(_) => "built in".to_owned(),
            ListSource::Url(url) => {
                let meta = lists::read_meta(&dir, &sub.id);
                if meta.checked_at == 0 {
                    format!("not downloaded  {url}")
                } else {
                    format!(
                        "{} bytes, checked at unix {}  {url}",
                        meta.bytes, meta.checked_at
                    )
                }
            }
        };
        println!("{:<22} {:<45} {state}", sub.id, sub.name);
    }
    for id in invalid {
        println!("{id:<22} (unknown or invalid; ignored)");
    }
    ExitCode::SUCCESS
}

fn lists_lint(data: &DataDir, config: &Config, id: &str, limit: usize) -> ExitCode {
    let (subs, _) = lists::subscriptions(&config.lists);
    let Some(sub) = subs.iter().find(|s| s.id == id) else {
        eprintln!("error: no enabled list with id '{id}' (see `openshield-cli lists show`)");
        return ExitCode::FAILURE;
    };
    let Some(text) = lists::read_cached(&data.lists_dir(), sub) else {
        eprintln!("error: '{id}' is not downloaded yet (run `openshield-cli lists update`)");
        return ExitCode::FAILURE;
    };
    let (mut rules, mut ignored) = (0usize, 0usize);
    let mut unsupported = Vec::new();
    let mut invalid = Vec::new();
    for (index, line) in text.lines().enumerate() {
        match classify_line(line) {
            LineClass::Rule => rules += 1,
            LineClass::Ignored => ignored += 1,
            LineClass::Unsupported => unsupported.push((index + 1, line.trim())),
            LineClass::Invalid => invalid.push((index + 1, line.trim())),
        }
    }
    println!(
        "{}: {rules} rule lines, {ignored} ignored, {} unsupported, {} invalid",
        sub.name,
        unsupported.len(),
        invalid.len()
    );
    for (title, items) in [
        ("unsupported (skipped)", &unsupported),
        ("invalid", &invalid),
    ] {
        if items.is_empty() {
            continue;
        }
        println!("\n{title}:");
        for (line, text) in items.iter().take(limit) {
            println!("  {line:>7}: {text}");
        }
        if items.len() > limit {
            println!("  ... {} more", items.len() - limit);
        }
    }
    ExitCode::SUCCESS
}

fn test_domain(data: &DataDir, config: &Config, domain: &str) -> ExitCode {
    let Some(domain) = normalize_domain(domain) else {
        eprintln!("error: '{domain}' is not a valid domain name");
        return ExitCode::FAILURE;
    };
    let (matcher, report) = filtering::build_matcher(data, &config.lists);
    let missing: Vec<&str> = report
        .sources
        .iter()
        .filter(|s| s.missing)
        .map(|s| s.name.as_str())
        .collect();
    if !missing.is_empty() {
        eprintln!(
            "note: not downloaded yet: {} (run `openshield-cli lists update`)",
            missing.join(", ")
        );
    }
    let describe = |source| matcher.source_name(source).unwrap_or("?");
    match matcher.check(&domain) {
        Verdict::Block(rule) => {
            let text = report.rule_text(data, rule).unwrap_or_default();
            println!(
                "{domain}: BLOCKED by {} line {}: {text}",
                describe(rule.source),
                rule.line
            );
        }
        Verdict::Allow(rule) => {
            let text = report.rule_text(data, rule).unwrap_or_default();
            println!(
                "{domain}: allowed by {} line {}: {text}",
                describe(rule.source),
                rule.line
            );
        }
        Verdict::NoMatch => println!("{domain}: not blocked (no matching rule)"),
    }
    ExitCode::SUCCESS
}
