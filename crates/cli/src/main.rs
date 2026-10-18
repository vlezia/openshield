// SPDX-License-Identifier: GPL-3.0-or-later
//! `openshield-cli`: status, enable/disable, list updates and URL checks.
//!
//! Stage 0 only answers `--version`; commands talk to the service over IPC
//! once it exists.

use std::process::ExitCode;

const USAGE: &str =
    "usage: openshield-cli [--version | status | enable | disable | lists update | test <url>]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version" | "-V") => {
            println!(
                "{} (ipc protocol v{})",
                openshield_core::version_line(),
                openshield_ipc::PROTOCOL_VERSION
            );
            ExitCode::SUCCESS
        }
        Some("status" | "enable" | "disable" | "lists" | "test") => {
            eprintln!("not implemented yet: the service and IPC arrive in stages 1-2");
            ExitCode::FAILURE
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}
