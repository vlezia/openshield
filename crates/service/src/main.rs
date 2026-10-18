// SPDX-License-Identifier: GPL-3.0-or-later
//! OpenShield service entry point.
//!
//! Stage 0 only answers `--version`. `--console` (stage 1) runs the filtering
//! core in the foreground; without flags the binary will run as a Windows
//! service (stage 2).

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version" | "-V") => {
            println!("{}", openshield_core::version_line());
            ExitCode::SUCCESS
        }
        Some("--console") => {
            eprintln!("--console mode is not implemented yet (stage 1)");
            ExitCode::FAILURE
        }
        _ => {
            eprintln!("usage: openshield-service [--version | --console]");
            eprintln!("ipc pipe: {}", openshield_ipc::PIPE_NAME);
            ExitCode::FAILURE
        }
    }
}
