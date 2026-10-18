// SPDX-License-Identifier: GPL-3.0-or-later
//! Platform-independent core of OpenShield.
//!
//! Stage 1 adds the DNS domain matcher, filter list download/cache and
//! statistics here. Nothing in this crate may depend on WinAPI.

/// Product name shown in logs, the CA subject and the GUI.
pub const PRODUCT_NAME: &str = "OpenShield";

/// Version of the OpenShield workspace.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns a one-line `name version` string for `--version` output.
pub fn version_line() -> String {
    format!("{PRODUCT_NAME} {VERSION}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_line_contains_name_and_version() {
        let line = version_line();
        assert!(line.starts_with(PRODUCT_NAME));
        assert!(line.ends_with(VERSION));
    }
}
