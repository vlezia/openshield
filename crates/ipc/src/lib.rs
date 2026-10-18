// SPDX-License-Identifier: GPL-3.0-or-later
//! Protocol between the GUI/CLI and the OpenShield service.
//!
//! Stage 2: JSON-RPC over a named pipe whose ACL allows only Administrators
//! and the interactive user.

/// Named pipe the service listens on.
pub const PIPE_NAME: &str = r"\\.\pipe\openshield";

/// Bumped on every incompatible protocol change.
pub const PROTOCOL_VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_name_is_local_pipe() {
        assert!(PIPE_NAME.starts_with(r"\\.\pipe\"));
    }
}
