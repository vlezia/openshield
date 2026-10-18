// SPDX-License-Identifier: GPL-3.0-or-later
//! HTTPS filtering: MITM proxy, local CA manager and HTML injection.
//!
//! Implemented in stage 3. See `docs/ARCHITECTURE.md` and `docs/SECURITY.md`
//! for the CA and upstream-verification rules this crate must follow.

/// Prefix of the local root CA subject; the full subject is
/// `OpenShield Local CA — <hostname>`. `scripts/cleanup.ps1` finds our CA by it.
pub const CA_SUBJECT_PREFIX: &str = "OpenShield Local CA";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_subject_prefix_names_the_product() {
        assert!(CA_SUBJECT_PREFIX.starts_with("OpenShield"));
    }
}
