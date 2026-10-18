// SPDX-License-Identifier: GPL-3.0-or-later
//! Layout of the data directory (`%ProgramData%\OpenShield` by default).

use std::path::{Path, PathBuf};

/// Root of OpenShield's data: config, cached lists, user rules.
///
/// Query history is never written here (privacy): statistics live in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataDir {
    root: PathBuf,
}

impl DataDir {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// `%ProgramData%\OpenShield`, or `.\dev-data` when `ProgramData` is unset.
    pub fn default_location() -> Self {
        match std::env::var_os("ProgramData") {
            Some(base) => Self::new(PathBuf::from(base).join(crate::PRODUCT_NAME)),
            None => Self::new("dev-data"),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn config_file(&self) -> PathBuf {
        self.root.join("config.toml")
    }

    /// Cached filter lists: `<id>.txt` plus `<id>.meta.toml`.
    pub fn lists_dir(&self) -> PathBuf {
        self.root.join("lists")
    }

    /// User rules in DNS filter syntax.
    pub fn user_rules_file(&self) -> PathBuf {
        self.root.join("user_rules.txt")
    }

    /// Domains that are never filtered (including subdomains), one per line.
    pub fn allowlist_file(&self) -> PathBuf {
        self.root.join("allowlist.txt")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_live_under_root() {
        let dir = DataDir::new("root");
        assert_eq!(dir.config_file(), Path::new("root").join("config.toml"));
        assert_eq!(dir.lists_dir(), Path::new("root").join("lists"));
        assert!(dir.user_rules_file().starts_with("root"));
        assert!(dir.allowlist_file().starts_with("root"));
    }
}
