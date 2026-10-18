// SPDX-License-Identifier: GPL-3.0-or-later
//! `config.toml`: user-editable settings.

use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::lists;

/// Errors while reading or writing the configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid config {path}: {source}")]
    Parse {
        path: String,
        source: toml::de::Error,
    },
    #[error("cannot write {path}: {source}")]
    Write {
        path: String,
        source: std::io::Error,
    },
    #[error("cannot serialize config: {0}")]
    Serialize(#[from] toml::ser::Error),
}

/// Top-level configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub dns: DnsConfig,
    pub lists: ListsConfig,
    pub watchdog: WatchdogConfig,
}

impl Config {
    /// Loads the config, or returns defaults when the file does not exist.
    pub fn load_or_default(path: &Path) -> Result<Self, ConfigError> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(source) => {
                return Err(ConfigError::Read {
                    path: path.display().to_string(),
                    source,
                });
            }
        };
        toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.display().to_string(),
            source,
        })
    }

    /// Writes the config, creating parent directories.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        let text = toml::to_string_pretty(self)?;
        let write_err = |source| ConfigError::Write {
            path: path.display().to_string(),
            source,
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(write_err)?;
        }
        std::fs::write(path, text).map_err(write_err)
    }
}

/// How a blocked DNS query is answered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsBlockingMode {
    /// `A 0.0.0.0` / `AAAA ::`; other record types get an empty answer.
    #[default]
    NullIp,
    /// `NXDOMAIN` for every record type.
    Nxdomain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    pub enabled: bool,
    pub blocking_mode: DnsBlockingMode,
    /// TTL of forged answers, in seconds.
    pub blocked_ttl: u32,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            blocking_mode: DnsBlockingMode::NullIp,
            blocked_ttl: 10,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ListsConfig {
    /// Ids of enabled catalog lists (see [`lists::catalog`]).
    pub enabled: Vec<String>,
    /// Additional DNS lists by URL.
    pub custom: Vec<CustomList>,
    pub update_interval_hours: u32,
}

impl Default for ListsConfig {
    fn default() -> Self {
        Self {
            enabled: lists::catalog()
                .iter()
                .filter(|s| s.enabled_by_default)
                .map(|s| s.id.to_owned())
                .collect(),
            custom: Vec::new(),
            update_interval_hours: 24,
        }
    }
}

impl ListsConfig {
    pub fn update_interval(&self) -> Duration {
        Duration::from_secs(u64::from(self.update_interval_hours.max(1)) * 3600)
    }
}

/// A user-added list subscription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomList {
    /// File-name-safe identifier: `[a-z0-9-]`.
    pub id: String,
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WatchdogConfig {
    /// A packet that is not processed within this time counts as a hang:
    /// capture is released (fail open). Must exceed WinDivert's queue time.
    pub stall_timeout_ms: u64,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            stall_timeout_ms: 3000,
        }
    }
}

impl WatchdogConfig {
    pub fn stall_timeout(&self) -> Duration {
        Duration::from_millis(self.stall_timeout_ms.max(500))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_roundtrips_through_toml() -> Result<(), Box<dyn std::error::Error>> {
        let config = Config::default();
        let text = toml::to_string_pretty(&config)?;
        let parsed: Config = toml::from_str(&text)?;
        assert_eq!(parsed, config);
        Ok(())
    }

    #[test]
    fn partial_file_uses_defaults() -> Result<(), Box<dyn std::error::Error>> {
        let parsed: Config = toml::from_str("[dns]\nblocking_mode = \"nxdomain\"\n")?;
        assert_eq!(parsed.dns.blocking_mode, DnsBlockingMode::Nxdomain);
        assert!(parsed.dns.enabled);
        assert_eq!(parsed.lists, ListsConfig::default());
        Ok(())
    }

    #[test]
    fn unknown_keys_are_rejected() {
        assert!(toml::from_str::<Config>("[dns]\nblockng_mode = \"nxdomain\"\n").is_err());
    }

    #[test]
    fn missing_file_gives_defaults() -> Result<(), ConfigError> {
        let config = Config::load_or_default(Path::new("this/does/not/exist.toml"))?;
        assert_eq!(config, Config::default());
        Ok(())
    }
}
