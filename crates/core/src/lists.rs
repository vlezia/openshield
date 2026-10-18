// SPDX-License-Identifier: GPL-3.0-or-later
//! Filter list catalog, download and on-disk cache.
//!
//! Lists are downloaded from their original URLs with conditional requests
//! (`If-None-Match` / `If-Modified-Since`). A failed download never replaces
//! the cached copy.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::StatusCode;
use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use serde::{Deserialize, Serialize};

use crate::config::ListsConfig;

/// Largest list we accept, to bound memory and disk use.
pub const MAX_LIST_BYTES: usize = 64 * 1024 * 1024;

/// Where a list comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListSource {
    Url(String),
    /// Compiled into the binary.
    Embedded(&'static str),
}

/// A list known to OpenShield.
#[derive(Debug, Clone, Copy)]
pub struct CatalogEntry {
    pub id: &'static str,
    pub name: &'static str,
    pub url: Option<&'static str>,
    pub embedded: Option<&'static str>,
    pub license: &'static str,
    pub enabled_by_default: bool,
}

const OPENSHIELD_DOH: &str = include_str!("../../../filters/dns/openshield-doh.txt");

static CATALOG: [CatalogEntry; 4] = [
    CatalogEntry {
        id: "adguard-dns",
        name: "AdGuard DNS filter",
        url: Some("https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"),
        embedded: None,
        license: "GPL-3.0",
        enabled_by_default: true,
    },
    CatalogEntry {
        id: "peter-lowe",
        name: "Peter Lowe's Blocklist",
        // AdGuard's HostlistsRegistry mirror in "||domain^" form; pgl's own
        // "adblock" format uses "*.domain" lines, which we cannot apply.
        url: Some("https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt"),
        embedded: None,
        license: "custom (see pgl.yoyo.org; not bundled)",
        enabled_by_default: true,
    },
    CatalogEntry {
        id: "stevenblack-unified",
        name: "StevenBlack Unified hosts",
        url: Some("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"),
        embedded: None,
        license: "MIT",
        enabled_by_default: true,
    },
    CatalogEntry {
        id: "openshield-doh",
        name: "OpenShield: known DNS-over-HTTPS resolvers",
        url: None,
        embedded: Some(OPENSHIELD_DOH),
        license: "GPL-3.0-or-later",
        enabled_by_default: true,
    },
];

/// All lists OpenShield knows about.
pub fn catalog() -> &'static [CatalogEntry] {
    &CATALOG
}

/// An enabled list, from the catalog or user-added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub source: ListSource,
}

/// Enabled subscriptions in config order. Unknown or invalid ids are skipped
/// and returned separately so the caller can warn about them.
pub fn subscriptions(config: &ListsConfig) -> (Vec<Subscription>, Vec<String>) {
    let mut subs = Vec::new();
    let mut invalid = Vec::new();
    for id in &config.enabled {
        match catalog().iter().find(|e| e.id == id) {
            Some(entry) => subs.push(Subscription {
                id: entry.id.to_owned(),
                name: entry.name.to_owned(),
                source: match (entry.url, entry.embedded) {
                    (_, Some(text)) => ListSource::Embedded(text),
                    (Some(url), None) => ListSource::Url(url.to_owned()),
                    (None, None) => unreachable!("catalog entry without source"),
                },
            }),
            None => invalid.push(id.clone()),
        }
    }
    for custom in &config.custom {
        let id_ok = !custom.id.is_empty()
            && custom
                .id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        let url_ok = custom.url.starts_with("https://") || custom.url.starts_with("http://");
        if id_ok && url_ok && !subs.iter().any(|s| s.id == custom.id) {
            subs.push(Subscription {
                id: custom.id.clone(),
                name: custom.name.clone(),
                source: ListSource::Url(custom.url.clone()),
            });
        } else {
            invalid.push(custom.id.clone());
        }
    }
    (subs, invalid)
}

/// Cache metadata stored next to a downloaded list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListMeta {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// Last successful check (download or 304), seconds since the Unix epoch.
    pub checked_at: u64,
    pub bytes: u64,
}

impl ListMeta {
    fn is_fresh(&self, max_age: Duration) -> bool {
        unix_now().saturating_sub(self.checked_at) < max_age.as_secs()
    }
}

/// Result of updating one list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    Updated {
        bytes: u64,
    },
    NotModified,
    /// Checked recently enough; nothing requested.
    Fresh,
    /// Compiled into the binary; never downloaded.
    Embedded,
    /// Download failed; the cached copy (if any) is kept.
    Failed(String),
}

/// Builds the HTTP client used for list downloads.
pub fn http_client() -> Result<reqwest::Client, reqwest::Error> {
    // reqwest is built with `rustls-no-provider`; ring is our provider.
    // Installing twice is harmless (the second call returns Err).
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .user_agent(concat!(
            "OpenShield/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/vlezia/openshield)"
        ))
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(120))
        .build()
}

fn list_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.txt"))
}

fn meta_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.meta.toml"))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Reads cache metadata; missing or corrupt metadata counts as "never fetched".
pub fn read_meta(dir: &Path, id: &str) -> ListMeta {
    std::fs::read_to_string(meta_path(dir, id))
        .ok()
        .and_then(|text| toml::from_str(&text).ok())
        .unwrap_or_default()
}

/// Returns the list text: embedded text, or the cached download.
pub fn read_cached(dir: &Path, sub: &Subscription) -> Option<String> {
    match &sub.source {
        ListSource::Embedded(text) => Some((*text).to_owned()),
        ListSource::Url(_) => std::fs::read_to_string(list_path(dir, &sub.id)).ok(),
    }
}

/// Downloads `sub` into `dir` unless it was checked within `max_age`
/// (`None` forces a conditional request).
pub async fn update_list(
    client: &reqwest::Client,
    dir: &Path,
    sub: &Subscription,
    max_age: Option<Duration>,
) -> UpdateOutcome {
    let url = match &sub.source {
        ListSource::Embedded(_) => return UpdateOutcome::Embedded,
        ListSource::Url(url) => url,
    };
    let meta = read_meta(dir, &sub.id);
    let have_cache = list_path(dir, &sub.id).exists();
    if have_cache && max_age.is_some_and(|age| meta.is_fresh(age)) {
        return UpdateOutcome::Fresh;
    }
    match download(client, url, have_cache.then_some(&meta)).await {
        Ok(Download::NotModified) => {
            let meta = ListMeta {
                checked_at: unix_now(),
                ..meta
            };
            match write_meta(dir, &sub.id, &meta) {
                Ok(()) => UpdateOutcome::NotModified,
                Err(e) => UpdateOutcome::Failed(format!("cannot write metadata: {e}")),
            }
        }
        Ok(Download::Body {
            text,
            etag,
            last_modified,
        }) => {
            let meta = ListMeta {
                etag,
                last_modified,
                checked_at: unix_now(),
                bytes: text.len() as u64,
            };
            match store(dir, &sub.id, &text, &meta) {
                Ok(()) => UpdateOutcome::Updated { bytes: meta.bytes },
                Err(e) => UpdateOutcome::Failed(format!("cannot write cache: {e}")),
            }
        }
        Err(e) => UpdateOutcome::Failed(e),
    }
}

enum Download {
    NotModified,
    Body {
        text: String,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

async fn download(
    client: &reqwest::Client,
    url: &str,
    cached: Option<&ListMeta>,
) -> Result<Download, String> {
    let mut request = client.get(url);
    if let Some(meta) = cached {
        if let Some(etag) = &meta.etag {
            request = request.header(IF_NONE_MATCH, etag);
        }
        if let Some(lm) = &meta.last_modified {
            request = request.header(IF_MODIFIED_SINCE, lm);
        }
    }
    let mut response = request.send().await.map_err(|e| e.to_string())?;
    let status = response.status();
    if status == StatusCode::NOT_MODIFIED {
        return Ok(Download::NotModified);
    }
    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }
    let header = |name| {
        response
            .headers()
            .get(name)
            .and_then(|v: &reqwest::header::HeaderValue| v.to_str().ok())
            .map(str::to_owned)
    };
    let etag = header(ETAG);
    let last_modified = header(LAST_MODIFIED);

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if body.len() + chunk.len() > MAX_LIST_BYTES {
            return Err(format!("list is larger than {MAX_LIST_BYTES} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    let text = String::from_utf8_lossy(&body).into_owned();
    let head = text
        .trim_start()
        .get(..15)
        .unwrap_or("")
        .to_ascii_lowercase();
    if head.starts_with("<!doctype") || head.starts_with("<html") {
        // Captive portals and error pages must not replace a good list.
        return Err("server returned an HTML page instead of a filter list".to_owned());
    }
    Ok(Download::Body {
        text,
        etag,
        last_modified,
    })
}

fn write_meta(dir: &Path, id: &str, meta: &ListMeta) -> std::io::Result<()> {
    let text = toml::to_string(meta).map_err(std::io::Error::other)?;
    write_atomic(&meta_path(dir, id), text.as_bytes())
}

fn store(dir: &Path, id: &str, text: &str, meta: &ListMeta) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    write_atomic(&list_path(dir, id), text.as_bytes())?;
    write_meta(dir, id, meta)
}

/// Writes to a temporary file and renames it over the target.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("openshield-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// Serves canned HTTP responses, one per connection, and reports the
    /// request headers it received.
    fn serve(responses: Vec<String>) -> (String, mpsc::Receiver<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for response in responses {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut headers = Vec::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    headers.push(line.trim_end().to_ascii_lowercase());
                }
                let _ = tx.send(headers);
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (format!("http://{addr}/list.txt"), rx)
    }

    fn ok_response(body: &str, etag: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nETag: {etag}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn sub(url: String) -> Subscription {
        Subscription {
            id: "test".to_owned(),
            name: "Test".to_owned(),
            source: ListSource::Url(url),
        }
    }

    #[tokio::test]
    async fn download_then_not_modified_then_failure_keeps_cache() {
        let dir = temp_dir("lists-cycle");
        let (url, headers) = serve(vec![
            ok_response("||ads.example^\n", "\"v1\""),
            "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".to_owned(),
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_owned(),
        ]);
        let client = http_client().expect("client");
        let sub = sub(url);

        let first = update_list(&client, &dir, &sub, None).await;
        assert_eq!(first, UpdateOutcome::Updated { bytes: 15 });
        assert_eq!(read_meta(&dir, "test").etag.as_deref(), Some("\"v1\""));

        let second = update_list(&client, &dir, &sub, None).await;
        assert_eq!(second, UpdateOutcome::NotModified);
        let second_headers = headers.iter().nth(1).expect("second request");
        assert!(second_headers.iter().any(|h| h == "if-none-match: \"v1\""));

        let third = update_list(&client, &dir, &sub, None).await;
        assert!(matches!(third, UpdateOutcome::Failed(_)));
        assert_eq!(read_cached(&dir, &sub).as_deref(), Some("||ads.example^\n"));

        let fresh = update_list(&client, &dir, &sub, Some(Duration::from_secs(3600))).await;
        assert_eq!(fresh, UpdateOutcome::Fresh);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn html_page_does_not_replace_list() {
        let dir = temp_dir("lists-html");
        let (url, _headers) = serve(vec![ok_response("<!DOCTYPE html><p>login</p>", "\"x\"")]);
        let client = http_client().expect("client");
        let outcome = update_list(&client, &dir, &sub(url), None).await;
        assert!(matches!(outcome, UpdateOutcome::Failed(_)));
        assert!(!list_path(&dir, "test").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_config_resolves_all_catalog_defaults() {
        let (subs, invalid) = subscriptions(&ListsConfig::default());
        assert!(invalid.is_empty());
        assert_eq!(
            subs.len(),
            catalog().iter().filter(|e| e.enabled_by_default).count()
        );
        assert!(
            subs.iter()
                .any(|s| matches!(s.source, ListSource::Embedded(_)))
        );
    }

    #[test]
    fn invalid_custom_lists_are_reported() {
        let config = ListsConfig {
            enabled: vec!["nope".to_owned()],
            custom: vec![crate::config::CustomList {
                id: "Bad Id".to_owned(),
                name: "x".to_owned(),
                url: "https://example.org/list.txt".to_owned(),
            }],
            update_interval_hours: 24,
        };
        let (subs, invalid) = subscriptions(&config);
        assert!(subs.is_empty());
        assert_eq!(invalid, vec!["nope".to_owned(), "Bad Id".to_owned()]);
    }
}
