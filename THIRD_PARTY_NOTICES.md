# Third-party notices

OpenShield is licensed under GPL-3.0-or-later. It uses or downloads the
components below. Rust crate dependencies and their licenses will be generated
from `Cargo.lock` before each release.

## Bundled or fetched binaries

| Component | Version | License | Source |
|---|---|---|---|
| WinDivert | 2.2.2 | LGPL-3.0-or-later or GPL-2.0-or-later | https://github.com/basil00/WinDivert |

WinDivert is loaded at runtime from its official DLL; no WinDivert code is
compiled into OpenShield (ADR-009).

## Main Rust libraries

| Crate | License | Used for |
|---|---|---|
| tokio | MIT | async runtime |
| reqwest, rustls (ring), rustls-platform-verifier | MIT/Apache-2.0, Apache-2.0/ISC/MIT | filter list downloads over HTTPS |
| hickory-proto | MIT OR Apache-2.0 | DNS message parsing/encoding |
| etherparse | MIT OR Apache-2.0 | IP/UDP/TCP packet parsing and building |
| libloading | ISC | runtime loading of WinDivert.dll |
| arc-swap | MIT OR Apache-2.0 | lock-free policy swap |
| windows-registry | MIT OR Apache-2.0 | DoH detection (read-only) |
| serde, toml, clap, thiserror, tracing | MIT OR Apache-2.0 | config, CLI, errors, logging |

Planned: adblock-rust (`adblock` crate, MPL-2.0) for HTTPS filtering.

## Filter lists

Filter lists are downloaded by the user's machine from their original URLs.
Only lists marked "bundled" are shipped as an offline fallback (see ADR-008).

| List | Source | License | Bundled |
|---|---|---|---|
| AdGuard DNS filter | adguardteam.github.io/AdGuardSDNSFilter | GPL-3.0 | no |
| Peter Lowe's Blocklist | pgl.yoyo.org, via AdGuard HostlistsRegistry mirror | custom terms (see pgl.yoyo.org) | no |
| StevenBlack Unified hosts | github.com/StevenBlack/hosts | MIT | no |
| OpenShield DoH resolvers | `filters/dns/openshield-doh.txt` (this repository) | GPL-3.0-or-later | yes (built in) |
