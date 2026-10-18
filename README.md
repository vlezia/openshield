# OpenShield

Free, open-source, system-wide ad and tracker blocker for Windows 10/11.

OpenShield filters ads and trackers for the whole PC, not only inside one
browser: DNS filtering for every application, plus HTTPS filtering (network
rules, cosmetic filters, scriptlets) for selected applications — browsers by
default. It does one thing; there is no VPN, parental control or antivirus.

> **Status: early development (stage 0 — project skeleton).** Nothing is
> usable yet. Do not install development builds on a machine you depend on.

## Planned features

- DNS blocking for all apps, with forged `0.0.0.0` / NXDOMAIN answers
- HTTPS filtering for chosen apps with a per-PC local root CA (opt-in)
- EasyList, EasyPrivacy, uBlock Origin, AdGuard and regional filter lists
- Custom rules, allowlist ("don't filter this site"), blocked-request log
- Tray GUI; Windows service; fail-open design: if OpenShield breaks, your
  internet keeps working
- No telemetry

## Roadmap

| Stage | Scope |
|---|---|
| 0 | Workspace, CI, docs, dev scripts |
| 1 | Filter lists, DNS blocking via WinDivert, console mode, statistics |
| 2 | Windows service, IPC, Tauri tray GUI |
| 3 | HTTPS filtering: CA, MITM proxy, transparent redirect, cosmetics, scriptlets |
| 4 | Installer, uninstaller, first-run wizard, localization (en, ru, it, uk) |

## Known limitations

- Ads served from the same domain as content (e.g. YouTube) cannot be blocked
  by DNS alone; HTTPS filtering helps but is not complete.
- Apps that use certificate pinning are not HTTPS-filtered (DNS only).
- Browsers configured to use DNS-over-HTTPS with a custom provider can bypass
  DNS filtering (see ADR-002).
- Some antivirus products flag the WinDivert packet capture driver as a
  potentially unwanted tool (see ADR-005).

## Documentation

- [Architecture and decision records](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY.md)
- [Building](docs/BUILDING.md)

## License

Copyright (C) 2026 Vlezia and OpenShield contributors

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. See [LICENSE](LICENSE).

Third-party components and filter lists are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
