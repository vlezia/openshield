# OpenShield architecture

OpenShield is a free, open-source, system-wide ad and tracker blocker for
Windows 10/11 x64. Filtering works for the whole PC, not just one browser:
DNS filtering for all processes, plus HTTPS filtering for selected
applications (browsers by default). It deliberately does nothing else: no VPN,
parental control or antivirus.

**Status:** stage 0 (skeleton). Components below are the target design; each
section says in which stage it lands.

## Principles

1. **Fail open.** If the core crashes or hangs, the user's internet keeps
   working. Availability beats blocking.
2. **The local root CA is security-critical.** See [SECURITY.md](SECURITY.md).
3. **No telemetry.** The only network traffic OpenShield originates is filter
   list downloads.
4. **Nothing changes the system without explicit consent** (CA install,
   service, driver, browser policies), and everything can be rolled back with
   `scripts/cleanup.ps1` or the uninstaller.

## Components

```
┌──────────────────────┐   named pipe (JSON-RPC)   ┌───────────────────────────────┐
│  GUI (Tauri v2 tray) │ ◄───────────────────────► │  openshield-service (LocalSys)│
│  on/off, statistics, │                           │  ├─ Filter engines            │
│  lists, rules, apps, │                           │  │   DNS: own domain matcher  │
│  log                 │                           │  │   HTTPS: adblock-rust      │
└──────────────────────┘                           │  ├─ DNS filter (WinDivert)    │
                                                   │  ├─ Transparent redirector    │
                                                   │  │   (WinDivert, TCP 80/443)  │
                                                   │  ├─ MITM proxy (hyper+rustls) │
                                                   │  │   + HTML injection (lol_html)│
                                                   │  ├─ Proxy watchdog            │
                                                   │  ├─ Cert manager (rcgen, CA)  │
                                                   │  └─ List updater (reqwest)    │
                                                   └───────────────────────────────┘
```

| Crate | Role | Stage |
|---|---|---|
| `crates/core` | DNS domain matcher, list download and cache, config, statistics. No WinAPI. | 1 |
| `crates/dns` | Parse captured DNS queries, forge answers for blocked domains. | 1 |
| `crates/intercept` | `trait Interceptor` and the WinDivert backend (DNS capture, TCP redirect, NAT table, PID attribution). | 0 (trait), 1, 3 |
| `crates/proxy` | MITM proxy, CA manager, adblock-rust network/cosmetic filtering, HTML injection. | 3 |
| `crates/ipc` | GUI/CLI ↔ service message types. | 2 |
| `crates/service` | Windows service binary, `--console` mode for development. | 1, 2 |
| `crates/cli` | `openshield-cli`: status, enable/disable, lists update, test URL. | 1, 2 |
| `gui/` | Tauri v2 + React + TypeScript tray app. | 2 |

### DNS filtering (stage 1)

WinDivert captures outgoing DNS queries (UDP/TCP 53). For a blocked domain we
inject a forged answer (`0.0.0.0` / `::` or NXDOMAIN, configurable) and drop
the original; everything else is reinjected unchanged. We do not run our own
DNS server and do not touch adapter settings, so when the process dies the
driver releases the traffic. `DnsFlushResolverCache` runs after filtering is
toggled.

### HTTPS filtering (stage 3)

1. WinDivert at the `NETWORK` layer reflects TCP 80/443 of selected processes
   to the local proxy (the `streamdump` technique: NAT table keyed by source
   port → original destination). Our own process is always excluded.
2. The proxy reads SNI, issues a leaf certificate signed by the local CA (LRU
   cache), and connects upstream with strict verification against the system
   store (`rustls-platform-verifier`). HTTP/1.1 and HTTP/2 via ALPN.
3. Requests are checked against adblock-rust network rules (resource type,
   source URL / Referer); blocked ones get an empty response of the right type.
4. `text/html` responses (decompressed, charset-aware) get a `<style>` with
   cosmetic rules and a `<script>` with scriptlets, streamed through
   `lol_html`. CSP is adjusted only for our injection's nonce/hash.
5. UDP 443 (QUIC) is blocked for filtered apps so browsers fall back to TCP.
6. Pinned and sensitive domains (banks, government services, Windows Update,
   Microsoft/Apple sign-in, AV updates) are tunnelled without MITM by default.
7. Filtered apps by default: Chrome, Edge, Firefox, Opera, Brave, Vivaldi,
   Yandex Browser. Games, launchers, anti-cheat and system processes are
   covered by DNS filtering only.

## Decision records

Short ADRs. Status values: *Accepted*, *Proposed*, *Superseded by ADR-NNN*.

### ADR-001: Own domain matcher for DNS; adblock-rust only for HTTPS

- **Status:** Accepted (2026-10-18)
- **Context:** DNS lists (AdGuard DNS filter, hosts files) use DNS-specific
  syntax (`$dnsrewrite`, `$client`, `$dnstype`, `$important`) that adblock-rust
  does not support. adblock-rust also expects a full request (URL, source URL,
  resource type), which a DNS query does not have.
- **Decision:** `crates/core` gets a small domain matcher: `||domain^`,
  `@@||domain^`, hosts-file lines (`0.0.0.0 domain`) and plain domains, matched
  by walking domain suffixes in a hash set. Unsupported modifiers are skipped
  and counted. adblock-rust is used only by the HTTPS proxy.
- **Consequences:** Two engines and two list parsers to maintain, but each is
  simple and correct for its layer. DNS matching stays fast and predictable.

### ADR-002: Mitigate DNS-over-HTTPS bypass

- **Status:** Accepted (2026-10-18)
- **Context:** Chrome and Edge auto-upgrade to DoH when the system resolver is
  a known DoH provider (Google, Cloudflare, …); Firefox has its own DoH (TRR).
  Such queries never hit port 53, so the DNS filter does not see them.
- **Decision:** Stage 1 blocks resolution of well-known DoH endpoints and the
  Firefox canary domain `use-application-dns.net`, which makes browsers fall
  back to system DNS. In stage 3 filtered browsers go through the proxy anyway.
  The remaining gap is documented in the README.
- **Consequences:** Browsers with DoH configured by hand to an unknown
  provider can still bypass DNS filtering. We do not change browser DoH
  policies without consent.

### ADR-003: Attribute connections to processes via the WinDivert SOCKET layer

- **Status:** Accepted (2026-10-18)
- **Context:** The redirector must know the process of a connection before its
  first packet (SYN) to decide whether to redirect it. `FLOW_ESTABLISHED`
  events can arrive after the first packets, which causes races.
- **Decision:** Use the `SOCKET` layer `CONNECT` event, which fires before the
  SYN, to fill a (local addr, local port, protocol) → PID table. Unknown flows
  are passed through unfiltered (fail open).
- **Consequences:** One more WinDivert handle. Entries must expire on
  `CLOSE` events and by TTL to keep the table bounded.

### ADR-004: Proxy watchdog for hangs

- **Status:** Accepted (2026-10-18)
- **Context:** WinDivert fails open when our process dies (the handle closes),
  but not when the proxy hangs: traffic is still redirected into a proxy that
  no longer answers.
- **Decision:** A watchdog thread, independent of the proxy's async runtime,
  checks proxy health periodically (accepting and answering a loopback
  connection within a deadline). On failure it closes the redirect handle so
  traffic flows directly, logs the event and tries to restart the proxy.
- **Consequences:** A brief window of unfiltered traffic after a hang, which is
  acceptable under the fail-open principle. Health check deadline and interval
  are configurable.

### ADR-005: Antivirus false positives and code signing

- **Status:** Accepted (2026-10-18)
- **Context:** Several AV products flag WinDivert as HackTool/RiskWare. This is
  confirmed on the development machine: on 2026-10-18 Microsoft Defender
  blocked `WinDivert-2.2.2-A.zip` from the official GitHub release as
  `Misleading:Win32/Malgent!AMTB`. Unsigned executables also trigger
  SmartScreen and can be blocked by Smart App Control on Windows 11.
- **Decision:** Document the issue in the README and BUILDING.md; never ask
  users to disable their AV, only to allow the specific file if they choose to;
  report false positives to vendors (Microsoft WDSI first) on each release. By
  stage 4, sign our executables and installer. Evaluate **SignPath
  Foundation** (free code signing for OSS projects, GitHub Actions
  integration) first; check its eligibility rules and the reputation it builds
  with SmartScreen. Alternatives: Azure Trusted Signing, a commercial
  certificate.
- **Consequences:** Release builds must be reproducible from CI so a signing
  service can sign them. The WinDivert driver keeps its own upstream
  signature; we cannot change how AV treats it.

### ADR-006: Cleanup touches only OpenShield's own artifacts

- **Status:** Accepted (2026-10-18)
- **Context:** The WinDivert driver service is shared: other software (for
  example zapret and GoodbyeDPI) installs and uses the same driver.
- **Decision:** `scripts/cleanup.ps1` and the uninstaller remove only our CA
  certificates, the `OpenShield` service, our browser policy keys and our data
  directory. They never stop or delete the `WinDivert` driver service; the
  driver unloads by itself once no handle is open.
- **Consequences:** A WinDivert driver service entry may remain after
  uninstall if no other software removes it. This is documented.

### ADR-007: CA private key storage

- **Status:** Accepted (2026-10-18)
- **Context:** DPAPI with LocalMachine scope can be decrypted by any process
  on the machine, so it only protects the key at rest from offline copying.
  The real access control is the file ACL.
- **Decision:** v1 stores the CA key DPAPI-encrypted (LocalMachine) in
  `%ProgramData%\OpenShield\` with an ACL for SYSTEM and Administrators only.
  Later, move the key into a non-exportable CNG key (Microsoft Software KSP,
  machine key) and sign leaf certificates through it.
- **Consequences:** v1 protection equals "administrator-only", which is the
  same trust level as the root store itself. The CNG migration needs a custom
  signer for `rcgen`.

### ADR-008: Scriptlet resources and filter list licensing

- **Status:** Accepted (2026-10-18), resource source to be verified in stage 3
- **Context:** uBlock Origin now ships scriptlets as ES modules, which
  adblock-rust probably cannot load directly. Filter lists have different
  licenses (GPL-3.0, CC BY-SA, MIT, custom terms such as Peter Lowe's list).
- **Decision:** Stage 3 evaluates `brave/adblock-resources` as the
  prebuilt resource set for `use_resources`. Lists are downloaded by the user's
  machine from their original URLs. The bundled offline fallback set includes
  only lists whose license allows redistribution with a GPL-3.0 program;
  licenses are listed in `THIRD_PARTY_NOTICES.md`.
- **Consequences:** Some lists are subscription-only (no bundled copy). The
  fallback set is smaller than the default subscriptions.

## Future (not now)

Linux (nftables + TPROXY), macOS (Network Extension), scheduled filtering,
DoH upstream support.
