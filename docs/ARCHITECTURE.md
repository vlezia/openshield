# OpenShield architecture

OpenShield is a free, open-source, system-wide ad and tracker blocker for
Windows 10/11 x64. Filtering works for the whole PC, not just one browser:
DNS filtering for all processes, plus HTTPS filtering for selected
applications (browsers by default). It deliberately does nothing else: no VPN,
parental control or antivirus.

**Status:** stage 1 (DNS filtering in console mode). Components below are the
target design; each section says in which stage it lands.

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
| `crates/core` | Config, list catalog/download/cache, DNS domain matcher, in-memory statistics, watchdog. No WinAPI. | 1 ✅ |
| `crates/dns` | Per-packet DNS decisions (forged answers, TCP RST) and the packet loop. | 1 ✅ |
| `crates/intercept` | `trait Interceptor`, mock for tests, WinDivert backend loaded at runtime. Later: TCP redirect, NAT table, PID attribution. | 1 ✅, 3 |
| `crates/proxy` | MITM proxy, CA manager, adblock-rust network/cosmetic filtering, HTML injection. | 3 |
| `crates/ipc` | GUI/CLI ↔ service message types. | 2 |
| `crates/service` | `--console` mode (stage 1); Windows service (stage 2). | 1 ✅, 2 |
| `crates/cli` | `openshield-cli`: `lists update/show/lint`, `test <domain>`; status/enable/disable in stage 2. | 1 ✅, 2 |
| `gui/` | Tauri v2 + React + TypeScript tray app. | 2 |

### DNS filtering (stage 1)

```
app ──DNS query──► Windows network stack ──► WinDivert (outbound, UDP/TCP 53, !loopback)
                                                  │
                                    openshield-dns packet loop (hot path:
                                    no I/O, no locks; heartbeat per packet)
                                       │                        │
                              not blocked: reinject     blocked: drop original,
                                                        inject forged answer
                                                        (UDP) or RST (TCP)
watchdog thread: packet "in progress" > stall timeout → WinDivertShutdown → fail open
```

WinDivert captures outgoing DNS queries (filter in `openshield_dns::WINDIVERT_FILTER`).
For a blocked domain we inject a forged answer from the DNS server's address
(`0.0.0.0` / `::`, empty answer for other record types, or NXDOMAIN —
configurable) and drop the original; for DNS over TCP we reset the connection
(ADR-011). Everything else is reinjected unchanged. We do not run our own DNS
server and do not touch adapter settings, so when the process dies or the
handle is shut down the driver releases the traffic. `DnsFlushResolverCache`
runs when filtering starts and stops.

Data directory (`%ProgramData%\OpenShield`, or `--data-dir`): `config.toml`,
`lists/<id>.txt` + `<id>.meta.toml`, `user_rules.txt`, `allowlist.txt`. No
query history is stored (ADR-010).

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
- **Decision:** `crates/core` gets its own domain matcher (two hash maps,
  lookups walk the domain suffixes; ~0.1 s to load ~260k domains). Semantics
  follow the [AdGuard DNS filtering syntax](https://adguard-dns.io/kb/general/dns-filtering-syntax/)
  (checked 2026-10-18):
  - `||example.org^` blocks the domain **and subdomains**; `@@` allows them.
  - Hosts lines (`0.0.0.0 example.org`) and bare domains (`example.org`) match
    **exactly**, without subdomains. Only `0.0.0.0`, `::` and loopback
    addresses block; other addresses are rewrites in AdGuard Home and are
    skipped. `localhost`-style names are ignored.
  - `$important` beats non-important rules including exceptions;
    `@@...$important` beats `...$important`.
  - `$badfilter` disables rules with the same pattern, exception flag and
    `$important` flag (a structural match instead of AdGuard's textual one;
    differences only in modifier order are therefore ignored). Hosts rules
    are not affected, as in AdGuard.
  - Any other modifier (`$client`, `$dnsrewrite`, `$dnstype`, `$denyallow`,
    `$ctag`, `$third-party`, …) makes us **skip the whole rule**, as the
    AdGuard docs require for unknown modifiers; it is never turned into a
    plain block.
  - `||example.org` without `^` is matched like `||example.org^`. AdGuard also
    matches continuations such as `example.org.cn`, so we block a strict
    subset of what AdGuard blocks, never more.
  - Regular expressions, wildcards (`*`), `||example.` TLD wildcards,
    leading-dot and other substring patterns, `|` anchors and cosmetic rules
    are skipped and counted as unsupported (`openshield-cli lists lint`).
  - Priority, strongest first: allowlist (domain + subdomains), user rules,
    filter lists; within a group `@@$important`, `$important`, `@@`, block.
  adblock-rust is used only by the HTTPS proxy.
- **Consequences:** Two engines and two list parsers to maintain, but each is
  simple and correct for its layer. DNS matching stays fast and predictable.
  About 0.3 % of AdGuard DNS filter lines (mostly wildcards and regexes) are
  skipped today; wildcard support can be added later without changing
  semantics of the rest.

### ADR-002: Mitigate DNS-over-HTTPS bypass

- **Status:** Accepted (2026-10-18)
- **Context:** Chrome and Edge auto-upgrade to DoH when the system resolver is
  a known DoH provider (Google, Cloudflare, …); Firefox has its own DoH (TRR).
  Such queries never hit port 53, so the DNS filter does not see them.
- **Decision:** Stage 1 blocks resolution of well-known DoH endpoints (the
  built-in `openshield-doh` list, `filters/dns/openshield-doh.txt`) so browsers
  fall back to system DNS. The Firefox canary domain `use-application-dns.net`
  is always answered with **NXDOMAIN** (a `0.0.0.0` answer would not disable
  Firefox's DoH). In stage 3 filtered browsers go through the proxy anyway.
  Windows 11's own DoH sends system queries over HTTPS too; at startup the
  service looks for signs of it (`DoHPolicy` policy, `EnableAutoDoh`,
  `DohFlags` of well-known servers, per-interface `DohInterfaceSettings`) and
  warns that the DNS filter cannot see those queries. There is no official API
  for this, so the check is best-effort.
- **Consequences:** Browsers with DoH configured by hand to an unknown
  provider, and system DoH configurations the heuristic misses, can still
  bypass DNS filtering. We do not change browser or system DoH settings
  without consent.

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

### ADR-004: Watchdogs for hangs (packet loops and proxy)

- **Status:** Accepted (2026-10-18); packet-loop part implemented in stage 1
- **Context:** WinDivert fails open when our process dies (the handle closes),
  but not when we hang: diverted packets queue up for a loop that no longer
  processes them, and DNS (later: redirected TCP) stops working.
- **Decision:**
  - **Packet loops (stage 1).** The hot loop does no network or disk I/O and
    takes no locks: policy is read via `ArcSwap`, statistics via atomics and a
    non-blocking channel. Each packet is bracketed by `Heartbeat::begin/end`
    (atomic stores). A separate watchdog thread checks every timeout/4; if a
    packet has been in progress longer than `watchdog.stall_timeout_ms`
    (default 3000 ms, above WinDivert's default queue time), it calls
    `WinDivertShutdown`, so the driver stops diverting and traffic flows
    unfiltered. An idle loop waiting for packets is not a stall. In console
    mode the process then exits with code 2; the stuck thread never touches a
    closed handle because the handle is only closed on drop.
  - **Proxy (stage 3).** Same mechanism for the redirect loop, plus a health
    check of the proxy (accept and answer a loopback connection within a
    deadline); on failure the redirect handle is shut down and the proxy
    restarted.
  - A `fault-injection` cargo feature (development only) adds
    `--debug-stall-after N` to simulate a hang for manual testing.
- **Consequences:** A brief window of unfiltered traffic after a hang, which is
  acceptable under the fail-open principle. Packets held by the stuck loop at
  that moment are lost; DNS clients retry.

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

### ADR-009: Load WinDivert at runtime with minimal own bindings

- **Status:** Accepted (2026-10-18)
- **Context:** Linking WinDivert statically (the `vendored`/`static` features
  of the `windivert` crates) would put WinDivert code into our executables,
  which antivirus products already flag (ADR-005). Linking dynamically through
  an import library needs `WinDivert.lib` at build time, so CI and every
  contributor would have to download WinDivert just to compile. The
  `windivert` crate (0.6.0) had its last release in 2025 and few users.
- **Decision:** `crates/intercept` loads the official signed `WinDivert.dll`
  at runtime with `libloading`, by absolute path from an explicit directory
  (`--windivert-dir`, default: next to the executable), with dependency
  search limited to that directory and System32. We bind the eight functions
  we use (`WinDivertOpen/Recv/Send/Shutdown/Close/GetParam`,
  `WinDivertHelperCalcChecksums`) and define `WINDIVERT_ADDRESS` ourselves
  (size checked at compile time). Packet building and parsing stay in pure
  Rust (`etherparse`), so all filtering logic is testable without the driver.
  Only WinDivert 2.x drivers are accepted.
- **Consequences:** A small `unsafe` FFI surface to maintain (one module, each
  block with a SAFETY comment). Builds and tests need no WinDivert files. The
  directory holding the DLL must not be writable by non-administrators once
  the service runs as SYSTEM (installer, stage 4).

### ADR-010: Statistics in memory only

- **Status:** Accepted (2026-10-18)
- **Context:** DNS queries reveal browsing history.
- **Decision:** Totals and per-domain counters (bounded to 20,000 domains,
  least-seen evicted) live in memory only and disappear when the process
  exits. No query log is written to disk by default; console output (top
  domains, debug logs) goes to the terminal only. A persistent blocked-request
  log for the GUI (stage 2) will be opt-in, bounded and clearable.
- **Consequences:** Statistics reset on restart. Diagnosing a problem after
  the fact needs the user to reproduce it.

### ADR-011: DNS over TCP: reset instead of forged answers

- **Status:** Accepted (2026-10-18)
- **Context:** Forging a DNS answer inside an existing TCP stream needs exact
  sequence handling and breaks easily; DNS over TCP is rare for normal
  lookups.
- **Decision:** Only TCP segments to port 53 with payload are diverted (the
  handshake is never touched). Queries may be split across segments (e.g.
  the 2-byte length prefix and the message sent separately), so the loop
  keeps a small per-flow reassembly buffer (owned by the loop thread, at most
  256 flows and 4 KiB per query, stale entries dropped after 10 s). Segments
  before the one completing a query pass unchanged. If the completed query is
  for a blocked domain, the completing segment is dropped and a `RST|ACK` is
  sent to the client (seq = the segment's ack number, ack = segment seq +
  payload length). Out-of-order segments restart reassembly; anything we
  cannot reassemble passes (fail open).
- **Consequences:** Blocked names fail to resolve over TCP instead of
  resolving to `0.0.0.0`. The server may already have received the first
  bytes of the query; it times out the connection on its own.
- **Update 2026-10-19:** the first version only handled single-segment
  queries; the manual check `nslookup -vc doubleclick.net` returned real
  addresses, so reassembly was added.

## Future (not now)

Linux (nftables + TPROXY), macOS (Network Extension), scheduled filtering,
DoH upstream support.
