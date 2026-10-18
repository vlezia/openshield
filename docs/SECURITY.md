# Security

OpenShield's HTTPS filtering installs a local root certificate authority and
decrypts TLS traffic of selected applications. Done wrong, that would weaken
the security of every HTTPS connection on the machine. This document lists the
rules the code must follow.

## Reporting a vulnerability

Please do **not** open a public issue. Use GitHub's private vulnerability
reporting ("Security" tab → "Report a vulnerability") on the repository. We aim
to acknowledge reports within 7 days.

## Threat model (summary)

| Asset | Threat | Mitigation |
|---|---|---|
| CA private key | Theft → attacker can impersonate any site to this PC | Generated locally per PC, never shipped; DPAPI + ACL (SYSTEM, Administrators); see ADR-007 |
| CA certificate | Lingers after uninstall | Removed by uninstaller and `scripts/cleanup.ps1` from all stores |
| Upstream TLS | Real MITM attack hidden by our re-signing | Strict upstream verification; on failure the user gets an error page, never our certificate |
| IPC pipe | Unprivileged process reconfigures filtering | Pipe ACL: Administrators + interactive user; config changes only from them |
| Filter lists | Code execution from a malicious list | Lists are data; only scriptlets from the trusted resource set are injected |
| Packet capture | Process hang breaks networking | Fail open; proxy watchdog (ADR-004) |

## Local root CA rules

- Generated **on the user's machine** at install time, unique per PC. Keys are
  never committed, never bundled in an installer, never transmitted.
- Subject: `OpenShield Local CA — <hostname>`; `basicConstraints CA:true,
  pathlen:0`; key usage `keyCertSign, cRLSign`; limited validity (2 years) with
  re-issue.
- Installed into `LocalMachine\Root` **only after explicit user consent** in
  the GUI or installer. Firefox enterprise roots are enabled via
  `policies.json` only with consent as well.
- Removed from all stores on uninstall and by `scripts/cleanup.ps1`.

## Upstream verification

- Every upstream TLS connection is verified against the system trust store
  (`rustls-platform-verifier`), including hostname and validity.
- A verification failure is **never** masked: the client receives an error
  page signed by our CA explaining the failure, not a valid-looking page.
- Domains with certificate pinning and sensitive domains (banking, government,
  OS updates, identity providers, AV updates) bypass MITM by default.

## Development safety

System-changing actions (installing the CA, the service or the driver,
editing browser policies or the registry) are never performed by build or
test scripts. `scripts/cleanup.ps1` rolls back everything OpenShield may have
changed; see ADR-006 for what it intentionally leaves alone.
