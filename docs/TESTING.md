# Testing

Русская версия с подробными пошаговыми инструкциями: [TESTING.ru.md](TESTING.ru.md).

## Automated (CI and local)

```powershell
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Unit tests cover list parsing and matching, list download/caching (against a
local HTTP server), DNS packet decisions (forged UDP answers, TCP resets,
IPv4/IPv6), the packet loop (with an in-memory interceptor) and the watchdog.
They need neither administrator rights nor WinDivert.

## Manual checklist: stage 1 (DNS filtering)

These steps load the WinDivert driver and change DNS behaviour while running,
so they are never run by scripts or CI. Run them in an **elevated** PowerShell
from the repository root.

### Prepare

1. Antivirus: Defender may block the WinDivert archive (ADR-005). If you
   choose to proceed, allow only the folder it is fetched into, from an
   elevated PowerShell:

   ```powershell
   Add-MpPreference -ExclusionPath 'C:\dev\openshield\third_party'
   ```

   (Undo later with `Remove-MpPreference -ExclusionPath 'C:\dev\openshield\third_party'`.)
2. Fetch WinDivert and build:

   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\dev-setup.ps1
   cargo build --release
   .\target\release\openshield-cli.exe --data-dir dev-data lists update
   ```

3. Define a shortcut for the console run:

   ```powershell
   $wd = 'third_party\windivert\WinDivert-2.2.2-A\x64'
   ```

### Checks

| # | Step | Expected |
|---|---|---|
| 1 | `.\target\release\openshield-service.exe --console --data-dir dev-data --windivert-dir $wd --stats-interval 15` | Lists load, `DNS filtering active`. A warning appears if Windows DoH is enabled. |
| 2 | In a second window: `nslookup doubleclick.net` | `Address: 0.0.0.0` |
| 3 | `Resolve-DnsName ad.doubleclick.net -Type AAAA` | `::` |
| 4 | `Resolve-DnsName use-application-dns.net` | NXDOMAIN (DNS name does not exist) |
| 5 | `nslookup -vc doubleclick.net` (DNS over TCP) | Fails (connection reset), no real address |
| 6 | `Resolve-DnsName github.com`; open a few websites | Real addresses; sites work |
| 7 | Wait for a stats line | Totals and top blocked/queried domains |
| 8 | Fail open on kill: `taskkill /F /IM openshield-service.exe`, then `ipconfig /flushdns` and `nslookup doubleclick.net` | Real address (filtering gone), internet works |
| 9 | Start again (step 1), press **Ctrl+C** | Clean stop, final stats, DNS works afterwards |
| 10 | Watchdog (artificial hang), see below | Capture released within ~3 s, exit code 2, DNS works |
| 11 | `powershell -ExecutionPolicy Bypass -File scripts\cleanup.ps1` | Finishes without errors |

### Watchdog test (step 10)

Build with the development-only fault injection and make the loop hang on the
5th packet:

```powershell
cargo build --release -p openshield-service --features fault-injection
.\target\release\openshield-service.exe --console --data-dir dev-data --windivert-dir $wd --debug-stall-after 5
```

In a second window run a few lookups (`1..8 | % { Resolve-DnsName "test$_.example.com" -ErrorAction SilentlyContinue }`).
Expected in the service window: `fault injection: hanging on packet 5`, then
within about 3 seconds `watchdog: packet loop stuck ...; capture released`,
and the process exits with code 2 (`$LASTEXITCODE`). Lookups keep working
during and after the hang (the stuck query itself is retried by Windows).
Rebuild without the feature afterwards (`cargo build --release`).
