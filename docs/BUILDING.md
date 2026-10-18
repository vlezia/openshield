# Building OpenShield

## Requirements

- Windows 10/11 x64
- [rustup](https://rustup.rs/) with the stable `x86_64-pc-windows-msvc`
  toolchain (pinned in `rust-toolchain.toml`, installed automatically)
- Visual Studio 2022 Build Tools with the "Desktop development with C++"
  workload (MSVC + Windows SDK)
- Node.js LTS — only for the GUI (stage 2)
- Git

With winget:

```powershell
winget install --id Rustlang.Rustup -e
winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override "--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
winget install --id OpenJS.NodeJS.LTS -e
```

## Build and test

```powershell
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## WinDivert

Packet capture uses [WinDivert](https://github.com/basil00/WinDivert) 2.2.2.
It is not committed. Fetch it with:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\dev-setup.ps1
```

The script downloads the official release archive into `third_party\`,
verifies its SHA-256 and extracts it. It installs nothing.

> **Antivirus warning.** Microsoft Defender and other AV products may flag
> WinDivert (on our dev machine Defender reported
> `Misleading:Win32/Malgent!AMTB` for the release zip). This is a known false
> positive for packet capture tools; see ADR-005 in
> [ARCHITECTURE.md](ARCHITECTURE.md). If you choose to proceed, allow this
> specific file in your AV. Do not disable your AV.

## Rolling back a development machine

```powershell
# Preview what would be removed
powershell -ExecutionPolicy Bypass -File scripts\cleanup.ps1 -WhatIf
# Remove (run from an elevated PowerShell)
powershell -ExecutionPolicy Bypass -File scripts\cleanup.ps1
```
