<#
.SYNOPSIS
    Rolls back every system change OpenShield may have made.

.DESCRIPTION
    Safe to run repeatedly. Removes:
      1. OpenShield root CA certificates (subject 'OpenShield Local CA*') from
         the LocalMachine and CurrentUser certificate stores.
      2. The 'OpenShield' Windows service (stopped first).
      3. Browser policies and registry values recorded in the rollback journal
         %ProgramData%\OpenShield\rollback.json, restored to their previous
         values.
      4. With -Purge: the %ProgramData%\OpenShield data directory.
    Then flushes the DNS resolver cache.

    It never stops or deletes the WinDivert driver service: other software
    uses the same driver, and it unloads by itself when no handle is open
    (ADR-006 in docs\ARCHITECTURE.md).

    Run from an elevated PowerShell. -WhatIf shows what would be done and
    works without elevation.

    Rollback journal format (written by the service/installer, stage 2+):
      { "version": 1, "changes": [
          { "type": "firefox-policy", "path": "<policies.json>",
            "policy": "Certificates.ImportEnterpriseRoots",
            "previous": null, "createdFile": true },
          { "type": "registry-value", "key": "HKLM:\\SOFTWARE\\...",
            "name": "<value name>", "previous": null }
      ] }
    "previous": null means the value did not exist and is removed.

.PARAMETER Purge
    Also delete %ProgramData%\OpenShield (configuration, cached lists, logs,
    CA key).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\cleanup.ps1 -WhatIf
#>
# SPDX-License-Identifier: GPL-3.0-or-later
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Purge
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName = 'OpenShield'
$CaSubjectPattern = 'CN=OpenShield Local CA*'
$DataDir = Join-Path $env:ProgramData 'OpenShield'
$JournalPath = Join-Path $DataDir 'rollback.json'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $WhatIfPreference) {
    throw 'cleanup.ps1 must run from an elevated PowerShell (or use -WhatIf to preview).'
}

$failures = 0
function Invoke-Step([string]$Name, [scriptblock]$Body) {
    try {
        & $Body
    } catch {
        $script:failures++
        Write-Warning "${Name}: $($_.Exception.Message)"
    }
}

# 1. Root CA certificates
Invoke-Step 'certificates' {
    $stores = 'Cert:\LocalMachine\Root', 'Cert:\LocalMachine\CA', 'Cert:\LocalMachine\My',
              'Cert:\CurrentUser\Root', 'Cert:\CurrentUser\CA', 'Cert:\CurrentUser\My'
    $found = 0
    foreach ($store in $stores) {
        Get-ChildItem -Path $store | Where-Object { $_.Subject -like $CaSubjectPattern } | ForEach-Object {
            $found++
            if ($PSCmdlet.ShouldProcess("$store\$($_.Thumbprint) ($($_.Subject))", 'Remove certificate')) {
                Remove-Item -Path "$store\$($_.Thumbprint)" -DeleteKey -ErrorAction SilentlyContinue
                if (Test-Path "$store\$($_.Thumbprint)") {
                    Remove-Item -Path "$store\$($_.Thumbprint)"
                }
            }
        }
    }
    if ($found -eq 0) { Write-Host 'Certificates: none found.' }
}

# 2. Windows service
Invoke-Step 'service' {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Host "Service: '$ServiceName' not installed."
        return
    }
    if ($svc.Status -ne 'Stopped' -and $PSCmdlet.ShouldProcess($ServiceName, 'Stop service')) {
        Stop-Service -Name $ServiceName -Force
    }
    if ($PSCmdlet.ShouldProcess($ServiceName, 'Delete service')) {
        & sc.exe delete $ServiceName | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sc.exe delete exited with $LASTEXITCODE" }
    }
}

# 3. Policies and registry values from the rollback journal
function Restore-FirefoxPolicy($change) {
    $path = $change.path
    if (-not (Test-Path $path)) { return }
    $json = Get-Content -Raw -Path $path | ConvertFrom-Json
    # Policy paths are "<Policy>.<Key>", e.g. "Certificates.ImportEnterpriseRoots".
    $policyName, $key = $change.policy -split '\.', 2
    if (-not $json.policies.PSObject.Properties[$policyName]) { return }
    $node = $json.policies.$policyName
    if (-not $PSCmdlet.ShouldProcess("$path : $($change.policy)", 'Restore Firefox policy')) { return }
    if ($null -eq $change.previous) {
        $node.PSObject.Properties.Remove($key)
        if (@($node.PSObject.Properties).Count -eq 0) {
            $json.policies.PSObject.Properties.Remove($policyName)
        }
    } else {
        $node.$key = $change.previous
    }
    if ($change.createdFile -and @($json.policies.PSObject.Properties).Count -eq 0) {
        Remove-Item -Force -Path $path
    } else {
        # Firefox expects UTF-8 without BOM; Set-Content -Encoding UTF8 adds one on PowerShell 5.1.
        [IO.File]::WriteAllText($path, ($json | ConvertTo-Json -Depth 32), (New-Object Text.UTF8Encoding($false)))
    }
}

function Restore-RegistryValue($change) {
    if (-not (Test-Path $change.key)) { return }
    if (-not $PSCmdlet.ShouldProcess("$($change.key)\$($change.name)", 'Restore registry value')) { return }
    if ($null -eq $change.previous) {
        Remove-ItemProperty -Path $change.key -Name $change.name -ErrorAction SilentlyContinue
    } else {
        Set-ItemProperty -Path $change.key -Name $change.name -Value $change.previous
    }
}

Invoke-Step 'rollback journal' {
    if (-not (Test-Path $JournalPath)) {
        Write-Host 'Policies: no rollback journal, nothing to restore.'
        return
    }
    $journal = Get-Content -Raw -Path $JournalPath | ConvertFrom-Json
    $changes = @($journal.changes)
    [array]::Reverse($changes)
    foreach ($change in $changes) {
        Invoke-Step "journal entry $($change.type)" {
            switch ($change.type) {
                'firefox-policy' { Restore-FirefoxPolicy $change }
                'registry-value' { Restore-RegistryValue $change }
                default { throw "unknown change type '$($change.type)'" }
            }
        }
    }
    if ($script:failures -eq 0 -and $PSCmdlet.ShouldProcess($JournalPath, 'Remove rollback journal')) {
        Remove-Item -Force -Path $JournalPath
    }
}

# 4. Data directory
if ($Purge) {
    Invoke-Step 'data directory' {
        if ((Test-Path $DataDir) -and $PSCmdlet.ShouldProcess($DataDir, 'Delete directory')) {
            Remove-Item -Recurse -Force -Path $DataDir
        }
    }
} elseif (Test-Path $DataDir) {
    Write-Host "Data: kept $DataDir (use -Purge to delete it)."
}

# 5. DNS cache
Invoke-Step 'dns cache' {
    if ($PSCmdlet.ShouldProcess('DNS resolver cache', 'Flush')) {
        Clear-DnsClientCache
    }
}

Write-Host 'WinDivert driver: left untouched by design (ADR-006).'
if ($failures -gt 0) {
    Write-Warning "Cleanup finished with $failures error(s); see warnings above."
    exit 1
}
Write-Host 'Cleanup finished.'
