# AI Firewall Uninstaller Cleanup Script
# Stops processes, backs up and cleans hosts file, removes AIFirewall- rules, and flushes DNS

$ErrorActionPreference = "SilentlyContinue"

Write-Host "[AI Firewall Uninstaller] Stopping processes..."
try {
    taskkill /F /IM "AI Firewall.exe" /T 2>$null | Out-Null
} catch {}
try {
    taskkill /F /IM "aifirewall-backend.exe" /T 2>$null | Out-Null
} catch {}
Start-Sleep -Seconds 1

Write-Host "[AI Firewall Uninstaller] Cleaning hosts file..."
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
if (Test-Path $hostsPath) {
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $appdata = $env:APPDATA
    if (-not $appdata) {
        $appdata = "$env:USERPROFILE\AppData\Roaming"
    }
    $backupDir = "$appdata\AIFirewall\backups"
    if (-not (Test-Path $backupDir)) {
        New-Item -ItemType Directory -Path $backupDir -Force -ErrorAction SilentlyContinue | Out-Null
    }
    $backupFile = "$backupDir\hosts_uninstall_$ts.bak"
    try {
        Copy-Item -Path $hostsPath -Destination $backupFile -Force -ErrorAction SilentlyContinue
    } catch {}

    try {
        $allLines = [System.IO.File]::ReadAllLines($hostsPath)
        $cleanLines = New-Object System.Collections.Generic.List[string]
        foreach ($line in $allLines) {
            if ($line -notmatch "AIFirewall-Block" -and $line -notmatch "AI-FIREWALL-BLOCK") {
                $cleanLines.Add($line)
            }
        }
        [System.IO.File]::WriteAllLines($hostsPath, $cleanLines, [System.Text.Encoding]::UTF8)
        Write-Host "[AI Firewall Uninstaller] Hosts file cleaned and backed up to $backupFile"
    } catch {
        Write-Warning "[AI Firewall Uninstaller] Could not write to hosts file: $_"
    }
}

Write-Host "[AI Firewall Uninstaller] Removing firewall rules with prefix AIFirewall-..."
try {
    $ruleMatches = netsh advfirewall firewall show rule name=all | Select-String "Rule Name:\s*(AIFirewall-[^\r\n]*)"
    foreach ($m in $ruleMatches) {
        if ($m.Matches.Count -gt 0) {
            $val = $m.Matches[0].Groups[1].Value.Trim()
            if ($val) {
                Write-Host "[AI Firewall Uninstaller] Deleting rule: $val"
                netsh advfirewall firewall delete rule name="$val" | Out-Null
            }
        }
    }
} catch {
    Write-Warning "[AI Firewall Uninstaller] Error enumerating/deleting firewall rules: $_"
}

Write-Host "[AI Firewall Uninstaller] Flushing DNS cache..."
try {
    Clear-DnsClientCache -ErrorAction SilentlyContinue | Out-Null
} catch {}
try {
    ipconfig /flushdns | Out-Null
} catch {}

Write-Host "[AI Firewall Uninstaller] Cleanup completed."
