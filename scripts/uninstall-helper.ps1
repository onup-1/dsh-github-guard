# Remove the privileged half of dsh-github-guard and restore the hosts file.
#
# Run elevated (UAC). Keeps the helper logs in ProgramData unless -Purge is passed.
param([switch]$Purge)

$ErrorActionPreference = 'Continue'
$guardDir = 'C:\ProgramData\DSHGuard'
$taskName = 'DSH-GitHubGuardHelper'
$hostsPath = 'C:\Windows\System32\drivers\etc\hosts'
$marker = '# dsh-github-guard: pinned edge'

$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($task -eq $null) {
    "task $taskName not found"
} else {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    "task $taskName removed"
}

Get-Process dsh-github-guard -ErrorAction SilentlyContinue | ForEach-Object {
    try { $_.Kill(); "killed helper pid=$($_.Id)" } catch { "kill failed: $($_.Exception.Message)" }
}

$kept = Get-Content $hostsPath | Where-Object {
    $trimmed = $_.Trim()
    if ($trimmed.StartsWith($marker)) { return $false }
    $parts = $trimmed.Split(" `t".ToCharArray(), [StringSplitOptions]::RemoveEmptyEntries)
    if ($parts.Length -ge 2) {
        $hostName = $parts[1].ToLowerInvariant()
        if ($hostName -eq 'github.com' -or $hostName -eq 'www.github.com' -or $hostName -eq 'gist.github.com') { return $false }
    }
    return $true
}
Set-Content -Path $hostsPath -Value $kept -Encoding ASCII
ipconfig /flushdns | Out-Null
'hosts pins removed (github.com will resolve through DNS again)'

if ($Purge) {
    if (Test-Path $guardDir) {
        try { Remove-Item $guardDir -Recurse -Force; "purged $guardDir" } catch { "purge failed: $($_.Exception.Message)" }
    }
} else {
    "kept $guardDir (pass -Purge to delete the helper, token and logs)"
}
