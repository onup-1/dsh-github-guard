# Install the privileged half of dsh-github-guard.
#
# The plugin only *probes*; rewriting %SystemRoot%\System32\drivers\etc\hosts needs an
# elevated token. This script copies the native helper to ProgramData, creates a shared
# token, and registers it as a SYSTEM task that listens on 127.0.0.1:8898.
#
# Run elevated (UAC). Re-running is safe: it replaces the task and keeps the token.
$ErrorActionPreference = 'Stop'

$sourceExe = Join-Path (Split-Path -Parent $PSScriptRoot) 'native\dsh-github-guard.exe'
$guardDir = 'C:\ProgramData\DSHGuard'
$targetExe = Join-Path $guardDir 'dsh-github-guard.exe'
$tokenFile = Join-Path $guardDir 'token.txt'
$taskName = 'DSH-GitHubGuardHelper'
$logFile = Join-Path $guardDir 'install.log'

function Say($text) {
    Write-Output $text
    try { [IO.File]::AppendAllText($logFile, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' ' + $text + "`r`n") } catch { }
}

[IO.Directory]::CreateDirectory($guardDir) | Out-Null

if (-not (Test-Path $sourceExe)) { throw "helper executable not found: $sourceExe" }
Copy-Item -LiteralPath $sourceExe -Destination $targetExe -Force
Say "copied helper -> $targetExe"

if (-not (Test-Path $tokenFile)) {
    $bytes = New-Object byte[] 24
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $token = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
    [IO.File]::WriteAllText($tokenFile, $token, [Text.Encoding]::ASCII)
    Say 'generated a new helper token'
} else {
    Say 'kept the existing helper token'
}

foreach ($stale in @($taskName, 'DSH-GitHubGuard')) {
    $existing = Get-ScheduledTask -TaskName $stale -ErrorAction SilentlyContinue
    if ($existing -ne $null) {
        Stop-ScheduledTask -TaskName $stale -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $stale -Confirm:$false -ErrorAction SilentlyContinue
        Say "removed previous task $stale"
    }
}
foreach ($processName in @('dsh-github-guard', 'ghguard')) {
    Get-Process $processName -ErrorAction SilentlyContinue | ForEach-Object {
        try { $_.Kill(); Say "killed stale $processName pid=$($_.Id)" } catch { }
    }
}

$action = New-ScheduledTaskAction -Execute $targetExe -Argument 'serve'
$triggers = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -AtLogOn))
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Description 'Privileged hosts writer for the DSH github-guard plugin (listens on 127.0.0.1:8898).' | Out-Null
Say "registered task $taskName (SYSTEM, AtStartup + AtLogOn)"

Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 3

$state = (Get-ScheduledTask -TaskName $taskName).State
Say "task state = $state"

# Prove the helper answers before we declare success.
$token = [IO.File]::ReadAllText($tokenFile).Trim()
$ok = $false
for ($attempt = 0; $attempt -lt 10 -and -not $ok; $attempt++) {
    try {
        $client = New-Object Net.Sockets.TcpClient
        $client.Connect('127.0.0.1', 8898)
        $stream = $client.GetStream()
        $writer = New-Object IO.StreamWriter($stream)
        $writer.AutoFlush = $true
        $reader = New-Object IO.StreamReader($stream)
        $writer.WriteLine('AUTH ' + $token)
        $authReply = $reader.ReadLine()
        $writer.WriteLine('status')
        $statusReply = $reader.ReadLine()
        $client.Close()
        Say "helper auth reply: $authReply"
        Say "helper status reply: $statusReply"
        $ok = $authReply -eq 'OK authenticated'
    } catch {
        Start-Sleep -Milliseconds 700
    }
}
if (-not $ok) { throw 'the helper did not answer on 127.0.0.1:8898 after 10 attempts' }
Say 'helper installed and answering'
Say 'done'
