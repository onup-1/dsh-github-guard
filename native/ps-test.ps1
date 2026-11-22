$ErrorActionPreference = 'Continue'
$dir = 'C:\Users\rog\Documents\deepseek-harness\default-workspace\plugins\dsh-github-guard\native'
$exe = Join-Path $dir 'dsh-github-guard.exe'
$hosts = Join-Path $dir 'tmp-hosts.txt'
$log = Join-Path $dir 'tmp-helper.log'
$out = Join-Path $dir 'tmp-ps-result.txt'
$lines = New-Object System.Collections.Generic.List[string]

$seed = "127.0.0.1 localhost`r`n192.168.1.9 github.com`r`n# dsh-github-guard: pinned edge`r`n9.9.9.9 github.com`r`n9.9.9.9 gist.github.com`r`n# keep me`r`n"
[IO.File]::WriteAllText($hosts, $seed, [Text.Encoding]::ASCII)

# 1) one-shot pin mode, no server involved
$env:DSH_GUARD_HOSTS = $hosts
$env:DSH_GUARD_LOG = $log
$env:DSH_GUARD_TOKEN = 'test-token-1234'
$pinOut = & $exe pin 1.2.3.4
$lines.Add('pin-mode exit=' + $LASTEXITCODE + ' out=' + ($pinOut -join '|'))
$lines.Add('--- hosts after pin mode ---')
$lines.Add((Get-Content $hosts -Raw))

# 2) server mode over loopback TCP
$env:DSH_GUARD_PORT = '8899'
$proc = Start-Process -FilePath $exe -ArgumentList 'serve' -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2
$lines.Add('serve pid=' + $proc.Id + ' running=' + (-not $proc.HasExited))

function Talk([string[]]$commandLines) {
    $client = New-Object Net.Sockets.TcpClient
    $client.Connect('127.0.0.1', 8899)
    $stream = $client.GetStream()
    $writer = New-Object IO.StreamWriter($stream)
    $writer.AutoFlush = $true
    $reader = New-Object IO.StreamReader($stream)
    $replies = @()
    foreach ($commandLine in $commandLines) { $writer.WriteLine($commandLine) }
    foreach ($commandLine in $commandLines) { $replies += $reader.ReadLine() }
    $client.Close()
    return ($replies -join ' | ')
}

try { $lines.Add('wrong token: ' + (Talk @('AUTH nope'))) } catch { $lines.Add('wrong token failed: ' + $_.Exception.Message) }
try { $lines.Add('good token : ' + (Talk @('AUTH test-token-1234'))) } catch { $lines.Add('good token failed: ' + $_.Exception.Message) }
try { $lines.Add('status     : ' + (Talk @('AUTH test-token-1234', 'status'))) } catch { $lines.Add('status failed: ' + $_.Exception.Message) }
try { $lines.Add('pin        : ' + (Talk @('AUTH test-token-1234', 'pin 4.3.2.1,8.8.8.8'))) } catch { $lines.Add('pin failed: ' + $_.Exception.Message) }
try { $lines.Add('bad pin    : ' + (Talk @('AUTH test-token-1234', 'pin nonsense'))) } catch { $lines.Add('bad pin failed: ' + $_.Exception.Message) }

$lines.Add('--- hosts after server pin ---')
$lines.Add((Get-Content $hosts -Raw))
$lines.Add('--- helper log ---')
if (Test-Path $log) { $lines.Add((Get-Content $log -Raw)) } else { $lines.Add('(no log)') }

if (-not $proc.HasExited) { try { $proc.Kill() } catch { } }
$lines.Add('done')
[IO.File]::WriteAllText($out, ($lines -join "`r`n"), [Text.Encoding]::UTF8)
