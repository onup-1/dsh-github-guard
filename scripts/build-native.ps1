# Rebuild native\dsh-github-guard.exe from source.
#
# Only C# 5 features are used, so the framework compiler that ships with Windows is
# enough - no .NET SDK required.
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$source = Join-Path $root 'native\dsh-github-guard.cs'
$output = Join-Path $root 'native\dsh-github-guard.exe'
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
if (-not (Test-Path $csc)) { throw 'csc.exe not found; install the .NET Framework 4 compiler' }

& $csc /nologo /target:exe /platform:anycpu /optimize+ "/out:$output" $source
if ($LASTEXITCODE -ne 0) { throw "csc failed with exit code $LASTEXITCODE" }
"built $output ($((Get-Item $output).Length) bytes)"
