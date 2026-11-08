<#
.SYNOPSIS
  Collects the Windows event logs SOC in a repo needs and zips them for upload.

.DESCRIPTION
  Exports the last N days of the Security, System, Sysmon, PowerShell and Windows Defender logs
  to a zip on your Desktop. Read-only: it does not change any settings or delete anything.
  Run it in an elevated PowerShell (Run as administrator), because the Security log needs admin rights.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\collect.ps1
  powershell -ExecutionPolicy Bypass -File .\collect.ps1 -Days 7
#>
param(
    [ValidateRange(1, 30)][int]$Days = 3,
    [string]$OutDir = [Environment]::GetFolderPath("Desktop")
)

$ErrorActionPreference = "Stop"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Not running as administrator. The Security log will be skipped. Right-click PowerShell and choose 'Run as administrator' for a full collection."
}

$channels = [ordered]@{
    "Security"   = "Security"
    "System"     = "System"
    "Sysmon"     = "Microsoft-Windows-Sysmon/Operational"
    "PowerShell" = "Microsoft-Windows-PowerShell/Operational"
    "Defender"   = "Microsoft-Windows-Windows Defender/Operational"
}

$stamp = Get-Date -Format "yyyyMMdd-HHmm"
$work = Join-Path $env:TEMP "soc-collect-$stamp"
New-Item -ItemType Directory -Path $work -Force | Out-Null
$ms = [int64]$Days * 24 * 60 * 60 * 1000
$query = "*[System[TimeCreated[timediff(@SystemTime) <= $ms]]]"

foreach ($name in $channels.Keys) {
    $channel = $channels[$name]
    $file = Join-Path $work "$name.evtx"
    try {
        & wevtutil.exe epl "$channel" "$file" "/q:$query" /ow:true 2>$null
        if ($LASTEXITCODE -eq 0 -and (Test-Path $file)) {
            $mb = [math]::Round((Get-Item $file).Length / 1MB, 1)
            Write-Host ("  {0,-11} exported ({1} MB)" -f $name, $mb) -ForegroundColor Green
        } else {
            Write-Host ("  {0,-11} skipped (log not found or no access)" -f $name) -ForegroundColor Yellow
        }
    } catch {
        Write-Host ("  {0,-11} skipped ({1})" -f $name, $_.Exception.Message) -ForegroundColor Yellow
    }
}

$files = Get-ChildItem $work -Filter *.evtx -ErrorAction SilentlyContinue
if (-not $files) { Write-Error "No logs were exported."; exit 1 }

$zip = Join-Path $OutDir "$($env:COMPUTERNAME)-logs-$stamp.zip"
Compress-Archive -Path $files.FullName -DestinationPath $zip -Force
Remove-Item $work -Recurse -Force
$size = [math]::Round((Get-Item $zip).Length / 1MB, 1)

Write-Host ""
Write-Host "Done: $zip ($size MB)" -ForegroundColor Cyan
if ($size -gt 25) {
    Write-Warning "The zip is over 25 MB. Run again with fewer days, for example: -Days 1"
}
Write-Host "Next: open a new 'Investigate a Windows log' issue in your PRIVATE copy, choose 'My own log', and drag this zip in."
