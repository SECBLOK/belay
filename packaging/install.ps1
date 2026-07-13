#Requires -Version 5.1
<#
.SYNOPSIS
    Belay for Windows - one-line installer.

    Canonical use:
        irm https://dl.belay.secblok.io/install.ps1 | iex

    Downloads the Belay desktop installer (a Tauri/NSIS "-setup.exe") from the
    Secblok CDN (dl.belay.secblok.io, falling back to GitHub Releases), verifies
    its SHA-256 against the published checksum, then runs it in PASSIVE mode:
    a progress bar, no clicks, and it creates BOTH a Start Menu entry and a
    Desktop shortcut before launching Belay.

    This is the Windows counterpart to packaging/install.sh (Linux/macOS).

.NOTES
    Requires Windows 10/11 x64 and Windows PowerShell 5.1+ (preinstalled).
    Environment overrides (parity with install.sh):
        BELAY_VERSION        pin a release, e.g. 0.1.0 (default: latest)
        BELAY_DOWNLOAD_BASE  CDN base URL (default: https://dl.belay.secblok.io)
        BELAY_REPO           GitHub fallback repo (default: SECBLOK/belay)
#>
[CmdletBinding()]
param(
    [string]$Version      = $env:BELAY_VERSION,
    [string]$DownloadBase = $(if ($env:BELAY_DOWNLOAD_BASE) { $env:BELAY_DOWNLOAD_BASE } else { 'https://dl.belay.secblok.io' }),
    [string]$Repo         = $(if ($env:BELAY_REPO) { $env:BELAY_REPO } else { 'SECBLOK/belay' }),
    # Also register the machine-wide firewall/boot-start service (prompts for
    # Administrator). Optional: the desktop app already spawns an unprivileged
    # daemon on its own, so the GUI and approval flow work without this.
    [switch]$WithService,
    # Fully silent install (no window) instead of the default passive progress bar.
    [switch]$Silent,
    # Do not launch Belay after installing.
    [switch]$NoLaunch
)

$ErrorActionPreference = 'Stop'
# Invoke-WebRequest's per-byte progress bar pegs a CPU core and throttles
# downloads 10-100x on Windows PowerShell 5.1. Every download here is
# fire-and-forget, so suppress it for the whole run.
$ProgressPreference = 'SilentlyContinue'

try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new() } catch {}

function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Warn2($m) { Write-Host "warning: $m" -ForegroundColor Yellow }
function Die($m) { Write-Host "error: $m" -ForegroundColor Red; exit 1 }

# --- platform sanity ----------------------------------------------------------
# $IsWindows exists only on PowerShell 6+ (it is $null on 5.1, which is always
# Windows). Reject only an explicit non-Windows PowerShell Core host.
if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) {
    Die 'Belay for Windows requires Windows. On Linux/macOS use: curl -fsSL https://dl.belay.secblok.io/install.sh | bash'
}

# --- architecture -------------------------------------------------------------
$arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
switch ($arch) {
    'AMD64' { $slug = 'x64' }
    default {
        Die "Belay v0.1 ships an x64 Windows installer only (detected '$arch'). ARM64 is on the roadmap - track the releases page for $Repo."
    }
}
$asset = "belay-setup-$slug.exe"

# --- resolve download URLs (CDN first, GitHub Releases fallback) --------------
$cdn = $DownloadBase.TrimEnd('/')
if ($Version) {
    $tag = if ($Version.StartsWith('v')) { $Version } else { "v$Version" }
    $ghBase = "https://github.com/$Repo/releases/download/$tag"
} else {
    $ghBase = "https://github.com/$Repo/releases/latest/download"
}
# Append a unique cache-buster to the CDN URLs so a freshly rebuilt installer is
# never served stale from Cloudflare's edge cache (the large .exe is cached hard;
# a re-upload to R2 does not purge the edge). GitHub URLs are left plain.
$cb = "cb=" + [Guid]::NewGuid().ToString("N")
$sources = @(
    @{ Exe = "$cdn/$asset?$cb";    Sum = "$cdn/$asset.sha256?$cb" },
    @{ Exe = "$ghBase/$asset"; Sum = "$ghBase/$asset.sha256" }
)

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("belay-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$exePath = Join-Path $tmp $asset
$sumPath = "$exePath.sha256"

function Get-File($url, $dest) {
    try { Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing -MaximumRedirection 5; return $true }
    catch { return $false }
}

$got = $false
foreach ($s in $sources) {
    Write-Step "Downloading $($s.Exe)"
    if (Get-File $s.Exe $exePath) {
        if (-not (Get-File $s.Sum $sumPath)) {
            Write-Warn2 "checksum not found at $($s.Sum) - trying next source"
            continue
        }
        $got = $true; break
    }
}
if (-not $got) {
    Die "could not download $asset from the CDN or GitHub Releases. Check your connection, or download it manually from https://github.com/$Repo/releases"
}

# --- verify SHA-256 -----------------------------------------------------------
Write-Step 'Verifying SHA-256'
$expected = ((Get-Content -Raw $sumPath) -split '\s+')[0].Trim().ToLower()
$actual   = (Get-FileHash -Algorithm SHA256 -Path $exePath).Hash.ToLower()
if (-not $expected) { Die 'the published checksum was empty - refusing to install' }
if ($expected -ne $actual) {
    Die "checksum mismatch - refusing to install.`n  expected $expected`n  actual   $actual"
}
Write-Host "    ok ($actual)" -ForegroundColor DarkGray

# --- run the installer (passive: progress bar + auto shortcuts) ---------------
# Tauri/NSIS flags: /P = passive (progress UI, no prompts, creates Start Menu +
# Desktop shortcuts automatically); /S = fully silent. Both are non-interactive.
try { Unblock-File -Path $exePath } catch {}
$mode = if ($Silent) { '/S' } else { '/P' }
Write-Step "Installing Belay ($asset $mode)"
$proc = Start-Process -FilePath $exePath -ArgumentList $mode -PassThru -Wait
if ($proc.ExitCode -ne 0) {
    Die "the installer exited with code $($proc.ExitCode). If Windows SmartScreen blocked an unsigned build, click 'More info' -> 'Run anyway', or run the downloaded $asset manually."
}
Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue

# --- locate the install via the uninstall registry key ------------------------
function Get-BelayInstallDir {
    $roots = @(
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($r in $roots) {
        $k = Get-ItemProperty $r -ErrorAction SilentlyContinue |
             Where-Object { $_.DisplayName -like 'Belay*' -and $_.InstallLocation } |
             Select-Object -First 1
        # NSIS writes InstallLocation QUOTED (e.g. "C:\Users\...\Belay"). The
        # literal quotes make Join-Path parse the drive as `"C` and throw
        # DriveNotFound, so strip surrounding quotes/whitespace and the trailing \.
        if ($k) { return $k.InstallLocation.Trim().Trim('"').Trim().TrimEnd('\') }
    }
    return $null
}
$installDir = Get-BelayInstallDir

# --- optional: machine-wide firewall/boot-start service (elevates) ------------
if ($WithService) {
    # Build the path by string (NOT Join-Path, which resolves the drive and can
    # throw on an unusual path); $installDir is already quote-stripped above.
    $belayExe = if ($installDir) { "$installDir\belay.exe" } else { $null }
    if ($belayExe -and (Test-Path -LiteralPath $belayExe)) {
        Write-Step 'Registering the Belay service (requires Administrator)'
        try {
            Start-Process -FilePath $belayExe -ArgumentList 'install-service', '--enable' -Verb RunAs -Wait
        } catch {
            Write-Warn2 "service registration was cancelled/failed: $($_.Exception.Message). Run later from an elevated prompt: `"$belayExe`" install-service --enable"
        }
    } else {
        Write-Warn2 'could not locate the installed belay.exe; from an elevated prompt run: belay install-service --enable'
    }
}

# --- launch + next steps ------------------------------------------------------
# The install already SUCCEEDED above (the installer exited 0); everything here
# is best-effort convenience, so a path/launch hiccup must never surface as a
# failure. Build the exe path by string and guard the launch.
$appExe = if ($installDir) { "$installDir\Belay.exe" } else { $null }
if (-not $NoLaunch -and $appExe -and (Test-Path -LiteralPath $appExe)) {
    Write-Step 'Launching Belay'
    try { Start-Process -FilePath $appExe | Out-Null }
    catch { Write-Warn2 "could not auto-launch Belay ($($_.Exception.Message)); open it from the Start Menu." }
}

Write-Host ''
Write-Host 'Belay installed.' -ForegroundColor Green
Write-Host '  Start Menu   search "Belay"'
Write-Host '  Desktop      a Belay shortcut was added'
Write-Host '  Taskbar      right-click Belay (running, or in the Start Menu) -> Pin to taskbar'
if (-not $WithService) {
    Write-Host '  Boot-start + firewall (optional): re-run with -WithService, or toggle "Start on boot" from Belay (dashboard or tray menu).'
}
Write-Host ''
