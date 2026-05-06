# Launch FEAR with AppCompat shimming disabled for the spawned process tree.
# Used to test H2 (whether Windows AppCompat / apphelp.dll is corrupting bridge IPC setup).
# Run from this directory: powershell -ExecutionPolicy Bypass -File .\launch_remix_test.ps1

$ErrorActionPreference = 'Stop'
$gameDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$exePath = Join-Path $gameDir 'FEAR.exe'

if (-not (Test-Path $exePath)) {
    Write-Error "FEAR.exe not found at $exePath"
}

Write-Host "Setting __COMPAT_LAYER=RUNASINVOKER for this launch (suppresses AppCompat shimming)" -ForegroundColor Cyan
$env:__COMPAT_LAYER = 'RUNASINVOKER'

# Force CWD to game dir so any relative-path lookups by the bridge resolve correctly
Set-Location $gameDir

Write-Host "Launching: $exePath" -ForegroundColor Cyan
Write-Host "(Watch Task Manager for NvRemixBridge.exe to confirm bridge spawn)" -ForegroundColor Yellow
& $exePath
