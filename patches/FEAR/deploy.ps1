# Deploy patches/FEAR/ build artifacts into the FEAR game directory.
# Run after every build.bat invocation so the next launch picks up the latest output.
#
# Usage: powershell -File deploy.ps1
#        powershell -File deploy.ps1 -GameDir "<path>"   # override target install
#        OR from cmd: powershell -ExecutionPolicy Bypass -File deploy.ps1

param(
    [string]$GameDir
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$buildDir = Join-Path $root 'build\bin\release'

if (-not $GameDir) {
    $GameDir = Resolve-Path (Join-Path $root '..\..\FEAR Ultimate Shooter Edition')
}
$gameDir = $GameDir

if (-not (Test-Path $buildDir)) {
    Write-Error "Build dir not found: $buildDir. Run build.bat release --name FEAR first."
}
if (-not (Test-Path $gameDir)) {
    Write-Error "Game dir not found: $gameDir"
}

Write-Output "Game dir: $gameDir"

# 1) The proxy itself + its INI. The INI source-of-truth is assets/, NOT the build
#    output — build.bat snapshots assets/ at compile time, but INI-only edits don't
#    rebuild, so deploying from build/ would silently ship a stale config.
Copy-Item -Force (Join-Path $buildDir 'd3d9.dll') (Join-Path $gameDir 'd3d9.dll')
Copy-Item -Force (Join-Path $root 'assets\remix-comp-proxy.ini') (Join-Path $gameDir 'remix-comp-proxy.ini')

# 2) The 32-bit Remix bridge client (renamed). FEAR is 32-bit so we need the bridge
#    shim that IPCs to NvRemixBridge.exe (which loads the 64-bit .trex/d3d9.dll runtime).
#    The 32-bit bridge ships as the ROOT d3d9.dll in the Remix release zip — NOT the
#    .trex/d3d9.dll, which is the 64-bit DXVK-Remix runtime and will fail LoadLibrary
#    with ERROR_BAD_EXE_FORMAT (0xC1) inside a 32-bit process.
$bridge = Join-Path $root 'deps\remix-bridge-x86\d3d9.dll'
if (-not (Test-Path $bridge)) {
    Write-Error "32-bit Remix bridge not staged at $bridge. Extract d3d9.dll from tools/rtx_remix_dl/remix-release.zip into patches/FEAR/deps/remix-bridge-x86/."
}
Copy-Item -Force $bridge (Join-Path $gameDir 'd3d9_remix.dll')

# 2b) bridge.conf for the 64-bit server. The proxy's remix_api::initialize() calls
#     remixapi_InitializeLibrary() which returns NOT_INITIALIZED (Code 11) unless
#     "exposeRemixApi = True" is set in .trex/bridge.conf. Our staged copy in
#     assets/.trex/bridge.conf has this enabled; the rtx-remix release ships it
#     commented out (default False). Push our version on every deploy.
$bridgeConfSrc = Join-Path $root 'assets\.trex\bridge.conf'
$trexDir = Join-Path $gameDir '.trex'
if ((Test-Path $bridgeConfSrc) -and (Test-Path $trexDir)) {
    Copy-Item -Force $bridgeConfSrc (Join-Path $trexDir 'bridge.conf')
} elseif (-not (Test-Path $trexDir)) {
    Write-Warning ".trex/ not found in game dir - bridge.conf not deployed. Install the rtx-remix runtime first."
}

# 3) Per-game PDB next to the DLL is helpful for crash analysis.
$pdb = Join-Path $buildDir 'FEAR-comp-proxy.pdb'
if (Test-Path $pdb) {
    Copy-Item -Force $pdb (Join-Path $gameDir 'FEAR-comp-proxy.pdb')
}

Write-Output 'Deployed:'
Get-ChildItem (Join-Path $gameDir 'd3d9.dll'), `
              (Join-Path $gameDir 'd3d9_remix.dll'), `
              (Join-Path $gameDir 'remix-comp-proxy.ini'), `
              (Join-Path $gameDir '.trex\bridge.conf'), `
              (Join-Path $gameDir 'FEAR-comp-proxy.pdb') -ErrorAction SilentlyContinue |
    Format-Table Name, Length, LastWriteTime -AutoSize
