# Tight-loop watcher that captures the exact command-line FEAR's bridge client
# passes to NvRemixBridge.exe and any child processes Remix spawns. Writes results
# to capture_nvremix_cmdline.log next to this script.
#
# Usage:
#   1. Open this script in PowerShell.
#   2. powershell -ExecutionPolicy Bypass -File .\capture_nvremix_cmdline.ps1
#   3. While it says "WATCHING", launch FEAR.exe in a separate window (double-click or run launch_remix_test.ps1).
#   4. Script captures ANY process named NvRemix*, NvRemixBridge*, or whose parent is FEAR.exe / NvRemixLauncher32.exe.
#   5. Stop with Ctrl+C when done; results saved to capture_nvremix_cmdline.log.

$logPath = Join-Path $PSScriptRoot 'capture_nvremix_cmdline.log'
"=== Capture started $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') ===" | Out-File -FilePath $logPath -Encoding utf8

$seen = @{}
$startTime = Get-Date
$timeoutSeconds = 60

Write-Host "WATCHING for NvRemix*, FEAR.exe children. Polling every 30ms. Timeout: $timeoutSeconds s." -ForegroundColor Cyan
Write-Host "Log file: $logPath" -ForegroundColor Cyan
Write-Host "Launch FEAR.exe now in another window." -ForegroundColor Yellow

while ((Get-Date) - $startTime -lt [TimeSpan]::FromSeconds($timeoutSeconds)) {
    try {
        $procs = Get-CimInstance Win32_Process -Filter "Name LIKE 'NvRemix%' OR Name = 'FEAR.exe'" -ErrorAction SilentlyContinue
        foreach ($p in $procs) {
            $key = "$($p.ProcessId):$($p.Name)"
            if (-not $seen.ContainsKey($key)) {
                $seen[$key] = $true
                $line = "[$((Get-Date).ToString('HH:mm:ss.fff'))] PID=$($p.ProcessId) PPID=$($p.ParentProcessId) Name=$($p.Name)"
                $cmd  = "    CmdLine: $($p.CommandLine)"
                $exe  = "    ExePath: $($p.ExecutablePath)"
                Write-Host $line -ForegroundColor Green
                Write-Host $cmd -ForegroundColor White
                $line | Out-File -Append -FilePath $logPath -Encoding utf8
                $cmd  | Out-File -Append -FilePath $logPath -Encoding utf8
                $exe  | Out-File -Append -FilePath $logPath -Encoding utf8

                # If this is NvRemixBridge.exe, immediately try to grab its loaded modules + exit code
                if ($p.Name -eq 'NvRemixBridge.exe') {
                    $bridgePid = $p.ProcessId
                    Start-Job -ScriptBlock {
                        param($pid_, $log)
                        try {
                            $proc = Get-Process -Id $pid_ -ErrorAction Stop
                            $proc.WaitForExit(15000) | Out-Null
                            "    NvRemixBridge.exe exited: ExitCode=$($proc.ExitCode) at $((Get-Date).ToString('HH:mm:ss.fff'))" | Out-File -Append -FilePath $log -Encoding utf8
                        } catch {
                            "    NvRemixBridge.exe wait failed: $_" | Out-File -Append -FilePath $log -Encoding utf8
                        }
                    } -ArgumentList $bridgePid, $logPath | Out-Null
                }
            }
        }
    } catch {
        # Swallow transient WMI errors
    }
    Start-Sleep -Milliseconds 30
}

Write-Host "Timeout reached. Capture stopped." -ForegroundColor Cyan
"=== Capture ended $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') ===" | Out-File -Append -FilePath $logPath -Encoding utf8

# Wait briefly for any pending exit-code jobs to flush
Start-Sleep -Seconds 2
Get-Job | Wait-Job -Timeout 5 | Out-Null
Get-Job | Receive-Job 2>&1 | Out-Null
Get-Job | Remove-Job -Force

Write-Host ""
Write-Host "Final log contents:" -ForegroundColor Cyan
Get-Content $logPath
