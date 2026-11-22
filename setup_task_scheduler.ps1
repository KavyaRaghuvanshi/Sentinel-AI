<#
.SYNOPSIS
    Registers Sentinel AI as a Windows Scheduled Task that runs at user logon.

.DESCRIPTION
    Creates a scheduled task "Sentinel_AI_Agent" that:
    - Triggers 1 minute after user logon (to let boot settle)
    - Runs the Sentinel AI pipeline
    - Requires Administrator privileges for full functionality

.NOTES
    Run this script as Administrator:
    > powershell -ExecutionPolicy Bypass -File setup_task_scheduler.ps1
#>

param(
    [string]$PythonPath = "python.exe",
    [string]$ProjectDir = $PSScriptRoot,
    [string]$TaskName = "Sentinel_AI_Agent",
    [switch]$WithGUI,
    [switch]$Remove
)

# --- Remove existing task if requested ---
if ($Remove) {
    Write-Host "Removing scheduled task '$TaskName'..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Done." -ForegroundColor Green
    exit 0
}

# --- Verify Python is available ---
$pythonCheck = Get-Command $PythonPath -ErrorAction SilentlyContinue
if (-not $pythonCheck) {
    Write-Host "ERROR: Python not found at '$PythonPath'." -ForegroundColor Red
    Write-Host "Specify the full path: .\setup_task_scheduler.ps1 -PythonPath 'C:\Python312\python.exe'"
    exit 1
}

Write-Host "=== Sentinel AI — Task Scheduler Setup ===" -ForegroundColor Cyan
Write-Host "Python:     $PythonPath"
Write-Host "Project:    $ProjectDir"
Write-Host "Task Name:  $TaskName"
Write-Host ""

# --- Create the scheduled task ---
$Arguments = if ($WithGUI) { "-m sentinel --gui" } else { "-m sentinel" }

$Action = New-ScheduledTaskAction `
    -Execute $PythonPath `
    -Argument $Arguments `
    -WorkingDirectory $ProjectDir

$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Trigger.Delay = 'PT1M'  # 1-minute delay post-logon

$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

# Remove existing task if present
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Settings $Settings `
    -Description "Sentinel AI — Autonomous Endpoint Health & Cyber-Defense Agent. Runs at logon to clean temp files, audit security, and generate a health report." `
    -Force

Write-Host ""
Write-Host "Scheduled task '$TaskName' registered successfully!" -ForegroundColor Green
Write-Host "It will run 1 minute after each user logon."
Write-Host ""
Write-Host "To remove:  .\setup_task_scheduler.ps1 -Remove" -ForegroundColor Gray
Write-Host "To run now: schtasks /Run /TN '$TaskName'" -ForegroundColor Gray
