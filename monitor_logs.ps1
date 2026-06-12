# PowerShell script to monitor TUI AI analysis logs in real-time
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  TUI Dashboard - AI Analysis Log Monitor" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Monitoring: tui_ai_analysis.log" -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop" -ForegroundColor Yellow
Write-Host ""

$logFile = "tui_ai_analysis.log"

if (-not (Test-Path $logFile)) {
    Write-Host "Waiting for log file to be created..." -ForegroundColor Yellow
    while (-not (Test-Path $logFile)) {
        Start-Sleep -Milliseconds 500
    }
}

Get-Content $logFile -Wait -Tail 20 | ForEach-Object {
    $line = $_
    
    # Color code different log levels
    if ($line -match "ERROR") {
        Write-Host $line -ForegroundColor Red
    }
    elseif ($line -match "WARNING") {
        Write-Host $line -ForegroundColor Yellow
    }
    elseif ($line -match "✓ Completed") {
        Write-Host $line -ForegroundColor Green
    }
    elseif ($line -match "Starting AI analysis") {
        Write-Host $line -ForegroundColor Cyan
    }
    elseif ($line -match "====") {
        Write-Host $line -ForegroundColor Blue
    }
    else {
        Write-Host $line
    }
}
