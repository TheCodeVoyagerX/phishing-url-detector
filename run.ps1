# PowerShell Launcher for Phishing URL Detector
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Starting Phishing URL Detector Web Application" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan

if (Test-Path ".\.venv\Scripts\Activate.ps1") {
    & ".\.venv\Scripts\Activate.ps1"
}

Write-Host "Launching Streamlit Dashboard on http://localhost:8501 ..." -ForegroundColor Yellow
streamlit run app.py
