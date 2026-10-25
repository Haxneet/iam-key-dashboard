# Windows launcher. Creates a virtual environment on first run.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path .venv)) {
    python -m venv .venv
    .\.venv\Scripts\python -m pip install --upgrade pip
    .\.venv\Scripts\pip install -r requirements.txt
}
if (-not (Test-Path accounts.json)) {
    Copy-Item accounts.example.json accounts.json
    Write-Host "Created accounts.json. Edit it with your account IDs."
}
.\.venv\Scripts\streamlit run app.py
