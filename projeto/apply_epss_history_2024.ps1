param(
    [string]$StartDate = "2024-01-01",
    [string]$EndDate = "2025-04-30"
)

$ErrorActionPreference = "Stop"
$python = Get-Command python.exe -ErrorAction SilentlyContinue
if ($null -eq $python) {
    throw "Python 3 is required to read concatenated gzip members in the EPSS archive."
}

$scriptPath = Join-Path $PSScriptRoot "apply_epss_history_2024.py"
& $python.Source $scriptPath --start-date $StartDate --end-date $EndDate
if ($LASTEXITCODE -ne 0) {
    throw "Historical EPSS processing failed with exit code $LASTEXITCODE."
}
