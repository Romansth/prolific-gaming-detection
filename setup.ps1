# Create a private Python environment for the screen (isolation only: nothing is installed).
$py = if ($env:PYTHON) { $env:PYTHON } else { "python" }
& $py -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)"
if ($LASTEXITCODE -ne 0) { Write-Host "Python 3.9 or newer is needed. Install it from https://www.python.org/downloads/ and re-run."; exit 1 }
& $py -m venv .venv
Write-Host "Ready. Run the screen with:  .\screen.ps1"
Write-Host "Look up a participant's token with:  .\screen.ps1 lookup <prolific id>"
