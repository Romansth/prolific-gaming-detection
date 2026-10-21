# Run the screen with the private environment when it exists, else the system Python.
Set-Location $PSScriptRoot
$py = if (Test-Path .venv\Scripts\python.exe) { ".venv\Scripts\python.exe" } elseif ($env:PYTHON) { $env:PYTHON } else { "python" }
if ($args.Count -gt 0 -and $args[0] -eq "lookup") { & $py -m fraudscreen.lookup $args[1..($args.Count-1)]; exit $LASTEXITCODE }
& $py -m fraudscreen @args
exit $LASTEXITCODE
