#!/bin/sh
# Create a private Python environment for the screen (isolation only: nothing is installed).
set -e
PY=${PYTHON:-python3}
if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
  echo "Python 3.9 or newer is needed. Install it from https://www.python.org/downloads/ and re-run."
  exit 1
fi
"$PY" -m venv .venv
echo "Ready. Run the screen with:"
echo "  ./screen.sh --data raw-data/<pull> --redact"
echo "Look up a participant's token with:"
echo "  ./screen.sh lookup <prolific id>"
