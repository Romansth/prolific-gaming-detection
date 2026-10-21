#!/bin/sh
# Run the screen with the private environment when it exists, else the system Python.
cd "$(dirname "$0")"
if [ -x .venv/bin/python ]; then PY=.venv/bin/python; else PY=${PYTHON:-python3}; fi
if [ "$1" = "lookup" ]; then shift; exec "$PY" -m fraudscreen.lookup "$@"; fi
exec "$PY" -m fraudscreen "$@"
