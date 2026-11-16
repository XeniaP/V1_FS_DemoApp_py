#!/usr/bin/env bash
set -euo pipefail

# Resolve project files relative to this script, even from another directory.
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

if [[ -f .env ]]; then
    set -a
    source .env
    set +a
fi

: "${V1_API_KEY:?Set V1_API_KEY in .env or your environment}"
: "${V1_REGION:?Set V1_REGION in .env or your environment}"

if [[ ! -d .venv ]]; then
    if [[ -n "${PYTHON:-}" ]]; then
        "$PYTHON" -m venv .venv
    elif command -v python3 >/dev/null 2>&1; then
        python3 -m venv .venv
    else
        python -m venv .venv
    fi
fi

if [[ -x .venv/bin/python ]]; then
    venv_python=.venv/bin/python
elif [[ -f .venv/Scripts/python.exe ]]; then
    venv_python=.venv/Scripts/python.exe
else
    printf '%s\n' 'No Python executable found in .venv. Recreate it for this platform.' >&2
    exit 1
fi

"$venv_python" -m pip install -r requirements.txt
printf 'Starting File Security demo at http://localhost:%s\n' "${PORT:-8080}"
exec "$venv_python" app.py
