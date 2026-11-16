#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

if [[ -f .env ]]; then
    set -a
    source .env
    set +a
fi

export SCAN_MODE="${SCAN_MODE:-live}"
if [[ "$SCAN_MODE" == live ]]; then
    : "${V1_API_KEY:?Set V1_API_KEY in .env or your environment}"
    : "${V1_REGION:?Set V1_REGION in .env or your environment}"
elif [[ "$SCAN_MODE" != simulation ]]; then
    printf '%s\n' 'SCAN_MODE must be live or simulation.' >&2
    exit 1
fi

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
"$venv_python" -c 'import sys; sys.exit(0 if (3,11) <= sys.version_info[:2] < (3,15) else "Use Python 3.11 through 3.14 and recreate .venv.")'
"$venv_python" -m pip install -r ai_demo/requirements.txt
printf 'TrendAI AI File Security Lab: http://localhost:%s (scan mode: %s)\n' "${AI_DEMO_PORT:-8081}" "$SCAN_MODE"
exec "$venv_python" -m ai_demo.app
