# File Security SDK Demo (Python)

A Flask application demonstrating file scanning with the Trend Micro Vision One File Security Python SDK (`visionone-filesecurity`, imported as `amaas.grpc`). Users upload a file through a browser, and the app scans it before keeping it in the upload directory. The web interface displays messages in Spanish.

## Requirements

- Python 3.11 through 3.14 with `pip` and `venv` available. The included Dockerfile uses Python 3.13. The SDK is pinned to `visionone-filesecurity==1.5.1`, the latest stable PyPI release verified on November 16, 2026.
- A Vision One API key authorized to use File Security, and the region associated with that service.
- Network access to the File Security service and, during installation, the Python package index.
- Bash for the quick-start script (Linux, macOS, WSL, or Git Bash on Windows).

## Configure the application

Create a `.env` file in the project root, or edit your existing one:

```bash
V1_API_KEY='your-api-key'
V1_REGION='us-east-1'
FLASK_SECRET_KEY='replace-with-a-long-random-secret'
UPLOAD_FOLDER='uploads'
PORT=8080
```

Use the region configured for your File Security service; `us-east-1` is an example. You can generate a secret with `python -c "import secrets; print(secrets.token_hex(32))"`.

| Variable | Purpose | Default |
| --- | --- | --- |
| `V1_API_KEY` | API key passed to the SDK | Required for scanning |
| `V1_REGION` | Region passed to the SDK | Required for scanning |
| `FLASK_SECRET_KEY` | Signs Flask session cookies and flash messages | `change-me-in-production` |
| `UPLOAD_FOLDER` | Writable directory for temporary and accepted files | `uploads` |
| `PORT` | Port used by `python app.py` | `8080` |

The application does not load `.env` itself. Export its variables before starting, or use `run.sh`, which loads it automatically. The Bash instructions source `.env` as shell code: use only a trusted file with shell-compatible assignments. Keep credentials private; `.env` is ignored by Git.

## Quick start with Bash

From Git Bash on Windows:

```bash
cd /d/Github/V1_FS_DemoApp_py
bash run.sh
```

On Linux/macOS, change to your checkout directory and run `bash run.sh`. In WSL, the equivalent Windows directory is `/mnt/d/Github/V1_FS_DemoApp_py`.

The script loads `.env` if present, checks the required variables, creates `.venv` if needed, installs `requirements.txt`, and starts the app. It supports both Unix and Windows virtual environment layouts. To select the Python executable used to create the environment:

```bash
PYTHON=python3 bash run.sh
```

Open **http://localhost:8080** (or your configured port). Press **Ctrl+C** to stop.

## Manual Python environment setup

### Bash (Linux, macOS, or WSL)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
set -a
source .env
set +a
python app.py
# After stopping the app:
deactivate
```

For Git Bash with Windows Python, use `python -m venv .venv` and `source .venv/Scripts/activate` instead.

### Windows PowerShell

```powershell
python -m venv .venv
# Set variables in this shell; app.py does not read .env automatically.
$env:V1_API_KEY = 'your-api-key'
$env:V1_REGION = 'us-east-1'
$env:FLASK_SECRET_KEY = 'replace-with-a-long-random-secret'
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Calling the environment's Python directly also avoids needing to activate it in PowerShell.

## Use the demo

1. Open the app in your browser.
2. Select a file and click **Analizar archivo**.
3. Read the success or error message after the scan.
4. Accepted files are stored under `UPLOAD_FOLDER` with a sanitized filename. An accepted upload with the same filename replaces the previous file.

Allowed extensions: `.txt`, `.pdf`, `.png`, `.jpg`, `.jpeg`, and `.gif` (case-insensitive). Flask limits the entire upload request to **16 MiB**; oversized requests receive HTTP 413.

The app first writes the upload to a temporary file in the upload directory. It calls `amaas.grpc.init_by_region`, then `amaas.grpc.scan_file` with `pml=True`, `feedback=True`, `verbose=True`, and a list of demo tags. The verbose result includes per-engine findings rather than relying only on the compact `scanResult` field. Files are accepted only when all reported engines return zero detections and no errors. Compact responses are also supported: only an explicit `scanResult` of `null` or `0`, with no findings or errors, is accepted. Unknown or malformed responses are rejected.

Scan exceptions are logged with a traceback and cause rejection; the UI labels these uploads as malicious too. Other processing errors produce a processing-error message. Consult the server output to distinguish a scan failure from a detection.

## Extended SDK logs

Every completed SDK call emits an INFO-level `filesecurity.scan.response` event with the **entire raw JSON response** in `sdk_response`, plus the installed SDK version, temporary file path, elapsed milliseconds, and a local `correlation_id`. The response is JSON-escaped inside a single-line event to preserve every returned field without splitting container log records. It includes engine versions, findings, hashes, service scan ID, timings, and other metadata when supplied by the service. No fields are fabricated when absent.

A second event, `filesecurity.scan.decision`, records the acceptance decision with the same correlation ID. Initialization, scanning, parsing, and cleanup failures are logged with tracebacks. The SDK channel is closed even when scanning fails.

Logs go to the server console (stderr), including under Gunicorn; no separate log file is created. For containers:

```bash
docker logs -f <container-name-or-id>
# Kubernetes:
kubectl logs -f deployment/fs-demoapp -n fs-demoapp
```

API keys and uploaded file bytes are not added to the log events. Extended service responses may include account identifiers, filenames, hashes, and detection details; handle the logs accordingly.

To update an existing virtual environment to the pinned SDK version:

```bash
python -m pip install --upgrade -r requirements.txt
python -c "from importlib.metadata import version; print(version('visionone-filesecurity'))"
```

Recreate environments older than Python 3.11 with a supported Python version. `bash run.sh` also installs the pinned version on startup. Rebuild Docker images to apply both the SDK and Python updates.

Release and API references: [PyPI](https://pypi.org/project/visionone-filesecurity/1.5.1/) and the [official Python SDK guide](https://github.com/trendmicro/tm-v1-fs-python-sdk).

## Health checks

```bash
curl http://localhost:8080/health
curl http://localhost:8080/ready
```

Both endpoints return HTTP 200 with a JSON status. They check application responsiveness; they do not validate credentials or connectivity to File Security.

## Container execution

```bash
docker build -t fs-demoapp .
docker run --rm --env-file .env -p 8080:8080 fs-demoapp
```

The image runs Gunicorn with two workers and a 120-second timeout, listening on port 8080. Its command fixes that port independently of `PORT`. Files inside the container are ephemeral unless you mount persistent storage at the configured upload directory. Deployment manifests are also available in `k8s/` and `openshift/`.

## Troubleshooting and demo limits

- **Missing credentials:** set `V1_API_KEY` and `V1_REGION` in `.env` or your shell.
- **Scan fails:** check server output, API permissions, region, and network access.
- **Cannot write uploads:** ensure `UPLOAD_FOLDER` exists or can be created and is writable.
- **Port already in use:** change `PORT` for local Python execution and open the matching URL.
- **Virtual environment fails:** install your platform's Python `venv` support. If moving between Windows and WSL, recreate the environment for the target platform or use separate checkouts.

`python app.py` runs Flask's development server, binding to all interfaces (`0.0.0.0`). This is a demo with no authentication or upload-management UI. Uploaded files persist on disk, and cleanup is manual. Review deployment security and file retention before exposing it beyond a demo environment.
