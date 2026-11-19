# TrendAI AI File Security Lab

A **second, standalone application** in this repository demonstrating a file-security checkpoint in two AI document workflows:

1. **Chat attachments:** scan an uploaded document before extracting text and attaching it to an assistant's context. One accepted attachment is active at a time.
2. **RAG ingestion:** scan each document before parsing, chunking, building retrieval vectors, and adding it to a persistent local knowledge base. Ask questions and inspect the retrieved sources, scores, chunk IDs, hashes, and service scan IDs.

The original application is still launched with `bash run.sh` on port 8080. This application uses **port 8081** by default and its own templates, static assets, database, and session cookie.

## Quick start: real File Security scans

Requirements: Python 3.11–3.14, Bash, and a Vision One API key with **Run file scan via SDK** permission in the configured region. Dependencies include `visionone-filesecurity==1.5.1` and `pypdf==7.1.0`.

From the repository root in Git Bash:

```bash
cd /d/Github/V1_FS_DemoApp_py
bash run_ai.sh
```

Open **http://localhost:8081**. The launcher loads the repository-root `.env`, installs the additional dependencies into `.venv`, and starts the new app. Use only a trusted, shell-compatible `.env`; its contents are sourced by Bash. The application module itself does not load `.env`.

Configuration example (also provided in [`.env.example`](.env.example)):

```bash
V1_API_KEY='your-key'
V1_REGION='us-east-1'
AI_DEMO_PORT=8081
SCAN_MODE=live
```

The SDK scans bytes using `scan_buffer(..., pml=True, verbose=True)`. This avoids the file-handle issue observed with `scan_file` on Windows during failed scans. A channel is closed in `finally`. No parser or model receives the upload before a valid, clean verdict. Authentication failures retain the original gRPC details when available, with the configured API key redacted.

### Manual environment setup

Linux / macOS / WSL, from the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r ai_demo/requirements.txt
set -a
source .env
set +a
python -m ai_demo.app
```

For Windows Python in Git Bash, use `python -m venv .venv` and `source .venv/Scripts/activate`. In PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r ai_demo/requirements.txt
$env:V1_API_KEY = 'your-key'
$env:V1_REGION = 'us-east-1'
.\.venv\Scripts\python.exe -m ai_demo.app
```

## Offline demonstration mode

```bash
SCAN_MODE=simulation bash run_ai.sh
```

If `.env` already defines `SCAN_MODE`, change its value there because the launcher sources it after inheriting shell variables. No Vision One credentials or network connection are required in simulation mode. A visible amber banner identifies all results as **synthetic**; the SDK is not called. Ordinary bytes receive a synthetic clean result. The harmless marker `[DEMO_BLOCK]` receives a synthetic detection. This is an intentional test double, not a malware detector. **Live mode never checks that marker:** it always relies on the real SDK.

Use the **Bloqueo simulado** sample to demonstrate that a rejected document does not reach parsing, context, or the index. Simulation also recognizes the exact built-in EICAR test bytes and returns a clearly synthetic detection. No actual malware is included. The EICAR antivirus test fixture is generated in memory for the guided comparison and optional download.

## Guided demo

### Three-stage RAG presentation: normal, unprotected, protected

Select **Knowledge / RAG** to open the new **El mismo archivo. Dos caminos.** comparison panel. Click **Ejecutar las 3 etapas** to run the sequence, or execute each stage separately while presenting:

| Stage | Input | Security checkpoint | Observable result |
| --- | --- | --- | --- |
| 1. Normal RAG | Fictional travel policy | Real SDK scan in `live` mode | A clean result permits extraction and indexing; retrieval finds the 180 USD hotel limit. |
| 2. Without protection | Standard 68-byte EICAR antivirus test | Intentionally skipped for this fixed fixture only | The test file is parsed, chunked, and retrieved as context. The comparison index contains the reference policy plus the test file. No SDK verdict is fabricated. |
| 3. With protection | Exactly the same EICAR bytes | Real SDK scan in `live` mode | A detection prevents extraction and indexing of the test file. Retrieval returns no EICAR chunks; the reference policy remains. |

**Ver evidencia** shows each stage's pipeline, document count, candidate fragment count, retrieved context, query, full SDK response, and file SHA-256. Once stages 2 and 3 have run, the UI verifies that the hashes match. An SDK error is shown as a failed scan, not as a detection. If the service unexpectedly accepts the sample, the UI reports acceptance rather than manufacturing a block.

These are independent, ephemeral experiments. Stages 2 and 3 each start with the same declared, preloaded reference policy fixture (not a fabricated SDK approval). Their candidate indices and retrieved passages exist only in memory. They do **not** change the persistent knowledge base or session activity below the comparison panel. Evidence remains in the browser until refresh. The comparison uses the real extraction, chunking, and TF-IDF retrieval functions, but never calls Ollama, even when a model is configured. It demonstrates a detectable file crossing the ingestion boundary, **not execution of malware, model infection, or a prompt-injection attack**.

In `simulation` mode, the UI explicitly labels the antivirus verdicts as synthetic; no protection claim should be made from that run. In `live` mode, the normal and protected stages call the real SDK. The unprotected stage is labeled **SIN ANÁLISIS** in both modes. The regular `/api/upload` endpoint always scans uploads: the comparison does not introduce a disable-scanning option for arbitrary files.

#### Obtain the test file

Use **Descargar eicar-test.txt** in the panel, or open `http://localhost:8081/api/rag-demo/test-file` while the app is running. It downloads the exact, standard 68-byte [EICAR antivirus test file](https://www.eicar.org/download-anti-malware-testfile/), with SHA-256:

```text
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

EICAR is not real malware. Antivirus products deliberately treat it as a detection, so a local antivirus or browser may block or quarantine the download. The integrated experiment buttons generate and process the same bytes in memory, without needing a file saved on your computer. The application never executes the test file. You can also upload the downloaded `.txt` through the regular protected RAG workflow to see its real scan response.

### Chat: protect a document before attaching it

1. Select **Chat con archivos**.
2. Click **Política de viajes**. The sample goes through the normal upload and scan endpoint.
3. Observe the pipeline and the real SDK response (or clearly marked synthetic result).
4. Ask: **¿Cuál es el límite de reembolso de hotel?** The sample states 180 USD per night.
5. Expand a citation to inspect the retrieved passage and its scan provenance.
6. A new accepted upload replaces the current chat attachment. A rejected upload leaves the previous accepted attachment intact.

### RAG: protect the knowledge ingestion boundary

1. Select **Knowledge / RAG**.
2. Load both **Política de viajes** and **Manual de soporte**.
3. Observe separate accepted documents and their fragment counts. Re-uploading identical bytes does not duplicate the index within the same workflow.
4. Ask the hotel question, then **¿Cuál es el tiempo de respuesta para un incidente crítico?** (15 minutes in the sample).
5. Inspect the source name, fragment number, similarity score, SHA-256, chunk ID, and scan ID used in each answer.
6. In simulation mode, load **Bloqueo simulado**. Its event stops at scanning; the document never appears in the knowledge base and cannot be retrieved.

The two workflows are isolated. A chat attachment is not automatically added to the RAG corpus. **Limpiar flujo** removes documents, chunks, activity, and the current browser conversation for the selected workflow only.

### Demonstrate the boundary of antimalware scanning

The **Contenido no confiable** sample contains a harmless textual prompt-injection example. An antimalware scan may accept it. This demonstrates a real limitation rather than claiming File Security detects prompt injection, misinformation, data poisoning, or sensitive-data leakage. Those concerns require additional AI security, authorization, and data controls. No document content is executed or rendered as HTML in this app.

## Retrieval and answer generation

By default, the assistant runs **locally without an LLM**. It returns relevant source excerpts with citations, explicitly labeled as an extractive response. It does not pretend to generate a model answer.

The retrieval implementation is inspectable: 800-character chunks with 120-character overlap; normalized token-count vectors persisted in SQLite; TF-IDF weighting and cosine similarity at query time; up to three relevant chunks. This is lexical retrieval, **not semantic embeddings**. Questions without matching evidence receive a no-evidence answer. A summary request may select the first three chunks and is not a full summary of the entire corpus.

For a complete retrieval-augmented **generative** flow, connect a running Ollama server and a model you have already installed:

```bash
# Add these optional values to the repository-root .env:
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=your-installed-model
```

Restart `bash run_ai.sh`. The app calls `POST /api/chat` with `stream=false`, the question, and the retrieved passages. The selected provider/model appears beside the assistant title. Only retrieved text is sent to Ollama, after scanning and parsing, not the raw upload. Pointing `OLLAMA_URL` at a remote server sends that text to the remote host. No model is automatically downloaded or started. An unavailable model returns an explicit error instead of silently falling back.

This assistant answers each question independently against the selected workflow's current documents. Browser message history is display-only and is not sent as conversational memory. Model output may contain mistakes or follow malicious document instructions; the system instruction is not a guarantee of prompt-injection resistance.

## Storage, limits, and deployment

| Setting | Default / behavior |
| --- | --- |
| `SCAN_MODE` | `live`; only `live` and `simulation` are accepted |
| `AI_DEMO_PORT` | `8081` for the Python development server |
| `AI_DEMO_DATA_DIR` | `ai_demo/.data`, ignored by Git |
| `FLASK_SECRET_KEY` | Uses the configured value, or a local key persisted beside the database |
| `OLLAMA_URL` | `http://localhost:11434` |
| `OLLAMA_MODEL` | Empty: local extractive answers |
| `TM_AM_SCAN_TIMEOUT_SECS` | `30` unless already configured before importing the SDK |
| Uploads | TXT/MD (UTF-8) and PDF with extractable text; 8 MiB total request |
| Documents | Up to 100,000 extracted characters; PDFs up to 40 pages, no OCR or encrypted PDFs |
| RAG corpus | Up to 30 accepted documents per browser session |
| Activity | Last 50 events per browser session across both workflows |

Raw uploads are scanned in memory and are not saved to disk. Accepted text chunks, vectors, scan provenance, and activity are stored in SQLite. SDK responses may contain account identifiers, hashes, filenames, and findings. The scanner emits full response events to stderr, but does not add API keys, file bytes, prompts, or extracted document text to those log events.

A signed session cookie contains a random browser identity and CSRF token, not the uploaded documents. Server-side queries are scoped to that identity. State persists across restarts while the database, secret, and cookie remain available. This is local demo isolation, not enterprise authentication. There is no automatic retention cleanup across abandoned sessions. Use the reset control for the active workflow; removing the database invalidates stored knowledge for all local demo sessions.

The development server binds to loopback. Production deployments need authentication, HTTPS, secure cookies, quotas, retention policies, and resource isolation for document parsers. The PDF limits are demo safeguards, not a parser sandbox. A successful antimalware verdict does not prove that parsing a file is risk-free.

### Docker

From the repository root:

```bash
docker build -f ai_demo/Dockerfile -t trendai-ai-file-security .
docker run --rm --name trendai-ai-demo --env-file .env \
  -p 127.0.0.1:8081:8081 -v trendai-ai-data:/app/data trendai-ai-file-security
docker logs -f trendai-ai-demo
```

The container uses Gunicorn on port 8081, independently of `AI_DEMO_PORT`, with one worker and four threads. The volume retains SQLite data and the fallback session key. To reach a host Ollama server from Docker Desktop, configure `OLLAMA_URL=http://host.docker.internal:11434` and ensure that server is reachable from the container.

## Verification

From the repository root:

```bash
python -m unittest discover -s ai_demo/tests -v
node --check ai_demo/static/app.js
curl http://localhost:8081/health
```

Unit tests use mocked SDK responses or the explicit simulation mode; they do not upload content to external services. `/health` reports process responsiveness and the configured scan mode; it does not certify credentials or connectivity.

Official references: [File Security Python SDK](https://github.com/trendmicro/tm-v1-fs-python-sdk), [pypdf text extraction](https://pypdf.readthedocs.io/en/stable/user/extract-text.html), and [Ollama chat API](https://docs.ollama.com/api/chat).
