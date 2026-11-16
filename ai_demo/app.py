"""Run with: python -m ai_demo.app (separate from the original demo)."""
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import secrets
import sqlite3
from uuid import uuid4

from flask import Flask, g, jsonify, render_template, request, session, send_file
from werkzeug.utils import secure_filename

from .retrieval import answer, chunk_text, extract_text, retrieve, terms
from .security import scan_bytes

MODES = {'chat', 'rag'}
SAMPLES = Path(__file__).parent / 'samples'


def create_app(config=None):
    app = Flask(__name__)
    data_dir = Path(os.getenv('AI_DEMO_DATA_DIR', str(Path(__file__).parent / '.data')))
    app.config.update(
        MAX_CONTENT_LENGTH=8 * 1024 * 1024,
        DATABASE=str(data_dir / 'demo.sqlite3'),
        SCAN_MODE=os.getenv('SCAN_MODE', 'live'),
        SESSION_COOKIE_NAME='trendai_ai_demo',
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
    )
    if config:
        app.config.update(config)
    if app.config['SCAN_MODE'] not in {'live', 'simulation'}:
        raise ValueError('SCAN_MODE must be live or simulation')
    Path(app.config['DATABASE']).parent.mkdir(parents=True, exist_ok=True)
    if not app.config.get('SECRET_KEY'):
        secret_path = Path(app.config['DATABASE']).parent / 'session.key'
        if not secret_path.exists():
            try:
                with secret_path.open('x', encoding='utf-8') as file:
                    file.write(secrets.token_hex(32))
                secret_path.chmod(0o600)
            except FileExistsError:
                pass
        app.secret_key = os.getenv('FLASK_SECRET_KEY') or secret_path.read_text(encoding='utf-8')

    def db():
        if 'db' not in g:
            g.db = sqlite3.connect(app.config['DATABASE'], timeout=15)
            g.db.row_factory = sqlite3.Row
            g.db.execute('PRAGMA foreign_keys = ON')
        return g.db

    with app.app_context():
        db().executescript('''
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS documents (
                id TEXT PRIMARY KEY, owner TEXT NOT NULL, mode TEXT NOT NULL,
                name TEXT NOT NULL, sha256 TEXT NOT NULL, scan_id TEXT, created TEXT NOT NULL,
                UNIQUE(owner, mode, sha256)
            );
            CREATE TABLE IF NOT EXISTS chunks (
                id TEXT PRIMARY KEY, document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
                position INTEGER NOT NULL, text TEXT NOT NULL, vector TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY, owner TEXT NOT NULL, mode TEXT NOT NULL,
                payload TEXT NOT NULL
            );
        ''')
        g.pop('db').close()

    @app.teardown_appcontext
    def close_db(error=None):
        connection = g.pop('db', None)
        if connection:
            connection.close()

    @app.before_request
    def identity():
        session.setdefault('owner', uuid4().hex)
        session.setdefault('csrf', secrets.token_hex(24))
        if request.method == 'POST' and not secrets.compare_digest(
            request.headers.get('X-CSRF-Token', ''), session['csrf'],
        ):
            return jsonify(error='Sesión inválida. Recarga la página e intenta de nuevo.'), 403

    @app.after_request
    def headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        return response

    @app.errorhandler(413)
    def too_large(error):
        return jsonify(error='La solicitud supera el límite de 8 MiB.'), 413

    @app.get('/')
    def home():
        return render_template('index.html')

    @app.get('/health')
    def health():
        return jsonify(status='ok', scan_mode=app.config['SCAN_MODE'])

    @app.get('/api/state')
    def state():
        docs = [dict(row) for row in db().execute('''
            SELECT d.id, d.mode, d.name, d.sha256, d.scan_id, d.created, COUNT(c.id) AS chunks
            FROM documents d LEFT JOIN chunks c ON d.id=c.document_id
            WHERE owner=? GROUP BY d.id ORDER BY d.created DESC
        ''', (session['owner'],))]
        events = [json.loads(row['payload']) for row in db().execute(
            'SELECT payload FROM events WHERE owner=? ORDER BY id DESC LIMIT 50', (session['owner'],))]
        return jsonify(documents=docs, events=events, csrf=session['csrf'],
                       scan_mode=app.config['SCAN_MODE'],
                       engine=f"Ollama / {os.environ['OLLAMA_MODEL']}" if os.getenv('OLLAMA_MODEL') else 'Local · respuesta extractiva')

    @app.get('/api/samples/<name>')
    def sample(name):
        if name not in {'politica-viajes.txt', 'manual-soporte.md', 'prompt-injection.txt', 'simulated-block.txt'}:
            return jsonify(error='Ejemplo no encontrado.'), 404
        return send_file(SAMPLES / name, as_attachment=True, download_name=name)

    @app.post('/api/upload')
    def upload():
        mode = request.form.get('mode')
        file = request.files.get('file')
        if mode not in MODES or not file or not file.filename:
            return jsonify(error='Selecciona un archivo y un flujo válido.'), 400
        filename = secure_filename(file.filename)
        if not filename.lower().endswith(('.txt', '.md', '.pdf')):
            return jsonify(error='Formatos admitidos: TXT, MD y PDF con texto.'), 400
        content = file.read()
        if not content:
            return jsonify(error='El archivo está vacío.'), 400
        # No document parsing, chunking, or model invocation is allowed before this verdict.
        scan = scan_bytes(content, filename, app.config['SCAN_MODE'])
        event = {
            **scan, 'scan_status': scan['status'], 'filename': filename, 'mode': mode,
            'created': datetime.now(timezone.utc).isoformat(),
            'sha256': hashlib.sha256(content).hexdigest(), 'chunks': 0,
            'stages': ['received', 'scanned'], 'indexed': False,
        }
        pieces = []
        if scan['status'] == 'clean':
            try:
                text = extract_text(content, filename)
                pieces = chunk_text(text)
                event['stages'] += ['extracted', 'chunked']
                event['chunks'] = len(pieces)
            except Exception:
                event['status'] = 'error'
                event['error'] = 'El archivo pasó el análisis, pero no pudo extraerse como texto. Usa TXT/MD UTF-8 o un PDF de texto no cifrado de hasta 40 páginas y 100.000 caracteres.'
        with db() as connection:
            connection.execute('BEGIN IMMEDIATE')
            if pieces:
                count = connection.execute('SELECT COUNT(*) FROM documents WHERE owner=? AND mode=?',
                                           (session['owner'], mode)).fetchone()[0]
                duplicate = connection.execute('SELECT id FROM documents WHERE owner=? AND mode=? AND sha256=?',
                                               (session['owner'], mode, event['sha256'])).fetchone()
                if mode == 'rag' and count >= 30 and not duplicate:
                    event.update(status='error', error='La base RAG llegó al límite de 30 documentos. Limpia la demo para continuar.')
                else:
                    if mode == 'chat':
                        connection.execute('DELETE FROM documents WHERE owner=? AND mode=?', (session['owner'], mode))
                        duplicate = None
                    if not duplicate:
                        document_id = uuid4().hex
                        sdk_data = scan['sdk_response'] if isinstance(scan['sdk_response'], dict) else {}
                        connection.execute('INSERT INTO documents VALUES (?, ?, ?, ?, ?, ?, ?)',
                                           (document_id, session['owner'], mode, filename, event['sha256'],
                                            sdk_data.get('scanId'), event['created']))
                        connection.executemany('INSERT INTO chunks VALUES (?, ?, ?, ?, ?)', [
                            (uuid4().hex, document_id, position, piece, json.dumps(terms(piece)))
                            for position, piece in enumerate(pieces)
                        ])
                    event['indexed'] = True
                    event['duplicate'] = bool(duplicate)
                    event['stages'] += ['indexed' if mode == 'rag' else 'attached']
            connection.execute('INSERT INTO events(owner, mode, payload) VALUES (?, ?, ?)',
                               (session['owner'], mode, json.dumps(event)))
            connection.execute('DELETE FROM events WHERE owner=? AND id NOT IN (SELECT id FROM events WHERE owner=? ORDER BY id DESC LIMIT 50)',
                               (session['owner'], session['owner']))
        return jsonify(event=event)

    @app.post('/api/ask')
    def ask():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(error='Se requiere una pregunta JSON.'), 400
        mode = data.get('mode')
        question = data.get('question', '')
        if mode not in MODES or not isinstance(question, str) or not 1 <= len(question.strip()) <= 1000:
            return jsonify(error='Escribe una pregunta de hasta 1.000 caracteres.'), 400
        rows = db().execute('''
            SELECT c.id, c.position, c.text, c.vector, d.name, d.sha256, d.scan_id
            FROM chunks c JOIN documents d ON d.id=c.document_id
            WHERE d.owner=? AND d.mode=? ORDER BY d.created, c.position
        ''', (session['owner'], mode)).fetchall()
        sources = retrieve(question.strip(), rows)
        try:
            response, engine = answer(question.strip(), sources)
        except Exception:
            app.logger.warning('AI generation failed (document content omitted)')
            return jsonify(error='No se pudo consultar Ollama. Revisa OLLAMA_URL, OLLAMA_MODEL y que el modelo esté disponible. No se generó una respuesta.'), 502
        safe_sources = [{k: v for k, v in source.items() if k != 'vector'} for source in sources]
        return jsonify(answer=response, sources=safe_sources, engine=engine, mode=mode)

    @app.post('/api/reset')
    def reset():
        data = request.get_json(silent=True) or {}
        mode = data.get('mode') if isinstance(data, dict) else None
        if mode not in MODES:
            return jsonify(error='Flujo inválido.'), 400
        with db() as connection:
            connection.execute('DELETE FROM documents WHERE owner=? AND mode=?', (session['owner'], mode))
            connection.execute('DELETE FROM events WHERE owner=? AND mode=?', (session['owner'], mode))
        return jsonify(ok=True)

    return app


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    create_app().run(host='127.0.0.1', port=int(os.getenv('AI_DEMO_PORT', '8081')), debug=False)
