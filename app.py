from flask import Flask, request, redirect, url_for, render_template, flash, jsonify
from werkzeug.utils import secure_filename
import os
import tempfile
import amaas.grpc
import time
import json
import logging
from importlib.metadata import version
from uuid import uuid4

app = Flask(__name__)
app.logger.setLevel(logging.INFO)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'change-me-in-production')

UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/health')
def health():
    return jsonify(status='ok'), 200


@app.route('/ready')
def ready():
    return jsonify(status='ready'), 200


@app.route('/')
def upload_form():
    return render_template('upload.html')


def scan_is_clean(result):
    """Read both SDK response formats; reject detections, errors and unknown data."""
    if not isinstance(result, dict):
        return False
    if result.get('scanResult') not in (None, 0) or result.get('foundMalwares') or result.get('error'):
        return False
    if 'result' in result:
        engines = result['result']
        if not isinstance(engines, dict) or not engines:
            return False
        return all(
            isinstance(engine, dict)
            and type(engine.get('malwareCount')) is int
            and engine['malwareCount'] == 0
            and not engine.get('malware')
            and not engine.get('error')
            for engine in engines.values()
        )
    return 'scanResult' in result and result['scanResult'] in (None, 0)


def malware_scan(file_path):
    handle = None
    correlation_id = uuid4().hex
    started = time.perf_counter()
    try:
        handle = amaas.grpc.init_by_region(region=os.getenv("V1_REGION"), api_key=os.getenv("V1_API_KEY"))
        result = amaas.grpc.scan_file(
            handle, file_name=file_path, pml=True, feedback=True,
            tags=['DemoApp', 'Container', 'Python'], verbose=True,
        )
        # Preserve the entire response, including unknown fields and malformed JSON.
        # JSON escaping keeps each event on one line for container log collectors.
        app.logger.info(json.dumps({
            'event': 'filesecurity.scan.response',
            'correlation_id': correlation_id,
            'sdk_version': version('visionone-filesecurity'),
            'file_path': file_path,
            'elapsed_ms': round((time.perf_counter() - started) * 1000, 2),
            'sdk_response': result,
        }))
        accepted = scan_is_clean(json.loads(result))
        app.logger.info(json.dumps({
            'event': 'filesecurity.scan.decision',
            'correlation_id': correlation_id,
            'accepted': accepted,
        }))
        return accepted
    except Exception:
        app.logger.exception('File Security scan failed correlation_id=%s', correlation_id)
        return False
    finally:
        if handle is not None:
            try:
                amaas.grpc.quit(handle)
            except Exception:
                app.logger.exception('File Security cleanup failed correlation_id=%s', correlation_id)


@app.route('/', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('Selecciona un archivo para iniciar el análisis.', 'error')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('Selecciona un archivo para iniciar el análisis.', 'error')
        return redirect(request.url)
    if not (file and allowed_file(file.filename)):
        flash('Tipo de archivo no permitido', 'error')
        return redirect(request.url)

    filename = secure_filename(file.filename)
    ext = os.path.splitext(filename)[1]

    # Save to temp location first, then scan before committing to uploads
    fd, tmp_path = tempfile.mkstemp(suffix=ext, dir=app.config['UPLOAD_FOLDER'])
    try:
        with os.fdopen(fd, 'wb') as tmp_file:
            file.save(tmp_file)

        if malware_scan(tmp_path):
            final_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            os.replace(tmp_path, final_path)
            flash(f'Archivo {filename} subido exitosamente', 'success')
        else:
            os.unlink(tmp_path)
            flash(f'Archivo {filename} es malicioso', 'error')
    except Exception as e:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        flash(f'Error al procesar el archivo: {str(e)}', 'error')

    return redirect(url_for('upload_form'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 8080)), debug=False)
