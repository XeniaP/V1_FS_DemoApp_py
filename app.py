from flask import Flask, request, redirect, url_for, render_template, flash, jsonify
from werkzeug.utils import secure_filename
import os
import tempfile
import amaas.grpc
import time
import json

app = Flask(__name__)
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


def malware_scan(file_path):
    handle = amaas.grpc.init_by_region(region=os.getenv("V1_REGION"), api_key=os.getenv("V1_API_KEY"))
    try:
        result = amaas.grpc.scan_file(handle, file_name=file_path, pml=True, feedback=True, tags="['DemoApp', 'Container', 'Python']")
        amaas.grpc.quit(handle)
        return json.loads(result).get("scanResult", 1) != 1
    except Exception as e:
        print(e)
        return False


@app.route('/', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No se seleccionó ningún archivo', 'error')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No se seleccionó ningún archivo', 'error')
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
