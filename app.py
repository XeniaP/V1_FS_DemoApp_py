from flask import Flask, request, redirect, url_for, render_template, flash
import os

import amaas.grpc
import time
import json

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Cambia esto por una clave secreta segura

# Carpeta donde se guardarán los archivos subidos
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Máximo tamaño de archivo permitido: 16 MB

# Extensiones de archivos permitidas
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def upload_form():
    return render_template('upload.html')

def malware_scan(file):
    handle = amaas.grpc.init_by_region(region=os.getenv("V1_REGION"), api_key=os.getenv("V1_API_KEY"))
    s = time.perf_counter()
    #print(f"scan started at {s}.")
    #print(f"file: {os.path.join(app.config['UPLOAD_FOLDER'], file)}")
    try:
        result = amaas.grpc.scan_file(handle, file_name=file, pml=True, feedback=True, tags="['DemoApp', 'Container', 'Python']")
        #elapsed = time.perf_counter() - s
        #print(f"scan executed in {elapsed:0.2f} seconds.")
        amaas.grpc.quit(handle)
        if json.loads(result)["scanResult"] == 1:
            return False
        else:
            print("SANDOBOX_CALLING")
        return True
    except Exception as e:
        print(e)
    

@app.route('/', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No se seleccionó ningún archivo','error')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No se seleccionó ningún archivo', 'error')
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = file.filename
        userAgent = request.headers.get('User-Agent')
        if malware_scan(os.path.join(app.config['UPLOAD_FOLDER'], filename)):
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash(f'Archivo {filename} subido exitosamente', 'success')
        else:
            flash(f'Archivo {filename} es malicioso', 'error')
        return redirect(url_for('upload_form'))
    else:
        flash('Tipo de archivo no permitido', 'error')
        return redirect(request.url)

if __name__ == "__main__":
    app.run(debug=True)
