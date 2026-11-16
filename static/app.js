(() => {
    const form = document.getElementById('upload-form');
    const input = document.getElementById('file');
    const zone = document.getElementById('drop-zone');
    const summary = document.getElementById('file-summary');
    const error = document.getElementById('client-error');
    const button = document.getElementById('scan-button');
    const allowed = new Set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif']);
    function validate() {
        const file = input.files[0];
        summary.hidden = !file;
        error.hidden = true;
        input.setCustomValidity('');
        if (!file) return false;
        document.getElementById('file-name').textContent = file.name;
        document.getElementById('file-size').textContent = `${(file.size / 1024 / 1024).toFixed(2)} MiB`;
        let message = '';
        if (!allowed.has(file.name.split('.').pop().toLowerCase()) || !file.name.includes('.')) {
            message = 'Formato no admitido. Selecciona un archivo TXT, PDF, PNG, JPG, JPEG o GIF.';
        } else if (file.size >= 16 * 1024 * 1024) {
            message = 'El archivo debe ser menor de 16 MiB para dejar espacio a los datos de la solicitud.';
        }
        input.setCustomValidity(message);
        error.textContent = message;
        error.hidden = !message;
        return !message;
    }
    input.addEventListener('change', validate);
    document.getElementById('clear-file').addEventListener('click', () => {
        input.value = '';
        validate();
        input.focus();
    });
    ['dragenter', 'dragover'].forEach(event => zone.addEventListener(event, e => {
        e.preventDefault();
        zone.classList.add('dragging');
    }));
    ['dragleave', 'drop'].forEach(event => zone.addEventListener(event, e => {
        e.preventDefault();
        zone.classList.remove('dragging');
    }));
    zone.addEventListener('drop', e => {
        if (e.dataTransfer.files.length !== 1) {
            error.textContent = 'Selecciona un solo archivo por análisis.';
            error.hidden = false;
            return;
        }
        input.files = e.dataTransfer.files;
        validate();
    });
    form.addEventListener('submit', e => {
        if (!validate()) {
            e.preventDefault();
            input.reportValidity();
            return;
        }
        button.disabled = true;
        document.getElementById('button-label').textContent = 'Analizando archivo…';
        document.getElementById('button-icon').textContent = '…';
        document.getElementById('scan-status').hidden = false;
        form.setAttribute('aria-busy', 'true');
    });
    // Restore controls when navigating back to a page cached during submission.
    window.addEventListener('pageshow', () => {
        button.disabled = false;
        document.getElementById('button-label').textContent = 'Analizar archivo';
        document.getElementById('button-icon').textContent = '→';
        document.getElementById('scan-status').hidden = true;
        form.removeAttribute('aria-busy');
        validate();
    });
})();
