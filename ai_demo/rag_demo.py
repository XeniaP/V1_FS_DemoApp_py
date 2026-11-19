"""Three isolated, in-memory RAG experiments; only the fixed fixture can skip scanning."""
import hashlib
import json
from pathlib import Path

from .retrieval import chunk_text, extract_text, retrieve, terms
from .security import scan_bytes
from .test_files import eicar_bytes

SCENARIOS = {'normal', 'unprotected', 'protected'}


def run_scenario(scenario, scan_mode):
    if scenario not in SCENARIOS:
        raise ValueError('Escenario inválido.')
    is_test = scenario != 'normal'
    filename = 'eicar-test.txt' if is_test else 'politica-viajes.txt'
    content = eicar_bytes() if is_test else (Path(__file__).parent / 'samples' / filename).read_bytes()
    question = 'EICAR STANDARD ANTIVIRUS TEST FILE' if is_test else 'limite de reembolso hotel'
    sha256 = hashlib.sha256(content).hexdigest()
    # Stages 2/3 start with the same fixed reference policy, as an existing corpus.
    # It is a declared fixture, not a fabricated SDK approval or a user upload.
    baseline = []
    if is_test:
        policy = (Path(__file__).parent / 'samples' / 'politica-viajes.txt').read_bytes()
        baseline = [
            dict(id=f'reference-{i}', position=i, text=piece, vector=json.dumps(terms(piece)),
                 name='politica-viajes.txt', sha256=hashlib.sha256(policy).hexdigest(),
                 scan_id=None, preloaded_fixture=True)
            for i, piece in enumerate(chunk_text(policy.decode('utf-8')))
        ]
    steps = [dict(id='received', label='Archivo recibido', status='complete')]
    if scenario == 'unprotected':
        # Deliberately scoped to the built-in harmless antivirus fixture, not uploads.
        scan = {'status': 'not_scanned', 'scan_mode': 'not_scanned',
                'sdk_response': None, 'error': None}
        steps.append(dict(id='scanned', label='Sin análisis (laboratorio)', status='skipped'))
        may_parse = True
    else:
        scan = scan_bytes(content, filename, scan_mode)
        steps.append(dict(id='scanned', label='File Security',
                          status='complete' if scan['status'] == 'clean' else 'stopped'))
        may_parse = scan['status'] == 'clean'
    chunks = []
    if may_parse:
        text = extract_text(content, filename)
        steps.append(dict(id='extracted', label='Texto extraído', status='complete'))
        chunks = [
            dict(id=f'{sha256[:12]}-{i}', position=i, text=piece,
                 vector=json.dumps(terms(piece)), name=filename, sha256=sha256,
                 scan_id=(scan.get('sdk_response') or {}).get('scanId'))
            for i, piece in enumerate(chunk_text(text))
        ]
        steps.append(dict(id='indexed', label='Fragmentos indexados', status='complete'))
    else:
        steps.extend([dict(id='extracted', label='Extracción impedida', status='pending'),
                      dict(id='indexed', label='Índice sin el archivo', status='pending')])
    sources = retrieve(question, baseline + chunks)
    steps.append(dict(id='retrieved', label='Recuperación de contexto', status='complete'))
    # Never send the unscanned fixture to a model or write it to the persistent corpus.
    if sources:
        context = '\n\n'.join(f'[{i}] {source["name"]}\n{source["text"]}'
                              for i, source in enumerate(sources, 1))
    else:
        context = 'No hay fragmentos del archivo de prueba disponibles para recuperar.'
    if scenario == 'unprotected':
        summary = ('Sin checkpoint, la muestra EICAR fue extraída, indexada y recuperada como contexto. '
                   'Esto demuestra la entrada de un archivo detectable al flujo, no la ejecución de malware ni una infección del modelo.')
    elif scan['status'] == 'blocked':
        summary = 'File Security detectó la muestra de antivirus. El archivo no llegó al parser ni al índice y no se recuperó como contexto.'
    elif scan['status'] == 'error':
        summary = 'El análisis falló. La ingesta se detuvo por falta de un veredicto válido; esto no acredita una detección de malware.'
    elif is_test:
        summary = 'El servicio aceptó la muestra de prueba. No se demostró un bloqueo: revisa la respuesta del SDK.'
    else:
        summary = 'El documento pasó el análisis y se recuperó información sobre el límite de hotel. Flujo RAG normal.'
    return {
        'scenario': scenario, 'filename': filename, 'sha256': sha256, 'size_bytes': len(content),
        'fixture': 'EICAR antivirus test (not real malware)' if is_test else 'Travel policy sample',
        'scan': scan, 'steps': steps, 'indexed': bool(chunks),
        'documents_before': int(bool(baseline)),
        'documents': int(bool(baseline)) + int(bool(chunks)),
        'chunks': len(baseline) + len(chunks), 'candidate_chunks': len(chunks),
        'retrieved': len(sources),
        'question': question, 'context': context, 'summary': summary,
        'sources': [{k: v for k, v in source.items() if k != 'vector'} for source in sources],
        'storage': 'isolated-memory', 'model_called': False,
    }
