"""Scan bytes before any document parser or index sees them."""
import json
import logging
import os
import time
from importlib.metadata import version
from uuid import uuid4

os.environ.setdefault('TM_AM_SCAN_TIMEOUT_SECS', '30')
import amaas.grpc
import grpc
from .test_files import eicar_bytes

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
if not logger.handlers:
    logger.addHandler(logging.StreamHandler())
logger.propagate = False


def verdict(data):
    if not isinstance(data, dict):
        return 'error'
    if data.get('error'):
        return 'error'
    compact = data.get('scanResult')
    if compact is not None and (type(compact) is not int or compact < 0):
        return 'error'
    if data.get('foundMalwares') or compact not in (None, 0):
        return 'blocked'
    if 'result' in data:
        engines = data['result']
        if not isinstance(engines, dict) or not engines:
            return 'error'
        for engine in engines.values():
            if not isinstance(engine, dict) or engine.get('error'):
                return 'error'
            count = engine.get('malwareCount')
            if type(count) is not int or count < 0:
                return 'error'
            if count or engine.get('malware'):
                return 'blocked'
        return 'clean'
    return 'clean' if 'scanResult' in data else 'error'


def scan_bytes(content, filename, mode='live'):
    started = time.perf_counter()
    correlation_id = uuid4().hex
    response = None
    handle = None
    error = None
    try:
        if mode == 'simulation':
            # This marker is not malware and is never used as a live SDK verdict.
            detected = b'[DEMO_BLOCK]' in content or content == eicar_bytes()
            response = {
                'simulation': True, 'scanId': f'sim-{correlation_id}',
                'scanResult': 1 if detected else 0,
                'foundMalwares': [{'malwareName': 'SIMULATED_DETECTION'}] if detected else [],
            }
        elif mode == 'live':
            key = os.getenv('V1_API_KEY', '').strip()
            region = os.getenv('V1_REGION', '').strip()
            if not key or not region:
                raise ValueError('Configura V1_API_KEY y V1_REGION para usar el SDK real.')
            handle = amaas.grpc.init_by_region(region=region, api_key=key)
            raw = amaas.grpc.scan_buffer(
                handle, bytes_buffer=content, uid=filename, pml=True, verbose=True,
            )
            try:
                response = json.loads(raw)
            except (TypeError, ValueError):
                response = {'raw_response': str(raw)}
                raise ValueError('El SDK devolvió una respuesta JSON inválida.')
        else:
            raise ValueError('SCAN_MODE debe ser live o simulation.')
        status = verdict(response)
    except Exception as exc:
        status = 'error'
        key = os.getenv('V1_API_KEY', '')
        message = str(exc)
        # The SDK maps UNAUTHENTICATED to a generic error; retain the real cause.
        cause = exc.__context__
        if isinstance(cause, grpc.RpcError):
            message = f'{cause.code().name}: {cause.details()}'
        error = message.replace(key, '[REDACTED]') if key else message
    finally:
        if handle is not None:
            try:
                amaas.grpc.quit(handle)
            except Exception:
                logger.warning('File Security channel cleanup failed correlation_id=%s', correlation_id)
    result = {
        'status': status, 'scan_mode': mode, 'correlation_id': correlation_id,
        'sdk_version': version('visionone-filesecurity'),
        'elapsed_ms': round((time.perf_counter() - started) * 1000, 2),
        'sdk_response': response, 'error': error,
    }
    # Do not log the file content, API key, prompts, or extracted text.
    logger.log(logging.INFO if status == 'clean' else logging.WARNING,
               json.dumps({'event': 'ai.filesecurity.scan', **result}, ensure_ascii=True))
    return result
