import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ai_demo.app import create_app
from ai_demo.security import scan_bytes, verdict


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.app = create_app({
            'TESTING': True, 'SECRET_KEY': 'test-only', 'SCAN_MODE': 'simulation',
            'DATABASE': str(Path(self.directory.name) / 'test.sqlite3'),
        })
        self.client = self.app.test_client()
        self.csrf = self.client.get('/api/state').json['csrf']

    def tearDown(self):
        self.directory.cleanup()

    def upload(self, content, name='policy.txt', mode='rag', client=None, csrf=None):
        response = (client or self.client).post('/api/upload', data={
            'mode': mode, 'file': (io.BytesIO(content), name),
        }, headers={'X-CSRF-Token': csrf or self.csrf})
        response.close()
        return response

    def post(self, path, data):
        return self.client.post(path, json=data, headers={'X-CSRF-Token': self.csrf})

    def test_pages_and_assets(self):
        page = self.client.get('/')
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'AI File Security', page.data)
        for asset in ('app.js', 'app.css'):
            with self.client.get('/static/' + asset) as response:
                self.assertEqual(response.status_code, 200)
        self.assertIn("frame-ancestors 'none'", page.headers['Content-Security-Policy'])

    def test_rag_ingestion_retrieval_citations_and_deduplication(self):
        event = self.upload(b'El limite de reembolso del hotel es de 180 USD por noche.').json['event']
        self.assertTrue(event['indexed'])
        self.assertEqual(event['stages'], ['received', 'scanned', 'extracted', 'chunked', 'indexed'])
        self.upload(b'El limite de reembolso del hotel es de 180 USD por noche.')
        self.assertEqual(len(self.client.get('/api/state').json['documents']), 1)
        self.upload(b'El tiempo de respuesta de soporte critico es de 15 minutos.', 'support.txt')
        result = self.post('/api/ask', {'mode': 'rag', 'question': 'limite de hotel'}).json
        self.assertIn('180 USD', result['answer'])
        self.assertEqual(result['sources'][0]['name'], 'policy.txt')
        self.assertTrue(result['sources'][0]['scan_id'].startswith('sim-'))
        self.assertNotIn('vector', result['sources'][0])
        self.assertEqual(len(self.client.get('/api/state').json['documents']), 2)

    @patch('ai_demo.app.extract_text', side_effect=AssertionError('must not parse blocked data'))
    def test_blocked_document_never_reaches_parser_or_index(self, extract):
        event = self.upload(b'[DEMO_BLOCK] malware demo').json['event']
        self.assertEqual(event['status'], 'blocked')
        self.assertFalse(event['indexed'])
        extract.assert_not_called()
        state = self.client.get('/api/state').json
        self.assertEqual(state['documents'], [])
        result = self.post('/api/ask', {'mode': 'rag', 'question': 'malware demo'}).json
        self.assertEqual(result['sources'], [])

    @patch('ai_demo.app.scan_bytes', return_value={
        'status': 'error', 'sdk_response': None, 'error': 'SDK unavailable',
        'scan_mode': 'live', 'correlation_id': 'test-error', 'elapsed_ms': 2,
    })
    @patch('ai_demo.app.extract_text')
    def test_scan_error_never_reaches_parser(self, extract, scan):
        event = self.upload(b'never parse this').json['event']
        self.assertEqual(event['status'], 'error')
        self.assertFalse(event['indexed'])
        extract.assert_not_called()

    def test_clean_but_unparseable_document_not_indexed(self):
        event = self.upload(b'not really a PDF', 'bad.pdf').json['event']
        self.assertEqual(event['scan_status'], 'clean')
        self.assertEqual(event['status'], 'error')
        self.assertFalse(event['indexed'])
        self.assertEqual(self.client.get('/api/state').json['documents'], [])

    def test_chat_context_replacement_and_mode_isolation(self):
        self.upload(b'hotel limite 180 USD', mode='chat')
        self.upload(b'[DEMO_BLOCK]', mode='chat')
        self.assertEqual(len(self.client.get('/api/state').json['documents']), 1)
        self.upload(b'soporte critico 15 minutos', 'new.txt', 'chat')
        docs = self.client.get('/api/state').json['documents']
        self.assertEqual([doc['name'] for doc in docs], ['new.txt'])
        self.assertEqual(self.post('/api/ask', {'mode': 'rag', 'question': 'soporte critico'}).json['sources'], [])

    def test_client_isolation_csrf_and_reset_scope(self):
        self.upload(b'hotel limite 180 USD')
        self.upload(b'soporte critico 15 minutos', mode='chat')
        other = self.app.test_client()
        csrf = other.get('/api/state').json['csrf']
        self.assertEqual(other.get('/api/state').json['documents'], [])
        self.assertEqual(other.get('/api/state').json['events'], [])
        result = other.post('/api/ask', json={'mode': 'rag', 'question': 'hotel'}, headers={'X-CSRF-Token': csrf})
        self.assertEqual(result.json['sources'], [])
        self.assertEqual(self.client.post('/api/reset', json={'mode': 'rag'}).status_code, 403)
        self.assertEqual(self.post('/api/reset', {'mode': 'rag'}).status_code, 200)
        docs = self.client.get('/api/state').json['documents']
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]['mode'], 'chat')

    def test_input_validation(self):
        self.assertEqual(self.upload(b'x', 'file.exe').status_code, 400)
        self.assertEqual(self.upload(b'', 'file.txt').status_code, 400)
        self.assertEqual(self.upload(b'x', mode='unknown').status_code, 400)
        self.assertEqual(self.post('/api/ask', {'mode': 'rag', 'question': []}).status_code, 400)
        self.assertEqual(self.post('/api/ask', {'mode': 'rag', 'question': 'x' * 1001}).status_code, 400)
        self.assertEqual(self.client.get('/api/samples/not-a-sample').status_code, 404)
        self.assertEqual(self.upload(b'x' * (8 * 1024 * 1024)).status_code, 413)

    def test_knowledge_survives_app_restart(self):
        self.upload(b'hotel limite 180 USD')
        new_app = create_app({
            'TESTING': True, 'SECRET_KEY': 'test-only', 'SCAN_MODE': 'simulation',
            'DATABASE': self.app.config['DATABASE'],
        })
        client = new_app.test_client()
        client.set_cookie('trendai_ai_demo', self.client.get_cookie('trendai_ai_demo').value)
        self.assertEqual(len(client.get('/api/state').json['documents']), 1)


class ScannerTests(unittest.TestCase):
    def test_malformed_response_cannot_be_clean(self):
        for data in (None, [], {}, {'result': {}}, {'result': {'atse': {}}},
                     {'result': {'atse': {'malwareCount': -1}}}, {'scanResult': 'unknown'},
                     {'scanResult': False}):
            self.assertEqual(verdict(data), 'error')
        self.assertEqual(verdict({'scanResult': 2}), 'blocked')
        self.assertEqual(verdict({'scanResult': 0}), 'clean')
        self.assertEqual(verdict({'result': {'atse': {'malwareCount': 0, 'error': None}}}), 'clean')

    @patch('ai_demo.security.amaas.grpc.scan_buffer')
    @patch('ai_demo.security.amaas.grpc.init_by_region')
    @patch('ai_demo.security.amaas.grpc.quit')
    def test_live_sdk_used_without_local_simulation_marker(self, quit, init, scan):
        scan.return_value = json.dumps({'scanResult': 0})
        with patch.dict(os.environ, {'V1_API_KEY': 'test-key', 'V1_REGION': 'us-east-1'}):
            result = scan_bytes(b'[DEMO_BLOCK]', 'test.txt', 'live')
        self.assertEqual(result['status'], 'clean')
        self.assertTrue(scan.call_args.kwargs['verbose'])
        self.assertEqual(scan.call_args.kwargs['bytes_buffer'], b'[DEMO_BLOCK]')
        quit.assert_called_once_with(init.return_value)

    @patch('ai_demo.security.amaas.grpc.init_by_region')
    def test_simulation_never_calls_sdk(self, init):
        self.assertEqual(scan_bytes(b'[DEMO_BLOCK]', 'test.txt', 'simulation')['status'], 'blocked')
        init.assert_not_called()

    @patch('ai_demo.security.amaas.grpc.scan_buffer', side_effect=RuntimeError('test-key unauthorized'))
    @patch('ai_demo.security.amaas.grpc.init_by_region')
    @patch('ai_demo.security.amaas.grpc.quit')
    def test_sdk_failure_is_redacted_and_channel_closed(self, quit, init, scan):
        with patch.dict(os.environ, {'V1_API_KEY': 'test-key', 'V1_REGION': 'us-east-1'}):
            result = scan_bytes(b'test', 'test.txt')
        self.assertEqual(result['status'], 'error')
        self.assertNotIn('test-key', result['error'])
        quit.assert_called_once_with(init.return_value)


if __name__ == '__main__':
    unittest.main()
