import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ai_demo.app import create_app
from ai_demo.rag_demo import run_scenario
from ai_demo.security import scan_bytes
from ai_demo.test_files import eicar_bytes


class ComparisonTests(unittest.TestCase):
    def test_fixture_is_standard_68_byte_antivirus_test(self):
        self.assertEqual(len(eicar_bytes()), 68)
        self.assertEqual(hashlib.sha256(eicar_bytes()).hexdigest(),
                         '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f')

    def test_normal_then_unprotected_then_protected(self):
        normal = run_scenario('normal', 'simulation')
        before = run_scenario('unprotected', 'simulation')
        after = run_scenario('protected', 'simulation')
        self.assertIn('180 USD', normal['context'])
        self.assertTrue(normal['indexed'])
        self.assertEqual(normal['documents'], 1)
        self.assertEqual(before['sha256'], after['sha256'])
        self.assertEqual(before['documents'], 2)
        self.assertEqual(before['scan']['status'], 'not_scanned')
        self.assertIsNone(before['scan']['sdk_response'])
        self.assertTrue(before['indexed'])
        self.assertGreater(before['retrieved'], 0)
        self.assertIn('EICAR', before['context'])
        self.assertEqual(after['scan']['status'], 'blocked')
        self.assertFalse(after['indexed'])
        self.assertEqual(after['candidate_chunks'], 0)
        self.assertEqual(after['documents'], 1)
        self.assertEqual(after['retrieved'], 0)
        for result in (normal, before, after):
            self.assertEqual(result['storage'], 'isolated-memory')
            self.assertFalse(result['model_called'])

    @patch('ai_demo.rag_demo.scan_bytes', side_effect=AssertionError('unprotected must not call scanner'))
    def test_unprotected_fixture_does_not_fake_sdk_approval(self, scan):
        result = run_scenario('unprotected', 'live')
        self.assertIsNone(result['scan']['sdk_response'])
        self.assertEqual(result['scan']['status'], 'not_scanned')
        self.assertTrue(result['indexed'])
        scan.assert_not_called()

    @patch('ai_demo.rag_demo.scan_bytes', return_value={
        'status': 'blocked', 'scan_mode': 'live', 'error': None,
        'sdk_response': {'scanResult': 1, 'scanId': 'real-scan-id'},
    })
    @patch('ai_demo.rag_demo.extract_text', side_effect=AssertionError('blocked fixture must not be parsed'))
    def test_protected_rejection_stops_parser(self, extract, scan):
        result = run_scenario('protected', 'live')
        extract.assert_not_called()
        self.assertFalse(result['indexed'])
        self.assertEqual(result['retrieved'], 0)
        self.assertEqual(scan.call_args.args[0], eicar_bytes())

    @patch('ai_demo.rag_demo.scan_bytes', return_value={
        'status': 'error', 'scan_mode': 'live', 'error': 'Service unavailable', 'sdk_response': None,
    })
    @patch('ai_demo.rag_demo.extract_text')
    def test_scan_failure_is_not_reported_as_detection(self, extract, scan):
        result = run_scenario('protected', 'live')
        extract.assert_not_called()
        self.assertEqual(result['scan']['status'], 'error')
        self.assertIn('no acredita', result['summary'])
        self.assertEqual(result['retrieved'], 0)

    @patch('ai_demo.rag_demo.scan_bytes', return_value={
        'status': 'clean', 'scan_mode': 'live', 'error': None, 'sdk_response': {'scanResult': 0},
    })
    def test_unexpected_clean_result_is_not_fabricated_as_block(self, scan):
        result = run_scenario('protected', 'live')
        self.assertTrue(result['indexed'])
        self.assertIn('No se demostró', result['summary'])

    def test_comparison_api_does_not_modify_corpus_or_disable_upload_protection(self):
        with tempfile.TemporaryDirectory() as folder:
            app = create_app({'TESTING': True, 'SECRET_KEY': 'test-only', 'SCAN_MODE': 'simulation',
                              'DATABASE': str(Path(folder) / 'test.sqlite3')})
            client = app.test_client()
            csrf = client.get('/api/state').json['csrf']
            headers = {'X-CSRF-Token': csrf}
            for scenario in ('normal', 'unprotected', 'protected'):
                response = client.post('/api/rag-demo/run', json={'scenario': scenario}, headers=headers)
                self.assertEqual(response.status_code, 200)
            state = client.get('/api/state').json
            self.assertEqual(state['documents'], [])
            self.assertEqual(state['events'], [])
            response = client.post('/api/upload', data={
                'file': (io.BytesIO(eicar_bytes()), 'test.txt'), 'mode': 'rag', 'unprotected': 'true',
            }, headers=headers)
            self.assertEqual(response.json['event']['status'], 'blocked')
            self.assertFalse(response.json['event']['indexed'])
            for data in ({'scenario': 'unknown'}, {'scenario': []}, {'scenario': 'unprotected', 'file': 'arbitrary'}, []):
                self.assertEqual(client.post('/api/rag-demo/run', json=data, headers=headers).status_code, 400)
            self.assertEqual(client.post('/api/rag-demo/run', json={'scenario': 'unprotected'}).status_code, 403)
            with client.get('/api/rag-demo/test-file') as response:
                self.assertEqual(response.data, eicar_bytes())
                self.assertIn('attachment', response.headers['Content-Disposition'])

    @patch('ai_demo.security.amaas.grpc.init_by_region')
    def test_simulated_eicar_is_explicit_and_never_calls_service(self, init):
        result = scan_bytes(eicar_bytes(), 'test.txt', 'simulation')
        self.assertEqual(result['status'], 'blocked')
        self.assertTrue(result['sdk_response']['simulation'])
        init.assert_not_called()


if __name__ == '__main__':
    unittest.main()
