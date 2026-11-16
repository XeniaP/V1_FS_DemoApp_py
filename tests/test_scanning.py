import json
import unittest
from unittest.mock import patch

from app import app, malware_scan, scan_is_clean


class ScanResultTests(unittest.TestCase):
    def test_verbose_results(self):
        clean = {'malwareCount': 0, 'malware': None, 'error': None}
        self.assertTrue(scan_is_clean({'result': {'atse': clean, 'trendx': clean}}))
        for engine in (
            {**clean, 'malwareCount': 1},
            {**clean, 'malware': [{'name': 'test detection'}]},
            {**clean, 'error': {'message': 'scan failed'}},
            {},
            None,
        ):
            with self.subTest(engine=engine):
                self.assertFalse(scan_is_clean({'result': {'atse': clean, 'trendx': engine}}))

    def test_compact_and_unknown_results(self):
        for result in ({'scanResult': None}, {'scanResult': 0}):
            self.assertTrue(scan_is_clean(result))
        for result in (
            {'scanResult': 1}, {'scanResult': 2}, {}, [], None,
            {'result': {}}, {'result': None},
            {'scanResult': 0, 'foundMalwares': [{'malwareName': 'test'}]},
        ):
            with self.subTest(result=result):
                self.assertFalse(scan_is_clean(result))


class ScanLoggingTests(unittest.TestCase):
    @patch('app.amaas.grpc.quit')
    @patch('app.amaas.grpc.scan_file')
    @patch('app.amaas.grpc.init_by_region')
    def test_full_response_and_extended_options(self, init, scan, quit):
        response = {
            'scanId': 'service-scan-id',
            'result': {'atse': {'malwareCount': 0, 'malware': None, 'error': None}},
            'additionalMetadata': {'nested': ['preserve', 'all fields']},
        }
        scan.return_value = json.dumps(response)
        with self.assertLogs(app.logger, level='INFO') as logs:
            self.assertTrue(malware_scan('sample.txt'))
        events = [json.loads(record.getMessage()) for record in logs.records]
        self.assertEqual(json.loads(events[0]['sdk_response']), response)
        self.assertEqual(events[0]['sdk_version'], '1.5.1')
        self.assertEqual(events[0]['correlation_id'], events[1]['correlation_id'])
        self.assertTrue(events[1]['accepted'])
        self.assertTrue(scan.call_args.kwargs['verbose'])
        self.assertEqual(scan.call_args.kwargs['tags'], ['DemoApp', 'Container', 'Python'])
        quit.assert_called_once_with(init.return_value)

    @patch('app.amaas.grpc.quit')
    @patch('app.amaas.grpc.scan_file')
    @patch('app.amaas.grpc.init_by_region')
    def test_failures_reject_and_close_channel(self, init, scan, quit):
        for malformed in (True, False):
            with self.subTest(malformed=malformed):
                quit.reset_mock()
                scan.side_effect = None if malformed else RuntimeError('service unavailable')
                scan.return_value = 'invalid JSON\nresponse'
                with self.assertLogs(app.logger, level='INFO') as logs:
                    self.assertFalse(malware_scan('sample.txt'))
                if malformed:
                    event = json.loads(logs.records[0].getMessage())
                    self.assertEqual(event['sdk_response'], scan.return_value)
                self.assertTrue(any(record.exc_info for record in logs.records))
                quit.assert_called_once_with(init.return_value)

    @patch('app.amaas.grpc.quit')
    @patch('app.amaas.grpc.init_by_region', side_effect=RuntimeError('init failed'))
    def test_initialization_failure(self, init, quit):
        with self.assertLogs(app.logger, level='ERROR'):
            self.assertFalse(malware_scan('sample.txt'))
        quit.assert_not_called()


if __name__ == '__main__':
    unittest.main()
