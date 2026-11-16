import io
import json
import os
import unittest
from unittest.mock import MagicMock, patch

from pypdf import PdfWriter
from ai_demo.retrieval import answer, chunk_text, extract_text, retrieve


class RetrievalTests(unittest.TestCase):
    def test_chunk_overlap_and_empty_pdf(self):
        chunks = chunk_text('x' * 2000)
        self.assertEqual(chunks[0][-120:], chunks[1][:120])
        writer = PdfWriter()
        writer.add_blank_page(width=100, height=100)
        buffer = io.BytesIO()
        writer.write(buffer)
        with self.assertRaises(ValueError):
            extract_text(buffer.getvalue(), 'image-only.pdf')

    def test_no_evidence_never_calls_model(self):
        with patch.dict(os.environ, {'OLLAMA_MODEL': 'test-model'}), patch('ai_demo.retrieval.urllib.request.urlopen') as call:
            text, engine = answer('question', [])
            self.assertIn('No encontr', text)
            call.assert_not_called()

    @patch('ai_demo.retrieval.urllib.request.urlopen')
    def test_ollama_receives_only_question_and_retrieved_context(self, call):
        response = MagicMock()
        response.read.return_value = json.dumps({'message': {'content': '180 USD [1]'}}).encode()
        call.return_value.__enter__.return_value = response
        source = {'name': 'policy.txt', 'text': 'Hotel 180 USD', 'position': 0}
        with patch.dict(os.environ, {'OLLAMA_MODEL': 'test-model', 'OLLAMA_URL': 'http://localhost:11434'}):
            text, engine = answer('Hotel?', [source])
        self.assertEqual(text, '180 USD [1]')
        self.assertEqual(engine, 'ollama/test-model')
        request = call.call_args.args[0]
        self.assertEqual(request.full_url, 'http://localhost:11434/api/chat')
        payload = json.loads(request.data)
        self.assertFalse(payload['stream'])
        self.assertEqual(payload['model'], 'test-model')
        self.assertIn('Hotel 180 USD', payload['messages'][1]['content'])
        self.assertNotIn('V1_API_KEY', request.data.decode())

    def test_missing_query_terms_produce_no_sources(self):
        chunks = [{'text': 'hotel 180 USD', 'vector': json.dumps({'hotel': 1, '180': 1})}]
        self.assertEqual(retrieve('astronomia', chunks), [])


if __name__ == '__main__':
    unittest.main()
