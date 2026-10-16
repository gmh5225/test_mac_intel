"""Controls for the actual HTTP transport as well as rendered SSE."""
from pathlib import Path
import http.client
import json
import tempfile
import unittest
from offline_server import OfflineServer
from sequence_fixture_controls import SPEC, check_sequence_fixture, events

class SequenceFixtureTests(unittest.TestCase):
    def test_rendered_protocol_and_refusals(self):
        self.assertEqual(len(check_sequence_fixture()), 8)

    def test_http_sequence_count_tokens_and_request_capture(self):
        controls = check_sequence_fixture()
        with tempfile.TemporaryDirectory() as directory:
            server = OfflineServer(SPEC, Path(directory))
            try:
                for ordinal in [1, 2, 3]:
                    connection = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
                    body = json.dumps({"model": "authored-fixture", "stream": True, "messages": []})
                    connection.request("POST", "/v1/messages/count_tokens", body, {"Content-Type": "application/json"})
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(json.loads(response.read()), {"input_tokens": 10})
                    connection.close()
                    connection = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
                    connection.request("POST", "/v1/messages", body, {"Content-Type": "application/json"})
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(events(response.read()), controls[ordinal - 1]["events"])
                    connection.close()
                self.assertEqual(server.messages, 3)
                self.assertEqual(len(server.requests), 6)
                self.assertFalse(server.errors)
            finally: server.close()

if __name__ == "__main__": unittest.main()
