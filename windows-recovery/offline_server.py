"""Authored, bounded loopback HTTP/SSE fixture. Never contacts a model service."""
import json
import select
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

def event(name, body):
    return "event: " + name + "\ndata: " + json.dumps(body, ensure_ascii=False, separators=(",", ":")) + "\n\n"

def message(spec, request, ordinal):
    tool = spec.get("kind") == "tool_then_text" and ordinal == 1
    result = event("message_start", {"type": "message_start", "message": {
        "id": "msg_offline_fixture_" + str(ordinal), "type": "message", "role": "assistant",
        "model": request.get("model", "claude-sonnet-5"), "content": [], "stop_reason": None, "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 1, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}}})
    if tool:
        result += event("content_block_start", {"type": "content_block_start", "index": 0,
            "content_block": {"type": "tool_use", "id": "toolu_offline_fixture_1", "name": spec["tool"]["name"], "input": {}}})
        result += event("content_block_delta", {"type": "content_block_delta", "index": 0,
            "delta": {"type": "input_json_delta", "partial_json": json.dumps(spec["tool"]["input"], separators=(",", ":"))}})
    else:
        result += event("content_block_start", {"type": "content_block_start", "index": 0,
            "content_block": {"type": "text", "text": ""}})
        result += event("content_block_delta", {"type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": spec.get("text", "offline-fixture-complete")}})
    if spec.get("kind") == "hold_after_text_delta": return result.encode()
    result += event("content_block_stop", {"type": "content_block_stop", "index": 0})
    result += event("message_delta", {"type": "message_delta", "delta": {
        "stop_reason": "tool_use" if tool else "end_turn", "stop_sequence": None}, "usage": {"output_tokens": 8}})
    result += event("message_stop", {"type": "message_stop"})
    return result.encode()

class OfflineServer:
    def __init__(self, spec, report):
        self.spec, self.report = spec, report
        self.requests = []; self.messages = 0; self.holds = []; self.errors = []
        fixture = self
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def log_message(self, *args): pass
            def do_GET(self): self.handle_fixture()
            def do_POST(self): self.handle_fixture()
            def handle_fixture(self):
                self.connection.settimeout(5)
                try:
                    assert len(fixture.requests) < 32, "request budget"
                    assert "Transfer-Encoding" not in self.headers, "chunked request unsupported"
                    length = int(self.headers.get("Content-Length", "0")); assert 0 <= length <= 1024 * 1024
                    raw = self.rfile.read(length); assert len(raw) == length
                    body = json.loads(raw) if raw else {}
                    fixture.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                    status, content_type = 200, "application/json"
                    if self.path == "/probe": payload = b'{"ok":true}\n'
                    elif self.path.startswith("/v1/messages/count_tokens"): payload = b'{"input_tokens":10}\n'
                    elif self.path.startswith("/v1/messages"):
                        fixture.messages += 1
                        if spec.get("kind") == "http_error":
                            status, payload = spec.get("status", 400), json.dumps(spec["body"]).encode()
                        elif spec.get("kind") == "forbid_all_requests":
                            status, payload = 500, b'{"error":"fixture forbids API requests"}'
                        else: content_type, payload = "text/event-stream", message(spec, body, fixture.messages)
                    else: status, payload = 404, b'{"error":"unplanned fixture endpoint"}'
                    hold = spec.get("kind") == "hold_after_text_delta" and content_type == "text/event-stream"
                    self.send_response(status); self.send_header("Content-Type", content_type)
                    self.send_header("Connection", "close")
                    if not hold: self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    if spec.get("kind") == "fragmented_text":
                        for at in range(0, len(payload), 7):
                            self.wfile.write(payload[at:at+7]); self.wfile.flush(); time.sleep(.001)
                    else: self.wfile.write(payload); self.wfile.flush()
                    if hold:
                        readable, _, _ = select.select([self.connection], [], [], 5)
                        fixture.holds.append({"poll": len(readable)})
                    self.close_connection = True
                except (BrokenPipeError, ConnectionResetError): self.close_connection = True
                except Exception as error:
                    fixture.errors.append(str(error)); self.close_connection = True
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.port = self.server.server_port

    def close(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=3)
        for name, rows in [("requests", self.requests), ("hold", self.holds), ("server-errors", self.errors)]:
            (self.report / (name + ".json")).write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
