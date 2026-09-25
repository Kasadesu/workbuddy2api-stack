#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用本地假上游验证 web_fetch 的完整两轮回灌链路。"""
import importlib.util
import json
import os
import tempfile
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
BRIDGE = os.path.join(os.path.dirname(HERE), "responses-bridge.py")
spec = importlib.util.spec_from_file_location("bridge", BRIDGE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class FakeUpstream(BaseHTTPRequestHandler):
    calls = []

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n).decode("utf-8"))
        self.calls.append(body)
        has_result = any(x.get("role") == "tool"
                         for x in body.get("messages") or [] if isinstance(x, dict))
        if has_result:
            chunks = [
                {"choices": [{"delta": {"content": "bridge fetch ok"}}]},
                {"choices": [], "usage": {"prompt_tokens": 4,
                                             "completion_tokens": 3,
                                             "total_tokens": 7}},
            ]
        else:
            chunks = [{"choices": [{"delta": {"tool_calls": [{
                "index": 0, "id": "call_fetch", "type": "function",
                "function": {"name": "web_fetch",
                              "arguments": '{"url":"https://example.com"}'}}]}}]}]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "close")
        self.end_headers()
        for chunk in chunks:
            self.wfile.write(("data: %s\n\n" % json.dumps(chunk)).encode())
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def log_message(self, *args):
        pass


def main():
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), FakeUpstream)
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()
    bridge = ThreadingHTTPServer(("127.0.0.1", 0), m.Handler)
    old_upstream, old_logdir, old_fetch = m.Handler.upstream, m.Handler.logdir, m.do_web_fetch
    with tempfile.TemporaryDirectory() as logdir:
        m.Handler.upstream = "http://127.0.0.1:%d/v1/chat/completions" % upstream.server_port
        m.Handler.logdir = logdir
        m.do_web_fetch = lambda url: "Fetched: %s\n\nSynthetic page body" % url
        bridge_thread = threading.Thread(target=bridge.serve_forever, daemon=True)
        bridge_thread.start()
        try:
            payload = {
                "model": "test:model",
                "input": [{"type": "message", "role": "user",
                           "content": [{"type": "input_text", "text": "open page"}]}],
                "tools": [{"type": "web_fetch"}],
                "stream": True,
            }
            req = urllib.request.Request(
                "http://127.0.0.1:%d/v1/responses" % bridge.server_port,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=10) as resp:
                output = resp.read().decode("utf-8", "replace")
            assert len(FakeUpstream.calls) == 2, len(FakeUpstream.calls)
            assert "bridge fetch ok" in output, output
            assert "web_fetch" not in output, output
            assert "response.completed" in output, output
            assert any(x.get("role") == "tool" for x in
                       FakeUpstream.calls[1].get("messages") or []), FakeUpstream.calls[1]
            print("web_fetch 完整回灌链路: OK")
        finally:
            bridge.shutdown()
            bridge.server_close()
            m.Handler.upstream, m.Handler.logdir, m.do_web_fetch = old_upstream, old_logdir, old_fetch
    upstream.shutdown()
    upstream.server_close()


if __name__ == "__main__":
    main()
