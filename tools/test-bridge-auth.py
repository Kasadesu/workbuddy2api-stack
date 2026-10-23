#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for Responses bridge key authentication."""
import importlib.util
import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
BRIDGE_FILE = os.path.join(os.path.dirname(HERE), "responses-bridge.py")

spec = importlib.util.spec_from_file_location("bridge_under_test", BRIDGE_FILE)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)

FAILS = []


def check(cond, label):
    status = "OK" if cond else "FAIL"
    print("%-56s %s" % (label, status))
    if not cond:
        FAILS.append(label)


class DummyUpstream(BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        chunk = {"choices": [{"delta": {"content": "ok"}}]}
        self.wfile.write(("data: %s\n\n" % json.dumps(chunk)).encode())
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def log_message(self, *args):
        pass


def post_request(port, path, headers=None, body=None):
    if body is None:
        body = {
            "model": "gpt-4o",
            "input": [{"type": "message", "role": "user", "content": "hi"}],
            "stream": True,
        }
    data = json.dumps(body).encode()
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        headers=hdrs,
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def main():
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), DummyUpstream)
    upstream_t = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_t.start()
    up_port = upstream.server_port

    with tempfile.TemporaryDirectory() as tmpdir:
        keys_path = os.path.join(tmpdir, "keys.json")
        logdir = os.path.join(tmpdir, "logs")

        initial_keys = {
            "keys": [
                {"key": "sk-good-1", "name": "active key 1", "enabled": True},
                {"key": "sk-good-2", "name": "active key 2", "enabled": True},
                {"key": "sk-disabled", "name": "disabled key", "enabled": False},
                {"key": "", "name": "empty key", "enabled": True},
                {"name": "missing key field", "enabled": True},
            ]
        }
        with open(keys_path, "w", encoding="utf-8") as f:
            json.dump(initial_keys, f)

        bridge.Handler.upstream = f"http://127.0.0.1:{up_port}/v1/chat/completions"
        bridge.Handler.logdir = logdir
        bridge.Handler.keys_file = keys_path
        bridge.Handler.key_check_enabled = True

        srv = ThreadingHTTPServer(("127.0.0.1", 0), bridge.Handler)
        srv_t = threading.Thread(target=srv.serve_forever, daemon=True)
        srv_t.start()
        port = srv.server_port

        try:
            code, resp = post_request(port, "/v1/responses", {"X-Client-Key": "Bearer sk-good-1"})
            check(code == 200 and "response.completed" in resp, "Valid X-Client-Key passes")

            code, resp = post_request(port, "/v1/responses", {"Authorization": "Bearer sk-good-2"})
            check(code == 200 and "response.completed" in resp, "Valid direct Authorization header passes")

            code, resp = post_request(port, "/v1/responses", {"Authorization": "sk-good-1"})
            check(code == 200 and "response.completed" in resp, "Raw key without Bearer prefix passes")

            code, resp = post_request(port, "/v1/responses", {"Authorization": "Bearer sk-unknown-999"})
            err_data = json.loads(resp) if code == 401 else {}
            err_obj = err_data.get("error", {})
            check(code == 401 and err_obj.get("message") == "invalid API key" and
                  err_obj.get("type") == "invalid_request_error",
                  "Unknown key returns 401 with standard error object")

            code, resp = post_request(port, "/v1/responses", {})
            check(code == 401, "Missing key returns 401")

            code, resp = post_request(port, "/v1/responses", {"Authorization": "Bearer sk-disabled"})
            check(code == 401, "Disabled key returns 401")

            time.sleep(0.05)
            updated_keys = {
                "keys": [
                    {"key": "sk-good-1", "enabled": True},
                    {"key": "sk-dynamic-new", "enabled": True},
                ]
            }
            with open(keys_path, "w", encoding="utf-8") as f:
                json.dump(updated_keys, f)

            code, resp = post_request(port, "/v1/responses", {"Authorization": "Bearer sk-dynamic-new"})
            check(code == 200 and "response.completed" in resp, "Dynamically modified keys file hot-reloaded")

            time.sleep(0.05)
            with open(keys_path, "w", encoding="utf-8") as f:
                f.write("INVALID JSON CONTENT {")
            code, resp = post_request(port, "/v1/responses", {"Authorization": "Bearer sk-good-1"})
            check(code == 401, "Fail closed on corrupted json returns 401")

            os.remove(keys_path)
            code, resp = post_request(port, "/v1/responses", {"Authorization": "Bearer sk-good-1"})
            check(code == 401, "Fail closed on missing keys file returns 401")

            bridge.Handler.key_check_enabled = False
            code, resp = post_request(port, "/v1/responses", {"Authorization": "Bearer sk-any-arbitrary"})
            check(code == 200 and "response.completed" in resp, "Bypass auth when key_check_enabled is false")

        finally:
            srv.shutdown()
            srv.server_close()
            upstream.shutdown()
            upstream.server_close()

    if FAILS:
        print("\nFailed %d test(s): %s" % (len(FAILS), FAILS))
        return 1

    print("\nAll tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
