#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线与本地端到端测试 Responses 桥接层的鉴权子系统。
覆盖 TC-01 至 TC-09 全部用例。
"""
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


def check(cond, label, extra=""):
    status = "OK" if cond else "FAIL"
    msg = "%-64s %s" % (label, status)
    if extra:
        msg += "  " + extra
    print(msg)
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
    print("=== 开始运行 Bridge 鉴权自动化测试 (TC-01 ~ TC-09) ===")

    # 启动假 upstream
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), DummyUpstream)
    upstream_t = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_t.start()
    up_port = upstream.server_port

    with tempfile.TemporaryDirectory() as tmpdir:
        keys_path = os.path.join(tmpdir, "keys.json")
        logdir = os.path.join(tmpdir, "logs")

        # 初始 keys.json
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

        # 启动 Bridge 服务
        bridge.Handler.upstream = f"http://127.0.0.1:{up_port}/v1/chat/completions"
        bridge.Handler.logdir = logdir
        bridge.Handler.keys_file = keys_path
        bridge.Handler.key_check_enabled = True

        srv = ThreadingHTTPServer(("127.0.0.1", 0), bridge.Handler)
        srv_t = threading.Thread(target=srv.serve_forever, daemon=True)
        srv_t.start()
        port = srv.server_port

        try:
            # TC-01: X-Client-Key 携带合法 key 鉴权通过
            code, resp = post_request(port, "/v1/responses", {"X-Client-Key": "Bearer sk-good-1"})
            check(code == 200 and "response.completed" in resp, "TC-01: X-Client-Key 携带合法 key 鉴权通过 (200)")

            # TC-02: Authorization 直连携带合法 key 鉴权通过
            code, resp = post_request(port, "/v1/responses", {"Authorization": "Bearer sk-good-2"})
            check(code == 200 and "response.completed" in resp, "TC-02: Authorization 直连携带合法 key 鉴权通过 (200)")

            # TC-03: 裸 key（无 Bearer 前缀）携带合法 key 鉴权通过
            code, resp = post_request(port, "/v1/responses", {"Authorization": "sk-good-1"})
            check(code == 200 and "response.completed" in resp, "TC-03: 裸 key（无 Bearer 前缀）鉴权通过 (200)")

            # TC-04: 非法/未知 key 返回 401（OpenAI 结构）
            code, resp = post_request(port, "/v1/responses", {"Authorization": "Bearer sk-unknown-999"})
            err_data = json.loads(resp) if code == 401 else {}
            err_obj = err_data.get("error", {})
            check(code == 401 and err_obj.get("message") == "invalid API key" and
                  err_obj.get("type") == "invalid_request_error",
                  "TC-04: 非法/未知 key 返回 401 且符合 OpenAI error 结构")

            # TC-05: 空/缺失 key 返回 401
            code, resp = post_request(port, "/v1/responses", {})
            check(code == 401, "TC-05: 缺失 key 返回 401")

            # TC-06: 被禁用 key（enabled=false）返回 401
            code, resp = post_request(port, "/v1/responses", {"Authorization": "Bearer sk-disabled"})
            check(code == 401, "TC-06: 被禁用 key（enabled: false）返回 401")

            # TC-07: 动态向 keys.json 追加 key，mtime 自动刷新感知立即通过
            time.sleep(0.05)  # 保证 mtime 发生变化
            updated_keys = {
                "keys": [
                    {"key": "sk-good-1", "enabled": True},
                    {"key": "sk-dynamic-new", "enabled": True},
                ]
            }
            with open(keys_path, "w", encoding="utf-8") as f:
                json.dump(updated_keys, f)

            code, resp = post_request(port, "/v1/responses", {"Authorization": "Bearer sk-dynamic-new"})
            check(code == 200 and "response.completed" in resp, "TC-07: 动态新写入 key 立即生效通过 (200)")

            # TC-08: Fail-Closed（文件缺失 / 坏 JSON）安全返回 401，绝不报 500
            time.sleep(0.05)
            with open(keys_path, "w", encoding="utf-8") as f:
                f.write("INVALID JSON CONTENT {")
            code, resp = post_request(port, "/v1/responses", {"Authorization": "Bearer sk-good-1"})
            check(code == 401, "TC-08-1: 损坏 JSON 文件时 Fail-Closed 返回 401 (非 500)")

            os.remove(keys_path)
            code, resp = post_request(port, "/v1/responses", {"Authorization": "Bearer sk-good-1"})
            check(code == 401, "TC-08-2: 密钥文件缺失时 Fail-Closed 返回 401 (非 500)")

            # TC-09: 逃生开关 key_check_enabled=False 放行
            bridge.Handler.key_check_enabled = False
            code, resp = post_request(port, "/v1/responses", {"Authorization": "Bearer sk-any-arbitrary"})
            check(code == 200 and "response.completed" in resp, "TC-09: 逃生开关关闭鉴权时全部放行 (200)")

        finally:
            srv.shutdown()
            srv.server_close()
            upstream.shutdown()
            upstream.server_close()

    print("\n测试结果汇总:")
    if FAILS:
        print(f"❌ 失败 {len(FAILS)} 个用例: {FAILS}")
        return 1
    else:
        print("✅ TC-01 ~ TC-09 全部 100% 通过！")
        return 0


if __name__ == "__main__":
    sys.exit(main())
