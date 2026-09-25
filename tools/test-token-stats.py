#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线测试桥接层 Token 聚合统计。"""
import importlib.util
import json
import os
import sys
import tempfile


HERE = os.path.dirname(os.path.abspath(__file__))
BRIDGE = os.path.join(os.path.dirname(HERE), "responses-bridge.py")
spec = importlib.util.spec_from_file_location("bridge_token_stats", BRIDGE)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


def check(condition, label, extra=""):
    print("%-56s %s%s" % (label, "OK" if condition else "FAIL",
                          ("  " + extra) if extra else ""))
    return condition


def main():
    failures = 0
    body, _kinds, _dropped, _nsmap = bridge.to_chat_body({
        "model": "test-model",
        "input": [{"type": "message", "role": "user",
                   "content": [{"type": "input_text", "text": "hi"}]}],
    })
    failures += not check(body.get("stream_options") == {"include_usage": True},
                          "桥接请求开启 SSE usage 返回")
    with tempfile.TemporaryDirectory() as tmp:
        day_one = 1789858800
        day_two = day_one + 86400
        ok = bridge.record_token_usage(
            tmp, {"prompt_tokens": 12, "completion_tokens": 8,
                  "total_tokens": 20}, now=day_one)
        failures += not check(ok, "记录 Chat Completions usage")
        ok = bridge.record_token_usage(
            tmp, {"input_tokens": 5, "output_tokens": 7}, now=day_one)
        failures += not check(ok, "记录 Responses usage 并补算 total_tokens")
        ok = bridge.record_token_usage(
            tmp, {"prompt_tokens": 3, "completion_tokens": 4,
                  "total_tokens": 7}, now=day_two)
        failures += not check(ok, "跨日记录 usage")

        stats = bridge.read_token_usage(tmp, now=day_one)
        failures += not check(stats["total_tokens"] == 39,
                              "总 Token 累计正确", str(stats))
        failures += not check(stats["today_tokens"] == 32,
                              "今日 Token 按 VPS 日期统计", str(stats))
        failures += not check(stats["total_input_tokens"] == 20 and
                              stats["total_output_tokens"] == 19,
                              "输入/输出 Token 分开累计", str(stats))

        raw = open(os.path.join(tmp, bridge.TOKEN_STATS_FILENAME),
                   encoding="utf-8").read()
        failures += not check("prompt_tokens" not in raw and
                              "completion_tokens" not in raw,
                              "聚合文件不保存原始 usage 字段")
        parsed = json.loads(raw)
        failures += not check("model" not in raw and "Authorization" not in raw,
                              "聚合文件不保存模型正文或鉴权信息")
        failures += not check(parsed["total"]["requests"] == 3,
                              "请求次数累计正确", str(parsed))

    print("\n%s" % ("全部通过" if failures == 0 else "%d 项失败" % failures))
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
