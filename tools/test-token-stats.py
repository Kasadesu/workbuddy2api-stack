#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for token usage aggregation."""
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
                          "Bridge request enables SSE usage reporting")
    with tempfile.TemporaryDirectory() as tmp:
        day_one = 1789858800
        day_two = day_one + 86400
        ok = bridge.record_token_usage(
            tmp, {"prompt_tokens": 12, "completion_tokens": 8,
                  "total_tokens": 20}, now=day_one)
        failures += not check(ok, "Record Chat Completions usage")
        ok = bridge.record_token_usage(
            tmp, {"input_tokens": 5, "output_tokens": 7}, now=day_one)
        failures += not check(ok, "Record Responses usage with total_tokens calculation")
        ok = bridge.record_token_usage(
            tmp, {"prompt_tokens": 3, "completion_tokens": 4,
                  "total_tokens": 7}, now=day_two)
        failures += not check(ok, "Cross-day usage recording")

        stats = bridge.read_token_usage(tmp, now=day_one)
        failures += not check(stats["total_tokens"] == 39,
                              "Total tokens aggregated correctly", str(stats))
        failures += not check(stats["today_tokens"] == 32,
                              "Today tokens aggregated correctly", str(stats))
        failures += not check(stats["total_input_tokens"] == 20 and
                              stats["total_output_tokens"] == 19,
                              "Input and output tokens aggregated separately", str(stats))

        raw = open(os.path.join(tmp, bridge.TOKEN_STATS_FILENAME),
                   encoding="utf-8").read()
        failures += not check("prompt_tokens" not in raw and
                              "completion_tokens" not in raw,
                              "Aggregated stats exclude raw usage field names")
        parsed = json.loads(raw)
        failures += not check("model" not in raw and "Authorization" not in raw,
                              "Aggregated stats exclude model body or authorization headers")
        failures += not check(parsed["total"]["requests"] == 3,
                              "Request count aggregated correctly", str(parsed))

    print("\n%s" % ("All tests passed" if failures == 0 else "%d failures" % failures))
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
