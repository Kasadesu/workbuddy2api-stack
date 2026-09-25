#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线测试桥接层对网关会话粘性字段的透传。"""
import importlib.util
import os


HERE = os.path.dirname(os.path.abspath(__file__))
BRIDGE = os.path.join(os.path.dirname(HERE), "responses-bridge.py")
spec = importlib.util.spec_from_file_location("bridge_sticky", BRIDGE)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


def check(condition, label):
    print("%-56s %s" % (label, "OK" if condition else "FAIL"))
    return condition


def main():
    failures = 0
    body, _kinds, _dropped, _nsmap = bridge.to_chat_body({
        "model": "test-model",
        "prompt_cache_key": "  cache-session-1  ",
        "metadata": {
            "conversation_id": "  conversation-1  ",
            "secret": "must-not-forward",
        },
        "input": [{"type": "message", "role": "user",
                   "content": [{"type": "input_text", "text": "hi"}]}],
    })
    failures += not check(body.get("prompt_cache_key") == "cache-session-1",
                          "透传并裁剪 prompt_cache_key")
    failures += not check(body.get("metadata") == {"conversation_id": "conversation-1"},
                          "显式会话 ID 优先于 prompt_cache_key")
    failures += not check("secret" not in body.get("metadata", {}),
                          "任意 metadata 不泄漏到上游")

    body2, _kinds, _dropped, _nsmap = bridge.to_chat_body({
        "model": "test-model",
        "conversationId": "top-level-conversation",
        "input": [{"type": "message", "role": "user",
                   "content": [{"type": "input_text", "text": "hi"}]}],
    })
    failures += not check(body2.get("metadata") == {
        "conversationId": "top-level-conversation"
    }, "兼容顶层 conversationId")

    body3, _kinds, _dropped, _nsmap = bridge.to_chat_body({
        "model": "test-model",
        "prompt_cache_key": "  cache-only-session  ",
        "input": [{"type": "message", "role": "user",
                   "content": [{"type": "input_text", "text": "hi"}]}],
    })
    failures += not check(body3.get("metadata") == {
        "conversation_id": "cache-only-session"
    }, "仅有 prompt_cache_key 时映射到 conversation_id")

    body4, _kinds, _dropped, _nsmap = bridge.to_chat_body({
        "model": "test-model",
        "prompt_cache_key": "cache-session-2",
        "conversation_id": "explicit-session-2",
        "input": [{"type": "message", "role": "user",
                   "content": [{"type": "input_text", "text": "hi"}]}],
    })
    failures += not check(body4.get("metadata") == {
        "conversation_id": "explicit-session-2"
    }, "顶层 conversation_id 优先于 prompt_cache_key")

    print("\n%s" % ("全部通过" if failures == 0 else "%d 项失败" % failures))
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
