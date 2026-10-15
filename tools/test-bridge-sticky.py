#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Offline unit tests for gateway session stickiness forwarding in responses-bridge."""
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
                          "Forward and trim prompt_cache_key")
    failures += not check(body.get("metadata") == {"conversation_id": "conversation-1"},
                          "Explicit conversation ID takes precedence over prompt_cache_key")
    failures += not check("secret" not in body.get("metadata", {}),
                          "Arbitrary metadata does not leak upstream")

    body2, _kinds, _dropped, _nsmap = bridge.to_chat_body({
        "model": "test-model",
        "conversationId": "top-level-conversation",
        "input": [{"type": "message", "role": "user",
                   "content": [{"type": "input_text", "text": "hi"}]}],
    })
    failures += not check(body2.get("metadata") == {
        "conversationId": "top-level-conversation"
    }, "Support top-level conversationId")

    body3, _kinds, _dropped, _nsmap = bridge.to_chat_body({
        "model": "test-model",
        "prompt_cache_key": "  cache-only-session  ",
        "input": [{"type": "message", "role": "user",
                   "content": [{"type": "input_text", "text": "hi"}]}],
    })
    failures += not check(body3.get("metadata") == {
        "conversation_id": "cache-only-session"
    }, "Map prompt_cache_key to conversation_id when missing")

    body4, _kinds, _dropped, _nsmap = bridge.to_chat_body({
        "model": "test-model",
        "prompt_cache_key": "cache-session-2",
        "conversation_id": "explicit-session-2",
        "input": [{"type": "message", "role": "user",
                   "content": [{"type": "input_text", "text": "hi"}]}],
    })
    failures += not check(body4.get("metadata") == {
        "conversation_id": "explicit-session-2"
    }, "Top-level conversation_id takes precedence over prompt_cache_key")

    print("\n%s" % ("All tests passed" if failures == 0 else "%d failures" % failures))
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
