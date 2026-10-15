#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Offline unit tests for image input conversion in responses-bridge."""
import importlib.util
import os


HERE = os.path.dirname(os.path.abspath(__file__))
BRIDGE = os.path.join(os.path.dirname(HERE), "responses-bridge.py")
spec = importlib.util.spec_from_file_location("bridge_images", BRIDGE)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


def check(condition, label):
    print("%-64s %s" % (label, "OK" if condition else "FAIL"))
    return condition


def image_message(content):
    body, _kinds, _dropped, _nsmap = bridge.to_chat_body({
        "model": "test-model",
        "input": [{"type": "message", "role": "user", "content": content}],
    })
    return body["messages"][-1]["content"]


def main():
    failures = 0

    remote = image_message([{
        "type": "input_image",
        "image_url": "https://example.com/photo.jpg",
        "detail": "high",
    }])
    failures += not check(remote == [{
        "type": "image_url",
        "image_url": {"url": "https://example.com/photo.jpg", "detail": "high"},
    }], "Remote input_image converted to Chat image_url")

    mixed = image_message([
        {"type": "input_text", "text": "Describe this photo"},
        {"type": "input_image", "image_url": "https://example.com/photo.jpg"},
    ])
    failures += not check(
        mixed[0] == {"type": "text", "text": "Describe this photo"} and
        mixed[1] == {"type": "image_url",
                     "image_url": {"url": "https://example.com/photo.jpg"}},
        "Preserve content array order when mixing text and images",
    )

    data_url = image_message([{
        "type": "image_url",
        "image_url": {"url": "data:image/png;base64,AAAA", "detail": "low"},
    }])
    failures += not check(
        data_url[0]["image_url"] == {
            "url": "data:image/png;base64,AAAA", "detail": "low"
        },
        "Support data:image base64 URLs and nested detail",
    )

    text_only, _kinds, _dropped, _nsmap = bridge.to_chat_body({
        "model": "test-model",
        "input": [{"type": "message", "role": "user",
                   "content": [{"type": "input_text", "text": "hello"}]}],
    })
    failures += not check(text_only["messages"][-1]["content"] == "hello",
                          "Pure text requests continue using string content")

    try:
        image_message([{"type": "input_image", "file_id": "file_123"}])
    except bridge.UnsupportedImageError as exc:
        failures += not check("file_id" in str(exc) and "image" in str(exc),
                              "file_id raises clear unsupported image error")
    else:
        failures += not check(False, "file_id raises clear unsupported image error")

    print("\n%s" % ("All tests passed" if failures == 0 else "%d failures" % failures))
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
