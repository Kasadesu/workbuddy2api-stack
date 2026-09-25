#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线测试 Responses 桥接层的图片输入转换。"""
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
    }], "远程 input_image 转成 Chat image_url")

    mixed = image_message([
        {"type": "input_text", "text": "请描述这张图"},
        {"type": "input_image", "image_url": "https://example.com/photo.jpg"},
    ])
    failures += not check(
        mixed[0] == {"type": "text", "text": "请描述这张图"} and
        mixed[1] == {"type": "image_url",
                     "image_url": {"url": "https://example.com/photo.jpg"}},
        "文本和图片混合时保留 content 数组顺序",
    )

    data_url = image_message([{
        "type": "image_url",
        "image_url": {"url": "data:image/png;base64,AAAA", "detail": "low"},
    }])
    failures += not check(
        data_url[0]["image_url"] == {
            "url": "data:image/png;base64,AAAA", "detail": "low"
        },
        "支持 data:image base64 URL 和嵌套 detail",
    )

    text_only, _kinds, _dropped, _nsmap = bridge.to_chat_body({
        "model": "test-model",
        "input": [{"type": "message", "role": "user",
                   "content": [{"type": "input_text", "text": "hello"}]}],
    })
    failures += not check(text_only["messages"][-1]["content"] == "hello",
                          "纯文本请求继续使用字符串 content")

    try:
        image_message([{"type": "input_image", "file_id": "file_123"}])
    except bridge.UnsupportedImageError as exc:
        failures += not check("file_id" in str(exc) and "image" in str(exc),
                              "file_id 返回明确的图片输入错误")
    else:
        failures += not check(False, "file_id 返回明确的图片输入错误")

    print("\n%s" % ("全部通过" if failures == 0 else "%d 项失败" % failures))
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
