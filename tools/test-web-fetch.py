#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""webfetch 的离线单测：声明转换、参数容错、HTML 清洗和 SSRF 防护。"""
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BRIDGE = os.path.join(os.path.dirname(HERE), "responses-bridge.py")

spec = importlib.util.spec_from_file_location("bridge", BRIDGE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

FAILS = []


def check(cond, label, extra=""):
    print("%-58s %s%s" % (label, "OK" if cond else "FAIL",
                          ("  " + extra) if extra else ""))
    if not cond:
        FAILS.append(label)


def rejects(url):
    try:
        m._validate_fetch_url(url)
    except ValueError:
        return True
    return False


def main():
    print("bridge VERSION =", m.VERSION)
    print("-" * 72)

    declarations = [
        {"type": "webfetch"},
        {"type": "web_fetch"},
        {"type": "web_fetch_preview"},
        {"type": "function", "name": "webfetch"},
    ]
    tools, kinds, dropped, _ = m.to_chat_tools(declarations)
    names = [x["function"]["name"] for x in tools]
    check(names == ["webfetch", "web_fetch", "web_fetch_preview", "webfetch"],
          "多种 webfetch 声明都转换为普通函数", str(names))
    check(all(kinds.get(name) == "function" for name in names),
          "webfetch 函数类型记录正确")
    check(dropped == [], "webfetch 不再进入 dropped_tools", str(dropped))
    check(tools[0]["function"]["parameters"]["required"] == ["url"],
          "webfetch 要求绝对 URL 参数")

    for raw, want in (
        ('{"url":"https://example.com/a"}', "https://example.com/a"),
        ('{"uri":"https://example.com/b"}', "https://example.com/b"),
        ('{"input":"请打开 https://example.com/c。"}', "https://example.com/c"),
        ('https://example.com/d', "https://example.com/d"),
        ('{"urls":["https://example.com/e"]}', "https://example.com/e"),
    ):
        got = m.fetch_url_from_args(raw)
        check(got == want, "URL 参数提取 %r" % raw[:25], "-> %r" % got)

    title, text = m._readable_html(
        "<html><head><title>  Demo page </title><style>.x{}</style></head>"
        "<body><script>alert(1)</script><h1>Hello</h1><p>first &amp; second</p>"
        "<div>third</div></body></html>")
    check(title == "Demo page", "HTML title 清洗")
    check("Hello" in text and "first & second" in text and "third" in text,
          "HTML 正文保留")
    check("alert" not in text and ".x{}" not in text,
          "HTML script/style 被移除")

    for bad in ("file:///etc/passwd", "ftp://example.com/a", "http://127.0.0.1/",
                "http://10.0.0.1/", "http://localhost/", "http://example.com:8080/"):
        check(rejects(bad), "拒绝不安全目标 %s" % bad)
    check(m._validate_fetch_url("https://example.com/path?x=1") ==
          "https://example.com/path?x=1", "允许公网 HTTPS URL")
    check("?token=" not in m._redact_fetch_url("https://example.com/a?token=secret"),
          "日志 URL 去除查询参数")

    print("-" * 72)
    if FAILS:
        print("失败 %d 项: %s" % (len(FAILS), FAILS))
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
