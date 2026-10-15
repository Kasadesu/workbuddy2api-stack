#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for web_fetch declarations, argument extraction, HTML cleaning, and SSRF validation."""
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
          "Various webfetch declarations converted to standard functions", str(names))
    check(all(kinds.get(name) == "function" for name in names),
          "webfetch function types recorded properly")
    check(dropped == [], "webfetch is not dropped", str(dropped))
    check(tools[0]["function"]["parameters"]["required"] == ["url"],
          "webfetch requires url parameter")

    for raw, want in (
        ('{"url":"https://example.com/a"}', "https://example.com/a"),
        ('{"uri":"https://example.com/b"}', "https://example.com/b"),
        ('{"input":"Please open https://example.com/c."}', "https://example.com/c"),
        ('https://example.com/d', "https://example.com/d"),
        ('{"urls":["https://example.com/e"]}', "https://example.com/e"),
    ):
        got = m.fetch_url_from_args(raw)
        check(got == want, "URL argument extraction %r" % raw[:25], "-> %r" % got)

    title, text = m._readable_html(
        "<html><head><title>  Demo page </title><style>.x{}</style></head>"
        "<body><script>alert(1)</script><h1>Hello</h1><p>first &amp; second</p>"
        "<div>third</div></body></html>")
    check(title == "Demo page", "HTML title sanitized")
    check("Hello" in text and "first & second" in text and "third" in text,
          "HTML body text preserved")
    check("alert" not in text and ".x{}" not in text,
          "HTML script and style tags stripped")

    for bad in ("file:///etc/passwd", "ftp://example.com/a", "http://127.0.0.1/",
                "http://10.0.0.1/", "http://localhost/", "http://example.com:8080/"):
        check(rejects(bad), "Reject invalid or private target: %s" % bad)
    check(m._validate_fetch_url("https://example.com/path?x=1") ==
          "https://example.com/path?x=1", "Allow public HTTPS URL")
    check("?token=" not in m._redact_fetch_url("https://example.com/a?token=secret"),
          "Query parameters redacted from log URL")

    print("-" * 72)
    if FAILS:
        print("FAILURES (%d): %s" % (len(FAILS), FAILS))
        return 1
    print("All tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
