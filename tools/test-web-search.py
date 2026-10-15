#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Connectivity and parsing test for search provider engines.

Usage:
    python tools/test-web-search.py [query]
"""
import importlib.util
import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
BRIDGE = os.path.join(os.path.dirname(HERE), "responses-bridge.py")

spec = importlib.util.spec_from_file_location("bridge", BRIDGE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def main():
    q = sys.argv[1] if len(sys.argv) > 1 else "OpenAI Responses API web_search tool"
    print("query =", q)
    print("=" * 72)
    for name, fn in (("360", m._search_360),
                     ("bing", m._search_bing),
                     ("duckduckgo", m._search_ddg)):
        print("[%s]" % name)
        try:
            rows, src = fn(q)
            print("  OK  %d hits (src=%s)" % (len(rows), src))
            for i, (title, url, snip) in enumerate(rows[:5], 1):
                print("   %d. %s" % (i, (title or "")[:70]))
                print("      %s" % url[:100])
                print("      %s" % (snip or "")[:110])
        except Exception as e:
            print("  FAIL %r" % (e,))
            if "-v" in sys.argv:
                traceback.print_exc()
    print("=" * 72)
    print("[do_web_search aggregated output]")
    out = m.do_web_search(q)
    print(out[:1500])


if __name__ == "__main__":
    main()
