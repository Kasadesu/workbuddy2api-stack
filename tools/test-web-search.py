#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""联网搜索后端连通性测试（本机 / VPS 通用）。

web_search 的命门不在翻译层，而在"桥接能不能真搜到东西"。
这个脚本分别打每个后端，把结果或异常原样打出来，方便对比不同网络环境。

用法：python tools/test-web-search.py "查询词"
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
    print("[do_web_search 汇总输出]")
    out = m.do_web_search(q)
    print(out[:1500])


if __name__ == "__main__":
    main()
