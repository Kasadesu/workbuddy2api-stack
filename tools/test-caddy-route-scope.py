#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线测试 caddy-route.py 只从目标站点块读取鉴权信息。"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "caddy-route.py")


def load():
    spec = importlib.util.spec_from_file_location("caddy_route_under_test", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    m = load()
    text = '''other.example.com {
    @bad {
        not header_regexp authcheck Authorization "^Bearer WRONG_KEY$"
    }
    header_up Authorization "Bearer wrong-builtin"
}

api.example.com {
    handle {
        @bad {
            not header_regexp authcheck Authorization "^Bearer GOOD1|GOOD2$"
        }
        reverse_proxy 127.0.0.1:7863 {
            header_up Authorization "Bearer right-builtin"
        }
    }
}
'''
    keys_re, builtin = m.extract_keys(text)
    ok1 = keys_re == "GOOD1|GOOD2"
    ok2 = builtin == "right-builtin"
    print("keys_re =", keys_re)
    print("builtin =", builtin)
    print("scope api site:", "OK" if ok1 and ok2 else "FAIL")
    return 0 if ok1 and ok2 else 1


if __name__ == "__main__":
    sys.exit(main())
