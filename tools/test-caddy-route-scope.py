#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Offline unit tests verifying caddy-route.py scopes authorization parsing to target site."""
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
    site_name = getattr(m, "SITE", "api.example.com")
    text = f'''other.example.com {{
    @bad {{
        not header_regexp authcheck Authorization "^Bearer WRONG_KEY$"
    }}
    header_up Authorization "Bearer wrong-builtin"
}}

{site_name} {{
    @qoder_v1 {{
        path /v1/chat/completions
    }}
    handle @qoder_v1 {{
        reverse_proxy 127.0.0.1:8791 {{
            header_up Authorization "Bearer qd-fake-key"
        }}
    }}

    handle {{
        @bad {{
            not header_regexp authcheck Authorization "^Bearer GOOD1|GOOD2$"
        }}
        reverse_proxy 127.0.0.1:7863 {{
            header_up X-Client-Key {{http.request.header.Authorization}}
            header_up Authorization "Bearer right-builtin"
        }}
    }}
}}
'''
    keys_re, builtin = m.extract_keys(text)
    ok1 = keys_re == "GOOD1|GOOD2"
    ok2 = builtin == "right-builtin"
    print("keys_re =", keys_re)
    print("builtin =", builtin)
    print("scope api site:", "OK" if ok1 and ok2 else "FAIL")

    block = m.build_block(builtin, 7866)
    ok3 = "reverse_proxy 127.0.0.1:7866" in block
    ok4 = 'header_up X-Client-Key {http.request.header.Authorization}' in block
    ok5 = 'header_up Authorization "Bearer right-builtin"' in block
    ok6 = "@badb" not in block
    print("build_block check:", "OK" if ok3 and ok4 and ok5 and ok6 else "FAIL")

    return 0 if (ok1 and ok2 and ok3 and ok4 and ok5 and ok6) else 1


if __name__ == "__main__":
    sys.exit(main())
