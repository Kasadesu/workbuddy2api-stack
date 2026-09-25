#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Emit a secret-free copy of /etc/caddy/Caddyfile for archival in a git repo.

Line-targeted redaction (a generic token regex is unsafe: keys contain "-",
which splits them into short fragments that survive a naive {20,} match).
"""
import os
import re

src = open(os.environ.get("CADDY_FILE", "/etc/caddy/Caddyfile"), encoding="utf-8").read()

out = []
for ln in src.split("\n"):
    low = ln.lower()
    if re.search(r"^\s*admin\s+\$2[aby]\$", ln):
        ln = re.sub(r"\$2[aby]\$\S+", "__BASICAUTH_HASH__", ln)
    elif "header_regexp" in low and "authorization" in low:
        ln = re.sub(r'"\^Bearer \(.*\)\$"',
                    '"^Bearer (__MANAGED_KEY_1__|__MANAGED_KEY_2__)$"', ln)
    elif "header_up" in low and "authorization" in low:
        ln = re.sub(r'(Authorization\s+)"[^"]*"',
                    r'\1"Bearer __GATEWAY_INTERNAL_KEY__"', ln)
    out.append(ln)

print("\n".join(out), end="")
