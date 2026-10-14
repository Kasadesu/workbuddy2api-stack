#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Maintain an idempotent managed routing block in VPS Caddyfile.

Usage (run as root on VPS):
    python3 caddy-route.py --target 7866
    python3 caddy-route.py --target 7866 --apply
    python3 caddy-route.py --remove --apply
    python3 caddy-route.py --status
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import time

CADDYFILE = os.environ.get("CADDY_FILE", "/etc/caddy/Caddyfile")
BEGIN = "\t# >>> responses-bridge (managed) >>>"
END = "\t# <<< responses-bridge (managed) <<<"
SITE = os.environ.get("PUBLIC_HOST", "api.example.com")


def read() -> str:
    with open(CADDYFILE, encoding="utf-8") as f:
        return f.read()


def extract_keys(text: str):
    """Extract key regex and builtin authorization key from target site block."""
    i, j = site_span(text)
    site = text[i:j]
    m = re.search(r'not header_regexp authcheck Authorization "\^Bearer (.+?)\$"', site)
    if not m:
        sys.exit("Could not find key validation regex in target site block")
    keys_re = m.group(1)

    m2 = re.search(r'header_up Authorization "Bearer (.+?)"', site)
    if not m2:
        sys.exit("Could not find header_up Authorization builtin key in target site block")
    builtin = m2.group(1)
    return keys_re, builtin


def build_block(keys_re: str, builtin: str, target: int) -> str:
    return "\n".join([
        BEGIN,
        "\thandle /v1/responses* {",
        "\t\t@badb {",
        '\t\t\tnot header_regexp authcheck Authorization "^Bearer ' + keys_re + '$"',
        "\t\t}",
        '\t\trespond @badb "invalid API key" 401',
        "\t\treverse_proxy 127.0.0.1:%d {" % target,
        '\t\t\theader_up Authorization "Bearer ' + builtin + '"',
        "\t\t\tflush_interval -1",
        "\t\t}",
        "\t}",
        END,
    ])


def current_block(text: str):
    pat = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END), re.S)
    m = pat.search(text)
    return m


def site_span(text: str):
    """Locate range of target site configuration block."""
    m = re.search(r"^" + re.escape(SITE) + r"\s*\{", text, re.M)
    if not m:
        sys.exit(f"Site block not found in Caddyfile: {SITE}")
    i = m.end()
    depth = 1
    j = i
    while j < len(text) and depth:
        c = text[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        j += 1
    return i, j - 1  # inner site block range


def apply_new(text: str, block: str) -> str:
    ex = current_block(text)
    if ex:
        return text[:ex.start()] + block + text[ex.end():]
    i, j = site_span(text)
    body = text[i:j]
    # insert before the first handle block
    k = body.find("\thandle")
    if k == -1:
        k = len(body.rstrip("\n\t ")) - len(body) if body.strip() else 0
        ins = len(body) - len(body.lstrip())
    else:
        ins = k
    new_body = body[:ins] + block + "\n" + body[ins:]
    return text[:i] + new_body + text[j:]


def run(cmd, check=True):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        print(r.stdout)
        print(r.stderr, file=sys.stderr)
        sys.exit(f"命令失败: {' '.join(cmd)}")
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", type=int, default=7866, help="桥接服务监听端口")
    ap.add_argument("--remove", action="store_true", help="移除受管块")
    ap.add_argument("--apply", action="store_true", help="实际写入并 reload（默认只预览）")
    ap.add_argument("--status", action="store_true", help="只显示当前受管块")
    a = ap.parse_args()

    text = read()
    ex = current_block(text)

    if a.status:
        print(ex.group(0) if ex else "(当前没有受管块)")
        return

    if a.remove:
        if not ex:
            print("没有受管块，无需移除")
            return
        new = text[:ex.start()] + text[ex.end():]
        # collapse consecutive empty lines
        new = re.sub(r"\n{3,}", "\n\n", new)
    else:
        keys_re, builtin = extract_keys(text)
        block = build_block(keys_re, builtin, a.target)
        new = apply_new(text, block)

    if new == text:
        print("内容无变化")
        return

    if not a.apply:
        print("=== 预览（未写入）===")
        print(new)
        return

    bak = CADDYFILE + ".bak." + time.strftime("%Y%m%d-%H%M%S")
    shutil.copy2(CADDYFILE, bak)
    with open(CADDYFILE, "w", encoding="utf-8", newline="\n") as f:
        f.write(new)
    print("已备份到", bak)

    v = run(["caddy", "validate", "--config", CADDYFILE, "--adapter", "caddyfile"], check=False)
    print("--- caddy validate ---")
    print(v.stdout or "", v.stderr or "")
    if v.returncode != 0:
        shutil.copy2(bak, CADDYFILE)
        sys.exit("校验失败，已回滚")

    r = run(["systemctl", "reload", "caddy"], check=False)
    print("--- reload ---")
    print(r.stdout or "", r.stderr or "")
    if r.returncode != 0:
        shutil.copy2(bak, CADDYFILE)
        run(["systemctl", "reload", "caddy"], check=False)
        sys.exit("reload 失败，已回滚")

    print("完成。当前受管块：")
    print(current_block(read()).group(0))


if __name__ == "__main__":
    main()
