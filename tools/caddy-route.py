#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
在 VPS 的 Caddyfile 里幂等维护一个「受管路由块」。

设计要点：
- 密钥不经过本脚本的参数：直接从 Caddyfile 现有的 @bad 校验块里解析出
  允许的 key 正则，以及 header_up 里的内置 key，原样复用。
- 改完先 caddy validate，通过才 reload；失败自动回滚。
- 用显式标记注释包裹，可反复执行、可一键移除。

用法（在 VPS 上以 root 执行）：
    python3 caddy-route.py --target 7866            # 路由 /v1/responses -> 7866
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
    """从目标站点块的 @bad 里取出 key 正则与内置 key。

    必须在站点块内部搜索。以后 Caddyfile 增加其它站点时，若从全文抓第一个
    header_regexp / header_up，可能误关联别的服务，造成密钥口径不一致。
    """
    i, j = site_span(text)
    site = text[i:j]
    m = re.search(r'not header_regexp authcheck Authorization "\^Bearer (.+?)\$"', site)
    if not m:
        sys.exit("目标站点块中找不到 key 校验正则，拒绝继续（避免两套口径不一致）")
    keys_re = m.group(1)

    m2 = re.search(r'header_up Authorization "Bearer (.+?)"', site)
    if not m2:
        sys.exit("目标站点块中找不到 header_up Authorization 内置 key，拒绝继续")
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
    """定位目标站点的配置块范围（从站点行到下一个顶层 '}' ）。"""
    m = re.search(r"^" + re.escape(SITE) + r"\s*\{", text, re.M)
    if not m:
        sys.exit(f"在 Caddyfile 里找不到站点 {SITE}")
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
    return i, j - 1  # 站点块内部区间


def apply_new(text: str, block: str) -> str:
    ex = current_block(text)
    if ex:
        return text[:ex.start()] + block + text[ex.end():]
    i, j = site_span(text)
    body = text[i:j]
    # 插到第一个 handle 之前（handle 按特异性排序，位置不影响匹配，但可读性好）
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
        # 清掉可能留下的连续空行
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
