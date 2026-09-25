#!/usr/bin/env python3
"""在 VPS 侧校验管理页密码：候选值 vs basicauth.hash。

只输出布尔结果，不打印任何一方的内容，避免回显脱敏造成误判。
用法: python3 verify-admin-pw.py <候选密码>
"""
import os
import sys

HASH_PATH = os.environ.get("ADMIN_HASH_FILE", "/opt/workbuddy2api/admin/basicauth.hash")

def main():
    cand = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        h = open(HASH_PATH, encoding="utf-8").read().strip()
    except OSError as e:
        print("READ_FAIL", e)
        return
    print("hash_prefix=%s len=%d" % (h[:7], len(h)))

    matched = None
    # 1) crypt 模块（glibc/libxcrypt 支持 $2a$ bcrypt 时可用）
    try:
        import crypt
        matched = (crypt.crypt(cand, h) == h)
        print("via=crypt")
    except Exception as e:
        print("crypt_unavailable:", type(e).__name__)
    # 2) bcrypt 包
    if matched is None:
        try:
            import bcrypt
            matched = bcrypt.checkpw(cand.encode(), h.encode())
            print("via=bcrypt")
        except Exception as e:
            print("bcrypt_unavailable:", type(e).__name__)

    if matched is None:
        print("RESULT=UNVERIFIABLE")
    else:
        print("RESULT=" + ("MATCH" if matched else "NO_MATCH"))

if __name__ == "__main__":
    main()
