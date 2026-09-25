#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Set admin basic-auth password: generate bcrypt hash and patch /etc/caddy/Caddyfile."""
import re
import os
import subprocess
import sys

PW_FILE = "/tmp/admin-credentials.txt"
BASE = os.environ.get("WB2A_BASE", "/opt/workbuddy2api")
CRED_DST = os.environ.get("ADMIN_CREDENTIALS_FILE", os.path.join(BASE, "admin", "credentials.txt"))
HASH_DST = os.environ.get("ADMIN_HASH_FILE", os.path.join(BASE, "admin", "basicauth.hash"))
CADDY_SRC = os.environ.get("CADDY_FILE", "/etc/caddy/Caddyfile")
CADDY_TMP = "/tmp/Caddyfile.patched"

# 1) read password from uploaded file
pw = None
with open(PW_FILE, encoding="utf-8") as f:
    for line in f:
        s = line.strip()
        if s.startswith("密码："):
            pw = s.split("密码：", 1)[1].strip()
            break
if not pw:
    print("ERROR: password not found in", PW_FILE)
    sys.exit(1)
print("password length:", len(pw))

# 2) generate bcrypt hash via caddy
h = subprocess.run(["caddy", "hash-password", "--plaintext", pw],
                   capture_output=True, text=True, timeout=120)
if h.returncode != 0:
    print("ERROR hash-password:", h.stderr[:300])
    sys.exit(1)
newhash = h.stdout.strip()
print("hash prefix:", newhash[:7], "len:", len(newhash))

# 3) write hash + credentials to admin dir (as admin user, no sudo needed)
with open(HASH_DST, "w", encoding="utf-8") as f:
    f.write(newhash)
with open(CRED_DST, "w", encoding="utf-8") as f:
    f.write("管理页登录账号: admin\n")
    f.write("管理页登录密码: %s\n" % pw)
subprocess.run(["chmod", "600", CRED_DST, HASH_DST], check=False)
print("credentials + hash written")

# 4) patch Caddyfile: replace bcrypt hash after "admin" inside basicauth block
with open(CADDY_SRC, encoding="utf-8") as f:
    src = f.read()
pattern = re.compile(r"(admin\s+)(\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53})")
new_src, n = pattern.subn(lambda m: m.group(1) + newhash, src)
if n == 0:
    print("WARNING: no existing bcrypt hash matched; trying to replace placeholder/other form")
    pattern2 = re.compile(r"(admin\s+)(\S+)")
    new_src, n = pattern2.subn(lambda m: m.group(1) + newhash, src)
print("replacements:", n)
with open(CADDY_TMP, "w", encoding="utf-8") as f:
    f.write(new_src)
print("patched Caddyfile written to", CADDY_TMP)
