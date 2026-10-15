#!/usr/bin/env python3
"""Verify admin password against basicauth.hash on VPS.

Outputs verification result without echoing secret values.
Usage: python3 verify-admin-pw.py <candidate_password>
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
    # 1) standard crypt module (if supported by platform)
    try:
        import crypt
        matched = (crypt.crypt(cand, h) == h)
        print("via=crypt")
    except Exception as e:
        print("crypt_unavailable:", type(e).__name__)
    # 2) bcrypt package fallback
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
