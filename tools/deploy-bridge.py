#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把桥接部署到 VPS 并重启服务（幂等，可直接重复跑）。

做的事：上传 py + service → install 到配置的桥接目录与 /etc/systemd/system
→ daemon-reload → restart → 校验 /healthz 的版本号。
版本号对不上就说明没换成功，比"看 systemctl 说 active"可靠得多。
"""
import os
import subprocess
import sys

KEY = os.environ.get("DEPLOY_SSH_KEY")
HOST = os.environ.get("DEPLOY_HOST")
WORKSPACE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BRIDGE_DIR = os.environ.get("REMOTE_BRIDGE_DIR", "/opt/responses-bridge")
SERVICE = os.environ.get("BRIDGE_SERVICE", "responses-bridge")
SRC = "responses-bridge.py"
DEST = BRIDGE_DIR + "/responses-bridge.py"
UNIT = "deploy/responses-bridge.service"
UNIT_DEST = "/etc/systemd/system/" + SERVICE + ".service"


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


def main():
    if not KEY or not HOST:
        print("请先设置 DEPLOY_HOST 和 DEPLOY_SSH_KEY；为避免误部署，脚本没有内置目标主机。", file=sys.stderr)
        return 2

    p = sh(["scp", "-i", KEY, "-o", "StrictHostKeyChecking=no",
            SRC, HOST + ":/tmp/bridge_new.py"], cwd=WORKSPACE, timeout=120)
    print("scp  py       rc=%d %s" % (p.returncode, (p.stderr or "").strip()[:200]))
    if p.returncode != 0:
        return 1

    p = sh(["scp", "-i", KEY, "-o", "StrictHostKeyChecking=no",
            UNIT, HOST + ":/tmp/bridge_unit.service"], cwd=WORKSPACE, timeout=120)
    print("scp  service  rc=%d %s" % (p.returncode, (p.stderr or "").strip()[:200]))
    if p.returncode != 0:
        return 1

    remote = (
        "sudo -n install -m 755 /tmp/bridge_new.py %s && "
        "sudo -n install -m 644 /tmp/bridge_unit.service %s && "
        "sudo -n systemctl daemon-reload && "
        "sudo -n systemctl restart %s && sleep 2 && "
        "echo '--- systemctl ---' && systemctl is-active %s && "
        "echo '--- healthz ---' && curl -s http://127.0.0.1:7866/healthz && echo && "
        "echo '--- version ---' && curl -s http://127.0.0.1:7866/version && echo && "
        "echo '--- search backends ---' && "
        "tr '\\0' '\\n' < /proc/$(systemctl show -p MainPID --value %s)/environ "
        "| grep -c -E '^(TAVILY|SERPER)_API_KEY=' || echo 0"
        % (DEST, UNIT_DEST, SERVICE, SERVICE, SERVICE, SERVICE))
    r = sh(["ssh", "-i", KEY, "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=15", HOST, remote], timeout=180)
    sys.stdout.write(r.stdout)
    if r.stderr.strip():
        sys.stderr.write("[stderr] " + r.stderr[:1200])
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
