#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deploy the WorkBuddy automation sidecar and updated admin page.

The remote service starts with task scheduling disabled by default. The final
health check is read-only and does not invoke signin_bin or task_runner. The
admin Caddy route is migrated so the page uses its own login screen while the
API remains protected by Basic Auth.
"""
import os
import subprocess
import sys


KEY = os.environ.get("DEPLOY_SSH_KEY")
HOST = os.environ.get("DEPLOY_HOST")
WORKSPACE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REMOTE_BASE = os.environ.get("WB2A_BASE", "/opt/workbuddy2api")
REMOTE_ADMIN = REMOTE_BASE + "/admin"
ADMIN_SERVICE = os.environ.get("ADMIN_SERVICE", "workbuddy2api-admin")
AUTOMATION_SERVICE = os.environ.get("AUTOMATION_SERVICE", "workbuddy-automation")
FILES = (
    ("wb2api-admin.py", "/tmp/wb2api-admin.new.py"),
    ("workbuddy_automation.py", "/tmp/workbuddy_automation.new.py"),
    ("deploy/workbuddy-automation.service", "/tmp/workbuddy-automation.new.service"),
)


def run(args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, **kwargs)


def main():
    if not KEY or not HOST:
        print("请先设置 DEPLOY_HOST 和 DEPLOY_SSH_KEY；为避免误部署，脚本没有内置目标主机。", file=sys.stderr)
        return 2

    for src, remote in FILES:
        p = run(
            ["scp", "-i", KEY, src, HOST + ":" + remote],
            cwd=WORKSPACE,
            timeout=120,
        )
        print("scp %-36s rc=%d %s" % (src, p.returncode, (p.stderr or "").strip()[:200]))
        if p.returncode != 0:
            return 1

    remote = (
        "sudo -n install -m 755 /tmp/wb2api-admin.new.py %s/app.py && "
        "sudo -n install -m 755 /tmp/workbuddy_automation.new.py "
        "%s/workbuddy_automation.py && "
        "sudo -n install -m 644 /tmp/workbuddy-automation.new.service "
        "/etc/systemd/system/%s.service && "
        "sudo -n systemctl daemon-reload && "
        "sudo -n systemctl restart %s && "
        "sudo -n /usr/bin/python3 %s/app.py --migrate-caddy && "
        "sudo -n systemctl enable --now %s && "
        "sleep 2 && "
        "echo '--- services ---' && "
        "systemctl is-active %s %s && "
        "echo '--- automation status ---' && "
        "curl -s http://127.0.0.1:7864/api/automation/status"
        % (REMOTE_ADMIN, REMOTE_ADMIN, AUTOMATION_SERVICE, ADMIN_SERVICE,
           REMOTE_ADMIN, AUTOMATION_SERVICE, ADMIN_SERVICE, AUTOMATION_SERVICE)
    )
    p = run(
        ["ssh", "-i", KEY, "-o", "ConnectTimeout=15", HOST, remote],
        timeout=180,
    )
    sys.stdout.write(p.stdout)
    if p.stderr.strip():
        sys.stderr.write("[stderr] " + p.stderr[:1600])
    return p.returncode


if __name__ == "__main__":
    raise SystemExit(main())
