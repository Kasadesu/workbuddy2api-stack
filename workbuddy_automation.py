#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Safe sidecar for WorkBuddy check-in and growth-task operations.

The gateway container remains the source of truth for credentials and its
native check-in scheduler. This module only invokes the existing container
tools through ``docker exec`` and keeps task automation opt-in.
"""
import argparse
import contextlib
import datetime as dt
import json
import os
import re
import shutil
import stat
import subprocess
import threading
import time

try:
    import fcntl  # type: ignore
except ImportError:  # pragma: no cover - Windows development environment
    fcntl = None


KNOWN_TASKS = (
    "chat_5",
    "first_buddy",
    "Model_chat_GLM5.2",
    "RichMeow_Chat",
    "Buddy_App",
    "Buddy_App_QQ",
    "automation_1",
    "Library_read",
    "template_5",
    "playbook_prompt",
    "create_canvas",
    "expert_5",
    "Expert_team_use_3",
    "Hp_Appearance",
    "skill_1",
    "Expert_lighthouse",
    "black_cat",
)
UNFORGEABLE_TASKS = ("Expert_Philanthropy", "task_student_verify")
UID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

DEFAULT_CONFIG = {
    "enabled": True,
    # The Go gateway already schedules check-in. This flag documents that
    # ownership and prevents this sidecar from sending duplicate check-ins.
    "gateway_checkin_enabled": True,
    "task_scheduler_enabled": False,
    "task_hours": [12],
    "task_uids": [],
    "task_codes": [],
    "task_gap_seconds": 1.2,
    "task_timeout_seconds": 900,
}

DEFAULT_GATEWAY_SCHEDULE = {
    "checkin_enabled": True,
    "checkin_hours": [9, 21],
    "travel_enabled": True,
    "travel_hours": [9, 21],
}
GATEWAY_SCHEDULE_FIELDS = tuple(DEFAULT_GATEWAY_SCHEDULE)


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _copy_config(data):
    return json.loads(json.dumps(data))


def normalize_config(raw):
    """Validate and normalize persisted configuration without side effects."""
    cfg = _copy_config(DEFAULT_CONFIG)
    if isinstance(raw, dict):
        cfg.update(raw)

    cfg["enabled"] = bool(cfg.get("enabled", True))
    cfg["gateway_checkin_enabled"] = bool(cfg.get("gateway_checkin_enabled", True))
    cfg["task_scheduler_enabled"] = bool(cfg.get("task_scheduler_enabled", False))

    hours = cfg.get("task_hours", [12])
    if not isinstance(hours, list):
        raise ValueError("task_hours must be a list")
    cfg["task_hours"] = sorted({int(x) for x in hours if 0 <= int(x) <= 23})

    def clean_uids(value):
        if not isinstance(value, list):
            raise ValueError("task_uids must be a list")
        out = []
        for item in value:
            uid = str(item).strip()
            if uid == "ALL" or UID_RE.fullmatch(uid):
                if uid not in out:
                    out.append(uid)
            else:
                raise ValueError("invalid task uid")
        return out

    def clean_codes(value):
        if not isinstance(value, list):
            raise ValueError("task_codes must be a list")
        out = []
        for item in value:
            code = str(item).strip()
            if code in UNFORGEABLE_TASKS:
                raise ValueError("task code is not automatable: " + code)
            if code not in KNOWN_TASKS:
                raise ValueError("unknown task code: " + code)
            if code not in out:
                out.append(code)
        return out

    cfg["task_uids"] = clean_uids(cfg.get("task_uids", []))
    if "ALL" in cfg["task_uids"] and len(cfg["task_uids"]) > 1:
        raise ValueError("ALL 不能和其他账号同时选择")
    cfg["task_codes"] = clean_codes(cfg.get("task_codes", []))

    try:
        gap = float(cfg.get("task_gap_seconds", 1.2))
    except (TypeError, ValueError):
        raise ValueError("task_gap_seconds must be a number")
    if not 1.0 <= gap <= 60.0:
        raise ValueError("task_gap_seconds must be between 1 and 60")
    cfg["task_gap_seconds"] = gap

    try:
        timeout = int(cfg.get("task_timeout_seconds", 900))
    except (TypeError, ValueError):
        raise ValueError("task_timeout_seconds must be an integer")
    if not 60 <= timeout <= 3600:
        raise ValueError("task_timeout_seconds must be between 60 and 3600")
    cfg["task_timeout_seconds"] = timeout
    return cfg


def normalize_gateway_schedule(raw):
    """Validate the gateway's native check-in/travel schedule only."""
    cfg = _copy_config(DEFAULT_GATEWAY_SCHEDULE)
    if isinstance(raw, dict):
        cfg.update({key: raw[key] for key in GATEWAY_SCHEDULE_FIELDS if key in raw})
    for key in ("checkin_enabled", "travel_enabled"):
        cfg[key] = bool(cfg.get(key, True))
    for key in ("checkin_hours", "travel_hours"):
        value = cfg.get(key, [])
        if not isinstance(value, list):
            raise ValueError(key + " must be a list")
        hours = []
        for item in value:
            try:
                hour = int(item)
            except (TypeError, ValueError):
                raise ValueError(key + " must contain hours from 0 to 23")
            if not 0 <= hour <= 23:
                raise ValueError(key + " must contain hours from 0 to 23")
            if hour not in hours:
                hours.append(hour)
        cfg[key] = sorted(hours)
    if cfg["checkin_enabled"] and not cfg["checkin_hours"]:
        raise ValueError("启用自动签到时至少需要一个签到时间")
    if cfg["travel_enabled"] and not cfg["travel_hours"]:
        raise ValueError("启用猫猫旅行时至少需要一个旅行时间")
    return cfg


def _atomic_json(path, data, mode=0o600):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _read_json(path, fallback):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, OSError, ValueError, TypeError):
        return _copy_config(fallback)


def redact_output(text):
    """Remove common credential fields before output reaches the admin page."""
    text = str(text or "")
    text = re.sub(r"(?i)(Bearer\s+)[A-Za-z0-9._~-]+", r"\1<redacted>", text)
    text = re.sub(
        r"(?i)([\"']?(?:accessToken|refreshToken|api_key|token)[\"']?\s*[:=]\s*)[\"']?[^,\s}\"']+",
        r"\1<redacted>",
        text,
    )
    return text


class AutomationManager:
    """Configuration, state and container command boundary for the sidecar."""

    def __init__(self, base="/opt/workbuddy2api", container="workbuddy2api", runner=None, host_runner=None):
        self.base = base
        self.container = container
        self.admin_dir = os.path.join(base, "admin")
        self.gateway_config_path = os.path.join(base, "config.json")
        self.config_path = os.path.join(self.admin_dir, "automation.json")
        self.state_path = os.path.join(self.admin_dir, "automation-state.json")
        self.lock_path = os.path.join(self.admin_dir, "automation.lock")
        self.runner = runner or self._docker_exec
        self.host_runner = host_runner or self._host_run
        self._thread_lock = threading.RLock()

    def load_config(self):
        raw = _read_json(self.config_path, DEFAULT_CONFIG)
        try:
            cfg = normalize_config(raw)
        except ValueError:
            cfg = _copy_config(DEFAULT_CONFIG)
        if not os.path.exists(self.config_path):
            _atomic_json(self.config_path, cfg)
        return cfg

    def save_config(self, raw):
        cfg = normalize_config(raw)
        _atomic_json(self.config_path, cfg)
        return cfg

    def load_gateway_schedule(self):
        raw = _read_json(self.gateway_config_path, {})
        try:
            return normalize_gateway_schedule(raw.get("schedule", {}) if isinstance(raw, dict) else {})
        except ValueError:
            return _copy_config(DEFAULT_GATEWAY_SCHEDULE)

    def save_gateway_schedule(self, raw):
        """Update native gateway schedule, restart safely, and roll back on failure."""
        if not isinstance(raw, dict):
            raise ValueError("网关自动化设置必须是对象")
        with self._operation_lock():
            gateway = _read_json(self.gateway_config_path, None)
            if not isinstance(gateway, dict):
                raise RuntimeError("读取网关配置失败")
            old_gateway = _copy_config(gateway)
            old_schedule = normalize_gateway_schedule(gateway.get("schedule", {}))
            merged = dict(old_schedule)
            merged.update({key: raw[key] for key in GATEWAY_SCHEDULE_FIELDS if key in raw})
            new_schedule = normalize_gateway_schedule(merged)
            gateway["schedule"] = new_schedule
            try:
                mode = stat.S_IMODE(os.stat(self.gateway_config_path).st_mode)
            except OSError:
                mode = 0o644
            backup = self.gateway_config_path + ".bak.automation-" + time.strftime("%Y%m%d%H%M%S")
            try:
                shutil.copy2(self.gateway_config_path, backup)
                _atomic_json(self.gateway_config_path, gateway, mode=mode)
                rc, out, err = self.host_runner(["docker", "restart", self.container], 180)
                if rc != 0:
                    raise RuntimeError((err or out or "重启网关失败").strip()[:240])
            except Exception as exc:
                try:
                    _atomic_json(self.gateway_config_path, old_gateway, mode=mode)
                    self.host_runner(["docker", "restart", self.container], 180)
                except Exception as rollback_exc:
                    raise RuntimeError("保存失败且回滚失败：%s / %s" % (str(exc)[:160], str(rollback_exc)[:120]))
                raise RuntimeError("保存失败，已恢复旧设置：%s" % str(exc)[:200])
            return new_schedule

    def load_state(self):
        fallback = {
            "running": False,
            "action": "",
            "started_at": "",
            "finished_at": "",
            "exit_code": None,
            "message": "",
            "output": "",
            "last_scheduled_slot": "",
        }
        state = _read_json(self.state_path, fallback)
        if not isinstance(state, dict):
            state = fallback
        for key, value in fallback.items():
            state.setdefault(key, value)
        return state

    def _save_state(self, **updates):
        with self._thread_lock:
            state = self.load_state()
            state.update(updates)
            _atomic_json(self.state_path, state)
            return state

    def status(self):
        cfg = self.load_config()
        state = self.load_state()
        schedule = self.load_gateway_schedule()
        return {
            "ok": True,
            "config": cfg,
            "state": state,
            "gateway_checkin": {
                "managed_by_gateway": schedule["checkin_enabled"],
                "message": "由网关调度，旁路不重复执行。",
            },
            "gateway_automation": {
                "checkin": {
                    "managed_by_gateway": schedule["checkin_enabled"],
                    "message": (
                        "自动执行；按钮仅用于手动补查。"
                        if schedule["checkin_enabled"] else "已关闭。"
                    ),
                },
                "travel": {
                    "managed_by_gateway": schedule["travel_enabled"],
                    "message": (
                        "自动执行；旁路不重复触发。"
                        if schedule["travel_enabled"] else "已关闭。"
                    ),
                },
            },
            "gateway_schedule": schedule,
            "task_codes": list(KNOWN_TASKS),
            "blocked_task_codes": list(UNFORGEABLE_TASKS),
        }

    def _docker_exec(self, args, timeout):
        cmd = ["docker", "exec", "-u", "10001", "-w", "/app", self.container]
        cmd.extend(str(x) for x in args)
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8", "ignore"), p.stderr.decode("utf-8", "ignore")

    @staticmethod
    def _host_run(args, timeout):
        p = subprocess.run(args, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8", "ignore"), p.stderr.decode("utf-8", "ignore")

    @contextlib.contextmanager
    def _operation_lock(self):
        os.makedirs(self.admin_dir, exist_ok=True)
        fh = open(self.lock_path, "a+")
        try:
            if fcntl is not None:
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise RuntimeError("已有 WorkBuddy 自动任务正在执行")
            yield
        finally:
            if fcntl is not None:
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
            fh.close()

    def _run_command(self, action, args, timeout):
        started = _now()
        try:
            self._save_state(
                running=True,
                action=action,
                started_at=started,
                finished_at="",
                exit_code=None,
                message="执行中",
                output="",
            )
            with self._operation_lock():
                rc, out, err = self.runner(args, timeout)
            output = redact_output((out or "") + ("\n[stderr]\n" + err if err else ""))
            message = "完成" if rc == 0 else "命令失败"
            self._save_state(
                running=False,
                finished_at=_now(),
                exit_code=rc,
                message=message,
                output=output[-16000:],
            )
            return {"ok": rc == 0, "exit_code": rc, "message": message, "output": output[-16000:]}
        except subprocess.TimeoutExpired:
            message = "命令超时"
            self._save_state(running=False, finished_at=_now(), exit_code=124, message=message, output="")
            return {"ok": False, "exit_code": 124, "message": message, "output": ""}
        except Exception as exc:
            message = str(exc)[:300]
            self._save_state(running=False, finished_at=_now(), exit_code=125, message=message, output="")
            return {"ok": False, "exit_code": 125, "message": message, "output": ""}

    def start(self, action, args, timeout):
        with self._thread_lock:
            state = self.load_state()
            if state.get("running"):
                return False, "已有 WorkBuddy 自动任务正在执行"
            self._save_state(
                running=True,
                action=action,
                started_at=_now(),
                finished_at="",
                exit_code=None,
                message="执行中",
                output="",
            )
            thread = threading.Thread(target=self._run_command, args=(action, args, timeout), daemon=True)
            thread.start()
            return True, "已启动"

    def start_checkin(self):
        return self.start("checkin", ["/app/signin_bin", "/app/auths"], 240)

    def start_scan(self, uid="ALL", uids=None):
        targets = self._validate_uids(uids if uids is not None else uid)
        return self.start("task-scan", ["python3", "/app/scripts/task_runner.py"] + targets, 300)

    def start_tasks(self, uid, task_codes, confirm=False, uids=None):
        if not confirm:
            return False, "任务执行需要 confirm=true"
        targets = self._validate_uids(uids if uids is not None else uid)
        codes = self._validate_codes(task_codes)
        if not codes:
            return False, "至少选择一个任务码"
        cfg = self.load_config()
        args = [
            "python3", "/app/scripts/task_runner.py", *targets,
            "--yes", "--gap", str(cfg["task_gap_seconds"]),
        ]
        for code in codes:
            args.extend(["--only", code])
        return self.start("task-run", args, cfg["task_timeout_seconds"])

    @staticmethod
    def _validate_uid(uid):
        uid = str(uid or "ALL").strip()
        if uid != "ALL" and not UID_RE.fullmatch(uid):
            raise ValueError("uid 格式不合法")
        return uid

    @classmethod
    def _validate_uids(cls, value):
        if isinstance(value, (list, tuple)):
            values = list(value)
        else:
            values = [value]
        if not values:
            raise ValueError("至少选择一个账号")
        out = []
        for item in values:
            uid = cls._validate_uid(item)
            if uid == "ALL" and len(values) != 1:
                raise ValueError("ALL 不能和其他账号同时选择")
            if uid not in out:
                out.append(uid)
        return out

    @staticmethod
    def _validate_codes(codes):
        if isinstance(codes, str):
            codes = [x.strip() for x in codes.split(",") if x.strip()]
        if not isinstance(codes, list):
            raise ValueError("task_codes 必须是数组")
        out = []
        for code in codes:
            code = str(code).strip()
            if code in UNFORGEABLE_TASKS:
                raise ValueError("该任务需要人工完成：" + code)
            if code not in KNOWN_TASKS:
                raise ValueError("未知任务码：" + code)
            if code not in out:
                out.append(code)
        return out

    def daemon(self, stop_event=None, interval=30):
        stop_event = stop_event or threading.Event()
        while not stop_event.is_set():
            cfg = self.load_config()
            now = dt.datetime.now()
            slot = now.strftime("%Y-%m-%d-%H")
            if (
                cfg["enabled"]
                and cfg["task_scheduler_enabled"]
                and now.minute < 5
                and now.hour in cfg["task_hours"]
                and cfg["task_codes"]
                and self.load_state().get("last_scheduled_slot") != slot
            ):
                uids = cfg["task_uids"] or ["ALL"]
                try:
                    self._save_state(last_scheduled_slot=slot)
                    ok, msg = self.start_tasks(uids, cfg["task_codes"], confirm=True)
                    if not ok:
                        self._save_state(message=msg)
                except Exception as exc:
                    self._save_state(message=str(exc)[:300])
            stop_event.wait(interval)


def main(argv=None):
    parser = argparse.ArgumentParser(description="WorkBuddy automation sidecar")
    parser.add_argument("--base", default=os.environ.get("WB2A_BASE", "/opt/workbuddy2api"))
    parser.add_argument("--container", default=os.environ.get("WB2A_CONTAINER", "workbuddy2api"))
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--once-checkin", action="store_true")
    parser.add_argument("--scan", metavar="UID", nargs="?", const="ALL")
    parser.add_argument("--run-tasks", metavar="UID")
    parser.add_argument("--only", action="append", default=[])
    args = parser.parse_args(argv)

    manager = AutomationManager(args.base, args.container)
    if args.daemon:
        manager.daemon()
        return 0
    if args.once_checkin:
        result = manager._run_command("checkin", ["/app/signin_bin", "/app/auths"], 240)
    elif args.scan is not None:
        uid = manager._validate_uid(args.scan)
        result = manager._run_command("task-scan", ["python3", "/app/scripts/task_runner.py", uid], 300)
    elif args.run_tasks:
        codes = manager._validate_codes(args.only)
        uid = manager._validate_uid(args.run_tasks)
        if not codes:
            parser.error("--run-tasks requires at least one --only task code")
        cfg = manager.load_config()
        cmd = ["python3", "/app/scripts/task_runner.py", uid, "--yes", "--gap", str(cfg["task_gap_seconds"])]
        for code in codes:
            cmd.extend(["--only", code])
        result = manager._run_command("task-run", cmd, cfg["task_timeout_seconds"])
    else:
        parser.error("choose --daemon, --once-checkin, --scan or --run-tasks")
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
