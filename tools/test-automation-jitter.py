#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for workbuddy_automation.py scheduling jitter and randomization."""
import datetime as dt
import importlib.util
import os
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
AUTO_FILE = os.path.join(os.path.dirname(HERE), "workbuddy_automation.py")

spec = importlib.util.spec_from_file_location("automation_module", AUTO_FILE)
auto = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auto)

FAILS = []


def check(cond, label):
    status = "OK" if cond else "FAIL"
    print("%-56s %s" % (label, status))
    if not cond:
        FAILS.append(label)


def test_config_normalization():
    cfg0 = auto.normalize_config({})
    check(cfg0.get("task_jitter_minutes") == 10, "Default task_jitter_minutes is 10")

    cfg1 = auto.normalize_config({"task_jitter_minutes": -5})
    check(cfg1.get("task_jitter_minutes") == 0, "Negative task_jitter_minutes clamps to 0")

    cfg2 = auto.normalize_config({"task_jitter_minutes": 120})
    check(cfg2.get("task_jitter_minutes") == 60, "Overflow task_jitter_minutes clamps to 60")

    cfg3 = auto.normalize_config({"task_jitter_minutes": 25})
    check(cfg3.get("task_jitter_minutes") == 25, "Valid task_jitter_minutes preserved")


def test_shuffle_and_gap():
    with tempfile.TemporaryDirectory() as tmpdir:
        recorded_calls = []

        mgr = auto.AutomationManager(base=tmpdir)

        def mock_start(action, args, timeout):
            recorded_calls.append((list(args), timeout))
            return True, "started"

        mgr.start = mock_start

        cfg = auto.DEFAULT_CONFIG.copy()
        cfg["task_scheduler_enabled"] = True
        cfg["task_codes"] = ["chat_5"]
        cfg["task_gap_seconds"] = 2.0
        mgr.save_config(cfg)

        gaps = set()
        orders = []
        uids_source = [f"account_{i}" for i in range(10)]

        for _ in range(15):
            mgr.start_tasks(uids_source, ["chat_5"], confirm=True)
            args, _timeout = recorded_calls[-1]
            gap_idx = args.index("--gap")
            gaps.add(float(args[gap_idx + 1]))
            dash_yes_idx = args.index("--yes")
            account_order = args[2:dash_yes_idx]
            orders.append(tuple(account_order))

        valid_bounds = all(1.4 <= g <= 2.6 for g in gaps)
        check(valid_bounds and len(gaps) > 1, "Jittered gap floats within range")
        check(len(set(orders)) > 1, "Multi-account tasks shuffled")


def test_schedule_slot_jitter():
    with tempfile.TemporaryDirectory() as tmpdir:
        calls = []

        mgr = auto.AutomationManager(base=tmpdir)

        def mock_start(uids, codes, confirm=False):
            calls.append((uids, codes))
            return True, "ok"

        mgr.start_tasks = mock_start

        now = dt.datetime.now()
        slot = now.strftime("%Y-%m-%d-%H")

        cfg = auto.DEFAULT_CONFIG.copy()
        cfg["enabled"] = True
        cfg["task_scheduler_enabled"] = True
        cfg["task_hours"] = [now.hour]
        cfg["task_codes"] = ["chat_5"]
        cfg["task_jitter_minutes"] = 10
        mgr.save_config(cfg)

        mgr._slot_jitters[slot] = now.timestamp() + 300
        stop_event = threading.Event()
        threading.Thread(target=lambda: (stop_event.wait(0.05), stop_event.set()), daemon=True).start()
        mgr.daemon(stop_event=stop_event, interval=0.01)

        state = mgr.load_state()
        check(len(calls) == 0, "Wait before reaching slot target timestamp")
        check("等待槽位抖动中" in state.get("message", ""), "Slot jitter wait recorded in state")

        mgr._slot_jitters[slot] = now.timestamp() - 10
        stop_event = threading.Event()
        threading.Thread(target=lambda: (stop_event.wait(0.05), stop_event.set()), daemon=True).start()
        mgr.daemon(stop_event=stop_event, interval=0.01)

        state = mgr.load_state()
        check(len(calls) == 1, "Trigger task after reaching slot target timestamp")
        check(state.get("last_scheduled_slot") == slot, "Record last_scheduled_slot on execution")


def main():
    test_config_normalization()
    test_shuffle_and_gap()
    test_schedule_slot_jitter()

    if FAILS:
        print("\nFailed %d test(s): %s" % (len(FAILS), FAILS))
        return 1

    print("\nAll tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
