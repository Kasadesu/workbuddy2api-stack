#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for workbuddy_automation.py anti-detection jitter and randomization."""
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


def check(cond, label, extra=""):
    status = "OK" if cond else "FAIL"
    msg = "%-64s %s" % (label, status)
    if extra:
        msg += "  " + extra
    print(msg)
    if not cond:
        FAILS.append(label)


def test_config_normalization():
    # 默认值
    cfg0 = auto.normalize_config({})
    check(cfg0.get("task_jitter_minutes") == 10, "TC-CFG-1: 默认 task_jitter_minutes 为 10")

    # 负数归 0
    cfg1 = auto.normalize_config({"task_jitter_minutes": -5})
    check(cfg1.get("task_jitter_minutes") == 0, "TC-CFG-2: 负数 task_jitter_minutes 归 0")

    # 超过 60 钳制为 60
    cfg2 = auto.normalize_config({"task_jitter_minutes": 120})
    check(cfg2.get("task_jitter_minutes") == 60, "TC-CFG-3: 超过 60 钳制为 60")

    # 正常范围保留
    cfg3 = auto.normalize_config({"task_jitter_minutes": 25})
    check(cfg3.get("task_jitter_minutes") == 25, "TC-CFG-4: 正常数值 25 准确保留")


def test_shuffle_and_gap():
    with tempfile.TemporaryDirectory() as tmpdir:
        recorded_calls = []

        mgr = auto.AutomationManager(base=tmpdir)
        def mock_start(action, args, timeout):
            recorded_calls.append((list(args), timeout))
            return True, "已启动"
        mgr.start = mock_start

        cfg = auto.DEFAULT_CONFIG.copy()
        cfg["task_scheduler_enabled"] = True
        cfg["task_codes"] = ["chat_5"]
        cfg["task_gap_seconds"] = 2.0
        mgr.save_config(cfg)

        # 测试多个账号顺序洗牌与 gap ±30% 浮动
        gaps = set()
        orders = []
        uids_source = [f"account_{i}" for i in range(10)]

        for _ in range(15):
            mgr.start_tasks(uid=None, task_codes=["chat_5"], confirm=True, uids=uids_source)
            args, _ = recorded_calls[-1]
            # args: ["python3", "/app/scripts/task_runner.py", *uids, "--yes", "--gap", gap_str, "--only", "chat_5"]
            gap_idx = args.index("--gap")
            gap_val = float(args[gap_idx + 1])
            gaps.add(gap_val)

            # 提取账号顺序
            call_uids = args[2:args.index("--yes")]
            orders.append(tuple(call_uids))

        # 检查 gap 范围在 2.0 * [0.7, 1.3] 之间 (即 1.4 到 2.6)
        all_gap_in_range = all(1.4 <= g <= 2.6 for g in gaps)
        check(all_gap_in_range and len(gaps) > 1, "TC-JITTER-1: gap 在 ±30% 范围内拟人化浮动")

        # 检查账号顺序洗牌
        unique_orders = len(set(orders))
        check(unique_orders > 1, f"TC-JITTER-2: 多账号任务顺序洗牌生效 (15次中产生 {unique_orders} 种不同排列)")


def test_schedule_slot_jitter():
    with tempfile.TemporaryDirectory() as tmpdir:
        calls = []

        mgr = auto.AutomationManager(base=tmpdir)
        def mock_start(action, args, timeout):
            calls.append(list(args))
            return True, "已启动"
        mgr.start = mock_start

        now = dt.datetime.now()
        slot = now.strftime("%Y-%m-%d-%H")
        slot_start = dt.datetime(now.year, now.month, now.day, now.hour, 0, 0)
        slot_start_ts = slot_start.timestamp()

        cfg = auto.DEFAULT_CONFIG.copy()
        cfg["enabled"] = True
        cfg["task_scheduler_enabled"] = True
        cfg["task_hours"] = [now.hour]
        cfg["task_codes"] = ["chat_5"]
        cfg["task_jitter_minutes"] = 10
        mgr.save_config(cfg)

        # 1. 模拟未到达 target_ts 时不触发
        mgr._slot_jitters[slot] = now.timestamp() + 300  # 设为未来 300 秒
        stop_event = threading.Event()
        # 跑一轮 daemon 周期
        threading.Thread(target=lambda: (stop_event.wait(0.05), stop_event.set()), daemon=True).start()
        mgr.daemon(stop_event=stop_event, interval=0.01)

        state = mgr.load_state()
        check(len(calls) == 0, "TC-SLOT-1: 未到达 target_ts 时保持等待杜绝整点机械打卡")
        check("等待槽位抖动中" in state.get("message", ""), "TC-SLOT-2: 状态中记录抖动等待提示")

        # 2. 模拟到达或超过 target_ts 时放行触发
        mgr._slot_jitters[slot] = now.timestamp() - 10  # 设为已到达
        stop_event = threading.Event()
        threading.Thread(target=lambda: (stop_event.wait(0.05), stop_event.set()), daemon=True).start()
        mgr.daemon(stop_event=stop_event, interval=0.01)

        state = mgr.load_state()
        check(len(calls) == 1, "TC-SLOT-3: 到达 target_ts 时放行触发任务")
        check(state.get("last_scheduled_slot") == slot, "TC-SLOT-4: 任务记录 last_scheduled_slot 槽位防止重复")


def main():
    print("=== 开始运行 workbuddy_automation 防检测时序抖动测试 ===")
    test_config_normalization()
    test_shuffle_and_gap()
    test_schedule_slot_jitter()

    print("\n测试结果汇总:")
    if FAILS:
        print(f"❌ 失败 {len(FAILS)} 个用例: {FAILS}")
        return 1
    else:
        print("✅ 自动化时序抖动与拟人化测试全部 100% 通过！")
        return 0


if __name__ == "__main__":
    sys.exit(main())
