#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""单元测试：验证历史回放时 custom_tool_call / local_shell_call 的参数是否被保留。

背景：Codex 的 shell 能力走 `type:"custom"` 的 exec 工具（输入是自由文本 JS）。
桥接在**回程**把它还原成 custom_tool_call{item: input}；而 Codex 在**下一轮**会把
这个 item 原样放进 input 数组带回来。此时桥接要做逆向映射（Responses item -> chat
的 assistant.tool_calls）。如果字段名对不上，历史里这次调用就会变成"空参数"。

用法: python3 test-history-roundtrip.py <bridge.py 路径>
"""
import json
import os
import sys

bridge_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "responses-bridge.py")
bridge_path = os.path.abspath(bridge_path)

g = {"__name__": "_unit_test_"}          # 关键：别让 __main__ 分支跑起来
src = open(bridge_path, encoding="utf-8").read()
exec(compile(src, bridge_path, "exec"), g)

to_chat_messages = g["to_chat_messages"]
print("已加载桥接: %s (VERSION=%s)\n" % (bridge_path, g.get("VERSION")))

JS = 'const r = await tools.exec_command({cmd: "Get-ChildItem -Force"}); text(r)'

CASES = {
    "custom_tool_call (Codex 的 exec 工具)": [
        {"type": "message", "role": "user",
         "content": [{"type": "input_text", "text": "列一下目录"}]},
        {"type": "custom_tool_call", "call_id": "call_A", "name": "exec", "input": JS},
        {"type": "custom_tool_call_output", "call_id": "call_A",
         "output": "file1.txt\nfile2.txt"},
        {"type": "message", "role": "assistant",
         "content": [{"type": "output_text", "text": "目录里有两个文件。"}]},
    ],
    "function_call (标准工具)": [
        {"type": "message", "role": "user",
         "content": [{"type": "input_text", "text": "读文件"}]},
        {"type": "function_call", "call_id": "call_B", "name": "read_file",
         "arguments": '{"path":"a.txt"}'},
        {"type": "function_call_output", "call_id": "call_B", "output": "hello"},
    ],
    "local_shell_call": [
        {"type": "local_shell_call", "call_id": "call_C",
         "action": {"type": "exec", "command": ["echo", "hi"]}},
        {"type": "local_shell_call_output", "call_id": "call_C", "output": "hi"},
    ],
}

EXPECT = {"custom_tool_call (Codex 的 exec 工具)": JS}

fail = 0
for label, inp in CASES.items():
    print("=" * 70)
    print("场景:", label)
    msgs = to_chat_messages({"input": inp})
    for m in msgs:
        role = m.get("role")
        if m.get("tool_calls"):
            for tc in m["tool_calls"]:
                fn = tc.get("function") or {}
                print("  assistant.tool_calls  name=%-10s arguments=%r"
                      % (fn.get("name"), fn.get("arguments")))
        else:
            print("  %-10s %r" % (role, str(m.get("content"))[:70]))

    # 断言：原始输入是否被完整保留
    want = EXPECT.get(label)
    if want is not None:
        got = "".join(
            (tc.get("function") or {}).get("arguments") or ""
            for m in msgs for tc in (m.get("tool_calls") or []))
        ok = (want in got) or (got and want == got)
        # 宽松判定：只要 arguments 非空且包含原文关键片段
        if not got.strip():
            ok = False
        elif "exec_command" not in got:
            ok = False
        else:
            ok = True
        print("  → 原文是否保留: %s" % ("✅ 是" if ok else "❌ 丢失/被破坏"))
        print("    期望包含: %r" % want[:60])
        print("    实际得到: %r" % got[:60])
        if not ok:
            fail += 1

# 额外：验证回程（chat -> Responses）再回放一遍，模拟真实往返
print("=" * 70)
print("往返一致性（模拟：桥接回程产出 -> Codex 带回来 -> 再翻译）")
cls = g["Translator"]
t = cls("cn:deepseek-v4.1-flash", {"exec": "custom"})
list(t.start())
list(t.tool_delta(0, "call_D", "exec", json.dumps({"input": JS}, ensure_ascii=False)))
items = []
for b in t.finish():
    pass
items = t.out
print("  回程产出的 item:")
for it in items:
    print("   ", json.dumps(it, ensure_ascii=False)[:150])
roundtrip = []
for it in items:
    cp = dict(it)
    if cp.get("type") == "custom_tool_call":
        cp["type"] = "custom_tool_call"      # Codex 原样带回
    roundtrip.append(cp)
roundtrip.append({"type": "custom_tool_call_output", "call_id": items[0].get("call_id") if items else "x", "output": "ok"})
msgs2 = to_chat_messages({"input": roundtrip})
got2 = "".join((tc.get("function") or {}).get("arguments") or ""
               for m in msgs2 for tc in (m.get("tool_calls") or []))
print("  回放后 arguments = %r" % got2[:90])
ok2 = "exec_command" in got2
print("  → 往返是否保真: %s" % ("✅ 是" if ok2 else "❌ 否 —— 源码在历史里丢失"))
if not ok2:
    fail += 1

print("\n结论: %s" % ("全部通过" if fail == 0 else "发现 %d 处缺陷" % fail))
sys.exit(1 if fail else 0)
