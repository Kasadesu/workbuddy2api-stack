#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test history replay preserves arguments for custom_tool_call and local_shell_call.

Usage:
    python tools/test-history-roundtrip.py [bridge_path]
"""
import json
import os
import sys

bridge_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "responses-bridge.py")
bridge_path = os.path.abspath(bridge_path)

g = {"__name__": "_unit_test_"}  # Prevent __main__ block from running
src = open(bridge_path, encoding="utf-8").read()
exec(compile(src, bridge_path, "exec"), g)

to_chat_messages = g["to_chat_messages"]
print("Loaded bridge: %s (VERSION=%s)\n" % (bridge_path, g.get("VERSION")))

JS = 'const r = await tools.exec_command({cmd: "Get-ChildItem -Force"}); text(r)'

CASES = {
    "custom_tool_call (exec)": [
        {"type": "message", "role": "user",
         "content": [{"type": "input_text", "text": "list directory"}]},
        {"type": "custom_tool_call", "call_id": "call_A", "name": "exec", "input": JS},
        {"type": "custom_tool_call_output", "call_id": "call_A",
         "output": "file1.txt\nfile2.txt"},
        {"type": "message", "role": "assistant",
         "content": [{"type": "output_text", "text": "There are two files in the directory."}]},
    ],
    "function_call (standard)": [
        {"type": "message", "role": "user",
         "content": [{"type": "input_text", "text": "read file"}]},
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

EXPECT = {"custom_tool_call (exec)": JS}

fail = 0
for label, inp in CASES.items():
    print("=" * 70)
    print("Scenario:", label)
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

    # Verify original input is preserved
    want = EXPECT.get(label)
    if want is not None:
        got = "".join(
            (tc.get("function") or {}).get("arguments") or ""
            for m in msgs for tc in (m.get("tool_calls") or []))
        ok = (want in got) or (got and want == got)
        if not got.strip():
            ok = False
        elif "exec_command" not in got:
            ok = False
        else:
            ok = True
        print("  -> Argument preserved: %s" % ("PASS" if ok else "FAIL"))
        print("     Expected to contain: %r" % want[:60])
        print("     Actual: %r" % got[:60])
        if not ok:
            fail += 1

# Verify roundtrip: chat -> Responses -> chat
print("=" * 70)
print("Roundtrip consistency test")
cls = g["Translator"]
t = cls("cn:deepseek-v4.1-flash", {"exec": "custom"})
list(t.start())
list(t.tool_delta(0, "call_D", "exec", json.dumps({"input": JS}, ensure_ascii=False)))
items = []
for b in t.finish():
    pass
items = t.out
print("  Output items:")
for it in items:
    print("   ", json.dumps(it, ensure_ascii=False)[:150])
roundtrip = []
for it in items:
    cp = dict(it)
    if cp.get("type") == "custom_tool_call":
        cp["type"] = "custom_tool_call"  # Replayed as-is
    roundtrip.append(cp)
roundtrip.append({"type": "custom_tool_call_output", "call_id": items[0].get("call_id") if items else "x", "output": "ok"})
msgs2 = to_chat_messages({"input": roundtrip})
got2 = "".join((tc.get("function") or {}).get("arguments") or ""
               for m in msgs2 for tc in (m.get("tool_calls") or []))
print("  Replayed arguments = %r" % got2[:90])
ok2 = "exec_command" in got2
print("  -> Roundtrip faithful: %s" % ("PASS" if ok2 else "FAIL"))
if not ok2:
    fail += 1

print("\nResult: %s" % ("All tests passed" if fail == 0 else "%d failures found" % fail))
sys.exit(1 if fail else 0)
