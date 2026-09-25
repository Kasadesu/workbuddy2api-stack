#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""桥接 v1.1 离线单测：namespace 拍平 / 回程还原 / web_search 降级 / 调用剔除。

样本全部取自 2026-09-18 从 VPS 桥接日志里挖出的 **Codex 真实请求体**，
不是凭空构造的，避免"测通过了但线上形状对不上"。
"""
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BRIDGE = os.path.join(os.path.dirname(HERE), "responses-bridge.py")


def load():
    spec = importlib.util.spec_from_file_location("bridge", BRIDGE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# ---- 真实工具表（摘自线上请求，collaboration 只保留两个子工具以缩短用例）
REAL_TOOLS = [
    {"type": "custom", "name": "exec",
     "description": "Run JavaScript to orchestrate tool calls.",
     "format": {"type": "grammar", "syntax": "lark", "definition": "start: ..."}},
    {"type": "function", "name": "wait",
     "description": "Waits on a yielded exec cell.",
     "strict": False,
     "parameters": {"type": "object", "properties": {
         "cell_id": {"type": "string"}, "yield_time_ms": {"type": "number"}},
         "required": ["cell_id"], "additionalProperties": False}},
    {"type": "function", "name": "request_user_input", "description": "Ask the user.",
     "strict": False, "parameters": {"type": "object", "properties": {}}},
    {"type": "namespace", "name": "collaboration",
     "description": "Tools for spawning and managing sub-agents.",
     "tools": [
         {"type": "function", "name": "spawn_agent",
          "description": "Spawn a sub-agent.",
          "strict": False,
          "parameters": {"type": "object", "properties": {
              "task_name": {"type": "string"},
              "message": {"type": "string", "encrypted": True},
              "fork_turns": {"type": "string"}},
              "required": ["task_name", "message"], "additionalProperties": False}},
         {"type": "function", "name": "send_message",
          "description": "Send a message to an existing agent.",
          "strict": False,
          "parameters": {"type": "object", "properties": {
              "target": {"type": "string"},
              "message": {"type": "string", "encrypted": True}},
              "required": ["target", "message"], "additionalProperties": False}}]},
    {"type": "namespace", "name": "mcp__cua_repl",
     "description": "UI automation through cua_repl using the initialized cua API.",
     "tools": [
         {"type": "function", "name": "js",
          "description": "Control native apps or browsers.",
          "strict": False,
          "parameters": {"type": "object", "properties": {
              "code": {"type": "string"}, "timeout_ms": {"type": "number"},
              "title": {"type": "string"}}, "required": ["code"],
              "additionalProperties": False}},
         {"type": "function", "name": "js_reset", "description": "Reset the REPL.",
          "strict": False, "parameters": {"type": "object", "properties": {}}}]},
    {"type": "web_search"},
]

FAILS = []


def check(cond, label, extra=""):
    print("%-58s %s%s" % (label, "OK" if cond else "FAIL", ("  " + extra) if extra else ""))
    if not cond:
        FAILS.append(label)


def main():
    m = load()
    print("bridge VERSION =", m.VERSION)
    print("-" * 72)

    # ---------- 1. 去程：namespace 拍平 ----------
    tools, kinds, dropped, nsmap = m.to_chat_tools(REAL_TOOLS)
    names = [t["function"]["name"] for t in tools]
    print("拍平后的函数名:", names)
    print("nsmap:", json.dumps(nsmap, ensure_ascii=False))
    print("dropped:", dropped)
    check(len(tools) == 8, "工具数 = 3 普通 + 4 namespace 子工具 + 1 web_search")
    check("collaboration__spawn_agent" in names, "collaboration.spawn_agent 已拍平")
    check("mcp__cua_repl__js" in names, "mcp__cua_repl.js 已拍平")
    check("mcp__cua_repl__js_reset" in names, "mcp__cua_repl.js_reset 已拍平")
    check("web_search" in names, "web_search 降级为普通函数")
    check(dropped == [], "没有任何工具被丢弃", str(dropped))
    check(nsmap.get("collaboration__spawn_agent") == ("collaboration", "spawn_agent"),
          "nsmap 记录 (namespace, 原名)")
    check(not any(t["function"]["name"] == "collaboration" for t in tools),
          "不残留裸 namespace 名")

    # encrypted 关键字必须剥掉，否则严格后端 400。
    # 注意只断言 parameters —— 工具描述里是可以出现 "encrypted" 这个词的
    # （桥接自己注入的网关限制说明就写了 encrypted payload），断言整个 tool 会误报。
    spawn = [t for t in tools if t["function"]["name"] == "collaboration__spawn_agent"][0]
    params_raw = json.dumps(spawn["function"]["parameters"])
    check("encrypted" not in params_raw, "schema 里的 encrypted 私有字段已剔除")
    check("task_name" in params_raw, "正常参数字段保留")
    check(spawn["function"]["parameters"]["required"] == ["task_name", "message"],
          "required 列表保留")

    # exec(custom) 仍走 custom 语义
    ex = [t for t in tools if t["function"]["name"] == "exec"][0]
    check(ex["function"]["parameters"]["required"] == ["input"],
          "custom 工具仍包成单字段 input")

    # ---------- 2. 历史回放：带 namespace 的 function_call ----------
    hist = {"input": [
        {"type": "message", "role": "user",
         "content": [{"type": "input_text", "text": "spawn a helper"}]},
        {"type": "function_call", "name": "js", "namespace": "mcp__cua_repl",
         "arguments": '{"code":"await cua.getState();"}', "call_id": "call_a1"},
        {"type": "function_call_output", "call_id": "call_a1",
         "output": [{"type": "output_text", "text": "ok"}]},
        {"type": "function_call", "name": "spawn_agent", "namespace": "collaboration",
         "arguments": '{"task_name":"t1","message":"hi"}', "call_id": "call_a2"},
        {"type": "function_call_output", "call_id": "call_a2",
         "output": [{"type": "output_text", "text": "spawned"}]},
    ]}
    msgs = m.to_chat_messages(hist)
    call_names = []
    for msg in msgs:
        for tc in msg.get("tool_calls") or []:
            call_names.append(tc["function"]["name"])
    print("历史回放后的工具名:", call_names)
    check(call_names == ["mcp__cua_repl__js", "collaboration__spawn_agent"],
          "历史里的 namespace 调用还原成拍平名")
    check(msgs[1]["tool_calls"][0]["function"]["arguments"] == '{"code":"await cua.getState();"}',
          "参数原样保留")
    check([x for x in msgs if x.get("role") == "tool"][0]["content"] == "ok",
          "工具结果保留")

    # ---------- 3. 回程：item 形状带 namespace ----------
    tr = m.Translator("cn:test", kinds, nsmap)
    chunks = [
        {"choices": [{"delta": {"tool_calls": [
            {"index": 0, "id": "call_z1", "type": "function",
             "function": {"name": "collaboration__spawn_agent",
                          "arguments": '{"task_name":'}}]}}]},
        {"choices": [{"delta": {"tool_calls": [
            {"index": 0, "function": {"arguments": '"t9","message":"go"}'}}]}}]},
        {"choices": [{"delta": {"tool_calls": [
            {"index": 1, "id": "call_z2", "type": "function",
             "function": {"name": "mcp__cua_repl__js", "arguments": '{"code":"1"}'}}]}}]},
    ]
    events = []
    for ch in chunks:
        events.extend(m.translate_chunk(tr, ch))
    events.extend(tr.finish())
    items = []
    for ev in events:
        for line in ev.decode("utf-8").splitlines():
            if not line.startswith("data: "):
                continue
            o = json.loads(line[6:])
            if o.get("type") == "response.output_item.done":
                items.append(o["item"])
    print("回程 item:", json.dumps(items, ensure_ascii=False))
    check(len(items) == 2, "两个工具调用各自成 item")
    i0, i1 = items
    check(i0["name"] == "spawn_agent" and i0.get("namespace") == "collaboration",
          "collaboration 调用还原成 name+namespace")
    check(i1["name"] == "js" and i1.get("namespace") == "mcp__cua_repl",
          "mcp__cua_repl 调用还原成 name+namespace")
    check(i0["call_id"] == "call_z1" and i0["arguments"] == '{"task_name":"t9","message":"go"}',
          "参数拼接完整且 call_id 保留")
    check(not any("__" in it["name"] for it in items), "拍平名没有泄漏给 Codex")

    # ---------- 4. strip_calls：剔除桥接自己消化的 web_search 调用 ----------
    src = [
        {"choices": [{"delta": {"content": "let me search. ",
                                "tool_calls": [{"index": 0, "id": "c1",
                                                "function": {"name": "web_search",
                                                             "arguments": '{"query":"x"}'}}]}}]},
        {"choices": [{"delta": {"tool_calls": [{"index": 1, "id": "c2",
                                                "function": {"name": "exec",
                                                             "arguments": "{}"}}]}}]},
    ]
    got = m.strip_calls(src, {0})
    left = [(tc["index"], tc["function"]["name"])
            for c in got for ch in c["choices"]
            for tc in (ch["delta"].get("tool_calls") or [])]
    check(left == [(1, "exec")], "web_search 调用被摘掉，其它调用不受影响", str(left))
    check(got[0]["choices"][0]["delta"]["content"] == "let me search. ",
          "正文增量不受影响")
    check(m.strip_calls(src, set()) is src, "drop 为空时原样返回（零开销）")

    # ---------- 5. search_query_from_args 容错 ----------
    cases = [
        ('{"query":"上海天气"}', "上海天气"),
        ('{"q":"openai"}', "openai"),
        ('{"keywords":"  spaced  "}', "spaced"),
        ('{"query": "broken json', "broken json"),
        ("", ""),
        ('{"other":"only"}', "only"),
    ]
    for raw, want in cases:
        got_q = m.search_query_from_args(raw)
        check(got_q == want, "query 解析 %r" % raw[:28], "-> %r" % got_q)

    print("-" * 72)
    if FAILS:
        print("失败 %d 项: %s" % (len(FAILS), FAILS))
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
