#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for namespace flattening, return translation, and web_search fallback."""
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


# Tool declarations matching client schemas
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

    # 1. Outbound: namespace flattening
    tools, kinds, dropped, nsmap = m.to_chat_tools(REAL_TOOLS)
    names = [t["function"]["name"] for t in tools]
    print("Flattened tool names:", names)
    print("nsmap:", json.dumps(nsmap, ensure_ascii=False))
    print("dropped:", dropped)
    check(len(tools) == 8, "Tool count: 3 standard + 4 namespace child tools + 1 web_search")
    check("collaboration__spawn_agent" in names, "collaboration.spawn_agent flattened")
    check("mcp__cua_repl__js" in names, "mcp__cua_repl.js flattened")
    check("mcp__cua_repl__js_reset" in names, "mcp__cua_repl.js_reset flattened")
    check("web_search" in names, "web_search downgraded to standard function")
    check(dropped == [], "No tools dropped", str(dropped))
    check(nsmap.get("collaboration__spawn_agent") == ("collaboration", "spawn_agent"),
          "nsmap records (namespace, original_name)")
    check(not any(t["function"]["name"] == "collaboration" for t in tools),
          "No bare namespace names remain")

    # Private encrypted keywords stripped from schema
    spawn = [t for t in tools if t["function"]["name"] == "collaboration__spawn_agent"][0]
    params_raw = json.dumps(spawn["function"]["parameters"])
    check("encrypted" not in params_raw, "Private encrypted keyword stripped from schema")
    check("task_name" in params_raw, "Standard parameters preserved")
    check(spawn["function"]["parameters"]["required"] == ["task_name", "message"],
          "required list preserved")

    # Custom tools wrapped with single input property
    ex = [t for t in tools if t["function"]["name"] == "exec"][0]
    check(ex["function"]["parameters"]["required"] == ["input"],
          "Custom tools wrapped with input field")

    # 2. History replay: namespace function_call
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
    print("Replayed tool names:", call_names)
    check(call_names == ["mcp__cua_repl__js", "collaboration__spawn_agent"],
          "Namespaced calls restored to flattened names")
    check(msgs[1]["tool_calls"][0]["function"]["arguments"] == '{"code":"await cua.getState();"}',
          "Arguments preserved")
    check([x for x in msgs if x.get("role") == "tool"][0]["content"] == "ok",
          "Tool results preserved")

    # 3. Inbound: item restored with namespace
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
    print("Inbound items:", json.dumps(items, ensure_ascii=False))
    check(len(items) == 2, "Two distinct tool items generated")
    i0, i1 = items
    check(i0["name"] == "spawn_agent" and i0.get("namespace") == "collaboration",
          "collaboration call restored with name and namespace")
    check(i1["name"] == "js" and i1.get("namespace") == "mcp__cua_repl",
          "mcp__cua_repl call restored with name and namespace")
    check(i0["call_id"] == "call_z1" and i0["arguments"] == '{"task_name":"t9","message":"go"}',
          "Arguments concatenated and call_id preserved")
    check(not any("__" in it["name"] for it in items), "Flattened names not leaked to client")

    # 4. strip_calls: remove consumed web_search calls
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
    check(left == [(1, "exec")], "web_search call removed without affecting other calls", str(left))
    check(got[0]["choices"][0]["delta"]["content"] == "let me search. ",
          "Text content preserved")
    check(m.strip_calls(src, set()) is src, "Empty drop returns original list")

    # 5. search_query_from_args parsing
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
        check(got_q == want, "query parse %r" % raw[:28], "-> %r" % got_q)

    print("-" * 72)
    if FAILS:
        print("FAILURES (%d): %s" % (len(FAILS), FAILS))
        return 1
    print("All tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
