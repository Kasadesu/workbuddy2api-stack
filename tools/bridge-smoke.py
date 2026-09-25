#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
桥接服务冒烟测试：按 Responses 协议发请求，把返回的 SSE 解析成事件轨迹打印。
用法:
  python3 tools/bridge-smoke.py --url http://127.0.0.1:17866/v1/responses --case text
  python3 tools/bridge-smoke.py --case tools
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

AUTH = os.path.expanduser(r"~\.codex\auth.json")


def load_key():
    with open(AUTH, encoding="utf-8") as f:
        return json.load(f)["OPENAI_API_KEY"]


def build(case, model):
    base = {"model": model, "stream": True, "store": False,
            "instructions": "You are a helpful coding agent.",
            "parallel_tool_calls": False}
    if case == "text":
        base["input"] = [{"type": "message", "role": "user",
                          "content": [{"type": "input_text",
                                       "text": "Reply with exactly the single word: PONG"}]}]
    elif case == "tools":
        base["input"] = [{"type": "message", "role": "user",
                          "content": [{"type": "input_text",
                                       "text": "List the files in /tmp using the shell tool."}]}]
        base["tools"] = [{
            "type": "function", "name": "shell",
            "description": "Run a shell command.",
            "strict": False,
            "parameters": {"type": "object",
                           "properties": {"command": {"type": "array",
                                                      "items": {"type": "string"}}},
                           "required": ["command"], "additionalProperties": False}}]
        base["tool_choice"] = "auto"
    elif case == "history":
        base["input"] = [
            {"type": "message", "role": "user",
             "content": [{"type": "input_text", "text": "Run echo hi"}]},
            {"type": "function_call", "name": "shell", "arguments": '{"command":["echo","hi"]}',
             "call_id": "call_x1"},
            {"type": "function_call_output", "call_id": "call_x1",
             "output": [{"type": "output_text", "text": "hi"}]},
            {"type": "reasoning", "id": "rs_1", "summary": [], "encrypted_content": "xxx"},
            {"type": "message", "role": "user",
             "content": [{"type": "input_text", "text": "Now reply with exactly: DONE"}]},
        ]
    return base


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:17866/v1/responses")
    ap.add_argument("--case", default="text")
    ap.add_argument("--model", default="cn:deepseek-v4.1-flash")
    ap.add_argument("--raw", action="store_true", help="打印原始 SSE")
    a = ap.parse_args()

    body = json.dumps(build(a.case, a.model), ensure_ascii=False).encode()
    req = urllib.request.Request(a.url, data=body, method="POST",
                                 headers={"Authorization": "Bearer " + load_key(),
                                          "Content-Type": "application/json",
                                          "Accept": "text/event-stream"})
    try:
        resp = urllib.request.urlopen(req, timeout=180)
    except urllib.error.HTTPError as e:
        print("HTTP", e.code)
        print(e.read().decode("utf-8", "replace")[:2000])
        return 1
    print("HTTP", resp.status, "|", resp.headers.get("Content-Type"))
    print("-" * 60)

    n = 0
    types = {}
    text_buf = []
    for line in resp:
        s = line.decode("utf-8", "replace").rstrip("\r\n")
        if a.raw:
            print("RAW|", s)
        if not s.startswith("data:"):
            continue
        try:
            ev = json.loads(s[5:].strip())
        except Exception as e:
            print("!! 无法解析:", s[:200], e)
            continue
        n += 1
        t = ev.get("type")
        types[t] = types.get(t, 0) + 1
        if t == "response.output_text.delta":
            text_buf.append(ev.get("delta") or "")
        if not a.raw:
            extra = ""
            if t == "response.output_item.added":
                it = ev.get("item") or {}
                extra = "item=%s id=%s name=%s" % (it.get("type"), it.get("id"), it.get("name"))
            elif t.endswith("arguments.delta"):
                extra = "delta=%r" % (ev.get("delta"),)
            elif t.endswith("arguments.done"):
                extra = "args=%r" % (ev.get("arguments"),)
            elif t == "response.output_text.delta":
                extra = "delta=%r" % (ev.get("delta"),)
            elif t in ("response.completed", "response.failed"):
                r = ev.get("response") or {}
                extra = "status=%s output=%d usage=%s err=%s" % (
                    r.get("status"), len(r.get("output") or []), r.get("usage"), r.get("error"))
            elif t == "response.created":
                r = ev.get("response") or {}
                extra = "id=%s" % r.get("id")
            else:
                extra = "out_idx=%s item_id=%s" % (ev.get("output_index"), ev.get("item_id"))
            print("%-46s %s" % (t, extra))
    print("-" * 60)
    print("事件总数:", n)
    print("正文:", "".join(text_buf)[:400])
    print("事件类型统计:", json.dumps(types, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
