#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    responses-bridge
=======================
把 Codex 发出的 OpenAI **Responses API**（POST /v1/responses）
翻译成上游唯一支持的 **Chat Completions API**（POST /v1/chat/completions），
再把流式回复翻译回 Responses 事件序列。

为什么需要它：新版 Codex(>=0.154) 只实现了 Responses 协议，`wire_api = "chat"`
已被硬移除；而 workbuddy2api 网关只有 chat/completions。两者无法直接对话。

设计约束：
- 纯标准库，零第三方依赖（VPS 只有 1.8G 内存，装不下 LiteLLM 之类）。
- 请求原文先落盘再解析，保证任何解析异常都能事后复原现场。
- 输出的 SSE 事件尽量对齐官方 Responses API 的真实形状（多余字段无害，缺字段才会出问题）。
"""
import argparse
import gzip
import html as html_mod
import io
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.7.0"

DEFAULT_UPSTREAM = "http://127.0.0.1:7863/v1/chat/completions"
DEFAULT_PORT = 7866
LOG_MAX_BYTES = 8 * 1024 * 1024
INLINE_BODY_MAX = 60000      # 超过此长度的请求体不内联，单独落盘（见 _log_request）
BODY_KEEP = 60               # bodies/ 目录最多保留的文件数
TOKEN_STATS_FILENAME = "token-usage.json"
TOKEN_STATS_DAY_LIMIT = 400
TOKEN_STATS_LOCK = threading.RLock()

NS_SEP = "__"                # namespace 拍平时的连接符（chat 工具名不允许点号）
WEB_SEARCH_TOOL = "web_search"
WEB_SEARCH_MAX_ROUNDS = 5    # 桥接代执行搜索的最大轮数，防止模型无限搜
WEB_SEARCH_TIMEOUT = 20
SNIPPET_MAX = 300            # 单条摘要截断长度，纯粹为了省 token

# Responses hosted tool 的名字在不同 Codex/SDK 版本里出现过多种写法。
# 对外保留原名，对内统一按“本地代执行工具”处理。
WEB_FETCH_TOOL_NAMES = frozenset((
    "webfetch", "web_fetch", "webfetch_preview", "web_fetch_preview",
))
WEB_FETCH_TIMEOUT = 20
WEB_FETCH_MAX_ROUNDS = 5
WEB_FETCH_MAX_BYTES = 2 * 1024 * 1024
WEB_FETCH_MAX_CHARS = 24000
WEB_FETCH_MAX_REDIRECTS = 5
WEB_FETCH_ALLOWED_PORTS = frozenset((80, 443))


# ---------------------------------------------------------------- 小工具

def _id(prefix: str) -> str:
    return prefix + os.urandom(12).hex()


def _nonnegative_int(value):
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def normalize_usage(usage):
    """将 Chat Completions / Responses 两种 usage 字段统一为安全计数。"""
    if not isinstance(usage, dict):
        return None
    input_tokens = _nonnegative_int(
        usage.get("input_tokens", usage.get("prompt_tokens", 0)))
    output_tokens = _nonnegative_int(
        usage.get("output_tokens", usage.get("completion_tokens", 0)))
    total_raw = usage.get("total_tokens")
    total_tokens = _nonnegative_int(total_raw)
    if total_tokens <= 0:
        total_tokens = input_tokens + output_tokens
    if total_tokens <= 0 and input_tokens <= 0 and output_tokens <= 0:
        return None
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
    }


def _empty_token_stats():
    return {
        "version": 1,
        "updated_at": 0,
        "total": {"input_tokens": 0, "output_tokens": 0,
                   "total_tokens": 0, "requests": 0},
        "days": {},
    }


def _token_stats_path(logdir):
    return os.path.join(logdir, TOKEN_STATS_FILENAME)


def _load_token_stats(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return _empty_token_stats()
    except Exception:
        return _empty_token_stats()
    base = _empty_token_stats()
    total = data.get("total") if isinstance(data.get("total"), dict) else {}
    base["updated_at"] = _nonnegative_int(data.get("updated_at"))
    for key in base["total"]:
        base["total"][key] = _nonnegative_int(total.get(key))
    days = data.get("days") if isinstance(data.get("days"), dict) else {}
    for day, raw in days.items():
        if not isinstance(day, str) or not isinstance(raw, dict):
            continue
        base["days"][day] = {
            "input_tokens": _nonnegative_int(raw.get("input_tokens")),
            "output_tokens": _nonnegative_int(raw.get("output_tokens")),
            "total_tokens": _nonnegative_int(raw.get("total_tokens")),
            "requests": _nonnegative_int(raw.get("requests")),
        }
    return base


def record_token_usage(logdir, usage, now=None):
    """累计一次上游响应的 usage，不记录模型正文、提示词或鉴权信息。"""
    normalized = normalize_usage(usage)
    if not normalized:
        return False
    timestamp = int(time.time() if now is None else now)
    day = time.strftime("%Y-%m-%d", time.localtime(timestamp))
    path = _token_stats_path(logdir)
    try:
        with TOKEN_STATS_LOCK:
            os.makedirs(logdir, mode=0o700, exist_ok=True)
            try:
                os.chmod(logdir, 0o700)
            except OSError:
                pass
            stats = _load_token_stats(path)
            total = stats["total"]
            daily = stats["days"].setdefault(day, {
                "input_tokens": 0, "output_tokens": 0,
                "total_tokens": 0, "requests": 0,
            })
            for key in ("input_tokens", "output_tokens", "total_tokens"):
                total[key] += normalized[key]
                daily[key] += normalized[key]
            total["requests"] += 1
            daily["requests"] += 1
            stats["updated_at"] = timestamp
            for old_day in sorted(stats["days"])[:-TOKEN_STATS_DAY_LIMIT]:
                stats["days"].pop(old_day, None)
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(stats, f, ensure_ascii=False, indent=2)
            os.replace(tmp, path)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        return True
    except Exception:
        # 统计文件不可写时不能影响正常对话请求。
        return False


def read_token_usage(logdir, now=None):
    """读取总量和 VPS 本地日期的当日量，供管理页展示。"""
    timestamp = int(time.time() if now is None else now)
    day = time.strftime("%Y-%m-%d", time.localtime(timestamp))
    path = _token_stats_path(logdir)
    with TOKEN_STATS_LOCK:
        stats = _load_token_stats(path)
    total = stats["total"]
    today = stats["days"].get(day) or {
        "input_tokens": 0, "output_tokens": 0,
        "total_tokens": 0, "requests": 0,
    }
    return {
        "ok": True,
        "available": os.path.exists(path),
        "source": "responses-bridge",
        "updated_at": stats["updated_at"],
        "total_tokens": total["total_tokens"],
        "today_tokens": today["total_tokens"],
        "total_input_tokens": total["input_tokens"],
        "total_output_tokens": total["output_tokens"],
        "today_input_tokens": today["input_tokens"],
        "today_output_tokens": today["output_tokens"],
        "total_requests": total["requests"],
        "today_requests": today["requests"],
    }


def content_to_text(c) -> str:
    """把 Responses 的 content（字符串或 part 数组）拍平成纯文本。"""
    if c is None:
        return ""
    if isinstance(c, str):
        return c
    if not isinstance(c, list):
        return str(c)
    parts = []
    for p in c:
        if isinstance(p, str):
            parts.append(p)
            continue
        if not isinstance(p, dict):
            continue
        t = p.get("type")
        if t in ("input_text", "output_text", "text", "summary_text"):
            parts.append(p.get("text") or "")
        elif t in ("input_image", "image_url"):
            parts.append("[image]")
        elif t == "refusal":
            parts.append(p.get("refusal") or "")
        elif isinstance(p.get("text"), str):
            parts.append(p["text"])
    return "".join(parts)


class UnsupportedImageError(ValueError):
    """图片输入无法映射到 Chat Completions 时的可解释错误。"""


def _image_chat_part(p: dict) -> dict:
    """把 Responses 的 input_image/image_url 转成 Chat 的 image_url part。"""
    raw_url = p.get("image_url")
    detail = p.get("detail")
    if isinstance(raw_url, dict):
        detail = raw_url.get("detail") or detail
        raw_url = raw_url.get("url") or raw_url.get("image_url")
    if raw_url is None:
        raw_url = p.get("url")
    if not isinstance(raw_url, str) or not raw_url.strip():
        if p.get("file_id"):
            raise UnsupportedImageError(
                "image file_id is not supported by this bridge; use a public http(s) URL "
                "or a data:image/...;base64 URL instead"
            )
        raise UnsupportedImageError(
            "image input requires image_url; use a public http(s) URL or a "
            "data:image/...;base64 URL"
        )

    url = raw_url.strip()
    lowered = url.lower()
    if not (lowered.startswith("http://") or lowered.startswith("https://") or
            lowered.startswith("data:image/")):
        raise UnsupportedImageError(
            "image_url must be an http(s) URL or a data:image/...;base64 URL"
        )

    image_url = {"url": url}
    if isinstance(detail, str) and detail in ("auto", "low", "high"):
        image_url["detail"] = detail
    return {"type": "image_url", "image_url": image_url}


def content_to_chat_content(c):
    """把 Responses 内容转成 Chat 内容；含图片时保留多模态 part 数组。"""
    if c is None:
        return ""
    if isinstance(c, str):
        return c
    if isinstance(c, dict):
        c = [c]
    if not isinstance(c, list):
        return str(c)

    parts = []
    has_image = False
    for p in c:
        if isinstance(p, str):
            parts.append({"type": "text", "text": p})
            continue
        if not isinstance(p, dict):
            continue
        t = p.get("type")
        if t in ("input_text", "output_text", "text", "summary_text"):
            value = p.get("text")
            if value is not None:
                parts.append({"type": "text", "text": str(value)})
        elif t in ("input_image", "image_url"):
            parts.append(_image_chat_part(p))
            has_image = True
        elif t == "refusal":
            value = p.get("refusal")
            if value is not None:
                parts.append({"type": "text", "text": str(value)})
        elif isinstance(p.get("text"), str):
            parts.append({"type": "text", "text": p["text"]})

    if not has_image:
        return "".join(part["text"] for part in parts if part.get("type") == "text")
    return parts


def _parse_args(s):
    """工具参数可能是 str / dict / None，统一成字符串。"""
    if s is None:
        return ""
    if isinstance(s, str):
        return s
    try:
        return json.dumps(s, ensure_ascii=False)
    except Exception:
        return str(s)


def flat_name(namespace: str, name: str) -> str:
    """把 namespace 工具拍成一个 chat 能表达的普通函数名。

    Codex 的 namespace 工具（collaboration.* / mcp__*.js）在 Responses 里是
    {"type":"namespace","name":"collaboration","tools":[...]}，
    chat 协议没有嵌套概念，只能拍平。用 `__` 连接而不是 `.`，
    因为多数后端的函数名校验只放行 [A-Za-z0-9_-]。
    """
    return "%s%s%s" % (namespace, NS_SEP, name)


def _normalized_tool_name(name) -> str:
    """工具名只用于本地路由判断，保持原名用于回程兼容。"""
    return str(name or "").strip().lower().replace("-", "_")


def is_web_fetch_name(name) -> bool:
    return _normalized_tool_name(name) in WEB_FETCH_TOOL_NAMES


def web_fetch_decl_name(tool):
    """返回 webfetch 声明应暴露给上游模型的函数名，否则返回 None。"""
    if not isinstance(tool, dict):
        return None
    tt = _normalized_tool_name(tool.get("type"))
    name = tool.get("name")
    if tt in WEB_FETCH_TOOL_NAMES:
        return str(name or tt)
    # 有些兼容客户端把 hosted 工具错误/简化地写成 function；只按明确的
    # 保留名接管，避免影响普通用户自定义函数。
    if tt == "function" and is_web_fetch_name(name):
        return str(name)
    return None


def is_local_web_tool_name(name) -> bool:
    return name == WEB_SEARCH_TOOL or is_web_fetch_name(name)


def _clean_schema(node):
    """递归剔除 schema 里的非标准关键字。

    Codex 的 collaboration 工具参数带 "encrypted": true（OpenAI 私有语义），
    严格校验 JSON Schema 的后端会因此 400，必须剥掉。
    """
    if isinstance(node, dict):
        return {k: _clean_schema(v) for k, v in node.items() if k != "encrypted"}
    if isinstance(node, list):
        return [_clean_schema(v) for v in node]
    return node


# ---------------------------------------------------- 请求：Responses -> Chat

def to_chat_messages(req: dict):
    msgs = []
    instr = req.get("instructions")
    if isinstance(instr, str) and instr.strip():
        msgs.append({"role": "system", "content": instr})

    inp = req.get("input")
    if isinstance(inp, str):
        msgs.append({"role": "user", "content": inp})
        return msgs
    if not isinstance(inp, list):
        return msgs

    pending_content = None # 暂存的 assistant 正文/多模态内容，便于与 function_call 合并
    open_tool_msg = None   # 正在进行中的 assistant(tool_calls) 消息

    def flush_pending():
        nonlocal pending_content
        if pending_content:
            msgs.append({"role": "assistant", "content": pending_content})
        pending_content = None

    def add_call(call):
        """把一次工具调用并入当前 assistant 消息，没有就新建。"""
        nonlocal open_tool_msg, pending_content
        if open_tool_msg is None:
            m = {"role": "assistant", "content": pending_content, "tool_calls": [call]}
            pending_content = None
            msgs.append(m)
            open_tool_msg = m
        else:
            open_tool_msg["tool_calls"].append(call)

    def add_tool_result(call_id, output):
        nonlocal open_tool_msg
        flush_pending()
        open_tool_msg = None
        msgs.append({"role": "tool", "tool_call_id": call_id or "",
                     "content": content_to_text(output) or ""})

    for it in inp:
        if not isinstance(it, dict):
            continue
        t = it.get("type")

        if t in (None, "message"):
            role = (it.get("role") or "user").lower()
            if role in ("developer", "system"):
                role = "system"
            content = content_to_chat_content(it.get("content"))
            if role == "assistant":
                if pending_content is None:
                    pending_content = content
                elif isinstance(pending_content, list) or isinstance(content, list):
                    if not isinstance(pending_content, list):
                        pending_content = [{"type": "text", "text": pending_content}]
                    if isinstance(content, list):
                        pending_content.extend(content)
                    elif content:
                        pending_content.append({"type": "text", "text": content})
                else:
                    pending_content += content
            else:
                flush_pending()
                open_tool_msg = None
                msgs.append({"role": role, "content": content})

        elif t == "function_call":
            # 回放历史时，命名空间工具必须还原成拍平后的名字，
            # 否则模型会看到一个自己没见过的工具名（工具表里只有 collaboration__spawn_agent）。
            nm = it.get("name") or ""
            ns = it.get("namespace")
            if ns:
                nm = flat_name(ns, nm)
            add_call({"id": it.get("call_id") or it.get("id") or _id("call_"),
                      "type": "function",
                      "function": {"name": nm, "arguments": _parse_args(it.get("arguments"))}})

        elif t == "function_call_output":
            add_tool_result(it.get("call_id"), it.get("output"))

        elif t == "reasoning":
            # 上游无对应概念，只能丢弃（不影响正文与工具调用）
            continue

        elif t == "custom_tool_call":
            # ⚠️ custom 工具（Codex 的 exec）输入在 `input` 字段，**不是** `arguments`。
            # 回放时必须按模型当初产出的形状重建 —— 即 {"input": <原文>} —— 因为
            # 上游工具表就是把 custom 工具暴露成"单字段对象"的。
            # 漏掉这一步，历史里每次 exec 调用都会变成"空参数"：模型看到自己
            # "调用过工具却没传任何参数"，会误判自己的调用格式有问题，反复重试和自我
            # 纠正。外部表现就是"我的工具调用格式一直写错"。
            raw_in = it.get("input")
            if raw_in is None:
                raw_in = it.get("arguments")
            if not isinstance(raw_in, str):
                raw_in = "" if raw_in is None else _parse_args(raw_in)
            add_call({"id": it.get("call_id") or it.get("id") or _id("call_"),
                      "type": "function",
                      "function": {"name": it.get("name") or t,
                                   "arguments": json.dumps({"input": raw_in},
                                                           ensure_ascii=False)}})

        elif t in ("local_shell_call", "tool_search_call"):
            # 回放历史时尽力还原成一次函数调用，保证上下文连贯
            args = it.get("arguments")
            if args is None and isinstance(it.get("action"), dict):
                args = json.dumps(it["action"], ensure_ascii=False)
            add_call({"id": it.get("call_id") or it.get("id") or _id("call_"),
                      "type": "function",
                      "function": {"name": it.get("name") or t, "arguments": _parse_args(args)}})

        elif t in ("custom_tool_call_output", "tool_search_output", "local_shell_call_output"):
            add_tool_result(it.get("call_id"), it.get("output"))

        else:
            txt = content_to_text(it.get("content")) or content_to_text(it.get("text"))
            if txt:
                flush_pending()
                open_tool_msg = None
                msgs.append({"role": "user", "content": txt})

    flush_pending()
    return msgs


def to_chat_tools(tools):
    """返回 (chat_tools, kinds, dropped, nsmap)。

    Responses 的工具是扁平结构 {type:function,name,parameters}，
    Chat Completions 是嵌套结构 {type:function,function:{...}}，需要转换。

    ⚠️ v1.0.x 把 namespace 整体丢弃了，等于砍掉了 Codex 的两个核心能力：
      - `collaboration.*`  → 子代理（spawn_agent / send_message / wait_agent ...）
      - `mcp__cua_repl.*`  → 浏览器与 UI 自动化（js / js_reset），联网搜索的实际执行者
    现在改为**拍平**：把 namespace 里的每个子工具提成独立的 chat 函数，
    名字用 `<ns>__<tool>`；回程再靠 nsmap 还原成带 namespace 字段的 item。

    web_search 属于 OpenAI 服务端 hosted 工具，上游 chat 后端不存在这个概念，
    这里把它降级成一个普通函数，由桥接自己代执行（见 do_web_search）。

    kinds:  扁平名 -> 回程 item 形状（function / custom / local_shell）
    nsmap:  扁平名 -> (namespace, 原子工具名)
    """
    out, kinds, dropped, nsmap = [], {}, [], {}

    def add_fn(flat, desc, params, strict=None):
        fn = {"name": flat, "description": desc or ""}
        fn["parameters"] = _clean_schema(params) if params else {"type": "object",
                                                                 "properties": {}}
        if strict is not None:
            fn["strict"] = strict
        out.append({"type": "function", "function": fn})

    for t in tools or []:
        if not isinstance(t, dict):
            continue
        tt = t.get("type")
        name = t.get("name")

        fetch_name = web_fetch_decl_name(t)
        if fetch_name:
            add_fn(fetch_name,
                   "Fetch one public web page and return readable text. Use an "
                   "absolute http or https URL. Do not use this for localhost, "
                   "private network addresses, images or binary downloads.",
                   {"type": "object", "properties": {
                       "url": {"type": "string",
                               "description": "Absolute public http(s) URL to fetch."}},
                    "required": ["url"], "additionalProperties": False})
            kinds[fetch_name] = "function"
            continue

        if tt == "function":
            f = t.get("function")
            if isinstance(f, dict):
                out.append({"type": "function", "function": _clean_schema(f)})
                kinds[f.get("name") or ""] = "function"
                continue
            fn = {"name": name or ""}
            if t.get("description"):
                fn["description"] = t["description"]
            if t.get("parameters") is not None:
                fn["parameters"] = _clean_schema(t["parameters"])
            elif t.get("input_schema") is not None:
                fn["parameters"] = _clean_schema(t["input_schema"])
            if t.get("strict") is not None:
                fn["strict"] = t["strict"]
            out.append({"type": "function", "function": fn})
            kinds[name or ""] = "function"

        elif tt == "local_shell":
            add_fn("local_shell", "Run a shell command on the user's machine.",
                   {"type": "object", "properties": {
                       "command": {"type": "array", "items": {"type": "string"}}},
                    "required": ["command"]})
            kinds["local_shell"] = "local_shell"

        elif tt == "custom":
            # custom 工具（Codex 的 exec 就是这一类）输入是自由文本而非 JSON Schema。
            # 用一个单字段对象把它包起来，模型才表达得出来；回程时再把 input
            # 解开，还原成自定义工具的原始输入。
            desc = (t.get("description") or "") + (
                "\n\nIMPORTANT: pass the raw free-form input (for example the exact "
                "source code to execute) verbatim in the single `input` string "
                "parameter. Do not escape, wrap or reformat it.")
            add_fn(name or "custom", desc,
                   {"type": "object", "properties": {
                       "input": {"type": "string",
                                 "description": "Raw free-form input for this tool."}},
                    "required": ["input"]}, strict=False)
            kinds[name or "custom"] = "custom"

        elif tt == "namespace":
            # 命名空间工具：整组提平成 `<ns>__<tool>` 普通函数。
            ns = name or "ns"
            nsdesc = (t.get("description") or "").strip()
            subs = t.get("tools") or []
            if not subs:
                dropped.append(ns)
                continue
            for sub in subs:
                if not isinstance(sub, dict):
                    continue
                sn = sub.get("name")
                if not sn:
                    continue
                flat = flat_name(ns, sn)
                desc = (sub.get("description") or "").strip()
                if nsdesc:
                    desc = "%s\n\n[namespace: %s]" % (desc, nsdesc)

                # ---- 网关适配提示（实测踩出来的，不是猜的）
                # Codex 把跨代理的任务正文（spawn_agent.message / send_message.message）
                # 打包成 {"type":"encrypted_content","encrypted_content":<明文>} 交给子代理，
                # 而解密用的密钥在 OpenAI 服务端 —— 走第三方网关时密文产生不出来，
                # 子代理读到的 Payload 就是空的，会回 "No task payload was provided"。
                # 但 fork_turns="all" 时子代理继承完整对话上下文，照样能知道要做什么
                # （已实测：继承历史的那个子代理正确算出了结果）。
                if ns == "collaboration" and sn == "spawn_agent":
                    desc += (
                        "\n\nIMPORTANT — GATEWAY LIMITATION: this endpoint is a "
                        "third-party gateway that cannot produce the server-side "
                        "encrypted task payload. A sub-agent spawned with "
                        "fork_turns=\"none\" receives an EMPTY task and will reply "
                        "\"no task payload was provided\". Therefore ALWAYS pass "
                        "fork_turns=\"all\" so the sub-agent inherits the full "
                        "conversation and can see what it must do, and put a short "
                        "task summary in task_name. Do not rely on `message` alone, "
                        "and do not retry after an empty-payload reply.")
                elif ns == "collaboration" and sn in ("send_message", "followup_task"):
                    desc += (
                        "\n\nIMPORTANT — GATEWAY LIMITATION: the `message` body cannot "
                        "be delivered through this third-party gateway (it travels as "
                        "an encrypted payload that only OpenAI's servers can produce), "
                        "so the target agent sees an empty payload. Prefer "
                        "spawn_agent with fork_turns=\"all\" over these two tools.")

                sub_tt = sub.get("type") or "function"
                if sub_tt == "custom":
                    # 自由文本子工具，同样用单字段 input 包一层
                    desc += ("\n\nIMPORTANT: pass the raw free-form input verbatim in the "
                             "single `input` string parameter.")
                    add_fn(flat, desc,
                           {"type": "object", "properties": {
                               "input": {"type": "string",
                                         "description": "Raw free-form input for this tool."}},
                            "required": ["input"]}, strict=False)
                    kinds[flat] = "custom"
                else:
                    add_fn(flat, desc,
                           sub.get("parameters") or sub.get("input_schema"),
                           sub.get("strict"))
                    kinds[flat] = "function"
                nsmap[flat] = (ns, sn)

        elif tt == WEB_SEARCH_TOOL:
            # Codex 的 hosted 联网搜索。上游没有这个能力，降级成本地代理执行的函数：
            # 模型发出调用 -> 桥接真去搜 -> 结果回灌 -> 再问一轮。
            add_fn(WEB_SEARCH_TOOL,
                   "Search the live web and return ranked result snippets. Use this "
                   "whenever the answer depends on current facts, news, prices, "
                   "releases or anything you are not certain about. You may call it "
                   "multiple times with different queries.",
                   {"type": "object", "properties": {
                       "query": {"type": "string",
                                 "description": "The search query. Be specific; "
                                                "include dates or product names when relevant."}},
                    "required": ["query"]})
            kinds[WEB_SEARCH_TOOL] = "function"

        else:
            # image_generation / computer_use / mcp(非 namespace) ...
            dropped.append(t.get("name") or (tt or "unknown"))

    return out, kinds, dropped, nsmap


def to_chat_body(req: dict):
    tools, kinds, dropped, nsmap = to_chat_tools(req.get("tools"))
    body = {
        "model": req.get("model"),
        "messages": to_chat_messages(req),
        "stream": True,
        # 没有这个字段时，部分 Chat Completions 网关不会在 SSE 尾部返回 usage。
        "stream_options": {"include_usage": True},
    }
    # workbuddy2api 的 session_sticky 会优先读取 conversation_id / prompt_cache_key。
    # Responses 客户端有时会提供这些字段；只复制稳定会话标识，避免把任意 metadata
    # 原样带到上游。若客户端只有 prompt_cache_key，则映射到现有网关识别的
    # metadata.conversation_id，避免同一缓存会话在多个账号之间轮换。
    sticky_metadata = {}
    raw_metadata = req.get("metadata")
    if isinstance(raw_metadata, dict):
        for name in ("conversation_id", "conversationId"):
            value = raw_metadata.get(name)
            if isinstance(value, str) and value.strip():
                sticky_metadata[name] = value.strip()[:256]
    for name in ("conversation_id", "conversationId"):
        value = req.get(name)
        if isinstance(value, str) and value.strip() and name not in sticky_metadata:
            sticky_metadata[name] = value.strip()[:256]
    prompt_cache_key = req.get("prompt_cache_key")
    if isinstance(prompt_cache_key, str) and prompt_cache_key.strip():
        prompt_cache_key = prompt_cache_key.strip()[:256]
        body["prompt_cache_key"] = prompt_cache_key
        if not sticky_metadata:
            sticky_metadata["conversation_id"] = prompt_cache_key
    if sticky_metadata:
        body["metadata"] = sticky_metadata
    if tools:
        body["tools"] = tools
        tc = req.get("tool_choice")
        if isinstance(tc, dict):
            if tc.get("type") == "function":
                # tool_choice 若指名 namespace 子工具，也要换成拍平名
                nm = tc.get("name") or ""
                ns = tc.get("namespace")
                if ns:
                    nm = flat_name(ns, nm)
                body["tool_choice"] = {"type": "function",
                                       "function": {"name": nm}}
            else:
                body["tool_choice"] = "auto"
        elif isinstance(tc, str):
            body["tool_choice"] = tc
        if isinstance(req.get("parallel_tool_calls"), bool):
            body["parallel_tool_calls"] = req["parallel_tool_calls"]
    mt = req.get("max_output_tokens")
    if isinstance(mt, int) and mt > 0:
        body["max_tokens"] = mt
    tp = req.get("temperature")
    if isinstance(tp, (int, float)):
        body["temperature"] = tp
    return body, kinds, dropped, nsmap


# ---------------------------------------------------- 响应：Chat -> Responses

class Translator:
    """把上游 chat 流翻译成 Responses 事件序列。"""

    def __init__(self, model: str, kinds: dict, nsmap: dict = None):
        self.model = model
        self.kinds = kinds
        self.nsmap = nsmap or {}   # 拍平名 -> (namespace, 原子工具名)
        self.seq = 0
        self.out = []          # 已完成的 output item
        self.n = 0             # output_index 游标
        self.msg_id = None     # 当前文本消息 item id
        self.msg_open = False  # 是否已发过 output_item.added
        self.msg_text = ""
        self.calls = {}        # 上游 tool_call index -> 状态
        self.usage = None
        self.rid = _id("resp_")

    # ---- 底层：产出 SSE 字节
    def ev(self, obj: dict) -> bytes:
        obj.setdefault("sequence_number", self.seq)
        self.seq += 1
        return ("event: %s\ndata: %s\n\n" % (
            obj["type"], json.dumps(obj, ensure_ascii=False))).encode()

    def _resp_obj(self, status, output=None):
        r = {
            "id": self.rid, "object": "response", "created_at": int(time.time()),
            "status": status, "error": None, "incomplete_details": None,
            "instructions": None, "max_output_tokens": None, "max_tool_calls": None,
            "model": self.model, "output": output if output is not None else [],
            "parallel_tool_calls": True, "previous_response_id": None,
            "prompt_cache_key": None, "reasoning": {"effort": None, "summary": None},
            "safety_identifier": None, "service_tier": "default", "store": False,
            "temperature": 1.0, "text": {"format": {"type": "text"}, "verbosity": "medium"},
            "tool_choice": "auto", "tools": [], "top_logprobs": 0, "top_p": 1.0,
            "truncation": "disabled", "usage": None, "user": None, "metadata": {},
        }
        if status == "completed":
            r["usage"] = self.usage or {
                "input_tokens": 0, "input_tokens_details": {"cached_tokens": 0},
                "output_tokens": 0, "output_tokens_details": {"reasoning_tokens": 0},
                "total_tokens": 0}
        return r

    def start(self):
        yield self.ev({"type": "response.created", "response": self._resp_obj("in_progress")})
        yield self.ev({"type": "response.in_progress", "response": self._resp_obj("in_progress")})

    # ---- 文本消息
    def _ensure_msg(self):
        if self.msg_id is None:
            self.msg_id = _id("msg_")
        if not self.msg_open:
            self.msg_open = True
            yield self.ev({"type": "response.output_item.added", "output_index": self.n,
                           "item": {"id": self.msg_id, "type": "message", "status": "in_progress",
                                    "role": "assistant", "content": []}})
            yield self.ev({"type": "response.content_part.added", "item_id": self.msg_id,
                           "output_index": self.n, "content_index": 0,
                           "part": {"type": "output_text", "text": "", "annotations": [],
                                    "logprobs": []}})

    def text(self, delta: str):
        if not delta:
            return
        for b in self._ensure_msg():
            yield b
        self.msg_text += delta
        yield self.ev({"type": "response.output_text.delta", "item_id": self.msg_id,
                       "output_index": self.n, "content_index": 0, "delta": delta,
                       "logprobs": []})

    def close_msg(self):
        if not self.msg_open:
            return
        self.msg_open = False
        item = {"id": self.msg_id, "type": "message", "status": "completed",
                "role": "assistant",
                "content": [{"type": "output_text", "text": self.msg_text,
                             "annotations": [], "logprobs": []}]}
        yield self.ev({"type": "response.output_text.done", "item_id": self.msg_id,
                       "output_index": self.n, "content_index": 0, "text": self.msg_text,
                       "logprobs": []})
        yield self.ev({"type": "response.content_part.done", "item_id": self.msg_id,
                       "output_index": self.n, "content_index": 0,
                       "part": {"type": "output_text", "text": self.msg_text,
                                "annotations": [], "logprobs": []}})
        yield self.ev({"type": "response.output_item.done", "output_index": self.n, "item": item})
        self.out.append(item)
        self.n += 1
        # 收尾后清空，后续若再有正文必须另起一个新的 message item，
        # 否则会复用同一个 item id 却带着新的 output_index。
        self.msg_id = None
        self.msg_text = ""

    # ---- 工具调用
    def _call_slot(self, idx):
        if idx not in self.calls:
            self.calls[idx] = {"item_id": _id("fc_"), "call_id": None, "name": None,
                               "args": "", "open": False, "kind": "function",
                               "out_index": None, "emitted_args": False}
        return self.calls[idx]

    def tool_delta(self, idx, call_id=None, name=None, args=None):
        buf = b""
        if self.msg_open and idx not in self.calls:
            # 正文消息必须先收尾：否则它会和紧随的工具调用抢同一个 output_index，
            # 而 output_item.done 又会晚于工具调用发出，顺序就乱了。
            for b in self.close_msg():
                buf += b
        st = self._call_slot(idx)
        if call_id:
            st["call_id"] = call_id
        if name:
            st["name"] = (st["name"] or "") + name
        if st["call_id"] is None:
            st["call_id"] = _id("call_")
        kind = self.kinds.get(st["name"] or "", "function")
        st["kind"] = kind

        if not st["open"]:
            st["open"] = True
            st["out_index"] = self.n
            self.n += 1
            item = self._item(st, "in_progress")
            buf += self.ev({"type": "response.output_item.added",
                            "output_index": st["out_index"], "item": item})
        if args:
            st["args"] += args
            st["emitted_args"] = True
            if st["kind"] == "custom":
                buf += self.ev({"type": "response.custom_tool_call_input.delta",
                                "item_id": st["item_id"], "output_index": st["out_index"],
                                "delta": args})
            else:
                buf += self.ev({"type": "response.function_call_arguments.delta",
                                "item_id": st["item_id"], "output_index": st["out_index"],
                                "delta": args})
        return buf

    @staticmethod
    def _custom_input(st):
        """custom 工具的回程还原。

        模型看到的是被包成 {"input": "..."} 的 JSON，这里要把里面的原文取出来，
        否则 Codex 拿到的是转义过的 JSON 字符串而不是可执行的源码。
        """
        raw = st["args"] or ""
        try:
            a = json.loads(raw)
        except Exception:
            return raw
        if isinstance(a, str):
            return a
        if isinstance(a, dict):
            for k in ("input", "code", "source", "script", "text"):
                v = a.get(k)
                if isinstance(v, str):
                    return v
            if len(a) == 1:
                v = list(a.values())[0]
                if isinstance(v, str):
                    return v
        return raw

    def _item(self, st, status):
        """按原始工具类型产出对应的 Responses item。"""
        if st["kind"] == "local_shell":
            act = {"type": "exec", "command": [], "timeout_ms": None,
                   "env": None, "working_directory": None}
            try:
                a = json.loads(st["args"] or "{}")
                if isinstance(a, dict):
                    if isinstance(a.get("command"), list):
                        act["command"] = a["command"]
                    elif isinstance(a.get("command"), str):
                        act["command"] = [a["command"]]
                    if a.get("timeout_ms") is not None:
                        act["timeout_ms"] = a["timeout_ms"]
                    if a.get("working_directory"):
                        act["working_directory"] = a["working_directory"]
            except Exception:
                pass
            return {"id": st["item_id"], "type": "local_shell_call", "status": status,
                    "call_id": st["call_id"], "action": act}
        if st["kind"] == "custom":
            return {"id": st["item_id"], "type": "custom_tool_call", "status": status,
                    "call_id": st["call_id"], "name": st["name"],
                    "input": self._custom_input(st)}
        nm = st["name"] or ""
        item = {"id": st["item_id"], "type": "function_call", "status": status,
                "call_id": st["call_id"], "name": nm, "arguments": st["args"]}
        ns = self.nsmap.get(nm)
        if ns:
            # 命名空间工具：Codex 期望 name=子工具、namespace=命名空间
            # （历史会话里官方后端返回的就是这个形状），拍平名不能泄漏给它。
            item["name"] = ns[1]
            item["namespace"] = ns[0]
        return item

    def close_calls(self):
        for idx in sorted(self.calls):
            st = self.calls[idx]
            if not st["open"]:
                continue
            if st["kind"] == "custom":
                yield self.ev({"type": "response.custom_tool_call_input.done",
                               "item_id": st["item_id"], "output_index": st["out_index"],
                               "input": self._custom_input(st)})
            elif st["kind"] == "function":
                yield self.ev({"type": "response.function_call_arguments.done",
                               "item_id": st["item_id"], "output_index": st["out_index"],
                               "arguments": st["args"]})
            item = self._item(st, "completed")
            yield self.ev({"type": "response.output_item.done",
                           "output_index": st["out_index"], "item": item})
            self.out.append(item)
            st["open"] = False

    def finish(self):
        for b in self.close_msg():
            yield b
        for b in self.close_calls():
            yield b
        yield self.ev({"type": "response.completed",
                       "response": self._resp_obj("completed", self.out)})

    def failed(self, message: str, code: str = "upstream_error"):
        for b in self.close_msg():
            yield b
        for b in self.close_calls():
            yield b
        r = self._resp_obj("failed")
        r["error"] = {"code": code, "message": message}
        yield self.ev({"type": "response.failed", "response": r})


def translate_chunk(t: Translator, chunk: dict):
    """处理一条上游 chat completion chunk。"""
    if isinstance(chunk.get("usage"), dict):
        u = chunk["usage"]
        t.usage = {
            "input_tokens": u.get("prompt_tokens", 0),
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens": u.get("completion_tokens", 0),
            "output_tokens_details": {"reasoning_tokens": 0},
            "total_tokens": u.get("total_tokens", 0)}
    for ch in chunk.get("choices") or []:
        d = ch.get("delta") or {}
        rc = d.get("reasoning_content") or d.get("reasoning")
        if isinstance(rc, str) and rc:
            pass  # 推理内容暂不外发（Responses 的 reasoning item 结构复杂，易断流）
        c = d.get("content")
        if isinstance(c, str) and c:
            for b in t.text(c):
                yield b
        elif isinstance(c, list):
            txt = content_to_text(c)
            if txt:
                for b in t.text(txt):
                    yield b
        for tc in d.get("tool_calls") or []:
            if not isinstance(tc, dict):
                continue
            idx = tc.get("index")
            if idx is None:
                idx = 0
            fn = tc.get("function") or {}
            b = t.tool_delta(idx, tc.get("id"), fn.get("name"), fn.get("arguments"))
            if b:
                yield b


# ------------------------------------------------------------ 联网搜索代执行
#
# Codex 的联网搜索是 OpenAI 服务端的 hosted 工具（{"type":"web_search"}），
# 上游 chat 后端没有这个概念。桥接的做法是把它降级成一个普通函数，
# 模型发出调用后由桥接**真实地**去搜，再把结果回灌给模型。
# 这样 Codex 侧看到的仍然是一次普通的工具调用循环，无需伪造任何 item。

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# 完整的浏览器头。实测对 Bing 的结果没有影响（它照样返回泛化结果），
# 但对 360 这类有基础反爬的引擎是必需的，所以统一带上。
BROWSER_HEADERS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Accept-Encoding": "gzip, deflate",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
}


def _http_get(url, timeout=WEB_SEARCH_TIMEOUT):
    req = urllib.request.Request(url, headers=dict(BROWSER_HEADERS))
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        raw = r.read(1500000)
        if "gzip" in (r.headers.get("Content-Encoding") or "").lower():
            try:
                raw = gzip.decompress(raw)
            except Exception:
                pass
        return raw.decode("utf-8", "replace")


def _validate_fetch_url(url: str) -> str:
    """校验并规范 webfetch 目标，拒绝 SSRF 常见目标。"""
    try:
        p = urllib.parse.urlsplit((url or "").strip())
        port = p.port
    except ValueError as e:
        raise ValueError("invalid URL: %s" % e)
    if p.scheme.lower() not in ("http", "https"):
        raise ValueError("only http and https URLs are allowed")
    if not p.hostname:
        raise ValueError("URL has no hostname")
    if p.username or p.password:
        raise ValueError("URL credentials are not allowed")
    if port is not None and port not in WEB_FETCH_ALLOWED_PORTS:
        raise ValueError("only ports 80 and 443 are allowed")
    host = p.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        raise ValueError("local hostnames are not allowed")

    def reject_ip(value):
        # is_global excludes loopback, link-local, RFC1918, documentation,
        # multicast, unspecified and other non-public ranges.
        if not value.is_global:
            raise ValueError("private or non-global address is not allowed")

    try:
        reject_ip(ipaddress.ip_address(host))
    except ValueError as direct:
        # Domain names need a DNS check as well; a domain resolving to even one
        # private address is rejected to reduce DNS-rebinding/SSRF risk.
        try:
            infos = socket.getaddrinfo(host, port or (443 if p.scheme.lower() == "https" else 80),
                                       type=socket.SOCK_STREAM)
        except OSError as e:
            raise ValueError("hostname could not be resolved: %s" % e)
        addresses = {info[4][0].split("%", 1)[0] for info in infos
                     if info and len(info) > 4 and info[4]}
        if not addresses:
            raise ValueError("hostname has no address")
        for address in addresses:
            try:
                reject_ip(ipaddress.ip_address(address))
            except ValueError as e:
                raise ValueError("hostname resolves to a non-public address: %s" % e)
    return p.geturl()


class _SafeFetchRedirectHandler(urllib.request.HTTPRedirectHandler):
    max_redirections = WEB_FETCH_MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urljoin(req.full_url, newurl)
        _validate_fetch_url(target)
        return super().redirect_request(req, fp, code, msg, headers, target)


def _read_limited(resp, limit: int):
    """读取最多 limit+1 字节，避免 chunked 响应绕过 Content-Length 限制。"""
    chunks = []
    total = 0
    while total <= limit:
        block = resp.read(min(65536, limit + 1 - total))
        if not block:
            break
        chunks.append(block)
        total += len(block)
        if total > limit:
            return b"".join(chunks[:]), True
    return b"".join(chunks), False


def _http_fetch(url: str, timeout=WEB_FETCH_TIMEOUT,
                max_bytes=WEB_FETCH_MAX_BYTES):
    """抓取一个经过公网校验的页面，返回 (final_url, content_type, bytes, truncated)。"""
    target = _validate_fetch_url(url)
    headers = dict(BROWSER_HEADERS)
    # 不主动请求 gzip，避免压缩炸弹；若站点强行返回 gzip，下面仍会解压并限长。
    headers["Accept-Encoding"] = "identity"
    headers["Accept"] = "text/html,application/xhtml+xml,text/plain,application/json," \
                         "application/xml;q=0.9,*/*;q=0.1"
    req = urllib.request.Request(target, headers=headers)
    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(
        _SafeFetchRedirectHandler(), urllib.request.HTTPSHandler(context=ctx))
    with opener.open(req, timeout=timeout) as r:
        final_url = _validate_fetch_url(r.geturl())
        content_type = (r.headers.get("Content-Type") or "").strip()
        length = r.headers.get("Content-Length")
        try:
            if length is not None and int(length) > max_bytes * 4:
                raise ValueError("response is larger than %d bytes" % max_bytes)
        except ValueError as e:
            if str(e).startswith("response is larger"):
                raise
        raw, truncated = _read_limited(r, max_bytes)
        encoding = (r.headers.get("Content-Encoding") or "").lower()
        if "gzip" in encoding:
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
                    raw, gzip_truncated = _read_limited(gz, max_bytes)
                truncated = truncated or gzip_truncated
            except (OSError, EOFError) as e:
                raise ValueError("invalid gzip response: %s" % e)
        return final_url, content_type, raw, truncated


class _ReadableHTMLParser(HTMLParser):
    """只保留正文文字，去掉脚本/样式等不可读节点。"""
    _SKIP = frozenset(("script", "style", "noscript", "template", "svg", "canvas"))
    _BLOCK = frozenset(("address", "article", "aside", "blockquote", "br", "dd",
                        "div", "dl", "dt", "figcaption", "figure", "footer",
                        "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr",
                        "li", "main", "nav", "ol", "p", "pre", "section",
                        "table", "td", "th", "tr", "ul"))

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.title_parts = []
        self.skip_depth = 0
        self.in_title = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in self._SKIP:
            self.skip_depth += 1
            return
        if self.skip_depth:
            return
        if tag == "title":
            self.in_title += 1
        if tag in self._BLOCK:
            self.parts.append("\n")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in self._SKIP and self.skip_depth:
            self.skip_depth -= 1
            return
        if self.skip_depth:
            return
        if tag == "title" and self.in_title:
            self.in_title -= 1
        if tag in self._BLOCK:
            self.parts.append("\n")

    def handle_data(self, data):
        if self.skip_depth:
            return
        if self.in_title:
            self.title_parts.append(data)
            return
        self.parts.append(data)


def _readable_html(raw: str):
    parser = _ReadableHTMLParser()
    try:
        parser.feed(raw)
        parser.close()
    except Exception:
        # HTML 容错失败时，退回已有的标准库正则清洗器，仍不把原始标签交给模型。
        return "", _strip_tags(raw)
    title = re.sub(r"\s+", " ", " ".join(parser.title_parts)).strip()
    text = "\n".join(re.sub(r"[ \t\f\v]+", " ", line).strip()
                        for line in "".join(parser.parts).splitlines())
    text = re.sub(r"\n{3,}", "\n\n", text)
    return title, text.strip()


def _decode_fetch_body(raw: bytes, content_type: str):
    charset = None
    m = re.search(r"charset\s*=\s*[\"']?\s*([A-Za-z0-9._-]+)",
                  content_type or "", flags=re.I)
    if m:
        charset = m.group(1)
    for enc in (charset, "utf-8", "gb18030"):
        if not enc:
            continue
        try:
            return raw.decode(enc, "replace")
        except (LookupError, UnicodeError):
            continue
    return raw.decode("utf-8", "replace")


def _redact_fetch_url(url: str) -> str:
    try:
        p = urllib.parse.urlsplit(url)
        host = p.hostname or ""
        if ":" in host and not host.startswith("["):
            host = "[%s]" % host
        netloc = host
        if p.port is not None:
            netloc += ":%d" % p.port
        return p._replace(netloc=netloc, query="", fragment="").geturl()
    except Exception:
        return (url or "")[:300]


def do_web_fetch(url: str) -> str:
    """抓取并清洗单个公网页面，返回适合回灌模型的有限长度文本。"""
    target = (url or "").strip()
    if not target:
        return "[web_fetch error] empty URL"
    try:
        final_url, content_type, raw, truncated = _http_fetch(target)
        ctype = (content_type or "").lower()
        if any(x in ctype for x in ("image/", "audio/", "video/", "application/pdf",
                                    "application/zip", "application/octet-stream")):
            return "[web_fetch unsupported] binary content is not readable (%s)" % (
                content_type or "unknown content type")
        decoded = _decode_fetch_body(raw, content_type)
        if "html" in ctype or re.match(r"\s*<!doctype\s+html|\s*<html[ >]", decoded,
                                        flags=re.I):
            title, text = _readable_html(decoded)
        else:
            title, text = "", re.sub(r"\n{3,}", "\n\n", decoded).strip()
        if not text:
            return "[web_fetch empty] no readable text at %s" % _redact_fetch_url(final_url)
        clipped = len(text) > WEB_FETCH_MAX_CHARS
        if clipped:
            text = text[:WEB_FETCH_MAX_CHARS].rstrip()
        lines = ["Fetched: %s" % _redact_fetch_url(final_url)]
        if title:
            lines.append("Title: %s" % title[:300])
        lines.append("Content-Type: %s" % (content_type or "unknown"))
        if truncated or clipped:
            lines.append("[content truncated for safety]")
        lines.extend(("", text))
        return "\n".join(lines)
    except urllib.error.HTTPError as e:
        return "[web_fetch http_error] %s %s" % (e.code, (e.reason or "")[:200])
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        return "[web_fetch error] %s" % str(e)[:500]
    except Exception as e:
        return "[web_fetch error] %r" % (e,)


def _strip_tags(s: str) -> str:
    s = re.sub(r"<script.*?</script>", " ", s, flags=re.S | re.I)
    s = re.sub(r"<style.*?</style>", " ", s, flags=re.S | re.I)
    # 块级闭合标签换成空格，避免 "Python</strong>.org" 被粘成 "Python.org" 之外
    # 还出现 "Python .org" 这类怪空格（HTML 版结果里踩过）
    s = re.sub(r"</?(?:br|p|div|li|ul|ol|h[1-6]|tr|td|table|span|strong|b|em)[^>]*>",
               " ", s, flags=re.I)
    s = re.sub(r"<[^>]+>", "", s, flags=re.S)
    return re.sub(r"\s+", " ", html_mod.unescape(s)).strip()


def _unwrap_bing(url: str) -> str:
    """Bing 有时把结果 URL 包成 /ck/a?...&u=a1<base64url>，这里还原。"""
    m = re.search(r"[?&]u=a1([A-Za-z0-9_\-]+)", url or "")
    if not m:
        return url
    s = m.group(1)
    s += "=" * (-len(s) % 4)
    try:
        import base64 as _b64
        return _b64.urlsafe_b64decode(s).decode("utf-8", "replace") or url
    except Exception:
        return url


def _mostly_ascii(q: str) -> bool:
    """英文技术查询走 ensearch=1 更准；中文查询不能带，否则结果会跑偏。"""
    if not q:
        return False
    return sum(1 for c in q if ord(c) < 128) / len(q) > 0.85


def _search_360(q):
    """360 搜索（so.com）—— 中文查询唯一实测可用的引擎。

    Bing 对中文长查询会退化成"按首字给泛化结果"：查「微信小游戏 云开发 价格」
    返回的是微信官网、百度百科「微」字条、微博首页；换 header、先取 cookie、
    加 mkt 参数全部无效（本机与 VPS 表现一致）。360 返回的则是
    「微信小游戏的开发费用 - 阿里云开发者社区」这类真正命中的结果。

    结果块的 data-mdurl 就是目标站点真实地址，无需跟随 so.com/link 跳转。
    """
    doc = _http_get("https://www.so.com/s?q=%s" % urllib.parse.quote(q))
    out = []
    for blk in re.split(r'<li[^>]*class="[^"]*res-list[^"]*"', doc)[1:22]:
        a = re.search(r'<a[^>]*data-mdurl="([^"]+)"[^>]*>(.*?)</a>', blk, re.S)
        if not a:
            continue
        url = html_mod.unescape(a.group(1))
        title = _strip_tags(a.group(2))
        if not title:
            continue
        sn = re.search(r'<span class="res-list-summary">(.*?)</span>', blk, re.S)
        out.append((title, url, _strip_tags(sn.group(1)) if sn else ""))
    if not out:
        raise RuntimeError("360: no results parsed (%d bytes)" % len(doc))
    return out, "360"


def _search_bing(q):
    """Bing 网页结果页。

    ⚠️ 顺序踩过坑：一开始以为 `&format=rss` 更稳（结构化、好解析），结果实测
    本机和 VPS 都返回**与查询完全无关**的缓存垃圾（查 "OpenAI Responses API"
    返回韩国游戏道具站）。那个 RSS 端点像是废弃后留着的兜底池。
    网页版 b_algo 块反而是正常结果，所以以它为主。
    """
    url = "https://www.bing.com/search?q=%s&count=15" % urllib.parse.quote(q)
    if _mostly_ascii(q):
        url += "&ensearch=1"      # 英文技术查询走英文结果更准
    doc = _http_get(url)
    out = []
    for blk in re.split(r'<li class="b_algo"', doc)[1:14]:
        blk = blk.split('<li class="b_algo"')[0]
        a = re.search(r'<h2[^>]*>\s*<a[^>]+href="(https?://[^"]+)"[^>]*>(.*?)</a>',
                      blk, re.S)
        if not a:
            continue
        url_i = html_mod.unescape(a.group(1))   # HTML 里是 &amp;u=a1... 先还原实体
        title = _strip_tags(a.group(2))
        sn = re.search(r"<p[^>]*>(.*?)</p>", blk, re.S)
        out.append((title, _unwrap_bing(url_i), _strip_tags(sn.group(1)) if sn else ""))
    if not out:
        raise RuntimeError("bing html: no results parsed (%d bytes)" % len(doc))
    return out, "bing"


def _search_ddg(q):
    doc = _http_get("https://lite.duckduckgo.com/lite/?q=%s"
                    % urllib.parse.quote(q))
    links = re.findall(r'<a[^>]+class=["\']result-link["\'][^>]*href=["\']([^"\']+)["\']'
                       r'[^>]*>(.*?)</a>', doc, re.S)
    snips = re.findall(r'class=["\']result-snippet["\'][^>]*>(.*?)</td>', doc, re.S)
    out = []
    for i, (url, title) in enumerate(links[:12]):
        out.append((_strip_tags(title), html_mod.unescape(url),
                    _strip_tags(snips[i]) if i < len(snips) else ""))
    if not out:
        raise RuntimeError("ddg: no results parsed (%d bytes)" % len(doc))
    return out, "duckduckgo"


def _http_post_json(url, payload, headers=None, timeout=WEB_SEARCH_TIMEOUT):
    """POST 一个 JSON 体，返回 dict。商用搜索 API 都走这个形态。"""
    import urllib.request as _u
    req = _u.Request(url, data=json.dumps(payload).encode(), method="POST",
                     headers={"Content-Type": "application/json",
                              "Accept": "application/json",
                              "User-Agent": "responses-bridge/%s" % VERSION,
                              **(headers or {})})
    ctx = ssl.create_default_context()
    with _u.urlopen(req, timeout=timeout, context=ctx) as r:
        return json.loads(r.read(400000).decode("utf-8", "replace"))


def _env(name):
    return (os.environ.get(name) or "").strip()


def _search_tavily(q):
    """Tavily：专为 agent 设计的搜索 API，返回已清洗的正文摘要，质量远高于抓 HTML。

    国内 VPS 实测可达（不带 key 时 401，约 1.1s）。免费额度每月 1000 次。
    """
    key = _env("TAVILY_API_KEY")
    if not key:
        raise RuntimeError("tavily: no TAVILY_API_KEY configured")
    d = _http_post_json("https://api.tavily.com/search", {
        "api_key": key, "query": q, "max_results": 8,
        "search_depth": "basic", "include_answer": True})
    rows = [(r.get("title") or "", r.get("url") or "",
             (r.get("content") or "").strip())
            for r in d.get("results") or [] if r.get("url")]
    if not rows:
        raise RuntimeError("tavily: empty results")
    out = []
    ans = (d.get("answer") or "").strip()
    if ans:
        out.append(("直接答案", "（由 Tavily 汇总）", ans))
    out.extend(rows)
    return out, "tavily"


def _search_serper(q):
    """Serper：Google 结果的结构化 API。国内 VPS 实测可达（缺 key 时 403）。
    注册送 2500 次免费额度。"""
    key = _env("SERPER_API_KEY")
    if not key:
        raise RuntimeError("serper: no SERPER_API_KEY configured")
    d = _http_post_json("https://google.serper.dev/search", {"q": q, "num": 10},
                        headers={"X-API-KEY": key})
    rows = [(r.get("title") or "", r.get("link") or "",
             r.get("snippet") or "")
            for r in d.get("organic") or [] if r.get("link")]
    if not rows:
        raise RuntimeError("serper: empty results")
    return rows, "serper"


def _query_tokens(q):
    """把查询拆成可匹配的词：英文整词 + 中文 2-gram。

    不取整段中文（"微信小游戏"整段在结果标题里几乎不会出现，只会误判为不相关）。
    """
    toks = set()
    for w in re.findall(r"[A-Za-z0-9]{2,}", q or ""):
        toks.add(w.lower())
    for run in re.findall(r"[\u4e00-\u9fff]{2,}", q or ""):
        for i in range(len(run) - 1):
            toks.add(run[i:i + 2])
    return sorted(toks)


def _relevance(rows, q):
    """结果集与查询的相关度（0~1）。

    免费搜索引擎被风控时会**照常返回 200 和一堆结果**，只是内容与查询无关
    （实测 360 被封后回落 Bing，查"微信小游戏 云开发 价格"返回微信官网和
    百度百科"微"字条目）。这种结果比"搜不到"更糟 —— 模型会拿它编造答案。
    所以每个后端返回后都要过这一关。
    """
    toks = _query_tokens(q)
    if not toks or len(rows) < 3:
        return 1.0
    blob = " ".join(((t or "") + " " + (s or "")) for t, _u, s in rows).lower()
    hit = sum(1 for t in toks if t in blob)
    return hit / float(len(toks))


RELEVANCE_MIN = 0.34


def do_web_search(query: str) -> str:
    """执行一次真实搜索，返回给模型看的文本结果。

    后端顺序（按质量排，前面没配 key 就自动跳过）：
      1. Tavily / Serper —— 商用搜索 API，返回干净结构化结果（**优先**）
      2. 360             —— 免费兜底，抓 HTML 解析，中英文都实测可用
      3. Bing / DDG      —— 最后兜底（Bing 只给泛化结果，DDG 国内不通）

    为什么不全用商用 API：它们要 key、要额度。没配 key 时行为与旧版一致，
    不会退化。每个后端重试一次，跨境 TLS 握手偶发超时很常见。
    """
    q = (query or "").strip()
    if not q:
        return "[web_search error] empty query"
    errs = []
    rows = None
    src = ""
    for fn in (_search_tavily, _search_serper, _search_360,
               _search_bing, _search_ddg):
        if fn in (_search_tavily, _search_serper) and not _env(
                "TAVILY_API_KEY" if fn is _search_tavily else "SERPER_API_KEY"):
            continue                      # 没配 key 就别浪费一次超时
        for attempt in (1, 2):
            try:
                rows, src = fn(q)
            except Exception as e:
                errs.append("%s#%d:%r" % (fn.__name__, attempt, e))
                rows = None
                continue
            if not rows:
                continue
            rel = _relevance(rows, q)
            if rel >= RELEVANCE_MIN:
                break
            # 拿到了结果但跟查询无关 —— 多半是反爬页被当成结果解析了。
            # 记下来继续换下一个后端，绝不能把不相干的内容喂给模型。
            errs.append("%s: irrelevant(%.2f) e.g. %s"
                        % (fn.__name__, rel, (rows[0][0] or "")[:40]))
            rows = None
        if rows:
            break
    if not rows:
        return ("[web_search unavailable] no backend returned relevant results "
                "for \"%s\". Failures: %s\n"
                "Do NOT guess an answer from stale memory. Instead use the exec "
                "tool (curl / python) to fetch a specific page, or tell the user "
                "search is currently unavailable."
                % (q, "; ".join(errs) or "none"))

    lines = ['Web search results for "%s" (source: %s, %d hits):'
             % (q, src, len(rows))]
    for i, (title, url, snip) in enumerate(rows, 1):
        lines.append("%d. %s\n   %s\n   %s" % (
            i, (title or "(no title)")[:150], url, (snip or "")[:SNIPPET_MAX]))
    lines.append("")
    lines.append("Cite the URLs above when you use them. If snippets are "
                 "insufficient, search again with a narrower query.")
    return "\n".join(lines)


# ------------------------------------------------- 上游流：缓冲与消息装配

def collect_stream(resp):
    """把一个上游响应完整读成 chunk 列表（用于需要回头看的场合）。"""
    ctype = resp.headers.get("Content-Type") or ""
    chunks = []
    if "text/event-stream" in ctype:
        for raw in resp:
            line = raw.decode("utf-8", "replace").strip()
            if not line or line.startswith(":") or not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if payload == "[DONE]":
                break
            try:
                chunks.append(json.loads(payload))
            except Exception:
                continue
    else:
        data = json.loads(resp.read().decode("utf-8", "replace"))
        chs = data.get("choices") or [{}]
        msg = chs[0].get("message") or {}
        chunks.append({"choices": [{"delta": msg}], "usage": data.get("usage")})
    return chunks


def assemble(chunks):
    """把 chunk 列表拼成 (正文, {tool_call_index: {...}}, usage)。"""
    text = []
    calls = {}
    usage = None
    for c in chunks:
        if isinstance(c.get("usage"), dict):
            usage = c["usage"]
        for ch in c.get("choices") or []:
            d = ch.get("delta") or {}
            ct = d.get("content")
            if isinstance(ct, str):
                text.append(ct)
            elif isinstance(ct, list):
                text.append(content_to_text(ct))
            for tc in d.get("tool_calls") or []:
                if not isinstance(tc, dict):
                    continue
                i = tc.get("index")
                if i is None:
                    i = 0
                st = calls.setdefault(i, {"id": None, "name": "", "args": ""})
                if tc.get("id"):
                    st["id"] = tc["id"]
                fn = tc.get("function") or {}
                if fn.get("name"):
                    st["name"] = (st["name"] or "") + fn["name"]
                if fn.get("arguments"):
                    st["args"] = (st["args"] or "") + fn["arguments"]
    return "".join(text), calls, usage


def strip_calls(chunks, drop_index):
    """从 chunk 流里按 index 摘掉若干 tool_call。

    用于把桥接自己消化掉的 web_search 调用藏干净 —— Codex 的工具表里没有这个
    函数，任何残留都会让它报 unknown tool。
    """
    if not drop_index:
        return chunks
    out = []
    for c in chunks:
        nc = dict(c)
        ncs = []
        for ch in c.get("choices") or []:
            nch = dict(ch)
            d = dict(ch.get("delta") or {})
            tcs = d.get("tool_calls")
            if isinstance(tcs, list):
                d["tool_calls"] = [tc for tc in tcs
                                   if not (isinstance(tc, dict)
                                           and tc.get("index") in drop_index)]
            nch["delta"] = d
            ncs.append(nch)
        nc["choices"] = ncs
        out.append(nc)
    return out


def search_query_from_args(raw: str) -> str:
    """从模型给的 arguments 里取 query。模型偶尔会写坏 JSON，兜底抓引号内容。"""
    try:
        a = json.loads(raw or "{}")
        if isinstance(a, dict):
            for k in ("query", "q", "search_query", "keywords"):
                v = a.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip()
            if len(a) == 1:
                v = list(a.values())[0]
                if isinstance(v, str):
                    return v.strip()
        if isinstance(a, str):
            return a.strip()
    except Exception:
        pass
    # 兜底：模型偶尔写出截断/未闭合的 JSON，这里允许字符串一直到结尾
    m = re.search(r'"(?:query|q)"\s*:\s*"((?:[^"\\]|\\.)*)(?:"|$)', raw or "")
    if m:
        try:
            return json.loads('"%s"' % m.group(1)).strip()
        except Exception:
            return m.group(1).strip()
    return (raw or "").strip()[:300]


def fetch_url_from_args(raw: str) -> str:
    """从 webfetch 参数中提取 URL，兼容 url/uri/link/input 等常见形状。"""
    try:
        value = json.loads(raw or "{}")
    except Exception:
        value = raw or ""

    def walk(node):
        if isinstance(node, str):
            m = re.search(r"https?://[^\s\"'<>]+", node, flags=re.I)
            if m:
                return m.group(0).rstrip(".,;:!?)]}\u3002\uff0c\uff01\uff1f\uff1b\uff1a\u3001\u300b\u300d")
            return ""
        if isinstance(node, dict):
            for key in ("url", "uri", "link", "href", "target", "input"):
                if key in node:
                    found = walk(node.get(key))
                    if found:
                        return found
            for item in node.values():
                found = walk(item)
                if found:
                    return found
            return ""
        if isinstance(node, list):
            for item in node:
                found = walk(item)
                if found:
                    return found
        return ""

    return walk(value)


# ------------------------------------------------------------------ HTTP 服务

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "responses-bridge/" + VERSION
    upstream = DEFAULT_UPSTREAM
    logdir = os.environ.get("BRIDGE_LOG_DIR", "/var/log/responses-bridge")
    verbose = False

    # ---- 基础输出
    def _json(self, code, obj, headers=None):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _retry_after_headers(exc):
        """只透传合法的 Retry-After 秒数，避免把上游任意头带给客户端。"""
        try:
            value = exc.headers.get("Retry-After")
            seconds = max(1, int(value))
        except (AttributeError, TypeError, ValueError):
            return {}
        return {"Retry-After": str(seconds)}

    def _sse_start(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-store")
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

    def _chunk(self, data: bytes):
        if not data:
            return
        self.wfile.write(b"%x\r\n" % len(data) + data + b"\r\n")

    def _chunk_end(self):
        try:
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except Exception:
            pass

    # ---- 落盘
    def _log(self, rec: dict):
        try:
            os.makedirs(self.logdir, mode=0o700, exist_ok=True)
            # 请求日志可能含提示词、代码和业务数据，目录只对服务账号开放。
            # 已存在目录也要收紧，避免早期版本留下的 0755 权限继续暴露。
            try:
                os.chmod(self.logdir, 0o700)
            except OSError:
                pass
            p = os.path.join(self.logdir, "requests.jsonl")
            if os.path.exists(p) and os.path.getsize(p) > LOG_MAX_BYTES:
                os.replace(p, p + ".1")
            with open(p, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            try:
                os.chmod(p, 0o600)
            except OSError:
                pass
        except Exception:
            pass

    def _log_request(self, text: str, req: dict, auth: str):
        """请求落盘。

        ⚠️ 大请求体**不要内联**进 requests.jsonl：一旦超过截断长度，整行 JSON 会在
        字符串中途断掉，`json.loads` 直接失败 —— 于是**同一文件里所有大请求都变成
        无法解析的脏行**，事后统计（模型分布、工具形态）全做不了。2026-09-18 排查
        「经桥接后模型变笨」时就被这个坑挡住过。改成：小请求内联，大请求单独存文件。
        """
        rec = {"ts": time.strftime("%F %T"), "path": self.path,
               "auth_len": len(auth), "model": req.get("model"),
               "stream": req.get("stream"), "raw_len": len(text)}
        if len(text) <= INLINE_BODY_MAX:
            rec["raw"] = text
        else:
            try:
                bd = os.path.join(self.logdir, "bodies")
                os.makedirs(bd, mode=0o700, exist_ok=True)
                try:
                    os.chmod(bd, 0o700)
                except OSError:
                    pass
                fn = time.strftime("%Y%m%dT%H%M%S") + "-" + os.urandom(3).hex() + ".json"
                body_path = os.path.join(bd, fn)
                with open(body_path, "w", encoding="utf-8") as f:
                    f.write(text)
                try:
                    os.chmod(body_path, 0o600)
                except OSError:
                    pass
                rec["body_file"] = "bodies/" + fn
                self._prune_bodies(bd)
            except Exception as e:
                rec["body_err"] = repr(e)
        self._log(rec)

    @staticmethod
    def _prune_bodies(bd: str):
        """只保留最新的 BODY_KEEP 个请求体文件，避免小磁盘被写满。"""
        try:
            ents = sorted(((e.stat().st_mtime, e.path) for e in os.scandir(bd)),
                          reverse=True)
            for _, p in ents[BODY_KEEP:]:
                try:
                    os.unlink(p)
                except OSError:
                    pass
        except Exception:
            pass

    # ---- 路由
    def do_GET(self):
        if self.path.startswith("/healthz"):
            return self._json(200, {"ok": True, "version": VERSION, "upstream": self.upstream})
        if self.path.startswith("/version"):
            return self._json(200, {"version": VERSION})
        self._json(404, {"error": {"message": "not found"}})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        text = raw.decode("utf-8", "replace")
        auth = self.headers.get("Authorization") or ""
        try:
            req = json.loads(text) if text.strip() else {}
        except Exception as e:
            self._log({"ts": time.strftime("%F %T"), "err": "bad json", "raw": text[:20000]})
            return self._json(400, {"error": {"message": "invalid json: %s" % e}})

        self._log_request(text, req, auth)

        if not self.path.startswith("/v1/responses"):
            return self._json(404, {"error": {"message": "unknown path " + self.path}})

        if req.get("previous_response_id"):
            # 无状态转发，历史由 Codex 每次全量带上；这里只是记录，不做处理
            pass

        model = req.get("model") or ""
        try:
            body, kinds, dropped, nsmap = to_chat_body(req)
        except UnsupportedImageError as e:
            return self._json(400, {"error": {
                "message": str(e),
                "type": "invalid_request_error",
                "param": "input",
            }})
        if dropped:
            self._log({"ts": time.strftime("%F %T"), "dropped_tools": dropped,
                       "note": "这些工具在 chat 协议下无法表达，已从上游工具表移除"})
        if self.verbose:
            print("[bridge] -> upstream body: %s" % json.dumps(body, ensure_ascii=False)[:4000],
                  flush=True)

        def open_upstream():
            u = urllib.request.Request(
                self.upstream, data=json.dumps(body, ensure_ascii=False).encode(),
                method="POST",
                headers={"Content-Type": "application/json",
                         "Authorization": auth or "",
                         "Accept": "text/event-stream",
                         "Accept-Encoding": "identity"})
            ctx = ssl.create_default_context()
            return urllib.request.urlopen(u, timeout=900, context=ctx)

        has_ws = any(isinstance(x, dict) and x.get("type") == WEB_SEARCH_TOOL
                     for x in (req.get("tools") or []))
        has_wf = any(web_fetch_decl_name(x) for x in (req.get("tools") or []))
        resp = None
        ctype = ""
        chunks = None
        fatal = None
        rounds = 0
        usage_recorded = False

        if has_ws or has_wf:
            # ---- 本地联网工具路径：先替模型执行搜索/抓取，再交付最终结果。
            msgs = list(body["messages"])
            local_tools_disabled = False
            while True:
                try:
                    resp = open_upstream()
                except urllib.error.HTTPError as e:
                    detail = e.read().decode("utf-8", "replace")
                    self._log({"ts": time.strftime("%F %T"), "upstream_status": e.code,
                               "round": rounds, "upstream_body": detail[:4000]})
                    if rounds == 0:
                        try:
                            msg = json.loads(detail)["error"]
                        except Exception:
                            msg = detail[:800] or str(e)
                        return self._json(e.code, {"error": {"message": msg,
                                                             "type": "upstream_error"}},
                                         self._retry_after_headers(e))
                    fatal = "upstream error during local web tool round %d: HTTP %d %s" % (
                        rounds, e.code, detail[:300])
                    break
                except Exception as e:
                    self._log({"ts": time.strftime("%F %T"), "upstream_err": repr(e),
                               "round": rounds})
                    if rounds == 0:
                        return self._json(502, {"error": {
                            "message": "upstream unreachable: %r" % e}})
                    fatal = "upstream unreachable during local web tool round %d: %r" % (
                        rounds, e)
                    break

                try:
                    chunks = collect_stream(resp)
                except Exception as e:
                    self._log({"ts": time.strftime("%F %T"), "stream_err": repr(e),
                               "round": rounds})
                    fatal = ("upstream stream broken during local web tool round %d: %r"
                             % (rounds, e))
                    chunks = None
                    break

                _txt, calls, _usage = assemble(chunks)
                # 本地工具会触发多次上游请求，每一轮都要计入总 Token。
                if record_token_usage(self.logdir, _usage):
                    usage_recorded = True
                local_calls = [c for c in calls.values()
                               if is_local_web_tool_name(c["name"])]
                others = [c for c in calls.values()
                          if not is_local_web_tool_name(c["name"])]
                # 只在"这一轮纯粹就是联网工具"时接管。混合调用（同时又调 exec 之类）
                # 交给 Codex 自己走，免得把别的工具结果吞掉。
                if local_calls and not others and rounds < max(WEB_SEARCH_MAX_ROUNDS,
                                                               WEB_FETCH_MAX_ROUNDS):
                    rounds += 1
                    msgs.append({
                        "role": "assistant", "content": _txt or None,
                        "tool_calls": [{
                            "id": c["id"] or _id("call_"), "type": "function",
                            "function": {"name": c["name"],
                                         "arguments": c["args"] or "{}"}}
                            for c in calls.values()]})
                    for c in local_calls:
                        if c["name"] == WEB_SEARCH_TOOL:
                            q = search_query_from_args(c["args"] or "")
                            result = do_web_search(q)
                            self._log({"ts": time.strftime("%F %T"), "web_search": q,
                                       "chars": len(result), "round": rounds})
                        else:
                            url = fetch_url_from_args(c["args"] or "")
                            result = do_web_fetch(url)
                            self._log({"ts": time.strftime("%F %T"),
                                       "web_fetch": _redact_fetch_url(url),
                                       "chars": len(result), "round": rounds})
                        msgs.append({"role": "tool",
                                     "tool_call_id": c["id"] or "",
                                     "content": result})
                    body["messages"] = msgs
                    continue
                if local_calls and not others and not local_tools_disabled:
                    # 联网工具预算用尽时不能直接丢调用，摘掉工具再问一轮，
                    # 逼模型用已有结果收尾，避免只输出“我准备去核对”。
                    local_tools_disabled = True
                    self._log({"ts": time.strftime("%F %T"),
                               "note": "联网工具预算用尽，摘掉本地工具让模型收尾"})
                    body["tools"] = [x for x in (body.get("tools") or [])
                                     if not is_local_web_tool_name(
                                         x.get("function", {}).get("name"))]
                    body["messages"] = msgs
                    msgs.append({"role": "system", "content":
                                 "The local web tool budget is exhausted. Answer now "
                                 "using the results already gathered. Do not say you "
                                 "will verify later; state what the sources say and "
                                 "cite the URLs when available."})
                    continue
                break
        else:
            try:
                resp = open_upstream()
            except urllib.error.HTTPError as e:
                detail = e.read().decode("utf-8", "replace")
                self._log({"ts": time.strftime("%F %T"), "upstream_status": e.code,
                           "upstream_body": detail[:4000]})
                try:
                    msg = json.loads(detail)["error"]
                except Exception:
                    msg = detail[:800] or str(e)
                return self._json(e.code, {"error": {"message": msg,
                                                     "type": "upstream_error"}},
                                 self._retry_after_headers(e))
            except Exception as e:
                self._log({"ts": time.strftime("%F %T"), "upstream_err": repr(e)})
                return self._json(502, {"error": {"message": "upstream unreachable: %r" % e}})
            ctype = (resp.headers.get("Content-Type") or "")

        t = Translator(model, kinds, nsmap)
        self.close_connection = True
        self._sse_start()
        try:
            for b in t.start():
                self._chunk(b)

            if fatal:
                for b in t.failed(fatal):
                    self._chunk(b)
            elif chunks is not None:
                # 落到这里说明联网工具轮已结束（或达到上限）。无论哪种情况，
                # 桥接代执行的调用都不能泄漏给 Codex，否则会被当作未知工具。
                _t2, calls2, _u2 = assemble(chunks)
                drop = {i for i, c in calls2.items()
                        if is_local_web_tool_name(c["name"])}
                if drop:
                    self._log({"ts": time.strftime("%F %T"),
                               "note": "残留本地联网工具调用已丢弃（达轮次上限或与其它工具混用）",
                               "dropped_calls": len(drop)})
                for ch in strip_calls(chunks, drop):
                    for b in translate_chunk(t, ch):
                        self._chunk(b)
            elif "text/event-stream" in ctype:
                for bytes_line in resp:
                    line = bytes_line.decode("utf-8", "replace").strip()
                    if not line or line.startswith(":"):
                        continue
                    if not line.startswith("data:"):
                        continue
                    payload = line[5:].strip()
                    if payload == "[DONE]":
                        break
                    try:
                        ch = json.loads(payload)
                    except Exception:
                        continue
                    for b in translate_chunk(t, ch):
                        self._chunk(b)
            else:
                # 上游没按流式返回：把整段回复当成一次输出
                raw_all = resp.read().decode("utf-8", "replace")
                self._log({"ts": time.strftime("%F %T"), "nonstream_body": raw_all[:4000]})
                try:
                    data = json.loads(raw_all)
                    chs = data.get("choices") or [{}]
                    m = chs[0].get("message") or {}
                    if isinstance(m.get("content"), str) and m["content"]:
                        for b in t.text(m["content"]):
                            self._chunk(b)
                    for i, tc in enumerate(m.get("tool_calls") or []):
                        fn = tc.get("function") or {}
                        b = t.tool_delta(i, tc.get("id"), fn.get("name"), fn.get("arguments"))
                        if b:
                            self._chunk(b)
                    if isinstance(data.get("usage"), dict):
                        list(translate_chunk(t, {"usage": data["usage"]}))
                except Exception as e:
                    self._log({"ts": time.strftime("%F %T"), "parse_err": repr(e)})
                    for b in t.failed("upstream returned unparsable body: %r" % e):
                        self._chunk(b)
                    return

            if not usage_recorded:
                record_token_usage(self.logdir, t.usage)
            for b in t.finish():
                self._chunk(b)
        except BrokenPipeError:
            return
        except Exception as e:
            traceback.print_exc()
            try:
                for b in t.failed("bridge internal error: %r" % e):
                    self._chunk(b)
            except Exception:
                pass
        finally:
            self._chunk_end()

    def log_message(self, *a):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--upstream", default=DEFAULT_UPSTREAM)
    ap.add_argument("--logdir", default=os.environ.get("BRIDGE_LOG_DIR", "/var/log/responses-bridge"))
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()

    Handler.upstream = a.upstream
    Handler.logdir = a.logdir
    Handler.verbose = a.verbose
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    print("responses-bridge %s on %s:%d -> %s  (log: %s)"
          % (VERSION, a.host, a.port, a.upstream, a.logdir), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
