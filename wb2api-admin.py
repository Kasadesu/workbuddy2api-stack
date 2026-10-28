#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Administration daemon and management interface for the API gateway stack.

- Binds to 127.0.0.1; public routing and TLS termination are managed by reverse proxy.
- File operations on auth credentials are executed under container UID 10001 via docker exec
  to maintain filesystem permission boundaries with gateway processes.
"""
import json
import hashlib
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError

try:
    from workbuddy_automation import AutomationManager
except ImportError:
    # The admin page is also loaded by offline tests from another cwd.
    _admin_source = globals().get("__file__") or os.path.join(os.getcwd(), "wb2api-admin.py")
    sys.path.insert(0, os.path.dirname(os.path.abspath(_admin_source)))
    from workbuddy_automation import AutomationManager

LISTEN = ("127.0.0.1", int(os.environ.get("ADMIN_PORT", "7864")))
BASE = os.environ.get("WB2A_BASE", "/opt/workbuddy2api")
CFG = os.path.join(BASE, "config.json")
CONTAINER = os.environ.get("WB2A_CONTAINER", "workbuddy2api")
C_AUTH = "/app/auths"
ADMIN_DIR = os.path.join(BASE, "admin")
KEYS_FILE = os.path.join(ADMIN_DIR, "keys.json")
USAGE_HISTORY_FILE = os.path.join(ADMIN_DIR, "usage-history.json")
BRIDGE_LOG_DIR = os.environ.get("BRIDGE_LOG_DIR", "/var/log/responses-bridge")
TOKEN_STATS_FILE = os.environ.get(
    "TOKEN_STATS_FILE", os.path.join(BRIDGE_LOG_DIR, "token-usage.json"))
GATEWAY_TOKEN_STATS_FILE = os.path.join(ADMIN_DIR, "gateway-token-usage.json")
CADDY_FILE = os.environ.get("CADDY_FILE", "/etc/caddy/Caddyfile")
PUBLIC_HOST = os.environ.get("PUBLIC_HOST", "api.example.com")
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "https://api.example.com/v1")
AUTOMATION = AutomationManager(BASE, CONTAINER)

# serialize operations that modify keys.json and Caddyfile
KEY_STATE_LOCK = threading.RLock()
USAGE_HISTORY_LOCK = threading.RLock()
TOKEN_STATS_LOCK = threading.RLock()
ADMIN_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
ADMIN_PASSWORD_MIN = 8
USAGE_HISTORY_LIMIT = 240

# version tag for frontend auto-reload
PAGE_VERSION = "v1.2.0"
RECENT_USAGE_LIMIT = 20

# cache upstream model catalog
MODEL_CACHE_TTL = 300
MODEL_CACHE_LOCK = threading.RLock()
MODEL_CACHE = {"at": 0.0, "data": None}
MODEL_TIMEOUT = 30

# ---------------- Helpers ----------------

def get_api_key():
    try:
        with open(CFG, "r", encoding="utf-8") as f:
            return json.load(f).get("api_key", "")
    except Exception:
        return ""


def dexec(args, stdin_bytes=None, timeout=60, user="10001"):
    """Execute command inside container under specified user."""
    cmd = ["docker", "exec", "-u", user, "-w", "/app"]
    if stdin_bytes is not None:
        cmd.append("-i")
    cmd += [CONTAINER] + list(args)
    try:
        p = subprocess.run(cmd, input=stdin_bytes, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8", "ignore"), p.stderr.decode("utf-8", "ignore")
    except subprocess.TimeoutExpired:
        return 124, "", "docker exec timed out after %ds" % timeout


def docker_host(args, timeout=60):
    """Execute docker command on the host."""
    try:
        p = subprocess.run(["docker"] + list(args), capture_output=True, timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8", "ignore"), p.stderr.decode("utf-8", "ignore")
    except subprocess.TimeoutExpired:
        return 124, "", "docker command timed out after %ds" % timeout


def get_device_token_status():
    """Read device token setting from config or data file (masked for display)."""
    token = ""
    source = ""
    # 1. Check data file first (./data/device_token on host)
    try:
        dt_file = os.path.join(BASE, "data", "device_token")
        if os.path.exists(dt_file):
            with open(dt_file, "r", encoding="utf-8") as f:
                tok = f.read().strip()
                if tok:
                    token = tok
                    source = "data/device_token"
    except Exception:
        pass
    # 2. Check CFG upstream.device_token
    if not token:
        try:
            if os.path.exists(CFG):
                with open(CFG, "r", encoding="utf-8") as f:
                    cfg_data = json.load(f)
                    tok = str((cfg_data.get("upstream") or {}).get("device_token") or "").strip()
                    if tok:
                        token = tok
                        source = "config.json"
        except Exception:
            pass
    # 3. Check environment
    if not token:
        env_tok = os.environ.get("WB2A_DEVICE_TOKEN", "").strip()
        if env_tok:
            token = env_tok
            source = "env:WB2A_DEVICE_TOKEN"
    if not token:
        return {"ok": True, "configured": False, "masked": "", "source": "", "len": 0}
    masked = token[:3] + "*" * max(4, len(token) - 6) + token[-3:] if len(token) >= 8 else "***"
    return {"ok": True, "configured": True, "masked": masked, "source": source, "len": len(token)}


def set_device_token(new_token):
    """Save device token to ./data/device_token and ensure gateway reads it."""
    token = str(new_token or "").strip()
    if token and not re.match(r"^[A-Za-z0-9_\-\.]{10,128}$", token):
        return False, "设备码格式不合法（应为 10-128 位的字母、数字或横线下划线）"
    data_dir = os.path.join(BASE, "data")
    try:
        os.makedirs(data_dir, exist_ok=True)
    except Exception as e:
        return False, "创建 data 目录失败: " + str(e)
    dt_path = os.path.join(data_dir, "device_token")
    try:
        with open(dt_path, "w", encoding="utf-8") as f:
            f.write(token)
        try:
            os.chmod(dt_path, 0o644)
        except Exception:
            pass
    except Exception as e:
        return False, "写入设备码文件失败: " + str(e)

    # Ensure config.json has device_token_file set
    try:
        if os.path.exists(CFG):
            with open(CFG, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            up = cfg.get("upstream")
            if isinstance(up, dict) and not up.get("device_token_file"):
                up["device_token_file"] = "/app/data/device_token"
                cfg["upstream"] = up
                with open(CFG, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

    try:
        docker_host(["restart", CONTAINER], timeout=120)
    except Exception:
        pass
    msg = "设备码已更新，网关已重启生效。" if token else "设备码已清除，网关已重启生效。"
    return True, msg


def _empty_token_stats(source="responses-bridge"):
    return {
        "ok": True,
        "available": False,
        "source": source,
        "updated_at": 0,
        "total_tokens": 0,
        "today_tokens": 0,
        "total_input_tokens": 0,
        "total_output_tokens": 0,
        "today_input_tokens": 0,
        "today_output_tokens": 0,
        "total_requests": 0,
        "today_requests": 0,
    }


def _token_stat_row(raw):
    raw = raw if isinstance(raw, dict) else {}
    input_tokens = _usage_int(raw.get("input_tokens"))
    if input_tokens is None:
        input_tokens = _usage_int(raw.get("prompt_tokens"))
    output_tokens = _usage_int(raw.get("output_tokens"))
    if output_tokens is None:
        output_tokens = _usage_int(raw.get("completion_tokens"))
    input_tokens = input_tokens or 0
    output_tokens = output_tokens or 0
    total_tokens = _usage_int(raw.get("total_tokens"))
    if total_tokens is None:
        total_tokens = input_tokens + output_tokens
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
        "requests": (_usage_int(raw.get("requests")) or
                      _usage_int(raw.get("request_count")) or 0),
    }


def _token_stats_view(data, source, available=True):
    """Format token usage stats dictionary for admin dashboard response."""
    data = data if isinstance(data, dict) else {}
    total = _token_stat_row(data.get("total"))
    day = time.strftime("%Y-%m-%d", time.localtime())
    today = _token_stat_row((data.get("days") or {}).get(day))
    result = _empty_token_stats(source)
    result["available"] = bool(available)
    result["updated_at"] = _usage_int(data.get("updated_at")) or 0
    result["total_tokens"] = total["total_tokens"]
    result["today_tokens"] = today["total_tokens"]
    result["total_input_tokens"] = total["input_tokens"]
    result["total_output_tokens"] = total["output_tokens"]
    result["today_input_tokens"] = today["input_tokens"]
    result["today_output_tokens"] = today["output_tokens"]
    result["total_requests"] = total["requests"]
    result["today_requests"] = today["requests"]
    return result


def _load_token_aggregate(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {}
    days = data.get("days") if isinstance(data.get("days"), dict) else {}
    return {
        "version": 1,
        "updated_at": _usage_int(data.get("updated_at")) or 0,
        "gateway_since": str(data.get("gateway_since") or ""),
        "last": _token_stat_row(data.get("last")),
        "total": _token_stat_row(data.get("total")),
        "days": {str(day): _token_stat_row(row) for day, row in days.items()
                 if isinstance(day, str) and isinstance(row, dict)},
    }


def _save_token_aggregate(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def _gateway_timestamp_day(value):
    """Extract YYYY-MM-DD date prefix from gateway timestamp."""
    text = str(value or "").strip()
    return text[:10] if re.match(r"^\d{4}-\d{2}-\d{2}", text) else ""


def _gateway_token_stats():
    """Aggregate token usage from gateway stats API."""
    stats = _gateway_usage_stats()
    if not isinstance(stats, dict) or not isinstance(stats.get("total"), dict):
        return None
    current = _token_stat_row(stats.get("total"))
    gateway_since = str(stats.get("since") or "")
    now = int(time.time())
    with TOKEN_STATS_LOCK:
        data = _load_token_aggregate(GATEWAY_TOKEN_STATS_FILE)
        day = time.strftime("%Y-%m-%d", time.localtime(now))
        has_saved_state = bool(data["updated_at"] or data["gateway_since"] or
                               any(data["last"].values()))
        if not has_saved_state:
            # count current baseline towards today only if gateway started today
            data["total"] = dict(current)
            if (_gateway_timestamp_day(gateway_since) or
                    _gateway_timestamp_day(stats.get("now"))) == day:
                data["days"][day] = dict(current)
        else:
            previous = data["last"]
            # reset baseline if gateway restarted
            if data["gateway_since"] and gateway_since and data["gateway_since"] != gateway_since:
                previous = _token_stat_row(None)
            delta = {}
            for key in ("input_tokens", "output_tokens", "total_tokens", "requests"):
                value = current[key] - previous[key]
                delta[key] = value if value >= 0 else current[key]
            daily = data["days"].setdefault(day, _token_stat_row(None))
            for key in delta:
                data["total"][key] += delta[key]
                daily[key] += delta[key]
        data["last"] = current
        data["gateway_since"] = gateway_since
        data["updated_at"] = now
        # keep last 90 days of daily stats
        for old_day in sorted(data["days"])[:-90]:
            data["days"].pop(old_day, None)
        try:
            _save_token_aggregate(GATEWAY_TOKEN_STATS_FILE, data)
        except Exception:
            pass
        return _token_stats_view(data, "workbuddy2api", True)


def _bridge_token_stats():
    """Read token stats from responses bridge."""
    empty = _empty_token_stats("responses-bridge")
    try:
        with open(TOKEN_STATS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return empty
        total = data.get("total") if isinstance(data.get("total"), dict) else {}
        days = data.get("days") if isinstance(data.get("days"), dict) else {}
        day = time.strftime("%Y-%m-%d", time.localtime())
        today = days.get(day) if isinstance(days.get(day), dict) else {}
        return _token_stats_view(data, "responses-bridge", True)
    except Exception:
        return empty


def _cached_gateway_token_stats():
    """Return cached gateway stats when live stats endpoint is temporarily unavailable."""
    try:
        data = _load_token_aggregate(GATEWAY_TOKEN_STATS_FILE)
        total = data.get("total") or {}
        if not data.get("updated_at") and not any(total.values()):
            return None
        result = _token_stats_view(data, "workbuddy2api-cache", True)
        result["stale"] = True
        return result
    except Exception:
        return None


def token_stats():
    """Retrieve aggregated token stats from gateway, cached file, or bridge stats."""
    return (_gateway_token_stats() or _cached_gateway_token_stats() or
            _bridge_token_stats())


def gw_status():
    """Fetch gateway /status and /healthz endpoints."""
    out = {}
    key = get_api_key()
    for name, path in (("status", "/status"), ("healthz", "/healthz")):
        try:
            req = Request("http://127.0.0.1:7863" + path,
                          headers={"Authorization": "Bearer " + key})
            with urlopen(req, timeout=10) as r:
                out[name] = json.loads(r.read().decode("utf-8", "ignore"))
        except HTTPError as e:
            out[name] = {"_error": "HTTP %d" % e.code}
        except Exception as e:
            out[name] = {"_error": str(e)}
    return out


def credit_info():
    """Query container credit CLI tool for account balances."""
    rc, out, err = dexec(["/app/credit"], timeout=90)
    if rc != 0:
        return {"ok": False, "error": (err or out).strip()[:300]}
    data = extract_json(out)
    if not data:
        return {"ok": False, "error": "解析积分数据失败：" + out.strip()[:200]}
    record_usage_snapshot(data)
    return {"ok": True, "data": data}


def _load_usage_history_unlocked():
    try:
        with open(USAGE_HISTORY_FILE, "r", encoding="utf-8") as f:
            records = json.load(f)
        return records if isinstance(records, list) else []
    except Exception:
        return []


def _save_usage_history_unlocked(records):
    os.makedirs(ADMIN_DIR, exist_ok=True)
    tmp = USAGE_HISTORY_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(records[-USAGE_HISTORY_LIMIT:], f, ensure_ascii=False, indent=2)
    os.replace(tmp, USAGE_HISTORY_FILE)
    try:
        os.chmod(USAGE_HISTORY_FILE, 0o600)
    except Exception:
        pass


def _usage_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _usage_snapshot(data):
    """Sanitize and persist only non-sensitive account credit balance metrics."""
    total = data.get("total") if isinstance(data, dict) else {}
    total = total if isinstance(total, dict) else {}
    accounts = []
    for raw in (data.get("accounts") or []) if isinstance(data, dict) else []:
        if not isinstance(raw, dict):
            continue
        accounts.append({
            "uid": str(raw.get("uid") or ""),
            "nickname": str(raw.get("nickname") or ""),
            "remain": _usage_int(raw.get("remain")),
            "used": _usage_int(raw.get("used")),
            "size": _usage_int(raw.get("size")),
            "ok": bool(raw.get("ok")),
        })
    return {
        "at": int(time.time()),
        "total": {
            "remain": _usage_int(total.get("remain")),
            "used": _usage_int(total.get("used")),
            "size": _usage_int(total.get("size")),
        },
        "accounts": accounts,
    }


def record_usage_snapshot(data):
    """Record periodic credit balance snapshot, skipping duplicates within 60s."""
    snapshot = _usage_snapshot(data)
    with USAGE_HISTORY_LOCK:
        records = _load_usage_history_unlocked()
        if records:
            last = records[-1]
            if (last.get("total") == snapshot["total"] and
                    last.get("accounts") == snapshot["accounts"] and
                    snapshot["at"] - int(last.get("at") or 0) < 60):
                return records
        records.append(snapshot)
        try:
            _save_usage_history_unlocked(records)
        except Exception:
            # ignore history save failure
            pass
        return records


def _gateway_usage_stats():
    """Read /v1/stats from gateway."""
    key = get_api_key()
    try:
        req = Request("http://127.0.0.1:7863/v1/stats",
                      headers={"Authorization": "Bearer " + key})
        with urlopen(req, timeout=10) as response:
            return json.loads(response.read().decode("utf-8", "ignore"))
    except Exception:
        return None


def _gateway_recent_usage(limit=RECENT_USAGE_LIMIT):
    """Retrieve sanitized recent request summaries from gateway."""
    key = get_api_key()
    try:
        req = Request("http://127.0.0.1:7863/v1/stats/recent",
                      headers={"Authorization": "Bearer " + key})
        with urlopen(req, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8", "ignore"))
        if not isinstance(payload, dict):
            return None
        rows = payload.get("records") if isinstance(payload.get("records"), list) else []
        try:
            limit = max(1, min(int(limit), RECENT_USAGE_LIMIT))
        except (TypeError, ValueError):
            limit = RECENT_USAGE_LIMIT
        return {"enabled": bool(payload.get("enabled")), "records": rows[:limit]}
    except Exception:
        return None


def recent_usage_info(limit=RECENT_USAGE_LIMIT):
    """Return normalized recent request logs ordered chronologically."""
    payload = _gateway_recent_usage(limit)
    if not isinstance(payload, dict):
        return {"ok": False, "source": "workbuddy2api", "records": []}
    records = []
    for raw in payload.get("records") or []:
        if not isinstance(raw, dict):
            continue
        uid = str(raw.get("uid") or raw.get("account_id") or raw.get("account_uid") or "")
        nickname = str(raw.get("nickname") or raw.get("account") or raw.get("name") or uid or "")
        model = str(raw.get("model") or raw.get("model_id") or raw.get("id") or raw.get("name") or "")
        input_tokens = _usage_int(raw.get("input_tokens"))
        if input_tokens is None:
            input_tokens = _usage_int(raw.get("prompt_tokens"))
        output_tokens = _usage_int(raw.get("output_tokens"))
        if output_tokens is None:
            output_tokens = _usage_int(raw.get("completion_tokens"))
        if input_tokens is not None and input_tokens < 0:
            input_tokens = None
        cached_input_tokens = _usage_int(raw.get(
            "cached_input_tokens", raw.get("cache_hit_tokens", raw.get("cached_tokens"))))
        if cached_input_tokens is not None and cached_input_tokens < 0:
            cached_input_tokens = None
        cache_hit_rate = None
        if cached_input_tokens is not None and input_tokens is not None:
            if cached_input_tokens <= input_tokens:
                if input_tokens > 0:
                    cache_hit_rate = cached_input_tokens / input_tokens
            else:
                cached_input_tokens = None
        total_tokens = _usage_int(raw.get("total_tokens"))
        if total_tokens is None and input_tokens is not None and output_tokens is not None:
            total_tokens = input_tokens + output_tokens
        records.append({
            "at": raw.get("at"),
            "uid": uid,
            "nickname": nickname,
            "realm": str(raw.get("realm") or raw.get("domain") or ""),
            "model": model,
            "mode": str(raw.get("mode") or ""),
            "status": _usage_int(raw.get("status")),
            "input_tokens": input_tokens,
            "cached_input_tokens": cached_input_tokens,
            "cache_hit_rate": cache_hit_rate,
            "output_tokens": output_tokens,
            "total_tokens": total_tokens,
            "credits": raw.get("credits", raw.get("credit")),
        })
    return {"ok": True, "source": "workbuddy2api", "records": records,
            "mode": "request", "enabled": bool(payload.get("enabled"))}


def usage_info():
    """Fetch real-time usage metrics and account balance snapshots."""
    credit = credit_info()
    if not credit.get("ok"):
        return {"ok": False, "error": credit.get("error") or "查询积分失败"}
    stats = _gateway_usage_stats()
    if isinstance(stats, dict) and isinstance(stats.get("models"), list):
        recent = recent_usage_info()
        return {"ok": True, "mode": "gateway", "current": credit["data"], "stats": stats,
                "recent": recent.get("records", []) if recent.get("ok") else [],
                "recent_available": bool(recent.get("ok"))}

    with USAGE_HISTORY_LOCK:
        history = _load_usage_history_unlocked()
    flattened = []
    previous = {}
    for snapshot in history:
        at = _usage_int(snapshot.get("at"))
        current = {}
        for account in snapshot.get("accounts") or []:
            uid = str(account.get("uid") or account.get("nickname") or "")
            if not uid:
                continue
            used = _usage_int(account.get("used"))
            before = previous.get(uid)
            delta = None
            if used is not None and before is not None and before["used"] is not None:
                delta = used - before["used"]
            current[uid] = {"used": used}
            flattened.append({
                "at": at,
                "uid": uid,
                "nickname": str(account.get("nickname") or uid),
                "used": used,
                "delta_used": delta,
                "remain": _usage_int(account.get("remain")),
                "size": _usage_int(account.get("size")),
                "ok": bool(account.get("ok")),
            })
        previous = current
    flattened.reverse()
    return {
        "ok": True,
        "mode": "snapshots",
        "current": credit["data"],
        "records": flattened[:120],
        "record_count": len(flattened),
    }


def list_accounts():
    """List accounts under auths/ directory."""
    rc, out, err = dexec(["ls", "-1", C_AUTH])
    if rc != 0:
        return []
    accounts = []
    for name in sorted(out.split()):
        if not name.endswith(".json"):
            continue
        rc2, raw, _ = dexec(["cat", C_AUTH + "/" + name])
        info = {"file": name, "uid": "", "nickname": "", "realm": ""}
        if rc2 == 0 and raw.strip():
            try:
                d = json.loads(raw)
                acct = d.get("account", {}) or {}
                au = d.get("auth", {}) or {}
                info["uid"] = str(acct.get("uid", "") or d.get("uid", ""))
                info["nickname"] = acct.get("nickname", "") or d.get("nickname", "") or ""
                info["realm"] = au.get("realm", "") or d.get("realm", "") or "cn"
            except Exception:
                pass
        accounts.append(info)
    return accounts


def platform_info():
    """Return platform directory without exposing sensitive credentials."""
    try:
        account_count = len(list_accounts())
    except Exception:
        account_count = None
    return {
        "ok": True,
        "brand": "Kasa2API",
        "platforms": [
            {
                "id": "workbuddy",
                "name": "WorkBuddy / CodeBuddy",
                "type": "账号池网关",
                "status": "active",
                "base_url": PUBLIC_BASE_URL,
                "auth": "使用 Kasa2API API Key",
                "usage": "WorkBuddy / CodeBuddy 共享积分和网关用量",
                "account_count": account_count,
                "features": ["Chat Completions", "Responses 桥接", "签到和猫猫旅行"],
            },
        ],
    }


def normalize_model_credits(value):
    """Normalize model credit multiplier strings by stripping trailing units."""
    text = str(value or "").strip()
    return re.sub(r"\s+credits?\s*$", "", text, flags=re.IGNORECASE).strip()


def parse_model_catalog(payload):
    """Parse upstream model catalog, filtering for CLI-enabled models."""
    if not isinstance(payload, dict):
        raise ValueError("模型目录格式无效")
    code = payload.get("code")
    if code not in (None, 0):
        raise ValueError("模型目录返回 code=%s" % code)
    data = payload.get("data") or {}
    if not isinstance(data, dict):
        raise ValueError("模型目录 data 格式无效")
    raw_models = data.get("models") or []
    if not isinstance(raw_models, list):
        raise ValueError("模型目录 models 格式无效")
    cli_ids = set()
    for agent in data.get("agents") or []:
        if isinstance(agent, dict) and agent.get("name") == "cli":
            cli_ids.update(str(x).strip() for x in (agent.get("models") or []) if str(x).strip())
            break

    models = []
    seen = set()
    for raw in raw_models:
        if not isinstance(raw, dict) or raw.get("disabled"):
            continue
        model_id = str(raw.get("id") or raw.get("name") or "").strip()
        if not model_id or model_id in seen or (cli_ids and model_id not in cli_ids):
            continue
        seen.add(model_id)
        models.append({
            "id": model_id,
            "name": str(raw.get("name") or model_id).strip(),
            # normalize multiplier string
            "credits": normalize_model_credits(raw.get("credits")),
        })
    return models


def _stable_account_header(uid, purpose):
    """Generate stable device header based on uid."""
    value = ("wb2a:%s:%s" % (purpose, uid)).encode("utf-8")
    return hashlib.sha256(value).hexdigest()[:36]


def _read_account_auth(account):
    """Read auth token for account."""
    name = str(account.get("file") or "")
    if not name or "/" in name or "\\" in name or not name.endswith(".json"):
        raise ValueError("账号文件名无效")
    rc, raw, err = dexec(["cat", C_AUTH + "/" + name], timeout=30)
    if rc != 0:
        raise RuntimeError((err or raw).strip()[:200] or "读取账号凭据失败")
    try:
        data = json.loads(raw)
    except Exception:
        raise ValueError("账号凭据格式无效")
    auth = data.get("auth") or {}
    token = str(auth.get("accessToken") or "").strip()
    if not token:
        raise ValueError("账号缺少 accessToken")
    realm = str(auth.get("realm") or account.get("realm") or "cn").strip().lower()
    if realm not in ("cn", "global"):
        realm = "cn"
    uid = str((data.get("account") or {}).get("uid") or account.get("uid") or "").strip()
    return {"token": token, "realm": realm, "uid": uid}


def _fetch_model_catalog(account):
    """Fetch model catalog from upstream domain without leaking access tokens."""
    auth = _read_account_auth(account)
    if auth["realm"] == "global":
        base = "https://www.workbuddy.ai"
        path = "/v2/enterprises/personal/models"
        origin = "https://www.workbuddy.ai"
        language = "en-US"
        platform = "WorkBuddy AI"
    else:
        base = "https://www.codebuddy.cn"
        path = "/console/enterprises/personal/models"
        origin = "https://www.codebuddy.cn"
        language = "zh-CN"
        platform = "WorkBuddy"
    headers = {
        "Authorization": "Bearer " + auth["token"],
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "X-CodeBuddy-Request": "1",
        "Origin": origin,
        "Referer": origin + "/",
        "Accept-Language": language,
        "User-Agent": "WorkBuddy/5.5.4 %s/5.5.4 CLI/2.137.1" % platform,
    }
    if auth["uid"]:
        headers["X-Machine-ID"] = _stable_account_header(auth["uid"], "machine")
        headers["X-Session-ID"] = _stable_account_header(auth["uid"], "session")
    req = Request(base + path, headers=headers)
    with urlopen(req, timeout=MODEL_TIMEOUT) as response:
        raw = response.read(2 * 1024 * 1024)
    return parse_model_catalog(json.loads(raw.decode("utf-8", "ignore")))


def invalidate_model_cache():
    with MODEL_CACHE_LOCK:
        MODEL_CACHE["at"] = 0.0
        MODEL_CACHE["data"] = None


def model_info(force=False):
    """Fetch and merge model catalogs across all configured accounts."""
    now = time.time()
    with MODEL_CACHE_LOCK:
        if (not force and MODEL_CACHE["data"] is not None and
                now - MODEL_CACHE["at"] < MODEL_CACHE_TTL):
            return MODEL_CACHE["data"]

    accounts = list_accounts()
    merged = {}
    errors = []
    for account in accounts:
        label = str(account.get("nickname") or account.get("uid") or account.get("realm") or "账号")
        try:
            models = _fetch_model_catalog(account)
        except Exception as exc:
            # truncate error summary without leaking headers
            errors.append({"account": label, "error": str(exc)[:200]})
            continue
        for model in models:
            entry = merged.setdefault(model["id"], {
                "id": model["id"], "name": model["name"],
                "credits": [], "accounts": [],
            })
            if model["name"] and entry["name"] == entry["id"]:
                entry["name"] = model["name"]
            if model["credits"] and model["credits"] not in entry["credits"]:
                entry["credits"].append(model["credits"])
            if label not in entry["accounts"]:
                entry["accounts"].append(label)

    data = {
        "ok": True,
        "models": list(merged.values()),
        "errors": errors,
        "account_count": len(accounts),
        "updated_at": int(now),
    }
    with MODEL_CACHE_LOCK:
        MODEL_CACHE["at"] = now
        MODEL_CACHE["data"] = data
    return data


def extract_json(text):
    """Extract outermost JSON object from string output."""
    s = text.find("{")
    e = text.rfind("}")
    if s == -1 or e == -1 or e <= s:
        return None
    try:
        return json.loads(text[s:e + 1])
    except Exception:
        return None


def write_auth(uid, realm, poll_result):
    """Write account authentication credentials file inside container."""
    auth = {
        "account": {
            "uid": str(uid),
            "enterpriseId": poll_result.get("enterprise_id", "") or "",
            "nickname": poll_result.get("nickname", "") or "",
        },
        "auth": {
            "accessToken": poll_result.get("access_token", ""),
            "refreshToken": poll_result.get("refresh_token", ""),
            "expiresAt": int(time.time()) + int(poll_result.get("expires_in", 0) or 0),
            "domain": poll_result.get("domain", "") or "",
            "realm": realm,
        },
    }
    if not auth["auth"]["accessToken"] or not uid:
        return False, "凭证不完整（缺少 access_token 或 uid）"

    # validate uid format and pass via docker exec args to prevent injection
    uid_s = str(uid)
    if not uid_s or len(uid_s) > 128 or not re.fullmatch(r"[A-Za-z0-9_-]+", uid_s):
        return False, "uid 含非法字符，拒绝写入"
    name = "workbuddy-%s.json" % uid_s
    target = C_AUTH + "/" + name
    blob = json.dumps(auth, ensure_ascii=False, indent=2).encode("utf-8")
    rc, out, err = dexec(["tee", target], stdin_bytes=blob)
    if rc != 0:
        return False, "写入失败: " + (err or out).strip()[:200]
    rc, out, err = dexec(["chmod", "600", target])
    if rc != 0:
        return False, "设置权限失败: " + (err or out).strip()[:200]
    return True, "已写入 %s" % target


# ---------------- API Key & Caddy Auth ----------------
KEY_PREFIX = "sk-"


def load_keys():
    try:
        with open(KEYS_FILE, "r", encoding="utf-8") as f:
            d = json.load(f)
            if isinstance(d.get("keys"), list):
                return d
    except Exception:
        pass
    return {"keys": []}


def save_keys(d):
    os.makedirs(ADMIN_DIR, exist_ok=True)
    tmp = KEYS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)
    os.replace(tmp, KEYS_FILE)
    try:
        os.chmod(KEYS_FILE, 0o600)
    except Exception:
        pass


def ensure_keys_init():
    """Ensure keys.json is initialized with the primary gateway API key."""
    with KEY_STATE_LOCK:
        d = load_keys()
        if not d["keys"]:
            real = get_api_key()
            if real:
                d["keys"].append({
                    "id": "default",
                    "name": "default（网关内置）",
                    "key": real,
                    "enabled": True,
                    "created_at": int(time.time()),
                    "system": True,
                })
                save_keys(d)
        dirty = False
        for k in d["keys"]:
            for field, default in (("enabled", True), ("system", False),
                                   ("created_at", int(time.time()))):
                if field not in k:
                    k[field] = default
                    dirty = True
            if "id" not in k:
                k["id"] = secrets.token_hex(6)
                dirty = True
        if dirty:
            save_keys(d)
        return d


def gen_key():
    return KEY_PREFIX + secrets.token_urlsafe(32)


def key_platforms():
    """Return supported platforms for API key assignment."""
    return [
        {"id": "workbuddy", "name": "WorkBuddy / CodeBuddy",
         "base_url": PUBLIC_BASE_URL, "auth": "Kasa2API Key"},
    ]


def _find_block(src, name):
    """Locate balanced Caddyfile site block by name."""
    m = re.search(r"^" + re.escape(name) + r"\s*\{", src, re.M)
    if not m:
        return None
    depth = 0
    for j in range(m.start(), len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return (m.start(), j + 1)
    return None


def _extract_basicauth(site_src):
    """Read basicauth username and bcrypt hash from site block."""
    # support both /admin/api/* and legacy /admin* blocks
    for route in ("/admin/api/\\*", "/admin\\*"):
        m_admin = re.search(r"(?m)^\s*handle\s+" + route + r"\s*\{", site_src)
        if not m_admin:
            continue
        depth = 0
        end = None
        for j in range(m_admin.end() - 1, len(site_src)):
            if site_src[j] == "{":
                depth += 1
            elif site_src[j] == "}":
                depth -= 1
                if depth == 0:
                    end = j + 1
                    break
        if end is None:
            continue
        admin_src = site_src[m_admin.start():end]
        m = re.search(
            r"(?m)^\s*([^\s{}]+)\s+(\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53})\s*$",
            admin_src)
        if m:
            return m.group(1), m.group(2)
    return None


def read_admin_auth():
    """Read admin HTTP Basic Auth credentials from Caddyfile."""
    try:
        with open(CADDY_FILE, "r", encoding="utf-8") as f:
            src = f.read()
        blk = _find_block(src, PUBLIC_HOST)
        if not blk:
            return None
        got = _extract_basicauth(src[blk[0]:blk[1]])
        if not got:
            return None
        return {"username": got[0], "hash": got[1]}
    except Exception:
        return None


def _extract_managed_bridge(site_src):
    """Extract managed responses-bridge routing block from site configuration."""
    m = re.search(
        r"(?ms)^\s*# >>> responses-bridge \(managed\) >>>.*?"
        r"^\s*# <<< responses-bridge \(managed\) <<<\s*",
        site_src)
    return m.group(0).rstrip() if m else ""


def render_api_block(keys, real_key, basicauth_user, basicauth_hash, bridge_block=""):
    enabled = [k["key"] for k in keys if k.get("enabled") and k.get("key")]
    pat = "|".join(re.escape(k) for k in enabled) if enabled else "___none___"
    auth_re = '"^Bearer (' + pat + ')$"'
    return (
        PUBLIC_HOST + " {\n"
        "\tencode gzip\n"
        "\thandle /admin/api/* {\n"
        "\t\turi strip_prefix /admin\n"
        "\t\tbasicauth {\n"
        "\t\t\t" + basicauth_user + " " + basicauth_hash + "\n"
        "\t\t}\n"
        "\t\treverse_proxy 127.0.0.1:7864\n"
        "\t}\n"
        "\thandle /admin* {\n"
        "\t\turi strip_prefix /admin\n"
        "\t\treverse_proxy 127.0.0.1:7864\n"
        "\t}\n"
        + (bridge_block + "\n" if bridge_block else "") +
        "\thandle {\n"
        "\t\t@bad {\n"
        "\t\t\tnot header_regexp authcheck Authorization " + auth_re + "\n"
        "\t\t\tnot path /healthz\n"
        "\t\t}\n"
        "\t\trespond @bad \"invalid API key\" 401\n"
        "\t\treverse_proxy 127.0.0.1:7863 {\n"
        "\t\t\theader_up Authorization \"Bearer " + real_key + "\"\n"
        "\t\t\tflush_interval -1\n"
        "\t\t}\n"
        "\t}\n"
        "}\n"
    )


def apply_caddy(keys, basicauth_user=None, basicauth_hash=None):
    """Render, validate, and apply updated keys and credentials to Caddyfile with rollback."""
    real = get_api_key()
    try:
        with open(CADDY_FILE, "r", encoding="utf-8") as f:
            src = f.read()
    except Exception as e:
        return False, "读取 Caddyfile 失败：%s" % e

    blk = _find_block(src, PUBLIC_HOST)
    if not blk:
        return False, "Caddyfile 中未找到 %s 块" % PUBLIC_HOST
    # extract basicauth scoped to target site block
    site_src = src[blk[0]:blk[1]]
    current = _extract_basicauth(site_src)
    if not current:
        return False, "Caddyfile 的 %s 块中未找到 basicauth 用户名或哈希" % PUBLIC_HOST
    current_user, current_hash = current
    new_user = basicauth_user if basicauth_user is not None else current_user
    new_hash = basicauth_hash if basicauth_hash is not None else current_hash
    bridge_block = _extract_managed_bridge(site_src)
    new_src = src[:blk[0]] + render_api_block(
        keys, real, new_user, new_hash, bridge_block) + src[blk[1]:]

    # use unique temp file to avoid permission conflicts
    tmp = "/tmp/Caddyfile.wb2api." + secrets.token_hex(8)
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(new_src)

        p = subprocess.run(["sudo", "-n", "caddy", "validate", "--adapter", "caddyfile",
                            "--config", tmp], capture_output=True, text=True, timeout=60)
        if p.returncode != 0:
            return False, "配置校验失败（未部署）：" + (p.stderr or p.stdout).strip()[-300:]

        stamp = time.strftime("%F-%H%M%S")
        bak = CADDY_FILE + ".bak." + stamp
        subprocess.run(["sudo", "-n", "cp", CADDY_FILE, bak], capture_output=True, timeout=30)
        p2 = subprocess.run(["sudo", "-n", "cp", tmp, CADDY_FILE],
                            capture_output=True, text=True, timeout=30)
        if p2.returncode != 0:
            return False, "部署失败：" + (p2.stderr or "").strip()[:200]
        p3 = subprocess.run(["sudo", "-n", "systemctl", "reload", "caddy"],
                            capture_output=True, text=True, timeout=60)
        if p3.returncode != 0:
            subprocess.run(["sudo", "-n", "cp", bak, CADDY_FILE], capture_output=True, timeout=30)
            subprocess.run(["sudo", "-n", "systemctl", "reload", "caddy"], capture_output=True, timeout=60)
            return False, "reload 失败，已回滚：" + (p3.stderr or "").strip()[:200]
        return True, "已生效（备份 %s）" % bak
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def hash_admin_password(password):
    """Hash password via caddy hash-password."""
    try:
        # pass password via stdin to keep it out of process arguments
        p = subprocess.run(
            ["sudo", "-n", "caddy", "hash-password", "--algorithm", "bcrypt"],
            input=password + "\n",
            capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return None, "生成密码哈希超时"
    except Exception as e:
        return None, "生成密码哈希失败：%s" % str(e)[:160]
    if p.returncode != 0:
        return None, (p.stderr or p.stdout).strip()[:200]
    value = (p.stdout or "").strip()
    if not re.fullmatch(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}", value):
        return None, "Caddy 返回的哈希格式不合法"
    return value, ""


def update_admin_credentials(username, password):
    """Update admin Basic Auth username and password in Caddyfile."""
    username = (username or "").strip()
    if not ADMIN_USER_RE.fullmatch(username):
        return False, "用户名只允许 1-64 位字母、数字、点、下划线和横线"
    password = password or ""
    if password and len(password) < ADMIN_PASSWORD_MIN:
        return False, "密码至少需要 %d 位" % ADMIN_PASSWORD_MIN
    if password and len(password) > 256:
        return False, "密码过长（最多 256 位）"
    if any(ch in password for ch in "\r\n\x00"):
        return False, "密码不能包含换行或 NUL 字符"

    with KEY_STATE_LOCK:
        current = read_admin_auth()
        if not current:
            return False, "当前 Caddyfile 中未找到管理页登录凭据"
        if password:
            new_hash, err = hash_admin_password(password)
            if not new_hash:
                return False, "生成密码哈希失败：" + err
        else:
            new_hash = current["hash"]
        keys = ensure_keys_init()["keys"]
        ok, msg = apply_caddy(keys, username, new_hash)
        if not ok:
            return False, msg
        return True, "管理页登录凭据已更新"


def _keys_snapshot(keys):
    """Deep copy keys list for atomic transaction isolation."""
    return json.loads(json.dumps(keys, ensure_ascii=False))


def _commit_keys_locked(old_keys, new_keys):
    """Apply updated keys to Caddy and commit to keys.json while holding KEY_STATE_LOCK.

    Applies to Caddy first so keys.json remains unchanged on validation/reload failure.
    Rolls back Caddy if persisting keys.json fails.
    """
    try:
        ok, msg = apply_caddy(new_keys)
    except subprocess.TimeoutExpired:
        return False, "网关配置应用超时，未提交", _keys_snapshot(old_keys)
    except Exception as e:
        return False, "网关配置应用异常：%s" % str(e)[:200], _keys_snapshot(old_keys)
    if not ok:
        return False, msg, _keys_snapshot(old_keys)
    try:
        save_keys({"keys": new_keys})
    except Exception as e:
        # rollback Caddy if keys.json save fails
        try:
            rb_ok, rb_msg = apply_caddy(old_keys)
        except Exception as rb_e:
            rb_ok, rb_msg = False, str(rb_e)[:200]
        if rb_ok:
            return False, "keys.json 写入失败，已回滚网关配置：%s" % str(e)[:160], _keys_snapshot(old_keys)
        return False, "keys.json 写入失败，且网关回滚失败：%s / %s" % (
            str(e)[:120], rb_msg[:120]), _keys_snapshot(old_keys)
    return True, msg, _keys_snapshot(new_keys)


def mutate_keys(mutator):
    """Serialize atomic keys.json + Caddy update transaction."""
    with KEY_STATE_LOCK:
        old = ensure_keys_init()["keys"]
        base = _keys_snapshot(old)
        try:
            out = mutator(_keys_snapshot(base))
        except ValueError as e:
            return False, str(e)[:200], _keys_snapshot(base), None
        except Exception as e:
            return False, "操作失败：%s" % str(e)[:200], base, None
        if not isinstance(out, tuple) or len(out) != 2:
            return False, "内部错误：事务函数返回值非法", base, None
        new_keys, result = out
        if not isinstance(new_keys, list):
            return False, "内部错误：Key 列表非法", base, None
        ok, msg, committed = _commit_keys_locked(base, new_keys)
        if not ok:
            return False, msg, _keys_snapshot(base), None
        return True, msg, committed, result


# ---------------- HTTP ----------------

PAGE = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kasa2API 管理</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0f172a;--bg-subtle:#162032;--card:#1e293b;--card-subtle:#243044;
  --bd:#334155;--bd-focus:#10a37f;--tx:#e2e8f0;--tx-heading:#f8fafc;--mut:#94a3b8;
  --pri:#10a37f;--pri-tx:#ffffff;--pri-hover:#1a7f64;
  --ok:#10a37f;--ok-bg:rgba(16,163,127,0.12);--ok-bd:rgba(16,163,127,0.3);
  --bad:#ef4444;--bad-bg:rgba(239,68,68,0.12);--bad-bd:rgba(239,68,68,0.3);
  --table-hover:rgba(255,255,255,0.02);--table-th-bg:#162032;
  --radius:8px;--radius-lg:10px;
  --shadow:0 4px 16px rgba(0,0,0,0.25);
}
[data-theme="light"]{
  --bg:#f8fafc;--bg-subtle:#f1f5f9;--card:#ffffff;--card-subtle:#f8fafc;
  --bd:#e2e8f0;--bd-focus:#10a37f;--tx:#1e293b;--tx-heading:#0f172a;--mut:#64748b;
  --pri:#10a37f;--pri-tx:#ffffff;--pri-hover:#1a7f64;
  --ok:#059669;--ok-bg:#ecfdf5;--ok-bd:#a7f3d0;
  --bad:#dc2626;--bad-bg:#fef2f2;--bad-bd:#fecaca;
  --table-hover:rgba(0,0,0,0.02);--table-th-bg:#f8fafc;
  --shadow:0 1px 3px rgba(0,0,0,0.05),0 4px 12px rgba(0,0,0,0.03);
}
*{box-sizing:border-box}
[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--tx);font:13.5px/1.55 "Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;-webkit-font-smoothing:antialiased}
.wrap{max-width:1280px;margin:0 auto;padding:24px 20px 80px}
.app-header{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:20px;padding-bottom:18px;border-bottom:1px solid var(--bd);flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:12px}
.brand-badge{width:28px;height:28px;border-radius:6px;background:var(--pri);color:#fff;display:inline-flex;align-items:center;justify-content:center;font-size:15px;font-weight:800;letter-spacing:0}
.brand-meta{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.brand-title{font-size:17px;font-weight:700;color:var(--tx-heading);letter-spacing:-0.02em}
.host-chip{font-size:12px;color:var(--mut);background:var(--bg-subtle);padding:3px 9px;border:1px solid var(--bd);border-radius:var(--radius)}
.header-actions{display:flex;align-items:center;gap:8px;margin-left:auto}
.version-chip{font-size:11.5px;color:var(--mut);padding:3px 8px;border:1px solid var(--bd);border-radius:var(--radius);background:var(--bg-subtle)}
.status-indicator{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--mut);padding:2px 8px;border-radius:999px;background:var(--ok-bg);border:1px solid var(--ok-bd)}
.status-indicator .dot{width:6px;height:6px;border-radius:50%;background:var(--ok);display:inline-block}

.login-page{min-height:100vh;display:grid;place-items:center;padding:24px;background:var(--bg)}
.login-card{width:min(380px,100%);background:var(--card);border:1px solid var(--bd);border-radius:var(--radius-lg);padding:32px 28px;box-shadow:var(--shadow)}
.login-card h1{margin:8px 0 4px;font-size:20px;font-weight:700;color:var(--tx-heading);letter-spacing:-0.02em}
.login-card .sub{margin-bottom:24px;font-size:13px;color:var(--mut)}
.login-field{display:flex;flex-direction:column;gap:6px;margin-top:14px;font-size:12.5px;font-weight:500;color:var(--mut)}
.login-field input{width:100%;margin-top:0}
.login-card button{width:100%;margin-top:24px;padding:10px 16px;font-size:14px}
.login-card .msg{margin-top:12px}

.card{background:var(--card);border:1px solid var(--bd);border-radius:var(--radius-lg);padding:22px 24px;margin-bottom:20px;box-shadow:var(--shadow)}
.card h2{font-size:15px;font-weight:600;margin:0 0 16px;display:flex;align-items:center;justify-content:space-between;color:var(--tx-heading);flex-wrap:wrap;gap:8px;letter-spacing:-0.01em}
.sub{color:var(--mut);margin:0 0 16px;font-size:13px;line-height:1.55}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px}
.stat{border:1px solid var(--bd);border-radius:var(--radius);padding:16px 18px;background:var(--bg-subtle);transition:border-color .15s}
.stat:hover{border-color:var(--bd-focus)}
.stat .k{color:var(--mut);font-size:12px;font-weight:500}
.stat .v{font-size:26px;font-weight:700;margin-top:6px;color:var(--tx-heading);font-family:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,monospace;font-variant-numeric:tabular-nums;letter-spacing:-0.02em}

.table-scroll{overflow-x:auto;border-radius:var(--radius);border:1px solid var(--bd);background:var(--card);-webkit-overflow-scrolling:touch}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:11px 16px;border-bottom:1px solid var(--bd)}
th{color:var(--mut);font-weight:600;font-size:12px;background:var(--table-th-bg);letter-spacing:0.02em;white-space:nowrap}
tr:last-child td{border-bottom:none}
tr:hover td{background:var(--table-hover)}

button{background:var(--pri);color:var(--pri-tx);border:0;border-radius:var(--radius);padding:8px 16px;cursor:pointer;font-size:13px;font-weight:600;display:inline-flex;align-items:center;justify-content:center;gap:6px;transition:opacity .15s,background .15s}
button:hover:not(:disabled){background:var(--pri-hover)}
button:active:not(:disabled){transform:scale(0.99)}
button:disabled{opacity:.4;cursor:not-allowed}
button.ghost{background:var(--card);color:var(--tx);border:1px solid var(--bd)}
button.ghost:hover:not(:disabled){background:var(--card-subtle);border-color:var(--bd-focus)}
button.danger{background:var(--bad-bg);color:var(--bad);border:1px solid var(--bad-bd)}
button.danger:hover:not(:disabled){background:var(--bad);color:#fff}
button.btn-sm{padding:6px 12px;font-size:12.5px}
select,input{padding:8px 12px;border:1px solid var(--bd);border-radius:var(--radius);font-size:13px;background:var(--bg);color:var(--tx);font-family:inherit}
select:focus,input:focus{outline:none;border-color:var(--bd-focus);box-shadow:0 0 0 2px var(--ok-bg)}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}

.module-nav{display:flex;gap:4px;padding:4px;background:var(--card);border:1px solid var(--bd);border-radius:var(--radius-lg);overflow-x:auto;-webkit-overflow-scrolling:touch;scrollbar-width:none;margin:0 0 24px;box-shadow:var(--shadow)}
.module-nav::-webkit-scrollbar{display:none}
.module-nav a{color:var(--mut);text-decoration:none;padding:8px 16px;font-size:13px;font-weight:500;border-radius:var(--radius);white-space:nowrap;transition:color .12s,background .12s}
.module-nav a:hover{color:var(--tx-heading);background:var(--bg-subtle)}
.module-nav a.active{color:#ffffff;background:var(--bg-subtle);border:1px solid var(--bd);font-weight:600}
[data-theme="light"] .module-nav a.active{color:var(--tx-heading);background:var(--bg-subtle)}
.module{display:none}
.module.active{display:block}

.urlbox{margin-top:14px;padding:12px 14px;background:var(--bg-subtle);border:1px solid var(--bd);border-radius:var(--radius);word-break:break-all;font-size:12.5px;line-height:1.55}
.urlbox a{color:var(--ok);text-decoration:underline}
.msg{margin-top:14px;padding:12px 14px;border-radius:var(--radius);font-size:13px;display:none;line-height:1.5}
.msg.ok{display:block;background:var(--ok-bg);color:var(--ok);border:1px solid var(--ok-bd)}
.msg.err{display:block;background:var(--bad-bg);color:var(--bad);border:1px solid var(--bad-bd)}
pre,code{font-family:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,monospace}
pre{background:var(--bg-subtle);border:1px solid var(--bd);border-radius:var(--radius);padding:12px 14px;overflow:auto;font-size:12.5px;max-height:280px;line-height:1.55;color:var(--tx)}
.mono{font-family:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,monospace;font-feature-settings:"tnum" 1;font-variant-numeric:tabular-nums}
.bar{height:6px;background:var(--bd);border-radius:3px;overflow:hidden;margin-top:14px}
.bar>i{display:block;height:100%;background:var(--ok);border-radius:3px;transition:width .3s ease}
h2 .fr{font-size:12px;padding:4px 10px}
label.sw{color:var(--mut);font-weight:400;font-size:12px;display:inline-flex;gap:6px;align-items:center;cursor:pointer}
#banner{display:none;position:fixed;top:0;left:0;right:0;z-index:99;background:var(--tx-heading);color:var(--bg);padding:8px 14px;font-size:12px;text-align:center;cursor:pointer;font-weight:600}
#banner u{text-underline-offset:2px}
.help{display:block;color:var(--mut);font-size:12px;line-height:1.55}
.notice{margin-top:14px;padding:12px 14px;border:1px solid var(--bd);border-radius:var(--radius);background:var(--bg-subtle);color:var(--mut);font-size:12.5px;line-height:1.55}
.field{display:flex;flex-direction:column;gap:5px;min-width:180px;flex:1}
.field>span{font-weight:600;font-size:13px;color:var(--tx-heading)}

.account-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px}
.account-option{display:flex;align-items:flex-start;gap:10px;border:1px solid var(--bd);border-radius:var(--radius);padding:12px 14px;cursor:pointer;background:var(--bg-subtle);transition:border-color .12s}
.account-option:hover{border-color:var(--bd-focus)}
.account-option input{margin:2px 0 0;padding:0}
.account-option strong{display:block;font-size:13px;font-weight:600;color:var(--tx-heading)}
.account-option small{display:block;color:var(--mut);font-size:11.5px;line-height:1.45;word-break:break-all;margin-top:3px}
.account-toolbar{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:12px;padding:2px 0}
.account-toolbar label{font-size:12.5px;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:6px}

.task-picker{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:10px;margin-top:10px}
.task-option{display:flex;align-items:flex-start;gap:10px;border:1px solid var(--bd);border-radius:var(--radius);padding:12px 14px;cursor:pointer;background:var(--bg-subtle);transition:border-color .12s}
.task-option:hover{border-color:var(--bd-focus)}
.task-option input{margin:2px 0 0;padding:0}
.task-option strong{display:block;font-size:13px;font-weight:600;color:var(--tx-heading)}
.task-option small{display:block;color:var(--mut);font-size:11.5px;line-height:1.45;word-break:break-word;margin-top:3px}
.task-option-disabled{cursor:not-allowed;opacity:.4;background:var(--bg-subtle)}
.task-toolbar{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-top:14px;padding:2px 0}
.task-toolbar label{font-size:12.5px;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:6px}
.task-help{margin-top:14px;border-top:1px solid var(--bd);padding-top:12px}
.task-help summary{cursor:pointer;color:var(--mut);font-size:12.5px}
.task-help summary:hover{color:var(--tx-heading)}
.task-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:8px 18px;margin-top:12px}
.task-item{font-size:12px;line-height:1.55}
.task-item code{color:var(--tx-heading);font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.task-item small{display:block;color:var(--mut)}

.model-table{min-width:380px}
.model-table .credit{font-weight:600;color:var(--tx-heading);white-space:nowrap}
.usage-table{min-width:560px}
.usage-table.account-usage{min-width:920px}
.usage-table.recent-usage{min-width:1200px}
.usage-table .account small{display:block;color:var(--mut);font-size:11.5px;margin-top:3px}
.usage-table .delta{font-weight:600;color:var(--ok);white-space:nowrap}
.usage-table .delta.neutral{color:var(--mut);font-weight:400}

.platform-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
.platform-card{border:1px solid var(--bd);border-radius:var(--radius);padding:16px;background:var(--bg-subtle)}
.platform-head{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:12px}
.platform-head strong{font-size:14.5px;color:var(--tx-heading)}
.platform-badge{font-size:11px;font-weight:600;color:var(--ok);background:var(--ok-bg);border:1px solid var(--ok-bd);border-radius:var(--radius);padding:2px 8px}
.platform-badge.passthrough{color:var(--mut);border-color:var(--bd)}
.platform-card dl{margin:0;font-size:12.5px;display:grid;grid-template-columns:auto 1fr;gap:6px 14px}
.platform-card dt{color:var(--mut);font-weight:500}
.platform-card dd{margin:0;word-break:break-word;color:var(--tx)}
.platform-card a{color:var(--ok);text-decoration:underline}
.platform-features{margin:12px 0 0;padding-left:18px;color:var(--mut);font-size:12px;line-height:1.55}

.chip{display:inline-flex;align-items:center;gap:4px;font-size:11.5px;padding:2px 7px;border-radius:var(--radius);background:var(--bg-subtle);border:1px solid var(--bd);color:var(--mut)}

@media (max-width:640px){
  .wrap{padding:14px 12px 60px}
  .app-header{flex-direction:column;align-items:flex-start;gap:12px}
  .header-actions{width:100%;justify-content:flex-end}
  .row{flex-direction:column;align-items:stretch}
  .row>*{width:100%}
  .field{width:100%}
  .grid{grid-template-columns:repeat(2,1fr)}
  .account-list,.task-picker{grid-template-columns:1fr}
}
</style></head><body>
<div id="loginView" class="login-page">
  <form id="loginForm" class="login-card">
    <div style="margin-bottom:20px">
      <span class="brand-badge">✳</span>
      <h1>Kasa2API</h1>
      <p class="sub">统一网关控制台</p>
    </div>
    <label class="login-field"><span>用户名</span><input id="loginUser" autocomplete="username" placeholder="admin" required></label>
    <label class="login-field"><span>密码</span><input id="loginPass" type="password" autocomplete="current-password" placeholder="••••••••" required></label>
    <button id="btnLogin" type="submit">登 录</button>
    <div id="loginMsg" class="msg"></div>
  </form>
</div>
<div id="appView" hidden>
<div id="banner"></div>
<div class="wrap">
<header class="app-header">
  <div class="brand">
    <span class="brand-badge">✳</span>
    <div class="brand-meta">
      <span class="brand-title">Kasa2API</span>
      <span class="host-chip mono">__PUBLIC_HOST__</span>
      <span class="status-indicator"><span class="dot"></span><span>Active</span></span>
    </div>
  </div>
  <div class="header-actions">
    <span class="version-chip mono">v__PAGE_VER__</span>
    <button id="btnTheme" class="ghost btn-sm" title="切换模式">🌓</button>
    <button id="btnLogout" class="ghost btn-sm">退出</button>
  </div>
</header>

<nav class="module-nav" aria-label="管理模块">
  <a href="#/overview" data-module-link="overview">总览</a>
  <a href="#/platforms" data-module-link="platforms">平台</a>
  <a href="#/accounts" data-module-link="accounts">账号与积分</a>
  <a href="#/usage" data-module-link="usage">积分使用记录</a>
  <a href="#/gateway" data-module-link="gateway">网关与 Key</a>
  <a href="#/automation" data-module-link="automation">WorkBuddy 自动化</a>
  <a href="#/security" data-module-link="security">安全设置</a>
</nav>
<div id="globalMsg" class="msg"></div>

<section class="module active" id="module-overview" data-module="overview">
<div class="card"><h2>总览<label class="sw"><input type="checkbox" id="autoOn" checked>自动刷新</label></h2>
  <div class="grid" id="stats"></div>
  <p class="sub" id="lastUpd" style="margin:10px 0 0"></p>
</div>
<div class="card"><h2>模型积分倍率<button id="btnModels" class="ghost fr">刷新</button></h2>
  <div id="modelBox"><p class="sub">加载中…</p></div>
</div>
</section>

<section class="module" id="module-platforms" data-module="platforms">
<div class="card"><h2>平台入口</h2>
  <p class="sub">统一查看各平台入口；账号、密钥和计费边界仍按平台分别管理。</p>
  <div id="platformBox"><p class="sub">加载中…</p></div>
</div>
</section>

<section class="module" id="module-accounts" data-module="accounts">
<div class="card"><h2>积分余额<button id="btnCredit" class="ghost fr">刷新</button></h2>
  <div id="creditBox"><p class="sub">加载中…</p></div>
</div>

<div class="card"><h2>添加账号（OAuth 登录）</h2>
  <div class="row">
    <select id="realm"><option value="cn">国内版 (cn)</option><option value="global">国际版 (global)</option></select>
    <button id="btnStart">1. 获取授权链接</button>
    <button id="btnFinish" class="ghost" disabled>2. 我已完成登录，完成添加</button>
  </div>
  <div id="urlbox" class="urlbox" style="display:none"></div>
  <p class="sub" style="margin:12px 0 0">流程：点第 1 步 → 打开链接并在浏览器登录你的 WorkBuddy/CodeBuddy 账号 → 回来点第 2 步。加完会自动重启容器加载账号。</p>
</div>

<div class="card"><h2>账号列表</h2><div id="accounts"></div></div>
</section>

<section class="module" id="module-usage" data-module="usage">
<div class="card"><h2>积分消耗使用记录<button id="btnUsage" class="ghost fr">刷新</button></h2>
  <p class="sub">网关按请求保存最近 20 条记录，同时保留账号和模型累计统计。</p>
  <div id="usageSummary"><p class="sub">加载中…</p></div>
  <h3 style="margin:22px 0 8px">最近 20 条请求</h3>
  <div id="recentUsageBox"><p class="sub">加载中…</p></div>
  <div id="usageBox" style="margin-top:16px"><p class="sub">加载中…</p></div>
</div>
</section>

<section class="module" id="module-gateway" data-module="gateway">
<div class="card"><h2>API Key 管理</h2>
  <div class="row">
    <input id="keyName" placeholder="备注名（如：手机端 / 脚本 A）" style="flex:1;min-width:180px">
    <button id="btnNewKey">创建新 Key</button>
  </div>
  <div class="row" style="margin-top:12px">
    <label class="field" style="max-width:360px"><span>当前平台</span><select id="keyPlatform"></select></label>
    <div id="keyPlatformInfo" class="notice" style="flex:1;margin-top:0;min-width:260px">正在读取平台入口…</div>
  </div>
  <div id="keysBox" style="margin-top:14px"><p class="sub">加载中…</p></div>
  <p class="sub" style="margin:12px 0 0">同一把 Kasa2API Key 可用于 WorkBuddy / CodeBuddy；Responses API 接口也沿用这把 Key。新建 Key 使用 <code>sk-</code> 前缀；已有 <code>wb-</code> Key 继续兼容。</p>
</div>

<div class="card"><h2>渠道风控与设备码（Device Token）</h2>
  <p class="sub">用于规避上游 <code>11128 这次调用没通过渠道校验</code> 拦截。请填入个人客户端生成的 <code>X-Device-Token</code>。</p>
  <div class="row" style="margin-top:12px">
    <input id="deviceTokenInput" type="password" placeholder="留空清除，或输入设备码（如 32-36 位十六进制指纹）" style="flex:1;min-width:240px" autocomplete="off">
    <button id="btnSaveDeviceToken">保存并重启网关</button>
  </div>
  <div id="deviceTokenStatus" class="notice" style="margin-top:10px">正在读取设备码状态…</div>
  <p class="sub" style="margin:10px 0 0">提示：设备码落盘于 <code>./data/device_token</code>，供所有账号共享。保存后会自动重启网关使配置生效。</p>
</div>

<div class="card"><h2>网关状态（原始）</h2><pre id="raw"></pre></div>
</section>

<section class="module" id="module-automation" data-module="automation">
<div class="card"><h2>签到和猫猫旅行</h2>
  <p class="sub">按设置的时间自动执行。保存后会重启网关。</p>
  <div class="row" style="margin-top:12px;align-items:flex-start">
    <label class="field"><span><input type="checkbox" id="gatewayCheckinEnabled" checked> 启用自动签到</span><input id="gatewayCheckinHours" placeholder="执行小时，例如 9,21"></label>
    <label class="field"><span><input type="checkbox" id="gatewayTravelEnabled" checked> 启用猫猫旅行</span><input id="gatewayTravelHours" placeholder="执行小时，例如 9,21"></label>
  </div>
  <span class="help">VPS 本地时间，小时用逗号分隔（0-23）。</span>
  <div id="gatewayAutomationStatus" class="notice">正在读取签到和旅行设置…</div>
  <div class="row" style="margin-top:12px"><button id="btnGatewayScheduleSave">保存签到和旅行设置</button></div>
</div>

<div class="card"><h2>执行账号</h2>
  <div id="autoAccountPicker"><p class="sub">加载中…</p></div>
</div>

<div class="card"><h2>手动操作</h2>
  <div class="row">
    <button id="btnAutoCheckin">立即执行签到</button>
    <button id="btnAutoScan" class="ghost">只读查看任务</button>
    <button id="btnAutoRun" class="ghost">执行已选成长任务</button>
    <button id="btnAutoRunAll" class="danger">一键完成所有任务</button>
  </div>
</div>

<div class="card"><h2>成长任务定时执行</h2>
  <p class="sub">按设定的小时执行已选任务。</p>
  <label><input type="checkbox" id="autoTaskEnabled"> 启用定时执行</label>
  <div class="row" style="margin-top:12px;align-items:flex-start">
    <label class="field"><span>执行小时（每天触发时刻）</span><input id="autoTaskHours" placeholder="例如 12,22"></label>
    <label class="field"><span>动作间隔（秒）</span><input id="autoTaskGap" placeholder="建议 ≥1，默认 1.2"></label>
  </div>
  <span class="help">使用 VPS 本地时间；例如填写 12,22，表示每天 12 点和 22 点后的前 5 分钟内各启动一次。只影响定时执行，手动按钮不受影响。</span>
  <div id="autoTaskPicker"><p class="sub">正在加载任务列表…</p></div>
  <div class="row" style="margin-top:12px"><button id="btnAutoSave" class="ghost">保存定时任务设置</button></div>
</div>

<div class="card"><h2>当前状态与最近结果</h2>
  <div id="automationBox" class="urlbox" style="margin-top:12px;white-space:pre-wrap">加载中…</div>
  <pre id="automationLog" style="display:none;margin-top:12px;max-height:260px;overflow:auto"></pre>
</div>
</section>

<section class="module" id="module-security" data-module="security">
<div class="card"><h2>管理页登录凭据</h2>
  <div class="row">
    <input id="adminUser" placeholder="用户名" autocomplete="username" style="min-width:180px">
    <input id="adminPass" type="password" placeholder="新密码（留空则不变）" autocomplete="new-password" style="flex:1;min-width:220px">
    <button id="btnSaveAuth">保存登录凭据</button>
  </div>
  <div id="authMsg" class="msg"></div>
  <p class="sub" style="margin:12px 0 0">用户名只允许字母、数字、点、下划线和横线；密码至少 8 位。修改后会立即生效，浏览器可能要求重新输入登录信息。</p>
</div>
</section>
</div>
</div>
<script>
const $=(s)=>document.querySelector(s);
const PAGE_VERSION='__PAGE_VER__';
let curRealm='cn';
let autoOn=true;
let busy=0;
let reloading=false;
let lastCredit=0;
let lastModels=0;
let lastUsage=0;
const MODULES=['overview','platforms','accounts','usage','gateway','automation','security'];
let currentModule='overview';
let authHeader='';
let appStarted=false;
let savedAccounts=[];
let autoAccountSelection=null;
let autoAccountsConfigured=false;
let autoAccountsTouched=false;
let autoConfiguredUids=null;
let availableTaskCodes=[];
let taskSelection=null;
let taskSelectionConfigured=false;
let taskSelectionTouched=false;
let configuredTaskCodes=null;
function utf8Base64(value){
  const bytes=new TextEncoder().encode(value); let binary='';
  bytes.forEach(b=>{binary+=String.fromCharCode(b);});
  return btoa(binary);
}
function makeBasicAuth(username,password){ return 'Basic '+utf8Base64(username+':'+password); }
function decodeBasicAuth(header){
  try{
    if(!header||header.slice(0,6)!=='Basic ') return null;
    const binary=atob(header.slice(6));
    const bytes=Uint8Array.from(binary,c=>c.charCodeAt(0));
    const value=new TextDecoder().decode(bytes), split=value.indexOf(':');
    return split<0?null:[value.slice(0,split),value.slice(split+1)];
  }catch(e){ return null; }
}
function storedAuth(){ try{return sessionStorage.getItem('kasa2api_auth')||sessionStorage.getItem('wb2api_auth')||'';}catch(e){return '';} }
function persistAuth(){ try{sessionStorage.setItem('kasa2api_auth',authHeader);sessionStorage.removeItem('wb2api_auth');}catch(e){} }
function clearAuth(){ authHeader=''; try{sessionStorage.removeItem('kasa2api_auth');sessionStorage.removeItem('wb2api_auth');}catch(e){} }
function loginMessage(txt,ok){
  const m=$('#loginMsg'); m.className='msg '+(ok?'ok':'err'); m.textContent=txt; m.style.display='block';
}
function showLogin(message){
  clearAuth();
  $('#appView').hidden=true; $('#loginView').hidden=false;
  if(message) loginMessage(message,false);
  setTimeout(()=>$('#loginUser').focus(),0);
}
async function verifyAuth(token){
  try{
    const r=await fetch('/admin/api/version',{headers:{Authorization:token},cache:'no-store'});
    if(!r.ok) return false;
    const d=await r.json(); return !!d.version;
  }catch(e){ return false; }
}
function startApp(){
  $('#loginView').hidden=true; $('#appView').hidden=false;
  if(appStarted) return;
  appStarted=true;
  try{ if(localStorage.getItem('wb2api_auto')==='0'){ autoOn=false; $('#autoOn').checked=false; } }catch(e){}
  refresh().then(stamp);
  routeModule();
  setInterval(tick,30000);
  setInterval(checkVersion,15000);
  checkVersion();
  document.addEventListener('visibilitychange',()=>{if(!document.hidden) tick();});
}
async function initAuth(){
  const saved=storedAuth();
  if(saved&&await verifyAuth(saved)){ authHeader=saved; startApp(); return; }
  clearAuth(); $('#loginUser').focus();
}
$('#loginForm').onsubmit=async(e)=>{
  e.preventDefault();
  const username=$('#loginUser').value.trim(), password=$('#loginPass').value;
  const button=$('#btnLogin');
  if(!username||!password){ loginMessage('请填写用户名和密码。',false); return; }
  button.disabled=true; loginMessage('正在登录…',true);
  const token=makeBasicAuth(username,password);
  try{
    if(!await verifyAuth(token)){ loginMessage('用户名或密码错误。',false); return; }
    authHeader=token; persistAuth(); $('#loginPass').value=''; loginMessage('',true); startApp();
  }catch(e){ loginMessage('登录失败，请稍后重试。',false); }
  finally{ button.disabled=false; }
};
$('#btnLogout').onclick=()=>showLogin('已退出登录。');
const AUTO_TASK_INFO={
  chat_5:['普通对话 5 次','真实对话行为上报'],
  first_buddy:['首次伙伴任务','当前只扫描展示，不由 runner 自动处理'],
  'Model_chat_GLM5.2':['GLM5.2 对话 1 次','真实对话行为上报'],
  RichMeow_Chat:['桌面连续对话','需要桌面指纹行为链'],
  Buddy_App:['Buddy 应用任务','需要应用行为链'],
  Buddy_App_QQ:['Buddy QQ 应用任务','需要应用行为链'],
  automation_1:['创建自动化任务 1 次','会上报自动化任务行为'],
  Library_read:['阅读资料库 1 次','会上报网页阅读行为'],
  template_5:['使用模板 5 次','会上报模板使用行为'],
  playbook_prompt:['发送案例提示词 1 次','会上报案例提示词行为'],
  create_canvas:['创建画布 1 次','会上报创建画布行为'],
  expert_5:['使用专家 5 次','会上报专家使用行为'],
  Expert_team_use_3:['使用团队专家 3 次','会上报团队专家行为'],
  Hp_Appearance:['应用外观主题 1 次','会上报主题应用行为'],
  skill_1:['使用技能 1 次','会上报技能使用行为'],
  Expert_lighthouse:['轻量云专家 1 次','会上报专家使用行为'],
  black_cat:['夜猫对话 3 次','仅 23:00-08:00（北京时间）处理']
};
function selectedAutoUids(){
  return Array.from(document.querySelectorAll('#autoAccountPicker input[data-auto-uid]'))
    .filter(el=>el.checked).map(el=>el.getAttribute('data-auto-uid'));
}
function selectedAutoTaskCodes(){
  return Array.from(document.querySelectorAll('#autoTaskPicker input[data-auto-task]'))
    .filter(el=>el.checked).map(el=>el.getAttribute('data-auto-task'));
}
function renderAutoAccountPicker(accounts,preferred){
  const box=$('#autoAccountPicker'); if(!box) return;
  const available=(accounts||[]).filter(a=>a&&a.uid).map(a=>({
    uid:String(a.uid), nickname:String(a.nickname||a.uid), realm:String(a.realm||'cn')
  }));
  savedAccounts=available;
  if(Array.isArray(preferred)){
    autoConfiguredUids=preferred.map(String);
    autoAccountsConfigured=true;
  }
  let selected;
  if(autoAccountsTouched){
    selected=available.map(a=>a.uid).filter(uid=>Array.isArray(autoAccountSelection)&&autoAccountSelection.includes(uid));
  }else if(autoAccountsConfigured){
    const wanted=autoConfiguredUids||[];
    selected=!wanted.length||wanted.includes('ALL')?available.map(a=>a.uid):available.map(a=>a.uid).filter(uid=>wanted.includes(uid));
  }else if(Array.isArray(autoAccountSelection)){
    selected=available.map(a=>a.uid).filter(uid=>autoAccountSelection.includes(uid));
  }else{
    selected=available.map(a=>a.uid);
  }
  autoAccountSelection=selected;
  if(!available.length){
    box.innerHTML='<p class="sub">暂无已保存账号。</p>';
    return;
  }
  const allChecked=selected.length===available.length;
  const rows=available.map(a=>'<label class="account-option"><input type="checkbox" data-auto-uid="'+esc(a.uid)+'"'+
    (selected.includes(a.uid)?' checked':'')+'><span><strong>'+esc(a.nickname)+'</strong><small>'+esc(a.uid)+' · '+esc(a.realm)+'</small></span></label>').join('');
  box.innerHTML='<div class="account-toolbar"><label><input type="checkbox" id="autoAccountsAll"'+(allChecked?' checked':'')+'> 全选</label>'+
    '<span id="autoAccountCount" class="help">已选 '+selected.length+' / '+available.length+'</span></div><div class="account-list">'+rows+'</div>';
}
function show(txt,ok){const m=$('#globalMsg');m.className='msg '+(ok?'ok':'err');m.textContent=txt;m.style.display='block';}
function showAuth(txt,ok){const m=$('#authMsg');m.className='msg '+(ok?'ok':'err');m.textContent=txt;m.style.display='block';}
function setBanner(html){const b=$('#banner');if(html){b.innerHTML=html;b.style.display='block';}else{b.style.display='none';}}
function moduleFromHash(){
  const name=(location.hash||'').slice(1).split('/').filter(Boolean)[0]||'';
  return MODULES.includes(name)?name:'overview';
}
function activateModule(name){
  if(!MODULES.includes(name)) name='overview';
  currentModule=name;
  document.querySelectorAll('.module').forEach(el=>el.classList.toggle('active',el.dataset.module===name));
  document.querySelectorAll('[data-module-link]').forEach(el=>{
    const active=el.getAttribute('data-module-link')===name;
    el.classList.toggle('active',active);
    if(active) el.setAttribute('aria-current','page'); else el.removeAttribute('aria-current');
  });
  if(location.hash!=='#/'+name) history.replaceState(null,'','#/'+name);
  if(name==='accounts') loadCredit(true);
  if(name==='overview'){ loadModels(true); }
  if(name==='platforms') loadPlatforms(true);
  if(name==='usage') loadUsage(true);
  if(name==='gateway'){ loadKeys(true); loadDeviceToken(true); }
  if(name==='automation') loadAutomation(true);
  if(name==='security') loadAdminAuth();
}
function routeModule(){activateModule(moduleFromHash());}
window.addEventListener('hashchange',routeModule);
async function api(path,body,timeoutMs){
  const headers={};
  if(body) headers['Content-Type']='application/json';
  if(authHeader) headers.Authorization=authHeader;
  const opt=body?{method:'POST',headers:headers,body:JSON.stringify(body)}:{headers:headers};
  const ms=timeoutMs||30000;
  const ctl=(typeof AbortController!=='undefined')?new AbortController():null;
  let timer=null;
  if(ctl){ opt.signal=ctl.signal; timer=setTimeout(()=>{try{ctl.abort();}catch(e){}},ms); }
  busy++;
  try{
    let r;
    try{ r=await fetch('/admin'+path,opt); }
    catch(e){
      if(e&&(e.name==='AbortError'||e.name==='TimeoutError'))
        throw new Error('请求超时（'+(ms/1000)+' 秒无响应），请刷新页面重试');
      throw e;
    }
    if(r.status===401){ showLogin('登录已过期，请重新登录。'); throw new Error('登录已过期'); }
    const t=await r.text();
    try{ return JSON.parse(t); }
    catch(e){ throw new Error('服务器返回非 JSON（HTTP '+r.status+'）：'+t.slice(0,120)); }
  }finally{
    if(timer)clearTimeout(timer);
    busy--;
  }
}
function formatCount(value){
  return formatTokenCount(value);
}
function formatTokenCount(value){
  const n=Number(value);
  if(!Number.isFinite(n)) return '--';
  return Math.abs(n)>=1000000?(n/1000000).toFixed(2)+'M':n.toLocaleString('zh-CN');
}
function usageTokenValue(value){
  return value===null||value===undefined||value===''?'--':esc(formatTokenCount(value));
}
function usagePercentValue(value){
  if(value===null||value===undefined||value==='') return '--';
  const n=Number(value);
  return Number.isFinite(n)&&n>=0&&n<=1?(n*100).toFixed(1)+'%':'--';
}
async function refresh(){
  try{
  const d=await api('/api/state');
  if(!d||!d.accounts) throw new Error((d&&d.error)||'返回数据异常');
  const h=(d.gw&&d.gw.healthz)||{};
  const st=(d.gw&&d.gw.status)||{};
  const up=!st._error;
  const tokens=(d.tokens&&d.tokens.available)?d.tokens:null;
  const tokenSuffix=(tokens&&tokens.stale)?'（缓存）':'';
  $('#stats').innerHTML=[
    ['账号文件数',d.accounts.length],
    ['健康账号',up?((st.healthy??0)+' / '+(st.total??0)):'-'],
    ['网关',up?'正常':'不可达'],
    ['总 Token'+tokenSuffix,tokens?formatCount(tokens.total_tokens):'--'],
    ['今日 Token'+tokenSuffix,tokens?formatCount(tokens.today_tokens):'--']
  ].map(([k,v])=>`<div class="stat"><div class="k">${k}</div><div class="v">${v}</div></div>`).join('');
  const rows=d.accounts.map(a=>`<tr><td class="mono">${esc(a.uid||'-')}</td><td>${esc(a.nickname||'-')}</td><td>${esc(a.realm)}</td><td class="mono">${esc(a.file)}</td>
    <td><button class="danger" data-act="delacct" data-uid="${esc(a.uid)}" data-file="${esc(a.file)}">删除</button></td></tr>`).join('');
  $('#accounts').innerHTML=d.accounts.length?`<div class="table-scroll"><table><tr><th>UID</th><th>昵称</th><th>域</th><th>文件</th><th></th></tr>${rows}</table></div>`:'<p class="sub">暂无账号，用上方「添加账号」接入。</p>';
  renderAutoAccountPicker(d.accounts);
  $('#raw').textContent=JSON.stringify({healthz:h,status:st},null,2);
  }catch(e){ $('#raw').textContent='加载失败：'+e.message; }
}
function renderModels(d){
  const box=$('#modelBox'); if(!box) return;
  const models=Array.isArray(d.models)?d.models:[];
  if(!models.length){
    box.innerHTML='<p class="sub">'+(d.account_count?'暂未读取到模型倍率。':'暂无已保存账号。')+'</p>';
  }else{
    const rows=models.map(m=>{
      const credits=Array.isArray(m.credits)?m.credits.filter(Boolean):[];
      const credit=credits.length?credits.join(' / '):'未返回';
      return '<tr><td class="mono">'+esc(m.id||'-')+'</td><td class="credit">'+esc(credit)+'</td></tr>';
    }).join('');
    box.innerHTML='<div class="table-scroll"><table class="model-table"><tr><th>模型</th><th>积分倍率</th></tr>'+rows+'</table></div>';
  }
  if(Array.isArray(d.errors)&&d.errors.length){
    box.innerHTML+='<p class="sub" style="margin:10px 0 0">部分账号读取失败：'+
      d.errors.map(e=>esc((e.account||'账号')+'：'+(e.error||'未知错误'))).join('；')+'</p>';
  }
}
async function loadModels(silent,force){
  const box=$('#modelBox');
  if(!silent&&box) box.innerHTML='<p class="sub">正在读取模型倍率…</p>';
  try{
    const r=await api('/api/models'+(force?'?refresh=1':''),null,45000);
    if(!r.ok){
      if(!silent&&box) box.innerHTML='<div class="msg err" style="display:block">读取失败：'+esc(r.error||'未知错误')+'</div>';
      return;
    }
    renderModels(r); lastModels=Date.now();
  }catch(e){
    if(!silent&&box) box.innerHTML='<div class="msg err" style="display:block">请求失败：'+esc(e.message)+'</div>';
  }
}
function renderPlatforms(d){
  const box=$('#platformBox'); if(!box) return;
  const platforms=Array.isArray(d.platforms)?d.platforms:[];
  if(!platforms.length){ box.innerHTML='<p class="sub">暂未读取到平台信息。</p>'; return; }
  const statusText={active:'已接入',passthrough:'透传'};
  box.innerHTML='<div class="platform-grid">'+platforms.map(p=>{
    const badge=statusText[p.status]||'已配置';
    const badgeClass=p.status==='passthrough'?' passthrough':'';
    const url=p.base_url?'<a href="'+esc(p.base_url)+'" target="_blank" rel="noopener">'+esc(p.base_url)+'</a>':'--';
    const count=p.account_count===null||p.account_count===undefined?'不适用':String(p.account_count);
    const features=Array.isArray(p.features)?p.features.map(x=>'<li>'+esc(x)+'</li>').join(''):'';
    return '<article class="platform-card"><div class="platform-head"><strong>'+esc(p.name||p.id)+'</strong><span class="platform-badge'+badgeClass+'">'+badge+'</span></div>'+
      '<dl><dt>类型</dt><dd>'+esc(p.type||'--')+'</dd><dt>入口</dt><dd>'+url+'</dd><dt>认证</dt><dd>'+esc(p.auth||'--')+'</dd><dt>用量归属</dt><dd>'+esc(p.usage||'--')+'</dd><dt>账号数</dt><dd>'+esc(count)+'</dd></dl>'+
      (features?'<ul class="platform-features">'+features+'</ul>':'')+'</article>';
  }).join('')+'</div>';
}
async function loadPlatforms(silent){
  const box=$('#platformBox');
  if(!silent&&box) box.innerHTML='<p class="sub">正在读取平台信息…</p>';
  try{
    const r=await api('/api/platforms');
    if(!r.ok){ if(!silent&&box) box.innerHTML='<div class="msg err" style="display:block">读取失败：'+esc(r.error||'未知错误')+'</div>'; return; }
    renderPlatforms(r);
  }catch(e){ if(!silent&&box) box.innerHTML='<div class="msg err" style="display:block">请求失败：'+esc(e.message)+'</div>'; }
}
async function loadAdminAuth(){
  try{ const a=await api('/api/admin-auth'); if(a.ok&&a.username) $('#adminUser').value=a.username; }
  catch(e){ showAuth('读取当前登录凭据失败：'+e.message,false); }
}
$('#btnStart').onclick=async()=>{
  curRealm=$('#realm').value; $('#btnStart').disabled=true; show('正在获取授权链接…',true);
  try{
    const r=await api('/api/login/start',{realm:curRealm});
    if(r.ok){$('#urlbox').style.display='block';
      $('#urlbox').innerHTML='授权链接（点击在新标签打开）：<br><a href="'+r.url+'" target="_blank" rel="noopener">'+r.url+'</a>';
      $('#btnFinish').disabled=false; show('请在浏览器完成登录，然后点第 2 步。',true);}
    else show('失败：'+(r.error||'未知错误'),false);
  }catch(e){ show('请求失败：'+e.message,false); }
  finally{ $('#btnStart').disabled=false; }
};
$('#btnFinish').onclick=async()=>{
  $('#btnFinish').disabled=true; show('正在轮询登录结果（可能需要十几秒）…',true);
  try{
    const r=await api('/api/login/finish',{realm:curRealm});
    if(r.ok){show('添加成功：'+(r.nickname||r.uid)+'，容器已重启加载。',true);$('#urlbox').style.display='none';refresh();}
    else show('失败：'+(r.error||'未知错误'),false);
  }catch(e){ show('请求失败：'+e.message,false); }
  finally{ $('#btnFinish').disabled=false; }
};
async function del(uid,file){
  if(!confirm('确定删除账号 '+uid+' 吗？'))return;
  try{
    const r=await api('/api/account/delete',{uid:uid,file:file});
    if(r.ok){show('已删除并重启容器。',true);refresh();}else show('失败：'+(r.error||''),false);
  }catch(e){ show('请求失败：'+e.message,false); }
}
const esc=(s)=>String(s==null?'':s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
async function loadCredit(silent){
  const box=$('#creditBox');
  if(!silent) box.innerHTML='<p class="sub">正在查询积分…</p>';
  try{
    const r=await api('/api/credit',null,90000);
    if(!r.ok){
      if(!silent) box.innerHTML='<div class="msg err" style="display:block">查询失败：'+esc(r.error||'未知错误')+'</div>';
      return;
    }
    const d=r.data||{}, t=d.total||{}, accs=d.accounts||[];
    const remain=t.remain??0, size=t.size??0, used=t.used??0;
    const pct=size>0?Math.round(remain*100/size):0;
    let h='<div class="grid">'+
      '<div class="stat"><div class="k">剩余积分</div><div class="v">'+remain+'</div></div>'+
      '<div class="stat"><div class="k">总额度</div><div class="v">'+size+'</div></div>'+
      '<div class="stat"><div class="k">已用</div><div class="v">'+used+'</div></div>'+
      '<div class="stat"><div class="k">剩余比例</div><div class="v">'+pct+'%</div></div></div>';
    h+='<div class="bar"><i style="width:'+pct+'%;background:'+(pct<20?'var(--bad)':'var(--ok)')+'"></i></div>';
    if(accs.length){
      h+='<div class="table-scroll" style="margin-top:16px"><table><tr><th>账号</th><th>UID</th><th>剩余</th><th>已用</th><th>总额</th><th>状态</th></tr>'+
        accs.map(a=>'<tr><td>'+esc(a.nickname||'-')+'</td><td class="mono">'+esc(String(a.uid||'').slice(0,8))+'…</td>'+
        '<td>'+(a.remain??'-')+'</td><td>'+(a.used??'-')+'</td><td>'+(a.size??'-')+'</td>'+
        '<td>'+(a.ok?'<span style="color:var(--ok)">正常</span>':'<span style="color:var(--bad)">'+esc(a.error||'失败')+'</span>')+'</td></tr>').join('')+'</table></div>';
    }else{
      h+='<p class="sub" style="margin:12px 0 0">暂无账号，添加账号后可查看积分明细。</p>';
    }
    box.innerHTML=h;
  }catch(e){ if(!silent) box.innerHTML='<div class="msg err" style="display:block">请求失败：'+esc(e.message)+'</div>'; }
}
$('#btnCredit').onclick=()=>loadCredit();
$('#btnModels').onclick=()=>loadModels(false,true);

function usageValue(value){
  return value===null||value===undefined||value===''?'--':esc(String(value));
}
function usageTime(value){
  if(value===null||value===undefined||value==='') return '--';
  try{
    let date;
    const stamp=Number(value);
    if(Number.isFinite(stamp)&&stamp>0) date=new Date(stamp*1000);
    else if(typeof value==='string') date=new Date(value);
    if(!date||Number.isNaN(date.getTime())) return '--';
    return esc(date.toLocaleString());
  }catch(e){return '--';}
}
function usageMetric(obj,names){
  for(const name of names){
    if(obj&&obj[name]!==undefined&&obj[name]!==null&&obj[name]!=='') return obj[name];
  }
  return null;
}
function renderRecentRequestRecords(records,available){
  const box=$('#recentUsageBox'); if(!box) return;
  if(!available){
    box.innerHTML='<p class="sub">当前网关未提供逐请求记录；旧版本只能显示累计统计或积分快照。</p>';
    return;
  }
  if(!Array.isArray(records)||!records.length){
    box.innerHTML='<p class="sub">暂无请求记录。</p>';
    return;
  }
  const rows=records.slice(0,20).map(record=>{
    const account=usageMetric(record,['nickname','uid'])||'-';
    const uid=usageMetric(record,['uid']);
    const realm=usageMetric(record,['realm','domain'])||'-';
    const model=usageMetric(record,['model','model_id'])||'-';
    const mode=usageMetric(record,['mode'])||'-';
    const status=usageMetric(record,['status']);
    const statusText=status===null||status===undefined||status===''?'--':
      (Number(status)===200?'成功':('失败 '+String(status)));
    const input=usageMetric(record,['input_tokens','prompt_tokens','inputToken']);
    const cachedInput=usageMetric(record,['cached_input_tokens','cache_hit_tokens','cached_tokens']);
    const cacheHitRate=usageMetric(record,['cache_hit_rate']);
    const output=usageMetric(record,['output_tokens','completion_tokens','outputToken']);
    const totalTokens=usageMetric(record,['total_tokens','totalTokens']);
    const credits=usageMetric(record,['credits','credit','cost']);
    return '<tr><td>'+usageTime(record&&record.at)+'</td><td>'+usageValue(account)+
      (uid&&String(uid)!==String(account)?'<small class="mono">'+usageValue(uid)+'</small>':'')+
      '</td><td>'+usageValue(realm)+'</td><td class="mono">'+usageValue(model)+
      '</td><td>'+usageValue(mode)+'</td><td>'+usageValue(statusText)+
      '</td><td>'+usageTokenValue(input)+'</td><td>'+usageTokenValue(cachedInput)+
      '</td><td>'+usagePercentValue(cacheHitRate)+'</td><td>'+usageTokenValue(output)+
      '</td><td>'+usageTokenValue(totalTokens)+'</td><td class="credit">'+usageValue(credits)+'</td></tr>';
  }).join('');
  box.innerHTML='<div class="table-scroll"><table class="usage-table recent-usage"><tr><th>时间</th><th>账号</th><th>域</th><th>模型</th><th>模式</th><th>状态</th><th>输入 Token</th><th>缓存输入 Token</th><th>命中率</th><th>输出 Token</th><th>总 Token</th><th>积分</th></tr>'+rows+'</table></div>';
}
function renderUsage(d){
  const summary=$('#usageSummary'), recentBox=$('#recentUsageBox'), box=$('#usageBox');
  if(!summary||!recentBox||!box) return;
  if(!d||!d.ok){
    summary.innerHTML='<div class="msg err" style="display:block">查询失败：'+esc((d&&d.error)||'未知错误')+'</div>';
    recentBox.innerHTML='';
    box.innerHTML='';
    return;
  }
  renderRecentRequestRecords(d.recent, d.recent_available===true);
  const total=(d.current&&d.current.total)||{};
  const remain=usageMetric(total,['remain']), used=usageMetric(total,['used']), size=usageMetric(total,['size']);
  const numericSize=Number(size), numericRemain=Number(remain);
  const pct=Number.isFinite(numericSize)&&numericSize>0&&Number.isFinite(numericRemain)?
    Math.max(0,Math.min(100,Math.round(numericRemain*100/numericSize))):0;
  summary.innerHTML='<div class="grid">'+
    '<div class="stat"><div class="k">当前剩余</div><div class="v">'+usageValue(remain)+'</div></div>'+
    '<div class="stat"><div class="k">累计已用</div><div class="v">'+usageValue(used)+'</div></div>'+
    '<div class="stat"><div class="k">总额度</div><div class="v">'+usageValue(size)+'</div></div>'+
    '<div class="stat"><div class="k">剩余比例</div><div class="v">'+pct+'%</div></div></div>'+
    '<div class="bar"><i style="width:'+pct+'%;background:'+(pct<20?'var(--bad)':'var(--ok)')+'"></i></div>';

  if(d.mode==='gateway'){
    const accounts=d.stats&&Array.isArray(d.stats.accounts)?d.stats.accounts:[];
    if(accounts.length){
      const rows=accounts.map(account=>{
        const m=account&&typeof account==='object'?account:{};
        const uid=usageMetric(m,['uid','account_id','account_uid']);
        const nickname=usageMetric(m,['nickname','account','name'])||uid||'-';
        const accountCell='<strong>'+usageValue(nickname)+'</strong>'+
          (uid&&String(uid)!==String(nickname)?'<small class="mono">'+usageValue(uid)+'</small>':'');
        const realm=usageMetric(m,['realm','domain']);
        const name=usageMetric(m,['model','model_id','id','name']);
        const requests=usageMetric(m,['requests','request_count','total_requests']);
        const input=usageMetric(m,['input_tokens','prompt_tokens','inputToken']);
        const output=usageMetric(m,['output_tokens','completion_tokens','outputToken']);
        const totalTokens=usageMetric(m,['total_tokens','totalTokens']);
        const credits=usageMetric(m,['credits','used_credits','credit','cost']);
        const lastSeen=usageMetric(m,['last_seen','lastSeen']);
        return '<tr><td class="account">'+accountCell+'</td><td>'+usageValue(realm)+
          '</td><td class="mono">'+usageValue(name)+'</td><td>'+usageValue(requests)+
          '</td><td>'+usageTokenValue(input)+'</td><td>'+usageTokenValue(output)+
          '</td><td>'+usageTokenValue(totalTokens)+'</td><td class="credit">'+usageValue(credits)+
          '</td><td>'+usageTime(lastSeen)+'</td></tr>';
      }).join('');
      box.innerHTML='<p class="sub">记录来源：网关按账号 + 模型累计；网关重启后重新累计。</p>'+
        '<div class="table-scroll"><table class="usage-table account-usage"><tr><th>账号</th><th>域</th><th>模型</th><th>请求数</th><th>输入 Token</th><th>输出 Token</th><th>总 Token</th><th>积分</th><th>最后使用</th></tr>'+rows+'</table></div>';
      return;
    }
    const models=d.stats&&Array.isArray(d.stats.models)?d.stats.models:[];
    if(!models.length){
      box.innerHTML='<p class="sub">网关暂未返回按模型统计。</p>';
      return;
    }
    const rows=models.map(model=>{
      const m=model&&typeof model==='object'?model:{};
      const name=usageMetric(m,['model','model_id','id','name']);
      const requests=usageMetric(m,['requests','request_count','total_requests']);
      const input=usageMetric(m,['input_tokens','prompt_tokens','inputToken']);
      const output=usageMetric(m,['output_tokens','completion_tokens','outputToken']);
      const totalTokens=usageMetric(m,['total_tokens','totalTokens']);
      const credits=usageMetric(m,['credits','used_credits','credit','cost']);
      return '<tr><td class="mono">'+usageValue(name)+'</td><td>'+usageValue(requests)+
        '</td><td>'+usageTokenValue(input)+'</td><td>'+usageTokenValue(output)+'</td><td>'+usageTokenValue(totalTokens)+
        '</td><td class="credit">'+usageValue(credits)+'</td></tr>';
    }).join('');
    box.innerHTML='<p class="sub">记录来源：网关按模型统计。</p><div class="table-scroll"><table class="usage-table"><tr><th>模型</th><th>请求数</th><th>输入 Token</th><th>输出 Token</th><th>总 Token</th><th>积分</th></tr>'+rows+'</table></div>';
    return;
  }

  const records=Array.isArray(d.records)?d.records:[];
  if(!records.length){
    box.innerHTML='<p class="sub">暂无记录。点击“刷新”后会保存一次积分快照。</p>';
    return;
  }
  const rows=records.map(record=>{
    const delta=record&&record.delta_used;
    const hasDelta=delta!==null&&delta!==undefined&&delta!==''&&Number.isFinite(Number(delta));
    const deltaText=hasDelta?(Number(delta)>0?'+'+Number(delta):String(Number(delta))):'--';
    const deltaClass=hasDelta&&Number(delta)>0?'delta':'delta neutral';
    const account=record&&record.nickname?record.nickname:(record&&record.uid?record.uid:'-');
    return '<tr><td>'+usageTime(record&&record.at)+'</td><td>'+esc(account)+'</td>'+
      '<td>'+usageValue(record&&record.used)+'</td><td class="'+deltaClass+'">'+esc(deltaText)+'</td>'+
      '<td>'+usageValue(record&&record.remain)+'</td></tr>';
  }).join('');
  box.innerHTML='<p class="sub">记录来源：积分查询快照；本次增加量按相邻两次查询的已用积分计算。</p>'+
    '<div class="table-scroll"><table class="usage-table"><tr><th>时间</th><th>账号</th><th>已用</th><th>本次增加</th><th>剩余</th></tr>'+rows+'</table></div>';
}
async function loadUsage(silent){
  const summary=$('#usageSummary'), recentBox=$('#recentUsageBox'), box=$('#usageBox');
  if(!silent&&summary&&recentBox&&box){
    summary.innerHTML='<p class="sub">正在查询积分使用记录…</p>';
    recentBox.innerHTML='<p class="sub">加载中…</p>';
    box.innerHTML='';
  }
  try{
    const r=await api('/api/usage',null,90000);
    if(!r.ok){
      if(!silent&&summary) summary.innerHTML='<div class="msg err" style="display:block">查询失败：'+esc(r.error||'未知错误')+'</div>';
      return;
    }
    renderUsage(r); lastUsage=Date.now();
  }catch(e){
    if(!silent&&summary) summary.innerHTML='<div class="msg err" style="display:block">请求失败：'+esc(e.message)+'</div>';
  }
}
$('#btnUsage').onclick=()=>loadUsage(false);

$('#btnSaveAuth').onclick=async()=>{
  const username=$('#adminUser').value.trim(), password=$('#adminPass').value;
  if(!username){ showAuth('请填写用户名。',false); return; }
  const tip=password?'确定修改用户名和密码吗？':'确定修改用户名吗？密码将保持不变。';
  if(!confirm(tip))return;
  $('#btnSaveAuth').disabled=true; showAuth('正在更新并应用登录凭据…',true);
  try{
    const r=await api('/api/admin-auth',{username:username,password:password});
    if(r.ok){
      const pair=decodeBasicAuth(authHeader), nextPassword=password||(pair&&pair[1]);
      if(nextPassword){ authHeader=makeBasicAuth(username,nextPassword); persistAuth(); }
      $('#adminPass').value=''; showAuth('保存成功：'+r.username+'。已立即生效。',true);
    }
    else showAuth('保存失败：'+esc(r.error||'未知错误'),false);
  }catch(e){ showAuth('请求失败：'+esc(e.message),false); }
  finally{ $('#btnSaveAuth').disabled=false; }
};

let keyReveal={};
let keyPlatforms=[];
let selectedKeyPlatform='workbuddy';
const maskKey=(k)=>k.length>14?k.slice(0,10)+'••••••••••••'+k.slice(-4):k;
function currentKeyPlatform(){
  return keyPlatforms.find(p=>p.id===selectedKeyPlatform)||keyPlatforms[0]||null;
}
function renderKeyPlatform(){
  const select=$('#keyPlatform'), info=$('#keyPlatformInfo'), p=currentKeyPlatform();
  if(!select||!info||!p) return;
  if(select.value!==p.id) select.value=p.id;
  info.textContent=p.name+' · '+p.base_url+' · 使用同一把 Kasa2API 通用 Key';
}
function renderKeyTable(){
  const box=$('#keysBox'), keys=window.__keys||[], p=currentKeyPlatform();
  if(!box) return;
  let h='';
  if(!keys.length){ h='<p class="sub">还没有 Key，在上方创建一个。</p>'; }
  else{
    h='<div class="table-scroll"><table><tr><th>备注</th><th>Key</th><th>适用范围</th><th>创建时间</th><th>状态</th><th></th></tr>';
    h+=keys.map(k=>{
      const rv=!!keyReveal[k.id];
      return '<tr><td>'+esc(k.name)+(k.system?' <span class="badge badge-brand">内置</span>':'')+'</td>'+
      '<td class="mono" style="word-break:break-all;max-width:340px">'+esc(rv?k.key:maskKey(k.key))+
      ' <button class="ghost" style="padding:2px 8px;font-size:12px" data-act="reveal" data-id="'+esc(k.id)+'">'+(rv?'隐藏':'显示')+'</button>'+
      ' <button class="ghost" style="padding:2px 8px;font-size:12px" data-act="copy" data-id="'+esc(k.id)+'">复制</button></td>'+
      '<td><span style="color:var(--ok)">WorkBuddy / Responses 共用</span></td>'+
      '<td>'+new Date((k.created_at||0)*1000).toLocaleDateString()+'</td>'+
      '<td>'+(k.enabled?'<span style="color:var(--ok)">启用</span>':'<span style="color:var(--mut)">已停用</span>')+'</td>'+
      '<td><button class="ghost" data-act="toggle" data-id="'+esc(k.id)+'">'+(k.enabled?'停用':'启用')+'</button>'+
      (k.system?'':' <button class="danger" data-act="delkey" data-id="'+esc(k.id)+'">删除</button>')+'</td></tr>';
    }).join('');
    h+='</table></div>';
  }
  h+='<div class="urlbox" style="margin-top:12px">当前平台 Base URL：<b>'+esc(p&&p.base_url||'')+'</b></div>';
  box.innerHTML=h;
}
async function loadKeys(silent){
  const box=$('#keysBox');
  if(!silent) box.innerHTML='<p class="sub">加载中…</p>';
  try{
    const r=await api('/api/keys');
    if(!r.ok){
      if(!silent) box.innerHTML='<div class="msg err" style="display:block">'+esc(r.error||'加载失败')+'</div>';
      return;
    }
    window.__keys=r.keys||[];
    keyPlatforms=Array.isArray(r.platforms)?r.platforms:[];
    const select=$('#keyPlatform');
    if(select){
      const current=selectedKeyPlatform;
      select.innerHTML=keyPlatforms.map(p=>'<option value="'+esc(p.id)+'">'+esc(p.name)+'</option>').join('');
      selectedKeyPlatform=keyPlatforms.some(p=>p.id===current)?current:(keyPlatforms[0]&&keyPlatforms[0].id)||'workbuddy';
      select.value=selectedKeyPlatform;
    }
    renderKeyPlatform();
    renderKeyTable();
  }catch(e){ if(!silent) box.innerHTML='<div class="msg err" style="display:block">请求失败：'+esc(e.message)+'</div>'; }
}
$('#keyPlatform').onchange=()=>{ selectedKeyPlatform=$('#keyPlatform').value||'workbuddy'; renderKeyPlatform(); renderKeyTable(); };
async function loadDeviceToken(silent){
  const el=$('#deviceTokenStatus');
  if(!el) return;
  try{
    const r=await api('/api/device-token');
    if(!r.ok){
      el.textContent=r.error||'读取设备码失败';
      return;
    }
    if(r.configured){
      el.innerHTML='已配置设备码：<code>'+esc(r.masked)+'</code>（长度 '+esc(r.len)+' 字符，来源：'+esc(r.source)+'）';
    }else{
      el.textContent='当前未配置设备码（如遇 11128 渠道拦截错误，请在此填入专属设备码）。';
    }
  }catch(e){
    if(!silent) el.textContent='读取设备码失败：'+e.message;
  }
}
const btnSaveDeviceToken=$('#btnSaveDeviceToken');
if(btnSaveDeviceToken){
  btnSaveDeviceToken.onclick=async()=>{
    const input=$('#deviceTokenInput');
    const token=(input.value||'').trim();
    if(token && (token.length < 10 || token.length > 128)){
      alert('设备码长度应在 10 到 128 字符之间。');
      return;
    }
    const msg = token ? '确认保存新设备码并重启网关吗？' : '确认清除设备码并重启网关吗？';
    if(!confirm(msg)) return;
    btnSaveDeviceToken.disabled=true;
    try{
      const r=await api('/api/device-token', {method:'POST', body:JSON.stringify({device_token:token})});
      if(!r.ok){
        alert('保存失败：'+(r.error||'未知错误'));
      }else{
        input.value='';
        alert(r.info||'设备码已保存，网关已重启生效。');
        await loadDeviceToken();
      }
    }catch(e){
      alert('请求失败：'+e.message);
    }finally{
      btnSaveDeviceToken.disabled=false;
    }
  };
}
function toggleReveal(id){ keyReveal[id]=!keyReveal[id]; loadKeys(); }
// Delegated click handling
document.addEventListener('click',(e)=>{
  const b=(e.target&&e.target.closest)?e.target.closest('button[data-act]'):null;
  if(!b) return;
  const act=b.getAttribute('data-act'), id=b.getAttribute('data-id');
  if(act==='reveal') toggleReveal(id);
  else if(act==='copy') copyKey(id);
  else if(act==='toggle') toggleKey(id);
  else if(act==='delkey') delKey(id);
  else if(act==='delacct') del(b.getAttribute('data-uid'), b.getAttribute('data-file'));
});
document.addEventListener('change',(e)=>{
  const target=e.target;
  if(!target||!target.closest) return;
  if(target.closest('#autoAccountPicker')){
    autoAccountsTouched=true;
    const boxes=Array.from(document.querySelectorAll('#autoAccountPicker input[data-auto-uid]'));
    if(target.id==='autoAccountsAll') boxes.forEach(el=>{el.checked=target.checked;});
    autoAccountSelection=boxes.filter(el=>el.checked).map(el=>el.getAttribute('data-auto-uid'));
    const all=$('#autoAccountsAll'), count=$('#autoAccountCount');
    if(all) all.checked=boxes.length>0&&autoAccountSelection.length===boxes.length;
    if(count) count.textContent='已选 '+autoAccountSelection.length+' / '+boxes.length;
    return;
  }
  if(target.closest('#autoTaskPicker')){
    taskSelectionTouched=true;
    const boxes=Array.from(document.querySelectorAll('#autoTaskPicker input[data-auto-task]'));
    if(target.id==='autoTasksAll') boxes.forEach(el=>{el.checked=target.checked;});
    taskSelection=boxes.filter(el=>el.checked).map(el=>el.getAttribute('data-auto-task'));
    const all=$('#autoTasksAll'), count=$('#autoTaskCount');
    if(all) all.checked=boxes.length>0&&taskSelection.length===boxes.length;
    if(count) count.textContent='已选 '+taskSelection.length+' / '+boxes.length;
  }
});
function copyKey(id){
  const k=(window.__keys||[]).find(x=>x.id===id); if(!k) return;
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(k.key).then(()=>show('已复制到剪贴板',true)).catch(()=>show('复制失败，请点「显示」后手动复制',false));
  } else show('当前环境不支持自动复制，请点「显示」后手动复制',false);
}
$('#btnNewKey').onclick=async()=>{
  const name=$('#keyName').value.trim();
  $('#btnNewKey').disabled=true; show('正在创建并应用到网关…',true);
  try{
    const r=await api('/api/keys/create',{name:name});
    if(r.ok){ $('#keyName').value=''; keyReveal[r.key.id]=true;
      show('创建成功：'+r.key.name+'，网关已更新生效。',true); loadKeys(); }
    else show('创建失败：'+esc(r.error||'未知错误'),false);
  }catch(e){ show('请求失败：'+esc(e.message),false); }
  finally{ $('#btnNewKey').disabled=false; }
};
async function toggleKey(id){
  try{
    const r=await api('/api/keys/toggle',{id:id});
    if(r.ok){ show(r.key.enabled?'已启用该 Key。':'已停用该 Key（立即失效）。',true); loadKeys(); }
    else show('操作失败：'+esc(r.error||''),false);
  }catch(e){ show('请求失败：'+esc(e.message),false); }
}
async function delKey(id){
  if(!confirm('确定删除这把 Key 吗？使用它的客户端会立即失去访问权限。'))return;
  try{
    const r=await api('/api/keys/delete',{id:id});
    if(r.ok){ show('已删除，网关已更新。',true); loadKeys(); }
    else show('删除失败：'+esc(r.error||''),false);
  }catch(e){ show('请求失败：'+esc(e.message),false); }
}
// WorkBuddy Automation
function autoText(v){ return Array.isArray(v)?v.join(','):String(v==null?'':v); }
function renderGatewayAutomation(d){
  const box=$('#gatewayAutomationStatus'); if(!box) return;
  const s=d.gateway_schedule||{};
  $('#gatewayCheckinEnabled').checked=!!s.checkin_enabled;
  $('#gatewayCheckinHours').value=autoText(s.checkin_hours);
  $('#gatewayTravelEnabled').checked=!!s.travel_enabled;
  $('#gatewayTravelHours').value=autoText(s.travel_hours);
  box.textContent='签到：'+(s.checkin_enabled?'已开启':'已关闭')+'（'+autoText(s.checkin_hours||[])+' 点）\\n'+
    '旅行：'+(s.travel_enabled?'已开启':'已关闭')+'（'+autoText(s.travel_hours||[])+' 点）';
}
function renderTaskPicker(codes,blocked,preferred){
  const box=$('#autoTaskPicker'); if(!box) return;
  const available=(codes||[]).map(String).filter((code,i,list)=>code&&list.indexOf(code)===i);
  const blockedCodes=(blocked||[]).map(String).filter((code,i,list)=>code&&list.indexOf(code)===i);
  availableTaskCodes=available;
  if(Array.isArray(preferred)){
    configuredTaskCodes=preferred.map(String);
    taskSelectionConfigured=true;
  }
  let selected;
  if(taskSelectionTouched){
    selected=available.filter(code=>Array.isArray(taskSelection)&&taskSelection.includes(code));
  }else if(taskSelectionConfigured){
    const wanted=configuredTaskCodes||[];
    selected=available.filter(code=>wanted.includes(code));
  }else if(Array.isArray(taskSelection)){
    selected=available.filter(code=>taskSelection.includes(code));
  }else{
    selected=[];
  }
  taskSelection=selected;
  if(!available.length&&!blockedCodes.length){
    box.innerHTML='<p class="sub">没有读取到可执行任务，请先点击“只读查看任务”。</p>';
    return;
  }
  const allChecked=available.length>0&&selected.length===available.length;
  const rows=available.map(code=>{
    const info=AUTO_TASK_INFO[code]||['服务端任务','以只读扫描结果为准'];
    return '<label class="task-option"><input type="checkbox" data-auto-task="'+esc(code)+'"'+
      (selected.includes(code)?' checked':'')+'><span><strong>'+esc(info[0])+'</strong><small>'+esc(code)+' · '+esc(info[1])+'</small></span></label>';
  });
  blockedCodes.forEach(code=>{
    const info=AUTO_TASK_INFO[code]||['人工任务','需要人工完成'];
    rows.push('<div class="task-option task-option-disabled"><input type="checkbox" disabled><span><strong>'+esc(info[0])+'</strong><small>'+esc(code)+' · 暂不支持自动执行</small></span></div>');
  });
  box.innerHTML='<div class="task-toolbar"><label><input type="checkbox" id="autoTasksAll"'+(allChecked?' checked':'')+'> 全选可执行任务</label>'+
    '<span id="autoTaskCount" class="help">已选 '+selected.length+' / '+available.length+'</span></div><div class="task-picker">'+rows.join('')+'</div>';
}
function renderAutomation(d){
  const c=d.config||{}, s=d.state||{}, box=$('#automationBox');
  renderGatewayAutomation(d);
  $('#autoTaskEnabled').checked=!!c.task_scheduler_enabled;
  $('#autoTaskHours').value=autoText(c.task_hours);
  $('#autoTaskGap').value=c.task_gap_seconds||1.2;
  const taskCodes=Array.isArray(d.task_codes)?d.task_codes.slice():Object.keys(AUTO_TASK_INFO);
  availableTaskCodes=taskCodes;
  renderAutoAccountPicker(savedAccounts,c.task_uids);
  renderTaskPicker(taskCodes,d.blocked_task_codes,c.task_codes);
  const run=s.running?'执行中':'空闲';
  box.textContent='定时执行：'+(c.task_scheduler_enabled?'已开启':'已关闭')+' · 当前状态：'+run+'\\n'+
    '执行小时：'+autoText(c.task_hours)+'（VPS 本地时间） · 动作间隔：'+c.task_gap_seconds+' 秒\\n'+
    '账号范围：'+(autoText(c.task_uids)||'全部')+' · 已选任务：'+(autoText(c.task_codes)||'未选择')+'\\n'+
    (s.message||'');
  const log=$('#automationLog');
  if(s.output){ log.style.display='block'; log.textContent=s.output; }
  else { log.style.display='none'; log.textContent=''; }
}
async function loadAutomation(silent){
  try{
    const r=await api('/api/automation/status');
    if(r.ok) renderAutomation(r);
    else if(!silent) $('#automationBox').textContent='加载失败：'+(r.error||'未知错误');
  }catch(e){ if(!silent) $('#automationBox').textContent='请求失败：'+e.message; }
}
async function startAutomation(body, message, timeoutMs){
  try{
    const r=await api('/api/automation/run',body,timeoutMs||30000);
    if(r.ok){ show(message,true); loadAutomation(); }
    else show('自动化启动失败：'+esc(r.error||r.message||'未知错误'),false);
  }catch(e){ show('自动化请求失败：'+esc(e.message),false); }
}
function selectedAccountsOrError(){
  const uids=selectedAutoUids();
  if(!uids.length){ show('请至少选择一个已保存账号。',false); return null; }
  return uids;
}
$('#btnAutoCheckin').onclick=()=>startAutomation({action:'checkin'},'签到检查已启动。');
$('#btnAutoScan').onclick=()=>{
  const uids=selectedAccountsOrError(); if(!uids) return;
  startAutomation({action:'scan',uids:uids},'只读任务查询已启动，不会提交任务行为。');
};
$('#btnAutoRun').onclick=()=>{
  const codes=selectedAutoTaskCodes();
  const uids=selectedAccountsOrError(); if(!uids) return;
  if(!codes.length){ show('请至少勾选一个成长任务；全部可执行任务请使用“一键完成所有任务”。',false); return; }
  if(!confirm('将执行 '+codes.join(', ')+'。这会向 WorkBuddy 上报行为，部分任务可能产生真实对话、消耗额度或领奖。确认继续吗？'))return;
  startAutomation({action:'tasks',uids:uids,task_codes:codes,confirm:true},'成长任务已启动，结果会显示在下方。');
};
$('#btnAutoRunAll').onclick=()=>{
  const uids=selectedAccountsOrError(); if(!uids) return;
  const codes=availableTaskCodes.length?availableTaskCodes.slice():Object.keys(AUTO_TASK_INFO);
  if(!codes.length){ show('暂时没有可执行的任务。',false); return; }
  if(!confirm('将对 '+uids.length+' 个账号执行全部 '+codes.length+' 个可执行任务，可能产生真实对话、消耗额度或领奖。确认继续吗？'))return;
  startAutomation({action:'tasks',uids:uids,task_codes:codes,confirm:true},'全部任务已启动，结果会显示在下方。');
};
function parseHourList(raw,label){
  const parts=String(raw||'').split(',').map(x=>x.trim()).filter(Boolean);
  const values=parts.map(Number);
  if(values.some(x=>!Number.isInteger(x)||x<0||x>23)) throw new Error(label+'只能填写 0 到 23 的整数小时。');
  return Array.from(new Set(values)).sort((a,b)=>a-b);
}
$('#btnGatewayScheduleSave').onclick=async()=>{
  try{
    const checkinHours=parseHourList($('#gatewayCheckinHours').value,'签到时间');
    const travelHours=parseHourList($('#gatewayTravelHours').value,'旅行时间');
    const checkinEnabled=$('#gatewayCheckinEnabled').checked;
    const travelEnabled=$('#gatewayTravelEnabled').checked;
    if(checkinEnabled&&!checkinHours.length) throw new Error('启用自动签到时至少填写一个签到时间。');
    if(travelEnabled&&!travelHours.length) throw new Error('启用猫猫旅行时至少填写一个旅行时间。');
    if(!confirm('保存后会重启 WorkBuddy 网关，确认更新签到和猫猫旅行设置吗？')) return;
    $('#btnGatewayScheduleSave').disabled=true;
    show('正在保存设置并重启网关…',true);
    const r=await api('/api/automation/gateway-config',{checkin_enabled:checkinEnabled,checkin_hours:checkinHours,
      travel_enabled:travelEnabled,travel_hours:travelHours},120000);
    if(r.ok){show('签到和猫猫旅行设置已保存，网关已重启。',true);loadAutomation();}
    else show('保存失败：'+esc(r.error||'未知错误'),false);
  }catch(e){show('设置无效：'+esc(e.message),false);}
  finally{$('#btnGatewayScheduleSave').disabled=false;}
};
$('#btnAutoSave').onclick=async()=>{
  const hours=$('#autoTaskHours').value.split(',').map(x=>x.trim()).filter(Boolean).map(Number);
  const uids=selectedAutoUids();
  const codes=selectedAutoTaskCodes();
  try{
    if($('#autoTaskEnabled').checked&&!uids.length) throw new Error('启用定时执行时至少选择一个账号；需要全部账号请点全选。');
    const r=await api('/api/automation/config',{task_scheduler_enabled:$('#autoTaskEnabled').checked,
      task_hours:hours,task_uids:uids,task_codes:codes,task_gap_seconds:Number($('#autoTaskGap').value||1.2)});
    if(r.ok){show('定时任务设置已保存；保存不会立即执行。',true);loadAutomation();}
    else show('保存失败：'+esc(r.error||'未知错误'),false);
  }catch(e){show('保存请求失败：'+esc(e.message),false);}
};
// Auto refresh
function stamp(){
  const el=$('#lastUpd'); if(!el) return;
  el.textContent='数据更新于 '+new Date().toLocaleTimeString()+(autoOn?' · 每 30 秒自动刷新':' · 自动刷新已关闭');
}
async function tick(){
  if(!autoOn||reloading||busy>0) return;
  if(typeof document.hidden!=='undefined'&&document.hidden) return;
  await refresh(); stamp();
  if(currentModule==='overview'&&Date.now()-lastModels>300000) loadModels(true);
  if(currentModule==='platforms') loadPlatforms(true);
  if(currentModule==='accounts'&&Date.now()-lastCredit>120000){ lastCredit=Date.now(); loadCredit(true); }
  if(currentModule==='usage'&&Date.now()-lastUsage>120000){ lastUsage=Date.now(); loadUsage(true); }
  if(currentModule==='gateway'){ loadKeys(true); loadDeviceToken(true); }
  if(currentModule==='automation') loadAutomation(true);
  if(currentModule==='security') loadAdminAuth();
}
// Hot-reload check on server deployment
async function checkVersion(){
  if(reloading||!autoOn) return;
  try{
    const r=await fetch('/admin/api/version',{headers:{Authorization:authHeader},cache:'no-store'});
    if(r.status===401){ showLogin('登录已过期，请重新登录。'); return; }
    const d=await r.json();
    if(d.version&&d.version!==PAGE_VERSION){
      reloading=true;
      const b=$('#banner');
      let n=3;
      const paint=()=>{ b.innerHTML='检测到服务端已更新（'+d.version+'），'+n+' 秒后自动刷新… <u>点此立即刷新</u>'; };
      b.onclick=()=>location.reload();
      paint(); b.style.display='block';
      const t=setInterval(()=>{ n--; if(n<=0){ clearInterval(t); location.reload(); } else paint(); },1000);
    }
  }catch(e){ /* ignore network jitter */ }
}
$('#autoOn').onchange=()=>{
  autoOn=$('#autoOn').checked;
  try{ localStorage.setItem('wb2api_auto',autoOn?'1':'0'); }catch(e){}
  setBanner(''); stamp();
  if(autoOn) tick();
};
function initTheme(){
  try{
    const saved=localStorage.getItem('kasa2api_theme');
    if(saved){ document.documentElement.setAttribute('data-theme',saved); }
  }catch(e){}
  const btn=$('#btnTheme');
  if(btn){
    btn.onclick=()=>{
      const current=document.documentElement.getAttribute('data-theme');
      const isDark=current==='dark'||(!current&&window.matchMedia('(prefers-color-scheme: dark)').matches);
      const next=isDark?'light':'dark';
      document.documentElement.setAttribute('data-theme',next);
      try{ localStorage.setItem('kasa2api_theme',next); }catch(e){}
    };
  }
}
initTheme();
initAuth();
</script></body></html>
""".replace("__PAGE_VER__", PAGE_VERSION).replace("__PUBLIC_HOST__", PUBLIC_HOST)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _norm(self):
        """Normalize request path, stripping optional /admin prefix when proxied."""
        p = self.path
        if p.startswith("/admin/"):
            p = p[len("/admin"):]
        elif p == "/admin":
            p = "/"
        return p

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # disable caching
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self._norm()
        if path in ("/", "/index.html"):
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif path == "/api/version":
            # auto-reload version endpoint
            self._send(200, json.dumps({"version": PAGE_VERSION}))
        elif path == "/api/state":
            try:
                self._send(200, json.dumps({"accounts": list_accounts(), "gw": gw_status(),
                                            "tokens": token_stats()}, ensure_ascii=False))
            except Exception as e:
                self._send(500, json.dumps({"error": str(e)}))
        elif path == "/api/platforms":
            try:
                self._send(200, json.dumps(platform_info(), ensure_ascii=False))
            except Exception as e:
                self._send(200, json.dumps({"ok": False, "error": str(e)[:300]}, ensure_ascii=False))
        elif path.split("?", 1)[0] == "/api/models":
            try:
                force = "refresh=1" in (path.split("?", 1)[1] if "?" in path else "")
                self._send(200, json.dumps(model_info(force), ensure_ascii=False))
            except Exception as e:
                self._send(200, json.dumps({"ok": False, "error": str(e)[:300]}, ensure_ascii=False))
        elif path == "/api/keys":
            try:
                d = ensure_keys_init()
                ks = [{k: v for k, v in x.items()} for x in d["keys"]]
                self._send(200, json.dumps({"ok": True, "keys": ks,
                                            "base_url": PUBLIC_BASE_URL,
                                            "key_scope": "shared",
                                            "platforms": key_platforms()}, ensure_ascii=False))
            except Exception as e:
                self._send(200, json.dumps({"ok": False, "error": str(e)[:300]}))
        elif path == "/api/credit":
            try:
                self._send(200, json.dumps(credit_info()))
            except subprocess.TimeoutExpired:
                self._send(200, json.dumps({"ok": False, "error": "查询积分超时"}))
            except Exception as e:
                self._send(200, json.dumps({"ok": False, "error": str(e)[:300]}))
        elif path == "/api/usage":
            try:
                self._send(200, json.dumps(usage_info(), ensure_ascii=False))
            except subprocess.TimeoutExpired:
                self._send(200, json.dumps({"ok": False, "error": "查询积分超时"}, ensure_ascii=False))
            except Exception as e:
                self._send(200, json.dumps({"ok": False, "error": str(e)[:300]}, ensure_ascii=False))
        elif path == "/api/automation/status":
            try:
                self._send(200, json.dumps(AUTOMATION.status(), ensure_ascii=False))
            except Exception as e:
                self._send(200, json.dumps({"ok": False, "error": str(e)[:300]}, ensure_ascii=False))
        elif path == "/api/device-token":
            try:
                self._send(200, json.dumps(get_device_token_status(), ensure_ascii=False))
            except Exception as e:
                self._send(200, json.dumps({"ok": False, "error": str(e)[:300]}, ensure_ascii=False))
        elif path == "/api/admin-auth":
            current = read_admin_auth()
            if current:
                self._send(200, json.dumps({"ok": True, "username": current["username"]}))
            else:
                self._send(200, json.dumps({"ok": False, "error": "读取管理页登录凭据失败"}))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            body = {}
        path = self._norm()
        try:
            if path == "/api/automation/gateway-config":
                schedule = AUTOMATION.save_gateway_schedule(body)
                self._send(200, json.dumps({"ok": True, "schedule": schedule,
                                            "info": "签到和猫猫旅行设置已保存，网关已重启。"}, ensure_ascii=False))
            elif path == "/api/automation/config":
                current = AUTOMATION.load_config()
                for key in ("task_scheduler_enabled", "task_hours", "task_uids", "task_codes", "task_gap_seconds"):
                    if key in body:
                        current[key] = body[key]
                cfg = AUTOMATION.save_config(current)
                self._send(200, json.dumps({"ok": True, "config": cfg}, ensure_ascii=False))
            elif path == "/api/automation/run":
                action = str(body.get("action") or "").strip().lower()
                if action == "checkin":
                    started, message = AUTOMATION.start_checkin()
                elif action == "scan":
                    targets = body["uids"] if "uids" in body else (body.get("uid") or "ALL")
                    started, message = AUTOMATION.start_scan(targets)
                elif action == "tasks":
                    targets = body["uids"] if "uids" in body else (body.get("uid") or "ALL")
                    started, message = AUTOMATION.start_tasks(
                        targets,
                        body.get("task_codes") or [],
                        confirm=body.get("confirm") is True,
                    )
                else:
                    self._send(200, json.dumps({"ok": False, "error": "未知自动化动作"}, ensure_ascii=False))
                    return
                self._send(200, json.dumps({"ok": started, "message": message}, ensure_ascii=False))
            elif path == "/api/login/start":
                realm = body.get("realm") or "cn"
                rc, out, err = dexec(["/app/login", "--realm=" + realm, "url"], timeout=60)
                url = out.strip().splitlines()[-1] if out.strip() else ""
                if rc != 0 or not url.startswith("http"):
                    self._send(200, json.dumps({"ok": False, "error": (err or out).strip()[:300]}))
                else:
                    self._send(200, json.dumps({"ok": True, "url": url}))
            elif path == "/api/login/finish":
                realm = body.get("realm") or "cn"
                rc, out, err = dexec(["/app/login", "--realm=" + realm, "poll"], timeout=180)
                data = extract_json(out)
                if rc != 0 or not data:
                    self._send(200, json.dumps({"ok": False, "error": (err or out).strip()[:300]}))
                    return
                uid = str(data.get("uid", "") or "")
                ok, msg = write_auth(uid, realm, data)
                if not ok:
                    self._send(200, json.dumps({"ok": False, "error": msg}))
                    return
                docker_host(["restart", CONTAINER], timeout=120)
                invalidate_model_cache()
                self._send(200, json.dumps({"ok": True, "uid": uid,
                                            "nickname": data.get("nickname", "")}))
            elif path == "/api/keys/create":
                name = (body.get("name") or "").strip()[:40] or "未命名"
                k = {"id": secrets.token_hex(6), "name": name, "key": gen_key(),
                     "enabled": True, "created_at": int(time.time()), "system": False}
                def _create(keys):
                    return keys + [k], {"key": k}
                ok, msg, _committed, result = mutate_keys(_create)
                if not ok:
                    self._send(200, json.dumps({"ok": False, "error": "网关配置应用失败：" + msg}))
                    return
                self._send(200, json.dumps({"ok": True, "key": result["key"], "info": msg}))
            elif path == "/api/keys/delete":
                kid = body.get("id") or ""
                d0 = ensure_keys_init()
                hit = next((x for x in d0["keys"] if x.get("id") == kid), None)
                if not hit:
                    self._send(200, json.dumps({"ok": False, "error": "未找到该 Key"}))
                    return
                if hit.get("system"):
                    self._send(200, json.dumps({"ok": False,
                                                "error": "内置 Key 不可删除，但可以停用"}))
                    return
                def _delete(keys):
                    return [x for x in keys if x.get("id") != kid], None
                ok, msg, _committed, _result = mutate_keys(_delete)
                self._send(200, json.dumps({"ok": ok, "info": msg,
                                            "error": None if ok else msg}))
            elif path == "/api/keys/toggle":
                kid = body.get("id") or ""
                d0 = ensure_keys_init()
                hit = next((x for x in d0["keys"] if x.get("id") == kid), None)
                if not hit:
                    self._send(200, json.dumps({"ok": False, "error": "未找到该 Key"}))
                    return
                def _toggle(keys):
                    updated = None
                    for x in keys:
                        if x.get("id") == kid:
                            x["enabled"] = not x.get("enabled", True)
                            updated = x
                            break
                    if updated is None:
                        raise ValueError("未找到该 Key")
                    return keys, {"key": updated}
                ok, msg, _committed, result = mutate_keys(_toggle)
                self._send(200, json.dumps({"ok": ok, "key": result.get("key") if result else None,
                                            "info": msg,
                                            "error": None if ok else msg}))
            elif path == "/api/account/delete":
                fname = body.get("file") or ("workbuddy-%s.json" % body.get("uid", ""))
                if "/" in fname or not fname.endswith(".json"):
                    self._send(200, json.dumps({"ok": False, "error": "非法文件名"}))
                    return
                rc, out, err = dexec(["rm", "-f", C_AUTH + "/" + fname], timeout=60)
                if rc != 0:
                    self._send(200, json.dumps({"ok": False, "error": (err or out).strip()[:200]}))
                    return
                docker_host(["restart", CONTAINER], timeout=120)
                invalidate_model_cache()
                self._send(200, json.dumps({"ok": True}))
            elif path == "/api/device-token":
                token = body.get("device_token", "")
                ok, msg = set_device_token(token)
                self._send(200, json.dumps({"ok": ok, "info": msg if ok else "",
                                            "error": None if ok else msg}, ensure_ascii=False))
            elif path == "/api/admin-auth":
                username = (body.get("username") or "").strip()
                password = body.get("password") or ""
                ok, msg = update_admin_credentials(username, password)
                if ok:
                    self._send(200, json.dumps({"ok": True, "username": username, "info": msg}))
                else:
                    self._send(200, json.dumps({"ok": False, "error": msg}))
            else:
                self._send(404, json.dumps({"error": "not found"}))
        except subprocess.TimeoutExpired:
            self._send(200, json.dumps({"ok": False, "error": "操作超时"}))
        except Exception as e:
            self._send(200, json.dumps({"ok": False, "error": str(e)[:300]}))


if __name__ == "__main__":
    if "--migrate-caddy" in sys.argv:
        ok, msg = apply_caddy(ensure_keys_init()["keys"])
        print(msg)
        raise SystemExit(0 if ok else 1)
    ThreadingHTTPServer(LISTEN, H).serve_forever()
