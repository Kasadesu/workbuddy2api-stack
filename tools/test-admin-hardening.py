#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线测试管理页的安全与状态一致性修复。

不依赖 VPS：用临时目录替换 keys.json / Caddyfile，注入假的 apply_caddy，
验证命令注入拦截、Caddy 失败回滚、keys.json 写失败回滚、并发串行化。
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ADMIN = os.path.join(os.path.dirname(HERE), "wb2api-admin.py")

FAILS = []


def check(cond, label, extra=""):
    print("%-64s %s%s" % (label, "OK" if cond else "FAIL", ("  " + extra) if extra else ""))
    if not cond:
        FAILS.append(label)


def load_admin(tmp):
    spec = importlib.util.spec_from_file_location("admin_under_test", ADMIN)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.ADMIN_DIR = tmp
    m.KEYS_FILE = os.path.join(tmp, "keys.json")
    m.CADDY_FILE = os.path.join(tmp, "Caddyfile")
    m.CFG = os.path.join(tmp, "config.json")
    m.USAGE_HISTORY_FILE = os.path.join(tmp, "usage-history.json")
    m.TOKEN_STATS_FILE = os.path.join(tmp, "token-usage.json")
    m.GATEWAY_TOKEN_STATS_FILE = os.path.join(tmp, "gateway-token-usage.json")
    with open(m.CFG, "w", encoding="utf-8") as f:
        json.dump({"api_key": "gw-real-key"}, f)
    with open(m.CADDY_FILE, "w", encoding="utf-8") as f:
        f.write('api.example.com {\n\thandle /admin* {\n\t\tbasicauth {\n'
                '\t\t\tadmin $2a$14$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'
                '\t\t}\n\t\treverse_proxy 127.0.0.1:7864\n\t}\n'
                '\thandle {\n\t\theader_up Authorization "Bearer gw-real-key"\n'
                '\t}\n}\n')
    m.__real_hash_admin_password = m.hash_admin_password
    m.__real_apply_caddy = m.apply_caddy
    return m


def test_write_auth_rejects_shell_metadata(m):
    calls = []
    m.dexec = lambda args, stdin_bytes=None, timeout=180, user="10001": calls.append(args) or (0, "", "")
    ok, msg = m.write_auth('abc; touch /tmp/pwned', "cn", {"access_token": "tok", "uid": "abc"})
    check(not ok and not calls, "write_auth 拒绝含 shell 元字符的 uid")


def test_write_auth_uses_argv(m):
    calls = []
    m.dexec = lambda args, stdin_bytes=None, timeout=180, user="10001": calls.append(args) or (0, "", "")
    ok, msg = m.write_auth("uid_123", "cn", {"access_token": "tok", "expires_in": 60})
    check(ok, "合法 uid 可以写入", msg)
    check(calls and calls[0][0] == "tee", "首次写入使用 tee 参数，不经过 sh -c")
    check(calls[0][1].endswith("/workbuddy-uid_123.json"), "目标文件名由校验后的 uid 生成")
    check("sh" not in calls[0], "参数列表中没有 shell")


def test_model_catalog_parser(m):
    payload = {
        "code": 0,
        "data": {
            "agents": [{"name": "cli", "models": ["keep", "no-credit"]}],
            "models": [
                {"id": "keep", "name": "Keep", "credits": "x0.03 credits"},
                {"id": "no-credit", "name": "No credit"},
                {"id": "disabled", "credits": "x9.99", "disabled": True},
                {"id": "other", "credits": "x8.88"},
            ],
        },
    }
    got = m.parse_model_catalog(payload)
    check([x["id"] for x in got] == ["keep", "no-credit"],
          "模型目录只保留 CLI 模型并跳过禁用项", str(got))
    check(got[0]["credits"] == "x0.03" and got[1]["credits"] == "",
          "模型倍率统一去除 credits 后缀，缺失倍率不伪造", str(got))


def test_mutate_rolls_back_on_caddy_failure(m):
    m.save_keys({"keys": [{"id": "default", "key": "old", "enabled": True, "system": True}]})
    m.apply_caddy = lambda keys: (False, "simulated caddy failure")
    ok, msg, committed, result = m.mutate_keys(lambda keys: (keys + [{"id": "new", "key": "n"}], {"key": "n"}))
    check(not ok, "Caddy 失败时事务失败", msg)
    on_disk = json.load(open(m.KEYS_FILE, encoding="utf-8"))["keys"]
    check([k["id"] for k in on_disk] == ["default"], "Caddy 失败后 keys.json 保持旧状态")
    check([k["id"] for k in committed] == ["default"], "返回值里的 committed 状态也回滚")


def test_mutate_rolls_back_caddy_when_keys_write_fails(m):
    m.save_keys({"keys": [{"id": "default", "key": "old", "enabled": True, "system": True}]})
    seen = []
    m.apply_caddy = lambda keys: seen.append([k["id"] for k in keys]) or (True, "ok")
    real_save = m.save_keys
    def bad_save(d):
        if any(k.get("id") == "new" for k in d["keys"]):
            raise OSError("disk full")
        return real_save(d)
    m.save_keys = bad_save
    ok, msg, committed, result = m.mutate_keys(lambda keys: (keys + [{"id": "new", "key": "n"}], None))
    check(not ok, "keys.json 写失败时事务失败", msg)
    check(seen == [["default", "new"], ["default"]], "keys.json 写失败后 Caddy 已回滚到旧 key", str(seen))
    check([k["id"] for k in committed] == ["default"], "committed 回到旧状态")


def test_mutate_serializes_concurrent_writers(m):
    m.save_keys({"keys": [{"id": "default", "key": "old", "enabled": True, "system": True}]})
    m.apply_caddy = lambda keys: (True, "ok")
    errors = []
    def writer(i):
        try:
            def mutate(keys):
                time.sleep(0.03)
                return keys + [{"id": "k%d" % i, "key": "v%d" % i}], None
            ok, msg, committed, result = m.mutate_keys(mutate)
            if not ok:
                errors.append(msg)
        except Exception as e:
            errors.append(repr(e))
    threads = [threading.Thread(target=writer, args=(i,)) for i in range(6)]
    for t in threads: t.start()
    for t in threads: t.join()
    ids = {k["id"] for k in json.load(open(m.KEYS_FILE, encoding="utf-8"))["keys"]}
    check(not errors, "并发事务没有异常", str(errors))
    check(ids == {"default", "k0", "k1", "k2", "k3", "k4", "k5"}, "并发创建没有丢更新", str(sorted(ids)))


def test_update_admin_credentials_keeps_hash_when_password_empty(m):
    m.save_keys({"keys": [{"id": "default", "key": "old", "enabled": True, "system": True}]})
    seen = []
    try:
        m.apply_caddy = lambda keys, user=None, digest=None: seen.append((user, digest)) or (True, "ok")
        m.hash_admin_password = lambda pw: (_ for _ in ()).throw(AssertionError("empty password must not hash"))
        ok, msg = m.update_admin_credentials("new-admin", "")
    finally:
        m.apply_caddy = m.__real_apply_caddy
        m.hash_admin_password = m.__real_hash_admin_password
    check(ok, "用户名可以单独修改", msg)
    check(seen and seen[0][0] == "new-admin", "应用了新用户名")
    check(seen and seen[0][1] == "$2a$14$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "密码留空时保留原 bcrypt 哈希")


def test_update_admin_credentials_hashes_new_password(m):
    m.save_keys({"keys": [{"id": "default", "key": "old", "enabled": True, "system": True}]})
    new_hash = "$2a$14$ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
    seen = []
    try:
        m.hash_admin_password = lambda pw: (new_hash, "")
        m.apply_caddy = lambda keys, user=None, digest=None: seen.append((user, digest)) or (True, "ok")
        ok, msg = m.update_admin_credentials("admin2", "new-password-123")
    finally:
        m.apply_caddy = m.__real_apply_caddy
        m.hash_admin_password = m.__real_hash_admin_password
    check(ok, "用户名和密码可以一起修改", msg)
    check(seen and seen[0] == ("admin2", new_hash), "应用了新用户名和新哈希", str(seen))


def test_update_admin_credentials_validation(m):
    m.save_keys({"keys": [{"id": "default", "key": "old", "enabled": True, "system": True}]})
    bad, msg1 = m.update_admin_credentials("bad user", "long-enough-password")
    short, msg2 = m.update_admin_credentials("admin", "short")
    multiline, msg3 = m.update_admin_credentials("admin", "long-enough\nsecond-line")
    check(not bad and "用户名" in msg1, "非法用户名被拒绝", msg1)
    check(not short and "至少" in msg2, "短密码被拒绝", msg2)
    check(not multiline and "换行" in msg3, "含换行的密码被拒绝", msg3)


def test_read_admin_auth_ignores_other_hash_in_site(m):
    with open(m.CADDY_FILE, "w", encoding="utf-8") as f:
        f.write('api.example.com {\n'
                '\tother {\n\t\tadmin $2a$14$zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n\t}\n'
                '\thandle /admin* {\n\t\tbasicauth {\n'
                '\t\t\tadmin $2a$14$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'
                '\t\t}\n\t}\n}\n')
    got = m.read_admin_auth()
    check(got and got["hash"].endswith("a" * 20), "只读取 /admin* 子块内的 basicauth 哈希", str(got))


def test_render_admin_auth_only_protects_api(m):
    digest = "$2a$14$" + ("a" * 53)
    bridge = ("\t# >>> responses-bridge (managed) >>>\n"
              "\thandle /v1/responses* {\n\t}\n"
              "\t# <<< responses-bridge (managed) <<<")
    rendered = m.render_api_block(
        [{"key": "wb-legacy", "enabled": True},
         {"key": "sk-new", "enabled": True}], "real", "admin", digest, bridge)
    api_block = rendered.split("\thandle /admin/api/* {", 1)[1].split("\thandle /admin* {", 1)[0]
    page_block = rendered.split("\thandle /admin* {", 1)[1].split("\thandle {", 1)[0]
    check("basicauth" in api_block, "Basic Auth 只保护管理 API")
    check("basicauth" not in page_block, "管理页本身不再触发浏览器认证框")
    check(bridge in rendered, "更新 Caddy 时保留 Responses 桥接路由")
    check("wb\\-legacy" in rendered and "sk\\-new" in rendered,
          "Caddy 白名单同时兼容旧、新 Key")


def test_new_api_key_uses_openai_prefix(m):
    got = m.gen_key()
    check(got.startswith("sk-"), "新建 API Key 使用 sk- 前缀", got[:8])
    check(len(got) > 20, "新建 API Key 保持足够长度", str(len(got)))


def test_hash_admin_password_uses_stdin(m):
    calls = []
    real_run = subprocess.run
    class P:
        returncode = 0
        stdout = "$2a$14$" + ("b" * 53) + "\n"
        stderr = ""
    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return P()
    subprocess.run = fake_run
    try:
        digest, err = m.hash_admin_password("secret-password")
    finally:
        subprocess.run = real_run
    check(digest and not err, "hash_admin_password 接受 Caddy 输出", err)
    check(calls and "--plaintext" not in calls[0][0], "密码不以 --plaintext 参数传递")
    check(calls and calls[0][1].get("input") == "secret-password\n", "密码通过 stdin 传入")


def test_usage_snapshots_keep_only_safe_deltas(m):
    first = {
        "total": {"remain": 100, "used": 10, "size": 110},
        "accounts": [{"uid": "account-a", "nickname": "Account A", "remain": 100,
                       "used": 10, "size": 110, "ok": True,
                       "access_token": "must-not-be-saved"}],
    }
    second = {
        "total": {"remain": 94, "used": 16, "size": 110},
        "accounts": [{"uid": "account-a", "nickname": "Account A", "remain": 94,
                       "used": 16, "size": 110, "ok": True,
                       "access_token": "must-not-be-saved"}],
    }
    m.record_usage_snapshot(first)
    m.record_usage_snapshot(second)
    m._gateway_usage_stats = lambda: None
    m.credit_info = lambda: {"ok": True, "data": second}
    got = m.usage_info()
    check(got.get("mode") == "snapshots", "旧网关使用快照模式展示积分记录")
    check(got.get("records") and got["records"][0]["delta_used"] == 6,
          "相邻快照正确计算已用积分增量", str(got.get("records")))
    raw = open(m.USAGE_HISTORY_FILE, encoding="utf-8").read()
    check("must-not-be-saved" not in raw and "access_token" not in raw,
          "积分历史文件不保存 access token")


def test_gateway_usage_keeps_account_model_stats(m):
    current = {"total": {"remain": 90, "used": 10, "size": 100}, "accounts": []}
    account_row = {
        "uid": "account-a", "nickname": "Account A", "realm": "cn",
        "model": "cn:deepseek-v4.1-flash", "requests": 2,
        "prompt_tokens": 120, "completion_tokens": 30,
        "total_tokens": 150, "credit": 0.25,
    }
    m._gateway_usage_stats = lambda: {
        "models": [{"model": "cn:deepseek-v4.1-flash", "total_tokens": 150}],
        "accounts": [account_row],
    }
    m._gateway_recent_usage = lambda limit=20: {
        "enabled": True,
        "records": [{"uid": "account-a", "model": "cn:deepseek-v4.1-flash", "status": 200}],
    }
    m.credit_info = lambda: {"ok": True, "data": current}
    got = m.usage_info()
    check(got.get("mode") == "gateway", "新网关使用账号+模型统计模式")
    check(got.get("stats", {}).get("accounts", [])[0] == account_row,
          "新网关统计保留账号、模型、积分和 Token 字段")
    check(got.get("recent", [])[0]["uid"] == "account-a" and got.get("recent_available"),
          "积分记录接口同时返回逐请求记录", str(got.get("recent")))


def test_token_stats_reading(m):
    day = time.strftime("%Y-%m-%d", time.localtime())
    with open(m.TOKEN_STATS_FILE, "w", encoding="utf-8") as f:
        json.dump({"updated_at": 123, "total": {
            "input_tokens": 11, "output_tokens": 7,
            "total_tokens": 18, "requests": 2},
            "days": {day: {"input_tokens": 5, "output_tokens": 3,
                            "total_tokens": 8, "requests": 1}}}, f)
    got = m.token_stats()
    check(got["available"] and got["total_tokens"] == 18,
          "管理页读取总 Token 聚合值", str(got))
    check(got["today_tokens"] == 8 and got["today_requests"] == 1,
          "管理页读取今日 Token 聚合值", str(got))


def test_gateway_token_stats_accumulate_and_fallback(m):
    today = time.strftime("%Y-%m-%d", time.localtime())
    yesterday = time.strftime("%Y-%m-%d", time.localtime(time.time() - 86400))
    m._gateway_usage_stats = lambda: {
        "since": yesterday + "T23:00:00+08:00",
        "total": {"prompt_tokens": 100, "completion_tokens": 10,
                   "total_tokens": 110, "requests": 1},
    }
    first = m.token_stats()
    check(first["source"] == "workbuddy2api" and first["total_tokens"] == 110 and
          first["today_tokens"] == 0,
          "网关 Token 兼容字段且不把历史流量记作今日", str(first))

    m._gateway_usage_stats = lambda: {
        "since": yesterday + "T23:00:00+08:00",
        "total": {"prompt_tokens": 130, "completion_tokens": 20,
                   "total_tokens": 150, "requests": 2},
    }
    second = m.token_stats()
    check(second["total_tokens"] == 150 and second["today_tokens"] == 40 and
          second["total_requests"] == 2,
          "网关 Token 只累计新增量", str(second))

    m._gateway_usage_stats = lambda: {
        "since": today + "T00:00:00+08:00",
        "total": {"prompt_tokens": 5, "completion_tokens": 1,
                   "total_tokens": 6, "requests": 1},
    }
    restarted = m.token_stats()
    check(restarted["total_tokens"] == 156 and restarted["today_tokens"] == 46 and
          restarted["total_requests"] == 3,
          "网关重启后重新累计当前进程统计", str(restarted))

    m._gateway_usage_stats = lambda: None
    got = m.token_stats()
    check(got["source"] == "workbuddy2api-cache" and got["total_tokens"] == 156 and
          got.get("stale"), "网关接口不可用时保留持久化累计值", str(got))

    os.unlink(m.GATEWAY_TOKEN_STATS_FILE)
    got = m.token_stats()
    check(got["source"] == "responses-bridge" and got["total_tokens"] == 18,
          "没有网关缓存时回退桥接层统计", str(got))


def test_page_formats_tokens_as_m(m):
    check("formatTokenCount" in m.PAGE and "toFixed(2)+'M'" in m.PAGE,
          "管理页包含 Token 的 M 格式化逻辑")
    check("usageTokenValue(input)" in m.PAGE and "usageTokenValue(totalTokens)" in m.PAGE,
          "积分使用记录的 Token 列使用 M 格式")
    check("缓存输入 Token" in m.PAGE and "usagePercentValue(cacheHitRate)" in m.PAGE and
          "value===null||value===undefined" in m.PAGE,
          "最近请求表展示缓存输入和命中率")


def test_recent_usage_info(m):
    m._gateway_recent_usage = lambda limit=20: {
        "enabled": True,
        "records": [
            {"at": "2026-09-22T10:00:00+08:00", "uid": "new", "nickname": "New",
             "realm": "cn", "model": "cn:new", "mode": "stream", "status": 200,
             "input_tokens": 20, "cached_input_tokens": 8, "output_tokens": 3,
             "total_tokens": 23, "credits": 0.2},
            {"at": "2026-09-21T10:00:00+08:00", "uid": "old", "nickname": "Old",
             "realm": "cn", "model": "cn:old", "mode": "sync", "status": 500,
             "credits": 0.1, "request_body": "must-not-be-saved"},
            {"at": "2026-09-20T10:00:00+08:00", "uid": "zero", "nickname": "Zero",
             "model": "cn:zero", "input_tokens": 12, "cached_input_tokens": 0},
            {"at": "2026-09-19T10:00:00+08:00", "uid": "unknown", "nickname": "Unknown",
             "model": "cn:unknown", "input_tokens": 12},
        ],
    }
    got = m.recent_usage_info()
    rows = got.get("records") or []
    check(got.get("ok") and got.get("mode") == "request" and got.get("enabled") and
          [row["uid"] for row in rows] == ["new", "old", "zero", "unknown"],
          "最近使用记录保留网关返回顺序", str(got))
    check(rows[0]["total_tokens"] == 23 and rows[0]["credits"] == 0.2 and
          rows[0]["cached_input_tokens"] == 8 and rows[0]["cache_hit_rate"] == 0.4,
          "最近使用记录计算缓存输入和命中率", str(rows))
    check(rows[2]["cached_input_tokens"] == 0 and rows[2]["cache_hit_rate"] == 0,
          "显式零缓存显示为 0% 命中", str(rows[2]))
    check(rows[1]["cached_input_tokens"] is None and rows[1]["cache_hit_rate"] is None and
          rows[3]["cached_input_tokens"] is None and rows[3]["cache_hit_rate"] is None,
          "缺缓存字段与失败请求显示未知而非 0%", str(rows))
    check("request_body" not in json.dumps(rows, ensure_ascii=False),
          "最近使用记录不向管理页透传请求正文", str(rows))


def main():
    print("admin hardening tests")
    with tempfile.TemporaryDirectory() as tmp:
        m = load_admin(tmp)
        test_write_auth_rejects_shell_metadata(m)
        test_write_auth_uses_argv(m)
        test_model_catalog_parser(m)
        test_mutate_rolls_back_on_caddy_failure(m)
        test_mutate_rolls_back_caddy_when_keys_write_fails(m)
        test_mutate_serializes_concurrent_writers(m)
        test_update_admin_credentials_keeps_hash_when_password_empty(m)
        test_update_admin_credentials_hashes_new_password(m)
        test_update_admin_credentials_validation(m)
        test_read_admin_auth_ignores_other_hash_in_site(m)
        test_render_admin_auth_only_protects_api(m)
        test_new_api_key_uses_openai_prefix(m)
        test_hash_admin_password_uses_stdin(m)
        test_usage_snapshots_keep_only_safe_deltas(m)
        test_gateway_usage_keeps_account_model_stats(m)
        test_token_stats_reading(m)
        test_gateway_token_stats_accumulate_and_fallback(m)
        test_page_formats_tokens_as_m(m)
        test_recent_usage_info(m)
    if FAILS:
        print("\n%d failures: %s" % (len(FAILS), FAILS))
        return 1
    print("\nall passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
