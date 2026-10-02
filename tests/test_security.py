import hashlib
import os
import stat
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from cryptography.exceptions import InvalidTag

from app import audit, config, security
from app.schemas import FormModel, OptInt, validate_form
from tests.base import WebTestCase, DBTestCase


class PasswordTests(DBTestCase):
    def setUp(self):
        super().setUp()
        for name, value in dict(SCRYPT_N=2**4, SCRYPT_R=8, SCRYPT_P=1).items():
            p = mock.patch.object(config, name, value)
            p.start()
            self.addCleanup(p.stop)

    def test_hash_roundtrip_and_format(self):
        h = security.hash_password("correct horse battery")
        self.assertTrue(h.startswith("scrypt$16$8$1$"))
        self.assertTrue(security.verify_password(h, "correct horse battery"))
        self.assertFalse(security.verify_password(h, "wrong password!!"))
        self.assertNotEqual(h, security.hash_password("correct horse battery"))   # salt 랜덤

    def test_verify_uses_stored_params_not_current_config(self):
        h = security.hash_password("correct horse battery")
        with mock.patch.object(config, "SCRYPT_N", 2**5):
            self.assertTrue(security.verify_password(h, "correct horse battery"))

    def test_malformed_hash_rejected(self):
        for bad in ("", "plain", "scrypt$1$1$1$a$b", "bcrypt$16$8$1$AAAA$AAAA", "scrypt$16$8$1$!!$!!",
                    "scrypt$%d$8$1$AAAA$AAAA" % 2**30):
            self.assertFalse(security.verify_password(bad, "x"), bad)

    def test_policy(self):
        self.assertIsNotNone(security.password_policy_error("short", "bob"))
        self.assertIsNotNone(security.password_policy_error("a" * 11, "bob"))
        self.assertIsNone(security.password_policy_error("a" * 12, "bob"))
        self.assertIsNotNone(security.password_policy_error("Administrator", "administrator"))  # 13자, 사용자명 동일
        self.assertIsNotNone(security.password_policy_error("x" * 300, "bob"))

    def test_random_password(self):
        a, b = security.random_password(), security.random_password()
        self.assertGreaterEqual(len(a), 20)
        self.assertNotEqual(a, b)

    def test_concurrent_hashing_is_limited(self):
        active, peak, lock = 0, 0, threading.Lock()

        def slow_scrypt(*args, **kwargs):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.05)
            with lock:
                active -= 1
            return b"\0" * 32

        with mock.patch.object(security.hashlib, "scrypt", slow_scrypt):
            threads = [threading.Thread(target=security.hash_password, args=("x" * 12,)) for _ in range(10)]
            [t.start() for t in threads]
            [t.join() for t in threads]
        self.assertLessEqual(peak, config.SCRYPT_CONCURRENCY)
        self.assertGreater(peak, 1)


class LoginLimiterTests(DBTestCase):
    def setUp(self):
        super().setUp()
        for name, value in dict(SCRYPT_N=2**4, SCRYPT_R=8, SCRYPT_P=1).items():
            p = mock.patch.object(config, name, value)
            p.start()
            self.addCleanup(p.stop)
        security._dummy_hash = None
        self.now = 1000.0
        self.limiter = security.LoginLimiter(clock=lambda: self.now)
        p = mock.patch.object(security, "login_limiter", self.limiter)
        p.start()
        self.addCleanup(p.stop)
        self.uid = self.conn.execute(
            "INSERT INTO users (username, display_name, role, password_hash, created_at, updated_at) "
            "VALUES ('bob', 'Bob', 'editor', ?, 'x', 'x')", (security.hash_password("right-password-1"),)).lastrowid

    def login(self, user="bob", pw="right-password-1", ip="1.1.1.1"):
        return security.attempt_login(self.conn, user, pw, ip)

    def test_success_and_failure(self):
        row, reason = self.login()
        self.assertEqual((row["username"], reason), ("bob", "ok"))
        self.assertEqual(self.login(pw="nope-nope-nope")[1], "invalid")
        self.assertEqual(self.login(user="ghost")[1], "invalid")           # 존재하지 않는 계정도 동일 사유

    def test_username_is_case_insensitive(self):
        self.assertEqual(self.login(user="BOB")[1], "ok")

    def test_account_lock_after_5_failures_and_unlock(self):
        for _ in range(5):
            self.assertEqual(self.login(pw="bad-bad-bad-bad", ip="9.9.9.%d" % _)[1], "invalid")
        self.assertEqual(self.login(ip="8.8.8.8")[1], "locked")           # 올바른 비밀번호도 잠금
        self.now += config.LOGIN_LOCK_SECONDS - 1
        self.assertEqual(self.login(ip="8.8.8.8")[1], "locked")
        self.now += 2
        self.assertEqual(self.login(ip="8.8.8.8")[1], "ok")

    def test_ip_lock_covers_other_accounts(self):
        for i in range(5):
            self.login(user="ghost%d" % i, pw="bad-bad-bad-bad", ip="7.7.7.7")
        self.assertEqual(self.login(ip="7.7.7.7")[1], "locked")            # 같은 IP는 정상 계정도 잠금
        self.assertEqual(self.login(ip="6.6.6.6")[1], "ok")                # 다른 IP는 영향 없음

    def test_old_failures_expire(self):
        for _ in range(4):
            self.login(pw="bad-bad-bad-bad", ip="5.5.5.5")
        self.now += config.LOGIN_LOCK_SECONDS + 1
        self.login(pw="bad-bad-bad-bad", ip="5.5.5.5")                     # 새로 1회
        self.assertEqual(self.login(ip="4.4.4.4")[1], "ok")

    def test_inactive_user_rejected(self):
        self.conn.execute("UPDATE users SET is_active=0")
        self.assertEqual(self.login()[1], "invalid")

    def test_admin_login_rejected_when_admin_disabled(self):
        self.conn.execute("UPDATE users SET role='admin'")
        with mock.patch.dict(os.environ, {"ADMIN_ENABLED": "false"}):
            self.assertEqual(self.login()[1], "invalid")
        with mock.patch.dict(os.environ, {"ADMIN_ENABLED": "true"}):
            self.assertEqual(self.login(ip="3.3.3.3")[1], "ok")

    def test_limiter_memory_is_bounded(self):
        lim = security.LoginLimiter(clock=lambda: self.now, max_entries=50)
        for i in range(500):
            lim.record_failure("u:%d" % i)
        self.assertLessEqual(len(lim._state), 50)

    def test_admin_enabled_parsing(self):
        for value, expected in (("true", True), ("TRUE", True), ("false", False), ("0", False), ("flase", False)):
            with mock.patch.dict(os.environ, {"ADMIN_ENABLED": value}):
                self.assertEqual(security.admin_enabled(), expected, value)
        with mock.patch.dict(os.environ, clear=True):
            self.assertTrue(security.admin_enabled())


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        p = mock.patch.object(config, "DATA_DIR", Path(self._tmp.name))
        p.start()
        self.addCleanup(p.stop)

    def test_key_created_once_with_mode_600(self):
        key = security.load_or_create_key()
        path = Path(self._tmp.name) / "secret.key"
        self.assertEqual(len(key), 32)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(security.load_or_create_key(), key)               # 재기동: 덮어쓰지 않음
        self.assertEqual(path.read_bytes(), key)

    def test_corrupted_key_fails_without_overwrite(self):
        path = Path(self._tmp.name) / "secret.key"
        path.write_bytes(b"short")
        with self.assertRaises(RuntimeError):
            security.load_or_create_key()
        self.assertEqual(path.read_bytes(), b"short")

    def test_encrypt_roundtrip_and_aad(self):
        key = security.load_or_create_key()
        blob = security.encrypt_field(key, 7, "license_key", "ABCD-1234-SECRET")
        self.assertNotIn(b"SECRET", blob)
        self.assertEqual(security.decrypt_field(key, 7, "license_key", blob), "ABCD-1234-SECRET")
        with self.assertRaises(InvalidTag):
            security.decrypt_field(key, 8, "license_key", blob)             # 다른 레코드 ID
        with self.assertRaises(InvalidTag):
            security.decrypt_field(key, 7, "account_info", blob)            # 다른 필드로 복사
        with self.assertRaises(InvalidTag):
            security.decrypt_field(security.secrets.token_bytes(32), 7, "license_key", blob)
        tampered = blob[:-1] + bytes([blob[-1] ^ 1])
        with self.assertRaises(InvalidTag):
            security.decrypt_field(key, 7, "license_key", tampered)

    def test_nonce_is_random_per_record(self):
        key = security.load_or_create_key()
        a = security.encrypt_field(key, 1, "f", "same")
        b = security.encrypt_field(key, 1, "f", "same")
        self.assertNotEqual(a, b)
        self.assertEqual(len(a[:12]), 12)

    def test_mask(self):
        self.assertEqual(security.mask_secret("ABCD-1234-WXYZ"), "****WXYZ")
        self.assertEqual(security.mask_secret("short"), "********")


class SessionTests(DBTestCase):
    def setUp(self):
        super().setUp()
        self.uid = self.user("bob")

    def test_only_hash_is_stored(self):
        raw = security.create_session(self.conn, self.uid)
        stored = self.conn.execute("SELECT id_hash FROM sessions").fetchone()[0]
        self.assertNotEqual(stored, raw)
        self.assertEqual(stored, hashlib.sha256(raw.encode()).hexdigest())
        self.assertGreaterEqual(len(raw), 43)

    def test_lookup_and_new_id_each_login(self):
        a = security.create_session(self.conn, self.uid)
        b = security.create_session(self.conn, self.uid)
        self.assertNotEqual(a, b)
        self.assertEqual(security.lookup_session(self.conn, a).username, "bob")
        self.assertIsNone(security.lookup_session(self.conn, "nonexistent"))
        self.assertIsNone(security.lookup_session(self.conn, None))

    def test_idle_expiry(self):
        t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
        raw = security.create_session(self.conn, self.uid, now=t0)
        self.assertIsNotNone(security.lookup_session(self.conn, raw, now=t0 + timedelta(minutes=29)))
        # 29분 시점에 last_seen이 갱신되었으므로 거기서 30분 더 지나야 만료
        self.assertIsNone(security.lookup_session(self.conn, raw, now=t0 + timedelta(minutes=29, seconds=1800)))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)

    def test_idle_expiry_without_activity(self):
        t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
        raw = security.create_session(self.conn, self.uid, now=t0)
        self.assertIsNone(security.lookup_session(self.conn, raw, now=t0 + timedelta(minutes=30)))

    def test_absolute_expiry_even_if_active(self):
        t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
        raw = security.create_session(self.conn, self.uid, now=t0)
        t = t0
        while t < t0 + timedelta(hours=12) - timedelta(minutes=20):      # 20분마다 활동
            t += timedelta(minutes=20)
            self.assertIsNotNone(security.lookup_session(self.conn, raw, now=t))
        self.assertIsNone(security.lookup_session(self.conn, raw, now=t0 + timedelta(hours=12, seconds=1)))

    def test_inactive_user_session_invalid(self):
        raw = security.create_session(self.conn, self.uid)
        self.conn.execute("UPDATE users SET is_active=0")
        self.assertIsNone(security.lookup_session(self.conn, raw))

    def test_delete_user_sessions_keeps_current(self):
        keep = security.create_session(self.conn, self.uid)
        other = security.create_session(self.conn, self.uid)
        other_user = self.user("alice")
        alice = security.create_session(self.conn, other_user)
        keep_hash = security.lookup_session(self.conn, keep).session_hash
        security.delete_user_sessions(self.conn, self.uid, keep_session_hash=keep_hash)
        self.assertIsNotNone(security.lookup_session(self.conn, keep))
        self.assertIsNone(security.lookup_session(self.conn, other))
        self.assertIsNotNone(security.lookup_session(self.conn, alice))
        security.delete_user_sessions(self.conn, self.uid)
        self.assertIsNone(security.lookup_session(self.conn, keep))

    def test_flash_is_consumed_once(self):
        user = security.lookup_session(self.conn, security.create_session(self.conn, self.uid))
        security.add_flash(self.conn, user, "저장했습니다.")
        self.assertEqual(security.pop_flash(self.conn, user)[0]["message"], "저장했습니다.")
        self.assertEqual(security.pop_flash(self.conn, user), [])

    def test_cookie_attributes(self):
        from fastapi import Response
        resp = Response()
        security.set_session_cookie(resp, "abc")
        header = resp.headers["set-cookie"]
        self.assertTrue(header.startswith("__Host-session=abc"))
        for attr in ("HttpOnly", "Secure", "SameSite=strict", "Path=/"):
            self.assertIn(attr, header)
        self.assertNotIn("Domain", header)


class RedirectTests(unittest.TestCase):
    def test_safe_redirect_path(self):
        ok = security.safe_redirect_path
        self.assertEqual(ok("/servers?page=2"), "/servers?page=2")
        for evil in ("//evil.com", "https://evil.com", "http://evil.com/x", "/\\evil.com", "javascript:alert(1)",
                     "evil.com", "", None, "/a\r\nSet-Cookie: x=1", "///evil.com", "/ok\x00"):
            self.assertEqual(ok(evil), "/", repr(evil))
        self.assertEqual(ok("//evil.com", default="/home"), "/home")


class AuditTests(DBTestCase):
    def test_diff_summary_excludes_sensitive_values(self):
        summary = audit.diff_summary(
            {"name": "a", "license_key": "OLD-SECRET", "same": 1},
            {"name": "b", "license_key": "NEW-SECRET", "same": 1})
        self.assertIn("name: a → b", summary)
        self.assertIn("license_key", summary)
        self.assertNotIn("SECRET", summary)
        self.assertNotIn("same", summary)

    def test_record_truncates_username_and_works_without_user(self):
        audit.record(self.conn, None, "login_failed", username="x" * 200)
        row = self.conn.execute("SELECT * FROM audit_logs").fetchone()
        self.assertEqual(len(row["username"]), 64)
        self.assertIsNone(row["user_id"])


class SchemaValidationTests(unittest.TestCase):
    class M(FormModel):
        name: str
        n: OptInt = None

    def test_extra_forbidden_and_messages_do_not_echo_input(self):
        obj, errors = validate_form(self.M, {"name": "a", "evil": "<script>alert(1)</script>"})
        self.assertIsNone(obj)
        self.assertEqual(errors["evil"], "허용되지 않는 항목입니다.")
        self.assertNotIn("script", str(errors))

    def test_blank_optional_int_and_errors(self):
        obj, errors = validate_form(self.M, {"name": " a ", "n": ""})
        self.assertEqual((obj.name, obj.n, errors), ("a", None, {}))
        _, errors = validate_form(self.M, {"name": "a", "n": "abc<b>"})
        self.assertEqual(errors["n"], "숫자를 입력하세요.")
        self.assertNotIn("<b>", errors["n"])
        _, errors = validate_form(self.M, {})
        self.assertEqual(errors["name"], "필수 항목입니다.")


class HttpSecurityTests(WebTestCase):
    def setUp(self):
        super().setUp()
        self.editor = self.user("ed", "editor")
        self.viewer = self.user("vw", "viewer")
        self.admin = self.user("adm", "admin")
        self.conn.execute("UPDATE users SET must_change_password=0")

    def assertSecurityHeaders(self, r):
        h = r.headers
        self.assertEqual(h["content-security-policy"],
                         "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                         "frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'")
        self.assertEqual(h["x-content-type-options"], "nosniff")
        self.assertEqual(h["referrer-policy"], "no-referrer")
        self.assertEqual(h["x-frame-options"], "DENY")

    def test_headers_on_every_kind_of_response(self):
        self.login_as(self.editor)
        for path, status in (("/healthz", 200), ("/t/ok", 200), ("/nope", 404), ("/static/style.css", 200),
                             ("/t/int?n=x", 422), ("/t/boom", 500), ("/t/admin", 403)):
            r = self.client.get(path)
            self.assertEqual(r.status_code, status, path)
            self.assertSecurityHeaders(r)
        self.assertEqual(self.client.get("/t/ok").headers["cache-control"], "no-store")
        self.assertEqual(self.client.get("/t/boom").headers["cache-control"], "no-store")
        self.assertNotIn("no-store", self.client.get("/static/style.css").headers.get("cache-control", ""))

    def test_headers_on_redirects_and_unauthenticated(self):
        r = self.client.get("/t/ok")
        self.assertEqual(r.status_code, 303)
        self.assertSecurityHeaders(r)

    def test_docs_disabled(self):
        for path in ("/docs", "/redoc", "/openapi.json"):
            self.assertEqual(self.client.get(path).status_code, 404, path)

    def test_error_pages_do_not_leak(self):
        self.login_as(self.editor)
        r = self.client.get("/t/boom")
        self.assertEqual(r.status_code, 500)
        self.assertNotIn("secret-internal-detail", r.text)
        self.assertNotIn("Traceback", r.text)
        self.assertIn("text/html", r.headers["content-type"])
        r = self.client.get("/t/int?n=<script>alert(1)</script>")
        self.assertEqual(r.status_code, 422)
        self.assertNotIn("alert(1)", r.text)                               # 입력값 에코 없음
        self.assertIn("text/html", r.headers["content-type"])
        self.assertIn("404", self.client.get("/missing").text)

    def test_unauthenticated_redirects_to_login(self):
        r = self.client.get("/t/ok")
        self.assertEqual((r.status_code, r.headers["location"]), (303, "/login?next=%2Ft%2Fok"))
        r = self.post("/t/post", "csrf_token=x")
        self.assertEqual((r.status_code, r.headers["location"]), (303, "/login"))

    def test_invalid_cookie_is_unauthenticated(self):
        self.client.cookies.set(config.SESSION_COOKIE, "garbage", domain="testserver.local")
        self.assertEqual(self.client.get("/t/ok").status_code, 303)

    def test_roles(self):
        self.login_as(self.viewer)
        self.assertEqual(self.client.get("/t/ok").status_code, 200)
        self.assertEqual(self.client.get("/t/editor").status_code, 403)
        self.assertEqual(self.client.get("/t/admin").status_code, 403)
        self.login_as(self.editor)
        self.assertEqual(self.client.get("/t/editor").status_code, 200)
        self.assertEqual(self.client.get("/t/admin").status_code, 403)
        self.login_as(self.admin)
        self.assertEqual(self.client.get("/t/editor").status_code, 200)
        self.assertEqual(self.client.get("/t/admin").status_code, 200)

    def test_admin_disabled(self):
        self.login_as(self.admin)
        self.assertEqual(self.client.get("/t/admin").status_code, 200)
        with mock.patch.dict(os.environ, {"ADMIN_ENABLED": "false"}):
            r = self.client.get("/t/ok")                                   # 기존 admin 세션 즉시 무효화
            self.assertEqual(r.status_code, 303)
            self.assertEqual(self.conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE user_id=?", (self.admin,)).fetchone()[0], 0)
        self.assertEqual(self.client.get("/t/ok").status_code, 303)        # 다시 켜도 세션은 이미 삭제됨
        # editor는 admin 전용 라우트에서 403 (admin 꺼짐 + 권한 부족)
        self.login_as(self.editor)
        with mock.patch.dict(os.environ, {"ADMIN_ENABLED": "false"}):
            self.assertEqual(self.client.get("/t/admin").status_code, 403)
            self.assertEqual(self.client.get("/t/ok").status_code, 200)    # 비admin은 영향 없음

    def test_csrf(self):
        token = self.login_as(self.editor)
        self.assertEqual(self.post("/t/post", "name=x").status_code, 403)                      # 누락
        self.assertEqual(self.post("/t/post", "name=x&csrf_token=wrong").status_code, 403)     # 불일치
        self.assertEqual(self.post("/t/post", "name=x&csrf_token=").status_code, 403)
        r = self.post("/t/post", "name=x&csrf_token=" + token)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), {"name": "x"})                                              # 토큰은 제거됨
        # 다른 세션의 토큰은 거부 (세션 바인딩)
        other_token = security.secrets.token_urlsafe(8)
        self.assertEqual(self.post("/t/post", "csrf_token=" + other_token).status_code, 403)

    def test_csrf_token_is_session_bound(self):
        t1 = self.login_as(self.editor)
        self.login_as(self.editor)             # 새 세션(쿠키 교체)
        self.assertEqual(self.post("/t/post", "csrf_token=" + t1).status_code, 403)

    def test_viewer_post_is_403_even_with_valid_csrf(self):
        token = self.login_as(self.viewer)
        self.assertEqual(self.post("/t/post", "csrf_token=" + token).status_code, 403)

    def test_content_type_must_be_urlencoded(self):
        token = self.login_as(self.editor)
        for ctype in ("application/json", "multipart/form-data; boundary=x", "text/plain", ""):
            r = self.client.post("/t/post", content=b"csrf_token=" + token.encode(), headers={"content-type": ctype})
            self.assertEqual(r.status_code, 415, ctype)
        r = self.client.post("/t/post", content=b"csrf_token=" + token.encode(),
                             headers={"content-type": "application/x-www-form-urlencoded; charset=utf-8"})
        self.assertEqual(r.status_code, 200)
        r = self.client.post("/t/post", content=b"csrf_token=" + token.encode(),
                             headers={"content-type": "application/x-www-form-urlencoded; charset=latin-1"})
        self.assertEqual(r.status_code, 415)

    def test_body_over_1mb_is_413(self):
        token = self.login_as(self.editor)
        big = "csrf_token=%s&x=%s" % (token, "a" * (config.MAX_BODY_BYTES + 1))
        self.assertEqual(self.post("/t/post", big).status_code, 413)
        # Content-Length 없이 chunked로 보내도 실제 수신량으로 차단
        def gen():
            for _ in range(20):
                yield b"x=" + b"a" * 100_000 + b"&"
        r = self.client.post("/t/post", content=gen(),
                             headers={"content-type": "application/x-www-form-urlencoded"})
        self.assertEqual(r.status_code, 413)
        # 제한 이하는 통과
        ok = "csrf_token=%s&x=%s" % (token, "a" * 1000)
        self.assertEqual(self.post("/t/post", ok).status_code, 200)

    def test_field_count_limit(self):
        token = self.login_as(self.editor)
        body = "csrf_token=%s&" % token + "&".join("f%d=1" % i for i in range(config.MAX_FORM_FIELDS + 5))
        self.assertEqual(self.post("/t/post", body).status_code, 400)

    def test_invalid_utf8_body_is_400(self):
        token = self.login_as(self.editor)
        r = self.client.post("/t/post", content=b"csrf_token=" + token.encode() + b"&x=%ff%fe",
                             headers={"content-type": "application/x-www-form-urlencoded"})
        self.assertEqual(r.status_code, 200)        # %ff는 퍼센트 디코딩 시 U+FFFD로 치환되어 통과
        r = self.client.post("/t/post", content=b"x=\xff\xfe",
                             headers={"content-type": "application/x-www-form-urlencoded"})
        self.assertEqual(r.status_code, 400)

    def test_blank_values_kept(self):
        token = self.login_as(self.editor)
        r = self.post("/t/post", "csrf_token=%s&a=&b=1" % token)
        self.assertEqual(r.json(), {"a": "", "b": "1"})

    def test_must_change_password_gate(self):
        self.conn.execute("UPDATE users SET must_change_password=1 WHERE id=?", (self.editor,))
        self.login_as(self.editor)
        r = self.client.get("/t/ok")
        self.assertEqual((r.status_code, r.headers["location"]), (303, "/password"))
        self.assertEqual(self.client.get("/password").status_code, 200)   # 변경 화면은 접근 가능

    def test_flash_rendered_once_on_get(self):
        self.login_as(self.editor)
        user = security.lookup_session(self.conn, self.client.cookies.get(config.SESSION_COOKIE, domain="testserver.local"))
        security.add_flash(self.conn, user, "저장했습니다 <b>x</b>")
        first = self.client.get("/t/page")
        self.assertIn("저장했습니다 &lt;b&gt;x&lt;/b&gt;", first.text)     # 자동 이스케이프
        self.assertNotIn("저장했습니다 <b>x</b>", first.text)
        self.assertNotIn("저장했습니다", self.client.get("/t/page").text)

    def test_template_autoescape_enabled(self):
        from app.templating import _env
        self.assertTrue(_env.autoescape)

    def test_logout_form_present_and_no_inline_script_or_style(self):
        self.login_as(self.editor)
        html = self.client.get("/t/page").text
        for needle in ("<script>", "style=", "onclick=", "onerror="):
            self.assertNotIn(needle, html)
        self.assertIn('action="/logout"', html)
        self.assertNotIn("/users", html)                                   # editor에게 admin 메뉴 숨김
        self.assertIn("/tags", html)

    def test_admin_menu_visibility(self):
        self.login_as(self.admin)
        self.assertIn("/users", self.client.get("/t/page").text)
        with mock.patch.dict(os.environ, {"ADMIN_ENABLED": "true"}):
            self.assertIn("/audit", self.client.get("/t/page").text)


class KeyAtStartupTests(DBTestCase):
    def test_app_creates_key_on_first_start_and_keeps_it(self):
        from starlette.testclient import TestClient
        from app.main import create_app
        path = config.DATA_DIR / "secret.key"
        self.assertFalse(path.exists())
        with TestClient(create_app(), base_url="https://testserver") as c:
            first = path.read_bytes()
            self.assertEqual(c.app.state.secret_key, first)
        with TestClient(create_app(), base_url="https://testserver") as c:
            self.assertEqual(path.read_bytes(), first)

    def test_corrupted_key_aborts_startup(self):
        from starlette.testclient import TestClient
        from app.main import create_app
        (config.DATA_DIR / "secret.key").write_bytes(b"bad")
        with self.assertRaises(RuntimeError):
            with TestClient(create_app(), base_url="https://testserver"):
                pass
        self.assertEqual((config.DATA_DIR / "secret.key").read_bytes(), b"bad")


if __name__ == "__main__":
    unittest.main()
