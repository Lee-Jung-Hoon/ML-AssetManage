import io
import os
import re
import unittest
from contextlib import redirect_stdout
from unittest import mock
from urllib.parse import urlencode

from starlette.testclient import TestClient

from app import __main__ as cli
from app import config, security
from app.main import create_app
from app.schemas import LoginForm, validate_form
from tests.base import DBTestCase, WebTestCase

PW = "correct-horse-battery"
GENERIC = "사용자명 또는 비밀번호가 올바르지 않습니다."


class BootstrapTests(WebTestCase):
    def test_first_start_creates_admin_and_logs_password_once(self):
        # WebTestCase.setUp이 이미 한 번 기동했다 (그때 admin이 생성됨)
        rows = self.conn.execute("SELECT * FROM users").fetchall()
        self.assertEqual([r["username"] for r in rows], ["admin"])
        admin = rows[0]
        self.assertEqual((admin["role"], admin["is_active"], admin["must_change_password"]), ("admin", 1, 1))
        self.assertTrue(admin["password_hash"].startswith("scrypt$"))
        audit = self.conn.execute("SELECT action, user_id FROM audit_logs").fetchall()
        self.assertEqual([a["action"] for a in audit], ["bootstrap_admin"])

    def test_password_logged_exactly_once_and_not_on_restart(self):
        self.conn.execute("DELETE FROM sessions")
        self.conn.execute("DROP TRIGGER audit_logs_no_delete")
        self.conn.execute("DELETE FROM audit_logs")
        self.conn.execute("DELETE FROM users")
        with self.assertLogs("app", "WARNING") as first:
            with TestClient(create_app(), base_url="https://testserver"):
                pass
        text = "\n".join(first.output)
        password = re.search(r"비밀번호: (\S+)", text).group(1)
        self.assertGreaterEqual(len(password), 20)
        stored = self.conn.execute("SELECT password_hash FROM users WHERE username='admin'").fetchone()[0]
        self.assertTrue(security.verify_password(stored, password))
        self.assertEqual(text.count(password), 1)
        # 재기동: 새 계정/로그 없음
        with self.assertNoLogs("app", "WARNING"):
            with TestClient(create_app(), base_url="https://testserver"):
                pass
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)
        self.assertEqual(self.conn.execute("SELECT password_hash FROM users").fetchone()[0], stored)

    def test_no_bootstrap_when_an_admin_exists(self):
        self.conn.execute("DELETE FROM sessions")
        self.conn.execute("UPDATE users SET username='root'")
        with self.assertNoLogs("app", "WARNING"):
            with TestClient(create_app(), base_url="https://testserver"):
                pass
        self.assertEqual([r[0] for r in self.conn.execute("SELECT username FROM users")], ["root"])

    def test_warns_when_admin_name_taken_by_non_admin(self):
        self.conn.execute("UPDATE users SET role='viewer'")
        with self.assertLogs("app", "WARNING") as logs:
            with TestClient(create_app(), base_url="https://testserver"):
                pass
        self.assertIn("reset-admin", "\n".join(logs.output))
        self.assertNotIn("비밀번호:", "\n".join(logs.output))


class LoginBase(WebTestCase):
    def make_user(self, username="bob", role="editor", must_change=0, active=1, password=PW):
        uid = self.user(username, role)
        self.conn.execute(
            "UPDATE users SET password_hash=?, must_change_password=?, is_active=? WHERE id=?",
            (security.hash_password(password), must_change, active, uid))
        return uid

    def do_login(self, username="bob", password=PW, next_path=None):
        data = {"username": username, "password": password}
        if next_path is not None:
            data["next"] = next_path
        return self.post("/login", urlencode(data))

    def audit_actions(self):
        return [(r["action"], r["username"], r["summary"]) for r in self.conn.execute(
            "SELECT action, username, summary FROM audit_logs ORDER BY id")]


class LoginTests(LoginBase):
    def test_login_page_is_public(self):
        r = self.client.get("/login")
        self.assertEqual(r.status_code, 200)
        self.assertIn('name="password"', r.text)
        self.assertIn('type="password"', r.text)
        self.assertEqual(r.headers["cache-control"], "no-store")

    def test_success_sets_hardened_cookie_and_session(self):
        self.make_user()
        r = self.do_login()
        self.assertEqual((r.status_code, r.headers["location"]), (303, "/"))
        cookie = r.headers["set-cookie"]
        self.assertTrue(cookie.startswith("__Host-session="))
        for attr in ("HttpOnly", "Secure", "SameSite=strict", "Path=/"):
            self.assertIn(attr, cookie)
        self.assertNotIn("Domain", cookie)
        raw = re.match(r"__Host-session=([^;]+)", cookie).group(1)
        stored = self.conn.execute("SELECT id_hash FROM sessions s JOIN users u ON u.id=s.user_id "
                                   "WHERE u.username='bob'").fetchone()[0]
        self.assertNotEqual(raw, stored)                                   # DB에는 해시만
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertIn(("login_success", "bob", ""), self.audit_actions())
        row = self.conn.execute("SELECT user_id FROM audit_logs WHERE action='login_success'").fetchone()
        self.assertIsNotNone(row["user_id"])

    def test_session_id_is_reissued_on_login(self):
        self.make_user()
        first = self.do_login()
        old_raw = re.match(r"__Host-session=([^;]+)", first.headers["set-cookie"]).group(1)
        second = self.do_login()                                           # 이미 로그인한 쿠키를 가진 채 재로그인
        new_raw = re.match(r"__Host-session=([^;]+)", second.headers["set-cookie"]).group(1)
        self.assertNotEqual(old_raw, new_raw)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.username='bob'").fetchone()[0], 1)
        self.assertIsNone(security.lookup_session(self.conn, old_raw))

    def test_attacker_chosen_cookie_is_not_adopted(self):
        self.make_user()
        self.client.cookies.set(config.SESSION_COOKIE, "attacker-chosen-value", domain="testserver.local")
        r = self.do_login()
        self.assertNotIn("attacker-chosen-value", r.headers["set-cookie"])

    def test_failures_all_look_identical(self):
        self.make_user()
        self.make_user("sleepy", active=0)
        self.make_user("root2", role="admin")
        bodies = []
        cases = [("bob", "wrong-password-xx"), ("ghost", PW), ("sleepy", PW), ("", ""), ("bob", "")]
        for u, p in cases:
            r = self.do_login(u, p)
            self.assertEqual(r.status_code, 401, (u, p))
            self.assertIn(GENERIC, r.text)
            self.assertNotIn(p, r.text) if p else None
            bodies.append(re.sub(r'value="[^"]*"', "", r.text))
        with mock.patch.dict(os.environ, {"ADMIN_ENABLED": "false"}):
            r = self.do_login("root2")
        self.assertEqual((r.status_code, GENERIC in r.text), (401, True))
        bodies.append(re.sub(r'value="[^"]*"', "", r.text))
        self.assertEqual(len(set(bodies)), 1)                              # 어떤 사유든 응답 본문이 같다
        self.assertNotIn("set-cookie", r.headers)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM sessions WHERE user_id != 1").fetchone()[0], 0)

    def test_failed_login_is_audited_with_attempted_username_only(self):
        self.make_user()
        self.do_login("bob", "wrong-password-xx")
        self.do_login("x" * 50, "p")
        failed = [a for a in self.audit_actions() if a[0] == "login_failed"]
        self.assertEqual(failed[0][1], "bob")
        self.assertNotIn("wrong-password-xx", str(self.audit_actions()))

    def test_lockout_after_5_failures_then_unlock(self):
        clock = {"t": 1000.0}
        security.login_limiter = security.LoginLimiter(clock=lambda: clock["t"])
        self.make_user()
        for _ in range(5):
            self.assertEqual(self.do_login("bob", "wrong-password-xx").status_code, 401)
        r = self.do_login("bob", PW)                                       # 올바른 비밀번호도 잠금 중에는 실패
        self.assertEqual((r.status_code, GENERIC in r.text), (401, True))
        clock["t"] += config.LOGIN_LOCK_SECONDS + 1
        self.assertEqual(self.do_login("bob", PW).status_code, 303)
        self.assertIn("locked", [a[2] for a in self.audit_actions() if a[0] == "login_failed"])

    def test_next_parameter_is_validated(self):
        self.make_user()
        r = self.do_login(next_path="/servers?page=2")
        self.assertEqual(r.headers["location"], "/servers?page=2")
        for evil in ("//evil.com", "https://evil.com", "/\\evil.com", "javascript:alert(1)"):
            self.client.cookies.clear()
            r = self.do_login(next_path=evil)
            self.assertEqual(r.headers["location"], "/", evil)
        page = self.client.get("/login?next=//evil.com")
        self.assertNotIn("evil.com", page.text)

    def test_login_redirects_to_next_after_protected_page_bounce(self):
        self.make_user()
        r = self.client.get("/t/ok?tab=a")
        self.assertEqual(r.headers["location"], "/login?next=%2Ft%2Fok%3Ftab%3Da")

    def test_logged_in_user_skips_login_page(self):
        self.make_user()
        self.do_login()
        r = self.client.get("/login")
        self.assertEqual((r.status_code, r.headers["location"]), (303, "/"))

    def test_login_post_requires_urlencoded_and_size_limit(self):
        r = self.client.post("/login", json={"username": "a", "password": "b"})
        self.assertEqual(r.status_code, 415)
        r = self.post("/login", "username=a&password=" + "x" * (config.MAX_BODY_BYTES + 1))
        self.assertEqual(r.status_code, 413)

    def test_password_is_not_stripped_or_trimmed(self):
        obj, _ = validate_form(LoginForm, {"username": "a", "password": "  spaced  "})
        self.assertEqual(obj.password, "  spaced  ")

    def test_login_with_unknown_field_fails_generically(self):
        self.make_user()
        r = self.post("/login", urlencode({"username": "bob", "password": PW, "evil": "1"}))
        self.assertEqual((r.status_code, GENERIC in r.text), (401, True))


class AdminDisabledTests(LoginBase):
    def test_admin_cannot_login_and_session_dies_when_disabled(self):
        self.make_user("boss", role="admin")
        self.make_user("ed", role="editor")
        self.assertEqual(self.do_login("boss").status_code, 303)
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertIn("/users", self.client.get("/").text)                 # 메뉴 표시
        with mock.patch.dict(os.environ, {"ADMIN_ENABLED": "false"}):
            self.assertEqual(self.client.get("/").status_code, 303)        # 기존 세션 즉시 무효화
            self.assertEqual(self.do_login("boss").status_code, 401)
        self.client.cookies.clear()
        with mock.patch.dict(os.environ, {"ADMIN_ENABLED": "false"}):
            self.assertEqual(self.do_login("ed").status_code, 303)
            page = self.client.get("/")
            self.assertEqual(page.status_code, 200)
            self.assertNotIn("/audit", page.text)


class MustChangePasswordTests(LoginBase):
    def setUp(self):
        super().setUp()
        self.uid = self.make_user(must_change=1)

    def test_forced_flow(self):
        r = self.do_login(next_path="/servers")
        self.assertEqual(r.headers["location"], "/password")               # next보다 변경이 우선
        r = self.client.get("/")
        self.assertEqual((r.status_code, r.headers["location"]), (303, "/password"))
        page = self.client.get("/password")
        self.assertEqual(page.status_code, 200)
        self.assertIn("초기 또는 임시 비밀번호", page.text)

    def csrf(self):
        return self.conn.execute("SELECT csrf_token FROM sessions WHERE user_id=?", (self.uid,)).fetchone()[0]

    def change(self, current=PW, new="brand-new-password-1", confirm=None, token=None):
        return self.post("/password", urlencode({
            "csrf_token": token or self.csrf(), "current_password": current, "new_password": new,
            "new_password2": new if confirm is None else confirm}))

    def test_validation_errors_rerender_without_echo(self):
        self.do_login()
        cases = [
            (dict(current="wrong-current-pass"), "현재 비밀번호가 올바르지 않습니다."),
            (dict(new="short"), "12자 이상"),
            (dict(new="bob"), "12자 이상"),
            (dict(new=PW), "다른 비밀번호"),
            (dict(confirm="different-password-9"), "확인이 일치하지 않습니다."),
        ]
        for kwargs, expected in cases:
            r = self.change(**kwargs)
            self.assertEqual(r.status_code, 422, kwargs)
            self.assertIn(expected, r.text, kwargs)
            self.assertNotIn(PW, r.text)
            self.assertNotIn("brand-new", r.text)
        stored = self.conn.execute("SELECT must_change_password FROM users WHERE id=?", (self.uid,)).fetchone()[0]
        self.assertEqual(stored, 1)

    def test_username_equal_password_rejected(self):
        self.do_login()
        r = self.change(new="bobbobbobbob")                                # 길이는 충분
        self.assertEqual(r.status_code, 303)
        self.conn.execute("UPDATE users SET must_change_password=1")
        self.do_login("bob", "bobbobbobbob")
        r = self.change(current="bobbobbobbob", new="BOB")
        self.assertEqual(r.status_code, 422)

    def test_success_invalidates_all_sessions_and_issues_new_one(self):
        self.do_login()
        other = security.create_session(self.conn, self.uid)               # 다른 기기의 세션
        old_cookie = self.client.cookies.get(config.SESSION_COOKIE, domain="testserver.local")
        r = self.change()
        self.assertEqual((r.status_code, r.headers["location"]), (303, "/"))
        self.assertIsNone(security.lookup_session(self.conn, other))
        self.assertIsNone(security.lookup_session(self.conn, old_cookie))
        new_cookie = re.match(r"__Host-session=([^;]+)", r.headers["set-cookie"]).group(1)
        self.assertIsNotNone(security.lookup_session(self.conn, new_cookie))
        row = self.conn.execute("SELECT * FROM users WHERE id=?", (self.uid,)).fetchone()
        self.assertEqual(row["must_change_password"], 0)
        self.assertTrue(security.verify_password(row["password_hash"], "brand-new-password-1"))
        self.assertFalse(security.verify_password(row["password_hash"], PW))
        page = self.client.get("/")                                        # 게이트 해제 + flash 표시
        self.assertEqual(page.status_code, 200)
        self.assertIn("비밀번호를 변경했습니다.", page.text)
        self.assertNotIn("비밀번호를 변경했습니다.", self.client.get("/").text)
        audit = self.conn.execute("SELECT summary FROM audit_logs WHERE action='password_change'").fetchone()
        self.assertEqual(audit["summary"], "")
        self.assertNotIn("brand-new", str(self.audit_actions()))
        self.client.cookies.clear()
        self.assertEqual(self.do_login("bob", PW).status_code, 401)        # 이전 비밀번호 폐기
        self.assertEqual(self.do_login("bob", "brand-new-password-1").status_code, 303)

    def test_csrf_required(self):
        self.do_login()
        r = self.change(token="wrong")
        self.assertEqual(r.status_code, 403)

    def test_current_password_guessing_is_rate_limited(self):
        self.do_login()
        for _ in range(5):
            self.assertEqual(self.change(current="wrong-current-pass").status_code, 422)
        r = self.change(current=PW)                                        # 잠금 중에는 맞아도 거부
        self.assertEqual(r.status_code, 422)
        self.assertIn("횟수를 초과", r.text)


class LogoutTests(LoginBase):
    def test_logout(self):
        uid = self.make_user()
        self.do_login()
        self.assertEqual(self.client.get("/logout").status_code, 405)      # GET 불가
        token = self.conn.execute("SELECT csrf_token FROM sessions WHERE user_id=?", (uid,)).fetchone()[0]
        self.assertEqual(self.post("/logout", "").status_code, 403)         # CSRF 누락
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM sessions WHERE user_id=?", (uid,)).fetchone()[0], 1)
        r = self.post("/logout", "csrf_token=" + token)
        self.assertEqual((r.status_code, r.headers["location"]), (303, "/login"))
        self.assertIn("Max-Age=0", r.headers["set-cookie"])
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM sessions WHERE user_id=?", (uid,)).fetchone()[0], 0)
        self.assertIn(("logout", "bob", ""), self.audit_actions())
        self.assertEqual(self.client.get("/").status_code, 303)

    def test_logout_allowed_while_password_change_pending(self):
        uid = self.make_user(must_change=1)
        self.do_login()
        token = self.conn.execute("SELECT csrf_token FROM sessions WHERE user_id=?", (uid,)).fetchone()[0]
        self.assertEqual(self.post("/logout", "csrf_token=" + token).headers["location"], "/login")


class ResetAdminTests(DBTestCase):
    def setUp(self):
        super().setUp()
        for name, value in dict(SCRYPT_N=2**4, SCRYPT_R=8, SCRYPT_P=1).items():
            p = mock.patch.object(config, name, value)
            p.start()
            self.addCleanup(p.stop)

    def admin_row(self):
        return self.conn.execute("SELECT * FROM users WHERE username='admin'").fetchone()

    def test_creates_admin_when_missing(self):
        pw = security.reset_admin(self.conn)
        row = self.admin_row()
        self.assertEqual((row["role"], row["is_active"], row["must_change_password"]), ("admin", 1, 1))
        self.assertTrue(security.verify_password(row["password_hash"], pw))

    def test_resets_password_revokes_sessions_and_audits(self):
        old = security.bootstrap_admin(self.conn)
        uid = self.admin_row()["id"]
        raw = security.create_session(self.conn, uid)
        self.conn.execute("UPDATE users SET must_change_password=0")
        new = security.reset_admin(self.conn)
        row = self.admin_row()
        self.assertNotEqual(old, new)
        self.assertGreaterEqual(len(new), 20)
        self.assertTrue(security.verify_password(row["password_hash"], new))
        self.assertFalse(security.verify_password(row["password_hash"], old))
        self.assertEqual(row["must_change_password"], 1)
        self.assertIsNone(security.lookup_session(self.conn, raw))
        log = self.conn.execute("SELECT * FROM audit_logs WHERE action='reset_admin'").fetchone()
        self.assertEqual((log["target_id"], log["username"]), (uid, "(cli)"))
        self.assertNotIn(new, log["summary"])

    def test_restores_demoted_or_deactivated_admin(self):
        security.bootstrap_admin(self.conn)
        self.conn.execute("UPDATE users SET role='viewer', is_active=0")
        security.reset_admin(self.conn)
        row = self.admin_row()
        self.assertEqual((row["role"], row["is_active"]), ("admin", 1))
        self.assertIn("복구", self.conn.execute("SELECT summary FROM audit_logs WHERE action='reset_admin'").fetchone()[0])

    def test_works_regardless_of_admin_enabled(self):
        with mock.patch.dict(os.environ, {"ADMIN_ENABLED": "false"}):
            self.assertTrue(security.reset_admin(self.conn))

    def test_cli_prints_password_and_exits_zero(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(["reset-admin"])
        self.assertEqual(code, 0)
        pw = re.search(r"새 비밀번호: (\S+)", buf.getvalue()).group(1)
        self.assertTrue(security.verify_password(self.admin_row()["password_hash"], pw))


class CliTests(unittest.TestCase):
    def test_healthcheck(self):
        ok = mock.MagicMock()
        ok.__enter__.return_value.status = 200
        ok.__enter__.return_value.read.return_value = b"ok"
        with mock.patch.object(cli.urllib.request, "urlopen", return_value=ok) as m:
            self.assertEqual(cli.main(["healthcheck"]), 0)
            self.assertEqual(m.call_args.args[0], "http://127.0.0.1:8080/healthz")
        bad = mock.MagicMock()
        bad.__enter__.return_value.status = 200
        bad.__enter__.return_value.read.return_value = b"nope"
        with mock.patch.object(cli.urllib.request, "urlopen", return_value=bad):
            self.assertEqual(cli.main(["healthcheck"]), 1)
        with mock.patch.object(cli.urllib.request, "urlopen", side_effect=OSError):
            self.assertEqual(cli.main(["healthcheck"]), 1)

    def test_serve_uses_required_uvicorn_settings(self):
        with mock.patch("uvicorn.run") as run, mock.patch.object(cli.logging, "basicConfig"):
            cli.main(["serve"])
        kwargs = run.call_args.kwargs
        self.assertEqual((kwargs["host"], kwargs["port"], kwargs["workers"]), ("0.0.0.0", 8080, 1))
        self.assertIs(kwargs["proxy_headers"], True)
        self.assertEqual(kwargs["forwarded_allow_ips"], "*")
        self.assertIs(kwargs["server_header"], False)

    def test_unknown_command_exits_2(self):
        with self.assertRaises(SystemExit) as cm, redirect_stdout(io.StringIO()), mock.patch("sys.stderr", io.StringIO()):
            cli.main(["bogus"])
        self.assertEqual(cm.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
