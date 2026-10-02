import os
import re
from unittest import mock
from urllib.parse import urlencode

from app import config, security
from tests.base import NOW, WebTestCase

PW = "correct-horse-battery"


class AdminCase(WebTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.make_user("boss", "admin")
        self.csrf = self.login_as(self.admin)

    def make_user(self, username, role="editor", must_change=0, active=1, password=PW):
        uid = self.user(username, role)
        self.conn.execute("UPDATE users SET password_hash=?, must_change_password=?, is_active=?, display_name=? "
                          "WHERE id=?", (security.hash_password(password), must_change, active, "이름-" + username, uid))
        return uid

    def post_form(self, path, **data):
        data.setdefault("csrf_token", self.csrf)
        return self.post(path, urlencode(data))

    def row(self, username):
        return self.conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

    def temp_password(self, response):
        return re.search(r"<code>([^<]+)</code>", response.text).group(1)

    def audits(self, action):
        return self.conn.execute("SELECT * FROM audit_logs WHERE action=? ORDER BY id", (action,)).fetchall()


class UserAccessTests(AdminCase):
    PATHS = ["/users", "/users/new", "/audit"]

    def test_non_admins_get_403(self):
        for role in ("viewer", "editor"):
            uid = self.make_user("u-" + role, role)
            token = self.login_as(uid)
            for path in self.PATHS + [f"/users/{self.admin}/edit"]:
                self.assertEqual(self.client.get(path).status_code, 403, (role, path))
            for path in ("/users/new", f"/users/{self.admin}/edit", f"/users/{self.admin}/reset-password"):
                self.assertEqual(self.post(path, urlencode({"csrf_token": token})).status_code, 403, (role, path))

    def test_unauthenticated_redirects(self):
        self.client.cookies.clear()
        for path in self.PATHS:
            r = self.client.get(path)
            self.assertEqual(r.status_code, 303, path)
            self.assertTrue(r.headers["location"].startswith("/login"))

    def test_routes_403_when_admin_disabled(self):
        editor = self.make_user("ed", "editor")
        self.login_as(editor)
        with mock.patch.dict(os.environ, {"ADMIN_ENABLED": "false"}):
            for path in self.PATHS:
                self.assertEqual(self.client.get(path).status_code, 403, path)

    def test_admin_session_dies_when_admin_disabled(self):
        with mock.patch.dict(os.environ, {"ADMIN_ENABLED": "false"}):
            self.assertEqual(self.client.get("/users").status_code, 303)

    def test_menu_visibility(self):
        html = self.client.get("/users").text
        for link in ('href="/users"', 'href="/audit"', 'href="/backup"', 'href="/tags"'):
            self.assertIn(link, html)


class UserCreateTests(AdminCase):
    def test_create_shows_temp_password_once(self):
        r = self.post_form("/users/new", username="alice", display_name="앨리스", team="개발1팀", role="editor")
        self.assertEqual(r.status_code, 200)
        pw = self.temp_password(r)
        self.assertGreaterEqual(len(pw), 20)
        row = self.row("alice")
        self.assertEqual((row["role"], row["team"], row["is_active"], row["must_change_password"]),
                         ("editor", "개발1팀", 1, 1))
        self.assertTrue(security.verify_password(row["password_hash"], pw))
        self.assertNotIn(pw, row["password_hash"])
        self.assertEqual(r.headers["cache-control"], "no-store")
        # 다시 볼 수 없다: 목록/수정 화면/flash/감사 로그 어디에도 없음
        for path in ("/users", f"/users/{row['id']}/edit", "/audit"):
            self.assertNotIn(pw, self.client.get(path).text)
        audit = self.audits("user_create")[0]
        self.assertEqual((audit["user_id"], audit["target_id"]), (self.admin, row["id"]))
        self.assertNotIn(pw, audit["summary"])
        self.assertIn("alice", audit["summary"])

    def test_new_user_must_change_password_on_first_login(self):
        r = self.post_form("/users/new", username="alice", display_name="앨리스", role="viewer")
        pw = self.temp_password(r)
        self.client.cookies.clear()
        login = self.post("/login", urlencode({"username": "alice", "password": pw}))
        self.assertEqual(login.headers["location"], "/password")
        self.assertEqual(self.client.get("/users").status_code, 303)      # 게이트 + 권한 모두 막힘

    def test_validation_errors_keep_input(self):
        for bad, field in (
            (dict(username="a", display_name="x", role="viewer"), "username"),
            (dict(username="bad name!", display_name="x", role="viewer"), "username"),
            (dict(username="-lead", display_name="x", role="viewer"), "username"),
            (dict(username="ok-name", display_name="", role="viewer"), "display_name"),
            (dict(username="ok-name", display_name="x", role="root"), "role"),
            (dict(username="ok-name", display_name="x" * 101, role="viewer"), "display_name"),
            (dict(username="ok-name", display_name="x", role="viewer", team="t" * 101), "team"),
        ):
            r = self.post_form("/users/new", **bad)
            self.assertEqual(r.status_code, 422, bad)
            self.assertIn("field-error", r.text, bad)
            self.assertIn('class="field has-error"', r.text)
            self.assertIsNone(self.row(bad["username"]) if bad["username"] != "a" else self.row("a"))
        r = self.post_form("/users/new", username="keep-me!", display_name="유지되는 이름", role="viewer")
        self.assertIn("유지되는 이름", r.text)                              # 입력값 유지

    def test_unknown_field_rejected(self):
        r = self.post_form("/users/new", username="alice", display_name="a", role="viewer", is_active="on")
        self.assertEqual(r.status_code, 422)
        self.assertIsNone(self.row("alice"))

    def test_duplicate_username_case_insensitive(self):
        self.post_form("/users/new", username="alice", display_name="a", role="viewer")
        r = self.post_form("/users/new", username="ALICE", display_name="b", role="viewer")
        self.assertEqual(r.status_code, 422)
        self.assertIn("이미 사용 중", r.text)

    def test_csrf_required(self):
        r = self.post("/users/new", urlencode({"username": "alice", "display_name": "a", "role": "viewer"}))
        self.assertEqual(r.status_code, 403)
        r = self.post_form("/users/new", csrf_token="bad", username="alice", display_name="a", role="viewer")
        self.assertEqual(r.status_code, 403)
        self.assertIsNone(self.row("alice"))


class UserEditTests(AdminCase):
    def setUp(self):
        super().setUp()
        self.bob = self.make_user("bob", "editor")

    def edit(self, uid, **data):
        data.setdefault("display_name", "밥")
        data.setdefault("team", "")
        data.setdefault("role", "editor")
        return self.post_form(f"/users/{uid}/edit", **data)

    def test_edit_form_is_prefilled_and_username_readonly(self):
        html = self.client.get(f"/users/{self.bob}/edit").text
        self.assertIn("이름-bob", html)
        self.assertIn("checked", html)
        self.assertNotIn('name="username"', html)

    def test_profile_change_keeps_sessions(self):
        sess = security.create_session(self.conn, self.bob)
        r = self.edit(self.bob, display_name="새 이름", team="인프라", is_active="on")
        self.assertEqual((r.status_code, r.headers["location"]), (303, "/users"))
        row = self.row("bob")
        self.assertEqual((row["display_name"], row["team"]), ("새 이름", "인프라"))
        self.assertIsNotNone(security.lookup_session(self.conn, sess))      # 역할/활성 변경이 아니면 유지
        self.assertIn("저장했습니다.", self.client.get("/users").text)
        summary = self.audits("user_update")[0]["summary"]
        self.assertIn("display_name: 이름-bob → 새 이름", summary)
        self.assertNotIn("is_active", summary)

    def test_role_change_revokes_sessions(self):
        sess = security.create_session(self.conn, self.bob)
        self.edit(self.bob, role="viewer", is_active="on")
        self.assertEqual(self.row("bob")["role"], "viewer")
        self.assertIsNone(security.lookup_session(self.conn, sess))
        self.assertIn("role: editor → viewer", self.audits("user_update")[0]["summary"])

    def test_deactivation_revokes_sessions_and_blocks_login(self):
        sess = security.create_session(self.conn, self.bob)
        self.edit(self.bob)                                                 # is_active 미전송 = 비활성화
        self.assertEqual(self.row("bob")["is_active"], 0)
        self.assertIsNone(security.lookup_session(self.conn, sess))
        self.client.cookies.clear()
        self.assertEqual(self.post("/login", urlencode({"username": "bob", "password": PW})).status_code, 401)
        self.csrf = self.login_as(self.admin)
        self.assertIn("비활성", self.client.get("/users").text)
        # 재활성화
        r = self.edit(self.bob, is_active="on")
        self.assertEqual(r.status_code, 303, r.text[-300:])
        self.assertEqual(self.row("bob")["is_active"], 1)
        self.client.cookies.clear()
        self.assertEqual(self.post("/login", urlencode({"username": "bob", "password": PW})).status_code, 303)

    def test_no_change_is_not_audited(self):
        self.edit(self.bob, display_name="이름-bob", is_active="on")
        self.assertEqual(self.audits("user_update"), [])

    def test_cannot_deactivate_or_demote_self(self):
        r = self.edit(self.admin, display_name="x", role="admin")           # is_active 누락 = 비활성화 시도
        self.assertEqual(r.status_code, 422)
        self.assertIn("본인 계정", r.text)
        r = self.edit(self.admin, display_name="x", role="editor", is_active="on")
        self.assertEqual(r.status_code, 422)
        row = self.row("boss")
        self.assertEqual((row["role"], row["is_active"]), ("admin", 1))
        r = self.edit(self.admin, display_name="나의 새 이름", role="admin", is_active="on")   # 이름 변경은 가능
        self.assertEqual(r.status_code, 303)

    def test_validation_and_missing_user(self):
        self.assertEqual(self.edit(self.bob, role="god").status_code, 422)
        self.assertEqual(self.edit(self.bob, display_name="").status_code, 422)
        self.assertEqual(self.post_form(f"/users/{self.bob}/edit", display_name="a", role="viewer", username="x").status_code, 422)
        self.assertEqual(self.client.get("/users/9999/edit").status_code, 404)
        self.assertEqual(self.edit(9999).status_code, 404)

    def test_admin_can_promote_to_admin(self):
        self.edit(self.bob, role="admin", is_active="on")
        self.assertEqual(self.row("bob")["role"], "admin")


class PasswordResetTests(AdminCase):
    def setUp(self):
        super().setUp()
        self.bob = self.make_user("bob", "editor")

    def test_reset(self):
        sess = security.create_session(self.conn, self.bob)
        r = self.post_form(f"/users/{self.bob}/reset-password")
        self.assertEqual(r.status_code, 200)
        pw = self.temp_password(r)
        row = self.row("bob")
        self.assertTrue(security.verify_password(row["password_hash"], pw))
        self.assertFalse(security.verify_password(row["password_hash"], PW))
        self.assertEqual(row["must_change_password"], 1)
        self.assertIsNone(security.lookup_session(self.conn, sess))
        audit = self.audits("user_password_reset")[0]
        self.assertEqual(audit["target_id"], self.bob)
        self.assertNotIn(pw, audit["summary"])
        for path in ("/users", "/audit"):
            self.assertNotIn(pw, self.client.get(path).text)

    def test_self_reset_is_refused(self):
        before = self.row("boss")["password_hash"]
        r = self.post_form(f"/users/{self.admin}/reset-password")
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.row("boss")["password_hash"], before)
        self.assertIn("본인 비밀번호", self.client.get(f"/users/{self.admin}/edit").text)

    def test_reset_requires_csrf_and_post(self):
        self.assertEqual(self.client.get(f"/users/{self.bob}/reset-password").status_code, 405)
        self.assertEqual(self.post(f"/users/{self.bob}/reset-password", "").status_code, 403)
        self.assertEqual(self.post_form("/users/9999/reset-password").status_code, 404)


class UserListTests(AdminCase):
    def test_list_escapes_and_shows_state(self):
        self.make_user("xss", "viewer")
        self.conn.execute("UPDATE users SET display_name='<script>alert(1)</script>' WHERE username='xss'")
        self.make_user("old", "viewer", active=0, must_change=1)
        html = self.client.get("/users").text
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertIn("비활성", html)
        self.assertIn("비밀번호 변경 대기", html)

    def test_no_delete_route(self):
        uid = self.make_user("bob")
        for method in ("delete", "get"):
            self.assertEqual(getattr(self.client, method)(f"/users/{uid}/delete").status_code, 404)
        self.assertEqual(self.post_form(f"/users/{uid}/delete").status_code, 404)


class AuditViewTests(AdminCase):
    def add(self, at, username="boss", action="login_success", target_type="", target_id=None, summary=""):
        self.conn.execute(
            "INSERT INTO audit_logs (at, username, ip, action, target_type, target_id, summary) VALUES (?,?,?,?,?,?,?)",
            (at, username, "10.0.0.1", action, target_type, target_id, summary))

    def test_lists_newest_first_in_kst(self):
        self.add("2026-01-01T15:30:00Z", action="a_first")
        self.add("2026-01-02T00:00:00Z", action="b_second")
        html = self.client.get("/audit").text.split("<tbody>")[1]
        self.assertIn("2026-01-02 00:30:00", html)                          # UTC 15:30 → KST 다음 날 00:30
        self.assertIn("2026-01-02 09:00:00", html)
        self.assertLess(html.index("b_second"), html.index("a_first"))
        self.assertEqual(self.client.get("/audit").headers["cache-control"], "no-store")

    def test_filters(self):
        self.add("2026-03-01T14:59:59Z", username="alice", action="login_failed")      # KST 3/1 23:59:59
        self.add("2026-03-01T15:00:00Z", username="alice", action="login_success")     # KST 3/2 00:00:00
        self.add("2026-03-02T10:00:00Z", username="bob", action="server_update", target_type="server", target_id=7)
        self.add("2026-03-04T10:00:00Z", username="bob", action="server_delete", target_type="server", target_id=8)

        def actions(**params):
            html = self.client.get("/audit?" + urlencode(params)).text
            return {a for a in ("login_failed", "login_success", "server_update", "server_delete") if
                    re.search(r"<td>%s</td>" % a, html)}

        self.assertEqual(actions(date_from="2026-03-02", date_to="2026-03-02"), {"login_success", "server_update"})
        self.assertEqual(actions(date_to="2026-03-01"), {"login_failed"})        # 종료일 당일(KST) 포함
        self.assertEqual(actions(date_from="2026-03-03"), {"server_delete"})
        self.assertEqual(actions(user="ALICE"), {"login_failed", "login_success"})
        self.assertEqual(actions(action="server_update"), {"server_update"})
        self.assertEqual(actions(target_type="server"), {"server_update", "server_delete"})
        self.assertEqual(actions(user="bob", target_type="server", date_to="2026-03-02"), {"server_update"})
        self.assertEqual(actions(user="nobody"), set())

    def test_invalid_filters_show_errors_not_data(self):
        for params in ({"date_from": "2026-13-45"}, {"page": "0"}, {"page": "abc"}, {"evil": "<b>"},
                       {"action": "x" * 51}):
            r = self.client.get("/audit?" + urlencode(params))
            self.assertEqual(r.status_code, 200, params)
            self.assertIn("조회 조건이 올바르지 않습니다", r.text, params)
            self.assertNotIn("<b>", r.text)

    def test_sql_injection_in_filter_is_harmless(self):
        self.add("2026-03-01T00:00:00Z", action="keep_me")
        r = self.client.get("/audit?" + urlencode({"action": "x' OR '1'='1"}))
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("keep_me</td>", r.text)
        self.assertGreater(self.conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0], 0)

    def test_pagination(self):
        for i in range(120):
            self.add("2026-03-01T00:%02d:00Z" % (i % 60), action="bulk_%03d" % i)
        total = self.conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
        p1 = self.client.get("/audit?action=").text
        self.assertEqual(p1.count("<tr>") - 1, 50)                           # 헤더 행 제외
        self.assertIn("page=2", p1)
        pages = -(-total // 50)
        last = self.client.get(f"/audit?page={pages}").text
        self.assertNotIn(f"page={pages + 1}", last)
        self.assertEqual(self.client.get("/audit?page=99999").status_code, 200)   # 범위 초과는 마지막 쪽으로 보정
        # 필터가 페이지 링크에 유지된다
        filtered = self.client.get("/audit?action=bulk_001&user=").text
        self.assertNotIn("page=2", filtered)

    def test_summary_is_escaped_and_multiline_preserved(self):
        self.add("2026-03-01T00:00:00Z", summary="name: <script>alert(1)</script>")
        html = self.client.get("/audit").text
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn('class="pre"', html)

    def test_read_only(self):
        for method in ("post", "put", "patch", "delete"):
            r = getattr(self.client, method)("/audit")
            self.assertEqual(r.status_code, 405, method)
        self.assertEqual(self.client.get("/audit/1/delete").status_code, 404)

    def test_login_and_user_actions_show_up(self):
        self.client.cookies.clear()
        self.post("/login", urlencode({"username": "boss", "password": PW}))
        self.post("/login", urlencode({"username": "boss", "password": "wrong-password-1"}))
        html = self.client.get("/audit").text
        self.assertIn("login_success", html)
        self.assertIn("login_failed", html)
        self.assertNotIn("wrong-password-1", html)
