"""CLAUDE.md 5장 보안 체크리스트와 4.0/4.1 공통 규칙을 앱 전체에 대해 자동으로 점검한다 (라우트 introspection 포함)."""
import inspect
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

from fastapi.routing import APIRoute

from app import config, security
from tests.base import WebTestCase, make_test_app
from tests.test_licenses import KEY, ACCOUNT, lic_data
from tests.test_servers import ServerCase, server_data

# 로그인 전에도 접근하는 라우트 (그 외 모든 라우트는 require_login이 걸려야 한다)
PUBLIC = {("GET", "/login"), ("POST", "/login"), ("GET", "/healthz")}
# 로그인만 되어 있으면 되는 POST (역할 검사 없음)
ANY_ROLE_POST = {"/logout", "/password"}
SAMPLE = {"server_id": 1, "service_id": 1, "model_id": 1, "license_id": 1, "user_id": 1, "tag_id": 1, "asset_id": 1,
          "item_id": 1, "note_id": 1, "link_id": 1, "kind": "ips"}


def dependency_calls(dependant) -> list:
    calls = []
    for dep in dependant.dependencies:
        calls.append(dep.call)
        calls += dependency_calls(dep)
    return calls


def real_routes(app):
    """테스트 전용 라우트(/t/...)를 제외한 운영 앱의 APIRoute (include_router는 `_IncludedRouter`로 감싸여 있다)."""
    routes = []
    for r in app.routes:
        if isinstance(r, APIRoute):
            routes.append(r)
        elif hasattr(r, "original_router"):
            routes += [x for x in r.original_router.routes if isinstance(x, APIRoute)]
    return [r for r in routes if not r.path.startswith("/t/")]


def sample_path(path: str) -> str:
    return re.sub(r"\{(\w+)\}", lambda m: str(SAMPLE[m.group(1)]), path)


class RouteIntrospectionTests(WebTestCase):
    def setUp(self):
        super().setUp()
        self.routes = real_routes(self.client.app)

    def test_there_are_many_routes(self):
        self.assertGreater(len(self.routes), 90)

    def test_only_get_and_post_methods_exist(self):
        """상태 변경은 POST로만: PUT/PATCH/DELETE 라우트가 하나도 없어야 한다."""
        methods = {m for r in self.routes for m in r.methods}
        self.assertEqual(methods - {"HEAD"}, {"GET", "POST"})

    def test_every_route_requires_login_except_the_public_ones(self):
        missing = []
        for route in self.routes:
            for method in route.methods - {"HEAD"}:
                if (method, route.path) in PUBLIC:
                    continue
                calls = dependency_calls(route.dependant)
                if security.require_login not in calls:
                    missing.append(f"{method} {route.path}")
        self.assertEqual(missing, [], "기본 거부 원칙: 라우터 단위 require_login이 빠진 라우트")

    def test_every_post_has_csrf_and_an_explicit_role_check(self):
        from app.forms import csrf_form
        problems = []
        for route in self.routes:
            if "POST" not in route.methods or ("POST", route.path) in PUBLIC:
                continue
            calls = dependency_calls(route.dependant)
            if csrf_form not in calls:
                problems.append(f"CSRF 없음: {route.path}")
            has_role = any(getattr(c, "__qualname__", "").startswith("require_role.<locals>") for c in calls)
            if not has_role and route.path not in ANY_ROLE_POST:
                problems.append(f"역할 검사 없음: {route.path}")
        self.assertEqual(problems, [])

    def test_state_changing_routes_are_never_get(self):
        """GET 라우트는 쓰기 SQL을 실행하지 않는다 (감사 로그가 필요한 내보내기도 POST)."""
        write = re.compile(r"INSERT INTO|UPDATE\s+\w+\s+SET|DELETE FROM|set_tags|add_note|mark_verified|transaction\(|"
                           r"audit\.record|add_flash")
        bad = []
        for route in self.routes:
            if "GET" in route.methods:
                source = inspect.getsource(route.endpoint)
                if write.search(source):
                    bad.append(route.path)
        self.assertEqual(bad, [])

    def test_endpoints_are_sync_functions(self):
        """엔드포인트는 동기 def (FastAPI 스레드풀에서 실행). 비동기 DB 드라이버를 쓰지 않는다."""
        asyncs = [r.path for r in self.routes if inspect.iscoroutinefunction(r.endpoint)]
        self.assertEqual(asyncs, [])

    def test_no_signup_or_api_style_routes(self):
        for path in ("/register", "/signup", "/api", "/api/servers", "/servers.json", "/graphql"):
            self.assertEqual(self.client.get(path).status_code, 404, path)

    def test_every_post_without_csrf_is_rejected_for_an_admin(self):
        """모든 POST에 CSRF가 적용되는지 실제 요청으로 확인 (관리자 세션으로 역할 검사는 통과시킨다)."""
        admin = self.user("root", "admin")
        self.conn.execute("UPDATE users SET must_change_password=0")
        self.login_as(admin)
        checked = 0
        for route in self.routes:
            if "POST" not in route.methods or ("POST", route.path) in PUBLIC:
                continue
            r = self.post(sample_path(route.path), "x=1")
            self.assertEqual(r.status_code, 403, f"POST {route.path} -> {r.status_code}")
            checked += 1
        self.assertGreater(checked, 50)

    def test_every_get_for_viewer_never_500(self):
        viewer = self.user("view", "viewer")
        self.conn.execute("UPDATE users SET must_change_password=0")
        self.login_as(viewer)
        for route in self.routes:
            if "GET" not in route.methods or route.path in ("/login", "/healthz"):
                continue
            r = self.client.get(sample_path(route.path))
            self.assertIn(r.status_code, (200, 403, 404, 303), f"GET {route.path} -> {r.status_code}")


class SecurityHeaderCoverageTests(ServerCase):
    HEADERS = ("content-security-policy", "x-content-type-options", "referrer-policy", "x-frame-options")

    def check(self, response, path):
        for header in self.HEADERS:
            self.assertIn(header, response.headers, f"{path}: {header}")
        self.assertEqual(response.headers["x-frame-options"], "DENY", path)
        self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"], path)

    def test_headers_on_representative_pages_errors_and_posts(self):
        sid = self.server(self.editor, hostname="h1")
        pages = ["/", "/servers", f"/servers/{sid}", f"/servers/{sid}/edit", "/servers/new", "/servers/import", "/services",
                 "/services/new", "/models", "/models/new", "/licenses", "/licenses/new", "/acls", "/tags", "/search?q=abc",
                 "/search", "/password", "/healthz", "/static/style.css", "/nope", "/servers/abc", "/users", "/audit", "/backup"]
        for path in pages:
            self.check(self.client.get(path), path)
        self.login(self.admin)
        for path in ("/users", "/audit", "/backup", "/users/new"):
            self.check(self.client.get(path), path)
        self.login(self.editor)
        self.check(self.post("/servers/new", "x=1"), "POST csrf-less")
        self.check(self.client.post("/servers/new", json={}), "POST json")
        self.check(self.post("/servers/new", "a=" + "x" * (config.MAX_BODY_BYTES + 1)), "POST oversized")
        self.check(self.post_form("/servers/new", **server_data(hostname="x-1")), "POST ok redirect")
        self.client.cookies.clear()
        self.check(self.client.get("/servers"), "unauthenticated redirect")
        self.check(self.client.get("/login"), "login")
        self.check(self.post("/login", "username=a&password=b"), "login failure")

    def test_authenticated_pages_are_never_cacheable(self):
        for path in ("/", "/servers", "/licenses", "/search?q=ab", "/tags", "/password", "/nope"):
            self.assertEqual(self.client.get(path).headers["cache-control"], "no-store", path)
        self.client.cookies.clear()
        self.assertEqual(self.client.get("/login").headers["cache-control"], "no-store")
        self.assertEqual(self.client.get("/servers").headers["cache-control"], "no-store")

    def test_error_pages_for_every_status_are_html_and_generic(self):
        sid = self.server(self.editor, hostname="h2")
        cases = [("get", "/nope", 404), ("get", "/servers/abc", 404), ("get", "/users", 403), ("post", "/servers/new", 403)]
        for method, path, status in cases:
            r = getattr(self.client, method)(path) if method == "get" else self.post(path, "x=1")
            self.assertEqual(r.status_code, status, path)
            self.assertIn("text/html", r.headers["content-type"])
            self.assertRegex(r.text, r'<section class="error-page">')
            for leak in ("Traceback", "File \"", "sqlite3", "pydantic", "fastapi", "detail"):
                self.assertNotIn(leak, r.text, (path, leak))
        r = self.client.put("/servers/new")
        self.assertEqual(r.status_code, 405)
        self.assertRegex(r.text, r'<section class="error-page">')
        r = self.client.get(f"/servers/{sid}?x=<script>alert(1)</script>")
        self.assertNotIn("<script>alert(1)</script>", r.text)


class LoggingTests(ServerCase):
    def test_secrets_never_reach_the_logs(self):
        records: list[str] = []

        class Capture(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())

        handler = Capture(level=logging.DEBUG)
        root = logging.getLogger()
        old_level = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        logging.getLogger("app").setLevel(logging.DEBUG)
        try:
            self.client.cookies.clear()
            secret_password = "Sup3r-Secret-Login-Password!"
            self.make_secret_user("loguser", secret_password)
            self.post("/login", urlencode({"username": "loguser", "password": "totally-wrong-password!"}))
            self.post("/login", urlencode({"username": "loguser", "password": secret_password}))
            session_cookie = self.client.cookies.get(config.SESSION_COOKIE, domain="testserver.local")
            csrf = security.lookup_session(self.conn, session_cookie).csrf_token
            lid = self.post_with(csrf, "/licenses/new", lic_data(license_key=KEY, account_info=ACCOUNT))
            self.post_with(csrf, f"/licenses/{lid}/reveal", {"field": "license_key"})
            self.client.get("/boom-not-found")
            self.post_with(csrf, "/servers/new", {"name": "x"})                       # 검증 실패
            security.encrypt_field(self.client.app.state.secret_key, 1, "x", "y")
        finally:
            root.removeHandler(handler)
            root.setLevel(old_level)
            logging.getLogger("app").setLevel(logging.CRITICAL)
        joined = "\n".join(records)
        secrets = [secret_password, "totally-wrong-password!", session_cookie, csrf, KEY, ACCOUNT, "Secret!",
                   self.client.app.state.secret_key.hex()]
        for secret in secrets:
            self.assertNotIn(secret, joined, secret[:8])
        self.assertNotIn("Traceback", joined)

    def make_secret_user(self, username, password):
        uid = self.user(username, "editor")
        self.conn.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?",
                          (security.hash_password(password), uid))

    def post_with(self, csrf, path, data):
        r = self.post(path, urlencode({"csrf_token": csrf, **data}))
        return int(r.headers["location"].rsplit("/", 1)[1]) if r.status_code == 303 else r.status_code


class SessionHygieneTests(ServerCase):
    def test_expired_sessions_are_purged_on_login_and_startup(self):
        old = datetime.now(timezone.utc) - timedelta(days=2)
        stale = security.create_session(self.conn, self.viewer, now=old)                      # 절대 만료 경과
        idle = security.create_session(self.conn, self.viewer, now=datetime.now(timezone.utc) - timedelta(hours=1))
        keep = security.create_session(self.conn, self.editor)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM sessions WHERE user_id=?", (self.viewer,)).fetchone()[0], 2)
        removed = security.purge_expired_sessions(self.conn)
        self.assertEqual(removed, 2)
        self.assertIsNotNone(security.lookup_session(self.conn, keep))
        self.assertIsNone(security.lookup_session(self.conn, stale))
        self.assertIsNone(security.lookup_session(self.conn, idle))

    def test_login_purges_stale_rows(self):
        self.conn.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?",
                          (security.hash_password("correct-horse-battery"), self.viewer))
        security.create_session(self.conn, self.editor, now=datetime.now(timezone.utc) - timedelta(days=3))
        self.client.cookies.clear()
        r = self.post("/login", urlencode({"username": "vw", "password": "correct-horse-battery"}))
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM sessions WHERE user_id=?", (self.editor,)).fetchone()[0], 1)


class StyleTests(ServerCase):
    def test_bar_width_classes_exist(self):
        css = (Path(__file__).resolve().parent.parent / "app" / "static" / "style.css").read_text(encoding="utf-8")
        for n in range(0, 101, 10):
            self.assertIn(f".w-{n} {{ width: {n}%; }}", css)

    def test_all_pages_use_the_single_stylesheet_only(self):
        html = self.client.get("/servers").text
        self.assertEqual(re.findall(r'<link [^>]*rel="stylesheet"[^>]*>', html), ['<link rel="stylesheet" href="/static/style.css">'])
        self.assertNotIn("<script", html)
