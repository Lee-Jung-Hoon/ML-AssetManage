"""테스트 공통: 임시 디렉터리 DB로 격리한다."""
import tempfile
import unittest
from pathlib import Path

from app import config, db

NOW = "2026-01-01T00:00:00Z"


class DBTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._orig_dir = config.DATA_DIR
        config.DATA_DIR = Path(self._tmp.name)
        self.addCleanup(setattr, config, "DATA_DIR", self._orig_dir)
        self.conn = db.connect()
        self.addCleanup(self.conn.close)
        db.run_migrations(self.conn)

    # --- 데이터 헬퍼 ---
    def user(self, username="u1", role="editor") -> int:
        return self.conn.execute(
            "INSERT INTO users (username, display_name, role, password_hash, created_at, updated_at) "
            "VALUES (?, ?, ?, 'x', ?, ?)", (username, username, role, NOW, NOW),
        ).lastrowid

    def server(self, uid, hostname="h1", **kw) -> int:
        row = dict(name="s", hostname=hostname, os_type="Linux", environment="prod", status="운영중",
                   server_type="VM", created_at=NOW, created_by=uid, updated_at=NOW, updated_by=uid)
        row.update(kw)
        return self._insert("servers", row)

    def service(self, uid, code="SVC-1", **kw) -> int:
        row = dict(name="svc", code=code, description="d", category="API", environment="prod",
                   status="운영중", tier=1, deploy_method="Docker",
                   created_at=NOW, created_by=uid, updated_at=NOW, updated_by=uid)
        row.update(kw)
        return self._insert("services", row)

    def license(self, uid, **kw) -> int:
        row = dict(name="lic", license_type="기타", expires_at="2027-01-01",
                   created_at=NOW, created_by=uid, updated_at=NOW, updated_by=uid)
        row.update(kw)
        return self._insert("licenses", row)

    def model(self, uid, **kw) -> int:
        row = dict(name="m", version="1", model_type="LLM", source="자체 학습", description="d",
                   status="실험", created_at=NOW, created_by=uid, updated_at=NOW, updated_by=uid)
        row.update(kw)
        return self._insert("models", row)

    def _insert(self, table, row) -> int:
        # 테스트 전용 헬퍼: 테이블명은 코드 상수, 값은 바인딩
        cols = ", ".join(row)
        marks = ", ".join("?" for _ in row)
        return self.conn.execute(f"INSERT INTO {table} ({cols}) VALUES ({marks})", tuple(row.values())).lastrowid

    def assertRejected(self, fn):
        with self.assertRaises(Exception) as cm:
            fn()
        self.assertIsInstance(cm.exception, __import__("sqlite3").IntegrityError)


# --- 웹 테스트 ---
import os  # noqa: E402
from unittest import mock  # noqa: E402

from fastapi import APIRouter, Depends, Request  # noqa: E402
from fastapi.responses import JSONResponse, PlainTextResponse  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from app import security  # noqa: E402
from app.forms import csrf_form  # noqa: E402
from app.main import create_app  # noqa: E402
from app.security import require_login, require_role  # noqa: E402
from app.templating import render  # noqa: E402

FAST_SCRYPT = dict(SCRYPT_N=2**4, SCRYPT_R=8, SCRYPT_P=1)


def make_test_app():
    """보호된 테스트 전용 라우트를 가진 앱 (운영 앱에는 포함되지 않는다)."""
    app = create_app()
    router = APIRouter(dependencies=[Depends(require_login)])

    @router.get("/t/ok")
    def ok(user=Depends(require_login)):
        return PlainTextResponse(user.username)

    @router.get("/t/editor")
    def editor(user=Depends(require_role("editor"))):
        return PlainTextResponse("editor-ok")

    @router.get("/t/admin")
    def admin(user=Depends(require_role("admin"))):
        return PlainTextResponse("admin-ok")

    @router.post("/t/post")
    def post(form=Depends(csrf_form), user=Depends(require_role("editor"))):
        return JSONResponse(form)

    @router.get("/t/page")
    def page(request: Request):
        return render(request, "error.html", {"status_code": 200, "message": "page"})

    @router.get("/t/int")
    def int_param(n: int):
        return PlainTextResponse(str(n))

    @router.get("/t/boom")
    def boom():
        raise RuntimeError("secret-internal-detail")

    app.include_router(router)
    return app


class WebTestCase(DBTestCase):
    def setUp(self):
        super().setUp()
        for name, value in FAST_SCRYPT.items():
            patcher = mock.patch.object(config, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        security._dummy_hash = None
        security.login_limiter = security.LoginLimiter()
        self.addCleanup(setattr, security, "_dummy_hash", None)
        self.client = TestClient(make_test_app(), base_url="https://testserver", follow_redirects=False,
                                 raise_server_exceptions=False)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    def login_as(self, uid) -> str:
        """세션을 직접 만들어 쿠키를 심는다. CSRF 토큰을 반환한다."""
        raw = security.create_session(self.conn, uid)
        self.client.cookies.set(config.SESSION_COOKIE, raw, domain="testserver.local")
        return self.conn.execute("SELECT csrf_token FROM sessions WHERE user_id=? ORDER BY created_at DESC",
                                 (uid,)).fetchone()[0]

    def post(self, path, data, **kw):
        return self.client.post(path, data=data, headers={"content-type": "application/x-www-form-urlencoded"}, **kw)
