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
