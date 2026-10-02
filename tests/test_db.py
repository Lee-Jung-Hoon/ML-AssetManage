import sqlite3
import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from app import config, db
from app.main import create_app
from tests.base import NOW, DBTestCase


class MigrationTests(DBTestCase):
    def test_applied_once_and_idempotent(self):
        rows = self.conn.execute("SELECT version FROM schema_migrations").fetchall()
        self.assertEqual([r["version"] for r in rows], [1])
        self.assertEqual(db.run_migrations(self.conn), [])
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0], 1)

    def test_failed_migration_rolls_back(self):
        bad = db.MIGRATIONS_DIR / "999_bad.sql"
        bad.write_text("CREATE TABLE t_ok (id INTEGER); INSERT INTO nonexistent VALUES (1);")
        self.addCleanup(bad.unlink)
        with self.assertRaises(sqlite3.Error):
            db.run_migrations(self.conn)
        self.assertFalse(self.conn.in_transaction)
        self.assertIsNone(self.conn.execute(
            "SELECT name FROM sqlite_master WHERE name='t_ok'").fetchone())
        self.assertIsNone(self.conn.execute(
            "SELECT 1 FROM schema_migrations WHERE version=999").fetchone())

    def test_pragmas(self):
        self.assertEqual(self.conn.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        self.assertEqual(self.conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)


class ConstraintTests(DBTestCase):
    def setUp(self):
        super().setUp()
        self.uid = self.user()

    def test_enum_check(self):
        self.assertRejected(lambda: self.server(self.uid, os_type="Mac"))
        self.assertRejected(lambda: self.service(self.uid, tier=4))

    def test_hostname_unique_case_insensitive(self):
        self.server(self.uid, hostname="Web1")
        self.assertRejected(lambda: self.server(self.uid, hostname="web1"))

    def test_single_primary_ip(self):
        sid = self.server(self.uid)
        ins = "INSERT INTO server_ips (server_id, ip, kind, is_primary) VALUES (?, ?, '사설', ?)"
        self.conn.execute(ins, (sid, "10.0.0.1", 1))
        self.conn.execute(ins, (sid, "10.0.0.2", 0))
        self.assertRejected(lambda: self.conn.execute(ins, (sid, "10.0.0.3", 1)))
        s2 = self.server(self.uid, hostname="h2")
        self.conn.execute(ins, (s2, "10.0.1.1", 1))  # 다른 서버는 가능

    def test_disk_used_not_over_total(self):
        sid = self.server(self.uid)
        ins = ("INSERT INTO server_disks (server_id, mount_point, disk_type, total_gb, used_gb) "
               "VALUES (?, '/', 'SSD', ?, ?)")
        self.conn.execute(ins, (sid, 100, 100))
        self.assertRejected(lambda: self.conn.execute(ins, (sid, 100, 101)))
        self.assertRejected(lambda: self.conn.execute(ins, (sid, 0, 0)))

    def test_gpu_quantity_range(self):
        sid = self.server(self.uid)
        ins = "INSERT INTO server_gpus (server_id, gpu_model, quantity) VALUES (?, 'H100', ?)"
        self.conn.execute(ins, (sid, 16))
        self.assertRejected(lambda: self.conn.execute(ins, (sid, 17)))
        self.assertRejected(lambda: self.conn.execute(ins, (sid, 0)))

    def test_container_gpu_devices_only_when_specific(self):
        sid = self.server(self.uid)
        ins = ("INSERT INTO server_containers (server_id, name, image, gpu_usage, gpu_devices) "
               "VALUES (?, 'c', 'img:1', ?, ?)")
        self.conn.execute(ins, (sid, "특정 디바이스", "0,1"))
        self.assertRejected(lambda: self.conn.execute(ins, (sid, "전체", "0,1")))

    def test_acl_port_and_date(self):
        sid = self.server(self.uid)
        ins = ("INSERT INTO server_acls (server_id, direction, src_cidr, dst_cidr, port_start, port_end, "
               "protocol, purpose, requester, requested_at, status) "
               "VALUES (?, 'Inbound', '10.0.0.0/8', '10.1.0.1/32', ?, ?, 'TCP', 'p', 'r', ?, '요청')")
        self.conn.execute(ins, (sid, 80, 90, "2026-01-01"))
        self.assertRejected(lambda: self.conn.execute(ins, (sid, 90, 80, "2026-01-01")))
        self.assertRejected(lambda: self.conn.execute(ins, (sid, 0, 80, "2026-01-01")))
        self.assertRejected(lambda: self.conn.execute(ins, (sid, 80, 80, "2026-13-01")))

    def test_service_code_unique_and_serving_engine(self):
        self.service(self.uid, code="A-1")
        self.assertRejected(lambda: self.service(self.uid, code="A-1"))
        self.service(self.uid, code="A-2", category="AI 추론", serving_engine="vLLM")
        self.assertRejected(lambda: self.service(self.uid, code="A-3", category="API", serving_engine="vLLM"))

    def test_service_link_xor_and_self_reference(self):
        a = self.service(self.uid, code="A-1")
        b = self.service(self.uid, code="B-1")
        ins = "INSERT INTO service_links (service_id, target_service_id, external_name, protocol) VALUES (?, ?, ?, 'HTTPS')"
        self.conn.execute(ins, (a, b, None))
        self.conn.execute(ins, (a, None, "토스페이먼츠 API"))
        self.assertRejected(lambda: self.conn.execute(ins, (a, b, "둘다")))
        self.assertRejected(lambda: self.conn.execute(ins, (a, None, None)))
        self.assertRejected(lambda: self.conn.execute(ins, (a, a, None)))

    def test_license_expiry_rule(self):
        self.license(self.uid, no_expiry=1, expires_at=None)
        self.assertRejected(lambda: self.license(self.uid, no_expiry=0, expires_at=None))
        self.assertRejected(lambda: self.license(self.uid, no_expiry=1, expires_at="2027-01-01"))
        self.assertRejected(lambda: self.license(self.uid, expires_at="2027-02-30"))

    def test_license_type_specific_fields(self):
        self.license(self.uid, license_type="SSL/TLS 인증서", ssl_cn="a.example.com", ssl_wildcard=1)
        self.assertRejected(lambda: self.license(self.uid, license_type="도메인", ssl_cn="a.example.com"))
        self.license(self.uid, license_type="AI API", ai_provider="OpenAI", ai_sends_customer_data="예")
        self.assertRejected(lambda: self.license(self.uid, license_type="기타", ai_provider="OpenAI"))
        # AI API는 키/계정 저장 불가, 다른 종류는 가능
        self.assertRejected(lambda: self.license(self.uid, license_type="AI API", license_key_enc=b"x"))
        self.license(self.uid, license_type="소프트웨어 라이선스", license_key_enc=b"x")

    def test_model_unique_and_source_rules(self):
        self.model(self.uid)
        self.assertRejected(lambda: self.model(self.uid))  # 이름+버전 중복
        self.model(self.uid, version="2")
        self.assertRejected(lambda: self.model(self.uid, version="3", source="파인튜닝"))  # 베이스 모델 필수
        self.model(self.uid, version="3", source="파인튜닝", base_model="Llama 3.1 8B")
        self.assertRejected(lambda: self.model(self.uid, version="4", commercial_use="모름"))

    def test_model_license_link_rules(self):
        lic = self.license(self.uid, license_type="AI API", ai_provider="OpenAI")
        self.model(self.uid, version="a", source="상용 API", license_id=lic)
        self.assertRejected(lambda: self.model(self.uid, version="b", source="자체 학습", license_id=lic))
        row = self.conn.execute("SELECT commercial_use FROM models WHERE version='a'").fetchone()
        self.assertEqual(row["commercial_use"], "미확인")  # 기본값
        # 라이선스 삭제 시 모델 연결만 해제
        self.conn.execute("DELETE FROM licenses WHERE id=?", (lic,))
        row = self.conn.execute("SELECT license_id FROM models WHERE version='a'").fetchone()
        self.assertIsNone(row["license_id"])

    def test_cascade_on_server_delete(self):
        sid = self.server(self.uid)
        svc = self.service(self.uid)
        lic = self.license(self.uid)
        self.conn.execute("INSERT INTO server_ips (server_id, ip, kind) VALUES (?, '10.0.0.1', '사설')", (sid,))
        self.conn.execute("INSERT INTO service_servers (service_id, server_id, role) VALUES (?, ?, 'WEB')", (svc, sid))
        self.conn.execute("INSERT INTO license_servers (license_id, server_id) VALUES (?, ?)", (lic, sid))
        self.conn.execute("DELETE FROM servers WHERE id=?", (sid,))
        for t in ("server_ips", "service_servers", "license_servers"):
            self.assertEqual(self.conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0], 0, t)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM services").fetchone()[0], 1)

    def test_cascade_on_service_delete_links(self):
        a = self.service(self.uid, code="A-1")
        b = self.service(self.uid, code="B-1")
        self.conn.execute("INSERT INTO service_links (service_id, target_service_id, protocol) VALUES (?, ?, 'HTTP')", (a, b))
        self.conn.execute("DELETE FROM services WHERE id=?", (b,))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM service_links").fetchone()[0], 0)

    def test_users_cannot_be_hard_deleted_when_referenced(self):
        self.server(self.uid)
        self.assertRejected(lambda: self.conn.execute("DELETE FROM users WHERE id=?", (self.uid,)))

    def test_asset_type_and_note_checks(self):
        self.assertRejected(lambda: self.conn.execute(
            "INSERT INTO asset_notes (asset_type, asset_id, note_date, content, author_id, created_at) "
            "VALUES ('bogus', 1, '2026-01-01', 'x', ?, ?)", (self.uid, NOW)))
        self.assertRejected(lambda: self.conn.execute(
            "INSERT INTO asset_notes (asset_type, asset_id, note_date, content, author_id, created_at) "
            "VALUES ('server', 1, '2026-01-01', ?, ?, ?)", ("x" * 2001, self.uid, NOW)))

    def test_tag_cascade_on_tag_delete(self):
        tid = self.conn.execute("INSERT INTO tags (name) VALUES ('proj')").lastrowid
        self.conn.execute("INSERT INTO asset_tags (asset_type, asset_id, tag_id) VALUES ('server', 1, ?)", (tid,))
        self.conn.execute("DELETE FROM tags WHERE id=?", (tid,))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM asset_tags").fetchone()[0], 0)

    def test_audit_log_append_only(self):
        self.conn.execute("INSERT INTO audit_logs (at, action) VALUES (?, 'login')", (NOW,))
        with self.assertRaises(sqlite3.Error):
            self.conn.execute("UPDATE audit_logs SET action='x'")
        with self.assertRaises(sqlite3.Error):
            self.conn.execute("DELETE FROM audit_logs")

    def test_session_cascade_on_user_delete(self):
        uid = self.user("tmp")
        self.conn.execute(
            "INSERT INTO sessions (id_hash, user_id, csrf_token, created_at, last_seen_at, expires_at) "
            "VALUES ('h', ?, 't', ?, ?, ?)", (uid, NOW, NOW, NOW))
        self.conn.execute("DELETE FROM users WHERE id=?", (uid,))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)

    def test_transaction_helper_rolls_back(self):
        with self.assertRaises(RuntimeError):
            with db.transaction(self.conn):
                self.user("rollme")
                raise RuntimeError
        self.assertIsNone(self.conn.execute("SELECT 1 FROM users WHERE username='rollme'").fetchone())
        with db.transaction(self.conn):
            self.user("keepme")
        self.assertIsNotNone(self.conn.execute("SELECT 1 FROM users WHERE username='keepme'").fetchone())


class AppTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        orig = config.DATA_DIR
        config.DATA_DIR = Path(self._tmp.name)
        self.addCleanup(setattr, config, "DATA_DIR", orig)

    def test_healthz_and_docs_disabled(self):
        with TestClient(create_app(), base_url="https://testserver") as client:
            r = client.get("/healthz")
            self.assertEqual((r.status_code, r.text), (200, "ok"))
            for path in ("/docs", "/redoc", "/openapi.json"):
                self.assertEqual(client.get(path).status_code, 404, path)
        self.assertTrue((Path(self._tmp.name) / "app.db").exists())


if __name__ == "__main__":
    unittest.main()
