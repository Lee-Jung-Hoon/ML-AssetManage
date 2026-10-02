import os
import re
import sqlite3
import stat
from unittest import mock

from app import config
from app.routers import backup
from tests.test_servers import ServerCase


class BackupCase(ServerCase):
    def setUp(self):
        super().setUp()
        self.login(self.admin)

    def files(self):
        return sorted(p.name for p in (config.DATA_DIR / "backups").iterdir())

    def create(self, expect=303):
        r = self.post_form("/backup")
        self.assertEqual(r.status_code, expect, r.text[-400:])
        return r

    def stamps(self, n):
        return mock.patch.object(backup, "_stamp", side_effect=[f"20260101-0000{i:02d}" for i in range(n)])


class AccessTests(BackupCase):
    def test_non_admins_forbidden_and_unauthenticated_redirected(self):
        for uid in (self.editor, self.viewer):
            self.login(uid)
            self.assertEqual(self.client.get("/backup").status_code, 403)
            self.assertEqual(self.post_form("/backup").status_code, 403)
        self.assertEqual(self.files(), [])
        self.client.cookies.clear()
        self.assertEqual(self.client.get("/backup").status_code, 303)
        self.assertEqual(self.post("/backup", "x=1").status_code, 303)

    def test_csrf_required(self):
        self.assertEqual(self.post_form("/backup", csrf_token="bad").status_code, 403)
        self.assertEqual(self.post("/backup", "x=1").status_code, 403)
        self.assertEqual(self.files(), [])

    def test_blocked_when_admin_disabled(self):
        self.login(self.editor)
        with mock.patch.dict(os.environ, {"ADMIN_ENABLED": "false"}):
            self.assertEqual(self.client.get("/backup").status_code, 403)
            self.assertEqual(self.post_form("/backup").status_code, 403)
            self.login(self.admin)                                  # admin 세션은 즉시 무효화
            self.assertEqual(self.client.get("/backup").status_code, 303)
        self.assertEqual(self.files(), [])

    def test_menu_link_only_for_admin(self):
        self.assertIn('href="/backup"', self.client.get("/backup").text)
        self.login(self.editor)
        self.assertNotIn('href="/backup"', self.client.get("/").text)


class CreateTests(BackupCase):
    def test_creates_consistent_private_snapshot(self):
        sid = self.server(self.editor, hostname="backed-up", name="백업 대상")
        self.create()
        names = self.files()
        self.assertEqual(len(names), 1)
        self.assertRegex(names[0], r"^app-\d{8}-\d{6}\.db$")
        path = config.DATA_DIR / "backups" / names[0]
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)                      # 소유자만 읽기/쓰기
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        snapshot = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        self.addCleanup(snapshot.close)
        self.assertEqual(snapshot.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        self.assertEqual(snapshot.execute("SELECT name FROM servers WHERE id=?", (sid,)).fetchone()[0], "백업 대상")
        self.assertGreaterEqual(snapshot.execute("SELECT COUNT(*) FROM users").fetchone()[0], 4)
        # 백업 이후의 변경은 스냅샷에 없다
        self.server(self.editor, hostname="later")
        self.assertEqual(snapshot.execute("SELECT COUNT(*) FROM servers").fetchone()[0], 1)
        self.assertFalse(list(path.parent.glob("*-wal")) or list(path.parent.glob("*-shm")))   # 단일 파일

    def test_audit_flash_and_listing(self):
        self.create()
        audit = self.conn.execute("SELECT * FROM audit_logs WHERE action='backup_create'").fetchone()
        self.assertEqual((audit["target_type"], audit["user_id"]), ("backup", self.admin))
        self.assertIn(self.files()[0], audit["summary"])
        page = self.client.get("/backup").text
        self.assertIn("백업을 생성했습니다", page)
        self.assertIn(self.files()[0], page)
        self.assertIn("bytes", page)
        self.assertNotIn("백업을 생성했습니다", self.client.get("/backup").text)           # flash는 한 번만

    def test_page_warns_about_key_and_volume(self):
        page = self.client.get("/backup").text
        self.assertIn("secret.key", page)
        self.assertIn("볼륨 백업본 자체를 기밀로 취급", page)
        self.assertIn("호스트에서 Docker 볼륨으로 가져가세요", page)
        self.assertIn("생성된 백업이 없습니다", page)

    def test_directory_exists_at_startup(self):
        self.assertTrue((config.DATA_DIR / "backups").is_dir())

    def test_no_web_download_path_exists(self):
        self.create()
        name = self.files()[0]
        for path in (f"/backup/{name}", f"/backup/download/{name}", f"/backups/{name}", f"/static/{name}",
                     f"/static/../backups/{name}", f"/data/backups/{name}"):
            self.assertEqual(self.client.get(path).status_code, 404, path)
        self.assertNotIn(f'href="', self.client.get("/backup").text.split("<tbody>")[1])      # 목록에 링크가 없다


class RetentionTests(BackupCase):
    def test_keeps_latest_14_only(self):
        with self.stamps(16):
            for _ in range(16):
                self.create()
        names = self.files()
        self.assertEqual(len(names), 14)
        self.assertEqual(names[0], "app-20260101-000002.db")                              # 가장 오래된 2개 삭제
        self.assertEqual(names[-1], "app-20260101-000015.db")
        self.assertIn("pruned: 1", self.conn.execute("SELECT summary FROM audit_logs WHERE action='backup_create' ORDER BY id DESC").fetchone()[0])
        self.assertEqual(len(backup.list_backups()), 14)
        table = self.client.get("/backup").text.split("<tbody>")[1]
        self.assertEqual(len(re.findall(r"app-\d{8}-\d{6}\.db", table)), 14)

    def test_fewer_than_14_untouched_and_foreign_files_never_deleted(self):
        directory = config.DATA_DIR / "backups"
        for name in ("README.txt", "app-bad.db", "app-20200101-000000.db.bak", "other-20200101-000000.db", "app-2020-01.db"):
            (directory / name).write_text("keep me")
        with self.stamps(16):
            for _ in range(16):
                self.create()
        remaining = self.files()
        for name in ("README.txt", "app-bad.db", "app-20200101-000000.db.bak", "other-20200101-000000.db", "app-2020-01.db"):
            self.assertIn(name, remaining)
        self.assertEqual(len([n for n in remaining if backup.BACKUP_NAME.fullmatch(n)]), 14)

    def test_prune_function(self):
        directory = config.DATA_DIR / "backups"
        for i in range(5):
            (directory / f"app-20260101-00000{i}.db").write_text("x")
        self.assertEqual(backup.prune_backups(keep=3), ["app-20260101-000001.db", "app-20260101-000000.db"])
        self.assertEqual(backup.prune_backups(keep=3), [])


class FailureTests(BackupCase):
    def test_same_second_collision_is_reported_not_crashing(self):
        with mock.patch.object(backup, "_stamp", return_value="20260101-000000"):
            self.create()
            first = (config.DATA_DIR / "backups" / "app-20260101-000000.db").read_bytes()
            self.create()
        self.assertEqual(self.files(), ["app-20260101-000000.db"])
        self.assertEqual((config.DATA_DIR / "backups" / "app-20260101-000000.db").read_bytes(), first)
        self.assertIn("같은 시각의 백업이 이미 있습니다", self.client.get("/backup").text)

    def test_database_error_does_not_leak_internal_details(self):
        with mock.patch.object(backup, "create_backup", side_effect=sqlite3.OperationalError("disk I/O error /secret/internal/path.db")):
            self.create()
        page = self.client.get("/backup").text
        self.assertIn("백업을 만들지 못했습니다", page)
        self.assertNotIn("/secret/internal", page)
        self.assertNotIn("disk I/O", page)
        self.assertIsNone(self.conn.execute("SELECT 1 FROM audit_logs WHERE action='backup_create'").fetchone())

    def test_os_error_is_handled(self):
        with mock.patch.object(backup, "create_backup", side_effect=PermissionError("/data/backups")):
            self.create()
        self.assertIn("백업을 만들지 못했습니다", self.client.get("/backup").text)
