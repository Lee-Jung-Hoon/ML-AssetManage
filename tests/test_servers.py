import re
from datetime import datetime, timedelta, timezone

from app import assets, config, security
from tests.base import NOW, WebTestCase


def server_data(**kw):
    data = dict(name="웹 서버 1", hostname="web-01", os_type="Linux", os_distro="Ubuntu", os_version="22.04",
                kernel_version="5.15", environment="prod", status="운영중", server_type="VM", location="IDC-A",
                cpu_model="Xeon", cpu_cores="16", memory_gb="64", description="웹\r\n프런트", notes="", owner_id="",
                tags="")
    data.update(kw)
    return data


class ServerCase(WebTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.make_user("boss", "admin")
        self.editor = self.make_user("ed", "editor")
        self.editor2 = self.make_user("ed2", "editor")
        self.viewer = self.make_user("vw", "viewer")
        self.login(self.editor)

    def make_user(self, username, role):
        uid = self.user(username, role)
        self.conn.execute("UPDATE users SET display_name=?, team=?, must_change_password=0 WHERE id=?",
                          ("이름-" + username, "팀-" + username, uid))
        return uid

    def create(self, **kw):
        r = self.post_form("/servers/new", **server_data(**kw))
        self.assertEqual(r.status_code, 303, r.text[-600:])
        return int(r.headers["location"].rsplit("/", 1)[1])

    def srv(self, sid):
        return self.conn.execute("SELECT * FROM servers WHERE id=?", (sid,)).fetchone()

    def audits(self, action):
        return self.conn.execute("SELECT * FROM audit_logs WHERE action=? ORDER BY id", (action,)).fetchall()

    def rows(self, html):
        return html.split("<tbody>")[1].count("<tr>")


class AccessTests(ServerCase):
    def test_viewer_can_read_but_not_write(self):
        sid = self.create()
        self.login(self.viewer)
        self.assertEqual(self.client.get("/servers").status_code, 200)
        self.assertEqual(self.client.get(f"/servers/{sid}").status_code, 200)
        for path in ("/servers/new", f"/servers/{sid}/edit", f"/servers/{sid}/delete"):
            self.assertEqual(self.client.get(path).status_code, 403, path)
        for path, data in (("/servers/new", server_data(hostname="x1")), (f"/servers/{sid}/edit", server_data()),
                           (f"/servers/{sid}/delete", {}), (f"/servers/{sid}/verify", {}),
                           (f"/servers/{sid}/notes", {"content": "hi"})):
            self.assertEqual(self.post_form(path, **data).status_code, 403, path)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM servers").fetchone()[0], 1)
        html = self.client.get(f"/servers/{sid}").text
        for hidden in ("/edit", "/delete", "/verify", "메모 추가"):
            self.assertNotIn(hidden, html)
        self.assertNotIn("서버 등록", self.client.get("/servers").text)

    def test_unauthenticated_redirects(self):
        self.client.cookies.clear()
        for path in ("/servers", "/servers/1", "/servers/new"):
            r = self.client.get(path)
            self.assertEqual((r.status_code, r.headers["location"].startswith("/login")), (303, True), path)
        self.assertEqual(self.post("/servers/new", "x=1").status_code, 303)

    def test_csrf_required_on_all_posts(self):
        sid = self.create()
        for path in (f"/servers/{sid}/edit", f"/servers/{sid}/delete", f"/servers/{sid}/verify",
                     f"/servers/{sid}/notes", "/servers/new"):
            self.assertEqual(self.post_form(path, csrf_token="bad", **server_data()).status_code, 403, path)
        self.assertIsNotNone(self.srv(sid))

    def test_missing_server_404(self):
        for path in ("/servers/999", "/servers/999/edit", "/servers/999/delete"):
            self.assertEqual(self.client.get(path).status_code, 404, path)
        self.assertEqual(self.post_form("/servers/999/verify").status_code, 404)


class CreateTests(ServerCase):
    def test_create_saves_everything(self):
        sid = self.create(tags=" Prod , Web,web ", owner_id=str(self.editor2))
        row = self.srv(sid)
        self.assertEqual((row["name"], row["hostname"], row["cpu_cores"], row["memory_gb"], row["owner_id"]),
                         ("웹 서버 1", "web-01", 16, 64, self.editor2))
        self.assertEqual(row["description"], "웹\n프런트")                      # CRLF → LF
        self.assertEqual((row["created_by"], row["updated_by"]), (self.editor, self.editor))
        self.assertIsNone(row["last_verified_at"])                              # 생성은 확인 처리가 아니다
        self.assertEqual(assets.get_tags(self.conn, "server", sid), ["prod", "web"])
        audit = self.audits("server_create")[0]
        self.assertEqual((audit["target_type"], audit["target_id"], audit["user_id"]), ("server", sid, self.editor))
        self.assertIn("hostname: ", audit["summary"])
        page = self.client.get(f"/servers/{sid}").text
        self.assertIn("서버를 등록했습니다.", page)
        self.assertIn("prod", page)

    def test_optional_fields_can_be_blank(self):
        sid = self.create(cpu_cores="", memory_gb="", os_distro="", location="")
        row = self.srv(sid)
        self.assertEqual((row["cpu_cores"], row["memory_gb"], row["owner_id"]), (None, None, None))

    def test_custom_distro_is_accepted(self):
        sid = self.create(os_distro="Alpine Linux")
        self.assertEqual(self.srv(sid)["os_distro"], "Alpine Linux")

    def test_validation_errors(self):
        self.create()
        bad_cases = {
            "name": ["", "x" * 101],
            "hostname": ["", "x" * 254, "bad host", "-bad", "bad-", "호스트", "a/b", "WEB-01"],   # 마지막은 중복(대소문자 무시)
            "os_type": ["Mac", ""],
            "environment": ["production", ""],
            "status": ["unknown"],
            "server_type": ["bare"],
            "cpu_cores": ["0", "-1", "abc", "4097", "1.5"],
            "memory_gb": ["0", "x", "100001"],
            "owner_id": ["abc", "9999"],
            "os_distro": ["x" * 101],
            "description": ["x" * 4001],
            "notes": ["x" * 4001],
        }
        for field, values in bad_cases.items():
            for value in values:
                r = self.post_form("/servers/new", **server_data(hostname="new-host", **{field: value}) if field != "hostname"
                                   else server_data(hostname=value))
                self.assertEqual(r.status_code, 422, (field, value))
                self.assertIn("has-error", r.text, (field, value))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM servers").fetchone()[0], 1)

    def test_duplicate_hostname_message(self):
        self.create()
        r = self.post_form("/servers/new", **server_data(hostname="WEB-01"))
        self.assertIn("이미 등록된 호스트명", r.text)

    def test_distro_must_match_os_type(self):
        r = self.post_form("/servers/new", **server_data(hostname="w1", os_type="Windows", os_distro="Ubuntu"))
        self.assertEqual(r.status_code, 422)
        self.assertIn("일치하지 않습니다", r.text)
        ok = self.post_form("/servers/new", **server_data(hostname="w2", os_type="Windows",
                                                          os_distro="Windows Server 2022"))
        self.assertEqual(ok.status_code, 303)

    def test_extra_and_system_fields_rejected(self):
        for extra in ("created_by", "last_verified_at", "id", "updated_at"):
            r = self.post_form("/servers/new", **server_data(hostname="zz", **{extra: "1"}))
            self.assertEqual(r.status_code, 422, extra)

    def test_owner_must_be_active_user(self):
        self.conn.execute("UPDATE users SET is_active=0 WHERE id=?", (self.editor2,))
        r = self.post_form("/servers/new", **server_data(owner_id=str(self.editor2)))
        self.assertEqual(r.status_code, 422)
        self.assertIn("활성 사용자만", r.text)
        form = self.client.get("/servers/new").text
        self.assertNotIn("이름-ed2", form)                                      # 선택지에는 활성 사용자만

    def test_form_keeps_input_on_error(self):
        r = self.post_form("/servers/new", **server_data(name="유지될 이름", cpu_cores="abc", tags="a b"))
        self.assertIn("유지될 이름", r.text)
        self.assertIn("숫자를 입력하세요", r.text)

    def test_html_is_escaped(self):
        sid = self.create(name="<script>alert(1)</script>", description="<img src=x onerror=alert(1)>")
        for path in (f"/servers/{sid}", "/servers"):
            html = self.client.get(path).text
            self.assertNotIn("<script>alert(1)", html)
            self.assertNotIn("<img src=x", html)
        self.assertIn("&lt;script&gt;", self.client.get(f"/servers/{sid}").text)


class TagTests(ServerCase):
    def test_parse_tags(self):
        self.assertEqual(assets.parse_tags(" Foo ,BAR,foo, 한글-태그 ,a_b,,"), ["foo", "bar", "한글-태그", "a_b"])
        self.assertEqual(assets.parse_tags(""), [])
        self.assertEqual(assets.parse_tags("t" * 30), ["t" * 30])
        for bad in ("t" * 31, "has space", "a;b", "a.b", "<b>", "emoji😀", "a/b"):
            with self.assertRaises(ValueError, msg=bad):
                assets.parse_tags(bad)
        assets.parse_tags(",".join(f"t{i}" for i in range(10)))
        with self.assertRaises(ValueError):
            assets.parse_tags(",".join(f"t{i}" for i in range(11)))
        self.assertEqual(len(assets.parse_tags(",".join(["x"] * 50))), 1)         # 중복은 한 개로 센다

    def test_tag_errors_via_form(self):
        for bad in ("t" * 31, "a b", ",".join(f"t{i}" for i in range(11))):
            r = self.post_form("/servers/new", **server_data(tags=bad))
            self.assertEqual(r.status_code, 422, bad)
            self.assertIn("태그", r.text)

    def test_tags_replaced_and_created_on_demand(self):
        sid = self.create(tags="a,b")
        self.post_form(f"/servers/{sid}/edit", **server_data(tags="b,c"))
        self.assertEqual(assets.get_tags(self.conn, "server", sid), ["b", "c"])
        self.assertEqual({r[0] for r in self.conn.execute("SELECT name FROM tags")}, {"a", "b", "c"})
        self.assertIn("tags: a, b → b, c", self.audits("server_update")[0]["summary"])


class EditTests(ServerCase):
    def test_edit_updates_and_audits(self):
        sid = self.create()
        r = self.post_form(f"/servers/{sid}/edit", **server_data(name="새 이름", status="점검", memory_gb="128"))
        self.assertEqual((r.status_code, r.headers["location"]), (303, f"/servers/{sid}"))
        row = self.srv(sid)
        self.assertEqual((row["name"], row["status"], row["memory_gb"]), ("새 이름", "점검", 128))
        summary = self.audits("server_update")[0]["summary"]
        self.assertIn("name: 웹 서버 1 → 새 이름", summary)
        self.assertIn("status: 운영중 → 점검", summary)
        self.assertNotIn("hostname", summary)

    def test_edit_does_not_count_as_verification(self):
        sid = self.create()
        self.conn.execute("UPDATE servers SET last_verified_at=?, last_verified_by=? WHERE id=?",
                          ("2020-01-01T00:00:00Z", self.admin, sid))
        self.post_form(f"/servers/{sid}/edit", **server_data(name="바뀜"))
        row = self.srv(sid)
        self.assertEqual((row["last_verified_at"], row["last_verified_by"]), ("2020-01-01T00:00:00Z", self.admin))
        self.assertEqual(row["updated_by"], self.editor)

    def test_unchanged_edit_writes_nothing(self):
        sid = self.create()
        before = self.srv(sid)["updated_at"]
        self.conn.execute("UPDATE servers SET updated_at='2020-01-01T00:00:00Z' WHERE id=?", (sid,))
        r = self.post_form(f"/servers/{sid}/edit", **server_data())
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.srv(sid)["updated_at"], "2020-01-01T00:00:00Z")
        self.assertEqual(self.audits("server_update"), [])

    def test_form_prefilled(self):
        sid = self.create(tags="x,y", notes="메모\n둘째줄")
        html = self.client.get(f"/servers/{sid}/edit").text
        self.assertIn('value="web-01"', html)
        self.assertIn("x, y", html)
        self.assertIn("메모\n둘째줄", html)

    def test_hostname_uniqueness_on_edit(self):
        a = self.create()
        b = self.create(hostname="web-02")
        r = self.post_form(f"/servers/{b}/edit", **server_data(hostname="web-01"))
        self.assertEqual(r.status_code, 422)
        self.assertIn("이미 등록된 호스트명", r.text)
        ok = self.post_form(f"/servers/{a}/edit", **server_data(hostname="WEB-01", name="대소문자만 변경"))
        self.assertEqual(ok.status_code, 303)

    def test_keep_inactive_owner_but_cannot_assign_new_inactive(self):
        sid = self.create(owner_id=str(self.editor2))
        self.conn.execute("UPDATE users SET is_active=0 WHERE id IN (?, ?)", (self.editor2, self.viewer))
        form = self.client.get(f"/servers/{sid}/edit").text
        self.assertIn("[비활성]", form)                                         # 기존 담당자는 표시 유지
        ok = self.post_form(f"/servers/{sid}/edit", **server_data(owner_id=str(self.editor2), name="그대로"))
        self.assertEqual(ok.status_code, 303)
        bad = self.post_form(f"/servers/{sid}/edit", **server_data(owner_id=str(self.viewer)))
        self.assertEqual(bad.status_code, 422)


class ListTests(ServerCase):
    def add(self, n, **kw):
        sids = []
        for i in range(n):
            sids.append(self.server(self.editor, hostname=kw.pop("hostname", None) or f"host-{i:03d}",
                                    name=kw.get("name", f"srv-{i:03d}"),
                                    **{k: v for k, v in kw.items() if k != "name"}))
        return sids

    def names(self, html):
        return re.findall(r'<a href="/servers/\d+">([^<]+)</a>', html)

    def test_pagination_20_per_page(self):
        for i in range(45):
            self.server(self.editor, hostname=f"h{i:03d}", name=f"s{i:03d}")
        p1, p2, p3 = (self.client.get(f"/servers?page={n}").text for n in (1, 2, 3))
        self.assertEqual((self.rows(p1), self.rows(p2), self.rows(p3)), (20, 20, 5))
        self.assertIn("총 45건", p1)
        self.assertIn("3 / 3", p3)
        self.assertEqual(self.names(p1)[0], "s000")
        self.assertEqual(self.rows(self.client.get("/servers?page=99").text), 5)    # 범위 초과 보정

    def test_search_name_hostname_ip_with_escaped_wildcards(self):
        a = self.server(self.editor, hostname="alpha-1", name="결제 서버")
        self.server(self.editor, hostname="beta_2", name="100%서버")
        self.server(self.editor, hostname="gamma", name="그냥")
        self.conn.execute("INSERT INTO server_ips (server_id, ip, kind) VALUES (?, '10.20.30.40', '사설')", (a,))
        def found(q):
            from urllib.parse import urlencode
            return self.names(self.client.get("/servers?" + urlencode({"q": q})).text)
        self.assertEqual(found("결제"), ["결제 서버"])
        self.assertEqual(found("ALPHA"), ["결제 서버"])
        self.assertEqual(found("10.20.30"), ["결제 서버"])
        self.assertEqual(found("%"), ["100%서버"])                              # 와일드카드는 리터럴
        self.assertEqual(found("_"), ["100%서버"])                              # beta_2의 밑줄만 일치
        self.assertEqual(found("a%a"), [])
        self.assertEqual(found("nothing"), [])
        self.assertEqual(found("x' OR '1'='1"), [])                            # SQL 주입 무해

    def test_filters(self):
        w = self.server(self.editor, hostname="w1", name="win", os_type="Windows", os_distro="Windows Server 2022",
                        environment="dev", status="점검")
        l = self.server(self.editor, hostname="l1", name="lin", os_distro="Ubuntu", owner_id=self.editor2)
        g = self.server(self.editor, hostname="g1", name="gpu", os_distro="Rocky")
        self.conn.execute("INSERT INTO server_gpus (server_id, gpu_model, quantity) VALUES (?, 'A100 80GB', 8)", (g,))
        assets_tag = lambda sid, t: (self.conn.execute("INSERT OR IGNORE INTO tags (name) VALUES (?)", (t,)),
                                     self.conn.execute("INSERT INTO asset_tags SELECT 'server', ?, id FROM tags WHERE name=?", (sid, t)))
        assets_tag(l, "proj-x")
        self.conn.execute("UPDATE servers SET last_verified_at=? WHERE id IN (?, ?)", (NOW.replace("2026", "2099"), w, l))
        def names(qs):
            return sorted(self.names(self.client.get("/servers?" + qs).text))
        self.assertEqual(names("os_type=Windows"), ["win"])
        self.assertEqual(names("os_distro=Ubuntu"), ["lin"])
        self.assertEqual(names("environment=dev"), ["win"])
        self.assertEqual(names("status=점검"), ["win"])
        self.assertEqual(names("gpu_only=on"), ["gpu"])
        self.assertEqual(names("tag=proj-x"), ["lin"])
        self.assertEqual(names(f"owner_id={self.editor2}"), ["lin"])
        self.assertEqual(names("stale=on"), ["gpu"])                            # 나머지는 확인됨
        self.assertEqual(names("os_type=Linux&environment=prod"), ["gpu", "lin"])
        self.login(self.editor2)
        self.assertEqual(names("mine=on"), ["lin"])

    def test_sorting_whitelist(self):
        a = self.server(self.editor, hostname="a", name="Bravo", updated_at="2026-01-01T00:00:00Z")
        b = self.server(self.editor, hostname="b", name="alpha", updated_at="2026-03-01T00:00:00Z")
        c = self.server(self.editor, hostname="c", name="Charlie", updated_at="2026-02-01T00:00:00Z")
        self.conn.execute("UPDATE servers SET last_verified_at='2026-01-05T00:00:00Z' WHERE id=?", (a,))
        self.conn.execute("UPDATE servers SET last_verified_at='2026-01-01T00:00:00Z' WHERE id=?", (b,))
        n = lambda sort: self.names(self.client.get(f"/servers?sort={sort}").text)
        self.assertEqual(n("name"), ["alpha", "Bravo", "Charlie"])
        self.assertEqual(n("updated"), ["alpha", "Charlie", "Bravo"])
        self.assertEqual(n("verified"), ["Charlie", "alpha", "Bravo"])         # 미확인 → 오래된 순
        for evil in ("name;DROP TABLE servers", "hostname", "1", ""):
            r = self.client.get("/servers?sort=" + evil)
            self.assertEqual(r.status_code, 200)
            if evil != "":
                self.assertIn("조회 조건이 올바르지 않습니다", r.text, evil)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM servers").fetchone()[0], 3)

    def test_invalid_filters_show_no_data(self):
        self.server(self.editor)
        for qs in ("os_type=Mac", "environment=x", "page=0", "page=abc", "evil=1", "owner_id=abc", "q=" + "x" * 101):
            r = self.client.get("/servers?" + qs)
            self.assertEqual(r.status_code, 200, qs)
            self.assertIn("조회 조건이 올바르지 않습니다", r.text, qs)
            self.assertEqual(self.rows(r.text), 1, qs)                           # '없음' 한 줄

    def test_columns_primary_ip_disk_gpu(self):
        sid = self.server(self.editor, hostname="c1", name="cols")
        ins = "INSERT INTO server_ips (server_id, ip, kind, is_primary) VALUES (?, ?, '사설', ?)"
        self.conn.execute(ins, (sid, "10.0.0.9", 0))
        self.conn.execute(ins, (sid, "10.0.0.1", 1))
        for mount, used in (("/", 50), ("/data", 95)):
            self.conn.execute("INSERT INTO server_disks (server_id, mount_point, disk_type, total_gb, used_gb) "
                              "VALUES (?, ?, 'SSD', 100, ?)", (sid, mount, used))
        self.conn.execute("INSERT INTO server_gpus (server_id, gpu_model, quantity) VALUES (?, 'A100 80GB', 8)", (sid,))
        html = self.client.get("/servers").text
        self.assertIn("10.0.0.1", html)
        self.assertIn("A100 80GB ×8", html)
        self.assertIn("95%", html)
        self.assertIn("badge-red", html)
        self.assertNotIn("style=", html)                                        # 막대는 클래스로만 표현

    def test_usage_levels(self):
        from app.templating import usage_class, usage_level
        self.assertEqual([usage_level(p) for p in (None, 0, 79.9, 80, 89.9, 90, 100)],
                         ["gray", "green", "green", "orange", "orange", "red", "red"])
        self.assertEqual([usage_class(p) for p in (None, 0, 4, 5, 94, 95, 100, 150)],
                         ["w-0", "w-0", "w-0", "w-10", "w-90", "w-100", "w-100", "w-100"])

    def test_tags_and_owner_displayed_inactive_warning(self):
        sid = self.server(self.editor, owner_id=self.editor2)
        self.conn.execute("UPDATE users SET is_active=0 WHERE id=?", (self.editor2,))
        html = self.client.get("/servers").text
        self.assertIn("이름-ed2", html)
        self.assertIn("비활성 담당자", html)
        self.assertIn("비활성 담당자", self.client.get(f"/servers/{sid}").text)


class FreshnessTests(ServerCase):
    def test_new_server_needs_verification_then_button_clears_it(self):
        sid = self.create()
        self.assertIn("확인 필요", self.client.get("/servers").text)
        self.assertIn("확인 필요", self.client.get(f"/servers/{sid}").text)
        r = self.post_form(f"/servers/{sid}/verify")
        self.assertEqual((r.status_code, r.headers["location"]), (303, f"/servers/{sid}"))
        row = self.srv(sid)
        self.assertIsNotNone(row["last_verified_at"])
        self.assertEqual(row["last_verified_by"], self.editor)
        for path in ("/servers", f"/servers/{sid}"):
            html = self.client.get(path).text
            self.assertNotIn("확인 필요", html.split("<tbody>")[-1] if path == "/servers" else html.split("기본 정보")[-1])
            self.assertIn("확인됨", html)
        self.assertEqual(len(self.audits("server_verify")), 1)
        self.assertEqual(self.client.get("/servers?stale=on").text.count("확인됨"), 0)

    def test_verify_is_post_only(self):
        sid = self.create()
        self.assertEqual(self.client.get(f"/servers/{sid}/verify").status_code, 405)

    def test_boundary_90_days(self):
        now = datetime(2026, 6, 1, tzinfo=timezone.utc)
        iso = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.assertTrue(assets.verify_state(None, now)["stale"])
        self.assertFalse(assets.verify_state(iso(now - timedelta(days=89)), now)["stale"])
        self.assertFalse(assets.verify_state(iso(now - timedelta(days=90)), now)["stale"])        # 정확히 90일
        self.assertTrue(assets.verify_state(iso(now - timedelta(days=90, seconds=1)), now)["stale"])
        self.assertTrue(assets.verify_state(iso(now - timedelta(days=200)), now)["stale"])

    def test_old_verification_flagged_and_filterable(self):
        old = self.server(self.editor, hostname="old", name="old")
        fresh = self.server(self.editor, hostname="fresh", name="fresh")
        self.conn.execute("UPDATE servers SET last_verified_at='2000-01-01T00:00:00Z' WHERE id=?", (old,))
        self.conn.execute("UPDATE servers SET last_verified_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=?", (fresh,))
        names = re.findall(r'<a href="/servers/\d+">([^<]+)</a>', self.client.get("/servers?stale=on").text)
        self.assertEqual(names, ["old"])

    def test_edit_does_not_refresh(self):
        sid = self.create()
        self.post_form(f"/servers/{sid}/edit", **server_data(name="수정됨"))
        self.assertIsNone(self.srv(sid)["last_verified_at"])
        self.assertIn("확인 필요", self.client.get(f"/servers/{sid}").text)


class NoteTests(ServerCase):
    def setUp(self):
        super().setUp()
        self.sid = self.create()

    def notes(self):
        return self.conn.execute("SELECT * FROM asset_notes ORDER BY id").fetchall()

    def test_add_note_defaults_to_today(self):
        r = self.post_form(f"/servers/{self.sid}/notes", content="디스크 500GB 증설", note_date="")
        self.assertEqual((r.status_code, r.headers["location"]), (303, f"/servers/{self.sid}#notes"))
        note = self.notes()[0]
        self.assertEqual((note["asset_type"], note["asset_id"], note["author_id"], note["note_date"]),
                         ("server", self.sid, self.editor, assets.today_kst()))
        self.assertIn("디스크 500GB 증설", self.client.get(f"/servers/{self.sid}").text)
        self.assertEqual(len(self.audits("server_note_add")), 1)

    def test_explicit_date_and_ordering_newest_first(self):
        self.post_form(f"/servers/{self.sid}/notes", content="첫째", note_date="2026-01-01")
        self.post_form(f"/servers/{self.sid}/notes", content="셋째", note_date="2026-03-01")
        self.post_form(f"/servers/{self.sid}/notes", content="둘째", note_date="2026-02-01")
        html = self.client.get(f"/servers/{self.sid}").text
        self.assertTrue(html.index("셋째") < html.index("둘째") < html.index("첫째"))

    def test_validation(self):
        for bad in (dict(content=""), dict(content="x" * 2001), dict(content="ok", note_date="2026-13-01"),
                    dict(content="ok", note_date="yesterday"), dict(content="ok", author_id="1")):
            r = self.post_form(f"/servers/{self.sid}/notes", **bad)
            self.assertEqual(r.status_code, 303)
            self.assertEqual(self.notes(), [], bad)
        self.assertIn("메모를 저장하지 못했습니다", self.client.get(f"/servers/{self.sid}").text)
        self.post_form(f"/servers/{self.sid}/notes", content="x" * 2000)
        self.assertEqual(len(self.notes()), 1)

    def test_multiline_and_escaping(self):
        self.post_form(f"/servers/{self.sid}/notes", content="줄1\r\n<b>줄2</b>")
        self.assertEqual(self.notes()[0]["content"], "줄1\n<b>줄2</b>")
        html = self.client.get(f"/servers/{self.sid}").text
        self.assertIn("&lt;b&gt;줄2&lt;/b&gt;", html)
        self.assertNotIn("<br", html)

    def test_delete_only_by_author_or_admin(self):
        self.post_form(f"/servers/{self.sid}/notes", content="내 메모")
        nid = self.notes()[0]["id"]
        self.login(self.editor2)
        self.assertNotIn(f"/notes/{nid}/delete", self.client.get(f"/servers/{self.sid}").text)   # 버튼도 숨김
        self.assertEqual(self.post_form(f"/servers/{self.sid}/notes/{nid}/delete").status_code, 403)
        self.login(self.viewer)
        self.assertEqual(self.post_form(f"/servers/{self.sid}/notes/{nid}/delete").status_code, 403)
        self.assertEqual(len(self.notes()), 1)
        self.login(self.editor)
        self.assertIn(f"/notes/{nid}/delete", self.client.get(f"/servers/{self.sid}").text)
        r = self.post_form(f"/servers/{self.sid}/notes/{nid}/delete")
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.notes(), [])
        self.assertEqual(len(self.audits("server_note_delete")), 1)

    def test_admin_can_delete_others_note(self):
        self.post_form(f"/servers/{self.sid}/notes", content="편집자 메모")
        nid = self.notes()[0]["id"]
        self.login(self.admin)
        self.assertEqual(self.post_form(f"/servers/{self.sid}/notes/{nid}/delete").status_code, 303)
        self.assertEqual(self.notes(), [])

    def test_note_of_other_asset_is_404_and_no_edit_feature(self):
        other = self.create(hostname="other-1")
        self.post_form(f"/servers/{self.sid}/notes", content="메모")
        nid = self.notes()[0]["id"]
        self.assertEqual(self.post_form(f"/servers/{other}/notes/{nid}/delete").status_code, 404)
        self.assertEqual(self.post_form(f"/servers/{self.sid}/notes/{nid}/edit", content="수정").status_code, 404)
        self.assertEqual(self.post_form(f"/servers/{self.sid}/notes/999/delete").status_code, 404)
        self.assertEqual(self.post_form("/servers/999/notes", content="x").status_code, 404)
        self.assertEqual(self.notes()[0]["content"], "메모")


class DeleteTests(ServerCase):
    def test_confirm_page_does_not_delete_and_warns_about_services(self):
        sid = self.create()
        svc = self.service(self.editor, code="PAY-API", name="결제 API", tier=1)
        self.conn.execute("INSERT INTO service_servers (service_id, server_id, role) VALUES (?, ?, 'API')", (svc, sid))
        r = self.client.get(f"/servers/{sid}/delete")
        self.assertEqual(r.status_code, 200)
        self.assertIn("구동 중인 서비스가 1개", r.text)
        self.assertIn("결제 API", r.text)
        self.assertIn("PAY-API", r.text)
        self.assertIsNotNone(self.srv(sid))
        clean = self.create(hostname="clean-1")
        self.assertNotIn("구동 중인 서비스", self.client.get(f"/servers/{clean}/delete").text)

    def test_delete_removes_children_tags_and_notes_without_orphans(self):
        sid = self.create(tags="keep,mine")
        other = self.create(hostname="other-1", tags="keep")
        self.post_form(f"/servers/{sid}/notes", content="삭제될 메모")
        self.post_form(f"/servers/{other}/notes", content="남을 메모")
        self.conn.execute("INSERT INTO server_ips (server_id, ip, kind) VALUES (?, '10.0.0.1', '사설')", (sid,))
        self.conn.execute("INSERT INTO server_gpus (server_id, gpu_model, quantity) VALUES (?, 'H100', 8)", (sid,))
        lic = self.license(self.editor)
        self.conn.execute("INSERT INTO license_servers (license_id, server_id) VALUES (?, ?)", (lic, sid))
        r = self.post_form(f"/servers/{sid}/delete")
        self.assertEqual((r.status_code, r.headers["location"]), (303, "/servers"))
        self.assertIsNone(self.srv(sid))
        q = lambda sql, *a: self.conn.execute(sql, a).fetchone()[0]
        self.assertEqual(q("SELECT COUNT(*) FROM asset_tags WHERE asset_type='server' AND asset_id=?", sid), 0)
        self.assertEqual(q("SELECT COUNT(*) FROM asset_notes WHERE asset_type='server' AND asset_id=?", sid), 0)
        for table in ("server_ips", "server_gpus", "license_servers"):
            self.assertEqual(q(f"SELECT COUNT(*) FROM {table} WHERE server_id=?", sid), 0, table)
        self.assertEqual(q("SELECT COUNT(*) FROM asset_tags WHERE asset_type='server' AND asset_id=?", other), 1)
        self.assertEqual(q("SELECT COUNT(*) FROM asset_notes WHERE asset_id=?", other), 1)
        self.assertEqual(q("SELECT COUNT(*) FROM licenses"), 1)                  # 연결된 라이선스는 유지
        audit = self.audits("server_delete")[0]
        self.assertEqual(audit["target_id"], sid)
        self.assertIn("web-01", audit["summary"])
        self.assertIn("서버를 삭제했습니다.", self.client.get("/servers").text)

    def test_get_does_not_delete_and_viewer_blocked(self):
        sid = self.create()
        self.assertEqual(self.client.get(f"/servers/{sid}/delete").status_code, 200)
        self.assertIsNotNone(self.srv(sid))
        self.login(self.viewer)
        self.assertEqual(self.post_form(f"/servers/{sid}/delete").status_code, 403)
        self.assertIsNotNone(self.srv(sid))


class HistoryTests(ServerCase):
    def test_history_only_for_this_asset_and_visible_to_viewers(self):
        a = self.create()
        b = self.create(hostname="b-1", name="다른 서버")
        self.post_form(f"/servers/{a}/edit", **server_data(name="A 변경"))
        self.post_form(f"/servers/{b}/edit", **server_data(hostname="b-1", name="B 변경"))
        self.login(self.viewer)
        html = self.client.get(f"/servers/{a}").text.split("변경 이력")[1]
        self.assertIn("A 변경", html)
        self.assertNotIn("B 변경", html)
        self.assertIn("server_create", html)
