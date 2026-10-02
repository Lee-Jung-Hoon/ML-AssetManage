import re

from app import assets
from tests.test_servers import ServerCase


def svc_data(**kw):
    data = dict(name="결제 API", code="PAY-API", description="결제를 처리한다", category="API", environment="prod",
                status="운영중", tier="1", team="결제팀", urls="https://pay.example.com\nlegacy-pay.example.com:8443",
                repo_url="https://git.example.com/pay", doc_url="https://wiki.example.com/pay", tech_stack="FastAPI",
                deploy_method="Docker", serving_engine="", notes="", primary_owner_id="", secondary_owner_id="", tags="")
    data.update(kw)
    return data


class ServiceCase(ServerCase):
    def create(self, **kw):
        r = self.post_form("/services/new", **svc_data(**kw))
        self.assertEqual(r.status_code, 303, r.text[-700:])
        return int(r.headers["location"].rsplit("/", 1)[1])

    def svc(self, sid):
        return self.conn.execute("SELECT * FROM services WHERE id=?", (sid,)).fetchone()

    def one(self, sql, *p):
        return self.conn.execute(sql, p).fetchone()

    def names(self, html):
        return re.findall(r'<a href="/services/\d+">([^<]+)</a>', html)


class AccessTests(ServiceCase):
    def test_viewer_read_only(self):
        sid = self.create()
        self.login(self.viewer)
        self.assertEqual(self.client.get("/services").status_code, 200)
        self.assertEqual(self.client.get(f"/services/{sid}").status_code, 200)
        for path in ("/services/new", f"/services/{sid}/edit", f"/services/{sid}/delete",
                     f"/services/{sid}/servers/new", f"/services/{sid}/links/new"):
            self.assertEqual(self.client.get(path).status_code, 403, path)
        for path in ("/services/new", f"/services/{sid}/edit", f"/services/{sid}/delete", f"/services/{sid}/verify",
                     f"/services/{sid}/notes", f"/services/{sid}/servers/new", f"/services/{sid}/links/new"):
            self.assertEqual(self.post_form(path, **svc_data(code="NEW-1")).status_code, 403, path)
        html = self.client.get(f"/services/{sid}").text
        for hidden in ("/edit", "/delete", "/verify", "서버 연결", "연결 추가"):
            self.assertNotIn(hidden, html)
        self.assertEqual(self.one("SELECT COUNT(*) FROM services")[0], 1)

    def test_unauth_and_csrf(self):
        sid = self.create()
        for path in (f"/services/{sid}/edit", f"/services/{sid}/delete", "/services/new", f"/services/{sid}/servers/new",
                     f"/services/{sid}/links/new", f"/services/{sid}/verify"):
            self.assertEqual(self.post_form(path, csrf_token="bad", **svc_data()).status_code, 403, path)
        self.client.cookies.clear()
        for path in ("/services", f"/services/{sid}", "/services/new"):
            self.assertEqual(self.client.get(path).status_code, 303, path)

    def test_404s(self):
        for path in ("/services/999", "/services/999/edit", "/services/999/delete", "/services/999/servers/new",
                     "/services/999/links/new"):
            self.assertEqual(self.client.get(path).status_code, 404, path)


class CreateTests(ServiceCase):
    def test_create_saves_everything(self):
        sid = self.create(tags="Pay, 결제", primary_owner_id=str(self.editor), secondary_owner_id=str(self.editor2))
        row = self.svc(sid)
        self.assertEqual((row["code"], row["tier"], row["primary_owner_id"], row["secondary_owner_id"]),
                         ("PAY-API", 1, self.editor, self.editor2))
        self.assertEqual(row["urls"], "https://pay.example.com\nlegacy-pay.example.com:8443")
        self.assertIsNone(row["serving_engine"])
        self.assertIsNone(row["last_verified_at"])
        self.assertEqual(assets.get_tags(self.conn, "service", sid), ["pay", "결제"])
        audit = self.one("SELECT * FROM audit_logs WHERE action='service_create'")
        self.assertEqual((audit["target_type"], audit["target_id"]), ("service", sid))
        self.assertIn("서비스를 등록했습니다.", self.client.get(f"/services/{sid}").text)

    def test_code_format(self):
        for ok in ("A", "PAY-API", "AB-12-CD", "API2", "9"):
            self.create(code=ok)
        for bad in ("pay-api", "Pay-Api", "PAY_API", "PAY API", "-PAY", "PAY-", "PAY--API", "결제", "PAY.API", "",
                    "A" * 51, "PAY/API", "<B>"):
            r = self.post_form("/services/new", **svc_data(code=bad))
            self.assertEqual(r.status_code, 422, repr(bad))
            self.assertIn("has-error", r.text)

    def test_code_unique(self):
        self.create()
        r = self.post_form("/services/new", **svc_data(name="다른 서비스"))
        self.assertEqual(r.status_code, 422)
        self.assertIn("이미 사용 중인 서비스 코드", r.text)

    def test_enum_and_range_validation(self):
        bads = dict(tier=["0", "4", "-1", "abc", "", "1.5"], category=["게임", ""], environment=["production"],
                    status=["중단"], deploy_method=["Ansible", ""], name=["", "x" * 101], description=["", "x" * 4001],
                    team=["x" * 101], tech_stack=["x" * 501], notes=["x" * 4001])
        for field, values in bads.items():
            for value in values:
                r = self.post_form("/services/new", **svc_data(code="OK-1", **{field: value}))
                self.assertEqual(r.status_code, 422, (field, value))
        self.assertEqual(self.one("SELECT COUNT(*) FROM services")[0], 0)

    def test_unknown_and_system_fields_rejected(self):
        for extra in ("created_by", "last_verified_at", "id", "tags2"):
            self.assertEqual(self.post_form("/services/new", **svc_data(**{extra: "1"})).status_code, 422, extra)

    def test_url_scheme_validation(self):
        bad_urls = ["javascript:alert(1)", "data:text/html,<script>alert(1)</script>", "ftp://files.example.com",
                    "file:///etc/passwd", "vbscript:msgbox(1)", "//evil.com", "http://", "https:// spaced.com",
                    "javascript://x.com/%0aalert(1)", "JAVASCRIPT:alert(1)", "https://user:pw@x.com"]
        for bad in bad_urls:
            for field in ("repo_url", "doc_url"):
                r = self.post_form("/services/new", **svc_data(code="URL-1", **{field: bad}))
                self.assertEqual(r.status_code, 422, (field, bad))
            r = self.post_form("/services/new", **svc_data(code="URL-1", urls="https://ok.example.com\n" + bad))
            self.assertEqual(r.status_code, 422, ("urls", bad))
        self.assertEqual(self.one("SELECT COUNT(*) FROM services")[0], 0)
        self.create(code="URL-OK", repo_url="http://git.local/x", doc_url="HTTPS://Wiki.Example.com/A?b=1#c",
                    urls="http://a.local\nb.example.com\nc.example.com/path?x=1\n10.0.0.5:8080")

    def test_too_many_urls(self):
        r = self.post_form("/services/new", **svc_data(urls="\n".join(f"h{i}.example.com" for i in range(21))))
        self.assertEqual(r.status_code, 422)
        self.create(urls="\n".join(f"h{i}.example.com" for i in range(20)))

    def test_urls_rendered_safely(self):
        sid = self.create(urls="https://pay.example.com/a?x=1&y=2\nbare.example.com", repo_url="https://git.example.com/p")
        html = self.client.get(f"/services/{sid}").text
        self.assertRegex(html, r'<a href="https://pay\.example\.com/a\?x=1&amp;y=2" rel="noopener noreferrer"')
        self.assertIn('<a href="https://git.example.com/p" rel="noopener noreferrer"', html)
        self.assertNotIn('href="bare.example.com', html)                      # 스킴 없는 도메인은 링크로 만들지 않음
        self.assertIn("bare.example.com", html)
        self.assertNotIn("javascript:", html.lower())
        for a in re.findall(r"<a [^>]*href=\"https?://[^>]*>", html):
            self.assertIn('rel="noopener noreferrer"', a)

    def test_serving_engine_only_for_ai_inference(self):
        a = self.create(code="NOT-AI", category="API", serving_engine="vLLM")
        self.assertIsNone(self.svc(a)["serving_engine"])                      # 서버측에서 비워 저장
        b = self.create(code="AI-1", category="AI 추론", serving_engine="vLLM")
        self.assertEqual(self.svc(b)["serving_engine"], "vLLM")
        self.assertIn("서빙 엔진 vLLM", self.client.get(f"/services/{b}").text)
        c = self.create(code="AI-2", category="AI 추론", serving_engine="")
        self.assertIsNone(self.svc(c)["serving_engine"])
        r = self.post_form("/services/new", **svc_data(code="AI-3", category="AI 추론", serving_engine="NoSuchEngine"))
        self.assertEqual(r.status_code, 422)
        for engine in ("SGLang", "Triton", "TGI", "Ollama", "TorchServe", "자체 구현", "기타"):
            self.create(code="E-" + str(abs(hash(engine)) % 10**6), category="AI 추론", serving_engine=engine)
        # 분류를 바꾸면 기존 엔진 값도 비워진다
        self.post_form(f"/services/{b}/edit", **svc_data(code="AI-1", category="웹", serving_engine="vLLM"))
        self.assertIsNone(self.svc(b)["serving_engine"])

    def test_owners_active_and_distinct(self):
        self.conn.execute("UPDATE users SET is_active=0 WHERE id=?", (self.editor2,))
        r = self.post_form("/services/new", **svc_data(primary_owner_id=str(self.editor2)))
        self.assertIn("활성 사용자만", r.text)
        r = self.post_form("/services/new", **svc_data(secondary_owner_id=str(self.editor2)))
        self.assertEqual(r.status_code, 422)
        r = self.post_form("/services/new", **svc_data(primary_owner_id=str(self.editor), secondary_owner_id=str(self.editor)))
        self.assertIn("서로 다른 사용자", r.text)
        self.assertNotIn("이름-ed2", self.client.get("/services/new").text)

    def test_escaping(self):
        sid = self.create(name="<img src=x onerror=alert(1)>", description="<script>alert(1)</script>")
        for path in (f"/services/{sid}", "/services"):
            html = self.client.get(path).text
            self.assertNotIn("<img src=x", html)
            self.assertNotIn("<script>alert(1)", html)


class EditTests(ServiceCase):
    def test_edit_audit_and_no_verification(self):
        sid = self.create()
        self.conn.execute("UPDATE services SET last_verified_at='2020-01-01T00:00:00Z' WHERE id=?", (sid,))
        r = self.post_form(f"/services/{sid}/edit", **svc_data(name="새 이름", tier="2", tags="x"))
        self.assertEqual((r.status_code, r.headers["location"]), (303, f"/services/{sid}"))
        row = self.svc(sid)
        self.assertEqual((row["name"], row["tier"], row["last_verified_at"]), ("새 이름", 2, "2020-01-01T00:00:00Z"))
        summary = self.one("SELECT summary FROM audit_logs WHERE action='service_update'")[0]
        self.assertIn("name: 결제 API → 새 이름", summary)
        self.assertIn("tier: 1 → 2", summary)
        self.assertIn("tags:  → x", summary)

    def test_unchanged_edit_writes_nothing(self):
        sid = self.create()
        self.conn.execute("UPDATE services SET updated_at='2020-01-01T00:00:00Z'")
        self.post_form(f"/services/{sid}/edit", **svc_data())
        self.assertEqual(self.svc(sid)["updated_at"], "2020-01-01T00:00:00Z")
        self.assertIsNone(self.one("SELECT 1 FROM audit_logs WHERE action='service_update'"))

    def test_code_uniqueness_on_edit(self):
        a = self.create(code="AAA")
        b = self.create(code="BBB")
        self.assertEqual(self.post_form(f"/services/{b}/edit", **svc_data(code="AAA")).status_code, 422)
        self.assertEqual(self.post_form(f"/services/{a}/edit", **svc_data(code="AAA", name="same code ok")).status_code, 303)

    def test_prefilled_form_and_inactive_owner_kept(self):
        sid = self.create(primary_owner_id=str(self.editor2), tags="a,b")
        self.conn.execute("UPDATE users SET is_active=0 WHERE id=?", (self.editor2,))
        html = self.client.get(f"/services/{sid}/edit").text
        self.assertIn("[비활성]", html)
        self.assertIn('value="PAY-API"', html)
        self.assertIn("a, b", html)
        ok = self.post_form(f"/services/{sid}/edit", **svc_data(primary_owner_id=str(self.editor2), name="그대로"))
        self.assertEqual(ok.status_code, 303)
        self.assertIn("비활성 담당자", self.client.get("/services").text)
        self.assertIn("비활성 담당자", self.client.get(f"/services/{sid}").text)


class ListTests(ServiceCase):
    def test_pagination_and_columns(self):
        for i in range(45):
            self.service(self.editor, code=f"S-{i:03d}", name=f"svc{i:03d}")
        p = [self.client.get(f"/services?page={n}").text for n in (1, 2, 3)]
        self.assertEqual([x.split("<tbody>")[1].count("<tr>") for x in p], [20, 20, 5])
        self.assertIn("총 45건", p[0])
        sid = self.create(code="COL-1")
        svr = self.server(self.editor, hostname="c1")
        self.conn.execute("INSERT INTO service_servers (service_id, server_id, role) VALUES (?, ?, 'WEB')", (sid, svr))
        row = self.client.get("/services?q=COL-1").text.split("<tbody>")[1]
        for needle in ("COL-1", "결제 API", "API", "운영중", "Tier 1", "확인 필요"):
            self.assertIn(needle, row)
        self.assertRegex(row, r"<td>1</td>")                                  # 구동 서버 수

    def test_search_name_code_domain_with_escaped_wildcards(self):
        self.create(code="PAY-API", name="결제", urls="pay.example.com")
        self.create(code="ADM", name="100%관리", urls="adm.example.com/admin_portal")
        self.create(code="GRP", name="그룹웨어", urls="https://mail.example.com")
        from urllib.parse import urlencode
        found = lambda q: sorted(self.names(self.client.get("/services?" + urlencode({"q": q})).text))
        self.assertEqual(found("결제"), ["PAY-API"])
        self.assertEqual(found("pay-api"), ["PAY-API"])
        self.assertEqual(found("mail.example"), ["GRP"])
        self.assertEqual(found("%"), ["ADM"])
        self.assertEqual(found("_"), ["ADM"])
        self.assertEqual(found("x' OR 1=1 --"), [])

    def test_filters(self):
        a = self.create(code="A-1", name="a", category="AI 추론", environment="stg", status="점검", tier="3",
                        primary_owner_id=str(self.editor), tags="t1")
        b = self.create(code="B-1", name="b", category="웹", secondary_owner_id=str(self.editor2))
        c = self.create(code="C-1", name="c", primary_owner_id=str(self.editor2))
        self.conn.execute("UPDATE services SET last_verified_at='2099-01-01T00:00:00Z' WHERE code='A-1'")
        f = lambda qs: sorted(self.names(self.client.get("/services?" + qs).text))
        self.assertEqual(f("category=AI 추론"), ["A-1"])
        self.assertEqual(f("environment=stg"), ["A-1"])
        self.assertEqual(f("status=점검"), ["A-1"])
        self.assertEqual(f("tier=3"), ["A-1"])
        self.assertEqual(f("tier=1"), ["B-1", "C-1"])
        self.assertEqual(f("tag=t1"), ["A-1"])
        self.assertEqual(f(f"owner_id={self.editor2}"), ["B-1", "C-1"])          # 정/부 모두 포함
        self.assertEqual(f("stale=on"), ["B-1", "C-1"])
        self.login(self.editor2)
        self.assertEqual(f("mine=on"), ["B-1", "C-1"])                            # 내 담당: 부 담당자 포함
        self.login(self.editor)
        self.assertEqual(f("mine=on"), ["A-1"])

    def test_sort_and_invalid_filters(self):
        self.service(self.editor, code="B-2", name="x", updated_at="2026-01-01T00:00:00Z")
        self.service(self.editor, code="A-2", name="y", updated_at="2026-03-01T00:00:00Z")
        self.assertEqual(self.names(self.client.get("/services?sort=name").text), ["A-2", "B-2"])
        self.assertEqual(self.names(self.client.get("/services?sort=updated").text), ["A-2", "B-2"])
        for qs in ("sort=code;DROP", "tier=9", "category=x", "page=0", "evil=1", "owner_id=abc"):
            r = self.client.get("/services?" + qs)
            self.assertIn("조회 조건이 올바르지 않습니다", r.text, qs)
        self.assertEqual(self.one("SELECT COUNT(*) FROM services")[0], 2)

    def test_tier_badges_have_text(self):
        for tier in (1, 2, 3):
            self.service(self.editor, code=f"T-{tier}", tier=tier)
        html = self.client.get("/services").text
        for tier, color in ((1, "red"), (2, "orange"), (3, "gray")):
            self.assertIn(f'badge-{color}">Tier {tier}</span>', html)


class ServerLinkTests(ServiceCase):
    def setUp(self):
        super().setUp()
        self.sid = self.create()
        self.srv_id = self.server(self.editor, hostname="web-1", name="웹1")

    def link(self, expect=303, **kw):
        data = dict(server_id=str(self.srv_id), role="WEB", note="")
        data.update(kw)
        r = self.post_form(f"/services/{self.sid}/servers/new", **data)
        self.assertEqual(r.status_code, expect, r.text[-500:] if r.status_code != expect else "")
        return r

    def test_link_edit_unlink(self):
        self.link(note="메인")
        self.assertEqual(self.one("SELECT role, note FROM service_servers")[:], ("WEB", "메인"))
        html = self.client.get(f"/services/{self.sid}").text
        self.assertIn("웹1", html)
        self.assertIn("메인", html)
        r = self.post_form(f"/services/{self.sid}/servers/{self.srv_id}/edit", role="DB", note="변경")
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.one("SELECT role, note FROM service_servers")[:], ("DB", "변경"))
        r = self.post_form(f"/services/{self.sid}/servers/{self.srv_id}/delete")
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.one("SELECT COUNT(*) FROM service_servers")[0], 0)
        self.assertIsNotNone(self.one("SELECT 1 FROM servers WHERE id=?", self.srv_id))     # 서버는 그대로

    def test_validation(self):
        self.link(422, role="없는역할")
        self.link(422, server_id="999")
        self.link(422, server_id="abc")
        self.link(422, server_id="")
        self.link(422, note="x" * 501)
        self.link(); self.link(422)                                                        # 중복 연결
        self.assertEqual(self.one("SELECT COUNT(*) FROM service_servers")[0], 1)
        self.assertNotIn("웹1 (web-1)", self.client.get(f"/services/{self.sid}/servers/new").text)  # 이미 연결된 서버는 선택지에서 제외

    def test_all_roles_accepted(self):
        for i, role in enumerate(("WEB", "WAS", "API", "DB", "캐시", "배치", "LB", "기타")):
            other = self.server(self.editor, hostname=f"r{i}")
            self.assertEqual(self.post_form(f"/services/{self.sid}/servers/new", server_id=str(other), role=role).status_code, 303)

    def test_server_detail_shows_running_services_with_tier(self):
        self.link()
        html = self.client.get(f"/servers/{self.srv_id}").text.split("구동 중인 서비스")[1]
        self.assertIn("결제 API", html)
        self.assertIn('badge-red">Tier 1', html)
        self.assertIn("1", self.client.get("/services").text.split("<tbody>")[1])

    def test_missing_link_404(self):
        self.assertEqual(self.client.get(f"/services/{self.sid}/servers/{self.srv_id}/edit").status_code, 404)
        self.assertEqual(self.post_form(f"/services/{self.sid}/servers/{self.srv_id}/delete").status_code, 404)


class LinkTests(ServiceCase):
    def setUp(self):
        super().setUp()
        self.a = self.create(code="SVC-A", name="서비스A", tier="1")
        self.b = self.create(code="SVC-B", name="서비스B", tier="2")

    def add(self, sid=None, expect=303, **kw):
        data = dict(target_service_id="", external_name="", protocol="HTTPS", port="", purpose="", auth_method="")
        data.update(kw)
        r = self.post_form(f"/services/{sid or self.a}/links/new", **data)
        self.assertEqual(r.status_code, expect, r.text[-600:] if r.status_code != expect else "")
        return r

    def test_internal_and_external_links(self):
        self.add(target_service_id=str(self.b), purpose="주문 조회", port="8443", auth_method="mTLS")
        self.add(external_name="토스페이먼츠 API", protocol="HTTPS", purpose="결제 승인 요청", auth_method="API Key")
        rows = self.conn.execute("SELECT target_service_id, external_name, protocol, port FROM service_links ORDER BY id").fetchall()
        self.assertEqual([tuple(r) for r in rows], [(self.b, None, "HTTPS", 8443), (None, "토스페이먼츠 API", "HTTPS", None)])
        html = self.client.get(f"/services/{self.a}").text
        self.assertIn("서비스B", html)
        self.assertIn("토스페이먼츠 API", html)
        self.assertIn("주문 조회", html)
        self.assertIn("외부", html)

    def test_exactly_one_target(self):
        r = self.add(expect=422)
        self.assertIn("정확히 하나", r.text)
        r = self.add(expect=422, target_service_id=str(self.b), external_name="AWS S3")
        self.assertIn("정확히 하나", r.text)
        self.assertEqual(self.one("SELECT COUNT(*) FROM service_links")[0], 0)

    def test_self_reference_rejected(self):
        r = self.add(expect=422, target_service_id=str(self.a))
        self.assertIn("자기 자신", r.text)
        self.assertNotIn(f'<option value="{self.a}"', self.client.get(f"/services/{self.a}/links/new").text)
        # DB 제약도 막는다
        with self.assertRaises(Exception):
            self.conn.execute("INSERT INTO service_links (service_id, target_service_id, protocol) VALUES (?, ?, 'HTTP')",
                              (self.a, self.a))

    def test_validation(self):
        self.add(expect=422, target_service_id="999")
        self.add(expect=422, target_service_id="abc")
        self.add(expect=422, external_name="x", protocol="FTP")
        for port in ("0", "65536", "-1", "abc"):
            self.add(expect=422, external_name="x", port=port)
        self.add(expect=422, external_name="x" * 101)
        self.add(expect=422, external_name="x", purpose="x" * 501)
        self.add(expect=422, external_name="x", evil="1")
        for protocol in ("HTTP", "HTTPS", "gRPC", "TCP", "DB", "MQ", "SFTP", "SMTP", "기타"):
            self.add(external_name="ext-" + protocol, protocol=protocol)

    def test_auth_method_must_not_be_a_credential(self):
        for secret in ("sk-" + "a" * 45, "A" * 41):
            r = self.add(expect=422, external_name="x", auth_method=secret)
            self.assertIn("인증 정보", r.text)
        for ok in ("API Key", "mTLS", "IP 화이트리스트", "OAuth2 client credentials flow with rotating secrets"):
            self.add(external_name="y-" + ok[:5], auth_method=ok)
        self.assertNotIn("sk-", self.client.get(f"/services/{self.a}").text)

    def test_incoming_links_shown_on_target(self):
        c = self.create(code="SVC-C", name="서비스C", tier="3")
        self.add(sid=self.a, target_service_id=str(self.b), purpose="A가 B 호출")
        self.add(sid=c, target_service_id=str(self.b), purpose="C가 B 호출", protocol="gRPC")
        html = self.client.get(f"/services/{self.b}").text.split("들어오는 연결")[1]
        for needle in ("서비스A", "서비스C", "A가 B 호출", "C가 B 호출", "gRPC", 'badge-red">Tier 1', 'badge-gray">Tier 3'):
            self.assertIn(needle, html)
        self.assertLess(html.index("서비스A"), html.index("서비스C"))                # 중요도 순
        self.assertIn("이 서비스에 의존하는 서비스가 없습니다", self.client.get(f"/services/{self.a}").text)
        outgoing = self.client.get(f"/services/{self.a}").text.split("나가는 연결")[1].split("들어오는 연결")[0]
        self.assertIn("서비스B", outgoing)

    def test_edit_switch_internal_to_external_and_delete(self):
        self.add(target_service_id=str(self.b))
        lid = self.one("SELECT id FROM service_links")[0]
        html = self.client.get(f"/services/{self.a}/links/{lid}/edit").text
        self.assertIn(f'<option value="{self.b}" selected', html)
        r = self.post_form(f"/services/{self.a}/links/{lid}/edit", target_service_id="", external_name="Kakao", protocol="HTTPS",
                           port="", purpose="", auth_method="")
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.one("SELECT target_service_id, external_name FROM service_links")[:], (None, "Kakao"))
        r = self.post_form(f"/services/{self.a}/links/{lid}/edit", target_service_id=str(self.a), external_name="", protocol="HTTPS",
                           port="", purpose="", auth_method="")
        self.assertEqual(r.status_code, 422)
        self.assertEqual(self.post_form(f"/services/{self.a}/links/{lid}/delete").status_code, 303)
        self.assertEqual(self.one("SELECT COUNT(*) FROM service_links")[0], 0)

    def test_link_of_other_service_is_404(self):
        self.add(target_service_id=str(self.b))
        lid = self.one("SELECT id FROM service_links")[0]
        self.assertEqual(self.client.get(f"/services/{self.b}/links/{lid}/edit").status_code, 404)
        self.assertEqual(self.post_form(f"/services/{self.b}/links/{lid}/delete").status_code, 404)
        self.assertEqual(self.one("SELECT COUNT(*) FROM service_links")[0], 1)


class DeleteTests(ServiceCase):
    def test_confirm_warns_about_dependents_and_get_does_not_delete(self):
        a = self.create(code="DEP-A", name="의존하는 서비스", tier="1")
        b = self.create(code="BASE-B", name="기반 서비스")
        self.conn.execute("INSERT INTO service_links (service_id, target_service_id, protocol) VALUES (?, ?, 'HTTP')", (a, b))
        r = self.client.get(f"/services/{b}/delete")
        self.assertEqual(r.status_code, 200)
        self.assertIn("의존하는 서비스가 1개", r.text)
        self.assertIn("의존하는 서비스", r.text)
        self.assertIsNotNone(self.svc(b))
        self.assertNotIn("의존하는 서비스가", self.client.get(f"/services/{a}/delete").text)       # a에 의존하는 서비스는 없음

    def test_delete_cascades_links_both_ways_and_cleans_extras_without_orphans(self):
        a = self.create(code="DEL-A", tags="keep,gone")
        b = self.create(code="DEL-B", tags="keep")
        c = self.create(code="DEL-C")
        self.post_form(f"/services/{a}/notes", content="삭제될 메모")
        self.post_form(f"/services/{b}/notes", content="남을 메모")
        srv = self.server(self.editor, hostname="s1")
        self.conn.execute("INSERT INTO service_servers VALUES (?, ?, 'WEB', '')", (a, srv))
        self.conn.execute("INSERT INTO service_links (service_id, target_service_id, protocol) VALUES (?, ?, 'HTTP')", (a, b))
        self.conn.execute("INSERT INTO service_links (service_id, target_service_id, protocol) VALUES (?, ?, 'HTTP')", (c, a))
        self.conn.execute("INSERT INTO service_links (service_id, external_name, protocol) VALUES (?, 'ext', 'HTTP')", (a,))
        lic = self.license(self.editor)
        self.conn.execute("INSERT INTO license_services VALUES (?, ?)", (lic, a))
        mdl = self.model(self.editor)
        self.conn.execute("INSERT INTO model_services (model_id, service_id) VALUES (?, ?)", (mdl, a))
        r = self.post_form(f"/services/{a}/delete")
        self.assertEqual((r.status_code, r.headers["location"]), (303, "/services"))
        self.assertIsNone(self.svc(a))
        q = lambda sql, *p: self.one(sql, *p)[0]
        self.assertEqual(q("SELECT COUNT(*) FROM service_links"), 0)                  # 나가는/들어오는 모두 삭제
        self.assertEqual(q("SELECT COUNT(*) FROM service_servers"), 0)
        self.assertEqual(q("SELECT COUNT(*) FROM license_services"), 0)
        self.assertEqual(q("SELECT COUNT(*) FROM model_services"), 0)
        self.assertEqual(q("SELECT COUNT(*) FROM asset_tags WHERE asset_type='service' AND asset_id=?", a), 0)
        self.assertEqual(q("SELECT COUNT(*) FROM asset_notes WHERE asset_type='service' AND asset_id=?", a), 0)
        self.assertEqual(q("SELECT COUNT(*) FROM asset_tags WHERE asset_type='service' AND asset_id=?", b), 1)
        self.assertEqual(q("SELECT COUNT(*) FROM asset_notes WHERE asset_id=?", b), 1)
        self.assertEqual(q("SELECT COUNT(*) FROM servers"), 1)                          # 서버/라이선스/모델 자체는 유지
        self.assertEqual(q("SELECT COUNT(*) FROM licenses"), 1)
        self.assertEqual(q("SELECT COUNT(*) FROM models"), 1)
        self.assertIn("DEL-A", self.one("SELECT summary FROM audit_logs WHERE action='service_delete'")[0])

    def test_viewer_cannot_delete(self):
        sid = self.create()
        self.login(self.viewer)
        self.assertEqual(self.post_form(f"/services/{sid}/delete").status_code, 403)
        self.assertIsNotNone(self.svc(sid))


class CommonFeatureTests(ServiceCase):
    def test_verify_notes_and_history_work_for_services(self):
        sid = self.create()
        self.assertIn("확인 필요", self.client.get(f"/services/{sid}").text)
        self.post_form(f"/services/{sid}/verify")
        self.assertIsNotNone(self.svc(sid)["last_verified_at"])
        self.assertIn("확인됨", self.client.get(f"/services/{sid}").text)
        self.post_form(f"/services/{sid}/notes", content="런북 갱신")
        html = self.client.get(f"/services/{sid}").text
        self.assertIn("런북 갱신", html)
        history = html.split("변경 이력")[1]
        for action in ("service_create", "service_verify", "service_note_add"):
            self.assertIn(action, history)
        nid = self.one("SELECT id FROM asset_notes")[0]
        self.login(self.editor2)
        self.assertEqual(self.post_form(f"/services/{sid}/notes/{nid}/delete").status_code, 403)
        self.login(self.admin)
        self.assertEqual(self.post_form(f"/services/{sid}/notes/{nid}/delete").status_code, 303)
        self.assertEqual(self.post_form(f"/services/999/verify").status_code, 404)

    def test_notes_and_verify_do_not_cross_asset_types(self):
        sid = self.create()
        server = self.server(self.editor, hostname="x1")
        self.post_form(f"/services/{sid}/notes", content="서비스 메모")
        nid = self.one("SELECT id FROM asset_notes")[0]
        self.assertEqual(self.post_form(f"/servers/{server}/notes/{nid}/delete").status_code, 404)
