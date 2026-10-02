import re
from urllib.parse import quote, urlencode

from app import assets
from app.routers import search as search_router
from tests.test_licenses import KEY, ACCOUNT, ai_data, lic_data, ssl_data
from tests.test_models import mdl_data
from tests.test_servers import ServerCase, server_data
from tests.test_services import svc_data


class SearchCase(ServerCase):
    def q(self, term, **kw):
        return self.client.get("/search?" + urlencode({"q": term}), **kw)

    def section(self, html, key):
        m = re.search(rf'<section class="section" id="{key}">(.*?)</section>', html, re.S)
        return m.group(1) if m else ""

    def add_acl(self, server_id, src, dst, port="443", status="적용완료", purpose="테스트 ACL"):
        self.conn.execute(
            "INSERT INTO server_acls (server_id, direction, src_cidr, dst_cidr, port_start, port_end, protocol, purpose, "
            "requester, requested_at, status) VALUES (?, 'Inbound', ?, ?, ?, ?, 'TCP', ?, 'r', '2026-01-01', ?)",
            (server_id, src, dst, int(port), int(port), purpose, status))


class SearchValidationTests(SearchCase):
    def test_length_limits(self):
        self.server(self.editor, hostname="ab-host", name="ab")
        for bad in ("a", "", " ", "   a ", "x" * 101):
            r = self.q(bad)
            self.assertEqual(r.status_code, 200, repr(bad))
            self.assertIn("검색어는 2자 이상 100자 이하로 입력하세요.", r.text, repr(bad))
            self.assertNotIn("검색 결과가 없습니다", r.text)
        self.assertIn("ab-host", self.q("ab").text)
        self.assertNotIn("100자 이하로 입력하세요.</div>", self.q("x" * 100).text)
        self.assertIn("검색 결과가 없습니다", self.q("x" * 100).text)

    def test_no_query_shows_form_only_and_unknown_param_rejected(self):
        r = self.client.get("/search")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("flash-error", r.text)
        self.assertIn("검색어는 2자 이상", self.client.get("/search?q=abc&evil=1").text)

    def test_unauthenticated_redirects_and_viewer_can_search(self):
        self.server(self.editor, hostname="visible-host", name="visible")
        self.login(self.viewer)
        self.assertIn("visible-host", self.q("visible").text)
        self.client.cookies.clear()
        self.assertEqual(self.q("visible").status_code, 303)

    def test_post_not_allowed(self):
        self.assertEqual(self.post_form("/search", q="abcd").status_code, 405)

    def test_header_search_box_on_every_page(self):
        html = self.client.get("/servers").text
        self.assertIn('action="/search"', html)
        self.assertIn('minlength="2" maxlength="100"', html)


class SearchTargetTests(SearchCase):
    def test_servers_by_name_hostname_and_ip(self):
        a = self.server(self.editor, hostname="alpha-web", name="결제 웹")
        self.server(self.editor, hostname="beta-db", name="데이터베이스")
        self.conn.execute("INSERT INTO server_ips (server_id, ip, kind) VALUES (?, '10.20.30.40', '사설')", (a,))
        for term in ("결제", "ALPHA", "10.20.30"):
            sec = self.section(self.q(term).text, "servers")
            self.assertIn("결제 웹", sec, term)
            self.assertNotIn("데이터베이스", sec, term)
        self.assertIn("10.20.30.40", self.section(self.q("10.20.30").text, "servers"))

    def test_services_by_name_code_and_domain(self):
        self.post_form("/services/new", **svc_data(code="PAY-API", name="결제 API", urls="pay.example.com"))
        for term in ("결제", "pay-api", "pay.example"):
            self.assertIn("PAY-API", self.section(self.q(term).text, "services"), term)

    def test_models_by_name_and_base_model(self):
        self.post_form("/models/new", **mdl_data(name="support-bot", base_model="Llama 3.1 8B Instruct"))
        for term in ("support", "llama 3.1"):
            self.assertIn("support-bot", self.section(self.q(term).text, "models"), term)

    def test_gpu_model_finds_servers(self):
        s = self.server(self.editor, hostname="gpu-1", name="GPU 서버")
        self.conn.execute("INSERT INTO server_gpus (server_id, gpu_model, quantity, assigned_to) VALUES (?, 'A100 80GB', 8, '추천팀')", (s,))
        self.conn.execute("INSERT INTO server_gpus (server_id, gpu_model, quantity) VALUES (?, 'T4', 2)", (s,))
        sec = self.section(self.q("a100").text, "gpus")
        self.assertIn("A100 80GB", sec)
        self.assertIn("×8", sec)
        self.assertIn("GPU 서버", sec)
        self.assertIn("추천팀", sec)
        self.assertNotIn("T4", sec)
        self.assertIn(f'href="/servers/{s}#gpus"', sec)

    def test_licenses_by_name_cn_san_and_provider(self):
        self.post_form("/licenses/new", **ssl_data(name="web-cert", ssl_cn="www.shop.example.com", ssl_san="www.shop.example.com\nm.shop.example.com"))
        self.post_form("/licenses/new", **ai_data(name="llm-key", ai_provider="Anthropic"))
        for term in ("web-cert", "www.shop", "m.shop.example", "anthrop"):
            sec = self.section(self.q(term).text, "licenses")
            self.assertTrue("web-cert" in sec or "llm-key" in sec, term)
        self.assertIn("llm-key", self.section(self.q("Anthropic").text, "licenses"))
        self.assertNotIn("llm-key", self.section(self.q("shop").text, "licenses"))

    def test_containers_by_name_and_image(self):
        s = self.server(self.editor, hostname="c-1", name="컨테이너 서버")
        self.conn.execute("INSERT INTO server_containers (server_id, name, image) VALUES (?, 'redis-main', 'redis:7.2')", (s,))
        for term in ("redis-main", "redis:7"):
            sec = self.section(self.q(term).text, "containers")
            self.assertIn("redis-main", sec)
            self.assertIn("컨테이너 서버", sec)

    def test_tag_name_finds_tagged_assets_of_every_type(self):
        srv = self.server(self.editor, hostname="t-srv", name="태그 서버")
        self.post_form(f"/servers/{srv}/edit", **server_data(hostname="t-srv", name="태그 서버", tags="proj-x"))
        self.post_form("/services/new", **svc_data(code="TAG-SVC", name="태그 서비스", tags="proj-x"))
        self.post_form("/models/new", **mdl_data(name="tag-model", tags="proj-x, other"))
        self.post_form("/licenses/new", **lic_data(name="태그 라이선스", tags="proj-x"))
        self.post_form("/licenses/new", **lic_data(name="무관한 라이선스", tags="unrelated"))
        sec = self.section(self.q("proj-x").text, "tags")
        for name in ("태그 서버", "TAG-SVC · 태그 서비스", "tag-model 8b-instruct", "태그 라이선스"):
            self.assertIn(name, sec)
        self.assertNotIn("무관한 라이선스", sec)
        for kind in ("서버", "서비스", "AI 모델", "라이선스"):
            self.assertIn(f"<td>{kind}</td>", sec)
        self.assertIn("proj-x", self.section(self.q("PROJ").text, "tags"))      # 부분 일치

    def test_groups_are_separate_and_empty_groups_hidden(self):
        self.server(self.editor, hostname="shop-1", name="shop 서버")
        self.post_form("/services/new", **svc_data(code="SHOP", name="shop 서비스"))
        html = self.q("shop").text
        self.assertIn('id="servers"', html)
        self.assertIn('id="services"', html)
        for hidden in ("models", "licenses", "containers", "gpus", "tags", "acls"):
            self.assertNotIn(f'id="{hidden}"', html, hidden)

    def test_group_limit_20_with_total(self):
        for i in range(25):
            self.server(self.editor, hostname=f"many-{i:02d}", name=f"many-{i:02d}")
        sec = self.section(self.q("many").text, "servers")
        self.assertEqual(sec.count("<tr><td><a"), 20)
        self.assertIn("25건 (최대 20건 표시)", sec)

    def test_like_wildcards_are_literal_and_injection_is_harmless(self):
        self.server(self.editor, hostname="plain-host", name="plain")
        self.server(self.editor, hostname="pct-host", name="100%할인")
        self.server(self.editor, hostname="under_host", name="under")
        self.assertIn("100%할인", self.section(self.q("0%").text, "servers"))
        self.assertNotIn("plain", self.section(self.q("0%").text, "servers"))
        self.assertEqual(self.section(self.q("%%").text, "servers"), "")           # 와일드카드는 리터럴이라 전부 일치하지 않는다
        sec = self.section(self.q("r_").text, "servers")
        self.assertIn("under", sec)
        self.assertNotIn("plain-host", sec)
        self.assertNotIn("플레인", self.q("a%a").text)
        for evil in ("x' OR '1'='1", "'; DROP TABLE servers; --", "\\", "%%", "a\\%"):
            r = self.q(evil)
            self.assertEqual(r.status_code, 200, evil)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM servers").fetchone()[0], 3)

    def test_xss_is_escaped(self):
        self.server(self.editor, hostname="xss-host", name="<script>alert(1)</script>")
        html = self.q("script").text
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)
        r = self.client.get("/search?q=" + quote("<img src=x onerror=alert(1)>"))
        self.assertNotIn("<img src=x", r.text)

    def test_sensitive_fields_are_never_searched_or_shown(self):
        self.post_form("/licenses/new", **lic_data(name="holder-x", license_key=KEY, account_info=ACCOUNT))
        for term in ("WXYZ", "LIC-KEY", "0123-ABCD", "Secret", "admin@corp", "P@ssw0rd"):
            r = self.q(term)
            self.assertNotIn("holder-x", r.text, term)
            self.assertIn("검색 결과가 없습니다", r.text, term)
        self.assertNotIn("license_key_enc", self.q("holder").text)
        self.assertNotIn(KEY, self.q("holder-x").text)
        sqls = " ".join(sql for pair in search_router._SQL.values() for sql in pair)
        self.assertNotIn("license_key", sqls)
        self.assertNotIn("account_info", sqls)


class ACLSearchTests(SearchCase):
    def setUp(self):
        super().setUp()
        self.srv = self.server(self.editor, hostname="acl-1", name="ACL 서버")

    def acl_section(self, term):
        return self.section(self.q(term).text, "acls")

    def test_ip_matches_containing_cidrs_in_src_or_dst(self):
        self.add_acl(self.srv, "10.0.0.0/24", "172.16.0.5/32", purpose="출발지 /24")
        self.add_acl(self.srv, "192.168.0.0/16", "10.0.0.7/32", purpose="목적지 단일")
        self.add_acl(self.srv, "10.0.1.0/24", "10.0.2.0/24", purpose="포함 안 됨")
        self.add_acl(self.srv, "0.0.0.0/0", "10.9.9.9/32", purpose="전체 허용")
        sec = self.acl_section("10.0.0.7")
        self.assertIn("출발지 /24", sec)
        self.assertIn("목적지 단일", sec)
        self.assertIn("전체 허용", sec)
        self.assertNotIn("포함 안 됨", sec)
        self.assertIn("이 IP(10.0.0.7)가 포함되는 ACL (3건)", sec)
        self.assertIn("ACL 서버", sec)

    def test_cidr_boundaries(self):
        self.add_acl(self.srv, "10.0.0.0/24", "1.1.1.1/32", purpose="범위")
        self.assertIn("범위", self.acl_section("10.0.0.0"))          # 네트워크 주소
        self.assertIn("범위", self.acl_section("10.0.0.255"))        # 브로드캐스트 주소
        self.assertNotIn("범위", self.acl_section("10.0.1.0"))       # 범위 밖 (바로 다음)
        self.assertNotIn("범위", self.acl_section("9.255.255.255"))
        self.add_acl(self.srv, "8.8.8.8/32", "9.9.9.9/32", purpose="단일")
        self.assertIn("단일", self.acl_section("8.8.8.8"))
        self.assertNotIn("단일", self.acl_section("8.8.8.9"))

    def test_ipv6_and_family_mixing(self):
        self.add_acl(self.srv, "2001:db8::/32", "10.0.0.0/8", purpose="v6 출발지")
        self.assertIn("v6 출발지", self.acl_section("2001:db8:1::5"))
        self.assertIn("v6 출발지", self.acl_section("10.1.2.3"))             # 같은 ACL의 v4 목적지
        self.assertNotIn("v6 출발지", self.acl_section("2001:db9::1"))
        self.assertNotIn("v6 출발지", self.acl_section("::ffff:10.1.2.3"))   # 다른 주소 체계는 매칭하지 않는다
        self.assertEqual(self.acl_section("::1"), "")

    def test_non_ip_or_malformed_input_does_not_search_acls(self):
        self.add_acl(self.srv, "0.0.0.0/0", "0.0.0.0/0", purpose="전체")
        for term in ("10.0.0", "10.0.0.256", "abc", "10.0.0.1/24", "fe80::1%eth0", "010.0.0.1"):
            r = self.q(term)
            self.assertEqual(r.status_code, 200, term)
            self.assertNotIn('id="acls"', r.text, term)
        self.assertIn('id="acls"', self.q(" 10.0.0.1 ").text)                    # 앞뒤 공백은 제거하고 판정

    def test_acl_status_and_port_shown_and_limit(self):
        self.add_acl(self.srv, "10.0.0.0/8", "1.1.1.1/32", port="8443", status="요청")
        sec = self.acl_section("10.1.1.1")
        self.assertIn("8443/TCP", sec)
        self.assertIn("요청", sec)
        for i in range(25):
            self.add_acl(self.srv, "10.0.0.0/8", f"2.2.2.{i}/32")
        sec = self.acl_section("10.1.1.1")
        self.assertIn("26건, 최대 20건 표시", sec)
        self.assertEqual(sec.count("<tr><td><a"), 20)

    def test_ip_also_searches_servers_by_ip_text(self):
        self.conn.execute("INSERT INTO server_ips (server_id, ip, kind) VALUES (?, '10.0.0.7', '사설')", (self.srv,))
        html = self.q("10.0.0.7").text
        self.assertIn("ACL 서버", self.section(html, "servers"))


class TagManagementTests(ServerCase):
    def make(self):
        a = self.server(self.editor, hostname="tg-1", name="서버1")
        b = self.server(self.editor, hostname="tg-2", name="서버2")
        self.post_form(f"/servers/{a}/edit", **server_data(hostname="tg-1", name="서버1", tags="used, shared"))
        self.post_form(f"/servers/{b}/edit", **server_data(hostname="tg-2", name="서버2", tags="shared"))
        self.post_form("/services/new", **svc_data(code="TG-S", tags="shared"))
        self.conn.execute("INSERT INTO tags (name) VALUES ('orphan')")
        return a, b

    def tag_id(self, name):
        return self.conn.execute("SELECT id FROM tags WHERE name=?", (name,)).fetchone()[0]

    def test_usage_counts(self):
        self.make()
        html = self.client.get("/tags").text
        rows = {}
        for row in html.split("<tr>")[2:]:
            name = re.search(r'class="tag">([^<]+)</span>', row)
            counts = re.findall(r"<td>(?:<strong>)?(\d+)(?:</strong>)?</td>", row)
            if name:
                rows[name.group(1)] = list(map(int, counts))
        self.assertEqual(rows["shared"], [3, 2, 1, 0, 0])
        self.assertEqual(rows["used"], [1, 1, 0, 0, 0])
        self.assertEqual(rows["orphan"], [0, 0, 0, 0, 0])

    def test_viewer_forbidden_everywhere(self):
        self.make()
        tid = self.tag_id("shared")
        self.login(self.viewer)
        self.assertEqual(self.client.get("/tags").status_code, 403)
        self.assertEqual(self.post_form(f"/tags/{tid}/rename", name="x").status_code, 403)
        self.assertEqual(self.post_form(f"/tags/{tid}/delete").status_code, 403)
        self.assertNotIn('href="/tags"', self.client.get("/").text)
        self.assertEqual(self.conn.execute("SELECT name FROM tags WHERE id=?", (tid,)).fetchone()[0], "shared")

    def test_unauth_csrf_404(self):
        self.make()
        tid = self.tag_id("orphan")
        self.assertEqual(self.post_form(f"/tags/{tid}/delete", csrf_token="bad").status_code, 403)
        self.assertEqual(self.post_form(f"/tags/{tid}/rename", csrf_token="bad", name="x").status_code, 403)
        self.assertEqual(self.post_form("/tags/999/delete").status_code, 404)
        self.assertEqual(self.post_form("/tags/999/rename", name="x").status_code, 404)
        self.assertEqual(self.client.get(f"/tags/{tid}/delete").status_code, 405)
        self.client.cookies.clear()
        self.assertEqual(self.client.get("/tags").status_code, 303)

    def test_rename_keeps_asset_links_and_normalizes(self):
        a, b = self.make()
        tid = self.tag_id("shared")
        r = self.post_form(f"/tags/{tid}/rename", name="  Team-Shared  ")
        self.assertEqual((r.status_code, r.headers["location"]), (303, "/tags"))
        self.assertEqual(self.conn.execute("SELECT name FROM tags WHERE id=?", (tid,)).fetchone()[0], "team-shared")
        self.assertEqual(assets.get_tags(self.conn, "server", a), ["team-shared", "used"])
        self.assertEqual(assets.get_tags(self.conn, "server", b), ["team-shared"])
        self.assertIn("태그 이름을 변경했습니다.", self.client.get("/tags").text)
        audit = self.conn.execute("SELECT * FROM audit_logs WHERE action='tag_rename'").fetchone()
        self.assertEqual((audit["target_type"], audit["target_id"], audit["summary"]), ("tag", tid, "name: shared → team-shared"))
        self.assertEqual(len(re.findall(r'<a href="/servers/\d+">', self.client.get("/servers?tag=team-shared").text)), 2)
        self.assertEqual(len(re.findall(r'<a href="/servers/\d+">', self.client.get("/servers?tag=shared").text)), 0)

    def test_rename_validation(self):
        self.make()
        tid, other = self.tag_id("used"), self.tag_id("shared")
        for bad in ("", "a b", "a,b", "x" * 31, "<b>", "한 글", "a;b"):
            self.post_form(f"/tags/{tid}/rename", name=bad)
            self.assertEqual(self.conn.execute("SELECT name FROM tags WHERE id=?", (tid,)).fetchone()[0], "used", repr(bad))
            self.assertIn("태그 이름을 바꾸지 못했습니다", self.client.get("/tags").text)
        self.post_form(f"/tags/{tid}/rename", name="SHARED")                   # 정규화하면 이미 존재
        self.assertEqual(self.conn.execute("SELECT name FROM tags WHERE id=?", (tid,)).fetchone()[0], "used")
        self.assertIn("이미 존재하는 태그입니다: shared", self.client.get("/tags").text)
        self.post_form(f"/tags/{tid}/rename", name="used")                     # 같은 이름 → 변경 없음
        self.assertIn("변경된 내용이 없습니다", self.client.get("/tags").text)
        self.assertEqual(self.post_form(f"/tags/{tid}/rename", name="ok", extra="1").status_code, 303)
        self.assertEqual(self.conn.execute("SELECT name FROM tags WHERE id=?", (tid,)).fetchone()[0], "used")
        self.assertIsNone(self.conn.execute("SELECT 1 FROM audit_logs WHERE action='tag_rename'").fetchone())
        self.post_form(f"/tags/{tid}/rename", name="한글-태그_1")
        self.assertEqual(self.conn.execute("SELECT name FROM tags WHERE id=?", (tid,)).fetchone()[0], "한글-태그_1")

    def test_delete_only_unused_tags(self):
        a, b = self.make()
        orphan, used = self.tag_id("orphan"), self.tag_id("used")
        r = self.post_form(f"/tags/{orphan}/delete")
        self.assertEqual((r.status_code, r.headers["location"]), (303, "/tags"))
        self.assertIsNone(self.conn.execute("SELECT 1 FROM tags WHERE id=?", (orphan,)).fetchone())
        self.assertIn("태그를 삭제했습니다.", self.client.get("/tags").text)
        self.post_form(f"/tags/{used}/delete")
        self.assertIsNotNone(self.conn.execute("SELECT 1 FROM tags WHERE id=?", (used,)).fetchone())      # 사용 중 → 거부
        self.assertEqual(assets.get_tags(self.conn, "server", a), ["shared", "used"])
        self.assertIn("사용 중인 태그는 삭제할 수 없습니다 (1건 사용 중)", self.client.get("/tags").text)
        audit = self.conn.execute("SELECT summary FROM audit_logs WHERE action='tag_delete'").fetchall()
        self.assertEqual([r[0] for r in audit], ["name: orphan"])

    def test_tag_becomes_deletable_after_assets_are_gone(self):
        a, b = self.make()
        used = self.tag_id("used")
        self.post_form(f"/servers/{a}/delete")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM asset_tags WHERE tag_id=?", (used,)).fetchone()[0], 0)
        self.post_form(f"/tags/{used}/delete")
        self.assertIsNone(self.conn.execute("SELECT 1 FROM tags WHERE id=?", (used,)).fetchone())

    def test_escaping(self):
        self.make()
        html = self.client.get("/tags").text
        self.assertNotIn("<script>", html)
        self.assertEqual(self.client.get("/tags").headers["cache-control"], "no-store")
