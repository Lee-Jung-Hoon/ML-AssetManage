import csv
import io
import re
from unittest import mock
from urllib.parse import urlencode

from app import assets, config, csvio
from app.routers import server_import
from tests.test_licenses import KEY, ACCOUNT, ai_data, lic_data, ssl_data
from tests.test_models import mdl_data
from tests.test_servers import ServerCase, server_data
from tests.test_services import svc_data


def rows_of(response):
    text = response.content.decode("utf-8-sig")
    return list(csv.reader(io.StringIO(text)))


class CsvCase(ServerCase):
    def export(self, path, query="", expect=200, **kw):
        r = self.post_form(path + ("?" + query if query else ""), **kw)
        self.assertEqual(r.status_code, expect, r.text[-300:] if r.status_code != expect else "")
        return r

    def table(self, response):
        rows = rows_of(response)
        return rows[0], [dict(zip(rows[0], r)) for r in rows[1:]]

    def audit_exports(self):
        return self.conn.execute("SELECT * FROM audit_logs WHERE action='csv_export' ORDER BY id").fetchall()


class SafeCellTests(CsvCase):
    def test_formula_injection_prefixes(self):
        for dangerous in ("=1+1", "+1", "-1", "@SUM(A1)", "\tcmd", "\rcmd", "=cmd|' /C calc'!A0", "-2+3", "@x"):
            self.assertEqual(csvio.safe_cell(dangerous), "'" + dangerous, repr(dangerous))
        for safe in ("plain", "a=b", "1+1", " =leading space", "'quoted", "한글", "", "x-y", "#hash", "\nnewline-first"):
            self.assertEqual(csvio.safe_cell(safe), safe, repr(safe))
        self.assertEqual((csvio.safe_cell(None), csvio.safe_cell(True), csvio.safe_cell(False)), ("", "Y", "N"))
        self.assertEqual((csvio.safe_cell(5), csvio.safe_cell(12.5), csvio.safe_cell(100.0)), ("5", "12.5", "100"))

    def test_build_csv_has_bom_crlf_and_quotes(self):
        data = csvio.build_csv(["a", "b"], [["x,y", 'say "hi"'], ["=evil", "줄1\n줄2"]])
        self.assertTrue(data.startswith(b"\xef\xbb\xbf"))
        text = data.decode("utf-8-sig")
        parsed = list(csv.reader(io.StringIO(text, newline="")))
        self.assertEqual(parsed, [["a", "b"], ["x,y", 'say "hi"'], ["'=evil", "줄1\n줄2"]])
        self.assertIn("\r\n", text)

    def test_parse_csv_text(self):
        self.assertEqual(csvio.parse_csv_text("﻿a,b\r\n\r\n1,2\n   ,  \n"), [["a", "b"], ["1", "2"]])
        self.assertEqual(csvio.parse_csv_text('a,"b\nc"\n'), [["a", "b\nc"]])
        with self.assertRaises(csv.Error):
            csvio.parse_csv_text('a,"unterminated\n')


class ExportAccessTests(CsvCase):
    PATHS = ("/servers/export", "/services/export", "/models/export", "/licenses/export", "/acls/export")

    def test_viewer_forbidden_and_get_not_allowed(self):
        self.login(self.viewer)
        for path in self.PATHS:
            self.assertEqual(self.post_form(path).status_code, 403, path)
        self.login(self.editor)
        for path in self.PATHS:
            self.assertIn(self.client.get(path).status_code, (404, 405), path)    # 내보내기는 POST 전용 (GET으로는 받지 않는다)
        self.assertEqual(self.audit_exports(), [])

    def test_csrf_and_unauthenticated(self):
        for path in self.PATHS:
            self.assertEqual(self.post_form(path, csrf_token="bad").status_code, 403, path)
            self.assertEqual(self.post(path, "x=1").status_code, 403, path)
        self.client.cookies.clear()
        for path in self.PATHS:
            self.assertEqual(self.post(path, "x=1").status_code, 303, path)

    def test_buttons_visibility(self):
        for page, action in (("/servers", "/servers/export"), ("/services", "/services/export"), ("/models", "/models/export"),
                             ("/licenses", "/licenses/export"), ("/acls", "/acls/export")):
            self.assertIn(f'action="{action}"', self.client.get(page).text, page)
        self.login(self.viewer)
        for page in ("/servers", "/services", "/models", "/licenses", "/acls"):
            self.assertNotIn("CSV 내보내기", self.client.get(page).text, page)

    def test_button_carries_current_filters(self):
        html = self.client.get("/servers?environment=dev&q=web").text
        self.assertRegex(html, r'action="/servers/export\?(environment=dev&amp;q=web|q=web&amp;environment=dev)"')

    def test_response_headers(self):
        self.server(self.editor, hostname="h1")
        r = self.export("/servers/export")
        self.assertTrue(r.headers["content-type"].startswith("text/csv"))
        self.assertRegex(r.headers["content-disposition"], r'^attachment; filename="servers-\d{8}\.csv"$')
        self.assertTrue(r.content.startswith(b"\xef\xbb\xbf"))
        self.assertEqual(r.headers["cache-control"], "no-store")
        self.assertEqual(r.headers["x-content-type-options"], "nosniff")
        for path, prefix in (("/services/export", "services"), ("/models/export", "models"), ("/licenses/export", "licenses"),
                             ("/acls/export", "acls")):
            r = self.export(path)
            self.assertRegex(r.headers["content-disposition"], rf'^attachment; filename="{prefix}-\d{{8}}\.csv"$')
            self.assertTrue(r.content.startswith(b"\xef\xbb\xbf"))
            self.assertTrue(r.headers["content-disposition"].isascii())

    def test_invalid_filter_is_400(self):
        for path, qs in (("/servers/export", "os_type=Mac"), ("/services/export", "tier=9"), ("/models/export", "sort=id"),
                         ("/licenses/export", "expiry=x"), ("/acls/export", "status=x")):
            self.export(path, qs, expect=400)
        self.assertEqual(self.audit_exports(), [])


class ServerExportTests(CsvCase):
    def test_columns_ips_disk_usage_tags_owner_gpu(self):
        sid = self.create_server(owner_id=str(self.editor2), tags="prod, 결제")
        self.conn.execute("INSERT INTO server_ips (server_id, ip, kind, is_primary) VALUES (?, '10.0.0.2', '사설', 0)", (sid,))
        self.conn.execute("INSERT INTO server_ips (server_id, ip, kind, is_primary) VALUES (?, '10.0.0.1', '사설', 1)", (sid,))
        for mount, used in (("/", 10), ("/data", 95)):
            self.conn.execute("INSERT INTO server_disks (server_id, mount_point, disk_type, total_gb, used_gb) VALUES (?, ?, 'SSD', 100, ?)",
                              (sid, mount, used))
        self.conn.execute("INSERT INTO server_gpus (server_id, gpu_model, quantity) VALUES (?, 'A100 80GB', 8)", (sid,))
        header, rows = self.table(self.export("/servers/export"))
        self.assertEqual(header[:17], server_import.HEADER)                     # 일괄 등록 헤더와 앞 17개 컬럼이 같다
        for extra in ("ips", "max_disk_usage_pct", "gpu_summary"):
            self.assertIn(extra, header)
        row = rows[0]
        self.assertEqual(row["ips"], "10.0.0.1;10.0.0.2")                       # IP를 ;로 합침 (대표 IP 먼저)
        self.assertEqual(row["primary_ip"], "10.0.0.1")
        self.assertEqual(row["max_disk_usage_pct"], "95")
        self.assertEqual(row["tags"], "prod;결제")
        self.assertEqual(row["owner_username"], "ed2")
        self.assertEqual(row["gpu_summary"], "A100 80GB x8")
        self.assertEqual((row["name"], row["hostname"], row["cpu_cores"]), ("웹 서버 1", "web-01", "16"))
        self.assertEqual(row["last_verified_at"], "")

    def create_server(self, **kw):
        r = self.post_form("/servers/new", **server_data(**kw))
        self.assertEqual(r.status_code, 303, r.text[-500:])
        return int(r.headers["location"].rsplit("/", 1)[1])

    def test_formula_injection_escaped_in_every_text_cell(self):
        dangerous = {"name": "=cmd|' /C calc'!A0", "location": "+SUM(1)", "cpu_model": "-2+3", "description": "@HYPERLINK(\"x\")",
                     "os_distro": "=Ubuntu"}
        self.create_server(**dangerous)
        header, rows = self.table(self.export("/servers/export"))
        row = rows[0]
        self.assertEqual(row["name"], "'=cmd|' /C calc'!A0")
        self.assertEqual(row["location"], "'+SUM(1)")
        self.assertEqual(row["cpu_model"], "'-2+3")
        self.assertEqual(row["description"], "'@HYPERLINK(\"x\")")
        self.assertEqual(row["os_distro"], "'=Ubuntu")
        self.assertEqual(row["hostname"], "web-01")                              # 안전한 값은 그대로
        for value in row.values():
            self.assertFalse(value.startswith(("=", "+", "-", "@", "\t", "\r")), value)

    def test_tab_and_cr_prefixed_values(self):
        sid = self.create_server()
        self.conn.execute("UPDATE servers SET location=?, cpu_model=? WHERE id=?", ("\t탭으로 시작", "\r캐리지리턴", sid))
        _, rows = self.table(self.export("/servers/export"))
        self.assertEqual(rows[0]["location"], "'\t탭으로 시작")
        self.assertEqual(rows[0]["cpu_model"], "'\r캐리지리턴")

    def test_filters_applied_and_pagination_ignored(self):
        for i in range(45):
            self.create_server(hostname=f"host-{i:02d}", name=f"srv-{i:02d}", environment="dev" if i % 3 == 0 else "prod",
                               tags="batch" if i < 5 else "")
        _, rows = self.table(self.export("/servers/export"))
        self.assertEqual(len(rows), 45)                                          # 20건 단위 페이지네이션과 무관하게 전체
        _, rows = self.table(self.export("/servers/export", "page=2"))
        self.assertEqual(len(rows), 45)
        _, rows = self.table(self.export("/servers/export", "environment=dev"))
        self.assertEqual(len(rows), 15)
        self.assertTrue(all(r["environment"] == "dev" for r in rows))
        _, rows = self.table(self.export("/servers/export", "tag=batch"))
        self.assertEqual(len(rows), 5)
        _, rows = self.table(self.export("/servers/export", urlencode({"q": "host-04"})))
        self.assertEqual([r["hostname"] for r in rows], ["host-04"])
        _, rows = self.table(self.export("/servers/export", "stale=on&environment=prod&sort=name"))
        self.assertEqual(len(rows), 30)
        self.assertEqual(rows[0]["name"], "srv-01")
        _, rows = self.table(self.export("/servers/export", urlencode({"q": "nothing-matches"})))
        self.assertEqual(rows, [])

    def test_export_is_audited_with_target_and_count(self):
        self.create_server()
        self.export("/servers/export", "environment=prod")
        audit = self.audit_exports()[0]
        self.assertEqual((audit["target_type"], audit["user_id"]), ("server", self.editor))
        self.assertIn("rows=1", audit["summary"])
        self.assertIn("environment=prod", audit["summary"])

    def test_mine_filter_uses_current_user(self):
        self.create_server(hostname="mine", owner_id=str(self.editor))
        self.create_server(hostname="theirs", owner_id=str(self.editor2))
        _, rows = self.table(self.export("/servers/export", "mine=on"))
        self.assertEqual([r["hostname"] for r in rows], ["mine"])


class OtherExportTests(CsvCase):
    def test_services_export(self):
        r = self.post_form("/services/new", **svc_data(tags="pay, core", primary_owner_id=str(self.editor),
                                                       urls="https://pay.example.com\nlegacy.example.com"))
        sid = int(r.headers["location"].rsplit("/", 1)[1])
        srv = self.server(self.editor, hostname="s1")
        self.conn.execute("INSERT INTO service_servers VALUES (?, ?, 'WEB', '')", (sid, srv))
        header, rows = self.table(self.export("/services/export"))
        row = rows[0]
        self.assertEqual((row["code"], row["tier"], row["server_count"], row["tags"], row["primary_owner"]),
                         ("PAY-API", "1", "1", "core;pay", "ed"))
        self.assertEqual(row["urls"], "https://pay.example.com;legacy.example.com")
        _, none = self.table(self.export("/services/export", "tier=3"))
        self.assertEqual(none, [])
        self.assertEqual(self.audit_exports()[-1]["target_type"], "service")

    def test_models_export_with_risk(self):
        self.post_form("/models/new", **mdl_data(name="risky", version="1", commercial_use="불가", status="운영", tags="llm"))
        self.post_form("/models/new", **mdl_data(name="cond", version="1", commercial_use="조건부"))
        self.post_form("/models/new", **mdl_data(name="fine", version="1", commercial_use="가능"))
        _, rows = self.table(self.export("/models/export"))
        by_name = {r["name"]: r for r in rows}
        self.assertEqual(by_name["risky"]["license_risk"], "라이선스 위험")
        self.assertEqual(by_name["cond"]["license_risk"], "조건 확인")
        self.assertEqual(by_name["fine"]["license_risk"], "")
        self.assertEqual(by_name["risky"]["tags"], "llm")
        _, rows = self.table(self.export("/models/export", "risk=on"))
        self.assertEqual([r["name"] for r in rows], ["risky"])

    def test_licenses_export_never_contains_sensitive_data(self):
        self.post_form("/licenses/new", **lic_data(name="secret-lic", license_key=KEY, account_info=ACCOUNT, tags="x"))
        self.post_form("/licenses/new", **ssl_data(name="cert", ssl_san="a.example.com\nb.example.com"))
        self.post_form("/licenses/new", **ai_data(name="ai-lic"))
        response = self.export("/licenses/export")
        raw = response.content.decode("utf-8-sig")
        for secret in (KEY, ACCOUNT, "Secret!", "LIC-KEY", "WXYZ", "P@ssw0rd"):
            self.assertNotIn(secret, raw, secret)
        header, rows = self.table(response)
        for column in header:
            self.assertFalse(column.endswith("_enc"), column)
            self.assertNotIn(column, ("license_key", "account_info"))
        by_name = {r["name"]: r for r in rows}
        self.assertEqual(by_name["cert"]["ssl_san"], "a.example.com;b.example.com")
        self.assertEqual(by_name["ai-lic"]["ai_provider"], "OpenAI")
        self.assertEqual(by_name["ai-lic"]["ai_models"], "gpt-4.1;gpt-4.1-mini")
        self.assertEqual(by_name["secret-lic"]["expiry_state"], "유효")
        self.assertEqual(by_name["secret-lic"]["tags"], "x")
        _, rows = self.table(self.export("/licenses/export", "license_type=AI API"))
        self.assertEqual([r["name"] for r in rows], ["ai-lic"])
        _, rows = self.table(self.export("/licenses/export", urlencode({"q": "WXYZ"})))      # 민감 값으로는 필터되지 않는다
        self.assertEqual(rows, [])

    def test_license_export_formula_escape(self):
        self.post_form("/licenses/new", **lic_data(name="=HYPERLINK(\"http://evil\")", vendor="@vendor"))
        _, rows = self.table(self.export("/licenses/export"))
        self.assertEqual(rows[0]["name"], "'=HYPERLINK(\"http://evil\")")
        self.assertEqual(rows[0]["vendor"], "'@vendor")


class ACLListTests(CsvCase):
    def setUp(self):
        super().setUp()
        self.a = self.server(self.editor, hostname="acl-a", name="ACL-A")
        self.b = self.server(self.editor, hostname="acl-b", name="ACL-B")
        for sid, src, status, port, purpose in ((self.a, "10.0.0.0/24", "요청", "443", "결제 연동"),
                                                 (self.a, "10.1.0.0/24", "적용완료", "8000", "=위험한 목적"),
                                                 (self.b, "192.168.0.0/16", "회수", "22", "점검")):
            self.conn.execute(
                "INSERT INTO server_acls (server_id, direction, src_cidr, dst_cidr, port_start, port_end, protocol, purpose, requester, "
                "requested_at, status, ticket_no) VALUES (?, 'Inbound', ?, '10.9.9.9/32', ?, ?, 'TCP', ?, 'r', '2026-01-01', ?, 'REQ-1')",
                (sid, src, int(port), int(port) + (10 if port == "8000" else 0), purpose, status))

    def test_all_servers_list_filters_and_viewer_access(self):
        self.login(self.viewer)
        html = self.client.get("/acls").text
        self.assertIn("ACL-A", html)
        self.assertIn("ACL-B", html)
        self.assertIn("8000-8010/TCP", html)
        self.assertIn("총 3건", html)
        self.assertIn("총 1건", self.client.get("/acls?status=요청").text)
        self.assertIn("총 2건", self.client.get("/acls?" + urlencode({"q": "acl-a"})).text)
        self.assertIn("총 1건", self.client.get("/acls?q=192.168").text)
        self.assertIn("조회 조건이 올바르지 않습니다", self.client.get("/acls?status=x").text)
        self.assertIn("조회 조건이 올바르지 않습니다", self.client.get("/acls?evil=1").text)
        self.assertEqual(self.client.get("/acls?q=%25").text.count("총 0건"), 1)

    def test_export(self):
        header, rows = self.table(self.export("/acls/export"))
        self.assertEqual(len(rows), 3)
        by = {r["purpose"]: r for r in rows}
        self.assertEqual(by["결제 연동"]["port"], "443")
        self.assertEqual(by["'=위험한 목적"]["port"], "8000-8010")             # 수식 시작 문자는 이스케이프
        self.assertEqual(by["결제 연동"]["server_name"], "ACL-A")
        _, rows = self.table(self.export("/acls/export", "status=회수"))
        self.assertEqual([r["hostname"] for r in rows], ["acl-b"])
        self.assertEqual(self.audit_exports()[-1]["target_type"], "acl")


# ---------------------------------------------------------------------------- 일괄 등록

HEADER_LINE = ",".join(server_import.HEADER)


def csv_text(*rows, header=HEADER_LINE):
    return "\n".join([header, *rows]) + "\n"


def row(name="웹", hostname="web-01", os_type="Linux", distro="Ubuntu", version="22.04", kernel="5.15", env="prod",
        status="운영중", stype="VM", location="IDC-A", cpu="Xeon", cores="16", mem="64", ip="10.0.0.1", owner="ed2",
        tags="a;b", desc="설명"):
    return ",".join([name, hostname, os_type, distro, version, kernel, env, status, stype, location, cpu, cores, mem, ip,
                     owner, tags, desc])


class ImportCase(CsvCase):
    def preview(self, text, expect=200):
        r = self.post_form("/servers/import/preview", csv=text)
        self.assertEqual(r.status_code, expect, r.text[-400:])
        return r

    def commit(self, text, expect=303):
        r = self.post_form("/servers/import/commit", csv=text)
        self.assertEqual(r.status_code, expect, r.text[-400:])
        return r

    def count(self):
        return self.conn.execute("SELECT COUNT(*) FROM servers").fetchone()[0]


class ImportAccessTests(ImportCase):
    def test_viewer_forbidden_everywhere(self):
        self.login(self.viewer)
        self.assertEqual(self.client.get("/servers/import").status_code, 403)
        self.assertEqual(self.post_form("/servers/import/preview", csv=csv_text(row())).status_code, 403)
        self.assertEqual(self.post_form("/servers/import/commit", csv=csv_text(row())).status_code, 403)
        self.assertEqual(self.count(), 0)
        self.assertNotIn("CSV 일괄 등록", self.client.get("/servers").text)

    def test_csrf_unauth_content_type_and_size(self):
        for path in ("/servers/import/preview", "/servers/import/commit"):
            self.assertEqual(self.post_form(path, csrf_token="bad", csv=csv_text(row())).status_code, 403, path)
            r = self.client.post(path, json={"csv": "x"})
            self.assertEqual(r.status_code, 415, path)
            big = "csv=" + "a" * (config.MAX_BODY_BYTES + 1)
            self.assertEqual(self.post(path, big).status_code, 413, path)
        self.assertEqual(self.client.get("/servers/import/commit").status_code, 405)
        self.client.cookies.clear()
        self.assertEqual(self.client.get("/servers/import").status_code, 303)
        self.assertEqual(self.post("/servers/import/commit", "csv=x").status_code, 303)

    def test_form_page_shows_header_and_examples(self):
        html = self.client.get("/servers/import").text
        self.assertIn(HEADER_LINE, html)
        self.assertIn("pay-web-01", html)
        self.assertIn("gpu-train-01", html)
        self.assertIn("최대 1000행", html)


class ImportPreviewTests(ImportCase):
    def test_valid_preview_saves_nothing(self):
        text = csv_text(row(), row(name="웹2", hostname="web-02", ip="8.8.8.8"))
        r = self.preview(text)
        self.assertEqual(r.text.count("badge-green\">성공"), 2)
        self.assertEqual(r.text.count("badge-red\">오류"), 0)
        self.assertIn("전체 2행, 오류 0행", r.text)
        self.assertIn("등록 확정 (2건)", r.text)
        self.assertEqual(self.count(), 0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM asset_tags").fetchone()[0], 0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM audit_logs WHERE action LIKE 'server_%'").fetchone()[0], 0)

    def test_per_row_error_reasons(self):
        self.server(self.editor, hostname="Existing-Host")
        self.conn.execute("UPDATE users SET is_active=0 WHERE username='vw'")
        text = csv_text(
            row(hostname="ok-1"),                                                   # 1: 정상
            row(hostname="EXISTING-host"),                                          # 2: DB 중복(대소문자 무시)
            row(hostname="dup-in-csv"), row(hostname="DUP-IN-CSV"),                 # 3,4: CSV 내부 중복
            row(hostname="bad-env", env="production"),                              # 5
            row(hostname="bad-ip", ip="999.1.1.1"),                                 # 6
            row(hostname="bad-owner", owner="nobody"),                              # 7
            row(hostname="inactive-owner", owner="vw"),                             # 8
            "only,three,columns",                                                   # 9
            row(hostname="bad-tags", tags="has space;ok"),                          # 10
            row(hostname="mismatch", os_type="Windows", distro="Ubuntu"),           # 11
            row(hostname="bad cores!", cores="abc"),                                # 12
            row(name="", hostname="no-name"),                                       # 13
        )
        r = self.preview(text)
        html = r.text
        self.assertIn("전체 13행, 오류 12행", html)
        for fragment in ("hostname: 이미 등록된 호스트명입니다.", "CSV 안에서 중복된 호스트명입니다 (행 3, 4)",
                         "environment: 허용되지 않는 값입니다.", "primary_ip: 올바른 IPv4/IPv6 주소가 아닙니다.",
                         "owner_username: 존재하지 않는 사용자입니다.", "owner_username: 비활성 사용자입니다.",
                         "컬럼 수가 17개여야 합니다 (현재 3개).", "tags: 태그에는 한글, 영문, 숫자",
                         "OS 종류와 배포판이 일치하지 않습니다.", "cpu_cores: 숫자를 입력하세요.", "name: 필수 항목입니다."):
            self.assertIn(fragment, html, fragment)
        self.assertNotIn('action="/servers/import/commit"', html)                    # 오류가 있으면 확정 폼이 없다
        self.assertEqual(html.count("badge-green\">성공"), 1)
        self.assertEqual(self.count(), 1)

    def test_file_level_errors(self):
        cases = {
            "": "CSV가 비어 있습니다",
            "   \n\n": "CSV가 비어 있습니다",
            HEADER_LINE + "\n": "등록할 행이 없습니다",
            "name,hostname\nx,y\n": "첫 줄은 정해진 헤더여야 합니다",
            ",".join(reversed(server_import.HEADER)) + "\n" + row() + "\n": "첫 줄은 정해진 헤더여야 합니다",
            HEADER_LINE.upper() + "\n" + row() + "\n": "첫 줄은 정해진 헤더여야 합니다",
            HEADER_LINE + ",extra\n" + row() + "\n": "첫 줄은 정해진 헤더여야 합니다",
            row() + "\n": "첫 줄은 정해진 헤더여야 합니다",
            HEADER_LINE + '\n"unterminated,field\n': "CSV 형식이 올바르지 않습니다",
        }
        for text, message in cases.items():
            r = self.preview(text)
            self.assertIn(message, r.text, repr(text[:40]))
            self.assertNotIn('action="/servers/import/commit"', r.text)
        r = self.post_form("/servers/import/preview", csv=csv_text(row()), extra="1")
        self.assertIn("CSV를 붙여 넣으세요", r.text)

    def test_row_limit_1000(self):
        self.assertIn("한 번에 최대 1000행", self.preview(csv_text(*[row(hostname=f"h{i:04d}") for i in range(1001)])).text)
        ok = self.preview(csv_text(*[row(hostname=f"h{i:04d}", ip="") for i in range(1000)]))
        self.assertIn("전체 1000행, 오류 0행", ok.text)
        self.assertIn("등록 확정 (1000건)", ok.text)

    def test_parsing_details(self):
        text = "﻿" + HEADER_LINE + "\r\n\r\n" + row(name='"따옴표, 포함"', hostname=" spaced-host ", desc='"줄1\n줄2, 쉼표"') + "\r\n\r\n"
        r = self.preview(text)
        self.assertIn("전체 1행, 오류 0행", r.text)
        self.commit(text)
        server = self.conn.execute("SELECT * FROM servers").fetchone()
        self.assertEqual((server["name"], server["hostname"], server["description"]), ("따옴표, 포함", "spaced-host", "줄1\n줄2, 쉼표"))

    def test_preview_escapes_values(self):
        r = self.preview(csv_text(row(name="<script>alert(1)</script>", hostname="xss-1", owner="<b>x</b>")))
        self.assertNotIn("<script>alert(1)</script>", r.text)
        self.assertNotIn("<b>x</b>", r.text)
        self.assertIn("&lt;script&gt;", r.text)


class ImportCommitTests(ImportCase):
    def test_commit_registers_everything(self):
        text = csv_text(row(hostname="pay-web-01", owner="ed2", ip="10.0.1.11", tags="Payment;prod"),
                        row(name="GPU", hostname="gpu-01", owner="", ip="8.8.4.4", tags=""),
                        row(name="no ip", hostname="no-ip", ip="", owner="ED"))
        r = self.commit(text)
        self.assertEqual((r.headers["location"]), "/servers")
        servers = {s["hostname"]: s for s in self.conn.execute("SELECT * FROM servers")}
        self.assertEqual(set(servers), {"pay-web-01", "gpu-01", "no-ip"})
        pay = servers["pay-web-01"]
        self.assertEqual((pay["owner_id"], pay["created_by"], pay["updated_by"], pay["cpu_cores"], pay["memory_gb"]),
                         (self.editor2, self.editor, self.editor, 16, 64))
        self.assertIsNone(pay["last_verified_at"])
        self.assertIsNone(servers["gpu-01"]["owner_id"])
        self.assertEqual(servers["no-ip"]["owner_id"], self.editor)                  # 사용자명은 대소문자 무시
        self.assertEqual(assets.get_tags(self.conn, "server", pay["id"]), ["payment", "prod"])
        ips = {r["server_id"]: (r["ip"], r["kind"], r["is_primary"]) for r in self.conn.execute("SELECT * FROM server_ips")}
        self.assertEqual(ips[pay["id"]], ("10.0.1.11", "사설", 1))
        self.assertEqual(ips[servers["gpu-01"]["id"]], ("8.8.4.4", "공인", 1))
        self.assertNotIn(servers["no-ip"]["id"], ips)
        audits = self.conn.execute("SELECT * FROM audit_logs WHERE action='server_bulk_import'").fetchall()
        self.assertEqual(len(audits), 1)                                              # 결과를 1건으로 기록
        self.assertEqual((audits[0]["summary"], audits[0]["target_type"], audits[0]["user_id"]), ("count=3", "server", self.editor))
        self.assertIsNone(self.conn.execute("SELECT 1 FROM audit_logs WHERE action='server_create'").fetchone())
        self.assertIn("서버 3대를 일괄 등록했습니다", self.client.get("/servers").text)
        self.assertEqual(len(self.client.get("/servers").text.split("<tbody>")[1].split("<tr>")) - 1, 3)

    def test_any_error_rejects_everything(self):
        text = csv_text(row(hostname="valid-1"), row(hostname="valid-2"), row(hostname="bad-1", env="nope"))
        r = self.commit(text, 422)
        self.assertIn("오류가 있는 행이 있어 등록할 수 없습니다", r.text)
        self.assertIn("아무것도 저장되지 않았습니다", r.text)
        self.assertEqual(self.count(), 0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM asset_tags").fetchone()[0], 0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM server_ips").fetchone()[0], 0)
        self.assertIsNone(self.conn.execute("SELECT 1 FROM audit_logs WHERE action='server_bulk_import'").fetchone())

    def test_tampered_csv_is_revalidated_from_scratch(self):
        good = csv_text(row(hostname="valid-1"), row(hostname="valid-2"))
        self.assertIn("등록 확정", self.preview(good).text)                             # 미리보기는 통과
        tampered = good.replace("valid-2", "bad host!").replace("Linux", "Solaris", 1)  # 확정 단계에서 CSV를 조작
        self.commit(tampered, 422)
        self.assertEqual(self.count(), 0)
        no_header = row(hostname="valid-1") + "\n"
        self.commit(no_header, 422)
        self.assertEqual(self.count(), 0)

    def test_state_change_between_preview_and_commit_is_caught(self):
        text = csv_text(row(hostname="race-1"))
        self.assertIn("등록 확정", self.preview(text).text)
        self.server(self.editor, hostname="race-1")                                     # 그 사이 같은 호스트명이 등록됨
        self.commit(text, 422)
        self.assertEqual(self.count(), 1)

    def test_duplicate_hostname_rejected_on_commit(self):
        self.commit(csv_text(row(hostname="dup"), row(hostname="DUP")), 422)
        self.assertEqual(self.count(), 0)
        self.server(self.editor, hostname="taken")
        self.commit(csv_text(row(hostname="free-1"), row(hostname="TAKEN")), 422)
        self.assertEqual(self.count(), 1)

    def test_commit_does_not_trust_preview_fields(self):
        r = self.post_form("/servers/import/commit", csv=csv_text(row(hostname="x1")), created_by="1", rows="1", ok="true")
        self.assertEqual(r.status_code, 422)                                            # 알 수 없는 필드는 거부
        self.assertEqual(self.count(), 0)

    def test_empty_commit_rejected(self):
        self.commit("", 422)
        self.commit(HEADER_LINE + "\n", 422)
        self.assertEqual(self.count(), 0)

    def test_atomic_rollback_when_database_fails_midway(self):
        calls = {"n": 0}
        real = assets.set_tags

        def flaky(conn, asset_type, asset_id, tags):
            calls["n"] += 1
            if calls["n"] == 3:
                raise RuntimeError("boom")
            return real(conn, asset_type, asset_id, tags)

        with mock.patch.object(assets, "set_tags", flaky):
            r = self.commit(csv_text(row(hostname="a1"), row(hostname="a2"), row(hostname="a3"), row(hostname="a4")), 500)
        self.assertEqual(self.count(), 0)                                                # 전부 롤백
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM server_ips").fetchone()[0], 0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM tags").fetchone()[0], 0)
        self.assertIsNone(self.conn.execute("SELECT 1 FROM audit_logs WHERE action='server_bulk_import'").fetchone())
        self.assertFalse(self.conn.in_transaction)
        self.commit(csv_text(row(hostname="a1"), row(hostname="a2")))                    # 이후 정상 동작
        self.assertEqual(self.count(), 2)

    def test_one_thousand_rows_commit(self):
        self.commit(csv_text(*[row(hostname=f"bulk-{i:04d}", ip="", tags="bulk") for i in range(1000)]))
        self.assertEqual(self.count(), 1000)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM audit_logs WHERE action='server_bulk_import'").fetchone()[0], 1)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM tags").fetchone()[0], 1)
        self.commit(csv_text(*[row(hostname=f"over-{i:04d}") for i in range(1001)]), 422)
        self.assertEqual(self.count(), 1000)

    def test_formula_values_are_stored_as_is_and_escaped_on_export(self):
        self.commit(csv_text(row(name="=1+1", hostname="formula-1", location="@cmd", desc="-5")))
        server = self.conn.execute("SELECT name, location FROM servers").fetchone()
        self.assertEqual((server["name"], server["location"]), ("=1+1", "@cmd"))
        _, rows = self.table(self.export("/servers/export"))
        self.assertEqual((rows[0]["name"], rows[0]["location"], rows[0]["description"]), ("'=1+1", "'@cmd", "'-5"))

    def test_imported_server_is_a_normal_server(self):
        self.commit(csv_text(row(hostname="normal-1")))
        sid = self.conn.execute("SELECT id FROM servers").fetchone()[0]
        self.assertEqual(self.client.get(f"/servers/{sid}").status_code, 200)
        self.assertIn("확인 필요", self.client.get(f"/servers/{sid}").text)             # 일괄 등록은 확인 처리가 아니다
        self.assertEqual(self.post_form(f"/servers/{sid}/edit", **server_data(hostname="normal-1", name="수정됨")).status_code, 303)
