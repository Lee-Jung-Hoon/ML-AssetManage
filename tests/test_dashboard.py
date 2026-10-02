import csv
import io
import re

from app import assets
from tests.test_licenses import rel
from tests.test_servers import ServerCase
from tests.test_models import mdl_data
from tests.test_licenses import ai_data, lic_data


def section(html, key):
    m = re.search(rf'<section[^>]* id="{key}"[^>]*>(.*?)</section>', html, re.S)
    return m.group(1) if m else ""


def count_rows(html):
    return {label.strip(): int(n) for label, n in re.findall(r'<td>([^<]+)</td><td class="num">(\d+)</td>', html)}


def cards(html):
    return {label.strip(): int(n) for n, label in re.findall(
        r'<div class="card-num">(\d+)</div>\s*<div class="card-label">(?:<a [^>]*>)?([^<]+)', html)}


def text(html):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()


class DashCase(ServerCase):
    def page(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        return r.text

    def disk(self, server_id, mount, used, total=100):
        self.conn.execute("INSERT INTO server_disks (server_id, mount_point, disk_type, total_gb, used_gb) VALUES (?, ?, 'SSD', ?, ?)",
                          (server_id, mount, total, used))

    def gpu(self, server_id, model, qty=1, vram=80, driver="", cuda="", assigned="팀"):
        self.conn.execute("INSERT INTO server_gpus (server_id, gpu_model, quantity, vram_gb, driver_version, cuda_version, assigned_to) "
                          "VALUES (?, ?, ?, ?, ?, ?, ?)", (server_id, model, qty, vram, driver, cuda, assigned))

    def verified(self, table, rid, when="2099-01-01T00:00:00Z"):
        self.conn.execute(f"UPDATE {table} SET last_verified_at=? WHERE id=?", (when, rid))


class BasicTests(DashCase):
    def test_empty_dashboard_renders_for_every_role(self):
        for uid in (self.editor, self.viewer, self.admin):
            self.login(uid)
            html = self.page()
            self.assertNotIn('id="alerts"', html)                          # 긴급 알림은 해당 항목이 있을 때만
            for key in ("summary", "mine", "servers", "disks", "services", "gpus", "models", "ai-api", "licenses", "stale", "recent"):
                self.assertIn(f'id="{key}"', html, key)
            self.assertNotIn("style=", html)
            self.assertNotIn("<script", html)
            self.assertEqual(self.client.get("/").headers["cache-control"], "no-store")

    def test_section_order_matches_spec(self):
        self.server(self.editor, hostname="s1")
        self.license(self.editor, license_type="AI API", ai_provider="X", ai_sends_customer_data="예", ai_training_opt_out="미설정")
        html = self.page()
        keys = ["alerts", "summary", "mine", "servers", "disks", "services", "gpus", "models", "ai-api", "licenses", "stale", "recent"]
        positions = [html.index(f'id="{k}"') for k in keys]
        self.assertEqual(positions, sorted(positions))

    def test_unauthenticated_redirects(self):
        self.client.cookies.clear()
        self.assertEqual(self.client.get("/").status_code, 303)

    def test_summary_cards(self):
        a = self.server(self.editor, hostname="a")
        b = self.server(self.editor, hostname="b", status="폐기")
        self.service(self.editor, code="S-1")
        self.model(self.editor)
        self.license(self.editor)
        self.gpu(a, "A100", 8)
        self.gpu(b, "A100", 4)                                             # 폐기 서버의 GPU는 제외
        for status in ("요청", "승인", "적용완료", "반려", "회수"):
            self.conn.execute(
                "INSERT INTO server_acls (server_id, direction, src_cidr, dst_cidr, port_start, port_end, protocol, purpose, "
                "requester, requested_at, status) VALUES (?, 'Inbound', '10.0.0.0/8', '1.1.1.1/32', 80, 80, 'TCP', 'p', 'r', '2026-01-01', ?)", (a, status))
        self.assertEqual(cards(self.page()), {"서버": 2, "서비스": 1, "AI 모델": 1, "라이선스": 1, "총 GPU 장수": 8,
                                              "처리 대기 ACL": 2, "확인 필요 자산": 4})   # 폐기 서버는 제외, 나머지 4종은 미확인

    def test_stale_count_excludes_decommissioned_and_clears_after_verify(self):
        s = self.server(self.editor, hostname="a")
        self.server(self.editor, hostname="b", status="폐기")
        sv = self.service(self.editor, code="S-1")
        self.service(self.editor, code="S-2", status="종료")
        m = self.model(self.editor)
        self.model(self.editor, version="2", status="폐기")
        l = self.license(self.editor)
        self.assertEqual(cards(self.page())["확인 필요 자산"], 4)
        for table, rid in (("servers", s), ("services", sv), ("models", m), ("licenses", l)):
            self.verified(table, rid)
        self.assertEqual(cards(self.page())["확인 필요 자산"], 0)


class UrgentAlertTests(DashCase):
    def alerts(self):
        return section(self.page(), "alerts")

    def test_tier1_license_expiry_alert(self):
        t1 = self.service(self.editor, code="T1-A", name="핵심 서비스", tier=1)
        t2 = self.service(self.editor, code="T2-A", name="중요 서비스", tier=2)
        cases = {"expired": rel(-5), "soon": rel(30), "later": rel(31), "today": rel(0)}
        for name, exp in cases.items():
            lic = self.license(self.editor, name=f"L-{name}", expires_at=exp)
            self.conn.execute("INSERT INTO license_services VALUES (?, ?)", (lic, t1))
            other = self.license(self.editor, name=f"T2-{name}", expires_at=exp)
            self.conn.execute("INSERT INTO license_services VALUES (?, ?)", (other, t2))
        forever = self.license(self.editor, name="L-forever", no_expiry=1, expires_at=None)
        self.conn.execute("INSERT INTO license_services VALUES (?, ?)", (forever, t1))
        unlinked = self.license(self.editor, name="L-unlinked", expires_at=rel(-1))
        html = self.alerts()
        for name in ("L-expired", "L-soon", "L-today"):
            self.assertIn(name, html, name)
        for name in ("L-later", "L-forever", "L-unlinked", "T2-expired", "T2-soon"):
            self.assertNotIn(name, html, name)
        self.assertIn("(3건)", html)
        self.assertIn("핵심 서비스", html)
        self.assertIn("만료됨", html)
        self.assertLess(html.index("L-expired"), html.index("L-today"))
        self.assertLess(html.index("L-today"), html.index("L-soon"))          # 만료 임박순

    def test_tier1_alert_ignores_terminated_services(self):
        dead = self.service(self.editor, code="DEAD", tier=1, status="종료")
        lic = self.license(self.editor, name="dead-lic", expires_at=rel(-3))
        self.conn.execute("INSERT INTO license_services VALUES (?, ?)", (lic, dead))
        self.assertNotIn('id="alerts"', self.page())

    def test_disk_alert_threshold_and_exclusions(self):
        a = self.server(self.editor, hostname="a", name="서버A")
        gone = self.server(self.editor, hostname="g", name="폐기서버", status="폐기")
        self.disk(a, "/danger", 90)
        self.disk(a, "/edge", 89.9)
        self.disk(a, "/warn", 80)
        self.disk(gone, "/gone", 99)
        html = self.alerts()
        self.assertIn("/danger", html)
        for absent in ("/edge", "/warn", "/gone"):
            self.assertNotIn(absent, html, absent)
        self.assertIn("(1건)", html)
        self.assertIn("서버A", html)

    def test_model_license_risk_alert(self):
        prod = self.service(self.editor, code="P-1", environment="prod", status="운영중")
        risky = self.model(self.editor, name="risky-op", commercial_use="불가", status="운영")
        unknown_linked = self.model(self.editor, name="unknown-linked", version="2", commercial_use="미확인", status="실험")
        self.conn.execute("INSERT INTO model_services (model_id, service_id) VALUES (?, ?)", (unknown_linked, prod))
        self.model(self.editor, name="fine", version="3", commercial_use="가능", status="운영")
        self.model(self.editor, name="cond", version="4", commercial_use="조건부", status="운영")
        self.model(self.editor, name="exp", version="5", commercial_use="불가", status="실험")
        html = self.alerts()
        self.assertIn("risky-op", html)
        self.assertIn("unknown-linked", html)
        for absent in ("fine", "cond", "exp"):
            self.assertNotIn(f">{absent} ", html, absent)
        self.assertIn("(2건)", html)
        self.assertIn("라이선스 위험", html)

    def test_data_policy_alert(self):
        for name, sends, opt in (("risky-1", "예", "미설정"), ("risky-2", "예", "미확인"), ("ok-1", "예", "설정됨"),
                                 ("ok-2", "아니오", "미설정"), ("ok-3", "미확인", "미확인"), ("ok-4", "예", "해당 없음")):
            self.license(self.editor, name=name, license_type="AI API", ai_provider="OpenAI", ai_sends_customer_data=sends,
                         ai_training_opt_out=opt)
        html = self.alerts()
        self.assertIn("risky-1", html)
        self.assertIn("risky-2", html)
        for absent in ("ok-1", "ok-2", "ok-3", "ok-4"):
            self.assertNotIn(absent, html)
        self.assertIn("(2건)", html)
        self.assertIn("데이터 정책 확인", html)

    def test_each_subsection_appears_only_when_relevant(self):
        self.license(self.editor, name="risky-api", license_type="AI API", ai_provider="X", ai_sends_customer_data="예",
                     ai_training_opt_out="미확인")
        html = self.alerts()
        self.assertIn("데이터 정책 확인 필요 AI API", html)
        for absent in ("Tier 1 서비스에 연결된 라이선스", "디스크", "라이선스 위험 AI 모델"):
            self.assertNotIn(absent, html)


class MineTests(DashCase):
    def test_my_counts_include_secondary_owner_and_stale_list(self):
        self.server(self.editor, hostname="mine-1", name="내 서버", owner_id=self.editor)
        self.server(self.editor, hostname="not-mine", owner_id=self.editor2)
        self.service(self.editor, code="P-SVC", name="정담당", primary_owner_id=self.editor)
        self.service(self.editor, code="S-SVC", name="부담당", primary_owner_id=self.editor2, secondary_owner_id=self.editor)
        self.service(self.editor, code="O-SVC", name="남의서비스", primary_owner_id=self.editor2)
        self.model(self.editor, owner_id=self.editor)
        lic = self.license(self.editor, owner_id=self.editor)
        self.verified("licenses", lic)
        html = section(self.page(), "mine")
        self.assertIn("담당 자산 5개", html.replace("<strong>", "").replace("</strong>", ""))
        self.assertIn("서버 1 · 서비스(정/부) 2 · AI 모델 1 · 라이선스 1", html)
        for name in ("내 서버", "정담당", "부담당"):
            self.assertIn(name, html)
        self.assertNotIn("남의서비스", html)
        self.assertNotIn("not-mine", html)

    def test_mine_stale_excludes_decommissioned(self):
        self.server(self.editor, hostname="gone", name="폐기된내서버", owner_id=self.editor, status="폐기")
        html = section(self.page(), "mine")
        self.assertNotIn("폐기된내서버", html)
        self.assertIn("담당 자산 1개", html.replace("<strong>", "").replace("</strong>", ""))

    def test_other_users_see_their_own(self):
        self.server(self.editor, hostname="a", owner_id=self.editor)
        self.login(self.editor2)
        self.assertIn("담당 자산 0개", section(self.page(), "mine").replace("<strong>", "").replace("</strong>", ""))


class ServerSectionTests(DashCase):
    def test_environment_os_status_counts(self):
        self.server(self.editor, hostname="a", environment="prod", os_distro="Ubuntu")
        self.server(self.editor, hostname="b", environment="prod", os_distro="Ubuntu", status="점검")
        self.server(self.editor, hostname="c", environment="dev", os_distro="Rocky")
        self.server(self.editor, hostname="d", environment="stg", os_type="Windows", os_distro="Windows Server 2022")
        self.server(self.editor, hostname="e", environment="test", os_type="Windows", os_distro="")
        html = section(self.page(), "servers")
        counts = count_rows(html)
        self.assertEqual({k: v for k, v in counts.items() if k in ("prod", "dev", "stg", "test")}, {"prod": 2, "dev": 1, "stg": 1, "test": 1})
        self.assertEqual(counts["Linux / Ubuntu"], 2)
        self.assertEqual(counts["Linux / Rocky"], 1)
        self.assertEqual(counts["Windows / Windows Server 2022"], 1)
        self.assertEqual(counts["Windows (배포판 미기재)"], 1)
        self.assertEqual({k: v for k, v in counts.items() if k in ("운영중", "점검")}, {"운영중": 4, "점검": 1})


class DiskSectionTests(DashCase):
    def test_warning_levels_sorted_and_top_10(self):
        a = self.server(self.editor, hostname="a", name="서버A")
        gone = self.server(self.editor, hostname="g", status="폐기", name="폐기서버")
        for i, pct in enumerate([99, 97, 95, 93, 91, 90, 89, 88, 86, 85, 83, 81, 80, 79, 50]):
            self.disk(a, f"/d{i:02d}", pct)
        self.disk(gone, "/gone", 100)
        html = section(self.page(), "disks")
        rows = re.findall(r'<td>(/d\d\d)</td>', html)
        self.assertEqual(len(rows), 10)                                        # 상위 10개
        self.assertEqual(rows, [f"/d{i:02d}" for i in range(10)])               # 사용률 높은 순
        self.assertNotIn("/gone", html)
        self.assertNotIn("/d10", html)
        self.assertRegex(html, r'badge-red">위험</span>')
        self.assertRegex(html, r'badge-orange">주의</span>')
        self.assertIn("위험 <span class=\"badge badge-red\">6</span>", html.replace("\n", " "))     # 90 이상: 99,97,95,93,91,90
        self.assertIn("주의 <span class=\"badge badge-orange\">7</span>", html.replace("\n", " "))   # 80~89: 89,88,86,85,83,81,80
        self.assertNotIn("style=", html)

    def test_no_warning_message(self):
        a = self.server(self.editor, hostname="a")
        self.disk(a, "/", 10)
        self.assertIn("경고 대상 디스크가 없습니다", section(self.page(), "disks"))


class ServiceSectionTests(DashCase):
    def test_status_tier_counts_and_no_owner_list(self):
        self.service(self.editor, code="A-1", name="정상", status="운영중", tier=1, primary_owner_id=self.editor)
        self.service(self.editor, code="A-2", name="담당자없음", status="운영중", tier=1)
        self.service(self.editor, code="A-3", name="비활성담당", status="개발중", tier=2, primary_owner_id=self.editor2)
        self.service(self.editor, code="A-4", name="부담당살아있음", status="운영중", tier=3, primary_owner_id=self.editor2, secondary_owner_id=self.editor)
        self.service(self.editor, code="A-5", name="종료됨", status="종료", tier=3)
        self.conn.execute("UPDATE users SET is_active=0 WHERE id=?", (self.editor2,))
        html = section(self.page(), "services")
        counts = count_rows(html)
        self.assertEqual({k: counts[k] for k in ("운영중", "개발중", "종료")}, {"운영중": 3, "개발중": 1, "종료": 1})
        self.assertEqual({k: counts[k] for k in ("Tier 1", "Tier 2", "Tier 3")}, {"Tier 1": 2, "Tier 2": 1, "Tier 3": 2})
        listing = html.split("담당자가 없거나 비활성 계정인 서비스")[1]
        self.assertIn("담당자없음", listing)
        self.assertIn("비활성담당", listing)
        for absent in ("정상", "부담당살아있음", "종료됨"):
            self.assertNotIn(absent, listing)
        self.assertIn("(2건)", listing)
        self.assertIn('badge-orange">담당자 없음', listing)
        self.assertIn('badge-orange">비활성 담당자', listing)

    def test_inactive_owner_counted_as_no_owner_for_every_asset_type(self):
        self.conn.execute("UPDATE users SET is_active=0 WHERE id=?", (self.editor2,))
        self.server(self.editor, hostname="a", owner_id=self.editor2)
        self.server(self.editor, hostname="b", owner_id=self.editor2, status="폐기")          # 폐기는 제외
        self.server(self.editor, hostname="c", owner_id=None)
        self.server(self.editor, hostname="d", owner_id=self.editor)
        self.model(self.editor, owner_id=self.editor2)
        self.license(self.editor, owner_id=self.editor2)
        self.license(self.editor, owner_id=None)
        self.service(self.editor, code="Z-1", primary_owner_id=self.editor2)
        text_ = re.sub(r"<[^>]+>", "", section(self.page(), "services"))
        self.assertIn("서버 2 · 서비스 1 · AI 모델 1 · 라이선스 2", text_)


class GPUSectionTests(DashCase):
    def test_totals_models_unassigned_and_decommissioned_excluded(self):
        a = self.server(self.editor, hostname="a", name="서버A")
        b = self.server(self.editor, hostname="b", name="서버B")
        gone = self.server(self.editor, hostname="g", name="폐기서버", status="폐기")
        self.gpu(a, "A100 80GB", 8, 80, assigned="추천팀")
        self.gpu(a, "L4", 2, 24, assigned="")
        self.gpu(b, "A100 80GB", 4, 80, assigned="   ")
        self.gpu(gone, "H100", 8, 80, assigned="")
        html = section(self.page(), "gpus")
        flat = re.sub(r"<[^>]+>", "", html)
        self.assertIn("총 GPU 14장", flat)
        self.assertIn("총 VRAM 1008 GB", flat)                                   # 8*80 + 2*24 + 4*80
        counts = count_rows(html)
        self.assertEqual((counts["A100 80GB"], counts["L4"]), (12, 2))
        self.assertNotIn("H100", html)
        unassigned = html.split("미할당 GPU")[1].split("GPU 모델별 드라이버")[0]
        self.assertIn("(2건)", unassigned)
        self.assertIn("L4 ×2", unassigned)
        self.assertIn("A100 80GB ×4", unassigned)
        self.assertNotIn("추천팀", unassigned)
        self.assertNotIn("폐기서버", unassigned)

    def test_version_combinations_and_mismatch_flag(self):
        a, b, c, d = (self.server(self.editor, hostname=h) for h in "abcd")
        self.gpu(a, "A100", driver="550.54.15", cuda="12.4")
        self.gpu(b, "A100", driver="550.54.15", cuda="12.4")
        self.gpu(c, "A100", driver="535.104.05", cuda="12.2")                       # 같은 모델, 다른 조합 → 불일치
        self.gpu(a, "L4", driver="550.54.15", cuda="12.4")
        self.gpu(b, "L4", driver="550.54.15", cuda="12.4")                          # 단일 조합 → 정상
        self.gpu(a, "T4", driver="550.54.15", cuda="12.4")
        self.gpu(d, "T4", driver="", cuda="")                                       # 미기재 조합은 불일치 판정에서 제외
        html = section(self.page(), "gpus").split("GPU 모델별 드라이버/CUDA 버전 조합")[1]
        rows, current = {}, None
        for model, driver, cuda, n, flag in re.findall(
                r"<tr><td>([^<]*)</td><td>([^<]*)</td><td>([^<]*)</td><td class=\"num\">(\d+)</td>\s*<td>(.*?)</td></tr>", html, re.S):
            current = model or current
            rows.setdefault(current, []).append((driver, cuda, int(n), "버전 불일치" in flag))
        self.assertEqual(rows["A100"][0], ("550.54.15", "12.4", 2, True))                 # 첫 행에만 불일치 배지
        self.assertIn(("535.104.05", "12.2", 1, False), rows["A100"])
        self.assertEqual(rows["L4"], [("550.54.15", "12.4", 2, False)])
        self.assertIn(("(미기재)", "(미기재)", 1, False), rows["T4"])                    # 미기재 조합은 불일치 판정에서 제외
        self.assertIn(("550.54.15", "12.4", 1, False), rows["T4"])
        self.assertEqual(sum(flag for v in rows.values() for *_x, flag in v), 1)
        self.assertIn("버전 불일치 1건", html)

    def test_no_mismatch_when_all_same(self):
        a, b = self.server(self.editor, hostname="a"), self.server(self.editor, hostname="b")
        self.gpu(a, "A100", driver="550", cuda="12.4")
        self.gpu(b, "A100", driver="550", cuda="12.4")
        self.assertNotIn("버전 불일치", section(self.page(), "gpus"))

    def test_gpu_inventory_export(self):
        a = self.server(self.editor, hostname="a", name="=서버A")
        gone = self.server(self.editor, hostname="g", name="폐기서버", status="폐기")
        self.gpu(a, "A100 80GB", 8, 80, driver="550.54.15", cuda="12.4", assigned="추천팀")
        self.gpu(a, "L4", 2, 24, assigned="")
        self.gpu(gone, "H100", 8, assigned="")
        self.assertIn('action="/dashboard/gpus/export"', self.page())
        r = self.post_form("/dashboard/gpus/export")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.content.startswith(b"\xef\xbb\xbf"))
        self.assertRegex(r.headers["content-disposition"], r'^attachment; filename="gpus-\d{8}\.csv"$')
        rows = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig"))))
        self.assertEqual(rows[0][:4], ["server_name", "hostname", "gpu_model", "quantity"])
        self.assertIn("assigned_to", rows[0])
        data = [dict(zip(rows[0], x)) for x in rows[1:]]
        self.assertEqual(len(data), 2)
        self.assertEqual({d["gpu_model"] for d in data}, {"A100 80GB", "L4"})
        self.assertEqual(data[0]["server_name"], "'=서버A")                        # 수식 주입 방지
        by = {d["gpu_model"]: d for d in data}
        self.assertEqual((by["A100 80GB"]["assigned_to"], by["L4"]["assigned_to"]), ("추천팀", ""))
        audit = self.conn.execute("SELECT * FROM audit_logs WHERE action='csv_export'").fetchone()
        self.assertEqual((audit["target_type"], audit["summary"]), ("gpu", "rows=2"))

    def test_export_permissions(self):
        self.login(self.viewer)
        self.assertNotIn("/dashboard/gpus/export", self.page())
        self.assertEqual(self.post_form("/dashboard/gpus/export").status_code, 403)
        self.login(self.editor)
        self.assertEqual(self.post_form("/dashboard/gpus/export", csrf_token="bad").status_code, 403)
        self.assertIn(self.client.get("/dashboard/gpus/export").status_code, (404, 405))
        self.client.cookies.clear()
        self.assertEqual(self.post("/dashboard/gpus/export", "x=1").status_code, 303)


class ModelAndAPISectionTests(DashCase):
    def test_model_counts_and_conditional_list(self):
        self.model(self.editor, name="cond-1", commercial_use="조건부", status="운영", source="오픈소스", base_model="b", license_note="MAU 초과 시 계약")
        self.model(self.editor, name="cond-2", version="2", commercial_use="조건부", status="폐기")
        self.model(self.editor, name="fine", version="3", commercial_use="가능", status="실험")
        html = section(self.page(), "models")
        counts = count_rows(html)
        self.assertEqual({k: counts[k] for k in ("운영", "폐기", "실험")}, {"운영": 1, "폐기": 1, "실험": 1})
        self.assertEqual(counts["오픈소스"], 1)
        self.assertEqual(counts["자체 학습"], 2)
        listing = html.split("조건부' 모델")[1]
        self.assertIn("cond-1", listing)
        self.assertIn("MAU 초과 시 계약", listing)
        self.assertNotIn("cond-2", listing)                                       # 폐기는 제외
        self.assertNotIn("fine", listing)
        self.assertIn('badge-orange">조건 확인', listing)

    def test_ai_api_provider_counts_and_per_currency_budget(self):
        mk = lambda name, prov, budget, cur, **kw: self.license(self.editor, name=name, license_type="AI API", ai_provider=prov,
                                                                  ai_monthly_budget=budget, currency=cur, **kw)
        mk("oa-1", "OpenAI", 1000, "USD")
        mk("oa-2", "OpenAI", 500.5, "USD")
        mk("oa-3", "OpenAI", 300000, "KRW")
        mk("an-1", "Anthropic", 2000, "USD")
        mk("an-expired", "Anthropic", 9999, "USD", expires_at=rel(-1))
        mk("no-budget", "Google", None, "USD")
        self.license(self.editor, name="not-ai", license_type="소프트웨어 라이선스")
        html = section(self.page(), "ai-api")
        rows = {m[0]: m for m in re.findall(r"<tr><td>([^<]+)</td><td class=\"num\">(\d+)</td>\s*<td>(.*?)</td></tr>", html, re.S)}
        self.assertEqual(rows["OpenAI"][1], "3")
        self.assertIn("1,500.50 USD", rows["OpenAI"][2])
        self.assertIn("300,000.00 KRW", rows["OpenAI"][2])                          # 통화별로 따로, 환율 변환 없음
        self.assertEqual(rows["Anthropic"][1], "1")                                 # 만료된 항목 제외
        self.assertIn("2,000.00 USD", rows["Anthropic"][2])
        self.assertNotIn("9,999", html)
        self.assertEqual(rows["Google"][1], "1")
        self.assertIn("-", rows["Google"][2])
        self.assertNotIn("not-ai", html)
        self.assertLess(html.index("OpenAI"), html.index("Anthropic"))              # 건수 많은 순


class LicenseSectionTests(DashCase):
    def test_counts_and_expiry_ordered_list(self):
        for name, exp in (("expired-old", rel(-100)), ("expired", rel(-1)), ("today", rel(0)), ("d30", rel(30)), ("d31", rel(31)),
                          ("d90", rel(90)), ("d91", rel(91))):
            self.license(self.editor, name=name, expires_at=exp)
        self.license(self.editor, name="forever", no_expiry=1, expires_at=None)
        html = section(self.page(), "licenses")
        flat = re.sub(r"<[^>]+>", "", html)
        self.assertIn("만료됨 2 · 30일 이내 2 · 90일 이내(30일 이내 포함) 4", re.sub(r"\s+", " ", flat))
        order = re.findall(r'<a href="/licenses/\d+">([^<]+)</a>', html)
        self.assertEqual(order, ["expired-old", "expired", "today", "d30", "d31", "d90"])
        self.assertNotIn("d91", html)
        self.assertNotIn("forever", html)

    def test_limit_20(self):
        for i in range(25):
            self.license(self.editor, name=f"l{i:02d}", expires_at=rel(i))
        self.assertEqual(len(re.findall(r'<a href="/licenses/\d+">', section(self.page(), "licenses"))), 20)


class StaleAndRecentTests(DashCase):
    def test_stale_top_10_oldest_first_excluding_decommissioned(self):
        for i in range(8):
            sid = self.server(self.editor, hostname=f"s{i}", name=f"srv{i}")
            self.verified("servers", sid, f"2020-01-{i + 1:02d}T00:00:00Z")          # 이른 날짜일수록 오래됨
        never = self.server(self.editor, hostname="never", name="미확인서버")
        gone = self.server(self.editor, hostname="gone", name="폐기서버", status="폐기")
        svc = self.service(self.editor, code="SVC-1", name="서비스")
        self.service(self.editor, code="SVC-2", name="종료서비스", status="종료")
        self.model(self.editor, name="폐기모델", status="폐기")
        lic = self.license(self.editor, name="라이선스")
        self.verified("licenses", lic, "2019-06-01T00:00:00Z")
        fresh = self.server(self.editor, hostname="fresh", name="최신서버")
        self.verified("servers", fresh)
        html = section(self.page(), "stale")
        names = re.findall(r'<td><a href="/[a-z]+/\d+">([^<]+)</a></td>', html)
        self.assertEqual(len(names), 10)
        self.assertEqual(set(names[:2]), {"미확인서버", "SVC-1 · 서비스"})                 # 미확인이 가장 오래된 것으로 먼저
        self.assertEqual(names[2], "라이선스")                                           # 그다음 2019년 확인
        for absent in ("폐기서버", "종료서비스", "폐기모델", "최신서버"):
            self.assertNotIn(absent, html)
        self.assertLess(names.index("라이선스"), names.index("srv0"))                 # 2019 < 2020
        self.assertLess(names.index("srv0"), names.index("srv1"))

    def test_verifying_removes_from_list(self):
        sid = self.server(self.editor, hostname="a", name="확인할서버")
        self.assertIn("확인할서버", section(self.page(), "stale"))
        self.post_form(f"/servers/{sid}/verify")
        self.assertNotIn("확인할서버", section(self.page(), "stale"))
        self.assertIn("확인이 필요한 자산이 없습니다", section(self.page(), "stale"))

    def test_recent_changes_latest_10_excluding_noise(self):
        for i in range(12):
            self.post_form("/servers/new", name=f"s{i:02d}", hostname=f"host-{i:02d}", os_type="Linux", environment="prod",
                           status="운영중", server_type="VM")
        sid = self.conn.execute("SELECT id FROM servers ORDER BY id DESC LIMIT 1").fetchone()[0]
        self.post_form(f"/servers/{sid}/verify")
        self.post_form(f"/servers/{sid}/notes", content="메모는 최근 변경에 나오지 않는다")
        self.post_form("/servers/export")
        html = section(self.page(), "recent")
        rows = html.split("<tbody>")[1].split("</tr>")[:-1]
        self.assertEqual(len(rows), 10)
        self.assertNotIn("verify", html)
        self.assertNotIn("note_add", html)
        self.assertNotIn("csv_export", html)
        self.assertIn("host-11", html)
        self.assertNotIn("host-01", html)                                            # 12건 중 오래된 2건은 제외
        self.assertRegex(html, r'<a href="/servers/\d+">서버 #\d+</a>')

    def test_deleted_asset_is_not_linked(self):
        sid = self.server(self.editor, hostname="doomed")
        self.post_form(f"/servers/{sid}/delete")
        html = section(self.page(), "recent")
        self.assertIn("server_delete", html)
        self.assertIn(f"서버 #{sid}", html)
        self.assertNotIn(f'href="/servers/{sid}"', html)

    def test_sensitive_values_never_in_recent_changes(self):
        self.post_form("/licenses/new", **lic_data(name="비밀 라이선스", license_key="TOPSECRET-KEY-1234", account_info="user/Pw!9999"))
        html = self.page()
        self.assertNotIn("TOPSECRET", html)
        self.assertNotIn("Pw!9999", html)
        self.assertIn("license_create", section(html, "recent"))

    def test_escaping(self):
        self.server(self.editor, hostname="xss", name="<script>alert(1)</script>")
        self.service(self.editor, code="X-1", name="<img src=x onerror=alert(1)>", tier=1)
        self.post_form("/servers/new", name="<b>bold</b>", hostname="xss-2", os_type="Linux", environment="prod", status="운영중", server_type="VM")
        html = self.page()
        self.assertNotIn("<script>alert(1)", html)
        self.assertNotIn("<img src=x", html)
        self.assertNotIn("<b>bold</b>", html)
