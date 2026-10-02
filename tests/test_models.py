import itertools
import re

from app import assets
from tests.test_licenses import ai_data, lic_data
from tests.test_servers import ServerCase


def mdl_data(**kw):
    data = dict(name="llama-3.1", version="8b-instruct", model_type="LLM", source="오픈소스",
                base_model="Llama 3.1 8B Instruct", model_license="Llama Community", commercial_use="조건부",
                license_note="월간 활성 사용자 기준 초과 시 별도 계약 필요", description="상담 요약용 모델", status="스테이징",
                param_size="8B", vram_gb="24", storage_location="s3://models/llama-3.1/8b", experiment_url="https://mlflow.example.com/1",
                card_url="https://wiki.example.com/llama", license_id="", owner_id="", tags="")
    data.update(kw)
    return data


class ModelCase(ServerCase):
    def create(self, **kw):
        r = self.post_form("/models/new", **mdl_data(**kw))
        self.assertEqual(r.status_code, 303, r.text[-900:])
        return int(r.headers["location"].rsplit("/", 1)[1])

    def mdl(self, mid):
        return self.conn.execute("SELECT * FROM models WHERE id=?", (mid,)).fetchone()

    def one(self, sql, *p):
        return self.conn.execute(sql, p).fetchone()

    def names(self, html):
        return re.findall(r'<a href="/models/\d+">([^<]+)</a>', html)

    def ai_license(self, **kw):
        r = self.post_form("/licenses/new", **ai_data(**kw))
        self.assertEqual(r.status_code, 303, r.text[-500:])
        return int(r.headers["location"].rsplit("/", 1)[1])


class AccessTests(ModelCase):
    def test_viewer_read_only(self):
        mid = self.create()
        self.login(self.viewer)
        self.assertEqual(self.client.get("/models").status_code, 200)
        self.assertEqual(self.client.get(f"/models/{mid}").status_code, 200)
        for path in ("/models/new", f"/models/{mid}/edit", f"/models/{mid}/delete", f"/models/{mid}/services/new"):
            self.assertEqual(self.client.get(path).status_code, 403, path)
        for path in ("/models/new", f"/models/{mid}/edit", f"/models/{mid}/delete", f"/models/{mid}/verify",
                     f"/models/{mid}/notes", f"/models/{mid}/services/new"):
            self.assertEqual(self.post_form(path, **mdl_data(version="x")).status_code, 403, path)
        html = self.client.get(f"/models/{mid}").text
        for hidden in ("/edit", "/delete", "/verify", "서비스 연결"):
            self.assertNotIn(hidden, html)
        self.assertEqual(self.one("SELECT COUNT(*) FROM models")[0], 1)

    def test_unauth_csrf_404(self):
        mid = self.create()
        for path in ("/models/new", f"/models/{mid}/edit", f"/models/{mid}/delete", f"/models/{mid}/verify"):
            self.assertEqual(self.post_form(path, csrf_token="bad", **mdl_data()).status_code, 403, path)
        for path in ("/models/999", "/models/999/edit", "/models/999/delete", "/models/999/services/new"):
            self.assertEqual(self.client.get(path).status_code, 404, path)
        self.client.cookies.clear()
        self.assertEqual(self.client.get("/models").status_code, 303)


class CreateTests(ModelCase):
    def test_create_saves_everything(self):
        mid = self.create(tags="LLM, 상담", owner_id=str(self.editor2))
        row = self.mdl(mid)
        self.assertEqual((row["name"], row["version"], row["source"], row["commercial_use"], row["vram_gb"], row["owner_id"]),
                         ("llama-3.1", "8b-instruct", "오픈소스", "조건부", 24, self.editor2))
        self.assertEqual(row["storage_location"], "s3://models/llama-3.1/8b")
        self.assertIsNone(row["last_verified_at"])
        self.assertEqual(assets.get_tags(self.conn, "model", mid), ["llm", "상담"])
        audit = self.one("SELECT * FROM audit_logs WHERE action='model_create'")
        self.assertEqual((audit["target_type"], audit["target_id"]), ("model", mid))

    def test_name_version_unique(self):
        self.create()
        r = self.post_form("/models/new", **mdl_data())
        self.assertEqual(r.status_code, 422)
        self.assertIn("이미 등록된 모델명 + 버전", r.text)
        self.create(version="70b")                                    # 같은 이름, 다른 버전은 가능
        self.create(name="mistral")                                   # 같은 버전, 다른 이름도 가능
        mid = self.one("SELECT id FROM models WHERE version='70b'")[0]
        self.assertEqual(self.post_form(f"/models/{mid}/edit", **mdl_data(version="8b-instruct")).status_code, 422)
        self.assertEqual(self.post_form(f"/models/{mid}/edit", **mdl_data(version="70b", status="운영")).status_code, 303)

    def test_commercial_use_defaults_to_unknown(self):
        data = mdl_data(version="d1")
        del data["commercial_use"]
        r = self.post_form("/models/new", **data)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.one("SELECT commercial_use FROM models WHERE version='d1'")[0], "미확인")
        self.assertIn('value="미확인" selected', self.client.get("/models/new").text)

    def test_base_model_required_for_finetune_and_open_source(self):
        for source in ("파인튜닝", "오픈소스"):
            r = self.post_form("/models/new", **mdl_data(version="b-" + source, source=source, base_model=""))
            self.assertEqual(r.status_code, 422, source)
            self.assertIn("베이스 모델이 필요", r.text)
            self.create(version="ok-" + source, source=source, base_model="Llama 3.1 8B")
        for source in ("자체 학습", "상용 API"):
            self.create(version="n-" + source, source=source, base_model="")

    def test_validation(self):
        bads = dict(name=["", "x" * 101], version=["", "x" * 51], model_type=["이미지"], source=["구매"], status=["배포"],
                    commercial_use=["아마도", ""], description=["", "x" * 4001], license_note=["x" * 2001],
                    model_license=["x" * 101], base_model=["x" * 201], param_size=["x" * 31], vram_gb=["0", "-1", "abc", "100001"],
                    storage_location=["x" * 501, "a\nb", "a\x00b"], owner_id=["x", "999"])
        for field, values in bads.items():
            for value in values:
                data = mdl_data(version="v-" + field)
                data[field] = value
                r = self.post_form("/models/new", **data)
                self.assertEqual(r.status_code, 422, (field, value))
        self.assertEqual(self.one("SELECT COUNT(*) FROM models")[0], 0)

    def test_enums_accepted(self):
        for i, (mtype, status, cu) in enumerate(itertools.product(("LLM", "임베딩", "비전", "음성", "분류·예측", "추천", "기타"),
                                                                    ("실험",), ("가능", "조건부", "불가", "미확인"))):
            self.create(version=f"e{i}", model_type=mtype, status=status, commercial_use=cu)
        for status in ("스테이징", "운영", "폐기"):
            self.create(version="s-" + status, status=status)

    def test_url_schemes_rejected_and_storage_location_not_a_link(self):
        for field in ("experiment_url", "card_url"):
            for bad in ("javascript:alert(1)", "data:text/html,x", "ftp://x.com", "s3://bucket/x", "//evil.com", "https://u:p@x.com"):
                self.assertEqual(self.post_form("/models/new", **mdl_data(version="u", **{field: bad})).status_code, 422, (field, bad))
        mid = self.create(version="loc", storage_location="s3://bucket/models/llama")
        html = self.client.get(f"/models/{mid}").text
        self.assertIn("s3://bucket/models/llama", html)
        self.assertNotIn('href="s3://', html)                         # 저장 위치는 링크가 아닌 일반 텍스트
        self.assertIn('href="https://mlflow.example.com/1" rel="noopener noreferrer"', html)
        for a in re.findall(r'<a [^>]*href="https?://[^>]*>', html):
            self.assertIn('rel="noopener noreferrer"', a)

    def test_extra_and_system_fields_rejected(self):
        for extra in ("created_by", "last_verified_at", "id", "risk"):
            self.assertEqual(self.post_form("/models/new", **mdl_data(version="x", **{extra: "1"})).status_code, 422, extra)

    def test_owner_rules_and_escaping(self):
        self.conn.execute("UPDATE users SET is_active=0 WHERE id=?", (self.editor2,))
        r = self.post_form("/models/new", **mdl_data(owner_id=str(self.editor2)))
        self.assertIn("활성 사용자만", r.text)
        mid = self.create(version="esc", name="<script>alert(1)</script>", description="<img src=x onerror=alert(1)>")
        for path in ("/models", f"/models/{mid}"):
            html = self.client.get(path).text
            self.assertNotIn("<script>alert(1)", html)
            self.assertNotIn("<img src=x", html)


class APILicenseLinkTests(ModelCase):
    def test_commercial_api_can_link_ai_api_license(self):
        lic = self.ai_license()
        mid = self.create(version="api", source="상용 API", base_model="", license_id=str(lic), commercial_use="가능")
        self.assertEqual(self.mdl(mid)["license_id"], lic)
        detail = self.client.get(f"/models/{mid}").text
        self.assertIn("연결된 AI API", detail)
        self.assertIn(f'href="/licenses/{lic}"', detail)
        self.assertIn("OpenAI 운영", detail)
        license_html = self.client.get(f"/licenses/{lic}").text.split("연결된 AI 모델")[1]
        self.assertIn(f'href="/models/{mid}"', license_html)               # 양방향
        self.assertIn("llama-3.1", license_html)

    def test_rejected_when_source_is_not_commercial_api(self):
        lic = self.ai_license()
        for source in ("자체 학습", "파인튜닝", "오픈소스"):
            r = self.post_form("/models/new", **mdl_data(version="x-" + source, source=source, base_model="B",
                                                         license_id=str(lic)))
            self.assertEqual(r.status_code, 422, source)
            self.assertIn("일 때만 AI API 라이선스를 연결", r.text)
        self.assertEqual(self.one("SELECT COUNT(*) FROM models")[0], 0)

    def test_rejected_when_license_is_not_ai_api_or_missing(self):
        plain = int(self.post_form("/licenses/new", **lic_data()).headers["location"].rsplit("/", 1)[1])
        for lic_id in (str(plain), "999", "abc"):
            r = self.post_form("/models/new", **mdl_data(version="bad", source="상용 API", base_model="", license_id=lic_id))
            self.assertEqual(r.status_code, 422, lic_id)
        self.assertEqual(self.one("SELECT COUNT(*) FROM models")[0], 0)
        # 선택지에는 AI API 라이선스만 나온다
        lic = self.ai_license()
        options = self.client.get("/models/new").text
        self.assertIn(f'<option value="{lic}"', options)
        self.assertNotIn(f'<option value="{plain}"', options.split('name="license_id"')[1].split("</select>")[0])

    def test_changing_source_away_requires_unlinking(self):
        lic = self.ai_license()
        mid = self.create(version="api", source="상용 API", base_model="", license_id=str(lic))
        r = self.post_form(f"/models/{mid}/edit", **mdl_data(version="api", source="자체 학습", base_model="", license_id=str(lic)))
        self.assertEqual(r.status_code, 422)
        r = self.post_form(f"/models/{mid}/edit", **mdl_data(version="api", source="자체 학습", base_model="", license_id=""))
        self.assertEqual(r.status_code, 303)
        self.assertIsNone(self.mdl(mid)["license_id"])

    def test_data_policy_badge_shown_for_linked_api(self):
        lic = self.ai_license(ai_sends_customer_data="예", ai_training_opt_out="미설정")
        mid = self.create(version="api", source="상용 API", base_model="", license_id=str(lic))
        self.assertIn("데이터 정책 확인", self.client.get(f"/models/{mid}").text)

    def test_license_deletion_unlinks_model_only(self):
        lic = self.ai_license()
        mid = self.create(version="api", source="상용 API", base_model="", license_id=str(lic))
        self.post_form(f"/licenses/{lic}/delete")
        self.assertIsNone(self.mdl(mid)["license_id"])


class RiskTests(ModelCase):
    def test_risk_function_matrix(self):
        for cu, status, prod in itertools.product(("가능", "조건부", "불가", "미확인"), ("실험", "스테이징", "운영", "폐기"), (False, True)):
            expected = None
            if cu in ("불가", "미확인") and (status == "운영" or prod):
                expected = "risk"
            elif cu == "조건부":
                expected = "conditional"
            self.assertEqual(assets.license_risk(cu, status, prod), expected, (cu, status, prod))

    def test_sql_and_python_agree_for_every_combination(self):
        prod_svc = self.service(self.editor, code="PROD-1", environment="prod", status="운영중")
        ids = {}
        for i, (cu, status, linked) in enumerate(itertools.product(("가능", "조건부", "불가", "미확인"),
                                                                   ("실험", "스테이징", "운영", "폐기"), (False, True))):
            mid = self.create(version=f"c{i}", commercial_use=cu, status=status, name=f"m{i:02d}")
            if linked:
                self.conn.execute("INSERT INTO model_services (model_id, service_id) VALUES (?, ?)", (mid, prod_svc))
            ids[mid] = (cu, status, linked)
        listing = self.client.get("/models?risk=on&page=1").text
        names = set()
        for page in (1, 2, 3):
            names |= set(self.names(self.client.get(f"/models?risk=on&page={page}").text))
        expected = {f"m{i:02d}" for i, (mid, (cu, st, ln)) in enumerate(ids.items()) if assets.license_risk(cu, st, ln) == "risk"}
        self.assertEqual(names, expected)
        self.assertTrue(expected)

    def test_prod_service_condition(self):
        cases = [("prod", "운영중", True), ("prod", "점검", False), ("prod", "개발중", False), ("stg", "운영중", False),
                 ("dev", "운영중", False), ("prod", "종료", False)]
        for i, (env, status, risky) in enumerate(cases):
            svc = self.service(self.editor, code=f"S-{i}", environment=env, status=status)
            mid = self.create(version=f"p{i}", name=f"pm{i}", commercial_use="불가", status="실험")
            self.assertNotIn("라이선스 위험", self.client.get(f"/models/{mid}").text)
            self.post_form(f"/models/{mid}/services/new", service_id=str(svc))
            html = self.client.get(f"/models/{mid}").text
            self.assertEqual("라이선스 위험" in html, risky, (env, status))

    def test_badges_in_list_and_detail(self):
        risk = self.create(version="r", name="risky", commercial_use="불가", status="운영")
        unknown_prod = self.create(version="u", name="unknown-op", commercial_use="미확인", status="운영")
        cond = self.create(version="c", name="conditional", commercial_use="조건부", status="실험")
        ok = self.create(version="o", name="fine", commercial_use="가능", status="운영")
        experimental = self.create(version="e", name="exp", commercial_use="불가", status="실험")
        html = self.client.get("/models").text.split("<tbody>")[1]
        rows = {name: row for name, row in zip(self.names(html), html.split("</tr>"))}
        self.assertIn('badge-red">라이선스 위험', rows["risky"])
        self.assertIn('badge-red">라이선스 위험', rows["unknown-op"])
        self.assertIn('badge-orange">조건 확인', rows["conditional"])
        self.assertNotIn("라이선스 위험", rows["fine"])
        self.assertNotIn("조건 확인", rows["fine"])
        self.assertNotIn("라이선스 위험", rows["exp"])                 # 실험 + 서비스 미연결 → 위험 아님
        self.assertIn('badge-red">상업 이용 불가', rows["risky"])
        self.assertIn('badge-green">상업 이용 가능', rows["fine"])
        self.assertIn('badge-orange">상업 이용 미확인', rows["unknown-op"])
        self.assertIn("라이선스 위험", self.client.get(f"/models/{risk}").text)
        self.assertIn("조건 확인", self.client.get(f"/models/{cond}").text)
        self.assertEqual(sorted(self.names(self.client.get("/models?risk=on").text)), ["risky", "unknown-op"])
        self.assertEqual(self.names(self.client.get("/models?commercial_use=조건부").text), ["conditional"])

    def test_conditional_badge_shown_regardless_of_status(self):
        mid = self.create(commercial_use="조건부", status="폐기")
        self.assertIn("조건 확인", self.client.get(f"/models/{mid}").text)


class ServiceLinkTests(ModelCase):
    def setUp(self):
        super().setUp()
        self.mid = self.create(commercial_use="불가", status="실험")
        self.svc = self.service(self.editor, code="CS-1", name="상담 서비스", environment="prod", status="운영중")

    def test_link_edit_unlink(self):
        r = self.post_form(f"/models/{self.mid}/services/new", service_id=str(self.svc), note="상담 요약")
        self.assertEqual((r.status_code, r.headers["location"]), (303, f"/models/{self.mid}#services"))
        self.assertIn("상담 요약", self.client.get(f"/models/{self.mid}").text)
        self.assertEqual(self.post_form(f"/models/{self.mid}/services/new", service_id=str(self.svc)).status_code, 422)
        self.assertEqual(self.post_form(f"/models/{self.mid}/services/new", service_id="999").status_code, 422)
        self.assertEqual(self.post_form(f"/models/{self.mid}/services/new", service_id="abc").status_code, 422)
        self.assertEqual(self.post_form(f"/models/{self.mid}/services/new", service_id=str(self.svc), note="x" * 501).status_code, 422)
        self.assertNotIn("CS-1 · 상담 서비스", self.client.get(f"/models/{self.mid}/services/new").text)
        self.post_form(f"/models/{self.mid}/services/{self.svc}/edit", note="검색 임베딩")
        self.assertEqual(self.one("SELECT note FROM model_services")[0], "검색 임베딩")
        self.assertEqual(self.post_form(f"/models/{self.mid}/services/{self.svc}/delete").status_code, 303)
        self.assertEqual(self.one("SELECT COUNT(*) FROM model_services")[0], 0)
        self.assertEqual(self.post_form(f"/models/{self.mid}/services/{self.svc}/delete").status_code, 404)
        self.assertIsNotNone(self.one("SELECT 1 FROM services WHERE id=?", self.svc))

    def test_service_detail_shows_models_with_risk(self):
        self.post_form(f"/models/{self.mid}/services/new", service_id=str(self.svc), note="상담 요약")
        html = self.client.get(f"/services/{self.svc}").text.split("사용 AI 모델")[1].split("연결된 라이선스")[0]
        for needle in ("llama-3.1", "8b-instruct", "상담 요약", "라이선스 위험", "상업 이용 불가"):
            self.assertIn(needle, html)
        self.assertEqual(self.one("SELECT COUNT(*) FROM model_services")[0], 1)
        self.assertIn("1", self.client.get("/models").text.split("<tbody>")[1])

    def test_service_count_column_and_updated_at(self):
        self.conn.execute("UPDATE models SET updated_at='2020-01-01T00:00:00Z'")
        self.post_form(f"/models/{self.mid}/services/new", service_id=str(self.svc))
        self.assertNotEqual(self.mdl(self.mid)["updated_at"], "2020-01-01T00:00:00Z")
        self.assertIn("model_service_add", self.client.get(f"/models/{self.mid}").text.split("변경 이력")[1])

    def test_permissions_and_missing(self):
        self.login(self.viewer)
        self.assertEqual(self.post_form(f"/models/{self.mid}/services/new", service_id=str(self.svc)).status_code, 403)
        self.login(self.editor)
        self.assertEqual(self.client.get(f"/models/{self.mid}/services/{self.svc}/edit").status_code, 404)


class EditTests(ModelCase):
    def test_edit_audit_and_no_verification(self):
        mid = self.create()
        self.conn.execute("UPDATE models SET last_verified_at='2020-01-01T00:00:00Z' WHERE id=?", (mid,))
        self.post_form(f"/models/{mid}/edit", **mdl_data(status="운영", commercial_use="가능", tags="x"))
        row = self.mdl(mid)
        self.assertEqual((row["status"], row["commercial_use"], row["last_verified_at"]), ("운영", "가능", "2020-01-01T00:00:00Z"))
        summary = self.one("SELECT summary FROM audit_logs WHERE action='model_update'")[0]
        self.assertIn("status: 스테이징 → 운영", summary)
        self.assertIn("commercial_use: 조건부 → 가능", summary)

    def test_unchanged_edit_writes_nothing(self):
        mid = self.create()
        self.conn.execute("UPDATE models SET updated_at='2020-01-01T00:00:00Z'")
        self.post_form(f"/models/{mid}/edit", **mdl_data())
        self.assertEqual(self.mdl(mid)["updated_at"], "2020-01-01T00:00:00Z")
        self.assertIsNone(self.one("SELECT 1 FROM audit_logs WHERE action='model_update'"))

    def test_prefilled_and_inactive_owner_kept(self):
        mid = self.create(owner_id=str(self.editor2), tags="a,b")
        self.conn.execute("UPDATE users SET is_active=0 WHERE id=?", (self.editor2,))
        html = self.client.get(f"/models/{mid}/edit").text
        self.assertIn('value="llama-3.1"', html)
        self.assertIn("[비활성]", html)
        self.assertIn("a, b", html)
        self.assertEqual(self.post_form(f"/models/{mid}/edit", **mdl_data(owner_id=str(self.editor2), status="운영")).status_code, 303)
        self.assertIn("비활성 담당자", self.client.get("/models").text)

    def test_freshness_notes_history(self):
        mid = self.create()
        self.assertIn("확인 필요", self.client.get(f"/models/{mid}").text)
        self.post_form(f"/models/{mid}/verify")
        self.post_form(f"/models/{mid}/notes", content="벤치마크 재측정")
        html = self.client.get(f"/models/{mid}").text
        self.assertIn("확인됨", html)
        self.assertIn("벤치마크 재측정", html)
        for action in ("model_create", "model_verify", "model_note_add"):
            self.assertIn(action, html.split("변경 이력")[1])


class ListTests(ModelCase):
    def test_pagination_search_filters_sort(self):
        for i in range(45):
            self.conn.execute(
                "INSERT INTO models (name, version, model_type, source, description, status, created_at, created_by, updated_at, "
                "updated_by) VALUES (?, '1', 'LLM', '자체 학습', 'd', '실험', '2026-01-01T00:00:00Z', ?, '2026-01-01T00:00:00Z', ?)", (f"bulk{i:03d}", self.editor, self.editor))
        p = [self.client.get(f"/models?page={n}").text.split("<tbody>")[1].count("<tr>") for n in (1, 2, 3)]
        self.assertEqual(p, [20, 20, 5])
        self.conn.execute("DELETE FROM models")
        a = self.create(name="alpha", version="1", model_type="임베딩", source="자체 학습", base_model="", status="운영",
                        commercial_use="가능", tags="t1", owner_id=str(self.editor))
        b = self.create(name="beta%x", version="1", base_model="Llama 3 70B", owner_id=str(self.editor2))
        self.conn.execute("UPDATE models SET last_verified_at='2099-01-01T00:00:00Z' WHERE id=?", (a,))
        f = lambda qs: sorted(self.names(self.client.get("/models?" + qs).text))
        self.assertEqual(f("model_type=임베딩"), ["alpha"])
        self.assertEqual(f("source=오픈소스"), ["beta%x"])
        self.assertEqual(f("status=운영"), ["alpha"])
        self.assertEqual(f("commercial_use=가능"), ["alpha"])
        self.assertEqual(f("tag=t1"), ["alpha"])
        self.assertEqual(f("stale=on"), ["beta%x"])
        self.assertEqual(f("mine=on"), ["alpha"])
        self.assertEqual(f("q=llama 3"), ["beta%x"])                     # 베이스 모델 검색
        self.assertEqual(f("q=ALPHA"), ["alpha"])
        self.assertEqual(f("q=%25"), ["beta%x"])                         # '%'는 리터럴
        self.assertEqual(f("q=x'+OR+'1'='1"), [])
        self.assertEqual(self.names(self.client.get("/models?sort=name").text), ["alpha", "beta%x"])

    def test_invalid_filters(self):
        self.create()
        for qs in ("model_type=x", "source=x", "status=x", "commercial_use=x", "sort=id", "page=0", "evil=1", "owner_id=x"):
            self.assertIn("조회 조건이 올바르지 않습니다", self.client.get("/models?" + qs).text, qs)


class DeleteTests(ModelCase):
    def test_confirm_warns_and_delete_cleans_without_orphans(self):
        mid = self.create(tags="keep,gone")
        other = self.create(version="other", tags="keep")
        self.post_form(f"/models/{mid}/notes", content="삭제될 메모")
        self.post_form(f"/models/{other}/notes", content="남을 메모")
        svc = self.service(self.editor, code="DM-1", name="모델 사용 서비스")
        self.post_form(f"/models/{mid}/services/new", service_id=str(svc))
        lic = self.ai_license()
        r = self.client.get(f"/models/{mid}/delete")
        self.assertIn("사용하는 서비스가 1개", r.text)
        self.assertIn("모델 사용 서비스", r.text)
        self.assertIsNotNone(self.mdl(mid))
        r = self.post_form(f"/models/{mid}/delete")
        self.assertEqual((r.status_code, r.headers["location"]), (303, "/models"))
        q = lambda sql, *p: self.one(sql, *p)[0]
        self.assertEqual(q("SELECT COUNT(*) FROM model_services"), 0)
        self.assertEqual(q("SELECT COUNT(*) FROM asset_tags WHERE asset_type='model' AND asset_id=?", mid), 0)
        self.assertEqual(q("SELECT COUNT(*) FROM asset_notes WHERE asset_type='model' AND asset_id=?", mid), 0)
        self.assertEqual(q("SELECT COUNT(*) FROM asset_tags WHERE asset_type='model' AND asset_id=?", other), 1)
        self.assertEqual(q("SELECT COUNT(*) FROM asset_notes WHERE asset_id=?", other), 1)
        self.assertEqual((q("SELECT COUNT(*) FROM services"), q("SELECT COUNT(*) FROM licenses")), (1, 1))
        self.assertIn("llama-3.1", self.one("SELECT summary FROM audit_logs WHERE action='model_delete'")[0])

    def test_viewer_cannot_delete(self):
        mid = self.create()
        self.login(self.viewer)
        self.assertEqual(self.post_form(f"/models/{mid}/delete").status_code, 403)
        self.assertIsNotNone(self.mdl(mid))
