import re
import sqlite3
from datetime import datetime, timedelta

from cryptography.exceptions import InvalidTag

from app import assets, config, security
from tests.test_servers import ServerCase

KEY = "LIC-KEY-0123-ABCD-WXYZ"
ACCOUNT = "admin@corp.example / P@ssw0rd-Secret!"


def lic_data(**kw):
    data = dict(name="IDE 라이선스", license_type="소프트웨어 라이선스", vendor="JetBrains", start_date="2026-01-01",
                expires_at="2099-12-31", quantity="50", cost="1200000", currency="KRW", billing_cycle="연",
                alert_days="30", notes="", owner_id="", tags="")
    data.update(kw)
    return data


def ai_data(**kw):
    data = lic_data(name="OpenAI 운영", license_type="AI API", vendor="OpenAI", ai_provider="OpenAI",
                    ai_models="gpt-4.1\ngpt-4.1-mini", ai_monthly_budget="3000", currency="USD", billing_cycle="월",
                    ai_key_location="Vault: secret/ai/openai-prod", ai_sends_customer_data="아니오",
                    ai_training_opt_out="설정됨", ai_retention_note="API 입력 30일 보관 후 삭제")
    data.update(kw)
    return data


def ssl_data(**kw):
    data = lic_data(name="*.example.com", license_type="SSL/TLS 인증서", vendor="DigiCert", ssl_cn="*.example.com",
                    ssl_san="example.com\n*.example.com\napi.example.com", ssl_wildcard="on", ssl_ca="DigiCert",
                    ssl_key_algo="RSA 2048", ssl_serial="0A:1B", ssl_sha256="ab" * 32)
    data.update(kw)
    return data


def rel(days):
    return (datetime.strptime(assets.today_kst(), "%Y-%m-%d") + timedelta(days=days)).strftime("%Y-%m-%d")


class LicenseCase(ServerCase):
    def create(self, data=None, **kw):
        r = self.post_form("/licenses/new", **(data or lic_data(**kw)))
        self.assertEqual(r.status_code, 303, r.text[-900:])
        return int(r.headers["location"].rsplit("/", 1)[1])

    def lic(self, lid):
        return self.conn.execute("SELECT * FROM licenses WHERE id=?", (lid,)).fetchone()

    def one(self, sql, *p):
        return self.conn.execute(sql, p).fetchone()

    def key(self):
        return self.client.app.state.secret_key

    def names(self, html):
        return re.findall(r'<a href="/licenses/\d+">([^<]+)</a>', html)


class StatusTests(LicenseCase):
    def test_boundaries(self):
        st = lambda exp, alert=30, no=False, today="2026-06-15": assets.license_status(exp, no, alert, today)["state"]
        self.assertEqual(st("2026-06-14"), "만료됨")                 # 어제
        self.assertEqual(st("2026-06-15"), "만료 임박")              # 오늘 (아직 만료 아님)
        self.assertEqual(st("2026-07-15"), "만료 임박")              # 오늘 + 알림 기준일
        self.assertEqual(st("2026-07-16"), "유효")                   # 하루 더
        self.assertEqual(st("2026-06-15", alert=0), "만료 임박")
        self.assertEqual(st("2026-06-16", alert=0), "유효")
        self.assertEqual(st("2026-06-14", alert=0), "만료됨")
        self.assertEqual(st(None, no=True), "영구")
        self.assertEqual(st("2020-01-01", no=True), "영구")           # 영구는 만료일과 무관
        self.assertEqual(st("2026-09-13", alert=90), "만료 임박")
        info = assets.license_status("2026-06-20", False, 30, "2026-06-15")
        self.assertEqual((info["days"], info["badge"]), (5, "orange"))
        self.assertEqual(assets.license_status("2026-06-10", False, 30, "2026-06-15")["days"], -5)

    def test_badge_colors(self):
        for exp, color in ((rel(-1), "red"), (rel(5), "orange"), (rel(100), "green")):
            self.create(name=f"L-{exp}", expires_at=exp)
        self.create(name="영구", no_expiry="on", expires_at="", billing_cycle="영구")
        html = self.client.get("/licenses").text.split("<tbody>")[1]
        for text, color in (("만료됨", "red"), ("만료 임박", "orange"), ("유효", "green"), ("영구", "gray")):
            self.assertRegex(html, rf'badge-{color}">{text}')
        self.assertIn("D-5", html)
        self.assertIn("D+1", html)

    def test_state_filter_matches_function_at_boundaries(self):
        dates = {"yesterday": rel(-1), "today": rel(0), "edge": rel(30), "after": rel(31)}
        for name, d in dates.items():
            self.create(name=name, expires_at=d, alert_days="30")
        self.create(name="forever", no_expiry="on", expires_at="")
        f = lambda state: sorted(self.names(self.client.get("/licenses?expiry=" + state).text))
        self.assertEqual(f("만료됨"), ["yesterday"])
        self.assertEqual(f("만료 임박"), ["edge", "today"])
        self.assertEqual(f("유효"), ["after"])
        self.assertEqual(f("영구"), ["forever"])
        for name, d in dates.items():       # 화면 배지와 필터가 같은 판정을 쓴다
            state = assets.license_status(d, False, 30)["state"]
            self.assertIn(name, f(state))

    def test_per_license_alert_days(self):
        self.create(name="A", expires_at=rel(10), alert_days="5")
        self.create(name="B", expires_at=rel(10), alert_days="10")
        self.assertEqual(self.names(self.client.get("/licenses?expiry=유효").text), ["A"])
        self.assertEqual(self.names(self.client.get("/licenses?expiry=만료 임박").text), ["B"])


class AccessTests(LicenseCase):
    def test_viewer_read_only_and_masked(self):
        lid = self.create(license_key=KEY, account_info=ACCOUNT)
        self.login(self.viewer)
        self.assertEqual(self.client.get("/licenses").status_code, 200)
        html = self.client.get(f"/licenses/{lid}").text
        self.assertIn("****WXYZ", html)
        self.assertNotIn(KEY, html)
        self.assertNotIn("원문 보기", html)
        for path in ("/licenses/new", f"/licenses/{lid}/edit", f"/licenses/{lid}/delete", f"/licenses/{lid}/servers/new",
                     f"/licenses/{lid}/services/new"):
            self.assertEqual(self.client.get(path).status_code, 403, path)
        for path in ("/licenses/new", f"/licenses/{lid}/edit", f"/licenses/{lid}/delete", f"/licenses/{lid}/verify",
                     f"/licenses/{lid}/notes", f"/licenses/{lid}/reveal", f"/licenses/{lid}/servers/new"):
            self.assertEqual(self.post_form(path, **lic_data(field="license_key")).status_code, 403, path)
        self.assertEqual(self.one("SELECT COUNT(*) FROM licenses")[0], 1)

    def test_unauth_csrf_404(self):
        lid = self.create()
        for path in ("/licenses/new", f"/licenses/{lid}/edit", f"/licenses/{lid}/delete", f"/licenses/{lid}/verify",
                     f"/licenses/{lid}/reveal"):
            self.assertEqual(self.post_form(path, csrf_token="bad", **lic_data()).status_code, 403, path)
        for path in ("/licenses/999", "/licenses/999/edit", "/licenses/999/delete"):
            self.assertEqual(self.client.get(path).status_code, 404, path)
        self.client.cookies.clear()
        self.assertEqual(self.client.get("/licenses").status_code, 303)


class SensitiveTests(LicenseCase):
    def test_encrypted_at_rest_with_record_id_aad(self):
        lid = self.create(license_key=KEY, account_info=ACCOUNT)
        row = self.lic(lid)
        for column, field, plain in (("license_key_enc", "license_key", KEY), ("account_info_enc", "account_info", ACCOUNT)):
            blob = row[column]
            self.assertNotIn(plain.encode(), blob)
            self.assertEqual(len(blob[:12]), 12)
            self.assertEqual(security.decrypt_field(self.key(), lid, field, blob), plain)
            with self.assertRaises(InvalidTag):
                security.decrypt_field(self.key(), lid + 1, field, blob)            # 다른 레코드 ID
        self.assertNotEqual(row["license_key_enc"][:12], row["account_info_enc"][:12])   # 레코드/필드마다 랜덤 nonce

    def test_plaintext_never_hits_the_database_file(self):
        lid = self.create(license_key=KEY, account_info=ACCOUNT, notes="평문 아님")
        self.post_form(f"/licenses/{lid}/edit", **lic_data(license_key=KEY + "-2", notes="수정"))
        self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        raw = (config.DATA_DIR / "app.db").read_bytes()
        wal = config.DATA_DIR / "app.db-wal"
        raw += wal.read_bytes() if wal.exists() else b""
        for secret in (KEY, ACCOUNT, "Secret!", KEY + "-2"):
            self.assertNotIn(secret.encode(), raw, secret)

    def test_masking(self):
        lid = self.create(license_key=KEY, account_info="short")
        html = self.client.get(f"/licenses/{lid}").text
        self.assertIn("****WXYZ", html)
        self.assertIn("********", html)                                         # 9자 이하는 전부 가림
        self.assertNotIn(KEY, html)
        self.assertNotIn("short", html)
        lid2 = self.create(name="키 없음")
        self.assertIn("저장된 값 없음", self.client.get(f"/licenses/{lid2}").text)

    def test_reveal_is_post_only_editor_and_audited(self):
        lid = self.create(license_key=KEY)
        self.assertEqual(self.client.get(f"/licenses/{lid}/reveal").status_code, 405)
        r = self.post_form(f"/licenses/{lid}/reveal", field="license_key")
        self.assertEqual(r.status_code, 200)
        self.assertIn(KEY, r.text)
        self.assertEqual(r.headers["cache-control"], "no-store")
        audit = self.one("SELECT * FROM audit_logs WHERE action='license_reveal'")
        self.assertEqual((audit["target_id"], audit["user_id"]), (lid, self.editor))
        self.assertIn("license_key", audit["summary"])
        self.assertNotIn(KEY, audit["summary"])
        self.assertNotIn(KEY, self.client.get(f"/licenses/{lid}").text)           # 이후 상세에도 남지 않음

    def test_reveal_validation(self):
        lid = self.create(license_key=KEY)
        self.assertEqual(self.post_form(f"/licenses/{lid}/reveal", field="license_key_enc").status_code, 422)
        self.assertEqual(self.post_form(f"/licenses/{lid}/reveal", field="name").status_code, 422)
        self.assertEqual(self.post_form(f"/licenses/{lid}/reveal").status_code, 422)
        self.assertEqual(self.post_form(f"/licenses/{lid}/reveal", field="account_info").status_code, 404)  # 값 없음
        self.assertEqual(self.post_form("/licenses/999/reveal", field="license_key").status_code, 404)
        self.assertEqual(self.post_form(f"/licenses/{lid}/reveal", field="license_key", extra="1").status_code, 422)
        self.assertEqual(self.one("SELECT COUNT(*) FROM audit_logs WHERE action='license_reveal'")[0], 0)

    def test_decrypt_failure_is_handled_not_500(self):
        a = self.create(name="A", license_key=KEY)
        b = self.create(name="B", license_key="OTHER-KEY-9999")
        self.conn.execute("UPDATE licenses SET license_key_enc=(SELECT license_key_enc FROM licenses WHERE id=?) WHERE id=?", (a, b))
        self.assertEqual(self.client.get(f"/licenses/{b}").status_code, 200)       # 복사된 암호문은 AAD 불일치
        self.assertIn("복호화 실패", self.client.get(f"/licenses/{b}").text)
        r = self.post_form(f"/licenses/{b}/reveal", field="license_key")
        self.assertEqual(r.status_code, 303)
        self.assertIn("복호화에 실패했습니다", self.client.get(f"/licenses/{b}").text)

    def test_sensitive_values_excluded_from_audit_history_list_and_forms(self):
        lid = self.create(license_key=KEY, account_info=ACCOUNT)
        self.post_form(f"/licenses/{lid}/edit", **lic_data(license_key=KEY + "-NEW", name="이름 변경"))
        for row in self.conn.execute("SELECT summary FROM audit_logs"):
            for secret in (KEY, ACCOUNT, "Secret!"):
                self.assertNotIn(secret, row[0])
        create_summary = self.one("SELECT summary FROM audit_logs WHERE action='license_create'")[0]
        update_summary = self.one("SELECT summary FROM audit_logs WHERE action='license_update'")[0]
        self.assertIn("민감 정보 등록: 라이선스 키, 계정 정보 (값 비공개)", create_summary)
        self.assertIn("민감 정보 변경: 라이선스 키 (값 비공개)", update_summary)
        for path in (f"/licenses/{lid}", "/licenses", f"/licenses/{lid}/edit"):
            html = self.client.get(path).text
            self.assertNotIn(KEY, html, path)
            self.assertNotIn("Secret!", html, path)
        self.login(self.admin)
        self.assertNotIn(KEY, self.client.get("/audit").text)

    def test_validation_error_does_not_echo_secrets(self):
        r = self.post_form("/licenses/new", **lic_data(name="", license_key=KEY, account_info=ACCOUNT))
        self.assertEqual(r.status_code, 422)
        self.assertNotIn(KEY, r.text)
        self.assertNotIn("Secret!", r.text)
        self.assertEqual(self.one("SELECT COUNT(*) FROM licenses")[0], 0)

    def test_blank_keeps_new_replaces_clear_removes(self):
        lid = self.create(license_key=KEY, account_info=ACCOUNT)
        before = self.lic(lid)["license_key_enc"]
        self.post_form(f"/licenses/{lid}/edit", **lic_data(name="이름만 변경"))                    # 키 입력 비움 → 유지
        self.assertEqual(self.lic(lid)["license_key_enc"], before)
        self.post_form(f"/licenses/{lid}/edit", **lic_data(name="이름만 변경", license_key="NEW-KEY-7777"))
        row = self.lic(lid)
        self.assertEqual(security.decrypt_field(self.key(), lid, "license_key", row["license_key_enc"]), "NEW-KEY-7777")
        self.assertEqual(security.decrypt_field(self.key(), lid, "account_info", row["account_info_enc"]), ACCOUNT)
        self.post_form(f"/licenses/{lid}/edit", **lic_data(name="이름만 변경", clear_account_info="on"))
        row = self.lic(lid)
        self.assertIsNone(row["account_info_enc"])
        self.assertIsNotNone(row["license_key_enc"])
        self.assertIn("저장된 값 없음", self.client.get(f"/licenses/{lid}").text)

    def test_edit_form_never_prefills_secrets(self):
        lid = self.create(license_key=KEY)
        html = self.client.get(f"/licenses/{lid}/edit").text
        self.assertNotIn(KEY, html)
        self.assertIn("비워 두면 기존 값 유지", html)
        self.assertIn("저장된 라이선스 키 삭제", html)
        self.assertRegex(html, r'type="password"[^>]*name|name="license_key"')

    def test_sensitive_only_change_is_audited_but_no_other_diff(self):
        lid = self.create(license_key=KEY)
        self.post_form(f"/licenses/{lid}/edit", **lic_data(license_key="ANOTHER-KEY-1"))
        summary = self.one("SELECT summary FROM audit_logs WHERE action='license_update'")[0]
        self.assertEqual(summary, "민감 정보 변경: 라이선스 키 (값 비공개)")

    def test_unchanged_edit_writes_nothing(self):
        lid = self.create()
        self.conn.execute("UPDATE licenses SET updated_at='2020-01-01T00:00:00Z'")
        self.post_form(f"/licenses/{lid}/edit", **lic_data())
        self.assertEqual(self.lic(lid)["updated_at"], "2020-01-01T00:00:00Z")
        self.assertIsNone(self.one("SELECT 1 FROM audit_logs WHERE action='license_update'"))


class AIAPITests(LicenseCase):
    def test_create_ai_api_and_defaults(self):
        lid = self.create(ai_data())
        row = self.lic(lid)
        self.assertEqual((row["ai_provider"], row["ai_models"], row["ai_monthly_budget"], row["currency"]),
                         ("OpenAI", "gpt-4.1\ngpt-4.1-mini", 3000.0, "USD"))
        self.assertEqual((row["license_key_enc"], row["account_info_enc"]), (None, None))
        self.assertEqual(row["ssl_cn"], None)
        lid2 = self.create(ai_data(name="기본값", ai_sends_customer_data="", ai_training_opt_out=""))
        row2 = self.lic(lid2)
        self.assertEqual((row2["ai_sends_customer_data"], row2["ai_training_opt_out"]), ("미확인", "미확인"))
        html = self.client.get(f"/licenses/{lid}").text
        for needle in ("gpt-4.1-mini", "Vault: secret/ai/openai-prod", "API 입력 30일 보관 후 삭제", "3,000.00 USD",
                       "API 키 자체는 저장하지 않습니다"):
            self.assertIn(needle, html)
        self.assertNotIn("민감 정보", html.split("AI API 정보")[1].split("연결된")[0])      # 민감 정보 섹션 숨김

    def test_server_rejects_api_key_values(self):
        for field in ("license_key", "account_info"):
            r = self.post_form("/licenses/new", **ai_data(**{field: "sk-proj-abcdef123456"}))
            self.assertEqual(r.status_code, 422, field)
            self.assertIn("AI API 종류에서는", r.text)
            self.assertNotIn("sk-proj-abcdef123456", r.text)
        self.assertEqual(self.one("SELECT COUNT(*) FROM licenses")[0], 0)
        lid = self.create(ai_data())
        r = self.post_form(f"/licenses/{lid}/edit", **ai_data(license_key="sk-proj-abcdef123456"))
        self.assertEqual(r.status_code, 422)
        self.assertIsNone(self.lic(lid)["license_key_enc"])

    def test_edit_form_hides_secret_inputs_for_ai_api(self):
        lid = self.create(ai_data())
        html = self.client.get(f"/licenses/{lid}/edit").text
        self.assertNotIn('name="license_key"', html)
        self.assertNotIn('name="account_info"', html)
        self.assertIn('name="ai_key_location"', html)

    def test_provider_required(self):
        r = self.post_form("/licenses/new", **ai_data(ai_provider=""))
        self.assertEqual(r.status_code, 422)
        self.assertIn("제공사가 필요", r.text)
        for provider in ("OpenAI", "Anthropic", "Google", "Azure OpenAI", "AWS Bedrock", "기타", "내가 쓰는 제공사"):
            self.create(ai_data(name="p-" + provider, ai_provider=provider))

    def test_ai_field_validation(self):
        for bad in (dict(ai_sends_customer_data="모름"), dict(ai_training_opt_out="아마도"), dict(ai_monthly_budget="-1"),
                    dict(ai_monthly_budget="nan"), dict(ai_key_location="x" * 301), dict(ai_retention_note="x" * 1001),
                    dict(ai_models="\n".join(f"m{i}" for i in range(31))), dict(ai_models="x" * 101)):
            self.assertEqual(self.post_form("/licenses/new", **ai_data(**bad)).status_code, 422, bad)

    def test_data_policy_warning_matrix(self):
        cases = {("예", "미설정"): True, ("예", "미확인"): True, ("예", "설정됨"): False, ("예", "해당 없음"): False,
                 ("아니오", "미설정"): False, ("아니오", "미확인"): False, ("미확인", "미설정"): False,
                 ("미확인", "미확인"): False}
        for (sends, opt), risky in cases.items():
            self.assertEqual(assets.data_policy_risk(sends, opt), risky, (sends, opt))
        risky = self.create(ai_data(name="위험", ai_sends_customer_data="예", ai_training_opt_out="미설정"))
        safe = self.create(ai_data(name="안전", ai_sends_customer_data="예", ai_training_opt_out="설정됨"))
        listing = self.client.get("/licenses").text
        self.assertEqual(listing.count("데이터 정책 확인"), 1)
        self.assertIn('badge-red">데이터 정책 확인', self.client.get(f"/licenses/{risky}").text)
        self.assertNotIn("데이터 정책 확인", self.client.get(f"/licenses/{safe}").text)

    def test_provider_filter(self):
        self.create(ai_data(name="oa", ai_provider="OpenAI"))
        self.create(ai_data(name="an", ai_provider="Anthropic"))
        self.create(lic_data(name="plain"))
        self.assertEqual(self.names(self.client.get("/licenses?ai_provider=Anthropic").text), ["an"])
        self.assertEqual(sorted(self.names(self.client.get("/licenses?license_type=AI API").text)), ["an", "oa"])

    def test_switching_type_to_ai_api_drops_stored_secrets(self):
        lid = self.create(license_key=KEY, account_info=ACCOUNT)
        r = self.post_form(f"/licenses/{lid}/edit", **ai_data())
        self.assertEqual(r.status_code, 303, r.text[-500:])
        row = self.lic(lid)
        self.assertEqual((row["license_type"], row["license_key_enc"], row["account_info_enc"]), ("AI API", None, None))

    def test_switching_from_ai_api_to_license_with_key(self):
        lid = self.create(ai_data())
        r = self.post_form(f"/licenses/{lid}/edit", **lic_data(license_key=KEY))
        self.assertEqual(r.status_code, 303, r.text[-500:])
        row = self.lic(lid)
        self.assertEqual(row["license_type"], "소프트웨어 라이선스")
        self.assertEqual(security.decrypt_field(self.key(), lid, "license_key", row["license_key_enc"]), KEY)
        self.assertIsNone(row["ai_provider"])                                  # AI 전용 필드는 비워짐


class SSLTests(LicenseCase):
    def test_ssl_fields_saved_and_displayed(self):
        lid = self.create(ssl_data())
        row = self.lic(lid)
        self.assertEqual((row["ssl_cn"], row["ssl_wildcard"], row["ssl_key_algo"]), ("*.example.com", 1, "RSA 2048"))
        self.assertEqual(row["ssl_san"], "example.com\n*.example.com\napi.example.com")
        self.assertEqual(row["ssl_sha256"], ":".join(["AB"] * 32))                # 정규화
        html = self.client.get(f"/licenses/{lid}").text
        self.assertIn("SSL/TLS 정보", html)
        self.assertIn("api.example.com", html)
        self.assertIn("와일드카드", html)

    def test_ssl_fields_only_for_ssl_type(self):
        lid = self.create(lic_data(ssl_cn="a.example.com", ssl_san="a.example.com", ssl_wildcard="on"))
        row = self.lic(lid)
        self.assertEqual((row["ssl_cn"], row["ssl_san"], row["ssl_wildcard"]), (None, None, 0))
        self.assertNotIn("SSL/TLS 정보", self.client.get(f"/licenses/{lid}").text)

    def test_validation(self):
        for bad in (dict(ssl_cn="<script>"), dict(ssl_cn="a b"), dict(ssl_san="ok.example.com\nbad host"),
                    dict(ssl_san="\n".join(f"h{i}.example.com" for i in range(101))), dict(ssl_sha256="zz"),
                    dict(ssl_sha256="ab" * 31), dict(ssl_key_algo="DSA"), dict(ssl_ca="x" * 201)):
            self.assertEqual(self.post_form("/licenses/new", **ssl_data(**bad)).status_code, 422, bad)
        for good in ("aa:" * 31 + "aa", "AB" * 32, "ab cd " * 0 + "cd" * 32):
            self.create(ssl_data(name="fp-" + good[:4], ssl_sha256=good))

    def test_search_by_name_cn_san(self):
        self.create(ssl_data(name="web-cert", ssl_cn="www.shop.example.com", ssl_san="www.shop.example.com\nm.shop.example.com"))
        self.create(lic_data(name="other"))
        f = lambda q: self.names(self.client.get("/licenses?q=" + q).text)
        self.assertEqual(f("web-cert"), ["web-cert"])
        self.assertEqual(f("www.shop"), ["web-cert"])
        self.assertEqual(f("m.shop"), ["web-cert"])
        self.assertEqual(f("%25"), [])
        self.assertEqual(f("zzz"), [])

    def test_search_never_matches_sensitive_fields(self):
        self.create(license_key=KEY, account_info=ACCOUNT)
        self.assertEqual(self.names(self.client.get("/licenses?q=WXYZ").text), [])
        self.assertEqual(self.names(self.client.get("/licenses?q=Secret").text), [])


class CommonFieldTests(LicenseCase):
    def test_expiry_rules(self):
        self.create(no_expiry="on", expires_at="", billing_cycle="영구")
        for bad, msg in ((dict(expires_at=""), "만료일을 입력하거나"), (dict(no_expiry="on"), "함께 지정할 수 없습니다"),
                         (dict(start_date="2027-01-01", expires_at="2026-01-01"), "시작일보다 빠를 수 없습니다"),
                         (dict(expires_at="2026-02-30"), "YYYY-MM-DD")):
            r = self.post_form("/licenses/new", **lic_data(**bad))
            self.assertEqual(r.status_code, 422, bad)
            self.assertIn(msg, r.text, bad)

    def test_field_validation(self):
        bads = dict(name=["", "x" * 201], license_type=["영수증"], vendor=["x" * 101], quantity=["-1", "abc", "10000001"],
                    cost=["-5", "nan", "inf", "abc", "1e13"], currency=["KR", "12A", "KRWW", "원화"], billing_cycle=["분기"],
                    alert_days=["-1", "366", "abc", ""], notes=["x" * 4001], start_date=["yesterday"], owner_id=["x", "999"])
        for field, values in bads.items():
            for value in values:
                self.assertEqual(self.post_form("/licenses/new", **lic_data(**{field: value})).status_code, 422, (field, value))
        self.assertEqual(self.one("SELECT COUNT(*) FROM licenses")[0], 0)
        self.create(currency="usd", quantity="0", cost="0", alert_days="0")
        self.assertEqual(self.one("SELECT currency FROM licenses")[0], "USD")

    def test_extra_fields_rejected(self):
        for extra in ("created_by", "last_verified_at", "license_key_enc", "id"):
            self.assertEqual(self.post_form("/licenses/new", **lic_data(**{extra: "x"})).status_code, 422, extra)

    def test_create_saves_everything_and_audits(self):
        lid = self.create(tags="Cert, 갱신", owner_id=str(self.editor2), auto_renew="on")
        row = self.lic(lid)
        self.assertEqual((row["name"], row["quantity"], row["cost"], row["billing_cycle"], row["auto_renew"], row["owner_id"]),
                         ("IDE 라이선스", 50, 1200000.0, "연", 1, self.editor2))
        self.assertEqual(assets.get_tags(self.conn, "license", lid), ["cert", "갱신"])
        self.assertIsNone(row["last_verified_at"])
        audit = self.one("SELECT * FROM audit_logs WHERE action='license_create'")
        self.assertEqual((audit["target_type"], audit["target_id"]), ("license", lid))

    def test_edit_updates_and_does_not_verify(self):
        lid = self.create()
        self.conn.execute("UPDATE licenses SET last_verified_at='2020-01-01T00:00:00Z' WHERE id=?", (lid,))
        self.post_form(f"/licenses/{lid}/edit", **lic_data(name="새 이름", quantity="60"))
        row = self.lic(lid)
        self.assertEqual((row["name"], row["quantity"], row["last_verified_at"]), ("새 이름", 60, "2020-01-01T00:00:00Z"))
        self.assertIn("quantity: 50 → 60", self.one("SELECT summary FROM audit_logs WHERE action='license_update'")[0])

    def test_owner_rules(self):
        self.conn.execute("UPDATE users SET is_active=0 WHERE id=?", (self.editor2,))
        r = self.post_form("/licenses/new", **lic_data(owner_id=str(self.editor2)))
        self.assertIn("활성 사용자만", r.text)
        lid = self.create(owner_id=str(self.editor))
        self.conn.execute("UPDATE users SET is_active=0 WHERE id=?", (self.editor,))
        self.login(self.admin)
        self.assertIn("비활성 담당자", self.client.get("/licenses").text)
        self.assertIn("비활성 담당자", self.client.get(f"/licenses/{lid}").text)
        self.assertEqual(self.post_form(f"/licenses/{lid}/edit", **lic_data(owner_id=str(self.editor), name="x")).status_code, 303)

    def test_freshness_notes_history(self):
        lid = self.create()
        self.assertIn("확인 필요", self.client.get(f"/licenses/{lid}").text)
        self.post_form(f"/licenses/{lid}/verify")
        self.assertIsNotNone(self.lic(lid)["last_verified_at"])
        self.post_form(f"/licenses/{lid}/notes", content="인증서 갱신 완료")
        html = self.client.get(f"/licenses/{lid}").text
        self.assertIn("인증서 갱신 완료", html)
        for action in ("license_create", "license_verify", "license_note_add"):
            self.assertIn(action, html.split("변경 이력")[1])

    def test_escaping(self):
        lid = self.create(name="<script>alert(1)</script>", vendor="<img src=x onerror=alert(1)>")
        for path in ("/licenses", f"/licenses/{lid}"):
            html = self.client.get(path).text
            self.assertNotIn("<script>alert(1)", html)
            self.assertNotIn("<img src=x", html)


class ListTests(LicenseCase):
    def test_default_sort_is_expiry_ascending_with_permanent_last(self):
        self.create(name="late", expires_at=rel(200))
        self.create(name="forever", no_expiry="on", expires_at="")
        self.create(name="soon", expires_at=rel(3))
        self.create(name="expired", expires_at=rel(-10))
        self.assertEqual(self.names(self.client.get("/licenses").text), ["expired", "soon", "late", "forever"])
        self.assertEqual(self.names(self.client.get("/licenses?sort=name").text), ["expired", "forever", "late", "soon"])

    def test_pagination_and_filters(self):
        for i in range(45):
            self.create(name=f"lic{i:03d}", expires_at=rel(100 + i))
        p = [self.client.get(f"/licenses?page={n}").text.split("<tbody>")[1].count("<tr>") for n in (1, 2, 3)]
        self.assertEqual(p, [20, 20, 5])
        self.conn.execute("DELETE FROM licenses")
        a = self.create(name="A", license_type="구독(SaaS)", tags="t1", owner_id=str(self.editor))
        b = self.create(name="B", owner_id=str(self.editor2))
        self.conn.execute("UPDATE licenses SET last_verified_at='2099-01-01T00:00:00Z' WHERE id=?", (a,))
        f = lambda qs: sorted(self.names(self.client.get("/licenses?" + qs).text))
        self.assertEqual(f("license_type=구독(SaaS)"), ["A"])
        self.assertEqual(f("tag=t1"), ["A"])
        self.assertEqual(f(f"owner_id={self.editor2}"), ["B"])
        self.assertEqual(f("stale=on"), ["B"])
        self.assertEqual(f("mine=on"), ["A"])
        self.login(self.editor2)
        self.assertEqual(f("mine=on"), ["B"])

    def test_invalid_filters(self):
        self.create()
        for qs in ("expiry=곧", "license_type=x", "sort=expires_at;DROP", "page=0", "evil=1", "owner_id=x"):
            self.assertIn("조회 조건이 올바르지 않습니다", self.client.get("/licenses?" + qs).text, qs)
        self.assertEqual(self.one("SELECT COUNT(*) FROM licenses")[0], 1)


class ConnectionTests(LicenseCase):
    def setUp(self):
        super().setUp()
        self.lid = self.create(name="공용 인증서", expires_at=rel(10))
        self.srv = self.server(self.editor, hostname="lic-srv", name="라이선스 서버")
        self.svc = self.service(self.editor, code="LIC-SVC", name="라이선스 서비스", tier=1)

    def test_connect_and_disconnect_server(self):
        r = self.post_form(f"/licenses/{self.lid}/servers/new", server_id=str(self.srv))
        self.assertEqual((r.status_code, r.headers["location"]), (303, f"/licenses/{self.lid}#servers"))
        self.assertIn("라이선스 서버", self.client.get(f"/licenses/{self.lid}").text)
        self.assertEqual(self.post_form(f"/licenses/{self.lid}/servers/new", server_id=str(self.srv)).status_code, 422)
        self.assertNotIn("라이선스 서버 (lic-srv)", self.client.get(f"/licenses/{self.lid}/servers/new").text)
        self.assertEqual(self.post_form(f"/licenses/{self.lid}/servers/new", server_id="999").status_code, 422)
        self.assertEqual(self.post_form(f"/licenses/{self.lid}/servers/new", server_id="abc").status_code, 422)
        self.assertEqual(self.post_form(f"/licenses/{self.lid}/servers/{self.srv}/delete").status_code, 303)
        self.assertEqual(self.one("SELECT COUNT(*) FROM license_servers")[0], 0)
        self.assertEqual(self.post_form(f"/licenses/{self.lid}/servers/{self.srv}/delete").status_code, 404)
        self.assertIsNotNone(self.one("SELECT 1 FROM servers WHERE id=?", self.srv))

    def test_connect_and_disconnect_service(self):
        self.assertEqual(self.post_form(f"/licenses/{self.lid}/services/new", service_id=str(self.svc)).status_code, 303)
        self.assertEqual(self.post_form(f"/licenses/{self.lid}/services/new", service_id=str(self.svc)).status_code, 422)
        self.assertEqual(self.post_form(f"/licenses/{self.lid}/services/new", service_id="999").status_code, 422)
        self.assertIn("LIC-SVC", self.client.get(f"/licenses/{self.lid}").text)
        self.assertEqual(self.post_form(f"/licenses/{self.lid}/services/{self.svc}/delete").status_code, 303)
        self.assertEqual(self.one("SELECT COUNT(*) FROM license_services")[0], 0)

    def test_server_and_service_details_show_licenses_with_expiry_badges(self):
        ai = self.create(ai_data(name="OpenAI 운영"))
        self.post_form(f"/licenses/{self.lid}/servers/new", server_id=str(self.srv))
        self.post_form(f"/licenses/{self.lid}/services/new", service_id=str(self.svc))
        self.post_form(f"/licenses/{ai}/services/new", service_id=str(self.svc))
        server_html = self.client.get(f"/servers/{self.srv}").text.split("연결된 라이선스")[1]
        self.assertIn("공용 인증서", server_html)
        self.assertIn('badge-orange">만료 임박 D-10', server_html)
        service_html = self.client.get(f"/services/{self.svc}").text
        plain, ai_group = service_html.split("연결된 라이선스")[1].split("연결된 AI API")
        self.assertIn("공용 인증서", plain)
        self.assertNotIn("OpenAI 운영", plain)                                  # AI API는 별도 묶음
        self.assertIn("OpenAI 운영", ai_group.split("<section")[0] if "<section" in ai_group else ai_group)

    def test_deleting_server_or_service_removes_connections(self):
        self.post_form(f"/licenses/{self.lid}/servers/new", server_id=str(self.srv))
        self.post_form(f"/licenses/{self.lid}/services/new", service_id=str(self.svc))
        self.post_form(f"/servers/{self.srv}/delete")
        self.post_form(f"/services/{self.svc}/delete")
        self.assertEqual(self.one("SELECT COUNT(*) FROM license_servers")[0] + self.one("SELECT COUNT(*) FROM license_services")[0], 0)
        self.assertIsNotNone(self.lic(self.lid))

    def test_permissions(self):
        self.login(self.viewer)
        self.assertEqual(self.post_form(f"/licenses/{self.lid}/servers/new", server_id=str(self.srv)).status_code, 403)
        self.assertEqual(self.post_form(f"/licenses/{self.lid}/servers/{self.srv}/delete").status_code, 403)


class DeleteTests(LicenseCase):
    def test_confirm_warns_about_models_and_get_does_not_delete(self):
        lid = self.create(ai_data())
        self.conn.execute("INSERT INTO models (name, version, model_type, source, description, status, license_id, "
                          "created_at, created_by, updated_at, updated_by) VALUES ('gpt-wrapper', '1', 'LLM', '상용 API', 'd', "
                          "'운영', ?, 'x', ?, 'x', ?)", (lid, self.editor, self.editor))
        r = self.client.get(f"/licenses/{lid}/delete")
        self.assertIn("사용하는 AI 모델이 1개", r.text)
        self.assertIn("gpt-wrapper", r.text)
        self.assertIsNotNone(self.lic(lid))
        detail = self.client.get(f"/licenses/{lid}").text
        self.assertIn("gpt-wrapper", detail)

    def test_delete_cleans_everything_without_orphans(self):
        lid = self.create(license_key=KEY, tags="keep,gone")
        other = self.create(name="다른", tags="keep")
        self.post_form(f"/licenses/{lid}/notes", content="삭제될 메모")
        self.post_form(f"/licenses/{other}/notes", content="남을 메모")
        srv = self.server(self.editor, hostname="d1")
        svc = self.service(self.editor, code="D-1")
        self.conn.execute("INSERT INTO license_servers VALUES (?, ?)", (lid, srv))
        self.conn.execute("INSERT INTO license_services VALUES (?, ?)", (lid, svc))
        ai = self.create(ai_data())
        mdl = self.model(self.editor, source="상용 API", license_id=ai)
        self.assertEqual(self.post_form(f"/licenses/{ai}/delete").status_code, 303)
        self.assertIsNone(self.one("SELECT license_id FROM models WHERE id=?", mdl)[0])     # 모델은 남고 연결만 해제
        r = self.post_form(f"/licenses/{lid}/delete")
        self.assertEqual((r.status_code, r.headers["location"]), (303, "/licenses"))
        q = lambda sql, *p: self.one(sql, *p)[0]
        self.assertEqual(q("SELECT COUNT(*) FROM license_servers"), 0)
        self.assertEqual(q("SELECT COUNT(*) FROM license_services"), 0)
        self.assertEqual(q("SELECT COUNT(*) FROM asset_tags WHERE asset_type='license' AND asset_id=?", lid), 0)
        self.assertEqual(q("SELECT COUNT(*) FROM asset_notes WHERE asset_type='license' AND asset_id=?", lid), 0)
        self.assertEqual(q("SELECT COUNT(*) FROM asset_tags WHERE asset_type='license' AND asset_id=?", other), 1)
        self.assertEqual(q("SELECT COUNT(*) FROM asset_notes WHERE asset_id=?", other), 1)
        self.assertEqual((q("SELECT COUNT(*) FROM servers"), q("SELECT COUNT(*) FROM services"), q("SELECT COUNT(*) FROM models")), (1, 1, 1))
        summary = self.one("SELECT summary FROM audit_logs WHERE action='license_delete' ORDER BY id DESC")[0]
        self.assertNotIn(KEY, summary)

    def test_viewer_cannot_delete(self):
        lid = self.create()
        self.login(self.viewer)
        self.assertEqual(self.post_form(f"/licenses/{lid}/delete").status_code, 403)
        self.assertIsNotNone(self.lic(lid))
