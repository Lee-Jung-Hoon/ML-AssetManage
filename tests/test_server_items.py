from app import assets
from tests.test_servers import ServerCase


class ItemCase(ServerCase):
    def setUp(self):
        super().setUp()
        self.sid = self.server(self.editor, hostname="items-1", name="아이템 서버")

    def add(self, slug, expect=303, **data):
        r = self.post_form(f"/servers/{self.sid}/{slug}/new", **data)
        self.assertEqual(r.status_code, expect, r.text[-800:] if r.status_code != expect else "")
        return r

    def one(self, sql, *params):
        return self.conn.execute(sql, params).fetchone()

    def count(self, table):
        return self.one(f"SELECT COUNT(*) FROM {table}")[0]


class PermissionTests(ItemCase):
    KINDS = ("ips", "disks", "gpus", "host-services", "containers", "acls")

    def test_viewer_can_read_sections_but_not_change(self):
        self.add("gpus", gpu_model="H100", quantity="8")
        self.login(self.viewer)
        html = self.client.get(f"/servers/{self.sid}").text
        for title in ("IP 주소", "디스크", "GPU", "호스트 서비스", "Docker 컨테이너", "ACL 요청"):
            self.assertIn(title, html)
        self.assertIn("H100", html)
        self.assertNotIn("/gpus/new", html)
        for kind in self.KINDS:
            self.assertEqual(self.client.get(f"/servers/{self.sid}/{kind}/new").status_code, 403, kind)
            self.assertEqual(self.post_form(f"/servers/{self.sid}/{kind}/new", gpu_model="x").status_code, 403, kind)
        gid = self.one("SELECT id FROM server_gpus")[0]
        self.assertEqual(self.client.get(f"/servers/{self.sid}/gpus/{gid}/edit").status_code, 403)
        self.assertEqual(self.post_form(f"/servers/{self.sid}/gpus/{gid}/edit", gpu_model="x", quantity="1").status_code, 403)
        self.assertEqual(self.post_form(f"/servers/{self.sid}/gpus/{gid}/delete").status_code, 403)
        self.assertEqual(self.count("server_gpus"), 1)

    def test_unauthenticated_and_csrf(self):
        for kind in self.KINDS:
            self.assertEqual(self.post_form(f"/servers/{self.sid}/{kind}/new", csrf_token="bad").status_code, 403, kind)
        self.client.cookies.clear()
        self.assertEqual(self.client.get(f"/servers/{self.sid}/ips/new").status_code, 303)
        self.assertEqual(self.post("/servers/1/ips/new", "ip=1.1.1.1").status_code, 303)

    def test_unknown_kind_or_server_or_item_is_404(self):
        self.assertEqual(self.client.get(f"/servers/{self.sid}/bogus/new").status_code, 404)
        self.assertEqual(self.client.get("/servers/999/ips/new").status_code, 404)
        self.assertEqual(self.post_form("/servers/999/ips/new", ip="1.1.1.1", kind="사설").status_code, 404)
        self.assertEqual(self.client.get(f"/servers/{self.sid}/ips/999/edit").status_code, 404)
        self.assertEqual(self.post_form(f"/servers/{self.sid}/ips/999/delete").status_code, 404)

    def test_item_cannot_be_reached_through_another_server(self):
        self.add("ips", ip="10.0.0.1", kind="사설")
        iid = self.one("SELECT id FROM server_ips")[0]
        other = self.server(self.editor, hostname="other-1")
        self.assertEqual(self.client.get(f"/servers/{other}/ips/{iid}/edit").status_code, 404)
        self.assertEqual(self.post_form(f"/servers/{other}/ips/{iid}/delete").status_code, 404)
        self.assertEqual(self.post_form(f"/servers/{other}/ips/{iid}/edit", ip="9.9.9.9", kind="사설").status_code, 404)
        self.assertEqual(self.one("SELECT ip FROM server_ips")[0], "10.0.0.1")

    def test_extra_fields_rejected(self):
        self.add("ips", 422, ip="10.0.0.1", kind="사설", server_id="99")
        self.assertEqual(self.count("server_ips"), 0)


class IPTests(ItemCase):
    def test_valid_and_normalized(self):
        for raw, norm in (("10.0.0.1", "10.0.0.1"), ("2001:DB8:0:0:0:0:0:1", "2001:db8::1"), (" 192.168.1.5 ", "192.168.1.5")):
            self.add("ips", ip=raw, kind="사설")
            self.assertEqual(self.one("SELECT ip FROM server_ips ORDER BY id DESC")[0], norm)

    def test_invalid_ips(self):
        for bad in ("", "999.1.1.1", "10.0.0", "abc", "10.0.0.1/24", "fe80::1%eth0", "10.0.0.1 ; DROP", "1.1.1.1.1",
                    "::g", "x" * 46):
            self.add("ips", 422, ip=bad, kind="사설")
        self.add("ips", 422, ip="10.0.0.1", kind="없는유형")
        self.assertEqual(self.count("server_ips"), 0)

    def test_duplicate_ip_on_same_server_rejected_other_server_ok(self):
        self.add("ips", ip="10.0.0.1", kind="사설")
        r = self.add("ips", 422, ip="10.0.0.1", kind="공인")
        self.assertIn("이미 등록된", r.text)
        other = self.server(self.editor, hostname="o1")
        self.assertEqual(self.post_form(f"/servers/{other}/ips/new", ip="10.0.0.1", kind="사설").status_code, 303)

    def test_only_one_primary_ip_auto_demotes(self):
        self.add("ips", ip="10.0.0.1", kind="사설", is_primary="on")
        self.add("ips", ip="10.0.0.2", kind="사설", is_primary="on")
        rows = self.conn.execute("SELECT ip, is_primary FROM server_ips ORDER BY id").fetchall()
        self.assertEqual([(r[0], r[1]) for r in rows], [("10.0.0.1", 0), ("10.0.0.2", 1)])
        self.add("ips", ip="10.0.0.3", kind="사설")
        self.assertEqual(self.one("SELECT COUNT(*) FROM server_ips WHERE is_primary=1")[0], 1)
        # 수정으로 대표 지정 시에도 단 하나
        first = self.one("SELECT id FROM server_ips WHERE ip='10.0.0.1'")[0]
        self.post_form(f"/servers/{self.sid}/ips/{first}/edit", ip="10.0.0.1", kind="사설", is_primary="on")
        self.assertEqual(self.one("SELECT ip FROM server_ips WHERE is_primary=1")[0], "10.0.0.1")
        self.assertEqual(self.one("SELECT COUNT(*) FROM server_ips WHERE is_primary=1")[0], 1)

    def test_primary_ip_shown_in_server_list_and_search_finds_any_ip(self):
        self.add("ips", ip="10.0.0.9", kind="사설")
        self.add("ips", ip="10.0.0.1", kind="사설", is_primary="on")
        html = self.client.get("/servers").text
        self.assertIn("10.0.0.1", html)
        self.assertNotIn("10.0.0.9", html)
        self.assertIn("아이템 서버", self.client.get("/servers?q=10.0.0.9").text)


class DiskTests(ItemCase):
    BASE = dict(mount_point="/data", disk_type="SSD", total_gb="500", used_gb="100")

    def test_add_and_display_usage(self):
        self.add("disks", **self.BASE, device="/dev/sda1", filesystem="ext4", raid="RAID10", measured_at="2026-01-01")
        row = self.one("SELECT * FROM server_disks")
        self.assertEqual((row["total_gb"], row["used_gb"], row["measured_at"]), (500.0, 100.0, "2026-01-01"))
        html = self.client.get(f"/servers/{self.sid}").text
        self.assertIn("100 / 500 GB", html)
        self.assertIn("20%", html)
        self.assertIn("2026-01-01", html)

    def test_measured_at_optional_and_flagged_when_missing(self):
        self.add("disks", **self.BASE)
        self.assertIsNone(self.one("SELECT measured_at FROM server_disks")[0])
        self.assertIn("미기재", self.client.get(f"/servers/{self.sid}").text)

    def test_used_cannot_exceed_total_but_may_equal(self):
        self.add("disks", **{**self.BASE, "used_gb": "500"})
        r = self.add("disks", 422, **{**self.BASE, "used_gb": "500.1"})
        self.assertIn("전체 용량을 넘을 수 없습니다", r.text)

    def test_numeric_validation(self):
        for field, bad in (("total_gb", "0"), ("total_gb", "-1"), ("total_gb", "nan"), ("total_gb", "inf"),
                           ("total_gb", "abc"), ("total_gb", ""), ("used_gb", "-1"), ("used_gb", "nan"),
                           ("used_gb", ""), ("total_gb", "1e9")):
            self.add("disks", 422, **{**self.BASE, field: bad})
        for bad_date in ("2026-13-01", "yesterday", "2026/01/01"):
            self.add("disks", 422, **{**self.BASE, "measured_at": bad_date})
        self.add("disks", 422, **{**self.BASE, "disk_type": "tape"})
        self.add("disks", 422, **{**self.BASE, "mount_point": ""})
        self.assertEqual(self.count("server_disks"), 0)

    def test_usage_color_thresholds_in_list(self):
        for mount, used, level in (("/a", 79, "green"), ("/b", 80, "orange"), ("/c", 89, "orange"), ("/d", 90, "red")):
            self.conn.execute("DELETE FROM server_disks")
            self.add("disks", mount_point=mount, disk_type="SSD", total_gb="100", used_gb=str(used))
            html = self.client.get("/servers").text.split("<tbody>")[1]
            self.assertIn(f"badge-{level}\">{used}%", html, (used, level))
            self.assertIn(f"bar-{level}", html)

    def test_edit_updates_and_audits(self):
        self.add("disks", **self.BASE)
        did = self.one("SELECT id FROM server_disks")[0]
        before = self.one("SELECT updated_at FROM servers")[0]
        self.conn.execute("UPDATE servers SET updated_at='2020-01-01T00:00:00Z'")
        r = self.post_form(f"/servers/{self.sid}/disks/{did}/edit", **{**self.BASE, "used_gb": "250"})
        self.assertEqual((r.status_code, r.headers["location"]), (303, f"/servers/{self.sid}#disks"))
        self.assertEqual(self.one("SELECT used_gb FROM server_disks")[0], 250.0)
        self.assertNotEqual(self.one("SELECT updated_at FROM servers")[0], "2020-01-01T00:00:00Z")   # 서버 수정일 갱신
        audit = self.one("SELECT * FROM audit_logs WHERE action='server_disks_update'")
        self.assertEqual((audit["target_type"], audit["target_id"]), ("server", self.sid))
        self.assertIn("used_gb: 100.0 → 250.0", audit["summary"])
        self.assertIn("/data", audit["summary"])

    def test_form_prefilled_and_delete(self):
        self.add("disks", **self.BASE, notes="메모")
        did = self.one("SELECT id FROM server_disks")[0]
        html = self.client.get(f"/servers/{self.sid}/disks/{did}/edit").text
        self.assertIn('value="/data"', html)
        self.assertIn('value="500"', html)
        r = self.post_form(f"/servers/{self.sid}/disks/{did}/delete")
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.count("server_disks"), 0)
        self.assertEqual(self.client.get(f"/servers/{self.sid}/disks/{did}/delete").status_code, 405)
        self.assertEqual(len(self.conn.execute("SELECT 1 FROM audit_logs WHERE action='server_disks_delete'").fetchall()), 1)


class GPUTests(ItemCase):
    BASE = dict(gpu_model="A100 80GB", quantity="8", vram_gb="80")

    def test_total_vram_and_summary_calculated_not_stored(self):
        self.add("gpus", **self.BASE, driver_version="550.54.15", cuda_version="12.4", nvlink="on",
                 assigned_to="추천팀", mig_config="")
        self.add("gpus", gpu_model="L4", quantity="2", vram_gb="24")
        cols = [r[1] for r in self.conn.execute("PRAGMA table_info(server_gpus)")]
        self.assertNotIn("total_vram", cols)
        html = self.client.get(f"/servers/{self.sid}").text
        self.assertIn("640 GB", html)                                       # 8 × 80
        self.assertIn("48 GB", html)                                        # 2 × 24
        self.assertIn("총 GPU <strong>10장</strong>", html)
        self.assertIn("총 VRAM <strong>688 GB</strong>", html)
        self.assertIn("A100 80GB ×8", self.client.get("/servers").text)

    def test_quantity_range(self):
        for ok in ("1", "16"):
            self.add("gpus", gpu_model="T4", quantity=ok)
        for bad in ("0", "17", "-1", "abc", "", "1.5"):
            self.add("gpus", 422, gpu_model="T4", quantity=bad)
        self.assertEqual(self.count("server_gpus"), 2)

    def test_vram_range_and_optional(self):
        self.add("gpus", gpu_model="T4", quantity="1")
        self.assertIsNone(self.one("SELECT vram_gb FROM server_gpus")[0])
        self.assertIn("총 GPU <strong>1장</strong>", self.client.get(f"/servers/{self.sid}").text)
        for bad in ("0", "-5", "1025", "x"):
            self.add("gpus", 422, gpu_model="T4", quantity="1", vram_gb=bad)

    def test_version_formats(self):
        for ok in ("550.54.15", "12.4", "12", "", "535.104.05"):
            self.add("gpus", gpu_model="T4", quantity="1", driver_version=ok, cuda_version=ok)
        for bad in ("550.54.", ".5", "12,4", "v12.4", "12.4-beta", "1..2", "a", "12 4", "<b>"):
            self.add("gpus", 422, gpu_model="T4", quantity="1", driver_version=bad)
            self.add("gpus", 422, gpu_model="T4", quantity="1", cuda_version=bad)

    def test_model_required_and_suggestions_listed(self):
        self.add("gpus", 422, gpu_model="", quantity="1")
        self.add("gpus", gpu_model="내가 정한 GPU", quantity="1")                # 자유 입력
        form = self.client.get(f"/servers/{self.sid}/gpus/new").text
        for model in ("H200", "H100", "A100 80GB", "A100 40GB", "L40S", "L4", "A10", "T4", "RTX 6000 Ada", "RTX 4090"):
            self.assertIn(f'<option value="{model}">', form)
        self.assertIn("<datalist", form)

    def test_unassigned_flag(self):
        self.add("gpus", **self.BASE, assigned_to="")
        self.add("gpus", gpu_model="T4", quantity="1", assigned_to="  ")
        self.add("gpus", gpu_model="L4", quantity="1", assigned_to="추천팀")
        self.assertEqual(self.one("SELECT COUNT(*) FROM server_gpus WHERE assigned_to=''")[0], 2)
        html = self.client.get(f"/servers/{self.sid}").text
        self.assertEqual(html.count("badge-orange\">미할당</span>"), 2)
        self.assertIn("미할당 2행", html)

    def test_edit_gpu(self):
        self.add("gpus", **self.BASE)
        gid = self.one("SELECT id FROM server_gpus")[0]
        self.post_form(f"/servers/{self.sid}/gpus/{gid}/edit", gpu_model="A100 80GB", quantity="4", vram_gb="80",
                       nvlink="on")
        row = self.one("SELECT quantity, nvlink FROM server_gpus")
        self.assertEqual((row[0], row[1]), (4, 1))
        self.assertIn("checked", self.client.get(f"/servers/{self.sid}/gpus/{gid}/edit").text)


class HostServiceTests(ItemCase):
    def test_add_with_and_without_port(self):
        self.add("host-services", name="nginx", run_type="systemd", port="443", protocol="TCP", version="1.25")
        self.add("host-services", name="cron", run_type="프로세스", port="", protocol="")
        rows = self.conn.execute("SELECT name, port, protocol FROM host_services ORDER BY id").fetchall()
        self.assertEqual([tuple(r) for r in rows], [("nginx", 443, "TCP"), ("cron", None, None)])
        html = self.client.get(f"/servers/{self.sid}").text
        self.assertIn("443/TCP", html)

    def test_validation(self):
        for bad in (dict(name="", run_type="systemd"), dict(name="x", run_type="init.d"),
                    dict(name="x", run_type="systemd", port="0"), dict(name="x", run_type="systemd", port="65536"),
                    dict(name="x", run_type="systemd", port="abc"), dict(name="x", run_type="systemd", protocol="ICMP")):
            self.add("host-services", 422, **bad)
        self.assertEqual(self.count("host_services"), 0)


class ContainerTests(ItemCase):
    BASE = dict(name="web", image="nginx:1.25")

    def test_gpu_device_format(self):
        for ok in ("0", "0,1", "0,1,2,3", " 0 , 1 "):
            self.add("containers", **self.BASE, gpu_usage="특정 디바이스", gpu_devices=ok)
        self.assertEqual({r[0] for r in self.conn.execute("SELECT gpu_devices FROM server_containers")},
                         {"0", "0,1", "0,1,2,3"})
        for bad in ("a", "0,,1", "0,1,", ",0", "0;1", "-1", "0 1", "0.5", "GPU-abc", "<b>"):
            self.add("containers", 422, **self.BASE, gpu_usage="특정 디바이스", gpu_devices=bad)
        self.add("containers", 422, **self.BASE, gpu_usage="특정 디바이스", gpu_devices="")        # 번호 필수

    def test_devices_cleared_unless_specific(self):
        self.add("containers", **self.BASE, gpu_usage="전체", gpu_devices="0,1")
        self.add("containers", **{**self.BASE, "name": "db"}, gpu_usage="없음", gpu_devices="3")
        self.assertEqual({r[0] for r in self.conn.execute("SELECT gpu_devices FROM server_containers")}, {""})
        html = self.client.get(f"/servers/{self.sid}").text
        self.assertIn("전체", html)

    def test_invalid_device_format_rejected_even_when_not_specific(self):
        self.add("containers", 422, **self.BASE, gpu_usage="없음", gpu_devices="abc")

    def test_port_mappings(self):
        self.add("containers", **self.BASE, port_mappings="8080:80, 127.0.0.1:5432:5432/tcp,9000-9010:9000-9010")
        self.assertEqual(self.one("SELECT port_mappings FROM server_containers")[0],
                         "8080:80, 127.0.0.1:5432:5432/tcp, 9000-9010:9000-9010")
        for bad in ("abc", "8080:", "70000:80", "80:99999", "8080:80;rm", "<script>"):
            self.add("containers", 422, **{**self.BASE, "name": "bad"}, port_mappings=bad)

    def test_required_and_enum(self):
        self.add("containers", 422, name="", image="x")
        self.add("containers", 422, name="x", image="")
        self.add("containers", 422, **self.BASE, gpu_usage="일부")
        self.assertEqual(self.count("server_containers"), 0)

    def test_compose_project_and_edit_roundtrip(self):
        self.add("containers", **self.BASE, compose_project="shop", status="running")
        cid = self.one("SELECT id FROM server_containers")[0]
        html = self.client.get(f"/servers/{self.sid}/containers/{cid}/edit").text
        self.assertIn('value="shop"', html)
        self.post_form(f"/servers/{self.sid}/containers/{cid}/edit", **self.BASE, compose_project="shop2", status="exited")
        self.assertEqual(self.one("SELECT compose_project, status FROM server_containers")[:], ("shop2", "exited"))


class ACLTests(ItemCase):
    BASE = dict(direction="Inbound", src_cidr="10.0.0.0/24", dst_cidr="10.1.0.5", port="443", protocol="TCP",
                purpose="결제 연동", requester="홍길동", requested_at="2026-03-01", status="요청")

    def test_normalization_and_storage(self):
        self.add("acls", **{**self.BASE, "src_cidr": "10.0.0.77/24", "port": "8000 - 8100"})
        row = self.one("SELECT * FROM server_acls")
        self.assertEqual((row["src_cidr"], row["dst_cidr"], row["port_start"], row["port_end"]),
                         ("10.0.0.0/24", "10.1.0.5/32", 8000, 8100))
        self.add("acls", **{**self.BASE, "src_cidr": "2001:db8::1234/64", "dst_cidr": "::1"})
        self.assertEqual(self.one("SELECT src_cidr, dst_cidr FROM server_acls ORDER BY id DESC")[:],
                         ("2001:db8::/64", "::1/128"))
        html = self.client.get(f"/servers/{self.sid}").text
        self.assertIn("8000-8100/TCP", html)
        self.assertIn("10.0.0.0/24", html)

    def test_single_port_stored_as_equal_start_end(self):
        self.add("acls", **self.BASE)
        row = self.one("SELECT port_start, port_end FROM server_acls")
        self.assertEqual((row[0], row[1]), (443, 443))
        self.assertIn("443/TCP", self.client.get(f"/servers/{self.sid}").text)

    def test_invalid_cidrs(self):
        for bad in ("", "10.0.0.0/33", "300.0.0.0/8", "10.0.0.0/-1", "abc", "10.0.0.0/24/1", "::g/64", "10.0.0.0 /24",
                    "fe80::1%eth0", "10.0.0.0/255.0.0.0.0"):
            self.add("acls", 422, **{**self.BASE, "src_cidr": bad})
            self.add("acls", 422, **{**self.BASE, "dst_cidr": bad})
        self.assertEqual(self.count("server_acls"), 0)

    def test_port_validation(self):
        for ok in ("1", "65535", "1-65535", "80-80"):
            self.add("acls", **{**self.BASE, "port": ok})
        for bad in ("0", "65536", "0-10", "10-65536", "100-10", "-5", "80-", "abc", "80,443", "", "1-2-3", "８０"):
            self.add("acls", 422, **{**self.BASE, "port": bad})
        self.assertEqual(self.count("server_acls"), 4)

    def test_enums_and_dates(self):
        for key, bad in (("direction", "Both"), ("protocol", "ICMP"), ("status", "대기"), ("requested_at", ""),
                         ("requested_at", "2026-02-30"), ("expires_at", "soon"), ("purpose", ""), ("requester", ""),
                         ("ticket_no", "x" * 51), ("purpose", "x" * 1001)):
            self.add("acls", 422, **{**self.BASE, key: bad})
        for ok_status in ("요청", "승인", "적용완료", "반려", "회수"):
            self.add("acls", **{**self.BASE, "status": ok_status})

    def test_expiry_not_before_request(self):
        self.add("acls", **self.BASE, expires_at="2026-03-01")
        r = self.add("acls", 422, **self.BASE, expires_at="2026-02-28")
        self.assertIn("요청일보다 빠를 수 없습니다", r.text)
        self.add("acls", **self.BASE, expires_at="")

    def test_expired_acl_flagged_and_status_badge(self):
        self.add("acls", **{**self.BASE, "status": "적용완료"}, expires_at="2026-03-02")
        html = self.client.get(f"/servers/{self.sid}").text
        self.assertIn("만료됨", html)
        self.assertIn("badge-green\">적용완료", html)

    def test_edit_roundtrip_keeps_values(self):
        self.add("acls", **self.BASE, ticket_no="REQ-1")
        aid = self.one("SELECT id FROM server_acls")[0]
        html = self.client.get(f"/servers/{self.sid}/acls/{aid}/edit").text
        self.assertIn('value="10.0.0.0/24"', html)
        self.assertIn('value="443"', html)
        self.assertIn("REQ-1", html)
        r = self.post_form(f"/servers/{self.sid}/acls/{aid}/edit", **{**self.BASE, "status": "승인", "port": "443-444"})
        self.assertEqual(r.status_code, 303)
        row = self.one("SELECT status, port_start, port_end FROM server_acls")
        self.assertEqual(row[:], ("승인", 443, 444))
        self.assertIn('value="443-444"', self.client.get(f"/servers/{self.sid}/acls/{aid}/edit").text)

    def test_values_are_escaped(self):
        self.add("acls", **{**self.BASE, "purpose": "<script>alert(1)</script>", "requester": "<b>x</b>"})
        html = self.client.get(f"/servers/{self.sid}").text
        self.assertNotIn("<script>alert(1)", html)
        self.assertNotIn("<b>x</b>", html)


class SectionRenderingTests(ItemCase):
    def test_empty_sections_and_cascade_on_server_delete(self):
        html = self.client.get(f"/servers/{self.sid}").text
        self.assertEqual(html.count("등록된 항목이 없습니다."), 6)
        self.add("ips", ip="10.0.0.1", kind="사설")
        self.add("acls", **ACLTests.BASE)
        self.add("containers", name="c", image="i:1")
        self.post_form(f"/servers/{self.sid}/delete")
        for table in ("server_ips", "server_acls", "server_containers"):
            self.assertEqual(self.count(table), 0, table)

    def test_item_changes_appear_in_server_history(self):
        self.add("ips", ip="10.0.0.1", kind="사설")
        html = self.client.get(f"/servers/{self.sid}").text.split("변경 이력")[1]
        self.assertIn("server_ips_add", html)
        self.assertIn("10.0.0.1", html)

    def test_edit_validation_error_rerenders_with_input(self):
        self.add("gpus", gpu_model="T4", quantity="1")
        gid = self.one("SELECT id FROM server_gpus")[0]
        r = self.post_form(f"/servers/{self.sid}/gpus/{gid}/edit", gpu_model="유지되는 모델", quantity="99")
        self.assertEqual(r.status_code, 422)
        self.assertIn("유지되는 모델", r.text)
        self.assertIn("허용 범위", r.text)
        self.assertEqual(self.one("SELECT quantity FROM server_gpus")[0], 1)
