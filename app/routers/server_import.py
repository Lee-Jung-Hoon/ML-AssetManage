"""서버 일괄 등록 (CSV 붙여넣기, editor 이상). 1차 범위: 서버 기본 정보 신규 등록만 (하위 항목/업데이트 없음).

2단계로 처리한다.
  1. 검증(미리보기): 각 행을 단건 등록과 동일한 Pydantic 모델(ServerForm)로 검증하고 결과만 보여준다. 저장하지 않는다.
  2. 등록 확정: 미리보기의 숨은 필드로 같은 CSV가 다시 제출된다. 서버는 이를 신뢰하지 않고 처음부터 전체를 다시 검증하며,
     하나라도 오류가 있으면 전부 거부한다. 모두 유효하면 단일 트랜잭션으로 등록한다 (all-or-nothing).
"""
import csv
import ipaddress
import sqlite3
from dataclasses import dataclass, field

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse

from .. import assets, audit, csvio, security
from ..db import get_db, now_iso, transaction
from ..forms import csrf_form
from ..schemas import ImportForm, ServerForm, _ip_address, validate_form
from ..security import CurrentUser, require_login, require_role
from ..templating import render
from .servers import FIELDS, insert_server

router = APIRouter(dependencies=[Depends(require_login)])

HEADER = ["name", "hostname", "os_type", "os_distro", "os_version", "kernel_version", "environment", "status",
          "server_type", "location", "cpu_model", "cpu_cores", "memory_gb", "primary_ip", "owner_username", "tags",
          "description"]
EXAMPLES = [
    "결제 웹 1,pay-web-01,Linux,Ubuntu,22.04,5.15.0,prod,운영중,VM,IDC-A R12,Xeon Gold 6330,32,128,10.0.1.11,hong,payment;prod,결제 웹 서버",
    "GPU 학습 1,gpu-train-01,Linux,Rocky,9.3,5.14.0,prod,운영중,물리,IDC-B R03,AMD EPYC 7763,128,1024,10.0.2.21,kim,gpu;train,학습용 GPU 서버",
]
MAX_ROWS = csvio.MAX_IMPORT_ROWS


@dataclass
class RowResult:
    number: int                                   # 데이터 행 번호 (헤더 제외, 1부터)
    name: str = ""
    hostname: str = ""
    primary_ip: str = ""
    owner_username: str = ""
    errors: list[str] = field(default_factory=list)
    fields: dict | None = None                    # 검증을 통과한 서버 필드 (owner_id 해석 완료)
    tags: list[str] = field(default_factory=list)


@dataclass
class Analysis:
    error: str | None = None                      # 파일 전체 수준의 오류 (헤더, 행 수, 형식)
    rows: list[RowResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error is None and bool(self.rows) and all(not r.errors for r in self.rows)

    @property
    def error_rows(self) -> int:
        return sum(1 for r in self.rows if r.errors)


def analyze(conn: sqlite3.Connection, text: str) -> Analysis:
    """CSV 텍스트를 처음부터 끝까지 검증한다 (미리보기와 등록 확정이 같은 함수를 쓴다)."""
    try:
        table = csvio.parse_csv_text(text)
    except csv.Error:
        return Analysis(error="CSV 형식이 올바르지 않습니다 (따옴표 짝이나 필드 크기를 확인하세요).")
    if not table:
        return Analysis(error="CSV가 비어 있습니다.")
    if [c.strip() for c in table[0]] != HEADER:
        return Analysis(error="첫 줄은 정해진 헤더여야 합니다: " + ",".join(HEADER))
    data_rows = table[1:]
    if not data_rows:
        return Analysis(error="헤더 아래에 등록할 행이 없습니다.")
    if len(data_rows) > MAX_ROWS:
        return Analysis(error=f"한 번에 최대 {MAX_ROWS}행까지 등록할 수 있습니다 (현재 {len(data_rows)}행).")

    existing = {r[0].lower() for r in conn.execute("SELECT hostname FROM servers")}
    owners = {r["username"].lower(): r for r in conn.execute("SELECT username, id, is_active FROM users")}
    seen: dict[str, list[int]] = {}
    results: list[RowResult] = []
    for index, raw in enumerate(data_rows, start=1):
        row = RowResult(number=index)
        results.append(row)
        if len(raw) != len(HEADER):
            row.errors.append(f"컬럼 수가 {len(HEADER)}개여야 합니다 (현재 {len(raw)}개).")
            continue
        cells = dict(zip(HEADER, (c.strip() for c in raw)))
        row.name, row.hostname = cells["name"], cells["hostname"]
        row.primary_ip, row.owner_username = cells["primary_ip"], cells["owner_username"]

        form = {k: v for k, v in cells.items() if k not in ("primary_ip", "owner_username", "tags")}
        form["tags"] = ",".join(t for t in cells["tags"].split(";"))          # `;` 구분 → 단건 등록과 같은 규칙으로 검증
        data, errors = validate_form(ServerForm, form)
        for column, message in errors.items():
            row.errors.append(f"{'' if column == '__all__' else column + ': '}{message}")

        if cells["hostname"]:
            seen.setdefault(cells["hostname"].lower(), []).append(index)
            if cells["hostname"].lower() in existing:
                row.errors.append("hostname: 이미 등록된 호스트명입니다.")

        owner_id = None
        if cells["owner_username"]:
            owner = owners.get(cells["owner_username"].lower())
            if owner is None:
                row.errors.append("owner_username: 존재하지 않는 사용자입니다.")
            elif not owner["is_active"]:
                row.errors.append("owner_username: 비활성 사용자입니다.")
            else:
                owner_id = owner["id"]

        if cells["primary_ip"]:
            try:
                row.primary_ip = _ip_address(cells["primary_ip"])
            except ValueError as exc:
                row.errors.append(f"primary_ip: {exc}")

        if data is not None and not row.errors:
            row.fields = {f: getattr(data, f) for f in FIELDS}
            row.fields["owner_id"] = owner_id
            row.tags = data.tags

    for hostname, numbers in seen.items():     # CSV 내부 중복은 관련된 모든 행의 오류로 처리한다
        if len(numbers) > 1:
            for n in numbers:
                results[n - 1].errors.append("hostname: CSV 안에서 중복된 호스트명입니다 (행 " + ", ".join(map(str, numbers)) + ").")
                results[n - 1].fields = None
    return Analysis(rows=results)


def _page(request: Request, csv_text: str, analysis: Analysis | None, status: int = 200):
    return render(request, "servers/import.html", {
        "csv_text": csv_text, "analysis": analysis, "header": ",".join(HEADER), "examples": EXAMPLES,
        "max_rows": MAX_ROWS, "columns": HEADER}, status)


@router.get("/servers/import")
def import_form(request: Request, user: CurrentUser = Depends(require_role("editor"))):
    return _page(request, ",".join(HEADER) + "\n", None)


@router.post("/servers/import/preview")
def import_preview(request: Request, user: CurrentUser = Depends(require_role("editor")),
                   form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    """검증만 한다. 아무것도 저장하지 않는다."""
    data, errors = validate_form(ImportForm, form)
    text = data.csv if data else ""
    analysis = analyze(conn, text) if data else Analysis(error="CSV를 붙여 넣으세요.")
    return _page(request, text, analysis)


@router.post("/servers/import/commit")
def import_commit(request: Request, user: CurrentUser = Depends(require_role("editor")),
                  form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    """미리보기 결과를 신뢰하지 않는다: 제출된 CSV 전체를 처음부터 다시 검증하고, 오류가 하나라도 있으면 전부 거부한다."""
    data, errors = validate_form(ImportForm, form)
    text = data.csv if data else ""
    analysis = analyze(conn, text) if data else Analysis(error="CSV를 붙여 넣으세요.")
    if not analysis.ok:
        return _page(request, text, analysis, 422)
    now = now_iso()
    with transaction(conn):                                    # 단일 트랜잭션: 중간에 실패하면 전부 롤백
        for row in analysis.rows:
            server_id = insert_server(conn, row.fields, user.id, now)
            assets.set_tags(conn, "server", server_id, row.tags)
            if row.primary_ip:
                kind = "사설" if ipaddress.ip_address(row.primary_ip).is_private else "공인"
                conn.execute("INSERT INTO server_ips (server_id, ip, kind, is_primary) VALUES (?, ?, ?, 1)",
                             (server_id, row.primary_ip, kind))
        audit.record(conn, request, "server_bulk_import", user=user, target_type="server",
                     summary=f"count={len(analysis.rows)}")
    security.add_flash(conn, user, f"서버 {len(analysis.rows)}대를 일괄 등록했습니다.")
    return RedirectResponse("/servers", status_code=303)
