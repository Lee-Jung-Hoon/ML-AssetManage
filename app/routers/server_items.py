"""서버 하위 항목: IP, 디스크, GPU, 호스트 서비스, 컨테이너, ACL.

항목마다 폼 화면(추가/수정)이 있고 삭제는 수정 화면의 POST 버튼으로 한다 (복잡한 동적 폼 없음).
항목 정의(ItemSpec)를 표로 선언하고 라우트·SQL·화면은 이 정의에서 한 번만 만든다.
SQL의 테이블/컬럼 이름은 모두 이 파일의 상수에서 오며 사용자 입력은 `?`로만 바인딩된다.
"""
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse

from .. import assets, audit, config, security
from ..db import get_db, now_iso, transaction
from ..forms import csrf_form
from ..schemas import (ACL_DIRECTIONS, ACL_STATUSES, DISK_TYPES, GPU_MODEL_SUGGESTIONS, GPU_USAGES, IP_KINDS,
                       PROTOCOLS, RUN_TYPES, ACLForm, ContainerForm, FormModel, HostServiceForm, ServerDiskForm,
                       ServerGPUForm, ServerIPForm, split_port_spec, validate_form)
from ..security import CurrentUser, require_login, require_role
from ..templating import render

router = APIRouter(dependencies=[Depends(require_login)])


@dataclass(frozen=True)
class FormField:
    name: str
    label: str
    kind: str = "text"            # text | number | date | select | checkbox | textarea
    options: tuple[str, ...] = ()
    required: bool = False
    maxlength: int | None = None
    datalist: tuple[str, ...] = ()
    help: str = ""


@dataclass(frozen=True)
class ItemSpec:
    slug: str
    title: str
    table: str
    model: type[FormModel]
    fields: tuple[FormField, ...]
    columns: tuple[str, ...]                 # DB 컬럼 (id, server_id 제외)
    order_by: str
    headers: tuple[str, ...]
    cells: Callable[[sqlite3.Row], list[dict]]
    label_column: str
    to_db: Callable[[dict], dict] = lambda d: d
    from_db: Callable[[sqlite3.Row], dict] | None = None
    defaults: Callable[[], dict] = lambda: {}
    sql: dict[str, str] = field(default_factory=dict)


def cell(text: Any = "", badge: str | None = None, usage: float | None = None, muted: bool = False) -> dict:
    return {"text": "" if text is None else str(text), "badge": badge, "usage": usage, "muted": muted}


def _num(value: float) -> str:
    return f"{value:g}"


def _date(value: str | None) -> str | None:
    return value


# ------------------------------------------------------------------ 항목별 정의

def _ip_cells(r):
    return [cell(r["ip"]), cell("대표" if r["is_primary"] else "", "green" if r["is_primary"] else None),
            cell(r["interface_name"]), cell(r["kind"])]


def _disk_cells(r):
    pct = r["used_gb"] * 100 / r["total_gb"]
    return [cell(r["mount_point"]), cell(r["device"]), cell(r["filesystem"]), cell(r["disk_type"]),
            cell(f"{_num(r['used_gb'])} / {_num(r['total_gb'])} GB"), cell(usage=pct), cell(r["raid"]),
            cell(r["measured_at"]) if r["measured_at"] else cell("미기재", muted=True)]


def _gpu_cells(r):
    total = r["quantity"] * r["vram_gb"] if r["vram_gb"] else None
    return [cell(r["gpu_model"]), cell(f"×{r['quantity']}"),
            cell(f"{r['vram_gb']} GB" if r["vram_gb"] else "-"), cell(f"{total} GB" if total else "-"),
            cell(r["driver_version"]), cell(r["cuda_version"]), cell(r["mig_config"]),
            cell("예" if r["nvlink"] else "아니오"),
            cell(r["assigned_to"]) if r["assigned_to"] else cell("미할당", "orange"), cell(r["assign_note"])]


def _host_cells(r):
    port = f"{r['port']}/{r['protocol'] or '-'}" if r["port"] else ""
    return [cell(r["name"]), cell(r["run_type"]), cell(port), cell(r["version"]), cell(r["description"])]


def _container_cells(r):
    gpu = {"없음": "없음", "전체": "전체"}.get(r["gpu_usage"], f"디바이스 {r['gpu_devices']}")
    return [cell(r["name"]), cell(r["image"]), cell(r["port_mappings"]), cell(r["compose_project"]),
            cell(r["status"]), cell(gpu), cell(r["description"])]


_ACL_BADGE = {"요청": "orange", "승인": "orange", "적용완료": "green", "반려": "gray", "회수": "gray"}


def _acl_cells(r):
    ports = str(r["port_start"]) if r["port_start"] == r["port_end"] else f"{r['port_start']}-{r['port_end']}"
    expires = cell(r["expires_at"]) if r["expires_at"] else cell("")
    if r["expires_at"] and r["expires_at"] < assets.today_kst():
        expires = cell(f"{r['expires_at']} 만료됨", "red")
    return [cell(r["direction"]), cell(r["src_cidr"]), cell(r["dst_cidr"]), cell(f"{ports}/{r['protocol']}"),
            cell(r["purpose"]), cell(r["requester"]), cell(r["requested_at"]), cell(r["ticket_no"]),
            cell(r["status"], _ACL_BADGE[r["status"]]), expires]


def _acl_to_db(d: dict) -> dict:
    d["port_start"], d["port_end"] = split_port_spec(d.pop("port"))
    return d


def _acl_from_db(r: sqlite3.Row) -> dict:
    ports = str(r["port_start"]) if r["port_start"] == r["port_end"] else f"{r['port_start']}-{r['port_end']}"
    values = _generic_from_db(ACL_SPEC, r)
    values["port"] = ports
    return values


def _generic_from_db(spec: "ItemSpec", row: sqlite3.Row) -> dict:
    checkboxes = {f.name for f in spec.fields if f.kind == "checkbox"}
    values: dict[str, str] = {}
    for column in spec.columns:
        value = row[column]
        if column in checkboxes:
            if value:
                values[column] = "on"
        elif isinstance(value, float):
            values[column] = _num(value)
        else:
            values[column] = "" if value is None else str(value)
    return values


def _today_defaults(**extra) -> Callable[[], dict]:
    return lambda: {**extra}


IP_SPEC = ItemSpec(
    slug="ips", title="IP 주소", table="server_ips", model=ServerIPForm,
    fields=(FormField("ip", "IP 주소 (IPv4/IPv6)", required=True, maxlength=45),
            FormField("interface_name", "인터페이스명", maxlength=50),
            FormField("kind", "유형", "select", IP_KINDS, required=True),
            FormField("is_primary", "대표 IP (서버당 1개, 다른 대표 IP는 자동 해제)", "checkbox")),
    columns=("ip", "interface_name", "kind", "is_primary"), order_by="is_primary DESC, id",
    headers=("IP", "", "인터페이스", "유형"), cells=_ip_cells, label_column="ip",
    to_db=lambda d: {**d, "is_primary": int(d["is_primary"])}, defaults=lambda: {"kind": "사설"})

DISK_SPEC = ItemSpec(
    slug="disks", title="디스크", table="server_disks", model=ServerDiskForm,
    fields=(FormField("mount_point", "마운트 포인트/드라이브 (/, /data, C:)", required=True, maxlength=100),
            FormField("device", "디바이스명 (/dev/sda1, nvme0n1p1)", maxlength=100),
            FormField("filesystem", "파일시스템 (ext4, xfs, ntfs)", maxlength=30),
            FormField("disk_type", "디스크 유형", "select", DISK_TYPES, required=True),
            FormField("total_gb", "전체 용량 (GB)", "number", required=True),
            FormField("used_gb", "사용량 (GB, 전체 용량 이하)", "number", required=True),
            FormField("raid", "RAID 구성", maxlength=100),
            FormField("measured_at", "마지막 측정일 (수기 입력 값이 언제 기준인지)", "date"),
            FormField("notes", "비고", "textarea", maxlength=1000)),
    columns=("mount_point", "device", "filesystem", "disk_type", "total_gb", "used_gb", "raid", "notes", "measured_at"),
    order_by="mount_point", headers=("마운트", "디바이스", "파일시스템", "유형", "사용 / 전체", "사용률", "RAID", "측정일"),
    cells=_disk_cells, label_column="mount_point",
    to_db=lambda d: {**d, "measured_at": d["measured_at"].isoformat() if d["measured_at"] else None},
    defaults=lambda: {"disk_type": "SSD", "measured_at": assets.today_kst()})

GPU_SPEC = ItemSpec(
    slug="gpus", title="GPU", table="server_gpus", model=ServerGPUForm,
    fields=(FormField("gpu_model", "GPU 모델 (목록에서 고르거나 직접 입력)", required=True, maxlength=100,
                      datalist=GPU_MODEL_SUGGESTIONS),
            FormField("quantity", "수량 (1~16, 같은 사양은 한 행에 묶어서)", "number", required=True),
            FormField("vram_gb", "장당 VRAM (GB)", "number"),
            FormField("driver_version", "드라이버 버전 (예: 550.54.15)", maxlength=30),
            FormField("cuda_version", "CUDA 버전 (예: 12.4)", maxlength=30),
            FormField("mig_config", "MIG 구성 (선택)", maxlength=200),
            FormField("nvlink", "NVLink 사용", "checkbox"),
            FormField("assigned_to", "할당 대상 (팀/프로젝트, 비우면 미할당)", maxlength=200),
            FormField("assign_note", "할당 메모", "textarea", maxlength=1000)),
    columns=("gpu_model", "quantity", "vram_gb", "driver_version", "cuda_version", "mig_config", "nvlink",
             "assigned_to", "assign_note"),
    order_by="gpu_model, id",
    headers=("GPU 모델", "수량", "장당 VRAM", "총 VRAM", "드라이버", "CUDA", "MIG", "NVLink", "할당 대상", "할당 메모"),
    cells=_gpu_cells, label_column="gpu_model",
    to_db=lambda d: {**d, "nvlink": int(d["nvlink"])})

HOST_SPEC = ItemSpec(
    slug="host-services", title="호스트 서비스", table="host_services", model=HostServiceForm,
    fields=(FormField("name", "서비스명 (nginx, mysqld)", required=True, maxlength=100),
            FormField("run_type", "실행 방식", "select", RUN_TYPES, required=True),
            FormField("port", "포트", "number"),
            FormField("protocol", "프로토콜", "select", PROTOCOLS),
            FormField("version", "버전", maxlength=50),
            FormField("description", "설명", "textarea", maxlength=1000)),
    columns=("name", "run_type", "port", "protocol", "version", "description"), order_by="name, id",
    headers=("서비스명", "실행 방식", "포트", "버전", "설명"), cells=_host_cells, label_column="name",
    to_db=lambda d: {**d, "protocol": d["protocol"] or None})

CONTAINER_SPEC = ItemSpec(
    slug="containers", title="Docker 컨테이너", table="server_containers", model=ContainerForm,
    fields=(FormField("name", "컨테이너명", required=True, maxlength=100),
            FormField("image", "이미지:태그", required=True, maxlength=300),
            FormField("port_mappings", "포트 매핑 (쉼표로 구분, 예: 8080:80, 5432:5432)", maxlength=300),
            FormField("compose_project", "Compose 프로젝트명", maxlength=100),
            FormField("status", "상태", maxlength=50),
            FormField("gpu_usage", "GPU 사용", "select", GPU_USAGES),
            FormField("gpu_devices", "디바이스 번호 ('특정 디바이스'일 때, 숫자와 쉼표만: 0,1)", maxlength=50),
            FormField("description", "설명", "textarea", maxlength=1000)),
    columns=("name", "image", "port_mappings", "compose_project", "status", "description", "gpu_usage", "gpu_devices"),
    order_by="name, id", headers=("컨테이너", "이미지", "포트", "Compose", "상태", "GPU", "설명"),
    cells=_container_cells, label_column="name", defaults=lambda: {"gpu_usage": "없음"})

ACL_SPEC = ItemSpec(
    slug="acls", title="ACL 요청", table="server_acls", model=ACLForm,
    fields=(FormField("direction", "방향", "select", ACL_DIRECTIONS, required=True),
            FormField("src_cidr", "출발지 IP/CIDR", required=True, maxlength=43),
            FormField("dst_cidr", "목적지 IP/CIDR", required=True, maxlength=43),
            FormField("port", "포트 (단일 80 또는 범위 8000-8100)", required=True, maxlength=11),
            FormField("protocol", "프로토콜", "select", PROTOCOLS, required=True),
            FormField("purpose", "목적/사유", "textarea", required=True, maxlength=1000),
            FormField("requester", "요청자", required=True, maxlength=100),
            FormField("requested_at", "요청일", "date", required=True),
            FormField("ticket_no", "티켓 번호 (선택)", maxlength=50),
            FormField("status", "상태", "select", ACL_STATUSES, required=True),
            FormField("expires_at", "만료일 (임시 ACL, 선택)", "date")),
    columns=("direction", "src_cidr", "dst_cidr", "port_start", "port_end", "protocol", "purpose", "requester",
             "requested_at", "ticket_no", "status", "expires_at"),
    order_by="id DESC",
    headers=("방향", "출발지", "목적지", "포트", "목적/사유", "요청자", "요청일", "티켓", "상태", "만료"),
    cells=_acl_cells, label_column="purpose",
    to_db=lambda d: {**_acl_to_db(d), "requested_at": d["requested_at"].isoformat(),
                     "expires_at": d["expires_at"].isoformat() if d["expires_at"] else None},
    from_db=_acl_from_db,
    defaults=lambda: {"direction": "Inbound", "protocol": "TCP", "status": "요청", "requested_at": assets.today_kst()})

SPECS: dict[str, ItemSpec] = {s.slug: s for s in (IP_SPEC, DISK_SPEC, GPU_SPEC, HOST_SPEC, CONTAINER_SPEC, ACL_SPEC)}


def _build_sql(spec: ItemSpec) -> dict[str, str]:
    cols = ", ".join(spec.columns)
    marks = ", ".join("?" for _ in spec.columns)
    sets = ", ".join(c + " = ?" for c in spec.columns)
    return {
        "insert": "INSERT INTO " + spec.table + " (server_id, " + cols + ") VALUES (?, " + marks + ")",
        "update": "UPDATE " + spec.table + " SET " + sets + " WHERE id = ? AND server_id = ?",
        "select": "SELECT * FROM " + spec.table + " WHERE server_id = ? ORDER BY " + spec.order_by,
        "get": "SELECT * FROM " + spec.table + " WHERE id = ? AND server_id = ?",
        "delete": "DELETE FROM " + spec.table + " WHERE id = ? AND server_id = ?",
    }


for _spec in SPECS.values():
    _spec.sql.update(_build_sql(_spec))


def values_from_row(spec: ItemSpec, row: sqlite3.Row) -> dict:
    return (spec.from_db or (lambda r: _generic_from_db(spec, r)))(row)


# ------------------------------------------------------------------ 상세 화면용 섹션

def build_sections(conn: sqlite3.Connection, server_id: int) -> list[dict]:
    sections = []
    for spec in SPECS.values():
        rows = conn.execute(spec.sql["select"], (server_id,)).fetchall()
        sections.append({"spec": spec, "rows": [{"id": r["id"], "cells": spec.cells(r)} for r in rows]})
    return sections


def gpu_totals(conn: sqlite3.Connection, server_id: int) -> dict:
    row = conn.execute(
        "SELECT COALESCE(SUM(quantity), 0) AS gpus, COALESCE(SUM(quantity * vram_gb), 0) AS vram, "
        "SUM(assigned_to = '') AS unassigned FROM server_gpus WHERE server_id = ?", (server_id,)).fetchone()
    return {"gpus": row["gpus"], "vram": row["vram"], "unassigned": row["unassigned"] or 0}


# ------------------------------------------------------------------ 라우트

def _spec_or_404(kind: str) -> ItemSpec:
    spec = SPECS.get(kind)
    if spec is None:
        raise HTTPException(status_code=404)
    return spec


def _require_server(conn: sqlite3.Connection, server_id: int) -> None:
    if not assets.exists(conn, "server", server_id):
        raise HTTPException(status_code=404)


def _get_item(conn: sqlite3.Connection, spec: ItemSpec, server_id: int, item_id: int) -> sqlite3.Row:
    row = conn.execute(spec.sql["get"], (item_id, server_id)).fetchone()
    if row is None:
        raise HTTPException(status_code=404)
    return row


def _extra_errors(conn: sqlite3.Connection, spec: ItemSpec, server_id: int, data: FormModel,
                  item_id: int | None) -> dict[str, str]:
    if spec is IP_SPEC:
        dup = conn.execute("SELECT 1 FROM server_ips WHERE server_id = ? AND ip = ? AND id IS NOT ?",
                           (server_id, data.ip, item_id)).fetchone()
        if dup:
            return {"ip": "이 서버에 이미 등록된 IP입니다."}
    return {}


def _form_page(request: Request, spec: ItemSpec, server_id: int, values: dict, errors: dict, item_id: int | None,
               status: int = 200):
    return render(request, "servers/item_form.html", {
        "spec": spec, "server_id": server_id, "item_id": item_id, "values": values, "errors": errors}, status)


def _write(conn: sqlite3.Connection, spec: ItemSpec, server_id: int, user: CurrentUser, request: Request,
           data: FormModel, item_id: int | None, old_values: dict | None) -> str:
    db_values = spec.to_db(data.model_dump())
    params = tuple(db_values[c] for c in spec.columns)
    with transaction(conn):
        if spec is IP_SPEC and db_values["is_primary"]:         # 대표 IP는 서버당 1개: 기존 대표는 자동 해제
            conn.execute("UPDATE server_ips SET is_primary = 0 WHERE server_id = ? AND id IS NOT ?",
                         (server_id, item_id))
        if item_id is None:
            item_id = conn.execute(spec.sql["insert"], (server_id, *params)).lastrowid
            action, summary = "add", f"{spec.title} 추가: {db_values[spec.label_column]}"
        else:
            conn.execute(spec.sql["update"], (*params, item_id, server_id))
            new_values = {c: str(v) if v is not None else "" for c, v in db_values.items()}
            action = "update"
            summary = f"{spec.title} 수정 [{db_values[spec.label_column]}]: " + audit.diff_summary(
                old_values or {}, new_values)
        conn.execute("UPDATE servers SET updated_at = ?, updated_by = ? WHERE id = ?", (now_iso(), user.id, server_id))
        audit.record(conn, request, f"server_{spec.slug.replace('-', '_')}_{action}", user=user,
                     target_type="server", target_id=server_id, summary=summary)
    return action


@router.get("/servers/{server_id}/{kind}/new")
def item_new_form(request: Request, server_id: int, kind: str, user: CurrentUser = Depends(require_role("editor")),
                  conn: sqlite3.Connection = Depends(get_db)):
    spec = _spec_or_404(kind)
    _require_server(conn, server_id)
    return _form_page(request, spec, server_id, spec.defaults(), {}, None)


@router.post("/servers/{server_id}/{kind}/new")
def item_create(request: Request, server_id: int, kind: str, user: CurrentUser = Depends(require_role("editor")),
                form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    spec = _spec_or_404(kind)
    _require_server(conn, server_id)
    data, errors = validate_form(spec.model, form)
    if data is not None:
        errors = _extra_errors(conn, spec, server_id, data, None)
    if data is None or errors:
        return _form_page(request, spec, server_id, form, errors, None, 422)
    _write(conn, spec, server_id, user, request, data, None, None)
    security.add_flash(conn, user, f"{spec.title}을(를) 추가했습니다.")
    return RedirectResponse(f"/servers/{server_id}#{spec.slug}", status_code=303)


@router.get("/servers/{server_id}/{kind}/{item_id}/edit")
def item_edit_form(request: Request, server_id: int, kind: str, item_id: int,
                   user: CurrentUser = Depends(require_role("editor")), conn: sqlite3.Connection = Depends(get_db)):
    spec = _spec_or_404(kind)
    row = _get_item(conn, spec, server_id, item_id)
    return _form_page(request, spec, server_id, values_from_row(spec, row), {}, item_id)


@router.post("/servers/{server_id}/{kind}/{item_id}/edit")
def item_edit(request: Request, server_id: int, kind: str, item_id: int,
              user: CurrentUser = Depends(require_role("editor")), form: dict[str, str] = Depends(csrf_form),
              conn: sqlite3.Connection = Depends(get_db)):
    spec = _spec_or_404(kind)
    row = _get_item(conn, spec, server_id, item_id)
    data, errors = validate_form(spec.model, form)
    if data is not None:
        errors = _extra_errors(conn, spec, server_id, data, item_id)
    if data is None or errors:
        return _form_page(request, spec, server_id, form, errors, item_id, 422)
    old_values = {c: "" if v is None else str(v) for c, v in dict(row).items() if c in spec.columns}
    _write(conn, spec, server_id, user, request, data, item_id, old_values)
    security.add_flash(conn, user, f"{spec.title}을(를) 저장했습니다.")
    return RedirectResponse(f"/servers/{server_id}#{spec.slug}", status_code=303)


@router.post("/servers/{server_id}/{kind}/{item_id}/delete")
def item_delete(request: Request, server_id: int, kind: str, item_id: int,
                user: CurrentUser = Depends(require_role("editor")), form: dict[str, str] = Depends(csrf_form),
                conn: sqlite3.Connection = Depends(get_db)):
    spec = _spec_or_404(kind)
    row = _get_item(conn, spec, server_id, item_id)
    with transaction(conn):
        conn.execute(spec.sql["delete"], (item_id, server_id))
        conn.execute("UPDATE servers SET updated_at = ?, updated_by = ? WHERE id = ?", (now_iso(), user.id, server_id))
        audit.record(conn, request, f"server_{spec.slug.replace('-', '_')}_delete", user=user,
                     target_type="server", target_id=server_id,
                     summary=f"{spec.title} 삭제: {row[spec.label_column]}")
    security.add_flash(conn, user, f"{spec.title}을(를) 삭제했습니다.")
    return RedirectResponse(f"/servers/{server_id}#{spec.slug}", status_code=303)
