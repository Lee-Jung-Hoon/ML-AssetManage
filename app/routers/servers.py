"""서버 관리: 목록 → 상세 → 등록/수정/삭제. 하위 항목(IP/디스크/...)은 6단계에서 추가한다."""
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse

from .. import assets, audit, config, security
from ..db import get_db, like_pattern, now_iso, paginate, select_where, transaction
from ..forms import csrf_form
from ..schemas import (ENVIRONMENTS, LINUX_DISTROS, OS_TYPES, SERVER_STATUSES, SERVER_TYPES, WINDOWS_DISTROS,
                       ServerFilter, ServerForm, validate_form)
from ..security import CurrentUser, require_login, require_role
from ..templating import render
from . import server_items
from .asset_common import make_common_router

router = APIRouter(dependencies=[Depends(require_login)])
common_router = make_common_router("server", "/servers")

FIELDS = ("name", "hostname", "os_type", "os_distro", "os_version", "kernel_version", "environment", "status",
          "server_type", "location", "cpu_model", "cpu_cores", "memory_gb", "description", "notes", "owner_id")

_LIST_SELECT = (
    "SELECT s.id, s.name, s.hostname, s.os_type, s.os_distro, s.environment, s.status, s.updated_at, "
    "s.last_verified_at, o.display_name AS owner_name, o.is_active AS owner_active, "
    "(SELECT i.ip FROM server_ips i WHERE i.server_id = s.id AND i.is_primary = 1) AS primary_ip, "
    "(SELECT MAX(d.used_gb * 100.0 / d.total_gb) FROM server_disks d WHERE d.server_id = s.id) AS max_disk_pct, "
    "(SELECT group_concat(g.gpu_model || ' ×' || g.quantity, ', ') FROM server_gpus g WHERE g.server_id = s.id) "
    "AS gpu_summary "
    "FROM servers s LEFT JOIN users o ON o.id = s.owner_id"
)
_COUNT = "SELECT COUNT(*) FROM servers s"
# 정렬 컬럼은 화이트리스트로만 선택한다
_ORDER = {
    "name": "ORDER BY s.name COLLATE NOCASE, s.id LIMIT ? OFFSET ?",
    "updated": "ORDER BY s.updated_at DESC, s.id LIMIT ? OFFSET ?",
    "verified": "ORDER BY s.last_verified_at IS NULL DESC, s.last_verified_at, s.id LIMIT ? OFFSET ?",
}


def server_conditions(flt: ServerFilter, user: CurrentUser) -> list[tuple[str, tuple]]:
    """목록/CSV 내보내기가 함께 쓰는 필터 조건. 조각은 코드 상수이고 값만 바인딩한다."""
    c: list[tuple[str, tuple]] = []
    if flt.q:
        p = like_pattern(flt.q)
        c.append(("(s.name LIKE ? ESCAPE '\\' OR s.hostname LIKE ? ESCAPE '\\' OR EXISTS "
                  "(SELECT 1 FROM server_ips i WHERE i.server_id = s.id AND i.ip LIKE ? ESCAPE '\\'))", (p, p, p)))
    if flt.os_type:
        c.append(("s.os_type = ?", (flt.os_type,)))
    if flt.os_distro:
        c.append(("s.os_distro = ?", (flt.os_distro,)))
    if flt.environment:
        c.append(("s.environment = ?", (flt.environment,)))
    if flt.status:
        c.append(("s.status = ?", (flt.status,)))
    if flt.gpu_only:
        c.append(("EXISTS (SELECT 1 FROM server_gpus g WHERE g.server_id = s.id)", ()))
    if flt.tag:
        c.append(("EXISTS (SELECT 1 FROM asset_tags a JOIN tags t ON t.id = a.tag_id WHERE a.asset_type = 'server' "
                  "AND a.asset_id = s.id AND t.name = ?)", (flt.tag,)))
    if flt.owner_id is not None:
        c.append(("s.owner_id = ?", (flt.owner_id,)))
    if flt.mine:
        c.append(("s.owner_id = ?", (user.id,)))
    if flt.stale:
        c.append(("(s.last_verified_at IS NULL OR s.last_verified_at < ?)", (assets.stale_cutoff(),)))
    return c


def _get_server(conn: sqlite3.Connection, server_id: int) -> sqlite3.Row:
    row = conn.execute(
        "SELECT s.*, o.display_name AS owner_name, o.is_active AS owner_active, "
        "cu.display_name AS created_by_name, uu.display_name AS updated_by_name, vu.display_name AS verified_by_name "
        "FROM servers s LEFT JOIN users o ON o.id = s.owner_id LEFT JOIN users cu ON cu.id = s.created_by "
        "LEFT JOIN users uu ON uu.id = s.updated_by LEFT JOIN users vu ON vu.id = s.last_verified_by "
        "WHERE s.id = ?", (server_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404)
    return row


@router.get("/servers")
def server_list(request: Request, user: CurrentUser = Depends(require_login),
                conn: sqlite3.Connection = Depends(get_db)):
    values = dict(request.query_params)
    flt, errors = validate_form(ServerFilter, values)
    rows, total, page, pages, tags, query = [], 0, 1, 1, {}, {}
    if flt is not None:
        conditions = server_conditions(flt, user)
        total = select_where(conn, _COUNT, conditions).fetchone()[0]
        page, pages, offset = paginate(flt.page, total, config.PAGE_SIZE)
        rows = select_where(conn, _LIST_SELECT, conditions, _ORDER[flt.sort], (config.PAGE_SIZE, offset)).fetchall()
        tags = assets.tags_by_asset(conn, "server", [r["id"] for r in rows])
        query = {k: v for k, v in values.items() if k != "page" and v != ""}
    distros = [r[0] for r in conn.execute("SELECT DISTINCT os_distro FROM servers WHERE os_distro != '' ORDER BY 1")]
    tag_names = [r[0] for r in conn.execute("SELECT name FROM tags ORDER BY name")]
    owners = [(str(r["id"]), r["display_name"]) for r in conn.execute(
        "SELECT id, display_name FROM users ORDER BY display_name")]
    return render(request, "servers/list.html", {
        "rows": rows, "tags": tags, "total": total, "page": page, "pages": pages, "query": query,
        "values": values, "errors": errors,
        "distro_options": [(d, d) for d in distros], "tag_options": [(t, t) for t in tag_names],
        "owner_filter_options": owners,
        "os_options": [(v, v) for v in OS_TYPES], "env_options": [(v, v) for v in ENVIRONMENTS],
        "status_options": [(v, v) for v in SERVER_STATUSES],
        "sort_options": [("name", "서버명"), ("updated", "수정일"), ("verified", "마지막 확인일 (오래된 순)")],
    })


def _form_context(conn: sqlite3.Connection, target, values: dict, errors: dict) -> dict:
    current_owner = target["owner_id"] if target is not None else None
    return {
        "target": target, "values": values, "errors": errors,
        "owner_opts": assets.owner_options(conn, current_owner),
        "os_options": [(v, v) for v in OS_TYPES], "env_options": [(v, v) for v in ENVIRONMENTS],
        "status_options": [(v, v) for v in SERVER_STATUSES], "type_options": [(v, v) for v in SERVER_TYPES],
        "distros": LINUX_DISTROS + WINDOWS_DISTROS,
    }


@router.get("/servers/new")
def server_new_form(request: Request, user: CurrentUser = Depends(require_role("editor")),
                    conn: sqlite3.Connection = Depends(get_db)):
    values = {"os_type": "Linux", "environment": "prod", "status": "운영중", "server_type": "VM"}
    return render(request, "servers/form.html", _form_context(conn, None, values, {}))


def _validate(conn: sqlite3.Connection, form: dict, current: sqlite3.Row | None):
    data, errors = validate_form(ServerForm, form)
    if data is not None:
        problem = assets.owner_error(conn, data.owner_id, current["owner_id"] if current else None)
        if problem:
            errors["owner_id"] = problem
        dup = conn.execute("SELECT id FROM servers WHERE hostname = ?", (data.hostname,)).fetchone()
        if dup is not None and (current is None or dup["id"] != current["id"]):
            errors["hostname"] = "이미 등록된 호스트명입니다."
    return data, errors


def _field_values(data: ServerForm) -> dict:
    return {f: getattr(data, f) for f in FIELDS}


@router.post("/servers/new")
def server_create(request: Request, user: CurrentUser = Depends(require_role("editor")),
                  form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    data, errors = _validate(conn, form, None)
    if data is None or errors:
        return render(request, "servers/form.html", _form_context(conn, None, form, errors), 422)
    fields, now = _field_values(data), now_iso()
    with transaction(conn):
        server_id = conn.execute(
            "INSERT INTO servers (name, hostname, os_type, os_distro, os_version, kernel_version, environment, "
            "status, server_type, location, cpu_model, cpu_cores, memory_gb, description, notes, owner_id, "
            "created_at, created_by, updated_at, updated_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (*fields.values(), now, user.id, now, user.id)).lastrowid
        assets.set_tags(conn, "server", server_id, data.tags)
        audit.record(conn, request, "server_create", user=user, target_type="server", target_id=server_id,
                     summary=audit.diff_summary({}, {**fields, "tags": ", ".join(data.tags)}))
    security.add_flash(conn, user, "서버를 등록했습니다.")
    return RedirectResponse(f"/servers/{server_id}", status_code=303)


@router.get("/servers/{server_id}")
def server_detail(request: Request, server_id: int, user: CurrentUser = Depends(require_login),
                  conn: sqlite3.Connection = Depends(get_db)):
    server = _get_server(conn, server_id)
    return render(request, "servers/detail.html", {
        "s": server, "can_write": security.ROLE_RANK[user.role] >= security.ROLE_RANK["editor"],
        "sections": server_items.build_sections(conn, server_id),
        "gpu_total": server_items.gpu_totals(conn, server_id),
        **assets.common_sections(conn, "server", server_id),
    })


def _edit_values(server: sqlite3.Row, tags: list[str]) -> dict:
    values = {f: "" if server[f] is None else str(server[f]) for f in FIELDS}
    values["tags"] = ", ".join(tags)
    return values


@router.get("/servers/{server_id}/edit")
def server_edit_form(request: Request, server_id: int, user: CurrentUser = Depends(require_role("editor")),
                     conn: sqlite3.Connection = Depends(get_db)):
    server = _get_server(conn, server_id)
    values = _edit_values(server, assets.get_tags(conn, "server", server_id))
    return render(request, "servers/form.html", _form_context(conn, server, values, {}))


@router.post("/servers/{server_id}/edit")
def server_edit(request: Request, server_id: int, user: CurrentUser = Depends(require_role("editor")),
                form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    server = _get_server(conn, server_id)
    data, errors = _validate(conn, form, server)
    if data is None or errors:
        return render(request, "servers/form.html", _form_context(conn, server, form, errors), 422)
    old_tags = assets.get_tags(conn, "server", server_id)
    fields = _field_values(data)
    old = {**{f: server[f] for f in FIELDS}, "tags": ", ".join(sorted(old_tags))}
    new = {**fields, "tags": ", ".join(sorted(data.tags))}
    summary = audit.diff_summary(old, new)
    if summary:
        # 일반 수정은 '확인 완료'로 간주하지 않는다: last_verified_*는 건드리지 않는다.
        with transaction(conn):
            conn.execute(
                "UPDATE servers SET name = ?, hostname = ?, os_type = ?, os_distro = ?, os_version = ?, "
                "kernel_version = ?, environment = ?, status = ?, server_type = ?, location = ?, cpu_model = ?, "
                "cpu_cores = ?, memory_gb = ?, description = ?, notes = ?, owner_id = ?, updated_at = ?, "
                "updated_by = ? WHERE id = ?", (*fields.values(), now_iso(), user.id, server_id))
            assets.set_tags(conn, "server", server_id, data.tags)
            audit.record(conn, request, "server_update", user=user, target_type="server", target_id=server_id,
                         summary=summary)
    security.add_flash(conn, user, "저장했습니다." if summary else "변경된 내용이 없습니다.")
    return RedirectResponse(f"/servers/{server_id}", status_code=303)


def _running_services(conn: sqlite3.Connection, server_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT sv.id, sv.name, sv.code, sv.tier, sv.status FROM service_servers ss "
        "JOIN services sv ON sv.id = ss.service_id WHERE ss.server_id = ? ORDER BY sv.tier, sv.name",
        (server_id,)).fetchall()


@router.get("/servers/{server_id}/delete")
def server_delete_confirm(request: Request, server_id: int, user: CurrentUser = Depends(require_role("editor")),
                          conn: sqlite3.Connection = Depends(get_db)):
    """삭제 확인 페이지 (GET은 아무것도 지우지 않는다). 구동 중인 서비스가 있으면 경고한다."""
    server = _get_server(conn, server_id)
    return render(request, "servers/delete.html", {"s": server, "services": _running_services(conn, server_id)})


@router.post("/servers/{server_id}/delete")
def server_delete(request: Request, server_id: int, user: CurrentUser = Depends(require_role("editor")),
                  form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    server = _get_server(conn, server_id)
    with transaction(conn):
        assets.delete_asset_extras(conn, "server", server_id)      # 태그 연결/메모 (FK CASCADE 불가)
        conn.execute("DELETE FROM servers WHERE id = ?", (server_id,))   # 하위 항목은 FK CASCADE
        audit.record(conn, request, "server_delete", user=user, target_type="server", target_id=server_id,
                     summary=f"name: {server['name']}; hostname: {server['hostname']}")
    security.add_flash(conn, user, "서버를 삭제했습니다.")
    return RedirectResponse("/servers", status_code=303)
