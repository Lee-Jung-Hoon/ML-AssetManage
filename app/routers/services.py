"""서비스 관리: 목록 → 상세 → 등록/수정/삭제, 구동 서버(N:M), 연결 관계(나가는/들어오는)."""
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse

from .. import assets, audit, config, security
from ..db import get_db, like_pattern, now_iso, paginate, select_where, transaction
from ..forms import csrf_form
from ..schemas import (DEPLOY_METHODS, ENVIRONMENTS, LINK_PROTOCOLS, SERVICE_CATEGORIES, SERVICE_ROLES,
                       SERVICE_STATUSES, SERVING_ENGINES, ServiceFilter, ServiceForm, ServiceLinkForm,
                       ServiceServerCreateForm, ServiceServerEditForm, validate_form)
from ..security import CurrentUser, require_login, require_role
from ..templating import render
from . import licenses as license_views
from . import models as model_views
from .asset_common import make_common_router

router = APIRouter(dependencies=[Depends(require_login)])
common_router = make_common_router("service", "/services")

FIELDS = ("name", "code", "description", "category", "environment", "status", "tier", "team", "urls", "repo_url",
          "doc_url", "tech_stack", "deploy_method", "serving_engine", "notes", "primary_owner_id",
          "secondary_owner_id")

_LIST_SELECT = (
    "SELECT s.id, s.code, s.name, s.category, s.environment, s.status, s.tier, s.updated_at, s.last_verified_at, "
    "p.display_name AS primary_name, p.is_active AS primary_active, "
    "q.display_name AS secondary_name, q.is_active AS secondary_active, "
    "(SELECT COUNT(*) FROM service_servers ss WHERE ss.service_id = s.id) AS server_count "
    "FROM services s LEFT JOIN users p ON p.id = s.primary_owner_id LEFT JOIN users q ON q.id = s.secondary_owner_id"
)
_COUNT = "SELECT COUNT(*) FROM services s"
_ORDER = {
    "name": "ORDER BY s.code, s.id LIMIT ? OFFSET ?",
    "updated": "ORDER BY s.updated_at DESC, s.id LIMIT ? OFFSET ?",
    "verified": "ORDER BY s.last_verified_at IS NULL DESC, s.last_verified_at, s.id LIMIT ? OFFSET ?",
}
_ORDER_ALL = {key: value.replace(" LIMIT ? OFFSET ?", "") for key, value in _ORDER.items()}   # CSV는 전체 결과
TIER_BADGE = {1: "red", 2: "orange", 3: "gray"}


def service_conditions(flt: ServiceFilter, user: CurrentUser) -> list[tuple[str, tuple]]:
    c: list[tuple[str, tuple]] = []
    if flt.q:
        p = like_pattern(flt.q)
        c.append(("(s.name LIKE ? ESCAPE '\\' OR s.code LIKE ? ESCAPE '\\' OR s.urls LIKE ? ESCAPE '\\')", (p, p, p)))
    if flt.category:
        c.append(("s.category = ?", (flt.category,)))
    if flt.environment:
        c.append(("s.environment = ?", (flt.environment,)))
    if flt.status:
        c.append(("s.status = ?", (flt.status,)))
    if flt.tier:
        c.append(("s.tier = ?", (int(flt.tier),)))
    if flt.tag:
        c.append(("EXISTS (SELECT 1 FROM asset_tags a JOIN tags t ON t.id = a.tag_id WHERE a.asset_type = 'service' "
                  "AND a.asset_id = s.id AND t.name = ?)", (flt.tag,)))
    if flt.owner_id is not None:
        c.append(("(s.primary_owner_id = ? OR s.secondary_owner_id = ?)", (flt.owner_id, flt.owner_id)))
    if flt.mine:     # 정/부 담당자 모두 포함
        c.append(("(s.primary_owner_id = ? OR s.secondary_owner_id = ?)", (user.id, user.id)))
    if flt.stale:
        c.append(("(s.last_verified_at IS NULL OR s.last_verified_at < ?)", (assets.stale_cutoff(),)))
    return c


def _get_service(conn: sqlite3.Connection, service_id: int) -> sqlite3.Row:
    row = conn.execute(
        "SELECT s.*, p.display_name AS primary_name, p.is_active AS primary_active, "
        "q.display_name AS secondary_name, q.is_active AS secondary_active, "
        "cu.display_name AS created_by_name, uu.display_name AS updated_by_name, vu.display_name AS verified_by_name "
        "FROM services s LEFT JOIN users p ON p.id = s.primary_owner_id LEFT JOIN users q ON q.id = s.secondary_owner_id "
        "LEFT JOIN users cu ON cu.id = s.created_by LEFT JOIN users uu ON uu.id = s.updated_by "
        "LEFT JOIN users vu ON vu.id = s.last_verified_by WHERE s.id = ?", (service_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404)
    return row


def _can_write(user: CurrentUser) -> bool:
    return security.ROLE_RANK[user.role] >= security.ROLE_RANK["editor"]


# ------------------------------------------------------------------ 목록

@router.get("/services")
def service_list(request: Request, user: CurrentUser = Depends(require_login),
                 conn: sqlite3.Connection = Depends(get_db)):
    values = dict(request.query_params)
    flt, errors = validate_form(ServiceFilter, values)
    rows, total, page, pages, tags, query = [], 0, 1, 1, {}, {}
    if flt is not None:
        conditions = service_conditions(flt, user)
        total = select_where(conn, _COUNT, conditions).fetchone()[0]
        page, pages, offset = paginate(flt.page, total, config.PAGE_SIZE)
        rows = select_where(conn, _LIST_SELECT, conditions, _ORDER[flt.sort], (config.PAGE_SIZE, offset)).fetchall()
        tags = assets.tags_by_asset(conn, "service", [r["id"] for r in rows])
        query = {k: v for k, v in values.items() if k != "page" and v != ""}
    tag_names = [r[0] for r in conn.execute("SELECT name FROM tags ORDER BY name")]
    owners = [(str(r["id"]), r["display_name"]) for r in conn.execute("SELECT id, display_name FROM users ORDER BY display_name")]
    return render(request, "services/list.html", {
        "rows": rows, "tags": tags, "total": total, "page": page, "pages": pages, "query": query,
        "values": values, "errors": errors, "tier_badge": TIER_BADGE,
        "category_options": [(v, v) for v in SERVICE_CATEGORIES], "env_options": [(v, v) for v in ENVIRONMENTS],
        "status_options": [(v, v) for v in SERVICE_STATUSES],
        "tier_options": [("1", "Tier 1 (핵심)"), ("2", "Tier 2 (중요)"), ("3", "Tier 3 (일반)")],
        "tag_options": [(t, t) for t in tag_names], "owner_filter_options": owners,
        "sort_options": [("name", "서비스 코드"), ("updated", "수정일"), ("verified", "마지막 확인일 (오래된 순)")],
    })


# ------------------------------------------------------------------ 등록/수정

def _form_context(conn: sqlite3.Connection, target, values: dict, errors: dict) -> dict:
    return {
        "target": target, "values": values, "errors": errors,
        "primary_opts": assets.owner_options(conn, target["primary_owner_id"] if target else None),
        "secondary_opts": assets.owner_options(conn, target["secondary_owner_id"] if target else None),
        "category_options": [(v, v) for v in SERVICE_CATEGORIES], "env_options": [(v, v) for v in ENVIRONMENTS],
        "status_options": [(v, v) for v in SERVICE_STATUSES],
        "tier_options": [("1", "Tier 1 (핵심, 중단 시 즉시 대응)"), ("2", "Tier 2 (중요)"), ("3", "Tier 3 (일반)")],
        "deploy_options": [(v, v) for v in DEPLOY_METHODS], "engine_options": [(v, v) for v in SERVING_ENGINES],
    }


def _validate(conn: sqlite3.Connection, form: dict, current: sqlite3.Row | None):
    data, errors = validate_form(ServiceForm, form)
    if data is not None:
        for field, key in (("primary_owner_id", "primary_owner_id"), ("secondary_owner_id", "secondary_owner_id")):
            problem = assets.owner_error(conn, getattr(data, field), current[field] if current else None)
            if problem:
                errors[key] = problem
        dup = conn.execute("SELECT id FROM services WHERE code = ?", (data.code,)).fetchone()
        if dup is not None and (current is None or dup["id"] != current["id"]):
            errors["code"] = "이미 사용 중인 서비스 코드입니다."
    return data, errors


def _db_fields(data: ServiceForm) -> dict:
    fields = {f: getattr(data, f) for f in FIELDS}
    fields["serving_engine"] = data.serving_engine or None       # 빈 값은 NULL (CHECK 제약)
    return fields


@router.get("/services/new")
def service_new_form(request: Request, user: CurrentUser = Depends(require_role("editor")),
                     conn: sqlite3.Connection = Depends(get_db)):
    values = {"category": "API", "environment": "prod", "status": "운영중", "tier": "2", "deploy_method": "Docker"}
    return render(request, "services/form.html", _form_context(conn, None, values, {}))


@router.post("/services/new")
def service_create(request: Request, user: CurrentUser = Depends(require_role("editor")),
                   form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    data, errors = _validate(conn, form, None)
    if data is None or errors:
        return render(request, "services/form.html", _form_context(conn, None, form, errors), 422)
    fields, now = _db_fields(data), now_iso()
    with transaction(conn):
        service_id = conn.execute(
            "INSERT INTO services (name, code, description, category, environment, status, tier, team, urls, "
            "repo_url, doc_url, tech_stack, deploy_method, serving_engine, notes, primary_owner_id, "
            "secondary_owner_id, created_at, created_by, updated_at, updated_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (*fields.values(), now, user.id, now, user.id)).lastrowid
        assets.set_tags(conn, "service", service_id, data.tags)
        audit.record(conn, request, "service_create", user=user, target_type="service", target_id=service_id,
                     summary=audit.diff_summary({}, {**fields, "tags": ", ".join(data.tags)}))
    security.add_flash(conn, user, "서비스를 등록했습니다.")
    return RedirectResponse(f"/services/{service_id}", status_code=303)


def _edit_values(service: sqlite3.Row, tags: list[str]) -> dict:
    values = {f: "" if service[f] is None else str(service[f]) for f in FIELDS}
    values["tags"] = ", ".join(tags)
    return values


@router.get("/services/{service_id}/edit")
def service_edit_form(request: Request, service_id: int, user: CurrentUser = Depends(require_role("editor")),
                      conn: sqlite3.Connection = Depends(get_db)):
    service = _get_service(conn, service_id)
    values = _edit_values(service, assets.get_tags(conn, "service", service_id))
    return render(request, "services/form.html", _form_context(conn, service, values, {}))


@router.post("/services/{service_id}/edit")
def service_edit(request: Request, service_id: int, user: CurrentUser = Depends(require_role("editor")),
                 form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    service = _get_service(conn, service_id)
    data, errors = _validate(conn, form, service)
    if data is None or errors:
        return render(request, "services/form.html", _form_context(conn, service, form, errors), 422)
    fields = _db_fields(data)
    old = {**{f: service[f] for f in FIELDS}, "tags": ", ".join(sorted(assets.get_tags(conn, "service", service_id)))}
    new = {**fields, "tags": ", ".join(sorted(data.tags))}
    summary = audit.diff_summary(old, new)
    if summary:
        # 일반 수정은 '확인 완료'로 간주하지 않는다.
        with transaction(conn):
            conn.execute(
                "UPDATE services SET name = ?, code = ?, description = ?, category = ?, environment = ?, status = ?, "
                "tier = ?, team = ?, urls = ?, repo_url = ?, doc_url = ?, tech_stack = ?, deploy_method = ?, "
                "serving_engine = ?, notes = ?, primary_owner_id = ?, secondary_owner_id = ?, updated_at = ?, "
                "updated_by = ? WHERE id = ?", (*fields.values(), now_iso(), user.id, service_id))
            assets.set_tags(conn, "service", service_id, data.tags)
            audit.record(conn, request, "service_update", user=user, target_type="service", target_id=service_id,
                         summary=summary)
    security.add_flash(conn, user, "저장했습니다." if summary else "변경된 내용이 없습니다.")
    return RedirectResponse(f"/services/{service_id}", status_code=303)


# ------------------------------------------------------------------ 상세

def servers_of(conn: sqlite3.Connection, service_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT ss.server_id, ss.role, ss.note, sv.name, sv.hostname, sv.environment, sv.status "
        "FROM service_servers ss JOIN servers sv ON sv.id = ss.server_id WHERE ss.service_id = ? "
        "ORDER BY ss.role, sv.name", (service_id,)).fetchall()


def outgoing_links(conn: sqlite3.Connection, service_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT l.*, t.name AS target_name, t.code AS target_code, t.tier AS target_tier FROM service_links l "
        "LEFT JOIN services t ON t.id = l.target_service_id WHERE l.service_id = ? ORDER BY l.id", (service_id,)).fetchall()


def incoming_links(conn: sqlite3.Connection, service_id: int) -> list[sqlite3.Row]:
    """이 서비스에 의존하는 서비스 (역방향 조회)."""
    return conn.execute(
        "SELECT l.id, l.protocol, l.port, l.purpose, l.auth_method, s.id AS source_id, s.name AS source_name, "
        "s.code AS source_code, s.tier AS source_tier, s.status AS source_status FROM service_links l "
        "JOIN services s ON s.id = l.service_id WHERE l.target_service_id = ? ORDER BY s.tier, s.code",
        (service_id,)).fetchall()


@router.get("/services/{service_id}")
def service_detail(request: Request, service_id: int, user: CurrentUser = Depends(require_login),
                   conn: sqlite3.Connection = Depends(get_db)):
    service = _get_service(conn, service_id)
    return render(request, "services/detail.html", {
        "s": service, "can_write": _can_write(user), "tier_badge": TIER_BADGE,
        "servers": servers_of(conn, service_id), "outgoing": outgoing_links(conn, service_id),
        "incoming": incoming_links(conn, service_id),
        "models": model_views.models_of_service(conn, service_id),
        "licenses": [x for x in license_views.licenses_of_service(conn, service_id) if x["license_type"] != "AI API"],
        "ai_apis": [x for x in license_views.licenses_of_service(conn, service_id) if x["license_type"] == "AI API"],
        **assets.common_sections(conn, "service", service_id),
    })


# ------------------------------------------------------------------ 삭제

@router.get("/services/{service_id}/delete")
def service_delete_confirm(request: Request, service_id: int, user: CurrentUser = Depends(require_role("editor")),
                           conn: sqlite3.Connection = Depends(get_db)):
    service = _get_service(conn, service_id)
    return render(request, "services/delete.html", {
        "s": service, "dependents": incoming_links(conn, service_id), "tier_badge": TIER_BADGE})


@router.post("/services/{service_id}/delete")
def service_delete(request: Request, service_id: int, user: CurrentUser = Depends(require_role("editor")),
                   form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    service = _get_service(conn, service_id)
    with transaction(conn):
        assets.delete_asset_extras(conn, "service", service_id)
        conn.execute("DELETE FROM services WHERE id = ?", (service_id,))     # 연결 테이블은 FK CASCADE
        audit.record(conn, request, "service_delete", user=user, target_type="service", target_id=service_id,
                     summary=f"code: {service['code']}; name: {service['name']}")
    security.add_flash(conn, user, "서비스를 삭제했습니다.")
    return RedirectResponse("/services", status_code=303)


# ------------------------------------------------------------------ 구동 서버 (N:M)

def _touch(conn: sqlite3.Connection, service_id: int, user: CurrentUser) -> None:
    conn.execute("UPDATE services SET updated_at = ?, updated_by = ? WHERE id = ?", (now_iso(), user.id, service_id))


def _server_options(conn: sqlite3.Connection, service_id: int) -> list[tuple[str, str]]:
    rows = conn.execute(
        "SELECT id, name, hostname FROM servers WHERE id NOT IN "
        "(SELECT server_id FROM service_servers WHERE service_id = ?) ORDER BY name", (service_id,))
    return [(str(r["id"]), f"{r['name']} ({r['hostname']})") for r in rows]


def _link_server_page(request, conn, service, values, errors, server_id, status=200):
    options = [] if server_id else _server_options(conn, service["id"])
    return render(request, "services/server_form.html", {
        "s": service, "server_id": server_id, "values": values, "errors": errors, "server_options": options,
        "role_options": [(v, v) for v in SERVICE_ROLES],
        "server": conn.execute("SELECT name, hostname FROM servers WHERE id = ?", (server_id,)).fetchone()
        if server_id else None}, status)


@router.get("/services/{service_id}/servers/new")
def server_link_new(request: Request, service_id: int, user: CurrentUser = Depends(require_role("editor")),
                    conn: sqlite3.Connection = Depends(get_db)):
    return _link_server_page(request, conn, _get_service(conn, service_id), {"role": "WEB"}, {}, None)


@router.post("/services/{service_id}/servers/new")
def server_link_create(request: Request, service_id: int, user: CurrentUser = Depends(require_role("editor")),
                       form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    service = _get_service(conn, service_id)
    data, errors = validate_form(ServiceServerCreateForm, form)
    if data is not None:
        if not assets.exists(conn, "server", data.server_id):
            errors = {"server_id": "존재하지 않는 서버입니다."}
        elif conn.execute("SELECT 1 FROM service_servers WHERE service_id = ? AND server_id = ?",
                          (service_id, data.server_id)).fetchone():
            errors = {"server_id": "이미 연결된 서버입니다."}
    if data is None or errors:
        return _link_server_page(request, conn, service, form, errors, None, 422)
    with transaction(conn):
        conn.execute("INSERT INTO service_servers (service_id, server_id, role, note) VALUES (?, ?, ?, ?)",
                     (service_id, data.server_id, data.role, data.note))
        _touch(conn, service_id, user)
        audit.record(conn, request, "service_server_add", user=user, target_type="service", target_id=service_id,
                     summary=f"server #{data.server_id} ({data.role})")
    security.add_flash(conn, user, "구동 서버를 연결했습니다.")
    return RedirectResponse(f"/services/{service_id}#servers", status_code=303)


def _get_server_link(conn: sqlite3.Connection, service_id: int, server_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM service_servers WHERE service_id = ? AND server_id = ?",
                       (service_id, server_id)).fetchone()
    if row is None:
        raise HTTPException(status_code=404)
    return row


@router.get("/services/{service_id}/servers/{server_id}/edit")
def server_link_edit_form(request: Request, service_id: int, server_id: int,
                          user: CurrentUser = Depends(require_role("editor")), conn: sqlite3.Connection = Depends(get_db)):
    service = _get_service(conn, service_id)
    link = _get_server_link(conn, service_id, server_id)
    return _link_server_page(request, conn, service, {"role": link["role"], "note": link["note"]}, {}, server_id)


@router.post("/services/{service_id}/servers/{server_id}/edit")
def server_link_edit(request: Request, service_id: int, server_id: int,
                     user: CurrentUser = Depends(require_role("editor")), form: dict[str, str] = Depends(csrf_form),
                     conn: sqlite3.Connection = Depends(get_db)):
    service = _get_service(conn, service_id)
    link = _get_server_link(conn, service_id, server_id)
    data, errors = validate_form(ServiceServerEditForm, form)
    if data is None:
        return _link_server_page(request, conn, service, form, errors, server_id, 422)
    with transaction(conn):
        conn.execute("UPDATE service_servers SET role = ?, note = ? WHERE service_id = ? AND server_id = ?",
                     (data.role, data.note, service_id, server_id))
        _touch(conn, service_id, user)
        audit.record(conn, request, "service_server_update", user=user, target_type="service", target_id=service_id,
                     summary=f"server #{server_id}: " + audit.diff_summary(
                         {"role": link["role"], "note": link["note"]}, {"role": data.role, "note": data.note}))
    security.add_flash(conn, user, "구동 서버 연결을 저장했습니다.")
    return RedirectResponse(f"/services/{service_id}#servers", status_code=303)


@router.post("/services/{service_id}/servers/{server_id}/delete")
def server_link_delete(request: Request, service_id: int, server_id: int,
                       user: CurrentUser = Depends(require_role("editor")), form: dict[str, str] = Depends(csrf_form),
                       conn: sqlite3.Connection = Depends(get_db)):
    _get_service(conn, service_id)
    _get_server_link(conn, service_id, server_id)
    with transaction(conn):
        conn.execute("DELETE FROM service_servers WHERE service_id = ? AND server_id = ?", (service_id, server_id))
        _touch(conn, service_id, user)
        audit.record(conn, request, "service_server_delete", user=user, target_type="service", target_id=service_id,
                     summary=f"server #{server_id}")
    security.add_flash(conn, user, "구동 서버 연결을 해제했습니다.")
    return RedirectResponse(f"/services/{service_id}#servers", status_code=303)


# ------------------------------------------------------------------ 연결 관계 (service_links)

def _link_page(request, conn, service, values, errors, link_id, status=200):
    options = [(str(r["id"]), f"{r['code']} · {r['name']}") for r in conn.execute(
        "SELECT id, code, name FROM services WHERE id != ? ORDER BY code", (service["id"],))]   # 자기 자신은 선택 불가
    return render(request, "services/link_form.html", {
        "s": service, "link_id": link_id, "values": values, "errors": errors, "target_options": options,
        "protocol_options": [(v, v) for v in LINK_PROTOCOLS]}, status)


def _link_target_errors(conn: sqlite3.Connection, service_id: int, data: ServiceLinkForm) -> dict[str, str]:
    if data.target_service_id is None:
        return {}
    if data.target_service_id == service_id:
        return {"target_service_id": "자기 자신은 연결 대상으로 선택할 수 없습니다."}
    if not assets.exists(conn, "service", data.target_service_id):
        return {"target_service_id": "존재하지 않는 서비스입니다."}
    return {}


def _get_link(conn: sqlite3.Connection, service_id: int, link_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM service_links WHERE id = ? AND service_id = ?", (link_id, service_id)).fetchone()
    if row is None:
        raise HTTPException(status_code=404)
    return row


def _link_values(link: sqlite3.Row) -> dict:
    return {k: "" if link[k] is None else str(link[k]) for k in
            ("target_service_id", "external_name", "protocol", "port", "purpose", "auth_method")}


@router.get("/services/{service_id}/links/new")
def link_new_form(request: Request, service_id: int, user: CurrentUser = Depends(require_role("editor")),
                  conn: sqlite3.Connection = Depends(get_db)):
    return _link_page(request, conn, _get_service(conn, service_id), {"protocol": "HTTPS"}, {}, None)


@router.post("/services/{service_id}/links/new")
def link_create(request: Request, service_id: int, user: CurrentUser = Depends(require_role("editor")),
                form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    service = _get_service(conn, service_id)
    data, errors = validate_form(ServiceLinkForm, form)
    if data is not None:
        errors = _link_target_errors(conn, service_id, data)
    if data is None or errors:
        return _link_page(request, conn, service, form, errors, None, 422)
    with transaction(conn):
        link_id = conn.execute(
            "INSERT INTO service_links (service_id, target_service_id, external_name, protocol, port, purpose, "
            "auth_method) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (service_id, data.target_service_id, data.external_name or None, data.protocol, data.port,
             data.purpose, data.auth_method)).lastrowid
        _touch(conn, service_id, user)
        target = f"service #{data.target_service_id}" if data.target_service_id else f"외부: {data.external_name}"
        audit.record(conn, request, "service_link_add", user=user, target_type="service", target_id=service_id,
                     summary=f"link #{link_id} → {target} ({data.protocol})")
    security.add_flash(conn, user, "연결 관계를 추가했습니다.")
    return RedirectResponse(f"/services/{service_id}#links", status_code=303)


@router.get("/services/{service_id}/links/{link_id}/edit")
def link_edit_form(request: Request, service_id: int, link_id: int,
                   user: CurrentUser = Depends(require_role("editor")), conn: sqlite3.Connection = Depends(get_db)):
    service = _get_service(conn, service_id)
    return _link_page(request, conn, service, _link_values(_get_link(conn, service_id, link_id)), {}, link_id)


@router.post("/services/{service_id}/links/{link_id}/edit")
def link_edit(request: Request, service_id: int, link_id: int, user: CurrentUser = Depends(require_role("editor")),
              form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    service = _get_service(conn, service_id)
    link = _get_link(conn, service_id, link_id)
    data, errors = validate_form(ServiceLinkForm, form)
    if data is not None:
        errors = _link_target_errors(conn, service_id, data)
    if data is None or errors:
        return _link_page(request, conn, service, form, errors, link_id, 422)
    new = {"target_service_id": data.target_service_id, "external_name": data.external_name, "protocol": data.protocol,
           "port": data.port, "purpose": data.purpose, "auth_method": data.auth_method}
    old = {k: ("" if link[k] is None else link[k]) for k in new}
    with transaction(conn):
        conn.execute(
            "UPDATE service_links SET target_service_id = ?, external_name = ?, protocol = ?, port = ?, purpose = ?, "
            "auth_method = ? WHERE id = ? AND service_id = ?",
            (data.target_service_id, data.external_name or None, data.protocol, data.port, data.purpose,
             data.auth_method, link_id, service_id))
        _touch(conn, service_id, user)
        audit.record(conn, request, "service_link_update", user=user, target_type="service", target_id=service_id,
                     summary=f"link #{link_id}: " + audit.diff_summary(old, {k: ("" if v is None else v) for k, v in new.items()}))
    security.add_flash(conn, user, "연결 관계를 저장했습니다.")
    return RedirectResponse(f"/services/{service_id}#links", status_code=303)


@router.post("/services/{service_id}/links/{link_id}/delete")
def link_delete(request: Request, service_id: int, link_id: int, user: CurrentUser = Depends(require_role("editor")),
                form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    _get_service(conn, service_id)
    _get_link(conn, service_id, link_id)
    with transaction(conn):
        conn.execute("DELETE FROM service_links WHERE id = ? AND service_id = ?", (link_id, service_id))
        _touch(conn, service_id, user)
        audit.record(conn, request, "service_link_delete", user=user, target_type="service", target_id=service_id,
                     summary=f"link #{link_id}")
    security.add_flash(conn, user, "연결 관계를 삭제했습니다.")
    return RedirectResponse(f"/services/{service_id}#links", status_code=303)
