"""AI 모델 관리: 목록 → 상세 → 등록/수정/삭제, 서비스 연결(N:M), 상용 API(AI API 라이선스) 연결, 라이선스 위험 표시.

모델 파일/가중치/학습 메트릭은 저장하지 않고 위치와 링크만 기록한다. 위험 판정은 저장하지 않고 조회 시 계산한다.
"""
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse

from .. import assets, audit, config, security
from ..db import get_db, like_pattern, now_iso, paginate, select_where, transaction
from ..forms import csrf_form
from ..schemas import (API_SOURCE, COMMERCIAL_USES, MODEL_LICENSES, MODEL_SOURCES, MODEL_STATUSES, MODEL_TYPES,
                       ModelFilter, ModelForm, ModelServiceCreateForm, ModelServiceEditForm, validate_form)
from ..security import CurrentUser, require_login, require_role
from ..templating import render
from .asset_common import make_common_router

router = APIRouter(dependencies=[Depends(require_login)])
common_router = make_common_router("model", "/models")

FIELDS = ("name", "version", "model_type", "source", "base_model", "model_license", "commercial_use", "license_note",
          "description", "status", "param_size", "vram_gb", "storage_location", "experiment_url", "card_url",
          "license_id", "owner_id")

_LIST_SELECT = (
    "SELECT m.id, m.name, m.version, m.model_type, m.source, m.base_model, m.commercial_use, m.status, m.updated_at, "
    "m.last_verified_at, o.display_name AS owner_name, o.is_active AS owner_active, "
    "(SELECT COUNT(*) FROM model_services ms WHERE ms.model_id = m.id) AS service_count, "
    "(" + assets.MODEL_PROD_LINKED_SQL + ") AS prod_linked "
    "FROM models m LEFT JOIN users o ON o.id = m.owner_id"
)
_COUNT = "SELECT COUNT(*) FROM models m"
_ORDER = {
    "name": "ORDER BY m.name COLLATE NOCASE, m.version, m.id LIMIT ? OFFSET ?",
    "updated": "ORDER BY m.updated_at DESC, m.id LIMIT ? OFFSET ?",
    "verified": "ORDER BY m.last_verified_at IS NULL DESC, m.last_verified_at, m.id LIMIT ? OFFSET ?",
}
_ORDER_ALL = {key: value.replace(" LIMIT ? OFFSET ?", "") for key, value in _ORDER.items()}   # CSV는 전체 결과
COMMERCIAL_BADGE = {"가능": "green", "조건부": "orange", "불가": "red", "미확인": "orange"}


def model_conditions(flt: ModelFilter, user: CurrentUser) -> list[tuple[str, tuple]]:
    c: list[tuple[str, tuple]] = []
    if flt.q:
        p = like_pattern(flt.q)
        c.append(("(m.name LIKE ? ESCAPE '\\' OR m.base_model LIKE ? ESCAPE '\\')", (p, p)))
    for column, value in (("model_type", flt.model_type), ("source", flt.source), ("status", flt.status),
                          ("commercial_use", flt.commercial_use)):
        if value:
            c.append((_EQ[column], (value,)))
    if flt.risk:
        c.append((assets.MODEL_RISK_SQL, ()))
    if flt.tag:
        c.append(("EXISTS (SELECT 1 FROM asset_tags a JOIN tags t ON t.id = a.tag_id WHERE a.asset_type = 'model' "
                  "AND a.asset_id = m.id AND t.name = ?)", (flt.tag,)))
    if flt.owner_id is not None:
        c.append(("m.owner_id = ?", (flt.owner_id,)))
    if flt.mine:
        c.append(("m.owner_id = ?", (user.id,)))
    if flt.stale:
        c.append(("(m.last_verified_at IS NULL OR m.last_verified_at < ?)", (assets.stale_cutoff(),)))
    return c


_EQ = {"model_type": "m.model_type = ?", "source": "m.source = ?", "status": "m.status = ?",
       "commercial_use": "m.commercial_use = ?"}


def with_risk(rows: list[sqlite3.Row]) -> list[dict]:
    result = []
    for r in rows:
        d = dict(r)
        d["risk"] = assets.license_risk(r["commercial_use"], r["status"], bool(r["prod_linked"]))
        result.append(d)
    return result


def _can_write(user: CurrentUser) -> bool:
    return security.ROLE_RANK[user.role] >= security.ROLE_RANK["editor"]


def _get_model(conn: sqlite3.Connection, model_id: int) -> sqlite3.Row:
    row = conn.execute(
        "SELECT m.*, (" + assets.MODEL_PROD_LINKED_SQL + ") AS prod_linked, o.display_name AS owner_name, "
        "o.is_active AS owner_active, cu.display_name AS created_by_name, uu.display_name AS updated_by_name, "
        "vu.display_name AS verified_by_name, l.name AS license_name, l.ai_provider AS license_provider, "
        "l.ai_sends_customer_data AS license_sends, l.ai_training_opt_out AS license_opt_out "
        "FROM models m LEFT JOIN users o ON o.id = m.owner_id LEFT JOIN users cu ON cu.id = m.created_by "
        "LEFT JOIN users uu ON uu.id = m.updated_by LEFT JOIN users vu ON vu.id = m.last_verified_by "
        "LEFT JOIN licenses l ON l.id = m.license_id WHERE m.id = ?", (model_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404)
    return row


def models_of_service(conn: sqlite3.Connection, service_id: int) -> list[dict]:
    """서비스 상세의 '사용 AI 모델' 섹션."""
    rows = conn.execute(
        "SELECT m.id, m.name, m.version, m.status, m.commercial_use, ms.note, "
        "(" + assets.MODEL_PROD_LINKED_SQL + ") AS prod_linked "
        "FROM model_services ms JOIN models m ON m.id = ms.model_id WHERE ms.service_id = ? ORDER BY m.name, m.version",
        (service_id,)).fetchall()
    return with_risk(rows)


# ------------------------------------------------------------------ 목록

@router.get("/models")
def model_list(request: Request, user: CurrentUser = Depends(require_login),
               conn: sqlite3.Connection = Depends(get_db)):
    values = dict(request.query_params)
    flt, errors = validate_form(ModelFilter, values)
    rows, total, page, pages, tags, query = [], 0, 1, 1, {}, {}
    if flt is not None:
        conditions = model_conditions(flt, user)
        total = select_where(conn, _COUNT, conditions).fetchone()[0]
        page, pages, offset = paginate(flt.page, total, config.PAGE_SIZE)
        rows = with_risk(select_where(conn, _LIST_SELECT, conditions, _ORDER[flt.sort],
                                      (config.PAGE_SIZE, offset)).fetchall())
        tags = assets.tags_by_asset(conn, "model", [r["id"] for r in rows])
        query = {k: v for k, v in values.items() if k != "page" and v != ""}
    tag_names = [r[0] for r in conn.execute("SELECT name FROM tags ORDER BY name")]
    owners = [(str(r["id"]), r["display_name"]) for r in conn.execute("SELECT id, display_name FROM users ORDER BY display_name")]
    return render(request, "models/list.html", {
        "rows": rows, "tags": tags, "total": total, "page": page, "pages": pages, "query": query,
        "values": values, "errors": errors, "commercial_badge": COMMERCIAL_BADGE,
        "type_options": [(v, v) for v in MODEL_TYPES], "source_options": [(v, v) for v in MODEL_SOURCES],
        "status_options": [(v, v) for v in MODEL_STATUSES], "commercial_options": [(v, v) for v in COMMERCIAL_USES],
        "tag_options": [(t, t) for t in tag_names], "owner_filter_options": owners,
        "sort_options": [("name", "모델명"), ("updated", "수정일"), ("verified", "마지막 확인일 (오래된 순)")],
    })


# ------------------------------------------------------------------ 등록/수정

def _api_license_options(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    rows = conn.execute("SELECT id, name, ai_provider FROM licenses WHERE license_type = 'AI API' ORDER BY name")
    return [(str(r["id"]), f"{r['name']} ({r['ai_provider']})") for r in rows]


def _form_context(conn: sqlite3.Connection, target, values: dict, errors: dict) -> dict:
    return {
        "target": target, "values": values, "errors": errors,
        "owner_opts": assets.owner_options(conn, target["owner_id"] if target else None),
        "type_options": [(v, v) for v in MODEL_TYPES], "source_options": [(v, v) for v in MODEL_SOURCES],
        "status_options": [(v, v) for v in MODEL_STATUSES], "commercial_options": [(v, v) for v in COMMERCIAL_USES],
        "license_choices": MODEL_LICENSES, "api_license_options": _api_license_options(conn),
    }


def _validate(conn: sqlite3.Connection, form: dict, current: sqlite3.Row | None):
    data, errors = validate_form(ModelForm, form)
    if data is not None:
        problem = assets.owner_error(conn, data.owner_id, current["owner_id"] if current else None)
        if problem:
            errors["owner_id"] = problem
        if data.license_id is not None:
            lic = conn.execute("SELECT license_type FROM licenses WHERE id = ?", (data.license_id,)).fetchone()
            if lic is None or lic["license_type"] != "AI API":
                errors["license_id"] = "종류가 'AI API'인 라이선스만 연결할 수 있습니다."
        dup = conn.execute("SELECT id FROM models WHERE name = ? AND version = ?", (data.name, data.version)).fetchone()
        if dup is not None and (current is None or dup["id"] != current["id"]):
            errors["name"] = "이미 등록된 모델명 + 버전 조합입니다."
    return data, errors


@router.get("/models/new")
def model_new_form(request: Request, user: CurrentUser = Depends(require_role("editor")),
                   conn: sqlite3.Connection = Depends(get_db)):
    values = {"model_type": "LLM", "source": "오픈소스", "status": "실험", "commercial_use": "미확인"}
    return render(request, "models/form.html", _form_context(conn, None, values, {}))


@router.post("/models/new")
def model_create(request: Request, user: CurrentUser = Depends(require_role("editor")),
                 form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    data, errors = _validate(conn, form, None)
    if data is None or errors:
        return render(request, "models/form.html", _form_context(conn, None, form, errors), 422)
    fields, now = {f: getattr(data, f) for f in FIELDS}, now_iso()
    with transaction(conn):
        model_id = conn.execute(
            "INSERT INTO models (name, version, model_type, source, base_model, model_license, commercial_use, "
            "license_note, description, status, param_size, vram_gb, storage_location, experiment_url, card_url, "
            "license_id, owner_id, created_at, created_by, updated_at, updated_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (*fields.values(), now, user.id, now, user.id)).lastrowid
        assets.set_tags(conn, "model", model_id, data.tags)
        audit.record(conn, request, "model_create", user=user, target_type="model", target_id=model_id,
                     summary=audit.diff_summary({}, {**fields, "tags": ", ".join(data.tags)}))
    security.add_flash(conn, user, "AI 모델을 등록했습니다.")
    return RedirectResponse(f"/models/{model_id}", status_code=303)


def _edit_values(model: sqlite3.Row, tags: list[str]) -> dict:
    values = {f: "" if model[f] is None else str(model[f]) for f in FIELDS}
    values["tags"] = ", ".join(tags)
    return values


@router.get("/models/{model_id}/edit")
def model_edit_form(request: Request, model_id: int, user: CurrentUser = Depends(require_role("editor")),
                    conn: sqlite3.Connection = Depends(get_db)):
    model = _get_model(conn, model_id)
    return render(request, "models/form.html", _form_context(
        conn, model, _edit_values(model, assets.get_tags(conn, "model", model_id)), {}))


@router.post("/models/{model_id}/edit")
def model_edit(request: Request, model_id: int, user: CurrentUser = Depends(require_role("editor")),
               form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    model = _get_model(conn, model_id)
    data, errors = _validate(conn, form, model)
    if data is None or errors:
        return render(request, "models/form.html", _form_context(conn, model, form, errors), 422)
    fields = {f: getattr(data, f) for f in FIELDS}
    old = {**{f: model[f] for f in FIELDS}, "tags": ", ".join(sorted(assets.get_tags(conn, "model", model_id)))}
    new = {**fields, "tags": ", ".join(sorted(data.tags))}
    summary = audit.diff_summary(old, new)
    if summary:
        # 일반 수정은 '확인 완료'로 간주하지 않는다.
        with transaction(conn):
            conn.execute(
                "UPDATE models SET name = ?, version = ?, model_type = ?, source = ?, base_model = ?, "
                "model_license = ?, commercial_use = ?, license_note = ?, description = ?, status = ?, "
                "param_size = ?, vram_gb = ?, storage_location = ?, experiment_url = ?, card_url = ?, "
                "license_id = ?, owner_id = ?, updated_at = ?, updated_by = ? WHERE id = ?",
                (*fields.values(), now_iso(), user.id, model_id))
            assets.set_tags(conn, "model", model_id, data.tags)
            audit.record(conn, request, "model_update", user=user, target_type="model", target_id=model_id,
                         summary=summary)
    security.add_flash(conn, user, "저장했습니다." if summary else "변경된 내용이 없습니다.")
    return RedirectResponse(f"/models/{model_id}", status_code=303)


# ------------------------------------------------------------------ 상세

@router.get("/models/{model_id}")
def model_detail(request: Request, model_id: int, user: CurrentUser = Depends(require_login),
                 conn: sqlite3.Connection = Depends(get_db)):
    model = _get_model(conn, model_id)
    services = conn.execute(
        "SELECT s.id, s.name, s.code, s.tier, s.status, s.environment, ms.note FROM model_services ms "
        "JOIN services s ON s.id = ms.service_id WHERE ms.model_id = ? ORDER BY s.tier, s.code", (model_id,)).fetchall()
    return render(request, "models/detail.html", {
        "m_": model, "risk": assets.license_risk(model["commercial_use"], model["status"], bool(model["prod_linked"])),
        "commercial_badge": COMMERCIAL_BADGE, "can_write": _can_write(user), "services": services,
        "api_policy_risk": model["license_id"] is not None and assets.data_policy_risk(
            model["license_sends"], model["license_opt_out"]),
        **assets.common_sections(conn, "model", model_id),
    })


# ------------------------------------------------------------------ 삭제

@router.get("/models/{model_id}/delete")
def model_delete_confirm(request: Request, model_id: int, user: CurrentUser = Depends(require_role("editor")),
                         conn: sqlite3.Connection = Depends(get_db)):
    model = _get_model(conn, model_id)
    services = conn.execute(
        "SELECT s.id, s.name, s.code, s.tier, s.status FROM model_services ms JOIN services s ON s.id = ms.service_id "
        "WHERE ms.model_id = ? ORDER BY s.tier, s.code", (model_id,)).fetchall()
    return render(request, "models/delete.html", {"m_": model, "services": services})


@router.post("/models/{model_id}/delete")
def model_delete(request: Request, model_id: int, user: CurrentUser = Depends(require_role("editor")),
                 form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    model = _get_model(conn, model_id)
    with transaction(conn):
        assets.delete_asset_extras(conn, "model", model_id)
        conn.execute("DELETE FROM models WHERE id = ?", (model_id,))          # model_services는 FK CASCADE
        audit.record(conn, request, "model_delete", user=user, target_type="model", target_id=model_id,
                     summary=f"name: {model['name']}; version: {model['version']}")
    security.add_flash(conn, user, "AI 모델을 삭제했습니다.")
    return RedirectResponse("/models", status_code=303)


# ------------------------------------------------------------------ 서비스 연결 (N:M, 용도 비고)

def _touch(conn: sqlite3.Connection, model_id: int, user: CurrentUser) -> None:
    conn.execute("UPDATE models SET updated_at = ?, updated_by = ? WHERE id = ?", (now_iso(), user.id, model_id))


_SERVICE_OPTIONS = ("SELECT id, code || ' · ' || name AS label FROM services WHERE id NOT IN "
                    "(SELECT service_id FROM model_services WHERE model_id = ?) ORDER BY code")


def _service_page(request, conn, model, values, errors, service_id, status=200):
    options = [] if service_id else [(str(r["id"]), r["label"]) for r in conn.execute(_SERVICE_OPTIONS, (model["id"],))]
    service = conn.execute("SELECT code, name FROM services WHERE id = ?", (service_id,)).fetchone() if service_id else None
    return render(request, "models/service_form.html", {
        "m_": model, "service_id": service_id, "service": service, "values": values, "errors": errors,
        "service_options": options}, status)


def _get_link(conn: sqlite3.Connection, model_id: int, service_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM model_services WHERE model_id = ? AND service_id = ?",
                       (model_id, service_id)).fetchone()
    if row is None:
        raise HTTPException(status_code=404)
    return row


@router.get("/models/{model_id}/services/new")
def service_link_form(request: Request, model_id: int, user: CurrentUser = Depends(require_role("editor")),
                      conn: sqlite3.Connection = Depends(get_db)):
    return _service_page(request, conn, _get_model(conn, model_id), {}, {}, None)


@router.post("/models/{model_id}/services/new")
def service_link_create(request: Request, model_id: int, user: CurrentUser = Depends(require_role("editor")),
                        form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    model = _get_model(conn, model_id)
    data, errors = validate_form(ModelServiceCreateForm, form)
    if data is not None:
        if not assets.exists(conn, "service", data.service_id):
            errors = {"service_id": "존재하지 않는 서비스입니다."}
        elif conn.execute("SELECT 1 FROM model_services WHERE model_id = ? AND service_id = ?",
                          (model_id, data.service_id)).fetchone():
            errors = {"service_id": "이미 연결된 서비스입니다."}
    if data is None or errors:
        return _service_page(request, conn, model, form, errors, None, 422)
    with transaction(conn):
        conn.execute("INSERT INTO model_services (model_id, service_id, note) VALUES (?, ?, ?)",
                     (model_id, data.service_id, data.note))
        _touch(conn, model_id, user)
        audit.record(conn, request, "model_service_add", user=user, target_type="model", target_id=model_id,
                     summary=f"service #{data.service_id}: {data.note}")
    security.add_flash(conn, user, "서비스를 연결했습니다.")
    return RedirectResponse(f"/models/{model_id}#services", status_code=303)


@router.get("/models/{model_id}/services/{service_id}/edit")
def service_link_edit_form(request: Request, model_id: int, service_id: int,
                           user: CurrentUser = Depends(require_role("editor")), conn: sqlite3.Connection = Depends(get_db)):
    model = _get_model(conn, model_id)
    link = _get_link(conn, model_id, service_id)
    return _service_page(request, conn, model, {"note": link["note"]}, {}, service_id)


@router.post("/models/{model_id}/services/{service_id}/edit")
def service_link_edit(request: Request, model_id: int, service_id: int,
                      user: CurrentUser = Depends(require_role("editor")), form: dict[str, str] = Depends(csrf_form),
                      conn: sqlite3.Connection = Depends(get_db)):
    model = _get_model(conn, model_id)
    link = _get_link(conn, model_id, service_id)
    data, errors = validate_form(ModelServiceEditForm, form)
    if data is None:
        return _service_page(request, conn, model, form, errors, service_id, 422)
    with transaction(conn):
        conn.execute("UPDATE model_services SET note = ? WHERE model_id = ? AND service_id = ?",
                     (data.note, model_id, service_id))
        _touch(conn, model_id, user)
        audit.record(conn, request, "model_service_update", user=user, target_type="model", target_id=model_id,
                     summary=f"service #{service_id}: " + audit.diff_summary({"note": link["note"]}, {"note": data.note}))
    security.add_flash(conn, user, "서비스 연결을 저장했습니다.")
    return RedirectResponse(f"/models/{model_id}#services", status_code=303)


@router.post("/models/{model_id}/services/{service_id}/delete")
def service_link_delete(request: Request, model_id: int, service_id: int,
                        user: CurrentUser = Depends(require_role("editor")), form: dict[str, str] = Depends(csrf_form),
                        conn: sqlite3.Connection = Depends(get_db)):
    _get_model(conn, model_id)
    _get_link(conn, model_id, service_id)
    with transaction(conn):
        conn.execute("DELETE FROM model_services WHERE model_id = ? AND service_id = ?", (model_id, service_id))
        _touch(conn, model_id, user)
        audit.record(conn, request, "model_service_delete", user=user, target_type="model", target_id=model_id,
                     summary=f"service #{service_id}")
    security.add_flash(conn, user, "서비스 연결을 해제했습니다.")
    return RedirectResponse(f"/models/{model_id}#services", status_code=303)
