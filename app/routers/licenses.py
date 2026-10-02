"""라이선스 자산 관리: 공통 필드 + SSL/AI API 종류별 필드 + 암호화된 민감 정보 + 서버/서비스 연결.

민감 정보(라이선스 키, 계정 정보)는 AES-256-GCM으로 암호화해 저장하고, 화면에서는 `****abcd`로 마스킹한다.
editor 이상만 POST로 원문을 열람할 수 있고(감사 로그 기록), CSV/검색/감사 로그 요약에서는 항상 제외한다.
"""
import logging
import sqlite3

from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse

from .. import assets, audit, config, security
from ..db import get_db, like_pattern, now_iso, paginate, select_where, transaction
from ..forms import csrf_form
from ..schemas import (AI_OPT_OUT, AI_PROVIDERS, AI_SENDS, BILLING_CYCLES, CURRENCIES, KEY_ALGOS, LICENSE_TYPES,
                       AI_TYPE, SSL_TYPE, LicenseFilter, LicenseForm, LicenseServerForm, LicenseServiceForm,
                       RevealForm, validate_form)
from ..security import CurrentUser, require_login, require_role
from ..templating import render
from .asset_common import make_common_router

log = logging.getLogger("app")
router = APIRouter(dependencies=[Depends(require_login)])
common_router = make_common_router("license", "/licenses")

# 암호화 컬럼 ↔ 폼 필드 ↔ 삭제 체크박스
SENSITIVE = (
    ("license_key", "license_key_enc", "clear_license_key", "라이선스 키"),
    ("account_info", "account_info_enc", "clear_account_info", "계정 정보"),
)
COLUMNS = ("name", "license_type", "vendor", "start_date", "expires_at", "no_expiry", "auto_renew", "quantity", "cost",
           "currency", "billing_cycle", "alert_days", "notes", "ssl_cn", "ssl_san", "ssl_wildcard", "ssl_ca",
           "ssl_key_algo", "ssl_serial", "ssl_sha256", "ai_provider", "ai_models", "ai_monthly_budget",
           "ai_usage_limit_set", "ai_key_location", "ai_sends_customer_data", "ai_training_opt_out",
           "ai_retention_note", "owner_id")

_LIST_SELECT = (
    "SELECT l.id, l.name, l.license_type, l.vendor, l.expires_at, l.no_expiry, l.alert_days, l.ai_provider, "
    "l.ai_sends_customer_data, l.ai_training_opt_out, l.updated_at, l.last_verified_at, "
    "o.display_name AS owner_name, o.is_active AS owner_active "
    "FROM licenses l LEFT JOIN users o ON o.id = l.owner_id"
)
_COUNT = "SELECT COUNT(*) FROM licenses l"
_ORDER = {
    "expiry": "ORDER BY l.no_expiry, l.expires_at, l.id LIMIT ? OFFSET ?",        # 만료일 오름차순 (영구는 마지막)
    "name": "ORDER BY l.name COLLATE NOCASE, l.id LIMIT ? OFFSET ?",
    "updated": "ORDER BY l.updated_at DESC, l.id LIMIT ? OFFSET ?",
    "verified": "ORDER BY l.last_verified_at IS NULL DESC, l.last_verified_at, l.id LIMIT ? OFFSET ?",
}


def license_conditions(flt: LicenseFilter, user: CurrentUser, today: str) -> list[tuple[str, tuple]]:
    c: list[tuple[str, tuple]] = []
    if flt.q:
        p = like_pattern(flt.q)
        c.append(("(l.name LIKE ? ESCAPE '\\' OR l.ssl_cn LIKE ? ESCAPE '\\' OR l.ssl_san LIKE ? ESCAPE '\\')", (p, p, p)))
    if flt.license_type:
        c.append(("l.license_type = ?", (flt.license_type,)))
    if flt.expiry == "영구":
        c.append(("l.no_expiry = 1", ()))
    elif flt.expiry == "만료됨":
        c.append(("(l.no_expiry = 0 AND l.expires_at < ?)", (today,)))
    elif flt.expiry == "만료 임박":
        c.append(("(l.no_expiry = 0 AND l.expires_at >= ? AND l.expires_at <= date(?, '+' || l.alert_days || ' days'))",
                  (today, today)))
    elif flt.expiry == "유효":
        c.append(("(l.no_expiry = 0 AND l.expires_at > date(?, '+' || l.alert_days || ' days'))", (today,)))
    if flt.ai_provider:
        c.append(("l.ai_provider = ?", (flt.ai_provider,)))
    if flt.tag:
        c.append(("EXISTS (SELECT 1 FROM asset_tags a JOIN tags t ON t.id = a.tag_id WHERE a.asset_type = 'license' "
                  "AND a.asset_id = l.id AND t.name = ?)", (flt.tag,)))
    if flt.owner_id is not None:
        c.append(("l.owner_id = ?", (flt.owner_id,)))
    if flt.mine:
        c.append(("l.owner_id = ?", (user.id,)))
    if flt.stale:
        c.append(("(l.last_verified_at IS NULL OR l.last_verified_at < ?)", (assets.stale_cutoff(),)))
    return c


def with_status(rows: list[sqlite3.Row]) -> list[dict]:
    """각 행에 만료 상태(저장하지 않고 계산)와 데이터 정책 경고를 붙인다."""
    today = assets.today_kst()
    result = []
    for r in rows:
        d = dict(r)
        d["status"] = assets.license_status(r["expires_at"], bool(r["no_expiry"]), r["alert_days"], today)
        d["policy_risk"] = r["license_type"] == AI_TYPE and assets.data_policy_risk(
            r["ai_sends_customer_data"], r["ai_training_opt_out"])
        result.append(d)
    return result


def _get_license(conn: sqlite3.Connection, license_id: int) -> sqlite3.Row:
    row = conn.execute(
        "SELECT l.*, o.display_name AS owner_name, o.is_active AS owner_active, cu.display_name AS created_by_name, "
        "uu.display_name AS updated_by_name, vu.display_name AS verified_by_name FROM licenses l "
        "LEFT JOIN users o ON o.id = l.owner_id LEFT JOIN users cu ON cu.id = l.created_by "
        "LEFT JOIN users uu ON uu.id = l.updated_by LEFT JOIN users vu ON vu.id = l.last_verified_by "
        "WHERE l.id = ?", (license_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404)
    return row


def _can_write(user: CurrentUser) -> bool:
    return security.ROLE_RANK[user.role] >= security.ROLE_RANK["editor"]


# ------------------------------------------------------------------ 다른 자산 상세에서 쓰는 조회

_OF_SELECT = ("SELECT l.id, l.name, l.license_type, l.expires_at, l.no_expiry, l.alert_days, l.ai_provider, "
              "l.ai_sends_customer_data, l.ai_training_opt_out FROM licenses l ")


_OF_SERVER_SQL = (_OF_SELECT + "JOIN license_servers x ON x.license_id = l.id WHERE x.server_id = ? "
                  "ORDER BY l.no_expiry, l.expires_at")
_OF_SERVICE_SQL = (_OF_SELECT + "JOIN license_services x ON x.license_id = l.id WHERE x.service_id = ? "
                   "ORDER BY l.no_expiry, l.expires_at")


def licenses_of_server(conn: sqlite3.Connection, server_id: int) -> list[dict]:
    return with_status(conn.execute(_OF_SERVER_SQL, (server_id,)).fetchall())


def licenses_of_service(conn: sqlite3.Connection, service_id: int) -> list[dict]:
    return with_status(conn.execute(_OF_SERVICE_SQL, (service_id,)).fetchall())


# ------------------------------------------------------------------ 목록

@router.get("/licenses")
def license_list(request: Request, user: CurrentUser = Depends(require_login),
                 conn: sqlite3.Connection = Depends(get_db)):
    values = dict(request.query_params)
    flt, errors = validate_form(LicenseFilter, values)
    rows, total, page, pages, tags, query = [], 0, 1, 1, {}, {}
    if flt is not None:
        conditions = license_conditions(flt, user, assets.today_kst())
        total = select_where(conn, _COUNT, conditions).fetchone()[0]
        page, pages, offset = paginate(flt.page, total, config.PAGE_SIZE)
        rows = with_status(select_where(conn, _LIST_SELECT, conditions, _ORDER[flt.sort],
                                        (config.PAGE_SIZE, offset)).fetchall())
        tags = assets.tags_by_asset(conn, "license", [r["id"] for r in rows])
        query = {k: v for k, v in values.items() if k != "page" and v != ""}
    providers = [r[0] for r in conn.execute("SELECT DISTINCT ai_provider FROM licenses WHERE ai_provider IS NOT NULL "
                                            "ORDER BY 1")]
    tag_names = [r[0] for r in conn.execute("SELECT name FROM tags ORDER BY name")]
    owners = [(str(r["id"]), r["display_name"]) for r in conn.execute("SELECT id, display_name FROM users ORDER BY display_name")]
    return render(request, "licenses/list.html", {
        "rows": rows, "tags": tags, "total": total, "page": page, "pages": pages, "query": query,
        "values": values, "errors": errors,
        "type_options": [(v, v) for v in LICENSE_TYPES],
        "expiry_options": [(v, v) for v in ("만료됨", "만료 임박", "유효", "영구")],
        "provider_options": [(p, p) for p in providers], "tag_options": [(t, t) for t in tag_names],
        "owner_filter_options": owners,
        "sort_options": [("expiry", "만료일 (임박한 순)"), ("name", "이름"), ("updated", "수정일"),
                         ("verified", "마지막 확인일 (오래된 순)")],
    })


# ------------------------------------------------------------------ 등록/수정

def _form_context(conn: sqlite3.Connection, target, values: dict, errors: dict) -> dict:
    return {
        "target": target, "values": values, "errors": errors,
        "owner_opts": assets.owner_options(conn, target["owner_id"] if target else None),
        "type_options": [(v, v) for v in LICENSE_TYPES], "cycle_options": [(v, v) for v in BILLING_CYCLES],
        "algo_options": [(v, v) for v in KEY_ALGOS], "sends_options": [(v, v) for v in AI_SENDS],
        "opt_out_options": [(v, v) for v in AI_OPT_OUT], "providers": AI_PROVIDERS, "currencies": CURRENCIES,
        "has_key": bool(target and target["license_key_enc"]),
        "has_account": bool(target and target["account_info_enc"]),
    }


def _db_values(data: LicenseForm) -> dict:
    is_ai = data.license_type == AI_TYPE
    nn = lambda v: v or None   # noqa: E731  빈 문자열은 NULL (종류별 CHECK 제약)
    iso = lambda d: d.isoformat() if d else None   # noqa: E731
    return {
        "name": data.name, "license_type": data.license_type, "vendor": data.vendor,
        "start_date": iso(data.start_date), "expires_at": iso(data.expires_at), "no_expiry": int(data.no_expiry),
        "auto_renew": int(data.auto_renew), "quantity": data.quantity, "cost": data.cost, "currency": data.currency,
        "billing_cycle": nn(data.billing_cycle), "alert_days": data.alert_days, "notes": data.notes,
        "ssl_cn": nn(data.ssl_cn), "ssl_san": nn(data.ssl_san), "ssl_wildcard": int(data.ssl_wildcard),
        "ssl_ca": nn(data.ssl_ca), "ssl_key_algo": nn(data.ssl_key_algo), "ssl_serial": nn(data.ssl_serial),
        "ssl_sha256": nn(data.ssl_sha256),
        "ai_provider": nn(data.ai_provider), "ai_models": nn(data.ai_models),
        "ai_monthly_budget": data.ai_monthly_budget, "ai_usage_limit_set": int(data.ai_usage_limit_set) if is_ai else None,
        "ai_key_location": nn(data.ai_key_location), "ai_sends_customer_data": nn(data.ai_sends_customer_data),
        "ai_training_opt_out": nn(data.ai_training_opt_out), "ai_retention_note": nn(data.ai_retention_note),
        "owner_id": data.owner_id,
    }


def _validate(conn: sqlite3.Connection, form: dict, current: sqlite3.Row | None):
    data, errors = validate_form(LicenseForm, form)
    if data is not None:
        problem = assets.owner_error(conn, data.owner_id, current["owner_id"] if current else None)
        if problem:
            errors["owner_id"] = problem
    return data, errors


def _plan_sensitive(request: Request, license_id: int, data: LicenseForm,
                    current: sqlite3.Row | None) -> list[tuple[str, bytes | None, str]]:
    """(컬럼, 새 암호문 또는 None, 라벨) 목록. 새 값이 있으면 암호화, '삭제' 체크면 제거, 비어 있으면 유지."""
    key, plan = request.app.state.secret_key, []
    for form_field, column, clear_field, label in SENSITIVE:
        value = getattr(data, form_field)
        if value:
            plan.append((column, security.encrypt_field(key, license_id, form_field, value), label))
        elif getattr(data, clear_field) and current is not None and current[column] is not None:
            plan.append((column, None, label))
    return plan


def _run_sensitive(conn: sqlite3.Connection, license_id: int, plan, *, clears: bool) -> None:
    # DB CHECK(AI API는 민감 정보 없음) 때문에 순서가 중요하다: 삭제는 UPDATE 전에, 새 값 저장은 UPDATE 후에 한다.
    for column, blob, _label in plan:
        if (blob is None) == clears:
            conn.execute(_SET_SENSITIVE[column], (blob, license_id))    # 컬럼 이름은 SENSITIVE 상수에서만 온다


_SET_SENSITIVE = {
    "license_key_enc": "UPDATE licenses SET license_key_enc = ? WHERE id = ?",
    "account_info_enc": "UPDATE licenses SET account_info_enc = ? WHERE id = ?",
}


@router.get("/licenses/new")
def license_new_form(request: Request, user: CurrentUser = Depends(require_role("editor")),
                     conn: sqlite3.Connection = Depends(get_db)):
    values = {"license_type": "소프트웨어 라이선스", "currency": "KRW", "alert_days": "30"}
    return render(request, "licenses/form.html", _form_context(conn, None, values, {}))


def _form_page_values(form: dict) -> dict:
    """오류로 폼을 다시 그릴 때 민감 정보는 되돌려 보내지 않는다."""
    return {k: v for k, v in form.items() if k not in ("license_key", "account_info")}


@router.post("/licenses/new")
def license_create(request: Request, user: CurrentUser = Depends(require_role("editor")),
                   form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    data, errors = _validate(conn, form, None)
    if data is None or errors:
        return render(request, "licenses/form.html",
                      _form_context(conn, None, _form_page_values(form), errors), 422)
    values, now = _db_values(data), now_iso()
    with transaction(conn):
        license_id = conn.execute(_INSERT_SQL, (*values.values(), now, user.id, now, user.id)).lastrowid
        plan = _plan_sensitive(request, license_id, data, None)               # 레코드 ID가 AAD이므로 INSERT 후 암호화
        _run_sensitive(conn, license_id, plan, clears=False)
        changed = [label for _c, _b, label in plan]
        assets.set_tags(conn, "license", license_id, data.tags)
        summary = audit.diff_summary({}, {**values, "tags": ", ".join(data.tags)})
        if changed:
            summary += "; 민감 정보 등록: " + ", ".join(changed) + " (값 비공개)"
        audit.record(conn, request, "license_create", user=user, target_type="license", target_id=license_id,
                     summary=summary)
    security.add_flash(conn, user, "라이선스를 등록했습니다.")
    return RedirectResponse(f"/licenses/{license_id}", status_code=303)


_INSERT_SQL = ("INSERT INTO licenses (" + ", ".join(COLUMNS) + ", created_at, created_by, updated_at, updated_by) "
               "VALUES (" + ", ".join("?" for _ in COLUMNS) + ", ?, ?, ?, ?)")
_UPDATE_SQL = "UPDATE licenses SET " + ", ".join(c + " = ?" for c in COLUMNS) + ", updated_at = ?, updated_by = ? WHERE id = ?"


def _edit_values(lic: sqlite3.Row, tags: list[str]) -> dict:
    values = {}
    for c in COLUMNS:
        v = lic[c]
        if c in ("no_expiry", "auto_renew", "ssl_wildcard", "ai_usage_limit_set"):
            if v:
                values[c] = "on"
        else:
            values[c] = "" if v is None else (f"{v:g}" if isinstance(v, float) else str(v))
    values["tags"] = ", ".join(tags)
    return values


@router.get("/licenses/{license_id}/edit")
def license_edit_form(request: Request, license_id: int, user: CurrentUser = Depends(require_role("editor")),
                      conn: sqlite3.Connection = Depends(get_db)):
    lic = _get_license(conn, license_id)
    values = _edit_values(lic, assets.get_tags(conn, "license", license_id))
    return render(request, "licenses/form.html", _form_context(conn, lic, values, {}))


@router.post("/licenses/{license_id}/edit")
def license_edit(request: Request, license_id: int, user: CurrentUser = Depends(require_role("editor")),
                 form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    lic = _get_license(conn, license_id)
    data, errors = _validate(conn, form, lic)
    if data is None or errors:
        return render(request, "licenses/form.html",
                      _form_context(conn, lic, _form_page_values(form), errors), 422)
    values = _db_values(data)
    old = {**{c: lic[c] for c in COLUMNS}, "tags": ", ".join(sorted(assets.get_tags(conn, "license", license_id)))}
    new = {**values, "tags": ", ".join(sorted(data.tags))}
    plan = _plan_sensitive(request, license_id, data, lic)
    changed = [label for _c, _b, label in plan]
    summary = audit.diff_summary(old, new)
    with transaction(conn):
        if summary or changed:
            _run_sensitive(conn, license_id, plan, clears=True)
            conn.execute(_UPDATE_SQL, (*values.values(), now_iso(), user.id, license_id))
            _run_sensitive(conn, license_id, plan, clears=False)
            assets.set_tags(conn, "license", license_id, data.tags)
            if changed:
                summary = (summary + "; " if summary else "") + "민감 정보 변경: " + ", ".join(changed) + " (값 비공개)"
            audit.record(conn, request, "license_update", user=user, target_type="license", target_id=license_id,
                         summary=summary)
    security.add_flash(conn, user, "저장했습니다." if (summary or changed) else "변경된 내용이 없습니다.")
    return RedirectResponse(f"/licenses/{license_id}", status_code=303)


# ------------------------------------------------------------------ 상세 / 민감 정보 열람

def _masked(request: Request, lic: sqlite3.Row) -> list[dict]:
    """민감 정보는 기본적으로 마스킹(`****abcd`)해서 보여준다. AI API 종류에는 민감 정보가 없다."""
    items = []
    if lic["license_type"] == AI_TYPE:
        return items
    key = request.app.state.secret_key
    for form_field, column, _clear, label in SENSITIVE:
        blob = lic[column]
        if blob is None:
            items.append({"field": form_field, "label": label, "masked": None, "error": False})
            continue
        try:
            masked = security.mask_secret(security.decrypt_field(key, lic["id"], form_field, blob))
            items.append({"field": form_field, "label": label, "masked": masked, "error": False})
        except (InvalidTag, ValueError):
            log.error("license %s: %s 복호화 실패 (키 불일치 또는 데이터 손상)", lic["id"], form_field)
            items.append({"field": form_field, "label": label, "masked": None, "error": True})
    return items


def models_of_license(conn: sqlite3.Connection, license_id: int) -> list[sqlite3.Row]:
    return conn.execute("SELECT id, name, version, status, commercial_use FROM models WHERE license_id = ? "
                        "ORDER BY name, version", (license_id,)).fetchall()


@router.get("/licenses/{license_id}")
def license_detail(request: Request, license_id: int, user: CurrentUser = Depends(require_login),
                   conn: sqlite3.Connection = Depends(get_db)):
    lic = _get_license(conn, license_id)
    info = with_status([lic])[0]
    servers = conn.execute(
        "SELECT sv.id, sv.name, sv.hostname, sv.environment, sv.status FROM license_servers x "
        "JOIN servers sv ON sv.id = x.server_id WHERE x.license_id = ? ORDER BY sv.name", (license_id,)).fetchall()
    services = conn.execute(
        "SELECT sv.id, sv.name, sv.code, sv.tier, sv.status FROM license_services x "
        "JOIN services sv ON sv.id = x.service_id WHERE x.license_id = ? ORDER BY sv.tier, sv.code",
        (license_id,)).fetchall()
    return render(request, "licenses/detail.html", {
        "l": lic, "info": info, "can_write": _can_write(user), "sensitive": _masked(request, lic),
        "models": models_of_license(conn, license_id), "servers": servers, "services": services,
        "san_lines": (lic["ssl_san"] or "").splitlines(), "model_lines": (lic["ai_models"] or "").splitlines(),
        **assets.common_sections(conn, "license", license_id),
    })


@router.post("/licenses/{license_id}/reveal")
def license_reveal(request: Request, license_id: int, user: CurrentUser = Depends(require_role("editor")),
                   form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    """원문 열람은 POST + CSRF + editor 이상. 열람 행위는 (값 없이) 감사 로그에 남긴다."""
    lic = _get_license(conn, license_id)
    data, errors = validate_form(RevealForm, form)
    if data is None:
        raise HTTPException(status_code=422)
    column = dict((f, c) for f, c, _x, _l in SENSITIVE)[data.field]
    label = dict((f, lbl) for f, _c, _x, lbl in SENSITIVE)[data.field]
    if lic[column] is None:
        raise HTTPException(status_code=404)
    try:
        plain = security.decrypt_field(request.app.state.secret_key, license_id, data.field, lic[column])
    except (InvalidTag, ValueError):
        log.error("license %s: %s 복호화 실패", license_id, data.field)
        security.add_flash(conn, user, "복호화에 실패했습니다 (키 불일치 또는 데이터 손상).", "error")
        return RedirectResponse(f"/licenses/{license_id}", status_code=303)
    with transaction(conn):
        audit.record(conn, request, "license_reveal", user=user, target_type="license", target_id=license_id,
                     summary=f"{data.field} 원문 열람 (값 비공개)")
    return render(request, "licenses/reveal.html", {"l": lic, "label": label, "plain": plain})


# ------------------------------------------------------------------ 삭제

@router.get("/licenses/{license_id}/delete")
def license_delete_confirm(request: Request, license_id: int, user: CurrentUser = Depends(require_role("editor")),
                           conn: sqlite3.Connection = Depends(get_db)):
    lic = _get_license(conn, license_id)
    return render(request, "licenses/delete.html", {"l": lic, "models": models_of_license(conn, license_id)})


@router.post("/licenses/{license_id}/delete")
def license_delete(request: Request, license_id: int, user: CurrentUser = Depends(require_role("editor")),
                   form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    lic = _get_license(conn, license_id)
    with transaction(conn):
        assets.delete_asset_extras(conn, "license", license_id)
        conn.execute("DELETE FROM licenses WHERE id = ?", (license_id,))    # 연결 테이블 CASCADE, 모델 연결은 SET NULL
        audit.record(conn, request, "license_delete", user=user, target_type="license", target_id=license_id,
                     summary=f"name: {lic['name']}; type: {lic['license_type']}")
    security.add_flash(conn, user, "라이선스를 삭제했습니다.")
    return RedirectResponse("/licenses", status_code=303)


# ------------------------------------------------------------------ 서버/서비스 연결 (N:M)

def _touch(conn: sqlite3.Connection, license_id: int, user: CurrentUser) -> None:
    conn.execute("UPDATE licenses SET updated_at = ?, updated_by = ? WHERE id = ?", (now_iso(), user.id, license_id))


def _connect_page(request, lic, kind, options, errors, status=200):
    return render(request, "licenses/connect_form.html", {"l": lic, "kind": kind, "options": options, "errors": errors}, status)


_SERVER_OPTIONS = ("SELECT id, name || ' (' || hostname || ')' AS label FROM servers WHERE id NOT IN "
                   "(SELECT server_id FROM license_servers WHERE license_id = ?) ORDER BY name")
_SERVICE_OPTIONS = ("SELECT id, code || ' · ' || name AS label FROM services WHERE id NOT IN "
                    "(SELECT service_id FROM license_services WHERE license_id = ?) ORDER BY code")


@router.get("/licenses/{license_id}/servers/new")
def connect_server_form(request: Request, license_id: int, user: CurrentUser = Depends(require_role("editor")),
                        conn: sqlite3.Connection = Depends(get_db)):
    lic = _get_license(conn, license_id)
    return _connect_page(request, lic, "server", [(str(r["id"]), r["label"]) for r in conn.execute(_SERVER_OPTIONS, (license_id,))], {})


@router.post("/licenses/{license_id}/servers/new")
def connect_server(request: Request, license_id: int, user: CurrentUser = Depends(require_role("editor")),
                   form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    lic = _get_license(conn, license_id)
    data, errors = validate_form(LicenseServerForm, form)
    if data is not None:
        if not assets.exists(conn, "server", data.server_id):
            errors = {"server_id": "존재하지 않는 서버입니다."}
        elif conn.execute("SELECT 1 FROM license_servers WHERE license_id = ? AND server_id = ?",
                          (license_id, data.server_id)).fetchone():
            errors = {"server_id": "이미 연결된 서버입니다."}
    if data is None or errors:
        opts = [(str(r["id"]), r["label"]) for r in conn.execute(_SERVER_OPTIONS, (license_id,))]
        return _connect_page(request, lic, "server", opts, errors, 422)
    with transaction(conn):
        conn.execute("INSERT INTO license_servers (license_id, server_id) VALUES (?, ?)", (license_id, data.server_id))
        _touch(conn, license_id, user)
        audit.record(conn, request, "license_server_add", user=user, target_type="license", target_id=license_id,
                     summary=f"server #{data.server_id}")
    security.add_flash(conn, user, "서버를 연결했습니다.")
    return RedirectResponse(f"/licenses/{license_id}#servers", status_code=303)


@router.post("/licenses/{license_id}/servers/{server_id}/delete")
def disconnect_server(request: Request, license_id: int, server_id: int,
                      user: CurrentUser = Depends(require_role("editor")), form: dict[str, str] = Depends(csrf_form),
                      conn: sqlite3.Connection = Depends(get_db)):
    _get_license(conn, license_id)
    if not conn.execute("SELECT 1 FROM license_servers WHERE license_id = ? AND server_id = ?",
                        (license_id, server_id)).fetchone():
        raise HTTPException(status_code=404)
    with transaction(conn):
        conn.execute("DELETE FROM license_servers WHERE license_id = ? AND server_id = ?", (license_id, server_id))
        _touch(conn, license_id, user)
        audit.record(conn, request, "license_server_delete", user=user, target_type="license", target_id=license_id,
                     summary=f"server #{server_id}")
    security.add_flash(conn, user, "서버 연결을 해제했습니다.")
    return RedirectResponse(f"/licenses/{license_id}#servers", status_code=303)


@router.get("/licenses/{license_id}/services/new")
def connect_service_form(request: Request, license_id: int, user: CurrentUser = Depends(require_role("editor")),
                         conn: sqlite3.Connection = Depends(get_db)):
    lic = _get_license(conn, license_id)
    return _connect_page(request, lic, "service", [(str(r["id"]), r["label"]) for r in conn.execute(_SERVICE_OPTIONS, (license_id,))], {})


@router.post("/licenses/{license_id}/services/new")
def connect_service(request: Request, license_id: int, user: CurrentUser = Depends(require_role("editor")),
                    form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    lic = _get_license(conn, license_id)
    data, errors = validate_form(LicenseServiceForm, form)
    if data is not None:
        if not assets.exists(conn, "service", data.service_id):
            errors = {"service_id": "존재하지 않는 서비스입니다."}
        elif conn.execute("SELECT 1 FROM license_services WHERE license_id = ? AND service_id = ?",
                          (license_id, data.service_id)).fetchone():
            errors = {"service_id": "이미 연결된 서비스입니다."}
    if data is None or errors:
        opts = [(str(r["id"]), r["label"]) for r in conn.execute(_SERVICE_OPTIONS, (license_id,))]
        return _connect_page(request, lic, "service", opts, errors, 422)
    with transaction(conn):
        conn.execute("INSERT INTO license_services (license_id, service_id) VALUES (?, ?)", (license_id, data.service_id))
        _touch(conn, license_id, user)
        audit.record(conn, request, "license_service_add", user=user, target_type="license", target_id=license_id,
                     summary=f"service #{data.service_id}")
    security.add_flash(conn, user, "서비스를 연결했습니다.")
    return RedirectResponse(f"/licenses/{license_id}#services", status_code=303)


@router.post("/licenses/{license_id}/services/{service_id}/delete")
def disconnect_service(request: Request, license_id: int, service_id: int,
                       user: CurrentUser = Depends(require_role("editor")), form: dict[str, str] = Depends(csrf_form),
                       conn: sqlite3.Connection = Depends(get_db)):
    _get_license(conn, license_id)
    if not conn.execute("SELECT 1 FROM license_services WHERE license_id = ? AND service_id = ?",
                        (license_id, service_id)).fetchone():
        raise HTTPException(status_code=404)
    with transaction(conn):
        conn.execute("DELETE FROM license_services WHERE license_id = ? AND service_id = ?", (license_id, service_id))
        _touch(conn, license_id, user)
        audit.record(conn, request, "license_service_delete", user=user, target_type="license", target_id=license_id,
                     summary=f"service #{service_id}")
    security.add_flash(conn, user, "서비스 연결을 해제했습니다.")
    return RedirectResponse(f"/licenses/{license_id}#services", status_code=303)
