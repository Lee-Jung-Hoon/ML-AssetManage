"""CSV 내보내기 (editor 이상). 화면에 적용된 검색/필터 조건 그대로 전체 결과를 내보낸다 (페이지네이션 무시).

POST + CSRF로만 받는다: 내보내기는 감사 로그를 남기는(상태가 바뀌는) 요청이다. 필터는 쿼리스트링으로 전달된다.
민감 필드(라이선스 키/계정 정보)는 어떤 쿼리에서도 선택하지 않는다.
"""
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Request

from .. import assets, audit, csvio
from ..db import get_db, select_where
from ..forms import csrf_form
from ..schemas import LicenseFilter, ModelFilter, ServerFilter, ServiceFilter, validate_form
from ..security import CurrentUser, require_login, require_role
from ..templating import kst
from . import licenses as license_views
from . import models as model_views
from . import servers as server_views
from . import services as service_views

router = APIRouter(dependencies=[Depends(require_login)])

SERVER_HEADERS = ["name", "hostname", "os_type", "os_distro", "os_version", "kernel_version", "environment", "status",
                  "server_type", "location", "cpu_model", "cpu_cores", "memory_gb", "primary_ip", "owner_username",
                  "tags", "description", "ips", "max_disk_usage_pct", "gpu_summary", "last_verified_at", "updated_at"]
SERVICE_HEADERS = ["code", "name", "category", "environment", "status", "tier", "team", "urls", "repo_url", "doc_url",
                   "tech_stack", "deploy_method", "serving_engine", "primary_owner", "secondary_owner", "server_count",
                   "tags", "description", "notes", "last_verified_at", "updated_at"]
MODEL_HEADERS = ["name", "version", "model_type", "source", "base_model", "model_license", "commercial_use", "status",
                 "license_risk", "param_size", "vram_gb", "storage_location", "experiment_url", "card_url",
                 "api_license", "service_count", "owner", "tags", "description", "license_note", "last_verified_at",
                 "updated_at"]
LICENSE_HEADERS = ["name", "license_type", "vendor", "start_date", "expires_at", "no_expiry", "expiry_state", "auto_renew",
                   "quantity", "cost", "currency", "billing_cycle", "alert_days", "ssl_cn", "ssl_san", "ssl_wildcard",
                   "ssl_ca", "ssl_key_algo", "ssl_serial", "ssl_sha256", "ai_provider", "ai_models",
                   "ai_monthly_budget", "ai_usage_limit_set", "ai_key_location", "ai_sends_customer_data",
                   "ai_training_opt_out", "ai_retention_note", "owner", "tags", "notes", "last_verified_at", "updated_at"]
ACL_HEADERS = ["server_name", "hostname", "direction", "src_cidr", "dst_cidr", "port", "protocol", "purpose",
               "requester", "requested_at", "ticket_no", "status", "expires_at"]


def _joined(values: list[str]) -> str:
    return ";".join(values)


def _lines(text: str | None) -> str:
    return _joined((text or "").splitlines())


def _log_export(conn: sqlite3.Connection, request: Request, user: CurrentUser, target_type: str, count: int) -> None:
    filters = "; ".join(f"{k}={v}" for k, v in request.query_params.items() if k != "page" and v != "")
    audit.record(conn, request, "csv_export", user=user, target_type=target_type,
                 summary=f"rows={count}" + (f"; filters: {filters}" if filters else ""))


def _filter_or_400(model, request: Request):
    flt, errors = validate_form(model, dict(request.query_params))
    if flt is None:
        raise HTTPException(status_code=400)
    return flt


# ------------------------------------------------------------------ 서버

_SERVER_SELECT = (
    "SELECT s.id, s.name, s.hostname, s.os_type, s.os_distro, s.os_version, s.kernel_version, s.environment, s.status, "
    "s.server_type, s.location, s.cpu_model, s.cpu_cores, s.memory_gb, s.description, s.last_verified_at, s.updated_at, "
    "o.username AS owner_username, "
    "(SELECT MAX(d.used_gb * 100.0 / d.total_gb) FROM server_disks d WHERE d.server_id = s.id) AS max_disk_pct, "
    "(SELECT group_concat(g.gpu_model || ' x' || g.quantity, '; ') FROM server_gpus g WHERE g.server_id = s.id) AS gpus "
    "FROM servers s LEFT JOIN users o ON o.id = s.owner_id"
)
_IPS_OF = ("SELECT server_id, ip, is_primary FROM server_ips WHERE server_id IN (SELECT value FROM json_each(?)) "
           "ORDER BY server_id, is_primary DESC, id")


@router.post("/servers/export")
def export_servers(request: Request, user: CurrentUser = Depends(require_role("editor")),
                   form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    flt = _filter_or_400(ServerFilter, request)
    rows = select_where(conn, _SERVER_SELECT, server_views.server_conditions(flt, user),
                        server_views._ORDER_ALL[flt.sort]).fetchall()
    ids = [r["id"] for r in rows]
    tags = assets.tags_by_asset(conn, "server", ids)
    ips: dict[int, list[tuple[str, int]]] = {i: [] for i in ids}
    import json
    for r in conn.execute(_IPS_OF, (json.dumps(ids),)):
        ips[r["server_id"]].append((r["ip"], r["is_primary"]))
    data = []
    for r in rows:
        server_ips = ips[r["id"]]
        primary = next((ip for ip, is_primary in server_ips if is_primary), "")
        disk = round(r["max_disk_pct"], 1) if r["max_disk_pct"] is not None else ""
        data.append([r["name"], r["hostname"], r["os_type"], r["os_distro"], r["os_version"], r["kernel_version"],
                     r["environment"], r["status"], r["server_type"], r["location"], r["cpu_model"], r["cpu_cores"],
                     r["memory_gb"], primary, r["owner_username"] or "", _joined(tags[r["id"]]), r["description"],
                     _joined([ip for ip, _ in server_ips]), disk, r["gpus"] or "",
                     kst(r["last_verified_at"]), kst(r["updated_at"])])
    _log_export(conn, request, user, "server", len(data))
    return csvio.csv_download("servers", SERVER_HEADERS, data)


# ------------------------------------------------------------------ 서비스

_SERVICE_SELECT = (
    "SELECT s.id, s.code, s.name, s.category, s.environment, s.status, s.tier, s.team, s.urls, s.repo_url, s.doc_url, "
    "s.tech_stack, s.deploy_method, s.serving_engine, s.description, s.notes, s.last_verified_at, s.updated_at, "
    "p.username AS primary_owner, q.username AS secondary_owner, "
    "(SELECT COUNT(*) FROM service_servers ss WHERE ss.service_id = s.id) AS server_count "
    "FROM services s LEFT JOIN users p ON p.id = s.primary_owner_id LEFT JOIN users q ON q.id = s.secondary_owner_id"
)


@router.post("/services/export")
def export_services(request: Request, user: CurrentUser = Depends(require_role("editor")),
                    form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    flt = _filter_or_400(ServiceFilter, request)
    rows = select_where(conn, _SERVICE_SELECT, service_views.service_conditions(flt, user),
                        service_views._ORDER_ALL[flt.sort]).fetchall()
    tags = assets.tags_by_asset(conn, "service", [r["id"] for r in rows])
    data = [[r["code"], r["name"], r["category"], r["environment"], r["status"], r["tier"], r["team"], _lines(r["urls"]),
             r["repo_url"], r["doc_url"], r["tech_stack"], r["deploy_method"], r["serving_engine"] or "",
             r["primary_owner"] or "", r["secondary_owner"] or "", r["server_count"], _joined(tags[r["id"]]),
             r["description"], r["notes"], kst(r["last_verified_at"]), kst(r["updated_at"])] for r in rows]
    _log_export(conn, request, user, "service", len(data))
    return csvio.csv_download("services", SERVICE_HEADERS, data)


# ------------------------------------------------------------------ AI 모델

_MODEL_SELECT = (
    "SELECT m.id, m.name, m.version, m.model_type, m.source, m.base_model, m.model_license, m.commercial_use, m.status, "
    "m.param_size, m.vram_gb, m.storage_location, m.experiment_url, m.card_url, m.description, m.license_note, "
    "m.last_verified_at, m.updated_at, o.username AS owner, l.name AS api_license, "
    "(SELECT COUNT(*) FROM model_services ms WHERE ms.model_id = m.id) AS service_count, "
    "(" + assets.MODEL_PROD_LINKED_SQL + ") AS prod_linked "
    "FROM models m LEFT JOIN users o ON o.id = m.owner_id LEFT JOIN licenses l ON l.id = m.license_id"
)


@router.post("/models/export")
def export_models(request: Request, user: CurrentUser = Depends(require_role("editor")),
                  form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    flt = _filter_or_400(ModelFilter, request)
    rows = select_where(conn, _MODEL_SELECT, model_views.model_conditions(flt, user),
                        model_views._ORDER_ALL[flt.sort]).fetchall()
    tags = assets.tags_by_asset(conn, "model", [r["id"] for r in rows])
    risk_text = {"risk": "라이선스 위험", "conditional": "조건 확인", None: ""}
    data = [[r["name"], r["version"], r["model_type"], r["source"], r["base_model"], r["model_license"],
             r["commercial_use"], r["status"],
             risk_text[assets.license_risk(r["commercial_use"], r["status"], bool(r["prod_linked"]))],
             r["param_size"], r["vram_gb"], r["storage_location"], r["experiment_url"], r["card_url"],
             r["api_license"] or "", r["service_count"], r["owner"] or "", _joined(tags[r["id"]]), r["description"],
             r["license_note"], kst(r["last_verified_at"]), kst(r["updated_at"])] for r in rows]
    _log_export(conn, request, user, "model", len(data))
    return csvio.csv_download("models", MODEL_HEADERS, data)


# ------------------------------------------------------------------ 라이선스 (민감 컬럼은 선택하지 않는다)

_LICENSE_SELECT = (
    "SELECT l.id, l.name, l.license_type, l.vendor, l.start_date, l.expires_at, l.no_expiry, l.auto_renew, l.quantity, "
    "l.cost, l.currency, l.billing_cycle, l.alert_days, l.ssl_cn, l.ssl_san, l.ssl_wildcard, l.ssl_ca, l.ssl_key_algo, "
    "l.ssl_serial, l.ssl_sha256, l.ai_provider, l.ai_models, l.ai_monthly_budget, l.ai_usage_limit_set, "
    "l.ai_key_location, l.ai_sends_customer_data, l.ai_training_opt_out, l.ai_retention_note, l.notes, "
    "l.last_verified_at, l.updated_at, o.username AS owner "
    "FROM licenses l LEFT JOIN users o ON o.id = l.owner_id"
)


@router.post("/licenses/export")
def export_licenses(request: Request, user: CurrentUser = Depends(require_role("editor")),
                    form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    flt = _filter_or_400(LicenseFilter, request)
    today = assets.today_kst()
    rows = select_where(conn, _LICENSE_SELECT, license_views.license_conditions(flt, user, today),
                        license_views._ORDER_ALL[flt.sort]).fetchall()
    tags = assets.tags_by_asset(conn, "license", [r["id"] for r in rows])
    data = []
    for r in rows:
        state = assets.license_status(r["expires_at"], bool(r["no_expiry"]), r["alert_days"], today)["state"]
        data.append([r["name"], r["license_type"], r["vendor"], r["start_date"] or "", r["expires_at"] or "",
                     bool(r["no_expiry"]), state, bool(r["auto_renew"]), r["quantity"], r["cost"], r["currency"],
                     r["billing_cycle"] or "", r["alert_days"], r["ssl_cn"] or "", _lines(r["ssl_san"]),
                     bool(r["ssl_wildcard"]) if r["license_type"] == "SSL/TLS 인증서" else "", r["ssl_ca"] or "",
                     r["ssl_key_algo"] or "", r["ssl_serial"] or "", r["ssl_sha256"] or "", r["ai_provider"] or "",
                     _lines(r["ai_models"]), r["ai_monthly_budget"],
                     bool(r["ai_usage_limit_set"]) if r["ai_usage_limit_set"] is not None else "",
                     r["ai_key_location"] or "", r["ai_sends_customer_data"] or "", r["ai_training_opt_out"] or "",
                     r["ai_retention_note"] or "", r["owner"] or "", _joined(tags[r["id"]]), r["notes"],
                     kst(r["last_verified_at"]), kst(r["updated_at"])])
    _log_export(conn, request, user, "license", len(data))
    return csvio.csv_download("licenses", LICENSE_HEADERS, data)
