"""대시보드: 숫자 카드, 테이블, CSS 막대로만 표현한다 (차트 라이브러리 없음).

폐기/종료 상태의 자산은 디스크 경고, GPU 현황, 확인 필요, 담당자 없음 집계에서 제외한다.
모든 쿼리는 고정 SQL이며 값은 `?`로 바인딩한다.
"""
import sqlite3

from fastapi import APIRouter, Depends, Request

from .. import assets, audit, csvio
from ..db import get_db
from ..forms import csrf_form
from ..security import CurrentUser, require_login, require_role
from ..templating import render
from . import licenses as license_views

router = APIRouter(dependencies=[Depends(require_login)])

DISK_WARN, DISK_DANGER = 80, 90
ALERT_LICENSE_DAYS = 30
EXPIRY_DAYS = (30, 90)
LIST_LIMIT = 20


def _rows(conn: sqlite3.Connection, sql: str, *params) -> list[sqlite3.Row]:
    return conn.execute(sql, params).fetchall()


def _scalar(conn: sqlite3.Connection, sql: str, *params) -> int:
    return conn.execute(sql, params).fetchone()[0] or 0


def _counts(rows, key: str = "name") -> list[dict]:
    """[(라벨, 건수)] → 막대 너비(상대 비율) 계산용 dict 목록."""
    items = [{"label": r[key], "count": r["n"]} for r in rows]
    top = max((i["count"] for i in items), default=0)
    for i in items:
        i["pct"] = (i["count"] * 100 / top) if top else 0
    return items


# ------------------------------------------------------------------ 확인 필요 / 내 담당 (4종 자산 UNION)

# 폐기/종료 제외, 확인 필요(미확인 또는 90일 경과). 파라미터: 기준 시각 4회
_STALE_UNION = (
    "SELECT 'server' AS kind, s.id AS id, s.name AS name, s.last_verified_at AS verified, "
    "'/servers/' || s.id AS url, o.display_name AS owner, o.is_active AS owner_active "
    "FROM servers s LEFT JOIN users o ON o.id = s.owner_id "
    "WHERE s.status != '폐기' AND (s.last_verified_at IS NULL OR s.last_verified_at < :cutoff) "
    "UNION ALL SELECT 'service', s.id, s.code || ' · ' || s.name, s.last_verified_at, '/services/' || s.id, "
    "p.display_name, p.is_active FROM services s LEFT JOIN users p ON p.id = s.primary_owner_id "
    "WHERE s.status != '종료' AND (s.last_verified_at IS NULL OR s.last_verified_at < :cutoff) "
    "UNION ALL SELECT 'model', m.id, m.name || ' ' || m.version, m.last_verified_at, '/models/' || m.id, "
    "o.display_name, o.is_active FROM models m LEFT JOIN users o ON o.id = m.owner_id "
    "WHERE m.status != '폐기' AND (m.last_verified_at IS NULL OR m.last_verified_at < :cutoff) "
    "UNION ALL SELECT 'license', l.id, l.name, l.last_verified_at, '/licenses/' || l.id, o.display_name, o.is_active "
    "FROM licenses l LEFT JOIN users o ON o.id = l.owner_id "
    "WHERE (l.last_verified_at IS NULL OR l.last_verified_at < :cutoff)"
)
_STALE_ORDER = "ORDER BY verified IS NOT NULL, verified, name LIMIT :limit"      # 미확인(NULL)이 가장 오래된 것
_STALE_TOP = "SELECT * FROM (" + _STALE_UNION + ") " + _STALE_ORDER
_STALE_COUNT = "SELECT COUNT(*) FROM (" + _STALE_UNION + ")"

_MINE_STALE = (
    "SELECT * FROM (" + _STALE_UNION + ") WHERE (kind, id) IN ("
    "SELECT 'server', id FROM servers WHERE owner_id = :me UNION ALL "
    "SELECT 'service', id FROM services WHERE primary_owner_id = :me OR secondary_owner_id = :me UNION ALL "
    "SELECT 'model', id FROM models WHERE owner_id = :me UNION ALL SELECT 'license', id FROM licenses WHERE owner_id = :me) "
    + _STALE_ORDER
)


def _my_counts(conn: sqlite3.Connection, me: int) -> dict:
    counts = {
        "server": _scalar(conn, "SELECT COUNT(*) FROM servers WHERE owner_id = ?", me),
        "service": _scalar(conn, "SELECT COUNT(*) FROM services WHERE primary_owner_id = ? OR secondary_owner_id = ?",
                           me, me),                      # 서비스는 정/부 모두 포함
        "model": _scalar(conn, "SELECT COUNT(*) FROM models WHERE owner_id = ?", me),
        "license": _scalar(conn, "SELECT COUNT(*) FROM licenses WHERE owner_id = ?", me),
    }
    counts["total"] = sum(counts.values())
    return counts


# ------------------------------------------------------------------ 서버 / 디스크 / GPU

_DISK_ROWS = (
    "SELECT s.id AS server_id, s.name AS server_name, s.hostname, d.mount_point, d.used_gb, d.total_gb, "
    "d.used_gb * 100.0 / d.total_gb AS pct FROM server_disks d JOIN servers s ON s.id = d.server_id "
    "WHERE s.status != '폐기' AND d.used_gb * 100.0 / d.total_gb >= ? ORDER BY pct DESC, s.name LIMIT ?"
)
_DISK_COUNT = ("SELECT COUNT(*) FROM server_disks d JOIN servers s ON s.id = d.server_id "
               "WHERE s.status != '폐기' AND d.used_gb * 100.0 / d.total_gb >= ?")


def disk_level(pct: float) -> str:
    return "위험" if pct >= DISK_DANGER else "주의"


def _gpu_section(conn: sqlite3.Connection) -> dict:
    totals = conn.execute(
        "SELECT COALESCE(SUM(g.quantity), 0) AS gpus, COALESCE(SUM(g.quantity * g.vram_gb), 0) AS vram "
        "FROM server_gpus g JOIN servers s ON s.id = g.server_id WHERE s.status != '폐기'").fetchone()
    by_model = _rows(conn,
        "SELECT g.gpu_model AS name, SUM(g.quantity) AS n FROM server_gpus g JOIN servers s ON s.id = g.server_id "
        "WHERE s.status != '폐기' GROUP BY g.gpu_model ORDER BY n DESC, g.gpu_model")
    unassigned = _rows(conn,
        "SELECT s.id AS server_id, s.name AS server_name, s.hostname, g.gpu_model, g.quantity FROM server_gpus g "
        "JOIN servers s ON s.id = g.server_id WHERE s.status != '폐기' AND TRIM(g.assigned_to) = '' "
        "ORDER BY g.gpu_model, s.name LIMIT ?", LIST_LIMIT)
    unassigned_total = _scalar(conn,
        "SELECT COUNT(*) FROM server_gpus g JOIN servers s ON s.id = g.server_id "
        "WHERE s.status != '폐기' AND TRIM(g.assigned_to) = ''")
    combos = _rows(conn,
        "SELECT g.gpu_model, g.driver_version, g.cuda_version, COUNT(DISTINCT g.server_id) AS servers "
        "FROM server_gpus g JOIN servers s ON s.id = g.server_id WHERE s.status != '폐기' "
        "GROUP BY g.gpu_model, g.driver_version, g.cuda_version ORDER BY g.gpu_model, servers DESC, g.driver_version")
    models: dict[str, dict] = {}
    for r in combos:
        entry = models.setdefault(r["gpu_model"], {"model": r["gpu_model"], "combos": [], "known": 0})
        known = bool(r["driver_version"] or r["cuda_version"])
        entry["known"] += known
        entry["combos"].append({"driver": r["driver_version"] or "(미기재)", "cuda": r["cuda_version"] or "(미기재)",
                                "servers": r["servers"]})
    for entry in models.values():          # 같은 GPU 모델에 (드라이버, CUDA) 조합이 둘 이상이면 버전 불일치 (미기재 조합은 제외하고 판정)
        entry["mismatch"] = entry["known"] > 1
    return {"gpus": totals["gpus"], "vram": totals["vram"], "by_model": _counts(by_model), "unassigned": unassigned,
            "unassigned_total": unassigned_total, "versions": list(models.values()),
            "mismatch_count": sum(1 for m in models.values() if m["mismatch"])}


# ------------------------------------------------------------------ 라이선스

def _license_section(conn: sqlite3.Connection, today: str) -> dict:
    counts = {
        "expired": _scalar(conn, "SELECT COUNT(*) FROM licenses WHERE no_expiry = 0 AND expires_at < ?", today),
    }
    for days in EXPIRY_DAYS:     # 30일/90일 이내: 오늘 ~ 오늘+N일 (90일 이내는 30일 이내를 포함)
        counts[f"d{days}"] = _scalar(
            conn, "SELECT COUNT(*) FROM licenses WHERE no_expiry = 0 AND expires_at >= ? AND expires_at <= date(?, ?)",
            today, today, f"+{days} days")
    rows = _rows(conn,
        "SELECT l.id, l.name, l.license_type, l.expires_at, l.no_expiry, l.alert_days, l.ai_provider, "
        "l.ai_sends_customer_data, l.ai_training_opt_out FROM licenses l WHERE l.no_expiry = 0 AND "
        "l.expires_at <= date(?, ?) ORDER BY l.expires_at, l.name LIMIT ?", today, f"+{EXPIRY_DAYS[-1]} days", LIST_LIMIT)
    return {"counts": counts, "rows": license_views.with_status(rows)}


def _ai_api_section(conn: sqlite3.Connection, today: str) -> list[dict]:
    """제공사별 건수와 월 예산 합계. 통화별로 따로 합산한다 (환율 변환 없음). 만료된 API는 제외한다."""
    rows = _rows(conn,
        "SELECT ai_provider, currency, COUNT(*) AS n, SUM(ai_monthly_budget) AS budget FROM licenses "
        "WHERE license_type = 'AI API' AND (no_expiry = 1 OR expires_at >= ?) GROUP BY ai_provider, currency", today)
    providers: dict[str, dict] = {}
    for r in rows:
        entry = providers.setdefault(r["ai_provider"], {"provider": r["ai_provider"], "count": 0, "budgets": {}})
        entry["count"] += r["n"]
        if r["budget"]:
            entry["budgets"][r["currency"]] = r["budget"]
    return sorted(providers.values(), key=lambda p: (-p["count"], p["provider"]))


# ------------------------------------------------------------------ 요약

def build_dashboard(conn: sqlite3.Connection, user: CurrentUser) -> dict:
    today, cutoff = assets.today_kst(), assets.stale_cutoff()
    stale_total = _scalar_named(conn, _STALE_COUNT, cutoff=cutoff)

    # --- 긴급 알림 ---
    tier1_licenses = _rows(conn,
        "SELECT l.id AS license_id, l.name AS license_name, l.expires_at, l.alert_days, l.no_expiry, "
        "s.id AS service_id, s.name AS service_name, s.code FROM license_services ls "
        "JOIN licenses l ON l.id = ls.license_id JOIN services s ON s.id = ls.service_id "
        "WHERE s.tier = 1 AND s.status != '종료' AND l.no_expiry = 0 AND l.expires_at <= date(?, ?) "
        "ORDER BY l.expires_at, s.code LIMIT ?", today, f"+{ALERT_LICENSE_DAYS} days", LIST_LIMIT)
    tier1_total = _scalar(conn,
        "SELECT COUNT(*) FROM license_services ls JOIN licenses l ON l.id = ls.license_id "
        "JOIN services s ON s.id = ls.service_id WHERE s.tier = 1 AND s.status != '종료' AND l.no_expiry = 0 "
        "AND l.expires_at <= date(?, ?)", today, f"+{ALERT_LICENSE_DAYS} days")
    tier1 = [{**dict(r), "status": assets.license_status(r["expires_at"], False, r["alert_days"], today)}
             for r in tier1_licenses]
    danger_disks = _rows(conn, _DISK_ROWS, DISK_DANGER, LIST_LIMIT)
    danger_total = _scalar(conn, _DISK_COUNT, DISK_DANGER)
    risky_models = _rows(conn,
        "SELECT m.id, m.name, m.version, m.status, m.commercial_use, ("
        + assets.MODEL_PROD_LINKED_SQL + ") AS prod_linked FROM models m WHERE " + assets.MODEL_RISK_SQL +
        " ORDER BY m.name, m.version LIMIT ?", LIST_LIMIT)
    risky_total = _scalar(conn, "SELECT COUNT(*) FROM models m WHERE " + assets.MODEL_RISK_SQL)
    policy = _rows(conn,
        "SELECT id, name, ai_provider, ai_training_opt_out FROM licenses WHERE license_type = 'AI API' AND "
        "ai_sends_customer_data = '예' AND ai_training_opt_out IN ('미설정', '미확인') ORDER BY name LIMIT ?", LIST_LIMIT)
    policy_total = _scalar(conn,
        "SELECT COUNT(*) FROM licenses WHERE license_type = 'AI API' AND ai_sends_customer_data = '예' AND "
        "ai_training_opt_out IN ('미설정', '미확인')")
    alerts = {"tier1_licenses": tier1, "tier1_total": tier1_total, "disks": danger_disks, "disks_total": danger_total,
              "models": risky_models, "models_total": risky_total, "policy": policy, "policy_total": policy_total}
    alerts["any"] = bool(tier1_total or danger_total or risky_total or policy_total)

    # --- 요약 카드 ---
    gpu = _gpu_section(conn)
    cards = {
        "servers": _scalar(conn, "SELECT COUNT(*) FROM servers"),
        "services": _scalar(conn, "SELECT COUNT(*) FROM services"),
        "models": _scalar(conn, "SELECT COUNT(*) FROM models"),
        "licenses": _scalar(conn, "SELECT COUNT(*) FROM licenses"),
        "gpus": gpu["gpus"],
        "acl_pending": _scalar(conn, "SELECT COUNT(*) FROM server_acls WHERE status IN ('요청', '승인')"),
        "stale": stale_total,
    }

    # --- 내 담당 ---
    mine = _my_counts(conn, user.id)
    mine_stale = _rows_named(conn, _MINE_STALE, cutoff=cutoff, me=user.id, limit=LIST_LIMIT)

    # --- 서버 ---
    servers = {
        "environments": _counts(_rows(conn, "SELECT environment AS name, COUNT(*) AS n FROM servers GROUP BY environment "
                                            "ORDER BY n DESC, environment")),
        "status": _counts(_rows(conn, "SELECT status AS name, COUNT(*) AS n FROM servers GROUP BY status ORDER BY n DESC, status")),
        "os": _counts(_rows(conn,
            "SELECT os_type || CASE WHEN os_distro = '' THEN ' (배포판 미기재)' ELSE ' / ' || os_distro END AS name, "
            "COUNT(*) AS n FROM servers GROUP BY os_type, os_distro ORDER BY os_type DESC, n DESC, os_distro")),
    }
    disks = {
        "rows": [{**dict(r), "level": disk_level(r["pct"])} for r in _rows(conn, _DISK_ROWS, DISK_WARN, 10)],
        "warn": _scalar(conn, _DISK_COUNT, DISK_WARN) - danger_total, "danger": danger_total,
    }

    # --- 서비스 ---
    no_owner_sql = (
        "FROM services s LEFT JOIN users p ON p.id = s.primary_owner_id LEFT JOIN users q ON q.id = s.secondary_owner_id "
        "WHERE s.status != '종료' AND (p.id IS NULL OR p.is_active = 0) AND (q.id IS NULL OR q.is_active = 0)")
    services = {
        "status": _counts(_rows(conn, "SELECT status AS name, COUNT(*) AS n FROM services GROUP BY status ORDER BY n DESC, status")),
        "tiers": _counts(_rows(conn, "SELECT 'Tier ' || tier AS name, COUNT(*) AS n FROM services GROUP BY tier ORDER BY tier")),
        "no_owner": _rows(conn, "SELECT s.id, s.name, s.code, s.tier, s.primary_owner_id, s.secondary_owner_id " + no_owner_sql +
                          " ORDER BY s.tier, s.code LIMIT ?", LIST_LIMIT),
        "no_owner_total": _scalar(conn, "SELECT COUNT(*) " + no_owner_sql),
    }
    no_owner_counts = {
        "server": _scalar(conn, "SELECT COUNT(*) FROM servers s LEFT JOIN users o ON o.id = s.owner_id "
                                "WHERE s.status != '폐기' AND (o.id IS NULL OR o.is_active = 0)"),
        "service": services["no_owner_total"],
        "model": _scalar(conn, "SELECT COUNT(*) FROM models m LEFT JOIN users o ON o.id = m.owner_id "
                               "WHERE m.status != '폐기' AND (o.id IS NULL OR o.is_active = 0)"),
        "license": _scalar(conn, "SELECT COUNT(*) FROM licenses l LEFT JOIN users o ON o.id = l.owner_id "
                                 "WHERE o.id IS NULL OR o.is_active = 0"),
    }

    # --- AI 모델 ---
    models = {
        "status": _counts(_rows(conn, "SELECT status AS name, COUNT(*) AS n FROM models GROUP BY status ORDER BY n DESC, status")),
        "source": _counts(_rows(conn, "SELECT source AS name, COUNT(*) AS n FROM models GROUP BY source ORDER BY n DESC, source")),
        "conditional": _rows(conn,
            "SELECT id, name, version, status, license_note FROM models WHERE commercial_use = '조건부' AND status != '폐기' "
            "ORDER BY name, version LIMIT ?", LIST_LIMIT),
    }

    # --- 확인 필요 자산 / 최근 변경 ---
    stale_top = _rows_named(conn, _STALE_TOP, cutoff=cutoff, limit=10)
    recent = _rows(conn,
        "SELECT at, username, action, target_type, target_id, summary FROM audit_logs WHERE target_type IN "
        "('server', 'service', 'model', 'license') AND target_id IS NOT NULL AND action NOT LIKE '%verify' AND "
        "action NOT LIKE '%note%' AND action != 'license_reveal' ORDER BY id DESC LIMIT 10")

    return {"alerts": alerts, "cards": cards, "mine": mine, "mine_stale": mine_stale, "servers": servers, "disks": disks,
            "services": services, "no_owner_counts": no_owner_counts, "gpu": gpu, "models": models,
            "ai_api": _ai_api_section(conn, today), "licenses": _license_section(conn, today), "stale": stale_top,
            "recent": recent, "today": today}


def _scalar_named(conn: sqlite3.Connection, sql: str, **params) -> int:
    return conn.execute(sql, params).fetchone()[0] or 0


def _rows_named(conn: sqlite3.Connection, sql: str, **params) -> list[sqlite3.Row]:
    return conn.execute(sql, params).fetchall()


@router.get("/")
def dashboard(request: Request, user: CurrentUser = Depends(require_login), conn: sqlite3.Connection = Depends(get_db)):
    data = build_dashboard(conn, user)
    return render(request, "dashboard.html", {
        "d": data, "kinds": {"server": "서버", "service": "서비스", "model": "AI 모델", "license": "라이선스"},
        "can_export": user.role in ("editor", "admin"), "disk_warn": DISK_WARN, "disk_danger": DISK_DANGER,
        "alert_days": ALERT_LICENSE_DAYS, "expiry_days": EXPIRY_DAYS})


# ------------------------------------------------------------------ GPU 전체 인벤토리 CSV (editor 이상)

GPU_HEADERS = ["server_name", "hostname", "gpu_model", "quantity", "vram_gb", "driver_version", "cuda_version",
               "mig_config", "nvlink", "assigned_to", "assign_note"]


@router.post("/dashboard/gpus/export")
def export_gpus(request: Request, user: CurrentUser = Depends(require_role("editor")),
                form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    rows = _rows(conn,
        "SELECT s.name AS server_name, s.hostname, g.gpu_model, g.quantity, g.vram_gb, g.driver_version, g.cuda_version, "
        "g.mig_config, g.nvlink, g.assigned_to, g.assign_note FROM server_gpus g JOIN servers s ON s.id = g.server_id "
        "WHERE s.status != '폐기' ORDER BY s.name, g.gpu_model, g.id")
    data = [[r["server_name"], r["hostname"], r["gpu_model"], r["quantity"], r["vram_gb"], r["driver_version"],
             r["cuda_version"], r["mig_config"], bool(r["nvlink"]), r["assigned_to"], r["assign_note"]] for r in rows]
    audit.record(conn, request, "csv_export", user=user, target_type="gpu", summary=f"rows={len(data)}")
    return csvio.csv_download("gpus", GPU_HEADERS, data)
