"""통합 검색: GET /search?q= (조회 전용). 서버/서비스/AI 모델/GPU/라이선스/컨테이너/태그, IP 입력 시 ACL.

민감 필드(라이선스 키/계정 정보)는 검색 대상이 아니며 쿼리에 포함되지 않는다.
"""
import ipaddress
import sqlite3

from fastapi import APIRouter, Depends, Request

from .. import assets
from ..db import get_db, like_pattern
from ..schemas import SEARCH_MAX, SEARCH_MIN, SearchQuery, validate_form
from ..security import CurrentUser, require_login
from ..templating import render
from .licenses import with_status

router = APIRouter(dependencies=[Depends(require_login)])

GROUP_LIMIT = 20
_L = "LIKE ? ESCAPE '\\'"

# (그룹 키, 제목, 목록 SQL, 건수 SQL, 파라미터 개수). 모든 SQL은 고정 상수이며 검색어는 `?`로만 바인딩한다.
_SERVERS = (
    "FROM servers s WHERE s.name " + _L + " OR s.hostname " + _L + " OR EXISTS "
    "(SELECT 1 FROM server_ips i WHERE i.server_id = s.id AND i.ip " + _L + ")", 3)
_SERVICES = ("FROM services s WHERE s.name " + _L + " OR s.code " + _L + " OR s.urls " + _L, 3)
_MODELS = ("FROM models m WHERE m.name " + _L + " OR m.base_model " + _L, 2)
_GPUS = ("FROM server_gpus g JOIN servers s ON s.id = g.server_id WHERE g.gpu_model " + _L, 1)
_LICENSES = ("FROM licenses l WHERE l.name " + _L + " OR l.ssl_cn " + _L + " OR l.ssl_san " + _L +
             " OR l.ai_provider " + _L, 4)
_CONTAINERS = ("FROM server_containers c JOIN servers s ON s.id = c.server_id WHERE c.name " + _L +
               " OR c.image " + _L, 2)

_SQL = {
    "servers": (
        "SELECT s.id, s.name, s.hostname, s.status, (SELECT group_concat(i.ip, ', ') FROM server_ips i "
        "WHERE i.server_id = s.id AND i.ip " + _L + ") AS matched_ip " + _SERVERS[0] + " ORDER BY s.name, s.id LIMIT ?",
        "SELECT COUNT(*) " + _SERVERS[0]),
    "services": (
        "SELECT s.id, s.name, s.code, s.tier, s.status " + _SERVICES[0] + " ORDER BY s.code, s.id LIMIT ?",
        "SELECT COUNT(*) " + _SERVICES[0]),
    "models": (
        "SELECT m.id, m.name, m.version, m.base_model, m.status " + _MODELS[0] + " ORDER BY m.name, m.version LIMIT ?",
        "SELECT COUNT(*) " + _MODELS[0]),
    "gpus": (
        "SELECT s.id, s.name, s.hostname, g.gpu_model, g.quantity, g.assigned_to " + _GPUS[0] +
        " ORDER BY g.gpu_model, s.name, g.id LIMIT ?", "SELECT COUNT(*) " + _GPUS[0]),
    "licenses": (
        "SELECT l.id, l.name, l.license_type, l.expires_at, l.no_expiry, l.alert_days, l.ai_provider, "
        "l.ai_sends_customer_data, l.ai_training_opt_out " + _LICENSES[0] + " ORDER BY l.name, l.id LIMIT ?",
        "SELECT COUNT(*) " + _LICENSES[0]),
    "containers": (
        "SELECT s.id, s.name AS server_name, c.name, c.image " + _CONTAINERS[0] + " ORDER BY c.name, s.name LIMIT ?",
        "SELECT COUNT(*) " + _CONTAINERS[0]),
}
_PARAM_COUNTS = {"servers": 3, "services": 3, "models": 2, "gpus": 1, "licenses": 4, "containers": 2}

# 태그명으로 검색: 해당 태그가 붙은 자산 (유형별 UNION)
_TAGGED = (
    "SELECT t.name AS tag, 'server' AS kind, s.id AS id, s.name AS name, '/servers/' || s.id AS url "
    "FROM asset_tags a JOIN tags t ON t.id = a.tag_id JOIN servers s ON a.asset_type = 'server' AND s.id = a.asset_id "
    "WHERE t.name " + _L + " "
    "UNION ALL SELECT t.name, 'service', s.id, s.code || ' · ' || s.name, '/services/' || s.id "
    "FROM asset_tags a JOIN tags t ON t.id = a.tag_id JOIN services s ON a.asset_type = 'service' AND s.id = a.asset_id "
    "WHERE t.name " + _L + " "
    "UNION ALL SELECT t.name, 'model', m.id, m.name || ' ' || m.version, '/models/' || m.id "
    "FROM asset_tags a JOIN tags t ON t.id = a.tag_id JOIN models m ON a.asset_type = 'model' AND m.id = a.asset_id "
    "WHERE t.name " + _L + " "
    "UNION ALL SELECT t.name, 'license', l.id, l.name, '/licenses/' || l.id "
    "FROM asset_tags a JOIN tags t ON t.id = a.tag_id JOIN licenses l ON a.asset_type = 'license' AND l.id = a.asset_id "
    "WHERE t.name " + _L
)
_TAGGED_LIST = "SELECT * FROM (" + _TAGGED + ") ORDER BY tag, kind, name LIMIT ?"
_TAGGED_COUNT = "SELECT COUNT(*) FROM (" + _TAGGED + ")"

_ACL_SQL = (
    "SELECT a.id, a.direction, a.src_cidr, a.dst_cidr, a.port_start, a.port_end, a.protocol, a.status, a.purpose, "
    "s.id AS server_id, s.name AS server_name FROM server_acls a JOIN servers s ON s.id = a.server_id "
    "ORDER BY a.id DESC"
)


def parse_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if "%" in text:
        return None
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def acls_containing(conn: sqlite3.Connection, ip) -> list[dict]:
    """입력한 IP가 출발지/목적지 CIDR에 포함되는 ACL (Python `ipaddress`로 판정, IPv4/IPv6 혼용 안전)."""
    matches = []
    for row in conn.execute(_ACL_SQL):
        src = ipaddress.ip_network(row["src_cidr"], strict=False)
        dst = ipaddress.ip_network(row["dst_cidr"], strict=False)
        in_src = src.version == ip.version and ip in src
        in_dst = dst.version == ip.version and ip in dst
        if in_src or in_dst:
            d = dict(row)
            d["matched"] = "출발지" if in_src and not in_dst else "목적지" if in_dst and not in_src else "출발지·목적지"
            matches.append(d)
    return matches


def run_search(conn: sqlite3.Connection, term: str) -> dict:
    pattern = like_pattern(term)
    groups: dict[str, dict] = {}
    for key, (list_sql, count_sql) in _SQL.items():
        params = [pattern] * _PARAM_COUNTS[key]
        list_params = [pattern, *params] if key == "servers" else params     # 서버: 일치한 IP 표시용 서브쿼리가 하나 더 있다
        rows = conn.execute(list_sql, [*list_params, GROUP_LIMIT]).fetchall()
        total = conn.execute(count_sql, params).fetchone()[0]
        groups[key] = {"rows": rows, "total": total}
    groups["licenses"]["rows"] = with_status(groups["licenses"]["rows"])
    tag_params = [pattern] * 4
    groups["tags"] = {"rows": conn.execute(_TAGGED_LIST, [*tag_params, GROUP_LIMIT]).fetchall(),
                      "total": conn.execute(_TAGGED_COUNT, tag_params).fetchone()[0]}
    return groups


@router.get("/search")
def search(request: Request, user: CurrentUser = Depends(require_login), conn: sqlite3.Connection = Depends(get_db)):
    raw = request.query_params.get("q")
    context: dict = {"q": raw or "", "min": SEARCH_MIN, "max": SEARCH_MAX, "groups": None, "acls": None,
                     "ip": None, "error": None, "limit": GROUP_LIMIT}
    if raw is None:
        return render(request, "search.html", context)
    query, errors = validate_form(SearchQuery, dict(request.query_params))
    if query is None:
        context["error"] = f"검색어는 {SEARCH_MIN}자 이상 {SEARCH_MAX}자 이하로 입력하세요."
        return render(request, "search.html", context)
    term = query.q
    context["q"] = term
    context["groups"] = run_search(conn, term)
    ip = parse_ip(term)
    if ip is not None:       # 유효한 IP면 이 IP가 포함되는 ACL을 추가로 보여준다
        acls = acls_containing(conn, ip)
        context.update(ip=str(ip), acls=acls[:GROUP_LIMIT], acl_total=len(acls))
    context["empty"] = not any(g["total"] for g in context["groups"].values()) and not context.get("acls")
    return render(request, "search.html", context)
