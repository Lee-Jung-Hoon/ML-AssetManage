"""ACL 전체 목록 (모든 서버의 ACL 요청을 한 화면에서) + CSV 내보내기."""
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Request

from .. import audit, config, csvio
from ..db import get_db, like_pattern, paginate, select_where
from ..forms import csrf_form
from ..schemas import ACL_DIRECTIONS, ACL_STATUSES, AclFilter, validate_form
from ..security import CurrentUser, require_login, require_role
from ..templating import render

router = APIRouter(dependencies=[Depends(require_login)])

_SELECT = (
    "SELECT a.id, a.direction, a.src_cidr, a.dst_cidr, a.port_start, a.port_end, a.protocol, a.purpose, a.requester, "
    "a.requested_at, a.ticket_no, a.status, a.expires_at, s.id AS server_id, s.name AS server_name, s.hostname "
    "FROM server_acls a JOIN servers s ON s.id = a.server_id"
)
_COUNT = "SELECT COUNT(*) FROM server_acls a JOIN servers s ON s.id = a.server_id"
_ORDER = "ORDER BY a.id DESC"


def acl_conditions(flt: AclFilter) -> list[tuple[str, tuple]]:
    c: list[tuple[str, tuple]] = []
    if flt.q:
        p = like_pattern(flt.q)
        c.append(("(s.name LIKE ? ESCAPE '\\' OR s.hostname LIKE ? ESCAPE '\\' OR a.src_cidr LIKE ? ESCAPE '\\' OR "
                  "a.dst_cidr LIKE ? ESCAPE '\\' OR a.purpose LIKE ? ESCAPE '\\' OR a.ticket_no LIKE ? ESCAPE '\\' OR "
                  "a.requester LIKE ? ESCAPE '\\')", (p, p, p, p, p, p, p)))
    if flt.status:
        c.append(("a.status = ?", (flt.status,)))
    if flt.direction:
        c.append(("a.direction = ?", (flt.direction,)))
    return c


def port_text(row) -> str:
    return str(row["port_start"]) if row["port_start"] == row["port_end"] else f"{row['port_start']}-{row['port_end']}"


@router.get("/acls")
def acl_list(request: Request, user: CurrentUser = Depends(require_login), conn: sqlite3.Connection = Depends(get_db)):
    values = dict(request.query_params)
    flt, errors = validate_form(AclFilter, values)
    rows, total, page, pages, query = [], 0, 1, 1, {}
    if flt is not None:
        conditions = acl_conditions(flt)
        total = select_where(conn, _COUNT, conditions).fetchone()[0]
        page, pages, offset = paginate(flt.page, total, config.PAGE_SIZE)
        rows = select_where(conn, _SELECT, conditions, _ORDER + " LIMIT ? OFFSET ?", (config.PAGE_SIZE, offset)).fetchall()
        query = {k: v for k, v in values.items() if k != "page" and v != ""}
    return render(request, "acls/list.html", {
        "rows": rows, "total": total, "page": page, "pages": pages, "query": query, "values": values, "errors": errors,
        "status_options": [(v, v) for v in ACL_STATUSES], "direction_options": [(v, v) for v in ACL_DIRECTIONS],
        "port_text": port_text})


@router.post("/acls/export")
def export_acls(request: Request, user: CurrentUser = Depends(require_role("editor")),
                form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    flt, errors = validate_form(AclFilter, dict(request.query_params))
    if flt is None:
        raise HTTPException(status_code=400)
    rows = select_where(conn, _SELECT, acl_conditions(flt), _ORDER).fetchall()
    data = [[r["server_name"], r["hostname"], r["direction"], r["src_cidr"], r["dst_cidr"], port_text(r), r["protocol"],
             r["purpose"], r["requester"], r["requested_at"], r["ticket_no"], r["status"], r["expires_at"] or ""]
            for r in rows]
    filters = "; ".join(f"{k}={v}" for k, v in request.query_params.items() if k != "page" and v != "")
    audit.record(conn, request, "csv_export", user=user, target_type="acl",
                 summary=f"rows={len(data)}" + (f"; filters: {filters}" if filters else ""))
    from .exports import ACL_HEADERS
    return csvio.csv_download("acls", ACL_HEADERS, data)
