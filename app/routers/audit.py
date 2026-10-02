"""감사 로그 조회 (admin 전용, 읽기 전용). 수정/삭제 라우트는 없다."""
import sqlite3
from datetime import date, datetime, time, timedelta, timezone

from fastapi import APIRouter, Depends, Request

from .. import config
from ..db import get_db, now_iso, paginate, select_where
from ..schemas import AuditFilter, validate_form
from ..security import CurrentUser, require_login, require_role
from ..templating import render

router = APIRouter(dependencies=[Depends(require_login)])

PER_PAGE = 50
_SELECT = "SELECT at, username, ip, action, target_type, target_id, summary FROM audit_logs"
_COUNT = "SELECT COUNT(*) FROM audit_logs"


def _kst_midnight_utc(day: date) -> str:
    """KST 기준 해당 날짜 0시를 UTC 저장 형식으로 변환한다."""
    return now_iso(datetime.combine(day, time.min, tzinfo=config.DISPLAY_TZ).astimezone(timezone.utc))


@router.get("/audit")
def audit_list(request: Request, admin: CurrentUser = Depends(require_role("admin")),
               conn: sqlite3.Connection = Depends(get_db)):
    values = dict(request.query_params)
    flt, errors = validate_form(AuditFilter, values)

    rows, total, page, pages = [], 0, 1, 1
    query: dict[str, str] = {}
    if flt is not None:
        conditions: list[tuple[str, tuple]] = []
        if flt.date_from:
            conditions.append(("at >= ?", (_kst_midnight_utc(flt.date_from),)))
        if flt.date_to:     # 종료일 당일 포함 (다음 날 0시 미만)
            conditions.append(("at < ?", (_kst_midnight_utc(flt.date_to + timedelta(days=1)),)))
        if flt.user:
            conditions.append(("username = ? COLLATE NOCASE", (flt.user,)))
        if flt.action:
            conditions.append(("action = ?", (flt.action,)))
        if flt.target_type:
            conditions.append(("target_type = ?", (flt.target_type,)))

        total = select_where(conn, _COUNT, conditions).fetchone()[0]
        page, pages, offset = paginate(flt.page, total, PER_PAGE)
        rows = select_where(conn, _SELECT, conditions, "ORDER BY id DESC LIMIT ? OFFSET ?",
                            (PER_PAGE, offset)).fetchall()
        query = {k: v for k, v in values.items() if k != "page" and v != ""}

    users = [r[0] for r in conn.execute("SELECT username FROM users ORDER BY username")]
    actions = [r[0] for r in conn.execute("SELECT DISTINCT action FROM audit_logs ORDER BY action")]
    types = [r[0] for r in conn.execute(
        "SELECT DISTINCT target_type FROM audit_logs WHERE target_type != '' ORDER BY target_type")]
    return render(request, "audit/list.html", {
        "rows": rows, "total": total, "page": page, "pages": pages, "query": query,
        "values": values, "errors": errors,
        "user_options": [(u, u) for u in users], "action_options": [(a, a) for a in actions],
        "type_options": [(t, t) for t in types],
    })
