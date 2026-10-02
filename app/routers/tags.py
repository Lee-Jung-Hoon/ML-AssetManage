"""태그 관리 (editor 이상): 태그별 사용 수, 이름 변경, 사용되지 않는 태그 삭제."""
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse

from .. import audit, security
from ..db import get_db, transaction
from ..forms import csrf_form
from ..schemas import TagRenameForm, validate_form
from ..security import CurrentUser, require_login, require_role
from ..templating import render

router = APIRouter(dependencies=[Depends(require_login)])

_TAG_USAGE = (
    "SELECT t.id, t.name, COUNT(a.tag_id) AS total, "
    "COALESCE(SUM(a.asset_type = 'server'), 0) AS servers, COALESCE(SUM(a.asset_type = 'service'), 0) AS services, "
    "COALESCE(SUM(a.asset_type = 'model'), 0) AS models, COALESCE(SUM(a.asset_type = 'license'), 0) AS licenses "
    "FROM tags t LEFT JOIN asset_tags a ON a.tag_id = t.id GROUP BY t.id ORDER BY t.name"
)


@router.get("/tags")
def tag_list(request: Request, user: CurrentUser = Depends(require_role("editor")),
             conn: sqlite3.Connection = Depends(get_db)):
    return render(request, "tags.html", {"tags": conn.execute(_TAG_USAGE).fetchall()})


def _get_tag(conn: sqlite3.Connection, tag_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT id, name FROM tags WHERE id = ?", (tag_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404)
    return row


@router.post("/tags/{tag_id}/rename")
def tag_rename(request: Request, tag_id: int, user: CurrentUser = Depends(require_role("editor")),
               form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    tag = _get_tag(conn, tag_id)
    data, errors = validate_form(TagRenameForm, form)
    if data is None:
        security.add_flash(conn, user, "태그 이름을 바꾸지 못했습니다: " + " ".join(errors.values()), "error")
        return RedirectResponse("/tags", status_code=303)
    if data.name == tag["name"]:
        security.add_flash(conn, user, "변경된 내용이 없습니다.")
        return RedirectResponse("/tags", status_code=303)
    with transaction(conn):
        if conn.execute("SELECT 1 FROM tags WHERE name = ? AND id != ?", (data.name, tag_id)).fetchone():
            clash = True
        else:
            clash = False
            conn.execute("UPDATE tags SET name = ? WHERE id = ?", (data.name, tag_id))
            audit.record(conn, request, "tag_rename", user=user, target_type="tag", target_id=tag_id,
                         summary=f"name: {tag['name']} → {data.name}")
    if clash:
        security.add_flash(conn, user, f"이미 존재하는 태그입니다: {data.name}", "error")
    else:
        security.add_flash(conn, user, "태그 이름을 변경했습니다.")
    return RedirectResponse("/tags", status_code=303)


@router.post("/tags/{tag_id}/delete")
def tag_delete(request: Request, tag_id: int, user: CurrentUser = Depends(require_role("editor")),
               form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    tag = _get_tag(conn, tag_id)
    with transaction(conn):
        in_use = conn.execute("SELECT COUNT(*) FROM asset_tags WHERE tag_id = ?", (tag_id,)).fetchone()[0]
        if not in_use:      # 사용되지 않는 태그만 삭제한다 (확인과 삭제를 한 트랜잭션에서)
            conn.execute("DELETE FROM tags WHERE id = ?", (tag_id,))
            audit.record(conn, request, "tag_delete", user=user, target_type="tag", target_id=tag_id,
                         summary=f"name: {tag['name']}")
    if in_use:
        security.add_flash(conn, user, f"사용 중인 태그는 삭제할 수 없습니다 ({in_use}건 사용 중).", "error")
    else:
        security.add_flash(conn, user, "태그를 삭제했습니다.")
    return RedirectResponse("/tags", status_code=303)
