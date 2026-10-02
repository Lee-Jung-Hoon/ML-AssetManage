"""자산 공통 POST 라우트(확인 완료, 운영 메모 추가/삭제)를 자산 종류별로 만들어 준다."""
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse

from .. import assets, audit, security
from ..db import get_db, transaction
from ..forms import csrf_form
from ..schemas import NoteForm, validate_form
from ..security import CurrentUser, require_login, require_role


def make_common_router(asset_type: str, base: str) -> APIRouter:
    router = APIRouter(dependencies=[Depends(require_login)])

    def _require_asset(conn: sqlite3.Connection, asset_id: int) -> None:
        if not assets.exists(conn, asset_type, asset_id):
            raise HTTPException(status_code=404)

    @router.post(base + "/{asset_id}/verify")
    def verify(request: Request, asset_id: int, user: CurrentUser = Depends(require_role("editor")),
               form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
        """확인은 반드시 이 명시적 버튼으로만 한다 (일반 수정은 확인 처리로 간주하지 않는다)."""
        _require_asset(conn, asset_id)
        with transaction(conn):
            assets.mark_verified(conn, asset_type, asset_id, user.id)
            audit.record(conn, request, f"{asset_type}_verify", user=user, target_type=asset_type,
                         target_id=asset_id)
        security.add_flash(conn, user, "내용 확인 완료로 기록했습니다.")
        return RedirectResponse(f"{base}/{asset_id}", status_code=303)

    @router.post(base + "/{asset_id}/notes")
    def note_add(request: Request, asset_id: int, user: CurrentUser = Depends(require_role("editor")),
                 form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
        _require_asset(conn, asset_id)
        data, errors = validate_form(NoteForm, form)
        if data is None:
            security.add_flash(conn, user, "메모를 저장하지 못했습니다: 내용은 1~2000자, 날짜는 YYYY-MM-DD 형식이어야 합니다.", "error")
            return RedirectResponse(f"{base}/{asset_id}#notes", status_code=303)
        note_date = data.note_date.isoformat() if data.note_date else assets.today_kst()
        content = data.content.replace("\r\n", "\n").replace("\r", "\n")
        with transaction(conn):
            note_id = assets.add_note(conn, asset_type, asset_id, user.id, note_date, content)
            audit.record(conn, request, f"{asset_type}_note_add", user=user, target_type=asset_type,
                         target_id=asset_id, summary=f"note #{note_id} ({note_date})")
        security.add_flash(conn, user, "메모를 추가했습니다.")
        return RedirectResponse(f"{base}/{asset_id}#notes", status_code=303)

    @router.post(base + "/{asset_id}/notes/{note_id}/delete")
    def note_delete(request: Request, asset_id: int, note_id: int,
                    user: CurrentUser = Depends(require_role("editor")),
                    form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
        note = assets.get_note(conn, asset_type, asset_id, note_id)
        if note is None:
            raise HTTPException(status_code=404)
        if not assets.can_delete_note(note, user):          # 작성자 본인 또는 admin만
            raise HTTPException(status_code=403)
        with transaction(conn):
            conn.execute("DELETE FROM asset_notes WHERE id = ?", (note_id,))
            audit.record(conn, request, f"{asset_type}_note_delete", user=user, target_type=asset_type,
                         target_id=asset_id, summary=f"note #{note_id} ({note['note_date']})")
        security.add_flash(conn, user, "메모를 삭제했습니다.")
        return RedirectResponse(f"{base}/{asset_id}#notes", status_code=303)

    return router
