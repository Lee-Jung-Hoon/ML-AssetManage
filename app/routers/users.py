"""사용자 관리 (admin 전용). 하드 삭제 없이 비활성화한다."""
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse

from .. import audit, security
from ..db import get_db, now_iso, transaction
from ..forms import csrf_form
from ..schemas import UserCreateForm, UserEditForm, validate_form
from ..security import CurrentUser, require_login, require_role
from ..templating import render

router = APIRouter(dependencies=[Depends(require_login)])

ADMIN = Depends(require_role("admin"))   # ADMIN_ENABLED=false면 403


def _get_user(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404)
    return row


def _credentials(request: Request, heading: str, target: dict, temp_password: str):
    # 임시 비밀번호는 이 응답에서 한 번만 보여준다 (DB/flash/로그에 평문을 남기지 않는다).
    return render(request, "users/credentials.html",
                  {"heading": heading, "target": target, "temp_password": temp_password})


@router.get("/users")
def user_list(request: Request, admin: CurrentUser = ADMIN, conn: sqlite3.Connection = Depends(get_db)):
    users = conn.execute(
        "SELECT id, username, display_name, team, role, is_active, must_change_password, created_at "
        "FROM users ORDER BY is_active DESC, username"
    ).fetchall()
    return render(request, "users/list.html", {"users": users})


@router.get("/users/new")
def user_new_form(request: Request, admin: CurrentUser = ADMIN):
    return render(request, "users/form.html", {"target": None, "values": {"role": "viewer"}, "errors": {}})


@router.post("/users/new")
def user_create(request: Request, admin: CurrentUser = ADMIN, form: dict[str, str] = Depends(csrf_form),
                conn: sqlite3.Connection = Depends(get_db)):
    data, errors = validate_form(UserCreateForm, form)
    if data is None:
        return render(request, "users/form.html", {"target": None, "values": form, "errors": errors}, 422)

    temp_password = security.random_password()
    password_hash = security.hash_password(temp_password)        # 트랜잭션 밖에서 계산
    now = now_iso()
    uid = None
    with transaction(conn):
        if conn.execute("SELECT 1 FROM users WHERE username = ?", (data.username,)).fetchone() is None:
            uid = conn.execute(
                "INSERT INTO users (username, display_name, team, role, is_active, password_hash, "
                "must_change_password, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, 1, ?, ?)",
                (data.username, data.display_name, data.team, data.role, password_hash, now, now),
            ).lastrowid
            audit.record(conn, request, "user_create", user=admin, target_type="user", target_id=uid,
                         summary=f"username: {data.username}; role: {data.role}; team: {data.team}")
    if uid is None:
        return render(request, "users/form.html", {
            "target": None, "values": form, "errors": {"username": "이미 사용 중인 사용자명입니다."}}, 422)
    return _credentials(request, "사용자를 생성했습니다", {"username": data.username, "display_name": data.display_name},
                        temp_password)


def _edit_values(target: sqlite3.Row) -> dict[str, str]:
    values = {"display_name": target["display_name"], "team": target["team"], "role": target["role"]}
    if target["is_active"]:
        values["is_active"] = "on"
    return values


@router.get("/users/{user_id}/edit")
def user_edit_form(request: Request, user_id: int, admin: CurrentUser = ADMIN,
                   conn: sqlite3.Connection = Depends(get_db)):
    target = _get_user(conn, user_id)
    return render(request, "users/form.html", {"target": target, "values": _edit_values(target), "errors": {}})


@router.post("/users/{user_id}/edit")
def user_edit(request: Request, user_id: int, admin: CurrentUser = ADMIN, form: dict[str, str] = Depends(csrf_form),
              conn: sqlite3.Connection = Depends(get_db)):
    target = _get_user(conn, user_id)
    data, errors = validate_form(UserEditForm, form)
    if data is not None and target["id"] == admin.id and (data.role != target["role"] or not data.is_active):
        # 본인 비활성화/강등 금지: 마지막 활성 admin이 사라지는 사고를 원천 차단한다.
        errors = {"__all__": "본인 계정은 비활성화하거나 역할을 바꿀 수 없습니다."}
        data = None
    if data is None:
        return render(request, "users/form.html", {"target": target, "values": form, "errors": errors}, 422)

    old = {"display_name": target["display_name"], "team": target["team"], "role": target["role"],
           "is_active": int(target["is_active"])}
    new = {"display_name": data.display_name, "team": data.team, "role": data.role, "is_active": int(data.is_active)}
    revoke = old["role"] != new["role"] or (old["is_active"] and not new["is_active"])
    changed = old != new
    if changed:
        with transaction(conn):
            conn.execute("UPDATE users SET display_name = ?, team = ?, role = ?, is_active = ?, updated_at = ? "
                         "WHERE id = ?", (*new.values(), now_iso(), user_id))
            if revoke:      # 역할 변경/비활성화 시 기존 세션 모두 무효화
                security.delete_user_sessions(conn, user_id)
            audit.record(conn, request, "user_update", user=admin, target_type="user", target_id=user_id,
                         summary=f"username: {target['username']}; " + audit.diff_summary(old, new))
    security.add_flash(conn, admin, "저장했습니다." if changed else "변경된 내용이 없습니다.")
    return RedirectResponse("/users", status_code=303)


@router.post("/users/{user_id}/reset-password")
def user_reset_password(request: Request, user_id: int, admin: CurrentUser = ADMIN,
                        form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    target = _get_user(conn, user_id)
    if target["id"] == admin.id:
        security.add_flash(conn, admin, "본인 비밀번호는 비밀번호 변경 화면에서 바꾸세요.", "error")
        return RedirectResponse(f"/users/{user_id}/edit", status_code=303)

    temp_password = security.random_password()
    password_hash = security.hash_password(temp_password)
    with transaction(conn):
        conn.execute("UPDATE users SET password_hash = ?, must_change_password = 1, updated_at = ? WHERE id = ?",
                     (password_hash, now_iso(), user_id))
        security.delete_user_sessions(conn, user_id)
        audit.record(conn, request, "user_password_reset", user=admin, target_type="user", target_id=user_id,
                     summary=f"username: {target['username']}")
    return _credentials(request, "비밀번호를 초기화했습니다",
                        {"username": target["username"], "display_name": target["display_name"]}, temp_password)
