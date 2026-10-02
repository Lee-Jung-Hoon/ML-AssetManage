"""로그인 / 로그아웃 / 비밀번호 변경."""
import sqlite3

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse

from .. import audit, config, security
from ..db import get_db, now_iso, transaction
from ..forms import csrf_form, read_form
from ..schemas import LoginForm, PasswordChangeForm, validate_form
from ..security import CurrentUser, client_ip, require_login, safe_redirect_path
from ..templating import render

# 로그인 화면만 인증 없이 접근 가능하다 (예외: /static, /healthz).
public_router = APIRouter()
router = APIRouter(dependencies=[Depends(require_login)])

LOGIN_FAILED_MESSAGE = "사용자명 또는 비밀번호가 올바르지 않습니다."   # 실패 사유와 무관하게 항상 동일


@public_router.get("/login")
def login_page(request: Request, next: str = "", conn: sqlite3.Connection = Depends(get_db)):
    if security.lookup_session(conn, request.cookies.get(config.SESSION_COOKIE)) is not None:
        return RedirectResponse("/", status_code=303)
    return render(request, "login.html", {"values": {}, "next": safe_redirect_path(next, "")})


@public_router.post("/login")
def login_submit(request: Request, form: dict[str, str] = Depends(read_form),
                 conn: sqlite3.Connection = Depends(get_db)):
    # 세션이 아직 없으므로 세션 바인딩 CSRF를 적용할 수 없다 (SameSite=Strict + form-action 'self'에 의존).
    ip = client_ip(request)
    data, errors = validate_form(LoginForm, form)
    attempted = form.get("username", "")
    if data is None:
        return _login_failed(request, conn, attempted, "invalid_input", "")

    user, reason = security.attempt_login(conn, data.username, data.password, ip)
    if user is None:
        return _login_failed(request, conn, data.username, reason, safe_redirect_path(data.next, ""))

    old_raw = request.cookies.get(config.SESSION_COOKIE)
    old = security.lookup_session(conn, old_raw)
    with transaction(conn):
        security.purge_expired_sessions(conn)
        if old is not None:
            security.delete_session(conn, old.session_hash)
        raw = security.create_session(conn, user["id"])       # 로그인마다 세션 ID 재발급
        audit.record(conn, request, "login_success", user_id=user["id"], username=user["username"],
                     target_type="user", target_id=user["id"])
    target = "/password" if user["must_change_password"] else safe_redirect_path(data.next, "/")
    response = RedirectResponse(target, status_code=303)
    security.set_session_cookie(response, raw)
    return response


def _login_failed(request: Request, conn: sqlite3.Connection, username: str, reason: str, next_path: str):
    audit.record(conn, request, "login_failed", username=username, summary=reason)
    return render(request, "login.html", {"values": {"username": username[:50]}, "next": next_path,
                                          "error": LOGIN_FAILED_MESSAGE}, status_code=401)


@router.post("/logout")
def logout(request: Request, form: dict[str, str] = Depends(csrf_form), user: CurrentUser = Depends(require_login),
           conn: sqlite3.Connection = Depends(get_db)):
    with transaction(conn):
        security.delete_session(conn, user.session_hash)       # 서버측 세션 삭제
        audit.record(conn, request, "logout", user=user)
    response = RedirectResponse("/login", status_code=303)
    security.clear_session_cookie(response)
    return response


@router.get("/password")
def password_page(request: Request, user: CurrentUser = Depends(require_login)):
    return render(request, "password_change.html", {"errors": {}})


@router.post("/password")
def password_change(request: Request, form: dict[str, str] = Depends(csrf_form),
                    user: CurrentUser = Depends(require_login), conn: sqlite3.Connection = Depends(get_db)):
    data, errors = validate_form(PasswordChangeForm, form)
    if data is not None:
        errors = _password_errors(conn, user, data)
    if data is None or errors:
        return render(request, "password_change.html", {"errors": errors}, status_code=422)

    new_hash = security.hash_password(data.new_password)       # 트랜잭션 밖에서 계산
    with transaction(conn):
        conn.execute("UPDATE users SET password_hash = ?, must_change_password = 0, updated_at = ? WHERE id = ?",
                     (new_hash, now_iso(), user.id))
        security.delete_user_sessions(conn, user.id)           # 모든 기존 세션 무효화 (현재 세션 포함)
        raw = security.create_session(conn, user.id)           # 현재 브라우저에는 새 세션 발급
        audit.record(conn, request, "password_change", user=user, target_type="user", target_id=user.id)
    new_user = security.lookup_session(conn, raw)
    security.add_flash(conn, new_user, "비밀번호를 변경했습니다.")
    security.reset_account_failures(user.username)
    response = RedirectResponse("/", status_code=303)
    security.set_session_cookie(response, raw)
    return response


def _password_errors(conn: sqlite3.Connection, user: CurrentUser, data: PasswordChangeForm) -> dict[str, str]:
    errors: dict[str, str] = {}
    # 탈취된 세션으로 현재 비밀번호를 대입하는 공격을 로그인과 같은 계정 잠금으로 제한한다.
    if security.is_account_locked(user.username):
        return {"current_password": "시도 횟수를 초과했습니다. 잠시 후 다시 시도하세요."}
    stored = conn.execute("SELECT password_hash FROM users WHERE id = ?", (user.id,)).fetchone()["password_hash"]
    if not security.verify_password(stored, data.current_password):
        security.record_account_failure(user.username)
        return {"current_password": "현재 비밀번호가 올바르지 않습니다."}
    problem = security.password_policy_error(data.new_password, user.username)
    if problem:
        errors["new_password"] = problem
    elif data.new_password == data.current_password:
        errors["new_password"] = "현재 비밀번호와 다른 비밀번호를 사용하세요."
    if data.new_password != data.new_password2:
        errors["new_password2"] = "비밀번호 확인이 일치하지 않습니다."
    return errors
