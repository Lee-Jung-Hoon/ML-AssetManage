"""보안 기반: 비밀번호 해시, 서버측 세션, CSRF, 권한 의존성, 로그인 제한, 키 관리/암호화."""
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, HTTPException, Request, Response

from . import config
from .db import get_db, now_iso, parse_iso, transaction

# ------------------------------------------------------------------ 비밀번호

_hash_slots = threading.Semaphore(config.SCRYPT_CONCURRENCY)
_dummy_hash: str | None = None
_dummy_lock = threading.Lock()
_PASSWORD_ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_@#%+="


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    # 메모리 고갈 DoS 방지: 동시 연산 수 제한. maxmem은 파라미터에서 계산해 명시한다.
    maxmem = 128 * r * (n + p + 2) + 1024 * 1024
    with _hash_slots:
        return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, maxmem=maxmem, dklen=32)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def hash_password(password: str) -> str:
    """`scrypt$N$r$p$salt$hash` 형식. 파라미터를 포함하므로 향후 상향이 가능하다."""
    n, r, p = config.SCRYPT_N, config.SCRYPT_R, config.SCRYPT_P
    salt = secrets.token_bytes(16)
    digest = _scrypt(password, salt, n, r, p)
    return f"scrypt${n}${r}${p}${_b64(salt)}${_b64(digest)}"


def verify_password(stored: str, password: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, hash_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        n, r, p = int(n), int(r), int(p)
        if not (2 <= n <= 2**20 and n & (n - 1) == 0 and 1 <= r <= 32 and 1 <= p <= 16):
            return False
        salt = base64.b64decode(salt_b64, validate=True)
        expected = base64.b64decode(hash_b64, validate=True)
    except (ValueError, TypeError):
        return False
    actual = _scrypt(password, salt, n, r, p)
    return hmac.compare_digest(actual, expected)


def _get_dummy_hash() -> str:
    global _dummy_hash
    with _dummy_lock:
        if _dummy_hash is None:
            _dummy_hash = hash_password(secrets.token_urlsafe(16))
        return _dummy_hash


def password_policy_error(password: str, username: str) -> str | None:
    """정책 위반 사유(한국어)를 반환한다. 통과하면 None."""
    if len(password) < config.PASSWORD_MIN_LENGTH:
        return f"비밀번호는 {config.PASSWORD_MIN_LENGTH}자 이상이어야 합니다."
    if len(password) > config.PASSWORD_MAX_LENGTH:
        return f"비밀번호는 {config.PASSWORD_MAX_LENGTH}자 이하여야 합니다."
    if password.casefold() == username.casefold():
        return "비밀번호는 사용자명과 같을 수 없습니다."
    return None


def random_password(length: int = 20) -> str:
    return "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(max(length, 20)))


# ------------------------------------------------------------------ 로그인 제한

class LoginLimiter:
    """계정/IP 기준 실패 횟수 제한 (워커 1개이므로 인메모리 + 락으로 충분)."""

    def __init__(self, clock=time.monotonic, max_failures: int | None = None,
                 lock_seconds: int | None = None, max_entries: int = 10_000):
        self._clock = clock
        self._max_failures = max_failures or config.LOGIN_MAX_FAILURES
        self._lock_seconds = lock_seconds or config.LOGIN_LOCK_SECONDS
        self._max_entries = max_entries
        self._lock = threading.Lock()
        self._state: dict[str, list[float]] = {}   # key -> [실패 횟수, 잠금 해제 시각, 마지막 실패 시각]

    def is_locked(self, key: str) -> bool:
        with self._lock:
            entry = self._state.get(key)
            return bool(entry and entry[1] > self._clock())

    def record_failure(self, key: str) -> None:
        with self._lock:
            now = self._clock()
            entry = self._state.get(key)
            if entry is not None:
                lock_expired = entry[1] != 0 and entry[1] <= now
                stale = entry[1] == 0 and now - entry[2] > self._lock_seconds
                if lock_expired or stale:   # 잠금이 풀렸거나 오래된 실패는 새로 센다
                    entry = None
            if entry is None:
                entry = [0, 0.0, now]
            entry[0] += 1
            entry[2] = now
            if entry[0] >= self._max_failures:
                entry[1] = now + self._lock_seconds
            self._state[key] = entry
            if len(self._state) > self._max_entries:
                self._prune(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._state.pop(key, None)

    def _prune(self, now: float) -> None:
        # 공격자가 임의 사용자명으로 메모리를 채우는 것을 막는다.
        for k in [k for k, e in self._state.items() if e[1] <= now and now - e[2] > self._lock_seconds]:
            del self._state[k]
        if len(self._state) > self._max_entries:
            oldest = sorted(self._state, key=lambda k: self._state[k][2])
            for k in oldest[: len(self._state) - self._max_entries]:
                del self._state[k]


login_limiter = LoginLimiter()


def _account_key(username: str) -> str:
    return "u:" + username.strip().casefold()[:64]


def is_account_locked(username: str) -> bool:
    return login_limiter.is_locked(_account_key(username))


def record_account_failure(username: str) -> None:
    login_limiter.record_failure(_account_key(username))


def reset_account_failures(username: str) -> None:
    login_limiter.reset(_account_key(username))


def admin_enabled() -> bool:
    """ADMIN_ENABLED 환경변수. 미설정이면 true, 설정 시 명시적 true 값만 켠다 (오타는 안전한 쪽=꺼짐)."""
    value = os.environ.get("ADMIN_ENABLED")
    if value is None:
        return True
    return value.strip().lower() in ("true", "1", "yes", "on")


def attempt_login(conn: sqlite3.Connection, username: str, password: str, ip: str):
    """(user_row | None, reason) 반환. reason: 'ok' | 'locked' | 'invalid'.

    호출자는 reason과 무관하게 실패 시 동일한 메시지를 보여줘야 한다.
    존재하지 않는 계정도 더미 해시와 비교해 응답 시간 차이를 줄인다.
    """
    acct_key, ip_key = _account_key(username), "ip:" + ip
    if login_limiter.is_locked(acct_key) or login_limiter.is_locked(ip_key):
        return None, "locked"

    row = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username.strip(),)
    ).fetchone()
    stored = row["password_hash"] if row else _get_dummy_hash()
    password_ok = verify_password(stored, password)
    allowed = (
        row is not None and password_ok and bool(row["is_active"])
        and (row["role"] != "admin" or admin_enabled())
    )
    if not allowed:
        login_limiter.record_failure(acct_key)
        login_limiter.record_failure(ip_key)
        return None, "invalid"
    login_limiter.reset(acct_key)
    return row, "ok"


# ------------------------------------------------------------------ 세션

@dataclass(frozen=True)
class CurrentUser:
    id: int
    username: str
    display_name: str
    team: str
    role: str
    must_change_password: bool
    csrf_token: str
    session_hash: str


def _hash_session_id(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def create_session(conn: sqlite3.Connection, user_id: int, now: datetime | None = None) -> str:
    """새 세션을 만들고 원문 세션 ID를 반환한다 (DB에는 SHA-256 해시만 저장). 로그인마다 호출해 재발급한다."""
    now = now or datetime.now(timezone.utc)
    raw = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO sessions (id_hash, user_id, csrf_token, created_at, last_seen_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (_hash_session_id(raw), user_id, secrets.token_urlsafe(32), now_iso(now), now_iso(now),
         now_iso(now + timedelta(seconds=config.SESSION_ABSOLUTE_SECONDS))),
    )
    return raw


def lookup_session(conn: sqlite3.Connection, raw: str | None, now: datetime | None = None) -> CurrentUser | None:
    if not raw or len(raw) > 128:
        return None
    now = now or datetime.now(timezone.utc)
    sid = _hash_session_id(raw)
    row = conn.execute(
        "SELECT s.csrf_token, s.last_seen_at, s.expires_at, u.id, u.username, u.display_name, u.team, "
        "u.role, u.is_active, u.must_change_password "
        "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = ?", (sid,)
    ).fetchone()
    if row is None:
        return None
    idle_deadline = parse_iso(row["last_seen_at"]) + timedelta(seconds=config.SESSION_IDLE_SECONDS)
    if not row["is_active"] or now_iso(now) >= row["expires_at"] or now >= idle_deadline:
        conn.execute("DELETE FROM sessions WHERE id_hash = ?", (sid,))
        return None
    if (now - parse_iso(row["last_seen_at"])).total_seconds() >= config.SESSION_TOUCH_SECONDS:
        conn.execute("UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?", (now_iso(now), sid))
    return CurrentUser(
        id=row["id"], username=row["username"], display_name=row["display_name"], team=row["team"],
        role=row["role"], must_change_password=bool(row["must_change_password"]),
        csrf_token=row["csrf_token"], session_hash=sid,
    )


def delete_session(conn: sqlite3.Connection, session_hash: str) -> None:
    conn.execute("DELETE FROM sessions WHERE id_hash = ?", (session_hash,))


def delete_user_sessions(conn: sqlite3.Connection, user_id: int, keep_session_hash: str | None = None) -> None:
    """비밀번호 변경/비활성화/역할 변경 시 호출. keep_session_hash만 남기고 모두 파기한다."""
    conn.execute(
        "DELETE FROM sessions WHERE user_id = ? AND id_hash IS NOT ?", (user_id, keep_session_hash)
    )


def set_session_cookie(response: Response, raw: str) -> None:
    response.set_cookie(
        config.SESSION_COOKIE, raw, max_age=config.SESSION_ABSOLUTE_SECONDS,
        path="/", secure=True, httponly=True, samesite="strict",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(config.SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="strict")


# ------------------------------------------------------------------ flash (서버측 세션 기반)

def add_flash(conn: sqlite3.Connection, user: CurrentUser, message: str, level: str = "success") -> None:
    row = conn.execute("SELECT flash FROM sessions WHERE id_hash = ?", (user.session_hash,)).fetchone()
    items = json.loads(row["flash"]) if row and row["flash"] else []
    items.append({"level": level if level in ("success", "error", "warning") else "success",
                  "message": message[:500]})
    conn.execute("UPDATE sessions SET flash = ? WHERE id_hash = ?",
                 (json.dumps(items[-5:], ensure_ascii=False), user.session_hash))


def pop_flash(conn: sqlite3.Connection, user: CurrentUser) -> list[dict]:
    row = conn.execute("SELECT flash FROM sessions WHERE id_hash = ?", (user.session_hash,)).fetchone()
    if not row or not row["flash"]:
        return []
    conn.execute("UPDATE sessions SET flash = NULL WHERE id_hash = ?", (user.session_hash,))
    try:
        return json.loads(row["flash"])
    except ValueError:
        return []


# ------------------------------------------------------------------ 인증/권한 의존성 ("기본 거부")

class LoginRequired(Exception):
    """로그인 페이지로 리다이렉트."""


class PasswordChangeRequired(Exception):
    """비밀번호 변경 화면으로 리다이렉트."""


PASSWORD_CHANGE_PATHS = frozenset({"/password", "/logout"})
ROLE_RANK = {"viewer": 1, "editor": 2, "admin": 3}


def require_login(request: Request, conn: sqlite3.Connection = Depends(get_db)) -> CurrentUser:
    """모든 라우터에 router-level dependency로 건다. 예외: 로그인 페이지, /static, /healthz."""
    user = lookup_session(conn, request.cookies.get(config.SESSION_COOKIE))
    if user is not None and user.role == "admin" and not admin_enabled():
        delete_session(conn, user.session_hash)     # ADMIN_ENABLED=false: 기존 admin 세션도 즉시 무효화
        user = None
    if user is None:
        raise LoginRequired()
    if user.must_change_password and request.url.path not in PASSWORD_CHANGE_PATHS:
        raise PasswordChangeRequired()
    request.state.user = user
    # flash는 GET 렌더링에서만 소비한다 (POST 후 303 → GET에서 표시)
    request.state.flashes = pop_flash(conn, user) if request.method == "GET" else []
    return user


def require_role(minimum: str):
    """엔드포인트마다 명시: `Depends(require_role("editor"))`. admin 전용 라우트는 ADMIN_ENABLED=false면 403."""
    if minimum not in ROLE_RANK:
        raise ValueError(minimum)

    def dependency(user: CurrentUser = Depends(require_login)) -> CurrentUser:
        if minimum == "admin" and not admin_enabled():
            raise HTTPException(status_code=403)
        if ROLE_RANK[user.role] < ROLE_RANK[minimum]:
            raise HTTPException(status_code=403)
        return user

    return dependency


def check_csrf(user: CurrentUser, token: str) -> None:
    """세션에 바인딩된 CSRF 토큰 검증 (forms.py의 의존성에서 호출)."""
    if not hmac.compare_digest(token.encode("utf-8"), user.csrf_token.encode("utf-8")):
        raise HTTPException(status_code=403)


def safe_redirect_path(target: str | None, default: str = "/") -> str:
    """내부 경로만 허용한다 (`/`로 시작, `//` 금지). 오픈 리다이렉트 방지."""
    if not target or len(target) > 2000:
        return default
    if not target.startswith("/") or target.startswith("//") or "\\" in target:
        return default
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in target):
        return default
    parts = urlsplit(target)
    if parts.scheme or parts.netloc:
        return default
    return target


def client_ip(request: Request) -> str:
    # Uvicorn --proxy-headers가 X-Forwarded-For를 request.client에 반영한다 (신뢰 근거는 README 참고).
    return request.client.host if request.client else ""


# ------------------------------------------------------------------ 암호화 키 / AES-256-GCM

KEY_FILENAME = "secret.key"


def load_or_create_key() -> bytes:
    """첫 기동 시 32바이트 키를 생성(권한 600)하고, 이후에는 읽기만 한다. 손상되었으면 기동 실패 (덮어쓰기 금지)."""
    path = config.DATA_DIR / KEY_FILENAME
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        key = path.read_bytes()
        if len(key) != 32:
            raise RuntimeError(f"{path} 이(가) 손상되었습니다 (32바이트가 아님). 덮어쓰지 않고 기동을 중단합니다.")
        return key
    key = secrets.token_bytes(32)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
        f.flush()
        os.fsync(f.fileno())
    return key


def _aad(record_id: int, field: str) -> bytes:
    return f"{field}:{record_id}".encode("utf-8")


def encrypt_field(key: bytes, record_id: int, field: str, plaintext: str) -> bytes:
    """nonce(12바이트) || ciphertext. 레코드 ID(+필드명)를 AAD로 묶어 다른 레코드/필드로의 복사를 막는다."""
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), _aad(record_id, field))


def decrypt_field(key: bytes, record_id: int, field: str, blob: bytes) -> str:
    """AAD/키/데이터가 다르면 cryptography.exceptions.InvalidTag 발생."""
    return AESGCM(key).decrypt(blob[:12], blob[12:], _aad(record_id, field)).decode("utf-8")


def mask_secret(plaintext: str) -> str:
    return "****" + plaintext[-4:] if len(plaintext) > 8 else "********"


# ------------------------------------------------------------------ 관리자 부트스트랩 / 복구

log = logging.getLogger("app")
ADMIN_USERNAME = "admin"


def _insert_admin(conn: sqlite3.Connection, password_hash: str) -> int:
    now = now_iso()
    return conn.execute(
        "INSERT INTO users (username, display_name, team, role, is_active, password_hash, "
        "must_change_password, created_at, updated_at) VALUES (?, '관리자', '', 'admin', 1, ?, 1, ?, ?)",
        (ADMIN_USERNAME, password_hash, now, now),
    ).lastrowid


def bootstrap_admin(conn: sqlite3.Connection) -> str | None:
    """첫 기동 시 admin 계정이 없으면 랜덤 비밀번호로 만든다. 생성했으면 비밀번호를, 아니면 None을 반환한다."""
    from .audit import record      # 순환 import 방지 (audit이 security를 import)
    if conn.execute("SELECT 1 FROM users WHERE role = 'admin' OR username = ? LIMIT 1", (ADMIN_USERNAME,)).fetchone():
        if not conn.execute("SELECT 1 FROM users WHERE role = 'admin'").fetchone():
            log.warning("admin 역할 계정이 없습니다. `python -m app reset-admin`으로 복구하세요.")
        return None
    password = random_password()
    new_hash = hash_password(password)       # 트랜잭션 밖에서 계산
    with transaction(conn):
        uid = _insert_admin(conn, new_hash)
        record(conn, None, "bootstrap_admin", username="(system)", target_type="user", target_id=uid,
               summary="초기 admin 계정 생성")
    return password


def reset_admin(conn: sqlite3.Connection) -> str:
    """admin 비밀번호를 새 랜덤값으로 재설정(복구)하고 새 비밀번호를 반환한다.

    계정이 없으면 만들고, 비활성/강등 상태면 admin 역할·활성으로 되돌린다. 모든 세션을 파기하고 감사 로그를 남긴다.
    ADMIN_ENABLED와 무관하게 동작한다.
    """
    from .audit import record
    password = random_password()
    new_hash = hash_password(password)
    with transaction(conn):
        row = conn.execute("SELECT id, role, is_active FROM users WHERE username = ?", (ADMIN_USERNAME,)).fetchone()
        if row is None:
            uid, note = _insert_admin(conn, new_hash), "admin 계정 새로 생성"
        else:
            uid = row["id"]
            note = "비밀번호 재설정"
            if row["role"] != "admin" or not row["is_active"]:
                note += " (admin 역할·활성 상태로 복구)"
            conn.execute(
                "UPDATE users SET password_hash = ?, role = 'admin', is_active = 1, must_change_password = 1, "
                "updated_at = ? WHERE id = ?", (new_hash, now_iso(), uid))
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (uid,))
        record(conn, None, "reset_admin", username="(cli)", target_type="user", target_id=uid, summary=note)
    return password
