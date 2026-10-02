"""감사 로그 기록. 수정/삭제 기능은 없다 (DB 트리거로도 차단)."""
import sqlite3
from collections.abc import Mapping

from fastapi import Request

from .db import now_iso
from .security import CurrentUser, client_ip

# 변경 요약에서 값을 절대 남기지 않는 필드
SENSITIVE_FIELDS = frozenset({
    "password", "password_hash", "new_password", "current_password", "csrf_token",
    "license_key", "license_key_enc", "account_info", "account_info_enc",
})
_MAX_VALUE = 80


def _short(value: object) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\n", " ")
    return text if len(text) <= _MAX_VALUE else text[:_MAX_VALUE] + "…"


def diff_summary(old: Mapping[str, object], new: Mapping[str, object]) -> str:
    """변경된 필드명과 전/후 값. 민감 필드는 변경 사실만 적고 값은 제외한다."""
    parts = []
    for key in new:
        if old.get(key) == new[key]:
            continue
        if key in SENSITIVE_FIELDS:
            parts.append(f"{key}: 변경됨(값 비공개)")
        else:
            parts.append(f"{key}: {_short(old.get(key))} → {_short(new[key])}")
    return "; ".join(parts)


def record(conn: sqlite3.Connection, request: Request | None, action: str, *,
           user: CurrentUser | None = None, username: str = "",
           target_type: str = "", target_id: int | None = None, summary: str = "") -> None:
    """호출자의 트랜잭션 안에서 실행된다. 로그인 실패처럼 사용자가 없으면 시도한 username(64자 제한)을 남긴다."""
    conn.execute(
        "INSERT INTO audit_logs (at, user_id, username, ip, action, target_type, target_id, summary) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (now_iso(), user.id if user else None, (user.username if user else username)[:64],
         client_ip(request) if request else "", action, target_type, target_id, summary[:4000]),
    )
