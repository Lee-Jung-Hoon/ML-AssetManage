"""자산 공통 기능: 담당자, 태그, 운영 메모, 최신성 확인. 서버/서비스/AI 모델/라이선스가 함께 쓴다.

태그와 메모는 asset_type + asset_id 방식의 공통 테이블을 쓴다 (FK CASCADE 불가 → 삭제 시 명시 삭제).
테이블 이름이 필요한 문장은 f-string 대신 asset_type별 상수 SQL 사전으로 둔다.
"""
import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone

from . import config
from .db import now_iso, parse_iso

ASSET_TYPES = ("server", "service", "model", "license")

_EXISTS_SQL = {
    "server": "SELECT 1 FROM servers WHERE id = ?",
    "service": "SELECT 1 FROM services WHERE id = ?",
    "model": "SELECT 1 FROM models WHERE id = ?",
    "license": "SELECT 1 FROM licenses WHERE id = ?",
}
_VERIFY_SQL = {
    "server": "UPDATE servers SET last_verified_at = ?, last_verified_by = ? WHERE id = ?",
    "service": "UPDATE services SET last_verified_at = ?, last_verified_by = ? WHERE id = ?",
    "model": "UPDATE models SET last_verified_at = ?, last_verified_by = ? WHERE id = ?",
    "license": "UPDATE licenses SET last_verified_at = ?, last_verified_by = ? WHERE id = ?",
}


def exists(conn: sqlite3.Connection, asset_type: str, asset_id: int) -> bool:
    return conn.execute(_EXISTS_SQL[asset_type], (asset_id,)).fetchone() is not None


# ------------------------------------------------------------------ 태그

_TAG_RE = re.compile(r"[0-9a-z_\-가-힣ㄱ-ㅎㅏ-ㅣ]+")
MAX_TAG_LENGTH = 30
MAX_TAGS_PER_ASSET = 10


def parse_tags(text: object) -> list[str]:
    """쉼표로 구분한 입력을 정규화한다 (공백 제거, 영문 소문자화, 중복 제거). 위반 시 ValueError(한국어)."""
    if isinstance(text, list):
        return text
    if not isinstance(text, str):
        raise ValueError("태그 형식이 올바르지 않습니다.")
    tags: list[str] = []
    for raw in text.split(","):
        tag = raw.strip().lower()
        if not tag:
            continue
        if len(tag) > MAX_TAG_LENGTH:
            raise ValueError(f"태그는 {MAX_TAG_LENGTH}자 이하여야 합니다.")
        if not _TAG_RE.fullmatch(tag):
            raise ValueError("태그에는 한글, 영문, 숫자, '-', '_'만 사용할 수 있습니다 (쉼표로 구분).")
        if tag not in tags:
            tags.append(tag)
    if len(tags) > MAX_TAGS_PER_ASSET:
        raise ValueError(f"태그는 자산당 최대 {MAX_TAGS_PER_ASSET}개까지 지정할 수 있습니다.")
    return tags


def get_tags(conn: sqlite3.Connection, asset_type: str, asset_id: int) -> list[str]:
    rows = conn.execute(
        "SELECT t.name FROM asset_tags a JOIN tags t ON t.id = a.tag_id "
        "WHERE a.asset_type = ? AND a.asset_id = ? ORDER BY t.name", (asset_type, asset_id))
    return [r[0] for r in rows]


def tags_by_asset(conn: sqlite3.Connection, asset_type: str, ids: list[int]) -> dict[int, list[str]]:
    """목록 화면용 일괄 조회. ID 목록은 JSON 하나로 바인딩한다 (SQL 문자열 조립 없음)."""
    result: dict[int, list[str]] = {i: [] for i in ids}
    rows = conn.execute(
        "SELECT a.asset_id, t.name FROM asset_tags a JOIN tags t ON t.id = a.tag_id "
        "WHERE a.asset_type = ? AND a.asset_id IN (SELECT value FROM json_each(?)) ORDER BY t.name",
        (asset_type, json.dumps(ids)))
    for asset_id, name in rows:
        result[asset_id].append(name)
    return result


def set_tags(conn: sqlite3.Connection, asset_type: str, asset_id: int, tags: list[str]) -> bool:
    """태그를 교체한다 (없는 태그는 자동 생성). 변경이 있었으면 True. 호출자의 트랜잭션 안에서 실행."""
    if sorted(get_tags(conn, asset_type, asset_id)) == sorted(tags):
        return False
    conn.execute("DELETE FROM asset_tags WHERE asset_type = ? AND asset_id = ?", (asset_type, asset_id))
    for tag in tags:
        conn.execute("INSERT OR IGNORE INTO tags (name) VALUES (?)", (tag,))
        conn.execute(
            "INSERT INTO asset_tags (asset_type, asset_id, tag_id) SELECT ?, ?, id FROM tags WHERE name = ?",
            (asset_type, asset_id, tag))
    return True


def delete_asset_extras(conn: sqlite3.Connection, asset_type: str, asset_id: int) -> None:
    """자산 삭제와 같은 트랜잭션에서 호출한다. 다형 참조라 FK CASCADE가 없으므로 고아 데이터를 직접 지운다."""
    conn.execute("DELETE FROM asset_tags WHERE asset_type = ? AND asset_id = ?", (asset_type, asset_id))
    conn.execute("DELETE FROM asset_notes WHERE asset_type = ? AND asset_id = ?", (asset_type, asset_id))


# ------------------------------------------------------------------ 최신성 확인

def stale_cutoff(now: datetime | None = None) -> str:
    """이 시각보다 오래된(미만) 확인은 '확인 필요'다."""
    return now_iso((now or datetime.now(timezone.utc)) - timedelta(days=config.STALE_DAYS))


def verify_state(last_verified_at: str | None, now: datetime | None = None) -> dict:
    """한 번도 확인되지 않았거나 마지막 확인 후 STALE_DAYS(90일)가 지나면 '확인 필요'."""
    if not last_verified_at:
        return {"stale": True, "date": "", "days": None}
    now = now or datetime.now(timezone.utc)
    verified = parse_iso(last_verified_at)
    return {
        "stale": last_verified_at < stale_cutoff(now),
        "date": verified.astimezone(config.DISPLAY_TZ).strftime("%Y-%m-%d"),
        "days": (now - verified).days,
    }


def mark_verified(conn: sqlite3.Connection, asset_type: str, asset_id: int, user_id: int) -> None:
    conn.execute(_VERIFY_SQL[asset_type], (now_iso(), user_id, asset_id))


# ------------------------------------------------------------------ 담당자

def _label(row: sqlite3.Row) -> str:
    return f"{row['display_name']} ({row['team']})" if row["team"] else row["display_name"]


def owner_options(conn: sqlite3.Connection, keep_id: int | None = None) -> list[tuple[str, str]]:
    """담당자 선택지: 활성 사용자만. 이미 지정된 비활성 담당자는 유지할 수 있게 표시만 한다."""
    rows = conn.execute(
        "SELECT id, display_name, team, is_active FROM users WHERE is_active = 1 OR id = ? "
        "ORDER BY is_active DESC, display_name", (keep_id,))
    return [(str(r["id"]), _label(r) + ("" if r["is_active"] else " [비활성]")) for r in rows]


def owner_error(conn: sqlite3.Connection, owner_id: int | None, current_owner_id: int | None = None) -> str | None:
    """담당자는 활성 사용자여야 한다 (기존 담당자를 그대로 두는 경우는 예외)."""
    if owner_id is None or owner_id == current_owner_id:
        return None
    row = conn.execute("SELECT is_active FROM users WHERE id = ?", (owner_id,)).fetchone()
    if row is None or not row["is_active"]:
        return "활성 사용자만 담당자로 지정할 수 있습니다."
    return None


# ------------------------------------------------------------------ 운영 메모 (타임라인)

def today_kst() -> str:
    return datetime.now(config.DISPLAY_TZ).strftime("%Y-%m-%d")


def add_note(conn: sqlite3.Connection, asset_type: str, asset_id: int, author_id: int,
             note_date: str, content: str) -> int:
    return conn.execute(
        "INSERT INTO asset_notes (asset_type, asset_id, note_date, content, author_id, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)", (asset_type, asset_id, note_date, content, author_id, now_iso())).lastrowid


def list_notes(conn: sqlite3.Connection, asset_type: str, asset_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT n.id, n.note_date, n.content, n.created_at, n.author_id, u.display_name AS author_name "
        "FROM asset_notes n JOIN users u ON u.id = n.author_id "
        "WHERE n.asset_type = ? AND n.asset_id = ? ORDER BY n.note_date DESC, n.id DESC",
        (asset_type, asset_id)).fetchall()


def get_note(conn: sqlite3.Connection, asset_type: str, asset_id: int, note_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM asset_notes WHERE id = ? AND asset_type = ? AND asset_id = ?",
        (note_id, asset_type, asset_id)).fetchone()


def can_delete_note(note: sqlite3.Row, user) -> bool:
    """삭제는 작성자 본인 또는 admin만 가능하다. 메모 수정 기능은 두지 않는다 (기록 무결성)."""
    return note["author_id"] == user.id or user.role == "admin"


# ------------------------------------------------------------------ 상세 화면 공통 데이터

def history(conn: sqlite3.Connection, asset_type: str, asset_id: int, limit: int = 50) -> list[sqlite3.Row]:
    """자산별 변경 이력 (감사 로그에서 해당 자산 기록만)."""
    return conn.execute(
        "SELECT at, username, action, summary FROM audit_logs WHERE target_type = ? AND target_id = ? "
        "ORDER BY id DESC LIMIT ?", (asset_type, asset_id, limit)).fetchall()


def common_sections(conn: sqlite3.Connection, asset_type: str, asset_id: int) -> dict:
    return {
        "tags": get_tags(conn, asset_type, asset_id),
        "notes": list_notes(conn, asset_type, asset_id),
        "history": history(conn, asset_type, asset_id),
        "today": today_kst(),
    }


# ------------------------------------------------------------------ 라이선스 상태 (저장하지 않고 만료일로 계산)

LICENSE_STATE_BADGE = {"만료됨": "red", "만료 임박": "orange", "유효": "green", "영구": "gray"}


def license_status(expires_at: str | None, no_expiry: bool, alert_days: int, today: str | None = None) -> dict:
    """상태: 영구 / 만료됨(만료일 < 오늘) / 만료 임박(오늘 ≤ 만료일 ≤ 오늘+알림 기준일) / 유효.

    날짜 비교는 Asia/Seoul 기준의 'YYYY-MM-DD' 문자열이다. days는 만료까지 남은 일수(음수면 경과)."""
    if no_expiry or not expires_at:
        return {"state": "영구", "badge": "gray", "days": None}
    today = today or today_kst()
    days = (datetime.strptime(expires_at, "%Y-%m-%d").date() - datetime.strptime(today, "%Y-%m-%d").date()).days
    state = "만료됨" if days < 0 else "만료 임박" if days <= alert_days else "유효"
    return {"state": state, "badge": LICENSE_STATE_BADGE[state], "days": days}


def data_policy_risk(sends_customer_data: str | None, training_opt_out: str | None) -> bool:
    """고객 데이터를 전송하는 AI API인데 학습 활용 거부(opt-out)가 미설정/미확인이면 위험."""
    return sends_customer_data == "예" and training_opt_out in ("미설정", "미확인")


# ------------------------------------------------------------------ AI 모델 라이선스 위험 (저장하지 않고 조회 시 계산)

# prod 환경의 운영중 서비스에 연결되어 있는지 (모델 테이블 별칭 m 기준). 목록/필터/대시보드가 같은 조각을 쓴다.
MODEL_PROD_LINKED_SQL = (
    "EXISTS (SELECT 1 FROM model_services ms JOIN services s ON s.id = ms.service_id "
    "WHERE ms.model_id = m.id AND s.environment = 'prod' AND s.status = '운영중')"
)
# 라이선스 위험: 상업 이용이 불가/미확인이면서 (모델 상태가 운영이거나 prod 운영중 서비스에 연결된 경우)
MODEL_RISK_SQL = f"(m.commercial_use IN ('불가', '미확인') AND (m.status = '운영' OR {MODEL_PROD_LINKED_SQL}))"


def license_risk(commercial_use: str, status: str, prod_linked: bool) -> str | None:
    """'risk'(빨강 라이선스 위험) / 'conditional'(주황 조건 확인) / None."""
    if commercial_use in ("불가", "미확인") and (status == "운영" or prod_linked):
        return "risk"
    if commercial_use == "조건부":
        return "conditional"
    return None
