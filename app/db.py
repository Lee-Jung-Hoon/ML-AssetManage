"""SQLite 연결, 마이그레이션 실행기, 트랜잭션 헬퍼."""
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from . import config

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
_MIGRATION_NAME = re.compile(r"^(\d{3})_[a-z0-9_]+\.sql$")


def now_iso(now: datetime | None = None) -> str:
    """UTC ISO8601 문자열 (저장 형식). 문자열 비교로 시간 순서 비교가 가능하다."""
    return (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def connect() -> sqlite3.Connection:
    # isolation_level=None: 트랜잭션은 transaction()으로 명시 제어한다.
    # check_same_thread=False: FastAPI가 yield 의존성의 시작/종료를 서로 다른 스레드에서 실행할 수 있다.
    conn = sqlite3.connect(config.db_path(), isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def get_db() -> Iterator[sqlite3.Connection]:
    """요청 단위 연결 (Depends + yield)."""
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """쓰기 트랜잭션. 예외 시 롤백한다."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def run_migrations(conn: sqlite3.Connection) -> list[int]:
    """아직 적용되지 않은 migrations/NNN_*.sql을 번호 순으로 1회씩 적용한다. 적용한 버전 목록을 반환."""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations "
        "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    applied = {r["version"] for r in conn.execute("SELECT version FROM schema_migrations")}

    files = []
    for path in MIGRATIONS_DIR.iterdir():
        m = _MIGRATION_NAME.match(path.name)
        if m:
            files.append((int(m.group(1)), path))
    files.sort()
    versions = [v for v, _ in files]
    if len(versions) != len(set(versions)):
        raise RuntimeError("중복된 마이그레이션 번호가 있습니다.")

    done: list[int] = []
    for version, path in files:
        if version in applied:
            continue
        sql = path.read_text(encoding="utf-8")
        # executescript는 진행 중인 트랜잭션을 먼저 커밋하므로, BEGIN을 스크립트 앞에 붙여
        # 스키마 변경과 버전 기록이 한 트랜잭션에서 원자적으로 처리되게 한다 (SQLite DDL은 트랜잭션 지원).
        try:
            conn.executescript("BEGIN IMMEDIATE;\n" + sql)
            conn.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                (version, now_iso()),
            )
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        done.append(version)
    return done


def paginate(page: int, total: int, per_page: int) -> tuple[int, int, int]:
    """(보정된 page, 전체 pages, offset)."""
    pages = max(1, -(-total // per_page))
    page = min(max(page, 1), pages)
    return page, pages, (page - 1) * per_page


def select_where(conn: sqlite3.Connection, base_sql: str, conditions: list[tuple[str, tuple]],
                 tail: str = "", tail_params: tuple = ()) -> sqlite3.Cursor:
    """동적 필터 쿼리를 조립하는 유일한 지점. base_sql/tail/조건 조각은 모두 코드에 고정된 상수여야 하며
    (`?` 바인딩만 포함), 사용자 입력은 conditions의 값으로만 전달한다."""
    if conditions:
        base_sql += " WHERE " + " AND ".join(fragment for fragment, _ in conditions)
    values = [v for _, vals in conditions for v in vals]
    sql = f"{base_sql} {tail}"
    return conn.execute(sql, [*values, *tail_params])
