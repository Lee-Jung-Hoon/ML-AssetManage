"""백업 (admin 전용). `VACUUM INTO`로 /data/backups/app-YYYYMMDD-HHMMSS.db를 만들고 최근 14개만 보관한다.

웹에서 백업 파일을 다운로드하는 기능은 만들지 않는다 (유출 경로 차단). 호스트에서 볼륨으로 가져가야 한다.
파일 이름은 서버가 만들며 사용자 입력은 경로에 전혀 들어가지 않는다.
"""
import logging
import re
import sqlite3
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse

from .. import audit, config, security
from ..db import get_db
from ..forms import csrf_form
from ..security import CurrentUser, require_login, require_role
from ..templating import render

log = logging.getLogger("app")
router = APIRouter(dependencies=[Depends(require_login)])

KEEP = 14
BACKUP_NAME = re.compile(r"app-\d{8}-\d{6}\.db")


def backup_dir() -> Path:
    return config.DATA_DIR / "backups"


def _stamp() -> str:
    return datetime.now(config.DISPLAY_TZ).strftime("%Y%m%d-%H%M%S")


def list_backups() -> list[dict]:
    """최신순 목록 (이름 형식이 맞는 파일만)."""
    directory = backup_dir()
    if not directory.is_dir():
        return []
    items = []
    for path in directory.iterdir():
        if BACKUP_NAME.fullmatch(path.name) and path.is_file():
            stat = path.stat()
            items.append({"name": path.name, "size": stat.st_size,
                          "modified": datetime.fromtimestamp(stat.st_mtime, config.DISPLAY_TZ).strftime("%Y-%m-%d %H:%M:%S")})
    return sorted(items, key=lambda i: i["name"], reverse=True)


def prune_backups(keep: int = KEEP) -> list[str]:
    """최근 `keep`개만 남기고 오래된 백업을 삭제한다. 형식이 다른 파일은 건드리지 않는다."""
    removed = []
    for item in list_backups()[keep:]:
        (backup_dir() / item["name"]).unlink(missing_ok=True)
        removed.append(item["name"])
    return removed


def create_backup(conn: sqlite3.Connection) -> Path:
    directory = backup_dir()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = directory / f"app-{_stamp()}.db"
    if target.exists():
        raise FileExistsError(target.name)
    conn.execute("VACUUM INTO ?", (str(target),))          # 일관된 스냅샷 (WAL 포함), 파일 경로는 서버가 만든 값
    target.chmod(0o600)
    return target


@router.get("/backup")
def backup_page(request: Request, user: CurrentUser = Depends(require_role("admin"))):
    return render(request, "backup.html", {"backups": list_backups(), "keep": KEEP})


@router.post("/backup")
def backup_create(request: Request, user: CurrentUser = Depends(require_role("admin")),
                  form: dict[str, str] = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_db)):
    try:
        target = create_backup(conn)
    except FileExistsError:
        security.add_flash(conn, user, "같은 시각의 백업이 이미 있습니다. 잠시 후 다시 시도하세요.", "error")
        return RedirectResponse("/backup", status_code=303)
    except (sqlite3.Error, OSError) as exc:
        log.error("backup failed: %s", type(exc).__name__)      # 경로/내부 정보는 화면에 노출하지 않는다
        security.add_flash(conn, user, "백업을 만들지 못했습니다. 서버 로그를 확인하세요.", "error")
        return RedirectResponse("/backup", status_code=303)
    removed = prune_backups()
    audit.record(conn, request, "backup_create", user=user, target_type="backup",
                 summary=f"file: {target.name}; size: {target.stat().st_size}" + (f"; pruned: {len(removed)}" if removed else ""))
    security.add_flash(conn, user, f"백업을 생성했습니다: {target.name}")
    return RedirectResponse("/backup", status_code=303)
