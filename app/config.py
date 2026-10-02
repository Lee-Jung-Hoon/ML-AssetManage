"""고정 설정 상수. 사용자가 설정하는 환경변수는 ADMIN_ENABLED 하나뿐이므로 여기엔 환경변수가 없다.

테스트는 이 모듈의 상수를 패치해 임시 디렉터리를 사용한다 (다른 모듈은 `config.X`로 참조할 것).
"""
from pathlib import Path
from zoneinfo import ZoneInfo

DATA_DIR = Path("/data")

SESSION_IDLE_SECONDS = 30 * 60
SESSION_ABSOLUTE_SECONDS = 12 * 60 * 60

STALE_DAYS = 90          # 최신성 기준
PAGE_SIZE = 20

DISPLAY_TZ = ZoneInfo("Asia/Seoul")   # 저장은 UTC, 표시만 변환


def db_path() -> Path:
    return DATA_DIR / "app.db"
