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

# --- 요청 처리 ---
MAX_BODY_BYTES = 1024 * 1024        # 폼 본문 1MB
MAX_FORM_FIELDS = 500

# --- 인증 ---
SESSION_COOKIE = "__Host-session"
SESSION_TOUCH_SECONDS = 60          # last_seen 갱신 최소 간격 (요청마다 쓰기 방지)
LOGIN_MAX_FAILURES = 5
LOGIN_LOCK_SECONDS = 15 * 60
PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 256

# scrypt: OWASP 권장 동등 수준. 메모리 ≈ 128 * N * r = 32MiB
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 3
SCRYPT_CONCURRENCY = 3              # 동시 해시 연산 수 (3 × 32MiB, mem_limit 512m 내)
