# PROGRESS

## 1단계: 골격, DB, 마이그레이션, 전체 스키마 — 완료
- 만든 것: `app/config.py`, `app/db.py`, `app/main.py`, `app/migrations/001_init.sql`, `tests/base.py`, `tests/test_db.py`, `requirements.in`, `requirements-dev.in`, `.gitignore`, 빈 `templates/`·`static/style.css`
- 테스트: `.venv/bin/python -m unittest` 25개 통과

### 주요 결정
- `app/config.py` 추가 (상수만, 환경변수 없음). 테스트는 `config.DATA_DIR`을 패치하고, 다른 모듈은 `config.X`로 참조한다.
- 연결은 `isolation_level=None` + `transaction()` 헬퍼로 명시 제어. `check_same_thread=False`는 FastAPI가 yield 의존성의 시작/종료를 다른 스레드에서 실행할 수 있어서다.
- 마이그레이션은 파일당 `BEGIN IMMEDIATE` 한 트랜잭션에서 스키마 변경과 버전 기록을 함께 처리하고, 실패 시 롤백한다. `schema_migrations`는 실행기가 만든다.
- 날짜 CHECK는 `date(x) IS x`를 쓴다. `=`는 잘못된 날짜(`2026-13-01`)에서 NULL이 되어 CHECK를 통과하는 버그가 있었다.
- 컨테이너 `gpu_usage` 값은 `없음/전체/특정 디바이스`. 서버 유형은 `물리/VM/클라우드 인스턴스`.
- 감사 로그는 UPDATE/DELETE 트리거로 변조를 차단한다.
- 모델 규모 컬럼명은 `param_size`, 라이선스 SSL/AI 컬럼은 `ssl_*`/`ai_*` 접두사.

### 남은 이슈
- Starlette 1.7이 `httpx` 대신 `httpx2` 설치를 권하는 deprecation 경고를 낸다. 허용 개발 의존성은 `httpx`뿐이라 변경하지 않았다. 결정이 필요하면 문의한다.
- 해시 고정 `requirements.txt`는 14단계에서 생성한다 (지금은 `.in` 파일만).
- pip-audit, pip-tools는 14단계에서 설치한다.
