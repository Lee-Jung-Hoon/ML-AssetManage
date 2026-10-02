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

## 2단계: 보안 기반 — 완료
- 만든 것: `app/security.py`, `app/forms.py`, `app/schemas.py`, `app/audit.py`, `app/templating.py`, `app/templates/{base,macros,error}.html`, `app/static/style.css`, `tests/test_security.py`(+ `tests/base.py`에 `WebTestCase`), `config.py`/`db.py`/`main.py` 확장
- 테스트: `.venv/bin/python -m unittest` 전체 통과 (1단계 25개 + 2단계 신규)

### 주요 결정
- **`app/templating.py` 추가** (디렉터리 구조에 없던 파일): 라우터와 main 사이의 순환 import를 피하기 위해 `Jinja2Templates(env=Environment(autoescape=True))`와 `render()`를 분리. Starlette 1.7의 `Jinja2Templates`는 `autoescape` 인자를 받지 않아 Environment를 직접 만들어 넘긴다.
- **폼 파싱**: `read_form`(async, 스트림 1MB 제한·415·400)과 `csrf_form`(sync, 세션 CSRF 검증 후 `csrf_token` 제거) 두 의존성으로 분리. 같은 키가 여러 번 오면 마지막 값을 쓴다. 필드 수 초과·잘못된 UTF-8은 400.
- **로그인 폼은 CSRF 생략** (합의된 예외): 로그인 라우트는 `read_form`만 사용하고 `csrf_form`을 쓰지 않는다. 3단계에서 README 설계 결정에 기록할 것.
- **세션**: DB에는 SHA-256만 저장, `last_seen_at` 갱신은 60초 간격으로 제한(요청마다 쓰기 방지). 비활성 사용자의 세션은 조회 시 폐기. flash는 `sessions.flash`(JSON)에 저장하고 GET 렌더링에서만 소비.
- **AES-GCM AAD**: 레코드 ID 외에 필드명(`license_key`, `account_info`)도 AAD에 포함해 같은 레코드 안에서 필드 간 복사도 막는다.
- **`ADMIN_ENABLED`**: 미설정이면 true, 설정되어 있으면 `true/1/yes/on`만 켜짐 (오타는 안전한 쪽=꺼짐). admin 세션은 `require_login`에서 매 요청 검사해 삭제, `require_role("admin")`은 꺼져 있으면 403.
- **500 응답 헤더**: Starlette의 `ServerErrorMiddleware`는 사용자 미들웨어 바깥이라 500에는 헤더가 안 붙는다 → `Exception` 핸들러에서 `apply_security_headers`를 직접 호출. 500 로그에는 예외 타입만 남긴다.
- **no-store**: `/static/` 외 모든 응답(에러 페이지·리다이렉트 포함)에 적용.
- **로그인 제한**: 키는 `u:<소문자 사용자명[:64]>`, `ip:<주소>`. 존재하지 않는 계정도 동일하게 집계. 잠금 중에는 해시 연산을 건너뛴다(CPU 보호). 항목 수 상한(10,000)으로 메모리 고갈 방지. 성공 시 계정 카운터만 초기화(IP 카운터는 유지).
- **로그인 실패 시 해시 비용**: 더미 해시는 첫 사용 시 1회 생성해 캐시.
- 테스트는 쿠키 도메인을 `testserver.local`로 설정해야 httpx가 전송한다 (http.cookiejar가 점 없는 호스트에 `.local`을 붙임).
- 사이드바에는 아직 없는 라우트(`/servers` 등)의 링크가 포함되어 있다 (이후 단계에서 채워짐).
- `static/app.js`는 JS가 필요해질 때까지 만들지 않음 (`base.html`에도 script 태그 없음).

### 남은 이슈
- Starlette `httpx2` 경고 (1단계에서 기록, 변경 없음).
- 실제 uvicorn 기동 확인은 3단계(`serve` CLI)에서 한다.
