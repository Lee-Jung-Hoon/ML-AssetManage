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

## 3단계: 인증 화면, admin 부트스트랩, ADMIN_ENABLED, CLI — 완료
- 만든 것: `app/routers/auth.py`(login/logout/password), `app/routers/dashboard.py`(자리표시자), `app/__main__.py`(serve/reset-admin/healthcheck), `login.html`, `password_change.html`, `dashboard.html`, `security.py`에 `bootstrap_admin`/`reset_admin`/계정 잠금 헬퍼, `schemas.py`에 `LoginForm`/`PasswordChangeForm`/`SecretFormModel`, `audit.record`에 `user_id` 인자, `tests/test_auth.py`
- 테스트: `.venv/bin/python -m unittest` 116개 통과. 실제 `python -m app serve`(uvicorn)를 임시 데이터 경로로 띄워 `/healthz`, 보안 헤더, 서버 헤더 없음, `/` → `/login` 303, `/docs` 404, 초기 admin 비밀번호 1회 출력을 확인했다.
- grep 점검(SQL 조립, 템플릿 우회, 인라인 script/style) 0건.

### 주요 결정
- **로그인 CSRF 생략(합의된 예외)**: `POST /login`은 `read_form`만 사용한다. 로그인 후 모든 POST는 `csrf_form`. README 설계 결정·체크리스트에 예외로 명시해야 한다 (14단계).
- **로그인 실패 응답**: 사유(없는 계정/비활성/잘못된 비밀번호/잠금/admin 차단/잘못된 입력/알 수 없는 필드)와 무관하게 401 + 동일 문구. 사유는 감사 로그 `summary`에만 남긴다 (`locked`, `invalid`, `invalid_input`). 시도한 사용자명은 64자까지 기록하며 비밀번호는 기록하지 않는다.
- **세션 고정 방지**: 로그인 시 기존 쿠키의 세션을 삭제하고 새 ID를 발급한다 (공격자가 심은 쿠키 값은 채택하지 않음).
- **비밀번호 변경**: 현재 세션을 포함해 해당 사용자의 모든 세션을 삭제하고 새 세션을 발급한다. 새 비밀번호 해시는 트랜잭션 밖에서 계산. 현재 비밀번호 대입 공격은 로그인과 같은 계정 잠금(5회/15분)으로 제한한다. 검증 실패 재렌더링은 422.
- **초기 admin**: `role='admin'` 또는 `username='admin'`인 계정이 하나라도 있으면 만들지 않는다. admin 이름만 있고 admin 역할이 없으면 경고만 로그하고 `reset-admin` 안내.
- **`reset-admin`**: 계정이 없으면 생성, 비활성/강등이면 admin·활성으로 복구, 새 비밀번호 출력, 모든 세션 삭제, 감사 로그(`reset_admin`, 사용자명 `(cli)`) 기록. `ADMIN_ENABLED`와 무관. 한계: 실행 중 서버의 인메모리 로그인 잠금은 CLI가 풀 수 없다 (최대 15분 후 자동 해제).
- **자리표시자 대시보드**: 로그인 후 이동할 `/`를 위해 최소 라우트를 두었다 (12단계에서 교체).
- **로그 레벨**: `serve`는 `logging.basicConfig(INFO)`. 테스트 패키지는 `app` 로거를 CRITICAL로 올려 소음을 막는다 (`assertLogs`는 영향 없음).
- 존재하지 않는 경로는 로그인 여부와 무관하게 404 (보호된 라우트만 로그인으로 리다이렉트).

### 남은 이슈
- `httpx2` deprecation 경고 (1단계 기록).
- 비밀번호 변경 화면의 서버측 잠금 문구는 로그인 잠금과 같은 계정 카운터를 공유한다 (의도된 동작이지만 사용자 혼동 가능).
