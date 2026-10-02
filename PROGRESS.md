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

## 4단계: 사용자 관리, 비밀번호 초기화, 감사 로그 조회 — 완료
- 만든 것: `app/routers/users.py`, `app/routers/audit.py`, `templates/users/{list,form,credentials}.html`, `templates/audit/list.html`, `macros.html`(select/checkbox/pagination), `schemas.py`(UserCreateForm/UserEditForm/AuditFilter/Checkbox/OptDate), `db.py`(`paginate`, `select_where`), `templating.py`(`kst` 필터), `tests/test_users.py`
- 테스트: `.venv/bin/python -m unittest` 148개 통과 (반복 실행해도 동일). grep 점검(SQL 조립·템플릿 우회·인라인 script/style) 0건.

### 주요 결정
- **임시 비밀번호는 POST 응답 화면에 한 번만 표시** (PRG 예외). DB·flash·감사 로그·목록 어디에도 평문을 남기지 않는다. 새로고침(재전송)하면 중복 사용자명 오류가 나므로 재노출되지 않는다.
- **본인 계정 보호**: admin은 본인을 비활성화/강등할 수 없고 `비밀번호 초기화`도 본인에게는 불가(비밀번호 변경 화면 사용). 이 규칙으로 "마지막 활성 admin 보호"가 충족된다 — 변경을 수행하는 주체는 항상 활성 admin이므로, 본인 변경을 막으면 admin이 0명이 될 수 없다. (두 admin이 동시에 서로를 강등하는 극단적 경합만 남으며, 그 경우 `reset-admin`으로 복구한다.)
- **세션 무효화 규칙**: 역할 변경 또는 활성→비활성 시, 비밀번호 초기화 시 해당 사용자의 모든 세션 삭제. 이름/팀만 바꾸면 세션 유지.
- **변경 없음**은 감사 로그를 남기지 않고 "변경된 내용이 없습니다." flash.
- **사용자명 규칙**: 영문/숫자로 시작, `[A-Za-z0-9._-]` 2~50자, 대소문자 무시 중복 불가. 수정 화면에서 사용자명은 변경 불가. 삭제 라우트는 없다 (비활성화만).
- **감사 로그 필터**: 날짜는 KST 기준 (시작일 0시 ~ 종료일 당일 포함). 사용자 필터는 users 테이블의 사용자명 목록(로그인 실패 시 입력된 임의 문자열이 드롭다운을 키우지 못하게). 잘못된 필터(날짜 형식·알 수 없는 파라미터·길이 초과)는 데이터를 보여주지 않고 오류 배너만 표시. 페이지당 50건, 범위 초과 페이지는 마지막 쪽으로 보정. 동적 WHERE는 코드에 고정된 `?` 조각만 `select_where`로 결합.
- 감사 로그 화면은 읽기 전용 (GET 외 405, 수정/삭제 라우트 없음).
- 사이드바 admin 메뉴는 `ADMIN_ENABLED=true`이고 admin일 때만 표시 (3단계 구현 그대로).
- 테스트 헬퍼 수정: 같은 초에 만든 세션 두 개의 CSRF 토큰을 `created_at` 정렬로 구분하던 불안정성을 `lookup_session`으로 교체.

### 남은 이슈
- `/backup`, `/servers` 등 사이드바 링크는 이후 단계에서 구현된다 (현재 404).
- `httpx2` deprecation 경고 (1단계 기록).
- 자산별 "변경 이력"용 조회 헬퍼는 5단계에서 `audit.py`에 추가한다.

## 5단계: 서버 CRUD + 자산 공통 기능 — 완료
- 만든 것: `app/assets.py`(태그·운영 메모·최신성·담당자·변경 이력 공통 함수), `routers/asset_common.py`(확인 완료/메모 추가·삭제 라우트 팩토리 `make_common_router`), `routers/servers.py`, `templates/servers/*`, `macros.html` 공통 매크로(textarea/owner/tags/verify 배지/usage bar/메모 타임라인/변경 이력), 스키마(`ServerForm`, `ServerFilter`, `NoteForm`, `Tags`, `opt_int`, `opt_choice`, `Flag`), `db.like_pattern`, `.w-0 ~ .w-100` 막대 CSS, `tests/test_servers.py`
- 테스트: 195개 통과. grep 점검 0건.

### 주요 결정
- **재사용 구조**: 서비스/AI 모델/라이선스는 `make_common_router(asset_type, base)`로 확인·메모 라우트를 얻고, 상세 템플릿에서 `notes_section`/`history_section`/`verify_badge`/`owner_cell`/`tag_list` 매크로와 `assets.common_sections()`를 재사용한다. 테이블 이름이 필요한 문장(존재 확인, 확인 완료 UPDATE)은 f-string 대신 asset_type별 상수 SQL 사전.
- **태그**: 쉼표 구분 → 공백 제거·소문자화·중복 제거, 30자·자산당 10개, 한글/영문/숫자/`-`/`_`만. 목록의 태그 일괄 조회는 ID 목록을 JSON 하나로 바인딩(`json_each`)해 SQL 조립을 피했다.
- **최신성**: 미확인이거나 마지막 확인이 90일 **초과**(정확히 90일은 통과)면 "확인 필요". 수정은 `last_verified_*`를 건드리지 않고, 변경 없는 저장은 DB·감사 로그에 아무것도 쓰지 않는다 (`updated_at`도 유지).
- **담당자**: 선택지는 활성 사용자만. 이미 지정된 비활성 담당자는 `[비활성]` 표시로 유지 가능(그대로 저장 허용), 새로 비활성 사용자를 지정하는 것은 거부. 목록/상세에 "비활성 담당자" 배지.
- **메모**: 작성 editor+, 삭제 작성자 또는 admin(버튼도 권한 없는 사용자에게 숨김), 수정 기능 없음. 검증 실패는 flash 후 303 (상세 화면 재렌더링 불필요).
- **삭제**: GET 확인 페이지(구동 중인 서비스 경고) → POST 삭제. 같은 트랜잭션에서 태그 연결·메모를 명시 삭제, 하위 항목은 FK CASCADE, 감사 로그는 보존.
- **배포판**: 서버 폼은 `<datalist>` 추천 + 직접 입력(JS 없이 동작). OS 종류와 반대 OS의 알려진 배포판 조합은 거부.
- **선택 정수 검증**: `Field(ge=)`는 None에 적용 시 TypeError → `opt_int(min,max)`로 대체 (테스트로 발견).
- **목록**: 정렬은 `_ORDER` 화이트리스트(서버명/수정일/마지막 확인일 오래된 순), 잘못된 필터·정렬값은 오류 배너+빈 결과. 대표 IP/최대 디스크 사용률/GPU 요약은 하위 테이블 서브쿼리(6단계 입력 전에는 빈 값).
- `server_conditions()`를 함수로 분리해 11단계 CSV 내보내기가 같은 필터를 재사용한다.

### 남은 이슈
- 서버 상세의 하위 섹션(IP/디스크/GPU/호스트 서비스/컨테이너/ACL)은 6단계, 구동 서비스는 7단계, 연결 라이선스는 8~9단계에서 추가.
- `httpx2` deprecation 경고 (1단계 기록).
