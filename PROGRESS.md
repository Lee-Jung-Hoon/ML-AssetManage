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

## 6단계: 서버 하위 항목 (IP, 디스크, GPU, 호스트 서비스, 컨테이너, ACL) — 완료
- 만든 것: `app/routers/server_items.py`(항목 정의 표 `ItemSpec` → 라우트/SQL/표시 생성), `templates/servers/item_form.html`, 서버 상세의 섹션 렌더링과 GPU 합계, 스키마(`ServerIPForm`/`ServerDiskForm`/`ServerGPUForm`/`HostServiceForm`/`ContainerForm`/`ACLForm`), `macros.html`(`generic_field`, `item_cell`), `tests/test_server_items.py`
- 테스트: 239개 통과. grep 점검 0건.

### 주요 결정
- **선언형 구현**: 6개 항목을 `ItemSpec`(폼 필드, DB 컬럼, 표 헤더/셀 변환)으로 선언하고 라우트(`/servers/{id}/{kind}/new|{item}/edit|{item}/delete`)와 SQL은 한 번만 만든다. SQL 문자열은 import 시점에 코드 상수(테이블/컬럼명)로만 조립하고 사용자 입력은 `?` 바인딩 (`kind`는 SPECS 화이트리스트에 없으면 404).
- **폼 화면**: 항목 추가/수정은 별도 폼 화면, 삭제는 수정 화면의 POST 버튼(그 화면이 확인 단계). 인라인 JS/confirm 없음. 항목은 반드시 해당 서버에 속해야 하며(`WHERE id=? AND server_id=?`) 다른 서버 경로로는 404.
- **서버 수정일 갱신**: 하위 항목을 추가/수정/삭제하면 서버의 `updated_at/by`를 갱신하고, 감사 로그는 `server_<kind>_add|update|delete`로 서버(target_type=server)의 변경 이력에 남는다.
- **대표 IP**: 새 대표 지정 시 기존 대표는 자동 해제(부분 UNIQUE 인덱스 + 같은 트랜잭션). 같은 서버에 같은 IP 중복 등록 거부. IPv4/IPv6는 `ipaddress`로 검증하고 정규화(`2001:DB8::1` → `2001:db8::1`), 스코프 ID(`%`) 거부.
- **ACL**: 출발지/목적지는 `ip_network(strict=False)`로 정규화(`10.0.0.77/24` → `10.0.0.0/24`, 단일 IP → `/32`). 포트는 단일/범위 입력(`8000 - 8100`)을 `port_start/port_end`로 저장, 만료일은 요청일 이상. 만료일이 지난 ACL은 "만료됨" 배지.
- **디스크**: 사용량 ≤ 전체 용량(같으면 허용), `nan/inf` 거부, 사용률은 저장하지 않고 계산. 측정일이 비어 있으면 "미기재"로 표시.
- **GPU**: 수량 1~16, 장당 VRAM은 선택(1~1024, 비우면 총 VRAM `-`), 드라이버/CUDA는 숫자와 점만(`550.54.15`, `12.4`), 총 VRAM은 저장하지 않고 수량×VRAM으로 계산. 할당 대상이 비면(공백만 포함) "미할당" 배지, 모델은 `<datalist>` 추천 + 직접 입력.
- **컨테이너**: GPU 디바이스 번호는 숫자와 쉼표만(`0,1`; 쉼표 주변 공백만 허용하고 `0 1`은 거부), '특정 디바이스'면 필수, 다른 값이면 서버측에서 비워 저장. 포트 매핑은 쉼표 구분, 각 항목 형식과 1~65535 검증 후 정규화.
- **ASCII 전용 정규식**: `\d`가 전각 숫자(`８０`)를 통과시켜 포트 검증을 우회하던 것을 테스트로 발견 → `[0-9]`로 교체.
- 서버 상세 화면은 모든 로그인 사용자가 섹션 6개를 볼 수 있고, 추가/수정 링크는 editor 이상에게만 표시.

### 남은 이슈
- 대시보드 집계(디스크 경고, GPU 현황, 드라이버/CUDA 버전 불일치, 미할당 GPU, 처리 대기 ACL)는 12단계에서 이 테이블들을 사용한다.
- 서버 상세의 구동 서비스(7단계), 연결 라이선스(8~9단계) 섹션 추가 예정.

## 7단계: 서비스 CRUD, 구동 서버, 연결 관계 — 완료
- 만든 것: `app/routers/services.py`, `templates/services/{list,form,detail,delete,server_form,link_form}.html`, 서버 상세의 "구동 중인 서비스" 섹션, 스키마(`ServiceForm`/`ServiceFilter`/`ServiceServer*Form`/`ServiceLinkForm`, URL·도메인·코드·인증방식 검증기), 매크로(`url_list`/`url_link`/`tier_badge`), `tests/test_services.py`
- 테스트: 280개 통과. grep 점검 0건.

### 주요 결정
- **서비스 코드**: `[A-Z0-9]+(-[A-Z0-9]+)*`만 허용(소문자·밑줄·연속/선행/후행 하이픈 거부, 자동 대문자 변환 없음), 고유.
- **URL 필드(저장소/문서)**: `http://`/`https://`만, 계정 정보(`user:pw@`)와 공백/제어문자 거부. `javascript:`, `data:`, `ftp:`, `file:`, `//host` 등 모두 거부(테스트).
- **접속 URL/도메인**: 줄바꿈 구분, 최대 20줄. 각 줄은 http(s) URL이거나 스킴 없는 도메인(`host[:port][/path]`)이어야 한다 — CLAUDE.md의 "URL/도메인" 표기를 이렇게 해석했다. 화면에서 http(s)만 `rel="noopener noreferrer"` 링크로, 스킴 없는 도메인은 텍스트로 표시. 호스트명 밑줄은 허용하지 않는다(경로에는 허용).
- **서빙 엔진**: AI 추론이 아닌 분류로 제출되면 서버측에서 NULL로 저장(분류를 바꾸면 기존 값도 비워짐). 잘못된 엔진명은 거부. DB CHECK도 이중으로 막는다.
- **담당자**: 정/부 모두 활성 사용자만(기존 값 유지 예외), 같은 사용자를 정·부로 중복 지정 불가(제가 추가한 규칙). "내 담당만"과 담당자 필터는 정/부 모두 포함. 목록은 `정 / 부` 형태로 비활성 담당자 배지 표시.
- **중요도 배지 색**: Tier 1 빨강 / Tier 2 주황 / Tier 3 회색 (항상 "Tier N" 텍스트 동반).
- **연결 관계**: 내부 서비스/외부 시스템 정확히 하나(폼 검증 + DB CHECK), 자기 참조는 선택지에서 제외하고 서버에서도 거부(+DB CHECK). 상세에 나가는/들어오는 두 표(들어오는 쪽은 중요도 순). **인증 방식**은 이름만 받는다: 40자 초과 공백 없는 문자열(키/토큰처럼 보임)은 거부하고 폼에 "인증 정보는 입력 금지" 안내.
- **구동 서버/연결 관계 변경 시** 서비스의 `updated_at/by`를 갱신하고 감사 로그(`service_server_*`, `service_link_*`)를 서비스 변경 이력에 남긴다. 구동 서버 선택지에서는 이미 연결된 서버를 제외, 중복 연결 거부.
- **삭제**: 확인 페이지에 이 서비스에 의존하는 서비스 목록을 경고로 표시. 삭제 시 태그 연결·메모를 명시 삭제하고 `service_servers`/`service_links`(양방향)/`license_services`/`model_services`는 FK CASCADE. 서버·라이선스·모델 자체는 유지.
- 서비스 상세의 "사용 AI 모델"(9단계), "연결된 라이선스"(8~9단계) 섹션은 해당 단계에서 추가한다.

### 남은 이슈
- 대시보드의 Tier 1 라이선스 만료 알림, 담당자 없음/비활성 담당자 서비스 집계는 12단계.

## 8단계: 라이선스 (AI API 전용 필드, 암호화 필드, 서버/서비스 연결) — 완료
- 만든 것: `app/routers/licenses.py`, `templates/licenses/{list,form,detail,reveal,delete,connect_form}.html`, `assets.license_status`/`data_policy_risk`, 스키마(`LicenseForm`, `LicenseFilter`, `RevealForm`, 연결 폼), 서버/서비스 상세의 "연결된 라이선스"(+서비스는 AI API 별도 묶음) 섹션, `tests/test_licenses.py`
- 테스트: 331개 통과. grep 점검 0건.

### 주요 결정
- **암호화**: 라이선스 키/계정 정보는 `security.encrypt_field`(AES-256-GCM, 랜덤 12바이트 nonce, AAD=`<필드명>:<레코드 ID>`)로 저장. 레코드 ID가 AAD이므로 INSERT 후 같은 트랜잭션에서 암호화한다. DB 파일(+WAL) 바이트에 평문이 없음을 테스트로 검증, 다른 레코드로 암호문을 복사하면 복호화 실패 → 화면에 "복호화 실패" 표시(500 아님).
- **마스킹/열람**: 상세는 모든 역할에 `****abcd`(9자 이하는 `********`). 원문은 editor 이상, `POST /licenses/{id}/reveal`(CSRF)로만 열람하고 감사 로그(`license_reveal`)에 필드명만 기록한다. 원문 화면은 `no-store`.
- **민감 정보 제외**: 감사 로그 요약은 "민감 정보 등록/변경: 라이선스 키 (값 비공개)"만, 목록·검색(이름/CN/SAN만 대상)·폼 재렌더링(오류 시에도 값을 되돌리지 않음)·수정 폼 프리필에 평문이 나오지 않는다. 수정 시 키를 비우면 기존 값 유지, "삭제" 체크박스로 제거.
- **AI API**: API 키/계정 정보 값이 제출되면 서버측에서 422로 거부(필드 오류 메시지), 수정 화면에서는 민감 정보 입력란 자체를 숨기고 상세에도 민감 정보 섹션이 없다. 고객 데이터 전송·opt-out은 비워 제출하면 "미확인". 데이터 정책 경고는 `전송=예 AND opt-out ∈ {미설정, 미확인}`일 때만(표로 8개 조합 검증) 빨강 "데이터 정책 확인" 배지(목록/상세, 12단계 대시보드 긴급 알림에 사용).
- **종류 전환**: SSL/AI 전용 필드는 해당 종류가 아니면 서버측에서 비워 저장(CHECK 제약과 일치). 일반 라이선스 → AI API로 바꾸면 저장된 키/계정이 삭제되고, AI API → 일반으로 바꾸며 키를 넣을 때는 CHECK 때문에 "삭제는 UPDATE 전, 저장은 UPDATE 후" 순서로 처리(`_run_sensitive`).
- **만료 상태**: 저장하지 않고 계산. 만료일 < 오늘 → 만료됨, 오늘 ≤ 만료일 ≤ 오늘+알림일 → 만료 임박(오늘 만료는 아직 "임박"), 그 외 유효, 만료 없음 → 영구. 목록의 상태 필터는 같은 규칙의 SQL 조건이며 경계값(어제/오늘/+30/+31, alert_days=0)을 테스트했다. 날짜 기준은 Asia/Seoul. 배지는 `만료 임박 D-10`처럼 텍스트 동반.
- **입력 정규화**: SAN/사용 모델은 줄 단위 검증(최대 100/30줄), SHA-256 지문은 64자리 16진수를 `AA:BB:..`로 정규화, 통화는 3자리 영문 대문자, 비용/예산은 `nan/inf`·음수 거부. 폼의 문자열은 앞뒤 공백이 제거되므로 키의 앞뒤 공백도 제거된다.
- **목록 기본 정렬**은 만료일 오름차순(영구는 마지막). 서버/서비스 연결은 별도 폼(중복·존재하지 않는 ID 거부), 연결 해제는 상세의 POST 버튼. 삭제 확인 화면은 이 AI API를 쓰는 AI 모델을 경고하고, 삭제 시 모델의 `license_id`는 SET NULL.
- **개인키/인증서 파일은 저장하지 않는다**는 안내를 폼에 명시(README에도 기재 예정).

### 남은 이슈
- AI 모델 상세 링크(`/models/{id}`)는 9단계에서 생긴다. 대시보드 긴급 알림(Tier 1 서비스 연결 라이선스, 데이터 정책 확인 항목)은 12단계.

## 9단계: AI 모델, 서비스 연결, AI API 라이선스 연결, 라이선스 위험 판정 — 완료
- 만든 것: `app/routers/models.py`, `templates/models/{list,form,detail,delete,service_form}.html`, `assets.license_risk` + SQL 조각(`MODEL_PROD_LINKED_SQL`, `MODEL_RISK_SQL`), 스키마(`ModelForm`/`ModelFilter`/`ModelService*Form`), 서비스 상세의 "사용 AI 모델" 섹션, 매크로(`commercial_badge`, `risk_badge`), `tests/test_models.py`
- 테스트: 전체 통과(아래 보고 참고). grep 점검 0건.
- **양방향 링크 완성**: 서버 ↔ 서비스, 서비스 ↔ AI 모델, 서비스/서버 ↔ 라이선스, AI 모델 ↔ AI API 라이선스가 각 상세 화면에서 서로 보인다.

### 주요 결정
- **라이선스 위험**(저장하지 않고 계산): 상업 이용이 불가/미확인 **그리고** (모델 상태가 운영 **또는** prod 환경의 운영중 서비스에 연결) → 빨강 "라이선스 위험". 상업 이용이 조건부면 상태와 무관하게 주황 "조건 확인". 같은 규칙을 Python(`license_risk`)과 SQL(`MODEL_RISK_SQL`, 목록의 "라이선스 위험만" 필터와 12단계 대시보드가 사용)로 구현했고, 4×4×2 전 조합이 서로 일치함을 테스트한다. 서비스 연결 조건은 `environment='prod' AND status='운영중'`만 해당(점검/개발중/종료·stg·dev는 제외). 명세 그대로 "폐기" 모델도 prod 서비스에 연결되어 있으면 위험으로 본다.
- **상업 이용 배지 색**: 가능=초록, 조건부/미확인=주황, 불가=빨강 (항상 "상업 이용 ○○" 텍스트). 위험/조건 확인 배지는 그와 별도로 표시.
- **상용 API 연결**: 출처가 "상용 API"일 때만 `license_id` 허용(다른 출처에서 값이 오면 거부 — 출처를 바꾸려면 연결을 먼저 비워야 함), 종류가 AI API인 라이선스만 허용(서버측 검증 + DB CHECK). 모델 상세에 연결된 API와, 그 API가 "데이터 정책 확인" 상태이면 배지를 함께 표시. 라이선스 삭제 시 모델의 연결만 SET NULL.
- **필수 규칙**: 모델명+버전 고유(수정 시에도), 파인튜닝/오픈소스는 베이스 모델 필수, 상업 이용 기본값 "미확인"(폼 기본 선택, 누락 시에도 "미확인"), 설명 필수.
- **저장 위치**는 `s3://` 등 어떤 스킴이든 허용(제어 문자만 거부)하되 링크가 아닌 일반 텍스트로만 표시. 실험/문서 URL은 서비스와 같은 http(s) 규칙(`rel="noopener noreferrer"`).
- **서비스 연결**은 모델 상세에서만 관리(용도 비고 포함, 중복·존재하지 않는 서비스 거부). 연결 변경은 모델의 수정일/변경 이력에 기록, 서비스 상세에는 읽기 전용으로 표시. 삭제 확인 화면은 사용 중인 서비스를 경고.

### 남은 이슈
- 대시보드의 상업 이용 "조건부" 목록/긴급 알림(라이선스 위험)은 12단계.
