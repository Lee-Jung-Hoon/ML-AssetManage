# 사내 자산 관리 (서버 · 서비스 · AI 모델 · 라이선스)

개발 회사 내부의 서버(GPU 서버 포함), 그 위에서 운영되는 서비스, AI 모델, 라이선스(SSL 인증서, AI API 등)를
**"어떤 자산이 어디서, 어떤 라이선스로, 누구 책임하에 운영되는가"** 기준으로 기록하는 자체 호스팅 웹 서비스입니다.

> 이 시스템은 **자산 대장**입니다. MLOps 플랫폼도, 비밀 저장소(vault)도 아닙니다.
> - 실험 추적·학습 실행·모델 파일 저장은 하지 않습니다 (링크/저장 위치만 기록).
> - **개인키(private key)와 인증서 파일, SSH 키, 접속 비밀번호, AI API 키 자체는 저장하지 않습니다.** 라이선스 키/계정 정보만 AES-256-GCM으로 암호화해 저장하며, 그 외에는 "보관 위치(예: Vault 경로)"만 적습니다.

우선순위는 보안 → 단순성 → 최소 의존성 → 최소 설정 → 기능 완성도 순입니다.
Python 3.13 · FastAPI · Uvicorn(워커 1개) · Jinja2 · SQLite · `cryptography`가 전부이며 JS 프레임워크, 빌드 도구, 외부 CDN/폰트, 외부 네트워크 호출이 없습니다 (폐쇄망 동작).

---

## 1. 실행 방법

```bash
docker compose up -d --build
docker compose logs app        # 초기 admin 비밀번호는 여기서 딱 한 번 출력됩니다
```

브라우저에서 `http://localhost:8080` (포트는 호스트의 `127.0.0.1`에만 바인딩됩니다. 외부 공개는 아래 4장의 리버스 프록시를 사용하세요).

사용자가 설정하는 값은 **`ADMIN_ENABLED` 하나뿐**입니다 (`docker-compose.yml`, 기본 `"true"`). 나머지는 코드의 안전한 기본값이거나 자동 생성입니다.

| 항목 | 값 |
|---|---|
| 데이터 경로 | `/data` 고정 (`app.db`, `secret.key`, `backups/`) — compose의 named volume `data` |
| 세션 | 유휴 30분, 절대 12시간 |
| 최신성 기준 | 90일 |
| 쿠키 | `__Host-session`, Secure · HttpOnly · SameSite=Strict (항상) |
| 타임존 | 저장은 UTC, 화면 표시는 Asia/Seoul |
| 워커 | 1개 고정 (로그인 제한이 인메모리 상태에 의존) |

### 첫 로그인

1. `docker compose logs app`에서 `사용자명: admin` / `비밀번호: ...` 블록을 확인합니다 (20자 이상 랜덤, 이후 재기동 때는 다시 출력되지 않습니다).
2. 로그인하면 **비밀번호 변경이 강제**됩니다 (12자 이상, 사용자명과 같을 수 없음). 변경하면 다른 기기의 세션은 모두 종료됩니다.
3. **사용자 관리**에서 계정을 만듭니다 (회원가입은 없습니다). 임시 비밀번호는 화면에 한 번만 표시되고, 사용자는 첫 로그인 때 변경해야 합니다.

역할: `admin`(사용자 관리·감사 로그·백업 + 모든 자산 CRUD) / `editor`(자산 CRUD, 확인 완료, 메모, CSV 내보내기·일괄 등록, 태그 관리) / `viewer`(읽기 전용, 검색 포함).

### 관리자 차단과 비밀번호 복구

- 운영 중에는 관리자를 꺼 두고 계정 작업이 필요할 때만 켜는 방식을 전제로 합니다. `docker-compose.yml`에서 `ADMIN_ENABLED: "false"`로 바꾸고 `docker compose up -d`:
  - admin 역할 계정은 로그인이 거부됩니다 (다른 실패와 같은 메시지 → 계정 존재 여부 비노출).
  - 이미 발급된 admin 세션도 **매 요청마다 검사해 즉시 무효화**됩니다.
  - 사용자 관리·감사 로그·백업 화면은 403이고 메뉴에서도 사라집니다.
  - 값은 `true/1/yes/on`일 때만 켜집니다 (`flase` 같은 오타는 안전한 쪽인 "꺼짐").
- 비밀번호를 잊었거나 admin이 잠겼다면 (이 값과 무관하게 동작):

  ```bash
  docker compose exec app python -m app reset-admin
  ```

  새 랜덤 비밀번호를 터미널에 출력하고, `admin` 계정이 없거나 비활성/강등 상태면 admin·활성으로 복구하며, 모든 세션을 무효화하고 감사 로그에 남깁니다. (실행 중인 서버의 인메모리 로그인 잠금은 최대 15분 뒤 자동으로 풀립니다.)

---

## 2. 기능 요약

| 영역 | 내용 |
|---|---|
| 서버 | 기본 정보 + IP · 디스크(사용률 계산) · GPU(수량×VRAM, 드라이버/CUDA, 할당 대상) · 호스트 서비스 · Docker 컨테이너 · ACL 요청. 목록 검색/필터/정렬/페이지네이션, 삭제 전 확인(구동 중인 서비스 경고) |
| 서비스 | 코드/분류/환경/중요도(Tier), 구동 서버(N:M), 연결 관계(나가는/들어오는 두 표), 사용 AI 모델, 연결된 라이선스(AI API는 별도 묶음), 서빙 엔진(AI 추론일 때만) |
| AI 모델 | 출처/라이선스 조건/상업 이용, 상용 API 연결, 서비스 연결, **라이선스 위험·조건 확인 배지**(조회 시 계산) |
| 라이선스 | SSL/AI API 전용 필드, 만료 상태 계산(영구/유효/임박/만료), **키·계정 정보 암호화(AES-256-GCM)와 마스킹**, 서버/서비스 연결 |
| 공통 | 담당자(활성 사용자만), 태그, 운영 메모 타임라인(수정 불가·삭제는 작성자/admin), "내용 확인 완료" 최신성 관리, 자산별 변경 이력 |
| 대시보드 | 긴급 알림 · 요약 · 내 담당 · 서버 · 디스크 경고 · 서비스 · GPU 현황 · AI 모델 · AI API · 라이선스 만료 · 확인 필요 · 최근 변경 (숫자 카드/표/CSS 막대) |
| 검색 | 헤더의 통합 검색 (서버·서비스·모델·GPU·라이선스·컨테이너·태그, **IP를 입력하면 그 IP가 포함되는 ACL**) |
| CSV | 서버/서비스/AI 모델/라이선스/ACL/GPU 인벤토리 내보내기, 서버 일괄 등록 |
| 운영 | 사용자 관리, 감사 로그, 백업 |

### CSV 일괄 등록 형식 (서버 기본 정보, editor 이상)

서버 목록의 **CSV 일괄 등록**에 붙여 넣습니다 (파일 업로드 없음, 본문 1MB 제한은 그대로 적용). 한 번에 최대 1000행.

```
name,hostname,os_type,os_distro,os_version,kernel_version,environment,status,server_type,location,cpu_model,cpu_cores,memory_gb,primary_ip,owner_username,tags,description
결제 웹 1,pay-web-01,Linux,Ubuntu,22.04,5.15.0,prod,운영중,VM,IDC-A R12,Xeon Gold 6330,32,128,10.0.1.11,hong,payment;prod,결제 웹 서버
GPU 학습 1,gpu-train-01,Linux,Rocky,9.3,5.14.0,prod,운영중,물리,IDC-B R03,AMD EPYC 7763,128,1024,10.0.2.21,kim,gpu;train,학습용 GPU 서버
```

- 첫 줄은 위 헤더와 **정확히 같아야** 합니다. `tags`는 `;` 구분, `owner_username`은 활성 사용자의 사용자명입니다.
- **2단계**: ① 검증(미리보기) — 각 행을 단건 등록과 같은 검증 모델로 확인해 행별 성공/오류 사유를 보여주며 아무것도 저장하지 않습니다. ② 등록 확정 — 서버는 미리보기를 신뢰하지 않고 **제출된 CSV 전체를 처음부터 다시 검증**하며, 하나라도 오류면 전부 거부하고, 모두 유효하면 단일 트랜잭션으로 등록합니다 (all-or-nothing).
- 기존 호스트명과 겹치거나 CSV 안에서 중복되면 오류입니다 (업데이트 없이 신규 등록만). 하위 항목(디스크, ACL 등)은 등록 후 서버 상세에서 입력합니다.
- 한글은 폼 전송(퍼센트 인코딩) 때 길이가 늘어나므로 1000행의 한글 CSV는 1MB를 넘어 413이 될 수 있습니다. 나눠서 등록하세요.
- 내보내기 CSV는 UTF-8 BOM(엑셀 한글 깨짐 방지), 수식 주입 방지(`= + - @` 탭 CR로 시작하면 앞에 `'`), 파일명 `servers-YYYYMMDD.csv`입니다. 라이선스 키 등 민감 필드는 절대 포함되지 않으며, 내보내기는 POST + CSRF이고 대상/건수가 감사 로그에 남습니다.

---

## 3. 백업과 키 보관

- admin 전용 **백업** 화면의 "백업 생성"이 `VACUUM INTO`로 `/data/backups/app-YYYYMMDD-HHMMSS.db`를 만들고 **최근 14개만 보관**합니다.
- **웹에서 백업 파일을 다운로드하는 기능은 의도적으로 없습니다** (유출 경로 차단). 호스트에서 볼륨으로 가져가세요:

  ```bash
  docker run --rm -v ml-assetmanage_data:/data -v "$PWD":/out alpine cp -r /data/backups /out/   # 볼륨 이름은 `docker volume ls`로 확인
  ```

> **경고 — 반드시 읽으세요**
> - `/data/secret.key` **없이는 암호화 필드(라이선스 키/계정 정보)를 복구할 수 없습니다.** DB 백업과 함께 **키 파일도 반드시 보관**하세요. 키가 손상되면 앱은 기동을 거부하고 파일을 덮어쓰지 않습니다.
> - 키와 DB가 **같은 볼륨**에 있으므로, **볼륨 백업본 자체를 기밀로 취급**해야 합니다 (암호화 키와 암호문이 함께 있으면 의미가 없습니다). 접근 통제된 저장소에 두세요.

---

## 4. TLS(리버스 프록시)와 클라이언트 IP

TLS는 앱이 처리하지 않고 앞단 프록시에 맡깁니다 (compose에는 포함하지 않음). Caddy 예시:

```caddyfile
inventory.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy가 인증서를 자동 발급하며, 클라이언트가 보낸 `X-Forwarded-For`는 신뢰하지 않고 실제 접속 주소로 **덮어씁니다** (기본 동작). 쿠키가 `Secure`이므로 `http://localhost` 외에는 HTTPS가 필요합니다.

### X-Forwarded-For를 신뢰하는 근거와 한계

Uvicorn은 `--proxy-headers --forwarded-allow-ips="*"`로 구동됩니다.

- 포트를 호스트의 `127.0.0.1`에만 바인딩하고 compose 네트워크에는 이 앱만 있으므로 **컨테이너에 도달할 수 있는 주체는 호스트의 리버스 프록시뿐**입니다.
- 컨테이너 안에서는 요청 출발지가 루프백이 아니라 Docker 게이트웨이 IP로 보이므로 루프백 여부로 판정하면 안 됩니다. 그래서 `*`를 신뢰합니다.
- **한계**: 포트 바인딩을 `0.0.0.0`으로 바꾸거나 프록시가 들어온 `X-Forwarded-For`를 덮어쓰지 않으면 IP 위조가 가능해집니다. 이 경우 **감사 로그의 IP와 IP 기준 로그인 제한**이 영향을 받습니다 (계정 기준 잠금은 그대로 유효).

---

## 5. 보안 체크리스트 충족 내역

각 항목은 자동 테스트로 검증됩니다 (`python -m unittest`). 표의 "구현"은 파일/함수, "검증"은 대표 테스트입니다.

### 인증·세션

| 요구 | 구현 | 검증 |
|---|---|---|
| 비밀번호는 `hashlib.scrypt` (N=2^15, r=8, p=3, 16바이트 salt, `maxmem` 명시, 파라미터 포함 저장, `hmac.compare_digest`) | `security.hash_password/verify_password` (`scrypt$N$r$p$salt$hash`) | `test_security.PasswordTests` |
| 비밀번호 정책 (12자 이상, 사용자명과 동일 금지) | `security.password_policy_error`, 비밀번호 변경/사용자 생성 | `test_auth.MustChangePasswordTests` |
| 동시 해시 연산 수 제한 (`threading.Semaphore`) | `security._hash_slots` (3개) | `test_concurrent_hashing_is_limited` |
| 서버측 세션 (SessionMiddleware 미사용), ID는 `secrets.token_urlsafe(32)`, DB에는 SHA-256만 | `security.create_session/lookup_session` | `SessionTests.test_only_hash_is_stored` |
| 쿠키 `HttpOnly; Secure; SameSite=Strict; Path=/`, `__Host-` 접두사 | `security.set_session_cookie` | `test_cookie_attributes`, `test_success_sets_hardened_cookie_and_session` |
| 로그인 시 세션 ID 재발급, 로그아웃 시 서버측 삭제 | `routers/auth.py` | `test_session_id_is_reissued_on_login`, `LogoutTests` |
| 비밀번호 변경/계정 비활성화/역할 변경 시 기존 세션 모두 무효화 | `security.delete_user_sessions` | `test_success_invalidates_all_sessions...`, `UserEditTests` |
| 로그인 실패 제한 (계정·IP 각각 5회 → 15분) | `security.LoginLimiter` + `attempt_login` | `LoginLimiterTests`, `test_lockout_after_5_failures_then_unlock` |
| 실패 메시지는 항상 동일, 없는 계정도 더미 해시와 비교 | `security._get_dummy_hash` | `test_failures_all_look_identical` |

### 요청 처리

| 요구 | 구현 | 검증 |
|---|---|---|
| 상태 변경은 POST만 | PUT/PATCH/DELETE 라우트 없음, GET 핸들러는 쓰기 없음 | `test_policy.RouteIntrospectionTests` (라우트 전수 점검) |
| 모든 POST에 CSRF (세션 바인딩, `compare_digest`, 폼 파서에서 검증) | `forms.csrf_form` | `test_every_post_without_csrf_is_rejected_for_an_admin` (모든 POST 라우트 실제 요청) |
| 모든 SQL은 `?` 바인딩만, 동적 필터는 고정 조각만 조합 | `db.select_where`, 각 라우터의 `*_conditions` | `test_packaging.PolicyTests.test_no_sql_string_building` (grep 0건) |
| 모든 입력을 Pydantic으로 검증 (`max_length`, enum, IP/CIDR/포트, URL 스킴, 날짜, 범위, `extra="forbid"`) | `schemas.py` | 각 `test_validation` 계열 |
| 본문 1MB·필드 500개 제한, Content-Type 검사 | `forms.read_form` (스트림 카운트, 415/413/400) | `test_body_over_1mb_is_413`, `test_content_type_must_be_urlencoded` |
| 리다이렉트는 내부 경로만 | `security.safe_redirect_path` | `RedirectTests`, `test_next_parameter_is_validated` |
| 404/403/422/500은 사용자 정의 HTML, 내부 정보 비노출 | `main.py` 예외 핸들러 | `test_error_pages_do_not_leak`, `test_error_pages_for_every_status...` |
| CSV 수식 주입 방지 | `csvio.safe_cell` | `SafeCellTests`, `ServerExportTests` |
| CSV 일괄 등록은 확정 때 전체 재검증 | `routers/server_import.py` | `test_tampered_csv_is_revalidated_from_scratch` |
| 기본 거부 (라우터 단위 `require_login`, 엔드포인트마다 `require_role`) | `security.require_login/require_role` | `test_every_route_requires_login...`, `test_every_post_has_csrf_and_an_explicit_role_check` |
| 로그인 폼 CSRF **예외** | 세션이 아직 없어 세션 바인딩 CSRF를 적용할 수 없음 → `SameSite=Strict` + `form-action 'self'`에 의존 (로그인 이후 모든 POST는 CSRF 적용) | `test_auth.LoginTests` |

### 응답 헤더 · 로깅 · 컨테이너

| 요구 | 구현 | 검증 |
|---|---|---|
| CSP (`default-src 'self'; script-src 'self'; style-src 'self'; ...`), `nosniff`, `no-referrer`, `X-Frame-Options: DENY` — **모든 응답** (500 포함) | `main.apply_security_headers` | `test_policy.SecurityHeaderCoverageTests` |
| 인증된 페이지·CSV는 `Cache-Control: no-store` | 미들웨어 (`/static/` 제외 전부) | `test_authenticated_pages_are_never_cacheable` |
| `--no-server-header` | `__main__.serve` (`server_header=False`) | 컨테이너 실측 (`server:` 헤더 없음) |
| 인라인 `<script>/<style>/style=/onclick=` 없음 | 막대 너비는 `.w-0~.w-100` 클래스 | `test_no_inline_script_style_or_handlers` |
| 비밀번호/세션 ID/CSRF/라이선스 키/암호화 키를 로그에 남기지 않음 (예외: 최초 admin 비밀번호, `reset-admin` 출력) | 500 로그는 예외 타입만, 민감 값 GET 파라미터 없음 | `test_policy.LoggingTests` |
| 멀티스테이지, venv에 `--require-hashes` 설치, `python:3.13-slim`, pip/setuptools 제거, non-root UID 10001, `PYTHONDONTWRITEBYTECODE/UNBUFFERED`, `HEALTHCHECK` | `Dockerfile` | `test_packaging.DockerTests` + 실제 빌드/실행 확인 |
| `python -m app serve`: 0.0.0.0:8080, 워커 1, `proxy_headers`, `forwarded_allow_ips="*"`, `server_header=False` | `app/__main__.py` | `test_serve_uses_required_uvicorn_settings` |
| 읽기 전용 FS, `cap_drop: ALL`, `no-new-privileges`, `mem_limit 512m`, `127.0.0.1` 바인딩 | `docker-compose.yml` (명세와 동일, 설정 변경 지점은 `ADMIN_ENABLED` 하나) | `test_compose_matches_the_specified_minimal_shape` |

의존성은 `fastapi`, `uvicorn`(extras 없음), `jinja2`, `cryptography`와 그 전이 의존성뿐이며 `requirements.txt`에 해시로 고정되어 있습니다
(`fastapi`가 `starlette`, `pydantic`, `opentelemetry-api` 등을 끌어옵니다). 허용 목록 밖의 패키지가 들어오면 `test_packaging`이 실패합니다.

---

## 6. 설계 결정

애매한 곳은 "더 단순하고 더 안전한 쪽"을 골랐습니다.

1. 설정은 `ADMIN_ENABLED` 하나뿐, 나머지는 `app/config.py`의 상수 (테스트만 상수를 패치).
2. 로그인 폼은 CSRF를 적용하지 않고 `SameSite=Strict`와 `form-action 'self'`에 의존한다 (세션이 없어 세션 바인딩 불가). 이후 모든 POST는 CSRF.
3. 비밀번호 변경은 현재 세션을 포함한 모든 세션을 지우고 새 세션을 발급하며, 현재 비밀번호 대입은 로그인과 같은 계정 잠금으로 막는다.
4. admin은 본인을 비활성화·강등·비밀번호 초기화할 수 없다 (마지막 admin 소실 방지, 복구는 `reset-admin`).
5. 임시 비밀번호는 POST 응답 화면에 한 번만 보여주고 DB/flash/로그에 평문을 남기지 않는다.
6. `ADMIN_ENABLED`는 명시적 true 값만 켠다 (오타는 꺼짐). admin 세션은 `require_login`에서 매 요청 검사한다.
7. 내보내기는 감사 로그를 남기므로 GET이 아니라 POST + CSRF.
8. 검증 오류는 422 JSON이 아니라 폼 재렌더링 + 한국어 메시지(입력값 유지, 비밀번호/민감 값은 되돌리지 않음). 경로 파라미터가 잘못되면 404.
9. 일반 수정은 "확인 완료"로 간주하지 않고, 변경이 없으면 DB/감사 로그에 아무것도 쓰지 않는다.
10. 담당자 선택지는 활성 사용자만, 이미 지정된 비활성 담당자는 `[비활성]` 표시로 유지하고 배지로 경고.
11. 메모는 수정할 수 없고 삭제는 작성자 또는 admin만.
12. 자산 삭제는 확인 페이지(GET)를 거친 POST이며, 태그 연결·메모는 같은 트랜잭션에서 명시 삭제 (다형 참조라 FK CASCADE 불가).
13. 서버 하위 항목은 선언형 정의(`ItemSpec`) 하나에서 라우트/SQL/화면을 만들고, 대표 IP는 새로 지정하면 기존 것이 자동 해제된다.
14. 디스크 사용률·총 VRAM·라이선스 만료 상태·라이선스 위험은 저장하지 않고 조회 시 계산한다.
15. 만료 상태: 만료일 < 오늘 = 만료됨, 오늘 ≤ 만료일 ≤ 오늘+알림일 = 임박(오늘 만료는 아직 임박), 날짜 기준은 Asia/Seoul.
16. 라이선스 위험은 Python 함수와 SQL 조각을 모두 두고 전 조합이 일치함을 테스트한다 (목록 필터·대시보드가 SQL 조각을 쓴다).
17. AES-GCM의 AAD는 `<필드명>:<레코드 ID>` (다른 레코드/필드로의 복사를 막는다). 복호화 실패는 500이 아니라 "복호화 실패" 표시.
18. AI API 종류는 키 값이 들어오면 서버가 거부하고 입력란도 숨긴다 (종류 전환 시 기존 민감 정보는 삭제).
19. URL은 `http(s)`만(계정 정보·공백 거부)이며 `rel="noopener noreferrer"`로 링크, 모델 저장 위치는 임의 스킴이지만 링크 없이 텍스트로만 표시.
20. 서비스 연결의 "인증 방식"은 이름만 받고 키/토큰처럼 보이는 긴 문자열은 거부 (인증 정보 저장 금지).
21. 통합 검색은 고정 SQL + 와일드카드 이스케이프, IP는 `ipaddress`로 CIDR 포함을 판정(IPv4/IPv6 혼용 안전).
22. 태그 이름 변경은 병합하지 않고 같은 이름이 있으면 거부, 삭제는 사용되지 않는 태그만.
23. 일괄 등록은 신규 등록만(업데이트 없음), 하위 항목 없음, 감사 로그는 1건(`count=N`). 대표 IP의 공인/사설은 자동 분류.
24. 대시보드 폐기/종료 제외는 명세의 4개 집계(디스크, GPU, 확인 필요, 담당자 없음)에만 적용하고, 버전 불일치는 기재된 조합이 둘 이상일 때만, AI API 예산은 통화별 합산·만료된 항목 제외.
25. 백업 파일은 모드 600(디렉터리 700), 같은 초 충돌은 덮어쓰지 않으며 실패 사유는 로그에만 남긴다.
26. 로그인 실패 기록의 사용자명은 64자까지, 비밀번호는 기록하지 않는다. 잠금 상태에서는 해시 연산을 건너뛰어 CPU를 보호한다.
27. 만료된 세션 행은 기동 시와 로그인 시 정리한다.

## 7. 범위 외 항목 (만들지 않았습니다)

사용자가 요청하지 않는 한 구현하지 않으며, 복잡도나 보안 부담이 이유입니다.

| 항목 | 이유 |
|---|---|
| 서버 접속 비밀번호·SSH 키 등 접속 정보 저장 | 이 시스템은 비밀 저장소가 아님 — 전용 비밀 관리 도구를 쓰고 여기에는 보관 위치만 비고로 적는다 |
| 파일 첨부/업로드 | 업로드는 공격 표면이 크다 (폼은 `x-www-form-urlencoded`만 허용) |
| 이메일·슬랙 등 외부 알림 | 외부 네트워크 호출 금지 → 대시보드로 대체 |
| 에이전트 기반 자동 수집, 외부 연동용 JSON API | 자산 대장은 수기 기록이 원칙, API 문서/JSON 엔드포인트도 비활성 |
| 의존 관계 그래프/다이어그램 | 표 두 개(나가는/들어오는)로 충분 |
| AI 모델 파일·가중치·체크포인트 저장 | 저장 위치만 기록 |
| 실험 추적·학습 메트릭·학습 잡 실행 | MLflow, W&B 등 전문 도구의 영역 (링크만 기록) |
| GPU 실시간 사용률 모니터링 | DCGM Exporter, Prometheus, Grafana의 영역 (할당 현황만 기록) |
| AI API 키 저장 | 키 보관 위치만 기록 |

---

## 9. 화면 미리보기

가상의 예시 데이터(실제 폼 라우트로 입력)로 캡처한 화면입니다. 파일은 `docs/screenshots/`에 있습니다.

| 화면 | 파일 |
|---|---|
| 로그인 | [01-login](docs/screenshots/01-login.png) |
| 대시보드 (긴급 알림, 요약, 디스크/GPU/AI 모델/라이선스 현황) | [02-dashboard](docs/screenshots/02-dashboard.png) |
| 서버 목록 / GPU 필터 | [03-servers-list](docs/screenshots/03-servers-list.png) · [04-servers-gpu-filter](docs/screenshots/04-servers-gpu-filter.png) |
| 서버 상세 (IP·디스크·호스트 서비스·ACL·구동 서비스·라이선스·메모·변경 이력) | [05-server-detail](docs/screenshots/05-server-detail.png) |
| GPU 서버 상세 (GPU·컨테이너) / GPU 입력 폼 | [06-server-detail-gpu-containers](docs/screenshots/06-server-detail-gpu-containers.png) · [07-server-gpu-form](docs/screenshots/07-server-gpu-form.png) |
| 서비스 목록 / 상세 (구동 서버, 나가는·들어오는 연결, 사용 AI 모델) | [08-services-list](docs/screenshots/08-services-list.png) · [09-service-detail](docs/screenshots/09-service-detail.png) |
| AI 모델 목록 (라이선스 위험·조건 확인 배지) / 상세 | [10-models-list](docs/screenshots/10-models-list.png) · [11-model-detail](docs/screenshots/11-model-detail.png) |
| 라이선스 목록 / SSL 상세 / 마스킹된 민감 정보 / AI API 상세 / 입력 폼 | [12](docs/screenshots/12-licenses-list.png) · [13](docs/screenshots/13-license-detail-ssl.png) · [14](docs/screenshots/14-license-detail-masked-secret.png) · [15](docs/screenshots/15-license-detail-ai-api.png) · [16](docs/screenshots/16-license-form.png) |
| 통합 검색 (IP로 ACL 조회) / ACL 전체 목록 / 태그 관리 | [17](docs/screenshots/17-search-ip-acl.png) · [18](docs/screenshots/18-acls-all.png) · [19](docs/screenshots/19-tags.png) |
| CSV 일괄 등록 미리보기 (행별 오류 사유) | [20-bulk-import-preview](docs/screenshots/20-bulk-import-preview.png) |
| 사용자 관리 / 감사 로그 / 백업 / 오류 페이지 | [21](docs/screenshots/21-users.png) · [22](docs/screenshots/22-audit-log.png) · [23](docs/screenshots/23-backup.png) · [24](docs/screenshots/24-error-404.png) |

**반응형 (모바일 390px / 태블릿 820px, 라이트·다크)** — `docs/screenshots/responsive/`. 720px 이하에서는 사이드바가 가로 메뉴로, 폼·상세가 한 열로 바뀌고, 1024px 이하에서는 표가 가로 스크롤됩니다.

| 화면 | 모바일 (라이트) | 모바일 (다크) | 태블릿 |
|---|---|---|---|
| 로그인 | [보기](docs/screenshots/responsive/mobile-light-01-login.png) | [보기](docs/screenshots/responsive/mobile-dark-01-login.png) | [보기](docs/screenshots/responsive/tablet-light-01-login.png) |
| 대시보드 | [보기](docs/screenshots/responsive/mobile-light-02-dashboard.png) | [보기](docs/screenshots/responsive/mobile-dark-02-dashboard.png) | [보기](docs/screenshots/responsive/tablet-light-02-dashboard.png) |
| 서버 목록 | [보기](docs/screenshots/responsive/mobile-light-03-servers.png) | [보기](docs/screenshots/responsive/mobile-dark-03-servers.png) | [보기](docs/screenshots/responsive/tablet-light-03-servers.png) |
| 서버 상세 | [보기](docs/screenshots/responsive/mobile-light-04-server-detail.png) | [보기](docs/screenshots/responsive/mobile-dark-04-server-detail.png) | [보기](docs/screenshots/responsive/tablet-light-04-server-detail.png) |
| 라이선스 목록 | [보기](docs/screenshots/responsive/mobile-light-05-licenses.png) | [보기](docs/screenshots/responsive/mobile-dark-05-licenses.png) | [보기](docs/screenshots/responsive/tablet-light-05-licenses.png) |
| 서버 등록 폼 | [보기](docs/screenshots/responsive/mobile-light-06-server-form.png) | [보기](docs/screenshots/responsive/mobile-dark-06-server-form.png) | [보기](docs/screenshots/responsive/tablet-light-06-server-form.png) |

## 10. 개발

```bash
python3.13 -m venv .venv && .venv/bin/pip install -r requirements-dev.in   # 개발용 (httpx, pip-audit, pip-tools 포함, 이미지에는 들어가지 않음)
.venv/bin/python -m unittest                                              # 전체 테스트 (표준 unittest + Starlette TestClient, 임시 디렉터리 DB)
.venv/bin/pip-audit -r requirements.txt --disable-pip                     # 의존성 취약점
.venv/bin/pip-compile --generate-hashes --allow-unsafe --strip-extras requirements.in -o requirements.txt   # 해시 고정 갱신
grep -rnE "execute\(f|execute\(.*%|execute\(.*\+" app/                    # 0건이어야 함 (SQL 조립 점검)
grep -rnE "\|safe|Markup\(|autoescape false" app/                         # 0건이어야 함 (템플릿 안전성 점검)
.venv/bin/python -m app serve                                             # 로컬 실행 (데이터 경로는 /data 고정이므로 쓰기 가능해야 함)
```

구조: `app/main.py`(앱·미들웨어·예외 핸들러) · `app/security.py`(비밀번호/세션/CSRF/권한/제한/암호화) · `app/forms.py`(폼 파서) · `app/schemas.py`(Pydantic 모델) · `app/assets.py`(담당자·태그·메모·최신성 공통) · `app/csvio.py` · `app/audit.py` · `app/db.py`(연결·마이그레이션) · `app/migrations/` · `app/routers/` · `app/templates/` · `app/static/style.css`(단일 CSS, JS 없음) · `tests/`.

스키마를 바꿀 때는 적용된 마이그레이션을 수정하지 말고 `app/migrations/002_*.sql`처럼 새 파일을 추가하세요 (파일당 한 트랜잭션, `schema_migrations`에 버전 기록).
