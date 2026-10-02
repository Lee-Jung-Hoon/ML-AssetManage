-- 001_init.sql: 전체 초기 스키마
-- 규칙: 시각은 UTC ISO8601 TEXT (예: 2026-01-31T09:00:00Z), 날짜는 'YYYY-MM-DD' TEXT.
-- 사용자는 하드 삭제하지 않으므로 users 참조는 모두 ON DELETE RESTRICT.
-- 이 파일은 적용 후 수정하지 않는다. 변경은 002_... 로 추가한다.

-- ---------------------------------------------------------------- 사용자/세션
CREATE TABLE users (
    id                   INTEGER PRIMARY KEY,
    username             TEXT NOT NULL UNIQUE COLLATE NOCASE
                         CHECK (length(username) BETWEEN 1 AND 50),
    display_name         TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 100),
    team                 TEXT NOT NULL DEFAULT '' CHECK (length(team) <= 100),
    role                 TEXT NOT NULL CHECK (role IN ('admin', 'editor', 'viewer')),
    is_active            INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    password_hash        TEXT NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 1 CHECK (must_change_password IN (0, 1)),
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL
);

CREATE TABLE sessions (
    id_hash      TEXT PRIMARY KEY,               -- 세션 ID의 SHA-256 hex (원문 저장 금지)
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token   TEXT NOT NULL,
    flash        TEXT,                           -- JSON, 1회 표시 후 삭제
    created_at   TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    expires_at   TEXT NOT NULL                   -- 절대 만료
);
CREATE INDEX idx_sessions_user ON sessions(user_id);

-- ---------------------------------------------------------------- 서버
CREATE TABLE servers (
    id               INTEGER PRIMARY KEY,
    name             TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    hostname         TEXT NOT NULL UNIQUE COLLATE NOCASE CHECK (length(hostname) BETWEEN 1 AND 253),
    os_type          TEXT NOT NULL CHECK (os_type IN ('Windows', 'Linux')),
    os_distro        TEXT NOT NULL DEFAULT '' CHECK (length(os_distro) <= 100),
    os_version       TEXT NOT NULL DEFAULT '' CHECK (length(os_version) <= 100),
    kernel_version   TEXT NOT NULL DEFAULT '' CHECK (length(kernel_version) <= 100),
    environment      TEXT NOT NULL CHECK (environment IN ('prod', 'stg', 'dev', 'test')),
    status           TEXT NOT NULL CHECK (status IN ('운영중', '점검', '폐기예정', '폐기')),
    server_type      TEXT NOT NULL CHECK (server_type IN ('물리', 'VM', '클라우드 인스턴스')),
    location         TEXT NOT NULL DEFAULT '' CHECK (length(location) <= 200),
    cpu_model        TEXT NOT NULL DEFAULT '' CHECK (length(cpu_model) <= 100),
    cpu_cores        INTEGER CHECK (cpu_cores IS NULL OR cpu_cores > 0),
    memory_gb        INTEGER CHECK (memory_gb IS NULL OR memory_gb > 0),
    description      TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 4000),
    notes            TEXT NOT NULL DEFAULT '' CHECK (length(notes) <= 4000),
    owner_id         INTEGER REFERENCES users(id) ON DELETE RESTRICT,
    last_verified_at TEXT,
    last_verified_by INTEGER REFERENCES users(id) ON DELETE RESTRICT,
    created_at       TEXT NOT NULL,
    created_by       INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_at       TEXT NOT NULL,
    updated_by       INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT
);
CREATE INDEX idx_servers_name ON servers(name);
CREATE INDEX idx_servers_owner ON servers(owner_id);
CREATE INDEX idx_servers_updated ON servers(updated_at);

CREATE TABLE server_ips (
    id             INTEGER PRIMARY KEY,
    server_id      INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    ip             TEXT NOT NULL CHECK (length(ip) BETWEEN 2 AND 45),
    interface_name TEXT NOT NULL DEFAULT '' CHECK (length(interface_name) <= 50),
    kind           TEXT NOT NULL CHECK (kind IN ('공인', '사설', '관리용', 'VIP')),
    is_primary     INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0, 1))
);
CREATE INDEX idx_server_ips_server ON server_ips(server_id);
CREATE INDEX idx_server_ips_ip ON server_ips(ip);
-- 서버당 대표 IP는 최대 1개
CREATE UNIQUE INDEX uq_server_ips_primary ON server_ips(server_id) WHERE is_primary = 1;

CREATE TABLE server_disks (
    id          INTEGER PRIMARY KEY,
    server_id   INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    mount_point TEXT NOT NULL CHECK (length(mount_point) BETWEEN 1 AND 100),
    device      TEXT NOT NULL DEFAULT '' CHECK (length(device) <= 100),
    filesystem  TEXT NOT NULL DEFAULT '' CHECK (length(filesystem) <= 30),
    disk_type   TEXT NOT NULL CHECK (disk_type IN ('SSD', 'HDD', 'NVMe', 'SAN', 'NAS')),
    total_gb    REAL NOT NULL CHECK (total_gb > 0),
    used_gb     REAL NOT NULL CHECK (used_gb >= 0),
    raid        TEXT NOT NULL DEFAULT '' CHECK (length(raid) <= 100),
    notes       TEXT NOT NULL DEFAULT '' CHECK (length(notes) <= 1000),
    measured_at TEXT CHECK (measured_at IS NULL OR date(measured_at) IS measured_at),
    CHECK (used_gb <= total_gb)
);
CREATE INDEX idx_server_disks_server ON server_disks(server_id);

CREATE TABLE server_gpus (
    id             INTEGER PRIMARY KEY,
    server_id      INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    gpu_model      TEXT NOT NULL CHECK (length(gpu_model) BETWEEN 1 AND 100),
    quantity       INTEGER NOT NULL CHECK (quantity BETWEEN 1 AND 16),
    vram_gb        INTEGER CHECK (vram_gb IS NULL OR vram_gb > 0),
    driver_version TEXT NOT NULL DEFAULT '' CHECK (length(driver_version) <= 30),
    cuda_version   TEXT NOT NULL DEFAULT '' CHECK (length(cuda_version) <= 30),
    mig_config     TEXT NOT NULL DEFAULT '' CHECK (length(mig_config) <= 200),
    nvlink         INTEGER NOT NULL DEFAULT 0 CHECK (nvlink IN (0, 1)),
    assigned_to    TEXT NOT NULL DEFAULT '' CHECK (length(assigned_to) <= 200),  -- 비어 있으면 미할당
    assign_note    TEXT NOT NULL DEFAULT '' CHECK (length(assign_note) <= 1000)
);
CREATE INDEX idx_server_gpus_server ON server_gpus(server_id);
CREATE INDEX idx_server_gpus_model ON server_gpus(gpu_model);

CREATE TABLE host_services (
    id          INTEGER PRIMARY KEY,
    server_id   INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    name        TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    run_type    TEXT NOT NULL CHECK (run_type IN ('systemd', 'Windows 서비스', '프로세스', '기타')),
    port        INTEGER CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
    protocol    TEXT CHECK (protocol IS NULL OR protocol IN ('TCP', 'UDP')),
    version     TEXT NOT NULL DEFAULT '' CHECK (length(version) <= 50),
    description TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 1000)
);
CREATE INDEX idx_host_services_server ON host_services(server_id);

CREATE TABLE server_containers (
    id              INTEGER PRIMARY KEY,
    server_id       INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    name            TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    image           TEXT NOT NULL CHECK (length(image) BETWEEN 1 AND 300),
    port_mappings   TEXT NOT NULL DEFAULT '' CHECK (length(port_mappings) <= 300),
    compose_project TEXT NOT NULL DEFAULT '' CHECK (length(compose_project) <= 100),
    status          TEXT NOT NULL DEFAULT '' CHECK (length(status) <= 50),
    description     TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 1000),
    gpu_usage       TEXT NOT NULL DEFAULT '없음' CHECK (gpu_usage IN ('없음', '전체', '특정 디바이스')),
    gpu_devices     TEXT NOT NULL DEFAULT '' CHECK (length(gpu_devices) <= 50),
    CHECK (gpu_usage = '특정 디바이스' OR gpu_devices = '')
);
CREATE INDEX idx_server_containers_server ON server_containers(server_id);
CREATE INDEX idx_server_containers_name ON server_containers(name);

CREATE TABLE server_acls (
    id           INTEGER PRIMARY KEY,
    server_id    INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    direction    TEXT NOT NULL CHECK (direction IN ('Inbound', 'Outbound')),
    src_cidr     TEXT NOT NULL CHECK (length(src_cidr) BETWEEN 2 AND 43),
    dst_cidr     TEXT NOT NULL CHECK (length(dst_cidr) BETWEEN 2 AND 43),
    port_start   INTEGER NOT NULL CHECK (port_start BETWEEN 1 AND 65535),
    port_end     INTEGER NOT NULL CHECK (port_end BETWEEN 1 AND 65535),
    protocol     TEXT NOT NULL CHECK (protocol IN ('TCP', 'UDP')),
    purpose      TEXT NOT NULL CHECK (length(purpose) BETWEEN 1 AND 1000),
    requester    TEXT NOT NULL CHECK (length(requester) BETWEEN 1 AND 100),
    requested_at TEXT NOT NULL CHECK (date(requested_at) IS requested_at),
    ticket_no    TEXT NOT NULL DEFAULT '' CHECK (length(ticket_no) <= 50),
    status       TEXT NOT NULL CHECK (status IN ('요청', '승인', '적용완료', '반려', '회수')),
    expires_at   TEXT CHECK (expires_at IS NULL OR date(expires_at) IS expires_at),
    CHECK (port_start <= port_end)
);
CREATE INDEX idx_server_acls_server ON server_acls(server_id);
CREATE INDEX idx_server_acls_status ON server_acls(status);

-- ---------------------------------------------------------------- 서비스
CREATE TABLE services (
    id                 INTEGER PRIMARY KEY,
    name               TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    code               TEXT NOT NULL UNIQUE CHECK (length(code) BETWEEN 1 AND 50),
    description        TEXT NOT NULL CHECK (length(description) BETWEEN 1 AND 4000),
    category           TEXT NOT NULL CHECK (category IN
                       ('웹', 'API', '배치', 'DB', '메시지 큐', '모니터링', '내부 도구',
                        'AI 추론', 'AI 학습', '데이터 파이프라인', '기타')),
    environment        TEXT NOT NULL CHECK (environment IN ('prod', 'stg', 'dev', 'test')),
    status             TEXT NOT NULL CHECK (status IN ('운영중', '개발중', '점검', '종료예정', '종료')),
    tier               INTEGER NOT NULL CHECK (tier IN (1, 2, 3)),
    team               TEXT NOT NULL DEFAULT '' CHECK (length(team) <= 100),
    urls               TEXT NOT NULL DEFAULT '' CHECK (length(urls) <= 2000),   -- 줄바꿈 구분
    repo_url           TEXT NOT NULL DEFAULT '' CHECK (length(repo_url) <= 500),
    doc_url            TEXT NOT NULL DEFAULT '' CHECK (length(doc_url) <= 500),
    tech_stack         TEXT NOT NULL DEFAULT '' CHECK (length(tech_stack) <= 500),
    deploy_method      TEXT NOT NULL CHECK (deploy_method IN
                       ('Docker', 'Docker Compose', 'Kubernetes', 'systemd', 'IIS', '기타')),
    serving_engine     TEXT CHECK (serving_engine IS NULL OR serving_engine IN
                       ('vLLM', 'SGLang', 'Triton', 'TGI', 'Ollama', 'TorchServe', '자체 구현', '기타')),
    notes              TEXT NOT NULL DEFAULT '' CHECK (length(notes) <= 4000),
    primary_owner_id   INTEGER REFERENCES users(id) ON DELETE RESTRICT,
    secondary_owner_id INTEGER REFERENCES users(id) ON DELETE RESTRICT,
    last_verified_at   TEXT,
    last_verified_by   INTEGER REFERENCES users(id) ON DELETE RESTRICT,
    created_at         TEXT NOT NULL,
    created_by         INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_at         TEXT NOT NULL,
    updated_by         INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    CHECK (serving_engine IS NULL OR category = 'AI 추론')
);
CREATE INDEX idx_services_name ON services(name);
CREATE INDEX idx_services_primary_owner ON services(primary_owner_id);
CREATE INDEX idx_services_secondary_owner ON services(secondary_owner_id);

CREATE TABLE service_servers (
    service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    server_id  INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    role       TEXT NOT NULL CHECK (role IN ('WEB', 'WAS', 'API', 'DB', '캐시', '배치', 'LB', '기타')),
    note       TEXT NOT NULL DEFAULT '' CHECK (length(note) <= 500),
    PRIMARY KEY (service_id, server_id)
);
CREATE INDEX idx_service_servers_server ON service_servers(server_id);

CREATE TABLE service_links (
    id                INTEGER PRIMARY KEY,
    service_id        INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    target_service_id INTEGER REFERENCES services(id) ON DELETE CASCADE,
    external_name     TEXT CHECK (external_name IS NULL OR length(external_name) BETWEEN 1 AND 100),
    protocol          TEXT NOT NULL CHECK (protocol IN
                      ('HTTP', 'HTTPS', 'gRPC', 'TCP', 'DB', 'MQ', 'SFTP', 'SMTP', '기타')),
    port              INTEGER CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
    purpose           TEXT NOT NULL DEFAULT '' CHECK (length(purpose) <= 500),
    auth_method       TEXT NOT NULL DEFAULT '' CHECK (length(auth_method) <= 100),  -- 인증 정보 자체는 저장하지 않음
    -- 내부 서비스/외부 시스템 중 정확히 하나
    CHECK ((target_service_id IS NULL) <> (external_name IS NULL)),
    CHECK (target_service_id IS NULL OR target_service_id <> service_id)
);
CREATE INDEX idx_service_links_service ON service_links(service_id);
CREATE INDEX idx_service_links_target ON service_links(target_service_id);

-- ---------------------------------------------------------------- 라이선스
CREATE TABLE licenses (
    id               INTEGER PRIMARY KEY,
    name             TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    license_type     TEXT NOT NULL CHECK (license_type IN
                     ('SSL/TLS 인증서', '소프트웨어 라이선스', '구독(SaaS)', 'AI API', '도메인', '기타')),
    vendor           TEXT NOT NULL DEFAULT '' CHECK (length(vendor) <= 100),
    start_date       TEXT CHECK (start_date IS NULL OR date(start_date) IS start_date),
    expires_at       TEXT CHECK (expires_at IS NULL OR date(expires_at) IS expires_at),
    no_expiry        INTEGER NOT NULL DEFAULT 0 CHECK (no_expiry IN (0, 1)),
    auto_renew       INTEGER NOT NULL DEFAULT 0 CHECK (auto_renew IN (0, 1)),
    quantity         INTEGER CHECK (quantity IS NULL OR quantity >= 0),
    cost             REAL CHECK (cost IS NULL OR cost >= 0),
    currency         TEXT NOT NULL DEFAULT 'KRW' CHECK (length(currency) BETWEEN 1 AND 10),
    billing_cycle    TEXT CHECK (billing_cycle IS NULL OR billing_cycle IN ('월', '연', '영구')),
    alert_days       INTEGER NOT NULL DEFAULT 30 CHECK (alert_days BETWEEN 0 AND 365),
    notes            TEXT NOT NULL DEFAULT '' CHECK (length(notes) <= 4000),

    -- 민감 정보: AES-256-GCM (nonce 12바이트 || ciphertext). 레코드 ID가 AAD.
    license_key_enc  BLOB,
    account_info_enc BLOB,

    -- SSL/TLS 인증서 전용
    ssl_cn           TEXT CHECK (ssl_cn IS NULL OR length(ssl_cn) <= 253),
    ssl_san          TEXT CHECK (ssl_san IS NULL OR length(ssl_san) <= 4000),  -- 줄바꿈 구분
    ssl_wildcard     INTEGER NOT NULL DEFAULT 0 CHECK (ssl_wildcard IN (0, 1)),
    ssl_ca           TEXT CHECK (ssl_ca IS NULL OR length(ssl_ca) <= 200),
    ssl_key_algo     TEXT CHECK (ssl_key_algo IS NULL OR ssl_key_algo IN
                     ('RSA 2048', 'RSA 4096', 'ECDSA P-256', '기타')),
    ssl_serial       TEXT CHECK (ssl_serial IS NULL OR length(ssl_serial) <= 100),
    ssl_sha256       TEXT CHECK (ssl_sha256 IS NULL OR length(ssl_sha256) <= 100),

    -- AI API 전용 (API 키 자체는 저장하지 않고 보관 위치만 기록)
    ai_provider      TEXT CHECK (ai_provider IS NULL OR length(ai_provider) <= 100),
    ai_models        TEXT CHECK (ai_models IS NULL OR length(ai_models) <= 2000),  -- 줄바꿈 구분
    ai_monthly_budget REAL CHECK (ai_monthly_budget IS NULL OR ai_monthly_budget >= 0),
    ai_usage_limit_set INTEGER CHECK (ai_usage_limit_set IS NULL OR ai_usage_limit_set IN (0, 1)),
    ai_key_location  TEXT CHECK (ai_key_location IS NULL OR length(ai_key_location) <= 300),
    ai_sends_customer_data TEXT CHECK (ai_sends_customer_data IS NULL OR
                     ai_sends_customer_data IN ('예', '아니오', '미확인')),
    ai_training_opt_out TEXT CHECK (ai_training_opt_out IS NULL OR
                     ai_training_opt_out IN ('설정됨', '미설정', '해당 없음', '미확인')),
    ai_retention_note TEXT CHECK (ai_retention_note IS NULL OR length(ai_retention_note) <= 1000),

    owner_id         INTEGER REFERENCES users(id) ON DELETE RESTRICT,
    last_verified_at TEXT,
    last_verified_by INTEGER REFERENCES users(id) ON DELETE RESTRICT,
    created_at       TEXT NOT NULL,
    created_by       INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_at       TEXT NOT NULL,
    updated_by       INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,

    -- 만료일은 필수이되 영구 라이선스는 '만료 없음'
    CHECK ((no_expiry = 1 AND expires_at IS NULL) OR (no_expiry = 0 AND expires_at IS NOT NULL)),
    -- 종류별 전용 필드는 해당 종류에서만 허용
    CHECK (license_type = 'SSL/TLS 인증서' OR
           (ssl_cn IS NULL AND ssl_san IS NULL AND ssl_wildcard = 0 AND ssl_ca IS NULL AND
            ssl_key_algo IS NULL AND ssl_serial IS NULL AND ssl_sha256 IS NULL)),
    CHECK (license_type = 'AI API' OR
           (ai_provider IS NULL AND ai_models IS NULL AND ai_monthly_budget IS NULL AND
            ai_usage_limit_set IS NULL AND ai_key_location IS NULL AND
            ai_sends_customer_data IS NULL AND ai_training_opt_out IS NULL AND
            ai_retention_note IS NULL)),
    -- AI API 종류는 민감 정보(키/계정)를 저장하지 않는다
    CHECK (license_type <> 'AI API' OR (license_key_enc IS NULL AND account_info_enc IS NULL))
);
CREATE INDEX idx_licenses_name ON licenses(name);
CREATE INDEX idx_licenses_expires ON licenses(expires_at);
CREATE INDEX idx_licenses_owner ON licenses(owner_id);

CREATE TABLE license_servers (
    license_id INTEGER NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    server_id  INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    PRIMARY KEY (license_id, server_id)
);
CREATE INDEX idx_license_servers_server ON license_servers(server_id);

CREATE TABLE license_services (
    license_id INTEGER NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    PRIMARY KEY (license_id, service_id)
);
CREATE INDEX idx_license_services_service ON license_services(service_id);

-- ---------------------------------------------------------------- AI 모델
CREATE TABLE models (
    id               INTEGER PRIMARY KEY,
    name             TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    version          TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 50),
    model_type       TEXT NOT NULL CHECK (model_type IN
                     ('LLM', '임베딩', '비전', '음성', '분류·예측', '추천', '기타')),
    source           TEXT NOT NULL CHECK (source IN ('자체 학습', '파인튜닝', '오픈소스', '상용 API')),
    base_model       TEXT NOT NULL DEFAULT '' CHECK (length(base_model) <= 200),
    model_license    TEXT NOT NULL DEFAULT '' CHECK (length(model_license) <= 100),
    commercial_use   TEXT NOT NULL DEFAULT '미확인' CHECK (commercial_use IN ('가능', '조건부', '불가', '미확인')),
    license_note     TEXT NOT NULL DEFAULT '' CHECK (length(license_note) <= 2000),
    description      TEXT NOT NULL CHECK (length(description) BETWEEN 1 AND 4000),
    status           TEXT NOT NULL CHECK (status IN ('실험', '스테이징', '운영', '폐기')),
    param_size       TEXT NOT NULL DEFAULT '' CHECK (length(param_size) <= 30),
    vram_gb          INTEGER CHECK (vram_gb IS NULL OR vram_gb > 0),
    storage_location TEXT NOT NULL DEFAULT '' CHECK (length(storage_location) <= 500),
    experiment_url   TEXT NOT NULL DEFAULT '' CHECK (length(experiment_url) <= 500),
    card_url         TEXT NOT NULL DEFAULT '' CHECK (length(card_url) <= 500),
    license_id       INTEGER REFERENCES licenses(id) ON DELETE SET NULL,  -- 상용 API일 때만, AI API 종류
    owner_id         INTEGER REFERENCES users(id) ON DELETE RESTRICT,
    last_verified_at TEXT,
    last_verified_by INTEGER REFERENCES users(id) ON DELETE RESTRICT,
    created_at       TEXT NOT NULL,
    created_by       INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_at       TEXT NOT NULL,
    updated_by       INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    UNIQUE (name, version),
    CHECK (source NOT IN ('파인튜닝', '오픈소스') OR base_model <> ''),
    CHECK (license_id IS NULL OR source = '상용 API')
);
CREATE INDEX idx_models_owner ON models(owner_id);
CREATE INDEX idx_models_license ON models(license_id);

CREATE TABLE model_services (
    model_id   INTEGER NOT NULL REFERENCES models(id) ON DELETE CASCADE,
    service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    note       TEXT NOT NULL DEFAULT '' CHECK (length(note) <= 500),
    PRIMARY KEY (model_id, service_id)
);
CREATE INDEX idx_model_services_service ON model_services(service_id);

-- ---------------------------------------------------------------- 공통: 태그/운영 메모
-- asset_type + asset_id는 다형 참조라 FK CASCADE가 불가능하다.
-- 자산 삭제 시 같은 트랜잭션에서 코드로 명시 삭제한다 (assets.py).
CREATE TABLE tags (
    id   INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 30)
);

CREATE TABLE asset_tags (
    asset_type TEXT NOT NULL CHECK (asset_type IN ('server', 'service', 'model', 'license')),
    asset_id   INTEGER NOT NULL,
    tag_id     INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (asset_type, asset_id, tag_id)
);
CREATE INDEX idx_asset_tags_tag ON asset_tags(tag_id);

CREATE TABLE asset_notes (
    id         INTEGER PRIMARY KEY,
    asset_type TEXT NOT NULL CHECK (asset_type IN ('server', 'service', 'model', 'license')),
    asset_id   INTEGER NOT NULL,
    note_date  TEXT NOT NULL CHECK (date(note_date) IS note_date),
    content    TEXT NOT NULL CHECK (length(content) BETWEEN 1 AND 2000),
    author_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_asset_notes_asset ON asset_notes(asset_type, asset_id);

-- ---------------------------------------------------------------- 감사 로그
CREATE TABLE audit_logs (
    id          INTEGER PRIMARY KEY,
    at          TEXT NOT NULL,
    user_id     INTEGER REFERENCES users(id) ON DELETE RESTRICT,  -- 로그인 실패 등은 NULL
    username    TEXT NOT NULL DEFAULT '' CHECK (length(username) <= 64),
    ip          TEXT NOT NULL DEFAULT '' CHECK (length(ip) <= 45),
    action      TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 50),
    target_type TEXT NOT NULL DEFAULT '' CHECK (length(target_type) <= 30),
    target_id   INTEGER,
    summary     TEXT NOT NULL DEFAULT '' CHECK (length(summary) <= 4000)
);
CREATE INDEX idx_audit_at ON audit_logs(at);
CREATE INDEX idx_audit_target ON audit_logs(target_type, target_id);
CREATE INDEX idx_audit_user ON audit_logs(user_id);

-- 감사 로그는 수정/삭제 불가 (애플리케이션 버그·SQL 주입이 있어도 변조 방지)
CREATE TRIGGER audit_logs_no_update BEFORE UPDATE ON audit_logs
BEGIN
    SELECT RAISE(ABORT, 'audit_logs is append-only');
END;

CREATE TRIGGER audit_logs_no_delete BEFORE DELETE ON audit_logs
BEGIN
    SELECT RAISE(ABORT, 'audit_logs is append-only');
END;
