"""Pydantic 입력 모델 공통 기반. 모든 폼 모델은 FormModel을 상속한다 (extra="forbid")."""
import re
from datetime import date
from typing import Annotated, Any, Literal

from pydantic import (AfterValidator, BaseModel, BeforeValidator, ConfigDict, Field, ValidationError,
                      field_validator, model_validator)

from .assets import parse_tags


class FormModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _blank_to_none(value: Any) -> Any:
    return None if isinstance(value, str) and value.strip() == "" else value


# HTML 폼은 빈 입력을 ''로 보내므로 선택 항목은 None으로 바꿔 검증한다.
OptInt = Annotated[int | None, BeforeValidator(_blank_to_none)]
OptFloat = Annotated[float | None, BeforeValidator(_blank_to_none)]
OptDate = Annotated[date | None, BeforeValidator(_blank_to_none)]


def opt_int(minimum: int, maximum: int):
    """빈 입력은 None, 값이 있으면 범위를 검사한다 (Field(ge=)는 None에 적용하면 TypeError가 난다)."""
    def check(value: int | None) -> int | None:
        if value is not None and not minimum <= value <= maximum:
            raise ValueError(f"{minimum}~{maximum} 사이의 숫자를 입력하세요.")
        return value
    return Annotated[int | None, BeforeValidator(_blank_to_none), AfterValidator(check)]


def opt_float(minimum: float, maximum: float):
    def check(value: float | None) -> float | None:
        if value is not None and not minimum <= value <= maximum:
            raise ValueError("허용 범위를 벗어난 값입니다.")
        return value
    return Annotated[float | None, BeforeValidator(_blank_to_none), AfterValidator(check)]


# 쉼표로 구분한 태그 입력 → 정규화된 목록 (assets.parse_tags가 한국어 오류를 던진다)
Tags = Annotated[list[str], BeforeValidator(parse_tags)]


def _flag(value: Any) -> bool:
    return value in ("1", "on", "true", True)


# 목록 필터의 체크박스 (쿼리스트링 ?gpu_only=1)
Flag = Annotated[bool, BeforeValidator(_flag)]


def opt_choice(*allowed: str):
    """빈 값('')이거나 허용 목록에 있는 값만 통과하는 필터용 문자열."""
    def check(value: str) -> str:
        if value != "" and value not in allowed:
            raise ValueError("허용되지 않는 값입니다.")
        return value
    return Annotated[str, AfterValidator(check)]
# 체크박스는 체크된 경우에만 전송된다 (미전송 = False).
Checkbox = Annotated[bool, BeforeValidator(lambda v: v in ("on", "1", "true", True))]

_MESSAGES = {
    "missing": "필수 항목입니다.",
    "string_too_short": "필수 항목입니다.",
    "string_type": "문자열을 입력하세요.",
    "literal_error": "허용되지 않는 값입니다.",
    "enum": "허용되지 않는 값입니다.",
    "int_parsing": "숫자를 입력하세요.",
    "int_type": "숫자를 입력하세요.",
    "float_parsing": "숫자를 입력하세요.",
    "float_type": "숫자를 입력하세요.",
    "bool_parsing": "올바른 값이 아닙니다.",
    "date_parsing": "날짜를 YYYY-MM-DD 형식으로 입력하세요.",
    "date_from_datetime_parsing": "날짜를 YYYY-MM-DD 형식으로 입력하세요.",
    "extra_forbidden": "허용되지 않는 항목입니다.",
}
_RANGE_TYPES = {"greater_than", "greater_than_equal", "less_than", "less_than_equal"}


def _message(err: dict) -> str:
    kind = err["type"]
    if kind == "string_too_long":
        return f"{err['ctx']['max_length']}자 이하로 입력하세요."
    if kind in _RANGE_TYPES:
        return "허용 범위를 벗어났습니다."
    if kind == "value_error":
        return str(err["ctx"]["error"])        # 우리 검증기가 던진 한국어 메시지
    return _MESSAGES.get(kind, "올바르지 않은 값입니다.")


def validate_form[T: FormModel](model: type[T], data: dict[str, str]) -> tuple[T | None, dict[str, str]]:
    """(검증된 모델, {필드: 한국어 오류}) 반환. 오류 메시지에 입력값을 에코하지 않는다."""
    try:
        return model.model_validate(data), {}
    except ValidationError as exc:
        errors: dict[str, str] = {}
        for err in exc.errors():
            field = str(err["loc"][0]) if err["loc"] else "__all__"
            errors.setdefault(field, _message(err))
        return None, errors


class SecretFormModel(FormModel):
    """비밀번호가 들어 있는 폼. 공백을 자르지 않는다 (비밀번호의 앞뒤 공백은 의미가 있다)."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class LoginForm(SecretFormModel):
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=256)
    next: str = Field(default="", max_length=2000)


class PasswordChangeForm(SecretFormModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)
    new_password2: str = Field(min_length=1, max_length=256)


Role = Literal["admin", "editor", "viewer"]
_USERNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{1,49}")


class UserCreateForm(FormModel):
    username: str = Field(max_length=50)
    display_name: str = Field(min_length=1, max_length=100)
    team: str = Field(default="", max_length=100)
    role: Role

    @field_validator("username")
    @classmethod
    def _username_format(cls, v: str) -> str:
        if not _USERNAME.fullmatch(v):
            raise ValueError("영문, 숫자, '.', '_', '-'만 사용해 2~50자로 입력하세요 (첫 글자는 영문/숫자).")
        return v


class UserEditForm(FormModel):
    display_name: str = Field(min_length=1, max_length=100)
    team: str = Field(default="", max_length=100)
    role: Role
    is_active: Checkbox = False


class AuditFilter(FormModel):
    date_from: OptDate = None
    date_to: OptDate = None
    user: str = Field(default="", max_length=64)
    action: str = Field(default="", max_length=50)
    target_type: str = Field(default="", max_length=30)
    page: int = Field(default=1, ge=1, le=100000)


# ------------------------------------------------------------------ 서버
OS_TYPES = ("Windows", "Linux")
ENVIRONMENTS = ("prod", "stg", "dev", "test")
SERVER_STATUSES = ("운영중", "점검", "폐기예정", "폐기")
SERVER_TYPES = ("물리", "VM", "클라우드 인스턴스")
LINUX_DISTROS = ("Ubuntu", "Debian", "RHEL", "Rocky", "AlmaLinux", "CentOS", "Amazon Linux", "SUSE")
WINDOWS_DISTROS = ("Windows Server 2016", "Windows Server 2019", "Windows Server 2022", "Windows Server 2025")
_HOSTNAME = re.compile(r"[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?")


def _multiline(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


class ServerForm(FormModel):
    name: str = Field(min_length=1, max_length=100)
    hostname: str = Field(min_length=1, max_length=253)
    os_type: Literal[*OS_TYPES]
    os_distro: str = Field(default="", max_length=100)       # 목록 추천 + 직접 입력
    os_version: str = Field(default="", max_length=100)
    kernel_version: str = Field(default="", max_length=100)  # Windows는 빌드 번호
    environment: Literal[*ENVIRONMENTS]
    status: Literal[*SERVER_STATUSES]
    server_type: Literal[*SERVER_TYPES]
    location: str = Field(default="", max_length=200)
    cpu_model: str = Field(default="", max_length=100)
    cpu_cores: opt_int(1, 4096) = None
    memory_gb: opt_int(1, 100000) = None
    description: Annotated[str, AfterValidator(_multiline)] = Field(default="", max_length=4000)
    notes: Annotated[str, AfterValidator(_multiline)] = Field(default="", max_length=4000)
    owner_id: OptInt = None
    tags: Tags = []

    @field_validator("hostname")
    @classmethod
    def _hostname_format(cls, v: str) -> str:
        if not _HOSTNAME.fullmatch(v):
            raise ValueError("호스트명은 영문, 숫자, '.', '-', '_'만 사용할 수 있습니다.")
        return v

    @model_validator(mode="after")
    def _distro_matches_os(self):
        other = LINUX_DISTROS if self.os_type == "Windows" else WINDOWS_DISTROS
        if self.os_distro in other:
            raise ValueError("OS 종류와 배포판이 일치하지 않습니다.")
        return self


class ServerFilter(FormModel):
    q: str = Field(default="", max_length=100)
    os_type: opt_choice(*OS_TYPES) = ""
    os_distro: str = Field(default="", max_length=100)
    environment: opt_choice(*ENVIRONMENTS) = ""
    status: opt_choice(*SERVER_STATUSES) = ""
    gpu_only: Flag = False
    tag: str = Field(default="", max_length=30)
    owner_id: OptInt = None
    mine: Flag = False
    stale: Flag = False
    sort: Literal["name", "updated", "verified"] = "name"
    page: int = Field(default=1, ge=1, le=100000)


class NoteForm(FormModel):
    note_date: OptDate = None
    content: str = Field(min_length=1, max_length=2000)


# ------------------------------------------------------------------ 서버 하위 항목 (6단계)
import ipaddress  # noqa: E402

IP_KINDS = ("공인", "사설", "관리용", "VIP")
DISK_TYPES = ("SSD", "HDD", "NVMe", "SAN", "NAS")
RUN_TYPES = ("systemd", "Windows 서비스", "프로세스", "기타")
PROTOCOLS = ("TCP", "UDP")
GPU_USAGES = ("없음", "전체", "특정 디바이스")
ACL_DIRECTIONS = ("Inbound", "Outbound")
ACL_STATUSES = ("요청", "승인", "적용완료", "반려", "회수")
GPU_MODEL_SUGGESTIONS = ("H200", "H100", "A100 80GB", "A100 40GB", "L40S", "L4", "A10", "T4",
                         "RTX 6000 Ada", "RTX 4090")

_VERSION = re.compile(r"[0-9]+(\.[0-9]+)*")
_DEVICES = re.compile(r"[0-9]+(,[0-9]+)*")
_PORT_MAPPING = re.compile(r"(([0-9]{1,3}\.){3}[0-9]{1,3}:)?([0-9]{1,5})(-[0-9]{1,5})?(:([0-9]{1,5})(-[0-9]{1,5})?)?(/(tcp|udp))?")
_PORT_SPEC = re.compile(r"([0-9]{1,5})(\s*-\s*([0-9]{1,5}))?")


def _ip_address(value: str) -> str:
    try:
        if "%" in value:
            raise ValueError
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise ValueError("올바른 IPv4/IPv6 주소가 아닙니다.") from None


def _ip_network(value: str) -> str:
    """IP 또는 CIDR을 검증하고 정규화한다 (ip_network(strict=False): 호스트 비트는 0으로)."""
    try:
        if "%" in value:
            raise ValueError
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        raise ValueError("올바른 IP 또는 CIDR이 아닙니다 (예: 10.0.0.0/24).") from None


def _version(value: str) -> str:
    if value and not _VERSION.fullmatch(value):
        raise ValueError("숫자와 점만 사용할 수 있습니다 (예: 550.54.15, 12.4).")
    return value


def _port_spec(value: str) -> str:
    """단일 포트 또는 범위('8000-8100')를 1~65535로 검증하고 정규화한다."""
    m = _PORT_SPEC.fullmatch(value)
    if not m:
        raise ValueError("포트는 단일 값(80) 또는 범위(8000-8100)로 입력하세요.")
    start = int(m.group(1))
    end = int(m.group(3)) if m.group(3) else start
    if not (1 <= start <= 65535 and 1 <= end <= 65535):
        raise ValueError("포트는 1~65535 사이여야 합니다.")
    if start > end:
        raise ValueError("포트 범위의 시작이 끝보다 클 수 없습니다.")
    return str(start) if start == end else f"{start}-{end}"


def split_port_spec(spec: str) -> tuple[int, int]:
    start, _, end = spec.partition("-")
    return int(start), int(end or start)


def _port_mappings(value: str) -> str:
    entries = [e.strip() for e in re.split(r"[,\n]", value) if e.strip()]
    for entry in entries:
        m = _PORT_MAPPING.fullmatch(entry)
        ports = [int(p) for p in re.findall(r"(?<![0-9.])[0-9]{1,5}(?![0-9.])", entry.split("/")[0])] if m else []
        if not m or any(not 1 <= p <= 65535 for p in ports):
            raise ValueError("포트 매핑 형식이 올바르지 않습니다 (예: 8080:80, 127.0.0.1:5432:5432/tcp).")
    return ", ".join(entries)


IPAddress = Annotated[str, Field(min_length=1, max_length=45), AfterValidator(_ip_address)]
Network = Annotated[str, Field(min_length=1, max_length=43), AfterValidator(_ip_network)]
Version = Annotated[str, Field(max_length=30), AfterValidator(_version)]
PortSpec = Annotated[str, Field(min_length=1, max_length=11), AfterValidator(_port_spec)]
Money = Field(allow_inf_nan=False)


class ServerIPForm(FormModel):
    ip: IPAddress
    interface_name: str = Field(default="", max_length=50)
    kind: Literal[*IP_KINDS]
    is_primary: Checkbox = False


class ServerDiskForm(FormModel):
    mount_point: str = Field(min_length=1, max_length=100)
    device: str = Field(default="", max_length=100)
    filesystem: str = Field(default="", max_length=30)
    disk_type: Literal[*DISK_TYPES]
    total_gb: float = Field(gt=0, le=10_000_000, allow_inf_nan=False)
    used_gb: float = Field(ge=0, le=10_000_000, allow_inf_nan=False)
    raid: str = Field(default="", max_length=100)
    notes: str = Field(default="", max_length=1000)
    measured_at: OptDate = None

    @field_validator("used_gb")
    @classmethod
    def _used_within_total(cls, v: float, info) -> float:
        total = info.data.get("total_gb")
        if total is not None and v > total:
            raise ValueError("사용량은 전체 용량을 넘을 수 없습니다.")
        return v


class ServerGPUForm(FormModel):
    gpu_model: str = Field(min_length=1, max_length=100)
    quantity: int = Field(ge=1, le=16)
    vram_gb: opt_int(1, 1024) = None
    driver_version: Version = ""
    cuda_version: Version = ""
    mig_config: str = Field(default="", max_length=200)
    nvlink: Checkbox = False
    assigned_to: str = Field(default="", max_length=200)      # 비어 있으면 '미할당'
    assign_note: str = Field(default="", max_length=1000)


class HostServiceForm(FormModel):
    name: str = Field(min_length=1, max_length=100)
    run_type: Literal[*RUN_TYPES]
    port: opt_int(1, 65535) = None
    protocol: opt_choice(*PROTOCOLS) = ""
    version: str = Field(default="", max_length=50)
    description: str = Field(default="", max_length=1000)


class ContainerForm(FormModel):
    name: str = Field(min_length=1, max_length=100)
    image: str = Field(min_length=1, max_length=300)
    port_mappings: Annotated[str, AfterValidator(_port_mappings)] = Field(default="", max_length=300)
    compose_project: str = Field(default="", max_length=100)
    status: str = Field(default="", max_length=50)
    description: str = Field(default="", max_length=1000)
    gpu_usage: Literal[*GPU_USAGES] = "없음"
    gpu_devices: str = Field(default="", max_length=50, validate_default=True)

    @field_validator("gpu_devices")
    @classmethod
    def _devices(cls, v: str, info) -> str:
        usage = info.data.get("gpu_usage")
        v = re.sub(r"\s*,\s*", ",", v.strip())      # 쉼표 주변 공백만 허용 ('0 1'은 거부)
        if v and not _DEVICES.fullmatch(v):
            raise ValueError("디바이스 번호는 숫자와 쉼표만 사용할 수 있습니다 (예: 0,1).")
        if usage == "특정 디바이스" and not v:
            raise ValueError("'특정 디바이스'를 선택한 경우 번호를 입력하세요.")
        return v if usage == "특정 디바이스" else ""         # 다른 값이면 서버측에서 비워 저장


class ACLForm(FormModel):
    direction: Literal[*ACL_DIRECTIONS]
    src_cidr: Network
    dst_cidr: Network
    port: PortSpec
    protocol: Literal[*PROTOCOLS]
    purpose: str = Field(min_length=1, max_length=1000)
    requester: str = Field(min_length=1, max_length=100)
    requested_at: date
    ticket_no: str = Field(default="", max_length=50)
    status: Literal[*ACL_STATUSES]
    expires_at: OptDate = None

    @field_validator("expires_at")
    @classmethod
    def _expiry_after_request(cls, v, info):
        requested = info.data.get("requested_at")
        if v is not None and requested is not None and v < requested:
            raise ValueError("만료일은 요청일보다 빠를 수 없습니다.")
        return v


# ------------------------------------------------------------------ 서비스 (7단계)
from urllib.parse import urlsplit  # noqa: E402

SERVICE_CATEGORIES = ("웹", "API", "배치", "DB", "메시지 큐", "모니터링", "내부 도구", "AI 추론", "AI 학습",
                      "데이터 파이프라인", "기타")
SERVICE_STATUSES = ("운영중", "개발중", "점검", "종료예정", "종료")
DEPLOY_METHODS = ("Docker", "Docker Compose", "Kubernetes", "systemd", "IIS", "기타")
SERVING_ENGINES = ("vLLM", "SGLang", "Triton", "TGI", "Ollama", "TorchServe", "자체 구현", "기타")
SERVICE_ROLES = ("WEB", "WAS", "API", "DB", "캐시", "배치", "LB", "기타")
LINK_PROTOCOLS = ("HTTP", "HTTPS", "gRPC", "TCP", "DB", "MQ", "SFTP", "SMTP", "기타")
TIERS = (1, 2, 3)

_SERVICE_CODE = re.compile(r"[A-Z0-9]+(-[A-Z0-9]+)*")
_BARE_DOMAIN = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?(/[^\s]*)?")
MAX_ACCESS_URLS = 20


def _http_url(value: str) -> str:
    """http://, https:// 만 허용한다 (javascript:, data: 등 차단). URL에 계정 정보는 넣을 수 없다."""
    if value == "":
        return value
    if any(c.isspace() or ord(c) < 0x20 for c in value):
        raise ValueError("URL에 공백이나 제어 문자를 넣을 수 없습니다.")
    parts = urlsplit(value)
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise ValueError("http:// 또는 https:// 로 시작하는 URL만 입력할 수 있습니다.")
    if parts.username or parts.password:
        raise ValueError("URL에 계정 정보를 포함할 수 없습니다.")
    return value


def _access_urls(value: str) -> str:
    """접속 URL/도메인 (줄바꿈 구분). 각 줄은 http(s) URL이거나 스킴 없는 도메인이어야 한다."""
    lines = [line.strip() for line in value.replace("\r\n", "\n").replace("\r", "\n").split("\n") if line.strip()]
    if len(lines) > MAX_ACCESS_URLS:
        raise ValueError(f"접속 URL/도메인은 최대 {MAX_ACCESS_URLS}개까지 입력할 수 있습니다.")
    for line in lines:
        if len(line) > 500:
            raise ValueError("각 줄은 500자 이하여야 합니다.")
        if "://" in line:
            _http_url(line)
        elif not _BARE_DOMAIN.fullmatch(line):
            raise ValueError("각 줄은 http(s):// URL 또는 도메인이어야 합니다 (javascript:, data: 등은 허용되지 않습니다).")
    return "\n".join(lines)


def _service_code(value: str) -> str:
    if not _SERVICE_CODE.fullmatch(value):
        raise ValueError("서비스 코드는 영문 대문자, 숫자, 하이픈만 사용할 수 있습니다 (예: PAY-API).")
    return value


def _auth_method(value: str) -> str:
    """인증 정보 자체는 저장하지 않는다: 방식 이름만 받고, 키/토큰처럼 보이는 긴 연속 문자열은 거부한다."""
    if len(value) > 40 and not any(c.isspace() for c in value):
        raise ValueError("인증 방식의 이름만 입력하세요 (키, 비밀번호, 토큰 등 인증 정보는 입력 금지).")
    return value


HttpUrl = Annotated[str, Field(max_length=500), AfterValidator(_http_url)]
ServiceCode = Annotated[str, Field(min_length=1, max_length=50), AfterValidator(_service_code)]
AccessUrls = Annotated[str, Field(max_length=4000), AfterValidator(_access_urls)]


class ServiceForm(FormModel):
    name: str = Field(min_length=1, max_length=100)
    code: ServiceCode
    description: Annotated[str, AfterValidator(_multiline)] = Field(min_length=1, max_length=4000)
    category: Literal[*SERVICE_CATEGORIES]
    environment: Literal[*ENVIRONMENTS]
    status: Literal[*SERVICE_STATUSES]
    tier: int = Field(ge=1, le=3)
    team: str = Field(default="", max_length=100)
    urls: AccessUrls = ""
    repo_url: HttpUrl = ""
    doc_url: HttpUrl = ""
    tech_stack: str = Field(default="", max_length=500)
    deploy_method: Literal[*DEPLOY_METHODS]
    serving_engine: opt_choice(*SERVING_ENGINES) = Field(default="", validate_default=True)
    notes: Annotated[str, AfterValidator(_multiline)] = Field(default="", max_length=4000)
    primary_owner_id: OptInt = None
    secondary_owner_id: OptInt = None
    tags: Tags = []

    @field_validator("serving_engine")
    @classmethod
    def _engine_only_for_inference(cls, v: str, info) -> str:
        # AI 추론이 아닌 분류로 제출되면 서버측에서 값을 비워 저장한다.
        return v if info.data.get("category") == "AI 추론" else ""

    @model_validator(mode="after")
    def _distinct_owners(self):
        if self.primary_owner_id is not None and self.primary_owner_id == self.secondary_owner_id:
            raise ValueError("정 담당자와 부 담당자는 서로 다른 사용자여야 합니다.")
        return self


class ServiceFilter(FormModel):
    q: str = Field(default="", max_length=100)
    category: opt_choice(*SERVICE_CATEGORIES) = ""
    environment: opt_choice(*ENVIRONMENTS) = ""
    status: opt_choice(*SERVICE_STATUSES) = ""
    tier: opt_choice("1", "2", "3") = ""
    tag: str = Field(default="", max_length=30)
    owner_id: OptInt = None
    mine: Flag = False
    stale: Flag = False
    sort: Literal["name", "updated", "verified"] = "name"
    page: int = Field(default=1, ge=1, le=100000)


class ServiceServerCreateForm(FormModel):
    server_id: int = Field(ge=1)
    role: Literal[*SERVICE_ROLES]
    note: str = Field(default="", max_length=500)


class ServiceServerEditForm(FormModel):
    role: Literal[*SERVICE_ROLES]
    note: str = Field(default="", max_length=500)


class ServiceLinkForm(FormModel):
    target_service_id: OptInt = None
    external_name: str = Field(default="", max_length=100)
    protocol: Literal[*LINK_PROTOCOLS]
    port: opt_int(1, 65535) = None
    purpose: str = Field(default="", max_length=500)
    auth_method: Annotated[str, AfterValidator(_auth_method)] = Field(default="", max_length=100)

    @model_validator(mode="after")
    def _exactly_one_target(self):
        if (self.target_service_id is None) == (self.external_name == ""):
            raise ValueError("내부 서비스와 외부 시스템 중 정확히 하나만 지정하세요.")
        return self


# ------------------------------------------------------------------ 라이선스 (8단계)
LICENSE_TYPES = ("SSL/TLS 인증서", "소프트웨어 라이선스", "구독(SaaS)", "AI API", "도메인", "기타")
BILLING_CYCLES = ("월", "연", "영구")
KEY_ALGOS = ("RSA 2048", "RSA 4096", "ECDSA P-256", "기타")
AI_PROVIDERS = ("OpenAI", "Anthropic", "Google", "Azure OpenAI", "AWS Bedrock", "기타")
AI_SENDS = ("예", "아니오", "미확인")
AI_OPT_OUT = ("설정됨", "미설정", "해당 없음", "미확인")
CURRENCIES = ("KRW", "USD", "EUR", "JPY", "CNY")
SSL_TYPE, AI_TYPE = "SSL/TLS 인증서", "AI API"
SENSITIVE_FORM_FIELDS = ("license_key", "account_info")

_CN = re.compile(r"[A-Za-z0-9*._:@-]+")
_SAN = re.compile(r"[A-Za-z0-9*._:-]+")
_FINGERPRINT = re.compile(r"[0-9A-Fa-f]{64}")


def _lines(value: str, label: str, max_lines: int, max_len: int, pattern: re.Pattern | None = None) -> str:
    items = [line.strip() for line in value.replace("\r\n", "\n").replace("\r", "\n").split("\n") if line.strip()]
    if len(items) > max_lines:
        raise ValueError(f"{label}은(는) 최대 {max_lines}줄까지 입력할 수 있습니다.")
    for item in items:
        if len(item) > max_len or (pattern and not pattern.fullmatch(item)):
            raise ValueError(f"{label}의 형식이 올바르지 않습니다 (줄당 {max_len}자 이하).")
    return "\n".join(items)


def _san_lines(value: str) -> str:
    return _lines(value, "SAN 목록", 100, 253, _SAN)


def _model_lines(value: str) -> str:
    return _lines(value, "사용 모델", 30, 100)


def _cn(value: str) -> str:
    if value and not _CN.fullmatch(value):
        raise ValueError("CN 형식이 올바르지 않습니다.")
    return value


def _fingerprint(value: str) -> str:
    if value == "":
        return value
    hex_only = value.replace(":", "").replace(" ", "")
    if not _FINGERPRINT.fullmatch(hex_only):
        raise ValueError("SHA-256 지문은 64자리 16진수여야 합니다 (콜론 구분 가능).")
    upper = hex_only.upper()
    return ":".join(upper[i:i + 2] for i in range(0, 64, 2))


def _currency(value: str) -> str:
    value = value.upper()
    if not re.fullmatch(r"[A-Z]{3}", value):
        raise ValueError("통화는 3자리 영문 코드여야 합니다 (예: KRW, USD).")
    return value


class LicenseForm(FormModel):
    name: str = Field(min_length=1, max_length=200)
    license_type: Literal[*LICENSE_TYPES]
    vendor: str = Field(default="", max_length=100)
    start_date: OptDate = None
    no_expiry: Checkbox = False
    expires_at: OptDate = None
    auto_renew: Checkbox = False
    quantity: opt_int(0, 10_000_000) = None
    cost: opt_float(0, 1e12) = None
    currency: Annotated[str, AfterValidator(_currency)] = "KRW"
    billing_cycle: opt_choice(*BILLING_CYCLES) = ""
    alert_days: int = Field(default=30, ge=0, le=365)
    notes: Annotated[str, AfterValidator(_multiline)] = Field(default="", max_length=4000)

    # 민감 정보 (AES-256-GCM으로 암호화해 저장). 수정 화면에서 비워 두면 기존 값을 유지한다.
    license_key: str = Field(default="", max_length=2000, validate_default=True)
    account_info: str = Field(default="", max_length=2000, validate_default=True)
    clear_license_key: Checkbox = False
    clear_account_info: Checkbox = False

    # SSL/TLS 인증서 전용
    ssl_cn: Annotated[str, AfterValidator(_cn)] = Field(default="", max_length=253)
    ssl_san: Annotated[str, AfterValidator(_san_lines)] = Field(default="", max_length=30000)
    ssl_wildcard: Checkbox = False
    ssl_ca: str = Field(default="", max_length=200)
    ssl_key_algo: opt_choice(*KEY_ALGOS) = ""
    ssl_serial: str = Field(default="", max_length=100)
    ssl_sha256: Annotated[str, AfterValidator(_fingerprint)] = Field(default="", max_length=100)

    # AI API 전용 (API 키 자체는 받지 않고 보관 위치만 기록)
    ai_provider: str = Field(default="", max_length=100, validate_default=True)
    ai_models: Annotated[str, AfterValidator(_model_lines)] = Field(default="", max_length=4000)
    ai_monthly_budget: opt_float(0, 1e12) = None
    ai_usage_limit_set: Checkbox = False
    ai_key_location: str = Field(default="", max_length=300)
    ai_sends_customer_data: opt_choice(*AI_SENDS) = ""
    ai_training_opt_out: opt_choice(*AI_OPT_OUT) = ""
    ai_retention_note: str = Field(default="", max_length=1000)

    owner_id: OptInt = None
    tags: Tags = []

    @field_validator("license_key", "account_info")
    @classmethod
    def _no_secrets_for_ai_api(cls, v: str, info) -> str:
        # API 키 자체는 받지 않는다: AI API 종류에서는 값이 들어오면 거부한다.
        if v and info.data.get("license_type") == AI_TYPE:
            raise ValueError("AI API 종류에서는 키/계정 정보를 입력할 수 없습니다. 키 보관 위치(예: Vault 경로)만 기록하세요.")
        return v

    @field_validator("ai_provider")
    @classmethod
    def _provider_required_for_ai(cls, v: str, info) -> str:
        if info.data.get("license_type") == AI_TYPE:
            if not v:
                raise ValueError("AI API 종류는 제공사가 필요합니다.")
            return v
        return ""

    @model_validator(mode="after")
    def _cross_checks(self):
        if self.no_expiry and self.expires_at is not None:
            raise ValueError("'만료 없음'과 만료일은 함께 지정할 수 없습니다.")
        if not self.no_expiry and self.expires_at is None:
            raise ValueError("만료일을 입력하거나 '만료 없음'을 체크하세요.")
        if self.start_date and self.expires_at and self.expires_at < self.start_date:
            raise ValueError("만료일은 시작일보다 빠를 수 없습니다.")
        if self.license_type != SSL_TYPE:        # 종류별 전용 필드는 해당 종류에서만 저장한다
            self.ssl_cn = self.ssl_san = self.ssl_ca = self.ssl_key_algo = self.ssl_serial = self.ssl_sha256 = ""
            self.ssl_wildcard = False
        if self.license_type == AI_TYPE:
            self.ai_sends_customer_data = self.ai_sends_customer_data or "미확인"
            self.ai_training_opt_out = self.ai_training_opt_out or "미확인"
            self.clear_license_key = self.clear_account_info = True
        else:
            self.ai_models = self.ai_key_location = self.ai_retention_note = ""
            self.ai_sends_customer_data = self.ai_training_opt_out = ""
            self.ai_monthly_budget, self.ai_usage_limit_set = None, False
        return self


class LicenseFilter(FormModel):
    q: str = Field(default="", max_length=100)
    license_type: opt_choice(*LICENSE_TYPES) = ""
    expiry: opt_choice("만료됨", "만료 임박", "유효", "영구") = ""
    ai_provider: str = Field(default="", max_length=100)
    tag: str = Field(default="", max_length=30)
    owner_id: OptInt = None
    mine: Flag = False
    stale: Flag = False
    sort: Literal["expiry", "name", "updated", "verified"] = "expiry"
    page: int = Field(default=1, ge=1, le=100000)


class RevealForm(FormModel):
    field: Literal["license_key", "account_info"]


class LicenseServerForm(FormModel):
    server_id: int = Field(ge=1)


class LicenseServiceForm(FormModel):
    service_id: int = Field(ge=1)


# ------------------------------------------------------------------ AI 모델 (9단계)
MODEL_TYPES = ("LLM", "임베딩", "비전", "음성", "분류·예측", "추천", "기타")
MODEL_SOURCES = ("자체 학습", "파인튜닝", "오픈소스", "상용 API")
MODEL_STATUSES = ("실험", "스테이징", "운영", "폐기")
COMMERCIAL_USES = ("가능", "조건부", "불가", "미확인")
MODEL_LICENSES = ("Apache-2.0", "MIT", "Llama Community", "Gemma Terms", "CC-BY", "CC-BY-NC", "상용 계약", "자체 소유",
                  "기타")
API_SOURCE = "상용 API"


def _plain_text(value: str) -> str:
    """저장 위치 등: s3:// 같은 다른 스킴도 허용하되 링크가 아닌 일반 텍스트로만 표시한다. 제어 문자만 거부."""
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise ValueError("줄바꿈이나 제어 문자를 넣을 수 없습니다.")
    return value


class ModelForm(FormModel):
    name: str = Field(min_length=1, max_length=100)
    version: str = Field(min_length=1, max_length=50)
    model_type: Literal[*MODEL_TYPES]
    source: Literal[*MODEL_SOURCES]
    base_model: str = Field(default="", max_length=200, validate_default=True)
    model_license: str = Field(default="", max_length=100)
    commercial_use: Literal[*COMMERCIAL_USES] = "미확인"
    license_note: Annotated[str, AfterValidator(_multiline)] = Field(default="", max_length=2000)
    description: Annotated[str, AfterValidator(_multiline)] = Field(min_length=1, max_length=4000)
    status: Literal[*MODEL_STATUSES]
    param_size: str = Field(default="", max_length=30)
    vram_gb: opt_int(1, 100000) = None
    storage_location: Annotated[str, AfterValidator(_plain_text)] = Field(default="", max_length=500)
    experiment_url: HttpUrl = ""
    card_url: HttpUrl = ""
    license_id: OptInt = Field(default=None, validate_default=True)
    owner_id: OptInt = None
    tags: Tags = []

    @field_validator("base_model")
    @classmethod
    def _base_model_required(cls, v: str, info) -> str:
        if info.data.get("source") in ("파인튜닝", "오픈소스") and not v:
            raise ValueError("출처가 파인튜닝/오픈소스이면 베이스 모델이 필요합니다.")
        return v

    @field_validator("license_id")
    @classmethod
    def _api_license_only_for_commercial_api(cls, v, info):
        # 상용 API 연결은 출처가 '상용 API'일 때만 허용하고, 다른 출처에서는 거부한다.
        if v is not None and info.data.get("source") != API_SOURCE:
            raise ValueError("출처가 '상용 API'일 때만 AI API 라이선스를 연결할 수 있습니다.")
        return v


class ModelFilter(FormModel):
    q: str = Field(default="", max_length=100)
    model_type: opt_choice(*MODEL_TYPES) = ""
    source: opt_choice(*MODEL_SOURCES) = ""
    status: opt_choice(*MODEL_STATUSES) = ""
    commercial_use: opt_choice(*COMMERCIAL_USES) = ""
    risk: Flag = False
    tag: str = Field(default="", max_length=30)
    owner_id: OptInt = None
    mine: Flag = False
    stale: Flag = False
    sort: Literal["name", "updated", "verified"] = "name"
    page: int = Field(default=1, ge=1, le=100000)


class ModelServiceCreateForm(FormModel):
    service_id: int = Field(ge=1)
    note: str = Field(default="", max_length=500)


class ModelServiceEditForm(FormModel):
    note: str = Field(default="", max_length=500)


# ------------------------------------------------------------------ 통합 검색 / 태그 관리 (10단계)
SEARCH_MIN, SEARCH_MAX = 2, 100


class SearchQuery(FormModel):
    q: str = Field(min_length=SEARCH_MIN, max_length=SEARCH_MAX)


def _single_tag(value: str) -> str:
    tags = parse_tags(value)
    if len(tags) != 1:
        raise ValueError("태그 이름 하나를 입력하세요 (쉼표 없이).")
    return tags[0]


class TagRenameForm(FormModel):
    name: Annotated[str, Field(min_length=1, max_length=60), AfterValidator(_single_tag)]
