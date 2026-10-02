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
