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
