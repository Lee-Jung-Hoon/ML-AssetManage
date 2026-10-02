"""Pydantic 입력 모델 공통 기반. 모든 폼 모델은 FormModel을 상속한다 (extra="forbid")."""
import re
from datetime import date
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, ValidationError, field_validator


class FormModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _blank_to_none(value: Any) -> Any:
    return None if isinstance(value, str) and value.strip() == "" else value


# HTML 폼은 빈 입력을 ''로 보내므로 선택 항목은 None으로 바꿔 검증한다.
OptInt = Annotated[int | None, BeforeValidator(_blank_to_none)]
OptFloat = Annotated[float | None, BeforeValidator(_blank_to_none)]
OptDate = Annotated[date | None, BeforeValidator(_blank_to_none)]
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
