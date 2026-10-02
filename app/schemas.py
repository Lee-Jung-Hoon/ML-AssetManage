"""Pydantic 입력 모델 공통 기반. 모든 폼 모델은 FormModel을 상속한다 (extra="forbid")."""
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, ConfigDict, ValidationError


class FormModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _blank_to_none(value: Any) -> Any:
    return None if isinstance(value, str) and value.strip() == "" else value


# HTML 폼은 빈 입력을 ''로 보내므로 선택 항목은 None으로 바꿔 검증한다.
OptInt = Annotated[int | None, BeforeValidator(_blank_to_none)]
OptFloat = Annotated[float | None, BeforeValidator(_blank_to_none)]

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
