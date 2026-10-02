"""폼 파싱 의존성: 크기 제한 + Content-Type 검사 + CSRF 검증."""
from urllib.parse import parse_qs

from fastapi import Depends, HTTPException, Request

from . import config
from .security import CurrentUser, check_csrf, require_login

_FORM_TYPE = "application/x-www-form-urlencoded"


async def read_form(request: Request) -> dict[str, str]:
    """본문을 스트림으로 읽어 파싱한다. CSRF 검증이 필요 없는 곳(로그인)에서만 직접 쓴다."""
    media_type, _, params = request.headers.get("content-type", "").partition(";")
    if media_type.strip().lower() != _FORM_TYPE:
        raise HTTPException(status_code=415)
    charset = params.strip().lower().replace(" ", "")
    if charset and charset not in ("charset=utf-8", 'charset="utf-8"'):
        raise HTTPException(status_code=415)

    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > config.MAX_BODY_BYTES:
        raise HTTPException(status_code=413)

    # Content-Length만 믿지 않고 실제 수신 바이트를 센다 (chunked 포함). 초과 즉시 중단.
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > config.MAX_BODY_BYTES:
            raise HTTPException(status_code=413)
        chunks.append(chunk)
    try:
        text = b"".join(chunks).decode("utf-8")
        parsed = parse_qs(text, keep_blank_values=True, max_num_fields=config.MAX_FORM_FIELDS)
    except ValueError:      # 잘못된 UTF-8 또는 필드 수 초과
        raise HTTPException(status_code=400)
    return {key: values[-1] for key, values in parsed.items()}


def csrf_form(form: dict[str, str] = Depends(read_form), user: CurrentUser = Depends(require_login)) -> dict[str, str]:
    """로그인 후 모든 POST 엔드포인트가 사용한다. csrf_token을 검증하고 제거한 폼 값을 반환한다."""
    form = dict(form)
    check_csrf(user, form.pop("csrf_token", ""))
    return form
