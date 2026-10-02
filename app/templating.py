"""Jinja2 템플릿 설정과 렌더 헬퍼. 자동 이스케이프를 명시적으로 켜며, 이스케이프를 우회하는 필터/클래스는 쓰지 않는다."""
from pathlib import Path

import jinja2
from fastapi import Request
from starlette.templating import Jinja2Templates

from . import assets, config, security
from .db import parse_iso

_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=True,
)


def kst(value: str | None, seconds: bool = False) -> str:
    """UTC ISO 문자열을 Asia/Seoul 표시 문자열로 변환한다 (저장은 UTC, 표시만 KST)."""
    if not value:
        return ""
    local = parse_iso(value).astimezone(config.DISPLAY_TZ)
    return local.strftime("%Y-%m-%d %H:%M:%S" if seconds else "%Y-%m-%d %H:%M")


def kst_date(value: str | None) -> str:
    return kst(value)[:10]


def usage_class(percent: float | None) -> str:
    """막대 너비를 10% 단위 클래스(w-0 ~ w-100)로 변환한다 (CSP로 style 속성 금지)."""
    if percent is None:
        return "w-0"
    return f"w-{min(100, max(0, int(percent / 10 + 0.5) * 10))}"


def usage_level(percent: float | None) -> str:
    """80% 이상 주의(주황), 90% 이상 위험(빨강)."""
    if percent is None:
        return "gray"
    return "red" if percent >= 90 else "orange" if percent >= 80 else "green"


_env.filters["kst"] = kst
_env.filters["kst_date"] = kst_date
_env.globals.update(verify_state=assets.verify_state, usage_class=usage_class, usage_level=usage_level)
templates = Jinja2Templates(env=_env)


def render(request: Request, name: str, context: dict | None = None, status_code: int = 200):
    user = getattr(request.state, "user", None)
    ctx = {
        "user": user,
        "csrf_token": user.csrf_token if user else "",
        "flashes": getattr(request.state, "flashes", []),
        "admin_enabled": security.admin_enabled(),
        **(context or {}),
    }
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)
