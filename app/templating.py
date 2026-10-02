"""Jinja2 템플릿 설정과 렌더 헬퍼. 자동 이스케이프를 명시적으로 켜며, 이스케이프를 우회하는 필터/클래스는 쓰지 않는다."""
from pathlib import Path

import jinja2
from fastapi import Request
from starlette.templating import Jinja2Templates

from . import security

_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=True,
)
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
