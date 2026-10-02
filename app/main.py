"""FastAPI 앱 생성, 보안 헤더 미들웨어, 예외 핸들러. 라우터는 이후 단계에서 등록한다."""
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import config, db, security
from .security import LoginRequired, PasswordChangeRequired, safe_redirect_path
from .templating import render

BASE_DIR = Path(__file__).parent
log = logging.getLogger("app")

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'"
)
ERROR_MESSAGES = {
    400: "잘못된 요청입니다.",
    403: "접근 권한이 없습니다.",
    404: "페이지를 찾을 수 없습니다.",
    405: "허용되지 않는 요청 방식입니다.",
    413: "요청 본문이 너무 큽니다 (최대 1MB).",
    415: "지원하지 않는 요청 형식입니다.",
    422: "입력값이 올바르지 않습니다.",
    500: "서버 오류가 발생했습니다.",
}


def apply_security_headers(response: Response, path: str) -> Response:
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    if not path.startswith("/static/"):         # 인증된 페이지·CSV·에러 페이지는 캐시 금지
        response.headers["Cache-Control"] = "no-store"
    return response


def error_response(request: Request, status_code: int) -> Response:
    message = ERROR_MESSAGES.get(status_code, "요청을 처리할 수 없습니다.")
    return render(request, "error.html", {"status_code": status_code, "message": message}, status_code)


@asynccontextmanager
async def lifespan(app: FastAPI):
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    app.state.secret_key = security.load_or_create_key()    # 손상 시 예외 → 기동 실패
    conn = db.connect()
    try:
        db.run_migrations(conn)
    finally:
        conn.close()
    yield


def create_app() -> FastAPI:
    # 자동 API 문서를 완전히 비활성화한다 (/docs, /redoc, /openapi.json 모두 404).
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        return apply_security_headers(response, request.url.path)

    # --- 예외 핸들러: 스택트레이스/입력값/내부 정보를 노출하지 않는다 ---
    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        return error_response(request, exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        return error_response(request, 422)

    @app.exception_handler(LoginRequired)
    async def login_required(request: Request, exc: LoginRequired):
        target = "/login"
        if request.method == "GET":
            next_path = safe_redirect_path(request.url.path + (f"?{request.url.query}" if request.url.query else ""))
            if next_path != "/":
                target += "?next=" + quote(next_path, safe="")
        return RedirectResponse(target, status_code=303)

    @app.exception_handler(PasswordChangeRequired)
    async def password_change_required(request: Request, exc: PasswordChangeRequired):
        return RedirectResponse("/password", status_code=303)

    @app.exception_handler(Exception)
    async def server_error(request: Request, exc: Exception):
        # ServerErrorMiddleware가 처리하므로 사용자 미들웨어를 거치지 않는다 → 헤더를 직접 적용한다.
        log.error("unhandled error on %s %s: %s", request.method, request.url.path, type(exc).__name__)
        return apply_security_headers(error_response(request, 500), request.url.path)

    app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

    @app.get("/healthz", response_class=PlainTextResponse)
    def healthz() -> str:
        return "ok"

    return app


app = create_app()
