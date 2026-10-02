"""FastAPI 앱 생성. 라우터/미들웨어/예외 핸들러는 이후 단계에서 등록한다."""
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import config, db

BASE_DIR = Path(__file__).parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = db.connect()
    try:
        db.run_migrations(conn)
    finally:
        conn.close()
    yield


def create_app() -> FastAPI:
    # 자동 API 문서를 완전히 비활성화한다 (/docs, /redoc, /openapi.json 모두 404).
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

    @app.get("/healthz", response_class=PlainTextResponse)
    def healthz() -> str:
        return "ok"

    return app


app = create_app()
