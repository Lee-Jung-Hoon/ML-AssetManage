"""대시보드. 3단계에서는 로그인 후 이동할 자리표시자만 둔다 (12단계에서 구현)."""
from fastapi import APIRouter, Depends, Request

from ..security import require_login
from ..templating import render

router = APIRouter(dependencies=[Depends(require_login)])


@router.get("/")
def dashboard(request: Request):
    return render(request, "dashboard.html")
