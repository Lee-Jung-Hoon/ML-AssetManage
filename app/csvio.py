"""CSV 내보내기/가져오기 공통 함수. 수식 주입 방지, UTF-8 BOM, 안전한 파일명."""
import csv
import io
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Any

from fastapi import Response

from . import config

# 엑셀이 수식으로 해석하는 시작 문자. 해당하면 앞에 '를 붙여 텍스트로 만든다.
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
MAX_IMPORT_ROWS = 1000


def safe_cell(value: Any) -> str:
    """CSV 수식 주입(CSV injection) 방지: 위험한 시작 문자를 가진 문자열 앞에 `'`를 붙인다."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Y" if value else "N"
    if isinstance(value, float):
        return f"{value:g}"
    if isinstance(value, int):
        return str(value)
    text = str(value)
    return "'" + text if text.startswith(FORMULA_PREFIXES) else text


def build_csv(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> bytes:
    """UTF-8 with BOM (엑셀 한글 깨짐 방지)."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(headers)
    for row in rows:
        writer.writerow([safe_cell(v) for v in row])
    return b"\xef\xbb\xbf" + buffer.getvalue().encode("utf-8")


def csv_download(prefix: str, headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> Response:
    """첨부 다운로드 응답. 파일명은 ASCII (`servers-YYYYMMDD.csv`), 캐시 금지는 응답 미들웨어가 적용한다."""
    stamp = datetime.now(config.DISPLAY_TZ).strftime("%Y%m%d")
    return Response(
        build_csv(headers, rows), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{prefix}-{stamp}.csv"'})


def parse_csv_text(text: str) -> list[list[str]]:
    """붙여 넣은 CSV 텍스트를 행 목록으로 파싱한다 (BOM 제거, 완전히 빈 줄 무시). 형식 오류는 csv.Error."""
    text = text.lstrip("﻿")
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    return [row for row in reader if any(cell.strip() for cell in row)]
