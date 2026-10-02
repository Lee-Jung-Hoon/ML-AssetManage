"""CLI: `python -m app serve | reset-admin | healthcheck`."""
import argparse
import logging
import sys
import urllib.request

from . import config, db, security

HEALTH_URL = "http://127.0.0.1:8080/healthz"


def serve() -> int:
    import uvicorn
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    from .main import app
    # 워커 1개 고정 (로그인 제한/세션 정리가 인메모리 상태에 의존). 프록시 헤더 신뢰 근거는 README 참고.
    uvicorn.run(app, host="0.0.0.0", port=8080, workers=1, proxy_headers=True,
                forwarded_allow_ips="*", server_header=False)
    return 0


def reset_admin() -> int:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = db.connect()
    try:
        db.run_migrations(conn)
        password = security.reset_admin(conn)
    finally:
        conn.close()
    print("=" * 60)
    print("admin 비밀번호를 재설정했습니다 (모든 세션 무효화, 다음 로그인 시 변경 강제).")
    print(f"  사용자명: {security.ADMIN_USERNAME}")
    print(f"  새 비밀번호: {password}")
    print("=" * 60)
    return 0


def healthcheck() -> int:
    try:
        with urllib.request.urlopen(HEALTH_URL, timeout=3) as resp:      # 표준 라이브러리만 사용
            return 0 if resp.status == 200 and resp.read().strip() == b"ok" else 1
    except Exception:
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app")
    parser.add_argument("command", choices=["serve", "reset-admin", "healthcheck"])
    args = parser.parse_args(argv)
    return {"serve": serve, "reset-admin": reset_admin, "healthcheck": healthcheck}[args.command]()


if __name__ == "__main__":
    sys.exit(main())
