# syntax=docker/dockerfile:1

# ---- build stage: venv를 만들고 해시로 고정된 의존성만 설치한다 ----
FROM python:3.13-slim AS build
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
COPY requirements.txt /tmp/requirements.txt
RUN /opt/venv/bin/pip install --require-hashes -r /tmp/requirements.txt \
 && /opt/venv/bin/pip uninstall -y pip setuptools

# ---- final stage: venv와 앱 코드만 복사한다 (빌드 도구/pip/setuptools 없음) ----
FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# 최종 이미지에서 pip/setuptools/wheel 제거
RUN python -m pip uninstall -y pip setuptools wheel \
 && rm -rf /root/.cache \
 && groupadd --gid 10001 app \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app \
 && mkdir -p /data/backups \
 && chown -R 10001:10001 /data \
 && chmod 700 /data/backups

COPY --from=build /opt/venv /opt/venv
WORKDIR /srv
COPY app /srv/app

# non-root 고정 UID. 데이터(/data)는 볼륨, 나머지 파일시스템은 읽기 전용으로 실행할 수 있다.
USER 10001:10001
EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-m", "app", "healthcheck"]

CMD ["python", "-m", "app", "serve"]
