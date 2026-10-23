# syntax=docker/dockerfile:1.7

FROM ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff AS uv

FROM python:3.15.1-slim@sha256:08275f764e022331c6d3e3ca55d8cce01fa4684b02111adf0445d71806fe7941 AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /build

COPY --from=uv /uv /uvx /usr/local/bin/
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project

FROM python:3.15.1-slim@sha256:08275f764e022331c6d3e3ca55d8cce01fa4684b02111adf0445d71806fe7941 AS runtime

ARG VERSION
ARG REVISION
ARG SOURCE_REPOSITORY_URL
ARG WEB_REVISION

LABEL org.opencontainers.image.title="Camellia Remote Management Server" \
      org.opencontainers.image.description="Account, device, policy, audit, and management API for Camellia Remote" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.source="${SOURCE_REPOSITORY_URL}" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.vendor="Camellia Computing" \
      io.camellia.remote.web.revision="${WEB_REVISION}"

RUN test -n "${VERSION}" \
    && test -n "${REVISION}" \
    && test -n "${SOURCE_REPOSITORY_URL}" \
    && test -n "${WEB_REVISION}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    HOST="0.0.0.0" \
    PORT="21114" \
    TZ="UTC"

RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid appuser --no-create-home --shell /usr/sbin/nologin appuser

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY --chown=appuser:appuser manage.py run.sh ./
COPY --chown=appuser:appuser web-client.lock ./
COPY --chown=appuser:appuser api ./api
COPY --chown=appuser:appuser locale ./locale
COPY --chown=appuser:appuser camellia_remote_management ./camellia_remote_management
COPY --chown=appuser:appuser static ./static
COPY --chown=appuser:appuser templates ./templates
COPY --chown=appuser:appuser webui2 ./webui2
RUN locked_revision="$(tr -d '\r\n' < web-client.lock)" \
    && printf '%s\n' "$locked_revision" | grep -Eq '^[0-9a-f]{40}$' \
    && grep -Fxq "${locked_revision} clean" static/web_client/.source_revision \
    && mkdir -p records static_root \
    && chown appuser:appuser records static_root

USER appuser
RUN CAMELLIA_REMOTE_DEBUG=true \
    CAMELLIA_REMOTE_SECRET_KEY="build-only-secret-key-with-at-least-fifty-characters-000000000" \
    CAMELLIA_REMOTE_DEVICE_VERIFICATION_TOKEN="build-only-device-verification-token-000000000000" \
    python manage.py collectstatic --noinput --clear

EXPOSE 21114/tcp

ENTRYPOINT ["sh", "run.sh"]
