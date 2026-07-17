# Public verification service image. Build context: marty-credentials repository root.
FROM python:3.12-slim

ARG MARTY_RS_SHA256
ARG MARTY_MSF_SHA256
ARG MARTY_COMMON_SHA256
ARG MARTY_RS_WHEEL
ARG MARTY_MSF_WHEEL
ARG MARTY_COMMON_WHEEL

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app:/app/services:/app/packages

WORKDIR /app
COPY release-deps /release-deps
RUN echo "${MARTY_RS_SHA256}  /release-deps/${MARTY_RS_WHEEL}" | sha256sum -c - \
    && echo "${MARTY_MSF_SHA256}  /release-deps/${MARTY_MSF_WHEEL}" | sha256sum -c - \
    && echo "${MARTY_COMMON_SHA256}  /release-deps/${MARTY_COMMON_WHEEL}" | sha256sum -c - \
    && pip install --no-cache-dir /release-deps/*.whl \
      fastapi==0.109.0 \
      'uvicorn[standard]==0.27.0' \
      'sqlalchemy[asyncio]==2.0.25' \
      asyncpg==0.29.0 \
      pydantic==2.11.7 \
      pydantic-settings==2.11.0 \
      httpx==0.26.0 \
      redis==5.0.1 \
      python-multipart==0.0.6

COPY services/verification /app/services/verification
COPY packages /app/packages

WORKDIR /app/services/verification
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8006/health || exit 1
EXPOSE 8006
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8006"]
