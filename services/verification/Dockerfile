# Public verification service image. Build context: marty-credentials repository root.
FROM python:3.12-slim

ARG MARTY_RS_VERSION=0.1.0
ARG MARTY_MSF_VERSION=1.0.0

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app:/app/services:/app/packages

WORKDIR /app
RUN pip install --no-cache-dir \
      "marty-rs==${MARTY_RS_VERSION}" \
      "marty-msf==${MARTY_MSF_VERSION}" \
      fastapi==0.109.0 \
      'uvicorn[standard]==0.27.0' \
      'sqlalchemy[asyncio]==2.0.25' \
      asyncpg==0.29.0 \
      pydantic==2.5.3 \
      pydantic-settings==2.1.0 \
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
