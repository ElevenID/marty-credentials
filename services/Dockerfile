# Public issuance service image. Build context: marty-credentials repository root.
FROM python:3.12-slim

ARG MARTY_RS_SHA256
ARG MARTY_MSF_SHA256
ARG MARTY_COMMON_SHA256

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app:/app/services:/app/packages

WORKDIR /app

# Cross-repository inputs are checksum-verified GitHub release artifacts,
# never sibling source or an unpublished registry package.
COPY release-deps /release-deps
RUN echo "${MARTY_RS_SHA256}  /release-deps/marty_rs.whl" | sha256sum -c - \
    && echo "${MARTY_MSF_SHA256}  /release-deps/marty_msf.whl" | sha256sum -c - \
    && echo "${MARTY_COMMON_SHA256}  /release-deps/marty_common.whl" | sha256sum -c - \
    && pip install --no-cache-dir /release-deps/*.whl \
      fastapi==0.109.0 \
      'uvicorn[standard]==0.27.0' \
      'sqlalchemy[asyncio]==2.0.25' \
      asyncpg==0.29.0 \
      pydantic==2.5.3 \
      pydantic-settings==2.1.0 \
      httpx==0.26.0 \
      redis==5.0.1 \
      python-multipart==0.0.6 \
      'grpcio>=1.62.0' \
      'grpcio-health-checking>=1.62.0' \
      'grpcio-reflection>=1.62.0' \
      'googleapis-common-protos>=1.63.0' \
      'protobuf>=4.25.0' \
      'cryptography>=44.0.0' \
      'cbor2>=5.6.0'

COPY services/issuance /app/services/issuance
COPY packages /app/packages
COPY python/status_list /app/status_list

WORKDIR /app/services/issuance
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8005/health || exit 1
EXPOSE 8005
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8005"]
